## !pip install scapy plotly

#!/usr/bin/env python3
"""
Generate a Sankey diagram from a PCAP file.

Features:
- Reads IPv4/IPv6 packets from a pcap
- Builds Source IP -> Destination IP flows
- Weights links by packet count or byte count
- Optional filtering by protocol and top N flows
- Exports an interactive HTML Sankey chart

Usage examples:
    python pcap_to_sankey.py input.pcap
    python pcap_to_sankey.py input.pcap -o sankey.html --metric bytes
    python pcap_to_sankey.py input.pcap --protocol udp --top 30
    python pcap_to_sankey.py input.pcap --port 3610 --protocol udp
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import defaultdict
from typing import Dict, Tuple, List, Optional

import plotly.graph_objects as go
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP  # type: ignore


FlowKey = Tuple[str, str]


def detect_protocol(pkt) -> Optional[str]:
    """Return a normalized protocol name for the packet."""
    if UDP in pkt:
        return "udp"
    if TCP in pkt:
        return "tcp"
    if ICMP in pkt:
        return "icmp"
    return None


def get_ip_pair(pkt) -> Optional[FlowKey]:
    """Extract source/destination IP pair from IPv4/IPv6 packet."""
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return None


def get_ports(pkt) -> Tuple[Optional[int], Optional[int]]:
    """Extract source/destination ports if available."""
    if TCP in pkt:
        return int(pkt[TCP].sport), int(pkt[TCP].dport)
    if UDP in pkt:
        return int(pkt[UDP].sport), int(pkt[UDP].dport)
    return None, None


def parse_pcap(
    pcap_path: str,
    metric: str = "packets",
    protocol: Optional[str] = None,
    port: Optional[int] = None,
) -> Dict[FlowKey, int]:
    """
    Parse packets and aggregate flows.

    metric:
        - "packets": count each packet as 1
        - "bytes": use packet length
    protocol:
        - None, "tcp", "udp", "icmp"
    port:
        - if set, include packets where src or dst port matches
    """
    flows: Dict[FlowKey, int] = defaultdict(int)

    try:
        packets = rdpcap(pcap_path)
    except FileNotFoundError:
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
    except Exception as exc:
        raise RuntimeError(f"Failed to read pcap: {exc}") from exc

    for pkt in packets:
        pair = get_ip_pair(pkt)
        if not pair:
            continue

        pkt_proto = detect_protocol(pkt)
        if protocol and pkt_proto != protocol:
            continue

        sport, dport = get_ports(pkt)
        if port is not None and port not in (sport, dport):
            continue

        weight = len(pkt) if metric == "bytes" else 1
        flows[pair] += weight

    return flows


def keep_top_flows(flows: Dict[FlowKey, int], top_n: Optional[int]) -> Dict[FlowKey, int]:
    """Keep only the top N largest flows."""
    if top_n is None or top_n <= 0:
        return flows

    sorted_items = sorted(flows.items(), key=lambda x: x[1], reverse=True)[:top_n]
    return dict(sorted_items)


def build_sankey_data(flows: Dict[FlowKey, int]):
    """Convert flow dictionary into Plotly Sankey node/link data."""
    nodes: List[str] = []
    node_index: Dict[str, int] = {}

    def add_node(label: str) -> int:
        if label not in node_index:
            node_index[label] = len(nodes)
            nodes.append(label)
        return node_index[label]

    sources: List[int] = []
    targets: List[int] = []
    values: List[int] = []
    link_labels: List[str] = []

    for (src_ip, dst_ip), value in flows.items():
        src_idx = add_node(src_ip)
        dst_idx = add_node(dst_ip)

        sources.append(src_idx)
        targets.append(dst_idx)
        values.append(value)
        link_labels.append(f"{src_ip} → {dst_ip}: {value}")

    return nodes, sources, targets, values, link_labels


def make_figure(
    nodes: List[str],
    sources: List[int],
    targets: List[int],
    values: List[int],
    link_labels: List[str],
    title: str,
) -> go.Figure:
    """Create Plotly Sankey figure."""
    fig = go.Figure(
        data=[
            go.Sankey(
                arrangement="snap",
                node=dict(
                    pad=18,
                    thickness=18,
                    line=dict(width=0.5),
                    label=nodes,
                ),
                link=dict(
                    source=sources,
                    target=targets,
                    value=values,
                    label=link_labels,
                ),
            )
        ]
    )

    fig.update_layout(
        title_text=title,
        font_size=12,
    )
    return fig


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a Sankey chart from a PCAP file.")
    parser.add_argument("pcap", help="Input PCAP file")
    parser.add_argument(
        "-o",
        "--output",
        default="sankey_output.html",
        help="Output HTML file (default: sankey_output.html)",
    )
    parser.add_argument(
        "--metric",
        choices=["packets", "bytes"],
        default="packets",
        help="Weight links by packet count or bytes (default: packets)",
    )
    parser.add_argument(
        "--protocol",
        choices=["tcp", "udp", "icmp"],
        default=None,
        help="Filter by protocol",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Filter by source or destination port",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=30,
        help="Keep only top N flows by weight (default: 30)",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.pcap):
        print(f"Error: file does not exist: {args.pcap}", file=sys.stderr)
        return 1

    try:
        flows = parse_pcap(
            pcap_path=args.pcap,
            metric=args.metric,
            protocol=args.protocol,
            port=args.port,
        )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not flows:
        print("No matching IP flows found in the pcap.", file=sys.stderr)
        return 1

    flows = keep_top_flows(flows, args.top)

    nodes, sources, targets, values, link_labels = build_sankey_data(flows)

    title_parts = [f"PCAP Sankey Diagram ({args.metric})"]
    if args.protocol:
        title_parts.append(f"protocol={args.protocol}")
    if args.port:
        title_parts.append(f"port={args.port}")
    title = " | ".join(title_parts)

    fig = make_figure(nodes, sources, targets, values, link_labels, title)

    try:
        fig.write_html(args.output)
    except Exception as exc:
        print(f"Failed to write output HTML: {exc}", file=sys.stderr)
        return 1

    print(f"Sankey chart written to: {args.output}")
    print(f"Flows included: {len(values)}")
    print(f"Nodes included: {len(nodes)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())