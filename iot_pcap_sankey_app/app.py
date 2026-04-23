import io
import tempfile
from collections import defaultdict

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, rdpcap
except Exception:
    IP = IPv6 = TCP = UDP = ICMP = None
    rdpcap = None

st.set_page_config(page_title="IoT PCAP Sankey Visualizer", layout="wide")


def endpoint_from_packet(pkt):
    """Return the best source/destination identifiers available."""
    if IP and pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if IPv6 and pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst

    if hasattr(pkt, "src") and hasattr(pkt, "dst"):
        return str(pkt.src), str(pkt.dst)

    return "unknown", "unknown"


def proto_from_packet(pkt):
    if TCP and pkt.haslayer(TCP):
        sport = getattr(pkt[TCP], "sport", "?")
        dport = getattr(pkt[TCP], "dport", "?")
        return f"TCP {sport}→{dport}"
    if UDP and pkt.haslayer(UDP):
        sport = getattr(pkt[UDP], "sport", "?")
        dport = getattr(pkt[UDP], "dport", "?")
        return f"UDP {sport}→{dport}"
    if ICMP and pkt.haslayer(ICMP):
        return "ICMP"

    if IP and pkt.haslayer(IP):
        return f"IP proto={pkt[IP].proto}"
    if IPv6 and pkt.haslayer(IPv6):
        return f"IPv6 nh={pkt[IPv6].nh}"

    return pkt.lastlayer().name if hasattr(pkt, "lastlayer") else "OTHER"


def parse_pcap(uploaded_file):
    if rdpcap is None:
        raise RuntimeError(
            "Scapy is not installed. Please install the dependencies from requirements.txt first."
        )

    suffix = ".pcapng" if uploaded_file.name.lower().endswith(".pcapng") else ".pcap"
    with tempfile.NamedTemporaryFile(delete=True, suffix=suffix) as tmp:
        tmp.write(uploaded_file.getbuffer())
        tmp.flush()
        packets = rdpcap(tmp.name)

    flow_stats = defaultdict(lambda: {
        "packets": 0,
        "bytes": 0,
        "protocols": defaultdict(int),
    })

    for pkt in packets:
        src, dst = endpoint_from_packet(pkt)
        key = (str(src), str(dst))
        flow_stats[key]["packets"] += 1
        flow_stats[key]["bytes"] += len(bytes(pkt))
        flow_stats[key]["protocols"][proto_from_packet(pkt)] += 1

    rows = []
    for (src, dst), stat in flow_stats.items():
        top_protocols = sorted(
            stat["protocols"].items(), key=lambda x: x[1], reverse=True
        )
        rows.append(
            {
                "source": src,
                "target": dst,
                "packets": stat["packets"],
                "bytes": stat["bytes"],
                "top_protocol": top_protocols[0][0] if top_protocols else "OTHER",
                "protocol_breakdown": ", ".join(
                    f"{name} ({count})" for name, count in top_protocols[:5]
                ),
            }
        )

    df = pd.DataFrame(rows)
    if df.empty:
        return df

    return df.sort_values(by="packets", ascending=False).reset_index(drop=True)


def build_sankey(df: pd.DataFrame, top_n: int, metric: str):
    df_top = df.head(top_n).copy()
    if df_top.empty:
        return None, df_top

    node_labels = pd.unique(pd.concat([df_top["source"], df_top["target"]], ignore_index=True))
    node_map = {label: idx for idx, label in enumerate(node_labels)}

    fig = go.Figure(
        data=[
            go.Sankey(
                arrangement="snap",
                node=dict(
                    pad=16,
                    thickness=18,
                    line=dict(color="black", width=0.5),
                    label=list(node_labels),
                    hovertemplate="%{label}<extra></extra>",
                ),
                link=dict(
                    source=[node_map[s] for s in df_top["source"]],
                    target=[node_map[t] for t in df_top["target"]],
                    value=df_top[metric],
                    customdata=df_top[["packets", "bytes", "top_protocol", "protocol_breakdown"]].values,
                    hovertemplate=(
                        "<b>%{source.label}</b> → <b>%{target.label}</b><br>"
                        + f"{metric.title()}: %{{value}}<br>"
                        + "Packets: %{customdata[0]}<br>"
                        + "Bytes: %{customdata[1]}<br>"
                        + "Top protocol: %{customdata[2]}<br>"
                        + "Breakdown: %{customdata[3]}<extra></extra>"
                    ),
                ),
            )
        ]
    )

    fig.update_layout(
        title=f"Top {min(top_n, len(df))} Communication Links by {metric.title()}",
        font_size=12,
        height=700,
        margin=dict(l=20, r=20, t=60, b=20),
    )
    return fig, df_top


st.title("IoT PCAP Sankey Visualizer")
st.write(
    "Upload a **PCAP/PCAPNG** file, choose the number of top communication links, and inspect the traffic flow in a Sankey diagram."
)

with st.sidebar:
    st.header("Controls")
    top_n = st.slider("Top communication links", min_value=10, max_value=100, value=20, step=10)
    metric = st.selectbox("Rank and size links by", options=["packets", "bytes"], index=0)
    uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])
    st.caption("The diagram aggregates links by source → destination endpoint.")

if uploaded_file is None:
    st.info("Upload a PCAP/PCAPNG file from the sidebar to begin.")
    st.stop()

try:
    with st.spinner("Parsing PCAP and building Sankey data..."):
        flow_df = parse_pcap(uploaded_file)
except Exception as exc:
    st.error(f"Failed to parse the uploaded file: {exc}")
    st.stop()

if flow_df.empty:
    st.warning("No parseable communication flows were found in the uploaded capture.")
    st.stop()

fig, shown_df = build_sankey(flow_df.sort_values(by=metric, ascending=False), top_n, metric)

col1, col2 = st.columns([2.2, 1])
with col1:
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("Summary")
    st.metric("Unique links", len(flow_df))
    st.metric("Shown links", len(shown_df))
    st.metric("Total packets (all links)", int(flow_df["packets"].sum()))
    st.metric("Total bytes (all links)", int(flow_df["bytes"].sum()))

st.subheader("Top communication links")
st.dataframe(
    shown_df[["source", "target", "packets", "bytes", "top_protocol", "protocol_breakdown"]],
    use_container_width=True,
)

csv_bytes = shown_df.to_csv(index=False).encode("utf-8")
st.download_button(
    "Download current top-link table as CSV",
    data=csv_bytes,
    file_name="top_links.csv",
    mime="text/csv",
)

with st.expander("How the app works"):
    st.markdown(
        """
- Reads the uploaded PCAP/PCAPNG file.
- Extracts source and destination endpoints from IPv4, IPv6, or MAC layer.
- Aggregates communication into source → destination links.
- Counts packets and bytes per link.
- Displays the top N links (10–100) as a Sankey diagram.
        """
    )
