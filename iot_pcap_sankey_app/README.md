# IoT PCAP Sankey Visualizer

A lightweight web application for visualizing IoT communication flows from a PCAP/PCAPNG file using a Sankey diagram.

## Features
- Upload `.pcap` or `.pcapng`
- Select **Top N** communication links from **10 to 100**
- Rank links by **packets** or **bytes**
- Interactive Sankey diagram with hover details
- Table view of top communication links
- Export current results to CSV

## Run locally
```bash
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
streamlit run app.py
```

## Expected behavior
- Input: upload a network capture file
- Output: Sankey diagram of source-to-destination communication links
- Controls: Top-N selector (10–100), packets/bytes metric

## Notes
- If IP is unavailable, the app falls back to MAC-level endpoints when possible.
- Large PCAP files may take longer to parse.
