
# IoT Packet Capture & Cloud Upload Pipeline

This project provides an automated pipeline for:

- 📥 Capturing IoT network traffic (PCAP) using `tcpdump`
- 📂 Rotating capture files periodically
- ☁️ Uploading completed PCAP files to Google Drive using `rclone`
- 🔁 Continuous monitoring and automation

---

## System Overview
IoT Devices → Network Interface (en0) \
↓ \
tcpdump (PCAP capture)\
↓ \
Local Storage (rotating .pcap files) \
↓ \
Python Upload Script (auto-detect) \
↓ \
rclone → Google Drive


---

## 📁 Project Structure
iot-pcap-pipeline/\
│ \
├── capture_pcap.py # Python script to start tcpdump \
├── upload_pcap.py # Python script to upload PCAP files \
├── data/ \
│ └── pcap/ # Local PCAP storage \
├── README.md \
└── .gitignore 

---

## ⚙️ Requirements

- Python 3.8+
- `tcpdump`
- `rclone`
- macOS / Linux

---

## 🔧 Installation

### 1. Install tcpdump

```bash
brew install tcpdump
```
2. Install rclone
```bash
brew install rclone
```

Steps:

New remote → name: datapcap \
Storage → drive \
Leave client_id and client_secret empty \
Scope → 1 (full access) \
Auto config → yes 

Test:
```bash
rclone lsd datapcap:
```
:
🚀 Usage
Step 1: Start Packet Capture
````
sudo python3 capture_pcap.py
````
This will:

Capture packets from en0 \
Save files in ~/Downloads/data/pcap \
Rotate every 5 minutes 

Example output:
````
capture_20260414_010000.pcap
capture_20260414_010500.pcap
Step 2: Start Auto Upload
python3 upload_pcap.py
````
This will:

Monitor .pcap files \
Upload files older than 6 minutes \
Skip active files \
Avoid duplicate uploads 

