# IoT Sentinel — Network Security Analyzer

A modern, single-page IoT security dashboard that lets users upload PCAP files and visualize network traffic through an interactive Sankey diagram.

---

## Project Structure

```
iot-sentinel/
└── index.html      ← entire app (HTML + CSS + JS, zero dependencies)
```

This is a **pure static site** — no build step, no npm, no framework. One file is all you need.

---

## Features

- Drag-and-drop PCAP file upload (`.pcap`, `.pcapng`, `.cap`)
- Animated analysis sequence with progress labels
- **Interactive Sankey diagram** — source devices → protocols → destinations
  - Filter by ALL / THREATS / CLEAN
  - Hover tooltips on each flow ribbon
- Threat detection panel with risk score meter
- Protocol breakdown with animated bars (TCP, UDP, DNS, ICMP, ARP, TLS)
- IoT device inventory with SECURE / WARNING / ALERT status
- Timestamped security alert log with severity badges
- Responsive layout (desktop + mobile)

> **Note:** The current version uses mock/demo data for the analysis results.
> See the "Connecting a Real Backend" section below to wire up actual PCAP parsing.

---

## Deployment Options

### Option 1 — Open Locally (no server needed)

Just open the file in any modern browser:

```bash
open index.html          # macOS
start index.html         # Windows
xdg-open index.html      # Linux
```

---

### Option 2 — Nginx (recommended for production)

**Install Nginx:**
```bash
# Ubuntu / Debian
sudo apt update && sudo apt install nginx -y

# CentOS / RHEL
sudo yum install nginx -y
```

**Copy the file:**
```bash
sudo mkdir -p /var/www/iot-sentinel
sudo cp index.html /var/www/iot-sentinel/
```

**Create Nginx config:**
```bash
sudo nano /etc/nginx/sites-available/iot-sentinel
```

Paste this config (replace `your-domain.com` or use `_` to catch all):
```nginx
server {
    listen 80;
    server_name your-domain.com;

    root /var/www/iot-sentinel;
    index index.html;

    # Compression
    gzip on;
    gzip_types text/html text/css application/javascript;

    location / {
        try_files $uri $uri/ =404;
    }

    # Optional: increase upload size limit if adding backend later
    client_max_body_size 256M;
}
```

**Enable and start:**
```bash
sudo ln -s /etc/nginx/sites-available/iot-sentinel /etc/nginx/sites-enabled/
sudo nginx -t                  # test config
sudo systemctl reload nginx
```

**Add HTTPS with Let's Encrypt (optional but recommended):**
```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d your-domain.com
```

---

### Option 3 — Apache

**Copy the file:**
```bash
sudo cp index.html /var/www/html/iot-sentinel/
```

**Create `.htaccess`** in the same folder:
```apache
Options -Indexes
DirectoryIndex index.html
```

---

### Option 4 — Node.js / Express (serve-static)

```bash
npm init -y
npm install express
```

Create `server.js`:
```javascript
const express = require('express');
const path    = require('path');
const app     = express();

app.use(express.static(path.join(__dirname)));

app.listen(3000, () => {
  console.log('IoT Sentinel running at http://localhost:3000');
});
```

Run:
```bash
node server.js
```

---

### Option 5 — Python (quick local test)

```bash
# Python 3
python3 -m http.server 8080

# Then open: http://localhost:8080
```

---

### Option 6 — Docker

Create `Dockerfile` next to `index.html`:
```dockerfile
FROM nginx:alpine
COPY index.html /usr/share/nginx/html/index.html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

Build and run:
```bash
docker build -t iot-sentinel .
docker run -d -p 8080:80 --name iot-sentinel iot-sentinel
# Open: http://localhost:8080
```

---

## Connecting a Real Backend (PCAP Parsing)

To parse actual PCAP files instead of showing demo data, you need a backend service. Here is the recommended architecture:

### Backend Stack (Python example)

**Install dependencies:**
```bash
pip install flask scapy flask-cors
```

Create `backend.py`:
```python
from flask import Flask, request, jsonify
from flask_cors import CORS
from scapy.all import rdpcap, IP, TCP, UDP, DNS, ICMP
import tempfile, os

app = Flask(__name__)
CORS(app)

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    f = request.files['file']
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
        f.save(tmp.name)
        packets = rdpcap(tmp.name)
        os.unlink(tmp.name)

    protocols = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'DNS': 0, 'Other': 0}
    devices = set()
    flows = []

    for pkt in packets:
        if IP in pkt:
            devices.add(pkt[IP].src)
            devices.add(pkt[IP].dst)
            if TCP in pkt:   protocols['TCP']  += 1
            elif UDP in pkt:
                protocols['UDP'] += 1
                if DNS in pkt: protocols['DNS'] += 1
            elif ICMP in pkt: protocols['ICMP'] += 1
            else:             protocols['Other'] += 1

    return jsonify({
        'packets':   len(packets),
        'devices':   len(devices),
        'protocols': protocols,
        'duration':  '—',
        'threats':   0,    # add your detection logic here
    })

if __name__ == '__main__':
    app.run(port=5000, debug=True)
```

### Frontend — swap mock analysis for real API call

In `index.html`, replace the `showResults()` mock with a real fetch.
Find the `startAnalysis()` function and replace the `setTimeout` block:

```javascript
// Replace this block in startAnalysis():
fetch('http://localhost:5000/analyze', {
  method: 'POST',
  body: formData,  // formData containing the uploaded file
})
.then(r => r.json())
.then(data => {
  clearInterval(iv);
  showResults(data);   // pass real data into showResults()
})
.catch(err => {
  console.error('Analysis failed:', err);
});
```

---

## Customization

| What to change | Where in index.html |
|---|---|
| Color scheme | `:root` CSS variables at the top |
| Mock devices | `DEVICES` array in the `<script>` section |
| Mock alerts | `ALERTS` array |
| Protocol list | `PROTOCOLS` array |
| Sankey nodes/flows | `NODES` and `FLOWS` arrays |
| Risk score | The `74` hardcoded in the threat panel HTML |
| Nav links | `<nav>` section in HTML |
| Logo name | `IOT·SENTINEL` text in nav |

---

## Browser Support

Works in all modern browsers: Chrome 90+, Firefox 88+, Safari 14+, Edge 90+.
No polyfills needed.

---

## License

MIT — free to use, modify, and deploy.
