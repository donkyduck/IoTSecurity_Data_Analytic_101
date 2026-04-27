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