from flask import Flask, request, jsonify
from flask_cors import CORS
from scapy.all import rdpcap, IP, TCP, UDP, DNS, ICMP, ARP
import tempfile, os
from datetime import datetime

app = Flask(__name__)
CORS(app)

def detect_threats(packets):
    """Basic threat detection rules."""
    alerts = []
    syn_count = {}

    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src

            # Detect TCP SYN flood
            if TCP in pkt and pkt[TCP].flags == 'S':
                syn_count[src] = syn_count.get(src, 0) + 1
                if syn_count[src] == 20:   # threshold
                    alerts.append({
                        'time': datetime.now().strftime('%H:%M:%S'),
                        'sev':  'critical',
                        'msg':  f'TCP SYN flood detected from {src}',
                        'src':  src
                    })

            # Detect Telnet (port 23)
            if TCP in pkt and hasattr(pkt[TCP], 'dport') and pkt[TCP].dport == 23:
                alerts.append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'sev':  'high',
                    'msg':  'Unencrypted Telnet connection detected',
                    'src':  src
                })

    return alerts

@app.route('/api/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    f = request.files['file']

    # Save to a stable temp path — don't delete inside finally (race condition)
    tmp_dir  = tempfile.gettempdir()
    tmp_path = os.path.join(tmp_dir, f'iot_pcap_{os.getpid()}.pcap')
    f.save(tmp_path)
    try:
        packets = rdpcap(tmp_path)
    except Exception as e:
        return jsonify({'error': f'Failed to parse PCAP: {str(e)}'}), 400
    finally:
        try: os.remove(tmp_path)
        except: pass

    # Count protocols
    proto_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'DNS': 0, 'ARP': 0, 'Other': 0}
    devices = {}

    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            devices[src] = devices.get(src, {'ip': src, 'count': 0})
            devices[src]['count'] += 1

            if TCP in pkt:        proto_counts['TCP']  += 1
            elif UDP in pkt:
                proto_counts['UDP'] += 1
                if DNS in pkt:    proto_counts['DNS']  += 1
            elif ICMP in pkt:     proto_counts['ICMP'] += 1
            elif ARP in pkt:      proto_counts['ARP']  += 1
            else:                 proto_counts['Other']+= 1

    # Build device list for frontend
    device_icons = ['📡','📷','💡','🔒','📱','🌡️','🖥️','📻','🔌','📟']
    devices_list = [
        {
            'icon':   device_icons[i % len(device_icons)],
            'name':   f'Device {i+1}',
            'ip':     d['ip'],
            'status': 'alert' if d['count'] > 500 else 'warn' if d['count'] > 100 else 'ok'
        }
        for i, d in enumerate(sorted(devices.values(), key=lambda x: -x['count'])[:8])
    ]

    alerts     = detect_threats(packets)
    duration_s = int(float(packets[-1].time) - float(packets[0].time)) if len(packets) > 1 else 0
    duration   = f"{duration_s // 60}m {duration_s % 60}s"

    return jsonify({
        'packets':      len(packets),
        'threats':      len(alerts),
        'devices':      len(devices),
        'duration':     duration,
        'protocols':    proto_counts,   # { TCP: 120, UDP: 40, ... }
        'devices_list': devices_list,   # array of device objects
        'alerts':       alerts,         # array of alert objects
    })

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)