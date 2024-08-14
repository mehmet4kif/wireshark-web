from flask import Flask, jsonify, render_template, request
from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.layers.dns import DNSQR
from scapy.packet import Raw
from threading import Thread
from collections import defaultdict
import json
import time

app = Flask(__name__)

# Veri yapıları
traffic_data = defaultdict(int)
packet_types = defaultdict(int)
alerts_data = []
user_domains = []

# JSON dosyasından kullanıcı domainlerini yükle
def load_user_domains():
    global user_domains
    try:
        with open("user_domains.json", "r") as f:
            user_domains = json.load(f)
    except FileNotFoundError:
        user_domains = []

def save_user_domains():
    with open("user_domains.json", "w") as f:
        json.dump(user_domains, f)

# Paket işleme fonksiyonu
def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        packet_types[packet.sprintf("%IP.proto%")] += 1

        # DNS trafiğini kontrol et
        if packet.haslayer(DNSQR):
            domain_name = packet[DNSQR].qname.decode().lower()
            print(f"Detected DNS Domain: {domain_name}")

            traffic_data[domain_name] += 1

            for domain in user_domains:
                if domain.lower() in domain_name:
                    alert_message = f"Warning: DNS traffic containing '{domain}' detected from {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')}"
                    print(alert_message)
                    alerts_data.append(alert_message)

        # HTTP trafiğini kontrol et
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors="ignore").lower()
            if "host:" in payload:
                lines = payload.split("\r\n")
                for line in lines:
                    if line.startswith("host:"):
                        host = line.split(" ")[1].strip()
                        print(f"Detected HTTP Host: {host}")
                        
                        traffic_data[host] += 1

                        for domain in user_domains:
                            if domain.lower() in host:
                                alert_message = f"Warning: HTTP traffic containing '{domain}' detected from {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')}"
                                print(alert_message)
                                alerts_data.append(alert_message)

            # Paket içeriğini kontrol et
            for domain in user_domains:
                if domain.lower() in payload:
                    alert_message = f"Warning: Payload containing '{domain}' detected in HTTP traffic from {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')}"
                    print(alert_message)
                    alerts_data.append(alert_message)

        # IP adreslerine dayalı trafik kontrolü
        traffic_data[f"{src_ip} -> {dst_ip}"] += 1

        for domain in user_domains:
            if domain.lower() in src_ip.lower() or domain.lower() in dst_ip.lower():
                alert_message = f"Warning: Traffic to/from '{domain}' detected from {src_ip} to {dst_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')}"
                print(alert_message)
                alerts_data.append(alert_message)

def start_sniffing():
    sniff(prn=packet_callback, filter="ip", store=0)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '').lower()
    filtered_data = {k: v for k, v in traffic_data.items() if query in k.lower()}
    return jsonify(filtered_data)

@app.route('/detailed_alerts')
def detailed_alerts():
    return jsonify(alerts_data)
    
@app.route('/data')
def data():
    return jsonify(traffic_data)

@app.route('/alerts')
def alerts():
    return jsonify(alerts_data)

@app.route('/packet_stats')
def packet_stats():
    return jsonify(packet_types)

@app.route('/add_domain', methods=['POST'])
def add_domain():
    domain = request.form['domain'].lower()
    user_domains.append(domain)
    save_user_domains()
    return jsonify({'status': 'success', 'domain': domain})

@app.route('/user_domains')
def get_user_domains():
    return jsonify(user_domains)

if __name__ == '__main__':
    load_user_domains()
    sniffing_thread = Thread(target=start_sniffing)
    sniffing_thread.daemon = True
    sniffing_thread.start()
    app.run(debug=True)
