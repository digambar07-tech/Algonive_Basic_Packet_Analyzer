from scapy.all import sniff, IP, TCP, UDP, Raw, DNS
from datetime import datetime


class PacketEngine:

    def __init__(self, callback=None):
        self.callback = callback
        self.running = False

    def analyze(self, packet):
        if not self.running:
            return

        if IP not in packet:
            return

        data = {}
        data["time"] = datetime.now().strftime("%H:%M:%S")
        data["src"] = packet[IP].src
        data["dst"] = packet[IP].dst

        # Protocol detection
        if TCP in packet:
            data["protocol"] = "TCP"
            data["sport"] = packet[TCP].sport
            data["dport"] = packet[TCP].dport

        elif UDP in packet:
            data["protocol"] = "UDP"
            data["sport"] = packet[UDP].sport
            data["dport"] = packet[UDP].dport

        else:
            data["protocol"] = "OTHER"
            data["sport"] = None
            data["dport"] = None

        # Payload extraction
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load
                data["payload"] = payload.decode(errors="ignore")[:100]
            except:
                data["payload"] = "Binary Data"
        else:
            data["payload"] = None

        # Detection
        data["alert"] = self.detect_threat(packet)

        if self.callback:
            self.callback(data)

    def detect_threat(self, packet):
        if TCP in packet and packet[TCP].dport == 4444:
            return "⚠ Possible Reverse Shell"

        if packet.haslayer(DNS):
            return "DNS Query Detected"

        return None

    def start(self, interface=None):
        self.running = True

        sniff(
            iface=interface,
            prn=self.analyze,
            store=False,
            stop_filter=lambda x: not self.running
        )

    def stop(self):
        self.running = False