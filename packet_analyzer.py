from scapy.all import IP, TCP, UDP, DNS, Raw
import string


def analyze_packet(packet):

    if IP not in packet:
        return None

    analysis = {}

    # -----------------------------
    # Basic IP Info
    # -----------------------------
    analysis["src_ip"] = packet[IP].src
    analysis["dst_ip"] = packet[IP].dst

    # -----------------------------
    # Protocol Detection
    # -----------------------------
    if TCP in packet:
        analysis["protocol"] = "TCP"
        analysis["src_port"] = packet[TCP].sport
        analysis["dst_port"] = packet[TCP].dport

        if packet[TCP].dport == 4444:
            analysis["alert"] = "⚠ Possible Reverse Shell Traffic"

    elif UDP in packet:
        analysis["protocol"] = "UDP"
        analysis["src_port"] = packet[UDP].sport
        analysis["dst_port"] = packet[UDP].dport

    else:
        analysis["protocol"] = "OTHER"
        analysis["src_port"] = None
        analysis["dst_port"] = None

    # -----------------------------
    # DNS Detection
    # -----------------------------
    if DNS in packet and packet[DNS].qd is not None:
        try:
            analysis["dns_query"] = packet[DNS].qd.qname.decode(errors="ignore")
        except:
            analysis["dns_query"] = "Unreadable DNS"

    # -----------------------------
    # Payload Extraction (Improved)
    # -----------------------------
    if Raw in packet:
        raw_bytes = packet[Raw].load

        # Try UTF-8 decode
        try:
            decoded = raw_bytes.decode("utf-8", errors="ignore")

            # Clean non-printable characters
            printable_text = "".join(
                c if c in string.printable else " "
                for c in decoded
            )

            printable_text = printable_text.strip()

            # Detect HTTP manually
            if printable_text.startswith(("GET", "POST", "HTTP", "PUT", "DELETE")):
                analysis["payload"] = printable_text[:300]
                analysis["protocol_detected"] = "HTTP"

            elif printable_text:
                analysis["payload"] = printable_text[:200]

            else:
                # If decoded but empty → show HEX preview
                analysis["payload"] = raw_bytes[:50].hex()

        except:
            # If decoding completely fails → show HEX
            analysis["payload"] = raw_bytes[:50].hex()

    else:
        analysis["payload"] = None

    return analysis