from scapy.all import AsyncSniffer
from packet_analyzer import analyze_packet

sniffer = None


def start_sniffing(callback_function, interface=None):
    """
    Starts packet sniffing.
    :param callback_function: Function to send analyzed packet data to GUI
    :param interface: Network interface (None = default)
    """

    global sniffer

    def process_packet(packet):
        try:
            result = analyze_packet(packet)
            if result:
                callback_function(result)
        except Exception as e:
            print(f"Packet processing error: {e}")

    # Create Async Sniffer (non-blocking)
    sniffer = AsyncSniffer(
        iface=interface,
        prn=process_packet,
        store=False
    )

    sniffer.start()
    print("Sniffing started...")


def stop_sniffing():
    """
    Stops packet sniffing safely.
    """
    global sniffer

    if sniffer:
        sniffer.stop()
        sniffer = None
        print("Sniffing stopped.")