import time
from collections import deque
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel,
    QComboBox, QLineEdit, QFileDialog,
    QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, Qt
import pyqtgraph as pg


# ---------------- Sniffer Thread ---------------- #

class SnifferThread(QThread):
    packet_signal = pyqtSignal(object)

    def __init__(self, interface=None):
        super().__init__()
        self.interface = interface
        self.running = False

    def run(self):
        self.running = True
        sniff(
            prn=self.process_packet,
            store=False,
            iface=self.interface,
            stop_filter=self.should_stop
        )

    def process_packet(self, packet):
        if self.running:
            self.packet_signal.emit(packet)

    def should_stop(self, packet):
        return not self.running

    def stop(self):
        self.running = False


# ---------------- Main UI ---------------- #

class PacketSnifferUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Advanced Packet Sniffer")
        self.resize(1300, 850)

        self.packet_count = 0
        self.packet_rate = 0
        self.start_time = time.time()

        self.all_packets = []
        self.suspicious_packets = []
        self.rate_history = deque(maxlen=50)

        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()

        # Controls
        control_layout = QHBoxLayout()

        self.start_btn = QPushButton("Start Capture")
        self.stop_btn = QPushButton("Stop")
        self.export_btn = QPushButton("Export to PCAP")
        self.export_suspicious_btn = QPushButton("Save Suspicious Only")

        self.protocol_filter = QComboBox()
        self.protocol_filter.addItems(["ALL", "TCP", "UDP", "ICMP"])

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search packets...")

        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(QLabel("Protocol:"))
        control_layout.addWidget(self.protocol_filter)
        control_layout.addWidget(self.search_bar)
        control_layout.addWidget(self.export_btn)
        control_layout.addWidget(self.export_suspicious_btn)

        main_layout.addLayout(control_layout)

        # Packet Counter
        self.counter_label = QLabel("Packets Captured: 0")
        main_layout.addWidget(self.counter_label)

        # Table
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(9)
        self.packet_table.setHorizontalHeaderLabels([
            "No", "Time", "Source IP", "Destination IP",
            "Protocol", "Src Port", "Dst Port",
            "Length", "Status"
        ])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.packet_table.cellClicked.connect(self.show_payload)

        main_layout.addWidget(self.packet_table, stretch=3)

        # Payload Viewer
        self.payload_viewer = QTextEdit()
        self.payload_viewer.setReadOnly(True)
        self.payload_viewer.setPlaceholderText("Payload will appear here...")
        main_layout.addWidget(self.payload_viewer, stretch=2)

        # Graph
        self.graph = pg.PlotWidget()
        self.graph.setMaximumHeight(150)
        self.graph.setBackground("#0d1117")
        self.graph.setTitle("Traffic Rate")
        self.graph.setLabel("left", "Pkts/s")
        self.graph.setLabel("bottom", "Time")

        self.curve = self.graph.plot()
        main_layout.addWidget(self.graph, stretch=1)

        self.setLayout(main_layout)

        # Connections
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.export_btn.clicked.connect(self.export_pcap)
        self.export_suspicious_btn.clicked.connect(self.export_suspicious)
        self.search_bar.textChanged.connect(self.apply_filters)
        self.protocol_filter.currentTextChanged.connect(self.apply_filters)

        # Timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_graph)
        self.timer.start(1000)

    # ---------------- Capture ---------------- #

    def start_capture(self):
        self.packet_count = 0
        self.packet_rate = 0
        self.start_time = time.time()

        self.sniffer = SnifferThread()
        self.sniffer.packet_signal.connect(self.handle_packet)
        self.sniffer.start()

    def stop_capture(self):
        if hasattr(self, "sniffer") and self.sniffer.isRunning():
            self.sniffer.stop()
            self.sniffer.wait()

    def handle_packet(self, packet):
        self.packet_count += 1
        self.all_packets.append(packet)

        elapsed = time.time() - self.start_time
        if elapsed > 0:
            self.packet_rate = self.packet_count / elapsed

        self.counter_label.setText(f"Packets Captured: {self.packet_count}")

        self.insert_packet_into_table(packet)

    # ---------------- Insert Into Table ---------------- #

    def insert_packet_into_table(self, packet):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

        timestamp = time.strftime("%H:%M:%S")
        src = dst = proto = sport = dport = "-"
        length = len(packet)
        status = "Normal"

        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst

            if TCP in packet:
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif UDP in packet:
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
            elif ICMP in packet:
                proto = "ICMP"

        if self.detect_reverse_shell(packet):
            status = "Suspicious"
            self.suspicious_packets.append(packet)

        values = [
            str(self.packet_count),
            timestamp,
            str(src),
            str(dst),
            str(proto),
            str(sport),
            str(dport),
            str(length),
            status
        ]

        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setFlags(item.flags() ^ Qt.ItemIsEditable)
            self.packet_table.setItem(row, col, item)

        # Auto scroll
        self.packet_table.scrollToBottom()

    # ---------------- Payload ---------------- #

    def show_payload(self, row, column):
        packet = self.all_packets[row]

        if Raw in packet:
            raw_data = packet[Raw].load
            decoded = raw_data.decode(errors="ignore")
            hex_view = raw_data.hex()

            display = (
                "===== ASCII =====\n"
                + decoded +
                "\n\n===== HEX =====\n"
                + hex_view
            )

            self.payload_viewer.setText(display)
        else:
            self.payload_viewer.setText("No Payload Data")

    # ---------------- Detection ---------------- #

    def detect_reverse_shell(self, packet):
        if TCP in packet:
            suspicious_ports = [4444, 5555, 6666, 9001, 1234]
            if packet[TCP].dport in suspicious_ports or packet[TCP].sport in suspicious_ports:
                return True
        return False

    # ---------------- Filtering ---------------- #

    def apply_filters(self):
        protocol = self.protocol_filter.currentText()
        search_text = self.search_bar.text().lower()

        self.packet_table.setRowCount(0)

        for packet in self.all_packets:
            if IP in packet:
                proto = ""
                if TCP in packet:
                    proto = "TCP"
                elif UDP in packet:
                    proto = "UDP"
                elif ICMP in packet:
                    proto = "ICMP"

                if protocol != "ALL" and proto != protocol:
                    continue

                summary = f"{packet[IP].src} {packet[IP].dst} {proto}".lower()
                if search_text and search_text not in summary:
                    continue

            self.insert_packet_into_table(packet)

    # ---------------- Graph ---------------- #

    def update_graph(self):
        self.rate_history.append(self.packet_rate)
        self.curve.setData(list(self.rate_history))

    # ---------------- Export ---------------- #

    def export_pcap(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save PCAP", "", "PCAP Files (*.pcap)")
        if filename:
            wrpcap(filename, self.all_packets)

    def export_suspicious(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save Suspicious PCAP", "", "PCAP Files (*.pcap)")
        if filename:
            wrpcap(filename, self.suspicious_packets)