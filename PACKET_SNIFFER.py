import sys
from scapy.all import sniff, IP
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTextEdit, QPushButton, QFrame, QStatusBar
)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import QThread, pyqtSignal

class PacketSniffer(QThread):
    packet_data = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.running = True

    def run(self):
        sniff(prn=self.handle_packet, store=False, stop_filter=self.should_stop)

    def should_stop(self, packet):
        return not self.running

    def handle_packet(self, packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto
            summary = f"[Protocol: {proto}] {src} ➜ {dst}"
            self.packet_data.emit(summary)

    def stop(self):
        self.running = False


class PacketSnifferApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔍 Packet Sniffer")
        self.setGeometry(200, 150, 800, 500)
        self.setStyleSheet("background-color: #121212; color: #E0E0E0; font-family: 'Consolas';")

        self.packet_count = 0
        self.sniffer_thread = None

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Title Bar
        title = QLabel("🛰️ Live Packet Sniffer")
        title.setFont(QFont("Consolas", 18, QFont.Bold))
        layout.addWidget(title)

        # Horizontal button layout
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶ Start Sniffing")
        self.start_btn.setStyleSheet("background-color: #1DB954; padding: 8px;")
        self.start_btn.clicked.connect(self.start_sniffing)
        btn_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("⏹ Stop Sniffing")
        self.stop_btn.setStyleSheet("background-color: #FF3B30; padding: 8px;")
        self.stop_btn.clicked.connect(self.stop_sniffing)
        btn_layout.addWidget(self.stop_btn)

        layout.addLayout(btn_layout)

        # Packet Log Display
        self.packet_display = QTextEdit()
        self.packet_display.setReadOnly(True)
        self.packet_display.setStyleSheet(
            "background-color: #1E1E1E; color: #00FF7F; border: 1px solid #333;"
        )
        layout.addWidget(self.packet_display)

        # Status Bar
        self.status_bar = QStatusBar()
        self.status_label = QLabel("Status: Ready")
        self.counter_label = QLabel("Packets: 0")
        self.status_bar.addWidget(self.status_label)
        self.status_bar.addPermanentWidget(self.counter_label)
        layout.addWidget(self.status_bar)

        self.setLayout(layout)

    def start_sniffing(self):
        self.packet_count = 0
        self.packet_display.append("🚀 Sniffing started...\n")
        self.sniffer_thread = PacketSniffer()
        self.sniffer_thread.packet_data.connect(self.display_packet)
        self.sniffer_thread.start()
        self.status_label.setText("Status: Sniffing...")

    def stop_sniffing(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.quit()
            self.sniffer_thread.wait()
            self.status_label.setText("Status: Stopped")
            self.packet_display.append("\n✅ Sniffing stopped.")

    def display_packet(self, packet_info):
        self.packet_count += 1
        self.packet_display.append(f"{self.packet_count}. {packet_info}")
        self.counter_label.setText(f"Packets: {self.packet_count}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSnifferApp()
    window.show()
    sys.exit(app.exec_())
