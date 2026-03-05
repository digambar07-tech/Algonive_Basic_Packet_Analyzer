import sys
from PyQt5.QtWidgets import QApplication
from packet_analyzer_gui import PacketSnifferUI

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSnifferUI()
    window.show()
    sys.exit(app.exec_())