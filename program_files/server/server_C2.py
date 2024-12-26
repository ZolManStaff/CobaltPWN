import sys
import threading
import ssl
import os
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QLineEdit, QFileDialog, QCheckBox, QTableWidget, QTableWidgetItem, QHBoxLayout
from PyQt5.QtCore import QTimer
from OpenSSL import crypto
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import socket
import tempfile
import psutil 
from PyQt5.QtGui import QColor, QPalette, QFont

class AdaptiveC2Handler(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def _html(self, message):
        content = f"{message}"
        return content.encode("utf8")

    def do_GET(self):
        self._set_headers()
        self.wfile.write(self._html("404 Not Found"))
        currtime = (datetime.now()).strftime("%d/%m/%Y %H:%M:%S")
        print(f"[{currtime}] GET request from {self.address_string()}")
        for x, y in self.headers.items():
            print(f"  - {x}: {y}")
        print("------------------------------------------------------------")

    def do_HEAD(self):
        self._set_headers()
        self.wfile.write(self._html("404 Not Found"))
        currtime = (datetime.now()).strftime("%d/%m/%Y %H:%M:%S")
        print(f"[{currtime}] HEAD request from {self.address_string()}")
        for x, y in self.headers.items():
            print(f"  - {x}: {y}")
        print("------------------------------------------------------------")

    def do_POST(self):
        pass

    def log_message(self, format, *args):
        return

class C2ServerApp(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('Adaptive C2 Server')
        self.setGeometry(100, 100, 900, 650)

        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: white;
            }
            QLabel, QLineEdit, QPushButton {
                font: bold 12pt "Arial";
                color: white;
                margin: 5px;
            }
            QTableWidget {
                font: 10pt "Arial";
                background-color: #333333;
                color: white;
                border: 1px solid #800000;
            }
            QTextEdit {
                font: 11pt "Courier New";
                background-color: #2e2e2e;
                color: white;
                border: 1px solid #800000;
            }
            QTableWidget QHeaderView::section {
                background-color: #800000;
                padding: 5px;
            }
            QPushButton {
                background-color: #B22222;
                border-radius: 5px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #8B0000;
            }
        """)

        self.layout = QVBoxLayout()
        self.layout.setSpacing(15)

        self.info_label = QLabel("Server Info and Log Output:")
        self.layout.addWidget(self.info_label)

        self.log_output = QTextEdit(self)
        self.log_output.setReadOnly(True)
        self.layout.addWidget(self.log_output)

        self.layout.addWidget(QLabel("Server IP Address:"))
        self.ip_input = QLineEdit("0.0.0.0")  
        self.layout.addWidget(self.ip_input)

        self.layout.addWidget(QLabel("Server Port:"))
        self.port_input = QLineEdit("443") 
        self.layout.addWidget(self.port_input)

        self.layout.addWidget(QLabel("Certificate File:"))
        self.cert_input = QLineEdit() 
        self.layout.addWidget(self.cert_input)

        self.layout.addWidget(QLabel("Private Key File:"))
        self.key_input = QLineEdit()  
        self.layout.addWidget(self.key_input)

        self.self_signed_checkbox = QCheckBox("Use Self-Signed Certificate")
        self.self_signed_checkbox.setChecked(True)
        self.layout.addWidget(self.self_signed_checkbox)

        self.layout.addWidget(QLabel("Client Connections:"))
        self.client_table = QTableWidget(0, 2)  
        self.client_table.setHorizontalHeaderLabels(["IP Address", "Connection Time"])
        self.client_table.horizontalHeader().setStretchLastSection(True)
        self.layout.addWidget(self.client_table)

        button_layout = QHBoxLayout()
        self.start_button = QPushButton('Start Server', self)
        self.start_button.clicked.connect(self.start_server)
        button_layout.addWidget(self.start_button)

        self.stop_button = QPushButton('Stop Server', self)
        self.stop_button.clicked.connect(self.stop_server)
        button_layout.addWidget(self.stop_button)

        self.clear_logs_button = QPushButton('Clear Logs', self)
        self.clear_logs_button.clicked.connect(self.clear_logs)
        button_layout.addWidget(self.clear_logs_button)

        self.layout.addLayout(button_layout)

        self.layout.addWidget(QLabel("Server Statistics:"))
        self.cpu_label = QLabel("CPU Usage: 0%")
        self.memory_label = QLabel("Memory Usage: 0%")
        self.layout.addWidget(self.cpu_label)
        self.layout.addWidget(self.memory_label)

        self.stats_timer = QTimer(self)
        self.stats_timer.timeout.connect(self.update_stats)
        self.stats_timer.start(1000) 

        self.setLayout(self.layout)

    def append_log(self, message):
        self.log_output.append(message)

    def update_stats(self):
        cpu_usage = psutil.cpu_percent()
        memory_usage = psutil.virtual_memory().percent
        self.cpu_label.setText(f"CPU Usage: {cpu_usage}%")
        self.memory_label.setText(f"Memory Usage: {memory_usage}%")

    def start_server(self):
        if not self.server_running:
            self.append_log("Starting server...")
            self.server_thread = threading.Thread(target=self.run_server)
            self.server_thread.daemon = True
            self.server_thread.start()
            self.server_running = True
        else:
            self.append_log("Server is already running.")

    def stop_server(self):
        if self.server_running:
            self.append_log("Stopping server...")
            self.server_running = False
        else:
            self.append_log("Server is not running.")

    def clear_logs(self):
        self.log_output.clear()

    def add_client(self, ip_address):
        row_position = self.client_table.rowCount()
        self.client_table.insertRow(row_position)
        self.client_table.setItem(row_position, 0, QTableWidgetItem(ip_address))
        self.client_table.setItem(row_position, 1, QTableWidgetItem(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

    def select_cert_file(self):
        cert_path, _ = QFileDialog.getOpenFileName(self, "Select Certificate File", "", "PEM Files (*.pem)")
        if cert_path:
            self.cert_input.setText(cert_path)

    def select_key_file(self):
        key_path, _ = QFileDialog.getOpenFileName(self, "Select Key File", "", "PEM Files (*.pem)")
        if key_path:
            self.key_input.setText(key_path)

    def create_self_signed_cert(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        cert.get_subject().CN = "localhost"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(31536000)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')

        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

        return cert_pem, key_pem

    def run_server(self):
        LHOST = self.ip_input.text()
        LPORT = int(self.port_input.text())

        cert_file = "certf/certificate.pem" 
        key_file = "certf/private_key.pem"  

        if not os.path.isfile(cert_file) or not os.path.isfile(key_file):
            self.append_log("Error: Default certificate or key not found in 'certf' folder.")
            return

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)

        try:
            httpd = HTTPServer((LHOST, LPORT), AdaptiveC2Handler)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

            self.append_log(f"[{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}] Server started on {LHOST}:{LPORT}")
            httpd.serve_forever()
        except Exception as e:
            self.append_log(f"Error starting server: {str(e)}")


def main():
    app = QApplication(sys.argv)
    c2_app = C2ServerApp()
    c2_app.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
