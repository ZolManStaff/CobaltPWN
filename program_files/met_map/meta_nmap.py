import sys
import subprocess
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QLabel, QTextEdit, QComboBox, QFileDialog, QDialog
from PyQt5.QtCore import Qt

class NmapMetasploitGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("MetaScan")
        self.setGeometry(100, 100, 800, 600)
        
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2e2e2e; 
            }
            QWidget {
                background-color: #2e2e2e; 
            }
            QLabel {
                color: #ffffff;
                font-size: 12pt;
            }
            QLineEdit, QTextEdit {
                background-color: #333333;
                color: #ffffff;
                border: 2px solid #FF0000;
                border-radius: 5px;
                padding: 5px;
                font-size: 11pt;
            }
            QPushButton {
                background-color: #FF0000; 
                color: #ffffff;
                border-radius: 5px;
                padding: 10px;
                font-size: 12pt;
                border: 2px solid #FF0000; 
            }
            QPushButton:hover {
                background-color: #cc0000; 
            }
            QComboBox {
                background-color: #333333;
                color: #ffffff;
                border: 2px solid #FF0000; 
                border-radius: 5px;
                padding: 5px;
            }
            QTextEdit {
                background-color: #333333;
                color: #ffffff;
                border: 2px solid #FF0000; 
                font-size: 10pt;
            }
            QTabWidget::pane {
                border: 2px solid #FF0000; 
            }
            QTabBar::tab {
                background-color: #333333;
                color: #ffffff;
                border: 2px solid #FF0000;
                padding: 10px;
            }
            QTabBar::tab:selected {
                background-color: #FF0000;
                color: #ffffff;
            }
            QTextEdit#log_window {
                height: 150px;
                background-color: #2e2e2e;
                color: #ffffff;
                border: 2px solid #FF0000;
                font-size: 10pt;
                border-radius: 5px;
            }
        """)

        self.tabs = QTabWidget(self)
        self.setCentralWidget(self.tabs)

        self.create_nmap_tab()
        self.create_metasploit_tab()
        self.create_extra_functions_tab()
        self.create_log_window()
        
        self.show()

    def create_nmap_tab(self):
        nmap_tab = QWidget()
        nmap_layout = QVBoxLayout()
        
        target_layout = QHBoxLayout()
        target_label = QLabel("Цель (IP):")
        self.target_input = QLineEdit()
        target_layout.addWidget(target_label)
        target_layout.addWidget(self.target_input)
        
        options_layout = QHBoxLayout()
        options_label = QLabel("Опции (например, -sP):")
        self.options_input = QLineEdit()
        options_layout.addWidget(options_label)
        options_layout.addWidget(self.options_input)
        
        scan_type_layout = QHBoxLayout()
        scan_type_label = QLabel("Тип сканирования:")
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["S", "T", "U", "A", "P", "F"])
        scan_type_layout.addWidget(scan_type_label)
        scan_type_layout.addWidget(self.scan_type_combo)

        self.nmap_button = QPushButton("START")
        self.nmap_button.clicked.connect(self.run_nmap)
        
        self.nmap_output = QTextEdit()
        self.nmap_output.setReadOnly(True)
        
        nmap_layout.addLayout(target_layout)
        nmap_layout.addLayout(options_layout)
        nmap_layout.addLayout(scan_type_layout)
        nmap_layout.addWidget(self.nmap_button)
        nmap_layout.addWidget(self.nmap_output)
        
        nmap_tab.setLayout(nmap_layout)
        self.tabs.addTab(nmap_tab, "Nmap")

    def create_metasploit_tab(self):
        metasploit_tab = QWidget()
        metasploit_layout = QVBoxLayout()

        exploit_layout = QHBoxLayout()
        exploit_label = QLabel("Эксплойт (например, exploit/windows/smb/ms17_010_eternalblue):")
        self.exploit_input = QLineEdit()
        exploit_layout.addWidget(exploit_label)
        exploit_layout.addWidget(self.exploit_input)

        target_layout = QHBoxLayout()
        target_label = QLabel("Цель (IP):")
        self.metasploit_target_input = QLineEdit()
        target_layout.addWidget(target_label)
        target_layout.addWidget(self.metasploit_target_input)

        payload_layout = QHBoxLayout()
        payload_label = QLabel("Payload (например, windows/meterpreter/reverse_tcp):")
        self.payload_input = QLineEdit()
        payload_layout.addWidget(payload_label)
        payload_layout.addWidget(self.payload_input)

        self.metasploit_button = QPushButton("START")
        self.metasploit_button.clicked.connect(self.run_metasploit)

        self.metasploit_output = QTextEdit()
        self.metasploit_output.setReadOnly(True)

        metasploit_layout.addLayout(exploit_layout)
        metasploit_layout.addLayout(target_layout)
        metasploit_layout.addLayout(payload_layout)
        metasploit_layout.addWidget(self.metasploit_button)
        metasploit_layout.addWidget(self.metasploit_output)

        metasploit_tab.setLayout(metasploit_layout)
        self.tabs.addTab(metasploit_tab, "Metasploit")

    def create_extra_functions_tab(self):
        extra_tab = QWidget()
        extra_layout = QVBoxLayout()

        self.report_button = QPushButton("Сканировать и сохранить отчет Nmap")
        self.report_button.clicked.connect(self.run_nmap_report)
        
        self.save_button = QPushButton("Сохранить отчет Metasploit")
        self.save_button.clicked.connect(self.save_metasploit_report)

        extra_layout.addWidget(self.report_button)
        extra_layout.addWidget(self.save_button)

        extra_tab.setLayout(extra_layout)
        self.tabs.addTab(extra_tab, "Дополнительные функции")

    def create_log_window(self):
        self.log_window = QTextEdit(self)
        self.log_window.setObjectName("log_window")
        self.log_window.setReadOnly(True)

        log_layout = QVBoxLayout()
        log_layout.addWidget(self.log_window)
        log_widget = QWidget(self)
        log_widget.setLayout(log_layout)
        log_widget.setGeometry(10, 480, 780, 100)
        self.setCentralWidget(self.tabs)

    def log_action(self, action):
        self.log_window.append(action)

    def run_nmap(self):
        target = self.target_input.text()
        options = self.options_input.text()
        scan_type = self.scan_type_combo.currentText()
        
        if not target:
            self.show_error("Ошибка", "Введите IP-адрес для сканирования")
            return
        
        try:
            command = f"nmap -s{scan_type} {options} {target}"
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            output = result.decode()
            self.nmap_output.setText(output)
            self.log_action(f"Запуск Nmap с командой: {command}\nРезультат: {output}")
        except subprocess.CalledProcessError as e:
            error_message = e.output.decode()
            self.show_error("Ошибка при выполнении Nmap", error_message)
            self.log_action(f"Ошибка при запуске Nmap: {error_message}")

    def run_metasploit(self):
        exploit = self.exploit_input.text()
        target = self.metasploit_target_input.text()
        payload = self.payload_input.text()

        if not exploit or not target or not payload:
            self.show_error("Ошибка", "Введите все необходимые данные для Metasploit")
            return

        try:
            command = f"msfconsole -x 'use {exploit}; set RHOSTS {target}; set PAYLOAD {payload}; run;'"
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            output = result.decode()
            self.metasploit_output.setText(output)
            self.log_action(f"Запуск Metasploit с командой: {command}\nРезультат: {output}")
        except subprocess.CalledProcessError as e:
            error_message = e.output.decode()
            self.show_error("Ошибка при выполнении Metasploit", error_message)
            self.log_action(f"Ошибка при запуске Metasploit: {error_message}")

    def run_nmap_report(self):
        target = self.target_input.text()
        
        if not target:
            self.show_error("Ошибка", "Введите IP-адрес для сканирования")
            return

        options = self.options_input.text()
        scan_type = self.scan_type_combo.currentText()
        
        try:
            file_dialog = QFileDialog(self)
            file_dialog.setDefaultSuffix(".txt")
            report_file, _ = file_dialog.getSaveFileName(self, "Сохранить отчет", "", "Текстовые файлы (*.txt);;Все файлы (*)")

            if report_file:
                command = f"nmap -s{scan_type} {options} {target} -oN {report_file}"
                subprocess.check_output(command, shell=True)
                self.show_info("Успех", "Отчет сохранен успешно!")
                self.log_action(f"Отчет Nmap сохранен в файл: {report_file}")
        except Exception as e:
            self.show_error("Ошибка", f"Не удалось сохранить отчет:\n{str(e)}")

    def save_metasploit_report(self):
        try:
            file_dialog = QFileDialog(self)
            file_dialog.setDefaultSuffix(".txt")
            report_file, _ = file_dialog.getSaveFileName(self, "Сохранить отчет Metasploit", "", "Текстовые файлы (*.txt);;Все файлы (*)")

            if report_file:
                with open(report_file, "w") as file:
                    file.write(self.metasploit_output.toPlainText())
                self.show_info("Успех", "Отчет Metasploit сохранен успешно!")
                self.log_action(f"Отчет Metasploit сохранен в файл: {report_file}")
        except Exception as e:
            self.show_error("Ошибка", f"Не удалось сохранить отчет Metasploit:\n{str(e)}")

    def show_error(self, title, message):
        error_message = f"{title}: {message}"
        self.metasploit_output.setText(error_message)
        self.nmap_output.setText(error_message)
        self.log_action(f"Ошибка: {error_message}")

    def show_info(self, title, message):
        messagebox = QDialog(self)
        messagebox.setWindowTitle(title)
        messagebox.setText(message)
        messagebox.exec_()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NmapMetasploitGUI()
    sys.exit(app.exec_())
