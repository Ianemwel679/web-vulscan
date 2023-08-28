import wx
import requests
import re
import threading
import xss_payloads
from sql_injection_payloads import sql_injection_payloads

class WebScannerThread(threading.Thread):
    def __init__(self, url_to_scan, frame):
        super().__init__()
        self.url_to_scan = url_to_scan
        self.frame = frame

    def run(self):
        self.analyze_response(self.url_to_scan)

    def scan_url(self, url):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.text
        except requests.RequestException as e:
            self.update_console(f"Error during request: {e}")
            return None

    def analyze_response(self, url_to_scan):
        found_xss_vulnerabilities = []
        found_sqli_vulnerabilities = []

        total_payloads = len(xss_payloads.xss_payloads) + len(sql_injection_payloads)

        # XSS Vulnerability Scanning
        for idx, payload in enumerate(xss_payloads.xss_payloads, start=1):
            injected_url = url_to_scan + payload
            response = self.scan_url(injected_url)

            if response and re.search(re.escape(payload), response):
                found_xss_vulnerabilities.append(payload)

            self.update_console(f"XSS Payload {idx}/{len(xss_payloads.xss_payloads)}: {payload}", wx.Colour(0, 128, 0))  # Dark Green color
            self.update_progress_bar(self.frame.xss_progress_bar, idx, total_payloads)

        # SQL Injection Vulnerability Scanning
        for idx, payload in enumerate(sql_injection_payloads, start=1):
            injected_url = url_to_scan + payload
            response = self.scan_url(injected_url)

            if response and "error" in response.lower():
                found_sqli_vulnerabilities.append(f"SQL Injection Payload {idx}/{len(sql_injection_payloads)}: {payload}")

            self.update_console(f"SQLi Payload {idx}/{len(sql_injection_payloads)}: {payload}", wx.Colour(0, 128, 0))  # Dark Green color
            self.update_progress_bar(self.frame.sqli_progress_bar, idx + len(xss_payloads.xss_payloads), total_payloads)

        vulnerabilities = {
            "XSS": found_xss_vulnerabilities,
            "SQL Injection": found_sqli_vulnerabilities
        }

        wx.CallAfter(self.show_result_message, vulnerabilities)

    def update_console(self, text, color):
        wx.CallAfter(self.frame.console_text.SetDefaultStyle, wx.TextAttr(color))
        wx.CallAfter(self.frame.console_text.AppendText, text + '\n')
        wx.CallAfter(self.frame.console_text.SetDefaultStyle, wx.TextAttr(wx.BLACK))  # Reset to black color

    def update_progress_bar(self, progress_bar, current_payload, total_payloads):
        progress = int((current_payload / total_payloads) * 100)
        wx.CallAfter(progress_bar.SetValue, progress)

    def show_result_message(self, vulnerabilities):
        message = ""
        for vuln_type, vulns in vulnerabilities.items():
            if vulns:
                message += f"{vuln_type} vulnerabilities found:\n\n"
                for vuln in vulns:
                    message += f"{vuln}\n"
                message += "\n"

        if message:
            wx.MessageBox(message, "Vulnerabilities Found", wx.OK | wx.ICON_WARNING)
        else:
            wx.MessageBox("No vulnerabilities found.", "Scan Result", wx.OK | wx.ICON_INFORMATION)
        self.frame.scan_button.Enable()

class WebScannerApp(wx.App):
    def OnInit(self):
        global window
        window = WebScannerFrame(None, title="Web Vulnerability Scanner")
        self.SetTopWindow(window)
        window.Show(True)
        return True

class WebScannerFrame(wx.Frame):
    def __init__(self, *args, **kw):
        super(WebScannerFrame, self).__init__(*args, **kw)

        self.panel = wx.Panel(self)
        self.sizer = wx.BoxSizer(wx.VERTICAL)

        self.url_label = wx.StaticText(self.panel, label="Enter URL:")
        self.url_entry = wx.TextCtrl(self.panel, style=wx.TE_PROCESS_ENTER)
        self.scan_button = wx.Button(self.panel, label="Scan")
        self.xss_progress_bar = wx.Gauge(self.panel)
        self.sqli_progress_bar = wx.Gauge(self.panel)

        self.console_label = wx.StaticText(self.panel, label="Scan Progress:")
        self.console_text = wx.TextCtrl(self.panel, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.HSCROLL)

        self.sizer.Add(self.url_label, 0, wx.ALL, 5)
        self.sizer.Add(self.url_entry, 0, wx.ALL | wx.EXPAND, 5)
        self.sizer.Add(self.scan_button, 0, wx.ALL | wx.ALIGN_CENTER, 5)
        self.sizer.Add(self.xss_progress_bar, 0, wx.ALL | wx.EXPAND, 5)
        self.sizer.Add(self.sqli_progress_bar, 0, wx.ALL | wx.EXPAND, 5)
        self.sizer.Add(self.console_label, 0, wx.ALL, 5)
        self.sizer.Add(self.console_text, 1, wx.ALL | wx.EXPAND, 5)

        self.panel.SetSizerAndFit(self.sizer)

        self.scan_button.Bind(wx.EVT_BUTTON, self.scan_button_clicked)
        self.url_entry.Bind(wx.EVT_TEXT_ENTER, self.scan_button_clicked)

    def scan_button_clicked(self, event):
        url_to_scan = self.url_entry.GetValue()
        self.scan_button.Disable()
        self.console_text.Clear()
        self.xss_progress_bar.SetValue(0)
        self.sqli_progress_bar.SetValue(0)

        self.console_text.AppendText("Starting scan...\n")

        worker_thread = WebScannerThread(url_to_scan, self)
        worker_thread.start()

if __name__ == "__main__":
    app = WebScannerApp(False)
    app.MainLoop()
