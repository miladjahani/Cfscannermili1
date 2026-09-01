import subprocess
import threading
import time
import re
import ipaddress
from kivymd.app import MDApp
from kivymd.uix.screen import MDScreen
from kivymd.uix.list import TwoLineRightIconListItem, IconRightWidget
from kivy.lang import Builder
from kivy.clock import Clock

KV = '''
MDScreen:
    md_bg_color: 0.95, 0.95, 0.98, 1

    MDBoxLayout:
        orientation: 'vertical'

        MDTopAppBar:
            title: "Cloudflare Speed Test"
            anchor_title: "center"
            elevation: 3
            specific_text_color: 1, 1, 1, 1
            md_bg_color: 0.2, 0.4, 0.8, 1

        MDBoxLayout:
            orientation: 'vertical'
            padding: "20dp"
            spacing: "20dp"
            size_hint_y: 0.35

            MDCard:
                orientation: 'vertical'
                padding: "10dp"
                size_hint: 1, None
                height: "140dp"
                elevation: 1
                radius: [15, 15, 15, 15]

                MDIcon:
                    icon: "cloud"
                    pos_hint: {"center_x": .5}
                    font_size: "48sp"
                    theme_text_color: "Custom"
                    text_color: 0.2, 0.5, 0.9, 1
                
                MDLabel:
                    text: "پیدا کردن بهترین آی‌پی"
                    halign: "center"
                    theme_text_color: "Secondary"
                    font_style: "Caption"
                    margin_top: "10dp"

                MDTextField:
                    id: cidr_input
                    text: "104.16.105.0/24"
                    halign: "center"
                    font_size: "18sp"
                    size_hint_x: 0.8
                    pos_hint: {"center_x": .5}
            
            MDRaisedButton:
                id: scan_btn
                text: "شروع تست"
                font_name: "Roboto"
                size_hint_x: 1
                md_bg_color: 0.2, 0.4, 0.8, 1
                on_release: app.start_scan()
                elevation: 2

        MDScrollView:
            MDList:
                id: results_list
'''

class ResultItem(TwoLineRightIconListItem):
    pass

class CloudflareScanner(MDApp):
    def build(self):
        self.theme_cls.theme_style = "Light"
        self.theme_cls.primary_palette = "Blue"
        return Builder.load_string(KV)

    def start_scan(self):
        cidr = self.root.ids.cidr_input.text
        self.root.ids.results_list.clear_widgets()
        self.root.ids.scan_btn.text = "در حال اسکن..."
        self.root.ids.scan_btn.disabled = True
        
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            ips = [str(ip) for ip in network.hosts()][:20]
        except Exception:
            self.root.ids.scan_btn.text = "رنج نامعتبر!"
            self.root.ids.scan_btn.disabled = False
            return
            
        threading.Thread(target=self.scan_network, args=(ips,), daemon=True).start()

    def scan_network(self, ips):
        results = []
        for ip in ips:
            ping_ms = self.ping_ip(ip)
            if ping_ms:
                results.append((ip, ping_ms))
        
        results.sort(key=lambda x: x[1])
        Clock.schedule_once(lambda dt: self.update_ui(results))

    def ping_ip(self, ip):
        try:
            proc = subprocess.Popen(['ping', '-c', '1', '-W', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate()
            output = out.decode('utf-8')
            match = re.search(r'time=([\d\.]+)\s*ms', output)
            if match:
                return float(match.group(1))
        except Exception:
            pass
        return None

    def update_ui(self, results):
        self.root.ids.scan_btn.text = "شروع تست"
        self.root.ids.scan_btn.disabled = False
        
        for ip, ping in results:
            item = TwoLineRightIconListItem(
                text=f"{ip}",
                secondary_text=f"Ping: {ping} ms",
            )
            icon = IconRightWidget(icon="check-circle", theme_text_color="Custom", text_color=(0, 0.8, 0, 1))
            item.add_widget(icon)
            self.root.ids.results_list.add_widget(item)

if __name__ == "__main__":
    CloudflareScanner().run()
