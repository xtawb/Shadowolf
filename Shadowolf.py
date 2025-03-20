#!/usr/bin/env python3
"""
ShadowWolf - Real-Time Internal Network Guardian
Author: xtawb
License: MIT
"""

import argparse
import sys
import threading
from datetime import datetime
from scapy.all import ARP, Ether, srp, arping
import nmap
from fpdf import FPDF
from colorama import Fore, Style, init

init(autoreset=True)


class ShadowWolf:
    def __init__(self, target):
        self.target = target
        self.report_data = []
        self.lock = threading.Lock()
        self.oui_db = self._load_oui_database()
        self.weak_credentials = {
            'ssh': ['admin:admin', 'root:root'],
            'ftp': ['anonymous:anonymous']
        }

    def _load_oui_database(self):
        """Load MAC vendor database"""
        return {
            # Virtualization & Cloud Providers
            '00:0C:29': 'VMware',
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:05:69': 'Xen',
            '52:54:00': 'QEMU/KVM',
            '00:16:3E': 'Xen',
            '00:15:5D': 'Hyper-V',
            '42:01:0A': 'Docker',
            '02:42:AC': 'Docker',

            # Raspberry Pi & IoT Devices
            'DC:A6:32': 'Raspberry Pi',
            'B8:27:EB': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi',
            '00:0C:42': 'MikroTik',
            'AC:64:62': 'Aruba Networks',

            # Network & Security Vendors
            '00:1A:2B': 'Cisco',
            '00:25:90': 'Cisco',
            '00:23:04': 'Cisco',
            '00:1E:49': 'Cisco',
            'F4:CE:46': 'Cisco Meraki',
            'CC:46:D6': 'Ubiquiti',
            'E0:63:DA': 'Ubiquiti',
            '4C:5E:0C': 'Fortinet',
            '00:60:2F': 'Juniper Networks',
            '00:04:96': 'Extreme Networks',

            # PC & Laptop Vendors
            '00:1E:65': 'HP',
            '08:2E:5F': 'HP',
            'C4:34:6B': 'HP',
            '00:23:24': 'Dell',
            '00:14:22': 'Dell',
            'F0:1F:AF': 'Dell',
            'D4:BE:D9': 'Lenovo',
            '28:D2:44': 'Lenovo',
            'E8:2A:EA': 'Acer',
            '20:6A:8A': 'Acer',
            '00:26:B9': 'Toshiba',
            '5C:F9:38': 'Asus',

            # Mobile Devices
            'FC:FB:FB': 'Apple',
            'D0:17:C2': 'Apple',
            '00:17:9A': 'Apple',
            'F8:FF:C2': 'Intel',
            '00:21:86': 'Intel',
            '60:A4:4C': 'Huawei',
            '84:A1:D1': 'Huawei',
            'F4:8C:50': 'Xiaomi',
            '28:6D:CD': 'Samsung',
            '5C:0A:5B': 'Samsung',
            'A0:0B:BA': 'Oppo',
            '70:2C:1F': 'OnePlus',
            'AC:DE:48': 'Realme',
            '48:D2:24': 'Vivo',

            # Smart Home & IoT
            '40:16:7E': 'Amazon Echo',
            '44:65:0D': 'Amazon Echo',
            '68:54:FD': 'Google Nest',
            'F4:03:04': 'Google Nest',
            '90:DD:5D': 'Sonos',
            '00:12:FB': 'Philips Hue',
            'A4:C1:38': 'Tuya Smart',

            # Gaming Consoles
            '78:2B:44': 'PlayStation',
            '30:59:B7': 'Xbox',
            '00:22:48': 'Nintendo',
            'B8:CA:3A': 'Nintendo Switch',
            '04:A3:16': 'Valve Steam Deck',

            # TV & Streaming Devices
            'F8:1A:67': 'Roku',
            'D0:27:88': 'Chromecast',
            '38:8B:59': 'Amazon Fire TV',
            '28:EF:01': 'Samsung Smart TV',
            '00:0D:67': 'LG Smart TV',
            'EC:02:9A': 'Sony Bravia TV',

            # Routers & Networking
            'C8:3A:35': 'TP-Link',
            '50:C7:BF': 'TP-Link',
            'D8:0D:17': 'Netgear',
            'A4:91:B1': 'Netgear',
            '00:17:3F': 'Linksys',
            '18:E8:29': 'D-Link',
            '00:15:E9': 'Zyxel',

            # Industrial & Enterprise
            'A0:36:9F': 'Siemens',
            '00:1E:C0': 'Schneider Electric',
            '00:80:64': 'Bosch',
            '00:40:9D': 'Honeywell',
            'F0:9F:C2': 'General Electric',
        }

    def print_banner(self):
        """Display ASCII art banner"""
        banner = f"""{Fore.MAGENTA}
 .-. .   .    .    .--.  .--..  .   .  ..  .   .  ..--. .    .---.
(   )|   |   / \\   |   ::    :\\  \\ /  /  \\  \\ /  /:    :|    |    
 `-. |---|  /___\\  |   ||    | \\  \\  /    \\  \\  / |    ||    |--- 
(   )|   | /     \\ |   ;:    ;  \\/ \\/      \\/ \\/  :    ;|    |    
 `-' '   ''       `'--'  `--'    ' '        ' '    `--' '---''    
{Style.RESET_ALL}{Fore.CYAN}
Internal Network Sentinel | v1.0.0 | Real-Time Protection
Contact: https://linktr.ee/xtawb
Github : https://github.com/xtawb
        """
        print(banner)

    def _live_alert(self, color, prefix, message):
        """Display real-time results with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        with self.lock:
            print(f"{color}[{timestamp}] {Fore.WHITE}[{prefix}]{Style.RESET_ALL} {message}")

    def lightning_arp_scan(self):
        """Lightning-fast ARP scan"""
        try:
            ans, _ = arping(self.target, verbose=0)
            for snd, rcv in ans:
                vendor = self._get_mac_vendor(rcv.hwsrc)
                msg = f"{rcv.psrc} ({rcv.hwsrc}) - {vendor}"
                self._live_alert(Fore.GREEN, "DEVICE", msg)
                self._add_data('Device', msg)
        except Exception as e:
            self._live_alert(Fore.RED, "ERROR", f"ARP Scan Failed: {str(e)}")

    def os_fingerprint(self):
        """OS fingerprinting"""
        try:
            nm = nmap.PortScanner()
            nm.scan(self.target, arguments='-O')
            for host in nm.all_hosts():
                os_info = nm[host]['osmatch'][0]['name'] if nm[host]['osmatch'] else 'Unknown'
                msg = f"{host} - OS: {os_info}"
                self._live_alert(Fore.YELLOW, "OS", msg)
                self._add_data('OS', msg)
        except Exception as e:
            self._live_alert(Fore.RED, "ERROR", f"OS Detection Failed: {str(e)}")

    def vulnerability_assessment(self):
        """Vulnerability assessment by severity"""
        severity_colors = {
            'Critical': Fore.RED,
            'High': Fore.MAGENTA,
            'Medium': Fore.YELLOW,
            'Low': Fore.CYAN
        }

        try:
            nm = nmap.PortScanner()
            nm.scan(self.target, arguments='-T4 --script vulners')

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]
                        vulns = service.get('script', {})
                        for vuln in vulns.get('vulners', '').split('\n'):
                            if 'CVE' in vuln:
                                severity = self._get_severity(vuln)
                                color = severity_colors.get(severity, Fore.WHITE)
                                msg = f"{host}:{port} - {vuln}"
                                self._live_alert(color, severity.upper(), msg)
                                self._add_data(severity, msg)
        except Exception as e:
            self._live_alert(Fore.RED, "ERROR", f"Vulnerability Scan Failed: {str(e)}")

    def detect_weak_devices(self):
        """Detect devices with weak configurations"""
        try:
            nm = nmap.PortScanner()
            nm.scan(self.target, arguments='-p 21,22,23 -sV')

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]['name']
                        if service in self.weak_credentials:
                            msg = f"{host}:{port} - Weak {service.upper()} config detected!"
                            self._live_alert(Fore.RED, "WEAK", msg)
                            self._add_data('Weakness', msg)
        except Exception as e:
            self._live_alert(Fore.RED, "ERROR", f"Weak Device Scan Failed: {str(e)}")

    def generate_report(self, filename):
        """Generate a detailed PDF report"""
        try:
            pdf = FPDF()
            pdf.add_page()

            # Set up fonts
            pdf.set_font("Arial", size=12)  # Set font family and size

            # Header
            pdf.set_fill_color(60, 60, 60)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(200, 10, txt="ShadowWolf Network Report", ln=True, align='C', fill=True)

            # Body
            pdf.set_text_color(0, 0, 0)
            categories = ['Critical', 'High', 'Medium', 'Low', 'Device', 'OS', 'Weakness']

            for category in categories:
                # Bold font for headers
                pdf.set_font("Arial", style='B', size=12)
                pdf.cell(0, 10, txt=f"===== {category} =====", ln=True)
                pdf.set_font("Arial", size=10)  # Normal font for details
                for entry in [e for e in self.report_data if e['type'] == category]:
                    pdf.multi_cell(0, 8, txt=entry['info'])

            pdf.output(filename)
            self._live_alert(Fore.GREEN, "REPORT", f"Saved to {filename}")
        except Exception as e:
            self._live_alert(Fore.RED, "ERROR", f"Report Generation Failed: {str(e)}")

    def _get_severity(self, vuln):
        """Determine vulnerability severity"""
        vuln = vuln.lower()
        if 'critical' in vuln:
            return 'Critical'
        if 'high' in vuln:
            return 'High'
        if 'medium' in vuln:
            return 'Medium'
        return 'Low'

    def _get_mac_vendor(self, mac):
        """Get vendor from MAC address"""
        prefix = mac[:8].upper()
        return self.oui_db.get(prefix, 'Unknown')

    def _add_data(self, data_type, info):
        """Add data to report"""
        with self.lock:
            self.report_data.append({'type': data_type, 'info': info})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ShadowWolf - Internal Network Security Sentinel",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""Examples:
  {sys.argv[0]} 192.168.1.0/24 --arp --vuln
  {sys.argv[0]} 192.168.1.0/24 --full
  {sys.argv[0]} 192.168.1.0/24 --weak"""
    )

    parser.add_argument("target", help="Network target (CIDR or IP)")
    parser.add_argument("--arp", action='store_true', help="Lightning-fast ARP scan")
    parser.add_argument("--os", action='store_true', help="OS fingerprinting")
    parser.add_argument("--vuln", action='store_true', help="Vulnerability assessment")
    parser.add_argument("--weak", action='store_true', help="Detect weak devices")
    parser.add_argument("--full", action='store_true', help="Full network audit")
    parser.add_argument("--output", default="wolf_report.pdf", help="Output filename")

    args = parser.parse_args()

    wolf = ShadowWolf(args.target)
    wolf.print_banner()

    try:
        if args.arp or args.full:
            wolf.lightning_arp_scan()

        if args.os or args.full:
            wolf.os_fingerprint()

        if args.vuln or args.full:
            wolf.vulnerability_assessment()

        if args.weak or args.full:
            wolf.detect_weak_devices()

        wolf.generate_report(args.output)

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan aborted by user{Style.RESET_ALL}")
        sys.exit(1)
