import re
import sys
import json
import subprocess
import argparse

try:
    from rich import print
    from rich.table import Table
except ImportError:
    print("Error: >rich< module not found.")
    sys.exit(1)

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Configurating strings parameter and make compatibility
strings_param = "--all"
if sys.platform == "darwin":
    strings_param = "-a"
elif sys.platform == "win32":
    strings_param = "-a"
else:
    pass

# Load patterns

powershell_code_patterns = json.load(open("./powershell_code_patterns.json"))

class PowerShellAnalyzer:
    def __init__(self, target_files):
        self.target_files = target_files

    def scan_code_patterns(self):
        for target_file in self.target_files:
            print(f"{infoS} Scanning file: [bold green]{target_file}[white]")
            self.target_buffer_normal = subprocess.run(["strings", strings_param, target_file], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            if sys.platform != "win32":
                self.target_buffer_16bit = subprocess.run(["strings", strings_param, "-e", "l", target_file], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                self.all_strings = self.target_buffer_16bit.stdout.decode().split("\n") + self.target_buffer_normal.stdout.decode().split("\n")
            else:
                self.all_strings = self.target_buffer_normal.stdout.decode().split("\n")

            self.scan_patterns(target_file)
            self.extract_urls(target_file)
            self.extract_domains(target_file)
            self.extract_file_paths(target_file)
            self.extract_ip_addresses(target_file)
            self.extract_files(target_file)

    def scan_patterns(self, target_file):
        for pat in powershell_code_patterns:
            pat_table = Table()
            pat_table.add_column(f"Extracted patterns about [bold green]{pat}[white] in [bold green]{target_file}[white]", justify="center")
            for code in powershell_code_patterns[pat]["patterns"]:
                matchh = re.findall(code, str(self.all_strings), re.IGNORECASE)
                if matchh:
                    pat_table.add_row(code)
                    powershell_code_patterns[pat]["occurence"] += 1
            if powershell_code_patterns[pat]["occurence"]:
                print(pat_table)

    def extract_urls(self, target_file):
        url_pattern = r'(https?://[^\s/$.?#].[^\s]*)'
        urls = re.findall(url_pattern, str(self.all_strings), re.IGNORECASE)
        if urls:
            url_table = Table()
            url_table.add_column(f"Extracted URLs from [bold green]{target_file}[white]", justify="center")
            for url in set(urls):  # Use set to avoid duplicates
                url_table.add_row(url)
            print(f"\n{infoS} Extracting URLs from [bold green]{target_file}[white]...")
            print(url_table)
        else:
            print(f"{errorS} No URLs found in [bold green]{target_file}[white].\n")

    def extract_domains(self, target_file):
        domain_pattern = r'\b(?:[a-zA-Z0-9-]{2,}\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, str(self.all_strings), re.IGNORECASE)
        if domains:
            domain_table = Table()
            domain_table.add_column(f"Extracted Domains from [bold green]{target_file}[white]", justify="center")
            for domain in set(domains):  # Use set to avoid duplicates
                domain_table.add_row(domain)
            print(f"\n{infoS} Extracting Domains from [bold green]{target_file}[white]...")
            print(domain_table)
        else:
            print(f"{errorS} No Domains found in [bold green]{target_file}[white].\n")

    def extract_file_paths(self, target_file):
        file_path_pattern = r'\b[A-Za-z][A-Za-z0-9]*:\\[^\s\'"]*\b'
        file_paths = re.findall(file_path_pattern, str(self.all_strings), re.IGNORECASE)
        if file_paths:
            file_path_table = Table()
            file_path_table.add_column(f"Extracted File Paths from [bold green]{target_file}[white]", justify="center")
            for file_path in set(file_paths):  # Use set to avoid duplicates
                file_path_table.add_row(file_path)
            print(f"\n{infoS} Extracting File Paths from [bold green]{target_file}[white]...")
            print(file_path_table)
        else:
            print(f"{errorS} No File Paths found in [bold green]{target_file}[white].\n")

    def extract_ip_addresses(self, target_file):
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_addresses = re.findall(ip_pattern, str(self.all_strings), re.IGNORECASE)
        if ip_addresses:
            ip_table = Table()
            ip_table.add_column(f"Extracted IP Addresses from [bold green]{target_file}[white]", justify="center")
            for ip in set(ip_addresses):  # Use set to avoid duplicates
                ip_table.add_row(ip)
            print(f"\n{infoS} Extracting IP Addresses from [bold green]{target_file}[white]...")
            print(ip_table)
        else:
            print(f"{errorS} No IP Addresses found in [bold green]{target_file}[white].\n")

    def extract_files(self, target_file):
        # Define regex pattern for matching common file extensions
        file_patterns = r'\b(?:[a-zA-Z0-9._%+-]+(?:\.exe|\.dll|\.scr|\.bat|\.cmd|\.vbs|\.ps1|\.psm1|\.psd1|\.php|\.js|\.jse|\.wsf|\.wsh|\.hta|\.inf|\.pif|\.vbe|\.vb|\.bas|\.sh|\.jar|\.asec|\.lnk|\.b64|\.msi|\.msp|\.rtf|\.doc|\.docx|\.xlsx|\.pdf|\.zip|\.rar|\.iso|\.7z)\b)'

        # Extract file paths based on the pattern
        files = re.findall(file_patterns, str(self.all_strings), re.IGNORECASE)
        
        if files:
            file_table = Table()
            file_table.add_column(f"Extracted Files from [bold green]{target_file}[white]", justify="center")
            for file in set(files):  # Use set to avoid duplicates
                file_table.add_row(file)
            print(f"\n{infoS} Extracting Files from [bold green]{target_file}[white]...")
            print(file_table)
        else:
            print(f"{errorS} No Files found in [bold green]{target_file}[white].\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PowerShell Malicious Script Analyzer")
    parser.add_argument("target_files", nargs='+', help="Paths to the PowerShell scripts to analyze")
    args = parser.parse_args()
    analyzer = PowerShellAnalyzer(target_files=args.target_files)
    analyzer.scan_code_patterns()
