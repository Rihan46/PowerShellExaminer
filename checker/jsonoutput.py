import re
import sys
import json
import subprocess
import argparse

# Configuring strings parameter and making compatibility adjustments
strings_param = "--all"
if sys.platform == "darwin":
    strings_param = "-a"
elif sys.platform == "win32":
    strings_param = "-a"

# Load patterns from JSON file
powershell_code_patterns = json.load(open("./powershell_code_patterns.json"))

class PowerShellAnalyzer:
    def __init__(self, target_files):
        self.target_files = target_files
        self.results = {}

    def scan_code_patterns(self):
        for target_file in self.target_files:
            self.results[target_file] = {}
            self.target_buffer_normal = subprocess.run(
                ["strings", strings_param, target_file], stderr=subprocess.PIPE, stdout=subprocess.PIPE
            )
            if sys.platform != "win32":
                self.target_buffer_16bit = subprocess.run(
                    ["strings", strings_param, "-e", "l", target_file], stderr=subprocess.PIPE, stdout=subprocess.PIPE
                )
                self.all_strings = self.target_buffer_16bit.stdout.decode().split("\n") + \
                                   self.target_buffer_normal.stdout.decode().split("\n")
            else:
                self.all_strings = self.target_buffer_normal.stdout.decode().split("\n")

            self.scan_patterns(target_file)
            self.extract_urls(target_file)
            self.extract_domains(target_file)
            self.extract_file_paths(target_file)
            self.extract_ip_addresses(target_file)
            self.extract_files(target_file)

        # Print the results as JSON
        print(json.dumps(self.results, indent=4))

    def scan_patterns(self, target_file):
        self.results[target_file]['patterns'] = {}
        for pat in powershell_code_patterns:
            pattern_matches = []
            for code in powershell_code_patterns[pat]["patterns"]:
                matches = re.findall(code, str(self.all_strings), re.IGNORECASE)
                if matches:
                    pattern_matches.append(code)
                    powershell_code_patterns[pat]["occurence"] += 1

            if pattern_matches:
                self.results[target_file]['patterns'][pat] = pattern_matches

    def extract_urls(self, target_file):
        url_pattern = r'(https?://[^\s/$.?#].[^\s]*)'
        urls = re.findall(url_pattern, str(self.all_strings), re.IGNORECASE)
        if urls:
            self.results[target_file]['urls'] = list(set(urls))

    def extract_domains(self, target_file):
        domain_pattern = r'\b(?:[a-zA-Z0-9-]{2,}\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, str(self.all_strings), re.IGNORECASE)
        if domains:
            self.results[target_file]['domains'] = list(set(domains))

    def extract_file_paths(self, target_file):
        file_path_pattern = r'\b[A-Za-z][A-Za-z0-9]*:\\[^\s\'"]*\b'
        file_paths = re.findall(file_path_pattern, str(self.all_strings), re.IGNORECASE)
        if file_paths:
            self.results[target_file]['file_paths'] = list(set(file_paths))

    def extract_ip_addresses(self, target_file):
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_addresses = re.findall(ip_pattern, str(self.all_strings), re.IGNORECASE)
        if ip_addresses:
            self.results[target_file]['ip_addresses'] = list(set(ip_addresses))

    def extract_files(self, target_file):
        file_patterns = r'\b(?:[a-zA-Z0-9._%+-]+(?:\.exe|\.dll|\.scr|\.bat|\.cmd|\.vbs|\.ps1|\.psm1|\.psd1|\.php|\.js|\.jse|\.wsf|\.wsh|\.hta|\.inf|\.pif|\.vbe|\.vb|\.bas|\.sh|\.jar|\.asec|\.lnk|\.b64|\.msi|\.msp|\.rtf|\.doc|\.docx|\.xlsx|\.pdf|\.zip|\.rar|\.iso|\.7z)\b)'
        files = re.findall(file_patterns, str(self.all_strings), re.IGNORECASE)
        if files:
            self.results[target_file]['files'] = list(set(files))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PowerShell Malicious Script Analyzer")
    parser.add_argument("target_files", nargs='+', help="Paths to the PowerShell scripts to analyze")
    args = parser.parse_args()
    analyzer = PowerShellAnalyzer(target_files=args.target_files)
    analyzer.scan_code_patterns()
