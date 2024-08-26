#!/usr/bin/env python3
import re
import json
import subprocess
import os
from cortexutils.analyzer import Analyzer

# Load patterns
with open("./powershell_code_patterns.json", "r") as f:
    powershell_code_patterns = json.load(f)

class PowerShellExaminerAnalyzer(Analyzer):
    def __init__(self):
        super().__init__()
        self.strings_param = "--all"
        self.results = {}

    def run(self):
        # Get the file path from the parameters
        target_file = self.get_param("file", None)
        
        # Check if the file path was provided
        if not target_file:
            self.report({"error": "No file provided"})
            return
        
        # Verify file existence
        if not os.path.isfile(target_file):
            self.report({"error": f"File does not exist: {target_file}"})
            return

        # Perform analysis
        self.scan_code_patterns(target_file)
        self.report_results()

    def scan_code_patterns(self, target_file):
        self.target_buffer_normal = subprocess.run(
            ["strings", self.strings_param, target_file],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        self.all_strings = self.target_buffer_normal.stdout.decode().split("\n")

        # Perform analysis
        self.scan_patterns()
        self.extract_urls()
        self.extract_domains()
        self.extract_file_paths()
        self.extract_ip_addresses()
        self.extract_files()

    def scan_patterns(self):
    pattern_results = {}
    for pat in powershell_code_patterns:
        matched_values = []
        for code in powershell_code_patterns[pat]["patterns"]:
            matches = re.findall(code, str(self.all_strings), re.IGNORECASE)
            matched_values.extend(matches)
        if matched_values:
            pattern_results[pat] = matched_values
            self.results['patterns'] = pattern_results

    def extract_urls(self):
        url_pattern = r'(https?://[^\s/$.?#].[^\s]*)'
        urls = re.findall(url_pattern, str(self.all_strings), re.IGNORECASE)
        self.results['urls'] = list(set(urls))

    def extract_domains(self):
        domain_pattern = r'\b(?:[a-zA-Z0-9-]{2,}\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, str(self.all_strings), re.IGNORECASE)
        self.results['domains'] = list(set(domains))

    def extract_file_paths(self):
        file_path_pattern = r'\b[A-Za-z][A-Za-z0-9]*:\\[^\s\'"]*\b'
        file_paths = re.findall(file_path_pattern, str(self.all_strings), re.IGNORECASE)
        self.results['file_paths'] = list(set(file_paths))

    def extract_ip_addresses(self):
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_addresses = re.findall(ip_pattern, str(self.all_strings), re.IGNORECASE)
        self.results['ip_addresses'] = list(set(ip_addresses))

    def extract_files(self):
        file_patterns = r'\b(?:[a-zA-Z0-9._%+-]+(?:\.exe|\.dll|\.scr|\.bat|\.cmd|\.vbs|\.ps1|\.psm1|\.psd1|\.php|\.js|\.jse|\.wsf|\.wsh|\.hta|\.inf|\.pif|\.vbe|\.vb|\.bas|\.sh|\.jar|\.asec|\.lnk|\.b64|\.msi|\.msp|\.rtf|\.doc|\.docx|\.xlsx|\.pdf|\.zip|\.rar|\.iso|\.7z)\b)'
        files = re.findall(file_patterns, str(self.all_strings), re.IGNORECASE)
        self.results['files'] = list(set(files))

    def report_results(self):
        # Report all collected results
        self.report(self.results)

if __name__ == "__main__":
    PowerShellExaminerAnalyzer().run()
