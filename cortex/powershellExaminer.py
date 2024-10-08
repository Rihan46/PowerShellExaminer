#!/usr/bin/env python3
import re
import json
import subprocess
from cortexutils.analyzer import Analyzer

# Load patterns
with open("./powershell_code_patterns.json", "r") as f:
    powershell_code_patterns = json.load(f)

class PowerShellExaminerAnalyzer(Analyzer):
    def __init__(self):
        super().__init__()
        self.strings_param = "--all"

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
        self.scan_patterns(target_file)
        self.extract_urls(target_file)
        self.extract_domains(target_file)
        self.extract_file_paths(target_file)
        self.extract_ip_addresses(target_file)
        self.extract_files(target_file)

    def scan_patterns(self, target_file):
        results = {}
        for pat in powershell_code_patterns:
            occurrence = 0
            for code in powershell_code_patterns[pat]["patterns"]:
                matches = re.findall(code, str(self.all_strings), re.IGNORECASE)
                occurrence += len(matches)
            if occurrence > 0:
                results[pat] = occurrence
        self.report({'patterns': results})

    def extract_urls(self, target_file):
        url_pattern = r'(https?://[^\s/$.?#].[^\s]*)'
        urls = re.findall(url_pattern, str(self.all_strings), re.IGNORECASE)
        self.report({'urls': list(set(urls))})

    def extract_domains(self, target_file):
        domain_pattern = r'\b(?:[a-zA-Z0-9-]{2,}\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, str(self.all_strings), re.IGNORECASE)
        self.report({'domains': list(set(domains))})

    def extract_file_paths(self, target_file):
        file_path_pattern = r'\b[A-Za-z][A-Za-z0-9]*:\\[^\s\'"]*\b'
        file_paths = re.findall(file_path_pattern, str(self.all_strings), re.IGNORECASE)
        self.report({'file_paths': list(set(file_paths))})

    def extract_ip_addresses(self, target_file):
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_addresses = re.findall(ip_pattern, str(self.all_strings), re.IGNORECASE)
        self.report({'ip_addresses': list(set(ip_addresses))})

    def extract_files(self, target_file):
        file_patterns = r'\b(?:[a-zA-Z0-9._%+-]+(?:\.exe|\.dll|\.scr|\.bat|\.cmd|\.vbs|\.ps1|\.psm1|\.psd1|\.php|\.js|\.jse|\.wsf|\.wsh|\.hta|\.inf|\.pif|\.vbe|\.vb|\.bas|\.sh|\.jar|\.asec|\.lnk|\.b64|\.msi|\.msp|\.rtf|\.doc|\.docx|\.xlsx|\.pdf|\.zip|\.rar|\.iso|\.7z)\b)'
        files = re.findall(file_patterns, str(self.all_strings), re.IGNORECASE)
        self.report({'files': list(set(files))})

    def report_results(self):
        # Collect all results and report them
        # Example placeholder for any additional result reporting
        self.report({"status": "Analysis complete"})

if __name__ == "__main__":
    PowerShellExaminerAnalyzer().run()
