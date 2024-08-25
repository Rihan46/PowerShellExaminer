from cortexutils.analyzer import Analyzer
import os
import re
import json
import subprocess

# Load patterns
patterns_file = "./powershell_code_patterns.json"
with open(patterns_file, "r") as f:
    powershell_code_patterns = json.load(f)

class PowerShellExaminerAnalyzer(Analyzer):
    def __init__(self):
        super().__init__()

    def run(self):
        # Get the file parameter
        target_file = self.get_param("file", None)
        
        # Check if the file path was provided
        if not target_file:
            self.report({"error": "No file provided"})
            return
        
        # Verify file existence
        if not os.path.isfile(target_file):
            self.report({"error": f"File does not exist: {target_file}"})
            return

        # Process the file
        results = self.scan_code_patterns(target_file)
        
        # Report results
        self.report(results)

    def scan_code_patterns(self, target_file):
        self.target_buffer_normal = subprocess.run(
            ["strings", "--all", target_file],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        self.all_strings = self.target_buffer_normal.stdout.decode().split("\n")

        # Example pattern scanning
        results = {}
        for pat in powershell_code_patterns:
            pattern_matches = []
            for code in powershell_code_patterns[pat]["patterns"]:
                matches = re.findall(code, str(self.all_strings), re.IGNORECASE)
                if matches:
                    pattern_matches.extend(matches)
            if pattern_matches:
                results[pat] = pattern_matches
        return results

if __name__ == "__main__":
    PowerShellExaminerAnalyzer().run()
