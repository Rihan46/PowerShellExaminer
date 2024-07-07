# PowerShellExaminer

## Introduction

**`PowerShellExaminer`** is a robust tool designed for analyzing PowerShell scripts to identify potential malicious activities. Inspired by the [Qu1cksc0pe](https://github.com/CYB3RMX/Qu1cksc0pe) project, which focuses on detecting malicious PowerShell code, this tool provides various features to help security professionals and researchers uncover suspicious patterns in PowerShell scripts.

The `PowerShellExaminer` utilizes a set of predefined patterns and advanced text analysis techniques to scan scripts for indicators of malicious activity. The project draws on the techniques from Qu1cksc0pe but expands on them by incorporating additional functionalities to enhance script analysis and threat detection.

## Features

- **Pattern Scanning**
  - Detects known malicious patterns in PowerShell scripts based on predefined regular expressions. This feature helps identify potentially harmful code snippets or techniques commonly used in malicious scripts.
  
- **URL Extraction**
  - Extracts URLs present in the PowerShell script content. This can be useful for identifying suspicious links that might lead to external resources or malware.

- **Domain Extraction**
  - Extracts domain names from the script. This helps in detecting domains associated with phishing or other malicious activities.

- **File Path Extraction**
  - Finds and lists file paths mentioned in the script. This can reveal potential paths to files or directories that may be targeted or manipulated by the script.

- **IP Address Extraction**
  - Extracts IP addresses from the script content. This is useful for uncovering connections to external servers or networks.

- **File Extension Detection**
  - Identifies files with specific extensions that may indicate potentially malicious files. The tool checks for common file types associated with malware or exploitation techniques.

### Installation

To use `PowerShellExaminer`, you need to have Python 3.x installed along with the 'rich' library. You can install the necessary dependencies using pip:

```bash
pip install rich
```

### Example

Here’s an example of how you might run the `PowerShellExaminer` tool:

```bash
python powershellexaminer.py path/to/script.ps1
```

### Known Limitations

Here are some of the known limitations of the `PowerShellExaminer` tool:

- **Encoded PowerShell Scripts:** The tool is unable to analyze PowerShell scripts that are encoded. For effective analysis, the script must be in plain text format.

- **False Positives in Domain Extraction:** There might be occasional false positives during the domain extraction process.

- **Pattern List:** The list of patterns used for detection is not exhaustive. We encourage users to contribute by adding new patterns to the `powershell_code_patterns` file to improve the tool’s effectiveness.
