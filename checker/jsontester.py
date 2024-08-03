import os
import json

def load_json_file(file_path):
    if os.path.isdir(file_path):
        raise ValueError(f"{file_path} is a directory. Please provide a path to a JSON file.")
    elif not os.path.isfile(file_path):
        raise FileNotFoundError(f"{file_path} does not exist.")
    elif not file_path.endswith('.json'):
        raise ValueError(f"{file_path} is not a JSON file.")
    
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        print("JSON file loaded successfully.")
        return data
    except json.JSONDecodeError as e:
        raise ValueError(f"Error decoding JSON: {e}")
    except Exception as e:
        raise RuntimeError(f"An unexpected error occurred: {e}")

# Usage example
json_file_path = "./powershell_code_patterns.json"

try:
    powershell_code_patterns = load_json_file(json_file_path)
except (ValueError, FileNotFoundError, RuntimeError) as e:
    print(f"Error: {e}")

