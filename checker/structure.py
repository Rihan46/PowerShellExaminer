import json

def validate_json_file(file_path):
    try:
        # Open and load the JSON file
        with open(file_path, 'r') as file:
            data = json.load(file)
        
        # If json.load() doesn't raise an error, the file is valid JSON
        print("The JSON file has a proper structure.")
        return True
    except json.JSONDecodeError as e:
        print(f"Invalid JSON structure: {e}")
        return False
    except FileNotFoundError:
        print(f"The file {file_path} was not found.")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

# Example usage
file_path = "./powershell_code_patterns.json"
is_valid = validate_json_file(file_path)

