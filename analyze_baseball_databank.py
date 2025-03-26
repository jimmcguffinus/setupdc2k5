import csv
import os
from typing import Dict, Set, List

def get_csv_files(directory: str) -> List[str]:
    """Get all CSV files in the directory."""
    return [f for f in os.listdir(directory) if f.endswith('.csv')]

def is_integer(value: str) -> bool:
    """Check if a value represents an integer."""
    try:
        int(value)
        return True
    except (ValueError, TypeError):
        return False

def analyze_value(value: str) -> str:
    """Analyze a single value to determine its type."""
    if not value or value.strip() == '':
        return 'unknown'
    
    # Check for multiple values (comma-separated within quotes or semicolon-separated)
    if (',' in value and value.startswith('"')) or ';' in value:
        return 'multivalue'
        
    # Check for integer
    if is_integer(value):
        return 'integer'
        
    # Must be string if not integer or multivalue
    return 'string'

def derive_field_type(values: Set[str]) -> str:
    """Derive the field type from a set of values."""
    types = {analyze_value(val) for val in values if val}
    
    # If we see multivalue anywhere, the field is multivalue
    if 'multivalue' in types:
        return 'multivalue'
    
    # If all non-empty values are integers, it's an integer field
    if types == {'integer'} or types == {'integer', 'unknown'}:
        return 'integer'
        
    # Default to string for mixed types or pure strings
    return 'string'

def analyze_csv_files(directory: str) -> Dict[str, str]:
    """Analyze all CSV files to derive field types."""
    field_values: Dict[str, Set[str]] = {}
    
    for csv_file in get_csv_files(directory):
        with open(os.path.join(directory, csv_file), 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                for field, value in row.items():
                    if field not in field_values:
                        field_values[field] = set()
                    if value:  # Only add non-empty values
                        field_values[field].add(value)
    
    # Derive types from collected values
    derived_types = {}
    for field, values in field_values.items():
        derived_types[field] = derive_field_type(values)
    
    return derived_types

def read_grok_definitions(grok_file: str) -> Dict[str, str]:
    """Read the grok attribute definitions."""
    grok_types = {}
    with open(grok_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            grok_types[row['attributename']] = row['string_integer_multivalue']
    return grok_types

def compare_types(derived_types: Dict[str, str], grok_types: Dict[str, str]) -> None:
    """Compare derived types with grok definitions."""
    matches = 0
    mismatches = []
    
    for field, derived_type in derived_types.items():
        if field in grok_types:
            grok_type = grok_types[field]
            if derived_type == grok_type:
                matches += 1
                print(f"✓ {field}: {derived_type}")
            else:
                mismatches.append(f"✗ {field}: derived={derived_type}, grok={grok_type}")
    
    # Print results
    print("\nResults:")
    print(f"Total matches: {matches}")
    print("\nMismatches:")
    for mismatch in mismatches:
        print(mismatch)

def main():
    baseball_dir = "data/baseball"  # Directory containing Baseball Databank CSVs
    grok_file = "data/csv/grok.attribute.definitions.csv"
    
    print("Analyzing Baseball Databank CSVs...")
    derived_types = analyze_csv_files(baseball_dir)
    
    print("\nReading grok definitions...")
    grok_types = read_grok_definitions(grok_file)
    
    print("\nComparing types...")
    compare_types(derived_types, grok_types)

if __name__ == "__main__":
    main() 