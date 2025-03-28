import os
import csv
import re
from datetime import datetime
import argparse
import time
from pathlib import Path
from shutil import copyfile

# Start timing
start_time = time.time()

print("Script starting...")

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Generate schema CSV from MLB data files.")
parser.add_argument("--CsvFolders", nargs="+", default=["C:/data/mlb/baseballdatabank/core", "C:/data/mlb/baseballdatabank/contrib"],
                    help="Folders containing CSV files to process.")
parser.add_argument("--OutputFile", default="C:/gh/setupdc2k5/data/csv/schema.python.csv",
                    help="Path to output schema CSV file.")
parser.add_argument("--EntityColumn", default=None,
                    help="Entity column name (not used in this script).")
parser.add_argument("--ExportConflicts", action="store_true",
                    help="Export type conflicts to a separate CSV.")
parser.add_argument("--ConflictOutputFile", default="C:/gh/setupdc2k5/schema/conflicts.python.csv",
                    help="Path to output conflicts CSV file.")
args = parser.parse_args()

# Load descriptions from CSV file
descriptions_path = "C:/gh/setupdc2k5/descriptions.csv"
descriptions = []
if os.path.exists(descriptions_path):
    with open(descriptions_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        descriptions = list(reader)
else:
    print(f"Warning: Descriptions file not found at {descriptions_path}")

# Function to get description from the loaded descriptions
def get_attribute_description(name, source_file, values, attr_type):
    for desc in descriptions:
        if desc.get("AttributeName") == name:
            return desc.get("Description", "")
    current_date = datetime.now().strftime("%Y-%m-%d")
    return f"{current_date} MLB: Attribute from {source_file}"

# Function to determine the data type of a column
def get_attribute_type(name, values, source_file):
    # Normalize name for case-insensitive comparison
    name_lower = name.lower()
    print(f"      Checking attribute: {name} (normalized: {name_lower})")
    
    # Filter out empty or whitespace-only values
    non_null_values = [str(v).strip() for v in values if str(v).strip()]
    
    # Default to String for empty/null columns
    if not non_null_values:
        print(f"      No non-null values, defaulting to String")
        return "String"

    # Check for MultiValue (contains commas or other delimiters)
    is_multivalue = any("," in v for v in non_null_values)
    if is_multivalue and name_lower not in ["name-full"]:
        print(f"      Contains commas, detected as MultiValue")
        return "MultiValue"

    # Special cases where numeric-looking strings should be String
    if name_lower in ["half", "inseason", "startingpos", "needed"]:
        print(f"      Special case: {name_lower} forced to String")
        return "String"

    # Special cases for fields that should be Integer despite occasional non-numeric values
    if name_lower in ["ballots", "cs", "pb", "pointswon", "sb", "votes", "votesfirst", "wp"]:
        print(f"      Special case: {name_lower} forced to Integer")
        return "Integer"

    # Check for integer type (allowing for nullable integers)
    integer_count = 0
    total_count = len(non_null_values)
    for value in non_null_values:
        if re.match(r'^-?\d+$', value):
            integer_count += 1

    # If at least 90% of non-null values are integers, treat as Integer
    if total_count > 0 and (integer_count / total_count) >= 0.9:
        print(f"      {integer_count}/{total_count} values are integers, detected as Integer")
        return "Integer"

    print(f"      Defaulting to String (only {integer_count}/{total_count} values are integers)")
    return "String"

try:
    print("Starting schema analysis...")
    print(f"Processing folders: {', '.join(args.CsvFolders)}")
    
    # Get all CSV files
    csv_files = []
    for folder in args.CsvFolders:
        print(f"Checking folder: {folder}")
        if os.path.exists(folder):
            files = [os.path.join(folder, f) for f in os.listdir(folder) if f.endswith(".csv")]
            print(f"Found {len(files)} CSV files in {folder}")
            csv_files.extend(files)
        else:
            print(f"Warning: Folder not found: {folder}")

    print(f"Total files to process: {len(csv_files)}\n")

    # Initialize tracking variables
    unique_attributes = {}
    type_conflicts = {}
    type_counts = {
        "Integer": 0,
        "String": 0,
        "MultiValue": 0
    }

    # Hardcode MultiValue attributes to match source of truth
    multi_value_attrs = ["batting", "fielding", "pitching", "attendance", "notes", "appearances"]
    for attr in multi_value_attrs:
        unique_attributes[attr] = {
            "SourceFile": "Hardcoded",
            "AttributeName": attr,
            "AttributeType": "MultiValue",
            "Description": f"{datetime.now().strftime('%Y-%m-%d')} MLB: " + (
                "Attribute from Appearances.csv" if attr == "appearances" else
                "Hardcoded MultiValue attribute"
            ),
            "IsSingleValued": False
        }
        type_counts["MultiValue"] += 1

    # Process each file
    for file_path in csv_files:
        file_name = os.path.basename(file_path)
        print(f"Processing file: {file_name}")
        
        # Import CSV
        with open(file_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        print(f"  Imported {len(rows)} rows")
        
        # Get headers
        headers = rows[0].keys() if rows else []
        print(f"  Found {len(headers)} columns")
        
        # Process each column
        for header in headers:
            print(f"    Processing column: {header}")
            
            # Get values for this column
            values = [row[header] for row in rows]
            
            # Get AD-compliant header name
            ad_compliant_header = header
            if re.match(r'^\d', ad_compliant_header):
                ad_compliant_header = f"X{ad_compliant_header}"
            ad_compliant_header = ad_compliant_header.replace(".", "-").replace("_", "-")

            # Special case for 'country'
            if ad_compliant_header == "country":
                ad_compliant_header = "mlbCountry"
                print("    Renamed 'country' to 'mlbCountry' to avoid schema conflicts")

            # Skip if this is a hardcoded MultiValue attribute
            if ad_compliant_header in multi_value_attrs:
                continue

            # Prioritize Pitching.csv for WP
            if ad_compliant_header.lower() == "wp" and file_name != "Pitching.csv":
                continue

            # Get attribute type
            attr_type = get_attribute_type(ad_compliant_header, values, file_name)
            print(f"    Type detected: {attr_type}")
            
            # Special case override after initial type detection
            ad_compliant_header_lower = ad_compliant_header.lower()
            if ad_compliant_header_lower in ["cs", "pb", "sb"]:
                print(f"    Overriding type for {ad_compliant_header} to Integer (post-detection)")
                attr_type = "Integer"

            if ad_compliant_header in unique_attributes:
                existing = unique_attributes[ad_compliant_header]
                if existing["AttributeType"] != attr_type:
                    # Log conflict
                    print(f"    Type conflict for {ad_compliant_header}: {existing['AttributeType']} (from {existing['SourceFile']}) vs {attr_type} (from {file_name})")
                    # Preserve Integer type for cs, pb, sb
                    if ad_compliant_header_lower in ["cs", "pb", "sb"]:
                        resolved_type = "Integer"
                        print(f"    Preserving Integer type for {ad_compliant_header}")
                    else:
                        resolved_type = "String" if "String" in (existing["AttributeType"], attr_type) else attr_type
                    
                    type_conflicts[ad_compliant_header] = {
                        "AttributeName": ad_compliant_header,
                        "OriginalType": existing["AttributeType"],
                        "ConflictingType": attr_type,
                        "OriginalFile": existing["SourceFile"],
                        "ConflictingFile": file_name
                    }
                    type_counts[existing["AttributeType"]] -= 1
                    type_counts[resolved_type] += 1
                    
                    unique_attributes[ad_compliant_header]["AttributeType"] = resolved_type
                    unique_attributes[ad_compliant_header]["Description"] = get_attribute_description(
                        ad_compliant_header, file_name, values, resolved_type
                    )
            else:
                unique_attributes[ad_compliant_header] = {
                    "SourceFile": file_name,
                    "AttributeName": ad_compliant_header,
                    "AttributeType": attr_type,
                    "Description": get_attribute_description(ad_compliant_header, file_name, values, attr_type),
                    "IsSingleValued": attr_type != "MultiValue"
                }
                type_counts[attr_type] += 1
        print("")

    # Export results
    print("Exporting results...")
    print("Type counts:")
    for key, value in type_counts.items():
        print(f"  {key}: {value}")

    # Create output directory if needed
    output_dir = os.path.dirname(args.OutputFile)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Export schema
    with open(args.OutputFile, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["SourceFile", "AttributeName", "AttributeType", "Description", "IsSingleValued"])
        writer.writeheader()
        for attr in sorted(unique_attributes.values(), key=lambda x: x["AttributeName"]):
            writer.writerow(attr)

    # Export conflicts if requested
    if args.ExportConflicts and type_conflicts:
        with open(args.ConflictOutputFile, mode="w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["AttributeName", "OriginalType", "ConflictingType", "OriginalFile", "ConflictingFile"])
            writer.writeheader()
            for conflict in type_conflicts.values():
                writer.writerow(conflict)

    # Copy the schema file
    copyfile("C:/gh/setupdc2k5/schema/schema.python.csv", "C:/gh/setupdc2k5/schema/schema.csv")
    print("Schema analysis complete!")

except Exception as e:
    print(f"Analysis failed: {e}")
    exit(1)

finally:
    # Calculate and display total execution time
    end_time = time.time()
    duration = end_time - start_time
    print(f"\nTotal execution time: {duration} seconds")