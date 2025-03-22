#!/usr/bin/env python3

"""
Generate-42Schema: A Python script to analyze Baseball Databank CSVs and generate a schema.csv for AD schema extension.
"""

import os
import pandas as pd
from datetime import datetime
import argparse

def load_descriptions(descriptions_path):
    """Load attribute descriptions from descriptions.csv."""
    if os.path.exists(descriptions_path):
        return pd.read_csv(descriptions_path).set_index('AttributeName').to_dict()['Description']
    return {}

def get_attribute_description(name, source_file, descriptions):
    """Get the description for an attribute, falling back to a default if not found."""
    if name in descriptions:
        return descriptions[name]
    return f"{datetime.now().strftime('%Y-%m-%d')} MLB: Attribute from {source_file}"

def get_attribute_type(values):
    """Determine the data type of a column (Integer or String)."""
    non_null_values = [str(val) for val in values if pd.notna(val) and str(val).strip()]
    
    if not non_null_values:
        return "String"
    
    all_integer = all(val.lstrip('-').isdigit() for val in non_null_values)
    return "Integer" if all_integer else "String"

def main():
    parser = argparse.ArgumentParser(description="Generate schema.csv from Baseball Databank CSVs.")
    parser.add_argument("--csv-folders", nargs='+', default=["data/csv"], help="Folders containing CSV files")
    parser.add_argument("--output-file", default="data/schema.csv", help="Output path for schema.csv")
    parser.add_argument("--descriptions", default="data/descriptions.csv", help="Path to descriptions.csv")
    parser.add_argument("--export-conflicts", action="store_true", help="Export type conflicts to a CSV")
    parser.add_argument("--conflict-output", default="data/conflicts.csv", help="Output path for conflicts.csv")
    args = parser.parse_args()

    print("Starting schema analysis...")
    print(f"Processing folders: {', '.join(args.csv_folders)}")

    # Load descriptions
    descriptions = load_descriptions(args.descriptions)

    # Get all CSV files
    csv_files = []
    for folder in args.csv_folders:
        if not os.path.exists(folder):
            print(f"Warning: Folder not found: {folder}")
            continue
        csv_files.extend([os.path.join(folder, f) for f in os.listdir(folder) if f.endswith('.csv')])
    
    print(f"Total files to process: {len(csv_files)}")

    # Initialize tracking variables
    unique_attributes = []
    type_conflicts = []
    type_counts = {"Integer": 0, "String": 0, "MultiValue": 0}

    # Hardcode MultiValue attributes
    multi_value_attrs = ["batting", "appearances", "fielding", "pitching"]
    for attr in multi_value_attrs:
        unique_attributes.append({
            "SourceFile": "Hardcoded",
            "AttributeName": attr,
            "AttributeType": "MultiValue",
            "Description": f"{datetime.now().strftime('%Y-%m-%d')} MLB: Hardcoded MultiValue attribute",
            "IsSingleValued": False
        })
        type_counts["MultiValue"] += 1

    # Process each CSV file
    for csv_file in csv_files:
        print(f"Processing file: {os.path.basename(csv_file)}")
        df = pd.read_csv(csv_file)
        print(f"  Imported {len(df)} rows")
        headers = df.columns.tolist()
        print(f"  Found {len(headers)} columns")

        for header in headers:
            print(f"    Processing column: {header}")
            
            # Get AD-compliant header name
            ad_compliant_header = header
            if ad_compliant_header[0].isdigit():
                ad_compliant_header = f"X{ad_compliant_header}"
            ad_compliant_header = ad_compliant_header.replace('.', '-').replace('_', '-')

            # Special case for 'country'
            if ad_compliant_header.lower() == 'country':
                ad_compliant_header = 'mlbCountry'
                print("    Renamed 'country' to 'mlbCountry' to avoid schema conflicts")

            # Skip if this is a hardcoded MultiValue attribute
            if ad_compliant_header in multi_value_attrs:
                continue

            # Get attribute type
            values = df[header]
            attr_type = get_attribute_type(values)
            print(f"    Type detected: {attr_type}")

            # Check for existing attribute
            existing_attr = next((attr for attr in unique_attributes if attr["AttributeName"] == ad_compliant_header), None)
            if existing_attr:
                if existing_attr["AttributeType"] != attr_type:
                    # Resolve Integer vs String conflicts to String
                    resolved_type = "String"
                    type_conflicts.append({
                        "AttributeName": ad_compliant_header,
                        "OriginalType": existing_attr["AttributeType"],
                        "ConflictingType": attr_type,
                        "OriginalFile": existing_attr["SourceFile"],
                        "ConflictingFile": os.path.basename(csv_file)
                    })
                    type_counts[existing_attr["AttributeType"]] -= 1
                    type_counts[resolved_type] += 1
                    existing_attr["AttributeType"] = resolved_type
                    existing_attr["Description"] = get_attribute_description(ad_compliant_header, os.path.basename(csv_file), descriptions)
            else:
                unique_attributes.append({
                    "SourceFile": os.path.basename(csv_file),
                    "AttributeName": ad_compliant_header,
                    "AttributeType": attr_type,
                    "Description": get_attribute_description(ad_compliant_header, os.path.basename(csv_file), descriptions),
                    "IsSingleValued": True
                })
                type_counts[attr_type] += 1

    # Export results
    print("Exporting results...")
    print("Type counts:")
    for key, value in type_counts.items():
        print(f"  {key}: {value}")

    # Create output directory if needed
    output_dir = os.path.dirname(args.output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Export schema
    pd.DataFrame(unique_attributes).sort_values("AttributeName").to_csv(args.output_file, index=False, encoding='utf-8')
    print(f"Schema saved to {args.output_file}")

    # Export conflicts if requested
    if args.export_conflicts and type_conflicts:
        pd.DataFrame(type_conflicts).to_csv(args.conflict_output, index=False, encoding='utf-8')
        print(f"Conflicts saved to {args.conflict_output}")

    print("Schema analysis complete!")

if __name__ == "__main__":
    main()