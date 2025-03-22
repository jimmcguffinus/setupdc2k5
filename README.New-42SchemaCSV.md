# New-42SchemaCSV

A PowerShell script for generating Active Directory schema CSV files from LDIF definitions.

## Overview

This script reads LDIF files containing Active Directory schema definitions and generates a CSV file that can be used to extend the Active Directory schema. It's particularly useful for managing MLB-specific attributes in Active Directory.

## Features

- Reads LDIF files containing schema definitions
- Generates CSV files with proper formatting for AD schema extension
- Handles various attribute types (String, Integer, MultiValueUnicode)
- Validates LDIF syntax and content
- Generates unique OIDs for new attributes
- Creates detailed logging of the process

## Prerequisites

- PowerShell 7 or higher
- Active Directory Domain Controller
- Schema modification rights
- LDIF files containing schema definitions

## Usage

```powershell
.\New-42SchemaCSV.ps1 -LdifPath "path\to\your\schema.ldf" -OutputPath "path\to\output\schema.csv"
```

### Parameters

- `-LdifPath`: Path to the LDIF file containing schema definitions
- `-OutputPath`: Path where the CSV file will be saved

## LDIF File Format

The script expects LDIF files with the following format:

```ldif
dn: CN=Schema,CN=Configuration,DC=mlb,DC=dev
changetype: modify
add: schemaUpgradeInProgress
schemaUpgradeInProgress: 1
-
```

## CSV Output Format

The generated CSV file will contain the following columns:
- Attribute Name
- Description
- OID
- Syntax
- Multi-Valued
- Indexed
- Required

## Logging

Logs are stored in `C:\gh\setupdc2k5\logs\schema-{timestamp}.log`

## Examples

```powershell
# Generate schema CSV from LDIF
.\New-42SchemaCSV.ps1 -LdifPath "C:\gh\setupdc2k5\data\ldfs\schema.ldf" -OutputPath "C:\gh\setupdc2k5\data\schema.csv"

# View generated schema
Import-Csv "C:\gh\setupdc2k5\data\schema.csv" | Format-Table
```

## Notes

- Always backup your Active Directory before making schema changes
- Schema modifications are permanent and cannot be undone
- Ensure you have the necessary permissions to modify the schema
- Test schema changes in a non-production environment first

## Error Handling

The script includes comprehensive error handling and will:
- Validate LDIF file existence and format
- Check for required permissions
- Verify OID uniqueness
- Log all operations and errors

## Contributing

Feel free to submit issues and enhancement requests! 