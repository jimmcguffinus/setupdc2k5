#requires -Version 7.0
[CmdletBinding()]
param (
    [string[]]$CsvFolders             = @("C:\data\mlb\baseballdatabank\core", "C:\data\mlb\baseballdatabank\contrib"),
    [string]$OutputFile               = "C:\gh\setupdc2k5\data\csv\schema.powershell.csv",
    [string]$EntityColumn             = $null,
    [switch]$ExportConflicts,
    [string]$ConflictOutputFile       = "C:\gh\setupdc2k5\schema\conflicts.powershell.csv"
)

# Start timing
$startTime = Get-Date

Write-Host "Script starting..."

# Load descriptions from CSV file once at the start of the script
$descriptionsPath = "C:\gh\setupdc2k5\descriptions.csv"
$descriptions = if (Test-Path $descriptionsPath) { Import-Csv $descriptionsPath } else { @() }

# Function to get description from the loaded descriptions
function Get-AttributeDescription {
    param (
        [string]$Name,
        [string]$SourceFile,
        [object[]]$Values,
        [string]$Type
    )

    $matchingDesc = $descriptions | Where-Object { $_.AttributeName -eq $Name }
    if ($matchingDesc) {
        return $matchingDesc.Description
    }

    $fallbackDesc = "$(Get-Date -Format 'yyyy-MM-dd') MLB: Attribute from $SourceFile"
    Write-Host "    Warning: Description not found for $Name in descriptions.csv. Using fallback: $fallbackDesc"
    return $fallbackDesc
}

# Function to determine the data type of a column
function Get-AttributeType {
    param (
        [string]$Name,
        [object[]]$Values,
        [string]$SourceFile
    )

    Write-Host "      Checking attribute: $Name"

    # Filter out empty or whitespace-only values
    $nonNullValues = $Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    
    # Default to String for empty/null columns
    if ($null -eq $nonNullValues -or $nonNullValues.Count -eq 0) {
        Write-Host "      No non-null values, defaulting to String"
        return "String"
    }

    # Special cases for String
    if ($Name -in @("half", "inseason", "startingPos", "needed")) {
        Write-Host "      Special case: $Name forced to String"
        return "String"
    }

    # Special cases for Integer
    if ($Name -in @("ballots", "CS", "PB", "pointsWon", "SB", "votes", "votesFirst", "WP")) {
        Write-Host "      Special case: $Name forced to Integer"
        return "Integer"
    }

    # Check for integer type with 90% threshold
    $integerCount = 0
    $totalCount = $nonNullValues.Count
    foreach ($value in $nonNullValues) {
        if ($value -match '^-?\d+$') {
            $integerCount++
        }
    }

    if ($totalCount -gt 0 -and ($integerCount / $totalCount) -ge 0.9) {
        Write-Host "      $integerCount/$totalCount values are integers, detected as Integer"
        return "Integer"
    }

    Write-Host "      Defaulting to String (only $integerCount/$totalCount values are integers)"
    return "String"
}

try {
    Write-Host "Starting schema analysis..."
    Write-Host "Processing folders: $($CsvFolders -join ', ')"
    
    # Get all CSV files
    $csvFiles = @()
    foreach ($folder in $CsvFolders) {
        Write-Host "Checking folder: $folder"
        if (Test-Path $folder) {
            $files = Get-ChildItem -Path $folder -Filter "*.csv"
            Write-Host "Found $($files.Count) CSV files in $folder"
            $csvFiles += $files
        } else {
            Write-Warning "Folder not found: $folder"
        }
    }

    Write-Host "Total files to process: $($csvFiles.Count)"
    Write-Host ""

    # Initialize tracking variables
    $uniqueAttributes = @{}
    $typeConflicts = @{}
    $typeCounts = [ordered]@{
        "Integer" = 0
        "String" = 0
        "MultiValue" = 0
    }

    # Hardcode MultiValue attributes upfront
    $multiValueAttrs = @("batting", "fielding", "pitching", "attendance", "notes")
    foreach ($attr in $multiValueAttrs) {
        $uniqueAttributes[$attr] = [PSCustomObject]@{
            SourceFile = "Hardcoded"
            AttributeName = $attr
            AttributeType = "MultiValue"
            Description = "$(Get-Date -Format 'yyyy-MM-dd') MLB: Hardcoded MultiValue attribute"
            IsSingleValued = $false
        }
        $typeCounts["MultiValue"]++
    }

    # Process each file
    foreach ($file in $csvFiles) {
        Write-Host "Processing file: $($file.Name)"
        
        # Import CSV
        $csv = Import-Csv -Path $file.FullName
        Write-Host "  Imported $($csv.Count) rows"
        
        # Get headers
        $headers = $csv[0].PSObject.Properties.Name
        Write-Host "  Found $($headers.Count) columns"
        
        # Process each column
        foreach ($header in $headers) {
            Write-Host "    Processing column: $header"
            
            # Get values for this column
            $values = $csv.$header
            
            # Get AD-compliant header name
            $adCompliantHeader = $header -replace '^[0-9]', 'X$0' -replace '[._]', '-'

            # Add special case for 'country'
            if ($adCompliantHeader -eq 'country') {
                $adCompliantHeader = 'mlbCountry'
                Write-Host "    Renamed 'country' to 'mlbCountry' to avoid schema conflicts"
            }

            # Skip if this is a hardcoded MultiValue attribute
            if ($adCompliantHeader -in $multiValueAttrs) {
                continue
            }

            # Prioritize Pitching.csv for WP
            if ($adCompliantHeader -eq "WP" -and $file.Name -ne "Pitching.csv") {
                continue
            }

            # Get attribute type
            $type = Get-AttributeType -Name $adCompliantHeader -Values $values -SourceFile $file.Name
            Write-Host "    Type detected: $type"

            # Post-detection override for CS, PB, SB
            if ($adCompliantHeader -in @("CS", "PB", "SB")) {
                Write-Host "    Overriding type for $adCompliantHeader to Integer (post-detection)"
                $type = "Integer"
            }
            
            if ($uniqueAttributes[$adCompliantHeader]) {
                $existing = $uniqueAttributes[$adCompliantHeader]
                if ($existing.AttributeType -ne $type) {
                    Write-Host "    Type conflict for $adCompliantHeader`: $($existing.AttributeType) (from $($existing.SourceFile)) vs $type (from $($file.Name))"
                    # Preserve Integer type for CS, PB, SB
                    if ($adCompliantHeader -in @("CS", "PB", "SB")) {
                        $resolvedType = "Integer"
                        Write-Host "    Preserving Integer type for $adCompliantHeader"
                    } else {
                        $resolvedType = "String"
                    }
                    
                    $typeConflicts[$adCompliantHeader] = [PSCustomObject]@{
                        AttributeName = $adCompliantHeader
                        OriginalType = $existing.AttributeType
                        ConflictingType = $type
                        OriginalFile = $existing.SourceFile
                        ConflictingFile = $file.Name
                    }
                    $typeCounts[$existing.AttributeType]--
                    $typeCounts[$resolvedType]++
                    
                    $uniqueAttributes[$adCompliantHeader].AttributeType = $resolvedType
                    $uniqueAttributes[$adCompliantHeader].Description = Get-AttributeDescription -Name $adCompliantHeader -SourceFile $file.Name -Values $values -Type $resolvedType
                }
            } else {
                $uniqueAttributes[$adCompliantHeader] = [PSCustomObject]@{
                    SourceFile = $file.Name
                    AttributeName = $adCompliantHeader
                    AttributeType = $type
                    Description = Get-AttributeDescription -Name $adCompliantHeader -SourceFile $file.Name -Values $values -Type $type
                    IsSingleValued = $type -ne "MultiValue"
                }
                $typeCounts[$type]++
            }
        }
        Write-Host ""
    }

    # Export results
    Write-Host "Exporting results..."
    Write-Host "Type counts:"
    $typeCounts.GetEnumerator() | ForEach-Object {
        Write-Host "  $($_.Key): $($_.Value)"
    }

    # Create output directory if needed
    $outputDir = Split-Path -Parent $OutputFile
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    # Export schema
    $uniqueAttributes.Values | Sort-Object AttributeName | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

    # Export conflicts if requested
    if ($ExportConflicts -and $typeConflicts.Count -gt 0) {
        $typeConflicts.Values | Export-Csv -Path $ConflictOutputFile -NoTypeInformation -Encoding UTF8
    }
    Copy-Item C:\gh\setupdc2k5\schema\schema.powershell.csv C:\gh\setupdc2k5\schema\schema.csv
    Write-Host "Schema analysis complete!"
} catch {
    Write-Error "Analysis failed: $_"
    exit 1
} finally {
    # Calculate and display total execution time
    $endTime = Get-Date
    $duration = $endTime - $startTime
    Write-Host "`nTotal execution time: $($duration.TotalSeconds) seconds"
}