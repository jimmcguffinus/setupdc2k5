#requires -Version 7.0
[CmdletBinding()]
param (
    [string[]]$CsvFolders             = @("C:\data\mlb\baseballdatabank\core", "C:\data\mlb\baseballdatabank\contrib"),
    [string]$OutputFile               = "schema\schema.csv",
    [string]$EntityColumn             = $null,
    [switch]$ExportConflicts,
    [string]$ConflictOutputFile       = "schema\conflicts.csv"
)

Write-Host "Script starting..."

# Function to determine the data type of a column
function Get-AttributeType {
    param (
        [string]$Name,
        [object[]]$Values,
        [string]$SourceFile
    )

    # Get the base filename without extension
    $baseFileName = [System.IO.Path]::GetFileNameWithoutExtension($SourceFile).ToLower()

    # Hardcode MultiValue for specific files and columns
    if ($baseFileName -in @("batting", "pitching", "appearances", "fielding")) {
        if ($Name -in @("teamID", "lgID")) {
            return "MultiValue"
        }
    }

    # For all other cases, just check if it's an integer or string
    $nonNullValues = $Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    
    # Default to String for empty/null columns
    if ($null -eq $nonNullValues -or $nonNullValues.Count -eq 0) {
        return "String"
    }

    # Check for integer type
    $allInteger = $true
    foreach ($value in $nonNullValues) {
        if ($value -notmatch '^-?\d+$') {
            $allInteger = $false
            break
        }
    }

    return $(if ($allInteger) { "Integer" } else { "String" })
}

# Function to generate a description for each attribute
function Get-AttributeDescription {
    param (
        [string]$Name,
        [string]$SourceFile,
        [object[]]$Values,
        [string]$Type
    )

    $nonNullValues = $Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if ($null -eq $nonNullValues -or $nonNullValues.Count -eq 0) {
        return "No values found in $SourceFile"
    }

    $uniqueValues = $nonNullValues | Select-Object -Unique
    $totalValues = $Values.Count
    $nullCount = ($Values | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count
    $uniqueCount = $uniqueValues.Count

    return "Found in $SourceFile. $uniqueCount unique values out of $totalValues total values ($nullCount null/empty)"
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
    $multiValueAttrs = @("batting", "appearances", "fielding", "pitching")
    foreach ($attr in $multiValueAttrs) {
        $uniqueAttributes[$attr] = [PSCustomObject]@{
            SourceFile = "Hardcoded"
            AttributeName = $attr
            AttributeType = "MultiValue"
            Description = "Hardcoded MultiValue attribute"
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
            
            # Skip if this is a hardcoded MultiValue attribute
            if ($adCompliantHeader -in $multiValueAttrs) {
                continue
            }

            # Get attribute type (only Integer or String)
            $nonNullValues = $Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            if ($null -eq $nonNullValues -or $nonNullValues.Count -eq 0) {
                $type = "String"
            } else {
                $allInteger = $true
                foreach ($value in $nonNullValues) {
                    if ($value -notmatch '^-?\d+$') {
                        $allInteger = $false
                        break
                    }
                }
                $type = if ($allInteger) { "Integer" } else { "String" }
            }
            Write-Host "    Type detected: $type"
            
            if ($uniqueAttributes[$adCompliantHeader]) {
                $existing = $uniqueAttributes[$adCompliantHeader]
                if ($existing.AttributeType -ne $type) {
                    # Always resolve Integer vs String conflicts to String
                    $resolvedType = "String"
                    
                    $typeConflicts[$adCompliantHeader] = @($existing.AttributeType, $type, $existing.SourceFile, $file.Name)
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
                    IsSingleValued = $true
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
        $conflicts = $typeConflicts.GetEnumerator() | ForEach-Object {
            [PSCustomObject]@{
                AttributeName = $_.Key
                OriginalType = $_.Value[0]
                ConflictingType = $_.Value[1]
                OriginalFile = $_.Value[2]
                ConflictingFile = $_.Value[3]
            }
        }
        $conflicts | Export-Csv -Path $ConflictOutputFile -NoTypeInformation -Encoding UTF8
    }

    Write-Host "Schema analysis complete!"
} catch {
    Write-Error "Analysis failed: $_"
    exit 1
}
