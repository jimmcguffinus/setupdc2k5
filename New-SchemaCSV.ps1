#Requires -Version 7.0

param (
    [string[]]$CsvFolders = @(
        "C:\data\mlb\baseballdatabank\core",
        "C:\data\mlb\baseballdatabank\contrib"
    ),
    [string]$OutputFile = "schema\schema.csv"
)

function Get-AttributeDescription {
    param (
        [string]$Name,
        [string]$SourceFile,
        [array]$Values,
        [string]$Type
    )

    if ($null -eq $Values -or $Values.Count -eq 0) {
        return "MLB: Field from $SourceFile (No sample values available)"
    }

    $nonEmptyValues = $Values | Where-Object { $_ }
    $uniqueValues = $nonEmptyValues | Select-Object -Unique
    $sampleValue = $uniqueValues | Select-Object -First 1

    # Detect date-like fields
    $isDateField = $nonEmptyValues -match '^\d{4}-\d{2}-\d{2}$' -or $nonEmptyValues -match '^\d{2}/\d{2}/\d{4}$'

    # Assign description
    $description = "MLB: "
    if ($isDateField) {
        $description += "Date field from $SourceFile (Format: YYYY-MM-DD)"
    } elseif ($Type -eq "MultiValue") {
        $description += "Multi-Value field from $SourceFile (Entity has multiple distinct values)"
    } else {
        $description += "Field from $SourceFile"
        if ($sampleValue) { $description += " (Sample: $sampleValue)" }
        if ($uniqueValues.Count -lt 15) { $description += " - Possible values: $($uniqueValues -join ', ')" }
    }

    return $description
}

function Get-AttributeType {
    param (
        [string]$Name,
        [array]$Values,
        [hashtable]$GroupedData
    )
    
    if ($null -eq $Values -or $Values.Count -eq 0) { return "String" }

    $nonEmptyValues = $Values | Where-Object { $_ }
    
    # Numeric Type Detection
    $allNumbers = $true
    $hasDecimal = $false

    foreach ($val in $nonEmptyValues) {
        if ($val -notmatch '^-?\d*\.?\d+$') { $allNumbers = $false }
        if ($val -match '\.') { $hasDecimal = $true }
    }

    if ($allNumbers) { 
        if ($hasDecimal) { 
            return "String" 
        } else { 
            return "Integer" 
        }
    }
    
    # Check for MultiValue by seeing if one entity has multiple unique values
    if ($GroupedData.ContainsKey($Name)) {
        $multiValueCount = $GroupedData[$Name] | Where-Object { $_.UniqueValues.Count -gt 1 }
        if ($multiValueCount.Count -gt 0) { return "MultiValue" }
    }
    
    return "String"
}

try {
    Write-Host "🔍 Analyzing CSV files in multiple directories..."
    $uniqueAttributes = @{}
    $totalFiles = 0
    $typeCounts = @{ "String" = 0; "MultiValue" = 0; "Integer" = 0; "Double" = 0 }

    foreach ($folder in $CsvFolders) {
        if (-not (Test-Path $folder)) {
            Write-Warning "⚠️ Folder not found, skipping: $folder"
            continue
        }

        Write-Host "📂 Processing folder: $folder"
        $files = Get-ChildItem $folder -Filter "*.csv" | Where-Object { $_.Name -notmatch '^schema_|analysis' }
        
        if (-not $files) {
            Write-Warning "⚠️ No CSV files found in $folder"
            continue
        }

        Write-Host "✅ Found $($files.Count) CSV files"
        $totalFiles += $files.Count

        foreach ($file in $files) {
            Write-Host "  📄 Processing $($file.Name)"
            try {
                $csv = Import-Csv -Path $file.FullName
                if ($null -eq $csv -or $csv.Count -eq 0) {
                    Write-Warning "    ⚠️ Skipping empty CSV file: $($file.Name)"
                    continue
                }

                $headers = $csv[0].PSObject.Properties.Name

                # Detect entity column (first column)
                $entityColumn = $headers[0]

                # Group data by entity to detect multi-value fields
                $groupedData = @{}
                foreach ($header in $headers) {
                    $groupedData[$header] = $csv | Group-Object -Property $entityColumn | 
                        ForEach-Object { 
                            [PSCustomObject]@{ 
                                Entity = $_.Name
                                UniqueValues = ($_.Group | Select-Object -ExpandProperty $header -Unique)
                            }
                        }
                }

                foreach ($header in $headers) {
                    if (-not $uniqueAttributes.ContainsKey($header)) {
                        $values = $csv | ForEach-Object { $_.$header }

                        # Fix numeric attribute names for AD compliance
                        $adCompliantHeader = if ($header -match '^[0-9]') { "X$header" } else { $header }
                        
                        # Replace dots with hyphens for AD compliance
                        $adCompliantHeader = $adCompliantHeader.Replace(".", "-")
                        $adCompliantHeader = $adCompliantHeader.Replace("_", "-")
                        
                        $type = Get-AttributeType -Name $adCompliantHeader -Values $values -GroupedData $groupedData
                        $description = Get-AttributeDescription -Name $adCompliantHeader -SourceFile $file.Name -Values $values -Type $type

                        # Count the types
                        if ($typeCounts.ContainsKey($type)) {
                            $typeCounts[$type]++
                        }

                        $uniqueAttributes[$adCompliantHeader] = [PSCustomObject]@{
                            SourceFile = $file.Name
                            AuxClass = "auxMLB"
                            AttributeName = $adCompliantHeader
                            AttributeType = $type
                            Description = $description
                            IsSingleValued = ($type -ne "MultiValue")  # Boolean instead of string
                        }
                    }
                }
            }
            catch {
                Write-Warning "    ⚠️ Error processing $($file.Name): $_"
            }
        }
    }

    if ($uniqueAttributes.Values) {
        $uniqueAttributes.Values | Export-Csv $OutputFile -NoTypeInformation
        Write-Host "✅ Analysis complete. Results saved to $OutputFile"
        Write-Host "📊 Summary:"
        Write-Host "  🗂️ Total folders processed: $($CsvFolders.Count)"
        Write-Host "  📄 Total files processed: $totalFiles"
        Write-Host "  🔢 Total unique attributes: $($uniqueAttributes.Count)"
        Write-Host "  🔠 Total 'String' attributes: $($typeCounts["String"])"
        Write-Host "  🔢 Total 'MultiValue' attributes: $($typeCounts["MultiValue"])"
        Write-Host "  🔢 Total 'Integer' attributes: $($typeCounts["Integer"])"
        Write-Host "  🔢 Total 'Double' attributes: $($typeCounts["Double"])"
    }
    else {
        throw "No results were generated"
    }
}
catch {
    Write-Error "🚨 Script failed: $_"
    exit 1
} 