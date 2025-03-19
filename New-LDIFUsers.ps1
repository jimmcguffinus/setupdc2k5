#Requires -Version 7.0

param (
    [string]$CsvFolder = "C:\gh\setupdc2k5\schema",
    [string]$OutputDir = "C:\gh\setupdc2k5\schema\userldifpackets",
    [int]$BatchSize = 1000
)

# Ensure we are in PowerShell 7+
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7.0 or later."
    exit 1
}

# Get current domain DN
$domainDN = (Get-ADDomain).DistinguishedName
$domain = (Get-ADDomain).DNSRoot

# Performance optimization: Use .NET StringBuilder for string concatenation
$StringBuilder = New-Object System.Text.StringBuilder

# Create role-specific directories and clean up old files
$roleDirs = @{
    "People" = "players"
    "Managers" = "managers"
}

# Add ous directory
$ouDir = Join-Path $OutputDir "ous"
if (Test-Path $ouDir) {
    Remove-Item -Path "$ouDir\*.ldf" -Force
} else {
    New-Item -ItemType Directory -Path $ouDir | Out-Null
}

foreach ($dir in $roleDirs.Values) {
    $path = Join-Path $OutputDir $dir
    if (Test-Path $path) {
        # Clean up old LDIF files
        Remove-Item -Path "$path\*.ldf" -Force
    } else {
        New-Item -ItemType Directory -Path $path | Out-Null
    }
}

# Clean up any old LDIF files in root directory
Remove-Item -Path "$OutputDir\*.ldf" -Force -ErrorAction SilentlyContinue

Write-Host "Processing MLB users from:"
Write-Host "  - C:\data\mlb\baseballdatabank\core\People.csv"
Write-Host "  - C:\data\mlb\baseballdatabank\core\Managers.csv"
Write-Host "Output directory: $OutputDir"

# Create individual LDIF files for each OU
# MLB OU
[void]$StringBuilder.Clear()
[void]$StringBuilder.AppendLine(@"
# MLB Root OU - Generated $(Get-Date)

dn: OU=MLB,$domainDN
changetype: add
objectClass: organizationalUnit
ou: MLB
"@)
[System.IO.File]::WriteAllText("$ouDir\mlb.ldf", $StringBuilder.ToString(), [System.Text.Encoding]::UTF8)

# Players OU
[void]$StringBuilder.Clear()
[void]$StringBuilder.AppendLine(@"
# MLB Players OU - Generated $(Get-Date)

dn: OU=Players,OU=MLB,$domainDN
changetype: add
objectClass: organizationalUnit
ou: Players
"@)
[System.IO.File]::WriteAllText("$ouDir\players.ldf", $StringBuilder.ToString(), [System.Text.Encoding]::UTF8)

# Managers OU
[void]$StringBuilder.Clear()
[void]$StringBuilder.AppendLine(@"
# MLB Managers OU - Generated $(Get-Date)

dn: OU=Managers,OU=MLB,$domainDN
changetype: add
objectClass: organizationalUnit
ou: Managers
"@)
[System.IO.File]::WriteAllText("$ouDir\managers.ldf", $StringBuilder.ToString(), [System.Text.Encoding]::UTF8)

Write-Host "✅ OU LDIF files created in: $ouDir"

# Track overall progress
$totalRecords = 0
$processedRecords = 0
$startTime = Get-Date

# Define files to process
$filesToProcess = @(
    "C:\data\mlb\baseballdatabank\core\People.csv",
    "C:\data\mlb\baseballdatabank\core\Managers.csv"
)

# Count total records
foreach ($file in $filesToProcess) {
    if (Test-Path $file) {
        $totalRecords += (Get-Content $file).Count - 1 # Subtract header
    } else {
        Write-Warning "File not found: $file"
    }
}

Write-Host "Total records to process: $totalRecords"

# Process each file
foreach ($file in $filesToProcess) {
    if (-not (Test-Path $file)) { continue }

    Write-Host "`nProcessing $([System.IO.Path]::GetFileName($file))..."
    
    try {
        # Read file efficiently using .NET StreamReader
        $reader = New-Object System.IO.StreamReader($file)
        $csvHeader = $reader.ReadLine() -split ','
        $processedInFile = 0
        $totalLinesInFile = (Get-Content $file).Count - 1

        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            $data = $line -split ','
            $record = @{}

            for ($i = 0; $i -lt $csvHeader.Count; $i++) {
                if ($i -lt $data.Count) {
                    $record[$csvHeader[$i]] = $data[$i].Trim('"') # Remove quotes if present
                }
            }

            # Get player ID and name
            $id = $record["playerID"]
            $firstName = $record["nameFirst"]
            $lastName = $record["nameLast"]
            $birthYear = $record["birthYear"]
            $birthMonth = $record["birthMonth"]
            $birthDay = $record["birthDay"]
            $birthCountry = $record["birthCountry"]
            $birthState = $record["birthState"]
            $birthCity = $record["birthCity"]
            $deathYear = $record["deathYear"]

            # Create derived attributes
            $fullName = "$firstName $lastName".Trim()
            $description = "MLB Player ID: $id"
            if ($birthYear) {
                $birthPlace = @($birthCity, $birthState, $birthCountry) | Where-Object { $_ } | Join-String -Separator ", "
                $description += "`nBorn: $birthMonth/$birthDay/$birthYear in $birthPlace"
            }
            if ($deathYear) {
                $description += "`nDeceased: $deathYear"
            }

            # Create LDIF content for each user
            [void]$StringBuilder.Clear()
            [void]$StringBuilder.AppendLine(@"

dn: CN=$id,OU=$(if ([System.IO.Path]::GetFileNameWithoutExtension($file) -eq "Managers") { "Managers" } else { "Players" }),OU=MLB,$domainDN
changetype: add
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: auxMLB
cn: $id
sAMAccountName: $id
userPrincipalName: $id@$domain
displayName: $fullName
name: $fullName
givenName: $firstName
sn: $lastName
description: $description
"@)

            # Add all MLB-specific attributes from the record
            foreach ($prop in $record.Keys) {
                if (![string]::IsNullOrEmpty($record[$prop])) {
                    [void]$StringBuilder.AppendLine("$($prop): $($record[$prop])")
                }
            }

            # Determine output directory based on file type
            $roleDir = if ([System.IO.Path]::GetFileNameWithoutExtension($file) -eq "Managers") {
                Join-Path $OutputDir "managers"
            } else {
                Join-Path $OutputDir "players"
            }

            # Write individual LDIF file
            $ldifFile = Join-Path $roleDir "$($id.Substring(0, [Math]::Min(20, $id.Length))).ldf"
            [System.IO.File]::WriteAllText($ldifFile, $StringBuilder.ToString(), [System.Text.Encoding]::UTF8)
            
            $processedRecords++
            $processedInFile++

            # Show progress
            $percentComplete = [math]::Round(($processedRecords / $totalRecords) * 100, 1)
            $elapsed = (Get-Date) - $startTime
            if ($processedRecords -gt 0) {
                $estimatedTotal = $elapsed.TotalSeconds * ($totalRecords / $processedRecords)
                $remaining = [TimeSpan]::FromSeconds($estimatedTotal - $elapsed.TotalSeconds)
                
                Write-Progress -Activity "Processing $([System.IO.Path]::GetFileName($file))" `
                    -Status "$percentComplete% Complete" `
                    -PercentComplete $percentComplete `
                    -CurrentOperation "Processed $processedInFile of $totalLinesInFile records" `
                    -SecondsRemaining $remaining.TotalSeconds
            }
        }

        $reader.Close()
    }
    catch {
        Write-Error "Error processing $([System.IO.Path]::GetFileName($file)): $_"
        if ($reader) { $reader.Close() }
        continue
    }

    Write-Progress -Activity "Processing $([System.IO.Path]::GetFileName($file))" -Completed
}

$totalTime = (Get-Date) - $startTime
Write-Host "`n== LDIF Generation Complete! =="
Write-Host "----------------------------------------"
Write-Host "Summary:"
Write-Host "  * Structure file: $structureFile"
Write-Host "  * LDIF files: $processedRecords user files created"
Write-Host "  * Processing time: $($totalTime.ToString('hh\:mm\:ss'))"
Write-Host "----------------------------------------"
Write-Host "`nNext Steps:"
Write-Host "1. Import structure: ldifde -i -f `"$structureFile`""
Write-Host "2. Import user LDIF files: Get-ChildItem `"$OutputDir\*.ldf`" | ForEach-Object { ldifde -i -f `$_.FullName }" 