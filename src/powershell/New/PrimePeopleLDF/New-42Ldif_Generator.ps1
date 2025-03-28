#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    LDIF Generator Script (PowerShell Version with Snapshot Cache)

.DESCRIPTION
    Reads OU structure CSV and People CSV. Determines attributes to manage based
    on People.csv headers (assuming direct mapping to AD attributes).
    Builds/loads an AD snapshot cache (JSON file) to avoid slow AD queries.
    Compares CSV data to snapshot data and generates LDIF packets only if changes
    are detected or the user is new. Backs up previous LDF output.
    Designed to mirror the functionality of the Python ldif_generator.py script.

.PARAMETER DefaultPassword
    Default password for new user accounts.

.PARAMETER DomainDN
    Domain DN (e.g., DC=mlb,DC=dev). Used as search base for snapshot.

.PARAMETER Domain
    Domain suffix for UPN (e.g., mlb.dev).

.PARAMETER LdapServer
    LDAP server hostname/IP to target for AD queries. Defaults to a DC in the current domain if not specified.

.PARAMETER Credential
    Optional credentials to use for AD queries. Defaults to the current user.

.PARAMETER PlayersOuName
    Name of the OU where player objects will be created (e.g., "Players").

.PARAMETER CsvPath
    Path to the People CSV file (e.g., C:\path\to\People.csv).

.PARAMETER OuCsvPath
    Path to the OU structure CSV file (e.g., C:\path\to\PrimeOUStructure.csv).

.PARAMETER OuOutputPath
    Output path for the OU structure LDIF file (e.g., C:\path\to\ouStructure.ldf).

.PARAMETER PlayersOutputDir
    Directory path to store individual player LDIF files (e.g., C:\path\to\peopleldf_files).

.PARAMETER ForceRefresh
    Switch to force refresh of AD snapshot cache, ignoring existing cache file.

.PARAMETER MaxCacheAgeHours
    Maximum age of cache file in hours before refresh is triggered.

.PARAMETER LogBaseDir
    Base directory for log files. Default: C:\gh\setupdc2k5\data\logs

.EXAMPLE
    .\Generate-PlayerLdif.ps1 -CsvPath "C:\Data\mlb\People.csv" `
        -OuCsvPath "C:\gh\setupdc2k5\data\csv\PrimeOUStructure.csv" `
        -OuOutputPath "C:\gh\setupdc2k5\data\ldfs\ouStructure.ldf" `
        -PlayersOutputDir "C:\gh\setupdc2k5\data\ldfs\peopleldf_files" `
        -DomainDN "DC=mlb,DC=dev" `
        -Domain "mlb.dev" `
        -LdapServer "dc1.mlb.dev" `
        -Verbose

.EXAMPLE
    .\Generate-PlayerLdif.ps1 -CsvPath "C:\Data\mlb\People.csv" -PlayersOutputDir "C:\temp\ldfs" -ForceRefresh -Verbose
    # Uses defaults for other paths, domain, etc. Forces cache refresh.

.NOTES
    Author: Based on Python script by Jim, converted by AI Assistant
    Version: 1.0
    Requires: ActiveDirectory PowerShell Module
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [SecureString]$DefaultPassword = (ConvertTo-SecureString "MLBPlayer2025!" -AsPlainText -Force),

    [Parameter(Mandatory = $false)]
    [string]$DomainDN = "DC=mlb,DC=dev",

    [Parameter(Mandatory = $false)]
    [string]$Domain = "mlb.dev",

    [Parameter(Mandatory = $false)]
    [string]$LdapServer, # Optional, AD module handles discovery if null/empty

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential, # Optional credentials

    [Parameter(Mandatory = $false)]
    [string]$PlayersOuName = "Players",

    [Parameter(Mandatory = $true)]
    [string]$CsvPath = "C:\Data\mlb\baseballdatabank\core\People.csv",

    [Parameter(Mandatory = $true)]
    [string]$OuCsvPath = "C:\gh\setupdc2k5\data\csv\PrimeOUStructure.csv",

    [Parameter(Mandatory = $true)]
    [string]$OuOutputPath = "C:\gh\setupdc2k5\data\ldfs\ouStructure.ldf",

    [Parameter(Mandatory = $true)]
    [string]$PlayersOutputDir,

    [Parameter(Mandatory = $false)]
    [switch]$ForceRefresh,

    [Parameter(Mandatory = $false)]
    [int]$MaxCacheAgeHours = 24,

    [Parameter(Mandatory = $false)]
    [string]$LogBaseDir = "C:\gh\setupdc2k5\data\logs"
)

# --- Script Setup ---
$ErrorActionPreference = 'Stop' # Exit on terminating errors

# --- Global Variables / Constants (PowerShell Style) ---
$script:CsvPlayerIdField = "playerID"
$script:AdSamAccountNameAttr = "sAMAccountName"
$script:AdPlayerIdAttr = "playerID" # Custom AD attribute

# Calculated AD Attributes Map (Internal Key -> AD Name)
$script:CalculatedAdAttributes = @{
    "_calculated_cn"          = "cn"
    "_calculated_displayName" = "displayName"
    "_calculated_description" = "description"
    "_calculated_givenName"   = "givenName"
    "_calculated_sn"          = "sn"
    "_calculated_name"        = "name" # AD 'name' often mirrors 'cn'
}

# Excluded CSV Headers (Case-Insensitive Check Recommended)
$script:ExcludedCsvHeaders = @{
    # Add headers to ignore here, use .ContainsKey() for checks
}.Keys | ForEach-Object { $_.ToLower() } # Store as lowercase array

# CSV Headers used only for calculations
$script:CalculationSourceHeaders = @("nameFirst", "nameLast", "nameGiven", "debut", "finalGame") | ForEach-Object { $_.ToLower() }

# Cache Config
$script:CacheFilename = "player_ad_snapshot.json"
$script:CacheDirectoryName = "snapshot_cache"
$script:CurrentCacheVersion = "1.1"

# ANSI Colors (Check if terminal supports them)
$script:GREEN = "`e[92m"
$script:YELLOW = "`e[93m"
$script:CYAN = "`e[96m"
$script:RED = "`e[91m"
$script:RESET = "`e[0m"

# --- Logging Function ---
Function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')]
        [string]$Level = 'INFO',
        [Parameter(Mandatory = $false)]
        [string]$LogFilePath
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Level - $Message"

    # Write to Console based on Level (Mirror Python slightly)
    switch ($Level) {
        'DEBUG'    { Write-Verbose $logEntry } # Only shows if -Verbose is used
        'INFO'     { Write-Host $logEntry }
        'WARNING'  { Write-Warning $logEntry }
        'ERROR'    { Write-Error $logEntry }
        'CRITICAL' { Write-Error $logEntry -ErrorAction Stop } # Stop on critical? Or just log as error?
    }

    # Write to File (if path provided)
    if (-not [string]::IsNullOrEmpty($LogFilePath)) {
        try {
            Out-File -FilePath $LogFilePath -InputObject $logEntry -Append -Encoding utf8 -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to write to log file '$LogFilePath': $_"
        }
    }
}

# --- Helper Functions ---
Function Convert-PasswordToLdif {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]$Password
    )
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    try {
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        $quotedPassword = "`"$plainPassword`""
        $unicodeBytes = [System.Text.Encoding]::Unicode.GetBytes($quotedPassword)
        return [System.Convert]::ToBase64String($unicodeBytes)
    }
    finally {
        if ($BSTR -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        }
    }
}

Function Convert-TextToSanitized {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        $Text,
        [switch]$IsDnComponent
    )
    process {
        if ($null -eq $Text) { return "" }
        $strText = ($Text | Out-String).Trim()
        if ([string]::IsNullOrWhiteSpace($strText)) { return "" }

        # Base replacements
        $strText = $strText -replace '[,=\+<>#;\\"]', '_'
        $strText = $strText.Trim()
        if ($strText.StartsWith('#')) { $strText = "_$($strText.Substring(1))" }
        $strText = $strText -replace "`r|`n", ' '

        # DN component specific rules
        if ($IsDnComponent.IsPresent) {
            $strText = $strText -replace '[\\/\[\]\{\}\(\)\*\?\!\@\$\%\^\&]', '_'
            $strText = $strText.Trim()
            $strText = $strText -replace '_+', '_'
        }

        return $strText.Trim()
    }
}

Function Limit-CNLength {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$PlayerIdForLogging,
        [Parameter(Mandatory = $false)]
        [int]$MaxLength = 64
    )
    $originalName = $Name
    if ($Name.Length -le $MaxLength) { return $Name }

    $parts = $Name.Split('[', 2)
    $baseName = $parts[0].Trim()
    $suffix = if ($parts.Length -gt 1) { "[$($parts[1])" } else { "" }
    $availableSpace = $MaxLength - $suffix.Length - 3

    $truncatedName = if ($availableSpace -lt 10) {
        $Name.Substring(0, $MaxLength - 3) + "..."
    } else {
        $baseName.Substring(0, $availableSpace) + "..." + $suffix
    }

    Write-Log "CN for player '$PlayerIdForLogging' truncated: '$originalName' -> '$truncatedName'" -Level WARNING -LogFilePath $script:LogFilePath
    return $truncatedName
}

Function Get-LdifSafeString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )
    try {
        [void][System.Text.Encoding]::ASCII.GetBytes($Text)
        return @{ IsBase64 = $false; Value = $Text }
    }
    catch [System.Text.EncoderFallbackException] {
        $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $base64String = [System.Convert]::ToBase64String($utf8Bytes)
        return @{ IsBase64 = $true; Value = $base64String }
    }
    catch {
        Write-Log "Error encoding string '$Text': $_" -Level ERROR -LogFilePath $script:LogFilePath
        return @{ IsBase64 = $false; Value = $Text }
    }
}

# --- OU Structure ---
Function New-OuLdifFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OuCsvPath,
        [Parameter(Mandatory = $true)]
        [string]$DomainDN,
        [Parameter(Mandatory = $true)]
        [string]$OuOutputPath,
        [Parameter(Mandatory = $true)]
        [string]$PlayersOuName
    )
    if (-not (Test-Path $OuCsvPath)) { Write-Log "OU CSV not found: $OuCsvPath" -Level CRITICAL -LogFilePath $script:LogFilePath } # Exits due to ErrorActionPreference=Stop
    Write-Log "Processing OU structure from $OuCsvPath" -Level INFO -LogFilePath $script:LogFilePath

    $ldifContent = New-Object System.Text.StringBuilder
    $finalPlayerContainerDN = $null
    $createdDns = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    $level1Ous = @{}

    try {
        $ouData = Import-Csv -Path $OuCsvPath -Encoding UTF8 # PowerShell often uses UTF8 w/ BOM

        # First pass for Level 1
        foreach ($row in $ouData) {
            $level1 = Convert-TextToSanitized $row.Level1 -IsDnComponent
            if (-not $level1) { continue }
            $level1DN = "OU=$level1,$DomainDN"
            if ($createdDns.Add($level1DN)) {
                Write-Log "Defining Level 1 OU: $level1DN" -Level DEBUG -LogFilePath $script:LogFilePath
                [void]$ldifContent.AppendLine("dn: $level1DN")
                [void]$ldifContent.AppendLine("changetype: add")
                [void]$ldifContent.AppendLine("objectClass: organizationalUnit")
                [void]$ldifContent.AppendLine("ou: $level1")
                [void]$ldifContent.AppendLine("description: $level1 Organization Unit")
                [void]$ldifContent.AppendLine()
                $level1Ous[$level1] = $level1DN
            }
        }

        # Second pass for Level 2 and Players
        foreach ($row in $ouData) {
            $level1 = Convert-TextToSanitized $row.Level1 -IsDnComponent
            $level2 = Convert-TextToSanitized $row.Level2 -IsDnComponent
            if (-not $level1) { continue }

            $level1DN = $level1Ous[$level1]
            if (-not $level1DN) {
                Write-Log "Could not find parent Level 1 OU '$level1' for Level 2 '$level2'. Skipping." -Level WARNING -LogFilePath $script:LogFilePath
                continue
            }

            $currentParentDn = $level1DN
            $targetPlayerDN = $null

            if ($level2) {
                if ($level2 -eq $PlayersOuName) { # Case-insensitive by default
                    $playersDN = "OU=$level2,$level1DN"
                    if ($createdDns.Add($playersDN)) {
                        Write-Log "Defining Players OU (as Level 2): $playersDN" -Level DEBUG -LogFilePath $script:LogFilePath
                        [void]$ldifContent.AppendLine("dn: $playersDN"); [void]$ldifContent.AppendLine("changetype: add"); [void]$ldifContent.AppendLine("objectClass: organizationalUnit"); [void]$ldifContent.AppendLine("ou: $level2"); [void]$ldifContent.AppendLine("description: Container for player objects"); [void]$ldifContent.AppendLine()
                    }
                    $targetPlayerDN = $playersDN
                } else {
                    $level2DN = "OU=$level2,$level1DN"
                    if ($createdDns.Add($level2DN)) {
                        Write-Log "Defining Level 2 OU: $level2DN" -Level DEBUG -LogFilePath $script:LogFilePath
                        [void]$ldifContent.AppendLine("dn: $level2DN"); [void]$ldifContent.AppendLine("changetype: add"); [void]$ldifContent.AppendLine("objectClass: organizationalUnit"); [void]$ldifContent.AppendLine("ou: $level2"); [void]$ldifContent.AppendLine("description: $level2 Container"); [void]$ldifContent.AppendLine()
                    }
                    $currentParentDn = $level2DN # Update parent

                    # Create Players under Level 2
                    $playersDN = "OU=$PlayersOuName,$currentParentDn"
                    if ($createdDns.Add($playersDN)) {
                        Write-Log ("Defining Players OU under " + $level2 + ": " + $playersDN) -Level DEBUG -LogFilePath $script:LogFilePath
                        [void]$ldifContent.AppendLine("dn: $playersDN"); [void]$ldifContent.AppendLine("changetype: add"); [void]$ldifContent.AppendLine("objectClass: organizationalUnit"); [void]$ldifContent.AppendLine("ou: $PlayersOuName"); [void]$ldifContent.AppendLine("description: Container for player objects"); [void]$ldifContent.AppendLine()
                    }
                    $targetPlayerDN = $playersDN
                }
            } else { # No Level 2
                # Create Players under Level 1
                $playersDN = "OU=$PlayersOuName,$currentParentDn"
                if ($createdDns.Add($playersDN)) {
                    Write-Log ("Defining Players OU under " + $level1 + ": " + $playersDN) -Level DEBUG -LogFilePath $script:LogFilePath
                    [void]$ldifContent.AppendLine("dn: $playersDN"); [void]$ldifContent.AppendLine("changetype: add"); [void]$ldifContent.AppendLine("objectClass: organizationalUnit"); [void]$ldifContent.AppendLine("ou: $PlayersOuName"); [void]$ldifContent.AppendLine("description: Container for player objects"); [void]$ldifContent.AppendLine()
                }
                $targetPlayerDN = $playersDN
            }

            if ($targetPlayerDN) { $finalPlayerContainerDN = $targetPlayerDN }
        }

        # Write file
        $null = New-Item -Path (Split-Path $OuOutputPath -Parent) -ItemType Directory -Force
        Set-Content -Path $OuOutputPath -Value $ldifContent.ToString() -Encoding Ascii -Force
        Write-Log "OU structure LDIF file created at: $OuOutputPath" -Level INFO -LogFilePath $script:LogFilePath
        return $finalPlayerContainerDN
    }
    catch {
        Write-Log "Error processing OU structure: $_" -Level CRITICAL -LogFilePath $script:LogFilePath # Exits script
    }
}

# --- AD Interaction (Snapshot) ---
Function Get-AdSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetContainerDN,
        [Parameter(Mandatory = $true)]
        [string[]]$AttributesToFetch,
        [Parameter(Mandatory = $false)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    Write-Log "Building AD snapshot for container: $TargetContainerDN" -Level INFO -LogFilePath $script:LogFilePath
    $adSnapshot = @{}
    
    if (-not $AttributesToFetch) {
        Write-Log "No attributes specified to fetch. Snapshot will be empty." -Level WARNING -LogFilePath $script:LogFilePath
        return $adSnapshot
    }

    # Ensure sAMAccountName is always fetched
    $fetchList = ($AttributesToFetch + $script:AdSamAccountNameAttr | Select-Object -Unique)
    Write-Log "Fetching attributes: $($fetchList -join ', ')" -Level DEBUG -LogFilePath $script:LogFilePath

    $maxRetries = 3
    $retryCount = 0
    $success = $false

    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            $getAdUserParams = @{
                Filter     = "*"
                SearchBase = $TargetContainerDN
                Properties = $fetchList
                ErrorAction = 'Stop'
            }
            if ($Server) { $getAdUserParams.Server = $Server }
            if ($Credential) { $getAdUserParams.Credential = $Credential }

            $adUsers = Get-ADUser @getAdUserParams
            $count = $adUsers.Count
            Write-Log "AD Query executed, processing $count results..." -Level INFO -LogFilePath $script:LogFilePath
            $startTime = Get-Date

            foreach ($user in $adUsers) {
                $sam = $user.($script:AdSamAccountNameAttr)
                if (-not $sam) { continue }
                $samLower = $sam.ToLower()
                $userAttributes = @{}
                foreach ($attr in $fetchList) {
                    if ($user.PSObject.Properties.Name -contains $attr) {
                        $userAttributes[$attr] = $user.$attr
                    } else {
                        $userAttributes[$attr] = $null
                    }
                }
                $adSnapshot[$samLower] = [PSCustomObject]$userAttributes
            }

            $endTime = Get-Date
            Write-Log "Built AD snapshot with $($adSnapshot.Count) users in $($endTime - $startTime)." -Level INFO -LogFilePath $script:LogFilePath
            $success = $true
        }
        catch {
            $retryCount++
            if ($retryCount -lt $maxRetries) {
                Write-Log "AD snapshot attempt $retryCount failed: $_" -Level WARNING -LogFilePath $script:LogFilePath
                Start-Sleep -Seconds (2 * $retryCount) # Exponential backoff
            } else {
                Write-Log "Failed AD snapshot query for '$TargetContainerDN' after $maxRetries attempts: $_" -Level ERROR -LogFilePath $script:LogFilePath
                return $null
            }
        }
    }

    return $adSnapshot
}

# --- Cache Handling ---
Function Get-CachePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PlayersOutputDir
    )
    $baseDir = Split-Path $PlayersOutputDir -Parent
    $cacheDir = Join-Path $baseDir $script:CacheDirectoryName
    $null = New-Item -Path $cacheDir -ItemType Directory -Force -ErrorAction SilentlyContinue
    return Join-Path $cacheDir $script:CacheFilename
}

Function Test-CacheValidity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CacheFilePath,
        [Parameter(Mandatory = $true)]
        [int]$MaxAgeHours
    )
    if (-not (Test-Path $CacheFilePath)) { Write-Log "Cache file not found." -Level INFO -LogFilePath $script:LogFilePath; return $false }

    try {
        $fileInfo = Get-Item $CacheFilePath
        $fileAge = (Get-Date) - $fileInfo.LastWriteTime
        if ($fileAge.TotalHours -gt $MaxAgeHours) {
            Write-Log "Cache file '$CacheFilePath' is older than $MaxAgeHours hours ($($fileAge.TotalHours) hours). Requires refresh." -Level INFO -LogFilePath $script:LogFilePath
            return $false
        }

        Write-Log "Attempting to load cache file: $CacheFilePath" -Level INFO -LogFilePath $script:LogFilePath
        $cacheContent = Get-Content -Path $CacheFilePath -Encoding UTF8 -Raw
        $cacheData = $cacheContent | ConvertFrom-Json -ErrorAction Stop

        # Verify structure, version
        if (($null -eq $cacheData) -or `
            ($cacheData.version -ne $script:CurrentCacheVersion) -or `
            (-not $cacheData.PSObject.Properties.Name -contains 'snapshot') -or `
            ($null -eq $cacheData.snapshot)) { # Allow empty snapshot dict, but not missing key
            Write-Log "Cache file invalid structure or version mismatch. Requires refresh." -Level WARNING -LogFilePath $script:LogFilePath
            return $false
        }

        Write-Log "Valid cache file loaded (Version: $($cacheData.version), Updated: $($cacheData.last_updated))." -Level INFO -LogFilePath $script:LogFilePath
        # Convert the nested snapshot back to a Hashtable for faster lookups?
        # ConvertFrom-Json creates PSCustomObjects. Hashtable might be marginally faster for key lookups.
        $snapshotHashtable = @{}
        # Handle potential System.Management.Automation.PSCustomObject case from JSON
        if ($cacheData.snapshot -is [System.Management.Automation.PSCustomObject]) {
             $cacheData.snapshot.PSObject.Properties | ForEach-Object { $snapshotHashtable[$_.Name] = $_.Value }
        } elseif ($cacheData.snapshot -is [hashtable]) {
             $snapshotHashtable = $cacheData.snapshot # Already a hashtable
        } else {
             Write-Log "Snapshot data in cache is not a recognizable dictionary type." -Level WARNING -LogFilePath $script:LogFilePath
             return $false # Invalid format
        }

        return $true

    }
    catch {
        Write-Log "Failed to load or verify cache file '$CacheFilePath': $_" -Level WARNING -LogFilePath $script:LogFilePath
        return $false
    }
}

Function Save-Cache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CacheFilePath,
        [Parameter(Mandatory = $true)]
        [hashtable]$AdSnapshotHashtable
    )
    $cacheData = @{
        version      = $script:CurrentCacheVersion
        last_updated = (Get-Date).ToString("o") # ISO 8601 format
        snapshot     = $AdSnapshotHashtable
    }
    try {
        $tempCacheFile = $CacheFilePath + ".tmp"
        $cacheData | ConvertTo-Json -Depth 5 | Out-File -FilePath $tempCacheFile -Encoding utf8 -Force -ErrorAction Stop
        Move-Item -Path $tempCacheFile -Destination $CacheFilePath -Force -ErrorAction Stop
        Write-Log "Successfully saved AD snapshot cache to $CacheFilePath" -Level INFO -LogFilePath $script:LogFilePath
    }
    catch {
        Write-Log "Failed to save cache file '$CacheFilePath': $_" -Level ERROR -LogFilePath $script:LogFilePath
        # Attempt to clean up temp file if it exists
        if (Test-Path $tempCacheFile) { Remove-Item $tempCacheFile -Force -ErrorAction SilentlyContinue }
    }
}

# --- Comparison Logic ---
Function Convert-ValueToNormalized {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Value
    )
    if ($null -eq $Value) { return "" }
    
    # Handle AD specific types
    if ($Value -is [System.Array]) {
        $Value = $Value[0]
    }
    elseif ($Value -is [System.DateTime]) {
        $Value = $Value.ToString("yyyy-MM-dd")
    }
    elseif ($Value -is [System.Security.Principal.SecurityIdentifier]) {
        $Value = $Value.Value
    }
    
    return ($Value | Out-String).Trim()
}

Function Compare-ObjectAttributes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$CurrentAdValues,
        [Parameter(Mandatory = $true)]
        [hashtable]$NewCsvValues,
        [Parameter(Mandatory = $true)]
        [string[]]$AttributesToCompare,
        [Parameter(Mandatory = $true)]
        [string]$PlayerIdForLogging
    )
    
    if ($null -eq $CurrentAdValues) { 
        Write-Log "No current AD values for $PlayerIdForLogging - treating as different" -Level DEBUG -LogFilePath $script:LogFilePath
        return $true 
    }

    foreach ($attr in $AttributesToCompare) {
        try {
            # Get AD value (handle PSCustomObject property access)
            $adValue = $null
            if ($CurrentAdValues.PSObject.Properties.Name -contains $attr) {
                $adValue = $CurrentAdValues.$attr
            }
            $csvValue = $NewCsvValues[$attr]

            $adValNorm = Convert-ValueToNormalized $adValue
            $csvValNorm = Convert-ValueToNormalized $csvValue

            # PowerShell string comparison is case-insensitive by default
            if ($adValNorm -ne $csvValNorm) {
                Write-Log ("Difference DETECTED for '" + $attr + "' on " + $PlayerIdForLogging + ":") -Level DEBUG -LogFilePath $script:LogFilePath
                Write-Log ("  AD value: '" + $adValue + "' (normalized: '" + $adValNorm + "')") -Level DEBUG -LogFilePath $script:LogFilePath
                Write-Log ("  CSV value: '" + $csvValue + "' (normalized: '" + $csvValNorm + "')") -Level DEBUG -LogFilePath $script:LogFilePath
                return $true
            }
        }
        catch {
            Write-Log ("Error comparing attribute '" + $attr + "' for " + $PlayerIdForLogging + ": " + $_) -Level ERROR -LogFilePath $script:LogFilePath
            return $true # Treat as different on error
        }
    }
    return $false # No differences found
}

# --- LDIF Generation ---
Function New-PlayerLdifContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Player,
        [Parameter(Mandatory = $true)]
        [string]$PlayerContainerDN,
        [Parameter(Mandatory = $true)]
        [SecureString]$Base64Password,
        [Parameter(Mandatory = $true)]
        [hashtable]$AdSnapshot,
        [Parameter(Mandatory = $true)]
        [string[]]$DynamicAdAttributes,
        [Parameter(Mandatory = $true)]
        [hashtable]$CalculatedAdAttributesMap,
        [Parameter(Mandatory = $true)]
        [string]$DomainSuffix
    )

    # Convert SecureString to string at the last possible moment
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Base64Password)
    try {
        $base64PasswordString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        $playerId = ($Player.($script:CsvPlayerIdField)).Trim()
        if (-not $playerId) { return $null, "Skipped (No PlayerID)" }
        $playerIdLower = $playerId.ToLower()

        $userExistsInSnapshot = $AdSnapshot.ContainsKey($playerIdLower)

        # --- Construct New Values Hashtable ---
        $newValues = @{}

        # 1. Calculated Attributes
        $nameLast = ($Player.nameLast).Trim()
        if (-not $nameLast) { return $null, "Skipped (No Last Name)" }

        $nameFirst = ($Player.nameFirst).Trim()
        $nameGiven = ($Player.nameGiven).Trim()
        if (-not $nameFirst -and -not $nameGiven) { $nameFirst = $nameLast; $nameGiven = $nameLast }
        $nameFirst = if ($nameFirst) { $nameFirst } elseif ($nameGiven) { $nameGiven } else { $nameLast }
        $nameGiven = if ($nameGiven) { $nameGiven } else { $nameFirst }

        $newValues["givenName"] = Convert-TextToSanitized $nameFirst
        $newValues["sn"] = Convert-TextToSanitized $nameLast

        $debut = ($Player.debut).Trim()
        $finalGame = ($Player.finalGame).Trim()
        $debutYear = if ($debut -match '^\d{4}') { $debut.Split('-')[0] } else { "" }
        $finalGameYear = if ($finalGame -match '^\d{4}') { $finalGame.Split('-')[0] } else { "" }
        $careerSpan = if ($debutYear -and $finalGameYear) { "$debutYear-$finalGameYear" } else { "Unknown" }

        $displayNameRaw = "$nameGiven $nameLast [$playerId $careerSpan]"
        $newValues["displayName"] = Convert-TextToSanitized $displayNameRaw

        $cnRaw = "$nameGiven $nameLast $playerId"
        $calculatedCN = Limit-CNLength (Convert-TextToSanitized $cnRaw) $playerId
        $newValues["cn"] = $calculatedCN
        $newValues["name"] = $calculatedCN

        $country = Convert-TextToSanitized ($Player.birthCountry -replace '^$', 'NoCountry')
        $state = Convert-TextToSanitized $Player.birthState
        if (-not $state -and $country -eq 'USA') { $state = "NoState" }
        elseif (-not $state) { $state = "NoProvince" }
        $city = Convert-TextToSanitized ($Player.birthCity -replace '^$', 'NoCity')
        $city = ($city -split 'Retrosheet')[0].Trim()
        $city = ($city -split 'Baseball-Reference')[0].Trim()
        $descriptionRaw = "$country|$state|$city"
        $newValues["description"] = Convert-TextToSanitized $descriptionRaw

        $newValues[$script:AdPlayerIdAttr] = $playerId

        # 2. Dynamic Attributes
        foreach ($adAttrName in $DynamicAdAttributes) {
            $csvHeader = $adAttrName
            $rawValue = $Player.$csvHeader
            $newValues[$adAttrName] = Convert-TextToSanitized $rawValue
        }

        # --- Attributes to Compare ---
        $attributesToCompare = @($CalculatedAdAttributesMap.Values) + @($DynamicAdAttributes) | Select-Object -Unique | Sort-Object
        $attributesToCompare = $attributesToCompare | Where-Object { $_ -ne $script:AdSamAccountNameAttr }

        # --- Check for Differences ---
        $generateModify = $false
        $statusDetail = "Unknown"

        if ($userExistsInSnapshot) {
            $currentAdValues = $AdSnapshot[$playerIdLower]
            if (Compare-ObjectAttributes $currentAdValues $newValues $attributesToCompare $playerId) {
                $generateModify = $true
                $statusDetail = "Exists (Modify)"
            } else {
                $statusDetail = "Exists (No Change)"
                Write-Log "No changes detected for existing player $playerId. Skipping." -Level INFO -LogFilePath $script:LogFilePath
                return $null, $statusDetail
            }
        } else {
            $statusDetail = "New (Add)"
        }

        # --- Build LDIF Content ---
        $ldifBuilder = New-Object System.Text.StringBuilder
        $dn = "CN=$($newValues['cn']),$PlayerContainerDN"
        [void]$ldifBuilder.AppendLine("dn: $dn")

        $attributesToWrite = $attributesToCompare

        if ($generateModify) {
            [void]$ldifBuilder.AppendLine("changetype: modify")
            $opsCount = 0
            foreach ($attrName in $attributesToWrite) {
                if ($attrName -eq 'cn') { continue }

                $valueToWrite = $newValues[$attrName]
                $currentAdValue = $AdSnapshot[$playerIdLower].$attrName
                $adValNorm = Convert-ValueToNormalized $currentAdValue
                $newValNorm = Convert-ValueToNormalized $valueToWrite

                if ($adValNorm -ne $newValNorm) {
                    $opsCount++
                    $ldifValue = Get-LdifSafeString $valueToWrite
                    [void]$ldifBuilder.AppendLine("replace: " + $attrName)
                    if ($ldifValue.IsBase64) {
                        [void]$ldifBuilder.AppendLine($attrName + ":: " + $ldifValue.Value)
                    } else {
                        [void]$ldifBuilder.AppendLine($attrName + ": " + $ldifValue.Value)
                    }
                    [void]$ldifBuilder.AppendLine("-")
                }
            }
            if ($opsCount -gt 0) { $ldifBuilder.Length = $ldifBuilder.Length - 3 }
        } elseif (-not $userExistsInSnapshot) {
            [void]$ldifBuilder.AppendLine("changetype: add")
            [void]$ldifBuilder.AppendLine("objectClass: top")
            [void]$ldifBuilder.AppendLine("objectClass: person")
            [void]$ldifBuilder.AppendLine("objectClass: organizationalPerson")
            [void]$ldifBuilder.AppendLine("objectClass: user")

            # Core attributes
            [void]$ldifBuilder.AppendLine("cn: " + $newValues['cn'])
            [void]$ldifBuilder.AppendLine($script:AdSamAccountNameAttr + ": " + $playerId)
            [void]$ldifBuilder.AppendLine("userPrincipalName: " + $playerId + "@" + $DomainSuffix)
            [void]$ldifBuilder.AppendLine("givenName: " + $newValues['givenName'])
            [void]$ldifBuilder.AppendLine("sn: " + $newValues['sn'])
            [void]$ldifBuilder.AppendLine("name: " + $newValues['name'])
            [void]$ldifBuilder.AppendLine("userAccountControl: 512")
            [void]$ldifBuilder.AppendLine("unicodePwd:: " + $base64PasswordString)

            # Other attributes
            $coreAttrs = 'cn', $script:AdSamAccountNameAttr, 'userPrincipalName', 'givenName', 'sn', 'name'
            foreach ($attrName in $attributesToWrite) {
                if ($attrName -notin $coreAttrs) {
                    $valueToWrite = $newValues[$attrName]
                    if ($valueToWrite) {
                        $ldifValue = Get-LdifSafeString $valueToWrite
                        if ($ldifValue.IsBase64) {
                            [void]$ldifBuilder.AppendLine($attrName + ":: " + $ldifValue.Value)
                        } else {
                            [void]$ldifBuilder.AppendLine($attrName + ": " + $ldifValue.Value)
                        }
                    }
                }
            }
        } else {
            return $null, "Internal Error"
        }

        [void]$ldifBuilder.AppendLine()
        return $ldifBuilder.ToString(), $statusDetail
    }
    finally {
        if ($BSTR -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        }
    }
}

# --- Main Processing Logic ---
Function Start-PlayerProcessing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath,
        [Parameter(Mandatory = $true)]
        [string]$PlayerContainerDN,
        [Parameter(Mandatory = $true)]
        [SecureString]$Base64Password,
        [Parameter(Mandatory = $true)]
        [string]$PlayersOutputDir,
        [Parameter(Mandatory = $true)]
        [hashtable]$AdSnapshot,
        [Parameter(Mandatory = $true)]
        [string[]]$DynamicAdAttributes,
        [Parameter(Mandatory = $true)]
        [hashtable]$CalculatedAdAttributesMap,
        [Parameter(Mandatory = $true)]
        [string]$DomainSuffix
    )
    $processedCount = 0; $generatedCount = 0; $skippedNoChange = 0; $errorCount = 0
    try {
        # Import CSV - use pipeline for potentially large files
        $totalPlayers = (Import-Csv -Path $CsvPath -Encoding UTF8 | Where-Object { -not [string]::IsNullOrWhiteSpace($_.$($script:CsvPlayerIdField)) }).Length
        Write-Log "Processing $totalPlayers players from CSV..." -Level INFO -LogFilePath $script:LogFilePath
        if ($totalPlayers -eq 0) { Write-Log "No players with IDs found." -Level WARNING -LogFilePath $script:LogFilePath; return 0 }

        Import-Csv -Path $CsvPath -Encoding UTF8 | ForEach-Object -Process {
            $processedCount++
            $playerRow = $_
            $playerId = ($playerRow.($script:CsvPlayerIdField)).Trim()
            $status = "Processing..."; $color = $script:RESET; $ldifContent = $null; $statusDetail = "Init"

            Write-Host "`r[$processedCount/$totalPlayers] $($color)$($playerId): $status$($script:RESET)" -NoNewline

            try {
                $ldifContent, $statusDetail = New-PlayerLdifContent `
                    -Player $playerRow `
                    -PlayerContainerDN $PlayerContainerDN `
                    -Base64Password $Base64Password `
                    -AdSnapshot $AdSnapshot `
                    -DynamicAdAttributes $DynamicAdAttributes `
                    -CalculatedAdAttributesMap $CalculatedAdAttributesMap `
                    -DomainSuffix $DomainSuffix

                if ($ldifContent) {
                    $outputFile = Join-Path $PlayersOutputDir "$playerId.ldf"
                    Set-Content -Path $outputFile -Value $ldifContent -Encoding Ascii -Force -ErrorAction Stop
                    $generatedCount++
                    if ($statusDetail -eq "New (Add)") { $color = $script:GREEN }
                    elseif ($statusDetail -eq "Exists (Modify)") { $color = $script:YELLOW }
                    else { $color = $script:YELLOW }
                } elseif ($statusDetail -eq "Exists (No Change)") {
                    $skippedNoChange++
                    $color = $script:CYAN
                } else { # Input error skip
                    $errorCount++
                    $color = $script:RED
                }
                # Update final status
                 Write-Host "`r[$processedCount/$totalPlayers] $($color)$($playerId): $statusDetail$($script:RESET)" -NoNewline

            } catch {
                $errorCount++ ; $status = "ERROR"; $color = $script:RED
                Write-Host "`r[$processedCount/$totalPlayers] $($color)$($playerId): $status$($script:RESET)" -NoNewline
                Write-Log ("`nError processing player " + $playerId + ": " + $_) -Level ERROR -LogFilePath $script:LogFilePath
                # Continue to next player in pipeline
            }
        } -End { Write-Host "" } # Newline after loop

        Write-Log "Processing Summary:" -Level INFO -LogFilePath $script:LogFilePath
        Write-Log "  Total records processed: $processedCount" -Level INFO -LogFilePath $script:LogFilePath
        Write-Log "  LDF files generated: $generatedCount" -Level INFO -LogFilePath $script:LogFilePath
        Write-Log "  Skipped (no changes): $skippedNoChange" -Level INFO -LogFilePath $script:LogFilePath
        Write-Log "  Skipped/Errors: $errorCount" -Level INFO -LogFilePath $script:LogFilePath
        return $generatedCount
    }
    catch {
        Write-Log "Critical error during player processing: $_" -Level CRITICAL -LogFilePath $script:LogFilePath # Exits
    }
}


# --- Main Execution ---
# Define $script:LogFilePath globally for Write-Log access
$script:LogFilePath = $null
try {
    $script:LogFilePath = Join-Path $LogBaseDir "ldif_generator_powershell_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    # Ensure log dir exists before first log write
    $null = New-Item -Path (Split-Path $script:LogFilePath -Parent) -ItemType Directory -Force -ErrorAction SilentlyContinue
    Write-Log "============================== Starting LDIF Generator (PowerShell) ==============================" -Level INFO -LogFilePath $script:LogFilePath

    # Validate required parameters
    if (-not (Test-Path $CsvPath)) {
        throw "CSV file not found: $CsvPath"
    }
    if (-not (Test-Path $OuCsvPath)) {
        throw "OU CSV file not found: $OuCsvPath"
    }
    if ([string]::IsNullOrWhiteSpace($PlayersOutputDir)) {
        throw "PlayersOutputDir is required"
    }

    # Convert password to LDIF format
    $Base64Password = Convert-PasswordToLdif -Password $DefaultPassword
    $CacheFile = Get-CachePath $PlayersOutputDir

    # --- Backup and Clear Logic ---
    Write-Log "Checking output directory: $PlayersOutputDir" -Level INFO -LogFilePath $script:LogFilePath
    if (Test-Path $PlayersOutputDir) {
        # Check if directory is not empty
        if (Get-ChildItem -Path $PlayersOutputDir) {
            $backupBaseDir = Join-Path (Split-Path $PlayersOutputDir -Parent) "ldf_backups_ps" # Distinct name
            $null = New-Item -Path $backupBaseDir -ItemType Directory -Force -ErrorAction SilentlyContinue
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $backupDestDir = Join-Path $backupBaseDir "backup_$timestamp"
            try {
                Write-Log "Backing up existing '$((Split-Path $PlayersOutputDir -Leaf))' to '$backupDestDir'..." -Level INFO -LogFilePath $script:LogFilePath
                Move-Item -Path $PlayersOutputDir -Destination $backupDestDir -Force -ErrorAction Stop
                Write-Log "Backup complete." -Level INFO -LogFilePath $script:LogFilePath
            } catch { Write-Log "Backup failed: $_" -Level CRITICAL -LogFilePath $script:LogFilePath } # Exits
        } else { Write-Log "Output dir '$PlayersOutputDir' exists but is empty." -Level INFO -LogFilePath $script:LogFilePath }
    } else { Write-Log "Output dir '$PlayersOutputDir' does not exist." -Level INFO -LogFilePath $script:LogFilePath }
    try {
        $null = New-Item -Path $PlayersOutputDir -ItemType Directory -Force -ErrorAction Stop
        Write-Log "Ensured output directory exists: $PlayersOutputDir" -Level INFO -LogFilePath $script:LogFilePath
    } catch { Write-Log "Failed create output dir '$PlayersOutputDir': $_" -Level CRITICAL -LogFilePath $script:LogFilePath } # Exits
    # --- END Backup and Clear Logic ---

    # --- Get CSV Headers and Determine Dynamic Attributes ---
    Write-Log "Processing CSV Headers from $CsvPath" -Level INFO -LogFilePath $script:LogFilePath
    try {
        # Use Select-Object -First 1 | Get-Member for headers if Import-Csv fails on large files early
        $csvHeaders = (Import-Csv -Path $CsvPath -Encoding UTF8 -Delimiter ',' | Select-Object -First 1).PSObject.Properties.Name
        if (-not $csvHeaders) { throw "People CSV is empty or has no header." }
        Write-Log "Read $($csvHeaders.Count) headers: $($csvHeaders -join ', ')" -Level INFO -LogFilePath $script:LogFilePath

        $allCalculatedTargetAttrs = $script:CalculatedAdAttributes.Values | Select-Object -Unique
        $dynamicAdAttributes = $csvHeaders | Where-Object {
            $lowerHeader = $_.ToLower()
            ($lowerHeader -ne $script:CsvPlayerIdField.ToLower()) -and
            ($lowerHeader -notin $script:ExcludedCsvHeaders) -and
            ($lowerHeader -notin $script:CalculationSourceHeaders) -and
            ($lowerHeader -notin $allCalculatedTargetAttrs) # Ensure AD name from map isn't duplicated
        }
        Write-Log "Dynamically determined $($dynamicAdAttributes.Count) AD attributes from headers." -Level INFO -LogFilePath $script:LogFilePath
        Write-Log "Dynamic Attributes: $($dynamicAdAttributes -join ', ')" -Level DEBUG -LogFilePath $script:LogFilePath
    } catch { Write-Log "Failed CSV header processing: $_" -Level CRITICAL -LogFilePath $script:LogFilePath } # Exits
    # --- End Dynamic Attribute Determination ---

    # --- Create OU structure ---
    $PlayerContainerDN = New-OuLdifFile -OuCsvPath $OuCsvPath -DomainDN $DomainDN -OuOutputPath $OuOutputPath -PlayersOuName $PlayersOuName
    if (-not $PlayerContainerDN) { Write-Log "Failed to determine player container DN." -Level CRITICAL -LogFilePath $script:LogFilePath } # Exits
    Write-Log "Target container DN for players: $PlayerContainerDN" -Level INFO -LogFilePath $script:LogFilePath

    # --- Build or Load AD Snapshot ---
    $adSnapshot = $null
    if (-not $ForceRefresh.IsPresent) {
        $adSnapshot = Load-And-VerifyCache -CacheFilePath $CacheFile -MaxAgeHours $MaxCacheAgeHours
    }

    if ($null -eq $adSnapshot) {
        Write-Log "Refreshing AD snapshot from Active Directory..." -Level INFO -LogFilePath $script:LogFilePath
        $attributesToFetch = @($script:CalculatedAdAttributes.Values) + @($dynamicAdAttributes) | Select-Object -Unique | Sort-Object

        # Pass LdapServer and Credential to Build-AdSnapshot
        $adSnapshot = Get-AdSnapshot -TargetContainerDN $PlayerContainerDN -AttributesToFetch $attributesToFetch -Server $LdapServer -Credential $Credential

        if ($null -ne $adSnapshot) { # Snapshot build succeeded (even if empty)
            Save-Cache -CacheFilePath $CacheFile -AdSnapshotHashtable $adSnapshot
        } else { Write-Log "Snapshot build failed. Cannot proceed." -Level CRITICAL -LogFilePath $script:LogFilePath } # Exits
    }
    # --- End Build AD Snapshot ---

    # --- Process players ---
    Write-Log "Starting player processing..." -Level INFO -LogFilePath $script:LogFilePath
    $startTime = Get-Date
    $filesGeneratedCount = Start-PlayerProcessing `
        -CsvPath $CsvPath `
        -PlayerContainerDN $PlayerContainerDN `
        -Base64Password $Base64Password `
        -PlayersOutputDir $PlayersOutputDir `
        -AdSnapshot $adSnapshot `
        -DynamicAdAttributes $dynamicAdAttributes `
        -CalculatedAdAttributesMap $script:CalculatedAdAttributes `
        -DomainSuffix $Domain

    $endTime = Get-Date
    Write-Log "Player processing completed in $($endTime - $startTime)." -Level INFO -LogFilePath $script:LogFilePath
    Write-Log "Generated $filesGeneratedCount LDF files requiring changes." -Level INFO -LogFilePath $script:LogFilePath
    Write-Host "`nGenerated $filesGeneratedCount LDF files."

    Write-Log "LDIF Generator finished successfully." -Level INFO -LogFilePath $script:LogFilePath

} catch {
    Write-Log "FATAL Error: $_" -Level CRITICAL -LogFilePath $script:LogFilePath
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level CRITICAL -LogFilePath $script:LogFilePath
    throw # Re-throw to ensure script exits with error
} finally {
    Write-Log "============================== Script Execution Ended ==============================" -Level INFO -LogFilePath $script:LogFilePath
    if ($script:LogFilePath) { Write-Host "`nLog file location: $($script:LogFilePath)" }
    # Optional: Stop-Transcript if started
}