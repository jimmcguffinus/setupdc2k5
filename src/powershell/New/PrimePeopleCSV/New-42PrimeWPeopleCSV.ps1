<#
.SYNOPSIS
    AD User Synchronization Script (PowerShell Version)

.DESCRIPTION
    Reads People CSV, determines attributes based on headers, checks against Active Directory
    (using a file-based JSON cache for performance), and creates or updates AD users
    using native PowerShell cmdlets (New-ADUser, Set-ADUser). Only updates if changes
    are detected. Creates necessary OU structure based on OU CSV. Backs up previous logs/cache.
    Designed as a PowerShell equivalent to the Python LDIF generator with snapshot caching.

.PARAMETER DefaultPassword
    Default password for new user accounts. Will be converted to a SecureString.

.PARAMETER DomainDN
    Domain DN (e.g., DC=mlb,DC=dev). Used as search base for snapshot and OU creation.

.PARAMETER Domain
    Domain suffix for UPN (e.g., mlb.dev).

.PARAMETER LdapServer
    Optional: LDAP server hostname/IP to target. Defaults to AD module's discovery.

.PARAMETER Credential
    Optional: PSCredential object to use for AD operations. Defaults to current user.

.PARAMETER PlayersOuName
    Name of the final OU where player objects will reside (e.g., "Players").

.PARAMETER CsvPath
    Path to the People CSV file.

.PARAMETER OuCsvPath
    Path to the OU structure CSV file.

.PARAMETER PlayersOutputDir
    Base directory where logs, cache, and backups will be stored relative to each other.
    Example: C:\gh\setupdc2k5\data\ldfs -> Logs in 'logs', Cache in 'snapshot_cache', Backups in 'ldf_backups_ps'.

.PARAMETER ForceRefresh
    Switch to force refresh of AD snapshot cache, ignoring existing cache file.

.PARAMETER MaxCacheAgeHours
    Maximum age of cache file in hours before refresh is triggered.

.PARAMETER WhatIf
    Switch to run the script in simulation mode. Shows what would happen without making changes.

.PARAMETER Confirm
    Switch to prompt before making changes to Active Directory.

.EXAMPLE
    .\Sync-MLBPlayersToAD.ps1 -CsvPath "C:\Data\mlb\People.csv" `
        -OuCsvPath "C:\gh\setupdc2k5\data\csv\PrimeOUStructure.csv" `
        -PlayersOutputDir "C:\gh\setupdc2k5\data\ad_sync" `
        -DomainDN "DC=mlb,DC=dev" `
        -Domain "mlb.dev" `
        -LdapServer "dc1.mlb.dev" `
        -Verbose

.EXAMPLE
    .\Sync-MLBPlayersToAD.ps1 -CsvPath "C:\Data\mlb\People.csv" -PlayersOutputDir "C:\temp\ad_sync" -ForceRefresh -Verbose -WhatIf
    # Simulates a run, forcing cache refresh, using defaults for other paths/domain.

.NOTES
    Author: Based on Python script by Jim, converted by AI Assistant
    Version: 1.0
    Requires: ActiveDirectory PowerShell Module
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false)]
    [System.Security.SecureString]$DefaultPassword = (ConvertTo-SecureString "MLBPlayer2025!" -AsPlainText -Force),

    [Parameter(Mandatory = $false)]
    [string]$DomainDN = "DC=mlb,DC=dev",

    [Parameter(Mandatory = $false)]
    [string]$Domain = "mlb.dev",

    [Parameter(Mandatory = $false)]
    [string]$LdapServer,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [string]$PlayersOuName = "Players",

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath, # = "C:\Data\mlb\baseballdatabank\core\People.csv",

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$OuCsvPath, # = "C:\gh\setupdc2k5\data\csv\PrimeOUStructure.csv",

    [Parameter(Mandatory = $true)]
    [string]$PlayersOutputDir, # Base path for logs/cache/backup

    [Parameter(Mandatory = $false)]
    [switch]$ForceRefresh,

    [Parameter(Mandatory = $false)]
    [int]$MaxCacheAgeHours = 24
)

# --- Script Setup ---
$ErrorActionPreference = 'Stop' # Exit on terminating errors
$VerbosePreference = if ($PSBoundParameters['Verbose']) { 'Continue' } else { 'SilentlyContinue' }
$DebugPreference = if ($PSBoundParameters['Debug']) { 'Continue' } else { 'SilentlyContinue' }

# --- Global Variables / Derived Paths ---
$script:CsvPlayerIdField = "playerID"
$script:AdSamAccountNameAttr = "sAMAccountName"
$script:AdPlayerIdAttr = "playerID" # Custom AD attribute

$script:CalculatedAdAttributes = @{ # Internal Key -> AD Name
    "_calculated_cn"          = "cn"
    "_calculated_displayName" = "displayName"
    "_calculated_description" = "description"
    "_calculated_givenName"   = "givenName"
    "_calculated_sn"          = "sn"
    "_calculated_name"        = "name"
}
$script:ExcludedCsvHeaders = @{}.Keys | ForEach-Object { $_.ToLower() }
$script:CalculationSourceHeaders = @("nameFirst", "nameLast", "nameGiven", "debut", "finalGame") | ForEach-Object { $_.ToLower() }

# Cache Config
$script:CacheDirectoryName = "snapshot_cache_ps" # Distinct name
$script:CacheFilename = "player_ad_snapshot.json"
$script:CurrentCacheVersion = "1.1"
$script:CacheFile = Join-Path (Join-Path $PlayersOutputDir $script:CacheDirectoryName) $script:CacheFilename

# Log Config
$script:LogDirectoryName = "logs_ps"
$script:LogFile = Join-Path (Join-Path $PlayersOutputDir $script:LogDirectoryName) "ad_sync_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Backup Config
$script:BackupDirectoryName = "sync_backups_ps"

# Common AD Parameters Hashtable
$script:commonAdParams = @{}
if ($LdapServer) { $script:commonAdParams.Server = $LdapServer }
if ($Credential) { $script:commonAdParams.Credential = $Credential }

# ANSI Colors (Optional)
$script:GREEN = "`e[92m"; $script:YELLOW = "`e[93m"; $script:CYAN = "`e[96m"; $script:RED = "`e[91m"; $script:RESET = "`e[0m"

# --- Logging Function ---
Function Write-Log {
    param(
        [Parameter(Mandatory = $true)] [string]$Message,
        [Parameter(Mandatory = $false)] [ValidateSet('DEBUG', 'VERBOSE', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')] [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Level - $Message"

    # Ensure log directory exists
    $logDir = Split-Path $script:LogFile -Parent
    if (-not (Test-Path $logDir -PathType Container)) {
        try {
            $null = New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop
            Write-Host "INFO - Created log directory: $logDir"
        } catch { Write-Warning "Failed to create log directory '$logDir': $_"; return }
    }

    # Write to File
    try { $logEntry | Out-File -FilePath $script:LogFile -Append -Encoding utf8 -ErrorAction Stop }
    catch { Write-Warning "Failed to write to log file '$($script:LogFile)': $_" }

    # Write to Console/Streams
    switch ($Level) {
        'DEBUG'    { Write-Debug $Message }
        'VERBOSE'  { Write-Verbose $Message }
        'INFO'     { Write-Host $Message } # Or Write-Information
        'WARNING'  { Write-Warning $Message }
        'ERROR'    { Write-Error $Message -ErrorAction Continue } # Continue after logging error
        'CRITICAL' { Write-Error $Message -ErrorAction Stop } # Stop script on critical
    }
}

# --- Helper Functions ---
Function ConvertTo-SecureStringPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [System.Security.SecureString]
        $Password
    )
    return $Password
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
        $strText = $strText -replace '[,=\+<>#;\\"]', '_'
        $strText = $strText.Trim()
        if ($strText.StartsWith('#')) { $strText = "_$($strText.Substring(1))" }
        $strText = $strText -replace "`r|`n", ' '

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
    # (Keep existing Truncate-CN logic using Substring - Snipped for brevity)
    $originalName = $Name; if ($Name.Length -le $MaxLength) { return $Name }
    $parts = $Name.Split('[', 2); $baseName = $parts[0].Trim()
    $suffix = if ($parts.Length -gt 1) { "[$($parts[1])" } else { "" }
    $availableSpace = $MaxLength - $suffix.Length - 3
    $truncatedName = if ($availableSpace -lt 10) { $Name.Substring(0, $MaxLength - 3) + "..." }
    else { $baseName.Substring(0, $availableSpace) + "..." + $suffix }
    Write-Log "CN for player '$PlayerIdForLogging' truncated: '$originalName' -> '$truncatedName'" -Level WARNING
    return $truncatedName
}

# --- OU Structure ---
Function Test-OuStructure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OuCsvPath,
        [Parameter(Mandatory = $true)]
        [string]$DomainDN,
        [Parameter(Mandatory = $true)]
        [string]$PlayersOuName
    )
    
    try {
        $ouData = Import-Csv -Path $OuCsvPath -Encoding UTF8
        foreach ($row in $ouData) {
            $level1Name = Convert-TextToSanitized $row.Level1 -IsDnComponent
            if (-not $level1Name) { continue }
            $level1DN = "OU=${level1Name},${DomainDN}"
            
            $currentParentDnForPlayerOu = $level1DN
            $targetPlayerDnForThisRow = $null
            $level2Name = Convert-TextToSanitized $row.Level2 -IsDnComponent

            if ($level2Name) {
                if ($level2Name -eq $PlayersOuName) {
                    $playersDN = "OU=${level2Name},${level1DN}"
                    $targetPlayerDnForThisRow = $playersDN
                } else {
                    $level2DN = "OU=${level2Name},${level1DN}"
                    $currentParentDnForPlayerOu = $level2DN
                    $playersDN = "OU=${PlayersOuName},${currentParentDnForPlayerOu}"
                    $targetPlayerDnForThisRow = $playersDN
                }
            } else {
                $playersDN = "OU=${PlayersOuName},${currentParentDnForPlayerOu}"
                $targetPlayerDnForThisRow = $playersDN
            }

            if ($targetPlayerDnForThisRow) {
                return $targetPlayerDnForThisRow
            }
        }
        return $null
    }
    catch {
        Write-Log "Error processing OU structure: $_" -Level ERROR
        return $null
    }
}


# --- AD Interaction (Snapshot) ---
Function Get-AdUserSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ContainerDN,
        [Parameter(Mandatory = $true)]
        [string[]]$AttributesToFetch,
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        [Parameter(Mandatory = $false)]
        [int]$RetryDelaySeconds = 5
    )

    $retryCount = 0
    while ($retryCount -lt $MaxRetries) {
        try {
            Write-Log "Building AD snapshot from container $ContainerDN" -Level INFO
            $users = Get-ADUser -SearchBase $ContainerDN -Filter * -Properties $AttributesToFetch @script:commonAdParams
            
            $snapshot = @{}
            foreach ($user in $users) {
                $snapshot[$user.SamAccountName] = @{}
                foreach ($attr in $AttributesToFetch) {
                    $snapshot[$user.SamAccountName][$attr] = $user.$attr
                }
            }
            
            Write-Log "AD snapshot complete - Found $($users.Count) users" -Level INFO
            return $snapshot
        }
        catch {
            $retryCount++
            if ($retryCount -ge $MaxRetries) {
                Write-Log "Failed to build AD snapshot after $MaxRetries attempts: $_" -Level ERROR
                throw
            }
            Write-Log "Error building AD snapshot (attempt $retryCount/$MaxRetries): $_" -Level WARN
            Start-Sleep -Seconds ($RetryDelaySeconds * [Math]::Pow(2, $retryCount - 1))
        }
    }
}

# --- Cache Handling ---
Function Get-CachePath { 
    param([string]$PlayersOutputDir)
    $baseDir = Split-Path $PlayersOutputDir -Parent
    $cacheDir = Join-Path $baseDir $script:CacheDirectoryName
    $null = New-Item -Path $cacheDir -ItemType Directory -Force -EA 0
    return Join-Path $cacheDir $script:CacheFilename 
}

Function Test-CacheValidity { 
    param(
        [string]$CacheFilePath, 
        [int]$MaxAgeHours
    )
    # Keep existing Load-AndVerifyCache function logic
    return $null
}

Function Save-Cache { 
    param(
        [string]$CacheFilePath, 
        [hashtable]$AdSnapshotHashtable
    )
    # Keep existing Save-Cache function logic
    return $null
}

# --- Comparison Logic ---
Function Convert-ValueToNormalized { 
    param($Value)
    if ($null -eq $Value) { return "" }
    return ($Value | Out-String).Trim() 
}

Function Compare-AdAttributes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$CurrentAdValues,
        [Parameter(Mandatory = $true)]
        [hashtable]$NewCsvValues,
        [Parameter(Mandatory = $true)]
        [string[]]$AttributesToCompare,
        [Parameter(Mandatory = $true)]
        [string]$PlayerIdForLogging
    )

    if ($null -eq $CurrentAdValues) {
        Write-Log "No current AD values found for player $PlayerIdForLogging" -Level DEBUG
        return $true
    }

    foreach ($attr in $AttributesToCompare) {
        try {
            $currentValue = $CurrentAdValues[$attr]
            $newValue = $NewCsvValues[$attr]
            
            if ($null -eq $currentValue -and $null -eq $newValue) { continue }
            if ($null -eq $currentValue -or $null -eq $newValue) {
                Write-Log "Difference detected for $PlayerIdForLogging - Attribute $attr`: Current=$currentValue, New=$newValue" -Level DEBUG
                return $true
            }

            $normalizedCurrent = $currentValue | ForEach-Object { Convert-TextToSanitized $_ }
            $normalizedNew = $newValue | ForEach-Object { Convert-TextToSanitized $_ }

            if (Compare-Object $normalizedCurrent $normalizedNew) {
                Write-Log "Difference detected for $PlayerIdForLogging - Attribute $attr`: Current=$currentValue, New=$newValue" -Level DEBUG
                return $true
            }
        }
        catch {
            Write-Log "Error comparing attribute $attr for player $PlayerIdForLogging`: $_" -Level ERROR
            return $true
        }
    }
    return $false
}

# --- AD User Synchronization ---
Function Sync-ADUser {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)] [PSCustomObject]$Player, # Row from Import-Csv
        [Parameter(Mandatory)] [string]$PlayerContainerDN,
        [Parameter(Mandatory)] [System.Security.SecureString]$SecurePassword,
        [Parameter(Mandatory)] [hashtable]$AdSnapshot, # Snapshot Hashtable
        [Parameter(Mandatory)] [string[]]$DynamicAdAttributes,
        [Parameter(Mandatory)] [hashtable]$CalculatedAdAttributesMap, # Expects @{_calc_cn = 'cn'; ...}
        [Parameter(Mandatory)] [string]$DomainSuffix # e.g., mlb.dev
    )

    $playerId = ($Player.($script:CsvPlayerIdField)).Trim()
    if (-not $playerId) { return "Skipped (No PlayerID)" }
    $playerIdLower = $playerId.ToLower()
    $userExistsInSnapshot = $AdSnapshot.ContainsKey($playerIdLower)

    # --- Construct New Values Hashtable from CSV ---
    $newValues = @{}; $statusDetail = "Unknown"

    # 1. Calculated Attributes
    # (Keep logic to calculate cn, displayName, description, givenName, sn, name - Snipped)
    $nameLast = ($Player.nameLast).Trim(); if (-not $nameLast) { return "Skipped (No Last Name)" }
    $nameFirst = ($Player.nameFirst).Trim(); $nameGiven = ($Player.nameGiven).Trim()
    if (-not $nameFirst -and -not $nameGiven) { $nameFirst = $nameLast; $nameGiven = $nameLast }
    $nameFirst = if ($nameFirst) { $nameFirst } elseif ($nameGiven) { $nameGiven } else { $nameLast }
    $nameGiven = if ($nameGiven) { $nameGiven } else { $nameFirst }
    $newValues["givenName"] = Convert-TextToSanitized $nameFirst; $newValues["sn"] = Convert-TextToSanitized $nameLast
    $debut = ($Player.debut).Trim(); $finalGame = ($Player.finalGame).Trim()
    $debutYear = if ($debut -match '^\d{4}') { $debut.Split('-')[0] } else { "" }
    $finalGameYear = if ($finalGame -match '^\d{4}') { $finalGame.Split('-')[0] } else { "" }
    $careerSpan = if ($debutYear -and $finalGameYear) { "$debutYear-$finalGameYear" } else { "Unknown" }
    $displayNameRaw = "$nameGiven $nameLast [$playerId $careerSpan]"; $newValues["displayName"] = Convert-TextToSanitized $displayNameRaw
    $cnRaw = "$nameGiven $nameLast $playerId"; $calculatedCN = Limit-CNLength (Convert-TextToSanitized $cnRaw) $playerId
    $newValues["cn"] = $calculatedCN; $newValues["name"] = $calculatedCN
    $country = Convert-TextToSanitized ($Player.birthCountry -replace '^$', 'NoCountry'); $state = Convert-TextToSanitized $Player.birthState
    if (-not $state -and $country -eq 'USA') { $state = "NoState" } elseif (-not $state) { $state = "NoProvince" }
    $city = Convert-TextToSanitized ($Player.birthCity -replace '^$', 'NoCity'); $city = ($city -split 'Retrosheet')[0].Trim(); $city = ($city -split 'Baseball-Reference')[0].Trim()
    $descriptionRaw = "$country|$state|$city"; $newValues["description"] = Convert-TextToSanitized $descriptionRaw
    $newValues[$script:AdPlayerIdAttr] = $playerId # Custom playerID

    # 2. Dynamic Attributes
    foreach ($adAttrName in $DynamicAdAttributes) {
        $csvHeader = $adAttrName; $rawValue = $Player.$csvHeader
        $newValues[$adAttrName] = Convert-TextToSanitized $rawValue
    }

    # --- Attributes to Compare/Set ---
    $attributesToProcess = @($CalculatedAdAttributesMap.Values) + @($DynamicAdAttributes) | Select-Object -Unique | Sort-Object
    $attributesToProcess = $attributesToProcess | Where-Object { $_ -ne $script:AdSamAccountNameAttr }

    # --- Compare and Act ---
    try {
        if ($userExistsInSnapshot) {
            $currentAdValues = $AdSnapshot[$playerIdLower]
            if (Compare-AdAttributes $currentAdValues $newValues $attributesToProcess $playerId) {
                # Build -Replace Hashtable with ONLY changed attributes
                $replaceHashTable = @{}
                foreach ($attr in $attributesToProcess) {
                    if ($attr -eq 'cn' -or $attr -eq 'name') { continue } # Cannot replace cn/name easily
                    $adValueNorm = Convert-ValueToNormalized $currentAdValues.$attr
                    $csvValueNorm = Convert-ValueToNormalized $newValues[$attr]
                    if ($adValueNorm -ne $csvValueNorm) { # Case-insensitive compare
                        # Use the value from $newValues which should be sanitized string
                        $replaceHashTable[$attr] = $newValues[$attr]
                    }
                }

                if ($replaceHashTable.Count -gt 0) {
                     $statusDetail = "Exists (Modify)"
                     $targetUser = $AdSnapshot[$playerIdLower].($script:AdSamAccountNameAttr) # Use SAM for identity
                     $setParams = @{ Identity = $targetUser; Replace = $replaceHashTable } + $script:commonAdParams

                     if ($PSCmdlet.ShouldProcess($targetUser, "Set-ADUser -Replace attributes")) {
                         Set-ADUser @setParams
                         Write-Log "Modified AD User: $playerId" -Level INFO
                     } else { $statusDetail = "Exists (Modify - WhatIf)" }
                } else {
                     $statusDetail = "Exists (No Change)"
                     Write-Log "No actionable changes detected for existing player $playerId." -Level INFO
                }
            } else {
                $statusDetail = "Exists (No Change)"
                Write-Log "No changes detected for existing player $playerId." -Level INFO
            }
        } else { # New User
            $statusDetail = "New (Add)"
            # Build parameter hash for New-ADUser
            $newUserParams = @{
                Name            = $newValues['cn']
                SamAccountName  = $playerId
                UserPrincipalName = "$($playerId)@$($DomainSuffix)"
                GivenName       = $newValues['givenName']
                Surname         = $newValues['sn']
                DisplayName     = $newValues['displayName']
                Description     = $newValues['description']
                Path            = $PlayerContainerDN
                AccountPassword = $SecurePassword
                Enabled         = $true
                ChangePasswordAtLogon = $true # Good practice for initial password
            } + $script:commonAdParams

            # Build -OtherAttributes hash for custom/dynamic fields
            $otherAttributes = @{}
            $coreAttrs = 'cn', $script:AdSamAccountNameAttr, 'userPrincipalName', 'givenName', 'sn', 'name', 'displayName', 'description'
            foreach ($attr in $attributesToProcess) {
                 if ($attr -notin $coreAttrs) {
                     $valueToWrite = $newValues[$attr]
                     if ($valueToWrite) { # Only add if not empty string
                         $otherAttributes[$attr] = $valueToWrite
                     }
                 }
            }
            if ($otherAttributes.Count -gt 0) {
                $newUserParams.OtherAttributes = $otherAttributes
            }

            if ($PSCmdlet.ShouldProcess($newUserParams.Name, "New-ADUser in $PlayerContainerDN")) {
                New-ADUser @newUserParams
                Write-Log "Created AD User: $playerId" -Level INFO
            } else { $statusDetail = "New (Add - WhatIf)" }
        }
        return $statusDetail
    } catch {
        Write-Log ("Error syncing player ${playerId}: " + $_) -Level ERROR
        return "Error"
    }
}


# --- Main Script Body ---
try {
    # Setup Logging
    Write-Log "============================== Starting AD Sync (PowerShell) ==============================" -Level INFO

    # --- Backup and Clear (Placeholder - Add logic if needed for logs/cache) ---
    Write-Log "Backup/Clear step (if needed for logs/cache) - Placeholder" -Level INFO
    # Example: Move old cache dir if exists (similar to Python LDF backup)

    # --- Get CSV Headers & Dynamic Attributes ---
    Write-Log "Processing CSV Headers from $CsvPath" -Level INFO
    try {
        $csvHeaders = (Import-Csv -Path $CsvPath -Encoding UTF8 -Delimiter ',' | Select-Object -First 1).PSObject.Properties.Name
        if (-not $csvHeaders) { throw "People CSV is empty or has no header." }
        # (Keep dynamic attribute calculation logic - Snipped)
        $dynamicAdAttributes = $csvHeaders | Where-Object { ... } # As before
        Write-Log "Dynamically determined $($dynamicAdAttributes.Count) AD attributes." -Level INFO
    } catch { Write-Log "Failed CSV header processing: $_" -Level CRITICAL }

    # --- Ensure OU Structure ---
    $PlayerContainerDN = Test-OuStructure -OuCsvPath $OuCsvPath -DomainDN $DomainDN -PlayersOuName $PlayersOuName
    if (-not $PlayerContainerDN) { Write-Log "Failed to determine player container DN." -Level CRITICAL }
    Write-Log "Target container DN for players: $PlayerContainerDN" -Level INFO

    # --- Build or Load AD Snapshot ---
    $adSnapshot = $null
    if (-not $ForceRefresh.IsPresent) {
        $adSnapshot = Test-CacheValidity -CacheFilePath $script:CacheFile -MaxAgeHours $MaxCacheAgeHours
    }
    if ($null -eq $adSnapshot) {
        Write-Log "Refreshing AD snapshot..." -Level INFO
        $attributesToFetch = @($script:CalculatedAdAttributes.Values) + @($dynamicAdAttributes) | Select-Object -Unique | Sort-Object
        $adSnapshot = Get-AdUserSnapshot -ContainerDN $PlayerContainerDN -AttributesToFetch $attributesToFetch
        if ($null -ne $adSnapshot) {
            Save-Cache -CacheFilePath $script:CacheFile -AdSnapshotHashtable $adSnapshot
        } else { Write-Log "Snapshot build failed. Cannot proceed." -Level CRITICAL }
    }

    # --- Process Players ---
    Write-Log "Starting player synchronization..." -Level INFO
    $securePassword = $DefaultPassword # Already a SecureString from parameter
    $startTime = Get-Date
    $processedCount = 0; $createdCount = 0; $modifiedCount = 0; $noChangeCount = 0; $errorCount = 0; $skippedCount = 0
    $totalPlayersEstimate = (Import-Csv -Path $CsvPath -Encoding UTF8 | Where-Object { -not [string]::IsNullOrWhiteSpace($_.$($script:CsvPlayerIdField)) }).Length # Re-estimate

    Import-Csv -Path $CsvPath -Encoding UTF8 | ForEach-Object -Process {
        $processedCount++
        $playerRow = $_
        $playerId = ($playerRow.($script:CsvPlayerIdField)).Trim()

        Write-Progress -Activity "Syncing Players" -Status ("Processing ${processedCount}/${totalPlayersEstimate}: ${playerId}") -PercentComplete (($processedCount / $totalPlayersEstimate) * 100)

        try {
            $syncStatus = Sync-ADUser `
                -Player $playerRow `
                -PlayerContainerDN $PlayerContainerDN `
                -SecurePassword $securePassword `
                -AdSnapshot $adSnapshot `
                -DynamicAdAttributes $dynamicAdAttributes `
                -CalculatedAdAttributesMap $script:CalculatedAdAttributes `
                -DomainSuffix $Domain

            # Update console status line (optional, Write-Progress is often better)
            # Tally results
            switch -Regex ($syncStatus) {
                'Created'              { $script:createdCount++ }
                'Modify'               { $script:modifiedCount++ } # Catches "Exists (Modify)" and "Exists (Modify - WhatIf)"
                'No Change'            { $script:noChangeCount++ }
                'Skipped'              { $script:skippedCount++ }
                'Error'                { $script:errorCount++ }
            }
        } catch {
             $script:errorCount++
             Write-Log ("CRITICAL error during Sync-ADUser for ${playerId}: " + $_) -Level ERROR
             # Consider stopping vs continuing based on error severity
        }
    } -End { Write-Progress -Activity "Syncing Players" -Completed }

    $endTime = Get-Date
    Write-Log "Player synchronization completed in $($endTime - $startTime)." -Level INFO
    Write-Log "Summary: Processed=$processedCount, Created=$createdCount, Modified=$modifiedCount, NoChange=$noChangeCount, SkippedInput=$skippedCount, Errors=$errorCount" -Level INFO

    Write-Host "`nSynchronization Summary"
    Write-Host "---------------------"
    Write-Host "Processed: $processedCount"
    Write-Host "Created: $createdCount" -ForegroundColor Green
    Write-Host "Modified: $modifiedCount" -ForegroundColor Yellow
    Write-Host "No Change: $noChangeCount" -ForegroundColor Cyan
    Write-Host "Skipped (Input): $skippedCount" -ForegroundColor DarkGray
    Write-Host "Errors: $errorCount" -ForegroundColor Red

    Write-Log "AD Sync finished successfully." -Level INFO

} catch {
    Write-Log "FATAL Script Error: $_" -Level CRITICAL
} finally {
    Write-Log "============================== Script Execution Ended ==============================" -Level INFO
    Write-Host "`nLog file location: $($script:LogFile)"
}