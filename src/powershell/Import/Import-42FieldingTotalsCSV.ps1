# ... existing code ...
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
    Optional: Domain DN (e.g., DC=mlb,DC=dev). Used as search base.
    If not provided, the script attempts to discover the current domain's DN using Get-ADDomain.

.PARAMETER Domain
    Optional: Domain suffix for UPN (e.g., mlb.dev).
    If not provided, the script attempts to discover the current domain's DNS root using Get-ADDomain.

.PARAMETER LdapServer
    Optional: LDAP server hostname/IP to target. Defaults to AD module's discovery.

.PARAMETER Credential
    Optional: PSCredential object to use for AD operations. Defaults to current user.

# ... rest of existing help ...
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false)]
    [System.Security.SecureString]$DefaultPassword = (ConvertTo-SecureString "MLBPlayer2025!" -AsPlainText -Force),

    [Parameter(Mandatory = $false)]
    [string]$DomainDN,

    [Parameter(Mandatory = $false)]
    [string]$Domain,

    [Parameter(Mandatory = $false)]
    [string]$LdapServer,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [string]$PlayersOuName = "Players",

    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath = "C:\Data\mlb\baseballdatabank\core\Fielding.csv",

    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$OuCsvPath = "C:\gh\setupdc2k5\data\csv\PrimeOUStructure.csv",

    [Parameter(Mandatory = $false)]
    [string]$PlayersOutputDir = "C:\gh\setupdc2k5\data\ldfs\peopleldf_files",

    [Parameter(Mandatory = $false)]
    [switch]$ForceRefresh,

    [Parameter(Mandatory = $false)]
    [int]$MaxCacheAgeHours = 24
)

# --- Write-Log Function ---
function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'CRITICAL', 'SUCCESS', 'UPDATE')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'INFO' { Write-Host $logMessage -ForegroundColor White }
        'WARNING' { Write-Host $logMessage -ForegroundColor Yellow }
        'ERROR' { Write-Host $logMessage -ForegroundColor Red }
        'CRITICAL' { 
            Write-Host $logMessage -ForegroundColor Red
            throw $Message
        }
        'SUCCESS' { Write-Host $logMessage -ForegroundColor Green }
        'UPDATE' { Write-Host $logMessage -ForegroundColor Cyan }
    }
}

Write-Host "`n=== MLB Player Data Import Script Starting ===" -ForegroundColor Cyan
Write-Log "Script starting..." -Level INFO

# Check if AD module is available
Write-Host "`n=== Checking Prerequisites ===" -ForegroundColor Cyan
Write-Host "Checking for ActiveDirectory module..." -ForegroundColor White
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Log "ActiveDirectory module is not installed. Please install RSAT tools." -Level ERROR
    return
}

try {
    Write-Host "Loading ActiveDirectory module..." -ForegroundColor White
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Log "Successfully loaded ActiveDirectory module" -Level INFO
} catch [System.Exception] {
    $msg = $_.Exception.Message
    Write-Log "Failed to load ActiveDirectory module: $msg" -Level ERROR
    return
}

# --- Script Setup ---
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'  # Always show verbose output
$DebugPreference = 'Continue'    # Always show debug output

Write-Host "`n=== Setting up Checkpoints ===" -ForegroundColor Cyan
# --- Checkpoint Setup ---
$scriptName = $MyInvocation.MyCommand.Name
$checkpointDir = "C:\gh\setupdc2k5\data\logs\checkpoint"
$checkpointFile = Join-Path $checkpointDir "$scriptName.csv"

# Ensure checkpoint directory exists
Write-Host "Checking checkpoint directory..." -ForegroundColor White
if (-not (Test-Path $checkpointDir)) {
    Write-Host "Creating checkpoint directory..." -ForegroundColor White
    New-Item -ItemType Directory -Path $checkpointDir -Force | Out-Null
    Write-Log "Created checkpoint directory: $checkpointDir" -Level INFO
}

# Import existing checkpoints if they exist
Write-Host "Loading checkpoints..." -ForegroundColor White
if (Test-Path $checkpointFile) {
    $checkpoints = Import-Csv $checkpointFile
    $successCount = ($checkpoints | Where-Object Status -eq 'Success').Count
    Write-Log "Loaded $successCount successful checkpoints" -Level INFO
    Write-Host "Found $successCount existing successful checkpoints" -ForegroundColor Green
} else {
    $checkpoints = @()
    Write-Log "No existing checkpoints found" -Level INFO
    Write-Host "No existing checkpoints found" -ForegroundColor Yellow
}

function Write-Checkpoint {
    param(
        [string]$scriptName,
        [string]$playerId,
        [string]$status
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = [PSCustomObject]@{
         ScriptName = $scriptName
         PlayerID   = $playerId
         Status     = $status
         Timestamp  = $timestamp
    }
    $entry | Export-Csv -Path $checkpointFile -Append -NoTypeInformation
}

# --- Common AD Parameters Hashtable ---
$script:commonAdParams = @{}
if ($LdapServer) { $script:commonAdParams.Server = $LdapServer }
if ($Credential) { $script:commonAdParams.Credential = $Credential }

# --- Auto-Discover Domain Info if Not Provided ---
if (-not $PSBoundParameters.ContainsKey('DomainDN') -or [string]::IsNullOrWhiteSpace($DomainDN)) {
    Write-Log "DomainDN parameter not specified, attempting auto-discovery..." -Level INFO
    try {
        $currentDomain = Get-ADDomain @script:commonAdParams
        $DomainDN = $currentDomain.DistinguishedName
        Write-Log "Auto-discovered DomainDN: $DomainDN" -Level INFO
    } catch {
        Write-Log "Failed to auto-discover DomainDN: $_. Check AD connectivity/permissions or provide -DomainDN parameter." -Level CRITICAL
    }
} else {
    Write-Log "Using provided DomainDN: $DomainDN" -Level INFO
}

if (-not $PSBoundParameters.ContainsKey('Domain') -or [string]::IsNullOrWhiteSpace($Domain)) {
    Write-Log "Domain parameter not specified, attempting auto-discovery..." -Level INFO
    try {
        if ($null -eq $currentDomain) {
            $currentDomain = Get-ADDomain @script:commonAdParams
        }
        $Domain = $currentDomain.DNSRoot
        Write-Log "Auto-discovered Domain: $Domain" -Level INFO
    } catch {
        Write-Log "Failed to auto-discover Domain: $_. Check AD connectivity/permissions or provide -Domain parameter." -Level CRITICAL
    }
} else {
    Write-Log "Using provided Domain: $Domain" -Level INFO
}

# --- Main Script Logic ---
try {
    Write-Host "`n=== Reading Input Data ===" -ForegroundColor Cyan
    Write-Host "Reading Fielding CSV file..." -ForegroundColor White
    Write-Log "Reading Fielding CSV from: $CsvPath" -Level INFO
    
    if (-not (Test-Path $CsvPath)) {
        Write-Log "CSV file not found at: $CsvPath" -Level ERROR
        Write-Host "ERROR: CSV file not found!" -ForegroundColor Red
        return
    }

    $fieldingData = Import-Csv -Path $CsvPath
    if (-not $fieldingData) {
        Write-Log "No data found in Fielding CSV file" -Level ERROR
        Write-Host "ERROR: CSV file is empty!" -ForegroundColor Red
        return
    }
    
    $recordCount = $fieldingData.Count
    Write-Log "Found $recordCount fielding records" -Level INFO
    Write-Host "Successfully loaded $recordCount fielding records" -ForegroundColor Green

    Write-Host "`n=== Processing Player Data ===" -ForegroundColor Cyan
    # Get unique player IDs
    Write-Host "Getting unique player IDs..." -ForegroundColor White
    try {
        $playerIds = $fieldingData | Select-Object -ExpandProperty playerID -Unique | Sort-Object
        $playerCount = $playerIds.Count
        Write-Log "Successfully retrieved $playerCount unique players" -Level INFO
        Write-Host "Found $playerCount unique players" -ForegroundColor Green
        Write-Host "First 5 players: $($playerIds[0..4] -join ', ')" -ForegroundColor White
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Log ("Error getting unique player IDs: {0}" -f $errorMessage) -Level ERROR
        Write-Host "ERROR: Failed to get unique players!" -ForegroundColor Red
        throw
    }

    # Initialize progress counter
    $progressCount = 0
    $totalPlayers = $playerIds.Count
    Write-Host "`nStarting player processing..." -ForegroundColor Cyan
    Write-Log "Starting to process $totalPlayers players..." -Level INFO

    # Process each player
    foreach ($playerId in $playerIds) {
        $progressCount++
        $percentComplete = [math]::Round(($progressCount / $totalPlayers) * 100, 2)
        
        Write-Host ("`nProcessing {0} ({1}/{2} - {3}%)" -f $playerId, $progressCount, $totalPlayers, $percentComplete) -ForegroundColor Yellow
        Write-Progress -Activity "Processing MLB Fielding Statistics" -Status "Processing player $progressCount of $totalPlayers ($percentComplete%)" -PercentComplete $percentComplete

        try {
            # Check if the checkpoint already exists
            $existingCheckpoint = $checkpoints | Where-Object { 
                $_.PlayerID -eq $playerId -and 
                $_.ScriptName -eq $scriptName -and 
                $_.Status -eq "Success"
            }
            
            if ($existingCheckpoint) {
                Write-Log "[$progressCount/$totalPlayers] Skipping $playerId (already processed at $($existingCheckpoint.Timestamp))" -Level INFO
                continue
            }

            # Get all fielding records for this player
            Write-Log "Getting fielding records for $playerId..." -Level INFO
            $playerFielding = $fieldingData | Where-Object playerID -eq $playerId | Sort-Object yearID

            # Skip if no records found (shouldn't happen but just in case)
            if (-not $playerFielding) {
                Write-Log "[$progressCount/$totalPlayers] No fielding records found for player $playerId" -Level WARNING
                continue
            }

            # Initialize stats totals with valid numeric attributes
            $stats = @{}
            foreach ($attr in $validAttributes) {
                if ($attr.CsvName -notin @('playerID', 'yearID', 'teamID', 'lgID', 'POS')) {
                    $stats[$attr.AdName] = 0
                }
            }

            # Calculate career totals and prepare fielding records
            $fieldingRecords = @()

            # Add the CSV header for fielding
            $fieldingRecords += """playerID"",""yearID"",""stint"",""teamID"",""lgID"",""POS"",""G"",""GS"",""InnOuts"",""PO"",""A"",""E"",""DP"",""PB"",""WP"",""SB"",""CS"",""ZR"""

            foreach ($record in $playerFielding) {
                # Add to career totals
                foreach ($attr in $validAttributes) {
                    if ($attr.CsvName -notin @('playerID', 'yearID', 'teamID', 'lgID', 'POS')) {
                        if (![string]::IsNullOrEmpty($record.($attr.CsvName))) {
                            $stats[$attr.AdName] += [int]$record.($attr.CsvName)
                        }
                    }
                }

                # Create season record in CSV format
                $values = @(
                    $record.playerID,
                    $record.yearID,
                    $record.stint,
                    $record.teamID,
                    $record.lgID,
                    $record.POS,
                    $record.G,
                    $record.GS,
                    $record.InnOuts,
                    $record.PO,
                    $record.A,
                    $record.E,
                    $record.DP,
                    $record.PB,
                    $record.WP,
                    $record.SB,
                    $record.CS,
                    $record.ZR
                )
                $fieldingRecords += """$($values -join '","')"""
            }

            # Get the most recent year for yearID
            $lastYear = ($playerFielding | Select-Object -ExpandProperty yearID | Sort-Object -Descending | Select-Object -First 1)
            $teamList = ($playerFielding | Select-Object -ExpandProperty teamID -Unique | Sort-Object) -join '|'
            $leagueList = ($playerFielding | Select-Object -ExpandProperty lgID -Unique | Sort-Object) -join '|'
            $posList = ($playerFielding | Select-Object -ExpandProperty POS -Unique | Sort-Object) -join '|'

            # Prepare update attributes
            $updateAttributes = @{}
            
            # Add numeric stats with type checking
            foreach ($key in $stats.Keys) {
                if ($null -ne $stats[$key]) {
                    $updateAttributes[$key] = [int]$stats[$key]
                }
            }

            # Add yearID as integer (most recent year)
            if ($lastYear) {
                $updateAttributes['yearID'] = [int]$lastYear
            }

            # Add string attributes
            if (![string]::IsNullOrEmpty($teamList)) {
                $updateAttributes['teamID'] = $teamList
            }
            if (![string]::IsNullOrEmpty($leagueList)) {
                $updateAttributes['lgID'] = $leagueList
            }
            if (![string]::IsNullOrEmpty($posList)) {
                $updateAttributes['POS'] = $posList
            }

            # Add fielding records as multi-value
            if ($fieldingRecords.Count -gt 0) {
                Write-Log "Found $($fieldingRecords.Count) season records for $playerId" -Level INFO
                Write-Log "First season: $($fieldingRecords[0])" -Level INFO
                Write-Log "Last season: $($fieldingRecords[-1])" -Level INFO
                Write-Log "Sample of fielding records:" -Level INFO
                $fieldingRecords | Select-Object -First 3 | ForEach-Object {
                    Write-Log "  $_" -Level INFO
                }
                Write-Log "Career totals:" -Level INFO
                foreach ($key in $stats.Keys) {
                    Write-Log "  $key = $($stats[$key])" -Level INFO
                }
                $updateAttributes['fielding'] = $fieldingRecords
            }

            # Update AD user
            try {
                $adUser = Get-ADUser -Filter "SamAccountName -eq '$playerId'" -Properties * @script:commonAdParams
                if ($adUser) {
                    Write-Log "[$progressCount/$totalPlayers] UPDATE $playerId" -Level UPDATE
                    Write-Log "Player $playerId - Attribute Values:" -Level INFO
                    foreach ($key in $updateAttributes.Keys) {
                        if ($key -eq 'fielding') {
                            Write-Log "  $key (Type: $($updateAttributes[$key].GetType().Name)) = $($updateAttributes[$key].Count) seasons" -Level INFO
                        } else {
                            Write-Log "  $key (Type: $($updateAttributes[$key].GetType().Name)) = $($updateAttributes[$key])" -Level INFO
                        }
                    }

                    # Try updating attributes one at a time to identify problematic ones
                    $updateSuccess = $true
                    foreach ($key in $updateAttributes.Keys) {
                        try {
                            $singleUpdate = @{ $key = $updateAttributes[$key] }
                            Set-ADUser -Identity $playerId -Replace $singleUpdate @script:commonAdParams
                            Write-Log "  Successfully updated $key" -Level INFO
                        } catch {
                            $updateSuccess = $false
                            Write-Log "  Failed to update $key (Type: $($updateAttributes[$key].GetType().Name), Value: $($updateAttributes[$key]))" -Level ERROR
                            Write-Log "  Error: $($_.Exception.Message)" -Level ERROR
                        }
                    }

                    # Log checkpoint if all updates were successful
                    if ($updateSuccess) {
                        Write-Checkpoint -scriptName $scriptName -playerId $playerId -status "Success"
                        Write-Log "  Checkpoint saved for $playerId" -Level INFO
                    }
                } else {
                    Write-Log "[$progressCount/$totalPlayers] Player $playerId not found in AD" -Level WARNING
                }
            } catch {
                $errorMessage = $_.Exception.Message
                Write-Log "[$progressCount/$totalPlayers] Error updating $playerId - $errorMessage" -Level ERROR
                Write-Log "Attempted attributes:" -Level ERROR
                foreach ($key in $updateAttributes.Keys) {
                    Write-Log "  $key (Type: $($updateAttributes[$key].GetType().Name)) = $($updateAttributes[$key])" -Level ERROR
                }
            }
        } catch {
            $errorMessage = $_.Exception.Message
            Write-Log ("Error processing player {0}: {1}" -f $playerId, $errorMessage) -Level ERROR
        }
    }

    # Clear progress bar
    Write-Progress -Activity "Processing MLB Fielding Statistics" -Completed
    Write-Log "Script completed successfully" -Level SUCCESS

} catch {
    Write-Log "Error occurred: $_" -Level ERROR
    throw
}

# ... rest of the script ... 