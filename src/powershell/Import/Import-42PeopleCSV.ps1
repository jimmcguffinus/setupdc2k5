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
    [string]$CsvPath = "C:\Data\mlb\baseballdatabank\core\People.csv",

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

# --- Script Setup ---
$ErrorActionPreference = 'Stop'
$VerbosePreference = if ($PSBoundParameters['Verbose']) { 'Continue' } else { 'SilentlyContinue' }
$DebugPreference = if ($PSBoundParameters['Debug']) { 'Continue' } else { 'SilentlyContinue' }

# --- Common AD Parameters Hashtable ---
# Build this before discovery, as discovery might need it
$script:commonAdParams = @{}
if ($LdapServer) { $script:commonAdParams.Server = $LdapServer }
if ($Credential) { $script:commonAdParams.Credential = $Credential }

# --- Auto-Discover Domain Info if Not Provided ---
# Use $PSBoundParameters to check if the user explicitly provided the parameters
if (-not $PSBoundParameters.ContainsKey('DomainDN') -or [string]::IsNullOrWhiteSpace($DomainDN)) {
    Write-Log "DomainDN parameter not specified, attempting auto-discovery..." -Level INFO
    try {
        $currentDomain = Get-ADDomain @script:commonAdParams # Use common params for target server/creds
        $DomainDN = $currentDomain.DistinguishedName
        Write-Log "Auto-discovered DomainDN: $DomainDN" -Level INFO
    } catch {
        Write-Log "Failed to auto-discover DomainDN: $_. Check AD connectivity/permissions or provide -DomainDN parameter." -Level CRITICAL # Exits
    }
} else {
    Write-Log "Using provided DomainDN: $DomainDN" -Level INFO
}

if (-not $PSBoundParameters.ContainsKey('Domain') -or [string]::IsNullOrWhiteSpace($Domain)) {
    Write-Log "Domain parameter not specified, attempting auto-discovery..." -Level INFO
    try {
        # Reuse previous query result if available, or query again
        if ($null -eq $currentDomain) {
            $currentDomain = Get-ADDomain @script:commonAdParams
        }
        $Domain = $currentDomain.DNSRoot
        Write-Log "Auto-discovered Domain: $Domain" -Level INFO
    } catch {
        Write-Log "Failed to auto-discover Domain: $_. Check AD connectivity/permissions or provide -Domain parameter." -Level CRITICAL # Exits
    }
} else {
    Write-Log "Using provided Domain: $Domain" -Level INFO
}
# --- END Auto-Discovery ---

# --- Global Variables / Derived Paths ---
$script:CsvPlayerIdField = "playerID"

# --- Schema Verification ---
function Test-SchemaAttribute {
    param(
        [string]$AttributeName
    )
    try {
        $schema = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter "ldapDisplayName -eq '$AttributeName'" -Properties ldapDisplayName
        return $null -ne $schema
    } catch {
        return $false
    }
}

# --- Main Script Logic ---
try {
    # Verify custom schema attributes
    $customAttributes = @(
        'birthYear',
        'birthMonth',
        'birthDay',
        'birthCountry',
        'birthState',
        'birthCity',
        'nameFirst',
        'nameLast',
        'nameGiven',
        'weight',
        'height',
        'bats',
        'throws',
        'debut',
        'finalGame',
        'retroID',
        'bbrefID'
    )

    $missingAttributes = @()
    foreach ($attr in $customAttributes) {
        if (-not (Test-SchemaAttribute -AttributeName $attr)) {
            $missingAttributes += $attr
            Write-Log "Warning: Custom schema attribute '$attr' not found in AD schema" -Level WARNING
        }
    }

    if ($missingAttributes.Count -gt 0) {
        Write-Log "Missing custom schema attributes: $($missingAttributes -join ', ')" -Level WARNING
        Write-Log "These attributes will be skipped during user creation/update" -Level WARNING
    }

    # Ensure output directory exists
    if (-not (Test-Path $PlayersOutputDir)) {
        New-Item -ItemType Directory -Path $PlayersOutputDir -Force | Out-Null
        Write-Log "Created output directory: $PlayersOutputDir" -Level INFO
    }

    # Read and validate CSV files
    Write-Log "Reading People CSV from: $CsvPath" -Level INFO
    $peopleData = Import-Csv -Path $CsvPath
    if (-not $peopleData) {
        throw "No data found in People CSV file"
    }
    Write-Log "Found $($peopleData.Count) records in People CSV" -Level INFO

    Write-Log "Reading OU CSV from: $OuCsvPath" -Level INFO
    $ouData = Import-Csv -Path $OuCsvPath
    if (-not $ouData) {
        throw "No data found in OU CSV file"
    }
    Write-Log "Found $($ouData.Count) records in OU CSV" -Level INFO

    # Initialize progress counter
    $progressCount = 0
    $totalRecords = $peopleData.Count

    # Process each person from the CSV
    foreach ($person in $peopleData) {
        # Update progress
        $progressCount++
        $percentComplete = [math]::Round(($progressCount / $totalRecords) * 100, 2)
        Write-Progress -Activity "Processing MLB Players" -Status "Processing record $progressCount of $totalRecords ($percentComplete%)" -PercentComplete $percentComplete

        # Get playerID from CSV; fallback to SamAccountName if missing.
        $playerId = $person.$script:CsvPlayerIdField
        if ([string]::IsNullOrWhiteSpace($playerId)) {
            $playerId = $person.SamAccountName
        }
        if (-not $playerId) {
            Write-Log "[$progressCount/$totalRecords] Skipping record with missing playerID" -Level WARNING
            continue
        }

        # Determine career years for DisplayName
        $careerYears = if ($person.debut -and $person.finalGame) { 
            "$($person.debut.Substring(0,4))-$($person.finalGame.Substring(0,4))" 
        } else { 
            "Unknown" 
        }

        # Handle default values for required fields
        $birthState = if ([string]::IsNullOrWhiteSpace($person.birthState)) { "NoProvince" } else { $person.birthState }
        $birthCountry = if ([string]::IsNullOrWhiteSpace($person.birthCountry)) { "Russia" } else { $person.birthCountry }
        $birthCity = if ([string]::IsNullOrWhiteSpace($person.birthCity)) { "NoCity" } else { $person.birthCity }

        # Retrieve the AD user (if exists) including all properties
        $adUser = Get-ADUser -Filter "SamAccountName -eq '$playerId'" -Properties * @script:commonAdParams -ErrorAction SilentlyContinue

        if ($null -eq $adUser) {
            # User doesn't exist, create new user with all attributes
            # Standard AD attributes
            $newUserAttributes = @{
                Name             = $playerId  # Using playerID as CN to ensure uniqueness
                SamAccountName    = $playerId
                GivenName         = $person.nameFirst
                Surname           = $person.nameLast
                DisplayName       = "$($person.nameGiven) $($person.nameLast) [$playerId $careerYears]"
                UserPrincipalName = "$playerId@$Domain"
                Description       = "$birthCountry|$birthState|$birthCity"
                Enabled           = $true
                AccountPassword   = $DefaultPassword
                Path              = "OU=$PlayersOuName,OU=MLB,$DomainDN"
            }

            # Custom schema attributes
            $otherAttributes = @{
                birthState   = $birthState
                birthCountry = $birthCountry
                birthCity   = $birthCity
                playerID    = $playerId
            }

            Write-Log "[$progressCount/$totalRecords] Creating new user: $($newUserAttributes.DisplayName)" -Level SUCCESS
            New-ADUser @newUserAttributes -OtherAttributes $otherAttributes @script:commonAdParams
        } else {
            $updateAttributes = @{}
            $deltaMessages = @()

            # Compute the derived attributes
            $computedAttrs = @{
                DisplayName       = "$($person.nameGiven) $($person.nameLast) [$playerId $careerYears]"
                Description       = "$birthCountry|$birthState|$birthCity"
                UserPrincipalName = "$playerId@$Domain"
                birthState        = $birthState
                birthCountry      = $birthCountry
                birthCity         = $birthCity
            }

            # Compare computed attributes
            foreach ($attr in $computedAttrs.Keys) {
                $computedValue = $computedAttrs[$attr]
                $adValue = if ($adUser.$attr) { $adUser.$attr.ToString().Trim() } else { "" }
                if ($computedValue.ToString().Trim() -ne $adValue) {
                    $updateAttributes[$attr] = $computedValue
                    $deltaMessages += "${attr}: '$adValue' -> '$computedValue'"
                }
            }

            # Loop through remaining CSV header properties (skip computed and others not to be compared)
            foreach ($prop in $person.PSObject.Properties) {
                $csvPropName = $prop.Name
                if ($csvPropName -in @('AccountPassword', 'Path', 'DisplayName', 'Description', 'UserPrincipalName', 'birthState', 'birthCountry', 'birthCity')) {
                    continue
                }

                if ($adUser.PSObject.Properties.Name -contains $csvPropName) {
                    $csvValue = if ($prop.Value) { $prop.Value.ToString().Trim() } else { "" }
                    $adValue = if ($adUser.$csvPropName) { $adUser.$csvPropName.ToString().Trim() } else { "" }
                    if ($csvValue -ne $adValue) {
                        $updateAttributes[$csvPropName] = $csvValue
                        $deltaMessages += "${csvPropName}: '$adValue' -> '$csvValue'"
                    }
                }
            }

            if ($updateAttributes.Count -gt 0) {
                $changes = $deltaMessages -join '; '
                Write-Log "[$progressCount/$totalRecords] UPDATE $playerId - $changes" -Level UPDATE
                Set-ADUser -Identity $adUser.DistinguishedName -Replace $updateAttributes @script:commonAdParams
            } else {
                Write-Verbose "[$progressCount/$totalRecords] No changes detected for user '$playerId'"
            }
        }
    }

    # Clear the progress bar
    Write-Progress -Activity "Processing MLB Players" -Completed
    Write-Log "Script completed successfully" -Level INFO
} catch {
    Write-Log "Error occurred: $_" -Level ERROR
    throw
}

# ... rest of the script ... 