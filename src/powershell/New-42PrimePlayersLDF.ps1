# Script parameters
param(
    [Parameter(Mandatory = $false)]
    [SecureString]$DefaultPassword = (ConvertTo-SecureString -String "Welcome2024!" -AsPlainText -Force),
    
    [Parameter(Mandatory = $false)]
    [string]$Server = "DC1_2K5",
    
    [Parameter(Mandatory = $false)]
    [string]$DomainDN = "DC=mlb,DC=dev"
)

# Function to create an LDIF packet for a single player
function New-42CreateLDFPlayerPacket {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Player,

        [Parameter(Mandatory = $true)]
        [string]$OUPath,

        [Parameter(Mandatory = $true)]
        [SecureString]$Base64Password,

        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    # Skip if playerID is missing (required field)
    if (-not $Player.PlayerID) {
        Write-Warning "Player is missing playerID. Skipping LDIF packet creation."
        return $null
    }

    # Extract debut and final game years (if available)
    $debutYear = if ($Player.Debut) { $Player.Debut.Split('-')[0] } else { "" }
    $finalGameYear = if ($Player.FinalGame) { $Player.FinalGame.Split('-')[0] } else { "" }
    $careerSpan = if ($debutYear -and $finalGameYear) { "$debutYear-$finalGameYear" } else { "Unknown" }

    # Build the display name
    $displayName = "$($Player.NameGiven) $($Player.NameLast) [$($Player.PlayerID) $careerSpan]"
    $displayName = $displayName -replace '[,\=\+\<\>#;]', '_'  # Sanitize for LDIF

    # Build the description
    $country = if ($Player.BirthCountry) { $Player.BirthCountry.Trim() } else { "NoCountry" }
    $state = if ($Player.BirthState) { $Player.BirthState.Trim() } else { if ($country -eq "USA") { "NoState" } else { "NoProvince" } }
    $city = if ($Player.BirthCity) { $Player.BirthCity.Trim() } else { "NoCity" }
    $description = "$country|$state|$city"

    # Build the CN
    $cn = $displayName

    # Define the DistinguishedName
    $dn = "CN=$cn,$OUPath"

    # Check if user exists
    $userExists = $false
    try {
        $result = & dsquery user -samid $Player.PlayerID
        $userExists = $null -ne $result
    } catch {
        $userExists = $false
    }

    # Start building LDIF content
    $ldifContent = "dn: $dn`n"

    if ($userExists) {
        # Modify Operation
        $ldifContent += "changetype: modify`n"
        
        # Add modify operations for each attribute
        $attributes = @{
            'cn' = $cn
            'sAMAccountName' = $Player.PlayerID
            'userPrincipalName' = "$($Player.PlayerID)@mlb.dev"
            'givenName' = $Player.NameFirst
            'sn' = $Player.NameLast
            'displayName' = $displayName
            'description' = $description
            'name' = $cn
        }

        foreach ($attr in $attributes.GetEnumerator()) {
            $ldifContent += "replace: $($attr.Key)`n$($attr.Key): $($attr.Value)`n-`n"
        }

        # Add MLB-specific attributes
        if ($null -ne $Player.BirthYear) { $ldifContent += "replace: birthYear`nbirthYear: $($Player.BirthYear)`n-`n" }
        if ($null -ne $Player.BirthMonth) { $ldifContent += "replace: birthMonth`nbirthMonth: $($Player.BirthMonth)`n-`n" }
        if ($null -ne $Player.BirthDay) { $ldifContent += "replace: birthDay`nbirthDay: $($Player.BirthDay)`n-`n" }
        if ($Player.BirthCountry) { $ldifContent += "replace: mlbCountry`nmlbCountry: $($Player.BirthCountry)`n-`n" }
        if ($Player.BirthState) { $ldifContent += "replace: birthState`nbirthState: $($Player.BirthState)`n-`n" }
        if ($Player.BirthCity) { $ldifContent += "replace: birthCity`nbirthCity: $($Player.BirthCity)`n-`n" }
        if ($null -ne $Player.DeathYear) { $ldifContent += "replace: deathYear`ndeathYear: $($Player.DeathYear)`n-`n" }
        if ($null -ne $Player.DeathMonth) { $ldifContent += "replace: deathMonth`ndeathMonth: $($Player.DeathMonth)`n-`n" }
        if ($null -ne $Player.DeathDay) { $ldifContent += "replace: deathDay`ndeathDay: $($Player.DeathDay)`n-`n" }
        if ($Player.DeathCountry) { $ldifContent += "replace: deathCountry`ndeathCountry: $($Player.DeathCountry)`n-`n" }
        if ($Player.DeathState) { $ldifContent += "replace: deathState`ndeathState: $($Player.DeathState)`n-`n" }
        if ($Player.DeathCity) { $ldifContent += "replace: deathCity`ndeathCity: $($Player.DeathCity)`n-`n" }
        if ($Player.NameFirst) { $ldifContent += "replace: nameFirst`nnameFirst: $($Player.NameFirst)`n-`n" }
        if ($Player.NameLast) { $ldifContent += "replace: nameLast`nnameLast: $($Player.NameLast)`n-`n" }
        if ($Player.NameGiven) { $ldifContent += "replace: nameGiven`nnameGiven: $($Player.NameGiven)`n-`n" }
        if ($null -ne $Player.Weight) { $ldifContent += "replace: weight`nweight: $($Player.Weight)`n-`n" }
        if ($null -ne $Player.Height) { $ldifContent += "replace: height`nheight: $($Player.Height)`n-`n" }
        if ($Player.Bats) { $ldifContent += "replace: bats`nbats: $($Player.Bats)`n-`n" }
        if ($Player.Throws) { $ldifContent += "replace: throws`nthrows: $($Player.Throws)`n-`n" }
        if ($Player.Debut) { $ldifContent += "replace: debut`ndebut: $($Player.Debut)`n-`n" }
        if ($Player.FinalGame) { $ldifContent += "replace: finalGame`nfinalGame: $($Player.FinalGame)`n-`n" }
        if ($Player.RetroID) { $ldifContent += "replace: retroID`nretroID: $($Player.RetroID)`n-`n" }
        if ($Player.BbrefID) { $ldifContent += "replace: bbrefID`nbbrefID: $($Player.BbrefID)`n-`n" }
    } else {
        # Add Operation
        $ldifContent += @"
changetype: add
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: $cn
sAMAccountName: $($Player.PlayerID)
userPrincipalName: $($Player.PlayerID)@mlb.dev
givenName: $($Player.NameFirst)
sn: $($Player.NameLast)
displayName: $displayName
description: $description
name: $cn
userAccountControl: 512
unicodePwd:: $([System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('"MLBPlayer2025!"')))
playerID: $($Player.PlayerID)
"@

        # Add MLB-specific attributes
        if ($null -ne $Player.BirthYear) { $ldifContent += "`nbirthYear: $($Player.BirthYear)" }
        if ($null -ne $Player.BirthMonth) { $ldifContent += "`nbirthMonth: $($Player.BirthMonth)" }
        if ($null -ne $Player.BirthDay) { $ldifContent += "`nbirthDay: $($Player.BirthDay)" }
        if ($Player.BirthCountry) { $ldifContent += "`nmlbCountry: $($Player.BirthCountry)" }
        if ($Player.BirthState) { $ldifContent += "`nbirthState: $($Player.BirthState)" }
        if ($Player.BirthCity) { $ldifContent += "`nbirthCity: $($Player.BirthCity)" }
        if ($null -ne $Player.DeathYear) { $ldifContent += "`ndeathYear: $($Player.DeathYear)" }
        if ($null -ne $Player.DeathMonth) { $ldifContent += "`ndeathMonth: $($Player.DeathMonth)" }
        if ($null -ne $Player.DeathDay) { $ldifContent += "`ndeathDay: $($Player.DeathDay)" }
        if ($Player.DeathCountry) { $ldifContent += "`ndeathCountry: $($Player.DeathCountry)" }
        if ($Player.DeathState) { $ldifContent += "`ndeathState: $($Player.DeathState)" }
        if ($Player.DeathCity) { $ldifContent += "`ndeathCity: $($Player.DeathCity)" }
        if ($Player.NameFirst) { $ldifContent += "`nnameFirst: $($Player.NameFirst)" }
        if ($Player.NameLast) { $ldifContent += "`nnameLast: $($Player.NameLast)" }
        if ($Player.NameGiven) { $ldifContent += "`nnameGiven: $($Player.NameGiven)" }
        if ($null -ne $Player.Weight) { $ldifContent += "`nweight: $($Player.Weight)" }
        if ($null -ne $Player.Height) { $ldifContent += "`nheight: $($Player.Height)" }
        if ($Player.Bats) { $ldifContent += "`nbats: $($Player.Bats)" }
        if ($Player.Throws) { $ldifContent += "`nthrows: $($Player.Throws)" }
        if ($Player.Debut) { $ldifContent += "`ndebut: $($Player.Debut)" }
        if ($Player.FinalGame) { $ldifContent += "`nfinalGame: $($Player.FinalGame)" }
        if ($Player.RetroID) { $ldifContent += "`nretroID: $($Player.RetroID)" }
        if ($Player.BbrefID) { $ldifContent += "`nbbrefID: $($Player.BbrefID)" }
    }

    # Add a blank line to separate entries
    $ldifContent += "`n"

    return $ldifContent
}

# Function to import an LDIF packet using ldifde
function New-42LDIFDePlayer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$LdifContent,

        [Parameter(Mandatory = $true)]
        [string]$LdifFilePath,

        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [string]$LogFilePath,

        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,

        [Parameter(Mandatory = $false)]
        [string]$GivenName = "Unknown"
    )

    # Write the LDIF content to a temporary file
    $LdifContent | Out-File -FilePath $LdifFilePath -Encoding ASCII

    # Import the LDIF file using ldifde
    $ldifdeCommand = "ldifde -i -f `"$LdifFilePath`" -s `"$Server`" -k -v"
    Write-Verbose "Executing ldifde command: $ldifdeCommand"
    Invoke-Expression $ldifdeCommand > $LogFilePath 2>&1

    # Check the log for errors
    $logContent = Get-Content -Path $LogFilePath
    if ($logContent -match "The command has completed successfully") {
        Write-Host "LDIF packet imported successfully for Player $SamAccountName ($GivenName). Log written to $LogFilePath"
    } else {
        Write-Warning "LDIF packet import may have failed. Please check the log at $LogFilePath"
    }
}

# Function to create OU LDIF packets
function New-42CreateOUStructureLDF {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$OUStructurePath,

        [Parameter(Mandatory = $true)]
        [string]$DomainDN,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    # Verify that PrimeOUStructure.csv exists
    if (-not (Test-Path $OUStructurePath)) {
        Write-Error "PrimeOUStructure.csv not found at $OUStructurePath. Please create the file with the OU structure."
        return $null
    }

    # Initialize the LDIF content for OUs
    $ldifContent = @()

    # Import the OU structure
    $ouStructure = Import-Csv -Path $OUStructurePath

    # Generate the OU entries and construct the OU path
    $parentDN = $DomainDN
    $ouPath = $null
    foreach ($ou in $ouStructure) {
        # Create Level1 OU
        $level1DN = "OU=$($ou.Level1),$parentDN"
        $ldifContent += @"
dn: $level1DN
changetype: add
objectClass: top
objectClass: organizationalUnit
ou: $($ou.Level1)
description: $($ou.Level1) Organization Unit

"@

        # Create Level2 OU
        if ($ou.Level2) {
            $level2DN = "OU=$($ou.Level2),$level1DN"
            $ldifContent += @"
dn: $level2DN
changetype: add
objectClass: top
objectClass: organizationalUnit
ou: $($ou.Level2)
description: $($ou.Level2) Container

"@
            $parentDN = $level2DN
            $ouPath = $level2DN
        } else {
            $parentDN = $level1DN
            $ouPath = $level1DN
        }
    }

    # Write the OU LDIF content to the specified output path
    $ldifContent | Out-File -FilePath $OutputPath -Encoding ASCII
    Write-Host "OU structure LDIF file created at: $OutputPath"

    return $ouPath
}

# Main script to process the first player and import the LDIF packet
# Define paths
$baseDir = "C:\gh\setupdc2k5"
$csvPath = "C:\Data\mlb\baseballdatabank\core\People.csv"
$ouStructurePath = "$baseDir\data\csv\PrimeOUStructure.csv"
$ldifPath = "$baseDir\data\ldfs\tempPlayer.ldf"
$logPath = "$baseDir\data\ldfs\ldifde_import.log"
$ouLdifPath = "$baseDir\data\ldfs\ouStructure.ldf"
$failureReportPath = "$baseDir\data\csv\failure_report.csv"

# Create directories if they don't exist
$directories = @(
    "$baseDir\data\csv",
    "$baseDir\data\ldfs"
)
foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "Created directory: $dir"
    }
}

# Create OU structure and get the final OU path
$ouPath = New-42CreateOUStructureLDF -OUStructurePath $ouStructurePath -DomainDN $DomainDN -OutputPath $ouLdifPath

if (-not $ouPath) {
    Write-Error "Failed to create OU structure. Exiting script."
    return
}

# Import player data from CSV with error handling
try {
    $csvData = Import-Csv -Path $csvPath -ErrorAction Stop
    Write-Host "Successfully imported $($csvData.Count) players from CSV"
} catch {
    Write-Error "Failed to import CSV file: $_"
    return
}

# Convert DefaultPassword to Base64 for LDIF
$Base64Password = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(
    (ConvertFrom-SecureString -SecureString $DefaultPassword -AsPlainText)
))

# Initialize progress tracking
$totalPlayers = $csvData.Count
$currentPlayer = 0
$successfulImports = 0
$failedImports = 0
# Add tracking for failures
$failureDetails = @()

Write-Host "Starting player import process..."
foreach ($player in $csvData) {
    $currentPlayer++
    Write-Progress -Activity "Processing Players" -Status "Processing player $currentPlayer of $totalPlayers" -PercentComplete (($currentPlayer / $totalPlayers) * 100)
    
    try {
        # Set default values for missing names
        $nameFirst = if ([string]::IsNullOrWhiteSpace($player.nameFirst)) { "Unknown" } else { $player.nameFirst }
        $nameGiven = if ([string]::IsNullOrWhiteSpace($player.nameGiven)) { $nameFirst } else { $player.nameGiven }
        
        $playerObject = [PSCustomObject]@{
            PlayerID      = $player.playerID
            BirthYear     = if ($player.birthYear) { [int]::Parse($player.birthYear) } else { $null }
            BirthMonth    = if ($player.birthMonth) { [int]::Parse($player.birthMonth) } else { $null }
            BirthDay      = if ($player.birthDay) { [int]::Parse($player.birthDay) } else { $null }
            BirthCountry  = $player.birthCountry
            BirthState    = $player.birthState
            BirthCity     = $player.birthCity
            DeathYear     = if ($player.deathYear) { [int]::Parse($player.deathYear) } else { $null }
            DeathMonth    = if ($player.deathMonth) { [int]::Parse($player.deathMonth) } else { $null }
            DeathDay      = if ($player.deathDay) { [int]::Parse($player.deathDay) } else { $null }
            DeathCountry  = $player.deathCountry
            DeathState    = $player.deathState
            DeathCity     = $player.deathCity
            NameFirst     = $nameFirst
            NameLast      = $player.nameLast
            NameGiven     = $nameGiven
            Weight        = if ($player.weight) { [int]::Parse($player.weight) } else { $null }
            Height        = if ($player.height) { [int]::Parse($player.height) } else { $null }
            Bats          = $player.bats
            Throws        = $player.throws
            Debut         = $player.debut
            FinalGame     = $player.finalGame
            RetroID       = $player.retroID
            BbrefID       = $player.bbrefID
        }

        # Generate the LDIF packet for the player
        $playerLdifContent = New-42CreateLDFPlayerPacket -Player $playerObject -OUPath $ouPath -Base64Password $Base64Password -Server $Server

        if ($playerLdifContent) {   
            # Import the LDIF packet using ldifde
            New-42LDIFDePlayer -LdifContent $playerLdifContent -LdifFilePath $ldifPath -Server $Server -LogFilePath $logPath -SamAccountName $playerObject.PlayerID -GivenName $playerObject.NameFirst
            
            # Check if the import was successful by reading the log
            $logContent = Get-Content -Path $logPath
            if ($logContent -match "The command has completed successfully") {
                $successfulImports++
            } else {
                $failedImports++
                $failureDetails += [PSCustomObject]@{
                    PlayerID = $playerObject.PlayerID
                    Name = "$($playerObject.NameFirst) $($playerObject.NameLast)"
                    ErrorType = "LDIF Import Failed"
                    ErrorDetails = ($logContent | Where-Object { $_ -match "Error|failed|warning" }) -join "; "
                    LogFile = $logPath
                }
            }
        } else {
            Write-Warning "Failed to generate LDIF packet for player $($playerObject.PlayerID)."
            $failedImports++
            $failureDetails += [PSCustomObject]@{
                PlayerID = $playerObject.PlayerID
                Name = "$($playerObject.NameFirst) $($playerObject.NameLast)"
                ErrorType = "LDIF Generation Failed"
                ErrorDetails = "Failed to generate LDIF packet"
                LogFile = $null
            }
        }
    } catch {
        Write-Error "Error processing player $($player.playerID): $_"
        $failedImports++
        $failureDetails += [PSCustomObject]@{
            PlayerID = $player.playerID
            Name = "$($player.nameFirst) $($player.nameLast)"
            ErrorType = "Processing Error"
            ErrorDetails = $_.Exception.Message
            LogFile = $null
        }
    }
}

# Clear progress bar
Write-Progress -Activity "Processing Players" -Completed

# Display summary
Write-Host "`nImport Summary:"
Write-Host "Total Players Processed: $totalPlayers"
Write-Host "Successful Imports: $successfulImports"
Write-Host "Failed Imports: $failedImports"
Write-Host "Success Rate: $([math]::Round(($successfulImports / $totalPlayers) * 100, 2))%"

# If there were failures, provide detailed analysis
if ($failedImports -gt 0) {
    Write-Host "`nFailure Analysis:"
    Write-Host "=================="
    
    # Group failures by error type
    $groupedFailures = $failureDetails | Group-Object ErrorType
    foreach ($group in $groupedFailures) {
        Write-Host "`nError Type: $($group.Name)"
        Write-Host "Count: $($group.Count)"
        Write-Host "Affected Players:"
        $group.Group | ForEach-Object {
            Write-Host "  - PlayerID: $($_.PlayerID)"
            Write-Host "    Name: $($_.Name)"
            Write-Host "    Details: $($_.ErrorDetails)"
            if ($_.LogFile) {
                Write-Host "    Log File: $($_.LogFile)"
            }
            Write-Host ""
        }
    }
    
    # Export failure details to CSV for further analysis
    $failureDetails | Export-Csv -Path $failureReportPath -NoTypeInformation
    Write-Host "`nDetailed failure report exported to: $failureReportPath"

    # Analyze the failure report
    Write-Host "`nFailure Analysis Summary:"
    Write-Host "======================="
    
    Write-Host "`nCounts by Error Type:"
    $failureDetails | Group-Object ErrorType | Format-Table @{
        Label = "Error Type"
        Expression = { $_.Name }
    }, @{
        Label = "Count"
        Expression = { $_.Count }
    }

    Write-Host "`nMost Common Error Patterns:"
    $failureDetails | Group-Object ErrorDetails | 
        Sort-Object Count -Descending | 
        Select-Object @{
            Label = "Error Pattern"
            Expression = { $_.Name }
        }, @{
            Label = "Occurrences"
            Expression = { $_.Count }
        } | Format-Table -Wrap

    Write-Host "`nDetailed LDIF Import Failures:"
    $failureDetails | Where-Object ErrorType -eq "LDIF Import Failed" | 
        Format-Table PlayerID, Name, ErrorDetails -Wrap
}