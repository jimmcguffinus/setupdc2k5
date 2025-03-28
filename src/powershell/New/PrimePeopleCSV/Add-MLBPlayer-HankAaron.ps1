#Requires -Version 7.0
#Requires -Modules ActiveDirectory

# Hank Aaron's MLB attributes
$hankAttributes = @{
    # MLB specific attributes first (since we'll use playerID for AD attributes)
    playerID = "aaronha01"
    nameFirst = "Henry"
    nameLast = "Aaron"
    nameGiven = "Henry Louis"
    birthYear = "1934"
    birthMonth = "02"
    birthDay = "05"
    birthCountry = "USA"
    birthState = "AL"
    birthCity = "Mobile"
    deathYear = "2021"
    deathMonth = "01"
    deathDay = "22"
    deathCountry = "USA"
    deathState = "GA"
    deathCity = "Atlanta"
    weight = "180"
    height = "72"
    bats = "R"
    throws = "R"
    debut = "1954-04-13"
    finalGame = "1976-10-03"
    bbrefID = "aaronha01"
    retroID = "aaroh101"

    # Basic AD attributes (using playerID as SamAccountName)
    Name = "Hank Aaron"
    GivenName = "Henry"
    Surname = "Aaron"
    DisplayName = "Hank Aaron"
    SamAccountName = "aaronha01"  # Using playerID instead of haaron
    UserPrincipalName = "aaronha01@$((Get-ADDomain).DNSRoot)"  # Also using playerID here
    Description = "MLB Hall of Fame Player - Home Run King (1954-1976)"
    Enabled = $false  # Since this is a historical figure
}

# Ensure the MLB OU exists
$mlbOUPath = "OU=MLB,$((Get-ADDomain).DistinguishedName)"
if (-not (Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$mlbOUPath'" -ErrorAction SilentlyContinue)) {
    Write-Host "Creating MLB OU..."
    New-ADOrganizationalUnit -Name "MLB" -Path $((Get-ADDomain).DistinguishedName)
    Write-Host "✅ Created MLB OU"
}

# Ensure the Players OU exists
$playersOUPath = "OU=Players,$mlbOUPath"
if (-not (Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$playersOUPath'" -ErrorAction SilentlyContinue)) {
    Write-Host "Creating Players OU..."
    New-ADOrganizationalUnit -Name "Players" -Path $mlbOUPath
    Write-Host "✅ Created Players OU"
}

# Remove existing user if it exists
Write-Host "Checking for existing user account..."
try {
    Get-ADUser -Identity $hankAttributes.SamAccountName | ForEach-Object {
        Write-Host "Found existing user account, removing..."
        Remove-ADUser -Identity $_ -Confirm:$false
        Write-Host "✅ Removed existing user account"
        Start-Sleep -Seconds 2  # Wait for replication
    }
}
catch {
    # User doesn't exist, which is fine
}

Write-Host "`nCreating Hank Aaron's user account..."
try {
    # Create new user account in the MLB Players OU
    $user = New-ADUser -Path $playersOUPath `
        -Name $hankAttributes.Name `
        -GivenName $hankAttributes.GivenName `
        -Surname $hankAttributes.Surname `
        -DisplayName $hankAttributes.DisplayName `
        -SamAccountName $hankAttributes.SamAccountName `
        -UserPrincipalName $hankAttributes.UserPrincipalName `
        -Description $hankAttributes.Description `
        -Enabled $hankAttributes.Enabled `
        -PassThru

    Write-Host "✅ Successfully created user account"

    # Add MLB attributes
    Write-Host "Adding MLB attributes..."
    $mlbAttributes = @{
        playerID = $hankAttributes.playerID
        nameFirst = $hankAttributes.nameFirst
        nameLast = $hankAttributes.nameLast
        nameGiven = $hankAttributes.nameGiven
        birthYear = $hankAttributes.birthYear
        birthMonth = $hankAttributes.birthMonth
        birthDay = $hankAttributes.birthDay
        birthCountry = $hankAttributes.birthCountry
        birthState = $hankAttributes.birthState
        birthCity = $hankAttributes.birthCity
        deathYear = $hankAttributes.deathYear
        deathMonth = $hankAttributes.deathMonth
        deathDay = $hankAttributes.deathDay
        deathCountry = $hankAttributes.deathCountry
        deathState = $hankAttributes.deathState
        deathCity = $hankAttributes.deathCity
        weight = $hankAttributes.weight
        height = $hankAttributes.height
        bats = $hankAttributes.bats
        throws = $hankAttributes.throws
        debut = $hankAttributes.debut
        finalGame = $hankAttributes.finalGame
        bbrefID = $hankAttributes.bbrefID
        retroID = $hankAttributes.retroID
    }

    Set-ADUser -Identity $user -Add $mlbAttributes
    Write-Host "✅ Successfully added MLB attributes"

    # Verify the user and attributes
    Write-Host "`nVerifying user account and attributes..."
    $verifyUser = Get-ADUser -Identity $user -Properties *
    Write-Host "User Properties:"
    Write-Host "  Name: $($verifyUser.Name)"
    Write-Host "  SamAccountName: $($verifyUser.SamAccountName)"
    Write-Host "  playerID: $($verifyUser.playerID)"
    Write-Host "  Birth: $($verifyUser.birthMonth)/$($verifyUser.birthDay)/$($verifyUser.birthYear) in $($verifyUser.birthCity), $($verifyUser.birthState)"
    Write-Host "  Death: $($verifyUser.deathMonth)/$($verifyUser.deathDay)/$($verifyUser.deathYear) in $($verifyUser.deathCity), $($verifyUser.deathState)"
    Write-Host "  Height: $($verifyUser.height) inches"
    Write-Host "  Weight: $($verifyUser.weight) lbs"
    Write-Host "  Bats: $($verifyUser.bats)"
    Write-Host "  Throws: $($verifyUser.throws)"
    Write-Host "  MLB Debut: $($verifyUser.debut)"
    Write-Host "  Final Game: $($verifyUser.finalGame)"
}
catch {
    Write-Error "Failed to create or modify user account: $_"
} 