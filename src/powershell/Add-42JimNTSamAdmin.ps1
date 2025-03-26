#requires -RunAsAdministrator
#requires -Version 5.1

# Define log file
$logFile = "C:\Temp\Add-42JimNTSamAdmin.log"
if (-not (Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory -Force }

function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "$timestamp - $Message"
    Write-Host $logMessage  # Output to console for visibility
    $logMessage | Out-File -FilePath $logFile -Append
}

# Function to remove a profile and its registry entries
function Remove-Profile {
    param (
        [string]$ProfilePath
    )

    Write-Log "Removing profile '$ProfilePath'..."

    # Remove the profile folder
    if (Test-Path $ProfilePath) {
        try {
            Remove-Item -Path $ProfilePath -Recurse -Force -ErrorAction Stop
            Write-Log "Deleted profile folder: $ProfilePath"
        }
        catch {
            Write-Log "Failed to delete profile folder '$ProfilePath': $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "Profile folder '$ProfilePath' does not exist."
    }

    # Remove the corresponding registry entry
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    $sid = Get-ChildItem $regPath | Where-Object { (Get-ItemProperty $_.PSPath).ProfileImagePath -eq $ProfilePath }
    if ($sid) {
        try {
            Remove-Item -Path $sid.PSPath -Force -ErrorAction Stop
            Write-Log "Deleted registry entry for $ProfilePath"
        }
        catch {
            Write-Log "Failed to delete registry entry for '$ProfilePath': $($_.Exception.Message)"
        }
    }
}

# Function to clean up all profiles except system profiles and the logged-in user's profile
function Clean-AllProfiles {
    Write-Log "Starting cleanup of all user profiles (except system profiles and the logged-in user's profile)..."

    # Get the current user's profile path
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $currentUserProfile = $env:USERPROFILE
    Write-Log "Current user: $currentUser with profile path: $currentUserProfile"

    # System profiles to exclude
    $systemProfiles = @(
        "C:\Users\Public",
        "C:\Users\.NET v4.5",
        "C:\Users\.NET v4.5 Classic",
        "C:\Users\Default"
    )

    # Get all profiles from the registry
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    $profiles = Get-ChildItem -Path $regPath

    # Specifically target Administrator.DC1_2K5.001, jim.MLB, and any .MLB profiles
    $targetProfiles = @("C:\Users\Administrator.DC1_2K5.001", "C:\Users\jim.MLB")
    $mlbProfiles = Get-ChildItem -Path "C:\Users" -Directory | Where-Object { $_.Name -like "*.MLB" } | ForEach-Object { $_.FullName }
    $targetProfiles += $mlbProfiles

    foreach ($profile in $profiles) {
        $profilePath = (Get-ItemProperty -Path $profile.PSPath).ProfileImagePath

        # Skip the current user's profile
        if ($profilePath -eq $currentUserProfile) {
            Write-Log "Skipping profile '$profilePath' because it belongs to the current user ($currentUser)."
            continue
        }

        # Skip system profiles
        if ($systemProfiles -contains $profilePath) {
            Write-Log "Skipping system profile '$profilePath'."
            continue
        }

        # Remove the profile if it's in the target list or matches any other non-system profile
        if ($targetProfiles -contains $profilePath -or $profilePath -like "C:\Users\*.MLB") {
            Write-Log "Processing targeted profile: $profilePath (SID: $($profile.PSChildName))"
            Remove-Profile -ProfilePath $profilePath
        }
        elseif (-not $systemProfiles -contains $profilePath) {
            Write-Log "Processing non-system profile: $profilePath (SID: $($profile.PSChildName))"
            Remove-Profile -ProfilePath $profilePath
        }
    }

    # Remove local accounts (except the built-in Administrator and the current user)
    Write-Log "Removing unnecessary local accounts..."
    $localUsers = Get-LocalUser
    foreach ($user in $localUsers) {
        $username = $user.Name
        # Skip the built-in Administrator account and the current user
        if ($username -eq "Administrator" -or $currentUser -like "*\$username") {
            Write-Log "Skipping account '$username' (built-in Administrator or current user)."
            continue
        }

        try {
            Remove-LocalUser -Name $username -ErrorAction Stop
            Write-Log "Removed local account '$username'."
        }
        catch {
            Write-Log "Failed to remove local account '$username': $($_.Exception.Message)"
        }
    }

    Write-Log "Profile and account cleanup completed."
}

# Function to create or update the jim account
function Add-42JimNTSamAdmin {
    param (
        [string]$Username = "jim"
    )

    $profilePath = "C:\Users\$Username"

    # Step 1: Clean up all profiles before creating the jim account
    Clean-AllProfiles

    # Check if the server is a domain controller
    $domainRole = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole
    $isDomainController = $domainRole -eq 5  # 5 indicates a domain controller

    if ($isDomainController) {
        Write-Log "Server is a domain controller. Managing domain user '$Username'..."

        # Step 2: Delete the domain jim account if it exists
        Write-Log "Checking for domain user '$Username'..."
        $userExists = $null
        try {
            $userExists = Get-ADUser -Filter { SamAccountName -eq $Username } -ErrorAction Stop
        }
        catch {
            Write-Log "Domain user '$Username' does not exist."
        }

        if ($userExists) {
            Write-Log "Domain user '$Username' exists. Removing to ensure a fresh account..."
            try {
                Remove-ADUser -Identity $Username -Confirm:$false -ErrorAction Stop
                Write-Log "Removed existing domain user '$Username'."
            }
            catch {
                Write-Log "Failed to remove existing domain user '$Username': $($_.Exception.Message)"
                exit 1
            }
        }

        # Step 3: Create the new domain jim account
        Write-Log "Creating new domain user '$Username'..."
        try {
            $domain = Get-ADDomain
            $domainName = $domain.NetBIOSName  # e.g., MLB
            $password = Read-Host -Prompt "Enter a secure password for domain user '$Username'" -AsSecureString
            New-ADUser -Name $Username `
                       -SamAccountName $Username `
                       -UserPrincipalName "$Username@$($domain.DNSRoot)" `
                       -DisplayName "Jim Admin" `
                       -Description "Admin account for workgroup and DC transitions" `
                       -AccountPassword $password `
                       -Enabled $true `
                       -PasswordNeverExpires $true `
                       -ErrorAction Stop
            Write-Log "Created domain user '$domainName\$Username'."
        }
        catch {
            Write-Log "Failed to create domain user '$Username': $($_.Exception.Message)"
            exit 1
        }

        # Step 4: Add jim to the required groups
        $groups = @("Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins")
        foreach ($group in $groups) {
            try {
                Add-ADGroupMember -Identity $group -Members $Username -ErrorAction Stop
                Write-Log "Added '$domainName\$Username' to '$group' group."
            }
            catch {
                if ($_.Exception.Message -like "*already a member*") {
                    Write-Log "'$domainName\$Username' is already in the '$group' group."
                }
                else {
                    Write-Log "Failed to add '$domainName\$Username' to '$group' group: $($_.Exception.Message)"
                }
            }
        }

        # Step 5: Verify the setup
        try {
            $user = Get-ADUser -Identity $Username -ErrorAction Stop
            Write-Log "Domain user '$Username' exists with SID: $($user.SID.Value)"

            foreach ($group in $groups) {
                $groupMembers = Get-ADGroupMember -Identity $group
                if ($groupMembers.SamAccountName -contains $Username) {
                    Write-Log "User '$domainName\$Username' is confirmed to be in the '$group' group."
                }
                else {
                    Write-Log "User '$domainName\$Username' is NOT in the '$group' group. Please check manually."
                }
            }
        }
        catch {
            Write-Log "Failed to verify domain user '$Username': $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "Server is not a domain controller. Managing local user '$Username'..."

        # Step 2: Delete the local jim account if it exists
        Write-Log "Checking for local user '$Username' in the SAM database..."
        $userExists = $null
        try {
            $userExists = Get-LocalUser -Name $Username -ErrorAction Stop
        }
        catch {
            Write-Log "Local user '$Username' does not exist."
        }

        if ($userExists) {
            Write-Log "Local user '$Username' exists. Removing to ensure a fresh account..."
            try {
                Remove-LocalUser -Name $Username -ErrorAction Stop
                Write-Log "Removed existing local user '$Username'."
            }
            catch {
                Write-Log "Failed to remove existing local user '$Username': $($_.Exception.Message)"
                exit 1
            }
        }

        # Step 3: Create the new local jim account
        Write-Log "Creating new local user '$Username'..."
        try {
            $password = Read-Host -Prompt "Enter a secure password for local user '$Username'" -AsSecureString
            New-LocalUser -Name $Username `
                          -Password $password `
                          -FullName "Jim Admin" `
                          -Description "Admin account for workgroup and DC transitions" `
                          -PasswordNeverExpires `
                          -AccountNeverExpires `
                          -ErrorAction Stop
            Write-Log "Created local user '$Username'."
        }
        catch {
            Write-Log "Failed to create local user '$Username': $($_.Exception.Message)"
            exit 1
        }

        # Step 4: Add jim to the local Administrators group
        try {
            Add-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction Stop
            Write-Log "Added '$Username' to the local Administrators group."
        }
        catch {
            if ($_.Exception.Message -like "*already a member*") {
                Write-Log "'$Username' is already in the local Administrators group."
            }
            else {
                Write-Log "Failed to add '$Username' to local Administrators group: $($_.Exception.Message)"
                exit 1
            }
        }

        # Step 5: Verify the setup
        try {
            $user = Get-LocalUser -Name $Username -ErrorAction Stop
            Write-Log "Local user '$Username' exists with SID: $($user.SID.Value)"

            $adminGroup = Get-LocalGroupMember -Group "Administrators"
            if ($adminGroup.Name -contains "$env:COMPUTERNAME\$Username") {
                Write-Log "User '$Username' is confirmed to be in the local Administrators group."
            }
            else {
                Write-Log "User '$Username' is NOT in the local Administrators group. Please check manually."
            }
        }
        catch {
            Write-Log "Failed to verify local user '$Username': $($_.Exception.Message)"
        }
    }

    Write-Log "User '$Username' has been created. A new profile will be created at first login."
}

# Main script
Write-Log "Starting script to create and configure user 'jim' on Windows Server 2025..."

# Create or update the jim account
Add-42JimNTSamAdmin -Username "jim"

Write-Log "Script completed."