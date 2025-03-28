#requires -RunAsAdministrator
#requires -Version 5.1

# Define log file
$logFile = "C:\Temp\CreateJim.log"
if (-not (Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory -Force }

function Write-Log {
    param ([string]$Message)
    "$((Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) - $Message" | Out-File -FilePath $logFile -Append
}

# Function to create or update the jim account
function Create-JimAccount {
    param (
        [string]$Username = "jim"
    )

    Write-Log "Checking for user '$Username'..."

    # Check if jim already exists
    $userExists = $null
    try {
        $userExists = Get-LocalUser -Name $Username -ErrorAction Stop
    }
    catch {
        Write-Log "User '$Username' does not exist. Creating..."
    }

    if (-not $userExists) {
        try {
            # Prompt for the password securely
            $password = Read-Host -Prompt "Enter a secure password for user '$Username'" -AsSecureString

            # Create the jim account
            New-LocalUser -Name $Username `
                          -Password $password `
                          -FullName "Jim Admin" `
                          -Description "Admin account for workgroup and DC transitions" `
                          -PasswordNeverExpires `
                          -AccountNeverExpires `
                          -ErrorAction Stop
            Write-Log "Created user '$Username'."
        }
        catch {
            Write-Log "Failed to create user '$Username': $($_.Exception.Message)"
            exit 1
        }
    }
    else {
        Write-Log "User '$Username' already exists."
    }

    # Add jim to the Administrators group
    try {
        Add-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction Stop
        Write-Log "Added '$Username' to the Administrators group."
    }
    catch {
        if ($_.Exception.Message -like "*already a member*") {
            Write-Log "'$Username' is already in the Administrators group."
        }
        else {
            Write-Log "Failed to add '$Username' to Administrators group: $($_.Exception.Message)"
            exit 1
        }
    }

    # Check if the C:\Users\jim profile exists and associate it
    $profilePath = "C:\Users\$Username"
    if (Test-Path $profilePath) {
        Write-Log "Profile folder '$profilePath' exists. Associating with user '$Username'..."
        try {
            # Get the SID of the jim account
            $sid = (Get-LocalUser -Name $Username).SID.Value

            # Update the registry to point to the existing profile
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
            if (Test-Path $regPath) {
                Set-ItemProperty -Path $regPath -Name "ProfileImagePath" -Value $profilePath -ErrorAction Stop
                Write-Log "Associated '$profilePath' with user '$Username' in the registry."
            }
            else {
                Write-Log "Registry entry for SID '$sid' not found. It will be created on first login."
            }
        }
        catch {
            Write-Log "Failed to associate profile with '$Username': $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "Profile folder '$profilePath' does not exist. It will be created on first login."
    }
}

# Main script
Write-Log "Starting script to create and configure user 'jim' in workgroup mode on Windows Server 2025..."

# Create or update the jim account
Create-JimAccount -Username "jim"

# Verify the setup
try {
    $user = Get-LocalUser -Name "jim" -ErrorAction Stop
    Write-Log "User 'jim' exists with SID: $($user.SID.Value)"
    
    $adminGroup = Get-LocalGroupMember -Group "Administrators"
    if ($adminGroup.Name -contains "$env:COMPUTERNAME\jim") {
        Write-Log "User 'jim' is confirmed to be in the Administrators group."
    }
    else {
        Write-Log "User 'jim' is NOT in the Administrators group. Please check manually."
    }
}
catch {
    Write-Log "Failed to verify user 'jim': $($_.Exception.Message)"
}

Write-Log "Script completed."