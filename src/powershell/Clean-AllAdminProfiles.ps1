#requires -RunAsAdministrator
#requires -Version 5.1

# Log file
$logFile = "C:\Temp\Clean-AllProfiles.log"
if (-not (Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory -Force }

function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "$timestamp - $Message"
    Write-Host $logMessage
    $logMessage | Out-File -FilePath $logFile -Append
}

# Function to remove a profile and its registry entry
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

# Main script
Write-Log "Starting cleanup of all Administrator, jim, and tempadmin profiles..."

# Check if logged in as Administrator, jim, or tempadmin
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
if ($currentUser -like "*\Administrator") {
    Write-Log "Cannot clean up Administrator profiles while logged in as Administrator. Please log in as a different domain admin (e.g., MLB\jim) and run this script again."
    exit 1
}
if ($currentUser -like "*\jim") {
    Write-Log "Cannot clean up jim profiles while logged in as jim. Please log in as a different domain admin (e.g., MLB\Administrator) and run this script again."
    exit 1
}
if ($currentUser -like "*\tempadmin") {
    Write-Log "Cannot clean up tempadmin profiles while logged in as tempadmin. Please log in as a different domain admin (e.g., MLB\Administrator or MLB\jim) and run this script again."
    exit 1
}

# Get the SID of the domain Administrator account
try {
    $adminSid = (Get-ADUser -Identity "Administrator").SID.Value
    Write-Log "Domain Administrator SID: $adminSid"
}
catch {
    Write-Log "Failed to get SID for domain Administrator: $($_.Exception.Message)"
    exit 1
}

# Get the SID of the domain jim account
try {
    $jimSid = (Get-ADUser -Identity "jim").SID.Value
    Write-Log "Domain jim SID: $jimSid"
}
catch {
    Write-Log "Failed to get SID for domain jim: $($_.Exception.Message)"
    exit 1
}

# Find all profiles that match Administrator (including duplicates like Administrator.MLB)
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$adminProfiles = Get-ChildItem -Path $regPath | Where-Object {
    $profilePath = (Get-ItemProperty -Path $_.PSPath).ProfileImagePath
    $profilePath -like "C:\Users\Administrator*" -and $_.PSChildName -ne $adminSid
}

if ($adminProfiles) {
    Write-Log "Found $($adminProfiles.Count) Administrator profiles to clean up."
    foreach ($profile in $adminProfiles) {
        $profilePath = (Get-ItemProperty -Path $profile.PSPath).ProfileImagePath
        Write-Log "Processing profile: $profilePath (SID: $($profile.PSChildName))"
        Remove-Profile -ProfilePath $profilePath
    }
}
else {
    Write-Log "No conflicting Administrator profiles found."
}

# Ensure the primary Administrator profile is cleaned up (if not associated with the current SID)
$primaryAdminProfilePath = "C:\Users\Administrator"
$primaryAdminProfileSid = Get-ChildItem $regPath | Where-Object { (Get-ItemProperty $_.PSPath).ProfileImagePath -eq $primaryAdminProfilePath }
if ($primaryAdminProfileSid -and $primaryAdminProfileSid.PSChildName -ne $adminSid) {
    Write-Log "Primary Administrator profile ($primaryAdminProfilePath) is not associated with the current domain Administrator SID. Cleaning up..."
    Remove-Profile -ProfilePath $primaryAdminProfilePath
}
else {
    Write-Log "Primary Administrator profile ($primaryAdminProfilePath) is either associated with the current domain Administrator SID or does not exist. No cleanup needed."
}

# Find all profiles that match jim (including duplicates like jim.MLB)
$jimProfiles = Get-ChildItem -Path $regPath | Where-Object {
    $profilePath = (Get-ItemProperty -Path $_.PSPath).ProfileImagePath
    $profilePath -like "C:\Users\jim*" -and $_.PSChildName -ne $jimSid
}

if ($jimProfiles) {
    Write-Log "Found $($jimProfiles.Count) jim profiles to clean up."
    foreach ($profile in $jimProfiles) {
        $profilePath = (Get-ItemProperty -Path $profile.PSPath).ProfileImagePath
        Write-Log "Processing profile: $profilePath (SID: $($profile.PSChildName))"
        Remove-Profile -ProfilePath $profilePath
    }
}
else {
    Write-Log "No conflicting jim profiles found."
}

# Ensure the primary jim profile is cleaned up (if not associated with the current SID)
$primaryJimProfilePath = "C:\Users\jim"
$primaryJimProfileSid = Get-ChildItem $regPath | Where-Object { (Get-ItemProperty $_.PSPath).ProfileImagePath -eq $primaryJimProfilePath }
if ($primaryJimProfileSid -and $primaryJimProfileSid.PSChildName -ne $jimSid) {
    Write-Log "Primary jim profile ($primaryJimProfilePath) is not associated with the current domain jim SID. Cleaning up..."
    Remove-Profile -ProfilePath $primaryJimProfilePath
}
else {
    Write-Log "Primary jim profile ($primaryJimProfilePath) is either associated with the current domain jim SID or does not exist. No cleanup needed."
}

# Remove the tempadmin account and its profile
Write-Log "Removing tempadmin account and profile..."

# Remove the tempadmin account from Active Directory
try {
    $tempadminExists = Get-ADUser -Filter { SamAccountName -eq "tempadmin" } -ErrorAction Stop
    if ($tempadminExists) {
        Remove-ADUser -Identity "tempadmin" -Confirm:$false -ErrorAction Stop
        Write-Log "Removed tempadmin account from Active Directory."
    }
    else {
        Write-Log "tempadmin account does not exist in Active Directory."
    }
}
catch {
    Write-Log "Failed to remove tempadmin account: $($_.Exception.Message)"
}

# Clean up tempadmin profile
$tempadminProfilePath = "C:\Users\tempadmin"
Write-Log "Cleaning up tempadmin profile ($tempadminProfilePath)..."
Remove-Profile -ProfilePath $tempadminProfilePath

Write-Log "Cleanup of all Administrator, jim, and tempadmin profiles completed. Log in as MLB\Administrator or MLB\jim to create fresh profiles."