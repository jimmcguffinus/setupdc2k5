#Requires -Version 7.0

param (
    [switch]$Demote
)

function Backup-AdministratorProfile {
    Write-Host "🔹 Backing up Administrator profile registry and SID..."
    
    # Export the ProfileList registry (Stores SIDs for user profiles)
    $backupPath = "C:\ProfileListBackup.reg"
    reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" $backupPath /y
    
    if (Test-Path $backupPath) {
        Write-Host "✅ ProfileList registry backup saved: $backupPath"
    } else {
        Write-Host "⚠️ Failed to backup profile registry!" -ForegroundColor Red
        exit 1
    }

    # Get current Administrator SID
    $adminSID = (Get-WmiObject Win32_UserAccount | Where-Object { $_.Name -eq "Administrator" }).SID
    if ($adminSID) {
        Write-Host "✅ Administrator SID: $adminSID"
        return $adminSID
    } else {
        Write-Host "⚠️ Failed to retrieve Administrator SID!" -ForegroundColor Red
        exit 1
    }
}

function Create-LocalAdmin {
    Write-Host "🔹 Creating a backup local Administrator account..."

    # Define a secure password for the backup account
    $securePassword = ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force

    # Check if AdminBackup already exists
    $existingUser = Get-LocalUser -Name "AdminBackup" -ErrorAction SilentlyContinue
    if ($existingUser) {
        Write-Host "✅ Backup Administrator account (AdminBackup) already exists."
    } else {
        # Create a new local admin account
        New-LocalUser -Name "AdminBackup" -Password $securePassword -FullName "Backup Admin" -Description "Backup Administrator Account" -AccountNeverExpires | Out-Null
        Add-LocalGroupMember -Group "Administrators" -Member "AdminBackup"
        Write-Host "✅ Backup Administrator account created successfully!"
    }
}

function Demote-DomainController {
    Write-Host "🔹 Checking if this machine is a Domain Controller..."
    $dcRole = (Get-WmiObject Win32_ComputerSystem).DomainRole

    if ($dcRole -ge 4) {
        Write-Host "✅ This machine is a Domain Controller. Proceeding with demotion..." -ForegroundColor Yellow

        # Backup Administrator profile
        $adminSID = Backup-AdministratorProfile

        # Create a local admin account for post-demotion login
        Create-LocalAdmin

        # Demote the DC
        Write-Host "⚠️ WARNING: The system will reboot after demotion!"
        Start-Sleep -Seconds 5
        Uninstall-ADDSDomainController -DemoteOperationMasterRole -LastDomainControllerInDomain -RemoveApplicationPartition -Force

        Write-Host "✅ Domain Controller demotion completed. The system will restart now." -ForegroundColor Green
        Restart-Computer -Force
    } else {
        Write-Host "✅ This machine is NOT a Domain Controller. No action needed."
    }
}

function Restore-AdministratorProfile {
    Write-Host "🔹 Restoring Administrator profile after demotion..."

    # Get the new local Administrator SID
    $newAdminSID = (Get-WmiObject Win32_UserAccount | Where-Object { $_.Name -eq "Administrator" }).SID
    if (-not $newAdminSID) {
        Write-Host "⚠️ Failed to retrieve new Administrator SID!" -ForegroundColor Red
        exit 1
    }

    Write-Host "✅ New Administrator SID: $newAdminSID"

    # Restore registry backup
    Write-Host "🔹 Restoring profile registry..."
    reg import "C:\ProfileListBackup.reg"

    # Find the old Administrator profile path
    $profilePath = "C:\Users\Administrator"

    if (Test-Path $profilePath) {
        Write-Host "✅ Administrator profile found at: $profilePath"

        # Assign correct ownership and permissions
        Write-Host "🔹 Reassigning profile ownership..."
        takeown /F $profilePath /R /D Y
        icacls $profilePath /setowner "Administrator" /T /C /Q
        icacls $profilePath /grant "Administrator:(F)" /T /C /Q

        Write-Host "✅ Administrator profile restored successfully!"
    } else {
        Write-Host "⚠️ Administrator profile not found. Manual intervention may be needed!" -ForegroundColor Red
    }
}

# Check if demotion is requested
if ($Demote) {
    Demote-DomainController
} else {
    Restore-AdministratorProfile
}
