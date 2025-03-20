#Requires -Version 7.0

<#
.SYNOPSIS
    Script to toggle between domain controller and workgroup modes for schema testing.

.DESCRIPTION
    This script allows switching between:
    - Domain Controller mode (for schema modifications)
    - Workgroup mode (for testing)

    The script preserves the Administrator profile and installed applications
    during transitions to avoid reinstallation requirements.

.OUTPUTS
    Success or failure messages for each phase of the transition.
#>

# Ensure we are in PowerShell 7+.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7.0 or later."
    exit 1
}

# Set execution policy to bypass for this session.
Set-ExecutionPolicy Bypass -Scope Process -Force

# Function to check current system state.
function Get-SystemState {
    $isDomainController = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
    $isWorkgroup        = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq $false

    if ($isDomainController) {
        return "DomainController"
    }
    elseif ($isWorkgroup) {
        return "Workgroup"
    }
    else {
        return "DomainMember"
    }
}

# Function to enable schema modifications.
function Enable-SchemaModifications {
    # Enable Schema modifications by setting registry key.
    $regPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
    Set-ItemProperty -Path $regPath -Name "Schema Update Allowed" -Value 1 -Type DWord
    
    # Restart AD DS service.
    Restart-Service NTDS
    
    Write-Output "Schema modifications have been enabled. You can now modify the schema."
}

# Function to back up Administrator profile data.
function Backup-AdminProfile {
    Write-Output "Backing up Administrator profile data..."
    $backupPath = "C:\AdminProfileBackup"

    if (-not (Test-Path $backupPath)) {
        New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
    }

    # Use robocopy instead of Copy-Item for better handling of in-use files.
    # Exclude problematic directories and use backup mode.
    $excludeDirs   = @('Application Data','Temporary Internet Files','History','Cache','Temp')
    $excludeParams = $excludeDirs | ForEach-Object { "/XD `"$($_)`"" }

    # Backup AppData\Local excluding problematic folders.
    $cmd = "robocopy `"C:\Users\Administrator\AppData\Local`" `"$backupPath\Local`" /E /ZB /R:1 /W:1 /XJ $excludeParams"
    Invoke-Expression $cmd

    # Backup AppData\Roaming excluding problematic folders.
    $cmd = "robocopy `"C:\Users\Administrator\AppData\Roaming`" `"$backupPath\Roaming`" /E /ZB /R:1 /W:1 /XJ $excludeParams"
    Invoke-Expression $cmd

    # Backup Desktop.
    $cmd = "robocopy `"C:\Users\Administrator\Desktop`" `"$backupPath\Desktop`" /E /ZB /R:1 /W:1 /XJ"
    Invoke-Expression $cmd

    Write-Output "Profile backup completed with robocopy."
}

# Function to restore Administrator profile data.
function Restore-AdminProfile {
    if (Test-Path "C:\AdminProfileBackup") {
        Write-Output "Restoring Administrator profile..."

        # Use robocopy for restoration.
        $excludeDirs   = @('Application Data','Temporary Internet Files','History','Cache','Temp')
        $excludeParams = $excludeDirs | ForEach-Object { "/XD `"$($_)`"" }

        # Restore Local AppData.
        $cmd = "robocopy `"C:\AdminProfileBackup\Local`" `"C:\Users\Administrator\AppData\Local`" /E /ZB /R:1 /W:1 /XJ $excludeParams"
        Invoke-Expression $cmd

        # Restore Roaming AppData.
        $cmd = "robocopy `"C:\AdminProfileBackup\Roaming`" `"C:\Users\Administrator\AppData\Roaming`" /E /ZB /R:1 /W:1 /XJ $excludeParams"
        Invoke-Expression $cmd

        # Restore Desktop.
        $cmd = "robocopy `"C:\AdminProfileBackup\Desktop`" `"C:\Users\Administrator\Desktop`" /E /ZB /R:1 /W:1 /XJ"
        Invoke-Expression $cmd

        Write-Output "Profile restoration completed."
    }
}

# Function to convert to domain controller.
function Convert-ToDomainController {
    # Prompt the user to enter the domain name (FQDN).
    $domainName = Read-Host "Enter the fully qualified domain name (FQDN)"

    # If ADDS role isn't installed, install it.
    if (-not (Get-WindowsFeature -Name AD-Domain-Services).Installed) {
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    }

    # Back up profile data we want to preserve.
    Backup-AdminProfile

    # Check if we're creating a new domain or promoting to an existing one.
    $existingDomain = $null
    try {
        $existingDomain = Get-ADDomain -Identity $domainName -ErrorAction SilentlyContinue
    }
    catch {
        # Domain doesn't exist yet.
    }

    # Create the startup script for restoration after reboot.
    $startupScript = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\RestoreProfile.ps1"

    $restoreScript = @"
# Wait for system to fully initialize
Start-Sleep -Seconds 60

# Set execution policy
Set-ExecutionPolicy Bypass -Scope Process -Force

# Restore Administrator profile function
function Restore-AdminProfile {
    if (Test-Path "C:\AdminProfileBackup") {
        Write-Output "Restoring Administrator profile..."

        # Use robocopy for restoration
        `$excludeDirs   = @('Application Data','Temporary Internet Files','History','Cache','Temp')
        `$excludeParams = `$excludeDirs | ForEach-Object { "/XD `"`$_`"" }

        # Restore Local AppData
        `$cmd = "robocopy `"C:\AdminProfileBackup\Local`" `"C:\Users\Administrator\AppData\Local`" /E /ZB /R:1 /W:1 /XJ `$excludeParams"
        Invoke-Expression `$cmd

        # Restore Roaming AppData
        `$cmd = "robocopy `"C:\AdminProfileBackup\Roaming`" `"C:\Users\Administrator\AppData\Roaming`" /E /ZB /R:1 /W:1 /XJ `$excludeParams"
        Invoke-Expression `$cmd

        # Restore Desktop
        `$cmd = "robocopy `"C:\AdminProfileBackup\Desktop`" `"C:\Users\Administrator\Desktop`" /E /ZB /R:1 /W:1 /XJ"
        Invoke-Expression `$cmd

        Write-Output "Profile restoration completed."
    }
}

# Run restoration
Restore-AdminProfile

# Enable schema modifications automatically
`$regPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
if (Test-Path `$regPath) {
    Set-ItemProperty -Path `$regPath -Name "Schema Update Allowed" -Value 1 -Type DWord
    Restart-Service NTDS -ErrorAction SilentlyContinue
}

# Remove this script
Remove-Item -Path "$startupScript" -Force
"@

    # Create the startup script.
    Set-Content -Path $startupScript -Value $restoreScript

    if ($null -eq $existingDomain) {
        # Create a new forest and domain.
        Write-Output "Creating new forest and domain: $domainName"
        Install-ADDSForest -DomainName $domainName -InstallDNS -Force -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd1" -AsPlainText -Force)
    }
    else {
        # Promote to an existing domain.
        Write-Output "Promoting to existing domain: $domainName"
        Install-ADDSDomainController -DomainName $domainName -InstallDNS -Force -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd1" -AsPlainText -Force)
    }

    Write-Output "System will reboot and continue setup..."
    Start-Sleep -Seconds 5
    Restart-Computer -Force
}

# Function to convert to workgroup.
function Convert-ToWorkgroup {
    $workgroupName = "SCHEMATEST"

    # Back up profile data.
    Backup-AdminProfile

    # Create restore script for after reboot.
    $startupScript  = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\RestoreProfile.ps1"
    $restoreScript = @"
# Wait for system to fully initialize
Start-Sleep -Seconds 30

# Set execution policy
Set-ExecutionPolicy Bypass -Scope Process -Force

# Restore Administrator profile function
function Restore-AdminProfile {
    if (Test-Path "C:\AdminProfileBackup") {
        Write-Output "Restoring Administrator profile..."

        # Use robocopy for restoration
        `$excludeDirs   = @('Application Data','Temporary Internet Files','History','Cache','Temp')
        `$excludeParams = `$excludeDirs | ForEach-Object { "/XD `"`$_`"" }

        # Restore Local AppData
        `$cmd = "robocopy `"C:\AdminProfileBackup\Local`" `"C:\Users\Administrator\AppData\Local`" /E /ZB /R:1 /W:1 /XJ `$excludeParams"
        Invoke-Expression `$cmd

        # Restore Roaming AppData
        `$cmd = "robocopy `"C:\AdminProfileBackup\Roaming`" `"C:\Users\Administrator\AppData\Roaming`" /E /ZB /R:1 /W:1 /XJ `$excludeParams"
        Invoke-Expression `$cmd

        # Restore Desktop
        `$cmd = "robocopy `"C:\AdminProfileBackup\Desktop`" `"C:\Users\Administrator\Desktop`" /E /ZB /R:1 /W:1 /XJ"
        Invoke-Expression `$cmd

        Write-Output "Profile restoration completed."
    }
}

# Run restoration
Restore-AdminProfile

# Join workgroup
Add-Computer -WorkgroupName "$workgroupName" -Force

# Remove this script
Remove-Item -Path "$startupScript" -Force

# Schedule a reboot to complete workgroup joining
Restart-Computer -Force
"@

    # Create the startup script.
    Set-Content -Path $startupScript -Value $restoreScript

    # Remove domain controller role.
    Write-Output "Removing domain controller role..."
    Uninstall-ADDSDomainController -LocalAdministratorPassword (ConvertTo-SecureString "P@ssw0rd1" -AsPlainText -Force) -Force

    Write-Output "System will reboot and continue setup..."
    Start-Sleep -Seconds 5
    Restart-Computer -Force
}

# Main execution logic.
$currentState = Get-SystemState

Write-Output "Current system state: $currentState"
Write-Output "1. Switch to Domain Controller mode"
Write-Output "2. Switch to Workgroup mode"
Write-Output "3. Enable Schema Modifications (if already in DC mode)"
Write-Output "4. Exit"

$choice = Read-Host "Enter your choice (1-4)"

switch ($choice) {
    "1" {
        if ($currentState -eq "DomainController") {
            Write-Output "System is already a domain controller."
            Enable-SchemaModifications
        }
        else {
            Convert-ToDomainController
        }
    }
    "2" {
        if ($currentState -eq "Workgroup") {
            Write-Output "System is already in workgroup mode."
        }
        else {
            Convert-ToWorkgroup
        }
    }
    "3" {
        if ($currentState -eq "DomainController") {
            Enable-SchemaModifications
        }
        else {
            Write-Output "System must be a domain controller to enable schema modifications."
        }
    }
    "4" {
        Write-Output "Exiting script."
        exit 0
    }
    default {
        Write-Output "Invalid choice. Exiting."
        exit 1
    }
}
