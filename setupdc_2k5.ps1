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

function Enable-SchemaModifications {
    # Enable Schema modifications by setting a registry key.
    $regPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
    Set-ItemProperty -Path $regPath -Name "Schema Update Allowed" -Value 1 -Type DWord
    
    # Restart AD DS service.
    Restart-Service NTDS
    
    Write-Output "Schema modifications have been enabled. You can now modify the schema."
}

function Backup-AdminProfile {
    Write-Output "Backing up Administrator profile data..."
    $backupPath = "C:\AdminProfileBackup"
    if (-not (Test-Path $backupPath)) {
        New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
    }

    # Use robocopy instead of Copy-Item for better handling of in-use files.
    $excludeDirs   = @('Application Data', 'Temporary Internet Files', 'History', 'Cache', 'Temp')
    $excludeParams = $excludeDirs | ForEach-Object { "/XD `"$_`"" }

    # Backup AppData\Local, excluding problematic folders.
    $cmd = "robocopy `"C:\Users\Administrator\AppData\Local`" `"$backupPath\Local`" /E /ZB /R:1 /W:1 /XJ $excludeParams"
    Invoke-Expression $cmd
    
    # Backup AppData\Roaming, excluding problematic folders.
    $cmd = "robocopy `"C:\Users\Administrator\AppData\Roaming`" `"$backupPath\Roaming`" /E /ZB /R:1 /W:1 /XJ $excludeParams"
    Invoke-Expression $cmd
    
    # Backup Desktop.
    $cmd = "robocopy `"C:\Users\Administrator\Desktop`" `"$backupPath\Desktop`" /E /ZB /R:1 /W:1 /XJ"
    Invoke-Expression $cmd
    
    Write-Output "Profile backup completed with robocopy."
}

function Convert-ToDomainController {
    # Prompt for domain name (FQDN).
    $domainName = Read-Host "Enter the fully qualified domain name (e.g. domain.local)"
    
    # Validate FQDN format.
    if (-not ($domainName -match "^[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)+$")) {
        Write-Error "Invalid FQDN format. Please use a format like 'domain.local'"
        return
    }
    
    # Prompt for Safe Mode Administrator password.
    $safeModePassword = Read-Host "Enter Safe Mode Administrator password" -AsSecureString
    
    # If AD DS role isn't installed, install it.
    if (-not (Get-WindowsFeature -Name AD-Domain-Services).Installed) {
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    }
    
    # Back up profile data to preserve it.
    Backup-AdminProfile
    
    # Check if we're creating a new domain or promoting to an existing one.
    $existingDomain = $null
    try {
        $existingDomain = Get-ADDomain -Identity $domainName -ErrorAction SilentlyContinue
    }
    catch {
        # Domain doesn't exist yet.
    }
    
    if ($null -eq $existingDomain) {
        Write-Output "Creating new forest and domain: $domainName"
        Install-ADDSForest `
            -DomainName $domainName `
            -InstallDNS `
            -Force `
            -SafeModeAdministratorPassword $safeModePassword `
            -NoRebootOnCompletion
    }
    else {
        Write-Output "Promoting to existing domain: $domainName"
        Install-ADDSDomainController `
            -DomainName $domainName `
            -InstallDNS `
            -Force `
            -SafeModeAdministratorPassword $safeModePassword `
            -NoRebootOnCompletion
    }
    
    Write-Output "System will reboot and continue setup..."
    Start-Sleep -Seconds 5
    Restart-Computer -Force
}

function Convert-ToWorkgroup {
    
    # Prompt for local administrator password.
    $securePassword  = Read-Host "Enter local administrator password" -AsSecureString
    
    Write-Output "Removing domain controller role..."
    
    try {
        Write-Output "Attempting DC demotion - system will reboot after this..."
        Start-Sleep -Seconds 2
        
        Uninstall-ADDSDomainController `
            -LocalAdministratorPassword $securePassword `
            -DemoteOperationMasterRole:$true `
            -RemoveApplicationPartitions:$true `
            -RemoveDnsDelegation:$true `
            -LastDomainControllerInDomain:$true `
            -IgnoreLastDnsServerForZone:$true `
            -Force:$true
        
        Restart-Computer -Force
    }
    catch {
        Write-Output "Demotion attempt encountered an error - forcing reboot..."
        Start-Sleep -Seconds 2
        Restart-Computer -Force
    }
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
