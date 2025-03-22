#Requires -Version 7.0

<#
.SYNOPSIS
    Toggle between Domain Controller and Workgroup modes for schema testing,
    backing up/restoring the Administrator profile and using robocopy with
    verbose progress output.

.DESCRIPTION
    1. Switch to Domain Controller mode (prompts for the domain FQDN).
    2. Switch to Workgroup mode.
    3. Enable schema modifications if already a Domain Controller.
    4. Exit.

    The script uses robocopy (/V /TEE) to display file copy progress directly
    in the console. It does *not* auto‐run at startup.

.OUTPUTS
    Success or failure messages for each phase.
#>

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7.0 or later."
    exit 1
}

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
    $regPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
    Set-ItemProperty -Path $regPath -Name "Schema Update Allowed" -Value 1 -Type DWord

    Restart-Service NTDS -ErrorAction SilentlyContinue
    Write-Output "Schema modifications have been enabled."
}

function Backup-AdminProfile {
    Write-Output "Backing up Administrator profile with robocopy..."

    $backupPath = "C:\AdminProfileBackup"
    if (-not (Test-Path $backupPath)) {
        New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
    }

    $excludeDirs   = @('Application Data','Temporary Internet Files','History','Cache','Temp')
    $excludeParams = $excludeDirs | ForEach-Object { "/XD `"$($_)`"" }
    # Join them into a single string for robocopy
    $excludeParamsString = $excludeParams -join ' '

    # Common robocopy options for verbose progress
    $robocopyOptions = "/E /ZB /V /TEE /R:1 /W:1 /XJ $excludeParamsString"

    # Backup Local
    $cmd = "robocopy `"C:\Users\Administrator\AppData\Local`" `"C:\AdminProfileBackup\Local`" $robocopyOptions"
    Invoke-Expression $cmd

    # Backup Roaming
    $cmd = "robocopy `"C:\Users\Administrator\AppData\Roaming`" `"C:\AdminProfileBackup\Roaming`" $robocopyOptions"
    Invoke-Expression $cmd

    # Backup Desktop
    $cmd = "robocopy `"C:\Users\Administrator\Desktop`" `"C:\AdminProfileBackup\Desktop`" $robocopyOptions"
    Invoke-Expression $cmd

    Write-Output "Backup complete."
}

function Restore-AdminProfile {
    if (-not (Test-Path "C:\AdminProfileBackup")) {
        Write-Output "No backup found. Skipping profile restoration."
        return
    }

    Write-Output "Restoring Administrator profile with robocopy..."

    $excludeDirs   = @('Application Data','Temporary Internet Files','History','Cache','Temp')
    $excludeParams = $excludeDirs | ForEach-Object { "/XD `"$($_)`"" }
    $excludeParamsString = $excludeParams -join ' '

    $robocopyOptions = "/E /ZB /V /TEE /R:1 /W:1 /XJ $excludeParamsString"

    # Restore Local
    $cmd = "robocopy `"C:\AdminProfileBackup\Local`" `"C:\Users\Administrator\AppData\Local`" $robocopyOptions"
    Invoke-Expression $cmd

    # Restore Roaming
    $cmd = "robocopy `"C:\AdminProfileBackup\Roaming`" `"C:\Users\Administrator\AppData\Roaming`" $robocopyOptions"
    Invoke-Expression $cmd

    # Restore Desktop
    $cmd = "robocopy `"C:\AdminProfileBackup\Desktop`" `"C:\Users\Administrator\Desktop`" $robocopyOptions"
    Invoke-Expression $cmd

    Write-Output "Restore complete."
}

function Convert-ToDomainController {
    $domainName = Read-Host "Enter the fully qualified domain name (FQDN)"

    if (-not (Get-WindowsFeature -Name AD-Domain-Services).Installed) {
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    }

    Backup-AdminProfile

    $existingDomain = $null
    try {
        $existingDomain = Get-ADDomain -Identity $domainName -ErrorAction SilentlyContinue
    }
    catch {
        # Domain does not exist
    }

    if ($null -eq $existingDomain) {
        Write-Output "Creating a new forest and domain: $domainName"
        Install-ADDSForest `
            -DomainName $domainName `
            -InstallDNS `
            -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd1" -AsPlainText -Force) `
            -Force
    }
    else {
        Write-Output "Promoting to existing domain: $domainName"
        Install-ADDSDomainController `
            -DomainName $domainName `
            -InstallDNS `
            -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd1" -AsPlainText -Force) `
            -Force
    }

    Write-Output "System will reboot now to complete the domain‐controller promotion..."
    Start-Sleep -Seconds 5
    Restart-Computer -Force
}

function Convert-ToWorkgroup {
    
    Backup-AdminProfile

    Write-Output "Removing Domain Controller role..."
    Uninstall-ADDSDomainController `
        -LocalAdministratorPassword (ConvertTo-SecureString "P@ssw0rd1" -AsPlainText -Force) `
        -Force

    Write-Output "System will reboot to complete demotion. Upon returning, run this script again to restore if needed."
    Start-Sleep -Seconds 5
    Restart-Computer -Force

    # After reboot, you can manually re-run:
    #   Restore-AdminProfile
    #   Add-Computer -WorkgroupName $workgroupName -Force
    #   Restart-Computer -Force
    #
    # If you prefer fully automatic behavior, you'd have to store script calls somewhere
    # that runs after reboot. But here we've omitted that to avoid using Startup folder.
}

# Main
$currentState = Get-SystemState

Write-Output "Current system state: $currentState"
Write-Output "1. Switch to Domain Controller mode"
Write-Output "2. Switch to Workgroup mode"
Write-Output "3. Enable Schema Modifications (if already in DC mode)"
Write-Output "4. Backup Administrator profile only"
Write-Output "5. Restore Administrator profile only"
Write-Output "6. Exit"

$choice = Read-Host "Enter your choice (1-6)"

switch ($choice) {
    "1" {
        if ($currentState -eq "DomainController") {
            Write-Output "Already a domain controller. Enabling schema modifications..."
            Enable-SchemaModifications
        }
        else {
            Convert-ToDomainController
        }
    }
    "2" {
        if ($currentState -eq "Workgroup") {
            Write-Output "Already in workgroup mode."
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
            Write-Output "Must be a domain controller to enable schema modifications."
        }
    }
    "4" {
        Backup-AdminProfile
    }
    "5" {
        Restore-AdminProfile
    }
    "6" {
        Write-Output "Exiting..."
        exit 0
    }
    default {
        Write-Output "Invalid choice. Exiting."
        exit 1
    }
}
