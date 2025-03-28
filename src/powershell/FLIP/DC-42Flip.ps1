#Requires -Version 7.0

<#
.SYNOPSIS
    Toggle between Domain Controller and Workgroup modes for schema testing,
    backup/restore of the Administrator profile, and file copying with verbose progress.

.DESCRIPTION
    1. Switch to Domain Controller mode (prompts for the domain FQDN).
    2. Switch to Workgroup mode (aggressive forced demotion).
    3. Enable schema modifications if already a DC.
    4. Backup or restore the Administrator profile.
    5. Exit.

.NOTES
    - The "aggressive" demotion will forcibly remove AD DS even if this is the last DC.
    - Data in the domain will be lost if this is the final domain controller.
#>

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7.0 or later."
    exit 1
}

Set-ExecutionPolicy Bypass -Scope Process -Force

function Get-SystemState {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($computerSystem.DomainRole -ge 4) {
        return "DomainController"
    }
    elseif (-not $computerSystem.PartOfDomain) {
        return "Workgroup"
    }
    else {
        return "DomainMember"
    }
}

function Enable-SchemaModifications {
    $regPath = 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters'
    Set-ItemProperty -Path $regPath -Name 'Schema Update Allowed' -Value 1 -Type DWord
    Restart-Service NTDS -ErrorAction SilentlyContinue
    Write-Output "Schema modifications have been enabled."
}

function Backup-AdminProfile {
    Write-Output "Backing up Administrator profile with robocopy..."

    $backupPath = 'C:\AdminProfileBackup'
    if (-not (Test-Path $backupPath)) {
        New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
    }

    $excludeDirs = @('Application Data', 'Temporary Internet Files', 'History', 'Cache', 'Temp')
    $excludeParams = $excludeDirs | ForEach-Object { "/XD `"$($_)`"" }
    $excludeParamsString = $excludeParams -join ' '

    $robocopyOptions = "/E /ZB /V /TEE /R:1 /W:1 /XJ $excludeParamsString"

    $localCmd   = "robocopy `"C:\Users\Administrator\AppData\Local`" `"C:\AdminProfileBackup\Local`" $robocopyOptions"
    $roamingCmd = "robocopy `"C:\Users\Administrator\AppData\Roaming`" `"C:\AdminProfileBackup\Roaming`" $robocopyOptions"
    $desktopCmd = "robocopy `"C:\Users\Administrator\Desktop`" `"C:\AdminProfileBackup\Desktop`" $robocopyOptions"

    Invoke-Expression $localCmd
    Invoke-Expression $roamingCmd
    Invoke-Expression $desktopCmd

    Write-Output "Backup complete."
}

function Restore-AdminProfile {
    if (-not (Test-Path 'C:\AdminProfileBackup')) {
        Write-Output "No backup found. Skipping profile restoration."
        return
    }

    Write-Output "Restoring Administrator profile with robocopy..."

    $excludeDirs = @('Application Data', 'Temporary Internet Files', 'History', 'Cache', 'Temp')
    $excludeParams = $excludeDirs | ForEach-Object { "/XD `"$($_)`"" }
    $excludeParamsString = $excludeParams -join ' '

    $robocopyOptions = "/E /ZB /V /TEE /R:1 /W:1 /XJ $excludeParamsString"

    $localCmd   = "robocopy `"C:\AdminProfileBackup\Local`" `"C:\Users\Administrator\AppData\Local`" $robocopyOptions"
    $roamingCmd = "robocopy `"C:\AdminProfileBackup\Roaming`" `"C:\Users\Administrator\AppData\Roaming`" $robocopyOptions"
    $desktopCmd = "robocopy `"C:\AdminProfileBackup\Desktop`" `"C:\Users\Administrator\Desktop`" $robocopyOptions"

    Invoke-Expression $localCmd
    Invoke-Expression $roamingCmd
    Invoke-Expression $desktopCmd

    Write-Output "Restore complete."
}

function Convert-ToDomainController {
    $domainName = Read-Host "Enter the fully qualified domain name (FQDN)"

    if (-not (Get-WindowsFeature -Name AD-Domain-Services).Installed) {
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    }

    try {
        $existingDomain = Get-ADDomain -Identity $domainName -ErrorAction SilentlyContinue
    }
    catch {
        $existingDomain = $null
    }

    if ($null -eq $existingDomain) {
        Write-Output "Creating a new forest and domain: $domainName"
        Install-ADDSForest `
            -DomainName $domainName `
            -InstallDNS `
            -SafeModeAdministratorPassword (ConvertTo-SecureString 'P@ssw0rd1' -AsPlainText -Force) `
            -Force
    }
    else {
        Write-Output "Promoting to existing domain: $domainName"
        Install-ADDSDomainController `
            -DomainName $domainName `
            -InstallDNS `
            -SafeModeAdministratorPassword (ConvertTo-SecureString 'P@ssw0rd1' -AsPlainText -Force) `
            -Force
    }

    Write-Output "System will reboot now to complete the domain controller promotion..."
    Start-Sleep -Seconds 5
    Restart-Computer -Force
}

function Convert-ToWorkgroup {
    Write-Output "Aggressively removing Domain Controller role (forced demotion)..."

    try {
        Uninstall-ADDSDomainController `
            -DemoteOperationMasterRole `
            -LocalAdministratorPassword (ConvertTo-SecureString 'P@ssw0rd1' -AsPlainText -Force) `
            -Force `
            -IgnoreLastDCInDomainMismatch
    }
    catch {
        Write-Error "Demotion failed: $($_.Exception.Message)"
        exit 1
    }

    Write-Output "Demotion initiated. The system will reboot to complete the process..."
    Start-Sleep -Seconds 5
    Restart-Computer -Force

    # NOTE: After reboot, the server is no longer a DC and is in a local state.
    # If you want to explicitly join "WORKGROUP" automatically, you'll need
    # a second script that runs on startup or manual steps afterward, e.g.:
    #   Add-Computer -WorkgroupName "WORKGROUP" -Force
    #   Restart-Computer
}

# Main Menu
$currentState = Get-SystemState

Write-Output "Current system state: $currentState"
Write-Output "1. Switch to Domain Controller mode"
Write-Output "2. Switch to Workgroup mode (AGGRESSIVE)"
Write-Output "3. Enable Schema Modifications (if already in DC mode)"
Write-Output "4. Backup Administrator profile only"
Write-Output "5. Restore Administrator profile only"
Write-Output "6. Exit"

$choice = Read-Host "Enter your choice (1-6)"

switch ($choice) {
    '1' {
        if ($currentState -eq 'DomainController') {
            Write-Output "Already a domain controller. Enabling schema modifications..."
            Enable-SchemaModifications
        }
        else {
            Convert-ToDomainController
        }
    }
    '2' {
        if ($currentState -eq 'Workgroup') {
            Write-Output "Already in workgroup mode."
        }
        else {
            Convert-ToWorkgroup
        }
    }
    '3' {
        if ($currentState -eq 'DomainController') {
            Enable-SchemaModifications
        }
        else {
            Write-Output "Must be a domain controller to enable schema modifications."
        }
    }
    '4' {
        Backup-AdminProfile
    }
    '5' {
        Restore-AdminProfile
    }
    '6' {
        Write-Output "Exiting..."
        exit 0
    }
    default {
        Write-Output "Invalid choice. Exiting."
        exit 1
    }
}
