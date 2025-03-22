#Requires -Version 7.0

<#
.SYNOPSIS
    Enables schema updates in Active Directory by setting the appropriate registry key.

.DESCRIPTION
    This script:
    - Checks for administrative privileges
    - Sets the registry key to allow schema updates
    - Verifies the change was successful

    NOTE: Requires PowerShell 7.x for best compatibility.
    Must be run with administrative privileges.

.OUTPUTS
    Success or failure message for schema update enablement.
#>

# Ensure we are in PowerShell 7+
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7.0 or later."
    exit 1
}

# Enable Schema Updates in Active Directory
# This script must be run with administrative privileges

# Check if running with administrative privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run with administrative privileges."
    exit 1
}
regsvr32 schmmgmt.dll


# Registry path for schema updates
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
$valueName = "Schema Update Allowed"
$valueData = 1

try {
    # Check if the registry path exists
    if (-not (Test-Path $registryPath)) {
        Write-Error "Registry path not found: $registryPath"
        exit 1
    }

    # Set the registry value
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWORD -Force

    # Verify the change
    $currentValue = Get-ItemProperty -Path $registryPath -Name $valueName
    if ($currentValue.$valueName -eq $valueData) {
        Write-Host "Schema updates have been enabled successfully."
        Write-Host "Registry value '$valueName' has been set to $valueData in $registryPath"
    } else {
        Write-Error "Failed to verify the registry change."
        exit 1
    }
} catch {
    Write-Error "An error occurred: $_"
    exit 1
}

Write-Host "`nSchema updates are now enabled. You can proceed with schema modifications." 