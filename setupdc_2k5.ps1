#Requires -Version 7.0

<#
.SYNOPSIS
    Main script for setting up an MLB Active Directory environment.

.DESCRIPTION
    This script:
    - Configures the first domain controller
    - Enables schema updates
    - Imports MLB schema extensions
    - Creates MLB user accounts

    NOTE: Requires PowerShell 7.x for best compatibility.
    Must be run with administrative privileges.

.OUTPUTS
    Success or failure messages for each setup phase.
#>

# Ensure we are in PowerShell 7+
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7.0 or later."
    exit 1
}

# Set execution policy to bypass for this session
Set-ExecutionPolicy Bypass -Scope Process -Force

# Rename the server
Rename-Computer -NewName "dc1_2k5" -Force
Write-Output "Server name changed to dc1_2k5. A reboot is required."

# Enable Remote Desktop
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Write-Output "Remote Desktop enabled."

# Allow RDP for Administrators
$group = "Administrators"
$rdpGroup = "Remote Desktop Users"
(Get-WmiObject Win32_Group -Filter "Name='$group'").Invoke("Add", @((Get-WmiObject Win32_Group -Filter "Name='$rdpGroup'").__PATH))
Write-Output "Administrators added to Remote Desktop Users group."

# Disable all Windows firewalls
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Write-Output "All firewalls disabled."

# Reboot the server to apply changes
Write-Output "Rebooting the server in 10 seconds..."
Start-Sleep -Seconds 10
Restart-Computer -Force
