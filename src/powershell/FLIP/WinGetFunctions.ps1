# =============================================================================
# File: WingetFunctions.ps1
# =============================================================================
# This file contains the functions for OS detection, retrieving URLs, etc.
# Dot-source this file in the main script (Install-Winget.ps1).

function Get-OSInfo {
    <#
    .SYNOPSIS
    Retrieves operating system information (version, type, architecture).
    #>
    [CmdletBinding()]
    param ()

    try {
        $reg      = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $osName   = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
        $osVerObj = [System.Environment]::OSVersion.Version

        # Identify architecture (simplified)
        $arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x32" }

        [PSCustomObject]@{
            ProductName  = $reg.ProductName
            OSName       = $osName
            Version      = $osVerObj
            Architecture = $arch
        }
    }
    catch {
        Write-Error "Unable to get OS info: $_"
        return $null
    }
}


function Get-TempFolder {
    <#
    .SYNOPSIS
    Returns the current user's temp folder path.
    #>
    return [IO.Path]::GetTempPath()
}


function Get-WingetDownloadUrl {
    <#
    .SYNOPSIS
    Retrieves the download URL of the latest stable (non-preview) winget MSIX bundle
    from the GitHub winget-cli releases.

    .PARAMETER Match
    The regex pattern to match the asset name (e.g. "msixbundle").
    #>
    [CmdletBinding()]
    param (
        [string]$Match = "msixbundle"
    )

    $uri = "https://api.github.com/repos/microsoft/winget-cli/releases"
    try {
        $releases = Invoke-RestMethod -Uri $uri -Method GET -ErrorAction Stop
    }
    catch {
        Write-Warning "Error retrieving releases from GitHub: $_"
        return $null
    }

    foreach ($release in $releases) {
        # Skip any preview builds
        if ($release.name -match "preview") { continue }

        # Try to find an asset that matches $Match (typically "msixbundle")
        $asset = $release.assets | Where-Object { $_.name -match $Match }
        if ($asset) {
            return $asset.browser_download_url
        }
    }

    # If we got here, no stable msixbundle was found
    return $null
}


function Install-VCLibs {
    <#
    .SYNOPSIS
    Simple example to install VCLibs from a given URL.
    #>
    param (
        [string]$VCLibsUrl
    )

    Write-Host "Installing VCLibs from: $VCLibsUrl"
    try {
        Add-AppxPackage -Path $VCLibsUrl -ErrorAction Stop
        Write-Host "VCLibs installed successfully."
    }
    catch {
        Write-Warning "Failed to install VCLibs: $($_.Exception.Message)"
    }
}


function Install-WingetBundle {
    <#
    .SYNOPSIS
    Installs the winget msixbundle for the current user.

    .PARAMETER WingetPath
    The local file path to the winget msixbundle.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$WingetPath
    )

    Write-Host "Installing winget from: $WingetPath"
    try {
        # User-scoped install example:
        Add-AppxPackage -Path $WingetPath -ErrorAction Stop
        Write-Host "winget installed successfully."
    }
    catch {
        Write-Warning "Failed to install winget: $($_.Exception.Message)"
    }
}
