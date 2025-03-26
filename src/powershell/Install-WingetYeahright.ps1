<#
.SYNOPSIS
Main script that dot-sources WingetFunctions.ps1 and handles the winget install process.
#>

# 1. Dot-source our functions file (adjust path if needed)
. .\WingetFunctions.ps1

# 2. Get OS Info
$os = Get-OSInfo
if (-not $os) {
    Write-Error "Could not retrieve OS info. Exiting."
    return
}

Write-Host "Detected OS: $($os.OSName) ($($os.Architecture))"
Write-Host "Version: $($os.Version)"

# 3. Optional: Check basic compatibility (simplified example)
if ($os.Version.Major -lt 10) {
    Write-Error "Your Windows version is too old; winget requires Windows 10 or above."
    return
}

# 4. (Optional) Install VCLibs, UI.Xaml, or other dependencies
#    Here, we demonstrate a minimal approach. Typically, these might be more sophisticated
$downloadVCLibs = $false
if ($downloadVCLibs) {
    $vclibsTempPath = Join-Path (Get-TempFolder) "VCLibs.appx"
    $vclibsUrl      = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
    # Download the file
    Invoke-WebRequest -Uri $vclibsUrl -OutFile $vclibsTempPath
    # Install
    Install-VCLibs -VCLibsUrl $vclibsTempPath
}

# 5. Download Winget .msixbundle
$wingetUrl = Get-WingetDownloadUrl -Match "msixbundle"
if (-not $wingetUrl) {
    Write-Warning "Unable to find a valid winget msixbundle URL from GitHub. Provide one manually."
    return
}
Write-Host "Found winget bundle URL: $wingetUrl"

# 6. Save it to disk
$wingetPath = Join-Path (Get-TempFolder) "winget.msixbundle"
Write-Host "Downloading to: $wingetPath"
Invoke-WebRequest -Uri $wingetUrl -OutFile $wingetPath

# 7. Install Winget
Install-WingetBundle -WingetPath $wingetPath

Write-Host "`nDone! Try running 'winget --version' to confirm installation."
