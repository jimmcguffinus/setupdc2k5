# Requires -Version 3.0
<#
PSScriptInfo

.VERSION 3.0.0
.GUID 3b581edb-5d90-4fa1-ba15-4f2377275463
.AUTHOR asheroto, 1ckov, MisterZeus, ChrisTitusTech
.COMPANYNAME asheroto
.TAGS PowerShell Windows winget win get install installer fix script setup
.PROJECTURI https://github.com/asheroto/winget-install
.RELEASENOTES
[Version 0.0.1] - Initial Release.
[Version 0.0.2] - Implemented function to get the latest version of winget and its license.
[Version 0.0.3] - Signed file for PSGallery.
[Version 0.0.4] - Changed URI to grab latest release instead of releases and preleases.
[Version 0.0.5] - Updated version number of dependencies.
[Version 1.0.0] - Major refactor code, see release notes for more information.
[Version 1.0.1] - Fixed minor bug where version 2.8 was hardcoded in URL.
[Version 1.0.2] - Hardcoded UI Xaml version 2.8.4 as a failsafe in case the API fails. Added CheckForUpdates, Version, Help functions. Various bug fixes.
[Version 1.0.3] - Added error message to catch block. Fixed bug where appx package was not being installed.
[Version 1.0.4] - MisterZeus optimized code for readability.
[Version 2.0.0] - Major refactor. Reverted to UI.Xaml 2.7.3 for stability. Adjusted script to fix install issues due to winget changes (thank you ChrisTitusTech). Added in all architecture support.
[Version 2.0.1] - Renamed repo and URL references from winget-installer to winget-install. Added extra space after the last line of output.
[Version 2.0.2] - Adjusted CheckForUpdates to include Install-Script instructions and extra spacing.
[Version 2.1.0] - Added alternate method/URL for dependencies in case the main URL is down. Fixed licensing issue when winget is installed on Server 2022.
[Version 2.1.1] - Switched primary/alternate methods. Added Cleanup function to avoid errors when cleaning up temp files. Added output of URL for alternate method. Suppressed Add-AppxProvisionedPackage output. Improved success message. Improved verbiage. Improve PS script comments. Added check if the URL is empty. Moved display of URL beneath the check.
[Version 3.0.0] - Major changes. Added OS version detection checks - detects OS version, release ID, ensures compatibility. Forces older file installation for Server 2022 to avoid issues after installing. Added DebugMode, DisableCleanup, Force. Renamed CheckForUpdates to CheckForUpdate. Improved output. Improved error handling. Improved comments. Improved code readability. Moved CheckForUpdate into function. Added PowerShellGalleryName. Renamed Get-OSVersion to Get-OSInfo. Moved architecture detection into Get-OSInfo. Renamed Get-NewestLink to Get-WingetDownloadUrl. Have Get-WingetDownloadUrl not get preview releases.
#>

<#
.SYNOPSIS
Downloads and installs the latest version of winget and its dependencies. Updates the PATH variable if needed.

.DESCRIPTION
This script is designed to be straightforward and easy to use, removing the hassle of manually downloading, installing, and configuring winget. 
A system reboot may be required after running the script to fully enable the newly installed winget.

.PARAMETER DebugMode
Enables debug mode, showing additional information for debugging.

.PARAMETER DisableCleanup
Disables cleanup of the script and prerequisites after installation.

.PARAMETER Force
Ensures installation of winget and its dependencies even if already present.

.PARAMETER CheckForUpdate
Checks if there is an update available for the script.

.PARAMETER Version
Displays the version of the script.

.PARAMETER Help
Displays the full help information for the script.

.EXAMPLE
winget-install

.NOTES
Version      : 3.0.0
Created by   : asheroto

.LINK
Project Site: https://github.com/asheroto/winget-install
#>

[CmdletBinding()]
param (
    [switch]$Version,
    [switch]$Help,
    [switch]$CheckForUpdate,
    [switch]$DisableCleanup,
    [switch]$DebugMode,
    [switch]$Force
)

# Script-wide variables
$CurrentVersion         = '3.0.0'
$RepoOwner              = 'asheroto'
$RepoName               = 'winget-install'
$PowerShellGalleryName  = 'winget-install'
$ProgressPreference     = 'SilentlyContinue' # Suppress progress bar
$ConfirmPreference      = 'None'            # Suppress confirmation prompts


###############################################################################
#                             FUNCTION DEFINITIONS                            #
###############################################################################

function CheckForUpdate {
    <#
    .SYNOPSIS
    Checks if there is a new version of the script available on GitHub.

    .DESCRIPTION
    Retrieves the latest release from GitHub, compares it with the current script version,
    and displays instructions if a newer version is available.

    .PARAMETER RepoOwner
    The GitHub username of the repository owner.

    .PARAMETER RepoName
    The name of the repository.

    .PARAMETER CurrentVersion
    The current version of the script.

    .PARAMETER PowerShellGalleryName
    The name of the script on the PowerShell Gallery.

    .EXAMPLE
    CheckForUpdate -RepoOwner "asheroto" -RepoName "winget-install" -CurrentVersion "1.0.0" -PowerShellGalleryName "winget-install"
    #>
    param (
        [string]$RepoOwner,
        [string]$RepoName,
        [version]$CurrentVersion,
        [string]$PowerShellGalleryName
    )

    $Data = Get-GitHubRelease -Owner $RepoOwner -Repo $RepoName

    if ($Data.LatestVersion -gt $CurrentVersion) {
        Write-Output "`nA new version of $RepoName is available.`n"
        Write-Output "Current version: $CurrentVersion."
        Write-Output "Latest version: $($Data.LatestVersion)."
        Write-Output "Published at: $($Data.PublishedDateTime).`n"
        Write-Output "Download the latest version from:"
        Write-Output "https://github.com/$RepoOwner/$RepoName/releases`n"
        if ($PowerShellGalleryName) {
            Write-Output "Or update via PowerShell:"
            Write-Output "Install-Script $PowerShellGalleryName -Force`n"
        }
    } else {
        Write-Output "`n$RepoName is up to date.`n"
        Write-Output "Current version: $CurrentVersion."
        Write-Output "Latest version: $($Data.LatestVersion)."
        Write-Output "Published at: $($Data.PublishedDateTime)."
        Write-Output "`nRepository: https://github.com/$RepoOwner/$RepoName/releases`n"
    }
    exit 0
}


function Cleanup {
    <#
    .SYNOPSIS
    Deletes a file or directory at the specified path without prompting or displaying errors.

    .DESCRIPTION
    This function deletes a path (file or directory) silently. If the path is a directory,
    it can optionally delete all its contents.

    .PARAMETER Path
    The path of the file or directory to delete.

    .PARAMETER Recurse
    If specified and the path is a directory, delete the directory and all contents.

    .EXAMPLE
    Cleanup -Path "C:\Temp"
    #>
    param (
        [string]$Path,
        [switch]$Recurse
    )
    try {
        if (Test-Path -Path $Path) {
            if ($Recurse -and (Get-Item -Path $Path) -is [System.IO.DirectoryInfo]) {
                Get-ChildItem -Path $Path -Recurse | Remove-Item -Force -Recurse
                Remove-Item -Path $Path -Force -Recurse
            } else {
                Remove-Item -Path $Path -Force
            }
        }
        if ($DebugMode) {
            Write-Output "Deleted: $Path"
        }
    } catch {
        # Intentionally silent
    }
}


function Get-GitHubRelease {
    <#
    .SYNOPSIS
    Fetches the latest release information of a GitHub repository.

    .DESCRIPTION
    Uses the GitHub API to retrieve the latest release info including version and publish date.

    .PARAMETER Owner
    The GitHub username of the repository owner.

    .PARAMETER Repo
    The name of the repository.

    .EXAMPLE
    Get-GitHubRelease -Owner "microsoft" -Repo "winget-cli"
    #>
    [CmdletBinding()]
    param (
        [string]$Owner,
        [string]$Repo
    )
    try {
        $url       = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
        $response  = Invoke-RestMethod -Uri $url -ErrorAction Stop
        $latestVer = $response.tag_name
        $published = $response.published_at

        # Convert UTC to local time
        $UtcDateTime            = [DateTime]::Parse($published, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        $PublishedLocalDateTime = $UtcDateTime.ToLocalTime()

        [PSCustomObject]@{
            LatestVersion     = $latestVer
            PublishedDateTime = $PublishedLocalDateTime
        }
    } catch {
        Write-Error "Unable to check for updates.`nError: $_"
        exit 1
    }
}


function Get-OSInfo {
    <#
    .SYNOPSIS
    Retrieves detailed information about the operating system version and architecture.

    .DESCRIPTION
    This function queries both the Windows registry and the Win32_OperatingSystem class
    to gather OS data (e.g. name, release ID, version, architecture).

    .EXAMPLE
    Get-OSInfo
    #>
    [CmdletBinding()]
    param ()

    try {
        $registryValues      = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $releaseIdValue      = $registryValues.ReleaseId
        $displayVersionValue = $registryValues.DisplayVersion
        $nameValue           = $registryValues.ProductName
        $editionIdValue      = $registryValues.EditionId -replace "Server", ""
        $osDetails           = Get-CimInstance -ClassName Win32_OperatingSystem
        $nameValue           = $osDetails.Caption
        $architecture        = $osDetails.OSArchitecture

        if ($architecture -eq "32-bit") {
            $architecture = "x32"
        } elseif ($architecture -eq "64-bit") {
            $architecture = "x64"
        }

        $versionValue = [System.Environment]::OSVersion.Version
        if ($osDetails.ProductType -eq 1) {
            $typeValue = "Workstation"
        } elseif ($osDetails.ProductType -in 2,3) {
            $typeValue = "Server"
        } else {
            $typeValue = "Unknown"
        }

        $numericVersion = ($nameValue -replace "[^\d]").Trim()

        [PSCustomObject]@{
            ReleaseId      = $releaseIdValue
            DisplayVersion = $displayVersionValue
            Name           = $nameValue
            Type           = $typeValue
            NumericVersion = $numericVersion
            EditionId      = $editionIdValue
            Version        = $versionValue
            Architecture   = $architecture
        }
    } catch {
        Write-Error "Unable to get OS version details.`nError: $_"
        exit 1
    }
}


function Get-TempFolder {
    <#
    .SYNOPSIS
    Returns the current user's temp folder path.

    .DESCRIPTION
    Simply uses [System.IO.Path] to retrieve the temp path.

    .EXAMPLE
    Get-TempFolder
    #>
    return [System.IO.Path]::GetTempPath()
}


function Get-WingetDownloadUrl {
    <#
    .SYNOPSIS
    Retrieves the download URL of the latest release asset matching a pattern from the winget-cli repository.

    .DESCRIPTION
    Calls GitHub’s API to get the winget-cli releases, skipping any “preview” releases, and
    returns the asset URL that matches the given pattern.

    .PARAMETER Match
    The pattern to match in the asset names.

    .EXAMPLE
    Get-WingetDownloadUrl -Match "msixbundle"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Match
    )

    $uri      = "https://api.github.com/repos/microsoft/winget-cli/releases"
    Write-Debug "Getting information from $uri"
    $releases = Invoke-RestMethod -uri $uri -Method Get -ErrorAction Stop

    Write-Debug "Getting latest release..."
    foreach ($release in $releases) {
        if ($release.name -match "preview") { continue }
        $data = $release.assets | Where-Object name -Match $Match
        if ($data) {
            return $data.browser_download_url
        }
    }

    Write-Debug "Falling back to the latest release..."
    $latestRelease = $releases | Select-Object -First 1
    $data          = $latestRelease.assets | Where-Object name -Match $Match
    return $data.browser_download_url
}


function Get-WingetStatus {
    <#
    .SYNOPSIS
    Checks if winget is installed on the system.

    .DESCRIPTION
    Tries to get the winget command. If successful, returns $true; otherwise, $false.

    .EXAMPLE
    Get-WingetStatus
    #>
    $winget = Get-Command -Name winget -ErrorAction SilentlyContinue
    if ($null -ne $winget) { return $true }
    return $false
}


function Handle-Error {
    <#
    .SYNOPSIS
    Handles known error codes that can occur during installation.

    .DESCRIPTION
    If the exception message matches certain codes, an appropriate warning is shown.
    Otherwise, the error record is re-thrown.

    .PARAMETER ErrorRecord
    The error record captured in a try/catch block.

    .EXAMPLE
    try {
        # ...
    } catch {
        Handle-Error $_
    }
    #>
    param($ErrorRecord)

    $OriginalErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference         = 'SilentlyContinue'

    if     ($ErrorRecord.Exception.Message -match '0x80073D06') {
        Write-Warning "Higher version already installed. Continuing..."
    }
    elseif ($ErrorRecord.Exception.Message -match '0x80073CF0') {
        Write-Warning "Same version already installed. Continuing..."
    }
    elseif ($ErrorRecord.Exception.Message -match '0x80073D02') {
        Write-Warning "Resources modified are in use. Close Windows Terminal / PowerShell / CMD and retry."
        Write-Warning "If it persists, restart your computer."
        return $ErrorRecord
    }
    elseif ($ErrorRecord.Exception.Message -match 'Unable to connect to the remote server') {
        Write-Warning "Cannot connect to the Internet. Ensure connectivity or retry later."
        return $ErrorRecord
    }
    elseif ($ErrorRecord.Exception.Message -match "The remote name could not be resolved") {
        Write-Warning "Cannot resolve the remote server. Check DNS or retry later."
    }
    else {
        # Return the error record to be thrown by the calling try/catch
        return $ErrorRecord
    }

    $ErrorActionPreference = $OriginalErrorActionPreference
}


function Install-Prerequisite {
    <#
    .SYNOPSIS
    Downloads and installs a prerequisite for winget.

    .DESCRIPTION
    This function installs dependencies (VCLibs, UI.Xaml) using either a primary or alternate URL.

    .PARAMETER Name
    The name of the prerequisite.

    .PARAMETER Url
    Primary URL of the prerequisite.

    .PARAMETER AlternateUrl
    Alternate URL of the prerequisite.

    .PARAMETER ContentType
    Content type used for the primary download.

    .PARAMETER Body
    POST body for the primary download.

    .PARAMETER NupkgVersion
    The nupkg version of the prerequisite.

    .PARAMETER AppxFileVersion
    The appx file version of the prerequisite.

    .EXAMPLE
    Install-Prerequisite -Name "VCLibs" -Url "..." -AlternateUrl "..." ...
    #>
    param (
        [string]$Name,
        [string]$Url,
        [string]$AlternateUrl,
        [string]$ContentType,
        [string]$Body,
        [string]$NupkgVersion,
        [string]$AppxFileVersion
    )

    $osVersion = Get-OSInfo
    $arch      = $osVersion.Architecture

    Write-Section "Downloading & installing ${arch} ${Name}..."

    $ThrowReason = [PSCustomObject]@{
        Message = ""
        Code    = 0
    }

    try {
        # Detect Windows 10 or Server 2022 for forced alternate approach
        function Get-DomainFromUrl($inputUrl) {
            $uri = [System.Uri]$inputUrl
            $uri.Host -replace "^www\."
        }

        if ((($osVersion.Type -eq "Server" -and $osVersion.NumericVersion -eq 2022) -or
             ($osVersion.Type -eq "Workstation" -and $osVersion.NumericVersion -eq 10))) {
            if ($osVersion.Type -eq "Server") {
                $osName = "Server 2022"
            } else {
                $osName = "Windows 10"
            }
            $domain              = Get-DomainFromUrl $AlternateUrl
            $ThrowReason.Message = "Using $domain version of $Name for $osName."
            $ThrowReason.Code    = 1
            throw
        }

        # Primary method
        $primaryResults = Invoke-WebRequest -Uri $Url -Method "POST" -ContentType $ContentType -Body $Body -UseBasicParsing
        $dlUrl         = $primaryResults | ForEach-Object Links | Where-Object outerHTML -match "$Name.+_${arch}__8wekyb3d8bbwe.appx" | ForEach-Object href

        if ($dlUrl -eq "") {
            $ThrowReason.Message = "URL is empty"
            $ThrowReason.Code    = 2
            throw
        }

        Write-Output "URL: ${dlUrl}"
        Write-Output "`nInstalling ${arch} ${Name}..."
        Add-AppxPackage $dlUrl -ErrorAction Stop
        Write-Output "`n$Name installed successfully."
    } catch {
        # Alternate method
        try {
            $dlUrl = $AlternateUrl
            if ($ThrowReason.Code -eq 0) {
                Write-Warning "Error installing $Name. Trying alternate method..."
            } else {
                Write-Warning $ThrowReason.Message
            }
            Write-Output ""

            if ($dlUrl -eq "") {
                throw "URL is empty"
            }

            if ($Name -eq "VCLibs") {
                if ($DebugMode) {
                    Write-Output "URL: $($dlUrl)`n"
                }
                Write-Output "Installing ${arch} ${Name}..."
                Add-AppxPackage $dlUrl -ErrorAction Stop
                Write-Output "`n$Name installed successfully."
            }
            elseif ($Name -eq "UI.Xaml") {
                $TempFolder    = Get-TempFolder
                $uiXaml        = @{
                    url           = $dlUrl
                    appxFolder    = "tools/AppX/$arch/Release/"
                    appxFilename  = "Microsoft.UI.Xaml.$AppxFileVersion.appx"
                    nupkgFilename = Join-Path -Path $TempFolder -ChildPath "Microsoft.UI.Xaml.$NupkgVersion.nupkg"
                    nupkgFolder   = Join-Path -Path $TempFolder -ChildPath "Microsoft.UI.Xaml.$NupkgVersion"
                }

                if ($DebugMode) {
                    $formattedDebugOutput = ($uiXaml | ConvertTo-Json -Depth 10 -Compress) -replace '\\\\', '\'
                    Write-Output "uiXaml:"
                    Write-Output $formattedDebugOutput
                    Write-Output ""
                }

                Write-Output "Downloading UI.Xaml..."
                if ($DebugMode) {
                    Write-Output "URL: $($uiXaml.url)"
                }

                Invoke-WebRequest -Uri $uiXaml.url -OutFile $uiXaml.nupkgFilename

                Cleanup -Path $uiXaml.nupkgFolder -Recurse

                Write-Output "Extracting...`n"
                if ($DebugMode) {
                    Write-Output "Into folder: $($uiXaml.nupkgFolder)`n"
                }
                Add-Type -Assembly System.IO.Compression.FileSystem
                [IO.Compression.ZipFile]::ExtractToDirectory($uiXaml.nupkgFilename, $uiXaml.nupkgFolder)

                Write-Output "Installing ${arch} ${Name}..."
                $XamlAppxFolder = Join-Path -Path $uiXaml.nupkgFolder -ChildPath $uiXaml.appxFolder
                $XamlAppxPath   = Join-Path -Path $XamlAppxFolder -ChildPath $uiXaml.appxFilename

                if ($DebugMode) {
                    Write-Output "Installing appx from: $XamlAppxFolder"
                }

                Get-ChildItem -Path $XamlAppxPath -Filter *.appx | ForEach-Object {
                    if ($DebugMode) {
                        Write-Output "Installing appx Package: $($_.Name)"
                    }
                    Add-AppxPackage $_.FullName -ErrorAction Stop
                }
                Write-Output "`nUI.Xaml installed successfully."

                if ($DisableCleanup -eq $false) {
                    if ($DebugMode) { Write-Output "" }
                    Cleanup -Path $uiXaml.nupkgFilename
                    Cleanup -Path $uiXaml.nupkgFolder -Recurse $true
                }
            }
        } catch {
            $ShowOldVersionMessage = $false
            if ($_.Exception.Message -match "Unable to connect to the remote server") {
                if ($osVersion.Type -eq "Workstation" -and $osVersion.NumericVersion -eq 10) {
                    $WindowsCaption       = "Windows 10"
                    $ShowOldVersionMessage = $true
                } elseif ($osVersion.Type -eq "Server" -and $osVersion.NumericVersion -eq 2022) {
                    $WindowsCaption       = "Server 2022"
                    $ShowOldVersionMessage = $true
                }

                if ($ShowOldVersionMessage) {
                    Write-Warning "Issues connecting to the server to download $Name. You must use the non-store versions on $WindowsCaption; please retry later."
                } else {
                    Write-Warning "Error downloading or installing $Name. Try again or install manually."
                }
            }

            $errorHandled = Handle-Error $_
            if ($null -ne $errorHandled) {
                throw $errorHandled
            }
            $errorHandled = $null
        }
    }
}


function Update-PathEnvironmentVariable {
    <#
    .SYNOPSIS
    Updates the PATH environment variable with a new path at both the User and Machine levels.

    .DESCRIPTION
    Checks if the given path is already in PATH. If not, appends it to PATH for both User and Machine.

    .PARAMETER NewPath
    The directory path to add to the PATH environment variable.

    .EXAMPLE
    Update-PathEnvironmentVariable -NewPath "C:\NewDirectory"
    #>
    param(
        [string]$NewPath
    )

    foreach ($Level in "Machine", "User") {
        $path = [Environment]::GetEnvironmentVariable("PATH", $Level)

        if (!$path.Contains($NewPath)) {
            if ($DebugMode) {
                Write-Output "Adding $NewPath to PATH for $Level..."
            } else {
                Write-Output "Adding PATH for $Level..."
            }
            $path = ($path + ";" + $NewPath).Split(';') | Select-Object -Unique
            $path = $path -join ';'
            [Environment]::SetEnvironmentVariable("PATH", $path, $Level)
        } else {
            if ($DebugMode) {
                Write-Output "$NewPath is already in PATH for $Level; skipping."
            } else {
                Write-Output "PATH variable is already present for $Level; skipping."
            }
        }
    }
}


function Write-Section($text) {
    <#
    .SYNOPSIS
    Prints a text block surrounded by section dividers for clarity.

    .DESCRIPTION
    Outputs the given text with a header and footer of '#' characters.

    .PARAMETER text
    The text to be displayed as a heading.

    .EXAMPLE
    Write-Section "Downloading Files..."
    #>
    Write-Output ""
    Write-Output ("#" * ($text.Length + 4))
    Write-Output "# $text #"
    Write-Output ("#" * ($text.Length + 4))
    Write-Output ""
}


###############################################################################
#                                MAIN LOGIC                                    #
###############################################################################

# Display version if requested
if ($Version.IsPresent) {
    $CurrentVersion
    exit 0
}

# Display full help if requested
if ($Help) {
    Get-Help -Name $MyInvocation.MyCommand.Source -Full
    exit 0
}

# Show $PSVersionTable and Get-Host if -Verbose
if ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose']) {
    $PSVersionTable
    Get-Host
}

# Check for updates if requested
if ($CheckForUpdate) {
    CheckForUpdate -RepoOwner $RepoOwner -RepoName $RepoName -CurrentVersion $CurrentVersion -PowerShellGalleryName $PowerShellGalleryName
}

Write-Output "winget-install $CurrentVersion"

# Gather OS info
$osVersion = Get-OSInfo
$arch      = $osVersion.Architecture

# Basic compatibility checks
if ($osVersion.Type -eq "Workstation" -and $osVersion.NumericVersion -lt 10) {
    Write-Error "winget is only compatible with Windows 10 or greater."
    exit 1
}

if ($osVersion.Type -eq "Workstation" -and $osVersion.NumericVersion -eq 10 -and $osVersion.ReleaseId -lt 1809) {
    Write-Error "winget is only compatible with Windows 10 version 1809 or greater."
    exit 1
}

if ($osVersion.Type -eq "Server" -and $osVersion.NumericVersion -lt 2022) {
    Write-Error "winget is only compatible with Windows Server 2022 or newer."
    exit 1
}

# If winget is installed and not forcing, exit
if (Get-WingetStatus -and -not $Force) {
    Write-Output "winget is already installed, exiting..."
    exit 0
}

try {
    # Install prerequisites
    Install-Prerequisite -Name "VCLibs" -Url "https://store.rg-adguard.net/api/GetFiles" `
        -AlternateUrl "https://aka.ms/Microsoft.VCLibs.$arch.14.00.Desktop.appx" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body "type=PackageFamilyName&url=Microsoft.VCLibs.140.00_8wekyb3d8bbwe&ring=RP&lang=en-US"

    Install-Prerequisite -Name "UI.Xaml" -Url "https://store.rg-adguard.net/api/GetFiles" `
        -AlternateUrl "https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.7.3" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body "type=ProductId&url=9P5VK8KZB5QZ&ring=RP&lang=en-US" `
        -NupkgVersion "2.7.3" `
        -AppxFileVersion "2.7"

    # Install winget
    $TempFolder       = Get-TempFolder
    Write-Section "Downloading & installing winget..."

    Write-Output "Retrieving winget download URL..."
    $wingetUrl        = Get-WingetDownloadUrl -Match "msixbundle"
    $wingetPath       = Join-Path -Path $TempFolder -ChildPath "winget.msixbundle"
    $wingetLicenseUrl = Get-WingetDownloadUrl -Match "License1.xml"
    $wingetLicensePath= Join-Path -Path $TempFolder -ChildPath "license1.xml"

    if ($wingetUrl -eq "") { throw "winget URL is empty" }

    Write-Output "Downloading winget..."
    if ($DebugMode) {
        Write-Output "`nURL: $wingetUrl"
        Write-Output "Saving as: $wingetPath"
    }
    Invoke-WebRequest -Uri $wingetUrl -OutFile $wingetPath

    Write-Output "Downloading license..."
    if ($DebugMode) {
        Write-Output "`nURL: $wingetLicenseUrl"
        Write-Output "Saving as: $wingetLicensePath"
    }
    Invoke-WebRequest -Uri $wingetLicenseUrl -OutFile $wingetLicensePath

    Write-Output "`nInstalling winget..."
    if ($DebugMode) {
        Write-Output "wingetPath: $wingetPath"
        Write-Output "wingetLicensePath: $wingetLicensePath"
    }

    try {
        Add-AppxProvisionedPackage -Online -PackagePath $wingetPath -LicensePath $wingetLicensePath -ErrorAction SilentlyContinue | Out-Null
        Write-Output "`nwinget installed successfully."
    } catch {
        $errorHandled = Handle-Error $_
        if ($null -ne $errorHandled) {
            throw $errorHandled
        }
        $errorHandled = $null
    }

    # Cleanup
    if (-not $DisableCleanup) {
        if ($DebugMode) { Write-Output "" }
        Cleanup -Path $wingetPath
        Cleanup -Path $wingetLicensePath
    }

    # Ensure WindowsApps in PATH
    Write-Section "Checking and adding WindowsApps directory to PATH..."
    $WindowsAppsPath = Join-Path -Path ([Environment]::GetEnvironmentVariable("LOCALAPPDATA")) -ChildPath "Microsoft\WindowsApps"
    Update-PathEnvironmentVariable -NewPath $WindowsAppsPath

    # Finish
    Write-Section "Installation complete!"
    Write-Output "Verifying winget installation..."
    Start-Sleep -Seconds 3

    if (Get-WingetStatus) {
        Write-Output "winget is installed and ready for use."
    } else {
        Write-Warning "winget is installed but not yet detected. A restart may be required."
        Write-Warning "If issues persist, see: https://github.com/asheroto/winget-install#troubleshooting"
        Write-Warning "Update the script: $PowerShellGalleryName -CheckForUpdate"
    }
} catch {
    Write-Section "WARNING! An error occurred during installation!"
    Write-Warning "If problems persist, check the Troubleshooting section:"
    Write-Warning "https://github.com/asheroto/winget-install#troubleshooting"
    Write-Warning "Ensure latest script with: $PowerShellGalleryName -CheckForUpdate"
    if ($_.Exception.Message -notmatch '0x80073D02') {
        if ($DebugMode) {
            Write-Warning "Line : $($_.InvocationInfo.ScriptLineNumber)"
        }
        Write-Warning "Error: $($_.Exception.Message)`n"
    }
}
