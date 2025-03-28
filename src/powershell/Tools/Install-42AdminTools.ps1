#requires -RunAsAdministrator
#requires -Version 5.1

# Define log file in jim's profile
$logFile = "C:\Users\jim\AdminToolsInstall.log"

# Ensure jim exists
if (-not (Test-Path "C:\Users\jim")) {
    Write-Host "jim's profile not found! Creating jim account..."
    try {
        $password = Read-Host -Prompt "Enter a secure password for user 'jim'" -AsSecureString
        New-LocalUser -Name "jim" `
                      -Password $password `
                      -FullName "Jim Admin" `
                      -Description "Admin account for workgroup and DC transitions" `
                      -PasswordNeverExpires `
                      -AccountNeverExpires `
                      -ErrorAction Stop
        Add-LocalGroupMember -Group "Administrators" -Member "jim" -ErrorAction Stop
        Write-Host "jim account created and added to Administrators."
    }
    catch {
        Write-Host "Failed to create jim account: $($_.Exception.Message)"
        exit 1
    }
}

if (-not (Test-Path "C:\Users\jim\Downloads")) { New-Item -Path "C:\Users\jim\Downloads" -ItemType Directory -Force }

function Write-Log {
    param ([string]$Message)
    "$((Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) - $Message" | Out-File -FilePath $logFile -Append
}

function Install-Tool {
    param (
        [string]$ToolId,
        [string]$ToolName
    )
    Write-Log "Installing $ToolName ($ToolId)..."
    try {
        winget install --id $ToolId --silent --accept-package-agreements --accept-source-agreements --force
        Write-Log "$ToolName installed successfully."
    }
    catch {
        Write-Log "Failed to install $ToolName : $($_.Exception.Message)"
    }
}

# Default tools list
$defaultTools = @(
    @{ Id = "CursorAI.Cursor"; Name = "Cursor" },
    @{ Id = "Microsoft.VisualStudioCode"; Name = "VSCode" },
    @{ Id = "Microsoft.VisualStudioCodeInsiders"; Name = "VSCode Insiders" },
    @{ Id = "Mythic.AgentRansack"; Name = "Agent Ransack" },
    @{ Id = "JAMSoftware.TreeSize.Free"; Name = "TreeSize Free" },
    @{ Id = "Google.Chrome"; Name = "Chrome" },
    @{ Id = "RevoUninstaller.RevoUninstaller"; Name = "Revo Uninstaller Free" },
    @{ Id = "MartiCliment.UniGetUI"; Name = "UniGetUI" }
)

# Check for CSV file
$csvPath = "C:\gh\setupdc2k5\data\AdminTools.csv"
$tools = $defaultTools
if (Test-Path $csvPath) {
    Write-Log "Found CSV file at $csvPath. Loading tools from CSV..."
    try {
        $csvTools = Import-Csv -Path $csvPath | Where-Object { $_.Id -and $_.Name }
        if ($csvTools) {
            $tools = $csvTools | ForEach-Object { @{ Id = $_.Id; Name = $_.Name } }
            Write-Log "Loaded $($tools.Count) tools from CSV."
        }
        else {
            Write-Log "CSV is empty or invalid. Using default tools list."
        }
    }
    catch {
        Write-Log "Failed to read CSV: $($_.Exception.Message). Using default tools list."
    }
}

# Install tools
foreach ($tool in $tools) {
    Install-Tool -ToolId $tool.Id -ToolName $tool.Name
}

Write-Log "Installation process completed."
winget upgrade --all --accept-source-agreements --accept-package-agreements 