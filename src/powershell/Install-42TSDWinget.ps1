# Minimal-Winget-Copy.ps1
# Only copy core runtime files

$dest = "\\tsclient\d\temp\winget-min"
New-Item -ItemType Directory -Path $dest -Force | Out-Null

$base = "C:\Program Files\WindowsApps"
$wingetFolder = Get-ChildItem -Path $base -Directory |
    Where-Object { $_.Name -like "Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

$sourcePath = $wingetFolder.FullName

# Core runtime files (minimum viable set)
$coreFiles = @(
    "winget.exe",
    "winget.dll",
    "Microsoft.Management.Deployment.dll"
)

foreach ($file in $coreFiles) {
    $sourceFile = Join-Path $sourcePath $file
    if (Test-Path $sourceFile) {
        Copy-Item -Path $sourceFile -Destination $dest -Force
        Write-Host "✅ Copied: $file"
    } else {
        Write-Warning "❌ Missing: $file"
    }
}
