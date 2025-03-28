<#
.SYNOPSIS
    LDIF Import Script for Python-generated LDF Packets

.DESCRIPTION
    This script imports LDIF files using ldifde.
    It first imports the OU structure LDIF file, then processes individual Player LDIF files from a directory.
    Each player LDF packet is imported one at a time.
    The script writes logs and checks for successful completion.

.PARAMETER Server
    The target server for ldifde import.

.PARAMETER OUFile
    Path to the OU structure LDIF file.

.PARAMETER PlayersDir
    Directory path containing individual Player LDF packet files.

.PARAMETER LogFile
    Path where the import log will be written.

.EXAMPLE
    .\Import-42PyLDFPackes.ps1 -Server "DC1_2K5" `
        -OUFile "C:\gh\setupdc2k5\data\ldfs\ouStructure.ldf" `
        -PlayersDir "C:\gh\setupdc2k5\data\ldfs\peopleldf_files" `
        -LogFile "C:\gh\setupdc2k5\data\csv\ldifde_import.log"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Server,

    [Parameter(Mandatory=$true)]
    [string]$OUFile,

    [Parameter(Mandatory=$true)]
    [string]$PlayersDir,

    [Parameter(Mandatory=$true)]
    [string]$LogFile
)

# Create a hashtable to track failures
$failures = @{}

# Function to log messages
function Write-Log {
    param(
        [string]$Message,
        [switch]$NoConsole,
        [switch]$IsError
    )
    
    try {
        # Ensure log directory exists
        $logDir = Split-Path -Parent $LogFile
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            Write-Host "Created log directory: $logDir"
        }
        
        # Create log file if it doesn't exist
        if (-not (Test-Path $LogFile)) {
            New-Item -ItemType File -Path $LogFile -Force | Out-Null
            Write-Host "Created log file: $LogFile"
        }
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "[$timestamp] $Message"
        
        # Write to log file with error handling
        try {
            Add-Content -Path $LogFile -Value $logMessage -ErrorAction Stop
        }
        catch {
            Write-Host "Error writing to log file: $_" -ForegroundColor Red
            Write-Host "Attempting to write with Set-Content..."
            Set-Content -Path $LogFile -Value $logMessage -Force
        }
        
        if (-not $NoConsole) {
            if ($IsError) {
                Write-Host $logMessage -ForegroundColor Red
            } else {
                Write-Host $logMessage
            }
        }
    }
    catch {
        Write-Host "Critical error in Write-Log: $_" -ForegroundColor Red
        # Try one last time with Out-File
        try {
            $logMessage | Out-File -FilePath $LogFile -Append -Force
        }
        catch {
            Write-Host "Failed to write to log file even with Out-File" -ForegroundColor Red
        }
    }
}

# Function to analyze failures
function Test-Failures {
    Write-Log "`n=== Failure Analysis ==="
    
    # Group failures by error type
    $errorTypes = $failures.Values | Group-Object { $_.ErrorType }
    Write-Log "`nFailure Count by Error Type:"
    $errorTypes | ForEach-Object {
        Write-Log "  $($_.Name): $($_.Count)"
    }
    
    # Find common error patterns
    $errorPatterns = $failures.Values | Group-Object { $_.ErrorDetails } | Sort-Object Count -Descending | Select-Object -First 5
    Write-Log "`nMost Common Error Patterns:"
    $errorPatterns | ForEach-Object {
        Write-Log "  $($_.Name): $($_.Count) occurrences"
    }
    
    # Export failures to CSV
    $failureReportPath = "C:\gh\setupdc2k5\data\csv\failure_report.csv"
    $failures.Values | Export-Csv -Path $failureReportPath -NoTypeInformation
    Write-Log "`nFailure report exported to: $failureReportPath"
}

# Function to run ldifde and check its output
function Invoke-LDIFDE {
    param(
        [string]$FilePath,
        [string]$PlayerID = ""
    )
    
    # Create ldifde logs directory
    $ldifdeLogDir = Join-Path (Split-Path $LogFile -Parent) "ldifde_logs"
    New-Item -ItemType Directory -Path $ldifdeLogDir -Force -ErrorAction SilentlyContinue | Out-Null
    
    # Create unique log file name for this operation
    $fileBaseName = Split-Path $FilePath -Leaf
    $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
    $ldifdeLogFile = Join-Path $ldifdeLogDir "$($fileBaseName)-$timestamp.log"
    
    # Log the exact command being run
    $cmdLine = "ldifde -i -f `"$FilePath`" -s $Server -k -j `"$ldifdeLogFile`" -v"
    Write-Log "Running command: $cmdLine"
    Write-Log "Detailed ldifde log will be written to: $ldifdeLogFile"
    
    try {
        # Capture both success and error output
        $output = & ldifde -i -f $FilePath -s $Server -k -j $ldifdeLogFile -v 2>&1
        $exitCode = $LASTEXITCODE  # Capture exit code immediately after ldifde

        # Log all output lines to our log file
        foreach ($line in $output) {
            Write-Log $line
        }
        
        if ($exitCode -eq 0) {
            # Success case - ldifde completed without errors
            if ($PlayerID) {
                Write-Log "Successfully imported player $PlayerID (ldifde exit code 0)"
            } else {
                Write-Log "Successfully imported/updated OU structure (ldifde exit code 0)"
            }
            return $true
        } else {
            # Failure case - non-zero exit code indicates an error
            $errorMsg = $output -join "`n"
            
            # Try to get additional error details from ldifde log
            if (Test-Path $ldifdeLogFile) {
                $ldifdeLogContent = Get-Content $ldifdeLogFile -Raw
                $errorMsg += "`n`nDetailed ldifde log:`n$ldifdeLogContent"
            }
            
            if ($PlayerID) {
                Write-Log "Error importing player $PlayerID (ldifde exit code $exitCode)" -IsError
                Write-Log "Error details: $errorMsg" -IsError
                Write-Log "Detailed ldifde log available at: $ldifdeLogFile" -IsError
                
                # Get player name from LDIF file for better error tracking
                $playerName = Get-Content $FilePath | 
                    Select-String "^cn: " | 
                    ForEach-Object { $_.Line.Replace("cn: ", "") } | 
                    Select-Object -First 1
                
                $script:failures[$PlayerID] = @{
                    PlayerID = $PlayerID
                    Name = $playerName
                    ErrorType = "LDIFDE Error"
                    ErrorDetails = $errorMsg
                    ExitCode = $exitCode
                    LogFile = $FilePath
                    LdifdeLogFile = $ldifdeLogFile
                    ErrorCategory = switch ($exitCode) {
                        1 { "Invalid Parameters" }
                        2 { "File Access Error" }
                        3 { "Memory Error" }
                        4 { "Directory Service Error" }
                        5 { "Security Error" }
                        default { "Unknown Error (Code: $exitCode)" }
                    }
                    ErrorCode = $exitCode
                    FixSuggestion = switch ($exitCode) {
                        1 { "Check LDIF syntax and parameters" }
                        2 { "Verify file permissions and paths" }
                        3 { "Check system resources" }
                        4 { "Verify AD connectivity and permissions" }
                        5 { "Check security context and permissions" }
                        default { "Review ldifde documentation for exit code $exitCode" }
                    }
                }
            } else {
                Write-Log "Error importing OU structure (ldifde exit code $exitCode)" -IsError
                Write-Log "Error details: $errorMsg" -IsError
                Write-Log "Detailed ldifde log available at: $ldifdeLogFile" -IsError
                $script:failures["OU_Structure"] = @{
                    ErrorType = "OU_Import"
                    ErrorDetails = $errorMsg
                    ExitCode = $exitCode
                    LdifdeLogFile = $ldifdeLogFile
                    ErrorCategory = "LDIFDE Error (Code: $exitCode)"
                    FixSuggestion = "Check OU structure LDIF syntax and AD permissions"
                }
            }
            return $false
        }
    }
    catch {
        # Handle PowerShell exceptions when trying to run ldifde
        $exceptionMsg = $_.Exception.Message
        Write-Log "Exception occurred while running ldifde" -IsError
        Write-Log "Exception details: $exceptionMsg" -IsError
        Write-Log "Detailed ldifde log available at: $ldifdeLogFile" -IsError
        
        if ($PlayerID) {
            $script:failures[$PlayerID] = @{
                PlayerID = $PlayerID
                Name = (Get-Content $FilePath | 
                    Select-String "^cn: " | 
                    ForEach-Object { $_.Line.Replace("cn: ", "") } | 
                    Select-Object -First 1)
                ErrorType = "PowerShell Exception"
                ErrorDetails = $exceptionMsg
                ExitCode = -1  # Indicate PowerShell exception
                LogFile = $FilePath
                LdifdeLogFile = $ldifdeLogFile
                ErrorCategory = "System Error"
                ErrorCode = $_.Exception.HResult
                FixSuggestion = "Check system permissions, ldifde availability, and connectivity"
            }
        } else {
            $script:failures["OU_Structure"] = @{
                ErrorType = "PowerShell Exception"
                ErrorDetails = $exceptionMsg
                ExitCode = -1
                LdifdeLogFile = $ldifdeLogFile
                ErrorCategory = "System Error"
                ErrorCode = $_.Exception.HResult
                FixSuggestion = "Check system permissions and ldifde availability"
            }
        }
        return $false
    }
}

# Clear the screen and show initial status
Clear-Host
Write-Host "MLB Player Import Process" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan
Write-Host "Server: $Server"
Write-Host "OU File: $OUFile"
Write-Host "Players Directory: $PlayersDir"
Write-Host "Log File: $LogFile`n"

# Initialize logging
Write-Log "=== Import Process Started ==="
Write-Log "Server: $Server"
Write-Log "OU File: $OUFile"
Write-Log "Players Directory: $PlayersDir"
Write-Log "Log File: $LogFile"

# Import OU structure
Write-Host "[1/2] Importing OU Structure..." -ForegroundColor Yellow
if (Invoke-LDIFDE -FilePath $OUFile) {
    Write-Host "✓ OU Structure imported successfully" -ForegroundColor Green
} else {
    Write-Host "× OU Structure import failed" -ForegroundColor Red
    exit 1
}

# Process each player LDIF file
Write-Host "`n[2/2] Importing Players..." -ForegroundColor Yellow
$playerFiles = Get-ChildItem -Path $PlayersDir -Filter "*.ldf"
$totalPlayers = $playerFiles.Count
$processedCount = 0
$successCount = 0
$failureCount = 0

# Initialize progress bar
$progressParams = @{
    Activity = "Importing MLB Players"
    Status = "Processing players..."
    PercentComplete = 0
}

foreach ($file in $playerFiles) {
    $playerId = $file.BaseName
    $processedCount++
    
    # Update progress bar
    $progressParams.PercentComplete = ($processedCount / $totalPlayers) * 100
    $progressParams.Status = "Processing $processedCount of $totalPlayers ($playerId)"
    Write-Progress @progressParams
    
    # Import player
    Write-Log "Processing player $playerId ($processedCount of $totalPlayers)..." -NoConsole
    if (Invoke-LDIFDE -FilePath $file.FullName -PlayerID $playerId) {
        $successCount++
    } else {
        $failureCount++
    }
}

# Clear progress bar
Write-Progress -Activity "Importing MLB Players" -Completed

# Show summary
Write-Host "`nImport Summary" -ForegroundColor Cyan
Write-Host "=============" -ForegroundColor Cyan
Write-Host "Total Players Processed: $totalPlayers"
Write-Host "Successful Imports: $successCount" -ForegroundColor Green
if ($failureCount -gt 0) {
    Write-Host "Failed Imports: $failureCount" -ForegroundColor Red
    Test-Failures
} else {
    Write-Host "✓ All players imported successfully" -ForegroundColor Green
}

Write-Host "`nDetailed log available at: $LogFile" -ForegroundColor Gray
