# Script to analyze LDIF import failure report
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$FailureReportPath = "C:\gh\setupdc2k5\data\csv\failure_report.csv",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\gh\setupdc2k5\data\csv\failure_analysis.csv",

    [Parameter(Mandatory = $false)]
    [switch]$FixMode
)

# Function to categorize errors based on patterns
function Get-ErrorCategory {
    param([string]$ErrorDetails)
    
    switch -Regex ($ErrorDetails) {
        'already exists' { 'Duplicate Entry' }
        'invalid DN|invalid RDN|invalid attribute|syntax|malformed' { 'LDIF Syntax Error' }
        'access denied|insufficient rights|permission' { 'Permission Error' }
        'connection|network|unable to connect' { 'Network Error' }
        'attribute|no such object|schema' { 'Schema Error' }
        'Failed to generate LDIF packet' { 'Generation Error' }
        default { 'Other Error' }
    }
}

# Function to extract error codes from error messages
function Get-ErrorCode {
    param([string]$ErrorDetails)
    
    if ($ErrorDetails -match '0x[0-9a-fA-F]+') {
        return $Matches[0]
    }
    return "No Error Code"
}

# Function to create ASCII bar chart
function New-ASCIIBarChart {
    param(
        [array]$Data,
        [int]$MaxWidth = 50,
        [string]$Title
    )
    
    Write-Host "`n$Title"
    Write-Host ("=" * $Title.Length)
    
    $maxValue = ($Data | Measure-Object -Property Count -Maximum).Maximum
    $scale = $MaxWidth / $maxValue
    
    foreach ($item in $Data) {
        $barLength = [math]::Round($item.Count * $scale)
        $bar = "█" * $barLength
        $percentage = "{0:P1}" -f ($item.Count / ($Data | Measure-Object -Property Count -Sum).Sum)
        Write-Host ("{0,-30} [{1,-50}] {2,5} {3,8}" -f $item.Name, $bar, $item.Count, $percentage)
    }
}

# Function to get specific fix suggestion
function Get-FixSuggestion {
    param(
        [string]$ErrorDetails,
        [string]$ErrorCategory,
        [string]$ErrorCode
    )
    
    $suggestion = switch -Regex ($ErrorDetails) {
        'already exists' { 
            @{
                Issue = "Duplicate entry detected"
                Fix = "Use: ldifde -i -f file.ldf -s server -k -c DC=X DC=Y -j . -v"
                Explanation = "Adds -c switch to handle conflicts"
            }
        }
        'invalid DN' { 
            @{
                Issue = "Distinguished Name syntax error"
                Fix = "Review DN format and escape special characters"
                Explanation = "Common in entries with special characters in names"
            }
        }
        'attribute|no such object' { 
            @{
                Issue = "Schema validation failure"
                Fix = "Verify attribute definitions in AD Schema"
                Explanation = "Custom attributes may need to be added to schema first"
            }
        }
        default { 
            @{
                Issue = "General error"
                Fix = "Review LDIF syntax and server connectivity"
                Explanation = "Could be related to network, permissions, or data format"
            }
        }
    }
    return $suggestion
}

# Import and analyze the failure report
try {
    Write-Host "╔══════════════════════════════════════════╗"
    Write-Host "║     MLB Player LDIF Import Analysis      ║"
    Write-Host "╚══════════════════════════════════════════╝`n"

    Write-Host "Loading failure report from: $FailureReportPath"
    $failures = Import-Csv -Path $FailureReportPath
    
    $totalFailures = $failures.Count
    Write-Host "`nTotal Failures Found: $totalFailures"
    
    # Enhanced error analysis
    $enrichedFailures = $failures | Select-Object *, 
        @{Name='ErrorCategory'; Expression={ Get-ErrorCategory $_.ErrorDetails }},
        @{Name='ErrorCode'; Expression={ Get-ErrorCode $_.ErrorDetails }},
        @{Name='FixSuggestion'; Expression={ (Get-FixSuggestion $_.ErrorDetails $_.ErrorCategory (Get-ErrorCode $_.ErrorDetails)).Fix }},
        @{Name='NameComplexity'; Expression={ 
            switch -Regex ($_.Name) {
                '[^a-zA-Z\s]' { 'Complex' }
                '\s' { 'Simple with Space' }
                default { 'Simple' }
            }
        }}

    # Create visualizations
    $errorTypes = $enrichedFailures | Group-Object ErrorType | Sort-Object Count -Descending
    New-ASCIIBarChart -Data $errorTypes -Title "Error Distribution by Type"

    $errorCategories = $enrichedFailures | Group-Object ErrorCategory | Sort-Object Count -Descending
    New-ASCIIBarChart -Data $errorCategories -Title "Error Distribution by Category"

    # Detailed pattern analysis
    Write-Host "`n🔍 Pattern Analysis"
    Write-Host "================="
    
    # Name complexity patterns
    $namePatterns = $enrichedFailures | Group-Object NameComplexity | Sort-Object Count -Descending
    Write-Host "`nName Complexity Distribution:"
    $namePatterns | Format-Table @{
        Label = "Complexity"
        Expression = { $_.Name }
    }, Count, @{
        Label = "Example Names"
        Expression = { ($_.Group | Select-Object -First 2 | ForEach-Object { $_.Name }) -join ", " }
    } -Wrap

    # Error hotspots
    Write-Host "`n🎯 Error Hotspots"
    Write-Host "==============="
    $errorHotspots = $enrichedFailures | Group-Object { "$($_.ErrorCategory) - $($_.NameComplexity)" } | 
        Sort-Object Count -Descending |
        Select-Object -First 5
    $errorHotspots | Format-Table @{
        Label = "Pattern"
        Expression = { $_.Name }
    }, Count, @{
        Label = "Example PlayerIDs"
        Expression = { ($_.Group | Select-Object -First 3 | ForEach-Object { $_.PlayerID }) -join ", " }
    } -Wrap

    # Specific fix suggestions
    Write-Host "`n🔧 Top Issues and Fixes"
    Write-Host "===================="
    $topIssues = $enrichedFailures | Group-Object ErrorCategory | Sort-Object Count -Descending | Select-Object -First 3
    foreach ($issue in $topIssues) {
        $example = $issue.Group[0]
        $fix = Get-FixSuggestion $example.ErrorDetails $example.ErrorCategory $example.ErrorCode
        Write-Host "`nIssue Category: $($issue.Name) (Count: $($issue.Count))"
        Write-Host "Problem: $($fix.Issue)"
        Write-Host "Fix: $($fix.Fix)"
        Write-Host "Explanation: $($fix.Explanation)"
        Write-Host "Example PlayerID: $($example.PlayerID)"
    }

    # Export enhanced analysis
    $enrichedFailures | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "`nEnhanced analysis exported to: $OutputPath"

    # Quick fix mode
    if ($FixMode) {
        Write-Host "`n🛠️ Quick Fix Mode"
        Write-Host "==============="
        Write-Host "Generating fix commands for common issues..."
        
        # Generate ldifde commands for retrying failed imports
        $retryCommands = $enrichedFailures | Where-Object ErrorType -eq "LDIF Import Failed" | ForEach-Object {
            "# Retry import for $($_.PlayerID)"
            "ldifde -i -f `"$($_.LogFile)`" -s DC1_2K5 -k -c DC=X DC=Y -j . -v"
        }
        
        $fixScriptPath = Join-Path (Split-Path $OutputPath) "retry_imports.ps1"
        $retryCommands | Out-File -FilePath $fixScriptPath
        Write-Host "Fix commands exported to: $fixScriptPath"
    }

    # Interactive analysis hints
    Write-Host "`n📊 Interactive Analysis Commands:"
    Write-Host "==============================="
    Write-Host @'
# Analyze specific error patterns:
$data = Import-Csv "$OutputPath"

# Find all errors for a specific player:
$data | Where-Object PlayerID -eq "PLAYERID" | Format-List *

# Group similar errors:
$data | Group-Object ErrorCategory | Sort-Object Count -Descending | Format-Table Name, Count

# Export specific category for review:
$data | Where-Object ErrorCategory -eq "CATEGORY" | Export-Csv "category_review.csv"

# Find patterns in complex names:
$data | Where-Object NameComplexity -eq "Complex" | Format-Table PlayerID, Name, ErrorCategory

# Generate retry script:
$data | Where-Object ErrorType -eq "LDIF Import Failed" | ForEach-Object {
    "ldifde -i -f `"$($_.LogFile)`" -s DC1_2K5 -k -c DC=X DC=Y -j . -v"
} | Out-File retry_imports.ps1
'@

} catch {
    Write-Error "Error analyzing failure report: $_"
} 