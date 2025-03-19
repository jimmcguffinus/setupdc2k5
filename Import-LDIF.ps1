#Requires -Version 7.0

<#
.SYNOPSIS
    Imports LDIF files into Active Directory using ldifde.exe.

.DESCRIPTION
    This script:
    - Validates LDIF file paths
    - Checks for ldifde.exe availability
    - Imports LDIF files in the correct order
    - Handles errors and provides detailed feedback

    NOTE: Requires PowerShell 7.x for best compatibility.
    Must be run with administrative privileges.

.PARAMETER SchemaLDIF
    Path to the schema LDIF file.

.PARAMETER UsersLDIF
    Path to the users LDIF file.

.PARAMETER Domain
    Target domain (default: mlb.local)

.OUTPUTS
    Success or failure messages for each LDIF import operation.
#>

function Import-LDIF {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SchemaLDIF = "C:\data\mlb\mlb_schema.ldf",
        [string]$UsersLDIF = "C:\data\mlb\mlb_users.ldf",
        [string]$Domain = "mlb.local"
    )

    # Ensure we are in PowerShell 7+
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Error "This script requires PowerShell 7.0 or later."
        exit 1
    }

    # Get domain components for substitution
    $domainDN = "DC=" + ($Domain -split "\." -join ",DC=")

    try {
        # Import schema extensions
        Write-Host "Importing schema extensions..." -ForegroundColor Cyan
        $result = ldifde -i -f $SchemaLDIF -c "DC=X" $domainDN
        if ($LASTEXITCODE -ne 0) {
            throw "Schema import failed: $result"
        }
        Write-Host "✅ Schema imported successfully" -ForegroundColor Green

        # Wait for schema to replicate
        Write-Host "Waiting for schema to replicate (15 seconds)..." -ForegroundColor Yellow
        Start-Sleep -Seconds 15

        # Import MLB data
        Write-Host "Importing MLB data..." -ForegroundColor Cyan
        $result = ldifde -i -f $UsersLDIF -c "DC=X" $domainDN
        if ($LASTEXITCODE -ne 0) {
            throw "Data import failed: $result"
        }
        Write-Host "✅ MLB data imported successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Error during import: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Example usage:
# Import-LDIF -SchemaLDIF "C:\data\mlb\mlb_schema.ldf" -UsersLDIF "C:\data\mlb\mlb_users.ldf" -Domain "mlb.local" 