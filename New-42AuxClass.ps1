<#
.SYNOPSIS
    Creates a new auxiliary class in the Active Directory Schema.

.DESCRIPTION
    This script defines a function to create a new auxiliary class in the AD Schema.
    It includes a helper function to generate a unique OID and uses New-ADObject
    for proper schema extension. Auxiliary classes allow adding custom attributes 
    to AD objects without modifying the base classes.

.PARAMETER Name
    The LDAP display name of the new auxiliary class.

.PARAMETER AdminDescription
    A brief description of the auxiliary class. This will be prefixed with "MLB: ".

.EXAMPLE
    .\New-42ADAuxClass.ps1 -Name "auxMLB" -AdminDescription "Custom metadata extension for baseball objects"

.NOTES
    Requires:
    - Schema Admin privileges
    - ActiveDirectory module
    - Execution on the Schema Master FSMO role holder
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $true)]
    [string]$AdminDescription
)

# Function to generate a unique OID
function New-OID {
    return "1.2.840.113556.1.8000.2554.$(Get-Random -Minimum 1000 -Maximum 9999)"
}

# Verify prerequisites
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "❌ ActiveDirectory module not available."
    exit 1
}

Import-Module ActiveDirectory

# Get the schema path dynamically
$schemaPath = (Get-ADRootDSE).schemaNamingContext

# Check if class already exists - with more specific search and debugging
try {
    Write-Host "Searching in: $schemaPath"
    $existingClass = Get-ADObject -LDAPFilter "(&(objectClass=classSchema)(cn=$Name))" -SearchBase $schemaPath -ErrorAction Stop
    if ($existingClass) {
        Write-Warning "⚠️ Auxiliary class '$Name' already exists."
        exit 1
    }
} catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    Write-Host "✅ Verified class does not exist, proceeding with creation..."
} catch {
    Write-Error "❌ Error checking for existing class: $_"
    exit 1
}

# Generate fields
$oid = New-OID
$fullDesc = "MLB: $AdminDescription"

# Create auxiliary class
try {
    New-ADObject `
        -Name $Name `
        -Type "classSchema" `
        -Path $schemaPath `
        -OtherAttributes @{
            lDAPDisplayName     = $Name
            objectClassCategory = 3               # Auxiliary class
            governsID           = $oid
            adminDescription    = $fullDesc
            subClassOf         = "top"
        }

    Write-Host "✅ Successfully created auxiliary class '$Name' with OID: $oid"
} catch {
    Write-Error "❌ Failed to create auxiliary class: $_"
}
