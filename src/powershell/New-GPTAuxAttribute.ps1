<# 
.SYNOPSIS
    Creates a new custom attribute and a new auxiliary class in the AD Schema,
    then assigns the attribute to the auxiliary class.
    
.DESCRIPTION
    This script creates a new attribute (gptAttribute) of type Unicode string (single-valued)
    and a new auxiliary class named auxGPT. Both objects are created using a consistent OID
    prefix so that the attribute can be assigned to the auxiliary class via its mayContain list.
    
.PARAMETER AttributeName
    The LDAP display name of the new attribute. (Default: gptAttribute)
    
.PARAMETER AuxClassName
    The LDAP display name of the new auxiliary class. (Default: auxGPT)
    
.PARAMETER AdminDescription
    A brief description for both the new attribute and auxiliary class.
    (Default: "Custom extension via GPT")
    
.EXAMPLE
    .\New-GPTSchemaExtension.ps1
#>

param (
    [string]$AttributeName = "gptAttribute",
    [string]$AuxClassName  = "auxGPT",
    [string]$AdminDescription = "Custom extension via GPT"
)

# Requires -Version 7.0
# Requires -Modules ActiveDirectory

# --- Helper: New-OID using a common prefix ---
function New-OID {
    # Define a common OID prefix that will be used for both objects.
    $Prefix = "1.2.840.113556.4.2424.24242"
    return "$Prefix.$(Get-Random -Minimum 1000 -Maximum 9999)"
}

# --- Set up logging (optional) ---
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message"
}

# --- Get Schema Naming Context ---
$schemaPath = (Get-ADRootDSE).schemaNamingContext
Write-Log "Schema Path: $schemaPath"

# --- Define Schema Master ---
$schemaMaster = (Get-ADForest).SchemaMaster
Write-Log "Using Schema Master: $schemaMaster"

# --- Create New Attribute ---
$attrDN = "CN=$AttributeName,CN=Schema,CN=Configuration,DC=mlb,DC=dev"
try {
    # Check if the attribute already exists
    $existingAttr = Get-ADObject -LDAPFilter "(&(objectClass=attributeSchema)(cn=$AttributeName))" -SearchBase $schemaPath -ErrorAction SilentlyContinue
    if ($existingAttr) {
        Write-Log "Attribute '$AttributeName' already exists. Skipping creation." "WARNING"
    }
    else {
        $attrOID = New-OID
        $fullDescAttr = "GPT: $AdminDescription"
        # Define attribute details for a Unicode string (single-valued)
        $attrProps = @{
            lDAPDisplayName  = $AttributeName
            attributeId      = $attrOID
            oMSyntax         = 64        # Unicode string
            attributeSyntax  = "2.5.5.12"  # Unicode string syntax
            isSingleValued   = $true
            adminDescription = $fullDescAttr
            searchflags      = 1
        }
        New-ADObject -Name $AttributeName -Type "attributeSchema" -Path $schemaPath -OtherAttributes $attrProps -Server $schemaMaster
        Write-Log "Successfully created attribute '$AttributeName' with OID: $attrOID"
    }
}
catch {
    Write-Error "Failed to create attribute '$AttributeName': $($_.Exception.Message)"
    exit 1
}

# --- Create New Auxiliary Class ---
try {
    # Check if the auxiliary class already exists
    $existingAux = Get-ADObject -LDAPFilter "(&(objectClass=classSchema)(cn=$AuxClassName))" -SearchBase $schemaPath -ErrorAction SilentlyContinue
    if ($existingAux) {
        Write-Log "Auxiliary class '$AuxClassName' already exists. Skipping creation." "WARNING"
    }
    else {
        $auxOID = New-OID
        $fullDescAux = "GPT: $AdminDescription"
        $auxProps = @{
            lDAPDisplayName     = $AuxClassName
            objectClassCategory = 3           # Mark as Auxiliary
            governsID           = $auxOID     # governsID should use the same prefix as attributes
            adminDescription    = $fullDescAux
            subClassOf          = "top"
        }
        New-ADObject -Name $AuxClassName -Type "classSchema" -Path $schemaPath -OtherAttributes $auxProps -Server $schemaMaster
        Write-Log "Successfully created auxiliary class '$AuxClassName' with OID: $auxOID"
    }
}
catch {
    Write-Error "Failed to create auxiliary class '$AuxClassName': $($_.Exception.Message)"
    exit 1
}

# --- Retrieve the newly created auxiliary class ---
$auxClass = Get-ADObject -LDAPFilter "(&(objectClass=classSchema)(cn=$AuxClassName))" -SearchBase $schemaPath -Properties DistinguishedName, mayContain -Server $schemaMaster
if (-not $auxClass) {
    Write-Error "Auxiliary class '$AuxClassName' not found after creation."
    exit 1
}
Write-Log "Retrieved auxiliary class '$AuxClassName': $($auxClass.DistinguishedName)"

# --- Add the new attribute to the aux class's mayContain list ---
try {
    # Wrap the value in an array
    Set-ADObject -Server $schemaMaster -Identity $auxClass.DistinguishedName -Add @{ mayContain = @("CN=$AttributeName,CN=Schema,CN=Configuration,DC=mlb,DC=dev") }
    Write-Log "Successfully added attribute '$AttributeName' to '$AuxClassName'."
}
catch {
    Write-Error "Failed to add attribute '$AttributeName' to '$AuxClassName': $($_.Exception.Message)`nStackTrace: $($_.Exception.StackTrace)`nFull error: $($_ | Out-String)"
    exit 1
}

Write-Log "Schema extension completed successfully!" "INFO"
