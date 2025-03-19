#Requires -Version 7.0

param (
    [string]$SchemaCsvFile = "schema\schema.csv",
    [string]$LdifOutputFolder = "schema\ldif_packets"
)

# Ensure the schema CSV file exists
if (-not (Test-Path $SchemaCsvFile)) {
    Write-Error "Schema CSV file not found: $SchemaCsvFile"
    exit 1
}

# Remove existing ldif_packets directory if it exists
if (Test-Path $LdifOutputFolder) {
    Write-Host "Removing existing LDIF packets directory..."
    Remove-Item -Path $LdifOutputFolder -Recurse -Force
}

# Create the output folder
New-Item -ItemType Directory -Path $LdifOutputFolder -Force | Out-Null

# Read the schema CSV
$schemaData = Import-Csv -Path $SchemaCsvFile

# Define Base OID (Replace with your registered OID arc)
$baseOID = "1.2.840.113556.1.8000"

# Function to check if an attribute already exists
function Test-AttributeExists {
    param (
        [string]$LdapDisplayName
    )
    try {
        $exists = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter "(lDAPDisplayName=$LdapDisplayName)"
        return $null -ne $exists
    }
    catch {
        Write-Warning "Could not check for attribute $LdapDisplayName due to error: $_"
        return $false
    }
}

# Function to generate Base64 Schema GUID
function Get-Base64SchemaGUID {
    $guid = [guid]::NewGuid()
    [byte[]]$guidBytes = $guid.ToByteArray()
    return [System.Convert]::ToBase64String($guidBytes)
}

# Generate LDIF packets for new attributes
$counter = 1
foreach ($attr in $schemaData) {
    $attrName = $attr.AttributeName
    $attrType = $attr.AttributeType
    $attrDescription = $attr.Description  # Already has "MLB: " prefix from schema.csv

    # Check if the attribute already exists in AD schema
    if (Test-AttributeExists -LdapDisplayName $attrName) {
        Write-Host "Skipping existing attribute: $attrName"
        continue
    }

    # Determine syntax and OID
    $syntax = switch ($attrType) {
        "Integer" { "2.5.5.9" }
        "Double" { "2.5.5.10" }
        "String" { "2.5.5.12" }
        "MultiValue" { "2.5.5.12" }
        default { "2.5.5.12" }
    }
    
    $oMSyntax = switch ($attrType) {
        "Integer" { "2" }
        "Double" { "10" }
        "String" { "27" }
        "MultiValue" { "27" }
        default { "27" }
    }

    $attributeId = "$baseOID.$counter"
    $schemaIdGuid = Get-Base64SchemaGUID

    # Generate LDIF content
    $ldifContent = @"
dn: CN=$attrName,CN=Schema,CN=Configuration,$((Get-ADRootDSE).schemaNamingContext)
changetype: add
objectClass: top
objectClass: attributeSchema
cn: $attrName
lDAPDisplayName: $attrName
attributeId: $attributeId
attributeSyntax: $syntax
oMSyntax: $oMSyntax
isSingleValued: $(-not ($attrType -eq "MultiValue"))
searchFlags: 1
adminDisplayName: $attrName
adminDescription: $attrDescription
schemaIdGuid:: $schemaIdGuid
showInAdvancedViewOnly: FALSE
"@

    # Save LDIF to individual packet file
    $ldifFilePath = "$LdifOutputFolder\$attrName.ldf"
    $ldifContent | Out-File -FilePath $ldifFilePath -Encoding UTF8
    Write-Host "Generated LDIF packet: $ldifFilePath"

    $counter++
}

Write-Host "LDIF packet generation completed. Files stored in $LdifOutputFolder" 