#Requires -Version 7.0

<#
.SYNONOPSIS
    Creates the auxMLB auxiliary class in Active Directory.

.DESCRIPTION
    This script creates the auxMLB auxiliary class in Active Directory that will contain
    all MLB-related attributes. The class is created with proper schema extensions and
    can be attached to user objects to store MLB data.

    NOTE: Requires PowerShell 7.x for best compatibility.
    The script requires the ActiveDirectory module, available with RSAT or on a domain controller.

.PARAMETER OutputDirectory
    Output directory for the generated schema files. Defaults to `.\schema`.

.PARAMETER SchemaPrefix
    Prefix for the generated schema files. Defaults to `mlb`.

.OUTPUTS
    LDIF file for the auxiliary class definition.
#>

param(
    [string]$OutputDirectory = ".\schema",
    [string]$SchemaPrefix = "mlb"
)

# Ensure we are in PowerShell 7+
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7.0 or later."
    exit 1
}

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
}

# Define output paths
$AuxClassFile = Join-Path $OutputDirectory "auxiliary_class.ldf"

# Generate a unique OID for the auxiliary class
$CustomGovernsID = "1.2.840.113556.1.8000.2554.1364230575"

# Create the auxiliary class LDIF content
$AuxClassContent = @"
dn: CN=Schema,CN=Configuration,DC=mlb,DC=dev
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
-
dn: CN=auxMLB,CN=Schema,CN=Configuration,DC=mlb,DC=dev
changetype: add
objectClass: classSchema
cn: auxMLB
lDAPDisplayName: auxMLB
adminDisplayName: auxMLB
adminDescription: MLB Auxiliary Class for storing baseball-related attributes
governsID: $CustomGovernsID
objectClassCategory: 3
rDNAttID: 2.5.4.3
subClassOf: top
schemaIDGUID:: $([System.Convert]::ToBase64String([System.Guid]::NewGuid().ToByteArray()))
defaultObjectCategory: CN=auxMLB,CN=Schema,CN=Configuration,DC=mlb,DC=dev
defaultHidingValue: FALSE
defaultSecurityDescriptor: D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPLCLORC;;;AU)
instanceType: 4
systemOnly: FALSE
systemFlags: 16
"@

# Write the auxiliary class LDIF file
$AuxClassContent | Out-File -FilePath $AuxClassFile -Encoding UTF8

Write-Host "Generated auxiliary class LDIF at: $AuxClassFile"
Write-Host "You can now use this LDIF file to create the auxMLB class in Active Directory." 