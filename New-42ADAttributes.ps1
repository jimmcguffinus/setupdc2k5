param (
    [string]$SchemaFile = "C:\gh\setupdc2k5\schema\schema.csv",
    [string]$DescriptionPrefix = "MLB:"
)

# Check if the schema file exists.
if (-not (Test-Path $SchemaFile)) {
    Write-Error "❌ Schema file not found: $SchemaFile"
    exit 1
}

# Dynamically get AD Schema Naming Context.
$schemaPath = (Get-ADRootDSE).schemaNamingContext
Write-Host "Schema Path: $schemaPath"

# Define attribute syntax mappings.
$syntaxMap = @{
    "Integer"    = @{ attributeSyntax = "2.5.5.9";  oMSyntax = 2  }
    "String"     = @{ attributeSyntax = "2.5.5.12"; oMSyntax = 64 }
    "MultiValue" = @{ attributeSyntax = "2.5.5.12"; oMSyntax = 64 }
}

# Function to generate a unique OID.
function New-OID {
    return "1.2.840.113556.1.8000.2554.$(Get-Random -Minimum 1000 -Maximum 9999)"
}

# Function to check if an attribute exists in the schema.
function Get-ADAttribute {
    param (
        [string]$AttributeName
    )
    return $existingAttributes[$AttributeName]
}

# Import CSV data.
$schemaData = Import-Csv -Path $SchemaFile
Write-Host "🔍 Processing $($schemaData.Count) attributes from schema.csv..."

# Retrieve all existing attributes for faster lookups.
$existingAttributes = @{}
Get-ADObject -Filter { objectClass -eq "attributeSchema" } -SearchBase $schemaPath -Property lDAPDisplayName, adminDescription |
    ForEach-Object { $existingAttributes[$_.lDAPDisplayName] = $_ }

# Process each row in the schema data.
foreach ($row in $schemaData) {
    $name          = $row.AttributeName
    $type          = $row.AttributeType
    $isSingleValued = [bool]($row.IsSingleValued -eq "True")
    $description   = "$DescriptionPrefix $($row.Description)"

    # Check if the attribute already exists.
    $existingAttribute = Get-ADAttribute -AttributeName $name
    if ($existingAttribute) {
        $existingDesc = $existingAttribute.adminDescription
        if (-not $existingDesc -or $existingDesc -notmatch "^$DescriptionPrefix") {
            try {
                Set-ADObject -Identity $existingAttribute.DistinguishedName -Replace @{ adminDescription = $description } -ErrorAction Stop
                Write-Host "✅ Updated adminDescription for: $name"
            }
            catch {
                Write-Error "❌ Failed to update adminDescription for [$name]: $($_.Exception.Message)"
            }
        }
        else {
            Write-Host "⚠️ Attribute already exists with $DescriptionPrefix prefix: $name (Skipping)"
        }
        continue
    }

    # Validate the attribute type.
    if (-not $syntaxMap.ContainsKey($type)) {
        Write-Error "❌ Unrecognized type [$type] for attribute [$name]. Skipping."
        continue
    }

    $attributeSyntax = $syntaxMap[$type].attributeSyntax
    $oMSyntax        = $syntaxMap[$type].oMSyntax

    # Generate a unique OID.
    $oid = New-OID
    Write-Host "Generated OID: $oid"

    # Replace underscores with dashes in the name.
    $name = $name.Replace("_", "-")

    # Log attribute details.
    Write-Host "⚙️ Creating Attribute: $name"
    Write-Host "   🔹 Type: $type"
    Write-Host "   🔹 OID: $oid"
    Write-Host "   🔹 Syntax: $attributeSyntax ($oMSyntax)"
    Write-Host "   🔹 Single-Valued: $isSingleValued"
    Write-Host "   🔹 Schema Path: $schemaPath"

    # Prepare attributes for creation.
    $minimalAttributes = @{
        'cn'              = $name
        'lDAPDisplayName' = $name
        'attributeID'     = $oid
        'attributeSyntax' = $attributeSyntax
        'oMSyntax'        = [int]$oMSyntax
        'adminDescription'= $description
        'isSingleValued'  = $isSingleValued
    }

    try {
        $null = New-ADObject -Name $name -Type "attributeSchema" -Path $schemaPath -OtherAttributes $minimalAttributes -ErrorAction Stop
        Write-Host "✅ Successfully created attribute: $name"
    }
    catch {
        Write-Error "❌ Failed to create attribute [$name]: $($_.Exception.Message)"
        Write-Error "Detailed error: $($error[0].Exception.Message)"
        Write-Error "Stack trace: $($_.ScriptStackTrace)"
        Write-Host "Attributes passed to New-ADObject:"
        $minimalAttributes.GetEnumerator() | ForEach-Object {
            Write-Host "   $($_.Key): $($_.Value)"
        }
    }
}

Write-Host "🎯 Attribute creation process completed!"