param (
    [string]$SchemaFile = "C:\gh\setupdc2k5\schema\schema.csv"
)

if (-not (Test-Path $SchemaFile)) {
    Write-Error "❌ Schema file not found: $SchemaFile"
    exit 1
}

# Dynamically get AD Schema Naming Context
$schemaPath = (Get-ADRootDSE).schemaNamingContext

Write-Host "Schema Path: $schemaPath"

# Define attribute syntax mappings
$syntaxMap = @{
    "Integer"      = @{ attributeSyntax = "2.5.5.9";  oMSyntax = 2  }
    "Double"       = @{ attributeSyntax = "2.5.5.16"; oMSyntax = 4  }
    "String"       = @{ attributeSyntax = "2.5.5.12"; oMSyntax = 64 }
    "MultiValue"   = @{ attributeSyntax = "2.5.5.12"; oMSyntax = 64 }
}

# Generate Unique OID
function New-OID {
    return "1.2.840.113556.1.8000.2554.$(Get-Random -Minimum 1000 -Maximum 9999)"
}

# Function to check if the attribute exists in the schema
function Get-ADAttribute {
    param (
        [string]$AttributeName
    )
    return Get-ADObject -Filter { lDAPDisplayName -eq $AttributeName } -SearchBase $schemaPath -Property adminDescription -ErrorAction SilentlyContinue
}

# Import CSV Data
$schemaData = Import-Csv -Path $SchemaFile

Write-Host "🔍 Processing $($schemaData.Count) attributes from schema.csv..."

# Process each row in the schema data
foreach ($row in $schemaData) {
    $name = $row.AttributeName
    $type = $row.AttributeType
    $isSingleValued = [bool]($row.IsSingleValued -eq "True")
    $description = "MLB: $($row.Description)"

    # Check if the attribute already exists
    $existingAttribute = Get-ADAttribute -AttributeName $name
    if ($existingAttribute) {
        $existingDesc = $existingAttribute.adminDescription
        if (-not $existingDesc -or $existingDesc -notmatch '^MLB:') {
            # Update adminDescription with MLB: prefix
            Set-ADObject -Identity $existingAttribute.DistinguishedName -Replace @{ adminDescription = $description }
            Write-Host "✅ Updated adminDescription for: $name"
        } else {
            Write-Host "⚠️ Attribute already exists with MLB prefix: $name (Skipping)"
        }
        continue
    }

    # Ensure the type exists in the map
    if ($syntaxMap.ContainsKey($type)) {
        $attributeSyntax = $syntaxMap[$type].attributeSyntax
        $oMSyntax = $syntaxMap[$type].oMSyntax
    } else {
        Write-Warning "⚠️ Unrecognized type [$type] for attribute [$name], defaulting to String."
        $attributeSyntax = "2.5.5.12"
        $oMSyntax = 64
    }

    # Generate Unique OID
    $oid = New-OID
    Write-Host "Generated OID: $oid"
    $name = $name.Replace("_", "-")

    # Log Attribute Details
    Write-Host "⚙️ Creating Attribute: $name"
    Write-Host "   🔹 Type: $type"
    Write-Host "   🔹 OID: $oid"
    Write-Host "   🔹 Syntax: $attributeSyntax ($oMSyntax)"
    Write-Host "   🔹 Single-Valued: $isSingleValued"
    Write-Host "   🔹 Schema Path: $schemaPath"

    # Create the attribute
    $minimalAttributes = @{
        'cn' = $name
        'lDAPDisplayName' = $name
        'attributeID' = $oid
        'attributeSyntax' = $attributeSyntax
        'oMSyntax' = [int]$oMSyntax
        'adminDescription' = $description
    }

    try {
        $null = New-ADObject -Name $name -Type "attributeSchema" -Path $schemaPath -OtherAttributes $minimalAttributes -ErrorAction Stop
        Write-Host "✅ Successfully created attribute: $name"
    } catch {
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
