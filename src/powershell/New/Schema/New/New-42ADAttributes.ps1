#requires -Version 7.0
#requires -Modules ActiveDirectory

[CmdletBinding()]
param (
    [string]$SchemaFile = "C:\gh\setupdc2k5\data\csv\schema.python.csv",
    [string]$DescriptionPrefix = "MLB:",
    [string]$LogFile = "C:\gh\setupdc2k5\logs\New42ADAttributes_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

#--------------------------------------------------------------------
# Add this at the top of your script: Custom OID generator using a GUID
Function New-42ADOID {
    $Prefix = "1.2.840.113556.4.2424.24242"
    $GUID = [System.Guid]::NewGuid().ToString("N")
    $Parts = @()

    $Parts += [UInt64]::Parse($GUID.SubString(0, 4), "AllowHexSpecifier")
    $Parts += [UInt64]::Parse($GUID.SubString(4, 4), "AllowHexSpecifier")

    $oid = [String]::Format("{0}.{1}.{2}", $Prefix, $Parts[0], $Parts[1])
    return $oid
}

#--------------------------------------------------------------------
# Test the log directory exists.
function Test-LogDirectory {
    param (
        [string]$Path
    )
    $logDir = Split-Path -Parent $Path
    if (-not (Test-Path $logDir)) {
        try {
            New-Item -ItemType Directory -Path $logDir -Force -ErrorAction Stop | Out-Null
            Write-Host "📁 Created log directory: $logDir"
        }
        catch {
            Write-Error "❌ Failed to create log directory [$logDir]: $($_.Exception.Message)"
            exit 1
        }
    }
}
Test-LogDirectory -Path $LogFile

#--------------------------------------------------------------------
# Function to write logs to both file and console.
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"  # INFO, WARNING, ERROR
    )
    $timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    switch ($Level) {
        "INFO"    { Write-Host $logMessage -ForegroundColor Green }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
        default   { Write-Host $logMessage }
    }
    try {
        $logMessage | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-Host "❌ Failed to write to log file [$LogFile]: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Log "Starting New42ADAttributes.ps1 script..."

#--------------------------------------------------------------------
# Test0 the schema file exists.
Write-Log "Checking if schema file exists: $SchemaFile"
if (-not (Test-Path $SchemaFile)) {
    Write-Log "Schema file not found: $SchemaFile" "ERROR"
    exit 1
}

#--------------------------------------------------------------------
# Test Active Directory connectivity.
function Test-ADConnectivity {
    try {
        $null = Get-ADDomainController -ErrorAction Stop
        Write-Log "Successfully connected to AD."
    }
    catch {
        Write-Log "Failed to connect to Active Directory: $($_.Exception.Message)" "ERROR"
        Write-Log "Ensure the ActiveDirectory module is installed and you have network connectivity to a domain controller." "ERROR"
        exit 1
    }
}
Test-ADConnectivity

#--------------------------------------------------------------------
# Test that the current user is a Schema Admin.
function Test-SchemaAdminMembership {
    try {
        $currentUser  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $adminUser    = $currentUser.Name.Split("\")[1]
        $ADUser       = Get-ADUser -Identity $adminUser -ErrorAction Stop
        $schemaMember = Get-ADGroupMember -Identity "Schema Admins" | Where-Object { $ADUser.Name -eq $_.Name }
        if ($schemaMember) {
            Write-Log "$($ADUser.Name) is a schema admin." "INFO"
        }
        else {
            Write-Log "$($ADUser.Name) is not a member of Schema Admins." "ERROR"
            Write-Log "You must be a member of Schema Admins to modify the AD schema." "ERROR"
            exit 1
        }
    }
    catch {
        Write-Log "Failed to test Schema Admins membership: $($_.Exception.Message)" "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
        exit 1
    }
}
Test-SchemaAdminMembership

#--------------------------------------------------------------------
# Retrieve the AD Schema Naming Context.
function Get-SchemaNamingContext {
    try {
        $schemaPath = (Get-ADRootDSE -ErrorAction Stop).schemaNamingContext
        Write-Log "Schema Path: $schemaPath"
        return $schemaPath
    }
    catch {
        Write-Log "Failed to retrieve schema naming context: $($_.Exception.Message)" "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
        exit 1
    }
}
$schemaPath = Get-SchemaNamingContext

#--------------------------------------------------------------------
# Define attribute syntax mappings.
$syntaxMap = @{
    "Integer"    = @{ attributeSyntax = "2.5.5.9";  oMSyntax = 2  }
    "String"     = @{ attributeSyntax = "2.5.5.12"; oMSyntax = 64 }
    "MultiValue" = @{ attributeSyntax = "2.5.5.12"; oMSyntax = 64 }
}
Write-Log "Defined syntax mappings for attribute types: $($syntaxMap.Keys -join ', ')"

#--------------------------------------------------------------------
# (Legacy) Function to generate a more unique OID.
# Note: This is replaced by New-42ADOID but kept here if needed.
function New-OID {
    # Simplified OID generation using timestamp in format yyyyMMddHHmm
    $timestamp = [DateTime]::UtcNow.ToString("yyyyMMddHHmm")
    $randomPart = Get-Random -Minimum 1000 -Maximum 9999
    return "1.2.840.113556.1.8000.2554.$timestamp$randomPart"
}

#--------------------------------------------------------------------
# Retrieve all existing attributes for comparison.
function Get-ExistingADAttributes {
    try {
        $existingAttributes = @{}
        Get-ADObject -Filter { objectClass -eq "attributeSchema" } `
            -SearchBase $schemaPath -Property lDAPDisplayName, adminDescription -ErrorAction Stop |
            ForEach-Object { $existingAttributes[$_.lDAPDisplayName] = $_ }
        Write-Log "Retrieved $($existingAttributes.Count) existing attributes from AD schema."
        return $existingAttributes
    }
    catch {
        Write-Log "Failed to retrieve existing attributes: $($_.Exception.Message)" "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
        exit 1
    }
}
$existingAttributes = Get-ExistingADAttributes

#--------------------------------------------------------------------
# Test the schema CSV structure.
function Test-SchemaCSVStructure {
    param (
        [Parameter(Mandatory)]
        [array]$SchemaData,
        [Parameter(Mandatory)]
        [array]$RequiredColumns
    )
    
    foreach ($column in $RequiredColumns) {
        if ($SchemaData[0].PSObject.Properties.Name -notcontains $column) {
            Write-Log "Schema CSV is missing required column: $column" "ERROR"
            exit 1
        }
    }
    Write-Log "Schema CSV structure validated. All required columns present: $($RequiredColumns -join ', ')"
}

#--------------------------------------------------------------------
# Import and test the schema CSV data.
Write-Log "Importing schema data from: $SchemaFile"
try {
    $schemaData = Import-Csv -Path $SchemaFile -ErrorAction Stop
    Write-Log "Successfully imported $($schemaData.Count) attributes from schema.csv"
}
catch {
    Write-Log "Failed to import schema CSV: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    exit 1
}

$requiredColumns = @("AttributeName", "AttributeType", "Description", "IsSingleValued")
Test-SchemaCSVStructure -SchemaData $schemaData -RequiredColumns $requiredColumns

#--------------------------------------------------------------------
# Specialized attribute creation functions
function New-42ADString {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipelinebyPropertyName)]
        [String]
        $ColumnName,

        [Parameter(Mandatory, ValueFromPipelinebyPropertyName)]
        [Alias('AdminDescription')]
        [String]
        $Description,

        [Parameter(ValueFromPipelinebyPropertyName)]
        [Alias('OID')]
        [String]
        $AttributeID = (New-42ADOID),

        [Parameter(ValueFromPipelinebyPropertyName)]
        [Alias('SingleValued')]
        [Boolean]
        $IsSingleValued = $True
    )
    BEGIN {}
    PROCESS {
        $schemaPath = (Get-ADRootDSE).schemaNamingContext

        # Check if the attribute already exists
        $existingAttribute = Get-ADObject -Filter "lDAPDisplayName -eq '$ColumnName'" -SearchBase $schemaPath -ErrorAction SilentlyContinue
        if ($existingAttribute) {
            Write-Warning "Attribute '$ColumnName' already exists."
            return
        }

        # Attribute details specific to string type
        $attributes = @{
            lDAPDisplayName  = $ColumnName;
            attributeId      = $AttributeID;
            oMSyntax         = 64; # For Unicode string
            attributeSyntax  = '2.5.5.12'; # For Unicode string
            isSingleValued   = $IsSingleValued;
            adminDescription = $Description;
            searchflags      = 1
        }

        Try {
            New-ADObject -Name $ColumnName -Type 'attributeSchema' -Path $schemaPath -OtherAttributes $attributes
        }
        Catch {
            $error[0]
        }
    }
    END {}
}

function New-42ADInteger {
    param(
        [Parameter(Mandatory, ValueFromPipelinebyPropertyName)]
        [String]
        $ColumnName,

        [Parameter(Mandatory, ValueFromPipelinebyPropertyName)]
        [Alias('AdminDescription')]
        [String]
        $Description,

        [Parameter(ValueFromPipelinebyPropertyName)]
        [Alias('OID')]
        [String]
        $AttributeID = (New-42ADOID)
    )
    BEGIN {}
    PROCESS {
        $schemaPath = (Get-ADRootDSE).schemaNamingContext

        # Check if the attribute already exists
        $existingAttribute = Get-ADObject -Filter "lDAPDisplayName -eq '$ColumnName'" -SearchBase $schemaPath -ErrorAction SilentlyContinue
        if ($existingAttribute) {
            Write-Warning "Attribute '$ColumnName' already exists."
            return
        }

        # Attribute details specific to integer type
        $attributes = @{
            lDAPDisplayName  = $ColumnName;
            attributeId      = $AttributeID;
            oMSyntax         = 2; # For Int
            attributeSyntax  = '2.5.5.9'; # For Int
            isSingleValued   = $True;
            adminDescription = $Description;
            searchflags      = 1
        }

        Try {
            New-ADObject -Name $ColumnName -Type 'attributeSchema' -Path $schemaPath -OtherAttributes $attributes
        }
        Catch {
            $error[0]
        }
    }
    END {}
}

function New-42ADMultValueUnicode {
    param(
        [Parameter(Mandatory, ValueFromPipelinebyPropertyName)]
        [String]
        $ColumnName,

        [Parameter(Mandatory, ValueFromPipelinebyPropertyName)]
        [Alias('AdminDescription')]
        [String]
        $Description,

        [Parameter(ValueFromPipelinebyPropertyName)]
        [Alias('OID')]
        [String]
        $AttributeID = (New-42ADOID)
    )
    BEGIN {}
    PROCESS {
        $schemaPath = (Get-ADRootDSE).schemaNamingContext

        # Check if the attribute already exists
        $existingAttribute = Get-ADObject -Filter "lDAPDisplayName -eq '$ColumnName'" -SearchBase $schemaPath -ErrorAction SilentlyContinue
        if ($existingAttribute) {
            Write-Warning "Attribute '$ColumnName' already exists."
            return
        }

        # Attribute details specific to Unicode string type and multivalued
        $attributes = @{
            lDAPDisplayName  = $ColumnName;
            attributeId      = $AttributeID;
            oMSyntax         = 64; # For Unicode string
            attributeSyntax  = '2.5.5.12'; # For Unicode string
            isSingleValued   = $False;
            adminDescription = $Description;
            searchflags      = 1
        }

        Try {
            New-ADObject -Name $ColumnName -Type 'attributeSchema' -Path $schemaPath -OtherAttributes $attributes
        }
        Catch {
            $error[0]
        }
    }
    END {}
}

#--------------------------------------------------------------------
# Modified New-ADAttribute function to use specialized functions
function New-ADAttribute {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$Type,
        [Parameter(Mandatory)]
        [string]$Description,
        [Parameter(Mandatory)]
        [bool]$IsSingleValued,
        [Parameter(Mandatory)]
        [string]$SchemaPath,
        [Parameter(Mandatory)]
        [hashtable]$SyntaxMap
    )

    # Validate attribute type.
    if (-not $SyntaxMap.ContainsKey($Type)) {
        Write-Log "Unrecognized type [$Type] for attribute [$Name]." "ERROR"
        return $false
    }

    # Replace underscores with dashes and lowercase lDAPDisplayName.
    $NameFixed = $Name.Replace("_", "-")
    $ldapName = $NameFixed.ToLower()

    Write-Log "Creating attribute: $NameFixed"
    Write-Log "   Type: $Type"
    Write-Log "   Single-Valued: $IsSingleValued"
    Write-Log "   Description: $Description"

    try {
        # Get the schema master dynamically
        $schemaMaster = (Get-ADForest).SchemaMaster
        Write-Log "Using Schema Master: $schemaMaster"

        # Use specialized functions based on type
        switch ($Type) {
            "String" {
                New-42ADString -ColumnName $ldapName -Description $Description -IsSingleValued $IsSingleValued
            }
            "Integer" {
                New-42ADInteger -ColumnName $ldapName -Description $Description
            }
            "MultiValue" {
                New-42ADMultValueUnicode -ColumnName $ldapName -Description $Description
            }
            default {
                Write-Log "Unsupported type: $Type" "ERROR"
                return $false
            }
        }
        
        Write-Log "Successfully created attribute: $NameFixed"
        return $true
    }
    catch {
        Write-Log "Failed to create attribute [$NameFixed]: $($_.Exception.Message)" "ERROR"
        Write-Log "Detailed error: $($error[0].Exception.Message)" "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
        return $false
    }
}

#--------------------------------------------------------------------
# Process each attribute from the schema CSV.
$processedCount = 0
$skippedCount   = 0
$createdCount   = 0
$errorCount     = 0

foreach ($row in $schemaData) {
    $processedCount++
    # Validate row data.
    if (-not $row.AttributeName) {
        Write-Log "Skipping row $processedCount due to missing AttributeName" "WARNING"
        $skippedCount++
        continue
    }
    if (-not $row.AttributeType) {
        Write-Log "Skipping attribute [$($row.AttributeName)] due to missing AttributeType" "WARNING"
        $skippedCount++
        continue
    }
    if ($row.IsSingleValued -notin @("True", "False")) {
        Write-Log "Skipping attribute [$($row.AttributeName)] due to invalid IsSingleValued value: $($row.IsSingleValued)" "WARNING"
        $skippedCount++
        continue
    }
    $name           = $row.AttributeName
    $type           = $row.AttributeType
    $isSingleValued = [bool]($row.IsSingleValued -eq "True")
    $description    = if ($row.Description -notmatch "mlb:") {
        "$DescriptionPrefix $($row.Description)"
    }
    else {
        $row.Description
    }
    Write-Log "Processing attribute [$name] (Row $processedCount of $($schemaData.Count))"
    # Check if the attribute already exists.
    if ($existingAttributes.ContainsKey($name.ToLower())) {
        Write-Log "Attribute [$name] already exists with $DescriptionPrefix prefix. Skipping." "WARNING"
        $skippedCount++
        continue
    }
    # Call the new function to create the attribute.
    if (New-ADAttribute -Name $name -Type $type -Description $description -IsSingleValued $isSingleValued -SchemaPath $schemaPath -SyntaxMap $syntaxMap) {
        $createdCount++
    }
    else {
        $errorCount++
    }
}

#--------------------------------------------------------------------
# Summary report.
Write-Log "Attribute creation process completed!" "INFO"
Write-Log "Summary:" "INFO"
Write-Log "   Total Attributes Processed: $processedCount" "INFO"
Write-Log "   Attributes Created: $createdCount" "INFO"
Write-Log "   Attributes Updated: 0" "INFO"
Write-Log "   Attributes Skipped: $skippedCount" "INFO"
Write-Log "   Errors Encountered: $errorCount" "INFO"
Write-Log "Log file: $LogFile" "INFO"

if ($errorCount -gt 0) {
    Write-Log "Exiting with errors. Check the log file for details." "WARNING"
    exit 1
}
else {
    Write-Log "Script completed successfully!" "INFO"
    exit 0
}
