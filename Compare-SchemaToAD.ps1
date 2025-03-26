# Compare AD Schema attributes with schema.python.csv
[CmdletBinding()]
param(
    [string]$SchemaFile = "C:\gh\setupdc2k5\data\csv\schema.python.csv"
)

# Get the schema naming context and AD attributes
$schemaPath = (Get-ADRootDSE -ErrorAction Stop).schemaNamingContext
$adAttributes = Get-ADObject -Filter {
    objectClass -eq "attributeSchema" -and adminDescription -like "MLB:*"
} -SearchBase $schemaPath -Properties lDAPDisplayName, oMSyntax, isSingleValued, adminDescription

# Import CSV schema
$csvSchema = Import-Csv -Path $SchemaFile

# Create comparison results array
$results = @()

# Process each AD attribute
foreach ($adAttr in $adAttributes) {
    # Get matching CSV entry
    $csvAttr = $csvSchema | Where-Object { $_.AttributeName -eq $adAttr.lDAPDisplayName }
    
    # Determine AD type
    $adType = switch ($adAttr.oMSyntax) {
        2 { "Integer" }
        64 { if ($adAttr.isSingleValued) { "String" } else { "MultiValue" } }
        default { "Unknown" }
    }
    
    # Create comparison object
    $comparison = [PSCustomObject]@{
        AttributeName = $adAttr.lDAPDisplayName
        AD_Type = $adType
        CSV_Type = $csvAttr.AttributeType
        TypeMatch = $adType -eq $csvAttr.AttributeType
        AD_Description = $adAttr.adminDescription
        CSV_Description = $csvAttr.Description
        DescriptionMatch = $adAttr.adminDescription -eq $csvAttr.Description
        CSV_SourceFile = $csvAttr.SourceFile
        InCSV = $null -ne $csvAttr
    }
    
    $results += $comparison
}

# Find CSV attributes not in AD
$missingInAD = $csvSchema | Where-Object {
    $attrName = $_.AttributeName
    -not ($adAttributes | Where-Object { $_.lDAPDisplayName -eq $attrName })
}

# Output results
Write-Host "`nAttribute Comparison Matrix:" -ForegroundColor Cyan
$results | Format-Table -AutoSize

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "Total AD Attributes: $($adAttributes.Count)"
Write-Host "Total CSV Attributes: $($csvSchema.Count)"
Write-Host "Attributes in both: $($results.Count)"
Write-Host "Type Mismatches: $(($results | Where-Object { -not $_.TypeMatch }).Count)"
Write-Host "Description Mismatches: $(($results | Where-Object { -not $_.DescriptionMatch }).Count)"
Write-Host "Missing in AD: $($missingInAD.Count)"

if ($missingInAD.Count -gt 0) {
    Write-Host "`nAttributes in CSV but not in AD:" -ForegroundColor Yellow
    $missingInAD | Select-Object AttributeName, AttributeType, SourceFile | Format-Table -AutoSize
}

# Export detailed results if needed
$results | Export-Csv -Path "schema_comparison_results.csv" -NoTypeInformation 