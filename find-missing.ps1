# Read schema attributes
$schema = Import-Csv "C:\gh\setupdc2k5\schema\schema.csv"
$schemaAttrs = $schema.AttributeName

# Get Hank's current attributes
$hank = Get-ADUser -Identity "aaronha01" -Properties *

# Find missing or empty attributes (case-insensitive)
$missing = $schemaAttrs | Where-Object { 
    $attr = $_
    # Check if attribute exists (case-insensitive)
    $adAttr = $hank.PSObject.Properties | Where-Object { $_.Name.ToLower() -eq $attr.ToLower() }
    
    # Consider it missing if:
    # 1. Attribute doesn't exist OR
    # 2. Attribute exists but is null/empty/empty array
    # 3. But NOT if it's an empty string (which is valid for some attributes)
    -not $adAttr -or 
    ($adAttr.Value -eq $null -or 
     ($adAttr.Value -is [Array] -and $adAttr.Value.Count -eq 0))
}

Write-Host "`nMissing or Empty Attributes:`n-------------------------"
$missing | ForEach-Object { 
    $attr = $_
    $type = ($schema | Where-Object { $_.AttributeName -eq $attr }).AttributeType
    $value = ($hank.PSObject.Properties | Where-Object { $_.Name.ToLower() -eq $attr.ToLower() }).Value
    Write-Host "$attr ($type) = '$value'" 
} 