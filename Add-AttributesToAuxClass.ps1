#Requires -Version 7.0
#Requires -Modules ActiveDirectory

# Get all our custom MLB attributes
$mlbAttributes = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter "objectClass -eq 'attributeSchema'" -Properties * | 
    Where-Object {$_.attributeID -like "1.2.840.113556.1.8000.2554.*"} |
    Select-Object -ExpandProperty lDAPDisplayName |
    ForEach-Object { [string]$_ }  # Convert to string explicitly

Write-Host "Found $($mlbAttributes.Count) MLB attributes to add to auxMLB class"

# Get the auxMLB class
$auxClass = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter "objectClass -eq 'classSchema' -and name -eq 'auxMLB'" -Properties mayContain

# Add each attribute to the mayContain list
foreach ($attr in $mlbAttributes) {
    Write-Host "Adding $attr to auxMLB mayContain..."
    try {
        $currentMayContain = @($auxClass.mayContain)
        if ($currentMayContain -notcontains $attr) {
            Set-ADObject -Identity $auxClass.DistinguishedName -Add @{mayContain = [string]$attr}
            Write-Host "✅ Added $attr successfully"
        } else {
            Write-Host "ℹ️ Attribute $attr already in mayContain"
        }
    }
    catch {
        Write-Error "❌ Failed to add $attr`: $_"
    }
}

Write-Host "`nVerifying attributes in auxMLB class..."
$updatedClass = Get-ADObject -Identity $auxClass.DistinguishedName -Properties mayContain
Write-Host "Current mayContain attributes:"
$updatedClass.mayContain | Sort-Object | ForEach-Object { Write-Host "  - $_" } 