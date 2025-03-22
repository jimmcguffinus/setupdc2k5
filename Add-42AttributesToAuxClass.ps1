#Requires -Version 7.0
#Requires -Modules ActiveDirectory

# Get Schema Naming Context
$schemaNC = (Get-ADRootDSE).schemaNamingContext
Write-Host "Schema path: $schemaNC"

# Get all our custom MLB attributes
$mlbAttributes = Get-ADObject -SearchBase $schemaNC `
    -LDAPFilter "(objectClass=attributeSchema)" -Properties * |
    Where-Object { $_.attributeID -like "1.2.840.113556.1.8000.2554.*" } |
    Select-Object -ExpandProperty lDAPDisplayName |
    ForEach-Object { [string]$_ }  # Convert to string explicitly

Write-Host "Found $($mlbAttributes.Count) MLB attributes to add to auxMLB class"

# Get the auxMLB auxiliary class
$auxClass = Get-ADObject -SearchBase $schemaNC `
    -LDAPFilter "(&(objectClass=classSchema)(cn=auxMLB))" -Properties DistinguishedName, mayContain

# Ensure auxMLB class exists
if (-not $auxClass) {
    Write-Error "❌ auxMLB class not found in Active Directory schema."
    exit 1
}

Write-Host "✅ auxMLB found: $($auxClass.DistinguishedName)"

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

# ----- Link auxMLB to user class -----

Write-Host "`n🔗 Linking auxMLB to user structural class..."

# Get the user class with the correct property
$userClass = Get-ADObject -SearchBase $schemaNC `
    -LDAPFilter "(&(objectClass=classSchema)(cn=user))" -Properties DistinguishedName, auxiliaryClass

# Ensure user class exists
if (-not $userClass) {
    Write-Error "❌ User class not found in schema."
    exit 1
}

Write-Host "✅ User class found: $($userClass.DistinguishedName)"

# Add auxMLB to auxiliaryClass of user (not systemAuxiliaryClass)
try {
    $currentAuxClasses = @($userClass.auxiliaryClass)
    if ($currentAuxClasses -notcontains "auxMLB") {
        Set-ADObject -Identity $userClass.DistinguishedName -Add @{auxiliaryClass = "auxMLB"}
        Write-Host "✅ auxMLB successfully linked to user class."
    } else {
        Write-Host "ℹ️ auxMLB already linked to user class."
    }
}
catch {
    Write-Error "❌ Failed to link auxMLB to user class: $_"
}

Write-Host "`n✅ Schema updates completed successfully!"
