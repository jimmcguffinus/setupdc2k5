<#
.SYNOPSIS
    Assigns all AD attributes (where adminDescription contains 'MLB') to a specified auxiliary class,
    then links that aux class to the user class. 
    Requires that we add each attribute's OID to mayContain.

.PARAMETER AuxClassName
    The name (CN) of the auxiliary class. Defaults to 'auxPlayer'.

.EXAMPLE
    .\Add-MLB-AttributesToAuxClass.ps1
#>

param (
    [string]$AuxClassName = 'auxMLB'
)

#Requires -Version 7.0
#Requires -Modules ActiveDirectory

Write-Host "`n=== Starting Attribute-to-AuxClass Assignment ==="

# 1. Get the Schema Naming Context
$schemaNC = (Get-ADRootDSE).schemaNamingContext
Write-Host "Schema path: $schemaNC"

# 2. Get all attributes whose adminDescription contains 'MLB' (case-insensitive),
#    retrieving both the lDAPDisplayName, adminDescription, and potential OID
$allMLBAttributes = Get-ADObject `
    -SearchBase $schemaNC `
    -LDAPFilter "(&(objectClass=attributeSchema)(adminDescription=*MLB*))" `
    -SearchScope Subtree `
    -Properties lDAPDisplayName, adminDescription, distinguishedName, attributeID

if (-not $allMLBAttributes) {
    Write-Warning "No attributes found with 'MLB' in adminDescription. Exiting."
    return
}

Write-Host "`nFound $($allMLBAttributes.Count) MLB-related attributes:"
foreach ($attrObj in $allMLBAttributes) {
    Write-Host "  - $($attrObj.lDAPDisplayName) => OID: $($attrObj.attributeID)"
}

# 3. Retrieve (or verify) the specified auxiliary class
$auxClass = Get-ADObject `
    -SearchBase $schemaNC `
    -LDAPFilter "(&(objectClass=classSchema)(cn=$AuxClassName))" `
    -Properties DistinguishedName, mayContain

if (-not $auxClass) {
    Write-Error "❌ Auxiliary class '$AuxClassName' not found in Active Directory schema."
    return
}

Write-Host "`n✅ Found auxiliary class '$AuxClassName': $($auxClass.DistinguishedName)"
$existingMayContain = @($auxClass.mayContain)

# 4. For each MLB attribute, add the attribute's OID to mayContain
foreach ($attrObj in $allMLBAttributes) {
    $attrName = $attrObj.lDAPDisplayName
    $attributeOID = $attrObj.attributeID

    Write-Host "Adding '$attrName' (OID: $attributeOID) to $AuxClassName.mayContain..."

    try {
        if ($existingMayContain -notcontains $attributeOID) {
            # Use the OID instead of Distinguished Name
            Set-ADObject -Identity $auxClass.DistinguishedName -Add @{mayContain = $attributeOID}
            Write-Host "   ✅ Added '$attrName' successfully."
            # Update our local copy to reflect the new addition
            $existingMayContain += $attributeOID
        } else {
            Write-Host "   ℹ️ Already present: '$attrName'."
        }
    }
    catch {
        Write-Error "❌ Failed to add '$attrName': $($_.Exception.Message)`nStackTrace: $($_.Exception.StackTrace)`nFull error: $($_ | Out-String)"
    }
}

# 5. Verify the updated list of mayContain
$updatedClass = Get-ADObject -Identity $auxClass.DistinguishedName -Properties mayContain
Write-Host "`nCurrent mayContain in '$AuxClassName':"
$updatedClass.mayContain | Sort-Object | ForEach-Object { Write-Host "   - $_" }

# 6. Link the AuxClass to the 'user' class
Write-Host "`n🔗 Linking '$AuxClassName' to the user structural class..."

$userClass = Get-ADObject `
    -SearchBase $schemaNC `
    -LDAPFilter "(&(objectClass=classSchema)(cn=user))" `
    -Properties DistinguishedName, auxiliaryClass

if (-not $userClass) {
    Write-Error "❌ User class not found in the schema."
    return
}

Write-Host "   ✅ Found user class: $($userClass.DistinguishedName)"

try {
    $currentAuxClasses = @($userClass.auxiliaryClass)
    if ($currentAuxClasses -notcontains $AuxClassName) {
        Write-Host "   Adding '$AuxClassName' to user class auxiliaryClass..."
        Set-ADObject -Identity $userClass.DistinguishedName -Add @{auxiliaryClass = $AuxClassName}
        Write-Host "   ✅ Successfully linked '$AuxClassName' to user class."
    } else {
        Write-Host "   ℹ️ '$AuxClassName' is already linked to user class."
    }
}
catch {
    Write-Error "❌ Failed to link '$AuxClassName' to user class: $($_.Exception.Message)`nStackTrace: $($_.Exception.StackTrace)`nFull error: $($_ | Out-String)"
    return
}

Write-Host "`n✅ Schema updates completed successfully!"