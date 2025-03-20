#Requires -Version 7.0
#Requires -Modules ActiveDirectory

# Get the user class from the schema
$userClass = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter "objectClass -eq 'classSchema' -and name -eq 'user'" -Properties auxiliaryClass, objectClass

Write-Host "Current auxiliary classes for user object:"
if ($userClass.auxiliaryClass) {
    $userClass.auxiliaryClass | ForEach-Object { Write-Host "  - $_" }
} else {
    Write-Host "  No auxiliary classes currently assigned"
}

# Add auxMLB to the auxiliaryClass list
Write-Host "`nAdding auxMLB to user auxiliary classes..."
try {
    Set-ADObject -Identity $userClass.DistinguishedName -Add @{auxiliaryClass = "auxMLB"}
    Write-Host "✅ Successfully added auxMLB to user auxiliary classes"
}
catch {
    if ($_.Exception.Message -like "*The specified directory service attribute or value already exists*") {
        Write-Host "ℹ️ auxMLB is already assigned to user auxiliary classes"
    }
    else {
        Write-Error "❌ Failed to add auxMLB`: $_"
    }
}

# Verify the changes
Write-Host "`nVerifying auxiliary classes for user object:"
$updatedUserClass = Get-ADObject -Identity $userClass.DistinguishedName -Properties auxiliaryClass
if ($updatedUserClass.auxiliaryClass) {
    $updatedUserClass.auxiliaryClass | ForEach-Object { Write-Host "  - $_" }
} else {
    Write-Host "  No auxiliary classes assigned"
}

# Now attach auxMLB to the user structural class
Write-Host "`nAttaching auxMLB to user structural class..."
try {
    # Get current object classes of the user class
    $currentClasses = $userClass.objectClass
    
    # Add auxMLB to the list if not already present
    if ($currentClasses -notcontains "auxMLB") {
        # Create a new array with all classes including auxMLB
        $newClasses = @()
        $newClasses += $currentClasses
        $newClasses += "auxMLB"
        
        # Use DirectoryEntry to modify the objectClass
        $de = [ADSI]"LDAP://$($userClass.DistinguishedName)"
        $de.Properties["objectClass"].Value = $newClasses
        $de.SetInfo()
        
        Write-Host "✅ Successfully attached auxMLB to user structural class"
    } else {
        Write-Host "ℹ️ auxMLB is already attached to user structural class"
    }
    
    # Verify the changes
    $updatedUserClass = Get-ADObject -Identity $userClass.DistinguishedName -Properties objectClass
    Write-Host "`nVerifying user structural class object classes:"
    $updatedUserClass.objectClass | ForEach-Object { Write-Host "  - $_" }
}
catch {
    Write-Error "❌ Failed to attach auxMLB to user structural class`: $_"
}

# Verify that the user class can now use MLB attributes
Write-Host "`nVerifying MLB attributes are available for user objects..."
try {
    $testUser = New-ADUser -Name "TestMLBUser" -UserPrincipalName "testmlbuser@$((Get-ADDomain).DNSRoot)" -Path "CN=Users,$((Get-ADDomain).DistinguishedName)" -Enabled $false -PassThru
    Write-Host "✅ Successfully created test user with MLB attributes"
    
    # Try to set an MLB attribute
    Set-ADUser -Identity $testUser -Add @{playerID = "test123"}
    Write-Host "✅ Successfully set MLB attribute on test user"
    
    # Clean up test user
    Remove-ADUser -Identity $testUser -Confirm:$false
    Write-Host "✅ Cleaned up test user"
}
catch {
    Write-Error "❌ Failed to verify MLB attributes`: $_"
} 