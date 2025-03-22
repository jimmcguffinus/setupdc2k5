#requires -Modules ActiveDirectory

# First, let's define the function
Function New-42OUByDN {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$New_OU_DN
    )
    
    # A regex to split the DN, taking escaped commas into account
    $DNRegex = '(?<![\\]),'
    
    # Array to hold each component
    $MissingOUs = @()
    
    # We'll need to traverse the path, level by level, let's figure out the number of possible levels 
    $Depth = ($New_OU_DN -split $DNRegex).Count
      
    # Step through each possible parent OU
    for ($i = 1; $i -le $Depth; $i++) {
        $NextOU = ($New_OU_DN -split $DNRegex, $i)[-1]
        if ($NextOU.IndexOf("OU=") -ne 0 -or [ADSI]::Exists("LDAP://$NextOU") ) {
            #Write-Host "$NextOU Exists"
            Continue
        }
        else {
            # OU does not exist, remember this for later
            $MissingOUs += $NextOU
        }
    }
    
    # Reverse the order of missing OUs, we want to create the top-most needed level first
    [array]::Reverse($MissingOUs)
    
    # Prepare common parameters to be passed to New-ADOrganizationalUnit
    $PSBoundParameters.Remove('New_OU_DN') | Out-Null
    
    # Now create the missing part of the tree, including the desired OU
    foreach ($OU in $MissingOUs) {
        $newOUName = (($OU -split $DNRegex, 2)[0] -split "=")[1]
        $newOUPath = ($OU -split $DNRegex, 2)[1]
        New-ADOrganizationalUnit -Name $newOUName -Path $newOUPath -ProtectedFromAccidentalDeletion $false @PSBoundParameters
    }
}

# Get domain DN
$DomainDN = (Get-ADDomain).DistinguishedName

# Create the OU structure
$MLBOUDN = "OU=MLB,$DomainDN"
$PlayersOUDN = "OU=Players,$MLBOUDN"

Write-Host "Creating MLB OU structure..."
New-42OUByDN -New_OU_DN $PlayersOUDN

Write-Host "✅ MLB OU structure created"
Write-Host "MLB OU: $MLBOUDN"
Write-Host "Players OU: $PlayersOUDN" 