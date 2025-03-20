# Define file paths
$schemaFile = "C:\gh\setupdc2k5\schema\schema.csv"
$logFile = "C:\gh\setupdc2k5\logs\ldifde_log.txt"
$tempLdif = "C:\gh\setupdc2k5\temp.ldif"

# Read schema CSV with attribute types
$schema = Import-Csv -Path $schemaFile

# Define target users (only baseball players in OU=Players)
$users = Get-ADUser -Filter * -SearchBase "OU=Players,OU=MLB,DC=mlb,DC=dev" -Properties *

# Clear old log
"Starting baseball attribute updates at $(Get-Date)" | Set-Content $logFile

# Helper function to get appropriate default value based on attribute type and name
function Get-DefaultValue {
    param(
        [string]$attrName,
        [string]$attrType
    )
    
    # Handle based on schema type first
    switch ($attrType) {
        "Integer" { return "0" }
        "MultiValue" { 
            # Special handling for known multi-value attributes
            switch -Wildcard ($attrName) {
                "franchID" { return "{ATL,ML1}" }
                "name" { return "{Aaron,Hank}" }
                "park-alias" { return "{Fulton County Stadium}" }
                "teamID*" { return "{ATL}" }
                default { return "{TBD}" }
            }
        }
        default {
            # Fallback to name-based defaults for unknown types
            switch -Wildcard ($attrName) {
                "notes" { return "Historical record pending verification" }
                "country" { return "USA" }
                "state" { return "GA" }
                "city" { return "Atlanta" }
                "*Win" { return "N" }
                default { return "0" }
            }
        }
    }
}

# Process each user
foreach ($user in $users) {
    $dn = $user.DistinguishedName
    "Processing player: $dn" | Add-Content -Path $logFile
    Write-Host "Processing player: $($user.Name)" -ForegroundColor Cyan

    # Process each attribute from the schema
    foreach ($attr in $schema) {
        $attrName = $attr.AttributeName
        $attrType = $attr.AttributeType
        
        # Skip if attribute name is empty or system attribute
        if ([string]::IsNullOrWhiteSpace($attrName) -or 
            $attrName -in @("ObjectClass", "ObjectGUID", "DistinguishedName")) { 
            continue 
        }

        # Check if the attribute is missing or empty
        if (-not $user.$attrName) {
            Write-Host "  Adding attribute: $attrName ($attrType)" -ForegroundColor Yellow
            
            # Get appropriate default value based on type
            $defaultValue = Get-DefaultValue -attrName $attrName -attrType $attrType
            
            # Generate LDIF content
            $ldifContent = @"
dn: $dn
changetype: modify
add: $attrName
$attrName`: $defaultValue
-
"@
            # Write LDIF file
            $ldifContent | Set-Content -Path $tempLdif -Encoding ASCII

            # Apply LDIF update
            $result = & ldifde -i -f $tempLdif -j . -v 2>&1
            $resultStr = $result -join "`n"

            # Log result with more detail
            if ($resultStr -match "Entry modified successfully") {
                "SUCCESS: Added $attrName ($attrType) = $defaultValue" | Add-Content -Path $logFile
                Write-Host "    Success!" -ForegroundColor Green
            } else {
                "FAILED: $attrName ($attrType) with value: $defaultValue - Error: $resultStr" | Add-Content -Path $logFile
                Write-Host "    Failed." -ForegroundColor Red
            }
        }
    }
}

Write-Host "`nProcessing complete. Check the log at: $logFile" -ForegroundColor Cyan
