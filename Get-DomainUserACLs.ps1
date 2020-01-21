#
# Domain User ACL Check v1.0
# Todos: Wrap in funtion
# Auth: Joe Stahl
#

cls

# Get list of domains
$domains = (Get-ADForest).domains

# Set Var for PSDrive loop
$i = 1

# Loop through domains found
foreach($domain in $domains){

    #Add PSDrive for each new domain being checked
    New-PSDrive -name AD$($i) -PSProvider ActiveDirectory -Server $domain -Root "//RootDSE/"


    Write-Host "`n`nChecking in the $($domain)..." -ForegroundColor Yellow

    # Clear Var and get selected domain list of users
    $users = $null
    $users = Get-ADUser -Server $domain -Filter * <#{Enabled -eq $true}#> -Properties Description | select Name, DistinguishedName, samaccountname, enabled, Description

    Write-Host "Users in domain: $($users.count)" -ForegroundColor Green

    # Create Var for progress bar
    $u = 0

    # Loop through users in domain
    foreach ($user in $users){
        
        # Add 1 to Var for each user completed
        $u++

        #Run ACL Report on AD for domain User, save into file, print to screen, clear report Var
        $results = (Get-Acl "AD$($i):$(($user).DistinguishedName)").Access | ? {($_.IsInherited -EQ $false) -and ($_.ActiveDirectoryRights -eq  "GenericAll") -and ($_.IdentityReference -ne "NT AUTHORITY\SYSTEM") -and ($_.IdentityReference -ne "S-1-5-32-548") -and ($_.IdentityReference -notlike "*\Domain Admins")} | select @{l="Username";e={$($user.samaccountname)}}, @{l="DisplayName";e={$($user.Name)}}, IdentityReference, AccessControlType, ActiveDirectoryRights, IsInherited, @{l="Description";e={$($user.Description)}}, @{l="Domain";e={$($domain)}}
        $results | Export-Csv -NoTypeInformation -Append -Path "c:\dos\full-AuthUsers-Report.csv"
        $results | format-table
        $results = $null

        # Niffty Progress Bar
        $percentComplete = ($u / $users.count) * 100
        Write-Progress -Activity "Checking $($domain) for ACLs on $($users.count) user objects..." -Status "$($u): Checking ACL on $($user.samaccountname)" -PercentComplete $percentComplete
        }

    # PSDrive cleanup
    Remove-PSDrive -Name AD$($i)

    # Add one to domain count
    $i = $i + 1
        
    }