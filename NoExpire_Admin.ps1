#Thanks Microsoft
#https://blogs.technet.microsoft.com/poshchap/2016/08/12/security-focus-one-liner-ad-privileged-user-and-password-doesnt-expire/

#Loop through each domain in the forest
(Get-ADForest).Domains | ForEach-Object {

    #Find objects configured with admincount = 1 and password set to not expire
    $Findings = Get-ADUser -Filter {(AdminCount -eq 1) -and (PasswordNeverExpires -eq $true)} -Server $_ -ErrorAction SilentlyContinue

    #If $Findings is populated, export to CSV
    if ($Findings) {

        #Get short domain name
        $DomainName = (Get-ADDomain -Identity $_).Name.ToUpper()
        $Findings | Export-Csv -Path ".\$($DomainName)_ADMIN_AND_DONT_EXPIRE_PASSWORD.csv"

    }   #End of if ($Findings)

}   #End of ForEach-Object
