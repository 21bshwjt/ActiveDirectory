#How to find Users from an OU using ADSI?
$test =
[adsi] "LDAP://localhost:389/ou=test,dc=contoso,dc=COM"
$searcher = [adsisearcher] $test
$searcher.Filter = '(objectClass=User)'
$searcher.FindAll() 

#All AD Users All attrs...
Get-ADUser -F * -PR * | Export-Csv Usersreports.csv -NoTypeInformation

#How to find Locked out accounts?
search-adaccount -u -l | ft name,lastlogondate -auto

#To unlock an account
Unlock-ADAccount -Identity BBISWAJIT

#Finding the Lockout Events

#Windows 2008
Get-EventLog -log Security | ? EventID -EQ 4740
#Windows 2003
Get-EventLog -log Security | ? EventID -EQ 644

#Find some specific attributes for an OU users
get-aduser -f * -Searchbase "ou=powershell,dc=contoso,dc=com" -pr SamAccountName,PasswordExpired,whenChanged,UserPrincipalName

#Find some specific attributes using input file
get-content c:\users.txt | get-aduser -pr SamAccountName,PasswordExpired,whenChanged,UserPrincipalName

#How to reset the passwords for some specific users
get-content c:\users.txt | get-aduser | Set-ADAccountPassword -NewPassword (ConvertTo-SecureString -AsPlainText monster@me123 -Force)

#How to update the manager field for bulk users?
get-content c:\users.txt | get-aduser | Set-ADUser -Manager "Biswajit"

#How to update "ProfilePath","homeDrive" & "HomeDirectory" based on a input file?
Get-Content users.txt | ForEach-Object {
  Set-ADUser -Identity $_ -ProfilePath "\\WIN-85IOGS94Q68\profile\$_" -homedrive "Y:" -homedirectory "\\WIN-85IOGS94Q68\netshare\$_"
}

#Find Users exist in AD or Not?
$users = get-content c:\users.txt
foreach ($user in $users) {
$User = Get-ADUser -Filter {(samaccountname -eq $user)}
If ($user -eq $Null) {"User does not exist in AD ($user)" }
Else {"User found in AD ($user)"}
}

#Find users are enabled and have E-Mail and Homedirectory and PasswordExpired -eq false)}
Get-ADUser -Filter {(enabled -eq $true) -and (EmailAddress -like "*") -and (Homedirectory -like "*") -and (PasswordExpired -eq $false)}

#Also finding the Groupmembership.
Get-ADUser -Filter {(enabled -eq $true) -and (EmailAddress -like "*") -and (Homedirectory -like "*") -and
(PasswordExpired -eq $false) -and (MemberOf -eq "CN=rock2,OU=win7,DC=Jaihanuman,DC=net")}

#ProtectedFromAccidentalDeletion for all the users
Get-ADObject -filter {(ObjectClass -eq "user")} | Set-ADObject -ProtectedFromAccidentalDeletion:$true

# How to find the users property using ADSI.
$users1=[ADSI]"LDAP://cn=copy,cn=users,dc=contoso,dc=com"
$users1 | select *
#search-adaccount (Accounts Disable,inactive)
search-adaccount (Accounts Disable,inactive)
search-adaccount -u -accountd -searchb "ou=test,dc=contoso,dc=com"
search-adaccount -u -accountd
search-adaccount -u -accounti -t "90"
search-adaccount -u -accounti -da "28 feb 2013"

# Enable Bulk AD user accounts based on a  input file
Cat c:\users.txt | get-aduser | Enable-ADAccount
#Disabled Bulk AD user accounts based on a  input file
Cat c:\users.txt | get-aduser | Disable-ADAccount

# Add proxyAddresses
Import-Csv D:\Scripts\users.csv | Foreach 
    { 
        Get-ADUser $_.samaccountname | Set-ADUser -Add @{proxyAddresses = ($_.proxyaddress)} 
    } 
#Clone Group-membership
(Get-ADUser "Source_Account" -Properties MemberOf).MemberOf | %{Add-ADGroupMember -Identity $_ -Members "New_Account"}

#Get the OS from a specific OU
Get-ADComputer -filter * -SearchBase "OU=Member Servers,DC=contoso,DC=biz" -Properties * | Select-Object SamAccountName,OperatingSystem

#Last 15 days password Expiry with Location
Get-ADUser -filter * -SearchBase "OU=users,DC=contoso,DC=biz"  -properties PasswordNeverExpires,msDS-UserPasswordExpiryTimeComputed,office | 
where {$_.enabled -eq $true -and $_.PasswordNeverExpires -eq  $False} | 
select Name,office,@{Name="ExpiryDate";Expression={([datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")).DateTime}} | 
where {($_.ExpiryDate | get-date)  -gt (get-date) -and ($_.ExpiryDate | get-date) -lt (get-date).adddays(15) }

#Search Server by a Role in a Domain
Get-ADComputer -Filter "OperatingSystem -like 'Windows Server*'" | 
ForEach-Object {if ((Get-WindowsFeature -ComputerName $_.Name -Name ADCS-Device-Enrollment -ErrorAction SilentlyContinue).Installed) {$_.Name}}

#List of All Privillaged Users-Domainwise
Get-aduser -ldapfilter "(objectcategory=person)(admincount=1)" -Properties * |  
Select samaccountname,displayname,Enabled,Lastlogondate -ErrorAction silentlycontinue |  
Export-Csv -Path "C:\scripts\All_users_list.csv" -NoTypeInformation

#Update/Modify Manager attr. of Bulk AD users using CSV
$Users = Import-csv c:\Users.csv
foreach ($User in $Users)
 {
 Set-ADUser $User.SamAccountName -Manager $User.Newmanager
 }

#Get SMB1 & SMB2 Details from bulk servers 
Invoke-Command -ComputerName (Get-Content c:\DCs.txt) -ScriptBlock {  
[pscustomobject]@{ 
PSComputerName = Get-SmbServerConfiguration | Select-Object -ExpandProperty PSComputerName 
SMB1 = Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol 
SMB2 = Get-SmbServerConfiguration | Select-Object -ExpandProperty  EnableSMB2Protocol  
 
 
} 
    }
