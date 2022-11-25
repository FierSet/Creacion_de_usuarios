function Creacion_usuarios
{ #param($numero)

    New-ADOrganizationalUnit "practica" -Path $raiz -ProtectedFromAccidentalDeletion $false
    $numusuarios = 0
    foreach($userlist in $datos)
    {
        $nombre = ($userlist.Name).Split(" ")
        $username = "$($nombre[0].Substring(0,1))$($nombre[1])"
        
        #_____________________________________________creacion de OU
        $OUCONTRY = "OU=$($userlist.Location),$raizOU"
        $OUdepartment = "OU=$($userlist.department),$OUCONTRY"
        $EXITEOUC = $(try {Get-ADOrganizationalUnit -Identity $OUCONTRY -ErrorAction Ignore}catch{}) -ne $null
        $EXITEOUD = $(try {Get-ADOrganizationalUnit -Identity $OUdepartment -ErrorAction Ignore}catch{}) -ne $null

        if(!$EXITEOUC){ New-ADOrganizationalUnit $userlist.Location -Path "$raizOU" -ProtectedFromAccidentalDeletion $false }

        if(!$EXITEOUD){ New-ADOrganizationalUnit $userlist.department -Path $OUCONTRY -ProtectedFromAccidentalDeletion $false }
        #_________________________________________fin creacion de OU
        
        #_________________________________________crea grupos
        $CNGROUPCOUNTY = "CN=$($userlist.Location)People,$raizOU"
        $CNGROUPDEPART = "CN=$($userlist.department)People,$raizOU"

        $EXISTEGC = $(try{Get-ADGroup -Identity $CNGROUPCOUNTY -ErrorAction Ignore}catch{}) -ne $null
        $EXISTEGD = $(try{Get-ADGroup -Identity $CNGROUPDEPART -ErrorAction Ignore}catch{}) -ne $null

        if(!$EXISTEGC)
        {
            New-ADGroup -Name "$($userlist.Location)People" -SamAccountName "$($userlist.Location)People" -GroupCategory Distribution -GroupScope Global  -DisplayName "$($userlist.Location)People" -Path $raizOU
        }
        if(!$EXISTEGD)
        {
            New-ADGroup -Name "$($userlist.department)People" -SamAccountName "$($userlist.department)People" -GroupCategory Security -GroupScope Global  -DisplayName "$($userlist.department)People" -Path $raizOU
        }
        #_____________________________________fin crea grupos
        
        #_________________verifica si el nombre usuario existe
        $userfilter = Get-ADUser -Filter "SamAccountName -eq '$username'"

        $i = 0;
        While($userfilter)
        {
          $i++
          $userfilter = Get-ADUser -Filter "SamAccountName -eq '$($username)$i'"
        }
        if($i -gt 0) { $username = "$username$i" }
        #______________fin verifica si el nombre usuario existe

        #_________________________________________________________verifiva la fecha de ingreso
        if((Get-Date $today) -ge (Get-Date $userlist.joinDate)){ $state = $true } 
        else { $state = $false }
        #_____________________________________________________fin verifiva la fecha de ingreso

        #_________________________________________________________________verifica la exigencia de la contraseña
        if(($userlist.department -eq "PMO") -or ($userlist.jobTitle -eq "Service Account")) { $paswex = $false } 
        else { $paswex = $true }
        #_____________________________________________________________fin verifica la exigencia de la contraseña

        #________________________________________________________________comprueba si debe expirar la contraseña
        if($userlist.jobTitle -eq "Service Account") { $expirepass = $true }
        else { $expirepass = $false }
        #____________________________________________________________fin comprueba si debe expirar la contraseña

        #__________________________________________________________________________________________Crea usuarios
        try
        {
            New-ADUser -Name $userlist.Name -GivenName "$($nombre[0])" -Surname "$($nombre[1])" -SamAccountName "$username" -Office $userlist.jobTitle -UserPrincipalName "$username.$domain" -Path $OUdepartment -AccountPassword $password -Enabled $state -ChangePasswordAtLogon:$paswex -PasswordNeverExpires $expirepass
            $numusuarios++
        }
        catch
        {Write-Output "Error: $($Error.ToArray())"}
        #______________________________________________________________________________________fin Crea usuarios

        #_____________________________________________________________________________________Asignacion de grupos
        Add-ADGroupMember "$($userlist.Location)People" $username
        Add-ADGroupMember "$($userlist.department)People" $username
        if($userlist.department -eq "Engineering") { Add-ADGroupMember "Administrators" $username }

        if($userlist.department -eq "Service Account") { Add-ADGroupMember "Server Operators" $username }
        #________________________________________________________________________________fin Asignacion de grupos 
        
        Write-Output "$username : $($userlist.Name) of $($userlist.jobTitle) is $($userlist.department) Domain: $username.$domain location $($userlist.Location) date $($userlist.joinDate)"
        
    }

    Write-Output "$numusuarios users create. All Complete"
}

function Deshacer_cambios
{ #param($numero)
        #Set-ADOrganizationalUnit -Identity $raizOU -ProtectedFromAccidentalDeletion $false
        Remove-ADOrganizationalUnit -Identity $raizOU -Recursive -Confirm
        Write-Output "All Done"
}

$Error.Clear()

$archivo = "Z:\ListaUsuarios.csv"

$datos = Import-Csv -Path $archivo -Delimiter ","
$today = Get-Date -Format "dd/MM/yyyy"

$domains = Get-ADDomain -Current LocalComputer
$domain = $domains.DNSRoot

$raiz = "DC=soa17140106,DC=com"
$raizOU = "OU=practica,$raiz"

$password = ConvertTo-SecureString "ITQ.soa2022" -AsPlainText -Force

Write-Output "Original"
Write-Output $datos | Format-Table

try
{
    Creacion_usuarios
    #Deshacer_cambios
}
catch
{
    Write-Output "Error: $($Error.ToArray())"
}

Write-Output "Se encontraron un total de $($Error.Count) Errores"