<#
This script will attempt to pull the primary user of a computer in AD from Intune. If the primary user is not yet set, the script detects the last logged on user, and sets this as the new primary user.

With this information, the script finds the organizational unit the user is in, and moves the computer to the corresponding OU. It then attaches the end user's name to the computer as a description.

Use the -live $true parameter to run live
.Example
UpdateOU_Description_v2.ps1
UpdateOU_Description_v2.ps1 -live $true
#>

Param(
    [Parameter(mandatory = $false)]
    [bool]$live
)

function Get-AuthToken {

    <#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $User
    )

    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

    $tenant = $userUpn.Host

    Write-Host "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null) {

        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null) {
        Write-Host
        Write-Host "AzureAD Powershell module not installed..." -f Red
        Write-Host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        Write-Host "Script can't continue..." -f Red
        Write-Host
        exit
    }

    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version

    if ($AadModule.count -gt 1) {

        $Latest_Version = ($AadModule | Select-Object version | Sort-Object)[-1]

        $aadModule = $AadModule | Where-Object { $_.version -eq $Latest_Version.version }

        # Checking if there are multiple versions of the same module found

        if ($AadModule.count -gt 1) {

            $aadModule = $AadModule | Select-Object -Unique

        }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

    $clientId = "TEMPCLIENTID"

    $redirectUri = "TEMPREDIRECTURI"

    $resourceAppIdURI = "https://graph.microsoft.com"

    $authority = "https://login.microsoftonline.com/$Tenant"

    try {

        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result

        # If the accesstoken is valid then create the authentication header

        if ($authResult.AccessToken) {

            # Creating header for Authorization token

            $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = "Bearer " + $authResult.AccessToken
                'ExpiresOn'     = $authResult.ExpiresOn
            }

            return $authHeader

        }

        else {

            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break

        }

    }

    catch {

        Write-Host $_.Exception.Message -f Red
        Write-Host $_.Exception.ItemName -f Red
        Write-Host
        break

    }

}

function Get-Win10IntuneManagedDevice {

    <#
.SYNOPSIS
This gets information on Intune managed devices
.DESCRIPTION
This gets information on Intune managed devices
.EXAMPLE
Get-Win10IntuneManagedDevice
.NOTES
NAME: Get-Win10IntuneManagedDevice
#>

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$deviceName
    )

    $graphApiVersion = "beta"

    try {

        if ($deviceName) {

            $Resource = "deviceManagement/managedDevices?`$filter=deviceName eq '$deviceName'"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value

        }

        else {

            $Resource = "Resource defined Here"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value

        }

    }
    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        throw "Get-IntuneManagedDevices error"
    }

}

####################################################

Function Get-AADUser() {

    <#
.SYNOPSIS
This function is used to get AAD Users from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any users registered with AAD
.EXAMPLE
Get-AADUser
Returns all users registered with Azure AD
.EXAMPLE
Get-AADUser -userPrincipleName user@domain.com
Returns specific user by UserPrincipalName registered with Azure AD
.NOTES
NAME: Get-AADUser
#>

    [cmdletbinding()]

    param
    (
        $userPrincipalName,
        $Property
    )

    # Defining Variables
    $graphApiVersion = "v1.0"
    $User_resource = "users"

    try {

        if ($userPrincipalName -eq "" -or $userPrincipalName -eq $null) {

            #$uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)"
            #(Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

        }

        else {

            if ($Property -eq "" -or $Property -eq $null) {

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$userPrincipalName"
                Write-Verbose $uri
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

            }

            else {

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$userPrincipalName/$Property"
                Write-Verbose $uri
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

            }

        }

    }

    catch {

        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        #break

    }

}

####################################################

Function  Get-IntuneDevicePrimaryUser {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceName
    )

    Try {
        $PrimaryUser = ($AllIntuneDevices | Where-Object { $_.devicename -eq $DeviceName } | Sort-Object -Descending -Property enrolledDateTime | Select-Object -First 1).userDisplayName
        $return = $PrimaryUser
    }
    Catch {
        Write-Error -Message "Problem retrieving info for device: [$DeviceName]. $_"
        $return = $false
    }

    return $return
}

function RetrieveLastLoggedInUser {

    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceName
    )

    Try {
        $Device = ($AllIntuneDevices | Where-Object { $_.devicename -eq $DeviceName })
        $LastLoggedInUserID = ($Device.usersLoggedOn[-1]).userId
        $AADUser = Get-AADUser -userPrincipalName $LastLoggedInUserID
        if (($null -eq $AADUser) -or ($AADUser -eq "")) {
            $return = $false
        }
        else {
            $return = $AADUser.displayName
        }
    }
    Catch {
        Write-Error -Message "Problem retrieving info for device: [$DeviceName]. $_"
        $return = $false
    }

    return $return

}

Write-Host
$domain = "@domain.com"
# Checking if authToken exists before running authentication
if ($global:authToken) {

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

    if ($TokenExpires -le 0) {

        Write-Host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        Write-Host

        # Defining User Principal Name if not present

        if ($User -eq $null -or $User -eq "") {

            $User = "$env:username$domain"
            #$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host
        }

        $global:authToken = Get-AuthToken -User $User
    }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if ($User -eq $null -or $User -eq "") {

        $User = "$env:username$domain"
        #$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"

        Write-Host
    }

    # Getting the authorization token
    $global:authToken = Get-AuthToken -User $User
}

# Get all Intune devices
$AllIntuneDevices = Get-Win10IntuneManagedDevice

# Define Name of Intune DEM account
$intunedemaccount = "Intune Device Enrollment Manager"

function Find-UserManager ($PrimaryUser) {
    $manager = (Get-ADUser -Filter {Name -eq $PrimaryUser} -Properties Manager).Manager
    $ManagerTitle = (Get-ADUser $manager -Properties Title).Title
    Return $ManagerTitle
}

#This function moves the computer to the correct OU
function Switch-ComputerOU ($PrimaryUser, $live, $computer, $ReadableName) {
    $testpath1 = "Test OU Path"
    $testpath2 = "Main OU Path"
    $testpath3 = "2nd OU Path"
    $testpath4 = "3rd OU Path"
    $testpath5 = "4th OU Path"
    $testpath6 = "5th OU Path"
    $testpath7 = "2nd Test OU Path"
    ## the following varialbe is to ensure that anyone in a specific department will be sent to the correct OU
    $testmanagertitle = "example", "example", "*example*"
    $userDepartment = (Get-ADUser -Filter {Name -eq $PrimaryUser} -Properties Department).Department
    If (!($userDepartment)) {
        $userDepartment = (Get-ADUser -Filter {DisplayName -eq $PrimaryUser} -Properties Department).Department
    }

    # Switch statement changes computer's OU based on associated user's department
    switch ($userDepartment) {
        "MultiLayerDepartment" {
            #Uses the manager's title in MultiLayerDepartment to find the correct OU
            $managerTitle = Find-UserManager ($PrimaryUser)
            If ($managerTitle -like "*example*") {
                "Moving $ReadableName to the Main OU Path...`n"
                If ($live -eq $true) {
                    Get-ADComputer $computer | Move-ADObject -TargetPath $testpath2
                    }
                    else {
                        Get-ADComputer $computer | Move-ADObject -TargetPath $testpath2 -whatif
                    }
            }
            elseif ($managerTitle -in $testmanagertitle) {
                "Moving $ReadableName to the 2nd OU Path...`n"
                If ($live -eq $true) {
                    Get-ADComputer $computer | Move-ADObject -TargetPath $testpath3
                    }
                    else {
                        Get-ADComputer $computer | Move-ADObject -TargetPath $testpath3 -whatif
                    }
            }
            elseif ($managerTitle -like "*EXAMPLE*") {
                "Moving $ReadableName to the 3rd OU Path...`n"
                If ($live -eq $true) {
                    Get-ADComputer $computer | Move-ADObject -TargetPath $testpath4
                    }
                    else {
                        Get-ADComputer $computer | Move-ADObject -TargetPath $testpath4 -whatif
                    }
            }
            elseif ($managerTitle -like "*EXAMPLE*") {
                "Moving $ReadableName to the 4th OU Path...`n"
                If ($live -eq $true) {
                    Get-ADComputer $computer | Move-ADObject -TargetPath $testpath5
                    }
                    else {
                        Get-ADComputer $computer | Move-ADObject -TargetPath $testpath5 -whatif
                    }
            }
            else {
                "Moving $ReadableName to the 5th OU Path...`n"
                if ($live -eq $true) {
                    Get-ADComputer $computer | Move-ADObject -TargetPath $testpath6
                    }
                    else {
                        Get-ADComputer $computer | Move-ADObject -TargetPath $testpath6 -whatif
                    }
                    Write-Host "Please make sure to move this computer to the correct OU inside of ITPMO`n"
            }
        }
         "Test Department" {
            Write-Host "Moving $ReadableName to the Test OU PATH...`n"
            If ($live -eq $true) {
            Get-ADComputer $computer | Move-ADObject -TargetPath $testpath1
            }
            else {
                Get-ADComputer $computer | Move-ADObject -TargetPath $testpath1 -whatif
            }
        }
        "Test Department 2" {
            Write-Host "Moving $ReadableName to the 2nd Test OU PATH`n"
            If ($live -eq $true) {
            Get-ADComputer $computer | Move-ADObject -TargetPath $testpath7
            }
            else {
                Get-ADComputer $computer | Move-ADObject -TargetPath $testpath7 -whatif
            }
        }
        Default {
            Write-Host "User $PrimaryUser does not have a valid department.`n"
        }
        
    }
}


    # Sets the OU path to Computers OU
    $ComputersOU = Get-ADComputer -Filter * -SearchBase "OU PATH"

    if ($ComputersOU.count -eq 0) {
        Write-Host "No computers present in the Computers OU"
    }
    # Loops through each computer in the OU
    ForEach ($Computer in $ComputersOU) {
        $ReadableName = $Computer.name
        $PrimaryUser = Get-IntuneDevicePrimaryUser -DeviceName $ReadableName
        #Write-Host $PrimaryUser
        # Sets Computer description based on Primary User
        If ($PrimaryUser -eq $null) {
            Write-Host "Device $ReadableName is not in Intune`n"
            continue
        }
            #When Primary User has a value, it will add to the description
            If ($PrimaryUser) {
                If ($live -eq $true) {
                Write-Host "Setting $ReadableName's description to $PrimaryUser"
                Set-ADComputer -Identity $Computer -Description $PrimaryUser
                }
                else {
                    Write-Host "Setting $ReadableName's description to $PrimaryUser"
                Set-ADComputer -Identity $Computer -Description $PrimaryUser -whatif
                }
            }
            #IF it does not, it will retrieve last logged on user and set to primary user
            else {
                $PrimaryUser = RetrieveLastLoggedInUser -DeviceName $ReadableName
                Write-Host "Checking last logged on user for Primary User..."
                If ($PrimaryUser) {
                    If ($live -eq $true) {
                    Write-Host "Setting $ReadableName's description to $PrimaryUser"
                    Set-ADComputer -Identity $Computer -Description $PrimaryUser
                    }
                    else {
                        Write-Host "Setting $ReadableName's description to $PrimaryUser"
                        Set-ADComputer -Identity $Computer -Description $PrimaryUser -whatif
                    }
                }
                else {
                    # If computer has not been logged into, will move onto next computer
                    Write-Host "Primary user has not been defined yet.`n"
                    continue
                }
            }
            Switch-ComputerOU $PrimaryUser $live $Computer $ReadableName
    }
