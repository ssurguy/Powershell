<#
.Synopsis
Assign Teams Number and Signature

.Description
Choose the signature group and add user to said group.
Assigns the first available teams number, prioritizing the numbers beginning with 770.
Adds the number to the Telephone Number field in AD. 

.Example
.\AssignTeamsNumber.ps1 -User XXXXXX

Updated: 8/17/2023

#>

#Requires -Modules @{ ModuleName="MicrosoftTeams"; ModuleVersion="5.5.0"} 

Param (

    [Parameter(mandatory = $true)]
    [String]$User

)

#Function to add the phone number to the OfficePhone field in AD
function AddNumberToAD ($User, $Number)
{

    #formats the number in the standard format for our AD
    $Format = "###-###-####"
    $ADNumber = "{0:$Format}" -f [int64] ($Number.Substring(2,10))
    #Sets the formatted number to the user
    Set-ADUser -Identity $User -OfficePhone $ADNumber


}


# Try Catch statement that collects the UPN
try {

    #Tries to receive the UPN based on the GASID input
    $UPN = (Get-ADUser $User -Properties UserPrincipalName -ErrorAction Stop).UserPrincipalName

}

# Catch statement if person running script is on the network with server down exception
catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {

    Write-Host "Not on the company network/VPN"
    exit

}

#Catch statement if User input is not found in AD with the AD ID not found exception
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
 
    Write-Host "User not found in AD"
    exit

}

#catch for any other thrown errors
catch {

    $PSItem.Exception
    exit

}

#collects the display name of the user and puts it in the $Name variable
$Name = (Get-ADUser $User -Properties DisplayName).DisplayName


#Try catch to connect to the Microsoft Teams module
try {

    Connect-MicrosoftTeams -ErrorAction Stop | Out-Null

}

#Catches for any errors while connecting
catch {

    Write-Host "Could not connect to Teams/O365, please review the error:"
    $PSItem.Exception
    exit

}

# sets array of all teams numbers and sorts them in descending order. The array includes the numbers and assignment status
$NumbersArray = Get-CsPhoneNumberAssignment -Top 1000 | Sort-Object -Property @{Expression = "TelephoneNumber"; Descending = $true} | select TelephoneNumber,PstnAssignmentStatus

#Loops through each phone number until available number is found
foreach ($Assignment in $NumbersArray) {

    #If the number is currently unasigned, it will assign to the user
    if ($Assignment.PstnAssignmentStatus -eq "Unassigned") {

        $Number = $Assignment.TelephoneNumber

        #try catch to check for PIM status
        try {

            #Assigns the number to the user with a CallingPlan and with the Example location
            Set-CsPhoneNumberAssignment -Identity $UPN -PhoneNumber $Number -PhoneNumberType CallingPlan -LocationID ExampleLocation -ErrorAction Stop | Out-Null
    
            }
    
        #Exception sees if runner was PIM'd up when running script
        catch [Microsoft.Teams.ConfigAPI.Cmdlets.Generated.Runtime.RestException`1[Microsoft.Teams.ConfigAPI.Cmdlets.Generated.Models.ISkypeTelephoneNumberMgmtErrorResponse]]{
                
            Write-Host "PIM up chump"
                exit

            }

        #Wait 5 seconds before checking to see if it was assigned
        Start-Sleep -Seconds 5

        #Grabs the status. if assigned, it will write to the console with the user name and number
        $Status = Get-CsPhoneNumberAssignment -AssignedPstnTargetId $UPN
        if ($Status.PstnAssignmentStatus -eq "UserAssigned") {

            AddNumberToAD -User $User -Number $Number
            Write-Host "$Name has been assigned the number $Number"

        }

        #If the status is still unassigned, it will write to the console that the assignment was unsuccesful
        else {

            Write-Host "Assignmment unsuccesful"

        }


        Disconnect-MicrosoftTeams
        exit

    }

}

Disconnect-MicrosoftTeams
#If each phone number is assigned, it will write that none are available
Write-Host "No numbers available!"
