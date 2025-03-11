<#     
 Detect-FSLogixForAVDs.ps1
        This script is for the corresponding remediation for FSLogixForAVDs.ps1
    checks for the Registry key created by the script.
    then checks all other keys relating to FSLogix.
#>

function DoesEntryExist {
    Param(
        [String]$RegPath,
        [String]$Property
    )

    #tests the registry path and returns false if not found. will exit 1
$pathexists = test-path $regPAth

if ($pathexists -eq $true) {

   try { 
    
    #attempts to get the property based off the name after confirming path exists. returns true and will continue script if exists
    get-itemproperty -path $regpath -name $property -erroraction stop
    return "true"

   }

   catch {

    #false if property couldnt be found, exits 1
    return "false"

   }

}
else {

    #false if path couldnt be found, exits 1
    return "false"
}
}

function Test-NeedRemediation ($ExtInstalled, $regPath, $Entry) {
 
try {

    if ($ExtInstalled) {
        try {
            $EntryCheck = DoesEntryExist $regPath $Entry
        }
        catch {
            #Intune will remediate with Exit Code 1
     
            Write-Host "Detection failed, needs remediation"
            exit 1
        }
        if ($EntryCheck -eq "True") {
                #Detection check successful, Intune will report success with Exit Code 0
                Write-Host "$entry property set"
        }
        else {
            #Intune will remediate with Exit Code 1
            Write-Host "$Entry is missing"
            Write-Host "Detection failed, needs remediation"
            exit 1
        }
    }
}

catch {
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
    exit 1
}

}
#Defining variables
$regpath = "HKLM:\Software\FSLogix\Profiles"

$regPathKeyDetection = "KeyPath"

    #Test if Intune registry detection path exist, if it doesn't, exit 0 as not applicable.
    If (!(Test-Path $regPathKeyDetection)) {
        Write-Host "Intune registry detection check not present.. exit as not applicable"
        exit 0
    }
    try {
        $ExtInstalled = Get-ItemPropertyValue -Path "KeyPath" -Name Success
    }
    catch {
        Write-Host "Intune registry detection check not present.. exit as not applicable"
        exit 0
    }

    #sets corresponding property names and paths for each property being checked
    $property = "DeleteLocalProfileWhenVHDShouldApply"
    Test-NeedRemediation -extInstalled $extInstalled -regpath $regpath -Entry $property

    $property = "Enabled"
    Test-NeedRemediation -extInstalled $extInstalled -regpath $regpath -Entry $property

    $property = "VHDLocations"
    Test-NeedRemediation -extInstalled $extInstalled -regpath $regpath -Entry $property

    $property = "SizeInMBs"    
    Test-NeedRemediation -extInstalled $extInstalled -regpath $regpath -Entry $property

    $regpath = "HKLM:\Software\FSLogix\Apps"

    $property = "CleanupInvalidSessions"
    Test-NeedRemediation -extInstalled $extInstalled -regpath $regpath -Entry $property

    $property = "RoamRecycleBin"
    Test-NeedRemediation -extInstalled $extInstalled -regpath $regpath -Entry $property

    #if script survives through the guantlet, all are present, return 0 for success
    Write-Host "Success! all properties are present."
    exit 0