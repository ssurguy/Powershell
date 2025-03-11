    <#
    This script is to set the corresponding registry key for VHDLocations for AVDs.
    uses host name to determine which address to use

    4/9/2024
#>

$exitCode = 0
$win32appScriptName = "FSLogixForAVDs" #Specifies the script name of the win32 app deployment to ensure detection matches if installed via remediation instead of standard deployment
if (![System.Environment]::Is64BitProcess) {
    # start new PowerShell as x64 bit process, wait for it and gather exit code and standard error output
    $sysNativePowerShell = "$($PSHOME.ToLower().Replace("syswow64", "sysnative"))\powershell.exe"

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $sysNativePowerShell
    $pinfo.Arguments = "-ex bypass -file `"$PSCommandPath`""
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.CreateNoWindow = $true
    $pinfo.UseShellExecute = $false
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null

    $exitCode = $p.ExitCode

    $stderr = $p.StandardError.ReadToEnd()

    if ($stderr) { Write-Error -Message $stderr }
}
else {
    # start logging to C:\Windows\Logs folder in file "scriptname + timestamp".log
    $logtimestamp = Get-Date -Format s | ForEach-Object { $_ -replace ":", "." }
    $logpath = "$env:SystemRoot\Logs\$($(Split-Path $PSCommandPath -Leaf).ToLower().Replace(".ps1","_$($logtimestamp)")).log"
    Start-Transcript -Path $logpath | Out-Null

    }

    $path = "Software\FSLogix\Profiles"
    $HKLM= "HKLM:\"

    $keyexists = Test-Path -path $HKLM$path

    if ($keyexists -eq $false) {

        #testing path to FSLogix in registry
        $keyexists2 = Test-Path -path $HKLM"Software\FSLogix"

        if ($Keyexists2 -eq $false) {

            #create key for FSLogix if not present
            New-Item -path $HKLM"Software\FSLogix"

        }

        #create key for Profiles if not present
        New-Item -path $HKLM$path

    }

    
    $path = "Software\FSLogix\Apps"

    $keyexists = Test-Path -path $HKLM$path

    if ($keyexists -eq $false) {

        #create key for Apps if not present
        New-Item -path $HKLM$path

    }

    #function to set the vhd location value
function set-VHDLocations ($value, $path, $HKLM) {


    $name = "VHDLocations"
    #testing path to profiles in registry

    try {
        #tests to see if property exists    
        Get-ItemPropertyValue -path $HKLM$path -name $name -ErrorAction Stop
        #sets VHDLocation if if it already exists
            Set-ItemProperty -path $HKLM$path -name $name -value $value
            Write-Host "`n"
    
    }
    
    catch {
        #if does not exist, create property and set to 2 (disabled)
        Write-Host "VHDLocations does not exist, creating property"
        New-ItemProperty -path $HKLM$path -propertyType MultiString -name $name -value $value
        Write-Host "`n"
    
    }

}
  
function set-OtherProperties ($path, $HKLM, $property, $value) {

    #testing path to profiles in registry

    try {
        #tests to see if property exists    
        Get-ItemPropertyValue -path $HKLM$path -name $property -ErrorAction Stop
        #sets VHDLocation if if it already exists
        Write-Host "$Property already exists, setting value to $value"
            Set-ItemProperty -path $HKLM$path -name $property -value $value
            Write-Host "`n"
    
    }
    
    catch {
        #if does not exist, create property and set to 2 (disabled)
        Write-Host "$property does not exist, creating property"
        New-ItemProperty -path $HKLM$path -propertyType DWord -name $property -value $value
        Write-Host "`n"
    
    }

}

    $path = "Software\FSLogix\Profiles"

    $hostname = (Get-ComputerInfo -Property CSName).CSName

    #sets vhdlocation value based on the hostname of the AVD
switch -Wildcard ($hostname) {
    "Example-1*" {

        set-vhdlocations -Value "\\FSLogixProfiles-Path" -path $path -HKLM $KHLM

    }
    "Example-2*" {

        set-vhdlocations -Value "\\FSLogixProfiles-Path" -path $path -HKLM $KHLM

    }
    "Example-3*" {

        set-vhdlocations -Value "\\FSLogixProfiles-Path" -path $path -HKLM $KHLM

    }
    "Example-4*" {

        set-vhdlocations -Value "\\FSLogixProfiles-Path" -path $path -HKLM $KHLM

    }
    "Example-5*" {
 
        set-vhdlocations -Value "\\FSLogixProfiles-Path" -path $path -HKLM $KHLM

    }
    "Example-6*" {

        set-vhdlocations -Value "\\FSLogixProfiles-Path" -path $path -HKLM $KHLM

    }
    "Example-6*" {

        set-vhdlocations -Value "\\FSLogixProfiles-Path" -path $path -HKLM $KHLM

    }
}

$path = "Software\FSLogix\Profiles"

#runs set properties function setting DeleteLocalProfileWhenVHDShouldApply to 1
$value = 1
$property = "DeleteLocalProfileWhenVHDShouldApply"
set-OtherProperties -path $path -HKLM $HKLM -property $property -Value $value

#runs set properties function setting Enabled to 1
$property = "Enabled"
set-OtherProperties -path $path -HKLM $HKLM -property $property -Value $value

#runs set properties function setting SizeinMBs to 100000
$value = 100000
$property = "SizeInMBs"
set-OtherProperties -path $path -HKLM $HKLM -property $property -Value $value

$path = "Software\FSLogix\Apps"

#runs set properties function setting CleanupInvalidSessions to 1
$value = 1
$property = "CleanupInvalidSessions"
set-Otherproperties -path $path -HKLM $HKLM -property $property -Value $value

#runs set properties function setting RoamRecycleBin to 1
$property = "RoamRecycleBin"
set-Otherproperties -path $path -HKLM $HKLM -property $property -Value $value


#creation and assignment of the registry check for detection methods
$Key = "HKEY_LOCAL_MACHINE\Software\GasSouthServiceDesk\$win32appScriptName\v1.0"
$NOW = Get-Date -F s


If ($exitCode -eq "0") {
    [microsoft.win32.registry]::SetValue($Key, "Success", $NOW)
}

else {
    [microsoft.win32.registry]::SetValue($Key, "Failure", $NOW)
    [microsoft.win32.registry]::SetValue($Key, "Error Code", $exitCode)
}



    Stop-Transcript | Out-Null





exit $exitCode