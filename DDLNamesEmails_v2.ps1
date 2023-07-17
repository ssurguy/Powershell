## This script returns the names and emails of a given dynamic distribution list and exports as an excel spreadsheet.

<# Example for running
    DDLNamesEmails -emailAddress "blahblah@gassouth.com"
#>

Param (
    [Parameter(Mandatory=$true)]
    [string]$emailAddress
)

function CreateXLSX($listName) {
    $Path = "C:\Temp"
    # Grab the newest DDLNamesEmails CSV file in the Temp directory
    $CSVFile = Get-ChildItem -Path $Path -Filter "*$listName*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    # Generate XLSX filename based on the filename of the CSV + a datestamp
    $XLFile = $CSVFile.FullName.Replace("csv", "xlsx")
    # Start an Excel application
    $ExcelProc = New-Object -com excel.application
    # Open the workbook
    #$ExcelWB = $ExcelProc.Workbooks.Open($CSVFile.FullName)
    $ExcelWB = $ExcelProc.Workbooks.Open($CSVFile.FullName)
    #Ref = https://docs.microsoft.com/en-us/office/vba/api/excel.xlfileformat
    # Save the newly modified CSV to a XLSX
    $result = $ExcelWB.SaveAs($XLFile, 51)
    # Close the workbook
    $result = $ExcelWB.Close($false)
    # Close Excel
    $result = $ExcelProc.Quit()
    $XLFile
}

#function to check if Dynamic Distro List exists
function Test-DDL {

    Param (
    [Parameter(Mandatory=$true)]
    [string]$emailAddress
)

    try {
        #checks to see if group exists, sends to catch if not
        Get-DynamicDistributionGroup -Identity $emailaddress -ErrorAction Stop | Out-Null
        return $true

    }

    catch {

        return $false

    }

}

#connects to Exchange
Connect-ExchangeOnline -ShowBanner:$false

#runs DDL check function
$testResult = Test-DDL -emailAddress $emailaddress


#if false, shows no list found and ends script
if ($testResult -eq $false) {

    Write-Host "No list found."
    exit

}

#if true, set list variable to the dynamic distro list
else {

    $list = Get-DynamicDistributionGroup -Identity $emailaddress

}

#sets variable listname to the DDL group name
$listName = $list.Name

$Path = "C:\Temp"
$filePath = $Path + "\" + $listName + "_"

#Force creation of Temp path directory if it doesn't exist.
If (!(Test-Path $path)) {

    New-Item -ItemType Directory -Force -Path $path

}

$file = "$filePath$(Get-Date -f yyyy-MM-dd-HH_mm_ss).csv"

# Get the email addresses and display names of the members and put into members array

    $members = Get-Recipient -RecipientPreviewFilter $list.RecipientFilter

# for each that runs through each entity in the members array, and adds their names and emails to the CSV
foreach ($member in $members) {
    #Declare an empty array for the names and emails
    $memberinfo = "" | Select-Object Name, Email
    $memberinfo.Name = $member.DisplayName
    $memberinfo.Email = $member.PrimarySmtpAddress

    #attach the above info to the CSV
    $memberinfo | Export-Csv  -Append -Path $file -NoTypeInformation
}

#Calls function to create the XLSX file
CreateXLSX -listName $listName

#Deletes the temporary CSV file created
Remove-Item -Path $file -Force