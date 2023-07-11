# Introduction 
This script will attempt to pull the primary user of a computer in AD from Intune. If the primary user is not yet set, the script detects the last logged on user, and sets this as the new primary user.

With this information, the script finds the organizational unit the user is in, and moves the computer to the corresponding OU. It then attaches the end user's name to the computer as a description.

# Getting Started
This script would need to be modified to fit the specific OU's of your organization. Make sure you have permissions in Active Directory and Intune to make these changes.

# Build and Test
Use the -live $true parameter to run live
.Example
UpdateOU_Description_v2.ps1
UpdateOU_Description_v2.ps1 -live $true
