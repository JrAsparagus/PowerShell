function Get-ADDuplicateUsers 
{
<# 

.SYNOPSIS 
  Function to find duplicate users. This function requires a working Active Directory Powershell Module.
  
.NOTES
	CreatedBy: Mark Braker
	CreatedOn: 20JAN2015
	
.LINK
   http://technet.microsoft.com/en-us/library/ee617195.aspx

.PARAMETER SamAccountName


.DESCRIPTION
  Function that takes an array of user login names and returns Active Directory users that are duplicated in the current forest

.EXAMPLE 

  Get-ADDuplicateUsers -SamAccountName jbrown 

.EXAMPLE 

  Get-ADDuplicateUsers -SamAccountName "jbrown","mbrown","ssmith"

.EXAMPLE 

  "jbrown","mbrown","ssmith"|Get-ADDuplicateUsers
  
.EXAMPLE 

  Get-ADDuplicateUsers (Get-Content .\DupUsers.txt) 
  
  --- DupUser.txt Content ---
  jbrown
  mbrown
  ssmith
  --- End DupUser.txt Content ---

.EXAMPLE 

  (import-csv .\dupusers.csv).username|Get-ADDuplicateUsers
    
  --- DupUser.csv Content ---
  username
  jbrown
  mbrown
  ssmith
  --- End DupUser.txt Content ---
  
.INPUTS
	System.String, String or strings representing user account login names
  
.OUTPUTS
	Microsoft.ActiveDirectory.Management.ADUser


#> 

	[CmdletBinding()]
	Param(
		[parameter( 
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
            HelpMessage="Enter SamAccountName to check for duplicates",
            Mandatory=$true
		)] # End Parameter
		[string[]]
		$SamAccountName
	) # End Param
	
	begin{
		try{
			Import-Module activedirectory -ErrorAction Stop
			$myForest = Get-ADForest |Select-Object -ExpandProperty rootDomain
			$myGC = $myForest + ":3268"
		} # End try import-module
		catch{
			write-error $_
		} # End Catch Import-Module
	} #End Begin

	process{
		foreach ($name in $SamAccountName) {
			$qty = (get-aduser -server $myGC -Filter {samaccountname -eq $name}|
				Measure-Object).count
			if ($qty -gt 0) {
				get-aduser -server $myGC -Filter {samaccountName -eq $name}
			} # End if qty
		} # End foreach $name
	} # End Process
	end{
	} # End End
} #End Function Get-ADDuplicateUsers

