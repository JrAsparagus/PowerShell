#REQUIRES -Version 4
#REQUIRES -Module NetSecurity
#Requires -RunAsAdministrator


function Add-SQLFirewallRule {
<#
.SYNOPSIS
Add Firewall Service Exceptions for Installed SQL Instances

.EXAMPLE
Add-SQLFirewallRule

Will add the SQL broswer service and installed SQL instance exceptions confirming before making each firewall rule addition.

.EXAMPLE
Add-SQLFirewallRule -Verbose
Will add the SQL broswer service and installed SQL instance exceptions confirming before making each firewall rule addition with a verbose output

.EXAMPLE
Add-SQLFirewallRule -Verbose -Confirm:$false
Will add the SQL broswer service and installed SQL instance exceptions with no output to screen.

#>
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High")]
    param(
    )
	function CheckFirewallProfileStatus {
		Write-Verbose "Checking Firewall Profile Status"
		$firewallProfiles = Get-NetFirewallProfile | Where-Object {$psitem.enabled -eq $false}
		if (($firewallProfiles|measure-Object).count -gt 0) {
			foreach ($firewallProfile in $firewallProfiles) {
				Write-Warning "Firewall not enabled for $($firewallProfile.Name) profile, enable now?"
				if ($pscmdlet.ShouldProcess("Profile: $($firewallProfile.Name)","Enable Firewall")) {
					Set-NetFirewallProfile -Name $firewallProfile.Name -Enabled "True"
				}
			}
		}
	}
	
    function NewSQLFirewallRule {
        param (
            [string]$DisplayName,
            [string]$Name
        )
        Write-Verbose "Adding new firewall rule for $DisplayName"
        New-NetFirewallRule -DisplayName $DisplayName -Name $Name -Direction Inbound -Group "SQL Server" -Action Allow -Profile Domain 
    }

    # Add SQL Browser Service Firewall Exception
    #region
    $sqlBrowserService = Get-Service -name "SQLBrowser" -EA SilentlyContinue
    if (($sqlBrowserService|measure).count -eq 1) {
        $sqlBrowserverFirewallRule = get-NetFirewallRule -displayname $($sqlBrowserService.displayName) -EA SilentlyContinue
        if (($sqlBrowserverFirewallRule|measure-object).count -eq 0) {
            if ($pscmdlet.ShouldProcess($($sqlBrowserService.DisplayName))) {
                NewSQLFirewallRule -DisplayName $sqlBrowserService.DisplayName -Name $sqlBrowserService.Name | Out-Null
            }
        }
        else {
            Write-Verbose "$($sqlBrowserverFirewallRule.DisplayName) Already Exists"
        }
    }
    else {
        Write-Warning "Unable to find SQLBrowser Service on this computer"
    }
    #endregion


    # Add SQL Server Service Firewall Exception(s)
    #region
    $sqlServerServices = get-service "mssql*" -EA SilentlyContinue |where {$psitem.DisplayName -like "SQL Server*"}
    if (($sqlServerServices|measure).count -gt 0) {
        foreach ($sqlServerService in $sqlServerServices) {
            $sqlServerFirewallRule = Get-NetFirewallRule -DisplayName $($sqlServerService.displayName) -EA SilentlyContinue
            if (($sqlServerFirewallRule|measure-object).count -eq 0) {
                if ($pscmdlet.ShouldProcess($($sqlServerService.DisplayName))) {
                    NewSQLFirewallRule -DisplayName $sqlServerService.DisplayName -Name $sqlServerService.Name | Out-Null
                }
            }
            else {
                Write-Verbose "$($sqlServerFirewallRule.DisplayName) Already Exists"
            }
        }
    }
    else {
        Write-Warning "Unable to find any SQL Server Instances on this computer"
    }
    #endregion
	
	CheckFirewallProfileStatus
}