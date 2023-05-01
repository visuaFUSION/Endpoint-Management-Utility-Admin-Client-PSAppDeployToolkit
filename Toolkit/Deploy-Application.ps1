<#
.SYNOPSIS

PSApppDeployToolkit - This script performs the installation or uninstallation of an application(s).

.DESCRIPTION

- The script is provided as a template to perform an install or uninstall of an application(s).
- The script either performs an "Install" deployment type or an "Uninstall" deployment type.
- The install deployment type is broken down into 3 main sections/phases: Pre-Install, Install, and Post-Install.

The script dot-sources the AppDeployToolkitMain.ps1 script which contains the logic and functions required to install or uninstall an application.

PSApppDeployToolkit is licensed under the GNU LGPLv3 License - (C) 2023 PSAppDeployToolkit Team (Sean Lillis, Dan Cunningham and Muhammad Mashwani).

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the
Free Software Foundation, either version 3 of the License, or any later version. This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
for more details. You should have received a copy of the GNU Lesser General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

.PARAMETER DeploymentType

The type of deployment to perform. Default is: Install.

.PARAMETER DeployMode

Specifies whether the installation should be run in Interactive, Silent, or NonInteractive mode. Default is: Interactive. Options: Interactive = Shows dialogs, Silent = No dialogs, NonInteractive = Very silent, i.e. no blocking apps. NonInteractive mode is automatically set if it is detected that the process is not user interactive.

.PARAMETER AllowRebootPassThru

Allows the 3010 return code (requires restart) to be passed back to the parent process (e.g. SCCM) if detected from an installation. If 3010 is passed back to SCCM, a reboot prompt will be triggered.

.PARAMETER TerminalServerMode

Changes to "user install mode" and back to "user execute mode" for installing/uninstalling applications for Remote Desktop Session Hosts/Citrix servers.

.PARAMETER DisableLogging

Disables logging to file for the script. Default is: $false.

.EXAMPLE

powershell.exe -Command "& { & '.\Deploy-Application.ps1' -DeployMode 'Silent'; Exit $LastExitCode }"

.EXAMPLE

powershell.exe -Command "& { & '.\Deploy-Application.ps1' -AllowRebootPassThru; Exit $LastExitCode }"

.EXAMPLE

powershell.exe -Command "& { & '.\Deploy-Application.ps1' -DeploymentType 'Uninstall'; Exit $LastExitCode }"

.EXAMPLE

Deploy-Application.exe -DeploymentType "Install" -DeployMode "Silent"

.INPUTS

None

You cannot pipe objects to this script.

.OUTPUTS

None

This script does not generate any output.

.NOTES

Toolkit Exit Code Ranges:
- 60000 - 68999: Reserved for built-in exit codes in Deploy-Application.ps1, Deploy-Application.exe, and AppDeployToolkitMain.ps1
- 69000 - 69999: Recommended for user customized exit codes in Deploy-Application.ps1
- 70000 - 79999: Recommended for user customized exit codes in AppDeployToolkitExtensions.ps1

.LINK

https://psappdeploytoolkit.com

This Script has been modified to work with EMU Admin Client's Application Packaging GUI:
https://visuafusion.com/Applications/endpoint-management-utility-admin-client

#>


[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)]
    [ValidateSet('Install', 'Uninstall', 'Repair')]
    [String]$DeploymentType = 'Install',
    [Parameter(Mandatory = $false)]
    [ValidateSet('Interactive', 'Silent', 'NonInteractive')]
    [String]$DeployMode = 'Interactive',
    [Parameter(Mandatory = $false)]
    [switch]$AllowRebootPassThru = $false,
    [Parameter(Mandatory = $false)]
    [switch]$TerminalServerMode = $false,
    [Parameter(Mandatory = $false)]
    [switch]$DisableLogging = $false
)

#####################################################################
# Start visuaFUSION Systems Solutions Additional Provided Functions #
#####################################################################

function Set-AppDirPermissions ($UserOrGroup, $Setting, $DirPath) {
    ########################################
    # Modify Directory Permissions
    # Function Date: 19.3.13.1
    # Function by Sean Huggans
    ########################################
    if (($UserOrGroup) -and ($Setting) -and ($DirPath)) {
        try {
            Write-Log -Severity 1 -Source "Directory Permission Adjustments" -Message "Granting ""$($UserOrGroup)"" ""$($Setting)"" permissions on ""$($DirPath)""..."
            $InstallDirObject = Get-Item -LiteralPath $DirPath -ErrorAction Stop
            $ACL = $InstallDirObject.GetAccessControl()
            $Rule= New-Object System.Security.AccessControl.FileSystemAccessRule("$($UserOrGroup)","$($Setting)","ContainerInherit,Objectinherit","none","Allow")
            $ACL.SetAccessRule($Rule)
            $InstallDirObject.SetAccessControl($ACL)
            Write-Log -Severity 1 -Source "Directory Permission Adjustments" -Message " - Success!"
            return $true
        } catch {
            Write-Log -Severity 3 -Source "Directory Permission Adjustments" -Message " - Error!"
            return $false
        }
    } else {
        Write-Log -Severity 3 -Source "Directory Permission Adjustments" -Message " - Error! (Incomplete Parameters Passed)"
        return $false
    }
}

function Set-FilePermissions ($Setting, $FilePath, $UserOrGroup) {
    ########################################
    # Modify File Permissions
    # Function Date: 19.3.13.1
    # Function By: Sean Huggans
    ########################################
    if (($Setting) -and ($FilePath) -and ($UserOrGroup)) {
        Write-Log -Severity 1 -Source "File Permission Adjustments" -Message "Applying '$($Setting)' permissions on '$($FilePath)'..."
        try {
            $InstallFileObject = Get-Item -LiteralPath $FilePath -ErrorAction Stop
            $ACL = $InstallFileObject.GetAccessControl()
            $Rule= New-Object System.Security.AccessControl.FileSystemAccessRule("$($UserOrGroup)","$($Setting)","Allow")
            $ACL.SetAccessRule($Rule)
            $InstallFileObject.SetAccessControl($ACL)
            Write-Log -Severity 1 -Source "Directory Permission Adjustments" -Message " - Success!"
            return $true
        } catch {
            Write-Log -Severity 3 -Source "Directory Permission Adjustments" -Message " - Failed!"
            return $false
        }
    } else {
        Write-Log -Severity 3 -Source "Directory Permission Adjustments" -Message "Invalid or missing Arguments Passed to Set-AppFilePermissions Function!"
        return $false
    }
}

function Set-AppRegPermissions ($Setting, $RegPath) {
    ########################################
    # Modify Registry Permissions
    # Function Date: 19.3.13.1
    # Function by Sean Huggans and Chad Loevinger
    ########################################
    if (($Setting) -and ($RegPath)) {
        try {
            Write-Log -Severity 1 -Source "Registry Permission Adjustments" -Message "Setting ""$($Setting)"" permission on ""$($RegPath)""..."
            $acl = Get-Acl "$($RegPath)"
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule ("everyone","$($Setting)","Allow")
            $acl.SetAccessRule($rule)
            $acl | Set-Acl -Path "$($RegPath)"
            Write-Log -Severity 1 -Source "Registry Permission Adjustments" -Message " - Success!"
            return $true
        } catch {
            Write-Log -Severity 3 -Source "Registry Permission Adjustments" -Message " - Error!"
            return $false
        }
    } else {
        Write-Log -Severity 3 -Source "Registry Permission Adjustments" -Message " - Error! (Incomplete Parameters Passed)"
        return $false
    }
}

function Add-FirewallRule ($RuleName, $RuleType, $ProtocolType, $PortNumber, $ProgramPath) {
    ########################################
    # Create Firewall Rule
    # Function Date: 19.3.13.1
    # Function By: Sean Huggans
    ########################################
    # Usage Note 1: function is dependent on the below 2 lines being present at the beginning of your script, as well as the standard logging function being present
    $script:wmiOS = Get-WmiObject -Class Win32_OperatingSystem;
    $script:OS = $wmiOS.Caption
    # Usage Note 2: Use the Add-Firewall function below in your script, Call the function with the following examples:
    # - Example 1 (Port): Add-FirewallRule -RuleName "ApplicationX" -RuleType Port -ProtocolType TCP -PortNumber 2233
    # - Example 1 (Port Range): Add-FirewallRule -RuleName "ApplicationX" -RuleType Port -ProtocolType UDP -PortNumber 2233-2236
    # - Example 2 (Process/Program): Add-FirewallRule -RuleName "ApplicationX" -RuleType Process -ProgramPath "C:\Program Files\Application X\X.exe"
    #Usage Note 3: It may be benneficial to use the Other firewall related standard functions in order to ensure the firewall is enabled and active prior to calling this function!
    try {
        if ($OS -like "*Windows 1*") {
            switch ($RuleType) {
                "Port" {
                    if ($PortNumber -notlike "*-*") {
                        New-NetFirewallRule -DisplayName "$($RuleName) ($($ProtocolType) $($PortNumber))" -profile Domain -Direction Inbound -Action Allow -Protocol $($ProtocolType) -LocalPort $PortNumber -ErrorAction Stop | Out-Null
                    } else {
                        Write-Log -Severity 1 -Source "Firewall Adjustments" -Message " - (Info!) Port Number ($PortNumber) is a Range, Attempting to add it now..."
                        New-NetFirewallRule -DisplayName "$($RuleName) ($($ProtocolType) $($PortNumber))" -profile Domain -Direction Inbound -Action Allow -Protocol $($ProtocolType) -LocalPort $PortNumber -ErrorAction Stop | Out-Null
                    }
                    Write-Log -Severity 1 -Source "Firewall Adjustments" -Message " - - Successfully created rule ""$($RuleName) ($($ProtocolType) $($PortNumber))"", Allowing inbound connections on $($ProtocolType) port ""$($PortNumber)"""
                    return $true
                }
                "Process" {
                    # Using Split instead get-ItemProperty incase the application is not yet installed when this is called
                    $ProgramSplit = $ProgramPath.Split("\")
                    $ProgramName = $ProgramSplit[$($ProgramSplit.Length -1)]
                    New-NetFirewallRule -DisplayName "$($RuleName) ($($ProgramName))" -profile Domain -Direction Inbound -Program $ProgramPath -Action Allow -ErrorAction Stop | Out-Null
                    Write-Log -Severity 1 -Source "Firewall Adjustments" -Message " - Successfully created rule ""$($RuleName) ($($ProgramName))"", Allowing inbound connections to ""$($ProgramPath)"""
                    return $true
                }
                default {
                    Write-Log -Severity 3 -Source "Firewall Adjustments" -Message " - Error: Unknown Rule Type ($($RuleType)) called attempting to create rule ("$($RuleName) ($($ProtocolType))")!  Check syntax!"
                    return $false
                }
            }
        } else {
            switch ($RuleType) {
                "Port" {
                    if ($PortNumber -notlike "*-*") {
                        $result = $(& netsh advfirewall firewall add rule name="$($RuleName) ($($ProtocolType) $($PortNumber))" dir=in action=allow protocol=$($ProtocolType) localport=$($PortNumber))[0]
                    } else {
                        Write-Log -Severity 1 -Source "Firewall Adjustments" -Message " - - (Info!) Port Number ($PortNumber) is a Range, Attempting to add it now..."
                        $result = $(& netsh advfirewall firewall add rule name="$($RuleName) ($($ProtocolType) $($PortNumber))" dir=in action=allow protocol=$($ProtocolType) localport=$($PortNumber))[0]
                    }
                    if ($result -like "*Ok.*") {
                        Write-Log -Severity 1 -Source "Firewall Adjustments" -Message " - Successfully created rule ""$($RuleName) ($($ProtocolType))"", Allowing inbound connections on $($ProtocolType) port ""$($PortNumber)"""
                        return $true
                    } else {
                        Write-Log -Severity 3 -Source "Firewall Adjustments" -Message " - Error!  The following NETSH command did not return ""Ok."": netsh advfirewall firewall add rule name=""$($RuleName) ($($ProtocolType) $($PortNumber))"" dir=in action=allow protocol=$($ProtocolType) localport=$($PortNumber)"
                        return $false
                    }
                }
                "Process" {
                    # Using Split instead get-ItemProperty incase the application is not yet installed when this is called
                    $ProgramSplit = $ProgramPath.Split("\")
                    $ProgramName = $ProgramSplit[$($ProgramSplit.Length -1)]
                    $result = $(& netsh advfirewall firewall add rule name="$($RuleName) ($($ProgramName))" action=allow protocol=any enable=yes dir=in program="$($ProgramPath)")[0]
                    if ($result -like "*Ok.*") {
                        Write-Log -Severity 1 -Source "Firewall Adjustments" -Message " - Successfully created rule ""$($RuleName) ($($ProgramName))"", Allowing inbound connections to ""$($ProgramPath)"""
                        return $true
                    } else {
                        Write-Log -Severity 3 -Source "Firewall Adjustments" -Message " - Error!  The following NETSH command did not return ""Ok."": netsh advfirewall firewall add rule name=""$($RuleName) ($($ProgramName))"" action=allow protocol=any enable=yes dir=in program="$($ProgramPath)""
                        return $false    
                    }
                }
                default {
                    Write-Log -Severity 3 -Source "Firewall Adjustments" -Message " - Error: Unknown Rule Type ($($RuleType)) called attempting to create rule ("$($RuleName) ($($ProtocolType))")!  Check syntax!"
                    return $false
                }
            }
        }
    } catch {
        Write-Log -Severity 3 -Source "Firewall Adjustments" -Message " - Error creating rule ""$($RuleName) ($($ProtocolType))""!"
        return $false
    }
}

###################################################################
# End visuaFUSION Systems Solutions Additional Provided Functions #
###################################################################

###################################################################
# Start Community Additional Provided Functions                   #
###################################################################

function Set-RegistryDetection ([string]$AppName, [string]$AppVersion)
{
	################################
	# Function Version 22.04.21.01
	# Function by Blake Volk
	################################
	# Function creates a name/value pair at the following registry path: HKLM:\SOFTWARE\Sanford\Deployment.
	# Usually helpful for standalone executables or shortcuts when detection via product code is not possible.
	# Notes: 
	# - Relies on Log-Action function to be in place to use.  Comment out Log-Action lines if logging is not needed (for non-app packaging scenarios) in order to get this to run.
	# - It is okay to remove note and description comments, but please leave the function version intact so that this function can be easily updated in the future for all scripts with older versions if necessary.
	# Typical usage
	# - Set-RegistryDetection -AppName "CPR+ Shortcut" -AppVersion "22.04.21.01"
	# Using global variables. note: Removes spaces in app name when inserted into the registry
	# - Set-RegistryDetection -AppName $appName -AppVersion $appVersion
	
	#Verifying Sanford Deployments Registry Path exists. Will create it if not found.
	if (!(Test-Path -Path "HKLM:\SOFTWARE\Sanford\Deployment"))
	{
		try
		{
			Write-Log -Severity 1 -Source "Set Registry Detection" -Message "Registry Path was not found, attempted to add Sanford Deployment Registry Path..."
			New-Item -Path "HKLM:\SOFTWARE\Sanford\Deployment"
			New-ItemProperty -Path "HKLM:\Software\Sanford\Deployment" -Name $AppName -Type String -Value $AppVersion -Force
			Write-Log -Severity 1 -Source "Set Registry Detection" -Message "Registry Path `"HKLM:\SOFTWARE\Sanford\Deployment`" was created!"
		}
		catch
		{
			Write-Log -Severity 3 -Source "Set Registry Detection" -Message "Failed creating HKLM:\SOFTWARE\Sanford\Deployment..."
			return $false
		}		
	}
	else
	{
		try
		{
			Write-Log -Severity 1 -Source "Set Registry Detection" -Message "Registry Path was not found, attempted to add Sanford Deployment Registry Path..."
			New-ItemProperty -Path "HKLM:\Software\Sanford\Deployment" -Name $AppName -Type String -Value $AppVersion -Force
			Write-Log -Severity 1 -Source "Set Registry Detection" -Message "Registry detection was created!"
		}
		catch
		{
			Write-Log -Severity 3 -Source "Set Registry Detection" -Message "Failed creating registry detection for $($appName)..."
			return $false
		}
	}
}

function Set-ServicePerms ([string]$ServiceName)
{
	################################
	# Function Version 22.10.14.1
	# Function by Joshua Slieter, Blake Volk
	################################
	# Description: This function allows the domain users AD group to modify a specified service. The parameter, ServiceName, requires the Service name found in the properties of the service rather than the Display Name

	# Typical usage example. The example line below will give domain users access to stop/start/etc. on the BITS service. Using "Background Intelligent Transfer Service" would not work.
	# Set-ServicePerms -ServiceName BITS

    # Online docs: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-service?view=powershell-7.2#example-9-change-the-securitydescriptor-of-a-service
	
    # The security descriptior. This specific descriptor gives the Domain Users group full permissions on a service to stop, start, etc. Other descriptors can be made by following: KB????????
    $SDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;SU)"

	try
	{
		Write-Log -Severity 1 -Source "Set ServiceShim" -Message "Attemping to shim the service $($ServiceName)..."
		Set-Service -Name $ServiceName -SecurityDescriptorSddl $SDDL -ErrorAction stop
		Write-Log -Severity 1 -Source "Set ServiceShim" -Message "Service Shim for $($ServiceName) was created!"
	}
	catch
	{
		Write-Log -Severity 3 -Source "Set ServiceShim" -Message "Failed creating Service Shim for $($ServiceName)."
        return $false
	}
}

function Set-AppShimDB ([string]$ApplicationName, [string]$ApplicationDirPath, [string]$SDBName)
{
	################################
	# Function Version 22.10.17.1
	# Function by Sean Huggans, Blake Volk, Joshua Slieter
	################################
	# Description: This function will copy a .sdb file to the application's directory and then call sdbinst to install the .sdb file. You must still create the .sdb file using the Compatibility Administrator application. Place this file in the Files folder. 
    # It will also give modify permissions for Domain Users to the application's directory. 
	
	# Typical usage example on the line below. Provide the name of the application (for logging purposes), the directory to where the executable will be located on target devices, and the created .sdb filename within the Files folder.
	# Set-AppShim -ApplicationName CytoVision -ApplicationDirPath "C:\Program Files (x86)\Applied Imaging\CytoVision" -SDBName "CytovisionRunAsInvoker.sdb"

	try
	{
		Write-Log -Severity 1 -Source "Set-AppShim" -Message "Attemping to apply shim database to the application $($ApplicationName)..."
		
        if ($(Set-AppDirPermissions -UserOrGroup "Domain Users" -Setting "Modify" -DirPath "$($ApplicationDirPath)") -eq $true) {

            Write-Log -Severity 1 -Source "Set-AppShim" -Message "Copying $($SDBName).sdb to path: $($ApplicationDirPath)"
            Copy-Item -Path "$($dirFiles)\$($SDBName).sdb" -Destination "$($ApplicationDirPath)\$($SDBName).sdb"
            
            try {
                Start-Process -FilePath sdbinst.exe -ArgumentList "-q ""$($ApplicationDirPath)\$($SDBName).sdb""" -Wait -ErrorAction Stop
                Write-Log -Severity 1 -Source "Set-AppShim" -Message "Successfully applied shim DB for the application: $($ApplicationName)"
            } catch {
                Write-Log -Severity 1 -Source "Set-AppShim" -Message "Failed to apply shim DB for the application: $($ApplicationName)"
            }
        }
		Write-Log -Severity 1 -Source "Set-AppShim" -Message "App Shim DB for $($ApplicationName) was applied!"
	}
	catch
	{
		Write-Log -Severity 3 -Source "Set-AppShim" -Message "Failed Applying the App Shim DB for $($ApplicationName)."
	}
}

###################################################################
# End Community Additional Provided Functions                     #
###################################################################

Try {
    ## Set the script execution policy for this process
    Try { 
		Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop' 
	} 
	Catch {
	}
																						 
    ##*===============================================
    ##* VARIABLE DECLARATION
    ##*===============================================
    ## Variables: Application
    [String]$appVendor = ''
    [String]$appName = ''
    [String]$appVersion = ''
    [String]$appArch = ''
    [String]$appLang = 'EN'
    [String]$appRevision = '01'
    [String]$appScriptVersion = '1.0.0'
    [String]$appScriptDate = 'XX/XX/20XX'
    [String]$appScriptAuthor = '<author name>'
    ##*===============================================
    ## Variables: Install Titles (Only set here to override defaults set by the toolkit)
    [String]$installName = ''
    [String]$installTitle = ''

    ##* Do not modify section below
    #region DoNotModify

    ## Variables: Exit Code
    [Int32]$mainExitCode = 0

    ## Variables: Script
    [String]$deployAppScriptFriendlyName = 'Deploy Application'
    [Version]$deployAppScriptVersion = [Version]'3.9.2'
    [String]$deployAppScriptDate = '02/02/2023'
    [Hashtable]$deployAppScriptParameters = $PsBoundParameters

    ## Variables: Environment
    If (Test-Path -LiteralPath 'variable:HostInvocation') { 
		$InvocationInfo = $HostInvocation 
	} 
	Else { 
		$InvocationInfo = $MyInvocation 
	}
    [String]$scriptDirectory = Split-Path -Path $InvocationInfo.MyCommand.Definition -Parent

    ## Dot source the required App Deploy Toolkit Functions
    Try {
        [String]$moduleAppDeployToolkitMain = "$scriptDirectory\AppDeployToolkit\AppDeployToolkitMain.ps1"
        If (-not (Test-Path -LiteralPath $moduleAppDeployToolkitMain -PathType 'Leaf')) {
			Throw "Module does not exist at the specified location [$moduleAppDeployToolkitMain]."
		}
        If ($DisableLogging) {
			. $moduleAppDeployToolkitMain -DisableLogging
		} 
		Else { 
			. $moduleAppDeployToolkitMain 
		}
    }
    Catch {
        If ($mainExitCode -eq 0) {
			[Int32]$mainExitCode = 60008 
		}
        Write-Error -Message "Module [$moduleAppDeployToolkitMain] failed to load: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
        ## Exit the script, returning the exit code to SCCM
        If (Test-Path -LiteralPath 'variable:HostInvocation') { 
			$script:ExitCode = $mainExitCode; Exit 
		} 
		Else { 
			Exit $mainExitCode 
		}
    }

    #endregion
    ##* Do not modify section above
    ##*===============================================
    ##* END VARIABLE DECLARATION
    ##*===============================================

    If ($deploymentType -ine 'Uninstall' -and $deploymentType -ine 'Repair') {
        ##*===============================================
        ##* PRE-INSTALLATION
        ##*===============================================
        [String]$installPhase = 'Pre-Installation'

        ## Show Welcome Message, close Internet Explorer if required, allow up to 3 deferrals, verify there is enough disk space to complete the install, and persist the prompt
		## <INSERT INSTALLATION LAUNCH STRING>

        ## Show Progress Message (with the default message)
        Show-InstallationProgress

        ## <Perform Pre-Installation tasks here>
        ## <INJECT FIREWALL RULE ADJUSTMENTS>
			

        ##*===============================================
        ##* INSTALLATION
        ##*===============================================
        [String]$installPhase = 'Installation'

        ## Handle Zero-Config MSI Installations
        If ($useDefaultMsi) {
            [Hashtable]$ExecuteDefaultMSISplat = @{ Action = 'Install'; Path = $defaultMsiFile }; If ($defaultMstFile) { 
				$ExecuteDefaultMSISplat.Add('Transform', $defaultMstFile) 
			}
            Execute-MSI @ExecuteDefaultMSISplat; If ($defaultMspFiles) { 
				$defaultMspFiles | ForEach-Object { Execute-MSI -Action 'Patch' -Path $_ } 
			}
        }

        ## <Perform Installation tasks here>


        ##*===============================================
        ##* POST-INSTALLATION
        ##*===============================================
        [String]$installPhase = 'Post-Installation'

        ## <Perform Post-Installation tasks here>
		## <INJECT PERMISSION ADJUSTMENTS>

        ## Create Public Desktop Shortcut
        ## <INJECT PUBLIC DESKTOP SHORTCUT ICO LINE>
        ## <INJECT PUBLIC DESKTOP SHORTCUT LINE>
		
		## Create Custom Shortcut
        ## <INJECT CUSTOM SHORTCUT ICO LINE>
        ## <INJECT CUSTOM SHORTCUT LINE>
		
        ## Display a message at the end of the install
		## <INJECT COMPLETION MESSAGE>
        
		## Reboot with a timer end of the install (10 minute default, do not allow hiding the window for the last minute)
        ## <INJECT REBOOT MESSAGE>
    }
    ElseIf ($deploymentType -ieq 'Uninstall') {
        ##*===============================================
        ##* PRE-UNINSTALLATION
        ##*===============================================
        [String]$installPhase = 'Pre-Uninstallation'

        ## Show Welcome Message, close Internet Explorer with a 60 second countdown before automatically closing
		## <INSERT INSTALLATION LAUNCH STRING>

        ## Show Progress Message (with the default message)
        Show-InstallationProgress

        ## <Perform Pre-Uninstallation tasks here>


        ##*===============================================
        ##* UNINSTALLATION
        ##*===============================================
        [String]$installPhase = 'Uninstallation'

        ## Handle Zero-Config MSI Uninstallations
        If ($useDefaultMsi) {
            [Hashtable]$ExecuteDefaultMSISplat = @{ Action = 'Uninstall'; Path = $defaultMsiFile }; If ($defaultMstFile) { 
				$ExecuteDefaultMSISplat.Add('Transform', $defaultMstFile) 
			}
            Execute-MSI @ExecuteDefaultMSISplat
        }

        ## <Perform Uninstallation tasks here>


        ##*===============================================
        ##* POST-UNINSTALLATION
        ##*===============================================
        [String]$installPhase = 'Post-Uninstallation'

        ## <Perform Post-Uninstallation tasks here>
        ## <INJECT PUBLIC DESKTOP SHORTCUT REMOVAL LINE>

    }
    ElseIf ($deploymentType -ieq 'Repair') {
        ##*===============================================
        ##* PRE-REPAIR
        ##*===============================================
        [String]$installPhase = 'Pre-Repair'

        ## Show Welcome Message, close Internet Explorer with a 60 second countdown before automatically closing
		## <INSERT INSTALLATION LAUNCH STRING>

        ## Show Progress Message (with the default message)
        Show-InstallationProgress

        ## <Perform Pre-Repair tasks here>

        ##*===============================================
        ##* REPAIR
        ##*===============================================
        [String]$installPhase = 'Repair'

        ## Handle Zero-Config MSI Repairs
        If ($useDefaultMsi) {
            [Hashtable]$ExecuteDefaultMSISplat = @{ Action = 'Repair'; Path = $defaultMsiFile; }; If ($defaultMstFile) {
                $ExecuteDefaultMSISplat.Add('Transform', $defaultMstFile)
            }
            Execute-MSI @ExecuteDefaultMSISplat
        }
        ## <Perform Repair tasks here>

        ##*===============================================
        ##* POST-REPAIR
        ##*===============================================
        [String]$installPhase = 'Post-Repair'

        ## <Perform Post-Repair tasks here>


    }
    ##*===============================================
    ##* END SCRIPT BODY
    ##*===============================================

    ## Call the Exit-Script function to perform final cleanup operations
    Exit-Script -ExitCode $mainExitCode
}
Catch {
    [Int32]$mainExitCode = 60001
    [String]$mainErrorMessage = "$(Resolve-Error)"
    Write-Log -Message $mainErrorMessage -Severity 3 -Source $deployAppScriptFriendlyName
    Show-DialogBox -Text $mainErrorMessage -Icon 'Stop'
    Exit-Script -ExitCode $mainExitCode
}
