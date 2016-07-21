[CmdletBinding(DefaultParameterSetName='Everything')]
param (
	[Parameter(Position = 0, Mandatory = $false, ParameterSetName = "Individual")]
	[switch] $Apps,
	
	[Parameter(Position = 0, Mandatory = $false, ParameterSetName = "Individual")]
	[switch] $OS,
	
	[Parameter(Position = 0, Mandatory = $false, ParameterSetName = "Individual")]
	[switch] $Drivers,
	
	[Parameter(Position = 0, Mandatory = $false, ParameterSetName = "Individual")]
	[switch] $Packages,
	
	[Parameter(Position = 0, Mandatory = $false, ParameterSetName = "Individual")]
	[switch] $Ts,
	
	[Parameter(Position = 0, Mandatory = $false, ParameterSetName = "Individual")]
	[switch] $Scripts,
	
	[Parameter(Position = 0, Mandatory = $false, ParameterSetName = "Everything")]
	[switch] $Bootstrap,
	
	[Parameter(Position = 0, Mandatory = $false, ParameterSetName = "Everything")]
	[switch] $CustomSettings,
	
	[Parameter(Position = 0, Mandatory = $false, ParameterSetName = "Everything")]
	[switch] $RegenBoot,
	
	[Parameter(Position = 0, Mandatory = $false, ParameterSetName = "Everything")]
	[switch] $All,
	
	[Parameter(Position = 0, Mandatory = $false, ParameterSetName = "Everything")]
	[Parameter(ParameterSetName = "Individual")]
	[string] $ConfigFile = $null,
	
	[Parameter(Position = 0, Mandatory = $false, ParameterSetName = "Everything")]
	[Parameter(ParameterSetName = "Individual")]
	[string] $LogDir
)

if ($ConfigFile -eq ""){$ConfigFile = "$PSScriptRoot\config.xml"}
if ($LogDir -eq ""){$LogDir = "$PSScriptRoot\Logs"}

function main {
	cls
	
	$Logger = [Logger]::new($LogDir, "MdtSync.log", $true)
	$config = ProcessConfig ($ConfigFile)
	
	if ($All) {
		$Apps = $true
		$OS = $true
		$Drivers = $true
		$Packages = $true
		$Ts = $true
		$Scripts = $True
		$CustomSettings = $true
		$Bootstrap = $true
		$RegenBoot = $true
	}
	
	foreach ($share in $config.share) {
		
		if ($Apps) {
			$Logger.Log("Syncing Apps")
			SyncFolder -Source "$($config.master)\Applications" -Destination "$($share.Path)\Applications" -FullSync
			SyncFolder -Source "$($config.master)\Control" -Destination "$($share.Path)\Control" -Filter 'ApplicationGroups.xml'
			SyncFolder -Source "$($config.master)\Control" -Destination "$($share.Path)\Control" -Filter 'Applications.xml'
		}
		
		if ($OS) {
			$Logger.Log("Syncing Operating Systems")
			SyncFolder -Source "$($config.master)\Operating Systems" -Destination "$($share.Path)\Operating Systems" -FullSync
			SyncFolder -Source "$($config.master)\Control" -Destination "$($share.Path)\Control" -Filter 'OperatingSystemGroups.xml'
			SyncFolder -Source "$($config.master)\Control" -Destination "$($share.Path)\Control" -Filter 'OperatingSystems.xml'
		}
		
		if ($Drivers) {
			$Logger.Log("Syncing Drivers")
			SyncFolder -Source "$($config.master)\Out-of-Box Drivers" -Destination "$($share.Path)\Out-of-Box Drivers" -FullSync
			SyncFolder -Source "$($config.master)\Control" -Destination "$($share.Path)\Control" -Filter 'DriverGroups.xml'
			SyncFolder -Source "$($config.master)\Control" -Destination "$($share.Path)\Control" -Filter 'Drivers.xml'
		}
		
		if ($Packages) {
			$Logger.Log("Syncing Packages")
			SyncFolder -Source "$($config.master)\Packages" -Destination "$($share.Path)\Packages" -FullSync
			SyncFolder -Source "$($config.master)\Control" -Destination "$($share.Path)\Control" -Filter 'PackageGroups.xml'
			SyncFolder -Source "$($config.master)\Control" -Destination "$($share.Path)\Control" -Filter 'Packages.xml'
		}
		
		if ($Ts) {
			$Logger.Log("Syncing Task Sequences")
			$TsFolders = Get-ChildItem "$($config.master)\Control" | Where {$_.PSIsContainer}
			foreach ($folder in $TsFolders){
				SyncFolder -Source $folder.FullName -Destination "$($share.Path)\Control\$($folder.Name) -FullSync"		
			}
			SyncFolder -Source "$($config.master)\Control" -Destination "$($share.Path)\Control" -Filter 'TaskSequenceGroups.xml'
			SyncFolder -Source "$($config.master)\Control" -Destination "$($share.Path)\Control" -Filter 'TaskSequences.xml'
		}
		
		if ($Scripts) {
			$Logger.Log("Syncing Scripts")
			SyncFolder -Source "$($config.master)\Scripts" -Destination "$($share.Path)\Scripts" -FullSync
		}
		
		if ($Bootstrap) {
			$Logger.Log("Syncing Bootstrap.ini")
			$BootstrapContent = (Get-Content -Path "$($config.master)\Control\Bootstrap.ini").replace($config.FQDNMaster, $share.FQDNPath).replace($config.FQDNMaster, $share.Path)
			$BootstrapContent | Set-Content -Path "$($share.Path)\Control\Bootstrap.ini" -Force
		}
		
		if ($CustomSettings) {
			$Logger.Log("Syncing CustomSettings.ini")
			$BootstrapContent = (Get-Content -Path "$($config.master)\Control\CustomSettings.ini").replace($config.FQDNMaster, $share.FQDNPath).replace($config.FQDNMaster, $share.Path)
			$BootstrapContent | Set-Content -Path "$($share.Path)\Control\CustomSettings.ini" -Force
		}
		
		
	}
}

function SyncFolder {
	[cmdletbinding()]
	param (
		[Parameter(Position = 0, Mandatory = $true)]
		[string] $Source,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[string] $Destination,
		
		[Parameter(Position = 2, Mandatory = $false)]
		[string] $Filter = "*.*",
		
		[Parameter(Position = 3, Mandatory = $false)]
		[switch] $FullSync
		
	)
	
	if ( !( Test-Path $Destination) ){
			Try {
				New-Item -ItemType directory -Path "$Destination" -ErrorAction Stop 
			} Catch {
				$Logger.Log("`tUnable to create folder`n $($_.Exception)")
			}
	}
	
	$Logger.Log("`tReading source folder ""$Source""")
	$srcItems = Get-ChildItem $Source -Recurse -Filter $filter | select Name, Length, LastWriteTime, FullName, PSIsContainer
	
	$Logger.Log("`tReading destination folder ""$Destination""")
	$dstItems = Get-ChildItem $Destination -Recurse -Filter $filter | select Name, Length, LastWriteTime, FullName, PSIsContainer
	
	$Logger.Log("`tComparing files")
	$diffItems = Compare-Object -ReferenceObject $srcItems -DifferenceObject $dstItems -PassThru -Property Name, Length, LastWriteTime
	
	$foldersToCreate = $diffItems | where { ($_.SideIndicator -eq '<=') -and ($_.PSIsContainer) }
	$Logger.Log("`tCreating $($foldersToCreate.length) folders on destination")
	foreach ($item in $foldersToCreate ){
		$relPath = $item.FullName.Replace("$Source", '')
		
		if (!(Test-Path "$Destination$relPath")){
			Try {
				New-Item -ItemType directory -Path "$Destination$relPath" -ErrorAction Stop 
				$item | Add-Member -MemberType NoteProperty -Name Done -Value $true -Force 
			} Catch {
				$Logger.Log("`tUnable to create folder`n $($_.Exception)")
			}
		}
	}
	
	$filesToCopy = $diffItems | where { ($_.SideIndicator -eq '<=') -and (!($_.PSIsContainer)) }
	$Logger.Log("`tCopying $($filesToCopy.length) files to destination")
	foreach ($item in $filesToCopy ){
		$relPath = $item.FullName.Replace("$Source", '')
		
		Try {
			Copy-Item -Path $item.FullName -Destination "$Destination$relPath" -ErrorAction Stop -force
			$item | Add-Member -MemberType NoteProperty -Name Done -Value $true -Force 
			$Logger.Log("`tCopied ""$($item.FullName)"" to ""$("$Destination$relPath")""")
		} Catch {
			$Logger.Log("`tUnable to copy file`n $($_.Exception)")
		}
		
	}
	
	if ($FullSync) {
		$filesToRemove = $diffItems | where { ($_.SideIndicator -eq '=>') -and (!($_.PSIsContainer) ) } 
		$Logger.Log("`tRemoving $($filesToRemove.length) files that do not exist in source")
		foreach ($item in $filesToRemove ){
			$relPath = $item.FullName.Replace("$Destination", '')
			if (!(Test-Path "$Source$relPath")){
				Try {
					Remove-Item -Path $item.fullname -ErrorAction Stop -WhatIf
				} Catch {
					$Logger.Log("`tUnable to remove uneeded destination file`n $($_.Exception)")
				}
			}
		}
	}
}

function ProcessConfig {
	param (
		[string] $ConfigFile
	)
	
	$config = ([xml](gc $ConfigFile)).config
	
	return $config
}

Class Logger {
	[string] $LogDir
	[string] $LogFile
	[bool] $WriteConsole
	
	Logger ($LogDir, $LogFile, $WriteConsole) {
		$this.LogFile = "$LogDir\$LogFile"
		$this.WriteConsole = $WriteConsole
				
		if ( !(Test-Path $LogDir)){
			New-Item -ItemType directory -Path $LogDir
		}
		"################################ START ($(Get-Date -format u)) ################################" | Out-File $this.LogFile -Append -force
	}	
	
	[Void]Log( $Message ){
		$date = Get-Date -format u

		if ($this.WriteConsole) {
			Write-Host "$date:: $Message"
		}
		
		"$date:: $Message" | Out-File $this.LogFile -Append
	}
	
}



main