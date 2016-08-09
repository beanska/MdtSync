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
	[switch] $Buildboot,
	
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
	
	$mstFqdnShare = "$($config.master.ComputerName).$($config.master.Domain)\$($config.master.Share)"
	$mstShare = "$($config.master.ComputerName)\$($config.master.Share)"
	
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
	
	foreach ($node in $config.node) {
	
		$nodeFqdnShare = "$($node.ComputerName).$($node.Domain)\$($node.Share)"
		$nodeShare = "$($node.ComputerName)\$($node.Share)"
		
		if ($Apps) {
			$Logger.Log("Syncing Apps")
			$srcApps = Get-ChildItem "$($config.master.DsLocal)\Applications" -Recurse -Filter $filter | select Name, Length, LastWriteTime, FullName, PSIsContainer, PSParentPath
			
			SyncFolder -SourceRef ([ref]$srcApps) -Destination "\\$nodeFqdnShare\Applications" -FullSync
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "\\$nodeFqdnShare\Control" -Filter 'ApplicationGroups.xml'
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "\\$nodeFqdnShare\Control" -Filter 'Applications.xml'
			
			#SyncFolder -Source "$($config.master.DsLocal)\Applications" -Destination "\\$nodeFqdnShare\Applications" -FullSync
			#SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "\\$nodeFqdnShare\Control" -Filter 'ApplicationGroups.xml'
			#SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "\\$nodeFqdnShare\Control" -Filter 'Applications.xml'
		}
		
		if ($OS) {
			$Logger.Log("Syncing Operating Systems")
			SyncFolder -Source "$($config.master.DsLocal)\Operating Systems" -Destination "\\$nodeFqdnShare\Operating Systems" -FullSync
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "\\$nodeFqdnShare\Control" -Filter 'OperatingSystemGroups.xml'
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "\\$nodeFqdnShare\Control" -Filter 'OperatingSystems.xml'
		}
		
		if ($Drivers) {
			$Logger.Log("Syncing Drivers")
			SyncFolder -Source "$($config.master.DsLocal)\Out-of-Box Drivers" -Destination "\\$nodeFqdnShare\Out-of-Box Drivers" -FullSync
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "\\$nodeFqdnShare\Control" -Filter 'DriverGroups.xml'
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "\\$nodeFqdnShare\Control" -Filter 'Drivers.xml'
		}
		
		if ($Packages) {
			$Logger.Log("Syncing Packages")
			SyncFolder -Source "$($config.master.DsLocal)\Packages" -Destination "\\$nodeFqdnShare\Packages" -FullSync
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "\\$nodeFqdnShare\Control" -Filter 'PackageGroups.xml'
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "\\$nodeFqdnShare\Control" -Filter 'Packages.xml'
		}
		
		if ($Ts) {
			$Logger.Log("Syncing Task Sequences")
			$TsFolders = Get-ChildItem "$($config.master.DsLocal)\Control" | Where {$_.PSIsContainer}
			foreach ($folder in $TsFolders){
				SyncFolder -Source $folder.FullName -Destination "\\$nodeFqdnShare\Control\$($folder.Name) -FullSync"		
			}
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "\\$nodeFqdnShare\Control" -Filter 'TaskSequenceGroups.xml'
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "\\$nodeFqdnShare\Control" -Filter 'TaskSequences.xml'
		}
		
		if ($Scripts) {
			$Logger.Log("Syncing Scripts")
			SyncFolder -Source "$($config.master.DsLocal)\Scripts" -Destination "\\$nodeFqdnShare\Scripts" -FullSync
		}
		
		if ($Bootstrap) {
			$Logger.Log("Syncing Bootstrap.ini")		
			$bsContent = (Get-Content -Path "$($config.master.DsLocal)\Control\Bootstrap.ini")
			$bsContent = $bsContent | EasyReplace -A $mstFqdnShare -B $nodeFqdnShare
			$bsContent = $bsContent | EasyReplace -A "$($config.master.ComputerName).$($config.master.Domain)" -B "$($node.ComputerName).$($node.Domain)"
			$bsContent = $bsContent | EasyReplace -A $mstShare -B $nodeShare
			$bsContent = $bsContent | EasyReplace -A $config.master.ComputerName -B $node.ComputerName
			$bsContent | Set-Content -Path "\\$nodeFqdnShare\Control\Bootstrap.ini" -Force
		}
		
		if ($CustomSettings) {
			$Logger.Log("Syncing CustomSettings.ini")
			$csContent = (Get-Content -Path "$($config.master.DsLocal)\Control\CustomSettings.ini")
			$csContent = $csContent | EasyReplace -A $mstFqdnShare -B $nodeFqdnShare
			$csContent = $csContent | EasyReplace -A "$($config.master.ComputerName).$($config.master.Domain)" -B "$($node.ComputerName).$($node.Domain)"
			$csContent = $csContent | EasyReplace -A $mstShare -B $nodeShare
			$csContent = $csContent | EasyReplace -A $config.master.ComputerName -B $node.ComputerName
			$csContent | Set-Content -Path "\\$nodeFqdnShare\Control\CustomSettings.ini" -Force
		}
		
		if ($Buildboot){
			BuildBoot -Node ($node)
		}
	}
}

function BuildBoot {
	param (
		[Parameter(Position = 0, Mandatory = $true)]
		$Node,
		
		[Parameter(Position = 1, Mandatory = $false)]
		[switch]$Rebuild
	)
	
	Invoke-Command -ComputerName $Node.Computername -ScriptBlock {
		param (
			$node
		)
		Import-Module "C:\Program Files\Microsoft Deployment Toolkit\Bin\MicrosoftDeploymentToolkit.psd1"
		
		New-PSDrive -Name "DS" -PSProvider MDTProvider -Root $node.DsLocal

		#Update-MDTDeploymentShare -path "DS:" -Force -Verbose -Compress
		
		& wdsutil.exe /Verbose /Progress /Replace-Image /Image:"Lite Touch Windows PE (x64)" /ImageType:Boot /Architecture:x64 /ReplacementImage /ImageFile:"$($node.DsLocal)\Boot\LiteTouchPE_x64.wim"
		
		Remove-PSDrive -Name "DS"

	} -ArgumentList $Node
	
}

function EasyReplace {
	[cmdletbinding()]
	param (
		[parameter(ValueFromPipeline)]
		[string[]]$Main,
		
		[string]$A,
		
		[string]$B
	)
	
	begin {
		$aEsc = [System.Text.RegularExpressions.Regex]::Escape($A)
		[String[]]$ret = $null
	}
	
	process {
		$ret += ($Main -replace ($aEsc, $B))
	}
	
	end {
		return $ret
	}
	
}

function SyncFolder {
	[cmdletbinding()]
	param (
		[Parameter(Position = 0, Mandatory = $true, ParameterSetName = "ByDir")]
		[string] $Source,
		
		[Parameter(Position = 0, Mandatory = $true, ParameterSetName = "ByRef")]
		[ref] $SourceRef,
		
		[Parameter(Position = 0, Mandatory = $true, ParameterSetName = "ByDir")]
		[Parameter(Position = 1, Mandatory = $true, ParameterSetName = "ByRef")]
		[string] $Destination,
		
		[Parameter(Position = 2, Mandatory = $false, ParameterSetName = "ByDir")]
		[string] $Filter = "*.*",
		
		[Parameter(Position = 0, Mandatory = $false, ParameterSetName = "ByDir")]
		[Parameter(Position = 3, Mandatory = $false, ParameterSetName = "ByRef")]
		[switch] $FullSync
		
	)
	
	if ( !( Test-Path $Destination) ){
			Try {
				New-Item -ItemType directory -Path "$Destination" -ErrorAction Stop 
			} Catch {
				$Logger.Log("`tUnable to create folder ""$Destination"".`n $($_.Exception)")
			}
	}
	
	if ($Source) {
		$Logger.Log("`tReading source folder ""$Source""")
		$srcItems = Get-ChildItem $Source -Recurse -Filter $filter | select Name, Length, LastWriteTime, FullName, PSIsContainer
	} else {
		$srcItems = $SourceRef.Value
		$Source = ($srcItems.PSParentPath[0] -split '::')[1]
	}
	
	$Logger.Log("`tReading destination folder ""$Destination""")
	$dstItems = Get-ChildItem $Destination -Recurse -Filter $filter | select Name, Length, LastWriteTime, FullName, PSIsContainer
	
	$Logger.Log("`tComparing files. SRC($($srcItems.length)) vs. DST($($dstItems.length))")
	if ($dstItems.length -gt 0){
		$diffItems = Compare-Object -ReferenceObject $srcItems -DifferenceObject $dstItems -PassThru -Property Name, Length, LastWriteTime 
		$foldersToCreate = $diffItems | where { ($_.SideIndicator -eq '<=') -and ($_.PSIsContainer) }
		$filesToCopy = $diffItems | where { ($_.SideIndicator -eq '<=') -and (!($_.PSIsContainer)) }
	} else {
		$foldersToCreate = $srcItems | where { $_.PSIsContainer }
		$filesToCopy = $srcItems | where { (!($_.PSIsContainer)) }
	}
	
	
	$Logger.Log("`tCreating $($foldersToCreate.length) folders on destination")
	foreach ($item in $foldersToCreate ){
		$relPath = $item.FullName | EasyReplace -A $Source -B ''
		
		if (!(Test-Path "$Destination$relPath")){
			Try {
				New-Item -ItemType directory -Path "$Destination$relPath" -ErrorAction Stop 
				$item | Add-Member -MemberType NoteProperty -Name Done -Value $true -Force 
			} Catch {
				$Logger.Log("`tUnable to create folder ""$Destination$relPath"".`n $($_.Exception)")
			}
		}
	}
	
	
	$Logger.Log("`tCopying $($filesToCopy.length) files to destination")
	foreach ($item in $filesToCopy ){
		$relPath = $item.FullName -ireplace [regex]::Escape($Source), ''
		
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