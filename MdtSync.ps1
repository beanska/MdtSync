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
	
	#New-PSDrive -Name SRC -PSProvider FileSystem -Root $config.master.DsLocal
	
	foreach ($node in $config.node) {
	
		$nodeFqdnShare = "$($node.ComputerName).$($node.Domain)\$($node.Share)"
		$nodeShare = "$($node.ComputerName)\$($node.Share)"
		write-host $nodeFqdnShare
		
		if ( Test-Path "c:\windows\temp\$($node.ComputerName)") {
			$dst = "c:\windows\temp\$($node.ComputerName)"
		} else {
			$dstSL = New-SymLink -SymName "c:\windows\temp\$($node.ComputerName)" -Path "\\$($node.ComputerName).$($node.Domain)\$($node.Share)" -Directory
			$dst = $dstSL.Path
		}
		
		
		#### $dstItems = Get-ChildItem 'DST:\' -Recurse -Filter $filter -ErrorAction Stop | select Name, Length, LastWriteTime, FullName, PSIsContainer 
		#### $test = Get-ChildItem "DST:\Control\APPINST" -Recurse -Filter * | select Name, Length, LastWriteTime, FullName, PSIsContainer
		
		if ($Apps) {
			$Logger.Log("Syncing Apps")
			if ($srcApps.Length -lt 1){
				$srcApps = Get-ChildItem "$($config.master.DsLocal)\Applications" -Recurse -Filter $filter | select Name, Length, LastWriteTime, FullName, PSIsContainer, PSParentPath
			}
			SyncFolder -SourceRef ([ref]$srcApps) -Destination "$dst\Applications" -FullSync
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "$dst\Control" -Filter 'ApplicationGroups.xml'
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "$dst\Control" -Filter 'Applications.xml'
		}
		
		if ($OS) {
			$Logger.Log("Syncing Operating Systems")
			if ($srcOs.Length -lt 1){
				$srcOs = Get-ChildItem "$($config.master.DsLocal)\Operating Systems" -Recurse -Filter $filter | select Name, Length, LastWriteTime, FullName, PSIsContainer, PSParentPath
			}
			SyncFolder -SourceRef ([ref]$srcOs) -Destination "$dst\Operating Systems" -FullSync
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "$dst\Control" -Filter 'OperatingSystemGroups.xml'
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "$dst\Control" -Filter 'OperatingSystems.xml'
		}
		
		if ($Drivers) {
			$Logger.Log("Syncing Drivers")
			if ($srcDrivers.Length -lt 1){
				$srcDrivers = Get-ChildItem "$($config.master.DsLocal)\Out-of-Box Drivers" -Recurse -Filter $filter | select Name, Length, LastWriteTime, FullName, PSIsContainer, PSParentPath
			}
			SyncFolder -SourceRef ([ref]$srcDrivers) -Destination "$dst\Out-of-Box Drivers" -FullSync
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "$dst\Control" -Filter 'DriverGroups.xml'
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "$dst\Control" -Filter 'Drivers.xml'
		}
		
		if ($Packages) {
			$Logger.Log("Syncing Packages")
			if ($srcPackages.Length -lt 1){
				$srcPackages = Get-ChildItem "$($config.master.DsLocal)\Packages" -Recurse -Filter $filter | select Name, Length, LastWriteTime, FullName, PSIsContainer, PSParentPath
			}
			SyncFolder -SourceRef ([ref]$srcPackages) -Destination "$dst\Packages" -FullSync
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "$dst\Control" -Filter 'PackageGroups.xml'
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "$dst\Control" -Filter 'Packages.xml'
		}
		
		if ($Ts) {
			$Logger.Log("Syncing Task Sequences")
			$TsFolders = Get-ChildItem "$($config.master.DsLocal)\Control" | Where {$_.PSIsContainer}
			foreach ($folder in $TsFolders){
				$Logger.Log("Syncing ""$($folder.FullName)"" to ""$dst\control\$($folder.Name)""")
				SyncFolder -Source $folder.FullName -Destination "$dst\control\$($folder.Name)" 		
			}
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "$dst\Control" -Filter 'TaskSequenceGroups.xml'
			SyncFolder -Source "$($config.master.DsLocal)\Control" -Destination "$dst\Control" -Filter 'TaskSequences.xml'
		}
		
		if ($Scripts) {
			$Logger.Log("Syncing Scripts")
			if ($srcScripts.Length -lt 1){
				$srcScripts = Get-ChildItem "$($config.master.DsLocal)\Scripts" -Recurse -Filter $filter | select Name, Length, LastWriteTime, FullName, PSIsContainer, PSParentPath
			}
			SyncFolder -SourceRef ([ref]$srcScripts) -Destination "$dst\Scripts" -FullSync
		}
		
		if ($Bootstrap) {
			$Logger.Log("Syncing Bootstrap.ini")		
			$bsContent = (Get-Content -Path "$($config.master.DsLocal)\Control\Bootstrap.ini")
			$bsContent = $bsContent | EasyReplace -A $mstFqdnShare -B "$($node.ComputerName).$($node.Domain)\$($node.Share)"
			$bsContent = $bsContent | EasyReplace -A "$($config.master.ComputerName).$($config.master.Domain)" -B "$($node.ComputerName).$($node.Domain)"
			$bsContent = $bsContent | EasyReplace -A $mstShare -B $nodeShare
			$bsContent = $bsContent | EasyReplace -A $config.master.ComputerName -B $node.ComputerName
			$bsContent | Set-Content -Path "$dst\Control\Bootstrap.ini" -Force
		}
		
		if ($CustomSettings) {
			$Logger.Log("Syncing CustomSettings.ini")
			$csContent = (Get-Content -Path "$($config.master.DsLocal)\Control\CustomSettings.ini")
			$csContent = $csContent | EasyReplace -A $mstFqdnShare -B "$($node.ComputerName).$($node.Domain)\$($node.Share)"
			$csContent = $csContent | EasyReplace -A "$($config.master.ComputerName).$($config.master.Domain)" -B "$($node.ComputerName).$($node.Domain)"
			$csContent = $csContent | EasyReplace -A $mstShare -B $nodeShare
			$csContent = $csContent | EasyReplace -A $config.master.ComputerName -B $node.ComputerName
			$csContent | Set-Content -Path "$dst\Control\CustomSettings.ini" -Force
		}
		
		if ($Buildboot){
			BuildBoot -Node ($node)
		}
		
		#Remove-PSDrive -Name DST
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
		[string] $Filter = "*",
		
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
		[array]$srcItems = Get-ChildItem $Source -Recurse -Filter $filter | select Name, Length, LastWriteTime, FullName, PSIsContainer 
	} else {
		$srcItems = $SourceRef.Value
		$Source = ($srcItems.PSParentPath[0] -split '::')[1]
	}
	
	$Logger.Log("`tReading destination folder ""$Destination""")
	Try {
		[array]$dstItems = Get-ChildItem $Destination -Recurse -Filter $filter -ErrorAction Stop | select Name, Length, LastWriteTime, FullName, PSIsContainer 
	} Catch {
		$Error
	}
	
	$Logger.Log("`tComparing files. SRC($($srcItems.length)) vs. DST($($dstItems.length))")
	if ($dstItems.length -gt 0){
		Try {
			#$diffItems = Compare-Object -ReferenceObject $srcItems -DifferenceObject $dstItems -PassThru -Property Name, Length -ErrorAction Stop
			$diffFiles = Compare-Object -ReferenceObject $srcItems -DifferenceObject $dstItems -PassThru -Property Name, Length, LastWriteTime -ErrorAction Stop |
				where { $_.PSIsContainer -eq $false}
			$diffFolders = Compare-Object -ReferenceObject $srcItems -DifferenceObject $dstItems -PassThru -Property Name, Length -ErrorAction Stop | 
				where { $_.PSIsContainer -eq $true}
		} Catch {
			$Error.exception
		}
		$foldersToCreate = $diffFolders | where { $_.SideIndicator -eq '<=' }
		$filesToCopy = $diffFiles | where { $_.SideIndicator -eq '<=' }
	} else {
		$foldersToCreate = $diffFolders
		$filesToCopy = $diffFiles
	}
	
	
	$Logger.Log("`tCreating $($foldersToCreate.length) folders on destination")
	foreach ($item in $foldersToCreate ){
		$relPath = $item.FullName | EasyReplace -A $Source -B ''
				
		if (!(Test-Path "$Destination$relPath")){
			Try {
				New-Item -ItemType directory -Path "$Destination$relPath" -ErrorAction Stop | Out-Null
				$item | Add-Member -MemberType NoteProperty -Name Done -Value $true -Force 
			} Catch {
				$Logger.Log("`tUnable to create folder ""$Destination$relPath"".`n $($_.Exception)")
			}
		}
	}
	
	
	$Logger.Log("`tCopying $($filesToCopy.length) files to destination")
	foreach ($item in $filesToCopy ){
		$relPath = $item.FullName | EasyReplace -A $Source -B ''
		$Logger.Log("`tCopying ""$($item.FullName)"" to ""$("$Destination$relPath")""")
		Try {
			Copy-Item -Path $item.FullName -Destination "$Destination$relPath" -ErrorAction Stop -force | Out-Null
			$item | Add-Member -MemberType NoteProperty -Name Done -Value $true -Force 
			
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

Function New-SymLink {
    <#
        .SYNOPSIS
            Creates a Symbolic link to a file or directory
        .DESCRIPTION
            Creates a Symbolic link to a file or directory as an alternative to mklink.exe
        .PARAMETER Path
            Name of the path that you will reference with a symbolic link.
        .PARAMETER SymName
            Name of the symbolic link to create. Can be a full path/unc or just the name.
            If only a name is given, the symbolic link will be created on the current directory that the
            function is being run on.
        .PARAMETER File
            Create a file symbolic link
        .PARAMETER Directory
            Create a directory symbolic link
        .NOTES
            Name: New-SymLink
            Author: Boe Prox
            Created: 15 Jul 2013
        .EXAMPLE
            New-SymLink -Path "C:\users\admin\downloads" -SymName "C:\users\admin\desktop\downloads" -Directory
            SymLink                          Target                   Type
            -------                          ------                   ----
            C:\Users\admin\Desktop\Downloads C:\Users\admin\Downloads Directory
            Description
            -----------
            Creates a symbolic link to downloads folder that resides on C:\users\admin\desktop.
        .EXAMPLE
            New-SymLink -Path "C:\users\admin\downloads\document.txt" -SymName "SomeDocument" -File
            SymLink                             Target                                Type
            -------                             ------                                ----
            C:\users\admin\desktop\SomeDocument C:\users\admin\downloads\document.txt File
            Description
            -----------
            Creates a symbolic link to document.txt file under the current directory called SomeDocument.
    #>
	[cmdletbinding(
				   DefaultParameterSetName = 'Directory',
				   SupportsShouldProcess = $True
				   )]
	Param (
		[parameter(Position = 0, ParameterSetName = 'Directory', ValueFromPipeline = $True,
				   ValueFromPipelineByPropertyName = $True, Mandatory = $True)]
		[parameter(Position = 0, ParameterSetName = 'File', ValueFromPipeline = $True,
				   ValueFromPipelineByPropertyName = $True, Mandatory = $True)]
		[ValidateScript({
			If (Test-Path $_) { $True } Else {
				Throw "`'$_`' doesn't exist!"
			}
		})]
		[string]$Path,
		[parameter(Position = 1, ParameterSetName = 'Directory')]
		[parameter(Position = 1, ParameterSetName = 'File')]
		[string]$SymName,
		[parameter(Position = 2, ParameterSetName = 'File')]
		[switch]$File,
		[parameter(Position = 2, ParameterSetName = 'Directory')]
		[switch]$Directory
	)
	Begin {
		Try {
			$null = [mklink.symlink]
		} Catch {
			Add-Type @"
            using System;
            using System.Runtime.InteropServices;
 
            namespace mklink
            {
                public class symlink
                {
                    [DllImport("kernel32.dll")]
                    public static extern bool CreateSymbolicLink(string lpSymlinkFileName, string lpTargetFileName, int dwFlags);
                }
            }
"@
		}
	}
	Process {
		#Assume target Symlink is on current directory if not giving full path or UNC
		If ($SymName -notmatch "^(?:[a-z]:\\)|(?:\\\\\w+\\[a-z]\$)") {
			$SymName = "{0}\{1}" -f $pwd, $SymName
		}
		$Flag = @{
			File = 0
			Directory = 1
		}
		If ($PScmdlet.ShouldProcess($Path, 'Create Symbolic Link')) {
			Try {
				$return = [mklink.symlink]::CreateSymbolicLink($SymName, $Path, $Flag[$PScmdlet.ParameterSetName])
				If ($return) {
					$object = New-Object PSObject -Property @{
						SymLink = $SymName
						Target = $Path
						Type = $PScmdlet.ParameterSetName
					}
					$object.pstypenames.insert(0, 'System.File.SymbolicLink')
					$object
				} Else {
					Throw "Unable to create symbolic link!"
				}
			} Catch {
				Write-warning ("{0}: {1}" -f $path, $_.Exception.Message)
			}
		}
	}
}




main