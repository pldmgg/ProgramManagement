[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Get public and private function definition files.
[array]$Public  = Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
[array]$Private = Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue
$ThisModule = $(Get-Item $PSCommandPath).BaseName

# Dot source the Private functions
foreach ($import in $Private) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

[System.Collections.Arraylist]$ModulesToInstallAndImport = @()
if (Test-Path "$PSScriptRoot\module.requirements.psd1") {
    $ModuleManifestData = Import-PowerShellDataFile "$PSScriptRoot\module.requirements.psd1"
    $ModuleManifestData.Keys | Where-Object {$_ -ne "PSDependOptions"} | foreach {$null = $ModulesToinstallAndImport.Add($_)}
}

if ($ModulesToInstallAndImport.Count -gt 0) {
    # NOTE: If you're not sure if the Required Module is Locally Available or Externally Available,
    # add it the the -RequiredModules string array just to be certain
    $InvModDepSplatParams = @{
        RequiredModules                     = $ModulesToInstallAndImport
        InstallModulesNotAvailableLocally   = $True
        ErrorAction                         = "SilentlyContinue"
        WarningAction                       = "SilentlyContinue"
    }
    $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
}

# Public Functions



<#
    .SYNOPSIS
        This function gathers information about a particular installed program from 3 different sources:
            - The Get-Package Cmdlet fromPowerShellGet/PackageManagement Modules
            - Chocolatey CmdLine (if it is installed)
            - Windows Registry

        All of this information is needed in order to determine the proper way to install/uninstall a program.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER ProgramName
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of the Program that you would like to gather information about.
        The name of the program does NOT have to be exact. For example, if you have 'python3' installed, you can simply use:
            Get-AllPackageInfo python

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -
        
        PS C:\Users\zeroadmin> Get-AllPackageInfo openssh
#>
function Get-AllPackageInfo {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$True,
            Position=0
        )]
        [string]$ProgramName
    )

    # Generate regex string to loosely match Program Name
    $PNRegexPrep = $([char[]]$ProgramName | foreach {"([\.]|[$_])+"}) -join ""
    $PNRegexPrep2 = $($PNRegexPrep -split "\+")[1..$($($PNRegexPrep -split "\+").Count)] -join "+"
    $PNRegex = "^$([char[]]$ProgramName[0])+$PNRegexPrep2"
    # For example, $PNRegex string for $ProgramName 'nodejs' should be:
    #     ^n+([\.]|[o])+([\.]|[d])+([\.]|[e])+([\.]|[j])+([\.]|[s])+

    # If PackageManagement/PowerShellGet is installed, determine if $ProgramName is installed
    if ([bool]$(Get-Command Get-Package -ErrorAction SilentlyContinue)) {
        $PSGetInstalledPrograms = Get-Package
        $PSGetInstalledPackageObjectsFinal = $PSGetInstalledPrograms | Where-Object {$_.Name -match $PNRegex}

        # Add some more information regarding these packages - specifically MSIFileItem, MSILastWriteTime, and RegLastWriteTime
        # This info will come in handy if there's a specific order related packages needed to be uninstalled in so that it's clean.
        # (In other words, with this info, we can sort by when specific packages were installed, and uninstall latest to earliest
        # so that there aren't any race conditions)
        [array]$CheckInstalledPrograms = Get-InstalledProgramsFromRegistry -ProgramTitleSearchTerm $PNRegex
        $WindowsInstallerMSIs = Get-ChildItem -Path "C:\Windows\Installer" -File
        $RelevantMSIFiles = foreach ($FileItem in $WindowsInstallerMSIs) {
            $MSIProductName = GetMSIFileInfo -Path $FileItem.FullName -Property ProductName -WarningAction SilentlyContinue
            if ($MSIProductName -match $PNRegex) {
                [pscustomobject]@{
                    ProductName = $MSIProductName
                    FileItem    = $FileItem
                }
            }
        }
        
        if ($CheckInstalledPrograms.Count -gt 0) {
            if ($($(Get-Item $CheckInstalledPrograms[0].PSPath) | Get-Member).Name -notcontains "LastWriteTime") {
                AddLastWriteTimeToRegKeys
            }

            foreach ($RegPropertiesCollection in $CheckInstalledPrograms) {
                $RegPropertiesCollection | Add-Member -MemberType NoteProperty -Name "LastWriteTime" -Value $(Get-Item $RegPropertiesCollection.PSPath).LastWriteTime
            }
            [System.Collections.ArrayList]$CheckInstalledPrograms = [System.Collections.ArrayList][array]$($CheckInstalledPrograms | Sort-Object -Property LastWriteTime)
            # Make sure that the LATEST Registry change comes FIRST in the ArrayList
            $CheckInstalledPrograms.Reverse()

            foreach ($Package in $PSGetInstalledPackageObjectsFinal) {
                $RelevantMSIFile = $RelevantMSIFiles | Where-Object {$_.ProductName -eq $Package.Name}
                $Package | Add-Member -MemberType NoteProperty -Name "MSIFileItem" -Value $RelevantMSIFile.FileItem
                $Package | Add-Member -MemberType NoteProperty -Name "MSILastWriteTime" -Value $RelevantMSIFile.FileItem.LastWriteTime

                if ($Package.TagId -ne $null) {
                    $RegProperties = $CheckInstalledPrograms | Where-Object {$_.PSChildName -match $Package.TagId}
                    $LastWriteTime = $(Get-Item $RegProperties.PSPath).LastWriteTime
                    $Package | Add-Member -MemberType NoteProperty -Name "RegLastWriteTime" -Value $LastWriteTime
                }
            }
            [System.Collections.ArrayList]$PSGetInstalledPackageObjectsFinal = [array]$($PSGetInstalledPackageObjectsFinal | Sort-Object -Property MSILastWriteTime)
            # Make sure that the LATEST install comes FIRST in the ArrayList
            $PSGetInstalledPackageObjectsFinal.Reverse()
        }        
    }

    # If the Chocolatey CmdLine is installed, get a list of programs installed via Chocolatey
    if ([bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
        #$ChocolateyInstalledProgramsPrep = clist --local-only
        
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
        $ProcessInfo.FileName = $(Get-Command clist).Source
        $ProcessInfo.RedirectStandardError = $true
        $ProcessInfo.RedirectStandardOutput = $true
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.Arguments = "--local-only"
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Process.Start() | Out-Null
        # Below $FinishedInAlottedTime returns boolean true/false
        $FinishedInAlottedTime = $Process.WaitForExit(15000)
        if (!$FinishedInAlottedTime) {
            $Process.Kill()
        }
        $stdout = $Process.StandardOutput.ReadToEnd()
        $stderr = $Process.StandardError.ReadToEnd()
        $AllOutput = $stdout + $stderr

        $ChocolateyInstalledProgramsPrep = $($stdout -split "`n")[1..$($($stdout -split "`n").Count-3)]

        [System.Collections.ArrayList]$ChocolateyInstalledProgramObjects = @()

        foreach ($program in $ChocolateyInstalledProgramsPrep) {
            $programParsed = $program -split " "
            $PSCustomObject = [pscustomobject]@{
                ProgramName     = $programParsed[0]
                Version         = $programParsed[1]
            }

            $null = $ChocolateyInstalledProgramObjects.Add($PSCustomObject)
        }

        $ChocolateyInstalledProgramObjectsFinal = $ChocolateyInstalledProgramObjects | Where-Object {$_.ProgramName -match $PNRegex}
    }

    [pscustomobject]@{
        ChocolateyInstalledProgramObjects           = $ChocolateyInstalledProgramObjectsFinal
        PSGetInstalledPackageObjects                = $PSGetInstalledPackageObjectsFinal
        RegistryProperties                          = $CheckInstalledPrograms
    }
}


<#
    .SYNOPSIS
        This function gathers information about programs installed on the specified Hosts by inspecting
        the Windows Registry.

        If you do NOT use the -ProgramTitleSearchTerm parameter, information about ALL programs installed on
        the specified hosts will be returned.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

        If you're looking for detailed information about an installed Program, or if you're looking to generate a list
        that closely resembles what you see in the 'Control Panel' 'Programs and Features' GUI, use this function.

    .PARAMETER ProgramTitleSearchTerm
        This parameter is OPTIONAL.

        This parameter takes a string that loosely matches the Program Name that you would like
        to gather information about. You can use regex with with this parameter.

        If you do NOT use this parameter, a list of ALL programs installed on the 

    .PARAMETER HostName
        This parameter is OPTIONAL, but is defacto mandatory since it defaults to $env:ComputerName.

        This parameter takes an array of string representing DNS-Resolveable host names that this function will
        attempt to gather Program Installation information from.

    .PARAMETER AllADWindowsComputers
        This parameter is OPTIONAL.

        This parameter is a switch. If it is used, this function will use the 'Get-ADComputer' cmdlet from the ActiveDirectory
        PowerShell Module (from RSAT) in order to generate a list of Computers on the domain. It will then get program information
        from each of those computers.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-InstalledProgramsFromRegistry -ProgramTitleSearchTerm openssh
#>
function Get-InstalledProgramsFromRegistry {
    [CmdletBinding(
        PositionalBinding=$True,
        DefaultParameterSetName='Default Param Set'
    )]
    Param(
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Default Param Set'
        )]
        [string]$ProgramTitleSearchTerm,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Default Param Set'
        )]
        [string[]]$HostName,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Secondary Param Set'
        )]
        [switch]$AllADWindowsComputers
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$HostName -and !$AllADWindowsComputers) {
        [string[]]$HostName = @($env:ComputerName)
    }

    $uninstallWow6432Path = "\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $uninstallPath = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

    $RegPaths = @(
        "HKLM:$uninstallWow6432Path",
        "HKLM:$uninstallPath",
        "HKCU:$uninstallWow6432Path",
        "HKCU:$uninstallPath"
    )
    
    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####
    # Get a list of Windows Computers from AD
    if ($AllADWindowsComputers) {
        if (!$(Get-Module -ListAvailable ActiveDirectory)) {
            Write-Error "The ActiveDirectory PowerShell Module (from RSAT) is not installed on this machine (i.e. $env:ComputerName)! Unable to get a list of Computers from Active Directory. Halting!"
            $global:FunctionResult = "1"
            return
        }
        if (!$(Get-Module ActiveDirectory)) {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
            }
            catch {
                Write-Error $_
                Write-Error "Problem importing the PowerShell Module 'ActiveDirectory'! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if (!$(Get-Command Get-ADComputer)) {
            Write-Error "Unable to find the cmdlet 'Get-ADComputer'! Unable to get a list of Computers from Active Directory. Halting!"
            $global:FunctionResult = "1"
            return
        }
        [array]$ComputersArray = $(Get-ADComputer -Filter * -Property * | Where-Object {$_.OperatingSystem -like "*Windows*"}).Name
    }
    else {
        [array]$ComputersArray = $HostName
    }

    foreach ($computer in $ComputersArray) {
        if ($computer -eq $env:ComputerName -or $computer.Split("\.")[0] -eq $env:ComputerName) {
            try {
                $InstalledPrograms = foreach ($regpath in $RegPaths) {if (Test-Path $regpath) {Get-ItemProperty $regpath}}
                if (!$InstalledPrograms) {
                    throw
                }
            }
            catch {
                Write-Warning "Unable to find registry path(s) on $computer. Skipping..."
                continue
            }
        }
        else {
            try {
                $InstalledPrograms = Invoke-Command -ComputerName $computer -ScriptBlock {
                    foreach ($regpath in $RegPaths) {
                        if (Test-Path $regpath) {
                            Get-ItemProperty $regpath
                        }
                    }
                } -ErrorAction SilentlyContinue
                if (!$InstalledPrograms) {
                    throw
                }
            }
            catch {
                Write-Warning "Unable to connect to $computer. Skipping..."
                continue
            }
        }

        if ($ProgramTitleSearchTerm) {
            $InstalledPrograms | Where-Object {$_.DisplayName -match "$ProgramTitleSearchTerm"}
        }
        else {
            $InstalledPrograms
        }
    }

    ##### END Main Body #####

}


<#
    .SYNOPSIS
        Installs the Chocolatey Command Line (i.e. choco.exe and related binaries)

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER UpdatePackageManagement
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to update PowerShellGet/PackageManagement Modules prior to attempting
        Chocolatey CmdLine install.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Install-ChocolateyCmdLine

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -
        
        PS C:\Users\zeroadmin> Install-ChocolateyCmdLine -UpdatePackageManagement

#>
function Install-ChocolateyCmdLine {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [switch]$UpdatePackageManagement
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    # Invoke-WebRequest fix...
    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

    if (!$(GetElevation)) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function must be ran from an elevated PowerShell Session (i.e. 'Run as Administrator')! Halting!"
        $global:FunctionResult = "1"
        return
    }

    Write-Host "Please wait..."
    $global:FunctionResult = "0"
    $MyFunctionsUrl = "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyFunctions"

    if ($UpdatePackageManagement) {
        if (![bool]$(Get-Command Update-PackageManagement -ErrorAction SilentlyContinue)) {
            $UpdatePMFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Update-PackageManagement.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($UpdatePMFunctionUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to load the Update-PackageManagement function! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        try {
            $global:FunctionResult = "0"
            $UPMResult = Update-PackageManagement -AddChocolateyPackageProvider -ErrorAction SilentlyContinue -ErrorVariable UPMErr
            if ($global:FunctionResult -eq "1" -or $UPMResult -eq $null) {throw "The Update-PackageManagement function failed!"}
        }
        catch {
            Write-Error $_
            Write-Host "Errors from the Update-PackageManagement function are as follows:"
            Write-Error $($UPMErr | Out-String)
            $global:FunctionResult = "1"
            return
        }
    }

    if (![bool]$(Get-Command Update-ChocolateyEnv -ErrorAction SilentlyContinue)) {
        $RefreshCEFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Update-ChocolateyEnv.ps1"
        try {
            Invoke-Expression $([System.Net.WebClient]::new().DownloadString($RefreshCEFunctionUrl))
        }
        catch {
            Write-Error $_
            Write-Error "Unable to load the Update-ChocolateyEnv function! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
        # The below Install-Package Chocolatey screws up $env:Path, so restore it afterwards
        $OriginalEnvPath = $env:Path

        # Installing Package Providers is spotty sometimes...Using while loop 3 times before failing
        $Counter = 0
        while ($(Get-PackageProvider).Name -notcontains "Chocolatey" -and $Counter -lt 3) {
            Install-PackageProvider -Name Chocolatey -Force -Confirm:$false -WarningAction SilentlyContinue
            $Counter++
            Start-Sleep -Seconds 5
        }
        if ($(Get-PackageProvider).Name -notcontains "Chocolatey") {
            Write-Error "Unable to install the Chocolatey Package Provider / Repo for PackageManagement/PowerShellGet! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if (![bool]$(Get-Package -Name Chocolatey -ProviderName Chocolatey -ErrorAction SilentlyContinue)) {
            # NOTE: The PackageManagement install of choco is unreliable, so just in case, fallback to the Chocolatey cmdline for install
            $null = Install-Package Chocolatey -Provider Chocolatey -Force -Confirm:$false -ErrorVariable ChocoInstallError -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            
            if ($ChocoInstallError.Count -gt 0) {
                Write-Warning "There was a problem installing the Chocolatey CmdLine via PackageManagement/PowerShellGet!"
                $InstallViaOfficialScript = $True
                Uninstall-Package Chocolatey -Force -ErrorAction SilentlyContinue
            }

            if ($ChocoInstallError.Count -eq 0) {
                $PMPGetInstall = $True
            }
        }

        # Try and find choco.exe
        try {
            Write-Host "Refreshing `$env:Path..."
            $global:FunctionResult = "0"
            $null = Update-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
            
            if ($RCEErr.Count -gt 0 -and
            $global:FunctionResult -eq "1" -and
            ![bool]$($RCEErr -match "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed!")) {
                throw "The Update-ChocolateyEnv function failed! Halting!"
            }
        }
        catch {
            Write-Error $_
            Write-Host "Errors from the Update-ChocolateyEnv function are as follows:"
            Write-Error $($RCEErr | Out-String)
            $global:FunctionResult = "1"
            return
        }

        if ($PMPGetInstall) {
            # It's possible that PowerShellGet didn't run the chocolateyInstall.ps1 script to actually install the
            # Chocolatey CmdLine. So do it manually.
            if (Test-Path "C:\Chocolatey") {
                $ChocolateyPath = "C:\Chocolatey"
            }
            elseif (Test-Path "C:\ProgramData\chocolatey") {
                $ChocolateyPath = "C:\ProgramData\chocolatey"
            }
            else {
                Write-Warning "Unable to find Chocolatey directory! Halting!"
                Write-Host "Installing via official script at https://chocolatey.org/install.ps1"
                $InstallViaOfficialScript = $True
            }
            
            if ($ChocolateyPath) {
                $ChocolateyInstallScript = $(Get-ChildItem -Path $ChocolateyPath -Recurse -File -Filter "*chocolateyinstall.ps1").FullName | Where-Object {
                    $_ -match ".*?chocolatey\.[0-9].*?chocolateyinstall.ps1$"
                }

                if (!$ChocolateyInstallScript) {
                    Write-Warning "Unable to find chocolateyinstall.ps1!"
                    $InstallViaOfficialScript = $True
                }
            }

            if ($ChocolateyInstallScript) {
                try {
                    Write-Host "Trying PowerShellGet Chocolatey CmdLine install script from $ChocolateyInstallScript ..." -ForegroundColor Yellow
                    & $ChocolateyInstallScript
                }
                catch {
                    Write-Error $_
                    Write-Error "The Chocolatey Install Script $ChocolateyInstallScript has failed!"

                    if ([bool]$(Get-Package $ProgramName)) {
                        Uninstall-Package Chocolatey -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }

        # If we still can't find choco.exe, then use the Chocolatey install script from chocolatey.org
        if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue) -or $InstallViaOfficialScript) {
            $ChocolateyInstallScriptUrl = "https://chocolatey.org/install.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($ChocolateyInstallScriptUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to install Chocolatey via the official chocolatey.org script! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $PMPGetInstall = $False
        }
        
        # If we STILL can't find choco.exe, then Update-ChocolateyEnv a third time...
        #if (![bool]$($env:Path -split ";" -match "chocolatey\\bin")) {
        if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
            # ...and then find it again and add it to $env:Path via Update-ChocolateyEnv function
            if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
                try {
                    Write-Host "Refreshing `$env:Path..."
                    $global:FunctionResult = "0"
                    $null = Update-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
                    
                    if ($RCEErr.Count -gt 0 -and
                    $global:FunctionResult -eq "1" -and
                    ![bool]$($RCEErr -match "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed!")) {
                        throw "The Update-ChocolateyEnv function failed! Halting!"
                    }
                }
                catch {
                    Write-Error $_
                    Write-Host "Errors from the Update-ChocolateyEnv function are as follows:"
                    Write-Error $($RCEErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }
        }

        # If we STILL can't find choco.exe, then give up...
        if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find choco.exe after install! Check your `$env:Path! Halting!"
            $global:FunctionResult = "1"
            return
        }
        else {
            Write-Host "Finished installing Chocolatey CmdLine." -ForegroundColor Green

            try {
                cup chocolatey-core.extension -y
            }
            catch {
                Write-Error "Installation of chocolatey-core.extension via the Chocolatey CmdLine failed! Halting!"
                $global:FunctionResult = "1"
                return
            }

            try {
                Write-Host "Refreshing `$env:Path..."
                $global:FunctionResult = "0"
                $null = Update-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
                if ($RCEErr.Count -gt 0 -and $global:FunctionResult -eq "1") {
                    throw "The Update-ChocolateyEnv function failed! Halting!"
                }
            }
            catch {
                Write-Error $_
                Write-Host "Errors from the Update-ChocolateyEnv function are as follows:"
                Write-Error $($RCEErr | Out-String)
                $global:FunctionResult = "1"
                return
            }

            $ChocoModulesThatRefreshEnvShouldHaveLoaded = @(
                "chocolatey-core"
                "chocolateyInstaller"
                "chocolateyProfile"
                "chocolateysetup"
            )

            foreach ($ModName in $ChocoModulesThatRefreshEnvShouldHaveLoaded) {
                if ($(Get-Module).Name -contains $ModName) {
                    #Write-Host "The $ModName Module has been loaded from $($(Get-Module -Name $ModName).Path)" -ForegroundColor Green
                }
            }
        }
    }
    else {
        Write-Warning "The Chocolatey CmdLine is already installed!"
    }

    ##### END Main Body #####
}


<#
    .SYNOPSIS
        Install a Program using PowerShellGet/PackageManagement Modules OR the Chocolatey CmdLine.

    .DESCRIPTION
        This function was written to make program installation on Windows as easy and generic
        as possible by leveraging existing solutions such as PackageManagement/PowerShellGet
        and the Chocolatey CmdLine.

        Default behavior for this function (using only the -ProgramName parameter) is to try
        installation via PackageManagement/PowerShellGet. If that fails for whatever reason, then
        the Chocolatey CmdLine is used (it will be installed if it isn't already). You can use
        more specific parameters to change this default behavior (i.e. ONLY try installation via
        PowerShellGet/PackageManagement or ONLY try installation via Chocolatey CmdLine).

        If you use the -ResolveCommandPath parameter, this function will attempt to find the Main
        Executable associated with the Program you are installing. If the .exe does NOT have the
        same name as the Program, the function may need additional information provided via the
        -CommandName and/or -ExpectedInstallLocation parameters in order to find the Main Executable.

    .NOTES

    .PARAMETER ProgramName
        This parameter is MANDATORY.

        This paramter takes a string that represents the name of the program that you'd like to install.

    .PARAMETER CommandName
        This parameter is OPTIONAL.

        This parameter takes a string that represents the name of the main executable for the installed
        program. For example, if you are installing 'openssh', the value of this parameter should be 'ssh'.

    .PARAMETER PreRelease
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the latest version of the program in the pre-release branch
        (if one exists) will be installed.

    .PARAMETER GetPreviousVersion
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the version preceding the latest version of the program will
        be installed.

    .PARAMETER UsePowerShellGet
        This parameter is OPTIONAL.

        This parameter is a switch. If used the function will attempt program installation using ONLY
        PackageManagement/PowerShellGet Modules. If installation using those modules fails, the function
        halts and returns the relevant error message(s).

        Installation via the Chocolatey CmdLine will NOT be attempted.

    .PARAMETER ForceChocoInstallScript
        This parameter is OPTIONAL.

        This parameter is a switch. If the program being installed is from the Chocolatey Package Repository,
        using this parameter will force running the program's associated 'chocolateyinstall.ps1' script.
        This switch exists because some Chocolatey packages do NOT run 'chocolateyinstall.ps1' by default,
        meaning that 'Get-Package' could report that a program is 'Installed' when it actually is not.

    .PARAMETER UseChocolateyCmdLine
        This parameter is OPTIONAL.

        This parameter is a switch. If used the function will attempt installation using ONLY
        the Chocolatey CmdLine. (The Chocolatey CmdLine will be installed if it is not already).
        If installation via the Chocolatey CmdLine fails for whatever reason,
        the function halts and returns the relevant error message(s).

    .PARAMETER UpdatePackageManagement
        This parameter is OPTIONAL.

        This parameter is a switch. If used, PowerShellGet/PackageManagement Modules will be updated before
        any install actions take place.

        WARNING: If the Modules are updated, you may need to open a new PowerShell Session before they can be used.

    .PARAMETER ExpectedInstallLocation
        This parameter is OPTIONAL.

        This parameter takes a string that represents the full path to a directory that will contain
        main executable associated with the program to be installed. This directory does NOT have to
        be the immediate parent directory of the .exe.

        If you are absolutely certain you know where the Main Executable for the program to be installed
        will be, then use this parameter to speed things up.

    .PARAMETER ScanCDriveForMainExeIfNecessary
        This parameter is OPTIONAL.

        This parameter is a switch. If used in conjunction with the -CommandName parameter, this function will
        scan the entire C Drive until it finds a .exe that matches the values provided to the -CommandName parameter.

    .PARAMETER ResolveCommandPath
        This parameter is OPTIONAL.

        This parameter is a switch. This switch is meant to be used in situations where you are not certain what the
        name of the Main Executable of the program to be installed will be. This switch will provide an array of
        exe files associated with the program installation in the 'PossibleMainExecutables' property of the function's
        output.

    .PARAMETER Force
        This parameter is OPTIONAL.

        This parameter is a switch. If used, install will be attempted for the specified -ProgramName even if it is
        already installed.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Install-Program -ProgramName kubernetes-cli -CommandName kubectl.exe

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Install-Program -ProgramName awscli -CommandName aws.exe -UsePowerShellGet

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Install-Program -ProgramName VisualStudioCode -CommandName Code.exe -UseChocolateyCmdLine

    .EXAMPLE
        # If the Program Name and Main Executable are the same, then this is all you need for the function to find the Main Executable
        
        PS C:\Users\zeroadmin> Install-Program -ProgramName vagrant

#>
function Install-Program {
    [CmdletBinding(DefaultParameterSetName='ChocoCmdLine')]
    Param (
        [Parameter(
            Mandatory=$True,
            Position=0
        )]
        [string]$ProgramName,

        [Parameter(Mandatory=$False)]
        [string]$CommandName,

        [Parameter(Mandatory=$False)]
        [switch]$PreRelease,

        [Parameter(Mandatory=$False)]
        [switch]$GetPreviousVersion,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PackageManagement'
        )]
        [switch]$UsePowerShellGet,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PackageManagement'
        )]
        [switch]$ForceChocoInstallScript,

        [Parameter(Mandatory=$False)]
        [switch]$UseChocolateyCmdLine,

        [Parameter(Mandatory=$False)]
        [switch]$UpdatePackageManagement,

        [Parameter(Mandatory=$False)]
        [string]$ExpectedInstallLocation,

        [Parameter(Mandatory=$False)]
        [switch]$ScanCDriveForMainExeIfNecessary,

        [Parameter(Mandatory=$False)]
        [switch]$ResolveCommandPath,

        [Parameter(Mandatory=$False)]
        [switch]$Force
    )

    ##### BEGIN Native Helper Functions #####

    # The below function adds Paths from System PATH that aren't present in $env:Path (this probably shouldn't
    # be an issue, because $env:Path pulls from System PATH...but sometimes profile.ps1 scripts do weird things
    # and also $env:Path wouldn't necessarily be updated within the same PS session where a program is installed...)
    function Synchronize-SystemPathEnvPath {
        $SystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
        
        $SystemPathArray = $SystemPath -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
        $EnvPathArray = $env:Path -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
        
        # => means that $EnvPathArray HAS the paths but $SystemPathArray DOES NOT
        # <= means that $SystemPathArray HAS the paths but $EnvPathArray DOES NOT
        $PathComparison = Compare-Object $SystemPathArray $EnvPathArray
        [System.Collections.ArrayList][Array]$SystemPathsThatWeWantToAddToEnvPath = $($PathComparison | Where-Object {$_.SideIndicator -eq "<="}).InputObject

        if ($SystemPathsThatWeWantToAddToEnvPath.Count -gt 0) {
            foreach ($NewPath in $SystemPathsThatWeWantToAddToEnvPath) {
                if ($env:Path[-1] -eq ";") {
                    $env:Path = "$env:Path$NewPath"
                }
                else {
                    $env:Path = "$env:Path;$NewPath"
                }
            }
        }
    }

    # Outputs [System.Collections.ArrayList]$ExePath
    function Adjudicate-ExePath {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$True)]
            [string]$ProgramName,

            [Parameter(Mandatory=$True)]
            [string]$OriginalSystemPath,

            [Parameter(Mandatory=$True)]
            [string]$OriginalEnvPath,

            [Parameter(Mandatory=$True)]
            [string]$FinalCommandName,

            [Parameter(Mandatory=$False)]
            [string]$ExpectedInstallLocation
        )

        # ...search for it in the $ExpectedInstallLocation if that parameter is provided by the user...
        if ($ExpectedInstallLocation) {
            if (Test-Path $ExpectedInstallLocation) {
                [System.Collections.ArrayList][Array]$ExePath = $(Get-ChildItem -Path $ExpectedInstallLocation -File -Recurse -Filter "*$FinalCommandName.exe").FullName
            }
        }
        # If we don't have $ExpectedInstallLocation provided...
        if (!$ExpectedInstallLocation) {
            # ...then we can compare $OriginalSystemPath to the current System PATH to potentially
            # figure out which directories *might* contain the main executable.
            $OriginalSystemPathArray = $OriginalSystemPath -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
            $OriginalEnvPathArray = $OriginalEnvPath -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}

            $CurrentSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
            $CurrentSystemPathArray = $CurrentSystemPath -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
            $CurrentEnvPath = $env:Path
            $CurrentEnvPathArray = $CurrentEnvPath -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
            

            $OriginalVsCurrentSystemPathComparison = Compare-Object $OriginalSystemPathArray $CurrentSystemPathArray
            $OriginalVsCurrentEnvPathComparison = Compare-Object $OriginalEnvPathArray $CurrentEnvPathArray

            [System.Collections.ArrayList]$DirectoriesToSearch = @()
            if ($OriginalVsCurrentSystemPathComparison -ne $null) {
                # => means that $CurrentSystemPathArray has some new directories
                [System.Collections.ArrayList][Array]$NewSystemPathDirs = $($OriginalVsCurrentSystemPathComparison | Where-Object {$_.SideIndicator -eq "=>"}).InputObject
            
                if ($NewSystemPathDirs.Count -gt 0) {
                    foreach ($dir in $NewSystemPathDirs) {
                        $null = $DirectoriesToSearch.Add($dir)
                    }
                }
            }
            if ($OriginalVsCurrentEnvPathComparison -ne $null) {
                # => means that $CurrentEnvPathArray has some new directories
                [System.Collections.ArrayList][Array]$NewEnvPathDirs = $($OriginalVsCurrentEnvPathComparison | Where-Object {$_.SideIndicator -eq "=>"}).InputObject
            
                if ($NewEnvPathDirs.Count -gt 0) {
                    foreach ($dir in $NewEnvPathDirs) {
                        $null = $DirectoriesToSearch.Add($dir)
                    }
                }
            }

            if ($DirectoriesToSearch.Count -gt 0) {
                $DirectoriesToSearchFinal = $($DirectoriesToSearch | Sort-Object | Get-Unique) | foreach {if (Test-Path $_ -ErrorAction SilentlyContinue) {$_}}
                $DirectoriesToSearchFinal = $DirectoriesToSearchFinal | Where-Object {$_ -match "$ProgramName"}

                [System.Collections.ArrayList]$ExePath = @()
                foreach ($dir in $DirectoriesToSearchFinal) {
                    [Array]$ExeFiles = $(Get-ChildItem -Path $dir -File -Filter "*$FinalCommandName.exe").FullName
                    if ($ExeFiles.Count -gt 0) {
                        $null = $ExePath.Add($ExeFiles)
                    }
                }

                # If there IS a difference in original vs current System PATH / $Env:Path, but we 
                # still DO NOT find the main executable in those diff directories (i.e. $ExePath is still not set),
                # it's possible that the name of the main executable that we're looking for is actually
                # incorrect...in which case just tell the user that we can't find the expected main
                # executable name and provide a list of other .exe files that we found in the diff dirs.
                if (!$ExePath -or $ExePath.Count -eq 0) {
                    [System.Collections.ArrayList]$ExePath = @()
                    foreach ($dir in $DirectoriesToSearchFinal) {
                        [Array]$ExeFiles = $(Get-ChildItem -Path $dir -File -Filter "*.exe").FullName
                        foreach ($File in $ExeFiles) {
                            $null = $ExePath.Add($File)
                        }
                    }
                }
            }
        }

        $ExePath | Sort-Object | Get-Unique
    }

    ##### END Native Helper Functions #####

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # Invoke-WebRequest fix...
    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

    Push-Location

    if (!$(GetElevation)) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function must be ran from an elevated PowerShell Session (i.e. 'Run as Administrator')! Halting!"
        $global:FunctionResult = "1"
        return
    }

    Write-Host "Please wait..."
    $global:FunctionResult = "0"
    $MyFunctionsUrl = "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyFunctions"

    if ($PSVersionTable.PSEdition -ne "Core") {
        $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
        $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        $null = Install-PackageProvider -Name Chocolatey -Force -Confirm:$False
        $null = Set-PackageSource -Name chocolatey -Trusted -Force
    }
    else {
        $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }

    if ($UpdatePackageManagement) {
        if (![bool]$(Get-Command Update-PackageManagement -ErrorAction SilentlyContinue)) {
            $UpdatePMFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Update-PackageManagement.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($UpdatePMFunctionUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to load the Update-PackageManagement function! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        try {
            $global:FunctionResult = "0"
            $null = Update-PackageManagement -AddChocolateyPackageProvider -ErrorAction SilentlyContinue -ErrorVariable UPMErr
            if ($UPMErr -and $global:FunctionResult -eq "1") {throw "The Update-PackageManagement function failed! Halting!"}
        }
        catch {
            Write-Error $_
            Write-Host "Errors from the Update-PackageManagement function are as follows:"
            Write-Error $($UPMErr | Out-String)
            $global:FunctionResult = "1"
            return
        }
    }

    if ($UseChocolateyCmdLine -or $(!$UsePowerShellGet -and !$UseChocolateyCmdLine)) {
        if (![bool]$(Get-Command Install-ChocolateyCmdLine -ErrorAction SilentlyContinue)) {
            $InstallCCFunctionUrl = "$MyFunctionsUrl/Install-ChocolateyCmdLine.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($InstallCCFunctionUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to load the Install-ChocolateyCmdLine function! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if (![bool]$(Get-Command Update-ChocolateyEnv -ErrorAction SilentlyContinue)) {
        $RefreshCEFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Update-ChocolateyEnv.ps1"
        try {
            Invoke-Expression $([System.Net.WebClient]::new().DownloadString($RefreshCEFunctionUrl))
        }
        catch {
            Write-Error $_
            Write-Error "Unable to load the Update-ChocolateyEnv function! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Get-AllPackageInfo
    try {
        #$null = clist --local-only
        $PackageManagerInstallObjects = Get-AllPackageInfo -ProgramName $ProgramName -ErrorAction SilentlyContinue
        [array]$ChocolateyInstalledProgramObjects = $PackageManagerInstallObjects.ChocolateyInstalledProgramObjects
        [array]$PSGetInstalledPackageObjects = $PackageManagerInstallObjects.PSGetInstalledPackageObjects
        [array]$RegistryProperties = $PackageManagerInstallObjects.RegistryProperties
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    $AllPackageManagementVersions = Find-Package -Name $ProgramName -Source chocolatey -AllVersions -EA SilentlyContinue
    if ([bool]$AllPackageManagementVersions) {
        $PackageManagementLatestVersion = $($AllPackageManagementVersions | Sort-Object -Property Version -EA SilentlyContinue)[-1]
        $PackageManagementPreviousVersion = $($AllPackageManagementVersions | Sort-Object -Property Version -EA SilentlyContinue)[-2]
    }
    if ([bool]$(Get-Command choco -EA SilentlyContinue)) {
        $AllChocoVersions = choco list $ProgramName -e --all
        if ([bool]$AllChocoVersions) {
            $ChocoLatestVersion = $($AllChocoVersions[1] -split "[\s]")[1].Trim()
            $ChocoPreviousVersion = $($AllChocoVersions[2] -split "[\s]")[1].Trim()
        }
    }

    if ($PSGetInstalledPackageObjects.Count -gt 0) {
        if ($PSGetInstalledPackageObjects.Count -eq 1) {
            $PackageManagementCurrentInstalledPackage = $PSGetInstalledPackageObjects
            $PackageManagementLatestVersion = $(Find-Package -Name $PSGetInstalledPackageObjects.Name -Source chocolatey -AllVersions | Sort-Object -Property Version)[-1]
            $PackageManagementPreviousVersion = $(Find-Package -Name $PSGetInstalledPackageObjects.Name -Source chocolatey -AllVersions | Sort-Object -Property Version)[-2]
        }
        if ($PSGetInstalledPackageObjects.Count -gt 1) {
            $ExactMatchCheck = $PSGetInstalledPackageObjects | Where-Object {$_.Name -eq $ProgramName}
            if (!$ExactMatchCheck) {
                Write-Warning "The following Programs are currently installed and match the string '$ProgramName':"
                for ($i=0; $i -lt $PSGetInstalledPackageObjects.Count; $i++) {
                    Write-Host "$i) $($PSGetInstalledPackageObjects[$i].Name)"
                }
                $ValidChoiceNumbers = 0..$($PSGetInstalledPackageObjects.Count-1)
                $ProgramChoiceNumber = Read-Host -Prompt " Please choose the number that corresponds to the Program you would like to update:"
                while ($ValidChoiceNumbers -notcontains $ProgramChoiceNumber) {
                    Write-Warning "'$ProgramChoiceNumber' is not a valid option. Please choose: $($ValidChoicenumbers -join ", ")"
                    $ProgramChoiceNumber = Read-Host -Prompt " Please choose the number that corresponds to the Program you would like to update:"
                }

                $ProgramName = $PSGetInstalledPackageObjects[$ProgramChoiceNumber].Name
                $PackageManagementLatestVersion = $(Find-Package -Name $UpdatedProgramName -Source chocolatey -AllVersions | Sort-Object -Property Version)[-1]
            }
            else {
                $PackageManagementLatestVersion = $(Find-Package -Name $ProgramName -Source chocolatey -AllVersions | Sort-Object -Property Version)[-1]
            }
        }
    }
    if ($ChocolateyInstalledProgramObjects.Count -gt 0) {
        if ($ChocolateyInstalledProgramObjects.Count -gt 1) {
            $ExactMatchCheck = $ChocolateyInstalledProgramObjects | Where-Object {$_.ProgramName -eq $ProgramName}
            if (!$ExactMatchCheck) {
                Write-Warning "The following Programs are currently installed and match the string '$ProgramName':"
                for ($i=0; $i -lt $ChocolateyInstalledProgramObjects.Count; $i++) {
                    Write-Host "$i) $($ChocolateyInstalledProgramObjects[$i].ProgramName)"
                }
                $ValidChoiceNumbers = 0..$($ChocolateyInstalledProgramObjects.Count-1)
                $ProgramChoiceNumber = Read-Host -Prompt " Please choose the number that corresponds to the Program you would like to update:"
                while ($ValidChoiceNumbers -notcontains $ProgramChoiceNumber) {
                    Write-Warning "'$ProgramChoiceNumber' is not a valid option. Please choose: $($ValidChoicenumbers -join ", ")"
                    $ProgramChoiceNumber = Read-Host -Prompt " Please choose the number that corresponds to the Program you would like to update:"
                }

                $ProgramName = $ChocolateyInstalledProgramObjects[$ProgramChoiceNumber].ProgramName
            }
        }

        # Also get a list of outdated packages in case this Install-Program function is used to update a package
        $ChocolateyOutdatedProgramsPrep = choco outdated
        $UpperLineMatch = $ChocolateyOutdatedProgramsPrep -match "Output is package name"
        $LowerLineMatch = $ChocolateyOutdatedProgramsPrep -match "Chocolatey has determined"
        $UpperIndex = $ChocolateyOutdatedProgramsPrep.IndexOf($UpperLineMatch) + 2
        $LowerIndex = $ChocolateyOutdatedProgramsPrep.IndexOf($LowerLineMatch) - 2
        $ChocolateyOutdatedPrograms = $ChocolateyOutdatedProgramsPrep[$UpperIndex..$LowerIndex]

        [System.Collections.ArrayList]$ChocolateyOutdatedProgramsPSObjects = @()
        foreach ($line in $ChocolateyOutdatedPrograms) {
            $ParsedLine = $line -split "\|"
            $Program = $ParsedLine[0]
            $CurrentInstalledVersion = $ParsedLine[1]
            $LatestAvailableVersion = $ParsedLine[2]

            $PSObject = [pscustomobject]@{
                ProgramName                 = $Program
                CurrentInstalledVersion     = $CurrentInstalledVersion
                LatestAvailableVersion      = $LatestAvailableVersion
            }

            $null = $ChocolateyOutdatedProgramsPSObjects.Add($PSObject)
        }

        # Get all available Chocolatey Versions
        $AllChocoVersions = choco list $ProgramName -e --all

        # Get the latest version of $ProgramName from chocolatey
        $ChocoLatestVersion = $($AllChocoVersions[1] -split "[\s]")[1].Trim()

        # Also get the previous version of $ProgramName in case we want the previous version
        $ChocoPreviousVersion = $($AllChocoVersions[2] -split "[\s]")[1].Trim()
    }

    if ($CommandName -match "\.exe") {
        $CommandName = $CommandName -replace "\.exe",""
    }
    $FinalCommandName = if ($CommandName) {$CommandName} else {$ProgramName}

    # Save the original System PATH and $env:Path before we do anything, just in case
    $OriginalSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
    $OriginalEnvPath = $env:Path
    Synchronize-SystemPathEnvPath
    $env:Path = Update-ChocolateyEnv -ErrorAction SilentlyContinue

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    $CheckLatestVersion = $(
        $PackageManagementCurrentInstalledPackage.Version -ne $PackageManagementLatestVersion.Version -or
        $ChocolateyOutdatedProgramsPSObjects.ProgramName -contains $ProgramName
    )
    $CheckPreviousVersion = $(
        $PackageManagementCurrentInstalledPackage.Version -ne $PackageManagementPreviousVersion.Version -or
        $ChocoPreviousVersion -ne $ChocolateyInstalledProgramObjects.Version
    )
    if ($GetPreviousVersion) {
        $VersionCheck = $CheckPreviousVersion
        $PackageManagementRequiredVersion = $PackageManagementPreviousVersion.Version
        $ChocoRequiredVersion = $ChocoLatestVersion
    }
    else {
        $VersionCheck = $CheckLatestVersion
        $PackageManagementRequiredVersion = $PackageManagementLatestVersion.Version
        $ChocoRequiredVersion = $ChocoPreviousVersion
    }

    # Install $ProgramName if it's not already or if it's outdated...
    if ($($PSGetInstalledPackageObjects.Name -notcontains $ProgramName -and
    $ChocolateyInstalledProgramsPSObjects.ProgramName -notcontains $ProgramName) -or
    $VersionCheck -or $Force
    ) {
        if ($UsePowerShellGet -or $(!$UsePowerShellGet -and !$UseChocolateyCmdLine) -or 
        $PSGetInstalledPackageObjects.Name -contains $ProgramName -and $ChocolateyInstalledProgramsPSObjects.ProgramName -notcontains $ProgramName
        ) {
            $InstallPackageSplatParams = @{
                Name            = $ProgramName
                Force           = $True
                ErrorAction     = "SilentlyContinue"
                ErrorVariable   = "InstallError"
                WarningAction   = "SilentlyContinue"
            }
            if ([bool]$PackageManagementRequiredVersion) {
                $InstallPackageSplatParams.Add("RequiredVersion",$PackageManagementRequiredVersion)
            }
            if ($PreRelease) {
                try {
                    $LatestVersion = $(Find-Package $ProgramName -AllVersions -ErrorAction Stop)[-1].Version
                    $InstallPackageSplatParams.Add("MinimumVersion",$LatestVersion)
                }
                catch {
                    Write-Verbose "Unable to find latest PreRelease version...Proceeding with 'Install-Package' without the '-MinimumVersion' parameter..."
                }
            }
            # NOTE: The PackageManagement install of $ProgramName is unreliable, so just in case, fallback to the Chocolatey cmdline for install
            $null = Install-Package @InstallPackageSplatParams
            if ($InstallError.Count -gt 0 -or $($(Get-Package).Name -match $ProgramName).Count -eq 0) {
                if ($($(Get-Package).Name -match $ProgramName).Count -gt 0) {
                    $null = Uninstall-Package $ProgramName -Force -ErrorAction SilentlyContinue
                }
                Write-Warning "There was a problem installing $ProgramName via PackageManagement/PowerShellGet!"
                
                if ($UsePowerShellGet) {
                    Write-Error "One or more errors occurred during the installation of $ProgramName via the the PackageManagement/PowerShellGet Modules failed! Installation has been rolled back! Halting!"
                    Write-Host "Errors for the Install-Package cmdlet are as follows:"
                    Write-Error $($InstallError | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    Write-Host "Trying install via Chocolatey CmdLine..."
                    $PMInstall = $False
                }
            }
            else {
                $PMInstall = $True

                # Since Installation via PackageManagement/PowerShellGet was succesful, let's update $env:Path with the
                # latest from System PATH before we go nuts trying to find the main executable manually
                Synchronize-SystemPathEnvPath
                $env:Path = $($(Update-ChocolateyEnv -ErrorAction SilentlyContinue) -split ";" | foreach {
                    if (-not [System.String]::IsNullOrWhiteSpace($_) -and $(Test-Path $_ -ErrorAction SilentlyContinue)) {$_}
                }) -join ";"
            }
        }

        if (!$PMInstall -or $UseChocolateyCmdLine -or
        $ChocolateyInstalledProgramsPSObjects.ProgramName -contains $ProgramName
        ) {
            try {
                Write-Host "Refreshing `$env:Path..."
                $global:FunctionResult = "0"
                $env:Path = Update-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr

                # The first time we attempt to Update-ChocolateyEnv, Chocolatey CmdLine and/or the
                # Chocolatey Package Provider legitimately might not be installed,
                # so if the Update-ChocolateyEnv function throws that error, we can ignore it
                if ($RCEErr.Count -gt 0 -and
                $global:FunctionResult -eq "1" -and
                ![bool]$($RCEErr -match "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed!")) {
                    throw "The Update-ChocolateyEnv function failed! Halting!"
                }
            }
            catch {
                Write-Error $_
                Write-Host "Errors from the Update-ChocolateyEnv function are as follows:"
                Write-Error $($RCEErr | Out-String)
                $global:FunctionResult = "1"
                return
            }

            # Make sure Chocolatey CmdLine is installed...if not, install it
            if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
                try {
                    $global:FunctionResult = "0"
                    $null = Install-ChocolateyCmdLine -ErrorAction SilentlyContinue -ErrorVariable ICCErr -WarningAction SilentlyContinue
                    if ($ICCErr -and $global:FunctionResult -eq "1") {throw "The Install-ChocolateyCmdLine function failed! Halting!"}
                }
                catch {
                    Write-Error $_
                    Write-Host "Errors from the Install-ChocolateyCmdline function are as follows:"
                    Write-Error $($ICCErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }

            # Make sure you can reach the Chocolatey Repo
            if ($(Invoke-WebRequest -Uri 'http://chocolatey.org/api/v2').StatusCode -ne 200) {
                Write-Error "Unable to reach the Chocolatey Package Repo at 'http://chocolatey.org/api/v2'! Halting!"
                $global:FunctionResult = "1"
                return
            }

            try {
                # TODO: Figure out how to handle errors from choco.exe. Some we can ignore, others
                # we shouldn't. But I'm not sure what all of the possibilities are so I can't
                # control for them...
                if ($PreRelease) {
                    $Arguments = "$ProgramName --pre -y"
                }
                elseif ([bool]$ChocoRequiredVersion) {
                    $Arguments = "$ProgramName -y --version $ChocoRequiredVersion"
                }
                else {
                    $Arguments = "$ProgramName -y"
                }
                
                $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
                $ProcessInfo.FileName = $(Get-Command cup).Source
                $ProcessInfo.RedirectStandardError = $true
                $ProcessInfo.RedirectStandardOutput = $true
                $ProcessInfo.UseShellExecute = $false
                $ProcessInfo.Arguments = $Arguments
                $Process = New-Object System.Diagnostics.Process
                $Process.StartInfo = $ProcessInfo
                $Process.Start() | Out-Null
                # Below $FinishedInAlottedTime returns boolean true/false
                # Give it 60 seconds to finish installing, otherwise, kill choco.exe
                $FinishedInAlottedTime = $Process.WaitForExit(60000)
                if (!$FinishedInAlottedTime) {
                    $Process.Kill()
                }
                $stdout = $Process.StandardOutput.ReadToEnd()
                $stderr = $Process.StandardError.ReadToEnd()
                $AllOutput = $stdout + $stderr
                
                if (![bool]$($(clist --local-only $ProgramName) -match $ProgramName)) {
                    if ($AllOutput -match "prerelease" -and $Arguments -notmatch '--pre') {
                        $Arguments = $Arguments +  ' --pre'

                        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                        #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
                        $ProcessInfo.FileName = $(Get-Command cup).Source
                        $ProcessInfo.RedirectStandardError = $true
                        $ProcessInfo.RedirectStandardOutput = $true
                        $ProcessInfo.UseShellExecute = $false
                        $ProcessInfo.Arguments = $Arguments
                        $Process = New-Object System.Diagnostics.Process
                        $Process.StartInfo = $ProcessInfo
                        $Process.Start() | Out-Null
                        # Below $FinishedInAlottedTime returns boolean true/false
                        # Give it 60 seconds to finish installing, otherwise, kill choco.exe
                        $FinishedInAlottedTime = $Process.WaitForExit(60000)
                        if (!$FinishedInAlottedTime) {
                            $Process.Kill()
                        }
                        $stdout = $Process.StandardOutput.ReadToEnd()
                        $stderr = $Process.StandardError.ReadToEnd()
                        $AllOutput = $stdout + $stderr
                    }
                }
                
                if (![bool]$($(clist --local-only $ProgramName) -match $ProgramName)) {
                    Write-Error "There was a problem installing the program '$ProgramName' via 'cup $Arguments'! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                $ChocoInstall = $true

                # Since Installation via the Chocolatey CmdLine was succesful, let's update $env:Path with the
                # latest from System PATH before we go nuts trying to find the main executable manually
                Synchronize-SystemPathEnvPath
                $env:Path = Update-ChocolateyEnv -ErrorAction SilentlyContinue
            }
            catch {
                Write-Error "There was a problem installing $ProgramName using the Chocolatey cmdline! Halting!"
                Write-Warning "Please update Chocolatey via:`n    cup chocolatey -y"
                $global:FunctionResult = "1"
                return
            }
        }

        if ($ResolveCommandPath -or $PSBoundParameters['CommandName']) {
            ## BEGIN Try to Find Main Executable Post Install ##

            # Now the parent directory of $ProgramName's main executable should be part of the SYSTEM Path
            # (and therefore part of $env:Path). If not, try to find it in Chocolatey directories...
            if ($(Get-Command $FinalCommandName -ErrorAction SilentlyContinue).CommandType -eq "Alias") {
                while (Test-Path Alias:\$FinalCommandName -ErrorAction SilentlyContinue) {
                    Remove-Item Alias:\$FinalCommandName
                }
            }

            if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
                try {
                    Write-Host "Refreshing `$env:Path..."
                    $global:FunctionResult = "0"
                    $env:Path = Update-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
                    if ($RCEErr.Count -gt 0 -and $global:FunctionResult -eq "1") {throw "The Update-ChocolateyEnv function failed! Halting!"}
                }
                catch {
                    Write-Error $_
                    Write-Host "Errors from the Update-ChocolateyEnv function are as follows:"
                    Write-Error $($RCEErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }
            
            # If we still can't find the main executable...
            if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue) -and $(!$ExePath -or $ExePath.Count -eq 0)) {
                $env:Path = Update-ChocolateyEnv -ErrorAction SilentlyContinue
                
                if ($ExpectedInstallLocation) {
                    if (Test-Path $ExpectedInstallLocation -ErrorAction SilentlyContinue) {
                        [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName -ExpectedInstallLocation $ExpectedInstallLocation
                    }
                }
                else {
                    [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName
                }
            }

            # Determine if there's an exact match for the $FinalCommandName
            if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
                if ($ExePath.Count -ge 1) {
                    if ([bool]$($ExePath -match "\\$FinalCommandName.exe$")) {
                        $FoundExactCommandMatch = $True
                    }
                }
            }

            # If we STILL can't find the main executable...
            if ($(![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue) -and $(!$ExePath -or $ExePath.Count -eq 0)) -or 
            $(!$FoundExactCommandMatch -and $PSBoundParameters['CommandName']) -or 
            $($ResolveCommandPath -and !$FoundExactCommandMatch) -or $ForceChocoInstallScript) {
                # If, at this point we don't have $ExePath, if we did a $ChocoInstall, then we have to give up...
                # ...but if we did a $PMInstall, then it's possible that PackageManagement/PowerShellGet just
                # didn't run the chocolateyInstall.ps1 script that sometimes comes bundled with Packages from the
                # Chocolatey Package Provider/Repo. So try running that...
                if ($ChocoInstall) {
                    if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
                        #Write-Warning "Unable to find main executable for $ProgramName!"
                        $MainExeSearchFail = $True
                    }
                }
                if ($PMInstall -or $ForceChocoInstallScript) {
                    [System.Collections.ArrayList]$PossibleChocolateyInstallScripts = @()
                    
                    if (Test-Path "C:\Chocolatey" -ErrorAction SilentlyContinue) {
                        $ChocoScriptsA = Get-ChildItem -Path "C:\Chocolatey" -Recurse -File -Filter "*chocolateyinstall.ps1" | Where-Object {$($(Get-Date) - $_.CreationTime).TotalMinutes -lt 5}
                        foreach ($Script in $ChocoScriptsA) {
                            $null = $PossibleChocolateyInstallScripts.Add($Script)
                        }
                    }
                    if (Test-Path "C:\ProgramData\chocolatey" -ErrorAction SilentlyContinue) {
                        $ChocoScriptsB = Get-ChildItem -Path "C:\ProgramData\chocolatey" -Recurse -File -Filter "*chocolateyinstall.ps1" | Where-Object {$($(Get-Date) - $_.CreationTime).TotalMinutes -lt 5}
                        foreach ($Script in $ChocoScriptsB) {
                            $null = $PossibleChocolateyInstallScripts.Add($Script)
                        }
                    }

                    [System.Collections.ArrayList][Array]$ChocolateyInstallScriptSearch = $PossibleChocolateyInstallScripts.FullName | Where-Object {$_ -match ".*?$ProgramName.*?chocolateyinstall.ps1$"}
                    if ($ChocolateyInstallScriptSearch.Count -eq 0) {
                        Write-Warning "Unable to find main the Chocolatey Install Script for $ProgramName PowerShellGet install!"
                        $MainExeSearchFail = $True
                    }
                    if ($ChocolateyInstallScriptSearch.Count -eq 1) {
                        $ChocolateyInstallScript = $ChocolateyInstallScriptSearch[0]
                    }
                    if ($ChocolateyInstallScriptSearch.Count -gt 1) {
                        $ChocolateyInstallScript = $($ChocolateyInstallScriptSearch | Sort-Object LastWriteTime)[-1]
                    }
                    
                    if ($ChocolateyInstallScript) {
                        try {
                            Write-Host "Trying the Chocolatey Install script from $ChocolateyInstallScript..." -ForegroundColor Yellow

                            # Make sure Chocolatey Modules / helper scripts are loaded
                            if (Test-Path "C:\ProgramData\chocolatey" -ErrorAction SilentlyContinue) {
                                $ChocoPath = "C:\ProgramData\chocolatey"
                            }
                            elseif (Test-Path "C:\Chocolatey" -ErrorAction SilentlyContinue) {
                                $ChocoPath = "C:\Chocolatey"
                            }
                            else {
                                if ($ExpectedInstallLocation) {
                                    if (Test-Path $ExpectedInstallLocation -ErrorAction SilentlyContinue) {
                                        [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName -ExpectedInstallLocation $ExpectedInstallLocation
                                    }
                                }
                                else {
                                    [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName
                                }
    
                                # If we STILL don't have $ExePath, try this...
                                if (!$ExePath -or $ExePath.Count -eq 0) {
                                    $ProgramSourceParentDir = $(Get-Package $ProgramName).Source | Split-Path -Parent
                                    if (![System.String]::IsNullOrWhiteSpace($ProgramSourceParentDir)) {
                                        $ExePath = $(Get-ChildItem -Path $ProgramSourceParentDir -Recurse -File | Where-Object {$_.Name -like "*$ProgramName*exe"}).FullName
                                    }
                                }
    
                                # If we STILL don't have $ExePath, we need to give up...
                                if (!$ExePath -or $ExePath.Count -eq 0) {
                                    #Write-Warning "Unable to find main executable for $ProgramName!"
                                    $MainExeSearchFail = $True
                                }

                                throw "Unable to find `$ChocoPath!"
                            }
                            
                            $ChocoInstallerModuleFileItem = Get-ChildItem -Path $ChocoPath -Recurse -File | Where-Object {$_.FullName -match "chocolateyinstaller\.psm1"}
                            $ChocoProfileModuleFileItem = Get-ChildItem -Path $ChocoPath -Recurse -File | Where-Object {$_.FullName -match "chocolateyProfile\.psm1"}
                            $ChocoScriptRunnerFileItem = Get-ChildItem -Path $ChocoPath -Recurse -File | Where-Object {$_.FullName -match "chocolateyScriptRunner\.ps1"}
                            $ChocoTabExpansionFileItem = Get-ChildItem -Path $ChocoPath -Recurse -File | Where-Object {$_.FullName -match "chocolateyTabExpansion\.ps1"}
                            
                            if (!$ChocoInstallerModuleFileItem -or !$ChocoProfileModuleFileItem) {
                                $ChocoResourcesPath = "$ChocoPath\lib\chocolatey.resources"
                                $null = New-Item -ItemType Directory -Path $ChocoResourcesPath -Force
                                $ChocoMasterSrcZipUri = "https://github.com/chocolatey/choco/archive/master.zip"
                                $ChocoMasterOutFile = "$HOME\Downloads\ChocoMaster.zip"
                                Invoke-WebRequest -Uri $ChocoMasterSrcZipUri -OutFile $ChocoMasterOutFile
                                UnzipFile -PathToZip $ChocoMasterOutFile -TargetDir $ChocoResourcesPath -SpecificItem 'chocolatey\.resources\\helpers$'

                                $ChocoInstallerModuleFileItem = Get-ChildItem -Path $ChocoResourcesPath -Recurse -File | Where-Object {$_.FullName -match "chocolateyinstaller\.psm1"}
                                $ChocoProfileModuleFileItem = Get-ChildItem -Path $ChocoResourcesPath -Recurse -File | Where-Object {$_.FullName -match "chocolateyProfile\.psm1"}
                                $ChocoScriptRunnerFileItem = Get-ChildItem -Path $ChocoResourcesPath -Recurse -File | Where-Object {$_.FullName -match "chocolateyScriptRunner\.ps1"}
                                $ChocoTabExpansionFileItem = Get-ChildItem -Path $ChocoResourcesPath -Recurse -File | Where-Object {$_.FullName -match "chocolateyTabExpansion\.ps1"}

                                if (!$ChocoInstallerModuleFileItem -or !$ChocoProfileModuleFileItem) {
                                    throw "Unable to find chocolateyInstaller.psm1 or chocolateyProfile.psm1"
                                }
                            }

                            if ($ChocoInstallerModuleFileItem) {
                                Import-Module $ChocoInstallerModuleFileItem.FullName -ErrorAction SilentlyContinue
                                $ChocoHelpersDir = $ChocoInstallerModuleFileItem.Directory
                            }
                            elseif ($ChocoProfileModuleFileItem) {
                                Import-Module $ChocoProfileModuleFileItem.FullName -ErrorAction SilentlyContinue
                                $ChocoHelpersDir = $ChocoProfileModuleFileItem.Directory
                            }
                            elseif ($ChocoScriptRunnerFileItem) {
                                $ChocoHelpersDir = $ChocoScriptRunnerFileItem.Directory
                            }
                            elseif ($ChocoTabExpansionFileItem) {
                                $ChocoHelpersDir = $ChocoTabExpansionFileItem.Directory
                            }
                            
                            # Run the install script
                            $tempfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
                            <#
                            $ChocoScriptContent = Get-Content $ChocolateyInstallScript
                            $LineToReplace = $ChocoScriptContent -match "-nonewwindow -wait"
                            $UpdatedLine = $LineToReplace + "-RedirectStandardOutput `"$tempfile`""
                            $UpdatedChocoScriptContent = $ChocoScriptContent -replace [regex]::Escape($LineToReplace),$UpdatedLine
                            Set-Content -Path $ChocolateyInstallScript -Value $UpdatedChocoScriptContent
                            #>
                            $null = & $ChocolateyInstallScript *> $tempfile
                            #$null = Start-Process powershell -ArgumentList "& `"$ChocolateyInstallScript`"" -NoNewWindow -Wait -RedirectStandardOutput $tempfile
                            if (Test-Path $tempfile -ErrorAction SilentlyContinue) {Remove-Item $tempfile -Force}

                            # Now that the $ChocolateyInstallScript ran, search for the main executable again
                            Synchronize-SystemPathEnvPath
                            $env:Path = Update-ChocolateyEnv -ErrorAction SilentlyContinue

                            if ($ExpectedInstallLocation) {
                                if (Test-Path $ExpectedInstallLocation -ErrorAction SilentlyContinue) {
                                    [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName -ExpectedInstallLocation $ExpectedInstallLocation
                                }
                            }
                            else {
                                [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName
                            }

                            # If we STILL don't have $ExePath, try this...
                            if (!$ExePath -or $ExePath.Count -eq 0) {
                                $ProgramSourceParentDir = $(Get-Package $ProgramName).Source | Split-Path -Parent
                                if (![System.String]::IsNullOrWhiteSpace($ProgramSourceParentDir)) {
                                    $ExePath = $(Get-ChildItem -Path $ProgramSourceParentDir -Recurse -File | Where-Object {$_.Name -like "*$ProgramName*exe"}).FullName
                                }
                            }

                            # If we STILL don't have $ExePath, we need to give up...
                            if (!$ExePath -or $ExePath.Count -eq 0) {
                                #Write-Warning "Unable to find main executable for $ProgramName!"
                                $MainExeSearchFail = $True
                            }
                        }
                        catch {
                            Write-Error $_
                            Write-Warning "The Chocolatey Install Script $ChocolateyInstallScript has failed!"
                            Write-Host "Installing via Chocolatey CmdLine..."

                            # If PackageManagement/PowerShellGet is ERRONEOUSLY reporting that the program was installed
                            # use the Uninstall-Package cmdlet to wipe it out. This scenario happens when PackageManagement/
                            # PackageManagement/PowerShellGet gets a Package from the Chocolatey Package Provider/Repo but
                            # fails to run the chocolateyInstall.ps1 script for some reason.
                            if ([bool]$(Get-Package $ProgramName -ErrorAction SilentlyContinue)) {
                                $null = Uninstall-Package $ProgramName -Force -ErrorAction SilentlyContinue
                            }

                            if (!$UsePowerShellGet -and !$ForceChocoInstallScript) {
                                Remove-Module chocolateyinstaller -ErrorAction SilentlyContinue
                                Remove-Module chocolateyProfile -ErrorAction SilentlyContinue

                                # Now we need to try the Chocolatey CmdLine. Easiest way to do this at this point is to just
                                # invoke the function again with the same parameters, but specify -UseChocolateyCmdLine
                                $BoundParametersDictionary = $PSCmdlet.MyInvocation.BoundParameters
                                $InstallProgramSplatParams = @{}
                                foreach ($kvpair in $BoundParametersDictionary.GetEnumerator()) {
                                    $key = $kvpair.Key
                                    $value = $BoundParametersDictionary[$key]
                                    if ($key -notmatch "UsePowerShellGet|ForceChocoInstallScript" -and $InstallProgramSplatParams.Keys -notcontains $key) {
                                        $InstallProgramSplatParams.Add($key,$value)
                                    }
                                }
                                if ($InstallProgramSplatParams.Keys -notcontains "UseChocolateyCmdLine") {
                                    $InstallProgramSplatParams.Add("UseChocolateyCmdLine",$True)
                                }
                                if ($InstallProgramSplatParams.Keys -notcontains "ErrorAction") {
                                    $InstallProgramSplatParams.Add("ErrorAction","Stop")
                                }
                                $PMInstall = $False
                                
                                try {
                                    if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {$null = Install-ChocolateyCmdLine}
                                    Install-Program @InstallProgramSplatParams
                                }
                                catch {
                                    Write-Error $_
                                    Write-Error "Install via Chocolatey CmdlLine failed. Please update Chocolatey via:`n    cup chocolatey -y"
                                    $global:FunctionResult = "1"
                                }
                                return
                                
                                <#
                                New-Runspace -RunspaceName "InstProgChocoCmd" -ScriptBlock {Install-Program @InstallProgramSplatParams}

                                while ($global:RSSyncHash.InstProgChocoCmdResult.Done -ne $True) {
                                    Write-Verbose "Waiting for install via Chocolatey CmdLine to finish..."
                                    Start-Sleep -Seconds 1
                                }

                                if ($global:RSSyncHash.Errors.Count -gt 0) {
                                    foreach ($ErrMsg in $global:RSSyncHash.Errors) {Write-Error $_}
                                }

                                if ($global:RSSyncHash.Output) {
                                    $global:RSSyncHash.Output
                                }

                                if (!$global:RSSyncHash.Output -or $global:RSSyncHash.Errors.Count -gt 0) {
                                    Write-Warning "Install via Chocolatey CmdlLine failed. Please update Chocolatey via:`n    cup chocolatey -y"
                                }
                                
                                return
                                #>
                            }
                            else {
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                    }
                }
            }

            ## END Try to Find Main Executable Post Install ##
        }
    }
    else {
        if ($ChocolateyInstalledProgramsPSObjects.ProgramName -contains $ProgramName) {
            Write-Warning "$ProgramName is already installed via the Chocolatey CmdLine!"
            $AlreadyInstalled = $True
        }
        elseif ([bool]$(Get-Package $ProgramName -ErrorAction SilentlyContinue)) {
            Write-Warning "$ProgramName is already installed via PackageManagement/PowerShellGet!"
            $AlreadyInstalled = $True
        }

        if ($CommandName -or $ExpectedInstallLocation -or $ResolveCommandPath) {
            if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue) -and $(!$ExePath -or $ExePath.Count -eq 0)) {
                $env:Path = Update-ChocolateyEnv -ErrorAction SilentlyContinue
                
                if ($ExpectedInstallLocation) {
                    if (Test-Path $ExpectedInstallLocation -ErrorAction SilentlyContinue) {
                        [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName -ExpectedInstallLocation $ExpectedInstallLocation
                    }
                }
                else {
                    [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName
                }
            }
        }
    }

    # If we weren't able to find the main executable (or any potential main executables) for
    # $ProgramName, offer the option to scan the whole C:\ drive (with some obvious exceptions)
    if ($MainExeSearchFail -and
    $($ResolveCommandPath -or $PSBoundParameters['CommandName'] -or $PSBoundParameters['ScanCDriveForMainExeIfNecessary']) -and
    ![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)
    ) {
        if (!$ScanCDriveForMainExeIfNecessary -and !$ResolveCommandPath -and !$PSBoundParameters['CommandName']) {
            $ScanCDriveChoice = Read-Host -Prompt "Would you like to scan C:\ for $FinalCommandName.exe? NOTE: This search excludes system directories but still could take some time. [Yes\No]"
            while ($ScanCDriveChoice -notmatch "Yes|yes|Y|y|No|no|N|n") {
                Write-Host "$ScanDriveChoice is not a valid input. Please enter 'Yes' or 'No'"
                $ScanCDriveChoice = Read-Host -Prompt "Would you like to scan C:\ for $FinalCommandName.exe? NOTE: This search excludes system directories but still could take some time. [Yes\No]"
            }
        }

        if ($ScanCDriveChoice -match "Yes|yes|Y|y" -or $ScanCDriveForMainExeIfNecessary -or $ResolveCommandPath -or $PSBoundParameters['CommandName']) {
            $DirectoriesToSearchRecursively = $(Get-ChildItem -Path "C:\" -Directory | Where-Object {$_.Name -notmatch "Windows|PerfLogs|Microsoft"}).FullName
            [System.Collections.ArrayList]$ExePath = @()
            # Try to find a directory that matches the $ProgramName
            [System.Collections.ArrayList]$FoundMatchingDirs = @()
            foreach ($dir in $DirectoriesToSearchRecursively) {
                $DirectoriesIndex = Get-ChildItem -Path $dir -Recurse -Directory
                foreach ($subdirItem in $DirectoriesIndex) {
                    if ($subdirItem.FullName -match $ProgramName) {
                        $null = $FoundMatchingDirs.Add($subdiritem)
                    }
                }
            }
            foreach ($MatchingDirItem in $FoundMatchingDirs) {
                $FilesIndex = Get-ChildItem -Path $MatchingDirItem.FullName -Recurse -File
                foreach ($FilePath in $FilesIndex.Fullname) {
                    if ($FilePath -match "(.*?)$FinalCommandName([^\\]+)") {
                        $null = $ExePath.Add($FilePath)
                    }
                }
            }
        }
    }

    # Finalize $env:Path
    if ($ResolveCommandPath -or $PSBoundParameters['CommandName']) {
        if ([bool]$($ExePath -match "\\$FinalCommandName.exe$")) {
            $PathToAdd = $($ExePath -match "\\$FinalCommandName.exe$") | Split-Path -Parent
            $env:Path = $PathToAdd + ";" + $env:Path
        }
        $FinalEnvPathArray = $env:Path -split ";" | foreach {if(-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
        $FinalEnvPathString = $($FinalEnvPathArray | foreach {if (Test-Path $_ -ErrorAction SilentlyContinue) {$_}}) -join ";"
        $env:Path = $FinalEnvPathString

        if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
            # Try to determine Main Executable
            if (!$ExePath -or $ExePath.Count -eq 0) {
                Write-Warning "Unable to find main executable for $ProgramName!"
                $FinalExeLocation = "NotFound"
            }
            elseif ($ExePath.Count -eq 1) {
                $UpdatedFinalCommandName = $ExePath | Split-Path -Leaf

                try {
                    $FinalExeLocation = $(Get-Command $UpdatedFinalCommandName -ErrorAction SilentlyContinue).Source
                }
                catch {
                    $FinalExeLocation = $ExePath | Where-Object {$($_ | Split-Path -Leaf) -match "\.exe$"}
                }
            }
            elseif ($ExePath.Count -gt 1) {
                if (![bool]$($ExePath -match "\\$FinalCommandName.exe$")) {
                    Write-Warning "No exact match for main executable $FinalCommandName.exe was found. However, other executables associated with $ProgramName were found."
                }
                $FinalExeLocation = $ExePath | Where-Object {$($_ | Split-Path -Leaf) -match "\.exe$"}
            }
        }
        else {
            $FinalExeLocation = $(Get-Command $FinalCommandName).Source
        }
    }

    if ($ChocoInstall) {
        $InstallManager = "choco.exe"
        $InstallCheck = $(clist --local-only $ProgramName)[1]
    }
    if ($PMInstall -or [bool]$(Get-Package $ProgramName -ProviderName Chocolatey -ErrorAction SilentlyContinue)) {
        $InstallManager = "PowerShellGet"
        $InstallCheck = Get-Package $ProgramName -ErrorAction SilentlyContinue
    }

    if ($AlreadyInstalled) {
        $InstallAction = "AlreadyInstalled"
    }
    elseif ($($PackageManagementCurrentInstalledPackage.Version -ne $null -and
    $PackageManagementCurrentInstalledPackage.Version -ne $PackageManagementLatestVersion.Version -and $PMInstall) -or
    $($ChocolateyOutdatedProgramsPSObjects.ProgramName -contains $ProgramName)
    ) {
        $InstallAction = "Updated"
    }
    else {
        $InstallAction = "FreshInstall"
    }

    $env:Path = Update-ChocolateyEnv

    1..3 | foreach {Pop-Location}

    if ($InstallAction -match "Updated|FreshInstall") {
        Write-Host "The program '$ProgramName' was installed successfully!" -ForegroundColor Green
    }
    elseif ($InstallAction -eq "AlreadyInstalled") {
        Write-Host "The program '$ProgramName' is already installed!" -ForegroundColor Green
    }

    $OutputHT = [ordered]@{
        InstallManager      = $InstallManager
        InstallAction       = $InstallAction
        InstallCheck        = $InstallCheck
    }
    if ([array]$($FinalExeLocation).Count -gt 1) {
        $OutputHT.Add("PossibleMainExecutables",$FinalExeLocation)
    }
    else {
        $OutputHT.Add("MainExecutable",$FinalExeLocation)
    }
    $OutputHT.Add("OriginalSystemPath",$OriginalSystemPath)
    $OutputHT.Add("CurrentSystemPath",$(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path)
    $OutputHT.Add("OriginalEnvPath",$OriginalEnvPath)
    $OutputHT.Add("CurrentEnvPath",$env:Path)
    
    [pscustomobject]$OutputHT

    ##### END Main Body #####
}


<#
    .SYNOPSIS
        The New-Runspace function creates a Runspace that executes the specified ScriptBlock in the background
        and posts results to a Global Variable called $global:RSSyncHash.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER RunspaceName
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of the new Runspace that you are creating. The name
        is represented as a key in the $global:RSSyncHash variable called: <RunspaceName>Result

    .PARAMETER ScriptBlock
        This parameter is MANDATORY.

        This parameter takes a scriptblock that will be executed in the new Runspace.

    .PARAMETER MirrorCurrentEnv
        This parameter is OPTIONAL, however, it is set to $True by default.

        This parameter is a switch. If used, all variables, functions, and Modules that are loaded in your
        current scope will be forwarded to the new Runspace.

        You can prevent the New-Runspace function from automatically mirroring your current environment by using
        this switch like: -MirrorCurrentEnv:$False 

    .PARAMETER Wait
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the main PowerShell thread will wait for the Runsapce to return
        output before proceeeding.

    .EXAMPLE
        # Open a PowerShell Session, source the function, and -

        PS C:\Users\zeroadmin> $GetProcessResults = Get-Process

        # In the below, Runspace1 refers to your current interactive PowerShell Session...

        PS C:\Users\zeroadmin> Get-Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        1 Runspace1       localhost       Local         Opened        Busy

        # The below will create a 'Runspace Manager Runspace' (if it doesn't already exist)
        # to manage all other new Runspaces created by the New-Runspace function.
        # Additionally, it will create the Runspace that actually runs the -ScriptBlock.
        # The 'Runspace Manager Runspace' disposes of new Runspaces when they're
        # finished running.

        PS C:\Users\zeroadmin> New-RunSpace -RunSpaceName PSIds -ScriptBlock {$($GetProcessResults | Where-Object {$_.Name -eq "powershell"}).Id}

        # The 'Runspace Manager Runspace' persists just in case you create any additional
        # Runspaces, but the Runspace that actually ran the above -ScriptBlock does not.
        # In the below, 'Runspace2' is the 'Runspace Manager Runspace. 

        PS C:\Users\zeroadmin> Get-Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        1 Runspace1       localhost       Local         Opened        Busy
        2 Runspace2       localhost       Local         Opened        Busy

        # You can actively identify (as opposed to infer) the 'Runspace Manager Runspace'
        # by using one of three Global variables created by the New-Runspace function:

        PS C:\Users\zeroadmin> $global:RSJobCleanup.PowerShell.Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        2 Runspace2       localhost       Local         Opened        Busy

        # As mentioned above, the New-RunspaceName function creates three Global
        # Variables. They are $global:RSJobs, $global:RSJobCleanup, and
        # $global:RSSyncHash. Your output can be found in $global:RSSyncHash.

        PS C:\Users\zeroadmin> $global:RSSyncHash

        Name                           Value
        ----                           -----
        PSIdsResult                    @{Done=True; Errors=; Output=System.Object[]}
        ProcessedJobRecords            {@{Name=PSIdsHelper; PSInstance=System.Management.Automation.PowerShell; Runspace=System.Management.Automation.Runspaces.Loca...


        PS C:\Users\zeroadmin> $global:RSSyncHash.PSIdsResult

        Done Errors Output
        ---- ------ ------
        True        {1300, 2728, 2960, 3712...}


        PS C:\Users\zeroadmin> $global:RSSyncHash.PSIdsResult.Output
        1300
        2728
        2960
        3712
        4632

        # Important Note: You don't need to worry about passing variables / functions /
        # Modules to the Runspace. Everything in your current session/scope is
        # automatically forwarded by the New-Runspace function:

        PS C:\Users\zeroadmin> function Test-Func {'This is Test-Func output'}
        PS C:\Users\zeroadmin> New-RunSpace -RunSpaceName FuncTest -ScriptBlock {Test-Func}
        PS C:\Users\zeroadmin> $global:RSSyncHash

        Name                           Value
        ----                           -----
        FuncTestResult                 @{Done=True; Errors=; Output=This is Test-Func output}
        PSIdsResult                    @{Done=True; Errors=; Output=System.Object[]}
        ProcessedJobRecords            {@{Name=PSIdsHelper; PSInstance=System.Management.Automation.PowerShell; Runspace=System.Management.Automation.Runspaces.Loca...

        PS C:\Users\zeroadmin> $global:RSSyncHash.FuncTestResult.Output
        This is Test-Func output  
#>
function New-RunSpace {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$RunspaceName,

        [Parameter(Mandatory=$True)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory=$False)]
        [switch]$MirrorCurrentEnv = $True,

        [Parameter(Mandatory=$False)]
        [switch]$Wait
    )

    #region >> Helper Functions

    function NewUniqueString {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string[]]$ArrayOfStrings,
    
            [Parameter(Mandatory=$True)]
            [string]$PossibleNewUniqueString
        )
    
        if (!$ArrayOfStrings -or $ArrayOfStrings.Count -eq 0 -or ![bool]$($ArrayOfStrings -match "[\w]")) {
            $PossibleNewUniqueString
        }
        else {
            $OriginalString = $PossibleNewUniqueString
            $Iteration = 1
            while ($ArrayOfStrings -contains $PossibleNewUniqueString) {
                $AppendedValue = "_$Iteration"
                $PossibleNewUniqueString = $OriginalString + $AppendedValue
                $Iteration++
            }
    
            $PossibleNewUniqueString
        }
    }

    #endregion >> Helper Functions

    #region >> Runspace Prep

    # Create Global Variable Names that don't conflict with other exisiting Global Variables
    $ExistingGlobalVariables = Get-Variable -Scope Global
    $DesiredGlobalVariables = @("RSSyncHash","RSJobCleanup","RSJobs")
    if ($ExistingGlobalVariables.Name -notcontains 'RSSyncHash') {
        $GlobalRSSyncHashName = NewUniqueString -PossibleNewUniqueString "RSSyncHash" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSSyncHashName = [hashtable]::Synchronized(@{})"
        $globalRSSyncHash = Get-Variable -Name $GlobalRSSyncHashName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSSyncHashName = 'RSSyncHash'

        # Also make sure that $RunSpaceName is a unique key in $global:RSSyncHash
        if ($RSSyncHash.Keys -contains $RunSpaceName) {
            $RSNameOriginal = $RunSpaceName
            $RunSpaceName = NewUniqueString -PossibleNewUniqueString $RunSpaceName -ArrayOfStrings $RSSyncHash.Keys
            if ($RSNameOriginal -ne $RunSpaceName) {
                Write-Warning "The RunspaceName '$RSNameOriginal' already exists. Your new RunspaceName will be '$RunSpaceName'"
            }
        }

        $globalRSSyncHash = $global:RSSyncHash
    }
    if ($ExistingGlobalVariables.Name -notcontains 'RSJobCleanup') {
        $GlobalRSJobCleanupName = NewUniqueString -PossibleNewUniqueString "RSJobCleanup" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSJobCleanupName = [hashtable]::Synchronized(@{})"
        $globalRSJobCleanup = Get-Variable -Name $GlobalRSJobCleanupName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSJobCleanupName = 'RSJobCleanup'
        $globalRSJobCleanup = $global:RSJobCleanup
    }
    if ($ExistingGlobalVariables.Name -notcontains 'RSJobs') {
        $GlobalRSJobsName = NewUniqueString -PossibleNewUniqueString "RSJobs" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSJobsName = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())"
        $globalRSJobs = Get-Variable -Name $GlobalRSJobsName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSJobsName = 'RSJobs'
        $globalRSJobs = $global:RSJobs
    }
    $GlobalVariables = @($GlobalSyncHashName,$GlobalRSJobCleanupName,$GlobalRSJobsName)
    #Write-Host "Global Variable names are: $($GlobalVariables -join ", ")"

    # Prep an empty pscustomobject for the RunspaceNameResult Key in $globalRSSyncHash
    $globalRSSyncHash."$RunspaceName`Result" = [pscustomobject]@{}

    #endregion >> Runspace Prep


    ##### BEGIN Runspace Manager Runspace (A Runspace to Manage All Runspaces) #####

    $globalRSJobCleanup.Flag = $True

    if ($ExistingGlobalVariables.Name -notcontains 'RSJobCleanup') {
        #Write-Host '$global:RSJobCleanup does NOT already exists. Creating New Runspace Manager Runspace...'
        $RunspaceMgrRunspace = [runspacefactory]::CreateRunspace()
        if ($PSVersionTable.PSEdition -ne "Core") {
            $RunspaceMgrRunspace.ApartmentState = "STA"
        }
        $RunspaceMgrRunspace.ThreadOptions = "ReuseThread"
        $RunspaceMgrRunspace.Open()

        # Prepare to Receive the Child Runspace Info to the RunspaceManagerRunspace
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("jobs",$globalRSJobs)
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

        $globalRSJobCleanup.PowerShell = [PowerShell]::Create().AddScript({

            ##### BEGIN Runspace Manager Runspace Helper Functions #####

            # Load the functions we packed up
            $FunctionsForSBUse | foreach { Invoke-Expression $_ }

            ##### END Runspace Manager Runspace Helper Functions #####

            # Routine to handle completed Runspaces
            $ProcessedJobRecords = [System.Collections.ArrayList]::new()
            $SyncHash.ProcessedJobRecords = $ProcessedJobRecords
            while ($JobCleanup.Flag) {
                if ($jobs.Count -gt 0) {
                    $Counter = 0
                    foreach($job in $jobs) { 
                        if ($ProcessedJobRecords.Runspace.InstanceId.Guid -notcontains $job.Runspace.InstanceId.Guid) {
                            $job | Export-CliXml "$HOME\job$Counter.xml" -Force
                            $CollectJobRecordPrep = Import-CliXML -Path "$HOME\job$Counter.xml"
                            Remove-Item -Path "$HOME\job$Counter.xml" -Force
                            $null = $ProcessedJobRecords.Add($CollectJobRecordPrep)
                        }

                        if ($job.AsyncHandle.IsCompleted -or $job.AsyncHandle -eq $null) {
                            [void]$job.PSInstance.EndInvoke($job.AsyncHandle)
                            $job.Runspace.Dispose()
                            $job.PSInstance.Dispose()
                            $job.AsyncHandle = $null
                            $job.PSInstance = $null
                        }
                        $Counter++
                    }

                    # Determine if we can have the Runspace Manager Runspace rest
                    $temparray = $jobs.clone()
                    $temparray | Where-Object {
                        $_.AsyncHandle.IsCompleted -or $_.AsyncHandle -eq $null
                    } | foreach {
                        $temparray.remove($_)
                    }

                    <#
                    if ($temparray.Count -eq 0 -or $temparray.AsyncHandle.IsCompleted -notcontains $False) {
                        $JobCleanup.Flag = $False
                    }
                    #>

                    Start-Sleep -Seconds 5

                    # Optional -
                    # For realtime updates to a GUI depending on changes in data within the $globalRSSyncHash, use
                    # a something like the following (replace with $RSSyncHash properties germane to your project)
                    <#
                    if ($RSSyncHash.WPFInfoDatagrid.Items.Count -ne 0 -and $($RSSynchash.IPArray.Count -ne 0 -or $RSSynchash.IPArray -ne $null)) {
                        if ($RSSyncHash.WPFInfoDatagrid.Items.Count -ge $RSSynchash.IPArray.Count) {
                            Update-Window -Control $RSSyncHash.WPFInfoPleaseWaitLabel -Property Visibility -Value "Hidden"
                        }
                    }
                    #>
                }
            } 
        })

        # Start the RunspaceManagerRunspace
        $globalRSJobCleanup.PowerShell.Runspace = $RunspaceMgrRunspace
        $globalRSJobCleanup.Thread = $globalRSJobCleanup.PowerShell.BeginInvoke()
    }

    ##### END Runspace Manager Runspace #####


    ##### BEGIN New Generic Runspace #####

    $GenericRunspace = [runspacefactory]::CreateRunspace()
    if ($PSVersionTable.PSEdition -ne "Core") {
        $GenericRunspace.ApartmentState = "STA"
    }
    $GenericRunspace.ThreadOptions = "ReuseThread"
    $GenericRunspace.Open()

    # Pass the $globalRSSyncHash to the Generic Runspace so it can read/write properties to it and potentially
    # coordinate with other runspaces
    $GenericRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

    # Pass $globalRSJobCleanup and $globalRSJobs to the Generic Runspace so that the Runspace Manager Runspace can manage it
    $GenericRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
    $GenericRunspace.SessionStateProxy.SetVariable("Jobs",$globalRSJobs)
    $GenericRunspace.SessionStateProxy.SetVariable("ScriptBlock",$ScriptBlock)

    # Pass all other notable environment characteristics 
    if ($MirrorCurrentEnv) {
        [System.Collections.ArrayList]$SetEnvStringArray = @()

        $VariablesNotToForward = @('globalRSSyncHash','RSSyncHash','globalRSJobCleanUp','RSJobCleanup',
        'globalRSJobs','RSJobs','ExistingGlobalVariables','DesiredGlobalVariables','$GlobalRSSyncHashName',
        'RSNameOriginal','GlobalRSJobCleanupName','GlobalRSJobsName','GlobalVariables','RunspaceMgrRunspace',
        'GenericRunspace','ScriptBlock')

        $Variables = Get-Variable
        foreach ($VarObj in $Variables) {
            if ($VariablesNotToForward -notcontains $VarObj.Name) {
                try {
                    $GenericRunspace.SessionStateProxy.SetVariable($VarObj.Name,$VarObj.Value)
                }
                catch {
                    Write-Verbose "Skipping `$$($VarObj.Name)..."
                }
            }
        }

        # Set Environment Variables
        $EnvVariables = Get-ChildItem Env:\
        if ($PSBoundParameters['EnvironmentVariablesToForward'] -and $EnvironmentVariablesToForward -notcontains '*') {
            $EnvVariables = foreach ($VarObj in $EnvVariables) {
                if ($EnvironmentVariablesToForward -contains $VarObj.Name) {
                    $VarObj
                }
            }
        }
        $SetEnvVarsPrep = foreach ($VarObj in $EnvVariables) {
            if ([char[]]$VarObj.Name -contains '(' -or [char[]]$VarObj.Name -contains ' ') {
                $EnvStringArr = @(
                    'try {'
                    $('    ${env:' + $VarObj.Name + '} = ' + "@'`n$($VarObj.Value)`n'@")
                    '}'
                    'catch {'
                    "    Write-Verbose 'Unable to forward environment variable $($VarObj.Name)'"
                    '}'
                )
            }
            else {
                $EnvStringArr = @(
                    'try {'
                    $('    $env:' + $VarObj.Name + ' = ' + "@'`n$($VarObj.Value)`n'@")
                    '}'
                    'catch {'
                    "    Write-Verbose 'Unable to forward environment variable $($VarObj.Name)'"
                    '}'
                )
            }
            $EnvStringArr -join "`n"
        }
        $SetEnvVarsString = $SetEnvVarsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetEnvVarsString)

        # Set Modules
        $Modules = Get-Module
        if ($PSBoundParameters['ModulesToForward'] -and $ModulesToForward -notcontains '*') {
            $Modules = foreach ($ModObj in $Modules) {
                if ($ModulesToForward -contains $ModObj.Name) {
                    $ModObj
                }
            }
        }

        $ModulesNotToForward = @('MiniLab')

        $SetModulesPrep = foreach ($ModObj in $Modules) {
            if ($ModulesNotToForward -notcontains $ModObj.Name) {
                $ModuleManifestFullPath = $(Get-ChildItem -Path $ModObj.ModuleBase -Recurse -File | Where-Object {
                    $_.Name -eq "$($ModObj.Name).psd1"
                }).FullName

                $ModStringArray = @(
                    '$tempfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())'
                    "if (![bool]('$($ModObj.Name)' -match '\.WinModule')) {"
                    '    try {'
                    "        Import-Module '$($ModObj.Name)' -NoClobber -ErrorAction Stop 2>`$tempfile"
                    '    }'
                    '    catch {'
                    '        try {'
                    "            Import-Module '$ModuleManifestFullPath' -NoClobber -ErrorAction Stop 2>`$tempfile"
                    '        }'
                    '        catch {'
                    "            Write-Warning 'Unable to Import-Module $($ModObj.Name)'"
                    '        }'
                    '    }'
                    '}'
                    'if (Test-Path $tempfile) {'
                    '    Remove-Item $tempfile -Force'
                    '}'
                )
                $ModStringArray -join "`n"
            }
        }
        $SetModulesString = $SetModulesPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetModulesString)
    
        # Set Functions
        $Functions = Get-ChildItem Function:\ | Where-Object {![System.String]::IsNullOrWhiteSpace($_.Name)}
        if ($PSBoundParameters['FunctionsToForward'] -and $FunctionsToForward -notcontains '*') {
            $Functions = foreach ($FuncObj in $Functions) {
                if ($FunctionsToForward -contains $FuncObj.Name) {
                    $FuncObj
                }
            }
        }
        $SetFunctionsPrep = foreach ($FuncObj in $Functions) {
            $FunctionText = Invoke-Expression $('@(${Function:' + $FuncObj.Name + '}.Ast.Extent.Text)')
            if ($($FunctionText -split "`n").Count -gt 1) {
                if ($($FunctionText -split "`n")[0] -match "^function ") {
                    if ($($FunctionText -split "`n") -match "^'@") {
                        Write-Warning "Unable to forward function $($FuncObj.Name) due to heredoc string: '@"
                    }
                    else {
                        'Invoke-Expression ' + "@'`n$FunctionText`n'@"
                    }
                }
            }
            elseif ($($FunctionText -split "`n").Count -eq 1) {
                if ($FunctionText -match "^function ") {
                    'Invoke-Expression ' + "@'`n$FunctionText`n'@"
                }
            }
        }
        $SetFunctionsString = $SetFunctionsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetFunctionsString)

        $GenericRunspace.SessionStateProxy.SetVariable("SetEnvStringArray",$SetEnvStringArray)
    }

    $GenericPSInstance = [powershell]::Create()

    # Define the main PowerShell Script that will run the $ScriptBlock
    $null = $GenericPSInstance.AddScript({
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Done -Value $False
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Errors -Value $null
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name ErrorsDetailed -Value $null
        $SyncHash."$RunspaceName`Result".Errors = [System.Collections.ArrayList]::new()
        $SyncHash."$RunspaceName`Result".ErrorsDetailed = [System.Collections.ArrayList]::new()
        $SyncHash."$RunspaceName`Result" | Add-Member -Type NoteProperty -Name ThisRunspace -Value $($(Get-Runspace)[-1])
        [System.Collections.ArrayList]$LiveOutput = @()
        $SyncHash."$RunspaceName`Result" | Add-Member -Type NoteProperty -Name LiveOutput -Value $LiveOutput
        

        
        ##### BEGIN Generic Runspace Helper Functions #####

        # Load the environment we packed up
        if ($SetEnvStringArray) {
            foreach ($obj in $SetEnvStringArray) {
                if (![string]::IsNullOrWhiteSpace($obj)) {
                    try {
                        Invoke-Expression $obj
                    }
                    catch {
                        $null = $SyncHash."$RunSpaceName`Result".Errors.Add($_)

                        $ErrMsg = "Problem with:`n$obj`nError Message:`n" + $($_ | Out-String)
                        $null = $SyncHash."$RunSpaceName`Result".ErrorsDetailed.Add($ErrMsg)
                    }
                }
            }
        }

        ##### END Generic Runspace Helper Functions #####

        ##### BEGIN Script To Run #####

        try {
            # NOTE: Depending on the content of the scriptblock, InvokeReturnAsIs() and Invoke-Command can cause
            # the Runspace to hang. Invoke-Expression works all the time.
            #$Result = $ScriptBlock.InvokeReturnAsIs()
            #$Result = Invoke-Command -ScriptBlock $ScriptBlock
            #$SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name SBString -Value $ScriptBlock.ToString()
            $Result = Invoke-Expression -Command $ScriptBlock.ToString()
            $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Output -Value $Result
        }
        catch {
            $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Output -Value $Result

            $null = $SyncHash."$RunSpaceName`Result".Errors.Add($_)

            $ErrMsg = "Problem with:`n$($ScriptBlock.ToString())`nError Message:`n" + $($_ | Out-String)
            $null = $SyncHash."$RunSpaceName`Result".ErrorsDetailed.Add($ErrMsg)
        }

        ##### END Script To Run #####

        $SyncHash."$RunSpaceName`Result".Done = $True
    })

    # Start the Generic Runspace
    $GenericPSInstance.Runspace = $GenericRunspace

    if ($Wait) {
        # The below will make any output of $GenericRunspace available in $Object in current scope
        $Object = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
        $GenericAsyncHandle = $GenericPSInstance.BeginInvoke($Object,$Object)

        $GenericRunspaceInfo = [pscustomobject]@{
            Name            = $RunSpaceName + "Generic"
            PSInstance      = $GenericPSInstance
            Runspace        = $GenericRunspace
            AsyncHandle     = $GenericAsyncHandle
        }
        $null = $globalRSJobs.Add($GenericRunspaceInfo)

        #while ($globalRSSyncHash."$RunSpaceName`Done" -ne $True) {
        while ($GenericAsyncHandle.IsCompleted -ne $True) {
            #Write-Host "Waiting for -ScriptBlock to finish..."
            Start-Sleep -Milliseconds 10
        }

        $globalRSSyncHash."$RunspaceName`Result".Output
        #$Object
    }
    else {
        $HelperRunspace = [runspacefactory]::CreateRunspace()
        if ($PSVersionTable.PSEdition -ne "Core") {
            $HelperRunspace.ApartmentState = "STA"
        }
        $HelperRunspace.ThreadOptions = "ReuseThread"
        $HelperRunspace.Open()

        # Pass the $globalRSSyncHash to the Helper Runspace so it can read/write properties to it and potentially
        # coordinate with other runspaces
        $HelperRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

        # Pass $globalRSJobCleanup and $globalRSJobs to the Helper Runspace so that the Runspace Manager Runspace can manage it
        $HelperRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
        $HelperRunspace.SessionStateProxy.SetVariable("Jobs",$globalRSJobs)

        # Set any other needed variables in the $HelperRunspace
        $HelperRunspace.SessionStateProxy.SetVariable("GenericRunspace",$GenericRunspace)
        $HelperRunspace.SessionStateProxy.SetVariable("GenericPSInstance",$GenericPSInstance)
        $HelperRunspace.SessionStateProxy.SetVariable("RunSpaceName",$RunSpaceName)

        $HelperPSInstance = [powershell]::Create()

        # Define the main PowerShell Script that will run the $ScriptBlock
        $null = $HelperPSInstance.AddScript({
            ##### BEGIN Script To Run #####

            # The below will make any output of $GenericRunspace available in $Object in current scope
            $Object = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
            $GenericAsyncHandle = $GenericPSInstance.BeginInvoke($Object,$Object)

            $GenericRunspaceInfo = [pscustomobject]@{
                Name            = $RunSpaceName + "Generic"
                PSInstance      = $GenericPSInstance
                Runspace        = $GenericRunspace
                AsyncHandle     = $GenericAsyncHandle
            }
            $null = $Jobs.Add($GenericRunspaceInfo)

            #while ($SyncHash."$RunSpaceName`Done" -ne $True) {
            while ($GenericAsyncHandle.IsCompleted -ne $True) {
                #Write-Host "Waiting for -ScriptBlock to finish..."
                Start-Sleep -Milliseconds 10
            }

            ##### END Script To Run #####
        })

        # Start the Helper Runspace
        $HelperPSInstance.Runspace = $HelperRunspace
        $HelperAsyncHandle = $HelperPSInstance.BeginInvoke()

        $HelperRunspaceInfo = [pscustomobject]@{
            Name            = $RunSpaceName + "Helper"
            PSInstance      = $HelperPSInstance
            Runspace        = $HelperRunspace
            AsyncHandle     = $HelperAsyncHandle
        }
        $null = $globalRSJobs.Add($HelperRunspaceInfo)
    }

    ##### END Generic Runspace
}


<#
    .SYNOPSIS
        Uninstalls the specified Program. The value provided to the -ProgramName parameter does NOT have
        to be an exact match. If multiple matches are found, the function prompts for a specific selection
        (one of which is 'all of the above').

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER ProgramName
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of the program you would like to uninstall. The
        value provided to this parameter does not have to be an exact match. If multiple matches are found the
        function prompts for a specfic selection (one of which is 'all of the above').

    .PARAMETER UninstallAllSimilarlyNamedPackages
        This parameter is OPTIONAL.

        This parameter is a switch. If used, all programs that match the string provided to the -ProgramName
        parameter will be uninstalled. The user will NOT receive a prompt for specific selection.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Uninstall-Program -ProgramName python

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -
        
        PS C:\Users\zeroadmin> Uninstall-Program -ProgramName python -UninstallAllSimilarlyNamedPackages

#>
function Uninstall-Program {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$True,
            Position=0
        )]
        [string]$ProgramName,

        [Parameter(Mandatory=$False)]
        [switch]$UninstallAllSimilarlyNamedPackages
    )

    #region >> Variable/Parameter Transforms and PreRun Prep

    if (!$(GetElevation)) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function must be ran from an elevated PowerShell Session (i.e. 'Run as Administrator')! Halting!"
        $global:FunctionResult = "1"
        return
    }

    try {
        #$null = clist --local-only
        $PackageManagerInstallObjects = Get-AllPackageInfo -ProgramName $ProgramName -ErrorAction SilentlyContinue
        [array]$ChocolateyInstalledProgramObjects = $PackageManagerInstallObjects.ChocolateyInstalledProgramObjects
        [array]$PSGetInstalledPackageObjects = $PackageManagerInstallObjects.PSGetInstalledPackageObjects
        [array]$RegistryProperties = $PackageManagerInstallObjects.RegistryProperties
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    #endregion >> Variable/Parameter Transforms and PreRun Prep
    

    #region >> Main Body
    if ($ChocolateyInstalledProgramObjects.Count -eq 0 -and $PSGetInstalledPackageObjects.Count -eq 0) {
        Write-Error "Unable to find an installed program matching the name $ProgramName! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # We MIGHT be able to get the directory where the Program's binaries are by using Get-Command.
    # This info is only useful if the uninstall isn't clean for some reason
    $ProgramExePath = $(Get-Command $ProgramName -ErrorAction SilentlyContinue).Source
    if ($ProgramExePath) {
        $ProgramParentDirPath = $ProgramExePath | Split-Path -Parent
    }

    [System.Collections.ArrayList]$PSGetUninstallFailures = @()
    if ($PSGetInstalledPackageObjects.Count -gt 0) {
        if ($PSGetInstalledPackageObjects.Count -gt 1) {
            Write-Warning "Multiple packages matching the name '$ProgramName' have been found."

            for ($i=0; $i -lt $PSGetInstalledPackageObjects.Count; $i++) {
                Write-Host "$i) $($PSGetInstalledPackageObjects[$i].Name)"
            }
            Write-Host "$($PSGetInstalledPackageObjects.Count)) All of the Above"

            [int[]]$ValidChoiceNumbers = 0..$($PSGetInstalledPackageObjects.Count)
            $UninstallChoice = Read-Host -Prompt "Please enter one or more numbers (separated by commas) that correspond to the program(s) you would like to uninstall."
            if ($UninstallChoice -match ',') {
                [array]$UninstallChoiceArray = $($UninstallChoice -split ',').Trim()
            }
            else {
                [array]$UninstallChoiceArray = $UninstallChoice
            }

            [System.Collections.ArrayList]$InvalidChoices = @()
            foreach ($ChoiceNumber in $UninstallChoiceArray) {
                if ($ValidChoiceNumbers -notcontains $ChoiceNumber) {
                    $null = $InvalidChoices.Add($ChoiceNumber)
                }
            }

            while ($InvalidChoices.Count -ne 0) {
                Write-Warning "The following selections are NOT valid Choice Numbers: $($InvalidChoices -join ', ')"

                $UninstallChoice = Read-Host -Prompt "Please enter one or more numbers (separated by commas) that correspond to the program(s) you would like to uninstall."
                if ($UninstallChoice -match ',') {
                    [array]$UninstallChoiceArray = $($UninstallChoice -split ',').Trim()
                }
                else {
                    [array]$UninstallChoiceArray = $UninstallChoice
                }

                [System.Collections.ArrayList]$InvalidChoices = @()
                foreach ($ChoiceNumber in $UninstallChoiceArray) {
                    if ($ValidChoiceNumbers -notcontains $ChoiceNumber) {
                        $null = $InvalidChoices.Add($ChoiceNumber)
                    }
                }
            }

            # Make sure that $UninstallChoiceArray is an integer array sorted 0..N
            try {
                [int[]]$UninstallChoiceArray = $UninstallChoiceArray | Sort-Object
            }
            catch {
                Write-Error $_
                Write-Error "`$UninstallChoiceArray cannot be converted to an array of integers! Halting!"
                $global:FunctionResult = "1"
                return
            }

            if ($UninstallChoiceArray -notcontains $PSGetInstalledPackageObjects.Count) {
                [array]$FinalPackagesSelectedForUninstall = foreach ($ChoiceNumber in $UninstallChoiceArray) {
                    $PSGetInstalledPackageObjects[$ChoiceNumber]
                }
            }
            else {
                [array]$FinalPackagesSelectedForUninstall = $PSGetInstalledPackageObjects
            }
        }
        if ($PSGetInstalledPackageObjects.Count -eq 1) {
            [array]$FinalPackagesSelectedForUninstall = $PSGetInstalledPackageObjects
        }
            
        # Make sure that we uninstall Packages where 'ProviderName' is 'Programs' LAST
        foreach ($Package in $FinalPackagesSelectedForUninstall) {
            if ($Package.ProviderName -ne "Programs") {
                Write-Host "Uninstalling $($Package.Name)..."
                $UninstallResult = $Package | Uninstall-Package -Force -Confirm:$False -ErrorAction SilentlyContinue
            }
        }
        foreach ($Package in $FinalPackagesSelectedForUninstall) {
            if ($Package.ProviderName -eq "Programs") {
                Write-Host "Uninstalling $($Package.Name)..."
                $UninstallResult = $Package | Uninstall-Package -Force -Confirm:$False -ErrorAction SilentlyContinue
            }
        }
    }

    try {
        $PackageManagerInstallObjects = Get-AllPackageInfo -ProgramName $ProgramName -ErrorAction Stop
        [array]$ChocolateyInstalledProgramObjects = $PackageManagerInstallObjects.ChocolateyInstalledProgramObjects
        [array]$PSGetInstalledPackageObjects = $PackageManagerInstallObjects.PSGetInstalledPackageObjects
        [array]$RegistryProperties = $PackageManagerInstallObjects.RegistryProperties
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # If we still have lingering packages, we need to try uninstall via what the Registry says the uninstall command is...
    if ($PSGetInstalledPackageObjects.Count -gt 0) {
        if ($RegistryProperties.Count -gt 0) {
            foreach ($Program in $RegistryProperties) {
                if ($Program.QuietUninstallString -ne $null) {
                    Invoke-Expression "& $($Program.QuietUninstallString)"
                }
            }
        }
    }

    try {
        $PackageManagerInstallObjects = Get-AllPackageInfo -ProgramName $ProgramName -ErrorAction Stop
        [array]$ChocolateyInstalledProgramObjects = $PackageManagerInstallObjects.ChocolateyInstalledProgramObjects
        [array]$PSGetInstalledPackageObjects = $PackageManagerInstallObjects.PSGetInstalledPackageObjects
        [array]$RegistryProperties = $PackageManagerInstallObjects.RegistryProperties
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # If we STILL have lingering packages, we'll just delete from the registry directly and clean up any binaries on the filesystem...
    if ($PSGetInstalledPackageObjects.Count -gt 0) {
        [System.Collections.ArrayList]$DirectoriesThatMightNeedToBeRemoved = @()
        
        if ($RegistryProperties.Count -gt 0) {
            foreach ($Program in $RegistryProperties) {
                if (Test-Path $Program.PSPath) {
                    $null = $DirectoriesThatMightNeedToBeRemoved.Add($Program.PSPath)
                    #Remove-Item -Path $Program.PSPath -Recurse -Force
                }
            }
        }

        if ($ProgramParentDirPath) {
            if (Test-Path $ProgramParentDirPath) {
                $null = $DirectoriesThatMightNeedToBeRemoved.Add($ProgramParentDirPath)
                #Remove-Item $ProgramParentDirPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    try {
        $PackageManagerInstallObjects = Get-AllPackageInfo -ProgramName $ProgramName -ErrorAction Stop
        [array]$ChocolateyInstalledProgramObjects = $PackageManagerInstallObjects.ChocolateyInstalledProgramObjects
        [array]$PSGetInstalledPackageObjects = $PackageManagerInstallObjects.PSGetInstalledPackageObjects
        [array]$RegistryProperties = $PackageManagerInstallObjects.RegistryProperties
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Now take care of chocolatey if necessary...
    if ($ChocolateyInstalledProgramObjects.Count -gt 0) {
        $ChocoUninstallAttempt = $True
        [System.Collections.ArrayList]$ChocoUninstallFailuresPrep = @()
        [System.Collections.ArrayList]$ChocoUninstallSuccesses = @()

        $ErrorFile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
        #$ErrorFile
        foreach ($ProgramObj in $ChocolateyInstalledProgramObjects) {
            #Write-Host "Running $($(Get-Command choco).Source) uninstall $($ProgramObj.ProgramName) -y"
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
            $ProcessInfo.FileName = $(Get-Command choco).Source
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.Arguments = "uninstall $($ProgramObj.ProgramName) -y --force" # optionally -n --remove-dependencies
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            # Below $FinishedInAlottedTime returns boolean true/false
            $FinishedInAlottedTime = $Process.WaitForExit(60000)
            if (!$FinishedInAlottedTime) {
                $Process.Kill()
            }
            $stdout = $Process.StandardOutput.ReadToEnd()
            $stderr = $Process.StandardError.ReadToEnd()
            $AllOutput = $stdout + $stderr

            if ($AllOutput -match "failed") {
                $null = $ChocoUninstallFailuresPrep.Add($ProgramObj)
            }
            else {
                $null = $ChocoUninstallSuccesses.Add($ProgramObj)
            }
        }
    }

    # Re-Check all PackageManager Objects because an uninstall action may/may not have happened
    try {
        $PackageManagerInstallObjects = Get-AllPackageInfo -ProgramName $ProgramName -ErrorAction Stop
        [array]$ChocolateyInstalledProgramObjects = $PackageManagerInstallObjects.ChocolateyInstalledProgramObjects
        [array]$PSGetInstalledPackageObjects = $PackageManagerInstallObjects.PSGetInstalledPackageObjects
        [array]$RegistryProperties = $PackageManagerInstallObjects.RegistryProperties
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if ($ChocolateyInstalledProgramObjects.Count -gt 0 -or $PSGetInstalledPackageObjects.Count -gt 0 -or $RegistryProperties.Count -gt 0) {
        Write-Warning "The program '$ProgramName' did NOT cleanly uninstall. Please review output of the Uninstall-Program function for details about lingering references."
    }
    else {
        Write-Host "The program '$ProgramName' was uninstalled successfully!" -ForegroundColor Green
    }

    [pscustomobject]@{
        DirectoriesThatMightNeedToBeRemoved = [array]$DirectoriesThatMightNeedToBeRemoved
        ChocolateyInstalledProgramObjects   = [array]$ChocolateyInstalledProgramObjects
        PSGetInstalledPackageObjects        = [array]$PSGetInstalledPackageObjects
        RegistryProperties                  = [array]$RegistryProperties
    }

    #endregion >> Main Body
}


<#
    .SYNOPSIS
        This function updates $env:Path to include directories that contain programs installed via the Chocolatey
        Package Repository / Chocolatey CmdLine. It also loads Chocolatey PowerShell Modules required for package
        installation via a Chocolatey Package's 'chocoinstallscript.ps1'.

        NOTE: This function will remove paths in $env:Path that do not exist on teh filesystem.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER ChocolateyDirectory
        This parameter is OPTIONAL.

        This parameter takes a string that represents the path to the location of the Chocolatey directory on your filesystem.
        Use this parameter ONLY IF Chocolatey packages are NOT located under "C:\Chocolatey" or "C:\ProgramData\chocolatey". 

    .PARAMETER UninstallAllSimilarlyNamedPackages
        This parameter is OPTIONAL.

        This parameter is a switch. If used, all programs that match the string provided to the -ProgramName
        parameter will be uninstalled. The user will NOT receive a prompt for specific selection.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -
        
        PS C:\Users\zeroadmin> Update-ChocolateyEnv

#>
function Update-ChocolateyEnv {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$ChocolateyDirectory
    )

    ##### BEGIN Main Body #####

    if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
        [System.Collections.ArrayList]$PotentialChocolateyPaths = @()
        if ($ChocolateyDirectory) {
            $null = $PotentialChocolateyPaths.Add($ChocolateyDirectory)
        }
        else {
            if (Test-Path "C:\Chocolatey") {
                $null = $PotentialChocolateyPaths.Add("C:\Chocolatey")
            }
            if (Test-Path "C:\ProgramData\chocolatey") {
                $null = $PotentialChocolateyPaths.Add("C:\ProgramData\chocolatey")
            }
        }
    }
    else {
        $ChocolateyPath = "$($($(Get-Command choco).Source -split "chocolatey")[0])chocolatey"
    }
    
    [System.Collections.ArrayList]$ChocolateyPathsPrep = @()
    [System.Collections.ArrayList]$ChocolateyPathsToAddToEnvPath = @()
    foreach ($PotentialPath in $PotentialChocolateyPaths) {
        if (Test-Path $PotentialPath) {
            $($(Get-ChildItem $PotentialPath -Directory | foreach {
                Get-ChildItem $_.FullName -Recurse -File
            } | foreach {
                if ($_.Extension -eq ".exe" -or $_.Extension -eq ".bat") {
                    $_.Directory.FullName
                }
            }) | Sort-Object | Get-Unique) | foreach {
                $null = $ChocolateyPathsPrep.Add($_.Trim("\\"))
            }   
        }
    }
    foreach ($ChocoPath in $ChocolateyPathsPrep) {
        if ($(Test-Path $ChocoPath) -and $($env:Path -split ";") -notcontains $ChocoPath -and $ChocoPath -ne $null) {
            $null = $ChocolateyPathsToAddToEnvPath.Add($ChocoPath)
        }
    }

    foreach ($ChocoPath in $ChocolateyPathsToAddToEnvPath) {
        if ($env:Path[-1] -eq ";") {
            $env:Path = "$env:Path" + $ChocoPath + ";"
        }
        else {
            $env:Path = "$env:Path" + ";" + $ChocoPath
        }
    }

    # Remove any repeats in $env:Path
    $UpdatedEnvPath = $($($($env:Path -split ";") | foreach {
        if (-not [System.String]::IsNullOrWhiteSpace($_)) {
            if (Test-Path $_) {
                $_.Trim("\\")
            }
        }
    }) | Select-Object -Unique) -join ";"

    # Next, find chocolatey-core.psm1, chocolateysetup.psm1, chocolateyInstaller.psm1, and chocolateyProfile.psm1
    # and import them
    [System.Collections.ArrayList]$PotentialHelpersDirItems = @()
    foreach ($PotentialPath in $PotentialChocolateyPaths) {
        [array]$HelperDir = Get-ChildItem $PotentialPath -Recurse -Directory -Filter "helpers" | Where-Object {$_.FullName -match "chocolatey\\helpers"}
        if ($HelperDir.Count -gt 0) {
            $null = $PotentialHelpersDirItems.Add($HelperDir)
        }
    }
    if ($PotentialHelpersDirItems.Count -gt 0) {
        [array]$ChocoHelperDir = $($PotentialHelpersDirItems | Sort-Object -Property LastWriteTime)[-1]
    }

    if ($ChocoHelperDirItem -ne $null) {
        $ChocoCoreModule = $(Get-ChildItem -Path $ChocoHelperDirItem.FullName -Recurse -File -Filter "*chocolatey-core.psm1").FullName
        $ChocoSetupModule = $(Get-ChildItem -Path $ChocoHelperDirItem.FullName -Recurse -File -Filter "*chocolateysetup.psm1").FullName
        $ChocoInstallerModule = $(Get-ChildItem -Path $ChocoHelperDirItem.FullName -Recurse -File -Filter "*chocolateyInstaller.psm1").FullName
        $ChocoProfileModule = $(Get-ChildItem -Path $ChocoHelperDirItem.FullName -Recurse -File -Filter "*chocolateyProfile.psm1").FullName

        $ChocoModulesToImportPrep = @($ChocoCoreModule, $ChocoSetupModule, $ChocoInstallerModule, $ChocoProfileModule)
        [System.Collections.ArrayList]$ChocoModulesToImport = @()
        foreach ($ModulePath in $ChocoModulesToImportPrep) {
            if ($ModulePath -ne $null) {
                $null = $ChocoModulesToImport.Add($ModulePath)
            }
        }

        foreach ($ModulePath in $ChocoModulesToImport) {
            Remove-Module -Name $([System.IO.Path]::GetFileNameWithoutExtension($ModulePath)) -ErrorAction SilentlyContinue
            Import-Module -Name $ModulePath
        }
    }

    $UpdatedEnvPath

    ##### END Main Body #####

}


<#
    .SYNOPSIS
        This function updates PowerShellGet and PackageManagement Powershell Modules to the latest available versions.

        IMPORTANT NOTE: If the Modules are update, their respective cmdlets MIGHT be broken until you start a new
        PowerShell Session, so it is recommended that you start a new PowerShell Session after the Modules are updated
        just to be certain that the cmdlets work as intended.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER AddChocolateyPackageProvider
        This parameter is OPTIONAL.

        This parameter is a switch. If it is used, the Chocolatey Package Provider will be added and trusted by default.

    .PARAMETER InstallNuGetCmdLine
        This parameter is OPTIONAL.

        This parameter is a switch. If it is used, the Nuget.CmdLine package will be installed (i.e. nuget.exe).

    .PARAMETER LoadUpdatedModulesInSameSession
        This parameter is OPTIONAL.

        This parameter is a switch. If used, if the PowerShellGet/PackageManagement Modules are updated,
        the updated Modules will be reloaded in the same PowerShell Session. This will break several
        cmdlets, so using this parameter not recommended unless you are certan that the cmdlets you are planning
        on using will still work.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -
        
        PS C:\Users\zeroadmin> Update-PackageManagement -AddChocolateyPackageProvider -InstallNuGetCmdLine

#>
function Update-PackageManagement {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$False)]
        [switch]$AddChocolateyPackageProvider,

        [Parameter(Mandatory=$False)]
        [switch]$InstallNuGetCmdLine,

        [Parameter(Mandatory=$False)]
        [switch]$LoadUpdatedModulesInSameSession
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # We're going to need Elevated privileges for some commands below, so might as well try to set this up now.
    if (!$(GetElevation)) {
        Write-Error "The Update-PackageManagement function must be run with elevated privileges. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$([Environment]::Is64BitProcess)) {
        Write-Error "You are currently running the 32-bit version of PowerShell. Please run the 64-bit version found under C:\Windows\SysWOW64\WindowsPowerShell\v1.0 and try again. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($PSVersionTable.PSEdition -eq "Core") {
        Write-Error "The Update-PackageManagement function should only be used in Windows PowerShell, *not* PowerShell Core! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -ne "Win32NT" -and $AddChocolateyPackageProvider) {
        Write-Error "The Chocolatey Repo should only be added on a Windows OS! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($InstallNuGetCmdLine -and !$AddChocolateyPackageProvider) {
        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5) {
            if ($(Get-PackageProvider).Name -notcontains "Chocolatey") {
                $WarningMessage = "NuGet Command Line Tool cannot be installed without using Chocolatey. Would you like to use the Chocolatey Package Provider (NOTE: This is NOT an installation of the chocolatey command line)?"
                $WarningResponse = PauseForWarning -PauseTimeInSeconds 15 -Message $WarningMessage
                if ($WarningResponse) {
                    $AddChocolateyPackageProvider = $true
                }
            }
            else {
                $AddChocolateyPackageProvider = $true
            }
        }
        elseif ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
            if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
                $WarningMessage = "NuGet Command Line Tool cannot be installed without using Chocolatey. Would you like to install Chocolatey Command Line Tools in order to install NuGet Command Line Tools?"
                $WarningResponse = PauseForWarning -PauseTimeInSeconds 15 -Message $WarningMessage
                if ($WarningResponse) {
                    $AddChocolateyPackageProvider = $true
                }
            }
            else {
                $AddChocolateyPackageProvider = $true
            }
        }
        elseif ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Unix") {
            $WarningMessage = "The NuGet Command Line Tools binary nuget.exe can be downloaded, but will not be able to be run without Mono. Do you want to download the latest stable nuget.exe?"
            $WarningResponse = PauseForWarning -PauseTimeInSeconds 15 -Message $WarningMessage
            if ($WarningResponse) {
                Write-Host "Downloading latest stable nuget.exe..."
                $OutFilePath = GetNativePath -PathAsStringArray @($HOME, "Downloads", "nuget.exe")
                Invoke-WebRequest -Uri "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" -OutFile $OutFilePath
            }
            $AddChocolateyPackageProvider = $false
        }
    }

    if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5) {
        # Check to see if we're behind a proxy
        if ([System.Net.WebProxy]::GetDefaultProxy().Address -ne $null) {
            $ProxyAddress = [System.Net.WebProxy]::GetDefaultProxy().Address
            [system.net.webrequest]::defaultwebproxy = New-Object system.net.webproxy($ProxyAddress)
            [system.net.webrequest]::defaultwebproxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
            [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true
        }
    }
    # TODO: Figure out how to identify default proxy on PowerShell Core...

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    if ($PSVersionTable.PSVersion.Major -lt 5) {
        if ($(Get-Module -ListAvailable).Name -notcontains "PackageManagement") {
            Write-Host "Downloading PackageManagement .msi installer..."
            $OutFilePath = GetNativePath -PathAsStringArray @($HOME, "Downloads", "PackageManagement_x64.msi")
            Invoke-WebRequest -Uri "https://download.microsoft.com/download/C/4/1/C41378D4-7F41-4BBE-9D0D-0E4F98585C61/PackageManagement_x64.msi" -OutFile $OutFilePath
            
            $DateStamp = Get-Date -Format yyyyMMddTHHmmss
            $MSIFullPath = $OutFilePath
            $MSIParentDir = $MSIFullPath | Split-Path -Parent
            $MSIFileName = $MSIFullPath | Split-Path -Leaf
            $MSIFileNameOnly = $MSIFileName -replace "\.msi",""
            $logFile = GetNativePath -PathAsStringArray @($MSIParentDir, "$MSIFileNameOnly$DateStamp.log")
            $MSIArguments = @(
                "/i"
                $MSIFullPath
                "/qn"
                "/norestart"
                "/L*v"
                $logFile
            )
            Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow
        }
        while ($($(Get-Module -ListAvailable).Name -notcontains "PackageManagement") -and $($(Get-Module -ListAvailable).Name -notcontains "PowerShellGet")) {
            Write-Host "Waiting for PackageManagement and PowerShellGet Modules to become available"
            Start-Sleep -Seconds 1
        }
        Write-Host "PackageManagement and PowerShellGet Modules are ready. Continuing..."
    }

    # We need to load whatever versions of PackageManagement/PowerShellGet are available on the Local Host in order
    # to use the Find-Module cmdlet to find out what the latest versions of each Module are...

    # ...but because there are sometimes issues with version compatibility between PackageManagement/PowerShellGet,
    # after loading the latest PackageManagement Module we need to try/catch available versions of PowerShellGet until
    # one of them actually loads
    
    # Set LatestLocallyAvailable variables...
    $PackageManagementLatestLocallyAvailableVersionItem = $(Get-Module -ListAvailable -All | Where-Object {$_.Name -eq "PackageManagement"} | Sort-Object -Property Version)[-1]
    $PowerShellGetLatestLocallyAvailableVersionItem = $(Get-Module -ListAvailable -All | Where-Object {$_.Name -eq "PowerShellGet"} | Sort-Object -Property Version)[-1]
    $PackageManagementLatestLocallyAvailableVersion = $PackageManagementLatestLocallyAvailableVersionItem.Version
    $PowerShellGetLatestLocallyAvailableVersion = $PowerShellGetLatestLocallyAvailableVersionItem.Version
    $PSGetLocallyAvailableVersions = $(Get-Module -ListAvailable -All | Where-Object {$_.Name -eq "PowerShellGet"}).Version | Sort-Object -Property Version | Get-Unique
    $PSGetLocallyAvailableVersions = $PSGetLocallyAvailableVersions | Sort-Object -Descending
    

    if ($(Get-Module).Name -notcontains "PackageManagement") {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion
        }
        else {
            Import-Module "PackageManagement"
        }
    }
    if ($(Get-Module).Name -notcontains "PowerShellGet") {
        foreach ($version in $PSGetLocallyAvailableVersions) {
            try {
                $ImportedPSGetModule = Import-Module "PowerShellGet" -RequiredVersion $version -PassThru -ErrorAction SilentlyContinue
                if (!$ImportedPSGetModule) {throw}

                break
            }
            catch {
                continue
            }
        }
    }

    if ($(Get-Module -Name PackageManagement).ExportedCommands.Count -eq 0 -or
        $(Get-Module -Name PowerShellGet).ExportedCommands.Count -eq 0
    ) {
        Write-Warning "Either PowerShellGet or PackagementManagement Modules were not able to be loaded Imported successfully due to an update initiated within the current session. Please close this PowerShell Session, open a new one, and run this function again."

        $Result = [pscustomobject][ordered]@{
            PackageManagementUpdated  = $false
            PowerShellGetUpdated      = $false
            NewPSSessionRequired      = $true
        }

        $Result
        return
    }

    # Determine if the NuGet Package Provider is available. If not, install it, because it needs it for some reason
    # that is currently not clear to me. Point is, if it's not installed it will prompt you to install it, so just
    # do it beforehand.
    if ($(Get-PackageProvider).Name -notcontains "NuGet") {
        Install-PackageProvider "NuGet" -Scope CurrentUser -Force
        Register-PackageSource -Name 'nuget.org' -Location 'https://api.nuget.org/v3/index.json' -ProviderName NuGet -Trusted -Force -ForceBootstrap
    }

    if ($AddChocolateyPackageProvider) {
        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5) {
            # Install the Chocolatey Package Provider to be used with PowerShellGet
            if ($(Get-PackageProvider).Name -notcontains "Chocolatey") {
                Install-PackageProvider "Chocolatey" -Scope CurrentUser -Force
                # The above Install-PackageProvider "Chocolatey" -Force DOES register a PackageSource Repository, so we need to trust it:
                Set-PackageSource -Name Chocolatey -Trusted

                # Make sure packages installed via Chocolatey PackageProvider are part of $env:Path
                [System.Collections.ArrayList]$ChocolateyPathsPrep = @()
                [System.Collections.ArrayList]$ChocolateyPathsFinal = @()
                $env:ChocolateyPSProviderPath = "C:\Chocolatey"

                if (Test-Path $env:ChocolateyPSProviderPath) {
                    if (Test-Path "$env:ChocolateyPSProviderPath\lib") {
                        $OtherChocolateyPathsToAdd = $(Get-ChildItem "$env:ChocolateyPSProviderPath\lib" -Directory | foreach {
                            Get-ChildItem $_.FullName -Recurse -File
                        } | foreach {
                            if ($_.Extension -eq ".exe") {
                                $_.Directory.FullName
                            }
                        }) | foreach {
                            $null = $ChocolateyPathsPrep.Add($_)
                        }
                    }
                    if (Test-Path "$env:ChocolateyPSProviderPath\bin") {
                        $OtherChocolateyPathsToAdd = $(Get-ChildItem "$env:ChocolateyPSProviderPath\bin" -Directory | foreach {
                            Get-ChildItem $_.FullName -Recurse -File
                        } | foreach {
                            if ($_.Extension -eq ".exe") {
                                $_.Directory.FullName
                            }
                        }) | foreach {
                            $null = $ChocolateyPathsPrep.Add($_)
                        }
                    }
                }
                
                if ($ChocolateyPathsPrep) {
                    foreach ($ChocoPath in $ChocolateyPathsPrep) {
                        if ($(Test-Path $ChocoPath) -and $OriginalEnvPathArray -notcontains $ChocoPath) {
                            $null = $ChocolateyPathsFinal.Add($ChocoPath)
                        }
                    }
                }
            
                try {
                    $ChocolateyPathsFinal = $ChocolateyPathsFinal | Sort-Object | Get-Unique
                }
                catch {
                    [System.Collections.ArrayList]$ChocolateyPathsFinal = @($ChocolateyPathsFinal)
                }
                if ($ChocolateyPathsFinal.Count -ne 0) {
                    $ChocolateyPathsAsString = $ChocolateyPathsFinal -join ";"
                }

                foreach ($ChocPath in $ChocolateyPathsFinal) {
                    if ($($env:Path -split ";") -notcontains $ChocPath) {
                        if ($env:Path[-1] -eq ";") {
                            $env:Path = "$env:Path$ChocPath"
                        }
                        else {
                            $env:Path = "$env:Path;$ChocPath"
                        }
                    }
                }

                if ($InstallNuGetCmdLine) {
                    # Next, install the NuGet CLI using the Chocolatey Repo
                    try {
                        Write-Host "Trying to find Chocolatey Package Nuget.CommandLine..."
                        while (!$(Find-Package Nuget.CommandLine)) {
                            Write-Host "Trying to find Chocolatey Package Nuget.CommandLine..."
                            Start-Sleep -Seconds 2
                        }
                        
                        Get-Package NuGet.CommandLine -ErrorAction SilentlyContinue
                        if (!$?) {
                            throw
                        }
                    } 
                    catch {
                        Install-Package Nuget.CommandLine -Source chocolatey -Force
                    }
                    
                    # Ensure there's a symlink from C:\Chocolatey\bin to the real NuGet.exe under C:\Chocolatey\lib
                    $NuGetSymlinkTest = Get-ChildItem "C:\Chocolatey\bin" | Where-Object {$_.Name -eq "NuGet.exe" -and $_.LinkType -eq "SymbolicLink"}
                    $RealNuGetPath = $(Resolve-Path "C:\Chocolatey\lib\*\*\NuGet.exe").Path
                    $TestRealNuGetPath = Test-Path $RealNuGetPath
                    if (!$NuGetSymlinkTest -and $TestRealNuGetPath) {
                        New-Item -Path "C:\Chocolatey\bin\NuGet.exe" -ItemType SymbolicLink -Value $RealNuGetPath
                    }
                }
            }
        }
        if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
            # Install the Chocolatey Command line
            if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
                # Suppressing all errors for Chocolatey cmdline install. They will only be a problem if
                # there is a Web Proxy between you and the Internet
                $env:chocolateyUseWindowsCompression = 'true'
                $null = Invoke-Expression $([System.Net.WebClient]::new()).DownloadString("https://chocolatey.org/install.ps1") -ErrorVariable ChocolateyInstallProblems 2>&1 6>&1
                $DateStamp = Get-Date -Format yyyyMMddTHHmmss
                $ChocolateyInstallLogFile = GetNativePath -PathAsStringArray @($(Get-Location).Path, "ChocolateyInstallLog_$DateStamp.txt")
                $ChocolateyInstallProblems | Out-File $ChocolateyInstallLogFile
            }

            if ($InstallNuGetCmdLine) {
                if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
                    Write-Error "Unable to find chocolatey.exe, however, it should be installed. Please check your System PATH and `$env:Path and try again. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    # 'choco update' aka 'cup' will update if already installed or install if not installed
                    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                    $ProcessInfo.WorkingDirectory = $NuGetPackagesPath
                    $ProcessInfo.FileName = "cup"
                    $ProcessInfo.RedirectStandardError = $true
                    $ProcessInfo.RedirectStandardOutput = $true
                    $ProcessInfo.UseShellExecute = $false
                    $ProcessInfo.Arguments = "nuget.commandline -y"
                    $Process = New-Object System.Diagnostics.Process
                    $Process.StartInfo = $ProcessInfo
                    $Process.Start() | Out-Null
                    $stdout = $($Process.StandardOutput.ReadToEnd()).Trim()
                    $stderr = $($Process.StandardError.ReadToEnd()).Trim()
                    $AllOutput = $stdout + $stderr
                    $AllOutput = $AllOutput -split "`n"
                }
                # NOTE: The chocolatey install should take care of setting $env:Path and System PATH so that
                # choco binaries and packages installed via chocolatey can be found here:
                # C:\ProgramData\chocolatey\bin
            }
        }
    }
    # Next, set the PSGallery PowerShellGet PackageProvider Source to Trusted
    if ($(Get-PackageSource | Where-Object {$_.Name -eq "PSGallery"}).IsTrusted -eq $False) {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }

    # Next, update PackageManagement and PowerShellGet where possible
    [version]$MinimumVer = "1.0.0.1"
    try {
        $PackageManagementLatestVersion = $(Find-Module PackageManagement).Version
    }
    catch {
        $PackageManagementLatestVersion = $PackageManagementLatestLocallyAvailableVersion
    }
    try {
        $PowerShellGetLatestVersion = $(Find-Module PowerShellGet).Version
    }
    catch {
        $PowerShellGetLatestVersion = $PowerShellGetLatestLocallyAvailableVersion
    }
    Write-Verbose "PackageManagement Latest Version is: $PackageManagementLatestVersion"
    Write-Verbose "PowerShellGetLatestVersion Latest Version is: $PowerShellGetLatestVersion"

    if ($PackageManagementLatestVersion -gt $PackageManagementLatestLocallyAvailableVersion -and $PackageManagementLatestVersion -gt $MinimumVer) {
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            Write-Host "`nUnable to update the PackageManagement Module beyond $($MinimumVer.ToString()) on PowerShell versions lower than 5."
        }
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            #Install-Module -Name "PackageManagement" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PowerShellGetLatestVersion -Force -WarningAction "SilentlyContinue"
            #Install-Module -Name "PackageManagement" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PackageManagementLatestVersion -Force
            Write-Host "Installing latest version of PackageManagement..."
            Install-Module -Name "PackageManagement" -Force -WarningAction SilentlyContinue
            $PackageManagementUpdated = $True
        }
    }
    if ($PowerShellGetLatestVersion -gt $PowerShellGetLatestLocallyAvailableVersion -and $PowerShellGetLatestVersion -gt $MinimumVer) {
        # Unless the force parameter is used, Install-Module will halt with a warning saying the 1.0.0.1 is already installed
        # and it will not update it.
        Write-Host "Installing latest version of PowerShellGet..."
        #Install-Module -Name "PowerShellGet" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PowerShellGetLatestVersion -Force -WarningAction "SilentlyContinue"
        #Install-Module -Name "PowerShellGet" -RequiredVersion $PowerShellGetLatestVersion -Force
        Install-Module -Name "PowerShellGet" -Force -WarningAction SilentlyContinue
        $PowerShellGetUpdated = $True
    }

    # Reset the LatestLocallyAvailable variables, and then load them into the current session
    $PackageManagementLatestLocallyAvailableVersionItem = $(Get-Module -ListAvailable -All | Where-Object {$_.Name -eq "PackageManagement"} | Sort-Object -Property Version)[-1]
    $PowerShellGetLatestLocallyAvailableVersionItem = $(Get-Module -ListAvailable -All | Where-Object {$_.Name -eq "PowerShellGet"} | Sort-Object -Property Version)[-1]
    $PackageManagementLatestLocallyAvailableVersion = $PackageManagementLatestLocallyAvailableVersionItem.Version
    $PowerShellGetLatestLocallyAvailableVersion = $PowerShellGetLatestLocallyAvailableVersionItem.Version
    Write-Verbose "Latest locally available PackageManagement version is $PackageManagementLatestLocallyAvailableVersion"
    Write-Verbose "Latest locally available PowerShellGet version is $PowerShellGetLatestLocallyAvailableVersion"

    $CurrentlyLoadedPackageManagementVersion = $(Get-Module | Where-Object {$_.Name -eq 'PackageManagement'}).Version
    $CurrentlyLoadedPowerShellGetVersion = $(Get-Module | Where-Object {$_.Name -eq 'PowerShellGet'}).Version
    Write-Verbose "Currently loaded PackageManagement version is $CurrentlyLoadedPackageManagementVersion"
    Write-Verbose "Currently loaded PowerShellGet version is $CurrentlyLoadedPowerShellGetVersion"

    if ($PackageManagementUpdated -eq $True -or $PowerShellGetUpdated -eq $True) {
        $NewPSSessionRequired = $True
        if ($LoadUpdatedModulesInSameSession) {
            if ($PowerShellGetUpdated -eq $True) {
                $PSGetWarningMsg = "Loading the latest installed version of PowerShellGet " +
                "(i.e. PowerShellGet $($PowerShellGetLatestLocallyAvailableVersion.ToString()) " +
                "in the current PowerShell session will break some PowerShellGet Cmdlets!"
                Write-Warning $PSGetWarningMsg
            }
            if ($PackageManagementUpdated -eq $True) {
                $PMWarningMsg = "Loading the latest installed version of PackageManagement " +
                "(i.e. PackageManagement $($PackageManagementLatestLocallyAvailableVersion.ToString()) " +
                "in the current PowerShell session will break some PackageManagement Cmdlets!"
                Write-Warning $PMWarningMsg
            }
        }
    }

    if ($LoadUpdatedModulesInSameSession) {
        if ($CurrentlyLoadedPackageManagementVersion -lt $PackageManagementLatestLocallyAvailableVersion) {
            # Need to remove PowerShellGet first since it depends on PackageManagement
            Write-Host "Removing Module PowerShellGet $CurrentlyLoadedPowerShellGetVersion ..."
            Remove-Module -Name "PowerShellGet"
            Write-Host "Removing Module PackageManagement $CurrentlyLoadedPackageManagementVersion ..."
            Remove-Module -Name "PackageManagement"
        
            if ($(Get-Host).Name -ne "Package Manager Host") {
                Write-Verbose "We are NOT in the Visual Studio Package Management Console. Continuing..."
                
                # Need to Import PackageManagement first since it's a dependency for PowerShellGet
                # Need to use -RequiredVersion parameter because older versions are still intalled side-by-side with new
                Write-Host "Importing PackageManagement Version $PackageManagementLatestLocallyAvailableVersion ..."
                $null = Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion -ErrorVariable ImportPackManProblems 2>&1 6>&1
                Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion ..."
                $null = Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion -ErrorVariable ImportPSGetProblems 2>&1 6>&1
            }
            if ($(Get-Host).Name -eq "Package Manager Host") {
                Write-Verbose "We ARE in the Visual Studio Package Management Console. Continuing..."
        
                # Need to Import PackageManagement first since it's a dependency for PowerShellGet
                # Need to use -RequiredVersion parameter because older versions are still intalled side-by-side with new
                Write-Host "Importing PackageManagement Version $PackageManagementLatestLocallyAvailableVersion`nNOTE: Module Members will have with Prefix 'PackMan' - Example: Get-PackManPackage"
                $null = Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion -Prefix PackMan -ErrorVariable ImportPackManProblems 2>&1 6>&1
                Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion`nNOTE: Module Members will have with Prefix 'PSGet' - Example: Find-PSGetModule"
                $null = Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion -Prefix PSGet -ErrorVariable ImportPSGetProblems 2>&1 6>&1
            }
        }
        
        # Reset CurrentlyLoaded Variables
        $CurrentlyLoadedPackageManagementVersion = $(Get-Module | Where-Object {$_.Name -eq 'PackageManagement'}).Version
        $CurrentlyLoadedPowerShellGetVersion = $(Get-Module | Where-Object {$_.Name -eq 'PowerShellGet'}).Version
        Write-Verbose "Currently loaded PackageManagement version is $CurrentlyLoadedPackageManagementVersion"
        Write-Verbose "Currently loaded PowerShellGet version is $CurrentlyLoadedPowerShellGetVersion"
        
        if ($CurrentlyLoadedPowerShellGetVersion -lt $PowerShellGetLatestLocallyAvailableVersion) {
            if (!$ImportPSGetProblems) {
                Write-Host "Removing Module PowerShellGet $CurrentlyLoadedPowerShellGetVersion ..."
            }
            Remove-Module -Name "PowerShellGet"
        
            if ($(Get-Host).Name -ne "Package Manager Host") {
                Write-Verbose "We are NOT in the Visual Studio Package Management Console. Continuing..."
                
                # Need to use -RequiredVersion parameter because older versions are still intalled side-by-side with new
                Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion ..."
                Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion
            }
            if ($(Get-Host).Name -eq "Package Manager Host") {
                Write-Host "We ARE in the Visual Studio Package Management Console. Continuing..."
        
                # Need to use -RequiredVersion parameter because older versions are still intalled side-by-side with new
                Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion`nNOTE: Module Members will have with Prefix 'PSGet' - Example: Find-PSGetModule"
                Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion -Prefix PSGet
            }
        }

        # Make sure all Repos Are Trusted
        if ($AddChocolateyPackageProvider -and $($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5)) {
            $BaselineRepoNames = @("Chocolatey","nuget.org","PSGallery")
        }
        else {
            $BaselineRepoNames = @("nuget.org","PSGallery")
        }
        if ($(Get-Module -Name PackageManagement).ExportedCommands.Count -gt 0) {
            $RepoObjectsForTrustCheck = Get-PackageSource | Where-Object {$_.Name -match "$($BaselineRepoNames -join "|")"}
        
            foreach ($RepoObject in $RepoObjectsForTrustCheck) {
                if ($RepoObject.IsTrusted -ne $true) {
                    Set-PackageSource -Name $RepoObject.Name -Trusted
                }
            }
        }

        # Reset CurrentlyLoaded Variables
        $CurrentlyLoadedPackageManagementVersion = $(Get-Module | Where-Object {$_.Name -eq 'PackageManagement'}).Version
        $CurrentlyLoadedPowerShellGetVersion = $(Get-Module | Where-Object {$_.Name -eq 'PowerShellGet'}).Version
        Write-Verbose "The FINAL loaded PackageManagement version is $CurrentlyLoadedPackageManagementVersion"
        Write-Verbose "The FINAL loaded PowerShellGet version is $CurrentlyLoadedPowerShellGetVersion"

        #$ErrorsArrayReversed = $($Error.Count-1)..$($Error.Count-4) | foreach {$Error[$_]}
        #$CheckForError = try {$ErrorsArrayReversed[0].ToString()} catch {$null}
        if ($($ImportPackManProblems | Out-String) -match "Assembly with same name is already loaded" -or 
            $CurrentlyLoadedPackageManagementVersion -lt $PackageManagementLatestVersion -or
            $(Get-Module -Name PackageManagement).ExportedCommands.Count -eq 0
        ) {
            Write-Warning "The PackageManagement Module has been updated and requires and brand new PowerShell Session. Please close this session, start a new one, and run the function again."
            $NewPSSessionRequired = $true
        }
    }

    $Result = [pscustomobject][ordered]@{
        PackageManagementUpdated                     = if ($PackageManagementUpdated) {$true} else {$false}
        PowerShellGetUpdated                         = if ($PowerShellGetUpdated) {$true} else {$false}
        NewPSSessionRequired                         = if ($NewPSSessionRequired) {$true} else {$false}
        PackageManagementCurrentlyLoaded             = Get-Module -Name PackageManagement
        PowerShellGetCurrentlyLoaded                 = Get-Module -Name PowerShellGet
        PackageManagementLatesLocallyAvailable       = $PackageManagementLatestLocallyAvailableVersionItem
        PowerShellGetLatestLocallyAvailable          = $PowerShellGetLatestLocallyAvailableVersionItem
    }

    $Result
}


[System.Collections.ArrayList]$script:FunctionsForSBUse = @(
    ${Function:AddLastWriteTimeToRegKey}.Ast.Extent.Text
    ${Function:AddWinRMTrustLocalHost}.Ast.Extent.Text
    ${Function:GetElevation}.Ast.Extent.Text
    ${Function:GetModuleDependencies}.Ast.Extent.Text
    ${Function:GetMSIFileInfo}.Ast.Extent.Text
    ${Function:GetNativePath}.Ast.Extent.Text
    ${Function:InvokeModuleDependencies}.Ast.Extent.Text
    ${Function:InvokePSCompatibility}.Ast.Extent.Text
    ${Function:MaualPSGalleryModuleInstall}.Ast.Extent.Text
    ${Function:PauseForWarning}.Ast.Extent.Text
    ${Function:UnzipFile}.Ast.Extent.Text
    ${Function:Get-AllPackageInfo}.Ast.Extent.Text
    ${Function:Get-InstalledProgramsFromRegistry}.Ast.Extent.Text
    ${Function:Install-ChocolateyCmdLine}.Ast.Extent.Text
    ${Function:Install-Program}.Ast.Extent.Text
    ${Function:New-Runspace}.Ast.Extent.Text
    ${Function:Uninstall-Program}.Ast.Extent.Text
    ${Function:Update-ChocolateyEnv}.Ast.Extent.Text
    ${Function:Update-PackageManagement}.Ast.Extent.Text
)

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU8RiajDt2nUu0zZtbpeOV/ZpJ
# WIqgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFJ6V7bNRzGXHtw+9
# Kcelr+n35YftMA0GCSqGSIb3DQEBAQUABIIBALSJ2Vh9+BxPEO4Kw4QhFSZ5ghhA
# SPJf64sAbmVcljIIFggLoF6DxNTQa0nfPzi1igswq6j57+OkLGCaKlH/QvLKjenb
# GZpeMjB+P8XsM+UUYn8oq/oDbf5/jX13lKnut2xzFRh5UZjujibQPQPEx5g6mR+o
# 5IBNUT6cSQu88QYcQbdXIoOPoe5PfOpwldvQquZT+mJSM+BoXgT1p7Bu5Bs/gNw8
# dDIelttM3TTQJmCltKzA+9sPj6VSoVeZQqjIph9WI7flt2UpGxk+lYm6k8qPXCiA
# 0qmZVb0RjJNp7ffLCZxtPzY63V6LNt4tPXMRyn/B3QQwfV7qauehnEBIPcg=
# SIG # End signature block
