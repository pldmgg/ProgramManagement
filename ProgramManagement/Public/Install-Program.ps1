<#
    .SYNOPSIS
        Install a Program using PowerShellGet/PackageManagement Modules OR the Chocolatey CmdLine.

    .DESCRIPTION
        This function was written to make program installation on Windows as easy and generic
        as possible by leveraging existing solutions such as PackageManagement/PowerShellGet
        and the Chocolatey CmdLine.

        For any scenario in which the Chocolatey CmdLine is used, if Chocolatey is not aleady installed
        on the machine, it will be installed.

        Default behavior for this function (using only the -ProgramName parameter) is to:
        - Try installation via Chocolatey as long as the program isn't already installed via PSGet.
        - If the program is already installed via PSGet and the update via PSGet fails, then
        the program will be uninstalled via PSGet and reinstalled via Chocolatey

        If you explicitly specify -UsePowerShellGet, then:
        - PSGet will be used for the install
        - If PSGet fails, then the function will give up

        If you explicitly specify -UseChocolateyCmdLine, then:
        - The Chocolatey CmdLine will be used for the install
        - If Chocolatey fails, then the function will give up

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

    .PARAMETER GetPenultimateVersion
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the version preceding the latest version of the program will
        be installed - unless Chocolatey is being used, in which case this switch will be ignored.

    .PARAMETER UsePowerShellGet
        This parameter is OPTIONAL.

        This parameter is a switch. If used the function will attempt program installation using ONLY
        PackageManagement/PowerShellGet Modules. If installation using those modules fails, the function
        halts and returns the relevant error message(s).

        Installation via the Chocolatey CmdLine will NOT be attempted.

    .PARAMETER UseChocolateyCmdLine
        This parameter is OPTIONAL.

        This parameter is a switch. If used the function will attempt installation using ONLY
        the Chocolatey CmdLine. (The Chocolatey CmdLine will be installed if it is not already).
        If installation via the Chocolatey CmdLine fails for whatever reason,
        the function halts and returns the relevant error message(s).

    .PARAMETER ExpectedInstallLocation
        This parameter is OPTIONAL.

        This parameter takes a string that represents the full path to a directory that will contain
        main executable associated with the program to be installed. This directory should be the
        immediate parent directory of the .exe.

        If you are **absolutely certain** you know where the Main Executable for the program to be installed
        will be, then use this parameter. STDOUT (i.e. Write-Host) will provide instructions on adding this
        location to the system PATH and PowerShell's $env:Path.

    .PARAMETER ScanCommonInstallDirs
        This parameter is OPTIONAL.

        This parameter is a switch. If used, common install locations will be searched for the Program's main .exe.
        If found, STDOUT (i.e. Write-Host) will provide instructions on adding this location to the system PATH and
        PowerShell's $env:Path.

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
    [CmdletBinding()]
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
        [switch]$GetPenultimateVersion,

        [Parameter(Mandatory=$False)]
        [switch]$UsePowerShellGet,

        [Parameter(Mandatory=$False)]
        [switch]$UseChocolateyCmdLine,

        [Parameter(Mandatory=$False)]
        [string]$ExpectedInstallLocation,

        [Parameter(Mandatory=$False)]
        [switch]$ScanCommonInstallDirs,

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

    ##### END Native Helper Functions #####

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

    if (!$(GetElevation)) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function must be ran from an elevated PowerShell Session (i.e. 'Run as Administrator')! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Need to make sure we are on Windows
    if (-not $($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT")) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function must only be used on Windows! Halting"
    }

    # Make sure use is not using both -UsePowerShellGet and -UseChocolateyCmdLine
    if ($UsePowerShellGet -and $UseChocolateyCmdLine) {
        Write-Error "Please only use either the -UsePowerShellGet switch or the -UseChocolateyCmdLine switch, not both. Halting!"
        return
    }

    if ($GetPenultimateVersion -and !$UsePowerShellGet) {
        Write-Error "The get -PenultimateVersion switch must be used with the -UsePowerShellGet switch. Halting!"
        return
    }

    if ($CommandName -match "\.exe") {
        $CommandName = $CommandName -replace "\.exe",""
    }
    $FinalCommandName = if ($CommandName) {$CommandName} else {$ProgramName}

    # Save the original System PATH and $env:Path before we do anything, just in case
    $OriginalSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
    $OriginalEnvPath = $env:Path
    Synchronize-SystemPathEnvPath

    try {
        if ($PSVersionTable.PSEdition -ne "Core") {
            $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
            $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

            # We're not going to attempt to use Chocolatey Resources with PSGet - it becomes a mess, so commenting out the below 2 lines
            #$null = Install-PackageProvider -Name Chocolatey -Force -Confirm:$False
            #$null = Set-PackageSource -Name chocolatey -Trusted -Force
        }
        else {
            $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # If a package provider is *not* specified or if -UseChocolateyCmdLine is explicitly specified, then we are just
    # going to use choco.exe because it is the most reliable method of getting things installed properly.
    if ($UseChocolateyCmdLine -or $(!$UsePowerShellGet -and !$UseChocolateyCmdLine)) {
        try {
            # NOTE: The Install-ChocolateyCmdLine function performs checks to see if Chocolatey is already installed, so don't worry about that
            $null = Install-ChocolateyCmdLine -ErrorAction Stop
        }
        catch {
            Write-Error "The Install-ChocolateyCmdLine function failed with the following error: $($_.Exception.Message)"
            return
        }

        try {
            if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
                # The above install.ps1 probably already updated PATH, but it may not be updated in this particular PowerShell session
                # So, start a new PowerShell session and see if choco is available
                $ChocoCheck = Start-Job -Name ChocoPathTest -ScriptBlock {Get-Command choco} | Wait-Job | Receive-Job
        
                # $ChocoCheck.Source should return C:\ProgramData\chocolatey\bin\choco.exe
                if (!$ChocoCheck) {
                    try {
                        Write-Host "Refreshing `$env:Path..."
                        $null = Update-ChocolateyEnv -ErrorAction Stop
                    }
                    catch {
                        Write-Warning $_.Exception.Message
                        Write-Warning "Please start another PowerShell session in order to use the Chocolatey cmdline."
                    }
                }
        
                # If we STILL can't find choco.exe, then give up...
                if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
                    Write-Error "Please start another PowerShell session in order to use the Chocolatey cmdline."
                    return
                }
            }
        }
        catch {
            Write-Error $_
            return
        }
    }
    
    try {
        $PackageManagerInstallObjects = Get-AllPackageInfo -ProgramName $ProgramName -ErrorAction SilentlyContinue
        [array]$ChocolateyInstalledProgramObjects = $PackageManagerInstallObjects.ChocolateyInstalledProgramObjects
        [array]$PSGetInstalledPackageObjects = $PackageManagerInstallObjects.PSGetInstalledPackageObjects
        [array]$RegistryProperties = $PackageManagerInstallObjects.RegistryProperties
        [array]$AppxInstalledPackageObjects = $PackageManagerInstallObjects.AppxAvailablePackages
    }
    catch {
        Write-Error $_
        return
    }

    # If PSGet says that a Program with a similar name is installed, get $PackageManagementCurrentVersion, $PackageManagementLatestVersion, and $PackageManagementPreviousVersion
    if ($PSGetInstalledPackageObjects.Count -eq 1) {
        $PackageManagementCurrentVersion = $PSGetInstalledPackageObjects
        $PackageManagementLatestVersion = $(Find-Package -Name $PSGetInstalledPackageObjects.Name -AllVersions | Sort-Object -Property Version -EA SilentlyContinue)[-1]
        $PackageManagementPreviousVersion = $(Find-Package -Name $PSGetInstalledPackageObjects.Name -AllVersions | Sort-Object -Property Version -EA SilentlyContinue)[-2]
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

            $UpdatedProgramName = $PSGetInstalledPackageObjects[$ProgramChoiceNumber].Name
            $PackageManagementCurrentVersion = Get-Package -Name $UpdatedProgramName
            $PackageManagementLatestVersion = $(Find-Package -Name $UpdatedProgramName -AllVersions | Sort-Object -Property Version -EA SilentlyContinue)[-1]
            $PackageManagementPreviousVersion = $(Find-Package -Name $UpdatedProgramName -AllVersions | Sort-Object -Property Version -EA SilentlyContinue)[-2]
        }
        else {
            $PackageManagementCurrentVersion = Get-Package -Name $ProgramName
            $PackageManagementLatestVersion = $(Find-Package -Name $ProgramName -AllVersions | Sort-Object -Property Version)[-1]
            $PackageManagementPreviousVersion = $(Find-Package -Name $ProgramName -AllVersions | Sort-Object -Property Version -EA SilentlyContinue)[-2]
        }
    }

    # If Chocolatey says that a Program with a similar name is installed, get $ChocoCurrentVersion and $ChocoLatestVersion
    # Currently it's not possible to figure out $ChocoPreviousVersion reliably
    if ($ChocolateyInstalledProgramObjects.Count -gt 0) {
        if ($ChocolateyInstalledProgramObjects.Count -eq 1) {
            $ChocoCurrentVersion = $ChocolateyInstalledProgramObjects.Version
        }
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

                $ChocoCurrentVersion = $ChocolateyInstalledProgramObjects[$ProgramChoiceNumber].Version
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
        #$ChocoPreviousVersion = $($AllChocoVersions[2] -split "[\s]")[1].Trim()
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    $CheckLatestVersion = $(
        $PackageManagementCurrentVersion.Version -ne $PackageManagementLatestVersion.Version -or
        $ChocolateyOutdatedProgramsPSObjects.ProgramName -contains $ProgramName
    )
    $CheckPreviousVersion = $(
        $PackageManagementCurrentVersion.Version -ne $PackageManagementPreviousVersion.Version
    )
    if ($GetPenultimateVersion) {
        $VersionCheck = $CheckPreviousVersion
        $PackageManagementRequiredVersion = $PackageManagementPreviousVersion.Version
        $ChocoRequiredVersion = $ChocoLatestVersion
    }
    else {
        $VersionCheck = $CheckLatestVersion
        $PackageManagementRequiredVersion = $PackageManagementLatestVersion.Version
        $ChocoRequiredVersion = $ChocoLatestVersion
    }

    # Install $ProgramName if it's not already or if it's not the right/specified version...
    if ($($PSGetInstalledPackageObjects.Name -notcontains $ProgramName -and
    $ChocolateyInstalledProgramsPSObjects.ProgramName -notcontains $ProgramName) -or
    $VersionCheck -or $Force
    ) {
        $UsePSGetCheck = $($UsePowerShellGet -or $($PSGetInstalledPackageObjects.Name -contains $ProgramName -and $ChocolateyInstalledProgramsPSObjects.ProgramName -notcontains $ProgramName)) -and !$UseChocolateyCmdLine
        if ($UsePSGetCheck) {
            $PreInstallPackagesList = $(Get-Package).Name

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

        $UseChocoCheck = $(!$PMInstall -or $UseChocolateyCmdLine -or $ChocolateyInstalledProgramsPSObjects.ProgramName -contains $ProgramName) -and !$UsePowerShellGet
        if ($UseChocoCheck) {
            # Since choco installs can hang indefinitely, we're starting another powershell process and giving it a time limit
            try {
                if ($PreRelease) {
                    $CupArgs = "--pre -y"
                }
                elseif ([bool]$ChocoRequiredVersion) {
                    $CupArgs = "--version=$ChocoRequiredVersion -y"
                }
                else {
                    $CupArgs = "-y"
                }
                <#
                $ChocoPrepScript = @(
                    "`$ChocolateyResourceDirectories = Get-ChildItem -Path '$env:ProgramData\chocolatey\lib' -Directory | Where-Object {`$_.BaseName -match 'chocolatey'}"
                    '$ModulesToImport = foreach ($ChocoResourceDir in $ChocolateyResourceDirectories) {'
                    "    `$(Get-ChildItem -Path `$ChocoResourceDir.FullName -Recurse -Filter '*.psm1').FullName"
                    '}'
                    'foreach ($ChocoModulePath in $($ModulesToImport | Where-Object {$_})) {'
                    '    Import-Module $ChocoModulePath -Global'
                    '}'
                    "cup $ProgramName $CupArgs"
                )
                #>
                $ChocoPrepScript = $ChocoPrepScript -join "`n"
                $FinalArguments = "-NoProfile -NoLogo -Command `"cup $ProgramName $CupArgs`""
                
                $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
                $ProcessInfo.FileName = $(Get-Command powershell).Source
                $ProcessInfo.RedirectStandardError = $true
                $ProcessInfo.RedirectStandardOutput = $true
                $ProcessInfo.UseShellExecute = $false
                $ProcessInfo.Arguments = $FinalArguments
                $Process = New-Object System.Diagnostics.Process
                $Process.StartInfo = $ProcessInfo
                $Process.Start() | Out-Null
                # Below $FinishedInAlottedTime returns boolean true/false
                # Give it 120 seconds to finish installing, otherwise, kill choco.exe
                $FinishedInAlottedTime = $Process.WaitForExit(120000)
                if (!$FinishedInAlottedTime) {
                    $Process.Kill()
                }
                $stdout = $Process.StandardOutput.ReadToEnd()
                $stderr = $Process.StandardError.ReadToEnd()
                $AllOutputA = $stdout + $stderr

                #$AllOutput | Export-CliXml "$HOME\CupInstallOutput.ps1"
                
                if (![bool]$($(clist --local-only $ProgramName) -match $ProgramName)) {
                    throw "'cup $ProgramName $CupArgs' failed with the following Output:`n$AllOutputA`n$AllOutputB"
                }

                # Since Installation via the Chocolatey CmdLine was succesful, let's update $env:Path with the
                # latest from System PATH before we go nuts trying to find the main executable manually
                Synchronize-SystemPathEnvPath
                $env:Path = Update-ChocolateyEnv -ErrorAction SilentlyContinue
            }
            catch {
                Write-Warning $_.Exception.Message

                Write-Host "Trying 'cup $ProgramName $CupArgs' within this powershell process ($PID)..." -ForegroundColor Yellow

                if (Get-Command cup -ErrorAction SilentlyContinue) {
                    cup $ProgramName -y
                }
                else {
                    Write-Warning "Please start a new PowerShell session and update Chocolatey via:`n    cup chocolatey -y"
                    Write-Error "'cup $ProgramName -y' failed! Halting!"
                    return
                }

                if (![bool]$($(clist --local-only $ProgramName) -match $ProgramName)) {
                    Write-Warning "Please start a new PowerShell session and update Chocolatey via:`n    cup chocolatey -y"
                    Write-Error "'cup $ProgramName -y' failed! Halting!"
                    return
                }
            }
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
    }

    ## BEGIN Try to Find Main Executable Post Install ##

    # Remove any conflicting Aliases
    if ($(Get-Command $FinalCommandName -ErrorAction SilentlyContinue).CommandType -eq "Alias") {
        while (Test-Path Alias:\$FinalCommandName -ErrorAction SilentlyContinue) {
            Remove-Item Alias:\$FinalCommandName
        }
    }
    
    # If we can't find the main executable...
    if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
        # Try to find where the new .exe is by either using the user-provided $ExpectedInstallLocation or by comparing $OriginalSystemPath and $OriginalEnvPath to
        # the current PATH and $env:Path. THis is what the Get-ExePath function does

        $GetExePathSplatParams = @{
            GetProgramName          = $ProgramName
            OriginalSystemPath      = $OriginalSystemPath
            OriginalEnvPath         = $OriginalEnvPath
            FinalCommandName        = $FinalCommandName
        }
        if ($ExpectedInstallLocation) {
            if (Test-Path $ExpectedInstallLocation -ErrorAction SilentlyContinue) {
                $GetExePathSplatParams.Add('ExpectedInstallLocation',$ExpectedInstallLocation)
            }
        }

        [System.Collections.ArrayList][Array]$ExePath = Get-ExePath @GetExePathSplatParams

        if ($ExePath.Count -ge 1) {
            # Look for an exact match 
            if ([bool]$($ExePath -match "\\$FinalCommandName\.exe$")) {
                $FinalExeLocation = $ExePath -match "\\$FinalCommandName\.exe$"
            }
            else {
                $FinalExeLocation = $ExePath
            }
        }
    }

    # If we weren't able to find the main executable (or any potential main executables) for
    # $ProgramName, offer the option to scan the whole C:\ drive (with some obvious exceptions)
    if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue) -and @($FinalExeLocation).Count -eq 0 -and $PSBoundParameters['ScanCommonInstallDirs']) {
        # Let's seach some common installation locations for directories that match $ProgramName

        $DirectoriesToSearch = @('C:\', $env:ProgramData, $env:ProgramFiles, ${env:ProgramFiles(x86)}, "$env:LocalAppData\Programs")

        [System.Collections.ArrayList]$ExePath = @()
        # Try to find a directory that matches the $ProgramName
        [System.Collections.ArrayList]$FoundMatchingDirs = @()
        foreach ($DirName in $DirectoriesToSearch) {
            $DirectoriesIndex = Get-ChildItem -Path $DirName -Directory
            foreach ($SubDirItem in $DirectoriesIndex) {
                if ($SubDirItem.Name -match $ProgramName) {
                    $null = $FoundMatchingDirs.Add($SubDirItem)
                }
            }
        }
        foreach ($MatchingDirItem in $FoundMatchingDirs) {
            $FilesIndex = Get-ChildItem -Path $MatchingDirItem.FullName -Recurse -File
            foreach ($FilePath in $FilesIndex.FullName) {
                if ($FilePath -match "(.*?)$FinalCommandName([^\\]+)") {
                    $null = $ExePath.Add($FilePath)
                }
            }
        }

        $FinalExeLocation = $ExePath
    }

    if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue) {
        Write-Host "The command '$FinalCommandName' is not currently available in PATH or env:Path, however, the following locations might contain the desired command:"
        @($FinalExeLocation) | foreach {Write-Host $_}

        Write-Host "Update System PATH and PowerShell $env:Path via:"
        Write-Host "Update-SystemPathNow -PathToAdd <PathToDirectoryContainingCommand>"
    }

    if ($UseChocoCheck) {
        $InstallManager = "choco.exe"
        $InstallCheck = $(clist --local-only $ProgramName)[1]
    }
    if ($PMInstall -or [bool]$(Get-Package $ProgramName -ErrorAction SilentlyContinue)) {
        $InstallManager = "PowerShellGet"
        $InstallCheck = Get-Package $ProgramName -ErrorAction SilentlyContinue
    }

    if ($AlreadyInstalled) {
        $InstallAction = "AlreadyInstalled"
    }
    elseif (!$AlreadyInstalled -and $VersionCheck) {
        $InstallAction = "Updated"
    }
    else {
        $InstallAction = "FreshInstall"
    }

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

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQULPWT4jmdHukttDF0B5yBpx06
# RfKgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFCazlqz35msZdp4t
# ErUOykG6hV8zMA0GCSqGSIb3DQEBAQUABIIBAFDs1r5VbXsEdC1FTpzwGS+XERVr
# Ze6JiWAIGZONlkTPhEGDPUKGUwDQflOpuIVXDRX9iWyDFTfdV2yf56sRJ+SAEJBi
# X1pNb4DitSD8z6/9SxHY8sqYaUlu308pil++LrdoDVVpEm4R0vQrS4JGvsI8IAT8
# 5gImjsEQ9fR/fmrtP9rxmYkfOXBXr5j3sOghtwTOdGMh4LGf3rMZqRncSCDWvZkC
# ot3TxyzxF8GtHK22/cvgV2TH0XFyZgCcCtbKtt8mv0SIOl3VnzTqkvYBgL0OhkwU
# j7T5zz7QnlLVbhzk5A31+L/BUbsGKzHppr01EcYt7DVC0XWLIg4vt83RGDc=
# SIG # End signature block
