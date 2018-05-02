function Install-ChocolateyCmdLine {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [switch]$NoUpdatePackageManagement
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

    if (!$NoUpdatePackageManagement) {
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

    if (![bool]$(Get-Command Refresh-ChocolateyEnv -ErrorAction SilentlyContinue)) {
        $RefreshCEFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Refresh-ChocolateyEnv.ps1"
        try {
            Invoke-Expression $([System.Net.WebClient]::new().DownloadString($RefreshCEFunctionUrl))
        }
        catch {
            Write-Error $_
            Write-Error "Unable to load the Refresh-ChocolateyEnv function! Halting!"
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
            $null = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
            
            if ($RCEErr.Count -gt 0 -and
            $global:FunctionResult -eq "1" -and
            ![bool]$($RCEErr -match "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed!")) {
                throw "The Refresh-ChocolateyEnv function failed! Halting!"
            }
        }
        catch {
            Write-Error $_
            Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
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
        
        # If we STILL can't find choco.exe, then Refresh-ChocolateyEnv a third time...
        #if (![bool]$($env:Path -split ";" -match "chocolatey\\bin")) {
        if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
            # ...and then find it again and add it to $env:Path via Refresh-ChocolateyEnv function
            if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
                try {
                    Write-Host "Refreshing `$env:Path..."
                    $global:FunctionResult = "0"
                    $null = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
                    
                    if ($RCEErr.Count -gt 0 -and
                    $global:FunctionResult -eq "1" -and
                    ![bool]$($RCEErr -match "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed!")) {
                        throw "The Refresh-ChocolateyEnv function failed! Halting!"
                    }
                }
                catch {
                    Write-Error $_
                    Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
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
                $null = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
                if ($RCEErr.Count -gt 0 -and $global:FunctionResult -eq "1") {
                    throw "The Refresh-ChocolateyEnv function failed! Halting!"
                }
            }
            catch {
                Write-Error $_
                Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
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
                    Write-Host "The $ModName Module has been loaded from $($(Get-Module -Name $ModName).Path)" -ForegroundColor Green
                }
            }
        }
    }
    else {
        Write-Warning "The Chocolatey CmdLine is already installed!"
    }

    ##### END Main Body #####
}