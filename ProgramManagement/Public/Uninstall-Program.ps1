function Uninstall-Program {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
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
        $PackageManagerInstallObjects = Get-PackageManagerInstallObjects -ProgramName $ProgramName -ErrorAction SilentlyContinue
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

    if ($PSGetInstalledPackageObjects.Count -gt 0) {
        [System.Collections.ArrayList]$PSGetUninstallFailures = @()
            
        # Make sure that we uninstall Packages where 'ProviderName' is 'Programs' LAST
        foreach ($Package in $PSGetInstalledPackageObjects) {
            if ($Package.ProviderName -ne "Programs") {
                Write-Host "Uninstalling $($Package.Name)..."
                $UninstallResult = $Package | Uninstall-Package -Force -Confirm:$False -ErrorAction SilentlyContinue
            }
        }
        foreach ($Package in $PSGetInstalledPackageObjects) {
            if ($Package.ProviderName -eq "Programs") {
                Write-Host "Uninstalling $($Package.Name)..."
                $UninstallResult = $Package | Uninstall-Package -Force -Confirm:$False -ErrorAction SilentlyContinue
            }
        }
    }

    try {
        $PackageManagerInstallObjects = Get-PackageManagerInstallObjects -ProgramName $ProgramName -ErrorAction Stop
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
        $PackageManagerInstallObjects = Get-PackageManagerInstallObjects -ProgramName $ProgramName -ErrorAction Stop
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
        if ($RegistryProperties.Count -gt 0) {
            foreach ($Program in $RegistryProperties) {
                if (Test-Path $Program.PSPath) {
                    Remove-Item -Path $Program.PSPath -Recurse -Force
                }
            }
        }

        if ($ProgramParentDirPath) {
            if (Test-Path $ProgramParentDirPath) {
                Remove-Item $ProgramParentDirPath -Recurse -Force
            }
        }
    }

    try {
        $PackageManagerInstallObjects = Get-PackageManagerInstallObjects -ProgramName $ProgramName -ErrorAction Stop
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
        $PackageManagerInstallObjects = Get-PackageManagerInstallObjects -ProgramName $ProgramName -ErrorAction Stop
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
        Write-Warning "The program $ProgramName did NOT cleanly uninstall. Please review output of the Uninstall-Program function for details about lingering references."
    }

    [pscustomobject]@{
        ChocolateyInstalledProgramObjects   = [array]$ChocolateyInstalledProgramObjects
        PSGetInstalledPackageObjects        = [array]$PSGetInstalledPackageObjects
        RegistryProperties                  = [array]$RegistryProperties
    }

    #endregion >> Main Body
}