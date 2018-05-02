function Refresh-ChocolateyEnv {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$ChocolateyDirectory
    )

    ##### BEGIN Main Body #####

    if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
        if ($ChocolateyDirectory) {
            $ChocolateyPath = $ChocolateyDirectory
        }
        else {
            if (Test-Path "C:\Chocolatey") {
                $ChocolateyPath = "C:\Chocolatey"
            }
            elseif (Test-Path "C:\ProgramData\chocolatey") {
                $ChocolateyPath = "C:\ProgramData\chocolatey"
            }
            else {
                Write-Error "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }
    else {
        $ChocolateyPath = "$($($(Get-Command choco).Source -split "chocolatey")[0])chocolatey"
    }
    [System.Collections.ArrayList]$ChocolateyPathsPrep = @()
    [System.Collections.ArrayList]$ChocolateyPathsToAddToEnvPath = @()
    if (Test-Path $ChocolateyPath) {
        $($(Get-ChildItem $ChocolateyPath -Directory | foreach {
            Get-ChildItem $_.FullName -Recurse -File
        } | foreach {
            if ($_.Extension -eq ".exe" -or $_.Extension -eq ".bat") {
                $_.Directory.FullName
            }
        }) | Sort-Object | Get-Unique) | foreach {
            $null = $ChocolateyPathsPrep.Add($_.Trim("\\"))
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
    }
    else {
        Write-Verbose "Unable to find Chocolatey Path $ChocolateyPath."
    }

    # Remove any repeats in $env:Path
    $UpdatedEnvPath = $($($($env:Path -split ";") | foreach {
        if (-not [System.String]::IsNullOrWhiteSpace($_)) {
            $_.Trim("\\")
        }
    }) | Select-Object -Unique) -join ";"

    # Next, find chocolatey-core.psm1, chocolateysetup.psm1, chocolateyInstaller.psm1, and chocolateyProfile.psm1
    # and import them
    $ChocoCoreModule = $(Get-ChildItem -Path $ChocolateyPath -Recurse -File -Filter "*chocolatey-core.psm1").FullName
    $ChocoSetupModule = $(Get-ChildItem -Path $ChocolateyPath -Recurse -File -Filter "*chocolateysetup.psm1").FullName
    $ChocoInstallerModule = $(Get-ChildItem -Path $ChocolateyPath -Recurse -File -Filter "*chocolateyInstaller.psm1").FullName
    $ChocoProfileModule = $(Get-ChildItem -Path $ChocolateyPath -Recurse -File -Filter "*chocolateyProfile.psm1").FullName

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

    $UpdatedEnvPath

    ##### END Main Body #####

}