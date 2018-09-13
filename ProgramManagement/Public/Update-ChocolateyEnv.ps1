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

    # Make sure we have ChocolateyInstall and ChocolateyPath environment variables are set
    $env:ChocolateyInstall = "C:\ProgramData\chocolatey"
    $env:ChocolateyPath = $env:ChocolateyInstall
    $null = [Environment]::SetEnvironmentVariable("ChocolateyInstall", $env:ChocolateyInstall, "User")
    $null = [Environment]::SetEnvironmentVariable("ChocolateyInstall", $env:ChocolateyInstall, "Machine")
    $null = [Environment]::SetEnvironmentVariable("ChocolateyPath", $env:ChocolateyPath, "User")
    $null = [Environment]::SetEnvironmentVariable("ChocolateyPath", $env:ChocolateyPath, "Machine")

    # Ensure that we have an "extensions" folder under $env:ProgramData\chocolatey
    if (Test-Path $env:ChocolateyPath) {
        $ChocoExtensionsFolder = "$env:ProgramData\chocolatey\extensions"
        if (!$(Test-Path $ChocoExtensionsFolder)) {
            $null = New-Item -ItemType Directory -Path $ChocoExtensionsFolder
        }
        $ExtensionModules = Get-ChildItem "$env:ProgramData\chocolatey\lib" -Directory | Where-Object {$_.Name -match "\.extension\."}
        foreach ($ModuleDirItem in $ExtensionModules) {
            if (Test-Path "$ChocoExtensionsFolder\$($ModuleDirItem.Name)") {
                $null = Remove-Item -Path "$ChocoExtensionsFolder\$($ModuleDirItem.Name)" -Recurse -Force
            }
            $null = Copy-Item -Path $ModuleDirItem.FullName -Destination $ChocoExtensionsFolder -Recurse -Force
        }
    }

    $UpdatedEnvPath

    ##### END Main Body #####

}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUFfZylP1+5hjOORdDj4E2/jG5
# dkigggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHchyuQy9yA9ywix
# WSbSABb/PgeHMA0GCSqGSIb3DQEBAQUABIIBAIto5sseLv6lsZ6icAzVt43J+4Aq
# wt7jNsv+rOYdJVin1ScrKscHYz5OA3bp4JPgaZlcsFUmIWgi/gUjPs7F9AXTy3I4
# X81MT1jb/or7GR967qahzIlPG/lLye2ze7Z5Qu08aGdwyVnSTXCYqiwOOqMUUlMT
# 3+NNwBV/iV2Xz4e5LUaul1xfUhH0zw2KeGI/almN/3Jn6zt29wAIa2+Ppx53IVhJ
# UrnuHr3Xz6Nf3UMNaMQYqkYAY8U4r1VNsT1HUsd2TqfpT/NaZe7tEZR86LWHXme7
# 1jO1FNJMeX3+lAI4OR+feLimH6Mo2NvuQwRN8tblnz+LatkGow8Cr1HsyEE=
# SIG # End signature block
