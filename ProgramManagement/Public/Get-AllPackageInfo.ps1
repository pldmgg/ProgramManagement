<#
    .SYNOPSIS
        This function gathers information about a particular installed program from 3-4 different sources:
            - The Get-Package Cmdlet fromPowerShellGet/PackageManagement Modules
            - Chocolatey CmdLine (if it is installed)
            - Windows Registry
            - The `Get-AppxPakcage` cmdlet (if the -IncludeAppx switch is used)

        All of this information is needed in order to determine the proper way to install/uninstall a program.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER ProgramName
        This parameter is OPTIONAL.

        This parameter takes a string that represents the name of the Program that you would like to gather information about.
        The name of the program does NOT have to be exact. For example, if you have 'python3' installed, you can simply use:
            Get-AllAvailablePackages python

    .PARAMETER IncludeAppx
        This parameter is OPTIONAL.

        This parameter is a switch. If used, information about available Appx (UWP) packages will also be returned.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -
        
        PS C:\Users\zeroadmin> Get-AllPackageInfo -IncludeAppX

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -
        
        PS C:\Users\zeroadmin> Get-AllPackageInfo openssh
#>
function Get-AllPackageInfo {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$False,
            Position=0
        )]
        [string]$ProgramName,

        [Parameter(Mandatory=$False)]
        [switch]$IncludeAppx
    )

    if ($ProgramName) {
        # Generate regex string to loosely match Program Name
        $PNRegexPrep = $([char[]]$ProgramName | foreach {"([\.]|[$_])+"}) -join ""
        $PNRegexPrep2 = $($PNRegexPrep -split "\+")[1..$($($PNRegexPrep -split "\+").Count)] -join "+"
        $PNRegex = "$([char[]]$ProgramName[0])+$PNRegexPrep2"
        # For example, $PNRegex string for $ProgramName 'nodejs' should be:
        #     ^n+([\.]|[o])+([\.]|[d])+([\.]|[e])+([\.]|[j])+([\.]|[s])+
    }

    #region >> Check PackageManagement/PowerShellGet for installed Programs

    # If PackageManagement/PowerShellGet is installed, determine if $ProgramName is installed
    if ([bool]$(Get-Command Get-Package -ErrorAction SilentlyContinue)) {
        $PSGetInstalledPrograms = Get-Package

        if ($ProgramName) {
            $PSGetInstalledPackageObjectsFinal = $PSGetInstalledPrograms | Where-Object {$_.Name -match $PNRegex}
        }
        else {
            $PSGetInstalledPackageObjectsFinal = $PSGetInstalledPrograms
        }
    }

    #endregion >> Check PackageManagement/PowerShellGet for installed Programs


    #region >> Check the Registry for installed Programs
    
    # Add some more information regarding these packages - specifically MSIFileItem, MSILastWriteTime, and RegLastWriteTime
    # This info will come in handy if there's a specific order related packages needed to be uninstalled in so that it's clean.
    # (In other words, with this info, we can sort by when specific packages were installed, and uninstall latest to earliest
    # so that there aren't any race conditions)
    try {
        [array]$CheckInstalledPrograms = @(Get-InstalledProgramsFromRegistry -ErrorAction Stop)
    }
    catch {
        Write-Error $_
        return
    }

    $WindowsInstallerMSIs = Get-ChildItem -Path "C:\Windows\Installer" -File
    $RelevantMSIFiles = foreach ($FileItem in $WindowsInstallerMSIs) {
        $MSIProductName = GetMSIFileInfo -MsiFileItem $FileItem -Property ProductName -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
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
            if ($RelevantMSIFile) {
                $Package | Add-Member -MemberType NoteProperty -Name "MSIFileItem" -Value $RelevantMSIFile.FileItem
                $Package | Add-Member -MemberType NoteProperty -Name "MSILastWriteTime" -Value $RelevantMSIFile.FileItem.LastWriteTime
            }

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

    if ($ProgramName) {
        $CheckInstalledProgramsFinal = $CheckInstalledPrograms | Where-Object {
            $_.InstallSource -match $PNRegex -or
            $_.DisplayName -match $PNRegex -or
            $_.InstallLocation -eq $PNRegex
        }
    }
    else {
        $CheckInstalledProgramsFinal = $CheckInstalledPrograms
    }

    #endregion >> Check the Registry for installed Programs


    #region >> Check chocolatey for installed Programs

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
                ProgramName     = $programParsed[0].Trim()
                Version         = $programParsed[1].Trim()
            }

            $null = $ChocolateyInstalledProgramObjects.Add($PSCustomObject)
        }

        if ($ProgramName) {
            $ChocolateyInstalledProgramObjectsFinal = $ChocolateyInstalledProgramObjects | Where-Object {$_.ProgramName -match $PNRegex}
        }
        else {
            $ChocolateyInstalledProgramObjectsFinal = $ChocolateyInstalledProgramObjects
        }
    }

    #endregion >> Check chocolatey for installed Programs


    #region >> Check for installed Appx Programs

    if ($IncludeAppx) {
        # Get all relevant AppX Package Info
        $AllAppxPackages = Get-AppxPackage -AllUsers
        if ($ProgramName) {
            $AppxPackagesFinal = $AllAppxPackages | Where-Object {$_.Name -match $PNRegex}
        }
        else {
            $AppxPackagesFinal = $AllAppxPackages
        }
        if ($AppxPackagesFinal.Count -gt 0) {
            $AppxPackagesFinal = $AppxPackagesFinal | foreach {
                $AppxManifest = $_.InstallLocation + "\AppxManifest.xml"
                if (Test-Path $AppxManifest) {
                    $AppxManifestContent = Get-Content $AppxManifest
                    $ApplicationIdCheck = $AppxManifestContent -match "Application Id="
                    if ($ApplicationIdCheck) {
                        $AppxId = $($ApplicationIdCheck -split '"')[1].Trim()
                        $LaunchString = 'explorer.exe shell:AppsFolder\'+ $_.PackageFamilyName + '!' + $AppxId
                        $_ | Add-Member -MemberType NoteProperty -Name "LaunchString" -Value $LaunchString
                    }
                    else {
                        $_ | Add-Member -MemberType NoteProperty -Name "LaunchString" -Value "unknown"
                    }
                    $_
                }
            }
        }
    }

    #endregion >> Check for installed Appx Programs

    [pscustomobject]@{
        ChocolateyInstalledProgramObjects           = $ChocolateyInstalledProgramObjectsFinal
        PSGetInstalledPackageObjects                = $PSGetInstalledPackageObjectsFinal
        AppxAvailablePackages                       = $AppxPackagesFinal
        RegistryProperties                          = $CheckInstalledProgramsFinal
    }
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUUuVy35iNG32n1CUoTOMxIQt4
# 18qgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFEe0E3oBjBegjSj
# O41FM053PonLMA0GCSqGSIb3DQEBAQUABIIBAAU6WSipWM6uvA2iodWz1QSD+uqx
# tjXGjoKGGutQrbY9FbqMFNAulXpeaimZlYe0gySon44UhDfOStynITb5YbU8Jk+h
# 95v7dGjRdwvuLwOxGIpxXMiBGrUKCj5wymgG5BpcudNoKtyGpP84JUkSSgHRIEmJ
# u/gUnfzJPQXxcRidnPhaxiBp/lpT4VZ2spAMwFYWPbowHkJm7FPdsLxyYkM26uzZ
# D3upkx3gFiIvAaN6s0C481y+BNj7+ZdzAwPzR3GH0a0E3prYygRtFQZKhwWk318P
# uRCGQdXZMCDgR3P3C7NQ4E1HVVv6fvrSMZ11HSmvYZ/4rfGJU7daWYH1uQc=
# SIG # End signature block
