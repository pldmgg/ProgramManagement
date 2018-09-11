[CmdletBinding()]
param(
    [Parameter(Mandatory=$False)]
    [System.Collections.Hashtable]$TestResources
)
# NOTE: `Set-BuildEnvironment -Force -Path $PSScriptRoot` from build.ps1 makes the following $env: available:
<#
    $env:BHBuildSystem = "Unknown"
    $env:BHProjectPath = "U:\powershell\ProjectRepos\Sudo"
    $env:BHBranchName = "master"
    $env:BHCommitMessage = "!deploy"
    $env:BHBuildNumber = 0
    $env:BHProjectName = "Sudo"
    $env:BHPSModuleManifest = "U:\powershell\ProjectRepos\Sudo\Sudo\Sudo.psd1"
    $env:BHModulePath = "U:\powershell\ProjectRepos\Sudo\Sudo"
    $env:BHBuildOutput = "U:\powershell\ProjectRepos\Sudo\BuildOutput"
#>

# NOTE: If -TestResources was used, the folloqing resources should be available
<#
    $TestResources = @{
        UserName        = $UserName
        SimpleUserName  = $SimpleUserName
        Password        = $Password
        Creds           = $Creds
    }
#>

# Load CustomAssertions.psm1
Import-Module "$env:BHProjectPath\Tests\CustomAssertions.psm1" -Force
Add-AssertionOperator -Name 'BeTypeOrType' -Test $Function:BeTypeOrType

# Make sure the Module is loaded
if ([bool]$(Get-Module -Name $env:BHProjectName -ErrorAction SilentlyContinue)) {
    Remove-Module $env:BHProjectName -Force
}
if (![bool]$(Get-Module -Name $env:BHProjectName -ErrorAction SilentlyContinue)) {
    Import-Module $env:BHPSModuleManifest -Force
}

Remove-Module PowerShellGet -Force -ErrorAction SilentlyContinue
Remove-Module PackageManagement -Force -ErrorAction SilentlyContinue
try {
    Import-Module PackageManagement -ErrorAction Stop
}
catch {
    Write-Error $_
    Write-Error "Problem importing the PowerShell Module PackageManagement! Halting!"
    $global:FunctionResult = "1"
    return
}
try {
    Import-Module PowerShellGet -ErrorAction Stop
}
catch {
    Write-Error $_
    Write-Error "Problem importing the PowerShell Module PowerShellGet! Halting!"
    $global:FunctionResult = "1"
    return
}

$InstallManagerValidOutputs = @("choco.exe","PowerShellGet")
$InstallActionValidOutputs = @("Updated","FreshInstall")
$InstallCheckValidOutputs = @($([Microsoft.PackageManagement.Packaging.SoftwareIdentity]::new()),"openssh")
$FinalExeLocation = "C:\Program Files\OpenSSH-Win64\ssh.exe"
$OriginalSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
$CurrentSystemPath = $OriginalSystemPath
$OriginalEnvPath = $env:Path
$CurrentSystemPath = $OriginalEnvPath

$FakeOutputHT = [ordered]@{
    InstallManager      = $InstallManagerValidOutputs[1]
    InstallAction       = $InstallActionValidOutputs[1]
    InstallCheck        = $InstallCheckValidOutputs[0]
    MainExecutable      = $FinalExeLocation
    OriginalSystemPath  = $OriginalSystemPath
    CurrentSystemPath   = $CurrentSystemPath
    OriginalEnvPath     = $OriginalEnvPath
    CurrentEnvPath      = $env:Path
}

function CommonTestSeries {
    Param (
        [Parameter(
            Mandatory=$True,
            ValueFromPipeline=$True
        )]
        $InputObject
    )

    it "Should return some kind of output" {
        $InputObject | Assert-NotNull
    }

    it "Should return a PSCustomObject" {
        $InputObject | Assert-Type System.Management.Automation.PSCustomObject
    }

    it "Should return a PSCustomObject with Specific Properties" {
        [System.Collections.ArrayList][array]$ActualPropertiesArray = $($InputObject | Get-Member -MemberType NoteProperty).Name
        [System.Collections.ArrayList][array]$ExpectedPropertiesArray = $global:MockResources['FakeOutputHT'].Keys
        if ($ActualPropertiesArray -contains "PossibleMainExecutables") {
            $ActualPropertiesArray.Remove("PossibleMainExecutables")
            $ExpectedPropertiesArray.Remove("MainExecutable")
        }
        foreach ($Item in $ExpectedPropertiesArray) {
            $ActualPropertiesArray -contains $Item | Assert-True
        }
    }

    it "Should return a PSCustomObject Property InstallManager of Type System.String" {
        $InputObject.InstallManager | Assert-Type System.String
    }

    it "Should return a PSCustomObject Property InstallAction of Type System.String" {
        $InputObject.InstallAction | Assert-Type System.String
    }

    it "Should return a PSCustomObject Property InstallCheck of Type Microsoft.PackageManagement.Packaging.SoftwareIdentity OR System.String" {
        $InputObject.InstallCheck | Should -BeTypeOrType @("Microsoft.PackageManagement.Packaging.SoftwareIdentity","System.String")
    }

    it "Should return a PSCustomObject Property MainExecutable of Type System.String or Null" {
        $InputObject.MainExecutable | Should -BeTypeOrType @("System.String",$null)
    }

    it "Should return a PSCustomObject Property OriginalSystemPath of Type System.String" {
        $InputObject.OriginalSystemPath | Assert-Type System.String
    }

    it "Should return a PSCustomObject Property CurrentSystemPath of Type System.String" {
        $InputObject.CurrentSystemPath | Assert-Type System.String
    }

    it "Should return a PSCustomObject Property OriginalEnvPath of Type System.String" {
        $InputObject.OriginalEnvPath | Assert-Type System.String
    }

    it "Should return a PSCustomObject Property CurrentEnvPath of Type System.String" {
        $InputObject.CurrentEnvPath | Assert-Type System.String
    }
}

function Cleanup {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$ProgramName
    )

    Uninstall-Program -ProgramName $ProgramName
}

function StartTesting {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        $SplatParamsSeriesItem,

        [Parameter(Mandatory=$True)]
        $ContextString
    )

    $global:MockResources['Functions'] | foreach { Invoke-Expression $_ }
    $IPSplatParams = $SplatParamsSeriesItem.TestSeriesSplatParams
    $PrgName = $SplatParamsSeriesItem.TestSeriesSplatParams['ProgramName']

    try {
        $null = Install-Program @IPSplatParams -OutVariable "InstallProgramResult" -ErrorAction Stop

        # Cleanup
        # NOTE: Using -EA SilentlyContinue for Remove-SudoSession because if we error, want to be sure it's from Install-Program
        $null = Cleanup -ProgramName $PrgName -ErrorAction SilentlyContinue
    }
    catch {
        # NOTE: Using Warning to output error message because any Error will prevent the rest of this Context block from running
        Write-Warning $($_.Exception.Message)
        
        $null = Cleanup -ProgramName $PrgName -ErrorAction SilentlyContinue
    }

    if ($InstallProgramResult) {
        switch ($SplatParamsSeriesItem.TestSeriesFunctionNames) {
            'CommonTestSeries' { $InstallProgramResult | CommonTestSeries }
        }
    }
    else {
        Write-Warning "Unable to run 'CommonTestSeries' in Context...`n    '$ContextString'`nbecause the 'Install-Program' function failed to output an object!"
    }
}

$Functions = @(
    ${Function:Cleanup}.Ast.Extent.Text
    ${Function:CommonTestSeries}.Ast.Extent.Text
    ${Function:StartTesting}.Ast.Extent.Text
)

$TestSplatParams = @(
    @{
        ProgramName         = "openssh"
        ResolveCommandPath  = $False
    }

    @{
        ProgramName         = "openssh"
        ResolveCommandPath  = $True
    }

    @{
        ProgramName     = "openssh"
        CommandName     = "ssh"
    }

    @{
        ProgramName                     = "openssh"
        CommandName                     = "ssh"
        ScanCDriveForMainExeIfNecessary = $True
    }

    @{
        ProgramName     = "openssh"
        CommandName     = "ssh"
        PreRelease      = $True
    }

    @{
        ProgramName             = "openssh"
        CommandName             = "ssh"
        ResolveCommandPath      = $False
    }

    @{
        ProgramName             = "openssh"
        CommandName             = "ssh"
        ExpectedInstallLocation = "C:\Program Files\OpenSSH-Win64"
    }

    @{
        ProgramName         = "openssh"
        CommandName         = "ssh"
        UsePowerShellGet    = $True
    }

    @{
        ProgramName             = "openssh"
        CommandName             = "ssh"
        UsePowerShellGet        = $True
        ForceChocoInstallScript = $True
    }

    @{
        ProgramName             = "openssh"
        CommandName             = "ssh"
        UseChocolateyCmdLine    = $True
    }
)

$ProgramAndCmdNameString = "-ProgramName '$($TestSplatParams[0]['ProgramName'])' -CommandName '$($TestSplatParams[0]['ProgramName'])'" 
$SplatParamsSeries = @(
    [pscustomobject]@{
        TestSeriesName          = "ProgramName"
        TestSeriesDescription   = "Test output using: -ProgramName '$($TestSplatParams[0]['ProgramName'])'"
        TestSeriesSplatParams   = $TestSplatParams[0]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
    [pscustomobject]@{
        TestSeriesName          = "ProgramName and ResolveCommandPath"
        TestSeriesDescription   = "Test output using: $ProgramAndCmdNameString"
        TestSeriesSplatParams   = $TestSplatParams[1]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
    [pscustomobject]@{
        TestSeriesName          = "ProgramName and CommandName"
        TestSeriesDescription   = "Test output using: $ProgramAndCmdNameString"
        TestSeriesSplatParams   = $TestSplatParams[2]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
    [pscustomobject]@{
        TestSeriesName          = "ProgramName and CommandName and ScanCDriveForMainExeIfNecessary"
        TestSeriesDescription   = "Test output using: $ProgramAndCmdNameString"
        TestSeriesSplatParams   = $TestSplatParams[3]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
    [pscustomobject]@{
        TestSeriesName          = "ProgramName and CommandName and PreRelease"
        TestSeriesDescription   = "Test output using: $ProgramAndCmdNameString -PreRelease"
        TestSeriesSplatParams   = $TestSplatParams[4]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
    [pscustomobject]@{
        TestSeriesName          = "ProgramName and CommandName and ResolveCommandPath is False"
        TestSeriesDescription   = "Test output using: $ProgramAndCmdNameString -ResolveCommandPath:`$False"
        TestSeriesSplatParams   = $TestSplatParams[5]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
    [pscustomobject]@{
        TestSeriesName          = "ProgramName and CommandName and ExpectedInstallLocation"
        TestSeriesDescription   = "Test output using: $ProgramAndCmdNameString -ExpectedInstallLocation 'C:\Program Files\OpenSSH-Win64'"
        TestSeriesSplatParams   = $TestSplatParams[6]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
    [pscustomobject]@{
        TestSeriesName          = "ProgramName and CommandName and PowerShellGet"
        TestSeriesDescription   = "Test output using: $ProgramAndCmdNameString -UserPowerShellGet"
        TestSeriesSplatParams   = $TestSplatParams[7]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
    [pscustomobject]@{
        TestSeriesName          = "ProgramName and CommandName and PowerShellGet and ForceChocolateyInstallScript"
        TestSeriesDescription   = "Test output using: $ProgramAndCmdNameString -UserPowerShellGet -ForceChocoInstallScript"
        TestSeriesSplatParams   = $TestSplatParams[8]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
    [pscustomobject]@{
        TestSeriesName          = "ProgramName and CommandName and PowerShellGet and UseChocolateyCmdLine"
        TestSeriesDescription   = "Test output using: $ProgramAndCmdNameString -UseChocolateyCmdLine"
        TestSeriesSplatParams   = $TestSplatParams[9]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
)

$global:MockResources = @{
    Functions           = $Functions
    SplatParamsSeries   = $SplatParamsSeries
    FakeOutputHT        = $FakeOutputHT
}

InModuleScope ProgramManagement {
    Describe "Test Install-Program" {
        Context "Non-Elevated PowerShell Session" {
            # IMPORTANT NOTE: Any functions that you'd like the 'it' blocks to use should be written in the 'Context' scope HERE!
            $global:MockResources['Functions'] | foreach { Invoke-Expression $_ }

            Mock 'GetElevation' -MockWith {$False}

            It "Should Throw An Error" {
                # New-SudoSession Common Parameters
                $IPSplat = @{
                    ProgramName = "openssh"
                    OutVariable = "InstallProgramResult"
                }

                {Install-Program @IPSplat} | Assert-Throw
            }
        }

        $i = 0
        foreach ($Series in $global:MockResources['SplatParamsSeries']) {
            $ContextSBPrep = @(
                "`$ContextInfo = `$global:MockResources['SplatParamsSeries'][$i].TestSeriesName"
                '$global:ContextStringBuilder = "Elevated PowerShell Session w/ $ContextInfo"'
                'Context $global:ContextStringBuilder {'
                '    $global:MockResources["Functions"] | foreach { Invoke-Expression $_ }'
                '    Mock "GetElevation" -MockWith {$True}'
                "    StartTesting -SplatParamsSeriesItem `$global:MockResources['SplatParamsSeries'][$i] -ContextString `$global:ContextStringBuilder"
                '}'
            )
            $ContextSB = [scriptblock]::Create($($ContextSBPrep -join "`n"))
            $ContextSB.InvokeReturnAsIs()
            $i++
        }
    }
}


# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUdSJpS/zOzwyNWgeCwpf20cFx
# boSgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFK8PwZkN4tAntGs0
# V2izO7+5rwFDMA0GCSqGSIb3DQEBAQUABIIBAGwO6zRCcAbNE3nEamJLf/bX8mQV
# Sqt3LxI/m5AL+wKpPm2SRtYSh6m/UOJJhH52Tw7raFVkhANdi6sobIvktzJQuJbL
# VsfnwXFOaK3WwGrv+BgmX7vxkGWG0DzDAr+lhZESn2Ke8TSnBrL7QsxhrlgORZX1
# R/9WNfzBtRKwMQGb/jX+6TDQmguGsu7Bg7XNDSux8T1Cdvq75GRUqCxa6bYNvw5z
# FQRYoEs6ndYIiqGcoEy9eZbLeQ4E4moGwtx7J6yNtP42VP/qDOTz4PACNW7f+Xqe
# N53uBaNLrzXtNdGNNtsj2OOY1IvCWpmLYy7i99LGleMqTygWI8Le17WG7XY=
# SIG # End signature block
