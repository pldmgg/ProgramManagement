function Get-PackageManagerInstallObjects {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
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
        [array]$CheckInstalledPrograms = Check-InstalledPrograms -ProgramTitleSearchTerm $PNRegex
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