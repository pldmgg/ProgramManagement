# Outputs [System.Collections.ArrayList]$ExePath
function Get-ExePath {
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
    else {
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
            $DirectoriesToSearchFinal = $DirectoriesToSearchFinal | Where-Object {$_ -match $ProgramName}

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