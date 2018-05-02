function PauseForWarning {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [int]$PauseTimeInSeconds,

        [Parameter(Mandatory=$True)]
        $Message
    )

    Write-Warning $Message
    Write-Host "To answer in the affirmative, press 'y' on your keyboard."
    Write-Host "To answer in the negative, press any other key on your keyboard, OR wait $PauseTimeInSeconds seconds"

    $timeout = New-Timespan -Seconds ($PauseTimeInSeconds - 1)
    $stopwatch = [diagnostics.stopwatch]::StartNew()
    while ($stopwatch.elapsed -lt $timeout){
        if ([Console]::KeyAvailable) {
            $keypressed = [Console]::ReadKey("NoEcho").Key
            Write-Host "You pressed the `"$keypressed`" key"
            if ($keypressed -eq "y") {
                $Result = $true
                break
            }
            if ($keypressed -ne "y") {
                $Result = $false
                break
            }
        }

        # Check once every 1 second to see if the above "if" condition is satisfied
        Start-Sleep 1
    }

    if (!$Result) {
        $Result = $false
    }
    
    $Result
}