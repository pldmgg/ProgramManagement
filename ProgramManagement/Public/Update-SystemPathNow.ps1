# Originally from: http://www.scconfigmgr.com/2014/08/22/how-to-get-msi-file-information-with-powershell/
function Update-SystemPathNow {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PathToAdd
    )

    $RegKeyPath = 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment'
    $CurrentSystemPath = $(Get-ItemProperty -Path $RegKeyPath -Name PATH).Path

    if ($CurrentSystemPath | Select-String -SimpleMatch $PathToAdd) {
        Write-Warning 'Folder already within $env:Path'
        return
    }

    $NewPath = $PathToAdd + ';' + $CurrentSystemPath

    # Update the Registry
    Set-ItemProperty -Path $RegKeyPath -Name PATH -Value $NewPath

    # Now the registry is updated, but current processes haven't taken the changes.
    # We will now force all open processes/windows to take the updated system PATH

    if (-not $("Win32.NativeMethods" -as [Type])) {
        # import sendmessagetimeout from win32
        $null = Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @"
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(
IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
"@
    }

    $HWND_BROADCAST = [IntPtr] 0xffff
    $WM_SETTINGCHANGE = 0x1a
    $result = [UIntPtr]::Zero

    # notify all windows of environment block change
    [Win32.Nativemethods]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, "Environment", 2, 5000, [ref] $result)
}