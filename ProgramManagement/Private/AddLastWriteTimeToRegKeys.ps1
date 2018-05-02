# From: https://gallery.technet.microsoft.com/scriptcenter/Get-Last-Write-Time-and-06dcf3fb
function AddLastWriteTimeToRegKeys {
    [CmdletBinding()]
    param ()

    # NOTE: If you use this method, do not import the Add-RegKeyMember function and Get-ChildItem proxy function

    Add-Type @"
using System; 
using System.Text;
using System.Runtime.InteropServices; 

namespace CustomNameSpace {
    public class advapi32 {
        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern Int32 RegQueryInfoKey(
            Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey,
            StringBuilder lpClass,
            [In, Out] ref UInt32 lpcbClass,
            UInt32 lpReserved,
            out UInt32 lpcSubKeys,
            out UInt32 lpcbMaxSubKeyLen,
            out UInt32 lpcbMaxClassLen,
            out UInt32 lpcValues,
            out UInt32 lpcbMaxValueNameLen,
            out UInt32 lpcbMaxValueLen,
            out UInt32 lpcbSecurityDescriptor,
            out Int64 lpftLastWriteTime
        );
    }
}
"@

    Update-TypeData -TypeName Microsoft.Win32.RegistryKey -MemberType ScriptProperty -MemberName LastWriteTime -Value {
        $LastWriteTime = $null
                
        $Return = [CustomNameSpace.advapi32]::RegQueryInfoKey(
            $this.Handle,
            $null,       # ClassName
            [ref] 0,     # ClassNameLength
            $null,  # Reserved
            [ref] $null, # SubKeyCount
            [ref] $null, # MaxSubKeyNameLength
            [ref] $null, # MaxClassLength
            [ref] $null, # ValueCount
            [ref] $null, # MaxValueNameLength 
            [ref] $null, # MaxValueValueLength 
            [ref] $null, # SecurityDescriptorSize
            [ref] $LastWriteTime
        )

        if ($Return -ne 0) {
            "[ERROR]"
        }
        else {
            # Return datetime object:
            [datetime]::FromFileTime($LastWriteTime)
        }
    }

    Update-TypeData -TypeName Microsoft.Win32.RegistryKey -MemberType ScriptProperty -MemberName ClassName -Value {
        $ClassLength = 255 # Buffer size (class name is rarely used, and when it is, I've never seen 
                            # it more than 8 characters. Buffer can be increased here, though. 
        $ClassName = New-Object System.Text.StringBuilder $ClassLength  # Will hold the class name
                
        $Return = [CustomNameSpace.advapi32]::RegQueryInfoKey(
            $this.Handle,
            $ClassName,
            [ref] $ClassLength,
            $null,  # Reserved
            [ref] $null, # SubKeyCount
            [ref] $null, # MaxSubKeyNameLength
            [ref] $null, # MaxClassLength
            [ref] $null, # ValueCount
            [ref] $null, # MaxValueNameLength 
            [ref] $null, # MaxValueValueLength 
            [ref] $null, # SecurityDescriptorSize
            [ref] $null  # LastWriteTime
        )

        if ($Return -ne 0) {
            "[ERROR]"
        }
        else {
            # Return class name
            $ClassName.ToString()
        }
    }
}