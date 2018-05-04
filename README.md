[![Build status](https://ci.appveyor.com/api/projects/status/github/pldmgg/programmanagement?branch=master&svg=true)](https://ci.appveyor.com/project/pldmgg/programmanagement/branch/master)


# ProgramManagement
This Module simplifies Program Installation/Uninstallation on Windows regardless of the method of installation (PowerShellGet, Chocolatey CmdLine, .msi, etc). Also, this function ensures that the Main Executable for the program is immediately available in PowerShell's $env:Path after the program is installed.

NOTE: Currently, this Module does not support installation/uninstallation of AppX packages. If AppX packages become more popular in the future, I will update this Module.

## Getting Started

```powershell
# One time setup
    # Download the repository
    # Unblock the zip
    # Extract the ProgramManagement folder to a module path (e.g. $env:USERPROFILE\Documents\WindowsPowerShell\Modules\)
# Or, with PowerShell 5 or later or PowerShellGet:
    Install-Module ProgramManagement

# Import the module.
    Import-Module ProgramManagement    # Alternatively, Import-Module <PathToModuleFolder>

# Get commands in the module
    Get-Command -Module ProgramManagement

# Get help
    Get-Help Install-Program -Full
    Get-Help about_ProgramManagement
```

## Examples

### Scenario 1 Install A Program

```powershell
PS C:\Users\zeroadmin> Install-Program openssh
Please wait...

The program 'openssh' was installed successfully!

InstallManager     : PowerShellGet
InstallAction      : FreshInstall
InstallCheck       : Microsoft.PackageManagement.Packaging.SoftwareIdentity
MainExecutable     :
OriginalSystemPath : C:\Chocolatey;C:\Chocolatey\li...[Truncated]...
CurrentSystemPath  : C:\Chocolatey;C:\Chocolatey\li...[Truncated]...
OriginalEnvPath    : C:\Program Files\ConEmu;C:\Program Files\ConE...[Truncated]...
CurrentEnvPath     : C:\Program Files\ConEmu;C:\Program Files\ConE...[Truncated]...

```

In the above example, the Install-Program function decides successfully installs 'openssh' via PowerShellGet. The 'MainExecutable' Property of the PSCustomObject output is null because there was no way for the `Install-Program` function to determine what the name of the Main Executable for this particular program is called (i.e. `ssh.exe`) since it is not exactly the same as the Program's Name a and no additional parameters (like `-CommandName`) are used. The properties `OriginalSystemPath`,`CurrentSystemPath`,`OriginalEnvPath`, and `CurrentEnvPath` are provided to make it relatively easy to determine what (if any) changes were made to System PATH or $env:Path. This information also makes it easy to revert any undesireable PATH changes that certain program installations might perform.

## Scenario 2 Uninstall A Program

```powershell
PS C:\Users\pdadmin> Uninstall-Program python
WARNING: Multiple packages matching the name 'python' have been found.
0) Python 3.6.5 Utility Scripts (64-bit)
1) Python 3.6.5 Test Suite (64-bit)
2) Python 3.6.5 Tcl/Tk Support (64-bit)
3) Python 3.6.5 pip Bootstrap (64-bit)
4) Python 3.6.5 Add to Path (64-bit)
5) Python 3.6.5 Standard Library (64-bit)
6) Python 3.6.5 Executables (64-bit)
7) Python 3.6.5 Documentation (64-bit)
8) Python 3.6.5 Development Libraries (64-bit)
9) Python 3.6.5 Core Interpreter (64-bit)
10) Python Launcher
11) Python 3.6.5 (64-bit)
12) All of the Above
Please enter one or more numbers (separated by commas) that correspond to the program(s) you would like to uninstall.: 12
Uninstalling Python 3.6.5 Utility Scripts (64-bit)...
Uninstalling Python 3.6.5 Test Suite (64-bit)...
Uninstalling Python 3.6.5 Tcl/Tk Support (64-bit)...
Uninstalling Python 3.6.5 pip Bootstrap (64-bit)...
Uninstalling Python 3.6.5 Add to Path (64-bit)...
Uninstalling Python 3.6.5 Standard Library (64-bit)...
Uninstalling Python 3.6.5 Executables (64-bit)...
Uninstalling Python 3.6.5 Documentation (64-bit)...
Uninstalling Python 3.6.5 Development Libraries (64-bit)...
Uninstalling Python 3.6.5 Core Interpreter (64-bit)...
Uninstalling Python Launcher...
Uninstalling Python 3.6.5 (64-bit)...
The program 'python' was uninstalled successfully!

DirectoriesThatMightNeedToBeRemoved ChocolateyInstalledProgramObjects PSGetInstalledPackageObjects RegistryProperties
----------------------------------- --------------------------------- ---------------------------- ------------------
{C:\Python36}
```

If you would like to skip the prompt and completely remove the specified program, use the `-UninstallAllSimilarlyNamedPackages` switch.


## Notes

* PSGallery: https://www.powershellgallery.com/packages/ProgramManagement
