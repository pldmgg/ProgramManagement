# Change log

## 1.3.1 (June 7, 2019)

- Fixed logic with -UninstallAllSimilarlyNamedPackages switch in Uninstall-Program function

## 1.3.0 (December 8, 2018)

- Removed Get-AllAvailablePackages function
- Updated Get-AllPackageInfo to handle Appx packages

## 1.2.0 (December 7, 2018)

- Added Get-AllAvailablePackages function

## 1.1.3 (November 26, 2018)

- Fixed issue with chocolatey v2 api availability check in PowerShell Core

## 1.1.2 (November 14, 2018)

- Fix Authenticode Signature Attempt 1

## 1.1.1 (September 16, 2018)

- Minor updates to build.

## 1.1.0 (September 13, 2018)

- Fixed issues with Chocolatey being unable to find Chocolatey Extensions Modules on the filesystem

## 1.0.9 (September 12, 2018)

- Minor updates to Install-Program and GetMSIFileInfo

## 1.0.8 (September 11, 2018)

- Updated logic to handle situations where PowerShellGet / PackageManagement completes a dirty install (installs program and dependencies, but throws one or more errors along the way)

## 1.0.7 (September 8, 2018)

- Changed Errors related to PowerShellGet / PackageManagement Chocolatey Repo Chocolatey installation script failures to Warnings

## 1.0.6 (September 7, 2018)

- Fixes to logic that handles PowerShell Get / PackageManagement failures

## 1.0.5 (September 7, 2018)

- Removed erroneous message saying package was installed when it was already present and no install action actually took place.

## 1.0.4 (September 7, 2018)

- Fixed Test-Path logic in Install-Program where sometimes the -Path parameter could be $null

## 1.0.3 (August 19, 2018)

- Fixed logic that determines whether or not to attempt install and added -Force switch

## 1.0.2 (August 1, 2018)

- Updated WinCompat Functions

## 1.0.1 (July 23, 2018)

- Updated InvokePSCompatibility Private to improve import speed in PSCore

## 1.0.0 (July 23, 2018)

- Added an error condition for situations where the Install-Package cmdlet (for PowerShellGet) does literally nothing

## 0.9.9 (July 23, 2018)

- Updated InvokeModuleDependencies and InvokePSCompatibility Private functions to ensure Module Dependencies are installed even when function names overlap

## 0.9.8 (July 23, 2018)

- Fixed issue with Output and Error Handling when falling back to Chocolatey CmdLine

## 0.9.7 (July 18, 2018)

- Updated GetModuleDependencies Private function to help Module load faster in PSCore

## 0.9.6 (July 13, 2018)

- Fixed logic to determine if installation is an Update or Fresh Install

## 0.9.5 (July 13, 2018)

- Suppressed multiple 7zip outputs

## 0.9.4 (July 10, 2018)

- Additional updates to psake

## 0.9.3 (July 8, 2018)

- Updated psake

## 0.9.2 (July 8, 2018)

- Updated psake and added PSCompatibility Functions

## 0.9.1 (July 1, 2018)

- Fixed issue with expected Chocolatey resource path

## 0.9.0 (June 28, 2018)

- Fixed compatibility issues with PowerShell Core (ON WINDOWS)

## 0.8.5 (June 13, 2018)

- Now compatible with PowerShell Core ON WINDOWS

## 0.8.4 (June 06, 2018)

- Updated build process and Pester testing
- Updated README.md

## 0.8.3 (June 04, 2018)

- Added -GetPreviousVersion switch to install version of Program preceding latest

## 0.8.2 (May 04, 2018)

- Updated Module Description on PSGallery

## 0.8.1 (May 04, 2018)

- Created

