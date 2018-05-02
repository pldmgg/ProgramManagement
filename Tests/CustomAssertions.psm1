<#
    .SYNOPSIS
    Tests whether a value matches one of the types listed in the $TypeArray
#>
function BeTypeOrType {
    [CmdletBinding()]
    Param(
        $ActualValue,
        [string[]]$TypeArray,
        [switch]$Negate
    )

    if ($ActualValue -ne $null) {
        $InputObjectType = $ActualValue.GetType().FullName
        [bool]$Pass = $TypeArray -contains $InputObjectType
    }
    else {
        $InputObjectType = $null
        [bool]$Pass = $TypeArray -contains $null
    }

    If ( $Negate ) { $Pass = -not($Pass) }

    If ( -not($Pass) ) {
        If ( $Negate ) {
            $FailureMessage = "Expected: Object type $InputObjectType to NOT be one of the following types: $($TypeArray -join ", ")"
        }
        Else {
            $FailureMessage = "Expected: Object type $InputObjectType to be one of the following types $($TypeArray -join ", ")"
        }
    }

    $ObjProperties = @{
        Succeeded      = $Pass
        FailureMessage = $FailureMessage
    }
    return New-Object PSObject -Property $ObjProperties
}