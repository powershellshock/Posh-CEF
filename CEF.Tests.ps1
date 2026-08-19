#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Tests for CEF.psm1 (Format-MacAddress, New-CefMessage).

.DESCRIPTION
    Both functions are pure - no filesystem, network, GUI or configuration dependencies - so these
    are plain unit tests with no mocking required.

    The module is imported directly by file rather than through any parent manifest, so this file
    and CEF.psm1 stand on their own and can be lifted into a repository of their own unchanged.
#>

BeforeAll {
    $script:ModulePath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'CEF.psm1'

    Remove-Module -Name 'CEF' -Force -ErrorAction SilentlyContinue
    Import-Module -Name $script:ModulePath -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'CEF' -Force -ErrorAction SilentlyContinue
}

Describe 'Format-MacAddress' {
    # Format-MacAddress has full public-style comment-based help and is used internally by
    # New-CefMessage. It is exercised through InModuleScope rather than assuming it is exported,
    # so these tests keep working whether or not it is part of the module's public surface.
    It 'normalizes a hyphen-delimited address with a colon separator' {
        InModuleScope 'CEF' {
            Format-MacAddress -Address '00-11-22-33-44-55' -Separator ':' -Case Upper | Should -Be '00:11:22:33:44:55'
        }
    }

    It 'normalizes a colon-delimited address with no separator' {
        InModuleScope 'CEF' {
            Format-MacAddress -Address '00:11:22:33:44:55' | Should -Be '001122334455'
        }
    }

    It 'normalizes a space-delimited address' {
        InModuleScope 'CEF' {
            Format-MacAddress -Address '00 11 22 33 44 55' -Separator '-' | Should -Be '00-11-22-33-44-55'
        }
    }

    It 'passes through an already-undelimited address unchanged when no separator is requested' {
        InModuleScope 'CEF' {
            Format-MacAddress -Address '001122334455' | Should -Be '001122334455'
        }
    }

    It 'forces upper case when -Case Upper is specified' {
        InModuleScope 'CEF' {
            Format-MacAddress -Address 'aa-bb-cc-dd-ee-ff' -Case Upper -Separator ':' | Should -Be 'AA:BB:CC:DD:EE:FF'
        }
    }

    It 'forces lower case when -Case Lower is specified' {
        InModuleScope 'CEF' {
            Format-MacAddress -Address 'AA-BB-CC-DD-EE-FF' -Case Lower -Separator ':' | Should -Be 'aa:bb:cc:dd:ee:ff'
        }
    }

    It 'accepts pipeline input' {
        InModuleScope 'CEF' {
            '00-11-22-33-44-55' | Format-MacAddress -Separator ':' | Should -Be '00:11:22:33:44:55'
        }
    }

    It 'rejects an address that is too short' {
        InModuleScope 'CEF' {
            { Format-MacAddress -Address '00-11-22' -ErrorAction Stop } | Should -Throw
        }
    }

    It 'rejects an address containing non-hex characters' {
        InModuleScope 'CEF' {
            { Format-MacAddress -Address 'ZZ-11-22-33-44-55' -ErrorAction Stop } | Should -Throw
        }
    }

    It 'rejects an unsupported separator character' {
        InModuleScope 'CEF' {
            { Format-MacAddress -Address '001122334455' -Separator '_' -ErrorAction Stop } | Should -Throw
        }
    }
}

Describe 'New-CefMessage' {
    It 'builds a CEF:0 header with no extensions' {
        $msg = New-CefMessage -DeviceVendor 'Contoso' -DeviceProduct 'Lab' -DeviceVersion '1.0' -DeviceEventClassId '100' -Name 'Test Event' -Severity 'Low'
        $msg | Should -Be 'CEF:0|Contoso|Lab|1.0|100|Test Event|Low|'
    }

    It 'uses CEF:1 header prefix when -CEFVersion 1 is specified' {
        $msg = New-CefMessage -CEFVersion 1 -DeviceVendor 'Contoso' -DeviceProduct 'Lab' -DeviceVersion '1.0' -DeviceEventClassId '100' -Name 'Test Event' -Severity '5'
        $msg | Should -BeLike 'CEF:1|*'
    }

    It 'accepts a numeric string severity' {
        { New-CefMessage -DeviceVendor 'V' -DeviceProduct 'P' -DeviceVersion '1' -DeviceEventClassId '1' -Name 'N' -Severity '10' -ErrorAction Stop } | Should -Not -Throw
    }

    It 'rejects an out-of-range severity value' {
        { New-CefMessage -DeviceVendor 'V' -DeviceProduct 'P' -DeviceVersion '1' -DeviceEventClassId '1' -Name 'N' -Severity '11' -ErrorAction Stop } | Should -Throw
    }

    It 'appends simple string/ipaddress extension fields as key=value pairs' {
        $msg = New-CefMessage -DeviceVendor 'Contoso' -DeviceProduct 'Lab' -DeviceVersion '1.0' -DeviceEventClassId '100' -Name 'Login' -Severity 'Medium' -src '10.0.0.5' -dst '10.0.0.10' -msg 'Test message'

        $msg | Should -BeLike '*src=10.0.0.5*'
        $msg | Should -BeLike '*dst=10.0.0.10*'
        $msg | Should -BeLike '*msg=Test message*'
    }

    It 'normalizes MAC address extensions via Format-MacAddress (colon-separated, upper case)' {
        $msg = New-CefMessage -DeviceVendor 'Contoso' -DeviceProduct 'Lab' -DeviceVersion '1.0' -DeviceEventClassId '100' -Name 'Login' -Severity 'Medium' -smac '00-11-22-33-44-55'

        $msg | Should -BeLike '*smac=00:11:22:33:44:55*'
    }

    It 'renders the deviceDirection enum extension as its integer value' {
        $msgOut = New-CefMessage -DeviceVendor 'Contoso' -DeviceProduct 'Lab' -DeviceVersion '1.0' -DeviceEventClassId '100' -Name 'N' -Severity 'Low' -deviceDirection outbound
        $msgIn = New-CefMessage -DeviceVendor 'Contoso' -DeviceProduct 'Lab' -DeviceVersion '1.0' -DeviceEventClassId '100' -Name 'N' -Severity 'Low' -deviceDirection inbound

        $msgOut | Should -BeLike '*deviceDirection=1*'
        $msgIn | Should -BeLike '*deviceDirection=0*'
    }

    It 'renders the type enum extension as its integer value' {
        $msg = New-CefMessage -DeviceVendor 'Contoso' -DeviceProduct 'Lab' -DeviceVersion '1.0' -DeviceEventClassId '100' -Name 'N' -Severity 'Low' -type Correlation
        $msg | Should -BeLike '*type=2*'
    }

    It 'appends raw custom extension key=value pairs verbatim' {
        $msg = New-CefMessage -DeviceVendor 'Contoso' -DeviceProduct 'Lab' -DeviceVersion '1.0' -DeviceEventClassId '100' -Name 'N' -Severity 'Low' -CustomExtensionRawString 'customKey=customValue anotherKey=anotherValue'

        $msg | Should -BeLike '*customKey=customValue anotherKey=anotherValue*'
    }

    It 'rejects a DeviceVendor longer than 63 characters' {
        $longVendor = 'V' * 64
        { New-CefMessage -DeviceVendor $longVendor -DeviceProduct 'P' -DeviceVersion '1' -DeviceEventClassId '1' -Name 'N' -Severity 'Low' -ErrorAction Stop } | Should -Throw
    }
}
