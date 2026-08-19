
enum CEF_Ext_Device_Direction {
	inbound
    outbound
}

enum CEF_Ext_Event_Type {
    Base
    Aggregated
    Correlation
    Action
}

<#
enum CEF_Header_Event_Severity {
    Unknown = 0
    Low_1 = 1
    Low = 2
    Low_3 = 3
    Medium_4 = 4
    Medium = 5
    Medium_6 = 6
    High_7 = 7
    High = 8
    VeryHigh_9 = 9
    VeryHigh = 10
}
#>

function Format-MacAddress {
<#
.SYNOPSIS
    Normalizes a MAC address string to a consistent, optionally-delimited format.

.DESCRIPTION
    Format-MacAddress strips any existing colon, hyphen, or space delimiters from the input MAC
    address, then reassembles it as six hex-byte pairs joined by the specified separator (or no
    separator at all if none is given). Optionally forces the result to all-uppercase or
    all-lowercase.

.PARAMETER Address
    The MAC address to format. May be colon-, hyphen-, or space-delimited, or undelimited.

.PARAMETER Separator
    Optional. The character to use to separate each byte pair in the output: ':', '-', or ' '. If
    omitted, no separator is used.

.PARAMETER Case
    Optional. Forces the output to 'Upper' or 'Lower' case.

.EXAMPLE
    Format-MacAddress -Address '00-11-22-33-44-55' -Separator ':' -Case Upper

    Returns '00:11:22:33:44:55'.

.EXAMPLE
    Format-MacAddress -Address '001122334455'

    Returns '001122334455' (no separator applied).

.OUTPUTS
    System.String

.NOTES
    Author: Jared Poeppelman (powershellshock)
#>
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # MAC address to be formatted. Can be colon/hyphen/space delimited or not delimited 
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,17)]
        #[ValidateScript({(($_.Replace(':','')).Replace('-','')).Replace(' ','') -match {^[A-Fa-f0-9]{12}$}})]
        [ValidateScript({($_ -replace ':|-| ','') -match {^[A-Fa-f0-9]{12}$}})]
        [Alias("MacAddress","PhysicalAddress")]
        [string]
        $Address,

        # Optional separator character to use (can be colon ':', hyphen '-', or space ' '). If not specified, no separator will be used.
        [Parameter(Mandatory=$false,
                   Position=1)]
        [ValidateSet(':','-',' ')]
        [char]
        $Separator,

        # Specify output in all upper/lower case
        [Parameter(Mandatory=$false,
                   Position=2)]
        [ValidateSet('Upper','Lower')]
        [string]
        $Case
    )
        
    If ($Case -eq 'Upper') {
        $Address = $Address.ToUpper()
        #Write-Verbose "Format-MacAddress: Upper case was enforced: $Address"
    }

    If ($Case -eq 'Lower') {
        $Address = $Address.ToLower()
        #Write-Verbose "Format-MacAddress: Lower case was enforced: $Address"
    }

    $Address = (($Address.Replace(':','')).Replace('-','')).Replace(' ','')
    #Write-Verbose "Format-MacAddress: Colon (:), hyphen (-), and space ( ) separators removed, if present: $MacAddress"

    $Address = @(($Address[0,1] -join ''),($Address[2,3] -join ''),($Address[4,5] -join ''),($Address[6,7] -join ''),($Address[8,9] -join ''),($Address[10,11] -join '')) -join $Separator
    #Write-Verbose "Format-MacAddress: Address was reconstructed with specified separator: $Address"

    $Address
}

function New-CefMessage {
    <#
    .Synopsis
        Creates a properly formatted CEF message (UTF-8 encoded string) that can sent via SYSLOG or written to file. (Note that Out-File uses UTF-8 encoding, by default.)

    .DESCRIPTION
        Generate properly formatted CEF:0 (v0.1) or CEF:1 (v1.2), as specified by Common Event Format v26 specification 
        and consisting of mandatory CEF header fields and optional CEF extension fields. Uses input validation and programmatic message 
        construction to help ensure CEF-compliant messages.

        CEF uses UTF-8 Unicode encoding:
        - Spaces used in the header are valid. Do not encode or escape a space in a CEF header value.

        - pipes (|) in the header must be escaped with a backslash (\). pipes in the extension do not need escaping.

        - backslashess (\) in the header or the extension must be escaped with another backslash (\)
        
        - equal signs (=) in the extensions must be escaped with a backslash (\). Equal signs in the header do not need escaping. 
        
        - encode multi-line values (extension values only) using the newline character (\n or \r).
    
    .EXAMPLE
        New-CefMessage
    
    .INPUTS
        Nothing can be piped directly into this function (splatting recommended)
    
    .OUTPUTS
        CEF message as a [string]
    
    .NOTES
        Name: New-CefMessage
        Author: Jared Poeppelman (powershellshock)
    
    .LINK
        https://github.com/poshsecurity/Posh-Syslog
    
    .LINK
        https://github.com/powershellshock
            
    .LINK
        https://poshsecurity.com
    #>
    [CMDLetBinding()]
    [OutputType([string])]
    Param
    (
        # Override the default CEF version of 0 (v0.x) by setting it to 1 (v1.x)
        [Parameter(Mandatory = $false,HelpMessage = 'Integer to specify the CEF version of the message (0 or 1). Default is CEF:0 for compatibility even if CEF:1 extensions are used')]
        [ValidateSet(0,1)]
        [int]
        $CEFVersion=0,

        # Specifies the value to use for the "Device Vendor" portion of the CEF message header
        [Parameter(Mandatory = $true,Position=0,HelpMessage = 'String to uniquely identify the vendor of the device or component generating the message (type=string; max length=63)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,63)]
        [string]
        $DeviceVendor,

        # Specifies the value to use for the "Device Product" portion of the CEF message header
        [Parameter(Mandatory = $true,Position=1,HelpMessage = 'String to uniquely identify the product name of the device or component generating the message (type=string; max length=63)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,63)]
        [string]
        $DeviceProduct,

        # Specifies the value to use for the "Device Version" portion of the CEF message header
        [Parameter(Mandatory = $true,Position=2,HelpMessage = 'String to uniquely identify the product version of the device or component generating the message (type=string; max length=31)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,31)]
        [string]
        $DeviceVersion,

        # Specifies the value (string or integer) to use for the "Device Event Class ID" portion of the CEF message header
        [Parameter(Mandatory = $true,Position=3,HelpMessage = 'String to uniquely identify the event type being reported in the message, also known as "Signature ID" (type=string; max length=1023); equals sign (=), percent sign (%) and hashtag (#) characters must be escaped with a backslash (\), if used')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("SignatureId")]
        [string]
        $DeviceEventClassId,

        # Specifies the value to use for the "Name" portion of the CEF message header
        [Parameter(Mandatory = $true,Position=4,HelpMessage = 'String representing a human-readable description of the event; should be general and not include information that is specific to a single instance of the event, such as source IP addresses (type=string; max length=512)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,512)]
        [string]
        $Name,

        # Specifies the severity value from 0 to 10 (0=lowest, 10=highest) to use for the "Severity" portion of the CEF message header
        [Parameter(Mandatory = $true,Position=5,HelpMessage = 'Integer that reflects the importance of the event (a string or integer and it reflects the importance of the event')]
        [ValidateSet('Unknown','Low','Medium','High','Very-High','0','1','2','3','4','5','6','7','8','9','10')]
        [string]
        $Severity,

#region ----------------------------Optional CEF Extensions----------------------------

        #region ----------------------------enumtype extensions----------------------------
        
        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The direction of the observed communication. The following values are supported: "Inbound" (translated to integer value of 0) or "Outbound" (translated to integer value of 1)')]
        [ValidateNotNullOrEmpty()]
        [CEF_Ext_Device_Direction]
        $deviceDirection,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Can be "Base", "Aggregated", "Correlation", or "Action" (translated to integer values of  0, 1, 2, or 3 respectively. This field can be omitted for base events (type 0)')]
        [ValidateNotNullOrEmpty()]
        [CEF_Ext_Event_Type]
        $type,

        #endregion

        #region ----------------------------ipaddress extensions----------------------------
                
        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of four IPV6 address fields available to map fields that do not apply to any other CEF extension key name (type=ipaddress)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomIPv6Address1")]
        [ipaddress]
        $c6a1,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of four IPV6 address fields available to map fields that do not apply to any other CEF extension key name (type=ipaddress)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomIPv6Address2")]
        [ipaddress]
        $c6a2,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of four IPV6 address fields available to map fields that do not apply to any other CEF extension key name (type=ipaddress)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomIPv6Address3")]
        [ipaddress]
        $c6a3,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of four IPV6 address fields available to map fields that do not apply to any other CEF extension key name (type=ipaddress)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomIPv6Address4")]
        [ipaddress]
        $c6a4,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the translated destination address to which the event refers. Example: "192.168.10.1" (type=ipaddress)')]
        [ValidateNotNullOrEmpty()]
        [ipaddress]
        $destinationTranslatedAddress,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the translated device address to which the event refers. Example: "192.168.10.1" (type=ipaddress)')]
        [ValidateNotNullOrEmpty()]
        [ipaddress]
        $deviceTranslatedAddress,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the destination device address to which the event refers. Example: "192.168.10.1" (type=ipaddress)')]
        [ValidateNotNullOrEmpty()]
        [Alias("destinationAddress")]
        [ipaddress]
        $dst,
        
        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the device address to which the event refers. Example: "192.168.10.1" (type=ipaddress)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceAddress")]
        [ipaddress]
        $dvc,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the translated source address to which the event refers. Example: "192.168.10.1" (type=ipaddress)')]
        [ValidateNotNullOrEmpty()]
        [ipaddress]
        $sourceTranslatedAddress,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the source device address to which the event refers. Example: "192.168.10.1" (type=ipaddress)')]
        [ValidateNotNullOrEmpty()]
        [Alias("sourceAddress")]
        [ipaddress]
        $src,

        #endregion

        #region ----------------------------mac addr extensions----------------------------
        
        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the destination MAC address to which an event refers. The format is six pairs of hexadecimal numbers which can be separated by colons, hyphens, spaces, or not separated. (type=string)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,17)]
        [ValidateScript({(($_.Replace(':','')).Replace('-','')).Replace(' ','') -match {^[A-Fa-f0-9]{12}$}})]
        [Alias("destinationMacAddress")]
        [string]
        $dmac,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the device MAC address to which an event refers. The format is six pairs of hexadecimal numbers which can be separated by colons, hyphens, spaces, or not separated. (type=string)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,17)]
        [ValidateScript({(($_.Replace(':','')).Replace('-','')).Replace(' ','') -match {^[A-Fa-f0-9]{12}$}})]
        [Alias("deviceMacAddress")]
        [string]
        $dvcmac,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the source MAC address to which an event refers. The format is six pairs of hexadecimal numbers which can be separated by colons, hyphens, spaces, or not separated. (type=string)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,17)]
        [ValidateScript({(($_.Replace(':','')).Replace('-','')).Replace(' ','') -match {^[A-Fa-f0-9]{12}$}})]
        [Alias("sourceMacAddress")]
        [string]
        $smac,

        #endregion

        #region ----------------------------int extensions----------------------------

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of three number fields available to map fields that do not apply to any other CEF extension key name (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomNumber1","Channel")]
        [int]
        $cn1,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of three number fields available to map fields that do not apply to any other CEF extension key name (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomNumber2")]
        [int]
        $cn2,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of three number fields available to map fields that do not apply to any other CEF extension key name (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomNumber3")]
        [int]
        $cn3,
               
        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'A count associated with this event. How many times was this same event observed? Count can be omitted if it is 1 (type=int)')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_ -gt 0})]
        [Alias("baseEventCount")]
        [int]
        $cnt,
        
        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the translated destination port number to which the event refers (type=int; range=0-65535)')]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(0,65535)]
        [int]
        $destinationTranslatedPort,
        
        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The ID number of the destination process associated with the event. For example, if an event contains process ID 105, "105" is the process ID (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("destinationProcessId")]
        [int]
        $dpid,
            
        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the destination port number to which the event refers (type=int; range=0-65535)')]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(0,65535)]
        [Alias("destinationPort")]
        [int]
        $dpt,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The ID number of the process on the device that generated the event. For example, if an event was generated by process ID 105, "105" is the process ID (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceProcessId")]
        [int]
        $dvcpid,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'A custom integer field typically reserved for customer use and should not be set by vendors unless necessary. Use all flex fields sparingly and seek a more specific field when possible (type=int)')]
        [ValidateNotNullOrEmpty()]
        [int]
        $flexNumber1,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'A custom integer field typically reserved for customer use and should not be set by vendors unless necessary. Use all flex fields sparingly and seek a more specific field when possible (type=int)')]
        [ValidateNotNullOrEmpty()]
        [int]
        $flexNumber2,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Size of the file (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("fileSize")]
        [int]
        $fsize,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Number of bytes transferred inbound to the destination from the source (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("bytesIn")]
        [int]
        $in,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Size of the old file (type=int)')]
        [ValidateNotNullOrEmpty()]
        [int]
        $oldFileSize,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Number of bytes transferred outbound from the source to the destination (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("bytesOut")]
        [int]
        $out,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the translated source port number to which the event refers (type=int; range=0-65535)')]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(0,65535)]
        [int]
        $sourceTranslatedPort,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The ID number of the source process associated with the event. For example, if an event contains process ID 105, "105" is the process ID (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("sourceProcessId")]
        [int]
        $spid,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the source port number to which the event refers (type=int; range=0-65535)')]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(0,65535)]
        [Alias("sourcePort")]
        [int]
        $spt,
      
        #endregion

        #region ----------------------------CEF:1 (v1.2) new int extensions----------------------------

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'ID of an agentTranslatedZone resource reference (type=int). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [Alias("agentTranslatedZone")]
        [int]
        $agentTranslatedZoneKey,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'ID of an agentZone resource reference (type=int). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [Alias("agentZone")]
        [int]
        $agentZoneKey,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'ID of a customer resource reference (type=int). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [Alias("customer")]
        [int]
        $customerKey,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'ID of a destinationTranslatedZone resource reference (type=int). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [Alias("destinationTranslatedZone")]
        [int]
        $dTranslatedZoneKey,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'ID of a destinationZone resource reference (type=int). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [Alias("destinationZone")]
        [int]
        $dZoneKey,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'ID of a deviceTranslatedZone resource reference (type=int). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceTranslatedZone")]
        [int]
        $deviceTranslatedZoneKey,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'ID of a deviceZone resource reference (type=int). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceZone")]
        [int]
        $deviceZoneKey,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'ID of a sourceTranslatedZone resource reference (type=int). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [Alias("sourceTranslatedZone")]
        [int]
        $sTranslatedZoneKey,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'ID of a sourceZone resource reference (type=int). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [Alias("sourceZone")]
        [int]
        $sZoneKey,

        #endregion

        #region ----------------------------datetime extensions----------------------------
        
        # Timestamps as [string] types
        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of two timestamp fields available to map fields that do not apply to any other CEF extension key name (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $deviceCustomDate1,


        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of two timestamp fields available to map fields that do not apply to any other CEF extension key name (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $deviceCustomDate2,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of two timestamp fields available to map fields that do not apply to any other CEF extension key name (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [Alias("endTime")]
        [string]
        $end,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Time when the file was created (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $fileCreateTime,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Time when the file was last modified (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $fileModificationTime,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'A custom timestamp field typically reserved for customer use and should not be set by vendors unless necessary. Use all flex fields sparingly and seek a more specific field when possible (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $flexDate1,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Time when the old file was created (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $oldFileCreateTime,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Time when the old file was last modified (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $OldFileModificationTime,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Time when the event related to the activity was received (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceReceiptTime")]
        [string]
        $rt,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of two timestamp fields available to map fields that do not apply to any other CEF extension key name (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [Alias("startTime")]
        [string]
        $start,

        #endregion

        #region ----------------------------float extensions----------------------------
        
        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of four floating point fields available to map fields that do not apply to any other CEF extension key name (type=float)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomFloatingPoint1")]
        [float]
        $cfp1,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of four floating point fields available to map fields that do not apply to any other CEF extension key name (type=float)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomFloatingPoint2")]
        [float]
        $cfp2,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of four floating point fields available to map fields that do not apply to any other CEF extension key name (type=float)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomFloatingPoint3")]
        [float]
        $cfp3,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of four floating point fields available to map fields that do not apply to any other CEF extension key name (type=float)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomFloatingPoint4")]
        [float]
        $cfp4,

        #endregion

        #region ----------------------------String extensions----------------------------
        
        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Action taken by the device (full name=deviceAction; type=string; max length=63)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,63)]
        [Alias("deviceAction","Action")]
        [String]
        $act,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Application level protocol, example values are: HTTP, HTTPS, SSHv2, Telnet, POP, IMAP, IMAPS, etc. (type=string; max length=31)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,31)]
        [Alias("applicationProtocol")]
        [String]
        $app,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of six string fields available to map fields that do not apply to any other CEF extension key name (type=string; max length=4000)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,4000)]
        [string]
        [Alias("deviceCustomString1","RuleNumber","AclNumber","VirusName","Relay")]
        $cs1,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of six string fields available to map fields that do not apply to any other CEF extension key name (type=string; max length=4000)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,4000)]
        [Alias("deviceCustomString2","SignatureVersion","EngineVersion","SSID")]
        [string]
        $cs2,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of six string fields available to map fields that do not apply to any other CEF extension key name (type=string; max length=4000)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,4000)]
        [Alias("deviceCustomString3")]
        [string]
        $cs3,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of six string fields available to map fields that do not apply to any other CEF extension key name (type=string; max length=4000)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,4000)]
        [Alias("deviceCustomString4")]
        [string]
        $cs4,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of six string fields available to map fields that do not apply to any other CEF extension key name (type=string; max length=4000)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,4000)]
        [Alias("deviceCustomString5")]
        [string]
        $cs5,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'One of six string fields available to map fields that do not apply to any other CEF extension key name (type=string; max length=4000)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,4000)]
        [Alias("deviceCustomString6")]
        [string]
        $cs6,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The DNS domain part of the complete fully qualified domain name (FQDN) of the destination (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,255)]
        [String]
        $destinationDnsDomain,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The service targeted by this event. Example: "sshd" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [String]
        $destinationServiceName,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'A name that uniquely identifies the device generating this event (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,255)]
        [string]
        $deviceExternalId,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The facility generating this event. For example, Syslog has an explicit facility associated with every event (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $deviceFacility,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Interface on which the packet or data entered the device (type=string; max length=128)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,128)]
        [string]
        $deviceInboundInterface,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The Windows domain name of the device address (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,255)]
        [string]
        $deviceNtDomain,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Interface on which the packet or data left the device (type=string; max length=128)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,128)]
        [string]
        $deviceOutboundInterface,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Unique identifier for the payload associated with the event (type=string; max length=128)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,128)]
        [string]
        $devicePayloadId,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Process name associated with the event. An example might be the process generating the syslog entry in UNIX (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $deviceProcessName,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the destination to which an event refers. The format should be a fully qualified domain name associated with the destination node, if available  (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("destinationHostName")]
        [string]
        $dhost,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The Windows domain name of the destination address (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,255)]
        [Alias("destinationNtDomain")]
        [string]
        $dntdom,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The typical values are: "Administrator", "User", and "Guest". This identifies the privilege level of the user on the destination system. For example, activity executed on the root user would be identified with value of "Administrator"')]
        [ValidateNotNullOrEmpty()]
        [Alias("destinationUserPrivileges")]
        [string]
        $dpriv,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The name of the destination process with which the event is associated. For example, "telnetd" or "sshd" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("destinationProcessName")]
        [string]
        $dproc,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The timezone for the device generating the event (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,255)]
        [Alias("deviceTimeZone")]
        [string]
        $dtz,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the destination user by ID. For example, in UNIX, the root user has the uid of 0 (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("destinationUserId")]
        [string]
        $duid,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the username associated with the destination system. For example, with email related events the recipient is a candidate to put into destinationUserName. (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("destinationUserName","Recipient")]
        [string]
        $duser,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Fully qualified domain name associated with the device, if available (type=string; max length=100)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,100)]
        [Alias("deviceHostName")]
        [string]
        $dvchost,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The unique event identifier used by an originating device (type=string; max length=40)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,40)]
        [string]
        $externalId,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The hash of the file (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,255)]
        [string]
        $fileHash,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'An ID associated with a file, could be the inode (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $fileId,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Full path to the file, including file name itself. Example: C:\Program Files\WindowsNT\Accessories\wordpad.exe or /usr/bin/zip (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $filePath,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Permissions of the file (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $filePermission,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Type of the file, such as pipe, socket, etc (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $fileType,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'A custom string field typically reserved for customer use and should not be set by vendors unless necessary. Use all flex fields sparingly and seek a more specific field when possible (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $flexstring1,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'A custom string field typically reserved for customer use and should not be set by vendors unless necessary. Use all flex fields sparingly and seek a more specific field when possible (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $flexstring2,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Name of the file only, without its path (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("fileName")]
        [string]
        $fname,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'An arbitrary message giving more details about the event. Multi-line entries can be produced by using \n as the new line separator (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("message")]
        [string]
        $msg,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The hash of the old file (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,255)]
        [string]
        $oldFileHash,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'An ID associated with the old file, could be the inode (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $oldFileId,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Name of the old file, without its path (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $oldFileName,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Full path to the old file, including file name itself. Example: C:\Program Files\WindowsNT\Accessories\wordpad.exe or /usr/bin/zip (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $oldFilePath,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Permissions of the old file (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $oldFilePermission,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Type of the old file, such as pipe, socket, etc (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $oldFileType,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The outcome of the event, typically "success" or "failure" (type=string; max length=63)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,63)]
        [Alias("eventOutcome")]
        [string]
        $outcome,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the layer-4 protocol used, such as TCP, UDP, ICMP, GRE, etc. (type=string; max length=31)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,31)]
        [Alias("transportProtocol")]
        [string]
        $proto,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The reason an event was generated, such as "Bad password" or "Unknown user" or return code like "0x1234" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $reason,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'In the case of an HTTP request, this field contains the URL accessed, such as "https://site.example/vdir/resource.html" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("requestUrl")]
        [string]
        $request,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The user-agent associated with the request (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $requestClientApplication,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Description of the content from which the request originated, such as "HTTP Referrer" (type=string; max length=2048)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,2048)]
        [string]
        $requestContext,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Cookies associated with the request (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $requestCookies,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Method used to access a URL, such as "GET" or "POST" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $requestMethod,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the source system to which an event refers. The format should be a fully qualified domain name associated with the source node, if available  (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("sourceHostName")]
        [string]
        $shost,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The Windows domain name of the source address (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,255)]
        [Alias("sourceNtDomain")]
        [string]
        $sntdom, 

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The DNS domain part of the complete fully qualified domain name (FQDN) of the source (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,255)]
        [String]
        $sourceDnsDomain,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The service responsible for generating the event (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [String]
        $sourceServiceName,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The typical values are: "Administrator", "User", and "Guest". This identifies the privilege level of the user on the source system. For example, activity executed on the root user would be identified with value of "Administrator"')]
        [ValidateNotNullOrEmpty()]
        [Alias("sourceUserPrivileges")]
        [string]
        $spriv,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The name of the source process with which the event is associated. For example, "telnet" or "ssh" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("sourceProcessName")]
        [string]
        $sproc,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the source user by ID. For example, in UNIX, the root user has the uid of 0 (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("sourceUserId")]
        [string]
        $suid,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Identifies the username associated with the source system. For example, with email related events the sender is a candidate to put into sourceUserName. (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("sourceUserName","Sender")]
        [string]
        $suser,

        [Parameter(HelpMessage = 'A custom raw string parameter allowing inclusion of one or more custom extensions. Use only when no reasonable mapping exists to existing key names (type=string)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $CustomExtensionRawString,

        #endregion

        #region ----------------------------custom label extensions----------------------------

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "c6a1" key. Recommended value is "Device IPv6 Address" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomIPv6Address1Label")]
        [string]
        $c6a1Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "c6a2" key. Recommended value is "Source IPv6 Address" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomIPv6Address2Label")]
        [string]
        $c6a2Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "c6a3" key. Recommended value is "Destination IPv6 Address" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomIPv6Address3Label")]
        [string]
        $c6a3Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "c6a4" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomIPv6Address4Label")]
        [string]
        $c6a4Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "cfp1" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomFloatingPoint1Label")]
        [string]
        $cfp1Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "cfp2" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomFloatingPoint2Label")]
        [string]
        $cfp2Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "cfp3" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomFloatingPoint3Label")]
        [string]
        $cfp3Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "cfp4" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomFloatingPoint4Label")]
        [string]
        $cfp4Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "cn1" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomNumber1Label")]
        [string]
        $cn1Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "cn2" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomNumber2Label")]
        [string]
        $cn2Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "cn3" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomNumber3Label")]
        [string]
        $cn3Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "cs1" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomString1Label")]
        [string]
        $cs1Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "cs2" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomString2Label")]
        [string]
        $cs2Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "cs3" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomString3Label")]
        [string]
        $cs3Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "cs4" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomString4Label")]
        [string]
        $cs4Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "cs5" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomString5Label")]
        [string]
        $cs5Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "cs6" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [Alias("deviceCustomString6Label")]
        [string]
        $cs6Label,
        
        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "deviceCustomDate1" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $deviceCustomDate1Label,
        
        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "deviceCustomDate2" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,1023)]
        [string]
        $deviceCustomDate2Label,

        #endregion

        #region ----------------------------flex label extensions----------------------------

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "flexDate1" key (type=string; max length=128)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,128)]
        [string]
        $flexDate1Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "flexNumber1" key (type=string; max length=128)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,128)]
        [string]
        $flexNumber1Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "flexNumber2" key (type=string; max length=128)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,128)]
        [string]
        $flexNumber2Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "flexString1" key (type=string; max length=128)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,128)]
        [string]
        $flexString1Label,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Label name for the "flexString2" key (type=string; max length=128)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,128)]
        [string]
        $flexString2Label,

        #endregion

        #region ----------------------------CEF:1 (v1.2) new string extensions----------------------------
        
        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Elapsed time in milliseconds of the action or entity the event represents (type=string; max length=64). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,64)]
        [string]
        $reportedDuration,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Name of a group containing the resource in the system that sent the event (type=string; max length=128). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,128)]
        [string]
        $reportedResourceGroupName,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'ID of the affected resource in the system that sent the event (type=string; max length=256). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,256)]
        [string]
        $reportedResourceID,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Name of the affected resource in the system that sent the event (type=string; max length=64). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,64)]
        [string]
        $reportedResourceName,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Type of the affected resource in the system that sent the event (type=string; max length=64). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,64)]
        [string]
        $reportedResourceType,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'The name of the framework used for threatAttackID (type=string; max length=256). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,256)]
        [string]
        $frameworkName,

        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'Threat actor associated with the event (type=string; max length=40). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,40)]
        [string]
        $threatActor,
        
        [Parameter(ParameterSetName='CEFExtension',HelpMessage = 'A full ID of a threat or attack as defined in the security framework in frameworkName (type=string; max length=32). Introduced in CEF:1 (v1.2)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0,32)]
        [string]
        $threatAttackID

        #endregion

#endregion CEF Extensions
    )
    [String]$CEFExtension = ''
    [String]$CEFVersion = 'CEF:{0}' -f $CEFVersion
    
    # Convert MAC addresses to CEF expected format
    If ($dmac) {
        $dmac = Format-MacAddress -MacAddress $dmac -Separator ':' -Case Upper
        Write-Verbose "New-CefMessage: dmac: Formatted MAC address: $dmac"
    }
    If ($dvcmac) {
        $dvcmac = Format-MacAddress -MacAddress $dvcmac -Separator ':' -Case Upper
        Write-Verbose "New-CefMessage: dvcmac: Formatted MAC address: $dvcmac"
    }
    If ($smac) {
        $smac = Format-MacAddress -MacAddress $smac   -Separator ':' -Case Upper
        Write-Verbose "New-CefMessage: smac: Formatted MAC address: $smac"
    }
    # Build list of parameters used when the cmdlet was called
    $SpecifiedExtensions = @() 
    Write-Verbose "New-CefMessage: Getting BoundParameters"
    $PSCmdlet.MyInvocation.BoundParameters.GetEnumerator() | ForEach-Object {
        $SpecifiedExtensions += $_.Key
        }

    # Build list of specified params that are part of the 'CEFExtension' param set
    $SpecifiedExtensions | ForEach-Object {      
        # Build list of param sets of which this param is a member
        $ParamSets = @()
        Write-Verbose ("New-CefMessage: {0}: Checking ParameterSets of '-{0}'" -f $_)
        ($MyInvocation.MyCommand.Parameters.Item($_)).ParameterSets.GetEnumerator() | ForEach-Object {
            $ParamSets += $_.Key
        }

        # If this param is a member of the 'CEFExtension' paramset, add it to the output variable
        If ($ParamSets -ccontains 'CEFExtension') {

            # Special handling of params of enum type: CEF_Ext_Device_Direction
            If (($MyInvocation.MyCommand.Parameters.Item($_)).ParameterType -eq [CEF_Ext_Device_Direction]) {
                Write-Verbose ("New-CefMessage: {0}: Using enum [int] value for '-{0}': enum type is CEF_Ext_Device_Direction" -f $_)
                $CEFExtension += (((Get-Variable $_).Name),((Get-Variable $_).Value -as [int]) -join '=')+' '
            }

            # Special handling of params of enum type: CEF_Ext_Event_Type
            ElseIf (($MyInvocation.MyCommand.Parameters.Item($_)).ParameterType -eq [CEF_Ext_Event_Type]) {
                Write-Verbose ("New-CefMessage: {0}: Using enum [int] value for '-{0}': enum type is CEF_Ext_Event_Type" -f $_)
                $CEFExtension += (((Get-Variable $_).Name),((Get-Variable $_).Value -as [int]) -join '=')+' '
            }

            # Default handling of CEF extension fields
            Else {
                Write-Verbose ("New-CefMessage: {0}: Using standard CEF extension handling for '-{0}'" -f $_)
                $CEFExtension += (((Get-Variable $_).Name),((Get-Variable $_).Value) -join '=').ToString().Trim()+' '
            }
        }
    }

    # Add raw, non-standard CEF extension field key-value pairs directly (this param is not a member of the 'CEFExtension' paramset on purpose, we handle it uniquely because it contains both key names and values, e.g.- "cefkeyname=value")
    If ($CustomExtensionRawString) {
        $CEFExtension += $CustomExtensionRawString.Trim()
        Write-Verbose "New-CefMessage: CEF custom extension field key-value pairs being used: $CEFExtension"
    }

    # Trim whitespace from CEF extension
    $CEFExtension = $CEFExtension.ToString().Trim()
    Write-Verbose "New-CefMessage: CEF extension being used: $CEFExtension"
    
    [String]$CEFHeader = "$CEFVersion|$DeviceVendor|$DeviceProduct|$DeviceVersion|$DeviceEventClassId|$Name|$Severity|"

    If ($CEFExtension -ne '') {
        $CEFMessage = '{0}{1}' -f $CEFHeader, $CEFExtension
    }
    Else {
        $CEFMessage = $CEFHeader
    }

    Write-Verbose ('New-CefMessage: CEF message length: {0}' -f ($CEFMessage.Length))
    $CEFMessage
}

Export-ModuleMember -Function * -Alias *