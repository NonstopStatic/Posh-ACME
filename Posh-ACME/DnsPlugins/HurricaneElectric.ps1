function Add-DnsTxtHurricaneElectric {
    [CmdletBinding(DefaultParameterSetName='PlainText')]
    param(
        [Parameter(Mandatory,Position=0)]
        [String]$RecordName,
        [Parameter(Mandatory,Position=1)]
        [String]$TxtValue,
        [Parameter(ParameterSetName='Credential',Mandatory,Position=2)]
        [pscredential]$HECredential,
        [Parameter(ParameterSetName='PlainText',Mandatory,Position=2)]
        [Parameter(ParameterSetName='SecureString',Mandatory,Position=2)]
        [String]$HEUsername,
        [Parameter(ParameterSetName='PlainText',Mandatory,Position=3)]
        [String]$HEPassword,
        [Parameter(ParameterSetName='SecureString',Mandatory,Position=3)]
        [SecureString]$HESecret,
        [Parameter(ValueFromRemainingArguments)]
        $ExtraParams
    )

    Invoke-DnsTxtHurricaneElectricAPI -Add @PsBoundParameters

    <#
    .SYNOPSIS
        Add a DNS TXT record to a Hurricane Electric hosted zone.

    .DESCRIPTION
                This plugin uses the Hurricane Electric DNS web interface to add DNS TXT records. The interface was reverse engineered by monitoring HTML traffic.

    .PARAMETER RecordName
        The fully qualified name of the TXT record.

    .PARAMETER TxtValue
        The value of the TXT record.

    .PARAMETER HEUsername
        The username for the Hurricane Electric account with permission to update the specified hosted zone.

    .PARAMETER HEPassword
        The password for the Hurricane Electric account specified by -HEUsername.

    .PARAMETER HEPassword
        The password stored in a secure string for the Hurricane Electric account specified by -HEUsername.

    .PARAMETER ExtraParams
        This parameter can be ignored and is only used to prevent errors when splatting with more parameters than this function supports.

    .EXAMPLE
        Add-DnsTxtHE '_acme-challenge.site1.example.com' 'asdfqwer12345678' User Password

        Adds a TXT record for the specified site with the specified value.
    #>
}

function Remove-DnsTxtHurricaneElectric {
    [CmdletBinding(DefaultParameterSetName='PlainText')]
    param(
        [Parameter(Mandatory,Position=0)]
        [String]$RecordName,
        [Parameter(Mandatory,Position=1)]
        [String]$TxtValue,
        [Parameter(ParameterSetName='Credential',Mandatory,Position=2)]
        [pscredential]$HECredential,
        [Parameter(ParameterSetName='PlainText',Mandatory,Position=2)]
        [Parameter(ParameterSetName='SecureString',Mandatory,Position=2)]
        [String]$HEUsername,
        [Parameter(ParameterSetName='PlainText',Mandatory,Position=3)]
        [String]$HEPassword,
        [Parameter(ParameterSetName='SecureString',Mandatory,Position=3)]
        [SecureString]$HESecret,
        [Parameter(ValueFromRemainingArguments)]
        $ExtraParams
    )

    Invoke-DnsTxtHurricaneElectricAPI -Remove @PsBoundParameters

    <#
    .SYNOPSIS
        Remove a DNS TXT record from a Hurricane Electric hosted zone.

    .DESCRIPTION
        This plugin uses the Hurricane Electric DNS web interface to remove DNS TXT records. The interface was reverse engineered by monitoring HTML traffic.

    .PARAMETER RecordName
        The fully qualified name of the TXT record.

    .PARAMETER TxtValue
        The value of the TXT record.

    .PARAMETER HEUsername
        The username for the Hurricane Electric account with permission to write the specified hosted zone.

    .PARAMETER HEPassword
        The password for the Hurricane Electric account specified by -HEUsername.

    .PARAMETER HEPassword
        The password stored in a secure string for the Hurricane Electric account specified by -HEUsername.

    .PARAMETER ExtraParams
        This parameter can be ignored and is only used to prevent errors when splatting with more parameters than this function supports.

    .EXAMPLE
        Remove-DnsTxtHE '_acme-challenge.site1.example.com' 'asdfqwer12345678'  User Password

        Removes a TXT record for the specified site with the specified value.
    #>
}

function Save-DnsTxtHurricaneElectric {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments)]
        $ExtraParams
    )
    <#
    .SYNOPSIS
        Not required.

    .DESCRIPTION
        This provider does not require calling this function to commit changes to DNS records.

    .PARAMETER ExtraParams
        This parameter can be ignored and is only used to prevent errors when splatting with more parameters than this function supports.
    #>
}

############################
# Helper Functions
############################
function Invoke-DnsTxtHurricaneElectricAPI {
    [CmdletBinding(DefaultParameterSetName='Add')]
    param(
        [Parameter(ParameterSetName='Add',Mandatory,Position=0)]
        [switch] $Add,
        [Parameter(ParameterSetName='Remove',Mandatory,Position=0)]
        [switch] $Remove,
        [Parameter(ParameterSetName='GetZoneID',Mandatory,Position=0)]
        [switch] $GetZoneID,
        [Parameter(ParameterSetName='GetRecordID',Mandatory,Position=0)]
        [switch] $GetRecordID,
        [Parameter(ParameterSetName='Add',Mandatory,Position=1)]
        [Parameter(ParameterSetName='Remove',Mandatory,Position=1)]
        [Parameter(ParameterSetName='GetZoneID',Mandatory,Position=1)]
        [Parameter(ParameterSetName='GetRecordID',Mandatory,Position=1)]
        [String]$RecordName,
        [Parameter(ParameterSetName='Add',Mandatory,Position=2)]
        [Parameter(ParameterSetName='Remove',Mandatory,Position=2)]
        [Parameter(ParameterSetName='GetRecordID',Mandatory,Position=2)]
        [String]$TxtValue,
        [Parameter(ParameterSetName='GetRecordID',Mandatory,Position=3)]
        [Int]$ZoneID,
        [Parameter(ParameterSetName='Add')]
        [Parameter(ParameterSetName='Remove')]
        [pscredential]$HECredential,
        [Parameter(ParameterSetName='Add')]
        [Parameter(ParameterSetName='Remove')]
        [String]$HEUsername,
        [Parameter(ParameterSetName='Add')]
        [Parameter(ParameterSetName='Remove')]
        [String]$HEPassword,
        [Parameter(ParameterSetName='Add')]
        [Parameter(ParameterSetName='Remove')]
        [SecureString]$HESecret,
        [Parameter(ParameterSetName='GetZoneID',Mandatory,Position=3)]
        [Parameter(ParameterSetName='GetRecordID',Mandatory,Position=4)]
        [hashtable]$Credential,
        [Parameter(ParameterSetName='Add')]
        [Parameter(ParameterSetName='Remove')]
        $ExtraParams
    )

    # This code is based on dns_he.sh in the dnsapi scripts of acme.sh.
    # The HTML parsing is using different regular expressions than that script.
    # This version also caches zone ids and record ids.

    if ($GetZoneID) {
        # setup a module variables to cache the id mappings so it's
        # quicker to find later and to limit the need to request data from
        # Hurricane Electric
        if(!$script:HEZones){
            # Set the dictionary key to be case insensitive.
            $script:HEZones = `
                [Collections.Generic.Dictionary[String,Int]]::new([StringComparer]::CurrentCultureIgnoreCase)
        }
        $SendPOST = $script:HEZones.Count -eq 0
        if($SendPOST){
            $Body = $Credential
        }
    } else {
        $SendPOST = $Add -or $Remove
        if($SendPOST){
            # Read in the Hurricane Electric user information to derive logon information.
            if($HECredential){
                $HEUsername = $HECredential.UserName
                # $HESecret = $HECredential.Password
                $HEPassword = $HECredential.GetNetworkCredential().password
            }
            if($HESecret){
                $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($HESecret)
                try {
                    $HEPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                }
                finally {
                    [Runtime.InteropServices.Marshal]::FreeBSTR($BSTR)
                }
                $HESecret = $HECredential.Password
            }
            $Credential = @{
                email = $HEUsername
                pass = $HEPassword
            }

            if(!($ZoneID = Invoke-DnsTxtHurricaneElectricAPI -GetZoneID $RecordName $Credential)){
                throw "Unable to find Hurricane Electric hosted zone for $RecordName"
                # This error could be caused by changes in the Web site interface or by
                # providing incorrect logon information.
            }
            if($Add){
                # Add TXT Record
                $Body = $Credential +
                    @{
                        menu                  = 'edit_zone'
                        hosted_dns_zoneid     = $ZoneID
                        hosted_dns_editzone   = 1
                        Name                  = $RecordName
                        Type                  = 'TXT'
                        TTL                   = 300
                        Content               = $TxtValue
                        hosted_dns_editrecord = 'Submit'
                    }
            } else {
                # Remove TXT Record
                if(!($RecordID = Invoke-DnsTxtHurricaneElectricAPI -GetRecordID $RecordName $TxtValue $ZoneID $Credential)){
                    Write-Debug "Record $RecordName with value $TxtValue doesn't exist. Nothing to do."
                    return
                }
                $Body = $Credential +
                    @{
                        menu                  = 'edit_zone'
                        hosted_dns_zoneid     = $ZoneID
                        hosted_dns_editzone   = 1
                        hosted_dns_recordid   = $RecordID
                        hosted_dns_delrecord  = 1
                        hosted_dns_delconfirm = 'delete'
                    }
            }
        }
        # setup a module variable to cache the record value to id mapping
        # so it's quicker to find later and to limit redundant data from
        # Hurricane Electric
        if(!$script:HERecords){
            $script:HERecords = `
                [Collections.Generic.Dictionary[Int,[Collections.Generic.Dictionary[String,Int]]]]::new()
        }
        if($script:HERecords.ContainsKey($ZoneID)){
            $HEZoneRecords = $script:HERecords[$ZoneID]
        } else {
            # The dictionary key will be case sensitive.
            $HEZoneRecords = [Collections.Generic.Dictionary[String,Int]]::new()
            $script:HERecords.Add($ZoneID,$HEZoneRecords)
            if($GetRecordID){
                # This code branch should only be taken if this function is called with a
                # GetRecordID switch before being called with an Add switch for a
                # given zone. That would not normally happen, but could happen during testing.
                $SendPOST = $true
                $Body = $Credential + `
                    @{
                        menu              = 'edit_zone'
                        hosted_dns_zoneid = $ZoneID
                        hosted_dns_editzone   = ''
                    }
            }
        }
    }
    if($SendPOST){
        $response = Invoke-WebRequest @script:UseBasic -Method POST -Uri https://dns.he.net/ `
            -Header @{'Accept-Encoding'='gzip, deflate'} -Body $Body
        if($GetZoneID){
            # Parse the HTML to find zone ids.
            $responseMatches = Select-String -InputObject $response.Content -AllMatches `
                -Pattern 'delete_dom\(this\);" name="(?<Zone>[-_\.a-zA-Z0-9]+)" value="(?<ZoneID>[0-9]+)"'
            foreach($match in $responseMatches.Matches){
                [String] $Zone = $match.Groups['Zone'].Value
                [Int] $ZoneID = $match.Groups['ZoneID'].Value
                $script:HEZones.Add($Zone,$ZoneID)
                Write-Debug "Caching ID $ZoneID for zone $Zone."
            }
        } else {
            # Parse the HTML to find record ids for the current zone id.
            $responseMatches = Select-String -InputObject $response.Content -AllMatches `
                -Pattern '(?s)class="rrlabel TXT" data="TXT"(?<RawHTML>.*?)</tr>'
            $SubPattern = '(?s)data="(?<TxtValue>[^"]+)"' +
                '.*deleteRecord\(''(?<RecordID>[0-9]+)'',''(?<RecordName>[-_\.a-zA-Z0-9]+)'''
            $HEZoneRecords.Clear()
            foreach($match in $responseMatches.Matches){
                if($match.Groups['RawHTML'].Value -match $SubPattern){
                    [String] $AddRecordName = $Matches.RecordName
                    [String] $AddTxtValue = [Net.WebUtility]::HtmlDecode($Matches.TxtValue).Trim('"')
                    # For TXT values encoded per the ACME standard, there should only be a single string.
                    # For now, we just trim enclosing double quotes.
                    [Int] $RecordID = $Matches.RecordID
                    # The resource name is not case sensitive but the TXT value is.
                    $SearchKey = "{0}`t{1}" -f $AddRecordName.ToLower(), $AddTxtValue
                    $HEZoneRecords.Add($SearchKey,$RecordID)
                    Write-Debug "Caching ID $RecordID for record $AddRecordName with value $AddTxtValue."
                }
            }
        }
    }
    if($GetZoneID){
        # We need to find the zone ID for the closest/deepest sub-zone that would contain the record.
        $rnIndex = $RecordName.IndexOf('.') + 1
        while($rnIndex){
            $Zone = $RecordName.SubString($rnIndex)
            if($script:HEZones.ContainsKey($Zone)){
                # Returning Zone ID
                return $script:HEZones[$Zone]
            }
            $rnIndex = $RecordName.IndexOf('.',$rnIndex) + 1
        }
        # Did not find Zone ID
        return 0
    } elseif($GetRecordID) {
        # The resource name is not case sensitive but the TXT value is.
        $SearchKey = "{0}`t{1}" -f $RecordName.ToLower(), $TxtValue
        if($HEZoneRecords.ContainsKey($SearchKey)){
            # Returning Record ID
            return $HEZoneRecords[$SearchKey]
        }
        # Did not find Record ID
        return 0
    } elseif($DebugPreference -ne 'SilentlyContinue') {
        # This code branch is not run unless we are debugging.
        if(!($RecordID = Invoke-DnsTxtHurricaneElectricAPI -GetRecordID $RecordName $TxtValue $ZoneID $Credential)){
            if($Remove){
                Write-Debug "Record $RecordName with value $TxtValue removed."
            } else {
                Write-Debug "Record $RecordName with value $TxtValue not added. [Error]"
            }
        } else {
            if($Add) {
                Write-Debug "Record $RecordName with value $TxtValue added as record id $RecordID."
            } else {
                Write-Debug "Record $RecordName with value $TxtValue not removed. Still exists with id $RecordID. [Error]"
            }
        }
    }
}
