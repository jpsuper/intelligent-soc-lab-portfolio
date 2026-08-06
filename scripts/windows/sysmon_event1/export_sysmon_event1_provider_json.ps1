[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [datetime] $StartTime = (Get-Date).AddMinutes(-10),

    [ValidateRange(1, 999)]
    [int] $MaxEvents = 20,

    [ValidatePattern('^[a-z0-9]+(?:-[a-z0-9]+)*$')]
    [string] $FixtureSlug = 'live-capture',

    [switch] $AllowUnknownEventData,

    [switch] $Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Channel = 'Microsoft-Windows-Sysmon/Operational'
$ProviderName = 'Microsoft-Windows-Sysmon'
$EventNamespace = 'http://schemas.microsoft.com/win/2004/08/events/event'
$AllowedEventDataNames = @(
    'RuleName',
    'UtcTime',
    'ProcessGuid',
    'ProcessId',
    'Image',
    'FileVersion',
    'Description',
    'Product',
    'Company',
    'OriginalFileName',
    'CommandLine',
    'CurrentDirectory',
    'User',
    'LogonGuid',
    'LogonId',
    'TerminalSessionId',
    'IntegrityLevel',
    'Hashes',
    'ParentProcessGuid',
    'ParentProcessId',
    'ParentImage',
    'ParentCommandLine',
    'ParentUser'
)
$RequiredEventDataNames = @(
    'UtcTime',
    'ProcessGuid',
    'ProcessId',
    'Image',
    'CommandLine',
    'User',
    'ParentProcessId',
    'ParentImage'
)

function Get-SingleXmlNode {
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode] $Document,

        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNamespaceManager] $NamespaceManager,

        [Parameter(Mandatory = $true)]
        [string] $XPath,

        [Parameter(Mandatory = $true)]
        [string] $FieldName,

        [switch] $Optional
    )

    $Nodes = @($Document.SelectNodes($XPath, $NamespaceManager))
    if ($Nodes.Count -gt 1) {
        throw "Duplicate XML field: $FieldName"
    }
    if ($Nodes.Count -eq 0) {
        if ($Optional) {
            return $null
        }
        throw "Missing XML field: $FieldName"
    }
    return $Nodes[0]
}

function Convert-ToInteger {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Text,

        [Parameter(Mandatory = $true)]
        [string] $FieldName
    )

    [long] $Value = 0
    if (-not [long]::TryParse($Text, [ref] $Value) -or $Value -lt 0) {
        throw "Invalid integer XML field: $FieldName"
    }
    return $Value
}

function Add-OptionalInteger {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary] $Target,

        [System.Xml.XmlNode] $Node,

        [Parameter(Mandatory = $true)]
        [string] $OutputName,

        [Parameter(Mandatory = $true)]
        [string] $FieldName
    )

    if ($null -ne $Node -and $Node.InnerText -ne '') {
        $Target[$OutputName] = Convert-ToInteger -Text $Node.InnerText -FieldName $FieldName
    }
}

try {
    $Events = @(
        Get-WinEvent -FilterHashtable @{
            LogName   = $Channel
            Id        = 1
            StartTime = $StartTime
        } -ErrorAction Stop |
            Sort-Object -Property RecordId |
            Select-Object -First $MaxEvents
    )
}
catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
        $Events = @()
    }
    else {
        throw 'Failed to query Sysmon Event ID 1 from the configured channel.'
    }
}

if ($Events.Count -eq 0) {
    throw 'No Sysmon Event ID 1 records found in the requested time window.'
}

$PendingOutputs = @()
$Sequence = 0

foreach ($EventRecord in $Events) {
    $Sequence += 1
    [xml] $EventXml = $EventRecord.ToXml()
    $NamespaceManager = New-Object System.Xml.XmlNamespaceManager($EventXml.NameTable)
    $NamespaceManager.AddNamespace('e', $EventNamespace)

    $ProviderNode = Get-SingleXmlNode -Document $EventXml `
        -NamespaceManager $NamespaceManager `
        -XPath '/e:Event/e:System/e:Provider' `
        -FieldName 'System.Provider'
    $EventIdNode = Get-SingleXmlNode -Document $EventXml `
        -NamespaceManager $NamespaceManager `
        -XPath '/e:Event/e:System/e:EventID' `
        -FieldName 'System.EventID'
    $VersionNode = Get-SingleXmlNode -Document $EventXml `
        -NamespaceManager $NamespaceManager `
        -XPath '/e:Event/e:System/e:Version' `
        -FieldName 'System.Version' `
        -Optional
    $LevelNode = Get-SingleXmlNode -Document $EventXml `
        -NamespaceManager $NamespaceManager `
        -XPath '/e:Event/e:System/e:Level' `
        -FieldName 'System.Level' `
        -Optional
    $TaskNode = Get-SingleXmlNode -Document $EventXml `
        -NamespaceManager $NamespaceManager `
        -XPath '/e:Event/e:System/e:Task' `
        -FieldName 'System.Task' `
        -Optional
    $OpcodeNode = Get-SingleXmlNode -Document $EventXml `
        -NamespaceManager $NamespaceManager `
        -XPath '/e:Event/e:System/e:Opcode' `
        -FieldName 'System.Opcode' `
        -Optional
    $KeywordsNode = Get-SingleXmlNode -Document $EventXml `
        -NamespaceManager $NamespaceManager `
        -XPath '/e:Event/e:System/e:Keywords' `
        -FieldName 'System.Keywords' `
        -Optional
    $TimeCreatedNode = Get-SingleXmlNode -Document $EventXml `
        -NamespaceManager $NamespaceManager `
        -XPath '/e:Event/e:System/e:TimeCreated' `
        -FieldName 'System.TimeCreated'
    $EventRecordIdNode = Get-SingleXmlNode -Document $EventXml `
        -NamespaceManager $NamespaceManager `
        -XPath '/e:Event/e:System/e:EventRecordID' `
        -FieldName 'System.EventRecordID'
    $ChannelNode = Get-SingleXmlNode -Document $EventXml `
        -NamespaceManager $NamespaceManager `
        -XPath '/e:Event/e:System/e:Channel' `
        -FieldName 'System.Channel'
    $ComputerNode = Get-SingleXmlNode -Document $EventXml `
        -NamespaceManager $NamespaceManager `
        -XPath '/e:Event/e:System/e:Computer' `
        -FieldName 'System.Computer'

    $ResolvedProviderName = $ProviderNode.GetAttribute('Name')
    $ResolvedEventId = Convert-ToInteger -Text $EventIdNode.InnerText -FieldName 'System.EventID'
    $ResolvedChannel = $ChannelNode.InnerText
    if ($ResolvedProviderName -cne $ProviderName) {
        throw 'Unexpected provider route at System.Provider.Name.'
    }
    if ($ResolvedEventId -ne 1) {
        throw 'Unexpected provider route at System.EventID.'
    }
    if ($ResolvedChannel -cne $Channel) {
        throw 'Unexpected provider route at System.Channel.'
    }

    $System = [ordered] @{
        provider_name     = $ResolvedProviderName
        provider_event_id = $ResolvedEventId
    }
    $ProviderGuid = $ProviderNode.GetAttribute('Guid')
    if ($ProviderGuid -ne '') {
        $System['provider_guid'] = $ProviderGuid
    }
    Add-OptionalInteger -Target $System -Node $VersionNode `
        -OutputName 'event_version' -FieldName 'System.Version'
    Add-OptionalInteger -Target $System -Node $LevelNode `
        -OutputName 'event_level' -FieldName 'System.Level'
    Add-OptionalInteger -Target $System -Node $TaskNode `
        -OutputName 'event_task' -FieldName 'System.Task'
    Add-OptionalInteger -Target $System -Node $OpcodeNode `
        -OutputName 'event_opcode' -FieldName 'System.Opcode'
    if ($null -ne $KeywordsNode -and $KeywordsNode.InnerText -ne '') {
        $System['event_keywords'] = $KeywordsNode.InnerText
    }

    $SystemTime = $TimeCreatedNode.GetAttribute('SystemTime')
    if ($SystemTime -eq '') {
        throw 'Missing XML attribute: System.TimeCreated.SystemTime'
    }
    $System['system_time'] = $SystemTime
    $System['event_record_id'] = Convert-ToInteger `
        -Text $EventRecordIdNode.InnerText `
        -FieldName 'System.EventRecordID'
    $System['channel'] = $ResolvedChannel
    $System['computer'] = $ComputerNode.InnerText

    $EventData = [ordered] @{}
    $SeenEventDataNames = @()
    $DataNodes = @(
        $EventXml.SelectNodes('/e:Event/e:EventData/e:Data', $NamespaceManager)
    )
    foreach ($DataNode in $DataNodes) {
        $Name = $DataNode.GetAttribute('Name')
        if ($Name -eq '') {
            throw 'Unnamed EventData.Data node.'
        }
        if ($SeenEventDataNames -ccontains $Name) {
            throw "Duplicate EventData field: $Name"
        }
        $SeenEventDataNames += $Name
        if ($AllowedEventDataNames -cnotcontains $Name) {
            if (-not $AllowUnknownEventData) {
                throw "Unknown EventData field: $Name"
            }
            Write-Warning "Ignored unknown EventData field: $Name"
            continue
        }
        $EventData[$Name] = $DataNode.InnerText
    }

    foreach ($RequiredName in $RequiredEventDataNames) {
        if (-not $EventData.Contains($RequiredName)) {
            throw "Missing EventData field: $RequiredName"
        }
    }

    $SequenceText = '{0:D3}' -f $Sequence
    $FixtureId = "sysmon-event1-$FixtureSlug-$SequenceText"
    $FileName = "$FixtureId.json"
    $OutputObject = [ordered] @{
        fixture_contract_version = '1.0'
        fixture_id               = $FixtureId
        source_format            = 'sysmon_eventlog_json'
        system                   = $System
        event_data               = $EventData
    }
    $PendingOutputs += [pscustomobject] @{
        FileName = $FileName
        Content  = ($OutputObject | ConvertTo-Json -Depth 8)
    }
}

[System.IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
foreach ($PendingOutput in $PendingOutputs) {
    $OutputPath = Join-Path -Path $OutputDirectory -ChildPath $PendingOutput.FileName
    if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
        throw "Output file already exists: $($PendingOutput.FileName)"
    }
}

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
foreach ($PendingOutput in $PendingOutputs) {
    $OutputPath = Join-Path -Path $OutputDirectory -ChildPath $PendingOutput.FileName
    [System.IO.File]::WriteAllText($OutputPath, $PendingOutput.Content, $Utf8NoBom)
    Write-Output "native-collector-ok: $($PendingOutput.FileName)"
}
Write-Output "native-collector-count: $($PendingOutputs.Count)"
