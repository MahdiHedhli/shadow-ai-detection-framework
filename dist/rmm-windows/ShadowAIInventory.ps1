#Requires -Version 5.1
<#
.SYNOPSIS
Read-only Shadow AI inventory collector for Windows RMM execution.

.DESCRIPTION
Emits metadata only. Command lines are evaluated locally and are never emitted.
No prompt, response, configuration, environment value, or file content is read.

.PARAMETER SelfTest
Emits an empty conformant document without scanning the endpoint.

.NOTES
Exit 0: complete collection (findings may exist)
Exit 2: partial collection
Exit 1: fatal collector failure
#>
[CmdletBinding()]
param([switch]$SelfTest)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$CollectorName = 'shadow-ai-rmm-windows'
$CollectorVersion = '0.2.1'
$MaxFindings = 5000
$ExtensionIdPattern = '^[a-p]{32}$'
$CatalogJson = @'
[
  {
    "artifact_id": "cmd-mcp-001",
    "artifact_type": "command_line",
    "capability": "mcp_server",
    "confidence": "high",
    "match_mode": "contains",
    "pattern": "@modelcontextprotocol",
    "platform": "any",
    "provider_id": "mcp"
  },
  {
    "artifact_id": "cmd-mcp-002",
    "artifact_type": "command_line",
    "capability": "mcp_server",
    "confidence": "medium",
    "match_mode": "contains",
    "pattern": "mcp-server",
    "platform": "any",
    "provider_id": "mcp"
  },
  {
    "artifact_id": "cmd-mcp-003",
    "artifact_type": "command_line",
    "capability": "mcp_server",
    "confidence": "high",
    "match_mode": "contains",
    "pattern": "fastmcp",
    "platform": "any",
    "provider_id": "mcp"
  },
  {
    "artifact_id": "env-anthropic-001",
    "artifact_type": "environment_variable_name",
    "capability": "api_credential_name",
    "confidence": "medium",
    "match_mode": "exact",
    "pattern": "ANTHROPIC_API_KEY",
    "platform": "any",
    "provider_id": "anthropic"
  },
  {
    "artifact_id": "env-google-001",
    "artifact_type": "environment_variable_name",
    "capability": "api_credential_name",
    "confidence": "low",
    "match_mode": "exact",
    "pattern": "GOOGLE_API_KEY",
    "platform": "any",
    "provider_id": "google"
  },
  {
    "artifact_id": "env-openai-001",
    "artifact_type": "environment_variable_name",
    "capability": "api_credential_name",
    "confidence": "medium",
    "match_mode": "exact",
    "pattern": "OPENAI_API_KEY",
    "platform": "any",
    "provider_id": "openai"
  },
  {
    "artifact_id": "file-mcp-001",
    "artifact_type": "config_file",
    "capability": "mcp_configuration",
    "confidence": "medium",
    "match_mode": "exact",
    "pattern": "mcp.json",
    "platform": "any",
    "provider_id": "mcp"
  },
  {
    "artifact_id": "file-mcp-002",
    "artifact_type": "config_file",
    "capability": "mcp_configuration",
    "confidence": "high",
    "match_mode": "exact",
    "pattern": "claude_desktop_config.json",
    "platform": "any",
    "provider_id": "mcp"
  },
  {
    "artifact_id": "file-mcp-003",
    "artifact_type": "config_file",
    "capability": "mcp_configuration",
    "confidence": "medium",
    "match_mode": "exact",
    "pattern": ".mcp.json",
    "platform": "any",
    "provider_id": "mcp"
  },
  {
    "artifact_id": "file-model-001",
    "artifact_type": "model_file",
    "capability": "model_weight",
    "confidence": "high",
    "match_mode": "suffix",
    "pattern": ".gguf",
    "platform": "any",
    "provider_id": "generic"
  },
  {
    "artifact_id": "file-model-002",
    "artifact_type": "model_file",
    "capability": "model_weight",
    "confidence": "high",
    "match_mode": "suffix",
    "pattern": ".ggml",
    "platform": "any",
    "provider_id": "generic"
  },
  {
    "artifact_id": "proc-gpt4all-001",
    "artifact_type": "process",
    "capability": "local_model_runtime",
    "confidence": "medium",
    "match_mode": "contains",
    "pattern": "gpt4all",
    "platform": "any",
    "provider_id": "gpt4all"
  },
  {
    "artifact_id": "proc-jan-001",
    "artifact_type": "process",
    "capability": "local_model_runtime",
    "confidence": "medium",
    "match_mode": "exact",
    "pattern": "jan",
    "platform": "any",
    "provider_id": "jan"
  },
  {
    "artifact_id": "proc-kobold-001",
    "artifact_type": "process",
    "capability": "local_model_runtime",
    "confidence": "high",
    "match_mode": "contains",
    "pattern": "koboldcpp",
    "platform": "any",
    "provider_id": "koboldcpp"
  },
  {
    "artifact_id": "proc-llamacpp-001",
    "artifact_type": "process",
    "capability": "local_model_runtime",
    "confidence": "high",
    "match_mode": "exact",
    "pattern": "llama-server",
    "platform": "any",
    "provider_id": "llamacpp"
  },
  {
    "artifact_id": "proc-llamacpp-002",
    "artifact_type": "process",
    "capability": "local_model_runtime",
    "confidence": "high",
    "match_mode": "exact",
    "pattern": "llama-cli",
    "platform": "any",
    "provider_id": "llamacpp"
  },
  {
    "artifact_id": "proc-lmstudio-001",
    "artifact_type": "process",
    "capability": "local_model_runtime",
    "confidence": "high",
    "match_mode": "exact",
    "pattern": "LM Studio.exe",
    "platform": "windows",
    "provider_id": "lmstudio"
  },
  {
    "artifact_id": "proc-localai-001",
    "artifact_type": "process",
    "capability": "local_model_runtime",
    "confidence": "medium",
    "match_mode": "contains",
    "pattern": "local-ai",
    "platform": "any",
    "provider_id": "localai"
  },
  {
    "artifact_id": "proc-ollama-001",
    "artifact_type": "process",
    "capability": "local_model_runtime",
    "confidence": "high",
    "match_mode": "exact",
    "pattern": "ollama",
    "platform": "any",
    "provider_id": "ollama"
  },
  {
    "artifact_id": "proc-vllm-001",
    "artifact_type": "command_line",
    "capability": "local_model_runtime",
    "confidence": "high",
    "match_mode": "contains",
    "pattern": "vllm.entrypoints",
    "platform": "any",
    "provider_id": "vllm"
  }
]
'@
$Catalog = @($CatalogJson | ConvertFrom-Json)
$BrowserCatalogJson = @'
[
  {
    "browser": "chromium-family",
    "extension_id": "camppjleccjaphfdbohjdohecfnoikec",
    "extension_name": "Merlin AI",
    "provider_id": "merlin"
  },
  {
    "browser": "chromium-family",
    "extension_id": "difoiogjjojoaoomphldepapgpbgkhkb",
    "extension_name": "Sider AI",
    "provider_id": "sider"
  },
  {
    "browser": "chromium-family",
    "extension_id": "iidnbdjijdkbmajdffnidomddglmieko",
    "extension_name": "QuillBot AI Writing Assistant",
    "provider_id": "quillbot"
  },
  {
    "browser": "chromium-family",
    "extension_id": "kbfnbcaeplbcioakkpcpgfkobkghlhen",
    "extension_name": "Grammarly AI Writing Assistant",
    "provider_id": "grammarly"
  }
]
'@
$BrowserExtensionCatalog = @($BrowserCatalogJson | ConvertFrom-Json)

function Get-IsoTimestamp {
    return [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
}

function Get-Architecture {
    if (-not [string]::IsNullOrWhiteSpace($env:PROCESSOR_ARCHITECTURE)) {
        return [string]$env:PROCESSOR_ARCHITECTURE
    }
    try {
        return [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    } catch {
        return 'unknown'
    }
}

function New-ObservationDocument {
    return [ordered]@{
        schema_version = '1.0'
        observation_id = ([Guid]::NewGuid().ToString())
        collected_at = Get-IsoTimestamp
        collector = [ordered]@{
            name = $CollectorName
            version = $CollectorVersion
            partial = $false
            errors = [object[]]@()
        }
        device = [ordered]@{
            hostname = [Environment]::MachineName
            os_family = 'windows'
            os_version = [Environment]::OSVersion.VersionString
            architecture = Get-Architecture
        }
        scope = [object[]]@('processes', 'known_paths', 'browser_extensions', 'installed_software')
        safety = [ordered]@{
            content_collected = $false
            raw_command_line_collected = $false
            environment_values_collected = $false
            network_requests_made = $false
            full_disk_search_performed = $false
            symlinks_followed = $false
        }
        findings = [object[]]@()
    }
}

$Document = New-ObservationDocument

function Add-PartialError {
    param([Parameter(Mandatory = $true)][string]$Operation, [Parameter(Mandatory = $true)][System.Exception]$Exception)
    $script:Document.collector.partial = $true
    if ($script:Document.collector.errors.Count -lt 100) {
        $safeMessage = '{0}:{1}' -f $Operation, $Exception.GetType().Name
        $script:Document.collector.errors += $safeMessage.Substring(0, [Math]::Min(200, $safeMessage.Length))
    }
}

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)]$Indicator,
        [AllowNull()][string]$SubjectUser,
        [Parameter(Mandatory = $true)][hashtable]$Attributes
    )
    if ($script:Document.findings.Count -ge $MaxFindings) {
        if (-not $script:Document.collector.partial) {
            Add-PartialError -Operation 'finding_limit' -Exception ([InvalidOperationException]::new('limit'))
        }
        return
    }
    $evidenceLevel = if ($Category -eq 'process') { 3 } else { 2 }
    $finding = [ordered]@{
        finding_id = ([Guid]::NewGuid().ToString())
        observed_at = Get-IsoTimestamp
        category = $Category
        indicator_id = [string]$Indicator.artifact_id
        provider_id = [string]$Indicator.provider_id
        capability = [string]$Indicator.capability
        confidence = [string]$Indicator.confidence
        evidence_level = $evidenceLevel
        subject_user = $SubjectUser
        attributes = $Attributes
    }
    $script:Document.findings += $finding
}

function Test-IndicatorMatch {
    param([AllowNull()][string]$Value, [Parameter(Mandatory = $true)]$Indicator)
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    switch ([string]$Indicator.match_mode) {
        'exact' { return $Value.Equals([string]$Indicator.pattern, [StringComparison]::OrdinalIgnoreCase) }
        'contains' { return $Value.IndexOf([string]$Indicator.pattern, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
        'suffix' { return $Value.EndsWith([string]$Indicator.pattern, [StringComparison]::OrdinalIgnoreCase) }
        default { return $false }
    }
}

function Test-SafePath {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    try {
        $item = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
        return (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
    } catch [System.Management.Automation.ItemNotFoundException] {
        return $false
    } catch [System.Management.Automation.DriveNotFoundException] {
        return $false
    } catch [System.UnauthorizedAccessException] {
        return $false
    }
}

function Get-TokenizedPath {
    param([Parameter(Mandatory = $true)][string]$LiteralPath, [AllowNull()][string]$HomePath)
    if ($HomePath -and $LiteralPath.StartsWith($HomePath, [StringComparison]::OrdinalIgnoreCase)) {
        return '{user_home}' + $LiteralPath.Substring($HomePath.Length).Replace('\', '/')
    }
    return $LiteralPath.Replace('\', '/')
}

function New-SyntheticIndicator {
    param([string]$ArtifactId, [string]$ProviderId, [string]$Capability, [string]$Confidence = 'medium')
    return [pscustomobject]@{
        artifact_id = $ArtifactId
        provider_id = $ProviderId
        capability = $Capability
        confidence = $Confidence
    }
}

function Collect-Processes {
    $processIndicators = @($Catalog | Where-Object {
        $_.artifact_type -eq 'process' -and $_.platform -in @('any', 'windows')
    })
    $argumentIndicators = @($Catalog | Where-Object {
        $_.artifact_type -eq 'command_line' -and $_.platform -in @('any', 'windows')
    })
    try {
        foreach ($process in @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)) {
            $seen = @{}
            foreach ($indicator in $processIndicators) {
                if ((Test-IndicatorMatch -Value ([string]$process.Name) -Indicator $indicator) -and -not $seen.ContainsKey($indicator.artifact_id)) {
                    Add-Finding -Category 'process' -Indicator $indicator -SubjectUser $null -Attributes @{
                        pid = [int64]$process.ProcessId
                        process_name = [string]$process.Name
                        match_basis = 'process_name'
                    }
                    $seen[$indicator.artifact_id] = $true
                }
            }
            $argumentsEvaluatedLocally = [string]$process.CommandLine
            foreach ($indicator in $argumentIndicators) {
                if ((Test-IndicatorMatch -Value $argumentsEvaluatedLocally -Indicator $indicator) -and -not $seen.ContainsKey($indicator.artifact_id)) {
                    Add-Finding -Category 'process' -Indicator $indicator -SubjectUser $null -Attributes @{
                        pid = [int64]$process.ProcessId
                        process_name = [string]$process.Name
                        match_basis = 'arguments_local_only'
                    }
                    $seen[$indicator.artifact_id] = $true
                }
            }
        }
    } catch {
        Add-PartialError -Operation 'process_inventory' -Exception $_.Exception
    }
}

function Get-UserProfiles {
    $profiles = @()
    try {
        foreach ($profile in @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object {
            -not $_.Special -and $_.LocalPath
        } | Select-Object -First 256)) {
            if (Test-SafePath -LiteralPath ([string]$profile.LocalPath)) {
                $profiles += [pscustomobject]@{
                    User = Split-Path -Path ([string]$profile.LocalPath) -Leaf
                    Home = [string]$profile.LocalPath
                }
            }
        }
    } catch {
        Add-PartialError -Operation 'profile_inventory' -Exception $_.Exception
    }
    return @($profiles)
}

function Collect-KnownPaths {
    param([object[]]$Profiles)
    $modelIndicator = $Catalog | Where-Object { $_.artifact_id -eq 'file-model-001' } | Select-Object -First 1
    $mcp = @{}
    foreach ($item in @($Catalog | Where-Object { $_.artifact_type -eq 'config_file' })) {
        $mcp[[string]$item.pattern.ToLowerInvariant()] = $item
    }
    $relativePaths = @(
        [pscustomobject]@{ Relative = '.ollama\models'; Category = 'model_directory'; Indicator = $modelIndicator },
        [pscustomobject]@{ Relative = '.cache\lm-studio\models'; Category = 'model_directory'; Indicator = $modelIndicator },
        [pscustomobject]@{ Relative = '.lmstudio\models'; Category = 'model_directory'; Indicator = $modelIndicator },
        [pscustomobject]@{ Relative = '.cursor\mcp.json'; Category = 'config_file'; Indicator = $mcp['mcp.json'] },
        [pscustomobject]@{ Relative = '.mcp.json'; Category = 'config_file'; Indicator = $mcp['.mcp.json'] },
        [pscustomobject]@{ Relative = 'AppData\Roaming\Claude\claude_desktop_config.json'; Category = 'config_file'; Indicator = $mcp['claude_desktop_config.json'] },
        [pscustomobject]@{ Relative = 'AppData\Roaming\Cursor\User\globalStorage\mcp.json'; Category = 'config_file'; Indicator = $mcp['mcp.json'] },
        [pscustomobject]@{ Relative = 'AppData\Local\LM Studio\models'; Category = 'model_directory'; Indicator = $modelIndicator }
    )
    foreach ($profile in $Profiles) {
        foreach ($entry in $relativePaths) {
            $candidate = Join-Path -Path $profile.Home -ChildPath $entry.Relative
            if (Test-SafePath -LiteralPath $candidate) {
                Add-Finding -Category $entry.Category -Indicator $entry.Indicator -SubjectUser $profile.User -Attributes @{
                    location = Get-TokenizedPath -LiteralPath $candidate -HomePath $profile.Home
                    presence_only = $true
                }
            }
        }
    }
}

function Collect-InstalledSoftware {
    $nameIndicators = @(
        [pscustomobject]@{ Pattern = 'Ollama'; Indicator = (New-SyntheticIndicator 'software-ollama' 'ollama' 'local_model_runtime' 'high') },
        [pscustomobject]@{ Pattern = 'LM Studio'; Indicator = (New-SyntheticIndicator 'software-lmstudio' 'lmstudio' 'local_model_runtime' 'high') },
        [pscustomobject]@{ Pattern = 'GPT4All'; Indicator = (New-SyntheticIndicator 'software-gpt4all' 'gpt4all' 'local_model_runtime' 'high') },
        [pscustomobject]@{ Pattern = 'Jan'; Indicator = (New-SyntheticIndicator 'software-jan' 'jan' 'local_model_runtime') },
        [pscustomobject]@{ Pattern = 'Claude'; Indicator = (New-SyntheticIndicator 'software-claude' 'anthropic' 'generative_ai_client') },
        [pscustomobject]@{ Pattern = 'ChatGPT'; Indicator = (New-SyntheticIndicator 'software-chatgpt' 'openai' 'generative_ai_client') },
        [pscustomobject]@{ Pattern = 'Cursor'; Indicator = (New-SyntheticIndicator 'software-cursor' 'cursor' 'ai_coding_assistant') },
        [pscustomobject]@{ Pattern = 'Windsurf'; Indicator = (New-SyntheticIndicator 'software-windsurf' 'windsurf' 'ai_coding_assistant') }
    )
    $registryPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    try {
        foreach ($software in @(Get-ItemProperty -Path $registryPaths -ErrorAction SilentlyContinue)) {
            # Uninstall registry entries are not schema-consistent. Under StrictMode,
            # direct access to an absent DisplayName or DisplayVersion property throws.
            $displayNameProperty = $software.PSObject.Properties['DisplayName']
            if ($null -eq $displayNameProperty) { continue }
            $displayName = [string]$displayNameProperty.Value
            if ([string]::IsNullOrWhiteSpace($displayName)) { continue }

            $displayVersionProperty = $software.PSObject.Properties['DisplayVersion']
            $displayVersion = if ($null -eq $displayVersionProperty) { '' } else { [string]$displayVersionProperty.Value }
            foreach ($mapping in $nameIndicators) {
                if ($displayName.IndexOf($mapping.Pattern, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    Add-Finding -Category 'software' -Indicator $mapping.Indicator -SubjectUser $null -Attributes @{
                        display_name = $displayName
                        version = $displayVersion
                        inventory_source = 'uninstall_registry'
                    }
                }
            }
        }
    } catch {
        Add-PartialError -Operation 'software_inventory' -Exception $_.Exception
    }
}

function Collect-BrowserExtensions {
    param([object[]]$Profiles)
    $knownExtensions = @{}
    foreach ($known in $BrowserExtensionCatalog) { $knownExtensions[[string]$known.extension_id] = $known }
    $browserRoots = @(
        [pscustomobject]@{ Browser = 'chrome'; Relative = 'AppData\Local\Google\Chrome\User Data' },
        [pscustomobject]@{ Browser = 'edge'; Relative = 'AppData\Local\Microsoft\Edge\User Data' },
        [pscustomobject]@{ Browser = 'brave'; Relative = 'AppData\Local\BraveSoftware\Brave-Browser\User Data' }
    )
    foreach ($profile in $Profiles) {
        foreach ($browser in $browserRoots) {
            $root = Join-Path -Path $profile.Home -ChildPath $browser.Relative
            if (-not (Test-SafePath -LiteralPath $root)) { continue }
            try {
                foreach ($browserProfile in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop | Select-Object -First 128)) {
                    if (($browserProfile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    $extensionRoot = Join-Path -Path $browserProfile.FullName -ChildPath 'Extensions'
                    if (-not (Test-SafePath -LiteralPath $extensionRoot)) { continue }
                    foreach ($extension in @(Get-ChildItem -LiteralPath $extensionRoot -Directory -Force -ErrorAction Stop | Select-Object -First 1000)) {
                        $known = $knownExtensions[[string]$extension.Name]
                        if (
                            $null -ne $known -and
                            $known.browser -in @($browser.Browser, 'chromium-family') -and
                            $extension.Name -match $ExtensionIdPattern -and
                            (($extension.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
                        ) {
                            $indicator = New-SyntheticIndicator ('browser-' + $extension.Name) $known.provider_id 'ai_browser_extension' 'high'
                            Add-Finding -Category 'browser_extension' -Indicator $indicator -SubjectUser $profile.User -Attributes @{
                                browser = $browser.Browser
                                profile = $browserProfile.Name
                                extension_id = $extension.Name
                                extension_name = $known.extension_name
                            }
                        }
                    }
                }
            } catch {
                Add-PartialError -Operation ('browser_inventory_' + $browser.Browser) -Exception $_.Exception
            }
        }
    }
}

try {
    if (-not $SelfTest) {
        if ($env:OS -ne 'Windows_NT') { throw [PlatformNotSupportedException]::new('Windows is required') }
        Collect-Processes
        $profiles = @(Get-UserProfiles)
        Collect-KnownPaths -Profiles $profiles
        Collect-InstalledSoftware
        Collect-BrowserExtensions -Profiles $profiles
    }
    $Document | ConvertTo-Json -Depth 8 -Compress
    if ($Document.collector.partial) { exit 2 }
    exit 0
} catch {
    $fatalType = $_.Exception.GetType().Name
    [ordered]@{ error = ('fatal:' + $fatalType) } | ConvertTo-Json -Compress | Write-Error
    exit 1
}
