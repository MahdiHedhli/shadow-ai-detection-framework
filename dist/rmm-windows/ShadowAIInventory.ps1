#Requires -Version 5.1
<#
.SYNOPSIS
Read-only Shadow AI inventory collector for Windows RMM execution.

.DESCRIPTION
Emits metadata only. Command lines and bounded browser-history databases are
evaluated locally and are never emitted. No prompt, response, configuration,
environment value, full URL, page title, or file content is emitted.

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
$CollectorVersion = '0.5.2'
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
    "extension_id": "ejcfepkfckglbgocfkanmcdngdijcgld",
    "extension_name": "ChatGPT search",
    "provider_id": "openai"
  },
  {
    "browser": "chromium-family",
    "extension_id": "fcoeoabgfenejglbffodgkkbkcdhcgfn",
    "extension_name": "Claude",
    "provider_id": "anthropic"
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
$BrowserNameCatalogJson = @'
[
  {
    "confidence": "medium",
    "pattern": "Microsoft Copilot",
    "provider_id": "microsoft"
  },
  {
    "confidence": "medium",
    "pattern": "GitHub Copilot",
    "provider_id": "github"
  },
  {
    "confidence": "medium",
    "pattern": "Character.AI",
    "provider_id": "characterai"
  },
  {
    "confidence": "medium",
    "pattern": "Blackbox AI",
    "provider_id": "blackbox"
  },
  {
    "confidence": "medium",
    "pattern": "Compose AI",
    "provider_id": "compose-ai"
  },
  {
    "confidence": "medium",
    "pattern": "Perplexity",
    "provider_id": "perplexity"
  },
  {
    "confidence": "medium",
    "pattern": "Writesonic",
    "provider_id": "writesonic"
  },
  {
    "confidence": "medium",
    "pattern": "ChatSonic",
    "provider_id": "writesonic"
  },
  {
    "confidence": "medium",
    "pattern": "Consensus",
    "provider_id": "consensus"
  },
  {
    "confidence": "medium",
    "pattern": "Grammarly",
    "provider_id": "grammarly"
  },
  {
    "confidence": "medium",
    "pattern": "Amazon Q",
    "provider_id": "amazon"
  },
  {
    "confidence": "medium",
    "pattern": "DeepSeek",
    "provider_id": "deepseek"
  },
  {
    "confidence": "medium",
    "pattern": "QuillBot",
    "provider_id": "quillbot"
  },
  {
    "confidence": "medium",
    "pattern": "SciSpace",
    "provider_id": "scispace"
  },
  {
    "confidence": "medium",
    "pattern": "Windsurf",
    "provider_id": "windsurf"
  },
  {
    "confidence": "medium",
    "pattern": "ChatGPT",
    "provider_id": "openai"
  },
  {
    "confidence": "medium",
    "pattern": "Codeium",
    "provider_id": "codeium"
  },
  {
    "confidence": "medium",
    "pattern": "Mistral",
    "provider_id": "mistral"
  },
  {
    "confidence": "medium",
    "pattern": "Tabnine",
    "provider_id": "tabnine"
  },
  {
    "confidence": "medium",
    "pattern": "Claude",
    "provider_id": "anthropic"
  },
  {
    "confidence": "medium",
    "pattern": "Gemini",
    "provider_id": "google"
  },
  {
    "confidence": "medium",
    "pattern": "Jasper",
    "provider_id": "jasper"
  },
  {
    "confidence": "medium",
    "pattern": "Merlin",
    "provider_id": "merlin"
  },
  {
    "confidence": "medium",
    "pattern": "Monica",
    "provider_id": "monica"
  },
  {
    "confidence": "medium",
    "pattern": "OpenAI",
    "provider_id": "openai"
  },
  {
    "confidence": "medium",
    "pattern": "HARPA",
    "provider_id": "harpa"
  },
  {
    "confidence": "medium",
    "pattern": "MaxAI",
    "provider_id": "maxai"
  },
  {
    "confidence": "medium",
    "pattern": "Phind",
    "provider_id": "phind"
  },
  {
    "confidence": "medium",
    "pattern": "Sider",
    "provider_id": "sider"
  },
  {
    "confidence": "medium",
    "pattern": "Grok",
    "provider_id": "xai"
  }
]
'@
$BrowserExtensionNameCatalog = @($BrowserNameCatalogJson | ConvertFrom-Json)
$DomainCatalogJson = @'
[
  {
    "artifact_id": "net-anthropic-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "claude.ai",
    "indicator_type": "registered_domain",
    "provider_id": "anthropic"
  },
  {
    "artifact_id": "net-anthropic-002",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "anthropic.com",
    "indicator_type": "registered_domain",
    "provider_id": "anthropic"
  },
  {
    "artifact_id": "net-character-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "character.ai",
    "indicator_type": "registered_domain",
    "provider_id": "characterai"
  },
  {
    "artifact_id": "net-codeium-001",
    "capability": "code_assistant",
    "confidence": "low",
    "domain": "codeium.com",
    "indicator_type": "registered_domain",
    "provider_id": "codeium"
  },
  {
    "artifact_id": "net-cohere-001",
    "capability": "model_provider",
    "confidence": "low",
    "domain": "cohere.com",
    "indicator_type": "registered_domain",
    "provider_id": "cohere"
  },
  {
    "artifact_id": "net-cohere-002",
    "capability": "model_provider",
    "confidence": "low",
    "domain": "cohere.ai",
    "indicator_type": "registered_domain",
    "provider_id": "cohere"
  },
  {
    "artifact_id": "net-cursor-001",
    "capability": "code_assistant",
    "confidence": "low",
    "domain": "cursor.com",
    "indicator_type": "registered_domain",
    "provider_id": "cursor"
  },
  {
    "artifact_id": "net-cursor-002",
    "capability": "code_assistant",
    "confidence": "low",
    "domain": "cursor.sh",
    "indicator_type": "registered_domain",
    "provider_id": "cursor"
  },
  {
    "artifact_id": "net-deepseek-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "deepseek.com",
    "indicator_type": "registered_domain",
    "provider_id": "deepseek"
  },
  {
    "artifact_id": "net-elevenlabs-001",
    "capability": "audio_generation",
    "confidence": "low",
    "domain": "elevenlabs.io",
    "indicator_type": "registered_domain",
    "provider_id": "elevenlabs"
  },
  {
    "artifact_id": "net-github-001",
    "capability": "code_assistant",
    "confidence": "low",
    "domain": "githubcopilot.com",
    "indicator_type": "registered_domain",
    "provider_id": "github"
  },
  {
    "artifact_id": "net-google-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "gemini.google.com",
    "indicator_type": "fqdn",
    "provider_id": "google"
  },
  {
    "artifact_id": "net-google-002",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "aistudio.google.com",
    "indicator_type": "fqdn",
    "provider_id": "google"
  },
  {
    "artifact_id": "net-google-003",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "generativelanguage.googleapis.com",
    "indicator_type": "fqdn",
    "provider_id": "google"
  },
  {
    "artifact_id": "net-groq-001",
    "capability": "model_provider",
    "confidence": "low",
    "domain": "groq.com",
    "indicator_type": "registered_domain",
    "provider_id": "groq"
  },
  {
    "artifact_id": "net-huggingface-001",
    "capability": "model_platform",
    "confidence": "low",
    "domain": "huggingface.co",
    "indicator_type": "registered_domain",
    "provider_id": "huggingface"
  },
  {
    "artifact_id": "net-lmstudio-001",
    "capability": "local_model_tooling",
    "confidence": "low",
    "domain": "lmstudio.ai",
    "indicator_type": "registered_domain",
    "provider_id": "lmstudio"
  },
  {
    "artifact_id": "net-meta-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "meta.ai",
    "indicator_type": "registered_domain",
    "provider_id": "meta"
  },
  {
    "artifact_id": "net-microsoft-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "copilot.microsoft.com",
    "indicator_type": "fqdn",
    "provider_id": "microsoft"
  },
  {
    "artifact_id": "net-midjourney-001",
    "capability": "image_generation",
    "confidence": "low",
    "domain": "midjourney.com",
    "indicator_type": "registered_domain",
    "provider_id": "midjourney"
  },
  {
    "artifact_id": "net-mistral-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "mistral.ai",
    "indicator_type": "registered_domain",
    "provider_id": "mistral"
  },
  {
    "artifact_id": "net-ollama-001",
    "capability": "local_model_tooling",
    "confidence": "low",
    "domain": "ollama.com",
    "indicator_type": "registered_domain",
    "provider_id": "ollama"
  },
  {
    "artifact_id": "net-openai-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "openai.com",
    "indicator_type": "registered_domain",
    "provider_id": "openai"
  },
  {
    "artifact_id": "net-openai-002",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "chatgpt.com",
    "indicator_type": "registered_domain",
    "provider_id": "openai"
  },
  {
    "artifact_id": "net-openai-003",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "oaiusercontent.com",
    "indicator_type": "registered_domain",
    "provider_id": "openai"
  },
  {
    "artifact_id": "net-openrouter-001",
    "capability": "model_gateway",
    "confidence": "low",
    "domain": "openrouter.ai",
    "indicator_type": "registered_domain",
    "provider_id": "openrouter"
  },
  {
    "artifact_id": "net-perplexity-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "perplexity.ai",
    "indicator_type": "registered_domain",
    "provider_id": "perplexity"
  },
  {
    "artifact_id": "net-poe-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "poe.com",
    "indicator_type": "registered_domain",
    "provider_id": "poe"
  },
  {
    "artifact_id": "net-replicate-001",
    "capability": "model_platform",
    "confidence": "low",
    "domain": "replicate.com",
    "indicator_type": "registered_domain",
    "provider_id": "replicate"
  },
  {
    "artifact_id": "net-runway-001",
    "capability": "video_generation",
    "confidence": "low",
    "domain": "runwayml.com",
    "indicator_type": "registered_domain",
    "provider_id": "runway"
  },
  {
    "artifact_id": "net-stability-001",
    "capability": "image_generation",
    "confidence": "low",
    "domain": "stability.ai",
    "indicator_type": "registered_domain",
    "provider_id": "stability"
  },
  {
    "artifact_id": "net-together-001",
    "capability": "model_provider",
    "confidence": "low",
    "domain": "together.ai",
    "indicator_type": "registered_domain",
    "provider_id": "together"
  },
  {
    "artifact_id": "net-together-002",
    "capability": "model_provider",
    "confidence": "low",
    "domain": "together.xyz",
    "indicator_type": "registered_domain",
    "provider_id": "together"
  },
  {
    "artifact_id": "net-windsurf-001",
    "capability": "code_assistant",
    "confidence": "low",
    "domain": "windsurf.com",
    "indicator_type": "registered_domain",
    "provider_id": "windsurf"
  },
  {
    "artifact_id": "net-xai-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "x.ai",
    "indicator_type": "registered_domain",
    "provider_id": "xai"
  },
  {
    "artifact_id": "net-xai-002",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "grok.com",
    "indicator_type": "registered_domain",
    "provider_id": "xai"
  }
]
'@
$DomainCatalog = @($DomainCatalogJson | ConvertFrom-Json)
$MaxHistoryBytesPerProfile = 268435456
$MaxManifestBytes = 1048576

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
        scope = [object[]]@('processes', 'known_paths', 'browser_extensions', 'browser_history', 'installed_software')
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
    $evidenceLevel = if ($Category -eq 'process') { 3 } elseif ($Category -eq 'browser_history') { 1 } else { 2 }
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
                    Sid = [string]$profile.SID
                }
            }
        }
    } catch {
        Add-PartialError -Operation 'profile_inventory' -Exception $_.Exception
    }
    return @($profiles)
}

function Collect-KnownPaths {
    param([AllowEmptyCollection()][object[]]$Profiles)
    # These bounded path probes have fixed semantics. Constructing their
    # indicators directly avoids a runtime catalog lookup becoming null while
    # preserving the stable catalog IDs used by downstream analytics.
    $modelIndicator = New-SyntheticIndicator 'file-model-001' 'generic' 'model_weight' 'high'
    $mcpIndicator = New-SyntheticIndicator 'file-mcp-001' 'mcp' 'mcp_configuration' 'medium'
    $claudeMcpIndicator = New-SyntheticIndicator 'file-mcp-002' 'mcp' 'mcp_configuration' 'high'
    $dotMcpIndicator = New-SyntheticIndicator 'file-mcp-003' 'mcp' 'mcp_configuration' 'medium'
    $relativePaths = @(
        [pscustomobject]@{ Relative = '.ollama\models'; Category = 'model_directory'; Indicator = $modelIndicator },
        [pscustomobject]@{ Relative = '.cache\lm-studio\models'; Category = 'model_directory'; Indicator = $modelIndicator },
        [pscustomobject]@{ Relative = '.lmstudio\models'; Category = 'model_directory'; Indicator = $modelIndicator },
        [pscustomobject]@{ Relative = '.cursor\mcp.json'; Category = 'config_file'; Indicator = $mcpIndicator },
        [pscustomobject]@{ Relative = '.mcp.json'; Category = 'config_file'; Indicator = $dotMcpIndicator },
        [pscustomobject]@{ Relative = 'AppData\Roaming\Claude\claude_desktop_config.json'; Category = 'config_file'; Indicator = $claudeMcpIndicator },
        [pscustomobject]@{ Relative = 'AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json'; Category = 'config_file'; Indicator = $claudeMcpIndicator },
        [pscustomobject]@{ Relative = 'AppData\Roaming\Cursor\User\globalStorage\mcp.json'; Category = 'config_file'; Indicator = $mcpIndicator },
        [pscustomobject]@{ Relative = 'AppData\Roaming\Code\User\mcp.json'; Category = 'config_file'; Indicator = $mcpIndicator },
        [pscustomobject]@{ Relative = 'AppData\Roaming\Code - Insiders\User\mcp.json'; Category = 'config_file'; Indicator = $mcpIndicator },
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

function Get-OptionalPropertyValue {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Add-SoftwareCandidate {
    param(
        [AllowNull()][string]$DisplayName,
        [AllowNull()][string]$Version,
        [Parameter(Mandatory = $true)][string]$InventorySource,
        [AllowNull()][string]$SubjectUser,
        [Parameter(Mandatory = $true)][object[]]$NameIndicators,
        [Parameter(Mandatory = $true)][hashtable]$Seen,
        [hashtable]$ExtraAttributes = @{}
    )
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { return }
    foreach ($mapping in $NameIndicators) {
        if ($DisplayName.IndexOf($mapping.Pattern, [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        $dedupeKey = '{0}|{1}|{2}|{3}' -f $mapping.Indicator.artifact_id, $InventorySource, [string]$SubjectUser, $DisplayName
        if ($Seen.ContainsKey($dedupeKey)) { continue }
        $attributes = @{
            display_name = $DisplayName
            version = if ($null -eq $Version) { '' } else { $Version }
            inventory_source = $InventorySource
        }
        foreach ($entry in $ExtraAttributes.GetEnumerator()) {
            $attributes[[string]$entry.Key] = $entry.Value
        }
        Add-Finding -Category 'software' -Indicator $mapping.Indicator -SubjectUser $SubjectUser -Attributes $attributes
        $Seen[$dedupeKey] = $true
    }
}

function Collect-UninstallRegistryPath {
    param(
        [Parameter(Mandatory = $true)][string]$RegistryPath,
        [Parameter(Mandatory = $true)][string]$InventorySource,
        [Parameter(Mandatory = $true)][string]$Operation,
        [AllowNull()][string]$SubjectUser,
        [Parameter(Mandatory = $true)][object[]]$NameIndicators,
        [Parameter(Mandatory = $true)][hashtable]$Seen
    )
    try {
        foreach ($software in @(Get-ItemProperty -Path $RegistryPath -ErrorAction Stop)) {
            $displayName = [string](Get-OptionalPropertyValue -InputObject $software -Name 'DisplayName')
            if ([string]::IsNullOrWhiteSpace($displayName)) { continue }
            $displayVersion = [string](Get-OptionalPropertyValue -InputObject $software -Name 'DisplayVersion')
            Add-SoftwareCandidate -DisplayName $displayName -Version $displayVersion -InventorySource $InventorySource -SubjectUser $SubjectUser -NameIndicators $NameIndicators -Seen $Seen
        }
    } catch [System.Management.Automation.ItemNotFoundException] {
        return
    } catch [System.Management.Automation.DriveNotFoundException] {
        return
    } catch {
        Add-PartialError -Operation $Operation -Exception $_.Exception
    }
}

function Collect-AppxSoftware {
    param(
        [Parameter(Mandatory = $true)][object[]]$NameIndicators,
        [Parameter(Mandatory = $true)][hashtable]$Seen,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Profiles
    )
    try {
        if ($null -eq (Get-Command -Name 'Get-AppxPackage' -ErrorAction SilentlyContinue)) {
            throw [InvalidOperationException]::new('Get-AppxPackage unavailable')
        }
        foreach ($package in @(Get-AppxPackage -AllUsers -ErrorAction Stop)) {
            $packageName = [string](Get-OptionalPropertyValue -InputObject $package -Name 'Name')
            $packageVersion = [string](Get-OptionalPropertyValue -InputObject $package -Name 'Version')
            $matchedUsers = @()
            foreach ($packageUser in @((Get-OptionalPropertyValue -InputObject $package -Name 'PackageUserInformation'))) {
                if ($null -eq $packageUser) { continue }
                $packageSid = [string](Get-OptionalPropertyValue -InputObject $packageUser -Name 'UserSecurityId')
                $installState = [string](Get-OptionalPropertyValue -InputObject $packageUser -Name 'InstallState')
                if ($installState -and $installState -ne 'Installed') { continue }
                foreach ($profile in $Profiles) {
                    if ($packageSid -and $packageSid.Equals([string]$profile.Sid, [StringComparison]::OrdinalIgnoreCase)) {
                        $matchedUsers += [string]$profile.User
                    }
                }
            }
            if ($matchedUsers.Count -eq 0) {
                Add-SoftwareCandidate -DisplayName $packageName -Version $packageVersion -InventorySource 'appx_all_users' -SubjectUser $null -NameIndicators $NameIndicators -Seen $Seen -ExtraAttributes @{
                    package_name = $packageName
                }
                continue
            }
            foreach ($matchedUser in @($matchedUsers | Select-Object -Unique)) {
                Add-SoftwareCandidate -DisplayName $packageName -Version $packageVersion -InventorySource 'appx_all_users' -SubjectUser $matchedUser -NameIndicators $NameIndicators -Seen $Seen -ExtraAttributes @{
                    package_name = $packageName
                }
            }
        }
    } catch {
        Add-PartialError -Operation 'appx_inventory' -Exception $_.Exception
    }
}

function Collect-KnownApplicationPaths {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Profiles,
        [Parameter(Mandatory = $true)][object[]]$NameIndicators,
        [Parameter(Mandatory = $true)][hashtable]$Seen
    )
    foreach ($profile in $Profiles) {
        $claudeRoot = Join-Path -Path $profile.Home -ChildPath 'AppData\Local\AnthropicClaude'
        $candidates = @((Join-Path -Path $claudeRoot -ChildPath 'claude.exe'))
        if (Test-SafePath -LiteralPath $claudeRoot) {
            try {
                foreach ($versionDirectory in @(Get-ChildItem -LiteralPath $claudeRoot -Directory -Force -ErrorAction Stop | Where-Object {
                    $_.Name -like 'app-*' -and (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
                } | Select-Object -First 128)) {
                    $candidates += Join-Path -Path $versionDirectory.FullName -ChildPath 'claude.exe'
                }
            } catch {
                Add-PartialError -Operation 'known_application_paths' -Exception $_.Exception
            }
        }
        foreach ($candidate in $candidates) {
            if (-not (Test-SafePath -LiteralPath $candidate)) { continue }
            Add-SoftwareCandidate -DisplayName 'Claude Desktop' -Version '' -InventorySource 'known_path' -SubjectUser $profile.User -NameIndicators $NameIndicators -Seen $Seen -ExtraAttributes @{
                location = Get-TokenizedPath -LiteralPath $candidate -HomePath $profile.Home
                presence_only = $true
            }
            break
        }
    }
}

function Collect-InstalledSoftware {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Profiles)
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
    $seen = @{}
    foreach ($registrySource in @(
        [pscustomobject]@{ Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'; Source = 'uninstall_registry_machine'; Operation = 'software_registry_machine' },
        [pscustomobject]@{ Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Source = 'uninstall_registry_machine'; Operation = 'software_registry_machine_wow6432' },
        [pscustomobject]@{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'; Source = 'uninstall_registry_current_user'; Operation = 'software_registry_current_user' }
    )) {
        Collect-UninstallRegistryPath -RegistryPath $registrySource.Path -InventorySource $registrySource.Source -Operation $registrySource.Operation -SubjectUser $null -NameIndicators $nameIndicators -Seen $seen
    }

    # Read only hives Windows already has loaded. Loading offline NTUSER.DAT files
    # would mutate registry state and is intentionally out of scope.
    foreach ($profile in $Profiles) {
        if ([string]::IsNullOrWhiteSpace($profile.Sid)) { continue }
        $loadedUserPath = 'Registry::HKEY_USERS\{0}\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -f $profile.Sid
        Collect-UninstallRegistryPath -RegistryPath $loadedUserPath -InventorySource 'uninstall_registry_loaded_user' -Operation 'software_registry_loaded_user' -SubjectUser $profile.User -NameIndicators $nameIndicators -Seen $seen
    }

    Collect-AppxSoftware -NameIndicators $nameIndicators -Seen $seen -Profiles $Profiles
    Collect-KnownApplicationPaths -Profiles $Profiles -NameIndicators $nameIndicators -Seen $seen
}

function Get-HistoryDomainMatchers {
    $matchers = @()
    foreach ($item in $DomainCatalog) {
        $escapedDomain = [Regex]::Escape(([string]$item.domain).ToLowerInvariant())
        $hostPattern = if ($item.indicator_type -eq 'registered_domain') {
            '(?:[a-z0-9-]+\.)*' + $escapedDomain
        } else {
            $escapedDomain
        }
        $matchers += [pscustomobject]@{
            Indicator = $item
            Regex = [Regex]::new('(?i)https?://' + $hostPattern + '(?:[:/?#]|$)', [Text.RegularExpressions.RegexOptions]::CultureInvariant)
        }
    }
    return @($matchers)
}

function Find-HistoryDomainMatches {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][object[]]$Matchers
    )
    $foundIndicators = @{}
    $stream = $null
    try {
        $stream = [IO.File]::Open($LiteralPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        if ($stream.Length -gt $MaxHistoryBytesPerProfile) {
            throw [IO.InvalidDataException]::new('history database exceeds per-profile byte limit')
        }
        $buffer = New-Object byte[] 1048576
        $carry = ''
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $text = $carry + [Text.Encoding]::ASCII.GetString($buffer, 0, $read)
            foreach ($matcher in $Matchers) {
                $key = [string]$matcher.Indicator.artifact_id
                if (-not $foundIndicators.ContainsKey($key) -and $matcher.Regex.IsMatch($text)) {
                    $foundIndicators[$key] = $matcher.Indicator
                }
            }
            if ($text.Length -gt 1024) { $carry = $text.Substring($text.Length - 1024) } else { $carry = $text }
        }
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    return @($foundIndicators.Values)
}

function Collect-BrowserHistory {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Profiles)
    $matchers = @(Get-HistoryDomainMatchers)
    $browserRoots = @(
        [pscustomobject]@{ Browser = 'chrome'; Relative = 'AppData\Local\Google\Chrome\User Data'; HistoryName = 'History' },
        [pscustomobject]@{ Browser = 'edge'; Relative = 'AppData\Local\Microsoft\Edge\User Data'; HistoryName = 'History' },
        [pscustomobject]@{ Browser = 'brave'; Relative = 'AppData\Local\BraveSoftware\Brave-Browser\User Data'; HistoryName = 'History' },
        [pscustomobject]@{ Browser = 'firefox'; Relative = 'AppData\Roaming\Mozilla\Firefox\Profiles'; HistoryName = 'places.sqlite' }
    )
    foreach ($profile in $Profiles) {
        foreach ($browser in $browserRoots) {
            $root = Join-Path -Path $profile.Home -ChildPath $browser.Relative
            if (-not (Test-SafePath -LiteralPath $root)) { continue }
            try {
                foreach ($browserProfile in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop | Select-Object -First 128)) {
                    if (($browserProfile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    $historyPath = Join-Path -Path $browserProfile.FullName -ChildPath $browser.HistoryName
                    if (-not (Test-SafePath -LiteralPath $historyPath)) { continue }
                    foreach ($indicator in @(Find-HistoryDomainMatches -LiteralPath $historyPath -Matchers $matchers)) {
                        Add-Finding -Category 'browser_history' -Indicator $indicator -SubjectUser $profile.User -Attributes @{
                            browser = $browser.Browser
                            profile = $browserProfile.Name
                            matched_domain = [string]$indicator.domain
                            match_basis = 'history_database_string_match_local_only'
                            presence_only = $true
                        }
                    }
                }
            } catch {
                Add-PartialError -Operation ('browser_history_' + $browser.Browser) -Exception $_.Exception
            }
        }
    }
}

function Read-BoundedJsonObject {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    if (-not (Test-SafePath -LiteralPath $LiteralPath)) { return $null }
    try {
        $item = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
        if ($item.PSIsContainer -or $item.Length -gt $MaxManifestBytes) { return $null }
        return ([IO.File]::ReadAllText($item.FullName) | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        return $null
    }
}

function Get-SafeExtensionName {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $name = $Value.Trim()
    if ($name.Length -gt 200 -or $name -match '[\x00-\x1f\x7f]') { return $null }
    return $name
}

function Resolve-ChromiumExtensionName {
    param([Parameter(Mandatory = $true)][string]$ExtensionPath)
    try {
        foreach ($versionDirectory in @(Get-ChildItem -LiteralPath $ExtensionPath -Directory -Force -ErrorAction Stop |
            Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 } |
            Sort-Object -Property Name -Descending | Select-Object -First 8)) {
            $manifest = Read-BoundedJsonObject -LiteralPath (Join-Path -Path $versionDirectory.FullName -ChildPath 'manifest.json')
            if ($null -eq $manifest) { continue }
            $name = Get-SafeExtensionName -Value ([string](Get-OptionalPropertyValue -InputObject $manifest -Name 'name'))
            if ($null -eq $name) { continue }
            if ($name -match '^__MSG_([A-Za-z0-9_@]+)__$') {
                $messageKey = $Matches[1]
                $defaultLocale = Get-SafeExtensionName -Value ([string](Get-OptionalPropertyValue -InputObject $manifest -Name 'default_locale'))
                if ($null -eq $defaultLocale -or $defaultLocale -notmatch '^[A-Za-z0-9_-]{2,20}$') { continue }
                $messagesPath = Join-Path -Path $versionDirectory.FullName -ChildPath ('_locales\{0}\messages.json' -f $defaultLocale)
                $messages = Read-BoundedJsonObject -LiteralPath $messagesPath
                if ($null -eq $messages) { continue }
                $messageObject = Get-OptionalPropertyValue -InputObject $messages -Name $messageKey
                if ($null -eq $messageObject) { continue }
                $name = Get-SafeExtensionName -Value ([string](Get-OptionalPropertyValue -InputObject $messageObject -Name 'message'))
            }
            if ($null -ne $name) { return $name }
        }
    } catch {
        return $null
    }
    return $null
}

function Find-ExtensionNameClassification {
    param([AllowNull()][string]$ExtensionName)
    if ([string]::IsNullOrWhiteSpace($ExtensionName)) { return $null }
    foreach ($mapping in $BrowserExtensionNameCatalog) {
        if ($ExtensionName.IndexOf([string]$mapping.pattern, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $mapping
        }
    }
    return $null
}

function Add-ExtensionInventorySummary {
    param(
        [Parameter(Mandatory = $true)][string]$Browser,
        [Parameter(Mandatory = $true)][string]$BrowserProfile,
        [AllowNull()][string]$SubjectUser,
        [Parameter(Mandatory = $true)][int]$InstalledCount,
        [Parameter(Mandatory = $true)][int]$ClassifiedCount
    )
    if ($InstalledCount -le 0) { return }
    $indicator = New-SyntheticIndicator 'browser-extension-inventory' 'generic' 'browser_extension_inventory' 'low'
    Add-Finding -Category 'browser_extension' -Indicator $indicator -SubjectUser $SubjectUser -Attributes @{
        browser = $Browser
        profile = $BrowserProfile
        installed_extension_count = $InstalledCount
        classified_extension_count = $ClassifiedCount
        reporting_scope = 'count_only'
        presence_only = $true
    }
}

function Collect-ChromiumExtensionProfile {
    param(
        [Parameter(Mandatory = $true)][string]$Browser,
        [Parameter(Mandatory = $true)]$BrowserProfile,
        [AllowNull()][string]$SubjectUser,
        [Parameter(Mandatory = $true)][hashtable]$KnownExtensions
    )
    $extensionRoot = Join-Path -Path $BrowserProfile.FullName -ChildPath 'Extensions'
    if (-not (Test-SafePath -LiteralPath $extensionRoot)) { return }
    $installedCount = 0
    $classifiedCount = 0
    foreach ($extension in @(Get-ChildItem -LiteralPath $extensionRoot -Directory -Force -ErrorAction Stop | Select-Object -First 1000)) {
        if (
            $extension.Name -notmatch $ExtensionIdPattern -or
            (($extension.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
        ) { continue }
        $installedCount += 1
        $known = $KnownExtensions[[string]$extension.Name]
        if (
            $null -ne $known -and
            $known.browser -in @($Browser, 'chromium-family')
        ) {
            $indicator = New-SyntheticIndicator ('browser-' + $extension.Name) $known.provider_id 'ai_browser_extension' 'high'
            Add-Finding -Category 'browser_extension' -Indicator $indicator -SubjectUser $SubjectUser -Attributes @{
                browser = $Browser
                profile = $BrowserProfile.Name
                extension_id = $extension.Name
                extension_name = $known.extension_name
                classification_basis = 'catalog_id'
                presence_only = $true
            }
            $classifiedCount += 1
            continue
        }
        $resolvedName = Resolve-ChromiumExtensionName -ExtensionPath $extension.FullName
        $classification = Find-ExtensionNameClassification -ExtensionName $resolvedName
        if ($null -ne $classification) {
            $indicator = New-SyntheticIndicator ('browser-' + $extension.Name) $classification.provider_id 'ai_browser_extension' $classification.confidence
            Add-Finding -Category 'browser_extension' -Indicator $indicator -SubjectUser $SubjectUser -Attributes @{
                browser = $Browser
                profile = $BrowserProfile.Name
                extension_id = $extension.Name
                extension_name = $resolvedName
                classification_basis = 'manifest_name_local_only'
                presence_only = $true
            }
            $classifiedCount += 1
        }
    }
    Add-ExtensionInventorySummary -Browser $Browser -BrowserProfile $BrowserProfile.Name -SubjectUser $SubjectUser -InstalledCount $installedCount -ClassifiedCount $classifiedCount
}

function Collect-FirefoxExtensionProfile {
    param(
        [Parameter(Mandatory = $true)]$BrowserProfile,
        [AllowNull()][string]$SubjectUser
    )
    $extensionDocument = Read-BoundedJsonObject -LiteralPath (Join-Path -Path $BrowserProfile.FullName -ChildPath 'extensions.json')
    if ($null -eq $extensionDocument) { return }
    $installedCount = 0
    $classifiedCount = 0
    foreach ($addon in @((Get-OptionalPropertyValue -InputObject $extensionDocument -Name 'addons'))) {
        if ($null -eq $addon) { continue }
        if (-not ([string](Get-OptionalPropertyValue -InputObject $addon -Name 'type')).Equals('extension', [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ((Get-OptionalPropertyValue -InputObject $addon -Name 'isSystem') -eq $true) { continue }
        $installedCount += 1
        $extensionName = Get-SafeExtensionName -Value ([string](Get-OptionalPropertyValue -InputObject $addon -Name 'name'))
        $defaultLocale = Get-OptionalPropertyValue -InputObject $addon -Name 'defaultLocale'
        if ($null -ne $defaultLocale) {
            $localizedName = Get-SafeExtensionName -Value ([string](Get-OptionalPropertyValue -InputObject $defaultLocale -Name 'name'))
            if ($null -ne $localizedName) { $extensionName = $localizedName }
        }
        $classification = Find-ExtensionNameClassification -ExtensionName $extensionName
        if ($null -eq $classification) { continue }
        $extensionId = Get-SafeExtensionName -Value ([string](Get-OptionalPropertyValue -InputObject $addon -Name 'id'))
        $indicator = New-SyntheticIndicator 'browser-firefox-name' $classification.provider_id 'ai_browser_extension' $classification.confidence
        Add-Finding -Category 'browser_extension' -Indicator $indicator -SubjectUser $SubjectUser -Attributes @{
            browser = 'firefox'
            profile = $BrowserProfile.Name
            extension_id = $extensionId
            extension_name = $extensionName
            classification_basis = 'extensions_json_name_local_only'
            presence_only = $true
        }
        $classifiedCount += 1
    }
    Add-ExtensionInventorySummary -Browser 'firefox' -BrowserProfile $BrowserProfile.Name -SubjectUser $SubjectUser -InstalledCount $installedCount -ClassifiedCount $classifiedCount
}

function Collect-BrowserExtensions {
    param([AllowEmptyCollection()][object[]]$Profiles)
    $knownExtensions = @{}
    foreach ($known in $BrowserExtensionCatalog) { $knownExtensions[[string]$known.extension_id] = $known }
    $browserRoots = @(
        [pscustomobject]@{ Browser = 'chrome'; Relative = 'AppData\Local\Google\Chrome\User Data' },
        [pscustomobject]@{ Browser = 'edge'; Relative = 'AppData\Local\Microsoft\Edge\User Data' },
        [pscustomobject]@{ Browser = 'brave'; Relative = 'AppData\Local\BraveSoftware\Brave-Browser\User Data' },
        [pscustomobject]@{ Browser = 'chromium'; Relative = 'AppData\Local\Chromium\User Data' },
        [pscustomobject]@{ Browser = 'vivaldi'; Relative = 'AppData\Local\Vivaldi\User Data' },
        [pscustomobject]@{ Browser = 'arc'; Relative = 'AppData\Local\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data' },
        [pscustomobject]@{ Browser = 'opera'; Relative = 'AppData\Roaming\Opera Software' }
    )
    foreach ($profile in $Profiles) {
        foreach ($browser in $browserRoots) {
            $root = Join-Path -Path $profile.Home -ChildPath $browser.Relative
            if (-not (Test-SafePath -LiteralPath $root)) { continue }
            try {
                foreach ($browserProfile in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop | Select-Object -First 128)) {
                    if (($browserProfile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    Collect-ChromiumExtensionProfile -Browser $browser.Browser -BrowserProfile $browserProfile -SubjectUser $profile.User -KnownExtensions $knownExtensions
                }
            } catch {
                Add-PartialError -Operation ('browser_inventory_' + $browser.Browser) -Exception $_.Exception
            }
        }
        $firefoxRoot = Join-Path -Path $profile.Home -ChildPath 'AppData\Roaming\Mozilla\Firefox\Profiles'
        if (Test-SafePath -LiteralPath $firefoxRoot) {
            try {
                foreach ($browserProfile in @(Get-ChildItem -LiteralPath $firefoxRoot -Directory -Force -ErrorAction Stop | Select-Object -First 128)) {
                    if (($browserProfile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    Collect-FirefoxExtensionProfile -BrowserProfile $browserProfile -SubjectUser $profile.User
                }
            } catch {
                Add-PartialError -Operation 'browser_inventory_firefox' -Exception $_.Exception
            }
        }
    }
}

try {
    if (-not $SelfTest) {
        if ($env:OS -ne 'Windows_NT') { throw [PlatformNotSupportedException]::new('Windows is required') }
        Collect-Processes
        $profiles = @(Get-UserProfiles)
        if ($profiles.Count -eq 0) {
            Add-PartialError -Operation 'profile_inventory_empty' -Exception ([IO.InvalidDataException]::new('no local profiles discovered'))
        }
        Collect-KnownPaths -Profiles $profiles
        Collect-InstalledSoftware -Profiles $profiles
        Collect-BrowserExtensions -Profiles $profiles
        Collect-BrowserHistory -Profiles $profiles
    }
    $Document | ConvertTo-Json -Depth 8 -Compress
    if ($Document.collector.partial) { exit 2 }
    exit 0
} catch {
    $fatalRecord = $_
    $fatalCommand = ''
    if ($null -ne $fatalRecord.InvocationInfo -and $null -ne $fatalRecord.InvocationInfo.MyCommand) {
        $fatalCommand = [string]$fatalRecord.InvocationInfo.MyCommand.Name
    }
    $fatalParameter = ''
    if ($fatalRecord.Exception.PSObject.Properties['ParameterName']) {
        $fatalParameter = [string]$fatalRecord.Exception.ParameterName
    }
    [ordered]@{
        error = ('fatal:' + $fatalRecord.Exception.GetType().Name)
        error_id = [string]$fatalRecord.FullyQualifiedErrorId
        command = $fatalCommand
        parameter = $fatalParameter
        line = [int]$fatalRecord.InvocationInfo.ScriptLineNumber
    } | ConvertTo-Json -Compress
    exit 1
}
