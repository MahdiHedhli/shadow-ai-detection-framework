#!/usr/bin/perl
use strict;
use warnings;
use JSON::PP qw(decode_json encode_json);
use IO::Compress::Gzip qw(gzip);
use MIME::Base64 qw(encode_base64);
use POSIX qw(strftime);
use Sys::Hostname qw(hostname);

# macOS fallback for managed endpoints without an installed Python runtime.
# Metadata only: matching is local; raw arguments/URLs and file contents are
# never included in the JSON observation.
my $CATALOG = decode_json(q~[
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
]~);
my $EXTENSIONS = decode_json(q~[
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
    "extension_id": "hehggadaopoacecdllhhajmbjkdcmajg",
    "extension_name": "ChatGPT",
    "provider_id": "openai"
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
]~);
my $DOMAINS = decode_json(q~[
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
]~);
my $MAX_FINDINGS = 5000;
my $MAX_HOMES = 256;
my $MAX_HISTORY_BYTES = 268435456;
my $RMM_COMPRESS_THRESHOLD_BYTES = 12000;
my $RMM_MAX_TRANSPORT_CHARS = 24000;
my @findings;
my @errors;
my $partial = JSON::PP::false;

sub utc_now {
    return strftime('%Y-%m-%dT%H:%M:%SZ', gmtime());
}

sub uuid {
    open my $random, '<:raw', '/dev/urandom' or die "random_source_unavailable";
    read($random, my $bytes, 16) == 16 or die "random_source_unavailable";
    close $random;
    my @b = unpack('C16', $bytes);
    $b[6] = ($b[6] & 0x0f) | 0x40;
    $b[8] = ($b[8] & 0x3f) | 0x80;
    return sprintf('%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x', @b);
}

sub record_error {
    my ($operation, $reason) = @_;
    $partial = JSON::PP::true;
    push @errors, substr("${operation}:${reason}", 0, 200) if @errors < 100;
}

sub add_finding {
    my ($category, $indicator, $user, %attributes) = @_;
    if (@findings >= $MAX_FINDINGS) {
        record_error('finding_limit', 'limit') if @findings == $MAX_FINDINGS;
        return;
    }
    push @findings, {
        finding_id => uuid(), observed_at => utc_now(), category => $category,
        indicator_id => $indicator->{artifact_id}, provider_id => $indicator->{provider_id},
        capability => $indicator->{capability}, confidence => $indicator->{confidence},
        evidence_level => $category eq 'browser_history' ? 1 : $category eq 'process' ? 3 : 2,
        subject_user => $user, attributes => \%attributes,
    };
}

sub path_is_safe {
    my ($path) = @_;
    return 0 if -l $path;
    return 1 if -e $path;
    return 0;
}

sub homes {
    my @result;
    for my $path (sort glob('/Users/*')) {
        next if $path =~ m{/(?:Shared|Guest)$} || !path_is_safe($path) || !-d $path;
        push @result, [substr($path, 7), $path];
        last if @result >= $MAX_HOMES;
    }
    return @result;
}

sub artifacts {
    my ($kind) = @_;
    return grep { $_->{artifact_type} eq $kind && ($_->{platform} eq 'any' || $_->{platform} eq 'macos') } @$CATALOG;
}

sub does_match {
    my ($value, $item) = @_;
    my $candidate = lc($value // '');
    my $pattern = lc($item->{pattern} // '');
    return $candidate eq $pattern if $item->{match_mode} eq 'exact';
    return index($candidate, $pattern) >= 0 if $item->{match_mode} eq 'contains';
    return length($candidate) >= length($pattern) && substr($candidate, -length($pattern)) eq $pattern;
}

sub collect_processes {
    my @process_items = artifacts('process');
    push @process_items, artifacts('command_line');
    my $ps = '/bin/ps';
    open my $fh, '-|', $ps, '-axo', 'pid=,comm=,args=' or do { record_error('process_inventory', 'unavailable'); return; };
    while (my $line = <$fh>) {
        my ($pid, $name, $args) = $line =~ /^\s*(\d+)\s+(\S+)(?:\s+(.*))?$/;
        next unless defined $pid && defined $name;
        for my $item (@process_items) {
            my $tested = $item->{artifact_type} eq 'process' ? $name : ($args // '');
            next unless does_match($tested, $item);
            add_finding('process', $item, undef, pid => int($pid), process_name => $name,
                match_basis => $item->{artifact_type} eq 'process' ? 'process_name' : 'arguments_local_only');
        }
    }
    close $fh or record_error('process_inventory', 'command_failed');
}

sub collect_known_paths {
    my @model = grep { $_->{artifact_id} eq 'file-model-001' } @$CATALOG;
    my @configs = artifacts('config_file');
    my %config_by_name = map { lc($_->{pattern}) => $_ } @configs;
    my @checks = (
        ['.ollama/models', 'model_directory', $model[0]],
        ['.cache/lm-studio/models', 'model_directory', $model[0]],
        ['.lmstudio/models', 'model_directory', $model[0]],
        ['Library/Application Support/LM Studio/models', 'model_directory', $model[0]],
        ['.cursor/mcp.json', 'config_file', $config_by_name{'mcp.json'}],
        ['.mcp.json', 'config_file', $config_by_name{'.mcp.json'}],
        ['.config/Claude/claude_desktop_config.json', 'config_file', $config_by_name{'claude_desktop_config.json'}],
        ['Library/Application Support/Claude/claude_desktop_config.json', 'config_file', $config_by_name{'claude_desktop_config.json'}],
        ['Library/Application Support/Cursor/User/globalStorage/mcp.json', 'config_file', $config_by_name{'mcp.json'}],
    );
    for my $home (homes()) {
        my ($user, $root) = @$home;
        for my $check (@checks) {
            my ($relative, $category, $indicator) = @$check;
            next unless $indicator;
            my $path = "$root/$relative";
            next unless path_is_safe($path);
            add_finding($category eq 'model_directory' ? 'model_directory' : 'config_file', $indicator, $user,
                path_token => "{user_home}/$relative", match_basis => 'known_path_presence_only');
        }
    }
}

sub read_json_file {
    my ($path, $limit) = @_;
    return undef unless path_is_safe($path) && -f $path && -s $path <= $limit;
    open my $fh, '<:raw', $path or return undef;
    local $/;
    my $raw = <$fh>;
    close $fh;
    my $data = eval { decode_json($raw) };
    return $@ ? undef : $data;
}

sub collect_extensions {
    my %known = map { $_->{extension_id} => $_ } @$EXTENSIONS;
    my @roots = (
        ['chrome', 'Library/Application Support/Google/Chrome'],
        ['edge', 'Library/Application Support/Microsoft Edge'],
        ['brave', 'Library/Application Support/BraveSoftware/Brave-Browser'],
        ['chromium', 'Library/Application Support/Chromium'],
    );
    for my $home (homes()) {
        my ($user, $base) = @$home;
        for my $root (@roots) {
            my ($browser, $relative) = @$root;
            my $browser_root = "$base/$relative";
            next unless path_is_safe($browser_root) && -d $browser_root;
            opendir my $dh, $browser_root or next;
            my @profiles = sort grep { $_ ne '.' && $_ ne '..' && path_is_safe("$browser_root/$_") && -d "$browser_root/$_" } readdir($dh);
            closedir $dh;
            splice(@profiles, 128) if @profiles > 128;
            for my $profile (@profiles) {
                my $profile_root = "$browser_root/$profile";
                my %present;
                my $extensions_dir = "$profile_root/Extensions";
                if (path_is_safe($extensions_dir) && -d $extensions_dir && opendir(my $edh, $extensions_dir)) {
                    for my $id (readdir($edh)) {
                        $present{$id} = 'extension_directory' if exists $known{$id} && $id =~ /^[a-p]{32}$/ && path_is_safe("$extensions_dir/$id");
                    }
                    closedir $edh;
                }
                my $prefs = read_json_file("$profile_root/Preferences", 16777216);
                my $settings = ref($prefs) eq 'HASH' && ref($prefs->{extensions}) eq 'HASH' ? $prefs->{extensions}->{settings} : undef;
                if (ref($settings) eq 'HASH') {
                    for my $id (keys %$settings) { $present{$id} ||= 'preferences_index' if exists $known{$id} && $id =~ /^[a-p]{32}$/; }
                }
                for my $id (keys %present) {
                    my $item = $known{$id};
                    add_finding('browser_extension', {
                        artifact_id => "browser-$id", provider_id => $item->{provider_id},
                        capability => 'ai_browser_extension', confidence => $present{$id} eq 'extension_directory' ? 'high' : 'medium',
                    }, $user, browser => $browser, profile => $profile, extension_id => $id,
                        extension_name => $item->{extension_name}, classification_basis => $present{$id});
                }
            }
        }
    }
}

sub history_item {
    my ($url) = @_;
    my ($host) = $url =~ m{^[a-z][a-z0-9+.-]*://(?:[^/@?#]*@)?(?:\[[^\]]+\]|([^/:?#]+))}i;
    return unless defined $host;
    $host = lc($host); $host =~ s/\.$//;
    for my $item (@$DOMAINS) {
        my $domain = $item->{domain};
        next if $item->{indicator_type} eq 'fqdn' ? $host ne $domain : ($host ne $domain && $host !~ /\.\Q$domain\E$/);
        return ($item, $host);
    }
    return;
}

sub collect_history_db {
    my ($path, $sql, $browser, $profile, $user) = @_;
    return unless path_is_safe($path) && -f $path;
    if (-s $path > $MAX_HISTORY_BYTES) { record_error("browser_history_$browser", 'size_limit'); return; }
    open my $fh, '-|', '/usr/bin/sqlite3', '-readonly', '-noheader', '-batch', $path, $sql or do { record_error("browser_history_$browser", 'query_failed'); return; };
    my %found;
    my $rows = 0;
    while (my $url = <$fh>) {
        chomp $url;
        next if ++$rows > 1000000;
        my ($item, $host) = history_item($url);
        $found{$item->{artifact_id}} = [$item, $host] if $item;
    }
    close $fh or record_error("browser_history_$browser", 'query_failed');
    for my $entry (values %found) {
        my ($item, $host) = @$entry;
        add_finding('browser_history', $item, $user, browser => $browser, profile => $profile,
            matched_domain => $host, match_basis => 'history_database_hostname_match_local_only', presence_only => JSON::PP::true);
    }
}

sub history_sql {
    my ($table, $column) = @_;
    my @clauses;
    for my $item (@$DOMAINS) {
        my $domain = $item->{domain};
        next unless $domain =~ /^[a-z0-9.-]+$/;
        push @clauses, "lower($column) LIKE '%" . $domain . "%'";
    }
    return "SELECT $column FROM $table WHERE " . join(' OR ', @clauses) . ' LIMIT 1000000;';
}

sub collect_history {
    for my $home (homes()) {
        my ($user, $base) = @$home;
        my @roots = (
            ['chrome', 'Library/Application Support/Google/Chrome', 'urls', 'url'],
            ['edge', 'Library/Application Support/Microsoft Edge', 'urls', 'url'],
            ['brave', 'Library/Application Support/BraveSoftware/Brave-Browser', 'urls', 'url'],
            ['chromium', 'Library/Application Support/Chromium', 'urls', 'url'],
            ['firefox', 'Library/Application Support/Firefox/Profiles', 'moz_places', 'url'],
        );
        for my $root (@roots) {
            my ($browser, $relative, $table, $column) = @$root;
            my $directory = "$base/$relative";
            next unless path_is_safe($directory) && -d $directory && opendir(my $dh, $directory);
            my @profiles = sort grep { $_ ne '.' && $_ ne '..' && path_is_safe("$directory/$_") && -d "$directory/$_" } readdir($dh);
            closedir $dh;
            splice(@profiles, 128) if @profiles > 128;
            for my $profile (@profiles) {
                my $db = "$directory/$profile/" . ($browser eq 'firefox' ? 'places.sqlite' : 'History');
                collect_history_db($db, history_sql($table, $column), $browser, $profile, $user) if path_is_safe($db);
            }
        }
    }
}

my $self_test = @ARGV && $ARGV[0] eq '--self-test';
my $doc = {
    schema_version => '1.0', observation_id => uuid(), collected_at => utc_now(),
    collector => { name => 'shadow-ai-rmm-macos-native', version => '0.2.0', partial => JSON::PP::false, errors => \@errors },
    device => { hostname => hostname() || 'unknown', os_family => 'macos', os_version => 'macOS ' . ((`/usr/bin/sw_vers -productVersion 2>/dev/null` || 'unknown') =~ s/\s+\z//r), architecture => ((`/usr/bin/uname -m 2>/dev/null` || 'unknown') =~ s/\s+\z//r) },
    scope => ['processes', 'known_paths', 'browser_extensions', 'browser_history'],
    safety => { content_collected => JSON::PP::false, raw_command_line_collected => JSON::PP::false,
        environment_values_collected => JSON::PP::false, network_requests_made => JSON::PP::false,
        full_disk_search_performed => JSON::PP::false, symlinks_followed => JSON::PP::false },
    findings => \@findings,
};

if (!$self_test) {
    eval { collect_processes(); collect_known_paths(); collect_extensions(); collect_history(); 1 }
        or record_error('collector', 'unexpected_error');
}
$doc->{collector}->{partial} = $partial;
my $output = encode_json($doc);
if (length($output) > $RMM_COMPRESS_THRESHOLD_BYTES) {
    my $compressed = '';
    gzip(\$output => \$compressed, Level => 9) or do {
        print STDERR "fatal:rmm_gzip_failed\n";
        exit 1;
    };
    $output = 'SHADOWAI_GZIP_V1:' . encode_base64($compressed, '');
    if (length($output) > $RMM_MAX_TRANSPORT_CHARS) {
        print STDERR "fatal:rmm_output_size_limit\n";
        exit 1;
    }
}
print $output, "\n";
exit($partial ? 2 : 0);
