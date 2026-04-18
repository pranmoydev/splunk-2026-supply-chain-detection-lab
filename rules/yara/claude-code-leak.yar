rule Claude_Code_Leak_Artifact {
    meta:
        description = "Detects Claude Code internal source exposure from March 2026 leak"
        severity = "high"
        attack_id = "T1530"  // Data from Information Repositories
        reference = "SC-004a"
        
    strings:
        $s1 = ".claude/settings.local.json" fullword ascii
        $s2 = "dangerouslySkipPermissions" ascii
        $s3 = "anthropic-ai/claude-code" ascii
        $s4 = "@anthropic-ai/claude-code" ascii
        $s5 = "2.1.88" ascii
        
    condition:
        any of them
}
