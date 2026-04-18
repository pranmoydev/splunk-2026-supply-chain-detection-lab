rule Claude_KAIROS_Daemon_Mode {
    meta:
        description = "Detects Claude Code daemon mode flag (KAIROS feature)"
        severity = "medium"
        reference = "SC-013a"
        
    strings:
        $s1 = "KAIROS_ENABLED" ascii
        $s2 = "daemon_mode" ascii
        $s3 = "claude" ascii nocase
        
    condition:
        ($s1 or $s2) and $s3
}
