rule Axios_RAT_PlainCryptoJS {
    meta:
        description = "Detects compromised axios dependency with plain-crypto-js RAT"
        severity = "critical"
        attack_id = "T1195.001"  // Compromise Software Dependencies
        
    strings:
        $s1 = "plain-crypto-js" ascii
        $s2 = "axios" ascii
        $s3 = "postinstall" ascii
        $s4 = "eval(process.env" ascii wide
        $s5 = "dump(process.env" ascii wide
        
    condition:
        ($s1 or $s2) and ($s4 or $s5)
}