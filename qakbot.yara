rule SecuriteInfo_Qakbot_1
{
        meta:
                author = "Arnaud Jacques / SecuriteInfo.com"
        strings:
                $a1 = { 46 75 6E 63 74 69 6F 6E 28 22 75 72 6C 22 2C 20 62 6F 64 79 2E 72 65 70 6C 61 63 65 28 2F 35 26 2F 67 2C 20 22 22 29 29 3B }
        condition:
                $a1
}

