import "pe"

rule Remcos_493Pro_Settings_RC4_x86 : remcos native_file experimental
{
    meta:
        description = "Build-scoped native x86 triage: version, SETTINGS resource and reviewed RC4 KSA"
        author = "remcos-lab"
        date = "2026-10-23"
        status = "experimental; one independent malware specimen"
        scope = "Unpacked native file; not a family-wide or memory-scan rule"
        sample_sha256 = "0af76f2897158bf752b5ee258053215a6de198e8910458c02282c2d4d284add5"

    strings:
        $version = "4.9.3 Pro\x00" ascii
        // Reviewed at VA 0x406CFC; wildcards cover stack displacement and branch distance.
        $ksa = {
            33 D2 8B C3 F7 74 24 ?? 0F B6 04 2A
            03 04 9F 03 F0 81 E6 FF 00 00 80
            79 ?? 4E 81 CE 00 FF FF FF 46
            8A 0C 9F 8B 04 B7 89 04 9F
            43 0F B6 C1 89 04 B7 81 FB 00 01 00 00
        }

    condition:
        uint16(0) == 0x5A4D and pe.is_pe and
        pe.machine == pe.MACHINE_I386 and filesize < 2MB and
        $version and pe.number_of_resources > 0 and
        for any i in (0..pe.number_of_resources - 1) : (
            pe.resources[i].type == pe.RESOURCE_TYPE_RCDATA and
            pe.resources[i].name_string == "S\x00E\x00T\x00T\x00I\x00N\x00G\x00S\x00" and
            pe.resources[i].length > 256 and
            pe.resources[i].offset + pe.resources[i].length <= filesize and
            uint8(pe.resources[i].offset) > 0 and
            uint8(pe.resources[i].offset) + 1 < pe.resources[i].length
        ) and
        for any j in (0..pe.number_of_sections - 1) : (
            pe.sections[j].characteristics & pe.SECTION_MEM_EXECUTE and
            pe.sections[j].raw_data_size >= !ksa and
            $ksa in (
                pe.sections[j].raw_data_offset..
                pe.sections[j].raw_data_offset + pe.sections[j].raw_data_size - !ksa
            )
        )
}

rule Remcos_493_Case_DecodedConfig_IOCs : remcos decoded_buffer case_specific
{
    meta:
        description = "Case-specific cleartext configuration artifacts; can also match analyst IOC notes"
        author = "remcos-lab"
        date = "2026-10-23"
        status = "case-specific content indicator, not standalone malware attribution"
        scope = "Small decoded buffers; not the encrypted native payload or a full process dump"

    strings:
        $domain_a = "remchukwugixiemu4.duckdns.org" ascii
        $domain_b = "remchukwugix231fgh.duckdns.org" ascii
        $namespace = "akpleoeurs-QPYUMO" ascii wide
        $file = "lpaowtrts.dat" ascii wide

    condition:
        filesize < 256KB and all of them
}
