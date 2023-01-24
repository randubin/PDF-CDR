
rule cleaning_rule {
	strings:
		$s1=/\/AA/
		$s2=/\/AcroForm/
		$s3=/\/EmbeddedFile/
		$s4=/\/URI/
		$s5=/\/JBIG2Decode/
		$s6=/\/JS/
	condition:
		any of them
}
rule INDICATOR_PDF_IPDropper {
    meta:
        description = "Detects PDF documents with Action and URL pointing to direct IP address"
        author = "ditekSHen"
    strings:
        $s1 = { 54 79 70 65 20 2f 41 63 74 69 6f 6e 0d 0a 2f 53 20 2f 55 52 49 0d 0a }
        $s2 = /\/URI \(http(s)?:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}\// ascii
    condition:
        uint32(0) == 0x46445025 and all of them
}
rule pdf_exploit_fontfile_SING_table_overflow_CVE_2010_2883_A_B {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit fontfile SING table overflow CVE-2010-2883 A"
		mitre = "T1203 T1204.002"
	strings:
		$h_hex1 = {1045086F0000EB4C00000024686D747809C68EB20000B4C4000004306B65726EDC52D5990000BDA000002D8A6C6F6361F3CBD23D0000BB840000021A6D6178700547063A0000EB2C0000002053494E47D9BCC8B50000011C00001DDF706F7374B45A2FBB0000B8F40000028E70726570}

	condition: any of them
}
rule blackhole2_pdf : EK PDF
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "BlackHole2 Exploit Kit Detection"
   hash0 = "d1e2ff36a6c882b289d3b736d915a6cc"
   sample_filetype = "pdf"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   weight = 6
   tag = "attack.initial"
strings:
   $string0 = "/StructTreeRoot 5 0 R/Type/Catalog>>"
   $string1 = "0000036095 00000 n"
   $string2 = "http://www.xfa.org/schema/xfa-locale-set/2.1/"
   $string3 = "subform[0].ImageField1[0])/Subtype/Widget/TU(Image Field)/Parent 22 0 R/F 4/P 8 0 R/T<FEFF0049006D00"
   $string4 = "0000000026 65535 f"
   $string5 = "0000029039 00000 n"
   $string6 = "0000029693 00000 n"
   $string7 = "%PDF-1.6"
   $string8 = "27 0 obj<</Subtype/Type0/DescendantFonts 28 0 R/BaseFont/KLGNYZ"
   $string9 = "0000034423 00000 n"
   $string10 = "0000000010 65535 f"
   $string11 = ">stream"
   $string12 = "/Pages 2 0 R%/StructTreeRoot 5 0 R/Type/Catalog>>"
   $string13 = "19 0 obj<</Subtype/Type1C/Length 23094/Filter/FlateDecode>>stream"
   $string14 = "0000003653 00000 n"
   $string15 = "0000000023 65535 f"
   $string16 = "0000028250 00000 n"
   $string17 = "iceRGB>>>>/XStep 9.0/Type/Pattern/TilingType 2/YStep 9.0/BBox[0 0 9 9]>>stream"
   $string18 = "<</Root 1 0 R>>"
condition:
   18 of them
}

rule bleedinglife2_adobe_2010_2884_exploit : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "BleedingLife2 Exploit Kit ADOBE"
   hash0 = "b22ac6bea520181947e7855cd317c9ac"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   weight = 6
   tag = "attack.initial"
strings:
   $string0 = "_autoRepeat"
   $string1 = "embedFonts"
   $string2 = "KeyboardEvent"
   $string3 = "instanceStyles"
   $string4 = "InvalidationType"
   $string5 = "autoRepeat"
   $string6 = "getScaleX"
   $string7 = "RadioButton_selectedDownIcon"
   $string8 = "configUI"
   $string9 = "deactivate"
   $string10 = "fl.controls:Button"
   $string11 = "_mouseStateLocked"
   $string12 = "fl.core.ComponentShim"
   $string13 = "toString"
   $string14 = "_group"
   $string15 = "addRadioButton"
   $string16 = "inCallLaterPhase"
   $string17 = "oldMouseState"
condition:
   17 of them
}

rule bleedinglife2_adobe_2010_1297_exploit : EK PDF
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "BleedingLife2 Exploit Kit PDF"
   hash0 = "8179a7f91965731daa16722bd95f0fcf"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   weight = 6
   tag = "attack.initial"
strings:
   $string0 = "getSharedStyle"
   $string1 = "currentCount"
   $string2 = "String"
   $string3 = "setSelection"
   $string4 = "BOTTOM"
   $string5 = "classToInstancesDict"
   $string6 = "buttonDown"
   $string7 = "focusRect"
   $string8 = "pill11"
   $string9 = "TEXT_INPUT"
   $string10 = "restrict"
   $string11 = "defaultButtonEnabled"
   $string12 = "copyStylesToChild"
   $string13 = " xmlns:xmpMM"
   $string14 = "_editable"
   $string15 = "classToDefaultStylesDict"
   $string16 = "IMEConversionMode"
   $string17 = "Scene 1"
condition:
   17 of them
}

rule phoenix_pdf : EK PDF
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Phoenix Exploit Kit PDF"
   hash0 = "16de68e66cab08d642a669bf377368da"
   hash1 = "bab281fe0cf3a16a396550b15d9167d5"
   sample_filetype = "pdf"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   weight = 6
   tag = "attack.initial"
strings:
   $string0 = "0000000254 00000 n"
   $string1 = "0000000295 00000 n"
   $string2 = "trailer<</Root 1 0 R /Size 7>>"
   $string3 = "0000000000 65535 f"
   $string4 = "3 0 obj<</JavaScript 5 0 R >>endobj"
   $string5 = "0000000120 00000 n"
   $string6 = "%PDF-1.0"
   $string7 = "startxref"
   $string8 = "0000000068 00000 n"
   $string9 = "endobjxref"
   $string10 = ")6 0 R ]>>endobj"
   $string11 = "0000000010 00000 n"
condition:
   11 of them
}

rule phoenix_pdf2 : EK PDF
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Phoenix Exploit Kit PDF"
   hash0 = "33cb6c67f58609aa853e80f718ab106a"
   sample_filetype = "pdf"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   weight = 6
   tag = "attack.initial"
strings:
   $string0 = "\\nQb<%"
   $string1 = "0000000254 00000 n"
   $string2 = ":S3>v0$EF"
   $string3 = "trailer<</Root 1 0 R /Size 7>>"
   $string4 = "%PDF-1.0"
   $string5 = "0000000000 65535 f"
   $string6 = "endstream"
   $string7 = "0000000010 00000 n"
   $string8 = "6 0 obj<</JS 7 0 R/S/JavaScript>>endobj"
   $string9 = "3 0 obj<</JavaScript 5 0 R >>endobj"
   $string10 = "}pr2IE"
   $string11 = "0000000157 00000 n"
   $string12 = "1 0 obj<</Type/Catalog/Pages 2 0 R /Names 3 0 R >>endobj"
   $string13 = "5 0 obj<</Names[("
condition:
   13 of them
}

rule phoenix_pdf3 : EK PDF
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Phoenix Exploit Kit PDF"
   hash0 = "bab281fe0cf3a16a396550b15d9167d5"
   sample_filetype = "pdf"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   weight = 6
   tag = "attack.initial"
strings:
   $string0 = "trailer<</Root 1 0 R /Size 7>>"
   $string1 = "stream"
   $string2 = ";_oI5z"
   $string3 = "0000000010 00000 n"
   $string4 = "3 0 obj<</JavaScript 5 0 R >>endobj"
   $string5 = "7 0 obj<</Filter[ /FlateDecode /ASCIIHexDecode /ASCII85Decode ]/Length 3324>>"
   $string6 = "endobjxref"
   $string7 = "L%}gE("
   $string8 = "0000000157 00000 n"
   $string9 = "1 0 obj<</Type/Catalog/Pages 2 0 R /Names 3 0 R >>endobj"
   $string10 = "0000000120 00000 n"
   $string11 = "4 0 obj<</Type/Page/Parent 2 0 R /Contents 12 0 R>>endobj"
condition:
   11 of them
}



rule Action_In_PDF {
   meta:
      description = "Detects Action in PDF"
      author = "Lionel PRAT"
      reference = "Basic rule PDF"
      version = "0.1"
      weight = 1
      var_match = "pdf_action_bool"
   strings:
      $a = /\/Action/
   condition:
      $a
}



rule ASCIIDecode_In_PDF {
   meta:
      description = "Detects ASCII Decode in PDF"
      author = "Lionel PRAT"
      reference = "Basic rule PDF"
      version = "0.1"
      weight = 1
      var_match = "pdf_asciidecode_bool"
   strings:
      $a = /\/ASCIIHexDecode|\/ASCII85Decode/
   condition:
      $a
}

rule oldversion_In_PDF {
   meta:
      description = "Old version PDF"
      author = "Lionel PRAT"
      reference = "Basic rule PDF"
      version = "0.1"
      weight = 0
      var_match = "pdf_oldver12_bool"
   strings:
      $ver = /%PDF-1\.[3-9]/
   condition:
      not $ver
}


rule invalide_structure_PDF {
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		description = "Invalide structure PDF"
		weight = 5
		var_match = "pdf_invalid_struct_bool"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
        strings:
                $magic = { 25 50 44 46 }
				// Required for a valid PDF
                $reg0 = /trailer\r?\n?.*\/Size.*\r?\n?\.*/
                $reg1 = /\/Root.*\r?\n?.*startxref\r?\n?.*\r?\n?%%EOF/
        condition:
                $magic in (0..1024) and not $reg0 and not $reg1
}


rule XFA_exploit_in_PDF {
   meta:
      description = "PDF potential exploit XFA CVE-2010-0188"
      author = "Lionel PRAT"
      reference = "https://www.exploit-db.com/exploits/11787"
      version = "0.1"
      weight = 6
      tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
      check_level2 = "check_command_bool"
   strings:
      $nop = "kJCQkJCQkJCQkJCQ"
      $xfa = /\/XFA|http:\/\/www\.xfa\.org\/schema\//
      $tif = "tif"
      $img = "ImageField"
   condition:
      $xfa and $img and $tif and $nop
}
                     
rule XFA_withJS_in_PDF {
   meta:
      description = "Detects Potential XFA with JS in PDF"
      author = "Lionel PRAT"
      reference = "EK Blackhole PDF exploit"
      version = "0.1"
      weight = 4
      var_match = "pdf_xfajs_bool"
      tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
      check_level2 = "check_command_bool"
   strings:
      $a = /\/XFA|http:\/\/www\.xfa\.org\/schema\//
      $b = "x-javascript" nocase
   condition:
      $a and $b 
}

rule XFA_in_PDF {
   meta:
      description = "Detects Potential XFA with JS in PDF"
      author = "Lionel PRAT"
      reference = "EK Blackhole PDF exploit"
      version = "0.1"
      weight = 3
      var_match = "pdf_xfa_bool"
      tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
      check_level2 = "check_command_bool"
   strings:
      $a = /\/XFA|http:\/\/www\.xfa\.org\/schema\//
   condition:
      $a
}

rule URI_on_OPENACTION_in_PDF {
   meta:
      description = "Detects Potential URI on OPENACTION in PDF"
      author = "Lionel PRAT"
      reference = "TokenCanary.pdf"
      version = "0.1"
      weight = 2
      var_match = "pdf_uri_bool"
      tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
   strings:
      $a = /\/S\s*\/URI\s*\/URI\s*\(/
      $b = /\OpenAction/
   condition:
      $a and $b 
}
                     
rule shellcode_metadata_PDF {
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "Potential shellcode in PDF metadata"
                weight = 5
                tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
                check_level2 = "check_command_bool"
        strings:
                $magic = { 25 50 44 46 }

                $reg_keyword = /\/Keywords.?\(([a-zA-Z0-9]{200,})/ //~6k was observed in BHEHv2 PDF exploits holding the shellcode
                $reg_author = /\/Author.?\(([a-zA-Z0-9]{200,})/
                $reg_title = /\/Title.?\(([a-zA-Z0-9]{200,})/
                $reg_producer = /\/Producer.?\(([a-zA-Z0-9]{200,})/
                $reg_creator = /\/Creator.?\(([a-zA-Z0-9]{300,})/
                $reg_create = /\/CreationDate.?\(([a-zA-Z0-9]{200,})/

        condition:
                $magic in (0..1024) and 1 of ($reg*)
}

rule potential_exploit_PDF{
	meta:
		author = "Glenn Edwards (@hiddenillusion) - modified by Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "Potential exploit in PDF metadata"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
		check_level2 = "check_command_bool"
	strings:
		
		$attrib0 = /\/JavaScript |\/JS /
		$attrib3 = /\/ASCIIHexDecode/
		$attrib4 = /\/ASCII85Decode/

		$action0 = /\/Action/
		$action1 = "Array"
		$shell = "A"
		$cond0 = "unescape"
		$cond1 = "String.fromCharCode"
		
		$nop = "%u9090%u9090"
	condition:
		(2 of ($attrib*) ) or (($action0) and #shell > 10 and 1 of ($cond*)) or ($action1 and $cond0 and $nop)
}



rule PDF_fileexport {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "PDF fonction export file (check file for found name)"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
	strings:
		$export = "exportDataObject" nocase wide ascii
		$cname = "cname" nocase wide ascii
	condition:
		$export and $cname
}




rule malicious_author : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 5
		
	strings:
		$magic = { 25 50 44 46 }
		
		$reg0 = /Creator.?\(yen vaw\)/
		$reg1 = /Title.?\(who cis\)/
		$reg2 = /Author.?\(ser pes\)/
	condition:
		$magic in (0..1024) and all of ($reg*)
}

rule suspicious_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1.\d{1}/
	condition:
		$magic in (0..1024) and not $ver
}

rule suspicious_creation : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$create0 = /CreationDate \(D:20101015142358\)/
		$create1 = /CreationDate \(2008312053854\)/
	condition:
		$magic in (0..1024) and $header and 1 of ($create*)
}

rule multiple_filtering : PDF raw
{
meta: 
author = "Glenn Edwards (@hiddenillusion)"
version = "0.2"
weight = 3

    strings:
            $magic = { 25 50 44 46 }
            $attrib = /\/Filter.*(\/ASCIIHexDecode\W+|\/LZWDecode\W+|\/ASCII85Decode\W+|\/FlateDecode\W+|\/RunLengthDecode){2}/ 
            // left out: /CCITTFaxDecode, JBIG2Decode, DCTDecode, JPXDecode, Crypt

    condition: 
            $magic in (0..1024) and $attrib
}

rule suspicious_title : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$title0 = "who cis"
		$title1 = "P66N7FF"
		$title2 = "Fohcirya"
	condition:
		$magic in (0..1024) and $header and 1 of ($title*)
}

rule suspicious_author : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/

		$author0 = "Ubzg1QUbzuzgUbRjvcUb14RjUb1"
		$author1 = "ser pes"
		$author2 = "Miekiemoes"
		$author3 = "Nsarkolke"
	condition:
		$magic in (0..1024) and $header and 1 of ($author*)
}

rule suspicious_producer : PDF raw 
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$producer0 = /Producer \(Scribus PDF Library/
		$producer1 = "Notepad"
	condition:
		$magic in (0..1024) and $header and 1 of ($producer*)
}

rule suspicious_creator : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$creator0 = "yen vaw"
		$creator1 = "Scribus"
		$creator2 = "Viraciregavi"
	condition:
		$magic in (0..1024) and $header and 1 of ($creator*)
}

rule possible_exploit : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/JavaScript /
		$attrib3 = /\/ASCIIHexDecode/
		$attrib4 = /\/ASCII85Decode/

		$action0 = /\/Action/
		$action1 = "Array"
		$shell = "A"
		$cond0 = "unescape"
		$cond1 = "String.fromCharCode"
		
		$nop = "%u9090%u9090"
	condition:
		$magic in (0..1024) and (2 of ($attrib*)) or ($action0 and #shell > 10 and 1 of ($cond*)) or ($action1 and $cond0 and $nop)
}

rule shellcode_blob_metadata : PDF raw
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "When there's a large Base64 blob inserted into metadata fields it often indicates shellcode to later be decoded"
                weight = 4
        strings:
                $magic = { 25 50 44 46 }

                $reg_keyword = /\/Keywords.?\(([a-zA-Z0-9]{200,})/ //~6k was observed in BHEHv2 PDF exploits holding the shellcode
                $reg_author = /\/Author.?\(([a-zA-Z0-9]{200,})/
                $reg_title = /\/Title.?\(([a-zA-Z0-9]{200,})/
                $reg_producer = /\/Producer.?\(([a-zA-Z0-9]{200,})/
                $reg_creator = /\/Creator.?\(([a-zA-Z0-9]{300,})/
                $reg_create = /\/CreationDate.?\(([a-zA-Z0-9]{200,})/

        condition:
                $magic in (0..1024) and 1 of ($reg*)
}

rule suspicious_js : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/OpenAction /
		$attrib1 = /\/JavaScript /

		$js0 = "eval"
		$js1 = "Array"
		$js2 = "String.fromCharCode"
		
	condition:
		$magic in (0..1024) and all of ($attrib*) and 2 of ($js*)
}

rule suspicious_launch_action : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/Launch/
		$attrib1 = /\/URL /
		$attrib2 = /\/Action/
		$attrib3 = /\/OpenAction/
		$attrib4 = /\/F /

	condition:
		$magic in (0..1024) and 3 of ($attrib*)
}

rule suspicious_embed : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "https://feliam.wordpress.com/2010/01/13/generic-pdf-exploit-hider-embedpdf-py-and-goodbye-av-detection-012010/"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		
		$meth0 = /\/Launch/
		$meth1 = /\/GoTo(E|R)/ //means go to embedded or remote
		$attrib0 = /\/URL /
		$attrib1 = /\/Action/
		$attrib2 = /\/Filespec/
		
	condition:
		$magic in (0..1024) and 1 of ($meth*) and 2 of ($attrib*)
}

rule suspicious_obfuscation : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$reg = /\/\w#[a-zA-Z0-9]{2}#[a-zA-Z0-9]{2}/
		
	condition:
		$magic in (0..1024) and #reg > 5
}

rule invalid_XObject_js : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "XObject's require v1.4+"
		ref = "https://blogs.adobe.com/ReferenceXObjects/"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1\.[4-9]/
		
		$attrib0 = /\/XObject/
		$attrib1 = /\/JavaScript/
		
	condition:
		$magic in (0..1024) and not $ver and all of ($attrib*)
}

rule invalid_trailer_structure : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				// Required for a valid PDF
                $reg0 = /trailer\r?\n?.*\/Size.*\r?\n?\.*/
                $reg1 = /\/Root.*\r?\n?.*startxref\r?\n?.*\r?\n?%%EOF/

        condition:
                $magic in (0..1024) and not $reg0 and not $reg1
}

rule multiple_versions : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
        description = "Written very generically and doesn't hold any weight - just something that might be useful to know about to help show incremental updates to the file being analyzed"		
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
                $s0 = "trailer"
                $s1 = "%%EOF"

        condition:
                $magic in (0..1024) and #s0 > 1 and #s1 > 1
}

rule js_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JavaScript was introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 2
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JavaScript/
				$ver = /%PDF-1\.[3-9]/

        condition:
                $magic in (0..1024) and $js and not $ver
}

rule JBIG2_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JBIG2 was introduced in v1.4"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JBIG2Decode/
				$ver = /%PDF-1\.[4-9]/

        condition:
                $magic in (0..1024) and $js and not $ver
}

rule FlateDecode_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "Flate was introduced in v1.2"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/FlateDecode/
				$ver = /%PDF-1\.[2-9]/

        condition:
                $magic in (0..1024) and $js and not $ver
}

rule embed_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "EmbeddedFiles were introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$embed = /\/EmbeddedFiles/
				$ver = /%PDF-1\.[3-9]/

        condition:
                $magic in (0..1024) and $embed and not $ver
}

rule invalid_xref_numbers : PDF raw
{
        meta:
			author = "Glenn Edwards (@hiddenillusion)"
			version = "0.1"
			description = "The first entry in a cross-reference table is always free and has a generation number of 65,535"
			notes = "This can be also be in a stream..."
			weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
                $reg0 = /xref\r?\n?.*\r?\n?.*65535\sf/
                $reg1 = /endstream.*\r?\n?endobj.*\r?\n?startxref/
        condition:
                $magic in (0..1024) and not $reg0 and not $reg1
}

rule js_splitting : PDF raw
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "These are commonly used to split up JS code"
                weight = 2
                
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JavaScript/
                $s0 = "getAnnots"
                $s1 = "getPageNumWords"
                $s2 = "getPageNthWord"
                $s3 = "this.info"
                                
        condition:
                $magic in (0..1024) and $js and 1 of ($s*)
}

rule header_evasion : PDF raw
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                description = "3.4.1, 'File Header' of Appendix H states that ' Acrobat viewers require only that the header appear somewhere within the first 1024 bytes of the file.'  Therefore, if you see this trigger then any other rule looking to match the magic at 0 won't be applicable"
                ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
                version = "0.1"
                weight = 3

        strings:
                $magic = { 25 50 44 46 }
        condition:
                $magic in (5..1024) and #magic == 1
}

rule BlackHole_v2 : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://fortknoxnetworks.blogspot.no/2012/10/blackhhole-exploit-kit-v-20-url-pattern.html"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$content = "Index[5 1 7 1 9 4 23 4 50"
		
	condition:
		$magic in (0..1024) and $content
}


rule XDP_embedded_PDF : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://blog.9bplus.com/av-bypass-for-malicious-pdfs-using-xdp"
        weight = 1		

	strings:
		$s1 = "<pdf xmlns="
		$s2 = "<chunk>"
		$s3 = "</pdf>"
		$header0 = "%PDF"
		$header1 = "JVBERi0"

	condition:
		all of ($s*) and 1 of ($header*)
}

rule PDF_Embedded_Exe : PDF
{
	meta:
		ref = "https://github.com/jacobsoo/Yara-Rules/blob/master/PDF_Embedded_Exe.yar"
	strings:
    	$header = {25 50 44 46}
    	$Launch_Action = {3C 3C 2F 53 2F 4C 61 75 6E 63 68 2F 54 79 70 65 2F 41 63 74 69 6F 6E 2F 57 69 6E 3C 3C 2F 46}
        $exe = {3C 3C 2F 45 6D 62 65 64 64 65 64 46 69 6C 65 73}
    condition:
    	$header at 0 and $Launch_Action and $exe
}
rule PDF_Document_with_Embedded_IQY_File
{
    meta:
        Author = "InQuest Labs"
        Description = "This signature detects IQY files embedded within PDF documents which use a JavaScript OpenAction object to run the IQY."
        Reference = "https://blog.inquest.net"  
  
    strings:
        $pdf_magic = "%PDF"
        $efile = /<<\/JavaScript [^\x3e]+\/EmbeddedFile/        
        $fspec = /<<\/Type\/Filespec\/F\(\w+\.iqy\)\/UF\(\w+\.iqy\)/
        $openaction = /OpenAction<<\/S\/JavaScript\/JS\(/
        
        /*
          <</Type/Filespec/F(10082016.iqy)/UF(10082016.iqy)/EF<</F 1 0 R/UF 1 0 R>>/Desc(10082016.iqy)>> 
          ...
          <</Names[(10082016.iqy) 2 0 R]>>
          ...
          <</JavaScript 9 0 R/EmbeddedFiles 10 0 R>>
          ...
          OpenAction<</S/JavaScript/JS(
        */
        
        /*
            obj 1.9
             Type: /EmbeddedFile
             Referencing:
             Contains stream
              <<
                /Length 51
                /Type /EmbeddedFile
                /Filter /FlateDecode
                /Params
                  <<
                    /ModDate "(D:20180810145018+03'00')"
                    /Size 45
                  >>
              >>
             WEB
            1
            http://i86h.com/data1.dat
            2
            3
            4
            5
        */
   
   condition:
      $pdf_magic in (0..60)  and all of them
}

rule Adobe_Flash_DRM_Use_After_Free
{    
    meta:
        note  = "This YARA rule is intended to run atop of decompiled Flash."

    strings:
        $as   = "package"
        $exp1 = "import com.adobe.tvsdk.mediacore" 	// covers .*
        $exp2 = "createDispatcher("
        $exp3 = "createMediaPlayer("
        $exp4 = "drmManager.initialize("    		// com.adobe.tvsdk.mediacore.DRMOperationCompleteListener;
        $vara_1 = "push(this)"
        $vara_2 = "push(null)"
        $vara_3 = /pop\(\)\..+\s*=\s*.+pop\(\)/
        $varb_1 = /push\([^\)]{1,24}drmManager.initialize/

        // all the requisite pieces in a single function.
        $varc_1 = /\{[^\}]+createDispatcher\s*\([^\}]+createMediaPlayer\s*\([^\}]+drmManager\.initialize\s*\([^\}]+=\s*null[^\}]+\}/

    condition:
        $as at 0 and all of ($exp*) and (all of ($vara*) or $varb_1 or $varc_1)
}
rule CVE_2018_4878_0day_ITW
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "This signature is mostly public sourced and detects an in-the-wild exploit for CVE-2018-4878."

    strings:
        $known1 = "F:\\work\\flash\\obfuscation\\loadswf\\src" nocase wide ascii
        $known2 = "G:\\FlashDeveloping" nocase wide ascii
        $known3 = "Z:\\Main\\zero day\\Troy" nocase wide ascii
        $known4 = "C:\\Users\\Rose\\Adobe Flash Builder 4.6\\ExpAll\\src" nocase wide ascii
        $known5 = "F:\\work\\flash\\obfuscation\\loadswf\\src" nocase wide ascii
        $known6 = "admincenter/files/boad/4/manager.php" nocase wide ascii

        // EMBEDDED FLASH OBJECT BIN HEADER
        $header = "rdf:RDF" wide ascii

        // OBJECT APPLICATION TYPE TITLE
        // disabled 2/13/18 due to false positive on 2a75ff1acdf9141bfb836343f94f4a73b8c64b226b0e2ae30a69e9aacc472cba
        // $title = "Adobe Flex" wide ascii

        // PDB PATH
        $pdb = "F:\\work\\flash\\obfuscation\\loadswf\\src" wide ascii

        // LOADER STRINGS
        $loader1 = "URLRequest" wide ascii
        $loader2 = "URLLoader" wide ascii
        $loader3 = "loadswf" wide ascii
        $loader4 = "myUrlReqest" wide ascii

        // 1a3269253784f76e3480e4b3de312dfee878f99045ccfd2231acb5ba57d8ed0d.fws exploit specific multivar definition.
        $observed_multivar_1 = /999(\x05[a-z]10[0-9][0-9]){100}/ nocase wide ascii
        $observed_multivar_2 = /999(\x05[a-z]11[0-9][0-9]){100}/ nocase wide ascii
        $flash_magic         = { (43 | 46 | 5A) 57 53 }

        // 53fa83d02cc60765a75abd0921f5084c03e0b7521a61c4260176e68b6a402834 exploit specific.
        $exp53_1 = "C:\\Users\\Miha\\AdobeMinePoC"
        $exp53_2 = "UAFGenerator"
        $exp53_3 = "shellcodBytes"
        $exp53_4 = "DRM_obj"
        $exp53_5 = "MainExp"

    condition:
        ($flash_magic at 0 and all of ($observed_multivar*))
            or
        (any of ($known*))
            or
        // disabled 2/13/18 due to false positive on 2a75ff1acdf9141bfb836343f94f4a73b8c64b226b0e2ae30a69e9aacc472cba
        //(all of ($header*) and all of ($title*) and 3 of ($loader*))
        //    or
        (all of ($pdb*) and all of ($header*) and 1 of ($loader*))
            or
        ($flash_magic at 0 and all of ($exp53*))
}
rule swfdoc_hunter
{
    strings:
        $a = { 6e db 7c d2 6d ae cf 11 96 b8 44 45 53 54 00 00 }
        $b = { 57 53 }
    condition:
        $a and $b and not (uint16be(0x0) == 0x4d5a)
}
rule shellcode_hash__CloseHandle {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  CloseHandle"
		mitre = "T1106"
	strings:
		$h_raw = "fb97fd0f" nocase
		$h_hex = { fb97fd0f }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__CreateFileA {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  CreateFileA"
		mitre = "T1106"
	strings:
		$h_raw = "a517007c" nocase
		$h_hex = { a517007c }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__CreateProcessA {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  CreateProcessA"
		mitre = "T1106"

	strings:
		$h_raw = "72feb316" nocase
		$h_hex = { 72feb316 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__DeleteFileA {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  DeleteFileA"
		mitre = "T1106"

	strings:
		$h_raw = "25b0ffc2" nocase
		$h_hex = { 25b0ffc2 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__ExitProcess {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  ExitProcess"
		mitre = "T1106"

	strings:
		$h_raw = "7ed8e273" nocase
		$h_hex = { 7ed8e273 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__ExitThread {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  ExitThread"
		mitre = "T1106"

	strings:
		$h_raw = "efcee060" nocase
		$h_hex = { efcee060 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__GetProcAddress {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  GetProcAddress"
		mitre = "T1129"

	strings:
		$h_raw = "aafc0d7c" nocase
		$h_hex = { aafc0d7c }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__GetSystemDirectoryA {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  GetSystemDirectoryA"
		mitre = "T1106"

	strings:
		$h_raw = "c179e5b8" nocase
		$h_hex = { c179e5b8 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash___hwrite {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  _hwrite"
		mitre = "T1106"

	strings:
		$h_raw = "d98a23e9" nocase
		$h_hex = { d98a23e9 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash___lclose {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  _lclose"
		mitre = "T1106"

	strings:
		$h_raw = "5b4c1add" nocase
		$h_hex = { 5b4c1add }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash___lcreat {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  _lcreat"
		mitre = "T1106"

	strings:
		$h_raw = "ea498ae8" nocase
		$h_hex = { ea498ae8 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__LoadLibraryA {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  LoadLibraryA"
		mitre = "T1129"

	strings:
		$h_raw = "8e4e0eec" nocase
		$h_hex = { 8e4e0eec }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash___lwrite {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  _lwrite"
		mitre = "T1106"

	strings:
		$h_raw = "db8a23e9" nocase
		$h_hex = { db8a23e9 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__SetUnhandledExceptionFilter {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  SetUnhandledExceptionFilter"
		mitre = "T1106"

	strings:
		$h_raw = "f08a045f" nocase
		$h_hex = { f08a045f }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__WaitForSingleObject {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  WaitForSingleObject"
		mitre = "T1106"

	strings:
		$h_raw = "add905ce" nocase
		$h_hex = { add905ce }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__WinExec {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  WinExec"
		mitre = "T1059.003"

	strings:
		$h_raw = "98fe8a0e" nocase
		$h_hex = { 98fe8a0e }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__WriteFile {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  WriteFile"
		mitre = "T1059"

	strings:
		$h_raw = "1f790ae8" nocase
		$h_hex = { 1f790ae8 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__accept {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  accept"
		mitre = "T1106"

	strings:
		$h_raw = "e5498649" nocase
		$h_hex = { e5498649 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__bind {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  bind"
		mitre = "T1106"

	strings:
		$h_raw = "a41a70c7" nocase
		$h_hex = { a41a70c7 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__closesocket {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  closesocket"
		mitre = "T1106"

	strings:
		$h_raw = "e779c679" nocase
		$h_hex = { e779c679 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__connect {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  connect"
		mitre = "T1106"

	strings:
		$h_raw = "ecf9aa60" nocase
		$h_hex = { ecf9aa60 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__listen {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  listen"
		mitre = "T1106"

	strings:
		$h_raw = "a4ad2ee9" nocase
		$h_hex = { a4ad2ee9 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__recv {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  recv"
		mitre = "T1106"

	strings:
		$h_raw = "b61918e7" nocase
		$h_hex = { b61918e7 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__send {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  send"
		mitre = "T1106"

	strings:
		$h_raw = "a41970e9" nocase
		$h_hex = { a41970e9 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__socket {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  socket"
		mitre = "T1106"

	strings:
		$h_raw = "6e0b2f49" nocase
		$h_hex = { 6e0b2f49 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__WSASocketA {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  WSASocketA"
		mitre = "T1106"

	strings:
		$h_raw = "d909f5ad" nocase
		$h_hex = { d909f5ad }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__WSAStartup {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  WSAStartup"
		mitre = "T1106"

	strings:
		$h_raw = "cbedfc3b" nocase
		$h_hex = { cbedfc3b }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__URLDownloadToFileA {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  URLDownloadToFileA"
		mitre = "T1106"

	strings:
		$h_raw = "361a2f70" nocase
		$h_hex = { 361a2f70 }

	condition:
		filesize < 1MB and any of them
}

rule suspicious_shellcode_NOP_Sled {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.shellcode NOP Sled"
		mitre = "T1106"

	strings:
		$h_raw = "9090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090" nocase
		$h_hex = { 9090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090 }

	condition:
		filesize < 1MB and any of them
}

rule suspicious_obfuscation_using_unescape {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using unescape"
		mitre = "T1027"
	strings:
		$h_reg1 = /une(.{0,6}?)sca(.{0,6}?)pe([^\)]{0,6}?)\(/
		$h_reg2 = /un(.{0,6}?)esc(.{0,6}?)ape([^\)]{0,6}?)\(/
		$h_reg3 = /unesc([\W]{0,6}?)ape/
		//$h_reg4 = /u([\W]{0,6}?)n([\W]{0,6}?)e([\W]{0,6}?)s([\W]{0,6}?)c([\W]{0,6}?)a([\W]{0,6}?)p([\W]{0,6}?)e/
		$h_reg5 = /unescape([^\)]{0,6}?)\(/
		$h_raw6 = "\"u\",\"s\",\"p\",\"c\",\"n\",\"e\",\"a\"," nocase
		$h_raw7 = "\"s\",\"n\",\"a\",\"e\",\"c\",\"u\",\"e\",\"p\"" nocase


	condition: any of them
}

/*
rule suspicious_obfuscation_using_charCodeAt {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using charCodeAt"
		mitre = "T1027"

	strings:
		$h_reg1 = /c([\W]{0,4}?)h([\W]{0,4}?)a([\W]{0,4}?)r([\W]{0,4}?)C([\W]{0,3}?)o([\W]{0,3}?)d([\W]{0,3}?)e([\W]{0,3}?)A(.{0,3}?)t/

	condition: any of them
}*/

rule suspicious_string_nopblock {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string nopblock"
		mitre = "T1027"

	strings:
		$h_raw1 = "nopblock" nocase

	condition: filesize < 1MB and any of them
}

rule suspicious_obfuscation_using_eval {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using eval"
		mitre = "T1027"

	strings:
		$h_reg1 = /eval(\s{0,3}?)\(/
		$h_raw2 = "eval\\" nocase
		$h_raw3 = "eval," nocase
		$h_reg4 = /'e'(.{1,30}?)'va'(.{1,3}?)'l/
		$h_raw5 = "\"l\",\"v\",\"e\",\"a\"" nocase
		$h_raw6 = "\"e\",\"l\",\"a\",\"v\"" nocase
		$h_reg7 = /=(\s{0,6}?)eval/

	condition: any of them
}

rule suspicious_javascript_object {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.javascript object"
		mitre = "T1027 T1059.007"

	strings:
		$h_raw1 = "/JavaScript" nocase
		$h_raw2 = "/JS " 

	condition: any of them
}
rule suspicious_EmbeddedFile_my_rule_object {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.javascript object"
		mitre = "T1027 T1059.007"

	strings:
		$embed = "EmbeddedFile"
	condition: 
		$embed
}
rule suspicious_javascript_in_XFA_block {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.javascript in XFA block"
		mitre = "T1027 T1059.007"

	strings:
		$h_raw1 = "application/x-javascript" nocase
		$h_raw2 = "application#2Fx-javascript" nocase
		//$h_reg3 = /(\&\#0*97;|a)(\&\#0*112;|p)(\&\#0*112;|p)(\&\#0*108;|l)(\&\#0*105;|i)(\&\#0*99;|c)(\&\#0*97;|a)(\&\#0*116;|t)(\&\#0*105;|i)(\&\#0*111;|o)(\&\#0*110;|n)(\&\#0*47;|\/)(\&\#0*120;|x)(\&\#0*45;|\-)(\&\#0*106;|j)(\&\#0*97;|a)(\&\#0*76;|v)(\&\#0*97;|a)(\&\#0*115;|s)(\&\#0*99;|c)(\&\#0*114;|r)(\&\#0*105;|i)(\&\#0*112;|p)(\&\#0*116;|t)/

	condition: any of them
}

rule suspicious_pdf_embedded_PDF_file {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.pdf embedded PDF file"
		mitre = "T1204.002"
	strings:
		$h_raw1 = "application#2Fpdf" nocase

	condition: any of them
}

rule suspicious_obfuscation_toString {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation toString"
		mitre = "T1027"

	strings:
		$h_raw1 = "toString(" nocase

	condition: filesize < 1MB and any of them
}

rule suspicious_obfuscation_using_substr {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using substr"
		mitre = "T1027"

	strings:
		$h_raw1 = "substr(" nocase

	condition: filesize < 1MB and any of them
}

rule suspicious_obfuscation_using_String_replace {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using String.replace"
		mitre = "T1027"

	strings:
		$h_reg1 = /'re'(.{1,24}?)'place'/
		$h_raw2 = ".replace" nocase

	condition: filesize < 1MB and any of them
}

rule suspicious_obfuscation_using_String_fromCharCode {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using String.fromCharCode"
		mitre = "T1027"

	strings:
		$h_raw1 = "\"rCo\",\"t\",\"cha\",\"\",\"deA\"" nocase
		$h_raw2 = "\"deA\",\"cha\",\"rCo\",\"t\"" nocase
		$h_reg3 = /from([\W]{0,6}?)C([\W]{0,6}?)h([\W]{0,6}?)a(.{0,6}?)r(.{0,6}?)C(.{0,6}?)o([\W]{0,6}?)d([\W]{0,6}?)e/
		$h_raw4 = ".fromCharC" nocase

	condition: any of them
}

rule suspicious_obfuscation_using_substring {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using substring"
		mitre = "T1027"

	strings:
		$h_reg1 = /\.substring(\s{0,3}?)\(/

	condition: filesize < 1MB and any of them
}

rule suspicious_obfuscation_using_util_byteToChar {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using util.byteToChar"
		mitre = "T1027"
	strings:
		$h_raw1 = "byteToChar" nocase

	condition: filesize < 1MB and any of them
}

rule suspicious_string_Shellcode_NOP_sled {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string Shellcode NOP sled"
		mitre = "T1027"

	strings:
		$h_raw1 = "%u9090" nocase

	condition: filesize < 1MB and any of them
}

rule suspicious_string_heap_spray_shellcode {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string heap spray shellcode"
		mitre = "T1027"

	strings:
		$h_raw1 = "\"%\" + \"u\" + \"0\" + \"c\" + \"0\" + \"c\" + \"%u\" + \"0\" + \"c\" + \"0\" + \"c\"" nocase

	condition: any of them
}

rule suspicious_string_shellcode {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string shellcode"
		mitre = "T1027"

	strings:
		$h_raw1 = "%u4141%u4141" nocase

	condition: filesize < 1MB and any of them
}

rule suspicious_string__Run_Sploit_ {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string -Run_Sploit-"
		mitre = "T1027"

	strings:
		$h_raw1 = "Run_Sploit" nocase

	condition: filesize < 1MB and any of them
}

rule suspicious_string__HeapSpray_ {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string -HeapSpray-"
		mitre = "T1027"

	strings:
		$h_raw1 = "HeapSpray" nocase

	condition: filesize < 1MB and any of them
}

rule suspicious_flash_writeMultiByte {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.flash writeMultiByte"
		mitre = "T1027"

	strings:
		$h_raw1 = "writeMultiByte" nocase

	condition: filesize < 1MB and any of them
}

rule suspicious_flash_addFrameScript {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.flash addFrameScript"
		mitre = "T1027"

	strings:
		$h_raw1 = "addFrameScript" nocase

	condition: filesize < 1MB and any of them
}

rule suspicious_flash_Adobe_Shockwave_Flash_in_a_PDF_define_obj_type {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.flash Adobe Shockwave Flash in a PDF define obj type"
	strings:
		$h_hex1 = { (52|233532) (69|233639) (63|233633) (68|233638) (4D|233444|233464) (65|233635) (64|233634) (69|233639)(61|233631) }

	condition: any of them
}

rule suspicious_flash_obfuscated_name {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.flash obfuscated name"
		mitre = "T1027"
	strings:
		$h_raw1 = "/R#69chM#65#64ia#53e#74ti#6e#67#73/" nocase

	condition: any of them
}

rule pdf_exploit_FlateDecode_Stream_Predictor_02_Integer_Overflow_CVE_2009_3459 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit FlateDecode Stream Predictor 02 Integer Overflow CVE-2009-3459"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /Predictor 02(\s{0,2}?)\/(\s{0,2}?)Colors 1073741838/

	condition: any of them
}

rule pdf_exploit_colors_number_is_high_CVE_2009_3459 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit colors number is high CVE-2009-3459"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /\/Colors \d{5,15}?/

	condition: any of them
}

rule pdf_exploit_URI_directory_traversal {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit URI directory traversal"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /URI.{1,30}?\/\.\.\/\.\./

	condition: any of them
}

rule pdf_exploit_URI_directory_traversal_system32 {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit URI directory traversal system32"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /URI.{1,65}?system32/

	condition: any of them
}

rule pdf_exploit_execute_EXE_file {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 10
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit execute EXE file"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /\/(A|#41)(c|#63)(t|#74)(i|#69)(o|#6F)(n|6e)(.{0,64}?)\.exe/
	condition: any of them
}


rule pdf_warning_openaction {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 1
		revision = "1"
		date = "July 14 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.warning OpenAction"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /\/(O|#4F)(p|#70)(e|#65)(n|#6e)(A|#41)(c|#63)(t|#74)(i|#69)(o|#6F)(n|6e)/
	condition: any of them
}


rule pdf_exploit_access_system32_directory {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit access system32 directory"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /\/(A|#41)(c|#63)(t|#74)(i|#69)(o|#6F)(n|6e)(.{0,64}?)system32/

	condition: any of them
}


rule pdf_warning_remote_action {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_active"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit action uri"
		mitre = "T1566.002"
	strings:
		$h_reg1 = /\/(A|#41)(c|#63)(t|#74)(i|#69)(o|#6F)(n|6e)\s*\/(U|#55)(R|#52)(I|49)/
		$h_reg2 = /\/(A|#41)(c|#63)(t|#74)(i|#69)(o|#6F)(n|6e)\s*\/(S|#53)\s*\/(U|#55)(R|#52)(I|49)/


	condition: any of them
}




rule pdf_exploit_execute_action_command {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit execute action command"
		mitre = "T1203 T1204.002"

	strings:
		$h_raw1 = "Launch/Type/Action/Win" nocase

	condition: any of them
}

rule pdf_exploit_printSeps_memory_heap_corruption_CVE_2010_4091 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit printSeps memory heap corruption CVE-2010-4091"
		mitre = "T1203 T1204.002"

	strings:
		$h_raw1 = "printSeps" nocase

	condition: filesize < 1MB and any of them
}

rule suspicious_obfuscation_jjencoded_javascript {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation jjencoded javascript"
		mitre = "T1059.007"
	strings:
		$h_raw1 = ":++$,$$$$:" nocase
		$h_raw2 = "$$:++$,$$$" nocase

	condition: any of them
}

rule suspicious_obfuscation_getAnnots_access_blocks {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation getAnnots access blocks"
		mitre = "T1059.007"

	strings:
        $h_hex1 = {67 [0-2] 65 [0-2] 74 [0-2] 41 [0-2] 6E [0-2] 6E [0-2] 6F [0-2] 74}

        $h_str2 = "getAnnots" nocase ascii wide
		//$h_reg1 = /g(\W{0,2}?)e(\W{0,2}?)t(\W{0,2}?)A([\W]{0,2}?)n([\W]{0,1}?)n([\W]{0,2}?)o([\W]{0,2}?)t/ //slow

	condition: any of them
}

rule suspicious_obfuscation_info_Trailer_to_access_blocks {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation info.Trailer to access blocks"
		mitre = "T1059.007"

	strings:
		$h_reg1 = /info([\W]{0,4}?)\.([\W]{0,4}?)Trailer/

	condition: any of them
}

rule suspicious_obfuscation_using_app_setTimeOut_to_eval_code {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using app.setTimeOut to eval code"
		mitre = "T1059.007"

	strings:
		$h_raw1 = "app.setTimeOut" nocase

	condition: any of them
}

rule suspicious_string__shellcode_ {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string -shellcode-"
		mitre = "T1027 T1059.007"
	strings:
		$h_raw1 = "var shellcode" nocase

	condition: any of them
}

rule pdf_exploit_Collab_collectEmailInfo_CVE_2008_0655 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit Collab.collectEmailInfo CVE-2008-0655"
		mitre = "T1203 T1204.002"
	strings:
		$h_reg1 = /Collabb([\W]{0,6}?).([\W]{0,6}?)collectEmailInfo/
		$h_raw2 = "CollabcollectEmailInfo" nocase
		$h_raw3 = "Collab.collectEmailInfo" nocase

	condition: any of them
}

rule pdf_exploit_Collab_getIcon_CVE_2009_0927 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit Collab.getIcon CVE-2009-0927"
		mitre = "T1203 T1204.002"
	strings:
		$h_reg1 = /Collab([\W]{0,6}?).([\W]{0,6}?)getIcon/
		$h_reg2 = /Collab.get(.{1,24}?)Icon/
		$h_raw3 = "Collab.getIcon" nocase

	condition: any of them
}

rule pdf_suspicious_util_printd_used_to_fill_buffers {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.suspicious util.printd used to fill buffers"
		mitre = "T1027 T1059.007"
	strings:
		$h_raw1 = "util.printd" nocase

	condition: any of them
}

rule pdf_exploit_media_newPlayer_CVE_2009_4324 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit media.newPlayer CVE-2009-4324"
		mitre = "T1203 T1204.002"
	strings:
		$h_reg1 = /med(.{1,24}?)ia(.{1,24}?)new(.{1,24}?)Play(.{1,24}?)er/
		$h_reg2 = /med(.{1,24}?)ia(.{1,24}?)newPlay(.{1,24}?)er/
		$h_reg3 = /me(.{1,24}?)dia\.(.{1,24}?)new(.{1,24}?)Play(.{1,24}?)er/
		$h_reg4 = /mediaa([\W]{0,6}?)newPlayer/
		$h_reg5 = /media(.{1,24}?)newPlayer/
		$h_raw6 = "media.newPlayer" nocase

	condition: any of them
}

rule pdf_exploit_spell_customDictionaryOpen_CVE_2009_1493 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit spell.customDictionaryOpen CVE-2009-1493"
		mitre = "T1203 T1204.002"
	strings:
		$h_reg1 = /spell(.{1,24}?)customDictionaryOpen/
		$h_raw2 = "spell.customDictionaryOpen" nocase

	condition: any of them
}

rule pdf_exploit_util_printf_CVE_2008_2992 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit util.printf CVE-2008-2992"
		mitre = "T1203 T1204.002"
	strings:
		$h_reg1 = /util(.{1,24}?)printf(.{1,24}?)45000f/

	condition: any of them
}

rule pdf_exploit_using_TIFF_overflow_CVE_2010_0188 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit using TIFF overflow CVE-2010-0188"
		mitre = "T1203 T1204.002"
	strings:
		$h_reg1 = /contentType=(.{0,6}?)image\/(.{0,30}?)CQkJCQkJCQkJCQkJCQkJCQkJ/
		$h_raw2 = "kJCQ,kJCQ,kJCQ,kJCQ,kJCQ,kJCQ" nocase

	condition: any of them
}

rule suspicious_string_TIFF_overflow_exploit_tif_name_CVE_2010_0188 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string TIFF overflow exploit.tif name CVE-2010-0188"
		mitre = "T1203 T1204.002"
	strings:
		$h_raw1 = "exploit.tif" nocase

	condition: any of them
}

rule suspicious_string_base_64_nop_sled_used_in_TIFF_overflow_CVE_2010_0188 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string base 64 nop sled used in TIFF overflow CVE-2010-0188"
		mitre = "T1203 T1204.002"
	strings:
		$h_raw1 = "JCQkJCQkJCQkJCQkJCQkJCQkJCQk" nocase
		$h_raw2 = "TU0AKgAAIDgMkAyQDJAMkAyQDJAMk" nocase
        $h_hex3 = { 4A [1-2] 43 [1-2] 51 [1-2] 6B [1-2] 4A [1-2] 43 [1-2] 51 [1-2] 6B}
		//$h_reg3 = /J.{1,2}?C.{1,2}?Q.{1,2}?k.{1,2}?J.{1,2}?C.{1,2}?Q.{1,2}?k.{1,2}?J.{1,2}?C.{1,2}?Q.{1,2}?k/ //slow
		$h_raw4 = "+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4" nocase

	condition: any of them
}

rule pdf_exploit_TIFF_overflow_CVE_2010_0188 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit TIFF overflow CVE-2010-0188"
		mitre = "T1203 T1204.002"
	strings:
		$h_reg1 = /ImageField1(.{0,6}?)xfa:contentType=(.{0,6}?)image\/tif/
		$h_hex2 = {BB1500070003FE7FB27F0007BB15000711000100ACA80007BB15000700010100ACA80007F772000711000100E2520007545C0007FFFFFFFF000101000000000004010100001000004000000031D70007BB1500075A526A024D15000722A70007BB15000758CD2E3C4D15000722A70007BB150007055A74F44D15000722A70007BB150007B849492A4D15000722A70007BB150007008BFAAF4D15000722A70007BB15000775EA87FE4D15000722A70007BB150007EB0A5FB94D15000722A70007BB150007}

	condition: any of them
}


rule pdf_execute_access_system32_directory {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.execute access system32 directory"
		mitre = "T1203 T1204.002"
	strings:
		$h_reg1 = /\/(A|#41)(c|#63)(t|#74)(i|#69)(o|#6F)(n|6e)(.{0,36}?)system32/

	condition: any of them
}

rule suspicious_string_obfuscated_unicode_NOP_sled {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string obfuscated unicode NOP sled"
		mitre = "T1027"
	strings:
		$h_raw1 = "M9090M9090M9090M9090" nocase

	condition: any of them
}

rule suspicious_flash_Embedded_Flash {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.flash Embedded Flash"
	strings:
		$h_reg1 = /^FWS/
		$h_reg2 = /^CWS/
		$h_reg3 = /^SWF/
		$h_hex4 = {0D0A43575309A2D20000789CECBD797C54}
		$h_reg5 = /\x0aFWS/
		$h_reg6 = /\x0aCWS/
		$h_reg7 = /\x0aSWF/


	condition: any of them
}

rule suspicious_flash_Embedded_Flash_define_obj {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.flash Embedded Flash define obj"
		mitre = "T1204.002"
	strings:
		$h_raw1 = "application#2Fx-shockwave-flash" nocase
		$h_raw2 = "application/x-shockwave-flash" nocase

	condition: any of them
}

rule pdf_exploit_fontfile_SING_table_overflow_CVE_2010_2883_generic {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit fontfile SING table overflow CVE-2010-2883 generic"
		mitre = "T1203 T1204.002"
	strings:
		$h_reg1 = "SING" nocase
		$h_hex2 = { 41414141414141414141 }

	condition: $h_reg1 in (0..400) and $h_hex2 in (0..500)
}

rule pdf_exploit_fontfile_SING_table_overflow_CVE_2010_2883_A {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit fontfile SING table overflow CVE-2010-2883 A"
		mitre = "T1203 T1204.002"
	strings:
		$h_hex1 = {1045086F0000EB4C00000024686D747809C68EB20000B4C4000004306B65726EDC52D5990000BDA000002D8A6C6F6361F3CBD23D0000BB840000021A6D6178700547063A0000EB2C0000002053494E47D9BCC8B50000011C00001DDF706F7374B45A2FBB0000B8F40000028E70726570}

	condition: any of them
}

rule flash_exploit_CVE_2011_0609 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "flash.exploit CVE-2011-0609"
		mitre = "T1203 T1204.002"
	strings:
		$h_hex1 = {4657530947CB0000480140005A0000190100441108000000BF141CCB0000000000000010002E00060080804094A8D0A001808004100002000000121212E24130F00931343134313431343134313431343134313431343134313431343134313431343134313431343134313431343134313431343134}
		$h_hex2 = {34363537353330394541433730303030373830303036343030303030304338303030303032443031303034343131313830303030303034333032463446344634383630363036303230303031303030304646303931303030303030303033303030313030383630363036303130303032303030303430303030303030424631313235}
		$h_hex3 = {3941303139413031394130313941303139064C6F61646572}

	condition: any of them
}

rule flash_exploit_CVE_2011_0611 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "flash.exploit CVE-2011-0611"
		mitre = "T1203 T1204.002"
	strings:
		$h_hex1 = {7772697465427974650541727261799817343635373533304143433035303030303738}
		$h_hex2 = {5131645443737746414142346E453155625778545A52512B743733742B3362744B4E30596E617767552F414452654D5848334777597276757737597A643743674A734A6C76643174374E716D393959576D4B676B5A7674686C68446942556E344D694645453030514659306D456F664A2B4F45504D55594E6F69614C526D4E696A4D45494444665065652B3139663534652B35356E764F63383578376532766732514551504148514C6B45384248683175303937414B7741654943394F6A336579756277574E52793141564A475939326D4777444832794278794147636569424250524348}
		$h_hex3 = {343635373533304143433035303030303738303030353546303030303046413030303030313830313030343431313030303030303030334630334137303530303030393630433030303530303037393543333743313330374642433337433133304531323944303230303443303439443032303031383030383831353030303930303431}
		$h_hex4 = {3063306330633063306330633063306306537472696E6706}
		$h_hex5 = {410042004300440045004600470048004900A18E110064656661756C74}
		$h_hex6 = {00414243444500566B6475686752656D686677317375727772777C73680064656661756C740067657453697A650047647768317375727772777C73680077777273757277}
		$h_raw7 = "AAB4AAVfAAAPoAAAGAEARBEAAAAAPwOnBQAAlgwABQAHlcN8Ewf7w3wTDhKdAgBMBJ0CABgAiBUACQBBAEIAQwBEAEUARgBHAEgASQChjhEAZGVmYXVsdAABAAQqAAIAmAGWCgAHWMBJSAenP7a3YJ0CAAAAmQIASQBAlgUABxZ0cAtMYp0CAAwAhwEAAxeHAQABlgoAB" nocase

	condition: any of them 
}

rule flash_suspicious_jit_spray {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "flash.suspicious jit_spray"
		mitre = "T1027 T1059.007"
	strings:
		$h_hex1 = {076A69745F65676708}

	condition: any of them
}

rule pdf_exploit_U3D_CVE_2011_2462_A {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit U3D CVE-2011-2462 A"
		mitre = "T1203 T1204.002"
	strings:
		$h_hex1 = {066F3A40AE366A4360DFCBEF8C38CA0492794B79E942BD2BB95B866065A4750119DACF6AF72A773CDEF1117533D394744A14734B18A166C20FDE3DED19D4322E}

	condition: any of them
}

rule pdf_exploit_PRC_CVE_2011_4369_A {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit PRC CVE-2011-4369 A"
		mitre = "T1203 T1204.002"
	strings:
		$h_hex1 = {ED7C7938945DF8FF9985868677108DA58C922C612A516FA9D182374A8B868AA25284242D8A3296B497B74849D2A210D14EA94654A2452ACA2B29D18268A5B7C5EF7E}

	condition: any of them
}

rule flash_exploit_flash_calling_malformed_MP4_CVE_2012_0754 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "flash.exploit flash calling malformed MP4 CVE-2012-0754"
		mitre = "T1203 T1204.002"
	strings:
		$h_hex1 = {537472696E6706586D6C537766094D6F766965436C6970076A69745F656767086368696C645265660D446973706C61794F626A656374074D79566964656F05566964656F044D794E430D4E6574436F6E6E656374696F6E}

	condition: any of them
}

rule flash_exploit_MP4_Loader_CVE_2012_0754_B {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "flash.exploit MP4 Loader CVE-2012-0754 B"
		mitre = "T1203 T1204.002"
	strings:
		$h_hex1 = {6D703405566964656F0A6E6574436F6E6E6563740D4E6574436F6E6E656374696F6E096E657453747265616D094E657453747265616D}

	condition: any of them
}

rule flash_exploit_MP4_CVE_2012_0754 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "flash.exploit MP4 CVE-2012-0754"
		mitre = "T1203 T1204.002"
	strings:
		$h_hex1 = {6D70343269736F6D000000246D646174018080800E1180808009029F0F808080020001C0101281302A056DC00000000D63707274}

	condition: any of them
}

rule pdf_exploit_Sandbox_Bypass_CVE_2013_0641 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit Sandbox Bypass CVE-2013-0641"
		mitre = "T1203 T1204.002"
	strings:
		$h_reg1 = /push(.{1,5}?)xfa.datasets.createNode(.{1,5}?)dataValue/

	condition: any of them
}

rule pdf_exploit_BMP_RLE_integer_heap_overflow_CVE_2013_2729 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit BMP RLE integer heap overflow CVE-2013-2729"
		mitre = "T1203 T1204.002"
	strings:
		$h_reg1 = /image.jpeg(.{1,5}?)Qk0AAAAAAAAAAAAAAABAAAAALAEAAAEAAAABAAgAAQAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAUkdC/
		$h_raw2 = "<image>Qk0AAAAAAAAAAAAAAABAAAAALAEAAAEAAAABAAgAAQAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAUkdC" nocase

	condition: any of them
}

rule pdf_exploit_ToolButton_use_after_free_CVE_2014_0496 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit ToolButton use-after-free CVE-2014-0496"
		mitre = "T1203 T1204.002"
	strings:
		$h_reg1 = /function(.{1,24}?)app.addToolButton/
		$h_reg2 = /function(.{1,24}?)app.removeToolButton/

	condition: any of them
}

rule suspicious_javascript_addToolButton {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.javascript addToolButton"
		mitre = "T1059.007"
	strings:
		$h_raw1 = "app.addToolButton" nocase

	condition: any of them
}

rule suspicious_embedded_doc_file {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded doc file"
		mitre = "T1204.002"
	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.doc/

	condition: any of them
}

rule suspicious_embedded_xls_file {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded xls file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.xls/

	condition: any of them
}

rule suspicious_embedded_ppt_file {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded ppt file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.ppt/
		$h_reg2 = /\/Type\/Filespec\/F(.{1,30}?)\.pps/

	condition: any of them
}

rule suspicious_embedded_scr_file {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded scr file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.scr/

	condition: any of them
}

rule suspicious_embedded_exe_file {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded exe file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.exe/

	condition: any of them
}

rule suspicious_embedded_bat_file {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded bat file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.bat/

	condition: any of them
}

rule suspicious_embedded_rtf_file {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded rtf file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.rtf/

	condition: any of them
}

rule suspicious_embedded_mso_file {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded mso file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.mso/

	condition: any of them
}

rule suspicious_embedded_html_file {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded html file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.htm/

	condition: any of them
}

rule suspicious_embedded_OLE_document_header {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded OLE document header"
		mitre = "T1204.002"

	strings:
		$h_reg1 = { d0 cf 11 e0}

	condition: $h_reg1 at 0
}

rule suspicious_embedded_external_content {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded external content"
		mitre = "T1566.002"
	strings:
		$h_raw1 = "/S /URI" nocase

	condition: any of them
}

rule pdf_exploit_Corrupted_JPEG2000_CVE_2018_4990 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit Corrupted JPEG2000 CVE-2018-4990"
		mitre = "T1203 T1204.002"
	strings:
		$h_hex1 = { 0C6A5020 200D0A87 0A000004 1D6A7032 68000000 16696864 72000000 20000000 200001FF 07000000 0003FC63 6D617000 }
	condition: $h_hex1
}


rule pdf_exploit_using_jbig2decode_CVE_2009_0658 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "July 20 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit using JBIG2Decode CVE-2009-0658"
		mitre = "T1203 T1204.002"
		url = "https://www.exploit-db.com/exploits/8099"
	strings:
		$h_raw1 = "JBIG2Decode" nocase
		$h_raw2 = "Decode [ 1 0 ]"
		$h_raw3 = "ABCD\x13"

	condition: all of them
}
