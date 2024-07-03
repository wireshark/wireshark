/** @file
 *
 * Declarations for IANA-registered character sets
 *
 *    http://www.iana.org/assignments/character-sets/character-sets.xhtml
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * WAP dissector based on original work by Ben Fowler
 * Updated by Neil Hunter <neil.hunter@energis-squared.com>
 * WTLS support by Alexandre P. Ferreira (Splice IP)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __IANA_CHARSETS_H__
#define __IANA_CHARSETS_H__

/* Map a MIBenum code for a charset to a Wireshark string encoding. */
WS_DLL_PUBLIC unsigned mibenum_charset_to_encoding (unsigned charset);

/* value_string_ext table of names for MIBenum codes */
WS_DLL_PUBLIC value_string_ext mibenum_vals_character_sets_ext;

/* Basic macro for creating iana charset or Wireshark supported string encoding
 * enumeration type, enum_val_t or value_string array.
 *
 * ZZZ is a record selection macro. If ZZZ is ICWE_SELECT_ALL then select all records,
 * or ICWE_SELECT_N1 then select records marked with '1' and ignore all records
 * marked with '0'. (The prefix of macro 'ICWE' is abrev of "IANA Charset and Wireshark Encoding")
 *
 * YYY is a column selection macro. For example, if YYY is ICWE_MAP_TO_VS_RECORD then choose
 * column 1+2+3 for defining xxx_VALUE_STRING_LIST.
 *
 * XXX is the final macro to expand the VALUE_STRING, ENUM_VAL_T or other type records
 * to enumeration type, value_string array, enum_val_t array or other codes.
 *
 * The fields of record "ZZZ(1, YYY(XXX, IANA_CS_US_ASCII, 3, "US-ASCII", ENC_NA|_DEFAULT_WS_ENC))"
 * means:
 *   - "ZZZ(1..."       -- means this is Wireshark supported charset encoding. 0 means not supported.
 *                         This mark tag (or called group id) can be extended to support 0, 1, 2, 3,
 *                         and etc, if we need to create more different value_string or enum_val_t
 *                         array about the iana charsets in the future by defining selector like this:
 *                               #define ICWE_SELECT_N1_N3(N, ...)  ICWE_SELECT_N1_N2_##N(__VA_ARGS__)
 *                               #define ICWE_SELECT_N1_N3_0(...)
 *                               #define ICWE_SELECT_N1_N3_1(...)   __VA_ARGS__
 *                               #define ICWE_SELECT_N1_N3_2(...)
 *                               #define ICWE_SELECT_N1_N3_3(...)   __VA_ARGS__
 *   - IANA_CS_US_ASCII -- is the enumeration name.
 *   - 3                -- is the IANA enum number of "US-ASCII".
 *   - "US-ASCII"       -- is the preferred name of IANA charset.
 *   - ENC_NA|_DEFAULT_WS_ENC -- is the corresponding Wireshark encoding.
 *
 * The IANA charset updated from 10/04/2012 version.
 */
#define _DEFAULT_WS_ENC  ENC_ASCII
#define IANA_CHARSETS_WS_ENCODING_MAP_LIST(XXX, YYY, ZZZ) \
    ZZZ(1, YYY(XXX, IANA_CS_US_ASCII,                     3, "US-ASCII",            ENC_NA|ENC_ASCII)) \
    ZZZ(1, YYY(XXX, IANA_CS_ISO_8859_1,                   4, "ISO-8859-1",          ENC_NA|ENC_ISO_8859_1)) \
    ZZZ(1, YYY(XXX, IANA_CS_ISO_8859_2,                   5, "ISO-8859-2",          ENC_NA|ENC_ISO_8859_2)) \
    ZZZ(1, YYY(XXX, IANA_CS_ISO_8859_3,                   6, "ISO-8859-3",          ENC_NA|ENC_ISO_8859_3)) \
    ZZZ(1, YYY(XXX, IANA_CS_ISO_8859_4,                   7, "ISO-8859-4",          ENC_NA|ENC_ISO_8859_4)) \
    ZZZ(1, YYY(XXX, IANA_CS_ISO_8859_5,                   8, "ISO-8859-5",          ENC_NA|ENC_ISO_8859_5)) \
    ZZZ(1, YYY(XXX, IANA_CS_ISO_8859_6,                   9, "ISO-8859-6",          ENC_NA|ENC_ISO_8859_6)) \
    ZZZ(1, YYY(XXX, IANA_CS_ISO_8859_7,                  10, "ISO-8859-7",          ENC_NA|ENC_ISO_8859_7)) \
    ZZZ(1, YYY(XXX, IANA_CS_ISO_8859_8,                  11, "ISO-8859-8",          ENC_NA|ENC_ISO_8859_8)) \
    ZZZ(1, YYY(XXX, IANA_CS_ISO_8859_9,                  12, "ISO-8859-9",          ENC_NA|ENC_ISO_8859_9)) \
    ZZZ(1, YYY(XXX, IANA_CS_ISO_8859_10,                 13, "ISO-8859-10",         ENC_NA|ENC_ISO_8859_10)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_6937_2_ADD,              14, "ISO_6937-2-add",      ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_JIS_X0201,                   15, "JIS_X0201",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_JIS_ENCODING,                16, "JIS_Encoding",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_SHIFT_JIS,                   17, "Shift_JIS",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EUC_JP,                      18, "EUC-JP",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EXTENDED_UNIX_CODE_FIXED_WIDTH_FOR_JAPANESE, 19, "Extended_UNIX_Code_Fixed_Width_for_Japanese", ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_BS_4730,                     20, "BS_4730",             ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_SEN_850200_C,                21, "SEN_850200_C",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IT,                          22, "IT",                  ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ES,                          23, "ES",                  ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_DIN_66003,                   24, "DIN_66003",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_NS_4551_1,                   25, "NS_4551-1",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_NF_Z_62_010,                 26, "NF_Z_62-010",         ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_10646_UTF_1,             27, "ISO-10646-UTF-1",     ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_646_BASIC_1983,          28, "ISO_646.basic:1983",  ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_INVARIANT,                   29, "INVARIANT",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_646_IRV_1983,            30, "ISO_646.irv:1983",    ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_NATS_SEFI,                   31, "NATS-SEFI",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_NATS_SEFI_ADD,               32, "NATS-SEFI-ADD",       ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_NATS_DANO,                   33, "NATS-DANO",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_NATS_DANO_ADD,               34, "NATS-DANO-ADD",       ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_SEN_850200_B,                35, "SEN_850200_B",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_KS_C_5601_1987,              36, "KS_C_5601-1987",      ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_2022_KR,                 37, "ISO-2022-KR",         ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(1, YYY(XXX, IANA_CS_EUC_KR,                      38, "EUC-KR",              ENC_NA|ENC_EUC_KR)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_2022_JP,                 39, "ISO-2022-JP",         ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_2022_JP_2,               40, "ISO-2022-JP-2",       ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_JIS_C6220_1969_JP,           41, "JIS_C6220-1969-jp",   ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_JIS_C6220_1969_RO,           42, "JIS_C6220-1969-ro",   ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_PT,                          43, "PT",                  ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_GREEK7_OLD,                  44, "greek7-old",          ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_LATIN_GREEK,                 45, "latin-greek",         ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_NF_Z_62_010_1973,            46, "NF_Z_62-010_(1973)",  ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_LATIN_GREEK_1,               47, "Latin-greek-1",       ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_5427,                    48, "ISO_5427",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_JIS_C6226_1978,              49, "JIS_C6226-1978",      ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_BS_VIEWDATA,                 50, "BS_viewdata",         ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_INIS,                        51, "INIS",                ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_INIS_8,                      52, "INIS-8",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_INIS_CYRILLIC,               53, "INIS-cyrillic",       ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_5427_1981,               54, "ISO_5427:1981",       ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_5428_1980,               55, "ISO_5428:1980",       ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_GB_1988_80,                  56, "GB_1988-80",          ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_GB_2312_80,                  57, "GB_2312-80",          ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_NS_4551_2,                   58, "NS_4551-2",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_VIDEOTEX_SUPPL,              59, "videotex-suppl",      ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_PT2,                         60, "PT2",                 ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ES2,                         61, "ES2",                 ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_MSZ_7795_3,                  62, "MSZ_7795.3",          ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_JIS_C6226_1983,              63, "JIS_C6226-1983",      ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_GREEK7,                      64, "greek7",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ASMO_449,                    65, "ASMO_449",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_IR_90,                   66, "iso-ir-90",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_JIS_C6229_1984_A,            67, "JIS_C6229-1984-a",    ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_JIS_C6229_1984_B,            68, "JIS_C6229-1984-b",    ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_JIS_C6229_1984_B_ADD,        69, "JIS_C6229-1984-b-add",ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_JIS_C6229_1984_HAND,         70, "JIS_C6229-1984-hand", ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_JIS_C6229_1984_HAND_ADD,     71, "JIS_C6229-1984-hand-add", ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_JIS_C6229_1984_KANA,         72, "JIS_C6229-1984-kana", ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_2033_1983,               73, "ISO_2033-1983",       ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ANSI_X3_110_1983,            74, "ANSI_X3.110-1983",    ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_T_61_7BIT,                   75, "T.61-7bit",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_T_61_8BIT,                   76, "T.61-8bit",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ECMA_CYRILLIC,               77, "ECMA-cyrillic",       ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_CSA_Z243_4_1985_1,           78, "CSA_Z243.4-1985-1",   ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_CSA_Z243_4_1985_2,           79, "CSA_Z243.4-1985-2",   ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_CSA_Z243_4_1985_GR,          80, "CSA_Z243.4-1985-gr",  ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_8859_6_E,                81, "ISO-8859-6-E",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_8859_6_I,                82, "ISO-8859-6-I",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_T_101_G2,                    83, "T.101-G2",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_8859_8_E,                84, "ISO-8859-8-E",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_8859_8_I,                85, "ISO-8859-8-I",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_CSN_369103,                  86, "CSN_369103",          ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_JUS_I_B1_002,                87, "JUS_I.B1.002",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IEC_P27_1,                   88, "IEC_P27-1",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_JUS_I_B1_003_SERB,           89, "JUS_I.B1.003-serb",   ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_JUS_I_B1_003_MAC,            90, "JUS_I.B1.003-mac",    ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_GREEK_CCITT,                 91, "greek-ccitt",         ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_NC_NC00_10_81,               92, "NC_NC00-10:81",       ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_6937_2_25,               93, "ISO_6937-2-25",       ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_GOST_19768_74,               94, "GOST_19768-74",       ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_8859_SUPP,               95, "ISO_8859-supp",       ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_10367_BOX,               96, "ISO_10367-box",       ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_LATIN_LAP,                   97, "latin-lap",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_JIS_X0212_1990,              98, "JIS_X0212-1990",      ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_DS_2089,                     99, "DS_2089",             ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_US_DK,                      100, "us-dk",               ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_DK_US,                      101, "dk-us",               ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_KSC5636,                    102, "KSC5636",             ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_UNICODE_1_1_UTF_7,          103, "UNICODE-1-1-UTF-7",   ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_2022_CN,                104, "ISO-2022-CN",         ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_2022_CN_EXT,            105, "ISO-2022-CN-EXT",     ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(1, YYY(XXX, IANA_CS_UTF_8,                      106, "UTF-8",               ENC_NA|ENC_UTF_8)) \
    ZZZ(1, YYY(XXX, IANA_CS_ISO_8859_13,                109, "ISO-8859-13",         ENC_NA|ENC_ISO_8859_13)) \
    ZZZ(1, YYY(XXX, IANA_CS_ISO_8859_14,                110, "ISO-8859-14",         ENC_NA|ENC_ISO_8859_14)) \
    ZZZ(1, YYY(XXX, IANA_CS_ISO_8859_15,                111, "ISO-8859-15",         ENC_NA|ENC_ISO_8859_15)) \
    ZZZ(1, YYY(XXX, IANA_CS_ISO_8859_16,                112, "ISO-8859-16",         ENC_NA|ENC_ISO_8859_16)) \
    ZZZ(1, YYY(XXX, IANA_CS_GBK,                        113, "GBK",                 ENC_NA|ENC_GB18030)) \
    ZZZ(1, YYY(XXX, IANA_CS_GB18030,                    114, "GB18030",             ENC_NA|ENC_GB18030)) \
    ZZZ(0, YYY(XXX, IANA_CS_OSD_EBCDIC_DF04_15,         115, "OSD_EBCDIC_DF04_15",  ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_OSD_EBCDIC_DF03_IRV,        116, "OSD_EBCDIC_DF03_IRV", ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_OSD_EBCDIC_DF04_1,          117, "OSD_EBCDIC_DF04_1",   ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_11548_1,                118, "ISO-11548-1",         ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_KZ_1048,                    119, "KZ-1048",             ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(1, YYY(XXX, IANA_CS_ISO_10646_UCS_2,           1000, "ISO-10646-UCS-2",     ENC_BIG_ENDIAN|ENC_UCS_2)) \
    ZZZ(1, YYY(XXX, IANA_CS_ISO_10646_UCS_4,           1001, "ISO-10646-UCS-4",     ENC_BIG_ENDIAN|ENC_UCS_4)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_10646_UCS_BASIC,       1002, "ISO-10646-UCS-Basic", ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_10646_UNICODE_LATIN1,  1003, "ISO-10646-Unicode-Latin1", ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_10646_J_1,             1004, "ISO-10646-J-1",       ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_UNICODE_IBM_1261,      1005, "ISO-Unicode-IBM-1261",ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_UNICODE_IBM_1268,      1006, "ISO-Unicode-IBM-1268",ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_UNICODE_IBM_1276,      1007, "ISO-Unicode-IBM-1276",ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_UNICODE_IBM_1264,      1008, "ISO-Unicode-IBM-1264",ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_UNICODE_IBM_1265,      1009, "ISO-Unicode-IBM-1265",ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_UNICODE_1_1,               1010, "UNICODE-1-1",         ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_SCSU,                      1011, "SCSU",                ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_UTF_7,                     1012, "UTF-7",               ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(1, YYY(XXX, IANA_CS_UTF_16BE,                  1013, "UTF-16BE",            ENC_BIG_ENDIAN|ENC_UTF_16)) \
    ZZZ(1, YYY(XXX, IANA_CS_UTF_16LE,                  1014, "UTF-16LE",            ENC_LITTLE_ENDIAN|ENC_UTF_16)) \
    ZZZ(1, YYY(XXX, IANA_CS_UTF_16,                    1015, "UTF-16",              ENC_LITTLE_ENDIAN|ENC_BOM|ENC_UTF_16)) \
    ZZZ(0, YYY(XXX, IANA_CS_CESU_8,                    1016, "CESU-8",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_UTF_32,                    1017, "UTF-32",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_UTF_32BE,                  1018, "UTF-32BE",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_UTF_32LE,                  1019, "UTF-32LE",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_BOCU_1,                    1020, "BOCU-1",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_UTF_7_IMAP,                1021, "UTF-7-IMAP",          ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_8859_1_WINDOWS_3_0_LATIN_1, 2000, "ISO-8859-1-Windows-3.0-Latin-1", ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_8859_1_WINDOWS_3_1_LATIN_1, 2001, "ISO-8859-1-Windows-3.1-Latin-1", ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_8859_2_WINDOWS_LATIN_2,2002, "ISO-8859-2-Windows-Latin-2", ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ISO_8859_9_WINDOWS_LATIN_5,2003, "ISO-8859-9-Windows-Latin-5", ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_HP_ROMAN8,                 2004, "hp-roman8",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ADOBE_STANDARD_ENCODING,   2005, "Adobe-Standard-Encoding", ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_VENTURA_US,                2006, "Ventura-US",          ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_VENTURA_INTERNATIONAL,     2007, "Ventura-International", ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_DEC_MCS,                   2008, "DEC-MCS",             ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM850,                    2009, "IBM850",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM852,                    2010, "IBM852",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(1, YYY(XXX, IANA_CS_IBM437,                    2011, "IBM437",              ENC_NA|ENC_CP437)) \
    ZZZ(0, YYY(XXX, IANA_CS_PC8_DANISH_NORWEGIAN,      2012, "PC8-Danish-Norwegian",ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM862,                    2013, "IBM862",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_PC8_TURKISH,               2014, "PC8-Turkish",         ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM_SYMBOLS,               2015, "IBM-Symbols",         ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM_THAI,                  2016, "IBM-Thai",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_HP_LEGAL,                  2017, "HP-Legal",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_HP_PI_FONT,                2018, "HP-Pi-font",          ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_HP_MATH8,                  2019, "HP-Math8",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_ADOBE_SYMBOL_ENCODING,     2020, "Adobe-Symbol-Encoding", ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_HP_DESKTOP,                2021, "HP-DeskTop",          ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_VENTURA_MATH,              2022, "Ventura-Math",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_MICROSOFT_PUBLISHING,      2023, "Microsoft-Publishing",ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_WINDOWS_31J,               2024, "Windows-31J",         ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(1, YYY(XXX, IANA_CS_GB2312,                    2025, "GB2312",              ENC_NA|ENC_GB18030)) \
    ZZZ(0, YYY(XXX, IANA_CS_BIG5,                      2026, "Big5",                ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_MACINTOSH,                 2027, "macintosh",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(1, YYY(XXX, IANA_CS_IBM037,                    2028, "IBM037",              ENC_NA|ENC_EBCDIC_CP037)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM038,                    2029, "IBM038",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM273,                    2030, "IBM273",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM274,                    2031, "IBM274",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM275,                    2032, "IBM275",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM277,                    2033, "IBM277",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM278,                    2034, "IBM278",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM280,                    2035, "IBM280",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM281,                    2036, "IBM281",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM284,                    2037, "IBM284",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM285,                    2038, "IBM285",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM290,                    2039, "IBM290",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM297,                    2040, "IBM297",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM420,                    2041, "IBM420",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM423,                    2042, "IBM423",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM424,                    2043, "IBM424",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(1, YYY(XXX, IANA_CS_IBM500,                    2044, "IBM500",              ENC_NA|ENC_EBCDIC_CP500)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM851,                    2045, "IBM851",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(1, YYY(XXX, IANA_CS_IBM855,                    2046, "IBM855",              ENC_NA|ENC_CP855)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM857,                    2047, "IBM857",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM860,                    2048, "IBM860",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM861,                    2049, "IBM861",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM863,                    2050, "IBM863",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM864,                    2051, "IBM864",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM865,                    2052, "IBM865",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM868,                    2053, "IBM868",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM869,                    2054, "IBM869",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM870,                    2055, "IBM870",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM871,                    2056, "IBM871",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM880,                    2057, "IBM880",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM891,                    2058, "IBM891",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM903,                    2059, "IBM903",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM904,                    2060, "IBM904",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM905,                    2061, "IBM905",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM918,                    2062, "IBM918",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM1026,                   2063, "IBM1026",             ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EBCDIC_AT_DE,              2064, "EBCDIC-AT-DE",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EBCDIC_AT_DE_A,            2065, "EBCDIC-AT-DE-A",      ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EBCDIC_CA_FR,              2066, "EBCDIC-CA-FR",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EBCDIC_DK_NO,              2067, "EBCDIC-DK-NO",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EBCDIC_DK_NO_A,            2068, "EBCDIC-DK-NO-A",      ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EBCDIC_FI_SE,              2069, "EBCDIC-FI-SE",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EBCDIC_FI_SE_A,            2070, "EBCDIC-FI-SE-A",      ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EBCDIC_FR,                 2071, "EBCDIC-FR",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EBCDIC_IT,                 2072, "EBCDIC-IT",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EBCDIC_PT,                 2073, "EBCDIC-PT",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EBCDIC_ES,                 2074, "EBCDIC-ES",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EBCDIC_ES_A,               2075, "EBCDIC-ES-A",         ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EBCDIC_ES_S,               2076, "EBCDIC-ES-S",         ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EBCDIC_UK,                 2077, "EBCDIC-UK",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_EBCDIC_US,                 2078, "EBCDIC-US",           ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_UNKNOWN_8BIT,              2079, "UNKNOWN-8BIT",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_MNEMONIC,                  2080, "MNEMONIC",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_MNEM,                      2081, "MNEM",                ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_VISCII,                    2082, "VISCII",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_VIQR,                      2083, "VIQR",                ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_KOI8_R,                    2084, "KOI8-R",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_HZ_GB_2312,                2085, "HZ-GB-2312",          ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(1, YYY(XXX, IANA_CS_IBM866,                    2086, "IBM866",              ENC_NA|ENC_CP866)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM775,                    2087, "IBM775",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_KOI8_U,                    2088, "KOI8-U",              ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM00858,                  2089, "IBM00858",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM00924,                  2090, "IBM00924",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM01140,                  2091, "IBM01140",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM01141,                  2092, "IBM01141",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM01142,                  2093, "IBM01142",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM01143,                  2094, "IBM01143",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM01144,                  2095, "IBM01144",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM01145,                  2096, "IBM01145",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM01146,                  2097, "IBM01146",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM01147,                  2098, "IBM01147",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM01148,                  2099, "IBM01148",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM01149,                  2100, "IBM01149",            ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_BIG5_HKSCS,                2101, "Big5-HKSCS",          ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_IBM1047,                   2102, "IBM1047",             ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_PTCP154,                   2103, "PTCP154",             ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_AMIGA_1251,                2104, "Amiga-1251",          ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_KOI7_SWITCHED,             2105, "KOI7-switched",       ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_BRF,                       2106, "BRF",                 ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_TSCII,                     2107, "TSCII",               ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_CP51932,                   2108, "CP51932",             ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_WINDOWS_874,               2109, "windows-874",         ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_WINDOWS_1250,              2250, "windows-1250",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_WINDOWS_1251,              2251, "windows-1251",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_WINDOWS_1252,              2252, "windows-1252",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_WINDOWS_1253,              2253, "windows-1253",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_WINDOWS_1254,              2254, "windows-1254",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_WINDOWS_1255,              2255, "windows-1255",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_WINDOWS_1256,              2256, "windows-1256",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_WINDOWS_1257,              2257, "windows-1257",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(0, YYY(XXX, IANA_CS_WINDOWS_1258,              2258, "windows-1258",        ENC_NA|_DEFAULT_WS_ENC)) \
    ZZZ(1, YYY(XXX, IANA_CS_TIS_620,                   2259, "TIS-620",             ENC_NA|ENC_ISO_8859_11)) \
    ZZZ(0, YYY(XXX, IANA_CS_CP50220,                   2260, "CP50220",             ENC_NA|_DEFAULT_WS_ENC))
/*  ZZZ(Mark,....., IANA_ENUM,                     IANA_VAL, IANA_NAME,             WIRESHARK_ENCODING */

/* RFC 2781 suggests that 1015 "UTF-16" (UTF-16 with BOM) SHOULD be
 * interpreted as ENC_BIG_ENDIAN if the BOM is missing, but in practice
 * it's more common to see the encoding as Little Endian, especially if
 * a BOM is expected.
 */

/* select all records */
#define ICWE_SELECT_ALL(N, ...)   ICWE_SELECT_ALL_##N(__VA_ARGS__)
#define ICWE_SELECT_ALL_0(...)    __VA_ARGS__
#define ICWE_SELECT_ALL_1(...)    __VA_ARGS__

/* ignore records marked 0 and only select records marked 1 */
#define ICWE_SELECT_N1(N, ...)   ICWE_SELECT_N1_##N(__VA_ARGS__)
#define ICWE_SELECT_N1_0(...)
#define ICWE_SELECT_N1_1(...)    __VA_ARGS__

/* convert iana charset and Wireshark encoding map to value_string macro record and passing to XXX macro */
#define ICWE_MAP_TO_VS_RECORD(XXX, ic_enum_name, ic_enum_val, ic_name, ws_enc) XXX(ic_enum_name, ic_enum_val, ic_name)

/* convert iana charset and Wireshark encoding map to enum_val_t macro record and passing to XXX macro */
#define ICWE_MAP_TO_EV_RECORD(XXX, ic_enum_name, ic_enum_val, ic_name, ws_enc) XXX(ic_enum_name, ic_enum_val, ic_name, ic_name)

/* convert iana charset and Wireshark encoding map to enum value only map and passing to XXX macro */
#define ICWE_MAP_TO_ENUM_MAP_ONLY(XXX, ic_enum_name, ic_enum_val, ic_name, ws_enc)  XXX(ic_enum_val, ws_enc)

/* macro used for creating iana charset enumeration type, value_string array and enum_val_t array */
#define mibenum_vals_character_sets_VALUE_STRING_LIST(XXX) IANA_CHARSETS_WS_ENCODING_MAP_LIST(XXX, ICWE_MAP_TO_VS_RECORD, ICWE_SELECT_ALL)

/* macro used for creating Wireshark supported displaying iana charset enum_val_t array */
#define ws_supported_mibenum_vals_character_sets_VALUE_STRING_LIST(XXX) IANA_CHARSETS_WS_ENCODING_MAP_LIST(XXX, ICWE_MAP_TO_VS_RECORD, ICWE_SELECT_N1)

/* define iana charset enumeration type */
typedef VALUE_STRING_ENUM(mibenum_vals_character_sets) mibenum_vals_character_sets_type_t;

/* declare an iana charset enum_val_t array named mibenum_vals_character_sets_ev_array */
VS_LIST_TO_ENUM_VAL_T_ARRAY_GLOBAL_DCL(mibenum_vals_character_sets_ev_array);

/* declare an short and Wireshark supported iana charset enum_val_t array */
VS_LIST_TO_ENUM_VAL_T_ARRAY_GLOBAL_DCL(ws_supported_mibenum_vals_character_sets_ev_array);

#endif /* iana_charsets.h */
