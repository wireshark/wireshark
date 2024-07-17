/* packet-sbas_l1.c
 * SBAS L1 protocol dissection.
 *
 * By Timo Warns <timo.warns@gmail.com>
 * Copyright 2023 Timo Warns
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>

#include <wsutil/pint.h>
#include <wsutil/utf8_entities.h>

#include "packet-ubx.h"
#include "packet-sbas_l1.h"

/*
 * Dissects navigation messages of the Satellite Based Augmentation System
 * (SBAS) sent on L1 frequency as defined by ICAO Annex 10, Vol I.
 */

// SBAS L1 preamble values
#define SBAS_L1_PREAMBLE_1 0x53
#define SBAS_L1_PREAMBLE_2 0x9a
#define SBAS_L1_PREAMBLE_3 0xc6

// SBAS service provider identifier mapping
// see ICAO Annex 10, Vol I, Table B-27
static const value_string SBAS_SPID[] = {
    {0, "WAAS"},
    {1, "EGNOS"},
    {2, "MSAS"},
    {0, NULL}
};

// UDREI_i mapping
// see ICAO Annex 10, Vol I, Table B-29
const value_string UDREI_EVALUATION[] = {
    {0,  "0.0520 m" UTF8_SUPERSCRIPT_TWO},
    {1,  "0.0924 m" UTF8_SUPERSCRIPT_TWO},
    {2,  "0.1444 m" UTF8_SUPERSCRIPT_TWO},
    {3,  "0.2830 m" UTF8_SUPERSCRIPT_TWO},
    {4,  "0.4678 m" UTF8_SUPERSCRIPT_TWO},
    {5,  "0.8315 m" UTF8_SUPERSCRIPT_TWO},
    {6,  "1.2992 m" UTF8_SUPERSCRIPT_TWO},
    {7,  "1.8709 m" UTF8_SUPERSCRIPT_TWO},
    {8,  "2.5465 m" UTF8_SUPERSCRIPT_TWO},
    {9,  "3.3260 m" UTF8_SUPERSCRIPT_TWO},
    {10, "5.1968 m" UTF8_SUPERSCRIPT_TWO},
    {11, "20.7870 m" UTF8_SUPERSCRIPT_TWO},
    {12, "230.9661 m" UTF8_SUPERSCRIPT_TWO},
    {13, "2078.695 m" UTF8_SUPERSCRIPT_TWO},
    {14, "Not Monitored"},
    {15, "Do Not Use"},
    {0,  NULL}
};

// GIVEI_i mapping
// see ICAO Annex 10, Vol I, Table B-33
static const value_string GIVEI_EVALUATION[] = {
    {0,  "0.0084 m" UTF8_SUPERSCRIPT_TWO},
    {1,  "0.0333 m" UTF8_SUPERSCRIPT_TWO},
    {2,  "0.0749 m" UTF8_SUPERSCRIPT_TWO},
    {3,  "0.1331 m" UTF8_SUPERSCRIPT_TWO},
    {4,  "0.2079 m" UTF8_SUPERSCRIPT_TWO},
    {5,  "0.2994 m" UTF8_SUPERSCRIPT_TWO},
    {6,  "0.4075 m" UTF8_SUPERSCRIPT_TWO},
    {7,  "0.5322 m" UTF8_SUPERSCRIPT_TWO},
    {8,  "0.6735 m" UTF8_SUPERSCRIPT_TWO},
    {9,  "0.8315 m" UTF8_SUPERSCRIPT_TWO},
    {10, "1.1974 m" UTF8_SUPERSCRIPT_TWO},
    {11, "1.8709 m" UTF8_SUPERSCRIPT_TWO},
    {12, "3.3260 m" UTF8_SUPERSCRIPT_TWO},
    {13, "20.787 m" UTF8_SUPERSCRIPT_TWO},
    {14, "187.0826 m" UTF8_SUPERSCRIPT_TWO},
    {15, "Not Monitored"},
    {0,  NULL}
};

// Mapping for fast correction degradation factor
// see ICAO Annex 10, Vol I, Table B-34
static const value_string DEGRADATION_FACTOR_INDICATOR[] = {
    {0,  "0.0 mm/s" UTF8_SUPERSCRIPT_TWO},
    {1,  "0.05 mm/s" UTF8_SUPERSCRIPT_TWO},
    {2,  "0.09 mm/s" UTF8_SUPERSCRIPT_TWO},
    {3,  "0.12 mm/s" UTF8_SUPERSCRIPT_TWO},
    {4,  "0.15 mm/s" UTF8_SUPERSCRIPT_TWO},
    {5,  "0.20 mm/s" UTF8_SUPERSCRIPT_TWO},
    {6,  "0.30 mm/s" UTF8_SUPERSCRIPT_TWO},
    {7,  "0.45 mm/s" UTF8_SUPERSCRIPT_TWO},
    {8,  "0.60 mm/s" UTF8_SUPERSCRIPT_TWO},
    {9,  "0.90 mm/s" UTF8_SUPERSCRIPT_TWO},
    {10, "1.50 mm/s" UTF8_SUPERSCRIPT_TWO},
    {11, "2.10 mm/s" UTF8_SUPERSCRIPT_TWO},
    {12, "2.70 mm/s" UTF8_SUPERSCRIPT_TWO},
    {13, "3.30 mm/s" UTF8_SUPERSCRIPT_TWO},
    {14, "4.60 mm/s" UTF8_SUPERSCRIPT_TWO},
    {15, "5.80 mm/s" UTF8_SUPERSCRIPT_TWO},
    {0,  NULL}
};

// table for SBAS L1 CRC24Q computation
static const uint32_t CRC24Q_TBL[] = {
    0x000000, 0x864CFB, 0x8AD50D, 0x0C99F6, 0x93E6E1, 0x15AA1A, 0x1933EC, 0x9F7F17,
    0xA18139, 0x27CDC2, 0x2B5434, 0xAD18CF, 0x3267D8, 0xB42B23, 0xB8B2D5, 0x3EFE2E,
    0xC54E89, 0x430272, 0x4F9B84, 0xC9D77F, 0x56A868, 0xD0E493, 0xDC7D65, 0x5A319E,
    0x64CFB0, 0xE2834B, 0xEE1ABD, 0x685646, 0xF72951, 0x7165AA, 0x7DFC5C, 0xFBB0A7,
    0x0CD1E9, 0x8A9D12, 0x8604E4, 0x00481F, 0x9F3708, 0x197BF3, 0x15E205, 0x93AEFE,
    0xAD50D0, 0x2B1C2B, 0x2785DD, 0xA1C926, 0x3EB631, 0xB8FACA, 0xB4633C, 0x322FC7,
    0xC99F60, 0x4FD39B, 0x434A6D, 0xC50696, 0x5A7981, 0xDC357A, 0xD0AC8C, 0x56E077,
    0x681E59, 0xEE52A2, 0xE2CB54, 0x6487AF, 0xFBF8B8, 0x7DB443, 0x712DB5, 0xF7614E,
    0x19A3D2, 0x9FEF29, 0x9376DF, 0x153A24, 0x8A4533, 0x0C09C8, 0x00903E, 0x86DCC5,
    0xB822EB, 0x3E6E10, 0x32F7E6, 0xB4BB1D, 0x2BC40A, 0xAD88F1, 0xA11107, 0x275DFC,
    0xDCED5B, 0x5AA1A0, 0x563856, 0xD074AD, 0x4F0BBA, 0xC94741, 0xC5DEB7, 0x43924C,
    0x7D6C62, 0xFB2099, 0xF7B96F, 0x71F594, 0xEE8A83, 0x68C678, 0x645F8E, 0xE21375,
    0x15723B, 0x933EC0, 0x9FA736, 0x19EBCD, 0x8694DA, 0x00D821, 0x0C41D7, 0x8A0D2C,
    0xB4F302, 0x32BFF9, 0x3E260F, 0xB86AF4, 0x2715E3, 0xA15918, 0xADC0EE, 0x2B8C15,
    0xD03CB2, 0x567049, 0x5AE9BF, 0xDCA544, 0x43DA53, 0xC596A8, 0xC90F5E, 0x4F43A5,
    0x71BD8B, 0xF7F170, 0xFB6886, 0x7D247D, 0xE25B6A, 0x641791, 0x688E67, 0xEEC29C,
    0x3347A4, 0xB50B5F, 0xB992A9, 0x3FDE52, 0xA0A145, 0x26EDBE, 0x2A7448, 0xAC38B3,
    0x92C69D, 0x148A66, 0x181390, 0x9E5F6B, 0x01207C, 0x876C87, 0x8BF571, 0x0DB98A,
    0xF6092D, 0x7045D6, 0x7CDC20, 0xFA90DB, 0x65EFCC, 0xE3A337, 0xEF3AC1, 0x69763A,
    0x578814, 0xD1C4EF, 0xDD5D19, 0x5B11E2, 0xC46EF5, 0x42220E, 0x4EBBF8, 0xC8F703,
    0x3F964D, 0xB9DAB6, 0xB54340, 0x330FBB, 0xAC70AC, 0x2A3C57, 0x26A5A1, 0xA0E95A,
    0x9E1774, 0x185B8F, 0x14C279, 0x928E82, 0x0DF195, 0x8BBD6E, 0x872498, 0x016863,
    0xFAD8C4, 0x7C943F, 0x700DC9, 0xF64132, 0x693E25, 0xEF72DE, 0xE3EB28, 0x65A7D3,
    0x5B59FD, 0xDD1506, 0xD18CF0, 0x57C00B, 0xC8BF1C, 0x4EF3E7, 0x426A11, 0xC426EA,
    0x2AE476, 0xACA88D, 0xA0317B, 0x267D80, 0xB90297, 0x3F4E6C, 0x33D79A, 0xB59B61,
    0x8B654F, 0x0D29B4, 0x01B042, 0x87FCB9, 0x1883AE, 0x9ECF55, 0x9256A3, 0x141A58,
    0xEFAAFF, 0x69E604, 0x657FF2, 0xE33309, 0x7C4C1E, 0xFA00E5, 0xF69913, 0x70D5E8,
    0x4E2BC6, 0xC8673D, 0xC4FECB, 0x42B230, 0xDDCD27, 0x5B81DC, 0x57182A, 0xD154D1,
    0x26359F, 0xA07964, 0xACE092, 0x2AAC69, 0xB5D37E, 0x339F85, 0x3F0673, 0xB94A88,
    0x87B4A6, 0x01F85D, 0x0D61AB, 0x8B2D50, 0x145247, 0x921EBC, 0x9E874A, 0x18CBB1,
    0xE37B16, 0x6537ED, 0x69AE1B, 0xEFE2E0, 0x709DF7, 0xF6D10C, 0xFA48FA, 0x7C0401,
    0x42FA2F, 0xC4B6D4, 0xC82F22, 0x4E63D9, 0xD11CCE, 0x575035, 0x5BC9C3, 0xDD8538
};

/* Initialize the protocol and registered fields */
static int proto_sbas_l1;

// see ICAO Annex 10, Vol I, Appendix B, Section 3.5.3
static int hf_sbas_l1_preamble;
static int hf_sbas_l1_mt;
static int hf_sbas_l1_chksum;

static int hf_sbas_l1_mt0;
static int hf_sbas_l1_mt0_spare_1;
static int hf_sbas_l1_mt0_spare_2;
static int hf_sbas_l1_mt0_spare_3;

// see ICAO Annex 10, Vol I, Table B-38
static int hf_sbas_l1_mt1;
static int hf_sbas_l1_mt1_prn_mask_gps;
static int hf_sbas_l1_mt1_prn_mask_glonass;
static int hf_sbas_l1_mt1_prn_mask_spare_1;
static int hf_sbas_l1_mt1_prn_mask_sbas;
static int hf_sbas_l1_mt1_prn_mask_spare_2;
static int hf_sbas_l1_mt1_iodp;

// see ICAO Annex 10, Vol I, Table B-39
static int hf_sbas_l1_mt2;
static int hf_sbas_l1_mt2_iodf_2;
static int hf_sbas_l1_mt2_iodp;
static int hf_sbas_l1_mt2_fc_1;
static int hf_sbas_l1_mt2_fc_2;
static int hf_sbas_l1_mt2_fc_3;
static int hf_sbas_l1_mt2_fc_4;
static int hf_sbas_l1_mt2_fc_5;
static int hf_sbas_l1_mt2_fc_6;
static int hf_sbas_l1_mt2_fc_7;
static int hf_sbas_l1_mt2_fc_8;
static int hf_sbas_l1_mt2_fc_9;
static int hf_sbas_l1_mt2_fc_10;
static int hf_sbas_l1_mt2_fc_11;
static int hf_sbas_l1_mt2_fc_12;
static int hf_sbas_l1_mt2_fc_13;
static int hf_sbas_l1_mt2_udrei_1;
static int hf_sbas_l1_mt2_udrei_2;
static int hf_sbas_l1_mt2_udrei_3;
static int hf_sbas_l1_mt2_udrei_4;
static int hf_sbas_l1_mt2_udrei_5;
static int hf_sbas_l1_mt2_udrei_6;
static int hf_sbas_l1_mt2_udrei_7;
static int hf_sbas_l1_mt2_udrei_8;
static int hf_sbas_l1_mt2_udrei_9;
static int hf_sbas_l1_mt2_udrei_10;
static int hf_sbas_l1_mt2_udrei_11;
static int hf_sbas_l1_mt2_udrei_12;
static int hf_sbas_l1_mt2_udrei_13;

// see ICAO Annex 10, Vol I, Table B-39
static int hf_sbas_l1_mt3;
static int hf_sbas_l1_mt3_iodf_3;
static int hf_sbas_l1_mt3_iodp;
static int hf_sbas_l1_mt3_fc_14;
static int hf_sbas_l1_mt3_fc_15;
static int hf_sbas_l1_mt3_fc_16;
static int hf_sbas_l1_mt3_fc_17;
static int hf_sbas_l1_mt3_fc_18;
static int hf_sbas_l1_mt3_fc_19;
static int hf_sbas_l1_mt3_fc_20;
static int hf_sbas_l1_mt3_fc_21;
static int hf_sbas_l1_mt3_fc_22;
static int hf_sbas_l1_mt3_fc_23;
static int hf_sbas_l1_mt3_fc_24;
static int hf_sbas_l1_mt3_fc_25;
static int hf_sbas_l1_mt3_fc_26;
static int hf_sbas_l1_mt3_udrei_14;
static int hf_sbas_l1_mt3_udrei_15;
static int hf_sbas_l1_mt3_udrei_16;
static int hf_sbas_l1_mt3_udrei_17;
static int hf_sbas_l1_mt3_udrei_18;
static int hf_sbas_l1_mt3_udrei_19;
static int hf_sbas_l1_mt3_udrei_20;
static int hf_sbas_l1_mt3_udrei_21;
static int hf_sbas_l1_mt3_udrei_22;
static int hf_sbas_l1_mt3_udrei_23;
static int hf_sbas_l1_mt3_udrei_24;
static int hf_sbas_l1_mt3_udrei_25;
static int hf_sbas_l1_mt3_udrei_26;

// see ICAO Annex 10, Vol I, Table B-39
static int hf_sbas_l1_mt4;
static int hf_sbas_l1_mt4_iodf_4;
static int hf_sbas_l1_mt4_iodp;
static int hf_sbas_l1_mt4_fc_27;
static int hf_sbas_l1_mt4_fc_28;
static int hf_sbas_l1_mt4_fc_29;
static int hf_sbas_l1_mt4_fc_30;
static int hf_sbas_l1_mt4_fc_31;
static int hf_sbas_l1_mt4_fc_32;
static int hf_sbas_l1_mt4_fc_33;
static int hf_sbas_l1_mt4_fc_34;
static int hf_sbas_l1_mt4_fc_35;
static int hf_sbas_l1_mt4_fc_36;
static int hf_sbas_l1_mt4_fc_37;
static int hf_sbas_l1_mt4_fc_38;
static int hf_sbas_l1_mt4_fc_39;
static int hf_sbas_l1_mt4_udrei_27;
static int hf_sbas_l1_mt4_udrei_28;
static int hf_sbas_l1_mt4_udrei_29;
static int hf_sbas_l1_mt4_udrei_30;
static int hf_sbas_l1_mt4_udrei_31;
static int hf_sbas_l1_mt4_udrei_32;
static int hf_sbas_l1_mt4_udrei_33;
static int hf_sbas_l1_mt4_udrei_34;
static int hf_sbas_l1_mt4_udrei_35;
static int hf_sbas_l1_mt4_udrei_36;
static int hf_sbas_l1_mt4_udrei_37;
static int hf_sbas_l1_mt4_udrei_38;
static int hf_sbas_l1_mt4_udrei_39;

// see ICAO Annex 10, Vol I, Table B-39
static int hf_sbas_l1_mt5;
static int hf_sbas_l1_mt5_iodf_5;
static int hf_sbas_l1_mt5_iodp;
static int hf_sbas_l1_mt5_fc_40;
static int hf_sbas_l1_mt5_fc_41;
static int hf_sbas_l1_mt5_fc_42;
static int hf_sbas_l1_mt5_fc_43;
static int hf_sbas_l1_mt5_fc_44;
static int hf_sbas_l1_mt5_fc_45;
static int hf_sbas_l1_mt5_fc_46;
static int hf_sbas_l1_mt5_fc_47;
static int hf_sbas_l1_mt5_fc_48;
static int hf_sbas_l1_mt5_fc_49;
static int hf_sbas_l1_mt5_fc_50;
static int hf_sbas_l1_mt5_fc_51;
static int hf_sbas_l1_mt5_fc_52;
static int hf_sbas_l1_mt5_udrei_40;
static int hf_sbas_l1_mt5_udrei_41;
static int hf_sbas_l1_mt5_udrei_42;
static int hf_sbas_l1_mt5_udrei_43;
static int hf_sbas_l1_mt5_udrei_44;
static int hf_sbas_l1_mt5_udrei_45;
static int hf_sbas_l1_mt5_udrei_46;
static int hf_sbas_l1_mt5_udrei_47;
static int hf_sbas_l1_mt5_udrei_48;
static int hf_sbas_l1_mt5_udrei_49;
static int hf_sbas_l1_mt5_udrei_50;
static int hf_sbas_l1_mt5_udrei_51;
static int hf_sbas_l1_mt5_udrei_52;

// see ICAO Annex 10, Vol I, Table B-40
static int hf_sbas_l1_mt6;
static int hf_sbas_l1_mt6_iodf_2;
static int hf_sbas_l1_mt6_iodf_3;
static int hf_sbas_l1_mt6_iodf_4;
static int hf_sbas_l1_mt6_iodf_5;
static int hf_sbas_l1_mt6_udrei_1;
static int hf_sbas_l1_mt6_udrei_2;
static int hf_sbas_l1_mt6_udrei_3;
static int hf_sbas_l1_mt6_udrei_4;
static int hf_sbas_l1_mt6_udrei_5;
static int hf_sbas_l1_mt6_udrei_6;
static int hf_sbas_l1_mt6_udrei_7;
static int hf_sbas_l1_mt6_udrei_8;
static int hf_sbas_l1_mt6_udrei_9;
static int hf_sbas_l1_mt6_udrei_10;
static int hf_sbas_l1_mt6_udrei_11;
static int hf_sbas_l1_mt6_udrei_12;
static int hf_sbas_l1_mt6_udrei_13;
static int hf_sbas_l1_mt6_udrei_14;
static int hf_sbas_l1_mt6_udrei_15;
static int hf_sbas_l1_mt6_udrei_16;
static int hf_sbas_l1_mt6_udrei_17;
static int hf_sbas_l1_mt6_udrei_18;
static int hf_sbas_l1_mt6_udrei_19;
static int hf_sbas_l1_mt6_udrei_20;
static int hf_sbas_l1_mt6_udrei_21;
static int hf_sbas_l1_mt6_udrei_22;
static int hf_sbas_l1_mt6_udrei_23;
static int hf_sbas_l1_mt6_udrei_24;
static int hf_sbas_l1_mt6_udrei_25;
static int hf_sbas_l1_mt6_udrei_26;
static int hf_sbas_l1_mt6_udrei_27;
static int hf_sbas_l1_mt6_udrei_28;
static int hf_sbas_l1_mt6_udrei_29;
static int hf_sbas_l1_mt6_udrei_30;
static int hf_sbas_l1_mt6_udrei_31;
static int hf_sbas_l1_mt6_udrei_32;
static int hf_sbas_l1_mt6_udrei_33;
static int hf_sbas_l1_mt6_udrei_34;
static int hf_sbas_l1_mt6_udrei_35;
static int hf_sbas_l1_mt6_udrei_36;
static int hf_sbas_l1_mt6_udrei_37;
static int hf_sbas_l1_mt6_udrei_38;
static int hf_sbas_l1_mt6_udrei_39;
static int hf_sbas_l1_mt6_udrei_40;
static int hf_sbas_l1_mt6_udrei_41;
static int hf_sbas_l1_mt6_udrei_42;
static int hf_sbas_l1_mt6_udrei_43;
static int hf_sbas_l1_mt6_udrei_44;
static int hf_sbas_l1_mt6_udrei_45;
static int hf_sbas_l1_mt6_udrei_46;
static int hf_sbas_l1_mt6_udrei_47;
static int hf_sbas_l1_mt6_udrei_48;
static int hf_sbas_l1_mt6_udrei_49;
static int hf_sbas_l1_mt6_udrei_50;
static int hf_sbas_l1_mt6_udrei_51;

// see ICAO Annex 10, Vol I, Table B-41
static int hf_sbas_l1_mt7;
static int hf_sbas_l1_mt7_t_lat;
static int hf_sbas_l1_mt7_iodp;
static int hf_sbas_l1_mt7_spare;
static int hf_sbas_l1_mt7_ai_1;
static int hf_sbas_l1_mt7_ai_2;
static int hf_sbas_l1_mt7_ai_3;
static int hf_sbas_l1_mt7_ai_4;
static int hf_sbas_l1_mt7_ai_5;
static int hf_sbas_l1_mt7_ai_6;
static int hf_sbas_l1_mt7_ai_7;
static int hf_sbas_l1_mt7_ai_8;
static int hf_sbas_l1_mt7_ai_9;
static int hf_sbas_l1_mt7_ai_10;
static int hf_sbas_l1_mt7_ai_11;
static int hf_sbas_l1_mt7_ai_12;
static int hf_sbas_l1_mt7_ai_13;
static int hf_sbas_l1_mt7_ai_14;
static int hf_sbas_l1_mt7_ai_15;
static int hf_sbas_l1_mt7_ai_16;
static int hf_sbas_l1_mt7_ai_17;
static int hf_sbas_l1_mt7_ai_18;
static int hf_sbas_l1_mt7_ai_19;
static int hf_sbas_l1_mt7_ai_20;
static int hf_sbas_l1_mt7_ai_21;
static int hf_sbas_l1_mt7_ai_22;
static int hf_sbas_l1_mt7_ai_23;
static int hf_sbas_l1_mt7_ai_24;
static int hf_sbas_l1_mt7_ai_25;
static int hf_sbas_l1_mt7_ai_26;
static int hf_sbas_l1_mt7_ai_27;
static int hf_sbas_l1_mt7_ai_28;
static int hf_sbas_l1_mt7_ai_29;
static int hf_sbas_l1_mt7_ai_30;
static int hf_sbas_l1_mt7_ai_31;
static int hf_sbas_l1_mt7_ai_32;
static int hf_sbas_l1_mt7_ai_33;
static int hf_sbas_l1_mt7_ai_34;
static int hf_sbas_l1_mt7_ai_35;
static int hf_sbas_l1_mt7_ai_36;
static int hf_sbas_l1_mt7_ai_37;
static int hf_sbas_l1_mt7_ai_38;
static int hf_sbas_l1_mt7_ai_39;
static int hf_sbas_l1_mt7_ai_40;
static int hf_sbas_l1_mt7_ai_41;
static int hf_sbas_l1_mt7_ai_42;
static int hf_sbas_l1_mt7_ai_43;
static int hf_sbas_l1_mt7_ai_44;
static int hf_sbas_l1_mt7_ai_45;
static int hf_sbas_l1_mt7_ai_46;
static int hf_sbas_l1_mt7_ai_47;
static int hf_sbas_l1_mt7_ai_48;
static int hf_sbas_l1_mt7_ai_49;
static int hf_sbas_l1_mt7_ai_50;
static int hf_sbas_l1_mt7_ai_51;

// see ICAO Annex 10, Vol I, Table B-45
static int hf_sbas_l1_mt17;
static int hf_sbas_l1_mt17_reserved;
static int hf_sbas_l1_mt17_prn;
static int hf_sbas_l1_mt17_health_and_status;
static int hf_sbas_l1_mt17_health_and_status_spid;
static int hf_sbas_l1_mt17_health_and_status_spare;
static int hf_sbas_l1_mt17_health_and_status_sat_status_basic_corrections;
static int hf_sbas_l1_mt17_health_and_status_precision_corrections;
static int hf_sbas_l1_mt17_health_and_status_ranging;
static int hf_sbas_l1_mt17_x_ga;
static int hf_sbas_l1_mt17_y_ga;
static int hf_sbas_l1_mt17_z_ga;
static int hf_sbas_l1_mt17_x_ga_vel;
static int hf_sbas_l1_mt17_y_ga_vel;
static int hf_sbas_l1_mt17_z_ga_vel;
static int hf_sbas_l1_mt17_t_a;

static int * const sbas_l1_mt17_health_and_status_fields[] = {
    &hf_sbas_l1_mt17_health_and_status_spid,
    &hf_sbas_l1_mt17_health_and_status_spare,
    &hf_sbas_l1_mt17_health_and_status_sat_status_basic_corrections,
    &hf_sbas_l1_mt17_health_and_status_precision_corrections,
    &hf_sbas_l1_mt17_health_and_status_ranging,
    NULL
};

// see ICAO Annex 10, Vol I, Table B-47
static int hf_sbas_l1_mt24;
static int hf_sbas_l1_mt24_fc_i1;
static int hf_sbas_l1_mt24_fc_i2;
static int hf_sbas_l1_mt24_fc_i3;
static int hf_sbas_l1_mt24_fc_i4;
static int hf_sbas_l1_mt24_fc_i5;
static int hf_sbas_l1_mt24_fc_i6;
static int hf_sbas_l1_mt24_udrei_i1;
static int hf_sbas_l1_mt24_udrei_i2;
static int hf_sbas_l1_mt24_udrei_i3;
static int hf_sbas_l1_mt24_udrei_i4;
static int hf_sbas_l1_mt24_udrei_i5;
static int hf_sbas_l1_mt24_udrei_i6;
static int hf_sbas_l1_mt24_iodp;
static int hf_sbas_l1_mt24_fc_type;
static int hf_sbas_l1_mt24_iodf_j;
static int hf_sbas_l1_mt24_spare;
static int hf_sbas_l1_mt24_velocity_code;
static int hf_sbas_l1_mt24_v0_prn_mask_nr_1;
static int hf_sbas_l1_mt24_v0_iod_1;
static int hf_sbas_l1_mt24_v0_delta_x_1;
static int hf_sbas_l1_mt24_v0_delta_y_1;
static int hf_sbas_l1_mt24_v0_delta_z_1;
static int hf_sbas_l1_mt24_v0_delta_a_1_f0;
static int hf_sbas_l1_mt24_v0_prn_mask_nr_2;
static int hf_sbas_l1_mt24_v0_iod_2;
static int hf_sbas_l1_mt24_v0_delta_x_2;
static int hf_sbas_l1_mt24_v0_delta_y_2;
static int hf_sbas_l1_mt24_v0_delta_z_2;
static int hf_sbas_l1_mt24_v0_delta_a_2_f0;
static int hf_sbas_l1_mt24_v0_iodp;
static int hf_sbas_l1_mt24_v0_spare;
static int hf_sbas_l1_mt24_v1_prn_mask_nr;
static int hf_sbas_l1_mt24_v1_iod;
static int hf_sbas_l1_mt24_v1_delta_x;
static int hf_sbas_l1_mt24_v1_delta_y;
static int hf_sbas_l1_mt24_v1_delta_z;
static int hf_sbas_l1_mt24_v1_delta_a_f0;
static int hf_sbas_l1_mt24_v1_delta_x_vel;
static int hf_sbas_l1_mt24_v1_delta_y_vel;
static int hf_sbas_l1_mt24_v1_delta_z_vel;
static int hf_sbas_l1_mt24_v1_delta_a_f1;
static int hf_sbas_l1_mt24_v1_t_lt;
static int hf_sbas_l1_mt24_v1_iodp;

// see ICAO Annex 10, Vol I, Table B-48
static int hf_sbas_l1_mt25;
static int hf_sbas_l1_mt25_h1_velocity_code;
static int hf_sbas_l1_mt25_h1_v0_prn_mask_nr_1;
static int hf_sbas_l1_mt25_h1_v0_iod_1;
static int hf_sbas_l1_mt25_h1_v0_delta_x_1;
static int hf_sbas_l1_mt25_h1_v0_delta_y_1;
static int hf_sbas_l1_mt25_h1_v0_delta_z_1;
static int hf_sbas_l1_mt25_h1_v0_delta_a_1_f0;
static int hf_sbas_l1_mt25_h1_v0_prn_mask_nr_2;
static int hf_sbas_l1_mt25_h1_v0_iod_2;
static int hf_sbas_l1_mt25_h1_v0_delta_x_2;
static int hf_sbas_l1_mt25_h1_v0_delta_y_2;
static int hf_sbas_l1_mt25_h1_v0_delta_z_2;
static int hf_sbas_l1_mt25_h1_v0_delta_a_2_f0;
static int hf_sbas_l1_mt25_h1_v0_iodp;
static int hf_sbas_l1_mt25_h1_v0_spare;
static int hf_sbas_l1_mt25_h1_v1_prn_mask_nr;
static int hf_sbas_l1_mt25_h1_v1_iod;
static int hf_sbas_l1_mt25_h1_v1_delta_x;
static int hf_sbas_l1_mt25_h1_v1_delta_y;
static int hf_sbas_l1_mt25_h1_v1_delta_z;
static int hf_sbas_l1_mt25_h1_v1_delta_a_f0;
static int hf_sbas_l1_mt25_h1_v1_delta_x_vel;
static int hf_sbas_l1_mt25_h1_v1_delta_y_vel;
static int hf_sbas_l1_mt25_h1_v1_delta_z_vel;
static int hf_sbas_l1_mt25_h1_v1_delta_a_f1;
static int hf_sbas_l1_mt25_h1_v1_t_lt;
static int hf_sbas_l1_mt25_h1_v1_iodp;
static int hf_sbas_l1_mt25_h2_velocity_code;
static int hf_sbas_l1_mt25_h2_v0_prn_mask_nr_1;
static int hf_sbas_l1_mt25_h2_v0_iod_1;
static int hf_sbas_l1_mt25_h2_v0_delta_x_1;
static int hf_sbas_l1_mt25_h2_v0_delta_y_1;
static int hf_sbas_l1_mt25_h2_v0_delta_z_1;
static int hf_sbas_l1_mt25_h2_v0_delta_a_1_f0;
static int hf_sbas_l1_mt25_h2_v0_prn_mask_nr_2;
static int hf_sbas_l1_mt25_h2_v0_iod_2;
static int hf_sbas_l1_mt25_h2_v0_delta_x_2;
static int hf_sbas_l1_mt25_h2_v0_delta_y_2;
static int hf_sbas_l1_mt25_h2_v0_delta_z_2;
static int hf_sbas_l1_mt25_h2_v0_delta_a_2_f0;
static int hf_sbas_l1_mt25_h2_v0_iodp;
static int hf_sbas_l1_mt25_h2_v0_spare;
static int hf_sbas_l1_mt25_h2_v1_prn_mask_nr;
static int hf_sbas_l1_mt25_h2_v1_iod;
static int hf_sbas_l1_mt25_h2_v1_delta_x;
static int hf_sbas_l1_mt25_h2_v1_delta_y;
static int hf_sbas_l1_mt25_h2_v1_delta_z;
static int hf_sbas_l1_mt25_h2_v1_delta_a_f0;
static int hf_sbas_l1_mt25_h2_v1_delta_x_vel;
static int hf_sbas_l1_mt25_h2_v1_delta_y_vel;
static int hf_sbas_l1_mt25_h2_v1_delta_z_vel;
static int hf_sbas_l1_mt25_h2_v1_delta_a_f1;
static int hf_sbas_l1_mt25_h2_v1_t_lt;
static int hf_sbas_l1_mt25_h2_v1_iodp;

// see ICAO Annex 10, Vol I, Table B-50
static int hf_sbas_l1_mt26;
static int hf_sbas_l1_mt26_igp_band_id;
static int hf_sbas_l1_mt26_igp_block_id;
static int hf_sbas_l1_mt26_igp_vertical_delay_est_1;
static int hf_sbas_l1_mt26_givei_1;
static int hf_sbas_l1_mt26_igp_vertical_delay_est_2;
static int hf_sbas_l1_mt26_givei_2;
static int hf_sbas_l1_mt26_igp_vertical_delay_est_3;
static int hf_sbas_l1_mt26_givei_3;
static int hf_sbas_l1_mt26_igp_vertical_delay_est_4;
static int hf_sbas_l1_mt26_givei_4;
static int hf_sbas_l1_mt26_igp_vertical_delay_est_5;
static int hf_sbas_l1_mt26_givei_5;
static int hf_sbas_l1_mt26_igp_vertical_delay_est_6;
static int hf_sbas_l1_mt26_givei_6;
static int hf_sbas_l1_mt26_igp_vertical_delay_est_7;
static int hf_sbas_l1_mt26_givei_7;
static int hf_sbas_l1_mt26_igp_vertical_delay_est_8;
static int hf_sbas_l1_mt26_givei_8;
static int hf_sbas_l1_mt26_igp_vertical_delay_est_9;
static int hf_sbas_l1_mt26_givei_9;
static int hf_sbas_l1_mt26_igp_vertical_delay_est_10;
static int hf_sbas_l1_mt26_givei_10;
static int hf_sbas_l1_mt26_igp_vertical_delay_est_11;
static int hf_sbas_l1_mt26_givei_11;
static int hf_sbas_l1_mt26_igp_vertical_delay_est_12;
static int hf_sbas_l1_mt26_givei_12;
static int hf_sbas_l1_mt26_igp_vertical_delay_est_13;
static int hf_sbas_l1_mt26_givei_13;
static int hf_sbas_l1_mt26_igp_vertical_delay_est_14;
static int hf_sbas_l1_mt26_givei_14;
static int hf_sbas_l1_mt26_igp_vertical_delay_est_15;
static int hf_sbas_l1_mt26_givei_15;
static int hf_sbas_l1_mt26_iodi_k;
static int hf_sbas_l1_mt26_spare;

// see ICAO Annex 10, Vol I, Table B-52
static int hf_sbas_l1_mt63;
static int hf_sbas_l1_mt63_spare_1;
static int hf_sbas_l1_mt63_spare_2;
static int hf_sbas_l1_mt63_spare_3;

static dissector_table_t sbas_l1_mt_dissector_table;

static expert_field ei_sbas_l1_preamble;
static expert_field ei_sbas_l1_mt0;
static expert_field ei_sbas_l1_crc;
static expert_field ei_sbas_l1_mt26_igp_band_id;
static expert_field ei_sbas_l1_mt26_igp_block_id;

static int ett_sbas_l1;
static int ett_sbas_l1_mt0;
static int ett_sbas_l1_mt1;
static int ett_sbas_l1_mt2;
static int ett_sbas_l1_mt3;
static int ett_sbas_l1_mt4;
static int ett_sbas_l1_mt5;
static int ett_sbas_l1_mt6;
static int ett_sbas_l1_mt7;
static int ett_sbas_l1_mt17;
static int ett_sbas_l1_mt17_prn_data[3];
static int ett_sbas_l1_mt17_health_and_status;
static int ett_sbas_l1_mt24;
static int ett_sbas_l1_mt25;
static int ett_sbas_l1_mt26;
static int ett_sbas_l1_mt63;

// compute the CRC24Q checksum for an SBAS L1 nav msg
// see ICAO Annex 10, Vol I, Appendix B, Section 3.5.3.5
static uint32_t sbas_crc24q(const uint8_t *data) {
    uint32_t crc = 0;

    // source byte and bit level index
    int s8 = 0, s1 = 7;

    uint8_t s,d = 0;

    // At byte level, nav msg needs to be right aligned.
    // So, pretend that 6 bits (with value zero) have been processed.
    uint8_t d1 = 6;

    // process 226 bits nav msg (= 28 bytes + 2 bits)
    while ((s8 < 28) || (s8 == 28 && s1 > 5)) {

        // get next bit from nav msg
        s = (data[s8] >> s1) & 0x01;

        // include next bit
        d = (d << 1) ^ s;

        // 8 bits included?
        if (d1 == 7) {
            // do crc update
            crc=((crc<<8) & 0xffffff) ^ CRC24Q_TBL[(crc>>16) ^ d];

            d1 = 0;
        }
        else {
            d1++;
        }

        // move to next byte if the last bit of current one was processed.
        if (s1 == 0) {
            s8++;
            s1 = 7;
        }
        else {
            s1--;
        }
    }

    return crc;
}

/* Format GEO position (X or Y axis) with 2600m resolution */
static void fmt_geo_xy_position(char *label, int32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d m", c * 2600);
}

/* Format GEO position (Z axis) with 26000m resolution */
static void fmt_geo_z_position(char *label, int32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d m", c * 26000);
}

/* Format GEO velocity (X or Y axis) with 10m/s resolution */
static void fmt_geo_xy_velocity(char *label, int32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d m/s", c * 10);
}

/* Format GEO velocity (Z axis) with 60m/s resolution */
static void fmt_geo_z_velocity(char *label, int32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d m/s", c * 60);
}

/* Format time of almanac with 64s resolution */
static void fmt_time_of_almanac(char *label, uint32_t c) {
    c = c * 64;
    snprintf(label, ITEM_LABEL_LENGTH, "%us (%02u:%02u:%02u)", c, c / 3600, (c / 60) % 60, c % 60);
}

/* Format clock corrections */
static void fmt_clock_correction(char *label, int32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d * 2^-31 s", c);
}

/* Format corrections with 0.125m resolution */
static void fmt_correction_125m(char *label, int32_t c) {
    c = c * 125;
    if (c >= 0) {
        snprintf(label, ITEM_LABEL_LENGTH, "%d.%03dm", c / 1000, c % 1000);
    }
    else {
        snprintf(label, ITEM_LABEL_LENGTH, "-%d.%03dm", -c / 1000, -c % 1000);
    }
}

/* Format velocity corrections with 2^-11 m/s resolution */
static void fmt_velo_correction(char *label, int32_t c) {
    int64_t temp = c * INT64_C(48828125);
    if (c >= 0) {
        snprintf(label, ITEM_LABEL_LENGTH, " %" PRId64 ".%011" PRId64 "m/s", temp / 100000000000, temp % 100000000000);
    }
    else {
        snprintf(label, ITEM_LABEL_LENGTH, "-%" PRId64 ".%011" PRId64 "m/s", -temp / 100000000000, -temp % 100000000000);
    }
}

/* Format clock rate corrections with 2^-39 s/s resolution */
static void fmt_clk_rate_correction(char *label, int32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d * 2^-39s/s", c);
}

/* Format time of applicability with 16s resolution */
static void fmt_time_of_applicability(char *label, uint32_t c) {
    c = c * 16;
    snprintf(label, ITEM_LABEL_LENGTH, "%us (%02u:%02u:%02u)", c, c / 3600, (c / 60) % 60, c % 60);
}

/* Dissect SBAS L1 message */
static int dissect_sbas_l1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    tvbuff_t *next_tvb;
    uint32_t preamble, mt, cmp_crc;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L1");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_sbas_l1, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l1_tree = proto_item_add_subtree(ti, ett_sbas_l1);

    // preamble
    proto_item* pi_preamble = proto_tree_add_item_ret_uint(
            sbas_l1_tree, hf_sbas_l1_preamble,
            tvb, 0, 1, ENC_BIG_ENDIAN,
            &preamble);
    if (preamble != SBAS_L1_PREAMBLE_1 &&
            preamble != SBAS_L1_PREAMBLE_2 &&
            preamble != SBAS_L1_PREAMBLE_3) {
        expert_add_info_format(pinfo, pi_preamble, &ei_sbas_l1_preamble,
                "Erroneous preamble");
    }

    // message type
    proto_item* pi_mt = proto_tree_add_item_ret_uint(
            sbas_l1_tree, hf_sbas_l1_mt,
            tvb, 1, 1, ENC_BIG_ENDIAN,
            &mt);
    if (mt == 0) { // flag "Do Not Use" MT0 messages
        expert_add_info(pinfo, pi_mt, &ei_sbas_l1_mt0);
    }

    // checksum
    cmp_crc = sbas_crc24q((uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, 29));
    proto_tree_add_checksum(sbas_l1_tree, tvb, 28, hf_sbas_l1_chksum, -1,
            &ei_sbas_l1_crc, NULL, cmp_crc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

    // try to dissect MT data
    next_tvb = tvb_new_subset_length(tvb, 1, 28);
    if (!dissector_try_uint(sbas_l1_mt_dissector_table, mt, next_tvb, pinfo, tree)) {
        call_data_dissector(next_tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

/* Dissect SBAS L1 MT 0 */
static int dissect_sbas_l1_mt0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L1 MT0");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_sbas_l1_mt0, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l1_mt0_tree = proto_item_add_subtree(ti, ett_sbas_l1_mt0);

    proto_tree_add_item(sbas_l1_mt0_tree, hf_sbas_l1_mt0_spare_1, tvb,  0,  1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt0_tree, hf_sbas_l1_mt0_spare_2, tvb,  1, 26, ENC_NA);
    proto_tree_add_item(sbas_l1_mt0_tree, hf_sbas_l1_mt0_spare_3, tvb, 27,  1, ENC_NA);

    return tvb_captured_length(tvb);
}

/* Dissect SBAS L1 MT 1 */
static int dissect_sbas_l1_mt1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L1 MT1");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_sbas_l1_mt1, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l1_mt1_tree = proto_item_add_subtree(ti, ett_sbas_l1_mt1);

    proto_tree_add_item(sbas_l1_mt1_tree, hf_sbas_l1_mt1_prn_mask_gps,     tvb, 0,  8, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt1_tree, hf_sbas_l1_mt1_prn_mask_glonass, tvb, 5,  8, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt1_tree, hf_sbas_l1_mt1_prn_mask_spare_1, tvb, 8,  8, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt1_tree, hf_sbas_l1_mt1_prn_mask_sbas,    tvb, 15, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt1_tree, hf_sbas_l1_mt1_prn_mask_spare_2, tvb, 20, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt1_tree, hf_sbas_l1_mt1_iodp,             tvb, 27, 1, ENC_NA);

    return tvb_captured_length(tvb);
}

/* Dissect SBAS L1 MT 2 */
static int dissect_sbas_l1_mt2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L1 MT2");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_sbas_l1_mt2, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l1_mt2_tree = proto_item_add_subtree(ti, ett_sbas_l1_mt2);

    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_iodf_2,   tvb, 0,  1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_iodp,     tvb, 1,  1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_fc_1,     tvb, 1,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_fc_2,     tvb, 2,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_fc_3,     tvb, 4,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_fc_4,     tvb, 5,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_fc_5,     tvb, 7,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_fc_6,     tvb, 8,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_fc_7,     tvb, 10, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_fc_8,     tvb, 11, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_fc_9,     tvb, 13, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_fc_10,    tvb, 14, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_fc_11,    tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_fc_12,    tvb, 17, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_fc_13,    tvb, 19, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_udrei_1,  tvb, 20, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_udrei_2,  tvb, 21, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_udrei_3,  tvb, 21, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_udrei_4,  tvb, 22, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_udrei_5,  tvb, 22, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_udrei_6,  tvb, 23, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_udrei_7,  tvb, 23, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_udrei_8,  tvb, 24, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_udrei_9,  tvb, 24, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_udrei_10, tvb, 25, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_udrei_11, tvb, 25, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_udrei_12, tvb, 26, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt2_tree, hf_sbas_l1_mt2_udrei_13, tvb, 26, 2, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect SBAS L1 MT 3 */
static int dissect_sbas_l1_mt3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L1 MT3");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_sbas_l1_mt3, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l1_mt3_tree = proto_item_add_subtree(ti, ett_sbas_l1_mt3);

    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_iodf_3,   tvb, 0,  1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_iodp,     tvb, 1,  1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_fc_14,    tvb, 1,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_fc_15,    tvb, 2,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_fc_16,    tvb, 4,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_fc_17,    tvb, 5,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_fc_18,    tvb, 7,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_fc_19,    tvb, 8,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_fc_20,    tvb, 10, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_fc_21,    tvb, 11, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_fc_22,    tvb, 13, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_fc_23,    tvb, 14, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_fc_24,    tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_fc_25,    tvb, 17, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_fc_26,    tvb, 19, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_udrei_14, tvb, 20, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_udrei_15, tvb, 21, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_udrei_16, tvb, 21, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_udrei_17, tvb, 22, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_udrei_18, tvb, 22, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_udrei_19, tvb, 23, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_udrei_20, tvb, 23, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_udrei_21, tvb, 24, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_udrei_22, tvb, 24, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_udrei_23, tvb, 25, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_udrei_24, tvb, 25, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_udrei_25, tvb, 26, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt3_tree, hf_sbas_l1_mt3_udrei_26, tvb, 26, 2, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect SBAS L1 MT 4 */
static int dissect_sbas_l1_mt4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L1 MT4");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_sbas_l1_mt4, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l1_mt4_tree = proto_item_add_subtree(ti, ett_sbas_l1_mt4);

    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_iodf_4,   tvb, 0,  1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_iodp,     tvb, 1,  1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_fc_27,    tvb, 1,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_fc_28,    tvb, 2,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_fc_29,    tvb, 4,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_fc_30,    tvb, 5,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_fc_31,    tvb, 7,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_fc_32,    tvb, 8,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_fc_33,    tvb, 10, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_fc_34,    tvb, 11, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_fc_35,    tvb, 13, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_fc_36,    tvb, 14, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_fc_37,    tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_fc_38,    tvb, 17, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_fc_39,    tvb, 19, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_udrei_27, tvb, 20, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_udrei_28, tvb, 21, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_udrei_29, tvb, 21, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_udrei_30, tvb, 22, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_udrei_31, tvb, 22, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_udrei_32, tvb, 23, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_udrei_33, tvb, 23, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_udrei_34, tvb, 24, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_udrei_35, tvb, 24, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_udrei_36, tvb, 25, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_udrei_37, tvb, 25, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_udrei_38, tvb, 26, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt4_tree, hf_sbas_l1_mt4_udrei_39, tvb, 26, 2, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect SBAS L1 MT 5 */
static int dissect_sbas_l1_mt5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L1 MT5");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_sbas_l1_mt5, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l1_mt5_tree = proto_item_add_subtree(ti, ett_sbas_l1_mt5);

    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_iodf_5,   tvb, 0,  1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_iodp,     tvb, 1,  1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_fc_40,    tvb, 1,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_fc_41,    tvb, 2,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_fc_42,    tvb, 4,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_fc_43,    tvb, 5,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_fc_44,    tvb, 7,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_fc_45,    tvb, 8,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_fc_46,    tvb, 10, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_fc_47,    tvb, 11, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_fc_48,    tvb, 13, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_fc_49,    tvb, 14, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_fc_50,    tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_fc_51,    tvb, 17, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_fc_52,    tvb, 19, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_udrei_40, tvb, 20, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_udrei_41, tvb, 21, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_udrei_42, tvb, 21, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_udrei_43, tvb, 22, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_udrei_44, tvb, 22, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_udrei_45, tvb, 23, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_udrei_46, tvb, 23, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_udrei_47, tvb, 24, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_udrei_48, tvb, 24, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_udrei_49, tvb, 25, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_udrei_50, tvb, 25, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_udrei_51, tvb, 26, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt5_tree, hf_sbas_l1_mt5_udrei_52, tvb, 26, 2, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect SBAS L1 MT 6 */
static int dissect_sbas_l1_mt6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L1 MT6");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_sbas_l1_mt6, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l1_mt6_tree = proto_item_add_subtree(ti, ett_sbas_l1_mt6);

    // IODF_2 to IODF_5
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_iodf_2, tvb, 0, 1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_iodf_3, tvb, 1, 1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_iodf_4, tvb, 1, 1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_iodf_5, tvb, 1, 1, ENC_NA);

    // UDREI_i
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_1,  tvb, 1,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_2,  tvb, 2,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_3,  tvb, 2,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_4,  tvb, 3,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_5,  tvb, 3,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_6,  tvb, 4,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_7,  tvb, 4,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_8,  tvb, 5,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_9,  tvb, 5,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_10, tvb, 6,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_11, tvb, 6,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_12, tvb, 7,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_13, tvb, 7,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_14, tvb, 8,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_15, tvb, 8,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_16, tvb, 9,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_17, tvb, 9,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_18, tvb, 10, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_19, tvb, 10, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_20, tvb, 11, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_21, tvb, 11, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_22, tvb, 12, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_23, tvb, 12, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_24, tvb, 13, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_25, tvb, 13, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_26, tvb, 14, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_27, tvb, 14, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_28, tvb, 15, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_29, tvb, 15, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_30, tvb, 16, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_31, tvb, 16, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_32, tvb, 17, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_33, tvb, 17, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_34, tvb, 18, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_35, tvb, 18, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_36, tvb, 19, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_37, tvb, 19, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_38, tvb, 20, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_39, tvb, 20, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_40, tvb, 21, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_41, tvb, 21, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_42, tvb, 22, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_43, tvb, 22, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_44, tvb, 23, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_45, tvb, 23, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_46, tvb, 24, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_47, tvb, 24, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_48, tvb, 25, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_49, tvb, 25, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_50, tvb, 26, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt6_tree, hf_sbas_l1_mt6_udrei_51, tvb, 26, 2, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect SBAS L1 MT 7 */
static int dissect_sbas_l1_mt7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L1 MT7");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_sbas_l1_mt7, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l1_mt7_tree = proto_item_add_subtree(ti, ett_sbas_l1_mt7);

    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_t_lat,  tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_iodp,   tvb, 1, 1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_spare,  tvb, 1, 1, ENC_NA);

    // Degradation factor indicator ai_i
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_1,  tvb, 1,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_2,  tvb, 2,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_3,  tvb, 2,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_4,  tvb, 3,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_5,  tvb, 3,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_6,  tvb, 4,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_7,  tvb, 4,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_8,  tvb, 5,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_9,  tvb, 5,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_10, tvb, 6,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_11, tvb, 6,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_12, tvb, 7,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_13, tvb, 7,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_14, tvb, 8,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_15, tvb, 8,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_16, tvb, 9,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_17, tvb, 9,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_18, tvb, 10, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_19, tvb, 10, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_20, tvb, 11, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_21, tvb, 11, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_22, tvb, 12, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_23, tvb, 12, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_24, tvb, 13, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_25, tvb, 13, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_26, tvb, 14, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_27, tvb, 14, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_28, tvb, 15, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_29, tvb, 15, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_30, tvb, 16, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_31, tvb, 16, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_32, tvb, 17, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_33, tvb, 17, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_34, tvb, 18, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_35, tvb, 18, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_36, tvb, 19, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_37, tvb, 19, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_38, tvb, 20, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_39, tvb, 20, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_40, tvb, 21, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_41, tvb, 21, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_42, tvb, 22, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_43, tvb, 22, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_44, tvb, 23, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_45, tvb, 23, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_46, tvb, 24, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_47, tvb, 24, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_48, tvb, 25, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_49, tvb, 25, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_50, tvb, 26, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt7_tree, hf_sbas_l1_mt7_ai_51, tvb, 26, 2, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect SBAS L1 MT 17 */
static int dissect_sbas_l1_mt17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    uint8_t i;
    tvbuff_t *prn_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L1 MT17");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_sbas_l1_mt17, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l1_mt17_tree = proto_item_add_subtree(ti, ett_sbas_l1_mt17);

    // dissect data for each of 3 PRNs
    for (i = 0; i < 3; i++) {
        prn_tvb = tvb_new_octet_aligned(tvb, 6 + i*67, 67);
        if (prn_tvb) {
            add_new_data_source(pinfo, prn_tvb, "PRN data");

            uint16_t prn = (tvb_get_uint16(prn_tvb, 0, ENC_BIG_ENDIAN) >> 6) & 0xff;

            proto_tree *prn_tree = proto_tree_add_subtree_format(sbas_l1_mt17_tree, tvb, (6 + i * 67) / 8, (i == 0) ? 10 : 9, ett_sbas_l1_mt17_prn_data[i], NULL, "PRN %u", prn);

            proto_tree_add_item(prn_tree, hf_sbas_l1_mt17_reserved, prn_tvb, 0,  1, ENC_NA);
            proto_tree_add_item(prn_tree, hf_sbas_l1_mt17_prn,      prn_tvb, 0,  2, ENC_BIG_ENDIAN);

            proto_tree_add_bitmask(prn_tree, prn_tvb, 1, hf_sbas_l1_mt17_health_and_status, ett_sbas_l1_mt17_health_and_status, sbas_l1_mt17_health_and_status_fields, ENC_NA);

            proto_tree_add_item(prn_tree, hf_sbas_l1_mt17_x_ga,     prn_tvb, 2,  4, ENC_BIG_ENDIAN);
            proto_tree_add_item(prn_tree, hf_sbas_l1_mt17_y_ga,     prn_tvb, 4,  4, ENC_BIG_ENDIAN);
            proto_tree_add_item(prn_tree, hf_sbas_l1_mt17_z_ga,     prn_tvb, 4,  4, ENC_BIG_ENDIAN);
            proto_tree_add_item(prn_tree, hf_sbas_l1_mt17_x_ga_vel, prn_tvb, 4,  4, ENC_BIG_ENDIAN);
            proto_tree_add_item(prn_tree, hf_sbas_l1_mt17_y_ga_vel, prn_tvb, 4,  4, ENC_BIG_ENDIAN);
            proto_tree_add_item(prn_tree, hf_sbas_l1_mt17_z_ga_vel, prn_tvb, 5,  4, ENC_BIG_ENDIAN);
        }
    }

    proto_tree_add_item(sbas_l1_mt17_tree, hf_sbas_l1_mt17_t_a, tvb, 24, 4, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect SBAS L1 MT 24 */
static int dissect_sbas_l1_mt24(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    uint32_t velocity_code;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L1 MT24");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_sbas_l1_mt24, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l1_mt24_tree = proto_item_add_subtree(ti, ett_sbas_l1_mt24);

    proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_fc_i1,     tvb, 0,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_fc_i2,     tvb, 2,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_fc_i3,     tvb, 3,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_fc_i4,     tvb, 5,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_fc_i5,     tvb, 6,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_fc_i6,     tvb, 8,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_udrei_i1,  tvb, 9,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_udrei_i2,  tvb, 10, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_udrei_i3,  tvb, 10, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_udrei_i4,  tvb, 11, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_udrei_i5,  tvb, 11, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_udrei_i6,  tvb, 12, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_iodp,      tvb, 12, 1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_fc_type,   tvb, 13, 1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_iodf_j,    tvb, 13, 1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_spare,     tvb, 13, 1, ENC_NA);

    proto_tree_add_item_ret_uint(sbas_l1_mt24_tree, hf_sbas_l1_mt24_velocity_code, tvb, 14, 1, ENC_NA, &velocity_code);

    if (velocity_code == 0) {
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v0_prn_mask_nr_1, tvb, 14, 1, ENC_NA);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v0_iod_1,         tvb, 14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v0_delta_x_1,     tvb, 15, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v0_delta_y_1,     tvb, 17, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v0_delta_z_1,     tvb, 18, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v0_delta_a_1_f0,  tvb, 19, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v0_prn_mask_nr_2, tvb, 20, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v0_iod_2,         tvb, 21, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v0_delta_x_2,     tvb, 22, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v0_delta_y_2,     tvb, 23, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v0_delta_z_2,     tvb, 24, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v0_delta_a_2_f0,  tvb, 25, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v0_iodp,          tvb, 26, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v0_spare,         tvb, 27, 1, ENC_NA);
    }
    else {
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v1_prn_mask_nr, tvb, 14, 1, ENC_NA);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v1_iod,         tvb, 14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v1_delta_x,     tvb, 15, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v1_delta_y,     tvb, 17, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v1_delta_z,     tvb, 18, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v1_delta_a_f0,  tvb, 20, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v1_delta_x_vel, tvb, 21, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v1_delta_y_vel, tvb, 22, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v1_delta_z_vel, tvb, 23, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v1_delta_a_f1,  tvb, 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v1_t_lt,        tvb, 25, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt24_tree, hf_sbas_l1_mt24_v1_iodp,        tvb, 27, 1, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

/* Dissect SBAS L1 MT 25 */
static int dissect_sbas_l1_mt25(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    uint32_t velocity_code;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L1 MT25");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_sbas_l1_mt25, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l1_mt25_tree = proto_item_add_subtree(ti, ett_sbas_l1_mt25);

    // first half message
    proto_tree_add_item_ret_uint(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_velocity_code,
            tvb, 0, 1, ENC_NA, &velocity_code);
    if (velocity_code == 0) {
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v0_prn_mask_nr_1,
                tvb, 0, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v0_iod_1,
                tvb, 1, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v0_delta_x_1,
                tvb, 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v0_delta_y_1,
                tvb, 3, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v0_delta_z_1,
                tvb, 4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v0_delta_a_1_f0,
                tvb, 6, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v0_prn_mask_nr_2,
                tvb, 7, 1, ENC_NA);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v0_iod_2,
                tvb, 8, 1, ENC_NA);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v0_delta_x_2,
                tvb, 9, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v0_delta_y_2,
                tvb, 10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v0_delta_z_2,
                tvb, 11, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v0_delta_a_2_f0,
                tvb, 12, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v0_iodp,
                tvb, 13, 1, ENC_NA);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v0_spare,
                tvb, 13, 1, ENC_NA);
    }
    else { // velocity_code == 1
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v1_prn_mask_nr,
                tvb, 0, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v1_iod,
                tvb, 1, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v1_delta_x,
                tvb, 2, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v1_delta_y,
                tvb, 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v1_delta_z,
                tvb, 5, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v1_delta_a_f0,
                tvb, 6, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v1_delta_x_vel,
                tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v1_delta_y_vel,
                tvb, 9, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v1_delta_z_vel,
                tvb, 10, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v1_delta_a_f1,
                tvb, 11, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v1_t_lt,
                tvb, 12, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h1_v1_iodp,
                tvb, 13, 1, ENC_NA);
    }

    // second half message
    proto_tree_add_item_ret_uint(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_velocity_code,
            tvb, 14, 1, ENC_NA, &velocity_code);
    if (velocity_code == 0) {
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v0_prn_mask_nr_1,
                tvb, 14, 1, ENC_NA);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v0_iod_1,
                tvb, 14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v0_delta_x_1,
                tvb, 15, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v0_delta_y_1,
                tvb, 17, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v0_delta_z_1,
                tvb, 18, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v0_delta_a_1_f0,
                tvb, 19, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v0_prn_mask_nr_2,
                tvb, 20, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v0_iod_2,
                tvb, 21, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v0_delta_x_2,
                tvb, 22, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v0_delta_y_2,
                tvb, 23, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v0_delta_z_2,
                tvb, 24, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v0_delta_a_2_f0,
                tvb, 25, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v0_iodp,
                tvb, 26, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v0_spare,
                tvb, 27, 1, ENC_NA);
    }
    else { // velocity_code == 1
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v1_prn_mask_nr,
                tvb, 14, 1, ENC_NA);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v1_iod,
                tvb, 14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v1_delta_x,
                tvb, 15, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v1_delta_y,
                tvb, 17, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v1_delta_z,
                tvb, 18, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v1_delta_a_f0,
                tvb, 20, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v1_delta_x_vel,
                tvb, 21, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v1_delta_y_vel,
                tvb, 22, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v1_delta_z_vel,
                tvb, 23, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v1_delta_a_f1,
                tvb, 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v1_t_lt,
                tvb, 25, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sbas_l1_mt25_tree, hf_sbas_l1_mt25_h2_v1_iodp,
                tvb, 27, 1, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

/* Dissect SBAS L1 MT 26 */
static int dissect_sbas_l1_mt26(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L1 MT26");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_sbas_l1_mt26, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l1_mt26_tree = proto_item_add_subtree(ti, ett_sbas_l1_mt26);

    uint32_t igp_band_id;
    proto_item* pi_igp_band_id = proto_tree_add_item_ret_uint(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_band_id,
            tvb, 0, 2, ENC_BIG_ENDIAN, &igp_band_id);
    if (igp_band_id > 10) {
        expert_add_info_format(pinfo, pi_igp_band_id, &ei_sbas_l1_mt26_igp_band_id, "Invalid IGP Band Identifier");
    }

    uint32_t igp_block_id;
    proto_item* pi_igp_block_id = proto_tree_add_item_ret_uint(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_block_id,
            tvb, 1, 1, ENC_NA, &igp_block_id);
    if (igp_block_id > 13) {
        expert_add_info_format(pinfo, pi_igp_block_id, &ei_sbas_l1_mt26_igp_block_id, "Invalid IGP Block Identifier");
    }

    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_vertical_delay_est_1, tvb, 1, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_givei_1, tvb, 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_vertical_delay_est_2, tvb, 3, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_givei_2, tvb, 4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_vertical_delay_est_3, tvb, 5, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_givei_3, tvb, 6, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_vertical_delay_est_4, tvb, 6, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_givei_4, tvb, 7, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_vertical_delay_est_5, tvb, 8, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_givei_5, tvb, 9, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_vertical_delay_est_6, tvb, 9, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_givei_6, tvb, 11, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_vertical_delay_est_7, tvb, 11, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_givei_7, tvb, 12, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_vertical_delay_est_8, tvb, 13, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_givei_8, tvb, 14, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_vertical_delay_est_9, tvb, 14, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_givei_9, tvb, 15, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_vertical_delay_est_10, tvb, 16, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_givei_10, tvb, 17, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_vertical_delay_est_11, tvb, 18, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_givei_11, tvb, 19, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_vertical_delay_est_12, tvb, 19, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_givei_12, tvb, 20, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_vertical_delay_est_13, tvb, 21, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_givei_13, tvb, 22, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_vertical_delay_est_14, tvb, 22, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_givei_14, tvb, 24, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_igp_vertical_delay_est_15, tvb, 24, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_givei_15, tvb, 25, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_iodi_k, tvb, 26, 1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt26_tree, hf_sbas_l1_mt26_spare, tvb, 26, 2, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect SBAS L1 MT 63 */
static int dissect_sbas_l1_mt63(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBAS L1 MT63");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_sbas_l1_mt63, tvb, 0, 32, ENC_NA);
    proto_tree *sbas_l1_mt63_tree = proto_item_add_subtree(ti, ett_sbas_l1_mt63);

    proto_tree_add_item(sbas_l1_mt63_tree, hf_sbas_l1_mt63_spare_1, tvb,  0,  1, ENC_NA);
    proto_tree_add_item(sbas_l1_mt63_tree, hf_sbas_l1_mt63_spare_2, tvb,  1, 26, ENC_NA);
    proto_tree_add_item(sbas_l1_mt63_tree, hf_sbas_l1_mt63_spare_3, tvb, 27,  1, ENC_NA);

    return tvb_captured_length(tvb);
}

void proto_register_sbas_l1(void) {

    static hf_register_info hf[] = {
        {&hf_sbas_l1_preamble, {"Preamble",     "sbas_l1.preamble", FT_UINT8,  BASE_HEX, NULL, 0xff,       NULL, HFILL}},
        {&hf_sbas_l1_mt,       {"Message Type", "sbas_l1.mt"      , FT_UINT8,  BASE_DEC, NULL, 0xfc,       NULL, HFILL}},
        {&hf_sbas_l1_chksum,   {"Checksum",     "sbas_l1.chksum"  , FT_UINT32, BASE_HEX, NULL, 0x3fffffc0, NULL, HFILL}},

        // MT0
        {&hf_sbas_l1_mt0,         {"MT0",     "sbas_l1.mt0",         FT_NONE,  BASE_NONE, NULL, 0x00, NULL, HFILL}},
        {&hf_sbas_l1_mt0_spare_1, {"Spare 1", "sbas_l1.mt0.spare_1", FT_UINT8, BASE_HEX,  NULL, 0x03, NULL, HFILL}},
        {&hf_sbas_l1_mt0_spare_2, {"Spare 2", "sbas_l1.mt0.spare_2", FT_BYTES, SEP_SPACE, NULL, 0x00, NULL, HFILL}},
        {&hf_sbas_l1_mt0_spare_3, {"Spare 3", "sbas_l1.mt0.spare_3", FT_UINT8, BASE_HEX,  NULL, 0xc0, NULL, HFILL}},

        // MT1
        {&hf_sbas_l1_mt1,                  {"MT1",                        "sbas_l1.mt1",                  FT_NONE,   BASE_NONE, NULL, 0x0,                          NULL, HFILL}},
        {&hf_sbas_l1_mt1_prn_mask_gps,     {"PRN Mask GPS",               "sbas_l1.mt1.prn_mask_gps",     FT_UINT64, BASE_HEX,  NULL, UINT64_C(0x03ffffffffe00000), NULL, HFILL}},
        {&hf_sbas_l1_mt1_prn_mask_glonass, {"PRN Mask Glonass",           "sbas_l1.mt1.prn_mask_glonass", FT_UINT64, BASE_HEX,  NULL, UINT64_C(0x1fffffe000000000), NULL, HFILL}},
        {&hf_sbas_l1_mt1_prn_mask_spare_1, {"PRN Mask spare",             "sbas_l1.mt1.prn_mask_spare_1", FT_UINT64, BASE_HEX,  NULL, UINT64_C(0x1ffffffffffffff8), NULL, HFILL}},
        {&hf_sbas_l1_mt1_prn_mask_sbas,    {"PRN Mask SBAS",              "sbas_l1.mt1.prn_mask_sbas",    FT_UINT64, BASE_HEX,  NULL, UINT64_C(0x07fffffffff00000), NULL, HFILL}},
        {&hf_sbas_l1_mt1_prn_mask_spare_2, {"PRN Mask spare",             "sbas_l1.mt1.prn_mask_spare_2", FT_UINT64, BASE_HEX,  NULL, UINT64_C(0x0fffffffffffff00), NULL, HFILL}},
        {&hf_sbas_l1_mt1_iodp,             {"Issue of Data - PRN (IODP)", "sbas_l1.mt1.iodp",             FT_UINT8,  BASE_DEC,  NULL, 0xc0,                         NULL, HFILL}},

        // MT2
        {&hf_sbas_l1_mt2,          {"MT2",                                      "sbas_l1.mt2",          FT_NONE,   BASE_NONE,   NULL,                          0x0,        NULL, HFILL}},
        {&hf_sbas_l1_mt2_iodf_2,   {"Issue of Data - Fast Correction (IODF_2)", "sbas_l1.mt2.iodf_2",   FT_UINT8,  BASE_DEC,    NULL,                          0x03,       NULL, HFILL}},
        {&hf_sbas_l1_mt2_iodp,     {"Issue of Data - PRN (IODP)",               "sbas_l1.mt2.iodp",     FT_UINT8,  BASE_DEC,    NULL,                          0xc0,       NULL, HFILL}},
        {&hf_sbas_l1_mt2_fc_1,     {"Fast Correction Satellite 1 (FC_1)",       "sbas_l1.mt2.fc_1",     FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt2_fc_2,     {"Fast Correction Satellite 2 (FC_2)",       "sbas_l1.mt2.fc_2",     FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt2_fc_3,     {"Fast Correction Satellite 3 (FC_3)",       "sbas_l1.mt2.fc_3",     FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt2_fc_4,     {"Fast Correction Satellite 4 (FC_4)",       "sbas_l1.mt2.fc_4",     FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt2_fc_5,     {"Fast Correction Satellite 5 (FC_5)",       "sbas_l1.mt2.fc_5",     FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt2_fc_6,     {"Fast Correction Satellite 6 (FC_6)",       "sbas_l1.mt2.fc_6",     FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt2_fc_7,     {"Fast Correction Satellite 7 (FC_7)",       "sbas_l1.mt2.fc_7",     FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt2_fc_8,     {"Fast Correction Satellite 8 (FC_8)",       "sbas_l1.mt2.fc_8",     FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt2_fc_9,     {"Fast Correction Satellite 9 (FC_9)",       "sbas_l1.mt2.fc_9",     FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt2_fc_10,    {"Fast Correction Satellite 10 (FC_10)",     "sbas_l1.mt2.fc_10",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt2_fc_11,    {"Fast Correction Satellite 11 (FC_11)",     "sbas_l1.mt2.fc_11",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt2_fc_12,    {"Fast Correction Satellite 12 (FC_12)",     "sbas_l1.mt2.fc_12",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt2_fc_13,    {"Fast Correction Satellite 13 (FC_13)",     "sbas_l1.mt2.fc_13",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt2_udrei_1,  {"UDREI_1",                                  "sbas_l1.mt2.udrei_1",  FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt2_udrei_2,  {"UDREI_2",                                  "sbas_l1.mt2.udrei_2",  FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt2_udrei_3,  {"UDREI_3",                                  "sbas_l1.mt2.udrei_3",  FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt2_udrei_4,  {"UDREI_4",                                  "sbas_l1.mt2.udrei_4",  FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt2_udrei_5,  {"UDREI_5",                                  "sbas_l1.mt2.udrei_5",  FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt2_udrei_6,  {"UDREI_6",                                  "sbas_l1.mt2.udrei_6",  FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt2_udrei_7,  {"UDREI_7",                                  "sbas_l1.mt2.udrei_7",  FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt2_udrei_8,  {"UDREI_8",                                  "sbas_l1.mt2.udrei_8",  FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt2_udrei_9,  {"UDREI_9",                                  "sbas_l1.mt2.udrei_9",  FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt2_udrei_10, {"UDREI_10",                                 "sbas_l1.mt2.udrei_10", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt2_udrei_11, {"UDREI_11",                                 "sbas_l1.mt2.udrei_11", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt2_udrei_12, {"UDREI_12",                                 "sbas_l1.mt2.udrei_12", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt2_udrei_13, {"UDREI_13",                                 "sbas_l1.mt2.udrei_13", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},

        // MT3
        {&hf_sbas_l1_mt3,          {"MT3",                                      "sbas_l1.mt3",          FT_NONE,   BASE_NONE,   NULL,                          0x0,        NULL, HFILL}},
        {&hf_sbas_l1_mt3_iodf_3,   {"Issue of Data - Fast Correction (IODF_3)", "sbas_l1.mt3.iodf_3",   FT_UINT8,  BASE_DEC,    NULL,                          0x03,       NULL, HFILL}},
        {&hf_sbas_l1_mt3_iodp,     {"Issue of Data - PRN (IODP)",               "sbas_l1.mt3.iodp",     FT_UINT8,  BASE_DEC,    NULL,                          0xc0,       NULL, HFILL}},
        {&hf_sbas_l1_mt3_fc_14,    {"Fast Correction Satellite 14 (FC_14)",     "sbas_l1.mt3.fc_14",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt3_fc_15,    {"Fast Correction Satellite 15 (FC_15)",     "sbas_l1.mt3.fc_15",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt3_fc_16,    {"Fast Correction Satellite 16 (FC_16)",     "sbas_l1.mt3.fc_16",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt3_fc_17,    {"Fast Correction Satellite 17 (FC_17)",     "sbas_l1.mt3.fc_17",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt3_fc_18,    {"Fast Correction Satellite 18 (FC_18)",     "sbas_l1.mt3.fc_18",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt3_fc_19,    {"Fast Correction Satellite 19 (FC_19)",     "sbas_l1.mt3.fc_19",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt3_fc_20,    {"Fast Correction Satellite 20 (FC_20)",     "sbas_l1.mt3.fc_20",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt3_fc_21,    {"Fast Correction Satellite 21 (FC_21)",     "sbas_l1.mt3.fc_21",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt3_fc_22,    {"Fast Correction Satellite 22 (FC_22)",     "sbas_l1.mt3.fc_22",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt3_fc_23,    {"Fast Correction Satellite 23 (FC_23)",     "sbas_l1.mt3.fc_23",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt3_fc_24,    {"Fast Correction Satellite 24 (FC_24)",     "sbas_l1.mt3.fc_24",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt3_fc_25,    {"Fast Correction Satellite 25 (FC_25)",     "sbas_l1.mt3.fc_25",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt3_fc_26,    {"Fast Correction Satellite 26 (FC_26)",     "sbas_l1.mt3.fc_26",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt3_udrei_14, {"UDREI_14",                                 "sbas_l1.mt3.udrei_14", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt3_udrei_15, {"UDREI_15",                                 "sbas_l1.mt3.udrei_15", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt3_udrei_16, {"UDREI_16",                                 "sbas_l1.mt3.udrei_16", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt3_udrei_17, {"UDREI_17",                                 "sbas_l1.mt3.udrei_17", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt3_udrei_18, {"UDREI_18",                                 "sbas_l1.mt3.udrei_18", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt3_udrei_19, {"UDREI_19",                                 "sbas_l1.mt3.udrei_19", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt3_udrei_20, {"UDREI_20",                                 "sbas_l1.mt3.udrei_20", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt3_udrei_21, {"UDREI_21",                                 "sbas_l1.mt3.udrei_21", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt3_udrei_22, {"UDREI_22",                                 "sbas_l1.mt3.udrei_22", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt3_udrei_23, {"UDREI_23",                                 "sbas_l1.mt3.udrei_23", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt3_udrei_24, {"UDREI_24",                                 "sbas_l1.mt3.udrei_24", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt3_udrei_25, {"UDREI_25",                                 "sbas_l1.mt3.udrei_25", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt3_udrei_26, {"UDREI_26",                                 "sbas_l1.mt3.udrei_26", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},

        // MT4
        {&hf_sbas_l1_mt4,          {"MT4",                                      "sbas_l1.mt4",          FT_NONE,   BASE_NONE,   NULL,                          0x0,        NULL, HFILL}},
        {&hf_sbas_l1_mt4_iodf_4,   {"Issue of Data - Fast Correction (IODF_4)", "sbas_l1.mt4.iodf_4",   FT_UINT8,  BASE_DEC,    NULL,                          0x03,       NULL, HFILL}},
        {&hf_sbas_l1_mt4_iodp,     {"Issue of Data - PRN (IODP)",               "sbas_l1.mt4.iodp",     FT_UINT8,  BASE_DEC,    NULL,                          0xc0,       NULL, HFILL}},
        {&hf_sbas_l1_mt4_fc_27,    {"Fast Correction Satellite 27 (FC_27)",     "sbas_l1.mt4.fc_27",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt4_fc_28,    {"Fast Correction Satellite 28 (FC_28)",     "sbas_l1.mt4.fc_28",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt4_fc_29,    {"Fast Correction Satellite 29 (FC_29)",     "sbas_l1.mt4.fc_29",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt4_fc_30,    {"Fast Correction Satellite 30 (FC_30)",     "sbas_l1.mt4.fc_30",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt4_fc_31,    {"Fast Correction Satellite 31 (FC_31)",     "sbas_l1.mt4.fc_31",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt4_fc_32,    {"Fast Correction Satellite 32 (FC_32)",     "sbas_l1.mt4.fc_32",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt4_fc_33,    {"Fast Correction Satellite 33 (FC_33)",     "sbas_l1.mt4.fc_33",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt4_fc_34,    {"Fast Correction Satellite 34 (FC_34)",     "sbas_l1.mt4.fc_34",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt4_fc_35,    {"Fast Correction Satellite 35 (FC_35)",     "sbas_l1.mt4.fc_35",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt4_fc_36,    {"Fast Correction Satellite 36 (FC_36)",     "sbas_l1.mt4.fc_36",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt4_fc_37,    {"Fast Correction Satellite 37 (FC_37)",     "sbas_l1.mt4.fc_37",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt4_fc_38,    {"Fast Correction Satellite 38 (FC_38)",     "sbas_l1.mt4.fc_38",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt4_fc_39,    {"Fast Correction Satellite 39 (FC_39)",     "sbas_l1.mt4.fc_39",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt4_udrei_27, {"UDREI_27",                                 "sbas_l1.mt4.udrei_27", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt4_udrei_28, {"UDREI_28",                                 "sbas_l1.mt4.udrei_28", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt4_udrei_29, {"UDREI_29",                                 "sbas_l1.mt4.udrei_29", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt4_udrei_30, {"UDREI_30",                                 "sbas_l1.mt4.udrei_30", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt4_udrei_31, {"UDREI_31",                                 "sbas_l1.mt4.udrei_31", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt4_udrei_32, {"UDREI_32",                                 "sbas_l1.mt4.udrei_32", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt4_udrei_33, {"UDREI_33",                                 "sbas_l1.mt4.udrei_33", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt4_udrei_34, {"UDREI_34",                                 "sbas_l1.mt4.udrei_34", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt4_udrei_35, {"UDREI_35",                                 "sbas_l1.mt4.udrei_35", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt4_udrei_36, {"UDREI_36",                                 "sbas_l1.mt4.udrei_36", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt4_udrei_37, {"UDREI_37",                                 "sbas_l1.mt4.udrei_37", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt4_udrei_38, {"UDREI_38",                                 "sbas_l1.mt4.udrei_38", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt4_udrei_39, {"UDREI_39",                                 "sbas_l1.mt4.udrei_39", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},

        // MT5
        {&hf_sbas_l1_mt5,          {"MT5",                                      "sbas_l1.mt5",          FT_NONE,   BASE_NONE,   NULL,                          0x0,        NULL, HFILL}},
        {&hf_sbas_l1_mt5_iodf_5,   {"Issue of Data - Fast Correction (IODF_5)", "sbas_l1.mt5.iodf_5",   FT_UINT8,  BASE_DEC,    NULL,                          0x03,       NULL, HFILL}},
        {&hf_sbas_l1_mt5_iodp,     {"Issue of Data - PRN (IODP)",               "sbas_l1.mt5.iodp",     FT_UINT8,  BASE_DEC,    NULL,                          0xc0,       NULL, HFILL}},
        {&hf_sbas_l1_mt5_fc_40,    {"Fast Correction Satellite 40 (FC_40)",     "sbas_l1.mt5.fc_40",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt5_fc_41,    {"Fast Correction Satellite 41 (FC_41)",     "sbas_l1.mt5.fc_41",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt5_fc_42,    {"Fast Correction Satellite 42 (FC_42)",     "sbas_l1.mt5.fc_42",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt5_fc_43,    {"Fast Correction Satellite 43 (FC_43)",     "sbas_l1.mt5.fc_43",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt5_fc_44,    {"Fast Correction Satellite 44 (FC_44)",     "sbas_l1.mt5.fc_44",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt5_fc_45,    {"Fast Correction Satellite 45 (FC_45)",     "sbas_l1.mt5.fc_45",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt5_fc_46,    {"Fast Correction Satellite 46 (FC_46)",     "sbas_l1.mt5.fc_46",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt5_fc_47,    {"Fast Correction Satellite 47 (FC_47)",     "sbas_l1.mt5.fc_47",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt5_fc_48,    {"Fast Correction Satellite 48 (FC_48)",     "sbas_l1.mt5.fc_48",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt5_fc_49,    {"Fast Correction Satellite 49 (FC_49)",     "sbas_l1.mt5.fc_49",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt5_fc_50,    {"Fast Correction Satellite 50 (FC_50)",     "sbas_l1.mt5.fc_50",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt5_fc_51,    {"Fast Correction Satellite 51 (FC_51)",     "sbas_l1.mt5.fc_51",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt5_fc_52,    {"Fast Correction Satellite 52 (FC_52)",     "sbas_l1.mt5.fc_52",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt5_udrei_40, {"UDREI_40",                                 "sbas_l1.mt5.udrei_40", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt5_udrei_41, {"UDREI_41",                                 "sbas_l1.mt5.udrei_41", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt5_udrei_42, {"UDREI_42",                                 "sbas_l1.mt5.udrei_42", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt5_udrei_43, {"UDREI_43",                                 "sbas_l1.mt5.udrei_43", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt5_udrei_44, {"UDREI_44",                                 "sbas_l1.mt5.udrei_44", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt5_udrei_45, {"UDREI_45",                                 "sbas_l1.mt5.udrei_45", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt5_udrei_46, {"UDREI_46",                                 "sbas_l1.mt5.udrei_46", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt5_udrei_47, {"UDREI_47",                                 "sbas_l1.mt5.udrei_47", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt5_udrei_48, {"UDREI_48",                                 "sbas_l1.mt5.udrei_48", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt5_udrei_49, {"UDREI_49",                                 "sbas_l1.mt5.udrei_49", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt5_udrei_50, {"UDREI_50",                                 "sbas_l1.mt5.udrei_50", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt5_udrei_51, {"UDREI_51",                                 "sbas_l1.mt5.udrei_51", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt5_udrei_52, {"UDREI_52",                                 "sbas_l1.mt5.udrei_52", FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},

        // MT6
        {&hf_sbas_l1_mt6,          {"MT6",                                      "sbas_l1.mt6",          FT_NONE,   BASE_NONE, NULL,                   0x0,    NULL, HFILL}},
        {&hf_sbas_l1_mt6_iodf_2,   {"Issue of Data - Fast Correction (IODF_2)", "sbas_l1.mt6.iodf_2",   FT_UINT8,  BASE_DEC,  NULL,                   0x03,   NULL, HFILL}},
        {&hf_sbas_l1_mt6_iodf_3,   {"Issue of Data - Fast Correction (IODF_3)", "sbas_l1.mt6.iodf_3",   FT_UINT8,  BASE_DEC,  NULL,                   0xc0,   NULL, HFILL}},
        {&hf_sbas_l1_mt6_iodf_4,   {"Issue of Data - Fast Correction (IODF_4)", "sbas_l1.mt6.iodf_4",   FT_UINT8,  BASE_DEC,  NULL,                   0x30,   NULL, HFILL}},
        {&hf_sbas_l1_mt6_iodf_5,   {"Issue of Data - Fast Correction (IODF_5)", "sbas_l1.mt6.iodf_5",   FT_UINT8,  BASE_DEC,  NULL,                   0x0c,   NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_1,  {"UDREI_1",                                  "sbas_l1.mt6.udrei_1",  FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_2,  {"UDREI_2",                                  "sbas_l1.mt6.udrei_2",  FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_3,  {"UDREI_3",                                  "sbas_l1.mt6.udrei_3",  FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_4,  {"UDREI_4",                                  "sbas_l1.mt6.udrei_4",  FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_5,  {"UDREI_5",                                  "sbas_l1.mt6.udrei_5",  FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_6,  {"UDREI_6",                                  "sbas_l1.mt6.udrei_6",  FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_7,  {"UDREI_7",                                  "sbas_l1.mt6.udrei_7",  FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_8,  {"UDREI_8",                                  "sbas_l1.mt6.udrei_8",  FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_9,  {"UDREI_9",                                  "sbas_l1.mt6.udrei_9",  FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_10, {"UDREI_10",                                 "sbas_l1.mt6.udrei_10", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_11, {"UDREI_11",                                 "sbas_l1.mt6.udrei_11", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_12, {"UDREI_12",                                 "sbas_l1.mt6.udrei_12", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_13, {"UDREI_13",                                 "sbas_l1.mt6.udrei_13", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_14, {"UDREI_14",                                 "sbas_l1.mt6.udrei_14", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_15, {"UDREI_15",                                 "sbas_l1.mt6.udrei_15", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_16, {"UDREI_16",                                 "sbas_l1.mt6.udrei_16", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_17, {"UDREI_17",                                 "sbas_l1.mt6.udrei_17", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_18, {"UDREI_18",                                 "sbas_l1.mt6.udrei_18", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_19, {"UDREI_19",                                 "sbas_l1.mt6.udrei_19", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_20, {"UDREI_20",                                 "sbas_l1.mt6.udrei_20", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_21, {"UDREI_21",                                 "sbas_l1.mt6.udrei_21", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_22, {"UDREI_22",                                 "sbas_l1.mt6.udrei_22", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_23, {"UDREI_23",                                 "sbas_l1.mt6.udrei_23", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_24, {"UDREI_24",                                 "sbas_l1.mt6.udrei_24", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_25, {"UDREI_25",                                 "sbas_l1.mt6.udrei_25", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_26, {"UDREI_26",                                 "sbas_l1.mt6.udrei_26", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_27, {"UDREI_27",                                 "sbas_l1.mt6.udrei_27", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_28, {"UDREI_28",                                 "sbas_l1.mt6.udrei_28", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_29, {"UDREI_29",                                 "sbas_l1.mt6.udrei_29", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_30, {"UDREI_30",                                 "sbas_l1.mt6.udrei_30", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_31, {"UDREI_31",                                 "sbas_l1.mt6.udrei_31", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_32, {"UDREI_32",                                 "sbas_l1.mt6.udrei_32", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_33, {"UDREI_33",                                 "sbas_l1.mt6.udrei_33", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_34, {"UDREI_34",                                 "sbas_l1.mt6.udrei_34", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_35, {"UDREI_35",                                 "sbas_l1.mt6.udrei_35", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_36, {"UDREI_36",                                 "sbas_l1.mt6.udrei_36", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_37, {"UDREI_37",                                 "sbas_l1.mt6.udrei_37", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_38, {"UDREI_38",                                 "sbas_l1.mt6.udrei_38", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_39, {"UDREI_39",                                 "sbas_l1.mt6.udrei_39", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_40, {"UDREI_40",                                 "sbas_l1.mt6.udrei_40", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_41, {"UDREI_41",                                 "sbas_l1.mt6.udrei_41", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_42, {"UDREI_42",                                 "sbas_l1.mt6.udrei_42", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_43, {"UDREI_43",                                 "sbas_l1.mt6.udrei_43", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_44, {"UDREI_44",                                 "sbas_l1.mt6.udrei_44", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_45, {"UDREI_45",                                 "sbas_l1.mt6.udrei_45", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_46, {"UDREI_46",                                 "sbas_l1.mt6.udrei_46", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_47, {"UDREI_47",                                 "sbas_l1.mt6.udrei_47", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_48, {"UDREI_48",                                 "sbas_l1.mt6.udrei_48", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_49, {"UDREI_49",                                 "sbas_l1.mt6.udrei_49", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_50, {"UDREI_50",                                 "sbas_l1.mt6.udrei_50", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt6_udrei_51, {"UDREI_51",                                 "sbas_l1.mt6.udrei_51", FT_UINT16, BASE_DEC,  VALS(UDREI_EVALUATION), 0x03c0, NULL, HFILL}},

        // MT7
        {&hf_sbas_l1_mt7,          {"MT7",                                "sbas_l1.mt7",          FT_NONE,   BASE_NONE, NULL,                               0x0,    NULL, HFILL}},
        {&hf_sbas_l1_mt7_t_lat,    {"System Latency (t_lat)",             "sbas_l1.mt7.t_lat",    FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_seconds,     0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_iodp,     {"Issue of Data - PRN (IODP)",         "sbas_l1.mt7.iodp",     FT_UINT8,  BASE_DEC,  NULL,                               0x30,   NULL, HFILL}},
        {&hf_sbas_l1_mt7_spare,    {"Spare",                              "sbas_l1.mt7.spare",    FT_UINT8,  BASE_DEC,  NULL,                               0x0c,   NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_1,     {"Degradation Factor Indicator ai_1",  "sbas_l1.mt7.ai_1",     FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_2,     {"Degradation Factor Indicator ai_2",  "sbas_l1.mt7.ai_2",     FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_3,     {"Degradation Factor Indicator ai_3",  "sbas_l1.mt7.ai_3",     FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_4,     {"Degradation Factor Indicator ai_4",  "sbas_l1.mt7.ai_4",     FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_5,     {"Degradation Factor Indicator ai_5",  "sbas_l1.mt7.ai_5",     FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_6,     {"Degradation Factor Indicator ai_6",  "sbas_l1.mt7.ai_6",     FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_7,     {"Degradation Factor Indicator ai_7",  "sbas_l1.mt7.ai_7",     FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_8,     {"Degradation Factor Indicator ai_8",  "sbas_l1.mt7.ai_8",     FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_9,     {"Degradation Factor Indicator ai_9",  "sbas_l1.mt7.ai_9",     FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_10,    {"Degradation Factor Indicator ai_10", "sbas_l1.mt7.ai_10",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_11,    {"Degradation Factor Indicator ai_11", "sbas_l1.mt7.ai_11",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_12,    {"Degradation Factor Indicator ai_12", "sbas_l1.mt7.ai_12",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_13,    {"Degradation Factor Indicator ai_13", "sbas_l1.mt7.ai_13",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_14,    {"Degradation Factor Indicator ai_14", "sbas_l1.mt7.ai_14",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_15,    {"Degradation Factor Indicator ai_15", "sbas_l1.mt7.ai_15",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_16,    {"Degradation Factor Indicator ai_16", "sbas_l1.mt7.ai_16",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_17,    {"Degradation Factor Indicator ai_17", "sbas_l1.mt7.ai_17",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_18,    {"Degradation Factor Indicator ai_18", "sbas_l1.mt7.ai_18",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_19,    {"Degradation Factor Indicator ai_19", "sbas_l1.mt7.ai_19",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_20,    {"Degradation Factor Indicator ai_20", "sbas_l1.mt7.ai_20",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_21,    {"Degradation Factor Indicator ai_21", "sbas_l1.mt7.ai_21",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_22,    {"Degradation Factor Indicator ai_22", "sbas_l1.mt7.ai_22",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_23,    {"Degradation Factor Indicator ai_23", "sbas_l1.mt7.ai_23",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_24,    {"Degradation Factor Indicator ai_24", "sbas_l1.mt7.ai_24",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_25,    {"Degradation Factor Indicator ai_25", "sbas_l1.mt7.ai_25",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_26,    {"Degradation Factor Indicator ai_26", "sbas_l1.mt7.ai_26",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_27,    {"Degradation Factor Indicator ai_27", "sbas_l1.mt7.ai_27",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_28,    {"Degradation Factor Indicator ai_28", "sbas_l1.mt7.ai_28",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_29,    {"Degradation Factor Indicator ai_29", "sbas_l1.mt7.ai_29",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_30,    {"Degradation Factor Indicator ai_30", "sbas_l1.mt7.ai_30",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_31,    {"Degradation Factor Indicator ai_31", "sbas_l1.mt7.ai_31",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_32,    {"Degradation Factor Indicator ai_32", "sbas_l1.mt7.ai_32",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_33,    {"Degradation Factor Indicator ai_33", "sbas_l1.mt7.ai_33",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_34,    {"Degradation Factor Indicator ai_34", "sbas_l1.mt7.ai_34",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_35,    {"Degradation Factor Indicator ai_35", "sbas_l1.mt7.ai_35",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_36,    {"Degradation Factor Indicator ai_36", "sbas_l1.mt7.ai_36",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_37,    {"Degradation Factor Indicator ai_37", "sbas_l1.mt7.ai_37",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_38,    {"Degradation Factor Indicator ai_38", "sbas_l1.mt7.ai_38",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_39,    {"Degradation Factor Indicator ai_39", "sbas_l1.mt7.ai_39",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_40,    {"Degradation Factor Indicator ai_40", "sbas_l1.mt7.ai_40",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_41,    {"Degradation Factor Indicator ai_41", "sbas_l1.mt7.ai_41",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_42,    {"Degradation Factor Indicator ai_42", "sbas_l1.mt7.ai_42",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_43,    {"Degradation Factor Indicator ai_43", "sbas_l1.mt7.ai_43",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_44,    {"Degradation Factor Indicator ai_44", "sbas_l1.mt7.ai_44",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_45,    {"Degradation Factor Indicator ai_45", "sbas_l1.mt7.ai_45",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_46,    {"Degradation Factor Indicator ai_46", "sbas_l1.mt7.ai_46",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_47,    {"Degradation Factor Indicator ai_47", "sbas_l1.mt7.ai_47",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_48,    {"Degradation Factor Indicator ai_48", "sbas_l1.mt7.ai_48",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_49,    {"Degradation Factor Indicator ai_49", "sbas_l1.mt7.ai_49",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_50,    {"Degradation Factor Indicator ai_50", "sbas_l1.mt7.ai_50",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt7_ai_51,    {"Degradation Factor Indicator ai_51", "sbas_l1.mt7.ai_51",    FT_UINT16, BASE_DEC,  VALS(DEGRADATION_FACTOR_INDICATOR), 0x03c0, NULL, HFILL}},

        // MT17
        {&hf_sbas_l1_mt17,                                                {"MT17",                                   "sbas_l1.mt17",                                                FT_NONE,    BASE_NONE,   NULL,                          0x0,        NULL, HFILL}},
        {&hf_sbas_l1_mt17_reserved,                                       {"Reserved",                               "sbas_l1.mt17.reserved",                                       FT_UINT8,   BASE_HEX,    NULL,                          0xc0,       NULL, HFILL}},
        {&hf_sbas_l1_mt17_prn,                                            {"PRN",                                    "sbas_l1.mt17.prn",                                            FT_UINT16,  BASE_DEC,    NULL,                          0x3fc0,     NULL, HFILL}},
        {&hf_sbas_l1_mt17_health_and_status,                              {"Health and Status",                      "sbas_l1.mt17.health_and_status",                              FT_UINT16,  BASE_HEX,    NULL,                          0x3fc0,     NULL, HFILL}},
        {&hf_sbas_l1_mt17_health_and_status_spid,                         {"Service Provider Identifier",            "sbas_l1.mt17.health_and_status.spid",                         FT_UINT16,  BASE_DEC,    VALS(SBAS_SPID),               0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt17_health_and_status_spare,                        {"Spare",                                  "sbas_l1.mt17.health_and_status.spare",                        FT_UINT16,  BASE_HEX,    NULL,                          0x0200,     NULL, HFILL}},
        {&hf_sbas_l1_mt17_health_and_status_sat_status_basic_corrections, {"Satellite Status and Basic Corrections", "sbas_l1.mt17.health_and_status.sat_status_basic_corrections", FT_BOOLEAN, 16,          TFS(&tfs_off_on),              0x0100,     NULL, HFILL}},
        {&hf_sbas_l1_mt17_health_and_status_precision_corrections,        {"Precision Corrections",                  "sbas_l1.mt17.health_and_status.precision_corrections",        FT_BOOLEAN, 16,          TFS(&tfs_off_on),              0x0080,     NULL, HFILL}},
        {&hf_sbas_l1_mt17_health_and_status_ranging,                      {"Ranging",                                "sbas_l1.mt17.health_and_status.ranging",                      FT_BOOLEAN, 16,          TFS(&tfs_off_on),              0x0040,     NULL, HFILL}},
        {&hf_sbas_l1_mt17_x_ga,                                           {"X_G,A",                                  "sbas_l1.mt17.x_ga",                                           FT_INT32,   BASE_CUSTOM, CF_FUNC(&fmt_geo_xy_position), 0x3fff8000, NULL, HFILL}},
        {&hf_sbas_l1_mt17_y_ga,                                           {"Y_G,A",                                  "sbas_l1.mt17.y_ga",                                           FT_INT32,   BASE_CUSTOM, CF_FUNC(&fmt_geo_xy_position), 0x7fff0000, NULL, HFILL}},
        {&hf_sbas_l1_mt17_z_ga,                                           {"Z_G,A",                                  "sbas_l1.mt17.z_ga",                                           FT_INT32,   BASE_CUSTOM, CF_FUNC(&fmt_geo_z_position),  0x0000ff80, NULL, HFILL}},
        {&hf_sbas_l1_mt17_x_ga_vel,                                       {"X_G,A velocity",                         "sbas_l1.mt17.x_ga_vel",                                       FT_INT32,   BASE_CUSTOM, CF_FUNC(&fmt_geo_xy_velocity), 0x00000070, NULL, HFILL}},
        {&hf_sbas_l1_mt17_y_ga_vel,                                       {"Y_G,A velocity",                         "sbas_l1.mt17.y_ga_vel",                                       FT_INT32,   BASE_CUSTOM, CF_FUNC(&fmt_geo_xy_velocity), 0x0000000e, NULL, HFILL}},
        {&hf_sbas_l1_mt17_z_ga_vel,                                       {"Z_G,A velocity",                         "sbas_l1.mt17.z_ga_vel",                                       FT_INT32,   BASE_CUSTOM, CF_FUNC(&fmt_geo_z_velocity),  0x000001e0, NULL, HFILL}},
        {&hf_sbas_l1_mt17_t_a,                                            {"t_almanac",                              "sbas_l1.mt17.t_a",                                            FT_UINT32,  BASE_CUSTOM, CF_FUNC(&fmt_time_of_almanac), 0x0001ffc0, NULL, HFILL}},

        // MT24
        {&hf_sbas_l1_mt24,                  {"MT24",                                     "sbas_l1.mt24",                  FT_NONE,   BASE_NONE,   NULL,                          0x0,        NULL, HFILL}},
        {&hf_sbas_l1_mt24_fc_i1,            {"Fast Correction i1 (FC_i1)",               "sbas_l1.mt24.fc_i1",            FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt24_fc_i2,            {"Fast Correction i2 (FC_i2)",               "sbas_l1.mt24.fc_i2",            FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt24_fc_i3,            {"Fast Correction i3 (FC_i3)",               "sbas_l1.mt24.fc_i3",            FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt24_fc_i4,            {"Fast Correction i4 (FC_i4)",               "sbas_l1.mt24.fc_i4",            FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt24_fc_i5,            {"Fast Correction i5 (FC_i5)",               "sbas_l1.mt24.fc_i5",            FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt24_fc_i6,            {"Fast Correction i6 (FC_i6)",               "sbas_l1.mt24.fc_i6",            FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt24_udrei_i1,         {"UDREI_i1",                                 "sbas_l1.mt24.udrei_i1",         FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt24_udrei_i2,         {"UDREI_i2",                                 "sbas_l1.mt24.udrei_i2",         FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt24_udrei_i3,         {"UDREI_i3",                                 "sbas_l1.mt24.udrei_i3",         FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt24_udrei_i4,         {"UDREI_i4",                                 "sbas_l1.mt24.udrei_i4",         FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt24_udrei_i5,         {"UDREI_i5",                                 "sbas_l1.mt24.udrei_i5",         FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x03c0,     NULL, HFILL}},
        {&hf_sbas_l1_mt24_udrei_i6,         {"UDREI_i6",                                 "sbas_l1.mt24.udrei_i6",         FT_UINT16, BASE_DEC,    VALS(UDREI_EVALUATION),        0x3c00,     NULL, HFILL}},
        {&hf_sbas_l1_mt24_iodp,             {"Issue of Data - PRN (IODP)",               "sbas_l1.mt24.iodp",             FT_UINT8,  BASE_DEC,    NULL,                          0x03,   NULL, HFILL}},
        {&hf_sbas_l1_mt24_fc_type,          {"Fast Correction Type ID",                  "sbas_l1.mt24.fc_type",          FT_UINT8,  BASE_DEC,    NULL,                          0xc0,   NULL, HFILL}},
        {&hf_sbas_l1_mt24_iodf_j,           {"Issue of Data - Fast Correction (IODF_j)", "sbas_l1.mt24.iodf_j",           FT_UINT8,  BASE_DEC,    NULL,                          0x30,       NULL, HFILL}},
        {&hf_sbas_l1_mt24_spare,            {"Spare",                                    "sbas_l1.mt24.spare",            FT_UINT8,  BASE_DEC,    NULL,                           0x0f,    NULL, HFILL}},
        {&hf_sbas_l1_mt24_velocity_code,    {"Velocity Code",                            "sbas_l1.mt24.velocity_code",    FT_UINT8,  BASE_DEC,    NULL,                           0x80,   NULL, HFILL}},
        {&hf_sbas_l1_mt24_v0_prn_mask_nr_1, {"PRN Mask Number",                          "sbas_l1.mt24.v0.prn_mask_nr_1", FT_UINT8,  BASE_DEC,    NULL,                           0x7e, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v0_iod_1,         {"Issue of Data (IOD_i)",                    "sbas_l1.mt24.v0.iod_1",         FT_UINT16, BASE_DEC,    NULL,                           0x01fe, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v0_delta_x_1,     {"dx_i",                                     "sbas_l1.mt24.v0.dx_1",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),  0x01ff, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v0_delta_y_1,     {"dy_i",                                     "sbas_l1.mt24.v0.dy_1",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),  0xff80, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v0_delta_z_1,     {"dz_i",                                     "sbas_l1.mt24.v0.dz_1",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),  0x7fc0, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v0_delta_a_1_f0,  {"da_i_f0",                                  "sbas_l1.mt24.v0.da_f0_1",       FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_clock_correction), 0x3ff0, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v0_prn_mask_nr_2, {"PRN Mask Number",                          "sbas_l1.mt24.v0.prn_mask_nr_2", FT_UINT16, BASE_DEC,    NULL,                           0x0fc0, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v0_iod_2,         {"Issue of Data (IOD_i)",                    "sbas_l1.mt24.v0.iod_2",         FT_UINT16, BASE_DEC,    NULL,                           0x3fc0, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v0_delta_x_2,     {"dx_i",                                     "sbas_l1.mt24.v0.dx_2",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),  0x3fe0, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v0_delta_y_2,     {"dy_i",                                     "sbas_l1.mt24.v0.dy_2",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),  0x1ff0, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v0_delta_z_2,     {"dz_i",                                     "sbas_l1.mt24.v0.dz_2",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),  0x0ff8, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v0_delta_a_2_f0,  {"da_i_f0",                                  "sbas_l1.mt24.v0.da_f0_2",       FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_clock_correction), 0x07fe, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v0_iodp,          {"Issue of Data PRN (IODP)",                 "sbas_l1.mt24.v0.iodp",          FT_UINT16, BASE_DEC,    NULL,                           0x0180,   NULL, HFILL}},
        {&hf_sbas_l1_mt24_v0_spare,         {"Spare",                                    "sbas_l1.mt24.v0.spare",         FT_UINT8,  BASE_DEC,    NULL,                           0x40,   NULL, HFILL}},
        {&hf_sbas_l1_mt24_v1_prn_mask_nr,   {"PRN Mask Number",                          "sbas_l1.mt24.v1.prn_mask_nr",   FT_UINT8,  BASE_DEC,    NULL,                           0x7e, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v1_iod,           {"Issue of Data (IOD_i)",                    "sbas_l1.mt24.v1.iod",           FT_UINT16, BASE_DEC,    NULL,                           0x01fe, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v1_delta_x,       {"dx_i",                                     "sbas_l1.mt24.v1.dx",            FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x01ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v1_delta_y,       {"dy_i",                                     "sbas_l1.mt24.v1.dy",            FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x3ff80000, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v1_delta_z,       {"dz_i",                                     "sbas_l1.mt24.v1.dz",            FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x07ff0000, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v1_delta_a_f0,    {"da_i_f0",                                  "sbas_l1.mt24.v1.da_f0",         FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_clock_correction),     0xffe00000, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v1_delta_x_vel,   {"dx_vel_i",                                 "sbas_l1.mt24.v1.dx_vel",        FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_velo_correction),      0x1fe00000, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v1_delta_y_vel,   {"dy_vel_i",                                 "sbas_l1.mt24.v1.dy_vel",        FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_velo_correction),      0x1fe00000, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v1_delta_z_vel,   {"dz_vel_i",                                 "sbas_l1.mt24.v1.dz_vel",        FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_velo_correction),      0x1fe00000, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v1_delta_a_f1,    {"da_i_f1",                                  "sbas_l1.mt24.v1.da_f1",         FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_clk_rate_correction),  0x1fe00000, NULL, HFILL}},
        {&hf_sbas_l1_mt24_v1_t_lt,          {"t_i_lt",                                   "sbas_l1.mt24.v1.t_lt",          FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_time_of_applicability),0x1fff,     NULL, HFILL}},
        {&hf_sbas_l1_mt24_v1_iodp,          {"Issue of Data PRN (IODP)",                 "sbas_l1.mt24.v1.iodp",          FT_UINT8,  BASE_DEC,    NULL,                               0xc0,       NULL, HFILL}},

        // MT25
        {&hf_sbas_l1_mt25,                       {"MT25",                     "sbas_l1.mt25",                     FT_NONE,   BASE_NONE,   NULL,                               0x0,        NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_velocity_code,      {"Velocity Code",            "sbas_l1.mt25.h1.velocity_code",    FT_UINT8,  BASE_DEC,    NULL,                               0x02,       NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v0_prn_mask_nr_1,   {"PRN Mask Number",          "sbas_l1.mt25.h1.v0.prn_mask_nr_1", FT_UINT16, BASE_DEC,    NULL,                               0x01f8,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v0_iod_1,           {"Issue of Data (IOD_i)",    "sbas_l1.mt25.h1.v0.iod_1",         FT_UINT16, BASE_DEC,    NULL,                               0x07f8,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v0_delta_x_1,       {"dx_i",                     "sbas_l1.mt25.h1.v0.dx_1",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x07fc,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v0_delta_y_1,       {"dy_i",                     "sbas_l1.mt25.h1.v0.dy_1",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x03fe,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v0_delta_z_1,       {"dz_i",                     "sbas_l1.mt25.h1.v0.dz_1",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x01ff,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v0_delta_a_1_f0,    {"da_i_f0",                  "sbas_l1.mt25.h1.v0.da_f0_1",       FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_clock_correction),     0xffc0,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v0_prn_mask_nr_2,   {"PRN Mask Number",          "sbas_l1.mt25.h1.v0.prn_mask_nr_2", FT_UINT8,  BASE_DEC,    NULL,                               0x3f,       NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v0_iod_2,           {"Issue of Data (IOD_i)",    "sbas_l1.mt25.h1.v0.iod_2",         FT_UINT8,  BASE_DEC,    NULL,                               0xff,       NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v0_delta_x_2,       {"dx_i",                     "sbas_l1.mt25.h1.v0.dx_2",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0xff80,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v0_delta_y_2,       {"dy_i",                     "sbas_l1.mt25.h1.v0.dy_2",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x7fc0,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v0_delta_z_2,       {"dz_i",                     "sbas_l1.mt25.h1.v0.dz_2",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x3fe0,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v0_delta_a_2_f0,    {"da_i_f0",                  "sbas_l1.mt25.h1.v0.da_f0_2",       FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_clock_correction),     0x1ff8,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v0_iodp,            {"Issue of Data - PRN (IODP)", "sbas_l1.mt25.h1.v0.iodp",          FT_UINT8,  BASE_DEC,    NULL,                               0x06,       NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v0_spare,           {"Spare",                    "sbas_l1.mt25.h1.v0.spare",         FT_NONE,   BASE_NONE,   NULL,                               0x0,        NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v1_prn_mask_nr,     {"PRN Mask Number",          "sbas_l1.mt25.h1.v1.prn_mask_nr_1", FT_UINT16, BASE_DEC,    NULL,                               0x01f8,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v1_iod,             {"Issue of Data (IOD_i)",    "sbas_l1.mt25.h1.v1.iod",           FT_UINT16, BASE_DEC,    NULL,                               0x07f8,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v1_delta_x,         {"dx_i",                     "sbas_l1.mt25.h1.v1.dx",            FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x07ff0000, NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v1_delta_y,         {"dy_i",                     "sbas_l1.mt25.h1.v1.dy",            FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0xffe00000, NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v1_delta_z,         {"dz_i",                     "sbas_l1.mt25.h1.v1.dz",            FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x1ffc0000, NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v1_delta_a_f0,      {"da_i_f0",                  "sbas_l1.mt25.h1.v1.da_f0",         FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_clock_correction),     0x03ff8000, NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v1_delta_x_vel,     {"dx_vel_i",                 "sbas_l1.mt25.h1.v1.dx_vel",        FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_velo_correction),      0x7f800000, NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v1_delta_y_vel,     {"dy_vel_i",                 "sbas_l1.mt25.h1.v1.dy_vel",        FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_velo_correction),      0x7f800000, NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v1_delta_z_vel,     {"dz_vel_i",                 "sbas_l1.mt25.h1.v1.dz_vel",        FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_velo_correction),      0x7f800000, NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v1_delta_a_f1,      {"da_i_f1",                  "sbas_l1.mt25.h1.v1.da_f1",         FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_clk_rate_correction),  0x7f800000, NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v1_t_lt,            {"t_i_lt",                   "sbas_l1.mt25.h1.v1.t_lt",          FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_time_of_applicability),0x7ffc,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h1_v1_iodp,            {"Issue of Data - PRN (IODP)", "sbas_l1.mt25.h1.v1.iodp",          FT_UINT8,  BASE_DEC,    NULL,                               0x03,       NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_velocity_code,      {"Velocity Code",            "sbas_l1.mt25.h2.velocity_code",    FT_UINT8,  BASE_DEC,    NULL,                               0x80,       NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v0_prn_mask_nr_1,   {"PRN Mask Number",          "sbas_l1.mt25.h2.v0.prn_mask_nr_1", FT_UINT8,  BASE_DEC,    NULL,                               0x7e,       NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v0_iod_1,           {"Issue of Data (IOD_i)",    "sbas_l1.mt25.h2.v0.iod_1",         FT_UINT16, BASE_DEC,    NULL,                               0x01fe,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v0_delta_x_1,       {"dx_i",                     "sbas_l1.mt25.h2.v0.dx_1",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x01ff,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v0_delta_y_1,       {"dy_i",                     "sbas_l1.mt25.h2.v0.dy_1",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0xff80,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v0_delta_z_1,       {"dz_i",                     "sbas_l1.mt25.h2.v0.dz_1",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x7fc0,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v0_delta_a_1_f0,    {"da_i_f0",                  "sbas_l1.mt25.h2.v0.da_f0_1",       FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_clock_correction),     0x3ff0,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v0_prn_mask_nr_2,   {"PRN Mask Number",          "sbas_l1.mt25.h2.v0.prn_mask_nr_2", FT_UINT16, BASE_DEC,    NULL,                               0x0fc0,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v0_iod_2,           {"Issue of Data (IOD_i)",    "sbas_l1.mt25.h2.v0.iod_2",         FT_UINT16, BASE_DEC,    NULL,                               0x3fc0,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v0_delta_x_2,       {"dx_i",                     "sbas_l1.mt25.h2.v0.dx_2",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x3fe0,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v0_delta_y_2,       {"dy_i",                     "sbas_l1.mt25.h2.v0.dy_2",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x1ff0,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v0_delta_z_2,       {"dz_i",                     "sbas_l1.mt25.h2.v0.dz_2",          FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x0ff8,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v0_delta_a_2_f0,    {"da_i_f0",                  "sbas_l1.mt25.h2.v0.da_f0_2",       FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_clock_correction),     0x07fe,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v0_iodp,            {"Issue of Data PRN (IODP)", "sbas_l1.mt25.h2.v0.iodp",          FT_UINT16, BASE_DEC,    NULL,                               0x0180,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v0_spare,           {"Spare",                    "sbas_l1.mt25.h2.v0.spare",         FT_NONE,   BASE_NONE,   NULL,                               0x0,        NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v1_prn_mask_nr,     {"PRN Mask Number",          "sbas_l1.mt25.h2.v1.prn_mask_nr",   FT_UINT8,  BASE_DEC,    NULL,                               0x7e,       NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v1_iod,             {"Issue of Data (IOD_i)",    "sbas_l1.mt25.h2.v1.iod",           FT_UINT16, BASE_DEC,    NULL,                               0x01fe,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v1_delta_x,         {"dx_i",                     "sbas_l1.mt25.h2.v1.dx",            FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x01ffc000, NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v1_delta_y,         {"dy_i",                     "sbas_l1.mt25.h2.v1.dy",            FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x3ff80000, NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v1_delta_z,         {"dz_i",                     "sbas_l1.mt25.h2.v1.dz",            FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_correction_125m),      0x07ff0000, NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v1_delta_a_f0,      {"da_i_f0",                  "sbas_l1.mt25.h2.v1.da_f0",         FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_clock_correction),     0xffe00000, NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v1_delta_x_vel,     {"dx_vel_i",                 "sbas_l1.mt25.h2.v1.dx_vel",        FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_velo_correction),      0x1fe00000, NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v1_delta_y_vel,     {"dy_vel_i",                 "sbas_l1.mt25.h2.v1.dy_vel",        FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_velo_correction),      0x1fe00000, NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v1_delta_z_vel,     {"dz_vel_i",                 "sbas_l1.mt25.h2.v1.dz_vel",        FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_velo_correction),      0x1fe00000, NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v1_delta_a_f1,      {"da_i_f1",                  "sbas_l1.mt25.h2.v1.da_f1",         FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_clk_rate_correction),  0x1fe00000, NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v1_t_lt,            {"t_i_lt",                   "sbas_l1.mt25.h2.v1.t_lt",          FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_time_of_applicability),0x1fff,     NULL, HFILL}},
        {&hf_sbas_l1_mt25_h2_v1_iodp,            {"Issue of Data PRN (IODP)", "sbas_l1.mt25.h2.v1.iodp",          FT_UINT8,  BASE_DEC,    NULL,                               0xc0,       NULL, HFILL}},

        // MT26
        {&hf_sbas_l1_mt26,                           {"MT26",                          "sbas_l1.mt26",                                     FT_NONE,   BASE_NONE,   NULL,                          0x0,    NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_band_id,               {"IGP Band Identifier",           "sbas_l1.mt26.igp_band_id",                         FT_UINT16, BASE_DEC,    NULL,                          0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_block_id,              {"IGP Block Identifier",          "sbas_l1.mt26.igp_block_id",                        FT_UINT16, BASE_DEC,    NULL,                          0x3c,   NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_vertical_delay_est_1,  {"IGP Vertical Delay Estimate 1", "sbas_l1.mt26.igp_vertical_delay_est_1",            FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03fe, NULL, HFILL}},
        {&hf_sbas_l1_mt26_givei_1,                   {"Grid Ionospheric Vertical Error Indicator 1 (GIVEI_1)", "sbas_l1.mt26.givei_1",     FT_UINT16, BASE_DEC,    VALS(GIVEI_EVALUATION),        0x01e0, NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_vertical_delay_est_2,  {"IGP Vertical Delay Estimate 2", "sbas_l1.mt26.igp_vertical_delay_est_2",            FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x1ff0, NULL, HFILL}},
        {&hf_sbas_l1_mt26_givei_2,                   {"Grid Ionospheric Vertical Error Indicator 2 (GIVEI_2)", "sbas_l1.mt26.givei_2",     FT_UINT16, BASE_DEC,    VALS(GIVEI_EVALUATION),        0x0f00, NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_vertical_delay_est_3,  {"IGP Vertical Delay Estimate 3", "sbas_l1.mt26.igp_vertical_delay_est_3",            FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0xff80, NULL, HFILL}},
        {&hf_sbas_l1_mt26_givei_3,                   {"Grid Ionospheric Vertical Error Indicator 3 (GIVEI_3)", "sbas_l1.mt26.givei_3",     FT_UINT16, BASE_DEC,    VALS(GIVEI_EVALUATION),        0x7800, NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_vertical_delay_est_4,  {"IGP Vertical Delay Estimate 4", "sbas_l1.mt26.igp_vertical_delay_est_4",            FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x07fc, NULL, HFILL}},
        {&hf_sbas_l1_mt26_givei_4,                   {"Grid Ionospheric Vertical Error Indicator 4 (GIVEI_4)", "sbas_l1.mt26.givei_4",     FT_UINT16, BASE_DEC,    VALS(GIVEI_EVALUATION),        0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_vertical_delay_est_5,  {"IGP Vertical Delay Estimate 5", "sbas_l1.mt26.igp_vertical_delay_est_5",            FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3fe0, NULL, HFILL}},
        {&hf_sbas_l1_mt26_givei_5,                   {"Grid Ionospheric Vertical Error Indicator 5 (GIVEI_5)", "sbas_l1.mt26.givei_5",     FT_UINT16, BASE_DEC,    VALS(GIVEI_EVALUATION),        0x1e00, NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_vertical_delay_est_6,  {"IGP Vertical Delay Estimate 6", "sbas_l1.mt26.igp_vertical_delay_est_6",            FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x01ff, NULL, HFILL}},
        {&hf_sbas_l1_mt26_givei_6,                   {"Grid Ionospheric Vertical Error Indicator 6 (GIVEI_6)", "sbas_l1.mt26.givei_6",     FT_UINT16, BASE_DEC,    VALS(GIVEI_EVALUATION),        0xf000, NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_vertical_delay_est_7,  {"IGP Vertical Delay Estimate 7", "sbas_l1.mt26.igp_vertical_delay_est_7",            FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x0ff8, NULL, HFILL}},
        {&hf_sbas_l1_mt26_givei_7,                   {"Grid Ionospheric Vertical Error Indicator 7 (GIVEI_7)", "sbas_l1.mt26.givei_7",     FT_UINT16, BASE_DEC,    VALS(GIVEI_EVALUATION),        0x0780, NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_vertical_delay_est_8,  {"IGP Vertical Delay Estimate 8", "sbas_l1.mt26.igp_vertical_delay_est_8",            FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x7fc0, NULL, HFILL}},
        {&hf_sbas_l1_mt26_givei_8,                   {"Grid Ionospheric Vertical Error Indicator 8 (GIVEI_8)", "sbas_l1.mt26.givei_8",     FT_UINT16, BASE_DEC,    VALS(GIVEI_EVALUATION),        0x3c00, NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_vertical_delay_est_9,  {"IGP Vertical Delay Estimate 9", "sbas_l1.mt26.igp_vertical_delay_est_9",            FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x03fe, NULL, HFILL}},
        {&hf_sbas_l1_mt26_givei_9,                   {"Grid Ionospheric Vertical Error Indicator 9 (GIVEI_9)", "sbas_l1.mt26.givei_9",     FT_UINT16, BASE_DEC,    VALS(GIVEI_EVALUATION),        0x01e0, NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_vertical_delay_est_10,  {"IGP Vertical Delay Estimate 10", "sbas_l1.mt26.igp_vertical_delay_est_10",         FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x1ff0, NULL, HFILL}},
        {&hf_sbas_l1_mt26_givei_10,                   {"Grid Ionospheric Vertical Error Indicator 10 (GIVEI_10)", "sbas_l1.mt26.givei_10", FT_UINT16, BASE_DEC,    VALS(GIVEI_EVALUATION),        0x0f00, NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_vertical_delay_est_11,  {"IGP Vertical Delay Estimate 11", "sbas_l1.mt26.igp_vertical_delay_est_11",         FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0xff80, NULL, HFILL}},
        {&hf_sbas_l1_mt26_givei_11,                   {"Grid Ionospheric Vertical Error Indicator 11 (GIVEI_11)", "sbas_l1.mt26.givei_11", FT_UINT16, BASE_DEC,    VALS(GIVEI_EVALUATION),        0x7800, NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_vertical_delay_est_12,  {"IGP Vertical Delay Estimate 12", "sbas_l1.mt26.igp_vertical_delay_est_12",         FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x07fc, NULL, HFILL}},
        {&hf_sbas_l1_mt26_givei_12,                   {"Grid Ionospheric Vertical Error Indicator 12 (GIVEI_12)", "sbas_l1.mt26.givei_12", FT_UINT16, BASE_DEC,    VALS(GIVEI_EVALUATION),        0x03c0, NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_vertical_delay_est_13,  {"IGP Vertical Delay Estimate 13", "sbas_l1.mt26.igp_vertical_delay_est_13",         FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x3fe0, NULL, HFILL}},
        {&hf_sbas_l1_mt26_givei_13,                   {"Grid Ionospheric Vertical Error Indicator 13 (GIVEI_13)", "sbas_l1.mt26.givei_13", FT_UINT16, BASE_DEC,    VALS(GIVEI_EVALUATION),        0x1e00, NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_vertical_delay_est_14,  {"IGP Vertical Delay Estimate 14", "sbas_l1.mt26.igp_vertical_delay_est_14",         FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x01ff, NULL, HFILL}},
        {&hf_sbas_l1_mt26_givei_14,                   {"Grid Ionospheric Vertical Error Indicator 14 (GIVEI_14)", "sbas_l1.mt26.givei_14", FT_UINT16, BASE_DEC,    VALS(GIVEI_EVALUATION),        0xf000, NULL, HFILL}},
        {&hf_sbas_l1_mt26_igp_vertical_delay_est_15,  {"IGP Vertical Delay Estimate 15", "sbas_l1.mt26.igp_vertical_delay_est_15",         FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_correction_125m), 0x0ff8, NULL, HFILL}},
        {&hf_sbas_l1_mt26_givei_15,                   {"Grid Ionospheric Vertical Error Indicator 15 (GIVEI_15)", "sbas_l1.mt26.givei_15", FT_UINT16, BASE_DEC,    VALS(GIVEI_EVALUATION),        0x0780, NULL, HFILL}},
        {&hf_sbas_l1_mt26_iodi_k,                     {"Issue of Data - IGP (IODI_k)", "sbas_l1.mt26.iodi_k",                              FT_UINT8,  BASE_DEC,    NULL,                          0x60,   NULL, HFILL}},
        {&hf_sbas_l1_mt26_spare,                      {"Spare", "sbas_l1.mt26.spare",                                                      FT_UINT16, BASE_DEC,    NULL,                          0x1fc0, NULL, HFILL}},

        // MT63
        {&hf_sbas_l1_mt63,         {"MT63",    "sbas_l1.mt63",         FT_NONE,  BASE_NONE, NULL, 0x00, NULL, HFILL}},
        {&hf_sbas_l1_mt63_spare_1, {"Spare 1", "sbas_l1.mt63.spare_1", FT_UINT8, BASE_HEX,  NULL, 0x03, NULL, HFILL}},
        {&hf_sbas_l1_mt63_spare_2, {"Spare 2", "sbas_l1.mt63.spare_2", FT_BYTES, SEP_SPACE, NULL, 0x00, NULL, HFILL}},
        {&hf_sbas_l1_mt63_spare_3, {"Spare 3", "sbas_l1.mt63.spare_3", FT_UINT8, BASE_HEX,  NULL, 0xc0, NULL, HFILL}},
    };

    expert_module_t *expert_sbas_l1;

    static ei_register_info ei[] = {
        {&ei_sbas_l1_preamble,          {"sbas_l1.illegal_preamble",          PI_PROTOCOL, PI_WARN, "Illegal preamble", EXPFILL}},
        {&ei_sbas_l1_mt0,               {"sbas_l1.mt0",                       PI_PROTOCOL, PI_WARN, "MT is 0", EXPFILL}},
        {&ei_sbas_l1_crc,               {"sbas_l1.crc",                       PI_CHECKSUM, PI_WARN, "CRC", EXPFILL}},
        {&ei_sbas_l1_mt26_igp_band_id,  {"sbas_l1.mt26.illegal_igp_band_id",  PI_PROTOCOL, PI_WARN, "Illegal IGP Band Identifier", EXPFILL}},
        {&ei_sbas_l1_mt26_igp_block_id, {"sbas_l1.mt26.illegal_igp_block_id", PI_PROTOCOL, PI_WARN, "Illegal IGP Block Identifier", EXPFILL}},
    };

    static int *ett[] = {
        &ett_sbas_l1,
        &ett_sbas_l1_mt0,
        &ett_sbas_l1_mt1,
        &ett_sbas_l1_mt2,
        &ett_sbas_l1_mt3,
        &ett_sbas_l1_mt4,
        &ett_sbas_l1_mt5,
        &ett_sbas_l1_mt6,
        &ett_sbas_l1_mt7,
        &ett_sbas_l1_mt17,
        &ett_sbas_l1_mt17_prn_data[0],
        &ett_sbas_l1_mt17_prn_data[1],
        &ett_sbas_l1_mt17_prn_data[2],
        &ett_sbas_l1_mt17_health_and_status,
        &ett_sbas_l1_mt24,
        &ett_sbas_l1_mt25,
        &ett_sbas_l1_mt26,
        &ett_sbas_l1_mt63,
    };

    proto_sbas_l1 = proto_register_protocol("SBAS L1 Navigation Message", "SBAS L1", "sbas_l1");

    proto_register_field_array(proto_sbas_l1, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_sbas_l1 = expert_register_protocol(proto_sbas_l1);
    expert_register_field_array(expert_sbas_l1, ei, array_length(ei));

    register_dissector("sbas_l1", dissect_sbas_l1, proto_sbas_l1);

    sbas_l1_mt_dissector_table = register_dissector_table("sbas_l1.mt",
            "SBAS L1 MT", proto_sbas_l1, FT_UINT8, BASE_DEC);
}


void proto_reg_handoff_sbas_l1(void) {
    dissector_add_uint("ubx.rxm.sfrbx.gnssid", GNSS_ID_SBAS,
        create_dissector_handle(dissect_sbas_l1, proto_sbas_l1));

    dissector_add_uint("sbas_l1.mt", 0,  create_dissector_handle(dissect_sbas_l1_mt0,  proto_sbas_l1));
    dissector_add_uint("sbas_l1.mt", 1,  create_dissector_handle(dissect_sbas_l1_mt1,  proto_sbas_l1));
    dissector_add_uint("sbas_l1.mt", 2,  create_dissector_handle(dissect_sbas_l1_mt2,  proto_sbas_l1));
    dissector_add_uint("sbas_l1.mt", 3,  create_dissector_handle(dissect_sbas_l1_mt3,  proto_sbas_l1));
    dissector_add_uint("sbas_l1.mt", 4,  create_dissector_handle(dissect_sbas_l1_mt4,  proto_sbas_l1));
    dissector_add_uint("sbas_l1.mt", 5,  create_dissector_handle(dissect_sbas_l1_mt5,  proto_sbas_l1));
    dissector_add_uint("sbas_l1.mt", 6,  create_dissector_handle(dissect_sbas_l1_mt6,  proto_sbas_l1));
    dissector_add_uint("sbas_l1.mt", 7,  create_dissector_handle(dissect_sbas_l1_mt7,  proto_sbas_l1));
    dissector_add_uint("sbas_l1.mt", 17, create_dissector_handle(dissect_sbas_l1_mt17, proto_sbas_l1));
    dissector_add_uint("sbas_l1.mt", 24, create_dissector_handle(dissect_sbas_l1_mt24, proto_sbas_l1));
    dissector_add_uint("sbas_l1.mt", 25, create_dissector_handle(dissect_sbas_l1_mt25, proto_sbas_l1));
    dissector_add_uint("sbas_l1.mt", 26, create_dissector_handle(dissect_sbas_l1_mt26, proto_sbas_l1));
    dissector_add_uint("sbas_l1.mt", 63, create_dissector_handle(dissect_sbas_l1_mt63, proto_sbas_l1));
}
