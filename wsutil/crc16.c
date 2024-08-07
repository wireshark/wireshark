/* crc16.c
 * CRC-16 routine
 *
 * 2004 Richard van der Hoff <richardv@mxtelecom.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References:
 *  "A Painless Guide to CRC Error Detection Algorithms", Ross Williams
 *      http://www.repairfaq.org/filipg/LINK/F_crc_v3.html
 *
 *  ITU-T Recommendation V.42 (2002), "Error-Correcting Procedures for
 *      DCEs using asynchronous-to-synchronous conversion", Para. 8.1.1.6.1
 */

#include "config.h"

#include <wsutil/crc16.h>

/*****************************************************************/

/*
 * Table for the CCITT/ITU/CRC-16 16-bit CRC
 *
 * Polynomial is
 *
 *     x^16 + x^12 + x^5 + 1
 */

/*                                                               */
/* CRC LOOKUP TABLE                                              */
/* ================                                              */
/* The following CRC lookup table was generated automagically    */
/* by the Rocksoft^tm Model CRC Algorithm Table Generation       */
/* Program V1.0 using the following model parameters:            */
/*                                                               */
/*    Width   : 2 bytes.                                         */
/*    Poly    : 0x1021                                           */
/*    Reverse : true.                                           */
/*                                                               */
/* For more information on the Rocksoft^tm Model CRC Algorithm,  */
/* see the document titled "A Painless Guide to CRC Error        */
/* Detection Algorithms" by Ross Williams.  See                  */
/*                                                               */
/*    http://www.ross.net/crc/crcpaper.html                      */
/*                                                               */
/* which links to a text version and an HTML-but-not-all-on-one- */
/* page version, or various HTML-all-on-one-page versions such   */
/* as the one at                                                 */
/*                                                               */
/*    http://www.geocities.com/SiliconValley/Pines/8659/crc.htm  */
/*                                                               */
/* (search for the title to find others).                        */
/*                                                               */
/*****************************************************************/

static const unsigned crc16_ccitt_table_reverse[256] =
{
    0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF,
    0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
    0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E,
    0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876,
    0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD,
    0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
    0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C,
    0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974,
    0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
    0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
    0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A,
    0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
    0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9,
    0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
    0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738,
    0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70,
    0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7,
    0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
    0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036,
    0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
    0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5,
    0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
    0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134,
    0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
    0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3,
    0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
    0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
    0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
    0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1,
    0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
    0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330,
    0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78
};

/* Same as above, only without reverse (Reverse=false) */
static const unsigned crc16_ccitt_table[256] =
{
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
    0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
    0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
    0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
    0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
    0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
    0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
    0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
    0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
    0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
    0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
    0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
    0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
    0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
    0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
    0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
    0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
    0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
    0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
    0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
    0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
    0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
    0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
};

/* This table was compiled using the polynom 0x5935 */
static const unsigned crc16_precompiled_5935[256] =
{
    0x0000, 0x5935, 0xB26A, 0xEB5F, 0x3DE1, 0x64D4, 0x8F8B, 0xD6BE,
    0x7BC2, 0x22F7, 0xC9A8, 0x909D, 0x4623, 0x1F16, 0xF449, 0xAD7C,
    0xF784, 0xAEB1, 0x45EE, 0x1CDB, 0xCA65, 0x9350, 0x780F, 0x213A,
    0x8C46, 0xD573, 0x3E2C, 0x6719, 0xB1A7, 0xE892, 0x03CD, 0x5AF8,
    0xB63D, 0xEF08, 0x0457, 0x5D62, 0x8BDC, 0xD2E9, 0x39B6, 0x6083,
    0xCDFF, 0x94CA, 0x7F95, 0x26A0, 0xF01E, 0xA92B, 0x4274, 0x1B41,
    0x41B9, 0x188C, 0xF3D3, 0xAAE6, 0x7C58, 0x256D, 0xCE32, 0x9707,
    0x3A7B, 0x634E, 0x8811, 0xD124, 0x079A, 0x5EAF, 0xB5F0, 0xECC5,
    0x354F, 0x6C7A, 0x8725, 0xDE10, 0x08AE, 0x519B, 0xBAC4, 0xE3F1,
    0x4E8D, 0x17B8, 0xFCE7, 0xA5D2, 0x736C, 0x2A59, 0xC106, 0x9833,
    0xC2CB, 0x9BFE, 0x70A1, 0x2994, 0xFF2A, 0xA61F, 0x4D40, 0x1475,
    0xB909, 0xE03C, 0x0B63, 0x5256, 0x84E8, 0xDDDD, 0x3682, 0x6FB7,
    0x8372, 0xDA47, 0x3118, 0x682D, 0xBE93, 0xE7A6, 0x0CF9, 0x55CC,
    0xF8B0, 0xA185, 0x4ADA, 0x13EF, 0xC551, 0x9C64, 0x773B, 0x2E0E,
    0x74F6, 0x2DC3, 0xC69C, 0x9FA9, 0x4917, 0x1022, 0xFB7D, 0xA248,
    0x0F34, 0x5601, 0xBD5E, 0xE46B, 0x32D5, 0x6BE0, 0x80BF, 0xD98A,
    0x6A9E, 0x33AB, 0xD8F4, 0x81C1, 0x577F, 0x0E4A, 0xE515, 0xBC20,
    0x115C, 0x4869, 0xA336, 0xFA03, 0x2CBD, 0x7588, 0x9ED7, 0xC7E2,
    0x9D1A, 0xC42F, 0x2F70, 0x7645, 0xA0FB, 0xF9CE, 0x1291, 0x4BA4,
    0xE6D8, 0xBFED, 0x54B2, 0x0D87, 0xDB39, 0x820C, 0x6953, 0x3066,
    0xDCA3, 0x8596, 0x6EC9, 0x37FC, 0xE142, 0xB877, 0x5328, 0x0A1D,
    0xA761, 0xFE54, 0x150B, 0x4C3E, 0x9A80, 0xC3B5, 0x28EA, 0x71DF,
    0x2B27, 0x7212, 0x994D, 0xC078, 0x16C6, 0x4FF3, 0xA4AC, 0xFD99,
    0x50E5, 0x09D0, 0xE28F, 0xBBBA, 0x6D04, 0x3431, 0xDF6E, 0x865B,
    0x5FD1, 0x06E4, 0xEDBB, 0xB48E, 0x6230, 0x3B05, 0xD05A, 0x896F,
    0x2413, 0x7D26, 0x9679, 0xCF4C, 0x19F2, 0x40C7, 0xAB98, 0xF2AD,
    0xA855, 0xF160, 0x1A3F, 0x430A, 0x95B4, 0xCC81, 0x27DE, 0x7EEB,
    0xD397, 0x8AA2, 0x61FD, 0x38C8, 0xEE76, 0xB743, 0x5C1C, 0x0529,
    0xE9EC, 0xB0D9, 0x5B86, 0x02B3, 0xD40D, 0x8D38, 0x6667, 0x3F52,
    0x922E, 0xCB1B, 0x2044, 0x7971, 0xAFCF, 0xF6FA, 0x1DA5, 0x4490,
    0x1E68, 0x475D, 0xAC02, 0xF537, 0x2389, 0x7ABC, 0x91E3, 0xC8D6,
    0x65AA, 0x3C9F, 0xD7C0, 0x8EF5, 0x584B, 0x017E, 0xEA21, 0xB314
};

/* This table was compiled using the polynom 0x755B */
static const unsigned crc16_precompiled_755B[] =
{
    0x0000, 0x755b, 0xeab6, 0x9fed, 0xa037, 0xd56c, 0x4a81, 0x3fda,     /* 0x00 */
    0x3535, 0x406e, 0xdf83, 0xaad8, 0x9502, 0xe059, 0x7fb4, 0x0aef,     /* 0x08 */
    0x6a6a, 0x1f31, 0x80dc, 0xf587, 0xca5d, 0xbf06, 0x20eb, 0x55b0,     /* 0x10 */
    0x5f5f, 0x2a04, 0xb5e9, 0xc0b2, 0xff68, 0x8a33, 0x15de, 0x6085,     /* 0x18 */
    0xd4d4, 0xa18f, 0x3e62, 0x4b39, 0x74e3, 0x01b8, 0x9e55, 0xeb0e,     /* 0x20 */
    0xe1e1, 0x94ba, 0x0b57, 0x7e0c, 0x41d6, 0x348d, 0xab60, 0xde3b,     /* 0x28 */
    0xbebe, 0xcbe5, 0x5408, 0x2153, 0x1e89, 0x6bd2, 0xf43f, 0x8164,     /* 0x30 */
    0x8b8b, 0xfed0, 0x613d, 0x1466, 0x2bbc, 0x5ee7, 0xc10a, 0xb451,     /* 0x38 */
    0xdcf3, 0xa9a8, 0x3645, 0x431e, 0x7cc4, 0x099f, 0x9672, 0xe329,     /* 0x40 */
    0xe9c6, 0x9c9d, 0x0370, 0x762b, 0x49f1, 0x3caa, 0xa347, 0xd61c,     /* 0x48 */
    0xb699, 0xc3c2, 0x5c2f, 0x2974, 0x16ae, 0x63f5, 0xfc18, 0x8943,     /* 0x50 */
    0x83ac, 0xf6f7, 0x691a, 0x1c41, 0x239b, 0x56c0, 0xc92d, 0xbc76,     /* 0x58 */
    0x0827, 0x7d7c, 0xe291, 0x97ca, 0xa810, 0xdd4b, 0x42a6, 0x37fd,     /* 0x60 */
    0x3d12, 0x4849, 0xd7a4, 0xa2ff, 0x9d25, 0xe87e, 0x7793, 0x02c8,     /* 0x68 */
    0x624d, 0x1716, 0x88fb, 0xfda0, 0xc27a, 0xb721, 0x28cc, 0x5d97,     /* 0x70 */
    0x5778, 0x2223, 0xbdce, 0xc895, 0xf74f, 0x8214, 0x1df9, 0x68a2,     /* 0x78 */
    0xccbd, 0xb9e6, 0x260b, 0x5350, 0x6c8a, 0x19d1, 0x863c, 0xf367,     /* 0x80 */
    0xf988, 0x8cd3, 0x133e, 0x6665, 0x59bf, 0x2ce4, 0xb309, 0xc652,     /* 0x88 */
    0xa6d7, 0xd38c, 0x4c61, 0x393a, 0x06e0, 0x73bb, 0xec56, 0x990d,     /* 0x90 */
    0x93e2, 0xe6b9, 0x7954, 0x0c0f, 0x33d5, 0x468e, 0xd963, 0xac38,     /* 0x98 */
    0x1869, 0x6d32, 0xf2df, 0x8784, 0xb85e, 0xcd05, 0x52e8, 0x27b3,     /* 0xA0 */
    0x2d5c, 0x5807, 0xc7ea, 0xb2b1, 0x8d6b, 0xf830, 0x67dd, 0x1286,     /* 0xA8 */
    0x7203, 0x0758, 0x98b5, 0xedee, 0xd234, 0xa76f, 0x3882, 0x4dd9,     /* 0xB0 */
    0x4736, 0x326d, 0xad80, 0xd8db, 0xe701, 0x925a, 0x0db7, 0x78ec,     /* 0xB8 */
    0x104e, 0x6515, 0xfaf8, 0x8fa3, 0xb079, 0xc522, 0x5acf, 0x2f94,     /* 0xC0 */
    0x257b, 0x5020, 0xcfcd, 0xba96, 0x854c, 0xf017, 0x6ffa, 0x1aa1,     /* 0xC8 */
    0x7a24, 0x0f7f, 0x9092, 0xe5c9, 0xda13, 0xaf48, 0x30a5, 0x45fe,     /* 0xD0 */
    0x4f11, 0x3a4a, 0xa5a7, 0xd0fc, 0xef26, 0x9a7d, 0x0590, 0x70cb,     /* 0xD8 */
    0xc49a, 0xb1c1, 0x2e2c, 0x5b77, 0x64ad, 0x11f6, 0x8e1b, 0xfb40,     /* 0xE0 */
    0xf1af, 0x84f4, 0x1b19, 0x6e42, 0x5198, 0x24c3, 0xbb2e, 0xce75,     /* 0xE8 */
    0xaef0, 0xdbab, 0x4446, 0x311d, 0x0ec7, 0x7b9c, 0xe471, 0x912a,     /* 0xF0 */
    0x9bc5, 0xee9e, 0x7173, 0x0428, 0x3bf2, 0x4ea9, 0xd144, 0xa41f      /* 0xF8 */
};

/* This table was compiled using the polynom: 0x9949 */
static const unsigned crc16_precompiled_9949_reverse[] =
{
    0x0000, 0x0ED2, 0x1DA4, 0x1376, 0x3B48, 0x359A, 0x26EC, 0x283E,
    0x7690, 0x7842, 0x6B34, 0x65E6, 0x4DD8, 0x430A, 0x507C, 0x5EAE,
    0xED20, 0xE3F2, 0xF084, 0xFE56, 0xD668, 0xD8BA, 0xCBCC, 0xC51E,
    0x9BB0, 0x9562, 0x8614, 0x88C6, 0xA0F8, 0xAE2A, 0xBD5C, 0xB38E,
    0xFF73, 0xF1A1, 0xE2D7, 0xEC05, 0xC43B, 0xCAE9, 0xD99F, 0xD74D,
    0x89E3, 0x8731, 0x9447, 0x9A95, 0xB2AB, 0xBC79, 0xAF0F, 0xA1DD,
    0x1253, 0x1C81, 0x0FF7, 0x0125, 0x291B, 0x27C9, 0x34BF, 0x3A6D,
    0x64C3, 0x6A11, 0x7967, 0x77B5, 0x5F8B, 0x5159, 0x422F, 0x4CFD,
    0xDBD5, 0xD507, 0xC671, 0xC8A3, 0xE09D, 0xEE4F, 0xFD39, 0xF3EB,
    0xAD45, 0xA397, 0xB0E1, 0xBE33, 0x960D, 0x98DF, 0x8BA9, 0x857B,
    0x36F5, 0x3827, 0x2B51, 0x2583, 0x0DBD, 0x036F, 0x1019, 0x1ECB,
    0x4065, 0x4EB7, 0x5DC1, 0x5313, 0x7B2D, 0x75FF, 0x6689, 0x685B,
    0x24A6, 0x2A74, 0x3902, 0x37D0, 0x1FEE, 0x113C, 0x024A, 0x0C98,
    0x5236, 0x5CE4, 0x4F92, 0x4140, 0x697E, 0x67AC, 0x74DA, 0x7A08,
    0xC986, 0xC754, 0xD422, 0xDAF0, 0xF2CE, 0xFC1C, 0xEF6A, 0xE1B8,
    0xBF16, 0xB1C4, 0xA2B2, 0xAC60, 0x845E, 0x8A8C, 0x99FA, 0x9728,
    0x9299, 0x9C4B, 0x8F3D, 0x81EF, 0xA9D1, 0xA703, 0xB475, 0xBAA7,
    0xE409, 0xEADB, 0xF9AD, 0xF77F, 0xDF41, 0xD193, 0xC2E5, 0xCC37,
    0x7FB9, 0x716B, 0x621D, 0x6CCF, 0x44F1, 0x4A23, 0x5955, 0x5787,
    0x0929, 0x07FB, 0x148D, 0x1A5F, 0x3261, 0x3CB3, 0x2FC5, 0x2117,
    0x6DEA, 0x6338, 0x704E, 0x7E9C, 0x56A2, 0x5870, 0x4B06, 0x45D4,
    0x1B7A, 0x15A8, 0x06DE, 0x080C, 0x2032, 0x2EE0, 0x3D96, 0x3344,
    0x80CA, 0x8E18, 0x9D6E, 0x93BC, 0xBB82, 0xB550, 0xA626, 0xA8F4,
    0xF65A, 0xF888, 0xEBFE, 0xE52C, 0xCD12, 0xC3C0, 0xD0B6, 0xDE64,
    0x494C, 0x479E, 0x54E8, 0x5A3A, 0x7204, 0x7CD6, 0x6FA0, 0x6172,
    0x3FDC, 0x310E, 0x2278, 0x2CAA, 0x0494, 0x0A46, 0x1930, 0x17E2,
    0xA46C, 0xAABE, 0xB9C8, 0xB71A, 0x9F24, 0x91F6, 0x8280, 0x8C52,
    0xD2FC, 0xDC2E, 0xCF58, 0xC18A, 0xE9B4, 0xE766, 0xF410, 0xFAC2,
    0xB63F, 0xB8ED, 0xAB9B, 0xA549, 0x8D77, 0x83A5, 0x90D3, 0x9E01,
    0xC0AF, 0xCE7D, 0xDD0B, 0xD3D9, 0xFBE7, 0xF535, 0xE643, 0xE891,
    0x5B1F, 0x55CD, 0x46BB, 0x4869, 0x6057, 0x6E85, 0x7DF3, 0x7321,
    0x2D8F, 0x235D, 0x302B, 0x3EF9, 0x16C7, 0x1815, 0x0B63, 0x05B1
};

/* This table was compiled using the polynom: 0x3D65 */
static const unsigned crc16_precompiled_3D65_reverse[] =
{
    0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
    0xFF89, 0xC9D7, 0x9335, 0xA56B, 0x26F1, 0x10AF, 0x4A4D, 0x7C13,
    0xB26B, 0x8435, 0xDED7, 0xE889, 0x6B13, 0x5D4D, 0x07AF, 0x31F1,
    0x4DE2, 0x7BBC, 0x215E, 0x1700, 0x949A, 0xA2C4, 0xF826, 0xCE78,
    0x29AF, 0x1FF1, 0x4513, 0x734D, 0xF0D7, 0xC689, 0x9C6B, 0xAA35,
    0xD626, 0xE078, 0xBA9A, 0x8CC4, 0x0F5E, 0x3900, 0x63E2, 0x55BC,
    0x9BC4, 0xAD9A, 0xF778, 0xC126, 0x42BC, 0x74E2, 0x2E00, 0x185E,
    0x644D, 0x5213, 0x08F1, 0x3EAF, 0xBD35, 0x8B6B, 0xD189, 0xE7D7,
    0x535E, 0x6500, 0x3FE2, 0x09BC, 0x8A26, 0xBC78, 0xE69A, 0xD0C4,
    0xACD7, 0x9A89, 0xC06B, 0xF635, 0x75AF, 0x43F1, 0x1913, 0x2F4D,
    0xE135, 0xD76B, 0x8D89, 0xBBD7, 0x384D, 0x0E13, 0x54F1, 0x62AF,
    0x1EBC, 0x28E2, 0x7200, 0x445E, 0xC7C4, 0xF19A, 0xAB78, 0x9D26,
    0x7AF1, 0x4CAF, 0x164D, 0x2013, 0xA389, 0x95D7, 0xCF35, 0xF96B,
    0x8578, 0xB326, 0xE9C4, 0xDF9A, 0x5C00, 0x6A5E, 0x30BC, 0x06E2,
    0xC89A, 0xFEC4, 0xA426, 0x9278, 0x11E2, 0x27BC, 0x7D5E, 0x4B00,
    0x3713, 0x014D, 0x5BAF, 0x6DF1, 0xEE6B, 0xD835, 0x82D7, 0xB489,
    0xA6BC, 0x90E2, 0xCA00, 0xFC5E, 0x7FC4, 0x499A, 0x1378, 0x2526,
    0x5935, 0x6F6B, 0x3589, 0x03D7, 0x804D, 0xB613, 0xECF1, 0xDAAF,
    0x14D7, 0x2289, 0x786B, 0x4E35, 0xCDAF, 0xFBF1, 0xA113, 0x974D,
    0xEB5E, 0xDD00, 0x87E2, 0xB1BC, 0x3226, 0x0478, 0x5E9A, 0x68C4,
    0x8F13, 0xB94D, 0xE3AF, 0xD5F1, 0x566B, 0x6035, 0x3AD7, 0x0C89,
    0x709A, 0x46C4, 0x1C26, 0x2A78, 0xA9E2, 0x9FBC, 0xC55E, 0xF300,
    0x3D78, 0x0B26, 0x51C4, 0x679A, 0xE400, 0xD25E, 0x88BC, 0xBEE2,
    0xC2F1, 0xF4AF, 0xAE4D, 0x9813, 0x1B89, 0x2DD7, 0x7735, 0x416B,
    0xF5E2, 0xC3BC, 0x995E, 0xAF00, 0x2C9A, 0x1AC4, 0x4026, 0x7678,
    0x0A6B, 0x3C35, 0x66D7, 0x5089, 0xD313, 0xE54D, 0xBFAF, 0x89F1,
    0x4789, 0x71D7, 0x2B35, 0x1D6B, 0x9EF1, 0xA8AF, 0xF24D, 0xC413,
    0xB800, 0x8E5E, 0xD4BC, 0xE2E2, 0x6178, 0x5726, 0x0DC4, 0x3B9A,
    0xDC4D, 0xEA13, 0xB0F1, 0x86AF, 0x0535, 0x336B, 0x6989, 0x5FD7,
    0x23C4, 0x159A, 0x4F78, 0x7926, 0xFABC, 0xCCE2, 0x9600, 0xA05E,
    0x6E26, 0x5878, 0x029A, 0x34C4, 0xB75E, 0x8100, 0xDBE2, 0xEDBC,
    0x91AF, 0xA7F1, 0xFD13, 0xCB4D, 0x48D7, 0x7E89, 0x246B, 0x1235
};

/* This table was compiled using the polynom: 0x080F */
static const unsigned crc16_precompiled_080F[] =
{
    0x0000, 0x080F, 0x101E, 0x1811, 0x203C, 0x2833, 0x3022, 0x382D,
    0x4078, 0x4877, 0x5066, 0x5869, 0x6044, 0x684B, 0x705A, 0x7855,
    0x80F0, 0x88FF, 0x90EE, 0x98E1, 0xA0CC, 0xA8C3, 0xB0D2, 0xB8DD,
    0xC088, 0xC887, 0xD096, 0xD899, 0xE0B4, 0xE8BB, 0xF0AA, 0xF8A5,
    0x09EF, 0x01E0, 0x19F1, 0x11FE, 0x29D3, 0x21DC, 0x39CD, 0x31C2,
    0x4997, 0x4198, 0x5989, 0x5186, 0x69AB, 0x61A4, 0x79B5, 0x71BA,
    0x891F, 0x8110, 0x9901, 0x910E, 0xA923, 0xA12C, 0xB93D, 0xB132,
    0xC967, 0xC168, 0xD979, 0xD176, 0xE95B, 0xE154, 0xF945, 0xF14A,
    0x13DE, 0x1BD1, 0x03C0, 0x0BCF, 0x33E2, 0x3BED, 0x23FC, 0x2BF3,
    0x53A6, 0x5BA9, 0x43B8, 0x4BB7, 0x739A, 0x7B95, 0x6384, 0x6B8B,
    0x932E, 0x9B21, 0x8330, 0x8B3F, 0xB312, 0xBB1D, 0xA30C, 0xAB03,
    0xD356, 0xDB59, 0xC348, 0xCB47, 0xF36A, 0xFB65, 0xE374, 0xEB7B,
    0x1A31, 0x123E, 0x0A2F, 0x0220, 0x3A0D, 0x3202, 0x2A13, 0x221C,
    0x5A49, 0x5246, 0x4A57, 0x4258, 0x7A75, 0x727A, 0x6A6B, 0x6264,
    0x9AC1, 0x92CE, 0x8ADF, 0x82D0, 0xBAFD, 0xB2F2, 0xAAE3, 0xA2EC,
    0xDAB9, 0xD2B6, 0xCAA7, 0xC2A8, 0xFA85, 0xF28A, 0xEA9B, 0xE294,
    0x27BC, 0x2FB3, 0x37A2, 0x3FAD, 0x0780, 0x0F8F, 0x179E, 0x1F91,
    0x67C4, 0x6FCB, 0x77DA, 0x7FD5, 0x47F8, 0x4FF7, 0x57E6, 0x5FE9,
    0xA74C, 0xAF43, 0xB752, 0xBF5D, 0x8770, 0x8F7F, 0x976E, 0x9F61,
    0xE734, 0xEF3B, 0xF72A, 0xFF25, 0xC708, 0xCF07, 0xD716, 0xDF19,
    0x2E53, 0x265C, 0x3E4D, 0x3642, 0x0E6F, 0x0660, 0x1E71, 0x167E,
    0x6E2B, 0x6624, 0x7E35, 0x763A, 0x4E17, 0x4618, 0x5E09, 0x5606,
    0xAEA3, 0xA6AC, 0xBEBD, 0xB6B2, 0x8E9F, 0x8690, 0x9E81, 0x968E,
    0xEEDB, 0xE6D4, 0xFEC5, 0xF6CA, 0xCEE7, 0xC6E8, 0xDEF9, 0xD6F6,
    0x3462, 0x3C6D, 0x247C, 0x2C73, 0x145E, 0x1C51, 0x0440, 0x0C4F,
    0x741A, 0x7C15, 0x6404, 0x6C0B, 0x5426, 0x5C29, 0x4438, 0x4C37,
    0xB492, 0xBC9D, 0xA48C, 0xAC83, 0x94AE, 0x9CA1, 0x84B0, 0x8CBF,
    0xF4EA, 0xFCE5, 0xE4F4, 0xECFB, 0xD4D6, 0xDCD9, 0xC4C8, 0xCCC7,
    0x3D8D, 0x3582, 0x2D93, 0x259C, 0x1DB1, 0x15BE, 0x0DAF, 0x05A0,
    0x7DF5, 0x75FA, 0x6DEB, 0x65E4, 0x5DC9, 0x55C6, 0x4DD7, 0x45D8,
    0xBD7D, 0xB572, 0xAD63, 0xA56C, 0x9D41, 0x954E, 0x8D5F, 0x8550,
    0xFD05, 0xF50A, 0xED1B, 0xE514, 0xDD39, 0xD536, 0xCD27, 0xC528
};

/**
 * Generated on Fri Jul 19 17:16:42 2019
 * by pycrc v0.9.2, https://pycrc.org
 * using the configuration:
 *  - Width         = 16
 *  - Poly          = 0x8005
 *  - XorIn         = 0xffff
 *  - ReflectIn     = True
 *  - XorOut        = 0xffff
 *  - ReflectOut    = True
 *  - Algorithm     = table-driven
 */
static const unsigned crc16_usb_table[] = {
    0x0000, 0xc0c1, 0xc181, 0x0140, 0xc301, 0x03c0, 0x0280, 0xc241,
    0xc601, 0x06c0, 0x0780, 0xc741, 0x0500, 0xc5c1, 0xc481, 0x0440,
    0xcc01, 0x0cc0, 0x0d80, 0xcd41, 0x0f00, 0xcfc1, 0xce81, 0x0e40,
    0x0a00, 0xcac1, 0xcb81, 0x0b40, 0xc901, 0x09c0, 0x0880, 0xc841,
    0xd801, 0x18c0, 0x1980, 0xd941, 0x1b00, 0xdbc1, 0xda81, 0x1a40,
    0x1e00, 0xdec1, 0xdf81, 0x1f40, 0xdd01, 0x1dc0, 0x1c80, 0xdc41,
    0x1400, 0xd4c1, 0xd581, 0x1540, 0xd701, 0x17c0, 0x1680, 0xd641,
    0xd201, 0x12c0, 0x1380, 0xd341, 0x1100, 0xd1c1, 0xd081, 0x1040,
    0xf001, 0x30c0, 0x3180, 0xf141, 0x3300, 0xf3c1, 0xf281, 0x3240,
    0x3600, 0xf6c1, 0xf781, 0x3740, 0xf501, 0x35c0, 0x3480, 0xf441,
    0x3c00, 0xfcc1, 0xfd81, 0x3d40, 0xff01, 0x3fc0, 0x3e80, 0xfe41,
    0xfa01, 0x3ac0, 0x3b80, 0xfb41, 0x3900, 0xf9c1, 0xf881, 0x3840,
    0x2800, 0xe8c1, 0xe981, 0x2940, 0xeb01, 0x2bc0, 0x2a80, 0xea41,
    0xee01, 0x2ec0, 0x2f80, 0xef41, 0x2d00, 0xedc1, 0xec81, 0x2c40,
    0xe401, 0x24c0, 0x2580, 0xe541, 0x2700, 0xe7c1, 0xe681, 0x2640,
    0x2200, 0xe2c1, 0xe381, 0x2340, 0xe101, 0x21c0, 0x2080, 0xe041,
    0xa001, 0x60c0, 0x6180, 0xa141, 0x6300, 0xa3c1, 0xa281, 0x6240,
    0x6600, 0xa6c1, 0xa781, 0x6740, 0xa501, 0x65c0, 0x6480, 0xa441,
    0x6c00, 0xacc1, 0xad81, 0x6d40, 0xaf01, 0x6fc0, 0x6e80, 0xae41,
    0xaa01, 0x6ac0, 0x6b80, 0xab41, 0x6900, 0xa9c1, 0xa881, 0x6840,
    0x7800, 0xb8c1, 0xb981, 0x7940, 0xbb01, 0x7bc0, 0x7a80, 0xba41,
    0xbe01, 0x7ec0, 0x7f80, 0xbf41, 0x7d00, 0xbdc1, 0xbc81, 0x7c40,
    0xb401, 0x74c0, 0x7580, 0xb541, 0x7700, 0xb7c1, 0xb681, 0x7640,
    0x7200, 0xb2c1, 0xb381, 0x7340, 0xb101, 0x71c0, 0x7080, 0xb041,
    0x5000, 0x90c1, 0x9181, 0x5140, 0x9301, 0x53c0, 0x5280, 0x9241,
    0x9601, 0x56c0, 0x5780, 0x9741, 0x5500, 0x95c1, 0x9481, 0x5440,
    0x9c01, 0x5cc0, 0x5d80, 0x9d41, 0x5f00, 0x9fc1, 0x9e81, 0x5e40,
    0x5a00, 0x9ac1, 0x9b81, 0x5b40, 0x9901, 0x59c0, 0x5880, 0x9841,
    0x8801, 0x48c0, 0x4980, 0x8941, 0x4b00, 0x8bc1, 0x8a81, 0x4a40,
    0x4e00, 0x8ec1, 0x8f81, 0x4f40, 0x8d01, 0x4dc0, 0x4c80, 0x8c41,
    0x4400, 0x84c1, 0x8581, 0x4540, 0x8701, 0x47c0, 0x4680, 0x8641,
    0x8201, 0x42c0, 0x4380, 0x8341, 0x4100, 0x81c1, 0x8081, 0x4040
};

static const uint16_t crc16_ccitt_start = 0xFFFF;
static const uint16_t crc16_ccitt_xorout = 0xFFFF;

static const uint16_t crc16_usb_start = 0xFFFF;
static const uint16_t crc16_usb_xorout = 0xFFFF;

/* two types of crcs are possible: unreflected (bits shift left) and
 * reflected (bits shift right).
 */
static uint16_t crc16_unreflected(const uint8_t *buf, unsigned len,
                                 uint16_t crc_in, const unsigned table[])
{
    /* we use uints, rather than uint16s, as they are likely to be
       faster. We just ignore the top 16 bits and let them do what they want.
    */
    unsigned crc16 = (unsigned)crc_in;

    while( len-- != 0 )
        crc16 = table[((crc16 >> 8) ^ *buf++) & 0xff] ^ (crc16 << 8);

    return (uint16_t)crc16;
}

static uint16_t crc16_reflected(const uint8_t *buf, unsigned len,
                                uint16_t crc_in, const unsigned table[])
{
    /* we use uints, rather than uint16s, as they are likely to be
       faster. We just ignore the top 16 bits and let them do what they want.
       XXX - does any time saved not zero-extending uint16_t's to 32 bits
       into a register outweigh any increased cache footprint from the
       larger CRC table? */
    unsigned crc16 = (unsigned)crc_in;

    while( len-- != 0 )
       crc16 = table[(crc16 ^ *buf++) & 0xff] ^ (crc16 >> 8);

    return (uint16_t)crc16;
}

uint16_t crc16_ccitt(const uint8_t *buf, unsigned len)
{
    return crc16_reflected(buf,len,crc16_ccitt_start,crc16_ccitt_table_reverse)
       ^ crc16_ccitt_xorout;
}

uint16_t crc16_x25_ccitt_seed(const uint8_t *buf, unsigned len, uint16_t seed)
{
    return crc16_unreflected(buf,len,seed,crc16_ccitt_table);
}

uint16_t crc16_ccitt_seed(const uint8_t *buf, unsigned len, uint16_t seed)
{
    return crc16_reflected(buf,len,seed,crc16_ccitt_table_reverse)
       ^ crc16_ccitt_xorout;
}

/* ISO14443-3, section 6.2.4: For ISO14443-A, the polynomial 0x1021 is
   used, the initial register value shall be 0x6363, the final register
   value is not XORed with anything. */
uint16_t crc16_iso14443a(const uint8_t *buf, unsigned len)
{
    return crc16_reflected(buf,len, 0x6363 ,crc16_ccitt_table_reverse);
}

uint16_t crc16_usb(const uint8_t *buf, unsigned len)
{
    return crc16_reflected(buf, len, crc16_usb_start, crc16_usb_table)
        ^ crc16_usb_xorout;
}

uint16_t crc16_0x5935(const uint8_t *buf, uint32_t len, uint16_t seed)
{
    return crc16_unreflected(buf, len, seed, crc16_precompiled_5935);
}

uint16_t crc16_0x755B(const uint8_t *buf, uint32_t len, uint16_t seed)
{
    return crc16_unreflected(buf, len, seed, crc16_precompiled_755B);
}

uint16_t crc16_0x9949_seed(const uint8_t *buf, unsigned len, uint16_t seed)
{
    return crc16_reflected(buf, len, seed, crc16_precompiled_9949_reverse);
}

uint16_t crc16_0x3D65_seed(const uint8_t *buf, unsigned len, uint16_t seed)
{
    return crc16_reflected(buf, len, seed, crc16_precompiled_3D65_reverse);
}

uint16_t crc16_0x080F_seed(const uint8_t *buf, unsigned len, uint16_t seed)
{
    uint16_t crc = seed;

    if (len > 0)
    {
        while (len-- > 0)
        {
            uint8_t data = *buf++;
            crc = crc16_precompiled_080F[((crc >> 8) ^ data)] ^ (crc << 8);
        }
    }

    return crc;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
