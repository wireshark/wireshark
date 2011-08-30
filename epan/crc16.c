/* crc16.c
 * CRC-16 routine
 *
 * 2004 Richard van der Hoff <richardv@mxtelecom.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@xxxxxxxxxxxx>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * References:
 *  "A Painless Guide to CRC Error Detection Algorithms", Ross Williams
 *      http://www.repairfaq.org/filipg/LINK/F_crc_v3.html
 *
 *  ITU-T Recommendation V.42 (2002), "Error-Correcting Procedures for
 *      DCEs using asynchronous-to-synchronous conversion", Para. 8.1.1.6.1
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/tvbuff.h>
#include <epan/crc16.h>
#include <epan/crc/crc-16-plain.h>


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
/*    Reverse : TRUE.                                           */
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

static const guint crc16_ccitt_table_reverse[256] =
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

/* Same as above, only without reverse (Reverse=FALSE) */
static const guint crc16_ccitt_table[256] =
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

static const guint16 crc16_ccitt_start = 0xFFFF;
static const guint16 crc16_ccitt_xorout = 0xFFFF;

/* two types of crcs are possible: unreflected (bits shift left) and
 * reflected (bits shift right).
 */
static guint16 crc16_unreflected(const guint8 *buf, guint len,
				 guint16 crc_in, const guint table[])
{
    /* we use guints, rather than guint16s, as they are likely to be
       faster. We just ignore the top 16 bits and let them do what they want.
    */
    guint crc16 = (guint)crc_in;;

    while( len-- != 0 )
        crc16 = table[((crc16 >> 8) ^ *buf++) & 0xff] ^ (crc16 << 8);

    return (guint16)crc16;
}

static guint16 crc16_reflected(const guint8 *buf, guint len,
                                guint16 crc_in, const guint table[])
{
    /* we use guints, rather than guint16s, as they are likely to be
       faster. We just ignore the top 16 bits and let them do what they want.
       XXX - does any time saved not zero-extending guint16's to 32 bits
       into a register outweigh any increased cache footprint from the
       larger CRC table? */
    guint crc16 = (guint)crc_in;

    while( len-- != 0 )
       crc16 = table[(crc16 ^ *buf++) & 0xff] ^ (crc16 >> 8);

    return (guint16)crc16;
}

guint16 crc16_ccitt(const guint8 *buf, guint len)
{
    return crc16_reflected(buf,len,crc16_ccitt_start,crc16_ccitt_table_reverse)
       ^ crc16_ccitt_xorout;
}

guint16 crc16_x25_ccitt(const guint8 *buf, guint len)
{
    return crc16_unreflected(buf,len,crc16_ccitt_start,crc16_ccitt_table);
}

guint16 crc16_ccitt_seed(const guint8 *buf, guint len, guint16 seed)
{
    return crc16_reflected(buf,len,seed,crc16_ccitt_table_reverse)
       ^ crc16_ccitt_xorout;
}

guint16 crc16_ccitt_tvb(tvbuff_t *tvb, guint len)
{
    const guint8* buf = tvb_get_ptr(tvb, 0, len);

    return crc16_ccitt(buf, len);
}

guint16 crc16_x25_ccitt_tvb(tvbuff_t *tvb, guint len)
{
    const guint8* buf = tvb_get_ptr(tvb, 0, len);

    return crc16_x25_ccitt(buf, len);
}

guint16 crc16_ccitt_tvb_offset(tvbuff_t *tvb, guint offset, guint len)
{
    const guint8* buf = tvb_get_ptr(tvb, offset, len);

    return crc16_ccitt(buf, len);
}

guint16 crc16_ccitt_tvb_seed(tvbuff_t *tvb, guint len, guint16 seed)
{
    const guint8* buf = tvb_get_ptr(tvb, 0, len);

    return crc16_ccitt_seed(buf, len, seed);
}

guint16 crc16_ccitt_tvb_offset_seed(tvbuff_t *tvb, guint offset, guint len, guint16 seed)
{
    const guint8* buf = tvb_get_ptr(tvb, offset, len);

    return crc16_ccitt_seed(buf, len, seed);
}

guint16 crc16_plain_tvb_offset(tvbuff_t *tvb, guint offset, guint len)
{
    guint16 crc = crc16_plain_init();
    
    const guint8* buf = tvb_get_ptr(tvb, offset, len);

    crc = crc16_plain_update(crc, buf, len);
    
    return crc16_plain_finalize(crc);
}

