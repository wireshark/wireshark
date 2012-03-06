/* Routines for UMTS FP disassembly
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* Target Channel Type Field (TCTF) values */
#define TCTF_CCCH_RACH_FDD      0x0
#define TCTF_DCCH_DTCH_RACH_FDD 0x1

#define TCTF_BCCH_FACH_FDD      0x0
#define TCTF_DCCH_DTCH_FACH_FDD 0x3
#define TCTF_MTCH_FACH_FDD      0x6
#define TCTF_CCCH_FACH_FDD      0x40
#define TCTF_MCCH_FACH_FDD      0x50
#define TCTF_MSCH_FACH_FDD      0x5f
#define TCTF_CTCH_FACH_FDD      0x80

/* UeID Type values */
#define MAC_UEID_TYPE_URNTI     0x0
#define MAC_UEID_TYPE_CRNTI     0x1

#define MAC_CONTENT_UNKNOWN 0
#define MAC_CONTENT_DCCH    1
#define MAC_CONTENT_PS_DTCH 2
#define MAC_CONTENT_CS_DTCH 3

#define MAX_MAC_FRAMES 64
typedef struct umts_mac_info
{
    gboolean ctmux[MAX_MAC_FRAMES];
    guint8 content[MAX_MAC_FRAMES];
} umts_mac_info;
