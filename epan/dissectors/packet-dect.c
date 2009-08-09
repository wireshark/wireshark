/* packet-dect.c
 *
 * Dissector for the Digital Enhanced Cordless Telecommunications
 * protocol.
 *
 * $Id$
 *
 * Copyright 2008-2009:
 * - Andreas Schuler <krater (A) badterrorist.com>
 * - Matthias Wenzel <dect (A) mazzoo.de>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 TODO (roughly in that order)
 - Don't use structs to access the elements in the datastream.
 - Use tvb_..._item wherever possible
 - Add references to documentation (ETSI EN 300 175 parts 1-8)
 - Make things stateful
 - Once the capture format has stabilized, get rid of the Ethernet
 hack and use a proper capture type.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/etypes.h>
#include <string.h>

#define ETHERTYPE_DECT 0x2323				/* move to epan/etypes.h */

#define DECT_PACKET_PP	0
#define DECT_PACKET_FP	1

/* scramble table with corrections by Jakub Hruska */
static guint8 scrt[8][31]=
{
	{0x3B, 0xCD, 0x21, 0x5D, 0x88, 0x65, 0xBD, 0x44, 0xEF, 0x34, 0x85, 0x76, 0x21, 0x96, 0xF5, 0x13, 0xBC, 0xD2, 0x15, 0xD8, 0x86, 0x5B, 0xD4, 0x4E, 0xF3, 0x48, 0x57, 0x62, 0x19, 0x6F, 0x51},
	{0x32, 0xDE, 0xA2, 0x77, 0x9A, 0x42, 0xBB, 0x10, 0xCB, 0x7A, 0x89, 0xDE, 0x69, 0x0A, 0xEC, 0x43, 0x2D, 0xEA, 0x27, 0x79, 0xA4, 0x2B, 0xB1, 0x0C, 0xB7, 0xA8, 0x9D, 0xE6, 0x90, 0xAE, 0xC4},
	{0x2D, 0xEA, 0x27, 0x79, 0xA4, 0x2B, 0xB1, 0x0C, 0xB7, 0xA8, 0x9D, 0xE6, 0x90, 0xAE, 0xC4, 0x32, 0xDE, 0xA2, 0x77, 0x9A, 0x42, 0xBB, 0x10, 0xCB, 0x7A, 0x89, 0xDE, 0x69, 0x0A, 0xEC, 0x43},
	{0x27, 0x79, 0xA4, 0x2B, 0xB1, 0x0C, 0xB7, 0xA8, 0x9D, 0xE6, 0x90, 0xAE, 0xC4, 0x32, 0xDE, 0xA2, 0x77, 0x9A, 0x42, 0xBB, 0x10, 0xCB, 0x7A, 0x89, 0xDE, 0x69, 0x0A, 0xEC, 0x43, 0x2D, 0xEA},
	{0x19, 0x6F, 0x51, 0x3B, 0xCD, 0x21, 0x5D, 0x88, 0x65, 0xBD, 0x44, 0xEF, 0x34, 0x85, 0x76, 0x21, 0x96, 0xF5, 0x13, 0xBC, 0xD2, 0x15, 0xD8, 0x86, 0x5B, 0xD4, 0x4E, 0xF3, 0x48, 0x57, 0x62},
	{0x13, 0xBC, 0xD2, 0x15, 0xD8, 0x86, 0x5B, 0xD4, 0x4E, 0xF3, 0x48, 0x57, 0x62, 0x19, 0x6F, 0x51, 0x3B, 0xCD, 0x21, 0x5D, 0x88, 0x65, 0xBD, 0x44, 0xEF, 0x34, 0x85, 0x76, 0x21, 0x96, 0xF5},
	{0x0C, 0xB7, 0xA8, 0x9D, 0xE6, 0x90, 0xAE, 0xC4, 0x32, 0xDE, 0xA2, 0x77, 0x9A, 0x42, 0xBB, 0x10, 0xCB, 0x7A, 0x89, 0xDE, 0x69, 0x0A, 0xEC, 0x43, 0x2D, 0xEA, 0x27, 0x79, 0xA4, 0x2B, 0xB1},
	{0x79, 0xA4, 0x2B, 0xB1, 0x0C, 0xB7, 0xA8, 0x9D, 0xE6, 0x90, 0xAE, 0xC4, 0x32, 0xDE, 0xA2, 0x77, 0x9A, 0x42, 0xBB, 0x10, 0xCB, 0x7A, 0x89, 0xDE, 0x69, 0x0A, 0xEC, 0x43, 0x2D, 0xEA, 0x27}
};

struct dect_afield
{
	guint8	Header;
	guint8	Tail[5];
	guint16	RCRC;
};

struct dect_bfield
{
	guint8	Data[128];
	guint8	Length;
};

static int proto_dect = -1;

#if 0
static int proto_dect2 = -1;
#endif


static gint ett_dect				= -1;
static gint ett_afield				= -1;
static gint ett_ahead				= -1;
static gint ett_atail				= -1;
static gint ett_aqt				= -1;
static gint ett_bfield				= -1;

static int hf_dect_transceivermode		= -1;
static int hf_dect_preamble			= -1;
static int hf_dect_type				= -1;
static int hf_dect_channel			= -1;
static int hf_dect_framenumber			= -1;
static int hf_dect_rssi				= -1;
static int hf_dect_slot				= -1;
static int hf_dect_A				= -1;
static int hf_dect_A_Head			= -1;
static int hf_dect_A_Head_TA_FP			= -1;
static int hf_dect_A_Head_TA_PP			= -1;
static int hf_dect_A_Head_Q1			= -1;
static int hf_dect_A_Head_BA			= -1;
static int hf_dect_A_Head_Q2			= -1;
static int hf_dect_A_Tail			= -1;
static int hf_dect_A_Tail_Nt			= -1;
static int hf_dect_A_Tail_Qt_Qh			= -1;
static int hf_dect_A_Tail_Qt_0_Sn		= -1;
static int hf_dect_A_Tail_Qt_0_Nr		= -1;
static int hf_dect_A_Tail_Qt_0_Sp		= -1;
static int hf_dect_A_Tail_Qt_0_Esc		= -1;
static int hf_dect_A_Tail_Qt_0_Txs		= -1;
static int hf_dect_A_Tail_Qt_0_Mc		= -1;
static int hf_dect_A_Tail_Qt_0_Spr1		= -1;
static int hf_dect_A_Tail_Qt_0_Cn		= -1;
static int hf_dect_A_Tail_Qt_0_Spr2		= -1;
static int hf_dect_A_Tail_Qt_0_PSCN		= -1;
static int hf_dect_A_Tail_Qt_3_A12		= -1;
static int hf_dect_A_Tail_Qt_3_A13		= -1;
static int hf_dect_A_Tail_Qt_3_A14		= -1;
static int hf_dect_A_Tail_Qt_3_A15		= -1;
static int hf_dect_A_Tail_Qt_3_A16		= -1;
static int hf_dect_A_Tail_Qt_3_A17		= -1;
static int hf_dect_A_Tail_Qt_3_A18		= -1;
static int hf_dect_A_Tail_Qt_3_A19		= -1;
static int hf_dect_A_Tail_Qt_3_A20		= -1;
static int hf_dect_A_Tail_Qt_3_A21		= -1;
static int hf_dect_A_Tail_Qt_3_A22		= -1;
static int hf_dect_A_Tail_Qt_3_A23		= -1;
static int hf_dect_A_Tail_Qt_3_A24		= -1;
static int hf_dect_A_Tail_Qt_3_A25		= -1;
static int hf_dect_A_Tail_Qt_3_A26		= -1;
static int hf_dect_A_Tail_Qt_3_A27		= -1;
static int hf_dect_A_Tail_Qt_3_A28		= -1;
static int hf_dect_A_Tail_Qt_3_A29		= -1;
static int hf_dect_A_Tail_Qt_3_A30		= -1;
static int hf_dect_A_Tail_Qt_3_A31		= -1;
static int hf_dect_A_Tail_Qt_3_A32		= -1;
static int hf_dect_A_Tail_Qt_3_A33		= -1;
static int hf_dect_A_Tail_Qt_3_A34		= -1;
static int hf_dect_A_Tail_Qt_3_A35		= -1;
static int hf_dect_A_Tail_Qt_3_A36		= -1;
static int hf_dect_A_Tail_Qt_3_A37		= -1;
static int hf_dect_A_Tail_Qt_3_A38		= -1;
static int hf_dect_A_Tail_Qt_3_A39		= -1;
static int hf_dect_A_Tail_Qt_3_A40		= -1;
static int hf_dect_A_Tail_Qt_3_A41		= -1;
static int hf_dect_A_Tail_Qt_3_A42		= -1;
static int hf_dect_A_Tail_Qt_3_A43		= -1;
static int hf_dect_A_Tail_Qt_3_A44		= -1;
static int hf_dect_A_Tail_Qt_3_A45		= -1;
static int hf_dect_A_Tail_Qt_3_A46		= -1;
static int hf_dect_A_Tail_Qt_3_A47		= -1;
static int hf_dect_A_Tail_Qt_4_CRFPHops		= -1;
static int hf_dect_A_Tail_Qt_4_CRFPEnc		= -1;
static int hf_dect_A_Tail_Qt_4_REFHops		= -1;
static int hf_dect_A_Tail_Qt_4_REPCap		= -1;
static int hf_dect_A_Tail_Qt_4_Sync		= -1;
static int hf_dect_A_Tail_Qt_4_A20		= -1;
static int hf_dect_A_Tail_Qt_4_MACSusp		= -1;
static int hf_dect_A_Tail_Qt_4_MACIpq		= -1;
static int hf_dect_A_Tail_Qt_4_A23		= -1;
static int hf_dect_A_Tail_Qt_4_A24		= -1;
static int hf_dect_A_Tail_Qt_4_A25		= -1;
static int hf_dect_A_Tail_Qt_4_A26		= -1;
static int hf_dect_A_Tail_Qt_4_A27		= -1;
static int hf_dect_A_Tail_Qt_4_A28		= -1;
static int hf_dect_A_Tail_Qt_4_A29		= -1;
static int hf_dect_A_Tail_Qt_4_A30		= -1;
static int hf_dect_A_Tail_Qt_4_A31		= -1;
static int hf_dect_A_Tail_Qt_4_A32		= -1;
static int hf_dect_A_Tail_Qt_4_A33		= -1;
static int hf_dect_A_Tail_Qt_4_A34		= -1;
static int hf_dect_A_Tail_Qt_4_A35		= -1;
static int hf_dect_A_Tail_Qt_4_A36		= -1;
static int hf_dect_A_Tail_Qt_4_A37		= -1;
static int hf_dect_A_Tail_Qt_4_A38		= -1;
static int hf_dect_A_Tail_Qt_4_A39		= -1;
static int hf_dect_A_Tail_Qt_4_A40		= -1;
static int hf_dect_A_Tail_Qt_4_A41		= -1;
static int hf_dect_A_Tail_Qt_4_A42		= -1;
static int hf_dect_A_Tail_Qt_4_A43		= -1;
static int hf_dect_A_Tail_Qt_4_A44		= -1;
static int hf_dect_A_Tail_Qt_4_A45		= -1;
static int hf_dect_A_Tail_Qt_4_A46		= -1;
static int hf_dect_A_Tail_Qt_4_A47		= -1;
static int hf_dect_A_Tail_Qt_6_Spare		= -1;
static int hf_dect_A_Tail_Qt_6_Mfn		= -1;
static int hf_dect_A_Tail_Mt_Mh			= -1;
static int hf_dect_A_Tail_Mt_Mh_fmid		= -1;
static int hf_dect_A_Tail_Mt_Mh_pmid		= -1;
static int hf_dect_A_Tail_Mt_BasicConCtrl	= -1;
static int hf_dect_A_Tail_Mt_Encr_Cmd1		= -1;
static int hf_dect_A_Tail_Mt_Encr_Cmd2		= -1;
static int hf_dect_A_Tail_Pt_ExtFlag		= -1;
static int hf_dect_A_Tail_Pt_SDU		= -1;
static int hf_dect_A_Tail_Pt_InfoType		= -1;
static int hf_dect_A_Tail_Pt_Fill_Fillbits	= -1;
static int hf_dect_A_Tail_Pt_Bearer_Sn		= -1;
static int hf_dect_A_Tail_Pt_Bearer_Cn		= -1;
static int hf_dect_A_Tail_Pt_Bearer_Sp		= -1;
static int hf_dect_A_RCRC			= -1;
static int hf_dect_B				= -1;
static int hf_dect_B_Data			= -1;
static int hf_dect_B_fn				= -1;
static int hf_dect_B_XCRC			= -1;

static const value_string tranceiver_mode[]=
{
	{0, "Receive"},
	{1, "Send"},
	{0, NULL}
};

static const value_string TA_vals_FP[]=
{
	{0, "Ct Next Data Packet"},
	{1, "Ct First Data Packet"},
	{2, "Nt Identities Information on Connectionless Bearer"},
	{3, "Nt Identities Information"},
	{4, "Qt Multiframe Synchronisation and System Information"},
	{5, "Escape"},
	{6, "Mt MAC Layer Control"},
	{7, "Pt Paging Tail"},
	{0, NULL}
};

static const value_string TA_vals_PP[]=
{
	{0, "Ct Next Data Packet"},
	{1, "Ct First Data Packet"},
	{2, "Nt Identities Information on Connectionless Bearer"},
	{3, "Nt Identities Information"},
	{4, "Qt Multiframe Synchronisation and System Information"},
	{5, "Escape"},
	{6, "Mt MAC Layer Control"},
	{7, "Mt MAC Layer Control,first packet"},
	{0, NULL}
};

static const value_string BA_vals[]=
{
	{0, "U-Type, In, SIn or Ip Packet No. 0 or No Valid Ip_error_detect Channel Data"},
	{1, "U-Type, Ip_error_detect or Ip Packet No. 1 or SIn or No Valid In Channel Data"},
	{2, "Double-Slot Required / E-Type, all Cf or CLf, Packet No. 0"},
	{3, "E-Type, All Cf, Packet No. 1"},
	{4, "Half-Slot Required / E-Type, not all Cf or CLf, Cf Packet No. 0"},
	{5, "E-Type, not all Cf, Cf Packet No. 1"},
	{6, "E-Type, All MAC control (unnumbered)"},
	{7, "No B-Field"},
	{0, NULL}
};

static const value_string QTHead_vals[]=
{
	{0, "Static System Info"},
	{1, "Static System Info"},
	{2, "Extended RF Carriers Part 1"},
	{3, "Fixed Part Capabilities"},
	{4, "Extended Fixed Part Capabilities"},
	{5, "SARI List Contents"},
	{6, "Multi-Frame No."},
	{7, "Escape"},
	{8, "Obsolete"},
	{9, "Extended RF Carriers Part 2"},
	{10, "Reserved(?)"},
	{11, "Transmit Information(?)"},
	{12, "Reserved"},
	{13, "Reserved"},
	{14, "Reserved"},
	{15, "Reserved"},
	{0, NULL}
};

static const value_string QTNormalReverse_vals[]=
{
	{0, "Normal RFP Transmit Half-Frame"},
	{1, "Normal PP Transmit Half-Frame"},
	{0, NULL}
};

static const value_string QTSlotNumber_vals[]=
{
	{0, "Slot Pair 0/12"},
	{1, "Slot Pair 1/13"},
	{2, "Slot Pair 2/14"},
	{3, "Slot Pair 3/15"},
	{4, "Slot Pair 4/16"},
	{5, "Slot Pair 5/17"},
	{6, "Slot Pair 6/18"},
	{7, "Slot Pair 7/19"},
	{8, "Slot Pair 8/20"},
	{9, "Slot Pair 9/21"},
	{10, "Slot Pair 10/22"},
	{11, "Slot Pair 11/23"},
	{12, "Reserved"},
	{13, "Reserved"},
	{14, "Reserved"},
	{15, "Reserved"},
	{0, NULL}
};

static const value_string QTStartPosition_vals[]=
{
	{0, "S-Field starts at Bit F0"},
	{1, "Reserved for Future Use"},
	{2, "S-Field starts at Bit F240"},
	{3, "Reserved for Future Use"},
	{0, NULL}
};

static const value_string QTEscape_vals[]=
{
	{0, "No QT Escape is broadcast"},
	{1, "The QT Escape is broadcast"},
	{0, NULL}
};

static const value_string QTTranceiver_vals[]=
{
	{0, "RFP has 1 Transceiver"},
	{1, "RFP has 2 Transceiver"},
	{2, "RFP has 3 Transceiver"},
	{3, "RFP has 4 or more Transceiver"},
	{0, NULL}
};

static const value_string QTExtendedCarrier_vals[]=
{
	{0, "No Extended RF Carrier Information Message"},
	{1, "Extended RF Carrier Information Message shall be transmitted in the next Multiframe"},
	{0, NULL}
};

static const value_string QTSpr_vals[]=
{
	{0, "OK"},
	{1, "Reserved"},
	{2, "Reserved"},
	{3, "Reserved"},
	{0, NULL}
};

static const value_string QTCarrierNumber_vals[]=
{
	{0, "RF Carrier 0"},
	{1, "RF Carrier 1"},
	{2, "RF Carrier 2"},
	{3, "RF Carrier 3"},
	{4, "RF Carrier 4"},
	{5, "RF Carrier 5"},
	{6, "RF Carrier 6"},
	{7, "RF Carrier 7"},
	{8, "RF Carrier 8"},
	{9, "RF Carrier 9"},
	{10, "RF Carrier 10"},
	{11, "RF Carrier 11"},
	{12, "RF Carrier 12"},
	{13, "RF Carrier 13"},
	{14, "RF Carrier 14"},
	{15, "RF Carrier 15"},
	{16, "RF Carrier 16"},
	{17, "RF Carrier 17"},
	{18, "RF Carrier 18"},
	{19, "RF Carrier 19"},
	{20, "RF Carrier 20"},
	{21, "RF Carrier 21"},
	{22, "RF Carrier 22"},
	{23, "RF Carrier 23"},
	{24, "RF Carrier 24"},
	{25, "RF Carrier 25"},
	{26, "RF Carrier 26"},
	{27, "RF Carrier 27"},
	{28, "RF Carrier 28"},
	{29, "RF Carrier 29"},
	{30, "RF Carrier 30"},
	{31, "RF Carrier 31"},
	{32, "RF Carrier 32"},
	{33, "RF Carrier 33"},
	{34, "RF Carrier 34"},
	{35, "RF Carrier 35"},
	{36, "RF Carrier 36"},
	{37, "RF Carrier 37"},
	{38, "RF Carrier 38"},
	{39, "RF Carrier 39"},
	{40, "RF Carrier 40"},
	{41, "RF Carrier 41"},
	{42, "RF Carrier 42"},
	{43, "RF Carrier 43"},
	{44, "RF Carrier 44"},
	{45, "RF Carrier 45"},
	{46, "RF Carrier 46"},
	{47, "RF Carrier 47"},
	{48, "RF Carrier 48"},
	{49, "RF Carrier 49"},
	{50, "RF Carrier 50"},
	{51, "RF Carrier 51"},
	{52, "RF Carrier 52"},
	{53, "RF Carrier 53"},
	{54, "RF Carrier 54"},
	{55, "RF Carrier 55"},
	{56, "RF Carrier 56"},
	{57, "RF Carrier 57"},
	{58, "RF Carrier 58"},
	{59, "RF Carrier 59"},
	{60, "RF Carrier 60"},
	{61, "RF Carrier 61"},
	{62, "RF Carrier 62"},
	{63, "RF Carrier 63"},
	{0, NULL}
};

static const value_string QTScanCarrierNum_vals[]=
{
	{0, "Primary Scan next on RF Carrier 0"},
	{1, "Primary Scan next on RF Carrier 1"},
	{2, "Primary Scan next on RF Carrier 2"},
	{3, "Primary Scan next on RF Carrier 3"},
	{4, "Primary Scan next on RF Carrier 4"},
	{5, "Primary Scan next on RF Carrier 5"},
	{6, "Primary Scan next on RF Carrier 6"},
	{7, "Primary Scan next on RF Carrier 7"},
	{8, "Primary Scan next on RF Carrier 8"},
	{9, "Primary Scan next on RF Carrier 9"},
	{10, "Primary Scan next on RF Carrier 10"},
	{11, "Primary Scan next on RF Carrier 11"},
	{12, "Primary Scan next on RF Carrier 12"},
	{13, "Primary Scan next on RF Carrier 13"},
	{14, "Primary Scan next on RF Carrier 14"},
	{15, "Primary Scan next on RF Carrier 15"},
	{16, "Primary Scan next on RF Carrier 16"},
	{17, "Primary Scan next on RF Carrier 17"},
	{18, "Primary Scan next on RF Carrier 18"},
	{19, "Primary Scan next on RF Carrier 19"},
	{20, "Primary Scan next on RF Carrier 20"},
	{21, "Primary Scan next on RF Carrier 21"},
	{22, "Primary Scan next on RF Carrier 22"},
	{23, "Primary Scan next on RF Carrier 23"},
	{24, "Primary Scan next on RF Carrier 24"},
	{25, "Primary Scan next on RF Carrier 25"},
	{26, "Primary Scan next on RF Carrier 26"},
	{27, "Primary Scan next on RF Carrier 27"},
	{28, "Primary Scan next on RF Carrier 28"},
	{29, "Primary Scan next on RF Carrier 29"},
	{30, "Primary Scan next on RF Carrier 30"},
	{31, "Primary Scan next on RF Carrier 31"},
	{32, "Primary Scan next on RF Carrier 32"},
	{33, "Primary Scan next on RF Carrier 33"},
	{34, "Primary Scan next on RF Carrier 34"},
	{35, "Primary Scan next on RF Carrier 35"},
	{36, "Primary Scan next on RF Carrier 36"},
	{37, "Primary Scan next on RF Carrier 37"},
	{38, "Primary Scan next on RF Carrier 38"},
	{39, "Primary Scan next on RF Carrier 39"},
	{40, "Primary Scan next on RF Carrier 40"},
	{41, "Primary Scan next on RF Carrier 41"},
	{42, "Primary Scan next on RF Carrier 42"},
	{43, "Primary Scan next on RF Carrier 43"},
	{44, "Primary Scan next on RF Carrier 44"},
	{45, "Primary Scan next on RF Carrier 45"},
	{46, "Primary Scan next on RF Carrier 46"},
	{47, "Primary Scan next on RF Carrier 47"},
	{48, "Primary Scan next on RF Carrier 48"},
	{49, "Primary Scan next on RF Carrier 49"},
	{50, "Primary Scan next on RF Carrier 50"},
	{51, "Primary Scan next on RF Carrier 51"},
	{52, "Primary Scan next on RF Carrier 52"},
	{53, "Primary Scan next on RF Carrier 53"},
	{54, "Primary Scan next on RF Carrier 54"},
	{55, "Primary Scan next on RF Carrier 55"},
	{56, "Primary Scan next on RF Carrier 56"},
	{57, "Primary Scan next on RF Carrier 57"},
	{58, "Primary Scan next on RF Carrier 58"},
	{59, "Primary Scan next on RF Carrier 59"},
	{60, "Primary Scan next on RF Carrier 60"},
	{61, "Primary Scan next on RF Carrier 61"},
	{62, "Primary Scan next on RF Carrier 62"},
	{63, "Primary Scan next on RF Carrier 63"},
	{0, NULL}
};

static const value_string Qt_A12_vals[]=
{
	{0, "   Extended FP Info"},
	{1, "Extended FP Info"},
	{0, NULL}
};

static const value_string Qt_A13_vals[]=
{
	{0, "   Double Duplex Bearer Connections"},
	{1, "Double Duplex Bearer Connections"},
	{0, NULL}
};

static const value_string Qt_A14_vals[]=
{
	{0, "   Reserved"},
	{1, "Reserved"},
	{0, NULL}
};

static const value_string Qt_A15_vals[]=
{
	{0, "   Double Slot"},
	{1, "Double Slot"},
	{0, NULL}
};

static const value_string Qt_A16_vals[]=
{
	{0, "   Half Slot"},
	{1, "Half Slot"},
	{0, NULL}
};

static const value_string Qt_A17_vals[]=
{
	{0, "   Full Slot"},
	{1, "Full Slot"},
	{0, NULL}
};

static const value_string Qt_A18_vals[]=
{
	{0, "   Frequency Control"},
	{1, "Frequency Control"},
	{0, NULL}
};

static const value_string Qt_A19_vals[]=
{
	{0, "   Page Repetition"},
	{1, "Page Repetition"},
	{0, NULL}
};

static const value_string Qt_A20_vals[]=
{
	{0, "   C/O Setup on Dummy allowed"},
	{1, "C/O Setup on Dummy allowed"},
	{0, NULL}
};

static const value_string Qt_A21_vals[]=
{
	{0, "   C/L Uplink"},
	{1, "C/L Uplink"},
	{0, NULL}
};

static const value_string Qt_A22_vals[]=
{
	{0, "   C/L Downlink"},
	{1, "C/L Downlink"},
	{0, NULL}
};

static const value_string Qt_A23_vals[]=
{
	{0, "   Basic A-Field Set-Up"},
	{1, "Basic A-Field Set-Up"},
	{0, NULL}
};

static const value_string Qt_A24_vals[]=
{
	{0, "   Advanced A-Field Set-Up"},
	{1, "Advanced A-Field Set-Up"},
	{0, NULL}
};

static const value_string Qt_A25_vals[]=
{
	{0, "   B-field Set-Up"},
	{1, "B-field Set-Up"},
	{0, NULL}
};

static const value_string Qt_A26_vals[]=
{
	{0, "   Cf Messages"},
	{1, "Cf Messages"},
	{0, NULL}
};

static const value_string Qt_A27_vals[]=
{
	{0, "   In Minimum Delay"},
	{1, "In Minimum Delay"},
	{0, NULL}
};

static const value_string Qt_A28_vals[]=
{
	{0, "   In Normal Delay"},
	{1, "In Normal Delay"},
	{0, NULL}
};

static const value_string Qt_A29_vals[]=
{
	{0, "   Ip Error Detection"},
	{1, "Ip Error Detection"},
	{0, NULL}
};

static const value_string Qt_A30_vals[]=
{
	{0, "   Ip Error Correction"},
	{1, "Ip Error Correction"},
	{0, NULL}
};

static const value_string Qt_A31_vals[]=
{
	{0, "   Multibearer Connections"},
	{1, "Multibearer Connections"},
	{0, NULL}
};

static const value_string Qt_A32_vals[]=
{
	{0, "   ADPCM/G.726 Voice service"},
	{1, "ADPCM/G.726 Voice service"},
	{0, NULL}
};

static const value_string Qt_A33_vals[]=
{
	{0, "   GAP basic speech"},
	{1, "GAP basic speech"},
	{0, NULL}
};

static const value_string Qt_A34_vals[]=
{
	{0, "   Non-voice circuit switched service"},
	{1, "Non-voice circuit switched service"},
	{0, NULL}
};

static const value_string Qt_A35_vals[]=
{
	{0, "   Non-voice packet switched service"},
	{1, "Non-voice packet switched service"},
	{0, NULL}
};

static const value_string Qt_A36_vals[]=
{
	{0, "   Standard authentication required"},
	{1, "Standard authentication required"},
	{0, NULL}
};

static const value_string Qt_A37_vals[]=
{
	{0, "   Standard ciphering supported"},
	{1, "Standard ciphering supported"},
	{0, NULL}
};

static const value_string Qt_A38_vals[]=
{
	{0, "   Location registration supported"},
	{1, "Location registration supported"},
	{0, NULL}
};

static const value_string Qt_A39_vals[]=
{
	{0, "   SIM services available"},
	{1, "SIM services available"},
	{0, NULL}
};

static const value_string Qt_A40_vals[]=
{
	{0, "   Non-static Fixed Part (FP)"},
	{1, "Non-static Fixed Part (FP)"},
	{0, NULL}
};

static const value_string Qt_A41_vals[]=
{
	{0, "   CISS services available"},
	{1, "CISS services available"},
	{0, NULL}
};

static const value_string Qt_A42_vals[]=
{
	{0, "   CLMS service available"},
	{1, "CLMS service available"},
	{0, NULL}
};

static const value_string Qt_A43_vals[]=
{
	{0, "   COMS service available"},
	{1, "COMS service available"},
	{0, NULL}
};

static const value_string Qt_A44_vals[]=
{
	{0, "   Access rights requests supported"},
	{1, "Access rights requests supported"},
	{0, NULL}
};

static const value_string Qt_A45_vals[]=
{
	{0, "   External handover supported"},
	{1, "External handover supported"},
	{0, NULL}
};

static const value_string Qt_A46_vals[]=
{
	{0, "   Connection handover supported"},
	{1, "Connection handover supported"},
	{0, NULL}
};

static const value_string Qt_A47_vals[]=
{
	{0, "   Reserved"},
	{1, "Reserved"},
	{0, NULL}
};


static const value_string Qt_EA20_vals[]=
{
	{0, "   Reserved"},
	{1, "Reserved"},
	{0, NULL}
};

static const value_string Qt_CRFPHops_vals[]=
{
	{0, "1 CRFP is allowed"},
	{1, "2 CRFP allowed in cascade"},
	{2, "3 CRFP allowed in cascade"},
	{3, "No CRFP allowed"},
	{0, NULL}
};

static const value_string Qt_CRFPEnc_vals[]=
{
	{0, "CRFP encryption not supported"},
	{1, "CRFP encryption supported"},
	{0, NULL}
};

static const value_string Qt_REPHops_vals[]=
{
	{0, "REP not supported"},
	{1, "1 REP is allowed"},
	{2, "2 REP are allowed in cascade"},
	{3, "3 REP are allowed in cascade"},
	{0, NULL}
};

static const value_string Qt_REPCap_vals[]=
{
	{0, "REP interlacing not supported"},
	{1, "REP interlacing supported"},
	{0, NULL}
};

static const value_string Qt_Sync_vals[]=
{
	{0, "standard, see EN 300 175-2 [2], clauses 4.6 and 5.2"},
	{1, "prolonged preamble, see EN 300 175-2 [2], annex C (see note)"},
	{2, "reserved"},
	{3, "reserved"},
	{0, NULL}
};

static const value_string Qt_MACSusp_vals[]=
{
	{0, "Suspend and Resume not supported"},
	{1, "Suspend and Resume supported"},
	{0, NULL}
};

static const value_string Qt_MACIpq_vals[]=
{
	{0, "Ipq not supported"},
	{1, "Ipq supported"},
	{0, NULL}
};

static const value_string Qt_EA23_vals[]=
{
	{0, "   Extended Fixed Part Info 2"},
	{1, "Extended Fixed Part Info 2"},
	{0, NULL}
};

static const value_string Qt_EA24_vals[]=
{
	{0, "   Unused"},
	{1, "Unused"},
	{0, NULL}
};

static const value_string Qt_EA25_vals[]=
{
	{0, "   F-MMS Interworking profile supported"},
	{1, "F-MMS Interworking profile supported"},
	{0, NULL}
};

static const value_string Qt_EA26_vals[]=
{
	{0, "   Basic ODAP supported"},
	{1, "Basic ODAP supported"},
	{0, NULL}
};

static const value_string Qt_EA27_vals[]=
{
	{0, "   Generic Media Encapsulation transport (DPRS) supported"},
	{1, "Generic Media Encapsulation transport (DPRS) supported"},
	{0, NULL}
};

static const value_string Qt_EA28_vals[]=
{
	{0, "   IP Roaming unrestricted supported"},
	{1, "IP Roaming unrestricted supported"},
	{0, NULL}
};

static const value_string Qt_EA29_vals[]=
{
	{0, "   Ethernet"},
	{1, "Ethernet"},
	{0, NULL}
};

static const value_string Qt_EA30_vals[]=
{
	{0, "   Token Ring"},
	{1, "Token Ring"},
	{0, NULL}
};

static const value_string Qt_EA31_vals[]=
{
	{0, "   IP"},
	{1, "IP"},
	{0, NULL}
};

static const value_string Qt_EA32_vals[]=
{
	{0, "   PPP"},
	{1, "PPP"},
	{0, NULL}
};

static const value_string Qt_EA33_vals[]=
{
	{0, "   V.24"},
	{1, "V.24"},
	{0, NULL}
};

static const value_string Qt_EA34_vals[]=
{
	{0, "   Reserved"},
	{1, "Reserved"},
	{0, NULL}
};

static const value_string Qt_EA35_vals[]=
{
	{0, "   Reserved"},
	{1, "Reserved"},
	{0, NULL}
};

static const value_string Qt_EA36_vals[]=
{
	{0, "   RAP Part 1 Profile"},
	{1, "RAP Part 1 Profile"},
	{0, NULL}
};

static const value_string Qt_EA37_vals[]=
{
	{0, "   ISDN intermediate system"},
	{1, "ISDN intermediate system"},
	{0, NULL}
};

static const value_string Qt_EA38_vals[]=
{
	{0, "   Synchronization to GPS achieved"},
	{1, "Synchronization to GPS achieved"},
	{0, NULL}
};

static const value_string Qt_EA39_vals[]=
{
	{0, "   Location registration with TPUI allowed"},
	{1, "Location registration with TPUI allowed"},
	{0, NULL}
};

static const value_string Qt_EA40_vals[]=
{
	{0, "   Emergency call supported"},
	{1, "Emergency call supported"},
	{0, NULL}
};

static const value_string Qt_EA41_vals[]=
{
	{0, "   Asymmetric bearers supported"},
	{1, "Asymmetric bearers supported"},
	{0, NULL}
};

static const value_string Qt_EA42_vals[]=
{
	{0, "   Reserved"},
	{1, "Reserved"},
	{0, NULL}
};

static const value_string Qt_EA43_vals[]=
{
	{0, "   LRMS"},
	{1, "LRMS"},
	{0, NULL}
};

static const value_string Qt_EA44_vals[]=
{
	{0, "   Data Service Profile D"},
	{1, "Data Service Profile D"},
	{0, NULL}
};

static const value_string Qt_EA45_vals[]=
{
	{0, "   DPRS Stream"},
	{1, "DPRS Stream"},
	{0, NULL}
};

static const value_string Qt_EA46_vals[]=
{
	{0, "   DPRS FREL"},
	{1, "DPRS FREL"},
	{0, NULL}
};

static const value_string Qt_EA47_vals[]=
{
	{0, "   ISDN Data Services"},
	{1, "ISDN Data Services"},
	{0, NULL}
};




static const value_string MTHead_vals[]=
{
	{0, "Basic Connection Control"},
	{1, "Advanced Connection Control"},
	{2, "MAC Layer Test Messages"},
	{3, "Quality Control"},
	{4, "Broadcast and Connectionless Services"},
	{5, "Encryption Control"},
	{6, "Tail for use with the first Transmission of a B-Field \"bearer request\" Message"},
	{7, "Escape"},
	{8, "TARI Message"},
	{9, "REP Connection Control"},
	{10, "Reserved"},
	{11, "Reserved"},
	{12, "Reserved"},
	{13, "Reserved"},
	{14, "Reserved"},
	{15, "Reserved"},
	{0, NULL}
};

static const value_string MTBasicConCtrl_vals[]=
{
	{0, "Access Request"},
	{1, "Bearer Handover Request"},
	{2, "Connection Handover Request"},
	{3, "Unconfirmed Access Request"},
	{4, "Bearer Confirm"},
	{5, "Wait"},
	{6, "Attributes T Request"},
	{7, "Attributes T Confirm"},
	{8, "Reserved"},
	{9, "Reserved"},
	{10, "Reserved"},
	{11, "Reserved"},
	{12, "Reserved"},
	{13, "Reserved"},
	{14, "Reserved"},
	{15, "Release"},
	{0, NULL}
};

static const value_string MTEncrCmd1_vals[]=
{
	{0, "Start Encryption"},
	{1, "Stop Encryption"},
	{2, "reserved"},
	{3, "reserved"},
	{0, NULL}
};

static const value_string MTEncrCmd2_vals[]=
{
	{0, "Request"},
	{1, "Confirm"},
	{2, "Grant"},
	{3, "Reserved"},
	{0, NULL}
};

static const value_string PTExtFlag_vals[]=
{
	{0, "bla1"},
	{1, "bla2"},
	{0, NULL}
};

static const value_string PTSDU_vals[]=
{
	{0, "Zero Length Page"},
	{1, "Short Page"},
	{2, "Full Page"},
	{3, "MAC resume page"},
	{4, "Not the last 36 Bits of a Long Page"},
	{5, "The first 36 Bits of a Long Page"},
	{6, "The last 36 Bits of a Long Page"},
	{7, "All of a Long Page (first and last)"},
	{0, NULL}
};

static const value_string PTInfoType_vals[]=
{
	{0, "Fill Bits"},
	{1, "Blind Full Slot Information for Circuit Mode Service"},
	{2, "Other Bearer"},
	{3, "Recommended Other Bearer"},
	{4, "Good RFP Bearer"},
	{5, "Dummy or connectionless Bearer Position"},
	{6, "Extended Modulation Types"},
	{7, "Escape"},
	{8, "Dummy or connectionless Bearer Marker"},
	{9, "Bearer Handover/Replacement Information"},
	{10, "RFP Status and Modulation Types"},
	{11, "Active Carriers"},
	{12, "Connectionless Bearer Position"},
	{13, "RFP Power Level"},
	{14, "Blind Double Slot/RFP-FP Interface Resource Information"},
	{15, "Blind Full Slot Information for Packet Mode Service"},
	{0, NULL}
};

static const value_string PTRFPPower_vals[]=
{
	{0, "0 dBm"},
	{1, "2 dBm"},
	{2, "4 dBm"},
	{3, "6 dBm"},
	{4, "8 dBm"},
	{5, "10 dBm"},
	{6, "12 dBm"},
	{7, "14 dBm"},
	{8, "16 dBm"},
	{9, "18 dBm"},
	{10, "20 dBm"},
	{11, "22 dBm"},
	{12, "24 dBm"},
	{13, "26 dBm"},
	{14, "28 dBm"},
	{15, "30 dBm"},
	{0, NULL}
};

static unsigned char
getbit(guint8 *data, int bit)
{
	guint8 c;
	guint8 byte=data[bit/8];

	c=1;
	c<<=bit%8;

	return (byte&c)>>bit%8;
}

static void
setbit(guint8 *data, int bit, guint8 value)
{
	if(!value)
		data[bit/8]&=~(1<<(bit%8));
	else
		data[bit/8]|=(1<<(bit%8));
}

static guint8
calc_xcrc(guint8* data, guint8 length)
{
	guint8 bits[21];
	guint8 gp=0x1;
	guint8 crc;
	guint8 next;
	int y, x;

	for(y=0;y<80;y++)
	{
		setbit(bits, y, getbit(data, y+48*(1+(int)(y/16))));
	}
	length=10;
	crc=bits[0];
	y=0;
	while(y<length)
	{
		if(y<(length-1))
			next=bits[y+1];
		else
			next=0;
		y++;
		x=0;
		while(x<8)
		{
			while(!(crc&0x80))
			{
				crc<<=1;
				crc|=!!(next&0x80);
				next<<=1;
				x++;
				if(x>7)
					break;
			}
			if(x>7)
				break;
			crc<<=1;
			crc|=!!(next&0x80);
			next<<=1;
			x++;
			crc^=(gp<<4);
		}
	}
/* 	crc^=0x10; */
	return crc;
}

static guint16
calc_rcrc(guint8* data)
{
	guint16 gp=0x0589;		/* 10000010110001001 without the leading 1 */

	guint16 crc;
	guint8 next;
	int y, x;

	crc=data[0]<<8|data[1];
	y=0;
	while(y<6)
	{
		next=data[2+y];
		y++;
		x=0;
		while(x<8)
		{
			while(!(crc&0x8000))
			{
				crc<<=1;
				crc|=!!(next&0x80);
				next<<=1;
				x++;
				if(x>7)
					break;
			}
			if(x>7)
				break;
			crc<<=1;
			crc|=!!(next&0x80);
			next<<=1;
			x++;
			crc^=gp;
		}
	}
	crc^=1;
	return crc;
}

static gint
dissect_bfield(gboolean dect_packet_type _U_, guint8 a_header,
	struct dect_bfield *pkt_bfield, packet_info *pinfo, const guint8 *pkt_ptr _U_,
	tvbuff_t *tvb, proto_item *ti _U_, proto_tree *DectTree, gint offset)
{
	guint8 xcrc, xcrclen;
	guint16 blen;
	gint oldoffset, fn;
	proto_item *bfieldti	=NULL;
#if 0
	proto_item *bxcrc	=NULL;
#endif
	proto_tree *BField	=NULL;

	/* B-Feld */
	switch((a_header&0x0E)>>1)
	{
	case 0:
	case 1:
	case 3:
	case 5:
	case 6:
		blen=40;
		xcrclen=4;

		if(check_col(pinfo->cinfo, COL_INFO /*Type1*/))
		{
			col_append_str(pinfo->cinfo, COL_INFO /*Type1*/, "Full Slot");
		}
		break;
	case 2:
		blen=100;
		xcrclen=4;

		if(check_col(pinfo->cinfo, COL_INFO /*Type1*/))
		{
			col_append_str(pinfo->cinfo, COL_INFO /*Type1*/, "Double Slot");
		}
		break;
	case 4:
		blen=10;
		xcrclen=4;

		if(check_col(pinfo->cinfo, COL_INFO /*Type1*/))
		{
			col_append_str(pinfo->cinfo, COL_INFO /*Type1*/, "Half Slot");
		}
		break;
	case 7:
	default:
		blen=0;
		xcrclen=0;

		if(check_col(pinfo->cinfo, COL_INFO /*Type1*/))
		{
			col_append_str(pinfo->cinfo, COL_INFO /*Type1*/, "No B-Field");
		}
		break;

	}
	if(blen)
	{
		bfieldti	= proto_tree_add_item(DectTree, hf_dect_B, tvb, offset, 40, FALSE);
		BField		= proto_item_add_subtree(bfieldti, ett_bfield);
	}

	oldoffset=offset;

	if((blen+(xcrclen/8)+1)<=pkt_bfield->Length)
	{
		guint16 x, y;
		for(x=0;x<blen;x+=16)
		{
			/*
			 * XXX - should this just be an FTYPE_BYTES field,
			 * and possibly just displayed as "Data: N bytes"
			 * rather than giving all the bytes of data?
			 */
			for(y=0;y<16;y++)
			{
				if((x+y)>=blen)
					break;
			}
			proto_tree_add_item(BField, hf_dect_B_Data, tvb, offset, y, FALSE);
			if(y==16)
				offset+=16;
			else
				/* XXX: Why 16-y and not y??? */
				offset+=16-y;
		}
		for(fn=0;fn<8;fn++)
		{
			guint16 bytecount=0;

			offset=oldoffset;

			proto_tree_add_none_format(BField, hf_dect_B_fn, tvb, offset, 0, "\nFramenumber %u/%u", fn, fn+8);
			for(x=0;x<blen;x+=16)
			{
				/*
				 * XXX - should this just be an FTYPE_BYTES
				 * field, and possibly just displayed as
				 * "Data: N bytes" rather than giving all
				 * the bytes of data?
				 */
				emem_strbuf_t *string;
				string = ep_strbuf_new(NULL);
				for(y=0;y<16;y++)
				{
					if((x+y)>=blen)
						break;

					ep_strbuf_append_printf(string,"%.2x ", pkt_bfield->Data[x+y]^scrt[fn][bytecount%31]);
					bytecount++;
				}
				proto_tree_add_uint_format(BField, hf_dect_B_Data, tvb, offset, y, 0x2323, "Data: %s", string->str);
				if(y==16)
					offset+=16;
				else
					offset+=16-y;
			}
		}
		xcrc=calc_xcrc(pkt_bfield->Data, 83);

		if(xcrc!=(pkt_bfield->Data[40]&0xf0))
			/* XXX: pkt_bfield->Data[40]&0xf0 isn't really the Recv value?? */
			proto_tree_add_uint_format(bfieldti, hf_dect_B_XCRC, tvb, offset, 1, 0, "X-CRC Error (Calc:%.2x, Recv:%.2x)", xcrc, pkt_bfield->Data[40]&0xf0);
		else
			/* XXX: pkt_bfield->Data[40]&0xf0 isn't really the Recv value?? */
			proto_tree_add_uint_format(bfieldti, hf_dect_B_XCRC, tvb, offset, 1, 1, "X-CRC Match (Calc:%.2x, Recv:%.2x)", xcrc, pkt_bfield->Data[40]&0xf0);
	}
	else
		proto_tree_add_uint_format(BField, hf_dect_B_Data, tvb, offset, 0, 0x2323, "Data too Short");
	return offset;
}

static void
dissect_decttype(gboolean dect_packet_type, struct dect_afield *pkt_afield,
	struct dect_bfield *pkt_bfield, packet_info *pinfo, const guint8 *pkt_ptr,
	tvbuff_t *tvb, proto_item *ti, proto_tree *DectTree)
{
	guint16 rcrc;
	guint8 rcrcdat[8];
	gint offset		=11;
	guint8 tailtype		=0;
	proto_item *afieldti	=NULL;
	proto_item *aheadti	=NULL;
	proto_item *atailti	=NULL;
#if 0
	proto_item *arcrc	=NULL;
	proto_item *aqtti	=NULL;
#endif
	proto_tree *AField	=NULL;
	proto_tree *AHead	=NULL;
	proto_tree *ATail	=NULL;

	guint8	header, tail_0, tail_1, tail_2, tail_3, tail_4;
#if 0
	proto_tree *AQT		=NULL;
#endif

	/************************** A-Field ***********************************/

	/* A-Feld */
	header=tvb_get_guint8(tvb, offset+0);
	tail_0=tvb_get_guint8(tvb, offset+1);
	tail_1=tvb_get_guint8(tvb, offset+2);
	tail_2=tvb_get_guint8(tvb, offset+3);
	tail_3=tvb_get_guint8(tvb, offset+4);
	tail_4=tvb_get_guint8(tvb, offset+5);
	tailtype	= header >> 5;
	afieldti	= proto_tree_add_item(DectTree, hf_dect_A, tvb, offset, 8, FALSE);
	AField		= proto_item_add_subtree(afieldti, ett_afield);

	/* Header */
	aheadti		= proto_tree_add_item(afieldti, hf_dect_A_Head, tvb, offset, 1, FALSE);
	AHead		= proto_item_add_subtree(aheadti, ett_ahead);

	if(dect_packet_type==DECT_PACKET_FP)
		proto_tree_add_item(AHead, hf_dect_A_Head_TA_FP, tvb, offset, 1, FALSE);
	else
		proto_tree_add_item(AHead, hf_dect_A_Head_TA_PP, tvb, offset, 1, FALSE);

	proto_tree_add_item(AHead, hf_dect_A_Head_Q1, tvb, offset, 1, FALSE);
	proto_tree_add_item(AHead, hf_dect_A_Head_BA, tvb, offset, 1, FALSE);
	proto_tree_add_item(AHead, hf_dect_A_Head_Q2, tvb, offset, 1, FALSE);
	offset++;

	/* Tail */
	if(dect_packet_type==DECT_PACKET_FP)
	{
		atailti	= proto_tree_add_uint_format(afieldti, hf_dect_A_Tail, tvb, offset, 5, 0x2323, "FP-Tail: %s", val_to_str(tailtype, TA_vals_FP, "Error, please report: %d"));
	}
	else
	{
		atailti	= proto_tree_add_uint_format(afieldti, hf_dect_A_Tail, tvb, offset, 5, 0x2323, "PP-Tail: %s", val_to_str(tailtype, TA_vals_PP, "Error, please report: %d"));
	}

	ATail = proto_item_add_subtree(atailti, ett_atail);

	if((tailtype==0)||(tailtype==1))		/* Ct */
	{
		col_set_str(pinfo->cinfo, COL_INFO, "[Ct]");
	}
	else if((tailtype==2)||(tailtype==3))		/* Nt, Nt connectionless bearer */
	{
		col_set_str(pinfo->cinfo, COL_INFO, "[Nt]");
		if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
			col_append_fstr(pinfo->cinfo, COL_INFO /*Type2*/, "RFPI: %s",
				tvb_bytes_to_str(tvb, offset, 5));

		proto_tree_add_item(atailti, hf_dect_A_Tail_Nt, tvb, offset, 5, FALSE);
	}
	else if(tailtype==4)				/* Qt */
	{
		col_set_str(pinfo->cinfo, COL_INFO, "[Qt]");

		proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_Qh, tvb, offset, 1, FALSE);

		switch(tail_0>>4)
		{
		case 0:		/* Static System Info */
		case 1:
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Static System Info");

			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_0_Nr, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_0_Sn, tvb, offset, 1, FALSE);
			offset++;

			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_0_Sp, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_0_Esc, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_0_Txs, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_0_Mc, tvb, offset, 1, FALSE);
			offset++;

			proto_tree_add_uint_format(ATail, hf_dect_A_Tail_Mt_Mh, tvb, offset, 2, 0x2323, " Carrier%s%s%s%s%s%s%s%s%s%s available",
				(tail_1&0x02)?" 0":"", (tail_1&0x01)?" 1":"", (tail_2&0x80)?" 2":"",
				(tail_2&0x40)?" 3":"", (tail_2&0x20)?" 4":"", (tail_2&0x10)?" 5":"",
				(tail_2&0x08)?" 6":"", (tail_2&0x04)?" 7":"", (tail_2&0x02)?" 8":"",
				(tail_2&0x01)?" 9":"");
			offset++;

			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_0_Spr1, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_0_Cn, tvb, offset, 1, FALSE);
			offset++;

			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_0_Spr2, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_0_PSCN, tvb, offset, 1, FALSE);
			offset++;
			/* due to addition further down */
			offset-=5;
			break;
		case 2:		/* Extended RF Carriers Part 1 */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Extended RF Carriers Part 1");
			break;
		case 3:		/* Fixed Part Capabilities */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Fixed Part Capabilities");

			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A12, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A13, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A14, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A15, tvb, offset, 1, FALSE);
			offset++;

			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A16, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A17, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A18, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A19, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A20, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A21, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A22, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A23, tvb, offset, 1, FALSE);
			offset++;

			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A24, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A25, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A26, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A27, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A28, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A29, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A30, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A31, tvb, offset, 1, FALSE);
			offset++;


			/* higher layer capabilities */
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A32, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A33, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A34, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A35, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A36, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A37, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A38, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A39, tvb, offset, 1, FALSE);
			offset++;

			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A40, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A41, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A42, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A43, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A44, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A45, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A46, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_3_A47, tvb, offset, 1, FALSE);
			offset++;

			/* due to addition further down */
			offset-=5;
			break;
		case 4:		/* Extended Fixed Part Capabilities */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Extended Fixed Part Capabilities");

			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_CRFPHops, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_CRFPEnc, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_REFHops, tvb, offset, 2, FALSE);
			offset++;

			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_REPCap, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_Sync, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A20, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_MACSusp, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_MACIpq, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A23, tvb, offset, 1, FALSE);
			offset++;


			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A24, tvb, offset, 1, FALSE);

			/* higher layer capabilities */
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A25, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A26, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A27, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A28, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A29, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A30, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A31, tvb, offset, 1, FALSE);
			offset++;


			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A32, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A33, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A34, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A35, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A36, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A37, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A38, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A39, tvb, offset, 1, FALSE);
			offset++;

			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A40, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A41, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A42, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A43, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A44, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A45, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A46, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_4_A47, tvb, offset, 1, FALSE);
			offset++;

			/* due to addition further down */
			offset-=5;
			break;
		case 5:		/* SARI List Contents */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "SARI List Contents");
			break;
		case 6:		/* Multi-Frame No. */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Multi-Frame No.");

			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_6_Spare, tvb, offset, 2, FALSE);
			offset+=2;

			proto_tree_add_item(ATail, hf_dect_A_Tail_Qt_6_Mfn, tvb, offset, 3, FALSE);
			offset+=3;

			/* due to addition further down */
			offset-=5;
			break;
		case 7:		/* Escape */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Escape");
			break;
		case 8:		/* Obsolete */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Obsolete");
			break;
		case 9:		/* Extended RF Carriers Part 2 */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Extended RF Carriers Part 2");
			break;
		case 10:	/* Reserved(?) */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Reserved(?)");
			break;
		case 11:	/* Transmit Information(?) */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Transmit Information(?)");
			break;
		case 12:	/* Extended Fixed Part Capabilities 2 */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Extended Fixed Part Capabilities 2");
			break;
		case 13:
		case 14:
		case 15:
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Reserved");
			break;
		}
	}
	else if(tailtype==5)				/* Escape */
	{
	}
	else if((tailtype==6)||((tailtype==7)&&(dect_packet_type==DECT_PACKET_PP)))	/* Mt */
	{
		col_set_str(pinfo->cinfo, COL_INFO, "[Mt]");

		proto_tree_add_uint(ATail, hf_dect_A_Tail_Mt_Mh, tvb, offset, 1, tail_0);

		switch(tail_0>>4)
		{
		case 0:		/* Basic Connection Control */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Basic Connection Control");
			proto_tree_add_item(ATail, hf_dect_A_Tail_Mt_BasicConCtrl, tvb, offset, 1, FALSE);
			offset++;

			if(((tail_0 & 0x0f)==6)||((tail_0 & 0x0f)==7))
			{
				proto_tree_add_uint_format(ATail, hf_dect_A_Tail_Mt_Mh, tvb, offset, 4, 0x2323, "here should be attributes...");
				offset +=4;
			}
			else
			{
				proto_tree_add_item(ATail, hf_dect_A_Tail_Mt_Mh_fmid, tvb, offset, 2, FALSE);
				offset++;

				proto_tree_add_item(ATail, hf_dect_A_Tail_Mt_Mh_pmid, tvb, offset, 3, FALSE);
				offset+=3;
			}

			/* due to addition further down */
			offset-=5;
			break;
		case 1:		/* Advanced Connection Control */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Advanced Connection Control");
			break;
		case 2:		/* MAC Layer Test Messages */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "MAC Layer Test Messages");
			break;
		case 3:		/* Quality Control */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Quality Control");
			break;
		case 4:		/* Broadcast and Connectionless Services */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Broadcast and Connectionless Services");
			break;
		case 5:		/* Encryption Control */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Encryption Control");

			proto_tree_add_item(ATail, hf_dect_A_Tail_Mt_Encr_Cmd1, tvb, offset, 1, FALSE);
			proto_tree_add_item(ATail, hf_dect_A_Tail_Mt_Encr_Cmd2, tvb, offset, 1, FALSE);
			offset++;

			proto_tree_add_item(ATail, hf_dect_A_Tail_Mt_Mh_fmid, tvb, offset, 2, FALSE);
			offset++;

			proto_tree_add_item(ATail, hf_dect_A_Tail_Mt_Mh_pmid, tvb, offset, 3, FALSE);
			offset+=3;

			/* wegen addition weiter unten */
			offset-=5;
			break;
		case 6:		/* Tail for use with the first Transmission of a B-Field \"bearer request\" Message */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Tail for use with the first Transmission of a B-Field \"bearer request\" Message");
			break;
		case 7:		/* Escape */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Escape");
			break;
		case 8:		/* TARI Message */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "TARI Message");
			break;
		case 9:		/* REP Connection Control */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "REP Connection Control");
			break;
		case 10:	/* Reserved */
		case 11:
		case 12:
		case 13:
		case 14:
		case 15:
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Reserved");
			break;
		}
	}
	else if((tailtype==7)&&(dect_packet_type==DECT_PACKET_FP))	/* Pt */
	{
		col_set_str(pinfo->cinfo, COL_INFO, "[Pt]");

		proto_tree_add_item(ATail, hf_dect_A_Tail_Pt_ExtFlag, tvb, offset, 1, FALSE);
		proto_tree_add_item(ATail, hf_dect_A_Tail_Pt_SDU, tvb, offset, 1, FALSE);
		switch((tail_0&0x70)>>4)
		{
		case 0:		/* Zero Length Page */
		case 1:		/* Short Page */
			if(((tail_0&0x70)>>4)==0)
#if 0
XXX: Hier weitermachen
#endif
			{
				if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
					col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Zero Length Page: ");
				proto_tree_add_uint_format(atailti, hf_dect_A_Tail_Pt_InfoType, tvb, offset, 3, 0x2323, "RFPI:xxxxx%.1x%.2x%.2x", (pkt_afield->Tail[0]&0x0f), pkt_afield->Tail[1], pkt_afield->Tail[2]);
				offset+=3;

				proto_tree_add_item(ATail, hf_dect_A_Tail_Pt_InfoType, tvb, offset, 1, FALSE);
			}
			else
			{
				if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
					col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Short Page: ");
				proto_tree_add_uint_format(atailti, hf_dect_A_Tail_Pt_InfoType, tvb, offset, 3, 0x2323, "Bs Data:%.1x%.2x%.2x", (pkt_afield->Tail[0]&0x0f), pkt_afield->Tail[1], pkt_afield->Tail[2]);
				offset+=3;

				proto_tree_add_item(ATail, hf_dect_A_Tail_Pt_InfoType, tvb, offset, 1, FALSE);
			}
			switch(pkt_afield->Tail[3]>>4)
			{
			case 0: /* Fill Bits */
				proto_tree_add_uint_format(ATail, hf_dect_A_Tail_Pt_Fill_Fillbits, tvb, offset, 2, 0x2323, "Fillbits:%.1x%.2x", pkt_afield->Tail[3]&0x0f, pkt_afield->Tail[4]);
				offset+=2;
				break;
			case 1: /* Blind Full Slot Information for Circuit Mode Service */
			case 7: /* Escape */
			case 8: /* Dummy or connectionless Bearer Marker */
				proto_tree_add_uint_format(ATail, hf_dect_A_Tail_Pt_InfoType, tvb, offset, 2, 0x2323, " Slot-Pairs:%s%s%s%s%s%s%s%s%s%s%s%s available",
					(pkt_afield->Tail[3]&0x08)?" 0/12":"", (pkt_afield->Tail[3]&0x04)?" 1/13":"", (pkt_afield->Tail[3]&0x02)?" 2/14":"",
					(pkt_afield->Tail[3]&0x01)?" 3/15":"", (pkt_afield->Tail[4]&0x80)?" 4/16":"", (pkt_afield->Tail[4]&0x40)?" 5/17":"",
					(pkt_afield->Tail[4]&0x20)?" 6/18":"", (pkt_afield->Tail[4]&0x10)?" 7/19":"", (pkt_afield->Tail[4]&0x08)?" 8/20":"",
					(pkt_afield->Tail[4]&0x04)?" 9/21":"", (pkt_afield->Tail[4]&0x02)?" 10/22":"", (pkt_afield->Tail[4]&0x01)?" 11/23":"");

				offset+=2;
				break;
			case 2: /* Other Bearer */
			case 3: /* Recommended Other Bearer */
			case 4: /* Good RFP Bearer */
			case 5: /* Dummy or connectionless Bearer Position */
			case 12: /* Connectionless Bearer Position */
				proto_tree_add_item(ATail, hf_dect_A_Tail_Pt_Bearer_Sn, tvb, offset, 1, FALSE);
				offset++;

				proto_tree_add_item(ATail, hf_dect_A_Tail_Pt_Bearer_Sp, tvb, offset, 1, FALSE);
				proto_tree_add_item(ATail, hf_dect_A_Tail_Pt_Bearer_Cn, tvb, offset, 1, FALSE);
				offset++;
				break;
			case 6: /* Extended Modulation Types */
				offset+=2;
				break;

			case 9: /* Bearer Handover/Replacement Information */
				offset+=2;
				break;
			case 10: /* RFP Status and Modulation Types */
				offset+=2;
				break;
			case 11: /* Active Carriers */
				offset+=2;
				break;
			case 13: /* RFP Power Level */
				offset+=2;
				break;
			case 14: /* Blind Double Slot/RFP-FP Interface Resource Information */
				offset+=2;
				break;
			case 15: /* Blind Full Slot Information for Packet Mode Service */
				offset+=2;
				break;
			}
			/* due to addition further down */
			offset-=5;
			break;
		case 2:		/* Full Page */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Full Page: ");
			break;
		case 3:		/* MAC Resume Page */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "MAC Resume Page: ");
			break;
		case 4:		/* Not the Last 36 Bits of a Long Page */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "Not the Last 36 Bits: ");
			break;
		case 5:		/* The First 36 Bits of a Long Page */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "The First 36 Bits: ");
			break;
		case 6:		/* The Last 36 Bits of a Long Page */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "The Last 36 Bits: ");
			break;
		case 7:		/* All of a Long Page */
			if(check_col(pinfo->cinfo, COL_INFO /*Type2*/))
				col_append_str(pinfo->cinfo, COL_INFO /*Type2*/, "All of a Long Page: ");
			break;
		}
	}

	offset+=5;

	/* R-CRC */

	memcpy(rcrcdat, pkt_ptr, 6);
	rcrcdat[6]=0;
	rcrcdat[7]=0;
	rcrc=calc_rcrc(rcrcdat);
	if(rcrc!=pkt_afield->RCRC)
		proto_tree_add_uint_format(afieldti, hf_dect_A_RCRC, tvb, offset, 2, 0, "R-CRC Error (Calc:%.4x, Recv:%.4x)", rcrc, pkt_afield->RCRC);
	else
		proto_tree_add_uint_format(afieldti, hf_dect_A_RCRC, tvb, offset, 2, 1, "R-CRC Match (Calc:%.4x, Recv:%.4x)", rcrc, pkt_afield->RCRC);

	offset+=2;

	/* **************** B-Field ************************************/
	offset=dissect_bfield(dect_packet_type, header, pkt_bfield, pinfo, pkt_ptr, tvb, ti, DectTree, offset);
}

static void
dissect_dect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint16			type;
	guint			pkt_len;
	const guint8		*pkt_ptr;
	struct dect_afield	pkt_afield;
	struct dect_bfield	pkt_bfield;

	/* Packetpointer */
	pkt_len=tvb_length(tvb);

	if(pkt_len>140)
			pkt_len=140;

	if(pkt_len<13)
	{
		if(check_col(pinfo->cinfo, COL_PROTOCOL))
		{
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "No Data");
		}
		return;
	}

	pkt_ptr=tvb_get_ptr(tvb, 11, pkt_len-11);

	/* fill A-Field */
	pkt_afield.Header=pkt_ptr[0];
	memcpy((char*)(&(pkt_afield.Tail)), (char*)(pkt_ptr+1), 5);
	pkt_afield.RCRC=(((guint16)pkt_ptr[6])<<8)|pkt_ptr[7];


	/* fill B-Field */
	if(pkt_len>13)
		memcpy((char*)(&(pkt_bfield.Data)), (char*)(pkt_ptr+8), pkt_len-5-8);
	else
		memset((char*)(&(pkt_bfield.Data)), 0, 128);
	pkt_bfield.Length=pkt_len-13;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DECT");

	/* Clear out stuff in the info column */
	if(check_col(pinfo->cinfo, COL_INFO))
	{
		col_clear(pinfo->cinfo, COL_INFO);
	}
	if(tree)
	{
		proto_item *ti		=NULL;
		proto_item *typeti	=NULL;
		proto_tree *DectTree	=NULL;
		gint offset		=0;

		ti=proto_tree_add_item(tree, proto_dect, tvb, 0, -1, FALSE);

		DectTree=proto_item_add_subtree(ti, ett_dect);
		proto_tree_add_item(DectTree, hf_dect_transceivermode, tvb, offset, 1, FALSE);
		offset++;

		proto_tree_add_item(DectTree, hf_dect_channel, tvb, offset, 1, FALSE);
		offset++;

		proto_tree_add_item(DectTree, hf_dect_slot, tvb, offset, 2, FALSE);
		offset+=2;

		proto_tree_add_item(DectTree, hf_dect_framenumber, tvb, offset, 1, FALSE);
		offset++;

		proto_tree_add_item(DectTree, hf_dect_rssi, tvb, offset, 1, FALSE);
		offset++;

		proto_tree_add_item(DectTree, hf_dect_preamble, tvb, offset, 3, FALSE);
		offset+=3;

		typeti=proto_tree_add_item(DectTree, hf_dect_type, tvb, offset, 2, FALSE);

		type=tvb_get_ntohs(tvb, offset);
		offset+=2;

		switch(type) {
		case 0x1675:
			if(check_col(pinfo->cinfo, COL_PROTOCOL))
			{
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "DECT PP");
			}
			proto_item_append_text(typeti, " Phone Packet");
			dissect_decttype(DECT_PACKET_PP, &pkt_afield, &pkt_bfield, pinfo, pkt_ptr, tvb, ti, DectTree);
			break;
		case 0xe98a:
			if(check_col(pinfo->cinfo, COL_PROTOCOL))
			{
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "DECT RFP");
			}
			proto_item_append_text(typeti, " Station Packet");
			dissect_decttype(DECT_PACKET_FP, &pkt_afield, &pkt_bfield, pinfo, pkt_ptr, tvb, ti, DectTree);
			break;
		default:
			if(check_col(pinfo->cinfo, COL_PROTOCOL))
			{
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "DECT Unk");
			}
			proto_item_append_text(typeti, " Unknown Packet");
			break;
		}
	}
}

void
proto_register_dect(void)
{
	static hf_register_info hf[]=
	{
		{ &hf_dect_transceivermode,
		{"Tranceiver-Mode", "dect.tranceivermode", FT_UINT8, BASE_HEX, VALS(tranceiver_mode),
			0x0, NULL, HFILL}},

		{ &hf_dect_channel,
		{"Channel", "dect.channel", FT_UINT8, BASE_DEC, NULL,
			0x0, NULL, HFILL}},

		{ &hf_dect_framenumber,
		{"Frame#", "dect.framenumber", FT_UINT16, BASE_DEC, NULL,
			0x0, NULL, HFILL}},

		{ &hf_dect_rssi,
		{"RSSI", "dect.rssi", FT_UINT8, BASE_DEC, NULL,
			0x0, NULL, HFILL}},

		{ &hf_dect_slot,
		{"Slot", "dect.slot", FT_UINT16, BASE_DEC, NULL,
			0x0, NULL, HFILL}},

		{ &hf_dect_preamble,
		{"Preamble", "dect.preamble", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL}},

		{ &hf_dect_type,
		{"Packet-Type", "dect.type", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL}},

	/* **************** A-Field ******************************/
	/* ***** Header ***** */
		{ &hf_dect_A,
		{"A-Field", "dect.afield", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL}},

		{ &hf_dect_A_Head,
		{"A-Field Header", "dect.afield.head", FT_UINT8, BASE_HEX, NULL,
			0x0, NULL, HFILL}},

		{ &hf_dect_A_Head_TA_FP,
		{"TA", "dect.afield.head.TA", FT_UINT8, BASE_DEC, VALS(TA_vals_FP),
			0xE0, NULL, HFILL}},

		{ &hf_dect_A_Head_TA_PP,
		{"TA", "dect.afield.head.TA", FT_UINT8, BASE_DEC, VALS(TA_vals_PP),
			0xE0, NULL, HFILL}},

		{ &hf_dect_A_Head_Q1,
		{"Q1", "dect.afield.head.Q1", FT_UINT8, BASE_DEC, NULL,
			0x10, NULL, HFILL}},

		{ &hf_dect_A_Head_BA,
		{"BA", "dect.afield.head.BA", FT_UINT8, BASE_DEC, VALS(BA_vals),
			0x0E, NULL, HFILL}},

		{ &hf_dect_A_Head_Q2,
		{"Q2", "dect.afield.head.Q2", FT_UINT8, BASE_DEC, NULL,
			0x01, NULL, HFILL}},

	/* ***** Tail ***** */
		{ &hf_dect_A_Tail,
		{"A-Field Tail", "dect.afield.tail", FT_UINT8, BASE_DEC, NULL,
			0xE0, NULL, HFILL}},

	/* Nt */
		{ &hf_dect_A_Tail_Nt,
		{"Nt/RFPI", "dect.afield.tail.Nt", FT_BYTES, BASE_NONE, NULL,
			0x0, "A-Field Tail: Nt/RFPI", HFILL}},

	/* Qt */
		{ &hf_dect_A_Tail_Qt_Qh,
		{"Qh", "dect.afield.tail.Qt.Qh", FT_UINT8, BASE_DEC, VALS(QTHead_vals),
			0xF0, NULL, HFILL}},

	/* Qt Static System Information */
	/* Byte 0 */
		{ &hf_dect_A_Tail_Qt_0_Nr,
		{"NR", "dect.afield.tail.Qt.NR", FT_UINT8, BASE_DEC, VALS(QTNormalReverse_vals),
			0x10, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_0_Sn,
		{"SN", "dect.afield.tail.Qt.SN", FT_UINT8, BASE_DEC, VALS(QTSlotNumber_vals),
			0x0F, NULL, HFILL}},

	/* Byte 1 */
		{ &hf_dect_A_Tail_Qt_0_Sp,
		{"SP", "dect.afield.tail.Qt.SP", FT_UINT8, BASE_DEC, VALS(QTStartPosition_vals),
			0xC0, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_0_Esc,
		{"Esc", "dect.afield.tail.Qt.Esc", FT_UINT8, BASE_DEC, VALS(QTEscape_vals),
			0x20, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_0_Txs,
		{"Txs", "dect.afield.tail.Qt.Txs", FT_UINT8, BASE_DEC, VALS(QTTranceiver_vals),
			0x18, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_0_Mc,
		{"Mc", "dect.afield.tail.Qt.Mc", FT_UINT8, BASE_DEC, VALS(QTExtendedCarrier_vals),
			0x04, NULL, HFILL}},

	/* Byte 3 */
		{ &hf_dect_A_Tail_Qt_0_Spr1,
		{"Spr", "dect.afield.tail.Qt.Spr1", FT_UINT8, BASE_DEC, VALS(QTSpr_vals),
			0xC0, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_0_Cn,
		{"CN", "dect.afield.tail.Qt.CN", FT_UINT8, BASE_DEC, VALS(QTCarrierNumber_vals),
			0x3F, NULL, HFILL}},

	/* Byte 4 */
		{ &hf_dect_A_Tail_Qt_0_Spr2,
		{"Spr", "dect.afield.tail.Qt.Spr2", FT_UINT8, BASE_DEC, VALS(QTSpr_vals),
			0xC0, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_0_PSCN,
		{"PSCN", "dect.afield.tail.Qt.PSCN", FT_UINT8, BASE_DEC, VALS(QTScanCarrierNum_vals),
			0x3F, NULL, HFILL}},

	/* Qt Fixed Part Capabilities */
		{ &hf_dect_A_Tail_Qt_3_A12,
		{"A12", "dect.afield.tail.Qt.Fp.A12", FT_UINT8, BASE_DEC, VALS(Qt_A12_vals),
			0x08, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A13,
		{"A13", "dect.afield.tail.Qt.Fp.A13", FT_UINT8, BASE_DEC, VALS(Qt_A13_vals),
			0x04, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A14,
		{"A14", "dect.afield.tail.Qt.Fp.A14", FT_UINT8, BASE_DEC, VALS(Qt_A14_vals),
			0x02, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A15,
		{"A15", "dect.afield.tail.Qt.Fp.A15", FT_UINT8, BASE_DEC, VALS(Qt_A15_vals),
			0x01, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A16,
		{"A16", "dect.afield.tail.Qt.Fp.A16", FT_UINT8, BASE_DEC, VALS(Qt_A16_vals),
			0x80, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A17,
		{"A17", "dect.afield.tail.Qt.Fp.A17", FT_UINT8, BASE_DEC, VALS(Qt_A17_vals),
			0x40, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A18,
		{"A18", "dect.afield.tail.Qt.Fp.A18", FT_UINT8, BASE_DEC, VALS(Qt_A18_vals),
			0x20, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A19,
		{"A19", "dect.afield.tail.Qt.Fp.A19", FT_UINT8, BASE_DEC, VALS(Qt_A19_vals),
			0x10, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A20,
		{"A20", "dect.afield.tail.Qt.Fp.A20", FT_UINT8, BASE_DEC, VALS(Qt_A20_vals),
			0x08, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A21,
		{"A21", "dect.afield.tail.Qt.Fp.A21", FT_UINT8, BASE_DEC, VALS(Qt_A21_vals),
			0x04, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A22,
		{"A22", "dect.afield.tail.Qt.Fp.A22", FT_UINT8, BASE_DEC, VALS(Qt_A22_vals),
			0x02, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A23,
		{"A23", "dect.afield.tail.Qt.Fp.A23", FT_UINT8, BASE_DEC, VALS(Qt_A23_vals),
			0x01, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A24,
		{"A24", "dect.afield.tail.Qt.Fp.A24", FT_UINT8, BASE_DEC, VALS(Qt_A24_vals),
			0x80, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A25,
		{"A25", "dect.afield.tail.Qt.Fp.A25", FT_UINT8, BASE_DEC, VALS(Qt_A25_vals),
			0x40, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A26,
		{"A26", "dect.afield.tail.Qt.Fp.A26", FT_UINT8, BASE_DEC, VALS(Qt_A26_vals),
			0x20, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A27,
		{"A27", "dect.afield.tail.Qt.Fp.A27", FT_UINT8, BASE_DEC, VALS(Qt_A27_vals),
			0x10, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A28,
		{"A28", "dect.afield.tail.Qt.Fp.A28", FT_UINT8, BASE_DEC, VALS(Qt_A28_vals),
			0x08, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A29,
		{"A29", "dect.afield.tail.Qt.Fp.A29", FT_UINT8, BASE_DEC, VALS(Qt_A29_vals),
			0x04, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A30,
		{"A30", "dect.afield.tail.Qt.Fp.A30", FT_UINT8, BASE_DEC, VALS(Qt_A30_vals),
			0x02, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A31,
		{"A31", "dect.afield.tail.Qt.Fp.A31", FT_UINT8, BASE_DEC, VALS(Qt_A31_vals),
			0x01, NULL, HFILL}},


		/* higher layer capabilities */
		{ &hf_dect_A_Tail_Qt_3_A32,
		{"A32", "dect.afield.tail.Qt.Fp.A32", FT_UINT8, BASE_DEC, VALS(Qt_A32_vals),
			0x80, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A33,
		{"A33", "dect.afield.tail.Qt.Fp.A33", FT_UINT8, BASE_DEC, VALS(Qt_A33_vals),
			0x40, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A34,
		{"A34", "dect.afield.tail.Qt.Fp.A34", FT_UINT8, BASE_DEC, VALS(Qt_A34_vals),
			0x20, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A35,
		{"A35", "dect.afield.tail.Qt.Fp.A35", FT_UINT8, BASE_DEC, VALS(Qt_A35_vals),
			0x10, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A36,
		{"A36", "dect.afield.tail.Qt.Fp.A36", FT_UINT8, BASE_DEC, VALS(Qt_A36_vals),
			0x08, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A37,
		{"A37", "dect.afield.tail.Qt.Fp.A37", FT_UINT8, BASE_DEC, VALS(Qt_A37_vals),
			0x04, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A38,
		{"A38", "dect.afield.tail.Qt.Fp.A38", FT_UINT8, BASE_DEC, VALS(Qt_A38_vals),
			0x02, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A39,
		{"A39", "dect.afield.tail.Qt.Fp.A39", FT_UINT8, BASE_DEC, VALS(Qt_A39_vals),
			0x01, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A40,
		{"A40", "dect.afield.tail.Qt.Fp.A40", FT_UINT8, BASE_DEC, VALS(Qt_A40_vals),
			0x80, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A41,
		{"A41", "dect.afield.tail.Qt.Fp.A41", FT_UINT8, BASE_DEC, VALS(Qt_A41_vals),
			0x40, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A42,
		{"A42", "dect.afield.tail.Qt.Fp.A42", FT_UINT8, BASE_DEC, VALS(Qt_A42_vals),
			0x20, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A43,
		{"A43", "dect.afield.tail.Qt.Fp.A43", FT_UINT8, BASE_DEC, VALS(Qt_A43_vals),
			0x10, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A44,
		{"A44", "dect.afield.tail.Qt.Fp.A44", FT_UINT8, BASE_DEC, VALS(Qt_A44_vals),
			0x08, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A45,
		{"A45", "dect.afield.tail.Qt.Fp.A45", FT_UINT8, BASE_DEC, VALS(Qt_A45_vals),
			0x04, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A46,
		{"A46", "dect.afield.tail.Qt.Fp.A46", FT_UINT8, BASE_DEC, VALS(Qt_A46_vals),
			0x02, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_3_A47,
		{"A47", "dect.afield.tail.Qt.Fp.A47", FT_UINT8, BASE_DEC, VALS(Qt_A47_vals),
			0x01, NULL, HFILL}},

	/* Qt Extended Fixed Part Capabilities */

		{ &hf_dect_A_Tail_Qt_4_CRFPHops,
		{"CRFP Hops", "dect.afield.tail.Qt.Efp.CRFPHops", FT_UINT8, BASE_DEC, VALS(Qt_CRFPHops_vals),
			0x0C, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_CRFPEnc,
		{"CRFP Enc", "dect.afield.tail.Qt.Efp.CRFPEnc", FT_UINT8, BASE_DEC, VALS(Qt_CRFPEnc_vals),
			0x02, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_REFHops,
		{"REP Hops", "dect.afield.tail.Qt.Efp.REPHops", FT_UINT16, BASE_DEC, VALS(Qt_REPHops_vals),
			0x0180, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_REPCap,
		{"REP Cap.", "dect.afield.tail.Qt.Efp.REPCap", FT_UINT8, BASE_DEC, VALS(Qt_REPCap_vals),
			0x40, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_Sync,
		{"Sync", "dect.afield.tail.Qt.Efp.Sync", FT_UINT8, BASE_DEC, VALS(Qt_Sync_vals),
			0x30, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A20,
		{"A20", "dect.afield.tail.Qt.Efp.A20", FT_UINT8, BASE_DEC, VALS(Qt_EA20_vals),
			0x08, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_MACSusp,
		{"MAC Suspend", "dect.afield.tail.Qt.Efp.MACSusp", FT_UINT8, BASE_DEC, VALS(Qt_MACSusp_vals),
			0x04, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_MACIpq,
		{"MAC Ipq", "dect.afield.tail.Qt.Efp.MACIpq", FT_UINT8, BASE_DEC, VALS(Qt_MACIpq_vals),
			0x02, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A23,
		{"A23", "dect.afield.tail.Qt.Efp.A23", FT_UINT8, BASE_DEC, VALS(Qt_EA23_vals),
			0x01, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A24,
		{"A24", "dect.afield.tail.Qt.Efp.A24", FT_UINT8, BASE_DEC, VALS(Qt_EA24_vals),
			0x80, NULL, HFILL}},


		/* Higher Layer Capabilities */

		{ &hf_dect_A_Tail_Qt_4_A25,
		{"A25", "dect.afield.tail.Qt.Efp.A25", FT_UINT8, BASE_DEC, VALS(Qt_EA25_vals),
			0x40, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A26,
		{"A26", "dect.afield.tail.Qt.Efp.A26", FT_UINT8, BASE_DEC, VALS(Qt_EA26_vals),
			0x20, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A27,
		{"A27", "dect.afield.tail.Qt.Efp.A27", FT_UINT8, BASE_DEC, VALS(Qt_EA27_vals),
			0x10, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A28,
		{"A28", "dect.afield.tail.Qt.Efp.A28", FT_UINT8, BASE_DEC, VALS(Qt_EA28_vals),
			0x08, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A29,
		{"A29", "dect.afield.tail.Qt.Efp.A29", FT_UINT8, BASE_DEC, VALS(Qt_EA29_vals),
			0x04, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A30,
		{"A30", "dect.afield.tail.Qt.Efp.A30", FT_UINT8, BASE_DEC, VALS(Qt_EA30_vals),
			0x02, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A31,
		{"A31", "dect.afield.tail.Qt.Efp.A31", FT_UINT8, BASE_DEC, VALS(Qt_EA31_vals),
			0x01, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A32,
		{"A32", "dect.afield.tail.Qt.Efp.A32", FT_UINT8, BASE_DEC, VALS(Qt_EA32_vals),
			0x80, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A33,
		{"A33", "dect.afield.tail.Qt.Efp.A33", FT_UINT8, BASE_DEC, VALS(Qt_EA33_vals),
			0x40, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A34,
		{"A34", "dect.afield.tail.Qt.Efp.A34", FT_UINT8, BASE_DEC, VALS(Qt_EA34_vals),
			0x20, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A35,
		{"A35", "dect.afield.tail.Qt.Efp.A35", FT_UINT8, BASE_DEC, VALS(Qt_EA35_vals),
			0x10, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A36,
		{"A36", "dect.afield.tail.Qt.Efp.A36", FT_UINT8, BASE_DEC, VALS(Qt_EA36_vals),
			0x08, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A37,
		{"A37", "dect.afield.tail.Qt.Efp.A37", FT_UINT8, BASE_DEC, VALS(Qt_EA37_vals),
			0x04, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A38,
		{"A38", "dect.afield.tail.Qt.Efp.A38", FT_UINT8, BASE_DEC, VALS(Qt_EA38_vals),
			0x02, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A39,
		{"A39", "dect.afield.tail.Qt.Efp.A39", FT_UINT8, BASE_DEC, VALS(Qt_EA39_vals),
			0x01, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A40,
		{"A40", "dect.afield.tail.Qt.Efp.A40", FT_UINT8, BASE_DEC, VALS(Qt_EA40_vals),
			0x80, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A41,
		{"A41", "dect.afield.tail.Qt.Efp.A41", FT_UINT8, BASE_DEC, VALS(Qt_EA41_vals),
			0x40, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A42,
		{"A42", "dect.afield.tail.Qt.Efp.A42", FT_UINT8, BASE_DEC, VALS(Qt_EA42_vals),
			0x20, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A43,
		{"A43", "dect.afield.tail.Qt.Efp.A43", FT_UINT8, BASE_DEC, VALS(Qt_EA43_vals),
			0x10, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A44,
		{"A44", "dect.afield.tail.Qt.Efp.A44", FT_UINT8, BASE_DEC, VALS(Qt_EA44_vals),
			0x08, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A45,
		{"A45", "dect.afield.tail.Qt.Efp.A45", FT_UINT8, BASE_DEC, VALS(Qt_EA45_vals),
			0x04, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A46,
		{"A46", "dect.afield.tail.Qt.Efp.A46", FT_UINT8, BASE_DEC, VALS(Qt_EA46_vals),
			0x02, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_4_A47,
		{"A47", "dect.afield.tail.Qt.Efp.A47", FT_UINT8, BASE_DEC, VALS(Qt_EA47_vals),
			0x01, NULL, HFILL}},


	/* Qt Multiframe  Number */
		{ &hf_dect_A_Tail_Qt_6_Spare,
		{"Spare Bits", "dect.afield.tail.Qt.Mfn.Spare", FT_UINT16, BASE_HEX, NULL,
			0x0FFF, NULL, HFILL}},

		{ &hf_dect_A_Tail_Qt_6_Mfn,
		{"Multiframe Number", "dect.afield.tail.Qt.Mfn.Mfn", FT_BYTES, BASE_NONE, NULL,
			0, NULL, HFILL}},


	/* Mt */
		{ &hf_dect_A_Tail_Mt_Mh,
		{"Mh", "dect.afield.tail.Mt.Mh", FT_UINT8, BASE_DEC, VALS(MTHead_vals),
			0xF0, NULL, HFILL}},

		{ &hf_dect_A_Tail_Mt_Mh_fmid,
		{"Mh/FMID", "dect.afield.tail.Mt.Mh.fmid", FT_UINT16, BASE_HEX, NULL,
			0x0FF0, NULL, HFILL}},

		{ &hf_dect_A_Tail_Mt_Mh_pmid,
		{"Mh/PMID", "dect.afield.tail.Mt.Mh.pmid", FT_UINT24, BASE_HEX, NULL,
			0x0FFFFF, NULL, HFILL}},

	/* Mt Basic Connection Control */
		{ &hf_dect_A_Tail_Mt_BasicConCtrl,
		{"Cmd", "dect.afield.tail.Mt.BasicConCtrl", FT_UINT8, BASE_DEC, VALS(MTBasicConCtrl_vals),
			0x0F, NULL, HFILL}},

	/* Mt Encryption Control */
		{ &hf_dect_A_Tail_Mt_Encr_Cmd1,
		{"Cmd1", "dect.afield.tail.Mt.Encr.Cmd1", FT_UINT8, BASE_DEC, VALS(MTEncrCmd1_vals),
			0x0C, NULL, HFILL}},

		{ &hf_dect_A_Tail_Mt_Encr_Cmd2,
		{"Cmd2", "dect.afield.tail.Mt.Encr.Cmd2", FT_UINT8, BASE_DEC, VALS(MTEncrCmd2_vals),
			0x03, NULL, HFILL}},

	/* Pt */
		{ &hf_dect_A_Tail_Pt_ExtFlag,
		{"ExtFlag", "dect.afield.tail.Pt.ExtFlag", FT_UINT8, BASE_DEC, VALS(PTExtFlag_vals),
			0x80, NULL, HFILL}},

		{ &hf_dect_A_Tail_Pt_SDU,
		{"SDU", "dect.afield.tail.Pt.SDU", FT_UINT8, BASE_DEC, VALS(PTSDU_vals),
			0x70, NULL, HFILL}},

		{ &hf_dect_A_Tail_Pt_InfoType,
		{"InfoType", "dect.afield.tail.Pt.InfoType", FT_UINT8, BASE_DEC, VALS(PTInfoType_vals),
			0xF0, NULL, HFILL}},

		{ &hf_dect_A_Tail_Pt_Fill_Fillbits,
		{"FillBits", "dect.afield.tail.Pt.InfoType.FillBits", FT_UINT8, BASE_DEC, NULL,
			0x0, NULL, HFILL}},

		{ &hf_dect_A_Tail_Pt_Bearer_Sn,
		{"SN", "dect.afield.tail.Pt.SN", FT_UINT8, BASE_DEC, VALS(QTSlotNumber_vals),
			0x0F, NULL, HFILL}},

		{ &hf_dect_A_Tail_Pt_Bearer_Sp,
		{"SP", "dect.afield.tail.Pt.SP", FT_UINT8, BASE_DEC, VALS(QTStartPosition_vals),
			0xC0, NULL, HFILL}},

		{ &hf_dect_A_Tail_Pt_Bearer_Cn,
		{"CN", "dect.afield.tail.Pt.CN", FT_UINT8, BASE_DEC, VALS(QTCarrierNumber_vals),
			0x3F, NULL, HFILL}},

	/* ***** R-CRC ***** */
		{ &hf_dect_A_RCRC,
		{"A-Field R-CRC", "dect.afield.rcrc", FT_UINT8, BASE_DEC, NULL,
			0x0, NULL, HFILL}},

	/* ***************** B-Field *************************** */
		{ &hf_dect_B,
		{"B-Field", "dect.bfield", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL}},

		{ &hf_dect_B_Data,
		{"B-Field", "dect.bfield.data", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL}},

		{ &hf_dect_B_fn,
		{"B-Field", "dect.bfield.framenumber", FT_NONE, BASE_NONE, NULL,
			0x0, NULL, HFILL}},

	/* ***** X-CRC ***** */
		{ &hf_dect_B_XCRC,
		{"B-Field X-CRC", "dect.bfield.xcrc", FT_UINT8, BASE_DEC, NULL,
			0x0, NULL, HFILL}}
	};


	/* Setup protocol subtree array */
	static gint *ett[]=
	{
		&ett_dect,
		&ett_ahead,
		&ett_afield,
		&ett_atail,
		&ett_aqt,
		&ett_bfield
	};

	proto_dect=proto_register_protocol("DECT Protocol", "DECT", "dect");
	proto_register_field_array(proto_dect, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dect(void)
{
	dissector_handle_t dect_handle;

	dect_handle = create_dissector_handle(dissect_dect, proto_dect);
	dissector_add("ethertype", ETHERTYPE_DECT , dect_handle);
}

