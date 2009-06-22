/* packet-cfm.h
 * Value declarations for CFM EOAM (IEEE 802.1ag) dissection
 * Copyright 2007, Keith Mercer <keith.mercer@alcatel-lucent.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __PACKET_CFM_H__
#define __PACKET_CFM_H__

#define IEEE8021 0x00
#define CCM 0x01
#define LBR 0x02
#define LBM 0x03
#define LTR 0x04
#define LTM 0X05

#define AIS 0x21
#define LCK 0x23
#define TST 0x25
#define APS 0x27
#define MCC 0x29
#define LMM 0x2B
#define LMR 0x2A
#define ODM 0x2D
#define DMM 0x2F
#define DMR 0x2E
#define EXM 0x31
#define EXR 0x30
#define VSM 0x33
#define VSR 0x32

#define END_TLV 	0x00
#define SENDER_ID_TLV	0x01
#define PORT_STAT_TLV	0x02
#define DATA_TLV	0x03
#define INTERF_STAT_TLV	0x04
#define REPLY_ING_TLV	0x05
#define REPLY_EGR_TLV	0x06
#define LTM_EGR_ID_TLV	0x07
#define LTR_EGR_ID_TLV	0x08
#define ORG_SPEC_TLV	0x1F
#define TEST_TLV        0x20

#endif
