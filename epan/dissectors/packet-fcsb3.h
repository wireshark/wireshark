/* packet-fc-sb3.h
 * Routines for Fibre Channel Single Byte Protocol (SBCCS); used in FICON.
 * This decoder is for FC-SB3 version 1.4 
 * Copyright 2003 Dinesh G Dutt (ddutt@cisco.com)
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

#ifndef __PACKET_FCSB3_H_
#define __PACKET_FCSB3_H_

/* SB-3 IU Types */
#define FC_SBCCS_IU_DATA          0x0
#define FC_SBCCS_IU_CMD_HDR       0x1
#define FC_SBCCS_IU_STATUS        0x2
#define FC_SBCCS_IU_CTL           0x3
#define FC_SBCCS_IU_CMD_DATA      0x4
#define FC_SBCCS_IU_CMD_LINK_CTL  0x5

/* Control Function Types */
#define FC_SBCCS_CTL_FN_CTL_END     0x0
#define FC_SBCCS_CTL_FN_CMD_RSP     0x10
#define FC_SBCCS_CTL_FN_STK_STS     0x20
#define FC_SBCCS_CTL_FN_CANCEL      0x30
#define FC_SBCCS_CTL_FN_SYS_RST     0x40
#define FC_SBCCS_CTL_FN_SEL_RST     0x50
#define FC_SBCCS_CTL_FN_REQ_STS     0x70
#define FC_SBCCS_CTL_FN_DEV_XCP     0x80
#define FC_SBCCS_CTL_FN_STS_ACC     0xA0
#define FC_SBCCS_CTL_FN_DEV_ACK     0xB0
#define FC_SBCCS_CTL_FN_PRG_PTH     0xC1
#define FC_SBCCS_CTL_FN_PRG_RSP     0xD0

/* Link Control Function Types */
#define FC_SBCCS_LINK_CTL_FN_ELP     0x41
#define FC_SBCCS_LINK_CTL_FN_RLP     0x49
#define FC_SBCCS_LINK_CTL_FN_TIN     0x09
#define FC_SBCCS_LINK_CTL_FN_LPE     0x51
#define FC_SBCCS_LINK_CTL_FN_LPR     0x59
#define FC_SBCCS_LINK_CTL_FN_TIR     0x01
#define FC_SBCCS_LINK_CTL_FN_LRJ     0x11
#define FC_SBCCS_LINK_CTL_FN_LBY     0x21
#define FC_SBCCS_LINK_CTL_FN_LACK    0x61

#define FC_SBCCS_SB3_HDR_SIZE        8
#define FC_SBCCS_IU_HDR_SIZE         8
#define FC_SBCCS_DIB_LRC_HDR_SIZE    16

/* Decodes the DIB Type from the IU header and returns type */
static inline guint get_fc_sbccs_iu_type (tvbuff_t *tvb, guint offset)
{
    /* This is in the IUI field of the IU header */
    return (tvb_get_guint8 (tvb, offset+FC_SBCCS_SB3_HDR_SIZE) & 0x7);
}

#endif
