/* packet-fclctl.h
 * Fibre Channel Link Control definitions
 * Copyright 2001 Dinesh G Dutt (ddutt@cisco.com)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_FCLCTL_H_
#define __PACKET_FCLCTL_H_

#define FC_LCTL_ACK1      0x00
#define FC_LCTL_ACK0      0x01
#define FC_LCTL_PRJT      0x02
#define FC_LCTL_FRJT      0x03
#define FC_LCTL_PBSY      0x04
#define FC_LCTL_FBSYL     0x05
#define FC_LCTL_FBSYB     0x06
#define FC_LCTL_LCR       0x07
#define FC_LCTL_NTY       0x08
#define FC_LCTL_END       0x09

extern const value_string fc_lctl_proto_val[];

#define FC_LCTL_FBSY_FBSY  0x01
#define FC_LCTL_FBSY_NBSY  0x03

#define FC_LCTL_PBSY_ACODE_SEQBSY 0x01
#define FC_LCTL_PBSY_ACODE_C2BSY  0x02

#define FC_LCTL_PBSY_PORTBSY      0x01
#define FC_LCTL_PBSY_RSRCBSY      0x03
#define FC_LCTL_PBSY_MCASTBSY     0x07
#define FC_LCTL_PBSY_VENDBSY      0xFF

#define FC_LCTL_RJT_ACODE_RETRY   0x01
#define FC_LCTL_RJT_ACODE_NORETRY 0x02

#define FC_LCTL_RJT_INVDID                 0x01
#define FC_LCTL_RJT_INVSID                 0x02
#define FC_LCTL_RJT_NPORT_NOTAVAIL_T       0x03
#define FC_LCTL_RJT_NPORT_NOTAVAIL_P       0x04
#define FC_LCTL_RJT_CLASS_NOTSUPP          0x05
#define FC_LCTL_RJT_DELIM_USERR            0x06
#define FC_LCTL_RJT_TYPE_NOTSUPP           0x07
#define FC_LCTL_RJT_INV_LCTL               0x08
#define FC_LCTL_RJT_INV_RCTL               0x09
#define FC_LCTL_RJT_INV_FCTL               0x0A
#define FC_LCTL_RJT_INV_OXID               0x0B
#define FC_LCTL_RJT_INV_RXID               0x0C
#define FC_LCTL_RJT_INV_SEQID              0x0D
#define FC_LCTL_RJT_INV_DFCTL              0x0E
#define FC_LCTL_RJT_INV_SEQCNT             0x0F
#define FC_LCTL_RJT_INV_PARAM              0x10
#define FC_LCTL_RJT_EXCHG_ERR              0x11
#define FC_LCTL_RJT_PROTO_ERR              0x12
#define FC_LCTL_RJT_INV_LEN                0x13
#define FC_LCTL_RJT_UNEXP_ACK              0x14
#define FC_LCTL_RJT_CLS_NOTSUPP            0x15
#define FC_LCTL_RJT_LOGI_REQD              0x16
#define FC_LCTL_RJT_TOOMANY_SEQ            0x17
#define FC_LCTL_RJT_EXCHG_NOTESTD          0x18
#define FC_LCTL_RJT_RSVD                   0x19
#define FC_LCTL_RJT_FPATH_NOTAVAIL         0x1A
#define FC_LCTL_RJT_INV_VCID               0x1B
#define FC_LCTL_RJT_INV_CSCTL              0x1C
#define FC_LCTL_RJT_OORSRC                 0x1D
#define FC_LCTL_RJT_INV_CLASS              0x1F
#define FC_LCTL_RJT_PRMPT_RJT              0x20
#define FC_LCTL_RJT_PRMPT_DIS              0x21
#define FC_LCTL_RJT_MCAST_ERR              0x22
#define FC_LCTL_RJT_MCAST_TERM             0x23
#define FC_LCTL_RJT_PRLI_REQD              0x24
#define FC_LCTL_RJT_VEND_ERR               0xFF

/* Function definitions */
const gchar *fclctl_get_typestr (guint8 linkctl_type, guint8 type);
const gchar *fclctl_get_paramstr (guint32 linkctl_type, guint32 param);
#endif
