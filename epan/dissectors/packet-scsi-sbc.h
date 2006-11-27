/* packet-scsi-sbc.h
 * Dissector for the SCSI SBC commandset
 * Extracted from packet-scsi.h
 *
 * Dinesh G Dutt (ddutt@cisco.com)
 * Ronnie sahlberg 2006
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2002 Gerald Combs
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

#ifndef __PACKET_SCSI_SBC_H_
#define __PACKET_SCSI_SBC_H_

/* SBC Commands */
#define SCSI_SBC2_FORMATUNIT             0x04
#define SCSI_SBC2_LOCKUNLKCACHE10        0x36
#define SCSI_SBC2_LOCKUNLKCACHE16        0x92
#define SCSI_SBC2_PREFETCH10             0x34
#define SCSI_SBC2_PREFETCH16             0x90
#define SCSI_SBC2_READ6                  0x08
#define SCSI_SBC2_READ10                 0x28
#define SCSI_SBC2_READ12                 0xA8
#define SCSI_SBC2_READ16                 0x88
#define SCSI_SBC2_READCAPACITY10         0x25
#define SCSI_SBC2_SERVICEACTIONIN16      0x9E
#define SCSI_SBC2_READDEFDATA10          0x37
#define SCSI_SBC2_READDEFDATA12          0xB7
#define SCSI_SBC2_READLONG               0x3E
#define SCSI_SBC2_REASSIGNBLKS           0x07
#define SCSI_SBC2_REBUILD16              0x81
#define SCSI_SBC2_REBUILD32              0x7F
#define SCSI_SBC2_REGENERATE16           0x82
#define SCSI_SBC2_REGENERATE32           0x7F
#define SCSI_SBC2_SEEK10                 0x2B
#define SCSI_SBC2_SETLIMITS10            0x33
#define SCSI_SBC2_SETLIMITS12            0xB3
#define SCSI_SBC2_STARTSTOPUNIT          0x1B
#define SCSI_SBC2_SYNCCACHE10            0x35
#define SCSI_SBC2_SYNCCACHE16            0x91
#define SCSI_SBC2_VERIFY10               0x2F
#define SCSI_SBC2_VERIFY12               0xAF
#define SCSI_SBC2_VERIFY16               0x8F
#define SCSI_SBC2_WRITE6                 0x0A
#define SCSI_SBC2_WRITE10                0x2A
#define SCSI_SBC2_WRITE12                0xAA
#define SCSI_SBC2_WRITE16                0x8A
#define SCSI_SBC2_WRITENVERIFY10         0x2E
#define SCSI_SBC2_WRITENVERIFY12         0xAE
#define SCSI_SBC2_WRITENVERIFY16         0x8E
#define SCSI_SBC2_WRITELONG              0x3F
#define SCSI_SBC2_WRITESAME10            0x41
#define SCSI_SBC2_WRITESAME16            0x93
#define SCSI_SBC2_XDREAD10               0x52
#define SCSI_SBC2_XDREAD32               0x7F
#define SCSI_SBC2_XDWRITE10              0x50
#define SCSI_SBC2_XDWRITE32              0x7F
#define SCSI_SBC2_XDWRITEREAD10          0x53
#define SCSI_SBC2_XDWRITEREAD32          0x7F
#define SCSI_SBC2_XDWRITEEXTD16          0x80
#define SCSI_SBC2_XDWRITEEXTD32          0x7F
#define SCSI_SBC2_XPWRITE10              0x51
#define SCSI_SBC2_XPWRITE32              0x7F



void dissect_sbc2_startstopunit (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq _U_, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_sbc2_readwrite12 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_sbc2_readwrite10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_sbc2_readcapacity10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);


extern int hf_scsi_sbc_opcode;
extern scsi_cdb_table_t scsi_sbc_table[256];
WS_VAR_IMPORT const value_string scsi_sbc_vals[];

#endif
