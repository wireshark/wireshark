/* packet-scsi-sbc.h
 * Dissector for the SCSI SBC commandset
 * Extracted from packet-scsi.h
 *
 * Dinesh G Dutt (ddutt@cisco.com)
 * Ronnie sahlberg 2006
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_SCSI_SBC_H_
#define __PACKET_SCSI_SBC_H_

#include "ws_symbol_export.h"

/* SBC Commands */
#define SCSI_SBC_FORMATUNIT             0x04
#define SCSI_SBC_LOCKUNLKCACHE10        0x36
#define SCSI_SBC_LOCKUNLKCACHE16        0x92
#define SCSI_SBC_PREFETCH10             0x34
#define SCSI_SBC_PREFETCH16             0x90
#define SCSI_SBC_READ6                  0x08
#define SCSI_SBC_READ10                 0x28
#define SCSI_SBC_READ12                 0xA8
#define SCSI_SBC_READ16                 0x88
#define SCSI_SBC_READCAPACITY10         0x25
#define SCSI_SBC_SERVICEACTIONIN16      0x9E
#define SCSI_SBC_SERVICEACTIONOUT16     0x9F
#define SCSI_SBC_READDEFDATA10          0x37
#define SCSI_SBC_READDEFDATA12          0xB7
#define SCSI_SBC_READLONG               0x3E
#define SCSI_SBC_REASSIGNBLKS           0x07
#define SCSI_SBC_REBUILD16              0x81
#define SCSI_SBC_REBUILD32              0x7F
#define SCSI_SBC_REGENERATE16           0x82
#define SCSI_SBC_REGENERATE32           0x7F
#define SCSI_SBC_SANITIZE               0x48
#define SCSI_SBC_SEEK10                 0x2B
#define SCSI_SBC_SETLIMITS10            0x33
#define SCSI_SBC_SETLIMITS12            0xB3
#define SCSI_SBC_STARTSTOPUNIT          0x1B
#define SCSI_SBC_SYNCCACHE10            0x35
#define SCSI_SBC_SYNCCACHE16            0x91
#define SCSI_SBC_UNMAP                  0x42
#define SCSI_SBC_VERIFY10               0x2F
#define SCSI_SBC_VERIFY12               0xAF
#define SCSI_SBC_VERIFY16               0x8F
#define SCSI_SBC_WRITE6                 0x0A
#define SCSI_SBC_WRITE10                0x2A
#define SCSI_SBC_WRITE12                0xAA
#define SCSI_SBC_COMPARENWRITE          0x89
#define SCSI_SBC_WRITE16                0x8A
#define SCSI_SBC_WRITEATOMIC16          0x9C
#define SCSI_SBC_ORWRITE                0x8B
#define SCSI_SBC_WRITENVERIFY10         0x2E
#define SCSI_SBC_WRITENVERIFY12         0xAE
#define SCSI_SBC_WRITENVERIFY16         0x8E
#define SCSI_SBC_WRITELONG              0x3F
#define SCSI_SBC_WRITESAME10            0x41
#define SCSI_SBC_WRITESAME16            0x93
#define SCSI_SBC_XDREAD10               0x52
#define SCSI_SBC_XDREAD32               0x7F
#define SCSI_SBC_XDWRITE10              0x50
#define SCSI_SBC_XDWRITE32              0x7F
#define SCSI_SBC_XDWRITEREAD10          0x53
#define SCSI_SBC_XDWRITEREAD32          0x7F
#define SCSI_SBC_XDWRITEEXTD16          0x80
#define SCSI_SBC_XDWRITEEXTD32          0x7F
#define SCSI_SBC_XPWRITE10              0x51
#define SCSI_SBC_XPWRITE32              0x7F



void dissect_sbc_startstopunit (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq _U_, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_sbc_read12 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_sbc_write12 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_sbc_read10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_sbc_write10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_sbc_readcapacity10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);


extern int hf_scsi_sbc_opcode;
extern scsi_cdb_table_t scsi_sbc_table[256];
WS_DLL_PUBLIC value_string_ext scsi_sbc_vals_ext;

#endif
