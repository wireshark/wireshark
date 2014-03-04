/* packet-scsi-smc.h
 * Dissector for the SCSI SMC commandset
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

#ifndef __PACKET_SCSI_SMC_H_
#define __PACKET_SCSI_SMC_H_

#include "ws_symbol_export.h"

/* SMC Commands */
#define SCSI_SMC_EXCHANGE_MEDIUM                 0x40
#define SCSI_SMC_INITIALIZE_ELEMENT_STATUS       0x07
#define SCSI_SMC_INITIALIZE_ELEMENT_STATUS_RANGE 0x37
#define SCSI_SMC_MOVE_MEDIUM                     0xA5
#define SCSI_SMC_MOVE_MEDIUM_ATTACHED            0xA7
#define SCSI_SMC_OPENCLOSE_ELEMENT               0x1B
#define SCSI_SMC_POSITION_TO_ELEMENT             0x2B
#define SCSI_SMC_READ_ATTRIBUTE                  0x8C
#define SCSI_SMC_READ_ELEMENT_STATUS             0xB8
#define SCSI_SMC_READ_ELEMENT_STATUS_ATTACHED    0xB4
#define SCSI_SMC_REPORT_VOLUME_TYPES_SUPPORTED   0x44
#define SCSI_SMC_REQUEST_VOLUME_ELEMENT_ADDRESS  0xB5
#define SCSI_SMC_SEND_VOLUME_TAG                 0xB6
#define SCSI_SMC_WRITE_ATTRIBUTE                 0x8D
void dissect_smc_movemedium (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_smc_readelementstatus (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);


extern int hf_scsi_smc_opcode;
extern scsi_cdb_table_t scsi_smc_table[256];
WS_DLL_PUBLIC value_string_ext scsi_smc_vals_ext;

#endif
