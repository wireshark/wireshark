/* packet-scsi-mmc.h
 * Ronnie sahlberg 2006
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2002 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SCSI_MMC_H_
#define __PACKET_SCSI_MMC_H_

extern int hf_scsi_mmc_opcode;
extern scsi_cdb_table_t scsi_mmc_table[256];

WS_DLL_PUBLIC value_string_ext scsi_mmc_vals_ext;

#endif
