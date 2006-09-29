/* packet-scsi.h
 * Author: Dinesh G Dutt (ddutt@cisco.com)
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

#ifndef __PACKET_SCSI_H_
#define __PACKET_SCSI_H_


/* SPC and SPC-2 Commands */
#define SCSI_SPC_CHANGE_DEFINITION       0x40
#define SCSI_SPC_COMPARE                 0x39
#define SCSI_SPC_COPY                    0x18
#define SCSI_SPC_COPY_AND_VERIFY         0x3A
#define SCSI_SPC2_INQUIRY                0x12
#define SCSI_SPC2_EXTCOPY                0x83
#define SCSI_SPC2_LOGSELECT              0x4C
#define SCSI_SPC2_LOGSENSE               0x4D
#define SCSI_SPC2_MODESELECT6            0x15
#define SCSI_SPC2_MODESELECT10           0x55
#define SCSI_SPC2_MODESENSE6             0x1A
#define SCSI_SPC2_MODESENSE10            0x5A
#define SCSI_SPC2_PERSRESVIN             0x5E
#define SCSI_SPC2_PERSRESVOUT            0x5F
#define SCSI_SPC2_PREVMEDREMOVAL         0x1E
#define SCSI_SPC2_READBUFFER             0x3C
#define SCSI_SPC2_RCVCOPYRESULTS         0x84
#define SCSI_SPC2_RCVDIAGRESULTS         0x1C
#define SCSI_SPC2_RELEASE6               0x17
#define SCSI_SPC2_RELEASE10              0x57
#define SCSI_SPC2_REPORTDEVICEID         0xA3
#define SCSI_SPC2_REPORTLUNS             0xA0
#define SCSI_SPC2_REQSENSE               0x03
#define SCSI_SPC2_RESERVE6               0x16
#define SCSI_SPC2_RESERVE10              0x56
#define SCSI_SPC2_SENDDIAG               0x1D
#define SCSI_SPC2_SETDEVICEID            0xA4
#define SCSI_SPC2_TESTUNITRDY            0x00
#define SCSI_SPC2_WRITEBUFFER            0x3B
#define SCSI_SPC2_VARLENCDB              0x7F

extern const value_string scsi_status_val[];

/*
 * SCSI Device Types.
 *
 * These can be supplied to the dissection routines if the caller happens
 * to know the device type (e.g., NDMP assumes that a "jukebox" is a
 * media changer, SCSI_DEV_SMC, and a "tape" is a sequential access device,
 * SCSI_DEV_SSC).
 *
 * If the caller doesn't know the device type, it supplies SCSI_DEV_UNKNOWN.
 */
#define SCSI_DEV_UNKNOWN   -1
#define SCSI_DEV_SBC       0x0
#define SCSI_DEV_SSC       0x1
#define SCSI_DEV_PRNT      0x2
#define SCSI_DEV_PROC      0x3
#define SCSI_DEV_WORM      0x4
#define SCSI_DEV_CDROM     0x5
#define SCSI_DEV_SCAN      0x6
#define SCSI_DEV_OPTMEM    0x7
#define SCSI_DEV_SMC       0x8
#define SCSI_DEV_COMM      0x9
#define SCSI_DEV_RAID      0xC
#define SCSI_DEV_SES       0xD
#define SCSI_DEV_RBC       0xE
#define SCSI_DEV_OCRW      0xF
#define SCSI_DEV_OSD       0x11
#define SCSI_DEV_ADC       0x12
#define SCSI_DEV_NOLUN     0x1F

#define SCSI_DEV_BITS      0x1F /* the lower 5 bits indicate device type */
#define SCSI_MS_PCODE_BITS 0x3F /* Page code bits in Mode Sense */

/* Function Decls; functions invoked by SAM-2 transport protocols such as
 * FCP/iSCSI
 */
void dissect_scsi_cdb (tvbuff_t *, packet_info *, proto_tree *,
                       gint, itlq_nexus_t *, itl_nexus_t *);
void dissect_scsi_rsp (tvbuff_t *, packet_info *, proto_tree *, itlq_nexus_t *, itl_nexus_t *, guint8);
void dissect_scsi_payload (tvbuff_t *, packet_info *, proto_tree *,
                           gboolean, itlq_nexus_t *, itl_nexus_t *);
void dissect_scsi_snsinfo (tvbuff_t *, packet_info *, proto_tree *, guint, guint, itlq_nexus_t *, itl_nexus_t *);

WS_VAR_IMPORT const value_string scsi_sbc2_vals[];
WS_VAR_IMPORT const value_string scsi_mmc_vals[];
WS_VAR_IMPORT const value_string scsi_ssc2_vals[];

#endif
