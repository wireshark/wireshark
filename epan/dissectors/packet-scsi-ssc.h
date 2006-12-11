/* packet-scsi-ssc.h
 * Dissector for the SCSI SSC commandset
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

#ifndef __PACKET_SCSI_SSC_H_
#define __PACKET_SCSI_SSC_H_

/* SSC2 Commands */
#define SCSI_SSC2_REWIND                        0x01
#define SCSI_SSC_FORMAT_MEDIUM                  0x04
#define SCSI_SSC2_READ_BLOCK_LIMITS             0x05
#define SCSI_SSC2_READ6                         0x08
#define SCSI_SSC2_WRITE6                        0x0A
#define SCSI_SSC2_SET_CAPACITY                  0x0B
#define SCSI_SSC2_READ_REVERSE_6                0x0F
#define SCSI_SSC2_WRITE_FILEMARKS_6             0x10
#define SCSI_SSC2_SPACE_6                       0x11
#define SCSI_SSC2_VERIFY_6                      0x13
#define SCSI_SSC2_RECOVER_BUFFERED_DATA         0x14
#define SCSI_SSC2_ERASE_6                       0x19
#define SCSI_SSC2_LOAD_UNLOAD                   0x1B
#define SCSI_SSC2_LOCATE_10                     0x2B
#define SCSI_SSC2_READ_POSITION                 0x34
#define SCSI_SSC2_REPORT_DENSITY_SUPPORT        0x44
#define SCSI_SSC2_WRITE_FILEMARKS_16            0x80
#define SCSI_SSC2_READ_REVERSE_16               0x81
#define SCSI_SSC2_READ_16                       0x88
#define SCSI_SSC2_WRITE_16                      0x8A
#define SCSI_SSC2_VERIFY_16                     0x8F
#define SCSI_SSC2_SPACE_16                      0x91
#define SCSI_SSC2_LOCATE_16                     0x92
#define SCSI_SSC_ERASE_16                       0x93

extern int hf_scsi_ssc_opcode;
extern scsi_cdb_table_t scsi_ssc_table[256];
WS_VAR_IMPORT const value_string scsi_ssc_vals[];

#endif
