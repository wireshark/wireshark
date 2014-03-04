/* packet-scsi-osd.h
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

#ifndef __PACKET_SCSI_OSD_H_
#define __PACKET_SCSI_OSD_H_

#include "ws_symbol_export.h"

#define SCSI_OSD_OPCODE			0x7f

WS_DLL_PUBLIC value_string_ext attributes_page_vals_ext;

typedef struct _scsi_osd_lun_info_t scsi_osd_lun_info_t;
typedef struct _attribute_page_numbers_t attribute_page_numbers_t;
typedef void (*attribute_dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                    scsi_osd_lun_info_t *lun_info, const attribute_page_numbers_t *att);

struct _attribute_page_numbers_t {
    guint32    number;
    const char *name;
    attribute_dissector dissector;
    int* hf_index;
    guint expected_length;
};

const attribute_page_numbers_t *
osd_lookup_attribute(guint32 page, guint32 number);

extern int hf_scsi_osd_opcode;
extern scsi_cdb_table_t scsi_osd_table[256];
WS_DLL_PUBLIC value_string_ext scsi_osd_vals_ext;

#endif
