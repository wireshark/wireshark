/* based on the SMC 3 standard */
/* packet-scsi-smc.c
 * Dissector for the SCSI SMC commandset
 * Extracted from packet-scsi.c
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

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include "packet-scsi.h"
#include "packet-fc.h"
#include "packet-scsi-smc.h"

void proto_register_scsi_smc(void);
void proto_reg_handoff_scsi_smc(void);

static int proto_scsi_smc			= -1;
int hf_scsi_smc_opcode				= -1;
static int hf_scsi_smc_mta			= -1;
static int hf_scsi_smc_sa			= -1;
static int hf_scsi_smc_da			= -1;
static int hf_scsi_smc_fda			= -1;
static int hf_scsi_smc_sda			= -1;
static int hf_scsi_smc_medium_flags		= -1;
static int hf_scsi_smc_inv1			= -1;
static int hf_scsi_smc_inv2			= -1;
static int hf_scsi_smc_range_flags		= -1;
static int hf_scsi_smc_fast			= -1;
static int hf_scsi_smc_range			= -1;
/* static int hf_scsi_smc_sea			= -1; */
static int hf_scsi_smc_num_elements		= -1;
static int hf_scsi_smc_invert			= -1;
static int hf_scsi_smc_ea			= -1;
static int hf_scsi_smc_action_code		= -1;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_scsi_smc_allocation_length = -1;
static int hf_scsi_smc_first_element_address_reported = -1;
static int hf_scsi_smc_voltag = -1;
static int hf_scsi_smc_element_descriptor_length = -1;
static int hf_scsi_smc_byte_count_of_descriptor_data_available = -1;
static int hf_scsi_smc_pvoltag = -1;
static int hf_scsi_smc_code_set = -1;
static int hf_scsi_smc_starting_element_address = -1;
static int hf_scsi_smc_curdata = -1;
static int hf_scsi_smc_element_type_code = -1;
static int hf_scsi_smc_element_type_code_0F = -1;
static int hf_scsi_smc_identifier = -1;
static int hf_scsi_smc_vendor_specific_data = -1;
static int hf_scsi_smc_source_storage_element_address = -1;
static int hf_scsi_smc_number_of_elements_available = -1;
static int hf_scsi_smc_identifier_type = -1;
static int hf_scsi_smc_number_of_elements = -1;
static int hf_scsi_smc_identifier_length = -1;
static int hf_scsi_smc_scsi_bus_address = -1;
static int hf_scsi_smc_byte_count_of_report_available = -1;
static int hf_scsi_smc_cmc = -1;
static int hf_scsi_smc_svalid = -1;
static int hf_scsi_smc_avoltag = -1;
static int hf_scsi_smc_access = -1;
static int hf_scsi_smc_additional_sense_code_qualifier = -1;
static int hf_scsi_smc_lu_valid = -1;
static int hf_scsi_smc_dvcid = -1;
static int hf_scsi_smc_except = -1;
static int hf_scsi_smc_id_valid = -1;
static int hf_scsi_smc_not_bus = -1;
static int hf_scsi_smc_exenab = -1;
static int hf_scsi_smc_lun = -1;
static int hf_scsi_smc_inenab = -1;
static int hf_scsi_smc_full = -1;
static int hf_scsi_smc_impexp = -1;
static int hf_scsi_smc_primary_vol_tag_id = -1;
static int hf_scsi_smc_primary_vol_seq_num = -1;
static int hf_scsi_smc_alternate_vol_tag_id = -1;
static int hf_scsi_smc_alternate_vol_seq_num = -1;

static gint ett_scsi_exchange_medium		= -1;
static gint ett_scsi_range			= -1;
static gint ett_scsi_move			= -1;

static void
dissect_smc_exchangemedium (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *exchg_fields[] = {
        &hf_scsi_smc_inv1,
        &hf_scsi_smc_inv2,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_smc_mta, tvb, offset+1, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_smc_sa,  tvb, offset+3, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_smc_fda, tvb, offset+5, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_smc_sda, tvb, offset+7, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+9, hf_scsi_smc_medium_flags,
            ett_scsi_exchange_medium, exchg_fields, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_smc_position_to_element (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *pte_fields[] = {
        &hf_scsi_smc_invert,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_smc_mta, tvb, offset+1, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_smc_da,  tvb, offset+3, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+7, hf_scsi_smc_medium_flags,
            ett_scsi_exchange_medium, pte_fields, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_smc_initialize_element_status (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_smc_initialize_element_status_with_range (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *range_fields[] = {
        &hf_scsi_smc_fast,
        &hf_scsi_smc_range,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_smc_range_flags,
            ett_scsi_range, range_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_smc_sa,  tvb, offset+1, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_smc_num_elements,  tvb, offset+5, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_smc_openclose_importexport_element (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_smc_ea,  tvb, offset+1, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_smc_action_code,  tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}
void
dissect_smc_movemedium (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *move_fields[] = {
        &hf_scsi_smc_invert,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_smc_mta, tvb, offset+1, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_smc_sa,  tvb, offset+3, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_smc_da,  tvb, offset+5, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+9, hf_scsi_smc_range_flags,
            ett_scsi_move, move_fields, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

#define MT_ELEM  0x1
#define ST_ELEM  0x2
#define I_E_ELEM 0x3
#define DT_ELEM  0x4

static const value_string element_type_code_vals[] = {
    {0x0,      "All element types"},
    {MT_ELEM,  "Medium transport element"},
    {ST_ELEM,  "Storage element"},
    {I_E_ELEM, "Import/export element"},
    {DT_ELEM,  "Data transfer element"},
    {0, NULL}
};

static const value_string action_code_vals[] = {
    {0, "OPEN Import/Export Element"},
    {1, "CLOSE Import/Export Element"},
    {0, NULL}
};

#define PVOLTAG 0x80
#define AVOLTAG 0x40

#define EXCEPT 0x04

#define ID_VALID 0x20
#define LU_VALID 0x10

#define SVALID 0x80

static void
dissect_scsi_smc_volume_tag (tvbuff_t *tvb, packet_info *pinfo _U_,
                              proto_tree *tree, guint offset, int hf_vol_id, int hf_vol_seq_num)
{
    char volid[32+1];
    char *p;

    tvb_memcpy (tvb, (guint8 *)volid, offset, 32);
    p = &volid[32];
    for (;;) {
    	*p = '\0';
        if (p == volid)
            break;
        if (*(p - 1) != ' ')
            break;
        p--;
    }

    proto_tree_add_string(tree, hf_vol_id, tvb, offset, 32, volid);
    proto_tree_add_item(tree, hf_vol_seq_num, tvb, offset+34, 2, ENC_BIG_ENDIAN);
}


static void
dissect_scsi_smc_element (tvbuff_t *tvb, packet_info *pinfo _U_,
                         proto_tree *tree, guint offset,
                         guint elem_bytecnt, guint8 elem_type,
                         guint8 voltag_flags)
{
    guint8 flags;
    guint8 ident_len;

    proto_tree_add_item(tree, hf_scsi_smc_ea, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    elem_bytecnt -= 2;

    if (elem_bytecnt < 1)
        return;
    flags = tvb_get_guint8 (tvb, offset);
    switch (elem_type) {

    case MT_ELEM:
        proto_tree_add_item(tree, hf_scsi_smc_except, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_full, tvb, offset, 1, ENC_NA);
        break;

    case ST_ELEM:
    case DT_ELEM:
        proto_tree_add_item(tree, hf_scsi_smc_access, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_except, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_full, tvb, offset, 1, ENC_NA);
        break;

    case I_E_ELEM:
        proto_tree_add_item(tree, hf_scsi_smc_cmc, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_inenab, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_exenab, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_impexp, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_access, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_except, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_full, tvb, offset, 1, ENC_NA);
        break;
    }
    offset += 1;
    elem_bytecnt -= 1;

    if (elem_bytecnt < 1)
        return;
    offset += 1; /* reserved */
    elem_bytecnt -= 1;

    if (elem_bytecnt < 2)
        return;
    if (flags & EXCEPT) {
        proto_tree_add_item(tree, hf_scsi_smc_additional_sense_code_qualifier, tvb, offset, 2, ENC_BIG_ENDIAN);
    }
    offset += 2;
    elem_bytecnt -= 2;

    if (elem_bytecnt < 3)
        return;
    switch (elem_type) {

    case DT_ELEM:
        flags = tvb_get_guint8 (tvb, offset);
        if (flags & LU_VALID) {
            proto_tree_add_item(tree, hf_scsi_smc_lun, tvb, offset, 1, ENC_NA);
        }
        proto_tree_add_item(tree, hf_scsi_smc_not_bus, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_id_valid, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_lu_valid, tvb, offset, 1, ENC_NA);

        offset += 1;
        if (flags & ID_VALID) {
            proto_tree_add_item(tree, hf_scsi_smc_scsi_bus_address, tvb, offset, 1, ENC_NA);
        }
        offset += 1;
        offset += 1; /* reserved */
        break;

    default:
        offset += 3; /* reserved */
        break;
    }
    elem_bytecnt -= 3;

    if (elem_bytecnt < 3)
        return;
    flags = tvb_get_guint8 (tvb, offset);
    proto_tree_add_item(tree, hf_scsi_smc_svalid, tvb, offset, 1, ENC_NA);
    if (flags & SVALID) {
        proto_tree_add_item(tree, hf_scsi_smc_invert, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(tree, hf_scsi_smc_source_storage_element_address, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    } else {
        offset += 3;
    }
    elem_bytecnt -= 3;

    if (voltag_flags & PVOLTAG) {
        if (elem_bytecnt < 36)
            return;
        dissect_scsi_smc_volume_tag (tvb, pinfo, tree, offset, hf_scsi_smc_primary_vol_tag_id,
                                      hf_scsi_smc_primary_vol_seq_num);
        offset += 36;
        elem_bytecnt -= 36;
    }

    if (voltag_flags & AVOLTAG) {
        if (elem_bytecnt < 36)
            return;
        dissect_scsi_smc_volume_tag (tvb, pinfo, tree, offset, hf_scsi_smc_alternate_vol_tag_id,
                                      hf_scsi_smc_alternate_vol_seq_num);
        offset += 36;
        elem_bytecnt -= 36;
    }

    if (elem_bytecnt < 1)
        return;
    proto_tree_add_item(tree, hf_scsi_smc_code_set, tvb, offset, 1, ENC_NA);
    offset += 1;
    elem_bytecnt -= 1;

    if (elem_bytecnt < 1)
        return;
    proto_tree_add_item(tree, hf_scsi_smc_identifier_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    elem_bytecnt -= 1;

    if (elem_bytecnt < 1)
        return;
    offset += 1; /* reserved */
    elem_bytecnt -= 1;

    if (elem_bytecnt < 1)
        return;
    ident_len = tvb_get_guint8 (tvb, offset);
    proto_tree_add_item(tree, hf_scsi_smc_identifier_length, tvb, offset, 1, ENC_NA);
    offset += 1;
    elem_bytecnt -= 1;

    if (ident_len != 0) {
        if (elem_bytecnt < ident_len)
            return;
        proto_tree_add_item(tree, hf_scsi_smc_identifier, tvb, offset, ident_len, ENC_NA);
        offset += ident_len;
        elem_bytecnt -= ident_len;
    }
    if (elem_bytecnt != 0) {
        proto_tree_add_item(tree, hf_scsi_smc_vendor_specific_data, tvb, offset, elem_bytecnt, ENC_NA);
    }
}


static void
dissect_scsi_smc_elements (tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, guint offset,
                            guint desc_bytecnt, guint8 elem_type,
                            guint8 voltag_flags, guint16 elem_desc_len)
{
    guint elem_bytecnt;

    while (desc_bytecnt != 0) {
        elem_bytecnt = elem_desc_len;

        if (elem_bytecnt > desc_bytecnt)
            elem_bytecnt = desc_bytecnt;

	if (elem_bytecnt < 2)
	    break;

        dissect_scsi_smc_element (tvb, pinfo, tree, offset, elem_bytecnt,
                                   elem_type, voltag_flags);
        offset += elem_bytecnt;
        desc_bytecnt -= elem_bytecnt;
    }
}


void
dissect_smc_readelementstatus (tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree, guint offset, gboolean isreq,
                         gboolean iscdb,
                         guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint   bytecnt, desc_bytecnt;
    guint8  elem_type;
    guint8  voltag_flags;
    guint16 elem_desc_len;

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item(tree, hf_scsi_smc_voltag, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_element_type_code_0F, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_starting_element_address, tvb, offset+1, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_smc_number_of_elements, tvb, offset+3, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_smc_curdata, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_dvcid, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_allocation_length, tvb, offset+6, 3, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    else if (!isreq) {
        proto_tree_add_item(tree, hf_scsi_smc_first_element_address_reported, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_scsi_smc_number_of_elements_available, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        offset += 1; /* reserved */
        bytecnt = tvb_get_ntoh24 (tvb, offset);
        proto_tree_add_item(tree, hf_scsi_smc_byte_count_of_report_available, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
        while (bytecnt != 0) {
            if (bytecnt < 1)
                break;
            elem_type = tvb_get_guint8 (tvb, offset);
            proto_tree_add_item(tree, hf_scsi_smc_element_type_code, tvb, offset, 1, ENC_NA);
            offset += 1;
            bytecnt -= 1;

            if (bytecnt < 1)
                break;
            voltag_flags = tvb_get_guint8 (tvb, offset);
            proto_tree_add_item(tree, hf_scsi_smc_pvoltag, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_scsi_smc_avoltag, tvb, offset, 1, ENC_NA);
            offset += 1;
            bytecnt -= 1;

            if (bytecnt < 2)
                break;
            elem_desc_len = tvb_get_ntohs (tvb, offset);
            proto_tree_add_item(tree, hf_scsi_smc_element_descriptor_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            bytecnt -= 2;

            if (bytecnt < 1)
                break;
            offset += 1; /* reserved */
            bytecnt -= 1;

            if (bytecnt < 3)
                break;
            desc_bytecnt = tvb_get_ntoh24 (tvb, offset);
            proto_tree_add_item(tree, hf_scsi_smc_byte_count_of_descriptor_data_available, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;
            bytecnt -= 3;

            if (desc_bytecnt > bytecnt)
                desc_bytecnt = bytecnt;
            dissect_scsi_smc_elements (tvb, pinfo, tree, offset,
                                        desc_bytecnt, elem_type,
                                        voltag_flags, elem_desc_len);
            offset += desc_bytecnt;
            bytecnt -= desc_bytecnt;
        }
    }
}



/* SMC Commands */
static const value_string scsi_smc_vals[] = {
    /* 0x00 */    {SCSI_SPC_TESTUNITRDY                     , "Test Unit Ready"},
    /* 0x03 */    {SCSI_SPC_REQSENSE                        , "Request Sense"},
    /* 0x07 */    {SCSI_SMC_INITIALIZE_ELEMENT_STATUS       , "Initialize Element Status"},
    /* 0x12 */    {SCSI_SPC_INQUIRY                         , "Inquiry"},
    /* 0x15 */    {SCSI_SPC_MODESELECT6                     , "Mode Select(6)"},
    /* 0x16 */    {SCSI_SPC_RESERVE6                        , "Reserve(6)"},
    /* 0x17 */    {SCSI_SPC_RELEASE6                        , "Release(6)"},
    /* 0x1A */    {SCSI_SPC_MODESENSE6                      , "Mode Sense(6)"},
    /* 0x1B */    {SCSI_SMC_OPENCLOSE_ELEMENT               , "Open/Close Import/Export Element"},
    /* 0x1C */    {SCSI_SPC_RCVDIAGRESULTS                  , "Receive Diagnostics Results"},
    /* 0x1D */    {SCSI_SPC_SENDDIAG                        , "Send Diagnostic"},
    /* 0x1E */    {SCSI_SPC_PREVMEDREMOVAL                  , "Prevent/Allow Medium Removal"},
    /* 0x2B */    {SCSI_SMC_POSITION_TO_ELEMENT             , "Position To Element"},
    /* 0x37 */    {SCSI_SMC_INITIALIZE_ELEMENT_STATUS_RANGE , "Initialize Element Status With Range"},
    /* 0x3B */    {SCSI_SPC_WRITEBUFFER                     , "Write Buffer"},
    /* 0x3C */    {SCSI_SPC_READBUFFER                      , "Read Buffer"},
    /* 0x40 */    {SCSI_SMC_EXCHANGE_MEDIUM                 , "Exchange Medium"},
    /* 0x44 */    {SCSI_SMC_REPORT_VOLUME_TYPES_SUPPORTED   , "Report Volume Types Supported"},
    /* 0x4C */    {SCSI_SPC_LOGSELECT                       , "Log Select"},
    /* 0x4D */    {SCSI_SPC_LOGSENSE                        , "Log Sense"},
    /* 0x55 */    {SCSI_SPC_MODESELECT10                    , "Mode Select(10)"},
    /* 0x56 */    {SCSI_SPC_RESERVE10                       , "Reserve(10)"},
    /* 0x57 */    {SCSI_SPC_RELEASE10                       , "Release(10)"},
    /* 0x5A */    {SCSI_SPC_MODESENSE10                     , "Mode Sense(10)"},
    /* 0x5E */    {SCSI_SPC_PERSRESVIN                      , "Persistent Reserve In"},
    /* 0x5F */    {SCSI_SPC_PERSRESVOUT                     , "Persistent Reserve Out"},
    /* 0x86 */    {SCSI_SPC_ACCESS_CONTROL_IN               , "Access Control In"},
    /* 0x87 */    {SCSI_SPC_ACCESS_CONTROL_OUT              , "Access Control Out"},
    /* 0x8C */    {SCSI_SMC_READ_ATTRIBUTE                  , "Read Attribute"},
    /* 0x8D */    {SCSI_SMC_WRITE_ATTRIBUTE                 , "Write Attribute"},
    /* 0xA0 */    {SCSI_SPC_REPORTLUNS                      , "Report LUNs"},
    /* 0xA3 */    {SCSI_SPC_MGMT_PROTOCOL_IN                , "Mgmt Protocol In"},
    /* 0xA5 */    {SCSI_SMC_MOVE_MEDIUM                     , "Move Medium"},
    /* 0xA7 */    {SCSI_SMC_MOVE_MEDIUM_ATTACHED            , "Move Medium Attached"},
    /* 0xB4 */    {SCSI_SMC_READ_ELEMENT_STATUS_ATTACHED    , "Read Element Status Attached"},
    /* 0xB5 */    {SCSI_SMC_REQUEST_VOLUME_ELEMENT_ADDRESS  , "Request Volume Element Address"},
    /* 0xB6 */    {SCSI_SMC_SEND_VOLUME_TAG                 , "Send Volume Tag"},
    /* 0xB8 */    {SCSI_SMC_READ_ELEMENT_STATUS             , "Read Element Status"},
    {0, NULL},
};
value_string_ext scsi_smc_vals_ext = VALUE_STRING_EXT_INIT(scsi_smc_vals);

scsi_cdb_table_t scsi_smc_table[256] = {
/*SPC 0x00*/{dissect_spc_testunitready},
/*SMC 0x01*/{NULL},
/*SMC 0x02*/{NULL},
/*SPC 0x03*/{dissect_spc_requestsense},
/*SMC 0x04*/{NULL},
/*SMC 0x05*/{NULL},
/*SMC 0x06*/{NULL},
/*SMC 0x07*/{dissect_smc_initialize_element_status},
/*SMC 0x08*/{NULL},
/*SMC 0x09*/{NULL},
/*SMC 0x0a*/{NULL},
/*SMC 0x0b*/{NULL},
/*SMC 0x0c*/{NULL},
/*SMC 0x0d*/{NULL},
/*SMC 0x0e*/{NULL},
/*SMC 0x0f*/{NULL},
/*SMC 0x10*/{NULL},
/*SMC 0x11*/{NULL},
/*SPC 0x12*/{dissect_spc_inquiry},
/*SMC 0x13*/{NULL},
/*SMC 0x14*/{NULL},
/*SPC 0x15*/{dissect_spc_modeselect6},
/*SPC 0x16*/{dissect_spc_reserve6},
/*SPC 0x17*/{dissect_spc_release6},
/*SMC 0x18*/{NULL},
/*SMC 0x19*/{NULL},
/*SPC 0x1a*/{dissect_spc_modesense6},
/*SMC 0x1b*/{dissect_smc_openclose_importexport_element},
/*SMC 0x1c*/{NULL},
/*SPC 0x1d*/{dissect_spc_senddiagnostic},
/*SMC 0x1e*/{dissect_spc_preventallowmediaremoval},
/*SMC 0x1f*/{NULL},
/*SMC 0x20*/{NULL},
/*SMC 0x21*/{NULL},
/*SMC 0x22*/{NULL},
/*SMC 0x23*/{NULL},
/*SMC 0x24*/{NULL},
/*SMC 0x25*/{NULL},
/*SMC 0x26*/{NULL},
/*SMC 0x27*/{NULL},
/*SMC 0x28*/{NULL},
/*SMC 0x29*/{NULL},
/*SMC 0x2a*/{NULL},
/*SMC 0x2b*/{dissect_smc_position_to_element},
/*SMC 0x2c*/{NULL},
/*SMC 0x2d*/{NULL},
/*SMC 0x2e*/{NULL},
/*SMC 0x2f*/{NULL},
/*SMC 0x30*/{NULL},
/*SMC 0x31*/{NULL},
/*SMC 0x32*/{NULL},
/*SMC 0x33*/{NULL},
/*SMC 0x34*/{NULL},
/*SMC 0x35*/{NULL},
/*SMC 0x36*/{NULL},
/*SMC 0x37*/{dissect_smc_initialize_element_status_with_range},
/*SMC 0x38*/{NULL},
/*SMC 0x39*/{NULL},
/*SMC 0x3a*/{NULL},
/*SPC 0x3b*/{dissect_spc_writebuffer},
/*SMC 0x3c*/{NULL},
/*SMC 0x3d*/{NULL},
/*SMC 0x3e*/{NULL},
/*SMC 0x3f*/{NULL},
/*SMC 0x40*/{NULL},
/*SMC 0x41*/{NULL},
/*SMC 0x42*/{NULL},
/*SMC 0x43*/{NULL},
/*SMC 0x44*/{NULL},
/*SMC 0x45*/{NULL},
/*SMC 0x46*/{NULL},
/*SMC 0x47*/{NULL},
/*SMC 0x48*/{NULL},
/*SMC 0x49*/{NULL},
/*SMC 0x4a*/{NULL},
/*SMC 0x4b*/{NULL},
/*SPC 0x4c*/{dissect_spc_logselect},
/*SPC 0x4d*/{dissect_spc_logsense},
/*SMC 0x4e*/{NULL},
/*SMC 0x4f*/{NULL},
/*SMC 0x50*/{NULL},
/*SMC 0x51*/{NULL},
/*SMC 0x52*/{NULL},
/*SMC 0x53*/{NULL},
/*SMC 0x54*/{NULL},
/*SPC 0x55*/{dissect_spc_modeselect10},
/*SPC 0x56*/{dissect_spc_reserve10},
/*SPC 0x57*/{dissect_spc_release10},
/*SMC 0x58*/{NULL},
/*SMC 0x59*/{NULL},
/*SPC 0x5a*/{dissect_spc_modesense10},
/*SMC 0x5b*/{NULL},
/*SMC 0x5c*/{NULL},
/*SMC 0x5d*/{NULL},
/*SPC 0x5e*/{dissect_spc_persistentreservein},
/*SPC 0x5f*/{dissect_spc_persistentreserveout},
/*SMC 0x60*/{NULL},
/*SMC 0x61*/{NULL},
/*SMC 0x62*/{NULL},
/*SMC 0x63*/{NULL},
/*SMC 0x64*/{NULL},
/*SMC 0x65*/{NULL},
/*SMC 0x66*/{NULL},
/*SMC 0x67*/{NULL},
/*SMC 0x68*/{NULL},
/*SMC 0x69*/{NULL},
/*SMC 0x6a*/{NULL},
/*SMC 0x6b*/{NULL},
/*SMC 0x6c*/{NULL},
/*SMC 0x6d*/{NULL},
/*SMC 0x6e*/{NULL},
/*SMC 0x6f*/{NULL},
/*SMC 0x70*/{NULL},
/*SMC 0x71*/{NULL},
/*SMC 0x72*/{NULL},
/*SMC 0x73*/{NULL},
/*SMC 0x74*/{NULL},
/*SMC 0x75*/{NULL},
/*SMC 0x76*/{NULL},
/*SMC 0x77*/{NULL},
/*SMC 0x78*/{NULL},
/*SMC 0x79*/{NULL},
/*SMC 0x7a*/{NULL},
/*SMC 0x7b*/{NULL},
/*SMC 0x7c*/{NULL},
/*SMC 0x7d*/{NULL},
/*SMC 0x7e*/{NULL},
/*SMC 0x7f*/{NULL},
/*SMC 0x80*/{NULL},
/*SMC 0x81*/{NULL},
/*SMC 0x82*/{NULL},
/*SMC 0x83*/{NULL},
/*SMC 0x84*/{NULL},
/*SMC 0x85*/{NULL},
/*SMC 0x86*/{NULL},
/*SMC 0x87*/{NULL},
/*SMC 0x88*/{NULL},
/*SMC 0x89*/{NULL},
/*SMC 0x8a*/{NULL},
/*SMC 0x8b*/{NULL},
/*SMC 0x8c*/{NULL},
/*SMC 0x8d*/{NULL},
/*SMC 0x8e*/{NULL},
/*SMC 0x8f*/{NULL},
/*SMC 0x90*/{NULL},
/*SMC 0x91*/{NULL},
/*SMC 0x92*/{NULL},
/*SMC 0x93*/{NULL},
/*SMC 0x94*/{NULL},
/*SMC 0x95*/{NULL},
/*SMC 0x96*/{NULL},
/*SMC 0x97*/{NULL},
/*SMC 0x98*/{NULL},
/*SMC 0x99*/{NULL},
/*SMC 0x9a*/{NULL},
/*SMC 0x9b*/{NULL},
/*SMC 0x9c*/{NULL},
/*SMC 0x9d*/{NULL},
/*SMC 0x9e*/{NULL},
/*SMC 0x9f*/{NULL},
/*SPC 0xa0*/{dissect_spc_reportluns},
/*SMC 0xa1*/{NULL},
/*SMC 0xa2*/{NULL},
/*SPC 0xa3*/{dissect_spc_mgmt_protocol_in},
/*SMC 0xa4*/{NULL},
/*SMC 0xa5*/{dissect_smc_movemedium},
/*SMC 0xa6*/{dissect_smc_exchangemedium},
/*SMC 0xa7*/{dissect_smc_movemedium},
/*SMC 0xa8*/{NULL},
/*SMC 0xa9*/{NULL},
/*SMC 0xaa*/{NULL},
/*SMC 0xab*/{NULL},
/*SMC 0xac*/{NULL},
/*SMC 0xad*/{NULL},
/*SMC 0xae*/{NULL},
/*SMC 0xaf*/{NULL},
/*SMC 0xb0*/{NULL},
/*SMC 0xb1*/{NULL},
/*SMC 0xb2*/{NULL},
/*SMC 0xb3*/{NULL},
/*SMC 0xb4*/{dissect_smc_readelementstatus},
/*SMC 0xb5*/{NULL},
/*SMC 0xb6*/{NULL},
/*SMC 0xb7*/{NULL},
/*SMC 0xb8*/{dissect_smc_readelementstatus},
/*SMC 0xb9*/{NULL},
/*SMC 0xba*/{NULL},
/*SMC 0xbb*/{NULL},
/*SMC 0xbc*/{NULL},
/*SMC 0xbd*/{NULL},
/*SMC 0xbe*/{NULL},
/*SMC 0xbf*/{NULL},
/*SMC 0xc0*/{NULL},
/*SMC 0xc1*/{NULL},
/*SMC 0xc2*/{NULL},
/*SMC 0xc3*/{NULL},
/*SMC 0xc4*/{NULL},
/*SMC 0xc5*/{NULL},
/*SMC 0xc6*/{NULL},
/*SMC 0xc7*/{NULL},
/*SMC 0xc8*/{NULL},
/*SMC 0xc9*/{NULL},
/*SMC 0xca*/{NULL},
/*SMC 0xcb*/{NULL},
/*SMC 0xcc*/{NULL},
/*SMC 0xcd*/{NULL},
/*SMC 0xce*/{NULL},
/*SMC 0xcf*/{NULL},
/*SMC 0xd0*/{NULL},
/*SMC 0xd1*/{NULL},
/*SMC 0xd2*/{NULL},
/*SMC 0xd3*/{NULL},
/*SMC 0xd4*/{NULL},
/*SMC 0xd5*/{NULL},
/*SMC 0xd6*/{NULL},
/*SMC 0xd7*/{NULL},
/*SMC 0xd8*/{NULL},
/*SMC 0xd9*/{NULL},
/*SMC 0xda*/{NULL},
/*SMC 0xdb*/{NULL},
/*SMC 0xdc*/{NULL},
/*SMC 0xdd*/{NULL},
/*SMC 0xde*/{NULL},
/*SMC 0xdf*/{NULL},
/*SMC 0xe0*/{NULL},
/*SMC 0xe1*/{NULL},
/*SMC 0xe2*/{NULL},
/*SMC 0xe3*/{NULL},
/*SMC 0xe4*/{NULL},
/*SMC 0xe5*/{NULL},
/*SMC 0xe6*/{NULL},
/*SMC 0xe7*/{NULL},
/*SMC 0xe8*/{NULL},
/*SMC 0xe9*/{NULL},
/*SMC 0xea*/{NULL},
/*SMC 0xeb*/{NULL},
/*SMC 0xec*/{NULL},
/*SMC 0xed*/{NULL},
/*SMC 0xee*/{NULL},
/*SMC 0xef*/{NULL},
/*SMC 0xf0*/{NULL},
/*SMC 0xf1*/{NULL},
/*SMC 0xf2*/{NULL},
/*SMC 0xf3*/{NULL},
/*SMC 0xf4*/{NULL},
/*SMC 0xf5*/{NULL},
/*SMC 0xf6*/{NULL},
/*SMC 0xf7*/{NULL},
/*SMC 0xf8*/{NULL},
/*SMC 0xf9*/{NULL},
/*SMC 0xfa*/{NULL},
/*SMC 0xfb*/{NULL},
/*SMC 0xfc*/{NULL},
/*SMC 0xfd*/{NULL},
/*SMC 0xfe*/{NULL},
/*SMC 0xff*/{NULL}
};


void
proto_register_scsi_smc(void)
{
    static hf_register_info hf[] = {
        { &hf_scsi_smc_opcode,
          {"SMC Opcode", "scsi_smc.opcode",
           FT_UINT8, BASE_HEX | BASE_EXT_STRING, &scsi_smc_vals_ext, 0x0,
           NULL, HFILL}
        },
        { &hf_scsi_smc_mta,
          {"Medium Transport Address", "scsi_smc.mta",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_scsi_smc_sa,
          {"Source Address", "scsi_smc.sa",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_scsi_smc_da,
          {"Destination Address", "scsi_smc.da",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_scsi_smc_fda,
          {"First Destination Address", "scsi_smc.fda",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_scsi_smc_sda,
          {"Second Destination Address", "scsi_smc.sda",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
	{ &hf_scsi_smc_medium_flags,
          {"Flags", "scsi_smc.medium_flags",
           FT_UINT8, BASE_HEX, NULL, 0x0,
           NULL, HFILL}
        },
	{ &hf_scsi_smc_inv1,
          {"INV1", "scsi_smc.inv1",
           FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}
        },
	{ &hf_scsi_smc_inv2,
          {"INV2", "scsi_smc.inv2",
           FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}
        },
	{ &hf_scsi_smc_range_flags,
          {"Flags", "scsi_smc.range_flags",
           FT_UINT8, BASE_HEX, NULL, 0x0,
           NULL, HFILL}
        },
	{ &hf_scsi_smc_fast,
          {"FAST", "scsi_smc.fast",
           FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}
        },
	{ &hf_scsi_smc_range,
          {"RANGE", "scsi_smc.range",
           FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}
        },
#if 0
        { &hf_scsi_smc_sea,
          {"Starting Element Address", "scsi_smc.sea",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
#endif
        { &hf_scsi_smc_num_elements,
          {"Number of Elements", "scsi_smc.num_elements",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
	{ &hf_scsi_smc_invert,
          {"INVERT", "scsi_smc.invert",
           FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}
        },
        { &hf_scsi_smc_ea,
          {"Element Address", "scsi_smc.ea",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_scsi_smc_action_code,
          {"Action Code", "scsi_smc.action_code",
           FT_UINT8, BASE_HEX, VALS(action_code_vals), 0x1f,
           NULL, HFILL}
        },

        /* Generated from convert_proto_tree_add_text.pl */
        { &hf_scsi_smc_scsi_bus_address,
          { "SCSI Bus Address", "scsi_smc.scsi_bus_address",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_source_storage_element_address,
          { "Source Storage Element Address", "scsi_smc.source_storage_element_address",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_code_set,
          { "Code Set", "scsi_smc.code_set",
            FT_UINT8, BASE_DEC, VALS(scsi_devid_codeset_val), 0x0F,
            NULL, HFILL }
        },
        { &hf_scsi_smc_identifier_type,
          { "Identifier Type", "scsi_smc.identifier_type",
            FT_UINT8, BASE_DEC, VALS(scsi_devid_idtype_val), 0x0F,
            NULL, HFILL }
        },
        { &hf_scsi_smc_identifier_length,
          { "Identifier Length", "scsi_smc.identifier_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_identifier,
          { "Identifier", "scsi_smc.identifier",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_vendor_specific_data,
          { "Vendor-specific Data", "scsi_smc.vendor_specific_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_voltag,
          { "VOLTAG", "scsi_smc.voltag",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_scsi_smc_starting_element_address,
          { "Starting Element Address", "scsi_smc.starting_element_address",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_number_of_elements,
          { "Number of Elements", "scsi_smc.number_of_elements",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_curdata,
          { "CURDATA", "scsi_smc.curdata",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_scsi_smc_allocation_length,
          { "Allocation Length", "scsi_smc.allocation_length",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_first_element_address_reported,
          { "First Element Address Reported", "scsi_smc.first_element_address_reported",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_number_of_elements_available,
          { "Number of Elements Available", "scsi_smc.number_of_elements_available",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_byte_count_of_report_available,
          { "Byte Count of Report Available", "scsi_smc.byte_count_of_report_available",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_element_type_code,
          { "Element Type Code", "scsi_smc.element_type_code",
            FT_UINT8, BASE_DEC, VALS(element_type_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_element_type_code_0F,
          { "Element Type Code", "scsi_smc.element_type_code",
            FT_UINT8, BASE_DEC, VALS(element_type_code_vals), 0x0F,
            NULL, HFILL }
        },
        { &hf_scsi_smc_pvoltag,
          { "PVOLTAG", "scsi_smc.pvoltag",
            FT_BOOLEAN, 8, NULL, PVOLTAG,
            NULL, HFILL }
        },
        { &hf_scsi_smc_element_descriptor_length,
          { "Element Descriptor Length", "scsi_smc.element_descriptor_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_byte_count_of_descriptor_data_available,
          { "Byte Count Of Descriptor Data Available", "scsi_smc.byte_count_of_descriptor_data_available",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_except,
          { "EXCEPT", "scsi_smc.except",
            FT_BOOLEAN, 8, NULL, EXCEPT,
            NULL, HFILL }
        },
        { &hf_scsi_smc_access,
          { "ACCESS", "scsi_smc.access",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_scsi_smc_cmc,
          { "cmc", "scsi_smc.cmc",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_scsi_smc_additional_sense_code_qualifier,
          { "Additional Sense Code+Qualifier", "scsi_smc.additional_sense_code_qualifier",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &scsi_asc_val_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_not_bus,
          { "NOT BUS", "scsi_smc.not_bus",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_scsi_smc_id_valid,
          { "ID VALID", "scsi_smc.id_valid",
            FT_BOOLEAN, 8, NULL, ID_VALID,
            NULL, HFILL }
        },
        { &hf_scsi_smc_lu_valid,
          { "LU VALID", "scsi_smc.lu_valid",
            FT_BOOLEAN, 8, NULL, LU_VALID,
            NULL, HFILL }
        },
        { &hf_scsi_smc_svalid,
          { "SVALID", "scsi_smc.svalid",
            FT_BOOLEAN, 8, NULL, SVALID,
            NULL, HFILL }
        },
        { &hf_scsi_smc_dvcid,
          { "DVCID", "scsi_smc.dvcid",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_scsi_smc_avoltag,
          { "AVOLTAG", "scsi_smc.pvoltag",
            FT_BOOLEAN, 8, NULL, AVOLTAG,
            NULL, HFILL }
        },
        { &hf_scsi_smc_full,
          { "FULL", "scsi_smc.full",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_scsi_smc_exenab,
          { "EXENAB", "scsi_smc.exenab",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_scsi_smc_inenab,
          { "INENAB", "scsi_smc.inenab",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_scsi_smc_impexp,
          { "IMPEXP", "scsi_smc.impexp",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_scsi_smc_lun,
          { "LUN", "scsi_smc.lun",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_scsi_smc_primary_vol_tag_id,
          { "Primary Volume Identification", "scsi_smc.primary_vol_tag_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_alternate_vol_tag_id,
          { "Alternate Volume Identification", "scsi_smc.alternate_vol_tag_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_primary_vol_seq_num,
          { "Primary Volume Sequence Number", "scsi_smc.primary_vol_seq_num",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scsi_smc_alternate_vol_seq_num,
          { "Alternate Volume Sequence Number", "scsi_smc.alternate_vol_seq_num",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
    };


    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_scsi_exchange_medium,
        &ett_scsi_range,
        &ett_scsi_move
    };

    /* Register the protocol name and description */
    proto_scsi_smc = proto_register_protocol("SCSI_SMC", "SCSI_SMC", "scsi_smc");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_scsi_smc, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_scsi_smc(void)
{
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
