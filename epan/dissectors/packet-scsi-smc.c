/* based on the SMC 3 standard */
/* packet-scsi-smc.c
 * Dissector for the SCSI SMC commandset
 * Extracted from packet-scsi.c
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/strutil.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include "packet-scsi.h"
#include "packet-fc.h"
#include "packet-scsi-smc.h"


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
static int hf_scsi_smc_sea			= -1;
static int hf_scsi_smc_num_elements		= -1;
static int hf_scsi_smc_invert			= -1;
static int hf_scsi_smc_ea			= -1;
static int hf_scsi_smc_action_code		= -1;

static gint ett_scsi_exchange_medium		= -1;
static gint ett_scsi_range			= -1;
static gint ett_scsi_move			= -1;

void
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
            ett_scsi_exchange_medium, exchg_fields, FALSE);
        proto_tree_add_bitmask(tree, tvb, offset+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

void
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
            ett_scsi_exchange_medium, pte_fields, FALSE);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

void
dissect_smc_initialize_element_status (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

void
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
            ett_scsi_range, range_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_smc_sa,  tvb, offset+1, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_smc_num_elements,  tvb, offset+5, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

void
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
            ett_scsi_control, cdb_control_fields, FALSE);
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
            ett_scsi_move, move_fields, FALSE);
        proto_tree_add_bitmask(tree, tvb, offset+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
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
                              proto_tree *tree, guint offset,
                              const char *name)
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
    proto_tree_add_text (tree, tvb, offset, 36,
                         "%s: Volume Identification = \"%s\", Volume Sequence Number = %u",
	                 name, volid, tvb_get_ntohs (tvb, offset+34));
}


static void
dissect_scsi_smc_element (tvbuff_t *tvb, packet_info *pinfo _U_,
                         proto_tree *tree, guint offset,
                         guint elem_bytecnt, guint8 elem_type,
                         guint8 voltag_flags)
{
    guint8 flags;
    guint8 ident_len;

    proto_tree_add_text (tree, tvb, offset, 2,
                         "Element Address: %u",
                         tvb_get_ntohs (tvb, offset));
    offset += 2;
    elem_bytecnt -= 2;

    if (elem_bytecnt < 1)
        return;
    flags = tvb_get_guint8 (tvb, offset);
    switch (elem_type) {

    case MT_ELEM:
        proto_tree_add_text (tree, tvb, offset, 1,
                            "EXCEPT: %u, FULL: %u",
                             (flags & EXCEPT) >> 2, flags & 0x01);
        break;

    case ST_ELEM:
    case DT_ELEM:
        proto_tree_add_text (tree, tvb, offset, 1,
                             "ACCESS: %u, EXCEPT: %u, FULL: %u",
                             (flags & 0x08) >> 3,
                             (flags & EXCEPT) >> 2, flags & 0x01);
        break;

    case I_E_ELEM:
        proto_tree_add_text (tree, tvb, offset, 1,
                             "cmc: %u, INENAB: %u, EXENAB: %u, ACCESS: %u, EXCEPT: %u, IMPEXP: %u, FULL: %u",
                             (flags & 0x40) >> 6,
                             (flags & 0x20) >> 5,
                             (flags & 0x10) >> 4,
                             (flags & 0x08) >> 3,
                             (flags & EXCEPT) >> 2,
                             (flags & 0x02) >> 1,
                             flags & 0x01);
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
        proto_tree_add_text (tree, tvb, offset, 2,
                             "Additional Sense Code+Qualifier: %s",
                             val_to_str_ext (tvb_get_ntohs (tvb, offset),
                                         &scsi_asc_val_ext, "Unknown (0x%04x)"));
    }
    offset += 2;
    elem_bytecnt -= 2;

    if (elem_bytecnt < 3)
        return;
    switch (elem_type) {

    case DT_ELEM:
        flags = tvb_get_guint8 (tvb, offset);
        if (flags & LU_VALID) {
            proto_tree_add_text (tree, tvb, offset, 1,
                                 "NOT BUS: %u, ID VALID: %u, LU VALID: 1, LUN: %u",
                                 (flags & 0x80) >> 7,
                                 (flags & ID_VALID) >> 5,
                                 flags & 0x07);
        } else if (flags & ID_VALID) {
            proto_tree_add_text (tree, tvb, offset, 1,
                                 "ID VALID: 1, LU VALID: 0");
        } else {
            proto_tree_add_text (tree, tvb, offset, 1,
                                 "ID VALID: 0, LU VALID: 0");
        }
        offset += 1;
        if (flags & ID_VALID) {
            proto_tree_add_text (tree, tvb, offset, 1,
                                 "SCSI Bus Address: %u",
                                 tvb_get_guint8 (tvb, offset));
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
    if (flags & SVALID) {
        proto_tree_add_text (tree, tvb, offset, 1,
                             "SVALID: 1, INVERT: %u",
                             (flags & 0x40) >> 6);
        offset += 1;
        proto_tree_add_text (tree, tvb, offset, 2,
                             "Source Storage Element Address: %u",
                             tvb_get_ntohs (tvb, offset));
        offset += 2;
    } else {
        proto_tree_add_text (tree, tvb, offset, 1,
                             "SVALID: 0");
        offset += 3;
    }
    elem_bytecnt -= 3;

    if (voltag_flags & PVOLTAG) {
        if (elem_bytecnt < 36)
            return;
        dissect_scsi_smc_volume_tag (tvb, pinfo, tree, offset,
                                      "Primary Volume Tag Information");
        offset += 36;
        elem_bytecnt -= 36;
    }

    if (voltag_flags & AVOLTAG) {
        if (elem_bytecnt < 36)
            return;
        dissect_scsi_smc_volume_tag (tvb, pinfo, tree, offset,
                                      "Alternate Volume Tag Information");
        offset += 36;
        elem_bytecnt -= 36;
    }

    if (elem_bytecnt < 1)
        return;
    flags = tvb_get_guint8 (tvb, offset);
    proto_tree_add_text (tree, tvb, offset, 1,
                         "Code Set: %s",
                         val_to_str (flags & 0x0F,
                                     scsi_devid_codeset_val,
                                     "Unknown (0x%02x)"));
    offset += 1;
    elem_bytecnt -= 1;

    if (elem_bytecnt < 1)
        return;
    flags = tvb_get_guint8 (tvb, offset);
    proto_tree_add_text (tree, tvb, offset, 1,
                         "Identifier Type: %s",
                         val_to_str ((flags & 0x0F),
                                     scsi_devid_idtype_val,
                                     "Unknown (0x%02x)"));
    offset += 1;
    elem_bytecnt -= 1;

    if (elem_bytecnt < 1)
        return;
    offset += 1; /* reserved */
    elem_bytecnt -= 1;

    if (elem_bytecnt < 1)
        return;
    ident_len = tvb_get_guint8 (tvb, offset);
    proto_tree_add_text (tree, tvb, offset, 1,
                         "Identifier Length: %u",
                         ident_len);
    offset += 1;
    elem_bytecnt -= 1;

    if (ident_len != 0) {
        if (elem_bytecnt < ident_len)
            return;
        proto_tree_add_text (tree, tvb, offset, ident_len,
                             "Identifier: %s",
                             tvb_bytes_to_str (tvb, offset, ident_len));
        offset += ident_len;
        elem_bytecnt -= ident_len;
    }
    if (elem_bytecnt != 0) {
        proto_tree_add_text (tree, tvb, offset, elem_bytecnt,
                             "Vendor-specific Data: %s",
                             tvb_bytes_to_str (tvb, offset, elem_bytecnt));
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
    guint8 flags;
    guint numelem, bytecnt, desc_bytecnt;
    guint8 elem_type;
    guint8 voltag_flags;
    guint16 elem_desc_len;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "VOLTAG: %u, Element Type Code: %s",
                             (flags & 0x10) >> 4,
                             val_to_str (flags & 0xF, element_type_code_vals,
                                         "Unknown (0x%x)"));
        proto_tree_add_text (tree, tvb, offset+1, 2,
                             "Starting Element Address: %u",
                             tvb_get_ntohs (tvb, offset+1));
        proto_tree_add_text (tree, tvb, offset+3, 2,
                             "Number of Elements: %u",
                             tvb_get_ntohs (tvb, offset+3));
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_text (tree, tvb, offset+4, 1,
                             "CURDATA: %u, DVCID: %u",
                             (flags & 0x02) >> 1, flags & 0x01);
        proto_tree_add_text (tree, tvb, offset+6, 3,
                             "Allocation Length: %u",
                             tvb_get_ntoh24 (tvb, offset+6));
        proto_tree_add_bitmask(tree, tvb, offset+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
    else if (!isreq) {
        proto_tree_add_text (tree, tvb, offset, 2,
                             "First Element Address Reported: %u",
                             tvb_get_ntohs (tvb, offset));
        offset += 2;
        numelem = tvb_get_ntohs (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 2,
                             "Number of Elements Available: %u", numelem);
        offset += 2;
        offset += 1; /* reserved */
        bytecnt = tvb_get_ntoh24 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 3,
                             "Byte Count of Report Available: %u", bytecnt);
        offset += 3;
        while (bytecnt != 0) {
            if (bytecnt < 1)
                break;
            elem_type = tvb_get_guint8 (tvb, offset);
            proto_tree_add_text (tree, tvb, offset, 1,
                                 "Element Type Code: %s",
                                 val_to_str (elem_type, element_type_code_vals,
                                             "Unknown (0x%x)"));
            offset += 1;
            bytecnt -= 1;

            if (bytecnt < 1)
                break;
            voltag_flags = tvb_get_guint8 (tvb, offset);
            proto_tree_add_text (tree, tvb, offset, 1,
                                 "PVOLTAG: %u, AVOLTAG: %u",
                                 (voltag_flags & PVOLTAG) >> 7,
                                 (voltag_flags & AVOLTAG) >> 6);
            offset += 1;
            bytecnt -= 1;

            if (bytecnt < 2)
                break;
            elem_desc_len = tvb_get_ntohs (tvb, offset);
            proto_tree_add_text (tree, tvb, offset, 2,
                                 "Element Descriptor Length: %u",
                                 elem_desc_len);
            offset += 2;
            bytecnt -= 2;

            if (bytecnt < 1)
                break;
            offset += 1; /* reserved */
            bytecnt -= 1;

            if (bytecnt < 3)
                break;
            desc_bytecnt = tvb_get_ntoh24 (tvb, offset);
            proto_tree_add_text (tree, tvb, offset, 3,
                                 "Byte Count Of Descriptor Data Available: %u",
                                 desc_bytecnt);
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
const value_string scsi_smc_vals[] = {
    {SCSI_SPC_ACCESS_CONTROL_IN               , "Access Control In"},
    {SCSI_SPC_ACCESS_CONTROL_OUT              , "Access Control Out"},
    {SCSI_SMC_EXCHANGE_MEDIUM                 , "Exchange Medium"},
    {SCSI_SMC_INITIALIZE_ELEMENT_STATUS       , "Initialize Element Status"},
    {SCSI_SMC_INITIALIZE_ELEMENT_STATUS_RANGE , "Initialize Element Status With Range"},
    {SCSI_SPC_INQUIRY                         , "Inquiry"},
    {SCSI_SPC_LOGSELECT                       , "Log Select"},
    {SCSI_SPC_LOGSENSE                        , "Log Sense"},
    {SCSI_SPC_MODESELECT6                     , "Mode Select(6)"},
    {SCSI_SPC_MODESELECT10                    , "Mode Select(10)"},
    {SCSI_SPC_MODESENSE6                      , "Mode Sense(6)"},
    {SCSI_SPC_MODESENSE10                     , "Mode Sense(10)"},
    {SCSI_SMC_MOVE_MEDIUM                     , "Move Medium"},
    {SCSI_SMC_MOVE_MEDIUM_ATTACHED            , "Move Medium Attached"},
    {SCSI_SMC_OPENCLOSE_ELEMENT               , "Open/Close Import/Export Element"},
    {SCSI_SPC_PERSRESVIN                      , "Persistent Reserve In"},
    {SCSI_SPC_PERSRESVOUT                     , "Persistent Reserve Out"},
    {SCSI_SMC_POSITION_TO_ELEMENT             , "Position To Element"},
    {SCSI_SPC_PREVMEDREMOVAL                  , "Prevent/Allow Medium Removal"},
    {SCSI_SMC_READ_ATTRIBUTE                  , "Read Attribute"},
    {SCSI_SPC_READBUFFER                      , "Read Buffer"},
    {SCSI_SMC_READ_ELEMENT_STATUS             , "Read Element Status"},
    {SCSI_SMC_READ_ELEMENT_STATUS_ATTACHED    , "Read Element Status Attached"},
    {SCSI_SPC_RCVDIAGRESULTS                  , "Receive Diagnostics Results"},
    {SCSI_SPC_RELEASE6                        , "Release(6)"},
    {SCSI_SPC_RELEASE10                       , "Release(10)"},
    {SCSI_SPC_REPORTLUNS                      , "Report LUNs"},
    {SCSI_SMC_REPORT_VOLUME_TYPES_SUPPORTED   , "Report Volume Types Supported"},
    {SCSI_SPC_REQSENSE                        , "Request Sense"},
    {SCSI_SMC_REQUEST_VOLUME_ELEMENT_ADDRESS  , "Request Volume Element Address"},
    {SCSI_SPC_RESERVE6                        , "Reserve(6)"},
    {SCSI_SPC_RESERVE10                       , "Reserve(10)"},
    {SCSI_SMC_SEND_VOLUME_TAG                 , "Send Volume Tag"},
    {SCSI_SPC_SENDDIAG                        , "Send Diagnostic"},
    {SCSI_SPC_TESTUNITRDY                     , "Test Unit Ready"},
    {SCSI_SMC_WRITE_ATTRIBUTE                 , "Write Attribute"},
    {SCSI_SPC_WRITEBUFFER                     , "Write Buffer"},
    {0, NULL},
};

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
/*SMC 0xa3*/{NULL},
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
          {"SMC Opcode", "scsi.smc.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_smc_vals), 0x0, NULL, HFILL}},
        { &hf_scsi_smc_mta,
          {"Medium Transport Address", "scsi.smc.mta", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_smc_sa,
          {"Source Address", "scsi.smc.sa", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_smc_da,
          {"Destination Address", "scsi.smc.da", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_smc_fda,
          {"First Destination Address", "scsi.smc.fda", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_smc_sda,
          {"Second Destination Address", "scsi.smc.sda", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
	{ &hf_scsi_smc_medium_flags,
          {"Flags", "scsi.smc.medium_flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
	{ &hf_scsi_smc_inv1,
          {"INV1", "scsi.smc.inv1", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
	{ &hf_scsi_smc_inv2,
          {"INV2", "scsi.smc.inv2", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
	{ &hf_scsi_smc_range_flags,
          {"Flags", "scsi.smc.range_flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
	{ &hf_scsi_smc_fast,
          {"FAST", "scsi.smc.fast", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
	{ &hf_scsi_smc_range,
          {"RANGE", "scsi.smc.range", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_smc_sea,
          {"Starting Element Address", "scsi.smc.sea", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_smc_num_elements,
          {"Number of Elements", "scsi.smc.num_elements", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
	{ &hf_scsi_smc_invert,
          {"INVERT", "scsi.smc.invert", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_smc_ea,
          {"Element Address", "scsi.smc.ea", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_smc_action_code,
          {"Action Code", "scsi.smc.action_code", FT_UINT8, BASE_HEX,
           VALS(action_code_vals), 0x1f, NULL, HFILL}},
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

