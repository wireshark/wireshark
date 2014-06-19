/* packet-fc-dns.c
 * Routines for FC distributed Name Server (dNS)
 * Copyright 2001, Dinesh G Dutt <ddutt@andiamo.com>
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

#define NEW_PROTO_TREE_API

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/wmem/wmem.h>
#include <epan/conversation.h>
#include <epan/etypes.h>
#include "packet-fc.h"
#include "packet-fcct.h"
#include "packet-fcdns.h"
#include "packet-fcswils.h"

void proto_register_fcdns(void);
void proto_reg_handoff_fcdns(void);

/*
 * See FC-GS-2.
 */

static dissector_handle_t dns_handle;

/* protocol and registered fields */

static header_field_info *hfi_fcdns = NULL;

#define FCDNS_HFI_INIT HFI_INIT(proto_fcdns)

#if 0
static header_field_info hfi_fcdns_gssubtype FCDNS_HFI_INIT =
          {"GS_Subtype", "fcdns.gssubtype", FT_UINT8, BASE_HEX,
           VALS(fc_dns_subtype_val), 0x0, NULL, HFILL};
#endif

static header_field_info hfi_fcdns_opcode FCDNS_HFI_INIT =
         {"Opcode", "fcdns.opcode", FT_UINT16, BASE_HEX, VALS (fc_dns_opcode_val),
          0x0, NULL, HFILL};

static header_field_info hfi_fcdns_reason FCDNS_HFI_INIT =
          {"Reason Code", "fcdns.rply.reason", FT_UINT8, BASE_HEX,
           VALS (fc_ct_rjt_code_vals), 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_vendor FCDNS_HFI_INIT =
          {"Vendor Unique Reject Code", "fcdns.rply.vendor", FT_UINT8,
           BASE_HEX, NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_req_portid FCDNS_HFI_INIT =
          {"Port Identifier", "fcdns.req.portid", FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL};

static header_field_info hfi_fcdns_rply_pname FCDNS_HFI_INIT =
          {"Port Name", "fcdns.rply.pname", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
           HFILL};

static header_field_info hfi_fcdns_rply_nname FCDNS_HFI_INIT =
          {"Node Name", "fcdns.rply.nname", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
           HFILL};

static header_field_info hfi_fcdns_rply_gft FCDNS_HFI_INIT =
          {"FC-4 Types Supported", "fcdns.rply.fc4type", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_rply_snamelen FCDNS_HFI_INIT =
          {"Symbolic Node Name Length", "fcdns.rply.snamelen", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_rply_sname FCDNS_HFI_INIT =
          {"Symbolic Node Name", "fcdns.rply.sname", FT_STRING, BASE_NONE, NULL,
           0x0, NULL, HFILL};

static header_field_info hfi_fcdns_rply_ptype FCDNS_HFI_INIT =
          {"Port Type", "fcdns.rply.porttype", FT_UINT8, BASE_HEX,
           VALS (fc_dns_port_type_val), 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_rply_fpname FCDNS_HFI_INIT =
          {"Fabric Port Name", "fcdns.rply.fpname", FT_STRING, BASE_NONE, NULL,
           0x0, NULL, HFILL};

static header_field_info hfi_fcdns_fc4type FCDNS_HFI_INIT =
          {"FC-4 Types", "fcdns.req.fc4type", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_rply_fc4type FCDNS_HFI_INIT =
          {"FC-4 Descriptor Type", "fcdns.rply.fc4type", FT_UINT8, BASE_HEX,
           VALS (fc_fc4_val), 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_rply_fc4desc FCDNS_HFI_INIT =
          {"FC-4 Descriptor", "fcdns.rply.fc4desc", FT_BYTES, BASE_NONE, NULL,
           0x0, NULL, HFILL};

static header_field_info hfi_fcdns_req_pname FCDNS_HFI_INIT =
          {"Port Name", "fcdns.req.portname", FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL};

static header_field_info hfi_fcdns_rply_portid FCDNS_HFI_INIT =
          {"Port Identifier", "fcdns.rply.portid", FT_STRING, BASE_NONE, NULL,
           0x0, NULL, HFILL};

static header_field_info hfi_fcdns_req_nname FCDNS_HFI_INIT =
          {"Node Name", "fcdns.req.nname", FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL};

static header_field_info hfi_fcdns_req_domainscope FCDNS_HFI_INIT =
          {"Domain ID Scope", "fcdns.req.domainid", FT_UINT8, BASE_HEX, NULL,
           0x0, NULL, HFILL};

static header_field_info hfi_fcdns_req_areascope FCDNS_HFI_INIT =
          {"Area ID Scope", "fcdns.req.areaid", FT_UINT8, BASE_HEX, NULL,
           0x0, NULL, HFILL};

static header_field_info hfi_fcdns_req_ptype FCDNS_HFI_INIT =
          {"Port Type", "fcdns.req.porttype", FT_UINT8, BASE_HEX,
           VALS (fc_dns_port_type_val), 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_req_cos FCDNS_HFI_INIT =
          {"Requested Class of Service", "fcdns.req.class", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_req_fc4types FCDNS_HFI_INIT =
          {"FC-4 Types Supported", "fcdns.req.fc4types", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_req_snamelen FCDNS_HFI_INIT =
          {"Symbolic Name Length", "fcdns.req.snamelen", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_req_sname FCDNS_HFI_INIT =
          {"Symbolic Port Name", "fcdns.req.sname", FT_STRING, BASE_NONE, NULL,
           0x0, NULL, HFILL};

static header_field_info hfi_fcdns_rply_spnamelen FCDNS_HFI_INIT =
          {"Symbolic Port Name Length", "fcdns.rply.spnamelen", FT_UINT8,
           BASE_DEC, NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_rply_spname FCDNS_HFI_INIT =
         {"Symbolic Port Name", "fcdns.rply.spname", FT_STRING, BASE_NONE, NULL,
          0x0, NULL, HFILL};

static header_field_info hfi_fcdns_req_spnamelen FCDNS_HFI_INIT =
          {"Symbolic Port Name Length", "fcdns.req.spnamelen", FT_UINT8,
           BASE_DEC, NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_req_spname FCDNS_HFI_INIT =
          {"Symbolic Port Name", "fcdns.req.spname", FT_STRING, BASE_NONE, NULL,
           0x0, NULL, HFILL};

static header_field_info hfi_fcdns_rply_ipa FCDNS_HFI_INIT =
          {"Initial Process Associator", "fcdns.rply.ipa", FT_BYTES, BASE_NONE,
           NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_rply_ipnode FCDNS_HFI_INIT =
          {"Node IP Address", "fcdns.rply.ipnode", FT_IPv6, BASE_NONE, NULL,
           0x0, NULL, HFILL};

static header_field_info hfi_fcdns_rply_ipport FCDNS_HFI_INIT =
          {"Port IP Address", "fcdns.rply.ipport", FT_IPv6, BASE_NONE, NULL,
           0x0, NULL, HFILL};

static header_field_info hfi_fcdns_rply_fc4desclen FCDNS_HFI_INIT =
          {"FC-4 Descriptor Length", "fcdns.rply.fc4desclen", FT_UINT8,
           BASE_DEC, NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_rply_hrdaddr FCDNS_HFI_INIT =
          {"Hard Address", "fcdns.rply.hrdaddr", FT_STRING, BASE_NONE, NULL,
           0x0, NULL, HFILL};

static header_field_info hfi_fcdns_req_fdesclen FCDNS_HFI_INIT =
          {"FC-4 Descriptor Length", "fcdns.req.fc4desclen", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_req_fdesc FCDNS_HFI_INIT =
          {"FC-4 Descriptor", "fcdns.req.fc4desc", FT_STRING, BASE_NONE, NULL,
           0x0, NULL, HFILL};

static header_field_info hfi_fcdns_req_ip FCDNS_HFI_INIT =
          {"IP Address", "fcdns.req.ip", FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL};

static header_field_info hfi_fcdns_rjtdetail FCDNS_HFI_INIT =
          {"Reason Code Explanantion", "fcdns.rply.reasondet", FT_UINT8,
           BASE_HEX, VALS (fc_dns_rjt_det_code_val), 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_zone_mbrtype FCDNS_HFI_INIT =
          {"Zone Member Type", "fcdns.zone.mbrtype", FT_UINT8, BASE_HEX,
           VALS (fc_swils_zonembr_type_val), 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_zone_mbrid FCDNS_HFI_INIT =
          {"Member Identifier", "fcdns.zone.mbrid", FT_STRING, BASE_NONE, NULL,
           0x0, NULL, HFILL};

static header_field_info hfi_fcdns_zonenm FCDNS_HFI_INIT =
          {"Zone Name", "fcdns.zonename", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
           HFILL};

static header_field_info hfi_fcdns_portip FCDNS_HFI_INIT =
          {"Port IP Address", "fcdns.portip", FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL};

static header_field_info hfi_fcdns_sw2_objfmt FCDNS_HFI_INIT =
          {"Name Entry Object Format", "fcdns.entry.objfmt", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_num_fc4desc FCDNS_HFI_INIT =
          {"Number of FC4 Descriptors Registered", "fcdns.entry.numfc4desc",
           FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_rply_ownerid FCDNS_HFI_INIT =
          {"Owner Id", "fcdns.rply.ownerid", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
           HFILL};

static header_field_info hfi_fcdns_maxres_size FCDNS_HFI_INIT =
          {"Maximum/Residual Size", "fcdns.maxres_size", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_reply_cos FCDNS_HFI_INIT =
          {"Class of Service Supported", "fcdns.reply.cos", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_cos_f FCDNS_HFI_INIT =
          {"F", "fcdns.cos.f", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), 0x01, NULL, HFILL};

static header_field_info hfi_fcdns_cos_1 FCDNS_HFI_INIT =
          {"1", "fcdns.cos.1", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), 0x02, NULL, HFILL};

static header_field_info hfi_fcdns_cos_2 FCDNS_HFI_INIT =
          {"2", "fcdns.cos.2", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), 0x04, NULL, HFILL};

static header_field_info hfi_fcdns_cos_3 FCDNS_HFI_INIT =
          {"3", "fcdns.cos.3", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), 0x08, NULL, HFILL};

static header_field_info hfi_fcdns_cos_4 FCDNS_HFI_INIT =
          {"4", "fcdns.cos.4", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), 0x10, NULL, HFILL};

static header_field_info hfi_fcdns_cos_6 FCDNS_HFI_INIT =
          {"6", "fcdns.cos.6", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), 0x40, NULL, HFILL};

static header_field_info hfi_fcdns_fc4type_llcsnap FCDNS_HFI_INIT =
          {"LLC/SNAP", "fcdns.fc4types.llc_snap", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), 0x0010, NULL, HFILL};

static header_field_info hfi_fcdns_fc4type_ip FCDNS_HFI_INIT =
          {"IP", "fcdns.fc4types.ip", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), 0x0020, NULL, HFILL};

static header_field_info hfi_fcdns_fc4type_fcp FCDNS_HFI_INIT =
          {"FCP", "fcdns.fc4types.fcp", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), 0x0100, NULL, HFILL};

static header_field_info hfi_fcdns_fc4type_swils FCDNS_HFI_INIT =
          {"SW_ILS", "fcdns.fc4types.swils", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), 0x0010, NULL, HFILL};

static header_field_info hfi_fcdns_fc4type_snmp FCDNS_HFI_INIT =
          {"SNMP", "fcdns.fc4types.snmp", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), 0x0004, NULL, HFILL};

static header_field_info hfi_fcdns_fc4type_gs3 FCDNS_HFI_INIT =
          {"GS3", "fcdns.fc4types.gs3", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), 0x0001, NULL, HFILL};

static header_field_info hfi_fcdns_fc4type_vi FCDNS_HFI_INIT =
          {"VI", "fcdns.fc4types.vi", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), 0x0001, NULL, HFILL};

static header_field_info hfi_fcdns_fc4features FCDNS_HFI_INIT =
          {"FC-4 Feature Bits", "fcdns.fc4features", FT_UINT8,
           BASE_HEX, NULL, 0x0, NULL, HFILL};

static header_field_info hfi_fcdns_fc4features_i FCDNS_HFI_INIT =
          {"I", "fcdns.fc4features.i", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), 0x02, NULL, HFILL};

static header_field_info hfi_fcdns_fc4features_t FCDNS_HFI_INIT =
          {"T", "fcdns.fc4features.t", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), 0x01, NULL, HFILL};

static header_field_info hfi_fcdns_req_fc4type FCDNS_HFI_INIT =
          {"FC-4 Type", "fcdns.req.fc4type", FT_UINT8, BASE_HEX,
           VALS (fc_fc4_val), 0x0, NULL, HFILL};


/* Initialize the subtree pointers */
static gint ett_fcdns = -1;
static gint ett_cos_flags = -1;
static gint ett_fc4flags = -1;
static gint ett_fc4features = -1;

typedef struct _fcdns_conv_key {
    guint32 conv_idx;
} fcdns_conv_key_t;

typedef struct _fcdns_conv_data {
    guint32 opcode;
} fcdns_conv_data_t;

static GHashTable *fcdns_req_hash = NULL;

/*
 * Hash Functions
 */
static gint
fcdns_equal(gconstpointer v, gconstpointer w)
{
  const fcdns_conv_key_t *v1 = (const fcdns_conv_key_t *)v;
  const fcdns_conv_key_t *v2 = (const fcdns_conv_key_t *)w;

  return (v1->conv_idx == v2->conv_idx);
}

static guint
fcdns_hash (gconstpointer v)
{
    const fcdns_conv_key_t *key = (const fcdns_conv_key_t *)v;
    guint val;

    val = key->conv_idx;

    return val;
}

/*
 * Protocol initialization
 */
static void
fcdns_init_protocol(void)
{
    if (fcdns_req_hash)
        g_hash_table_destroy(fcdns_req_hash);

    fcdns_req_hash = g_hash_table_new(fcdns_hash, fcdns_equal);
}


static void
dissect_cos_flags (proto_tree *parent_tree, tvbuff_t *tvb, int offset, const header_field_info *hfinfo)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    guint32 flags;

    flags = tvb_get_ntohl (tvb, offset);
    if(parent_tree){
        item=proto_tree_add_uint(parent_tree, hfinfo,
                                 tvb, offset, 1, flags);
        tree=proto_item_add_subtree(item, ett_cos_flags);
    }


    proto_tree_add_boolean(tree, &hfi_fcdns_cos_f, tvb, offset, 4, flags);
    if (flags&0x01){
        proto_item_append_text(item, "  F");
    }
    flags&=(~( 0x01 ));

    proto_tree_add_boolean(tree, &hfi_fcdns_cos_1, tvb, offset, 4, flags);
    if (flags&0x02){
        proto_item_append_text(item, "  1");
    }
    flags&=(~( 0x02 ));

    proto_tree_add_boolean(tree, &hfi_fcdns_cos_2, tvb, offset, 4, flags);
    if (flags&0x04){
        proto_item_append_text(item, "  2");
    }
    flags&=(~( 0x04 ));

    proto_tree_add_boolean(tree, &hfi_fcdns_cos_3, tvb, offset, 4, flags);
    if (flags&0x08){
        proto_item_append_text(item, "  3");
    }
    flags&=(~( 0x08 ));

    proto_tree_add_boolean(tree, &hfi_fcdns_cos_4, tvb, offset, 4, flags);
    if (flags&0x10){
        proto_item_append_text(item, "  4");
    }
    flags&=(~( 0x10 ));

    proto_tree_add_boolean(tree, &hfi_fcdns_cos_6, tvb, offset, 4, flags);
    if (flags&0x40){
        proto_item_append_text(item, "  6");
    }
    /*flags&=(~( 0x40 ));*/
}



/* The feature routines just decode FCP's FC-4 features field
 * based on the flahs in offset and the type in offset+1
 */
static void
dissect_fc4features_and_type (proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    guint8 flags, type;

    flags = tvb_get_guint8(tvb, offset);
    type = tvb_get_guint8(tvb, offset+1);
    if(parent_tree){
        item=proto_tree_add_uint(parent_tree, &hfi_fcdns_fc4features,
                                 tvb, offset, 1, flags);
        tree=proto_item_add_subtree(item, ett_fc4features);
    }

    if(type==FC_TYPE_SCSI){
        proto_tree_add_boolean(tree, &hfi_fcdns_fc4features_i, tvb, offset, 1, flags);
        if (flags&0x02){
            proto_item_append_text(item, "  I");
        }
        flags&=(~( 0x02 ));

        proto_tree_add_boolean(tree, &hfi_fcdns_fc4features_t, tvb, offset, 1, flags);
        if (flags&0x01){
            proto_item_append_text(item, "  T");
        }
        /*flags&=(~( 0x01 ));*/
    }

    proto_tree_add_item (tree, &hfi_fcdns_req_fc4type, tvb, offset+1, 1, ENC_BIG_ENDIAN);
}

/* The feature routines just decode FCP's FC-4 features field
 */
static void
dissect_fc4features (proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    guint8 flags;

    flags = tvb_get_guint8(tvb, offset);
    if(parent_tree){
        item=proto_tree_add_uint(parent_tree, &hfi_fcdns_fc4features,
                                 tvb, offset, 1, flags);
        tree=proto_item_add_subtree(item, ett_fc4features);
    }

    proto_tree_add_boolean(tree, &hfi_fcdns_fc4features_i, tvb, offset, 1, flags);
    if (flags&0x02){
        proto_item_append_text(item, "  I");
    }
    flags&=(~( 0x02 ));

    proto_tree_add_boolean(tree, &hfi_fcdns_fc4features_t, tvb, offset, 1, flags);
    if (flags&0x01){
        proto_item_append_text(item, "  T");
    }
    /*flags&=(~( 0x01 ));*/
}



/* Decodes LLC/SNAP, IP, FCP, VI, GS, SW_ILS types only */
static void
dissect_fc4type (proto_tree *parent_tree, tvbuff_t *tvb, int offset, header_field_info *hfinfo)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    guint32 flags;

    if(parent_tree){
        item=proto_tree_add_item(parent_tree, hfinfo, tvb, offset,
                                 32, ENC_NA);
        tree=proto_item_add_subtree(item, ett_fc4flags);
    }

    flags = tvb_get_ntohl (tvb, offset);

    proto_tree_add_boolean(tree, &hfi_fcdns_fc4type_fcp, tvb, offset, 4, flags);
    if (flags&0x0100){
        proto_item_append_text(item, "  FCP");
    }
    flags&=(~( 0x0100 ));

    proto_tree_add_boolean(tree, &hfi_fcdns_fc4type_ip, tvb, offset, 4, flags);
    if (flags&0x0020){
        proto_item_append_text(item, "  IP");
    }
    flags&=(~( 0x0020 ));

    proto_tree_add_boolean(tree, &hfi_fcdns_fc4type_llcsnap, tvb, offset, 4, flags);
    if (flags&0x0010){
        proto_item_append_text(item, "  LLC/SNAP");
    }
    /*flags&=(~( 0x0010 ));*/


    flags = tvb_get_ntohl (tvb, offset+4);

    proto_tree_add_boolean(tree, &hfi_fcdns_fc4type_swils, tvb, offset+4, 4, flags);
    if (flags&0x0010){
        proto_item_append_text(item, "  SW_ILS");
    }
    flags&=(~( 0x0010 ));

    proto_tree_add_boolean(tree, &hfi_fcdns_fc4type_snmp, tvb, offset+4, 4, flags);
    if (flags&0x0004){
        proto_item_append_text(item, "  SNMP");
    }
    flags&=(~( 0x0004 ));

    proto_tree_add_boolean(tree, &hfi_fcdns_fc4type_gs3, tvb, offset+4, 4, flags);
    if (flags&0x0001){
        proto_item_append_text(item, "  GS3");
    }
    /*flags&=(~( 0x0001 ));*/


    flags = tvb_get_ntohl (tvb, offset+8);

    proto_tree_add_boolean(tree, &hfi_fcdns_fc4type_vi, tvb, offset+8, 4, flags);
    if (flags&0x0001){
        proto_item_append_text(item, "  VI");
    }
    /*flags&=(~( 0x0001 ));*/
}

/* Code to actually dissect the packets */

/* A bunch of get routines have a similar req packet format. The first few
 * routines deal with this decoding. All assume that tree is valid */
static void
dissect_fcdns_req_portid (tvbuff_t *tvb, proto_tree *tree, int offset)
{
    if (tree) {
        proto_tree_add_string (tree, &hfi_fcdns_req_portid, tvb, offset, 3,
                               tvb_fc_to_str (tvb, offset));
    }
}

static void
dissect_fcdns_ganxt (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 len;

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_item (req_tree, &hfi_fcdns_rply_ptype, tvb, offset,
                                 1, ENC_BIG_ENDIAN);
            proto_tree_add_string (req_tree, &hfi_fcdns_rply_portid, tvb,
                                   offset+1, 3,
                                   tvb_fc_to_str (tvb, offset+1));
            proto_tree_add_string (req_tree, &hfi_fcdns_rply_pname, tvb,
                                   offset+4, 8,
                                   tvb_fcwwn_to_str (tvb, offset+4));
            len = tvb_get_guint8 (tvb, offset+12);
            proto_tree_add_item (req_tree, &hfi_fcdns_rply_spnamelen, tvb,
                                 offset+12, 1, ENC_BIG_ENDIAN);
            if (!tvb_offset_exists (tvb, 29+len))
                return;

            if (len) {
                proto_tree_add_item (req_tree, &hfi_fcdns_rply_spname, tvb,
                                     offset+13, len, ENC_ASCII|ENC_NA);
            }

            if (tvb_offset_exists (tvb, 292)) {
                proto_tree_add_string (req_tree, &hfi_fcdns_rply_nname, tvb,
                                       offset+268, 8,
                                       tvb_fcwwn_to_str (tvb, offset+268));
            }
            if (tvb_offset_exists (tvb, 548)) {
                len = tvb_get_guint8 (tvb, offset+276);
                proto_tree_add_item (req_tree, &hfi_fcdns_rply_snamelen, tvb,
                                     offset+276, 1, ENC_BIG_ENDIAN);
                if (len) {
                    proto_tree_add_item (req_tree, &hfi_fcdns_rply_sname, tvb,
                                         offset+277, len, ENC_ASCII|ENC_NA);
                }
            }
            if (tvb_offset_exists (tvb, 556)) {
                proto_tree_add_item (req_tree, &hfi_fcdns_rply_ipa, tvb,
                                     offset+532, 8, ENC_NA);
            }
            if (tvb_offset_exists (tvb, 572)) {
                proto_tree_add_item (req_tree, &hfi_fcdns_rply_ipnode, tvb,
                                     offset+540, 16, ENC_NA);
            }
            if (tvb_offset_exists (tvb, 576)) {
                dissect_cos_flags(req_tree, tvb, offset+556, &hfi_fcdns_reply_cos);
            }
            if (tvb_offset_exists (tvb, 608)) {
                dissect_fc4type(req_tree, tvb, offset+560, &hfi_fcdns_rply_gft);
            }
            if (tvb_offset_exists (tvb, 624)) {
                proto_tree_add_item (req_tree, &hfi_fcdns_rply_ipport, tvb,
                                     offset+592, 16, ENC_NA);
            }
            if (tvb_offset_exists (tvb, 632)) {
                proto_tree_add_string (req_tree, &hfi_fcdns_rply_fpname, tvb,
                                       offset+608, 8,
                                       tvb_fcwwn_to_str (tvb, offset+608));
            }
            if (tvb_offset_exists (tvb, 635)) {
                proto_tree_add_string (req_tree, &hfi_fcdns_rply_hrdaddr, tvb,
                                       offset+617, 3,
                                       tvb_fc_to_str (tvb, offset+617));
            }
        }
    }
}

static void
dissect_fcdns_gpnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_string (req_tree, &hfi_fcdns_rply_pname, tvb, offset,
                                   8, tvb_fcwwn_to_str (tvb, offset));
        }
    }
}

static void
dissect_fcdns_gnnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_string (req_tree, &hfi_fcdns_rply_nname, tvb,
                                   offset, 8,
                                   tvb_fcwwn_to_str (tvb, offset));
        }
    }
}

static void
dissect_fcdns_gcsid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset);
        }
        else {
            dissect_cos_flags(req_tree, tvb, offset, &hfi_fcdns_reply_cos);
        }
    }
}

static void
dissect_fcdns_gftid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            dissect_fc4type(req_tree, tvb, offset, &hfi_fcdns_rply_gft);
        }
    }
}

static void
dissect_fcdns_gspnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 len;

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_item (req_tree, &hfi_fcdns_rply_spnamelen,
                                 tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, &hfi_fcdns_rply_spname, tvb,
                                 offset+1, len, ENC_ASCII|ENC_NA);
        }
    }
}

static void
dissect_fcdns_gptid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_item (req_tree, &hfi_fcdns_rply_ptype, tvb,
                                 offset, 1, ENC_BIG_ENDIAN);
        }
    }
}

static void
dissect_fcdns_gfpnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_string (req_tree, &hfi_fcdns_rply_fpname, tvb,
                                   offset, 8,
                                   tvb_fcwwn_to_str (tvb, offset));
        }
    }

}

static void
dissect_fcdns_gfdid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int tot_len, desclen;

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
            dissect_fc4type(req_tree, tvb, offset+4, &hfi_fcdns_fc4type);
        }
        else {
            tot_len = tvb_reported_length_remaining (tvb, offset); /* excluding CT header */
            while (tot_len > 0) {
                /* The count of the descriptors is not returned and so we have
                 * to track the display by the length field */
                desclen = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (req_tree, &hfi_fcdns_rply_fc4desc, tvb,
                                     offset, desclen, ENC_NA);
                tot_len -= 255; /* descriptors are aligned to 255 bytes */
                offset += 256;
            }
        }
    }
}

static void
dissect_fcdns_gffid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            dissect_fc4features(req_tree, tvb, offset);
        }
    }
}

static void
dissect_fcdns_gidpn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            proto_tree_add_string (req_tree, &hfi_fcdns_req_pname, tvb,
                                   offset, 8,
                                   tvb_fcwwn_to_str (tvb, offset));
        }
        else {
            proto_tree_add_string (req_tree, &hfi_fcdns_rply_portid, tvb,
                                   offset+1, 3,
                                   tvb_fc_to_str (tvb, offset+1));
        }
    }
}

static void
dissect_fcdns_gipppn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            proto_tree_add_string (req_tree, &hfi_fcdns_req_pname, tvb,
                                   offset, 8,
                                   tvb_fcwwn_to_str (tvb, offset));
        }
        else {
            proto_tree_add_item (req_tree, &hfi_fcdns_rply_ipport, tvb, offset,
                                 16, ENC_NA);
        }
    }
}

static void
dissect_fcdns_gidnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_string (req_tree, &hfi_fcdns_req_nname, tvb,
                                   offset, 8,
                                   tvb_fcwwn_to_str (tvb, offset));
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_string (req_tree, &hfi_fcdns_rply_portid,
                                       tvb, offset+1, 3,
                                       tvb_fc_to_str (tvb, offset+1));
                offset += 4;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gipnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            proto_tree_add_string (req_tree, &hfi_fcdns_req_nname, tvb,
                                   offset, 8,
                                   tvb_fcwwn_to_str (tvb, offset));
        }
        else {
            proto_tree_add_item (req_tree, &hfi_fcdns_rply_ipnode, tvb, offset,
                                 16, ENC_NA);
        }
    }
}

static void
dissect_fcdns_gpnnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_string (req_tree, &hfi_fcdns_req_nname, tvb,
                                   offset, 8,
                                   tvb_fcwwn_to_str (tvb, offset));
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_string (req_tree, &hfi_fcdns_rply_portid,
                                       tvb, offset+1, 3,
                                       tvb_fc_to_str (tvb, offset+1));
                proto_tree_add_string (req_tree, &hfi_fcdns_rply_pname,
                                       tvb, offset+8, 8,
                                       tvb_fcwwn_to_str (tvb, offset+8));
                offset += 16;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gsnnnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 len;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_string (req_tree, &hfi_fcdns_req_nname, tvb,
                                   offset, 8,
                                   tvb_fcwwn_to_str (tvb, offset));
        }
        else {
            len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_item (req_tree, &hfi_fcdns_rply_snamelen, tvb,
                                 offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, &hfi_fcdns_rply_sname, tvb,
                                 offset+1, len, ENC_ASCII|ENC_NA);
        }
    }
}

static void
dissect_fcdns_gidft (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, &hfi_fcdns_req_domainscope,
                                 tvb, offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, &hfi_fcdns_req_areascope,
                                 tvb, offset+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, &hfi_fcdns_req_fc4type,
                                 tvb, offset+3, 1, ENC_BIG_ENDIAN);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_string (req_tree, &hfi_fcdns_rply_portid,
                                       tvb, offset+1, 3,
                                       tvb_fc_to_str (tvb, offset+1));
                offset += 4;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gpnft (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, &hfi_fcdns_req_domainscope,
                                 tvb, offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, &hfi_fcdns_req_areascope,
                                 tvb, offset+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, &hfi_fcdns_req_fc4type,
                                 tvb, offset+3, 1, ENC_BIG_ENDIAN);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_string (req_tree, &hfi_fcdns_rply_portid,
                                       tvb, offset+1, 3,
                                       tvb_fc_to_str (tvb, offset+1));
                proto_tree_add_string (req_tree, &hfi_fcdns_rply_pname,
                                       tvb, offset+4, 8,
                                       tvb_fcwwn_to_str (tvb, offset+8));
                offset += 16;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gnnft (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, &hfi_fcdns_req_domainscope,
                                 tvb, offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, &hfi_fcdns_req_areascope,
                                 tvb, offset+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, &hfi_fcdns_req_fc4type,
                                 tvb, offset+3, 1, ENC_BIG_ENDIAN);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_string (req_tree, &hfi_fcdns_rply_portid,
                                       tvb, offset+1, 3,
                                       tvb_fc_to_str (tvb, offset+1));
                proto_tree_add_string (req_tree, &hfi_fcdns_rply_nname,
                                       tvb, offset+4, 8,
                                       tvb_fcwwn_to_str (tvb, offset+8));
                offset += 16;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gidpt (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast = 0;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, &hfi_fcdns_req_ptype,
                                 tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, &hfi_fcdns_req_domainscope,
                                 tvb, offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, &hfi_fcdns_req_areascope,
                                 tvb, offset+2, 1, ENC_BIG_ENDIAN);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_string (req_tree, &hfi_fcdns_rply_portid,
                                       tvb, offset+1, 3,
                                       tvb_fc_to_str (tvb, offset+1));
                offset += 4;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gidipp (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, &hfi_fcdns_req_ip, tvb, offset,
                                 16, ENC_NA);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_string (req_tree, &hfi_fcdns_rply_portid,
                                       tvb, offset+1, 3,
                                       tvb_fc_to_str (tvb, offset+1));
                offset += 4;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gidff (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, &hfi_fcdns_req_domainscope, tvb,
                                 offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, &hfi_fcdns_req_areascope, tvb,
                                 offset+2, 1, ENC_BIG_ENDIAN);
            dissect_fc4features_and_type(req_tree, tvb, offset+6);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_string (req_tree, &hfi_fcdns_rply_portid,
                                       tvb, offset+1, 3,
                                       tvb_fc_to_str (tvb, offset+1));
                offset += 4;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_rpnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            proto_tree_add_string (req_tree, &hfi_fcdns_req_portid,
                                   tvb, offset+1, 3,
                                   tvb_fc_to_str (tvb, offset+1));
            proto_tree_add_string (req_tree, &hfi_fcdns_req_pname, tvb,
                                   offset+4, 8,
                                   tvb_fcwwn_to_str (tvb, offset+4));
        }
    }
}

static void
dissect_fcdns_rnnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            proto_tree_add_string (req_tree, &hfi_fcdns_req_portid,
                                   tvb, offset+1, 3,
                                   tvb_fc_to_str (tvb, offset+1));
            proto_tree_add_string (req_tree, &hfi_fcdns_req_nname, tvb,
                                   offset+4, 8,
                                   tvb_fcwwn_to_str (tvb, offset+4));
        }
    }
}

static void
dissect_fcdns_rcsid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, &hfi_fcdns_req_portid, tvb,
                               offset+1, 3,
                               tvb_fc_to_str (tvb, offset+1));
        dissect_cos_flags(req_tree, tvb, offset+4, &hfi_fcdns_req_cos);
    }
}

static void
dissect_fcdns_rptid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, &hfi_fcdns_req_portid, tvb,
                               offset+1, 3,
                               tvb_fc_to_str (tvb, offset+1));
        proto_tree_add_item (req_tree, &hfi_fcdns_req_ptype, tvb,
                             offset+4, 1, ENC_BIG_ENDIAN);
    }
}

static void
dissect_fcdns_rftid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, &hfi_fcdns_req_portid, tvb,
                               offset+1, 3,
                               tvb_fc_to_str (tvb, offset+1));
        dissect_fc4type(req_tree, tvb, offset+4, &hfi_fcdns_req_fc4types);
    }
}

static void
dissect_fcdns_rspnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 len;

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, &hfi_fcdns_req_portid, tvb,
                               offset+1, 3,
                               tvb_fc_to_str (tvb, offset+1));
        proto_tree_add_item (req_tree, &hfi_fcdns_req_spnamelen, tvb,
                             offset+4, 1, ENC_BIG_ENDIAN);
        len = tvb_get_guint8 (tvb, offset+4);

        proto_tree_add_item (req_tree, &hfi_fcdns_req_spname, tvb, offset+5,
                             len, ENC_ASCII|ENC_NA);
    }
}

static void
dissect_fcdns_rippid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, &hfi_fcdns_req_portid, tvb,
                               offset+1, 3,
                               tvb_fc_to_str (tvb, offset+1));
        proto_tree_add_item (req_tree, &hfi_fcdns_req_ip, tvb,
                             offset+4, 16, ENC_NA);
    }
}

static void
dissect_fcdns_rfdid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int len;

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, &hfi_fcdns_req_portid, tvb,
                               offset+1, 3,
                               tvb_fc_to_str (tvb, offset+1));
        dissect_fc4type(req_tree, tvb, offset+4, &hfi_fcdns_req_fc4types);

        offset += 36;
        len = tvb_reported_length_remaining (tvb, offset);

        while (len > 0) {
            proto_tree_add_item (req_tree, &hfi_fcdns_req_fdesclen, tvb, offset,
                                 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, &hfi_fcdns_req_fdesc, tvb, offset+1,
                                 len, ENC_ASCII|ENC_NA);
            offset += 256;
            len -= 256;
        }
    }
}

static void
dissect_fcdns_rffid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, &hfi_fcdns_req_portid, tvb, offset+1, 3,
                               tvb_fc_to_str (tvb, offset+1));
        dissect_fc4features_and_type(req_tree, tvb, offset+6);
    }
}

static void
dissect_fcdns_ripnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, &hfi_fcdns_req_nname, tvb, offset, 8,
                               tvb_fcwwn_to_str (tvb, offset));
        proto_tree_add_item (req_tree, &hfi_fcdns_req_ip, tvb, offset+8, 16, ENC_NA);
    }
}

static void
dissect_fcdns_rsnnnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 len;

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, &hfi_fcdns_req_nname, tvb, offset, 8,
                               tvb_fcwwn_to_str (tvb, offset));
        len = tvb_get_guint8 (tvb, offset+8);

        proto_tree_add_item (req_tree, &hfi_fcdns_req_snamelen, tvb, offset+8,
                             1, ENC_BIG_ENDIAN);
        proto_tree_add_item (req_tree, &hfi_fcdns_req_sname, tvb, offset+9,
                             len, ENC_ASCII|ENC_NA);
    }
}

static void
dissect_fcdns_daid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree && isreq) {
        proto_tree_add_string (req_tree, &hfi_fcdns_req_portid, tvb, offset+1, 3,
                               tvb_fc_to_str (tvb, offset+1));
    }
}

static guint8 *
zonenm_to_str (tvbuff_t *tvb, gint offset)
{
    int len = tvb_get_guint8 (tvb, offset);
    return tvb_get_string_enc(wmem_packet_scope(), tvb, offset+4, len, ENC_ASCII);
}

static void
dissect_fcdns_zone_mbr (tvbuff_t *tvb, proto_tree *zmbr_tree, int offset)
{
    guint8 mbrtype;
    int idlen;
    char dpbuf[2+8+1];
    char *str;

    mbrtype = tvb_get_guint8 (tvb, offset);
    proto_tree_add_uint (zmbr_tree, &hfi_fcdns_zone_mbrtype, tvb,
                         offset, 1, mbrtype);
    proto_tree_add_text (zmbr_tree, tvb, offset+2, 1, "Flags: 0x%x",
                         tvb_get_guint8 (tvb, offset+2));
    idlen = tvb_get_guint8 (tvb, offset+3);
    proto_tree_add_text (zmbr_tree, tvb, offset+3, 1,
                         "Identifier Length: %d", idlen);
    switch (mbrtype) {
    case FC_SWILS_ZONEMBR_WWN:
        proto_tree_add_string (zmbr_tree, &hfi_fcdns_zone_mbrid, tvb,
                               offset+4, 8,
                               tvb_fcwwn_to_str (tvb, offset+4));
        break;
    case FC_SWILS_ZONEMBR_DP:
        g_snprintf(dpbuf, sizeof(dpbuf), "0x%08x", tvb_get_ntohl (tvb, offset+4));
        proto_tree_add_string (zmbr_tree, &hfi_fcdns_zone_mbrid, tvb,
                               offset+4, 4, dpbuf);
        break;
    case FC_SWILS_ZONEMBR_FCID:
        proto_tree_add_string (zmbr_tree, &hfi_fcdns_zone_mbrid, tvb,
                               offset+4, 4,
                               tvb_fc_to_str (tvb, offset+5));
        break;
    case FC_SWILS_ZONEMBR_ALIAS:
        str = zonenm_to_str (tvb, offset+4);
        proto_tree_add_string (zmbr_tree, &hfi_fcdns_zone_mbrid, tvb,
                               offset+4, idlen, str);
        break;
    default:
        proto_tree_add_string (zmbr_tree, &hfi_fcdns_zone_mbrid, tvb,
                               offset+4, idlen,
                               "Unknown member type format");

    }
}

static void
dissect_fcdns_swils_entries (tvbuff_t *tvb, proto_tree *tree, int offset)
{
    int numrec, i, len;
    guint8 objfmt;

    numrec = tvb_get_ntohl (tvb, offset);

    if (tree) {
        proto_tree_add_text (tree, tvb, offset, 4, "Number of Entries: %d",
                             numrec);
        offset += 4;

        for (i = 0; i < numrec; i++) {
            objfmt = tvb_get_guint8 (tvb, offset);

            proto_tree_add_item (tree, &hfi_fcdns_sw2_objfmt, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_string (tree, &hfi_fcdns_rply_ownerid, tvb, offset+1,
                                   3, fc_to_str (tvb_get_string_enc(wmem_packet_scope(), tvb, offset+1,
                                                              3, ENC_ASCII)));
            proto_tree_add_item (tree, &hfi_fcdns_rply_ptype, tvb, offset+4,
                                 1, ENC_BIG_ENDIAN);
            proto_tree_add_string (tree, &hfi_fcdns_rply_portid, tvb, offset+5, 3,
                                   tvb_fc_to_str (tvb, offset+5));
            proto_tree_add_string (tree, &hfi_fcdns_rply_pname, tvb, offset+8, 8,
                                   tvb_fcwwn_to_str (tvb, offset+8));
            offset += 16;
            if (!(objfmt & 0x1)) {
                len = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (tree, &hfi_fcdns_rply_spnamelen, tvb,
                                     offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, &hfi_fcdns_rply_spname, tvb,
                                     offset+1, len, ENC_ASCII|ENC_NA);
                offset += 256;
            }
            proto_tree_add_string (tree, &hfi_fcdns_rply_nname, tvb, offset, 8,
                                   tvb_fcwwn_to_str (tvb, offset));
            offset += 8;
            if (!(objfmt & 0x1)) {
                len = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (tree, &hfi_fcdns_rply_snamelen, tvb,
                                     offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, &hfi_fcdns_rply_sname, tvb,
                                     offset+1, len, ENC_ASCII|ENC_NA);
                offset += 256;
            }
            proto_tree_add_item (tree, &hfi_fcdns_rply_ipa, tvb, offset, 8, ENC_NA);
            proto_tree_add_item (tree, &hfi_fcdns_rply_ipnode, tvb, offset+8, 16,
                                 ENC_NA);
            dissect_cos_flags(tree, tvb, offset+24, &hfi_fcdns_reply_cos);
            dissect_fc4type(tree, tvb, offset+28, &hfi_fcdns_rply_gft);
            proto_tree_add_item (tree, &hfi_fcdns_rply_ipport, tvb, offset+60,
                                 16, ENC_NA);
            proto_tree_add_string (tree, &hfi_fcdns_rply_fpname, tvb, offset+76,
                                   8, tvb_fcwwn_to_str (tvb, offset+76));
            proto_tree_add_string (tree, &hfi_fcdns_rply_hrdaddr, tvb, offset+85,
                                   3, tvb_fc_to_str (tvb, offset+85));
            offset += 88;
            if (objfmt & 0x2) {
                dissect_fc4features(tree, tvb, offset);
                if (tvb_get_guint8 (tvb, offset+129)) {
                    proto_tree_add_item (tree, &hfi_fcdns_rply_fc4type, tvb,
                                         offset+128, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item (tree, &hfi_fcdns_num_fc4desc, tvb,
                                         offset+129, 1, ENC_BIG_ENDIAN);
                    len = tvb_get_guint8 (tvb, offset+132);
                    proto_tree_add_item (tree, &hfi_fcdns_rply_fc4desclen, tvb,
                                         offset+132, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item (tree, &hfi_fcdns_rply_fc4desc, tvb,
                                         offset+133, len, ENC_NA);
                }
                else {
                    proto_tree_add_item (tree, &hfi_fcdns_num_fc4desc, tvb,
                                         offset+129, 1, ENC_BIG_ENDIAN);
                }
                offset += 388;  /* FC4 desc is 260 bytes, maybe padded */
            }
        }
    }
}

static void
dissect_fcdns_geid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            proto_tree_add_string (req_tree, &hfi_fcdns_req_portid, tvb, offset+1,
                                   3, tvb_fc_to_str (tvb, offset+1));
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_gepn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    if (isreq) {
        if (req_tree) {
            proto_tree_add_string (req_tree, &hfi_fcdns_req_pname, tvb, offset, 8,
                                   tvb_fcwwn_to_str (tvb, offset));
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_genn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            proto_tree_add_string (req_tree, &hfi_fcdns_req_nname, tvb, offset, 8,
                                   tvb_fcwwn_to_str (tvb, offset));
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_geip (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            proto_tree_add_item (req_tree, &hfi_fcdns_req_ip, tvb, offset, 16, ENC_NA);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_geft (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            dissect_fc4type(req_tree, tvb, offset, &hfi_fcdns_fc4type);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_gept (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            proto_tree_add_item (req_tree, &hfi_fcdns_req_ptype, tvb, offset+3,
                                 1, ENC_BIG_ENDIAN);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_gezm (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            dissect_fcdns_zone_mbr (tvb, req_tree, offset);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_gezn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int str_len;

    if (isreq) {
        if (req_tree) {
            str_len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_text (req_tree, tvb, offset, 1, "Name Length: %d",
                                 str_len);
            proto_tree_add_item (req_tree, &hfi_fcdns_zonenm, tvb, offset+3,
                                 str_len, ENC_ASCII|ENC_NA);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_geipp (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            proto_tree_add_item (req_tree, &hfi_fcdns_portip, tvb, offset, 4, ENC_BIG_ENDIAN);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_geff (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            dissect_fc4features(req_tree, tvb, offset);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_rjt (tvbuff_t *tvb, proto_tree *req_tree)
{
    int offset = 0;

    if (req_tree) {
        proto_tree_add_item (req_tree, &hfi_fcdns_reason, tvb, offset+13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (req_tree, &hfi_fcdns_rjtdetail, tvb, offset+14, 1,
                             ENC_BIG_ENDIAN);
        proto_tree_add_item (req_tree, &hfi_fcdns_vendor, tvb, offset+15, 1, ENC_BIG_ENDIAN);
    }
}

static int
dissect_fcdns (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti = NULL;
    proto_tree *fcdns_tree = NULL;
    int offset = 0;
    int opcode,
        failed_opcode = 0;
    int isreq = 1;
    fc_ct_preamble cthdr;
    conversation_t *conversation;
    fcdns_conv_data_t *cdata;
    fcdns_conv_key_t ckey, *req_key;
    fc_hdr *fchdr;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    fchdr = (fc_hdr *)data;

    tvb_memcpy (tvb, (guint8 *)&cthdr, offset, FCCT_PRMBL_SIZE);
    cthdr.revision = tvb_get_guint8 (tvb, offset);
    cthdr.in_id = tvb_get_ntoh24 (tvb, offset+1);
    cthdr.opcode = g_ntohs (cthdr.opcode);
    opcode = cthdr.opcode;
    cthdr.maxres_size = g_ntohs (cthdr.maxres_size);

    /* Determine the type of server the request/response is for */
    if (cthdr.gstype == FCCT_GSTYPE_DIRSVC)
        col_set_str (pinfo->cinfo, COL_PROTOCOL, "dNS");
    else
        col_set_str (pinfo->cinfo, COL_PROTOCOL, "Unzoned NS");

    if (tree) {
        if (cthdr.gstype == FCCT_GSTYPE_DIRSVC) {
            ti = proto_tree_add_protocol_format (tree, hfi_fcdns->id, tvb, 0,
                                                 -1,
                                                 "dNS");
            fcdns_tree = proto_item_add_subtree (ti, ett_fcdns);
        }
        else {
            ti = proto_tree_add_protocol_format (tree, hfi_fcdns->id, tvb, 0,
                                                 -1,
                                                 "Unzoned NS");
            fcdns_tree = proto_item_add_subtree (ti, ett_fcdns);
        }
    }

    if ((opcode != FCCT_MSG_ACC) && (opcode != FCCT_MSG_RJT)) {
        conversation = find_conversation (pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                          pinfo->ptype, fchdr->oxid,
                                          fchdr->rxid, NO_PORT2);
        if (!conversation) {
            conversation = conversation_new (pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                             pinfo->ptype, fchdr->oxid,
                                             fchdr->rxid, NO_PORT2);
        }

        ckey.conv_idx = conversation->index;

        cdata = (fcdns_conv_data_t *)g_hash_table_lookup (fcdns_req_hash,
                                                            &ckey);
        if (cdata) {
            /* Since we never free the memory used by an exchange, this maybe a
             * case of another request using the same exchange as a previous
             * req.
             */
            cdata->opcode = opcode;
        }
        else {
            req_key = wmem_new(wmem_file_scope(), fcdns_conv_key_t);
            req_key->conv_idx = conversation->index;

            cdata = wmem_new(wmem_file_scope(), fcdns_conv_data_t);
            cdata->opcode = opcode;

            g_hash_table_insert (fcdns_req_hash, req_key, cdata);
        }
        col_add_str (pinfo->cinfo, COL_INFO, val_to_str (opcode, fc_dns_opcode_val,
                                                          "0x%x"));
    }
    else {
        /* Opcode is ACC or RJT */
        conversation = find_conversation (pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                          pinfo->ptype, fchdr->oxid,
                                          fchdr->rxid, NO_PORT2);
        isreq = 0;
        if (!conversation) {
            if (opcode == FCCT_MSG_ACC) {
                col_add_str (pinfo->cinfo, COL_INFO,
                                 val_to_str (opcode, fc_dns_opcode_val,
                                             "0x%x"));
                /* No record of what this accept is for. Can't decode */
                proto_tree_add_text (fcdns_tree, tvb, 0, -1,
                                     "No record of Exchg. Unable to decode MSG_ACC/RJT");
                return 0;
            }
        }
        else {
            ckey.conv_idx = conversation->index;

            cdata = (fcdns_conv_data_t *)g_hash_table_lookup (fcdns_req_hash, &ckey);

            if (cdata != NULL) {
                if (opcode == FCCT_MSG_ACC) {
                    opcode = cdata->opcode;
                }
                else
                    failed_opcode = cdata->opcode;
            }

            if (opcode != FCCT_MSG_RJT) {
                col_add_fstr (pinfo->cinfo, COL_INFO, "ACC (%s)",
                                val_to_str (opcode, fc_dns_opcode_val,
                                            "0x%x"));
            }
            else {
                col_add_fstr (pinfo->cinfo, COL_INFO, "RJT (%s)",
                                val_to_str (failed_opcode,
                                            fc_dns_opcode_val,
                                            "0x%x"));
            }

            if (tree) {
                if ((cdata == NULL) && (opcode != FCCT_MSG_RJT)) {
                    /* No record of what this accept is for. Can't decode */
                    proto_tree_add_text (fcdns_tree, tvb, 0, -1,
                                         "No record of Exchg. Unable to decode MSG_ACC/RJT");
                    return 0;
                }
            }
        }
    }

     if (tree) {
        proto_tree_add_item (fcdns_tree, &hfi_fcdns_opcode, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (fcdns_tree, &hfi_fcdns_maxres_size, tvb, offset+10,
                             2, ENC_BIG_ENDIAN);
    }

    switch (opcode) {
    case FCCT_MSG_RJT:
        dissect_fcdns_rjt (tvb, fcdns_tree);
        break;
    case FCDNS_GA_NXT:
        dissect_fcdns_ganxt (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GPN_ID:
        dissect_fcdns_gpnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GNN_ID:
        dissect_fcdns_gnnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GCS_ID:
        dissect_fcdns_gcsid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GFT_ID:
        dissect_fcdns_gftid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GSPN_ID:
        dissect_fcdns_gspnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GPT_ID:
        dissect_fcdns_gptid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GFPN_ID:
        dissect_fcdns_gfpnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GFD_ID:
        dissect_fcdns_gfdid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GFF_ID:
        dissect_fcdns_gffid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_PN:
        dissect_fcdns_gidpn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GIPP_PN:
        dissect_fcdns_gipppn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_NN:
        dissect_fcdns_gidnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GPN_NN:
        dissect_fcdns_gpnnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GIP_NN:
        dissect_fcdns_gipnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GSNN_NN:
        dissect_fcdns_gsnnnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_FT:
        dissect_fcdns_gidft (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GPN_FT:
        dissect_fcdns_gpnft (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GNN_FT:
        dissect_fcdns_gnnft (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_PT:
        dissect_fcdns_gidpt (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_IPP:
        dissect_fcdns_gidipp (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_FF:
        dissect_fcdns_gidff (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RPN_ID:
        dissect_fcdns_rpnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RNN_ID:
        dissect_fcdns_rnnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RCS_ID:
        dissect_fcdns_rcsid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RPT_ID:
        dissect_fcdns_rptid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RFT_ID:
        dissect_fcdns_rftid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RSPN_ID:
        dissect_fcdns_rspnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RIPP_ID:
        dissect_fcdns_rippid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RFD_ID:
        dissect_fcdns_rfdid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RFF_ID:
        dissect_fcdns_rffid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RIP_NN:
        dissect_fcdns_ripnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RSNN_NN:
        dissect_fcdns_rsnnnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_DA_ID:
        dissect_fcdns_daid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_ID:
        dissect_fcdns_geid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_PN:
        dissect_fcdns_gepn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_NN:
        dissect_fcdns_genn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_IP:
        dissect_fcdns_geip (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_FT:
        dissect_fcdns_geft (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_PT:
        dissect_fcdns_gept (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_ZM:
        dissect_fcdns_gezm (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_ZN:
        dissect_fcdns_gezn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_IPP:
        dissect_fcdns_geipp (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_FF:
        dissect_fcdns_geff (tvb, fcdns_tree, isreq);
        break;
    default:
        break;
    }

    return tvb_length(tvb);
}

/* Register the protocol with Wireshark */

void
proto_register_fcdns (void)
{
#ifndef HAVE_HFI_SECTION_INIT
    static header_field_info *hfi[] = {
        /* &hfi_fcdns_gssubtype */
        &hfi_fcdns_opcode,
        &hfi_fcdns_req_portid,
        &hfi_fcdns_rply_pname,
        &hfi_fcdns_rply_nname,
        &hfi_fcdns_rply_snamelen,
        &hfi_fcdns_rply_sname,
        &hfi_fcdns_rply_ptype,
        &hfi_fcdns_rply_fpname,
        &hfi_fcdns_req_pname,
        &hfi_fcdns_rply_portid,
        &hfi_fcdns_req_nname,
        &hfi_fcdns_req_domainscope,
        &hfi_fcdns_req_areascope,
        &hfi_fcdns_req_fc4type,
        &hfi_fcdns_req_ptype,
        &hfi_fcdns_req_ip,
        &hfi_fcdns_rply_fc4type,
        &hfi_fcdns_req_snamelen,
        &hfi_fcdns_req_sname,
        &hfi_fcdns_rply_spnamelen,
        &hfi_fcdns_rply_spname,
        &hfi_fcdns_rply_ipa,
        &hfi_fcdns_rply_ipnode,
        &hfi_fcdns_rply_ipport,
        &hfi_fcdns_rply_fc4desclen,
        &hfi_fcdns_rply_fc4desc,
        &hfi_fcdns_rply_hrdaddr,
        &hfi_fcdns_req_fdesclen,
        &hfi_fcdns_req_fdesc,
        &hfi_fcdns_req_spnamelen,
        &hfi_fcdns_req_spname,
        &hfi_fcdns_reason,
        &hfi_fcdns_rjtdetail,
        &hfi_fcdns_vendor,
        &hfi_fcdns_zone_mbrtype,
        &hfi_fcdns_zone_mbrid,
        &hfi_fcdns_zonenm,
        &hfi_fcdns_portip,
        &hfi_fcdns_sw2_objfmt,
        &hfi_fcdns_num_fc4desc,
        &hfi_fcdns_rply_ownerid,
        &hfi_fcdns_maxres_size,
        &hfi_fcdns_reply_cos,
        &hfi_fcdns_req_cos,
        &hfi_fcdns_cos_f,
        &hfi_fcdns_cos_1,
        &hfi_fcdns_cos_2,
        &hfi_fcdns_cos_3,
        &hfi_fcdns_cos_4,
        &hfi_fcdns_cos_6,
        &hfi_fcdns_fc4type_llcsnap,
        &hfi_fcdns_fc4type_ip,
        &hfi_fcdns_fc4type_fcp,
        &hfi_fcdns_fc4type_swils,
        &hfi_fcdns_fc4type_snmp,
        &hfi_fcdns_fc4type_gs3,
        &hfi_fcdns_fc4type_vi,
        &hfi_fcdns_rply_gft,
        &hfi_fcdns_req_fc4types,
        &hfi_fcdns_fc4type,
        &hfi_fcdns_fc4features,
        &hfi_fcdns_fc4features_i,
        &hfi_fcdns_fc4features_t,
    };
#endif

    static gint *ett[] = {
        &ett_fcdns,
        &ett_cos_flags,
        &ett_fc4flags,
        &ett_fc4features,
    };

    int proto_fcdns;

    proto_fcdns = proto_register_protocol("Fibre Channel Name Server",
                                          "FC-dNS", "fcdns");
    hfi_fcdns = proto_registrar_get_nth(proto_fcdns);

    proto_register_fields(proto_fcdns, hfi, array_length(hfi));
    proto_register_subtree_array(ett, array_length(ett));
    register_init_routine (&fcdns_init_protocol);

    dns_handle = new_create_dissector_handle (dissect_fcdns, proto_fcdns);
}

void
proto_reg_handoff_fcdns (void)
{
    dissector_add_uint("fcct.server", FCCT_GSRVR_DNS, dns_handle);
    dissector_add_uint("fcct.server", FCCT_GSRVR_UNS, dns_handle);
}
