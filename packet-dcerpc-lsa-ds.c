/* packet-dcerpc-lsa-ds.c
 * Routines for SMB \PIPE\lsarpc packet disassembly
 * Copyright 2002-2003, Tim Potter <tpot@samba.org>
 * Copyright 2002, Jim McDonough <jmcd@samba.org>
 *
 * $Id: packet-dcerpc-lsa-ds.c,v 1.8 2003/01/30 08:19:37 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <string.h>

#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "smb.h"

#define LSA_DS_DSROLEGETDOMINFO 0x0000

#define LSA_DS_DSROLE_BASIC_INFO 0x0001
#define LSA_DS_DSROLE_UPGRADE_STATUS 0x0002
#define LSA_DS_DSROLE_OP_STATUS 0x0003

static int proto_dcerpc_lsa_ds = -1;

static int hf_lsa_ds_opnum = -1;
static int hf_lsa_ds_dominfo_level = -1;
static int hf_lsa_ds_machine_role = -1;
static int hf_lsa_ds_dominfo_flags = -1;
static int hf_lsa_ds_dominfo_netb_name = -1;
static int hf_lsa_ds_dominfo_dns_name = -1;
static int hf_lsa_ds_dominfo_forest_name = -1;
static int hf_lsa_ds_upgrade_state = -1;
static int hf_lsa_ds_previous_role = -1;
static int hf_lsa_ds_op_status = -1;
static int hf_lsa_ds_rc = -1;

static gint ett_dcerpc_lsa_ds = -1;
static gint ett_lsa_ds_domain_info = -1;
static gint ett_lsa_ds_basic_domain_info = -1;
static gint ett_lsa_ds_upgrade_status = -1;
static gint ett_lsa_ds_op_status = -1;

static int
lsa_ds_dissect_DSROLE_BASIC_INFO(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"DSROLE_BASIC_DOMAIN_INFO:");
		tree = proto_item_add_subtree(item, 
					      ett_lsa_ds_basic_domain_info);
	}

	ALIGN_TO_4_BYTES;
	/* role */
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
				    hf_lsa_ds_machine_role, 0);

	/* flags */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_lsa_ds_dominfo_flags, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "NetBIOS domain name pointer", 
		hf_lsa_ds_dominfo_netb_name, 0);
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "DNS domain pointer", 
		hf_lsa_ds_dominfo_dns_name, 0);
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "DNS forest name pointer", 
		hf_lsa_ds_dominfo_forest_name, 0);

	/* GUID */
	offset = dissect_nt_GUID(tvb, offset, pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int 
lsa_ds_dissect_DSROLE_UPGRADE_STATUS(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, 
				     proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"DSROLE_UPGRADE_STATUS:");
		tree = proto_item_add_subtree(item, 
					      ett_lsa_ds_upgrade_status);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_ds_upgrade_state, NULL);
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_ds_previous_role, NULL);
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

static int
lsa_ds_dissect_DSROLE_OP_STATUS(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, 
				     proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"DSROLE_OP_STATUS:");
		tree = proto_item_add_subtree(item, 
					      ett_lsa_ds_op_status);
	}
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_ds_op_status, NULL);
	proto_item_set_len(item, offset-old_offset);

	return offset;
}
	
static int
lsa_ds_dissect_DS_DOMINFO_CTR(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"DOMAIN_INFO:");
		tree = proto_item_add_subtree(item, ett_lsa_ds_domain_info);
	}

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_ds_dominfo_level, &level);

	switch(level){
	case LSA_DS_DSROLE_BASIC_INFO:
		offset = lsa_ds_dissect_DSROLE_BASIC_INFO(
			tvb, offset, pinfo, tree, drep);
		break;
	case LSA_DS_DSROLE_UPGRADE_STATUS:
		offset = lsa_ds_dissect_DSROLE_UPGRADE_STATUS(
			tvb, offset, pinfo, tree, drep);
		break;
	case LSA_DS_DSROLE_OP_STATUS:
		offset = lsa_ds_dissect_DSROLE_OP_STATUS(
			tvb, offset, pinfo, tree, drep);
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

static int
lsa_ds_dissect_role_get_dom_info_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
				    hf_lsa_ds_dominfo_level, NULL);
	return offset;
}

static int
lsa_ds_dissect_role_get_dom_info_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_ds_dissect_DS_DOMINFO_CTR, NDR_POINTER_UNIQUE,
		"DOMAIN_INFORMATION pointer", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_ds_rc, NULL);

	return offset;
}


static const value_string lsa_ds_opnum_vals[] = {
	{ LSA_DS_DSROLEGETDOMINFO, "DsRoleGetDomInfo" },
	{ 0, NULL }
};

static const value_string lsa_ds_dominfo_levels[] = {
	{ LSA_DS_DSROLE_BASIC_INFO, "DsRoleBasicInfo"},
	{ LSA_DS_DSROLE_UPGRADE_STATUS, "DsRoleUpgradeStatus"},
	{ LSA_DS_DSROLE_OP_STATUS, "DsRoleOpStatus"},
	{ 0, NULL }
};

static const value_string lsa_ds_role_vals[] = {
	{ 0, "Standalone Workstation" },
	{ 1, "Domain Member Workstation" },
	{ 2, "Standalone Server" },
	{ 3, "Domain Member Server" },
	{ 4, "Backup Domain Controller" },
	{ 5, "Primary Domain Controller" },
	{ 0, NULL }
};

static const value_string lsa_ds_upgrade_vals[] = {
	{ 0, "Not currently upgrading"},
	{ 1, "Upgrade in progress"},
	{ 0, NULL }
};

static const value_string lsa_ds_previous_roles[] = {
	{ 0, "Unknown state" },
	{ 1, "Primary" },
	{ 2, "Backup" },
	{ 0, NULL }
};

static const value_string lsa_ds_op_states[] = {
	{ 0, "Idle" },
	{ 1, "Active" },
	{ 2, "Needs reboot" },
	{ 0, NULL }
};

void
proto_register_dcerpc_lsa_ds(void)
{
        static hf_register_info hf[] = {

	{ &hf_lsa_ds_opnum,
	  { "Operation", "ls_ads.opnum", FT_UINT16, BASE_DEC,
	    VALS(lsa_ds_opnum_vals), 0x0, "Operation", HFILL }},
	
	{ &hf_lsa_ds_dominfo_level,
	  { "Level", "lsa_ds.dominfo.level", FT_UINT16, BASE_DEC,
	    VALS(lsa_ds_dominfo_levels), 0x0, 
	    "Information level of requested data", HFILL }},

	{ &hf_lsa_ds_machine_role,
	  { "Machine role", "lsa_ds.role", FT_UINT16, BASE_HEX,
	    VALS(lsa_ds_role_vals), 0x0, "Role of machine in domain", HFILL}},

	{ &hf_lsa_ds_dominfo_flags,
	  { "Flags", "lsa_ds.dominfo.flags", FT_UINT32, BASE_HEX,
	    NULL, 0x0, "Machine flags", HFILL }},

	{ &hf_lsa_ds_dominfo_netb_name,
	  { "Netbios name", "lsa_ds.dominfo.nbname", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Netbios Domain Name", HFILL}},

	{ &hf_lsa_ds_dominfo_dns_name,
	  { "DNS name", "lsa_ds.dominfo.dnsname", FT_STRING, BASE_NONE,
	    NULL, 0x0, "DNS Domain Name", HFILL}},

	{ &hf_lsa_ds_dominfo_forest_name,
	  { "Forest name", "lsa_ds.dominfo.forest", FT_STRING, BASE_NONE,
	    NULL, 0x0, "DNS Forest Name", HFILL}},

	{ &hf_lsa_ds_upgrade_state,
	  { "Upgrading", "ls_ads.upgrading", FT_UINT32, BASE_DEC,
	    VALS(lsa_ds_upgrade_vals), 0x0, "Upgrade State", HFILL }},
	
	{ &hf_lsa_ds_previous_role,
	  { "Previous role", "ls_ads.upgrading", FT_UINT16, BASE_DEC,
	    VALS(lsa_ds_previous_roles), 0x0, 
	    "Previous server role before upgrade", HFILL }},

	{ &hf_lsa_ds_op_status,
	  { "Operational status", "ls_ads.op_status", FT_UINT16, BASE_DEC,
	    VALS(lsa_ds_op_states), 0x0, 
	    "Current operational status", HFILL }},
	
	{ &hf_lsa_ds_rc,
	  { "Return code", "lsa_ds.rc", FT_UINT32, BASE_HEX,
	  VALS (NT_errors), 0x0, "LSA_DS return status code", HFILL }},
	};

        static gint *ett[] = {
                &ett_dcerpc_lsa_ds,
		&ett_lsa_ds_domain_info,
		&ett_lsa_ds_basic_domain_info,
		&ett_lsa_ds_upgrade_status,
		&ett_lsa_ds_op_status
        };

        proto_dcerpc_lsa_ds = proto_register_protocol(
                "Microsoft Local Security Architecture (Directory Services)", 
		"LSA_DS", "lsa_ds");
	proto_register_field_array(proto_dcerpc_lsa_ds, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}

/* Protocol handoff */

static e_uuid_t uuid_dcerpc_lsa_ds = {
        0x3919286a, 0xb10c, 0x11d0,
        { 0x9b, 0xa8, 0x00, 0xc0, 0x4f, 0xd9, 0x2e, 0xf5}
};

static guint16 ver_dcerpc_lsa_ds = 0;

static dcerpc_sub_dissector lsa_ds_dissectors[] = {
	{ LSA_DS_DSROLEGETDOMINFO, "DsRoleGetDomInfo", 
	  lsa_ds_dissect_role_get_dom_info_rqst, 
	  lsa_ds_dissect_role_get_dom_info_reply },
	{ 0, NULL, NULL, NULL },
};

void
proto_reg_handoff_dcerpc_lsa_ds(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_lsa_ds, ett_dcerpc_lsa_ds, 
			 &uuid_dcerpc_lsa_ds, ver_dcerpc_lsa_ds, 
			 lsa_ds_dissectors, -1);
}
