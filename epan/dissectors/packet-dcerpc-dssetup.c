/* packet-dcerpc-dssetup.c
 * Routines for SMB \PIPE\lsarpc packet disassembly
 * Copyright 2002-2003, Tim Potter <tpot@samba.org>
 * Copyright 2002, Jim McDonough <jmcd@samba.org>
 *
 * $Id$
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
#include "packet-windows-common.h"

#define DSSETUP_DSROLERGETDOMINFO 			0x0000
#define DSSETUP_DSROLER_DNS_NAME_TO_FLAT_NAME 		0x0001
#define DSSETUP_DSROLER_DC_AS_DC				0x0002
#define DSSETUP_DSROLER_DC_AS_REPLICA			0x0003
#define DSSETUP_DSROLER_DEMOTE_DC			0x0004
#define DSSETUP_DSROLER_GET_DC_OPERATION_PROGRESS	0x0005
#define DSSETUP_DSROLER_GET_DC_OPERATION_RESULTS		0x0006
#define DSSETUP_DSROLER_CANCEL				0x0007
#define DSSETUP_DSROLER_SERVER_SAVE_STATE_FOR_UPGRADE	0x0008
#define DSSETUP_DSROLER_UPGRADE_DOWNLEVEL_SERVER		0x0009
#define DSSETUP_DSROLER_ABORT_DOWNLEVEL_SERVER_UPGRADE	0x000a

#define DSSETUP_DSROLE_BASIC_INFO 0x0001
#define DSSETUP_DSROLE_UPGRADE_STATUS 0x0002
#define DSSETUP_DSROLE_OP_STATUS 0x0003

static int proto_dcerpc_dssetup = -1;

static int hf_dssetup_opnum = -1;
static int hf_dssetup_guid = -1;
static int hf_dssetup_dominfo_level = -1;
static int hf_dssetup_machine_role = -1;
static int hf_dssetup_dominfo_flags = -1;
static int hf_dssetup_dominfo_netb_name = -1;
static int hf_dssetup_dominfo_dns_name = -1;
static int hf_dssetup_dominfo_forest_name = -1;
static int hf_dssetup_upgrade_state = -1;
static int hf_dssetup_previous_role = -1;
static int hf_dssetup_op_status = -1;
static int hf_dssetup_rc = -1;

static gint ett_dcerpc_dssetup = -1;
static gint ett_dssetup_domain_info = -1;
static gint ett_dssetup_basic_domain_info = -1;
static gint ett_dssetup_upgrade_status = -1;
static gint ett_dssetup_op_status = -1;

static int
dssetup_dissect_DSROLE_BASIC_INFO(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"DSROLE_BASIC_DOMAIN_INFO:");
		tree = proto_item_add_subtree(item, 
					      ett_dssetup_basic_domain_info);
	}

	ALIGN_TO_4_BYTES;
	/* role */
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
				    hf_dssetup_machine_role, 0);

	/* flags */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_dssetup_dominfo_flags, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "NetBIOS domain name pointer", 
		hf_dssetup_dominfo_netb_name, 0);
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "DNS domain pointer", 
		hf_dssetup_dominfo_dns_name, 0);
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "DNS forest name pointer", 
		hf_dssetup_dominfo_forest_name, 0);

	/* GUID */
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, drep, hf_dssetup_guid, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int 
dssetup_dissect_DSROLE_UPGRADE_STATUS(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, 
				     proto_tree *parent_tree, guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"DSROLE_UPGRADE_STATUS:");
		tree = proto_item_add_subtree(item, 
					      ett_dssetup_upgrade_status);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_dssetup_upgrade_state, NULL);
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_dssetup_previous_role, NULL);
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

static int
dssetup_dissect_DSROLE_OP_STATUS(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, 
				     proto_tree *parent_tree, guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"DSROLE_OP_STATUS:");
		tree = proto_item_add_subtree(item, 
					      ett_dssetup_op_status);
	}
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_dssetup_op_status, NULL);
	proto_item_set_len(item, offset-old_offset);

	return offset;
}
	
static int
dssetup_dissect_DS_DOMINFO_CTR(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"DOMAIN_INFO:");
		tree = proto_item_add_subtree(item, ett_dssetup_domain_info);
	}

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_dssetup_dominfo_level, &level);

	switch(level){
	case DSSETUP_DSROLE_BASIC_INFO:
		offset = dssetup_dissect_DSROLE_BASIC_INFO(
			tvb, offset, pinfo, tree, drep);
		break;
	case DSSETUP_DSROLE_UPGRADE_STATUS:
		offset = dssetup_dissect_DSROLE_UPGRADE_STATUS(
			tvb, offset, pinfo, tree, drep);
		break;
	case DSSETUP_DSROLE_OP_STATUS:
		offset = dssetup_dissect_DSROLE_OP_STATUS(
			tvb, offset, pinfo, tree, drep);
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

static int
dssetup_dissect_role_get_dom_info_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint16 level;

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
				    hf_dssetup_dominfo_level, &level);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	return offset;
}

static int
dssetup_dissect_role_get_dom_info_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dssetup_dissect_DS_DOMINFO_CTR, NDR_POINTER_UNIQUE,
		"DOMAIN_INFORMATION pointer", -1);

	offset = dissect_ntstatus(
		tvb, offset, pinfo, tree, drep, hf_dssetup_rc, NULL);

	return offset;
}

static const value_string dssetup_dominfo_levels[] = {
	{ DSSETUP_DSROLE_BASIC_INFO, "DsRoleBasicInfo"},
	{ DSSETUP_DSROLE_UPGRADE_STATUS, "DsRoleUpgradeStatus"},
	{ DSSETUP_DSROLE_OP_STATUS, "DsRoleOpStatus"},
	{ 0, NULL }
};

static const value_string dssetup_role_vals[] = {
	{ 0, "Standalone Workstation" },
	{ 1, "Domain Member Workstation" },
	{ 2, "Standalone Server" },
	{ 3, "Domain Member Server" },
	{ 4, "Backup Domain Controller" },
	{ 5, "Primary Domain Controller" },
	{ 0, NULL }
};

static const value_string dssetup_upgrade_vals[] = {
	{ 0, "Not currently upgrading"},
	{ 1, "Upgrade in progress"},
	{ 0, NULL }
};

static const value_string dssetup_previous_roles[] = {
	{ 0, "Unknown state" },
	{ 1, "Primary" },
	{ 2, "Backup" },
	{ 0, NULL }
};

static const value_string dssetup_op_states[] = {
	{ 0, "Idle" },
	{ 1, "Active" },
	{ 2, "Needs reboot" },
	{ 0, NULL }
};

void
proto_register_dcerpc_dssetup(void)
{
        static hf_register_info hf[] = {

	{ &hf_dssetup_opnum,
	  { "Operation", "dssetup.opnum", FT_UINT16, BASE_DEC,
	    NULL, 0x0, "Operation", HFILL }},
	
	{ &hf_dssetup_dominfo_level,
	  { "Level", "dssetup.dominfo.level", FT_UINT16, BASE_DEC,
	    VALS(dssetup_dominfo_levels), 0x0, 
	    "Information level of requested data", HFILL }},

	{ &hf_dssetup_machine_role,
	  { "Machine role", "dssetup.role", FT_UINT16, BASE_HEX,
	    VALS(dssetup_role_vals), 0x0, "Role of machine in domain", HFILL}},

	{ &hf_dssetup_dominfo_flags,
	  { "Flags", "dssetup.dominfo.flags", FT_UINT32, BASE_HEX,
	    NULL, 0x0, "Machine flags", HFILL }},

	{ &hf_dssetup_dominfo_netb_name,
	  { "Netbios name", "dssetup.dominfo.nbname", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Netbios Domain Name", HFILL}},

	{ &hf_dssetup_dominfo_dns_name,
	  { "DNS name", "dssetup.dominfo.dnsname", FT_STRING, BASE_NONE,
	    NULL, 0x0, "DNS Domain Name", HFILL}},

	{ &hf_dssetup_guid,
	  { "GUID", "dssetup.guid", FT_STRING, BASE_NONE,
	    NULL, 0x0, "", HFILL}},

	{ &hf_dssetup_dominfo_forest_name,
	  { "Forest name", "dssetup.dominfo.forest", FT_STRING, BASE_NONE,
	    NULL, 0x0, "DNS Forest Name", HFILL}},

	{ &hf_dssetup_upgrade_state,
	  { "Upgrading", "dssetup.upgrading", FT_UINT32, BASE_DEC,
	    VALS(dssetup_upgrade_vals), 0x0, "Upgrade State", HFILL }},
	
	{ &hf_dssetup_previous_role,
	  { "Previous role", "dssetup.upgrading", FT_UINT16, BASE_DEC,
	    VALS(dssetup_previous_roles), 0x0, 
	    "Previous server role before upgrade", HFILL }},

	{ &hf_dssetup_op_status,
	  { "Operational status", "dssetup.op_status", FT_UINT16, BASE_DEC,
	    VALS(dssetup_op_states), 0x0, 
	    "Current operational status", HFILL }},
	
	{ &hf_dssetup_rc,
	  { "Return code", "dssetup.rc", FT_UINT32, BASE_HEX,
	  VALS (NT_errors), 0x0, "DSSETUP return status code", HFILL }},
	};

        static gint *ett[] = {
                &ett_dcerpc_dssetup,
		&ett_dssetup_domain_info,
		&ett_dssetup_basic_domain_info,
		&ett_dssetup_upgrade_status,
		&ett_dssetup_op_status
        };

        proto_dcerpc_dssetup = proto_register_protocol(
                "Active Directory Setup", 
		"DSSETUP", "dssetup");
	proto_register_field_array(proto_dcerpc_dssetup, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}

/* Protocol handoff */

static e_uuid_t uuid_dcerpc_dssetup = {
        0x3919286a, 0xb10c, 0x11d0,
        { 0x9b, 0xa8, 0x00, 0xc0, 0x4f, 0xd9, 0x2e, 0xf5}
};

static guint16 ver_dcerpc_dssetup = 0;

static dcerpc_sub_dissector dssetup_dissectors[] = {
	{ DSSETUP_DSROLERGETDOMINFO, "DsRolerGetDomInfo", 
	  dssetup_dissect_role_get_dom_info_rqst, 
	  dssetup_dissect_role_get_dom_info_reply },
	{ DSSETUP_DSROLER_DNS_NAME_TO_FLAT_NAME, 
	  "DsRolerDnsNameToFlatName", NULL, NULL },
	{ DSSETUP_DSROLER_DC_AS_DC, 
	  "DsRolerDcAsDc", NULL, NULL },
	{ DSSETUP_DSROLER_DC_AS_REPLICA,
	  "DsRolerDcAsReplica", NULL, NULL },
	{ DSSETUP_DSROLER_DEMOTE_DC,
	  "DsRolerDemoteDc", NULL, NULL },
	{ DSSETUP_DSROLER_GET_DC_OPERATION_PROGRESS,
	  "DsRolerGetDcOperationProgress", NULL, NULL },
	{ DSSETUP_DSROLER_GET_DC_OPERATION_RESULTS,
	  "DsRolerGetDcOperationResults", NULL, NULL },
	{ DSSETUP_DSROLER_CANCEL,
	  "DsRolerCancel", NULL, NULL },
	{ DSSETUP_DSROLER_SERVER_SAVE_STATE_FOR_UPGRADE, 
	  "DsRolerServerSaveStateForUpgrade", NULL, NULL },
	{ DSSETUP_DSROLER_UPGRADE_DOWNLEVEL_SERVER,
	  "DsRolerUpgradeDownlevelServer", NULL, NULL },
	{ DSSETUP_DSROLER_ABORT_DOWNLEVEL_SERVER_UPGRADE,
	  "DsRolerAbortDownlevelServerUpgrade", NULL, NULL },
	{ 0, NULL, NULL, NULL },
};

void
proto_reg_handoff_dcerpc_dssetup(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_dssetup, ett_dcerpc_dssetup, 
			 &uuid_dcerpc_dssetup, ver_dcerpc_dssetup, 
			 dssetup_dissectors, hf_dssetup_opnum);
}
