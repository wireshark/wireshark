/* packet-dcerpc-oxid.c
 * Routines for DCOM OXID Resolver
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 *
 * $Id: packet-dcerpc-oxid.c,v 1.8 2003/09/24 08:05:50 guy Exp $
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

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-dcom.h"
#include "packet-smb-common.h"

static int proto_oxid = -1;

static int hf_opnum = -1;
static int hf_COMVERSION_MjrVer = -1;
static int hf_COMVERSION_MnrVer = -1;
static int hf_wNumEntries = -1;
static int hf_wSecurityOffset = -1;
static int hf_wTowerId = -1;
static int hf_aNetworkAddr = -1;
static int hf_wAuthnSvc = -1;
static int hf_wAuthzSvc = -1;
static int hf_aPrinceName = -1;
static int hf_Unknown1 = -1;
static int hf_Unknown2 = -1;

static gint ett_oxid = -1;

static e_uuid_t uuid_oxid = { 0x99fcfec4, 0x5260, 0x101b, { 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a } };
static guint16  ver_oxid = 0;

static const char *
authz_val2str(unsigned short authz) {
	switch (authz) {
		case 0:
			return "RPC_C_AUTHZ_NONE";
			break;
		case 1:
			return "RPC_C_AUTHZ_NAME";
			break;
		case 2:
			return "RPC_C_AUTHZ_DCE";
			break;
		case 0xffff: 
			return "Default";
			break;
		default: 
			return "Unknown";
			break;
	}
}

static const char *
authn_val2str(unsigned short authn) {
	switch (authn) {
		case 0:
			return "RPC_C_AUTHN_NONE";
			break;
		case 1:
			return "RPC_C_AUTHN_DCE_PRIVATE";
			break;
		case 2: 
			return "RPC_C_AUTHN_DCE_PUBLIC";
			break;
		case 4: 
			return "RPC_C_AUTHN_DEC_PUBLIC";
			break;
		case 9: 
			return "RPC_C_AUTHN_GSS_NEGOTIATE";
			break;
		case 10:
			return "RPC_C_AUTH_WINNT";
			break;
		case 14:
			return "RPC_C_AUTHN_GSS_SCHANNEL";
			break;
		case 16: 
			return "RPC_C_AUTHN_GSS_KERBEROS";
			break;
		case 17: 
			return "RPC_C_AUTHN_MSN";
			break;
		case 18:
			return "RPC_C_AUTHN_DPA";
			break;
		case 100:
			return "RPC_C_AUTHN_MQ";
			break;
		case 0xffff:
			return "RPC_C_AUTHN_DEFAULT";
			break;
		default:
			return "Unknown";
			break;
	}
}

static const char *
towerid_val2str(unsigned short tower) {
	switch (tower) {
		case 0x4:
			return "NCACN_DNET_NSP";
			break;
		case 0x7: 
			return "NCACN_IP_TCP";
			break;
		case 0x8:
			return "NCADG_IP_UDP";
			break;
		case 0xC:
			return "NCACN_SPX";
			break;

		case 0xD:
			return "NCACN_NB_IPX";
			break;
		case 0xE:
			return "NCADG_IPX";
			break;
		case 0x12: 
			return "NCACN_NB_NB";
			break;
		case 0x1F:
			return "NCACN_HTTP";
			break;
		default:
			return "Unknown";
			break;
	}
}

static int
oxid5_dissect_rply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, char *drep) {
	COMVERSION comver;
	DUALSTRINGARRAY stringarray;
	STRINGBINDING stringbind;
	SECURITYBINDING securitybind;
 	proto_item *bind_hdr, *entries_hdr, *sec_hdr;
	proto_tree *bind_tree, *entries_tree, *sec_tree;	
	char *aNetworkAddr = NULL;
	char *aPrinceName = NULL;
	unsigned short string_len = 0;
	unsigned short security_len = 0;
	unsigned char unknown1[8];
	unsigned char unknown2[8];

	dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_COMVERSION_MjrVer, &comver.MajorVersion);
	offset += sizeof(comver.MajorVersion);

	dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_COMVERSION_MnrVer, &comver.MinorVersion);
	offset += sizeof(comver.MinorVersion);

	dissect_dcerpc_uint64(tvb , offset, pinfo, tree, drep, hf_Unknown1, unknown1);

	offset += sizeof(unknown1); /*FIXME - understand what those 8 bytes mean! don't skip'em!*/
	string_len = dcerpc_tvb_get_ntohs(tvb, offset, drep) * 2;
	bind_hdr = proto_tree_add_text(tree, tvb, offset, (int)string_len, "DUALSTRINGARRAY structure");
	bind_tree = proto_item_add_subtree(bind_hdr, 0);

	dissect_dcerpc_uint16(tvb, offset, pinfo, bind_tree, drep, hf_wNumEntries, &stringarray.wNumEntries);
	offset += sizeof(stringarray.wNumEntries);

	security_len = dcerpc_tvb_get_ntohs(tvb, offset, drep) * 2;
	dissect_dcerpc_uint16(tvb, offset, pinfo, bind_tree, drep, hf_wSecurityOffset, &stringarray.wSecurityOffset);
        offset += sizeof(stringarray.wSecurityOffset);

	entries_hdr = proto_tree_add_text(bind_tree, tvb, offset, (int)security_len, "STRING BINDING");
	entries_tree = proto_item_add_subtree(entries_hdr, 0);

	while(tvb_get_ntohs(tvb, offset) != 0) { // check that this is not terminating zero
		
		stringbind.wTowerId = dcerpc_tvb_get_ntohs(tvb, offset, drep);
		proto_tree_add_text(entries_tree, tvb, offset, sizeof(stringbind.wTowerId), "Network Protocol ('TowerID'): %s (0x%x)",towerid_val2str(stringbind.wTowerId), stringbind.wTowerId);

		offset += sizeof(stringbind.wTowerId);

		offset = display_unicode_string(tvb, entries_tree, offset, hf_aNetworkAddr, &aNetworkAddr);	
	}	
	offset += 2; // hop over the extra terminating zero
	
	sec_hdr = proto_tree_add_text(bind_tree, tvb, offset, 0, "SECURITY BINDING");
        sec_tree = proto_item_add_subtree(sec_hdr, 0);

	while(tvb_get_ntohs(tvb, offset) != 0) {
		securitybind.wAuthnSvc = dcerpc_tvb_get_ntohs(tvb, offset, drep);
                proto_tree_add_text(sec_tree, tvb, offset, sizeof(securitybind.wAuthnSvc), "Authentication Service: %s (0x%x)",authn_val2str(securitybind.wAuthnSvc),securitybind.wAuthnSvc);
		offset += sizeof(securitybind.wAuthnSvc);

		securitybind.wAuthzSvc = dcerpc_tvb_get_ntohs(tvb, offset, drep);
		proto_tree_add_text(sec_tree, tvb, offset, sizeof(securitybind.wAuthzSvc), "Authorization Service: %s (0x%x)",authz_val2str(securitybind.wAuthzSvc),securitybind.wAuthzSvc);
		offset += sizeof(securitybind.wAuthzSvc);

		offset = display_unicode_string(tvb, sec_tree, offset, hf_aPrinceName, &aPrinceName);
	}
	offset += 2; // hop over the extra terminating zero
	
	dissect_dcerpc_uint64(tvb, offset, pinfo, tree, drep, hf_Unknown2, unknown2);
	offset += sizeof(unknown2);
        return offset;
}

static dcerpc_sub_dissector oxid_dissectors[] = {
    { 0, "ResolveOxid", NULL, NULL },
    { 1, "SimplePing", NULL, NULL },
    { 2, "ComplexPing", NULL, NULL },
    { 3, "ServerAlive", NULL, NULL },
    { 4, "Operation #4", NULL, NULL },
    { 5, "Oxid Operation #5", NULL, oxid5_dissect_rply },
    { 0, NULL, NULL, NULL },
};

void
proto_register_oxid (void)
{
	static hf_register_info hf[] = {
		{ &hf_opnum,
		  { "Operation", "oxid.opnum", FT_UINT16, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
                { &hf_COMVERSION_MjrVer,
                  { "COM Major Version", "oxid5.com_mjr_ver", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
                { &hf_COMVERSION_MnrVer,
                  { "COM Minor Version", "oxid5.com_mnr_ver", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_wNumEntries,
		  { "Total Entries length (in 16 bytes blocks)", "oxid5.NumEntries", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_wSecurityOffset,
		  { "Offset of Security Binding (in 16 bytes blocks)", "oxid5.SecurityOffset", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_wTowerId,
		  { "Network Protocol ('TowerID')", "oxid5.wTowerId", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_aNetworkAddr,
		  { "Network Address ('aNetworkAddr')", "oxid5.aNetworkAddr", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
		                { &hf_wAuthnSvc,
                  { "Authentication Service", "oxid5.AuthnSvc", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
                { &hf_wAuthzSvc,
                  { "Autherization Service", "oxid5.AuthzSvc", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
		{ &hf_aPrinceName,
                  { "aPrinceName", "oxid5.aPrinceName", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_Unknown1,
		  { "unknown 8 bytes 1", "oxid5.unknown1", FT_UINT64, BASE_HEX, NULL, 0x0, "", HFILL }},
		{ &hf_Unknown2,
                  { "unknown 8 bytes 2", "oxid5.unknown2", FT_UINT64, BASE_HEX, NULL, 0x0, "", HFILL }},
	};
	static gint *ett[] = {
		&ett_oxid
	};
	proto_oxid = proto_register_protocol ("DCOM OXID Resolver", "OXID", "oxid");
	proto_register_field_array (proto_oxid, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_oxid (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_oxid, ett_oxid, &uuid_oxid, ver_oxid, oxid_dissectors, hf_opnum);
}
