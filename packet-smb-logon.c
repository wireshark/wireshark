/* packet-smb-logon.c
 * Routines for SMB net logon packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id: packet-smb-logon.c,v 1.16 2001/07/08 22:56:22 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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

#include "packet-smb-common.h"
#include "packet-smb-logon.h"

static int proto_smb_logon = -1;
static int hf_command = -1;
static int hf_computer_name = -1;
static int hf_unicode_computer_name = -1;
static int hf_server_name = -1;
static int hf_user_name = -1;
static int hf_domain_name = -1;
static int hf_mailslot_name = -1;
static int hf_pdc_name = -1;
static int hf_unicode_pdc_name = -1;
static int hf_script_name = -1;
static int hf_nt_version = -1;
static int hf_lmnt_token = -1;
static int hf_lm_token = -1;
static int hf_major_version = -1;
static int hf_minor_version = -1;
static int hf_os_version = -1;
static int hf_date_time = -1;
static int hf_update_type = -1;
static int hf_request_count = -1;
static int hf_flags_autolock = -1;
static int hf_flags_expire = -1;
static int hf_flags_server_trust = -1;
static int hf_flags_workstation_trust = -1;
static int hf_flags_interdomain_trust = -1;
static int hf_flags_mns_user = -1;
static int hf_flags_normal_user = -1;
static int hf_flags_temp_dup_user = -1;
static int hf_flags_password_required = -1;
static int hf_flags_homedir_required = -1;
static int hf_flags_enabled = -1;
static int hf_domain_sid_size = -1;
static int hf_domain_sid = -1;
static int hf_low_serial = -1;
static int hf_pulse = -1;
static int hf_random = -1;
static int hf_db_count = -1;
static int hf_db_index = -1;
static int hf_large_serial = -1;
static int hf_nt_date_time = -1;

static int ett_smb_logon = -1;
static int ett_smb_account_flags = -1;
static int ett_smb_db_info = -1;

#define	ACC_FLAG_AUTO_LOCKED			0x0400
#define ACC_FLAG_EXPIRE				0x0200
#define ACC_FLAG_SERVER_TRUST			0x0100
#define ACC_FLAG_WORKSTATION_TRUST		0x0080
#define ACC_FLAG_INTERDOMAIN_TRUST		0x0040
#define ACC_FLAG_MNS_USER			0x0020
#define ACC_FLAG_NORMAL_USER			0x0010
#define ACC_FLAG_TEMP_DUP_USER			0x0008
#define ACC_FLAG_PASSWORD_REQUIRED		0x0004
#define ACC_FLAG_HOMEDIR_REQUIRED		0x0002
#define ACC_FLAG_ENABLED			0x0001

static const true_false_string tfs_flags_autolock = {
	"User account auto-locked",
	"User account NOT auto-locked"
};
static const true_false_string tfs_flags_expire = {
	"User password will NOT expire",
	"User password will expire"
};
static const true_false_string tfs_flags_server_trust = {
	"Server Trust user account",
	"NOT a Server Trust user account"
};
static const true_false_string tfs_flags_workstation_trust = {
	"Workstation Trust user account",
	"NOT a Workstation Trust user account"
};
static const true_false_string tfs_flags_interdomain_trust = {
	"Inter-domain Trust user account",
	"NOT a Inter-domain Trust user account"
};
static const true_false_string tfs_flags_mns_user = {
	"MNS Logon user account",
	"NOT a MNS Logon user account"
};
static const true_false_string tfs_flags_normal_user = {
	"Normal user account",
	"NOT a normal user account"
};
static const true_false_string tfs_flags_temp_dup_user = {
	"Temp duplicate user account",
	"NOT a temp duplicate user account"
};
static const true_false_string tfs_flags_password_required = {
	"NO password required",
	"Password required"
};
static const true_false_string tfs_flags_homedir_required = {
	"NO homedir required",
	"Homedir required"
};
static const true_false_string tfs_flags_enabled = {
	"User account enabled",
	"User account disabled"
};



static int
dissect_account_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	/* display the Allowable Account control bits */

	proto_item *ti = NULL;
	proto_tree *flags_tree = NULL;
	guint32 flags;

	flags = tvb_get_letohl(tvb, offset);

	if (tree) {
		ti = proto_tree_add_text(tree, tvb, offset, 4,
			"Account control  = 0x%04x", flags);

		flags_tree = proto_item_add_subtree(ti, ett_smb_account_flags);
	}

	proto_tree_add_boolean(flags_tree, hf_flags_autolock, tvb, offset, 4, flags);
	proto_tree_add_boolean(flags_tree, hf_flags_expire, tvb, offset, 4, flags);
	proto_tree_add_boolean(flags_tree, hf_flags_server_trust, tvb, offset, 4, flags);
	proto_tree_add_boolean(flags_tree, hf_flags_workstation_trust, tvb, offset, 4, flags);
	proto_tree_add_boolean(flags_tree, hf_flags_interdomain_trust, tvb, offset, 4, flags);
	proto_tree_add_boolean(flags_tree, hf_flags_mns_user, tvb, offset, 4, flags);
	proto_tree_add_boolean(flags_tree, hf_flags_normal_user, tvb, offset, 4, flags);
	proto_tree_add_boolean(flags_tree, hf_flags_temp_dup_user, tvb, offset, 4, flags);
	proto_tree_add_boolean(flags_tree, hf_flags_password_required, tvb, offset, 4, flags);
	proto_tree_add_boolean(flags_tree, hf_flags_homedir_required, tvb, offset, 4, flags);
	proto_tree_add_boolean(flags_tree, hf_flags_enabled, tvb, offset, 4, flags);

	offset += 4;

	return offset;
}

static int
display_LM_token(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree)
{
	guint16 Token;

	Token = tvb_get_letohs(tvb, offset);

	if (Token & 0x01) {
		proto_tree_add_uint_format(tree, hf_lm_token, tvb, offset, 2, 
			Token,
			"LM20 Token: 0x%04x (LanMan 2.0 or higher)", Token);
	} else {
		proto_tree_add_uint_format(tree, hf_lm_token, tvb, offset, 2, 
			Token,
			"LM10 Token: 0x%04x (WFW Networking)", Token);
	}

	offset += 2;

	return offset;
}

static int
display_LMNT_token(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree)
{
	guint16 Token;

	Token = tvb_get_letohs(tvb, offset);

	if (Token == 0xffff) {
		proto_tree_add_uint_format(tree, hf_lmnt_token, tvb, offset, 2, 
			Token,
			"LMNT Token: 0x%04x (Windows NT Networking)", Token);
	} else {
		proto_tree_add_uint_format(tree, hf_lm_token, tvb, offset, 2, 
			Token,
			"LMNT Token: 0x%04x (Unknown)", Token);
	}

	offset += 2;

	return offset;
}

static int
dissect_smb_logon_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	/*** 0x00 (LM1.0/LM2.0 LOGON Request) ***/
 
	/* computer name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_computer_name);

	/* user name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_user_name);

	/* mailslot name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_mailslot_name);

	/*$$$$$ here add the Mailslot to the response list (if needed) */

	/* Request count */
	proto_tree_add_item(tree, hf_request_count, tvb, offset, 1, TRUE);
	offset += 1;

	/* NT version */
  	proto_tree_add_item(tree, hf_nt_version, tvb, offset, 2, TRUE);
	offset += 2;

	/* LM token */
	offset = display_LM_token(tvb, offset, pinfo, tree);

	return offset;
}



static int
dissect_smb_logon_LM10_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	/*** 0x01 LanMan 1.0 Logon response ***/

	/* user name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_user_name);

	/* script name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_script_name);

	return offset;
}


static int
dissect_smb_logon_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	/*** 0x02  LM1.0 Query - Centralized Initialization ***/
	/*** 0x03  LM1.0 Query - Distributed Initialization ***/
	/*** 0x04  LM1.0 Query - Centralized Query Response ***/
	/*** 0x04  LM1.0 Query - Distributed Query Response ***/

	/* computer name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_computer_name);

	/* mailslot name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_mailslot_name);

	/* NT version */
  	proto_tree_add_item(tree, hf_nt_version, tvb, offset, 2, TRUE);
	offset += 2;

	/* LM token */
	offset = display_LM_token(tvb, offset, pinfo, tree);

	return offset;
}



static int
dissect_smb_logon_LM20_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	/*** 0x06 (LM2.0 LOGON Response)	***/

	/* server name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_server_name);

	/* LM token */
	offset = display_LM_token(tvb, offset, pinfo, tree);

	return offset;
}



static int
dissect_smb_pdc_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	/*** 0x07 Query for Primary PDC  ***/
 
	/* computer name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_computer_name);

	/* mailslot name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_mailslot_name);

	if (tvb_reported_length_remaining(tvb, offset) > 2) {
		/*
		 * NT-style Query for PDC?
		 * If only 2 bytes remain, it's probably a Windows 95-style
		 * query, which has only an LM token after the mailslot
		 * name.
		 *
		 * XXX - base this on flags in the SMB header, e.g.
		 * the ASCII/Unicode strings flag?
		 */
		if (offset % 2) offset++;      /* word align ... */

		/* Unicode computer name */
		offset = display_unicode_string(tvb, pinfo, tree, offset, hf_unicode_computer_name);

		/* NT version */
	  	proto_tree_add_item(tree, hf_nt_version, tvb, offset, 4, TRUE);
		offset += 4;

		/* LMNT token */
		offset = display_LMNT_token(tvb, offset, pinfo, tree);
	}

	/* LM token */
	offset = display_LM_token(tvb, offset, pinfo, tree);

	return offset;
}



static int
dissect_smb_pdc_startup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	/*** 0x08  Announce startup of PDC ***/
 
	/* pdc name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_pdc_name);

	/* A short Announce will not have the rest */

	if (tvb_length_remaining(tvb, offset) != 0) { 

	  if (offset % 2) offset++;      /* word align ... */

	  /* pdc name */
	  offset = display_unicode_string(tvb, pinfo, tree, offset, hf_unicode_pdc_name);

	  if (offset % 2) offset++;

	  /* domain name */
	  offset = display_unicode_string(tvb, pinfo, tree, offset, hf_domain_name);

	  /* NT version */
  	  proto_tree_add_item(tree, hf_nt_version, tvb, offset, 4, TRUE);
	  offset += 4;

	  /* LMNT token */
	  offset = display_LMNT_token(tvb, offset, pinfo, tree);

	  /* LM token */
	  offset = display_LM_token(tvb, offset, pinfo, tree);
	}

	return offset;
}



static int
dissect_smb_pdc_failure(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	/*** 0x09 Announce failure of the PDC ***/
	/*** 0x0F LM2.0 Resp. during LOGON pause ***/
	/*** 0x10 (LM 2.0 Unknown user response) ***/

	/* NT version */
	proto_tree_add_item(tree, hf_nt_version, tvb, offset, 4, TRUE);
	offset += 4;

	/* LM token */
	offset = display_LM_token(tvb, offset, pinfo, tree);

	return offset;
}


static int
dissect_announce_change(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	/*** 0x0A ( Announce change to UAS or SAM ) ***/
	guint32 info_count;
	proto_item *ti = NULL;
	proto_tree *info_tree = NULL;
	guint32 db_index;
	guint32 domain_sid_size;

	/* low serial number */
	proto_tree_add_item(tree, hf_low_serial, tvb, offset, 4, TRUE);
	offset += 4;

	/* date/time */
	proto_tree_add_item(tree, hf_date_time, tvb, offset, 4, TRUE);
	offset += 4;

	/* pulse */
	proto_tree_add_item(tree, hf_pulse, tvb, offset, 4, TRUE);
	offset += 4;

	/* random */
	proto_tree_add_item(tree, hf_random, tvb, offset, 4, TRUE);
	offset += 4;

	/* pdc name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_pdc_name);

	/* domain name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_domain_name);

	if (offset % 2) offset++;      /* word align ... */

	/* pdc name */
	offset = display_unicode_string(tvb, pinfo, tree, offset, hf_unicode_pdc_name);

	/* domain name */
	offset = display_unicode_string(tvb, pinfo, tree, offset, hf_domain_name);

	/* DB count */
	info_count = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_db_count, tvb, offset, 4, info_count);
	offset += 4;

	while (info_count != 0) {
		db_index = tvb_get_letohl(tvb, offset);
		if (tree) {
			ti = proto_tree_add_text(tree, tvb, offset, 20,
			    "DBChange Info Structure: index %u", db_index);
			info_tree = proto_item_add_subtree(ti, ett_smb_db_info);
		}

		proto_tree_add_uint(info_tree, hf_db_index, tvb, offset, 4,
		    db_index);
		offset += 4;

		proto_tree_add_item(info_tree, hf_large_serial, tvb, offset, 8,
		    FALSE);
		offset += 8;

		proto_tree_add_item(info_tree, hf_nt_date_time, tvb, offset, 8,
		    FALSE);
		offset += 8;

		info_count--;
	}

	/* Domain SID Size */
	domain_sid_size = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_domain_sid_size, tvb, offset, 4,
	    domain_sid_size);
	offset += 4;

	if (domain_sid_size != 0) {
		/* Domain SID */
		proto_tree_add_item(tree, hf_domain_sid, tvb, offset,
		    domain_sid_size, TRUE);
		offset += domain_sid_size;
	}

	/* NT version */
	proto_tree_add_item(tree, hf_nt_version, tvb, offset, 4, TRUE);
	offset += 4;

	/* LMNT token */
	offset = display_LMNT_token(tvb, offset, pinfo, tree);

	/* LM token */
	offset = display_LM_token(tvb, offset, pinfo, tree);

	return offset;
}



static int
dissect_smb_sam_logon_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	/* Netlogon command 0x12 - decode the SAM logon request from client */

	guint32 domain_sid_size;

	/* Request count */
	proto_tree_add_item(tree, hf_request_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* computer name */
	offset = display_unicode_string(tvb, pinfo, tree, offset, hf_unicode_computer_name);

	/* user name */
	offset = display_unicode_string(tvb, pinfo, tree, offset, hf_user_name);

	/* mailslot name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_mailslot_name);

	/* account control */
	offset = dissect_account_control(tvb, pinfo, tree, offset);

	/* Domain SID Size */
	domain_sid_size = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_domain_sid_size, tvb, offset, 4,
	    domain_sid_size);
	offset += 4;

	if (domain_sid_size != 0) {
		/* Domain SID */
		proto_tree_add_item(tree, hf_domain_sid, tvb, offset,
		    domain_sid_size, TRUE);
		offset += domain_sid_size;

		/* XXX - at least one packet appears to put the NT version on
		   a 4-byte boundary, with padding after the domain SID, at
		   least according to Network Monitor.

		   However, another frame, with a zero-length domain SID,
		   doesn't do any padding, and other packets don't appear
		   to put the NT version of a 4-byte boundary, so maybe
		   the padding comes *before* the domain SID, and NetMon
		   is just confused?  (NetMon has been known to misdissect
		   SMB packets, even though, err, umm, NetMon comes from
		   the people who are adding all this stuff to SMB....) */
		offset = ((offset + 3)/4)*4;
	}
 	
	/* NT version */
	proto_tree_add_item(tree, hf_nt_version, tvb, offset, 4, TRUE);
	offset += 4;

	/* LMNT token */
	offset = display_LMNT_token(tvb, offset, pinfo, tree);

	/* LM token */
	offset = display_LM_token(tvb, offset, pinfo, tree);

	return offset;
}



static int
dissect_smb_no_user(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	/* 0x0B (Announce no user on machine) */

	/* computer name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_computer_name);

	return offset;
}



static int
dissect_smb_relogon_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	/*** 0x0d LanMan Response to relogon request ***/

	/* Major version */
	proto_tree_add_item(tree, hf_major_version, tvb, offset, 1, TRUE);
	offset += 1;

	/* Minor version */
	proto_tree_add_item(tree, hf_minor_version, tvb, offset, 1, TRUE);
	offset += 1;

	/* OS version */
	proto_tree_add_item(tree, hf_os_version, tvb, offset, 1, TRUE);
	offset += 1;

	/* NT version */
	proto_tree_add_item(tree, hf_nt_version, tvb, offset, 4, TRUE);
	offset += 4;

	/* LM token */
	offset = display_LM_token(tvb, offset, pinfo, tree);

	return offset;
}



static int
dissect_smb_acc_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	/*** 0x11  LM2.1 Announce Acc updates  ***/

	guint32 Temp1, Temp2;

	Temp1 = tvb_get_letohl(tvb, offset);
	Temp2 = tvb_get_letohl(tvb, offset + 4);

	/* signature */
	proto_tree_add_text(tree, tvb, offset, 8, "Signature: 0x%08x%08x",
		Temp1, Temp2);
	offset += 8;

	/* date/time */
	proto_tree_add_item(tree, hf_date_time, tvb, offset, 4, TRUE);
	offset += 4;

	/* computer name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_computer_name);

	/* user name */
	offset = display_ms_string(tvb, pinfo, tree, offset, hf_user_name);

	/* update type */
	proto_tree_add_item(tree, hf_update_type, tvb, offset, 2, TRUE);
	offset += 2;

	/* NT version */
	proto_tree_add_item(tree, hf_nt_version, tvb, offset, 4, TRUE);
	offset += 4;

	/* LM token */
	offset = display_LM_token(tvb, offset, pinfo, tree);

	return offset;
}



static int
dissect_smb_inter_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	/* 0x0e LanMan Response to interrogate request */

	/* Major version */
	proto_tree_add_item(tree, hf_major_version, tvb, offset, 1, TRUE);
	offset += 1;

	/* Minor version */
	proto_tree_add_item(tree, hf_minor_version, tvb, offset, 1, TRUE);
	offset += 1;

	/* OS version */
	proto_tree_add_item(tree, hf_os_version, tvb, offset, 1, TRUE);
	offset += 1;

	/* NT version */
	proto_tree_add_item(tree, hf_nt_version, tvb, offset, 4, TRUE);
	offset += 4;

	/* LMNT token */
	offset = display_LMNT_token(tvb, offset, pinfo, tree);

	/* XXX - no LM token? */
	return offset;
}


static int
dissect_smb_sam_logon_resp(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset)
{
	/* Netlogon command 0x13 - decode the SAM logon response from server */

	guint16 lmt;

	/* server name */
	offset = display_unicode_string(tvb, pinfo, tree, offset, hf_server_name);

	/* user name */
	offset = display_unicode_string(tvb, pinfo, tree, offset, hf_user_name);

	/* domain name */
	offset = display_unicode_string(tvb, pinfo, tree, offset, hf_domain_name);

	/* NT version */
	proto_tree_add_item(tree, hf_nt_version, tvb, offset, 4, TRUE);
	offset += 4;

	/* LMNT token */
	offset = display_LMNT_token(tvb, offset, pinfo, tree);

	/* LM token */
	offset = display_LM_token(tvb, offset, pinfo, tree);

	return offset;
}


#define LOGON_LM10_LOGON_REQUEST		0x00
#define LOGON_LM10_LOGON_RESPONSE		0x01
#define LOGON_LM10_QUERY_CI			0x02
#define LOGON_LM10_QUERY_DI			0x03
#define LOGON_LM10_RESPONSE_CI			0x04
#define LOGON_LM10_RESPONSE_DI			0x05
#define LOGON_LM20_LOGON_RESPONSE		0x06
#define LOGON_PDC_QUERY				0x07
#define LOGON_PDC_STARTUP			0x08
#define LOGON_PDC_FAILED			0x09
#define LOGON_UAS_SAM				0x0a
#define LOGON_NO_USER				0x0b
#define LOGON_PDC_RESPONSE			0x0c
#define LOGON_RELOGON_RESPONSE			0x0d
#define LOGON_INTERROGATE_RESPONSE		0x0e
#define LOGON_LM20_RESPONSE_DURING_LOGON	0x0f
#define LOGON_LM20_USER_UNKNOWN			0x10
#define LOGON_LM20_ACCOUNT_UPDATE		0x11
#define LOGON_SAM_LOGON_REQUEST			0x12
#define LOGON_SAM_LOGON_RESPONSE		0x13
#define LOGON_SAM_RESPONSE_DURING_LOGON		0x14
#define LOGON_SAM_USER_UNKNOWN			0x15
#define LOGON_SAM_INTERROGATE_RESPONSE		0x16
#define LOGON_LAST_CMD				0x17

static const value_string commands[] = {
	{LOGON_LM10_LOGON_REQUEST,	"LM1.0/LM2.0 LOGON Request"},
	{LOGON_LM10_LOGON_RESPONSE,	"LM1.0 LOGON Response"},
	{LOGON_LM10_QUERY_CI,		"LM1.0 Query - Centralized Initialization"},
	{LOGON_LM10_QUERY_DI,		"LM1.0 Query - Distributed Initialization"},
	{LOGON_LM10_RESPONSE_CI,	"LM1.0 Response - Centralized Query"},
	{LOGON_LM10_RESPONSE_DI,	"LM1.0 Response - Distributed Initialization"},
	{LOGON_LM20_LOGON_RESPONSE,	"LM2.0 Response to LOGON Request"},
	{LOGON_PDC_QUERY,		"Query for PDC"},
	{LOGON_PDC_STARTUP,		"Announce Startup of PDC"},
	{LOGON_PDC_FAILED,		"Announce Failed PDC"},
	{LOGON_UAS_SAM,			"Announce Change to UAS or SAM"},
	{LOGON_NO_USER,			"Announce no user on machine"},
	{LOGON_PDC_RESPONSE,		"Response from PDC"},
	{LOGON_RELOGON_RESPONSE,	"LM1.0/LM2.0 Response to re-LOGON Request"},
	{LOGON_INTERROGATE_RESPONSE,	"LM1.0/LM2.0 Response to Interrogate Request"},
	{LOGON_LM20_RESPONSE_DURING_LOGON,"LM2.0 Response during LOGON pause"},
	{LOGON_LM20_USER_UNKNOWN,	"LM2.0 Response - user unknown"},
	{LOGON_LM20_ACCOUNT_UPDATE,	"LM2.0 Announce account updates"},
	{LOGON_SAM_LOGON_REQUEST,	"SAM LOGON request from client"},
	{LOGON_SAM_LOGON_RESPONSE,	"Response to SAM LOGON request"},
	{LOGON_SAM_RESPONSE_DURING_LOGON,"SAM Response during LOGON pause"},
	{LOGON_SAM_USER_UNKNOWN,	"SAM Response - user unknown"},
	{LOGON_SAM_INTERROGATE_RESPONSE,"SAM Response to Interrogate Request"},
	{0,	NULL}
};


static int (*dissect_smb_logon_cmds[])(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset) = {
	dissect_smb_logon_request,  /* 0x00 (LM1.0/LM2.0 LOGON Request) */
	dissect_smb_logon_LM10_resp,/* 0x01 (LM1.0 LOGON Response)	*/
	dissect_smb_logon_2,	    /* 0x02 (LM1.0 Query Centralized Init.)*/
	dissect_smb_logon_2,	    /* 0x03 (LM1.0 Query Distributed Init.)*/
	dissect_smb_logon_2,	    /* 0x04 (LM1.0 Centralized Query Resp.)*/
	dissect_smb_logon_2,	    /* 0x05 (LM1.0 Distributed Query Resp.) */
	dissect_smb_logon_LM20_resp,/* 0x06 (LM2.0 LOGON Response)	*/
	dissect_smb_pdc_query,	    /* 0x07 (Query for PDC) 		*/
	dissect_smb_pdc_startup,    /* 0x08 (Announce PDC startup)	*/
	dissect_smb_pdc_failure,    /* 0x09 (Announce Failed PDC)	*/
	dissect_announce_change,    /* 0x0A (Announce Change to UAS or SAM)*/
	dissect_smb_no_user,	    /* 0x0B (Announce no user on machine)*/
	dissect_smb_pdc_startup,    /* 0x0C (Response from PDC)		*/
	dissect_smb_relogon_resp,   /* 0x0D (Relogon response) 		*/
	dissect_smb_inter_resp,     /* 0x0E (Interrogate response) 	*/
	dissect_smb_pdc_failure,    /* 0x0F (LM2.0 Resp. during LOGON pause*/
	dissect_smb_pdc_failure,    /* 0x10 (LM 2.0 Unknown user response)*/
	dissect_smb_acc_update,	    /* 0x11 (LM2.1 Announce Acc updates)*/
	dissect_smb_sam_logon_req,  /* 0x12 (SAM LOGON request )	*/
	dissect_smb_sam_logon_resp, /* 0x13 (SAM LOGON response)	*/
	dissect_smb_unknown,        /* 0x14 (SAM Response during LOGON Pause) */
	dissect_smb_unknown,        /* 0x15 (SAM Response User Unknown)      */
	dissect_smb_unknown,        /* 0x16 (SAM Response to Interrogate)   */
};


gboolean
dissect_smb_logon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int        offset = 0;
	guint8     cmd;
	proto_tree *smb_logon_tree = NULL;
	proto_item *item = NULL;

	if (!proto_is_protocol_enabled(proto_smb_logon))
		return FALSE;

	pinfo->current_proto = "NETLOGON";

	/* get the Command field */
   	cmd = tvb_get_guint8(tvb, offset);

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "NETLOGON");

	if (check_col(pinfo->fd, COL_INFO))
		col_add_str(pinfo->fd, COL_INFO, val_to_str(cmd, commands, "Unknown Command:%02x") );

    	if (tree) {
		item = proto_tree_add_item(tree, proto_smb_logon, tvb,
			offset,	tvb_length_remaining(tvb, offset), FALSE);

		smb_logon_tree = proto_item_add_subtree(item, ett_smb_logon);
	}

	/* command */
	proto_tree_add_uint(smb_logon_tree, hf_command, tvb, offset, 1, cmd);
	offset += 1;

	/* skip next byte */
	offset += 1;

	if (cmd<LOGON_LAST_CMD) {
		offset = (dissect_smb_logon_cmds[cmd])(tvb, pinfo,
		    smb_logon_tree, offset);
	} else {
		/* unknown command */
		offset = dissect_smb_unknown(tvb, pinfo, smb_logon_tree,
		    offset);
	}

	return TRUE;
}



void
register_proto_smb_logon( void){

	static hf_register_info hf[] = {
		{ &hf_command,
			{ "Command", "netlogon.command", FT_UINT8, BASE_HEX,
			  VALS(commands), 0, "NETLOGON Command", HFILL }},

		{ &hf_computer_name,
			{ "Computer Name", "netlogon.computer_name", FT_STRING, BASE_NONE,
			  NULL, 0, "NETLOGON Computer Name", HFILL }},

		{ &hf_unicode_computer_name,
			{ "Unicode Computer Name", "netlogon.unicode_computer_name", FT_STRING, BASE_NONE,
			  NULL, 0, "NETLOGON Unicode Computer Name", HFILL }},

		{ &hf_server_name,
			{ "Server Name", "netlogon.server_name", FT_STRING, BASE_NONE,
			  NULL, 0, "NETLOGON Server Name", HFILL }},

		{ &hf_user_name,
			{ "User Name", "netlogon.user_name", FT_STRING, BASE_NONE,
			  NULL, 0, "NETLOGON User Name", HFILL }},

		{ &hf_domain_name,
			{ "Domain Name", "netlogon.domain_name", FT_STRING, BASE_NONE,
			  NULL, 0, "NETLOGON Domain Name", HFILL }},

		{ &hf_mailslot_name,
			{ "Mailslot Name", "netlogon.mailslot_name", FT_STRING, BASE_NONE,
			  NULL, 0, "NETLOGON Mailslot Name", HFILL }},

		{ &hf_pdc_name,
			{ "PDC Name", "netlogon.pdc_name", FT_STRING, BASE_NONE,
			  NULL, 0, "NETLOGON PDC Name", HFILL }},

		{ &hf_unicode_pdc_name,
			{ "Unicode PDC Name", "netlogon.unicode_pdc_name", FT_STRING, BASE_NONE,
			  NULL, 0, "NETLOGON Unicode PDC Name", HFILL }},

		{ &hf_script_name,
			{ "Script Name", "netlogon.script_name", FT_STRING, BASE_NONE,
			  NULL, 0, "NETLOGON Script Name", HFILL }},

		{ &hf_nt_version,
			{ "NT Version", "netlogon.nt_version", FT_UINT32, BASE_DEC,
			  NULL, 0, "NETLOGON NT Version", HFILL }},

		/* An LMNT Token, if 0xffff, is "WindowsNT Networking"; 
		   what is it otherwise? */
		{ &hf_lmnt_token,
			{ "LMNT Token", "netlogon.lmnt_token", FT_UINT16, BASE_HEX,
			  NULL, 0, "NETLOGON LMNT Token", HFILL }},

		{ &hf_lm_token,
			{ "LM Token", "netlogon.lm_token", FT_UINT16, BASE_HEX,
			  NULL, 0, "NETLOGON LM Token", HFILL }},

		{ &hf_major_version,
			{ "Workstation Major Version", "netlogon.major_version", FT_UINT8, BASE_DEC,
			  NULL, 0, "NETLOGON Workstation Major Version", HFILL }},

		{ &hf_minor_version,
			{ "Workstation Minor Version", "netlogon.minor_version", FT_UINT8, BASE_DEC,
			  NULL, 0, "NETLOGON Workstation Minor Version", HFILL }},

		{ &hf_os_version,
			{ "Workstation OS Version", "netlogon.os_version", FT_UINT8, BASE_DEC,
			  NULL, 0, "NETLOGON Workstation OS Version", HFILL }},

		{ &hf_date_time,
			{ "Date/Time", "netlogon.date_time", FT_UINT32, BASE_DEC,
			  NULL, 0, "NETLOGON Date/Time", HFILL }},

		{ &hf_update_type,
			{ "Update Type", "netlogon.update", FT_UINT16, BASE_DEC,
			  NULL, 0, "NETLOGON Update Type", HFILL }},

		{ &hf_request_count,
			{ "Request Count", "netlogon.request_count", FT_UINT16, BASE_DEC,
			  NULL, 0, "NETLOGON Request Count", HFILL }},

		{ &hf_flags_autolock,
			{ "Autolock", "netlogon.flags.autolock", FT_BOOLEAN, 32,
			TFS(&tfs_flags_autolock), ACC_FLAG_AUTO_LOCKED, "NETLOGON Account Autolock", HFILL}},

		{ &hf_flags_expire,
			{ "Expire", "netlogon.flags.expire", FT_BOOLEAN, 32,
			TFS(&tfs_flags_expire), ACC_FLAG_EXPIRE, "NETLOGON Will Account Expire", HFILL}},

		{ &hf_flags_server_trust,
			{ "Server Trust", "netlogon.flags.server", FT_BOOLEAN, 32,
			TFS(&tfs_flags_server_trust), ACC_FLAG_SERVER_TRUST, "NETLOGON Server Trust Account", HFILL}},

		{ &hf_flags_workstation_trust,
			{ "Workstation Trust", "netlogon.flags.workstation", FT_BOOLEAN, 32,
			TFS(&tfs_flags_workstation_trust), ACC_FLAG_WORKSTATION_TRUST, "NETLOGON Workstation Trust Account", HFILL}},

		{ &hf_flags_interdomain_trust,
			{ "Interdomain Trust", "netlogon.flags.interdomain", FT_BOOLEAN, 32,
			TFS(&tfs_flags_interdomain_trust), ACC_FLAG_INTERDOMAIN_TRUST, "NETLOGON Inter-domain Trust Account", HFILL}},

		{ &hf_flags_mns_user,
			{ "MNS User", "netlogon.flags.mns", FT_BOOLEAN, 32,
			TFS(&tfs_flags_mns_user), ACC_FLAG_MNS_USER, "NETLOGON MNS User Account", HFILL}},

		{ &hf_flags_normal_user,
			{ "Normal User", "netlogon.flags.normal", FT_BOOLEAN, 32,
			TFS(&tfs_flags_normal_user), ACC_FLAG_NORMAL_USER, "NETLOGON Normal User Account", HFILL}},

		{ &hf_flags_temp_dup_user,
			{ "Temp Duplicate User", "netlogon.flags.temp_dup", FT_BOOLEAN, 32,
			TFS(&tfs_flags_temp_dup_user), ACC_FLAG_TEMP_DUP_USER, "NETLOGON Temp Duplicate User Account", HFILL}},

		{ &hf_flags_password_required,
			{ "Password", "netlogon.flags.password", FT_BOOLEAN, 32,
			TFS(&tfs_flags_password_required), ACC_FLAG_PASSWORD_REQUIRED, "NETLOGON Password Required", HFILL}},

		{ &hf_flags_homedir_required,
			{ "Homedir", "netlogon.flags.homedir", FT_BOOLEAN, 32,
			TFS(&tfs_flags_homedir_required), ACC_FLAG_HOMEDIR_REQUIRED, "NETLOGON Homedir Required", HFILL}},

		{ &hf_flags_enabled,
			{ "Enabled", "netlogon.flags.enabled", FT_BOOLEAN, 32,
			TFS(&tfs_flags_enabled), ACC_FLAG_ENABLED, "NETLOGON Is This Account Enabled", HFILL}},

		{ &hf_domain_sid_size,
			{ "Domain SID Size", "netlogon.domain_sid_size", FT_UINT32, BASE_DEC,
			  NULL, 0, "NETLOGON Domain SID Size", HFILL }},

		{ &hf_domain_sid,
			{ "Domain SID", "netlogon.domain_sid", FT_BYTES, BASE_NONE,
			  NULL, 0, "NETLOGON Domain SID", HFILL }},

		{ &hf_low_serial,
			{ "Low Serial Number", "netlogon.low_serial", FT_UINT32, BASE_DEC,
			  NULL, 0, "NETLOGON Low Serial Number", HFILL }},

		{ &hf_pulse,
			{ "Pulse", "netlogon.pulse", FT_UINT32, BASE_DEC,
			  NULL, 0, "NETLOGON Pulse", HFILL }},

		{ &hf_random,
			{ "Random", "netlogon.random", FT_UINT32, BASE_DEC,
			  NULL, 0, "NETLOGON Random", HFILL }},

		{ &hf_db_count,
			{ "DB Count", "netlogon.db_count", FT_UINT32, BASE_DEC,
			  NULL, 0, "NETLOGON DB Count", HFILL }},

		{ &hf_db_index,
			{ "Database Index", "netlogon.db_index", FT_UINT32, BASE_DEC,
			  NULL, 0, "NETLOGON Database Index", HFILL }},

		/* XXX - 64-bit integer? */
		{ &hf_large_serial,
			{ "Large Serial Number", "netlogon.large_serial", FT_BYTES, BASE_NONE,
			  NULL, 0, "NETLOGON Large Serial Number", HFILL }},

		/* XXX - 64-bit FILETIME */
		{ &hf_nt_date_time,
			{ "NT Date/Time", "netlogon.nt_date_time", FT_BYTES, BASE_NONE,
			  NULL, 0, "NETLOGON NT Date/Time", HFILL }},
	};

	static gint *ett[] = {
		&ett_smb_logon,
		&ett_smb_account_flags,
		&ett_smb_db_info
	};

   	proto_smb_logon = proto_register_protocol(
   		"Microsoft Windows Logon Protocol", "NETLOGON", "netlogon");

	proto_register_field_array(proto_smb_logon, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));          
}
