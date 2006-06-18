/* packet-smb-browse.c
 * Routines for SMB Browser packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#include <time.h>
#include <string.h>
#include <glib.h>
#include <ctype.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/dissectors/packet-smb.h>

#include "packet-smb-browse.h"
#include "packet-dcerpc.h"

static int proto_smb_browse = -1;
static int hf_command = -1;
static int hf_update_count = -1;
static int hf_periodicity = -1;
static int hf_server_name = -1;
static int hf_mb_server_name = -1;
static int hf_mb_reset_command = -1;
static int hf_mb_reset_demote = -1;
static int hf_mb_reset_flush = -1;
static int hf_mb_reset_stop = -1;
static int hf_os_major = -1;
static int hf_os_minor = -1;
static int hf_server_type = -1;
static int hf_server_type_workstation = -1;
static int hf_server_type_server = -1;
static int hf_server_type_sql = -1;
static int hf_server_type_domain = -1;
static int hf_server_type_backup = -1;
static int hf_server_type_time = -1;
static int hf_server_type_apple = -1;
static int hf_server_type_novell = -1;
static int hf_server_type_member = -1;
static int hf_server_type_print = -1;
static int hf_server_type_dialin = -1;
static int hf_server_type_xenix = -1;
static int hf_server_type_ntw = -1;
static int hf_server_type_wfw = -1;
static int hf_server_type_nts = -1;
static int hf_server_type_potentialb = -1;
static int hf_server_type_backupb = -1;
static int hf_server_type_masterb = -1;
static int hf_server_type_domainmasterb = -1;
static int hf_server_type_osf = -1;
static int hf_server_type_vms = -1;
static int hf_server_type_w95 = -1;
static int hf_server_type_local = -1;
static int hf_server_type_domainenum = -1;
static int hf_election_version = -1;
static int hf_proto_major = -1;
static int hf_proto_minor = -1;
static int hf_sig_const = -1;
static int hf_server_comment = -1;
static int hf_unused_flags = -1;
static int hf_response_computer_name = -1;
static int hf_election_criteria = -1;
static int hf_election_desire = -1;
static int hf_election_desire_flags_backup = -1;
static int hf_election_desire_flags_standby = -1;
static int hf_election_desire_flags_master = -1;
static int hf_election_desire_flags_domain_master = -1;
static int hf_election_desire_flags_wins = -1;
static int hf_election_desire_flags_nt = -1;
static int hf_election_revision = -1;
static int hf_election_os = -1;
static int hf_election_os_wfw = -1;
static int hf_election_os_ntw = -1;
static int hf_election_os_nts = -1;
static int hf_server_uptime = -1;
static int hf_backup_count = -1;
static int hf_backup_token = -1;
static int hf_backup_server = -1;
static int hf_browser_to_promote = -1;

static gint ett_browse = -1;
static gint ett_browse_flags = -1;
static gint ett_browse_election_criteria = -1;
static gint ett_browse_election_os = -1;
static gint ett_browse_election_desire = -1;
static gint ett_browse_reset_cmd_flags = -1;

#define SERVER_WORKSTATION		0
#define SERVER_SERVER			1
#define SERVER_SQL_SERVER		2
#define SERVER_DOMAIN_CONTROLLER	3
#define SERVER_BACKUP_CONTROLLER	4
#define SERVER_TIME_SOURCE		5
#define SERVER_APPLE_SERVER		6
#define SERVER_NOVELL_SERVER		7
#define SERVER_DOMAIN_MEMBER_SERVER	8
#define SERVER_PRINT_QUEUE_SERVER	9
#define SERVER_DIALIN_SERVER		10
#define SERVER_XENIX_SERVER		11
#define SERVER_NT_WORKSTATION		12
#define SERVER_WINDOWS_FOR_WORKGROUPS	13
#define SERVER_NT_SERVER		15
#define SERVER_POTENTIAL_BROWSER	16
#define SERVER_BACKUP_BROWSER		17
#define SERVER_MASTER_BROWSER		18
#define SERVER_DOMAIN_MASTER_BROWSER	19
#define SERVER_OSF			20
#define SERVER_VMS			21
#define SERVER_WINDOWS_95		22
#define SERVER_LOCAL_LIST_ONLY		30
#define SERVER_DOMAIN_ENUM		31

static const value_string server_types[] = {
	{SERVER_WORKSTATION,		"Workstation"},
	{SERVER_SERVER,			"Server"},
	{SERVER_SQL_SERVER,		"SQL Server"},
	{SERVER_DOMAIN_CONTROLLER,	"Domain Controller"},
	{SERVER_BACKUP_CONTROLLER,	"Backup Controller"},
	{SERVER_TIME_SOURCE,		"Time Source"},
	{SERVER_APPLE_SERVER,		"Apple Server"},
	{SERVER_NOVELL_SERVER,		"Novell Server"},
	{SERVER_DOMAIN_MEMBER_SERVER,	"Domain Member Server"},
	{SERVER_PRINT_QUEUE_SERVER,	"Print Queue Server"},
	{SERVER_DIALIN_SERVER,		"Dialin Server"},
	{SERVER_XENIX_SERVER,		"Xenix Server"},
	{SERVER_NT_WORKSTATION,		"NT Workstation"},
	{SERVER_WINDOWS_FOR_WORKGROUPS,	"Windows for Workgroups"},
	{SERVER_NT_SERVER,		"NT Server"},
	{SERVER_POTENTIAL_BROWSER,	"Potential Browser"},
	{SERVER_BACKUP_BROWSER,		"Backup Browser"},
	{SERVER_MASTER_BROWSER,		"Master Browser"},
	{SERVER_DOMAIN_MASTER_BROWSER,	"Domain Master Browser"},
	{SERVER_OSF,			"OSF"},
	{SERVER_VMS,			"VMS"},
	{SERVER_WINDOWS_95,		"Windows 95 or above"},
	{SERVER_LOCAL_LIST_ONLY,	"Local List Only"},
	{SERVER_DOMAIN_ENUM,		"Domain Enum"},
	{0,	NULL}
};

static const value_string resetbrowserstate_command_names[] = {
  { 0x01, "Stop being a master browser and become a backup browser"},
  { 0x02, "Discard browse lists, stop being a master browser, and try again"},
  { 0x04, "Stop being a master browser for ever"},
  { 0, NULL}
};

static true_false_string tfs_demote_to_backup = {
	"Demote an LMB to a Backup Browser",
	"Do not demote an LMB to a Backup Browser"
};

static true_false_string tfs_flush_browse_list = {
	"Flush the Browse List",
	"Do not Flush the Browse List"
};

static true_false_string tfs_stop_being_lmb = {
	"Stop Being a Local Master Browser",
	"Do not Stop Being a Local Master Browser"
};

static const true_false_string tfs_workstation = {
	"This is a Workstation",
	"This is NOT a Workstation"
};
static const true_false_string tfs_server = {
	"This is a Server",
	"This is NOT a Server"
};
static const true_false_string tfs_sql = {
	"This is an SQL server",
	"This is NOT an SQL server"
};
static const true_false_string tfs_domain = {
	"This is a Domain Controller",
	"This is NOT a Domain Controller"
};
static const true_false_string tfs_backup = {
	"This is a Backup Controller",
	"This is NOT a Backup Controller"
};
static const true_false_string tfs_time = {
	"This is a Time Source",
	"This is NOT a Time Source"
};
static const true_false_string tfs_apple = {
	"This is an Apple host",
	"This is NOT an Apple host"
};
static const true_false_string tfs_novell = {
	"This is a Novell server",
	"This is NOT a Novell server"
};
static const true_false_string tfs_member = {
	"This is a Domain Member server",
	"This is NOT a Domain Member server"
};
static const true_false_string tfs_print = {
	"This is a Print Queue server",
	"This is NOT a Print Queue server"
};
static const true_false_string tfs_dialin = {
	"This is a Dialin server",
	"This is NOT a Dialin server"
};
static const true_false_string tfs_xenix = {
	"This is a Xenix server",
	"This is NOT a Xenix server"
};
static const true_false_string tfs_ntw = {
	"This is an NT Workstation",
	"This is NOT an NT Workstation"
};
static const true_false_string tfs_wfw = {
	"This is a WfW host",
	"This is NOT a WfW host"
};
static const true_false_string tfs_nts = {
	"This is an NT Server",
	"This is NOT an NT Server"
};
static const true_false_string tfs_potentialb = {
	"This is a Potential Browser",
	"This is NOT a Potential Browser"
};
static const true_false_string tfs_backupb = {
	"This is a Backup Browser",
	"This is NOT a Backup Browser"
};
static const true_false_string tfs_masterb = {
	"This is a Master Browser",
	"This is NOT a Master Browser"
};
static const true_false_string tfs_domainmasterb = {
	"This is a Domain Master Browser",
	"This is NOT a Domain Master Browser"
};
static const true_false_string tfs_osf = {
	"This is an OSF host",
	"This is NOT an OSF host"
};
static const true_false_string tfs_vms = {
	"This is a VMS host",
	"This is NOT a VMS host"
};
static const true_false_string tfs_w95 = {
	"This is a Windows 95 or above host",
	"This is NOT a Windows 95 or above host"
};
static const true_false_string tfs_local = {
	"This is a local list only request",
	"This is NOT a local list only request"
};
static const true_false_string tfs_domainenum = {
	"This is a Domain Enum request",
	"This is NOT a Domain Enum request"
};

#define DESIRE_BACKUP			0
#define DESIRE_STANDBY			1
#define DESIRE_MASTER			2
#define DESIRE_DOMAIN_MASTER		3
#define DESIRE_WINS			5
#define DESIRE_NT			7

static const true_false_string tfs_desire_backup = {
	"Backup Browse Server",
	"NOT Backup Browse Server"
};
static const true_false_string tfs_desire_standby = {
	"Standby Browse Server",
	"NOT Standby Browse Server"
};
static const true_false_string tfs_desire_master = {
	"Master Browser",
	"NOT Master Browser"
};
static const true_false_string tfs_desire_domain_master = {
	"Domain Master Browse Server",
	"NOT Domain Master Browse Server"
};
static const true_false_string tfs_desire_wins = {
	"WINS Client",
	"NOT WINS Client"
};
static const true_false_string tfs_desire_nt = {
	"Windows NT Advanced Server",
	"NOT Windows NT Advanced Server"
};

#define BROWSE_HOST_ANNOUNCE			1
#define BROWSE_REQUEST_ANNOUNCE			2
#define BROWSE_ELECTION_REQUEST			8
#define BROWSE_BACKUP_LIST_REQUEST		9
#define BROWSE_BACKUP_LIST_RESPONSE		10
#define BROWSE_BECOME_BACKUP			11
#define BROWSE_DOMAIN_ANNOUNCEMENT		12
#define BROWSE_MASTER_ANNOUNCEMENT		13
#define BROWSE_RESETBROWSERSTATE_ANNOUNCEMENT   14
#define BROWSE_LOCAL_MASTER_ANNOUNCEMENT	15

static const value_string commands[] = {
	{BROWSE_HOST_ANNOUNCE,		"Host Announcement"},
	{BROWSE_REQUEST_ANNOUNCE,	"Request Announcement"},
	{BROWSE_ELECTION_REQUEST,	"Browser Election Request"},
	{BROWSE_BACKUP_LIST_REQUEST,	"Get Backup List Request"},
	{BROWSE_BACKUP_LIST_RESPONSE,	"Get Backup List Response"},
	{BROWSE_BECOME_BACKUP,		"Become Backup Browser"},
	{BROWSE_DOMAIN_ANNOUNCEMENT,	"Domain/Workgroup Announcement"},
	{BROWSE_MASTER_ANNOUNCEMENT,	"Master Announcement"},
	{BROWSE_RESETBROWSERSTATE_ANNOUNCEMENT, "Reset Browser State Announcement"},
	{BROWSE_LOCAL_MASTER_ANNOUNCEMENT,"Local Master Announcement"},
	{0,				NULL}
};

#define OS_WFW				0
#define OS_NTW				4
#define OS_NTS				5

static const true_false_string tfs_os_wfw = {
	"Windows for Workgroups",
	"Not Windows for Workgroups"
};
static const true_false_string tfs_os_ntw = {
	"Windows NT Workstation",
	"Not Windows NT Workstation"
};
static const true_false_string tfs_os_nts = {
	"Windows NT Server",
	"Not Windows NT Server"
};

static void
dissect_election_criterion_os(tvbuff_t *tvb, proto_tree *parent_tree, int offset)
{
	proto_tree *tree = NULL;
	proto_item *item = NULL;
	guint8 os;

	os = tvb_get_guint8(tvb, offset);

	if (parent_tree) {
		item = proto_tree_add_uint(parent_tree, hf_election_os, tvb, offset, 1, os);
	      	tree = proto_item_add_subtree(item, ett_browse_election_os);
	}

	proto_tree_add_boolean(tree, hf_election_os_wfw,
		tvb, offset, 1, os);
	proto_tree_add_boolean(tree, hf_election_os_ntw,
		tvb, offset, 1, os);
	proto_tree_add_boolean(tree, hf_election_os_nts,
		tvb, offset, 1, os);

}

static void
dissect_election_criterion_desire(tvbuff_t *tvb, proto_tree *parent_tree, int offset)
{
	proto_tree *tree = NULL;
	proto_item *item = NULL;
	guint8 desire;

	desire = tvb_get_guint8(tvb, offset);

	if (parent_tree) {
		item = proto_tree_add_uint(parent_tree, hf_election_desire, tvb, offset, 1, desire);
	      	tree = proto_item_add_subtree(item, ett_browse_election_desire);
	}

	proto_tree_add_boolean(tree, hf_election_desire_flags_backup,
		tvb, offset, 1, desire);
	proto_tree_add_boolean(tree, hf_election_desire_flags_standby,
		tvb, offset, 1, desire);
	proto_tree_add_boolean(tree, hf_election_desire_flags_master,
		tvb, offset, 1, desire);
	proto_tree_add_boolean(tree, hf_election_desire_flags_domain_master,
		tvb, offset, 1, desire);
	proto_tree_add_boolean(tree, hf_election_desire_flags_wins,
		tvb, offset, 1, desire);
	proto_tree_add_boolean(tree, hf_election_desire_flags_nt,
		tvb, offset, 1, desire);

}

static void
dissect_election_criterion(tvbuff_t *tvb, proto_tree *parent_tree, int offset)
{
	proto_tree *tree = NULL;
	proto_item *item = NULL;
	guint32 criterion;

	criterion = tvb_get_letohl(tvb, offset);

	if (parent_tree) {
		item = proto_tree_add_uint(parent_tree, hf_election_criteria, tvb, offset, 4, criterion);
	      	tree = proto_item_add_subtree(item, ett_browse_election_criteria);
	}

	/* election desire */
	dissect_election_criterion_desire(tvb, tree, offset);
	offset += 1;

	/* browser protocol major version */
	proto_tree_add_item(tree, hf_proto_major, tvb, offset, 1, TRUE);
	offset += 1;

	/* browser protocol minor version */
	proto_tree_add_item(tree, hf_proto_minor, tvb, offset, 1, TRUE);
	offset += 1;

	/* election os */
	dissect_election_criterion_os(tvb, tree, offset);
	offset += 1;

}

/*
 * XXX - this causes non-browser packets to have browser fields.
 */
int
dissect_smb_server_type_flags(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *parent_tree, guint8 *drep, 
			      gboolean infoflag)
{
	proto_tree *tree = NULL;
	proto_item *item = NULL;
	guint32 flags;
	int i;

	if (drep != NULL) {
		/*
		 * Called from a DCE RPC protocol dissector, for a
		 * protocol where a 32-bit NDR integer contains
		 * an server type mask; extract the server type mask
		 * with an NDR call (but don't put it into the
		 * protocol tree, as we can't get a pointer to the
		 * item it puts in, and thus can't put a tree below
		 * it with the values of the individual bits).
		 */
		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, NULL, drep, hf_server_type, &flags);
	} else {
		/*
		 * Called from SMB browser or RAP, where the server type
		 * mask is just a 4-byte little-endian quantity with no
		 * special NDR alignment requirement; extract it with
		 * "tvb_get_letohl()".
		 */
		flags = tvb_get_letohl(tvb, offset);
		offset += 4;
	}

	if (parent_tree) {
		item = proto_tree_add_uint(parent_tree, hf_server_type, tvb, offset-4, 4, flags);
	      	tree = proto_item_add_subtree(item, ett_browse_flags);
	}

	if (infoflag) {
		/* Append the type(s) of the system to the COL_INFO line ... */
		if (check_col(pinfo->cinfo, COL_INFO)) {
			for (i = 0; i < 32; i++) {
				if (flags & (1<<i)) {
					col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
						val_to_str(i, server_types,
						"Unknown server type:%d"));
				}
			}
		}
	}

	proto_tree_add_boolean(tree, hf_server_type_workstation,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_server,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_sql,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_domain,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_backup,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_time,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_apple,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_novell,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_member,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_print,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_dialin,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_xenix,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_ntw,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_wfw,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_nts,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_potentialb,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_backupb,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_masterb,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_domainmasterb,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_osf,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_vms,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_w95,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_local,
		tvb, offset-4, 4, flags);
	proto_tree_add_boolean(tree, hf_server_type_domainenum,
		tvb, offset-4, 4, flags);

	return offset;
}


static void
dissect_mailslot_browse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	guint8 cmd;
	proto_tree *tree = NULL;
	proto_item *item = NULL;
	guint32 periodicity;
	guint8 host_name[17];
	gint namelen;
	guint8 server_count, reset_cmd;
	int i;
	guint32 uptime;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BROWSER");
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
	}

	cmd = tvb_get_guint8(tvb, offset);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		/* Put in something, and replace it later */
		col_set_str(pinfo->cinfo, COL_INFO, val_to_str(cmd, commands, "Unknown command:0x%02x"));
	}


	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, proto_smb_browse, tvb, offset, -1, TRUE);

		tree = proto_item_add_subtree(item, ett_browse);
	}

	/* command */
	proto_tree_add_uint(tree, hf_command, tvb, offset, 1, cmd);
	offset += 1;

	switch (cmd) {
	case BROWSE_DOMAIN_ANNOUNCEMENT:
	case BROWSE_LOCAL_MASTER_ANNOUNCEMENT:
	case BROWSE_HOST_ANNOUNCE: {
		/* update count */
		proto_tree_add_item(tree, hf_update_count, tvb, offset, 1, TRUE);
		offset += 1;

		/* periodicity (in milliseconds) */
		periodicity = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint_format(tree, hf_periodicity, tvb, offset, 4,
		    periodicity,
		    "Update Periodicity: %s",
		    time_msecs_to_str(periodicity));
		offset += 4;

		/* server name */
		tvb_get_nstringz0(tvb, offset, sizeof(host_name), host_name);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s", host_name);
		}
		proto_tree_add_string_format(tree, hf_server_name,
			tvb, offset, 16,
			host_name,
			(cmd==BROWSE_DOMAIN_ANNOUNCEMENT)?
				"Domain/Workgroup: %s":
				"Host Name: %s",
			host_name);
		offset += 16;

		/* OS major version */
		proto_tree_add_item(tree, hf_os_major, tvb, offset, 1, TRUE);
		offset += 1;

		/* OS minor version */
		proto_tree_add_item(tree, hf_os_minor, tvb, offset, 1, TRUE);
		offset += 1;

		/* server type flags */
		offset = dissect_smb_server_type_flags(
			tvb, offset, pinfo, tree, NULL, TRUE);

		if (cmd == BROWSE_DOMAIN_ANNOUNCEMENT) {
			/*
			 * Network Monitor claims this is a "Comment
			 * Pointer".  I don't believe it.
			 *
			 * It's not a browser protocol major/minor
			 * version number, and signature constant,
			 * however.
			 */
			proto_tree_add_text(tree, tvb, offset, 4,
			    "Mysterious Field: 0x%08x",
			    tvb_get_letohl(tvb, offset));
			offset += 4;
		} else {
			/* browser protocol major version */
			proto_tree_add_item(tree, hf_proto_major, tvb, offset, 1, TRUE);
			offset += 1;

			/* browser protocol minor version */
			proto_tree_add_item(tree, hf_proto_minor, tvb, offset, 1, TRUE);
			offset += 1;

			/* signature constant */
			proto_tree_add_item(tree, hf_sig_const, tvb, offset, 2, TRUE);
			offset += 2;
		}

		/* master browser server name or server comment */
		namelen = tvb_strsize(tvb, offset);
		proto_tree_add_item(tree,
			(cmd==BROWSE_DOMAIN_ANNOUNCEMENT)?
			    hf_mb_server_name : hf_server_comment,
			tvb, offset, namelen, TRUE);
		offset += namelen;
		break;
	}
	case BROWSE_REQUEST_ANNOUNCE: {
		guint8 *computer_name;

		/* unused/unknown flags */
		proto_tree_add_item(tree, hf_unused_flags,
			tvb, offset, 1, TRUE);
		offset += 1;

		/* name of computer to which to send reply */
		computer_name = tvb_get_ephemeral_stringz(tvb, offset, &namelen);
		proto_tree_add_string(tree, hf_response_computer_name,
			tvb, offset, namelen, computer_name);
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(
				pinfo->cinfo, COL_INFO, " %s", computer_name);
		offset += namelen;
		break;
	}

	case BROWSE_ELECTION_REQUEST:
		/* election version */
		proto_tree_add_item(tree, hf_election_version, tvb, offset, 1, TRUE);
		offset += 1;

		/* criterion */
		dissect_election_criterion(tvb, tree, offset);
		offset += 4;

		/* server uptime */
		uptime = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint_format(tree, hf_server_uptime,
		    tvb, offset, 4, uptime,
		    "Uptime: %s",
		    time_msecs_to_str(uptime));
		offset += 4;

		/* next 4 bytes must be zero */
		offset += 4;

		/* server name */
		namelen = tvb_strsize(tvb, offset);
		proto_tree_add_item(tree, hf_server_name,
			tvb, offset, namelen, TRUE);
		offset += namelen;
		break;

	case BROWSE_BACKUP_LIST_REQUEST:
		/* backup list requested count */
		proto_tree_add_item(tree, hf_backup_count, tvb, offset, 1, TRUE);
		offset += 1;

		/* backup requested token */
		proto_tree_add_item(tree, hf_backup_token, tvb, offset, 4, TRUE);
		offset += 4;
		break;

	case BROWSE_BACKUP_LIST_RESPONSE:
		/* backup list requested count */
		server_count = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(tree, hf_backup_count, tvb, offset, 1,
		    server_count);
		offset += 1;

		/* backup requested token */
		proto_tree_add_item(tree, hf_backup_token, tvb, offset, 4, TRUE);
		offset += 4;

		/* backup server names */
		for (i = 0; i < server_count; i++) {
			namelen = tvb_strsize(tvb, offset);
			proto_tree_add_item(tree, hf_backup_server,
				tvb, offset, namelen, TRUE);
			offset += namelen;
		}
		break;

	case BROWSE_MASTER_ANNOUNCEMENT:
		/* master browser server name */
		namelen = tvb_strsize(tvb, offset);
		proto_tree_add_item(tree, hf_mb_server_name,
			tvb, offset, namelen, TRUE);
		offset += namelen;
		break;

	case BROWSE_RESETBROWSERSTATE_ANNOUNCEMENT: {
	        proto_tree *sub_tree;
	        proto_item *reset_item;

		/* the subcommand follows ... one of three values */

	        reset_cmd = tvb_get_guint8(tvb, offset);
		reset_item = proto_tree_add_uint(tree, hf_mb_reset_command, tvb, 
						 offset, 1, reset_cmd);
		sub_tree = proto_item_add_subtree(item, ett_browse_reset_cmd_flags);
		proto_tree_add_boolean(sub_tree, hf_mb_reset_demote, tvb, 
				       offset, 1, reset_cmd);
		proto_tree_add_boolean(sub_tree, hf_mb_reset_flush, tvb, 
				       offset, 1, reset_cmd);
		proto_tree_add_boolean(sub_tree, hf_mb_reset_stop, tvb, 
				       offset, 1, reset_cmd);
		offset += 1;
		break;
	}

	case BROWSE_BECOME_BACKUP:
		/* name of browser to promote */
		namelen = tvb_strsize(tvb, offset);
		proto_tree_add_item(tree, hf_browser_to_promote,
			tvb, offset, namelen, TRUE);
		offset += namelen;
		break;
	}
}

/*
 * It appears that browser announcements sent to \MAILSLOT\LANMAN aren't
 * the same as browser announcements sent to \MAILSLOT\BROWSE.
 * Was that an older version of the protocol?
 *
 * The document at
 *
 *	http://www.samba.org/samba/ftp/specs/brow_rev.txt
 *
 * gives both formats of host announcement packets, saying that
 * "[The first] format seems wrong", that one being what appears to
 * show up in \MAILSLOT\LANMAN packets, and that "[The second one]
 * may be better", that one being what appears to show up in
 * \MAILSLOT\BROWSE packets.
 *
 * XXX - what other browser packets go out to that mailslot?
 */
static void
dissect_mailslot_lanman(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	guint8 cmd;
	proto_tree *tree = NULL;
	proto_item *item = NULL;
	guint32 periodicity;
	const guint8 *host_name;
	guint namelen;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BROWSER");
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
	}

	cmd = tvb_get_guint8(tvb, offset);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		/* Put in something, and replace it later */
		col_set_str(pinfo->cinfo, COL_INFO, val_to_str(cmd, commands, "Unknown command:0x%02x"));
	}


	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, proto_smb_browse, tvb, offset, -1, TRUE);

		tree = proto_item_add_subtree(item, ett_browse);
	}

	/* command */
	proto_tree_add_uint(tree, hf_command, tvb, offset, 1, cmd);
	offset += 1;

	switch (cmd) {
	case BROWSE_DOMAIN_ANNOUNCEMENT:
	case BROWSE_LOCAL_MASTER_ANNOUNCEMENT:
	case BROWSE_HOST_ANNOUNCE:

		/* update count */
		proto_tree_add_item(tree, hf_update_count, tvb, offset, 1, TRUE);
		offset += 1;

		/* server type flags */
		offset = dissect_smb_server_type_flags(
			tvb, offset, pinfo, tree, NULL, TRUE);

		/* OS major version */
		proto_tree_add_item(tree, hf_os_major, tvb, offset, 1, TRUE);
		offset += 1;

		/* OS minor version */
		proto_tree_add_item(tree, hf_os_minor, tvb, offset, 1, TRUE);
		offset += 1;

		/* periodicity (in seconds; convert to milliseconds) */
		periodicity = tvb_get_letohs(tvb, offset)*1000;
		proto_tree_add_uint_format(tree, hf_periodicity, tvb, offset, 2,
		    periodicity,
		    "Update Periodicity: %s",
		    time_msecs_to_str(periodicity));
		offset += 2;

		/* server name */
		namelen = tvb_strsize(tvb, offset);
		host_name = tvb_get_ptr(tvb, offset, namelen);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s", host_name);
		}
		proto_tree_add_item(tree, hf_server_name,
			tvb, offset, namelen, TRUE);
		offset += namelen;

		/* master browser server name or server comment */
		namelen = tvb_strsize(tvb, offset);
		proto_tree_add_item(tree,
			(cmd==BROWSE_DOMAIN_ANNOUNCEMENT)?
			    hf_mb_server_name : hf_server_comment,
			tvb, offset, namelen, TRUE);
		offset += namelen;
		break;
	}
}

void
proto_register_smb_browse(void)
{
	static hf_register_info hf[] = {
		{ &hf_command,
			{ "Command", "browser.command", FT_UINT8, BASE_HEX,
			VALS(commands), 0, "Browse command opcode", HFILL }},

		{ &hf_update_count,
			{ "Update Count", "browser.update_count", FT_UINT8, BASE_DEC,
			NULL, 0, "Browse Update Count", HFILL }},

		{ &hf_periodicity,
			{ "Update Periodicity", "browser.period", FT_UINT32, BASE_DEC,
			NULL, 0, "Update Periodicity in ms", HFILL }},

		{ &hf_server_name,
			{ "Server Name", "browser.server", FT_STRING, BASE_NONE,
			NULL, 0, "BROWSE Server Name", HFILL }},

		{ &hf_mb_server_name,
			{ "Master Browser Server Name", "browser.mb_server", FT_STRING, BASE_NONE,
			NULL, 0, "BROWSE Master Browser Server Name", HFILL }},

		{ &hf_mb_reset_command,
		  { "ResetBrowserState Command", "browser.reset_cmd", FT_UINT8,
		    BASE_HEX, VALS(&resetbrowserstate_command_names), 0,
		    "ResetBrowserState Command", HFILL }},
		{ &hf_mb_reset_demote,
		  { "Demote LMB", "browser.reset_cmd.demote", FT_BOOLEAN, 
		    8, TFS(&tfs_demote_to_backup), 0x01, "Demote LMB", HFILL}}, 
		{ &hf_mb_reset_flush,
		  { "Flush Browse List", "browser.reset_cmd.flush", FT_BOOLEAN,
		    8, TFS(&tfs_flush_browse_list), 0x02, "Flush Browse List", HFILL}},
		{ &hf_mb_reset_stop,
		  { "Stop Being LMB", "browser.reset_cmd.stop_lmb", FT_BOOLEAN,
		    8, TFS(&tfs_stop_being_lmb), 0x04, "Stop Being LMB", HFILL}},
		{ &hf_os_major,
			{ "OS Major Version", "browser.os_major", FT_UINT8, BASE_DEC,
			NULL, 0, "Operating System Major Version", HFILL }},

		{ &hf_os_minor,
			{ "OS Minor Version", "browser.os_minor", FT_UINT8, BASE_DEC,
			NULL, 0, "Operating System Minor Version", HFILL }},

		{ &hf_server_type,
			{ "Server Type", "browser.server_type", FT_UINT32, BASE_HEX,
			NULL, 0, "Server Type Flags", HFILL }},

		{ &hf_server_type_workstation,
			{ "Workstation", "browser.server_type.workstation", FT_BOOLEAN, 32,
			TFS(&tfs_workstation), 1<<SERVER_WORKSTATION, "Is This A Workstation?", HFILL }},

		{ &hf_server_type_server,
			{ "Server", "browser.server_type.server", FT_BOOLEAN, 32,
			TFS(&tfs_server), 1<<SERVER_SERVER, "Is This A Server?", HFILL }},

		{ &hf_server_type_sql,
			{ "SQL", "browser.server_type.sql", FT_BOOLEAN, 32,
			TFS(&tfs_sql), 1<<SERVER_SQL_SERVER, "Is This A SQL Server?", HFILL }},

		{ &hf_server_type_domain,
			{ "Domain Controller", "browser.server_type.domain_controller", FT_BOOLEAN, 32,
			TFS(&tfs_domain), 1<<SERVER_DOMAIN_CONTROLLER, "Is This A Domain Controller?", HFILL }},

		{ &hf_server_type_backup,
			{ "Backup Controller", "browser.server_type.backup_controller", FT_BOOLEAN, 32,
			TFS(&tfs_backup), 1<<SERVER_BACKUP_CONTROLLER, "Is This A Backup Domain Controller?", HFILL }},

		{ &hf_server_type_time,
			{ "Time Source", "browser.server_type.time", FT_BOOLEAN, 32,
			TFS(&tfs_time), 1<<SERVER_TIME_SOURCE, "Is This A Time Source?", HFILL }},

		{ &hf_server_type_apple,
			{ "Apple", "browser.server_type.apple", FT_BOOLEAN, 32,
			TFS(&tfs_apple), 1<<SERVER_APPLE_SERVER, "Is This An Apple Server ?", HFILL }},

		{ &hf_server_type_novell,
			{ "Novell", "browser.server_type.novell", FT_BOOLEAN, 32,
			TFS(&tfs_novell), 1<<SERVER_NOVELL_SERVER, "Is This A Novell Server?", HFILL }},

		{ &hf_server_type_member,
			{ "Member", "browser.server_type.member", FT_BOOLEAN, 32,
			TFS(&tfs_member), 1<<SERVER_DOMAIN_MEMBER_SERVER, "Is This A Domain Member Server?", HFILL }},

		{ &hf_server_type_print,
			{ "Print", "browser.server_type.print", FT_BOOLEAN, 32,
			TFS(&tfs_print), 1<<SERVER_PRINT_QUEUE_SERVER, "Is This A Print Server?", HFILL }},

		{ &hf_server_type_dialin,
			{ "Dialin", "browser.server_type.dialin", FT_BOOLEAN, 32,
			TFS(&tfs_dialin), 1<<SERVER_DIALIN_SERVER, "Is This A Dialin Server?", HFILL }},

		{ &hf_server_type_xenix,
			{ "Xenix", "browser.server_type.xenix", FT_BOOLEAN, 32,
			TFS(&tfs_xenix), 1<<SERVER_XENIX_SERVER, "Is This A Xenix Server?", HFILL }},

		{ &hf_server_type_ntw,
			{ "NT Workstation", "browser.server_type.ntw", FT_BOOLEAN, 32,
			TFS(&tfs_ntw), 1<<SERVER_NT_WORKSTATION, "Is This A NT Workstation?", HFILL }},

		{ &hf_server_type_wfw,
			{ "WfW", "browser.server_type.wfw", FT_BOOLEAN, 32,
			TFS(&tfs_wfw), 1<<SERVER_WINDOWS_FOR_WORKGROUPS, "Is This A Windows For Workgroups Server?", HFILL }},

		{ &hf_server_type_nts,
			{ "NT Server", "browser.server_type.nts", FT_BOOLEAN, 32,
			TFS(&tfs_nts), 1<<SERVER_NT_SERVER, "Is This A NT Server?", HFILL }},

		{ &hf_server_type_potentialb,
			{ "Potential Browser", "browser.server_type.browser.potential", FT_BOOLEAN, 32,
			TFS(&tfs_potentialb), 1<<SERVER_POTENTIAL_BROWSER, "Is This A Potential Browser?", HFILL }},

		{ &hf_server_type_backupb,
			{ "Backup Browser", "browser.server_type.browser.backup", FT_BOOLEAN, 32,
			TFS(&tfs_backupb), 1<<SERVER_BACKUP_BROWSER, "Is This A Backup Browser?", HFILL }},

		{ &hf_server_type_masterb,
			{ "Master Browser", "browser.server_type.browser.master", FT_BOOLEAN, 32,
			TFS(&tfs_masterb), 1<<SERVER_MASTER_BROWSER, "Is This A Master Browser?", HFILL }},

		{ &hf_server_type_domainmasterb,
			{ "Domain Master Browser", "browser.server_type.browser.domain_master", FT_BOOLEAN, 32,
			TFS(&tfs_domainmasterb), 1<<SERVER_DOMAIN_MASTER_BROWSER, "Is This A Domain Master Browser?", HFILL }},

		{ &hf_server_type_osf,
			{ "OSF", "browser.server_type.osf", FT_BOOLEAN, 32,
			TFS(&tfs_osf), 1<<SERVER_OSF, "Is This An OSF server ?", HFILL }},

		{ &hf_server_type_vms,
			{ "VMS", "browser.server_type.vms", FT_BOOLEAN, 32,
			TFS(&tfs_vms), 1<<SERVER_VMS, "Is This A VMS Server?", HFILL }},

		{ &hf_server_type_w95,
			{ "Windows 95+", "browser.server_type.w95", FT_BOOLEAN, 32,
			TFS(&tfs_w95), 1<<SERVER_WINDOWS_95, "Is This A Windows 95 or above server?", HFILL }},

		{ &hf_server_type_local,
			{ "Local", "browser.server_type.local", FT_BOOLEAN, 32,
			TFS(&tfs_local), 1<<SERVER_LOCAL_LIST_ONLY, "Is This A Local List Only request?", HFILL }},

		{ &hf_server_type_domainenum,
			{ "Domain Enum", "browser.server_type.domainenum", FT_BOOLEAN, 32,
			TFS(&tfs_domainenum), 1<<SERVER_DOMAIN_ENUM, "Is This A Domain Enum request?", HFILL }},

		{ &hf_election_version,
			{ "Election Version", "browser.election.version", FT_UINT8, BASE_DEC,
			NULL, 0, "Election Version", HFILL }},

		{ &hf_proto_major,
			{ "Browser Protocol Major Version", "browser.proto_major", FT_UINT8, BASE_DEC,
			NULL, 0, "Browser Protocol Major Version", HFILL }},

		{ &hf_proto_minor,
			{ "Browser Protocol Minor Version", "browser.proto_minor", FT_UINT8, BASE_DEC,
			NULL, 0, "Browser Protocol Minor Version", HFILL }},

		{ &hf_sig_const,
			{ "Signature", "browser.sig", FT_UINT16, BASE_HEX,
			NULL, 0, "Signature Constant", HFILL }},

		{ &hf_server_comment,
			{ "Host Comment", "browser.comment", FT_STRINGZ, BASE_NONE,
			NULL, 0, "Server Comment", HFILL }},

		{ &hf_unused_flags,
			{ "Unused flags", "browser.unused", FT_UINT8, BASE_HEX,
			NULL, 0, "Unused/unknown flags", HFILL }},

		{ &hf_response_computer_name,
			{ "Response Computer Name", "browser.response_computer_name", FT_STRINGZ, BASE_NONE,
			NULL, 0, "Response Computer Name", HFILL }},

		{ &hf_election_criteria,
			{ "Election Criteria", "browser.election.criteria", FT_UINT32, BASE_HEX,
			NULL, 0, "Election Criteria", HFILL }},

		{ &hf_election_desire,
			{ "Election Desire", "browser.election.desire", FT_UINT8, BASE_HEX,
			NULL, 0, "Election Desire", HFILL }},

		{ &hf_election_desire_flags_backup,
			{ "Backup", "browser.election.desire.backup", FT_BOOLEAN, 8,
			TFS(&tfs_desire_backup), 1<<DESIRE_BACKUP, "Is this a backup server", HFILL }},

		{ &hf_election_desire_flags_standby,
			{ "Standby", "browser.election.desire.standby", FT_BOOLEAN, 8,
			TFS(&tfs_desire_standby), 1<<DESIRE_STANDBY, "Is this a standby server?", HFILL }},

		{ &hf_election_desire_flags_master,
			{ "Master", "browser.election.desire.master", FT_BOOLEAN, 8,
			TFS(&tfs_desire_master), 1<<DESIRE_MASTER, "Is this a master server", HFILL }},

		{ &hf_election_desire_flags_domain_master,
			{ "Domain Master", "browser.election.desire.domain_master", FT_BOOLEAN, 8,
			TFS(&tfs_desire_domain_master), 1<<DESIRE_DOMAIN_MASTER, "Is this a domain master", HFILL }},

		{ &hf_election_desire_flags_wins,
			{ "WINS", "browser.election.desire.wins", FT_BOOLEAN, 8,
			TFS(&tfs_desire_wins), 1<<DESIRE_WINS, "Is this a WINS server", HFILL }},

		{ &hf_election_desire_flags_nt,
			{ "NT", "browser.election.desire.nt", FT_BOOLEAN, 8,
			TFS(&tfs_desire_nt), 1<<DESIRE_NT, "Is this a NT server", HFILL }},

		{ &hf_election_revision,
			{ "Election Revision", "browser.election.revision", FT_UINT16, BASE_DEC,
			NULL, 0, "Election Revision", HFILL }},

		{ &hf_election_os,
			{ "Election OS", "browser.election.os", FT_UINT8, BASE_HEX,
			NULL, 0, "Election OS", HFILL }},

		{ &hf_election_os_wfw,
			{ "WfW", "browser.election.os.wfw", FT_BOOLEAN, 8,
			TFS(&tfs_os_wfw), 1<<OS_WFW, "Is this a WfW host?", HFILL }},

		{ &hf_election_os_ntw,
			{ "NT Workstation", "browser.election.os.ntw", FT_BOOLEAN, 8,
			TFS(&tfs_os_ntw), 1<<OS_NTW, "Is this a NT Workstation?", HFILL }},

		{ &hf_election_os_nts,
			{ "NT Server", "browser.election.os.nts", FT_BOOLEAN, 8,
			TFS(&tfs_os_nts), 1<<OS_NTS, "Is this a NT Server?", HFILL }},

		{ &hf_server_uptime,
			{ "Uptime", "browser.uptime", FT_UINT32, BASE_DEC,
			NULL, 0, "Server uptime in ms", HFILL }},

		{ &hf_backup_count,
			{ "Backup List Requested Count", "browser.backup.count", FT_UINT8, BASE_DEC,
			NULL, 0, "Backup list requested count", HFILL }},

		{ &hf_backup_token,
			{ "Backup Request Token", "browser.backup.token", FT_UINT32, BASE_DEC,
			NULL, 0, "Backup requested/response token", HFILL }},

		{ &hf_backup_server,
			{ "Backup Server", "browser.backup.server", FT_STRING, BASE_NONE,
			NULL, 0, "Backup Server Name", HFILL }},

		{ &hf_browser_to_promote,
			{ "Browser to Promote", "browser.browser_to_promote", FT_STRINGZ, BASE_NONE,
			NULL, 0, "Browser to Promote", HFILL }},

	};

	static gint *ett[] = {
		&ett_browse,
		&ett_browse_flags,
		&ett_browse_election_criteria,
		&ett_browse_election_os,
		&ett_browse_election_desire,
		&ett_browse_reset_cmd_flags,
	};

    	proto_smb_browse = proto_register_protocol("Microsoft Windows Browser Protocol",
	    "BROWSER", "browser");

	proto_register_field_array(proto_smb_browse, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("mailslot_browse", dissect_mailslot_browse,
	    proto_smb_browse);
	register_dissector("mailslot_lanman", dissect_mailslot_lanman,
	    proto_smb_browse);
}
