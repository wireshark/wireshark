/* packet-aim-generic.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Family Generic
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 *
 * $Id: packet-aim-generic.c,v 1.1 2004/03/23 06:21:16 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-aim.h"
#include "prefs.h"

#define STRIP_TAGS 1

/* SNAC families */
#define FAMILY_GENERIC    0x0001

/* Family Generic */
#define FAMILY_GENERIC_ERROR          0x0001
#define FAMILY_GENERIC_CLIENTREADY    0x0002
#define FAMILY_GENERIC_SERVERREADY    0x0003
#define FAMILY_GENERIC_SERVICEREQ     0x0004
#define FAMILY_GENERIC_REDIRECT       0x0005
#define FAMILY_GENERIC_RATEINFOREQ    0x0006
#define FAMILY_GENERIC_RATEINFO       0x0007
#define FAMILY_GENERIC_RATEINFOACK    0x0008
#define FAMILY_GENERIC_UNKNOWNx09     0x0009
#define FAMILY_GENERIC_RATECHANGE     0x000a
#define FAMILY_GENERIC_SERVERPAUSE    0x000b
#define FAMILY_GENERIC_CLIENTPAUSEACK 0x000c
#define FAMILY_GENERIC_SERVERRESUME   0x000d
#define FAMILY_GENERIC_REQSELFINFO    0x000e
#define FAMILY_GENERIC_SELFINFO       0x000f
#define FAMILY_GENERIC_EVIL           0x0010
#define FAMILY_GENERIC_SETIDLE        0x0011
#define FAMILY_GENERIC_MIGRATIONREQ   0x0012
#define FAMILY_GENERIC_MOTD           0x0013
#define FAMILY_GENERIC_SETPRIVFLAGS   0x0014
#define FAMILY_GENERIC_WELLKNOWNURL   0x0015
#define FAMILY_GENERIC_NOP            0x0016
#define FAMILY_GENERIC_CAPABILITIES   0x0017
#define FAMILY_GENERIC_CAPACK         0x0018
#define FAMILY_GENERIC_SETSTATUS      0x001e
#define FAMILY_GENERIC_CLIENTVERREQ   0x001f
#define FAMILY_GENERIC_CLIENTVERREPL  0x0020
#define FAMILY_GENERIC_DEFAULT        0xffff

static const value_string aim_fnac_family_generic[] = {
  { FAMILY_GENERIC_ERROR, "Error" },
  { FAMILY_GENERIC_CLIENTREADY , "Client Ready" },
  { FAMILY_GENERIC_SERVERREADY, "Server Ready" },
  { FAMILY_GENERIC_SERVICEREQ, "Service Request" },
  { FAMILY_GENERIC_REDIRECT, "Redirect" },
  { FAMILY_GENERIC_RATEINFOREQ, "Rate Info Request" },
  { FAMILY_GENERIC_RATEINFO, "Rate Info" },
  { FAMILY_GENERIC_RATEINFOACK, "Rate Info Ack" },
  { FAMILY_GENERIC_UNKNOWNx09, "Unknown" },
  { FAMILY_GENERIC_RATECHANGE, "Rate Change" },
  { FAMILY_GENERIC_SERVERPAUSE, "Server Pause" },
  { FAMILY_GENERIC_CLIENTPAUSEACK, "Client Pause Ack" },
  { FAMILY_GENERIC_SERVERRESUME, "Server Resume" },
  { FAMILY_GENERIC_REQSELFINFO, "Self Info Request" },
  { FAMILY_GENERIC_SELFINFO, "Self Info" },
  { FAMILY_GENERIC_EVIL, "Evil" },
  { FAMILY_GENERIC_SETIDLE, "Set Idle" },
  { FAMILY_GENERIC_MIGRATIONREQ, "Migration Request" },
  { FAMILY_GENERIC_MOTD, "Message Of The Day" },
  { FAMILY_GENERIC_SETPRIVFLAGS, "Set Privilege Flags" },
  { FAMILY_GENERIC_WELLKNOWNURL, "Well Known URL" },
  { FAMILY_GENERIC_NOP, "noop" },
  { FAMILY_GENERIC_CAPABILITIES, "Capabilities (ICQ specific)" },
  { FAMILY_GENERIC_CAPACK, "Capabilities Ack (ICQ specific)" },
  { FAMILY_GENERIC_SETSTATUS, "Set Status (ICQ specific)" },
  { FAMILY_GENERIC_CLIENTVERREQ, "Client Verification Requst" },
  { FAMILY_GENERIC_CLIENTVERREPL, "Client Verification Reply" },
  { FAMILY_GENERIC_DEFAULT, "Generic Default" },
  { 0, NULL }
};

#define FAMILY_GENERIC_MOTD_MOTDTYPE_MDT_UPGRADE       0x0001
#define FAMILY_GENERIC_MOTD_MOTDTYPE_ADV_UPGRADE       0x0002
#define FAMILY_GENERIC_MOTD_MOTDTYPE_SYS_BULLETIN      0x0003
#define FAMILY_GENERIC_MOTD_MOTDTYPE_NORMAL            0x0004
#define FAMILY_GENERIC_MOTD_MOTDTYPE_NEWS              0x0006

static const value_string aim_snac_generic_motd_motdtypes[] = {
  { FAMILY_GENERIC_MOTD_MOTDTYPE_MDT_UPGRADE, "Mandatory Upgrade Needed Notice" },
  { FAMILY_GENERIC_MOTD_MOTDTYPE_ADV_UPGRADE, "Advisable Upgrade Notice" },
  { FAMILY_GENERIC_MOTD_MOTDTYPE_SYS_BULLETIN, "AIM/ICQ Service System Announcements" },
  { FAMILY_GENERIC_MOTD_MOTDTYPE_NORMAL, "Standard Notice" },
  { FAMILY_GENERIC_MOTD_MOTDTYPE_NEWS, "News from AOL service" },
  { 0, NULL }
};

#define RATEINFO_STATE_LIMITED			0x01
#define RATEINFO_STATE_ALERT			0x02
#define RATEINFO_STATE_CLEAR			0x03

static const value_string rateinfo_states[] = {
	{ RATEINFO_STATE_LIMITED, "Limited" },
	{ RATEINFO_STATE_ALERT, "Alert" },
	{ RATEINFO_STATE_CLEAR, "Clear" },
	{ 0, NULL }
};

#define RATECHANGE_MSG_LIMIT_PARAMS_CHANGED      0x0001
#define RATECHANGE_MSG_LIMIT_WARN                0x0002
#define RATECHANGE_MSG_LIMIT_HIT                 0x0003
#define RATECHANGE_MSG_LIMIT_CLEAR               0x0004

static const value_string ratechange_msgs[] = {
	{ RATECHANGE_MSG_LIMIT_PARAMS_CHANGED, "Rate limits parameters changed" },
	{ RATECHANGE_MSG_LIMIT_WARN, "Rate limits warning (current level < alert level)" },
	{ RATECHANGE_MSG_LIMIT_HIT, "Rate limit hit (current level < limit level)" },
	{ RATECHANGE_MSG_LIMIT_CLEAR, "Rate limit clear (current level now > clear level)" },
	{ 0, NULL },
};

static int dissect_aim_snac_generic(tvbuff_t *tvb, packet_info *pinfo, 
				     proto_tree *tree);

/* Initialize the protocol and registered fields */
static int proto_aim_generic = -1;
static int hf_generic_motd_motdtype = -1;
static int hf_generic_servicereq_service = -1;
static int hf_generic_rateinfo_numclasses = -1;
static int hf_generic_rateinfo_windowsize = -1;
static int hf_generic_rateinfo_clearlevel = -1;
static int hf_generic_rateinfo_alertlevel = -1;
static int hf_generic_rateinfo_limitlevel = -1;
static int hf_generic_rateinfo_disconnectlevel = -1;
static int hf_generic_rateinfo_currentlevel = -1;
static int hf_generic_rateinfo_maxlevel = -1;
static int hf_generic_rateinfo_lasttime = -1;
static int hf_generic_rateinfo_curstate = -1;
static int hf_generic_rateinfo_classid = -1;
static int hf_generic_rateinfo_numpairs = -1;
static int hf_generic_rateinfoack_group = -1;
static int hf_generic_ratechange_msg    = -1;
static int hf_generic_migration_numfams  = -1;
static int hf_generic_priv_flags = -1;
static int hf_generic_allow_idle_see = -1;
static int hf_generic_allow_member_see = -1;

/* Initialize the subtree pointers */
static gint ett_generic_clientready = -1;
static gint ett_generic_migratefamilies = -1;
static gint ett_generic_clientready_item = -1;
static gint ett_generic_serverready = -1;
static gint ett_generic = -1;
static gint ett_generic_priv_flags = -1;
static gint ett_generic_rateinfo_class = -1;
static gint ett_generic_rateinfo_classes = -1;
static gint ett_generic_rateinfo_groups = -1;
static gint ett_generic_rateinfo_group = -1;

static int dissect_rate_class(tvbuff_t *tvb, packet_info *pinfo _U_, int offset,
					proto_tree *class_tree) {
	proto_tree_add_uint(class_tree, hf_generic_rateinfo_classid, tvb, offset, 2, tvb_get_ntohs(tvb, offset));offset+=2;
	proto_tree_add_uint(class_tree, hf_generic_rateinfo_windowsize, tvb, offset, 4, tvb_get_ntoh24(tvb, offset));offset+=4;
	proto_tree_add_uint(class_tree, hf_generic_rateinfo_clearlevel, tvb, offset, 4, tvb_get_ntoh24(tvb, offset));offset+=4;
	proto_tree_add_uint(class_tree, hf_generic_rateinfo_alertlevel, tvb, offset, 4, tvb_get_ntoh24(tvb, offset));offset+=4;
	proto_tree_add_uint(class_tree, hf_generic_rateinfo_limitlevel, tvb, offset, 4, tvb_get_ntoh24(tvb, offset));offset+=4;
	proto_tree_add_uint(class_tree, hf_generic_rateinfo_disconnectlevel, tvb, offset, 4, tvb_get_ntoh24(tvb, offset));offset+=4;
	proto_tree_add_uint(class_tree, hf_generic_rateinfo_currentlevel, tvb, offset, 4, tvb_get_ntoh24(tvb, offset));offset+=4;
	proto_tree_add_uint(class_tree, hf_generic_rateinfo_maxlevel, tvb, offset, 4, tvb_get_ntoh24(tvb, offset));offset+=4;
	proto_tree_add_uint(class_tree, hf_generic_rateinfo_lasttime, tvb, offset, 4, tvb_get_ntoh24(tvb, offset));offset+=4;
	proto_tree_add_uint(class_tree, hf_generic_rateinfo_curstate, tvb, offset, 1, tvb_get_guint8(tvb, offset));offset+=1;
	return offset;
}

static int dissect_generic_rateinfo(tvbuff_t *tvb, packet_info *pinfo _U_, 
				    proto_tree *tree) {
	int offset = 0;
	guint16 i;
	proto_item *ti;
	guint16 numclasses = tvb_get_ntohs(tvb, 0);	
	proto_tree *classes_tree, *groups_tree, *group_tree;
    proto_tree_add_uint(tree, hf_generic_rateinfo_numclasses, tvb, 0, 2, numclasses );
	offset+=2;

	ti = proto_tree_add_text(tree, tvb, offset, 33*numclasses, "Available Rate Classes");
	classes_tree = proto_item_add_subtree(ti, ett_generic_rateinfo_classes);

	for(i = 0; i < numclasses; i++) {
		guint16 myid = tvb_get_ntohs(tvb, offset); 
		proto_item *ti = proto_tree_add_text(classes_tree, tvb, offset, 33,"Rate Class 0x%02x", myid);
		proto_tree *class_tree = proto_item_add_subtree(ti, ett_generic_rateinfo_class);
		offset = dissect_rate_class(tvb, pinfo, offset, class_tree);
	}

	ti = proto_tree_add_text(tree, tvb, offset, -1, "Rate Groups");
	groups_tree = proto_item_add_subtree(ti, ett_generic_rateinfo_groups);

	for(i = 0; i < numclasses; i++) {
		guint16 myid = tvb_get_ntohs(tvb, offset); 
		guint16 j;
		guint16 numpairs;

		proto_item *ti = proto_tree_add_text(groups_tree, tvb, offset, 33,"Rate Group 0x%02x", myid);
		group_tree = proto_item_add_subtree(ti, ett_generic_rateinfo_group);
		proto_tree_add_uint(group_tree, hf_generic_rateinfo_classid, tvb, offset, 2, myid);offset+=2;
		numpairs = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(group_tree, hf_generic_rateinfo_numpairs, tvb, offset, 2, numpairs); offset+=2;
		for(j = 0; j < numpairs; j++) {
			const char *fam_name, *subtype_name;
			guint16 family; 
			guint16 subtype;
			family = tvb_get_ntohs(tvb, offset); offset+=2;
			subtype = tvb_get_ntohs(tvb, offset); offset+=2;

			fam_name = aim_get_familyname(family);
			subtype_name = aim_get_subtypename(family, subtype);

			proto_tree_add_text(group_tree, tvb, offset-4, 4, "Family: %s (0x%04x), Subtype: %s (0x%04x)", fam_name?fam_name:"Unknown", family, subtype_name?subtype_name:"Unknown", subtype);
		}
	}
	
	return offset;
}

static int dissect_aim_snac_generic(tvbuff_t *tvb, packet_info *pinfo, 
				    proto_tree *tree)
{
  int offset = 0;
  const char *name;
  struct aiminfo *aiminfo = pinfo->private_data;
  guint16 n, i;
  proto_item *ti = NULL;
  proto_tree *gen_tree = NULL;
  proto_tree *entry = NULL;

  if(tree) {
    ti = proto_tree_add_text(tree, tvb, 0, -1,"AIM Generic Service");
    gen_tree = proto_item_add_subtree(ti, ett_generic);
  }
	
  if ((name = match_strval(aiminfo->subtype, aim_fnac_family_generic)) != NULL) {
    if (ti)
      proto_item_append_text(ti, ", %s", name);

    if (check_col(pinfo->cinfo, COL_INFO))
      col_add_fstr(pinfo->cinfo, COL_INFO, name);
  }

  switch(aiminfo->subtype)
    {
	case FAMILY_GENERIC_ERROR:
	   return dissect_aim_snac_error(tvb, pinfo, 0, gen_tree);
	case FAMILY_GENERIC_CLIENTREADY:
	   ti = proto_tree_add_text(gen_tree, tvb, 0, -1, "Supported services");
	   entry = proto_item_add_subtree(ti, ett_generic_clientready);
	   while(tvb_reported_length_remaining(tvb, offset) > 0) {
			guint16 famnum = tvb_get_ntohs(tvb, offset);
			const char *famname = aim_get_familyname(famnum);
			proto_tree *subentry;
			ti = proto_tree_add_text(entry, tvb, offset, 2, "%s (0x%x)", famname?famname:"Unknown Family", famnum);
			offset+=2;
			
			subentry = proto_item_add_subtree(ti, ett_generic_clientready_item);

			proto_tree_add_text(subentry, tvb, offset, 2, "Version: %u", tvb_get_ntohs(tvb, offset) ); offset += 2;
			proto_tree_add_text(subentry, tvb, offset, 4, "DLL Version: %u", tvb_get_ntoh24(tvb, offset) ); offset += 4;
	  }
	  return offset;
	case FAMILY_GENERIC_SERVERREADY:
	   ti = proto_tree_add_text(gen_tree, tvb, offset, tvb_length_remaining(tvb, offset), "Supported services");
	   entry = proto_item_add_subtree(ti, ett_generic_clientready);
	   while(tvb_length_remaining(tvb, offset) > 0) {
			guint16 famnum = tvb_get_ntohs(tvb, offset);
			const char *famname = aim_get_familyname(famnum);
			proto_tree_add_text(entry, tvb, offset, 2, "%s (0x%x)", famname?famname:"Unknown Family", famnum);
			offset+=2;
	  }
	  return offset;
	case FAMILY_GENERIC_SERVICEREQ:
	  name = aim_get_familyname( tvb_get_ntohs(tvb, offset) );
	  proto_tree_add_uint_format(gen_tree, hf_generic_servicereq_service, tvb, offset, 2, tvb_get_ntohs(tvb, offset), "%s (0x%04x)", name?name:"Unknown", tvb_get_ntohs(tvb, offset) );
	  offset+=2;
	  return offset;
	case FAMILY_GENERIC_REDIRECT:
	  while(tvb_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_tlv(tvb, pinfo, offset, gen_tree);
	  }
	  return offset;
	case FAMILY_GENERIC_CAPABILITIES:
	   ti = proto_tree_add_text(gen_tree, tvb, offset, tvb_length_remaining(tvb, offset), "Requested services");
	   entry = proto_item_add_subtree(ti, ett_generic_clientready);
	   while(tvb_length_remaining(tvb, offset) > 0) {
			guint16 famnum = tvb_get_ntohs(tvb, offset);
			const char *famname = aim_get_familyname(famnum);
			ti = proto_tree_add_text(entry, tvb, offset, 4, "%s (0x%x), Version: %d", famname?famname:"Unknown Family", famnum, tvb_get_ntohs(tvb, offset+2));
			offset += 4;
	  }
	  return offset;
	case FAMILY_GENERIC_CAPACK:
	   ti = proto_tree_add_text(gen_tree, tvb, offset, tvb_length_remaining(tvb, offset), "Accepted requested services");
	   entry = proto_item_add_subtree(ti, ett_generic_clientready);
	   while(tvb_length_remaining(tvb, offset) > 0) {
			guint16 famnum = tvb_get_ntohs(tvb, offset);
			const char *famname = aim_get_familyname(famnum);
			ti = proto_tree_add_text(entry, tvb, offset, 4, "%s (0x%x), Version: %d", famname?famname:"Unknown Family", famnum, tvb_get_ntohs(tvb, offset+2));
			offset += 4;
	  }
	   return offset;


    case FAMILY_GENERIC_MOTD: 
	  proto_tree_add_item(gen_tree, hf_generic_motd_motdtype, tvb, offset, 
			  2, tvb_get_ntohs(tvb, offset));
	  offset+=2;
	  while(tvb_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_tlv(tvb, pinfo, offset, gen_tree);
	  }
	  return offset;

	case FAMILY_GENERIC_RATEINFO:
	  return dissect_generic_rateinfo(tvb, pinfo, gen_tree);
	case FAMILY_GENERIC_RATEINFOACK:
	  while(tvb_length_remaining(tvb, offset) > 0) {
		  proto_tree_add_uint(gen_tree, hf_generic_rateinfoack_group, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
		  offset+=2;
	  }
	  return offset;
	case FAMILY_GENERIC_UNKNOWNx09:
	  /* Unknown: FIXME: */
	  return offset;
	case FAMILY_GENERIC_RATECHANGE:
	  proto_tree_add_uint(gen_tree, hf_generic_ratechange_msg, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
	  offset+=2;
	  offset = dissect_rate_class(tvb, pinfo, offset, gen_tree);
	  break;
	  

	case FAMILY_GENERIC_CLIENTPAUSEACK:
	  while(tvb_length_remaining(tvb, offset) > 0) {
			guint16 famnum = tvb_get_ntohs(tvb, offset);
			const char *famname = aim_get_familyname(famnum);
			proto_tree_add_text(gen_tree, tvb, offset, 4, "Family: %s (0x%x)", famname?famname:"Unknown Family", famnum);
			offset += 2;
	  }
	  return offset;
	case FAMILY_GENERIC_SERVERRESUME:
	case FAMILY_GENERIC_REQSELFINFO:
	case FAMILY_GENERIC_NOP:
	case FAMILY_GENERIC_SERVERPAUSE:
	case FAMILY_GENERIC_RATEINFOREQ:
	  /* No data */
	  return offset;
	case FAMILY_GENERIC_MIGRATIONREQ:
	  n = tvb_get_ntohs(tvb, offset);offset+=2;
	  proto_tree_add_uint(gen_tree, hf_generic_migration_numfams, tvb, offset, 2, n);
	  ti = proto_tree_add_text(gen_tree, tvb, offset, 2 * n, "Families to migrate");
	  entry = proto_item_add_subtree(ti, ett_generic_migratefamilies);
	  for(i = 0; i < n; i++) {
			guint16 famnum = tvb_get_ntohs(tvb, offset);
			const char *famname = aim_get_familyname(famnum);
			proto_tree_add_text(gen_tree, tvb, offset, 4, "Family: %s (0x%x)", famname?famname:"Unknown Family", famnum);
			offset += 2;
	  }

	  while(tvb_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_tlv(tvb, pinfo, offset, gen_tree);
	  }

	  return offset;
	case FAMILY_GENERIC_SETPRIVFLAGS:
	  {
		  guint32 flags = tvb_get_ntoh24(tvb, offset); 
		  ti = proto_tree_add_uint(gen_tree, hf_generic_priv_flags, tvb, offset, 4, flags);
		  entry = proto_item_add_subtree(ti, ett_generic_priv_flags);
		  proto_tree_add_boolean(entry, hf_generic_allow_idle_see, tvb, offset, 4, flags);
		  proto_tree_add_boolean(entry, hf_generic_allow_member_see, tvb, offset, 4, flags);
		  offset+=4;
	  }
	  return offset;
	case FAMILY_GENERIC_SELFINFO:
	case FAMILY_GENERIC_EVIL:
	case FAMILY_GENERIC_SETIDLE:
	case FAMILY_GENERIC_SETSTATUS:
	case FAMILY_GENERIC_WELLKNOWNURL:
	case FAMILY_GENERIC_CLIENTVERREQ:
	case FAMILY_GENERIC_CLIENTVERREPL:
	  /* FIXME */
	  return 0;
	default: return 0;
    }
  return 0;
}

/* Register the protocol with Ethereal */
void
proto_register_aim_generic(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
	{ &hf_generic_servicereq_service, 
	  { "Requested Service", "generic.servicereq.service", FT_UINT16,
		  BASE_HEX, NULL, 0x0, "", HFILL },
	},
	{ &hf_generic_motd_motdtype, 
	  { "MOTD Type", "generic.motd.motdtype", FT_UINT16,
		  BASE_HEX, VALS(aim_snac_generic_motd_motdtypes), 0x0, "", HFILL },
	},
	{ &hf_generic_rateinfo_numclasses,
	  { "Number of Rateinfo Classes", "aim.rateinfo.numclasses", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
	},
	{ &hf_generic_rateinfo_windowsize,
	  { "Window Size", "aim.rateinfo.class.window_size", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
	},
	{ &hf_generic_rateinfo_clearlevel,
	  { "Clear Level", "aim.rateinfo.class.clearlevel", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
	},
	{ &hf_generic_rateinfo_alertlevel,
	  { "Alert Level", "aim.rateinfo.class.alertlevel", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
	},
	{ &hf_generic_rateinfo_limitlevel,
	  { "Limit Level", "aim.rateinfo.class.limitlevel", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
	},
	{ &hf_generic_rateinfo_disconnectlevel,
	  { "Disconnect Level", "aim.rateinfo.class.disconnectlevel", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
	},
	{ &hf_generic_rateinfo_currentlevel,
	  { "Current Level", "aim.rateinfo.class.currentlevel", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
	},
	{ &hf_generic_rateinfo_maxlevel,
      { "Max Level", "aim.rateinfo.class.maxlevel", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
	},
	{ &hf_generic_rateinfo_lasttime,
	  { "Last Time", "aim.rateinfo.class.lasttime", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
	},
	{ &hf_generic_rateinfo_curstate, 
	  { "Current State", "aim.rateinfo.class.curstate", FT_UINT8, BASE_HEX, VALS(rateinfo_states), 0x0, "", HFILL },
	},
	{ &hf_generic_rateinfo_classid,
	  { "Class ID", "aim.rateinfo.class.id", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
	},
	{ &hf_generic_rateinfo_numpairs,
	  { "Number of Family/Subtype pairs", "aim.rateinfo.class.numpairs", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
	},
	{ &hf_generic_rateinfoack_group,
	  { "Acknowledged Rate Class", "aim.rateinfoack.class", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
	},
	{ &hf_generic_ratechange_msg,
	  { "Rate Change Message", "aim.ratechange.msg", FT_UINT16, BASE_HEX, VALS(ratechange_msgs), 0x0, "", HFILL },
	},
	{ &hf_generic_migration_numfams,
	  { "Number of families to migrate", "aim.migrate.numfams", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
	},
	{ &hf_generic_priv_flags,
	  { "Privilege flags", "aim.privilege_flags", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
	},
	{ &hf_generic_allow_idle_see,
	  { "Allow other users to see idle time", "aim.privilege_flags.allow_idle", FT_BOOLEAN, 32, TFS(&flags_set_truth), 0x0001, "", HFILL },
	},
	{ &hf_generic_allow_member_see,
	  { "Allow other users to see how long account has been a member", "aim.privilege_flags.allow_member", FT_BOOLEAN, 32, TFS(&flags_set_truth), 0x0002, "", HFILL },
	},
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
	&ett_generic,
	&ett_generic_migratefamilies,
	&ett_generic_rateinfo_class,
	&ett_generic_rateinfo_group,
	&ett_generic_rateinfo_groups,
	&ett_generic_rateinfo_classes,
	&ett_generic_clientready,
	&ett_generic_clientready_item,
	&ett_generic_serverready,
	&ett_generic_priv_flags,
  };

/* Register the protocol name and description */
  proto_aim_generic = proto_register_protocol("AIM Generic Service", "AIM Generic", "aim_generic");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_aim_generic, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_generic(void)
{
  dissector_handle_t aim_handle;
  aim_handle = new_create_dissector_handle(dissect_aim_snac_generic, proto_aim_generic);
  dissector_add("aim.family", FAMILY_GENERIC, aim_handle);
  aim_init_family(FAMILY_GENERIC, "Generic", aim_fnac_family_generic);
}
