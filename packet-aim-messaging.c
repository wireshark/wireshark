/* packet-aim-messaging.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Messaging
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
 *
 * $Id: packet-aim-messaging.c,v 1.2 2004/03/23 18:36:05 guy Exp $
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

#define FAMILY_MESSAGING  0x0004

/* Family Messaging Service */
#define FAMILY_MESSAGING_ERROR          0x0001
#define FAMILY_MESSAGING_SETICBMPARAM   0x0002
#define FAMILY_MESSAGING_RESETICBMPARAM 0x0003
#define FAMILY_MESSAGING_REQPARAMINFO   0x0004
#define FAMILY_MESSAGING_PARAMINFO      0x0005
#define FAMILY_MESSAGING_OUTGOING       0x0006
#define FAMILY_MESSAGING_INCOMING       0x0007
#define FAMILY_MESSAGING_EVIL           0x0009
#define FAMILY_MESSAGING_MISSEDCALL     0x000a
#define FAMILY_MESSAGING_CLIENTAUTORESP 0x000b
#define FAMILY_MESSAGING_ACK            0x000c
#define FAMILY_MESSAGING_MINITYPING     0x0014
#define FAMILY_MESSAGING_DEFAULT        0xffff

static const value_string aim_fnac_family_messaging[] = {
  { FAMILY_MESSAGING_ERROR, "Error" },
  { FAMILY_MESSAGING_SETICBMPARAM, "Set ICBM Parameter" },
  { FAMILY_MESSAGING_RESETICBMPARAM, "Reset ICBM Parameter" },
  { FAMILY_MESSAGING_REQPARAMINFO, "Request Parameter Info" },
  { FAMILY_MESSAGING_PARAMINFO, "Parameter Info" },
  { FAMILY_MESSAGING_INCOMING, "Incoming" },
  { FAMILY_MESSAGING_EVIL, "Evil" },
  { FAMILY_MESSAGING_MISSEDCALL, "Missed Call" },
  { FAMILY_MESSAGING_CLIENTAUTORESP, "Client Auto Response" },
  { FAMILY_MESSAGING_ACK, "Acknowledge" },
  { FAMILY_MESSAGING_MINITYPING, "Mini Typing Notifications (MTN)" },
  { FAMILY_MESSAGING_DEFAULT, "Messaging Default" },
  { 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_aim_messaging = -1;

/* Initialize the subtree pointers */
static gint ett_aim_messaging = -1;

static int dissect_aim_messaging(tvbuff_t *tvb, packet_info *pinfo, 
				       proto_tree *tree)
{
  guint8 buddyname_length = 0;
  char buddyname[MAX_BUDDYNAME_LENGTH + 1];
  guchar msg[1000];
  int offset = 0;
  struct aiminfo *aiminfo = pinfo->private_data;

  switch(aiminfo->subtype)
    {    
	case FAMILY_MESSAGING_ERROR:
      return dissect_aim_snac_error(tvb, pinfo, offset, tree);
    case FAMILY_MESSAGING_OUTGOING:

      /* Unknown */
      offset += 10;

      buddyname_length = aim_get_buddyname( buddyname, tvb, offset, offset + 1 );

      /* djh - My test suggest that this is broken.  Need to give this a
	 closer look @@@@@@@@@ */
      aim_get_message( msg, tvb, 36 + buddyname_length, tvb_length(tvb) - 36
		   - buddyname_length );
      
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_append_fstr(pinfo->cinfo, COL_INFO, "to: %s", buddyname);
	col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
      }
      
      if(tree) {
	proto_tree_add_text(tree, tvb, 27, buddyname_length, 
			    "Screen Name: %s", buddyname);
      }
      
	  return offset;
      
    case FAMILY_MESSAGING_INCOMING:

      /* Unknown */
      offset += 10;

      buddyname_length = aim_get_buddyname( buddyname, tvb, offset, offset + 1 );

      /* djh - My test suggest that this is broken.  Need to give this a
	 closer look @@@@@@@@@ */      
      aim_get_message( msg, tvb, 36 + buddyname_length,  tvb_length(tvb) - 36
		   - buddyname_length);
      
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_append_fstr(pinfo->cinfo, COL_INFO, " from: %s", buddyname);
	
	col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
      }
      
      if(tree) {
	proto_tree_add_text(tree, tvb, 27, buddyname_length, 
			    "Screen Name: %s", buddyname);
      }
      return offset;
	case FAMILY_MESSAGING_SETICBMPARAM:
	case FAMILY_MESSAGING_RESETICBMPARAM:
	case FAMILY_MESSAGING_REQPARAMINFO:
	case FAMILY_MESSAGING_PARAMINFO:
	case FAMILY_MESSAGING_EVIL:
	case FAMILY_MESSAGING_MISSEDCALL:
	case FAMILY_MESSAGING_CLIENTAUTORESP:
	case FAMILY_MESSAGING_ACK:
	case FAMILY_MESSAGING_MINITYPING:
	case FAMILY_MESSAGING_DEFAULT:
		/*FIXME*/

	default:
	  return 0;
    }
}

/* Register the protocol with Ethereal */
void
proto_register_aim_messaging(void)
{

/* Setup list of header fields */
/*FIXME
  static hf_register_info hf[] = {
  };*/

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_messaging,
  };

/* Register the protocol name and description */
  proto_aim_messaging = proto_register_protocol("AIM Messaging", "AIM Messaging", "aim_messaging");

/* Required function calls to register the header fields and subtrees used */
/*FIXME
  proto_register_field_array(proto_aim_messaging, hf, array_length(hf));*/
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_messaging(void)
{
  dissector_handle_t aim_handle;

  aim_handle = new_create_dissector_handle(dissect_aim_messaging, proto_aim_messaging);
  dissector_add("aim.family", FAMILY_MESSAGING, aim_handle);
  aim_init_family(FAMILY_MESSAGING, "Messaging", aim_fnac_family_messaging);
}
