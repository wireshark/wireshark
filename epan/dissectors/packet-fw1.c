/* packet-fw1.c
 * Routines for Ethernet header disassembly of FW1 "monitor" files
 * Copyright 2002,2003, Alfred Koebler <ako@icon.de>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Alfred Koebler <ako@icon.de>
 * Copyright 2002,2003 Alfred Koebler
 *
 * To use this dissector use the command line option
 * -o eth.interpret_as_fw1_monitor:TRUE
 *
 * At the moment the way with the option is the best one.
 * A automatic way is not possible, because the file format isn't different
 * to the snoop file.
 *
 * With "fw monitor" it is possible to collect packets on several places.
 * The additional information:
 * - is it a incoming or outgoing packet
 * - is it before or after the firewall
 *   i  incoming before the firewall
 *   I  incoming after the firewall
 *   o  outcoming before the firewall
 *   O  outcoming after the firewall
 * - the name of the interface
 *
 * What's the problem ?
 * Think about one packet traveling across the firewall.
 * With ethereal you will see 4 lines in the Top Pane.
 * To analyze a problem it is helpful to see the additional information
 * in the protocol tree of the Middle Pane.
 *
 * The presentation of the summary line is designed in the following way:
 * Every time the next selected packet in the Top Pane includes a
 * "new" interface name the name is added to the list in the summary line.
 * The interface names are listed one after the other.
 * The position of the interface names didn't change.
 *
 * And who are the 4 places represented ?
 * The interface name represents the firewall module of the interface.
 * On the left side of the interface name is the interface module.
 * On the right side of the interface name is the "IP" module.
 *
 * Example for a ping from the firewall to another host:
 * For the four lines in the Top Pane you will see the according lines
 * in the Middle Pane:
 *   El90x1 o
 * O El90x1
 * i El90x1
 *   El90x1 I
 *
 * Example for a packet traversing through the Firewall, first through
 * the inner side firewall module then through the outer side firewall module:
 * i  El90x1        El90x2
 *    El90x1 I      El90x2
 *    El90x1      o E190x2
 *    El90x1        E190x2 O
 *
 * 9.12.2002
 * Add new column with summary of FW-1 interface/direction
 *
 * 11.8.2003
 * Additional interpretation of field Chain Position.
 * Show the chain position in the interface list.
 * Support for new format of fw monitor file 
 * writen by option -u | -s for UUID/SUUID.
 * NOTICE: First paket will have UUID == 0 !
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

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/etypes.h>

/* Place FW1 summary in proto tree */
static gboolean fw1_summary_in_tree = TRUE;
static gboolean fw1_with_uuid = FALSE;
static gboolean fw1_iflist_with_chain = FALSE;

/* Initialize the protocol and registered fields */
static int proto_fw1 = -1;
static int hf_fw1_direction = -1;
static int hf_fw1_chain = -1;
static int hf_fw1_interface = -1;
static int hf_fw1_uuid = -1;
static int hf_fw1_type = -1;
static int hf_fw1_trailer = -1;

/* Initialize the subtree pointers */
static gint ett_fw1 = -1;

#define ETH_HEADER_SIZE	14

#define	MAX_INTERFACES	20
static char	*p_interfaces[MAX_INTERFACES];
static int	interface_anzahl=0;

static void
fw1_init(void)
{
  int		i;

  for (i=0; i<interface_anzahl; i++) {
    free(p_interfaces[i]);
  }
  interface_anzahl = 0;
}

static void
dissect_fw1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item    *ti;
  proto_tree    *volatile fh_tree = NULL;
  char		direction;
  char	chain;
  char		*interface_name;
  guint32	iface_len = 10;
  guint16	etype;
  char		*header; 
  char		*p_header;
  int		i;
  gboolean	found;
  static const char	fw1_header[] = "FW1 Monitor";

#define MAX_HEADER_LEN 1000
  header=ep_alloc(MAX_HEADER_LEN);
  g_snprintf(header, MAX_HEADER_LEN, "FW1 Monitor");

  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FW1");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);


  /* g_snprintf(header, sizeof(header), fw1_header); */

  /* fetch info to local variable */
  direction = tvb_get_guint8(tvb, 0);

  if (!fw1_iflist_with_chain)
  	chain = ' ';
  else
  	chain = tvb_get_guint8(tvb, 1);

  if (fw1_with_uuid)
  	iface_len = 6;
  
  interface_name=ep_alloc(iface_len+1);
  tvb_get_nstringz0(tvb, 2, iface_len, interface_name);

  /* Known interface name - if not, remember it */
  found=FALSE;
  for (i=0; i<interface_anzahl; i++) {
    if ( strcmp(p_interfaces[i], interface_name) == 0 ) {
      found=TRUE;
      break;
    }
  }
  if (!found && interface_anzahl < MAX_INTERFACES) {
    p_interfaces[interface_anzahl] = g_strdup(interface_name);
    interface_anzahl++;
  }

  /* display all interfaces always in the same order */
  for (i=0; i<interface_anzahl; i++) {
    p_header = header + strlen(header);
    if ( strcmp(p_interfaces[i], interface_name) == 0 ) {
       	g_snprintf(p_header, MAX_HEADER_LEN-(p_header-header), "  %c%c %s %c%c",
 			direction == 'i' ? 'i' : (direction == 'O' ? 'O' : ' '),
			(direction == 'i' || direction == 'O') ? chain : ' ',
			p_interfaces[i],
			direction == 'I' ? 'I' : (direction == 'o' ? 'o' : ' '),
			(direction == 'I' || direction == 'o') ? chain : ' '
		);
    } else {
    	g_snprintf(p_header, MAX_HEADER_LEN-(p_header-header), "    %s  ", p_interfaces[i]);
    }
  }

  if (check_col(pinfo->cinfo, COL_IF_DIR))
    col_add_str(pinfo->cinfo, COL_IF_DIR, header + sizeof(fw1_header) + 1);

  if (tree) {
    if (!fw1_summary_in_tree)
      /* Do not show the summary in Protocol Tree */
      ti = proto_tree_add_protocol_format(tree, proto_fw1, tvb, 0, ETH_HEADER_SIZE, fw1_header);
    else
      ti = proto_tree_add_protocol_format(tree, proto_fw1, tvb, 0, ETH_HEADER_SIZE, header);

    /* create display subtree for the protocol */
    fh_tree = proto_item_add_subtree(ti, ett_fw1);

    proto_tree_add_item(fh_tree, hf_fw1_direction, tvb, 0, 1, FALSE);

    if (fw1_iflist_with_chain)
      proto_tree_add_item(fh_tree, hf_fw1_chain, tvb, 1, 1, FALSE);

    proto_tree_add_string_format(fh_tree, hf_fw1_interface, tvb, 2, iface_len, "Interface: %s", interface_name);
  
    if (fw1_with_uuid) 
      proto_tree_add_item(fh_tree, hf_fw1_uuid, tvb, 8, 4, FALSE);
  }

  etype = tvb_get_ntohs(tvb, 12);
  ethertype(etype, tvb, ETH_HEADER_SIZE, pinfo, tree, fh_tree, hf_fw1_type, hf_fw1_trailer, 0);
}

void
proto_register_fw1(void)
{
  static hf_register_info hf[] = {
	{ &hf_fw1_direction,
	{ "Direction",	"fw1.direction", FT_STRING, BASE_NONE, NULL, 0x0,
		"Direction", HFILL }},
	{ &hf_fw1_chain,
	{ "Chain Position",	"fw1.chain", FT_STRING, BASE_NONE, NULL, 0x0,
		"Chain Position", HFILL }},
	{ &hf_fw1_interface,
	{ "Interface",	"fw1.interface", FT_STRING, BASE_NONE, NULL, 0x0,
		"Interface", HFILL }},
	{ &hf_fw1_uuid,
	{ "UUID",	"fw1.uuid", FT_UINT32, BASE_DEC, NULL, 0x0,
		"UUID", HFILL }},
		/* registered here but handled in ethertype.c */
	{ &hf_fw1_type,
	{ "Type",		"fw1.type", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
		"", HFILL }},
  };
  /* Setup protocol subtree array */
  static gint *ett[] = {
	&ett_fw1,
  };
  module_t *fw1_module;

  /* Register the protocol name and description */
  proto_fw1 = proto_register_protocol("Checkpoint FW-1", "FW-1", "fw1");
  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_fw1, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register configuration preferences */
  fw1_module = prefs_register_protocol(proto_fw1, NULL);
  prefs_register_bool_preference(fw1_module, "summary_in_tree",
            "Show FireWall-1 summary in protocol tree",
	    "Whether the FireWall-1 summary line should be shown in the protocol tree",
            &fw1_summary_in_tree);
  prefs_register_bool_preference(fw1_module, "with_uuid",
            "Monitor file includes UUID",
	    "Whether the Firewall-1 monitor file includes UUID information",
            &fw1_with_uuid);
  prefs_register_bool_preference(fw1_module, "iflist_with_chain",
            "Interface list includes chain position",
	    "Whether the interface list includes the chain position",
            &fw1_iflist_with_chain);

  register_dissector("fw1", dissect_fw1, proto_fw1);

  register_init_routine(fw1_init);
}
