/* packet-fw1.c
 * Routines for Ethernet header disassembly of FW1 "monitor" files
 * Copyright 2002, Alfred Koebler <ak@icon-sult.de>
 *
 * $Id: packet-fw1.c,v 1.3 2002/08/08 21:42:05 jmayer Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Alfred Koebler <ak@icon-sult.de>
 * Copyright 2002 I.Consult
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
#include "prefs.h"
#include "etypes.h"

/* Place FW1 summary in proto tree */
static gboolean fw1_summary_in_tree = TRUE;

/* Initialize the protocol and registered fields */
static int proto_fw1 = -1;
static int hf_fw1_direction = -1;
static int hf_fw1_interface = -1;
static int hf_fw1_type = -1;
static int hf_fw1_trailer = -1;

/* Initialize the subtree pointers */
static gint ett_fw1 = -1;

#define ETH_HEADER_SIZE	14

static dissector_handle_t eth_handle;

static void
dissect_fw1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item    *ti; 
  proto_tree    *volatile fh_tree = NULL;
  char		direction[3];
  char		interface[20];
  guint16	etype;
  char		header[1000];
  char		*p_header;
  int		i;
  int		found;

  #define	MAX_INTERFACES	20
  static char	*p_interfaces[MAX_INTERFACES];
  static int	interface_anzahl=0;

  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FW1");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  etype = tvb_get_ntohs(tvb, 12);

  if (tree) {
    sprintf(header, "FW1 Monitor");

    /* fetch info to local variable */
    direction[0] = tvb_get_guint8(tvb, 0);
    direction[1] = 0;
    tvb_get_nstringz0(tvb, 2, 10, interface);

    if (fw1_summary_in_tree) {
      /* Known interface name - if not, remember it */
      found=1;
      for (i=0; i<interface_anzahl && i<MAX_INTERFACES; i++) {
        if ( strcmp(p_interfaces[i], interface) == 0 ) {
          found=0;
        }
      }
      if (found == 1 ) {
        p_interfaces[interface_anzahl] = strdup(interface);
        interface_anzahl++;
      }
      /* display all interfaces always in the same order */
      for (i=0; i<interface_anzahl; i++) {
        found=1;
        if ( strcmp(p_interfaces[i], interface) == 0 ) {
          found=0;
        }
        p_header = header + strlen(header);
        sprintf(p_header, "  %c %s %c",
  	  found==0 ? (direction[0]=='i' ? 'i' : (direction[0]=='O' ? 'O' : ' ')) : ' ',
	  p_interfaces[i],
	  found==0 ? (direction[0]=='I' ? 'I' : (direction[0]=='o' ? 'o' : ' ')) : ' '
	  );
      }
    } else {
      /* without FW1 summary delete all remembered names of interfaces */
      for (i=0; i<interface_anzahl && i<MAX_INTERFACES; i++) {
        free(p_interfaces[i]);
      }
      interface_anzahl = 0;
    }

    ti = proto_tree_add_protocol_format(tree, proto_fw1, tvb, 0, ETH_HEADER_SIZE, header);
 
    /* create display subtree for the protocol */
    fh_tree = proto_item_add_subtree(ti, ett_fw1);

    proto_tree_add_item(fh_tree, hf_fw1_direction, tvb, 0, 1, FALSE);

    proto_tree_add_string_format(fh_tree, hf_fw1_interface,
	tvb, 2, 10,
	interface, "Interface: %s", interface);
  }
  ethertype(etype, tvb, ETH_HEADER_SIZE, pinfo, tree, fh_tree, hf_fw1_type,
          hf_fw1_trailer);
}
    
void
proto_register_fw1(void)
{
  static hf_register_info hf[] = {
	{ &hf_fw1_direction,
	{ "Direction",	"fw1.direction", FT_STRING, BASE_NONE, NULL, 0x0,
		"Direction", HFILL }},
	{ &hf_fw1_interface,
	{ "Interface",	"fw1.interface", FT_STRING, BASE_NONE, NULL, 0x0,
		"Interface", HFILL }},
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

  register_dissector("fw1", dissect_fw1, proto_fw1);
}

void
proto_reg_handoff_fw1(void)
{
  /*
   * Get handles for the Ethernet dissectors.
   */
  eth_handle = find_dissector("eth");
}
