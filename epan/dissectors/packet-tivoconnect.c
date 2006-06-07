/* packet-tivoconnect.c
 * Routines for TiVoConnect Discovery Protocol dissection
 * Copyright 2006, Kees Cook <kees@outflux.net>
 * IANA UDP/TCP port: 2190 (tivoconnect)
 * Protocol Spec: http://tivo.com/developer/i/TiVoConnectDiscovery.pdf
 *
 * IANA's full name is "TiVoConnect Beacon", where as TiVo's own
 * documentation calls this protocol "TiVoConnect Discovery Protocol".
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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

/*
 * TODO
 * - split services into a subtree
 * - split platform into a subtree
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/ipproto.h>

/* Forward declaration we need below */
void proto_reg_handoff_tivoconnect(void);

/* Initialize the protocol and registered fields */
static int proto_tivoconnect = -1;
static int hf_tivoconnect_flavor = -1;
static int hf_tivoconnect_method = -1;
static int hf_tivoconnect_platform = -1;
static int hf_tivoconnect_machine = -1;
static int hf_tivoconnect_identity = -1;
static int hf_tivoconnect_services = -1;
static int hf_tivoconnect_version = -1;

/* Initialize the subtree pointers */
static gint ett_tivoconnect = -1;

/* Code to actually dissect the packets */
static gboolean
dissect_tivoconnect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* parsing variables */
    gchar * string = NULL;
    gint length = -1;
    /* value strings */
    gchar * proto_name = NULL;
    gchar * packet_identity = NULL;
    gchar * packet_machine = NULL;

    /* validate that we have a tivoconnect packet */
    length = tvb->length;
    if ( length < 11 ||
         !(string = (gchar*)tvb_get_ephemeral_string(tvb, 0, length)) ||
         strncasecmp(string,"tivoconnect",11) != 0) {
        return FALSE;
    }

    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "TiVoConnect");
    
    /* make a distinction between UDP and TCP packets */
    proto_name = pinfo->ipproto == IP_PROTO_TCP ?
                    "Discovery Connection" :
                    "Discovery Beacon";

    if (check_col(pinfo->cinfo, COL_INFO)) 
        col_set_str(pinfo->cinfo, COL_INFO, proto_name);

    if (tree) {
        /* Set up structures needed to add the protocol subtree and manage it */
        proto_item *ti = NULL;
        proto_tree *tivoconnect_tree = NULL;

        /* parsing variables */
        guint offset = 0;
        gchar * field = NULL;

        /* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_tivoconnect, tvb, 0, -1, FALSE);

        tivoconnect_tree = proto_item_add_subtree(ti, ett_tivoconnect);

        /* process the packet */
        for ( field = strtok(string,"\n");
              field;
              offset+=length, field = strtok(NULL,"\n") ) {
            gchar * value = NULL;
            gint fieldlen;

            length = strlen(field) + 1;

            if ( !(value=strchr(field, '=')) ) {
                /* bad packet: missing the field separator */
                continue;
            }
            *value++='\0';
            fieldlen=strlen(field)+1;

            if ( strcasecmp(field,"tivoconnect") == 0 ) {
                proto_tree_add_item(tivoconnect_tree,
                    hf_tivoconnect_flavor, tvb, offset+fieldlen,
                    length-fieldlen-1, FALSE);
            }
            else if ( strcasecmp(field,"method") == 0 ) {
                proto_tree_add_item(tivoconnect_tree,
                    hf_tivoconnect_method, tvb, offset+fieldlen,
                    length-fieldlen-1, FALSE);
            }
            else if ( strcasecmp(field,"platform") == 0 ) {
                proto_tree_add_item(tivoconnect_tree,
                    hf_tivoconnect_platform, tvb, offset+fieldlen,
                    length-fieldlen-1, FALSE);
            }
            else if ( strcasecmp(field,"machine") == 0 ) {
                proto_tree_add_item(tivoconnect_tree,
                    hf_tivoconnect_machine, tvb, offset+fieldlen,
                    length-fieldlen-1, FALSE);
                packet_machine = value;
            }
            else if ( strcasecmp(field,"identity") == 0 ) {
                proto_tree_add_item(tivoconnect_tree,
                    hf_tivoconnect_identity, tvb, offset+fieldlen,
                    length-fieldlen-1, FALSE);
                packet_identity = value;
            }
            else if ( strcasecmp(field,"services") == 0 ) {
                proto_tree_add_item(tivoconnect_tree,
                    hf_tivoconnect_services, tvb, offset+fieldlen,
                    length-fieldlen-1, FALSE);
            }
            else if ( strcasecmp(field,"swversion") == 0 ) {
                proto_tree_add_item(tivoconnect_tree,
                    hf_tivoconnect_version, tvb, offset+fieldlen,
                    length-fieldlen-1, FALSE);
            }
            else {
                /* unknown field! */
            }
        }

        /* Adjust "Info" column and top of tree into more useful info */
        if (packet_machine) {
            proto_item_append_text(ti, ", %s", packet_machine);
            if (check_col(pinfo->cinfo, COL_INFO)) 
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                                            proto_name, packet_machine);
        }
        if (packet_identity) {
            proto_item_append_text(ti,
                        packet_machine ? " (%s)" : ", ID:%s",
                        packet_identity);
            if (packet_machine) {
                if (check_col(pinfo->cinfo, COL_INFO)) 
                    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s (%s)",
                                 proto_name, packet_machine, packet_identity);
            }
            else {
                if (check_col(pinfo->cinfo, COL_INFO)) 
                    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ID:%s",
                                 proto_name, packet_identity);
            }
        }

    }

    /* If this protocol has a sub-dissector call it here, see section 1.8 */

    return TRUE;
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_tivoconnect(void)
{                 
    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_tivoconnect_flavor,
            { "Flavor",           "tivoconnect.flavor",
            FT_STRINGZ, BASE_NONE, NULL, 0,          
            "Protocol Flavor supported by the originator", HFILL }},
        { &hf_tivoconnect_method,
            { "Method",           "tivoconnect.method",
            FT_STRINGZ, BASE_NONE, NULL, 0,          
            "Packet was delivered via UDP(broadcast) or TCP(connected)", HFILL }},
        { &hf_tivoconnect_platform,
            { "Platform",           "tivoconnect.platform",
            FT_STRINGZ, BASE_NONE, NULL, 0,          
            "System platform, either tcd(TiVo) or pc(Computer)", HFILL }},
        { &hf_tivoconnect_machine,
            { "Machine",           "tivoconnect.machine",
            FT_STRINGZ, BASE_NONE, NULL, 0,          
            "Human-readable system name", HFILL }},
        { &hf_tivoconnect_identity,
            { "Identity",           "tivoconnect.identity",
            FT_STRINGZ, BASE_NONE, NULL, 0,          
            "Unique serial number for the system", HFILL }},
        { &hf_tivoconnect_services,
            { "Services",           "tivoconnect.services",
            FT_STRINGZ, BASE_NONE, NULL, 0,          
            "List of available services on the system", HFILL }},
        { &hf_tivoconnect_version,
            { "Version",           "tivoconnect.version",
            FT_STRINGZ, BASE_NONE, NULL, 0,          
            "System software version", HFILL }},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_tivoconnect,
    };

    /* Register the protocol name and description */
    proto_tivoconnect = proto_register_protocol("TiVoConnect Discovery Protocol",
        "TiVoConnect", "tivoconnect");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_tivoconnect, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_tivoconnect(void)
{
        static gboolean inited = FALSE;
        
        if( !inited ) {

            dissector_handle_t tivoconnect_handle;

            tivoconnect_handle = create_dissector_handle(dissect_tivoconnect,
                                                         proto_tivoconnect);
            dissector_add("udp.port", 2190, tivoconnect_handle);
            dissector_add("tcp.port", 2190, tivoconnect_handle);
        
            inited = TRUE;
        }
}

