/* packet-p7.c
 * Routines for X.413 (P7) packet dissection
 * Graeme Lunt 2007
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"
#include "packet-rtse.h"

#include "packet-p1.h"
#include <epan/strutil.h>

#define PNAME  "X.413 Message Store Service"
#define PSNAME "P7"
#define PFNAME "p7"

static guint global_p7_tcp_port = 102;
static dissector_handle_t tpkt_handle;
static const char *object_identifier_id = NULL; /* attribute identifier */
static int seqno = 0;

static void prefs_register_p7(void); /* forward declaration for use in preferences registration */


/* Initialize the protocol and registered fields */
static int proto_p7 = -1;

#include "packet-p7-val.h"

#include "packet-p7-hf.c"

/* Initialize the subtree pointers */
static gint ett_p7 = -1;
#include "packet-p7-ett.c"

#include "packet-p7-table.c"   /* operation and error codes */

#include "packet-p7-fn.c"

#include "packet-p7-table11.c" /* operation argument/result dissectors */
#include "packet-p7-table21.c" /* error dissector */

static const ros_info_t p7_ros_info = {
  "P7",
  &proto_p7,
  &ett_p7,
  p7_opr_code_string_vals,
  p7_opr_tab,
  p7_err_code_string_vals,
  p7_err_tab
};


/*--- proto_register_p7 -------------------------------------------*/
void proto_register_p7(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-p7-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_p7,
#include "packet-p7-ettarr.c"
  };
  module_t *p7_module;

  /* Register protocol */
  proto_p7 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_p7, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for P7, particularly our port */

  p7_module = prefs_register_protocol_subtree("OSI/X.400", proto_p7, prefs_register_p7);

  prefs_register_uint_preference(p7_module, "tcp.port", "P7 TCP Port",
				 "Set the port for P7 operations (if other"
				 " than the default of 102)",
				 10, &global_p7_tcp_port);

}


/*--- proto_reg_handoff_p7 --- */
void proto_reg_handoff_p7(void) {

  #include "packet-p7-dis-tab.c"

  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-ms-access","2.6.0.1.11");
  oid_add_from_string("id-ac-ms-reliable-access","2.6.0.1.12");

  /* ABSTRACT SYNTAXES */

  /* Register P7 with ROS (with no use of RTSE) */
  register_ros_protocol_info("2.6.0.2.9", &p7_ros_info, 0, "id-as-ms", FALSE);
  register_ros_protocol_info("2.6.0.2.5", &p7_ros_info, 0, "id-as-mrse", FALSE);
  register_ros_protocol_info("2.6.0.2.1", &p7_ros_info, 0, "id-as-msse", FALSE);

  /* remember the tpkt handler for change in preferences */
  tpkt_handle = find_dissector("tpkt");
}


static void
prefs_register_p7(void)
{
  static guint tcp_port = 0;

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_delete_uint("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_p7_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add_uint("tcp.port", global_p7_tcp_port, tpkt_handle);

}
