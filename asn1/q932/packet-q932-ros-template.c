/* packet-q932-ros.c
 * Routines for Q.932 packet dissection
 * 2007  Tomas Kukosa
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/emem.h>

#include "packet-ber.h"
#include "packet-q932-ros.h"

#define PNAME  "Q.932 Operations Service Element"
#define PSNAME "Q932.ROS"
#define PFNAME "q932.ros"

/* Initialize the protocol and registered fields */
int proto_rose = -1;
#include "packet-q932-ros-hf.c" 

/* Initialize the subtree pointers */
#include "packet-q932-ros-ett.c" 

/* Preferences */

/* Subdissectors */
static dissector_handle_t data_handle = NULL; 

/* Gloabl variables */
static rose_context *rose_ctx;

static gint32 code_choice;
static guint32 code_local;
static const gchar *code_global;
static guint32 problem_val;
static gchar problem_str[64];
static tvbuff_t *arg_next_tvb, *res_next_tvb, *err_next_tvb;


#include "packet-q932-ros-fn.c" 

/*--- dissect_rose_apdu -----------------------------------------------------*/
int dissect_rose_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, rose_context *rctx) {
  if (rctx)
    rose_ctx = rctx;
  return dissect_RoseAPDU_PDU(tvb, pinfo, tree);
}

/*--- proto_register_rose ---------------------------------------------------*/
void proto_register_rose(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-q932-ros-hfarr.c" 
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-q932-ros-ettarr.c" 
  };

  /* Register protocol and dissector */
  proto_rose = proto_register_protocol(PNAME, PSNAME, PFNAME);
  proto_set_cant_toggle(proto_rose);

  /* Register fields and subtrees */
  proto_register_field_array(proto_rose, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

/*--- proto_reg_handoff_rose ------------------------------------------------*/
void proto_reg_handoff_rose(void) {
  data_handle = find_dissector("data");
}

/*---------------------------------------------------------------------------*/
