/* packet-h450-ros.c
 * Routines for H.450 packet dissection
 * 2007  Tomas Kukosa
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

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/expert.h>

#include "packet-per.h"
#include "packet-h450-ros.h"

#define PNAME  "H.450 Remote Operations Apdus"
#define PSNAME "H450.ROS"
#define PFNAME "h450.ros"

void proto_register_h450_ros(void);
void proto_reg_handoff_h450_ros(void);

/* Initialize the protocol and registered fields */
static int proto_h450_ros = -1;
#include "packet-h450-ros-hf.c"

/* Initialize the subtree pointers */
#include "packet-h450-ros-ett.c"

static expert_field ei_ros_undecoded = EI_INIT;

/* Preferences */

/* Subdissectors */
static dissector_handle_t data_handle = NULL;

/* Global variables */
static gint32 problem_val;
static gchar problem_str[64];
static tvbuff_t *arg_next_tvb, *res_next_tvb, *err_next_tvb;

static int
argument_cb(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_) {
  arg_next_tvb = tvb;
  return tvb_captured_length(tvb);
}

static int
result_cb(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_) {
  res_next_tvb = tvb;
  return tvb_captured_length(tvb);
}

static int
error_cb(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_) {
  err_next_tvb = tvb;
  return tvb_captured_length(tvb);
}

#include "packet-h450-ros-fn.c"

/*--- proto_register_h450_ros -----------------------------------------------*/
void proto_register_h450_ros(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-h450-ros-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-h450-ros-ettarr.c"
  };

  static ei_register_info ei[] = {
     { &ei_ros_undecoded, { "h450.ros.undecoded", PI_UNDECODED, PI_WARN, "Undecoded", EXPFILL }},
  };

  expert_module_t* expert_h450_ros;

  /* Register protocol and dissector */
  proto_h450_ros = proto_register_protocol(PNAME, PSNAME, PFNAME);
  proto_set_cant_toggle(proto_h450_ros);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h450_ros, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_h450_ros = expert_register_protocol(proto_h450_ros);
  expert_register_field_array(expert_h450_ros, ei, array_length(ei));
}

/*--- proto_reg_handoff_h450_ros --------------------------------------------*/
void proto_reg_handoff_h450_ros(void) {
  data_handle = find_dissector("data");
}

/*---------------------------------------------------------------------------*/
