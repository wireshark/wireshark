/* packet-q932-ros.c
 * Routines for Q.932 packet dissection
 * 2007  Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <wsutil/array.h>

#include "packet-ber.h"

#define PNAME  "Q.932 Operations Service Element"
#define PSNAME "Q932.ROS"
#define PFNAME "q932.ros"

void proto_register_q932_ros(void);
void proto_reg_handoff_q932_ros(void);

/* Initialize the protocol and registered fields */
static int proto_q932_ros;
#include "packet-q932-ros-hf.c"

/* Initialize the subtree pointers */
#include "packet-q932-ros-ett.c"

static expert_field ei_ros_undecoded;

/* Preferences */

/* Subdissectors */
static dissector_handle_t data_handle;

/* Global variables */
static rose_ctx_t *rose_ctx_tmp;

static uint32_t problem_val;
static char problem_str[64];
static tvbuff_t *arg_next_tvb, *res_next_tvb, *err_next_tvb;


#include "packet-q932-ros-fn.c"

/*--- dissect_q932_ros -----------------------------------------------------*/
static int dissect_q932_ros(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  /* Reject the packet if data is NULL */
  if (data == NULL)
    return 0;
  rose_ctx_tmp = get_rose_ctx(data);
  DISSECTOR_ASSERT(rose_ctx_tmp);
  return dissect_ROS_PDU(tvb, pinfo, tree, NULL);
}

/*--- proto_register_q932_ros -----------------------------------------------*/
void proto_register_q932_ros(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-q932-ros-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-q932-ros-ettarr.c"
  };

  static ei_register_info ei[] = {
     { &ei_ros_undecoded, { "q932.ros.undecoded", PI_UNDECODED, PI_WARN, "Undecoded", EXPFILL }},
  };

  expert_module_t* expert_q932_ros;

  /* Register protocol and dissector */
  proto_q932_ros = proto_register_protocol(PNAME, PSNAME, PFNAME);
  proto_set_cant_toggle(proto_q932_ros);

  /* Register fields and subtrees */
  proto_register_field_array(proto_q932_ros, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_q932_ros = expert_register_protocol(proto_q932_ros);
  expert_register_field_array(expert_q932_ros, ei, array_length(ei));

  register_dissector(PFNAME, dissect_q932_ros, proto_q932_ros);
}

/*--- proto_reg_handoff_q932_ros --------------------------------------------*/
void proto_reg_handoff_q932_ros(void) {
  data_handle = find_dissector("data");
}

/*---------------------------------------------------------------------------*/
