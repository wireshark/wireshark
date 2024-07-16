/* packet-t125.c
 * Routines for t125 packet dissection
 * Copyright 2007, Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>

#include <epan/asn1.h>
#include "packet-ber.h"
#include "packet-per.h"

#include "packet-t124.h"

#define PNAME  "MULTIPOINT-COMMUNICATION-SERVICE T.125"
#define PSNAME "T.125"
#define PFNAME "t125"


#define HF_T125_ERECT_DOMAIN_REQUEST 1
#define HF_T125_DISCONNECT_PROVIDER_ULTIMATUM 8
#define HF_T125_ATTACH_USER_REQUEST 10
#define HF_T125_ATTACH_USER_CONFIRM 11
#define HF_T125_CHANNEL_JOIN_REQUEST 14
#define HF_T125_CHANNEL_JOIN_CONFIRM 15
#define HF_T125_SEND_DATA_REQUEST 25
#define HF_T125_SEND_DATA_INDICATION 26

void proto_register_t125(void);
void proto_reg_handoff_t125(void);

/* Initialize the protocol and registered fields */
static int proto_t125;
static proto_tree *top_tree;
#include "packet-t125-hf.c"

/* Initialize the subtree pointers */
static int ett_t125;

#include "packet-t125-ett.c"

static heur_dissector_list_t t125_heur_subdissector_list;

#include "packet-t125-fn.c"

static int
dissect_t125(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int8_t ber_class;
  bool pc;
  int32_t tag;

  top_tree = parent_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.125");
  col_clear(pinfo->cinfo, COL_INFO);

  item = proto_tree_add_item(parent_tree, proto_t125, tvb, 0, tvb_captured_length(tvb), ENC_NA);
  tree = proto_item_add_subtree(item, ett_t125);

  get_ber_identifier(tvb, 0, &ber_class, &pc, &tag);

  if ( (ber_class==BER_CLASS_APP) && (tag>=101) && (tag<=104) ){
    dissect_ConnectMCSPDU_PDU(tvb, pinfo, tree, NULL);
  } else  {
    t124_set_top_tree(top_tree);
    dissect_DomainMCSPDU_PDU(tvb, pinfo, tree);
  }

  return tvb_captured_length(tvb);
}

static bool
dissect_t125_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
  int8_t ber_class;
  bool pc;
  int32_t tag;
  volatile bool failed;

  /*
   * We must catch all the "ran past the end of the packet" exceptions
   * here and, if we catch one, just return false.  It's too painful
   * to have a version of dissect_per_sequence() that checks all
   * references to the tvbuff before making them and returning "no"
   * if they would fail.
   */
  failed = false;
  TRY {
    /* could be BER */
    get_ber_identifier(tvb, 0, &ber_class, &pc, &tag);
  } CATCH_BOUNDS_ERRORS {
    failed = true;
  } ENDTRY;

  if (failed) {
      return false;
  }

  if (((ber_class==BER_CLASS_APP) && ((tag>=101) && (tag<=104)))) {
    dissect_t125(tvb, pinfo, parent_tree, NULL);

    return true;
  }

  /*
   * Check that the first byte of the packet is a valid t125/MCS header.
   * This might not be enough, but since t125 only catch COTP packets,
   * it should not be a problem.
   */
  uint8_t first_byte = tvb_get_uint8(tvb, 0) >> 2;
  switch (first_byte) {
    case HF_T125_ERECT_DOMAIN_REQUEST:
    case HF_T125_ATTACH_USER_REQUEST:
    case HF_T125_ATTACH_USER_CONFIRM:
    case HF_T125_CHANNEL_JOIN_REQUEST:
    case HF_T125_CHANNEL_JOIN_CONFIRM:
    case HF_T125_DISCONNECT_PROVIDER_ULTIMATUM:
    case HF_T125_SEND_DATA_REQUEST:
    case HF_T125_SEND_DATA_INDICATION:
      dissect_t125(tvb, pinfo, parent_tree, NULL);
      return true;
  }

  return false;
}


/*--- proto_register_t125 -------------------------------------------*/
void proto_register_t125(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-t125-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
	  &ett_t125,
#include "packet-t125-ettarr.c"
  };

  /* Register protocol */
  proto_t125 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_t125, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  t125_heur_subdissector_list= register_heur_dissector_list_with_description("t125", "T.125 User data", proto_t125);

  register_dissector("t125", dissect_t125, proto_t125);
}


/*--- proto_reg_handoff_t125 ---------------------------------------*/
void proto_reg_handoff_t125(void) {

  heur_dissector_add("cotp", dissect_t125_heur, "T.125 over COTP", "t125_cotp", proto_t125, HEURISTIC_ENABLE);
  heur_dissector_add("cotp_is", dissect_t125_heur, "T.125 over COTP (inactive subset)", "t125_cotp_is", proto_t125, HEURISTIC_ENABLE);
}
