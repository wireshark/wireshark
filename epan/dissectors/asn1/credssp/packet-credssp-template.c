/* packet-credssp.c
 * Routines for CredSSP (Credential Security Support Provider) packet dissection
 * Graeme Lunt 2011
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/tap.h>
#include <epan/exported_pdu.h>

#include "packet-ber.h"
#include "packet-gssapi.h"
#include "packet-kerberos.h"
#include "packet-ntlmssp.h"
#include "packet-credssp.h"

#define PNAME  "Credential Security Support Provider"
#define PSNAME "CredSSP"
#define PFNAME "credssp"

#define TS_PASSWORD_CREDS   1
#define TS_SMARTCARD_CREDS  2
#define TS_REMOTEGUARD_CREDS  6

static int creds_type;
static int credssp_ver;

static char kerberos_pname[] = "K\0e\0r\0b\0e\0r\0o\0s";
static char ntlm_pname[] = "N\0T\0L\0M";

#define TS_RGC_UNKNOWN	0
#define TS_RGC_KERBEROS	1
#define TS_RGC_NTLM	2

static int credssp_TS_RGC_package;

static int exported_pdu_tap = -1;

/* Initialize the protocol and registered fields */
static int proto_credssp;

/* List of dissectors to call for negoToken data */
static heur_dissector_list_t credssp_heur_subdissector_list;

static dissector_handle_t gssapi_handle;
static dissector_handle_t gssapi_wrap_handle;

static int hf_credssp_TSPasswordCreds;   /* TSPasswordCreds */
static int hf_credssp_TSSmartCardCreds;  /* TSSmartCardCreds */
static int hf_credssp_TSRemoteGuardCreds;/* TSRemoteGuardCreds */
static int hf_credssp_TSCredentials;     /* TSCredentials */
static int hf_credssp_decr_PublicKeyAuth;/* decr_PublicKeyAuth */
#include "packet-credssp-hf.c"

/* Initialize the subtree pointers */
static int ett_credssp;
static int ett_credssp_RGC_CredBuffer;

#include "packet-credssp-ett.c"

#include "packet-credssp-fn.c"

/*
* Dissect CredSSP PDUs
*/
static int
dissect_credssp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_credssp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_credssp);
	}
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CredSSP");
  	col_clear(pinfo->cinfo, COL_INFO);

	creds_type = -1;
	credssp_ver = -1;

	return dissect_TSRequest_PDU(tvb, pinfo, tree, data);
}

static bool
dissect_credssp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
  asn1_ctx_t asn1_ctx;
  int offset = 0;
  int8_t ber_class;
  bool pc;
  int32_t tag;
  uint32_t length;
  int8_t ver;

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

  /* Look for SEQUENCE, CONTEXT 0, and INTEGER 2 */
  if(tvb_captured_length(tvb) > 7) {
    offset = get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
    if((ber_class == BER_CLASS_UNI) && (tag == BER_UNI_TAG_SEQUENCE) && (pc == true)) {
      offset = get_ber_length(tvb, offset, NULL, NULL);
      offset = get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
      if((ber_class == BER_CLASS_CON) && (tag == 0)) {
        offset = get_ber_length(tvb, offset, NULL, NULL);
        offset = get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
        if((ber_class == BER_CLASS_UNI) && (tag == BER_UNI_TAG_INTEGER)) {
          offset = get_ber_length(tvb, offset, &length, NULL);
          ver = tvb_get_uint8(tvb, offset);
          if((length == 1) && (ver > 1) && (ver < 99)) {
            if (have_tap_listener(exported_pdu_tap)) {
              exp_pdu_data_t *exp_pdu_data = export_pdu_create_common_tags(pinfo, "credssp", EXP_PDU_TAG_DISSECTOR_NAME);

              exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
              exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
              exp_pdu_data->pdu_tvb = tvb;

              tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
            }
            dissect_credssp(tvb, pinfo, parent_tree, data);
            return true;
          }
        }
      }
    }
  }
  return false;
}


/*--- proto_register_credssp -------------------------------------------*/
void proto_register_credssp(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
    { &hf_credssp_TSPasswordCreds,
      { "TSPasswordCreds", "credssp.TSPasswordCreds",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_TSSmartCardCreds,
      { "TSSmartCardCreds", "credssp.TSSmartCardCreds",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_TSRemoteGuardCreds,
      { "TSRemoteGuardCreds", "credssp.TSRemoteGuardCreds",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_TSCredentials,
      { "TSCredentials", "credssp.TSCredentials",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_decr_PublicKeyAuth,
      { "Decrypted PublicKeyAuth (sha256)", "credssp.decr_PublicKeyAuth",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
#include "packet-credssp-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_credssp,
    &ett_credssp_RGC_CredBuffer,
#include "packet-credssp-ettarr.c"
  };


  /* Register protocol */
  proto_credssp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("credssp", dissect_credssp, proto_credssp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_credssp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* heuristic dissectors for any preamble e.g. CredSSP before RDP */
  credssp_heur_subdissector_list = register_heur_dissector_list_with_description("credssp", "Unused", proto_credssp);

}


/*--- proto_reg_handoff_credssp --- */
void proto_reg_handoff_credssp(void) {

  gssapi_handle = find_dissector_add_dependency("gssapi", proto_credssp);
  gssapi_wrap_handle = find_dissector_add_dependency("gssapi_verf", proto_credssp);

  heur_dissector_add("tls", dissect_credssp_heur, "CredSSP over TLS", "credssp_tls", proto_credssp, HEURISTIC_ENABLE);
  heur_dissector_add("rdp", dissect_credssp_heur, "CredSSP in TPKT", "credssp_tpkt", proto_credssp, HEURISTIC_ENABLE);
  exported_pdu_tap = find_tap_id(EXPORT_PDU_TAP_NAME_LAYER_7);
}

