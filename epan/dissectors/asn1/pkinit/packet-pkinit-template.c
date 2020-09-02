/* packet-pkinit.c
 * Routines for PKINIT packet dissection
 *  Ronnie Sahlberg 2004
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

#include "packet-ber.h"
#include "packet-pkinit.h"
#include "packet-cms.h"
#include "packet-pkix1explicit.h"
#include "packet-kerberos.h"

#define PNAME  "PKINIT"
#define PSNAME "PKInit"
#define PFNAME "pkinit"

void proto_register_pkinit(void);
void proto_reg_handoff_pkinit(void);

/* Initialize the protocol and registered fields */
static int proto_pkinit = -1;
#include "packet-pkinit-hf.c"

/* Initialize the subtree pointers */
#include "packet-pkinit-ett.c"

static int dissect_KerberosV5Spec2_KerberosTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);
static int dissect_KerberosV5Spec2_Realm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);
static int dissect_KerberosV5Spec2_PrincipalName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);
static int dissect_pkinit_PKAuthenticator_Win2k(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

#include "packet-pkinit-fn.c"

int
dissect_pkinit_PA_PK_AS_REQ(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_) {
  offset = dissect_pkinit_PaPkAsReq(FALSE, tvb, offset, actx, tree, -1);
  return offset;
}

int
dissect_pkinit_PA_PK_AS_REP(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_) {
  offset = dissect_pkinit_PaPkAsRep(FALSE, tvb, offset, actx, tree, -1);
  return offset;
}

static int
dissect_KerberosV5Spec2_KerberosTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {
  offset = dissect_krb5_ctime(tree, tvb, offset, actx);
  return offset;
}

static int
dissect_KerberosV5Spec2_Realm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {
  offset = dissect_krb5_realm(tree, tvb, offset, actx);
  return offset;
}

static int
dissect_KerberosV5Spec2_PrincipalName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {
  offset = dissect_krb5_cname(tree, tvb, offset, actx);
  return offset;
}


/*--- proto_register_pkinit ----------------------------------------------*/
void proto_register_pkinit(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-pkinit-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-pkinit-ettarr.c"
  };

  /* Register protocol */
  proto_pkinit = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkinit, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkinit -------------------------------------------*/
void proto_reg_handoff_pkinit(void) {
#include "packet-pkinit-dis-tab.c"
}

