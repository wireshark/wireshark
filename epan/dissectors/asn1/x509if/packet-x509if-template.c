/* packet-x509if.c
 * Routines for X.509 Information Framework packet dissection
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
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>
#include <epan/strutil.h>

#include "packet-ber.h"
#include "packet-dap.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"
#include "packet-frame.h"

#define PNAME  "X.509 Information Framework"
#define PSNAME "X509IF"
#define PFNAME "x509if"

void proto_register_x509if(void);
void proto_reg_handoff_x509if(void);

/* Initialize the protocol and registered fields */
static int proto_x509if;
static int hf_x509if_object_identifier_id;
static int hf_x509if_any_string;
#include "packet-x509if-hf.c"

/* Initialize the subtree pointers */
#include "packet-x509if-ett.c"

static proto_tree *top_of_dn;
static proto_tree *top_of_rdn;

static bool rdn_one_value; /* have we seen one value in an RDN yet */
static bool dn_one_rdn; /* have we seen one RDN in a DN yet */
static bool doing_attr;

static wmem_strbuf_t *last_dn_buf;
static wmem_strbuf_t *last_rdn_buf;

static int ava_hf_index;
#define MAX_FMT_VALS   32
static value_string fmt_vals[MAX_FMT_VALS];
#define MAX_AVA_STR_LEN   64
static char *last_ava;

static void
x509if_frame_end(void)
{
  top_of_dn = NULL;
  top_of_rdn = NULL;

  rdn_one_value = false;
  dn_one_rdn = false;
  doing_attr = false;

  last_dn_buf = NULL;
  last_rdn_buf = NULL;
  last_ava = NULL;
}

#include "packet-x509if-fn.c"

const char * x509if_get_last_dn(void)
{
  return last_dn_buf ? wmem_strbuf_get_str(last_dn_buf) : NULL;
}

bool x509if_register_fmt(int hf_index, const char *fmt)
{
  static int idx = 0;

  if(idx < (MAX_FMT_VALS - 1)) {

    fmt_vals[idx].value = hf_index;
    fmt_vals[idx].strptr = fmt;

    idx++;

    fmt_vals[idx].value = 0;
    fmt_vals[idx].strptr = NULL;

    return true;

  } else
    return false; /* couldn't register it */

}

const char * x509if_get_last_ava(void)
{
  return last_ava;
}

/*--- proto_register_x509if ----------------------------------------------*/
void proto_register_x509if(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509if_object_identifier_id,
      { "Object Id", "x509if.oid", FT_OID, BASE_NONE, NULL, 0,
	"Object identifier Id", HFILL }},
    { &hf_x509if_any_string,
      { "AnyString", "x509if.any.String", FT_BYTES, BASE_NONE,
	    NULL, 0, "This is any String", HFILL }},

#include "packet-x509if-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-x509if-ettarr.c"
  };

  /* Register protocol */
  proto_x509if = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509if, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* initialise array */
  fmt_vals[0].value = 0;
  fmt_vals[0].strptr = NULL;

}


/*--- proto_reg_handoff_x509if -------------------------------------------*/
void proto_reg_handoff_x509if(void) {
#include "packet-x509if-dis-tab.c"
}

