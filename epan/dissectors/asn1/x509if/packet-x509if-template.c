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
static int proto_x509if = -1;
static int hf_x509if_object_identifier_id = -1;
static int hf_x509if_any_string = -1;
#include "packet-x509if-hf.c"

/* Initialize the subtree pointers */
#include "packet-x509if-ett.c"

static proto_tree *top_of_dn = NULL;
static proto_tree *top_of_rdn = NULL;

static gboolean rdn_one_value = FALSE; /* have we seen one value in an RDN yet */
static gboolean dn_one_rdn = FALSE; /* have we seen one RDN in a DN yet */
static gboolean doing_attr = FALSE;

#define MAX_RDN_STR_LEN   128
#define MAX_DN_STR_LEN    (20 * MAX_RDN_STR_LEN)

static char *last_dn = NULL;
static char *last_rdn = NULL;

static int ava_hf_index;
#define MAX_FMT_VALS   32
static value_string fmt_vals[MAX_FMT_VALS];
#define MAX_AVA_STR_LEN   64
static char *last_ava = NULL;

static void
x509if_frame_end(void)
{
  top_of_dn = NULL;
  top_of_rdn = NULL;

  rdn_one_value = FALSE;
  dn_one_rdn = FALSE;
  doing_attr = FALSE;

  last_dn = NULL;
  last_rdn = NULL;
  last_ava = NULL;
}

#include "packet-x509if-fn.c"

const char * x509if_get_last_dn(void)
{
  return last_dn;
}

gboolean x509if_register_fmt(int hf_index, const gchar *fmt)
{
  static int idx = 0;

  if(idx < (MAX_FMT_VALS - 1)) {

    fmt_vals[idx].value = hf_index;
    fmt_vals[idx].strptr = fmt;

    idx++;

    fmt_vals[idx].value = 0;
    fmt_vals[idx].strptr = NULL;

    return TRUE;

  } else
    return FALSE; /* couldn't register it */

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
  static gint *ett[] = {
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

