/* packet-x509if.c
 * Routines for X.509 Information Framework packet dissection
 *  Ronnie Sahlberg 2004
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-x509if.h"
#include "packet-ber.h"
#include "packet-x509sat.h"
#include <epan/emem.h>
#include <epan/strutil.h>

#define PNAME  "X.509 Information Framework"
#define PSNAME "X509IF"
#define PFNAME "x509if"

/* Initialize the protocol and registered fields */
int proto_x509if = -1;
static int hf_x509if_object_identifier_id = -1;
static int hf_x509if_any_string = -1;
#include "packet-x509if-hf.c"

/* Initialize the subtree pointers */
#include "packet-x509if-ett.c"

static const char *object_identifier_id;
static proto_tree *top_of_dn = NULL;
static proto_tree *top_of_rdn = NULL;

static gboolean rdn_one_value = FALSE; /* have we seen one value in an RDN yet */
static gboolean dn_one_rdn = FALSE; /* have we seen one RDN in a DN yet */
static gboolean doing_dn = TRUE;

#define MAX_RDN_STR_LEN   64
#define MAX_DN_STR_LEN    (20 * MAX_RDN_STR_LEN)

static char *last_dn = NULL;
static char *last_rdn = NULL;

#include "packet-x509if-fn.c"

const char * x509if_get_last_dn(void)
{
  return last_dn;
}

/*--- proto_register_x509if ----------------------------------------------*/
void proto_register_x509if(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509if_object_identifier_id, 
      { "Id", "x509if.id", FT_STRING, BASE_NONE, NULL, 0,
	"Object identifier Id", HFILL }},
    { &hf_x509if_any_string, 
      { "AnyString", "x509if.any.String", FT_BYTES, BASE_HEX,
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

}


/*--- proto_reg_handoff_x509if -------------------------------------------*/
void proto_reg_handoff_x509if(void) {

}

