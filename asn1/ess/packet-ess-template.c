/* packet-ess.c
 * Routines for RFC 2634 and RFC 5035 Extended Security Services packet
 * dissection
 *   Ronnie Sahlberg 2004
 *   Stig Bjorlykke 2010
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
#include <string.h>

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/uat.h>

#include "packet-ber.h"
#include "packet-ess.h"
#include "packet-cms.h"
#include "packet-x509ce.h"
#include "packet-x509af.h"

#define PNAME  "Extended Security Services"
#define PSNAME "ESS"
#define PFNAME "ess"

void proto_register_ess(void);
void proto_reg_handoff_ess(void);

typedef struct _ess_category_attributes_t {
   char *oid;
   guint lacv;
   char *name;
} ess_category_attributes_t;

static ess_category_attributes_t *ess_category_attributes;
static guint num_ess_category_attributes;

/* Initialize the protocol and registered fields */
static int proto_ess = -1;
static int hf_ess_SecurityCategory_type_OID = -1;
static int hf_ess_Category_attribute = -1;

static gint ett_Category_attributes = -1;

#include "packet-ess-hf.c"

#include "packet-ess-val.h"

/* Initialize the subtree pointers */
#include "packet-ess-ett.c"

static const char *object_identifier_id;

UAT_CSTRING_CB_DEF(ess_category_attributes, oid, ess_category_attributes_t)
UAT_DEC_CB_DEF(ess_category_attributes, lacv, ess_category_attributes_t)
UAT_CSTRING_CB_DEF(ess_category_attributes, name, ess_category_attributes_t)

static void *
ess_copy_cb(void *dest, const void *orig, size_t len _U_)
{
  ess_category_attributes_t *u = (ess_category_attributes_t *)dest;
  const ess_category_attributes_t *o = (const ess_category_attributes_t *)orig;

  u->oid  = g_strdup(o->oid);
  u->lacv = o->lacv;
  u->name = g_strdup(o->name);

  return dest;
}

static void
ess_free_cb(void *r)
{
  ess_category_attributes_t *u = (ess_category_attributes_t *)r;

  g_free(u->oid);
  g_free(u->name);
}

static void
ess_dissect_attribute (guint32 value, asn1_ctx_t *actx)
{
  guint i;

  for (i = 0; i < num_ess_category_attributes; i++) {
    ess_category_attributes_t *u = &(ess_category_attributes[i]);

    if ((strcmp (u->oid, object_identifier_id) == 0) &&
        (u->lacv == value))
    {
       proto_item_append_text (actx->created_item, " (%s)", u->name);
       break;
    }
  }
}

static void
ess_dissect_attribute_flags (tvbuff_t *tvb, asn1_ctx_t *actx)
{
  proto_tree *tree;
  guint8 *value;
  guint i;

  tree = proto_item_add_subtree (actx->created_item, ett_Category_attributes);
  value = (guint8 *)tvb_memdup (wmem_packet_scope(), tvb, 0, tvb_captured_length (tvb));

  for (i = 0; i < num_ess_category_attributes; i++) {
    ess_category_attributes_t *u = &(ess_category_attributes[i]);

    if ((strcmp (u->oid, object_identifier_id) == 0) &&
        ((u->lacv / 8) < tvb_captured_length (tvb)) &&
        (value[u->lacv / 8] & (1 << (7 - (u->lacv % 8)))))
    {
       proto_tree_add_string_format (tree, hf_ess_Category_attribute, tvb,
                                     u->lacv / 8, 1, u->name,
                                     "%s (%d)", u->name, u->lacv);
    }
  }
}

#include "packet-ess-fn.c"

/*--- proto_register_ess ----------------------------------------------*/
void proto_register_ess(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_ess_SecurityCategory_type_OID,
      { "type", "ess.type_OID", FT_STRING, BASE_NONE, NULL, 0,
	"Type of Security Category", HFILL }},
    { &hf_ess_Category_attribute,
      { "Attribute", "ess.attribute", FT_STRING, BASE_NONE, NULL, 0,
	NULL, HFILL }},
#include "packet-ess-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
     &ett_Category_attributes,
#include "packet-ess-ettarr.c"
  };

  static uat_field_t attributes_flds[] = {
    UAT_FLD_CSTRING(ess_category_attributes,oid, "Tag Set", "Category Tag Set (Object Identifier)"),
    UAT_FLD_DEC(ess_category_attributes,lacv, "Value", "Label And Cert Value"),
    UAT_FLD_CSTRING(ess_category_attributes,name, "Name", "Category Name"),
    UAT_END_FIELDS
  };

  uat_t *attributes_uat = uat_new("ESS Category Attributes",
                                  sizeof(ess_category_attributes_t),
                                  "ess_category_attributes",
                                  TRUE,
                                  &ess_category_attributes,
                                  &num_ess_category_attributes,
                                  UAT_AFFECTS_DISSECTION, /* affects dissection of packets, but not set of named fields */
                                  "ChEssCategoryAttributes",
                                  ess_copy_cb,
                                  NULL,
                                  ess_free_cb,
                                  NULL,
                                  attributes_flds);

  static module_t *ess_module;

  /* Register protocol */
  proto_ess = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ess, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ess_module = prefs_register_protocol(proto_ess, NULL);

  prefs_register_uat_preference(ess_module, "attributes_table",
                                "ESS Category Attributes",
                                "ESS category attributes translation table",
                                attributes_uat);

}


/*--- proto_reg_handoff_ess -------------------------------------------*/
void proto_reg_handoff_ess(void) {
#include "packet-ess-dis-tab.c"
}

