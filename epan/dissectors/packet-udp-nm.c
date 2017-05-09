/* packet-udp-nm.c
 * UDP-NM Dissector
 * By Dr. Lars Voelker <lars.voelker@bmw.de>
 * Copyright 2014-2017 Dr. Lars Voelker, BMW
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

/*
 * UDP-NM is an automotive communication protocol as standardized by
 * AUTOSAR (www.autosar.org) and is specified in AUTOSAR_SWS_UDPNetworkManagement.pdf,
 * which can be accessed on:
 * autosar.org -> Classic Platform -> Software Arch -> Comm Stack.
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/uat.h>

void proto_reg_handoff_udp_nm(void);
void proto_register_udp_nm(void);

typedef struct _user_data_field_t {
  gchar*  udf_name;
  gchar*  udf_desc;
  guint32 udf_offset;
  guint32 udf_length;
  guint32 udf_mask;
  gchar*  udf_value_desc;
} user_data_field_t;

static int proto_udp_nm = -1;

/*** header fields ***/
static int hf_udp_nm_source_node_identifier = -1;
static int hf_udp_nm_control_bit_vector = -1;
static int hf_udp_nm_control_bit_vector_repeat_msg_req = -1;
static int hf_udp_nm_control_bit_vector_nm_coord_sleep = -1;
static int hf_udp_nm_control_bit_vector_active_wakeup = -1;
static int hf_udp_nm_control_bit_vector_pni = -1;
static int hf_udp_nm_user_data = -1;

/*** protocol tree items ***/
static gint ett_udp_nm = -1;
static gint ett_udp_nm_cbv = -1;
static gint ett_udp_nm_user_data = -1;

/*** Bit meanings ***/
static const true_false_string tfs_udp_nm_control_rep_msg_req = {
  "Repeat Message State requested", "Repeat Message State not requested" };

static const true_false_string tfs_udp_nm_control_sleep_bit = {
  "Start of synchronized shutdown requested", "Start of synchronized shutdown not requested" };

static const true_false_string tfs_udp_nm_control_active_wakeup = {
  "Node has woken up the network", "Node has not woken up the network" };

static const true_false_string tfs_udp_nm_control_pni = {
  "NM message contains no Partial Network request information", "NM message contains Partial Network request information" };

/*** Configuration items ***/
/* Set the order of the first two fields (Source Node Identifier and Control Bit Vector */
static gboolean g_udp_nm_swap_first_fields = TRUE;

/*******************************
 ****** User data fields  ******
 *******************************/

/*** stolen from the HTTP disector ;-) ***/

static user_data_field_t* user_data_fields = NULL;
static guint num_user_data_fields = 0;
static GHashTable* user_data_fields_hash_hf = NULL;
static GHashTable* user_data_fields_hash_ett = NULL;

static gboolean
user_data_fields_update_cb(void *r, char **err)
{
  user_data_field_t *rec = (user_data_field_t *)r;
  char c;
  *err = NULL;

  if (rec->udf_length == 0) {
    *err = g_strdup_printf("length of user data field can't be 0 Bytes (name: %s offset: %i length: %i)", rec->udf_name, rec->udf_offset, rec->udf_length);
    return (*err == NULL);
  }

  if (rec->udf_length > 4) {
    *err = g_strdup_printf("length of user data field can't be greater 4 Bytes (name: %s offset: %i length: %i)", rec->udf_name, rec->udf_offset, rec->udf_length);
    return (*err == NULL);
  }

  if (rec->udf_offset < 2) {
    *err = g_strdup_printf("offset of user data field can't be short than 2 (name: %s offset: %i length: %i)", rec->udf_name, rec->udf_offset, rec->udf_length);
    return (*err == NULL);
  }

  if (rec->udf_mask >= G_MAXUINT32) {
    *err = g_strdup_printf("mask can only be up to 32bits (name: %s)", rec->udf_name);
    return (*err == NULL);
  }

  if (rec->udf_name == NULL) {
    *err = g_strdup_printf("Name of user data field can't be empty");
    return (*err == NULL);
  }

  g_strstrip(rec->udf_name);
  if (rec->udf_name[0] == 0) {
    *err = g_strdup_printf("Name of user data field can't be empty");
    return (*err == NULL);
  }

  /* Check for invalid characters (to avoid asserting out when
   * registering the field).
   */
  c = proto_check_field_name(rec->udf_name);
  if (c) {
    *err = g_strdup_printf("Name of user data field can't contain '%c'", c);
    return (*err == NULL);
  }

  return (*err == NULL);
}

static void *
user_data_fields_copy_cb(void* n, const void* o, size_t siz _U_)
{
  user_data_field_t* new_rec = (user_data_field_t*)n;
  const user_data_field_t* old_rec = (const user_data_field_t*)o;

  if (old_rec->udf_name) {
    new_rec->udf_name = g_strdup(old_rec->udf_name);
  }
  else {
    new_rec->udf_name = NULL;
  }

  if (old_rec->udf_desc) {
    new_rec->udf_desc = g_strdup(old_rec->udf_desc);
  }
  else {
    new_rec->udf_desc = NULL;
  }

  new_rec->udf_offset = old_rec->udf_offset;
  new_rec->udf_length = old_rec->udf_length;

  new_rec->udf_mask = old_rec->udf_mask;

  if (old_rec->udf_value_desc) {
    new_rec->udf_value_desc = g_strdup(old_rec->udf_value_desc);
  }
  else {
    new_rec->udf_value_desc = NULL;
  }

  return new_rec;
}

static void
user_data_fields_free_cb(void*r)
{
  user_data_field_t* rec = (user_data_field_t*)r;

  if (rec->udf_name) g_free(rec->udf_name);
  if (rec->udf_desc) g_free(rec->udf_desc);
  if (rec->udf_value_desc) g_free(rec->udf_value_desc);
}

UAT_CSTRING_CB_DEF(user_data_fields, udf_name, user_data_field_t)
UAT_CSTRING_CB_DEF(user_data_fields, udf_desc, user_data_field_t)
UAT_DEC_CB_DEF(user_data_fields, udf_offset, user_data_field_t)
UAT_DEC_CB_DEF(user_data_fields, udf_length, user_data_field_t)
UAT_HEX_CB_DEF(user_data_fields, udf_mask, user_data_field_t)
UAT_CSTRING_CB_DEF(user_data_fields, udf_value_desc, user_data_field_t)

static guint64
calc_ett_key(guint32 offset, guint32 length)
{
  guint64 ret = offset;
  return (ret * 0x100000000) ^ length;
}

/*
 * This creates a string for you that can be used as key for the hash table.
 * YOU must g_free that string!
 */
static gchar*
calc_hf_key(user_data_field_t udf)
{
  gchar* ret = NULL;
  ret = g_strdup_printf("%i-%i-%i-%s", udf.udf_offset, udf.udf_length, udf.udf_mask, udf.udf_name);
  return ret;
}

/*
 *
 */
static gint*
get_hf_for_user_data(gchar* key)
{
  gint* hf_id = NULL;

  if (user_data_fields_hash_hf) {
    hf_id = (gint*)g_hash_table_lookup(user_data_fields_hash_hf, key);
  }
  else {
    hf_id = NULL;
  }

  return hf_id;
}

/*
 *
 */
static gint*
get_ett_for_user_data(guint32 offset, guint32 length)
{
  gint* ett_id = NULL;

  guint64 key = calc_ett_key(offset, length);

  if (user_data_fields_hash_ett) {
    ett_id = (gint*)g_hash_table_lookup(user_data_fields_hash_ett, &key);
  }
  else {
    ett_id = NULL;
  }

  return ett_id;
}

/*
 *
 */
static void
user_data_post_update_cb(void)
{
  static hf_register_info* hf;
  gint* hf_id;
  guint i;
  //gchar* udf_name;

  gchar* tmp = NULL;
  guint64* key = NULL;

  static gint ett_dummy = -1;
  static gint *ett[] = {
    &ett_dummy,
  };

  static gint *ett_id;

  if (user_data_fields_hash_hf && hf) {
    guint hf_size = g_hash_table_size(user_data_fields_hash_hf);
    /* Unregister all fields */
    for (i = 0; i < hf_size; i++) {
      proto_deregister_field(proto_udp_nm, *(hf[i].p_id));
    }
    g_hash_table_destroy(user_data_fields_hash_hf);

    user_data_fields_hash_hf = NULL;
  }

  // we cannot unregister ETTs, so we should try to limit the damage of an update
  if (num_user_data_fields) {
    user_data_fields_hash_hf = g_hash_table_new(g_str_hash, g_str_equal);
    hf = g_new0(hf_register_info, num_user_data_fields);

    if (user_data_fields_hash_ett == NULL) {
      user_data_fields_hash_ett = g_hash_table_new(g_int64_hash, g_int64_equal);
    }

    for (i = 0; i < num_user_data_fields; i++) {
      hf_id = g_new(gint, 1);
      *hf_id = -1;

      hf[i].p_id = hf_id;
      hf[i].hfinfo.strings = NULL;
      hf[i].hfinfo.bitmask = user_data_fields[i].udf_mask;
      hf[i].hfinfo.same_name_next = NULL;
      hf[i].hfinfo.same_name_prev_id = -1;

      if (user_data_fields[i].udf_mask == 0 || user_data_fields[i].udf_length <= 0 || user_data_fields[i].udf_length>4) {
        hf[i].hfinfo.name = g_strdup(user_data_fields[i].udf_name);
        hf[i].hfinfo.abbrev = g_strdup_printf("nm.user_data.%s", user_data_fields[i].udf_name);
        hf[i].hfinfo.type = FT_BYTES;
        hf[i].hfinfo.display = BASE_NONE;
        hf[i].hfinfo.bitmask = 0;
        hf[i].hfinfo.blurb = g_strdup(user_data_fields[i].udf_desc);
      }
      else {
        hf[i].hfinfo.name = g_strdup(user_data_fields[i].udf_value_desc);
        hf[i].hfinfo.abbrev = g_strdup_printf("nm.user_data.%s.%s", user_data_fields[i].udf_name, user_data_fields[i].udf_value_desc);
        hf[i].hfinfo.type = FT_BOOLEAN;
        hf[i].hfinfo.display = 8 * (user_data_fields[i].udf_length);
        // hf[i].hfinfo.bitmask = 0;
        hf[i].hfinfo.blurb = g_strdup(user_data_fields[i].udf_value_desc);
      }

      tmp = calc_hf_key(user_data_fields[i]);
      g_hash_table_insert(user_data_fields_hash_hf, tmp, hf_id);

      // generate etts for new fields only
      if (get_ett_for_user_data(user_data_fields[i].udf_offset, user_data_fields[i].udf_length) == NULL) {
        ett_dummy = -1;
        proto_register_subtree_array(ett, array_length(ett));

        ett_id = g_new(gint, 1);
        *ett_id = ett_dummy;

        key = g_new(guint64, 1);
        *key = calc_ett_key(user_data_fields[i].udf_offset, user_data_fields[i].udf_length);

        g_hash_table_insert(user_data_fields_hash_ett, key, ett_id);
      }
    }

    proto_register_field_array(proto_udp_nm, hf, num_user_data_fields);
  }
}


/**********************************
 ****** The dissector itself ******
 **********************************/

static int
dissect_udp_nm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  proto_tree *udp_nm_tree;
  proto_tree *udp_nm_subtree = NULL;
  gchar* tmp = NULL;
  guint32 offset = 0;
  guint32 length = 0;
  guint32 msg_length = 0;
  guint32 ctrl_bit_vector;
  guint32 src_node_id = 0;
  guint i = 0;
  int* hf_id;
  int ett_id;

  // AUTOSAR says default is Source Node ID first and Ctrl Bit Vector second but this can be also swapped
  guint32 offset_ctrl_bit_vector = 1;
  guint32 offset_src_node_id = 0;

 static const int * control_bits[] = {
    &hf_udp_nm_control_bit_vector_repeat_msg_req,
    &hf_udp_nm_control_bit_vector_nm_coord_sleep,
    &hf_udp_nm_control_bit_vector_active_wakeup,
    &hf_udp_nm_control_bit_vector_pni,
    NULL
 };

  if (g_udp_nm_swap_first_fields == TRUE) {
    offset_ctrl_bit_vector = 0;
    offset_src_node_id = 1;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "NM");
  col_clear(pinfo->cinfo, COL_INFO);

  msg_length = tvb_reported_length(tvb);

  ti = proto_tree_add_item(tree, proto_udp_nm, tvb, 0, -1, ENC_NA);
  udp_nm_tree = proto_item_add_subtree(ti, ett_udp_nm);

  if (g_udp_nm_swap_first_fields == FALSE) {
    proto_tree_add_item_ret_uint(udp_nm_tree, hf_udp_nm_source_node_identifier, tvb, offset_src_node_id, 1, ENC_BIG_ENDIAN, &src_node_id);
  }

  proto_tree_add_bitmask(udp_nm_tree, tvb, offset_ctrl_bit_vector, hf_udp_nm_control_bit_vector, ett_udp_nm_cbv, control_bits, ENC_BIG_ENDIAN);
  ctrl_bit_vector = tvb_get_guint8(tvb, offset_ctrl_bit_vector);

  if (g_udp_nm_swap_first_fields == TRUE) {
    proto_tree_add_item_ret_uint(udp_nm_tree, hf_udp_nm_source_node_identifier, tvb, offset_src_node_id, 1, ENC_BIG_ENDIAN, &src_node_id);
  }

  col_add_fstr(pinfo->cinfo, COL_INFO, "Control Bit Vector: 0x%02x, Source Node: 0x%02x", ctrl_bit_vector, src_node_id);
  proto_item_append_text(ti, ", Control Bit Vector: 0x%02x, Source Node: %i", ctrl_bit_vector, src_node_id);

  offset = 2;

  /* now we need to process the user defined fields ... */
  ti = proto_tree_add_item(udp_nm_tree, hf_udp_nm_user_data, tvb, offset, msg_length - offset, ENC_NA);
  udp_nm_tree = proto_item_add_subtree(ti, ett_udp_nm_user_data);

  for (i = 0; i < num_user_data_fields; i++) {
    tmp = calc_hf_key(user_data_fields[i]);
    hf_id = get_hf_for_user_data(tmp);

    offset = user_data_fields[i].udf_offset;
    length = user_data_fields[i].udf_length;
    ett_id = *(get_ett_for_user_data(offset, length));

    if (hf_id && msg_length >= length + offset) {
      if (user_data_fields[i].udf_mask == 0) {
        ti = proto_tree_add_item(udp_nm_tree, *hf_id, tvb, offset, length, ENC_BIG_ENDIAN);
        udp_nm_subtree = proto_item_add_subtree(ti, ett_id);
      }
      else {
        if (udp_nm_subtree != NULL) {
          proto_tree_add_item(udp_nm_subtree, *hf_id, tvb, offset, length, ENC_BIG_ENDIAN);
        }
      }
    }
    else {
      /* should we warn? */
    }

    g_free(tmp);
  }

  return 8;
}

void proto_register_udp_nm(void)
{
  module_t *udp_nm_module;
  uat_t* user_data_fields_uat;

  static hf_register_info hf_udp_nm[] = {
    { &hf_udp_nm_control_bit_vector,
    { "Control Bit Vector", "nm.ctrl", FT_UINT8, BASE_HEX, NULL, 0x0, "The Control Bit Vector", HFILL } },
    { &hf_udp_nm_control_bit_vector_repeat_msg_req,
    { "Repeat Message Request", "nm.ctrl.repeat_msg_req", FT_BOOLEAN, 8, TFS(&tfs_udp_nm_control_rep_msg_req), 0x01, "The Repeat Message Request Bit", HFILL } },
    { &hf_udp_nm_control_bit_vector_nm_coord_sleep,
    { "NM Coordinator Sleep", "nm.ctrl.nm_coord_sleep", FT_BOOLEAN, 8, TFS(&tfs_udp_nm_control_sleep_bit), 0x08, "NM Coordinator Sleep Bit", HFILL } },
    { &hf_udp_nm_control_bit_vector_active_wakeup,
    { "Active Wakeup", "nm.ctrl.active_wakeup", FT_BOOLEAN, 8, TFS(&tfs_udp_nm_control_active_wakeup), 0x10, "Active Wakeup Bit", HFILL } },
    { &hf_udp_nm_control_bit_vector_pni,
    { "Partial Network Information", "nm.ctrl.pni", FT_BOOLEAN, 8, TFS(&tfs_udp_nm_control_pni), 0x40, "Partial Network Information Bit", HFILL } },

    { &hf_udp_nm_source_node_identifier,
    { "Source Node Identifier", "nm.src", FT_UINT8, BASE_DEC, NULL, 0x0, "The identification of the sending node", HFILL } },

    { &hf_udp_nm_user_data,
    { "User Data", "nm.user_data", FT_BYTES, BASE_NONE, NULL, 0x0, "The User Data", HFILL } },
  };

  static gint *ett[] = {
    &ett_udp_nm,
    &ett_udp_nm_cbv,
    &ett_udp_nm_user_data,
  };

  /* UAT for user_data fields */
  static uat_field_t user_data_uat_fields[] = {
    UAT_FLD_CSTRING(user_data_fields, udf_name, "User data name", "Name of user data field"),
    UAT_FLD_CSTRING(user_data_fields, udf_desc, "User data desc", "Description of user data field"),
    UAT_FLD_DEC(user_data_fields, udf_offset, "User data offset", "Offset of the user data field in the UDP-NM message (uint32)"),
    UAT_FLD_DEC(user_data_fields, udf_length, "User data length", "Length of the user data field in the UDP-NM message (uint32)"),
    UAT_FLD_DEC(user_data_fields, udf_mask, "User data mask", "Relevant bits of the user data field in the UDP-NM message (uint32)"),
    UAT_FLD_CSTRING(user_data_fields, udf_value_desc, "User data value", "Description what the masked bits mean"),
    UAT_END_FIELDS
  };

  /* Register the protocol name and description */
  proto_udp_nm = proto_register_protocol("Network Management", "NM", "nm");
  proto_register_field_array(proto_udp_nm, hf_udp_nm, array_length(hf_udp_nm));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register configuration options */
  udp_nm_module = prefs_register_protocol(proto_udp_nm, NULL);
  prefs_register_bool_preference(udp_nm_module, "swap_ctrl_and_src",
    "Swap Source Node Identifier and Control Bit Vector",
    "In the standard the Source Node Identifier is the first byte "
    "and the Control Bit Vector is the second byte. "
    "Using this parameter they can be swapped",
    &g_udp_nm_swap_first_fields);

  /* UAT */
  user_data_fields_uat = uat_new("NM User Data Fields Table",
    sizeof(user_data_field_t),       /* record size            */
    "NM_user_data_fields",        /* filename              */
    TRUE,                             /* from_profile          */
    &user_data_fields,                /* data_ptr              */
    &num_user_data_fields,            /* numitems_ptr          */
    UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS,  /* specifies named fields, so affects dissection and the set of named fields */
    NULL,                             /* help                  */
    user_data_fields_copy_cb,         /* copy callback         */
    user_data_fields_update_cb,       /* update callback       */
    user_data_fields_free_cb,         /* free callback         */
    user_data_post_update_cb,         /* post update callback  */
    NULL,                             /* reset callback        */
    user_data_uat_fields);            /* UAT field definitions */

  prefs_register_uat_preference(udp_nm_module, "udp_nm_user_data_fields", "User Data Field Configuration",
    "A table to define user defined fields in the NM payload",
    user_data_fields_uat);
}

void proto_reg_handoff_udp_nm(void)
{
  dissector_handle_t nm_handle = create_dissector_handle(dissect_udp_nm, proto_udp_nm);

  dissector_add_for_decode_as_with_preference("udp.port", nm_handle);
  dissector_add_for_decode_as("can.subdissector", nm_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
