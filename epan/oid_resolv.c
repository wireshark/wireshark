/* oid_resolv.c
 * Routines for OBJECT IDENTIFIER name resolution
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

#include "oid_resolv.h"
#include "to_str.h"
#include "strutil.h"
#include "epan/dissectors/format-oid.h"

static GHashTable *oid_table = NULL;

void oid_resolv_init(void) {
  oid_table = g_hash_table_new(g_str_hash, g_str_equal);
}

static void free_oid_str(gpointer key, gpointer value _U_,
                         gpointer user_data _U_) {
  g_free(key);
}

void oid_resolv_cleanup(void) {
  g_hash_table_foreach(oid_table, free_oid_str, NULL);
  g_hash_table_destroy(oid_table);
  oid_table = NULL;
}

gboolean oid_resolv_enabled(void) {
  return TRUE;
}

const gchar *get_oid_name(const guint8 *oid, gint oid_len) {
  const gchar *name;
  subid_t *subid_oid;
  guint subid_oid_length;
  gchar *decoded_oid;
  gchar *non_decoded_oid;

  name = g_hash_table_lookup(oid_table, oid_to_str(oid, oid_len));
  if (name) return name;
  subid_oid = g_malloc((oid_len+1) * sizeof(gulong));
  subid_oid_length = oid_to_subid_buf(oid, oid_len, subid_oid, ((oid_len+1) * sizeof(gulong)));
  new_format_oid(subid_oid, subid_oid_length, &non_decoded_oid, &decoded_oid);
  g_free(subid_oid);
  return decoded_oid;
}

const gchar *get_oid_str_name(const gchar *oid_str) {
  const gchar *name;
  GByteArray *bytes;
  gboolean res;

  bytes = g_byte_array_new();
  res = oid_str_to_bytes(oid_str, bytes);
  if (!res) return NULL;
  name = get_oid_name(bytes->data, bytes->len);
  g_byte_array_free(bytes, TRUE);
  return name;
}


extern void add_oid_name(const guint8 *oid, gint oid_len, const gchar *name) {
  add_oid_str_name(oid_to_str(oid, oid_len), name);
}

extern void add_oid_str_name(const gchar *oid_str, const gchar *name) {
  g_hash_table_insert(oid_table, (gpointer)g_strdup(oid_str), (gpointer)name);
}
