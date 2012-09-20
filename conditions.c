/* conditions.c
 * Implementation for condition handler.
 *
 * $Id$
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

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "conditions.h"

/* container for condition classes */
static GHashTable* classes = NULL;

/* condition data structure declaration */
struct condition{
  char* class_id;
  void* user_data;
  _cnd_eval eval_func;
  _cnd_reset reset_func;
};

/* structure used to store class functions in GHashTable */
typedef struct _cnd_class{
  _cnd_constr constr_func;
  _cnd_destr destr_func;
  _cnd_eval eval_func;
  _cnd_reset reset_func;
} _cnd_class;

/* helper function prototypes */
static void _cnd_init(void);
static void _cnd_find_hash_key_for_class_id(gpointer, gpointer, gpointer);

condition* cnd_new(const char* class_id, ...){
  va_list ap;
  condition *cnd = NULL, *cnd_ref = NULL;
  _cnd_class *cls = NULL;
  char* id = NULL;

  /* check if hash table is already initialized */
  _cnd_init();

  /* get class structure for this id */
  if((cls = (_cnd_class*)g_hash_table_lookup(classes, class_id)) == NULL) {
    g_warning("cnd_new: Couldn't find class ID \"%s\"", class_id);
    return NULL;
  }

  /* initialize the basic structure */
  if((cnd_ref = (condition*)g_malloc(sizeof(condition))) == NULL) return NULL;
  cnd_ref->user_data = NULL;
  cnd_ref->eval_func = cls->eval_func;
  cnd_ref->reset_func = cls->reset_func;

  cnd_ref->class_id = g_strdup(class_id);

  /* perform class specific initialization */
  va_start(ap, class_id);
  cnd = (cls->constr_func)(cnd_ref, ap);
  va_end(ap);

  /* check for successful construction */
  if(cnd == NULL){
    g_free(cnd_ref);
    g_free(id);
  }
  return cnd;
} /* END cnd_new() */

void cnd_delete(condition *cnd){
  _cnd_class *cls = NULL;
  const char* class_id;
  /* check for valid pointer */
  if(cnd == NULL) return;

  class_id = cnd->class_id;
  /* check if hash table is already initialized */
  _cnd_init();
  /* get the condition class */
  cls = (_cnd_class*)g_hash_table_lookup(classes, class_id);
  /* call class specific destructor */
  if(cls != NULL) (cls->destr_func)(cnd);
  /* free memory */
  g_free(cnd->class_id);
  /* free basic structure */
  g_free(cnd);
} /* END cnd_delete() */

gboolean cnd_eval(condition *cnd, ...){
  va_list ap;
  gboolean ret_val = FALSE;
  /* validate cnd */
  if(cnd == NULL) return FALSE;
  /* call specific handler */
  va_start(ap, cnd);
  ret_val = (cnd->eval_func)(cnd, ap);
  va_end(ap);
  return ret_val;
} /*  END cnd_eval() */

void cnd_reset(condition *cnd){
  if(cnd != NULL) (cnd->reset_func)(cnd);
} /* END cnd_reset() */

void* cnd_get_user_data(condition *cnd){
  return cnd->user_data;
} /* END cnd_get_user_data() */

void cnd_set_user_data(condition *cnd, void* user_data){
  cnd->user_data = user_data;
} /* END cnd_set_user_data() */

gboolean cnd_register_class(const char* class_id,
                            _cnd_constr constr_func,
                            _cnd_destr destr_func,
                            _cnd_eval eval_func,
                            _cnd_reset reset_func){
  char* key = NULL;
  _cnd_class *cls = NULL;
  /* check for valid parameters */
  if((constr_func == NULL) || (destr_func == NULL) ||
     (eval_func == NULL) || (reset_func == NULL) || (class_id == NULL))
    return FALSE;
  /* check if hash table is already initialized */
  _cnd_init();
  /* check for unique class id */
  if(g_hash_table_lookup(classes, class_id) != NULL) {
    g_warning("cnd_register_class: Duplicate class ID \"%s\"", class_id);
    return FALSE;
  }
  /* GHashTable keys need to be persistent for the lifetime of the hash
     table. Allocate memory and copy the class id which we use as key. */
  key = g_strdup(class_id);
  /* initialize class structure */
  if((cls = (_cnd_class*)g_malloc(sizeof(_cnd_class))) == NULL){
    g_free(key);
    return FALSE;
  }
  cls->constr_func = constr_func;
  cls->destr_func = destr_func;
  cls->eval_func = eval_func;
  cls->reset_func = reset_func;
  /* insert new class */
  g_hash_table_insert(classes, key, cls);
  return TRUE;
} /* END cnd_register_class() */

static char* pkey = NULL;
void cnd_unregister_class(const char* class_id){
  const char *key = (const char*)class_id;
  _cnd_class *cls = NULL;
  /* check if hash table is already initialized */
  _cnd_init();
  /* find the key for this class id and store it in 'pkey' */
  g_hash_table_foreach(classes,
                       _cnd_find_hash_key_for_class_id,
                       (gpointer)key);
  /* find the class structure for this class id */
  cls = (_cnd_class*)g_hash_table_lookup(classes, class_id);
  /* remove constructor from hash table */
  g_hash_table_remove(classes, class_id);
  /* free the key */
  g_free(pkey);
  pkey = NULL;
  /* free the value */
  g_free(cls);
} /* END cnd_unregister_class() */

/*
 * Initialize hash table.
 */
static void _cnd_init(void){
  if(classes != NULL) return;
  /* create hash table, we use strings as keys */
  classes = g_hash_table_new(g_str_hash, g_str_equal);
} /* END _cnd_init() */

/*
 * Callback for function 'g_hash_table_foreach()'.
 * We don't keep references to hash table keys. Keys have memory allocated
 * which must be freed when they are not used anymore. This function finds
 * the reference to a key corresponding to a particular class id. The reference
 * to the key is stored in a global variable.
 */
void _cnd_find_hash_key_for_class_id(gpointer key,
                                     gpointer value _U_,
                                     gpointer user_data){
  char* class_id = (char*)user_data;
  char* key_value = (char*)key;
  if(strcmp(class_id, key_value) == 0) pkey = key_value;
} /* END _cnd_find_hash_key_for_class_id() */

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
