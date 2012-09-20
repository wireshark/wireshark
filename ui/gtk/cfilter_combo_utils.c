/* cfilter_combo_utils.c
 * Capture filter combo box routines
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

#include <stdio.h>
#include <string.h>

#include <gtk/gtk.h>

#include "ui/recent.h"
#include "ui/recent_utils.h"

#include "ui/gtk/main.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/cfilter_combo_utils.h"


/* XXX: use a preference for this setting! */
static guint cfilter_combo_max_recent = 20;

static gboolean
cfilter_combo_add(gchar *s) {
  GList     *li;
  GList     *fl = g_object_get_data(G_OBJECT(top_level), E_CFILTER_FL_KEY);

  li = g_list_first(fl);
  while (li) {
    /* If the filter is already in the list, remove the old one and
     * append the new one at the latest position (at g_list_append() below) */
    if (li->data && strcmp(s, li->data) == 0) {
      fl = g_list_remove(fl, li->data);
      break;
    }
    li = li->next;
  }
  fl = g_list_append(fl, s);
  g_object_set_data(G_OBJECT(top_level), E_CFILTER_FL_KEY, fl);
  return TRUE;
}


/* write all non empty capture filters (until maximum count)
 * of the combo box GList to the user's recent file */
void
 cfilter_combo_recent_write_all(FILE *rf) {
   GList     *cfilter_list = g_object_get_data(G_OBJECT(top_level), E_CFILTER_FL_KEY);
   GList     *li;
   guint      max_count = 0;

   /* write all non empty capture filter strings to the recent file (until max count) */
   li = g_list_first(cfilter_list);
   while (li && (max_count++ <= cfilter_combo_max_recent) ) {
     if (li->data && strlen(li->data)) {
       fprintf (rf, RECENT_KEY_CAPTURE_FILTER ": %s\n", (char *)li->data);
     }
     li = li->next;
   }
}

/* add a capture filter coming from the user's recent file to the cfilter combo box */
gboolean
 cfilter_combo_add_recent(gchar *s) {
   gchar *dup;

   if (s) {
     dup = g_strdup(s);
     if (!cfilter_combo_add(dup)) {
       g_free(dup);
       return FALSE;
     }
   }
   return TRUE;
}
