/* preference_utils.h
 * Routines for handling preferences
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

#include <errno.h>

#include <glib.h>

#include <epan/filesystem.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>

#ifdef HAVE_LIBPCAP
#include "capture_opts.h"
#include "ui/capture_globals.h"
#endif

#include "ui/preference_utils.h"
#include "ui/simple_dialog.h"

guint
pref_stash(pref_t *pref, gpointer unused _U_)
{
    g_log(NULL,G_LOG_LEVEL_INFO, "=stashing %s", pref->name);
  switch (pref->type) {

  case PREF_UINT:
    pref->stashed_val.uint = *pref->varp.uint;
    break;

  case PREF_BOOL:
    pref->stashed_val.boolval = *pref->varp.boolp;
    break;

  case PREF_ENUM:
    pref->stashed_val.enumval = *pref->varp.enump;
    break;

  case PREF_STRING:
  case PREF_FILENAME:
    g_free(pref->stashed_val.string);
    pref->stashed_val.string = g_strdup(*pref->varp.string);
    break;

  case PREF_RANGE:
    g_free(pref->stashed_val.range);
    pref->stashed_val.range = range_copy(*pref->varp.range);
    break;

  case PREF_COLOR:
    g_log(NULL,G_LOG_LEVEL_INFO, "=stashing %s", pref->name);
    pref->stashed_val.color = *pref->varp.colorp;
    break;
  
  case PREF_STATIC_TEXT:
  case PREF_UAT:
  case PREF_CUSTOM:
    break;

  case PREF_OBSOLETE:
    g_assert_not_reached();
    break;
  }
  return 0;
}

guint
pref_unstash(pref_t *pref, gpointer changed_p)
{
  gboolean *pref_changed_p = changed_p;

  /* Revert the preference to its saved value. */
  switch (pref->type) {

  case PREF_UINT:
    if (*pref->varp.uint != pref->stashed_val.uint) {
      *pref_changed_p = TRUE;
      *pref->varp.uint = pref->stashed_val.uint;
    }
    break;

  case PREF_BOOL:
    if (*pref->varp.boolp != pref->stashed_val.boolval) {
      *pref_changed_p = TRUE;
      *pref->varp.boolp = pref->stashed_val.boolval;
    }
    break;

  case PREF_ENUM:
    if (*pref->varp.enump != pref->stashed_val.enumval) {
      *pref_changed_p = TRUE;
      *pref->varp.enump = pref->stashed_val.enumval;
    }
    break;

  case PREF_STRING:
  case PREF_FILENAME:
    if (strcmp(*pref->varp.string, pref->stashed_val.string) != 0) {
      *pref_changed_p = TRUE;
      g_free((void *)*pref->varp.string);
      *pref->varp.string = g_strdup(pref->stashed_val.string);
    }
    break;

  case PREF_RANGE:
    if (!ranges_are_equal(*pref->varp.range, pref->stashed_val.range)) {
      *pref_changed_p = TRUE;
      g_free(*pref->varp.range);
      *pref->varp.range = range_copy(pref->stashed_val.range);
    }
    break;

  case PREF_COLOR:
    *pref->varp.colorp = pref->stashed_val.color;
    break;

  case PREF_STATIC_TEXT:
  case PREF_UAT:
  case PREF_CUSTOM:
    break;

  case PREF_OBSOLETE:
    g_assert_not_reached();
    break;
  }
  return 0;
}

void
reset_stashed_pref(pref_t *pref) {
  switch (pref->type) {

  case PREF_UINT:
    pref->stashed_val.uint = pref->default_val.uint;
    break;

  case PREF_BOOL:
    pref->stashed_val.boolval = pref->default_val.boolval;
    break;

  case PREF_ENUM:
    pref->stashed_val.enumval = pref->default_val.enumval;
    break;

  case PREF_STRING:
  case PREF_FILENAME:
    g_free(pref->stashed_val.string);
    pref->stashed_val.string = g_strdup(pref->default_val.string);
    break;

  case PREF_RANGE:
    g_free(pref->stashed_val.range);
    pref->stashed_val.range = range_copy(pref->default_val.range);
    break;

  case PREF_COLOR:
    memcpy(&pref->stashed_val.color, &pref->default_val.color, sizeof(color_t));
    break;

  case PREF_STATIC_TEXT:
  case PREF_UAT:
  case PREF_CUSTOM:
    break;

  case PREF_OBSOLETE:
    g_assert_not_reached();
    break;
  }
}

guint
pref_clean_stash(pref_t *pref, gpointer unused _U_)
{
  switch (pref->type) {

  case PREF_UINT:
    break;

  case PREF_BOOL:
    break;

  case PREF_ENUM:
    break;

  case PREF_STRING:
  case PREF_FILENAME:
    if (pref->stashed_val.string != NULL) {
      g_free(pref->stashed_val.string);
      pref->stashed_val.string = NULL;
    }
    break;

  case PREF_RANGE:
    if (pref->stashed_val.range != NULL) {
      g_free(pref->stashed_val.range);
      pref->stashed_val.range = NULL;
    }
    break;

  case PREF_STATIC_TEXT:
  case PREF_UAT:
  case PREF_COLOR:
  case PREF_CUSTOM:
    break;

  case PREF_OBSOLETE:
    g_assert_not_reached();
    break;
  }
  return 0;
}

/* Fill in capture options with values from the preferences */
void
prefs_to_capture_opts(void)
{
#ifdef HAVE_LIBPCAP
  /* Set promiscuous mode from the preferences setting. */
  /* the same applies to other preferences settings as well. */
    global_capture_opts.default_options.promisc_mode = prefs.capture_prom_mode;
    global_capture_opts.use_pcapng                   = prefs.capture_pcap_ng;
    global_capture_opts.show_info                    = prefs.capture_show_info;
    global_capture_opts.real_time_mode               = prefs.capture_real_time;
    auto_scroll_live                                 = prefs.capture_auto_scroll;
#endif /* HAVE_LIBPCAP */
}

void
prefs_main_write(void)
{
  int   err;
  char *pf_dir_path;
  char *pf_path;

  /* Create the directory that holds personal configuration files, if
     necessary.  */
  if (create_persconffile_dir(&pf_dir_path) == -1) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                  "Can't create directory\n\"%s\"\nfor preferences file: %s.", pf_dir_path,
                  g_strerror(errno));
    g_free(pf_dir_path);
  } else {
    /* Write the preferencs out. */
    err = write_prefs(&pf_path);
    if (err != 0) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "Can't open preferences file\n\"%s\": %s.", pf_path,
                    g_strerror(err));
      g_free(pf_path);
    }
  }

#ifdef HAVE_AIRPCAP
  /*
   * Load the Wireshark decryption keys (just set) and save
   * the changes to the adapters' registry
   */
  airpcap_load_decryption_keys(airpcap_if_list);
#endif
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
