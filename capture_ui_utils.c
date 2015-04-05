/* capture_ui_utils.c
 * Utilities for capture user interfaces
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

#ifdef HAVE_LIBPCAP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>

#include "epan/prefs.h"
#include "epan/ex-opt.h"
#include "capture_ifinfo.h"
#include "capture_ui_utils.h"
#include "ui/capture_globals.h"
#include "wiretap/wtap.h"
#include "epan/to_str.h"

/*
 * Find user-specified capture device description that matches interface
 * name, if any.
 */
char *
capture_dev_user_descr_find(const gchar *if_name)
{
  char *p;
  char *p2 = NULL;
  char *descr = NULL;
  int lp = 0;
  int ct = 0;

  if ((prefs.capture_devices_descr == NULL) ||
      (*prefs.capture_devices_descr == '\0')) {
    /* There are no descriptions. */
    return NULL;
  }

  if ((p = strstr(prefs.capture_devices_descr, if_name)) == NULL) {
    /* There are, but there isn't one for this interface. */
    return NULL;
  }

  while (*p != '\0') {
    /* error: ran into next interface description */
    if (*p == ',')
      return NULL;
    /* found left parenthesis, start of description */
    else if (*p == '(') {
      ct = 0;
      lp++;
      /* skip over left parenthesis */
      p++;
      /* save pointer to beginning of description */
      p2 = p;
      continue;
    }
    else if (*p == ')') {
      /* end of description */
      break;
    }
    else {
        p++;
        ct++;
    }
  }

  if ((lp == 1) && (ct > 0) && (p2 != NULL)) {
    /* Allocate enough space to return the string,
       which runs from p2 to p, plus a terminating
       '\0'. */
    descr = (char *)g_malloc(p - p2 + 1);
    memcpy(descr, p2, p - p2);
    descr[p - p2] = '\0';
    return descr;
  }
  else
    return NULL;
}

gint
capture_dev_user_linktype_find(const gchar *if_name)
{
  gchar *p, *next;
  long linktype;

  if ((prefs.capture_devices_linktypes == NULL) ||
      (*prefs.capture_devices_linktypes == '\0')) {
    /* There are no link-layer header types */
    return -1;
  }

  if ((p = strstr(prefs.capture_devices_linktypes, if_name)) == NULL) {
    /* There are, but there isn't one for this interface. */
    return -1;
  }

  p += strlen(if_name) + 1;
  linktype = strtol(p, &next, 10);
  if (next == p || *next != ')' || linktype < 0) {
    /* Syntax error */
    return -1;
  }
  if (linktype > G_MAXINT) {
    /* Value doesn't fit in a gint */
    return -1;
  }

  return (gint)linktype;
}

#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
gint
capture_dev_user_buffersize_find(const gchar *if_name)
{
  gchar *p, *next;
  gint buffersize;

  if ((prefs.capture_devices_buffersize == NULL) ||
      (*prefs.capture_devices_buffersize == '\0')) {
    /* There are no buffersizes defined */
    return -1;
  }

  if ((p = strstr(prefs.capture_devices_buffersize, if_name)) == NULL) {
    /* There are, but there isn't one for this interface. */
    return -1;
  }

  p += strlen(if_name) + 1;
  buffersize = (gint)strtol(p, &next, 10);
  if (next == p || *next != ')' || buffersize < 0) {
    /* Syntax error */
    return -1;
  }
  if (buffersize > G_MAXINT) {
    /* Value doesn't fit in a gint */
    return -1;
  }

  return (gint)buffersize;
}
#endif

gint
capture_dev_user_snaplen_find(const gchar *if_name)
{
  gchar *p, *next;
  gint snaplen;

  if ((prefs.capture_devices_snaplen == NULL) ||
      (*prefs.capture_devices_snaplen == '\0')) {
    /* There is no snap length defined */
    return -1;
  }

  if ((p = strstr(prefs.capture_devices_snaplen, if_name)) == NULL) {
    /* There are, but there isn't one for this interface. */
    return -1;
  }

  p += strlen(if_name) + 3;
  snaplen = (gint)strtol(p, &next, 10);
  if (next == p || *next != ')' || snaplen < 0) {
    /* Syntax error */
    return -1;
  }
  if (snaplen > WTAP_MAX_PACKET_SIZE) {
    /* Value doesn't fit in a gint */
    return -1;
  }

  return (gint)snaplen;
}

gboolean
capture_dev_user_hassnap_find(const gchar *if_name)
{
  gchar *p, *next;
  gboolean hassnap;

  if ((prefs.capture_devices_snaplen == NULL) ||
      (*prefs.capture_devices_snaplen == '\0')) {
    /* There is no snap length defined */
    return -1;
  }

  if ((p = strstr(prefs.capture_devices_snaplen, if_name)) == NULL) {
    /* There are, but there isn't one for this interface. */
    return -1;
  }

  p += strlen(if_name) + 1;
  hassnap = (gboolean)strtol(p, &next, 10);
  if (next == p || *next != '(') {
    /* Syntax error */
    return -1;
  }

  return (gboolean)hassnap;
}

gboolean
capture_dev_user_pmode_find(const gchar *if_name)
{
  gchar *p, *next;
  gboolean pmode;

  if ((prefs.capture_devices_pmode == NULL) ||
      (*prefs.capture_devices_pmode == '\0')) {
    /* There is no promiscuous mode defined */
    return -1;
  }

  if ((p = strstr(prefs.capture_devices_pmode, if_name)) == NULL) {
    /* There are, but there isn't one for this interface. */
    return -1;
  }

  p += strlen(if_name) + 1;
  pmode = (gboolean)strtol(p, &next, 10);
  if (next == p || *next != ')') {
    /* Syntax error */
    return -1;
  }
  return (gboolean)pmode;
}

/*
 * Return as descriptive a name for an interface as we can get.
 * If the user has specified a comment, use that.  Otherwise,
 * if capture_interface_list() supplies a description, use that,
 * otherwise use the interface name.
 *
 * The result must be g_free()'d when you're done with it.
 *
 * Note: given that this calls capture_interface_list(), which attempts to
 * open all adapters it finds in order to check whether they can be
 * captured on, this is an expensive routine to call, so don't call it
 * frequently.
 */
char *
get_interface_descriptive_name(const char *if_name)
{
  char *descr;
  GList *if_list;
  GList *if_entry;
  if_info_t *if_info;
  int err;

  /* Do we have a user-supplied description? */
  descr = capture_dev_user_descr_find(if_name);
  if (descr != NULL) {
    /* Yes - make a copy of that. */
    descr = g_strdup(descr);
  } else if (strcmp(if_name, "-") == 0) {
    /*
     * Strictly speaking, -X (extension) options are for modules, e.g. Lua
     * and using one here stretches that definition. However, this doesn't
     * waste a single-letter option on something that might be rarely used
     * and is backward-compatible to 1.0.
     */
    descr = g_strdup(ex_opt_get_nth("stdin_descr", 0));
    if (!descr) {
      descr = g_strdup("Standard input");
    }
  } else {
    /* No, we don't have a user-supplied description; did we get
       one from the OS or libpcap? */
    descr = NULL;
    if_list = capture_interface_list(&err, NULL, NULL);
    if (if_list != NULL) {
      if_entry = if_list;
      do {
        if_info = (if_info_t *)if_entry->data;
        if (strcmp(if_info->name, if_name) == 0) {
          if (if_info->friendly_name != NULL) {
              /* We have a "friendly name"; return a copy of that
                 as the description - when we free the interface
                 list, that'll also free up the strings to which
                 it refers. */
              descr = g_strdup(if_info->friendly_name);
          } else if (if_info->vendor_description != NULL) {
            /* We have no "friendly name", but we have a vendor
               description; return a copy of that - when we free
               the interface list, that'll also free up the strings
               to which it refers. */
            descr = g_strdup(if_info->vendor_description);
          }
          break;
        }
      } while ((if_entry = g_list_next(if_entry)) != NULL);
    }
    free_interface_list(if_list);

    if (descr == NULL) {
      /* The interface name is all we have, so just return a copy of that. */
      descr = g_strdup(if_name);
    }
  }

  return descr;
}


/* search interface info by interface name */
static if_info_t *
search_info(GList *if_list, gchar *if_name)
{
  GList *if_entry;
  if_info_t *if_info;


  for (if_entry = if_list; if_entry != NULL; if_entry = g_list_next(if_entry)) {
    if_info = (if_info_t *)if_entry->data;

    if(strcmp(if_name, if_info->name) == 0) {
      return if_info;
    }
  }

  return NULL;
}


/* build the string to display in the combo box for the given interface */
char *
build_capture_combo_name(GList *if_list, gchar *if_name)
{
  gchar *descr;
  char *if_string;
  if_info_t *if_info;

  /* Do we have a user-supplied description? */
  descr = capture_dev_user_descr_find(if_name);
  if (descr != NULL) {
    /* Yes, we have a user-supplied description; use it. */
    if_string = g_strdup_printf("%s: %s", descr, if_name);
    g_free(descr);
  } else {
    /* No, we don't have a user-supplied description; did we get
     one from the OS or libpcap? */
    if_info = search_info(if_list, if_name);
    if (if_info != NULL && if_info->vendor_description != NULL) {
      /* Yes - use it. */
      if_string = g_strdup_printf("%s: %s", if_info->vendor_description,
                                  if_info->name);
    } else {
      /* No. */
      if_string = g_strdup(if_name);
    }
  }

  return if_string;
}


GList *
build_capture_combo_list(GList *if_list, gboolean do_hide)
{
  GList *combo_list;
  GList *if_entry;
  if_info_t *if_info;
  char *if_string;
  gchar *descr;

  combo_list = NULL;
  if (if_list != NULL) {
    /* Scan through the list and build a list of strings to display. */
    for (if_entry = if_list; if_entry != NULL;
         if_entry = g_list_next(if_entry)) {
      if_info = (if_info_t *)if_entry->data;

      /* Is this interface hidden and, if so, should we include it
         anyway? */
      if (!prefs_is_capture_device_hidden(if_info->name) || !do_hide) {
        /* It's not hidden, or it is but we should include it in the list. */

        /* Do we have a user-supplied description? */
        descr = capture_dev_user_descr_find(if_info->name);
        if (descr != NULL) {
          /* Yes, we have a user-supplied description; use it. */
          if_string = g_strdup_printf("%s: %s", descr, if_info->name);
          g_free(descr);
        } else {
          /* No, we don't have a user-supplied description; did we get
             one from the OS or libpcap? */
          if (if_info->vendor_description != NULL) {
            /* Yes - use it. */
            if_string = g_strdup_printf("%s: %s",
                                        if_info->vendor_description,
                                        if_info->name);
          } else {
            /* No. */
            if_string = g_strdup(if_info->name);
          }
        }
        combo_list = g_list_append(combo_list, if_string);
      }
    }/*for*/
  }
  return combo_list;
}

static void
free_if_string(gpointer data, gpointer user_data _U_)
{
  g_free(data);
}

void
free_capture_combo_list(GList *combo_list)
{
  if (combo_list != NULL) {
    g_list_foreach(combo_list, free_if_string, NULL);
    g_list_free(combo_list);
  }
}

/*
 * Given text that contains an interface name possibly prefixed by an
 * interface description, extract the interface name.
 */
const char *
get_if_name(const char *if_text)
{
  const char *if_name;

#ifdef _WIN32
  /*
   * We cannot assume that the interface name doesn't contain a space;
   * some names on Windows OT do.
   *
   * We also can't assume it begins with "\Device\", either, as, on
   * Windows OT, WinPcap doesn't put "\Device\" in front of the name.
   *
   * As I remember, we can't assume that the interface description
   * doesn't contain a colon, either; I think some do.
   *
   * We can probably assume that the interface *name* doesn't contain
   * a colon, however; if any interface name does contain a colon on
   * Windows, it'll be time to just get rid of the damn interface
   * descriptions in the drop-down list, have just the names in the
   * drop-down list, and have a "Browse..." button to browse for interfaces,
   * with names, descriptions, IP addresses, blah blah blah available when
   * possible.
   *
   * So we search backwards for a colon.  If we don't find it, just
   * return the entire string; otherwise, skip the colon and any blanks
   * after it, and return that string.
   */
   if_name = if_text + strlen(if_text);
   for (;;) {
     if (if_name == if_text) {
       /* We're at the beginning of the string; return it. */
       break;
     }
     if_name--;
     if (*if_name == ':') {
       /*
        * We've found a colon.
        * Unfortunately, a colon is used in the string "rpcap://",
        * which is used in case of a remote capture.
        * So we'll check to make sure the colon isn't followed by "//";
        * it'll be followed by a blank if it separates the description
        * and the interface name.  (We don't wire in "rpcap", in case we
        * support other protocols in the same syntax.)
        * Unfortunately, another colon can be used in "rpcap://host:port/"
        * before port. Check if colon is followed by digit.
        */
       if ((strncmp(if_name, "://", 3) != 0) && !g_ascii_isdigit(if_name[1])) {
         /*
          * OK, we've found a colon followed neither by "//" nor by digit.
          * Skip blanks following it.
          */
         if_name++;
         while (*if_name == ' ')
           if_name++;
         break;
       }
     }
     /* Keep looking for a colon not followed by "//". */
   }
#else
  /*
   * There's a space between the interface description and name, and
   * the interface name shouldn't have a space in it (it doesn't, on
   * UNIX systems); look backwards in the string for a space.
   *
   * (An interface name might, however, contain a colon in it, which
   * is why we don't use the colon search on UNIX.)
   */
  if_name = strrchr(if_text, ' ');
  if (if_name == NULL) {
    if_name = if_text;
  } else {
    if_name++;
  }
#endif
  return if_name;
}

/*  Return interface_opts->descr (after setting it if it is not set)
 *  This is necessary because capture_opts.c can't set descr (at least
 *  not without adding significant dependencies there).
 */
const char *
get_iface_description_for_interface(capture_options *capture_opts, guint i)
{
  interface_options interface_opts;

  if (i < capture_opts->ifaces->len) {
    interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
    if (!interface_opts.descr && interface_opts.name) {
      interface_opts.descr = get_interface_descriptive_name(interface_opts.name);
      capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, i);
      g_array_insert_val(capture_opts->ifaces, i, interface_opts);
    }
    return (interface_opts.descr);
  } else {
    return (NULL);
  }
}

/*
 * Set the active DLT for a device appropriately.
 */
void
set_active_dlt(interface_t *device, int global_default_dlt)
{
  GList    *list;
  gboolean  found_active_dlt;
  link_row *link;

  /*
   * If there's a preference for the link-layer header type for
   * this interface, use it.  If not, use the all-interface
   * default; if that's not set on the command line, that will
   * be -1, meaning "use per-interface defaults", otherwise
   * we'll fail if it's not one of the types the interface
   * supports.
   */
  if ((device->active_dlt = capture_dev_user_linktype_find(device->name)) == -1) {
    device->active_dlt = global_default_dlt;
  }

  /*
   * Is that one of the supported link-layer header types?
   * If not, set it to -1, so we'll fall back on the first supported
   * link-layer header type.
   */
  found_active_dlt = FALSE;
  for (list = device->links; list != NULL; list = g_list_next(list)) {
    link = (link_row *)(list->data);
    if (link->dlt != -1 && link->dlt == device->active_dlt) {
      found_active_dlt = TRUE;
      break;
    }
  }
  if (!found_active_dlt) {
    device->active_dlt = -1;
  }
  if (device->active_dlt == -1) {
    /* Fall back on the first supported DLT, if we have one. */
    for (list = device->links; list != NULL; list = g_list_next(list)) {
      link = (link_row *)(list->data);
      if (link->dlt != -1) {
        device->active_dlt = link->dlt;
        break;
      }
    }
  }
}

GString *
get_iface_list_string(capture_options *capture_opts, guint32 style)
{
  GString *iface_list_string = g_string_new("");
  guint i;

  /*
   * If we have a descriptive name for the interface, show that,
   * rather than its raw name.  On NT 5.x (2K/XP/Server2K3), the
   * interface name is something like "\Device\NPF_{242423..."
   * which is pretty useless to the normal user.  On other platforms,
   * it might be less cryptic, but if a more descriptive name is
   * available, we should still use that.
   */
#ifdef _WIN32
  if (capture_opts->ifaces->len < 2) {
#else
  if (capture_opts->ifaces->len < 4) {
#endif
    for (i = 0; i < capture_opts->ifaces->len; i++) {
      if (i > 0) {
        if (capture_opts->ifaces->len > 2) {
          g_string_append_printf(iface_list_string, ",");
        }
        g_string_append_printf(iface_list_string, " ");
        if (i == capture_opts->ifaces->len - 1) {
          g_string_append_printf(iface_list_string, "and ");
        }
      }
      if (style & IFLIST_QUOTE_IF_DESCRIPTION)
        g_string_append_printf(iface_list_string, "'");
      g_string_append_printf(iface_list_string, "%s", get_iface_description_for_interface(capture_opts, i));
      if (style & IFLIST_QUOTE_IF_DESCRIPTION)
        g_string_append_printf(iface_list_string, "'");
      if (style & IFLIST_SHOW_FILTER) {
        interface_options interface_opts;

        interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
        if (interface_opts.cfilter != NULL &&
            strlen(interface_opts.cfilter) > 0) {
          g_string_append_printf(iface_list_string, " (%s)", interface_opts.cfilter);
        }
      }
    }
  } else {
    g_string_append_printf(iface_list_string, "%u interfaces", capture_opts->ifaces->len);
  }
  return iface_list_string;
}

#endif /* HAVE_LIBPCAP */
