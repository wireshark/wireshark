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
#include <capchild/capture_ifinfo.h>
#include "capture_ui_utils.h"
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
  gchar *p, *next, *tmpname;
  long linktype;

  if ((prefs.capture_devices_linktypes == NULL) ||
      (*prefs.capture_devices_linktypes == '\0')) {
    /* There are no link-layer header types */
    return -1;
  }
  tmpname = g_strdup_printf(",%s(", if_name);
  if ((p = strstr(prefs.capture_devices_linktypes, tmpname)) == NULL) {
    /* There are, but there isn't one for this interface. */
    return -1;
  }

  p += strlen(if_name) + 2;
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
  gchar *p, *next, *tmpname;
  gint buffersize;

  if ((prefs.capture_devices_buffersize == NULL) ||
      (*prefs.capture_devices_buffersize == '\0')) {
    /* There are no buffersizes defined */
    return -1;
  }
  tmpname = g_strdup_printf(",%s(", if_name);
  if ((p = strstr(prefs.capture_devices_buffersize, tmpname)) == NULL) {
    /* There are, but there isn't one for this interface. */
    return -1;
  }

  p += strlen(if_name) + 2;
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
  gchar *p, *next, *tmpname;
  gint snaplen;

  if ((prefs.capture_devices_snaplen == NULL) ||
      (*prefs.capture_devices_snaplen == '\0')) {
    /* There is no snap length defined */
    return -1;
  }
  tmpname = g_strdup_printf(",%s:", if_name);
  if ((p = strstr(prefs.capture_devices_snaplen, tmpname)) == NULL) {
    /* There are, but there isn't one for this interface. */
    return -1;
  }

  p += strlen(if_name) + 4;
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
  gchar *p, *next, *tmpname;
  gboolean hassnap;

  if ((prefs.capture_devices_snaplen == NULL) ||
      (*prefs.capture_devices_snaplen == '\0')) {
    /* There is no snap length defined */
    return -1;
  }
  tmpname = g_strdup_printf(",%s:", if_name);
  if ((p = strstr(prefs.capture_devices_snaplen, tmpname)) == NULL) {
    /* There are, but there isn't one for this interface. */
    return -1;
  }

  p += strlen(if_name) + 2;
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
  gchar *p, *next, *tmpname;
  gboolean pmode;

  if ((prefs.capture_devices_pmode == NULL) ||
      (*prefs.capture_devices_pmode == '\0')) {
    /* There is no promiscuous mode defined */
    return -1;
  }
  tmpname = g_strdup_printf(",%s(", if_name);
  if ((p = strstr(prefs.capture_devices_pmode, tmpname)) == NULL) {
    /* There are, but there isn't one for this interface. */
    return -1;
  }

  p += strlen(if_name) + 2;
  pmode = (gboolean)strtol(p, &next, 10);
  if (next == p || *next != ')') {
    /* Syntax error */
    return -1;
  }
  return (gboolean)pmode;
}

gchar*
capture_dev_user_cfilter_find(const gchar *if_name)
{
  gchar *p, q[MAX_VAL_LEN], *tmpname;
  int i = 0;

  if ((prefs.capture_devices_filter == NULL) ||
      (*prefs.capture_devices_filter == '\0')) {
    /* There is no capture filter defined */
    return NULL;
  }
  tmpname = g_strdup_printf(",%s(", if_name);
  if ((p = strstr(prefs.capture_devices_filter, tmpname)) == NULL) {
    /* There are, but there isn't one for this interface. */
    return NULL;
  }

  p += strlen(if_name) + 2;
  while (p[i+1] != ',' && p[i+1] != '\0') {
    q[i] = p[i];
    i++;
  }
  q[i] = '\0';
  return g_strdup(q);
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
       if ((strncmp(if_name, "://", 3) != 0) && !isdigit(if_name[1])) {
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

#endif /* HAVE_LIBPCAP */
