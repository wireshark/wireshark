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
#include <glib.h>

#include "epan/prefs.h"
#include "epan/ex-opt.h"
#include "caputils/capture_ifinfo.h"
#include "ui/capture_ui_utils.h"
#include "ui/capture_globals.h"
#include "wiretap/wtap.h"
#include "epan/to_str.h"

/*
 * In a list of interface information, in the form of a comma-separated
 * list of {name}({property}) items, find the entry for a particular
 * interface, and return a pointer a g_malloced string containing
 * the property.
 */
static char *
capture_dev_get_if_property(const gchar *pref, const gchar *if_name)
{
  gchar **if_tokens;
  gchar *property = NULL;
  int i;

  if (if_name == NULL || strlen(if_name) < 1) {
    return NULL;
  }

  if (pref == NULL || strlen(pref) < 1) {
    /* There is no interface information list. */
    return NULL;
  }

  /*
   * Split the list into a sequence of items.
   *
   * XXX - this relies on the items not themselves containing commas.
   */
  if_tokens = g_strsplit(pref, ",", -1);
  for (i = 0; if_tokens[i] != NULL; i++) {
    gchar *opening_parenp, *closing_parenp;

    /*
     * Separate this item into name and property.
     * The first opening parenthesis and the last closing parenthesis
     * surround the property.  Any other parentheses are part of
     * the property.
     */
    opening_parenp = strchr(if_tokens[i], '(');
    if (opening_parenp == NULL) {
      /* No opening parenthesis. Give up. */
      break;
    }
    closing_parenp = strrchr(if_tokens[i], ')');
    if (closing_parenp == NULL || closing_parenp <= opening_parenp) {
      /* No closing parenthesis or invalid input. Give up. */
      break;
    }
    *opening_parenp = '\0'; /* Split {name} from what follows */
    *closing_parenp = '\0'; /* Terminate {property} */
    if (strcmp(if_tokens[i], if_name) == 0) {
      if (strlen(opening_parenp + 1) > 0) {
        property = g_strdup(opening_parenp + 1);
      }
      break;
    }
  }
  g_strfreev(if_tokens);

  return property;
}

/*
 * Find a property that should be an integral value, and return the
 * value or, if it's not found or not a valid integral value, -1.
 */
static gint
capture_dev_get_if_int_property(const gchar *pref, const gchar *if_name)
{
  gchar *property_string, *next;
  long property;

  property_string = capture_dev_get_if_property(pref, if_name);
  if (property_string == NULL) {
    /* No property found for this interface. */
    return -1;
  }
  property = strtol(property_string, &next, 10);
  if (next == property_string || *next != '\0' || property < 0) {
    /* Syntax error */
    g_free(property_string);
    return -1;
  }
  if (property > G_MAXINT) {
    /* Value doesn't fit in a gint */
    g_free(property_string);
    return -1;
  }

  g_free(property_string);
  return (gint)property;
}

/*
 * Find user-specified capture device description that matches interface
 * name, if any.
 */
char *
capture_dev_user_descr_find(const gchar *if_name)
{
  return capture_dev_get_if_property(prefs.capture_devices_descr, if_name);
}

gint
capture_dev_user_linktype_find(const gchar *if_name)
{
  return capture_dev_get_if_int_property(prefs.capture_devices_linktypes, if_name);
}

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
gint
capture_dev_user_buffersize_find(const gchar *if_name)
{
  return capture_dev_get_if_int_property(prefs.capture_devices_buffersize, if_name);
}
#endif

gboolean
capture_dev_user_snaplen_find(const gchar *if_name, gboolean *hassnap, int *snaplen)
{
  gboolean found = FALSE;
  gchar **if_tokens;
  int i;

  if (if_name == NULL || strlen(if_name) < 1) {
    return FALSE;
  }

  if ((prefs.capture_devices_snaplen == NULL) ||
      (*prefs.capture_devices_snaplen == '\0')) {
    /* There are no snap lengths defined */
    return FALSE;
  }

  /*
   * Split the list into a sequence of items.
   *
   * XXX - this relies on the items not themselves containing commas.
   */
  if_tokens = g_strsplit(prefs.capture_devices_snaplen, ",", -1);
  for (i = 0; if_tokens[i] != NULL; i++) {
    gchar *colonp, *next;
    long value;

    /*
     * This one's a bit ugly.
     * The syntax of the item is {name}:{hassnap}({snaplen}),
     * where {hassnap} is 0 if the interface shouldn't have a snapshot
     * length and 1 if it should, and {snaplen} is the maximum snapshot
     * length if {hassnap} is 0 and the specified snapshot length if
     * {hassnap} is 1.
     *
     * Sadly, : was a bad choice of separator, given that, on some OSes,
     * an interface can have a colon in its name.
     *
     * So we look for the *last* colon in the string.
     */
    colonp = strrchr(if_tokens[i], ':');
    if (colonp == NULL) {
      /* No separating colon. Give up. */
      break;
    }
    *colonp = '\0'; /* Split {name} from what follows */
    if (strcmp(if_tokens[i], if_name) == 0) {
      /* OK, this matches. */
      if (*(colonp + 1) == '0') {
        /* {hassnap} is false, so just set the snaplen to WTAP_MAX_PACKET_SIZE. */
        found = TRUE;
        *hassnap = FALSE;
        *snaplen = WTAP_MAX_PACKET_SIZE;
      } else if (*(colonp + 1) == '1') {
        /* {hassnap} is true, so extract {snaplen} */
        if (*(colonp + 2) != '(') {
          /* Not followed by a parenthesis. Give up. */
          break;
        }
        value = strtol(colonp + 3, &next, 10);
        if (next == colonp + 3 || *next != ')' || value < 0) {
          /* Syntax error. Give up. */
          break;
        }
        if (value > G_MAXINT) {
          /* Value doesn't fit in a gint. Give up. */
          break;
        }
        found = TRUE;
        *hassnap = TRUE;
        *snaplen = (gint)value;
      } else {
        /* Bad {hassnap}. Give up. */
        break;
      }
      break;
    }
  }
  g_strfreev(if_tokens);

  return found;
}

gboolean
capture_dev_user_pmode_find(const gchar *if_name, gboolean *pmode)
{
  int value;

  value = capture_dev_get_if_int_property(prefs.capture_devices_pmode, if_name);
  if (value == -1) {
    /* Not found or bad. */
    return FALSE;
  }
  *pmode = (value != 0);
  return TRUE;
}

gchar*
capture_dev_user_cfilter_find(const gchar *if_name)
{
  return capture_dev_get_if_property(prefs.capture_devices_filter, if_name);
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
  if (descr == NULL) {
    /* No; try to construct a descriptive name. */
    if (strcmp(if_name, "-") == 0) {
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
  }

  return descr;
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

gchar *
get_iface_display_name(const gchar *description, const if_info_t *if_info)
{
  if (description && description[0]) {
    /* We have a user-supplied description. */
#ifdef _WIN32
    gchar *if_string = if_info->friendly_name ? if_info->friendly_name : if_info->name;
    return g_strdup_printf("%s: %s", description, if_string);
#else
    return g_strdup_printf("%s: %s", description, if_info->name);
#endif
  }

  if (if_info->friendly_name) {
    /* We have a friendly name from the OS. */
#ifdef _WIN32
    /*
     * On Windows, if we have a friendly name, just show it,
     * don't show the name, as that's a string made out of
     * the device GUID, and not at all friendly.
     */
    return g_strdup_printf("%s", if_info->friendly_name);
#else
    /*
     * On UN*X, if we have a friendly name, show it along
     * with the interface name; the interface name is short
     * and somewhat friendly, and many UN*X users are used
     * to interface names, so we should show it.
     */
    return g_strdup_printf("%s: %s", if_info->friendly_name, if_info->name);
#endif
  }

  if (if_info->vendor_description) {
    /* We have a device description from libpcap. */
    return g_strdup_printf("%s: %s", if_info->vendor_description, if_info->name);
  }

  /* No additional descriptions found. */
  return g_strdup(if_info->name);
}

#endif /* HAVE_LIBPCAP */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
