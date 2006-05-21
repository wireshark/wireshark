/* capture_ui_utils.c
 * Utilities for capture user interfaces
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_LIBPCAP

#include <string.h>
#include <glib.h>

#include <epan/prefs.h>
#include "capture-pcap-util.h"
#include "capture_ui_utils.h"

/*
 * Find user-specified capture device description that matches interface
 * name, if any.
 */
static char *
capture_dev_user_descr_find(const gchar *if_name)
{
	char	*p;
	char	*p2 = NULL;
	char	*descr = NULL;
	int	lp = 0;
	int	ct = 0;

	if (prefs.capture_devices_descr == NULL) {
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
		descr = g_malloc(p - p2 + 1);
		memcpy(descr, p2, p - p2);
		descr[p - p2] = '\0';
		return descr;
	}
	else
		return NULL;
}

/*
 * Return as descriptive a name for an interface as we can get.
 * If the user has specified a comment, use that.  Otherwise,
 * if get_interface_list() supplies a description, use that,
 * otherwise use the interface name.
 */
char *
get_interface_descriptive_name(const char *if_name)
{
  char *descr;
  GList *if_list;
  GList *if_entry;
  if_info_t *if_info;
  int err;
  char err_buf[CAPTURE_PCAP_ERRBUF_SIZE];

  /* Do we have a user-supplied description? */
  descr = capture_dev_user_descr_find(if_name);
  if (descr != NULL) {
    /* Yes - make a copy of that. */
    descr = g_strdup(descr);
  } else {
    /* No, we don't have a user-supplied description; did we get
       one from the OS or libpcap? */
    descr = NULL;
    if_list = get_interface_list(&err, err_buf);
    if (if_list != NULL) {
      if_entry = if_list;
      do {
        if_info = if_entry->data;
        if (strcmp(if_info->name, if_name) == 0) {
          if (if_info->description != NULL) {
            /* Return a copy of that - when we free the interface
               list, that'll also free up the strings to which
               it refers. */
            descr = g_strdup(if_info->description);
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
        if_info = if_entry->data;

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
	  if (if_info && if_info->description != NULL) {
	    /* Yes - use it. */
	    if_string = g_strdup_printf("%s: %s", if_info->description,
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
      if_info = if_entry->data;

      /* Is this interface hidden and, if so, should we include it
         anyway? */
      if (prefs.capture_devices_hide == NULL ||
	  strstr(prefs.capture_devices_hide, if_info->name) == NULL ||
	  !do_hide) {
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
	  if (if_info->description != NULL) {
	    /* Yes - use it. */
	    if_string = g_strdup_printf("%s: %s", if_info->description,
					if_info->name);
	  } else {
	    /* No. */
	    if_string = g_strdup(if_info->name);
	  }
	}
	combo_list = g_list_append(combo_list, if_string);
      }
    }
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
        */
       if (strncmp(if_name, "://", 3) != 0) {
         /*
          * OK, we've found a colon not followed by "//".  Skip blanks
          * following it.
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

#endif /* HAVE_LIBPCAP */
