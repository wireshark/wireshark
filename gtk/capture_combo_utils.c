/* capture_combo_utils.c
 * Utilities for combo box of interface names
 *
 * $Id: capture_combo_utils.c,v 1.1 2003/09/10 05:35:25 guy Exp $
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

#ifdef HAVE_LIBPCAP

#include <string.h>
#include <gtk/gtk.h>

#include <pcap.h>

#include "prefs.h"
#include "pcap-util.h"
#include "capture_combo_utils.h"

/*
 * Find capture device description that matches interface name.
 */
static char *
capture_dev_descr_find(const gchar *if_name)
{
	char	*p;
	char	*p2 = NULL;
	char	*descr = NULL;
	int		lp = 0;
	int		ct = 0;
	
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
    for (if_entry = g_list_first(if_list); if_entry != NULL;
	if_entry = g_list_next(if_entry)) {
      if_info = if_entry->data;

      /* Is this interface hidden and, if so, should we include it
         anyway? */
      if (prefs.capture_devices_hide == NULL ||
	  strstr(prefs.capture_devices_hide, if_info->name) == NULL ||
	  !do_hide) {
	/* It's not hidden, or it is but we should include it in the list. */

	/* Do we have a user-supplied description? */
	descr = capture_dev_descr_find(if_info->name);
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

#endif /* HAVE_LIBPCAP */
