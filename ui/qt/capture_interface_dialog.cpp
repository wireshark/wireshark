/* capture_interface_dialog.cpp
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

#include "capture_interface_dialog.h"

#ifdef HAVE_PCAP_REMOTE

#include "qt_ui_utils.h"

#include "gtk/recent.h"

#include <epan/prefs.h>

#include <QHash>

QHash<QString, remote_host_t *> remote_host_list;

// xxx - copied from capture_dlg.c
void
capture_remote_combo_recent_write_all(FILE *rf)
{
    remote_host_t *rh;
    foreach (rh, remote_host_list) {
        fprintf (rf, RECENT_KEY_REMOTE_HOST ": %s,%s,%d\n", rh->remote_host, rh->remote_port, rh->auth_type);
    }
}

gboolean
capture_remote_combo_add_recent(gchar *s)
{
  GList *vals = prefs_get_string_list (s);
  GList *valp = vals;
  struct remote_host_t *rh;
  gint auth_type;
  char *p;

  if (valp == NULL)
    return FALSE;

  rh = (remote_host_t *) g_malloc (sizeof (remote_host_t));

  /* First value is the host */
  rh->remote_host = g_strdup ((const gchar *) valp->data);
  if (strlen(rh->remote_host) == 0)
    /* Empty remote host */
    return FALSE;
  rh->auth_type = CAPTURE_AUTH_NULL;
  valp = valp->next;

  if (valp) {
    /* Found value 2, this is the port number */
    rh->remote_port = g_strdup ((const gchar *) valp->data);
    valp = valp->next;
  } else {
    /* Did not find a port number */
    rh->remote_port = g_strdup ("");
  }

  if (valp) {
    /* Found value 3, this is the authentication type */
    auth_type = strtol((const gchar *) valp->data, &p, 0);
    if (p != valp->data && *p == '\0') {
      rh->auth_type = auth_type;
    }
  }

  /* Do not store username and password */
  rh->auth_username = g_strdup ("");
  rh->auth_password = g_strdup ("");

  prefs_clear_string_list(vals);

  remote_host_list.insert(QString::fromUtf8(rh->remote_host), rh);

  return TRUE;
}
#endif /* HAVE_PCAP_REMOTE */

CaptureInterfaceDialog::CaptureInterfaceDialog(QWidget *parent) :
    QDialog(parent)
{
}
