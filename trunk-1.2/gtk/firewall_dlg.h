/* firewall_dlg.h
 * Produce ACL rules for various products from a packet.
 *
 * $Id:$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef FIREWALL_DLG_H_INCLUDED
#define FIREWALL_DLG_H_INCLUDED

/* Generate ACL / firewall rules from different fields in the
   selected packet. */
void firewall_rule_cb(GtkWidget * w, gpointer data _U_);

#endif /* FIREWALL_DLG_H_INCLUDED */
