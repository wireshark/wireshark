/* capture.h
 * Definitions for packet capture windows
 *
 * $Id: capture.h,v 1.3 1998/09/29 21:39:29 hannes Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef __CAPTURE_H__
#define __CAPTURE_H__

typedef struct _loop_data {
  gint           go;
  gint           count;
  gint           max;
  gint           tcp;
  gint           udp;
  gint           ospf;
  gint           other;
  pcap_dumper_t *pdh;
} loop_data;

GList *get_interface_list();
void   capture_prep_cb(GtkWidget *, gpointer);
void   capture_prep_file_cb(GtkWidget *, gpointer);
void   cap_prep_fs_ok_cb(GtkWidget *, gpointer);
void   cap_prep_fs_cancel_cb(GtkWidget *, gpointer);
void   capture_prep_ok_cb(GtkWidget *, gpointer);
void   capture_prep_close_cb(GtkWidget *, gpointer);
void   capture(gint);
float  pct(gint, gint);
void   capture_stop_cb(GtkWidget *, gpointer);
void   capture_pcap_cb(u_char *, const struct pcap_pkthdr *, const u_char *);

#endif /* capture.h */
