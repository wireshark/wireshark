/* tap-rtp-common.h
 * MEGACO statistics handler functions used by tshark and wireshark
 *
 * $Id$
 *
 * Copyright 2008, Ericsson AB
 * By Balint Reczey <balint.reczey@ericsson.com>
 *
 * most functions are copied from ui/gtk/rtp_stream.c and ui/gtk/rtp_analysis.c
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef TAP_MEGACO_COMMON_H
#define TAP_MEGACO_COMMON_H

#define NUM_TIMESTATS 12

#define GCP_CMD_REPLY_CASE \
        case GCP_CMD_ADD_REPLY: \
        case GCP_CMD_MOVE_REPLY: \
        case GCP_CMD_MOD_REPLY: \
        case GCP_CMD_SUB_REPLY: \
        case GCP_CMD_AUDITCAP_REPLY: \
        case GCP_CMD_AUDITVAL_REPLY: \
        case GCP_CMD_NOTIFY_REPLY: \
        case GCP_CMD_SVCCHG_REPLY: \
        case GCP_CMD_TOPOLOGY_REPLY: \
        case GCP_CMD_REPLY:

#define GCP_CMD_REQ_CASE \
        case GCP_CMD_ADD_REQ: \
        case GCP_CMD_MOVE_REQ: \
        case GCP_CMD_MOD_REQ: \
        case GCP_CMD_SUB_REQ: \
        case GCP_CMD_AUDITCAP_REQ: \
        case GCP_CMD_AUDITVAL_REQ: \
        case GCP_CMD_NOTIFY_REQ: \
        case GCP_CMD_SVCCHG_REQ: \
        case GCP_CMD_TOPOLOGY_REQ: \
        case GCP_CMD_CTX_ATTR_AUDIT_REQ: \
        case GCP_CMD_OTHER_REQ:

/* used to keep track of the statistics for an entire program interface */
typedef struct _megacostat_t {
	char *filter;
        timestat_t rtd[NUM_TIMESTATS];
	guint32 open_req_num;
	guint32 disc_rsp_num;
	guint32 req_dup_num;
	guint32 rsp_dup_num;
#ifdef __GTK_H__
	GtkWidget *win;
	GtkWidget *vbox;
	GtkWidget *scrolled_window;
	GtkTreeView *table;
#endif /*__GHTK_H__*/
} megacostat_t;

static const value_string megaco_message_type[] = {
  {  0,	"ADD "},
  {  1,	"MOVE"},
  {  2,	"MDFY"},
  {  3,	"SUBT"},
  {  4,	"AUCP"},
  {  5,	"AUVL"},
  {  6,	"NTFY"},
  {  7, "SVCC"},
  {  8, "TOPO"},
  {  9, "NONE"},
  {  10,"ALL "},
  {  0, NULL}
};

int megacostat_packet(void *pms, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pmi);

#endif /*TAP_MEGACO_COMMON_H*/
