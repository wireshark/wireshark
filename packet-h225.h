/* packet-h225.h
 * Routines for H.225 packet dissection
 * 2003  Tomas Kukosa
 *
 * $Id: packet-h225.h,v 1.5 2003/11/16 23:11:18 sahlberg Exp $
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

#ifndef __H225_H__
#define __H225_H__

extern int dissect_h225_NonStandardParameter(tvbuff_t*, int, packet_info*, proto_tree*, int);

extern int dissect_h225_AliasAddress(tvbuff_t*, int, packet_info*, proto_tree*);

typedef enum _h225_msg_type {
	H225_RAS,
	H225_CS,
	H225_OTHERS
} h225_msg_type;

typedef struct _h225_packet_info {
	h225_msg_type msg_type;		/* ras or cs message */
	gint msg_tag;			/* message tag*/
	gint reason;			/* reason tag, if available */
	guint requestSeqNum;		/* request sequence number of ras-message, if available */
	guint8 guid[16];		/* globally unique call id */
	gboolean is_duplicate;		/* true, if this is a repeated message */
	gboolean request_available;	/* true, if response matches to a request */
	nstime_t delta_time; 		/* this is the RAS response time delay */
} h225_packet_info;

#endif  /* __H225_H__ */
