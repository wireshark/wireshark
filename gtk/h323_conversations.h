/* h323_conversations.h
 * H323 conversations summary addition for ethereal
 *
 * $Id$
 *
 * Copyright 2004, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
 *
 * based on rtp_stream.h
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef H323_STREAM_H_INCLUDED
#define H323_STREAM_H_INCLUDED

#include <glib.h>
#include <stdio.h>

/****************************************************************************/
/* defines h323 state */
typedef enum _h323_call_state {
        CALL_SETUP,
        IN_CALL,
        COMPLETED,
        REJECTED,
	UNKNOWN
} h323_call_state;

/* defines an h323 conversation */
typedef struct _h323_conversations_info {
	h323_call_state call_state;
	guint32 src_addr;
	guint16 src_port;
	guint32 dest_addr;
	guint16 dest_port;
	guint8  pt;
	guint32 npackets;
	gboolean faststart;
	guint32 transport;
	/* if there are also h245 messages */
	gboolean is_h245;
	guint32 h245packets;
	guint32 h245address;
	guint16 h245port;

	guint32 first_frame_num; /* frame number of first frame */

} h323_conversations_info_t;

extern char *transport_prot_name[256];

/* structure that holds the information about all detected conversationss */
/* struct holding all information of the tap */
typedef struct _h323conversations_tapinfo {
	int     nconversationss;       /* number of conversationss in the list */
	GList*  strinfo_list;   /* list with all conversationss */
	int     npackets;       /* total number of h323 packets of all conversationss */
	h323_conversations_info_t* filter_conversations_fwd;  /* used as filter in some tap modes */
	guint32 launch_count;   /* number of times the tap has been run */
	int setup_packets;
	int completed_calls;
	int rejected_calls;
} h323conversations_tapinfo_t;


/****************************************************************************/
/* INTERFACE */

/*
* Registers the h323_conversationss tap listener (if not already done).
* From that point on, the H323 conversationss list will be updated with every redissection.
* This function is also the entry point for the initialization routine of the tap system.
* So whenever h323_conversations.c is added to the list of ETHEREAL_TAP_SRCs, the tap will be registered on startup.
* If not, it will be registered on demand by the h323_conversationss and h323_analysis functions that need it.
*/
void h225conversations_init_tap(void);
void h245conversations_init_tap(void);

/*
* Removes the h323_conversationss tap listener (if not already done)
* From that point on, the H323 conversationss list won't be updated any more.
*/
void remove_tap_listener_h225_conversations(void);
void remove_tap_listener_h245_conversations(void);

/*
* Retrieves a constant reference to the unique info structure of the h323_conversationss tap listener.
* The user should not modify the data pointed to.
*/
const h323conversations_tapinfo_t* h323conversations_get_info(void);

/*
* Cleans up memory of h323 conversationss tap.
*/
void h225conversations_reset(h323conversations_tapinfo_t *tapinfo);
void h245conversations_reset(h323conversations_tapinfo_t *tapinfo);

/*
* Marks all packets belonging to conversations.
* (can be NULL)
* (redissects all packets)
*/
void h323conversations_mark(h323_conversations_info_t* conversations_fwd);


#endif /*H323_STREAM_H_INCLUDED*/
