/*
 * h225-persistentdata.c
 * Source for lists and hash tables used in ethereal's h225 dissector
 * for calculation of delays in h225-calls
 *
 * Copyright 2003 Lars Roland
 *
 * $Id$
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/emem.h>

#include <stdio.h>
#include <string.h>

#include "h225-persistentdata.h"

/* Global Memory Chunks for lists and Global hash tables*/

static GHashTable *ras_calls[7] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};

/*
 * Functions needed for Ras-Hash-Table
 */

/* compare 2 keys */
static gint h225ras_call_equal(gconstpointer k1, gconstpointer k2)
{
	const h225ras_call_info_key* key1 = (const h225ras_call_info_key*) k1;
	const h225ras_call_info_key* key2 = (const h225ras_call_info_key*) k2;

	return (key1->reqSeqNum == key2->reqSeqNum &&
	    key1->conversation == key2->conversation);
}

/* calculate a hash key */
static guint h225ras_call_hash(gconstpointer k)
{
	const h225ras_call_info_key* key = (const h225ras_call_info_key*) k;

	return key->reqSeqNum + GPOINTER_TO_UINT(key->conversation);
}


h225ras_call_t * find_h225ras_call(h225ras_call_info_key *h225ras_call_key ,int category)
{
 	h225ras_call_t *h225ras_call = NULL;
	h225ras_call = (h225ras_call_t *)g_hash_table_lookup(ras_calls[category], h225ras_call_key);

	return h225ras_call;
}

h225ras_call_t * new_h225ras_call(h225ras_call_info_key *h225ras_call_key, packet_info *pinfo, guint8 *guid, int category)
{
	h225ras_call_info_key *new_h225ras_call_key;
 	h225ras_call_t *h225ras_call = NULL;


	/* Prepare the value data.
	   "req_num" and "rsp_num" are frame numbers;
	   frame numbers are 1-origin, so we use 0
	   to mean "we don't yet know in which frame
	   the reply for this call appears". */
	new_h225ras_call_key = se_alloc(sizeof(h225ras_call_info_key));
	new_h225ras_call_key->reqSeqNum = h225ras_call_key->reqSeqNum;
	new_h225ras_call_key->conversation = h225ras_call_key->conversation;
	h225ras_call = se_alloc(sizeof(h225ras_call_t));
	h225ras_call->req_num = pinfo->fd->num;
	h225ras_call->rsp_num = 0;
	h225ras_call->requestSeqNum = h225ras_call_key->reqSeqNum;
	h225ras_call->responded = FALSE;
	h225ras_call->next_call = NULL;
	h225ras_call->req_time=pinfo->fd->abs_ts;
	memcpy(h225ras_call->guid, guid,16);
	/* store it */
	g_hash_table_insert(ras_calls[category], new_h225ras_call_key, h225ras_call);

	return h225ras_call;
}

h225ras_call_t * append_h225ras_call(h225ras_call_t *prev_call, packet_info *pinfo, guint8 *guid, int category _U_)
{
	h225ras_call_t *h225ras_call = NULL;

	/* Prepare the value data.
	   "req_num" and "rsp_num" are frame numbers;
	   frame numbers are 1-origin, so we use 0
	   to mean "we don't yet know in which frame
	   the reply for this call appears". */
	h225ras_call = se_alloc(sizeof(h225ras_call_t));
	h225ras_call->req_num = pinfo->fd->num;
	h225ras_call->rsp_num = 0;
	h225ras_call->requestSeqNum = prev_call->requestSeqNum;
	h225ras_call->responded = FALSE;
	h225ras_call->next_call = NULL;
	h225ras_call->req_time=pinfo->fd->abs_ts;
	memcpy(h225ras_call->guid, guid,16);

	prev_call->next_call = h225ras_call;
	return h225ras_call;
}


/* Init routine for hash tables and delay calculation
   This routine will be called by Ethereal, before it
   is (re-)dissecting a trace file from beginning.
   We need to discard and init any state we've saved */

void
h225_init_routine(void)
{
	int i;

	/* free hash-tables for RAS SRT */
	for(i=0;i<7;i++) {
		if (ras_calls[i] != NULL) {
			g_hash_table_destroy(ras_calls[i]);
			ras_calls[i] = NULL;
		}
	}

	/* create new hash-tables for RAS SRT */

	for(i=0;i<7;i++) {
		ras_calls[i] = g_hash_table_new(h225ras_call_hash, h225ras_call_equal);
	}

}
