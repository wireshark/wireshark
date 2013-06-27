/* echld-util.c
 *  utility for echld
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copyright (c) 2013 by Luis Ontanon <luis@ontanon.org>
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

#include "../config.h"

#include "echld-int.h"
#include "echld-util.h"

struct _ping {
	struct timeval tv;
	echld_ping_cb_t cb;
	void* cb_data;
};

static long timevaldiff(struct timeval *starttime, struct timeval *finishtime) {
  long msec;
  msec=(finishtime->tv_sec-starttime->tv_sec)*1000;
  msec+=(finishtime->tv_usec-starttime->tv_usec)/1000;
  return msec;
}

static gboolean pong(echld_msg_type_t type, GByteArray* ba _U_, void* data) {
	struct _ping* p = (struct _ping*)data;
	struct timeval t;
	long ret = -1;
	gettimeofday(&t,NULL);

	
	switch (type) {
		case ECHLD_PONG:
			ret = timevaldiff(&(p->tv),&t);
			break;
		default:
			ret = -1;
			break;
	}

	if (p->cb) p->cb(ret, p->cb_data);

	g_free(p);

	return TRUE;
}


extern echld_state_t echld_ping(int chld_id, echld_ping_cb_t pcb, void* cb_data) {
	struct _ping* p = g_new0(struct _ping,1);

	p->cb = pcb;
	p->cb_data = cb_data;
	gettimeofday(&(p->tv),NULL);

	return echld_reqh(chld_id, ECHLD_PING, 0, NULL, pong, p);
}


