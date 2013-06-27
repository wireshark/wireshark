/* echld-test.c
 *  basic test framework for echld
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

#include "config.h"

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <sys/time.h>
#include <sys/uio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <glib.h>
#include <glib/gprintf.h>

#include "echld/echld.h"
#include "echld/echld-util.h"

#include "epan/epan.h"
#include "wsutil/str_util.h"

int pings = 0;
int errors = 0;

void ping_cb(long usec, void* data _U_) {

	fprintf(stderr, "Ping ping=%d usec=%d\n", pings ,(int)usec );

	if (usec >= 0) {
		pings++;
	} else {
		errors++;
	}
}


int main(int argc, char** argv) {
	struct timeval tv;
	int tot_cycles = 0;
	int max_cycles = 30;
	int npings;
	tv.tv_sec = 0;
	tv.tv_usec = 250000;

	echld_set_parent_dbg_level(5);

	switch(argc) {
		case 1:
			npings = 3;
			break;
		case 2:
			npings = (int)atoi(argv[1]);
			break;
		default:
			fprintf(stderr, "usage: %s [num pings, default=10]\n",argv[0]);
			return 1;
	}

	max_cycles = npings*4;

	echld_initialize(ECHLD_ENCODING_JSON);


	do {
		if ( (tot_cycles > npings) && npings && npings-- ) echld_ping(0,ping_cb,NULL);
		tot_cycles++;
		echld_wait(&tv);
	} while( (pings < npings) || (tot_cycles < max_cycles));

	fprintf(stderr, "Done: pings=%d errors=%d tot_cycles=%d\n", pings, errors ,tot_cycles );

	echld_terminate();
	return 0;
}


