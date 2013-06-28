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

int got_param = 0;

void param_cb(const char* param, const char* value, const char* error, void* data _U_) {
	if (error) {
		fprintf(stderr, "Param Set Error msg=%s\n", error );
		got_param = 0;
		return;
	}

	got_param = 1;
	fprintf(stderr, "Param: param='%s' val='%s'\n", param, value );
}


int main(int argc _U_, char** argv _U_) {
	struct timeval tv;
	int tot_cycles = 0;
	int max_cycles = 50;
	int child = -1;
	int keep_going = 1;

	tv.tv_sec = 0;
	tv.tv_usec = 250000;

	echld_set_parent_dbg_level(5);

	echld_initialize(ECHLD_ENCODING_JSON,argv[0],main);

	do {
		if ( tot_cycles == 2 ) echld_ping(0,ping_cb,NULL);

		if ( tot_cycles == 4 ) {
			if (pings!=1) {
				fprintf(stderr, "No Dispatcher PONG 0\n");
				break;
			}
			echld_ping(0,ping_cb,NULL);
		}

		if ( tot_cycles == 6 ) {
			if (pings!=2) {
				fprintf(stderr, "No Dispatcher PONG 1\n");
				break;
			}

			echld_set_param(0,"dbg_level","5",param_cb,NULL);
		}

		if ( tot_cycles == 8) {
			if (! got_param ) {
				fprintf(stderr, "Set Dispatcher Param Failed\n");
				break;
			}

			echld_get_param(0,"interfaces",param_cb,NULL);
		}

		if ( tot_cycles == 10) {
			if (! got_param ) {
				fprintf(stderr, "Set Dispatcher Param Failed\n");
				break;
			}

			child = echld_new(NULL);
			
			fprintf(stderr, "New chld_id=%d\n",child);

			if (child <= 0) {
				fprintf(stderr, "No child\n");
				break;
			}
		}


		if ( tot_cycles == 16 ) echld_ping(child,ping_cb,NULL);

		if ( tot_cycles == 18 ) {
			if (pings!=3) {
				fprintf(stderr, "No Child PONG 0\n");
				break;
			}
			echld_ping(child,ping_cb,NULL);
		}



		if ( tot_cycles == 20 ) {
			if (pings!=4) {
				fprintf(stderr, "No Child PONG 1\n");
				break;
			}

			echld_set_param(child,"cookie","hello-hello",param_cb,NULL);
		}


		if ( tot_cycles == 22 ) {
			if (!got_param) {
				fprintf(stderr, "Set Child Param Failed\n");
				break;
			}

			echld_get_param(child,"dbg_level",param_cb,NULL);
		}

		if ( tot_cycles == 24 ) {
			if (!got_param) {
				fprintf(stderr, "Get Child Param Failed\n");
				break;
			}

			keep_going = 0;
		}

		tot_cycles++;
		echld_wait(&tv);
	} while( keep_going && (tot_cycles < max_cycles));

	fprintf(stderr, "Done: pings=%d errors=%d tot_cycles=%d\n", pings, errors ,tot_cycles );

	echld_terminate();
	return 0;
}


void main_window_update(void) {}
