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

#include "echld.h"
#include <signal.h>
#include <stdio.h>


void reaper(int sig) {

};


int main(int argc, char** argv) {
	int pid;

	echld_initialize(ECHLD_ENCODING_JSON);


	switch((pid = fork())) {
		case -1:
			return 222;
		case 0:
			exit(echld_loop());
		case 1:
			echld_ping(0,)
			signal(reaper)
			waitpid();
	}
};
