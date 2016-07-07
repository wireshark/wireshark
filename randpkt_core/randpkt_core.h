/*
 * randpkt_core.h
 * ---------
 * Creates random packet traces. Useful for debugging sniffers by testing
 * assumptions about the veracity of the data found in the packet.
 *
 * Copyright (C) 1999 by Gilbert Ramirez <gram@alumni.rice.edu>
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

#ifndef __RANDPKT_CORE_H__
#define __RANDPKT_CORE_H__

#include <glib.h>
#include "wiretap/wtap.h"

#define MAXBYTES_LIMIT 65536

typedef struct {
	const char*  abbrev;
	const char*  longname;
	int          produceable_type;
	int          sample_wtap_encap;
	guint8*      sample_buffer;
	int          sample_length;
	guint8*      pseudo_buffer;
	guint        pseudo_length;
	wtap_dumper* dump;
	const char*  filename;
	guint        produce_max_bytes;

} randpkt_example;

/* Return the number of active examples */
guint randpkt_example_count(void);

/* Return the list of the active examples */
void randpkt_example_list(char*** abbrev_list, char*** longname_list);

/* Parse command-line option "type" and return enum type */
int randpkt_parse_type(char *string);

/* Find pkt_example record and return pointer to it */
randpkt_example* randpkt_find_example(int type);

/* Init a new example */
void randpkt_example_init(randpkt_example* example, char* produce_filename, int produce_max_bytes);

/* Loop the packet generation */
void randpkt_loop(randpkt_example* example, guint64 produce_count);

/* Close the current example */
gboolean randpkt_example_close(randpkt_example* example);

#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
