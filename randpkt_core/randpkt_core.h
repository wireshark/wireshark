/** @file
 *
 * randpkt_core.h
 * ---------
 * Creates random packet traces. Useful for debugging sniffers by testing
 * assumptions about the veracity of the data found in the packet.
 *
 * Copyright (C) 1999 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __RANDPKT_CORE_H__
#define __RANDPKT_CORE_H__

#include <glib.h>
#include "wiretap/wtap.h"

typedef struct {
	const char*  abbrev;
	const char*  longname;
	int          produceable_type;
	int          sample_wtap_encap;
	uint8_t*     sample_buffer;
	int          sample_length;
	uint8_t*     pseudo_buffer;
	unsigned     pseudo_length;
	wtap_dumper* dump;
	const char*  filename;
	unsigned     produce_max_bytes;

} randpkt_example;

/* Return the number of active examples */
unsigned randpkt_example_count(void);

/* Return the list of the active examples */
void randpkt_example_list(char*** abbrev_list, char*** longname_list);

/* Parse command-line option "type" and return enum type */
int randpkt_parse_type(char *string);

/* Find pkt_example record and return pointer to it */
randpkt_example* randpkt_find_example(int type);

/* Init a new example */
int randpkt_example_init(randpkt_example* example, char* produce_filename, int produce_max_bytes, int file_type_subtype);

/* Loop the packet generation */
void randpkt_loop(randpkt_example* example, uint64_t produce_count, uint64_t packet_delay_ms);

/* Close the current example */
bool randpkt_example_close(randpkt_example* example);

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
