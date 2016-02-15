/*
 * randpkt.c
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

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <wsutil/ws_diag_control.h>
#include <wsutil/unicode-utils.h>
#include <wsutil/file_util.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifndef HAVE_GETOPT_LONG
#include "wsutil/wsgetopt.h"
#endif

#include "randpkt_core/randpkt_core.h"

/* Print usage statement and exit program */
static void
usage(gboolean is_error)
{
	FILE *output;
	const char** abbrev_list;
	const char** longname_list;
	unsigned list_num;
	unsigned i;

	if (!is_error) {
		output = stdout;
	}
	else {
		output = stderr;
	}

	fprintf(output, "Usage: randpkt [-b maxbytes] [-c count] [-t type] [-r] filename\n");
	fprintf(output, "Default max bytes (per packet) is 5000\n");
	fprintf(output, "Default count is 1000.\n");
	fprintf(output, "-r: random packet type selection\n");
	fprintf(output, "\n");
	fprintf(output, "Types:\n");

	/* Get the examples list */
	randpkt_example_list(&abbrev_list, &longname_list, &list_num);
	for (i = 0; i < list_num; i++) {
		fprintf(output, "\t%-16s%s\n", abbrev_list[i], longname_list[i]);
	}
	g_free((char**)abbrev_list);
	g_free((char**)longname_list);

	fprintf(output, "\nIf type is not specified, a random packet will be chosen\n\n");

	exit(is_error ? 1 : 0);
}
int
main(int argc, char **argv)
{
	int			opt;
	int			produce_type = -1;
	char			*produce_filename = NULL;
	int			produce_max_bytes = 5000;
	int			produce_count = 1000;
	randpkt_example		*example;
	guint8*			type = NULL;
	int 			allrandom = FALSE;
	wtap_dumper		*savedump;
	static const struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{0, 0, 0, 0 }
	};

#ifdef _WIN32
	arg_list_utf_16to8(argc, argv);
	create_app_running_mutex();
#endif /* _WIN32 */

	while ((opt = getopt_long(argc, argv, "b:c:ht:r", long_options, NULL)) != -1) {
		switch (opt) {
			case 'b':	/* max bytes */
				produce_max_bytes = atoi(optarg);
				if (produce_max_bytes > 65536) {
					fprintf(stderr, "randpkt: Max bytes is 65536\n");
					return 1;
				}
				break;

			case 'c':	/* count */
				produce_count = atoi(optarg);
				break;

			case 't':	/* type of packet to produce */
				type = g_strdup(optarg);
				break;

			case 'h':
				usage(FALSE);
				break;

			case 'r':
				allrandom = TRUE;
				break;

			default:
				usage(TRUE);
				break;
		}
	}

	/* any more command line parameters? */
	if (argc > optind) {
		produce_filename = argv[optind];
	}
	else {
		usage(TRUE);
	}

	randpkt_seed();

	if (!allrandom) {
		produce_type = randpkt_parse_type(type);
		g_free(type);

		example = randpkt_find_example(produce_type);
		if (!example)
			return 1;

		randpkt_example_init(example, produce_filename, produce_max_bytes);
		randpkt_loop(example, produce_count);
	} else {
		if (type) {
			fprintf(stderr, "Can't set type in random mode\n");
			return 2;
		}

		produce_type = randpkt_parse_type(NULL);
		example = randpkt_find_example(produce_type);
		if (!example)
			return 1;
		randpkt_example_init(example, produce_filename, produce_max_bytes);

		while (produce_count-- > 0) {
			randpkt_loop(example, 1);
			produce_type = randpkt_parse_type(NULL);

			savedump = example->dump;

			example = randpkt_find_example(produce_type);
			if (!example)
				return 1;
			example->dump = savedump;
		}
	}
	if (!randpkt_example_close(example))
		return 2;
	return 0;

}

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
