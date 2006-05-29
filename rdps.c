/* rdps.c
 *
 * $Id$
 * 
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

/* takes the file listed as the first argument and creates the file listed
as the second argument. It takes a PostScript file and creates a C program
with 2 functions:
	print_ps_preamble()
	print_ps_finale()

*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 1024

void start_code(FILE *fd, const char *func);
void write_code(FILE *fd, char *string);
void end_code(FILE *fd);
void ps_clean_string(char *out, const char *in,
			int outbuf_size);

enum ps_state { null, preamble, hex, finale };

int main(int argc, char **argv)
{
	FILE	*input;
	FILE	*output;
	char	buf[BUFFER_SIZE];	/* static sized buffer! */
	enum ps_state	state = null;

	if (argc != 3) {
		fprintf(stderr, "%s: input_file output_file\n", argv[0]);
		exit(-1);
	}

	if (!(input = fopen(argv[1], "r"))) {
		fprintf(stderr, "%s: cannot open %s for input.\n", argv[0], argv[1]);
		exit(-1);
	}

	if (!(output = fopen(argv[2], "w"))) {
		fprintf(stderr, "%s: cannot open %s for output.\n", argv[0], argv[2]);
		exit(-1);
	}

	fprintf(output, "/* Created by rdps.c. Do not edit! */\n\n"
          "#include <stdio.h>\n\n"
          "#include \"ps.h\"\n\n");

	while (fgets(buf, BUFFER_SIZE - 1, input)) {

		if (state == null) {
			if (strcmp(buf, "% ---- ethereal preamble start ---- %\n") == 0) {
				state = preamble;
				start_code(output, "preamble");
				continue;
			}
			else if (strcmp(buf, "% ---- ethereal finale start ---- %\n") == 0) {
				state = finale;
				start_code(output, "finale");
				continue;
			}
		}
		else if (state == preamble) {
			if (strcmp(buf, "% ---- ethereal preamble end ---- %\n") == 0) {
				state = null;
				end_code(output);
				continue;
			}
			else {
				write_code(output, buf);
			}
		}
		else if (state == hex) {
			if (strcmp(buf, "% ---- ethereal hex end ---- %\n") == 0) {
				state = null;
				end_code(output);
				continue;
			}
			else {
				write_code(output, buf);
			}
		}
		else if (state == finale) {
			if (strcmp(buf, "% ---- ethereal finale end ---- %\n") == 0) {
				state = null;
				end_code(output);
				continue;
			}
			else {
				write_code(output, buf);
			}
		}
		else {
			fprintf(stderr, "NO MATCH:%s", buf);
			exit(-1);
		}
	}
        exit(0);
}

void start_code(FILE *fd, const char *func)
{
	fprintf(fd, "/* Created by rdps.c. Do not edit! */\n");
	fprintf(fd, "void print_ps_%s(FILE *fd) {\n", func);
}

void write_code(FILE *fd, char *string)
{
	char psbuf[BUFFER_SIZE];
	ps_clean_string(psbuf, string, BUFFER_SIZE);
	fprintf(fd, "\tfprintf(fd, \"%s\");\n", psbuf);
}

void end_code(FILE *fd)
{
	fprintf(fd, "}\n\n\n");
}

void ps_clean_string(char *out, const char *in,
			int outbuf_size)
{
	int rd, wr;
	char c;

	for (rd = 0, wr = 0 ; wr < outbuf_size; rd++, wr++ ) {
		c = in[rd];
		switch (c) {
			case '\\':
				out[wr] = '\\';
				out[++wr] = '\\';
				out[++wr] = c;
				break;

			case '%':
				out[wr] = '%';
				out[++wr] = '%';
				break;

			case '\n':
				out[wr] = '\\';
				out[++wr] = 'n';
				break;

			default:
				out[wr] = c;
				break;
		}

		if (c == 0) {
			break;
		}
	}
}
