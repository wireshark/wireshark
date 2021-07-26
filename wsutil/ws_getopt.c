/*
 * musl as a whole is licensed under the following standard MIT license:
 *
 * ----------------------------------------------------------------------
 * Copyright © 2005-2020 Rich Felker, et al.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ----------------------------------------------------------------------
 */

//#define _BSD_SOURCE
//#include <unistd.h>
#include <wchar.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>

#include <wsutil/ws_getopt.h>

char *ws_optarg;
int ws_optind=1, ws_opterr=1, ws_optopt, ws_optpos, ws_optreset=0;

void __getopt_msg(const char *a, const char *b, const char *c, size_t l)
{
	FILE *f = stderr;
	fputs(a, f);
	fwrite(b, strlen(b), 1, f);
	fwrite(c, 1, l, f);
	putc('\n', f);
}

int ws_getopt(int argc, char * const argv[], const char *optstring)
{
	int i;
	wchar_t c, d;
	int k, l;
	char *optchar;

	if (!ws_optind || ws_optreset) {
		ws_optreset = 0;
		ws_optpos = 0;
		ws_optind = 1;
	}

	if (ws_optind >= argc || !argv[ws_optind])
		return -1;

	if (argv[ws_optind][0] != '-') {
		if (optstring[0] == '-') {
			ws_optarg = argv[ws_optind++];
			return 1;
		}
		return -1;
	}

	if (!argv[ws_optind][1])
		return -1;

	if (argv[ws_optind][1] == '-' && !argv[ws_optind][2])
		return ws_optind++, -1;

	if (!ws_optpos) ws_optpos++;
	if ((k = mbtowc(&c, argv[ws_optind]+ws_optpos, MB_LEN_MAX)) < 0) {
		k = 1;
		c = 0xfffd; /* replacement char */
	}
	optchar = argv[ws_optind]+ws_optpos;
	ws_optpos += k;

	if (!argv[ws_optind][ws_optpos]) {
		ws_optind++;
		ws_optpos = 0;
	}

	if (optstring[0] == '-' || optstring[0] == '+')
		optstring++;

	i = 0;
	d = 0;
	do {
		l = mbtowc(&d, optstring+i, MB_LEN_MAX);
		if (l>0) i+=l; else i++;
	} while (l && d != c);

	if (d != c || c == ':') {
		ws_optopt = c;
		if (optstring[0] != ':' && ws_opterr)
			__getopt_msg(argv[0], ": unrecognized option: ", optchar, k);
		return '?';
	}
	if (optstring[i] == ':') {
		ws_optarg = 0;
		if (optstring[i+1] != ':' || ws_optpos) {
			ws_optarg = argv[ws_optind++] + ws_optpos;
			ws_optpos = 0;
		}
		if (ws_optind > argc) {
			ws_optopt = c;
			if (optstring[0] == ':') return ':';
			if (ws_opterr) __getopt_msg(argv[0],
				": option requires an argument: ",
				optchar, k);
			return '?';
		}
	}
	return c;
}
