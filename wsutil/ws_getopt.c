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

#include <wsutil/ws_getopt.h>

#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include <glib.h>

#include <ws_codepoints.h>

char *ws_optarg;
int ws_optind=1, ws_opterr=1, ws_optopt, ws_optpos, ws_optreset=0;

static void __getopt_msg(const char *prog, const char *errstr,
				const char *optbuf, size_t optsize)
{
	FILE *f = stderr;
	if ((fputs(prog, f) < 0) ||
			(fputs(errstr, f) < 0) ||
			(fwrite(optbuf, sizeof(char), optsize, f) != optsize)) {
		return;
	}
	putc('\n', f);
}

static void permute(char *const *argv, int dest, int src)
{
	char **av = (char **)argv;
	char *tmp = av[src];
	int i;
	for (i=src; i>dest; i--)
		av[i] = av[i-1];
	av[dest] = tmp;
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

	if (argv[ws_optind][1] == '-' && !argv[ws_optind][2]) {
		ws_optind++;
		return -1;
	}

	if (!ws_optpos) ws_optpos++;
	if ((k = mbtowc(&c, argv[ws_optind]+ws_optpos, MB_LEN_MAX)) < 0) {
		k = 1;
		c = UNICODE_REPLACEMENT_CHARACTER; /* replacement char */
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
			__getopt_msg(g_get_prgname(), ": unrecognized option: ", optchar, k);
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
			if (ws_opterr) __getopt_msg(g_get_prgname(),
				": option requires an argument: ",
				optchar, k);
			return '?';
		}
	}
	return c;
}

static int __getopt_long_core(int argc, char *const *argv, const char *optstring, const struct ws_option *longopts, int *idx, int longonly);

static int __getopt_long(int argc, char *const *argv, const char *optstring, const struct ws_option *longopts, int *idx, int longonly)
{
	int ret, skipped, resumed;
	if (!ws_optind || ws_optreset) {
		ws_optreset = 0;
		ws_optpos = 0;
		ws_optind = 1;
	}
	if (ws_optind >= argc || !argv[ws_optind]) return -1;
	skipped = ws_optind;
	if (optstring[0] != '+' && optstring[0] != '-') {
		int i;
		for (i=ws_optind; ; i++) {
			if (i >= argc || !argv[i]) return -1;
			if (argv[i][0] == '-' && argv[i][1]) break;
		}
		ws_optind = i;
	}
	resumed = ws_optind;
	ret = __getopt_long_core(argc, argv, optstring, longopts, idx, longonly);
	if (resumed > skipped) {
		int i, cnt = ws_optind-resumed;
		for (i=0; i<cnt; i++)
			permute(argv, skipped, ws_optind-1);
		ws_optind = skipped + cnt;
	}
	return ret;
}

static int __getopt_long_core(int argc, char *const *argv, const char *optstring, const struct ws_option *longopts, int *idx, int longonly)
{
	ws_optarg = 0;
	if (longopts && argv[ws_optind][0] == '-' &&
		((longonly && argv[ws_optind][1] && argv[ws_optind][1] != '-') ||
		 (argv[ws_optind][1] == '-' && argv[ws_optind][2])))
	{
		int colon = optstring[optstring[0]=='+'||optstring[0]=='-']==':';
		int i, cnt, match = -1;
		char *arg = NULL, *opt, *start = argv[ws_optind]+1;
		for (cnt=i=0; longopts[i].name; i++) {
			const char *name = longopts[i].name;
			opt = start;
			if (*opt == '-') opt++;
			while (*opt && *opt != '=' && *opt == *name) {
				name++;
				opt++;
			}
			if (*opt && *opt != '=') continue;
			arg = opt;
			match = i;
			if (!*name) {
				cnt = 1;
				break;
			}
			cnt++;
		}
		if (cnt==1 && longonly && arg-start == mblen(start, MB_LEN_MAX)) {
			ptrdiff_t l = arg - start;
			for (i=0; optstring[i]; i++) {
				ptrdiff_t j;
				for (j=0; j<l && start[j]==optstring[i+j]; j++);
				if (j==l) {
					cnt++;
					break;
				}
			}
		}
		if (cnt==1) {
			i = match;
			opt = arg;
			ws_optind++;
			if (*opt == '=') {
				if (!longopts[i].has_arg) {
					ws_optopt = longopts[i].val;
					if (colon || !ws_opterr)
						return '?';
					__getopt_msg(g_get_prgname(),
						": option does not take an argument: ",
						longopts[i].name,
						strlen(longopts[i].name));
					return '?';
				}
				ws_optarg = opt+1;
			} else if (longopts[i].has_arg == ws_required_argument) {
				if (!(ws_optarg = argv[ws_optind])) {
					ws_optopt = longopts[i].val;
					if (colon) return ':';
					if (!ws_opterr) return '?';
					__getopt_msg(g_get_prgname(),
						": option requires an argument: ",
						longopts[i].name,
						strlen(longopts[i].name));
					return '?';
				}
				ws_optind++;
			}
			if (idx) *idx = i;
			if (longopts[i].flag) {
				*longopts[i].flag = longopts[i].val;
				return 0;
			}
			return longopts[i].val;
		}
		if (argv[ws_optind][1] == '-') {
			ws_optopt = 0;
			if (!colon && ws_opterr)
				__getopt_msg(g_get_prgname(), cnt ?
					": option is ambiguous: " :
					": unrecognized option: ",
					argv[ws_optind]+2,
					strlen(argv[ws_optind]+2));
			ws_optind++;
			return '?';
		}
	}
	return ws_getopt(argc, argv, optstring);
}

int ws_getopt_long(int argc, char *const *argv, const char *optstring, const struct ws_option *longopts, int *idx)
{
	return __getopt_long(argc, argv, optstring, longopts, idx, 0);
}

int ws_getopt_long_only(int argc, char *const *argv, const char *optstring, const struct ws_option *longopts, int *idx)
{
	return __getopt_long(argc, argv, optstring, longopts, idx, 1);
}
