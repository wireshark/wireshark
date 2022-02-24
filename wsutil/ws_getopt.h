/** @file
 *
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

#ifndef _WS_GETOPT_H_
#define _WS_GETOPT_H_

#include <ws_symbol_export.h>

#ifdef __cplusplus
extern "C" {
#endif

WS_DLL_PUBLIC int ws_getopt(int, char * const [], const char *);
WS_DLL_PUBLIC char *ws_optarg;
WS_DLL_PUBLIC int ws_optind, ws_opterr, ws_optopt, ws_optpos, ws_optreset;

struct ws_option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};

WS_DLL_PUBLIC int ws_getopt_long(int, char *const *, const char *, const struct ws_option *, int *);
WS_DLL_PUBLIC int ws_getopt_long_only(int, char *const *, const char *, const struct ws_option *, int *);

#define ws_no_argument        0
#define ws_required_argument  1
#define ws_optional_argument  2

#ifdef __cplusplus
}
#endif

#endif
