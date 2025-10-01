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

/**
 * @brief Parse command-line options.
 *
 * Portable wrapper for parsing command-line arguments using a simplified getopt-style interface.
 * Processes options from the argument vector according to the specified option string.
 *
 * @param argc     Argument count.
 * @param argv     Argument vector.
 * @param optstring String containing the valid option characters.
 * @return         The next option character, or -1 when no more options are found.
 */
WS_DLL_PUBLIC int ws_getopt(int argc, char * const argv[], const char *optstring);
WS_DLL_PUBLIC char *ws_optarg;
WS_DLL_PUBLIC int ws_optind, ws_opterr, ws_optopt, ws_optpos, ws_optreset;

/**
 * @struct ws_option
 * @brief Structure representing a long-form command-line option.
 *
 * Used to define named options for extended argument parsing, similar to GNU getopt_long().
 *
 * @var name      Long option name (e.g., "help").
 * @var has_arg   Indicates if the option requires an argument (0 = no, 1 = required, 2 = optional).
 * @var flag      If non-NULL, set to `val` when option is found; otherwise, `val` is returned.
 * @var val       Value to return or store when the option is matched.
 */
struct ws_option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};

/**
 * @brief Parse command-line options, supporting both short and long forms.
 *
 * Extended getopt-style parser that handles short options and long options defined
 * in a `ws_option` array. Supports optional argument flags and returns the matched
 * option value or sets a flag pointer if specified.
 *
 * @param argc       Argument count.
 * @param argv       Argument vector.
 * @param optstring  String containing valid short option characters.
 * @param longopts   Array of `ws_option` structures defining long options.
 * @param idx        Optional pointer to receive index of matched long option.
 * @return           The matched option value, or -1 when no more options are found.
 */
WS_DLL_PUBLIC int ws_getopt_long(int argc, char *const *argv, const char *optstring, const struct ws_option *longopts, int *idx);

/**
 * @brief Parse command-line options, treating all options as long unless prefixed with '+'.
 *
 * Variant of `ws_getopt_long()` that interprets all options as long-form unless explicitly
 * marked as short. Useful for applications preferring long option syntax.
 *
 * @param argc       Argument count.
 * @param argv       Argument vector.
 * @param optstring  String containing valid short option characters.
 * @param longopts   Array of `ws_option` structures defining long options.
 * @param idx        Optional pointer to receive index of matched long option.
 * @return           The matched option value, or -1 when no more options are found.
 */
WS_DLL_PUBLIC int ws_getopt_long_only(int argc, char *const *argv, const char *optstring, const struct ws_option *longopts, int *idx);

#define ws_no_argument        0
#define ws_required_argument  1
#define ws_optional_argument  2

#ifdef __cplusplus
}
#endif

#endif
