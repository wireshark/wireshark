/*
 * Declaration of the real main routine, for all CLI programs where the
 * main routine should get UTF-8 arguments on Windows.  In those programs,
 * in the file that defines the main routine, include this header and link
 * those programs with cli_main.c.
 *
 * This is used in software licensed under the GPLv2, and its license MUST
 * be compatible with that license.
 *
 * This is used in software licensed under the Apache 2.0 license, and its
 * license MUST be compatible with that license.
 *
 * For that purpose, we use the MIT (X11) license.
 *
 * SPDX-License-Identifier: MIT
 */

#ifdef _WIN32
int real_main(int argc, char *argv[]);
#define main    real_main
#endif
