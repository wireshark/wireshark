/* report_err.h
 * Declarations of routines for dissectors to use to report errors to
 * the user (e.g., problems with preference settings)
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

#ifndef __REPORT_ERR_H__
#define __REPORT_ERR_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Report an error when trying to open a file.
 */
extern void report_open_failure(const char *filename, int err,
    gboolean for_writing);

/*
 * Report an error when trying to read a file.
 */
extern void report_read_failure(const char *filename, int err);

/*
 * Report a general error.
 */
extern void report_failure(const char *msg_format, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REPORT_ERR_H__ */
