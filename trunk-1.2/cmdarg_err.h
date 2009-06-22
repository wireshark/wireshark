/* cmdarg_err.h
 * Declarations of routines to report command-line errors.
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

#ifndef __CMDARG_ERR_H__
#define __CMDARG_ERR_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Report an error in command-line arguments.
 */
#if __GNUC__ >= 2
extern void cmdarg_err(const char *fmt, ...)
    __attribute__((format (printf, 1, 2)));
#else
extern void cmdarg_err(const char *fmt, ...);
#endif

/*
 * Report additional information for an error in command-line arguments.
 */
#if __GNUC__ >= 2
extern void cmdarg_err_cont(const char *fmt, ...)
    __attribute__((format (printf, 1, 2)));
#else
extern void cmdarg_err_cont(const char *fmt, ...);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CMDARG_ERR_H__ */
