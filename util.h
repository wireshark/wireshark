/* util.h
 * Utility definitions
 *
 * $Id: util.h,v 1.18 2000/01/29 16:41:15 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef __UTIL_H__
#define __UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Given a pathname, return the last component.
 */
char *get_basename(char *);

/*
 * Given a pathname, return a string containing everything but the
 * last component.  NOTE: this overwrites the pathname handed into
 * it....
 */
char *get_dirname(char *);

int create_tempfile(char *, int, const char *);

/* Returns the user's home directory, via the HOME environment
 * variable, or a default directory if HOME is not set */
const char* get_home_dir(void);

void ASCII_to_EBCDIC(guint8 *buf, guint bytes);
guint8 ASCII_to_EBCDIC1(guint8 c);
void EBCDIC_to_ASCII(guint8 *buf, guint bytes);
guint8 EBCDIC_to_ASCII1(guint8 c);

#ifdef HAVE_LIBPCAP

GList *get_interface_list(int *err, char *err_str);

/* Error values from "get_interface_list()". */
#define	CANT_GET_INTERFACE_LIST	0	/* error getting list */
#define	NO_INTERFACES_FOUND	1	/* list is empty */

void free_interface_list(GList *if_list);

#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UTIL_H__ */
