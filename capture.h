/* capture.h
 * Definitions for packet capture windows
 *
 * $Id: capture.h,v 1.22 2000/01/05 22:31:37 gerald Exp $
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

#ifndef __CAPTURE_H__
#define __CAPTURE_H__

#ifdef HAVE_LIBPCAP

/* Name we give to the child process when doing a "-S" capture. */
#define	CHILD_NAME	"ethereal-capture"

extern int sync_mode;	/* fork a child to do the capture, and sync between them */
extern int sync_pipe[2]; /* used to sync father */
extern int quit_after_cap; /* Makes a "capture only mode". Implies -k */
extern gboolean capture_child;	/* if this is the child for "-S" */

/* Open a specified file, or create a temporary file, and start a capture
   to the file in question. */
void   do_capture(char *capfile_name);

/* Do the low-level work of a capture. */
int    capture(void);

#endif /* HAVE_LIBPCAP */

#define EMPTY_FILTER ""
#endif /* capture.h */
