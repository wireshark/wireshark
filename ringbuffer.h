/* capture.h
 * Definitions for packet capture windows
 *
 * $Id: ringbuffer.h,v 1.1 2001/12/04 08:45:04 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef __RINGBUFFER_H__
#define __RINGBUFFER_H__

#ifdef HAVE_LIBPCAP

#include "file.h"
#include "wiretap/wtap.h"

/* minimum number of ringbuffer files */
#define RINGBUFFER_MIN_NUM_FILES 2 
/* maximum number of ringbuffer files */
#define RINGBUFFER_MAX_NUM_FILES MIN(10,FOPEN_MAX) 

int ringbuf_init(const char *capture_name, guint num_files);
wtap_dumper* ringbuf_init_wtap_dump_fdopen(int filetype, int linktype, 
  int snaplen, int *err);
gboolean ringbuf_switch_file(capture_file *cf, wtap_dumper **pdh, int *err);
gboolean ringbuf_wtap_dump_close(capture_file *cf, int *err);
void ringbuf_free(void);
void ringbuf_error_cleanup(void);

#endif /* HAVE_LIBPCAP */

#endif /* ringbuffer.h */
