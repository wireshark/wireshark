/* cfile.c
 * capture_file GUI-independent manipulation
 * Vassilii Khachaturov <vassilii@tarunz.org>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>

#include "cfile.h"

void
cap_file_init(capture_file *cf)
{
  /* Initialize the capture file struct */
  cf->filename      = NULL;
  cf->source        = NULL;
  cf->is_tempfile   = FALSE;
  cf->user_saved    = FALSE;
  cf->count         = 0;
  cf->has_snap      = FALSE;
  cf->snap          = WTAP_MAX_PACKET_SIZE;
  cf->wth           = NULL;
  cf->rfcode        = NULL;
  cf->dfilter       = NULL;
  cf->redissecting  = FALSE;
  cf->frames        = NULL;
}
