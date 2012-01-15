/* decode_as_ber.h
 *
 * $Id$
 *
 * Routines to modify BER decoding on the fly.
 * Only internally used between decode_as_dlg and decode_as_ber
 *
 * Copyright 2006 Graeme Lunt
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
 *
 */

#ifndef __DECODE_AS_BER_H__
#define __DECODE_AS_BER_H__

/** @file
 *  "Decode As" / "User Specified Decodes" dialog box.
 *  @ingroup dialog_group
 */

#define E_PAGE_BER "notebook_page_ber" /* ber only */

extern GtkWidget *
decode_ber_add_page(packet_info *pinfo);

#endif
