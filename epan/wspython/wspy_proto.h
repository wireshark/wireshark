/* wspy_proto.h
 *
 * $Id$
 *
 * Wireshark Protocol Python Binding
 *
 * Copyright (c) 2009 by Sebastien Tandel <sebastien [AT] tandel [dot] be>
 * Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
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
#ifndef __WS_PY_PROTO_H__
#define __WS_PY_PROTO_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef HAVE_PYTHON
hf_register_info *hf_register_info_create(const guint8 size);
void hf_register_info_destroy(hf_register_info *hf);
void hf_register_info_add(hf_register_info *hf, guint8 index,
          int *p_id, const char *name, const char *abbrev,
          enum ftenum type, int display, const void *strings,
          guint32 bitmask, const char *blurb);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __WS_PY_PROTO_H__ */
