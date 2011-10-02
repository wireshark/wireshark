/* wspy_register.h
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
#ifndef __WS_PY_REGISTER_H__
#define __WS_PY_REGISTER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef HAVE_PYTHON
void register_all_py_protocols_func(void);
void register_all_py_handoffs_func(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __WS_PY_REGISTER_H__ */
