/* rreh.h
 * Declarations of routines handling protocols with a request/response line,
 * entity headers, a blank line, and an optional body.
 *
 * $Id: rreh.h,v 1.1 2003/12/22 00:57:34 guy Exp $
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

#ifndef __RREH_H__
#define __RREH_H__

/*
 * Optionally do reassembly of the request/response line, entity headers,
 * and body.
 */
extern gboolean
rreh_do_reassembly(tvbuff_t *tvb, packet_info *pinfo,
    gboolean desegment_headers, gboolean desegment_body);

#endif
