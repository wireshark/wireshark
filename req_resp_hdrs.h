/* req_resp_hdrs.h
 * Declarations of routines handling protocols with a request/response line,
 * headers, a blank line, and an optional body.
 *
 * $Id: req_resp_hdrs.h,v 1.1 2003/12/23 02:29:11 guy Exp $
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

#ifndef __REQ_RESP_HDRS_H__
#define __REQ_RESP_HDRS_H__

/*
 * Optionally do reassembly of the request/response line, headers, and body.
 */
extern gboolean
req_resp_hdrs_do_reassembly(tvbuff_t *tvb, packet_info *pinfo,
    gboolean desegment_headers, gboolean desegment_body);

#endif
