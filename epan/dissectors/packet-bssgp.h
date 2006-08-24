/* packet-bssgp.h
 * Routines for Base Station Subsystem GPRS Protocol dissection
 * Copyright 2006, Anders Broman <anders.broman [at] ericsson.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* 3GPP TS 48.018 V 6.5.0 (2004-07) Release 6 */
#ifndef __PACKET_BSSGP_H__
#define __PACKET_BSSGP_H__

typedef struct {
  guint8        iei;
  const char   *name;
  guint8        presence_req;
  int           format;
  gint16        value_length; /* in bytes (read from capture)*/
  gint16        total_length; /* as specified, or 0 if unspecified */
} bssgp_ie_t;

typedef struct {
  tvbuff_t     *tvb;
  guint32       offset;
  packet_info  *pinfo;
  proto_tree   *bssgp_tree;
  proto_tree   *parent_tree;
  gboolean      dl_data;
  gboolean      ul_data;
  guint8		pdutype;
} build_info_t;


#endif /* __PACKET_BSSGP_H__ */