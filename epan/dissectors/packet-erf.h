/* packet-erf.h
 * Routines for ERF encapsulation dissection
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
#ifndef __PACKET_ERF_H_
#define __PACKET_ERF_H_

#define EXT_HDR_TYPE_CLASSIFICATION 3
#define EXT_HDR_TYPE_INTERCEPTID 4 
#define EXT_HDR_TYPE_RAW_LINK   5 

void proto_reg_handoff_erf(void);
void proto_register_erf(void);

struct erf_mc_hdlc_hdrx {
  guint16 byte01;
  guint8 byte2;
  guint8 byte3;
};

struct erf_mc_raw_hdrx {
  guint8 byte0;
  guint16 byte12;
  guint8 byte3;
};

struct erf_mc_atm_hdrx {
  guint16 byte01;
  guint8 byte2;
  guint8 byte3;
};

struct erf_mc_aal5_hdrx {
  guint16 byte01;
  guint8 byte2;
  guint8 byte3;
};

struct erf_mc_aal2_hdrx {
  guint16 byte01;
  guint8 byte2;
  guint8 byte3;
};

struct erf_mc_rawl_hdrx {
  guint16 byte01;
  guint8 byte2;
  guint8 byte3;
};

struct erf_eth_hdrx {
  guint8 byte0;
  guint8 byte1;
};

#endif
