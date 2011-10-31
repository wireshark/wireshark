/* packet-ua.h
* Routines for UA (Universal Alcatel) packet dissection.
* Copyright 2011, Marek Tews <marek@trx.com.pl>
*
* $Id$
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
* is a dissector file; if you just copied this from README.developer,
* don't bother with the "Copied from" - you don't even need to put
* in a "Copied from" if you copied an existing dissector, especially
* if the bulk of the code in the new dissector is your code)
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

extern gboolean is_ua(tvbuff_t *tvb);
