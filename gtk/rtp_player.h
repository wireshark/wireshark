/* player_rtp.h
 * RTP Player for Wireshark
 *
 * $Id$
 *
 * Copyright 2006, Alejandro Vaquero
 * By Alejandro Vaquero <alejandro.vaquero@yahoo.com>
 *
 * based on h323_calls.h
 * Copyright 2004, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
 *
 * H323, RTP and Graph Support
 * By Alejandro Vaquero, alejandro.vaquero@verso.com
 * Copyright 2005, Verso Technologies Inc.
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_LIBPORTAUDIO

#if GTK_MAJOR_VERSION >= 2
void rtp_player_init(voip_calls_tapinfo_t *voip_calls_tap);
void add_rtp_packet(const struct _rtp_info *rtp_info, packet_info *pinfo);
void reset_rtp_player(void);
#endif

#endif /* HAVE_LIBPORTAUDIO */
