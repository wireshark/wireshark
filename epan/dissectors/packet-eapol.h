/* packet-eapol.h
 * Common definitions for EAPOL protocol.
 * Copyright 2016, Ethan Young <imfargo@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_EAPOL_H__
#define __PACKET_EAPOL_H__

/* EAPOL packet types. */
#define EAPOL_EAP                    0
#define EAPOL_START                  1
#define EAPOL_LOGOFF                 2
#define EAPOL_KEY                    3
#define EAPOL_ENCAP_ASF_ALERT        4
#define EAPOL_MKA                    5
#define EAPOL_ANNOUNCEMENT_GENERIC   6
#define EAPOL_ANNOUNCEMENT_SPECIFIC  7
#define EAPOL_ANNOUNCEMENT_REQUEST   8

#endif /* __PACKET_EAPOL_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
