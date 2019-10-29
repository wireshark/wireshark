/* packet-eapol.h
 * Common definitions for EAPOL protocol.
 * Copyright 2016, Ethan Young <imfargo@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

extern int proto_eapol;

#define EAPOL_KEY_FRAME_KEY 0
typedef struct {
  guint len;
  guint8 type; /* eapol.keydes.type */
  guint8 *data;
} proto_eapol_key_frame_t;

#endif /* __PACKET_EAPOL_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
