/* packet-pdu-transport.h
 * PDU Transport dissector for FDN and others.
 * By <lars.voelker@technica-engineering.de>
 * Copyright 2020-2023 Dr. Lars Voelker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_PDU_TRANSPORT_H__
#define __PACKET_PDU_TRANSPORT_H__

/* Structure that gets passed between dissectors. */
typedef struct pdu_transport_info {
    uint32_t id;
} pdu_transport_info_t;

#endif /* __PACKET_PDU_TRANSPORT_H__ */

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
