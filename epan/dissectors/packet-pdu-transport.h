/* packet-pdu-transport.h
 * PDU Transport dissector for FDN and others.
 * By <lars.voelker@technica-engineering.de>
 * Copyright 2020-2020 Dr. Lars Voelker
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
struct pdu_transport_info
{
  guint32 id;
};

typedef struct pdu_transport_info pdu_transport_info_t;


#endif /* __PACKET_PDU_TRANSPORT_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
