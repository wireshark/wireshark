/* packet-autosar-ipdu-multiplexer.h
 * Definitions for AUTOSAR I-PDU Multiplexer dissector
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 * Copyright 2021-2023 Dr. Lars Voelker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_AUTOSAR_IPDU_MULTIPLEXER_H__
#define __PACKET_AUTOSAR_IPDU_MULTIPLEXER_H__

typedef struct _autosar_ipdu_multiplexer {
    uint32_t pdu_id;
} autosar_ipdu_multiplexer_info_t;

#endif /* __PACKET_AUTOSAR_IPDU_MULTIPLEXER_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
