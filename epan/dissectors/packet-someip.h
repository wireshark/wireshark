/* packet-someip.h
 * Definitions for SOME/IP packet disassembly structures and routines
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de> / <lars.voelker@bmw.de>
 * Copyright 2012-2023 Dr. Lars Voelker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SOMEIP_H__
#define __PACKET_SOMEIP_H__

/* used for SD to add ports dynamically */
void register_someip_port_udp(uint32_t portnumber);
void register_someip_port_tcp(uint32_t portnumber);

/* look up names for SD */
char *someip_lookup_service_name(uint16_t serviceid);
char *someip_lookup_eventgroup_name(uint16_t serviceid, uint16_t eventgroupid);

typedef struct _someip_info {
    uint16_t service_id;
    uint16_t method_id;
    uint16_t client_id;
    uint16_t session_id;
    uint8_t message_type;
    uint8_t major_version;
} someip_info_t;
#define SOMEIP_INFO_T_INIT { 0, 0, 0, 0, 0, 0 }

typedef struct _someip_messages_tap {
    uint16_t service_id;
    uint16_t method_id;
    uint8_t interface_version;
    uint8_t message_type;
} someip_messages_tap_t;

#endif /* __PACKET_SOMEIP_H__ */

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
