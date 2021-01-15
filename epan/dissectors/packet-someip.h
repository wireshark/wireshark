/* packet-someip.h
 * Definitions for SOME/IP packet disassembly structures and routines
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de> / <lars.voelker@bmw.de>
 * Copyright 2012-2021 Dr. Lars Voelker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* used for SD to add ports dynamically */
void register_someip_port_udp(guint32 portnumber);
void register_someip_port_tcp(guint32 portnumber);

/* look up names for SD */
char* someip_lookup_service_name(guint16 serviceid);
char* someip_lookup_eventgroup_name(guint16 serviceid, guint16 eventgroupid);

typedef struct _someip_info
{
    guint16 service_id;
    guint16 method_id;
    guint8  message_type;
    guint8  major_version;
} someip_info_t;

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
