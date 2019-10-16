/* packet-netmon.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_NETMON_H
#define PACKET_NETMON_H

#define EVENT_HEADER_FLAG_EXTENDED_INFO         0x0001
#define EVENT_HEADER_FLAG_PRIVATE_SESSION       0x0002
#define EVENT_HEADER_FLAG_STRING_ONLY           0x0004
#define EVENT_HEADER_FLAG_TRACE_MESSAGE         0x0008
#define EVENT_HEADER_FLAG_NO_CPUTIME            0x0010
#define EVENT_HEADER_FLAG_32_BIT_HEADER         0x0020
#define EVENT_HEADER_FLAG_64_BIT_HEADER         0x0040
#define EVENT_HEADER_FLAG_CLASSIC_HEADER        0x0100

/* Dissector data for Provider ID dissector table */
struct netmon_provider_id_data
{
    guint32 event_id;
    guint16 event_flags;
    guint8 event_version;
    guint64 keyword;
    guint8 opcode;
};


void netmon_etl_field(proto_tree *tree, tvbuff_t *tvb, int* offset, int hf, guint16 flags);
void netmon_sid_field(proto_tree *tree, tvbuff_t *tvb, int* offset, packet_info *pinfo,
                      int hf_revision, int hf_subauthority_count, int hf_sid_id, int hf_sid_authority,
                      expert_field* invalid_sid, gboolean conformant);


#endif /* PACKET_NETMON_H */

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
