/* packet-rtps.h
 * Header file for the Real-Time Publish-Subscribe (RTPS) and related (RTPS
 * Virtual Transport and Processed) protocols.
 *
 * (c) 2020 Copyright, Real-Time Innovations, Inc.
 * Real-Time Innovations, Inc.
 * 232 East Java Drive
 * Sunnyvale, CA 94089
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _TYPEDEFS_DEFINES_RTPS_H
#define _TYPEDEFS_DEFINES_RTPS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Vendor specific - rti */
#define NDDS_TRANSPORT_CLASSID_ANY                  (0)
#define NDDS_TRANSPORT_CLASSID_UDPv4                (1)
#define NDDS_TRANSPORT_CLASSID_UDPv6                (2)
#define NDDS_TRANSPORT_CLASSID_INTRA                (3)
#define NDDS_TRANSPORT_CLASSID_DTLS                 (6)
#define NDDS_TRANSPORT_CLASSID_WAN                  (7)
#define NDDS_TRANSPORT_CLASSID_TCPV4_LAN            (8)
#define NDDS_TRANSPORT_CLASSID_TCPV4_WAN            (9)
#define NDDS_TRANSPORT_CLASSID_TLSV4_LAN            (10)
#define NDDS_TRANSPORT_CLASSID_TLSV4_WAN            (11)
#define NDDS_TRANSPORT_CLASSID_PCIE                 (12)
#define NDDS_TRANSPORT_CLASSID_ITP                  (13)
#define NDDS_TRANSPORT_CLASSID_SHMEM                (0x01000000)
#define NDDS_TRANSPORT_CLASSID_UDPv4_WAN            (0x01000001)

/*
* Flags indicating which fields have been filled in.
*/
#define GUID_HAS_HOST_ID     0x00000001
#define GUID_HAS_APP_ID      0x00000002
#define GUID_HAS_INSTANCE_ID 0x00000004
#define GUID_HAS_ENTITY_ID   0x00000008
#define GUID_HAS_ALL         0x0000000F

typedef struct _endpoint_guid {
    unsigned   fields_present;
    uint32_t host_id;
    uint32_t app_id;
    uint32_t instance_id;
    uint32_t entity_id;
} endpoint_guid;

/* Process a submessage: used in packet-rtps-processed.c */
extern void dissect_rtps_submessages(
    tvbuff_t *tvb,
    int offset,
    packet_info *pinfo,
    proto_tree *rtps_tree,
    uint16_t version,
    uint16_t vendor_id,
    endpoint_guid *guid,
    bool dissecting_encrypted_submessage);

/* Information that the RTPS-VT protocol passes to RTPS-PROC */
struct rtpsvt_data {
    uint8_t version_major;
    uint8_t version_minor;
    uint8_t direction;
    uint16_t rtps_length;
};

#ifdef __cplusplus
} /* extern "C"*/
#endif

#endif /* _TYPEDEFS_DEFINES_RTPS_H */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
