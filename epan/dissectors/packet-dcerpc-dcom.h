/* packet-dcerpc-dcom.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_DCERPC_DCOM_H__
#define __PACKET_DCERPC_DCOM_H__

typedef struct tagCOMVERSION
    {
        guint16 MajorVersion;
        guint16 MinorVersion;
    } COMVERSION;

typedef struct tagORPC_EXTENT
    {
        e_guid_t id;
        guint32 size;
/*        guint8 data[];  */
    } ORPC_EXTENT;

typedef struct tagORPC_EXTENT_ARRAY
    {
        guint32 size;
        guint32 reserved;
        ORPC_EXTENT **extent;
    } ORPC_EXTENT_ARRAY;

typedef struct tagORPCTHIS {
    COMVERSION version;
    guint32 flags;
    guint32 reserved1;
    e_guid_t  cid;
    ORPC_EXTENT_ARRAY *extensions;
 } ORPCTHIS;

typedef struct tagMInterfacePointer {
    guint32 ulCntData;
/*  guint8 abData[];  */
 } MInterfacePointer,  *PMInterfacePointer;

typedef struct tagORPCTHAT {
    guint32 flags;
    ORPC_EXTENT_ARRAY *extensions;
 } ORPCTHAT;

typedef struct tagSTRINGBINDING {
    unsigned short wTowerId;     /* Cannot be zero. */
    unsigned short aNetworkAddr; /* Zero terminated. */
 } STRINGBINDING;

typedef struct tagSECURITYBINDING {
    unsigned short wAuthnSvc;  /* Cannot be zero. */
    unsigned short wAuthzSvc;  /* Must not be zero. */
    unsigned short aPrincName; /* Zero terminated. */
 }  SECURITYBINDING;

typedef struct tagDUALSTRINGARRAY {
    unsigned short wNumEntries;     /* Number of entries in array. */
    unsigned short wSecurityOffset; /* Offset of security info. */
/*  [size_is(wNumEntries)] unsigned short aStringArray[]; */
    } DUALSTRINGARRAY;

#endif /* packet-dcerpc-dcom.h */
