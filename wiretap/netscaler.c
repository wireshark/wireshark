/* netscaler.c
 *
 * Wiretap Library
 * Copyright (c) 2006 by Ravi Kondamuru <Ravi.Kondamuru@citrix.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "netscaler.h"

#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include <wsutil/ws_assert.h>

/* Defines imported from netscaler code: nsperfrc.h */

#define NSPR_SIGSTR_V10 "NetScaler Performance Data"
#define NSPR_SIGSTR_V20 "NetScaler V20 Performance Data"
#define NSPR_SIGSTR     NSPR_SIGSTR_V20
#define NSPR_SIGSTR_V30 "Netscaler V30 Performance Data"
#define NSPR_SIGSTR_V35 "Netscaler V35 Performance Data"
/* Defined but not used */
#define NSPR_SIGSTR_V21 "NetScaler V21 Performance Data"
#define NSPR_SIGSTR_V22 "NetScaler V22 Performance Data"

/*
 * NetScaler trace files are divided into 8K pages, with each page
 * containing one or more records.  The last page of the file
 * might be less than 8K bytes.
 *
 * Records are not split across page boundaries; if a record doesn't
 * fit in what remains in a page, the page is padded with null bytes
 * and the next record is put at the beginning of the next page.
 * A record type value of 0 means "unused space", so if there are
 * enough null bytes to constitute a record type value, it will
 * look as if there's an "unused space" record (which has no fields
 * other than the type and zero or more additional padding bytes).
 */
#define NSPR_PAGESIZE   8192
#define NSPR_PAGESIZE_TRACE (2*NSPR_PAGESIZE)

/* The different record types
** NOTE: The Record Type is two byte fields and unused space is recognized by
** either bytes being zero, therefore no record should any byte value as
** zero.
**
** New Performance Record Type is only one byte.
*/
#define NSPR_UNUSEDSPACE_V10    0x0000  /* rest of the page is unused */
#define NSPR_UNUSEDSPACE_V20    0x00    /* rest of the page is unused */
#define NSPR_SIGNATURE_V10      0x0101  /* signature */
#define NSPR_SIGNATURE_V20      0x01    /* signature */
#define NSPR_SIGNATURE_V30      NSPR_SIGNATURE_V20
#define NSPR_SIGNATURE_V35      NSPR_SIGNATURE_V20
#define NSPR_ABSTIME_V10        0x0107  /* data capture time in secs from 1970*/
#define NSPR_ABSTIME_V20        0x07    /* data capture time in secs from 1970*/
#define NSPR_RELTIME_V10        0x0108  /* relative time in ms from last time */
#define NSPR_RELTIME_V20        0x08    /* relative time in ms from last time */
#define NSPR_RELTIMEHR_V10      0x0109  /* high resolution relative time */
#define NSPR_RELTIMEHR_V20      0x09    /* high resolution relative time */
#define NSPR_SYSTARTIME_V10     0x010A  /* system start time */
#define NSPR_SYSTARTIME_V20     0x0A    /* system start time */
#define NSPR_RELTIME2B_V10      0x010B  /* relative time in ms from last time */
#define NSPR_RELTIME2B_V20      0x0B    /* relative time in ms from last time */


/* The high resolution relative time format.
** The MS 2 bits of the high resolution time is defined as follows:
** 00 : time value is in seconds
** 01 : time value is in milliseconds
** 10 : time value is in microseconds
** 11 : time value is in nanoseconds
*/
#define NSPR_HRTIME_MASKTM      0x3FFFFFFF /* mask to get time value */
#define NSPR_HRTIME_MASKFMT     0xC0000000 /* time value format mask */
#define NSPR_HRTIME_SEC         0x00000000 /* time value in second */
#define NSPR_HRTIME_MSEC        0x40000000 /* time value in mili second */
#define NSPR_HRTIME_USEC        0x80000000 /* time value in micro second */
#define NSPR_HRTIME_NSEC        0xC0000000 /* time value in nano second */


typedef struct nspr_header_v10
{
    uint8_t ph_RecordType[2]; /* Record Type */
    uint8_t ph_RecordSize[2]; /* Record Size including header */
} nspr_header_v10_t;
#define nspr_header_v10_s    ((uint32_t)sizeof(nspr_header_v10_t))

/* This is V20 short header (2 bytes long) to be included where needed */
#define NSPR_HEADER_V20(prefix) \
    uint8_t prefix##_RecordType; /* Record Type */ \
    uint8_t prefix##_RecordSize  /* Record Size including header */ \
                                /* end of declaration */

/* This is new long header (3 bytes long) to be included where needed */
#define NSPR_HEADER3B_V20(prefix) \
    uint8_t prefix##_RecordType;    /* Record Type */ \
    uint8_t prefix##_RecordSizeLow; /* Record Size including header */ \
    uint8_t prefix##_RecordSizeHigh /* Record Size including header */ \
                                   /* end of declaration */
#define NSPR_HEADER3B_V21 NSPR_HEADER3B_V20
#define NSPR_HEADER3B_V22 NSPR_HEADER3B_V20
#define NSPR_HEADER3B_V30 NSPR_HEADER3B_V20

typedef struct nspr_hd_v20
{
    NSPR_HEADER3B_V20(phd); /* long performance header */

} nspr_hd_v20_t;
#define nspr_hd_v20_s    ((uint32_t)sizeof(nspr_hd_v20_t))


/*
** How to know if header size is short or long?
** The short header size can be 0-127 bytes long. If MS Bit of ph_RecordSize
** is set then record size has 2 bytes
*/
#define NSPR_V20RECORDSIZE_2BYTES       0x80U

/* Performance Data Header with device number */
typedef struct nspr_headerdev_v10
{
    uint8_t ph_RecordType[2]; /* Record Type */
    uint8_t ph_RecordSize[2]; /* Record Size including header */
    uint8_t ph_DevNo[4];      /* Network Device (NIC/CONN) number */
} nspr_headerdev_v10_t;
#define nspr_headerdev_v10_s    ((uint32_t)sizeof(nspr_headerdev_v10_t))

typedef struct nspr_hd_v10
{
    nspr_header_v10_t phd; /* performance header */
} nspr_hd_v10_t;
#define nspr_hd_v10_s    ((uint32_t)sizeof(nspr_hd_v10_t))

typedef struct nspr_hdev_v10
{
    nspr_headerdev_v10_t phd; /* performance header */
} nspr_hdev_v10_t;
#define nspr_hdev_v10_s    ((uint32_t)sizeof(nspr_hdev_v10_t))

/* if structure has defined phd as first field, it can use following names */
#define nsprRecordType    phd.ph_RecordType
#define nsprRecordSize    phd.ph_RecordSize
#define nsprReserved      phd.ph_Reserved
#define nsprRecordTypeOrg phd.ph_Reserved
#define nsprDevNo         phd.ph_DevNo

/* NSPR_SIGNATURE_V10 structure */
#define NSPR_SIGSIZE_V10        56 /* signature value size in bytes */
typedef struct nspr_signature_v10
{
    nspr_header_v10_t phd; /* performance header */
    uint8_t sig_EndianType; /* Endian Type for the data */
    uint8_t sig_Reserved0;
    uint8_t sig_Reserved1[2];
    char sig_Signature[NSPR_SIGSIZE_V10]; /* Signature value */
} nspr_signature_v10_t;
#define nspr_signature_v10_s    ((uint32_t)sizeof(nspr_signature_v10_t))

/* NSPR_SIGNATURE_V20 structure */
#define NSPR_SIGSIZE_V20        sizeof(NSPR_SIGSTR_V20) /* signature value size in bytes */
typedef struct nspr_signature_v20
{
    NSPR_HEADER_V20(sig);  /* short performance header */
    uint8_t sig_EndianType; /* Endian Type for the data */
    char sig_Signature[NSPR_SIGSIZE_V20]; /* Signature value */
} nspr_signature_v20_t;
#define nspr_signature_v20_s    ((uint32_t)sizeof(nspr_signature_v20_t))

/* NSPR_SIGNATURE_V30 structure */
#define NSPR_SIGSIZE_V30        sizeof(NSPR_SIGSTR_V30) /* signature value size in bytes */
typedef struct nspr_signature_v30
{
    NSPR_HEADER_V20(sig);  /* short performance header */
    uint8_t sig_EndianType; /* Endian Type for the data */
    char sig_Signature[NSPR_SIGSIZE_V30]; /* Signature value */
} nspr_signature_v30_t;
#define nspr_signature_v30_s    ((uint32_t)sizeof(nspr_signature_v30_t))

#define NSPR_SIGSIZE_V35        sizeof(NSPR_SIGSTR_V35) /* signature value size in bytes */
typedef struct nspr_signature_v35
{
    NSPR_HEADER_V20(sig);  /* short performance header */
    uint8_t sig_EndianType; /* Endian Type for the data */
    char sig_Signature[NSPR_SIGSIZE_V35]; /* Signature value */
} nspr_signature_v35_t;
#define nspr_signature_v35_s    ((uint32_t)sizeof(nspr_signature_v35_t))

/* NSPR_ABSTIME_V10 and NSPR_SYSTARTIME_V10 structure */
typedef struct nspr_abstime_v10
{
    nspr_header_v10_t phd; /* performance header */
    uint8_t abs_RelTime[4]; /* relative time is ms from last time */
    uint8_t abs_Time[4];    /* absolute time in seconds from 1970 */
} nspr_abstime_v10_t;
#define nspr_abstime_v10_s    ((uint32_t)sizeof(nspr_abstime_v10_t))


/* NSPR_ABSTIME_V20 and NSPR_SYSTARTIME_V20 structure */
typedef struct nspr_abstime_v20
{
    NSPR_HEADER_V20(abs);  /* short performance header */
    uint8_t abs_RelTime[2]; /* relative time is ms from last time */
    uint8_t abs_Time[4];    /* absolute time in seconds from 1970 */
} nspr_abstime_v20_t;
#define nspr_abstime_v20_s    ((uint32_t)sizeof(nspr_abstime_v20_t))



/* full packet trace structure */
typedef struct nspr_pktracefull_v10
{
    nspr_headerdev_v10_t phd; /* performance header */
    uint8_t fp_RelTimeHr[4];   /* High resolution relative time */
} nspr_pktracefull_v10_t;
#define nspr_pktracefull_v10_s    ((uint32_t)(sizeof(nspr_pktracefull_v10_t)))

/* new full packet trace structure v20 */
typedef struct nspr_pktracefull_v20
{
    NSPR_HEADER3B_V20(fp);  /* long performance header */
    uint8_t fp_DevNo;        /* Network Device (NIC) number */
    uint8_t fp_RelTimeHr[4]; /* High resolution relative time */
} nspr_pktracefull_v20_t;
#define nspr_pktracefull_v20_s    ((uint32_t)(sizeof(nspr_pktracefull_v20_t)))

/* new full packet trace structure v21 */
typedef struct nspr_pktracefull_v21
{
    NSPR_HEADER3B_V21(fp);  /* long performance header */
    uint8_t fp_DevNo;        /* Network Device (NIC) number */
    uint8_t fp_RelTimeHr[4]; /* High resolution relative time */
    uint8_t fp_PcbDevNo[4];  /* PCB devno */
    uint8_t fp_lPcbDevNo[4]; /* link PCB devno */
} nspr_pktracefull_v21_t;
#define nspr_pktracefull_v21_s    ((uint32_t)(sizeof(nspr_pktracefull_v21_t)))

/* new full packet trace structure v22 */
typedef struct nspr_pktracefull_v22
{
    NSPR_HEADER3B_V22(fp);  /* long performance header */
    uint8_t fp_DevNo;        /* Network Device (NIC) number */
    uint8_t fp_RelTimeHr[4]; /* High resolution relative time */
    uint8_t fp_PcbDevNo[4];  /* PCB devno */
    uint8_t fp_lPcbDevNo[4]; /* link PCB devno */
    uint8_t fp_VlanTag[2];   /* vlan tag */
} nspr_pktracefull_v22_t;
#define nspr_pktracefull_v22_s    ((uint32_t)(sizeof(nspr_pktracefull_v22_t)))

typedef struct nspr_pktracefull_v23
{
    NSPR_HEADER3B_V22(fp);  /* long performance header */
    uint8_t fp_DevNo;        /* Network Device (NIC) number */
    uint8_t fp_AbsTimeHr[8]; /* High resolution absolute time */
    uint8_t fp_PcbDevNo[4];  /* PCB devno */
    uint8_t fp_lPcbDevNo[4]; /* link PCB devno */
    uint8_t fp_VlanTag[2];   /* vlan tag */
    uint8_t fp_Coreid[2];    /* coreid of the packet */
} nspr_pktracefull_v23_t;
#define nspr_pktracefull_v23_s    ((uint32_t)(sizeof(nspr_pktracefull_v23_t)))

/* New full packet trace structure v24 for cluster tracing */
typedef struct nspr_pktracefull_v24
{
    NSPR_HEADER3B_V22(fp);   /* long performance header */
    uint8_t fp_DevNo;         /* Network Device (NIC) number */
    uint8_t fp_AbsTimeHr[8];  /* High resolution absolute time in nanosec */
    uint8_t fp_PcbDevNo[4];   /* PCB devno */
    uint8_t fp_lPcbDevNo[4];  /* link PCB devno */
    uint8_t fp_VlanTag[2];    /* vlan tag */
    uint8_t fp_Coreid[2];     /* coreid of the packet */
    uint8_t fp_srcNodeId[2];  /* source node # */
    uint8_t fp_destNodeId[2]; /* destination node # */
    uint8_t fp_clFlags;       /* cluster flags */
} nspr_pktracefull_v24_t;
#define nspr_pktracefull_v24_s    ((uint32_t)(sizeof(nspr_pktracefull_v24_t)))

/* New full packet trace structure v25 for vm info tracing */
typedef struct nspr_pktracefull_v25
{
    NSPR_HEADER3B_V22(fp);    /* long performance header */
    uint8_t fp_DevNo;          /* Network Device (NIC) number */
    uint8_t fp_AbsTimeHr[8];   /* High resolution absolute time in nanosec */
    uint8_t fp_PcbDevNo[4];    /* PCB devno */
    uint8_t fp_lPcbDevNo[4];   /* link PCB devno */
    uint8_t fp_VlanTag[2];     /* vlan tag */
    uint8_t fp_Coreid[2];      /* coreid of the packet */
    uint8_t fp_srcNodeId[2];   /* source node # */
    uint8_t fp_destNodeId[2];  /* destination node # */
    uint8_t fp_clFlags;        /* cluster flags */
    uint8_t fp_src_vmname_len; /* vm src info */
    uint8_t fp_dst_vmname_len; /* vm src info */
} nspr_pktracefull_v25_t;
#define nspr_pktracefull_v25_s    ((uint32_t)(sizeof(nspr_pktracefull_v25_t)))

/* New full packet trace structure v26 for vm info tracing */
typedef struct nspr_pktracefull_v26
{
    NSPR_HEADER3B_V22(fp);     /* long performance header */
    uint8_t fp_DevNo;           /* Network Device (NIC) number */
    uint8_t fp_AbsTimeHr[8];    /* High resolution absolute time in nanosec */
    uint8_t fp_PcbDevNo[4];     /* PCB devno */
    uint8_t fp_lPcbDevNo[4];    /* link PCB devno */
    uint8_t fp_VlanTag[2];      /* vlan tag */
    uint8_t fp_Coreid[2];       /* coreid of the packet */
    uint8_t fp_srcNodeId[2];    /* source node # */
    uint8_t fp_destNodeId[2];   /* destination node # */
    uint8_t fp_clFlags;         /* cluster flags */
    uint8_t fp_src_vmname_len;  /* vm src info */
    uint8_t fp_dst_vmname_len;  /* vm src info */
    uint8_t fp_reserved;
    uint8_t fp_ns_activity[4];
    uint8_t fp_reserved_32[12]; /* Adding more field to reduce wireshark changes every time */
} nspr_pktracefull_v26_t;
#define nspr_pktracefull_v26_s    ((uint32_t)(sizeof(nspr_pktracefull_v26_t)))

/* partial packet trace structure */
typedef struct nspr_pktracepart_v10
{
    nspr_headerdev_v10_t phd; /* performance header */
    uint8_t pp_RelTimeHr[4];   /* High resolution relative time */
    uint8_t pp_PktSizeOrg[2];  /* Original packet size */
    uint8_t pp_PktOffset[2];   /* starting offset in packet */
} nspr_pktracepart_v10_t;
#define nspr_pktracepart_v10_s    ((uint32_t)(sizeof(nspr_pktracepart_v10_t)))

/* new partial packet trace structure */
typedef struct nspr_pktracepart_v20
{
    NSPR_HEADER3B_V20(pp);   /* long performance header */
    uint8_t pp_DevNo;         /* Network Device (NIC) number */
    uint8_t pp_RelTimeHr[4];  /* High resolution relative time */
    uint8_t pp_PktSizeOrg[2]; /* Original packet size */
    uint8_t pp_PktOffset[2];  /* starting offset in packet */
} nspr_pktracepart_v20_t;
#define nspr_pktracepart_v20_s    ((uint32_t)(sizeof(nspr_pktracepart_v20_t)))

/* new partial packet trace structure */
typedef struct nspr_pktracepart_v21
{
    NSPR_HEADER3B_V21(pp);   /* long performance header */
    uint8_t pp_DevNo;         /* Network Device (NIC) number */
    uint8_t pp_RelTimeHr[4];  /* High resolution relative time */
    uint8_t pp_PktSizeOrg[2]; /* Original packet size */
    uint8_t pp_PktOffset[2];  /* starting offset in packet */
    uint8_t pp_PcbDevNo[4];   /* PCB devno */
    uint8_t pp_lPcbDevNo[4];  /* link PCB devno */
} nspr_pktracepart_v21_t;
#define nspr_pktracepart_v21_s    ((uint32_t)(sizeof(nspr_pktracepart_v21_t)))

/* new partial packet trace structure v22 */
typedef struct nspr_pktracepart_v22
{
    NSPR_HEADER3B_V22(pp);   /* long performance header */
    uint8_t pp_DevNo;         /* Network Device (NIC) number */
    uint8_t pp_RelTimeHr[4];  /* High resolution relative time */
    uint8_t pp_PktSizeOrg[2]; /* Original packet size */
    uint8_t pp_PktOffset[2];  /* starting offset in packet */
    uint8_t pp_PcbDevNo[4];   /* PCB devno */
    uint8_t pp_lPcbDevNo[4];  /* link PCB devno */
    uint8_t pp_VlanTag[2];    /* Vlan Tag */
} nspr_pktracepart_v22_t;
#define nspr_pktracepart_v22_s    ((uint32_t)(sizeof(nspr_pktracepart_v22_t)))

typedef struct nspr_pktracepart_v23
{
    NSPR_HEADER3B_V22(pp);   /* long performance header */
    uint8_t pp_DevNo;         /* Network Device (NIC) number */
    uint8_t pp_AbsTimeHr[8];  /* High resolution absolute time */
    uint8_t pp_PktSizeOrg[2]; /* Original packet size */
    uint8_t pp_PktOffset[2];  /* starting offset in packet */
    uint8_t pp_PcbDevNo[4];   /* PCB devno */
    uint8_t pp_lPcbDevNo[4];  /* link PCB devno */
    uint8_t pp_VlanTag[2];    /* vlan tag */
    uint8_t pp_Coreid[2];     /* Coreid of the packet */
} nspr_pktracepart_v23_t;
#define nspr_pktracepart_v23_s    ((uint32_t)(sizeof(nspr_pktracepart_v23_t)))

/* New partial packet trace structure v24 for cluster tracing */
typedef struct nspr_pktracepart_v24
{
    NSPR_HEADER3B_V22(pp);   /* long performance header */
    uint8_t pp_DevNo;         /* Network Device (NIC) number */
    uint8_t pp_AbsTimeHr[8];  /*High resolution absolute time in nanosec*/
    uint8_t pp_PktSizeOrg[2]; /* Original packet size */
    uint8_t pp_PktOffset[2];  /* starting offset in packet */
    uint8_t pp_PcbDevNo[4];   /* PCB devno */
    uint8_t pp_lPcbDevNo[4];  /* link PCB devno */
    uint8_t pp_VlanTag[2];    /* vlan tag */
    uint8_t pp_Coreid[2];     /* Coreid of the packet */
    uint8_t pp_srcNodeId[2];  /* source node # */
    uint8_t pp_destNodeId[2]; /* destination node # */
    uint8_t pp_clFlags;       /* cluster flags */
} nspr_pktracepart_v24_t;
#define nspr_pktracepart_v24_s    ((uint32_t)(sizeof(nspr_pktracepart_v24_t)))

/* New partial packet trace structure v25 for vm info tracing */
typedef struct nspr_pktracepart_v25
{
    NSPR_HEADER3B_V22(pp);    /* long performance header */
    uint8_t pp_DevNo;          /* Network Device (NIC) number */
    uint8_t pp_AbsTimeHr[8];   /*High resolution absolute time in nanosec*/
    uint8_t pp_PktSizeOrg[2];  /* Original packet size */
    uint8_t pp_PktOffset[2];   /* starting offset in packet */
    uint8_t pp_PcbDevNo[4];    /* PCB devno */
    uint8_t pp_lPcbDevNo[4];   /* link PCB devno */
    uint8_t pp_VlanTag[2];     /* vlan tag */
    uint8_t pp_Coreid[2];      /* Coreid of the packet */
    uint8_t pp_srcNodeId[2];   /* source node # */
    uint8_t pp_destNodeId[2];  /* destination node # */
    uint8_t pp_clFlags;        /* cluster flags */
    uint8_t pp_src_vmname_len; /* vm info */
    uint8_t pp_dst_vmname_len; /* vm info */
} nspr_pktracepart_v25_t;
#define nspr_pktracepart_v25_s    ((uint32_t)(sizeof(nspr_pktracepart_v25_t)))

/* New full packet trace structure v30 for multipage spanning data */
typedef struct  nspr_pktracefull_v30
{
    NSPR_HEADER3B_V30(fp);  /* long performance header */
    uint8_t fp_DevNo;   /* Network Device (NIC) number */
    uint8_t fp_AbsTimeHr[8];  /*High resolution absolute time in nanosec*/
    uint8_t fp_PcbDevNo[4];    /* PCB devno */
    uint8_t fp_lPcbDevNo[4];   /* link PCB devno */
    uint8_t fp_PktSizeOrg[2];  /* Original packet size */
    uint8_t fp_VlanTag[2]; /* vlan tag */
    uint8_t fp_Coreid[2]; /* coreid of the packet */
    uint8_t fp_srcNodeId[2]; /* cluster nodeid of the packet */
    uint8_t fp_destNodeId[2];
    uint8_t fp_clFlags;
    uint8_t fp_src_vmname_len;
    uint8_t fp_dst_vmname_len;
    uint8_t fp_reserved[3];
    uint8_t fp_ns_activity[4];
    uint8_t fp_reserved_32[12];
} nspr_pktracefull_v30_t;
#define nspr_pktracefull_v30_s  ((uint32_t)(sizeof(nspr_pktracefull_v30_t)))

/* New full packet trace structure v35 for multipage spanning data */
typedef struct  nspr_pktracefull_v35
{
    NSPR_HEADER3B_V30(fp);  /* long performance header */
    uint8_t fp_DevNo;   /* Network Device (NIC) number */
    uint8_t fp_AbsTimeHr[8];  /*High resolution absolute time in nanosec*/
    uint8_t fp_PcbDevNo[4];    /* PCB devno */
    uint8_t fp_lPcbDevNo[4];   /* link PCB devno */
    uint8_t fp_PktSizeOrg[2];  /* Original packet size */
    uint8_t fp_VlanTag[2]; /* vlan tag */
    uint8_t fp_Coreid[2]; /* coreid of the packet */
    uint8_t fp_headerlen[2];
    uint8_t fp_errorcode;
    uint8_t fp_app;
    uint8_t fp_ns_activity[4];
    uint8_t fp_nextrectype;
} nspr_pktracefull_v35_t;
#define nspr_pktracefull_v35_s  ((uint32_t)(sizeof(nspr_pktracefull_v35_t)))

/* New partial packet trace structure v26 for vm info tracing */
typedef struct nspr_pktracepart_v26
{
    NSPR_HEADER3B_V22(pp);     /* long performance header */
    uint8_t pp_DevNo;           /* Network Device (NIC) number */
    uint8_t pp_AbsTimeHr[8];    /*High resolution absolute time in nanosec*/
    uint8_t pp_PktSizeOrg[2];   /* Original packet size */
    uint8_t pp_PktOffset[2];    /* starting offset in packet */
    uint8_t pp_PcbDevNo[4];     /* PCB devno */
    uint8_t pp_lPcbDevNo[4];    /* link PCB devno */
    uint8_t pp_VlanTag[2];      /* vlan tag */
    uint8_t pp_Coreid[2];       /* Coreid of the packet */
    uint8_t pp_srcNodeId[2];    /* source node # */
    uint8_t pp_destNodeId[2];   /* destination node # */
    uint8_t pp_clFlags;         /* cluster flags */
    uint8_t pp_src_vmname_len;  /* vm info */
    uint8_t pp_dst_vmname_len;  /* vm info */
    uint8_t pp_reserved;
    uint8_t pp_ns_activity[4];
    uint8_t pp_reserved_32[12]; /* Adding more field to reduce wireshark changes every time */
} nspr_pktracepart_v26_t;
#define nspr_pktracepart_v26_s    ((uint32_t)(sizeof(nspr_pktracepart_v26_t)))

#define __TNDO(rec,enumprefix,structname,hdrname)\
    static const uint8_t enumprefix##_##hdrname##_offset = (uint8_t)sizeof(nspr_##structname##_t);

#define __TNO(rec,enumprefix,structprefix,structname,hdrname,structfieldname) \
    static const uint8_t enumprefix##_##hdrname##_offset = (uint8_t)GPOINTER_TO_INT(offsetof(nspr_##structname##_t,structprefix##_##structfieldname));

#define __TNL(rec,enumprefix,structprefix,structname,hdrname,structfieldname) \
    static const uint8_t enumprefix##_##hdrname##_len = (uint8_t)sizeof(((nspr_##structname##_t*)0)->structprefix##_##structfieldname);

#define __TNV1O(rec,enumprefix,structprefix,structname,hdrname,structfieldname) \
    static const uint8_t enumprefix##_##hdrname##_offset = (uint8_t)GPOINTER_TO_INT(offsetof(nspr_##structname##_t,structfieldname));

#define __TNV1L(rec,enumprefix,structprefix,structname,hdrname,structfieldname) \
    static const uint8_t enumprefix##_##hdrname##_len = (uint8_t)sizeof(((nspr_##structname##_t*)0)->structfieldname);

#define TRACE_V10_REC_LEN_OFF(rec,enumprefix,structprefix,structname) \
    __TNV1O(rec,enumprefix,structprefix,structname,dir,phd.ph_RecordType)\
    __TNV1L(rec,enumprefix,structprefix,structname,dir,phd.ph_RecordType)\
    __TNV1O(rec,enumprefix,structprefix,structname,nicno,phd.ph_DevNo)\
    __TNV1L(rec,enumprefix,structprefix,structname,nicno,phd.ph_DevNo)\
    __TNDO(rec,enumprefix,structname,eth)

#define TRACE_V20_REC_LEN_OFF(rec,enumprefix,structprefix,structname) \
    __TNO(rec,enumprefix,structprefix,structname,dir,RecordType)\
    __TNL(rec,enumprefix,structprefix,structname,dir,RecordType)\
    __TNO(rec,enumprefix,structprefix,structname,nicno,DevNo)\
    __TNL(rec,enumprefix,structprefix,structname,nicno,DevNo)\
    __TNDO(rec,enumprefix,structname,eth)

#define TRACE_V21_REC_LEN_OFF(rec,enumprefix,structprefix,structname) \
    TRACE_V20_REC_LEN_OFF(rec,enumprefix,structprefix,structname)\
    __TNO(rec,enumprefix,structprefix,structname,pcb,PcbDevNo)\
    __TNO(rec,enumprefix,structprefix,structname,l_pcb,lPcbDevNo)

#define TRACE_V22_REC_LEN_OFF(rec,enumprefix,structprefix,structname) \
    TRACE_V21_REC_LEN_OFF(rec,enumprefix,structprefix,structname)\
    __TNO(rec,enumprefix,structprefix,structname,vlantag,VlanTag)

#define TRACE_V23_REC_LEN_OFF(rec,enumprefix,structprefix,structname) \
    TRACE_V22_REC_LEN_OFF(rec,enumprefix,structprefix,structname)\
    __TNO(rec,enumprefix,structprefix,structname,coreid,Coreid)

#define TRACE_V24_REC_LEN_OFF(rec,enumprefix,structprefix,structname) \
    TRACE_V23_REC_LEN_OFF(rec,enumprefix,structprefix,structname)\
    __TNO(rec,enumprefix,structprefix,structname,srcnodeid,srcNodeId)\
    __TNO(rec,enumprefix,structprefix,structname,destnodeid,destNodeId)\
    __TNO(rec,enumprefix,structprefix,structname,clflags,clFlags)

#define TRACE_V25_REC_LEN_OFF(rec,enumprefix,structprefix,structname) \
    TRACE_V24_REC_LEN_OFF(rec,enumprefix,structprefix,structname)\
    __TNO(rec,enumprefix,structprefix,structname,src_vmname_len,src_vmname_len)\
    __TNO(rec,enumprefix,structprefix,structname,dst_vmname_len,dst_vmname_len)\
    __TNDO(rec,enumprefix,structname,data)

#define TRACE_V26_REC_LEN_OFF(rec,enumprefix,structprefix,structname) \
    TRACE_V25_REC_LEN_OFF(rec,enumprefix,structprefix,structname)\
    __TNO(rec,enumprefix,structprefix,structname,ns_activity,ns_activity)\

#define TRACE_V30_REC_LEN_OFF(rec, enumprefix, structprefix, structname) \
    TRACE_V26_REC_LEN_OFF(rec,enumprefix,structprefix,structname)\

#define TRACE_V35_REC_LEN_OFF(rec, enumprefix, structprefix, structname) \
    TRACE_V23_REC_LEN_OFF(rec,enumprefix,structprefix,structname)\
    __TNDO(rec,enumprefix,structname,data)\
    __TNO(rec,enumprefix,structprefix,structname,ns_activity,ns_activity)

    TRACE_V10_REC_LEN_OFF(NULL,v10_part,pp,pktracepart_v10)
    TRACE_V10_REC_LEN_OFF(NULL,v10_full,fp,pktracefull_v10)
    TRACE_V20_REC_LEN_OFF(NULL,v20_part,pp,pktracepart_v20)
    TRACE_V20_REC_LEN_OFF(NULL,v20_full,fp,pktracefull_v20)
    TRACE_V21_REC_LEN_OFF(NULL,v21_part,pp,pktracepart_v21)
    TRACE_V21_REC_LEN_OFF(NULL,v21_full,fp,pktracefull_v21)
    TRACE_V22_REC_LEN_OFF(NULL,v22_part,pp,pktracepart_v22)
    TRACE_V22_REC_LEN_OFF(NULL,v22_full,fp,pktracefull_v22)
    TRACE_V23_REC_LEN_OFF(NULL,v23_part,pp,pktracepart_v23)
    TRACE_V23_REC_LEN_OFF(NULL,v23_full,fp,pktracefull_v23)
    TRACE_V24_REC_LEN_OFF(NULL,v24_part,pp,pktracepart_v24)
    TRACE_V24_REC_LEN_OFF(NULL,v24_full,fp,pktracefull_v24)
    TRACE_V25_REC_LEN_OFF(NULL,v25_part,pp,pktracepart_v25)
    TRACE_V25_REC_LEN_OFF(NULL,v25_full,fp,pktracefull_v25)
    TRACE_V26_REC_LEN_OFF(NULL,v26_part,pp,pktracepart_v26)
    TRACE_V26_REC_LEN_OFF(NULL,v26_full,fp,pktracefull_v26)
    TRACE_V30_REC_LEN_OFF(NULL,v30_full,fp,pktracefull_v30)
    TRACE_V35_REC_LEN_OFF(NULL,v35_full,fp,pktracefull_v35)

#undef __TNV1O
#undef __TNV1L
#undef __TNO
#undef __TNDO
#undef __TNL


#define ns_setabstime(nstrace, AbsoluteTime, RelativeTimems) \
    do { \
        (nstrace)->nspm_curtime = AbsoluteTime; \
        (nstrace)->nspm_curtimemsec += RelativeTimems; \
        (nstrace)->nspm_curtimelastmsec = nstrace->nspm_curtimemsec; \
    } while(0)


#define ns_setrelativetime(nstrace, RelativeTimems) \
    do { \
        uint32_t   rsec; \
        (nstrace)->nspm_curtimemsec += RelativeTimems; \
        rsec = (uint32_t)((nstrace)->nspm_curtimemsec - (nstrace)->nspm_curtimelastmsec)/1000; \
        (nstrace)->nspm_curtime += rsec; \
        (nstrace)->nspm_curtimelastmsec += rsec * 1000; \
    } while (0)


typedef struct {
    char   *pnstrace_buf;
    uint32_t page_size;
    int64_t xxx_offset;
    uint32_t nstrace_buf_offset;
    uint32_t nstrace_buflen;
    /* Performance Monitor Time variables */
    uint32_t nspm_curtime;         /* current time since 1970 */
    uint64_t nspm_curtimemsec;     /* current time in milliseconds */
    uint64_t nspm_curtimelastmsec; /* nspm_curtime last update time in milliseconds */
    uint64_t nsg_creltime;
    uint64_t file_size;
} nstrace_t;

/*
 * File versions.
 */
#define NSPM_SIGNATURE_1_0       0
#define NSPM_SIGNATURE_2_0       1
#define NSPM_SIGNATURE_3_0       2
#define NSPM_SIGNATURE_3_5       3
#define NSPM_SIGNATURE_NOMATCH  -1

static int nspm_signature_version(char*, unsigned);
static bool nstrace_read_v10(wtap *wth, wtap_rec *rec, Buffer *buf,
                                 int *err, char **err_info,
                                 int64_t *data_offset);
static bool nstrace_read_v20(wtap *wth, wtap_rec *rec, Buffer *buf,
                                 int *err, char **err_info,
                                 int64_t *data_offset);
static bool nstrace_read_v30(wtap *wth, wtap_rec *rec, Buffer *buf,
                                 int *err, char **err_info,
                                 int64_t *data_offset);
static bool nstrace_seek_read_v10(wtap *wth, int64_t seek_off,
                                      wtap_rec *rec,
                                      Buffer *buf,
                                      int *err, char **err_info);
static bool nstrace_seek_read_v20(wtap *wth, int64_t seek_off,
                                      wtap_rec *rec,
                                      Buffer *buf,
                                      int *err, char **err_info);
static bool nstrace_seek_read_v30(wtap *wth, int64_t seek_off,
                                      wtap_rec *rec,
                                      Buffer *buf,
                                      int *err, char **err_info);
static void nstrace_close(wtap *wth);

static bool nstrace_set_start_time_v10(wtap *wth, int *err,
                                           char **err_info);
static bool nstrace_set_start_time_v20(wtap *wth, int *err,
                                           char **err_info);
static bool nstrace_set_start_time(wtap *wth, int version, int *err,
                                       char **err_info);
static uint64_t ns_hrtime2nsec(uint32_t tm);

static bool nstrace_dump(wtap_dumper *wdh, const wtap_rec *rec,
                             const uint8_t *pd, int *err, char **err_info);


static int nstrace_1_0_file_type_subtype = -1;
static int nstrace_2_0_file_type_subtype = -1;
static int nstrace_3_0_file_type_subtype = -1;
static int nstrace_3_5_file_type_subtype = -1;

void register_nstrace(void);

/*
 * Minimum of the page size and the amount of data left in the file;
 * the last page of a file can be short.
 */
#define GET_READ_PAGE_SIZE(remaining_file_size) ((int32_t)((remaining_file_size>NSPR_PAGESIZE)?NSPR_PAGESIZE:remaining_file_size))
#define GET_READ_PAGE_SIZEV3(remaining_file_size) ((int32_t)((remaining_file_size>NSPR_PAGESIZE_TRACE)?NSPR_PAGESIZE_TRACE:remaining_file_size))

/*
 * Check whether we have enough room to retrieve the data in the caller.
 * If not, we have a malformed file.
 */
static bool nstrace_ensure_buflen(nstrace_t* nstrace, unsigned offset, unsigned len, int *err, char** err_info)
{
    if (offset > nstrace->nstrace_buflen || nstrace->nstrace_buflen - offset < len) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("nstrace: malformed file");
        return false;
    }
    return true;
}

static uint64_t ns_hrtime2nsec(uint32_t tm)
{
    uint32_t   val = tm & NSPR_HRTIME_MASKTM;
    switch(tm & NSPR_HRTIME_MASKFMT)
    {
    case NSPR_HRTIME_SEC:     return (uint64_t)val*1000000000;
    case NSPR_HRTIME_MSEC:    return (uint64_t)val*1000000;
    case NSPR_HRTIME_USEC:    return (uint64_t)val*1000;
    case NSPR_HRTIME_NSEC:    return val;
    }
    return tm;
}

static bool
nstrace_read_page(wtap *wth, int *err, char **err_info)
{
    nstrace_t *nstrace = (nstrace_t *)wth->priv;
    int bytes_read;

    bytes_read = file_read(nstrace->pnstrace_buf, nstrace->page_size, wth->fh);
    if (bytes_read < 0) {
        *err = file_error(wth->fh, err_info);
        return false;
    }
    if (bytes_read == 0) {
        /*
         * EOF.
         */
        *err = 0;
        return false;
    }
    nstrace->nstrace_buflen = (uint32_t)bytes_read;
    return true;
}

/*
** Netscaler trace format open routines
*/
wtap_open_return_val nstrace_open(wtap *wth, int *err, char **err_info)
{
    int file_version;
    char *nstrace_buf;
    int64_t file_size;
    int32_t page_size;
    int bytes_read;
    nstrace_t *nstrace;

    if ((file_size = wtap_file_size(wth, err)) == -1)
        return WTAP_OPEN_ERROR;
    if (file_size == 0)
        return WTAP_OPEN_NOT_MINE;
    /* The size is 64 bits; we assume it fits in 63 bits, so it's positive */

    nstrace_buf = (char *)g_malloc(NSPR_PAGESIZE);
    page_size = NSPR_PAGESIZE;

    /*
     * Read the first page, so we can look for a signature.
     * A short read is OK, as a file may have fewer records
     * than required to fill up a page.
     */
    bytes_read = file_read(nstrace_buf, NSPR_PAGESIZE, wth->fh);
    if (bytes_read < 0) {
        *err = file_error(wth->fh, err_info);
        g_free(nstrace_buf);
        return WTAP_OPEN_ERROR;
    }
    if (bytes_read == 0) {
        /* An empty file. */
        g_free(nstrace_buf);
        return WTAP_OPEN_NOT_MINE;
    }

    /*
     * Scan it for a signature block.
     */
    file_version = nspm_signature_version(nstrace_buf, (unsigned)bytes_read);
    switch (file_version) {

    case NSPM_SIGNATURE_1_0:
        wth->file_type_subtype = nstrace_1_0_file_type_subtype;
        wth->file_encap = WTAP_ENCAP_NSTRACE_1_0;
        break;

    case NSPM_SIGNATURE_2_0:
        wth->file_type_subtype = nstrace_2_0_file_type_subtype;
        wth->file_encap = WTAP_ENCAP_NSTRACE_2_0;
        break;

    case NSPM_SIGNATURE_3_0:
        wth->file_type_subtype = nstrace_3_0_file_type_subtype;
        wth->file_encap = WTAP_ENCAP_NSTRACE_3_0;
        /*
         * File pages are larger in version 3.0; grow the buffer.
         * (XXX - use g_realloc()?)
         */
        g_free(nstrace_buf);
        nstrace_buf = (char *)g_malloc(NSPR_PAGESIZE_TRACE);
        page_size = NSPR_PAGESIZE_TRACE;
        break;

    case NSPM_SIGNATURE_3_5:
        wth->file_type_subtype = nstrace_3_5_file_type_subtype;
        wth->file_encap = WTAP_ENCAP_NSTRACE_3_5;
        /*
         * File pages are larger in version 3.5; grow the buffer.
         * (XXX - use g_realloc()?)
         */
        g_free(nstrace_buf);
        nstrace_buf = (char *)g_malloc(NSPR_PAGESIZE_TRACE);
        page_size = NSPR_PAGESIZE_TRACE;
        break;

    default:
        /* No known signature found, assume it's not NetScaler */
        g_free(nstrace_buf);
        return WTAP_OPEN_NOT_MINE;
    }

    switch (file_version)
    {
    case NSPM_SIGNATURE_1_0:
        wth->subtype_read = nstrace_read_v10;
        wth->subtype_seek_read = nstrace_seek_read_v10;
        break;

    case NSPM_SIGNATURE_2_0:
        wth->subtype_read = nstrace_read_v20;
        wth->subtype_seek_read = nstrace_seek_read_v20;
        break;

    case NSPM_SIGNATURE_3_0:
        wth->subtype_read = nstrace_read_v30;
        wth->subtype_seek_read = nstrace_seek_read_v30;
        break;

    case NSPM_SIGNATURE_3_5:
        wth->subtype_read = nstrace_read_v30;
        wth->subtype_seek_read = nstrace_seek_read_v30;
        break;
    }
    wth->subtype_close = nstrace_close;

    nstrace = g_new(nstrace_t, 1);
    wth->priv = (void *)nstrace;
    nstrace->pnstrace_buf = nstrace_buf;
    nstrace->page_size = page_size;
    nstrace->xxx_offset = 0;
    nstrace->nstrace_buf_offset = 0;
    nstrace->nspm_curtime = 0;
    nstrace->nspm_curtimemsec = 0;
    nstrace->nspm_curtimelastmsec = 0;
    nstrace->nsg_creltime = 0;
    nstrace->file_size = file_size;

    /*
     * Seek back to the beginning of the file and read the first page,
     * now that we know the page size.
     */
    if ((file_seek(wth->fh, 0, SEEK_SET, err)) == -1)
    {
        g_free(nstrace_buf);
        return WTAP_OPEN_ERROR;
    }
    if (!nstrace_read_page(wth, err, err_info)) {
        if (*err == 0) {
            /* EOF, so an empty file. */
            g_free(nstrace_buf);
            return WTAP_OPEN_NOT_MINE;
        }
        /* Read error. */
        return WTAP_OPEN_ERROR;
    }

    /* Set the start time by looking for the abstime record */
    if ((nstrace_set_start_time(wth, file_version, err, err_info)) == false)
    {
        /*
         * No absolute time record seen, so we just reset the read
         * pointer to the start of the file, so we start reading
         * at the first record, rather than skipping records up
         * to and including an absolute time record.
         */
        if (*err != 0)
        {
            /* We got an error reading the records. */
            return WTAP_OPEN_ERROR;
        }
        if ((file_seek(wth->fh, 0, SEEK_SET, err)) == -1)
        {
            return WTAP_OPEN_ERROR;
        }

        /* Read the first page of data */
        if (!nstrace_read_page(wth, err, err_info)) {
            if (*err == 0) {
                /* EOF, so an empty file. */
                g_free(nstrace_buf);
                return WTAP_OPEN_NOT_MINE;
            }
            /* Read error. */
            return WTAP_OPEN_ERROR;
        }

        /* reset the buffer offset */
        nstrace->nstrace_buf_offset = 0;
    }

    wth->file_tsprec = WTAP_TSPREC_NSEC;

    *err = 0;

    /*
     * Add an IDB; we don't know how many interfaces were
     * involved, so we just say one interface, about which
     * we only know the link-layer type, snapshot length,
     * and time stamp resolution.
     */
    wtap_add_generated_idb(wth);

    return WTAP_OPEN_MINE;
}

/*
** Generates a function that checks whether the specified signature
** field, with the specified size, matches the signature string for
** the version specified as an argument to the macro.
**
** The function does so by checking whether the signature string for
** the version in question is a prefix of the signature field.  The
** signature field appears to be a blob of text, with one or more
** lines, with lines separated by '\n', and the last line terminated
** with '\0'.  The first lign is the signature field; it may end with
** '\n', meaning there's another line following it, or it may end
** with '\0', meaning it's the last line.
**
** For that to be true, the field must have a size >= to the size (not
** counting the terminating'\0') of the version's signature string,
** and the first N bytes of the field, where N is the length of the
** version string of the version (again, not counting the terminating
** '\0'), are equal to the version's signature string.
**
** XXX - should this do an exact match rather than a prefix match,
** checking whether either a '\n' or '\0' follows the first line?
*/
#define nspm_signature_func(ver) \
    static uint32_t nspm_signature_isv##ver(char *sigp, size_t sigsize) {\
        size_t versiglen = sizeof(NSPR_SIGSTR_V##ver)-1;\
        return sigsize >= versiglen && strncmp(sigp,NSPR_SIGSTR_V##ver,versiglen) == 0;\
    }

nspm_signature_func(10)
nspm_signature_func(20)
nspm_signature_func(30)
nspm_signature_func(35)

/*
** Scan a page for something that looks like a signature record and,
** if we find one, check the signature against the ones we support.
** If we find one we support, return the file type/subtype for that
** file version.  If we don't find a signature record with a signature
** we support, return NSPM_SIGNATURE_NOMATCH.
**
** We don't know what version the file is, so we can't make
** assumptions about the format of the records.
**
** XXX - can we assume the signature block is the first block?
*/
static int
nspm_signature_version(char *nstrace_buf, unsigned len)
{
    char *dp = nstrace_buf;

    for ( ; len > MIN(nspr_signature_v10_s, nspr_signature_v20_s); dp++, len--)
    {
#define sigv10p    ((nspr_signature_v10_t*)dp)
        /*
         * If this is a V10 signature record, then:
         *
         *    1) we have a full signature record's worth of data in what
         *       remains of the first page;
         *
         *    2) it appears to have a record type of NSPR_SIGNATURE_V10;
         *
         *    3) the length field specifies a length that fits in what
         *       remains of the first page;
         *
         *    4) it also specifies something as large as, or larger than,
         *       the declared size of a V10 signature record.
         *
         * (XXX - are all V10 signature records that size, or might they
         * be smaller, with a shorter signature field?)
         */
        if (len >= nspr_signature_v10_s &&
            (pletoh16(&sigv10p->nsprRecordType) == NSPR_SIGNATURE_V10) &&
            (pletoh16(&sigv10p->nsprRecordSize) <= len) &&
            (pletoh16(&sigv10p->nsprRecordSize) >= nspr_signature_v10_s))
        {
            if ((nspm_signature_isv10(sigv10p->sig_Signature, sizeof sigv10p->sig_Signature)))
                return NSPM_SIGNATURE_1_0;
        }
#undef    sigv10p

#define sigv20p    ((nspr_signature_v20_t*)dp)
        /*
         * If this is a V20-or-later signature record, then:
         *
         *    1) we have a full signature record's worth of data in what
         *       remains of the first page;
         *
         *    2) it appears to have a record type of NSPR_SIGNATURE_V20;
         *
         *    3) the length field specifies a length that fits in what
         *       remains of the first page;
         *
         *    4) it also specifies something as large as, or larger than,
         *       the declared size of a V20 signature record.
         */
        if (len >= nspr_signature_v20_s &&
            (sigv20p->sig_RecordType == NSPR_SIGNATURE_V20) &&
            (sigv20p->sig_RecordSize <= len) &&
            (sigv20p->sig_RecordSize >= nspr_signature_v20_s))
        {
            if (nspm_signature_isv20(sigv20p->sig_Signature, sizeof sigv20p->sig_Signature)){
                return NSPM_SIGNATURE_2_0;
            } else if (nspm_signature_isv30(sigv20p->sig_Signature, sizeof sigv20p->sig_Signature)){
                return NSPM_SIGNATURE_3_0;
            } else if (nspm_signature_isv35(sigv20p->sig_Signature, sizeof sigv20p->sig_Signature)){
                return NSPM_SIGNATURE_3_5;
            }
        }
#undef    sigv20p
    }

    return NSPM_SIGNATURE_NOMATCH;    /* no version found */
}

#define nspr_getv10recordtype(hdp) (pletoh16(&(hdp)->nsprRecordType))
#define nspr_getv10recordsize(hdp) (pletoh16(&(hdp)->nsprRecordSize))
#define nspr_getv20recordtype(hdp) ((hdp)->phd_RecordType)
#define nspr_getv20recordsize(hdp) \
    (uint32_t)(((hdp)->phd_RecordSizeLow & NSPR_V20RECORDSIZE_2BYTES)? \
        (((hdp)->phd_RecordSizeHigh * NSPR_V20RECORDSIZE_2BYTES)+ \
         ((hdp)->phd_RecordSizeLow & ~NSPR_V20RECORDSIZE_2BYTES)) : \
          (hdp)->phd_RecordSizeLow)


/*
 * For a given file version, this defines a routine to find an absolute
 * time record in a file of that version and set the start time based on
 * that.
 *
 * The routine called from the open routine after a file has been recognized
 * as a NetScaler trace.
 */
#define nstrace_set_start_time_ver(ver) \
    bool nstrace_set_start_time_v##ver(wtap *wth, int *err, char **err_info) \
    {\
        nstrace_t *nstrace = (nstrace_t *)wth->priv;\
        char* nstrace_buf = nstrace->pnstrace_buf;\
        uint32_t nstrace_buf_offset = nstrace->nstrace_buf_offset;\
        uint32_t nstrace_buflen = nstrace->nstrace_buflen;\
        uint32_t record_size;\
        do\
        {\
            while (nstrace_buf_offset < nstrace_buflen)\
            {\
                if (!nstrace_ensure_buflen(nstrace, nstrace_buf_offset, sizeof(nspr_hd_v##ver##_t), err, err_info))\
                    return false;\
                nspr_hd_v##ver##_t *fp = (nspr_hd_v##ver##_t *) &nstrace_buf[nstrace_buf_offset];\
                switch (nspr_getv##ver##recordtype(fp))\
                {\
                    case NSPR_ABSTIME_V##ver:\
                        if (!nstrace_ensure_buflen(nstrace, nstrace_buf_offset, sizeof(nspr_abstime_v##ver##_t), err, err_info))\
                            return false;\
                        ns_setabstime(nstrace, pletoh32(&((nspr_abstime_v##ver##_t *) fp)->abs_Time), pletoh16(&((nspr_abstime_v##ver##_t *) fp)->abs_RelTime));\
                        nstrace->nstrace_buf_offset = nstrace_buf_offset + nspr_getv##ver##recordsize(fp);\
                        nstrace->nstrace_buflen = nstrace_buflen;\
                        return true;\
                     case NSPR_UNUSEDSPACE_V10:\
                        nstrace_buf_offset = nstrace_buflen;\
                        break;\
                    default:\
                        record_size = nspr_getv##ver##recordsize(fp);\
                        if (record_size == 0) {\
                            *err = WTAP_ERR_BAD_FILE;\
                            *err_info = g_strdup("nstrace: zero size record found");\
                            return false;\
                        }\
                        nstrace_buf_offset += record_size;\
                }\
            }\
            nstrace_buf_offset = 0;\
            nstrace->xxx_offset += nstrace_buflen;\
            nstrace_buflen = GET_READ_PAGE_SIZE((nstrace->file_size - nstrace->xxx_offset));\
        }while((nstrace_buflen > 0) && (nstrace_read_page(wth, err, err_info)));\
        return false;\
    }

nstrace_set_start_time_ver(10)
nstrace_set_start_time_ver(20)

#undef nspr_getv10recordtype
#undef nspr_getv20recordtype

/*
** Set the start time of the trace file. We look for the first ABSTIME record. We use that
** to set the start time. Apart from that we also make sure that we remember the position of
** the next record after the ABSTIME record. Inorder to report correct time values, all trace
** records before the ABSTIME record are ignored.
*/
static bool nstrace_set_start_time(wtap *wth, int file_version, int *err,
                                       char **err_info)
{
    if (file_version == NSPM_SIGNATURE_1_0)
        return nstrace_set_start_time_v10(wth, err, err_info);
    else if (file_version == NSPM_SIGNATURE_2_0)
        return nstrace_set_start_time_v20(wth, err, err_info);
    else if (file_version == NSPM_SIGNATURE_3_0)
        return nstrace_set_start_time_v20(wth, err, err_info);
    return false;
}

#define __TNDO(rec,enumprefix,structname,hdrname)\
    (rec)->rec_header.packet_header.pseudo_header.nstr.hdrname##_offset = enumprefix##_##hdrname##_offset;

#define __TNO(rec,enumprefix,structprefix,structname,hdrname,structfieldname) \
    (rec)->rec_header.packet_header.pseudo_header.nstr.hdrname##_offset = enumprefix##_##hdrname##_offset;

#define __TNL(rec,enumprefix,structprefix,structname,hdrname,structfieldname) \
    (rec)->rec_header.packet_header.pseudo_header.nstr.hdrname##_len = enumprefix##_##hdrname##_len;

#define __TNV1O(rec,enumprefix,structprefix,structname,hdrname,structfieldname) \
    __TNO(rec,enumprefix,structprefix,structname,hdrname,structfieldname)

#define __TNV1L(rec,enumprefix,structprefix,structname,hdrname,structfieldname) \
    __TNL(rec,enumprefix,structprefix,structname,hdrname,structfieldname)



/*
** Netscaler trace format read routines.
**
** The maximum value of the record data size is 65535, which is less than
** WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't need to check it.
*/
#define TIMEDEFV10(rec,fp,type) \
    do {\
        (rec)->presence_flags = WTAP_HAS_TS;\
        nsg_creltime += ns_hrtime2nsec(pletoh32(&type->type##_RelTimeHr));\
        (rec)->ts.secs = nstrace->nspm_curtime + (uint32_t) (nsg_creltime / 1000000000);\
        (rec)->ts.nsecs = (uint32_t) (nsg_creltime % 1000000000);\
    }while(0)

#define PARTSIZEDEFV10(rec,pp,ver) \
    do {\
        (rec)->presence_flags |= WTAP_HAS_CAP_LEN;\
        (rec)->rec_header.packet_header.len = pletoh16(&pp->pp_PktSizeOrg) + nspr_pktracepart_v##ver##_s;\
        (rec)->rec_header.packet_header.caplen = pletoh16(&pp->nsprRecordSize);\
    }while(0)

#define FULLSIZEDEFV10(rec,fp,ver) \
    do {\
        (rec)->rec_header.packet_header.len = pletoh16(&(fp)->nsprRecordSize);\
        (rec)->rec_header.packet_header.caplen = (rec)->rec_header.packet_header.len;\
    }while(0)

#define PACKET_DESCRIBE(rec,buf,FULLPART,fullpart,ver,type,HEADERVER) \
    do {\
        /* Make sure the record header is entirely contained in the page */\
        if ((nstrace_buflen - nstrace_buf_offset) < sizeof(nspr_pktrace##fullpart##_v##ver##_t)) {\
            *err = WTAP_ERR_BAD_FILE;\
            *err_info = g_strdup("nstrace: record header crosses page boundary");\
            return false;\
        }\
        nspr_pktrace##fullpart##_v##ver##_t *type = (nspr_pktrace##fullpart##_v##ver##_t *) &nstrace_buf[nstrace_buf_offset];\
        /* Check sanity of record size */\
        if (pletoh16(&type->nsprRecordSize) < sizeof *type) {\
            *err = WTAP_ERR_BAD_FILE;\
            *err_info = g_strdup("nstrace: record size is less than record header size");\
            return false;\
        }\
        (rec)->rec_type = REC_TYPE_PACKET;\
        (rec)->block = wtap_block_create(WTAP_BLOCK_PACKET);\
        TIMEDEFV##ver((rec),fp,type);\
        FULLPART##SIZEDEFV##ver((rec),type,ver);\
        TRACE_V##ver##_REC_LEN_OFF((rec),v##ver##_##fullpart,type,pktrace##fullpart##_v##ver);\
        /* Make sure the record is entirely contained in the page */\
        if ((nstrace_buflen - nstrace_buf_offset) < (rec)->rec_header.packet_header.caplen) {\
            *err = WTAP_ERR_BAD_FILE;\
            *err_info = g_strdup("nstrace: record crosses page boundary");\
            return false;\
        }\
        ws_buffer_assure_space((buf), (rec)->rec_header.packet_header.caplen);\
        memcpy(ws_buffer_start_ptr((buf)), type, (rec)->rec_header.packet_header.caplen);\
        *data_offset = nstrace->xxx_offset + nstrace_buf_offset;\
        nstrace->nstrace_buf_offset = nstrace_buf_offset + (rec)->rec_header.packet_header.caplen;\
        nstrace->nstrace_buflen = nstrace_buflen;\
        nstrace->nsg_creltime = nsg_creltime;\
        return true;\
    }while(0)

static bool nstrace_read_v10(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset)
{
    nstrace_t *nstrace = (nstrace_t *)wth->priv;
    uint64_t nsg_creltime = nstrace->nsg_creltime;
    char *nstrace_buf = nstrace->pnstrace_buf;
    uint32_t nstrace_buf_offset = nstrace->nstrace_buf_offset;
    uint32_t nstrace_buflen = nstrace->nstrace_buflen;

    *err = 0;
    *err_info = NULL;
    do
    {
        while ((nstrace_buf_offset < nstrace_buflen) &&
            ((nstrace_buflen - nstrace_buf_offset) >= ((int32_t)sizeof((( nspr_header_v10_t*)&nstrace_buf[nstrace_buf_offset])->ph_RecordType))))
        {

#define GENERATE_CASE_FULL(rec,buf,ver,HEADERVER) \
        case NSPR_PDPKTRACEFULLTX_V##ver:\
        case NSPR_PDPKTRACEFULLTXB_V##ver:\
        case NSPR_PDPKTRACEFULLRX_V##ver:\
            PACKET_DESCRIBE(rec,buf,FULL,full,ver,fp,HEADERVER);

#define GENERATE_CASE_PART(rec,buf,ver,HEADERVER) \
        case NSPR_PDPKTRACEPARTTX_V##ver:\
        case NSPR_PDPKTRACEPARTTXB_V##ver:\
        case NSPR_PDPKTRACEPARTRX_V##ver:\
            PACKET_DESCRIBE(rec,buf,PART,part,ver,pp,HEADERVER);

            switch (pletoh16(&(( nspr_header_v10_t*)&nstrace_buf[nstrace_buf_offset])->ph_RecordType))
            {
                GENERATE_CASE_FULL(rec,buf,10,100)
                GENERATE_CASE_PART(rec,buf,10,100)

#undef GENERATE_CASE_FULL
#undef GENERATE_CASE_PART

                case NSPR_ABSTIME_V10:
                {
                    if (!nstrace_ensure_buflen(nstrace, nstrace_buf_offset, sizeof(nspr_pktracefull_v10_t), err, err_info))
                        return false;
                    nspr_pktracefull_v10_t *fp = (nspr_pktracefull_v10_t *) &nstrace_buf[nstrace_buf_offset];
                    if (pletoh16(&fp->nsprRecordSize) == 0) {
                        *err = WTAP_ERR_BAD_FILE;
                        *err_info = g_strdup("nstrace: zero size record found");
                        return false;
                    }
                    ns_setabstime(nstrace, pletoh32(((nspr_abstime_v10_t *) fp)->abs_Time), pletoh32(&((nspr_abstime_v10_t *) fp)->abs_RelTime));
                    nstrace_buf_offset += pletoh16(&fp->nsprRecordSize);
                    break;
                }

                case NSPR_RELTIME_V10:
                {
                    if (!nstrace_ensure_buflen(nstrace, nstrace_buf_offset, sizeof(nspr_pktracefull_v10_t), err, err_info))
                        return false;
                    nspr_pktracefull_v10_t *fp = (nspr_pktracefull_v10_t *) &nstrace_buf[nstrace_buf_offset];
                    if (pletoh16(&fp->nsprRecordSize) == 0) {
                        *err = WTAP_ERR_BAD_FILE;
                        *err_info = g_strdup("nstrace: zero size record found");
                        return false;
                    }
                    ns_setrelativetime(nstrace, pletoh32(((nspr_abstime_v10_t *) fp)->abs_RelTime));
                    nstrace_buf_offset += pletoh16(&fp->nsprRecordSize);
                    break;
                }

                case NSPR_UNUSEDSPACE_V10:
                    nstrace_buf_offset = nstrace_buflen;
                    break;

                default:
                {
                    if (!nstrace_ensure_buflen(nstrace, nstrace_buf_offset, sizeof(nspr_pktracefull_v10_t), err, err_info))
                        return false;
                    nspr_pktracefull_v10_t *fp = (nspr_pktracefull_v10_t *) &nstrace_buf[nstrace_buf_offset];
                    if (pletoh16(&fp->nsprRecordSize) == 0) {
                        *err = WTAP_ERR_BAD_FILE;
                        *err_info = g_strdup("nstrace: zero size record found");
                        return false;
                    }
                    nstrace_buf_offset += pletoh16(&fp->nsprRecordSize);
                    break;
                }
            }
        }

        nstrace_buf_offset = 0;
        nstrace->xxx_offset += nstrace_buflen;
        nstrace_buflen = GET_READ_PAGE_SIZE((nstrace->file_size - nstrace->xxx_offset));
    }while((nstrace_buflen > 0) && (nstrace_read_page(wth, err, err_info)));

    return false;
}

#undef PACKET_DESCRIBE

#define TIMEDEFV20(rec,fp,type) \
    do {\
        (rec)->presence_flags = WTAP_HAS_TS;\
        nsg_creltime += ns_hrtime2nsec(pletoh32(fp->type##_RelTimeHr));\
        (rec)->ts.secs = nstrace->nspm_curtime + (uint32_t) (nsg_creltime / 1000000000);\
        (rec)->ts.nsecs = (uint32_t) (nsg_creltime % 1000000000);\
    }while(0)

#define TIMEDEFV23(rec,fp,type) \
    do {\
        (rec)->presence_flags = WTAP_HAS_TS;\
        /* access _AbsTimeHr as a 64bit value */\
        nsg_creltime = pletoh64(fp->type##_AbsTimeHr);\
        (rec)->ts.secs = (uint32_t) (nsg_creltime / 1000000000);\
        (rec)->ts.nsecs = (uint32_t) (nsg_creltime % 1000000000);\
    }while(0)

#define TIMEDEFV21(rec,fp,type) TIMEDEFV20(rec,fp,type)
#define TIMEDEFV22(rec,fp,type) TIMEDEFV20(rec,fp,type)
#define TIMEDEFV24(rec,fp,type) TIMEDEFV23(rec,fp,type)
#define TIMEDEFV25(rec,fp,type) TIMEDEFV24(rec,fp,type)
#define TIMEDEFV26(rec,fp,type) TIMEDEFV24(rec,fp,type)

/*
** The maximum value of the record data size is 65535, which is less than
** WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't need to check it.
*/
#define PARTSIZEDEFV20(rec,pp,ver) \
    do {\
        (rec)->presence_flags |= WTAP_HAS_CAP_LEN;\
        (rec)->rec_header.packet_header.len = pletoh16(&pp->pp_PktSizeOrg) + nspr_pktracepart_v##ver##_s;\
        (rec)->rec_header.packet_header.caplen = nspr_getv20recordsize((nspr_hd_v20_t *)pp);\
    }while(0)

#define PARTSIZEDEFV21(rec,pp,ver) PARTSIZEDEFV20(rec,pp,ver)
#define PARTSIZEDEFV22(rec,pp,ver) PARTSIZEDEFV20(rec,pp,ver)
#define PARTSIZEDEFV23(rec,pp,ver) PARTSIZEDEFV20(rec,pp,ver)
#define PARTSIZEDEFV24(rec,pp,ver) PARTSIZEDEFV20(rec,pp,ver)
#define PARTSIZEDEFV25(rec,pp,ver) PARTSIZEDEFV20(rec,pp,ver)
#define PARTSIZEDEFV26(rec,pp,ver) PARTSIZEDEFV20(rec,pp,ver)

#define FULLSIZEDEFV20(rec,fp,ver)\
    do {\
        (rec)->rec_header.packet_header.len = nspr_getv20recordsize((nspr_hd_v20_t *)fp);\
        (rec)->rec_header.packet_header.caplen = (rec)->rec_header.packet_header.len;\
    }while(0)

#define FULLSIZEDEFV21(rec,fp,ver) FULLSIZEDEFV20(rec,fp,ver)
#define FULLSIZEDEFV22(rec,fp,ver) FULLSIZEDEFV20(rec,fp,ver)
#define FULLSIZEDEFV23(rec,fp,ver) FULLSIZEDEFV20(rec,fp,ver)
#define FULLSIZEDEFV24(rec,fp,ver) FULLSIZEDEFV20(rec,fp,ver)
#define FULLSIZEDEFV25(rec,fp,ver) FULLSIZEDEFV20(rec,fp,ver)
#define FULLSIZEDEFV26(rec,fp,ver) FULLSIZEDEFV20(rec,fp,ver)

#define PACKET_DESCRIBE(rec,buf,FULLPART,ver,enumprefix,type,structname,HEADERVER)\
    do {\
        nspr_##structname##_t *fp= (nspr_##structname##_t*)&nstrace_buf[nstrace_buf_offset];\
        /* Make sure the record header is entirely contained in the page */\
        if ((nstrace_buflen - nstrace_buf_offset) < sizeof *fp) {\
            *err = WTAP_ERR_BAD_FILE;\
            *err_info = g_strdup("nstrace: record header crosses page boundary");\
            return false;\
        }\
        /* Check sanity of record size */\
        if (nspr_getv20recordsize((nspr_hd_v20_t *)fp) < sizeof *fp) {\
            *err = WTAP_ERR_BAD_FILE;\
            *err_info = g_strdup("nstrace: record size is less than record header size");\
            return false;\
        }\
        (rec)->rec_type = REC_TYPE_PACKET;\
        (rec)->block = wtap_block_create(WTAP_BLOCK_PACKET);\
        TIMEDEFV##ver((rec),fp,type);\
        FULLPART##SIZEDEFV##ver((rec),fp,ver);\
        TRACE_V##ver##_REC_LEN_OFF((rec),enumprefix,type,structname);\
        (rec)->rec_header.packet_header.pseudo_header.nstr.rec_type = NSPR_HEADER_VERSION##HEADERVER;\
        /* Make sure the record is entirely contained in the page */\
        if ((nstrace_buflen - nstrace_buf_offset) < (rec)->rec_header.packet_header.caplen) {\
            *err = WTAP_ERR_BAD_FILE;\
            *err_info = g_strdup("nstrace: record crosses page boundary");\
            return false;\
        }\
        ws_buffer_assure_space((buf), (rec)->rec_header.packet_header.caplen);\
        memcpy(ws_buffer_start_ptr((buf)), fp, (rec)->rec_header.packet_header.caplen);\
        *data_offset = nstrace->xxx_offset + nstrace_buf_offset;\
        nstrace->nstrace_buf_offset = nstrace_buf_offset + nspr_getv20recordsize((nspr_hd_v20_t *)fp);\
        nstrace->nstrace_buflen = nstrace_buflen;\
        nstrace->nsg_creltime = nsg_creltime;\
        return true;\
    }while(0)

static bool nstrace_read_v20(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset)
{
    nstrace_t *nstrace = (nstrace_t *)wth->priv;
    uint64_t nsg_creltime = nstrace->nsg_creltime;
    char *nstrace_buf = nstrace->pnstrace_buf;
    uint32_t nstrace_buf_offset = nstrace->nstrace_buf_offset;
    uint32_t nstrace_buflen = nstrace->nstrace_buflen;

    *err = 0;
    *err_info = NULL;
    do
    {
        while ((nstrace_buf_offset < nstrace_buflen) &&
            ((nstrace_buflen - nstrace_buf_offset) >= ((int32_t)sizeof((( nspr_hd_v20_t*)&nstrace_buf[nstrace_buf_offset])->phd_RecordType))))
        {
            switch ((( nspr_hd_v20_t*)&nstrace_buf[nstrace_buf_offset])->phd_RecordType)
            {

#define GENERATE_CASE_FULL(rec,buf,ver,HEADERVER) \
        case NSPR_PDPKTRACEFULLTX_V##ver:\
        case NSPR_PDPKTRACEFULLTXB_V##ver:\
        case NSPR_PDPKTRACEFULLRX_V##ver:\
            PACKET_DESCRIBE(rec,buf,FULL,ver,v##ver##_full,fp,pktracefull_v##ver,HEADERVER);

#define GENERATE_CASE_FULL_V25(rec,buf,ver,HEADERVER) \
        case NSPR_PDPKTRACEFULLTX_V##ver:\
        case NSPR_PDPKTRACEFULLTXB_V##ver:\
        case NSPR_PDPKTRACEFULLRX_V##ver:\
        case NSPR_PDPKTRACEFULLNEWRX_V##ver:\
            PACKET_DESCRIBE(rec,buf,FULL,ver,v##ver##_full,fp,pktracefull_v##ver,HEADERVER);

#define GENERATE_CASE_PART(rec,buf,ver,HEADERVER) \
        case NSPR_PDPKTRACEPARTTX_V##ver:\
        case NSPR_PDPKTRACEPARTTXB_V##ver:\
        case NSPR_PDPKTRACEPARTRX_V##ver:\
            PACKET_DESCRIBE(rec,buf,PART,ver,v##ver##_part,pp,pktracepart_v##ver,HEADERVER);

#define GENERATE_CASE_PART_V25(rec,buf,ver,HEADERVER) \
        case NSPR_PDPKTRACEPARTTX_V##ver:\
        case NSPR_PDPKTRACEPARTTXB_V##ver:\
        case NSPR_PDPKTRACEPARTRX_V##ver:\
        case NSPR_PDPKTRACEPARTNEWRX_V##ver:\
            PACKET_DESCRIBE(rec,buf,PART,ver,v##ver##_part,pp,pktracepart_v##ver,HEADERVER);

                GENERATE_CASE_FULL(rec,buf,20,200);
                GENERATE_CASE_PART(rec,buf,20,200);
                GENERATE_CASE_FULL(rec,buf,21,201);
                GENERATE_CASE_PART(rec,buf,21,201);
                GENERATE_CASE_FULL(rec,buf,22,202);
                GENERATE_CASE_PART(rec,buf,22,202);
                GENERATE_CASE_FULL(rec,buf,23,203);
                GENERATE_CASE_PART(rec,buf,23,203);
                GENERATE_CASE_FULL_V25(rec,buf,24,204);
                GENERATE_CASE_PART_V25(rec,buf,24,204);
                GENERATE_CASE_FULL_V25(rec,buf,25,205);
                GENERATE_CASE_PART_V25(rec,buf,25,205);
                GENERATE_CASE_FULL_V25(rec,buf,26,206);
                GENERATE_CASE_PART_V25(rec,buf,26,206);

#undef GENERATE_CASE_FULL
#undef GENERATE_CASE_FULL_V25
#undef GENERATE_CASE_PART
#undef GENERATE_CASE_PART_V25

                case NSPR_ABSTIME_V20:
                {
                    if (!nstrace_ensure_buflen(nstrace, nstrace_buf_offset, sizeof(nspr_pktracefull_v20_t), err, err_info))
                        return false;
                    nspr_pktracefull_v20_t *fp20 = (nspr_pktracefull_v20_t *) &nstrace_buf[nstrace_buf_offset];
                    if (nspr_getv20recordsize((nspr_hd_v20_t *)fp20) == 0) {
                        *err = WTAP_ERR_BAD_FILE;
                        *err_info = g_strdup("nstrace: zero size record found");
                        return false;
                    }
                    if (!nstrace_ensure_buflen(nstrace, nstrace_buf_offset, sizeof(nspr_hd_v20_t), err, err_info))
                        return false;
                    nstrace_buf_offset += nspr_getv20recordsize((nspr_hd_v20_t *)fp20);
                    if (!nstrace_ensure_buflen(nstrace, nstrace_buf_offset, sizeof(nspr_abstime_v20_t), err, err_info))
                        return false;
                    ns_setabstime(nstrace, pletoh32(&((nspr_abstime_v20_t *) fp20)->abs_Time), pletoh16(&((nspr_abstime_v20_t *) fp20)->abs_RelTime));
                    break;
                }

                case NSPR_RELTIME_V20:
                {
                    if (!nstrace_ensure_buflen(nstrace, nstrace_buf_offset, sizeof(nspr_pktracefull_v20_t), err, err_info))
                        return false;
                    nspr_pktracefull_v20_t *fp20 = (nspr_pktracefull_v20_t *) &nstrace_buf[nstrace_buf_offset];
                    if (nspr_getv20recordsize((nspr_hd_v20_t *)fp20) == 0) {
                        *err = WTAP_ERR_BAD_FILE;
                        *err_info = g_strdup("nstrace: zero size record found");
                        return false;
                    }
                    if (!nstrace_ensure_buflen(nstrace, nstrace_buf_offset, sizeof(nspr_abstime_v20_t), err, err_info))
                        return false;
                    ns_setrelativetime(nstrace, pletoh16(&((nspr_abstime_v20_t *) fp20)->abs_RelTime));
                    nstrace_buf_offset += nspr_getv20recordsize((nspr_hd_v20_t *)fp20);
                    break;
                  }

                case NSPR_UNUSEDSPACE_V20:
                {
                    if (nstrace_buf_offset >= NSPR_PAGESIZE/2)
                        nstrace_buf_offset = nstrace_buflen;
                    else
                        nstrace_buf_offset = NSPR_PAGESIZE/2;
                    break;
                  }

                default:
                {
                    if (!nstrace_ensure_buflen(nstrace, nstrace_buf_offset, sizeof(nspr_pktracefull_v20_t), err, err_info))
                        return false;
                    nspr_pktracefull_v20_t *fp20 = (nspr_pktracefull_v20_t *) &nstrace_buf[nstrace_buf_offset];
                    if (nspr_getv20recordsize((nspr_hd_v20_t *)fp20) == 0) {
                        *err = WTAP_ERR_BAD_FILE;
                        *err_info = g_strdup("nstrace: zero size record found");
                        return false;
                    }
                    nstrace_buf_offset += nspr_getv20recordsize((nspr_hd_v20_t *)fp20);
                    break;
                }
            }
        }

        nstrace_buf_offset = 0;
        nstrace->xxx_offset += nstrace_buflen;
        nstrace_buflen = GET_READ_PAGE_SIZE((nstrace->file_size - nstrace->xxx_offset));
    }while((nstrace_buflen > 0) && (nstrace_read_page(wth, err, err_info)));

    return false;
}

#undef PACKET_DESCRIBE

#define SETETHOFFSET_35(rec)\
  (rec)->rec_header.packet_header.pseudo_header.nstr.eth_offset = pletoh16(&fp->fp_headerlen);\

#define SETETHOFFSET_30(rec) ;\

#define TIMEDEFV30(rec,fp,type) \
    do {\
        (rec)->presence_flags = WTAP_HAS_TS;\
        /* access _AbsTimeHr as a 64bit value */\
        nsg_creltime = pletoh64(fp->type##_AbsTimeHr);\
        (rec)->ts.secs = (uint32_t) (nsg_creltime / 1000000000);\
        (rec)->ts.nsecs = (uint32_t) (nsg_creltime % 1000000000);\
    }while(0)

#define TIMEDEFV35 TIMEDEFV30

/*
** The maximum value of the record data size is 65535, which is less than
** WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't need to check it.
*/
#define FULLSIZEDEFV30(rec,fp,ver)\
    do {\
        (rec)->presence_flags |= WTAP_HAS_CAP_LEN;\
        (rec)->rec_header.packet_header.len = pletoh16(&fp->fp_PktSizeOrg) + nspr_pktracefull_v##ver##_s + fp->fp_src_vmname_len + fp->fp_dst_vmname_len;\
        (rec)->rec_header.packet_header.caplen = nspr_getv20recordsize((nspr_hd_v20_t *)fp);\
    }while(0)

#define FULLSIZEDEFV35(rec,fp,ver)\
    do {\
        (rec)->presence_flags |= WTAP_HAS_CAP_LEN;\
        (rec)->rec_header.packet_header.len = pletoh16(&fp->fp_PktSizeOrg) + pletoh16(&fp->fp_headerlen);\
        (rec)->rec_header.packet_header.caplen = nspr_getv20recordsize((nspr_hd_v20_t *)fp);\
    }while(0)

#define PACKET_DESCRIBE(rec,buf,FULLPART,ver,enumprefix,type,structname,HEADERVER)\
    do {\
        /* Make sure the record header is entirely contained in the page */\
        if ((nstrace->nstrace_buflen - nstrace_buf_offset) < sizeof(nspr_##structname##_t)) {\
            *err = WTAP_ERR_BAD_FILE;\
            *err_info = g_strdup("nstrace: record header crosses page boundary");\
            g_free(nstrace_tmpbuff);\
            return false;\
        }\
        nspr_##structname##_t *fp = (nspr_##structname##_t *) &nstrace_buf[nstrace_buf_offset];\
        (rec)->rec_type = REC_TYPE_PACKET;\
        (rec)->block = wtap_block_create(WTAP_BLOCK_PACKET);\
        TIMEDEFV##ver((rec),fp,type);\
        FULLPART##SIZEDEFV##ver((rec),fp,ver);\
        TRACE_V##ver##_REC_LEN_OFF((rec),enumprefix,type,structname);\
        SETETHOFFSET_##ver(rec)\
        (rec)->rec_header.packet_header.pseudo_header.nstr.rec_type = NSPR_HEADER_VERSION##HEADERVER;\
        /* Check sanity of record size */\
        if ((rec)->rec_header.packet_header.caplen < sizeof *fp) {\
            *err = WTAP_ERR_BAD_FILE;\
            *err_info = g_strdup("nstrace: record size is less than record header size");\
            g_free(nstrace_tmpbuff);\
            return false;\
        }\
        ws_buffer_assure_space((buf), (rec)->rec_header.packet_header.caplen);\
        *data_offset = nstrace->xxx_offset + nstrace_buf_offset;\
        /* Copy record header */\
        while (nstrace_tmpbuff_off < nspr_##structname##_s) {\
            if (nstrace_buf_offset >= nstrace_buflen) {\
                *err = WTAP_ERR_BAD_FILE;\
                *err_info = g_strdup("nstrace: malformed file");\
                g_free(nstrace_tmpbuff);\
                return false;\
            }\
            nstrace_tmpbuff[nstrace_tmpbuff_off++] = nstrace_buf[nstrace_buf_offset++];\
        }\
        nst_dataSize = nspr_getv20recordsize(hdp);\
        rec_size = nst_dataSize - nstrace_tmpbuff_off;\
        nsg_nextPageOffset = ((nstrace_buf_offset + rec_size) >= (unsigned)nstrace->nstrace_buflen) ?\
        ((nstrace_buf_offset + rec_size) - (NSPR_PAGESIZE_TRACE - 1)) : 0;\
        /* Copy record data */\
        while (nsg_nextPageOffset) {\
            /* Copy everything from this page */\
            while (nstrace_buf_offset < nstrace->nstrace_buflen) {\
                nstrace_tmpbuff[nstrace_tmpbuff_off++] = nstrace_buf[nstrace_buf_offset++];\
            }\
            nstrace->xxx_offset += nstrace_buflen;\
            nstrace_buflen = NSPR_PAGESIZE_TRACE;\
            /* Read the next page */\
            bytes_read = file_read(nstrace_buf, NSPR_PAGESIZE_TRACE, wth->fh);\
            if ( !file_eof(wth->fh) && bytes_read != NSPR_PAGESIZE_TRACE) {\
                g_free(nstrace_tmpbuff);\
                return false;\
            } else {\
                nstrace_buf_offset = 0;\
            }\
            nstrace_buflen = bytes_read;\
            rec_size = nst_dataSize - nstrace_tmpbuff_off;\
            nsg_nextPageOffset = ((nstrace_buf_offset + rec_size) >= (unsigned)nstrace->nstrace_buflen) ?\
            ((nstrace_buf_offset + rec_size) - (NSPR_PAGESIZE_TRACE- 1)): 0;\
        } \
        /* Copy the rest of the record */\
        while (nstrace_tmpbuff_off < nst_dataSize) {\
            nstrace_tmpbuff[nstrace_tmpbuff_off++] = nstrace_buf[nstrace_buf_offset++];\
        }\
        memcpy(ws_buffer_start_ptr((buf)), nstrace_tmpbuff, (rec)->rec_header.packet_header.caplen);\
        nstrace->nstrace_buf_offset = nstrace_buf_offset;\
        nstrace->nstrace_buflen = nstrace_buflen;\
        nstrace->nsg_creltime = nsg_creltime;\
        g_free(nstrace_tmpbuff);\
        return true;\
    } while(0)

static bool nstrace_read_v30(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset)
{
    nstrace_t *nstrace = (nstrace_t *)wth->priv;
    uint64_t nsg_creltime;
    char *nstrace_buf = nstrace->pnstrace_buf;
    uint32_t nstrace_buf_offset = nstrace->nstrace_buf_offset;
    uint32_t nstrace_buflen = nstrace->nstrace_buflen;
    uint8_t* nstrace_tmpbuff;
    uint32_t nstrace_tmpbuff_off=0,nst_dataSize=0,rec_size=0,nsg_nextPageOffset=0;
    nspr_hd_v20_t *hdp;
    int bytes_read = 0;

    *err = 0;
    *err_info = NULL;
    if(nstrace_buflen == 0){
      return false; /* Reached End Of File */
    }

    nstrace_tmpbuff = (uint8_t*)g_malloc(65536);

    do
    {

        if (nstrace_buf_offset >= nstrace_buflen) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup("nstrace: malformed file");
            g_free(nstrace_tmpbuff);
            return false;
        }

        if (!nstrace_buf[nstrace_buf_offset] && nstrace_buf_offset <= NSPR_PAGESIZE_TRACE){
            nstrace_buf_offset = NSPR_PAGESIZE_TRACE;
        }
        if (file_eof(wth->fh) && bytes_read > 0 && bytes_read < NSPR_PAGESIZE_TRACE){
            memset(&nstrace_buf[bytes_read], 0, NSPR_PAGESIZE_TRACE-bytes_read);
        }
        while ((nstrace_buf_offset < NSPR_PAGESIZE_TRACE) &&
            nstrace_buf[nstrace_buf_offset])
        {
            if (!nstrace_ensure_buflen(nstrace, nstrace_buf_offset, sizeof(nspr_hd_v20_t), err, err_info)) {
                g_free(nstrace_tmpbuff);
                return false;
            }
            hdp = (nspr_hd_v20_t *) &nstrace_buf[nstrace_buf_offset];
            if (nspr_getv20recordsize(hdp) == 0) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup("nstrace: zero size record found");
                g_free(nstrace_tmpbuff);
                return false;
            }
            switch (hdp->phd_RecordType)
            {

#define GENERATE_CASE_FULL_V30(rec,buf,ver,HEADERVER) \
        case NSPR_PDPKTRACEFULLTX_V##ver:\
        case NSPR_PDPKTRACEFULLTXB_V##ver:\
        case NSPR_PDPKTRACEFULLRX_V##ver:\
        case NSPR_PDPKTRACEFULLNEWRX_V##ver:\
            PACKET_DESCRIBE(rec,buf,FULL,ver,v##ver##_full,fp,pktracefull_v##ver,HEADERVER);

                GENERATE_CASE_FULL_V30(rec,buf,30,300);

#undef GENERATE_CASE_FULL_V30

#define GENERATE_CASE_FULL_V35(rec,buf,ver,HEADERVER) \
        case NSPR_PDPKTRACEFULLTX_V##ver:\
        case NSPR_PDPKTRACEFULLTXB_V##ver:\
        case NSPR_PDPKTRACEFULLRX_V##ver:\
        case NSPR_PDPKTRACEFULLNEWRX_V##ver:\
            PACKET_DESCRIBE(rec,buf,FULL,ver,v##ver##_full,fp,pktracefull_v##ver,HEADERVER);
                GENERATE_CASE_FULL_V35(rec,buf,35,350);

#undef GENERATE_CASE_FULL_V35

                case NSPR_ABSTIME_V20:
                {
                    nstrace_buf_offset += nspr_getv20recordsize(hdp);
                    if (!nstrace_ensure_buflen(nstrace, nstrace_buf_offset, sizeof(nspr_abstime_v20_t), err, err_info)) {
                        g_free(nstrace_tmpbuff);
                        return false;
                    }
                    ns_setabstime(nstrace, pletoh32(&((nspr_abstime_v20_t *) &nstrace_buf[nstrace_buf_offset])->abs_Time), pletoh16(&((nspr_abstime_v20_t *) &nstrace_buf[nstrace_buf_offset])->abs_RelTime));
                    break;
                }

                case NSPR_RELTIME_V20:
                {
                    if (!nstrace_ensure_buflen(nstrace, nstrace_buf_offset, sizeof(nspr_abstime_v20_t), err, err_info)) {
                        g_free(nstrace_tmpbuff);
                        return false;
                    }
                    ns_setrelativetime(nstrace, pletoh16(&((nspr_abstime_v20_t *) &nstrace_buf[nstrace_buf_offset])->abs_RelTime));
                    nstrace_buf_offset += nspr_getv20recordsize(hdp);
                    break;
                }

                default:
                {
                    if (!nstrace_ensure_buflen(nstrace, nstrace_buf_offset, sizeof(nspr_hd_v20_t), err, err_info)) {
                        g_free(nstrace_tmpbuff);
                        return false;
                    }
                    nstrace_buf_offset += nspr_getv20recordsize(hdp);
                    break;
                }
            }
        }
        nstrace_buf_offset = 0;
        nstrace->xxx_offset += nstrace_buflen;
        nstrace_buflen = NSPR_PAGESIZE_TRACE;
    } while((nstrace_buflen > 0) && (bytes_read = file_read(nstrace_buf, nstrace_buflen, wth->fh)) > 0 && (file_eof(wth->fh) || (uint32_t)bytes_read == nstrace_buflen));

    if (bytes_read < 0)
        *err = file_error(wth->fh, err_info);
    else
        *err = 0;
    g_free(nstrace_tmpbuff);
    return false;
}

#undef PACKET_DESCRIBE

/*
 * XXX - for these, we can't set the time stamp in the seek-read
 * routine, because the time stamps are relative.
 */
#undef TIMEDEFV10
#define TIMEDEFV10(rec,fp,type) \
    do {\
        (rec)->presence_flags = 0;\
    }while(0)

#define PACKET_DESCRIBE(rec,FULLPART,fullpart,ver,type,HEADERVER) \
    do {\
        nspr_pktrace##fullpart##_v##ver##_t *type = (nspr_pktrace##fullpart##_v##ver##_t *) pd;\
        (rec)->rec_type = REC_TYPE_PACKET;\
        (rec)->block = wtap_block_create(WTAP_BLOCK_PACKET);\
        TIMEDEFV##ver((rec),fp,type);\
        FULLPART##SIZEDEFV##ver((rec),type,ver);\
        TRACE_V##ver##_REC_LEN_OFF(rec,v##ver##_##fullpart,type,pktrace##fullpart##_v##ver);\
        (rec)->rec_header.packet_header.pseudo_header.nstr.rec_type = NSPR_HEADER_VERSION##HEADERVER;\
    }while(0)

static bool nstrace_seek_read_v10(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
    nspr_hd_v10_t hdr;
    unsigned record_length;
    uint8_t *pd;
    unsigned int bytes_to_read;

    *err = 0;

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return false;

    /*
    ** Read the record header.
    */
    if (!wtap_read_bytes(wth->random_fh, (void *)&hdr, sizeof hdr,
                         err, err_info))
        return false;

    /*
    ** Get the record length.
    */
    record_length = nspr_getv10recordsize(&hdr);

    /*
    ** Copy the header to the buffer and read the rest of the record..
    */
    ws_buffer_assure_space(buf, record_length);
    pd = ws_buffer_start_ptr(buf);
    memcpy(pd, (void *)&hdr, sizeof hdr);
    if (record_length > sizeof hdr) {
        bytes_to_read = (unsigned int)(record_length - sizeof hdr);
        if (!wtap_read_bytes(wth->random_fh, pd + sizeof hdr, bytes_to_read,
                             err, err_info))
            return false;
    }

    /*
    ** Fill in what part of the struct wtap_rec we can.
    */
#define GENERATE_CASE_FULL(rec,type,HEADERVER) \
        case NSPR_PDPKTRACEFULLTX_V##type:\
        case NSPR_PDPKTRACEFULLTXB_V##type:\
        case NSPR_PDPKTRACEFULLRX_V##type:\
            PACKET_DESCRIBE(rec,FULL,full,type,fp,HEADERVER);\
            break;

#define GENERATE_CASE_PART(rec,type,HEADERVER) \
        case NSPR_PDPKTRACEPARTTX_V##type:\
        case NSPR_PDPKTRACEPARTTXB_V##type:\
        case NSPR_PDPKTRACEPARTRX_V##type:\
            PACKET_DESCRIBE(rec,PART,part,type,pp,HEADERVER);\
            break;

    switch (pletoh16(&(( nspr_header_v10_t*)pd)->ph_RecordType))
    {
        GENERATE_CASE_FULL(rec,10,100)
        GENERATE_CASE_PART(rec,10,100)
    }

#undef GENERATE_CASE_FULL
#undef GENERATE_CASE_PART

    return true;
}

#undef PACKET_DESCRIBE

/*
 * XXX - for these, we can't set the time stamp in the seek-read
 * routine, because the time stamps are relative.
 */
#undef TIMEDEFV20
#define TIMEDEFV20(rec,fp,type) \
    do {\
        (rec)->presence_flags = 0;\
    }while(0)

#undef TIMEDEFV21
#undef TIMEDEFV22
#define TIMEDEFV21(rec,fp,type) TIMEDEFV20(rec,fp,type)
#define TIMEDEFV22(rec,fp,type) TIMEDEFV20(rec,fp,type)

#define PACKET_DESCRIBE(rec,FULLPART,ver,enumprefix,type,structname,HEADERVER)\
    do {\
        nspr_##structname##_t *fp= (nspr_##structname##_t*)pd;\
        (rec)->rec_type = REC_TYPE_PACKET;\
        (rec)->block = wtap_block_create(WTAP_BLOCK_PACKET);\
        TIMEDEFV##ver((rec),fp,type);\
        FULLPART##SIZEDEFV##ver((rec),fp,ver);\
        TRACE_V##ver##_REC_LEN_OFF((rec),enumprefix,type,structname);\
        (rec)->rec_header.packet_header.pseudo_header.nstr.rec_type = NSPR_HEADER_VERSION##HEADERVER;\
        return true;\
    }while(0)

static bool nstrace_seek_read_v20(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
    nspr_hd_v20_t hdr;
    unsigned record_length;
    unsigned hdrlen;
    uint8_t *pd;
    unsigned int bytes_to_read;
    uint64_t nsg_creltime;

    *err = 0;

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return false;

    /*
    ** Read the first 2 bytes of the record header.
    */
    if (!wtap_read_bytes(wth->random_fh, (void *)&hdr, 2, err, err_info))
        return false;
    hdrlen = 2;

    /*
    ** Is there a third byte?  If so, read it.
    */
    if (hdr.phd_RecordSizeLow & NSPR_V20RECORDSIZE_2BYTES) {
        if (!wtap_read_bytes(wth->random_fh, (void *)&hdr.phd_RecordSizeHigh, 1,
                             err, err_info))
            return false;
        hdrlen = 3;
    }

    /*
    ** Get the record length.
    */
    record_length = nspr_getv20recordsize(&hdr);

    /*
    ** Copy the header to the buffer and read the rest of the record..
    */
    ws_buffer_assure_space(buf, record_length);
    pd = ws_buffer_start_ptr(buf);
    memcpy(pd, (void *)&hdr, hdrlen);
    if (record_length > hdrlen) {
        bytes_to_read = (unsigned int)(record_length - hdrlen);
        if (!wtap_read_bytes(wth->random_fh, pd + hdrlen, bytes_to_read,
                             err, err_info))
            return false;
    }

#define GENERATE_CASE_FULL(rec,ver,HEADERVER) \
        case NSPR_PDPKTRACEFULLTX_V##ver:\
        case NSPR_PDPKTRACEFULLTXB_V##ver:\
        case NSPR_PDPKTRACEFULLRX_V##ver:\
            PACKET_DESCRIBE(rec,FULL,ver,v##ver##_full,fp,pktracefull_v##ver,HEADERVER);

#define GENERATE_CASE_FULL_V25(rec,ver,HEADERVER) \
        case NSPR_PDPKTRACEFULLTX_V##ver:\
        case NSPR_PDPKTRACEFULLTXB_V##ver:\
        case NSPR_PDPKTRACEFULLRX_V##ver:\
        case NSPR_PDPKTRACEFULLNEWRX_V##ver:\
            PACKET_DESCRIBE(rec,FULL,ver,v##ver##_full,fp,pktracefull_v##ver,HEADERVER);

#define GENERATE_CASE_PART(rec,ver,HEADERVER) \
        case NSPR_PDPKTRACEPARTTX_V##ver:\
        case NSPR_PDPKTRACEPARTTXB_V##ver:\
        case NSPR_PDPKTRACEPARTRX_V##ver:\
            PACKET_DESCRIBE(rec,PART,ver,v##ver##_part,pp,pktracepart_v##ver,HEADERVER);

#define GENERATE_CASE_PART_V25(rec,ver,HEADERVER) \
        case NSPR_PDPKTRACEPARTTX_V##ver:\
        case NSPR_PDPKTRACEPARTTXB_V##ver:\
        case NSPR_PDPKTRACEPARTRX_V##ver:\
        case NSPR_PDPKTRACEPARTNEWRX_V##ver:\
            PACKET_DESCRIBE(rec,PART,ver,v##ver##_part,pp,pktracepart_v##ver,HEADERVER);

    switch ((( nspr_hd_v20_t*)pd)->phd_RecordType)
    {
        GENERATE_CASE_FULL(rec,20,200)
        GENERATE_CASE_PART(rec,20,200)
        GENERATE_CASE_FULL(rec,21,201)
        GENERATE_CASE_PART(rec,21,201)
        GENERATE_CASE_FULL(rec,22,202)
        GENERATE_CASE_PART(rec,22,202)
        GENERATE_CASE_FULL(rec,23,203)
        GENERATE_CASE_PART(rec,23,203)
        GENERATE_CASE_FULL_V25(rec,24,204)
        GENERATE_CASE_PART_V25(rec,24,204)
        GENERATE_CASE_FULL_V25(rec,25,205)
        GENERATE_CASE_PART_V25(rec,25,205)
        GENERATE_CASE_FULL_V25(rec,26,206)
        GENERATE_CASE_PART_V25(rec,26,206)
    }

#undef GENERATE_CASE_FULL
#undef GENERATE_CASE_FULL_V25
#undef GENERATE_CASE_PART
#undef GENERATE_CASE_PART_V25

    return true;
}

#undef PACKET_DESCRIBE
#undef SETETHOFFSET_35
#undef SETETHOFFSET_30

#define SETETHOFFSET_35(rec)\
   {\
    (rec)->rec_header.packet_header.pseudo_header.nstr.eth_offset = pletoh16(&fp->fp_headerlen);\
   }

#define SETETHOFFSET_30(rec) ;\

#define PACKET_DESCRIBE(rec,FULLPART,ver,enumprefix,type,structname,HEADERVER)\
    do {\
        nspr_##structname##_t *fp= (nspr_##structname##_t*)pd;\
        (rec)->rec_type = REC_TYPE_PACKET;\
        (rec)->block = wtap_block_create(WTAP_BLOCK_PACKET);\
        TIMEDEFV##ver((rec),fp,type);\
        SETETHOFFSET_##ver(rec);\
        FULLPART##SIZEDEFV##ver((rec),fp,ver);\
        TRACE_V##ver##_REC_LEN_OFF((rec),enumprefix,type,structname);\
        (rec)->rec_header.packet_header.pseudo_header.nstr.rec_type = NSPR_HEADER_VERSION##HEADERVER;\
        return true;\
    }while(0)

static bool nstrace_seek_read_v30(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
    nspr_hd_v20_t hdr;
    unsigned record_length;
    unsigned hdrlen;
    uint8_t *pd;
    unsigned int bytes_to_read;
    uint64_t nsg_creltime;

    *err = 0;

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return false;
    /*
    ** Read the first 2 bytes of the record header.
    */
    if (!wtap_read_bytes(wth->random_fh, (void *)&hdr, 2, err, err_info))
        return false;
    hdrlen = 2;

    /*
    ** Is there a third byte?  If so, read it.
    */
    if (hdr.phd_RecordSizeLow & NSPR_V20RECORDSIZE_2BYTES) {
        if (!wtap_read_bytes(wth->random_fh, (void *)&hdr.phd_RecordSizeHigh, 1,
                             err, err_info))
            return false;
        hdrlen = 3;
    }

    /*
    ** Get the record length.
    ** The maximum value of the record data size is 65535, which is less
    ** than WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't need to check it.
    */
    record_length = nspr_getv20recordsize(&hdr);

    /*
    ** Copy the header to the buffer and read the rest of the record..
    */
    ws_buffer_assure_space(buf, record_length);
    pd = ws_buffer_start_ptr(buf);
    memcpy(pd, (void *)&hdr, hdrlen);
    if (record_length > hdrlen) {
        bytes_to_read = (unsigned int)(record_length - hdrlen);
        if (!wtap_read_bytes(wth->random_fh, pd + hdrlen, bytes_to_read,
                             err, err_info))
            return false;
    }

    (rec)->rec_header.packet_header.caplen = (rec)->rec_header.packet_header.len = record_length;

#define GENERATE_CASE_V30(rec,ver,HEADERVER) \
    case NSPR_PDPKTRACEFULLTX_V##ver:\
    case NSPR_PDPKTRACEFULLTXB_V##ver:\
    case NSPR_PDPKTRACEFULLRX_V##ver:\
    case NSPR_PDPKTRACEFULLNEWRX_V##ver:\
        PACKET_DESCRIBE(rec,FULL,ver,v##ver##_full,fp,pktracefull_v##ver,HEADERVER);

        switch ((( nspr_hd_v20_t*)pd)->phd_RecordType)
        {
            GENERATE_CASE_V30(rec,30, 300);
            GENERATE_CASE_V30(rec,35, 350);
        }

    return true;
}


/*
** Netscaler trace format close routines.
*/
static void nstrace_close(wtap *wth)
{
    nstrace_t *nstrace = (nstrace_t *)wth->priv;

    g_free(nstrace->pnstrace_buf);
}


#define NSTRACE_1_0       0
#define NSTRACE_2_0       1
#define NSTRACE_3_0       2
#define NSTRACE_3_5       3

typedef struct {
    unsigned version;
    uint16_t page_offset;
    uint16_t page_len;
    uint32_t absrec_time;
    bool newfile;
} nstrace_dump_t;

/* Returns 0 if we could write the specified encapsulation type,
** an error indication otherwise. */
static int nstrace_10_dump_can_write_encap(int encap)
{
    if (encap == WTAP_ENCAP_NSTRACE_1_0)
        return 0;

    return WTAP_ERR_UNWRITABLE_ENCAP;
}


/* Returns 0 if we could write the specified encapsulation type,
** an error indication otherwise. */
static int nstrace_20_dump_can_write_encap(int encap)
{
    if (encap == WTAP_ENCAP_NSTRACE_2_0)
        return 0;

    return WTAP_ERR_UNWRITABLE_ENCAP;
}

/* Returns 0 if we could write the specified encapsulation type,
** an error indication otherwise. */
static int nstrace_30_dump_can_write_encap(int encap)
{
    if (encap == WTAP_ENCAP_NSTRACE_3_0)
        return 0;

    return WTAP_ERR_UNWRITABLE_ENCAP;
}

/* Returns 0 if we could write the specified encapsulation type,
** an error indication otherwise. */
static int nstrace_35_dump_can_write_encap(int encap)
{
    if (encap == WTAP_ENCAP_NSTRACE_3_5)
        return 0;

    return WTAP_ERR_UNWRITABLE_ENCAP;
}

/* Returns true on success, false on failure; sets "*err" to an error code on
** failure */
static bool nstrace_dump_open(wtap_dumper *wdh, unsigned version, int *err _U_,
                                  char **err_info _U_)
{
    nstrace_dump_t *nstrace;

    wdh->subtype_write = nstrace_dump;

    nstrace = g_new(nstrace_dump_t, 1);
    wdh->priv = (void *)nstrace;
    nstrace->version = version;
    nstrace->page_offset = 0;
    if ((nstrace->version == NSTRACE_3_0) ||
      (nstrace->version == NSTRACE_3_5))
      nstrace->page_len = NSPR_PAGESIZE_TRACE;
    else
      nstrace->page_len = NSPR_PAGESIZE;

    nstrace->absrec_time = 0;
    nstrace->newfile = true;

    return true;
}

static bool nstrace_10_dump_open(wtap_dumper *wdh, int *err,
                                     char **err_info)
{
    return nstrace_dump_open(wdh, NSTRACE_1_0, err, err_info);
}

static bool nstrace_20_dump_open(wtap_dumper *wdh, int *err,
                                     char **err_info)
{
    return nstrace_dump_open(wdh, NSTRACE_2_0, err, err_info);
}

static bool nstrace_30_dump_open(wtap_dumper *wdh, int *err,
                                     char **err_info)
{
    return nstrace_dump_open(wdh, NSTRACE_3_0, err, err_info);
}

static bool nstrace_35_dump_open(wtap_dumper *wdh, int *err,
                                     char **err_info)
{
    return nstrace_dump_open(wdh, NSTRACE_3_5, err, err_info);
}

static bool nstrace_add_signature(wtap_dumper *wdh, int *err)
{
    nstrace_dump_t *nstrace = (nstrace_dump_t *)wdh->priv;

    if (nstrace->version == NSTRACE_1_0)
    {
        uint16_t val16b;
        nspr_signature_v10_t sig10;

        /* populate the record */
        val16b = GUINT16_TO_LE(NSPR_SIGNATURE_V10);
        memcpy(sig10.phd.ph_RecordType, &val16b, sizeof sig10.phd.ph_RecordType);
        val16b = GUINT16_TO_LE(nspr_signature_v10_s);
        memcpy(sig10.phd.ph_RecordSize, &val16b, sizeof sig10.phd.ph_RecordSize);
        memset(sig10.sig_Signature, 0, NSPR_SIGSIZE_V10);
        (void) g_strlcpy(sig10.sig_Signature, NSPR_SIGSTR_V10, NSPR_SIGSIZE_V10);

        /* Write the record into the file */
        if (!wtap_dump_file_write(wdh, &sig10, nspr_signature_v10_s,
            err))
            return false;

        /* Move forward the page offset */
        nstrace->page_offset += (uint16_t) nspr_signature_v10_s;

    } else if (nstrace->version == NSTRACE_2_0)
    {
        nspr_signature_v20_t sig20;

        sig20.sig_RecordType = NSPR_SIGNATURE_V20;
        sig20.sig_RecordSize = nspr_signature_v20_s;
        memcpy(sig20.sig_Signature, NSPR_SIGSTR_V20, sizeof(NSPR_SIGSTR_V20));

        /* Write the record into the file */
        if (!wtap_dump_file_write(wdh, &sig20, sig20.sig_RecordSize,
            err))
            return false;

        /* Move forward the page offset */
        nstrace->page_offset += (uint16_t) sig20.sig_RecordSize;

    } else if (nstrace->version == NSTRACE_3_0)
    {
        nspr_signature_v30_t sig30;

        sig30.sig_RecordType = NSPR_SIGNATURE_V30;
        sig30.sig_RecordSize = nspr_signature_v30_s;
        memcpy(sig30.sig_Signature, NSPR_SIGSTR_V30, sizeof(NSPR_SIGSTR_V30));

        /* Write the record into the file */
        if (!wtap_dump_file_write(wdh, &sig30, sig30.sig_RecordSize,
            err))
            return false;

        /* Move forward the page offset */
        nstrace->page_offset += (uint16_t) sig30.sig_RecordSize;
    } else if (nstrace->version == NSTRACE_3_5)
    {
        nspr_signature_v35_t sig35;

        sig35.sig_RecordType = NSPR_SIGNATURE_V35;
        sig35.sig_RecordSize = nspr_signature_v35_s;
        memcpy(sig35.sig_Signature, NSPR_SIGSTR_V35, sizeof(NSPR_SIGSTR_V35));

        /* Write the record into the file */
        if (!wtap_dump_file_write(wdh, &sig35, sig35.sig_RecordSize,
            err))
            return false;

        /* Move forward the page offset */
        nstrace->page_offset += (uint16_t) sig35.sig_RecordSize;
    } else
    {
        ws_assert_not_reached();
        return false;
    }

    return true;
}


static bool
nstrace_add_abstime(wtap_dumper *wdh, const wtap_rec *rec,
     const uint8_t *pd, int *err)
{
    nstrace_dump_t *nstrace = (nstrace_dump_t *)wdh->priv;
    uint64_t nsg_creltime;

    if (nstrace->version == NSTRACE_1_0)
    {
        uint16_t val16;
        uint32_t reltime;
        uint64_t abstime;
        nspr_abstime_v10_t abs10;

        /* populate the record */
        val16 = GUINT16_TO_LE(NSPR_ABSTIME_V10);
        memcpy(abs10.phd.ph_RecordType, &val16, sizeof abs10.phd.ph_RecordType);
        val16 = GUINT16_TO_LE(nspr_abstime_v10_s);
        memcpy(abs10.phd.ph_RecordSize, &val16, sizeof abs10.phd.ph_RecordSize);

        memcpy(&reltime, ((const nspr_pktracefull_v10_t *)pd)->fp_RelTimeHr, sizeof reltime);
        nsg_creltime = ns_hrtime2nsec(reltime);

        memset(abs10.abs_RelTime, 0, sizeof abs10.abs_RelTime);
        abstime = GUINT32_TO_LE((uint32_t)rec->ts.secs - (uint32_t)(nsg_creltime/1000000000));
        memcpy(abs10.abs_Time, &abstime, sizeof abs10.abs_Time);

        /* Write the record into the file */
        if (!wtap_dump_file_write(wdh, &abs10, nspr_abstime_v10_s, err))
            return false;

        /* Move forward the page offset */
        nstrace->page_offset += nspr_abstime_v10_s;

    } else if ((nstrace->version == NSTRACE_2_0) ||
        (nstrace->version == NSTRACE_3_0) ||
        (nstrace->version == NSTRACE_3_5))    {
        uint32_t reltime;
        uint64_t abstime;
        nspr_abstime_v20_t abs20;

        abs20.abs_RecordType = NSPR_ABSTIME_V20;
        abs20.abs_RecordSize = nspr_abstime_v20_s;

        memcpy(&reltime, ((const nspr_pktracefull_v20_t *)pd)->fp_RelTimeHr, sizeof reltime);
        nsg_creltime = ns_hrtime2nsec(reltime);

        memset(abs20.abs_RelTime, 0, sizeof abs20.abs_RelTime);
        abstime = GUINT32_TO_LE((uint32_t)rec->ts.secs - (uint32_t)(nsg_creltime/1000000000));
        memcpy(abs20.abs_RelTime, &abstime, sizeof abs20.abs_RelTime);

        /* Write the record into the file */
        if (!wtap_dump_file_write(wdh, &abs20, nspr_abstime_v20_s, err))
            return false;

        /* Move forward the page offset */
        nstrace->page_offset += nspr_abstime_v20_s;

    } else
    {
        ws_assert_not_reached();
        return false;
    }

    return true;
}


/* Write a record for a packet to a dump file.
   Returns true on success, false on failure. */
static bool nstrace_dump(wtap_dumper *wdh, const wtap_rec *rec,
    const uint8_t *pd, int *err, char **err_info _U_)
{
    nstrace_dump_t *nstrace = (nstrace_dump_t *)wdh->priv;

    /* We can only write packet records. */
    if (rec->rec_type != REC_TYPE_PACKET) {
        *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
        return false;
    }

    /*
     * Make sure this packet doesn't have a link-layer type that
     * differs from the one for the file.
     */
    if (wdh->file_encap != rec->rec_header.packet_header.pkt_encap) {
        *err = WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;
        return false;
    }

    if (nstrace->newfile == true)
    {
        nstrace->newfile = false;
        /* Add the signature record and abs time record */
        if (nstrace->version == NSTRACE_1_0)
        {
            if (!nstrace_add_signature(wdh, err) ||
                !nstrace_add_abstime(wdh, rec, pd, err))
                return false;
        } else if (nstrace->version == NSTRACE_2_0)
        {
            if (!nstrace_add_signature(wdh, err) ||
                !nstrace_add_abstime(wdh, rec, pd, err))
                return false;
        } else if (nstrace->version == NSTRACE_3_0 ||
                   nstrace->version == NSTRACE_3_5 )
        {
            if (!nstrace_add_signature(wdh, err) ||
                !nstrace_add_abstime(wdh, rec, pd, err))
                return false;
        } else
        {
            ws_assert_not_reached();
            return false;
        }
    }

    switch (rec->rec_header.packet_header.pseudo_header.nstr.rec_type)
    {
    case NSPR_HEADER_VERSION100:

        if (nstrace->version == NSTRACE_1_0)
        {
            if (nstrace->page_offset + rec->rec_header.packet_header.caplen >= nstrace->page_len)
            {
                /* Start on the next page */
                if (wtap_dump_file_seek(wdh, (nstrace->page_len - nstrace->page_offset), SEEK_CUR, err) == -1)
                    return false;

                nstrace->page_offset = 0;

                /* Possibly add signature and abstime records and increment offset */
                if (!nstrace_add_signature(wdh, err))
                    return false;
            }

            /* Write the actual record as is */
            if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen, err))
                return false;

            nstrace->page_offset += (uint16_t) rec->rec_header.packet_header.caplen;
        } else if (nstrace->version == NSTRACE_2_0)
        {
            *err = WTAP_ERR_UNWRITABLE_FILE_TYPE;
            return false;
        }

        break;

    case NSPR_HEADER_VERSION200:
    case NSPR_HEADER_VERSION201:
    case NSPR_HEADER_VERSION202:
    case NSPR_HEADER_VERSION203:
    case NSPR_HEADER_VERSION204:
    case NSPR_HEADER_VERSION205:
    case NSPR_HEADER_VERSION206:
        if (nstrace->version == NSTRACE_1_0)
        {
            *err = WTAP_ERR_UNWRITABLE_FILE_TYPE;
            return false;
        } else if (nstrace->version == NSTRACE_2_0)
        {
            if (nstrace->page_offset + rec->rec_header.packet_header.caplen >= nstrace->page_len)
            {
                /* Start on the next page */
                if (wtap_dump_file_seek(wdh, (nstrace->page_len - nstrace->page_offset), SEEK_CUR, err) == -1)
                    return false;

                nstrace->page_offset = 0;

                /* Possibly add signature and abstime records and increment offset */
                if (!nstrace_add_signature(wdh, err))
                    return false;
            }

            /* Write the actual record as is */
            if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen, err))
                return false;

            nstrace->page_offset += (uint16_t) rec->rec_header.packet_header.caplen;
        }

        break;

    case NSPR_HEADER_VERSION300:
    case NSPR_HEADER_VERSION350:
        if (nstrace->version == NSTRACE_1_0)
        {
            *err = WTAP_ERR_UNWRITABLE_FILE_TYPE;
            return false;
        } else if (nstrace->version == NSTRACE_2_0)
        {
            *err = WTAP_ERR_UNWRITABLE_FILE_TYPE;
            return false;
        } else if (nstrace->version == NSTRACE_3_0 || nstrace->version == NSTRACE_3_5)
        {
            if (nstrace->page_offset + rec->rec_header.packet_header.caplen >= nstrace->page_len)
            {
                /* Start on the next page */
                if (wtap_dump_file_seek(wdh, (nstrace->page_len - nstrace->page_offset), SEEK_CUR, err) == -1)
                    return false;

                nstrace->page_offset = 0;

                /* Possibly add signature and abstime records and increment offset */
                if (!nstrace_add_signature(wdh, err))
                    return false;
            }

            /* Write the actual record as is */
            if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen, err))
                return false;

            nstrace->page_offset += (uint16_t) rec->rec_header.packet_header.caplen;
        } else
        {
            ws_assert_not_reached();
            return false;
        }
        break;

    default:
        ws_assert_not_reached();
        return false;
    }

    return true;
}

static const struct supported_block_type nstrace_1_0_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info nstrace_1_0_info = {
    "NetScaler Trace (Version 1.0)", "nstrace10", NULL, NULL,
    true, BLOCKS_SUPPORTED(nstrace_1_0_blocks_supported),
    nstrace_10_dump_can_write_encap, nstrace_10_dump_open, NULL
};

static const struct supported_block_type nstrace_2_0_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info nstrace_2_0_info = {
    "NetScaler Trace (Version 2.0)", "nstrace20", "cap", NULL,
    true, BLOCKS_SUPPORTED(nstrace_2_0_blocks_supported),
    nstrace_20_dump_can_write_encap, nstrace_20_dump_open, NULL
};

static const struct supported_block_type nstrace_3_0_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info nstrace_3_0_info = {
    "NetScaler Trace (Version 3.0)", "nstrace30", "cap", NULL,
    true, BLOCKS_SUPPORTED(nstrace_3_0_blocks_supported),
    nstrace_30_dump_can_write_encap, nstrace_30_dump_open, NULL
};

static const struct supported_block_type nstrace_3_5_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info nstrace_3_5_info = {
    "NetScaler Trace (Version 3.5)", "nstrace35", "cap", NULL,
    true, BLOCKS_SUPPORTED(nstrace_3_5_blocks_supported),
    nstrace_35_dump_can_write_encap, nstrace_35_dump_open, NULL
};

void register_nstrace(void)
{
    nstrace_1_0_file_type_subtype = wtap_register_file_type_subtype(&nstrace_1_0_info);
    nstrace_2_0_file_type_subtype = wtap_register_file_type_subtype(&nstrace_2_0_info);
    nstrace_3_0_file_type_subtype = wtap_register_file_type_subtype(&nstrace_3_0_info);
    nstrace_3_5_file_type_subtype = wtap_register_file_type_subtype(&nstrace_3_5_info);

    /*
     * Register names for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("NETSCALER_1_0",
                                                   nstrace_1_0_file_type_subtype);
    wtap_register_backwards_compatibility_lua_name("NETSCALER_2_0",
                                                   nstrace_2_0_file_type_subtype);
    wtap_register_backwards_compatibility_lua_name("NETSCALER_3_0",
                                                   nstrace_3_0_file_type_subtype);
    wtap_register_backwards_compatibility_lua_name("NETSCALER_3_5",
                                                   nstrace_3_5_file_type_subtype);
}

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
