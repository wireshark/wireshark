/* netscaler.c
 *
 * Wiretap Library
 * Copyright (c) 2006 by Ravi Kondamuru <Ravi.Kondamuru@citrix.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "netscaler.h"

/* Defines imported from netscaler code: nsperfrc.h */

#define NSPR_SIGSTR_V10 "NetScaler Performance Data"
#define NSPR_SIGSTR_V20 "NetScaler V20 Performance Data"
#define NSPR_SIGSTR     NSPR_SIGSTR_V20
#define NSPR_SIGSTR_V30 "Netscaler V30 Performance Data"
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
** The MS 2 bits of the high resoltion time is defined as follows:
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
    guint8 ph_RecordType[2]; /* Record Type */
    guint8 ph_RecordSize[2]; /* Record Size including header */
} nspr_header_v10_t;
#define nspr_header_v10_s    ((guint32)sizeof(nspr_header_v10_t))

/* This is V20 short header (2 bytes long) to be included where needed */
#define NSPR_HEADER_V20(prefix) \
    guint8 prefix##_RecordType; /* Record Type */ \
    guint8 prefix##_RecordSize  /* Record Size including header */ \
                                /* end of declaration */

/* This is new long header (3 bytes long) to be included where needed */
#define NSPR_HEADER3B_V20(prefix) \
    guint8 prefix##_RecordType;    /* Record Type */ \
    guint8 prefix##_RecordSizeLow; /* Record Size including header */ \
    guint8 prefix##_RecordSizeHigh /* Record Size including header */ \
                                   /* end of declaration */
#define NSPR_HEADER3B_V21 NSPR_HEADER3B_V20
#define NSPR_HEADER3B_V22 NSPR_HEADER3B_V20
#define NSPR_HEADER3B_V30 NSPR_HEADER3B_V20

typedef struct nspr_hd_v20
{
    NSPR_HEADER3B_V20(phd); /* long performance header */

} nspr_hd_v20_t;
#define nspr_hd_v20_s    ((guint32)sizeof(nspr_hd_v20_t))


/*
** How to know if header size is short or long?
** The short header size can be 0-127 bytes long. If MS Bit of ph_RecordSize
** is set then record size has 2 bytes
*/
#define NSPR_V20RECORDSIZE_2BYTES       0x80

/* Performance Data Header with device number */
typedef struct nspr_headerdev_v10
{
    guint8 ph_RecordType[2]; /* Record Type */
    guint8 ph_RecordSize[2]; /* Record Size including header */
    guint8 ph_DevNo[4];      /* Network Device (NIC/CONN) number */
} nspr_headerdev_v10_t;
#define nspr_headerdev_v10_s    ((guint32)sizeof(nspr_headerdev_v10_t))

typedef struct nspr_hd_v10
{
    nspr_header_v10_t phd; /* performance header */
} nspr_hd_v10_t;
#define nspr_hd_v10_s    ((guint32)sizeof(nspr_hd_v10_t))

typedef struct nspr_hdev_v10
{
    nspr_headerdev_v10_t phd; /* performance header */
} nspr_hdev_v10_t;
#define nspr_hdev_v10_s    ((guint32)sizeof(nspr_hdev_v10_t))

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
    guint8 sig_EndianType; /* Endian Type for the data */
    guint8 sig_Reserved0;
    guint8 sig_Reserved1[2];
    gchar sig_Signature[NSPR_SIGSIZE_V10]; /* Signature value */
} nspr_signature_v10_t;
#define nspr_signature_v10_s    ((guint32)sizeof(nspr_signature_v10_t))

/* NSPR_SIGNATURE_V20 structure */
#define NSPR_SIGSIZE_V20        sizeof(NSPR_SIGSTR_V20) /* signature value size in bytes */
typedef struct nspr_signature_v20
{
    NSPR_HEADER_V20(sig);  /* short performance header */
    guint8 sig_EndianType; /* Endian Type for the data */
    gchar sig_Signature[NSPR_SIGSIZE_V20]; /* Signature value */
} nspr_signature_v20_t;
#define nspr_signature_v20_s    ((guint32)sizeof(nspr_signature_v20_t))

/* NSPR_SIGNATURE_V30 structure */
#define NSPR_SIGSIZE_V30        sizeof(NSPR_SIGSTR_V30) /* signature value size in bytes */
typedef struct nspr_signature_v30
{
    NSPR_HEADER_V20(sig);  /* short performance header */
    guint8 sig_EndianType; /* Endian Type for the data */
    gchar sig_Signature[NSPR_SIGSIZE_V30]; /* Signature value */
} nspr_signature_v30_t;
#define nspr_signature_v30_s    ((guint32)sizeof(nspr_signature_v30_t))

/* NSPR_ABSTIME_V10 and NSPR_SYSTARTIME_V10 structure */
typedef struct nspr_abstime_v10
{
    nspr_header_v10_t phd; /* performance header */
    guint8 abs_RelTime[4]; /* relative time is ms from last time */
    guint8 abs_Time[4];    /* absolute time in seconds from 1970 */
} nspr_abstime_v10_t;
#define nspr_abstime_v10_s    ((guint32)sizeof(nspr_abstime_v10_t))


/* NSPR_ABSTIME_V20 and NSPR_SYSTARTIME_V20 structure */
typedef struct nspr_abstime_v20
{
    NSPR_HEADER_V20(abs);  /* short performance header */
    guint8 abs_RelTime[2]; /* relative time is ms from last time */
    guint8 abs_Time[4];    /* absolute time in seconds from 1970 */
} nspr_abstime_v20_t;
#define nspr_abstime_v20_s    ((guint32)sizeof(nspr_abstime_v20_t))



/* full packet trace structure */
typedef struct nspr_pktracefull_v10
{
    nspr_headerdev_v10_t phd; /* performance header */
    guint8 fp_RelTimeHr[4];   /* High resolution relative time */
    guint8 fp_Data[1];        /* packet data starts here */
} nspr_pktracefull_v10_t;
#define nspr_pktracefull_v10_s    (nspr_hdev_v10_s + 4)

/* new full packet trace structure v20 */
typedef struct nspr_pktracefull_v20
{
    NSPR_HEADER3B_V20(fp);  /* long performance header */
    guint8 fp_DevNo;        /* Network Device (NIC) number */
    guint8 fp_RelTimeHr[4]; /* High resolution relative time */
    guint8 fp_Data[4];      /* packet data starts here */
} nspr_pktracefull_v20_t;
#define nspr_pktracefull_v20_s    ((guint32)(sizeof(nspr_pktracefull_v20_t) - 4))

/* new full packet trace structure v21 */
typedef struct nspr_pktracefull_v21
{
    NSPR_HEADER3B_V21(fp);  /* long performance header */
    guint8 fp_DevNo;        /* Network Device (NIC) number */
    guint8 fp_RelTimeHr[4]; /* High resolution relative time */
    guint8 fp_PcbDevNo[4];  /* PCB devno */
    guint8 fp_lPcbDevNo[4]; /* link PCB devno */
    guint8 fp_Data[4];      /* packet data starts here */
} nspr_pktracefull_v21_t;
#define nspr_pktracefull_v21_s    ((guint32)(sizeof(nspr_pktracefull_v21_t) - 4))

/* new full packet trace structure v22 */
typedef struct nspr_pktracefull_v22
{
    NSPR_HEADER3B_V22(fp);  /* long performance header */
    guint8 fp_DevNo;        /* Network Device (NIC) number */
    guint8 fp_RelTimeHr[4]; /* High resolution relative time */
    guint8 fp_PcbDevNo[4];  /* PCB devno */
    guint8 fp_lPcbDevNo[4]; /* link PCB devno */
    guint8 fp_VlanTag[2];   /* vlan tag */
    guint8 fp_Data[2];      /* packet data starts here */
} nspr_pktracefull_v22_t;
#define nspr_pktracefull_v22_s    ((guint32)(sizeof(nspr_pktracefull_v22_t) - 2))

typedef struct nspr_pktracefull_v23
{
    NSPR_HEADER3B_V22(fp);  /* long performance header */
    guint8 fp_DevNo;        /* Network Device (NIC) number */
    guint8 fp_AbsTimeHr[8]; /* High resolution absolute time */
    guint8 fp_PcbDevNo[4];  /* PCB devno */
    guint8 fp_lPcbDevNo[4]; /* link PCB devno */
    guint8 fp_VlanTag[2];   /* vlan tag */
    guint8 fp_Coreid[2];    /* coreid of the packet */
    guint8 fp_Data[2];      /* packet data starts here */
} nspr_pktracefull_v23_t;
#define nspr_pktracefull_v23_s    ((guint32)(sizeof(nspr_pktracefull_v23_t) - 2))

/* New full packet trace structure v24 for cluster tracing */
typedef struct nspr_pktracefull_v24
{
    NSPR_HEADER3B_V22(fp);   /* long performance header */
    guint8 fp_DevNo;         /* Network Device (NIC) number */
    guint8 fp_AbsTimeHr[8];  /* High resolution absolute time in nanosec */
    guint8 fp_PcbDevNo[4];   /* PCB devno */
    guint8 fp_lPcbDevNo[4];  /* link PCB devno */
    guint8 fp_VlanTag[2];    /* vlan tag */
    guint8 fp_Coreid[2];     /* coreid of the packet */
    guint8 fp_srcNodeId[2];  /* source node # */
    guint8 fp_destNodeId[2]; /* destination node # */
    guint8 fp_clFlags;       /* cluster flags */
    guint8 fp_Data[2];       /* packet data starts here */
} nspr_pktracefull_v24_t;
#define nspr_pktracefull_v24_s    ((guint32)(sizeof(nspr_pktracefull_v24_t) - 4))

/* New full packet trace structure v25 for vm info tracing */
typedef struct nspr_pktracefull_v25
{
    NSPR_HEADER3B_V22(fp);    /* long performance header */
    guint8 fp_DevNo;          /* Network Device (NIC) number */
    guint8 fp_AbsTimeHr[8];   /* High resolution absolute time in nanosec */
    guint8 fp_PcbDevNo[4];    /* PCB devno */
    guint8 fp_lPcbDevNo[4];   /* link PCB devno */
    guint8 fp_VlanTag[2];     /* vlan tag */
    guint8 fp_Coreid[2];      /* coreid of the packet */
    guint8 fp_srcNodeId[2];   /* source node # */
    guint8 fp_destNodeId[2];  /* destination node # */
    guint8 fp_clFlags;        /* cluster flags */
    guint8 fp_src_vmname_len; /* vm src info */
    guint8 fp_dst_vmname_len; /* vm src info */
    guint8 fp_Data[4];        /* packet data starts here */
} nspr_pktracefull_v25_t;
#define nspr_pktracefull_v25_s    ((guint32)(sizeof(nspr_pktracefull_v25_t) - 4))
#define fp_src_vmname    fp_Data
#define fp_src_vmname    fp_Data

/* New full packet trace structure v26 for vm info tracing */
typedef struct nspr_pktracefull_v26
{
    NSPR_HEADER3B_V22(fp);     /* long performance header */
    guint8 fp_DevNo;           /* Network Device (NIC) number */
    guint8 fp_AbsTimeHr[8];    /* High resolution absolute time in nanosec */
    guint8 fp_PcbDevNo[4];     /* PCB devno */
    guint8 fp_lPcbDevNo[4];    /* link PCB devno */
    guint8 fp_VlanTag[2];      /* vlan tag */
    guint8 fp_Coreid[2];       /* coreid of the packet */
    guint8 fp_srcNodeId[2];    /* source node # */
    guint8 fp_destNodeId[2];   /* destination node # */
    guint8 fp_clFlags;         /* cluster flags */
    guint8 fp_src_vmname_len;  /* vm src info */
    guint8 fp_dst_vmname_len;  /* vm src info */
    guint8 fp_reserved;
    guint8 fp_ns_activity[4];
    guint8 fp_reserved_32[12]; /* Adding more field to reduce wireshark changes every time */
    guint8 fp_Data[4];         /* packet data starts here */
} nspr_pktracefull_v26_t;
#define nspr_pktracefull_v26_s    ((guint32)(sizeof(nspr_pktracefull_v26_t) - 4))

/* partial packet trace structure */
typedef struct nspr_pktracepart_v10
{
    nspr_headerdev_v10_t phd; /* performance header */
    guint8 pp_RelTimeHr[4];   /* High resolution relative time */
    guint8 pp_PktSizeOrg[2];  /* Original packet size */
    guint8 pp_PktOffset[2];   /* starting offset in packet */
    guint8 pp_Data[1];        /* packet data starts here */
} nspr_pktracepart_v10_t;
#define nspr_pktracepart_v10_s    (nspr_pktracefull_v10_s + 4)

/* new partial packet trace structure */
typedef struct nspr_pktracepart_v20
{
    NSPR_HEADER3B_V20(pp);   /* long performance header */
    guint8 pp_DevNo;         /* Network Device (NIC) number */
    guint8 pp_RelTimeHr[4];  /* High resolution relative time */
    guint8 pp_PktSizeOrg[2]; /* Original packet size */
    guint8 pp_PktOffset[2];  /* starting offset in packet */
    guint8 pp_Data[4];       /* packet data starts here */
} nspr_pktracepart_v20_t;
#define nspr_pktracepart_v20_s    ((guint32)(sizeof(nspr_pktracepart_v20_t) -4))

/* new partial packet trace structure */
typedef struct nspr_pktracepart_v21
{
    NSPR_HEADER3B_V21(pp);   /* long performance header */
    guint8 pp_DevNo;         /* Network Device (NIC) number */
    guint8 pp_RelTimeHr[4];  /* High resolution relative time */
    guint8 pp_PktSizeOrg[2]; /* Original packet size */
    guint8 pp_PktOffset[2];  /* starting offset in packet */
    guint8 pp_PcbDevNo[4];   /* PCB devno */
    guint8 pp_lPcbDevNo[4];  /* link PCB devno */
    guint8 pp_Data[4];       /* packet data starts here */
} nspr_pktracepart_v21_t;
#define nspr_pktracepart_v21_s    ((guint32)(sizeof(nspr_pktracepart_v21_t) -4))

/* new partial packet trace structure v22 */
typedef struct nspr_pktracepart_v22
{
    NSPR_HEADER3B_V22(pp);   /* long performance header */
    guint8 pp_DevNo;         /* Network Device (NIC) number */
    guint8 pp_RelTimeHr[4];  /* High resolution relative time */
    guint8 pp_PktSizeOrg[2]; /* Original packet size */
    guint8 pp_PktOffset[2];  /* starting offset in packet */
    guint8 pp_PcbDevNo[4];   /* PCB devno */
    guint8 pp_lPcbDevNo[4];  /* link PCB devno */
    guint8 pp_VlanTag[2];    /* Vlan Tag */
    guint8 pp_Data[2];       /* packet data starts here */
} nspr_pktracepart_v22_t;
#define nspr_pktracepart_v22_s    ((guint32)(sizeof(nspr_pktracepart_v22_t) -2))

typedef struct nspr_pktracepart_v23
{
    NSPR_HEADER3B_V22(pp);   /* long performance header */
    guint8 pp_DevNo;         /* Network Device (NIC) number */
    guint8 pp_AbsTimeHr[8];  /* High resolution absolute time */
    guint8 pp_PktSizeOrg[2]; /* Original packet size */
    guint8 pp_PktOffset[2];  /* starting offset in packet */
    guint8 pp_PcbDevNo[4];   /* PCB devno */
    guint8 pp_lPcbDevNo[4];  /* link PCB devno */
    guint8 pp_VlanTag[2];    /* vlan tag */
    guint8 pp_Coreid[2];     /* Coreid of the packet */
    guint8 pp_Data[4];       /* packet data starts here */
} nspr_pktracepart_v23_t;
#define nspr_pktracepart_v23_s    ((guint32)(sizeof(nspr_pktracepart_v23_t) -4))

/* New partial packet trace structure v24 for cluster tracing */
typedef struct nspr_pktracepart_v24
{
    NSPR_HEADER3B_V22(pp);   /* long performance header */
    guint8 pp_DevNo;         /* Network Device (NIC) number */
    guint8 pp_AbsTimeHr[8];  /*High resolution absolute time in nanosec*/
    guint8 pp_PktSizeOrg[2]; /* Original packet size */
    guint8 pp_PktOffset[2];  /* starting offset in packet */
    guint8 pp_PcbDevNo[4];   /* PCB devno */
    guint8 pp_lPcbDevNo[4];  /* link PCB devno */
    guint8 pp_VlanTag[2];    /* vlan tag */
    guint8 pp_Coreid[2];     /* Coreid of the packet */
    guint8 pp_srcNodeId[2];  /* source node # */
    guint8 pp_destNodeId[2]; /* destination node # */
    guint8 pp_clFlags;       /* cluster flags */
    guint8 pp_Data[4];       /* packet data starts here */
} nspr_pktracepart_v24_t;
#define nspr_pktracepart_v24_s    ((guint32)(sizeof(nspr_pktracepart_v24_t) -4))

/* New partial packet trace structure v25 for vm info tracing */
typedef struct nspr_pktracepart_v25
{
    NSPR_HEADER3B_V22(pp);    /* long performance header */
    guint8 pp_DevNo;          /* Network Device (NIC) number */
    guint8 pp_AbsTimeHr[8];   /*High resolution absolute time in nanosec*/
    guint8 pp_PktSizeOrg[2];  /* Original packet size */
    guint8 pp_PktOffset[2];   /* starting offset in packet */
    guint8 pp_PcbDevNo[4];    /* PCB devno */
    guint8 pp_lPcbDevNo[4];   /* link PCB devno */
    guint8 pp_VlanTag[2];     /* vlan tag */
    guint8 pp_Coreid[2];      /* Coreid of the packet */
    guint8 pp_srcNodeId[2];   /* source node # */
    guint8 pp_destNodeId[2];  /* destination node # */
    guint8 pp_clFlags;        /* cluster flags */
    guint8 pp_src_vmname_len; /* vm info */
    guint8 pp_dst_vmname_len; /* vm info */
    guint8 pp_Data[4];        /* packet data starts here */
} nspr_pktracepart_v25_t;
#define nspr_pktracepart_v25_s    ((guint32)(sizeof(nspr_pktracepart_v25_t) -4))
#define pp_src_vmname    pp_Data
#define pp_dst_vmname    pp_Data


/* New full packet trace structure v30 for multipage spanning data */
typedef struct  nspr_pktracefull_v30
{
    NSPR_HEADER3B_V30(fp);  /* long performance header */
    guint8 fp_DevNo;   /* Network Device (NIC) number */
    guint8 fp_AbsTimeHr[8];  /*High resolution absolute time in nanosec*/
    guint8 fp_PcbDevNo[4];    /* PCB devno */
    guint8 fp_lPcbDevNo[4];   /* link PCB devno */
    guint8 fp_PktSizeOrg[2];  /* Original packet size */
    guint8 fp_VlanTag[2]; /* vlan tag */
    guint8 fp_Coreid[2]; /* coreid of the packet */
    guint8 fp_srcNodeId[2]; /* cluster nodeid of the packet */
    guint8 fp_destNodeId[2];
    guint8 fp_clFlags;
    guint8 fp_src_vmname_len;
    guint8 fp_dst_vmname_len;
    guint8 fp_reserved[3];
    guint8 fp_ns_activity[4];
    guint8 fp_reserved_32[12];
    guint8 fp_Data[0]; /* packet data starts here */
} nspr_pktracefull_v30_t;
#define nspr_pktracefull_v30_s  ((guint32)(sizeof(nspr_pktracefull_v30_t)))
#define fp_src_vmname   fp_Data
#define fp_dst_vmname   fp_Data

/* New partial packet trace structure v26 for vm info tracing */
typedef struct nspr_pktracepart_v26
{
    NSPR_HEADER3B_V22(pp);     /* long performance header */
    guint8 pp_DevNo;           /* Network Device (NIC) number */
    guint8 pp_AbsTimeHr[8];    /*High resolution absolute time in nanosec*/
    guint8 pp_PktSizeOrg[2];   /* Original packet size */
    guint8 pp_PktOffset[2];    /* starting offset in packet */
    guint8 pp_PcbDevNo[4];     /* PCB devno */
    guint8 pp_lPcbDevNo[4];    /* link PCB devno */
    guint8 pp_VlanTag[2];      /* vlan tag */
    guint8 pp_Coreid[2];       /* Coreid of the packet */
    guint8 pp_srcNodeId[2];    /* source node # */
    guint8 pp_destNodeId[2];   /* destination node # */
    guint8 pp_clFlags;         /* cluster flags */
    guint8 pp_src_vmname_len;  /* vm info */
    guint8 pp_dst_vmname_len;  /* vm info */
    guint8 pp_reserved;
    guint8 pp_ns_activity[4];
    guint8 pp_reserved_32[12]; /* Adding more field to reduce wireshark changes every time */
    guint8 pp_Data[4];         /* packet data starts here */
} nspr_pktracepart_v26_t;
#define nspr_pktracepart_v26_s    ((guint32)(sizeof(nspr_pktracepart_v26_t) -4))

#define myoffsetof(type,fieldname) (&(((type*)0)->fieldname))

#define __TNO(phdr,enumprefix,structprefix,structname,hdrname,structfieldname) \
    guint8 enumprefix##_##hdrname##_offset = (guint8)GPOINTER_TO_INT(myoffsetof(nspr_##structname##_t,structprefix##_##structfieldname));

#define __TNL(phdr,enumprefix,structprefix,structname,hdrname,structfieldname) \
    guint8 enumprefix##_##hdrname##_len = (guint8)sizeof(((nspr_##structname##_t*)0)->structprefix##_##structfieldname);

#define __TNV1O(phdr,enumprefix,structprefix,structname,hdrname,structfieldname) \
    guint8 enumprefix##_##hdrname##_offset = (guint8)GPOINTER_TO_INT(myoffsetof(nspr_##structname##_t,structfieldname));

#define __TNV1L(phdr,enumprefix,structprefix,structname,hdrname,structfieldname) \
    guint8 enumprefix##_##hdrname##_len = (guint8)sizeof(((nspr_##structname##_t*)0)->structfieldname);

#define TRACE_V10_REC_LEN_OFF(phdr,enumprefix,structprefix,structname) \
    __TNV1O(phdr,enumprefix,structprefix,structname,dir,phd.ph_RecordType)\
    __TNV1L(phdr,enumprefix,structprefix,structname,dir,phd.ph_RecordType)\
    __TNV1O(phdr,enumprefix,structprefix,structname,nicno,phd.ph_DevNo)\
    __TNV1L(phdr,enumprefix,structprefix,structname,nicno,phd.ph_DevNo)\
    __TNO(phdr,enumprefix,structprefix,structname,eth,Data)

#define TRACE_FULL_V10_REC_LEN_OFF(phdr,enumprefix,structprefix,structname) \
    (phdr)->len = pletoh16(&(fp)->nsprRecordSize);\
    (phdr)->caplen = (phdr)->len;\
    TRACE_V10_REC_LEN_OFF(phdr,enumprefix,structprefix,structname)

#define TRACE_PART_V10_REC_LEN_OFF(phdr,enumprefix,structprefix,structname) \
    (phdr)->rec_type = REC_TYPE_PACKET;\
    (phdr)->presence_flags |= WTAP_HAS_CAP_LEN;\
    (phdr)->len =  pletoh16(&pp->pp_PktSizeOrg) + nspr_pktracepart_v10_s;\
    (phdr)->caplen =  pletoh16(&pp->nsprRecordSize);\
    TRACE_V10_REC_LEN_OFF(phdr,enumprefix,structprefix,structname)

#define TRACE_V20_REC_LEN_OFF(phdr,enumprefix,structprefix,structname) \
    __TNO(phdr,enumprefix,structprefix,structname,dir,RecordType)\
    __TNL(phdr,enumprefix,structprefix,structname,dir,RecordType)\
    __TNO(phdr,enumprefix,structprefix,structname,nicno,DevNo)\
    __TNL(phdr,enumprefix,structprefix,structname,nicno,DevNo)\
    __TNO(phdr,enumprefix,structprefix,structname,eth,Data)

#define TRACE_V21_REC_LEN_OFF(phdr,enumprefix,structprefix,structname) \
    TRACE_V20_REC_LEN_OFF(phdr,enumprefix,structprefix,structname)\
    __TNO(phdr,enumprefix,structprefix,structname,pcb,PcbDevNo)\
    __TNO(phdr,enumprefix,structprefix,structname,l_pcb,lPcbDevNo)

#define TRACE_V22_REC_LEN_OFF(phdr,enumprefix,structprefix,structname) \
    TRACE_V21_REC_LEN_OFF(phdr,enumprefix,structprefix,structname)\
    __TNO(phdr,enumprefix,structprefix,structname,vlantag,VlanTag)

#define TRACE_V23_REC_LEN_OFF(phdr,enumprefix,structprefix,structname) \
    TRACE_V22_REC_LEN_OFF(phdr,enumprefix,structprefix,structname)\
    __TNO(phdr,enumprefix,structprefix,structname,coreid,Coreid)

#define TRACE_V24_REC_LEN_OFF(phdr,enumprefix,structprefix,structname) \
    TRACE_V23_REC_LEN_OFF(phdr,enumprefix,structprefix,structname)\
    __TNO(phdr,enumprefix,structprefix,structname,srcnodeid,srcNodeId)\
    __TNO(phdr,enumprefix,structprefix,structname,destnodeid,destNodeId)\
    __TNO(phdr,enumprefix,structprefix,structname,clflags,clFlags)

#define TRACE_V25_REC_LEN_OFF(phdr,enumprefix,structprefix,structname) \
    TRACE_V24_REC_LEN_OFF(phdr,enumprefix,structprefix,structname)\
    __TNO(phdr,enumprefix,structprefix,structname,src_vmname_len,src_vmname_len)\
    __TNO(phdr,enumprefix,structprefix,structname,dst_vmname_len,dst_vmname_len)\
    __TNO(phdr,enumprefix,structprefix,structname,data,Data)

#define TRACE_V26_REC_LEN_OFF(phdr,enumprefix,structprefix,structname) \
    TRACE_V25_REC_LEN_OFF(phdr,enumprefix,structprefix,structname)\
    __TNO(phdr,enumprefix,structprefix,structname,ns_activity,ns_activity)\

#define TRACE_V30_REC_LEN_OFF(phdr, enumprefix, structprefix, structname) \
    TRACE_V26_REC_LEN_OFF(phdr,enumprefix,structprefix,structname)\

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

#undef __TNV1O
#undef __TNV1L
#undef __TNO
#undef __TNL


#define ns_setabstime(nstrace, AbsoluteTime, RelativeTimems) \
    do { \
        (nstrace)->nspm_curtime = AbsoluteTime; \
        (nstrace)->nspm_curtimemsec += RelativeTimems; \
        (nstrace)->nspm_curtimelastmsec = nstrace->nspm_curtimemsec; \
    } while(0)


#define ns_setrelativetime(nstrace, RelativeTimems) \
    do { \
        guint32    rsec; \
        (nstrace)->nspm_curtimemsec += RelativeTimems; \
        rsec = (guint32)((nstrace)->nspm_curtimemsec - (nstrace)->nspm_curtimelastmsec)/1000; \
        (nstrace)->nspm_curtime += rsec; \
        (nstrace)->nspm_curtimelastmsec += rsec * 1000; \
    } while (0)


typedef struct {
    gchar  *pnstrace_buf;
    gint64  xxx_offset;
    gint32  nstrace_buf_offset;
    gint32  nstrace_buflen;
    /* Performance Monitor Time variables */
    guint32 nspm_curtime;         /* current time since 1970 */
    guint64 nspm_curtimemsec;     /* current time in milliseconds */
    guint64 nspm_curtimelastmsec; /* nspm_curtime last update time in milliseconds */
    guint64 nsg_creltime;
    guint64 file_size;
} nstrace_t;

static guint32 nspm_signature_version(wtap*, gchar*, gint32);
static gboolean nstrace_read_v10(wtap *wth, int *err, gchar **err_info,
                                 gint64 *data_offset);
static gboolean nstrace_read_v20(wtap *wth, int *err, gchar **err_info,
                                 gint64 *data_offset);
static gboolean nstrace_read_v30(wtap *wth, int *err, gchar **err_info,
                                 gint64 *data_offset);
static gboolean nstrace_seek_read_v10(wtap *wth, gint64 seek_off,
                                      struct wtap_pkthdr *phdr,
                                      Buffer *buf,
                                      int *err, gchar **err_info);
static gboolean nstrace_seek_read_v20(wtap *wth, gint64 seek_off,
                                      struct wtap_pkthdr *phdr,
                                      Buffer *buf,
                                      int *err, gchar **err_info);
static gboolean nstrace_seek_read_v30(wtap *wth, gint64 seek_off,
                                      struct wtap_pkthdr *phdr,
                                      Buffer *buf,
                                      int *err, gchar **err_info);
static void nstrace_close(wtap *wth);

static gboolean nstrace_set_start_time_v10(wtap *wth);
static gboolean nstrace_set_start_time_v20(wtap *wth);
static gboolean nstrace_set_start_time(wtap *wth);
static guint64 ns_hrtime2nsec(guint32 tm);

static gboolean nstrace_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
                             const guint8 *pd, int *err);


/*
 * Minimum of the page size and the amount of data left in the file;
 * the last page of a file can be short.
 */
#define GET_READ_PAGE_SIZE(remaining_file_size) ((gint32)((remaining_file_size>NSPR_PAGESIZE)?NSPR_PAGESIZE:remaining_file_size))
#define GET_READ_PAGE_SIZEV3(remaining_file_size) ((gint32)((remaining_file_size>NSPR_PAGESIZE_TRACE)?NSPR_PAGESIZE_TRACE:remaining_file_size))

static guint64 ns_hrtime2nsec(guint32 tm)
{
    guint32    val = tm & NSPR_HRTIME_MASKTM;
    switch(tm & NSPR_HRTIME_MASKFMT)
    {
    case NSPR_HRTIME_SEC:     return (guint64)val*1000000000;
    case NSPR_HRTIME_MSEC:    return (guint64)val*1000000;
    case NSPR_HRTIME_USEC:    return (guint64)val*1000;
    case NSPR_HRTIME_NSEC:    return val;
    }
    return tm;
}


/*
** Netscaler trace format open routines
*/
int nstrace_open(wtap *wth, int *err, gchar **err_info)
{
    gchar *nstrace_buf;
    gint64 file_size;
    gint32 page_size;
    nstrace_t *nstrace;
    int bytes_read;

    errno = WTAP_ERR_CANT_READ;

    if ((file_size = wtap_file_size(wth, err)) == -1)
        return 0;

    nstrace_buf = (gchar *)g_malloc(NSPR_PAGESIZE);
    page_size = GET_READ_PAGE_SIZE(file_size);

    switch ((wth->file_type_subtype = nspm_signature_version(wth, nstrace_buf, page_size)))
    {
    case WTAP_FILE_TYPE_SUBTYPE_NETSCALER_1_0:
        wth->file_encap = WTAP_ENCAP_NSTRACE_1_0;
        break;

    case WTAP_FILE_TYPE_SUBTYPE_NETSCALER_2_0:
        wth->file_encap = WTAP_ENCAP_NSTRACE_2_0;
        break;

    case WTAP_FILE_TYPE_SUBTYPE_NETSCALER_3_0:
        wth->file_encap = WTAP_ENCAP_NSTRACE_3_0;
        g_free(nstrace_buf);
        nstrace_buf = (gchar *)g_malloc(NSPR_PAGESIZE_TRACE);
        page_size = GET_READ_PAGE_SIZEV3(file_size);
        break;

    default:
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = g_strdup_printf("nstrace: file type %d unsupported", wth->file_type_subtype);
        g_free(nstrace_buf);
        return 0;
    }

    if ((file_seek(wth->fh, 0, SEEK_SET, err)) == -1)
    {
        *err = file_error(wth->fh, err_info);
        g_free(nstrace_buf);
        return 0;
    }

    bytes_read = file_read(nstrace_buf, page_size, wth->fh);
    if (bytes_read != page_size)
    {
        *err = file_error(wth->fh, err_info);
        g_free(nstrace_buf);
        if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
            return -1;
        return 0;
    }

    switch (wth->file_type_subtype)
    {
    case WTAP_FILE_TYPE_SUBTYPE_NETSCALER_1_0:
        wth->subtype_read = nstrace_read_v10;
        wth->subtype_seek_read = nstrace_seek_read_v10;
        break;

    case WTAP_FILE_TYPE_SUBTYPE_NETSCALER_2_0:
        wth->subtype_read = nstrace_read_v20;
        wth->subtype_seek_read = nstrace_seek_read_v20;
        break;

    case WTAP_FILE_TYPE_SUBTYPE_NETSCALER_3_0:
        wth->subtype_read = nstrace_read_v30;
        wth->subtype_seek_read = nstrace_seek_read_v30;
        break;
    }
    wth->subtype_close = nstrace_close;

    nstrace = (nstrace_t *)g_malloc(sizeof(nstrace_t));
    wth->priv = (void *)nstrace;
    nstrace->pnstrace_buf = nstrace_buf;
    nstrace->xxx_offset = 0;
    nstrace->nstrace_buflen = page_size;
    nstrace->nstrace_buf_offset = 0;
    nstrace->nspm_curtime = 0;
    nstrace->nspm_curtimemsec = 0;
    nstrace->nspm_curtimelastmsec = 0;
    nstrace->nsg_creltime = 0;
    nstrace->file_size = file_size;


    /* Set the start time by looking for the abstime record */
    if ((nstrace_set_start_time(wth)) == FALSE)
    {
        /* Reset the read pointer to start of the file. */
        if ((file_seek(wth->fh, 0, SEEK_SET, err)) == -1)
        {
            *err = file_error(wth->fh, err_info);
            g_free(nstrace->pnstrace_buf);
            g_free(nstrace);
            return 0;
        }

        /* Read the first page of data */
        bytes_read = file_read(nstrace_buf, page_size, wth->fh);
        if (bytes_read != page_size)
        {
            *err = file_error(wth->fh, err_info);
            g_free(nstrace->pnstrace_buf);
            g_free(nstrace);
            return 0;
        }

        /* reset the buffer offset */
        nstrace->nstrace_buf_offset = 0;
    }

    wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
    wth->phdr.ts.secs = nstrace->nspm_curtime;
    wth->phdr.ts.nsecs = 0;

    *err = 0;
    return 1;
}


#define nspm_signature_func(ver) \
    static guint32 nspm_signature_isv##ver(gchar *sigp) {\
        return strncmp(sigp,NSPR_SIGSTR_V##ver,(sizeof(NSPR_SIGSTR_V##ver)-1));\
    }

nspm_signature_func(10)
nspm_signature_func(20)
nspm_signature_func(30)

/*
** Check signature and return the version number of the signature.
** If not found, it returns 0. At the time of return from this function
** we might not be at the first page. So after a call to this function, there
** has to be a file seek to return to the start of the first page.
*/
static guint32
nspm_signature_version(wtap *wth, gchar *nstrace_buf, gint32 len)
{
    gchar *dp = nstrace_buf;
    int bytes_read;

    bytes_read = file_read(dp, len, wth->fh);
    if (bytes_read == len) {

        for ( ; len > (gint32)(MIN(sizeof(NSPR_SIGSTR_V10), sizeof(NSPR_SIGSTR_V20))); dp++, len--)
        {
#define sigv10p    ((nspr_signature_v10_t*)dp)
            if ((pletoh16(&sigv10p->nsprRecordType) == NSPR_SIGNATURE_V10) &&
                (pletoh16(&sigv10p->nsprRecordSize) <= len) &&
                ((gint32)sizeof(NSPR_SIGSTR_V10) <= len) &&
                (!nspm_signature_isv10(sigv10p->sig_Signature)))
                return WTAP_FILE_TYPE_SUBTYPE_NETSCALER_1_0;
#undef    sigv10p

#define sigv20p    ((nspr_signature_v20_t*)dp)
            if ((sigv20p->sig_RecordType == NSPR_SIGNATURE_V20) &&
                (sigv20p->sig_RecordSize <= len) &&
                ((gint32)sizeof(NSPR_SIGSTR_V20) <= len))
            {
                if (!nspm_signature_isv20(sigv20p->sig_Signature))
                    return WTAP_FILE_TYPE_SUBTYPE_NETSCALER_2_0;
                else if (!nspm_signature_isv30(sigv20p->sig_Signature))
                    return WTAP_FILE_TYPE_SUBTYPE_NETSCALER_3_0;
            }
#undef    sigv20p
        }
    }

    return 0;    /* no version found */
}

#define nspr_getv10recordtype(hdp) (pletoh16(&(hdp)->nsprRecordType))
#define nspr_getv10recordsize(hdp) (pletoh16(&(hdp)->nsprRecordSize))
#define nspr_getv20recordtype(hdp) ((hdp)->phd_RecordType)
#define nspr_getv20recordsize(hdp) \
    (((hdp)->phd_RecordSizeLow & NSPR_V20RECORDSIZE_2BYTES)? \
        (((hdp)->phd_RecordSizeHigh * NSPR_V20RECORDSIZE_2BYTES)+ \
         ((hdp)->phd_RecordSizeLow & ~NSPR_V20RECORDSIZE_2BYTES)) : \
          (hdp)->phd_RecordSizeLow)


#define nstrace_set_start_time_ver(ver) \
    gboolean nstrace_set_start_time_v##ver(wtap *wth) \
    {\
        nstrace_t *nstrace = (nstrace_t *)wth->priv;\
        gchar* nstrace_buf = nstrace->pnstrace_buf;\
        gint32 nstrace_buf_offset = nstrace->nstrace_buf_offset;\
        gint32 nstrace_buflen = nstrace->nstrace_buflen;\
        int bytes_read;\
        do\
        {\
            while (nstrace_buf_offset < nstrace_buflen)\
            {\
                nspr_hd_v##ver##_t *fp = (nspr_hd_v##ver##_t *) &nstrace_buf[nstrace_buf_offset];\
                switch (nspr_getv##ver##recordtype(fp))\
                {\
                    case NSPR_ABSTIME_V##ver:\
                        ns_setabstime(nstrace, pletoh32(&((nspr_abstime_v##ver##_t *) fp)->abs_Time), pletoh16(&((nspr_abstime_v##ver##_t *) fp)->abs_RelTime));\
                        nstrace->nstrace_buf_offset = nstrace_buf_offset + nspr_getv##ver##recordsize(fp);\
                        nstrace->nstrace_buflen = nstrace_buflen;\
                        return TRUE;\
                     case NSPR_UNUSEDSPACE_V10:\
                        nstrace_buf_offset = nstrace_buflen;\
                        break;\
                    default:\
                        nstrace_buf_offset += nspr_getv##ver##recordsize(fp);\
                }\
            }\
            nstrace_buf_offset = 0;\
            nstrace->xxx_offset += nstrace_buflen;\
            nstrace_buflen = GET_READ_PAGE_SIZE((nstrace->file_size - nstrace->xxx_offset));\
        }while((nstrace_buflen > 0) && (bytes_read = file_read(nstrace_buf, nstrace_buflen, wth->fh)) && bytes_read == nstrace_buflen); \
        return FALSE;\
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
static gboolean nstrace_set_start_time(wtap *wth)
{
    if (wth->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_1_0)
        return nstrace_set_start_time_v10(wth);
    else if (wth->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_2_0)
        return nstrace_set_start_time_v20(wth);
    else if (wth->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_3_0)
        return nstrace_set_start_time_v20(wth);
    return FALSE;
}

#define __TNO(phdr,enumprefix,structprefix,structname,hdrname,structfieldname) \
    (phdr)->pseudo_header.nstr.hdrname##_offset = enumprefix##_##hdrname##_offset;

#define __TNL(phdr,enumprefix,structprefix,structname,hdrname,structfieldname) \
    (phdr)->pseudo_header.nstr.hdrname##_len = enumprefix##_##hdrname##_len;

#define __TNV1O(phdr,enumprefix,structprefix,structname,hdrname,structfieldname) \
    __TNO(phdr,enumprefix,structprefix,structname,hdrname,structfieldname)

#define __TNV1L(phdr,enumprefix,structprefix,structname,hdrname,structfieldname) \
    __TNL(phdr,enumprefix,structprefix,structname,hdrname,structfieldname)



/*
** Netscaler trace format read routines.
*/
static gboolean nstrace_read_v10(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
    nstrace_t *nstrace = (nstrace_t *)wth->priv;
    guint64 nsg_creltime = nstrace->nsg_creltime;
    gchar *nstrace_buf = nstrace->pnstrace_buf;
    gint32 nstrace_buf_offset = nstrace->nstrace_buf_offset;
    gint32 nstrace_buflen = nstrace->nstrace_buflen;
    nspr_pktracefull_v10_t *fp;
    nspr_pktracepart_v10_t *pp;
    int bytes_read;

    *err = 0;
    *err_info = NULL;
    do
    {
        while ((nstrace_buf_offset < nstrace_buflen) &&
            ((nstrace_buflen - nstrace_buf_offset) >= ((gint32)sizeof(fp->nsprRecordType))))
        {

#define GENERATE_CASE_FULL(phdr,type,acttype) \
        case NSPR_PDPKTRACEFULLTX_V##type:\
        case NSPR_PDPKTRACEFULLTXB_V##type:\
        case NSPR_PDPKTRACEFULLRX_V##type:\
            fp = (nspr_pktracefull_v10_t *) &nstrace_buf[nstrace_buf_offset];\
            /*\
             * XXX - we can't do this in the seek-read routine,\
             * as the time stamps in the records are relative to\
             * the previous packet.\
             */\
            (phdr)->rec_type = REC_TYPE_PACKET;\
            (phdr)->presence_flags = WTAP_HAS_TS;\
            nsg_creltime += ns_hrtime2nsec(pletoh32(&fp->fp_RelTimeHr));\
            (phdr)->ts.secs = nstrace->nspm_curtime + (guint32) (nsg_creltime / 1000000000);\
            (phdr)->ts.nsecs = (guint32) (nsg_creltime % 1000000000);\
            TRACE_FULL_V##type##_REC_LEN_OFF(phdr,v##type##_full,fp,pktracefull_v##type);\
            buffer_assure_space(wth->frame_buffer, (phdr)->caplen);\
            memcpy(buffer_start_ptr(wth->frame_buffer), fp, (phdr)->caplen);\
            *data_offset = nstrace->xxx_offset + nstrace_buf_offset;\
            nstrace->nstrace_buf_offset = nstrace_buf_offset + (phdr)->len;\
            nstrace->nstrace_buflen = nstrace_buflen;\
            nstrace->nsg_creltime = nsg_creltime;\
            return TRUE;

#define GENERATE_CASE_PART(phdr,type,acttype) \
        case NSPR_PDPKTRACEPARTTX_V##type:\
        case NSPR_PDPKTRACEPARTTXB_V##type:\
        case NSPR_PDPKTRACEPARTRX_V##type:\
            pp = (nspr_pktracepart_v10_t *) &nstrace_buf[nstrace_buf_offset];\
            /*\
             * XXX - we can't do this in the seek-read routine,\
             * as the time stamps in the records are relative to\
             * the previous packet.\
             */\
            (phdr)->rec_type = REC_TYPE_PACKET;\
            (phdr)->presence_flags = WTAP_HAS_TS;\
            nsg_creltime += ns_hrtime2nsec(pletoh32(&pp->pp_RelTimeHr));\
            (phdr)->ts.secs = nstrace->nspm_curtime + (guint32) (nsg_creltime / 1000000000);\
            (phdr)->ts.nsecs = (guint32) (nsg_creltime % 1000000000);\
            TRACE_PART_V##type##_REC_LEN_OFF(phdr,v##type##_part,pp,pktracepart_v##type);\
            buffer_assure_space(wth->frame_buffer, (phdr)->caplen);\
            memcpy(buffer_start_ptr(wth->frame_buffer), pp, (phdr)->caplen);\
            *data_offset = nstrace->xxx_offset + nstrace_buf_offset;\
            nstrace->nstrace_buf_offset = nstrace_buf_offset + (phdr)->caplen;\
            nstrace->nsg_creltime = nsg_creltime;\
            nstrace->nstrace_buflen = nstrace_buflen;\
            return TRUE;\

            switch (pletoh16(&(( nspr_header_v10_t*)&nstrace_buf[nstrace_buf_offset])->ph_RecordType))
            {
                GENERATE_CASE_FULL(&wth->phdr,10,100)
                GENERATE_CASE_PART(&wth->phdr,10,100)

#undef GENERATE_CASE_FULL
#undef GENERATE_CASE_PART

            case NSPR_ABSTIME_V10:

                fp = (nspr_pktracefull_v10_t *) &nstrace_buf[nstrace_buf_offset];
                ns_setabstime(nstrace, pletoh32(((nspr_abstime_v10_t *) fp)->abs_Time), pletoh32(&((nspr_abstime_v10_t *) fp)->abs_RelTime));
                nstrace_buf_offset += pletoh16(&fp->nsprRecordSize);
                break;

            case NSPR_RELTIME_V10:

                fp = (nspr_pktracefull_v10_t *) &nstrace_buf[nstrace_buf_offset];
                ns_setrelativetime(nstrace, pletoh32(((nspr_abstime_v10_t *) fp)->abs_RelTime));
                nstrace_buf_offset += pletoh16(&fp->nsprRecordSize);
                break;

            case NSPR_UNUSEDSPACE_V10:

                nstrace_buf_offset = nstrace_buflen;
                break;

            default:

                fp = (nspr_pktracefull_v10_t *) &nstrace_buf[nstrace_buf_offset];
                nstrace_buf_offset += pletoh16(&fp->nsprRecordSize);
                break;
            }
        }

        nstrace_buf_offset = 0;
        nstrace->xxx_offset += nstrace_buflen;
        nstrace_buflen = GET_READ_PAGE_SIZE((nstrace->file_size - nstrace->xxx_offset));
    }while((nstrace_buflen > 0) && (bytes_read = file_read(nstrace_buf, nstrace_buflen, wth->fh)) && (bytes_read == nstrace_buflen));

    return FALSE;
}

#define TIMEDEFV20(fp,type) \
    do {\
        wth->phdr.rec_type = REC_TYPE_PACKET;\
        wth->phdr.presence_flags |= WTAP_HAS_TS;\
        nsg_creltime += ns_hrtime2nsec(pletoh32(fp->type##_RelTimeHr));\
        wth->phdr.ts.secs = nstrace->nspm_curtime + (guint32) (nsg_creltime / 1000000000);\
        wth->phdr.ts.nsecs = (guint32) (nsg_creltime % 1000000000);\
    }while(0)

#define TIMEDEFV23(fp,type) \
    do {\
        wth->phdr.rec_type = REC_TYPE_PACKET;\
        wth->phdr.presence_flags |= WTAP_HAS_TS;\
        /* access _AbsTimeHr as a 64bit value */\
        nsg_creltime = pletoh64(fp->type##_AbsTimeHr);\
        wth->phdr.ts.secs = (guint32) (nsg_creltime / 1000000000);\
        wth->phdr.ts.nsecs = (guint32) (nsg_creltime % 1000000000);\
    }while(0)

#define TIMEDEFV30(fp,type) \
    do {\
        wth->phdr.rec_type = REC_TYPE_PACKET;\
        wth->phdr.presence_flags |= WTAP_HAS_TS;\
        /* access _AbsTimeHr as a 64bit value */\
        nsg_creltime = pletoh64(fp->type##_AbsTimeHr);\
        wth->phdr.ts.secs = (guint32) (nsg_creltime / 1000000000);\
        wth->phdr.ts.nsecs = (guint32) (nsg_creltime % 1000000000);\
    }while(0)

#define TIMEDEFV21(fp,type) TIMEDEFV20(fp,type)
#define TIMEDEFV22(fp,type) TIMEDEFV20(fp,type)
#define TIMEDEFV24(fp,type) TIMEDEFV23(fp,type)
#define TIMEDEFV25(fp,type) TIMEDEFV24(fp,type)
#define TIMEDEFV26(fp,type) TIMEDEFV24(fp,type)

#define PPSIZEDEFV20(phdr,pp,ver) \
    do {\
        (phdr)->rec_type = REC_TYPE_PACKET;\
        (phdr)->presence_flags |= WTAP_HAS_CAP_LEN;\
        (phdr)->len = pletoh16(&pp->pp_PktSizeOrg) + nspr_pktracepart_v##ver##_s;\
        (phdr)->caplen = nspr_getv20recordsize((nspr_hd_v20_t *)pp);\
    }while(0)

#define PPSIZEDEFV21(phdr,pp,ver) PPSIZEDEFV20(phdr,pp,ver)
#define PPSIZEDEFV22(phdr,pp,ver) PPSIZEDEFV20(phdr,pp,ver)
#define PPSIZEDEFV23(phdr,pp,ver) PPSIZEDEFV20(phdr,pp,ver)
#define PPSIZEDEFV24(phdr,pp,ver) PPSIZEDEFV20(phdr,pp,ver)
#define PPSIZEDEFV25(phdr,pp,ver) PPSIZEDEFV20(phdr,pp,ver)
#define PPSIZEDEFV26(phdr,pp,ver) PPSIZEDEFV20(phdr,pp,ver)

#define FPSIZEDEFV20(phdr,fp,ver)\
    do {\
        (phdr)->len = nspr_getv20recordsize((nspr_hd_v20_t *)fp);\
        (phdr)->caplen = (phdr)->len;\
    }while(0)

#define FPSIZEDEFV21(phdr,fp,ver) FPSIZEDEFV20(phdr,fp,ver)
#define FPSIZEDEFV22(phdr,fp,ver) FPSIZEDEFV20(phdr,fp,ver)
#define FPSIZEDEFV23(phdr,fp,ver) FPSIZEDEFV20(phdr,fp,ver)
#define FPSIZEDEFV24(phdr,fp,ver) FPSIZEDEFV20(phdr,fp,ver)
#define FPSIZEDEFV25(phdr,fp,ver) FPSIZEDEFV20(phdr,fp,ver)
#define FPSIZEDEFV26(phdr,fp,ver) FPSIZEDEFV20(phdr,fp,ver)

#define FPSIZEDEFV30(phdr,fp,ver)\
    do {\
        (phdr)->rec_type = REC_TYPE_PACKET;\
        (phdr)->presence_flags |= WTAP_HAS_CAP_LEN;\
        (phdr)->len = pletoh16(&fp->fp_PktSizeOrg) + nspr_pktracefull_v##ver##_s;\
        (phdr)->caplen = nspr_getv20recordsize((nspr_hd_v20_t *)fp);\
    }while(0)

#define PACKET_DESCRIBE(phdr,FPTIMEDEF,SIZEDEF,ver,enumprefix,type,structname,TYPE)\
    do {\
        nspr_##structname##_t *fp= (nspr_##structname##_t*)&nstrace_buf[nstrace_buf_offset];\
        TIMEDEFV##ver(fp,type);\
        SIZEDEF##ver((phdr),fp,ver);\
        TRACE_V##ver##_REC_LEN_OFF((phdr),enumprefix,type,structname);\
        (phdr)->pseudo_header.nstr.rec_type = NSPR_HEADER_VERSION##TYPE;\
        buffer_assure_space(wth->frame_buffer, (phdr)->caplen);\
        memcpy(buffer_start_ptr(wth->frame_buffer), fp, (phdr)->caplen);\
        *data_offset = nstrace->xxx_offset + nstrace_buf_offset;\
        nstrace->nstrace_buf_offset = nstrace_buf_offset + nspr_getv20recordsize((nspr_hd_v20_t *)fp);\
        nstrace->nstrace_buflen = nstrace_buflen;\
        nstrace->nsg_creltime = nsg_creltime;\
        return TRUE;\
    }while(0)

static gboolean nstrace_read_v20(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
    nstrace_t *nstrace = (nstrace_t *)wth->priv;
    guint64 nsg_creltime = nstrace->nsg_creltime;
    gchar *nstrace_buf = nstrace->pnstrace_buf;
    gint32 nstrace_buf_offset = nstrace->nstrace_buf_offset;
    gint32 nstrace_buflen = nstrace->nstrace_buflen;
    int bytes_read;

    *err = 0;
    *err_info = NULL;
    do
    {
        while ((nstrace_buf_offset < nstrace_buflen) &&
            ((nstrace_buflen - nstrace_buf_offset) >= ((gint32)sizeof((( nspr_hd_v20_t*)&nstrace_buf[nstrace_buf_offset])->phd_RecordType))))
        {
            switch ((( nspr_hd_v20_t*)&nstrace_buf[nstrace_buf_offset])->phd_RecordType)
            {

#define GENERATE_CASE_FULL(phdr,type,acttype) \
        case NSPR_PDPKTRACEFULLTX_V##type:\
        case NSPR_PDPKTRACEFULLTXB_V##type:\
        case NSPR_PDPKTRACEFULLRX_V##type:\
            PACKET_DESCRIBE(phdr,TIMEDEF,FPSIZEDEFV,type,v##type##_full,fp,pktracefull_v##type,acttype);

#define GENERATE_CASE_FULL_V25(phdr,type,acttype) \
        case NSPR_PDPKTRACEFULLTX_V##type:\
        case NSPR_PDPKTRACEFULLTXB_V##type:\
        case NSPR_PDPKTRACEFULLRX_V##type:\
        case NSPR_PDPKTRACEFULLNEWRX_V##type:\
            PACKET_DESCRIBE(phdr,TIMEDEF,FPSIZEDEFV,type,v##type##_full,fp,pktracefull_v##type,acttype);

#define GENERATE_CASE_PART(phdr,type,acttype) \
        case NSPR_PDPKTRACEPARTTX_V##type:\
        case NSPR_PDPKTRACEPARTTXB_V##type:\
        case NSPR_PDPKTRACEPARTRX_V##type:\
            PACKET_DESCRIBE(phdr,TIMEDEF,PPSIZEDEFV,type,v##type##_part,pp,pktracepart_v##type,acttype);

#define GENERATE_CASE_PART_V25(phdr,type,acttype) \
        case NSPR_PDPKTRACEPARTTX_V##type:\
        case NSPR_PDPKTRACEPARTTXB_V##type:\
        case NSPR_PDPKTRACEPARTRX_V##type:\
        case NSPR_PDPKTRACEPARTNEWRX_V##type:\
            PACKET_DESCRIBE(phdr,TIMEDEF,PPSIZEDEFV,type,v##type##_part,pp,pktracepart_v##type,acttype);

                GENERATE_CASE_FULL(&wth->phdr,20,200);
                GENERATE_CASE_PART(&wth->phdr,20,200);
                GENERATE_CASE_FULL(&wth->phdr,21,201);
                GENERATE_CASE_PART(&wth->phdr,21,201);
                GENERATE_CASE_FULL(&wth->phdr,22,202);
                GENERATE_CASE_PART(&wth->phdr,22,202);
                GENERATE_CASE_FULL(&wth->phdr,23,203);
                GENERATE_CASE_PART(&wth->phdr,23,203);
                GENERATE_CASE_FULL_V25(&wth->phdr,24,204);
                GENERATE_CASE_PART_V25(&wth->phdr,24,204);
                GENERATE_CASE_FULL_V25(&wth->phdr,25,205);
                GENERATE_CASE_PART_V25(&wth->phdr,25,205);
                GENERATE_CASE_FULL_V25(&wth->phdr,26,206);
                GENERATE_CASE_PART_V25(&wth->phdr,26,206);

#undef GENERATE_CASE_FULL
#undef GENERATE_CASE_FULL_V25
#undef GENERATE_CASE_PART
#undef GENERATE_CASE_PART_V25

                case NSPR_ABSTIME_V20:
                {
                    nspr_pktracefull_v20_t *fp20 = (nspr_pktracefull_v20_t *) &nstrace_buf[nstrace_buf_offset];
                    nstrace_buf_offset += nspr_getv20recordsize((nspr_hd_v20_t *)fp20);
                    ns_setabstime(nstrace, pletoh32(&((nspr_abstime_v20_t *) fp20)->abs_Time), pletoh16(&((nspr_abstime_v20_t *) fp20)->abs_RelTime));
                    break;
                }

                case NSPR_RELTIME_V20:
                {
                    nspr_pktracefull_v20_t *fp20 = (nspr_pktracefull_v20_t *) &nstrace_buf[nstrace_buf_offset];
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
                    nspr_pktracefull_v20_t *fp20 = (nspr_pktracefull_v20_t *) &nstrace_buf[nstrace_buf_offset];
                    nstrace_buf_offset += nspr_getv20recordsize((nspr_hd_v20_t *)fp20);
                    break;
                }
            }
        }

        nstrace_buf_offset = 0;
        nstrace->xxx_offset += nstrace_buflen;
        nstrace_buflen = GET_READ_PAGE_SIZE((nstrace->file_size - nstrace->xxx_offset));
    }while((nstrace_buflen > 0) && (bytes_read = file_read(nstrace_buf, nstrace_buflen, wth->fh)) && (bytes_read == nstrace_buflen));

    return FALSE;
}

#undef PACKET_DESCRIBE

#define PACKET_DESCRIBE(phdr,FPTIMEDEF,SIZEDEF,ver,enumprefix,type,structname,TYPE)\
    do {\
    nspr_##structname##_t *fp = (nspr_##structname##_t *) &nstrace_buf[nstrace_buf_offset];\
    TIMEDEFV##ver(fp,type);\
    SIZEDEF##ver((phdr),fp,ver);\
    TRACE_V##ver##_REC_LEN_OFF((phdr),enumprefix,type,structname);\
    (phdr)->pseudo_header.nstr.rec_type = NSPR_HEADER_VERSION##TYPE;\
    buffer_assure_space(wth->frame_buffer, (phdr)->caplen);\
    *data_offset = nstrace->xxx_offset + nstrace_buf_offset;\
    while (nstrace_tmpbuff_off < nspr_##structname##_s) {\
        nstrace_tmpbuff[nstrace_tmpbuff_off++] = nstrace_buf[nstrace_buf_offset++];\
    }\
    nst_dataSize = nspr_getv20recordsize(hdp);\
    rec_size = nst_dataSize - nstrace_tmpbuff_off;\
    nsg_nextPageOffset = ((nstrace_buf_offset + rec_size) >= NSPR_PAGESIZE_TRACE) ?\
    ((nstrace_buf_offset + rec_size) - (NSPR_PAGESIZE_TRACE - 1)) : 0;\
    while (nsg_nextPageOffset) {\
        while (nstrace_buf_offset < NSPR_PAGESIZE_TRACE) {\
            nstrace_tmpbuff[nstrace_tmpbuff_off++] = nstrace_buf[nstrace_buf_offset++];\
        }\
        nstrace_buflen = NSPR_PAGESIZE_TRACE;\
        nstrace->xxx_offset += nstrace_buflen;\
        bytes_read = file_read(nstrace_buf, NSPR_PAGESIZE_TRACE, wth->fh);\
        if (bytes_read != NSPR_PAGESIZE_TRACE) {\
            return FALSE;\
        } else {\
            nstrace_buf_offset = 0;\
        }\
        rec_size = nst_dataSize - nstrace_tmpbuff_off;\
        nsg_nextPageOffset = ((nstrace_buf_offset + rec_size) >= NSPR_PAGESIZE_TRACE) ?\
        ((nstrace_buf_offset + rec_size) - (NSPR_PAGESIZE_TRACE- 1)): 0;\
    } \
    while (nstrace_tmpbuff_off < nst_dataSize) {\
        nstrace_tmpbuff[nstrace_tmpbuff_off++] = nstrace_buf[nstrace_buf_offset++];\
    }\
    memcpy(buffer_start_ptr(wth->frame_buffer), nstrace_tmpbuff, (phdr)->caplen);\
    nstrace->nstrace_buf_offset = nstrace_buf_offset;\
    nstrace->nstrace_buflen = nstrace_buflen = ((gint32)NSPR_PAGESIZE_TRACE);\
    nstrace->nsg_creltime = nsg_creltime;\
    return TRUE;\
} while(0)

static gboolean nstrace_read_v30(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
    nstrace_t *nstrace = (nstrace_t *)wth->priv;
    guint64 nsg_creltime = nstrace->nsg_creltime;
    gchar *nstrace_buf = nstrace->pnstrace_buf;
    gint32 nstrace_buf_offset = nstrace->nstrace_buf_offset;
    gint32 nstrace_buflen = nstrace->nstrace_buflen;
    guint8 nstrace_tmpbuff[65536];
    guint32 nstrace_tmpbuff_off=0,nst_dataSize=0,rec_size=0,nsg_nextPageOffset=0;
    nspr_hd_v20_t *hdp;
    int bytes_read;
    *err = 0;
    *err_info = NULL;

    do
    {
        while ((nstrace_buf_offset < NSPR_PAGESIZE_TRACE) &&
            nstrace_buf[nstrace_buf_offset])
        {
            hdp = (nspr_hd_v20_t *) &nstrace_buf[nstrace_buf_offset];
            switch (hdp->phd_RecordType)
            {

#define GENERATE_CASE_V30(phdr,type,acttype) \
        case NSPR_PDPKTRACEFULLTX_V##type:\
        case NSPR_PDPKTRACEFULLTXB_V##type:\
        case NSPR_PDPKTRACEFULLRX_V##type:\
        case NSPR_PDPKTRACEFULLNEWRX_V##type:\
        PACKET_DESCRIBE(phdr, TIMEDEF, FPSIZEDEFV,type,v##type##_full,fp,pktracefull_v##type,acttype);
        GENERATE_CASE_V30(&wth->phdr,30, 300);
#undef GENERATE_CASE_V30

                case NSPR_ABSTIME_V20:
                {
                    nstrace_buf_offset += nspr_getv20recordsize(hdp);
                    ns_setabstime(nstrace, pletoh32(&((nspr_abstime_v20_t *) &nstrace_buf[nstrace_buf_offset])->abs_Time), pletoh16(&((nspr_abstime_v20_t *) &nstrace_buf[nstrace_buf_offset])->abs_RelTime));
                    break;
                }

                case NSPR_RELTIME_V20:
                {
                    ns_setrelativetime(nstrace, pletoh16(&((nspr_abstime_v20_t *) &nstrace_buf[nstrace_buf_offset])->abs_RelTime));
                    nstrace_buf_offset += nspr_getv20recordsize(hdp);
                    break;
                }

                default:
                {
                    nstrace_buf_offset += nspr_getv20recordsize(hdp);
                    break;
                }
            }
        }
        nstrace_buf_offset = 0;
        nstrace->xxx_offset += nstrace_buflen;
        nstrace_buflen = NSPR_PAGESIZE_TRACE;
    } while((nstrace_buflen > 0) && (bytes_read = file_read(nstrace_buf, nstrace_buflen, wth->fh)) && (bytes_read == nstrace_buflen));

    return FALSE;
}

#undef PACKET_DESCRIBE

static gboolean nstrace_seek_read_v10(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info)
{
    nspr_hd_v10_t hdr;
    int bytes_read;
    guint record_length;
    guint8 *pd;
    unsigned int bytes_to_read;
    nspr_pktracefull_v10_t *fp;
    nspr_pktracepart_v10_t *pp;

    *err = 0;

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return FALSE;

    /*
    ** Read the record header.
    */
    bytes_read = file_read((void *)&hdr, sizeof hdr, wth->random_fh);
    if (bytes_read != sizeof hdr) {
        *err = file_error(wth->random_fh, err_info);
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return FALSE;
    }

    /*
    ** Get the record length.
    */
    record_length = nspr_getv10recordsize(&hdr);

    /*
    ** Copy the header to the buffer and read the rest of the record..
    */
    buffer_assure_space(buf, record_length);
    pd = buffer_start_ptr(buf);
    memcpy(pd, (void *)&hdr, sizeof hdr);
    if (record_length > sizeof hdr) {
    	bytes_to_read = (unsigned int)(record_length - sizeof hdr);
        bytes_read = file_read(pd + sizeof hdr, bytes_to_read, wth->random_fh);
        if (bytes_read < 0 || (unsigned int)bytes_read != bytes_to_read) {
            *err = file_error(wth->random_fh, err_info);
            if (*err == 0)
                *err = WTAP_ERR_SHORT_READ;
            return FALSE;
        }
    }

    /*
    ** Fill in what part of the struct wtap_pkthdr we can.
    */
#define GENERATE_CASE_FULL(phdr,type,acttype) \
        case NSPR_PDPKTRACEFULLTX_V##type:\
        case NSPR_PDPKTRACEFULLTXB_V##type:\
        case NSPR_PDPKTRACEFULLRX_V##type:\
            fp = (nspr_pktracefull_v10_t *) pd;\
            TRACE_FULL_V##type##_REC_LEN_OFF(phdr,v##type##_full,fp,pktracefull_v##type);\
            (phdr)->pseudo_header.nstr.rec_type = NSPR_HEADER_VERSION##acttype;\
            break;

#define GENERATE_CASE_PART(phdr,type,acttype) \
        case NSPR_PDPKTRACEPARTTX_V##type:\
        case NSPR_PDPKTRACEPARTTXB_V##type:\
        case NSPR_PDPKTRACEPARTRX_V##type:\
            pp = (nspr_pktracepart_v10_t *) pd;\
            TRACE_PART_V##type##_REC_LEN_OFF(phdr,v##type##_part,pp,pktracepart_v##type);\
            (phdr)->pseudo_header.nstr.rec_type = NSPR_HEADER_VERSION##acttype;\
            break;

    switch (pletoh16(&(( nspr_header_v10_t*)pd)->ph_RecordType))
    {
        GENERATE_CASE_FULL(phdr,10,100)
        GENERATE_CASE_PART(phdr,10,100)
    }

#undef GENERATE_CASE_FULL
#undef GENERATE_CASE_PART

    return TRUE;
}

#define PACKET_DESCRIBE(phdr,FPTIMEDEF,SIZEDEF,ver,enumprefix,type,structname,TYPE)\
    do {\
        nspr_##structname##_t *fp= (nspr_##structname##_t*)pd;\
        SIZEDEF##ver((phdr),fp,ver);\
        TRACE_V##ver##_REC_LEN_OFF((phdr),enumprefix,type,structname);\
        (phdr)->pseudo_header.nstr.rec_type = NSPR_HEADER_VERSION##TYPE;\
        return TRUE;\
    }while(0)

static gboolean nstrace_seek_read_v20(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info)
{
    nspr_hd_v20_t hdr;
    int bytes_read;
    guint record_length;
    guint hdrlen;
    guint8 *pd;
    unsigned int bytes_to_read;

    *err = 0;

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return FALSE;

    /*
    ** Read the first 2 bytes of the record header.
    */
    bytes_read = file_read((void *)&hdr, 2, wth->random_fh);
    if (bytes_read != 2) {
        *err = file_error(wth->random_fh, err_info);
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return FALSE;
    }
    hdrlen = 2;

    /*
    ** Is there a third byte?  If so, read it.
    */
    if (hdr.phd_RecordSizeLow & NSPR_V20RECORDSIZE_2BYTES) {
        bytes_read = file_read((void *)&hdr.phd_RecordSizeHigh, 1, wth->random_fh);
        if (bytes_read != 1) {
            *err = file_error(wth->random_fh, err_info);
            if (*err == 0)
                *err = WTAP_ERR_SHORT_READ;
            return FALSE;
        }
        hdrlen = 3;
    }

    /*
    ** Get the record length.
    */
    record_length = nspr_getv20recordsize(&hdr);

    /*
    ** Copy the header to the buffer and read the rest of the record..
    */
    buffer_assure_space(buf, record_length);
    pd = buffer_start_ptr(buf);
    memcpy(pd, (void *)&hdr, hdrlen);
    if (record_length > hdrlen) {
    	bytes_to_read = (unsigned int)(record_length - hdrlen);
        bytes_read = file_read(pd + hdrlen, bytes_to_read, wth->random_fh);
        if (bytes_read < 0 || (unsigned int)bytes_read != bytes_to_read) {
            *err = file_error(wth->random_fh, err_info);
            if (*err == 0)
                *err = WTAP_ERR_SHORT_READ;
            return FALSE;
        }
    }

#define GENERATE_CASE_FULL(phdr,type,acttype) \
        case NSPR_PDPKTRACEFULLTX_V##type:\
        case NSPR_PDPKTRACEFULLTXB_V##type:\
        case NSPR_PDPKTRACEFULLRX_V##type:\
            PACKET_DESCRIBE(phdr,TIMEDEF,FPSIZEDEFV,type,v##type##_full,fp,pktracefull_v##type,acttype);

#define GENERATE_CASE_FULL_V25(phdr,type,acttype) \
        case NSPR_PDPKTRACEFULLTX_V##type:\
        case NSPR_PDPKTRACEFULLTXB_V##type:\
        case NSPR_PDPKTRACEFULLRX_V##type:\
        case NSPR_PDPKTRACEFULLNEWRX_V##type:\
            PACKET_DESCRIBE(phdr,TIMEDEF,FPSIZEDEFV,type,v##type##_full,fp,pktracefull_v##type,acttype);

#define GENERATE_CASE_PART(phdr,type,acttype) \
        case NSPR_PDPKTRACEPARTTX_V##type:\
        case NSPR_PDPKTRACEPARTTXB_V##type:\
        case NSPR_PDPKTRACEPARTRX_V##type:\
            PACKET_DESCRIBE(phdr,TIMEDEF,PPSIZEDEFV,type,v##type##_part,pp,pktracepart_v##type,acttype);

#define GENERATE_CASE_PART_V25(phdr,type,acttype) \
        case NSPR_PDPKTRACEPARTTX_V##type:\
        case NSPR_PDPKTRACEPARTTXB_V##type:\
        case NSPR_PDPKTRACEPARTRX_V##type:\
        case NSPR_PDPKTRACEPARTNEWRX_V##type:\
            PACKET_DESCRIBE(phdr,TIMEDEF,PPSIZEDEFV,type,v##type##_part,pp,pktracepart_v##type,acttype);

    switch ((( nspr_hd_v20_t*)pd)->phd_RecordType)
    {
        GENERATE_CASE_FULL(phdr,20,200)
        GENERATE_CASE_PART(phdr,20,200)
        GENERATE_CASE_FULL(phdr,21,201)
        GENERATE_CASE_PART(phdr,21,201)
        GENERATE_CASE_FULL(phdr,22,202)
        GENERATE_CASE_PART(phdr,22,202)
        GENERATE_CASE_FULL(phdr,23,203)
        GENERATE_CASE_PART(phdr,23,203)
        GENERATE_CASE_FULL_V25(phdr,24,204)
        GENERATE_CASE_PART_V25(phdr,24,204)
        GENERATE_CASE_FULL_V25(phdr,25,205)
        GENERATE_CASE_PART_V25(phdr,25,205)
        GENERATE_CASE_FULL_V25(phdr,26,206)
        GENERATE_CASE_PART_V25(phdr,26,206)
    }

#undef GENERATE_CASE_FULL
#undef GENERATE_CASE_FULL_V25
#undef GENERATE_CASE_PART
#undef GENERATE_CASE_PART_V25

    return TRUE;
}


static gboolean nstrace_seek_read_v30(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info)
{
    nspr_hd_v20_t hdr;
    int bytes_read;
    guint record_length;
    guint hdrlen;
    guint8 *pd;
    unsigned int bytes_to_read;

    *err = 0;

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return FALSE;
    /*
    ** Read the first 2 bytes of the record header.
    */
    bytes_read = file_read((void *)&hdr, 2, wth->random_fh);
    if (bytes_read != 2) {
        *err = file_error(wth->random_fh, err_info);
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return FALSE;
    }
    hdrlen = 2;

    /*
    ** Is there a third byte?  If so, read it.
    */
    if (hdr.phd_RecordSizeLow & NSPR_V20RECORDSIZE_2BYTES) {
        bytes_read = file_read((void *)&hdr.phd_RecordSizeHigh, 1, wth->random_fh);
        if (bytes_read != 1) {
            *err = file_error(wth->random_fh, err_info);
            if (*err == 0)
                *err = WTAP_ERR_SHORT_READ;
            return FALSE;
        }
        hdrlen = 3;
    }

    /*
    ** Get the record length.
    */
    record_length = nspr_getv20recordsize(&hdr);

    /*
    ** Copy the header to the buffer and read the rest of the record..
    */
    buffer_assure_space(buf, record_length);
    pd = buffer_start_ptr(buf);
    memcpy(pd, (void *)&hdr, hdrlen);
    if (record_length > hdrlen) {
        bytes_to_read = (unsigned int)(record_length - hdrlen);
        bytes_read = file_read(pd + hdrlen, bytes_to_read, wth->random_fh);
        if (bytes_read < 0 || (unsigned int)bytes_read != bytes_to_read) {
            *err = file_error(wth->random_fh, err_info);
            if (*err == 0)
                *err = WTAP_ERR_SHORT_READ;
            return FALSE;
        }
    }

#define GENERATE_CASE_V30(phdr,type,acttype) \
    case NSPR_PDPKTRACEFULLTX_V##type:\
    case NSPR_PDPKTRACEFULLTXB_V##type:\
    case NSPR_PDPKTRACEFULLRX_V##type:\
    case NSPR_PDPKTRACEFULLNEWRX_V##type:\
    TRACE_V##type##_REC_LEN_OFF((phdr),v##type##_full,fp,pktracefull_v##type);\
        (phdr)->pseudo_header.nstr.rec_type = NSPR_HEADER_VERSION##acttype;\
        break;

        switch ((( nspr_hd_v20_t*)pd)->phd_RecordType)
        {
            GENERATE_CASE_V30(phdr,30, 300);
        }

    return TRUE;
}


/*
** Netscaler trace format close routines.
*/
static void nstrace_close(wtap *wth)
{
    nstrace_t *nstrace = (nstrace_t *)wth->priv;

    g_free(nstrace->pnstrace_buf);
}


typedef struct {
    guint16 page_offset;
    guint16 page_len;
    guint32 absrec_time;
} nstrace_dump_t;

/* Returns 0 if we could write the specified encapsulation type,
** an error indication otherwise. */
int nstrace_10_dump_can_write_encap(int encap)
{
    if (encap == WTAP_ENCAP_NSTRACE_1_0)
        return 0;

    return WTAP_ERR_UNSUPPORTED_ENCAP;
}


/* Returns 0 if we could write the specified encapsulation type,
** an error indication otherwise. */
int nstrace_20_dump_can_write_encap(int encap)
{
    if (encap == WTAP_ENCAP_NSTRACE_2_0)
        return 0;

    return WTAP_ERR_UNSUPPORTED_ENCAP;
}

/* Returns 0 if we could write the specified encapsulation type,
** an error indication otherwise. */
int nstrace_30_dump_can_write_encap(int encap)
{
    if (encap == WTAP_ENCAP_NSTRACE_3_0)
        return 0;

    return WTAP_ERR_UNSUPPORTED_ENCAP;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
** failure */
gboolean nstrace_dump_open(wtap_dumper *wdh, int *err _U_)
{
    nstrace_dump_t *nstrace;

    wdh->subtype_write = nstrace_dump;

    nstrace = (nstrace_dump_t *)g_malloc(sizeof(nstrace_dump_t));
    wdh->priv = (void *)nstrace;
    nstrace->page_offset = 0;
    nstrace->page_len = NSPR_PAGESIZE;
    nstrace->absrec_time = 0;

    return TRUE;
}


static gboolean nstrace_add_signature(wtap_dumper *wdh, int *err)
{
    nstrace_dump_t *nstrace = (nstrace_dump_t *)wdh->priv;

    if (wdh->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_1_0)
    {
        guint16 val16b;
        nspr_signature_v10_t sig10;

        /* populate the record */
        val16b = GUINT16_TO_LE(NSPR_SIGNATURE_V10);
        memcpy(sig10.phd.ph_RecordType, &val16b, sizeof sig10.phd.ph_RecordType);
        val16b = GUINT16_TO_LE(nspr_signature_v10_s);
        memcpy(sig10.phd.ph_RecordSize, &val16b, sizeof sig10.phd.ph_RecordSize);
        memset(sig10.sig_Signature, 0, NSPR_SIGSIZE_V10);
        g_strlcpy(sig10.sig_Signature, NSPR_SIGSTR_V10, NSPR_SIGSIZE_V10);

        /* Write the record into the file */
        if (!wtap_dump_file_write(wdh, &sig10, nspr_signature_v10_s,
            err))
            return FALSE;

        /* Move forward the page offset */
        nstrace->page_offset += (guint16) nspr_signature_v10_s;

    } else if (wdh->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_2_0)
    {
        nspr_signature_v20_t sig20;

        sig20.sig_RecordType = NSPR_SIGNATURE_V20;
        sig20.sig_RecordSize = nspr_signature_v20_s;
        memcpy(sig20.sig_Signature, NSPR_SIGSTR_V20, sizeof(NSPR_SIGSTR_V20));

        /* Write the record into the file */
        if (!wtap_dump_file_write(wdh, &sig20, sig20.sig_RecordSize,
            err))
            return FALSE;

        /* Move forward the page offset */
        nstrace->page_offset += (guint16) sig20.sig_RecordSize;

    } else if (wdh->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_3_0)
    {
        nspr_signature_v30_t sig30;

        sig30.sig_RecordType = NSPR_SIGNATURE_V30;
        sig30.sig_RecordSize = nspr_signature_v30_s;
        memcpy(sig30.sig_Signature, NSPR_SIGSTR_V30, sizeof(NSPR_SIGSTR_V30));

        /* Write the record into the file */
        if (!wtap_dump_file_write(wdh, &sig30, sig30.sig_RecordSize,
            err))
            return FALSE;

        /* Move forward the page offset */
        nstrace->page_offset += (guint16) sig30.sig_RecordSize;
    } else
    {
        g_assert_not_reached();
        return FALSE;
    }

    return TRUE;
}


static gboolean
nstrace_add_abstime(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
     const guint8 *pd, int *err)
{
    nstrace_dump_t *nstrace = (nstrace_dump_t *)wdh->priv;
    guint64 nsg_creltime;

    if (wdh->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_1_0)
    {
        guint16 val16;
        guint32 reltime;
        guint64 abstime;
        nspr_abstime_v10_t abs10;

        /* populate the record */
        val16 = GUINT16_TO_LE(NSPR_ABSTIME_V10);
        memcpy(abs10.phd.ph_RecordType, &val16, sizeof abs10.phd.ph_RecordType);
        val16 = GUINT16_TO_LE(nspr_abstime_v10_s);
        memcpy(abs10.phd.ph_RecordSize, &val16, sizeof abs10.phd.ph_RecordSize);

        memcpy(&reltime, ((const nspr_pktracefull_v10_t *)pd)->fp_RelTimeHr, sizeof reltime);
        nsg_creltime = ns_hrtime2nsec(reltime);

        memset(abs10.abs_RelTime, 0, sizeof abs10.abs_RelTime);
        abstime = GUINT32_TO_LE((guint32)phdr->ts.secs - (guint32)(nsg_creltime/1000000000));
        memcpy(abs10.abs_Time, &abstime, sizeof abs10.abs_Time);

        /* Write the record into the file */
        if (!wtap_dump_file_write(wdh, &abs10, nspr_abstime_v10_s, err))
            return FALSE;

        /* Move forward the page offset */
        nstrace->page_offset += nspr_abstime_v10_s;

    } else if ((wdh->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_2_0) ||
        (wdh->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_3_0))    {
        guint32 reltime;
        guint64 abstime;
        nspr_abstime_v20_t abs20;

        abs20.abs_RecordType = NSPR_ABSTIME_V20;
        abs20.abs_RecordSize = nspr_abstime_v20_s;

        memcpy(&reltime, ((const nspr_pktracefull_v20_t *)pd)->fp_RelTimeHr, sizeof reltime);
        nsg_creltime = ns_hrtime2nsec(reltime);

        memset(abs20.abs_RelTime, 0, sizeof abs20.abs_RelTime);
        abstime = GUINT32_TO_LE((guint32)phdr->ts.secs - (guint32)(nsg_creltime/1000000000));
        memcpy(abs20.abs_RelTime, &abstime, sizeof abs20.abs_RelTime);

        /* Write the record into the file */
        if (!wtap_dump_file_write(wdh, &abs20, nspr_abstime_v20_s, err))
            return FALSE;

        /* Move forward the page offset */
        nstrace->page_offset += nspr_abstime_v20_s;

    } else
    {
        g_assert_not_reached();
        return FALSE;
    }

    return TRUE;
}


/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean nstrace_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const guint8 *pd, int *err)
{
    nstrace_dump_t *nstrace = (nstrace_dump_t *)wdh->priv;

    /* We can only write packet records. */
    if (phdr->rec_type != REC_TYPE_PACKET) {
        *err = WTAP_ERR_REC_TYPE_UNSUPPORTED;
        return FALSE;
    }

    if (nstrace->page_offset == 0)
    {
        /* Add the signature record and abs time record */
        if (wdh->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_1_0)
        {
            if (!nstrace_add_signature(wdh, err) ||
                !nstrace_add_abstime(wdh, phdr, pd, err))
                return FALSE;
        } else if (wdh->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_2_0)
        {
            if (!nstrace_add_signature(wdh, err) ||
                !nstrace_add_abstime(wdh, phdr, pd, err))
                return FALSE;
        } else if (wdh->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_3_0)
        {
            if (!nstrace_add_signature(wdh, err) ||
                !nstrace_add_abstime(wdh, phdr, pd, err))
                return FALSE;
        } else
        {
            g_assert_not_reached();
            return FALSE;
        }
    }

    switch (phdr->pseudo_header.nstr.rec_type)
    {
    case NSPR_HEADER_VERSION100:

        if (wdh->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_1_0)
        {
            if (nstrace->page_offset + phdr->caplen >= nstrace->page_len)
            {
                /* Start on the next page */
                if (wtap_dump_file_seek(wdh, (nstrace->page_len - nstrace->page_offset), SEEK_CUR, err) == -1)
                    return FALSE;

                nstrace->page_offset = 0;

                /* Possibly add signature and abstime records and increment offset */
                if (!nstrace_add_signature(wdh, err))
                    return FALSE;
            }

            /* Write the actual record as is */
            if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
                return FALSE;

            nstrace->page_offset += (guint16) phdr->caplen;
        } else if (wdh->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_2_0)
        {
            *err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
            return FALSE;
        }

        break;

    case NSPR_HEADER_VERSION200:
    case NSPR_HEADER_VERSION201:
    case NSPR_HEADER_VERSION202:
    case NSPR_HEADER_VERSION203:
    case NSPR_HEADER_VERSION204:
    case NSPR_HEADER_VERSION205:
    case NSPR_HEADER_VERSION206:
        if (wdh->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_1_0)
        {
            *err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
            return FALSE;
        } else if (wdh->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_2_0)
        {
            if (nstrace->page_offset + phdr->caplen >= nstrace->page_len)
            {
                /* Start on the next page */
                if (wtap_dump_file_seek(wdh, (nstrace->page_len - nstrace->page_offset), SEEK_CUR, err) == -1)
                    return FALSE;

                nstrace->page_offset = 0;

                /* Possibly add signature and abstime records and increment offset */
                if (!nstrace_add_signature(wdh, err))
                    return FALSE;
            }

            /* Write the actual record as is */
            if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
                return FALSE;

            nstrace->page_offset += (guint16) phdr->caplen;
        }

        break;

    case NSPR_HEADER_VERSION300:
        if (wdh->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_1_0)
        {
            *err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
            return FALSE;
        } else if (wdh->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_2_0)
        {
            *err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
            return FALSE;
        } else if (wdh->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_NETSCALER_3_0)
        {
            if (nstrace->page_offset + phdr->caplen >= nstrace->page_len)
            {
                /* Start on the next page */
                if (wtap_dump_file_seek(wdh, (nstrace->page_len - nstrace->page_offset), SEEK_CUR, err) == -1)
                    return FALSE;

                nstrace->page_offset = 0;

                /* Possibly add signature and abstime records and increment offset */
                if (!nstrace_add_signature(wdh, err))
                    return FALSE;
            }

            /* Write the actual record as is */
            if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
                return FALSE;

            nstrace->page_offset += (guint16) phdr->caplen;
        } else
        {
            g_assert_not_reached();
            return FALSE;
        }
        break;

    default:
        g_assert_not_reached();
        return FALSE;
    }

    return TRUE;
}
