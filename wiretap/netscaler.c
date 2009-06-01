/* netscaler.c
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "netscaler.h"

/* Defines imported from netscaler code: nstypes.h */

#define ns_min(a, b)	((a<b)?a:b)

/* Defines imported from netscaler code: nsperfrc.h */

#define	NSPR_SIGSTR_V10	"NetScaler Performance Data"
#define	NSPR_SIGSTR_V20	"NetScaler V20 Performance Data"
#define	NSPR_SIGSTR	NSPR_SIGSTR_V20
/* Defined but not used */
#define	NSPR_SIGSTR_V21	"NetScaler V21 Performance Data"
#define	NSPR_SIGSTR_V22	"NetScaler V22 Performance Data"

#define	NSPR_PAGESIZE	8192

/* The different record types
** NOTE: The Record Type is two byte fields and unused space is recognized by
** either bytes being zero, therefore no record should any byte value as
** zero.
**
** New Performance Record Type is only one byte.
*/
#define	NSPR_UNUSEDSPACE_V10	0x0000	/* rest of the page is unused */
#define	NSPR_UNUSEDSPACE_V20	0x00	/* rest of the page is unused */
#define	NSPR_SIGNATURE_V10	0x0101	/* signature */
#define	NSPR_SIGNATURE_V20	0x01	/* signature */
#define	NSPR_ABSTIME_V10	0x0107	/* data capture time in secs from 1970*/
#define	NSPR_ABSTIME_V20	0x07	/* data capture time in secs from 1970*/
#define	NSPR_RELTIME_V10	0x0108	/* relative time in ms from last time */
#define	NSPR_RELTIME_V20	0x08	/* relative time in ms from last time */
#define	NSPR_RELTIMEHR_V10	0x0109	/* high resolution relative time */
#define	NSPR_RELTIMEHR_V20	0x09	/* high resolution relative time */
#define	NSPR_SYSTARTIME_V10	0x010A	/* system start time */
#define	NSPR_SYSTARTIME_V20	0x0A	/* system start time */
#define	NSPR_RELTIME2B_V10	0x010B	/* relative time in ms from last time */
#define	NSPR_RELTIME2B_V20	0x0B	/* relative time in ms from last time */


/* The high resolution relative time format.
** The MS 2 bits of the high resoltion time is defined as follows:
** 00 : time value is in second
** 01 : time value is in mili second
** 10 : time value is in micro second
** 11 : time value is in nano second
*/
#define	NSPR_HRTIME_MASKTM	0x3FFFFFFF /* mask to get time value */
#define	NSPR_HRTIME_MASKFMT	0xC0000000 /* time value format mask */
#define	NSPR_HRTIME_SEC		0x00000000 /* time value in second */
#define	NSPR_HRTIME_MSEC	0x40000000 /* time value in mili second */
#define	NSPR_HRTIME_USEC	0x80000000 /* time value in micro second */
#define	NSPR_HRTIME_NSEC	0xC0000000 /* time value in nano second */


typedef  struct nspr_header_v10
{
	guint16	ph_RecordType;	/* Record Type */
	guint16	ph_RecordSize;	/* Record Size including header */
} nspr_header_v10_t;
#define	nspr_header_v10_s	sizeof(nspr_header_v10_t)

/* This is V20 short header (2 bytes long) to be included where needed */
#define NSPR_HEADER_V20(prefix) \
    guint8 prefix##_RecordType;    /* Record Type */ \
	guint8 prefix##_RecordSize     /* Record Size including header */	\
					/* end of declaration */

/* This is new long header (3 bytes long) to be included where needed */
#define	NSPR_HEADER3B_V20(prefix) \
	guint8	prefix##_RecordType;	/* Record Type */ \
	guint8	prefix##_RecordSizeLow;	/* Record Size including header */ \
	guint8	prefix##_RecordSizeHigh	/* Record Size including header */ \
					/* end of declaration */
#define NSPR_HEADER3B_V21 NSPR_HEADER3B_V20
#define NSPR_HEADER3B_V22 NSPR_HEADER3B_V20

typedef  struct nspr_hd_v20
{
	NSPR_HEADER3B_V20(phd);		/* long performance header */

} nspr_hd_v20_t;
#define nspr_hd_v20_s	sizeof(nspr_hd_v20_t)


/*
** How to know if header size is short or long?
** The short header size can be 0-127 bytes long. If MS Bit of ph_RecordSize
** is set then record size has 2 bytes
*/
#define	NSPR_V20RECORDSIZE_2BYTES	0x80

/* get the record size from performance record */
#define	nspr_getv20recordsize(hdp) \
	(((hdp)->phd_RecordSizeLow & NSPR_V20RECORDSIZE_2BYTES)? \
		(((hdp)->phd_RecordSizeHigh * NSPR_V20RECORDSIZE_2BYTES)+ \
		 ((hdp)->phd_RecordSizeLow & ~NSPR_V20RECORDSIZE_2BYTES)) : \
		  (hdp)->phd_RecordSizeLow)



/* Performance Data Header with device number */
typedef  struct nspr_headerdev_v10
{
	guint16	ph_RecordType;	/* Record Type */
	guint16	ph_RecordSize;	/* Record Size including header */
	guint32	ph_DevNo;	/* Network Device (NIC/CONN) number */
} nspr_headerdev_v10_t;
#define	nspr_headerdev_v10_s	sizeof(nspr_headerdev_v10_t)

typedef	struct nspr_hd_v10
{
	nspr_header_v10_t phd;	/* performance header */
} nspr_hd_v10_t;
#define	nspr_hd_v10_s	sizeof(nspr_hd_v10_t)

typedef	struct nspr_hdev_v10
{
	nspr_headerdev_v10_t phd;	/* performance header */
} nspr_hdev_v10_t;
#define	nspr_hdev_v10_s	sizeof(nspr_hdev_v10_t)

/* if structure has defined phd as first field, it can use following names */
#define	nsprRecordType		phd.ph_RecordType
#define	nsprRecordSize		phd.ph_RecordSize
#define	nsprReserved		phd.ph_Reserved
#define	nsprRecordTypeOrg	phd.ph_Reserved
#define	nsprDevNo		phd.ph_DevNo

/* NSPR_SIGNATURE_V10 structure */
#define	NSPR_SIGSIZE_V10	56	/* signature value size in bytes */


typedef	struct nspr_signature_v10
{
	nspr_header_v10_t phd;	/* performance header */
	guint8	sig_EndianType;	/* Endian Type for the data */
	guint8	sig_Reserved0;
	guint16	sig_Reserved1;
	gchar	sig_Signature[NSPR_SIGSIZE_V10];	/* Signature value */
} nspr_signature_v10_t;
#define	nspr_signature_v10_s	sizeof(nspr_signature_v10_t)

/* NSPR_SIGNATURE_V20 structure */
typedef	struct nspr_signature_v20
{
	NSPR_HEADER_V20(sig);	/* short performance header */
	guint8	sig_EndianType;	/* Endian Type for the data */
	gchar	sig_Signature[1]; /* Signature value */
} nspr_signature_v20_t;
#define	nspr_signature_v20_s	(sizeof(nspr_signature_v20_t) -1)

/* NSPR_ABSTIME_V10 and NSPR_SYSTARTIME_V10 structure */
typedef	struct nspr_abstime_v10
{
	nspr_header_v10_t phd;	/* performance header */
	guint32	abs_RelTime;	/* relative time is ms from last time */
	guint32	abs_Time;	/* absolute time in seconds from 1970 */
} nspr_abstime_v10_t;
#define	nspr_abstime_v10_s	sizeof(nspr_abstime_v10_t)


/* NSPR_ABSTIME_V20 and NSPR_SYSTARTIME_V20 structure */
typedef	struct nspr_abstime_v20
{
	NSPR_HEADER_V20(abs);	/* short performance header */
	guint16	abs_RelTime;	/* relative time is ms from last time */
	guint32	abs_Time;	/* absolute time in seconds from 1970 */
} nspr_abstime_v20_t;
#define	nspr_abstime_v20_s	sizeof(nspr_abstime_v20_t)



/* full packet trace structure */
typedef	struct	nspr_pktracefull_v10
{
	nspr_headerdev_v10_t phd;	/* performance header */
	guint32	fp_RelTimeHr;	/* High resolution relative time */
	guint8	fp_Data[1];	/* packet data starts here */
} nspr_pktracefull_v10_t;
#define	nspr_pktracefull_v10_s	(nspr_hdev_v10_s + 4)

/* new full packet trace structure v20 */
typedef	struct	nspr_pktracefull_v20
{
	NSPR_HEADER3B_V20(fp);	/* long performance header */
	guint8	fp_DevNo;	/* Network Device (NIC) number */
	guint32	fp_RelTimeHr;	/* High resolution relative time */
	guint8	fp_Data[4];	/* packet data starts here */
} nspr_pktracefull_v20_t;
#define	nspr_pktracefull_v20_s	(sizeof(nspr_pktracefull_v20_t) - 4)

/* new full packet trace structure v21 */
typedef	struct	nspr_pktracefull_v21
{
	NSPR_HEADER3B_V21(fp);	/* long performance header */
	guint8	fp_DevNo;	/* Network Device (NIC) number */
	guint32	fp_RelTimeHr;	/* High resolution relative time */
	guint32	fp_PcbDevNo;	/* PCB devno */
	guint32	fp_lPcbDevNo;	/* link PCB devno */
	guint8	fp_Data[4];	/* packet data starts here */
} nspr_pktracefull_v21_t;
#define	nspr_pktracefull_v21_s	(sizeof(nspr_pktracefull_v21_t) - 4)

/* new full packet trace structure v22 */
typedef	struct	nspr_pktracefull_v22
{
	NSPR_HEADER3B_V22(fp);	/* long performance header */
	guint8	fp_DevNo;	/* Network Device (NIC) number */
	guint32	fp_RelTimeHr;	/* High resolution relative time */
	guint32	fp_PcbDevNo;	/* PCB devno */
	guint32	fp_lPcbDevNo;	/* link PCB devno */
	guint16	fp_VlanTag;
	guint8	fp_Data[4];	/* packet data starts here */
} nspr_pktracefull_v22_t;
#define	nspr_pktracefull_v22_s	(sizeof(nspr_pktracefull_v22_t) - 4)

typedef	struct	nspr_pktracefull_v23
{
	NSPR_HEADER3B_V22(fp);	/* long performance header */
	guint8	fp_DevNo;	/* Network Device (NIC) number */
	guint32 fp_AbsTimeHighHdr; /* Higher value of the absolute time */
	guint32	fp_AbsTimeLowHdr;	/* High resolution low time */
	guint32	fp_PcbDevNo;	/* PCB devno */
	guint32	fp_lPcbDevNo;	/* link PCB devno */
	guint16 fp_VlanTag; /* vlan tag */
	guint16 fp_Coreid; /* coreid of the packet */
	guint8	fp_Data[4];	/* packet data starts here */
} nspr_pktracefull_v23_t;
#define	nspr_pktracefull_v23_s	(sizeof(nspr_pktracefull_v23_t) - 4)

/* partial packet trace structure */
typedef	struct	nspr_pktracepart_v10
{
	nspr_headerdev_v10_t phd;	/* performance header */
	guint32	pp_RelTimeHr;	/* High resolution relative time */
	guint16	pp_PktSizeOrg;	/* Original packet size */
	guint16	pp_PktOffset;	/* starting offset in packet */
	guint8	pp_Data[1];	/* packet data starts here */
} nspr_pktracepart_v10_t;
#define	nspr_pktracepart_v10_s	(nspr_pktracefull_v10_s + 4)

/* new partial packet trace structure */
typedef	struct	nspr_pktracepart_v20
{
	NSPR_HEADER3B_V20(pp);	/* long performance header */
	guint8	pp_DevNo;	/* Network Device (NIC) number */
	guint32	pp_RelTimeHr;	/* High resolution relative time */
	guint16	pp_PktSizeOrg;	/* Original packet size */
	guint16	pp_PktOffset;	/* starting offset in packet */
	guint8	pp_Data[4];	/* packet data starts here */
} nspr_pktracepart_v20_t;
#define	nspr_pktracepart_v20_s	(sizeof(nspr_pktracepart_v20_t) -4)

/* new partial packet trace structure */
typedef	struct	nspr_pktracepart_v21
{
	NSPR_HEADER3B_V21(pp);	/* long performance header */
	guint8	pp_DevNo;	/* Network Device (NIC) number */
	guint32	pp_RelTimeHr;	/* High resolution relative time */
	guint16	pp_PktSizeOrg;	/* Original packet size */
	guint16	pp_PktOffset;	/* starting offset in packet */
	guint32	pp_PcbDevNo;	/* PCB devno */
	guint32	pp_lPcbDevNo;	/* link PCB devno */
	guint8	pp_Data[4];	/* packet data starts here */
} nspr_pktracepart_v21_t;
#define	nspr_pktracepart_v21_s	(sizeof(nspr_pktracepart_v21_t) -4)

/* new partial packet trace structure v22 */
typedef	struct	nspr_pktracepart_v22
{
	NSPR_HEADER3B_V22(pp);	/* long performance header */
	guint8	pp_DevNo;	/* Network Device (NIC) number */
	guint32	pp_RelTimeHr;	/* High resolution relative time */
	guint16	pp_PktSizeOrg;	/* Original packet size */
	guint16	pp_PktOffset;	/* starting offset in packet */
	guint32	pp_PcbDevNo;	/* PCB devno */
	guint32	pp_lPcbDevNo;	/* link PCB devno */
	guint16	pp_VlanTag; 	/* Vlan Tag */
	guint8	pp_Data[4];	/* packet data starts here */
} nspr_pktracepart_v22_t;
#define	nspr_pktracepart_v22_s	(sizeof(nspr_pktracepart_v22_t) -4)

typedef	struct	nspr_pktracepart_v23
{
	NSPR_HEADER3B_V22(pp);	/* long performance header */
	guint8	pp_DevNo;	/* Network Device (NIC) number */
	guint32 pp_AbsTimeHighHdr; /* Higher value of the absolute time */
	guint32	pp_AbsTimeLowHdr;	/* High resolution low time */
	guint16	pp_PktSizeOrg;	/* Original packet size */
	guint16	pp_PktOffset;	/* starting offset in packet */
	guint32	pp_PcbDevNo;	/* PCB devno */
	guint32	pp_lPcbDevNo;	/* link PCB devno */
	guint16	pp_VlanTag;	/* vlan tag */
	guint16 pp_Coreid; /* Coreid of the packet */
	guint8	pp_Data[4];	/* packet data starts here */
} nspr_pktracepart_v23_t;
#define	nspr_pktracepart_v23_s	(sizeof(nspr_pktracepart_v23_t) -4)

#define TRACE_V10_REC_LEN_OFF(enumprefix,structprefix,structname) \
	__TNV1O(enumprefix,structprefix,structname,dir,phd.ph_RecordType)\
	__TNV1L(enumprefix,structprefix,structname,dir,phd.ph_RecordType)\
	__TNV1O(enumprefix,structprefix,structname,nicno,phd.ph_DevNo)\
	__TNV1L(enumprefix,structprefix,structname,nicno,phd.ph_DevNo)\
	__TNO(enumprefix,structprefix,structname,eth,Data)

#define TRACE_V20_REC_LEN_OFF(enumprefix,structprefix,structname) \
	__TNO(enumprefix,structprefix,structname,dir,RecordType)\
	__TNL(enumprefix,structprefix,structname,dir,RecordType)\
	__TNO(enumprefix,structprefix,structname,nicno,DevNo)\
	__TNL(enumprefix,structprefix,structname,nicno,DevNo)\
	__TNO(enumprefix,structprefix,structname,eth,Data)

#define TRACE_V21_REC_LEN_OFF(enumprefix,structprefix,structname) \
	TRACE_V20_REC_LEN_OFF(enumprefix,structprefix,structname)\
	__TNO(enumprefix,structprefix,structname,pcb,PcbDevNo)\
	__TNO(enumprefix,structprefix,structname,l_pcb,lPcbDevNo)

#define TRACE_V22_REC_LEN_OFF(enumprefix,structprefix,structname) \
	TRACE_V21_REC_LEN_OFF(enumprefix,structprefix,structname)\
	__TNO(enumprefix,structprefix,structname,vlantag,VlanTag)\

#define TRACE_V23_REC_LEN_OFF(enumprefix,structprefix,structname) \
	TRACE_V22_REC_LEN_OFF(enumprefix,structprefix,structname)\
	__TNO(enumprefix,structprefix,structname,coreid,Coreid)\

#define myoffsetof(type,fieldname) (&(((type*)0)->fieldname))
#define __TNO(enumprefix,structprefix,structname,hdrname,structfieldname) \
	guint8 enumprefix##_##hdrname##_offset = (guint8)myoffsetof(nspr_##structname##_t,structprefix##_##structfieldname);

#define __TNL(enumprefix,structprefix,structname,hdrname,structfieldname) \
	guint8 enumprefix##_##hdrname##_len = (guint8)sizeof(((nspr_##structname##_t*)0)->structprefix##_##structfieldname);
	
#define __TNV1O(enumprefix,structprefix,structname,hdrname,structfieldname) \
	guint8 enumprefix##_##hdrname##_offset = (guint8)myoffsetof(nspr_##structname##_t,structfieldname);

#define __TNV1L(enumprefix,structprefix,structname,hdrname,structfieldname) \
	guint8 enumprefix##_##hdrname##_len = (guint8)sizeof(((nspr_##structname##_t*)0)->structfieldname);

	TRACE_V10_REC_LEN_OFF(v10_part,pp,pktracepart_v10)
	TRACE_V10_REC_LEN_OFF(v10_full,fp,pktracefull_v10)
	TRACE_V20_REC_LEN_OFF(v20_part,pp,pktracepart_v20)
	TRACE_V20_REC_LEN_OFF(v20_full,fp,pktracefull_v20)
	TRACE_V21_REC_LEN_OFF(v21_part,pp,pktracepart_v21)
	TRACE_V21_REC_LEN_OFF(v21_full,fp,pktracefull_v21)
	TRACE_V22_REC_LEN_OFF(v22_part,pp,pktracepart_v22)
	TRACE_V22_REC_LEN_OFF(v22_full,fp,pktracefull_v22)
	TRACE_V23_REC_LEN_OFF(v23_part,pp,pktracepart_v23)
	TRACE_V23_REC_LEN_OFF(v23_full,fp,pktracefull_v23)
	
#undef __TNV1O
#undef __TNV1L
#undef __TNO
#undef __TNL

#define ns_setabstime(wth, AbsoluteTime, RelativeTimems)	\
	do { \
		wth->capture.nstrace->nspm_curtime = AbsoluteTime; \
		wth->capture.nstrace->nspm_curtimemsec += RelativeTimems; \
		wth->capture.nstrace->nspm_curtimelastmsec = wth->capture.nstrace->nspm_curtimemsec; \
	} while(0)


#define ns_setrelativetime(wth, RelativeTimems)	\
	do { \
		guint32	rsec; \
		wth->capture.nstrace->nspm_curtimemsec += RelativeTimems; \
		rsec = (guint32)(wth->capture.nstrace->nspm_curtimemsec - wth->capture.nstrace->nspm_curtimelastmsec)/1000; \
		wth->capture.nstrace->nspm_curtime += rsec; \
		wth->capture.nstrace->nspm_curtimelastmsec += rsec * 1000; \
	} while (0)


guint32 nspm_signature_isv10(gchar *sigp);
guint32 nspm_signature_isv20(gchar *sigp);
guint32 nspm_signature_version(wtap*, gchar*, gint32, gint64);
gboolean nstrace_read(wtap *wth, int *err, gchar **err_info,
		 gint64 *data_offset);
gboolean nstrace_read_v10(wtap *wth, int *err, gchar **err_info,
		 gint64 *data_offset);
gboolean nstrace_read_v20(wtap *wth, int *err, gchar **err_info,
		 gint64 *data_offset);
gboolean nstrace_seek_read(wtap *wth, gint64 seek_off, 
		      union wtap_pseudo_header *pseudo_header, 
		      guchar *pd, int length,
		      int *err, gchar **err_info _U_);
void nstrace_close(wtap *wth);
void nstrace_sequential_close(wtap *wth);

gboolean nstrace_set_start_time_v10(wtap *wth);
gboolean nstrace_set_start_time_v20(wtap *wth);
gboolean nstrace_set_start_time(wtap *wth);
guint64	ns_hrtime2nsec(guint32 tm);

static gboolean nstrace_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr, 
	const union wtap_pseudo_header *pseudo_header, const guchar *pd, int *err);
gboolean nstrace_add_signature(wtap_dumper *wdh);
gboolean nstrace_add_abstime(wtap_dumper *wdh, const struct wtap_pkthdr *phdr, const guchar *pd);


#define GET_READ_PAGE_SIZE(remaining_file_size) ((gint32)((remaining_file_size>NSPR_PAGESIZE)?NSPR_PAGESIZE:remaining_file_size))


guint64	ns_hrtime2nsec(guint32 tm)
{
	guint32	val = tm & NSPR_HRTIME_MASKTM;
	switch(tm & NSPR_HRTIME_MASKFMT)
	{
	case NSPR_HRTIME_SEC:	return (guint64)val*1000000000;
	case NSPR_HRTIME_MSEC:	return (guint64)val*1000000;
	case NSPR_HRTIME_USEC:	return (guint32)val*1000;
	case NSPR_HRTIME_NSEC:	return val;
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

	errno = WTAP_ERR_CANT_READ;

	if ((file_size = wtap_file_size(wth, err)) == -1)	
		return 0;
  
	nstrace_buf = g_malloc(NSPR_PAGESIZE);
	page_size = GET_READ_PAGE_SIZE(file_size);

	switch ((wth->file_type = nspm_signature_version(wth, nstrace_buf, page_size, file_size)))
	{
	case WTAP_FILE_NETSCALER_1_0:
		wth->file_encap = WTAP_ENCAP_NSTRACE_1_0;
		break;
	
	case WTAP_FILE_NETSCALER_2_0:
		wth->file_encap = WTAP_ENCAP_NSTRACE_2_0;
		break;

	default:
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("nstrace: file type %d unsupported", wth->file_type);
		g_free(nstrace_buf);
		return 0;
	}

	if ((file_seek(wth->fh, 0, SEEK_SET, err)) == -1)
	{
		*err = file_error(wth->fh);
		g_free(nstrace_buf);
		return 0;
	}

	if (page_size != file_read(nstrace_buf, 1, page_size, wth->fh))
	{
		*err = file_error(wth->fh);
		g_free(nstrace_buf);
		return 0;
	}
	
	wth->subtype_read = nstrace_read;
	wth->subtype_seek_read = nstrace_seek_read;
	wth->subtype_close = nstrace_close; 

	wth->capture.nstrace = g_malloc(sizeof(nstrace_t));
	wth->capture.nstrace->pnstrace_buf = nstrace_buf;
	wth->capture.nstrace->nstrace_buflen = page_size;
	wth->capture.nstrace->nstrace_buf_offset = 0;
	wth->capture.nstrace->nspm_curtime = 0;
	wth->capture.nstrace->nspm_curtimemsec = 0;
	wth->capture.nstrace->nspm_curtimelastmsec = 0;
	wth->capture.nstrace->nsg_creltime = 0;
	wth->capture.nstrace->file_size = file_size;

  
	/* Set the start time by looking for the abstime record */
	if ((nstrace_set_start_time(wth)) == FALSE)
	{
		/* Reset the read pointer to start of the file. */
		if ((file_seek(wth->fh, 0, SEEK_SET, err)) == -1)
		{
			*err = file_error(wth->fh);
			g_free(wth->capture.nstrace->pnstrace_buf);
			g_free(wth->capture.nstrace);
			return 0;
		}

		/* Read the first page of data */
		if (page_size != file_read(nstrace_buf, 1, page_size, wth->fh))
		{
			*err = file_error(wth->fh);
			g_free(wth->capture.nstrace->pnstrace_buf);
			g_free(wth->capture.nstrace);
			return 0;
		}
	
		/* reset the buffer offset */
		wth->capture.nstrace->nstrace_buf_offset = 0;
	}

	wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
	wth->phdr.ts.secs = wth->capture.nstrace->nspm_curtime; 
	wth->phdr.ts.nsecs = 0;

	*err = 0;
	return 1;
}


#define nspm_signature_func(ver) \
	guint32 nspm_signature_isv##ver(gchar *sigp) {\
		return strncmp(sigp,NSPR_SIGSTR_V##ver,(sizeof(NSPR_SIGSTR_V##ver)-1));\
	}

nspm_signature_func(10)
nspm_signature_func(20)

/*
** Check signature and return the version number of the signature.
** If not found, it returns 0. At the time of return from this function
** we might not be at the first page. So after a call to this function, there 
** has to be a file seek to return to the start of the first page.
*/
guint32
nspm_signature_version(wtap *wth, gchar *nstrace_buf, gint32 len, gint64 file_size)
{
	gchar *dp = nstrace_buf;
	gint64 data_offset = 0;

	while (len == file_read(dp, 1, len, wth->fh)) {

		data_offset += len;

		for ( ; len > (gint32)(ns_min(sizeof(NSPR_SIGSTR_V10), sizeof(NSPR_SIGSTR_V20))); dp++, len--)
		{
#define	sigv10p	((nspr_signature_v10_t*)dp)
			if ((sigv10p->nsprRecordType == NSPR_SIGNATURE_V10) &&
				(sigv10p->nsprRecordSize <= len) &&
				((gint32)sizeof(NSPR_SIGSTR_V10) <= len) &&
				(!nspm_signature_isv10(sigv10p->sig_Signature)))
				return WTAP_FILE_NETSCALER_1_0;
#undef	sigv10p
    
#define	sigv20p	((nspr_signature_v20_t*)dp)
			if ((sigv20p->sig_RecordType == NSPR_SIGNATURE_V20) &&
				(sigv20p->sig_RecordSize <= len) &&
				((gint32)sizeof(NSPR_SIGSTR_V20) <= len) &&
				(!nspm_signature_isv20(sigv20p->sig_Signature)))
				return WTAP_FILE_NETSCALER_2_0;
#undef	sigv20p
		}

		dp = nstrace_buf;
		len = GET_READ_PAGE_SIZE((file_size-data_offset));
	}

	return 0;	/* no version found */
}

#define nspr_getv10recordsize(hdp) (hdp->nsprRecordSize)
#define nspr_getv10recordtype(hdp) (hdp->nsprRecordType)
#define nspr_getv20recordtype(hdp) (hdp->phd_RecordType)

#define nstrace_set_start_time_ver(ver) \
	gboolean nstrace_set_start_time_v##ver(wtap *wth) \
	{\
		gchar* nstrace_buf = wth->capture.nstrace->pnstrace_buf;\
		gint32 nstrace_buf_offset = wth->capture.nstrace->nstrace_buf_offset;\
		gint32 nstrace_buflen = wth->capture.nstrace->nstrace_buflen;\
		do\
		{\
			while (nstrace_buf_offset < nstrace_buflen)\
			{\
				nspr_hd_v##ver##_t *fp = (nspr_hd_v##ver##_t *) &nstrace_buf[nstrace_buf_offset];\
				switch (nspr_getv##ver##recordtype(fp))\
				{\
					case NSPR_ABSTIME_V##ver:\
						ns_setabstime(wth, ((nspr_abstime_v##ver##_t *) fp)->abs_Time, ((nspr_abstime_v##ver##_t *) fp)->abs_RelTime);\
						wth->capture.nstrace->nstrace_buf_offset = nstrace_buf_offset + nspr_getv##ver##recordsize(fp);\
						wth->capture.nstrace->nstrace_buflen = nstrace_buflen;\
						return TRUE;\
 					case NSPR_UNUSEDSPACE_V10:\
						nstrace_buf_offset = nstrace_buflen;\
						break;\
					default:\
						nstrace_buf_offset += nspr_getv##ver##recordsize(fp);\
				}\
			}\
			nstrace_buf_offset = 0;\
			wth->data_offset += nstrace_buflen;\
			nstrace_buflen = GET_READ_PAGE_SIZE((wth->capture.nstrace->file_size - wth->data_offset));\
		}while((nstrace_buflen > 0) && (nstrace_buflen == (file_read(nstrace_buf, 1, nstrace_buflen, wth->fh))));\
		return FALSE;\
	}

nstrace_set_start_time_ver(10)
nstrace_set_start_time_ver(20)

#undef nspr_getv10recordtype
#undef nspr_getv20recordtype
#undef nspr_getv10recordsize

/*
** Set the start time of the trace file. We look for the first ABSTIME record. We use that
** to set the start time. Apart from that we also make sure that we remember the position of
** the next record after the ABSTIME record. Inorder to report correct time values, all trace
** records before the ABSTIME record are ignored. 
*/
gboolean nstrace_set_start_time(wtap *wth)
{
	if (wth->file_type == WTAP_FILE_NETSCALER_1_0)
		return nstrace_set_start_time_v10(wth);
	else if (wth->file_type == WTAP_FILE_NETSCALER_2_0)
		return nstrace_set_start_time_v20(wth);

	return FALSE;
}

#define __TNO(enumprefix,structprefix,structname,hdrname,structfieldname) \
	wth->pseudo_header.nstr.hdrname##_offset =  enumprefix##_##hdrname##_offset;

#define __TNL(enumprefix,structprefix,structname,hdrname,structfieldname) \
	wth->pseudo_header.nstr.hdrname##_len = enumprefix##_##hdrname##_len;

#define __TNV1O(enumprefix,structprefix,structname,hdrname,structfieldname) \
	__TNO(enumprefix,structprefix,structname,hdrname,structfieldname)

#define __TNV1L(enumprefix,structprefix,structname,hdrname,structfieldname) \
	__TNL(enumprefix,structprefix,structname,hdrname,structfieldname)



/*
** Netscaler trace format read routines.
*/
gboolean nstrace_read_v10(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{

	guint64 nsg_creltime = wth->capture.nstrace->nsg_creltime;
	gchar *nstrace_buf = wth->capture.nstrace->pnstrace_buf;
	gint32 nstrace_buf_offset = wth->capture.nstrace->nstrace_buf_offset;
	gint32 nstrace_buflen = wth->capture.nstrace->nstrace_buflen;
	nspr_pktracefull_v10_t *fp;
	nspr_pktracepart_v10_t *pp;
      
	*err = 0;
	*err_info = g_strdup_printf("nstrace: no error");
	do
	{
		while ((nstrace_buf_offset < nstrace_buflen) &&
			((nstrace_buflen - nstrace_buf_offset) >= ((gint32)sizeof(fp->nsprRecordType))))
		{
      
			fp = (nspr_pktracefull_v10_t *) &nstrace_buf[nstrace_buf_offset];
			pp = (nspr_pktracepart_v10_t *) fp;
      
			switch (fp->nsprRecordType)
			{
			case NSPR_PDPKTRACEFULLTX_V10:
			case NSPR_PDPKTRACEFULLTXB_V10:
			case NSPR_PDPKTRACEFULLRX_V10:
      
				nsg_creltime += ns_hrtime2nsec(fp->fp_RelTimeHr);
				wth->phdr.ts.secs = wth->capture.nstrace->nspm_curtime + (guint32) (nsg_creltime / 1000000000); 
				wth->phdr.ts.nsecs = (guint32) (nsg_creltime % 1000000000);
      
				wth->phdr.len = fp->nsprRecordSize;
				wth->phdr.caplen = wth->phdr.len;
 
     
				TRACE_V10_REC_LEN_OFF(v10_full,fp,pktracefull_v10);
				
				buffer_assure_space(wth->frame_buffer, wth->phdr.caplen);
				memcpy(buffer_start_ptr(wth->frame_buffer), fp, wth->phdr.caplen); 
				*data_offset = wth->data_offset + nstrace_buf_offset;
      
				wth->capture.nstrace->nstrace_buf_offset = nstrace_buf_offset + fp->nsprRecordSize;
				wth->capture.nstrace->nstrace_buflen = nstrace_buflen;
				wth->capture.nstrace->nsg_creltime = nsg_creltime;

				return TRUE;
      
			case NSPR_PDPKTRACEPARTTX_V10:
			case NSPR_PDPKTRACEPARTTXB_V10:
			case NSPR_PDPKTRACEPARTRX_V10:
      
				nsg_creltime += ns_hrtime2nsec(pp->pp_RelTimeHr);
				wth->phdr.ts.secs = wth->capture.nstrace->nspm_curtime + (guint32) (nsg_creltime / 1000000000); 
				wth->phdr.ts.nsecs = (guint32) (nsg_creltime % 1000000000);
      
				wth->phdr.len =  pp->pp_PktSizeOrg + nspr_pktracepart_v10_s;
				wth->phdr.caplen =  pp->nsprRecordSize;
      
				TRACE_V10_REC_LEN_OFF(v10_part,pp,pktracepart_v10);
				      
				buffer_assure_space(wth->frame_buffer, wth->phdr.caplen);
				memcpy(buffer_start_ptr(wth->frame_buffer), pp, wth->phdr.caplen); 
				*data_offset = wth->data_offset + nstrace_buf_offset;
      
				wth->capture.nstrace->nstrace_buf_offset = nstrace_buf_offset + pp->nsprRecordSize;
				wth->capture.nstrace->nsg_creltime = nsg_creltime;
				wth->capture.nstrace->nstrace_buflen = nstrace_buflen;

				return TRUE;
      
			case NSPR_ABSTIME_V10:

				ns_setabstime(wth, ((nspr_abstime_v10_t *) fp)->abs_Time, ((nspr_abstime_v10_t *) fp)->abs_RelTime);
				nstrace_buf_offset += fp->nsprRecordSize;
				break;
      
			case NSPR_RELTIME_V10:

				ns_setrelativetime(wth, ((nspr_abstime_v10_t *) fp)->abs_RelTime);
				nstrace_buf_offset += fp->nsprRecordSize;
				break;
      
			case NSPR_UNUSEDSPACE_V10:

				nstrace_buf_offset = nstrace_buflen;
				break;
	
			default:

				nstrace_buf_offset += fp->nsprRecordSize;
				break;
			}
		}
  
		nstrace_buf_offset = 0;
		wth->data_offset += nstrace_buflen;
		nstrace_buflen = GET_READ_PAGE_SIZE((wth->capture.nstrace->file_size - wth->data_offset));
	}while((nstrace_buflen > 0) && (nstrace_buflen == (file_read(nstrace_buf, 1, nstrace_buflen, wth->fh))));
  
	return FALSE;
}

#define TIMEDEFV20(fp,type) \
	do {\
		nsg_creltime += ns_hrtime2nsec(fp->type##_RelTimeHr);\
		wth->phdr.ts.secs = wth->capture.nstrace->nspm_curtime + (guint32) (nsg_creltime / 1000000000);\
		wth->phdr.ts.nsecs = (guint32) (nsg_creltime % 1000000000);\
	}while(0)

#define TIMEDEFV23(fp,type) \
	do {\
		nsg_creltime = (guint64) fp->type##_AbsTimeHighHdr * 1000000;\
		wth->phdr.ts.secs = (guint32) (nsg_creltime / 1000000000);\
		wth->phdr.ts.nsecs = (guint32) (nsg_creltime % 1000000000);\
	}while(0)

#define TIMEDEFV21(fp,type) TIMEDEFV20(fp,type)
#define TIMEDEFV22(fp,type) TIMEDEFV20(fp,type)

#define PPSIZEDEFV20(pp,ver) \
	do {\
		wth->phdr.len = pp->pp_PktSizeOrg + nspr_pktracepart_v##ver##_s;\
		wth->phdr.caplen = nspr_getv20recordsize((nspr_hd_v20_t *)pp);\
	}while(0)

#define PPSIZEDEFV21(pp,ver) PPSIZEDEFV20(pp,ver)
#define PPSIZEDEFV22(pp,ver) PPSIZEDEFV20(pp,ver)
#define PPSIZEDEFV23(pp,ver) PPSIZEDEFV20(pp,ver)
		
#define FPSIZEDEFV20(fp,ver)\
	do {\
		wth->phdr.len = nspr_getv20recordsize((nspr_hd_v20_t *)fp);\
		wth->phdr.caplen = wth->phdr.len;\
	}while(0)

#define FPSIZEDEFV21(pp,ver) FPSIZEDEFV20(fp,ver)
#define FPSIZEDEFV22(pp,ver) FPSIZEDEFV20(fp,ver)
#define FPSIZEDEFV23(pp,ver) FPSIZEDEFV20(fp,ver)

#define PACKET_DESCRIBE(FPTIMEDEF,SIZEDEF,ver,enumprefix,type,structname,TYPE)\
	do {\
		nspr_##structname##_t *fp= (nspr_##structname##_t*)&nstrace_buf[nstrace_buf_offset];\
		TIMEDEFV##ver(fp,type);\
		SIZEDEF##ver(fp,ver);\
		TRACE_V##ver##_REC_LEN_OFF(enumprefix,type,structname);\
		buffer_assure_space(wth->frame_buffer, wth->phdr.caplen);\
		memcpy(buffer_start_ptr(wth->frame_buffer), fp, wth->phdr.caplen);\
		*data_offset = wth->data_offset + nstrace_buf_offset;\
		wth->capture.nstrace->nstrace_buf_offset = nstrace_buf_offset + nspr_getv20recordsize((nspr_hd_v20_t *)fp);\
		wth->capture.nstrace->nstrace_buflen = nstrace_buflen;\
		wth->capture.nstrace->nsg_creltime = nsg_creltime;\
		wth->pseudo_header.nstr.rec_type = NSPR_HEADER_VERSION##TYPE;\
		return TRUE;\
	}while(0)

gboolean nstrace_read_v20(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	guint64 nsg_creltime = wth->capture.nstrace->nsg_creltime;
	gchar *nstrace_buf = wth->capture.nstrace->pnstrace_buf;
	gint32 nstrace_buf_offset = wth->capture.nstrace->nstrace_buf_offset;
	gint32 nstrace_buflen = wth->capture.nstrace->nstrace_buflen;
	nspr_pktracefull_v20_t *fp20;
	nspr_pktracefull_v21_t *fp21;
		
	*err = 0;
	*err_info = g_strdup_printf("nstrace: no error"); 
	do
	{
		while ((nstrace_buf_offset < nstrace_buflen) &&
			((nstrace_buflen - nstrace_buf_offset) >= ((gint32)sizeof(fp21->fp_RecordType))))
		{
			fp21 = (nspr_pktracefull_v21_t *) &nstrace_buf[nstrace_buf_offset];
    
			switch (fp21->fp_RecordType)
			{

#define GENERATE_CASE(type,acttype) \
		case NSPR_PDPKTRACEFULLTX_V##type:\
		case NSPR_PDPKTRACEFULLTXB_V##type:\
		case NSPR_PDPKTRACEFULLRX_V##type:\
			PACKET_DESCRIBE(TIMEDEF,FPSIZEDEFV,type,v##type##_full,fp,pktracefull_v##type,acttype);
				GENERATE_CASE(23,203);
				GENERATE_CASE(22,202);
				GENERATE_CASE(21,201);
				GENERATE_CASE(20,200);
#undef GENERATE_CASE

#define GENERATE_CASE(type,acttype) \
		case NSPR_PDPKTRACEPARTTX_V##type:\
		case NSPR_PDPKTRACEPARTTXB_V##type:\
		case NSPR_PDPKTRACEPARTRX_V##type:\
			PACKET_DESCRIBE(TIMEDEF,PPSIZEDEFV,type,v##type##_part,pp,pktracepart_v##type,acttype);
				GENERATE_CASE(23,203);
				GENERATE_CASE(22,202);
				GENERATE_CASE(21,201);
				GENERATE_CASE(20,200);
#undef GENERATE_CASE

				case NSPR_ABSTIME_V20:
				{
					fp20 = (nspr_pktracefull_v20_t *) &nstrace_buf[nstrace_buf_offset];
					nstrace_buf_offset += nspr_getv20recordsize((nspr_hd_v20_t *)fp20);
					ns_setabstime(wth, ((nspr_abstime_v20_t *) fp20)->abs_Time, ((nspr_abstime_v20_t *) fp20)->abs_RelTime);
					break;
				}
      
				case NSPR_RELTIME_V20:
				{
					fp20 = (nspr_pktracefull_v20_t *) &nstrace_buf[nstrace_buf_offset];
					ns_setrelativetime(wth, ((nspr_abstime_v20_t *) fp20)->abs_RelTime);
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
					fp20 = (nspr_pktracefull_v20_t *) &nstrace_buf[nstrace_buf_offset];
					nstrace_buf_offset += nspr_getv20recordsize((nspr_hd_v20_t *)fp20);
					break;
				}
			}
    	}      
   
		nstrace_buf_offset = 0;
	    wth->data_offset += nstrace_buflen;
    	nstrace_buflen = GET_READ_PAGE_SIZE((wth->capture.nstrace->file_size - wth->data_offset));
	}while((nstrace_buflen > 0) && (nstrace_buflen == (file_read(nstrace_buf, 1, nstrace_buflen, wth->fh))));
  
	return FALSE;
}

#undef __TNO
#undef __TNL
#undef __TNV1O
#undef __TNV1L



gboolean nstrace_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{

	if (wth->file_type == WTAP_FILE_NETSCALER_1_0)
		return nstrace_read_v10(wth, err, err_info, data_offset);
	else if (wth->file_type == WTAP_FILE_NETSCALER_2_0)
		return nstrace_read_v20(wth, err, err_info, data_offset);

	return FALSE;
}


#define __TNO(enumprefix,structprefix,structname,hdrname,structfieldname) \
	pseudo_header->nstr.hdrname##_offset = (guint8) enumprefix##_##hdrname##_offset;
#define __TNL(enumprefix,structprefix,structname,hdrname,structfieldname) \
	pseudo_header->nstr.hdrname##_len = (guint8) enumprefix##_##hdrname##_len;;

#define __TNV1O(enumprefix,structprefix,structname,hdrname,structfieldname) \
	__TNO(enumprefix,structprefix,structname,hdrname,structfieldname)
#define __TNV1L(enumprefix,structprefix,structname,hdrname,structfieldname) \
	__TNL(enumprefix,structprefix,structname,hdrname,structfieldname)


gboolean nstrace_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length,
    int *err, gchar **err_info _U_)
{
	*err = 0;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	/*
	** Read the packet data.
	*/
	if ((file_read(pd, 1, length, wth->random_fh)) != length)
		return FALSE;

	if (wth->file_type == WTAP_FILE_NETSCALER_1_0)
	{

#define GENERATE_CASE_FULL(type,acttype) \
		case NSPR_PDPKTRACEFULLTX_V##type:\
		case NSPR_PDPKTRACEFULLTXB_V##type:\
		case NSPR_PDPKTRACEFULLRX_V##type:\
			TRACE_V##type##_REC_LEN_OFF(v##type##_full,fp,pktracefull_v##type);\
			pseudo_header->nstr.rec_type = NSPR_HEADER_VERSION##acttype;\
			break;\

#define GENERATE_CASE_PART(type,acttype) \
		case NSPR_PDPKTRACEPARTTX_V##type:\
		case NSPR_PDPKTRACEPARTTXB_V##type:\
		case NSPR_PDPKTRACEPARTRX_V##type:\
			TRACE_V##type##_REC_LEN_OFF(v##type##_part,pp,pktracepart_v##type);\
			pseudo_header->nstr.rec_type = NSPR_HEADER_VERSION##acttype;\
			break;\

		switch ((( nspr_header_v10_t*)pd)->ph_RecordType)
		{
			GENERATE_CASE_FULL(10,100)
			GENERATE_CASE_PART(10,100)
		}
	} else if (wth->file_type == WTAP_FILE_NETSCALER_2_0)
	{
		switch ((( nspr_hd_v20_t*)pd)->phd_RecordType)
		{
			GENERATE_CASE_FULL(20,200)
			GENERATE_CASE_PART(20,200)
			GENERATE_CASE_FULL(21,201)
			GENERATE_CASE_PART(21,201)
			GENERATE_CASE_FULL(22,202)
			GENERATE_CASE_PART(22,202)
			GENERATE_CASE_FULL(23,203)
			GENERATE_CASE_PART(23,203)
		}
	}

	return TRUE;
}

#undef __TNL
#undef __TNO
#undef __TNV1L
#undef __TNV1O


/*
** Netscaler trace format close routines.
*/
void nstrace_close(wtap *wth)
{

	g_free(wth->capture.nstrace->pnstrace_buf);
	g_free(wth->capture.nstrace);
	return;
}


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


/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
** failure */
gboolean nstrace_dump_open(wtap_dumper *wdh, gboolean cant_seek, int *err)
{
	if (cant_seek) 
	{
		*err = WTAP_ERR_CANT_WRITE_TO_PIPE;
		return FALSE;
	}

	wdh->subtype_write = nstrace_dump;

	wdh->dump.nstr = g_malloc(sizeof(nstrace_dump_t));
	wdh->dump.nstr->page_offset = 0;
	wdh->dump.nstr->page_len = NSPR_PAGESIZE;
	wdh->dump.nstr->absrec_time = 0;

	return TRUE;
}


gboolean nstrace_add_signature(wtap_dumper *wdh)
{
	size_t nwritten;

	if (wdh->file_type == WTAP_FILE_NETSCALER_1_0)
	{
		nspr_signature_v10_t sig10;

		/* populate the record */
		sig10.phd.ph_RecordType = NSPR_SIGNATURE_V10;
		sig10.phd.ph_RecordSize = nspr_signature_v10_s;
		memcpy(sig10.sig_Signature, NSPR_SIGSTR_V10, NSPR_SIGSIZE_V10);

		/* Write the record into the file */
		nwritten = fwrite(&sig10, 1, nspr_signature_v10_s, wdh->fh);
		if (nwritten != nspr_signature_v10_s)
			return FALSE;    

		/* Move forward the page offset */
		wdh->dump.nstr->page_offset += (guint16) nwritten;
	
	} else if (wdh->file_type == WTAP_FILE_NETSCALER_2_0)
	{
		gchar sig[nspr_signature_v20_s + sizeof(NSPR_SIGSTR_V20)];
		nspr_signature_v20_t *sig20;

		sig20 = (nspr_signature_v20_t *)&sig;
		sig20->sig_RecordType = NSPR_SIGNATURE_V20;
		sig20->sig_RecordSize = nspr_signature_v20_s + sizeof(NSPR_SIGSTR_V20);
		memcpy(sig20->sig_Signature, NSPR_SIGSTR_V20, sizeof(NSPR_SIGSTR_V20));

		/* Write the record into the file */
		nwritten = fwrite(sig20, 1, sig20->sig_RecordSize, wdh->fh);
		if (nwritten != sig20->sig_RecordSize) 
			return FALSE;    

		/* Move forward the page offset */
		wdh->dump.nstr->page_offset += (guint16) nwritten;
	
	} else  
	{
		g_assert_not_reached();
		return FALSE;
	}

	return TRUE;
}


gboolean nstrace_add_abstime(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
     const guchar *pd)
{
	size_t nwritten;
	guint64 nsg_creltime;

	if (wdh->file_type == WTAP_FILE_NETSCALER_1_0)
	{
		nspr_abstime_v10_t abs10;
		nspr_pktracefull_v10_t fp10;

		/* populate the record */
		abs10.phd.ph_RecordType = NSPR_ABSTIME_V10;
		abs10.phd.ph_RecordSize = nspr_abstime_v10_s;

		memcpy(&fp10, pd, nspr_pktracefull_v10_s);
		nsg_creltime = ns_hrtime2nsec(fp10.fp_RelTimeHr);
		
		abs10.abs_RelTime = 0;
		abs10.abs_Time = (guint32)phdr->ts.secs - (guint32)(nsg_creltime/1000000000);

		/* Write the record into the file */
		nwritten = fwrite(&abs10, 1, nspr_abstime_v10_s, wdh->fh);
		if (nwritten != nspr_abstime_v10_s) 
			return FALSE;

		/* Move forward the page offset */
		wdh->dump.nstr->page_offset += nspr_abstime_v10_s;

	} else if (wdh->file_type == WTAP_FILE_NETSCALER_2_0)
	{
		nspr_abstime_v20_t abs20;
		nspr_pktracefull_v20_t fp20;

		abs20.abs_RecordType = NSPR_ABSTIME_V20;
		abs20.abs_RecordSize = nspr_abstime_v20_s;

		memcpy(&fp20, pd, nspr_pktracefull_v20_s);
		nsg_creltime = ns_hrtime2nsec(fp20.fp_RelTimeHr);

		abs20.abs_RelTime = 0;
		abs20.abs_Time = (guint32)phdr->ts.secs - (guint32)(nsg_creltime/1000000000);

		/* Write the record into the file */
		nwritten = fwrite(&abs20, 1, nspr_abstime_v20_s, wdh->fh);
		if (nwritten != nspr_abstime_v20_s) 
			return FALSE;

		/* Move forward the page offset */
		wdh->dump.nstr->page_offset += nspr_abstime_v20_s;

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
    const union wtap_pseudo_header *pseudo_header, const guchar *pd, int *err)
{  
	size_t nwritten;

	if (wdh->dump.nstr->page_offset == 0)
	{
		/* Add the signature record and abs time record */
		if (wdh->file_type == WTAP_FILE_NETSCALER_1_0)
		{
			if ((nstrace_add_signature(wdh) == FALSE) || (nstrace_add_abstime(wdh, phdr, pd) == FALSE))
				return FALSE;
		} else if (wdh->file_type == WTAP_FILE_NETSCALER_2_0)
		{
			if ((nstrace_add_signature(wdh) == FALSE) || (nstrace_add_abstime(wdh, phdr, pd) == FALSE))
				return FALSE;
		} else
		{
			g_assert_not_reached();
			return FALSE;
		}
	}

	switch (pseudo_header->nstr.rec_type)
	{
	case NSPR_HEADER_VERSION100:

		if (wdh->file_type == WTAP_FILE_NETSCALER_1_0)
		{
			if (wdh->dump.nstr->page_offset + phdr->caplen >= wdh->dump.nstr->page_len)
			{
				/* Start on the next page */
				if (fseek(wdh->fh, (wdh->dump.nstr->page_len - wdh->dump.nstr->page_offset), SEEK_CUR) == -1)
				{
					*err = errno;
					return FALSE;
				}

				wdh->dump.nstr->page_offset = 0;

				/* Possibly add signature and abstime records and increment offset */
				if (nstrace_add_signature(wdh) == FALSE)
					return FALSE;
			}

			/* Write the actual record as is */
			nwritten = fwrite(pd, 1, phdr->caplen, wdh->fh);
			if (nwritten != phdr->caplen)
			{
				if (nwritten == 0 && ferror(wdh->fh))
					*err = errno;
				else
					*err = WTAP_ERR_SHORT_WRITE;

				return FALSE;
			}

			wdh->dump.nstr->page_offset += (guint16) nwritten;
		} else if (wdh->file_type == WTAP_FILE_NETSCALER_2_0)
		{
			*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
			return FALSE;    
		}

		break;

	case NSPR_HEADER_VERSION200:
	case NSPR_HEADER_VERSION201:
	case NSPR_HEADER_VERSION202:
	case NSPR_HEADER_VERSION203:

		if (wdh->file_type == WTAP_FILE_NETSCALER_1_0)
		{
			*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
			return FALSE;
		} else if (wdh->file_type == WTAP_FILE_NETSCALER_2_0)
		{
			if (wdh->dump.nstr->page_offset + phdr->caplen >= wdh->dump.nstr->page_len)
			{
				/* Start on the next page */
				if (fseek(wdh->fh, (wdh->dump.nstr->page_len - wdh->dump.nstr->page_offset), SEEK_CUR) == -1)
				{
					*err = errno;
					return FALSE;
				}

				wdh->dump.nstr->page_offset = 0;

				/* Possibly add signature and abstime records and increment offset */
				if (nstrace_add_signature(wdh) == FALSE)
				return FALSE;
			}

			/* Write the actual record as is */
			nwritten = fwrite(pd, 1, phdr->caplen, wdh->fh);

			if (nwritten != phdr->caplen)
			{
				if (nwritten == 0 && ferror(wdh->fh))
					*err = errno;
				else
					*err = WTAP_ERR_SHORT_WRITE;

				return FALSE;
			}

			wdh->dump.nstr->page_offset += (guint16) nwritten;
		}

		break;

	default:
		g_assert_not_reached();
		return FALSE;
	} 

	return TRUE;
}

