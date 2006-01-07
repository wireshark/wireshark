/*
*
* Copyright (c) 2003 Endace Technology Ltd, Hamilton, New Zealand.
* All rights reserved.
*
* This software and documentation has been developed by Endace Technology Ltd.
* along with the DAG PCI network capture cards. For further information please
* visit http://www.endace.com/.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
*  1. Redistributions of source code must retain the above copyright notice,
*  this list of conditions and the following disclaimer.
*
*  2. Redistributions in binary form must reproduce the above copyright
*  notice, this list of conditions and the following disclaimer in the
*  documentation and/or other materials provided with the distribution.
*
*  3. The name of Endace Technology Ltd may not be used to endorse or promote
*  products derived from this software without specific prior written
*  permission.
*
* THIS SOFTWARE IS PROVIDED BY ENDACE TECHNOLOGY LTD ``AS IS'' AND ANY EXPRESS
* OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
* EVENT SHALL ENDACE TECHNOLOGY LTD BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
* PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
* BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
* IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* $Id$
*/

/* 
 * erf - Endace ERF (Extensible Record Format)
 *
 * See
 *
 *	http://www.endace.com/support/EndaceRecordFormat.pdf
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "atm.h"
#include "erf.h"

typedef guint32 atm_hdr_t;

static int erf_read_header(
		FILE_T fh,
		struct wtap_pkthdr *phdr,
		union wtap_pseudo_header *pseudo_header,
		erf_header_t *erf_header,
		erf_t *erf,
		int *err,
		gchar **err_info,
		guint32 *bytes_read,
		guint32 *packet_size);
static gboolean erf_read(wtap *wth, int *err, gchar **err_info,
		long *data_offset);
static gboolean erf_seek_read(wtap *wth, long seek_off,
		union wtap_pseudo_header *pseudo_header, guchar *pd,
		int length, int *err, gchar **err_info);
static void erf_close(wtap *wth);
static int erf_encap_to_wtap_encap(erf_t *erf, guint8 erf_encap);
static void erf_set_pseudo_header(
		guint8 type,
		erf_t *erf,
		guchar *pd,
		int length,
		union wtap_pseudo_header *pseudo_header);

int erf_open(wtap *wth, int *err, gchar **err_info _U_)
{
	guint32 i, n;
	char *s;
	guint32 records_for_erf_check = RECORDS_FOR_ERF_CHECK;
	guint32 atm_encap = WTAP_ENCAP_ATM_PDUS;
	gboolean is_rawatm = FALSE;
	gboolean is_ppp = FALSE;
	int common_type = 0;
	erf_timestamp_t prevts;

	memset(&prevts, 0, sizeof(prevts));

	if ((s = getenv("ERF_ATM_ENCAP")) != NULL) {
		if (!strcmp(s, "sunatm")) {
			atm_encap = WTAP_ENCAP_ATM_PDUS;
		} else
		if (!strcmp(s, "sunraw")) {
			atm_encap = WTAP_ENCAP_ATM_PDUS;
			is_rawatm = TRUE;
		} else
		if (!strcmp(s, "rfc1483")) {
			atm_encap = WTAP_ENCAP_ATM_RFC1483;
		}
	}

	/* number of records to scan before deciding if this really is ERF (dflt=3) */
	if ((s = getenv("ERF_RECORDS_TO_CHECK")) != NULL) {
		if ((n = atoi(s)) > 0 && n < 101) {
			records_for_erf_check = n;
		}
	}

	/* ERF is a little hard because there's no magic number */

	for (i = 0; i < records_for_erf_check; i++) {

		erf_header_t header;
		guint32 packet_size;
		erf_timestamp_t ts;

		if (file_read(&header,1,sizeof(header),wth->fh) != sizeof(header)) {
			if ((*err = file_error(wth->fh)) != 0)
				return -1;
			else
		        return 0;
		}

		packet_size = g_ntohs(header.rlen) - sizeof(header);

		/* fail on invalid record type, decreasing timestamps or non-zero pad-bits */
		if (header.type == 0 || header.type > TYPE_AAL5 ||
		    (header.flags & 0xc0) != 0) {
			return 0;
		}

		if ((ts = pletohll(&header.ts)) < prevts) {
			/* reassembled AAL5 records may not be in time order, so allow 1 sec fudge */
			if (header.type != TYPE_AAL5 || ((prevts-ts)>>32) > 1) {
				return 0;
			}
		}
		memcpy(&prevts, &ts, sizeof(prevts));

		if (common_type == 0) {
			common_type = header.type;
		} else
		if (common_type > 0 && common_type != header.type) {
			common_type = -1;
		}

		if (header.type == TYPE_HDLC_POS && !is_ppp) {
			guint16 chdlc_hdr;
			if (file_read(&chdlc_hdr,1,sizeof(chdlc_hdr),wth->fh) != sizeof(chdlc_hdr)) {
				*err = file_error(wth->fh);
			}
			packet_size -= sizeof(chdlc_hdr);
			if (g_ntohs(chdlc_hdr) == 0xff03) {
				is_ppp = TRUE;
			}
		}

		if (file_seek(wth->fh, packet_size, SEEK_CUR, err) == -1) {
			return -1;
		}
	}

	if (file_seek(wth->fh, 0L, SEEK_SET, err) == -1) {	/* rewind */
		return -1;
	}

	wth->data_offset = 0;

	/* This is an ERF file */
	wth->file_type = WTAP_FILE_ERF;
	wth->snapshot_length = 0;	/* not available in header, only in frame */
	wth->capture.erf = g_malloc(sizeof(erf_t));
	wth->capture.erf->is_ppp = is_ppp;
	if (common_type == TYPE_AAL5) {
		wth->capture.erf->atm_encap = WTAP_ENCAP_ATM_PDUS_UNTRUNCATED;
		wth->capture.erf->is_rawatm = FALSE;
	} else {
		wth->capture.erf->atm_encap = atm_encap;
		wth->capture.erf->is_rawatm = is_rawatm;
	}

	/*
	 * Really want WTAP_ENCAP_PER_PACKET here but that severely limits
	 * the number of output formats we can write to. If all the records
	 * tested in the loop above were the same encap then use that one,
	 * otherwise use WTAP_ENCAP_PER_PACKET.
	 */
	wth->file_encap =
		(common_type < 0
			? WTAP_ENCAP_PER_PACKET
			: erf_encap_to_wtap_encap(wth->capture.erf, (guint8) common_type));

	wth->subtype_read = erf_read;
	wth->subtype_seek_read = erf_seek_read;
	wth->subtype_close = erf_close;
    wth->tsprecision = WTAP_FILE_TSPREC_NSEC;

	return 1;
}

/* Read the next packet */
static gboolean erf_read(wtap *wth, int *err, gchar **err_info,
    long *data_offset)
{
	erf_header_t erf_header;
	guint32 packet_size, bytes_read;
	gint32 offset = 0;

	*data_offset = wth->data_offset;

	if (!erf_read_header(
			wth->fh,
			&wth->phdr, &wth->pseudo_header, &erf_header, wth->capture.erf,
			err, err_info, &bytes_read, &packet_size)) {
		return FALSE;
	}
	wth->data_offset += bytes_read;

	buffer_assure_space(wth->frame_buffer, packet_size+(wth->capture.erf->is_rawatm?(sizeof(atm_hdr_t)+1):0));

	if (wth->capture.erf->is_rawatm) {
		wtap_file_read_expected_bytes(
			buffer_start_ptr(wth->frame_buffer), (gint32)sizeof(atm_hdr_t), wth->fh, err
		);
		wth->data_offset += sizeof(atm_hdr_t);
		packet_size -= sizeof(atm_hdr_t);
		offset += sizeof(atm_hdr_t)+1;
	}

	wtap_file_read_expected_bytes(
		buffer_start_ptr(wth->frame_buffer)+offset, (gint32)packet_size, wth->fh, err
	);
	wth->data_offset += packet_size;

	erf_set_pseudo_header(
			erf_header.type, wth->capture.erf,
			buffer_start_ptr(wth->frame_buffer), packet_size, &wth->pseudo_header
	);

	return TRUE;
}

static gboolean erf_seek_read(wtap *wth, long seek_off,
		union wtap_pseudo_header *pseudo_header, guchar *pd,
		int length, int *err, gchar **err_info)
{
	erf_header_t erf_header;
	guint32 packet_size;
	int offset = 0;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	if (!erf_read_header(wth->random_fh, NULL, pseudo_header, &erf_header,
	    wth->capture.erf, err, err_info, NULL, &packet_size))
                return FALSE;

	if (wth->capture.erf->is_rawatm) {
		wtap_file_read_expected_bytes(pd, (int)sizeof(atm_hdr_t), wth->random_fh, err);
		packet_size -= sizeof(atm_hdr_t);
		offset += sizeof(atm_hdr_t)+1;
	}

	wtap_file_read_expected_bytes(pd+offset, (int)packet_size, wth->random_fh, err);

	erf_set_pseudo_header(erf_header.type, wth->capture.erf, pd, length, pseudo_header);

	return TRUE;
}

static void erf_close(wtap *wth)
{
    g_free(wth->capture.erf);
}

static int erf_read_header(
	FILE_T fh,
	struct wtap_pkthdr *phdr,
	union wtap_pseudo_header *pseudo_header,
	erf_header_t *erf_header,
	erf_t *erf,
	int *err,
	gchar **err_info,
	guint32 *bytes_read,
	guint32 *packet_size)
{
	guint32 rec_size, skip;

	wtap_file_read_expected_bytes(erf_header, sizeof(*erf_header), fh, err);
	if (bytes_read != NULL) {
		*bytes_read = sizeof(*erf_header);
	}

	rec_size = g_ntohs(erf_header->rlen);
	*packet_size = rec_size - sizeof(*erf_header);
	skip = 0; /* # bytes of payload to ignore */

	if (*packet_size > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("erf: File has %u-byte packet, bigger than maximum of %u",
		    *packet_size, WTAP_MAX_PACKET_SIZE);
		return FALSE;
	}

	if (phdr != NULL) {
		guint64 ts = pletohll(&erf_header->ts);

		phdr->ts.secs = (long) (ts >> 32);
		ts = ((ts & 0xffffffff) * 1000 * 1000);
		ts += (ts & 0x80000000) << 1; /* rounding */
		phdr->ts.nsecs = ((long) (ts >> 32)) * 1000;
		if (phdr->ts.nsecs >= 1000000000) {
			phdr->ts.nsecs -= 1000000000;
			phdr->ts.secs += 1;
		}
	}

	switch (erf_header->type) {

	case TYPE_ATM:
	case TYPE_AAL5:
		if (phdr != NULL) {
			if (erf_header->type == TYPE_AAL5) {
				phdr->caplen = phdr->len = *packet_size - sizeof(atm_hdr_t);
			} else {
				phdr->caplen = ATM_SLEN(erf_header, NULL);
				phdr->len = ATM_WLEN(erf_header, NULL);
			}
		}

		if (erf->atm_encap == WTAP_ENCAP_ATM_PDUS || erf->atm_encap == WTAP_ENCAP_ATM_PDUS_UNTRUNCATED) {
			memset(&pseudo_header->atm, 0, sizeof(pseudo_header->atm));
			if (erf->is_rawatm) {
				pseudo_header->atm.flags = ATM_RAW_CELL;
				if (phdr != NULL) {
					phdr->caplen += sizeof(atm_hdr_t)+1;
					phdr->len += sizeof(atm_hdr_t)+1;
				}
			} else {
				atm_hdr_t atm_hdr;

				wtap_file_read_expected_bytes(&atm_hdr, sizeof(atm_hdr), fh, err);
				if (bytes_read != NULL) {
					*bytes_read += sizeof(atm_hdr);
				}
				*packet_size -= sizeof(atm_hdr);

				atm_hdr = g_ntohl(atm_hdr);

				pseudo_header->atm.vpi = ((atm_hdr & 0x0ff00000) >> 20);
				pseudo_header->atm.vci = ((atm_hdr & 0x000ffff0) >>  4);
				pseudo_header->atm.channel = (erf_header->flags & 0x03);
			}
		} else {
			skip = 4;
		}
		break;
	case TYPE_ETH:
		if (phdr != NULL) {
			phdr->caplen = ETHERNET_SLEN(erf_header, erf);
			phdr->len = ETHERNET_WLEN(erf_header, erf);
		}
		skip = 2;
		break;
	case TYPE_HDLC_POS:
		if (phdr != NULL) {
			phdr->caplen = HDLC_SLEN(erf_header, erf);
			phdr->len = HDLC_WLEN(erf_header, erf);
		}
		memset(&pseudo_header->p2p, 0, sizeof(pseudo_header->p2p));
		pseudo_header->p2p.sent = ((erf_header->flags & 0x01) ? TRUE : FALSE);
		break;
	default:
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		*err_info = g_strdup_printf("erf: unknown record encapsulation %u",
		    erf_header->type);
		return FALSE;
	}

	if (phdr != NULL) {
		phdr->pkt_encap = erf_encap_to_wtap_encap(erf, erf_header->type);
	}

	if (skip > 0) {
		if (file_seek(fh, skip, SEEK_CUR, err) == -1) {
			return FALSE;
		}
		if (bytes_read != NULL) {
			*bytes_read += skip;
		}
		*packet_size -= skip;
	}

	return TRUE;
}

static int erf_encap_to_wtap_encap(erf_t *erf, guint8 erf_encap)
{
	int wtap_encap = WTAP_ENCAP_UNKNOWN;

	switch (erf_encap) {
	case TYPE_ATM:
	case TYPE_AAL5:
		wtap_encap = erf->atm_encap;
		break;
	case TYPE_ETH:
		wtap_encap = WTAP_ENCAP_ETHERNET;
		break;
	case TYPE_HDLC_POS:
		wtap_encap = (erf->is_ppp ? WTAP_ENCAP_PPP : WTAP_ENCAP_CHDLC);
		break;
	default:
		break;
	}

	return wtap_encap;
}

static void erf_set_pseudo_header(
	guint8 type, erf_t *erf, guchar *pd, int length, union wtap_pseudo_header *pseudo_header)
{
	if (type == TYPE_ETH) {
		/*
		 * We don't know whether there's an FCS in this frame or not.
		 */
		pseudo_header->eth.fcs_len = -1;
	} else
	if (!erf->is_rawatm &&
			(type == TYPE_ATM || type == TYPE_AAL5) &&
			(erf->atm_encap == WTAP_ENCAP_ATM_PDUS ||
			 erf->atm_encap == WTAP_ENCAP_ATM_PDUS_UNTRUNCATED)) { 
		atm_guess_traffic_type(pd, length, pseudo_header);
	} else
	if (type == TYPE_AAL5) {
		pseudo_header->atm.aal = AAL_5;
		pseudo_header->atm.type = TRAF_UNKNOWN;
		pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
	}
}
