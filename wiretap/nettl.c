/* nettl.c
 *
 * $Id: nettl.c,v 1.20 2001/10/04 08:30:36 guy Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@xiexie.org>
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
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "nettl.h"

static u_char nettl_magic_hpux9[12] = {
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xD0, 0x00
};
static u_char nettl_magic_hpux10[12] = {
    0x54, 0x52, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
};

/* HP nettl record header for the SX25L2 subsystem - The FCS is not included in the file. */
struct nettlrec_sx25l2_hdr {
    guint8	xxa[8];
    guint8	from_dce;
    guint8	xxb[55];
    guint8	length[2];
    guint8	length2[2];    /* don't know which one is captured length / real length */
    guint8	xxc[4];
    guint8	sec[4];
    guint8	usec[4];
    guint8	xxd[4];
};

/* HP nettl record header for the NS_LS_IP subsystem */
/* This also works for BASE100 and GSC100BT */
struct nettlrec_ns_ls_ip_hdr {
    guint8	xxa[28];
    guint8	length[4];
    guint8	length2[4];    /* don't know which one is captured length / real length */
    guint8	sec[4];
    guint8	usec[4];
    guint8	xxb[16];
};


/* header is followed by data and once again the total length (2 bytes) ! */

static gboolean nettl_read(wtap *wth, int *err, long *data_offset);
static int nettl_seek_read(wtap *wth, long seek_off,
		union wtap_pseudo_header *pseudo_header, u_char *pd, int length);
static int nettl_read_rec_header(wtap *wth, FILE_T fh,
		struct wtap_pkthdr *phdr, union wtap_pseudo_header *pseudo_header,
		int *err);
static int nettl_read_rec_data(FILE_T fh, u_char *pd, int length, int *err);
static void nettl_close(wtap *wth);

int nettl_open(wtap *wth, int *err)
{
    char magic[12], os_vers[2];
    int bytes_read;

    /* Read in the string that should be at the start of a HP file */
    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(magic, 1, 12, wth->fh);
    if (bytes_read != 12) {
    	*err = file_error(wth->fh);
	if (*err != 0)
	    return -1;
	return 0;
    }

    if (memcmp(magic, nettl_magic_hpux9, 12) &&
        memcmp(magic, nettl_magic_hpux10, 12)) {
	return 0;
    }

    file_seek(wth->fh, 0x63, SEEK_SET);
    wth->data_offset = 0x63;
    bytes_read = file_read(os_vers, 1, 2, wth->fh);
    if (bytes_read != 2) {
    	*err = file_error(wth->fh);
	if (*err != 0)
	    return -1;
	return 0;
    }

    file_seek(wth->fh, 0x80, SEEK_SET);
    wth->data_offset = 0x80;

    /* This is an nettl file */
    wth->file_type = WTAP_FILE_NETTL;
    wth->capture.nettl = g_malloc(sizeof(nettl_t));
    if (os_vers[0] == '1' && os_vers[1] == '1')
	wth->capture.nettl->is_hpux_11 = TRUE;
    else
	wth->capture.nettl->is_hpux_11 = FALSE;
    wth->subtype_read = nettl_read;
    wth->subtype_seek_read = nettl_seek_read;
    wth->subtype_close = nettl_close;
    wth->snapshot_length = 16384;	/* not available in header, only in frame */

    return 1;
}

/* Read the next packet */
static gboolean nettl_read(wtap *wth, int *err, long *data_offset)
{
    int ret;

    /* Read record header. */
    *data_offset = wth->data_offset;
    ret = nettl_read_rec_header(wth, wth->fh, &wth->phdr, &wth->pseudo_header,
        err);
    if (ret <= 0) {
	/* Read error or EOF */
	return FALSE;
    }
    wth->data_offset += ret;

    /*
     * Read the packet data.
     */
    buffer_assure_space(wth->frame_buffer, wth->phdr.caplen);
    if (nettl_read_rec_data(wth->fh, buffer_start_ptr(wth->frame_buffer),
		wth->phdr.caplen, err) < 0)
	return FALSE;	/* Read error */
    wth->data_offset += wth->phdr.caplen;
    return TRUE;
}

static int
nettl_seek_read(wtap *wth, long seek_off,
		union wtap_pseudo_header *pseudo_header, u_char *pd, int length)
{
    int ret;
    int err;		/* XXX - return this */
    struct wtap_pkthdr phdr;

    file_seek(wth->random_fh, seek_off, SEEK_SET);

    /* Read record header. */
    ret = nettl_read_rec_header(wth, wth->random_fh, &phdr, pseudo_header,
        &err);
    if (ret <= 0) {
	/* Read error or EOF */
	return ret;
    }

    /*
     * Read the packet data.
     */
    return nettl_read_rec_data(wth->random_fh, pd, length, &err);
}

static int
nettl_read_rec_header(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr,
		union wtap_pseudo_header *pseudo_header, int *err)
{
    int bytes_read;
    struct nettlrec_sx25l2_hdr lapb_hdr;
    struct nettlrec_ns_ls_ip_hdr ip_hdr;
    guint16 length;
    int offset = 0;
    guint8 encap[4];
    guint8 dummy[4];

    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(encap, 1, 4, fh);
    if (bytes_read != 4) {
	*err = file_error(fh);
	if (*err != 0)
	    return -1;
	if (bytes_read != 0) {
	    *err = WTAP_ERR_SHORT_READ;
	    return -1;
	}
	return 0;
    }
    offset += 4;

    switch (encap[3]) {
	case NETTL_SUBSYS_BASE100 :
	case NETTL_SUBSYS_GSC100BT :
	case NETTL_SUBSYS_NS_LS_IP :
	    if (encap[3] == NETTL_SUBSYS_NS_LS_IP) {
		phdr->pkt_encap = WTAP_ENCAP_RAW_IP; 
	    } else {
		wth->file_encap = WTAP_ENCAP_ETHERNET;
		phdr->pkt_encap = WTAP_ENCAP_ETHERNET; 
	    }

	    bytes_read = file_read(&ip_hdr, 1, sizeof ip_hdr, fh);
	    if (bytes_read != sizeof ip_hdr) {
		*err = file_error(fh);
		if (*err != 0)
		    return -1;
		if (bytes_read != 0) {
		    *err = WTAP_ERR_SHORT_READ;
		    return -1;
		}
		return 0;
	    }
	    offset += sizeof ip_hdr;

	    /* The packet header in HP-UX 11 nettl traces is 4 octets longer than
	     * HP-UX 9 and 10 */
	    if (wth->capture.nettl->is_hpux_11) {
		bytes_read = file_read(dummy, 1, 4, fh);
		if (bytes_read != 4) {
		    *err = file_error(fh);
		    if (*err != 0)
			return -1;
		    if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return -1;
		    }
		    return 0;
		}
		offset += 4;
	    }

	    length = pntohl(&ip_hdr.length);
	    if (length <= 0) return 0;
	    phdr->len = length;
	    phdr->caplen = length;

	    phdr->ts.tv_sec = pntohl(&ip_hdr.sec);
	    phdr->ts.tv_usec = pntohl(&ip_hdr.usec);
	    break;
	case NETTL_SUBSYS_SX25L2 :
	    phdr->pkt_encap = WTAP_ENCAP_LAPB;
	    bytes_read = file_read(&lapb_hdr, 1, sizeof lapb_hdr, fh);
	    if (bytes_read != sizeof lapb_hdr) {
		*err = file_error(fh);
		if (*err != 0)
		    return -1;
		if (bytes_read != 0) {
		    *err = WTAP_ERR_SHORT_READ;
		    return -1;
		}
		return 0;
	    }
	    offset += sizeof lapb_hdr;

	    if (wth->capture.nettl->is_hpux_11) {
		bytes_read = file_read(dummy, 1, 4, fh);
		if (bytes_read != 4) {
		    *err = file_error(fh);
		    if (*err != 0)
			return -1;
		    if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return -1;
		    }
		    return 0;
		}
		offset += 4;
	    }

	    length = pntohs(&lapb_hdr.length);
	    if (length <= 0) return 0;
	    phdr->len = length;
	    phdr->caplen = length;

	    phdr->ts.tv_sec = pntohl(&lapb_hdr.sec);
	    phdr->ts.tv_usec = pntohl(&lapb_hdr.usec);
	    pseudo_header->x25.flags = (lapb_hdr.from_dce & 0x20 ? 0x80 : 0x00);
	    break;
	default:
	    g_message("nettl: network type %u unknown or unsupported",
		    encap[3]);
	    *err = WTAP_ERR_UNSUPPORTED_ENCAP;
	    return -1;
    }
    return offset;
}

static int
nettl_read_rec_data(FILE_T fh, u_char *pd, int length, int *err)
{
    int bytes_read;

    bytes_read = file_read(pd, 1, length, fh);

    if (bytes_read != length) {
	*err = file_error(fh);
	if (*err == 0)
	    *err = WTAP_ERR_SHORT_READ;
	return -1;
    }
    return 0;
}

static void nettl_close(wtap *wth)
{
    g_free(wth->capture.nettl);
}
