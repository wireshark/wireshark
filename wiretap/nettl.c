/* nettl.c
 *
 * $Id: nettl.c,v 1.9 2000/03/22 07:06:56 guy Exp $
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
#include <time.h>
#include "wtap.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "nettl.h"

static char nettl_magic_hpux9[12] = {
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xD0, 0x00
};
static char nettl_magic_hpux10[12] = {
    0x54, 0x52, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
};

static gboolean is_hpux_11;

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
struct nettlrec_ns_ls_ip_hdr {
    guint8	xxa[28];
    guint8	length[4];
    guint8	length2[4];    /* don't know which one is captured length / real length */
    guint8	sec[4];
    guint8	usec[4];
    guint8	xxb[16];
};

/* header is followed by data and once again the total length (2 bytes) ! */

static int nettl_read(wtap *wth, int *err);
static void nettl_close(wtap *wth);

int nettl_open(wtap *wth, int *err)
{
    char magic[12], os_vers[2];
    int bytes_read;

    /* Read in the string that should be at the start of a HP file */
    file_seek(wth->fh, 0, SEEK_SET);
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
    if (os_vers[0] == '1' && os_vers[1] == '1')
	is_hpux_11 = TRUE;
    else
	is_hpux_11 = FALSE;

    file_seek(wth->fh, 0x80, SEEK_SET);
    wth->data_offset = 0x80;

    /* This is an nettl file */
    wth->file_type = WTAP_FILE_NETTL;
    wth->capture.nettl = g_malloc(sizeof(nettl_t));
    wth->subtype_read = nettl_read;
    wth->subtype_close = nettl_close;
    wth->snapshot_length = 16384;	/* not available in header, only in frame */

    wth->capture.nettl->start = 0;

    return 1;
}

/* Read the next packet */
static int nettl_read(wtap *wth, int *err)
{
    int	bytes_read;
    struct nettlrec_sx25l2_hdr lapb_hdr;
    struct nettlrec_ns_ls_ip_hdr ip_hdr;
    guint16 length;
    int	data_offset;
    guint8 encap[4];
    guint8 dummy[4];

    /* Read record header. */
    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(encap, 1, 4, wth->fh);
    if (bytes_read != 4) {
	*err = file_error(wth->fh);
	if (*err != 0)
	    return -1;
	if (bytes_read != 0) {
	    *err = WTAP_ERR_SHORT_READ;
	    return -1;
	}
	return 0;
    }
    wth->data_offset += 4;
    switch (encap[3]) {
    case NETTL_SUBSYS_NS_LS_IP :
	wth->phdr.pkt_encap = WTAP_ENCAP_RAW_IP;
	bytes_read = file_read(&ip_hdr, 1, sizeof ip_hdr, wth->fh);
	if (bytes_read != sizeof ip_hdr) {
	    *err = file_error(wth->fh);
	    if (*err != 0)
		return -1;
	    if (bytes_read != 0) {
		*err = WTAP_ERR_SHORT_READ;
		return -1;
	    }
	    return 0;
	}
	wth->data_offset += sizeof ip_hdr;

	/* The packet header in HP-UX 11 nettl traces is 4 octets longer than
	 * HP-UX 9 and 10 */
	if (is_hpux_11) {
	    bytes_read = file_read(dummy, 1, 4, wth->fh);
	    if (bytes_read != 4) {
		*err = file_error(wth->fh);
		if (*err != 0)
		    return -1;
		if (bytes_read != 0) {
		    *err = WTAP_ERR_SHORT_READ;
		    return -1;
		}
		return 0;
	    }
	    wth->data_offset += 4;
	}

	length = pntohl(&ip_hdr.length);
	if (length <= 0) return 0;
	wth->phdr.len = length;
	wth->phdr.caplen = length;

	wth->phdr.ts.tv_sec = pntohl(&ip_hdr.sec);
	wth->phdr.ts.tv_usec = pntohl(&ip_hdr.usec);
	if (wth->capture.nettl->start == 0)
	    wth->capture.nettl->start = wth->phdr.ts.tv_sec;

	/*
	 * Read the packet data.
	 */
	buffer_assure_space(wth->frame_buffer, length);
	data_offset = wth->data_offset;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(buffer_start_ptr(wth->frame_buffer), 1,
		length, wth->fh);

	if (bytes_read != length) {
	    *err = file_error(wth->fh);
	    if (*err == 0)
		*err = WTAP_ERR_SHORT_READ;
	    return -1;
	}
	wth->data_offset += length;
	break;
    case NETTL_SUBSYS_SX25L2 :
	wth->phdr.pkt_encap = WTAP_ENCAP_LAPB;
	bytes_read = file_read(&lapb_hdr, 1, sizeof lapb_hdr, wth->fh);
	if (bytes_read != sizeof lapb_hdr) {
	    *err = file_error(wth->fh);
	    if (*err != 0)
		return -1;
	    if (bytes_read != 0) {
		*err = WTAP_ERR_SHORT_READ;
		return -1;
	    }
	    return 0;
	}
	wth->data_offset += sizeof lapb_hdr;

	if (is_hpux_11) {
	    bytes_read = file_read(dummy, 1, 4, wth->fh);
	    if (bytes_read != 4) {
		*err = file_error(wth->fh);
		if (*err != 0)
		    return -1;
		if (bytes_read != 0) {
		    *err = WTAP_ERR_SHORT_READ;
		    return -1;
		}
		return 0;
	    }
	    wth->data_offset += 4;
	}

	length = pntohs(&lapb_hdr.length);
	if (length <= 0) return 0;
	wth->phdr.len = length;
	wth->phdr.caplen = length;

	wth->phdr.ts.tv_sec = pntohl(&lapb_hdr.sec);
	wth->phdr.ts.tv_usec = pntohl(&lapb_hdr.usec);
	if (wth->capture.nettl->start == 0)
	    wth->capture.nettl->start = wth->phdr.ts.tv_sec;
	wth->phdr.pseudo_header.x25.flags = (lapb_hdr.from_dce & 0x20 ? 0x80 : 0x00);

	/*
	 * Read the packet data.
	 */
	buffer_assure_space(wth->frame_buffer, length);
	data_offset = wth->data_offset;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(buffer_start_ptr(wth->frame_buffer), 1,
		length, wth->fh);

	if (bytes_read != length) {
	    *err = file_error(wth->fh);
	    if (*err == 0)
		*err = WTAP_ERR_SHORT_READ;
	    return -1;
	}
	wth->data_offset += length;
	break;
    default:
	g_message("nettl: network type %u unknown or unsupported",
		    encap[3]);
	*err = WTAP_ERR_UNSUPPORTED_ENCAP;
	return -1;
    }
    return data_offset;
}

static void nettl_close(wtap *wth)
{
    g_free(wth->capture.nettl);
}
