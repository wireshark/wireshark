/* nettl.c
 *
 * $Id: nettl.c,v 1.5 2000/01/22 06:22:40 guy Exp $
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

/* HP nettl record header - The FCS is not included in the file. */
struct nettlrec_hdr {
    char	xxa[12];
    char	from_dce;
    char	xxb[55];
    guint16	length;
    guint16	length2;    /* don't know which one is captured length / real length */
    char	xxc[4];
    char	sec[4];
    char	usec[4];
    char	xxd[4];
};

/* header is followed by data and once again the total length (2 bytes) ! */

static int nettl_read(wtap *wth, int *err);

int nettl_open(wtap *wth, int *err)
{
    char magic[12];
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

    file_seek(wth->fh, 0x80, SEEK_SET);
    wth->data_offset = 0x80;

    /* This is an nettl file */
    wth->file_type = WTAP_FILE_NETTL;
    wth->capture.nettl = g_malloc(sizeof(nettl_t));
    wth->subtype_read = nettl_read;
    wth->snapshot_length = 16384;	/* not available in header, only in frame */

    wth->capture.nettl->start = 0;

    wth->file_encap = WTAP_ENCAP_LAPB;

    return 1;
}

/* Read the next packet */
static int nettl_read(wtap *wth, int *err)
{
    int	bytes_read;
    struct nettlrec_hdr hdr;
    guint16 length;
    int	data_offset;

    /* Read record header. */
    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(&hdr, 1, sizeof hdr, wth->fh);
    if (bytes_read != sizeof hdr) {
	*err = file_error(wth->fh);
	if (*err != 0)
	    return -1;
	if (bytes_read != 0) {
	    *err = WTAP_ERR_SHORT_READ;
	    return -1;
	}
	return 0;
    }
    wth->data_offset += sizeof hdr;
    length = pntohs(&hdr.length);
    if (length <= 0) return 0;

    wth->phdr.len = length;
    wth->phdr.caplen = length;

    wth->phdr.ts.tv_sec = pntohl(&hdr.sec);
    wth->phdr.ts.tv_usec = pntohl(&hdr.usec);
    if (wth->capture.nettl->start == 0)
	wth->capture.nettl->start = wth->phdr.ts.tv_sec;
    wth->phdr.pseudo_header.x25.flags = (hdr.from_dce & 0x20 ? 0x80 : 0x00);

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

    wth->phdr.pkt_encap = wth->file_encap;

    return data_offset;
}
