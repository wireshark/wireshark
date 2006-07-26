/* nettl.c
 *
 * $Id$
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Enhancements by Mark C. Brown <mbrown@hp.com>
 * Copyright (C) 2003, 2005 Hewlett-Packard Development Company, L.P.
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

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "nettl.h"

/* HP nettl file header */

/* Magic number size */
#define MAGIC_SIZE	12

/* HP-UX 9.x */
static guint8 nettl_magic_hpux9[MAGIC_SIZE] = {
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xD0, 0x00
};
/* HP-UX 10.x and 11.x */
static guint8 nettl_magic_hpux10[MAGIC_SIZE] = {
    0x54, 0x52, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
};

#define FILE_HDR_SIZE	128

struct nettl_file_hdr {
    guint8	magic[MAGIC_SIZE];
    gchar	file_name[56];
    gchar	tz[20];
    gchar	host_name[9];
    gchar	os_vers[9];
    guchar	os_v;
    guint8	xxa[8];
    gchar	model[11];
    guint16	unknown;	/* just padding to 128 bytes? */
};

/* HP nettl record header for the SX25L2 subsystem - The FCS is not included in the file. */
struct nettlrec_sx25l2_hdr {
    guint8	xxa[8];
    guint8	from_dce;
    guint8	xxb[55];
    guint8	caplen[2];
    guint8	length[2];
    guint8	xxc[4];
    guint8	sec[4];
    guint8	usec[4];
    guint8	xxd[4];
};

/* HP nettl record header for the NS_LS_IP subsystem */
/* This also works for BASE100 and GSC100BT */
/* see /usr/include/sys/netdiag1.h for hints */
struct nettlrec_ns_ls_ip_hdr {
    guint32	devid;
    guint8	xxa[4];
    guint32	kind;
    guint8	xxb[16];
    guint32	caplen;
    guint32	length;
    guint32	sec;
    guint32	usec;
    guint32	pid;
    guint8	xxc[10];
    guint16	uid;
};

/* Full record header for writing out a nettl file */
struct nettlrec_dump_hdr {
    guint16	hdr_len;
    guint16	subsys;
    struct	nettlrec_ns_ls_ip_hdr hdr;
    guint8	xxd[4];
};

/* header is followed by data and once again the total length (2 bytes) ! */


/* NL_LS_DRIVER :
The following shows what the header looks like for NS_LS_DRIVER
The capture was taken on HPUX11 and for a 100baseT interface.

000080 00 44 00 0b 00 00 00 02 00 00 00 00 20 00 00 00
000090 00 00 00 00 00 00 04 06 00 00 00 00 00 00 00 00
0000a0 00 00 00 74 00 00 00 74 3c e3 76 19 00 06 34 63
0000b0 ff ff ff ff 00 00 00 00 00 00 00 00 ff ff ff ff
0000c0 00 00 00 00 00 00 01 02 00 5c 00 5c ff ff ff ff
0000d0 3c e3 76 19 00 06 34 5a 00 0b 00 14 <here starts the MAC heder>

Each entry starts with 0x0044000b

The values 0x005c at position 0x0000c8 and 0x0000ca matches the number of bytes in
the packet up to the next entry, which starts with 0x00440b again. These probably
indicate the real and captured length of the packet (order unknown)

The values 0x00000074 at positions 0x0000a0 and 0x0000a4 seems to indicate
the same number as positions 0x0000c8 and 0x0000ca but added with 24.
Perhaps we have here two layers of headers.
The first layer is fixed and consists of all the bytes from 0x000084 up to and
including 0x0000c3 which is a generic header for all packets captured from any
device. This header might be of fixed size 64 bytes and there might be something in
it which indicates the type of the next header which is link type specific.
Following this header there is another header for the 100baseT interface which
in this case is 24 bytes long spanning positions 0x0000c4 to 0x0000db.

When someone reports that the loading of the captures breaks, we can compare
this header above with what he/she got to learn how to distinguish between different
types of link specific headers.


For now:
The first header seems to be
	a normal nettlrec_ns_ls_ip_hdr

The header for 100baseT seems to be
	0-3	unknown
	4-5	captured length
	6-7	actual length
	8-11	unknown
	12-15	secs
	16-19	usecs
	20-23	unknown
*/
struct nettlrec_ns_ls_drv_eth_hdr {
    guint8	xxa[4];
    guint8      caplen[2];
    guint8      length[2];
    guint8	xxb[4];
    guint8	sec[4];
    guint8	usec[4];
    guint8	xxc[4];
};


static gboolean nettl_read(wtap *wth, int *err, gchar **err_info,
		long *data_offset);
static gboolean nettl_seek_read(wtap *wth, long seek_off,
		union wtap_pseudo_header *pseudo_header, guchar *pd,
		int length, int *err, gchar **err_info);
static int nettl_read_rec_header(wtap *wth, FILE_T fh,
		struct wtap_pkthdr *phdr, union wtap_pseudo_header *pseudo_header,
		int *err, gchar **err_info, gboolean *fddihack);
static gboolean nettl_read_rec_data(FILE_T fh, guchar *pd, int length,
		int *err, gboolean fddihack);
static void nettl_close(wtap *wth);
static gboolean nettl_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const guchar *pd, int *err);

int nettl_open(wtap *wth, int *err, gchar **err_info _U_)
{
    struct nettl_file_hdr file_hdr;
    guint16 dummy[2];
    int subsys;
    int bytes_read;

    /* Read in the string that should be at the start of a HP file */
    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(file_hdr.magic, 1, MAGIC_SIZE, wth->fh);
    if (bytes_read != MAGIC_SIZE) {
    	*err = file_error(wth->fh);
	if (*err != 0)
	    return -1;
	return 0;
    }

    if (memcmp(file_hdr.magic, nettl_magic_hpux9, MAGIC_SIZE) &&
        memcmp(file_hdr.magic, nettl_magic_hpux10, MAGIC_SIZE)) {
	return 0;
    }

    /* Read the rest of the file header */
    bytes_read = file_read(file_hdr.file_name, 1, FILE_HDR_SIZE - MAGIC_SIZE,
			   wth->fh);
    if (bytes_read != FILE_HDR_SIZE - MAGIC_SIZE) {
	*err = file_error(wth->fh);
	if (*err != 0)
	    return -1;
	return 0;
    }

    /* This is an nettl file */
    wth->file_type = WTAP_FILE_NETTL;
    wth->capture.nettl = g_malloc(sizeof(nettl_t));
    if (file_hdr.os_vers[2] == '1' && file_hdr.os_vers[3] == '1')
	wth->capture.nettl->is_hpux_11 = TRUE;
    else
	wth->capture.nettl->is_hpux_11 = FALSE;
    wth->subtype_read = nettl_read;
    wth->subtype_seek_read = nettl_seek_read;
    wth->subtype_close = nettl_close;
    wth->snapshot_length = 0;	/* not available in header, only in frame */

    /* read the first header to take a guess at the file encap */
    bytes_read = file_read(dummy, 1, 4, wth->fh);
    if (bytes_read != 4) {
        if (*err != 0)
            return -1;
        if (bytes_read != 0) {
            *err = WTAP_ERR_SHORT_READ;
            g_free(wth->capture.nettl);
            return -1;
        }
        return 0;
    }

    subsys = g_ntohs(dummy[1]);
    switch (subsys) {
        case NETTL_SUBSYS_HPPB_FDDI :
        case NETTL_SUBSYS_EISA_FDDI :
        case NETTL_SUBSYS_PCI_FDDI :
        case NETTL_SUBSYS_HSC_FDDI :
		wth->file_encap = WTAP_ENCAP_NETTL_FDDI;
		break;
        case NETTL_SUBSYS_TOKEN :
        case NETTL_SUBSYS_PCI_TR :
		wth->file_encap = WTAP_ENCAP_NETTL_TOKEN_RING;
		break;
        case NETTL_SUBSYS_NS_LS_IP :
        case NETTL_SUBSYS_NS_LS_LOOPBACK :
        case NETTL_SUBSYS_NS_LS_TCP :
        case NETTL_SUBSYS_NS_LS_UDP :
        case NETTL_SUBSYS_NS_LS_IPV6 :
		wth->file_encap = WTAP_ENCAP_NETTL_RAW_IP;
		break;
	default:
		/* If this assumption is bad, the read will catch it */
		wth->file_encap = WTAP_ENCAP_NETTL_ETHERNET;
    }

    if (file_seek(wth->fh, FILE_HDR_SIZE, SEEK_SET, err) == -1) {
        g_free(wth->capture.nettl);
	return -1;
    }
    wth->data_offset = FILE_HDR_SIZE;
	wth->tsprecision = WTAP_FILE_TSPREC_USEC;

    return 1;
}

/* Read the next packet */
static gboolean nettl_read(wtap *wth, int *err, gchar **err_info,
    long *data_offset)
{
    int ret;
    gboolean fddihack=FALSE;

    /* Read record header. */
    *data_offset = wth->data_offset;
    ret = nettl_read_rec_header(wth, wth->fh, &wth->phdr, &wth->pseudo_header,
        err, err_info, &fddihack);
    if (ret <= 0) {
	/* Read error or EOF */
	return FALSE;
    }
    wth->data_offset += ret;

    /*
     * If the per-file encapsulation isn't known, set it to this
     * packet's encapsulation.
     *
     * If it *is* known, and it isn't this packet's encapsulation,
     * set it to WTAP_ENCAP_PER_PACKET, as this file doesn't
     * have a single encapsulation for all packets in the file.
     */
    if (wth->file_encap == WTAP_ENCAP_UNKNOWN)
	wth->file_encap = wth->phdr.pkt_encap;
    else {
	if (wth->file_encap != wth->phdr.pkt_encap)
	    wth->file_encap = WTAP_ENCAP_PER_PACKET;
    }

    /*
     * Read the packet data.
     */
    buffer_assure_space(wth->frame_buffer, wth->phdr.caplen);
    if (!nettl_read_rec_data(wth->fh, buffer_start_ptr(wth->frame_buffer),
		wth->phdr.caplen, err, fddihack))
	return FALSE;	/* Read error */
    wth->data_offset += wth->phdr.caplen;
    return TRUE;
}

static gboolean
nettl_seek_read(wtap *wth, long seek_off,
		union wtap_pseudo_header *pseudo_header, guchar *pd,
		int length, int *err, gchar **err_info)
{
    int ret;
    struct wtap_pkthdr phdr;
    gboolean fddihack=FALSE;

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
	return FALSE;

    /* Read record header. */
    ret = nettl_read_rec_header(wth, wth->random_fh, &phdr, pseudo_header,
        err, err_info, &fddihack);
    if (ret <= 0) {
	/* Read error or EOF */
	if (ret == 0) {
	    /* EOF means "short read" in random-access mode */
	    *err = WTAP_ERR_SHORT_READ;
	}
	return FALSE;
    }

    /*
     * Read the packet data.
     */
    return nettl_read_rec_data(wth->random_fh, pd, length, err, fddihack);
}

static int
nettl_read_rec_header(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr,
		union wtap_pseudo_header *pseudo_header, int *err,
		gchar **err_info, gboolean *fddihack)
{
    int bytes_read;
    struct nettlrec_ns_ls_ip_hdr ip_hdr;
    struct nettlrec_ns_ls_drv_eth_hdr drv_eth_hdr;
    guint16 length;
    int offset = 0;
    int subsys;
    int padlen;
    guint16 dummy[2];
    guchar dummyc[10];

    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(dummy, 1, 4, fh);
    if (bytes_read != 4) {
	*err = file_error(fh);
	if (*err != 0) return -1;
	if (bytes_read != 0) {
	    *err = WTAP_ERR_SHORT_READ;
	    return -1;
	}
	return 0;
    }
    offset += 4;

    subsys = g_ntohs(dummy[1]);
    switch (subsys) {
	case NETTL_SUBSYS_LAN100 :
	case NETTL_SUBSYS_EISA100BT :
	case NETTL_SUBSYS_BASE100 :
	case NETTL_SUBSYS_GSC100BT :
	case NETTL_SUBSYS_PCI100BT :
	case NETTL_SUBSYS_SPP100BT :
	case NETTL_SUBSYS_100VG :
	case NETTL_SUBSYS_GELAN :
	case NETTL_SUBSYS_BTLAN :
	case NETTL_SUBSYS_INTL100 :
	case NETTL_SUBSYS_IGELAN :
	case NETTL_SUBSYS_IETHER :
	case NETTL_SUBSYS_IXGBE :
	case NETTL_SUBSYS_HPPB_FDDI :
	case NETTL_SUBSYS_EISA_FDDI :
        case NETTL_SUBSYS_PCI_FDDI :
        case NETTL_SUBSYS_HSC_FDDI :
        case NETTL_SUBSYS_TOKEN :
        case NETTL_SUBSYS_PCI_TR :
	case NETTL_SUBSYS_NS_LS_IP :
	case NETTL_SUBSYS_NS_LS_LOOPBACK :
	case NETTL_SUBSYS_NS_LS_TCP :
	case NETTL_SUBSYS_NS_LS_UDP :
	case NETTL_SUBSYS_HP_APAPORT :
	case NETTL_SUBSYS_HP_APALACP :
	case NETTL_SUBSYS_NS_LS_IPV6 :
	case NETTL_SUBSYS_NS_LS_ICMPV6 :
	case NETTL_SUBSYS_NS_LS_ICMP :
	    if( (subsys == NETTL_SUBSYS_NS_LS_IP)
	     || (subsys == NETTL_SUBSYS_NS_LS_LOOPBACK)
	     || (subsys == NETTL_SUBSYS_NS_LS_UDP)
	     || (subsys == NETTL_SUBSYS_NS_LS_TCP)
	     || (subsys == NETTL_SUBSYS_NS_LS_IPV6)) {
		phdr->pkt_encap = WTAP_ENCAP_NETTL_RAW_IP;
	    } else if (subsys == NETTL_SUBSYS_NS_LS_ICMP) {
		phdr->pkt_encap = WTAP_ENCAP_NETTL_RAW_ICMP;
	    } else if (subsys == NETTL_SUBSYS_NS_LS_ICMPV6) {
		phdr->pkt_encap = WTAP_ENCAP_NETTL_RAW_ICMPV6;
	    } else if( (subsys == NETTL_SUBSYS_HPPB_FDDI)
		    || (subsys == NETTL_SUBSYS_EISA_FDDI)
		    || (subsys == NETTL_SUBSYS_PCI_FDDI)
		    || (subsys == NETTL_SUBSYS_HSC_FDDI) ) {
		phdr->pkt_encap = WTAP_ENCAP_NETTL_FDDI;
	    } else if( (subsys == NETTL_SUBSYS_PCI_TR)
		    || (subsys == NETTL_SUBSYS_TOKEN) ) {
		phdr->pkt_encap = WTAP_ENCAP_NETTL_TOKEN_RING;
	    } else {
		phdr->pkt_encap = WTAP_ENCAP_NETTL_ETHERNET;
	    }

	    bytes_read = file_read(&ip_hdr, 1, sizeof ip_hdr, fh);
	    if (bytes_read != sizeof ip_hdr) {
		*err = file_error(fh);
		if (*err != 0) return -1;
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
		if (file_seek(fh, 4, SEEK_CUR, err) == -1) return -1;
		offset += 4;
	    }

	    /* HPPB FDDI has different inbound vs outbound trace records */
	    if (subsys == NETTL_SUBSYS_HPPB_FDDI) {
                if (pntohl(&ip_hdr.kind) == NETTL_HDR_PDUIN) {
                   /* inbound is very strange...
                      there are an extra 3 bytes after the DSAP and SSAP
                      for SNAP frames ???
                   */
                   *fddihack=TRUE;
		   length = pntohl(&ip_hdr.length);
		   if (length <= 0) return 0;
		   phdr->len = length;
		   phdr->caplen = pntohl(&ip_hdr.caplen);
                } else {
	           /* outbound appears to have variable padding */
		   bytes_read = file_read(dummyc, 1, 9, fh);
		   if (bytes_read != 9) {
		       *err = file_error(fh);
		       if (*err != 0) return -1;
		       if (bytes_read != 0) {
			   *err = WTAP_ERR_SHORT_READ;
			   return -1;
		       }
		       return 0;
		   }
                   /* padding is usually either a total 11 or 16 bytes??? */
		   padlen = (int)dummyc[8];
		   if (file_seek(fh, padlen, SEEK_CUR, err) == -1) return -1;
		   padlen += 9;
		   offset += padlen;
		   length = pntohl(&ip_hdr.length);
		   if (length <= 0) return 0;
		   phdr->len = length - padlen;
		   length = pntohl(&ip_hdr.caplen);
		   phdr->caplen = length - padlen;
               }
	    } else if ( (subsys == NETTL_SUBSYS_PCI_FDDI)
	             || (subsys == NETTL_SUBSYS_EISA_FDDI)
	             || (subsys == NETTL_SUBSYS_HSC_FDDI) ) {
	        /* other flavor FDDI cards have an extra 3 bytes of padding */
                if (file_seek(fh, 3, SEEK_CUR, err) == -1) return -1;
		offset += 3;
		length = pntohl(&ip_hdr.length);
		if (length <= 0) return 0;
		phdr->len = length - 3;
		length = pntohl(&ip_hdr.caplen);
		phdr->caplen = length - 3;
	    } else if (subsys == NETTL_SUBSYS_NS_LS_LOOPBACK) {
	        /* LOOPBACK has an extra 26 bytes of padding */
                if (file_seek(fh, 26, SEEK_CUR, err) == -1) return -1;
		offset += 26;
		length = pntohl(&ip_hdr.length);
		if (length <= 0) return 0;
		phdr->len = length - 26;
		length = pntohl(&ip_hdr.caplen);
		phdr->caplen = length - 26;
	    } else {
		length = pntohl(&ip_hdr.length);
		if (length <= 0) return 0;
		phdr->len = length;
		phdr->caplen = pntohl(&ip_hdr.caplen);
	    }

	    phdr->ts.secs = pntohl(&ip_hdr.sec);
	    phdr->ts.nsecs = pntohl(&ip_hdr.usec) * 1000;
	    break;

	case NETTL_SUBSYS_NS_LS_DRIVER :
	    bytes_read = file_read(&ip_hdr, 1, sizeof ip_hdr, fh);
	    if (bytes_read != sizeof ip_hdr) {
		*err = file_error(fh);
		if (*err != 0) return -1;
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
	        if (file_seek(fh, 4, SEEK_CUR, err) == -1) return -1;
		offset += 4;
	    }

	    /* XXX we dont know how to identify this as ethernet frames, so
	       we assumes everything is. We will crash and burn for anything else */
	    /* for encapsulated 100baseT we do this */
	    phdr->pkt_encap = WTAP_ENCAP_NETTL_ETHERNET;
	    bytes_read = file_read(&drv_eth_hdr, 1, sizeof drv_eth_hdr, fh);
	    if (bytes_read != sizeof drv_eth_hdr) {
		*err = file_error(fh);
		if (*err != 0) return -1;
		if (bytes_read != 0) {
		    *err = WTAP_ERR_SHORT_READ;
		    return -1;
		}
		return 0;
	    }
	    offset += sizeof drv_eth_hdr;

	    length = pntohs(&drv_eth_hdr.length); 
	    if (length <= 0) return 0;
	    phdr->len = length;
	    phdr->caplen = pntohs(&drv_eth_hdr.caplen);

	    phdr->ts.secs = pntohl(&ip_hdr.sec);
	    phdr->ts.nsecs = pntohl(&ip_hdr.usec) * 1000;
	    break;

	case NETTL_SUBSYS_SX25L2:
	case NETTL_SUBSYS_SX25L3:
            bytes_read = file_read(&ip_hdr, 1, sizeof ip_hdr, fh);
            if (bytes_read != sizeof ip_hdr) {
                *err = file_error(fh);
                if (*err != 0) return -1;
                if (bytes_read != 0) {
                    *err = WTAP_ERR_SHORT_READ;
                    return -1;
                }
                return 0;
            }
            offset += sizeof ip_hdr;
            length = pntohl(&ip_hdr.length);
            if (length <= 0) return 0;
            phdr->len = length - 24;
            phdr->caplen = pntohl(&ip_hdr.caplen) - 24;
            phdr->ts.secs = pntohl(&ip_hdr.sec);
            phdr->ts.nsecs = pntohl(&ip_hdr.usec) * 1000;
            if (wth->capture.nettl->is_hpux_11)
                padlen = 28;
	    else
		padlen = 24;
	    if (file_seek(fh, padlen, SEEK_CUR, err) == -1) return -1;
            offset += padlen;
	    phdr->pkt_encap = WTAP_ENCAP_NETTL_X25;
	    break;

	default:
	    wth->file_encap = WTAP_ENCAP_PER_PACKET;
	    phdr->pkt_encap = WTAP_ENCAP_NETTL_UNKNOWN;
            bytes_read = file_read(&ip_hdr, 1, sizeof ip_hdr, fh);
            if (bytes_read != sizeof ip_hdr) {
                *err = file_error(fh);
                if (*err != 0) return -1;
                if (bytes_read != 0) {
                    *err = WTAP_ERR_SHORT_READ;
                    return -1;
                }
                return 0;
            }
            offset += sizeof ip_hdr;
            length = pntohl(&ip_hdr.length);
            if (length <= 0) return 0;
            phdr->len = length;
            phdr->caplen = pntohl(&ip_hdr.caplen);
            phdr->ts.secs = pntohl(&ip_hdr.sec);
            phdr->ts.nsecs = pntohl(&ip_hdr.usec) * 1000;
            if (wth->capture.nettl->is_hpux_11) {
	       if (file_seek(fh, 4, SEEK_CUR, err) == -1) return -1;
               offset += 4;
            }
    }

    pseudo_header->nettl.subsys   = subsys;
    pseudo_header->nettl.devid    = pntohl(&ip_hdr.devid);
    pseudo_header->nettl.kind     = pntohl(&ip_hdr.kind);
    pseudo_header->nettl.pid      = pntohl(&ip_hdr.pid);
    pseudo_header->nettl.uid      = pntohs(&ip_hdr.uid);

    return offset;
}

static gboolean
nettl_read_rec_data(FILE_T fh, guchar *pd, int length, int *err, gboolean fddihack)
{
    int bytes_read;
    guchar *p=NULL;
    guint8 dummy[3];

    if (fddihack == TRUE) {
       /* read in FC, dest, src, DSAP and SSAP */
       if (file_read(pd, 1, 15, fh) == 15) {
          if (pd[13] == 0xAA) {
             /* it's SNAP, have to eat 3 bytes??? */
             if (file_read(dummy, 1, 3, fh) == 3) {
                p=pd+15;
                bytes_read = file_read(p, 1, length-18, fh);
                bytes_read += 18;
             } else {
                bytes_read = -1;
             }
          } else {
             /* not SNAP */
             p=pd+15;
             bytes_read = file_read(p, 1, length-15, fh);
             bytes_read += 15;
          }
       } else
          bytes_read = -1;
    } else
       bytes_read = file_read(pd, 1, length, fh);

    if (bytes_read != length) {
	*err = file_error(fh);
	if (*err == 0)
	    *err = WTAP_ERR_SHORT_READ;
	return FALSE;
    }
    return TRUE;
}

static void nettl_close(wtap *wth)
{
    g_free(wth->capture.nettl);
}


/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise.  nettl files are WTAP_ENCAP_UNKNOWN
   when they are first opened, so we allow that for tshark read/write.
 */

int nettl_dump_can_write_encap(int encap)
{

	switch (encap) {
		case WTAP_ENCAP_ETHERNET:
		case WTAP_ENCAP_FDDI_BITSWAPPED:
		case WTAP_ENCAP_TOKEN_RING:
		case WTAP_ENCAP_NETTL_ETHERNET:
		case WTAP_ENCAP_NETTL_FDDI:
		case WTAP_ENCAP_NETTL_TOKEN_RING:
		case WTAP_ENCAP_NETTL_RAW_IP:
		case WTAP_ENCAP_NETTL_RAW_ICMP:
		case WTAP_ENCAP_NETTL_RAW_ICMPV6:
/*
		case WTAP_ENCAP_NETTL_X25:
*/
		case WTAP_ENCAP_PER_PACKET:
		case WTAP_ENCAP_UNKNOWN:
		case WTAP_ENCAP_NETTL_UNKNOWN:
			return 0;
		default:
			return WTAP_ERR_UNSUPPORTED_ENCAP;
	}
}


/* Returns TRUE on success, FALSE on failure;
   sets "*err" to an error code on failure */
gboolean nettl_dump_open(wtap_dumper *wdh, gboolean cant_seek _U_, int *err)
{
	struct nettl_file_hdr file_hdr;
	size_t nwritten;

	/* This is a nettl file */
	wdh->subtype_write = nettl_dump;
	wdh->subtype_close = NULL;

	/* Write the file header. */
	memset(&file_hdr,0,sizeof(file_hdr));
	memcpy(file_hdr.magic,nettl_magic_hpux10,sizeof(file_hdr.magic));
	strcpy(file_hdr.file_name,"/tmp/wireshark.TRC000");
	strcpy(file_hdr.tz,"UTC");
	strcpy(file_hdr.host_name,"wshark");	/* XXX - leave blank? */
	strcpy(file_hdr.os_vers,"B.11.11");
	file_hdr.os_v=0x55;
	strcpy(file_hdr.model,"9000/800");
	file_hdr.unknown=g_htons(0x406);
	nwritten = fwrite(&file_hdr, 1, sizeof file_hdr, wdh->fh);
	if (nwritten != sizeof(file_hdr)) {
		if (nwritten == 0 && ferror(wdh->fh))
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}
	wdh->bytes_dumped += sizeof(file_hdr);

	return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean nettl_dump(wtap_dumper *wdh,
	const struct wtap_pkthdr *phdr,
	const union wtap_pseudo_header *pseudo_header _U_,
	const guchar *pd, int *err)
{
	struct nettlrec_dump_hdr rec_hdr;
	size_t nwritten;
	guint8 padding=0;

	memset(&rec_hdr,0,sizeof(rec_hdr));
	rec_hdr.hdr_len = g_htons(sizeof(rec_hdr));
	rec_hdr.hdr.kind = g_htonl(NETTL_HDR_PDUIN);
	rec_hdr.hdr.sec = g_htonl(phdr->ts.secs);
	rec_hdr.hdr.usec = g_htonl(phdr->ts.nsecs/1000);
	rec_hdr.hdr.caplen = g_htonl(phdr->caplen);
	rec_hdr.hdr.length = g_htonl(phdr->len);
	rec_hdr.hdr.devid = -1;
	rec_hdr.hdr.pid = -1;
	rec_hdr.hdr.uid = -1;

	switch (phdr->pkt_encap) {

		case WTAP_ENCAP_NETTL_FDDI:
			/* account for pad bytes */
			rec_hdr.hdr.caplen = g_htonl(phdr->caplen + 3);
			rec_hdr.hdr.length = g_htonl(phdr->len + 3);
                        /* fall through and fill the rest of the fields */
		case WTAP_ENCAP_NETTL_ETHERNET:
		case WTAP_ENCAP_NETTL_TOKEN_RING:
		case WTAP_ENCAP_NETTL_RAW_IP:
		case WTAP_ENCAP_NETTL_RAW_ICMP:
		case WTAP_ENCAP_NETTL_RAW_ICMPV6:
		case WTAP_ENCAP_NETTL_UNKNOWN:
			rec_hdr.subsys = g_htons(pseudo_header->nettl.subsys);
			rec_hdr.hdr.devid = g_htonl(pseudo_header->nettl.devid);
			rec_hdr.hdr.kind = g_htonl(pseudo_header->nettl.kind);
			rec_hdr.hdr.pid = g_htonl(pseudo_header->nettl.pid);
			rec_hdr.hdr.uid = g_htons(pseudo_header->nettl.uid);
			break;

		case WTAP_ENCAP_RAW_IP:
			rec_hdr.subsys = g_htons(NETTL_SUBSYS_NS_LS_IP);
			break;

		case WTAP_ENCAP_ETHERNET:
			rec_hdr.subsys = g_htons(NETTL_SUBSYS_BTLAN);
			break;

		case WTAP_ENCAP_FDDI_BITSWAPPED:
			rec_hdr.subsys = g_htons(NETTL_SUBSYS_PCI_FDDI);
			/* account for pad bytes */
			rec_hdr.hdr.caplen = g_htonl(phdr->caplen + 3);
			rec_hdr.hdr.length = g_htonl(phdr->len + 3);
			break;

		case WTAP_ENCAP_TOKEN_RING:
			rec_hdr.subsys = g_htons(NETTL_SUBSYS_PCI_TR);
			break;
/*	
		case WTAP_ENCAP_NETTL_X25:
			rec_hdr.hdr.caplen = g_htonl(phdr->caplen + 24);
			rec_hdr.hdr.length = g_htonl(phdr->len + 24);
			rec_hdr.subsys = g_htons(pseudo_header->nettl.subsys);
			rec_hdr.hdr.devid = g_htonl(pseudo_header->nettl.devid);
			rec_hdr.hdr.kind = g_htonl(pseudo_header->nettl.kind);
			rec_hdr.hdr.pid = g_htonl(pseudo_header->nettl.pid);
			rec_hdr.hdr.uid = g_htons(pseudo_header->nettl.uid);
			break;
*/
		default:
			/* found one we don't support */
			*err = WTAP_ERR_UNSUPPORTED_ENCAP;
			return FALSE;
	}

	nwritten = fwrite(&rec_hdr, 1, sizeof(rec_hdr), wdh->fh);
	if (nwritten != sizeof(rec_hdr)) {
		if (nwritten == 0 && ferror(wdh->fh))
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}
	wdh->bytes_dumped += sizeof(rec_hdr);

	if ((phdr->pkt_encap == WTAP_ENCAP_FDDI_BITSWAPPED) ||
	    (phdr->pkt_encap == WTAP_ENCAP_NETTL_FDDI)) {
		/* add those weird 3 bytes of padding */
		nwritten = fwrite(&padding, 1, 3, wdh->fh);
		if (nwritten != 3) {
			if (nwritten == 0 && ferror(wdh->fh))
				*err = errno;
			else
				*err = WTAP_ERR_SHORT_WRITE;
			return FALSE;
		}
        	wdh->bytes_dumped += 3;
	}
/*
	} else if (phdr->pkt_encap == WTAP_ENCAP_NETTL_X25) {
		nwritten = fwrite(&padding, 1, 24, wdh->fh);
		if (nwritten != 24) {
			if (nwritten == 0 && ferror(wdh->fh))
				*err = errno;
			else
				*err = WTAP_ERR_SHORT_WRITE;
			return FALSE;
		}
		wdh->bytes_dumped += 24;
	}
*/

	/* write actual PDU data */

	nwritten = fwrite(pd, 1, phdr->caplen, wdh->fh);
	if (nwritten != phdr->caplen) {
		if (nwritten == 0 && ferror(wdh->fh))
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}
        wdh->bytes_dumped += phdr->caplen;

	return TRUE;
}
