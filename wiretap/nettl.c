/* nettl.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

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
static const guint8 nettl_magic_hpux9[MAGIC_SIZE] = {
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xD0, 0x00
};
/* HP-UX 10.x and 11.x */
static const guint8 nettl_magic_hpux10[MAGIC_SIZE] = {
    0x54, 0x52, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
};

#define FILE_HDR_SIZE	128
#define NETTL_FILENAME_SIZE 56

struct nettl_file_hdr {
    guint8	magic[MAGIC_SIZE];
    gchar	file_name[NETTL_FILENAME_SIZE];
    gchar	tz[20];
    gchar	host_name[9];
    gchar	os_vers[9];
    guint8	os_v;
    guint8	xxa[8];
    gchar	model[11];
    guint16	unknown;	/* just padding to 128 bytes? */
};

/* HP nettl record header */
/* see /usr/include/sys/netdiag1.h for hints */
struct nettlrec_hdr {
    guint16	hdr_len;
    guint16	subsys;
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

/*
 * This is what we treat as the minimum size of a record header.
 * It is *not* necessarily the same as sizeof(struct nettlrec_hdr),
 * because it doesn't include any padding added to the structure.
 */
#define NETTL_REC_HDR_LEN	64

/* HP nettl record header for the SX25L2 subsystem - The FCS is not included
   in the file. */
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

/* NL_LS_DRIVER :
The following shows what the header and subheader looks like for NS_LS_DRIVER
The capture was taken on HPUX11 and for a 100baseT interface.

000080 00 44 00 0b 00 00 00 02 00 00 00 00 20 00 00 00
000090 00 00 00 00 00 00 04 06 00 00 00 00 00 00 00 00
0000a0 00 00 00 74 00 00 00 74 3c e3 76 19 00 06 34 63
0000b0 ff ff ff ff 00 00 00 00 00 00 00 00 ff ff ff ff
0000c0 00 00 00 00 00 00 01 02 00 5c 00 5c ff ff ff ff
0000d0 3c e3 76 19 00 06 34 5a 00 0b 00 14 <here starts the MAC header>

Each entry starts with 0x0044000b

The values 0x005c at position 0x0000c8 and 0x0000ca matches the number of
bytes in the packet up to the next entry, which starts with 0x00440b again.
These are the captured and real and captured length of the packet.

The values 0x00000074 at positions 0x0000a0 and 0x0000a4 seems to indicate
the same number as positions 0x0000c8 and 0x0000ca but added with 24.
Perhaps we have here two layers of headers.
The first layer is fixed and consists of all the bytes from 0x000084 up to and
including 0x0000c3 which is a generic header for all packets captured from any
device. This header might be of fixed size 64 bytes (although the first two
bytes appear to be the length of that header, in big-endian format) and there
might be something in it which indicates the type of the next header which is
link type specific. Following this header there is another header for the
100baseT interface which in this case is 24 bytes long spanning positions
0x0000c4 to 0x0000db.

In another capture, claimed to be taken on an HP-UX 8 box, but with a
file header suggesting it was taken on HP-UX 10.20, the header for
NS_LS_DRIVER looks like:

000080   00 40 00 0b ff ff ff ff 00 00 00 00 00 00 00 00
000090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0000a0   00 00 00 51 00 00 00 51 42 02 5e bf 00 0e ab 7c
0000b0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0000c0   00 02 01 00 00 3b 00 3b ff ff ff ff 42 02 5e bf
0000d0   00 0e 8e 44 00 0b <here starts the MAC header>

When someone reports that the loading of the captures breaks, we can
compare this header above with what he/she got to learn how to
distinguish between different types of link specific headers.


For now, the subheader for 100baseT seems to be
	4-5	captured length
	6-7	actual length
	8-11	unknown
	12-15	secs
	16-19	usecs
	20-21	unknown
*/
struct nettlrec_ns_ls_drv_eth_hdr {
    guint8	xxa[4];
    guint8      caplen[2];
    guint8      length[2];
    guint8	xxb[4];
    guint8	sec[4];
    guint8	usec[4];
    guint8	xxc[2];
};

/*
 * This is the size of an NS_LS_DRV_ETH header; it is *not* necessarily
 * the same as sizeof(struct nettlrec_ns_ls_drv_eth_hdr), because it
 * doesn't include any padding added to the structure.
 */
#define NS_LS_DRV_ETH_HDR_LEN	22

/* header is followed by data and once again the total length (2 bytes) ! */

typedef struct {
	gboolean is_hpux_11;
} nettl_t;

static gboolean nettl_read(wtap *wth, int *err, gchar **err_info,
		gint64 *data_offset);
static gboolean nettl_seek_read(wtap *wth, gint64 seek_off,
		struct wtap_pkthdr *phdr, Buffer *buf,
		int *err, gchar **err_info);
static gboolean nettl_read_rec(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr,
		Buffer *buf, int *err, gchar **err_info);
static gboolean nettl_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const guint8 *pd, int *err);

int nettl_open(wtap *wth, int *err, gchar **err_info)
{
    struct nettl_file_hdr file_hdr;
    guint16 dummy[2];
    int subsys;
    int bytes_read;
    nettl_t *nettl;

    memset(&file_hdr, 0, sizeof(file_hdr));

    /* Read in the string that should be at the start of a HP file */
    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(file_hdr.magic, MAGIC_SIZE, wth->fh);
    if (bytes_read != MAGIC_SIZE) {
    	*err = file_error(wth->fh, err_info);
	if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
	    return -1;
	return 0;
    }

    if (memcmp(file_hdr.magic, nettl_magic_hpux9, MAGIC_SIZE) &&
        memcmp(file_hdr.magic, nettl_magic_hpux10, MAGIC_SIZE)) {
	return 0;
    }

    /* Read the rest of the file header */
    bytes_read = file_read(file_hdr.file_name, FILE_HDR_SIZE - MAGIC_SIZE,
			   wth->fh);
    if (bytes_read != FILE_HDR_SIZE - MAGIC_SIZE) {
	*err = file_error(wth->fh, err_info);
	if (*err == 0)
	    *err = WTAP_ERR_SHORT_READ;
	return -1;
    }

    /* This is an nettl file */
    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_NETTL;
    nettl = g_new(nettl_t,1);
    wth->priv = (void *)nettl;
    if (file_hdr.os_vers[2] == '1' && file_hdr.os_vers[3] == '1')
	nettl->is_hpux_11 = TRUE;
    else
	nettl->is_hpux_11 = FALSE;
    wth->subtype_read = nettl_read;
    wth->subtype_seek_read = nettl_seek_read;
    wth->snapshot_length = 0;	/* not available */

    /* read the first header to take a guess at the file encap */
    bytes_read = file_read(dummy, 4, wth->fh);
    if (bytes_read != 4) {
        if (*err != 0) {
            return -1;
        }
        if (bytes_read != 0) {
            *err = WTAP_ERR_SHORT_READ;
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
        case NETTL_SUBSYS_NS_LS_ICMP :
		wth->file_encap = WTAP_ENCAP_NETTL_RAW_ICMP;
		break;
        case NETTL_SUBSYS_NS_LS_ICMPV6 :
		wth->file_encap = WTAP_ENCAP_NETTL_RAW_ICMPV6;
		break;
        case NETTL_SUBSYS_NS_LS_TELNET :
		wth->file_encap = WTAP_ENCAP_NETTL_RAW_TELNET;
		break;
	default:
		/* If this assumption is bad, the read will catch it */
		wth->file_encap = WTAP_ENCAP_NETTL_ETHERNET;
    }

    if (file_seek(wth->fh, FILE_HDR_SIZE, SEEK_SET, err) == -1) {
	return -1;
    }
    wth->tsprecision = WTAP_FILE_TSPREC_USEC;

    return 1;
}

/* Read the next packet */
static gboolean nettl_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
    /* Read record. */
    *data_offset = file_tell(wth->fh);
    if (!nettl_read_rec(wth, wth->fh, &wth->phdr, wth->frame_buffer,
        err, err_info)) {
	/* Read error or EOF */
	return FALSE;
    }

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

    return TRUE;
}

static gboolean
nettl_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *phdr,
		Buffer *buf, int *err, gchar **err_info)
{
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
	return FALSE;

    /* Read record. */
    if (!nettl_read_rec(wth, wth->random_fh, phdr, buf, err, err_info)) {
	/* Read error or EOF */
	if (*err == 0) {
	    /* EOF means "short read" in random-access mode */
	    *err = WTAP_ERR_SHORT_READ;
	}
	return FALSE;
    }
    return TRUE;
}

static gboolean
nettl_read_rec(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr, Buffer *buf,
		int *err, gchar **err_info)
{
    union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
    nettl_t *nettl = (nettl_t *)wth->priv;
    gboolean fddihack = FALSE;
    int bytes_read;
    struct nettlrec_hdr rec_hdr;
    guint16 hdr_len;
    struct nettlrec_ns_ls_drv_eth_hdr drv_eth_hdr;
    guint32 length, caplen;
    int subsys;
    guint padlen;
    int datalen;
    guint8 dummyc[16];
    int bytes_to_read;
    guint8 *pd;
    guint8 dummy[3];

    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(&rec_hdr.hdr_len, sizeof rec_hdr.hdr_len, fh);
    if (bytes_read != sizeof rec_hdr.hdr_len) {
	*err = file_error(fh, err_info);
	if (*err == 0 && bytes_read != 0)
	    *err = WTAP_ERR_SHORT_READ;
	return FALSE;
    }
    hdr_len = g_ntohs(rec_hdr.hdr_len);
    if (hdr_len < NETTL_REC_HDR_LEN) {
    	*err = WTAP_ERR_BAD_FILE;
	*err_info = g_strdup_printf("nettl: record header length %u too short",
	    hdr_len);
	return FALSE;
    }
    bytes_read = file_read(&rec_hdr.subsys, NETTL_REC_HDR_LEN - 2, fh);
    if (bytes_read != NETTL_REC_HDR_LEN - 2) {
	*err = file_error(fh, err_info);
	if (*err == 0)
	    *err = WTAP_ERR_SHORT_READ;
	return FALSE;
    }
    subsys = g_ntohs(rec_hdr.subsys);
    hdr_len -= NETTL_REC_HDR_LEN;
    if (file_seek(fh, hdr_len, SEEK_CUR, err) == -1)
	return FALSE;

    if ( (pntoh32(&rec_hdr.kind) & NETTL_HDR_PDU_MASK) == 0 ) {
        /* not actually a data packet (PDU) trace record */
        phdr->pkt_encap = WTAP_ENCAP_NETTL_RAW_IP;
        length = pntoh32(&rec_hdr.length);
        caplen = pntoh32(&rec_hdr.caplen);
        padlen = 0;
    } else switch (subsys) {
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
	case NETTL_SUBSYS_HSSN :
	case NETTL_SUBSYS_IGSSN :
	case NETTL_SUBSYS_ICXGBE :
	case NETTL_SUBSYS_IEXGBE :
	case NETTL_SUBSYS_IOCXGBE :
	case NETTL_SUBSYS_IQXGBE :
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
	case NETTL_SUBSYS_NS_LS_TELNET :
	case NETTL_SUBSYS_NS_LS_SCTP :
	    if( (subsys == NETTL_SUBSYS_NS_LS_IP)
	     || (subsys == NETTL_SUBSYS_NS_LS_LOOPBACK)
	     || (subsys == NETTL_SUBSYS_NS_LS_UDP)
	     || (subsys == NETTL_SUBSYS_NS_LS_TCP)
	     || (subsys == NETTL_SUBSYS_NS_LS_SCTP)
	     || (subsys == NETTL_SUBSYS_NS_LS_IPV6)) {
		phdr->pkt_encap = WTAP_ENCAP_NETTL_RAW_IP;
	    } else if (subsys == NETTL_SUBSYS_NS_LS_ICMP) {
		phdr->pkt_encap = WTAP_ENCAP_NETTL_RAW_ICMP;
	    } else if (subsys == NETTL_SUBSYS_NS_LS_ICMPV6) {
		phdr->pkt_encap = WTAP_ENCAP_NETTL_RAW_ICMPV6;
	    } else if (subsys == NETTL_SUBSYS_NS_LS_TELNET) {
		phdr->pkt_encap = WTAP_ENCAP_NETTL_RAW_TELNET;
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

	    length = pntoh32(&rec_hdr.length);
	    caplen = pntoh32(&rec_hdr.caplen);

	    /* HPPB FDDI has different inbound vs outbound trace records */
	    if (subsys == NETTL_SUBSYS_HPPB_FDDI) {
                if (pntoh32(&rec_hdr.kind) == NETTL_HDR_PDUIN) {
                    /* inbound is very strange...
                       there are an extra 3 bytes after the DSAP and SSAP
                       for SNAP frames ???
                    */
                    fddihack=TRUE;
                    padlen = 0;
                } else {
	            /* outbound appears to have variable padding */
		    bytes_read = file_read(dummyc, 9, fh);
		    if (bytes_read != 9) {
			*err = file_error(fh, err_info);
			if (*err == 0)
			    *err = WTAP_ERR_SHORT_READ;
			return FALSE;
		    }
                    /* padding is usually either a total 11 or 16 bytes??? */
		    padlen = (int)dummyc[8];
		    if (file_seek(fh, padlen, SEEK_CUR, err) == -1)
			return FALSE;
		    padlen += 9;
		}
	    } else if ( (subsys == NETTL_SUBSYS_PCI_FDDI)
	             || (subsys == NETTL_SUBSYS_EISA_FDDI)
	             || (subsys == NETTL_SUBSYS_HSC_FDDI) ) {
	        /* other flavor FDDI cards have an extra 3 bytes of padding */
                if (file_seek(fh, 3, SEEK_CUR, err) == -1)
                    return FALSE;
                padlen = 3;
	    } else if (subsys == NETTL_SUBSYS_NS_LS_LOOPBACK) {
	        /* LOOPBACK has an extra 26 bytes of padding */
                if (file_seek(fh, 26, SEEK_CUR, err) == -1)
                    return FALSE;
                padlen = 26;
            } else if (subsys == NETTL_SUBSYS_NS_LS_SCTP) {
                /*
                 * SCTP 8 byte header that we will ignore...
                 * 32 bit integer defines format
                 *   1 = Log
                 *   2 = ASCII
                 *   3 = Binary (PDUs should be Binary format)
                 * 32 bit integer defines type
                 *   1 = Inbound
                 *   2 = Outbound
                 */
                if (file_seek(fh, 8, SEEK_CUR, err) == -1)
                    return FALSE;
                padlen = 8;
	    } else {
	    	padlen = 0;
	    }
	    break;

	case NETTL_SUBSYS_NS_LS_DRIVER :
	    /* XXX we dont know how to identify this as ethernet frames, so
	       we assumes everything is. We will crash and burn for anything else */
	    /* for encapsulated 100baseT we do this */
	    phdr->pkt_encap = WTAP_ENCAP_NETTL_ETHERNET;
	    bytes_read = file_read(&drv_eth_hdr, NS_LS_DRV_ETH_HDR_LEN, fh);
	    if (bytes_read != NS_LS_DRV_ETH_HDR_LEN) {
		*err = file_error(fh, err_info);
		if (*err == 0)
		    *err = WTAP_ERR_SHORT_READ;
		return FALSE;
	    }

	    length = pntoh16(&drv_eth_hdr.length);
	    caplen = pntoh16(&drv_eth_hdr.caplen);
	    /*
	     * XXX - is there a length field that would give the length
	     * of this header, so that we don't have to check for
	     * nettl files from HP-UX 11?
	     *
	     * And what are the extra two bytes?
	     */
            if (nettl->is_hpux_11) {
                if (file_seek(fh, 2, SEEK_CUR, err) == -1) return FALSE;
            }
	    padlen = 0;
	    break;

	case NETTL_SUBSYS_SX25L2:
	case NETTL_SUBSYS_SX25L3:
	    /*
	     * XXX - is the 24-byte padding actually a header with
	     * packet lengths, time stamps, etc., just as is the case
	     * for NETTL_SUBSYS_NS_LS_DRIVER?  It might be
	     *
	     *    guint8	caplen[2];
	     *    guint8	length[2];
	     *    guint8	xxc[4];
	     *    guint8	sec[4];
	     *    guint8	usec[4];
	     *    guint8	xxd[4];
	     *
	     * or something such as that - if it has 4 bytes before that
	     * (making it 24 bytes), it'd be like struct
	     * nettlrec_ns_ls_drv_eth_hdr but with 2 more bytes at the end.
	     *
	     * And is "from_dce" at xxa[0] in the nettlrec_hdr structure?
	     */
	    phdr->pkt_encap = WTAP_ENCAP_NETTL_X25;
	    length = pntoh32(&rec_hdr.length);
	    caplen = pntoh32(&rec_hdr.caplen);
	    padlen = 24;	/* sizeof (struct nettlrec_sx25l2_hdr) - NETTL_REC_HDR_LEN + 4 */
	    if (file_seek(fh, padlen, SEEK_CUR, err) == -1)
		return FALSE;
	    break;

	default:
            /* We're going to assume it's ethernet if we don't recognize the
               subsystem -- We'll probably spew junks and core if it isn't... */
	    wth->file_encap = WTAP_ENCAP_PER_PACKET;
	    phdr->pkt_encap = WTAP_ENCAP_NETTL_ETHERNET;
            length = pntoh32(&rec_hdr.length);
            caplen = pntoh32(&rec_hdr.caplen);
            padlen = 0;
            break;
    }

    if (length < padlen) {
	*err = WTAP_ERR_BAD_FILE;
	*err_info = g_strdup_printf("nettl: packet length %u in record header too short, less than %u",
	    length, padlen);
	return FALSE;
    }
    phdr->rec_type = REC_TYPE_PACKET;
    phdr->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
    phdr->len = length - padlen;
    if (caplen < padlen) {
	*err = WTAP_ERR_BAD_FILE;
	*err_info = g_strdup_printf("nettl: captured length %u in record header too short, less than %u",
	    caplen, padlen);
	return FALSE;
    }
    datalen = caplen - padlen;
    phdr->caplen = datalen;
    phdr->ts.secs = pntoh32(&rec_hdr.sec);
    phdr->ts.nsecs = pntoh32(&rec_hdr.usec) * 1000;

    pseudo_header->nettl.subsys   = subsys;
    pseudo_header->nettl.devid    = pntoh32(&rec_hdr.devid);
    pseudo_header->nettl.kind     = pntoh32(&rec_hdr.kind);
    pseudo_header->nettl.pid      = pntoh32(&rec_hdr.pid);
    pseudo_header->nettl.uid      = pntoh16(&rec_hdr.uid);

    if (phdr->caplen > WTAP_MAX_PACKET_SIZE) {
	/*
	 * Probably a corrupt capture file; don't blow up trying
	 * to allocate space for an immensely-large packet.
	 */
	*err = WTAP_ERR_BAD_FILE;
	*err_info = g_strdup_printf("nettl: File has %u-byte packet, bigger than maximum of %u",
	    phdr->caplen, WTAP_MAX_PACKET_SIZE);
	return FALSE;
    }

    /*
     * Read the packet data.
     */
    buffer_assure_space(buf, datalen);
    pd = buffer_start_ptr(buf);
    errno = WTAP_ERR_CANT_READ;
    if (fddihack) {
        /* read in FC, dest, src, DSAP and SSAP */
        bytes_to_read = 15;
        if (bytes_to_read > datalen)
            bytes_to_read = datalen;
        bytes_read = file_read(pd, bytes_to_read, fh);
        if (bytes_read != bytes_to_read) {
            if (*err == 0)
                *err = WTAP_ERR_SHORT_READ;
            return FALSE;
        }
        datalen -= bytes_read;
        if (datalen == 0) {
            /* There's nothing past the FC, dest, src, DSAP and SSAP */
            return TRUE;
        }
        if (pd[13] == 0xAA) {
            /* it's SNAP, have to eat 3 bytes??? */
            bytes_to_read = 3;
            if (bytes_to_read > datalen)
                bytes_to_read = datalen;
            bytes_read = file_read(dummy, bytes_to_read, fh);
            if (bytes_read != bytes_to_read) {
                if (*err == 0)
                    *err = WTAP_ERR_SHORT_READ;
                return FALSE;
            }
            datalen -= bytes_read;
            if (datalen == 0) {
                /* There's nothing past the FC, dest, src, DSAP, SSAP, and 3 bytes to eat */
		return TRUE;
	    }
        }
        bytes_read = file_read(pd + 15, datalen, fh);
    } else
        bytes_read = file_read(pd, datalen, fh);

    if (bytes_read != datalen) {
	*err = file_error(fh, err_info);
	if (*err == 0)
	    *err = WTAP_ERR_SHORT_READ;
	return FALSE;
    }
    return TRUE;
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
		case WTAP_ENCAP_NETTL_RAW_TELNET:
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
gboolean nettl_dump_open(wtap_dumper *wdh, int *err)
{
	struct nettl_file_hdr file_hdr;

	/* This is a nettl file */
	wdh->subtype_write = nettl_dump;
	wdh->subtype_close = NULL;

	/* Write the file header. */
	memset(&file_hdr,0,sizeof(file_hdr));
	memcpy(file_hdr.magic,nettl_magic_hpux10,sizeof(file_hdr.magic));
	g_strlcpy(file_hdr.file_name,"/tmp/wireshark.TRC000",NETTL_FILENAME_SIZE);
	g_strlcpy(file_hdr.tz,"UTC",20);
	g_strlcpy(file_hdr.host_name,"",9);
	g_strlcpy(file_hdr.os_vers,"B.11.11",9);
	file_hdr.os_v=0x55;
	g_strlcpy(file_hdr.model,"9000/800",11);
	file_hdr.unknown=g_htons(0x406);
	if (!wtap_dump_file_write(wdh, &file_hdr, sizeof file_hdr, err))
		return FALSE;
	wdh->bytes_dumped += sizeof(file_hdr);

	return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean nettl_dump(wtap_dumper *wdh,
	const struct wtap_pkthdr *phdr,
	const guint8 *pd, int *err)
{
	const union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
	struct nettlrec_hdr rec_hdr;
	guint8 dummyc[24];

	/* We can only write packet records. */
	if (phdr->rec_type != REC_TYPE_PACKET) {
		*err = WTAP_ERR_REC_TYPE_UNSUPPORTED;
		return FALSE;
	}

	/* Don't write anything we're not willing to read. */
	if (phdr->caplen > WTAP_MAX_PACKET_SIZE) {
		*err = WTAP_ERR_PACKET_TOO_LARGE;
		return FALSE;
	}

	memset(&rec_hdr,0,sizeof(rec_hdr));
        /* HP-UX 11.X header should be 68 bytes */
	rec_hdr.hdr_len = g_htons(sizeof(rec_hdr) + 4);
	rec_hdr.kind = g_htonl(NETTL_HDR_PDUIN);
	rec_hdr.sec = g_htonl(phdr->ts.secs);
	rec_hdr.usec = g_htonl(phdr->ts.nsecs/1000);
	rec_hdr.caplen = g_htonl(phdr->caplen);
	rec_hdr.length = g_htonl(phdr->len);
	rec_hdr.devid = -1;
	rec_hdr.pid = -1;
	rec_hdr.uid = -1;

	switch (phdr->pkt_encap) {

		case WTAP_ENCAP_NETTL_FDDI:
			/* account for pad bytes */
			rec_hdr.caplen = g_htonl(phdr->caplen + 3);
			rec_hdr.length = g_htonl(phdr->len + 3);
                        /* fall through and fill the rest of the fields */
		case WTAP_ENCAP_NETTL_ETHERNET:
		case WTAP_ENCAP_NETTL_TOKEN_RING:
		case WTAP_ENCAP_NETTL_RAW_IP:
		case WTAP_ENCAP_NETTL_RAW_ICMP:
		case WTAP_ENCAP_NETTL_RAW_ICMPV6:
		case WTAP_ENCAP_NETTL_RAW_TELNET:
		case WTAP_ENCAP_NETTL_UNKNOWN:
			rec_hdr.subsys = g_htons(pseudo_header->nettl.subsys);
			rec_hdr.devid = g_htonl(pseudo_header->nettl.devid);
			rec_hdr.kind = g_htonl(pseudo_header->nettl.kind);
			rec_hdr.pid = g_htonl(pseudo_header->nettl.pid);
			rec_hdr.uid = g_htons(pseudo_header->nettl.uid);
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
			rec_hdr.caplen = g_htonl(phdr->caplen + 3);
			rec_hdr.length = g_htonl(phdr->len + 3);
			break;

		case WTAP_ENCAP_TOKEN_RING:
			rec_hdr.subsys = g_htons(NETTL_SUBSYS_PCI_TR);
			break;
#if 0
		case WTAP_ENCAP_NETTL_X25:
			rec_hdr.caplen = g_htonl(phdr->caplen + 24);
			rec_hdr.length = g_htonl(phdr->len + 24);
			rec_hdr.subsys = g_htons(pseudo_header->nettl.subsys);
			rec_hdr.devid = g_htonl(pseudo_header->nettl.devid);
			rec_hdr.kind = g_htonl(pseudo_header->nettl.kind);
			rec_hdr.pid = g_htonl(pseudo_header->nettl.pid);
			rec_hdr.uid = g_htons(pseudo_header->nettl.uid);
			break;
#endif
		default:
			/* found one we don't support */
			*err = WTAP_ERR_UNSUPPORTED_ENCAP;
			return FALSE;
	}

	if (!wtap_dump_file_write(wdh, &rec_hdr, sizeof(rec_hdr), err))
		return FALSE;
	wdh->bytes_dumped += sizeof(rec_hdr);

	/* Write out 4 extra bytes of unknown stuff for HP-UX11
	 * header format.
	 */
	memset(dummyc, 0, sizeof dummyc);
	if (!wtap_dump_file_write(wdh, dummyc, 4, err))
		return FALSE;
	wdh->bytes_dumped += 4;

	if ((phdr->pkt_encap == WTAP_ENCAP_FDDI_BITSWAPPED) ||
	    (phdr->pkt_encap == WTAP_ENCAP_NETTL_FDDI)) {
		/* add those weird 3 bytes of padding */
		if (!wtap_dump_file_write(wdh, dummyc, 3, err))
			return FALSE;
        	wdh->bytes_dumped += 3;
	}
/*
	} else if (phdr->pkt_encap == WTAP_ENCAP_NETTL_X25) {
		if (!wtap_dump_file_write(wdh, dummyc, 24, err))
			return FALSE;
		wdh->bytes_dumped += 24;
	}
*/

	/* write actual PDU data */

	if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
		return FALSE;
        wdh->bytes_dumped += phdr->caplen;

	return TRUE;
}
