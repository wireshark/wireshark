/* netxray.c
 *
 * $Id: netxray.c,v 1.68 2003/01/07 01:06:58 guy Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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
#include "netxray.h"
#include "buffer.h"

/* Capture file header, *including* magic number, is padded to 128 bytes. */
#define	CAPTUREFILE_HEADER_SIZE	128

/* Magic number in NetXRay 1.x files. */
static const char old_netxray_magic[] = {
	'V', 'L', '\0', '\0'
};

/* Magic number in NetXRay 2.0 and later, and Windows Sniffer, files. */
static const char netxray_magic[] = {	/* magic header */
	'X', 'C', 'P', '\0'
};

/* NetXRay file header (minus magic number). */
struct netxray_hdr {
	char	version[8];	/* version number */
	guint32	start_time;	/* UNIX time when capture started */
	guint32	nframes;	/* number of packets */
	guint32	xxx;		/* unknown */
	guint32	start_offset;	/* offset of first packet in capture */
	guint32	end_offset;	/* offset after last packet in capture */
	guint32 xxy[3];		/* unknown */
	guint16	network;	/* datalink type */
	guint8	xxz[2];		/* XXX - is this the upper 2 bytes of the datalink type? */
	guint8	timeunit;	/* encodes length of a tick */
	guint8	xxa[3];		/* XXX - is this the upper 3 bytes of the time units? */
	guint32	timelo;		/* lower 32 bits of time stamp of capture start */
	guint32	timehi;		/* upper 32 bits of time stamp of capture start */
	guint32 linespeed;	/* speed of network, in bits/second */
	guint8	xxb[64];	/* other stuff */
};

/*
 * # of ticks that equal 1 second
 */
static double TpS[] = { 1e6, 1193000.0, 1193180.0 };
#define NUM_NETXRAY_TIMEUNITS (sizeof TpS / sizeof TpS[0])

/* Version number strings. */
static const char vers_1_0[] = {
	'0', '0', '1', '.', '0', '0', '0', '\0'
};

static const char vers_1_1[] = {
	'0', '0', '1', '.', '1', '0', '0', '\0'
};

static const char vers_2_000[] = {
	'0', '0', '2', '.', '0', '0', '0', '\0'
};

static const char vers_2_001[] = {
	'0', '0', '2', '.', '0', '0', '1', '\0'
};

static const char vers_2_002[] = {
	'0', '0', '2', '.', '0', '0', '2', '\0'
};

/* Old NetXRay data record format - followed by frame data. */
struct old_netxrayrec_hdr {
	guint32	timelo;		/* lower 32 bits of time stamp */
	guint32	timehi;		/* upper 32 bits of time stamp */
	guint16	len;		/* packet length */
	guint8	xxx[6];		/* unknown */
};

/* NetXRay format version 1.x data record format - followed by frame data. */
struct netxrayrec_1_x_hdr {
	guint32	timelo;		/* lower 32 bits of time stamp */
	guint32	timehi;		/* upper 32 bits of time stamp */
	guint16	orig_len;	/* packet length */
	guint16	incl_len;	/* capture length */
	guint8	xxx[16];	/* unknown */
};

/* NetXRay format version 2.x data record format - followed by frame data. */
struct netxrayrec_2_x_hdr {
	guint32	timelo;		/* lower 32 bits of time stamp */
	guint32	timehi;		/* upper 32 bits of time stamp */
	guint16	orig_len;	/* packet length */
	guint16	incl_len;	/* capture length */
	guint8	xxx[28];	/* unknown */
	/* For 802.11 captures, "xxx" data appears to include:
	   the channel, in xxx[12];
	   the data rate, in .5 Mb/s units, in xxx[13];
	   the signal level, as a percentage, in xxx[14];
	   0xff, in xxx[15]. */
};

/*
 * Union of the data record headers.
 */
union netxrayrec_hdr {
	struct old_netxrayrec_hdr old_hdr;
	struct netxrayrec_1_x_hdr hdr_1_x;
	struct netxrayrec_2_x_hdr hdr_2_x;
};

static gboolean netxray_read(wtap *wth, int *err, long *data_offset);
static gboolean netxray_seek_read(wtap *wth, long seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length, int *err);
static int netxray_read_rec_header(wtap *wth, FILE_T fh,
    union netxrayrec_hdr *hdr, int *err);
static void netxray_set_pseudo_header(wtap *wth,
    union wtap_pseudo_header *pseudo_header, union netxrayrec_hdr *hdr);
static gboolean netxray_read_rec_data(FILE_T fh, guint8 *data_ptr,
    guint32 packet_size, int *err);
static void netxray_close(wtap *wth);
static gboolean netxray_dump_1_1(wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const guchar *pd, int *err);
static gboolean netxray_dump_close_1_1(wtap_dumper *wdh, int *err);
static gboolean netxray_dump_2_0(wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const guchar *pd, int *err);
static gboolean netxray_dump_close_2_0(wtap_dumper *wdh, int *err);

int netxray_open(wtap *wth, int *err)
{
	int bytes_read;
	char magic[sizeof netxray_magic];
	gboolean is_old;
	struct netxray_hdr hdr;
	double timeunit;
	int version_major;
	int file_type;
	double t;
	static const int netxray_encap[] = {
		WTAP_ENCAP_ETHERNET,
		WTAP_ENCAP_TOKEN_RING,
		WTAP_ENCAP_FDDI_BITSWAPPED,
		/*
		 * XXX - PPP captures may look like Ethernet, perhaps
		 * because they're using NDIS to capture on the
		 * same machine and it provides simulated-Ethernet
		 * packets, but at least one ISDN capture uses the
		 * same network type value but isn't shaped like
		 * Ethernet.
		 */
		WTAP_ENCAP_ETHERNET,	/* WAN(PPP), but shaped like Ethernet */
		WTAP_ENCAP_UNKNOWN,	/* LocalTalk */
		WTAP_ENCAP_UNKNOWN,	/* "DIX" - should not occur */
		WTAP_ENCAP_UNKNOWN,	/* ARCNET raw */
		WTAP_ENCAP_UNKNOWN,	/* ARCNET 878.2 */
		WTAP_ENCAP_ATM_PDUS_UNTRUNCATED,	/* ATM */
		WTAP_ENCAP_IEEE_802_11_WITH_RADIO,
					/* Wireless WAN with radio information */
		WTAP_ENCAP_UNKNOWN	/* IrDA */
	};
	#define NUM_NETXRAY_ENCAPS (sizeof netxray_encap / sizeof netxray_encap[0])
	int file_encap;
	guint isdn_type = 0;

	/* Read in the string that should be at the start of a NetXRay
	 * file */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(magic, 1, sizeof magic, wth->fh);
	if (bytes_read != sizeof magic) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += sizeof magic;

	if (memcmp(magic, netxray_magic, sizeof magic) == 0) {
		is_old = FALSE;
	} else if (memcmp(magic, old_netxray_magic, sizeof magic) == 0) {
		is_old = TRUE;
	} else {
		return 0;
	}

	/* Read the rest of the header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, 1, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += sizeof hdr;

	if (is_old) {
		timeunit = 1000.0;
		version_major = 0;
		file_type = WTAP_FILE_NETXRAY_OLD;
	} else {
		/* It appears that version 1.1 files (as produced by Windows
		 * Sniffer Pro 2.0.01) have the time stamp in microseconds,
		 * rather than the milliseconds version 1.0 files appear to
		 * have.
		 *
		 * It also appears that version 2.00x files have per-packet
		 * headers with some extra fields. */
		if (memcmp(hdr.version, vers_1_0, sizeof vers_1_0) == 0) {
			timeunit = 1000.0;
			version_major = 1;
			file_type = WTAP_FILE_NETXRAY_1_0;
		} else if (memcmp(hdr.version, vers_1_1, sizeof vers_1_1) == 0) {
			timeunit = 1000000.0;
			version_major = 1;
			file_type = WTAP_FILE_NETXRAY_1_1;
		} else if (memcmp(hdr.version, vers_2_000, sizeof vers_2_000) == 0
		    || memcmp(hdr.version, vers_2_001, sizeof vers_2_001) == 0
		    || memcmp(hdr.version, vers_2_002, sizeof vers_2_002) == 0) {
			if (hdr.timeunit > NUM_NETXRAY_TIMEUNITS) {
				g_message("netxray: Unknown timeunit %u",
					  hdr.timeunit);
				*err = WTAP_ERR_UNSUPPORTED;
				return -1;
			}
			timeunit = TpS[hdr.timeunit];
			version_major = 2;
			file_type = WTAP_FILE_NETXRAY_2_00x;
		} else {
			g_message("netxray: version \"%.8s\" unsupported", hdr.version);
			*err = WTAP_ERR_UNSUPPORTED;
			return -1;
		}
	}

	hdr.network = pletohs(&hdr.network);
	if (hdr.network >= NUM_NETXRAY_ENCAPS
	    || netxray_encap[hdr.network] == WTAP_ENCAP_UNKNOWN) {
		g_message("netxray: network type %u unknown or unsupported",
		    hdr.network);
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		return -1;
	}

	if (hdr.network == 3) {
		/*
		 * In version 0 and 1, we assume, for now, that all
		 * WAN captures have frames that look like Ethernet
		 * frames (as a result, presumably, of having passed
		 * through NDISWAN).
		 *
		 * In version 2, it looks as if there's stuff in the "xxb"
		 * words of the file header to specify what particular
		 * type of WAN capture we have; we handle the ones we've
		 * seen, and punt on the others.
		 */
		if (version_major == 2) {
			switch (hdr.xxb[20]) {

			case 4:
				/*
				 * Frame Relay.
				 */
				file_encap = WTAP_ENCAP_FRELAY;
				break;

			case 6:
				/*
				 * Various HDLC flavors?
				 */
				switch (hdr.xxb[28]) {

				case 0:	/* LAPB/X.25 */
					file_encap = WTAP_ENCAP_LAPB;
					break;

				case 1:	/* E1 PRI */
				case 2:	/* T1 PRI */
				case 3:	/* BRI */
					file_encap = WTAP_ENCAP_ISDN;
					isdn_type = hdr.xxb[28];
					break;

				default:
					g_message("netxray: WAN HDLC capture subsubtype 0x%02x unknown or unsupported",
					   hdr.xxb[28]);
					*err = WTAP_ERR_UNSUPPORTED_ENCAP;
					return -1;
				}
				break;

			default:
				g_message("netxray: WAN capture subtype 0x%02x unknown or unsupported",
				   hdr.xxb[20]);
				*err = WTAP_ERR_UNSUPPORTED_ENCAP;
				return -1;
			}
		} else
			file_encap = WTAP_ENCAP_ETHERNET;
	} else
		file_encap = netxray_encap[hdr.network];

	/* This is a netxray file */
	wth->file_type = file_type;
	wth->capture.netxray = g_malloc(sizeof(netxray_t));
	wth->subtype_read = netxray_read;
	wth->subtype_seek_read = netxray_seek_read;
	wth->subtype_close = netxray_close;
	wth->file_encap = file_encap;
	wth->snapshot_length = 0;	/* not available in header */
	wth->capture.netxray->start_time = pletohl(&hdr.start_time);
	wth->capture.netxray->timeunit = timeunit;
	t = (double)pletohl(&hdr.timelo)
	    + (double)pletohl(&hdr.timehi)*4294967296.0;
	t = t/timeunit;
	wth->capture.netxray->start_timestamp = t;
	wth->capture.netxray->version_major = version_major;

	/*
	 * End-of-packet padding.  802.11 captures appear to have four
	 * bytes of it, as do some ISDN captures.
	 *
	 * We've seen what appears to be an FCS at the end of some frames
	 * in some Ethernet captures, but this stuff appears to be just
	 * padding - Sniffers don't show it, and it doesn't have values
	 * that look like FCS values.  The same applies to those ISDN
	 * captures.
	 *
	 * XXX - but some ISDN captures *don't* have the extra end-of-packet
	 * stuff; how to tell?
	 */
	wth->capture.netxray->padding = 0;
	if (file_encap == WTAP_ENCAP_IEEE_802_11_WITH_RADIO
	    /*|| file_encap == WTAP_ENCAP_ISDN*/)
		wth->capture.netxray->padding = 4;

	/*
	 * Remember the ISDN type, as we need it to interpret the
	 * channel number in ISDN captures.
	 */
	wth->capture.netxray->isdn_type = isdn_type;

	/* Remember the offset after the last packet in the capture (which
	 * isn't necessarily the last packet in the file), as it appears
	 * there's sometimes crud after it. */
	wth->capture.netxray->wrapped = FALSE;
	wth->capture.netxray->end_offset = pletohl(&hdr.end_offset);

	/* Seek to the beginning of the data records. */
	if (file_seek(wth->fh, pletohl(&hdr.start_offset), SEEK_SET, err) == -1) {
		g_free(wth->capture.netxray);
		return -1;
	}
	wth->data_offset = pletohl(&hdr.start_offset);

	return 1;
}

/* Read the next packet */
static gboolean netxray_read(wtap *wth, int *err, long *data_offset)
{
	guint32	packet_size;
	union netxrayrec_hdr hdr;
	int	hdr_size;
	double	t;

reread:
	/* Have we reached the end of the packet data? */
	if (wth->data_offset == wth->capture.netxray->end_offset) {
		/* Yes. */
		*err = 0;	/* it's just an EOF, not an error */
		return FALSE;
	}
	/* Read record header. */
	hdr_size = netxray_read_rec_header(wth, wth->fh, &hdr, err);
	if (hdr_size == 0) {
		/*
		 * Error or EOF.
		 */
		if (*err != 0) {
			/*
			 * Error of some sort; give up.
			 */
			return FALSE;
		}

		/* We're at EOF.  Wrap? */
		if (!wth->capture.netxray->wrapped) {
			/* Yes.  Remember that we did. */
			wth->capture.netxray->wrapped = TRUE;
			if (file_seek(wth->fh, CAPTUREFILE_HEADER_SIZE,
			    SEEK_SET, err) == -1)
				return FALSE;
			wth->data_offset = CAPTUREFILE_HEADER_SIZE;
			goto reread;
		}

		/* We've already wrapped - don't wrap again. */
		return FALSE;
	}

	/*
	 * Return the offset of the record header, so we can reread it
	 * if we go back to this frame.
	 */
	*data_offset = wth->data_offset;
	wth->data_offset += hdr_size;

	/*
	 * Read the packet data.
	 */
	if (wth->capture.netxray->version_major == 0)
		packet_size = pletohs(&hdr.old_hdr.len);
	else
		packet_size = pletohs(&hdr.hdr_1_x.incl_len);
	buffer_assure_space(wth->frame_buffer, packet_size);
	if (!netxray_read_rec_data(wth->fh, buffer_start_ptr(wth->frame_buffer),
	    packet_size, err))
		return FALSE;
	wth->data_offset += packet_size;

	/*
	 * Set the pseudo-header.
	 */
	netxray_set_pseudo_header(wth, &wth->pseudo_header, &hdr);

	if (wth->capture.netxray->version_major == 0) {
		t = (double)pletohl(&hdr.old_hdr.timelo)
		    + (double)pletohl(&hdr.old_hdr.timehi)*4294967296.0;
		t /= wth->capture.netxray->timeunit;
		t -= wth->capture.netxray->start_timestamp;
		wth->phdr.ts.tv_sec = wth->capture.netxray->start_time + (long)t;
		wth->phdr.ts.tv_usec = (unsigned long)((t-(double)(unsigned long)(t))
			*1.0e6);
		/*
		 * We subtract the padding from the packet size, so our caller
		 * doesn't see it.
		 */
		wth->phdr.caplen = packet_size - wth->capture.netxray->padding;
		wth->phdr.len = wth->phdr.caplen;
	} else {
		t = (double)pletohl(&hdr.hdr_1_x.timelo)
		    + (double)pletohl(&hdr.hdr_1_x.timehi)*4294967296.0;
		t /= wth->capture.netxray->timeunit;
		t -= wth->capture.netxray->start_timestamp;
		wth->phdr.ts.tv_sec = wth->capture.netxray->start_time + (long)t;
		wth->phdr.ts.tv_usec = (unsigned long)((t-(double)(unsigned long)(t))
			*1.0e6);
		/*
		 * We subtract the padding from the packet size, so our caller
		 * doesn't see it.
		 */
		wth->phdr.caplen = packet_size - wth->capture.netxray->padding;
		wth->phdr.len = pletohs(&hdr.hdr_1_x.orig_len) - wth->capture.netxray->padding;
	}
	wth->phdr.pkt_encap = wth->file_encap;

	return TRUE;
}

static gboolean
netxray_seek_read(wtap *wth, long seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length, int *err)
{
	union netxrayrec_hdr hdr;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	if (!netxray_read_rec_header(wth, wth->random_fh, &hdr, err)) {
		if (*err == 0) {
			/*
			 * EOF - we report that as a short read, as
			 * we've read this once and know that it
			 * should be there.
			 */
			*err = WTAP_ERR_SHORT_READ;
		}
		return FALSE;
	}

	/*
	 * Set the pseudo-header.
	 */
	netxray_set_pseudo_header(wth, pseudo_header, &hdr);

	/*
	 * Read the packet data.
	 */
	return netxray_read_rec_data(wth->random_fh, pd, length, err);
}

static int
netxray_read_rec_header(wtap *wth, FILE_T fh, union netxrayrec_hdr *hdr,
    int *err)
{
	int	bytes_read;
	int	hdr_size = 0;

	/* Read record header. */
	switch (wth->capture.netxray->version_major) {

	case 0:
		hdr_size = sizeof (struct old_netxrayrec_hdr);
		break;

	case 1:
		hdr_size = sizeof (struct netxrayrec_1_x_hdr);
		break;

	case 2:
		hdr_size = sizeof (struct netxrayrec_2_x_hdr);
		break;
	}
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(hdr, 1, hdr_size, fh);
	if (bytes_read != hdr_size) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return 0;
		if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return 0;
		}

		/*
		 * We're at EOF.  "*err" is 0; we return FALSE - that
		 * combination tells our caller we're at EOF.
		 */
		return 0;
	}
	return hdr_size;
}

static void
netxray_set_pseudo_header(wtap *wth, union wtap_pseudo_header *pseudo_header,
    union netxrayrec_hdr *hdr)
{
	/*
	 * If this is 802.11, ISDN, or ATM, set the pseudo-header.
	 * XXX - what about X.25?
	 */
	if (wth->capture.netxray->version_major == 2) {
		switch (wth->file_encap) {

		case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
			pseudo_header->ieee_802_11.channel =
			    hdr->hdr_2_x.xxx[12];
			pseudo_header->ieee_802_11.data_rate =
			    hdr->hdr_2_x.xxx[13];
			pseudo_header->ieee_802_11.signal_level =
			    hdr->hdr_2_x.xxx[14];
			break;

		case WTAP_ENCAP_ISDN:
			/*
			 * ISDN.
			 * It appears that the high-order bit of byte
			 * 10 is a direction flag, and that the two
			 * low-order bits of byte 13 of "hdr.hdr_2_x.xxx"
			 * indicates whether this is a B-channel (1 or 2)
			 * or a D-channel (0).
			 *
			 * XXX - or is it just a channel number?  Primary
			 * Rate ISDN has more channels; let's assume that
			 * the bottom 5 bits are the channel number, which
			 * is enough for European PRI.  (XXX - maybe the
			 * whole byte is the channel number?)
			 *
			 * XXX - some stuff that Sniffer Pro 4.6 considers
			 * D-channel traffic has a channel number of 16.
			 * Let's call channel numbers 0 and 16 D channels,
			 * channel numbers 1 through 15 B1 through B15,
			 * and channel numbers 17 through 31 B16 through B31.
			 *
			 * XXX - is that direction flag right?
			 */
			pseudo_header->isdn.uton =
			    (hdr->hdr_2_x.xxx[10] & 0x80);
			pseudo_header->isdn.channel =
			    hdr->hdr_2_x.xxx[13] & 0x1F;
			switch (wth->capture.netxray->isdn_type) {

			case 1:
				/*
				 * E1 PRI.  Channel numbers 0 and 16
				 * are the D channel; channel numbers 1
				 * through 15 are B1 through B15; channel
				 * numbers 17 through 31 are B16 through
				 * B31.
				 */
				if (pseudo_header->isdn.channel == 16)
					pseudo_header->isdn.channel = 0;
				else if (pseudo_header->isdn.channel > 16)
					pseudo_header->isdn.channel -= 1;
				break;

			case 2:
				/*
				 * T1 PRI.  Channel numbers 0 and 24
				 * are the D channel; channel numbers 1
				 * through 23 are B1 through B23.
				 */
				if (pseudo_header->isdn.channel == 24)
					pseudo_header->isdn.channel = 0;
				else if (pseudo_header->isdn.channel > 24)
					pseudo_header->isdn.channel -= 1;
				break;
			}
			break;

		case WTAP_ENCAP_ATM_PDUS_UNTRUNCATED:
			pseudo_header->atm.aal = AAL_5;		/* XXX */
			pseudo_header->atm.type = TRAF_LLCMX;	/* XXX */
			pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;	/* XXX */
			pseudo_header->atm.vpi = hdr->hdr_2_x.xxx[11];
			pseudo_header->atm.vci = pletohs(&hdr->hdr_2_x.xxx[12]);
			pseudo_header->atm.channel = 0;		/* XXX */
			pseudo_header->atm.cells = 0;

			if (pseudo_header->atm.vpi == 0) {
				if (pseudo_header->atm.vci == 5)
					pseudo_header->atm.aal = AAL_SIGNALLING;
				else if (pseudo_header->atm.vci == 16)
					pseudo_header->atm.type = TRAF_ILMI;
			}
			break;
		}
	}
}

static gboolean
netxray_read_rec_data(FILE_T fh, guint8 *data_ptr, guint32 packet_size,
    int *err)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(data_ptr, 1, packet_size, fh);

	if (bytes_read <= 0 || (guint32)bytes_read != packet_size) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}

static void
netxray_close(wtap *wth)
{
	g_free(wth->capture.netxray);
}

static const int wtap_encap[] = {
    -1,		/* WTAP_ENCAP_UNKNOWN -> unsupported */
    0,		/* WTAP_ENCAP_ETHERNET -> NDIS Ethernet */
    1,		/* WTAP_ENCAP_TOKEN_RING -> NDIS Token Ring */
    -1,		/* WTAP_ENCAP_SLIP -> unsupported */
    -1,		/* WTAP_ENCAP_PPP -> unsupported */
    2,		/* WTAP_ENCAP_FDDI -> NDIS FDDI */
    2,		/* WTAP_ENCAP_FDDI_BITSWAPPED -> NDIS FDDI */
    -1,		/* WTAP_ENCAP_RAW_IP -> unsupported */
    -1,		/* WTAP_ENCAP_ARCNET -> unsupported */
    -1,		/* WTAP_ENCAP_ATM_RFC1483 -> unsupported */
    -1,		/* WTAP_ENCAP_LINUX_ATM_CLIP -> unsupported */
    -1,		/* WTAP_ENCAP_LAPB -> unsupported */
    -1,		/* WTAP_ENCAP_ATM_PDUS_UNTRUNCATED -> unsupported */
    -1		/* WTAP_ENCAP_NULL -> unsupported */
};
#define NUM_WTAP_ENCAPS (sizeof wtap_encap / sizeof wtap_encap[0])

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int netxray_dump_can_write_encap(int encap)
{
    /* Per-packet encapsulations aren't supported. */
    if (encap == WTAP_ENCAP_PER_PACKET)
	return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    if (encap < 0 || (unsigned)encap >= NUM_WTAP_ENCAPS || wtap_encap[encap] == -1)
	return WTAP_ERR_UNSUPPORTED_ENCAP;

    return 0;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean netxray_dump_open_1_1(wtap_dumper *wdh, gboolean cant_seek, int *err)
{
    /* This is a NetXRay file.  We can't fill in some fields in the header
       until all the packets have been written, so we can't write to a
       pipe. */
    if (cant_seek) {
	*err = WTAP_ERR_CANT_WRITE_TO_PIPE;
	return FALSE;
    }

    wdh->subtype_write = netxray_dump_1_1;
    wdh->subtype_close = netxray_dump_close_1_1;

    /* We can't fill in all the fields in the file header, as we
       haven't yet written any packets.  As we'll have to rewrite
       the header when we've written out all the packets, we just
       skip over the header for now. */
    if (fseek(wdh->fh, CAPTUREFILE_HEADER_SIZE, SEEK_SET) == -1) {
	*err = errno;
	return FALSE;
    }

    wdh->dump.netxray = g_malloc(sizeof(netxray_dump_t));
    wdh->dump.netxray->first_frame = TRUE;
    wdh->dump.netxray->start.tv_sec = 0;
    wdh->dump.netxray->start.tv_usec = 0;
    wdh->dump.netxray->nframes = 0;

    return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean netxray_dump_1_1(wtap_dumper *wdh,
	const struct wtap_pkthdr *phdr,
	const union wtap_pseudo_header *pseudo_header _U_,
	const guchar *pd, int *err)
{
    netxray_dump_t *netxray = wdh->dump.netxray;
    guint32 timestamp;
    struct netxrayrec_1_x_hdr rec_hdr;
    size_t nwritten;

    /* NetXRay/Windows Sniffer files have a capture start date/time
       in the header, in a UNIX-style format, with one-second resolution,
       and a start time stamp with microsecond resolution that's just
       an arbitrary time stamp relative to some unknown time (boot
       time?), and have times relative to the start time stamp in
       the packet headers; pick the seconds value of the time stamp
       of the first packet as the UNIX-style start date/time, and make
       the high-resolution start time stamp 0, with the time stamp of
       packets being the delta between the stamp of the packet and
       the stamp of the first packet with the microseconds part 0. */
    if (netxray->first_frame) {
	netxray->first_frame = FALSE;
	netxray->start = phdr->ts;
    }

    /* build the header for each packet */
    memset(&rec_hdr, '\0', sizeof(rec_hdr));
    timestamp = (phdr->ts.tv_sec - netxray->start.tv_sec)*1000000 +
        phdr->ts.tv_usec;
    rec_hdr.timelo = htolel(timestamp);
    rec_hdr.timehi = htolel(0);
    rec_hdr.orig_len = htoles(phdr->len);
    rec_hdr.incl_len = htoles(phdr->caplen);

    nwritten = fwrite(&rec_hdr, 1, sizeof(rec_hdr), wdh->fh);
    if (nwritten != sizeof(rec_hdr)) {
	if (nwritten == 0 && ferror(wdh->fh))
	    *err = errno;
	else
	    *err = WTAP_ERR_SHORT_WRITE;
	return FALSE;
    }

    /* write the packet data */
    nwritten = fwrite(pd, 1, phdr->caplen, wdh->fh);
    if (nwritten != phdr->caplen) {
	if (nwritten == 0 && ferror(wdh->fh))
	    *err = errno;
	else
	    *err = WTAP_ERR_SHORT_WRITE;
	return FALSE;
    }

    netxray->nframes++;

    return TRUE;
}

/* Finish writing to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean netxray_dump_close_1_1(wtap_dumper *wdh, int *err)
{
    char hdr_buf[CAPTUREFILE_HEADER_SIZE - sizeof(netxray_magic)];
    netxray_dump_t *netxray = wdh->dump.netxray;
    guint32 filelen;
    struct netxray_hdr file_hdr;
    size_t nwritten;

    filelen = ftell(wdh->fh);

    /* Go back to beginning */
    fseek(wdh->fh, 0, SEEK_SET);

    /* Rewrite the file header. */
    nwritten = fwrite(netxray_magic, 1, sizeof netxray_magic, wdh->fh);
    if (nwritten != sizeof netxray_magic) {
	if (err != NULL) {
	    if (nwritten == 0 && ferror(wdh->fh))
		*err = errno;
	    else
		*err = WTAP_ERR_SHORT_WRITE;
	}
	return FALSE;
    }

    /* "sniffer" version ? */
    memset(&file_hdr, '\0', sizeof file_hdr);
    memcpy(file_hdr.version, vers_1_1, sizeof vers_1_1);
    file_hdr.start_time = htolel(netxray->start.tv_sec);
    file_hdr.nframes = htolel(netxray->nframes);
    file_hdr.start_offset = htolel(CAPTUREFILE_HEADER_SIZE);
    file_hdr.end_offset = htolel(filelen);
    file_hdr.network = htoles(wtap_encap[wdh->encap]);
    file_hdr.timelo = htolel(0);
    file_hdr.timehi = htolel(0);

    memset(hdr_buf, '\0', sizeof hdr_buf);
    memcpy(hdr_buf, &file_hdr, sizeof(file_hdr));
    nwritten = fwrite(hdr_buf, 1, sizeof hdr_buf, wdh->fh);
    if (nwritten != sizeof hdr_buf) {
	if (err != NULL) {
	    if (nwritten == 0 && ferror(wdh->fh))
		*err = errno;
	    else
		*err = WTAP_ERR_SHORT_WRITE;
	}
	return FALSE;
    }

    return TRUE;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean netxray_dump_open_2_0(wtap_dumper *wdh, gboolean cant_seek, int *err)
{
    /* This is a NetXRay file.  We can't fill in some fields in the header
       until all the packets have been written, so we can't write to a
       pipe. */
    if (cant_seek) {
	*err = WTAP_ERR_CANT_WRITE_TO_PIPE;
	return FALSE;
    }

    wdh->subtype_write = netxray_dump_2_0;
    wdh->subtype_close = netxray_dump_close_2_0;

    /* We can't fill in all the fields in the file header, as we
       haven't yet written any packets.  As we'll have to rewrite
       the header when we've written out all the packets, we just
       skip over the header for now. */
    if (fseek(wdh->fh, CAPTUREFILE_HEADER_SIZE, SEEK_SET) == -1) {
	*err = errno;
	return FALSE;
    }

    wdh->dump.netxray = g_malloc(sizeof(netxray_dump_t));
    wdh->dump.netxray->first_frame = TRUE;
    wdh->dump.netxray->start.tv_sec = 0;
    wdh->dump.netxray->start.tv_usec = 0;
    wdh->dump.netxray->nframes = 0;

    return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean netxray_dump_2_0(wtap_dumper *wdh,
	const struct wtap_pkthdr *phdr,
	const union wtap_pseudo_header *pseudo_header _U_,
	const guchar *pd, int *err)
{
    netxray_dump_t *netxray = wdh->dump.netxray;
    guint32 timestamp;
    struct netxrayrec_2_x_hdr rec_hdr;
    size_t nwritten;

    /* NetXRay/Windows Sniffer files have a capture start date/time
       in the header, in a UNIX-style format, with one-second resolution,
       and a start time stamp with microsecond resolution that's just
       an arbitrary time stamp relative to some unknown time (boot
       time?), and have times relative to the start time stamp in
       the packet headers; pick the seconds value of the time stamp
       of the first packet as the UNIX-style start date/time, and make
       the high-resolution start time stamp 0, with the time stamp of
       packets being the delta between the stamp of the packet and
       the stamp of the first packet with the microseconds part 0. */
    if (netxray->first_frame) {
	netxray->first_frame = FALSE;
	netxray->start = phdr->ts;
    }

    /* build the header for each packet */
    memset(&rec_hdr, '\0', sizeof(rec_hdr));
    timestamp = (phdr->ts.tv_sec - netxray->start.tv_sec)*1000000 +
        phdr->ts.tv_usec;
    rec_hdr.timelo = htolel(timestamp);
    rec_hdr.timehi = htolel(0);
    rec_hdr.orig_len = htoles(phdr->len);
    rec_hdr.incl_len = htoles(phdr->caplen);

    if (phdr->pkt_encap == WTAP_ENCAP_IEEE_802_11_WITH_RADIO)
    {
        rec_hdr.xxx[12] = pseudo_header->ieee_802_11.channel;
        rec_hdr.xxx[13] = pseudo_header->ieee_802_11.data_rate;
        rec_hdr.xxx[14] = pseudo_header->ieee_802_11.signal_level;
    }

    nwritten = fwrite(&rec_hdr, 1, sizeof(rec_hdr), wdh->fh);
    if (nwritten != sizeof(rec_hdr)) {
	if (nwritten == 0 && ferror(wdh->fh))
	    *err = errno;
	else
	    *err = WTAP_ERR_SHORT_WRITE;
	return FALSE;
    }

    /* write the packet data */
    nwritten = fwrite(pd, 1, phdr->caplen, wdh->fh);
    if (nwritten != phdr->caplen) {
	if (nwritten == 0 && ferror(wdh->fh))
	    *err = errno;
	else
	    *err = WTAP_ERR_SHORT_WRITE;
	return FALSE;
    }

    netxray->nframes++;

    return TRUE;
}

/* Finish writing to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean netxray_dump_close_2_0(wtap_dumper *wdh, int *err)
{
    char hdr_buf[CAPTUREFILE_HEADER_SIZE - sizeof(netxray_magic)];
    netxray_dump_t *netxray = wdh->dump.netxray;
    guint32 filelen;
    struct netxray_hdr file_hdr;
    size_t nwritten;

    filelen = ftell(wdh->fh);

    /* Go back to beginning */
    fseek(wdh->fh, 0, SEEK_SET);

    /* Rewrite the file header. */
    nwritten = fwrite(netxray_magic, 1, sizeof netxray_magic, wdh->fh);
    if (nwritten != sizeof netxray_magic) {
	if (err != NULL) {
	    if (nwritten == 0 && ferror(wdh->fh))
		*err = errno;
	    else
		*err = WTAP_ERR_SHORT_WRITE;
	}
	return FALSE;
    }

    /* "sniffer" version ? */
    memset(&file_hdr, '\0', sizeof file_hdr);
    memcpy(file_hdr.version, vers_2_001, sizeof vers_2_001);
    file_hdr.start_time = htolel(netxray->start.tv_sec);
    file_hdr.nframes = htolel(netxray->nframes);
    file_hdr.start_offset = htolel(CAPTUREFILE_HEADER_SIZE);
    file_hdr.end_offset = htolel(filelen);
    file_hdr.network = htoles(wtap_encap[wdh->encap]);
    file_hdr.timelo = htolel(0);
    file_hdr.timehi = htolel(0);

    memset(hdr_buf, '\0', sizeof hdr_buf);
    memcpy(hdr_buf, &file_hdr, sizeof(file_hdr));
    nwritten = fwrite(hdr_buf, 1, sizeof hdr_buf, wdh->fh);
    if (nwritten != sizeof hdr_buf) {
	if (err != NULL) {
	    if (nwritten == 0 && ferror(wdh->fh))
		*err = errno;
	    else
		*err = WTAP_ERR_SHORT_WRITE;
	}
	return FALSE;
    }

    return TRUE;
}
