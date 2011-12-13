/* visual.c
 * File read and write routines for Visual Networks cap files.
 * Copyright (c) 2001, Tom Nisbet  tnisbet@visualnetworks.com
 *
 * $Id$
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
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "visual.h"

/*
 * A Visual Networks traffic capture file contains three sections. The
 * first is a 192 octet file header.  This is followed by the captured
 * packet header, and for ATM captures, there is an additional atm packet header.
 * The data follows the packet header. The last section is the packet index block.
 * The index block contains one 4 octet pointer for each captured packet.
 * The first packet index is (4 * num_pkts) octets from the end of the file
 * and the last index is in the last four octets of the file.
 *
 * All integer and time values are stored in little-endian format, except for 
 *  the ATM Packet Header, which is stored in network byte order.
 *
 * [ File Header ] 
 * 
 *
 * [ Packet Header 1 ] [(opt) ATM Packet Header] [ Data ]
 * ...
 * [ Packet Header n ] [(opt) ATM Packet Header] [ Data ]
 *
 *
 * [ Index Block 1 ] ... [ Index Block n ]
 */

/* Capture file header, INCLUDING the magic number, is 192 bytes. */
#define CAPTUREFILE_HEADER_SIZE 192

/* Magic number for Visual Networks traffic capture files. */
static const char visual_magic[] = {
    5, 'V', 'N', 'F'
};


/* Visual File Header (minus magic number). */
/* This structure is used to extract information */
struct visual_file_hdr
{
    guint32 num_pkts;           /* Number of packets in the file */
    guint32 start_time;         /* Capture start time in PC format */
    guint16 media_type;         /* IANA ifType of packet source */
    guint16 max_length;         /* Max allowable stored packet length */
    guint16 file_flags;         /* File type flags */
                                /*   Bit 0 indicates indexes present */
    guint16 file_version;       /* Version number of this file format */
    guint32 media_speed;        /* ifSpeed of packet source in bits/sec. */
    guint16 media_param;        /* Media-specific extra parameter. */
    char    RESERVED_[102];     /* MUST BE ALL ZEROS FOR FUTURE COMPATABILITY */
    char    description[64];    /* File description (null terminated) */
};


/* Packet status bits */
#define PS_LONG             0x01
#define PS_SHORT            0x02
#define PS_ERRORED          0x04
#define PS_1ST_AFTER_DROP   0x08
#define PS_APPROX_ORDER     0x10
#define PS_SENT             0x40
#define PS_ABORTED          0x80

/* Visual Packet Header */
/* This structure is used to extract information */
struct visual_pkt_hdr
{
    guint32 ts_delta;           /* Time stamp - msecs since start of capture */
    guint16 orig_len;           /* Actual length of packet */
    guint16 incl_len;           /* Number of octets captured in file */
    guint32 status;             /* Packet status flags (media specific) */
    guint8  encap_hint;         /* Encapsulation type hint */
    guint8  encap_skip;         /* Number of bytes to skip before decoding */
    char    RESERVED_[6];       /* RESERVED - must be zero */
};

/* Optional Visual ATM Packet Header */
/* This structure is used to extract information */
struct visual_atm_hdr
{
   guint16 vpi;           /* 4 bits of zeros; 12 bits of ATM VPI */ 
   guint16 vci;           /* ATM VCI */
   guint8  info;          /* 4 bits version; 3 bits unused-zero; 1 bit direction */
   guint8  category;      /* indicates type of traffic. 4 bits of status + 4 bits of type */
   guint16 cell_count;    /* number of cells that make up this pdu */
   guint32 data_length;   /* PDU data length for AAL-5 PDUs, all others - cellcount * 48 */
   guint32 ts_secs;       /* seonds value of sysUpTime when the last cell of this PDU was captured */
   guint32 ts_nsec;       /* nanoseonds value of sysUpTime when the last cell of this PDU was captured */

};

/* visual_atm_hdr info bit definitions */
#define FROM_NETWORK       0x01
#define ATM_VER_MASK       0xf0  /* Not currently displayed */

/* visual_atm_hdr category definitions */
/* High nibble - not currently displayed */
#define VN_INCOMPLETE      0x40
#define VN_BAD_CRC         0x80
#define VN_CAT_STAT_MASK   0xf0
/* Low nibble */
#define VN_UNKNOWN         0x00
#define VN_AAL1            0x01
#define VN_AAL2            0x02
#define VN_AAL34           0x03
#define VN_O191            0x04
#define VN_AAL5            0x05
#define VN_OAM             0x0a
#define VN_RM              0x0b
#define VN_IDLE            0x0c
#define VN_CAT_TYPE_MASK   0x0f


/* Additional information for reading Visual files */
struct visual_read_info
{
    guint32 num_pkts;           /* Number of pkts in the file */
    guint32 current_pkt;        /* Next packet to be read */
    double  start_time;         /* Capture start time in microseconds */
};


/* Additional information for writing Visual files */
struct visual_write_info
{
    unsigned start_time;        /* Capture start time in seconds */
    int     index_table_index;  /* Index of the next index entry */
    int     index_table_size;   /* Allocated size of the index table */
    guint32 * index_table;      /* File offsets for the packets */
    guint32 next_offset;        /* Offset of next packet */
};


/* Local functions to handle file reads and writes */
static gboolean visual_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean visual_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int packet_size,
    int *err, gchar **err_info);
static void visual_set_pseudo_header(int encap, struct visual_pkt_hdr *vpkt_hdr,
    struct visual_atm_hdr *vatm_hdr, union wtap_pseudo_header *pseudo_header);
static gboolean visual_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const guint8 *pd, int *err);
static gboolean visual_dump_close(wtap_dumper *wdh, int *err);
static void visual_dump_free(wtap_dumper *wdh);


/* Open a file for reading */
int visual_open(wtap *wth, int *err, gchar **err_info)
{
    int bytes_read;
    char magic[sizeof visual_magic];
    struct visual_file_hdr vfile_hdr;
    struct visual_read_info * visual;
    int encap;

    /* Check the magic string at the start of the file */
    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(magic, sizeof magic, wth->fh);
    if (bytes_read != sizeof magic)
    {
        *err = file_error(wth->fh, err_info);
        if (*err != 0)
            return -1;
        return 0;
    }
    if (memcmp(magic, visual_magic, sizeof visual_magic) != 0)
    {
        return 0;
    }

    /* Read the rest of the file header. */
    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(&vfile_hdr, sizeof vfile_hdr, wth->fh);
    if (bytes_read != sizeof vfile_hdr)
    {
        *err = file_error(wth->fh, err_info);
        if (*err != 0)
            return -1;
        return 0;
    }

    /* Verify the file version is known */
    vfile_hdr.file_version = pletohs(&vfile_hdr.file_version);
    if (vfile_hdr.file_version != 1)
    {
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = g_strdup_printf("visual: file version %u unsupported", vfile_hdr.file_version);
        return -1;
    }

    /* Translate the encapsulation type; these values are SNMP ifType
       values, as found in http://www.iana.org/assignments/smi-numbers.

       Note that a file with media type 22 ("propPointToPointSerial") may
       contain Cisco HDLC or PPP over HDLC.  This will get sorted out after
       the first packet is read.

       XXX - should we use WTAP_ENCAP_PER_PACKET for that? */
    switch (pletohs(&vfile_hdr.media_type))
    {
    case  6:	/* ethernet-csmacd */
        encap = WTAP_ENCAP_ETHERNET;
        break;

    case  9:	/* IEEE802.5 */
        encap = WTAP_ENCAP_TOKEN_RING;
        break;

    case 16:	/* lapb */
        encap = WTAP_ENCAP_LAPB;
        break;

    case 22:	/* propPointToPointSerial */
    case 118:	/* HDLC */
        encap = WTAP_ENCAP_CHDLC_WITH_PHDR;
        break;

    case 32:	/* frame-relay */
        encap = WTAP_ENCAP_FRELAY_WITH_PHDR;
        break;

    case 37:	/* ATM */
       encap = WTAP_ENCAP_ATM_PDUS;
       break;

    default:
        *err = WTAP_ERR_UNSUPPORTED_ENCAP;
        *err_info = g_strdup_printf("visual: network type %u unknown or unsupported",
                                     vfile_hdr.media_type);
        return -1;
    }

    /* Fill in the wiretap struct with data from the file header */
    wth->file_type = WTAP_FILE_VISUAL_NETWORKS;
    wth->file_encap = encap;
    wth->snapshot_length = pletohs(&vfile_hdr.max_length);

    /* Save the pointer to the beginning of the packet data so
       that the later seek_reads work correctly. */
    wth->data_offset = CAPTUREFILE_HEADER_SIZE;

    /* Set up the pointers to the handlers for this file type */
    wth->subtype_read = visual_read;
    wth->subtype_seek_read = visual_seek_read;
    wth->tsprecision = WTAP_FILE_TSPREC_USEC;

    /* Add Visual-specific information to the wiretap struct for later use. */
    visual = (struct visual_read_info *)g_malloc(sizeof(struct visual_read_info));
    wth->priv = (void *)visual;
    visual->num_pkts = pletohl(&vfile_hdr.num_pkts);
    visual->start_time = ((double) pletohl(&vfile_hdr.start_time)) * 1000000;
    visual->current_pkt = 1;

    return 1;
}


/* Read the next available packet from the file.  This is called
   in a loop to sequentially read the entire file one time.  After
   the file has been read once, any Future access to the packets is
   done through seek_read. */
static gboolean visual_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
    struct visual_read_info *visual = (struct visual_read_info *)wth->priv;
    guint32 packet_size = 0;
    int bytes_read;
    struct visual_pkt_hdr vpkt_hdr;
    struct visual_atm_hdr vatm_hdr;
    int phdr_size = sizeof(vpkt_hdr);
    int ahdr_size = sizeof(vatm_hdr);
    time_t  secs;
    guint32 usecs;
    double  t;

    /* Check for the end of the packet data.  Note that a check for file EOF
       will not work because there are index values stored after the last
       packet's data. */
    if (visual->current_pkt > visual->num_pkts)
    {
        *err = 0;   /* it's just an EOF, not an error */
        return FALSE;
    }
    visual->current_pkt++;

    /* Read the packet header. */
    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(&vpkt_hdr, phdr_size, wth->fh);
    if (bytes_read != phdr_size)
    {
        *err = file_error(wth->fh, err_info);
        if (*err == 0 && bytes_read != 0)
        {
            *err = WTAP_ERR_SHORT_READ;
        }
        return FALSE;
    }
    wth->data_offset += phdr_size;

    /* Get the included length of data. This includes extra headers + payload */
    packet_size = pletohs(&vpkt_hdr.incl_len);

    /* Check for additional ATM packet header */
    if (wth->file_encap == WTAP_ENCAP_ATM_PDUS)
    {
       /* Read the atm packet header. */
       errno = WTAP_ERR_CANT_READ;
       bytes_read = file_read(&vatm_hdr, ahdr_size, wth->fh);
       if (bytes_read != ahdr_size)
       {
           *err = file_error(wth->fh, err_info);
           if (*err == 0 && bytes_read != 0)
           {
               *err = WTAP_ERR_SHORT_READ;
           }
           return FALSE;
       }
       wth->data_offset += ahdr_size;
       
       /* Remove ATM header from length of included bytes in capture, as 
          this header was appended by the processor doing the packet reassembly,
          and was not transmitted across the wire */
       packet_size -= ahdr_size;
    }

    /* Read the packet data. */
    if (packet_size > WTAP_MAX_PACKET_SIZE)
    {
        /* Probably a corrupt capture file; don't blow up trying
          to allocate space for an immensely-large packet. */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("visual: File has %u-byte packet, bigger than maximum of %u",
            packet_size, WTAP_MAX_PACKET_SIZE);
        return FALSE;
    }
    buffer_assure_space(wth->frame_buffer, packet_size);
    *data_offset = wth->data_offset;
    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(buffer_start_ptr(wth->frame_buffer),
            packet_size, wth->fh);

    if (bytes_read != (int) packet_size)
    {
        *err = file_error(wth->fh, err_info);
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return FALSE;
    }
    wth->data_offset += packet_size;

    /* Set the packet time and length. */
    t = visual->start_time;
    t += ((double)pletohl(&vpkt_hdr.ts_delta))*1000;
    secs = (time_t)(t/1000000);
    usecs = (guint32)(t - secs*1000000);
    wth->phdr.ts.secs = secs;
    wth->phdr.ts.nsecs = usecs * 1000;
    
    /* Most visual capture types include FCS checks in the original length value, but
    * but don't include the FCS as part of the payload or captured length. 
    * This causes the RTP audio payload save to fail since then captured len != orig len.
    * Adjusting the original length to remove the FCS bytes we counted based
    * on the file encapsualtion type.
    *
    * Only downside to this fix is throughput calculations will be slightly lower
    * as they won't include the FCS bytes.
    */

    wth->phdr.caplen = packet_size;
    wth->phdr.len = pletohs(&vpkt_hdr.orig_len);

    switch (wth->file_encap)
    {
    case WTAP_ENCAP_ETHERNET:
       wth->phdr.len -= 4;
       break;
    
    case WTAP_ENCAP_FRELAY_WITH_PHDR:
    case WTAP_ENCAP_CHDLC_WITH_PHDR:
    case WTAP_ENCAP_LAPB:
       wth->phdr.len -= 2;
       break;

    /* ATM original length doesn't include any FCS. Do nothing. */
    case WTAP_ENCAP_ATM_PDUS:
    /* Not sure about token ring. Just leaving alone for now. */
    case WTAP_ENCAP_TOKEN_RING:
    default:
       break;
    }

    if (wth->phdr.len > WTAP_MAX_PACKET_SIZE) {
    /* Check if wth->phdr.len is sane, small values of wth.phdr.len before
       the case loop above can cause integer underflows */ 
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("visual: File has %u-byte original packet, bigger than maximum of %u",
                    wth->phdr.len, WTAP_MAX_PACKET_SIZE);
        return FALSE;
    }

    /* Sanity check */
    if (wth->phdr.len < wth->phdr.caplen)
    {
       wth->phdr.len = wth->phdr.caplen;
    }

    /* Set the pseudo_header. */
    visual_set_pseudo_header(wth->file_encap, &vpkt_hdr, &vatm_hdr, &wth->pseudo_header);

    /* Fill in the encapsulation.  Visual files have a media type in the
       file header and an encapsulation type in each packet header.  Files
       with a media type of HDLC can be either Cisco EtherType or PPP.

       The encapsulation hint values we've seen are:

         2 - seen in an Ethernet capture
         13 - seen in a PPP capture; possibly also seen in Cisco HDLC
              captures
         14 - seen in a PPP capture; probably seen only for PPP */
    if (wth->file_encap == WTAP_ENCAP_CHDLC_WITH_PHDR)
    {
        /* If PPP is specified in the encap hint, then use that */
        if (vpkt_hdr.encap_hint == 14)
        {
              /* But first we need to examine the first three octets to
               try to determine the proper encapsulation, see RFC 2364. */
            guint8 *buf = buffer_start_ptr(wth->frame_buffer);
            if ((0xfe == buf[0]) && (0xfe == buf[1]) && (0x03 == buf[2]))
            {
                /* It is actually LLC encapsulated PPP */
                wth->phdr.pkt_encap = WTAP_ENCAP_ATM_RFC1483;
            }
            else
            {
                /* It is actually PPP */
                wth->phdr.pkt_encap = WTAP_ENCAP_PPP_WITH_PHDR;
            }
        }
        else
        {
            /* Otherwise, we need to examine the first two octets to
               try to determine the encapsulation. */
            guint8 *buf = buffer_start_ptr(wth->frame_buffer);
            if ((0xff == buf[0]) && (0x03 == buf[1]))
            {
                /* It is actually PPP */
                wth->phdr.pkt_encap = WTAP_ENCAP_PPP_WITH_PHDR;
            }
        }
    }
    return TRUE;
}

/* Read packet data for random access.
   This gets the packet data and rebuilds the pseudo header so that
   the direction flag works. */
static gboolean visual_seek_read (wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int len,
    int *err, gchar **err_info)
{
    struct visual_pkt_hdr vpkt_hdr;
    struct visual_atm_hdr vatm_hdr;
    int phdr_size = sizeof(vpkt_hdr);
    int ahdr_size = sizeof(vatm_hdr);
    int bytes_read;
    int header_size;

    /* Get the size of the visual packet header to skip */
    header_size = sizeof(struct visual_pkt_hdr);

    /* If ATM capture, need to skip over visual ATM packet header too */
    if (wth->file_encap == WTAP_ENCAP_ATM_PDUS)
    {
       header_size += (int)sizeof(struct visual_atm_hdr);
    }
    
    /* Seek to the packet header */
    if (file_seek(wth->random_fh, seek_off - header_size,
                  SEEK_SET, err) == -1)
        return FALSE;

    /* Read the packet header to get the status flags. */
    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(&vpkt_hdr, phdr_size, wth->random_fh);
    if (bytes_read != phdr_size) {
    	*err = file_error(wth->random_fh, err_info);
    	if (*err == 0)
    	    *err = WTAP_ERR_SHORT_READ;
        return FALSE;
    }
    
    /* Check for additional ATM packet header */
    if (wth->file_encap == WTAP_ENCAP_ATM_PDUS)
    {
       /* Read the atm packet header */
       errno = WTAP_ERR_CANT_READ;
       bytes_read = file_read(&vatm_hdr, ahdr_size, wth->random_fh);
       if (bytes_read != ahdr_size)
       {
           *err = file_error(wth->fh, err_info);
           if (*err == 0 && bytes_read != 0)
           {
               *err = WTAP_ERR_SHORT_READ;
           }
           return FALSE;
       }
    }

    /* Read the packet data. */
    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(pd, len, wth->random_fh);
    if (bytes_read != len) {
    	if (*err == 0)
    	    *err = WTAP_ERR_SHORT_READ;
        return FALSE;
    }

    /* Set the pseudo_header. */
    visual_set_pseudo_header(wth->file_encap, &vpkt_hdr, &vatm_hdr, pseudo_header);

    return TRUE;
}

static void visual_set_pseudo_header(int encap, struct visual_pkt_hdr *vpkt_hdr,
    struct visual_atm_hdr *vatm_hdr, union wtap_pseudo_header *pseudo_header)
{
    guint32 packet_status;

    /* Set status flags.  The only status currently supported for all
       encapsulations is direction.  This either goes in the p2p or the
       X.25 pseudo header.  It would probably be better to move this up
       into the phdr. */
    packet_status = pletohl(&vpkt_hdr->status);
    switch (encap)
    {
    case WTAP_ENCAP_ETHERNET:
        /* XXX - is there an FCS in the frame? */
        pseudo_header->eth.fcs_len = -1;
        break;

    case WTAP_ENCAP_CHDLC_WITH_PHDR:
    case WTAP_ENCAP_PPP_WITH_PHDR:
        pseudo_header->p2p.sent = (packet_status & PS_SENT) ? TRUE : FALSE;
        break;

    case WTAP_ENCAP_FRELAY_WITH_PHDR:
    case WTAP_ENCAP_LAPB:
        pseudo_header->x25.flags =
            (packet_status & PS_SENT) ? 0x00 : FROM_DCE;
        break;

    case WTAP_ENCAP_ATM_PDUS:
       /* Set defaults */
       pseudo_header->atm.type = TRAF_UNKNOWN;
       pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
       pseudo_header->atm.aal5t_len = 0;

       /* Next two items not supported. Defaulting to zero */
       pseudo_header->atm.aal5t_u2u = 0;
       pseudo_header->atm.aal5t_chksum = 0;
       
       /* Flags appear only to convey that packet is a raw cell. Set to 0 */
       pseudo_header->atm.flags = 0; 
       
       /* Not supported. Defaulting to zero */
       pseudo_header->atm.aal2_cid = 0;

       switch(vatm_hdr->category & VN_CAT_TYPE_MASK )
       {
       case VN_AAL1:
          pseudo_header->atm.aal = AAL_1;
          break;

       case VN_AAL2:
          pseudo_header->atm.aal = AAL_2;
          break;
       
       case VN_AAL34:
          pseudo_header->atm.aal = AAL_3_4;
          break;
       
       case VN_AAL5:
          pseudo_header->atm.aal = AAL_5;
          pseudo_header->atm.type = TRAF_LLCMX;
          pseudo_header->atm.aal5t_len = pntohl(&vatm_hdr->data_length);
          break;
       
       case VN_OAM:
       /* Marking next 3 as OAM versus unknown */
       case VN_O191:
       case VN_IDLE:
       case VN_RM:
          pseudo_header->atm.aal = AAL_OAMCELL;
          break;

       case VN_UNKNOWN:
       default:
          pseudo_header->atm.aal = AAL_UNKNOWN;
          break;

       }
       pseudo_header->atm.vpi = pntohs(&vatm_hdr->vpi) & 0x0FFF;
       pseudo_header->atm.vci = pntohs(&vatm_hdr->vci);
       pseudo_header->atm.cells = pntohs(&vatm_hdr->cell_count);
       
       /* Using bit value of 1 (DCE -> DTE) to indicate From Network */
       pseudo_header->atm.channel = vatm_hdr->info & FROM_NETWORK;
       
       break;
    }
}

/* Check for media types that may be written in Visual file format.
   Returns 0 if the specified encapsulation type is supported,
   an error indication otherwise. */
int visual_dump_can_write_encap(int encap)
{
    /* Per-packet encapsulations aren't supported. */
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    /* Check for supported encapsulation types */
    switch (encap)
    {
    case WTAP_ENCAP_ETHERNET:
    case WTAP_ENCAP_TOKEN_RING:
    case WTAP_ENCAP_LAPB:
    case WTAP_ENCAP_CHDLC_WITH_PHDR:
    case WTAP_ENCAP_FRELAY_WITH_PHDR:
    case WTAP_ENCAP_PPP:
    case WTAP_ENCAP_PPP_WITH_PHDR:
        return 0;
    }

    return WTAP_ERR_UNSUPPORTED_ENCAP;
}


/* Open a file for writing.
   Returns TRUE on success, FALSE on failure; sets "*err" to an
   error code on failure */
gboolean visual_dump_open(wtap_dumper *wdh, int *err)
{
    struct visual_write_info *visual;

    /* Set the write routines for a visual file. */
    wdh->subtype_write = visual_dump;
    wdh->subtype_close = visual_dump_close;

    /* Create a struct to hold file information for the duration
       of the write */
    visual = (struct visual_write_info *)g_malloc(sizeof(struct visual_write_info));
    wdh->priv = (void *)visual;
    visual->index_table_index = 0;
    visual->index_table_size = 1024;
    visual->index_table = 0;
    visual->next_offset = CAPTUREFILE_HEADER_SIZE;

    /* All of the fields in the file header aren't known yet so
       just skip over it for now.  It will be created after all
       of the packets have been written. */
    if (fseek(wdh->fh, CAPTUREFILE_HEADER_SIZE, SEEK_SET) == -1) {
	*err = errno;
	return FALSE;
    }

    return TRUE;
}


/* Write a packet to a Visual dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean visual_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const guint8 *pd, int *err)
{
    struct visual_write_info * visual = wdh->priv;
    struct visual_pkt_hdr vpkt_hdr;
    size_t hdr_size = sizeof vpkt_hdr;
    unsigned delta_msec;
    guint32 packet_status;

    /* If the visual structure was never allocated then nothing useful
       can be done. */
    if (visual == 0)
        return FALSE;

    /* Zero out unused and reserved fields in the packet header. */
    memset(&vpkt_hdr, 0, hdr_size);

    /* Visual UpTime capture files have a capture start time in the
       file header.  Each packet has a capture time (in msec) relative
       to the file start time.  Use the time of the first packet as the
       file start time. */
    if (visual->index_table_index == 0)
    {
        /* This is the first packet.  Save its start time as the file time. */
        visual->start_time = (guint32) phdr->ts.secs;

        /* Initialize the index table */
        visual->index_table = g_malloc(1024 * sizeof *visual->index_table);
        visual->index_table_size = 1024;
    }

    /* Calculate milliseconds since capture start. */
    delta_msec = phdr->ts.nsecs / 1000000;
    delta_msec += ( (guint32) phdr->ts.secs - visual->start_time) * 1000;
    vpkt_hdr.ts_delta = htolel(delta_msec);

    /* Fill in the length fields. */
    vpkt_hdr.orig_len = htoles(phdr->len);
    vpkt_hdr.incl_len = htoles(phdr->caplen);

    /* Fill in the encapsulation hint for the file's media type. */
    switch (wdh->encap)
    {
    case WTAP_ENCAP_ETHERNET:   /* Ethernet */
        vpkt_hdr.encap_hint = 2;
        break;
    case WTAP_ENCAP_TOKEN_RING: /* Token Ring */
        vpkt_hdr.encap_hint = 3;
        break;
    case WTAP_ENCAP_PPP:        /* PPP */
    case WTAP_ENCAP_PPP_WITH_PHDR:
        vpkt_hdr.encap_hint = 14;
        break;
    case WTAP_ENCAP_CHDLC_WITH_PHDR:      /* HDLC Router */
        vpkt_hdr.encap_hint = 13;
        break;
    case WTAP_ENCAP_FRELAY_WITH_PHDR:     /* Frame Relay Auto-detect */
        vpkt_hdr.encap_hint = 12;
        break;
    case WTAP_ENCAP_LAPB:       /* Unknown */
    default:
        vpkt_hdr.encap_hint = 1;
        break;
    }

    /* Set status flags.  The only status currently supported for all
       encapsulations is direction.  This either goes in the p2p or the
       X.25 pseudo header.  It would probably be better to move this up
       into the phdr. */
    packet_status = 0;
    switch (wdh->encap)
    {
    case WTAP_ENCAP_CHDLC_WITH_PHDR:
        packet_status |= (pseudo_header->p2p.sent ? PS_SENT : 0x00);
        break;

    case WTAP_ENCAP_FRELAY_WITH_PHDR:
    case WTAP_ENCAP_LAPB:
        packet_status |=
            ((pseudo_header->x25.flags & FROM_DCE) ? 0x00 : PS_SENT);
        break;
    }
    vpkt_hdr.status = htolel(packet_status);

    /* Write the packet header. */
    if (!wtap_dump_file_write(wdh, &vpkt_hdr, hdr_size, err))
        return FALSE;

    /* Write the packet data */
    if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
        return FALSE;

    /* Store the frame offset in the index table. */
    if (visual->index_table_index >= visual->index_table_size)
    {
        /* End of table reached.  Reallocate with a larger size */
        visual->index_table_size *= 2;
        visual->index_table = g_realloc(visual->index_table,
            visual->index_table_size * sizeof *visual->index_table);
    }
    visual->index_table[visual->index_table_index] = htolel(visual->next_offset);

    /* Update the table index and offset for the next frame. */
    visual->index_table_index++;
    visual->next_offset += (guint32) hdr_size + phdr->caplen;

    return TRUE;
}


/* Finish writing to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean visual_dump_close(wtap_dumper *wdh, int *err)
{
    struct visual_write_info * visual = wdh->priv;
    size_t n_to_write;
    struct visual_file_hdr vfile_hdr;
    const char *magicp;
    size_t magic_size;

    /* If the visual structure was never allocated then nothing useful
       can be done. */
    if (visual == 0)
        return FALSE;

    /* Write out the frame table at the end of the file. */
    if (visual->index_table)
    {
        /* Write the index table to the file. */
        n_to_write = visual->index_table_index * sizeof *visual->index_table;
        if (!wtap_dump_file_write(wdh, visual->index_table, n_to_write, err))
        {
            visual_dump_free(wdh);
            return FALSE;
        }
    }

    /* Write the magic number at the start of the file. */
    fseek(wdh->fh, 0, SEEK_SET);
    magicp = visual_magic;
    magic_size = sizeof visual_magic;
    if (!wtap_dump_file_write(wdh, magicp, magic_size, err))
    {
        visual_dump_free(wdh);
        return FALSE;
    }

    /* Initialize the file header with zeroes for the reserved fields. */
    memset(&vfile_hdr, '\0', sizeof vfile_hdr);
    vfile_hdr.num_pkts = htolel(visual->index_table_index);
    vfile_hdr.start_time = htolel(visual->start_time);
    vfile_hdr.max_length = htoles(65535);
    vfile_hdr.file_flags = htoles(1);  /* indexes are present */
    vfile_hdr.file_version = htoles(1);
    g_strlcpy(vfile_hdr.description, "Wireshark file", 64);

    /* Translate the encapsulation type */
    switch (wdh->encap)
    {
    case WTAP_ENCAP_ETHERNET:
        vfile_hdr.media_type = htoles(6);
        break;

    case WTAP_ENCAP_TOKEN_RING:
        vfile_hdr.media_type = htoles(9);
        break;

    case WTAP_ENCAP_LAPB:
        vfile_hdr.media_type = htoles(16);
        break;

    case WTAP_ENCAP_PPP:        /* PPP is differentiated from CHDLC in PktHdr */
    case WTAP_ENCAP_PPP_WITH_PHDR:
    case WTAP_ENCAP_CHDLC_WITH_PHDR:
        vfile_hdr.media_type = htoles(22);
        break;

    case WTAP_ENCAP_FRELAY_WITH_PHDR:
        vfile_hdr.media_type = htoles(32);
        break;
    }

    /* Write the file header following the magic bytes. */
    if (!wtap_dump_file_write(wdh, &vfile_hdr, sizeof vfile_hdr, err))
    {
        visual_dump_free(wdh);
        return FALSE;
    }

    /* Deallocate the file write data */
    visual_dump_free(wdh);
    return TRUE;
}


/* Free the memory allocated by a visual file writer. */
static void visual_dump_free(wtap_dumper *wdh)
{
    struct visual_write_info * visual = wdh->priv;

    if (visual)
    {
        /* Free the index table memory. */
        if (visual->index_table)
            g_free(visual->index_table);
    }
}
