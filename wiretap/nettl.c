/* nettl.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Enhancements by Mark C. Brown <mbrown@hp.com>
 * Copyright (C) 2003, 2005 Hewlett-Packard Development Company, L.P.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "nettl.h"

#include <stdlib.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"

/* HP nettl file header */

/* Magic number size */
#define MAGIC_SIZE     12

/* HP-UX 9.x */
static const uint8_t nettl_magic_hpux9[MAGIC_SIZE] = {
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xD0, 0x00
};
/* HP-UX 10.x and 11.x */
static const uint8_t nettl_magic_hpux10[MAGIC_SIZE] = {
    0x54, 0x52, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
};

#define FILE_HDR_SIZE   128
#define NETTL_FILENAME_SIZE 56

struct nettl_file_hdr {
    uint8_t     magic[MAGIC_SIZE];
    char        file_name[NETTL_FILENAME_SIZE];
    char        tz[20];
    char        host_name[9];
    char        os_vers[9];
    uint8_t     os_v;
    uint8_t     xxa[8];
    char        model[11];
    uint16_t    unknown;        /* just padding to 128 bytes? */
};

/* HP nettl record header */
/* see /usr/include/sys/netdiag1.h for hints */
struct nettlrec_hdr {
    uint16_t    hdr_len;
    uint16_t    subsys;
    uint32_t    devid;
    uint8_t     xxa[4];
    uint32_t    kind;
    uint8_t     xxb[16];
    uint32_t    caplen;
    uint32_t    length;
    uint32_t    sec;
    uint32_t    usec;
    uint32_t    pid;
    uint8_t     xxc[8];
    uint32_t    uid;
    /* Other stuff might be here, but isn't always here */
};

/*
 * This is what we treat as the minimum size of a record header.
 * It is *not* necessarily the same as sizeof(struct nettlrec_hdr),
 * because it doesn't include any padding added to the structure.
 */
#define NETTL_REC_HDR_LEN       64

/* HP nettl record header for the SX25L2 subsystem - The FCS is not included
   in the file. */
struct nettlrec_sx25l2_hdr {
    uint8_t     xxa[8];
    uint8_t     from_dce;
    uint8_t     xxb[55];
    uint8_t     caplen[2];
    uint8_t     length[2];
    uint8_t     xxc[4];
    uint8_t     sec[4];
    uint8_t     usec[4];
    uint8_t     xxd[4];
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
        4-5     captured length
        6-7     actual length
        8-11    unknown
        12-15   secs
        16-19   usecs
        20-21   unknown
*/
struct nettlrec_ns_ls_drv_eth_hdr {
    uint8_t     xxa[4];
    uint8_t     caplen[2];
    uint8_t     length[2];
    uint8_t     xxb[4];
    uint8_t     sec[4];
    uint8_t     usec[4];
    uint8_t     xxc[2];
};

/*
 * This is the size of an NS_LS_DRV_ETH header; it is *not* necessarily
 * the same as sizeof(struct nettlrec_ns_ls_drv_eth_hdr), because it
 * doesn't include any padding added to the structure.
 */
#define NS_LS_DRV_ETH_HDR_LEN   22

/* header is followed by data and once again the total length (2 bytes) ! */

typedef struct {
        bool is_hpux_11;
} nettl_t;

static bool nettl_read(wtap *wth, wtap_rec *rec, Buffer *buf,
                int *err, char **err_info, int64_t *data_offset);
static bool nettl_seek_read(wtap *wth, int64_t seek_off,
                wtap_rec *rec, Buffer *buf,
                int *err, char **err_info);
static bool nettl_read_rec(wtap *wth, FILE_T fh, wtap_rec *rec,
                Buffer *buf, int *err, char **err_info);
static bool nettl_dump(wtap_dumper *wdh, const wtap_rec *rec,
    const uint8_t *pd, int *err, char **err_info);

static int nettl_file_type_subtype = -1;

void register_nettl(void);

wtap_open_return_val nettl_open(wtap *wth, int *err, char **err_info)
{
    struct nettl_file_hdr file_hdr;
    uint16_t dummy[2];
    int subsys;
    nettl_t *nettl;

    memset(&file_hdr, 0, sizeof(file_hdr));

    /* Read in the string that should be at the start of a HP file */
    if (!wtap_read_bytes(wth->fh, file_hdr.magic, MAGIC_SIZE, err, err_info)) {
        if (*err != WTAP_ERR_SHORT_READ)
            return WTAP_OPEN_ERROR;
        return WTAP_OPEN_NOT_MINE;
    }

    if (memcmp(file_hdr.magic, nettl_magic_hpux9, MAGIC_SIZE) &&
        memcmp(file_hdr.magic, nettl_magic_hpux10, MAGIC_SIZE)) {
        return WTAP_OPEN_NOT_MINE;
    }

    /* Read the rest of the file header */
    if (!wtap_read_bytes(wth->fh, file_hdr.file_name, FILE_HDR_SIZE - MAGIC_SIZE,
                         err, err_info))
        return WTAP_OPEN_ERROR;

    /* This is an nettl file */
    wth->file_type_subtype = nettl_file_type_subtype;
    nettl = g_new(nettl_t,1);
    wth->priv = (void *)nettl;
    if (file_hdr.os_vers[2] == '1' && file_hdr.os_vers[3] == '1')
        nettl->is_hpux_11 = true;
    else
        nettl->is_hpux_11 = false;
    wth->subtype_read = nettl_read;
    wth->subtype_seek_read = nettl_seek_read;
    wth->snapshot_length = 0;   /* not available */

    /* read the first header to take a guess at the file encap */
    if (!wtap_read_bytes_or_eof(wth->fh, dummy, 4, err, err_info)) {
        if (*err == 0) {
            /* EOF, so no records */
            return WTAP_OPEN_NOT_MINE;
        }
        return WTAP_OPEN_ERROR;
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
        return WTAP_OPEN_ERROR;
    }
    wth->file_tsprec = WTAP_TSPREC_USEC;

    return WTAP_OPEN_MINE;
}

/* Read the next packet */
static bool nettl_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset)
{
    /* Read record. */
    *data_offset = file_tell(wth->fh);
    if (!nettl_read_rec(wth, wth->fh, rec, buf, err, err_info)) {
        /* Read error or EOF */
        return false;
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
        wth->file_encap = rec->rec_header.packet_header.pkt_encap;
    else {
        if (wth->file_encap != rec->rec_header.packet_header.pkt_encap)
            wth->file_encap = WTAP_ENCAP_PER_PACKET;
    }

    return true;
}

static bool
nettl_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec,
                Buffer *buf, int *err, char **err_info)
{
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return false;

    /* Read record. */
    if (!nettl_read_rec(wth, wth->random_fh, rec, buf, err, err_info)) {
        /* Read error or EOF */
        if (*err == 0) {
            /* EOF means "short read" in random-access mode */
            *err = WTAP_ERR_SHORT_READ;
        }
        return false;
    }
    return true;
}

static bool
nettl_read_rec(wtap *wth, FILE_T fh, wtap_rec *rec, Buffer *buf,
                int *err, char **err_info)
{
    union wtap_pseudo_header *pseudo_header = &rec->rec_header.packet_header.pseudo_header;
    nettl_t *nettl = (nettl_t *)wth->priv;
    bool fddihack = false;
    struct nettlrec_hdr rec_hdr;
    uint16_t hdr_len;
    struct nettlrec_ns_ls_drv_eth_hdr drv_eth_hdr;
    uint32_t length, caplen;
    int subsys;
    unsigned padlen;
    int datalen;
    uint8_t dummyc[16];
    int bytes_to_read;
    uint8_t *pd;

    if (!wtap_read_bytes_or_eof(fh, &rec_hdr.hdr_len, sizeof rec_hdr.hdr_len,
                                err, err_info))
        return false;
    hdr_len = g_ntohs(rec_hdr.hdr_len);
    if (hdr_len < NETTL_REC_HDR_LEN) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("nettl: record header length %u too short",
            hdr_len);
        return false;
    }
    if (!wtap_read_bytes(fh, &rec_hdr.subsys, NETTL_REC_HDR_LEN - 2,
                         err, err_info))
        return false;
    subsys = g_ntohs(rec_hdr.subsys);
    hdr_len -= NETTL_REC_HDR_LEN;
    /* Skip the rest of the header. */
    if (!wtap_read_bytes(fh, NULL, hdr_len, err, err_info))
        return false;

    if ( (pntoh32(&rec_hdr.kind) & NETTL_HDR_PDU_MASK) == 0 ) {
        /* not actually a data packet (PDU) trace record */
        rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_NETTL_RAW_IP;
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
                rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_NETTL_RAW_IP;
            } else if (subsys == NETTL_SUBSYS_NS_LS_ICMP) {
                rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_NETTL_RAW_ICMP;
            } else if (subsys == NETTL_SUBSYS_NS_LS_ICMPV6) {
                rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_NETTL_RAW_ICMPV6;
            } else if (subsys == NETTL_SUBSYS_NS_LS_TELNET) {
                rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_NETTL_RAW_TELNET;
            } else if( (subsys == NETTL_SUBSYS_HPPB_FDDI)
                    || (subsys == NETTL_SUBSYS_EISA_FDDI)
                    || (subsys == NETTL_SUBSYS_PCI_FDDI)
                    || (subsys == NETTL_SUBSYS_HSC_FDDI) ) {
                rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_NETTL_FDDI;
            } else if( (subsys == NETTL_SUBSYS_PCI_TR)
                    || (subsys == NETTL_SUBSYS_TOKEN) ) {
                rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_NETTL_TOKEN_RING;
            } else {
                rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_NETTL_ETHERNET;
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
                    fddihack=true;
                    padlen = 0;
                } else {
                    /* outbound appears to have variable padding */
                    if (!wtap_read_bytes(fh, dummyc, 9, err, err_info))
                        return false;
                    /* padding is usually either a total 11 or 16 bytes??? */
                    padlen = (int)dummyc[8];
                    if (!wtap_read_bytes(fh, NULL, padlen, err, err_info))
                        return false;
                    padlen += 9;
                }
            } else if ( (subsys == NETTL_SUBSYS_PCI_FDDI)
                     || (subsys == NETTL_SUBSYS_EISA_FDDI)
                     || (subsys == NETTL_SUBSYS_HSC_FDDI) ) {
                /* other flavor FDDI cards have an extra 3 bytes of padding */
                if (!wtap_read_bytes(fh, NULL, 3, err, err_info))
                    return false;
                padlen = 3;
            } else if (subsys == NETTL_SUBSYS_NS_LS_LOOPBACK) {
                /* LOOPBACK has an extra 26 bytes of padding */
                if (!wtap_read_bytes(fh, NULL, 26, err, err_info))
                    return false;
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
                if (!wtap_read_bytes(fh, NULL, 8, err, err_info))
                    return false;
                padlen = 8;
            } else {
                padlen = 0;
            }
            break;

        case NETTL_SUBSYS_NS_LS_DRIVER :
            /* XXX we don't know how to identify this as ethernet frames, so
               we assume everything is. We will crash and burn for anything else */
            /* for encapsulated 100baseT we do this */
            rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_NETTL_ETHERNET;
            if (!wtap_read_bytes(fh, &drv_eth_hdr, NS_LS_DRV_ETH_HDR_LEN,
                                      err, err_info))
                return false;

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
                if (!wtap_read_bytes(fh, NULL, 2, err, err_info))
                    return false;
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
             *    uint8_t       caplen[2];
             *    uint8_t       length[2];
             *    uint8_t       xxc[4];
             *    uint8_t       sec[4];
             *    uint8_t       usec[4];
             *    uint8_t       xxd[4];
             *
             * or something such as that - if it has 4 bytes before that
             * (making it 24 bytes), it'd be like struct
             * nettlrec_ns_ls_drv_eth_hdr but with 2 more bytes at the end.
             *
             * And is "from_dce" at xxa[0] in the nettlrec_hdr structure?
             */
            rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_NETTL_X25;
            length = pntoh32(&rec_hdr.length);
            caplen = pntoh32(&rec_hdr.caplen);
            padlen = 24;        /* sizeof (struct nettlrec_sx25l2_hdr) - NETTL_REC_HDR_LEN + 4 */
            if (!wtap_read_bytes(fh, NULL, padlen, err, err_info))
                return false;
            break;

        default:
            /* We're going to assume it's ethernet if we don't recognize the
               subsystem -- We'll probably spew junks and core if it isn't... */
            wth->file_encap = WTAP_ENCAP_PER_PACKET;
            rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_NETTL_ETHERNET;
            length = pntoh32(&rec_hdr.length);
            caplen = pntoh32(&rec_hdr.caplen);
            padlen = 0;
            break;
    }

    if (length < padlen) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("nettl: packet length %u in record header too short, less than %u",
            length, padlen);
        return false;
    }
    rec->rec_type = REC_TYPE_PACKET;
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
    rec->rec_header.packet_header.len = length - padlen;
    if (caplen < padlen) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("nettl: captured length %u in record header too short, less than %u",
            caplen, padlen);
        return false;
    }
    datalen = caplen - padlen;
    rec->rec_header.packet_header.caplen = datalen;
    rec->ts.secs = pntoh32(&rec_hdr.sec);
    rec->ts.nsecs = pntoh32(&rec_hdr.usec) * 1000;

    pseudo_header->nettl.subsys   = subsys;
    pseudo_header->nettl.devid    = pntoh32(&rec_hdr.devid);
    pseudo_header->nettl.kind     = pntoh32(&rec_hdr.kind);
    pseudo_header->nettl.pid      = pntoh32(&rec_hdr.pid);
    pseudo_header->nettl.uid      = pntoh32(&rec_hdr.uid);

    if (rec->rec_header.packet_header.caplen > WTAP_MAX_PACKET_SIZE_STANDARD) {
        /*
         * Probably a corrupt capture file; don't blow up trying
         * to allocate space for an immensely-large packet.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("nettl: File has %u-byte packet, bigger than maximum of %u",
            rec->rec_header.packet_header.caplen, WTAP_MAX_PACKET_SIZE_STANDARD);
        return false;
    }

    /*
     * Read the packet data.
     */
    ws_buffer_assure_space(buf, datalen);
    pd = ws_buffer_start_ptr(buf);
    if (fddihack) {
        /* read in FC, dest, src, DSAP and SSAP */
        bytes_to_read = 15;
        if (bytes_to_read > datalen)
            bytes_to_read = datalen;
        if (!wtap_read_bytes(fh, pd, bytes_to_read, err, err_info))
            return false;
        datalen -= bytes_to_read;
        if (datalen == 0) {
            /* There's nothing past the FC, dest, src, DSAP and SSAP */
            return true;
        }
        if (pd[13] == 0xAA) {
            /* it's SNAP, have to eat 3 bytes??? */
            bytes_to_read = 3;
            if (bytes_to_read > datalen)
                bytes_to_read = datalen;
            if (!wtap_read_bytes(fh, NULL, bytes_to_read, err, err_info))
                return false;
            datalen -= bytes_to_read;
            if (datalen == 0) {
                /* There's nothing past the FC, dest, src, DSAP, SSAP, and 3 bytes to eat */
                return true;
            }
        }
        if (!wtap_read_bytes(fh, pd + 15, datalen, err, err_info))
            return false;
    } else {
        if (!wtap_read_bytes(fh, pd, datalen, err, err_info))
            return false;
    }

    return true;
}

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise.  nettl files are WTAP_ENCAP_UNKNOWN
   when they are first opened, so we allow that for tshark read/write.
 */

static int nettl_dump_can_write_encap(int encap)
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
            return WTAP_ERR_UNWRITABLE_ENCAP;
    }
}


/* Returns true on success, false on failure;
   sets "*err" to an error code on failure */
static bool nettl_dump_open(wtap_dumper *wdh, int *err, char **err_info _U_)
{
    struct nettl_file_hdr file_hdr;

    /* This is a nettl file */
    wdh->subtype_write = nettl_dump;

    /* Write the file header. */
    memset(&file_hdr,0,sizeof(file_hdr));
    memcpy(file_hdr.magic,nettl_magic_hpux10,sizeof(file_hdr.magic));
    (void) g_strlcpy(file_hdr.file_name,"/tmp/wireshark.TRC000",NETTL_FILENAME_SIZE);
    (void) g_strlcpy(file_hdr.tz,"UTC",20);
    (void) g_strlcpy(file_hdr.host_name,"",9);
    (void) g_strlcpy(file_hdr.os_vers,"B.11.11",9);
    file_hdr.os_v=0x55;
    (void) g_strlcpy(file_hdr.model,"9000/800",11);
    file_hdr.unknown=g_htons(0x406);
    if (!wtap_dump_file_write(wdh, &file_hdr, sizeof file_hdr, err))
        return false;

    return true;
}

/* Write a record for a packet to a dump file.
   Returns true on success, false on failure. */
static bool nettl_dump(wtap_dumper *wdh,
                           const wtap_rec *rec,
                           const uint8_t *pd, int *err, char **err_info _U_)
{
    const union wtap_pseudo_header *pseudo_header = &rec->rec_header.packet_header.pseudo_header;
    struct nettlrec_hdr rec_hdr;
    uint8_t dummyc[24];

    /* We can only write packet records. */
    if (rec->rec_type != REC_TYPE_PACKET) {
        *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
        return false;
    }

    /* Don't write anything we're not willing to read. */
    if (rec->rec_header.packet_header.caplen > WTAP_MAX_PACKET_SIZE_STANDARD) {
        *err = WTAP_ERR_PACKET_TOO_LARGE;
        return false;
    }

    memset(&rec_hdr,0,sizeof(rec_hdr));
    /* HP-UX 11.X header should be 68 bytes */
    rec_hdr.hdr_len = g_htons(sizeof(rec_hdr) + 4);
    rec_hdr.kind = g_htonl(NETTL_HDR_PDUIN);
    /*
     * Probably interpreted as signed in other programs that read it.
     * Maybe HPE will decide to make it unsigned, which could probably
     * be made to work once the last 32-bit UN*X is gone and time_t
     * is universally 64-bit.
     */
    if (rec->ts.secs < 0 || rec->ts.secs > INT32_MAX) {
        *err = WTAP_ERR_TIME_STAMP_NOT_SUPPORTED;
        return false;
    }
    rec_hdr.sec = g_htonl((uint32_t)rec->ts.secs);
    rec_hdr.usec = g_htonl(rec->ts.nsecs/1000);
    rec_hdr.caplen = g_htonl(rec->rec_header.packet_header.caplen);
    rec_hdr.length = g_htonl(rec->rec_header.packet_header.len);
    rec_hdr.devid = -1;
    rec_hdr.pid = -1;
    rec_hdr.uid = -1;

    switch (rec->rec_header.packet_header.pkt_encap) {

        case WTAP_ENCAP_NETTL_FDDI:
            /* account for pad bytes */
            rec_hdr.caplen = g_htonl(rec->rec_header.packet_header.caplen + 3);
            rec_hdr.length = g_htonl(rec->rec_header.packet_header.len + 3);
            /* fall through and fill the rest of the fields */
        /* FALL THROUGH */
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
            rec_hdr.caplen = g_htonl(rec->rec_header.packet_header.caplen + 3);
            rec_hdr.length = g_htonl(rec->rec_header.packet_header.len + 3);
            break;

        case WTAP_ENCAP_TOKEN_RING:
            rec_hdr.subsys = g_htons(NETTL_SUBSYS_PCI_TR);
            break;
#if 0
        case WTAP_ENCAP_NETTL_X25:
            rec_hdr.caplen = g_htonl(rec->rec_header.packet_header.caplen + 24);
            rec_hdr.length = g_htonl(rec->rec_header.packet_header.len + 24);
            rec_hdr.subsys = g_htons(pseudo_header->nettl.subsys);
            rec_hdr.devid = g_htonl(pseudo_header->nettl.devid);
            rec_hdr.kind = g_htonl(pseudo_header->nettl.kind);
            rec_hdr.pid = g_htonl(pseudo_header->nettl.pid);
            rec_hdr.uid = g_htons(pseudo_header->nettl.uid);
            break;
#endif
        default:
            /* found one we don't support */
            *err = WTAP_ERR_UNWRITABLE_ENCAP;
            return false;
    }

    if (!wtap_dump_file_write(wdh, &rec_hdr, sizeof(rec_hdr), err))
        return false;

    /* Write out 4 extra bytes of unknown stuff for HP-UX11
     * header format.
     */
    memset(dummyc, 0, sizeof dummyc);
    if (!wtap_dump_file_write(wdh, dummyc, 4, err))
        return false;

    if ((rec->rec_header.packet_header.pkt_encap == WTAP_ENCAP_FDDI_BITSWAPPED) ||
        (rec->rec_header.packet_header.pkt_encap == WTAP_ENCAP_NETTL_FDDI)) {
        /* add those weird 3 bytes of padding */
        if (!wtap_dump_file_write(wdh, dummyc, 3, err))
            return false;
    }
/*
  } else if (rec->rec_header.packet_header.pkt_encap == WTAP_ENCAP_NETTL_X25) {
  if (!wtap_dump_file_write(wdh, dummyc, 24, err))
  return false;
  }
*/

    /* write actual PDU data */

    if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen, err))
        return false;

    return true;
}

static const struct supported_block_type nettl_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info nettl_info = {
    "HP-UX nettl trace", "nettl", "trc0", "trc1",
    false, BLOCKS_SUPPORTED(nettl_blocks_supported),
    nettl_dump_can_write_encap, nettl_dump_open, NULL
};

void register_nettl(void)
{
    nettl_file_type_subtype = wtap_register_file_type_subtype(&nettl_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("NETTL",
                                                   nettl_file_type_subtype);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
