/* btsnoop.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "btsnoop.h"

/*
 * Symbian's btsnoop format is derived from Sun's snoop format.
 * See RFC 1761 for a description of the "snoop" file format.
 */

/* Magic number in "btsnoop" files. */
static const char btsnoop_magic[] = {
    'b', 't', 's', 'n', 'o', 'o', 'p', '\0'
};

/* "btsnoop" file header (minus magic number). */
struct btsnoop_hdr {
    guint32     version;        /* version number (should be 1) */
    guint32     datalink;       /* datalink type */
};

/* "btsnoop" record header. */
struct btsnooprec_hdr {
    guint32     orig_len;       /* actual length of packet */
    guint32     incl_len;       /* number of octets captured in file */
    guint32     flags;          /* packet flags */
    guint32     cum_drops;      /* cumulative number of dropped packets */
    gint64      ts_usec;        /* timestamp microseconds */
};

/* H1 is unframed data with the packet type encoded in the flags field of capture header */
/* It can be used for any datalink by placing logging above the datalink layer of HCI */
#define KHciLoggerDatalinkTypeH1                1001
/* H4 is the serial HCI with packet type encoded in the first byte of each packet */
#define KHciLoggerDatalinkTypeH4                1002
/* CSR's PPP derived bluecore serial protocol - in practice we log in H1 format after deframing */
#define KHciLoggerDatalinkTypeBCSP              1003
/* H5 is the official three wire serial protocol derived from BCSP*/
#define KHciLoggerDatalinkTypeH5                1004
/* Linux Monitor */
#define KHciLoggerDatalinkLinuxMonitor   2001
/* BlueZ 5 Simulator */
#define KHciLoggerDatalinkBlueZ5Simulator       2002

#define KHciLoggerHostToController              0
#define KHciLoggerControllerToHost              0x00000001
#define KHciLoggerACLDataFrame                  0
#define KHciLoggerCommandOrEvent                0x00000002

static const gint64 KUnixTimeBase = G_GINT64_CONSTANT(0x00dcddb30f2f8000); /* offset from symbian - unix time */

static gboolean btsnoop_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, gchar **err_info, gint64 *offset);
static gboolean btsnoop_seek_read(wtap *wth, gint64 seek_off,
    wtap_rec *rec, Buffer *buf, int *err, gchar **err_info);
static gboolean btsnoop_read_record(wtap *wth, FILE_T fh,
    wtap_rec *rec, Buffer *buf, int *err, gchar **err_info);

wtap_open_return_val btsnoop_open(wtap *wth, int *err, gchar **err_info)
{
    char magic[sizeof btsnoop_magic];
    struct btsnoop_hdr hdr;

    int file_encap=WTAP_ENCAP_UNKNOWN;

    /* Read in the string that should be at the start of a "btsnoop" file */
    if (!wtap_read_bytes(wth->fh, magic, sizeof magic, err, err_info)) {
        if (*err != WTAP_ERR_SHORT_READ)
            return WTAP_OPEN_ERROR;
        return WTAP_OPEN_NOT_MINE;
    }

    if (memcmp(magic, btsnoop_magic, sizeof btsnoop_magic) != 0) {
        return WTAP_OPEN_NOT_MINE;
    }

    /* Read the rest of the header. */
    if (!wtap_read_bytes(wth->fh, &hdr, sizeof hdr, err, err_info))
        return WTAP_OPEN_ERROR;

    /*
     * Make sure it's a version we support.
     */
    hdr.version = g_ntohl(hdr.version);
    if (hdr.version != 1) {
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = g_strdup_printf("btsnoop: version %u unsupported", hdr.version);
        return WTAP_OPEN_ERROR;
    }

    hdr.datalink = g_ntohl(hdr.datalink);
    switch (hdr.datalink) {
    case KHciLoggerDatalinkTypeH1:
        file_encap=WTAP_ENCAP_BLUETOOTH_HCI;
        break;
    case KHciLoggerDatalinkTypeH4:
        file_encap=WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR;
        break;
    case KHciLoggerDatalinkTypeBCSP:
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = g_strdup("btsnoop: BCSP capture logs unsupported");
        return WTAP_OPEN_ERROR;
    case KHciLoggerDatalinkTypeH5:
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = g_strdup("btsnoop: H5 capture logs unsupported");
        return WTAP_OPEN_ERROR;
    case KHciLoggerDatalinkLinuxMonitor:
        file_encap=WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR;
        break;
    case KHciLoggerDatalinkBlueZ5Simulator:
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = g_strdup("btsnoop: BlueZ 5 Simulator capture logs unsupported");
        return WTAP_OPEN_ERROR;
    default:
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = g_strdup_printf("btsnoop: datalink type %u unknown or unsupported", hdr.datalink);
        return WTAP_OPEN_ERROR;
    }

    wth->subtype_read = btsnoop_read;
    wth->subtype_seek_read = btsnoop_seek_read;
    wth->file_encap = file_encap;
    wth->snapshot_length = 0;   /* not available in header */
    wth->file_tsprec = WTAP_TSPREC_USEC;
    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_BTSNOOP;

    /*
     * Add an IDB; we don't know how many interfaces were
     * involved, so we just say one interface, about which
     * we only know the link-layer type, snapshot length,
     * and time stamp resolution.
     */
    wtap_add_generated_idb(wth);

    return WTAP_OPEN_MINE;
}

static gboolean btsnoop_read(wtap *wth, wtap_rec *rec, Buffer *buf,
                             int *err, gchar **err_info, gint64 *offset)
{
    *offset = file_tell(wth->fh);

    return btsnoop_read_record(wth, wth->fh, rec, buf, err, err_info);
}

static gboolean btsnoop_seek_read(wtap *wth, gint64 seek_off,
                                  wtap_rec *rec, Buffer *buf, int *err, gchar **err_info)
{
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return FALSE;

    return btsnoop_read_record(wth, wth->random_fh, rec, buf, err, err_info);
}

static gboolean btsnoop_read_record(wtap *wth, FILE_T fh,
                                    wtap_rec *rec, Buffer *buf, int *err, gchar **err_info)
{
    struct btsnooprec_hdr hdr;
    guint32 packet_size;
    guint32 flags;
    guint32 orig_size;
    gint64 ts;

    /* Read record header. */

    if (!wtap_read_bytes_or_eof(fh, &hdr, sizeof hdr, err, err_info))
        return FALSE;

    packet_size = g_ntohl(hdr.incl_len);
    orig_size = g_ntohl(hdr.orig_len);
    flags = g_ntohl(hdr.flags);
    if (packet_size > WTAP_MAX_PACKET_SIZE_STANDARD) {
        /*
         * Probably a corrupt capture file; don't blow up trying
         * to allocate space for an immensely-large packet.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("btsnoop: File has %u-byte packet, bigger than maximum of %u",
                                    packet_size, WTAP_MAX_PACKET_SIZE_STANDARD);
        return FALSE;
    }

    ts = GINT64_FROM_BE(hdr.ts_usec);
    ts -= KUnixTimeBase;

    rec->rec_type = REC_TYPE_PACKET;
    rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
    rec->ts.secs = (guint)(ts / 1000000);
    rec->ts.nsecs = (guint)((ts % 1000000) * 1000);
    rec->rec_header.packet_header.caplen = packet_size;
    rec->rec_header.packet_header.len = orig_size;
    if(wth->file_encap == WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR)
    {
        rec->rec_header.packet_header.pseudo_header.p2p.sent = (flags & KHciLoggerControllerToHost) ? FALSE : TRUE;
    } else if(wth->file_encap == WTAP_ENCAP_BLUETOOTH_HCI) {
        rec->rec_header.packet_header.pseudo_header.bthci.sent = (flags & KHciLoggerControllerToHost) ? FALSE : TRUE;
        if(flags & KHciLoggerCommandOrEvent)
        {
            if(rec->rec_header.packet_header.pseudo_header.bthci.sent)
            {
                rec->rec_header.packet_header.pseudo_header.bthci.channel = BTHCI_CHANNEL_COMMAND;
            }
            else
            {
                rec->rec_header.packet_header.pseudo_header.bthci.channel = BTHCI_CHANNEL_EVENT;
            }
        }
        else
        {
            rec->rec_header.packet_header.pseudo_header.bthci.channel = BTHCI_CHANNEL_ACL;
        }
    } else  if (wth->file_encap == WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR) {
        rec->rec_header.packet_header.pseudo_header.btmon.opcode = flags & 0xFFFF;
        rec->rec_header.packet_header.pseudo_header.btmon.adapter_id = flags >> 16;
    }


    /* Read packet data. */
    return wtap_read_packet_bytes(fh, buf, rec->rec_header.packet_header.caplen, err, err_info);
}

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int btsnoop_dump_can_write_encap(int encap)
{
    /* Per-packet encapsulations aren't supported. */
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    /* XXX - for now we only support WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR and WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR */
    if (encap != WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR && encap != WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR)
        return WTAP_ERR_UNWRITABLE_ENCAP;

    return 0;
}

struct hci_flags_mapping
{
    guint8 hci_type;
    guint8 sent;
    guint8 flags;
};

static const struct hci_flags_mapping hci_flags[] =
{
    { 0x02, TRUE,   KHciLoggerHostToController|KHciLoggerACLDataFrame   }, /* HCI_H4_TYPE_ACL */
    { 0x02, FALSE,  KHciLoggerControllerToHost|KHciLoggerACLDataFrame   }, /* HCI_H4_TYPE_ACL */
    { 0x01, TRUE,   KHciLoggerHostToController|KHciLoggerCommandOrEvent }, /* HCI_H4_TYPE_CMD */
    { 0x04, FALSE,  KHciLoggerControllerToHost|KHciLoggerCommandOrEvent }, /* HCI_H4_TYPE_EVT */
};

static guint8 btsnoop_lookup_flags(guint8 hci_type, gboolean sent, guint8 *flags)
{
    guint8 i;

    for (i=0; i < G_N_ELEMENTS(hci_flags); ++i)
    {
        if (hci_flags[i].hci_type == hci_type &&
            hci_flags[i].sent == sent)
        {
            *flags = hci_flags[i].flags;
            return TRUE;
        }
    }
    return FALSE;
}

static gboolean btsnoop_format_partial_rec_hdr(
    const wtap_rec *rec,
    const union wtap_pseudo_header *pseudo_header,
    const guint8 *pd, int *err, gchar **err_info,
    struct btsnooprec_hdr *rec_hdr)
{
    gint64 ts_usec;
    gint64 nsecs;
    guint8 flags = 0;

    if (!btsnoop_lookup_flags(*pd, pseudo_header->p2p.sent, &flags)) {
        *err = WTAP_ERR_UNWRITABLE_REC_DATA;
        *err_info = g_strdup_printf("btsnoop: hci_type 0x%02x for %s data isn't supported",
                                    *pd,
                                    pseudo_header->p2p.sent ? "sent" : "received");
        return FALSE;
    }

    nsecs = rec->ts.nsecs;
    ts_usec  = ((gint64) rec->ts.secs * 1000000) + (nsecs / 1000);
    ts_usec += KUnixTimeBase;

    rec_hdr->flags = GUINT32_TO_BE(flags);
    rec_hdr->cum_drops = GUINT32_TO_BE(0);
    rec_hdr->ts_usec = GINT64_TO_BE(ts_usec);

    return TRUE;
}

/* FIXME: How do we support multiple backends?*/
static gboolean btsnoop_dump_h1(wtap_dumper *wdh,
    const wtap_rec *rec,
    const guint8 *pd, int *err, gchar **err_info)
{
    const union wtap_pseudo_header *pseudo_header = &rec->rec_header.packet_header.pseudo_header;
    struct btsnooprec_hdr rec_hdr;

    /* We can only write packet records. */
    if (rec->rec_type != REC_TYPE_PACKET) {
        *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
        return FALSE;
    }

    /*
     * Make sure this packet doesn't have a link-layer type that
     * differs from the one for the file.
     */
    if (wdh->encap != rec->rec_header.packet_header.pkt_encap) {
        *err = WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;
        return FALSE;
    }

    /*
     * Don't write out anything bigger than we can read.
     * (This will also fail on a caplen of 0, as it should.)
     */
    if (rec->rec_header.packet_header.caplen-1 > WTAP_MAX_PACKET_SIZE_STANDARD) {
        *err = WTAP_ERR_PACKET_TOO_LARGE;
        return FALSE;
    }

    if (!btsnoop_format_partial_rec_hdr(rec, pseudo_header, pd, err, err_info,
                                        &rec_hdr))
        return FALSE;

    rec_hdr.incl_len = GUINT32_TO_BE(rec->rec_header.packet_header.caplen-1);
    rec_hdr.orig_len = GUINT32_TO_BE(rec->rec_header.packet_header.len-1);

    if (!wtap_dump_file_write(wdh, &rec_hdr, sizeof rec_hdr, err))
        return FALSE;

    wdh->bytes_dumped += sizeof rec_hdr;

    /* Skip HCI packet type */
    ++pd;

    if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen-1, err))
        return FALSE;

    wdh->bytes_dumped += rec->rec_header.packet_header.caplen-1;

    return TRUE;
}

static gboolean btsnoop_dump_h4(wtap_dumper *wdh,
    const wtap_rec *rec,
    const guint8 *pd, int *err, gchar **err_info)
{
    const union wtap_pseudo_header *pseudo_header = &rec->rec_header.packet_header.pseudo_header;
    struct btsnooprec_hdr rec_hdr;

    /* We can only write packet records. */
    if (rec->rec_type != REC_TYPE_PACKET) {
        *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
        return FALSE;
    }


    /*
     * Make sure this packet doesn't have a link-layer type that
     * differs from the one for the file.
     */
    if (wdh->encap != rec->rec_header.packet_header.pkt_encap) {
        *err = WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;
        return FALSE;
    }

    /* Don't write out anything bigger than we can read. */
    if (rec->rec_header.packet_header.caplen > WTAP_MAX_PACKET_SIZE_STANDARD) {
        *err = WTAP_ERR_PACKET_TOO_LARGE;
        return FALSE;
    }

    if (!btsnoop_format_partial_rec_hdr(rec, pseudo_header, pd, err, err_info,
                                        &rec_hdr))
        return FALSE;

    rec_hdr.incl_len = GUINT32_TO_BE(rec->rec_header.packet_header.caplen);
    rec_hdr.orig_len = GUINT32_TO_BE(rec->rec_header.packet_header.len);

    if (!wtap_dump_file_write(wdh, &rec_hdr, sizeof rec_hdr, err))
        return FALSE;

    wdh->bytes_dumped += sizeof rec_hdr;

    if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen, err))
        return FALSE;

    wdh->bytes_dumped += rec->rec_header.packet_header.caplen;

    return TRUE;
}

/* FIXME: How do we support multiple backends?*/
gboolean btsnoop_dump_open_h1(wtap_dumper *wdh, int *err)
{
    struct btsnoop_hdr file_hdr;

    /* This is a btsnoop file */
    wdh->subtype_write = btsnoop_dump_h1;

    /* Write the file header. */
    if (!wtap_dump_file_write(wdh, btsnoop_magic, sizeof btsnoop_magic, err))
        return FALSE;

    wdh->bytes_dumped += sizeof btsnoop_magic;

    /* current "btsnoop" format is 1 */
    file_hdr.version  = GUINT32_TO_BE(1);
    /* HCI type encoded in first byte */
    file_hdr.datalink = GUINT32_TO_BE(KHciLoggerDatalinkTypeH1);

    if (!wtap_dump_file_write(wdh, &file_hdr, sizeof file_hdr, err))
        return FALSE;

    wdh->bytes_dumped += sizeof file_hdr;

    return TRUE;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean btsnoop_dump_open_h4(wtap_dumper *wdh, int *err)
{
    struct btsnoop_hdr file_hdr;

    /* This is a btsnoop file */
    wdh->subtype_write = btsnoop_dump_h4;

    /* Write the file header. */
    if (!wtap_dump_file_write(wdh, btsnoop_magic, sizeof btsnoop_magic, err))
        return FALSE;

    wdh->bytes_dumped += sizeof btsnoop_magic;

    /* current "btsnoop" format is 1 */
    file_hdr.version  = GUINT32_TO_BE(1);
    /* HCI type encoded in first byte */
    file_hdr.datalink = GUINT32_TO_BE(KHciLoggerDatalinkTypeH4);

    if (!wtap_dump_file_write(wdh, &file_hdr, sizeof file_hdr, err))
        return FALSE;

    wdh->bytes_dumped += sizeof file_hdr;

    return TRUE;
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
