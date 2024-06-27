/* btsnoop.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "btsnoop.h"

#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"

/*
 * Symbian's btsnoop format is derived from Sun's snoop format.
 * See RFC 1761 for a description of the "snoop" file format.
 * See
 *
 *    https://gitlab.com/wireshark/wireshark/uploads/6d44fa94c164b58516e8577f44a6ccdc/btmodified_rfc1761.txt
 *
 * for a description of the btsnoop format.
 */

/* Magic number in "btsnoop" files. */
static const char btsnoop_magic[] = {
    'b', 't', 's', 'n', 'o', 'o', 'p', '\0'
};

/* "btsnoop" file header (minus magic number). */
struct btsnoop_hdr {
    uint32_t    version;        /* version number (should be 1) */
    uint32_t    datalink;       /* datalink type */
};

/* "btsnoop" record header. */
struct btsnooprec_hdr {
    uint32_t    orig_len;       /* actual length of packet */
    uint32_t    incl_len;       /* number of octets captured in file */
    uint32_t    flags;          /* packet flags */
    uint32_t    cum_drops;      /* cumulative number of dropped packets */
    int64_t     ts_usec;        /* timestamp microseconds */
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

static const int64_t KUnixTimeBase = INT64_C(0x00dcddb30f2f8000); /* offset from symbian - unix time */

static bool btsnoop_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *offset);
static bool btsnoop_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info);
static bool btsnoop_read_record(wtap *wth, FILE_T fh,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info);

static int btsnoop_file_type_subtype = -1;

void register_btsnoop(void);

wtap_open_return_val btsnoop_open(wtap *wth, int *err, char **err_info)
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
        *err_info = ws_strdup_printf("btsnoop: version %u unsupported", hdr.version);
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
        *err_info = ws_strdup_printf("btsnoop: datalink type %u unknown or unsupported", hdr.datalink);
        return WTAP_OPEN_ERROR;
    }

    wth->subtype_read = btsnoop_read;
    wth->subtype_seek_read = btsnoop_seek_read;
    wth->file_encap = file_encap;
    wth->snapshot_length = 0;   /* not available in header */
    wth->file_tsprec = WTAP_TSPREC_USEC;
    wth->file_type_subtype = btsnoop_file_type_subtype;

    /*
     * Add an IDB; we don't know how many interfaces were
     * involved, so we just say one interface, about which
     * we only know the link-layer type, snapshot length,
     * and time stamp resolution.
     */
    wtap_add_generated_idb(wth);

    return WTAP_OPEN_MINE;
}

static bool btsnoop_read(wtap *wth, wtap_rec *rec, Buffer *buf,
                             int *err, char **err_info, int64_t *offset)
{
    *offset = file_tell(wth->fh);

    return btsnoop_read_record(wth, wth->fh, rec, buf, err, err_info);
}

static bool btsnoop_seek_read(wtap *wth, int64_t seek_off,
                                  wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return false;

    return btsnoop_read_record(wth, wth->random_fh, rec, buf, err, err_info);
}

static bool btsnoop_read_record(wtap *wth, FILE_T fh,
                                    wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
    struct btsnooprec_hdr hdr;
    uint32_t packet_size;
    uint32_t flags;
    uint32_t orig_size;
    int64_t ts;

    /* Read record header. */

    if (!wtap_read_bytes_or_eof(fh, &hdr, sizeof hdr, err, err_info))
        return false;

    packet_size = g_ntohl(hdr.incl_len);
    orig_size = g_ntohl(hdr.orig_len);
    flags = g_ntohl(hdr.flags);
    if (packet_size > WTAP_MAX_PACKET_SIZE_STANDARD) {
        /*
         * Probably a corrupt capture file; don't blow up trying
         * to allocate space for an immensely-large packet.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("btsnoop: File has %u-byte packet, bigger than maximum of %u",
                                    packet_size, WTAP_MAX_PACKET_SIZE_STANDARD);
        return false;
    }

    ts = GINT64_FROM_BE(hdr.ts_usec);
    ts -= KUnixTimeBase;

    rec->rec_type = REC_TYPE_PACKET;
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
    rec->ts.secs = (unsigned)(ts / 1000000);
    rec->ts.nsecs = (unsigned)((ts % 1000000) * 1000);
    rec->rec_header.packet_header.caplen = packet_size;
    rec->rec_header.packet_header.len = orig_size;
    if(wth->file_encap == WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR)
    {
        rec->rec_header.packet_header.pseudo_header.p2p.sent = (flags & KHciLoggerControllerToHost) ? false : true;
    } else if(wth->file_encap == WTAP_ENCAP_BLUETOOTH_HCI) {
        rec->rec_header.packet_header.pseudo_header.bthci.sent = (flags & KHciLoggerControllerToHost) ? false : true;
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
static int btsnoop_dump_can_write_encap(int encap)
{
    /* Per-packet encapsulations aren't supported. */
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    /*
     * XXX - for now we only support WTAP_ENCAP_BLUETOOTH_HCI,
     * WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR, and
     * WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR.
     */
    if (encap != WTAP_ENCAP_BLUETOOTH_HCI &&
        encap != WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR &&
        encap != WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR)
        return WTAP_ERR_UNWRITABLE_ENCAP;

    return 0;
}

static bool btsnoop_dump(wtap_dumper *wdh,
    const wtap_rec *rec,
    const uint8_t *pd, int *err, char **err_info)
{
    const union wtap_pseudo_header *pseudo_header = &rec->rec_header.packet_header.pseudo_header;
    struct btsnooprec_hdr rec_hdr;
    uint32_t flags;
    int64_t nsecs;
    int64_t ts_usec;

    /* We can only write packet records. */
    if (rec->rec_type != REC_TYPE_PACKET) {
        *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
        return false;
    }

    /*
     * Make sure this packet doesn't have a link-layer type that
     * differs from the one for the file.
     */
    if (wdh->file_encap != rec->rec_header.packet_header.pkt_encap) {
        *err = WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;
        return false;
    }

    /* Don't write out anything bigger than we can read. */
    if (rec->rec_header.packet_header.caplen > WTAP_MAX_PACKET_SIZE_STANDARD) {
        *err = WTAP_ERR_PACKET_TOO_LARGE;
        return false;
    }

    rec_hdr.incl_len = GUINT32_TO_BE(rec->rec_header.packet_header.caplen);
    rec_hdr.orig_len = GUINT32_TO_BE(rec->rec_header.packet_header.len);

    switch (wdh->file_encap) {

    case WTAP_ENCAP_BLUETOOTH_HCI:
        switch (pseudo_header->bthci.channel) {

        case BTHCI_CHANNEL_COMMAND:
            if (!pseudo_header->bthci.sent) {
                *err = WTAP_ERR_UNWRITABLE_REC_DATA;
                *err_info = ws_strdup_printf("btsnoop: Command channel, sent false");
                return false;
            }
            flags = KHciLoggerCommandOrEvent|KHciLoggerHostToController;
            break;

        case BTHCI_CHANNEL_EVENT:
            if (pseudo_header->bthci.sent) {
                *err = WTAP_ERR_UNWRITABLE_REC_DATA;
                *err_info = ws_strdup_printf("btsnoop: Event channel, sent true");
                return false;
            }
            flags = KHciLoggerCommandOrEvent|KHciLoggerControllerToHost;
            break;

        case BTHCI_CHANNEL_ACL:
            if (pseudo_header->bthci.sent)
                flags = KHciLoggerACLDataFrame|KHciLoggerHostToController;
            else
                flags = KHciLoggerACLDataFrame|KHciLoggerControllerToHost;
            break;

        default:
            *err = WTAP_ERR_UNWRITABLE_REC_DATA;
            *err_info = ws_strdup_printf("btsnoop: Unknown channel %u",
                                        pseudo_header->bthci.channel);
            return false;
        }
        break;

    case WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR:
        if (pseudo_header->p2p.sent)
            flags = KHciLoggerHostToController;
        else
            flags = KHciLoggerControllerToHost;
        if (rec->rec_header.packet_header.caplen >= 1 &&
            (pd[0] == 0x01 || pd[0] == 0x04))
            flags |= KHciLoggerCommandOrEvent;
        break;

    case WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR:
        flags = (pseudo_header->btmon.adapter_id << 16) | pseudo_header->btmon.opcode;
        break;

    default:
        /* We should never get here - our open routine should only get
           called for the types above. */
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("btsnoop: invalid encapsulation %u",
                                    wdh->file_encap);
        return false;
    }
    rec_hdr.flags = GUINT32_TO_BE(flags);
    rec_hdr.cum_drops = GUINT32_TO_BE(0);

    nsecs = rec->ts.nsecs;
    ts_usec  = ((int64_t) rec->ts.secs * 1000000) + (nsecs / 1000);
    ts_usec += KUnixTimeBase;
    rec_hdr.ts_usec = GINT64_TO_BE(ts_usec);

    if (!wtap_dump_file_write(wdh, &rec_hdr, sizeof rec_hdr, err))
        return false;
    if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen, err))
        return false;
    return true;
}

/* Returns true on success, false on failure; sets "*err" to an error code on
   failure */
static bool btsnoop_dump_open(wtap_dumper *wdh, int *err, char **err_info _U_)
{
    struct btsnoop_hdr file_hdr;
    uint32_t datalink;

    /* This is a btsnoop file */
    wdh->subtype_write = btsnoop_dump;

    switch (wdh->file_encap) {

    case WTAP_ENCAP_BLUETOOTH_HCI:
        datalink = KHciLoggerDatalinkTypeH1;
        break;

    case WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR:
        datalink = KHciLoggerDatalinkTypeH4;
        break;

    case WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR:
        datalink = KHciLoggerDatalinkLinuxMonitor;
        break;

    default:
        /* We should never get here - our open routine should only get
           called for the types above. */
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("btsnoop: invalid encapsulation %u",
                                    wdh->file_encap);
        return false;
    }

    /* Write the file header. */
    if (!wtap_dump_file_write(wdh, btsnoop_magic, sizeof btsnoop_magic, err))
        return false;

    /* current "btsnoop" format is 1 */
    file_hdr.version  = GUINT32_TO_BE(1);
    /* HCI type encoded in first byte */
    file_hdr.datalink = GUINT32_TO_BE(datalink);

    if (!wtap_dump_file_write(wdh, &file_hdr, sizeof file_hdr, err))
        return false;

    return true;
}

static const struct supported_block_type btsnoop_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info btsnoop_info = {
    "Symbian OS btsnoop", "btsnoop", "log", NULL,
    false, BLOCKS_SUPPORTED(btsnoop_blocks_supported),
    btsnoop_dump_can_write_encap, btsnoop_dump_open, NULL
};

void register_btsnoop(void)
{
    btsnoop_file_type_subtype = wtap_register_file_type_subtype(&btsnoop_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("BTSNOOP",
                                                   btsnoop_file_type_subtype);
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
