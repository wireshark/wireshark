/* peektagged.c
 * Routines for opening files in what Savvius (formerly WildPackets) calls
 * the tagged file format in the description of their "PeekRdr Sample
 * Application" (C++ source code to read their capture files, downloading
 * of which requires a maintenance contract, so it's not free as in beer
 * and probably not as in speech, either).
 *
 * As that description says, it's used by AiroPeek and AiroPeek NX 2.0
 * and later, EtherPeek 6.0 and later, EtherPeek NX 3.0 and later,
 * EtherPeek VX 1.0 and later, GigaPeek NX 1.0 and later, Omni3 1.0
 * and later (both OmniPeek and the Remote Engine), and WANPeek NX
 * 1.0 and later.  They also say it'll be used by future Savvius
 * products.
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "peektagged.h"

#include <string.h>
#include <stdlib.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include <wsutil/802_11-utils.h>

/* CREDITS
 *
 * This file decoder could not have been written without examining
 * http://www.varsanofiev.com/inside/airopeekv9.htm, the help from
 * Martin Regner and Guy Harris, and the etherpeek.c file (as it
 * was called before renaming it to peekclassic.c).
 */

/*
 * Section header.
 *
 * A Peek tagged file consists of multiple sections, each of which begins
 * with a header in the following format.
 *
 * The section ID is a 4-character string saying what type of section
 * it is.  The section length is a little-endian field giving the
 * length of the section, in bytes, including the section header
 * itself.  The other field of the section header is a little-endian
 * constant that always appears to be 0x00000200.
 *
 * Files we've seen have the following sections, in order:
 *
 * "\177vers" - version information.  The contents are XML, giving
 * the file format version and application version information.
 *
 * "sess" - capture session information.  The contents are XML, giving
 * various information about the capture session.
 *
 * "pkts" - captured packets.  The contents are binary records, one for
 * each packet, with the record being a list of tagged values followed
 * by the raw packet data.
 */
typedef struct peektagged_section_header {
        int8_t  section_id[4];          /* string identifying the section */
        uint32_t section_len;            /* little-endian section length */
        uint32_t section_const;          /* little-endian 0x00000200 */
} peektagged_section_header_t;

/*
 * Network subtype values.
 *
 * XXX - do different network subtype values for 802.11 indicate different
 * network adapter types, with some adapters supplying the FCS and others
 * not supplying the FCS?
 */
#define PEEKTAGGED_NST_ETHERNET         0
#define PEEKTAGGED_NST_802_11           1       /* 802.11 with 0's at the end */
#define PEEKTAGGED_NST_802_11_2         2       /* 802.11 with 0's at the end */
#define PEEKTAGGED_NST_802_11_WITH_FCS  3       /* 802.11 with FCS at the end */

/* tags for fields in packet header */
#define TAG_PEEKTAGGED_LENGTH                   0x0000
#define TAG_PEEKTAGGED_TIMESTAMP_LOWER          0x0001
#define TAG_PEEKTAGGED_TIMESTAMP_UPPER          0x0002
#define TAG_PEEKTAGGED_FLAGS_AND_STATUS         0x0003  /* upper 24 bits unused? */
#define TAG_PEEKTAGGED_CHANNEL                  0x0004
#define TAG_PEEKTAGGED_DATA_RATE_OR_MCS_INDEX   0x0005
#define TAG_PEEKTAGGED_SIGNAL_PERC              0x0006
#define TAG_PEEKTAGGED_SIGNAL_DBM               0x0007
#define TAG_PEEKTAGGED_NOISE_PERC               0x0008
#define TAG_PEEKTAGGED_NOISE_DBM                0x0009
#define TAG_PEEKTAGGED_UNKNOWN_0x000A           0x000A
#define TAG_PEEKTAGGED_CENTER_FREQUENCY         0x000D  /* Frequency */
#define TAG_PEEKTAGGED_UNKNOWN_0x000E           0x000E  /* "Band"? */
#define TAG_PEEKTAGGED_UNKNOWN_0x000F           0x000F  /* antenna 2 signal dBm? */
#define TAG_PEEKTAGGED_UNKNOWN_0x0010           0x0010  /* antenna 3 signal dBm? */
#define TAG_PEEKTAGGED_UNKNOWN_0x0011           0x0011  /* antenna 4 signal dBm? */
#define TAG_PEEKTAGGED_UNKNOWN_0x0012           0x0012  /* antenna 2 noise dBm? */
#define TAG_PEEKTAGGED_UNKNOWN_0x0013           0x0013  /* antenna 3 noise dBm? */
#define TAG_PEEKTAGGED_UNKNOWN_0x0014           0x0014  /* antenna 4 noise dBm? */
#define TAG_PEEKTAGGED_EXT_FLAGS                0x0015  /* Extended flags for 802.11n and beyond */

#define TAG_PEEKTAGGED_SLICE_LENGTH             0xffff

/*
 * Flags.
 *
 * We're assuming here that the "remote Peek" flags from bug 9586 are
 * the same as the "Peek tagged" flags.
 *
 * Are these the same as in "Peek classic"?  The first three are.
 */
#define FLAGS_CONTROL_FRAME     0x01    /* Frame is a control frame */
#define FLAGS_HAS_CRC_ERROR     0x02    /* Frame has a CRC error */
#define FLAGS_HAS_FRAME_ERROR   0x04    /* Frame has a frame error */

/*
 * Status.
 *
 * Is this in the next 8 bits of the "flags and status" field?
 */
#define STATUS_PROTECTED        0x0400  /* Frame is protected (encrypted) */
#define STATUS_DECRYPT_ERROR    0x0800  /* Error decrypting protected frame */
#define STATUS_SHORT_PREAMBLE   0x4000  /* Short preamble */

/*
 * Extended flags.
 *
 * Some determined from bug 10637, some determined from bug 9586,
 * and the ones present in both agree, so we're assuming that
 * the "remote Peek" protocol and the "Peek tagged" file format
 * use the same bits (which wouldn't be too surprising, as they
 * both come from Wildpackets).
 */
#define EXT_FLAG_20_MHZ_LOWER                   0x00000001
#define EXT_FLAG_20_MHZ_UPPER                   0x00000002
#define EXT_FLAG_40_MHZ                         0x00000004
#define EXT_FLAGS_BANDWIDTH                     0x00000007
#define EXT_FLAG_HALF_GI                        0x00000008
#define EXT_FLAG_FULL_GI                        0x00000010
#define EXT_FLAGS_GI                            0x00000018
#define EXT_FLAG_AMPDU                          0x00000020
#define EXT_FLAG_AMSDU                          0x00000040
#define EXT_FLAG_802_11ac                       0x00000080
#define EXT_FLAG_MCS_INDEX_USED                 0x00000100

/* 64-bit time in nanoseconds from the (Windows FILETIME) epoch */
typedef struct peektagged_utime {
        uint32_t upper;
        uint32_t lower;
} peektagged_utime;

typedef struct {
        bool            has_fcs;
} peektagged_t;

static bool peektagged_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset);
static bool peektagged_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info);

static int peektagged_file_type_subtype = -1;

void register_peektagged(void);

static int wtap_file_read_pattern (wtap *wth, const char *pattern, int *err,
                                char **err_info)
{
    int c;
    const char *cp;

    cp = pattern;
    while (*cp)
    {
        c = file_getc(wth->fh);
        if (c == EOF)
        {
            *err = file_error(wth->fh, err_info);
            if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
                return -1;      /* error */
            return 0;   /* EOF */
        }
        if (c == *cp)
            cp++;
        else
        {
            if (c == pattern[0])
                cp = &pattern[1];
            else
                cp = pattern;
        }
    }
    return (*cp == '\0' ? 1 : 0);
}


static int wtap_file_read_till_separator (wtap *wth, char *buffer, int buflen,
                                        const char *separators, int *err,
                                        char **err_info)
{
    int c;
    char *cp;
    int i;

    for (cp = buffer, i = 0; i < buflen; i++, cp++)
    {
        c = file_getc(wth->fh);
        if (c == EOF)
        {
            *err = file_error(wth->fh, err_info);
            if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
                return -1;      /* error */
            return 0;   /* EOF */
        }
        if (strchr (separators, c) != NULL)
        {
            *cp = '\0';
            break;
        }
        else
            *cp = c;
    }
    return i;
}


static int wtap_file_read_number (wtap *wth, uint32_t *num, int *err,
                                char **err_info)
{
    int ret;
    char str_num[12];
    unsigned long value;
    char *p;

    ret = wtap_file_read_till_separator (wth, str_num, sizeof (str_num)-1, "<",
                                         err, err_info);
    if (ret == 0 || ret == -1) {
        /* 0 means EOF, which means "not a valid Peek tagged file";
           -1 means error, and "err" has been set. */
        return ret;
    }
    value = strtoul (str_num, &p, 10);
    if (p == str_num || value > UINT32_MAX)
        return 0;
    *num = (uint32_t)value;
    return 1;
}


wtap_open_return_val peektagged_open(wtap *wth, int *err, char **err_info)
{
    peektagged_section_header_t ap_hdr;
    int ret;
    uint32_t fileVersion = 0;
    uint32_t mediaType;
    uint32_t mediaSubType = 0;
    int file_encap;
    static const int peektagged_encap[] = {
        WTAP_ENCAP_ETHERNET,
        WTAP_ENCAP_IEEE_802_11_WITH_RADIO,
        WTAP_ENCAP_IEEE_802_11_WITH_RADIO,
        WTAP_ENCAP_IEEE_802_11_WITH_RADIO
    };
    #define NUM_PEEKTAGGED_ENCAPS array_length(peektagged_encap)
    peektagged_t *peektagged;

    if (!wtap_read_bytes(wth->fh, &ap_hdr, (int)sizeof(ap_hdr), err, err_info)) {
        if (*err != WTAP_ERR_SHORT_READ)
            return WTAP_OPEN_ERROR;
        return WTAP_OPEN_NOT_MINE;
    }

    if (memcmp (ap_hdr.section_id, "\177ver", sizeof(ap_hdr.section_id)) != 0)
        return WTAP_OPEN_NOT_MINE;      /* doesn't begin with a "\177ver" section */

    /*
     * XXX - we should get the length of the "\177ver" section, check
     * that it's followed by a little-endian 0x00000200, and then,
     * when reading the XML, make sure we don't go past the end of
     * that section, and skip to the end of that section when
     * we have the file version (and possibly check to make sure all
     * tags are properly opened and closed).
     */
    ret = wtap_file_read_pattern (wth, "<FileVersion>", err, err_info);
    if (ret == -1)
        return WTAP_OPEN_ERROR;
    if (ret == 0) {
        /* 0 means EOF, which means "not a valid Peek tagged file" */
        return WTAP_OPEN_NOT_MINE;
    }
    ret = wtap_file_read_number (wth, &fileVersion, err, err_info);
    if (ret == -1)
        return WTAP_OPEN_ERROR;
    if (ret == 0) {
        /* 0 means EOF, which means "not a valid Peek tagged file" */
        return WTAP_OPEN_NOT_MINE;
    }

    /* If we got this far, we assume it's a Peek tagged file. */
    if (fileVersion != 9) {
        /* We only support version 9. */
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = ws_strdup_printf("peektagged: version %u unsupported",
            fileVersion);
        return WTAP_OPEN_ERROR;
    }

    /*
     * XXX - once we've skipped the "\177ver" section, we should
     * check for a "sess" section and fail if we don't see it.
     * Then we should get the length of the "sess" section, check
     * that it's followed by a little-endian 0x00000200, and then,
     * when reading the XML, make sure we don't go past the end of
     * that section, and skip to the end of the section when
     * we have the file version (and possibly check to make sure all
     * tags are properly opened and closed).
     */
    ret = wtap_file_read_pattern (wth, "<MediaType>", err, err_info);
    if (ret == -1)
        return WTAP_OPEN_ERROR;
    if (ret == 0) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("peektagged: <MediaType> tag not found");
        return WTAP_OPEN_ERROR;
    }
    /* XXX - this appears to be 0 in both the EtherPeek and AiroPeek
       files we've seen; should we require it to be 0? */
    ret = wtap_file_read_number (wth, &mediaType, err, err_info);
    if (ret == -1)
        return WTAP_OPEN_ERROR;
    if (ret == 0) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("peektagged: <MediaType> value not found");
        return WTAP_OPEN_ERROR;
    }

    ret = wtap_file_read_pattern (wth, "<MediaSubType>", err, err_info);
    if (ret == -1)
        return WTAP_OPEN_ERROR;
    if (ret == 0) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("peektagged: <MediaSubType> tag not found");
        return WTAP_OPEN_ERROR;
    }
    ret = wtap_file_read_number (wth, &mediaSubType, err, err_info);
    if (ret == -1)
        return WTAP_OPEN_ERROR;
    if (ret == 0) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("peektagged: <MediaSubType> value not found");
        return WTAP_OPEN_ERROR;
    }
    if (mediaSubType >= NUM_PEEKTAGGED_ENCAPS
        || peektagged_encap[mediaSubType] == WTAP_ENCAP_UNKNOWN) {
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = ws_strdup_printf("peektagged: network type %u unknown or unsupported",
            mediaSubType);
        return WTAP_OPEN_ERROR;
    }

    ret = wtap_file_read_pattern (wth, "pkts", err, err_info);
    if (ret == -1)
        return WTAP_OPEN_ERROR;
    if (ret == 0) {
        *err = WTAP_ERR_SHORT_READ;
        return WTAP_OPEN_ERROR;
    }

    /* skip 8 zero bytes */
    if (!wtap_read_bytes (wth->fh, NULL, 8, err, err_info)) {
        return WTAP_OPEN_ERROR;
    }

    /*
     * This is an Peek tagged file.
     */
    file_encap = peektagged_encap[mediaSubType];

    wth->file_type_subtype = peektagged_file_type_subtype;
    wth->file_encap = file_encap;
    wth->subtype_read = peektagged_read;
    wth->subtype_seek_read = peektagged_seek_read;
    wth->file_tsprec = WTAP_TSPREC_NSEC;

    peektagged = g_new(peektagged_t, 1);
    wth->priv = (void *)peektagged;
    switch (mediaSubType) {

    case PEEKTAGGED_NST_ETHERNET:
    case PEEKTAGGED_NST_802_11:
    case PEEKTAGGED_NST_802_11_2:
        peektagged->has_fcs = false;
        break;

    case PEEKTAGGED_NST_802_11_WITH_FCS:
        peektagged->has_fcs = true;
        break;
    }

    wth->snapshot_length   = 0; /* not available in header */

    /*
     * Add an IDB; we don't know how many interfaces were involved,
     * so we just say one interface, about which we only know
     * the link-layer type, snapshot length, and time stamp
     * resolution.
     */
    wtap_add_generated_idb(wth);

    return WTAP_OPEN_MINE;
}

/*
 * Read the packet.
 *
 * XXX - we should supply the additional radio information;
 * the pseudo-header should probably be supplied in a fashion
 * similar to the radiotap radio header, so that the 802.11
 * dissector can determine which, if any, information items
 * are present.
 */
static int
peektagged_read_packet(wtap *wth, FILE_T fh, wtap_rec *rec,
                       Buffer *buf, int *err, char **err_info)
{
    peektagged_t *peektagged = (peektagged_t *)wth->priv;
    bool read_a_tag = false;
    uint8_t tag_value[6];
    uint16_t tag;
    bool saw_length = false;
    uint32_t length = 0;
    uint32_t sliceLength = 0;
    bool saw_timestamp_lower = false;
    bool saw_timestamp_upper = false;
    bool saw_flags_and_status = false;
    peektagged_utime timestamp;
    uint32_t flags_and_status = 0;
    uint32_t ext_flags = 0;
    bool saw_data_rate_or_mcs_index = false;
    uint32_t data_rate_or_mcs_index = 0;
    int channel;
    unsigned frequency;
    struct ieee_802_11_phdr ieee_802_11 = {0};
    unsigned i;
    int skip_len = 0;
    uint64_t t;

    timestamp.upper = 0;
    timestamp.lower = 0;
    ieee_802_11.fcs_len = -1; /* Unknown */
    ieee_802_11.decrypted = false;
    ieee_802_11.datapad = false;
    ieee_802_11.phy = PHDR_802_11_PHY_UNKNOWN;

    /* Extract the fields from the packet header */
    do {
        /* Get the tag and value.
           XXX - this assumes all values are 4 bytes long. */
        if (!wtap_read_bytes_or_eof(fh, tag_value, sizeof tag_value, err, err_info)) {
            if (*err == 0) {
                /*
                 * Short read if we've read something already;
                 * just an EOF if we haven't.
                 */
                if (read_a_tag)
                    *err = WTAP_ERR_SHORT_READ;
            }
            return -1;
        }
        read_a_tag = true;
        tag = pletoh16(&tag_value[0]);
        switch (tag) {

        case TAG_PEEKTAGGED_LENGTH:
            if (saw_length) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup("peektagged: record has two length fields");
                return -1;
            }
            length = pletoh32(&tag_value[2]);
            saw_length = true;
            break;

        case TAG_PEEKTAGGED_TIMESTAMP_LOWER:
            if (saw_timestamp_lower) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup("peektagged: record has two timestamp-lower fields");
                return -1;
            }
            timestamp.lower = pletoh32(&tag_value[2]);
            saw_timestamp_lower = true;
            break;

        case TAG_PEEKTAGGED_TIMESTAMP_UPPER:
            if (saw_timestamp_upper) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup("peektagged: record has two timestamp-upper fields");
                return -1;
            }
            timestamp.upper = pletoh32(&tag_value[2]);
            saw_timestamp_upper = true;
            break;

        case TAG_PEEKTAGGED_FLAGS_AND_STATUS:
            saw_flags_and_status = true;
            flags_and_status = pletoh32(&tag_value[2]);
            break;

        case TAG_PEEKTAGGED_CHANNEL:
            ieee_802_11.has_channel = true;
            ieee_802_11.channel = pletoh32(&tag_value[2]);
            break;

        case TAG_PEEKTAGGED_DATA_RATE_OR_MCS_INDEX:
            data_rate_or_mcs_index = pletoh32(&tag_value[2]);
            saw_data_rate_or_mcs_index = true;
            break;

        case TAG_PEEKTAGGED_SIGNAL_PERC:
            ieee_802_11.has_signal_percent = true;
            ieee_802_11.signal_percent = pletoh32(&tag_value[2]);
            break;

        case TAG_PEEKTAGGED_SIGNAL_DBM:
            ieee_802_11.has_signal_dbm = true;
            ieee_802_11.signal_dbm = pletoh32(&tag_value[2]);
            break;

        case TAG_PEEKTAGGED_NOISE_PERC:
            ieee_802_11.has_noise_percent = true;
            ieee_802_11.noise_percent = pletoh32(&tag_value[2]);
            break;

        case TAG_PEEKTAGGED_NOISE_DBM:
            ieee_802_11.has_noise_dbm = true;
            ieee_802_11.noise_dbm = pletoh32(&tag_value[2]);
            break;

        case TAG_PEEKTAGGED_UNKNOWN_0x000A:
            /*
             * XXX - seen in some 802.11 captures.
             * Always seems to have the value 0 or 5.
             */
            break;

        case TAG_PEEKTAGGED_CENTER_FREQUENCY:
            /* XXX - also seen in an EtherPeek capture; value unknown */
            ieee_802_11.has_frequency = true;
            ieee_802_11.frequency = pletoh32(&tag_value[2]);
            break;

        case TAG_PEEKTAGGED_UNKNOWN_0x000E:
            /*
             * XXX - seen in some 802.11 captures.
             * Usually has the value 4, but, in some packets, has the
             * values 6 or 302.
             *
             * Is this the mysterious "band" field that shows up in
             * some "Peek remote" protocol captures, with values in
             * the 30x or 40x ranges?  It's not always associated
             * with the "extended flags" tag for HT/VHT information,
             * so it's probably not 11n/11ac-specific.  Values other
             * than 4 appear, in my captures, only in packets with
             * the "extended flags" tag.  302 appeared in a packet
             * with EXT_FLAG_MCS_INDEX_USED; 6 appeared in packets
             * without EXT_FLAG_MCS_INDEX_USED.
             */
            break;

        case TAG_PEEKTAGGED_UNKNOWN_0x000F:
            /*
             * XXX - seen in some 802.11 captures; dB or dBm value?
             * Multiple antennas?
             */
            break;

        case TAG_PEEKTAGGED_UNKNOWN_0x0010:
            /*
             * XXX - seen in some 802.11 captures; dB or dBm value?
             * Multiple antennas?
             */
            break;

        case TAG_PEEKTAGGED_UNKNOWN_0x0011:
            /*
             * XXX - seen in some 802.11 captures; dB or dBm value?
             * Multiple antennas?
             */
            break;

        case TAG_PEEKTAGGED_UNKNOWN_0x0012:
            /*
             * XXX - seen in some 802.11 captures; dB or dBm value?
             * Multiple antennas?
             */
            break;

        case TAG_PEEKTAGGED_UNKNOWN_0x0013:
            /*
             * XXX - seen in some 802.11 captures; dB or dBm value?
             * Multiple antennas?
             */
            break;

        case TAG_PEEKTAGGED_UNKNOWN_0x0014:
            /*
             * XXX - seen in some 802.11 captures; dB or dBm value?
             * Multiple antennas?
             */
            break;

        case TAG_PEEKTAGGED_EXT_FLAGS:
            /*
             * We assume this is present for HT and VHT frames and absent
             * for other frames.
             */
            ext_flags = pletoh32(&tag_value[2]);
            if (ext_flags & EXT_FLAG_802_11ac) {
                ieee_802_11.phy = PHDR_802_11_PHY_11AC;
                /*
                 * XXX - this probably has only one user, so only
                 * one MCS index and only one NSS, but where's the
                 * NSS?
                 */
                for (i = 0; i < 4; i++)
                    ieee_802_11.phy_info.info_11ac.nss[i] = 0;

                switch (ext_flags & EXT_FLAGS_GI) {

                case EXT_FLAG_HALF_GI:
                    ieee_802_11.phy_info.info_11ac.has_short_gi = true;
                    ieee_802_11.phy_info.info_11ac.short_gi = 1;
                    break;

                case EXT_FLAG_FULL_GI:
                    ieee_802_11.phy_info.info_11ac.has_short_gi = true;
                    ieee_802_11.phy_info.info_11ac.short_gi = 0;
                    break;

                default:
                    /* Mutually exclusive flags set or nothing set */
                    break;
                }
            } else {
                ieee_802_11.phy = PHDR_802_11_PHY_11N;
                switch (ext_flags & EXT_FLAGS_BANDWIDTH) {

                case 0:
                    ieee_802_11.phy_info.info_11n.has_bandwidth = true;
                    ieee_802_11.phy_info.info_11n.bandwidth = PHDR_802_11_BANDWIDTH_20_MHZ;
                    break;

                case EXT_FLAG_20_MHZ_LOWER:
                    ieee_802_11.phy_info.info_11n.has_bandwidth = true;
                    ieee_802_11.phy_info.info_11n.bandwidth = PHDR_802_11_BANDWIDTH_20_20L;
                    break;

                case EXT_FLAG_20_MHZ_UPPER:
                    ieee_802_11.phy_info.info_11n.has_bandwidth = true;
                    ieee_802_11.phy_info.info_11n.bandwidth = PHDR_802_11_BANDWIDTH_20_20U;
                    break;

                case EXT_FLAG_40_MHZ:
                    ieee_802_11.phy_info.info_11n.has_bandwidth = true;
                    ieee_802_11.phy_info.info_11n.bandwidth = PHDR_802_11_BANDWIDTH_40_MHZ;
                    break;

                default:
                    /* Mutually exclusive flags set */
                    break;
                }

                switch (ext_flags & EXT_FLAGS_GI) {

                case EXT_FLAG_HALF_GI:
                    ieee_802_11.phy_info.info_11n.has_short_gi = true;
                    ieee_802_11.phy_info.info_11n.short_gi = 1;
                    break;

                case EXT_FLAG_FULL_GI:
                    ieee_802_11.phy_info.info_11n.has_short_gi = true;
                    ieee_802_11.phy_info.info_11n.short_gi = 0;
                    break;

                default:
                    /* Mutually exclusive flags set or nothing set */
                    break;
                }
            }
            break;

        case TAG_PEEKTAGGED_SLICE_LENGTH:
            sliceLength = pletoh32(&tag_value[2]);
            break;

        default:
            break;
        }
    } while (tag != TAG_PEEKTAGGED_SLICE_LENGTH);       /* last tag */

    if (!saw_length) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("peektagged: record has no length field");
        return -1;
    }
    if (!saw_timestamp_lower) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("peektagged: record has no timestamp-lower field");
        return -1;
    }
    if (!saw_timestamp_upper) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("peektagged: record has no timestamp-upper field");
        return -1;
    }

    /*
     * If sliceLength is 0, force it to be the actual length of the packet.
     */
    if (sliceLength == 0)
        sliceLength = length;

    if (sliceLength > WTAP_MAX_PACKET_SIZE_STANDARD) {
        /*
         * Probably a corrupt capture file; don't blow up trying
         * to allocate space for an immensely-large packet.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("peektagged: File has %u-byte packet, bigger than maximum of %u",
            sliceLength, WTAP_MAX_PACKET_SIZE_STANDARD);
        return -1;
    }

    rec->rec_type = REC_TYPE_PACKET;
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
    rec->rec_header.packet_header.len    = length;
    rec->rec_header.packet_header.caplen = sliceLength;
    if (saw_flags_and_status) {
        uint32_t flags = 0;
        if (flags_and_status & FLAGS_HAS_CRC_ERROR)
            flags |= PACK_FLAGS_CRC_ERROR;
        wtap_block_add_uint32_option(rec->block, OPT_PKT_FLAGS, flags);
    }

    /* calculate and fill in packet time stamp */
    t = (((uint64_t) timestamp.upper) << 32) + timestamp.lower;
    if (!nsfiletime_to_nstime(&rec->ts, t)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("peektagged: time stamp outside supported range");
        return -1;
    }

    switch (wth->file_encap) {

    case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
        if (saw_data_rate_or_mcs_index) {
            if (ext_flags & EXT_FLAG_MCS_INDEX_USED) {
                /*
                 * It's an MCS index.
                 *
                 * XXX - what about 11ac?
                 */
                if (!(ext_flags & EXT_FLAG_802_11ac)) {
                    ieee_802_11.phy_info.info_11n.has_mcs_index = true;
                    ieee_802_11.phy_info.info_11n.mcs_index = data_rate_or_mcs_index;
                }
            } else {
                /* It's a data rate. */
                ieee_802_11.has_data_rate = true;
                ieee_802_11.data_rate = data_rate_or_mcs_index;
                if (ieee_802_11.phy == PHDR_802_11_PHY_UNKNOWN) {
                  /*
                   * We don't know they PHY; try to guess it based
                   * on the data rate and channel/center frequency.
                   */
                  if (RATE_IS_DSSS(ieee_802_11.data_rate)) {
                    /* 11b */
                    ieee_802_11.phy = PHDR_802_11_PHY_11B;
                    if (saw_flags_and_status) {
                      ieee_802_11.phy_info.info_11b.has_short_preamble = true;
                      ieee_802_11.phy_info.info_11b.short_preamble =
                          (flags_and_status & STATUS_SHORT_PREAMBLE) ? true : false;
                    } else
                      ieee_802_11.phy_info.info_11b.has_short_preamble = false;
                  } else if (RATE_IS_OFDM(ieee_802_11.data_rate)) {
                    /* 11a or 11g, depending on the band. */
                    if (ieee_802_11.has_channel) {
                      if (CHAN_IS_BG(ieee_802_11.channel)) {
                        /* 11g */
                        ieee_802_11.phy = PHDR_802_11_PHY_11G;
                      } else {
                        /* 11a */
                        ieee_802_11.phy = PHDR_802_11_PHY_11A;
                      }
                    } else if (ieee_802_11.has_frequency) {
                      if (FREQ_IS_BG(ieee_802_11.frequency)) {
                        /* 11g */
                        ieee_802_11.phy = PHDR_802_11_PHY_11G;
                      } else {
                        /* 11a */
                        ieee_802_11.phy = PHDR_802_11_PHY_11A;
                      }
                    }
                    if (ieee_802_11.phy == PHDR_802_11_PHY_11G) {
                      /* Set 11g metadata */
                      ieee_802_11.phy_info.info_11g.has_mode = false;
                    } else if (ieee_802_11.phy == PHDR_802_11_PHY_11A) {
                      /* Set 11a metadata */
                      ieee_802_11.phy_info.info_11a.has_channel_type = false;
                      ieee_802_11.phy_info.info_11a.has_turbo_type = false;
                    }
                    /* Otherwise we don't know the PHY */
                  }
                }
            }
        }
        if (ieee_802_11.has_frequency && !ieee_802_11.has_channel) {
            /* Frequency, but no channel; try to calculate the channel. */
            channel = ieee80211_mhz_to_chan(ieee_802_11.frequency);
            if (channel != -1) {
                ieee_802_11.has_channel = true;
                ieee_802_11.channel = channel;
            }
        } else if (ieee_802_11.has_channel && !ieee_802_11.has_frequency) {
            /*
             * If it's 11 legacy DHSS, 11b, or 11g, it's 2.4 GHz,
             * so we can calculate the frequency.
             *
             * If it's 11a, it's 5 GHz, so we can calculate the
             * frequency.
             */
            switch (ieee_802_11.phy) {

            case PHDR_802_11_PHY_11_DSSS:
            case PHDR_802_11_PHY_11B:
            case PHDR_802_11_PHY_11G:
                frequency = ieee80211_chan_to_mhz(ieee_802_11.channel, true);
                break;

            case PHDR_802_11_PHY_11A:
                frequency = ieee80211_chan_to_mhz(ieee_802_11.channel, false);
                break;

            default:
                /* We don't know the band. */
                frequency = 0;
                break;
            }
            if (frequency != 0) {
                ieee_802_11.has_frequency = true;
                ieee_802_11.frequency = frequency;
            }
        }
        rec->rec_header.packet_header.pseudo_header.ieee_802_11 = ieee_802_11;
        if (peektagged->has_fcs)
            rec->rec_header.packet_header.pseudo_header.ieee_802_11.fcs_len = 4;
        else {
            if (rec->rec_header.packet_header.len < 4 || rec->rec_header.packet_header.caplen < 4) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("peektagged: 802.11 packet has length < 4");
                return false;
            }
            rec->rec_header.packet_header.pseudo_header.ieee_802_11.fcs_len = 0;
            rec->rec_header.packet_header.len -= 4;
            rec->rec_header.packet_header.caplen -= 4;
            skip_len = 4;
        }
        rec->rec_header.packet_header.pseudo_header.ieee_802_11.decrypted = false;
        rec->rec_header.packet_header.pseudo_header.ieee_802_11.datapad = false;
        break;

    case WTAP_ENCAP_ETHERNET:
        /*
         * The last 4 bytes appear to be 0 in the captures I've seen;
         * are there any captures where it's an FCS?
         */
        if (rec->rec_header.packet_header.len < 4 || rec->rec_header.packet_header.caplen < 4) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("peektagged: Ethernet packet has length < 4");
            return false;
        }
        rec->rec_header.packet_header.pseudo_header.eth.fcs_len = 0;
        rec->rec_header.packet_header.len -= 4;
        rec->rec_header.packet_header.caplen -= 4;
        skip_len = 4;
        break;
    }

    /* Read the packet data. */
    if (!wtap_read_packet_bytes(fh, buf, rec->rec_header.packet_header.caplen, err, err_info))
        return -1;

    return skip_len;
}

static bool peektagged_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset)
{
    int skip_len;

    *data_offset = file_tell(wth->fh);

    /* Read the packet. */
    skip_len = peektagged_read_packet(wth, wth->fh, rec, buf, err, err_info);
    if (skip_len == -1)
        return false;

    if (skip_len != 0) {
        /* Skip extra junk at the end of the packet data. */
        if (!wtap_read_bytes(wth->fh, NULL, skip_len, err, err_info))
            return false;
    }

    return true;
}

static bool
peektagged_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return false;

    /* Read the packet. */
    if (peektagged_read_packet(wth, wth->random_fh, rec, buf, err, err_info) == -1) {
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return false;
    }
    return true;
}

static const struct supported_block_type peektagged_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info peektagged_info = {
    "Savvius tagged", "peektagged", "pkt", "tpc;apc;wpz",
    false, BLOCKS_SUPPORTED(peektagged_blocks_supported),
    NULL, NULL, NULL
};

void register_peektagged(void)
{
    peektagged_file_type_subtype = wtap_register_file_type_subtype(&peektagged_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("PEEKTAGGED",
                                                   peektagged_file_type_subtype);
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
