/* pcapio.c
 * Our own private code for writing libpcap files when capturing.
 *
 * We have these because we want a way to open a stream for output given
 * only a file descriptor.  libpcap 0.9[.x] has "pcap_dump_fopen()", which
 * provides that, but
 *
 *      1) earlier versions of libpcap doesn't have it
 *
 * and
 *
 *      2) WinPcap/Npcap don't have it, because a file descriptor opened
 *         by code built for one version of the MSVC++ C library
 *         can't be used by library routines built for another version
 *         (e.g., threaded vs. unthreaded).
 *
 * Libpcap's pcap_dump() also doesn't return any error indications.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Derived from code in the Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef _WIN32
#include <Windows.h>
#endif

#include <glib.h>

#include <wsutil/epochs.h>

#include "pcapio.h"

/* Magic numbers in "libpcap" files.

   "libpcap" file records are written in the byte order of the host that
   writes them, and the reader is expected to fix this up.

   PCAP_MAGIC is the magic number, in host byte order; PCAP_SWAPPED_MAGIC
   is a byte-swapped version of that.

   PCAP_NSEC_MAGIC is for Ulf Lamping's modified "libpcap" format,
   which uses the same common file format as PCAP_MAGIC, but the
   timestamps are saved in nanosecond resolution instead of microseconds.
   PCAP_SWAPPED_NSEC_MAGIC is a byte-swapped version of that. */
#define PCAP_MAGIC                      0xa1b2c3d4
#define PCAP_SWAPPED_MAGIC              0xd4c3b2a1
#define PCAP_NSEC_MAGIC                 0xa1b23c4d
#define PCAP_SWAPPED_NSEC_MAGIC         0x4d3cb2a1

/* "libpcap" file header. */
struct pcap_hdr {
        guint32 magic;          /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
};

/* "libpcap" record header. */
struct pcaprec_hdr {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds (nsecs for PCAP_NSEC_MAGIC) */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
};

/* Magic numbers in ".pcapng" files.
 *
 * .pcapng file records are written in the byte order of the host that
 * writes them, and the reader is expected to fix this up.
 * PCAPNG_MAGIC is the magic number, in host byte order;
 * PCAPNG_SWAPPED_MAGIC is a byte-swapped version of that.
 */
#define PCAPNG_MAGIC         0x1A2B3C4D
#define PCAPNG_SWAPPED_MAGIC 0x4D3C2B1A

/* Currently we are only supporting the initial version of
   the file format. */
#define PCAPNG_MAJOR_VERSION 1
#define PCAPNG_MINOR_VERSION 0

/* Section Header Block without options and trailing Block Total Length */
struct shb {
        guint32 block_type;
        guint32 block_total_length;
        guint32 byte_order_magic;
        guint16 major_version;
        guint16 minor_version;
        guint64 section_length;
};
#define SECTION_HEADER_BLOCK_TYPE 0x0A0D0D0A

/* Interface Description Block without options and trailing Block Total Length */
struct idb {
        guint32 block_type;
        guint32 block_total_length;
        guint16 link_type;
        guint16 reserved;
        guint32 snap_len;
};
#define INTERFACE_DESCRIPTION_BLOCK_TYPE 0x00000001

/* Interface Statistics Block without actual packet, options, and trailing
   Block Total Length */
struct isb {
        guint32 block_type;
        guint32 block_total_length;
        guint32 interface_id;
        guint32 timestamp_high;
        guint32 timestamp_low;
};
#define INTERFACE_STATISTICS_BLOCK_TYPE 0x00000005

/* Enhanced Packet Block without actual packet, options, and trailing
   Block Total Length */
struct epb {
        guint32 block_type;
        guint32 block_total_length;
        guint32 interface_id;
        guint32 timestamp_high;
        guint32 timestamp_low;
        guint32 captured_len;
        guint32 packet_len;
};
#define ENHANCED_PACKET_BLOCK_TYPE 0x00000006

struct option {
        guint16 type;
        guint16 value_length;
};
#define OPT_ENDOFOPT      0
#define OPT_COMMENT       1
#define EPB_FLAGS         2
#define SHB_HARDWARE      2 /* currently not used */
#define SHB_OS            3
#define SHB_USERAPPL      4
#define IDB_NAME          2
#define IDB_DESCRIPTION   3
#define IDB_IF_SPEED      8
#define IDB_TSRESOL       9
#define IDB_FILTER       11
#define IDB_OS           12
#define IDB_HARDWARE     15
#define ISB_STARTTIME     2
#define ISB_ENDTIME       3
#define ISB_IFRECV        4
#define ISB_IFDROP        5
#define ISB_FILTERACCEPT  6
#define ISB_OSDROP        7
#define ISB_USRDELIV      8
#define ADD_PADDING(x) ((((x) + 3) >> 2) << 2)

/* Write to capture file */
static gboolean
write_to_file(FILE* pfile, const guint8* data, size_t data_length,
              guint64 *bytes_written, int *err)
{
        size_t nwritten;

        nwritten = fwrite(data, data_length, 1, pfile);
        if (nwritten != 1) {
                if (ferror(pfile)) {
                        *err = errno;
                } else {
                        *err = 0;
                }
                return FALSE;
        }

        (*bytes_written) += data_length;
        return TRUE;
}

/* Writing pcap files */

/* Write the file header to a dump file.
   Returns TRUE on success, FALSE on failure.
   Sets "*err" to an error code, or 0 for a short write, on failure*/
gboolean
libpcap_write_file_header(FILE* pfile, int linktype, int snaplen, gboolean ts_nsecs, guint64 *bytes_written, int *err)
{
        struct pcap_hdr file_hdr;

        file_hdr.magic = ts_nsecs ? PCAP_NSEC_MAGIC : PCAP_MAGIC;
        /* current "libpcap" format is 2.4 */
        file_hdr.version_major = 2;
        file_hdr.version_minor = 4;
        file_hdr.thiszone = 0;  /* XXX - current offset? */
        file_hdr.sigfigs = 0;   /* unknown, but also apparently unused */
        file_hdr.snaplen = snaplen;
        file_hdr.network = linktype;

        return write_to_file(pfile, (const guint8*)&file_hdr, sizeof(file_hdr), bytes_written, err);
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
gboolean
libpcap_write_packet(FILE* pfile,
                     time_t sec, guint32 usec,
                     guint32 caplen, guint32 len,
                     const guint8 *pd,
                     guint64 *bytes_written, int *err)
{
        struct pcaprec_hdr rec_hdr;

        rec_hdr.ts_sec = (guint32)sec; /* Y2.038K issue in pcap format.... */
        rec_hdr.ts_usec = usec;
        rec_hdr.incl_len = caplen;
        rec_hdr.orig_len = len;
        if (!write_to_file(pfile, (const guint8*)&rec_hdr, sizeof(rec_hdr), bytes_written, err))
                return FALSE;

        return write_to_file(pfile, pd, caplen, bytes_written, err);
}

/* Writing pcapng files */

static guint32
pcapng_count_string_option(const char *option_value)
{
        if ((option_value != NULL) && (strlen(option_value) > 0) && (strlen(option_value) < G_MAXUINT16)) {
                /* There's a value to write; get its length */
                return (guint32)(sizeof(struct option) +
                                 (guint16)ADD_PADDING(strlen(option_value)));
        }
        return 0; /* nothing to write */
}

static gboolean
pcapng_write_string_option(FILE* pfile,
                           guint16 option_type, const char *option_value,
                           guint64 *bytes_written, int *err)
{
        size_t option_value_length;
        struct option option;
        const guint32 padding = 0;

        if (option_value == NULL)
                return TRUE; /* nothing to write */
        option_value_length = strlen(option_value);
        if ((option_value_length > 0) && (option_value_length < G_MAXUINT16)) {
                /* something to write */
                option.type = option_type;
                option.value_length = (guint16)option_value_length;

                if (!write_to_file(pfile, (const guint8*)&option, sizeof(struct option), bytes_written, err))
                        return FALSE;

                if (!write_to_file(pfile, (const guint8*)option_value, (int) option_value_length, bytes_written, err))
                        return FALSE;

                if (option_value_length % 4) {
                        if (!write_to_file(pfile, (const guint8*)&padding, 4 - option_value_length % 4, bytes_written, err))
                                return FALSE;
                }
        }
        return TRUE;
}

/* Write a pre-formatted pcapng block directly to the output file */
gboolean
pcapng_write_block(FILE* pfile,
                   const guint8 *data,
                   guint32 length,
                   guint64 *bytes_written,
                   int *err)
{
    guint32 block_length, end_length;
    /* Check
     * - length and data are aligned to 4 bytes
     * - block_total_length field is the same at the start and end of the block
     *
     * The block_total_length is not checked against the provided length but
     * getting the trailing block_total_length from the length argument gives
     * us an implicit check of correctness without needing to do an endian swap
     */
    if (((length & 3) != 0) || (((gintptr)data & 3) != 0)) {
        *err = EINVAL;
        return FALSE;
    }
    block_length = *(const guint32 *) (data+sizeof(guint32));
    end_length = *(const guint32 *) (data+length-sizeof(guint32));
    if (block_length != end_length) {
        *err = EBADMSG;
        return FALSE;
    }
    return write_to_file(pfile, data, length, bytes_written, err);
}

gboolean
pcapng_write_section_header_block(FILE* pfile,
                                  const char *comment,
                                  const char *hw,
                                  const char *os,
                                  const char *appname,
                                  guint64 section_length,
                                  guint64 *bytes_written,
                                  int *err)
{
        struct shb shb;
        struct option option;
        guint32 block_total_length;
        guint32 options_length;

        /* Size of base header */
        block_total_length = sizeof(struct shb) +
                             sizeof(guint32);
        options_length = 0;
        options_length += pcapng_count_string_option(comment);
        options_length += pcapng_count_string_option(hw);
        options_length += pcapng_count_string_option(os);
        options_length += pcapng_count_string_option(appname);
        /* If we have options add size of end-of-options */
        if (options_length != 0) {
                options_length += (guint32)sizeof(struct option);
        }
        block_total_length += options_length;

        /* write shb header */
        shb.block_type = SECTION_HEADER_BLOCK_TYPE;
        shb.block_total_length = block_total_length;
        shb.byte_order_magic = PCAPNG_MAGIC;
        shb.major_version = PCAPNG_MAJOR_VERSION;
        shb.minor_version = PCAPNG_MINOR_VERSION;
        shb.section_length = section_length;

        if (!write_to_file(pfile, (const guint8*)&shb, sizeof(struct shb), bytes_written, err))
                return FALSE;

        if (!pcapng_write_string_option(pfile, OPT_COMMENT, comment,
                                        bytes_written, err))
                return FALSE;
        if (!pcapng_write_string_option(pfile, SHB_HARDWARE, hw,
                                        bytes_written, err))
                return FALSE;
        if (!pcapng_write_string_option(pfile, SHB_OS, os,
                                        bytes_written, err))
                return FALSE;
        if (!pcapng_write_string_option(pfile, SHB_USERAPPL, appname,
                                        bytes_written, err))
                return FALSE;
        if (options_length != 0) {
                /* write end of options */
                option.type = OPT_ENDOFOPT;
                option.value_length = 0;
                if (!write_to_file(pfile, (const guint8*)&option, sizeof(struct option), bytes_written, err))
                        return FALSE;
        }

        /* write the trailing block total length */
        return write_to_file(pfile, (const guint8*)&block_total_length, sizeof(guint32), bytes_written, err);
}

gboolean
pcapng_write_interface_description_block(FILE* pfile,
                                         const char *comment,  /* OPT_COMMENT        1 */
                                         const char *name,     /* IDB_NAME           2 */
                                         const char *descr,    /* IDB_DESCRIPTION    3 */
                                         const char *filter,   /* IDB_FILTER        11 */
                                         const char *os,       /* IDB_OS            12 */
                                         const char *hardware, /* IDB_HARDWARE      15 */
                                         int link_type,
                                         int snap_len,
                                         guint64 *bytes_written,
                                         guint64 if_speed,     /* IDB_IF_SPEED       8 */
                                         guint8 tsresol,       /* IDB_TSRESOL        9 */
                                         int *err)
{
        struct idb idb;
        struct option option;
        guint32 block_total_length;
        guint32 options_length;
        const guint32 padding = 0;

        block_total_length = (guint32)(sizeof(struct idb) + sizeof(guint32));
        options_length = 0;
        /* 01 - OPT_COMMENT */
        options_length += pcapng_count_string_option(comment);

        /* 02 - IDB_NAME */
        options_length += pcapng_count_string_option(name);

        /* 03 - IDB_DESCRIPTION */
        options_length += pcapng_count_string_option(descr);

        /* 08 - IDB_IF_SPEED */
        if (if_speed != 0) {
                options_length += (guint32)(sizeof(struct option) +
                                            sizeof(guint64));
        }

        /* 09 - IDB_TSRESOL */
        if (tsresol != 0) {
                options_length += (guint32)(sizeof(struct option) +
                                            sizeof(struct option));
        }

        /* 11 - IDB_FILTER */
        if ((filter != NULL) && (strlen(filter) > 0) && (strlen(filter) < G_MAXUINT16)) {
                /* No, this isn't a string, it has an extra type byte */
                options_length += (guint32)(sizeof(struct option) +
                                            (guint16)(ADD_PADDING(strlen(filter)+ 1)));
        }

        /* 12 - IDB_OS */
        options_length += pcapng_count_string_option(os);

        /* 15 - IDB_HARDWARE */
        options_length += pcapng_count_string_option(hardware);

        /* If we have options add size of end-of-options */
        if (options_length != 0) {
                options_length += (guint32)sizeof(struct option);
        }
        block_total_length += options_length;

        /* write block header */
        idb.block_type = INTERFACE_DESCRIPTION_BLOCK_TYPE;
        idb.block_total_length = block_total_length;
        idb.link_type = link_type;
        idb.reserved = 0;
        idb.snap_len = snap_len;
        if (!write_to_file(pfile, (const guint8*)&idb, sizeof(struct idb), bytes_written, err))
                return FALSE;

        /* 01 - OPT_COMMENT - write comment string if applicable */
        if (!pcapng_write_string_option(pfile, OPT_COMMENT, comment,
                                        bytes_written, err))
                return FALSE;

        /* 02 - IDB_NAME - write interface name string if applicable */
        if (!pcapng_write_string_option(pfile, IDB_NAME, name,
                                        bytes_written, err))
                return FALSE;

        /* 03 - IDB_DESCRIPTION */
        /* write interface description string if applicable */
        if (!pcapng_write_string_option(pfile, IDB_DESCRIPTION, descr,
                                        bytes_written, err))
                return FALSE;

        /* 08 - IDB_IF_SPEED */
        if (if_speed != 0) {
                option.type = IDB_IF_SPEED;
                option.value_length = sizeof(guint64);

                if (!write_to_file(pfile, (const guint8*)&option, sizeof(struct option), bytes_written, err))
                        return FALSE;

                if (!write_to_file(pfile, (const guint8*)&if_speed, sizeof(guint64), bytes_written, err))
                        return FALSE;
        }

        /* 09 - IDB_TSRESOL */
        if (tsresol != 0) {
                option.type = IDB_TSRESOL;
                option.value_length = sizeof(guint8);

                if (!write_to_file(pfile, (const guint8*)&option, sizeof(struct option), bytes_written, err))
                        return FALSE;

                if (!write_to_file(pfile, (const guint8*)&tsresol, sizeof(guint8), bytes_written, err))
                        return FALSE;

                if (!write_to_file(pfile, (const guint8*)&padding, 3, bytes_written, err))
                        return FALSE;
        }

        /* 11 - IDB_FILTER - write filter string if applicable
         * We only write version 1 of the filter, pcapng string
         */
        if ((filter != NULL) && (strlen(filter) > 0) && (strlen(filter) < G_MAXUINT16 - 1)) {
                option.type = IDB_FILTER;
                option.value_length = (guint16)(strlen(filter) + 1 );
                if (!write_to_file(pfile, (const guint8*)&option, sizeof(struct option), bytes_written, err))
                        return FALSE;

                /* The first byte of the Option Data keeps a code of the filter used, 0 = lipbpcap filter string */
                if (!write_to_file(pfile, (const guint8*)&padding, 1, bytes_written, err))
                        return FALSE;
                if (!write_to_file(pfile, (const guint8*)filter, (int) strlen(filter), bytes_written, err))
                        return FALSE;
                if ((strlen(filter) + 1) % 4) {
                        if (!write_to_file(pfile, (const guint8*)&padding, 4 - (strlen(filter) + 1) % 4, bytes_written, err))
                                return FALSE;
                }
        }

        /* 12 - IDB_OS - write os string if applicable */
        if (!pcapng_write_string_option(pfile, IDB_OS, os,
                                        bytes_written, err))
                return FALSE;

        /* 15 - IDB_HARDWARE - write hardware string if applicable */
        if (!pcapng_write_string_option(pfile, IDB_HARDWARE, hardware,
                                        bytes_written, err))
                return FALSE;

        if (options_length != 0) {
                /* write end of options */
                option.type = OPT_ENDOFOPT;
                option.value_length = 0;
                if (!write_to_file(pfile, (const guint8*)&option, sizeof(struct option), bytes_written, err))
                        return FALSE;
        }

        /* write the trailing Block Total Length */
        return write_to_file(pfile, (const guint8*)&block_total_length, sizeof(guint32), bytes_written, err);
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
gboolean
pcapng_write_enhanced_packet_block(FILE* pfile,
                                   const char *comment,
                                   time_t sec, guint32 usec,
                                   guint32 caplen, guint32 len,
                                   guint32 interface_id,
                                   guint ts_mul,
                                   const guint8 *pd,
                                   guint32 flags,
                                   guint64 *bytes_written,
                                   int *err)
{
        struct epb epb;
        struct option option;
        guint32 block_total_length;
        guint64 timestamp;
        guint32 options_length;
        const guint32 padding = 0;
        guint8 buff[8];
        guint8 i;
        guint8 pad_len = 0;

        block_total_length = (guint32)(sizeof(struct epb) +
                                       ADD_PADDING(caplen) +
                                       sizeof(guint32));
        options_length = 0;
        options_length += pcapng_count_string_option(comment);
        if (flags != 0) {
                options_length += (guint32)(sizeof(struct option) +
                                            sizeof(guint32));
        }
        /* If we have options add size of end-of-options */
        if (options_length != 0) {
                options_length += (guint32)sizeof(struct option);
        }
        block_total_length += options_length;
        timestamp = (guint64)sec * ts_mul + (guint64)usec;
        epb.block_type = ENHANCED_PACKET_BLOCK_TYPE;
        epb.block_total_length = block_total_length;
        epb.interface_id = interface_id;
        epb.timestamp_high = (guint32)((timestamp>>32) & 0xffffffff);
        epb.timestamp_low = (guint32)(timestamp & 0xffffffff);
        epb.captured_len = caplen;
        epb.packet_len = len;
        if (!write_to_file(pfile, (const guint8*)&epb, sizeof(struct epb), bytes_written, err))
                return FALSE;
        if (!write_to_file(pfile, pd, caplen, bytes_written, err))
                return FALSE;
        /* Use more efficient write in case of no "extras" */
        if(caplen % 4) {
            pad_len = 4 - (caplen % 4);
        }
        /*
         * If we have no options to write, just write out the padding and
         * the block total length with one fwrite() call.
         */
        if(!comment && flags == 0 && options_length==0){
            /* Put padding in the buffer */
            for (i = 0; i < pad_len; i++) {
                buff[i] = 0;
            }
            /* Write the total length */
            memcpy(&buff[i], &block_total_length, sizeof(guint32));
            i += sizeof(guint32);
            return write_to_file(pfile, (const guint8*)&buff, i, bytes_written, err);
        }
        if (pad_len) {
                if (!write_to_file(pfile, (const guint8*)&padding, pad_len, bytes_written, err))
                        return FALSE;
        }
        if (!pcapng_write_string_option(pfile, OPT_COMMENT, comment,
                                        bytes_written, err))
                return FALSE;
        if (flags != 0) {
                option.type = EPB_FLAGS;
                option.value_length = sizeof(guint32);
                if (!write_to_file(pfile, (const guint8*)&option, sizeof(struct option), bytes_written, err))
                        return FALSE;
                if (!write_to_file(pfile, (const guint8*)&flags, sizeof(guint32), bytes_written, err))
                        return FALSE;
        }
        if (options_length != 0) {
                /* write end of options */
                option.type = OPT_ENDOFOPT;
                option.value_length = 0;
                if (!write_to_file(pfile, (const guint8*)&option, sizeof(struct option), bytes_written, err))
                        return FALSE;
        }

       return write_to_file(pfile, (const guint8*)&block_total_length, sizeof(guint32), bytes_written, err);
}

gboolean
pcapng_write_interface_statistics_block(FILE* pfile,
                                        guint32 interface_id,
                                        guint64 *bytes_written,
                                        const char *comment,   /* OPT_COMMENT           1 */
                                        guint64 isb_starttime, /* ISB_STARTTIME         2 */
                                        guint64 isb_endtime,   /* ISB_ENDTIME           3 */
                                        guint64 isb_ifrecv,    /* ISB_IFRECV            4 */
                                        guint64 isb_ifdrop,    /* ISB_IFDROP            5 */
                                        int *err)
{
        struct isb isb;
#ifdef _WIN32
        FILETIME now;
#else
        struct timeval now;
#endif
        struct option option;
        guint32 block_total_length;
        guint32 options_length;
        guint64 timestamp;

#ifdef _WIN32
        /*
         * Current time, represented as 100-nanosecond intervals since
         * January 1, 1601, 00:00:00 UTC.
         *
         * I think DWORD might be signed, so cast both parts of "now"
         * to guint32 so that the sign bit doesn't get treated specially.
         *
         * Windows 8 provides GetSystemTimePreciseAsFileTime which we
         * might want to use instead.
         */
        GetSystemTimeAsFileTime(&now);
        timestamp = (((guint64)(guint32)now.dwHighDateTime) << 32) +
                    (guint32)now.dwLowDateTime;

        /*
         * Convert to same thing but as 1-microsecond, i.e. 1000-nanosecond,
         * intervals.
         */
        timestamp /= 10;

        /*
         * Subtract difference, in microseconds, between January 1, 1601
         * 00:00:00 UTC and January 1, 1970, 00:00:00 UTC.
         */
        timestamp -= EPOCH_DELTA_1601_01_01_00_00_00_UTC*1000000;
#else
        /*
         * Current time, represented as seconds and microseconds since
         * January 1, 1970, 00:00:00 UTC.
         */
        gettimeofday(&now, NULL);

        /*
         * Convert to delta in microseconds.
         */
        timestamp = (guint64)(now.tv_sec) * 1000000 +
                    (guint64)(now.tv_usec);
#endif
        block_total_length = (guint32)(sizeof(struct isb) + sizeof(guint32));
        options_length = 0;
        if (isb_ifrecv != G_MAXUINT64) {
                options_length += (guint32)(sizeof(struct option) +
                                            sizeof(guint64));
        }
        if (isb_ifdrop != G_MAXUINT64) {
                options_length += (guint32)(sizeof(struct option) +
                                            sizeof(guint64));
        }
        /* OPT_COMMENT */
        options_length += pcapng_count_string_option(comment);
        if (isb_starttime !=0) {
                options_length += (guint32)(sizeof(struct option) +
                                            sizeof(guint64)); /* ISB_STARTTIME */
        }
        if (isb_endtime !=0) {
                options_length += (guint32)(sizeof(struct option) +
                                            sizeof(guint64)); /* ISB_ENDTIME */
        }
        /* If we have options add size of end-of-options */
        if (options_length != 0) {
                options_length += (guint32)sizeof(struct option);
        }
        block_total_length += options_length;

        isb.block_type = INTERFACE_STATISTICS_BLOCK_TYPE;
        isb.block_total_length = block_total_length;
        isb.interface_id = interface_id;
        isb.timestamp_high = (guint32)((timestamp>>32) & 0xffffffff);
        isb.timestamp_low = (guint32)(timestamp & 0xffffffff);
        if (!write_to_file(pfile, (const guint8*)&isb, sizeof(struct isb), bytes_written, err))
                return FALSE;

        /* write comment string if applicable */
        if (!pcapng_write_string_option(pfile, OPT_COMMENT, comment,
                                        bytes_written, err))
                return FALSE;

        if (isb_starttime !=0) {
                guint32 high, low;

                option.type = ISB_STARTTIME;
                option.value_length = sizeof(guint64);
                high = (guint32)((isb_starttime>>32) & 0xffffffff);
                low = (guint32)(isb_starttime & 0xffffffff);
                if (!write_to_file(pfile, (const guint8*)&option, sizeof(struct option), bytes_written, err))
                        return FALSE;

                if (!write_to_file(pfile, (const guint8*)&high, sizeof(guint32), bytes_written, err))
                        return FALSE;

                if (!write_to_file(pfile, (const guint8*)&low, sizeof(guint32), bytes_written, err))
                        return FALSE;
        }
        if (isb_endtime !=0) {
                guint32 high, low;

                option.type = ISB_ENDTIME;
                option.value_length = sizeof(guint64);
                high = (guint32)((isb_endtime>>32) & 0xffffffff);
                low = (guint32)(isb_endtime & 0xffffffff);
                if (!write_to_file(pfile, (const guint8*)&option, sizeof(struct option), bytes_written, err))
                        return FALSE;

                if (!write_to_file(pfile, (const guint8*)&high, sizeof(guint32), bytes_written, err))
                        return FALSE;

                if (!write_to_file(pfile, (const guint8*)&low, sizeof(guint32), bytes_written, err))
                        return FALSE;
        }
        if (isb_ifrecv != G_MAXUINT64) {
                option.type = ISB_IFRECV;
                option.value_length = sizeof(guint64);
                if (!write_to_file(pfile, (const guint8*)&option, sizeof(struct option), bytes_written, err))
                        return FALSE;

                if (!write_to_file(pfile, (const guint8*)&isb_ifrecv, sizeof(guint64), bytes_written, err))
                        return FALSE;
        }
        if (isb_ifdrop != G_MAXUINT64) {
                option.type = ISB_IFDROP;
                option.value_length = sizeof(guint64);
                if (!write_to_file(pfile, (const guint8*)&option, sizeof(struct option), bytes_written, err))
                        return FALSE;

                if (!write_to_file(pfile, (const guint8*)&isb_ifdrop, sizeof(guint64), bytes_written, err))
                        return FALSE;
        }
        if (options_length != 0) {
                /* write end of options */
                option.type = OPT_ENDOFOPT;
                option.value_length = 0;
                if (!write_to_file(pfile, (const guint8*)&option, sizeof(struct option), bytes_written, err))
                        return FALSE;
        }

        return write_to_file(pfile, (const guint8*)&block_total_length, sizeof(guint32), bytes_written, err);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 expandtab:
 * :indentSize=8:tabSize=8:noTabs=true:
 */
