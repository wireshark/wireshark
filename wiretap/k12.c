/*
 * k12.c
 *
 *  routines for importing tektronix k12xx *.rf5 files
 *
 *  Copyright (c) 2005, Luis E. Garia Ontanon <luis@ontanon.org>
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "k12.h"

#include <stdlib.h>
#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"

#include <wsutil/str_util.h>
#include <wsutil/glib-compat.h>

/*
 * See
 *
 *  https://www.tek.com/manual/record-file-api-programmer-manual
 *
 * for some information about the file format.  You may have to fill in
 * a form to download the document ("Record File API Programmer Manual").
 *
 * Unfortunately, it describes an API that delivers records from an rf5
 * file, not the raw format of an rf5 file, so, while it gives the formats
 * of the records with various types, it does not indicate how those records
 * are stored in the file.
 */

static int k12_file_type_subtype = -1;

void register_k12(void);

/* #define DEBUG_K12 */
#ifdef DEBUG_K12
#include <stdio.h>
#include <stdarg.h>
#include <wsutil/file_util.h>

FILE* dbg_out;
char* env_file;

static unsigned int debug_level;

void k12_fprintf(const char* fmt, ...) {
    va_list ap;

    va_start(ap,fmt);
    vfprintf(dbg_out, fmt, ap);
    va_end(ap);
}

#define CAT(a,b) a##b
#define K12_DBG(level,args) do { if (level <= debug_level) { \
            fprintf(dbg_out,"%s:%d: ",CAT(__FI,LE__),CAT(__LI,NE__));   \
            k12_fprintf args ;                                          \
            fprintf(dbg_out,"\n");                                      \
} } while(0)

void k12_hex_ascii_dump(unsigned level, int64_t offset, const char* label, const unsigned char* b, unsigned int len) {
    static const char* c2t[] = {
        "00","01","02","03","04","05","06","07","08","09","0a","0b","0c","0d","0e","0f",
        "10","11","12","13","14","15","16","17","18","19","1a","1b","1c","1d","1e","1f",
        "20","21","22","23","24","25","26","27","28","29","2a","2b","2c","2d","2e","2f",
        "30","31","32","33","34","35","36","37","38","39","3a","3b","3c","3d","3e","3f",
        "40","41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f",
        "50","51","52","53","54","55","56","57","58","59","5a","5b","5c","5d","5e","5f",
        "60","61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f",
        "70","71","72","73","74","75","76","77","78","79","7a","7b","7c","7d","7e","7f",
        "80","81","82","83","84","85","86","87","88","89","8a","8b","8c","8d","8e","8f",
        "90","91","92","93","94","95","96","97","98","99","9a","9b","9c","9d","9e","9f",
        "a0","a1","a2","a3","a4","a5","a6","a7","a8","a9","aa","ab","ac","ad","ae","af",
        "b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","ba","bb","bc","bd","be","bf",
        "c0","c1","c2","c3","c4","c5","c6","c7","c8","c9","ca","cb","cc","cd","ce","cf",
        "d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","da","db","dc","dd","de","df",
        "e0","e1","e2","e3","e4","e5","e6","e7","e8","e9","ea","eb","ec","ed","ee","ef",
        "f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","fa","fb","fc","fd","fe","ff"
    };
    unsigned int i, j;

    if (debug_level < level) return;

    fprintf(dbg_out,"%s(%.8" PRIx64 ",%.4x):\n",label,offset,len);

    for (i=0 ; i<len ; i += 16) {
        for (j=0; j<16; j++) {
            if ((j%4)==0)
                fprintf(dbg_out," ");
            if ((i+j)<len)
                fprintf(dbg_out, "%s", c2t[b[i+j]]);
            else
                fprintf(dbg_out, "  ");
        }
        fprintf(dbg_out, "    ");
        for (j=0; j<16; j++) {
            if ((i+j)<len)
                fprintf(dbg_out, "%c", g_ascii_isprint(b[i+j]) ? b[i+j] : '.');
        }
        fprintf(dbg_out,"\n");
    }
}

#define K12_HEX_ASCII_DUMP(x,a,b,c,d) k12_hex_ascii_dump(x,a,b,c,d)

void k12_ascii_dump(unsigned level, uint8_t *buf, uint32_t len, uint32_t buf_offset) {
    uint32_t i;

    if (debug_level < level) return;

    for (i = buf_offset; i < len; i++) {
        if (g_ascii_isprint(buf[i]) || buf[i] == '\n' || buf[i] == '\t')
            putc(buf[i], dbg_out);
        else if (buf[i] == '\0')
            fprintf(dbg_out, "(NUL)\n");
    }
}

#define K12_ASCII_DUMP(x,a,b,c) k12_ascii_dump(x,a,b,c)

#else
#define K12_DBG(level,args) (void)0
#define K12_HEX_ASCII_DUMP(x,a,b,c,d)
#define K12_ASCII_DUMP(x,a,b,c)
#endif



/*
 * A 32-bit .rf5 file begins with a 512-byte file header, containing:
 *
 *  a 32-bit big-endian file header length, in bytes - always 512 in
 *  the files we've seen;
 *
 *  4 unknown bytes, always 0x12 0x05 0x00 0x10;
 *
 *  a 32-bit big-endian file length, giving the total length of the file,
 *  in bytes;
 *
 *  a 32-bit big-endian number giving the "page size" of the file, in
 *  bytes, which is normally 8192;
 *
 *  20 unknown bytes;
 *
 *  a 32-bit count of the number of records in the file;
 *
 *  4 unknown bytes;
 *
 *  a 32-bit count of the number of records in the file;
 *
 *  464 unknown bytes;
 *
 * followed by a sequence of records containing:
 *
 *  a 32-bit big-endian record length;
 *
 *  a 32-bit big-endian record type;
 *
 *  a 32-bit big-endian frame length;
 *
 *  a 32-bit big-endian source ID.
 *
 * Every 8192 bytes, starting immediately after the 512-byte header,
 * there's a 16-byte blob; it's not part of the record data.
 * There's no obvious pattern to the data; it might be junk left
 * in memory as the file was being written.
 *
 * There's a 16-bit terminator FFFF at the end.
 *
 * Older versions of the Wireshark .rf5 writing code incorrectly wrote
 * the header - they put 512 in the file length field (counting only the
 * header), put a count of records into the "page size" field, and wrote
 * out zeroes in the rest of the header.  We detect those files by
 * checking whether the rest of the header is zero.
 */

/*
 * We use the first 8 bytes of the file header as a magic number.
 */
static const uint8_t k12_file_magic[] = { 0x00, 0x00, 0x02, 0x00 ,0x12, 0x05, 0x00, 0x10 };

#define K12_FILE_HDR_LEN      512

/*
 * Offsets in the file header.
 */
#define K12_FILE_HDR_MAGIC_NUMBER   0x00
#define K12_FILE_HDR_FILE_SIZE      0x08
#define K12_FILE_HDR_PAGE_SIZE      0x0C
#define K12_FILE_HDR_RECORD_COUNT_1 0x24
#define K12_FILE_HDR_RECORD_COUNT_2 0x2C

#define K12_FILE_BLOB_LEN     16

typedef struct {
    uint32_t file_len;
    uint32_t num_of_records;     /* XXX: not sure about this */

    GHashTable* src_by_id;       /* k12_srcdsc_recs by input */
    GHashTable* src_by_name;     /* k12_srcdsc_recs by stack_name */

    uint8_t *seq_read_buff;      /* read buffer for sequential reading */
    unsigned seq_read_buff_len;  /* length of that buffer */
    uint8_t *rand_read_buff;     /* read buffer for random reading */
    unsigned rand_read_buff_len; /* length of that buffer */

    Buffer extra_info;           /* Buffer to hold per packet extra information */
} k12_t;

typedef struct _k12_src_desc_t {
    uint32_t input;
    uint32_t input_type;
    char* input_name;
    char* stack_file;
    k12_input_info_t input_info;
} k12_src_desc_t;


/*
 * According to the Tektronix documentation, this value is a combination of
 * a "group" code and a "type" code, with both being 2-byte values and
 * with the "group" code followe by the "type" code.  The "group" values
 * are:
 *
 *      0x0001 - "data event"
 *      0x0002 - "text or L1 event"
 *      0x0007 - "configuration event"
 *
 * and the "type" values are:
 *
 *  data events:
 *      0x0020 - "frame" (i.e., "an actual packet")
 *      0x0021 - "transparent frame"
 *      0x0022 - "bit data (TRAU frame)"
 *      0x0024 - "used to mark the frame which is a fragment"
 *      0x0026 - "used to mark the frame which is a fragment"
 *      0x0028 - "used to mark the frame which is generated by the LSA"
 *      0x002A - "used to mark the frame which is generated by the LSA"
 *
 *  text or L1 events:
 *      0x0030 - "text event"
 *      0x0031 - "L1 event"
 *      0x0032 - "L1 event (BAI)"
 *      0x0033 - "L1 event (VX)"
 *
 *  configuration events:
 *      0x0040 - Logical Data Source configuration event
 *      0x0041 - Logical Link configuration event
 */
/* so far we've seen these types of records */
#define K12_REC_PACKET        0x00010020 /* an actual packet */
#define K12_REC_D0020         0x000d0020 /* an actual packet, seen in a k18 file */
#define K12_REC_SCENARIO      0x00070040 /* what appears as the window's title */
#define K12_REC_SRCDSC        0x00070041 /* port-stack mapping + more, the key of the whole thing */
#define K12_REC_STK_FILE      0x00070042 /* a dump of an stk file */
#define K12_REC_SRCDSC2       0x00070043 /* another port-stack mapping */
#define K12_REC_TEXT          0x00070044 /* a string containing something with a grammar (conditions/responses?) */
#define K12_REC_START         0x00020030 /* a string containing human readable start time  */
#define K12_REC_STOP          0x00020031 /* a string containing human readable stop time */

/*
 * According to the Tektronix documentation, packets, i.e. "data events",
 * have several different group/type values, which differ in the last
 * nibble of the type code.  For now, we just mask that nibble off; the
 * format of the items are different, so we might have to treat different
 * data event types differently.
 */
#define K12_MASK_PACKET       0xfffffff0

/* offsets of elements in the records */
#define K12_RECORD_LEN         0x0 /* uint32, in bytes */
#define K12_RECORD_TYPE        0x4 /* uint32, see above */
#define K12_RECORD_FRAME_LEN   0x8 /* uint32, in bytes */
#define K12_RECORD_SRC_ID      0xc /* uint32 */

/*
 * Some records from K15 files have a port ID of an undeclared
 * interface which happens to be the only one with the first byte changed.
 * It is still unknown how to recognize when this happens.
 * If the lookup of the interface record fails we'll mask it
 * and retry.
 */
#define K12_RECORD_SRC_ID_MASK 0x00ffffff

/* elements of packet records */
#define K12_PACKET_TIMESTAMP  0x18 /* int64 (8b) representing 1/2us since 01-01-1990 Z00:00:00 */

#define K12_PACKET_FRAME      0x20 /* start of the actual frame in the record */
#define K12_PACKET_FRAME_D0020 0x34 /* start of the actual frame in the record */

#define K12_PACKET_OFFSET_VP  0x08 /* 2 bytes, big endian */
#define K12_PACKET_OFFSET_VC  0x0a /* 2 bytes, big endian */
#define K12_PACKET_OFFSET_CID 0x0c /* 1 byte */

/* elements of the source description records */
#define K12_SRCDESC_COLOR_FOREGROUND 0x12 /* 1 byte */
#define K12_SRCDESC_COLOR_BACKGROUND 0x13 /* 1 byte */

#define K12_SRCDESC_PORT_TYPE  0x1a /* 1 byte */
#define K12_SRCDESC_HWPARTLEN  0x1e /* uint16, big endian */
#define K12_SRCDESC_NAMELEN    0x20 /* uint16, big endian */
#define K12_SRCDESC_STACKLEN   0x22 /* uint16, big endian */

/* Hardware part of the record */
#define K12_SRCDESC_HWPART     0x24 /* offset of the hardware part */

/* Offsets relative to the beginning of the hardware part */
#define K12_SRCDESC_HWPARTTYPE 0    /* uint32, big endian */

#define K12_SRCDESC_DS0_MASK   24   /* variable-length */

#define K12_SRCDESC_ATM_VPI    20   /* uint16, big endian */
#define K12_SRCDESC_ATM_VCI    22   /* uint16, big endian */
#define K12_SRCDESC_ATM_AAL    24   /* 1 byte */

/*
 * A "stack file", as appears in a K12_REC_STK_FILE record, is a text
 * file (with CR-LF line endings) with a sequence of lines, each of
 * which begins with a keyword, and has white-space-separated tokens
 * after that.
 *
 * They appear to be:
 *
 *   STKVER, which is followed by a number (presumably a version number
 *   for the stack file format)
 *
 *   STACK, which is followed by a quoted string ("ProtocolStack" in one
 *   file) and two numbers
 *
 *   PATH, which is followed by a non-quoted string giving the pathname
 *   of the directory containing the stack file
 *
 *   HLAYER, which is followed by a quoted string, a path for something
 *   (protocol module?), a keyword ("LOADED", in one file), and a
 *   quoted string giving a description - this is probably a protocol
 *   layer of some sort
 *
 *   LAYER, which has a similar syntax to HLAYER - the first quoted
 *   string is a protocol name
 *
 *   RELATION, which has a quoted string giving a protocol name,
 *   another quoted string giving a protocol name, and a condition
 *   specifier of some sort, which probably says the second protocol
 *   is layered atop the first protocol if the condition is true.
 *   The first protocol can also be "BASE", which means that the
 *   second protocol is the lowest-level protocol.
 *   The conditions are:
 *
 *     CPLX, which may mean "complex" - it has parenthesized expressions
 *     including "&", presumably a boolean AND, with the individual
 *     tests being L:expr, where L is a letter such as "L", "D", or "P",
 *     and expr is:
 *
 *        0x........ for L, where each . is a hex digit or a ?, presumably
 *        meaning "don't care"
 *
 *        0;0{=,!=}0b........ for D, where . is presumably a bit or a ?
 *
 *        param=value for P, where param is something such as "src_port"
 *        and value is a value, presumably to test, for example, TCP or
 *        UDP ports
 *
 *     UNCOND, presumably meaning "always"
 *
 *     PARAM, followed by a parameter name (as with P:) and a value,
 *     possibly followed by LAYPARAM and a hex value
 *
 *   DECKRNL, followed by a quoted string protocol name, un-quoted
 *   "LSBF" or "MSBF" (Least/Most Significant Byte First?), and
 *   an un-quoted string ending with _DK
 *
 *   LAYPARAM, followed by a quoted protocol name and a number (-2147221504
 *   in one file, which is 0x80040000)
 *
 *   SPC_CONF, folloed by a number, a quoted string with numbers separated
 *   by hyphens, and another number
 *
 *   CIC_CONF, with a similar syntax to SPC_CONF
 *
 *   LAYPOS, followed by a protocol name or "BASE" and 3 numbers.
 *
 * Most of this is probably not useful, but the RELATION lines with
 * "BASE" could be used to figure out how to start the dissection
 * (if we knew what "L" and "D" did), and *some* of the others might
 * be useful if they don't match what's already in various dissector
 * tables (the ones for IP and a higher-level protocol, for example,
 * aren't very useful, as those are standardized, but the ones for
 * TCP, UDP, and SCTP ports, and SCTP PPIs, might be useful).
 */

/*
 * get_record: Get the next record into a buffer
 *   Every 8192 bytes 16 bytes are inserted in the file,
 *   even in the middle of a record.
 *   This reads the next record without the eventual 16 bytes.
 *   returns the length of the record + the stuffing (if any)
 *
 *   Returns number of bytes read on success, 0 on EOF, -1 on error;
 *   if -1 is returned, *err is set to the error indication and, for
 *   errors where that's appropriate, *err_info is set to an additional
 *   error string.
 *
 * XXX: works at most with 8191 bytes per record
 */
static int get_record(k12_t *file_data, FILE_T fh, int64_t file_offset,
                       bool is_random, int *err, char **err_info) {
    uint8_t *buffer = is_random ? file_data->rand_read_buff : file_data->seq_read_buff;
    unsigned buffer_len = is_random ? file_data->rand_read_buff_len : file_data->seq_read_buff_len;
    unsigned total_read = 0;
    unsigned left;
    uint8_t* writep;
#ifdef DEBUG_K12
    unsigned actual_len;
#endif

    /*
     * Where the next unknown 16 bytes are stuffed to the file.
     * Following the file header, they appear every 8192 bytes,
     * starting right after the file header, so if the file offset
     * relative to the file header is a multiple of 8192, the
     * 16-byte blob is there.
     */
    unsigned junky_offset = 8192 - (int) ( (file_offset - K12_FILE_HDR_LEN) % 8192 );

    K12_DBG(6,("get_record: ENTER: junky_offset=%" PRId64 ", file_offset=%" PRId64,junky_offset,file_offset));

    /* no buffer is given, lets create it */
    if (buffer == NULL) {
        buffer = (uint8_t*)g_malloc(8192);
        buffer_len = 8192;
        if (is_random) {
            file_data->rand_read_buff = buffer;
            file_data->rand_read_buff_len = buffer_len;
        } else {
            file_data->seq_read_buff = buffer;
            file_data->seq_read_buff_len = buffer_len;
        }
    }

    if ( junky_offset == 8192 ) {
        /*
         * We're at the beginning of one of the 16-byte blobs,
         * so we first need to skip the blob.
         *
         * XXX - what if the blob is in the middle of the record
         * length?  If the record length is always a multiple of
         * 4 bytes, that won't happen.
         */
        if ( ! wtap_read_bytes( fh, NULL, K12_FILE_BLOB_LEN, err, err_info ) )
            return -1;
        total_read += K12_FILE_BLOB_LEN;
    }

    /*
     * Read the record length.
     */
    if ( !wtap_read_bytes( fh, buffer, 4, err, err_info ) )
        return -1;
    total_read += 4;

    left = pntoh32(buffer + K12_RECORD_LEN);
#ifdef DEBUG_K12
    actual_len = left;
#endif
    junky_offset -= 4;

    K12_DBG(5,("get_record: GET length=%u",left));

    /*
     * Record length must be at least large enough for the length
     * and type, hence 8 bytes.
     *
     * XXX - is WTAP_MAX_PACKET_SIZE_STANDARD the right check for a maximum
     * record size?  Should we report this error differently?
     */
    if (left < 8) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("k12: Record length %u is less than 8 bytes long",left);
        return -1;
    }
    if (left > WTAP_MAX_PACKET_SIZE_STANDARD) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("k12: Record length %u is greater than the maximum %u",left,WTAP_MAX_PACKET_SIZE_STANDARD);
        return -1;
    }

    /*
     * XXX - calculate the lowest power of 2 >= left, rather than just
     * looping.
     */
    while (left > buffer_len) {
        buffer = (uint8_t*)g_realloc(buffer,buffer_len*=2);
        if (is_random) {
            file_data->rand_read_buff = buffer;
            file_data->rand_read_buff_len = buffer_len;
        } else {
            file_data->seq_read_buff = buffer;
            file_data->seq_read_buff_len = buffer_len;
        }
    }

    writep = buffer + 4;
    left -= 4;

    /* Read the rest of the record. */
    do {
        K12_DBG(6,("get_record: looping left=%d junky_offset=%" PRId64,left,junky_offset));

        if (junky_offset > left) {
            /*
             * The next 16-byte blob is past the end of this record.
             * Just read the rest of the record.
             */
            if ( !wtap_read_bytes( fh, writep, left, err, err_info ) )
                return -1;
            total_read += left;
            break;
        } else {
            /*
             * The next 16-byte blob is part of this record.
             * Read up to the blob.
             */
            if ( !wtap_read_bytes( fh, writep, junky_offset, err, err_info ) )
                return -1;

            total_read += junky_offset;
            writep += junky_offset;

            /*
             * Skip the blob.
             */
            if ( !wtap_read_bytes( fh, NULL, K12_FILE_BLOB_LEN, err, err_info ) )
                return -1;
            total_read += K12_FILE_BLOB_LEN;

            left -= junky_offset;
            junky_offset = 8192;
        }

    } while(left);

    K12_HEX_ASCII_DUMP(5,file_offset, "GOT record", buffer, actual_len);
    return total_read;
}

static bool
memiszero(const void *ptr, size_t count)
{
    const uint8_t *p = (const uint8_t *)ptr;

    while (count != 0) {
        if (*p != 0)
            return false;
        p++;
        count--;
    }
    return true;
}

static bool
process_packet_data(wtap_rec *rec, Buffer *target, uint8_t *buffer,
                    unsigned record_len, k12_t *k12, int *err, char **err_info)
{
    uint32_t type;
    unsigned buffer_offset;
    uint64_t ts;
    uint32_t length;
    uint32_t extra_len;
    uint32_t src_id;
    k12_src_desc_t* src_desc;

    type = pntoh32(buffer + K12_RECORD_TYPE);
    buffer_offset = (type == K12_REC_D0020) ? K12_PACKET_FRAME_D0020 : K12_PACKET_FRAME;
    if (buffer_offset > record_len) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("k12: Frame data offset %u > record length %u",
                                    buffer_offset, record_len);
        return false;
    }

    length = pntoh32(buffer + K12_RECORD_FRAME_LEN) & 0x00001FFF;
    if (length > record_len - buffer_offset) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("k12: Frame length %u > record frame data %u",
                                    length, record_len - buffer_offset);
        return false;
    }

    rec->rec_type = REC_TYPE_PACKET;
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_TS;

    ts = pntoh64(buffer + K12_PACKET_TIMESTAMP);

    rec->ts.secs = (time_t) ((ts / 2000000) + 631152000);
    rec->ts.nsecs = (uint32_t) ( (ts % 2000000) * 500 );

    rec->rec_header.packet_header.len = rec->rec_header.packet_header.caplen = length;

    ws_buffer_assure_space(target, length);
    memcpy(ws_buffer_start_ptr(target), buffer + buffer_offset, length);

    /* extra information need by some protocols */
    extra_len = record_len - buffer_offset - length;
    ws_buffer_assure_space(&(k12->extra_info), extra_len);
    memcpy(ws_buffer_start_ptr(&(k12->extra_info)),
           buffer + buffer_offset + length, extra_len);
    rec->rec_header.packet_header.pseudo_header.k12.extra_info = (uint8_t*)ws_buffer_start_ptr(&(k12->extra_info));
    rec->rec_header.packet_header.pseudo_header.k12.extra_length = extra_len;

    src_id = pntoh32(buffer + K12_RECORD_SRC_ID);
    K12_DBG(5,("process_packet_data: src_id=%.8x",src_id));
    rec->rec_header.packet_header.pseudo_header.k12.input = src_id;

    if ( ! (src_desc = (k12_src_desc_t*)g_hash_table_lookup(k12->src_by_id,GUINT_TO_POINTER(src_id))) ) {
        /*
         * Some records from K15 files have a port ID of an undeclared
         * interface which happens to be the only one with the first byte changed.
         * It is still unknown how to recognize when this happens.
         * If the lookup of the interface record fails we'll mask it
         * and retry.
         */
        src_desc = (k12_src_desc_t*)g_hash_table_lookup(k12->src_by_id,GUINT_TO_POINTER(src_id&K12_RECORD_SRC_ID_MASK));
    }

    if (src_desc) {
        K12_DBG(5,("process_packet_data: input_name='%s' stack_file='%s' type=%x",src_desc->input_name,src_desc->stack_file,src_desc->input_type));
        rec->rec_header.packet_header.pseudo_header.k12.input_name = src_desc->input_name;
        rec->rec_header.packet_header.pseudo_header.k12.stack_file = src_desc->stack_file;
        rec->rec_header.packet_header.pseudo_header.k12.input_type = src_desc->input_type;

        switch(src_desc->input_type) {
            case K12_PORT_ATMPVC:
                if (buffer_offset + length + K12_PACKET_OFFSET_CID < record_len) {
                    rec->rec_header.packet_header.pseudo_header.k12.input_info.atm.vp =  pntoh16(buffer + buffer_offset + length + K12_PACKET_OFFSET_VP);
                    rec->rec_header.packet_header.pseudo_header.k12.input_info.atm.vc =  pntoh16(buffer + buffer_offset + length + K12_PACKET_OFFSET_VC);
                    rec->rec_header.packet_header.pseudo_header.k12.input_info.atm.cid =  *((unsigned char*)(buffer + buffer_offset + length + K12_PACKET_OFFSET_CID));
                    break;
                }
                /* Fall through */
            default:
                memcpy(&(rec->rec_header.packet_header.pseudo_header.k12.input_info),&(src_desc->input_info),sizeof(src_desc->input_info));
                break;
        }
    } else {
        K12_DBG(5,("process_packet_data: NO SRC_RECORD FOUND"));

        memset(&(rec->rec_header.packet_header.pseudo_header.k12),0,sizeof(rec->rec_header.packet_header.pseudo_header.k12));
        rec->rec_header.packet_header.pseudo_header.k12.input_name = "unknown port";
        rec->rec_header.packet_header.pseudo_header.k12.stack_file = "unknown stack file";
    }

    rec->rec_header.packet_header.pseudo_header.k12.input = src_id;
    rec->rec_header.packet_header.pseudo_header.k12.stuff = k12;
    return true;
}

static bool k12_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err, char **err_info, int64_t *data_offset) {
    k12_t *k12 = (k12_t *)wth->priv;
    k12_src_desc_t* src_desc;
    uint8_t* buffer;
    int64_t offset;
    int len;
    uint32_t type;
    uint32_t src_id;

    offset = file_tell(wth->fh);

    /* ignore the record if it isn't a packet */
    do {
        if ( k12->num_of_records == 0 ) {
            /* No more records */
            *err = 0;
            return false;
        }

        K12_DBG(5,("k12_read: offset=%i",offset));

        *data_offset = offset;

        len = get_record(k12, wth->fh, offset, false, err, err_info);

        if (len < 0) {
            /* read error */
            return false;
        } else if (len == 0) {
            /* EOF */
            *err = WTAP_ERR_SHORT_READ;
            return false;
        } else if (len < K12_RECORD_SRC_ID + 4) {
            /* Record not large enough to contain a src ID */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("k12: Data record length %d too short", len);
            return false;
        }
        k12->num_of_records--;

        buffer = k12->seq_read_buff;

        type = pntoh32(buffer + K12_RECORD_TYPE);
        src_id = pntoh32(buffer + K12_RECORD_SRC_ID);


        if ( ! (src_desc = (k12_src_desc_t*)g_hash_table_lookup(k12->src_by_id,GUINT_TO_POINTER(src_id))) ) {
            /*
             * Some records from K15 files have a port ID of an undeclared
             * interface which happens to be the only one with the first byte changed.
             * It is still unknown how to recognize when this happens.
             * If the lookup of the interface record fails we'll mask it
             * and retry.
             */
            src_desc = (k12_src_desc_t*)g_hash_table_lookup(k12->src_by_id,GUINT_TO_POINTER(src_id&K12_RECORD_SRC_ID_MASK));
        }

        K12_DBG(5,("k12_read: record type=%x src_id=%x",type,src_id));

        offset += len;

    } while ( ((type & K12_MASK_PACKET) != K12_REC_PACKET && (type & K12_MASK_PACKET) != K12_REC_D0020) || !src_id || !src_desc );

    return process_packet_data(rec, buf, buffer, (unsigned)len, k12, err, err_info);
}


static bool k12_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec, Buffer *buf, int *err, char **err_info) {
    k12_t *k12 = (k12_t *)wth->priv;
    uint8_t* buffer;
    int len;
    bool status;

    K12_DBG(5,("k12_seek_read: ENTER"));

    if ( file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1) {
        K12_DBG(5,("k12_seek_read: SEEK ERROR"));
        return false;
    }

    len = get_record(k12, wth->random_fh, seek_off, true, err, err_info);
    if (len < 0) {
        K12_DBG(5,("k12_seek_read: READ ERROR"));
        return false;
    } else if (len < K12_RECORD_SRC_ID + 4) {
        /* Record not large enough to contain a src ID */
        K12_DBG(5,("k12_seek_read: SHORT READ"));
        *err = WTAP_ERR_SHORT_READ;
        return false;
    }

    buffer = k12->rand_read_buff;

    status = process_packet_data(rec, buf, buffer, (unsigned)len, k12, err, err_info);

    K12_DBG(5,("k12_seek_read: DONE OK"));

    return status;
}


static k12_t* new_k12_file_data(void) {
    k12_t* fd = g_new(k12_t,1);

    fd->file_len = 0;
    fd->num_of_records = 0;
    fd->src_by_name = g_hash_table_new(g_str_hash,g_str_equal);
    fd->src_by_id = g_hash_table_new(g_direct_hash,g_direct_equal);
    fd->seq_read_buff = NULL;
    fd->seq_read_buff_len = 0;
    fd->rand_read_buff = NULL;
    fd->rand_read_buff_len = 0;

    ws_buffer_init(&(fd->extra_info), 100);

    return fd;
}

static gboolean destroy_srcdsc(void *k _U_, void *v, void *p _U_) {
    k12_src_desc_t* rec = (k12_src_desc_t*)v;

    g_free(rec->input_name);
    g_free(rec->stack_file);
    g_free(rec);

    return true;
}

static void destroy_k12_file_data(k12_t* fd) {
    g_hash_table_destroy(fd->src_by_id);
    g_hash_table_foreach_remove(fd->src_by_name,destroy_srcdsc,NULL);
    g_hash_table_destroy(fd->src_by_name);
    ws_buffer_free(&(fd->extra_info));
    g_free(fd->seq_read_buff);
    g_free(fd->rand_read_buff);
    g_free(fd);
}

static void k12_close(wtap *wth) {
    k12_t *k12 = (k12_t *)wth->priv;

    destroy_k12_file_data(k12);
    wth->priv = NULL;   /* destroy_k12_file_data freed it */
#ifdef DEBUG_K12
    K12_DBG(5,("k12_close: CLOSED"));
    if (env_file) fclose(dbg_out);
#endif
}


wtap_open_return_val k12_open(wtap *wth, int *err, char **err_info) {
    k12_src_desc_t* rec;
    uint8_t header_buffer[K12_FILE_HDR_LEN];
    uint8_t* read_buffer;
    uint32_t type;
    long offset;
    long len;
    unsigned port_type;
    uint32_t rec_len;
    uint32_t hwpart_len;
    uint32_t name_len;
    uint32_t stack_len;
    unsigned i;
    k12_t* file_data;

#ifdef DEBUG_K12
    char* env_level = getenv("K12_DEBUG_LEVEL");
    env_file = getenv("K12_DEBUG_FILENAME");
    if ( env_file ) {
        dbg_out = ws_fopen(env_file,"w");
        if (dbg_out == NULL) {
                dbg_out = stderr;
                K12_DBG(1,("unable to open K12 DEBUG FILENAME for writing!  Logging to standard error"));
        }
    }
    else
        dbg_out = stderr;
    if ( env_level ) debug_level = (unsigned int)strtoul(env_level,NULL,10);
    K12_DBG(1,("k12_open: ENTER debug_level=%u",debug_level));
#endif

    if ( !wtap_read_bytes(wth->fh,header_buffer,K12_FILE_HDR_LEN,err,err_info) ) {
        K12_DBG(1,("k12_open: FILE HEADER TOO SHORT OR READ ERROR"));
        if (*err != WTAP_ERR_SHORT_READ) {
            return WTAP_OPEN_ERROR;
        }
        return WTAP_OPEN_NOT_MINE;
    }

    if ( memcmp(header_buffer,k12_file_magic,8) != 0 ) {
        K12_DBG(1,("k12_open: BAD MAGIC"));
        return WTAP_OPEN_NOT_MINE;
    }

    offset = K12_FILE_HDR_LEN;

    file_data = new_k12_file_data();

    file_data->file_len = pntoh32( header_buffer + 0x8);
    if (memiszero(header_buffer + 0x10, K12_FILE_HDR_LEN - 0x10)) {
        /*
         * The rest of the file header is all zeroes.  That means
         * this is a file written by the old Wireshark code, and
         * a count of records in the file is at an offset of 0x0C.
         */
        file_data->num_of_records = pntoh32( header_buffer + 0x0C );
    } else {
        /*
         * There's at least one non-zero byte in the rest of the
         * header.  The value 8192 is at 0xC (page size?), and
         * what appears to be the number of records in the file
         * is at an offset of 0x24 and at an offset of 0x2c.
         *
         * If the two values are not the same, we fail; if that's
         * the case, we need to see the file to figure out which
         * of those two values, if any, is the count.
         */
        file_data->num_of_records = pntoh32( header_buffer + K12_FILE_HDR_RECORD_COUNT_1 );
        if ( file_data->num_of_records != pntoh32( header_buffer + K12_FILE_HDR_RECORD_COUNT_2 ) ) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("k12: two different record counts, %u at 0x%02x and %u at 0x%02x",
                                        file_data->num_of_records,
                                        K12_FILE_HDR_RECORD_COUNT_1,
                                        pntoh32( header_buffer + K12_FILE_HDR_RECORD_COUNT_2 ),
                                        K12_FILE_HDR_RECORD_COUNT_2 );
            destroy_k12_file_data(file_data);
            return WTAP_OPEN_ERROR;
        }
    }

    K12_DBG(5,("k12_open: FILE_HEADER OK: offset=%x file_len=%i records=%i",
            offset,
            file_data->file_len,
            file_data->num_of_records ));

    do {
        if ( file_data->num_of_records == 0 ) {
            *err = WTAP_ERR_SHORT_READ;
            destroy_k12_file_data(file_data);
            return WTAP_OPEN_ERROR;
        }

        len = get_record(file_data, wth->fh, offset, false, err, err_info);

        if ( len < 0 ) {
            K12_DBG(1,("k12_open: BAD HEADER RECORD",len));
            destroy_k12_file_data(file_data);
            return WTAP_OPEN_ERROR;
        }
        if ( len == 0 ) {
            K12_DBG(1,("k12_open: BAD HEADER RECORD",len));
            *err = WTAP_ERR_SHORT_READ;
            destroy_k12_file_data(file_data);
            return WTAP_OPEN_ERROR;
        }

        read_buffer = file_data->seq_read_buff;

        rec_len = pntoh32( read_buffer + K12_RECORD_LEN );
        if (rec_len < K12_RECORD_TYPE + 4) {
            /* Record isn't long enough to have a type field */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("k12: record length %u < %u",
                                        rec_len, K12_RECORD_TYPE + 4);
            destroy_k12_file_data(file_data);
            return WTAP_OPEN_ERROR;
        }
        type = pntoh32( read_buffer + K12_RECORD_TYPE );

        if ( (type & K12_MASK_PACKET) == K12_REC_PACKET ||
             (type & K12_MASK_PACKET) == K12_REC_D0020) {
            /*
             * we are at the first packet record, rewind and leave.
             */
            if (file_seek(wth->fh, offset, SEEK_SET, err) == -1) {
                destroy_k12_file_data(file_data);
                return WTAP_OPEN_ERROR;
            }
            K12_DBG(5,("k12_open: FIRST PACKET offset=%x",offset));
            break;
        }

        switch (type) {

        case K12_REC_SRCDSC:
        case K12_REC_SRCDSC2:
            rec = g_new0(k12_src_desc_t,1);

            if (rec_len < K12_SRCDESC_HWPART) {
                /*
                 * Record isn't long enough to have the fixed-length portion
                 * of the source descriptor field.
                 */
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("k12: source descriptor record length %u < %u",
                                            rec_len, K12_SRCDESC_HWPART);
                destroy_k12_file_data(file_data);
                g_free(rec);
                return WTAP_OPEN_ERROR;
            }
            port_type = read_buffer[K12_SRCDESC_PORT_TYPE];
            hwpart_len = pntoh16( read_buffer + K12_SRCDESC_HWPARTLEN );
            name_len = pntoh16( read_buffer + K12_SRCDESC_NAMELEN );
            stack_len = pntoh16( read_buffer + K12_SRCDESC_STACKLEN );

            rec->input = pntoh32( read_buffer + K12_RECORD_SRC_ID );

            K12_DBG(5,("k12_open: INTERFACE RECORD offset=%x interface=%x",offset,rec->input));

            if (name_len == 0) {
                K12_DBG(5,("k12_open: failed (name_len == 0 in source description"));
                destroy_k12_file_data(file_data);
                g_free(rec);
                return WTAP_OPEN_NOT_MINE;
            }
            if (stack_len == 0) {
                K12_DBG(5,("k12_open: failed (stack_len == 0 in source description"));
                destroy_k12_file_data(file_data);
                g_free(rec);
                return WTAP_OPEN_NOT_MINE;
            }
            if (rec_len < K12_SRCDESC_HWPART + hwpart_len + name_len + stack_len) {
                /*
                 * Record isn't long enough to have the full source descriptor
                 * field, including the variable-length parts.
                 */
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("k12: source descriptor record length %u < %u (%u + %u + %u + %u)",
                                            rec_len,
                                            K12_SRCDESC_HWPART + hwpart_len + name_len + stack_len,
                                            K12_SRCDESC_HWPART, hwpart_len, name_len, stack_len);
                destroy_k12_file_data(file_data);
                g_free(rec);
                return WTAP_OPEN_ERROR;
            }

            if (hwpart_len) {
                if (hwpart_len < 4) {
                    /* Hardware part isn't long enough to have a type field */
                    *err = WTAP_ERR_BAD_FILE;
                    *err_info = ws_strdup_printf("k12: source descriptor hardware part length %u < 4",
                                                hwpart_len);
                    destroy_k12_file_data(file_data);
                    g_free(rec);
                    return WTAP_OPEN_ERROR;
                }
                switch(( rec->input_type = pntoh32( read_buffer + K12_SRCDESC_HWPART + K12_SRCDESC_HWPARTTYPE ) )) {
                    case K12_PORT_DS0S:
                        /* This appears to be variable-length */
                        rec->input_info.ds0mask = 0x00000000;
                        if (hwpart_len > K12_SRCDESC_DS0_MASK) {
                            for (i = 0; i < hwpart_len - K12_SRCDESC_DS0_MASK; i++) {
                                rec->input_info.ds0mask |= ( *(read_buffer + K12_SRCDESC_HWPART + K12_SRCDESC_DS0_MASK + i) == 0xff ) ? 1U<<(31-i) : 0x0;
                            }
                        }
                        break;
                    case K12_PORT_ATMPVC:
                        if (hwpart_len < K12_SRCDESC_ATM_VCI + 2) {
                            /* Hardware part isn't long enough to have ATM information */
                            *err = WTAP_ERR_BAD_FILE;
                            *err_info = ws_strdup_printf("k12: source descriptor hardware part length %u < %u",
                                                        hwpart_len,
                                                        K12_SRCDESC_ATM_VCI + 2);
                            destroy_k12_file_data(file_data);
                            g_free(rec);
                            return WTAP_OPEN_ERROR;
                        }

                        rec->input_info.atm.vp = pntoh16( read_buffer + K12_SRCDESC_HWPART + K12_SRCDESC_ATM_VPI );
                        rec->input_info.atm.vc = pntoh16( read_buffer + K12_SRCDESC_HWPART + K12_SRCDESC_ATM_VCI );
                        break;
                    default:
                        break;
                }
            } else {
                /* Record viewer generated files don't have this information */
                if (port_type >= 0x14
                    && port_type <= 0x17) {
                    /* For ATM2_E1DS1, ATM2_E3DS3,
                       ATM2_STM1EL and ATM2_STM1OP */
                    rec->input_type = K12_PORT_ATMPVC;
                    rec->input_info.atm.vp = 0;
                    rec->input_info.atm.vc = 0;
                }
            }

            if (read_buffer[K12_SRCDESC_HWPART + hwpart_len + name_len - 1] != '\0') {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup("k12_open: source descriptor record contains non-null-terminated link-layer name");
                destroy_k12_file_data(file_data);
                g_free(rec);
                return WTAP_OPEN_ERROR;
            }
            if (read_buffer[K12_SRCDESC_HWPART + hwpart_len + name_len + stack_len - 1] != '\0') {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup("k12_open: source descriptor record contains non-null-terminated stack path");
                destroy_k12_file_data(file_data);
                g_free(rec);
                return WTAP_OPEN_ERROR;
            }
            rec->input_name = (char *)g_memdup2(read_buffer + K12_SRCDESC_HWPART + hwpart_len, name_len);
            rec->stack_file = (char *)g_memdup2(read_buffer + K12_SRCDESC_HWPART + hwpart_len + name_len, stack_len);

            ascii_strdown_inplace (rec->stack_file);

            g_hash_table_insert(file_data->src_by_id,GUINT_TO_POINTER(rec->input),rec);
            g_hash_table_insert(file_data->src_by_name,rec->stack_file,rec);
            break;

        case K12_REC_STK_FILE:
            K12_DBG(1,("k12_open: K12_REC_STK_FILE"));
            K12_DBG(1,("Field 1: 0x%08x",pntoh32( read_buffer + 0x08 )));
            K12_DBG(1,("Field 2: 0x%08x",pntoh32( read_buffer + 0x0c )));
            K12_ASCII_DUMP(1, read_buffer, rec_len, 16);
            break;

        default:
            K12_DBG(1,("k12_open: RECORD TYPE 0x%08x",type));
            break;
        }
        offset += len;
        file_data->num_of_records--;
    } while(1);

    wth->file_type_subtype = k12_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_K12;
    wth->snapshot_length = 0;
    wth->subtype_read = k12_read;
    wth->subtype_seek_read = k12_seek_read;
    wth->subtype_close = k12_close;
    wth->priv = (void *)file_data;
    wth->file_tsprec = WTAP_TSPREC_NSEC;

    /*
     * Add an IDB; we don't know how many interfaces were
     * involved, so we just say one interface, about which
     * we only know the link-layer type, snapshot length,
     * and time stamp resolution.
     */
    wtap_add_generated_idb(wth);

    return WTAP_OPEN_MINE;
}

typedef struct {
    uint32_t file_len;
    uint32_t num_of_records;
    uint32_t file_offset;
} k12_dump_t;

static int k12_dump_can_write_encap(int encap) {

    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    if (encap != WTAP_ENCAP_K12)
        return WTAP_ERR_UNWRITABLE_ENCAP;

    return 0;
}

static const char dumpy_junk[] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

static bool k12_dump_record(wtap_dumper *wdh, uint32_t len,  uint8_t* buffer, int *err_p) {
    k12_dump_t *k12 = (k12_dump_t *)wdh->priv;
    uint32_t junky_offset = (8192 - ( (k12->file_offset - K12_FILE_HDR_LEN) % 8192 )) % 8192;

    if (len > junky_offset) {
        if (junky_offset) {
            if (! wtap_dump_file_write(wdh, buffer, junky_offset, err_p))
                return false;
        }
        if (! wtap_dump_file_write(wdh, dumpy_junk, K12_FILE_BLOB_LEN, err_p))
            return false;

        if (! wtap_dump_file_write(wdh, buffer+junky_offset, len - junky_offset, err_p))
            return false;

        k12->file_offset += len + K12_FILE_BLOB_LEN;
        k12->file_len += len + K12_FILE_BLOB_LEN;
    } else {
        if (! wtap_dump_file_write(wdh, buffer, len, err_p))
            return false;
        k12->file_offset += len;
        k12->file_len += len;
    }

    k12->num_of_records++;
    return true;
}

static void k12_dump_src_setting(void *k _U_, void *v, void *p) {
    k12_src_desc_t* src_desc = (k12_src_desc_t*)v;
    wtap_dumper *wdh = (wtap_dumper *)p;
    uint32_t len;
    unsigned offset;
    unsigned i;
    int   errxxx; /* dummy */

    union {
        uint8_t buffer[8192];

        struct {
            uint32_t len;
            uint32_t type;
            uint32_t unk32_1;
            uint32_t input;

            uint16_t unk32_2;
            uint16_t color;
            uint32_t unk32_3;
            uint32_t unk32_4;
            uint16_t unk16_1;
            uint16_t hwpart_len;

            uint16_t name_len;
            uint16_t stack_len;

            struct {
                uint32_t type;

                union {
                    struct {
                        uint32_t unk32;
                        uint8_t mask[32];
                    } ds0mask;

                    struct {
                        uint8_t unk_data[16];
                        uint16_t vp;
                        uint16_t vc;
                    } atm;

                    uint32_t unk;
                } desc;
            } extra;
        } record;
    } obj;

    obj.record.type = g_htonl(K12_REC_SRCDSC);
    obj.record.unk32_1 = g_htonl(0x00000001);
    obj.record.input = g_htonl(src_desc->input);

    obj.record.unk32_2 = g_htons(0x0000);
    obj.record.color = g_htons(0x060f);
    obj.record.unk32_3 = g_htonl(0x00000003);
    switch (src_desc->input_type) {
        case K12_PORT_ATMPVC:
            obj.record.unk32_4 = g_htonl(0x01001400);
            break;
        default:
            obj.record.unk32_4 = g_htonl(0x01000100);
    }

    obj.record.unk16_1 = g_htons(0x0000);
    obj.record.name_len = (uint16_t) strlen(src_desc->input_name) + 1;
    obj.record.stack_len = (uint16_t) strlen(src_desc->stack_file) + 1;

    obj.record.extra.type = g_htonl(src_desc->input_type);

    switch (src_desc->input_type) {
        case K12_PORT_ATMPVC:
            obj.record.hwpart_len = g_htons(0x18);
            obj.record.extra.desc.atm.vp = g_htons(src_desc->input_info.atm.vp);
            obj.record.extra.desc.atm.vc = g_htons(src_desc->input_info.atm.vc);
            offset = 0x3c;
            break;
        case K12_PORT_DS0S:
            obj.record.hwpart_len = g_htons(0x18);
            for( i=0; i<32; i++ ) {
                obj.record.extra.desc.ds0mask.mask[i] =
                (src_desc->input_info.ds0mask & (1UL << i)) ? 0xff : 0x00;
            }
            offset = 0x3c;
            break;
        default:
            obj.record.hwpart_len = g_htons(0x08);
            offset = 0x2c;
            break;
    }

    memcpy(obj.buffer + offset,
           src_desc->input_name,
           obj.record.name_len);

    memcpy(obj.buffer + offset + obj.record.name_len,
           src_desc->stack_file,
           obj.record.stack_len);

    len = offset + obj.record.name_len + obj.record.stack_len;
    len += (len % 4) ? 4 - (len % 4) : 0;

    obj.record.len = g_htonl(len);
    obj.record.name_len =  g_htons(obj.record.name_len);
    obj.record.stack_len = g_htons(obj.record.stack_len);

    k12_dump_record(wdh,len,obj.buffer, &errxxx); /* fwrite errs ignored: see k12_dump below */
}

static bool k12_dump(wtap_dumper *wdh, const wtap_rec *rec,
                         const uint8_t *pd, int *err, char **err_info _U_) {
    const union wtap_pseudo_header *pseudo_header = &rec->rec_header.packet_header.pseudo_header;
    k12_dump_t *k12 = (k12_dump_t *)wdh->priv;
    uint32_t len;
    union {
        uint8_t buffer[8192];
        struct {
            uint32_t len;
            uint32_t type;
            uint32_t frame_len;
            uint32_t input;

            uint32_t datum_1;
            uint32_t datum_2;
            uint64_t ts;

            uint8_t frame[0x1fc0];
        } record;
    } obj;

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

    if (k12->num_of_records == 0) {
        k12_t* file_data = (k12_t*)pseudo_header->k12.stuff;
        /* XXX: We'll assume that any fwrite errors in k12_dump_src_setting will    */
        /*      repeat during the final k12_dump_record at the end of k12_dump      */
        /*      (and thus cause an error return from k12_dump).                     */
        /*      (I don't see a reasonably clean way to handle any fwrite errors     */
        /*       encountered in k12_dump_src_setting).                              */
        g_hash_table_foreach(file_data->src_by_id,k12_dump_src_setting,wdh);
    }
    obj.record.len = 0x20 + rec->rec_header.packet_header.caplen;
    obj.record.len += (obj.record.len % 4) ? 4 - obj.record.len % 4 : 0;

    len = obj.record.len;

    obj.record.len = g_htonl(obj.record.len);

    obj.record.type = g_htonl(K12_REC_PACKET);
    obj.record.frame_len = g_htonl(rec->rec_header.packet_header.caplen);
    obj.record.input = g_htonl(pseudo_header->k12.input);

    obj.record.ts = GUINT64_TO_BE((((uint64_t)rec->ts.secs - 631152000) * 2000000) + (rec->ts.nsecs / 1000 * 2));

    memcpy(obj.record.frame,pd,rec->rec_header.packet_header.caplen);

    return k12_dump_record(wdh,len,obj.buffer, err);
}

static const uint8_t k12_eof[] = {0xff,0xff};

static bool k12_dump_finish(wtap_dumper *wdh, int *err, char **err_info _U_) {
    k12_dump_t *k12 = (k12_dump_t *)wdh->priv;
    union {
        uint8_t b[sizeof(uint32_t)];
        uint32_t u;
    } d;

    if (! wtap_dump_file_write(wdh, k12_eof, 2, err))
        return false;
    k12->file_len += 2;

    if (wtap_dump_file_seek(wdh, K12_FILE_HDR_FILE_SIZE, SEEK_SET, err) == -1)
        return false;

    d.u = g_htonl(k12->file_len);

    if (! wtap_dump_file_write(wdh, d.b, 4, err))
        return false;

    if (wtap_dump_file_seek(wdh, K12_FILE_HDR_PAGE_SIZE, SEEK_SET, err) == -1)
        return false;

    d.u = g_htonl(8192);

    if (! wtap_dump_file_write(wdh, d.b, 4, err))
        return false;

    if (wtap_dump_file_seek(wdh, K12_FILE_HDR_RECORD_COUNT_1, SEEK_SET, err) == -1)
        return false;

    d.u = g_htonl(k12->num_of_records);

    if (! wtap_dump_file_write(wdh, d.b, 4, err))
        return false;

    if (wtap_dump_file_seek(wdh, K12_FILE_HDR_RECORD_COUNT_2, SEEK_SET, err) == -1)
        return false;

    d.u = g_htonl(k12->num_of_records);

    if (! wtap_dump_file_write(wdh, d.b, 4, err))
        return false;

    /* Prevent the above calls to wtap_dump_file_write() from
     * double-counting the header length
     */
    wdh->bytes_dumped = k12->file_len;
    return true;
}


static bool k12_dump_open(wtap_dumper *wdh, int *err, char **err_info _U_) {
    k12_dump_t *k12;

    if ( ! wtap_dump_file_write(wdh, k12_file_magic, 8, err)) {
        return false;
    }

    if (wtap_dump_file_seek(wdh, K12_FILE_HDR_LEN, SEEK_SET, err) == -1)
        return false;

    wdh->bytes_dumped = K12_FILE_HDR_LEN;
    wdh->subtype_write = k12_dump;
    wdh->subtype_finish = k12_dump_finish;

    k12 = g_new(k12_dump_t, 1);
    wdh->priv = (void *)k12;
    k12->file_len = K12_FILE_HDR_LEN;
    k12->num_of_records = 0;
    k12->file_offset  = K12_FILE_HDR_LEN;

    return true;
}

static const struct supported_block_type k12_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info k12_info = {
    "Tektronix K12xx 32-bit .rf5 format", "rf5", "rf5", NULL,
    true, BLOCKS_SUPPORTED(k12_blocks_supported),
    k12_dump_can_write_encap, k12_dump_open, NULL
};

void register_k12(void)
{
    k12_file_type_subtype = wtap_register_file_type_subtype(&k12_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("K12",
                                                   k12_file_type_subtype);
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
