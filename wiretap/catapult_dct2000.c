/* catapult_dct2000.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "catapult_dct2000.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <wsutil/strtoi.h>

#include "wtap-int.h"
#include "file_wrappers.h"

#define MAX_FIRST_LINE_LENGTH      150
#define MAX_TIMESTAMP_LINE_LENGTH  50
#define MAX_LINE_LENGTH            131072
#define MAX_SECONDS_CHARS          16
#define MAX_TIMESTAMP_LEN          (MAX_SECONDS_CHARS+5)
#define MAX_SUBSECOND_DECIMALS     4
#define MAX_CONTEXT_NAME           64
#define MAX_PROTOCOL_NAME          64
#define MAX_PORT_DIGITS            2
#define MAX_VARIANT_DIGITS         16
#define MAX_OUTHDR_NAME            256
#define AAL_HEADER_CHARS           12

/* 's' or 'r' of a packet as read from .out file */
typedef enum packet_direction_t
{
    sent,
    received
} packet_direction_t;


/***********************************************************************/
/* For each line, store (in case we need to dump):                     */
/* - String before time field                                          */
/* - Whether or not " l " appears after timestamp                      */
typedef struct
{
    char *before_time;
    bool has_l;
} line_prefix_info_t;


/*******************************************************************/
/* Information stored external to a file (wtap) needed for reading and dumping */
typedef struct dct2000_file_externals
{
    /* Remember the time at the start of capture */
    time_t  start_secs;
    uint32_t start_usecs;

    /*
     * The following information is needed only for dumping.
     *
     * XXX - Wiretap is not *supposed* to require that a packet being
     * dumped come from a file of the same type that you currently have
     * open; this should be fixed.
     */

    /* Buffer to hold first line, including magic and format number */
    char firstline[MAX_FIRST_LINE_LENGTH];
    int  firstline_length;

    /* Buffer to hold second line with formatted file creation data/time */
    char secondline[MAX_TIMESTAMP_LINE_LENGTH];
    int  secondline_length;

    /* Hash table to store text prefix data part of displayed packets.
       Records (file offset -> line_prefix_info_t)
    */
    GHashTable *packet_prefix_table;
} dct2000_file_externals_t;

/* 'Magic number' at start of Catapult DCT2000 .out files. */
static const char catapult_dct2000_magic[] = "Session Transcript";

/************************************************************/
/* Functions called from wiretap core                       */
static bool catapult_dct2000_read(wtap *wth, wtap_rec *rec,
                                      Buffer *buf, int *err, char **err_info,
                                      int64_t *data_offset);
static bool catapult_dct2000_seek_read(wtap *wth, int64_t seek_off,
                                           wtap_rec *rec,
                                           Buffer *buf, int *err,
                                           char **err_info);
static void catapult_dct2000_close(wtap *wth);

static bool catapult_dct2000_dump(wtap_dumper *wdh, const wtap_rec *rec,
                                      const uint8_t *pd, int *err, char **err_info);


/************************************************************/
/* Private helper functions                                 */
static bool read_new_line(FILE_T fh, int *length,
                              char *buf, size_t bufsize, int *err,
                              char **err_info);
static bool parse_line(char *linebuff, int line_length,
                           int *seconds, int *useconds,
                           long *before_time_offset, long *after_time_offset,
                           long *data_offset,
                           int *data_chars,
                           packet_direction_t *direction,
                           int *encap, int *is_comment, int *is_sprint,
                           char *aal_header_chars,
                           char *context_name, uint8_t *context_portp,
                           char *protocol_name, char *variant_name,
                           char *outhdr_name);
static bool process_parsed_line(wtap *wth,
                                    const dct2000_file_externals_t *file_externals,
                                    wtap_rec *rec,
                                    Buffer *buf, int64_t file_offset,
                                    char *linebuff, long dollar_offset,
                                    int seconds, int useconds,
                                    char *timestamp_string,
                                    packet_direction_t direction, int encap,
                                    char *context_name, uint8_t context_port,
                                    char *protocol_name, char *variant_name,
                                    char *outhdr_name, char *aal_header_chars,
                                    bool is_comment, int data_chars,
                                    int *err, char **err_info);
static uint8_t hex_from_char(char c);
static void   prepare_hex_byte_from_chars_table(void);
static uint8_t hex_byte_from_chars(char *c);
static char char_from_hex(uint8_t hex);

static void set_aal_info(union wtap_pseudo_header *pseudo_header,
                         packet_direction_t direction,
                         char *aal_header_chars);
static void set_isdn_info(union wtap_pseudo_header *pseudo_header,
                          packet_direction_t direction);
static void set_ppp_info(union wtap_pseudo_header *pseudo_header,
                         packet_direction_t direction);

static int packet_offset_equal(const void *v, const void *v2);
static unsigned packet_offset_hash_func(const void *v);

static bool get_file_time_stamp(const char *linebuff, time_t *secs, uint32_t *usecs);
static gboolean free_line_prefix_info(void *key, void *value, void *user_data);

static int dct2000_file_type_subtype = -1;

void register_dct2000(void);


/********************************************/
/* Open file (for reading)                 */
/********************************************/
wtap_open_return_val
catapult_dct2000_open(wtap *wth, int *err, char **err_info)
{
    time_t  timestamp;
    uint32_t usecs;
    int firstline_length = 0;
    dct2000_file_externals_t *file_externals;
    static char linebuff[MAX_LINE_LENGTH];
    static bool hex_byte_table_values_set = false;

    /* Clear errno before reading from the file */
    errno = 0;


    /********************************************************************/
    /* First line needs to contain at least as many characters as magic */

    if (!read_new_line(wth->fh, &firstline_length, linebuff,
                       sizeof linebuff, err, err_info)) {
        if (*err != 0 && *err != WTAP_ERR_SHORT_READ) {
            return WTAP_OPEN_ERROR;
        }
        else {
            return WTAP_OPEN_NOT_MINE;
        }
    }
    if (((size_t)firstline_length < strlen(catapult_dct2000_magic)) ||
        firstline_length >= MAX_FIRST_LINE_LENGTH) {

        return WTAP_OPEN_NOT_MINE;
    }

    /* This file is not for us if it doesn't match our signature */
    if (memcmp(catapult_dct2000_magic, linebuff, strlen(catapult_dct2000_magic)) != 0) {
        return WTAP_OPEN_NOT_MINE;
    }

    /* Make sure table is ready for use */
    if (!hex_byte_table_values_set) {
        prepare_hex_byte_from_chars_table();
        hex_byte_table_values_set = true;
    }

    /*********************************************************************/
    /* Need entry in file_externals table                                */

    /* Allocate a new file_externals structure for this file */
    file_externals = g_new0(dct2000_file_externals_t, 1);

    /* Copy this first line into buffer so could write out later */
    (void) g_strlcpy(file_externals->firstline, linebuff, firstline_length+1);
    file_externals->firstline_length = firstline_length;


    /***********************************************************/
    /* Second line contains file timestamp                     */
    /* Store this offset in file_externals                     */

    if (!read_new_line(wth->fh, &(file_externals->secondline_length),
                       linebuff, sizeof linebuff, err, err_info)) {
        g_free(file_externals);
        if (*err != 0 && *err != WTAP_ERR_SHORT_READ) {
            return WTAP_OPEN_ERROR;
        }
        else {
            return WTAP_OPEN_NOT_MINE;
        }
    }
    if ((file_externals->secondline_length >= MAX_TIMESTAMP_LINE_LENGTH) ||
        (!get_file_time_stamp(linebuff, &timestamp, &usecs))) {

        /* Give up if file time line wasn't valid */
        g_free(file_externals);
        return WTAP_OPEN_NOT_MINE;
    }

    /* Fill in timestamp */
    file_externals->start_secs = timestamp;
    file_externals->start_usecs = usecs;

    /* Copy this second line into buffer so could write out later */
    (void) g_strlcpy(file_externals->secondline, linebuff, file_externals->secondline_length+1);


    /************************************************************/
    /* File is for us. Fill in details so packets can be read   */

    /* Set our file type */
    wth->file_type_subtype = dct2000_file_type_subtype;

    /* Use our own encapsulation to send all packets to our stub dissector */
    wth->file_encap = WTAP_ENCAP_CATAPULT_DCT2000;

    /* Callbacks for reading operations */
    wth->subtype_read = catapult_dct2000_read;
    wth->subtype_seek_read = catapult_dct2000_seek_read;
    wth->subtype_close = catapult_dct2000_close;

    /* Choose microseconds (have 4 decimal places...) */
    wth->file_tsprec = WTAP_TSPREC_USEC;


    /***************************************************************/
    /* Initialise packet_prefix_table (index is offset into file)  */
    file_externals->packet_prefix_table =
        g_hash_table_new(packet_offset_hash_func, packet_offset_equal);

    /* Set this wtap to point to the file_externals */
    wth->priv = (void*)file_externals;

    *err = errno;

    /*
     * Add an IDB; we don't know how many interfaces were
     * involved, so we just say one interface, about which
     * we only know the link-layer type, snapshot length,
     * and time stamp resolution.
     */
    wtap_add_generated_idb(wth);

    return WTAP_OPEN_MINE;
}

/* Ugly, but much faster than using snprintf! */
static void write_timestamp_string(char *timestamp_string, int secs, int tenthousandths)
{
    int idx = 0;

    /* Secs */
    if (secs < 10) {
        timestamp_string[idx++] = ((secs % 10))           + '0';
    }
    else if (secs < 100) {
        timestamp_string[idx++] = ( secs          / 10)   + '0';
        timestamp_string[idx++] = ((secs % 10))           + '0';
    }
    else if (secs < 1000) {
        timestamp_string[idx++] = ((secs)         / 100)   + '0';
        timestamp_string[idx++] = ((secs % 100))  / 10     + '0';
        timestamp_string[idx++] = ((secs % 10))            + '0';
    }
    else if (secs < 10000) {
        timestamp_string[idx++] = ((secs)          / 1000)   + '0';
        timestamp_string[idx++] = ((secs % 1000))  / 100     + '0';
        timestamp_string[idx++] = ((secs % 100))   / 10      + '0';
        timestamp_string[idx++] = ((secs % 10))              + '0';
    }
    else if (secs < 100000) {
        timestamp_string[idx++] = ((secs)          / 10000)   + '0';
        timestamp_string[idx++] = ((secs % 10000)) / 1000     + '0';
        timestamp_string[idx++] = ((secs % 1000))  / 100      + '0';
        timestamp_string[idx++] = ((secs % 100))   / 10       + '0';
        timestamp_string[idx++] = ((secs % 10))               + '0';
    }
    else if (secs < 1000000) {
        timestamp_string[idx++] = ((secs)           / 100000) + '0';
        timestamp_string[idx++] = ((secs % 100000)) / 10000   + '0';
        timestamp_string[idx++] = ((secs % 10000))  / 1000    + '0';
        timestamp_string[idx++] = ((secs % 1000))   / 100     + '0';
        timestamp_string[idx++] = ((secs % 100))    / 10      + '0';
        timestamp_string[idx++] = ((secs % 10))               + '0';
    }
    else {
        snprintf(timestamp_string, MAX_TIMESTAMP_LEN, "%d.%04d", secs, tenthousandths);
        return;
    }

    timestamp_string[idx++] = '.';
    timestamp_string[idx++] = ( tenthousandths          / 1000) + '0';
    timestamp_string[idx++] = ((tenthousandths % 1000)  / 100)  + '0';
    timestamp_string[idx++] = ((tenthousandths % 100)   / 10)   + '0';
    timestamp_string[idx++] = ((tenthousandths % 10))           + '0';
    timestamp_string[idx]   = '\0';
}

/**************************************************/
/* Read packet function.                          */
/* Look for and read the next usable packet       */
/* - return true and details if found             */
/**************************************************/
static bool
catapult_dct2000_read(wtap *wth, wtap_rec *rec, Buffer *buf,
                      int *err, char **err_info, int64_t *data_offset)
{
    long dollar_offset, before_time_offset, after_time_offset;
    packet_direction_t direction;
    int encap;

    /* Get wtap external structure for this wtap */
    dct2000_file_externals_t *file_externals =
        (dct2000_file_externals_t*)wth->priv;

    /* Search for a line containing a usable packet */
    while (1) {
        int line_length, seconds, useconds, data_chars;
        int is_comment = false;
        int is_sprint = false;
        int64_t this_offset;
        static char linebuff[MAX_LINE_LENGTH+1];
        char aal_header_chars[AAL_HEADER_CHARS];
        char context_name[MAX_CONTEXT_NAME];
        uint8_t context_port = 0;
        char protocol_name[MAX_PROTOCOL_NAME+1];
        char variant_name[MAX_VARIANT_DIGITS+1];
        char outhdr_name[MAX_OUTHDR_NAME+1];

        /* Get starting offset of the line we're about to read */
        this_offset = file_tell(wth->fh);

        /* Read a new line from file into linebuff */
        if (!read_new_line(wth->fh, &line_length, linebuff,
                           sizeof linebuff, err, err_info)) {
            if (*err != 0) {
                return false;  /* error */
            }
            /* No more lines can be read, so quit. */
            break;
        }

        /* Try to parse the line as a frame record */
        if (parse_line(linebuff, line_length, &seconds, &useconds,
                       &before_time_offset, &after_time_offset,
                       &dollar_offset,
                       &data_chars, &direction, &encap, &is_comment, &is_sprint,
                       aal_header_chars,
                       context_name, &context_port,
                       protocol_name, variant_name, outhdr_name)) {
            line_prefix_info_t *line_prefix_info;
            int64_t *pkey = NULL;
            char timestamp_string[MAX_TIMESTAMP_LEN+1];
            write_timestamp_string(timestamp_string, seconds, useconds/100);

            /* Set data_offset to the beginning of the line we're returning.
               This will be the seek_off parameter when this frame is re-read.
            */
            *data_offset = this_offset;

            if (!process_parsed_line(wth, file_externals,
                                     rec, buf, this_offset,
                                     linebuff, dollar_offset,
                                     seconds, useconds,
                                     timestamp_string,
                                     direction, encap,
                                     context_name, context_port,
                                     protocol_name, variant_name,
                                     outhdr_name, aal_header_chars,
                                     is_comment, data_chars,
                                     err, err_info))
                return false;

            /* Store the packet prefix in the hash table */
            line_prefix_info = g_new(line_prefix_info_t,1);

            /* Create and use buffer for contents before time */
            line_prefix_info->before_time = (char *)g_malloc(before_time_offset+1);
            memcpy(line_prefix_info->before_time, linebuff, before_time_offset);
            line_prefix_info->before_time[before_time_offset] = '\0';

            /* There is usually a ' l ' between the timestamp and the data.  Set flag to record this. */
            line_prefix_info->has_l =  ((size_t)(dollar_offset - after_time_offset -1) == strlen(" l ")) &&
                                        (strncmp(linebuff+after_time_offset, " l ", 3) == 0);

            /* Add packet entry into table */
            pkey = (int64_t *)g_malloc(sizeof(*pkey));
            *pkey = this_offset;
            g_hash_table_insert(file_externals->packet_prefix_table, pkey, line_prefix_info);

            /* OK, we have packet details to return */
            return true;
        }
    }

    /* No packet details to return... */
    return false;
}


/**************************************************/
/* Read & seek function.                          */
/**************************************************/
static bool
catapult_dct2000_seek_read(wtap *wth, int64_t seek_off,
                           wtap_rec *rec, Buffer *buf,
                           int *err, char **err_info)
{
    int length;
    long dollar_offset, before_time_offset, after_time_offset;
    static char linebuff[MAX_LINE_LENGTH+1];
    char aal_header_chars[AAL_HEADER_CHARS];
    char context_name[MAX_CONTEXT_NAME];
    uint8_t context_port = 0;
    char protocol_name[MAX_PROTOCOL_NAME+1];
    char variant_name[MAX_VARIANT_DIGITS+1];
    char outhdr_name[MAX_OUTHDR_NAME+1];
    int  is_comment = false;
    int  is_sprint = false;
    packet_direction_t direction;
    int encap;
    int seconds, useconds, data_chars;

    /* Get wtap external structure for this wtap */
    dct2000_file_externals_t *file_externals =
        (dct2000_file_externals_t*)wth->priv;

    /* Reset errno */
    *err = errno = 0;

    /* Seek to beginning of packet */
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1) {
        return false;
    }

    /* Re-read whole line (this really should succeed) */
    if (!read_new_line(wth->random_fh, &length, linebuff,
                      sizeof linebuff, err, err_info)) {
        return false;
    }

    /* Try to parse this line again (should succeed as re-reading...) */
    if (parse_line(linebuff, length, &seconds, &useconds,
                   &before_time_offset, &after_time_offset,
                   &dollar_offset,
                   &data_chars, &direction, &encap, &is_comment, &is_sprint,
                   aal_header_chars,
                   context_name, &context_port,
                   protocol_name, variant_name, outhdr_name)) {

        char timestamp_string[MAX_TIMESTAMP_LEN+1];
        write_timestamp_string(timestamp_string, seconds, useconds/100);

        if (!process_parsed_line(wth, file_externals,
                                 rec, buf, seek_off,
                                 linebuff, dollar_offset,
                                 seconds, useconds,
                                 timestamp_string,
                                 direction, encap,
                                 context_name, context_port,
                                 protocol_name, variant_name,
                                 outhdr_name, aal_header_chars,
                                 is_comment, data_chars,
                                 err, err_info)) {
            return false;
        }

        *err = errno = 0;
        return true;
    }

    /* If get here, must have failed */
    *err = errno;
    *err_info = ws_strdup_printf("catapult dct2000: seek_read failed to read/parse "
                                "line at position %" PRId64,
                                seek_off);
    return false;
}


/***************************************************************************/
/* Free dct2000-specific capture info from file that was open for reading  */
/***************************************************************************/
static void
catapult_dct2000_close(wtap *wth)
{
    /* Get externals for this file */
    dct2000_file_externals_t *file_externals =
        (dct2000_file_externals_t*)wth->priv;

    /* Free up its line prefix values */
    g_hash_table_foreach_remove(file_externals->packet_prefix_table,
                                free_line_prefix_info, NULL);
    /* Free up its line prefix table */
    g_hash_table_destroy(file_externals->packet_prefix_table);
}




/***************************/
/* Dump functions          */
/***************************/

typedef struct {
    bool       first_packet_written;
    nstime_t   start_time;
} dct2000_dump_t;

/*****************************************************/
/* The file that we are writing to has been opened.  */
/* Set other dump callbacks.                         */
/*****************************************************/
static bool
catapult_dct2000_dump_open(wtap_dumper *wdh, int *err _U_, char **err_info _U_)
{
    /* Fill in other dump callbacks */
    wdh->subtype_write = catapult_dct2000_dump;

    return true;
}

/*********************************************************/
/* Respond to queries about which encap types we support */
/* writing to.                                           */
/*********************************************************/
static int
catapult_dct2000_dump_can_write_encap(int encap)
{
    switch (encap) {
        case WTAP_ENCAP_CATAPULT_DCT2000:
            /* We support this */
            return 0;

        default:
            /* But can't write to any other formats... */
            return WTAP_ERR_UNWRITABLE_ENCAP;
    }
}


/*****************************************/
/* Write a single packet out to the file */
/*****************************************/

static bool
catapult_dct2000_dump(wtap_dumper *wdh, const wtap_rec *rec,
                      const uint8_t *pd, int *err, char **err_info _U_)
{
    const union wtap_pseudo_header *pseudo_header = &rec->rec_header.packet_header.pseudo_header;
    uint32_t n;
    line_prefix_info_t *prefix = NULL;
    char time_string[MAX_TIMESTAMP_LEN];
    bool is_comment;
    bool is_sprint = false;
    dct2000_dump_t *dct2000;
    int consecutive_slashes=0;
    char *p_c;

    /******************************************************/
    /* Get the file_externals structure for this file */
    /* Find wtap external structure for this wtap */
    dct2000_file_externals_t *file_externals =
        (dct2000_file_externals_t*)pseudo_header->dct2000.wth->priv;

    /* We can only write packet records. */
    if (rec->rec_type != REC_TYPE_PACKET) {
        *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
        return false;
    }

    /*
     * Make sure this packet doesn't have a link-layer type that
     * differs from the one for the file (which should always
     * be WTAP_ENCAP_CATAPULT_DCT2000).
     */
    if (wdh->file_encap != rec->rec_header.packet_header.pkt_encap) {
        *err = WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;
        return false;
    }

    dct2000 = (dct2000_dump_t *)wdh->priv;
    if (dct2000 == NULL) {

        /* Write out saved first line */
        if (!wtap_dump_file_write(wdh, file_externals->firstline,
                                  file_externals->firstline_length, err)) {
            return false;
        }
        if (!wtap_dump_file_write(wdh, "\n", 1, err)) {
            return false;
        }

        /* Also write out saved second line with timestamp corresponding to the
           opening time of the log.
        */
        if (!wtap_dump_file_write(wdh, file_externals->secondline,
                                  file_externals->secondline_length, err)) {
            return false;
        }
        if (!wtap_dump_file_write(wdh, "\n", 1, err)) {
            return false;
        }

        /* Allocate the dct2000-specific dump structure */
        dct2000 = g_new(dct2000_dump_t, 1);
        wdh->priv = (void *)dct2000;

        /* Copy time of beginning of file */
        dct2000->start_time.secs = file_externals->start_secs;
        dct2000->start_time.nsecs =
            (file_externals->start_usecs * 1000);

        /* Set flag so don't write header out again */
        dct2000->first_packet_written = true;
    }


    /******************************************************************/
    /* Write out this packet's prefix, including calculated timestamp */

    /* Look up line data prefix using stored offset */
    prefix = (line_prefix_info_t*)g_hash_table_lookup(file_externals->packet_prefix_table,
                                                      (const void*)&(pseudo_header->dct2000.seek_off));

    /* Write out text before timestamp */
    if (!wtap_dump_file_write(wdh, prefix->before_time,
                              strlen(prefix->before_time), err)) {
        return false;
    }

    /* Can infer from prefix if this is a comment (whose payload is displayed differently) */
    /* This is much faster than strstr() for "/////" */
    p_c = prefix->before_time;
    while (p_c && (*p_c != '/')) {
        p_c++;
    }
    while (p_c && (*p_c == '/')) {
        consecutive_slashes++;
        p_c++;
    }
    is_comment = (consecutive_slashes == 5);

    /* Calculate time of this packet to write, relative to start of dump */
    if (rec->ts.nsecs >= dct2000->start_time.nsecs) {
        write_timestamp_string(time_string,
                               (int)(rec->ts.secs - dct2000->start_time.secs),
                               (rec->ts.nsecs - dct2000->start_time.nsecs) / 100000);
    }
    else {
        write_timestamp_string(time_string,
                               (int)(rec->ts.secs - dct2000->start_time.secs-1),
                               ((1000000000 + (rec->ts.nsecs / 100000)) - (dct2000->start_time.nsecs / 100000)) % 10000);
    }

    /* Write out the calculated timestamp */
    if (!wtap_dump_file_write(wdh, time_string, strlen(time_string), err)) {
        return false;
    }

    /* Write out text between timestamp and start of hex data */
    if (prefix->has_l) {
        if (!wtap_dump_file_write(wdh, " l ", 3, err)) {
            return false;
        }
    }

    /****************************************************************/
    /* Need to skip stub header at start of pd before we reach data */

    /* Context name */
    for (n=0; pd[n] != '\0'; n++);
    n++;

    /* Context port number */
    n++;

    /* Timestamp */
    for (; pd[n] != '\0'; n++);
    n++;

    /* Protocol name */
    if (is_comment) {
        is_sprint = (strcmp((const char *)pd+n, "sprint") == 0);
    }
    for (; pd[n] != '\0'; n++);
    n++;

    /* Variant number (as string) */
    for (; pd[n] != '\0'; n++);
    n++;

    /* Outhdr (as string) */
    for (; pd[n] != '\0'; n++);
    n++;

    /* Direction & encap */
    n += 2;


    /**************************************/
    /* Remainder is encapsulated protocol */
    if (!wtap_dump_file_write(wdh, is_sprint ? " " : "$", 1, err)) {
        return false;
    }

    if (!is_comment) {
        /* Each binary byte is written out as 2 hex string chars */
        for (; n < rec->rec_header.packet_header.len; n++) {
            char c[2];
            c[0] = char_from_hex((uint8_t)(pd[n] >> 4));
            c[1] = char_from_hex((uint8_t)(pd[n] & 0x0f));

            /* Write both hex chars of byte together */
            if (!wtap_dump_file_write(wdh, c, 2, err)) {
                return false;
            }
        }
    }
    else {
        /* Comment */
        if (!wtap_dump_file_write(wdh, pd+n, rec->rec_header.packet_header.len-n, err)) {
            return false;
        }
    }

    /* End the line */
    if (!wtap_dump_file_write(wdh, "\n", 1, err)) {
        return false;
    }

    return true;
}


/****************************/
/* Private helper functions */
/****************************/

/**********************************************************************/
/* Read a new line from the file, starting at offset.                 */
/* - writes data to its argument linebuff                             */
/* - on return 'offset' will point to the next position to read from  */
/* - return true if this read is successful                           */
/**********************************************************************/
static bool
read_new_line(FILE_T fh, int *length,
              char *linebuff, size_t linebuffsize, int *err, char **err_info)
{
    /* Read in a line */
    int64_t pos_before = file_tell(fh);

    if (file_gets(linebuff, (int)linebuffsize - 1, fh) == NULL) {
        /* No characters found, or error */
        *err = file_error(fh, err_info);
        return false;
    }

    /* Set length (avoiding strlen()) and offset.. */
    *length = (int)(file_tell(fh) - pos_before);

    /* ...but don't want to include newline in line length */
    if (*length > 0 && linebuff[*length-1] == '\n') {
        linebuff[*length-1] = '\0';
        *length = *length - 1;
    }
    /* Nor do we want '\r' (as will be written when log is created on windows) */
    if (*length > 0 && linebuff[*length-1] == '\r') {
        linebuff[*length-1] = '\0';
        *length = *length - 1;
    }

    return true;
}


/**********************************************************************/
/* Parse a line from buffer, by identifying:                          */
/* - context, port and direction of packet                            */
/* - timestamp                                                        */
/* - data position and length                                         */
/* Return true if this packet looks valid and can be displayed        */
/**********************************************************************/
static bool
parse_line(char *linebuff, int line_length,
           int *seconds, int *useconds,
           long *before_time_offset, long *after_time_offset,
           long *data_offset, int *data_chars,
           packet_direction_t *direction,
           int *encap, int *is_comment, int *is_sprint,
           char *aal_header_chars,
           char *context_name, uint8_t *context_portp,
           char *protocol_name, char *variant_name,
           char *outhdr_name)
{
    int  n = 0;
    int  port_digits;
    char port_number_string[MAX_PORT_DIGITS+1];
    int  variant_digits;
    int  variant = 1;
    int  protocol_chars;
    int  outhdr_chars;

    char seconds_buff[MAX_SECONDS_CHARS+1];
    int  seconds_chars;
    char subsecond_decimals_buff[MAX_SUBSECOND_DECIMALS+1];
    int  subsecond_decimals_chars;
    int  skip_first_byte = false;
    bool atm_header_present = false;

    *is_comment = false;
    *is_sprint = false;

    /* Read context name until find '.' */
    for (n=0; (n < MAX_CONTEXT_NAME) && (n+1 < line_length) && (linebuff[n] != '.'); n++) {
        if (linebuff[n] == '/') {
            context_name[n] = '\0';

            /* If not a comment (/////), not a valid line */
            if (strncmp(linebuff+n, "/////", 5) != 0) {
                return false;
            }

            /* There is no variant, outhdr, etc.  Set protocol to be a comment */
            (void) g_strlcpy(protocol_name, "comment", MAX_PROTOCOL_NAME);
            *is_comment = true;
            break;
        }
        if (!g_ascii_isalnum(linebuff[n]) && (linebuff[n] != '_') && (linebuff[n] != '-')) {
            return false;
        }
        context_name[n] = linebuff[n];
    }
    if (n == MAX_CONTEXT_NAME || (n+1 >= line_length)) {
        return false;
    }

    /* Reset strings (that won't be set by comments) */
    variant_name[0] = '\0';
    outhdr_name[0] = '\0';
    port_number_string[0] = '\0';

    if (!(*is_comment)) {
        /* '.' must follow context name */
        if (linebuff[n] != '.') {
            return false;
        }
        context_name[n] = '\0';
        /* Skip it */
        n++;

        /* Now read port number */
        for (port_digits = 0;
             (linebuff[n] != '/') && (port_digits <= MAX_PORT_DIGITS) && (n+1 < line_length);
             n++, port_digits++) {

            if (!g_ascii_isdigit(linebuff[n])) {
                return false;
            }
            port_number_string[port_digits] = linebuff[n];
        }
        if (port_digits > MAX_PORT_DIGITS || (n+1 >= line_length)) {
            return false;
        }

        /* Slash char must follow port number */
        if (linebuff[n] != '/')
        {
            return false;
        }
        port_number_string[port_digits] = '\0';
        if (port_digits == 1) {
            *context_portp = port_number_string[0] - '0';
        }
        else {
            /* Everything in here is a digit, so we don't need to check
               whether what follows the number is anything other than
               a '\0'. */
            if (!ws_strtou8(port_number_string, NULL, context_portp)) {
              return false;
            }
        }
        /* Skip it */
        n++;

        /* Now for the protocol name */
        for (protocol_chars = 0;
             (linebuff[n] != '/') && (protocol_chars < MAX_PROTOCOL_NAME) && (n < line_length);
             n++, protocol_chars++) {

            if (!g_ascii_isalnum(linebuff[n]) && (linebuff[n] != '_') && (linebuff[n] != '.')) {
                return false;
            }
            protocol_name[protocol_chars] = linebuff[n];
        }
        if (protocol_chars == MAX_PROTOCOL_NAME || n >= line_length) {
            /* If doesn't fit, fail rather than truncate */
            return false;
        }
        protocol_name[protocol_chars] = '\0';

        /* Slash char must follow protocol name */
        if (linebuff[n] != '/') {
            return false;
        }
        /* Skip it */
        n++;


        /* Following the / is the variant number.  No digits indicate 1 */
        for (variant_digits = 0;
             (g_ascii_isdigit(linebuff[n])) && (variant_digits <= MAX_VARIANT_DIGITS) && (n+1 < line_length);
             n++, variant_digits++) {

            if (!g_ascii_isdigit(linebuff[n])) {
                return false;
            }
            variant_name[variant_digits] = linebuff[n];
        }
        if (variant_digits > MAX_VARIANT_DIGITS || (n+1 >= line_length)) {
            return false;
        }

        if (variant_digits > 0) {
            variant_name[variant_digits] = '\0';
            if (variant_digits == 1) {
                variant = variant_name[0] - '0';
            }
            else {
                if (!ws_strtoi32(variant_name, NULL, &variant)) {
                  return false;
                }
            }
        }
        else {
            variant_name[0] = '1';
            variant_name[1] = '\0';
        }


        /* Outheader values may follow */
        if (linebuff[n] == ',') {
            /* Skip , */
            n++;

            for (outhdr_chars = 0;
                 (g_ascii_isdigit(linebuff[n]) || linebuff[n] == ',') &&
                 (outhdr_chars <= MAX_OUTHDR_NAME) && (n+1 < line_length);
                 n++, outhdr_chars++) {

                if (!g_ascii_isdigit(linebuff[n]) && (linebuff[n] != ',')) {
                    return false;
                }
                outhdr_name[outhdr_chars] = linebuff[n];
            }
            if (outhdr_chars > MAX_OUTHDR_NAME || (n+1 >= line_length)) {
                return false;
            }
            /* Terminate (possibly empty) string */
            outhdr_name[outhdr_chars] = '\0';
        }
    }


    /******************************************************************/
    /* Now check whether we know how to use a packet of this protocol */

    if ((strcmp(protocol_name, "ip") == 0) ||
        (strcmp(protocol_name, "sctp") == 0) ||
        (strcmp(protocol_name, "gre") == 0) ||
        (strcmp(protocol_name, "mipv6") == 0) ||
        (strcmp(protocol_name, "igmp") == 0)) {

        *encap = WTAP_ENCAP_RAW_IP;
    }

    /* FP may be carried over ATM, which has separate atm header to parse */
    else
    if ((strcmp(protocol_name, "fp") == 0) ||
        (strncmp(protocol_name, "fp_r", 4) == 0)) {

        if ((variant > 256) && (variant % 256 == 3)) {
            /* FP over udp is contained in IPPrim... */
            *encap = 0;
        }
        else {
            /* FP over AAL0 or AAL2 */
            *encap = WTAP_ENCAP_ATM_PDUS_UNTRUNCATED;
            atm_header_present = true;
        }
    }
    else if (strcmp(protocol_name, "fpiur_r5") == 0) {
        /* FP (IuR) over AAL2 */
        *encap = WTAP_ENCAP_ATM_PDUS_UNTRUNCATED;
        atm_header_present = true;
    }

    else
    if (strcmp(protocol_name, "ppp") == 0) {
        *encap = WTAP_ENCAP_PPP;
    }
    else
    if (strcmp(protocol_name, "isdn_l3") == 0) {
       /* TODO: find out what this byte means... */
        skip_first_byte = true;
        *encap = WTAP_ENCAP_ISDN;
    }
    else
    if (strcmp(protocol_name, "isdn_l2") == 0) {
        *encap = WTAP_ENCAP_ISDN;
    }
    else
    if (strcmp(protocol_name, "ethernet") == 0) {
        *encap = WTAP_ENCAP_ETHERNET;
    }
    else
    if ((strcmp(protocol_name, "saalnni_sscop") == 0) ||
        (strcmp(protocol_name, "saaluni_sscop") == 0)) {

        *encap = DCT2000_ENCAP_SSCOP;
    }
    else
    if (strcmp(protocol_name, "frelay_l2") == 0) {
        *encap = WTAP_ENCAP_FRELAY;
    }
    else
    if (strcmp(protocol_name, "ss7_mtp2") == 0) {
        *encap = DCT2000_ENCAP_MTP2;
    }
    else
    if ((strcmp(protocol_name, "nbap") == 0) ||
        (strcmp(protocol_name, "nbap_r4") == 0) ||
        (strncmp(protocol_name, "nbap_sscfuni", strlen("nbap_sscfuni")) == 0)) {

        /* The entire message in these cases is nbap, so use an encap value. */
        *encap = DCT2000_ENCAP_NBAP;
    }
    else {
        /* Not a supported board port protocol/encap, but can show as raw data or
           in some cases find protocol embedded inside primitive */
        *encap = DCT2000_ENCAP_UNHANDLED;
    }


    /* Find separate ATM header if necessary */
    if (atm_header_present) {
        int header_chars_seen = 0;

        /* Scan ahead to the next $ */
        for (; (linebuff[n] != '$') && (n+1 < line_length); n++);
        /* Skip it */
        n++;
        if (n+1 >= line_length) {
            return false;
        }

        /* Read consecutive hex chars into atm header buffer */
        for (;
             ((n < line_length) &&
              (linebuff[n] >= '0') && (linebuff[n] <= '?') &&
              (header_chars_seen < AAL_HEADER_CHARS));
             n++, header_chars_seen++) {

            aal_header_chars[header_chars_seen] = linebuff[n];
            /* Next 6 characters after '9' are mapped to a->f */
            if (!g_ascii_isdigit(linebuff[n])) {
                aal_header_chars[header_chars_seen] = 'a' + (linebuff[n] - '9') -1;
            }
        }

        if (header_chars_seen != AAL_HEADER_CHARS || n >= line_length) {
            return false;
        }
    }

    /* Skip next '/' */
    n++;

    /* If there is a number, skip all info to next '/'.
       TODO: for IP encapsulation, should store PDCP ueid, drb in pseudo info
       and display dct2000 dissector... */
    if (g_ascii_isdigit(linebuff[n])) {
        while ((n+1 < line_length) && linebuff[n] != '/') {
            n++;
        }
    }

    /* Skip '/' */
    while ((n+1 < line_length) && linebuff[n] == '/') {
        n++;
    }

    /* Skip a space that may happen here */
    if ((n+1 < line_length) && linebuff[n] == ' ') {
        n++;
    }

    /* Next character gives direction of message (must be 's' or 'r') */
    if (!(*is_comment)) {
        if (linebuff[n] == 's') {
            *direction = sent;
        }
        else
        if (linebuff[n] == 'r') {
            *direction = received;
        }
        else {
            return false;
        }
        /* Skip it */
        n++;
    }
    else {
        *direction = sent;
    }


    /*********************************************************************/
    /* Find and read the timestamp                                       */

    /* Now scan to the next digit, which should be the start of the timestamp */
    /* This will involve skipping " tm "                                      */

    for (; ((linebuff[n] != 't') || (linebuff[n+1] != 'm')) && (n+1 < line_length); n++);
    if (n >= line_length) {
        return false;
    }

    for (; (n < line_length) && !g_ascii_isdigit(linebuff[n]); n++);
    if (n >= line_length) {
        return false;
    }

    *before_time_offset = n;

    /* Seconds */
    for (seconds_chars = 0;
         (linebuff[n] != '.') &&
         (seconds_chars <= MAX_SECONDS_CHARS) &&
         (n < line_length);
         n++, seconds_chars++) {

        if (!g_ascii_isdigit(linebuff[n])) {
            /* Found a non-digit before decimal point. Fail */
            return false;
        }
        seconds_buff[seconds_chars] = linebuff[n];
    }
    if (seconds_chars > MAX_SECONDS_CHARS || n >= line_length) {
        /* Didn't fit in buffer.  Fail rather than use truncated */
        return false;
    }

    /* Convert found value into number */
    seconds_buff[seconds_chars] = '\0';
    /* Already know they are digits, so avoid expense of ws_strtoi32() */
    int multiplier = 1;
    *seconds = 0;
    for (int d=seconds_chars-1; d >= 0; d--) {
        *seconds += ((seconds_buff[d]-'0')*multiplier);
        multiplier *= 10;
    }

    /* The decimal point must follow the last of the seconds digits */
    if (linebuff[n] != '.') {
        return false;
    }
    /* Skip it */
    n++;

    /* Subsecond decimal digits (expect 4-digit accuracy) */
    for (subsecond_decimals_chars = 0;
         (linebuff[n] != ' ') &&
         (subsecond_decimals_chars <= MAX_SUBSECOND_DECIMALS) &&
         (n < line_length);
         n++, subsecond_decimals_chars++) {

        if (!g_ascii_isdigit(linebuff[n])) {
            return false;
        }
        subsecond_decimals_buff[subsecond_decimals_chars] = linebuff[n];
    }
    if (subsecond_decimals_chars != MAX_SUBSECOND_DECIMALS || n >= line_length) {
        /* There should be exactly 4 subsecond digits - give up if not */
        return false;
    }
    /* Convert found value into microseconds */
    subsecond_decimals_buff[subsecond_decimals_chars] = '\0';
    /* Already know they are digits, so avoid expense of ws_strtoi32() */
    *useconds = ((subsecond_decimals_buff[0]-'0') * 100000) +
                ((subsecond_decimals_buff[1]-'0') * 10000) +
                ((subsecond_decimals_buff[2]-'0') * 1000) +
                ((subsecond_decimals_buff[3]-'0') * 100);

    /* Space character must follow end of timestamp */
    if (linebuff[n] != ' ') {
        return false;
    }

    *after_time_offset = n++;

    /* If we have a string message, it could either be a comment (with '$') or
       a sprint line (no '$') */
    if (*is_comment) {
        if (strncmp(linebuff+n, "l $", 3) != 0) {
            *is_sprint = true;
            (void) g_strlcpy(protocol_name, "sprint", MAX_PROTOCOL_NAME);
        }
    }

    if (!(*is_sprint)) {
        /* Now skip ahead to find start of data (marked by '$') */
        for (; (linebuff[n] != '$') && (linebuff[n] != '\'') && (n+1 < line_length); n++);
        if ((linebuff[n] == '\'') || (n+1 >= line_length)) {
            return false;
        }
        /* Skip it */
        n++;
    }

    /* Set offset to data start within line */
    *data_offset = n;

    /* Set number of chars that comprise the hex string protocol data */
    *data_chars = line_length - n;

    /* May need to skip first byte (2 hex string chars) */
    if (skip_first_byte) {
        *data_offset += 2;
        *data_chars -= 2;
    }

    return true;
}

/***********************************/
/* Process results of parse_line() */
/***********************************/
static bool
process_parsed_line(wtap *wth, const dct2000_file_externals_t *file_externals,
                    wtap_rec *rec,
                    Buffer *buf, int64_t file_offset,
                    char *linebuff, long dollar_offset,
                    int seconds, int useconds, char *timestamp_string,
                    packet_direction_t direction, int encap,
                    char *context_name, uint8_t context_port,
                    char *protocol_name, char *variant_name,
                    char *outhdr_name, char *aal_header_chars,
                    bool is_comment, int data_chars,
                    int *err, char **err_info)
{
    int n;
    int stub_offset = 0;
    size_t length;
    uint8_t *frame_buffer;

    rec->rec_type = REC_TYPE_PACKET;
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_TS;

    /* Make sure all packets go to Catapult DCT2000 dissector */
    rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_CATAPULT_DCT2000;

    /* Fill in timestamp (capture base + packet offset) */
    rec->ts.secs = file_externals->start_secs + seconds;
    if ((file_externals->start_usecs + useconds) >= 1000000) {
        rec->ts.secs++;
    }
    rec->ts.nsecs =
        ((file_externals->start_usecs + useconds) % 1000000) *1000;

    /*
     * Calculate the length of the stub info and the packet data.
     * The packet data length is half bytestring length.
     */
    rec->rec_header.packet_header.caplen = (unsigned)strlen(context_name)+1 +     /* Context name */
                   1 +                                 /* port */
                   (unsigned)strlen(timestamp_string)+1 + /* timestamp */
                   (unsigned)strlen(variant_name)+1 +     /* variant */
                   (unsigned)strlen(outhdr_name)+1 +      /* outhdr */
                   (unsigned)strlen(protocol_name)+1 +    /* Protocol name */
                   1 +                                 /* direction */
                   1 +                                 /* encap */
                   (is_comment ? data_chars : (data_chars/2));
    if (rec->rec_header.packet_header.caplen > WTAP_MAX_PACKET_SIZE_STANDARD) {
        /*
         * Probably a corrupt capture file; return an error,
         * so that our caller doesn't blow up trying to allocate
         * space for an immensely-large packet.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("catapult dct2000: File has %u-byte packet, bigger than maximum of %u",
                                    rec->rec_header.packet_header.caplen, WTAP_MAX_PACKET_SIZE_STANDARD);
        return false;
    }
    rec->rec_header.packet_header.len = rec->rec_header.packet_header.caplen;

    /*****************************/
    /* Get the data buffer ready */
    ws_buffer_assure_space(buf, rec->rec_header.packet_header.caplen);
    frame_buffer = ws_buffer_start_ptr(buf);

    /******************************************/
    /* Write the stub info to the data buffer */

    /* Context name */
    length = g_strlcpy((char*)frame_buffer, context_name, MAX_CONTEXT_NAME+1);
    stub_offset += (int)(length + 1);

    /* Context port number */
    frame_buffer[stub_offset] = context_port;
    stub_offset++;

    /* Timestamp within file (terminated string) */
    length = g_strlcpy((char*)&frame_buffer[stub_offset], timestamp_string, MAX_TIMESTAMP_LEN+1);
    stub_offset += (int)(length + 1);

    /* Protocol name (terminated string) */
    length = g_strlcpy((char*)&frame_buffer[stub_offset], protocol_name, MAX_PROTOCOL_NAME+1);
    stub_offset += (int)(length + 1);

    /* Protocol variant number (as terminated string) */
    length = g_strlcpy((char*)&frame_buffer[stub_offset], variant_name, MAX_VARIANT_DIGITS+1);
    stub_offset += (int)(length + 1);

    /* Outhdr (terminated string) */
    length = g_strlcpy((char*)&frame_buffer[stub_offset], outhdr_name, MAX_OUTHDR_NAME+1);
    stub_offset += (int)(length + 1);

    /* Direction */
    frame_buffer[stub_offset++] = direction;

    /* Encap */
    frame_buffer[stub_offset++] = (uint8_t)encap;

    if (!is_comment) {
        /***********************************************************/
        /* Copy packet data into buffer, converting from ascii hex */
        for (n=0; n < data_chars; n+=2) {
            frame_buffer[stub_offset + n/2] =
                hex_byte_from_chars(linebuff+dollar_offset+n);
        }
    }
    else {
        /***********************************************************/
        /* Copy packet data into buffer, just copying ascii chars  */
        for (n=0; n < data_chars; n++) {
            frame_buffer[stub_offset + n] = linebuff[dollar_offset+n];
        }
    }

    /*****************************************/
    /* Set packet pseudo-header if necessary */
    rec->rec_header.packet_header.pseudo_header.dct2000.seek_off = file_offset;
    rec->rec_header.packet_header.pseudo_header.dct2000.wth = wth;

    switch (encap) {
        case WTAP_ENCAP_ATM_PDUS_UNTRUNCATED:
            set_aal_info(&rec->rec_header.packet_header.pseudo_header, direction, aal_header_chars);
            break;
        case WTAP_ENCAP_ISDN:
            set_isdn_info(&rec->rec_header.packet_header.pseudo_header, direction);
            break;
        case WTAP_ENCAP_PPP:
            set_ppp_info(&rec->rec_header.packet_header.pseudo_header, direction);
            break;

        default:
            /* Other supported types don't need to set anything here... */
            break;
    }

    return true;
}

/*********************************************/
/* Fill in atm pseudo-header with known info */
/*********************************************/
static void
set_aal_info(union wtap_pseudo_header *pseudo_header,
             packet_direction_t direction,
             char *aal_header_chars)
{
    /* 'aal_head_chars' has this format (for AAL2 at least):
       Global Flow Control (4 bits) | VPI (8 bits) | VCI (16 bits) |
       Payload Type (4 bits) | Padding (3 bits?) | Link? (1 bit) |
       Channel Identifier (8 bits) | ...
    */

    /* Indicate that this is a reassembled PDU */
    pseudo_header->dct2000.inner_pseudo_header.atm.flags = 0x00;

    /* Channel 0 is DTE->DCE, 1 is DCE->DTE. Always set 0 for now.
       TODO: Can we infer the correct value here?
       Meanwhile, just use the direction to make them distinguishable...
    */
    pseudo_header->dct2000.inner_pseudo_header.atm.channel = (direction == received);

    /* Assume always AAL2 for FP */
    pseudo_header->dct2000.inner_pseudo_header.atm.aal = AAL_2;

    pseudo_header->dct2000.inner_pseudo_header.atm.type = TRAF_UMTS_FP;
    pseudo_header->dct2000.inner_pseudo_header.atm.subtype = TRAF_ST_UNKNOWN;

    /* vpi is 8 bits (2nd & 3rd nibble) */
    pseudo_header->dct2000.inner_pseudo_header.atm.vpi =
        hex_byte_from_chars(aal_header_chars+1);

    /* vci is next 16 bits */
    pseudo_header->dct2000.inner_pseudo_header.atm.vci =
        ((hex_from_char(aal_header_chars[3]) << 12) |
         (hex_from_char(aal_header_chars[4]) << 8) |
         (hex_from_char(aal_header_chars[5]) << 4) |
         hex_from_char(aal_header_chars[6]));

    /* 0 means we don't know how many cells the frame comprises. */
    pseudo_header->dct2000.inner_pseudo_header.atm.cells = 0;

    /* cid is usually last byte.  Unless last char is not hex digit, in which
       case cid is derived from last char in ascii */
    if (g_ascii_isalnum(aal_header_chars[11])) {
        pseudo_header->dct2000.inner_pseudo_header.atm.aal2_cid =
            hex_byte_from_chars(aal_header_chars+10);
    }
    else {
        pseudo_header->dct2000.inner_pseudo_header.atm.aal2_cid =
            (int)aal_header_chars[11] - '0';
    }
}


/**********************************************/
/* Fill in isdn pseudo-header with known info */
/**********************************************/
static void
set_isdn_info(union wtap_pseudo_header *pseudo_header,
              packet_direction_t direction)
{
    /* This field is used to set the 'Source' and 'Destination' columns to
       'User' or 'Network'. If we assume that we're simulating the network,
       treat Received messages as being destined for the network.
    */
    pseudo_header->dct2000.inner_pseudo_header.isdn.uton = (direction == received);

    /* This corresponds to the circuit ID.  0 is treated as LAPD,
       everything else would be treated as a B-channel
    */
    pseudo_header->dct2000.inner_pseudo_header.isdn.channel = 0;
}


/*********************************************/
/* Fill in ppp pseudo-header with known info */
/*********************************************/
static void
set_ppp_info(union wtap_pseudo_header *pseudo_header,
             packet_direction_t direction)
{
    /* Set direction. */
    pseudo_header->dct2000.inner_pseudo_header.p2p.sent = (direction == sent);
}


/********************************************************/
/* Return hex nibble equivalent of hex string character */
/********************************************************/
static uint8_t
hex_from_char(char c)
{
    if ((c >= '0') && (c <= '9')) {
        return c - '0';
    }

    if ((c >= 'a') && (c <= 'f')) {
        return 0x0a + (c - 'a');
    }

    /* Not a valid hex string character */
    return 0xff;
}



/* Table allowing fast lookup from a pair of ascii hex characters to a uint8_t */
static uint8_t s_tableValues[256][256];

/* Prepare table values so ready so don't need to check inside hex_byte_from_chars() */
static void  prepare_hex_byte_from_chars_table(void)
{
    const unsigned char hex_char_array[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                                        'a', 'b', 'c', 'd', 'e', 'f' };

    int i, j;
    for (i=0; i < 16; i++) {
        for (j=0; j < 16; j++) {
            s_tableValues[hex_char_array[i]][hex_char_array[j]] = i*16 + j;
        }
    }
}

/* Extract and return a byte value from 2 ascii hex chars, starting from the given pointer */
static uint8_t hex_byte_from_chars(char *c)
{
    /* Return value from quick table lookup */
    return s_tableValues[(unsigned char)c[0]][(unsigned char)c[1]];
}



/********************************************************/
/* Return character corresponding to hex nibble value   */
/********************************************************/
static char
char_from_hex(uint8_t hex)
{
    static const char hex_lookup[16] =
    { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    if (hex > 15) {
        return '?';
    }

    return hex_lookup[hex];
}

/***********************************************/
/* Equality test for packet prefix hash tables */
/***********************************************/
static int
packet_offset_equal(const void *v, const void *v2)
{
    /* Dereferenced pointers must have same int64_t offset value */
    return (*(const int64_t*)v == *(const int64_t*)v2);
}


/********************************************/
/* Hash function for packet-prefix hash table */
/********************************************/
static unsigned
packet_offset_hash_func(const void *v)
{
    /* Use low-order bits of int64_t offset value */
    return (unsigned)(*(const int64_t*)v);
}


/************************************************************************/
/* Parse year, month, day, hour, minute, seconds out of formatted line. */
/* Set secs and usecs as output                                         */
/* Return false if no valid time can be read                            */
/************************************************************************/
static bool
get_file_time_stamp(const char *linebuff, time_t *secs, uint32_t *usecs)
{
    struct tm tm;
    #define MAX_MONTH_LETTERS 9
    char month[MAX_MONTH_LETTERS+1];

    int day, year, hour, minute, second;
    int scan_found;

    /* If line longer than expected, file is probably not correctly formatted */
    if (strlen(linebuff) > MAX_TIMESTAMP_LINE_LENGTH) {
        return false;
    }

    /********************************************************/
    /* Scan for all fields                                  */
    scan_found = sscanf(linebuff, "%9s %2d, %4d     %2d:%2d:%2d.%4u",
                        month, &day, &year, &hour, &minute, &second, usecs);
    if (scan_found != 7) {
        /* Give up if not all found */
        return false;
    }

    if      (strcmp(month, "January"  ) == 0)  tm.tm_mon = 0;
    else if (strcmp(month, "February" ) == 0)  tm.tm_mon = 1;
    else if (strcmp(month, "March"    ) == 0)  tm.tm_mon = 2;
    else if (strcmp(month, "April"    ) == 0)  tm.tm_mon = 3;
    else if (strcmp(month, "May"      ) == 0)  tm.tm_mon = 4;
    else if (strcmp(month, "June"     ) == 0)  tm.tm_mon = 5;
    else if (strcmp(month, "July"     ) == 0)  tm.tm_mon = 6;
    else if (strcmp(month, "August"   ) == 0)  tm.tm_mon = 7;
    else if (strcmp(month, "September") == 0)  tm.tm_mon = 8;
    else if (strcmp(month, "October"  ) == 0)  tm.tm_mon = 9;
    else if (strcmp(month, "November" ) == 0)  tm.tm_mon = 10;
    else if (strcmp(month, "December" ) == 0)  tm.tm_mon = 11;
    else {
        /* Give up if not found a properly-formatted date */
        return false;
    }

    /******************************************************/
    /* Fill in remaining fields and return it in a time_t */
    tm.tm_year = year - 1900;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;
    tm.tm_isdst = -1;    /* daylight saving time info not known */

    /* Get seconds from this time */
    *secs = mktime(&tm);

    /* Multiply 4 digits given to get micro-seconds */
    *usecs = *usecs * 100;

    return true;
}

/* Free the data allocated inside a line_prefix_info_t */
static gboolean
free_line_prefix_info(void *key, void *value,
                      void *user_data _U_)
{
    line_prefix_info_t *info = (line_prefix_info_t*)value;

    /* Free the 64-bit key value */
    g_free(key);

    /* Free string */
    g_free(info->before_time);

    /* And the structure itself */
    g_free(info);

    /* Item will always be removed from table */
    return true;
}

static const struct supported_block_type dct2000_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info dct2000_info = {
    "Catapult DCT2000 trace (.out format)", "dct2000", "out", NULL,
    false, BLOCKS_SUPPORTED(dct2000_blocks_supported),
    catapult_dct2000_dump_can_write_encap, catapult_dct2000_dump_open, NULL
};

void register_dct2000(void)
{
    dct2000_file_type_subtype = wtap_register_file_type_subtype(&dct2000_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("CATAPULT_DCT2000",
                                                   dct2000_file_type_subtype);
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
