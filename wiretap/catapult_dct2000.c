/* catapult_dct2000.c
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
#include <stdlib.h>
#include <ctype.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"

#include "catapult_dct2000.h"

#define MAX_FIRST_LINE_LENGTH      200
#define MAX_TIMESTAMP_LINE_LENGTH  100
#define MAX_LINE_LENGTH            32000
#define MAX_SECONDS_CHARS          16
#define MAX_SUBSECOND_DECIMALS     4
#define MAX_CONTEXT_NAME           64
#define MAX_PROTOCOL_NAME          64
#define MAX_PORT_DIGITS            2
#define AAL_HEADER_CHARS           12

/* TODO:
   - support for x.25?
*/

/* 's' or 'r' of a packet as read from .out file */
typedef enum packet_direction_t
{
    sent,
    received
} packet_direction_t;


typedef struct
{
    gchar *before_time;
    gchar *after_time;
} line_prefix_info_t;

/*******************************************************************/
/* Information stored external to a file (wtap) needed for dumping */
typedef struct dct2000_file_externals
{
    /* Buffer to hold first line, including magic and format number */
    gchar firstline[MAX_FIRST_LINE_LENGTH];
    gint  firstline_length;

    /* Buffer to hold second line with formatted file creation data/time */
    gchar secondline[MAX_TIMESTAMP_LINE_LENGTH];
    gint  secondline_length;

    /* Hash table to store text prefix data part of displayed packets.
       Records (file offset -> pre-data-prefix-string)
       N.B. This is only needed for dumping
    */
    GHashTable *line_header_prefixes_table;
} dct2000_file_externals_t;

/* This global table maps wtap -> file_external structs */
static GHashTable *file_externals_table = NULL;


/***********************************************************/
/* Transient data used for parsing                         */

/* Buffer to hold a single text line read from the file */
static gchar linebuff[MAX_LINE_LENGTH];

/* Buffer for separate AAL header */
static gchar aal_header_chars[AAL_HEADER_CHARS];

/* 'Magic number' at start of Catapult DCT2000 .out files. */
static const gchar catapult_dct2000_magic[] = "Session Transcript";

/* Context name + port that the packet was captured at */
static gchar context_name[MAX_CONTEXT_NAME];
static guint8 context_port;

/* The DCT2000 protocol name of the packet */
static gchar protocol_name[MAX_PROTOCOL_NAME];

/*************************************************/
/* Preference state (shared with stub protocol). */
/* Set to FALSE to get better use out of other   */
/* wiretap applications (mergecap, editcap)      */
gboolean catapult_dct2000_board_ports_only = FALSE;

/************************************************************/
/* Functions called from wiretap                            */
static gboolean catapult_dct2000_read(wtap *wth, int *err, gchar **err_info,
                                      long *data_offset);
static gboolean catapult_dct2000_seek_read(wtap *wth, long seek_off,
                                           union wtap_pseudo_header *pseudo_header,
                                           guchar *pd, int length,
                                           int *err, gchar **err_info);
static void catapult_dct2000_close(wtap *wth);

static gboolean catapult_dct2000_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
                                      const union wtap_pseudo_header *pseudo_header,
                                      const guchar *pd, int *err);
static gboolean catapult_dct2000_dump_close(wtap_dumper *wdh, int *err);


/************************************************************/
/* Private helper functions                                 */
static gboolean read_new_line(FILE_T fh, long *offset, gint *length);
static gboolean parse_line(gint length, gint *seconds, gint *useconds,
                           long *before_time_offset, long *after_time_offset,
                           long *data_offset,
                           gint *data_chars,
                           packet_direction_t *direction,
                           int *encap,
                           gboolean seek_read);
static guchar hex_from_char(gchar c);
static gchar char_from_hex(guchar hex);

static void set_pseudo_header_info(wtap *wth,
                                   int pkt_encap,
                                   long file_offset,
                                   union wtap_pseudo_header *pseudo_header,
                                   gint length,
                                   packet_direction_t direction);
static void set_aal_info(union wtap_pseudo_header *pseudo_header, gint length,
                         packet_direction_t direction);
static void set_isdn_info(union wtap_pseudo_header *pseudo_header,
                          packet_direction_t direction);
static void set_ppp_info(union wtap_pseudo_header *pseudo_header,
                         packet_direction_t direction);


static gint prefix_equal(gconstpointer v, gconstpointer v2);
static guint prefix_hash_func(gconstpointer v);
static gboolean get_file_time_stamp(time_t *secs, guint32 *usecs);
static gboolean free_line_prefix_info(gpointer key, gpointer value, gpointer user_data);



/********************************************/
/* Open file                                */
/********************************************/
int catapult_dct2000_open(wtap *wth, int *err, gchar **err_info _U_)
{
    long    offset = 0;
    time_t  timestamp;
    guint32 usecs;
    gint firstline_length;
    dct2000_file_externals_t *file_externals;

    /* Clear errno before reading from the file */
    errno = 0;


    /*********************************************************************/
    /* Need entry in file_externals table                                */

    /* Create file externals table if it doesn't yet exist */
    if (file_externals_table == NULL)
    {
        file_externals_table = g_hash_table_new(prefix_hash_func, prefix_equal);
    }


    /********************************************************************/
    /* First line needs to contain at least as many characters as magic */

    read_new_line(wth->fh, &offset, &firstline_length);
    if (((size_t)firstline_length < strlen(catapult_dct2000_magic)) ||
        firstline_length >= MAX_FIRST_LINE_LENGTH)
    {
        return 0;
    }

    /* This file is not for us if it doesn't match our signature */
    if (memcmp(catapult_dct2000_magic, linebuff, strlen(catapult_dct2000_magic)) != 0)
    {
        return 0;
    }


    /* Allocate a new file_externals structure */
    file_externals = g_malloc(sizeof(dct2000_file_externals_t));
    memset((void*)file_externals, '\0', sizeof(dct2000_file_externals_t));

    /* Copy this first line into buffer so could write out later */
    strncpy(file_externals->firstline, linebuff, firstline_length);
    file_externals->firstline_length = firstline_length;


    /***********************************************************/
    /* Second line contains file timestamp                     */
    /* Store this offset in in wth->capture->catapult_dct2000  */

    read_new_line(wth->fh, &offset, &(file_externals->secondline_length));
    if ((file_externals->secondline_length >= MAX_TIMESTAMP_LINE_LENGTH) ||
        (!get_file_time_stamp(&timestamp, &usecs)))
    {
        /* Give up if file time line wasn't valid */
        g_free(file_externals);
        return 0;
    }

    wth->capture.catapult_dct2000 = g_malloc(sizeof(catapult_dct2000_t));
    wth->capture.catapult_dct2000->start_secs = timestamp;
    wth->capture.catapult_dct2000->start_usecs = usecs;

    /* Copy this second line into buffer so could write out later */
    strncpy(file_externals->secondline, linebuff, file_externals->secondline_length);


    /************************************************************/
    /* File is for us. Fill in details so packets can be read   */

    /* Set our file type */
    wth->file_type = WTAP_FILE_CATAPULT_DCT2000;

    /* Use our own encapsulation to send all packets to our stub dissector */
    wth->file_encap = WTAP_ENCAP_CATAPULT_DCT2000;

    /* Callbacks for reading operations */
    wth->subtype_read = catapult_dct2000_read;
    wth->subtype_seek_read = catapult_dct2000_seek_read;
    wth->subtype_close = catapult_dct2000_close;

    /* Choose microseconds (have 4 decimal places...) */
    wth->tsprecision = WTAP_FILE_TSPREC_USEC;


    /**********************************************/
    /* Initialise line_header_prefixes_table      */
    file_externals->line_header_prefixes_table =
        g_hash_table_new(prefix_hash_func, prefix_equal);

    /* Add file_externals for this wtap into the global table */
    g_hash_table_insert(file_externals_table,
                        (void*)wth, (void*)file_externals);

    *err = errno;
    return 1;
}


/**************************************************/
/* Read function.                                 */
/* Look for and read the next usable packet       */
/* - return TRUE and details if found             */
/**************************************************/
gboolean catapult_dct2000_read(wtap *wth, int *err, gchar **err_info _U_,
                               long *data_offset)
{
    long offset = wth->data_offset;
    long dollar_offset, before_time_offset, after_time_offset;
    packet_direction_t direction;
    int encap;

    /* Find wtap external structure for this wtap */
    dct2000_file_externals_t *file_externals =
        (dct2000_file_externals_t*)g_hash_table_lookup(file_externals_table, wth);

    /* There *has* to be an entry for this wth */
    if (!file_externals)
    {
        return FALSE;
    }

    /* Search for a line containing a usable board-port frame */
    while (1)
    {
        int length, seconds, useconds, data_chars;
        long this_offset = offset;

        /* Are looking for first packet after 2nd line */
        if (wth->data_offset == 0)
        {
            this_offset += (file_externals->firstline_length+1+
                            file_externals->secondline_length+1);
        }

        /* Clear errno before reading from the file */
        errno = 0;

        /* Read a new line from file into linebuff */
        if (read_new_line(wth->fh, &offset, &length) == FALSE)
        {
            /* Get out when no more lines to be read */
            break;
        }

        /* Try to parse the line as a message */
        if (parse_line(length, &seconds, &useconds,
                       &before_time_offset, &after_time_offset,
                       &dollar_offset,
                       &data_chars, &direction, &encap, FALSE))
        {
            guchar *frame_buffer;
            int n;
            int stub_offset = 0;
            line_prefix_info_t *line_prefix_info;
            char timestamp_string[32];
            sprintf(timestamp_string, "%d.%04d", seconds, useconds/100);

            /* All packets go to Catapult DCT2000 stub dissector */
            wth->phdr.pkt_encap = WTAP_ENCAP_CATAPULT_DCT2000;

            /* Set data_offset to the beginning of the line we're returning.
               This will be the seek_off parameter when this frame is re-read.
            */
            *data_offset = this_offset;

            /* This is the position in the file where the next _read() will be called from */
            wth->data_offset = this_offset + length + 1;

            /* Fill in timestamp (capture base + packet offset) */
            wth->phdr.ts.secs = wth->capture.catapult_dct2000->start_secs + seconds;
            if ((wth->capture.catapult_dct2000->start_usecs + useconds) >= 1000000)
            {
                wth->phdr.ts.secs++;
            }
            wth->phdr.ts.nsecs =
                ((wth->capture.catapult_dct2000->start_usecs + useconds) % 1000000) *1000;

            /* Get buffer pointer ready */
            buffer_assure_space(wth->frame_buffer,
                                strlen(context_name)+1 +  /* Context name */
                                1 +                       /* port */
                                strlen(protocol_name)+1 + /* Protocol name */
                                1 +                       /* direction */
                                1 +                       /* encap */
                                (data_chars/2));
            frame_buffer = buffer_start_ptr(wth->frame_buffer);


            /*********************/
            /* Write stub header */

            /* Context name */
            strcpy((char*)frame_buffer, context_name);
            stub_offset += (strlen(context_name) + 1);

            /* Context port number */
            frame_buffer[stub_offset] = context_port;
            stub_offset++;

            /* Timestamp within file */
            strcpy((char*)&frame_buffer[stub_offset], timestamp_string);
            stub_offset += (strlen(timestamp_string) + 1);

            /* Protocol name */
            strcpy((char*)&frame_buffer[stub_offset], protocol_name);
            stub_offset += (strlen(protocol_name) + 1);

            /* Direction */
            frame_buffer[stub_offset] = direction;
            stub_offset++;

            /* Encap */
            frame_buffer[stub_offset] = (guint8)encap;
            stub_offset++;

            /* Binary data length is half bytestring length + stub header */
            wth->phdr.len = data_chars/2 + stub_offset;
            wth->phdr.caplen = data_chars/2 + stub_offset;


            /*************************/
            /* Copy data into buffer */
            for (n=0; n <= data_chars; n+=2)
            {
                frame_buffer[stub_offset + n/2] =
                    (hex_from_char(linebuff[dollar_offset+n]) << 4) |
                     hex_from_char(linebuff[dollar_offset+n+1]);
            }
            
            /* Store the packet prefix in the hash table */
            line_prefix_info = g_malloc(sizeof(line_prefix_info_t));

            line_prefix_info->before_time = g_malloc(before_time_offset+1);
            strncpy(line_prefix_info->before_time, linebuff, before_time_offset);
            line_prefix_info->before_time[before_time_offset] = '\0';

            line_prefix_info->after_time = g_malloc(dollar_offset - after_time_offset);
            strncpy(line_prefix_info->after_time, linebuff+after_time_offset,
                   dollar_offset - after_time_offset);
            line_prefix_info->after_time[dollar_offset - after_time_offset-1] = '\0';

            /* Add packet entry into table */
            g_hash_table_insert(file_externals->line_header_prefixes_table,
                                (void*)this_offset, line_prefix_info);


            /* Set pseudo-header if necessary */
            set_pseudo_header_info(wth, encap, this_offset, &wth->pseudo_header,
                                   data_chars/2, direction);

            /* OK, we have packet details to return */
            *err = errno;
            return TRUE;
        }
    }

    /* No packet details to return... */
    *err = errno;
    return FALSE;
}


/**************************************************/
/* Read & seek function.                          */
/**************************************************/
static gboolean
catapult_dct2000_seek_read(wtap *wth, long seek_off,
                           union wtap_pseudo_header *pseudo_header, guchar *pd,
                           int length, int *err, gchar **err_info)
{
    long offset = wth->data_offset;
    long dollar_offset, before_time_offset, after_time_offset;
    packet_direction_t direction;
    int encap;
    int seconds, useconds, data_chars;

    /* Reset errno */
    *err = errno = 0;

    /* Seek to beginning of packet */
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
    {
        return FALSE;
    }

    /* Re-read whole line (this should succeed) */
    if (read_new_line(wth->random_fh, &offset, &length) == FALSE)
    {
        return FALSE;
    }

    /* Try to parse this line again (should succeed as re-reading...) */
    if (parse_line(length, &seconds, &useconds,
                   &before_time_offset, &after_time_offset,
                   &dollar_offset,
                   &data_chars, &direction, &encap, TRUE))
    {
        int n;
        int stub_offset = 0;
        char timestamp_string[32];
        sprintf(timestamp_string, "%d.%04d", seconds, useconds/100);

        /* Make sure all packets go to catapult dct2000 dissector */
        wth->phdr.pkt_encap = WTAP_ENCAP_CATAPULT_DCT2000;


        /*********************/
        /* Write stub header */

        strcpy((char*)pd, context_name);
        stub_offset += (strlen(context_name) + 1);

        /* Context port number */
        pd[stub_offset] = context_port;
        stub_offset++;

        /* Timestamp within file */
        strcpy((char*)&pd[stub_offset], timestamp_string);
        stub_offset += (strlen(timestamp_string) + 1);

        /* Protocol name */
        strcpy((char*)&pd[stub_offset], protocol_name);
        stub_offset += (strlen(protocol_name) + 1);

        /* Direction */
        pd[stub_offset] = direction;
        stub_offset++;

        /* Encap */
        pd[stub_offset] = encap;
        stub_offset++;

        /********************************/
        /* Copy packet data into buffer */
        for (n=0; n <= data_chars; n+=2)
        {
            pd[stub_offset + n/2] = (hex_from_char(linebuff[dollar_offset+n]) << 4) |
                                     hex_from_char(linebuff[dollar_offset+n+1]);
        }

        /* Set packet pseudo-header if necessary */
        set_pseudo_header_info(wth, encap, seek_off, pseudo_header, data_chars/2, direction);

        *err = errno = 0;
        return TRUE;
    }

    /* If get here, must have failed */
    *err = errno;
    *err_info = g_strdup_printf("catapult dct2000: seek_read failed to read/parse "
                                "line at position %ld", seek_off);
    return FALSE;
}


/******************************************/
/* Free dct2000-specific capture info     */
/******************************************/
void catapult_dct2000_close(wtap *wth)
{
    /* Look up externals for this file */
    dct2000_file_externals_t *file_externals =
        (dct2000_file_externals_t*)g_hash_table_lookup(file_externals_table, wth);

    /* The entry *has* to be found */
    if (!file_externals)
    {
        return;
    }

    /* Free up its line prefix values */
    g_hash_table_foreach_remove(file_externals->line_header_prefixes_table,
                                free_line_prefix_info, NULL);
    /* Free up its line prefix table */
    g_hash_table_destroy(file_externals->line_header_prefixes_table);

    /* And remove the externals entry from the global table */
    g_hash_table_remove(file_externals_table, (void*)wth);

    /* And free up file_externals itself */
    g_free(file_externals);

    /* Also free this capture info */
    g_free(wth->capture.catapult_dct2000);
}




/***************************/
/* Dump functions          */
/***************************/

/*****************************************************/
/* The file that we are writing to has been opened.  */
/* Set other dump callbacks.                         */
/*****************************************************/
gboolean catapult_dct2000_dump_open(wtap_dumper *wdh, gboolean cant_seek _U_, int *err _U_)
{
    /* Fill in other dump callbacks */
	wdh->subtype_write = catapult_dct2000_dump;
	wdh->subtype_close = catapult_dct2000_dump_close;

    return TRUE;
}

/*********************************************************/
/* Respond to queries about which encap types we support */
/* writing to.                                           */
/*********************************************************/
int catapult_dct2000_dump_can_write_encap(int encap)
{
    switch (encap)
    {
        case WTAP_ENCAP_CATAPULT_DCT2000:
            /* We support this */
            return 0;
        default:
            return WTAP_ERR_UNSUPPORTED_ENCAP;
    }
}


/*****************************************/
/* Write a single packet out to the file */
/*****************************************/
gboolean catapult_dct2000_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
                               const union wtap_pseudo_header *pseudo_header,
                               const guchar *pd, int *err _U_)
{
    guint32 n;
    line_prefix_info_t *prefix = NULL;
    gchar time_string[16];

    /******************************************************/
    /* Look up the file_externals structure for this file */
    /* Find wtap external structure for this wtap */
    dct2000_file_externals_t *file_externals =
        (dct2000_file_externals_t*)g_hash_table_lookup(file_externals_table,
                                                       pseudo_header->dct2000.wth);

    if (wdh->dump.dct2000 == NULL)
    {
        /* Allocate the dct2000-specific dump structure */
        wdh->dump.dct2000 = g_malloc(sizeof(catapult_dct2000_t));

        /* Write out saved first line */
        fwrite(file_externals->firstline, 1, file_externals->firstline_length, wdh->fh);
        fwrite("\n", 1, 1, wdh->fh);

        /* Also write out saved second line with timestamp corresponding to the
           opening time of the log.
        */
        fwrite(file_externals->secondline, 1, file_externals->secondline_length, wdh->fh);
        fwrite("\n", 1, 1, wdh->fh);

        /* Allocate the dct2000-specific dump structure */
        wdh->dump.dct2000 = g_malloc(sizeof(catapult_dct2000_t));

        /* Copy time of beginning of file */
        wdh->dump.dct2000->start_time.secs =
            pseudo_header->dct2000.wth->capture.catapult_dct2000->start_secs;
        wdh->dump.dct2000->start_time.nsecs =
            (pseudo_header->dct2000.wth->capture.catapult_dct2000->start_usecs * 1000);

        /* Set flag do don't write header out again */
        wdh->dump.dct2000->first_packet_written = TRUE;
    }


    /******************************************************************/
    /* Write out this packet's prefix, including calculated timestamp */

    /* Look up line data prefix using stored offset */
    prefix = (line_prefix_info_t*)g_hash_table_lookup(file_externals->line_header_prefixes_table,
                                                      (void*)pseudo_header->dct2000.seek_off);

    /* Write out text before timestamp */
    fwrite(prefix->before_time, 1, strlen(prefix->before_time), wdh->fh);

    /* Calculate time of this packet to write, relative to start of dump */
    if (phdr->ts.nsecs >= wdh->dump.dct2000->start_time.nsecs)
    {
        g_snprintf(time_string, 16, "%ld.%04d",
                 phdr->ts.secs - wdh->dump.dct2000->start_time.secs,
                 (phdr->ts.nsecs - wdh->dump.dct2000->start_time.nsecs) / 100000);
    }
    else
    {
        g_snprintf(time_string, 16, "%ld.%04u",
                 phdr->ts.secs - wdh->dump.dct2000->start_time.secs-1,
                 ((1000000000 + (phdr->ts.nsecs / 100000)) - (wdh->dump.dct2000->start_time.nsecs / 100000)) % 10000);
    }

    /* Write out the calculated timestamp */
    fwrite(time_string, 1, strlen(time_string), wdh->fh);

    /* Write out text between timestamp and start of hex data */
    fwrite(prefix->after_time, 1, strlen(prefix->after_time), wdh->fh);


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
    for (; pd[n] != '\0'; n++);
    n++;

    /* Direction & encap */
    n += 2;


    /**************************************/
    /* Remainder is encapsulated protocol */
    fwrite("$", 1, 1, wdh->fh);

    /* Each binary byte is written out as 2 hex string chars */ 
    for (; n < phdr->len; n++)
    {
        gchar c[2];
        c[0] = char_from_hex((guchar)(pd[n] >> 4));
        c[1] = char_from_hex((guchar)(pd[n] & 0x0f));

        /* Write both hex chars of byte together */
        fwrite(c, 1, 2, wdh->fh);
    }

    /* End the line */
    fwrite("\n", 1, 1, wdh->fh);

    return TRUE;
}


/******************************************************/
/* Close a file we've been writing to.                */
/******************************************************/
static gboolean catapult_dct2000_dump_close(wtap_dumper *wdh _U_, int *err _U_)
{
    return TRUE;
}




/****************************/
/* Private helper functions */
/****************************/

/**********************************************************************/
/* Read a new line from the file, starting at offset.                 */
/* - writes data to static var linebuff                               */
/* - on return 'offset' will point to the next position to read from  */
/* - return TRUE if this read is successful                           */
/**********************************************************************/
gboolean read_new_line(FILE_T fh, long *offset, gint *length)
{
    char *result;

    /* Read in a line */
    result = file_gets(linebuff, MAX_LINE_LENGTH, fh);
    if (result == NULL)
    {
        /* No characters found */
        return FALSE;
    }

    /* Set length and offset.. */
    *length = strlen(linebuff);
    *offset = *offset + *length;

    /* ...but don't want to include newline in line length */
    if (linebuff[*length-1] == '\n')
    {
        linebuff[*length-1] = '\0';
        *length = *length - 1;
    }

    return TRUE;
}


/**********************************************************************/
/* Parse a line from buffer, by identifying:                          */
/* - context, port and direction of packet                            */
/* - timestamp                                                        */
/* - data position and length                                         */
/* Return TRUE if this packet looks valid and can be displayed        */
/**********************************************************************/
gboolean parse_line(gint length, gint *seconds, gint *useconds,
                    long *before_time_offset, long *after_time_offset,
                    long *data_offset, gint *data_chars,
                    packet_direction_t *direction,
                    int *encap,
                    gboolean seek_read)
{
    int  n = 0;
    int  port_digits = 0;
    char port_number_string[MAX_PORT_DIGITS+1];
    int  protocol_chars = 0;

    char seconds_buff[MAX_SECONDS_CHARS+1];
    int  seconds_chars;
    char subsecond_decimals_buff[MAX_SUBSECOND_DECIMALS+1];
    int  subsecond_decimals_chars;

    gboolean atm_header_present = FALSE;

    /* Read context name until find '.' */
    for (n=0; linebuff[n] != '.' && (n < MAX_CONTEXT_NAME); n++)
    {
        if (!isalnum(linebuff[n]) && (linebuff[n] != '_'))
        {
            return FALSE;
        }
        context_name[n] = linebuff[n];
    }

    /* '.' must follow context name */
    if (linebuff[n] != '.')
    {
        return FALSE;
    }
    context_name[n] = '\0';
    /* Skip it */
    n++;


    /* Now read port number */
    for (port_digits = 0;
         (linebuff[n] != '/') && (port_digits <= MAX_PORT_DIGITS);
         n++, port_digits++)
    {
        if (!isdigit(linebuff[n]))
        {
            return FALSE;
        }
        port_number_string[port_digits] = linebuff[n];
    }

    /* Slash char must follow port number */
    if (linebuff[n] != '/')
    {
        return FALSE;
    }
    port_number_string[port_digits] = '\0';
    context_port = atoi(port_number_string);
    /* Skip it */
    n++;


    /* Now for the protocol name */
    for (protocol_chars = 0;
         (linebuff[n] != '/') && (protocol_chars < MAX_PROTOCOL_NAME) &&
         (n < MAX_LINE_LENGTH);
         n++, protocol_chars++)
    {
        if (!isalnum(linebuff[n]) && linebuff[n] != '_')
        {
            return FALSE;
        }
        protocol_name[protocol_chars] = linebuff[n];
    }
    protocol_name[protocol_chars] = '\0';

    /* Slash char must follow protocol name */
    if (linebuff[n] != '/')
    {
        return FALSE;
    }


    /******************************************************************/
    /* Now check whether we know how to use a packet of this protocol */

    if ((strcmp(protocol_name, "ip") == 0)  || (strcmp(protocol_name, "sctp") == 0))
    {
        *encap = WTAP_ENCAP_RAW_IP;
    }
    else

    /* For ATM protocols, we need to read the separate atm headerparse */
    if ((strcmp(protocol_name, "fp") == 0) ||
        (strcmp(protocol_name, "fp_r4") == 0) ||
        (strcmp(protocol_name, "fp_r5") == 0) ||
        (strcmp(protocol_name, "fp_r6") == 0))
    {
        *encap = WTAP_ENCAP_ATM_PDUS_UNTRUNCATED;
        atm_header_present = TRUE;
    }

    else
    if (strcmp(protocol_name, "ppp") == 0)
    {
        *encap = WTAP_ENCAP_PPP;
    }
    else
    if (strcmp(protocol_name, "isdn_l3") == 0)
    {
        /* Despite the name, this does seem to correspond to L2... */
        *encap = WTAP_ENCAP_ISDN;
    }
    else
    if (strcmp(protocol_name, "ethernet") == 0)
    {
        *encap = WTAP_ENCAP_ETHERNET;
    }
    else
    if ((strcmp(protocol_name, "saalnni_sscop") == 0) ||
        (strcmp(protocol_name, "saaluni_sscop") == 0))
    {
        *encap = DCT2000_ENCAP_SSCOP;
    }
    else
    if (strcmp(protocol_name, "frelay_l2") == 0)
    {
        *encap = WTAP_ENCAP_FRELAY;
    }
    else
    if (strcmp(protocol_name, "ss7_mtp2") == 0)
    {
        *encap = DCT2000_ENCAP_MTP2;
    }
    else
    {
        /* Only reject protocol if reading for the first time and preference
           setting says board ports only.  This should not fail to read a
           non board-port protocol on re-reading because the preference setting
           has since changed...
        */
        if (catapult_dct2000_board_ports_only && !seek_read)
        {
            return FALSE;
        }
        else
        {
            /* Not a supported protocol/encap, but should show as raw data anyway */
            *encap = DCT2000_ENCAP_UNHANDLED;
        }
    }


    /* Find separate ATM header if necessary */
    if (atm_header_present)
    {
        int header_chars_seen = 0;

        /* Scan ahead to the next $ */
        for (; (linebuff[n] != '$') && (n < MAX_LINE_LENGTH); n++);
        /* Skip it */
        n++;

        /* Read consecutive hex chars into atm header buffer */
        for (;
             (isalnum(linebuff[n]) &&
              (n < MAX_LINE_LENGTH) &&
              (header_chars_seen < AAL_HEADER_CHARS));
             n++, header_chars_seen++)
        {
            aal_header_chars[header_chars_seen] = linebuff[n];
        }

        if (header_chars_seen != AAL_HEADER_CHARS)
        {
            return FALSE;
        }
    }


    /* Scan ahead to the next space */
    for (; (linebuff[n] != ' ') && (n < MAX_LINE_LENGTH); n++);
    /* Skip it */
    n++;

    /* Next character gives direction of message (must be 's' or 'r') */
    if (linebuff[n] == 's')
    {
        *direction = sent;
    }
    else
    if (linebuff[n] == 'r')
    {
        *direction = received;
    }
    else
    {
        return FALSE;
    }


    /*********************************************************************/
    /* Find and read the timestamp                                       */

    /* Now scan to the next digit, which should be the start of the timestamp */
    for (; !isdigit(linebuff[n]) && (n < MAX_LINE_LENGTH); n++);

    *before_time_offset = n;

    /* Seconds */
    for (seconds_chars = 0;
         (linebuff[n] != '.') &&
         (seconds_chars <= MAX_SECONDS_CHARS) &&
         (n < MAX_LINE_LENGTH);
         n++, seconds_chars++)
    {
        if (!isdigit(linebuff[n]))
        {
            return FALSE;
        }
        seconds_buff[seconds_chars] = linebuff[n];
    }
    /* Convert found value into number */
    seconds_buff[seconds_chars] = '\0';
    *seconds = atoi(seconds_buff);

    /* The decimal point must follow the last of the seconds digits */
    if (linebuff[n] != '.')
    {
        return FALSE;
    }
    /* Skip it */
    n++;

    /* Subsecond decimal digits (expect 4-digit accuracy) */
    for (subsecond_decimals_chars = 0;
         (linebuff[n] != ' ') &&
         (subsecond_decimals_chars <= MAX_SUBSECOND_DECIMALS) &&
         (n < MAX_LINE_LENGTH);
         n++, subsecond_decimals_chars++)
    {
        if (!isdigit(linebuff[n]))
        {
            return FALSE;
        }
        subsecond_decimals_buff[subsecond_decimals_chars] = linebuff[n];
    }
    /* Convert found value into microseconds */
    subsecond_decimals_buff[subsecond_decimals_chars] = '\0';
    *useconds = atoi(subsecond_decimals_buff) * 100;

    /* Space character must follow end of timestamp */
    if (linebuff[n] != ' ')
    {
        return FALSE;
    }

    *after_time_offset = n;

    /* Now skip ahead to find start of data (marked by '$') */
    for (; (linebuff[n] != '$') && (n < MAX_LINE_LENGTH); n++);
    /* Skip it */
    n++;

    /* Set offset to data start within line */
    *data_offset = n;

    /* Set number of chars that comprise the hex string protocol data */
    *data_chars = length - n;

    /* Need to skip first byte (2 hex string chars) from ISDN messages.
       TODO: find out what this byte means...
    */
    if (*encap == WTAP_ENCAP_ISDN)
    {
        *data_offset += 2;
        *data_chars -= 2;
    }

    return TRUE;
}


/**************************************************************/
/* Set pseudo-header info depending upon packet encapsulation */
/**************************************************************/
void set_pseudo_header_info(wtap *wth,
                            int pkt_encap,
                            long file_offset,
                            union wtap_pseudo_header *pseudo_header,
                            gint length,
                            packet_direction_t direction)
{
    pseudo_header->dct2000.seek_off = file_offset;
    pseudo_header->dct2000.wth = wth;

    switch (pkt_encap)
    {
        case WTAP_ENCAP_ATM_PDUS_UNTRUNCATED:
            set_aal_info(pseudo_header, length, direction);
            break;
        case WTAP_ENCAP_ISDN:
            set_isdn_info(pseudo_header, direction);
            break;
        case WTAP_ENCAP_PPP:
            set_ppp_info(pseudo_header, direction);
            break;

        default:
            /* Other supported types don't need to set anything here... */
            break;
    }
}


/*********************************************/
/* Fill in atm pseudo-header with known info */
/*********************************************/
void set_aal_info(union wtap_pseudo_header *pseudo_header, gint length,
                  packet_direction_t direction)
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

    pseudo_header->dct2000.inner_pseudo_header.atm.type = TRAF_UNKNOWN;
    pseudo_header->dct2000.inner_pseudo_header.atm.subtype = TRAF_ST_UNKNOWN;

    /* vpi is 8 bits (2nd & 3rd nibble) */
    pseudo_header->dct2000.inner_pseudo_header.atm.vpi =
        ((hex_from_char(aal_header_chars[1]) << 4) |
          hex_from_char(aal_header_chars[2]));

    /* vci is next 16 bits */
    pseudo_header->dct2000.inner_pseudo_header.atm.vci =
        ((hex_from_char(aal_header_chars[3]) << 12) |
         (hex_from_char(aal_header_chars[4]) << 8) |
         (hex_from_char(aal_header_chars[5]) << 4) |
         hex_from_char(aal_header_chars[6]));

    /* 0 means we don't know how many cells the frame comprises. */
    pseudo_header->dct2000.inner_pseudo_header.atm.cells = 0;

    pseudo_header->dct2000.inner_pseudo_header.atm.aal5t_u2u = 0;
    pseudo_header->dct2000.inner_pseudo_header.atm.aal5t_len = length;
    pseudo_header->dct2000.inner_pseudo_header.atm.aal5t_chksum = 0;
}


/**********************************************/
/* Fill in isdn pseudo-header with known info */
/**********************************************/
void set_isdn_info(union wtap_pseudo_header *pseudo_header,
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
static void set_ppp_info(union wtap_pseudo_header *pseudo_header,
                         packet_direction_t direction)
{
    /* Set direction. */
    pseudo_header->dct2000.inner_pseudo_header.p2p.sent = (direction == sent);
}


/********************************************************/
/* Return hex nibble equivalent of hex string character */
/********************************************************/
guchar hex_from_char(gchar c)
{
    if ((c >= '0') && (c <= '9'))
    {
        return c - '0';
    }

    if ((c >= 'a') && (c <= 'f'))
    {
        return 0x0a + (c - 'a');
    }

    /* Not a valid hex string character */
    return 0xff;
}


/********************************************************/
/* Return character corresponding to hex nibble value   */
/********************************************************/
gchar char_from_hex(guchar hex)
{
    static char hex_lookup[16] =
    { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    if (hex > 15)
    {
        return '?';
    }

    return hex_lookup[hex];
}


/********************************************/
/* Equality test for line-prefix hash table */
/********************************************/
gint prefix_equal(gconstpointer v, gconstpointer v2)
{
    return (v == v2);
}


/********************************************/
/* Hash function for line-prefix hash table */
/********************************************/
guint prefix_hash_func(gconstpointer v)
{
    /* Just use pointer itself (is actually byte offset of line in file) */ 
    return (guint)v;
}


/************************************************************************/
/* Parse year, month, day, hour, minute, seconds out of formatted line. */
/* Set secs and usecs as output                                         */
/* Return FALSE if no valid time can be read                            */
/************************************************************************/
gboolean get_file_time_stamp(time_t *secs, guint32 *usecs)
{
    int n;
    struct tm tm;
    #define MAX_MONTH_LETTERS 9
    char month[MAX_MONTH_LETTERS+1];

    int day, year, hour, minute, second;
    int scan_found;

    /* If line longer than expected, file is probably not correctly formatted */
    if (strlen(linebuff) > MAX_TIMESTAMP_LINE_LENGTH)
    {
        return FALSE;
    }

    /**************************************************************/
    /* First is month. Read until get a space following the month */
    for (n=0; (linebuff[n] != ' ') && (n < MAX_MONTH_LETTERS); n++)
    {
        month[n] = linebuff[n];
    }
    month[n] = '\0';

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
    else
    {
        /* Give up if not found a properly-formatted date */
        return FALSE;
    }
    /* Skip space char */
    n++;

    /********************************************************/
    /* Scan for remaining numerical fields                  */
    scan_found = sscanf(linebuff+n, "%d, %d     %d:%d:%d.%u",
                        &day, &year, &hour, &minute, &second, usecs);
    if (scan_found != 6)
    {
        /* Give up if not all found */
        return FALSE;
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

    return TRUE;
}

/* Free the data allocated inside a line_prefix_info_t */
gboolean free_line_prefix_info(gpointer key _U_, gpointer value,
                               gpointer user_data _U_)
{
    line_prefix_info_t *info = (line_prefix_info_t*)value;

    /* Free the strings inside */
    g_free(info->before_time);
    g_free(info->after_time);

    /* And the structure itself */
    g_free(info);

    /* Item will always be removed from table */
    return TRUE;
}

