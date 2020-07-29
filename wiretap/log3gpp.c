/* log3gpp.c
 * Routines encapsulating/dumping 3gpp protocol logs.
 * The purpose of this format is to be able to log the 3GPP protocol stack on a mobile phone.
 * Copyright 2008, Vincent Helfre
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "wtap-int.h"
#include "file_wrappers.h"

#include "log3gpp.h"

#define MAX_FIRST_LINE_LENGTH      200
#define MAX_TIMESTAMP_LINE_LENGTH  100
#define MAX_LINE_LENGTH            65536
#define MAX_TIMESTAMP_LEN          32
#define MAX_SECONDS_CHARS          16
#define MAX_SUBSECOND_DECIMALS     4
#define MAX_PROTOCOL_NAME          64
#define MAX_PROTOCOL_PAR_STRING    64

/* 's' or 'r' of a packet as read from .out file */
typedef enum packet_direction_t
{
    uplink,
    downlink
} packet_direction_t;

typedef struct {
    time_t	start_secs;
    guint32	start_usecs;
} log3gpp_t;

gint first_packet_offset;
gchar firstline[MAX_FIRST_LINE_LENGTH];
gchar secondline[MAX_TIMESTAMP_LINE_LENGTH];
gint secondline_length = 0;

/***********************************************************/
/* Transient data used for parsing                         */

/* 'Magic number' at start of 3gpp log files. */
static const gchar log3gpp_magic[] = "3GPP protocols transcript";

/* Protocol name of the packet that the packet was captured at */
static gchar protocol_name[MAX_PROTOCOL_NAME+1];

/* Optional string parameter giving info required for the protocol dissector */
static gchar protocol_parameters[MAX_PROTOCOL_PAR_STRING+1];
/************************************************************/
/* Functions called from wiretap core                       */
static gboolean log3gpp_read( wtap* wth, wtap_rec* rec, Buffer* buf,
                                    int* err, gchar** err_info, gint64* data_offset);
static gboolean log3gpp_seek_read(struct wtap *wth, gint64 seek_off,
                                  wtap_rec *rec,
                                  Buffer *buf,
                                  int *err, gchar **err_info);

/************************************************************/
/* Private helper functions                                 */
static gboolean read_new_line(FILE_T fh, gint* length,
    gchar* buf, size_t bufsize, int* err,
    gchar** err_info);

static gboolean parse_line(char* linebuff, gint line_length, gint *seconds, gint *useconds,
                           long *data_offset,
                           gint *data_chars,
                           packet_direction_t *direction,
                           gboolean *is_text_data);
static int write_stub_header(guchar *frame_buffer, char *timestamp_string,
                             packet_direction_t direction);
static guchar hex_from_char(gchar c);
/*not used static gchar char_from_hex(guchar hex);*/

static gboolean get_file_time_stamp(gchar* linebuff, time_t *secs, guint32 *usecs);


/***************************************************************************/
/* Free log3gpp-specific capture info from file that was open for reading  */
/***************************************************************************/
void log3gpp_close(wtap* wth)
{
    log3gpp_t* log3gpp = (log3gpp_t*)wth->priv;
    /* Also free this capture info */
    g_free(log3gpp);
    wth->priv = NULL;
}

#if 0
static gboolean
log3gpp_dump(wtap_dumper* wdh _U_, const wtap_rec* rec _U_,
    const guchar* buf _U_, int* err _U_, gchar** err_info _U_)
{
    return TRUE;
}
#endif


/******************************************************/
/* Close a file we've been writing to.                */
/******************************************************/
#if 0
static gboolean
log3gpp_dump_finish(wtap_dumper* wdh _U_, int* err _U_)
{
    return TRUE;
}
#endif

/********************************************/
/* Open file (for reading)                 */
/********************************************/
wtap_open_return_val
log3gpp_open(wtap *wth, int *err, gchar **err_info _U_)
{
    time_t  timestamp;
    guint32 usecs;
    log3gpp_t *log3gpp;
    wtap_open_return_val retval;
    /* Buffer to hold a single text line read from the file */
    static gchar linebuff[MAX_LINE_LENGTH];
    gint firstline_length = 0;

    /* Clear errno before reading from the file */
    errno = 0;

    /********************************************************************/
    /* First line needs to contain at least as many characters as magic */

    /*g_warning("Open file"); */

    if (!read_new_line(wth->fh, &firstline_length, linebuff,
        sizeof linebuff, err, err_info)) {
        if (*err != 0 && *err != WTAP_ERR_SHORT_READ) {
            return WTAP_OPEN_ERROR;
        }
        else {
            return WTAP_OPEN_NOT_MINE;
        }
    }

    if (((size_t)firstline_length < strlen(log3gpp_magic)) ||
        firstline_length >= MAX_FIRST_LINE_LENGTH)
    {
        retval = WTAP_OPEN_NOT_MINE;
        return retval;
    }

    /* This file is not for us if it doesn't match our signature */
    if (memcmp(log3gpp_magic, linebuff, strlen(log3gpp_magic)) != 0)
    {
        retval = WTAP_OPEN_NOT_MINE;
        return retval;
    }

    /***********************************************************/
    /* Second line contains file timestamp                     */
    if (!read_new_line(wth->fh, &secondline_length,
        linebuff, sizeof linebuff, err, err_info)) {
        if (*err != 0 && *err != WTAP_ERR_SHORT_READ) {
            return WTAP_OPEN_ERROR;
        }
        else {
            return WTAP_OPEN_NOT_MINE;
        }
    }

    first_packet_offset = firstline_length +  secondline_length;

    if ((secondline_length >= MAX_TIMESTAMP_LINE_LENGTH) ||
        (!get_file_time_stamp(linebuff, &timestamp, &usecs)))
    {
        /* Give up if file time line wasn't valid */
        retval = WTAP_OPEN_NOT_MINE;
        return retval;
    }

    /* Allocate struct and fill in timestamp (netmon re used)*/
    log3gpp = (log3gpp_t *)g_malloc(sizeof(log3gpp_t));
    log3gpp->start_secs = timestamp;
    log3gpp->start_usecs = usecs;
    wth->priv = (void *)log3gpp;

    /************************************************************/
    /* File is for us. Fill in details so packets can be read   */

    /* Set our file type */
    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_LOG_3GPP;

    /* Use our own encapsulation to send all packets to our stub dissector */
    wth->file_encap = WTAP_ENCAP_LOG_3GPP;

    /* Callbacks for reading operations */
    wth->subtype_read = log3gpp_read;
    wth->subtype_seek_read = log3gpp_seek_read;
    wth->subtype_close = log3gpp_close;

    /* Choose microseconds (have 4 decimal places...) */
    wth->file_tsprec = WTAP_TSPREC_USEC;

    *err = errno;

    /*
     * Add an IDB; we don't know how many interfaces were
     * involved, so we just say one interface, about which
     * we only know the link-layer type, snapshot length,
     * and time stamp resolution.
     */
    wtap_add_generated_idb(wth);

    retval = WTAP_OPEN_MINE;
    return retval;
}


/**************************************************/
/* Read packet function.                          */
/* Look for and read the next usable packet       */
/* - return TRUE and details if found             */
/**************************************************/
gboolean log3gpp_read(wtap* wth, wtap_rec* rec, Buffer* buf,
    int* err, gchar** err_info, gint64* data_offset)
{
    gint64 offset = file_tell(wth->fh);
    static gchar linebuff[MAX_LINE_LENGTH + 1];
    long dollar_offset;
    packet_direction_t direction;
    gboolean is_text_data;
    log3gpp_t *log3gpp = (log3gpp_t *)wth->priv;

    /* Search for a line containing a usable packet */
    while (1)
    {
        int line_length, seconds, useconds, data_chars;
        gint64 this_offset = offset;

        /* Are looking for first packet after 2nd line */
        if (file_tell(wth->fh) == 0)
        {
            this_offset += (gint64)first_packet_offset +1+1;
        }

        /* Clear errno before reading from the file */
        errno = 0;

        /* Read a new line from file into linebuff */
        if (!read_new_line(wth->fh, &line_length, linebuff,
            sizeof linebuff, err, err_info)) {
            if (*err != 0) {
                return FALSE;  /* error */
            }
            /* No more lines can be read, so quit. */
            break;
        }

        /* Try to parse the line as a frame record */
        if (parse_line(linebuff, line_length, &seconds, &useconds,
                       &dollar_offset,
                       &data_chars,
                       &direction,
                       &is_text_data))
        {
            guchar *frame_buffer;
            int n;
            int stub_offset = 0;
            char timestamp_string[MAX_TIMESTAMP_LEN+1];
            /*not used gint64 *pkey = NULL;*/

            g_snprintf(timestamp_string, 32, "%d.%04d", seconds, useconds/100);

            /* All packets go to 3GPP protocol stub dissector */
            rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_LOG_3GPP;
            rec->rec_type = REC_TYPE_PACKET;
            rec->presence_flags = WTAP_HAS_TS;

            /* Set data_offset to the beginning of the line we're returning.
               This will be the seek_off parameter when this frame is re-read.
            */
            *data_offset = this_offset;

            /* Fill in timestamp (capture base + packet offset) */
            rec->ts.secs = log3gpp->start_secs + seconds;
            if ((log3gpp->start_usecs + useconds) >= 1000000)
            {
                rec->ts.secs++;
            }
            rec->ts.nsecs =
                ((log3gpp->start_usecs + useconds) % 1000000) *1000;

            if (!is_text_data)
            {
              /* Get buffer pointer ready */
              ws_buffer_assure_space(buf,
                                  strlen(timestamp_string)+1 + /* timestamp */
                                  strlen(protocol_name)+1 +    /* Protocol name */
                                  1 +                          /* direction */
                                  (size_t)(data_chars/2));

              frame_buffer = ws_buffer_start_ptr(buf);
              /*********************/
              /* Write stub header */
              stub_offset = write_stub_header(frame_buffer, timestamp_string,
                                              direction);

              /* Binary data length is half bytestring length + stub header */
              rec->rec_header.packet_header.len = data_chars/2 + stub_offset;
              rec->rec_header.packet_header.caplen = data_chars/2 + stub_offset;
              /********************************/
              /* Copy packet data into buffer */
              for (n=0; n <= data_chars; n+=2)
              {
                frame_buffer[stub_offset + n/2] = (hex_from_char(linebuff[dollar_offset+n]) << 4) |
                                                   hex_from_char(linebuff[dollar_offset+n+1]);
              }
              *err = errno = 0;
              return TRUE;
            }
            else
            {
              /* Get buffer pointer ready */
              ws_buffer_assure_space(buf,
                                  strlen(timestamp_string)+1 + /* timestamp */
                                  strlen(protocol_name)+1 +    /* Protocol name */
                                  1 +                          /* direction */
                                  data_chars);
              frame_buffer = ws_buffer_start_ptr(buf);

              /*********************/
              /* Write stub header */
              stub_offset = write_stub_header(frame_buffer, timestamp_string,
                                              direction);

              /* Binary data length is bytestring length + stub header */
              rec->rec_header.packet_header.len = data_chars + stub_offset;
              rec->rec_header.packet_header.caplen = data_chars + stub_offset;

              /* do not convert the ascii char */
              memcpy(&frame_buffer[stub_offset],&linebuff[dollar_offset],data_chars);
              frame_buffer[stub_offset+data_chars-1]= '\0';
              *err = errno = 0;
              return TRUE;
            }
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
log3gpp_seek_read(wtap *wth, gint64 seek_off,
                    wtap_rec *rec _U_ , Buffer *buf,
                    int *err, gchar **err_info)
{
    long dollar_offset;
    static gchar linebuff[MAX_LINE_LENGTH + 1];
    packet_direction_t direction;
    int seconds, useconds, data_chars;
    gboolean is_text_data;
    log3gpp_t* log3gpp = (log3gpp_t*)wth->priv;
    int length = 0;
    guchar *frame_buffer;

    /* Reset errno */
    *err = errno = 0;

    /* Seek to beginning of packet */
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
    {
        return FALSE;
    }

    /* Re-read whole line (this really should succeed) */
    if (!read_new_line(wth->random_fh, &length, linebuff,
        sizeof linebuff, err, err_info)) {
        return FALSE;
    }

    /* Try to parse this line again (should succeed as re-reading...) */
    if (parse_line(linebuff, length, &seconds, &useconds,
                   &dollar_offset,
                   &data_chars,
                   &direction,
                   &is_text_data))
    {
        int n;
        int stub_offset = 0;
        char timestamp_string[32];
        g_snprintf(timestamp_string, 32, "%d.%04d", seconds, useconds/100);

        /* Make sure all packets go to log3gpp dissector */
        rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_LOG_3GPP;
        rec->rec_type = REC_TYPE_PACKET;
        rec->presence_flags = WTAP_HAS_TS;

        /* Fill in timestamp (capture base + packet offset) */
        rec->ts.secs = log3gpp->start_secs + seconds;
        if ((log3gpp->start_usecs + useconds) >= 1000000)
        {
            rec->ts.secs++;
        }
        rec->ts.nsecs =
            ((log3gpp->start_usecs + useconds) % 1000000) * 1000;

        /*********************/
        /* Write stub header */
        ws_buffer_assure_space(buf,
                               strlen(timestamp_string)+1 + /* timestamp */
                               strlen(protocol_name)+1 +    /* Protocol name */
                               1 +                          /* direction */
                               data_chars);
        frame_buffer = ws_buffer_start_ptr(buf);
        stub_offset = write_stub_header(frame_buffer, timestamp_string,
                                        direction);

        if (!is_text_data)
        {
          /********************************/
          /* Copy packet data into buffer */
          for (n=0; n <= data_chars; n+=2)
          {
            frame_buffer[stub_offset + n/2] = (hex_from_char(linebuff[dollar_offset+n]) << 4) |
                                               hex_from_char(linebuff[dollar_offset+n+1]);
          }
          *err = errno = 0;
          return TRUE;
        }
        else
        {
          /* do not convert the ascii char */
          memcpy(&frame_buffer[stub_offset],&linebuff[dollar_offset],data_chars);
          frame_buffer[stub_offset+data_chars-1] = '\0';
          *err = errno = 0;
          return TRUE;
        }
    }

    /* If get here, must have failed */
    *err = errno;
    *err_info = g_strdup_printf("prot 3gpp: seek_read failed to read/parse "
                                "line at position %" G_GINT64_MODIFIER "d",
                                seek_off);
    return FALSE;
}


/***************************/
/* Dump functions          */
/***************************/

/*****************************************************/
/* The file that we are writing to has been opened.  */
/* Set other dump callbacks.                         */
/*****************************************************/
#if 0
gboolean log3gpp_dump_open(wtap_dumper *wdh, gboolean cant_seek _U_, int *err _U_)
{
    /* Fill in other dump callbacks */
    wdh->subtype_write = log3gpp_dump;
    wdh->subtype_finish = log3gpp_dump_finish;

    return TRUE;
}
#endif

/*****************************************/
/* Write a single packet out to the file */
/*****************************************/
/*
static gboolean do_fwrite(const void *data, size_t size, size_t count, FILE *stream, int *err_p)
{
    size_t nwritten;

    nwritten = fwrite(data, size, count, stream);
    if (nwritten != count) {
        if (nwritten == 0 && ferror(stream))
        {
            *err_p = errno;
        }
        else
        {
            *err_p = WTAP_ERR_SHORT_WRITE;
        }

        return FALSE;
    }
    return TRUE;
}*/



/****************************/
/* Private helper functions */
/****************************/

/**********************************************************************/
/* Read a new line from the file, starting at offset.                 */
/* - writes data to static var linebuff                               */
/* - on return 'offset' will point to the next position to read from  */
/* - return TRUE if this read is successful                           */
/**********************************************************************/
static gboolean
read_new_line(FILE_T fh, gint* length,
    gchar* linebuff, size_t linebuffsize, int* err, gchar** err_info)
{
    /* Read in a line */
    gint64 pos_before = file_tell(fh);

    if (file_gets(linebuff, (int)linebuffsize - 1, fh) == NULL) {
        /* No characters found, or error */
        *err = file_error(fh, err_info);
        return FALSE;
    }

    /* Set length (avoiding strlen()) and offset.. */
    *length = (gint)(file_tell(fh) - pos_before);

    /* ...but don't want to include newline in line length */
    if (*length > 0 && linebuff[*length - 1] == '\n') {
        linebuff[*length - 1] = '\0';
        *length = *length - 1;
    }
    /* Nor do we want '\r' (as will be written when log is created on windows) */
    if (*length > 0 && linebuff[*length - 1] == '\r') {
        linebuff[*length - 1] = '\0';
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
gboolean parse_line(gchar* linebuff, gint line_length, gint *seconds, gint *useconds,
                    long *data_offset, gint *data_chars,
                    packet_direction_t *direction,
                    gboolean *is_text_data)
{
    int  n = 0;
    /*not used int  variant_digits = 0;*/
    /*not used int  variant = 1;*/
    int  protocol_chars = 0;
    int  prot_option_chars = 0;
    char seconds_buff[MAX_SECONDS_CHARS+1];
    int  seconds_chars;
    char subsecond_decimals_buff[MAX_SUBSECOND_DECIMALS+1];
    int  subsecond_decimals_chars;

    /*********************************************************************/
    /* Find and read the timestamp                                       */
    /*********************************************************************/
    /* Now scan to the next digit, which should be the start of the timestamp */
    for (; !g_ascii_isdigit((guchar)linebuff[n]) && (n < line_length); n++);
    if (n >= line_length)
    {
        return FALSE;
    }

    /* Seconds */
    for (seconds_chars = 0;
         (linebuff[n] != '.') &&
         (seconds_chars <= MAX_SECONDS_CHARS) &&
         (n < line_length);
         n++, seconds_chars++)
    {
        if (!g_ascii_isdigit((guchar)linebuff[n]))
        {
            /* Found a non-digit before decimal point. Fail */
            return FALSE;
        }
        seconds_buff[seconds_chars] = linebuff[n];
    }
    if (seconds_chars > MAX_SECONDS_CHARS || n >= line_length)
    {
        /* Didn't fit in buffer.  Fail rather than use truncated */
        return FALSE;
    }

    /* Convert found value into number */
    seconds_buff[seconds_chars] = '\0';

    /* Already know they are digits, so avoid expense of ws_strtoi32() */
    int multiplier = 1;
    *seconds = 0;
    for (int d = seconds_chars - 1; d >= 0; d--) {
        *seconds += ((seconds_buff[d] - '0') * multiplier);
        multiplier *= 10;
    }

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
         (n < line_length);
         n++, subsecond_decimals_chars++)
    {
        if (!g_ascii_isdigit((guchar)linebuff[n]))
        {
            return FALSE;
        }
        subsecond_decimals_buff[subsecond_decimals_chars] = linebuff[n];
    }
    if (subsecond_decimals_chars > MAX_SUBSECOND_DECIMALS || n >= line_length)
    {
        /* More numbers than expected - give up */
        return FALSE;
    }
    /* Convert found value into microseconds */
    subsecond_decimals_buff[subsecond_decimals_chars] = '\0';
    /* Already know they are digits, so avoid expense of ws_strtoi32() */
    *useconds = ((subsecond_decimals_buff[0] - '0') * 100000) +
        ((subsecond_decimals_buff[1] - '0') * 10000) +
        ((subsecond_decimals_buff[2] - '0') * 1000) +
        ((subsecond_decimals_buff[3] - '0') * 100);

    /* Space character must follow end of timestamp */
    if (linebuff[n] != ' ')
    {
        return FALSE;
    }
    n++;

    /*********************************************************************/
    /* Find and read protocol name                                       */
    /*********************************************************************/
    /* Read context name until find ' ' */
    for (protocol_chars = 0;
         (linebuff[n] != ' ') && (protocol_chars < MAX_PROTOCOL_NAME) && (n < line_length);
         n++, protocol_chars++)
    {
        if (!g_ascii_isalnum((guchar)linebuff[n]) && linebuff[n] != '_' && linebuff[n] != '.' && linebuff[n] != '-')
        {
            return FALSE;
        }
        protocol_name[protocol_chars] = linebuff[n];
    }
    if (protocol_chars == MAX_PROTOCOL_NAME || n >= line_length)
    {
        /* If doesn't fit, fail rather than truncate */
        return FALSE;
    }
    protocol_name[protocol_chars] = '\0';

    /* Space char must follow protocol name */
    if (linebuff[n] != ' ')
    {
        return FALSE;
    }
    /* Skip it */
    n++;

    /* Scan ahead to the next space */
    for (; (!g_ascii_isalnum((guchar)linebuff[n])) && (n < line_length); n++);
    if (n >= line_length)
    {
        return FALSE;
    }


    if (strcmp(protocol_name,"TXT") == 0)
    {
      *direction = uplink;
      *data_offset = n;
      *data_chars = line_length - n;
      *is_text_data = TRUE;
    }
    else
    {
      /* Next character gives direction of message (must be 'u' or 'd') */
      if (linebuff[n] == 'u')
      {
        *direction = uplink;
      }
      else if (linebuff[n] == 'd')
      {
        *direction = downlink;
      }
      else
      {
        return FALSE;
      }
      n++;

      /* Now skip ahead to find start of data (marked by '$') */
      for (; (n <= line_length) && (linebuff[n] != '$') && (prot_option_chars <= MAX_PROTOCOL_PAR_STRING);
           n++,prot_option_chars++)
      {
        protocol_parameters[prot_option_chars] = linebuff[n];
      }
      protocol_parameters[prot_option_chars] = '\0';
      if (prot_option_chars == MAX_PROTOCOL_PAR_STRING || n >= line_length)
      {
        /* If doesn't fit, fail rather than truncate */
        return FALSE;
      }

      /* Skip it */
      n++;

    /* Set offset to data start within line */
    *data_offset = n;

    /* Set number of chars that comprise the hex string protocol data */
    *data_chars = line_length - n;

    *is_text_data = FALSE;
    }
    return TRUE;
}

/*****************************************************************/
/* Write the stub info to the data buffer while reading a packet */
/*****************************************************************/
int write_stub_header(guchar *frame_buffer, char *timestamp_string,
                      packet_direction_t direction)
{
    int stub_offset = 0;

    /* Timestamp within file */
    g_strlcpy((char*)&frame_buffer[stub_offset], timestamp_string, MAX_TIMESTAMP_LEN+1);
    stub_offset += (int)(strlen(timestamp_string) + 1);

    /* Protocol name */
    g_strlcpy((char*)&frame_buffer[stub_offset], protocol_name, MAX_PROTOCOL_NAME+1);
    stub_offset += (int)(strlen(protocol_name) + 1);

    /* Direction */
    frame_buffer[stub_offset] = direction;
    stub_offset++;

    /* Option string (might be string of length 0) */
    g_strlcpy((char*)&frame_buffer[stub_offset], protocol_parameters,MAX_PROTOCOL_PAR_STRING+1);
    stub_offset += (int)(strlen(protocol_parameters) + 1);
    return stub_offset;
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

    if ((c >= 'A') && (c <= 'F'))
    {
        return 0x0a + (c - 'A');
    }
    /* Not a valid hex string character */
    return 0xff;
}


/********************************************************/
/* Return character corresponding to hex nibble value   */
/********************************************************/
/*gchar char_from_hex(guchar hex)
{
    static char hex_lookup[16] =
    { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    if (hex > 15)
    {
        return '?';
    }

    return hex_lookup[hex];
}*/

/************************************************************************/
/* Parse year, month, day, hour, minute, seconds out of formatted line. */
/* Set secs and usecs as output                                         */
/* Return FALSE if no valid time can be read                            */
/************************************************************************/
gboolean get_file_time_stamp(gchar* linebuff, time_t *secs, guint32 *usecs)
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
    for (n=0; (n < MAX_MONTH_LETTERS) && (linebuff[n] != ' '); n++)
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

#if 0
/* Register with wtap */
void wtap_register_phonelog(void) {
        static struct file_type_subtype_info fi =
        { "3GPP Log", "3gpp_log", "*.log", NULL, TRUE, FALSE, 0, NULL, NULL, NULL };

        static struct open_info phonelog_oi =
        { "3gpp_log", OPEN_INFO_MAGIC, log3gpp_open, "*.log", NULL, NULL };

        wtap_register_open_info(&phonelog_oi, TRUE);

        encap_3gpp_log = wtap_register_encap_type("3GPP Log","3gpp_log");
        wf_3gpp_log =  wtap_register_file_type_subtypes(&fi, WTAP_FILE_TYPE_SUBTYPE_UNKNOWN);
}
#endif
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
