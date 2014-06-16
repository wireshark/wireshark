/* iseries.c
 *
 * Wiretap Library
 * Copyright (c) 2011 by Martin Warnes <Martin_Warnes@uk.ibm.com>
 *
 * Based on toshiba.c and vms.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * This module will read the contents of the iSeries (OS/400) Communication trace
 * Both ASCII & Unicode formatted traces are supported.
 *
 * iSeries Comms traces consist of a header page and a subsequent number of packet records
 *
 * The header page contains details on the options set during running of the trace,
 * currently the following options are a requirement for this module:
 *
 * 1. Object protocol = ETHERNET (Default)
 * 2. ASCII or UNICODE file formats.
 *
 * The above can be acheived by passing option ASCII(*YES) with the trace command
 *
 */

/* iSeries header page

 COMMUNICATIONS TRACE       Title: OS400 - OS400 trace               10/28/05  11:44:50                           Page:       1
   Trace Description  . . . . . :   OS400 - OS400 trace
   Configuration object . . . . :   ETH0
   Type . . . . . . . . . . . . :   1            1=Line, 2=Network Interface
                                                 3=Network server
   Object protocol  . . . . . . :   ETHERNET
   Start date/Time  . . . . . . :   10/28/05  11:43:00.341
   End date/Time  . . . . . . . :   10/28/05  11:44:22.148
   Bytes collected  . . . . . . :   11999
   Buffer size  . . . . . . . . :   2048         kilobytes
   Data direction . . . . . . . :   3            1=Sent, 2=Received, 3=Both
   Stop on buffer full  . . . . :   Y            Y=Yes, N=No
   Number of bytes to trace
     Beginning bytes  . . . . . :   *MAX         Value, *CALC, *MAX
     Ending bytes   . . . . . . :   *CALC        Value, *CALC
   Controller name  . . . . . . :   *ALL         *ALL, name
   Data representation  . . . . :   1            1=ASCII, 2=EBCDIC, 3=*CALC
   Format SNA data only . . . . :   N            Y=Yes, N=No
   Format RR, RNR commands  . . :   N            Y=Yes, N=No
   Format TCP/IP data only  . . :   Y            Y=Yes, N=No
     IP address . . . . . . . . :   *ALL             *ALL, address
     IP address . . . . . . . . :   *ALL             *ALL, address
     IP port  . . . . . . . . . :   *ALL             *ALL, IP port
   Format UI data only  . . . . :   N            Y=Yes, N=No
   Select Ethernet data . . . . :   3            1=802.3, 2=ETHV2, 3=Both
   Format Broadcast data  . . . :   Y            Y=Yes, N=No
*/

/* iSeries IPv4 formatted packet records consist of a packet header line
 * identifying the packet number, direction, size, timestamp,
 * source/destination MAC addresses and packet type.
 *
 * Thereafter there will be a formated display of the headers above
 * the link layer, such as ARP, IP, TCP, UDP, and ICMP (all but
 * ICMP have either been seen in captures or on pages such as the ones
 * at
 *
 *    http://www-912.ibm.com/s_dir/SLKBase.nsf/1ac66549a21402188625680b0002037e/e05fb0515bc3449686256ce600512c37?OpenDocument
 *
 * and
 *
 *    http://publib.boulder.ibm.com/infocenter/javasdk/v5r0/index.jsp?topic=%2Fcom.ibm.java.doc.diagnostics.50%2Fdiag%2Fproblem_determination%2Fi5os_perf_io_commstrace.html
 *
 * so we cannot assume that "IP Header" or "TCP Header" will appear). The
 * formatted display includes lines that show the contents of some of the
 * fields in the header, as well as hex strings dumps of the headers
 * themselves, with tags such as "IP Header  :", "ARP Header :",
 * "TCP Header :", "UDP Header :", and (presumably) "ICMP Header:".
 *
 * If the packet contains data this is displayed as 4 groups of 16 hex digits
 * followed by an ASCII representaion of the data line.
 *
 * Information from the packet header line, higher-level headers and, if
 * available, data lines are extracted by the module for displaying.
 *
 *
 Record       Data    Record           Controller  Destination   Source        Frame
 Number  S/R  Length  Timer            Name        MAC Address   MAC Address   Format
 ------  ---  ------  ---------------  ----------  ------------  ------------  ------
      8   S      145  11:43:59.82956               0006299C14AE  0006299C14FE   ETHV2   Type: 0800
                      Frame Type :  IP          DSCP: 0   ECN: 00-NECT  Length:   145   Protocol: TCP         Datagram ID: 388B
                                    Src Addr: 10.20.144.150       Dest Addr: 10.20.144.151       Fragment Flags: DON'T,LAST
                      IP Header  :  45000091388B40004006CC860A1490960A149097
                      IP Options :  NONE
                      TCP  . . . :  Src Port:  6006,Unassigned    Dest Port: 35366,Unassigned
                                    SEQ Number:  2666470699 ('9EEF1D2B'X)  ACK Number: 2142147535 ('7FAE93CF'X)
                                    Code Bits: ACK PSH                  Window: 32648  TCP Option: NO OP
                      TCP Header :  17768A269EEF1D2B7FAE93CF80187F885B5600000101080A0517E0F805166DE0
         Data . . . . . :  5443503200020010 0000004980000000  B800000080470103 01001E0000002000   *TCP2.......I*...*...*G........ .*
                           002F010080000004 0300800700C00600  4002008000000304 00800000060FB067   *./..*.....*..*..@..*.....*....*G*
                           FC276228786B3EB0 EF34F5F1D27EF8DF  20926820E7B322AA 739F1FB20D         **'B(XK>**4***.** *H **"*S*.*.   *
*/

/* iSeries IPv6 formatted traces are similar to the IPv4 version above,
 * except that the higher-level headers have "IPv6 Header:" and
 * "ICMPv6  Hdr:", and data data is no longer output in groups of 16 hex
 * digits.
 *

Record       Data      Record                       Destination   Source        Frame
Number  S/R  Length    Timer                        MAC Address   MAC Address   Format
------  ---  ------    ------------                 ------------  ------------  ------
   218   S     1488    15:01:14.389                 0011BC358680  00096B6BD918   ETHV2  Type: 86DD
                      IPv6   Data:  Ver: 06                      Traffic Class: 00            Flow Label: 000000
                                    Payload Length:  1448        Next Header: 06,TCP          Hop Limit:    64
                                    Src Addr:   fd00:0:0:20f2::122
                                    Dest Addr:  fd00:0:0:20a0::155
                      IPv6 Header:  6000000005A80640FD000000000020F20000000000000122FD000000000020A0
                                    0000000000000155
                      TCP  . . . :  Src Port: 21246,Unassigned    Dest Port: 13601,Unassigned
                                    SEQ Number:  2282300877 ('880925CD'X)  ACK Number: 3259003715 ('C2407343'X)
                                    Code Bits: ACK                      Window: 65535  TCP Option: NO OP
                      TCP Header :  52FE3521880925CDC24073438010FFFFCFBB00000101080A0E15127000237A08
         Data . . . . . :  54435032000200140000061880000000ECBEB867F0000000004CE640E6C1D9D5       *TCP2........*...***g*....L*@*****
                           C9D5C740E3C8C9E240C9E240E3C8C540E6C1D9D5C9D5C740C6C9C5D3C4404040       ****@****@**@***@*******@*****@@@*
                           4040404040404040404040404040404040404040404040404040404040404040       *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*
*/

/* iSeries unformatted packet record consist of the same header record as
 * the formatted trace but all other records are simply unformatted data
 * containing higher-level headers and packet data combined.
 *
 Record       Data    Record           Controller  Destination   Source        Frame            Number  Number    Poll/
 Number  S/R  Length  Timer            Name        MAC Address   MAC Address   Format  Command  Sent    Received  Final  DSAP  SSAP
 ------  ---  ------  ---------------  ----------  ------------  ------------  ------  -------  ------  --------  -----  ----  ----
      1   R       64  12:19:29.97108               000629ECF48E  0006D78E23C2   ETHV2   Type: 0800
         Data . . . . . :  4500003C27954000 3A06CE3D9797440F  0A5964EAC4F50554 58C9915500000000   *E..<'*@.:.*=**D..YD***.TX**U....*
                           A00216D06A200000 020405B40402080A  1104B6C000000000 010303000B443BF1   **..*J .....*......**.........D;**
*/

#include "config.h"
#include "wtap-int.h"
#include "buffer.h"
#include "iseries.h"
#include "file_wrappers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <wsutil/str_util.h>

#define ISERIES_HDR_MAGIC_STR         "COMMUNICATIONS TRACE"
#define ISERIES_HDR_MAGIC_LEN         20
#define ISERIES_LINE_LENGTH           270
#define ISERIES_HDR_LINES_TO_CHECK    100
#define ISERIES_PKT_LINES_TO_CHECK    4
#define ISERIES_MAX_PACKET_LEN        16384
#define ISERIES_MAX_TRACE_LEN         99999999
#define ISERIES_PKT_ALLOC_SIZE        (pkt_len*2)+1
#define ISERIES_FORMAT_ASCII          1
#define ISERIES_FORMAT_UNICODE        2

typedef struct {
  gboolean have_date;           /* TRUE if we found a capture start date */
  int      year, month, day;    /* The start date */
  int      format;              /* Trace format type        */
} iseries_t;

static gboolean iseries_read (wtap * wth, int *err, gchar ** err_info,
                              gint64 *data_offset);
static gboolean iseries_seek_read (wtap * wth, gint64 seek_off,
                                   struct wtap_pkthdr *phdr,
                                   Buffer * buf, int *err, gchar ** err_info);
static gboolean iseries_check_file_type (wtap * wth, int *err, gchar **err_info,
                                         int format);
static gint64 iseries_seek_next_packet (wtap * wth, int *err, gchar **err_info);
static gboolean iseries_parse_packet (wtap * wth, FILE_T fh,
                                      struct wtap_pkthdr *phdr,
                                      Buffer * buf, int *err, gchar ** err_info);
static int iseries_UNICODE_to_ASCII (guint8 * buf, guint bytes);
static gboolean iseries_parse_hex_string (const char * ascii, guint8 * buf,
                                          size_t len);

int
iseries_open (wtap * wth, int *err, gchar ** err_info)
{
  int  bytes_read;
  gint offset;
  char magic[ISERIES_LINE_LENGTH];
  char unicodemagic[] =
    { '\x43', '\x00', '\x4F', '\x00', '\x4D',
    '\x00', '\x4D', '\x00', '\x55', '\x00', '\x4E', '\x00', '\x49', '\x00',
    '\x43', '\x00', '\x41'
  };

  /*
   * Check that file starts with a valid iSeries COMMS TRACE header
   * by scanning for it in the first line
   */
  errno = WTAP_ERR_CANT_READ;
  bytes_read = file_read (&magic, sizeof magic, wth->fh);
  if (bytes_read != sizeof magic)
    {
      *err = file_error (wth->fh, err_info);
      if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
        return -1;
      return 0;
    }

  /*
   * Check if this is a UNICODE formatted file by scanning for the magic string
   */
  offset=0;
  while ((unsigned int)offset < (ISERIES_LINE_LENGTH - (sizeof unicodemagic)))
    {
      if (memcmp (magic + offset, unicodemagic, sizeof unicodemagic) == 0) {
        if (file_seek (wth->fh, 0, SEEK_SET, err) == -1)
          {
            return 0;
          }
        /*
         * Do some basic sanity checking to ensure we can handle the
         * contents of this trace
         */
        if (!iseries_check_file_type (wth, err, err_info, ISERIES_FORMAT_UNICODE))
          {
            if (*err == 0)
              return 0;
            else
              return -1;
          }

        wth->file_encap        = WTAP_ENCAP_ETHERNET;
        wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_ISERIES;
        wth->snapshot_length   = 0;
        wth->subtype_read      = iseries_read;
        wth->subtype_seek_read = iseries_seek_read;
        wth->tsprecision       = WTAP_FILE_TSPREC_USEC;

        if (file_seek (wth->fh, 0, SEEK_SET, err) == -1)
          {
            return 0;
          }
        return 1;
      }
      offset += 1;
    }

    /*
     * Check if this is a ASCII formatted file by scanning for the magic string
     */
    offset=0;
    while (offset < (ISERIES_LINE_LENGTH - ISERIES_HDR_MAGIC_LEN))
      {
        if (memcmp (magic + offset, ISERIES_HDR_MAGIC_STR, ISERIES_HDR_MAGIC_LEN) == 0)
          {
            if (file_seek (wth->fh, 0, SEEK_SET, err) == -1)
              {
                return 0;
              }
            /*
             * Do some basic sanity checking to ensure we can handle the
             * contents of this trace
             */
            if (!iseries_check_file_type (wth, err, err_info, ISERIES_FORMAT_ASCII))
              {
                if (*err == 0)
                  return 0;
                else
                  return -1;
              }

            wth->file_encap        = WTAP_ENCAP_ETHERNET;
            wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_ISERIES;
            wth->snapshot_length   = 0;
            wth->subtype_read      = iseries_read;
            wth->subtype_seek_read = iseries_seek_read;
            wth->tsprecision       = WTAP_FILE_TSPREC_USEC;

            if (file_seek (wth->fh, 0, SEEK_SET, err) == -1)
              {
                return 0;
              }
            return 1;
          }
        offset += 1;
      }

    /* Neither ASCII or UNICODE so not supported */
    return 0;
    }

/*
 * Do some basic sanity checking to ensure we can handle the
 * contents of this trace by checking the header page for
 * requisit requirements and additional information.
 */
static gboolean
iseries_check_file_type (wtap * wth, int *err, gchar **err_info, int format)
{
  guint      line;
  int        num_items_scanned;
  char       buf[ISERIES_LINE_LENGTH], protocol[9];
  iseries_t *iseries;

  /* Save trace format for passing between packets */
  iseries                = (iseries_t *) g_malloc (sizeof (iseries_t));
  wth->priv              = (void *) iseries;
  iseries->have_date     = FALSE;
  iseries->format        = format;

  for (line = 0; line < ISERIES_HDR_LINES_TO_CHECK; line++)
    {
      if (file_gets (buf, ISERIES_LINE_LENGTH, wth->fh) == NULL)
        {
          /* EOF or error. */
          *err = file_error (wth->fh, err_info);
          if (*err == WTAP_ERR_SHORT_READ)
            *err = 0;
          return FALSE;
        }

        /*
         * Check that we are dealing with an ETHERNET trace
         */
        if (iseries->format == ISERIES_FORMAT_UNICODE)
          {
            iseries_UNICODE_to_ASCII ((guint8 *)buf, ISERIES_LINE_LENGTH);
          }
        ascii_strup_inplace (buf);
        num_items_scanned = sscanf (buf,
                                   "%*[ \n\t]OBJECT PROTOCOL%*[ .:\n\t]%8s",
                                   protocol);
        if (num_items_scanned == 1)
          {
            if (memcmp (protocol, "ETHERNET", 8) != 0)
              return FALSE;
          }

        /*
         * The header is the only place where the date part of the timestamp is held, so
         * extract it here and store for all packets to access
         */
        num_items_scanned = sscanf (buf,
                                    "%*[ \n\t]START DATE/TIME%*[ .:\n\t]%2d/%2d/%2d",
                                    &iseries->month, &iseries->day,
                                    &iseries->year);
        if (num_items_scanned == 3)
          {
            iseries->have_date = TRUE;
          }
    }
  *err = 0;
  return TRUE;
}

/*
 * Find the next packet and parse it; called from wtap_read().
 */
static gboolean
iseries_read (wtap * wth, int *err, gchar ** err_info, gint64 *data_offset)
{
  gint64 offset;

  /*
   * Locate the next packet
   */
  offset = iseries_seek_next_packet (wth, err, err_info);
  if (offset < 0)
    return FALSE;
  *data_offset     = offset;

  /*
   * Parse the packet and extract the various fields
   */
  return iseries_parse_packet (wth, wth->fh, &wth->phdr, wth->frame_buffer,
                               err, err_info);
}

/*
 * Seeks to the beginning of the next packet, and returns the
 * byte offset.  Returns -1 on failure or EOF; on EOF, sets
 * *err to 0, and, on failure, sets *err to the error and *err_info
 * to null or an additional error string.
 */
static gint64
iseries_seek_next_packet (wtap * wth, int *err, gchar **err_info)
{
  iseries_t *iseries = (iseries_t *)wth->priv;
  char       buf[ISERIES_LINE_LENGTH],type[5];
  int        line, num_items_scanned;
  gint64     cur_off;
  long       buflen;

  for (line = 0; line < ISERIES_MAX_TRACE_LEN; line++)
    {
      if (file_gets (buf, ISERIES_LINE_LENGTH, wth->fh) == NULL)
        {
          /* EOF or error. */
          *err = file_error (wth->fh, err_info);
          return -1;
        }
        /* Convert UNICODE to ASCII if required and determine    */
        /* the number of bytes to rewind to beginning of record. */
        if (iseries->format == ISERIES_FORMAT_UNICODE)
          {
            /* buflen is #bytes to 1st 0x0A */
            buflen = iseries_UNICODE_to_ASCII ((guint8 *) buf, ISERIES_LINE_LENGTH);
          }
        else
          {
            /* Else buflen is just length of the ASCII string */
            buflen = (long) strlen (buf);
          }
        ascii_strup_inplace (buf);
        /* If packet header found return the offset */
        num_items_scanned =
          sscanf (buf+78,
                  "%*[ \n\t]ETHV2%*[ .:\n\t]TYPE%*[ .:\n\t]%4s",type);
        if (num_items_scanned == 1)
          {
            /* Rewind to beginning of line */
            cur_off = file_tell (wth->fh);
            if (cur_off == -1)
              {
                *err = file_error (wth->fh, err_info);
                return -1;
              }
            if (file_seek (wth->fh, cur_off - buflen, SEEK_SET, err) == -1)
              {
                return -1;
              }
            return cur_off - buflen;
          }
    }

  *err = WTAP_ERR_BAD_FILE;
  *err_info =
    g_strdup_printf ("iseries: next packet header not found within %d lines",
             ISERIES_MAX_TRACE_LEN);
  return -1;
}

/*
 * Read packets in random-access fashion
 */
static gboolean
iseries_seek_read (wtap * wth, gint64 seek_off, struct wtap_pkthdr *phdr,
                   Buffer * buf, int *err, gchar ** err_info)
{

  /* seek to packet location */
  if (file_seek (wth->random_fh, seek_off - 1, SEEK_SET, err) == -1)
    return FALSE;

  /*
   * Parse the packet and extract the various fields
   */
  return iseries_parse_packet (wth, wth->random_fh, phdr, buf,
                               err, err_info);
}

static int
append_hex_digits(char *ascii_buf, int ascii_offset, int max_offset,
                  char *data, int *err, gchar **err_info)
{
  int in_offset, out_offset;
  int c;
  unsigned int i;
  gboolean overflow = FALSE;

  in_offset = 0;
  out_offset = ascii_offset;
  for (;;)
    {
      /*
       * Process a block of up to 16 hex digits.
       * The block is terminated early by an end-of-line indication (NUL,
       * CR, or LF), by a space (which terminates the last block of the
       * data we're processing), or by a "*", which introduces the ASCII representation
       * of the data.
       * All characters in the block must be upper-case hex digits;
       * there might or might not be a space *after* a block, but, if so,
       * that will be skipped over after the block is processed.
       */
      for (i = 0; i < 16; i++, in_offset++)
        {
          /*
           * If we see an end-of-line indication, or an early-end-of-block
           * indication (space), we're done.  (Only the last block ends
           * early.)
           */
          c = data[in_offset] & 0xFF;
          if (c == '\0' || c == ' ' || c == '*' || c == '\r' || c == '\n')
            {
              goto done;
            }
          if (!isxdigit(c) || islower(c))
            {
              /*
               * Not a hex digit, or a lower-case hex digit.
               * Treat this as an indication that the line isn't a data
               * line, so we just ignore it.
               *
               * XXX - do so only for continuation lines; treat non-hex-digit
               * characters as errors for other lines?
               */
              return ascii_offset; /* pretend we appended nothing */
            }
          if (out_offset >= max_offset)
            overflow = TRUE;
          else
            {
              ascii_buf[out_offset] = c;
              out_offset++;
            }
        }
      /*
       * Skip blanks, if any.
       */
      for (; (data[in_offset] & 0xFF) == ' '; in_offset++)
        ;
    }
done:
  /*
   * If we processed an *odd* number of hex digits, report an error.
   */
  if ((i % 2) != 0)
    {
      *err = WTAP_ERR_BAD_FILE;
      *err_info = g_strdup("iseries: odd number of hex digits in a line");
      return -1;
    }
  if (overflow)
    {
      *err = WTAP_ERR_BAD_FILE;
      *err_info = g_strdup("iseries: more packet data than the packet length indicated");
      return -1;
    }
  return out_offset;
}

/* Parses a packet. */
static gboolean
iseries_parse_packet (wtap * wth, FILE_T fh, struct wtap_pkthdr *phdr,
                      Buffer *buf, int *err, gchar **err_info)
{
  iseries_t *iseries = (iseries_t *)wth->priv;
  gint64     cur_off;
  gboolean   isValid, isCurrentPacket;
  int        num_items_scanned, line, pktline, buflen;
  int        pkt_len, pktnum, hr, min, sec;
  char       direction[2], destmac[13], srcmac[13], type[5], csec[9+1];
  char       data[ISERIES_LINE_LENGTH * 2];
  int        offset;
  char      *ascii_buf;
  int        ascii_offset;
  struct tm  tm;

  /*
   * Check for packet headers in first 3 lines this should handle page breaks
   * situations and the header lines output at each page throw and ensure we
   * read both the captured and packet lengths.
   */
  isValid = FALSE;
  for (line = 1; line < ISERIES_PKT_LINES_TO_CHECK; line++)
    {
      if (file_gets (data, ISERIES_LINE_LENGTH, fh) == NULL)
        {
          *err = file_error (fh, err_info);
          return FALSE;
        }
      /* Convert UNICODE data to ASCII */
      if (iseries->format == ISERIES_FORMAT_UNICODE)
        {
         iseries_UNICODE_to_ASCII ((guint8 *)data, ISERIES_LINE_LENGTH);
        }
      ascii_strup_inplace (data);
      num_items_scanned =
        sscanf (data,
                "%*[ \n\t]%6d%*[ *\n\t]%1s%*[ \n\t]%6d%*[ \n\t]%2d:%2d:%2d.%9[0-9]%*[ \n\t]"
                "%12s%*[ \n\t]%12s%*[ \n\t]ETHV2%*[ \n\t]TYPE:%*[ \n\t]%4s",
                &pktnum, direction, &pkt_len, &hr, &min, &sec, csec, destmac,
                srcmac, type);
      if (num_items_scanned == 10)
        {
          /* OK! We found the packet header line */
          isValid = TRUE;
          /*
           * XXX - The Capture length returned by the iSeries trace doesn't
           * seem to include the Ethernet header, so we add its length here.
           */
          pkt_len += 14;
          break;
        }
    }

  /*
   * If no packet header found we exit at this point and inform the user.
   */
  if (!isValid)
    {
      *err = WTAP_ERR_BAD_FILE;
      *err_info = g_strdup ("iseries: packet header isn't valid");
      return FALSE;
    }

  phdr->rec_type = REC_TYPE_PACKET;
  phdr->presence_flags = WTAP_HAS_CAP_LEN;

  /*
   * If we have Wiretap Header then populate it here
   *
   * Timer resolution on the iSeries is hardware dependent.  We determine
   * the resolution based on how many digits we see.
   */
  if (iseries->have_date)
    {
      phdr->presence_flags |= WTAP_HAS_TS;
      tm.tm_year        = 100 + iseries->year;
      tm.tm_mon         = iseries->month - 1;
      tm.tm_mday        = iseries->day;
      tm.tm_hour        = hr;
      tm.tm_min         = min;
      tm.tm_sec         = sec;
      tm.tm_isdst       = -1;
      phdr->ts.secs = mktime (&tm);
      csec[sizeof(csec) - 1] = '\0';
      switch (strlen(csec))
        {
          case 0:
            phdr->ts.nsecs = 0;
            break;
          case 1:
            phdr->ts.nsecs = atoi(csec) * 100000000;
            break;
          case 2:
            phdr->ts.nsecs = atoi(csec) * 10000000;
            break;
          case 3:
            phdr->ts.nsecs = atoi(csec) * 1000000;
            break;
          case 4:
            phdr->ts.nsecs = atoi(csec) * 100000;
            break;
          case 5:
            phdr->ts.nsecs = atoi(csec) * 10000;
            break;
          case 6:
            phdr->ts.nsecs = atoi(csec) * 1000;
            break;
          case 7:
            phdr->ts.nsecs = atoi(csec) * 100;
            break;
          case 8:
            phdr->ts.nsecs = atoi(csec) * 10;
            break;
          case 9:
            phdr->ts.nsecs = atoi(csec);
            break;
        }
    }

  phdr->len                       = pkt_len;
  phdr->pkt_encap                 = WTAP_ENCAP_ETHERNET;
  phdr->pseudo_header.eth.fcs_len = -1;

  ascii_buf = (char *)g_malloc (ISERIES_PKT_ALLOC_SIZE);
  g_snprintf(ascii_buf, ISERIES_PKT_ALLOC_SIZE, "%s%s%s", destmac, srcmac, type);
  ascii_offset = 14*2; /* 14-byte Ethernet header, 2 characters per byte */

  /*
   * Start reading packet contents
   */
  isCurrentPacket = TRUE;

  /* loop through packet lines and breakout when the next packet header is read */
  pktline = 0;
  while (isCurrentPacket)
    {
      pktline++;
      /* Read the next line */
      if (file_gets (data, ISERIES_LINE_LENGTH, fh) == NULL)
        {
          *err = file_error (fh, err_info);
          if (*err == 0)
            {
              /* Hit the EOF without an error */
              break;
            }
          goto errxit;
        }

      /* Convert UNICODE data to ASCII and determine line length */
      if (iseries->format == ISERIES_FORMAT_UNICODE)
        {
         buflen = iseries_UNICODE_to_ASCII ((guint8 *)data, ISERIES_LINE_LENGTH);
        }
      else
        {
          /* Else bytes to rewind is just length of ASCII string */
          buflen = (int) strlen (data);
        }

      /*
       * Skip leading white space.
       */
      for (offset = 0; isspace(data[offset]); offset++)
        ;

      /*
       * The higher-level header information starts at an offset of
       * 22 characters.  The header tags are 14 characters long.
       *
       * XXX - for IPv6, if the next header isn't the last header,
       * the intermediate headers do *NOT* appear to be shown in
       * the dump file *at all*, so the packet *cannot* be
       * reconstructed!
       */
      if (offset == 22)
        {
          if (strncmp(data + 22, "IP Header  :  ", 14) == 0 ||
              strncmp(data + 22, "IPv6 Header:  ", 14) == 0 ||
              strncmp(data + 22, "ARP Header :  ", 14) == 0 ||
              strncmp(data + 22, "TCP Header :  ", 14) == 0 ||
              strncmp(data + 22, "UDP Header :  ", 14) == 0 ||
              strncmp(data + 22, "ICMP Header:  ", 14) == 0 ||
              strncmp(data + 22, "ICMPv6  Hdr:  ", 14) == 0 ||
              strncmp(data + 22, "Option  Hdr:  ", 14) == 0)
            {
              ascii_offset = append_hex_digits(ascii_buf, ascii_offset,
                                               ISERIES_PKT_ALLOC_SIZE - 1,
                                               data + 22 + 14, err,
                                               err_info);
              if (ascii_offset == -1)
                {
                  /* Bad line. */
                  return FALSE;
                }
              continue;
            }
        }

      /*
       * Is this a data line?
       *
       * The "Data" starts at an offset of 8.
       */
      if (offset == 9)
        {
          if (strncmp(data + 9, "Data . . . . . :  ", 18) == 0)
            {
              ascii_offset = append_hex_digits(ascii_buf, ascii_offset,
                                               ISERIES_PKT_ALLOC_SIZE - 1,
                                               data + 9 + 18, err,
                                               err_info);
              if (ascii_offset == -1)
                {
                  /* Bad line. */
                  return FALSE;
                }
              continue;
            }
        }

      /*
       * Is this a continuation of a previous header or data line?
       * That's blanks followed by hex digits; first try the
       * "no column separators" form.
       *
       * Continuations of header lines begin at an offset of 36;
       * continuations of data lines begin at an offset of 27.
       */
      if (offset == 36 || offset == 27)
        {
          ascii_offset = append_hex_digits(ascii_buf, ascii_offset,
                                           ISERIES_PKT_ALLOC_SIZE - 1,
                                           data + offset, err,
                                           err_info);
          if (ascii_offset == -1)
            {
              /* Bad line. */
              return FALSE;
            }
          continue;
        }

      /*
       * If we see the identifier for the next packet then rewind and set
       * isCurrentPacket FALSE
       */
      ascii_strup_inplace (data);
      /* If packet header found return the offset */
      num_items_scanned =
          sscanf (data+78,
          "%*[ \n\t]ETHV2%*[ .:\n\t]TYPE%*[ .:\n\t]%4s",type);
      if ((num_items_scanned == 1) && pktline > 1)
        {
          isCurrentPacket = FALSE;
          cur_off = file_tell( fh);
          if (cur_off == -1)
            {
              /* Error. */
              *err = file_error (fh, err_info);
              goto errxit;
            }
          if (file_seek (fh, cur_off - buflen, SEEK_SET, err) == -1)
            {
              /* XXX: need to set err_info ?? */
              goto errxit;
            }
        }
    }
  ascii_buf[ascii_offset] = '\0';

  /*
   * Make the captured length be the amount of bytes we've read (which
   * is half the number of characters of hex dump we have).
   *
   * XXX - this can happen for IPv6 packets if the next header isn't the
   * last header.
   */
  phdr->caplen = ((guint32) strlen (ascii_buf))/2;

  /* Make sure we have enough room for the packet. */
  buffer_assure_space (buf, ISERIES_MAX_PACKET_LEN);
  /* Convert ascii data to binary and return in the frame buffer */
  iseries_parse_hex_string (ascii_buf, buffer_start_ptr (buf), strlen (ascii_buf));

  /* free buffer allocs and return */
  *err = 0;
  g_free (ascii_buf);
  return TRUE;

errxit:
  g_free (ascii_buf);
  return FALSE;
}

/*
 * Simple routine to convert an UNICODE buffer to ASCII
 *
 * XXX - This may be possible with iconv or similar
 */
static int
iseries_UNICODE_to_ASCII (guint8 * buf, guint bytes)
{
  guint   i;
  guint8 *bufptr;

  bufptr = buf;

  for (i = 0; i < bytes; i++)
    {
      switch (buf[i])
        {
          case 0xFE:
          case 0xFF:
          case 0x00:
            break;
          default:
            *bufptr = buf[i];
            bufptr++;
        }
      if (buf[i] == 0x0A)
        return i;
    }
  return i;
}

/*
 * Simple routine to convert an ASCII hex string to binary data
 * Requires ASCII hex data and buffer to populate with binary data
 */
static gboolean
iseries_parse_hex_string (const char * ascii, guint8 * buf, size_t len)
{
  size_t i;
  int byte;
  gint   hexvalue;
  guint8 bytevalue;

  byte = 0;
  for (i = 0; i < len; i++)
    {
      hexvalue = g_ascii_xdigit_value(ascii[i]);
      i++;
      if (hexvalue == -1)
        return FALSE;        /* not a valid hex digit */
      bytevalue = (guint8)(hexvalue << 4);
      if (i >= len)
        return FALSE;        /* only one hex digit of the byte is present */
      hexvalue = g_ascii_xdigit_value(ascii[i]);
      if (hexvalue == -1)
        return FALSE;        /* not a valid hex digit */
      bytevalue |= (guint8) hexvalue;
      buf[byte] = bytevalue;
      byte++;
    }
  return TRUE;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
