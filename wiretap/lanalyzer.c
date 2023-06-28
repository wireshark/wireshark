/* lanalyzer.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#define WS_LOG_DOMAIN LOG_DOMAIN_WIRETAP
#include "lanalyzer.h"

#include <stdlib.h>
#include <errno.h>
#include "wtap-int.h"
#include "file_wrappers.h"

/* The LANalyzer format is documented (at least in part) in Novell document
   TID022037, which can be found at, among other places:

     http://www.blacksheepnetworks.com/security/info/nw/lan/trace.txt
 */

/*    Record header format */

typedef struct {
      uint8_t   record_type[2];
      uint8_t   record_length[2];
} LA_RecordHeader;

#define LA_RecordHeaderSize 4

/*    Record type codes:                */

#define     RT_HeaderRegular       0x1001
#define     RT_HeaderCyclic        0x1007
#define     RT_RxChannelName       0x1006
#define     RT_TxChannelName       0x100b
#define     RT_FilterName          0x1032
#define     RT_RxTemplateName      0x1035
#define     RT_TxTemplateName      0x1036
#define     RT_DisplayOptions      0x100a
#define     RT_Summary             0x1002
#define     RT_SubfileSummary      0x1003
#define     RT_CyclicInformation   0x1009
#define     RT_Index               0x1004
#define     RT_PacketData          0x1005

#define     LA_ProFileLimit       (1024 * 1024 * 32)

typedef uint8_t Eadr[6];
typedef uint16_t TimeStamp[3];  /* 0.5 microseconds since start of trace */

/*
 * These records have only 2-byte alignment for 4-byte quantities,
 * so the structures aren't necessarily valid; they're kept as comments
 * for reference purposes.
 */

/*
 * typedef struct {
 *       uint8_t     day;
 *       uint8_t     mon;
 *       int16_t     year;
 *       } Date;
 */

/*
 * typedef struct {
 *       uint8_t     second;
 *       uint8_t     minute;
 *       uint8_t     hour;
 *       uint8_t     day;
 *       int16_t     reserved;
 *       } Time;
 */

/*
 * RT_Summary:
 *
 * typedef struct {
 *       Date        datcre;
 *       Date        datclo;
 *       Time        timeopn;
 *       Time        timeclo;
 *       Eadr        statadr;
 *       int16_t     mxseqno;
 *       int16_t     slcoff;
 *       int16_t     mxslc;
 *       int32_t     totpktt;
 *       int32_t     statrg;
 *       int32_t     stptrg;
 *       int32_t     mxpkta[36];
 *       int16_t     board_type;
 *       int16_t     board_version;
 *       int8_t      reserved[18];
 *       } Summary;
 */

#define SummarySize (18+22+(4*36)+6+6+6+4+4)

/*
 * typedef struct {
 *       int16_t     rid;
 *       int16_t     rlen;
 *       Summary     s;
 *       } LA_SummaryRecord;
 */

#define LA_SummaryRecordSize (SummarySize + 4)

/* LANalyzer board types (which indicate the type of network on which
   the capture was done). */
#define BOARD_325               226     /* LANalyzer 325 (Ethernet) */
#define BOARD_325TR             227     /* LANalyzer 325TR (Token-ring) */


/*
 * typedef struct {
 *       int16_t     rid;
 *       int16_t     rlen;
 *       int16_t     seqno;
 *       int32_t     totpktf;
 *       } LA_SubfileSummaryRecord;
 */

#define LA_SubfileSummaryRecordSize 10


#define LA_IndexSize 500

/*
 * typedef struct {
 *       int16_t     rid;
 *       int16_t     rlen;
 *       int16_t     idxsp;                    = LA_IndexSize
 *       int16_t     idxct;
 *       int8_t      idxgranu;
 *       int8_t      idxvd;
 *       int32_t     trcidx[LA_IndexSize + 2]; +2 undocumented but used by La 2.2
 *       } LA_IndexRecord;
 */

#define LA_IndexRecordSize (10 + 4 * (LA_IndexSize + 2))


/*
 * typedef struct {
 *       uint16_t    rx_channels;
 *       uint16_t    rx_errors;
 *       int16_t     rx_frm_len;
 *       int16_t     rx_frm_sln;
 *       TimeStamp   rx_time;
 *       uint32_t    pktno;
 *       int16_t     prvlen;
 *       int16_t     offset;
 *       int16_t     tx_errs;
 *       int16_t     rx_filters;
 *       int8_t      unused[2];
 *       int16_t     hwcolls;
 *       int16_t     hwcollschans;
 *       Packetdata ....;
 *       } LA_PacketRecord;
 */

#define LA_PacketRecordSize 32

typedef struct {
      bool            init;
      nstime_t        start;
      uint32_t        pkts;
      int             encap;
      int             lastlen;
      } LA_TmpInfo;

static const uint8_t LA_HeaderRegularFake[] = {
0x01,0x10,0x4c,0x00,0x01,0x05,0x54,0x72,0x61,0x63,0x65,0x20,0x44,0x69,0x73,0x70,
0x6c,0x61,0x79,0x20,0x54,0x72,0x61,0x63,0x65,0x20,0x46,0x69,0x6c,0x65,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
      };

static const uint8_t LA_RxChannelNameFake[] = {
0x06,0x10,0x80,0x00,0x43,0x68,0x61,0x6e ,0x6e,0x65,0x6c,0x31,0x00,0x43,0x68,0x61,
0x6e,0x6e,0x65,0x6c,0x32,0x00,0x43,0x68 ,0x61,0x6e,0x6e,0x65,0x6c,0x33,0x00,0x43,
0x68,0x61,0x6e,0x6e,0x65,0x6c,0x34,0x00 ,0x43,0x68,0x61,0x6e,0x6e,0x65,0x6c,0x35,
0x00,0x43,0x68,0x61,0x6e,0x6e,0x65,0x6c ,0x36,0x00,0x43,0x68,0x61,0x6e,0x6e,0x65,
0x6c,0x37,0x00,0x43,0x68,0x61,0x6e,0x6e ,0x65,0x6c,0x38,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00
      };

static const uint8_t LA_TxChannelNameFake[] = {
                    0x0b,0x10,0x36,0x00 ,0x54,0x72,0x61,0x6e,0x73,0x31,0x00,0x00,
0x00,0x54,0x72,0x61,0x6e,0x73,0x32,0x00 ,0x00,0x00,0x54,0x72,0x61,0x6e,0x73,0x33,
0x00,0x00,0x00,0x54,0x72,0x61,0x6e,0x73 ,0x34,0x00,0x00,0x00,0x54,0x72,0x61,0x6e,
0x73,0x35,0x00,0x00,0x00,0x54,0x72,0x61 ,0x6e,0x73,0x36,0x00,0x00,0x00
      };

static const uint8_t LA_RxTemplateNameFake[] = {
                                                                       0x35,0x10,
0x90,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00
      };

static const uint8_t LA_TxTemplateNameFake[] = {
          0x36,0x10,0x36,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00
      };

static const uint8_t LA_DisplayOptionsFake[] = {
                                                             0x0a,0x10,0x0a,0x01,
0x00,0x00,0x01,0x00,0x01,0x02,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00
      };

static const uint8_t LA_CyclicInformationFake[] = {
                                                   0x09,0x10,0x1a,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
      };

static const uint8_t z64[64] = {
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
      };

typedef struct {
      time_t  start;
} lanalyzer_t;

static bool lanalyzer_read(wtap *wth, wtap_rec *rec,
    Buffer *buf, int *err, char **err_info, int64_t *data_offset);
static bool lanalyzer_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info);
static bool lanalyzer_dump_finish(wtap_dumper *wdh, int *err,
    char **err_info);

static int lanalyzer_file_type_subtype = -1;

void register_lanalyzer(void);

wtap_open_return_val lanalyzer_open(wtap *wth, int *err, char **err_info)
{
      LA_RecordHeader rec_header;
      char header_fixed[2];
      char *comment;
      bool found_summary;
      char summary[210];
      uint16_t board_type, mxslc;
      uint16_t record_type, record_length;
      uint8_t cr_day, cr_month;
      uint16_t cr_year;
      struct tm tm;
      time_t start;
      int file_encap;
      lanalyzer_t *lanalyzer;

      if (!wtap_read_bytes(wth->fh, &rec_header, LA_RecordHeaderSize,
                           err, err_info)) {
            if (*err != WTAP_ERR_SHORT_READ)
                  return WTAP_OPEN_ERROR;
            return WTAP_OPEN_NOT_MINE;
      }
      record_type = pletoh16(rec_header.record_type);
      record_length = pletoh16(rec_header.record_length); /* make sure to do this for while() loop */

      if (record_type != RT_HeaderRegular && record_type != RT_HeaderCyclic) {
            return WTAP_OPEN_NOT_MINE;
      }

      /* Read the major and minor version numbers */
      if (record_length < sizeof header_fixed) {
            /*
             * Not enough room for the major and minor version numbers.
             * Just treat that as a "not a LANalyzer file" indication.
             */
            return WTAP_OPEN_NOT_MINE;
      }
      if (!wtap_read_bytes(wth->fh, &header_fixed, sizeof header_fixed,
                           err, err_info)) {
            if (*err != WTAP_ERR_SHORT_READ)
                  return WTAP_OPEN_ERROR;
            return WTAP_OPEN_NOT_MINE;
      }
      record_length -= sizeof header_fixed;

      if (record_length != 0) {
            /* Read the rest of the record as a comment. */
            comment = (char *)g_malloc(record_length + 1);
            if (!wtap_read_bytes(wth->fh, comment, record_length,
                                 err, err_info)) {
                  if (*err != WTAP_ERR_SHORT_READ) {
                      g_free(comment);
                      return WTAP_OPEN_ERROR;
                  }
                  g_free(comment);
                  return WTAP_OPEN_NOT_MINE;
            }
            wtap_block_add_string_option(g_array_index(wth->shb_hdrs, wtap_block_t, 0), OPT_COMMENT, comment, record_length);
            g_free(comment);
      }

      /*
       * Read records until we find the start of packets.
       * The document cited above claims that the first 11 records are
       * in a particular sequence of types, but at least one capture
       * doesn't have all the types listed in the order listed.
       *
       * If we don't have a summary record, we don't know the link-layer
       * header type, so we can't read the file.
       */
      found_summary = false;
      while (1) {
            if (!wtap_read_bytes_or_eof(wth->fh, &rec_header,
                                        LA_RecordHeaderSize, err, err_info)) {
                  if (*err == 0) {
                        /*
                         * End of file and no packets;
                         * accept this file.
                         */
                        break;
                  }
                  return WTAP_OPEN_ERROR;
            }

            record_type = pletoh16(rec_header.record_type);
            record_length = pletoh16(rec_header.record_length);

            /*ws_message("Record 0x%04X Length %d", record_type, record_length);*/
            switch (record_type) {
                  /* Trace Summary Record */
            case RT_Summary:
                  if (record_length < sizeof summary) {
                        *err = WTAP_ERR_BAD_FILE;
                        *err_info = ws_strdup_printf("lanalyzer: summary record length %u is too short",
                                                    record_length);
                        return WTAP_OPEN_ERROR;
                  }
                  if (!wtap_read_bytes(wth->fh, summary,
                                       sizeof summary, err, err_info))
                        return WTAP_OPEN_ERROR;

                  /* Assume that the date of the creation of the trace file
                   * is the same date of the trace. Lanalyzer doesn't
                   * store the creation date/time of the trace, but only of
                   * the file. Unless you traced at 11:55 PM and saved at 00:05
                   * AM, the assumption that trace.date == file.date is true.
                   */
                  cr_day = summary[0];
                  cr_month = summary[1];
                  cr_year = pletoh16(&summary[2]);
                  /*ws_message("Day %d Month %d Year %d (%04X)", cr_day, cr_month,
                    cr_year, cr_year);*/

                  /* Get capture start time. I learned how to do
                   * this from Guy's code in ngsniffer.c
                   */
                  tm.tm_year = cr_year - 1900;
                  tm.tm_mon = cr_month - 1;
                  tm.tm_mday = cr_day;
                  tm.tm_hour = 0;
                  tm.tm_min = 0;
                  tm.tm_sec = 0;
                  tm.tm_isdst = -1;
                  start = mktime(&tm);
                  /*ws_message("Day %d Month %d Year %d", tm.tm_mday,
                    tm.tm_mon, tm.tm_year);*/
                  mxslc = pletoh16(&summary[30]);

                  board_type = pletoh16(&summary[188]);
                  switch (board_type) {
                  case BOARD_325:
                        file_encap = WTAP_ENCAP_ETHERNET;
                        break;
                  case BOARD_325TR:
                        file_encap = WTAP_ENCAP_TOKEN_RING;
                        break;
                  default:
                        *err = WTAP_ERR_UNSUPPORTED;
                        *err_info = ws_strdup_printf("lanalyzer: board type %u unknown",
                                                    board_type);
                        return WTAP_OPEN_ERROR;
                  }

                  if (found_summary) {
                        *err = WTAP_ERR_BAD_FILE;
                        *err_info = ws_strdup_printf("lanalyzer: file has more than one summary record");
                        return WTAP_OPEN_ERROR;
                  }
                  found_summary = true;

                  /* Skip the rest of the record */
                  record_length -= sizeof summary;
                  if (record_length != 0) {
                        if (!wtap_read_bytes(wth->fh, NULL, record_length, err, err_info)) {
                              return WTAP_OPEN_ERROR;
                        }
                  }
                  break;

                  /* Trace Packet Data Record */
            case RT_PacketData:
                  /* Go back header number of bytes so that lanalyzer_read
                   * can read this header */
                  if (file_seek(wth->fh, -LA_RecordHeaderSize, SEEK_CUR, err) == -1) {
                        return WTAP_OPEN_ERROR;
                  }
                  goto done;

            default:
                  /* Unknown record type - skip it */
                  if (!wtap_read_bytes(wth->fh, NULL, record_length, err, err_info)) {
                        return WTAP_OPEN_ERROR;
                  }
                  break;
            }
      }

done:
      if (!found_summary) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("lanalyzer: file has no summary record");
            return WTAP_OPEN_ERROR;
      }

      /* If we made it this far, then the file is a readable LANAlyzer file.
       * Let's get some info from it. Note that we get wth->snapshot_length
       * from a record later in the file. */
      wth->file_type_subtype = lanalyzer_file_type_subtype;
      lanalyzer = g_new(lanalyzer_t, 1);
      lanalyzer->start = start;
      wth->priv = (void *)lanalyzer;
      wth->subtype_read = lanalyzer_read;
      wth->subtype_seek_read = lanalyzer_seek_read;
      wth->file_encap = file_encap;
      wth->snapshot_length = mxslc;
      wth->file_tsprec = WTAP_TSPREC_NSEC;

      /*
       * Add an IDB; we don't know how many interfaces were involved,
       * so we just say one interface, about which we only know
       * the link-layer type, snapshot length, and time stamp
       * resolution.
       */
      wtap_add_generated_idb(wth);

      return WTAP_OPEN_MINE;
}

#define DESCRIPTOR_LEN  32

static bool lanalyzer_read_trace_record(wtap *wth, FILE_T fh,
                                            wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
      char         LE_record_type[2];
      char         LE_record_length[2];
      uint16_t     record_type, record_length;
      int          record_data_size;
      int          packet_size;
      char         descriptor[DESCRIPTOR_LEN];
      lanalyzer_t *lanalyzer;
      uint16_t     time_low, time_med, time_high, true_size;
      uint64_t     t;
      time_t       tsecs;

      /* read the record type and length. */
      if (!wtap_read_bytes_or_eof(fh, LE_record_type, 2, err, err_info))
            return false;
      if (!wtap_read_bytes(fh, LE_record_length, 2, err, err_info))
            return false;

      record_type = pletoh16(LE_record_type);
      record_length = pletoh16(LE_record_length);

      /* Only Trace Packet Data Records should occur now that we're in
       * the middle of reading packets.  If any other record type exists
       * after a Trace Packet Data Record, mark it as an error. */
      if (record_type != RT_PacketData) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("lanalyzer: record type %u seen after trace summary record",
                                        record_type);
            return false;
      }

      if (record_length < DESCRIPTOR_LEN) {
            /*
             * Uh-oh, the record isn't big enough to even have a
             * descriptor.
             */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("lanalyzer: file has a %u-byte record, too small to have even a packet descriptor",
                                        record_length);
            return false;
      }
      record_data_size = record_length - DESCRIPTOR_LEN;

      /* Read the descriptor data */
      if (!wtap_read_bytes(fh, descriptor, DESCRIPTOR_LEN, err, err_info))
            return false;

      true_size = pletoh16(&descriptor[4]);
      packet_size = pletoh16(&descriptor[6]);
      /*
       * The maximum value of packet_size is 65535, which is less than
       * WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't need to check
       * it.
       */

      /*
       * OK, is the frame data size greater than what's left of the
       * record?
       */
      if (packet_size > record_data_size) {
            /*
             * Yes - treat this as an error.
             */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup("lanalyzer: Record length is less than packet size");
            return false;
      }

      rec->rec_type = REC_TYPE_PACKET;
      rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
      rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;

      time_low = pletoh16(&descriptor[8]);
      time_med = pletoh16(&descriptor[10]);
      time_high = pletoh16(&descriptor[12]);
      t = (((uint64_t)time_low) << 0) + (((uint64_t)time_med) << 16) +
            (((uint64_t)time_high) << 32);
      tsecs = (time_t) (t/2000000);
      lanalyzer = (lanalyzer_t *)wth->priv;
      rec->ts.secs = tsecs + lanalyzer->start;
      rec->ts.nsecs = ((uint32_t) (t - tsecs*2000000)) * 500;

      if (true_size - 4 >= packet_size) {
            /*
             * It appears that the "true size" includes the FCS;
             * make it reflect the non-FCS size (the "packet size"
             * appears never to include the FCS, even if no slicing
             * is done).
             */
            true_size -= 4;
      }
      rec->rec_header.packet_header.len = true_size;
      rec->rec_header.packet_header.caplen = packet_size;

      switch (wth->file_encap) {

      case WTAP_ENCAP_ETHERNET:
            /* We assume there's no FCS in this frame. */
            rec->rec_header.packet_header.pseudo_header.eth.fcs_len = 0;
            break;
      }

      /* Read the packet data */
      return wtap_read_packet_bytes(fh, buf, packet_size, err, err_info);
}

/* Read the next packet */
static bool lanalyzer_read(wtap *wth, wtap_rec *rec, Buffer *buf,
                               int *err, char **err_info, int64_t *data_offset)
{
      *data_offset = file_tell(wth->fh);

      /* Read the record  */
      return lanalyzer_read_trace_record(wth, wth->fh, rec, buf, err,
                                         err_info);
}

static bool lanalyzer_seek_read(wtap *wth, int64_t seek_off,
                                    wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
      if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
            return false;

      /* Read the record  */
      if (!lanalyzer_read_trace_record(wth, wth->random_fh, rec, buf,
                                       err, err_info)) {
            if (*err == 0)
                  *err = WTAP_ERR_SHORT_READ;
            return false;
      }
      return true;
}

/*---------------------------------------------------
 * Returns true on success, false on error
 * Write "cnt" bytes of zero with error control
 *---------------------------------------------------*/
static bool s0write(wtap_dumper *wdh, size_t cnt, int *err)
{
      size_t snack;

      while (cnt) {
            snack = cnt > 64 ? 64 : cnt;

            if (!wtap_dump_file_write(wdh, z64, snack, err))
                  return false;
            cnt -= snack;
      }
      return true; /* ok */
}

/*---------------------------------------------------
 * Returns true on success, false on error
 * Write an 8-bit value
 *---------------------------------------------------*/
static bool s8write(wtap_dumper *wdh, const uint8_t s8, int *err)
{
      return wtap_dump_file_write(wdh, &s8, 1, err);
}
/*---------------------------------------------------
 * Returns true on success, false on error
 * Write a 16-bit value as little-endian
 *---------------------------------------------------*/
static bool s16write(wtap_dumper *wdh, const uint16_t s16, int *err)
{
      uint16_t s16_le = GUINT16_TO_LE(s16);
      return wtap_dump_file_write(wdh, &s16_le, 2, err);
}
/*---------------------------------------------------
 * Returns true on success, false on error
 * Write a 32-bit value as little-endian
 *---------------------------------------------------*/
static bool s32write(wtap_dumper *wdh, const uint32_t s32, int *err)
{
      uint32_t s32_le = GUINT32_TO_LE(s32);
      return wtap_dump_file_write(wdh, &s32_le, 4, err);
}
/*---------------------------------------------------
 * Returns true on success, false on error
 * Write a 48-bit value as little-endian
 *---------------------------------------------------*/
static bool s48write(wtap_dumper *wdh, const uint64_t s48, int *err)
{
#if G_BYTE_ORDER == G_BIG_ENDIAN
      uint16_t s48_upper_le = GUINT16_SWAP_LE_BE((uint16_t) (s48 >> 32));
      uint32_t s48_lower_le = GUINT32_SWAP_LE_BE((uint32_t) (s48 & 0xFFFFFFFF));
#else
      uint16_t s48_upper_le = (uint16_t) (s48 >> 32);
      uint32_t s48_lower_le = (uint32_t) (s48 & 0xFFFFFFFF);
#endif
      return wtap_dump_file_write(wdh, &s48_lower_le, 4, err) &&
             wtap_dump_file_write(wdh, &s48_upper_le, 2, err);
}
/*---------------------------------------------------
 * Write a record for a packet to a dump file.
 * Returns true on success, false on failure.
 *---------------------------------------------------*/
static bool lanalyzer_dump(wtap_dumper *wdh,
        const wtap_rec *rec,
        const uint8_t *pd, int *err, char **err_info _U_)
{
      uint64_t x;
      int    len;

      LA_TmpInfo *itmp = (LA_TmpInfo*)(wdh->priv);
      nstime_t td;
      int    thisSize = rec->rec_header.packet_header.caplen + LA_PacketRecordSize + LA_RecordHeaderSize;

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

      if (wdh->bytes_dumped + thisSize > LA_ProFileLimit) {
            /* printf(" LA_ProFileLimit reached\n");     */
            *err = EFBIG;
            return false; /* and don't forget the header */
            }

      len = rec->rec_header.packet_header.caplen + (rec->rec_header.packet_header.caplen ? LA_PacketRecordSize : 0);

      /* len goes into a 16-bit field, so there's a hard limit of 65535. */
      if (len > 65535) {
            *err = WTAP_ERR_PACKET_TOO_LARGE;
            return false;
            }

      if (!s16write(wdh, 0x1005, err))
            return false;
      if (!s16write(wdh, (uint16_t)len, err))
            return false;

      if (!itmp->init) {
            /* collect some information for the
             * finally written header
             */
            itmp->start   = rec->ts;
            itmp->pkts    = 0;
            itmp->init    = true;
            itmp->encap   = wdh->file_encap;
            itmp->lastlen = 0;
            }

      if (!s16write(wdh, 0x0001, err))                    /* pr.rx_channels */
            return false;
      if (!s16write(wdh, 0x0008, err))                    /* pr.rx_errors   */
            return false;
      if (!s16write(wdh, (uint16_t) (rec->rec_header.packet_header.len + 4), err)) /* pr.rx_frm_len  */
            return false;
      if (!s16write(wdh, (uint16_t) rec->rec_header.packet_header.caplen, err))    /* pr.rx_frm_sln  */
            return false;

      nstime_delta(&td, &rec->ts, &itmp->start);

      /* Convert to half-microseconds, rounded up. */
      x = (td.nsecs + 250) / 500;  /* nanoseconds -> half-microseconds, rounded */
      x += td.secs * 2000000;      /* seconds -> half-microseconds */

      if (!s48write(wdh, x, err))                        /* pr.rx_time[i]  */
            return false;

      if (!s32write(wdh, ++itmp->pkts, err))             /* pr.pktno      */
            return false;
      if (!s16write(wdh, (uint16_t)itmp->lastlen, err))   /* pr.prlen      */
            return false;
      itmp->lastlen = len;

      if (!s0write(wdh, 12, err))
            return false;

      if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen, err))
            return false;

      return true;
}

/*---------------------------------------------------
 * Returns 0 if we could write the specified encapsulation type,
 * an error indication otherwise.
 *---------------------------------------------------*/
static int lanalyzer_dump_can_write_encap(int encap)
{
      /* Per-packet encapsulations aren't supported. */
      if (encap == WTAP_ENCAP_PER_PACKET)
                  return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

      if ( encap != WTAP_ENCAP_ETHERNET
        && encap != WTAP_ENCAP_TOKEN_RING )
                  return WTAP_ERR_UNWRITABLE_ENCAP;
      /*
       * printf("lanalyzer_dump_can_write_encap(%d)\n",encap);
       */
      return 0;
}

/*---------------------------------------------------
 * Returns true on success, false on failure; sets "*err" to an
 * error code on failure
 *---------------------------------------------------*/
static bool lanalyzer_dump_open(wtap_dumper *wdh, int *err, char **err_info _U_)
{
      int   jump;
      void  *tmp;

      tmp = g_malloc(sizeof(LA_TmpInfo));
      if (!tmp) {
            *err = errno;
            return false;
            }

      ((LA_TmpInfo*)tmp)->init = false;
      wdh->priv           = tmp;
      wdh->subtype_write  = lanalyzer_dump;
      wdh->subtype_finish = lanalyzer_dump_finish;

      /* Some of the fields in the file header aren't known yet so
       just skip over it for now.  It will be created after all
       of the packets have been written. */

      jump = sizeof (LA_HeaderRegularFake)
           + sizeof (LA_RxChannelNameFake)
           + sizeof (LA_TxChannelNameFake)
           + sizeof (LA_RxTemplateNameFake)
           + sizeof (LA_TxTemplateNameFake)
           + sizeof (LA_DisplayOptionsFake)
           + LA_SummaryRecordSize
           + LA_SubfileSummaryRecordSize
           + sizeof (LA_CyclicInformationFake)
           + LA_IndexRecordSize;

      if (wtap_dump_file_seek(wdh, jump, SEEK_SET, err) == -1)
            return false;

      wdh->bytes_dumped = jump;
      return true;
}

/*---------------------------------------------------
 *
 *---------------------------------------------------*/
static bool lanalyzer_dump_header(wtap_dumper *wdh, int *err)
{
      LA_TmpInfo *itmp   = (LA_TmpInfo*)(wdh->priv);
      uint16_t board_type = itmp->encap == WTAP_ENCAP_TOKEN_RING
                              ? BOARD_325TR     /* LANalyzer Board Type */
                              : BOARD_325;      /* LANalyzer Board Type */
      struct tm *fT;

      fT = localtime(&itmp->start.secs);
      if (fT == NULL)
            return false;

      if (wtap_dump_file_seek(wdh, 0, SEEK_SET, err) == -1)
            return false;

      if (!wtap_dump_file_write(wdh, &LA_HeaderRegularFake,
                                sizeof LA_HeaderRegularFake, err))
            return false;
      if (!wtap_dump_file_write(wdh, &LA_RxChannelNameFake,
                                sizeof LA_RxChannelNameFake, err))
            return false;
      if (!wtap_dump_file_write(wdh, &LA_TxChannelNameFake,
                                sizeof LA_TxChannelNameFake, err))
            return false;
      if (!wtap_dump_file_write(wdh, &LA_RxTemplateNameFake,
                                sizeof LA_RxTemplateNameFake, err))
            return false;
      if (!wtap_dump_file_write(wdh, &LA_TxTemplateNameFake,
                                sizeof LA_TxTemplateNameFake, err))
            return false;
      if (!wtap_dump_file_write(wdh, &LA_DisplayOptionsFake,
                                sizeof LA_DisplayOptionsFake, err))
            return false;
      /*-----------------------------------------------------------------*/
      if (!s16write(wdh, RT_Summary, err))         /* rid */
            return false;
      if (!s16write(wdh, SummarySize, err))        /* rlen */
            return false;
      if (!s8write(wdh, (uint8_t) fT->tm_mday, err))        /* s.datcre.day */
            return false;
      if (!s8write(wdh, (uint8_t) (fT->tm_mon+1), err))     /* s.datcre.mon */
            return false;
      if (!s16write(wdh, (uint16_t) (fT->tm_year + 1900), err)) /* s.datcre.year */
            return false;
      if (!s8write(wdh, (uint8_t) fT->tm_mday, err))        /* s.datclo.day */
            return false;
      if (!s8write(wdh, (uint8_t) (fT->tm_mon+1), err))     /* s.datclo.mon */
            return false;
      if (!s16write(wdh, (uint16_t) (fT->tm_year + 1900), err)) /* s.datclo.year */
            return false;
      if (!s8write(wdh, (uint8_t) fT->tm_sec, err))         /* s.timeopn.second */
            return false;
      if (!s8write(wdh, (uint8_t) fT->tm_min, err))         /* s.timeopn.minute */
            return false;
      if (!s8write(wdh, (uint8_t) fT->tm_hour, err))        /* s.timeopn.hour */
            return false;
      if (!s8write(wdh, (uint8_t) fT->tm_mday, err))        /* s.timeopn.mday */
            return false;
      if (!s0write(wdh, 2, err))
            return false;
      if (!s8write(wdh, (uint8_t) fT->tm_sec, err))         /* s.timeclo.second */
            return false;
      if (!s8write(wdh, (uint8_t) fT->tm_min, err))         /* s.timeclo.minute */
            return false;
      if (!s8write(wdh, (uint8_t) fT->tm_hour, err))        /* s.timeclo.hour */
            return false;
      if (!s8write(wdh, (uint8_t) fT->tm_mday, err))        /* s.timeclo.mday */
            return false;
      if (!s0write(wdh, 2, err))
            return false;
      if (!s0write(wdh, 6, err))                           /* EAddr  == 0      */
            return false;
      if (!s16write(wdh, 1, err))                  /* s.mxseqno */
            return false;
      if (!s16write(wdh, 0, err))                  /* s.slcoffo */
            return false;
      if (!s16write(wdh, 1514, err))               /* s.mxslc */
            return false;
      if (!s32write(wdh, itmp->pkts, err))         /* s.totpktt */
            return false;
      /*
       * statrg == 0; ? -1
       * stptrg == 0; ? -1
       * s.mxpkta[0]=0
       */
      if (!s0write(wdh, 12, err))
            return false;
      if (!s32write(wdh, itmp->pkts, err))         /* sr.s.mxpkta[1]  */
            return false;
      if (!s0write(wdh, 34*4, err))                /* s.mxpkta[2-33]=0  */
            return false;
      if (!s16write(wdh, board_type, err))
            return false;
      if (!s0write(wdh, 20, err))                     /* board_version == 0 */
            return false;
      /*-----------------------------------------------------------------*/
      if (!s16write(wdh, RT_SubfileSummary, err))     /* ssr.rid */
            return false;
      if (!s16write(wdh, LA_SubfileSummaryRecordSize-4, err)) /* ssr.rlen */
            return false;
      if (!s16write(wdh, 1, err))                     /* ssr.seqno */
            return false;
      if (!s32write(wdh, itmp->pkts, err))            /* ssr.totpkts */
            return false;
      /*-----------------------------------------------------------------*/
      if (!wtap_dump_file_write(wdh, &LA_CyclicInformationFake,
                                sizeof LA_CyclicInformationFake, err))
            return false;
      /*-----------------------------------------------------------------*/
      if (!s16write(wdh, RT_Index, err))              /* rid */
            return false;
      if (!s16write(wdh, LA_IndexRecordSize -4, err)) /* rlen */
            return false;
      if (!s16write(wdh, LA_IndexSize, err))          /* idxsp */
            return false;
      if (!s0write(wdh, LA_IndexRecordSize - 6, err))
            return false;

      return true;
}

/*---------------------------------------------------
 * Finish writing to a dump file.
 * Returns true on success, false on failure.
 *---------------------------------------------------*/
static bool lanalyzer_dump_finish(wtap_dumper *wdh, int *err,
        char **err_info _U_)
{
      /* bytes_dumped already accounts for the size of the header,
       * but lanalyzer_dump_header() (via wtap_dump_file_write())
       * will keep incrementing it.
       */
      int64_t saved_bytes_dumped = wdh->bytes_dumped;
      lanalyzer_dump_header(wdh,err);
      wdh->bytes_dumped = saved_bytes_dumped;
      return *err ? false : true;
}

static const struct supported_block_type lanalyzer_blocks_supported[] = {
      /*
       * We support packet blocks, with no comments or other options.
       */
      { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info lanalyzer_info = {
      "Novell LANalyzer","lanalyzer", "tr1", NULL,
      true, BLOCKS_SUPPORTED(lanalyzer_blocks_supported),
      lanalyzer_dump_can_write_encap, lanalyzer_dump_open, NULL
};

void register_lanalyzer(void)
{
      lanalyzer_file_type_subtype = wtap_register_file_type_subtype(&lanalyzer_info);

      /*
       * Register name for backwards compatibility with the
       * wtap_filetypes table in Lua.
       */
      wtap_register_backwards_compatibility_lua_name("LANALYZER",
                                                     lanalyzer_file_type_subtype);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 6
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=6 tabstop=8 expandtab:
 * :indentSize=6:tabSize=8:noTabs=true:
 */
