/* lanalyzer.h
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
 *
 */

#ifndef __LANALYZER_H__
#define __LANALYZER_H__

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

typedef guint8  Eadr[6];
typedef guint16 TimeStamp[3];  /* 0.5 microseconds since start of trace */

/*
 * These records have only 2-byte alignment for 4-byte quantities,
 * so the structures aren't necessarily valid; they're kept as comments
 * for reference purposes.
 */

/*
 * typedef struct {
 *       guint8      day;
 *       guint8      mon;
 *       gint16      year;
 *       } Date;
 */

/*
 * typedef struct {
 *       guint8      second;
 *       guint8      minute;
 *       guint8      hour;
 *       guint8      day;
 *       gint16      reserved;
 *       } Time;
 */

/*
 * typedef struct {
 *       guint16     rx_channels;
 *       guint16     rx_errors;
 *       gint16      rx_frm_len;
 *       gint16      rx_frm_sln;
 *       TimeStamp   rx_time;
 *       guint32     pktno;
 *       gint16      prvlen;
 *       gint16      offset;
 *       gint16      tx_errs;
 *       gint16      rx_filters;
 *       gint8       unused[2];
 *       gint16      hwcolls;
 *       gint16      hwcollschans;
 *       Packetdata ....;
 *       } LA_PacketRecord;
 */

#define LA_PacketRecordSize 32

/*
 * typedef struct {
 *       Date        datcre;
 *       Date        datclo;
 *       Time        timeopn;
 *       Time        timeclo;
 *       Eadr        statadr;
 *       gint16      mxseqno;
 *       gint16      slcoff;
 *       gint16      mxslc;
 *       gint32      totpktt;
 *       gint32      statrg;
 *       gint32      stptrg;
 *       gint32      mxpkta[36];
 *       gint16      board_type;
 *       gint16      board_version;
 *       gint8       reserved[18];
 *       } Summary;
 */

#define SummarySize (18+22+(4*36)+6+6+6+4+4)


/*
 * typedef struct {
 *       gint16      rid;
 *       gint16      rlen;
 *       Summary     s;
 *       } LA_SummaryRecord;
 */

#define LA_SummaryRecordSize (SummarySize + 4)


/*
 * typedef struct {
 *       gint16      rid;
 *       gint16      rlen;
 *       gint16      seqno;
 *       gint32      totpktf;
 *       } LA_SubfileSummaryRecord;
 */

#define LA_SubfileSummaryRecordSize 10


#define LA_IndexSize 500

/*
 * typedef struct {
 *       gint16      rid;
 *       gint16      rlen;
 *       gint16      idxsp;                    = LA_IndexSize
 *       gint16      idxct;
 *       gint8       idxgranu;
 *       gint8       idxvd;
 *       gint32      trcidx[LA_IndexSize + 2]; +2 undocumented but used by La 2.2
 *       } LA_IndexRecord;
 */

#define LA_IndexRecordSize (10 + 4 * (LA_IndexSize + 2))

/*
 * typedef struct {
 *       gint16      rid;
 *       gint16      rlen;
 *       } LA_RecordHeader;
 */

#define LA_RecordHeaderSize 4

typedef struct {
      gboolean        init;
      struct timeval  start;
      guint32         pkts;
      int             encap;
      int             lastlen;
      } LA_TmpInfo;

int         lanalyzer_open(wtap *wth, int *err, gchar **err_info);
gboolean    lanalyzer_dump_open(wtap_dumper *wdh, int *err);
int         lanalyzer_dump_can_write_encap(int encap);

#endif
