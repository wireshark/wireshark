/* packet-rtps.c
 * Routines for Real-Time Publish-Subscribe Protocol (RTPS) dissection
 *
 * Copyright 2003, LUKAS POKORNY <maskis@seznam.cz>
 *                 PETR SMOLIK   <petr.smolik@wo.cz>
 *                 ZDENEK SEBEK  <sebek@fel.cvut.cz>
 * 
 * Czech Technical University in Prague 
 *  Faculty of Electrical Engineering <www.fel.cvut.cz>
 *  Department of Control Engineering <dce.felk.cvut.cz>                
 *                   
 * version: 2004/04/15 9:40:45
 * dedication to Kj :]
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-udp.c, packet-tftp.c, packet-x25.c
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * *********************************************************************** */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include  <stdio.h>
#include  <stdlib.h>
#include  <string.h>
#include  <glib.h>
#include  <epan/packet.h>
#include  <epan/addr_resolv.h>
#include  <epan/conversation.h>
#include  <epan/emem.h>


/* *********************************************************************** *
   RTPS protocol was developed by Real Time Innovation, Inc.

   Protocol specifikation and documenation you can find on these addresses:

   http://www.rti.com/

   http://www.rti.com/products/ndds/literature.html

   http://www.schneider-electric.com.au/Products/Automation/TF_RealTime/
         /technical%20library/specifications/WireProtocolExternal.pdf


 * *********************************************************************** */



/* redefine types because of definitions in 'packet-rtps.h' */
/*
#define  u_int8_t           guint8
#define  int8_t             gint8

#define  u_int16_t          guint16
#define  int16_t            gint16

#define  u_int32_t          guint32
#define  int32_t            gint32
*/

#include "packet-rtps.h"

/* number of APP_KIND byte in packet header */
#define  APP_KIND_BYTE          15


/*  definitions of flags */
#define    FLAG_E      0x01
#define    FLAG_F      0x02
#define    FLAG_I      0x02
#define    FLAG_M      0x02
#define    FLAG_P      0x02
#define    FLAG_A      0x04
#define    FLAG_H      0x08


/*  submessageId's ranges  */
#define  SUBMSG_ID_MIN     PAD
#define  SUBMSG_ID_MAX     INFO_DST

/*  Vendor specific submessageId's ranges */
#define  VENDOR_SUBMSG_ID_MIN      0x80
#define  VENDOR_SUBMSG_ID_MAX      0xff

/* *********************************************************************** */


/*  initialize the protocol and registered fields  */
static int proto_rtps                    = -1;
static int hf_rtps_submessage_id         = -1;
static int hf_rtps_submessage_flags      = -1;
static int hf_rtps_octets_to_next_header = -1;
static int hf_rtps_parameter_id          = -1;
static int hf_rtps_parameter_length      = -1;
static int hf_rtps_issue_data            = -1;

/*  Initialize the subtree pointers */
static gint ett_rtps                     = -1;
static gint ett_rtps_submessage          = -1;
static gint ett_rtps_bitmap              = -1;
static gint ett_rtps_parameter_sequence  = -1;
static gint ett_rtps_parameter           = -1;

/*  Functions declarations */
static void dissect_PAD(tvbuff_t *tvb,gint offset,guint8 flags,
                        int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);
static void dissect_VAR(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);
static void dissect_ISSUE(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);
static void dissect_ACK(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);
static void dissect_HEARTBEAT(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);
static void dissect_GAP(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);
static void dissect_INFO_TS(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);
static void dissect_INFO_SRC(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);
static void dissect_INFO_REPLY(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);
static void dissect_INFO_DST(tvbuff_t *tvb,gint offset,guint8 flags,
                        int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);

static guint16  get_guint16(tvbuff_t *tvb, gint offset, gboolean little_endian);
static guint32  get_guint32(tvbuff_t *tvb, gint offset, gboolean little_endian);

static char *protocol_version_to_string(gint offset,tvbuff_t *tvb,char *buff,int buff_len);
static char *vendor_id_to_string(gint offset, tvbuff_t *tvb, char *buff, int buff_len);

static char *host_id_to_string(gint offset,tvbuff_t *tvb, char *buff, int buff_len);
static char *app_id_to_string(gint offset,tvbuff_t *tvb,char *buff,int buff_len);
static char *object_id_to_string(gint offset, tvbuff_t *tvb, char *buff, int buff_len);

static char *IP_to_string(gint offset,tvbuff_t *tvb,gboolean little_endian,char *buff, int buff_len);
static char *port_to_string(gint offset,tvbuff_t *tvb,gboolean little_endian,char *buff, int buff_len);
static char *get_NtpTime(gint offset,tvbuff_t *tvb,gboolean little_endian,char *buff, int buff_len);

static void  get_bitmap(tvbuff_t *tvb, gint *p_offset, gboolean little_endian,
                        gint next_submsg, proto_tree *tree);

static void  get_parameter_sequence(tvbuff_t *tvb, gint *p_offset,
                                    gboolean little_endian,
                                    gint next_submsg_offset, proto_tree *tree);

static gint  seq_nr_to_string( gint offset, gboolean little_endian, tvbuff_t *tvb,
                             SequenceNumber *p_seqNumber);

static const value_string submessage_id_vals[] = {
  { PAD, "PAD" },
  { VAR, "VAR" },
  { ISSUE, "ISSUE" },
  { ACK, "ACK" },
  { HEARTBEAT, "HEARTBEAT" },
  { GAP, "GAP" },
  { INFO_TS, "INFO_TS" },
  { INFO_SRC, "INFO_SRC" },
  { INFO_REPLY, "INFO_REPLY" },
  { INFO_DST, "INFO_DST" },
  { APP_QUIT, "APP_QUIT" },
  { 0, NULL }
};

static const value_string parameter_id_vals[] = {
  { PID_PAD, "PID_PAD" },
  { PID_SENTINEL, "PID_SENTINEL" },
  { PID_EXPIRATION_TIME, "PID_EXPIRATION_TIME" },
  { PID_PERSISTENCE, "PID_PERSISTENCE" },
  { PID_MINIMUM_SEPARATION, "PID_MINIMUM_SEPARATION" },
  { PID_TOPIC, "PID_TOPIC" },
  { PID_STRENGTH, "PID_STRENGTH" },
  { PID_TYPE_NAME, "PID_TYPE_NAME" },
  { PID_TYPE_CHECKSUM, "PID_TYPE_CHECKSUM" },
  { RTPS_PID_TYPE2_NAME, "RTPS_PID_TYPE2_NAME" },
  { RTPS_PID_TYPE2_CHECKSUM, "RTPS_PID_TYPE2_CHECKSUM" },
  { PID_METATRAFFIC_MULTICAST_IPADDRESS, "PID_METATRAFFIC_MULTICAST_IPADDRESS" },
  { PID_APP_IPADDRESS, "PID_APP_IPADDRESS" },
  { PID_METATRAFFIC_UNICAST_PORT, "PID_METATRAFFIC_UNICAST_PORT" },
  { PID_USERDATA_UNICAST_PORT, "PID_USERDATA_UNICAST_PORT" },
  { PID_IS_RELIABLE, "PID_IS_RELIABLE" },
  { PID_EXPECTS_ACK, "PID_EXPECTS_ACK" },
  { PID_USERDATA_MULTICAST_IPADDRESS, "PID_USERDATA_MULTICAST_IPADDRESS" },
  { PID_MANAGER_KEY, "PID_MANAGER_KEY" },
  { PID_SEND_QUEUE_SIZE, "PID_SEND_QUEUE_SIZE" },
  { PID_RELIABILITY_ENABLED, "PID_RELIABILITY_ENABLED" },
  { PID_PROTOCOL_VERSION, "PID_PROTOCOL_VERSION" },
  { PID_VENDOR_ID, "PID_VENDOR_ID" },
  { PID_VARGAPPS_SEQUENCE_NUMBER_LAST, "PID_VARGAPPS_SEQUENCE_NUMBER_LAST" },
  { PID_RECV_QUEUE_SIZE, "PID_RECV_QUEUE_SIZE" },
  { PID_RELIABILITY_OFFERED, "PID_RELIABILITY_OFFERED" },
  { PID_RELIABILITY_REQUESTED, "PID_RELIABILITY_REQUESTED" },
  { 0, NULL }
};

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                  Code to actually dissect the packets                   *
 *                                                                         *
 * *********************************************************************** */

static gboolean
dissect_rtps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item       *ti;
  proto_tree       *rtps_tree=NULL;
  gint             offset = 0;
  gint             appKind;
  proto_tree       *rtps_submessage_tree;
  guint8           submessageId;
  guint8           flags;
  gboolean         little_endian;
  int              next_submsg;
  int              count_msg_type[11];
  char             *buff;
  int buff_len;

  buff=ep_alloc(200);
  buff[0]=0;
  /*  offset is the byte offset of 'tvb' at which the new tvbuff
      should start.  The first byte is the 0th byte.             */

  /* --- making disition if protocol is RTPS protocol --- */
  if (!tvb_bytes_exist(tvb, offset, 4)) return FALSE;
  if (tvb_get_guint8(tvb,offset++) != 'R') return FALSE;
  if (tvb_get_guint8(tvb,offset++) != 'T') return FALSE;
  if (tvb_get_guint8(tvb,offset++) != 'P') return FALSE;
  if (tvb_get_guint8(tvb,offset++) != 'S') return FALSE;

  /* --- Make entries in Protocol column ---*/
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTPS");

  if (check_col(pinfo->cinfo, COL_INFO))
   col_clear(pinfo->cinfo, COL_INFO);

  memset(count_msg_type, 0, sizeof(count_msg_type));

  if (tree) {

   /* create display subtree for the protocol */
   ti = proto_tree_add_item(tree, proto_rtps, tvb, 0, -1, FALSE);
   rtps_tree = proto_item_add_subtree(ti, ett_rtps);

   /*  Protocol Version */
   proto_tree_add_text(rtps_tree, tvb, offset, 2,
                       "Protocol  RTPS, version %s",
                       protocol_version_to_string(offset, tvb, buff, 200));
   offset +=2;

   /*  Vendor Id  */
   proto_tree_add_text(rtps_tree, tvb, offset, 2,
                       "VendorId: %s",
                       vendor_id_to_string(offset, tvb, buff, 200));
   offset +=2;

   /*  Host Id  */
   proto_tree_add_text(rtps_tree, tvb, offset, 4,
                       "HostId:   %s",
                       host_id_to_string(offset, tvb, buff, 200));
   offset +=4;

   /*  App Id  */
   proto_tree_add_text(rtps_tree, tvb, offset, 4,
                       "App ID:   %s",
                       app_id_to_string(offset, tvb, buff, 200));

  }

  /*  offset behind RTPS's Header */
  offset=16;

  while (tvb_reported_length_remaining(tvb, offset) > 0) {
    submessageId = tvb_get_guint8(tvb, offset);
    if (submessageId & 0x80) {
      ti = proto_tree_add_text(tree, tvb, offset, -1, "Submessage: %s",
                               val_to_str(submessageId, submessage_id_vals,
                                          "Vendor-specific (0x%02X)"));
    } else {
      ti = proto_tree_add_text(tree, tvb, offset, -1, "Submessage: %s",
                               val_to_str(submessageId, submessage_id_vals,
                                          "Unknown (0x%02X)"));
    }
    rtps_submessage_tree = proto_item_add_subtree(ti, ett_rtps_submessage);
    if (submessageId & 0x80) {
      proto_tree_add_uint_format(rtps_submessage_tree, hf_rtps_submessage_id,
                                 tvb, offset, 1, submessageId,
                                 "Submessage Id: Vendor-specific (0x%02x)",
                                 submessageId);
    } else {
      proto_tree_add_uint(rtps_submessage_tree, hf_rtps_submessage_id,
                          tvb, offset, 1, submessageId);
    }

    flags = tvb_get_guint8(tvb, offset + 1);
    /*  E flag |XXXX|HAPE| => masks with 000000001b = 1  */
    if ((flags & FLAG_E) != 0)      little_endian = TRUE;
      else                          little_endian = FALSE;

    next_submsg  = get_guint16(tvb, offset + 2, little_endian);
    proto_item_set_len(ti, next_submsg);

    switch (submessageId)
    {
      case PAD:
        if (tree)
          dissect_PAD(tvb, offset + 1, flags, next_submsg,
                      rtps_submessage_tree);
        count_msg_type[0]++;
        break;
      case VAR:
        if (tree)
          dissect_VAR(tvb, offset + 1, flags, little_endian, next_submsg,
                      rtps_submessage_tree);
        count_msg_type[1]++;
        break;
      case ISSUE:
        if (tree)
          dissect_ISSUE(tvb, offset + 1, flags, little_endian, next_submsg,
                        rtps_submessage_tree);
        count_msg_type[2]++;
        break;
      case ACK:
        if (tree)
          dissect_ACK(tvb, offset + 1, flags, little_endian, next_submsg,
                      rtps_submessage_tree);
        count_msg_type[3]++;
        break;
      case HEARTBEAT:
        if (tree)
          dissect_HEARTBEAT(tvb, offset + 1, flags, little_endian, next_submsg,
                            rtps_submessage_tree);
        count_msg_type[4]++;
        break;
      case GAP:
        if (tree)
          dissect_GAP(tvb, offset + 1, flags, little_endian, next_submsg,
                      rtps_submessage_tree);
        count_msg_type[5]++;
        break;
      case INFO_TS:
        if (tree)
          dissect_INFO_TS(tvb, offset + 1, flags, little_endian, next_submsg,
                          rtps_submessage_tree);
        count_msg_type[6]++;
        break;
      case INFO_SRC:
        if (tree)
          dissect_INFO_SRC(tvb, offset + 1, flags, little_endian, next_submsg,
                           rtps_submessage_tree);
        count_msg_type[7]++;
        break;
      case INFO_REPLY:
        if (tree)
          dissect_INFO_REPLY(tvb, offset + 1, flags, little_endian, next_submsg,
                             rtps_submessage_tree);
        count_msg_type[8]++;
        break;
      case INFO_DST:
        if (tree)
          dissect_INFO_DST(tvb, offset + 1, flags, next_submsg,
                           rtps_submessage_tree);
        count_msg_type[9]++;
        break;
      default:
        if (tree) {
          proto_tree_add_uint(rtps_submessage_tree, hf_rtps_submessage_flags,
                              tvb, offset + 1, 1, flags);
          proto_tree_add_uint(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                              tvb, offset + 2, 2, next_submsg);
        }
        break;
     }

     /* next submessage's offset */
     offset += next_submsg+4;

  }

  /* --- and Info column on summary display ---*/

  if (check_col(pinfo->cinfo, COL_INFO))
  {
    appKind = tvb_get_guint8(tvb, APP_KIND_BYTE);

    if (appKind == MANAGEDAPPLICATION ) {g_snprintf(buff, 200, "App: ");}
    if (appKind == MANAGER)             {g_snprintf(buff, 200, "Man: ");}
    if (appKind == AID_UNKNOWN)         {g_snprintf(buff, 200, "Unknown:");}

    if (appKind != MANAGEDAPPLICATION  && appKind != MANAGER &&
        appKind != AID_UNKNOWN)         {g_snprintf(buff, 200, "ERROR in APP type");}

   /* -- counts of submessages - for Information Frame */
   if (count_msg_type[0]>0) {
       buff_len=strlen(buff);
       g_snprintf(buff+buff_len, 200-buff_len, "PAD(%d) ",count_msg_type[0]);
   }

   if (count_msg_type[1]>0) {
       buff_len=strlen(buff);
       g_snprintf(buff+buff_len, 200-buff_len, "VAR(%d) ",count_msg_type[1]);
   }

   if (count_msg_type[2]>0) {
       buff_len=strlen(buff);
       g_snprintf(buff+buff_len, 200-buff_len, "ISSUE(%d) ",count_msg_type[2]);
   }

   if (count_msg_type[3]>0) {
       buff_len=strlen(buff);
       g_snprintf(buff+buff_len, 200-buff_len, "ACK(%d) ",count_msg_type[3]);
   }

   if (count_msg_type[4]>0) {
       buff_len=strlen(buff);
       g_snprintf(buff+buff_len, 200-buff_len, "HEARTBEAT(%d) ",count_msg_type[4]);
   }

   if (count_msg_type[5]>0) {
       buff_len=strlen(buff);
       g_snprintf(buff+buff_len, 200-buff_len, "GAP(%d) ",count_msg_type[5]);
   }

   if (count_msg_type[6]>0) {
       buff_len=strlen(buff);
       g_snprintf(buff+buff_len, 200-buff_len, "INFO_TS(%d) ",count_msg_type[6]);
   }

   if (count_msg_type[7]>0) {
       buff_len=strlen(buff);
       g_snprintf(buff+buff_len, 200-buff_len,  "INFO_SRC(%d) ",count_msg_type[7]);
   }

   if (count_msg_type[8]>0) {
       buff_len=strlen(buff);
       g_snprintf(buff+buff_len, 200-buff_len, "INFO_REPLY(%d) ",count_msg_type[8]);
   }

   if (count_msg_type[9]>0) {
       buff_len=strlen(buff);
       g_snprintf(buff+buff_len, 200-buff_len, "INFO_DST(%d) ",count_msg_type[9]);
   }

   if (count_msg_type[10]>0) {
       buff_len=strlen(buff);
       g_snprintf(buff+buff_len, 200-buff_len, "vendor specific(%d) ",count_msg_type[10]);
   }

   col_add_fstr(pinfo->cinfo, COL_INFO, buff);

  }


  return TRUE;

}  /* end dissect_rtps(...) */

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                        get 16 bit from the stream                       *
 *                                                                         *
 * *********************************************************************** */

static guint16  get_guint16(tvbuff_t *tvb, gint offset, gboolean little_endian)
{
  guint16   value;

  if (little_endian)
    value = tvb_get_letohs(tvb, offset);
  else
    value = tvb_get_ntohs(tvb, offset);

  return(value);
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                          get 32 bit from the stream                     *
 *                                                                         *
 * *********************************************************************** */

static guint32  get_guint32(tvbuff_t *tvb, gint offset, gboolean little_endian)
{
  guint32     value;

  if (little_endian)
    value = tvb_get_letohl(tvb, offset);
  else
    value = tvb_get_ntohl(tvb, offset);

  return(value);
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                               get Protocol version                      *
 *                                                                         *
 * *********************************************************************** */

static char *
protocol_version_to_string(gint offset,tvbuff_t *tvb,char *buff, int buff_len)
{
  guint8            major, minor;

  /* protocol verzion = major.minor */
   major = tvb_get_guint8(tvb, offset);
   minor = tvb_get_guint8(tvb, (offset+1));

   g_snprintf(buff, buff_len, "%d.%d", major, minor);
   return(buff);

}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                               get Vendor Id                             *
 *                                                                         *
 * *********************************************************************** */

static char *
vendor_id_to_string(gint offset, tvbuff_t *tvb, char *buff, int buff_len)
{
  guint8              major, minor;
  VendorId            vendorId_rti;

  VENDOR_ID_RTI(vendorId_rti);

  major = tvb_get_guint8(tvb, offset);
  minor = tvb_get_guint8(tvb, (offset+1));

  if (major == vendorId_rti.major &&
      minor == vendorId_rti.minor)
  { g_snprintf(buff, buff_len, "Real-Time Innovations,Inc.,CA,USA");
    return(buff); }

  g_snprintf(buff, buff_len, "Vendor unknown");
  return(buff);
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                               get IP Address                            *
 *                                                                         *
 * *********************************************************************** */

static char *
IP_to_string(gint offset,tvbuff_t *tvb,gboolean little_endian,char *buff, int buff_len)
{
  IPAddress         ip;
  guint8  a = 0, b = 0, c = 0, d = 0; /* IP Address = a.b.c.d */

  ip = get_guint32(tvb, offset, little_endian);
     /* get_guint32() - reads + endian conversion */
  a = (ip >> 24);
  b = (ip >> 16) & 0xff;
  c = (ip >>  8) & 0xff;
  d =  ip & 0xff;

  g_snprintf(buff, buff_len, "%d.%d.%d.%d", a, b, c, d);
  return(buff);
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                               get Port                                  *
 *                                                                         *
 * *********************************************************************** */

static char *
port_to_string(gint offset,tvbuff_t *tvb,gboolean little_endian,char *buff, int buff_len)
{
  Port port = get_guint32(tvb, offset, little_endian);
            /* get_guint32() - reads + endian conversion */

  if (port == PORT_INVALID)
    g_snprintf(buff, buff_len, "PORT_INVALID");
  else
    g_snprintf(buff, buff_len, "0x%X",port);

  return(buff);
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                                get NTP Time                             *
 *                                                                         *
 * *********************************************************************** */

static char *
get_NtpTime(gint offset,tvbuff_t *tvb,gboolean little_endian,char *buff, int buff_len)
{
  NtpTime         ntpTime;
  float           time;

  /* get_guint32() - reads + endian conversion */
  ntpTime.seconds  =  get_guint32(tvb, offset, little_endian);
  ntpTime.fraction =  get_guint32(tvb, (offset + 4), little_endian);
  time = (float) ntpTime.seconds + (ntpTime.fraction / 2^(32));

  g_snprintf(buff, buff_len, "%f", time);
  return(buff);
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                                get Host Id                              *
 *                                                                         *
 * *********************************************************************** */

static char *
host_id_to_string(gint offset,tvbuff_t *tvb, char *buff, int buff_len)
{
  guint32       hostId = tvb_get_ntohl(tvb, offset);
  /* get_ntohl() automaticaly convert data to BIG ENDIAN */

  g_snprintf(buff, buff_len, "0x%X", hostId);
  return(buff);
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                                get AppID                                *
 *                                                                         *
 * *********************************************************************** */

static char *
app_id_to_string(gint offset,tvbuff_t *tvb,char *buff, int buff_len)
{
  guint32        appId = tvb_get_ntohl(tvb, offset);
  /* get_ntohl() automaticaly convert data to BIG ENDIAN */

  /* Instance Id */
  guint32        instanceId = (appId >> 8);
  /* applicatin Kind */
  guint8         appKind    = (appId & 0xff);

  if (appKind == MANAGEDAPPLICATION)
  {
    g_snprintf(buff, buff_len, "Managed App, InstanceId: 0x%X",instanceId);
    return(buff);
  }

  if (appKind == MANAGER)
  {
    g_snprintf(buff, buff_len, "Manager, InstanceId: 0x%X",instanceId);
    return(buff);
  }

  g_snprintf(buff, buff_len, "Unknown");
  return(buff);

}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                         get Object_Id (32 bit)                          *
 *                                                                         *
 * *********************************************************************** */

static char *
object_id_to_string(gint offset, tvbuff_t *tvb, char *buff, int buff_len)
{
  guint32        objectId = tvb_get_ntohl(tvb, offset);
  /* get_ntohl() automaticaly convert data to BIG ENDIAN */

  if (objectId == OID_UNKNOWN)      { g_snprintf(buff, buff_len, "Unknown ObjectId");
                                      return(buff);}
  if (objectId == OID_APP)          { g_snprintf(buff, buff_len, "applicationSelf");
                                      return(buff);}
  if (objectId == OID_WRITE_APPSELF){ g_snprintf(buff, buff_len, "writerApplicationSelf");
                                      return(buff);}
  if (objectId == OID_WRITE_APP)    { g_snprintf(buff, buff_len, "writerApplications");
                                      return(buff);}
  if (objectId == OID_READ_APP)     { g_snprintf(buff, buff_len, "readerApplications");
                                      return(buff);}
  if (objectId == OID_WRITE_MGR)    { g_snprintf(buff, buff_len, "writerManagers");
                                      return(buff);}
  if (objectId == OID_READ_MGR)     { g_snprintf(buff, buff_len, "readerManagers ");
                                      return(buff);}
  if (objectId == OID_WRITE_PUBL)   { g_snprintf(buff, buff_len, "writerPublications");
                                      return(buff);}
  if (objectId == OID_READ_PUBL)    { g_snprintf(buff, buff_len, "readerPublications");
                                      return(buff);}
  if (objectId == OID_WRITE_SUBS)   { g_snprintf(buff, buff_len, "writerSubscriptions");
                                      return(buff);}
  if (objectId == OID_READ_SUBS)    { g_snprintf(buff, buff_len, "readerSubscriptions");
                                      return(buff);}

  /* nothing from the possibilites above */
  g_snprintf(buff, buff_len, "instanceId: 0x%X, objKind: 0x%X",
               (objectId >> 8),(objectId & 0xff));
  return(buff);

/* for the future
//Kind
#define OID_APPLICATION      0x01
#define OID_CSTWRITER        0x02
#define OID_PUBLICATION      0x03
#define OID_SUBSCRIPTION     0x04
#define OID_CSTREADER        0x07
//
#define OID_USEROBJ          0x00
#define OID_RESUSEROBJ       0x40
#define OID_METAOBJ          0x80
#define OID_RESMETAOBJ       0xC0
*/
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                      get Sequence Number (64 bit)                       *
 *                                                                         *
 * *********************************************************************** */

static gint
seq_nr_to_string(gint offset, gboolean little_endian, tvbuff_t *tvb,
                 SequenceNumber *p_seqNumber)
{
   p_seqNumber->high = get_guint32(tvb, offset, little_endian);
   p_seqNumber->low  = get_guint32(tvb, offset + 4, little_endian);

   return(1);
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                                get_Bitmap                               *
 *                                                                         *
 * *********************************************************************** */

static void
get_bitmap(tvbuff_t *tvb, gint *p_offset, gboolean little_endian,
           gint next_submsg, proto_tree *tree)
{
  proto_item             *ti;
  proto_tree             *rtps_bitmap_tree;
  gint                    i = 0;
  gint                    offset = *p_offset;
  SequenceNumber          sequenceNumber;
  guint32                 num_bits;
  guint                   num_longs;

  /* making subtree for the bitmap */
  ti = proto_tree_add_text(tree,tvb,offset,(next_submsg-offset),"Bitmap");
  rtps_bitmap_tree = proto_item_add_subtree(ti, ett_rtps_bitmap);

  /* SekvenceNumber bitmapBase */
  seq_nr_to_string(offset, little_endian, tvb, &sequenceNumber);
  proto_tree_add_text(rtps_bitmap_tree, tvb, offset, 8,
                      "bitmapBase:  0x%X%X",
                      sequenceNumber.high, sequenceNumber.low);
  offset +=8;

  num_bits = get_guint32(tvb, offset, little_endian);
  proto_tree_add_text(rtps_bitmap_tree, tvb, offset, 4,
                      "numBits:     %u",
                      num_bits);
  offset += 4;

  if (num_bits+31 < num_bits)
    num_longs = UINT_MAX; /* overflow */
  else
    num_longs = (num_bits+31)/32;
  while (num_longs != 0)
  {
    if (next_submsg-offset < 4)
    {
      proto_tree_add_text(rtps_bitmap_tree, tvb, offset, next_submsg-offset,
                          "bitmap[%d]:   < 4 bytes remain in message", i);
      offset = next_submsg;
      break;
    }
    proto_tree_add_text(rtps_bitmap_tree, tvb, offset, 4,
                        "bitmap[%d]:   0x%08X",
                        i, get_guint32(tvb, offset, little_endian));
    offset +=4;
    ++i;
    --num_longs;
  }  /* end while */

  *p_offset = offset;
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                          dissect submessage: PAD                        *
 *                                                                         *
 *           (this submessage has no meaning and it is always valid)       *
 * *********************************************************************** */

static void
dissect_PAD(tvbuff_t *tvb, gint offset, guint8 flags,
            int next_submsg_offset, proto_tree *rtps_submessage_tree)
{
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, flags);
  offset += 1;

  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                      tvb, offset, 2, next_submsg_offset);
  offset +=2;
  next_submsg_offset += offset;
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                          dissect submessage: VAR                        *
 *                                                                         *
 * *********************************************************************** */

static void
dissect_VAR(tvbuff_t *tvb, gint offset, guint8 flags, gboolean little_endian,
            int next_submsg_offset, proto_tree *rtps_submessage_tree)
{
  int                min_len;
  char               *buff;
  SequenceNumber     writerSeqNumber;

  buff=ep_alloc(200);
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, flags);
  offset +=1;

  min_len = 20;
  if ((flags & FLAG_H) != 0)
    min_len += 8;
  if ((flags & FLAG_P) != 0)
    min_len += 4;
  if (next_submsg_offset < min_len)
  {
    proto_tree_add_uint_format(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                               tvb, offset, 2, next_submsg_offset,
                               "Octets to next header: %u (bogus, must be >= %u)",
                               next_submsg_offset, min_len);
    return;
  }
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                      tvb, offset, 2, next_submsg_offset);
  offset +=2;
  next_submsg_offset += offset;

  /*  readerObjectId*/
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Reader Object ID:   %s ",
                       object_id_to_string(offset, tvb, buff, 200));
  offset +=4;

  /*  writerObjectId*/
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Writer Object ID:   %s ",
                      object_id_to_string(offset, tvb, buff, 200));
  offset+=4;

  /*  H flag |XXXX|HAPE| => masks with 00001000b = 8 */
  if ((flags & FLAG_H) != 0)
  {
    /*  HostId */
    proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                        "Host ID:            %s",
                        host_id_to_string(offset, tvb, buff, 200));
    offset+=4;

    /*  App Id  */
    proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                        "App ID:             %s",
                        app_id_to_string(offset, tvb, buff, 200));
    offset +=4;
  }

  /* Object Id */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Object ID:          %s ",
                      object_id_to_string(offset, tvb, buff, 200));
  offset +=4;

  /*  WriterSequence Number */
  seq_nr_to_string(offset, little_endian, tvb, &writerSeqNumber);
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 8,
                      "WriterSeqNumber:    0x%X%X",
                      writerSeqNumber.high, writerSeqNumber.low);
  offset +=8;

  /*  P flag |XXXX|HAPE| => masks with 00000010b = 2 */
  if ((flags & FLAG_P) != 0)
  {
    get_parameter_sequence(tvb, &offset, little_endian, next_submsg_offset,
                           rtps_submessage_tree);
  }
}

/* *********************************************************************** */

/* *********************************************************************** *
 *                                                                         *
 *                            get_ParameterSequence                        *
 *                                                                         *
 * *********************************************************************** */


static void
get_parameter_sequence(tvbuff_t *tvb, gint *p_offset, gboolean little_endian,
                       gint next_submsg_offset, proto_tree *tree)
{
  proto_item             *ti;
  proto_tree             *rtps_parameter_sequence_tree;
  proto_tree             *rtps_parameter_tree;
  gint                    offset = *p_offset;
  guint16                 parameter, param_length;
  gint                    str_length;
  SequenceNumber          seqNumber;
  char                    *buff_tmp;
  int                     i;
  char                    sep;

  buff_tmp=ep_alloc(MAX_PATHNAME);

  ti = proto_tree_add_text(tree, tvb, offset, (next_submsg_offset - offset),
                      "Parameters:");
  rtps_parameter_sequence_tree = proto_item_add_subtree(ti,
                                                        ett_rtps_parameter_sequence);
  for (;;)
  {
    if (next_submsg_offset-offset < 2)
    {
      proto_tree_add_text(rtps_parameter_sequence_tree, tvb, offset,
                          next_submsg_offset-offset,
                          "Parameter: < 2 bytes remain in message");
      offset = next_submsg_offset;
      break;
    }
    parameter    = get_guint16(tvb, offset, little_endian);
    ti = proto_tree_add_text(rtps_parameter_sequence_tree, tvb, offset, 2,
                             "%s",
                             val_to_str(parameter, parameter_id_vals,
                                        "Unknown parameter (0x%04X)"));
    rtps_parameter_tree = proto_item_add_subtree(ti, ett_rtps_parameter);
    proto_tree_add_uint(rtps_parameter_tree, hf_rtps_parameter_id,
                        tvb, offset, 2, parameter);
    offset +=2;
    if (next_submsg_offset-offset < 2)
    {
      proto_tree_add_text(rtps_parameter_tree, tvb, offset,
                          next_submsg_offset-offset,
                          "Parameter length: < 2 bytes remain in message");
      offset = next_submsg_offset;
      proto_item_set_end(ti, tvb, offset);
      break;
    }
    param_length = get_guint16(tvb, offset, little_endian);
    proto_tree_add_uint(rtps_parameter_tree, hf_rtps_parameter_length,
                        tvb, offset, 2, param_length);
    offset +=2;

    if (parameter == PID_SENTINEL) {
      proto_item_set_end(ti, tvb, offset);
      break;
    }

    if (next_submsg_offset-offset < param_length)
    {
      proto_tree_add_text(rtps_parameter_tree, tvb, offset,
                          next_submsg_offset-offset,
                          "Parameter value: < %u bytes remain in message",
                          param_length);
      offset = next_submsg_offset;
      proto_item_set_end(ti, tvb, offset);
      break;
    }
    proto_item_set_end(ti, tvb, offset + param_length);

    switch (parameter)
    {
      case PID_PAD:
        proto_item_append_text(ti, ": -");
        proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                            "Padding");
        break;

      case PID_EXPIRATION_TIME:
      	if (param_length < 8)
      	{
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: length < 8");
        }
        else
        {
          char *ntp_time_str;

          ntp_time_str = get_NtpTime(offset, tvb, little_endian, buff_tmp, MAX_PATHNAME);
          proto_item_append_text(ti, ": %s", ntp_time_str);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Expiration time: %s", ntp_time_str);
        }
        break;

      case PID_PERSISTENCE:
      	if (param_length < 8)
      	{
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: length < 8");
        }
        else
        {
          char *ntp_time_str;

          ntp_time_str = get_NtpTime(offset, tvb, little_endian, buff_tmp, MAX_PATHNAME);
          proto_item_append_text(ti, ": %s", ntp_time_str);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Persistence: %s", ntp_time_str);
        }
        break;

      case PID_MINIMUM_SEPARATION:
      	if (param_length < 8)
      	{
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: length < 8");
        }
        else
        {
          char *ntp_time_str;

          ntp_time_str = get_NtpTime(offset, tvb, little_endian, buff_tmp, MAX_PATHNAME);
          proto_item_append_text(ti, ": %s", ntp_time_str);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Minimum separation: %s", ntp_time_str);
        }
        break;

      case PID_TOPIC: /* --- ?? funguje spravne ?? */
        str_length = tvb_strnlen(tvb, offset, param_length);
        if (str_length == -1)
        {
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: Terminating zero missing");
        }
        else
        {
          char *str;

          str = tvb_format_text(tvb, offset, str_length);
          proto_item_append_text(ti, ": %s", str);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Topic: %s", str);
        }
        break;   

      case PID_STRENGTH:
      	if (param_length < 4)
      	{
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: length < 4");
        }
        else
        {
          guint32 strength;

          strength = get_guint32(tvb, offset, little_endian);
          proto_item_append_text(ti, ": 0x%X", strength);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Strength: 0x%X", strength);
        }
        break;

      case PID_TYPE_NAME: /* --- ?? funguje spravne ?? */
        str_length = tvb_strnlen(tvb, offset, param_length);
        if (str_length == -1)
        {
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: Terminating zero missing");
        }
        else
        {
          char *str;

          str = tvb_format_text(tvb, offset, str_length);
          proto_item_append_text(ti, ": %s", str);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Type name: %s", str);
        }
        break;   

      case PID_TYPE_CHECKSUM:
        /* nacitam jako UNSIGNED - nemuze to byt i zaporne cislo?? */
      	if (param_length < 4)
      	{
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: length < 4");
        }
        else
        {
          guint32 checksum;

          checksum = get_guint32(tvb, offset, little_endian);
          proto_item_append_text(ti, ": 0x%X", checksum);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Checksum: 0x%X", checksum);
        }
        break;

      case RTPS_PID_TYPE2_NAME:
        proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                            "Parameter data");
        break;
                          
      case RTPS_PID_TYPE2_CHECKSUM:
        proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                            "Parameter data");
        break;

      case PID_METATRAFFIC_MULTICAST_IPADDRESS:
        i = 0;
        sep = ':';
        while (param_length >= 4)
      	{
      	  char *ip_string;

          ip_string = IP_to_string(offset, tvb, little_endian, buff_tmp, MAX_PATHNAME);
          proto_item_append_text(ti, "%c %s", sep, ip_string);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Address[%d]: %s", i, ip_string);
          ++i;
          offset +=4;
          sep = ',';
          param_length -= 4; /* decrement count */       
        }
        offset += param_length;
        break;

      case PID_APP_IPADDRESS:
        i = 0;
        sep = ':';
        while (param_length >= 4)
      	{
      	  char *ip_string;

          ip_string = IP_to_string(offset, tvb, little_endian, buff_tmp, MAX_PATHNAME);
          proto_item_append_text(ti, "%c %s", sep, ip_string);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Address[%d]: %s", i, ip_string);
          ++i;
          offset +=4;
          sep = ',';
          param_length -= 4; /* decrement count */       
        }
        offset += param_length;
        break;

      case PID_METATRAFFIC_UNICAST_PORT:
      	if (param_length < 4)
      	{
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: length < 4");
        }
        else
        {
          char *port_str;

          port_str = port_to_string(offset, tvb, little_endian, buff_tmp, MAX_PATHNAME);
          proto_item_append_text(ti, ": %s", port_str);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Port: %s", port_str);
        }
        break;

      case PID_USERDATA_UNICAST_PORT:
      	if (param_length < 4)
      	{
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: length < 4");
        }
        else
        {
          char *port_str;

          port_str = port_to_string(offset, tvb, little_endian, buff_tmp, MAX_PATHNAME);
          proto_item_append_text(ti, ": %s", port_str);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Port: %s", port_str);
        }
        break;

      case PID_EXPECTS_ACK:
      	if (param_length < 1)
      	{
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: length < 1");
        }
        else
        {
          if (tvb_get_guint8(tvb, offset) == 0)
          {
            proto_item_append_text(ti, ": No");
            proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                                "ACK expected: No");
          }
          else
          {
            proto_item_append_text(ti, ": Yes");
            proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                                "ACK expected: Yes");
          }
        }
        break;

      case PID_USERDATA_MULTICAST_IPADDRESS:
        i = 0;
        sep = ':';
        while (param_length >= 4)
      	{
      	  char *ip_string;

          ip_string = IP_to_string(offset, tvb, little_endian, buff_tmp, MAX_PATHNAME);
          proto_item_append_text(ti, "%c %s", sep, ip_string);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Address[%d]: %s", i, ip_string);
          ++i;
          offset +=4;
          param_length -= 4; /* decrement count */       
        }
        offset += param_length;
        break;

      case PID_MANAGER_KEY:
        i = 0;
        sep = ':';
        while (param_length >= 4)
      	{
      	  guint32 manager_key;

          manager_key = get_guint32(tvb, offset, little_endian);
          proto_item_append_text(ti, "%c 0x%X", sep, manager_key);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Key[%d]: 0x%X", i, manager_key);
          ++i;
          offset +=4;
          sep = ',';
          param_length -= 4; /* decrement count */       
        }
        offset += param_length;
        break;

      case PID_SEND_QUEUE_SIZE:
      	if (param_length < 4)
      	{
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: length < 4");
        }
        else
        {
          guint32 send_queue_size;

          send_queue_size = get_guint32(tvb, offset, little_endian);
          proto_item_append_text(ti, ": %u", send_queue_size);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Send queue size: %u", send_queue_size);
        }
        break;

      case PID_PROTOCOL_VERSION:
      	if (param_length < 2)
      	{
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: length < 2");
        }
        else
        {
          char *protocol_version_str;

          protocol_version_str = protocol_version_to_string(offset, tvb, buff_tmp, MAX_PATHNAME);
          proto_item_append_text(ti, ": %s", protocol_version_str);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Protocol version: %s", protocol_version_str);
        }
        break;

      case PID_VENDOR_ID:
      	if (param_length < 2)
      	{
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: length < 2");
        }
        else
        {
          char *vendor_id_str;

          vendor_id_str = vendor_id_to_string(offset, tvb, buff_tmp, MAX_PATHNAME);
          proto_item_append_text(ti, ": %s", vendor_id_str);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Vendor ID: %s", vendor_id_str);
        }
        break;

      case PID_VARGAPPS_SEQUENCE_NUMBER_LAST:
      	if (param_length < 8)
      	{
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: length < 8");
        }
        else
        {
          seq_nr_to_string(offset, little_endian, tvb, &seqNumber);
          proto_item_append_text(ti, ": 0x%X%X",
                                 seqNumber.high, seqNumber.low);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Sequence number: 0x%X%X",
                              seqNumber.high, seqNumber.low);
        }
        break;

      case PID_RECV_QUEUE_SIZE:
      	if (param_length < 4)
      	{
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: length < 4");
        }
        else
        {
          guint32 recv_queue_size;

          recv_queue_size = get_guint32(tvb, offset, little_endian);
          proto_item_append_text(ti, ": %u", recv_queue_size);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Receive queue size: %u", recv_queue_size);
        }
        break;

      case PID_RELIABILITY_OFFERED:
        if (param_length < 4)
        {
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: length < 4");
        }
        else
        {
          guint32 reliability_offered;

          reliability_offered = get_guint32(tvb, offset, little_endian);
          proto_item_append_text(ti, ": 0x%X", reliability_offered);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Reliability offered: 0x%X", reliability_offered);
        }
        break;

      case PID_RELIABILITY_REQUESTED:
        if (param_length < 4)
        {
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Bad parameter: length < 4");
        }
        else
        {
          guint32 reliability_requested;

          reliability_requested = get_guint32(tvb, offset, little_endian);
          proto_item_append_text(ti, ": 0x%X", reliability_requested);
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                              "Reliability requested: 0x%X", reliability_requested);
        }
        break;

      default:
        proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                            "Unknown parameter value");
        break;
    }   /* end switch */

    offset += param_length;
  }

  *p_offset = offset;
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                  subdissector for submessage: ISSUE                     *
 *                                                                         *
 * *********************************************************************** */
 /* hotovo 12.01.04 - JEN OTESTOVAT :] */
static void
dissect_ISSUE(tvbuff_t *tvb, gint offset, guint8 flags,
              gboolean little_endian, int next_submsg_offset,
              proto_tree *rtps_submessage_tree)
{
  int                       min_len;
  char                      *buff;
  SequenceNumber            sequenceNumber;      /*  type struct  */

  buff=ep_alloc(40);
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, flags);
  offset +=1;

  min_len = 16;
  if ((flags & FLAG_P) != 0)
    min_len += 4;
  if (next_submsg_offset < min_len)
  {
    proto_tree_add_uint_format(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                               tvb, offset, 2, next_submsg_offset,
                               "Octets to next header: %u (bogus, must be >= %u)",
                               next_submsg_offset, min_len);
    return;
  }
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                      tvb, offset, 2, next_submsg_offset);
  offset +=2;
  next_submsg_offset += offset;

  /*  Reader Object ID  */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Reader Object ID: %s ",
                      object_id_to_string(offset, tvb, buff, 40));
  offset +=4;

  /*  Writer Object ID */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Writer Object ID: %s ",
                      object_id_to_string(offset, tvb, buff, 40));
  offset +=4;

  /*  Sequence Number */
  seq_nr_to_string(offset, little_endian, tvb, &sequenceNumber);
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 8,
                      "firstSeqNumber:   0x%X%X",
                      sequenceNumber.high, sequenceNumber.low);
  offset += 8;

  /*  Parameters */
/* *********************************************************************** *
 *              - for future extension of the protocol - in                *
 *                implementation of RTPS 1.0 can ignore the content        *
 * *********************************************************************** */

  /* -- P flag |XXXX|HAPE| => masks with 00000010b = 2 */
  if ((flags & FLAG_P) != 0)
  {
    get_parameter_sequence(tvb, &offset, little_endian, next_submsg_offset,
                           rtps_submessage_tree);
  }

  /*  Issue Data */
  proto_tree_add_item(rtps_submessage_tree, hf_rtps_issue_data, tvb,
                      offset, (next_submsg_offset - offset), FALSE);

}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                  subdissector for submessage: ACK                       *
 *                                                                         *
 * *********************************************************************** */
 /* hotovo 12.01.04 - JEN OTESTOVAT :] */
static void
dissect_ACK(tvbuff_t *tvb, gint offset, guint8 flags,
            gboolean little_endian, int next_submsg_offset,
            proto_tree *rtps_submessage_tree)
{
  char *buff;

  buff=ep_alloc(40);
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, flags);
  offset +=1;

  if (next_submsg_offset < 20)
  {
    proto_tree_add_uint_format(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                               tvb, offset, 2, next_submsg_offset,
                               "Octets to next header: %u (bogus, must be >= 20)",
                               next_submsg_offset);
    return;
  }
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                      tvb, offset, 2, next_submsg_offset);
  offset +=2;
  next_submsg_offset += offset;

  /*  Reader Object ID  */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Reader Object ID:   %s ",
                      object_id_to_string(offset, tvb, buff, 40));
  offset +=4;

  /*  Writer Object ID  */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Writer Object ID:   %s ",
                      object_id_to_string(offset, tvb, buff, 40));
  offset +=4;

  get_bitmap(tvb,&offset,little_endian,next_submsg_offset,rtps_submessage_tree);

}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                subdissector for submessage: HEARTBEAT                   *
 *                                                                         *
 * *********************************************************************** */
 /* hotovo 12.01.04 - JEN OTESTOVAT :] */
static void
dissect_HEARTBEAT(tvbuff_t *tvb, gint offset, guint8 flags,
                  gboolean little_endian, int next_submsg_offset,
                  proto_tree *rtps_submessage_tree)
{
  char *buff;
  SequenceNumber     sequenceNumber;      /* type struct  */

  buff=ep_alloc(40);
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, flags);
  offset +=1;

  if (next_submsg_offset < 24)
  {
    proto_tree_add_uint_format(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                               tvb, offset, 2, next_submsg_offset,
                               "Octets to next header: %u (bogus, must be >= 24)",
                               next_submsg_offset);
    return;
  }
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                      tvb, offset, 2, next_submsg_offset);
  offset +=2;
  next_submsg_offset += offset;

  /* Reader Object ID */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Reader Object ID:   %s ",
                      object_id_to_string(offset, tvb, buff, 40));
  offset +=4;

  /* Writer Object ID */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Writer Object ID:   %s ",
                          object_id_to_string(offset, tvb, buff, 40));
  offset +=4;

  /*  firstSeqNumber */
  seq_nr_to_string(offset, little_endian, tvb, &sequenceNumber);
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 8,
                      "firstSeqNumber:     0x%X%X",
                      sequenceNumber.high, sequenceNumber.low);
  offset +=8;

  /* lastSeqNumber */
  seq_nr_to_string(offset, little_endian, tvb, &sequenceNumber);
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 8,
                      "lastSeqNumber:      0x%X%X",
                      sequenceNumber.high, sequenceNumber.low);
  offset +=8;

}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                   subdissector for submessage: GAP                      *
 *                                                                         *
 * *********************************************************************** */
 /* hotovo 12.01.04 - JEN OTESTOVAT :] */
static void
dissect_GAP(tvbuff_t *tvb, gint offset, guint8 flags,
            gboolean little_endian, int next_submsg_offset,
            proto_tree *rtps_submessage_tree)
{
  char *buff;
  SequenceNumber          sequenceNumber;      /* type struct  */

  buff=ep_alloc(40);
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, flags);
  offset +=1;

  if (next_submsg_offset < 28)
  {
    proto_tree_add_uint_format(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                               tvb, offset, 2, next_submsg_offset,
                               "Octets to next header: %u (bogus, must be >= 28)",
                               next_submsg_offset);
    return;
  }
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                      tvb, offset, 2, next_submsg_offset);
  offset +=2;
  next_submsg_offset += offset;

  /*  Reader Object ID  */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Reader Object ID:          %s ",
                      object_id_to_string(offset, tvb, buff, 40));
  offset +=4;

  /*  Writer Object ID  */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Writer Object ID:          %s ",
                      object_id_to_string(offset, tvb, buff, 40));
  offset +=4;

  /*  Sequence Number */
  seq_nr_to_string(offset, little_endian, tvb, &sequenceNumber);
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 8,
                      "firstSeqNumber:   0x%X%X",
                      sequenceNumber.high, sequenceNumber.low);
  offset +=8;

  get_bitmap(tvb,&offset,little_endian,next_submsg_offset,rtps_submessage_tree);

}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                subdissector for submessage: INFO_TS                     *
 *                                                                         *
 * *********************************************************************** */
 /* hotovo 12.01.04 - JEN OTESTOVAT :] */

static void
dissect_INFO_TS(tvbuff_t *tvb, gint offset, guint8 flags,
                gboolean little_endian, int next_submsg_offset,
                proto_tree *rtps_submessage_tree)
{
  char *buff;

  buff=ep_alloc(10);
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, flags);
  offset +=1;

  /*   npTimestamp - valid if flag I = 1         *
   *   |XXXX|XXIE| => masks with 00000010b = 2   */
  if ((flags & FLAG_I) != 0)
  {
    if (next_submsg_offset < 8)
    {
      proto_tree_add_uint_format(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                                 tvb, offset, 2, next_submsg_offset,
                                 "Octets to next header: %u (bogus, must be >= 8)",
                                 next_submsg_offset);
      return;
    }
  }
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                      tvb, offset, 2, next_submsg_offset);
  offset +=2;
  next_submsg_offset += offset;

  /*   npTimestamp - valid if flag I = 1         *
   *   |XXXX|XXIE| => masks with 00000010b = 2   */
  if ((flags & FLAG_I) != 0)
  {
    proto_tree_add_text(rtps_submessage_tree, tvb, offset, 8,
                        "ntpTimestamp: %s (sec)",
                        get_NtpTime(offset, tvb, little_endian, buff, 10));
    offset +=8;
  }

}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *               subdissector for submessage: INFO_SRC                     *
 *                                                                         *
 * *********************************************************************** */
/* hotovo 12.01.04 JEN OTESTOVAT :] */
static void
dissect_INFO_SRC(tvbuff_t *tvb, gint offset, guint8 flags,
                 gboolean little_endian, int next_submsg_offset,
                 proto_tree *rtps_submessage_tree)
{
  char *buff;

  buff=ep_alloc(200);
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, flags);
  offset +=1;

  if (next_submsg_offset < 16)
  {
    proto_tree_add_uint_format(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                               tvb, offset, 2, next_submsg_offset,
                               "Octets to next header: %u (bogus, must be >= 16)",
                               next_submsg_offset);
    return;
  }
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                      tvb, offset, 2, next_submsg_offset);
  offset +=2;
  next_submsg_offset += offset;

  /*  IPAddress */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "appIP address: %s",
                      IP_to_string(offset, tvb, little_endian, buff, 200));
  offset +=4;

  /*  Protocol Version */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 2,
                      "Protocol  RTPS  version %s -new",
                      protocol_version_to_string(offset, tvb, buff, 200));
  offset +=2;

  /*  Vendor Id */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 2,
                      "VendorId: %s -new",
                      vendor_id_to_string(offset, tvb, buff, 200));
  offset +=2;

  /*  Host Id */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Host ID:            %s",
                      host_id_to_string(offset, tvb, buff, 200));
  offset+=4;

  /*  App Id */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "App ID:             %s-new",
                      app_id_to_string(offset, tvb, buff, 200));
  offset +=4;

}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *               subdissector for submessage: INFO_REPLY                   *
 *                                                                         *
 * *********************************************************************** */
 /* hotovo 11.01.04 :] */
static void
dissect_INFO_REPLY(tvbuff_t *tvb, gint offset, guint8 flags,
                   gboolean little_endian, int next_submsg_offset,
                   proto_tree *rtps_submessage_tree)
{
  int                     min_len;
  char                    *buff_ip, *buff_port;

  buff_port=ep_alloc(10);
  buff_ip=ep_alloc(200);
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, flags);
  offset +=1;

 /*  'multicastReplyAddress' and 'multicastReplyPort' are   *
  *   parts of submessage INFO REPLY which are available    *
  *   only when FLAG  M=1  flags: XXXX XXME                 */

  if ((flags & FLAG_M) != 0)
    min_len = 16;
  else
    min_len = 8;
  if (next_submsg_offset < min_len)
  {
    proto_tree_add_uint_format(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                               tvb, offset, 2, next_submsg_offset,
                               "Octets to next header: %u (bogus, must be >= %u)",
                               next_submsg_offset, min_len);
    return;
  }
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                      tvb, offset, 2, next_submsg_offset);
  offset +=2;
  next_submsg_offset += offset;

  /* Unicat Reply IPAddress */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Unicast Reply IP Address: %s",
                      IP_to_string(offset, tvb, little_endian, buff_ip, 200));
  offset +=4;


  /* Unicast Reply Port */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Unicast Reply IP Port: %s",
                      port_to_string(offset, tvb, little_endian, buff_port, 10));
  offset +=4;


 /*  'multicastReplyAddress' and 'multicastReplyPort' are   *
  *   parts of submessage INFO REPLY which are available    *
  *   only when FLAG  M=1  flags: XXXX XXME                 */

  if ((flags & FLAG_M) != 0)
  {
    /* Multicast Reply IPAddress */
    proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                        "Multicast Reply IP Address: %s",
                        IP_to_string(offset, tvb, little_endian, buff_ip, 200));
    offset +=4;

    /* Multicast Reply Port */
    proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                        "Multicast Reply IP Port: %s",
                        port_to_string(offset, tvb, little_endian, buff_port, 10));
    offset +=4;

  }
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                 subdissector for submessage: INFO_DST                   *
 *                                                                         *
 * *********************************************************************** */
 /* HOTOVO 12.01.04 - JEN OTESOVAT :]*/
static void
dissect_INFO_DST(tvbuff_t *tvb, gint offset, guint8 flags,
                 int next_submsg_offset,
                 proto_tree *rtps_submessage_tree)
{
  char *buff;

  buff=ep_alloc(200);
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, flags);
  offset +=1;

  if (next_submsg_offset < 8)
  {
    proto_tree_add_uint_format(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                               tvb, offset, 2, next_submsg_offset,
                               "Octets to next header: %u (bogus, must be >= 8)",
                               next_submsg_offset);
    return;
  }
  proto_tree_add_uint(rtps_submessage_tree, hf_rtps_octets_to_next_header,
                      tvb, offset, 2, next_submsg_offset);
  offset +=2;
  next_submsg_offset += offset;

  /*  Host Id */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Host ID:            %s",
                      host_id_to_string(offset, tvb, buff, 200));
  offset+=4;

  /*  App Id */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "App ID:             %s-new",
                      app_id_to_string(offset, tvb, buff, 200));
  offset +=4;

}

/* *********************************************************************** *
 *                                                                         *
 *                       Register the protocol with Ethereal               *
 *                                                                         *
 * *********************************************************************** */

void proto_register_rtps(void)
{
  static hf_register_info hf[] = {

    { &hf_rtps_submessage_id,
      { "Submessage Id", "rtps.submessage_id",
         FT_UINT8, BASE_HEX, VALS(submessage_id_vals), 0x0,
        "Submessage flags", HFILL }},

    { &hf_rtps_submessage_flags,
      { "Submessage flags", "rtps.submessage_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
        "Submessage flags", HFILL }},

    { &hf_rtps_octets_to_next_header,
      { "Octets to next header", "rtps.octets_to_next_header",
         FT_UINT16, BASE_DEC, NULL, 0x0,
        "Octets to next header", HFILL }},

    { &hf_rtps_parameter_id,
      { "Parameter Id", "rtps.parameter_id",
         FT_UINT16, BASE_HEX, VALS(parameter_id_vals), 0x0,
        "Parameter Id", HFILL }},

    { &hf_rtps_parameter_length,
      { "Parameter Length", "rtps.parameter_length",
         FT_UINT16, BASE_DEC, NULL, 0x0,
        "Parameter Length", HFILL }},

    { &hf_rtps_issue_data,
      { "User Data", "rtps.issue_data",
         FT_BYTES, BASE_HEX, NULL, 0x0,
        "Issue Data", HFILL }},
  };

  static gint *ett[] = {
    &ett_rtps,
    &ett_rtps_submessage,
    &ett_rtps_bitmap,
    &ett_rtps_parameter_sequence,
    &ett_rtps_parameter,
  };

  proto_rtps = proto_register_protocol("Real-Time Publish-Subscribe Wire Protocol",
                                       "RTPS", "rtps");
  proto_register_field_array(proto_rtps, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_rtps(void)
{
 heur_dissector_add("udp", dissect_rtps, proto_rtps);
}

