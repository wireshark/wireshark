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
 * $Id: packet-rtps.c,v 1.6 2004/04/18 20:08:59 guy Exp $
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

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include  <stdio.h>
#include  <stdlib.h>
#include  <string.h>
#include  <glib.h>
#include  <epan/packet.h>
#include  <epan/resolv.h>
#include  <epan/conversation.h>


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
static int proto_rtps                  = -1;
static int hf_rtps_submessage_flags    = -1;
static int hf_rtps_issue_data          = -1;

/*  Initialize the subtree pointers */
static gint ett_rtps                   = -1;
static gint ett_rtps_submessage        = -1;
static gint ett_rtps_bitmap            = -1;

/*  Functions declarations */
static void dissect_PAD(tvbuff_t *tvb,gint offset,proto_tree *tree);
static void dissect_VAR(tvbuff_t *tvb,gint offset,proto_tree *tree);
static void dissect_ISSUE(tvbuff_t *tvb,gint offset,proto_tree *tree);
static void dissect_ACK(tvbuff_t *tvb,gint offset,proto_tree *tree);
static void dissect_HEARTBEAT(tvbuff_t *tvb,gint offset,proto_tree *tree);
static void dissect_GAP(tvbuff_t *tvb,gint offset,proto_tree *tree);
static void dissect_INFO_TS(tvbuff_t *tvb,gint offset,proto_tree *tree);
static void dissect_INFO_SRC(tvbuff_t *tvb,gint offset,proto_tree *tree);
static void dissect_INFO_REPLY(tvbuff_t *tvb,gint offset,proto_tree *tree);
static void dissect_INFO_DST(tvbuff_t *tvb,gint offset,proto_tree *tree);

static guint16  get_guint16(tvbuff_t *tvb, gint offset, gboolean little_endian);
static guint32  get_guint32(tvbuff_t *tvb, gint offset, gboolean little_endian);

static char *protocol_version_to_string(gint offset,tvbuff_t *tvb,char *buff);
static char *vendor_id_to_string(gint offset, tvbuff_t *tvb, char *buff);

static char *host_id_to_string(gint offset,tvbuff_t *tvb, char buff[]);
static char *app_id_to_string(gint offset,tvbuff_t *tvb,char buff[]);
static char *object_id_to_string(gint offset, tvbuff_t *tvb, char buff[]);

static char *IP_to_string(gint offset,tvbuff_t *tvb,gboolean little_endian,char buff[]);
static char *port_to_string(gint offset,tvbuff_t *tvb,gboolean little_endian,char buff[]);
static char *get_NtpTime(gint offset,tvbuff_t *tvb,gboolean little_endian,char buff[]);

static void  get_bitmap(tvbuff_t *tvb, gint *p_offset, gboolean little_endian,
                        gint next_submsg, proto_tree *tree);

static char *get_parameter(gint offset, tvbuff_t *tvb, gboolean little_endian, char buff[],
                           guint16 parameter, guint16 param_length);

static gint  seq_nr_to_string( gint offset, gboolean little_endian, tvbuff_t *tvb,
                             SequenceNumber *p_seqNumber);



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
  gint             message_len = 0;
  gint             appKind = 0;
  guint8           submessageId = 0;
  int              next_submsg = 0;
  int              count_msg_type[11];
  char             buff[200], buff_tmp[30];/* buffers */

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
                       protocol_version_to_string(offset, tvb, buff));
   offset +=2;

   /*  Vendor Id  */
   proto_tree_add_text(rtps_tree, tvb, offset, 2,
                       "VendorId: %s",
                       vendor_id_to_string(offset, tvb, buff));
   offset +=2;

   /*  Host Id  */
   proto_tree_add_text(rtps_tree, tvb, offset, 4,
                       "HostId:   %s",
                       host_id_to_string(offset,tvb,buff));
   offset +=4;

   /*  App Id  */
   proto_tree_add_text(rtps_tree, tvb, offset, 4,
                       "App ID:   %s",
                       app_id_to_string(offset, tvb, buff));

  }

  /*  offset behind RTPS's Header */
  offset=16;

  message_len = tvb_reported_length(tvb);

  do {
    submessageId = tvb_get_guint8(tvb, offset);

    /* read value in littlendian format */
    /* XXX - is this in the byte order specified by the E bit? */
    next_submsg  = tvb_get_letohs(tvb, offset+2);

    switch (submessageId)
    {
      case PAD:
        if (tree)
          dissect_PAD(tvb, offset, rtps_tree);
        count_msg_type[0]++;
        break;
      case VAR:
        if (tree)
          dissect_VAR(tvb, offset, rtps_tree);
        count_msg_type[1]++;
        break;
      case ISSUE:
        if (tree)
          dissect_ISSUE(tvb, offset, rtps_tree);
        count_msg_type[2]++;
        break;
      case ACK:
        if (tree)
          dissect_ACK(tvb, offset, rtps_tree);
        count_msg_type[3]++;
        break;
      case HEARTBEAT:
        if (tree)
          dissect_HEARTBEAT(tvb,offset, rtps_tree);
        count_msg_type[4]++;
        break;
      case GAP:
        if (tree)
          dissect_GAP(tvb, offset, rtps_tree);
        count_msg_type[5]++;
        break;
      case INFO_TS:
        if (tree)
          dissect_INFO_TS(tvb, offset, rtps_tree);
        count_msg_type[6]++;
        break;
      case INFO_SRC:
        if (tree)
          dissect_INFO_SRC(tvb, offset, rtps_tree);
        count_msg_type[7]++;
        break;
      case INFO_REPLY:
        if (tree)
          dissect_INFO_REPLY(tvb, offset, rtps_tree);
        count_msg_type[8]++;
        break;
      case INFO_DST:
        if (tree)
          dissect_INFO_DST(tvb, offset, rtps_tree);
        count_msg_type[9]++;
        break;
      default:
        if (tree)
          proto_tree_add_text(rtps_tree, tvb, offset, 1,
                            "Submessage Id: Vendor-specific (0x%02x)",
                            submessageId);
        break;
     }

     /* next submessage's offset */
     offset += next_submsg+4;

  } while (offset<message_len);

  /* --- and Info column on summary display ---*/

  if (check_col(pinfo->cinfo, COL_INFO))
  {
    appKind = tvb_get_guint8(tvb, APP_KIND_BYTE);

    if (appKind == MANAGEDAPPLICATION ) {sprintf(buff,"App: ");}
    if (appKind == MANAGER)             {sprintf(buff,"Man: ");}
    if (appKind == AID_UNKNOWN)         {sprintf(buff,"Unknown:");}

    if (appKind != MANAGEDAPPLICATION  && appKind != MANAGER &&
        appKind != AID_UNKNOWN)         {sprintf(buff,"ERROR in APP type");}

   /* -- counts of submessages - for Information Frame */
   if (count_msg_type[0]>0) {
       sprintf(buff_tmp,"PAD(%d) ",count_msg_type[0]);
       strcat(buff,buff_tmp);
   }

   if (count_msg_type[1]>0) {
       sprintf(buff_tmp,"VAR(%d) ",count_msg_type[1]);
       strcat(buff,buff_tmp);
   }

   if (count_msg_type[2]>0) {
       sprintf(buff_tmp,"ISSUE(%d) ",count_msg_type[2]);
       strcat(buff,buff_tmp);
   }

   if (count_msg_type[3]>0) {
       sprintf(buff_tmp,"ACK(%d) ",count_msg_type[3]);
       strcat(buff,buff_tmp);
   }

   if (count_msg_type[4]>0) {
       sprintf(buff_tmp,"HEARTBEAT(%d) ",count_msg_type[4]);
       strcat(buff,buff_tmp);
   }

   if (count_msg_type[5]>0) {
       sprintf(buff_tmp,"GAP(%d) ",count_msg_type[5]);
       strcat(buff,buff_tmp);
   }

   if (count_msg_type[6]>0) {
       sprintf(buff_tmp,"INFO_TS(%d) ",count_msg_type[6]);
       strcat(buff,buff_tmp);
   }

   if (count_msg_type[7]>0) {
       sprintf(buff_tmp, "INFO_SRC(%d) ",count_msg_type[7]);
       strcat(buff,buff_tmp);
   }

   if (count_msg_type[8]>0) {
       sprintf(buff_tmp,"INFO_REPLY(%d) ",count_msg_type[8]);
       strcat(buff,buff_tmp);
   }

   if (count_msg_type[9]>0) {
       sprintf(buff_tmp,"INFO_DST(%d) ",count_msg_type[9]);
       strcat(buff,buff_tmp);
   }

   if (count_msg_type[10]>0) {
       sprintf(buff_tmp,"vendor specific(%d) ",count_msg_type[10]);
       strcat(buff,buff_tmp);
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
protocol_version_to_string(gint offset,tvbuff_t *tvb,char *buff)
{
  guint8            major, minor;

  /* protocol verzion = major.minor */
   major = tvb_get_guint8(tvb, offset);
   minor = tvb_get_guint8(tvb, (offset+1));

   sprintf(buff,"%d.%d", major, minor);
   return(buff);

}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                               get Vendor Id                             *
 *                                                                         *
 * *********************************************************************** */

static char *
vendor_id_to_string(gint offset, tvbuff_t *tvb, char *buff)
{
  guint8              major, minor;
  VendorId            vendorId_rti;

  VENDOR_ID_RTI(vendorId_rti);

  major = tvb_get_guint8(tvb, offset);
  minor = tvb_get_guint8(tvb, (offset+1));

  if (major == vendorId_rti.major &&
      minor == vendorId_rti.minor)
  { sprintf(buff,"Real-Time Innovations,Inc.,CA,USA");
    return(buff); }

  sprintf(buff,"Vendor unknown");
  return(buff);
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                               get IP Address                            *
 *                                                                         *
 * *********************************************************************** */

static char *
IP_to_string(gint offset,tvbuff_t *tvb,gboolean little_endian,char buff[])
{
  IPAddress         ip;
  guint8  a = 0, b = 0, c = 0, d = 0; /* IP Adresss = a.b.c.d */

  ip = get_guint32(tvb, offset, little_endian);
     /* get_guint32() - reads + endian conversion */
  a = (ip >> 24);
  b = (ip >> 16) & 0xff;
  c = (ip >>  8) & 0xff;
  d =  ip & 0xff;

  sprintf(buff,"%d.%d.%d.%d", a, b, c, d);
  return(buff);
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                               get Port                                  *
 *                                                                         *
 * *********************************************************************** */

static char *
port_to_string(gint offset,tvbuff_t *tvb,gboolean little_endian,char buff[])
{
  Port port = get_guint32(tvb, offset, little_endian);
            /* get_guint32() - reads + endian conversion */

  if (port == PORT_INVALID)
    sprintf(buff,"PORT_INVALID");
  else
    sprintf(buff,"0x%X",port);

  return(buff);
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                                get NTP Time                             *
 *                                                                         *
 * *********************************************************************** */

static char *
get_NtpTime(gint offset,tvbuff_t *tvb,gboolean little_endian,char buff[])
{
  NtpTime         ntpTime;
  float           time;

  /* get_guint32() - reads + endian conversion */
  ntpTime.seconds  =  get_guint32(tvb, offset, little_endian);
  ntpTime.fraction =  get_guint32(tvb, (offset + 4), little_endian);
  time = (float) ntpTime.seconds + (ntpTime.fraction / 2^(32));

  sprintf(buff,"%f", time);
  return(buff);
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                                get Host Id                              *
 *                                                                         *
 * *********************************************************************** */

static char *
host_id_to_string(gint offset,tvbuff_t *tvb, char buff[])
{
  guint32       hostId = tvb_get_ntohl(tvb, offset);
  /* get_ntohl() automaticaly convert data to BIG ENDIAN */

  sprintf(buff,"0x%X", hostId);
  return(buff);
}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                                get AppID                                *
 *                                                                         *
 * *********************************************************************** */

static char *
app_id_to_string(gint offset,tvbuff_t *tvb,char buff[])
{
  guint32        appId = tvb_get_ntohl(tvb, offset);
  /* get_ntohl() automaticaly convert data to BIG ENDIAN */

  /* Instance Id */
  guint32        instanceId = (appId >> 8);
  /* applicatin Kind */
  guint8         appKind    = (appId & 0xff);

  if (appKind == MANAGEDAPPLICATION)
  {
    sprintf(buff,"Managed App, InstanceId: 0x%X",instanceId);
    return(buff);
  }

  if (appKind == MANAGER)
  {
    sprintf(buff,"Manager, InstanceId: 0x%X",instanceId);
    return(buff);
  }

  sprintf(buff,"Unknown");
  return(buff);

}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                         get Object_Id (32 bit)                          *
 *                                                                         *
 * *********************************************************************** */

static char *
object_id_to_string(gint offset, tvbuff_t *tvb, char buff[])
{
  guint32        objectId = tvb_get_ntohl(tvb, offset);
  /* get_ntohl() automaticaly convert data to BIG ENDIAN */

  if (objectId == OID_UNKNOWN)      { sprintf(buff,"Unknown ObjectId");
                                      return(buff);}
  if (objectId == OID_APP)          { sprintf(buff,"applicationSelf");
                                      return(buff);}
  if (objectId == OID_WRITE_APPSELF){ sprintf(buff,"writerApplicationSelf");
                                      return(buff);}
  if (objectId == OID_WRITE_APP)    { sprintf(buff,"writerApplications");
                                      return(buff);}
  if (objectId == OID_READ_APP)     { sprintf(buff,"readerApplications");
                                      return(buff);}
  if (objectId == OID_WRITE_MGR)    { sprintf(buff,"writerManagers");
                                      return(buff);}
  if (objectId == OID_READ_MGR)     { sprintf(buff,"readerManagers ");
                                      return(buff);}
  if (objectId == OID_WRITE_PUBL)   { sprintf(buff,"writerPublications");
                                      return(buff);}
  if (objectId == OID_READ_PUBL)    { sprintf(buff,"readerPublications");
                                      return(buff);}
  if (objectId == OID_WRITE_SUBS)   { sprintf(buff,"writerSubscriptions");
                                      return(buff);}
  if (objectId == OID_READ_SUBS)    { sprintf(buff,"readerSubscriptions");
                                      return(buff);}

  /* nothing from the possibilites above */
  sprintf(buff,"instanceId: 0x%X, objKind: 0x%X",
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

  /* making subtree for the bitmap */
  ti = proto_tree_add_text(tree,tvb,offset,(next_submsg-offset),"Bitmap");
  rtps_bitmap_tree = proto_item_add_subtree(ti, ett_rtps_bitmap);

   /* SekvenceNumber bitmapBase */
   seq_nr_to_string(offset, little_endian, tvb, &sequenceNumber);
   proto_tree_add_text(rtps_bitmap_tree, tvb, offset, 8,
                       "bitmapBase:  0x%X%X",
                       sequenceNumber.high, sequenceNumber.low);
   offset +=8;

   proto_tree_add_text(rtps_bitmap_tree, tvb, offset, 4,
                       "numBits:     0x%X",
                       get_guint32(tvb, offset, little_endian));
   offset += 4;

   while (offset < (next_submsg -1))
   {
      proto_tree_add_text(rtps_bitmap_tree, tvb, offset, 4,
                          "bitmap[%d]:   0x%08X",
                          i, get_guint32(tvb, offset, little_endian));
      offset +=4;
      ++i;
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
dissect_PAD(tvbuff_t *tvb, gint offset,  proto_tree *tree)
{
  proto_item             *ti;
  proto_tree             *rtps_submessage_tree;
  gint                    flags = 0;
  gboolean                little_endian;

  ti = proto_tree_add_text(tree, tvb, offset, 1,"Submessage Id: PAD");
  rtps_submessage_tree = proto_item_add_subtree(ti, ett_rtps_submessage);
  offset += 1;

  /* -- if you want to see 'flags' in window - just uncomment -- */
  /*
  proto_tree_add_item(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, FALSE);
  */

  flags = tvb_get_guint8(tvb, offset);

  /*  E flag |XXXX|HAPE| => masks with 000000001b = 1  */
  if ((flags & FLAG_E) != 0)      little_endian = TRUE;
    else                          little_endian = FALSE;

  offset += 1;

  /* --if you want to see'Octets to Next Header'in window - uncomment -- */
  /*
  proto_tree_add_item(rtps_submessage_tree,hf_rtps_octets_to_next_header,
                      tvb, offset+2, 2, TRUE);
  */

}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                          dissect submessage: VAR                        *
 *                                                                         *
 * *********************************************************************** */

static void
dissect_VAR(tvbuff_t *tvb, gint offset,  proto_tree *tree)
{
   proto_item        *ti;
   proto_tree        *rtps_submessage_tree;
   gint               flags = 0;
   gboolean           little_endian;
   gint               next_submsg_offset = 0;
   char               buff[200];
   SequenceNumber     writerSeqNumber;
   guint16            parameter;       /* sekvence parameter */
   guint16            param_length;    /* length of sekvence parameter */

   ti =  proto_tree_add_text(tree, tvb, offset, 1, "Submessage Id: VAR ");
   rtps_submessage_tree = proto_item_add_subtree(ti, ett_rtps_submessage);
   offset += 1;


   flags = tvb_get_guint8(tvb, offset);
  /* -- if you want to see flags in window - just uncomment -- */
  /*
   proto_tree_add_item(rtps_submessage_tree, hf_rtps_submessage_flags,
                       tvb, offset, 1, FALSE);
  */

   offset +=1;

  /* E flag |XXXX|HAPE| => masks with 000000001b = 1 */
   if ((flags & FLAG_E) != 0)   little_endian = TRUE;
     else                       little_endian = FALSE;


   next_submsg_offset = offset + 2 + get_guint16(tvb, offset, little_endian);
  /* actual offset + long of the octetsToNextHeader =
   *  =  2 Bytes + octetsToNextHeader */


  /* -- if you want to see Offset to Next Header - just uncomment -- */
  /*
   proto_tree_add_text(rtps_submessage_tree, tvb, offset, 2,
                       "Octets_to_next_header + offset (NEW): 0x%X",
                        next_submsg_offset);
  */
  offset +=2;

  /*  readerObjectId*/
   proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                       "Reader Object ID:   %s ",
                        object_id_to_string(offset, tvb, buff));
   offset +=4;

   /*  writerObjectId*/
    proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                        "Writer Object ID:   %s ",
                        object_id_to_string(offset, tvb, buff));
    offset+=4;

   /*  H flag |XXXX|HAPE| => masks with 00001000b = 8 */
    if ((flags & FLAG_H) != 0)
     {
      /*  HostId */
       proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                           "Host ID:            %s",
                           host_id_to_string(offset,tvb,buff));
       offset+=4;

      /*  App Id  */
       proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                           "App ID:             %s",
                            app_id_to_string(offset, tvb, buff));
       offset +=4;
     }

    /* Object Id */
     proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                         "Object ID:          %s ",
                         object_id_to_string(offset, tvb, buff));
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
      proto_tree_add_text(rtps_submessage_tree, tvb, offset,
                          (next_submsg_offset - offset),
                          "Parameters:");
     do
     {
       parameter    = get_guint16(tvb, offset, little_endian);  offset +=2;
       param_length = get_guint16(tvb, offset, little_endian);  offset +=2;

       proto_tree_add_text(rtps_submessage_tree, tvb,offset, param_length,
                           "%s", get_parameter(offset, tvb, little_endian, buff,
                                               parameter,param_length));
       offset += param_length;

     }  while (offset < (next_submsg_offset -1));

    }  /* end if */


}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                                get_Parameter                            *
 *                                                                         *
 * *********************************************************************** */

static char *
get_parameter(gint offset, tvbuff_t *tvb, gboolean little_endian, char buff[],
              guint16 parameter, guint16 param_length)
{
  char              buff_tmp[MAX_PATHNAME];
  int               i;

  SequenceNumber    seqNumber;

  switch (parameter)
  {
    case PID_PAD:
    {
      sprintf(buff," PARAM_PID_PAD: -");
      return(buff);
    }

    case PID_SENTINEL:
    {
      sprintf(buff," PARAM_PID_SENTINEL: -");
      return(buff);
    }

    case PID_EXPIRATION_TIME:
    {
      sprintf(buff," PID_EXPIRATION_TIME: %s",
              get_NtpTime(offset, tvb, little_endian,buff_tmp));
      return(buff);
    }

    case PID_PERSISTENCE:
    {
      sprintf(buff," PID_PERSISTENCE: %s",
              get_NtpTime(offset, tvb, little_endian,buff_tmp));
      return(buff);
    }

   case PID_MINIMUM_SEPARATION:
   {
      sprintf(buff," PID_MINIMUM_SEPARATION: %s",
              get_NtpTime(offset, tvb, little_endian,buff_tmp));
      return(buff);
   }

   case PID_TOPIC: /* --- ?? funguje spravne ?? */
   {
     for (i = 0; i < param_length; i++)
     {
       buff_tmp[i] = tvb_get_guint8(tvb,offset);
       offset++;
     }

     sprintf(buff," PID_TOPIC: ");
     strcat(buff,buff_tmp);
     return(buff);
   }

   case PID_STRENGTH:
   {
     sprintf(buff," PID_STRENGTH: 0x%X",
             get_guint32(tvb, offset, little_endian));
     return(buff);
   }

   case PID_TYPE_NAME: /* --- ?? funguje spravne ?? */
   {
     for (i = 0; i < param_length; i++)
     {
       buff_tmp[i] = tvb_get_guint8(tvb,offset);
       offset++;
     }
     sprintf(buff," PID_TYPE_NAME:");
     strcat(buff,buff_tmp);
     return(buff);
   }

   case PID_TYPE_CHECKSUM:
   {
     /* nacitam jako UNSIGNED - nemuze to byt i zaporne cislo?? */
     sprintf(buff," PID_TYPE_CHECKSUM: 0x%X",
             get_guint32(tvb, offset, little_endian));
     return(buff);
   }

   case RTPS_PID_TYPE2_NAME:
   {
     sprintf(buff," RTPS_PID_TYPE2_NAME:"); return(buff);
   }

   case RTPS_PID_TYPE2_CHECKSUM:
   {
     sprintf(buff," RTPS_PID_TYPE2_CHECKSUM:"); return(buff);
   }

   case PID_METATRAFFIC_MULTICAST_IPADDRESS:
   {
      sprintf(buff," PID_METATRAFFIC_MULTICAST_IPADDRESS: %s",
              IP_to_string(offset, tvb, little_endian,buff_tmp));
      return(buff);
   }

   case PID_APP_IPADDRESS:
   {
      sprintf(buff," PID_APP_IPADDRESS: %s",
              IP_to_string(offset, tvb, little_endian,buff_tmp));
      return(buff);
   }

   case PID_METATRAFFIC_UNICAST_PORT:
   {
      sprintf(buff," PID_METATRAFFIC_UNICAST_PORT: %s",
              port_to_string(offset, tvb, little_endian,buff_tmp));
      return(buff);
   }

   case PID_USERDATA_UNICAST_PORT:
   {
      sprintf(buff," PID_USERDATA_UNICAST_PORT: %s",
              port_to_string(offset, tvb, little_endian,buff_tmp));
      return(buff);
   }

   case PID_EXPECTS_ACK:
   {
      if (tvb_get_guint8(tvb, offset) == 0)
      { sprintf(buff," PID_EXPECTS_ACK: No"); return(buff); }
      else
      { sprintf(buff," PID_EXPECTS_ACK: Yes"); return(buff); }
   }

   case PID_USERDATA_MULTICAST_IPADDRESS:
   {
      sprintf(buff," PID_USERDATA_MULTICAST_IPADDRESS: %s",
              IP_to_string(offset, tvb, little_endian,buff_tmp));
      return(buff);
   }

   case PID_MANAGER_KEY:
   {
      sprintf(buff," PID_STRENGTH: 0x%X",
              get_guint32(tvb, offset, little_endian));
      return(buff);
   }

   case PID_SEND_QUEUE_SIZE:
   {
      sprintf(buff," PID_SEND_QUEUE_SIZE: 0x%X",
              get_guint32(tvb, offset, little_endian));
      return(buff);
   }

   case PID_PROTOCOL_VERSION:
   {
      sprintf(buff," PID_PROTOCOL_VERSION: %s",
              protocol_version_to_string(offset, tvb, buff_tmp));
      return(buff);
   }

   case PID_VENDOR_ID:
   {
      sprintf(buff," PID_VENDOR_ID: %s",
              vendor_id_to_string(offset, tvb, buff_tmp));
      return(buff);
   }

   case PID_VARGAPPS_SEQUENCE_NUMBER_LAST:
   {
     seq_nr_to_string(offset, little_endian, tvb, &seqNumber);
     sprintf(buff," PID_VARGAPPS_SEQUENCE_NUMBER_LAST: 0x%X%X",
             seqNumber.high, seqNumber.low);
     return(buff);
   }

   case PID_RECV_QUEUE_SIZE:
   {
      sprintf(buff," PID_RECV_QUEUE_SIZE: 0x%X",
              get_guint32(tvb, offset, little_endian));
      return(buff);
   }

  case PID_RELIABILITY_OFFERED:
  {
     sprintf(buff," PID_RELIABILITY_OFFERED: 0x%X",
             get_guint32(tvb, offset, little_endian));
     return(buff);
  }

  case PID_RELIABILITY_REQUESTED:
  {
     sprintf(buff," PID_RELIABILITY_REQUESTED: 0x%X",
             get_guint32(tvb, offset, little_endian));
     return(buff);
  }

  default:
  {
     sprintf(buff," :!: Unknown sequence parameter");
     return(buff);
  }
 }   /* end switch */

}

/* *********************************************************************** */


/* *********************************************************************** *
 *                                                                         *
 *                  subdissector for submessage: ISSUE                     *
 *                                                                         *
 * *********************************************************************** */
 /* hotovo 12.01.04 - JEN OTESTOVAT :] */
static void
dissect_ISSUE(tvbuff_t *tvb, gint offset,  proto_tree *tree)
{
  proto_item               *ti;
  proto_tree               *rtps_submessage_tree;
  gint                      flags = 0;
  gboolean                  little_endian;
  gint                      next_submsg_offset = 0;
  char                      buff[40];
  SequenceNumber            sequenceNumber;      /*  type struct  */

  ti = proto_tree_add_text(tree, tvb, offset,1,"Submessage Id: ISSUE");
  rtps_submessage_tree = proto_item_add_subtree(ti, ett_rtps_submessage);
  offset +=1;

  flags = tvb_get_guint8(tvb, offset);

  /* -- if you want to see flags in window - just uncomment -- */
  /*
  proto_tree_add_item(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, FALSE);
  */
  offset +=1;

  /* E flag |XXXX|HAPE| => masks with 000000001b = 1 */
  if ((flags & FLAG_E) != 0)        little_endian = TRUE;
    else                            little_endian = FALSE;

  next_submsg_offset = offset + 2 + get_guint16(tvb, offset, little_endian);
  /* next_submsg_offset = actual offset + long of the octetsToNextHeader
   *                      + octetsToNextHeader                       */

  /* -- if you want to see Offset to Next Header - just uncomment -- */
  /*
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 2,
                      "Octets_to_next_header + offset (NEW): 0x%X",
                      next_submsg_offset);
  */
  offset +=2;

  /*  Reader Object ID  */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Reader Object ID: %s ",
                      object_id_to_string(offset, tvb, buff));
  offset +=4;

  /*  Writer Object ID */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Writer Object ID: %s ",
                      object_id_to_string(offset, tvb, buff));
  offset +=4;

  /*  Sequence Number */
  seq_nr_to_string(offset, little_endian, tvb, &sequenceNumber);
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 8,
                      "firstSeqNumber:   0x%X%X",
                      sequenceNumber.high, sequenceNumber.low);
  offset += 8;

  /*  Parameters */
/* *********************************************************************** *
 * 'Parameters' - are saved in 64bites so I dissect it like a              *
 *                'Sequence Number'                                        *
 *              - for future extension of the protocol - in                *
 *                implementation of RTPS 1.0 can ignore the content        *
 * *********************************************************************** */

  /* -- P flag |XXXX|HAPE| => masks with 00000010b = 2 */
  if ((flags & FLAG_P) != 0)
  {
    seq_nr_to_string(offset, little_endian, tvb, &sequenceNumber);
    proto_tree_add_text(rtps_submessage_tree, tvb, offset, 8,
                        "Parameters:   0x%X%X",
                        sequenceNumber.high, sequenceNumber.low);
    offset += 8;
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
dissect_ACK(tvbuff_t *tvb, gint offset,  proto_tree *tree)
{
  proto_item             *ti;
  proto_tree             *rtps_submessage_tree;
  gint                    flags = 0;
  gboolean                little_endian;
  gint                    next_submsg_offset = 0;
  char                    buff[40];

  ti = proto_tree_add_text(tree, tvb, offset, 1,"Submessage Id: ACK");
  rtps_submessage_tree = proto_item_add_subtree(ti, ett_rtps_submessage);
  offset +=1;

  flags = tvb_get_guint8(tvb, offset);
  /* -- if you want to see flags in window - just uncomment -- */
  /*
  proto_tree_add_item(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, FALSE);
  */
  offset +=1;

  /* E flag |XXXX|HAPE| => masks with 000000001b = 1 */
  if ((flags & FLAG_E) != 0)      little_endian = TRUE;
   else                           little_endian = FALSE;

  next_submsg_offset = offset + 2 + get_guint16(tvb, offset, little_endian);
  /* next_submsg_offset = actual offset + long of the octetsToNextHeader
   *                      + octetsToNextHeader                       */

  /* -- if you want to see Offset to Next Header - just uncomment -- */
  /*
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 2,
                      "Octets_to_next_header + offset (NEW): 0x%X",
                      next_submsg_offset);
  */
  offset +=2;

  /*  Reader Object ID  */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Reader Object ID:   %s ",
                      object_id_to_string(offset, tvb, buff));
  offset +=4;

  /*  Writer Object ID  */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Writer Object ID:   %s ",
                      object_id_to_string(offset, tvb, buff));
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
dissect_HEARTBEAT(tvbuff_t *tvb, gint offset, proto_tree *tree)
{
  proto_item         *ti;
  proto_tree         *rtps_submessage_tree;
  guint8              flags = 0;
  gboolean            little_endian;
  char                buff[40];
  SequenceNumber     sequenceNumber;      /* type struct  */

  ti = proto_tree_add_text(tree, tvb, offset,1,"Submessage Id: HEARTBEAT");
  rtps_submessage_tree = proto_item_add_subtree(ti, ett_rtps_submessage);
  offset +=1;

  /* -- if you want to see Submessage's Flags - just uncomment */
  /* proto_tree_add_item(rtps_submessage_tree, hf_rtps_submessage_flags,
                         tvb, offset, 1, FALSE); */
  flags = tvb_get_guint8(tvb, offset);
  offset +=1;

  /*  E flag |XXXX|HAPE| => masks with 000000001b = 1  */
  if ((flags & FLAG_E) != 0)      little_endian = TRUE;
   else                           little_endian = FALSE;

  /* -- if you want to see Offset to Next Header - just uncomment -- */
  /*
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 1,
                      "Octets_to_next_header: 0x%X",
                      get_guint16(tvb, offset, little_endian));
  */
  offset +=2;
  /* Reader Object ID */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Reader Object ID:   %s ",
                      object_id_to_string(offset, tvb, buff));
  offset +=4;

  /* Writer Object ID */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Writer Object ID:   %s ",
                          object_id_to_string(offset, tvb, buff));
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
dissect_GAP(tvbuff_t *tvb, gint offset, proto_tree *tree)
{
  proto_item             *ti;
  proto_tree             *rtps_submessage_tree;
  gint                    flags = 0;
  gboolean                little_endian;
  gint                    next_submsg_offset = 0;
  char                    buff[40];
  SequenceNumber          sequenceNumber;      /* type struct  */

  ti = proto_tree_add_text(tree, tvb, offset, 1,"Submessage Id: GAP");
  rtps_submessage_tree = proto_item_add_subtree(ti, ett_rtps_submessage);
  offset +=1;

  flags = tvb_get_guint8(tvb, offset);
  /* -- if you want to see flags in window - just uncomment -- */
  /*
  proto_tree_add_item(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, FALSE);
  */
  offset +=1;

  /* E flag |XXXX|HAPE| => masks with 000000001b = 1 */
  if ((flags & FLAG_E) != 0)      little_endian = TRUE;
    else                          little_endian = FALSE;

  next_submsg_offset = offset + 2 + get_guint16(tvb, offset, little_endian);
  /* next_submsg_offset = actual offset + long of the octetsToNextHeader
   *                      + octetsToNextHeader                       */

  /* -- if you want to see Offset to Next Header - just uncomment -- */
  /*
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 2,
                      "Octets_to_next_header + offset (NEW): 0x%X",
                      next_submsg_offset);
  */
  offset +=2;

  /*  Reader Object ID  */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Reader Object ID:          %s ",
                      object_id_to_string(offset, tvb, buff));
  offset +=4;

  /*  Writer Object ID  */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Writer Object ID:          %s ",
                      object_id_to_string(offset, tvb, buff));
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
dissect_INFO_TS(tvbuff_t *tvb, gint offset, proto_tree *tree)
{
  proto_item              *ti;
  proto_tree              *rtps_submessage_tree;
  gint                     flags = 0;
  gboolean                 little_endian;
  char                     buff[10];

  ti = proto_tree_add_text(tree, tvb, offset,1,"Submessage Id: INFO_TS");
  rtps_submessage_tree = proto_item_add_subtree(ti, ett_rtps_submessage);
  offset +=1;

  flags = tvb_get_guint8(tvb, offset);
  /*  Flags -- if you want to see - just uncomment -- */  /*
  proto_tree_add_item(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, FALSE);
  */
  offset +=1;

  /*  E flag |XXXX|HAPE| => masks with 000000001b = 1 */
  if ((flags & FLAG_E) != 0)      little_endian = TRUE;
   else                           little_endian = FALSE;

  /*  Offset to Next Header -- if you want to see - just uncomment */
  /*
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 2,
                      "Octets_to_next_header + offset (NEW): 0x%X",
                      next_submsg_offset);
  */
  offset +=2;

  /*   npTimestamp - valid if flag I = 1         *
   *   |XXXX|XXIE| => masks with 00000010b = 2   */
  if ((flags & FLAG_I) != 0)
  {
    proto_tree_add_text(rtps_submessage_tree, tvb, offset, 8,
                        "ntpTimestamp: %s (sec)",
                        get_NtpTime(offset, tvb, little_endian,buff));
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
dissect_INFO_SRC(tvbuff_t *tvb, gint offset,  proto_tree *tree)
{
  proto_item             *ti;
  proto_tree             *rtps_submessage_tree;
  gint                    flags = 0;
  gboolean                little_endian;
  char                    buff[200];


  ti = proto_tree_add_text(tree,tvb,offset,1,"Submessage Id: INFO_SRC");
  rtps_submessage_tree = proto_item_add_subtree(ti, ett_rtps_submessage);
  offset +=1;

  flags = tvb_get_guint8(tvb, offset);

  /*  Flags -- if you want to see - just uncomment -- */
  /*
  proto_tree_add_item(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, FALSE);
  */
  offset +=1;

  /*  E flag |XXXX|HAPE| => masks with 000000001b = 1 */
  if ((flags & FLAG_E) != 0)      little_endian = TRUE;
   else                           little_endian = FALSE;

  /*  Offset to Next Header -- if you want to see - just uncomment */
  /*
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 2,
                      "Octets_to_next_header + offset (NEW): 0x%X",
                      next_submsg_offset);
  */
  offset +=2;

  /*  IPAddress */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "appIP address: %s",
                      IP_to_string(offset, tvb, little_endian,buff));
  offset +=4;

  /*  Protocol Version */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 2,
                      "Protocol  RTPS  version %s -new",
                      protocol_version_to_string(offset, tvb, buff));
  offset +=2;

  /*  Vendor Id */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 2,
                      "VendorId: %s -new",
                      vendor_id_to_string(offset, tvb, buff));
  offset +=2;

  /*  Host Id */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Host ID:            %s",
                      host_id_to_string(offset,tvb,buff));
  offset+=4;

  /*  App Id */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "App ID:             %s-new",
                      app_id_to_string(offset, tvb, buff));
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
dissect_INFO_REPLY(tvbuff_t *tvb, gint offset, proto_tree *tree)
{
  proto_item             *ti;
  proto_tree             *rtps_submessage_tree;
  gint                    flags = 0;
  gboolean                little_endian;
  char                    buff_ip[10], buff_port[10];

  ti = proto_tree_add_text(tree,tvb,offset,1,"Submessage Id: INFO_REPLY");
  rtps_submessage_tree = proto_item_add_subtree(ti, ett_rtps_submessage);
  offset +=1;

  flags = tvb_get_guint8(tvb, offset);

  /*  Flags -- if you want to see - just uncomment -- */
  /*
  proto_tree_add_item(rtps_submessage_tree, hf_rtps_submessage_flags,
                      tvb, offset, 1, FALSE);
  */
  offset +=1;

  /*  E flag |XXXX|HAPE| => masks with 000000001b = 1 */
  if ((flags & FLAG_E) != 0)    little_endian = TRUE;
   else                         little_endian = FALSE;

  /*  Offset to Next Header -- if you want to see - just uncomment */
  /*
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 2,
                      "Octets_to_next_header + offset (NEW): 0x%X",
                      next_submsg_offset);
  */
  offset +=2;

  /* Unicat Reply IPAddress */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Unicast Reply IP Adress: %s",
                      IP_to_string(offset, tvb, little_endian,buff_ip));
  offset +=4;


  /* Unicast Reply Port */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Unicast Reply IP Port: %s",
                      port_to_string(offset, tvb, little_endian,buff_port));
  offset +=4;


 /*  'multicastReplayAdress' and 'multicastReplayPort'are   *
  *   parts of submessage INFO REPLAY which are available   *
  *   only when FLAG  M=1  flags: XXXX XXME                 */

  if ((flags & FLAG_M) != 0)
  {
    /* Multicast Reply IPAddress */
    proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                        "Multicast Reply IP Adress: %s",
                        IP_to_string(offset, tvb, little_endian,buff_ip));
    offset +=4;

    /* Multicast Reply Port */
    proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                        "Multicast Reply IP Port: %s",
                        port_to_string(offset, tvb, little_endian,buff_port));
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
dissect_INFO_DST(tvbuff_t *tvb,gint offset,proto_tree *tree)
{
  proto_item             *ti;
  proto_tree             *rtps_submessage_tree;
  gint                    flags = 0;
  gboolean                little_endian;
  char                    buff[200];

  ti = proto_tree_add_text(tree, tvb, offset,1,"Submessage Id: INFO_DST");
  rtps_submessage_tree = proto_item_add_subtree(ti, ett_rtps_submessage);
  offset+=1;

  flags = tvb_get_guint8(tvb, offset);
  /*  Flags -- if you want to see - just uncomment -- */
  /*
   proto_tree_add_item(rtps_submessage_tree, hf_rtps_submessage_flags, 
                       tvb, offset, 1, FALSE);
   */
  offset +=1;

  /*  E flag |XXXX|HAPE| => masks with 000000001b = 1 */
  if ((flags & FLAG_E) != 0)      little_endian = TRUE;
   else                           little_endian = FALSE;

  /*  Offset to Next Header -- if you want to see - just uncomment */
  /*
   proto_tree_add_text(rtps_submessage_tree, tvb, offset, 2,
                       "Octets_to_next_header + offset (NEW): 0x%X",
                       next_submsg_offset);
   */
  offset +=2;

  /*  Host Id */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "Host ID:            %s",
                      host_id_to_string(offset,tvb,buff));
  offset+=4;

  /*  App Id */
  proto_tree_add_text(rtps_submessage_tree, tvb, offset, 4,
                      "App ID:             %s-new",
                      app_id_to_string(offset, tvb, buff));
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

    { &hf_rtps_submessage_flags,
      { "Submessage flags", "rtps.submessage_flags",
         FT_BYTES, BASE_HEX, NULL, 0x0,
        "Submessage flags", HFILL }},


    { &hf_rtps_issue_data,
      { "User Data", "rtps.issue_data",
         FT_BYTES, BASE_HEX, NULL, 0x0,
        "Issue Data", HFILL }},
  };

  static gint *ett[] = {
    &ett_rtps,
    &ett_rtps_submessage,
    &ett_rtps_bitmap,
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

