/*
 *  $Id$
 *
 *  AUTHOR: Petr Smolik                 petr.smolik@wo.cz
 *
 *  ORTE - OCERA Real-Time Ethernet     http://www.ocera.org/
 *  --------------------------------------------------------------------
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 */
 
#ifndef _TYPEDEFS_DEFINES_RTPS_H
#define _TYPEDEFS_DEFINES_RTPS_H

#ifdef __cplusplus
extern "C" {
#endif

#define RTPS_HEADER_LENGTH   16

#define MAX_PATHNAME         128
#define MAX_TYPENAME         128
#define ORTE_TRUE            1
#define ORTE_FALSE           0

typedef gint8                    Boolean;

typedef gint8                    PathName[MAX_PATHNAME];
typedef gint8                    TypeName[MAX_TYPENAME];

typedef gint32                   TypeChecksum;

/*****************************************************************/
/*             Wire Protocol Specification (WPS)                 */
/*****************************************************************/

         
/**
  Host identifier.
   
  for example: IP address working nodes
*/
typedef gint32                   HostId;
#define HID_UNKNOWN              0x00

/**
  Application identifier.

  composed from: 3 bytes - instance Id
                 1 byte  - appKind (1 - ManagedApplication, 2 - Manager) 
*/
typedef gint32                   AppId;
#define AID_UNKNOWN              0x00
#define MANAGEDAPPLICATION       0x01
#define MANAGER                  0x02

/**
  Object identifier.
   
  composed from: 3 bytes - instance Id
                 1 byte  - objKind
*/
typedef gint32                   ObjectId;

#define OID_UNKNOWN              0x00000000
#define OID_APP                  0x000001C1
#define OID_WRITE_APPSELF        0x000008C2
#define OID_READ_APPSELF         0x000008C7
#define OID_WRITE_APP            0x000001C2
#define OID_READ_APP             0x000001C7
#define OID_WRITE_MGR            0x000007C2
#define OID_READ_MGR             0x000007C7
#define OID_WRITE_PUBL           0x000003C2
#define OID_READ_PUBL            0x000003C7
#define OID_WRITE_SUBS           0x000004C2
#define OID_READ_SUBS            0x000004C7
/* Kind */
#define OID_APPLICATION      0x01
#define OID_CSTWRITER        0x02
#define OID_PUBLICATION      0x03
#define OID_SUBSCRIPTION     0x04
#define OID_CSTREADER        0x07

#define OID_USEROBJ          0x00
#define OID_RESUSEROBJ       0x40
#define OID_METAOBJ          0x80
#define OID_RESMETAOBJ       0xC0

typedef struct {
       HostId                hid;
       AppId                 aid;
       ObjectId              oid;
     } GUID_RTPS;    

typedef struct {
       gint8                 major;
       gint8                 minor;
     } VendorId;

#define VENDOR_ID_UNKNOWN(id)    {id.major=0;id.minor=0;}
#define VENDOR_ID_RTI(id)        {id.major=1;id.minor=1;}
#define VENDOR_ID_OCERA(id)      {id.major=0;id.minor=0;}

typedef struct {
       gint8                 major;
       gint8                 minor;
     } ProtocolVersion;

#define PROTOCOL_VERSION_1_0(pv) {pv.major=1;pv.minor=0;}

typedef struct {
       gint32                high;
       gint32                low;
     } SequenceNumber;


#define SEQUENCE_NUMBER_NONE(sn)    {sn.high=0;sn.low=0;}
#define SEQUENCE_NUMBER_UNKNOWN(sn) {sn.high=0x7fffffff;sn.low=0xffffffff;}


typedef struct {
       gint32                seconds;    /* time in seconds */
       guint32               fraction;   /* time in seconds / 2^32 */
     } NtpTime;

#define NTPTIME_ZERO(t)          {t.seconds=0;t.fraction=0;}
#define NTPTIME_BUILD(t,s)       {t.seconds=s;t.fraction=0;}
#define NTPTIME_INFINITE(t)      {t.seconds=0xffffffff;t.fraction=0;}

typedef gint32                   IPAddress;

#define IPADDRESS_INVALID        0

typedef gint32                   Port;

#define PORT_INVALID             0

typedef enum {
       PAD                       = 0x01,
       VAR                       = 0x02,
       ISSUE                     = 0x03,
       ACK                       = 0x06,
       HEARTBEAT                 = 0x07,
       GAP                       = 0x08,
       INFO_TS                   = 0x09,
       INFO_SRC                  = 0x0c,
       INFO_REPLY                = 0x0d,
       INFO_DST                  = 0x0e,
       APP_QUIT                  = 0x90
     } SubmessageId;

typedef struct {
       ProtocolVersion           sourceVersion;
       VendorId                  sourceVendorId;
       HostId                    sourceHostId;
       AppId                     sourceAppId;
       HostId                    destHostId;
       AppId                     destAppId;
       IPAddress                 unicastReplyIPAddress;
       Port                      unicastReplyPort;
       IPAddress                 multicastReplyIPAddress;
       Port                      multicastReplyPort;
       Boolean                   haveTimestamp;
       NtpTime                   timestamp;          
     } MessageInterpret;


#define PID_PAD                             0x00
#define PID_SENTINEL                        0x01
#define PID_EXPIRATION_TIME                 0x02
#define PID_PERSISTENCE                     0x03
#define PID_MINIMUM_SEPARATION              0x04
#define PID_TOPIC                           0x05
#define PID_STRENGTH                        0x06
#define PID_TYPE_NAME                       0x07
#define PID_TYPE_CHECKSUM                   0x08
#define RTPS_PID_TYPE2_NAME                 0x09
#define RTPS_PID_TYPE2_CHECKSUM             0x0a
#define PID_METATRAFFIC_MULTICAST_IPADDRESS 0x0b  /*tady byla chyba MATA_TRAFF....*/
#define PID_APP_IPADDRESS                   0x0c
#define PID_METATRAFFIC_UNICAST_PORT        0x0d
#define PID_USERDATA_UNICAST_PORT           0x0e
#define PID_IS_RELIABLE                     0x0f
#define PID_EXPECTS_ACK                     0x10
#define PID_USERDATA_MULTICAST_IPADDRESS    0x11
#define PID_MANAGER_KEY                     0x12
#define PID_SEND_QUEUE_SIZE                 0x13
#define PID_RELIABILITY_ENABLED             0x14
#define PID_PROTOCOL_VERSION                0x15
#define PID_VENDOR_ID                       0x16
#define PID_VARGAPPS_SEQUENCE_NUMBER_LAST   0x17
#define PID_RECV_QUEUE_SIZE                 0x18
#define PID_RELIABILITY_OFFERED             0x19
#define PID_RELIABILITY_REQUESTED           0x1a

/* possible values for PID_RELIABILITY_REQUEST */
#define PID_VALUE_RELIABILITY_BEST_EFFORTS  0x01
#define PID_VALUE_RELIABILITY_STRICT        0x02

typedef guint16   ParameterId;
typedef guint16   ParameterLength;

/* State Machines */
typedef enum {
        MAYSENDHB                           = 0x01,
        MUSTSENDHB                          = 0x02,
        SENDHB                              = 0x03
      } StateMachineHB;

typedef enum {
        NOTHNIGTOSEND                       = 0x01,
        MUSTSENDDATA                        = 0x02
      } StateMachineSend;

typedef enum {
        NEW                                 = 0x01,
        TOSEND                              = 0x02,
        UNDERWAY                            = 0x03,
        UNACKNOWLEDGED                      = 0x04,
        ANNOUCED                            = 0x05,
        ACKNOWLEDGED                        = 0x06
      } StateMachineChFReader;

typedef enum {
        WAITING                             = 0x01,
        PULLING                             = 0x02,
        ACKPENDING                          = 0x03
      } StateMachineACK;

typedef enum {
        FUTURE                              = 0x01,
        REQUESTED                           = 0x02,
        MISSING                             = 0x03,
        RECEIVED                            = 0x04
      } StateMachineChFWriter;

#ifdef __cplusplus
} /* extern "C"*/
#endif
            
#endif /* _TYPEDEFS_DEFINES_RTPS_H */
