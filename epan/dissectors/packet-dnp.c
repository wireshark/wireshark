/* packet-dnp.c
 * Routines for DNP dissection
 * Copyright 2003, 2006, 2007, Graham Bloice <graham.bloice@trihedral.com>
 *
 * DNP3.0 Application Layer Object dissection added by Chris Bontje (chrisbontje@shaw.ca)
 * Copyright 2005
 *
 * Major updates: tcp and application layer defragmentation, more object dissections by Graham Bloice
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include "config.h"

#include <string.h>
#include <math.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/emem.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/conversation.h>
#include <epan/expert.h>

/*
 * See
 *
 * http://www.dnp.org/
 *
 * although note that you have to join the DNP organization to get to
 * see the protocol specs online - otherwise, you have to buy a
 * dead-tree version.
 *
 * ...Application Layer Notes...
 *
 * Application Layer Decoding based on information available in
 * DNP3 Basic 4 Documentation Set, specifically the document:
 * "DNP V3.00 Application Layer" v0.03 P009-0PD.APP & Technical Bulletins
 *
 * ---------------------------------------------------------------------------
 *
 * Several command codes were missing, causing the dissector to abort decoding
 * on valid packets.  Those commands have been added.
 *
 * The semantics of Variation 0 have been cleaned up.  Variation 0 is the
 * "Default Variation".  It is used only in Master -> Slave read commands
 * to request the data in whatever variation the Slave is configured to use by
 * default. Decoder strings have been added to the Binary Output and
 * Analog Output objects (10 and 40) so that group read commands will
 * decode properly.
 *
 * Roy M. Silvernail <roy@rant-central.com> 01/05/2009
 *
 */

/***************************************************************************/
/* DNP 3.0 Constants */
/***************************************************************************/
#define DNP_HDR_LEN     10
#define TCP_PORT_DNP    20000
#define UDP_PORT_DNP    20000

/***************************************************************************/
/* Datalink and Transport Layer Bit-Masks */
/***************************************************************************/
#define DNP3_CTL_DIR    0x80
#define DNP3_CTL_PRM    0x40
#define DNP3_CTL_FCB    0x20
#define DNP3_CTL_FCV    0x10
#define DNP3_CTL_RES    0x20
#define DNP3_CTL_DFC    0x10
#define DNP3_CTL_FUNC   0x0f

#define DNP3_TR_FIR     0x40
#define DNP3_TR_FIN     0x80
#define DNP3_TR_SEQ     0x3f

#define AL_MAX_CHUNK_SIZE 16

/***************************************************************************/
/* Data Link Function codes */
/***************************************************************************/
/* Primary to Secondary */
#define DL_FUNC_RESET_LINK  0x00
#define DL_FUNC_RESET_PROC  0x01
#define DL_FUNC_TEST_LINK   0x02
#define DL_FUNC_USER_DATA   0x03
#define DL_FUNC_UNC_DATA    0x04
#define DL_FUNC_LINK_STAT   0x09

/* Secondary to Primary */
#define DL_FUNC_ACK         0x00
#define DL_FUNC_NACK        0x01
#define DL_FUNC_STAT_LINK   0x0B
#define DL_FUNC_NO_FUNC     0x0E
#define DL_FUNC_NOT_IMPL    0x0F

/***************************************************************************/
/* Application Layer Bit-Masks */
/***************************************************************************/
#define DNP3_AL_UNS   0x10
#define DNP3_AL_CON   0x20
#define DNP3_AL_FIN   0x40
#define DNP3_AL_FIR   0x80
#define DNP3_AL_SEQ   0x0f
#define DNP3_AL_FUNC  0xff

/***************************************************************************/
/* Application Layer Function codes */
/***************************************************************************/
#define AL_FUNC_CONFIRM    0x00    /* 00  - Confirm */
#define AL_FUNC_READ       0x01    /* 01  - Read */
#define AL_FUNC_WRITE      0x02    /* 02  - Write */
#define AL_FUNC_SELECT     0x03    /* 03  - Select */
#define AL_FUNC_OPERATE    0x04    /* 04  - Operate */
#define AL_FUNC_DIROP      0x05    /* 05  - Direct Operate */
#define AL_FUNC_DIROPNACK  0x06    /* 06  - Direct Operate No ACK */
#define AL_FUNC_FRZ        0x07    /* 07  - Immediate Freeze */
#define AL_FUNC_FRZNACK    0x08    /* 08  - Immediate Freeze No ACK */
#define AL_FUNC_FRZCLR     0x09    /* 09  - Freeze and Clear */
#define AL_FUNC_FRZCLRNACK 0x0A    /* 10  - Freeze and Clear No ACK */
#define AL_FUNC_FRZT       0x0B    /* 11  - Freeze With Time */
#define AL_FUNC_FRZTNACK   0x0C    /* 12  - Freeze With Time No ACK */
#define AL_FUNC_COLDRST    0x0D    /* 13  - Cold Restart */
#define AL_FUNC_WARMRST    0x0E    /* 14  - Warm Restart */
#define AL_FUNC_INITDATA   0x0F    /* 15  - Initialize Data */
#define AL_FUNC_INITAPP    0x10    /* 16  - Initialize Application */
#define AL_FUNC_STARTAPP   0x11    /* 17  - Start Application */
#define AL_FUNC_STOPAPP    0x12    /* 18  - Stop Application */
#define AL_FUNC_SAVECFG    0x13    /* 19  - Save Configuration */
#define AL_FUNC_ENSPMSG    0x14    /* 20  - Enable Spontaneous Msg */
#define AL_FUNC_DISSPMSG   0x15    /* 21  - Disable Spontaneous Msg */
#define AL_FUNC_ASSIGNCL   0x16    /* 22  - Assign Classes */
#define AL_FUNC_DELAYMST   0x17    /* 23  - Delay Measurement */
#define AL_FUNC_RECCT      0x18    /* 24  - Record Current Time */
#define AL_FUNC_OPENFILE   0x19    /* 25  - Open File */
#define AL_FUNC_CLOSEFILE  0x1A    /* 26  - Close File */
#define AL_FUNC_DELETEFILE 0x1B    /* 27  - Delete File */
#define AL_FUNC_GETFILEINF 0x1C    /* 28  - Get File Info */
#define AL_FUNC_AUTHFILE   0x1D    /* 29  - Authenticate File */
#define AL_FUNC_ABORTFILE  0x1E    /* 30  - Abort File */
#define AL_FUNC_ACTCNF     0x1F    /* 31  - Activate Config */
#define AL_FUNC_AUTHREQ    0x20    /* 32  - Authentication Request */
#define AL_FUNC_AUTHERR    0x21    /* 33  - Authentication Error */
#define AL_FUNC_RESPON     0x81    /* 129 - Response */
#define AL_FUNC_UNSOLI     0x82    /* 130 - Unsolicited Response */
#define AL_FUNC_AUTHRESP   0x83    /* 131 - Authentication Response */

/***************************************************************************/
/* Application Layer Internal Indication (IIN) bits */
/* 2 Bytes, message formatting: [First Octet] | [Second Octet] */
/***************************************************************************/
/* Octet 1 */
#define AL_IIN_BMSG        0x0100   /* Bit 0 - Broadcast message rx'd */
#define AL_IIN_CLS1D       0x0200   /* Bit 1 - Class 1 Data Available */
#define AL_IIN_CLS2D       0x0400   /* Bit 2 - Class 2 Data Available */
#define AL_IIN_CLS3D       0x0800   /* Bit 3 - Class 3 Data Available */
#define AL_IIN_TSR         0x1000   /* Bit 4 - Time Sync Req'd from Master */
#define AL_IIN_DOL         0x2000   /* Bit 5 - Outputs in Local Mode */
#define AL_IIN_DT          0x4000   /* Bit 6 - Device Trouble */
#define AL_IIN_RST         0x8000   /* Bit 7 - Device Restart */

/* Octet 2 */
#define AL_IIN_FCNI        0x0001   /* Bit 0 - Function code not implemented */
#define AL_IIN_OBJU        0x0002   /* Bit 1 - Requested Objects Unknown */
#define AL_IIN_PIOOR       0x0004   /* Bit 2 - Parameters Invalid or Out of Range */
#define AL_IIN_EBO         0x0008   /* Bit 3 - Event Buffer Overflow */
#define AL_IIN_OAE         0x0010   /* Bit 4 - Operation Already Executing */
#define AL_IIN_CC          0x0020   /* Bit 5 - Device Configuration Corrupt */
                        /* 0x0040      Bit 6 - Reserved */
                        /* 0x0080      Bit 7 - Reserved */

/***************************************************************************/
/* Application Layer Data Object Qualifier */
/***************************************************************************/
/* Bit-Masks */
#define AL_OBJQ_INDEX          0x70     /* x111xxxx Masks Index from Qualifier */
#define AL_OBJQ_CODE           0x0F     /* xxxx1111 Masks Code from Qualifier */

/* Index Size (3-bits x111xxxx)            */
/* When Qualifier Code != 11               */
#define AL_OBJQL_IDX_NI        0x00    /* Objects are Packed with no index */
#define AL_OBJQL_IDX_1O        0x01    /* Objects are prefixed w/ 1-octet index */
#define AL_OBJQL_IDX_2O        0x02    /* Objects are prefixed w/ 2-octet index */
#define AL_OBJQL_IDX_4O        0x03    /* Objects are prefixed w/ 4-octet index */
#define AL_OBJQL_IDX_1OS       0x04    /* Objects are prefixed w/ 1-octet object size */
#define AL_OBJQL_IDX_2OS       0x05    /* Objects are prefixed w/ 2-octet object size */
#define AL_OBJQL_IDX_4OS       0x06    /* Objects are prefixed w/ 4-octet object size */

/* When Qualifier Code == 11 */
#define AL_OBJQL_IDX11_1OIS    0x01    /* 1 octet identifier size */
#define AL_OBJQL_IDX11_2OIS    0x02    /* 2 octet identifier size */
#define AL_OBJQL_IDX11_4OIS    0x03    /* 4 octet identifier size */

/* Qualifier Code (4-bits) */
/* 4-bits ( xxxx1111 ) */
#define AL_OBJQL_CODE_SSI8     0x00    /* 00 8-bit Start and Stop Indices in Range Field */
#define AL_OBJQL_CODE_SSI16    0x01    /* 01 16-bit Start and Stop Indices in Range Field */
#define AL_OBJQL_CODE_SSI32    0x02    /* 02 32-bit Start and Stop Indices in Range Field */
#define AL_OBJQL_CODE_AA8      0x03    /* 03 8-bit Absolute Address in Range Field */
#define AL_OBJQL_CODE_AA16     0x04    /* 04 16-bit Absolute Address in Range Field */
#define AL_OBJQL_CODE_AA32     0x05    /* 05 32-bit Absolute Address in Range Field */
#define AL_OBJQL_CODE_R0       0x06    /* 06 Length of Range field is 0 (no range field) */
#define AL_OBJQL_CODE_SF8      0x07    /* 07 8-bit Single Field Quantity */
#define AL_OBJQL_CODE_SF16     0x08    /* 08 16-bit Single Field Quantity */
#define AL_OBJQL_CODE_SF32     0x09    /* 09 32-bit Single Field Quantity */
                           /*  0x0A       10 Reserved  */
#define AL_OBJQL_CODE_FF       0x0B    /* 11 Free-format Qualifier, range field has 1 octet count of objects */
                           /*  0x0C       12 Reserved  */
                           /*  0x0D       13 Reserved  */
                           /*  0x0E       14 Reserved  */
                           /*  0x0F       15 Reserved  */

/***************************************************************************/
/* Application Layer Data Object Definitions                               */
/***************************************************************************/
/* Binary Input Objects */
#define AL_OBJ_BI_ALL      0x0100   /* 01 00 Binary Input Default Variation */
#define AL_OBJ_BI_1BIT     0x0101   /* 01 01 Single-bit Binary Input */
#define AL_OBJ_BI_STAT     0x0102   /* 01 02 Binary Input With Status */
#define AL_OBJ_BIC_ALL     0x0200   /* 02 00 Binary Input Change Default Variation */
#define AL_OBJ_BIC_NOTIME  0x0201   /* 02 01 Binary Input Change Without Time */
#define AL_OBJ_BIC_TIME    0x0202   /* 02 02 Binary Input Change With Time */
#define AL_OBJ_BIC_RTIME   0x0203   /* 02 03 Binary Input Change With Relative Time */

/* Double-bit Input Objects */
#define AL_OBJ_2BI_ALL     0x0300   /* 03 00 Double-bit Input Default Variation */
#define AL_OBJ_2BI_NF      0x0301   /* 03 01 Double-bit Input No Flags */
#define AL_OBJ_2BI_STAT    0x0302   /* 03 02 Double-bit Input With Status */
#define AL_OBJ_2BIC_NOTIME 0x0401   /* 04 01 Double-bit Input Change Without Time */
#define AL_OBJ_2BIC_TIME   0x0402   /* 04 02 Double-bit Input Change With Time */
#define AL_OBJ_2BIC_RTIME  0x0403   /* 04 03 Double-bit Input Change With Relative Time */

/* Binary Input Quality Flags */
#define AL_OBJ_BI_FLAG0    0x0001   /* Point Online (0=Offline; 1=Online) */
#define AL_OBJ_BI_FLAG1    0x0002   /* Restart (0=Normal; 1=Restart) */
#define AL_OBJ_BI_FLAG2    0x0004   /* Comms Lost (0=Normal; 1=Lost) */
#define AL_OBJ_BI_FLAG3    0x0008   /* Remote Force (0=Normal; 1=Forced) */
#define AL_OBJ_BI_FLAG4    0x0010   /* Local Force (0=Normal; 1=Forced) */
#define AL_OBJ_BI_FLAG5    0x0020   /* Chatter Filter (0=Normal; 1=Filter On) */
#define AL_OBJ_BI_FLAG6    0x0040   /* Double-bit LSB (0=Off; 1=On) */
#define AL_OBJ_BI_FLAG7    0x0080   /* Point State (0=Off; 1=On) or Double-bit MSB */

/***************************************************************************/
/* Binary Output Objects */
#define AL_OBJ_BO_ALL      0x0A00   /* 10 00 Binary Output Default Variation */
#define AL_OBJ_BO          0x0A01   /* 10 01 Binary Output */
#define AL_OBJ_BO_STAT     0x0A02   /* 10 02 Binary Output Status */
#define AL_OBJ_BOC_ALL     0x0B00   /* 11 00 Binary Output Change Default Variation */
#define AL_OBJ_BOC_NOTIME  0x0B01   /* 11 01 Binary Output Change Without Time */
#define AL_OBJ_BOC_TIME    0x0B02   /* 11 02 Binary Output Change With Time */
#define AL_OBJ_CTLOP_BLK   0x0C01   /* 12 01 Control Relay Output Block */
                        /* 0x0C02      12 02 Pattern Control Block */
                        /* 0x0C03      12 03 Pattern Mask */

#define AL_OBJCTLC_CODE    0x0F    /* Bit-Mask xxxx1111 for Control Code 'Code' */
#define AL_OBJCTLC_MISC    0x30    /* Bit-Mask xx11xxxx for Control Code Queue (obsolete) and Clear Fields */
#define AL_OBJCTLC_TC      0xC0    /* Bit-Mask 11xxxxxx for Control Code 'Trip/Close' */

#define AL_OBJCTLC_CODE0   0x00    /* xxxx0000 NUL Operation; only process R attribute */
#define AL_OBJCTLC_CODE1   0x01    /* xxxx0001 Pulse On ^On-Time -> vOff-Time, remain off */
#define AL_OBJCTLC_CODE2   0x02    /* xxxx0010 Pulse Off vOff-Time -> ^On-Time, remain on */
#define AL_OBJCTLC_CODE3   0x03    /* xxxx0011 Latch On */
#define AL_OBJCTLC_CODE4   0x04    /* xxxx0100 Latch Off */
                        /* 0x05-0x15  Reserved */

#define AL_OBJCTLC_QUEUE   0x10    /* xxx1xxxx for Control Code, Clear Field 'Queue' */
#define AL_OBJCTLC_CLEAR   0x20    /* xx1xxxxx for Control Code, Clear Field 'Clear' */
#define AL_OBJCTLC_NOTSET  0x00    /* xxxxxxxx for Control Code, Clear and Queue not set */
#define AL_OBJCTLC_BOTHSET 0x30    /* xx11xxxx for Control Code, Clear and Queue both set */

#define AL_OBJCTLC_TC0     0x00    /* 00xxxxxx NUL */
#define AL_OBJCTLC_TC1     0x40    /* 01xxxxxx Close */
#define AL_OBJCTLC_TC2     0x80    /* 10xxxxxx Trip */
#define AL_OBJCTLC_TC3     0xC0    /* 11xxxxxx Reserved */

#define AL_OBJCTL_STAT0    0x00    /* Request Accepted, Initiated or Queued */
#define AL_OBJCTL_STAT1    0x01    /* Request Not Accepted; Arm-timer expired */
#define AL_OBJCTL_STAT2    0x02    /* Request Not Accepted; No 'SELECT' rx'd */
#define AL_OBJCTL_STAT3    0x03    /* Request Not Accepted; Format errors in ctrl request */
#define AL_OBJCTL_STAT4    0x04    /* Control Operation Not Supported for this point */
#define AL_OBJCTL_STAT5    0x05    /* Request Not Accepted; Ctrl Queue full or pt. active */
#define AL_OBJCTL_STAT6    0x06    /* Request Not Accepted; Ctrl HW Problems */
#define AL_OBJCTL_STAT7    0x07    /* Request Not Accepted; Local/Remote switch in Local*/
#define AL_OBJCTL_STAT8    0x08    /* Request Not Accepted; Too many operations requested */
#define AL_OBJCTL_STAT9    0x09    /* Request Not Accepted; Insufficient authorization */
#define AL_OBJCTL_STAT10   0x0A    /* Request Not Accepted; Local automation proc active */

/* Binary Output Quality Flags */
#define AL_OBJ_BO_FLAG0    0x0001   /* Point Online (0=Offline; 1=Online) */
#define AL_OBJ_BO_FLAG1    0x0002   /* Restart (0=Normal; 1=Restart) */
#define AL_OBJ_BO_FLAG2    0x0004   /* Comms Lost (0=Normal; 1=Lost) */
#define AL_OBJ_BO_FLAG3    0x0008   /* Remote Force (0=Normal; 1=Forced) */
#define AL_OBJ_BO_FLAG4    0x0010   /* Local Force (0=Normal; 1=Forced) */
#define AL_OBJ_BO_FLAG5    0x0020   /* Reserved */
#define AL_OBJ_BO_FLAG6    0x0040   /* Reserved */
#define AL_OBJ_BO_FLAG7    0x0080   /* Point State (0=Off; 1=On) */

/***************************************************************************/
/* Counter Objects */
#define AL_OBJ_CTR_ALL     0x1400   /* 20 00 Binary Counter Default Variation */
#define AL_OBJ_CTR_32      0x1401   /* 20 01 32-Bit Binary Counter */
#define AL_OBJ_CTR_16      0x1402   /* 20 02 16-Bit Binary Counter */
#define AL_OBJ_DCTR_32     0x1403   /* 20 03 32-Bit Delta Counter */
#define AL_OBJ_DCTR_16     0x1404   /* 20 04 16-Bit Delta Counter */
#define AL_OBJ_CTR_32NF    0x1405   /* 20 05 32-Bit Binary Counter Without Flag */
#define AL_OBJ_CTR_16NF    0x1406   /* 20 06 16-Bit Binary Counter Without Flag */
#define AL_OBJ_DCTR_32NF   0x1407   /* 20 07 32-Bit Delta Counter Without Flag */
#define AL_OBJ_DCTR_16NF   0x1408   /* 20 08 16-Bit Delta Counter Without Flag */
#define AL_OBJ_FCTR_ALL    0x1500   /* 21 00 Frozen Binary Counter Default Variation */
#define AL_OBJ_FCTR_32     0x1501   /* 21 01 32-Bit Frozen Counter */
#define AL_OBJ_FCTR_16     0x1502   /* 21 02 16-Bit Frozen Counter */
#define AL_OBJ_FDCTR_32    0x1503   /* 21 03 32-Bit Frozen Delta Counter */
#define AL_OBJ_FDCTR_16    0x1504   /* 21 04 16-Bit Frozen Delta Counter */
#define AL_OBJ_FCTR_32T    0x1505   /* 21 05 32-Bit Frozen Counter w/ Time of Freeze */
#define AL_OBJ_FCTR_16T    0x1506   /* 21 06 16-Bit Frozen Counter w/ Time of Freeze */
#define AL_OBJ_FDCTR_32T   0x1507   /* 21 07 32-Bit Frozen Delta Counter w/ Time of Freeze */
#define AL_OBJ_FDCTR_16T   0x1508   /* 21 08 16-Bit Frozen Delta Counter w/ Time of Freeze */
#define AL_OBJ_FCTR_32NF   0x1509   /* 21 09 32-Bit Frozen Counter Without Flag */
#define AL_OBJ_FCTR_16NF   0x150A   /* 21 10 16-Bit Frozen Counter Without Flag */
#define AL_OBJ_FDCTR_32NF  0x150B   /* 21 11 32-Bit Frozen Delta Counter Without Flag */
#define AL_OBJ_FDCTR_16NF  0x150C   /* 21 12 16-Bit Frozen Delta Counter Without Flag */
#define AL_OBJ_CTRC_ALL    0x1600   /* 22 00 Counter Change Event Default Variation */
#define AL_OBJ_CTRC_32     0x1601   /* 22 01 32-Bit Counter Change Event w/o Time */
#define AL_OBJ_CTRC_16     0x1602   /* 22 02 16-Bit Counter Change Event w/o Time */
#define AL_OBJ_DCTRC_32    0x1603   /* 22 03 32-Bit Delta Counter Change Event w/o Time */
#define AL_OBJ_DCTRC_16    0x1604   /* 22 04 16-Bit Delta Counter Change Event w/o Time */
#define AL_OBJ_CTRC_32T    0x1605   /* 22 05 32-Bit Counter Change Event with Time */
#define AL_OBJ_CTRC_16T    0x1606   /* 22 06 16-Bit Counter Change Event with Time */
#define AL_OBJ_DCTRC_32T   0x1607   /* 22 07 32-Bit Delta Counter Change Event with Time */
#define AL_OBJ_DCTRC_16T   0x1608   /* 22 08 16-Bit Delta Counter Change Event with Time */
#define AL_OBJ_FCTRC_ALL   0x1700   /* 21 00 Frozen Binary Counter Change Event Default Variation */
#define AL_OBJ_FCTRC_32    0x1701   /* 21 01 32-Bit Frozen Counter Change Event */
#define AL_OBJ_FCTRC_16    0x1702   /* 21 02 16-Bit Frozen Counter Change Event */
#define AL_OBJ_FDCTRC_32   0x1703   /* 21 03 32-Bit Frozen Delta Counter Change Event */
#define AL_OBJ_FDCTRC_16   0x1704   /* 21 04 16-Bit Frozen Delta Counter Change Event */
#define AL_OBJ_FCTRC_32T   0x1705   /* 21 05 32-Bit Frozen Counter Change Event w/ Time of Freeze */
#define AL_OBJ_FCTRC_16T   0x1706   /* 21 06 16-Bit Frozen Counter Change Event w/ Time of Freeze */
#define AL_OBJ_FDCTRC_32T  0x1707   /* 21 07 32-Bit Frozen Delta Counter Change Event w/ Time of Freeze */
#define AL_OBJ_FDCTRC_16T  0x1708   /* 21 08 16-Bit Frozen Delta Counter Change Event w/ Time of Freeze */

/* Counter Quality Flags */
#define AL_OBJ_CTR_FLAG0   0x0001   /* Point Online (0=Offline; 1=Online) */
#define AL_OBJ_CTR_FLAG1   0x0002   /* Restart (0=Normal; 1=Restart) */
#define AL_OBJ_CTR_FLAG2   0x0004   /* Comms Lost (0=Normal; 1=Lost) */
#define AL_OBJ_CTR_FLAG3   0x0008   /* Remote Force (0=Normal; 1=Forced) */
#define AL_OBJ_CTR_FLAG4   0x0010   /* Local Force (0=Normal; 1=Forced) */
#define AL_OBJ_CTR_FLAG5   0x0020   /* Roll-over (0=Normal; 1=Roll-Over) */
#define AL_OBJ_CTR_FLAG6   0x0040   /* Discontinuity (0=Normal; 1=Discontinuity) */
#define AL_OBJ_CTR_FLAG7   0x0080   /* Reserved */

/***************************************************************************/
/* Analog Input Objects */
#define AL_OBJ_AI_ALL      0x1E00   /* 30 00 Analog Input Default Variation */
#define AL_OBJ_AI_32       0x1E01   /* 30 01 32-Bit Analog Input */
#define AL_OBJ_AI_16       0x1E02   /* 30 02 16-Bit Analog Input */
#define AL_OBJ_AI_32NF     0x1E03   /* 30 03 32-Bit Analog Input Without Flag */
#define AL_OBJ_AI_16NF     0x1E04   /* 30 04 16-Bit Analog Input Without Flag */
#define AL_OBJ_AI_FLT      0x1E05   /* 30 05 32-Bit Floating Point Input */
#define AL_OBJ_AI_DBL      0x1E06   /* 30 06 64-Bit Floating Point Input */
                        /* 0x1F01      31 01 32-Bit Frozen Analog Input */
                        /* 0x1F02      31 02 16-Bit Frozen Analog Input */
                        /* 0x1F03      31 03 32-Bit Frozen Analog Input w/ Time of Freeze */
                        /* 0x1F04      31 04 16-Bit Frozen Analog Input w/ Time of Freeze */
                        /* 0x1F05      31 05 32-Bit Frozen Analog Input Without Flag */
                        /* 0x1F06      31 06 16-Bit Frozen Analog Input Without Flag */
#define AL_OBJ_AIF_FLT     0x1F07   /* 31 07 32-Bit Frozen Floating Point Input */
#define AL_OBJ_AIF_DBL     0x1F08   /* 31 08 64-Bit Frozen Floating Point Input */
#define AL_OBJ_AIC_ALL     0x2000   /* 32 00 Analog Input Change Default Variation */
#define AL_OBJ_AIC_32NT    0x2001   /* 32 01 32-Bit Analog Change Event w/o Time */
#define AL_OBJ_AIC_16NT    0x2002   /* 32 02 16-Bit Analog Change Event w/o Time */
#define AL_OBJ_AIC_32T     0x2003   /* 32 03 32-Bit Analog Change Event w/ Time */
#define AL_OBJ_AIC_16T     0x2004   /* 32 04 16-Bit Analog Change Event w/ Time */
#define AL_OBJ_AIC_FLTNT   0x2005   /* 32 05 32-Bit Floating Point Change Event w/o Time*/
#define AL_OBJ_AIC_DBLNT   0x2006   /* 32 06 64-Bit Floating Point Change Event w/o Time*/
#define AL_OBJ_AIC_FLTT    0x2007   /* 32 07 32-Bit Floating Point Change Event w/ Time*/
#define AL_OBJ_AIC_DBLT    0x2008   /* 32 08 64-Bit Floating Point Change Event w/ Time*/
                        /* 0x2101      33 01 32-Bit Frozen Analog Event w/o Time */
                        /* 0x2102      33 02 16-Bit Frozen Analog Event w/o Time */
                        /* 0x2103      33 03 32-Bit Frozen Analog Event w/ Time */
                        /* 0x2104      33 04 16-Bit Frozen Analog Event w/ Time */
#define AL_OBJ_AIFC_FLTNT  0x2105   /* 33 05 32-Bit Floating Point Frozen Change Event w/o Time*/
#define AL_OBJ_AIFC_DBLNT  0x2106   /* 33 06 64-Bit Floating Point Frozen Change Event w/o Time*/
#define AL_OBJ_AIFC_FLTT   0x2107   /* 33 07 32-Bit Floating Point Frozen Change Event w/ Time*/
#define AL_OBJ_AIFC_DBLT   0x2108   /* 33 08 64-Bit Floating Point Frozen Change Event w/ Time*/

/* Analog Input Quality Flags */
#define AL_OBJ_AI_FLAG0    0x0001   /* Point Online (0=Offline; 1=Online) */
#define AL_OBJ_AI_FLAG1    0x0002   /* Restart (0=Normal; 1=Restart) */
#define AL_OBJ_AI_FLAG2    0x0004   /* Comms Lost (0=Normal; 1=Lost) */
#define AL_OBJ_AI_FLAG3    0x0008   /* Remote Force (0=Normal; 1=Forced) */
#define AL_OBJ_AI_FLAG4    0x0010   /* Local Force (0=Normal; 1=Forced) */
#define AL_OBJ_AI_FLAG5    0x0020   /* Over-Range (0=Normal; 1=Over-Range) */
#define AL_OBJ_AI_FLAG6    0x0040   /* Reference Check (0=Normal; 1=Error) */
#define AL_OBJ_AI_FLAG7    0x0080   /* Reserved */

#define AL_OBJ_AIDB_ALL    0x2200   /* 34 00 Analog Input Deadband Default Variation */
#define AL_OBJ_AIDB_16     0x2201   /* 34 01 16-Bit Analog Input Deadband */
#define AL_OBJ_AIDB_32     0x2202   /* 34 02 32-Bit Analog Input Deadband */
#define AL_OBJ_AIDB_FLT    0x2203   /* 34 03 Floating Point Analog Input Deadband */

/***************************************************************************/
/* Analog Output Objects */
#define AL_OBJ_AO_ALL      0x2800   /* 40 00 Analog Output Default Variation */
#define AL_OBJ_AO_32       0x2801   /* 40 01 32-Bit Analog Output Status */
#define AL_OBJ_AO_16       0x2802   /* 40 02 16-Bit Analog Output Status */
#define AL_OBJ_AO_FLT      0x2803   /* 40 03 32-Bit Floating Point Output Status */
#define AL_OBJ_AO_DBL      0x2804   /* 40 04 64-Bit Floating Point Output Status */
#define AL_OBJ_AO_32OPB    0x2901   /* 41 01 32-Bit Analog Output Block */
#define AL_OBJ_AO_16OPB    0x2902   /* 41 02 16-Bit Analog Output Block */
#define AL_OBJ_AO_FLTOPB   0x2903   /* 41 03 32-Bit Floating Point Output Block */
#define AL_OBJ_AO_DBLOPB   0x2904   /* 41 04 64-Bit Floating Point Output Block */
#define AL_OBJ_AOC_ALL     0x2A00   /* 42 00 Analog Output Event Default Variation */
#define AL_OBJ_AOC_32NT    0x2A01   /* 42 01 32-Bit Analog Output Event w/o Time */
#define AL_OBJ_AOC_16NT    0x2A02   /* 42 02 16-Bit Analog Output Event w/o Time */
#define AL_OBJ_AOC_32T     0x2A03   /* 42 03 32-Bit Analog Output Event w/ Time */
#define AL_OBJ_AOC_16T     0x2A04   /* 42 04 16-Bit Analog Output Event w/ Time */
#define AL_OBJ_AOC_FLTNT   0x2A05   /* 42 05 32-Bit Floating Point Output Event w/o Time*/
#define AL_OBJ_AOC_DBLNT   0x2A06   /* 42 06 64-Bit Floating Point Output Event w/o Time*/
#define AL_OBJ_AOC_FLTT    0x2A07   /* 42 07 32-Bit Floating Point Output Event w/ Time*/
#define AL_OBJ_AOC_DBLT    0x2A08   /* 42 08 64-Bit Floating Point Output Event w/ Time*/

/* Analog Output Quality Flags */
#define AL_OBJ_AO_FLAG0    0x0001   /* Point Online (0=Offline; 1=Online) */
#define AL_OBJ_AO_FLAG1    0x0002   /* Restart (0=Normal; 1=Restart) */
#define AL_OBJ_AO_FLAG2    0x0004   /* Comms Lost (0=Normal; 1=Lost) */
#define AL_OBJ_AO_FLAG3    0x0008   /* Remote Force (0=Normal; 1=Forced) */
#define AL_OBJ_AO_FLAG4    0x0010   /* Local Force (0=Normal; 1=Forced) */
#define AL_OBJ_AO_FLAG5    0x0020   /* Reserved */
#define AL_OBJ_AO_FLAG6    0x0040   /* Reserved */
#define AL_OBJ_AO_FLAG7    0x0080   /* Reserved */

/***************************************************************************/
/* Time Objects */
#define AL_OBJ_TD_ALL      0x3200   /* 50 00 Time and Date Default Variation */
#define AL_OBJ_TD          0x3201   /* 50 01 Time and Date */
#define AL_OBJ_TDI         0x3202   /* 50 02 Time and Date w/ Interval */
#define AL_OBJ_TDR         0x3203   /* 50 03 Last Recorded Time and Date */
#define AL_OBJ_TDCTO       0x3301   /* 51 01 Time and Date CTO */
#define AL_OBJ_UTDCTO      0x3302   /* 51 02 Unsynchronized Time and Date CTO */
#define AL_OBJ_TDELAYC     0x3401   /* 52 01 Time Delay Coarse */
#define AL_OBJ_TDELAYF     0x3402   /* 52 02 Time Delay Fine */

/***************************************************************************/
/* Class Data Objects */
#define AL_OBJ_CLASS0      0x3C01   /* 60 01 Class 0 Data */
#define AL_OBJ_CLASS1      0x3C02   /* 60 02 Class 1 Data */
#define AL_OBJ_CLASS2      0x3C03   /* 60 03 Class 2 Data */
#define AL_OBJ_CLASS3      0x3C04   /* 60 04 Class 3 Data */

/***************************************************************************/
/* File Objects */
#define AL_OBJ_FILE_CMD         0x4603   /* 70 03 File Control - Command */
#define AL_OBJ_FILE_STAT        0x4604   /* 70 04 File Control - Status */
#define AL_OBJ_FILE_TRANS       0x4605   /* 70 05 File Control - Transport */
#define AL_OBJ_FILE_TRAN_ST     0x4606   /* 70 05 File Control - Transport Status */

/* File Control Mode flags */
#define AL_OBJ_FILE_MODE_NULL   0x00   /* NULL */
#define AL_OBJ_FILE_MODE_READ   0x01   /* READ */
#define AL_OBJ_FILE_MODE_WRITE  0x02   /* WRITE */
#define AL_OBJ_FILE_MODE_APPEND 0x03   /* APPEND */


/***************************************************************************/
/* Device Objects */
#define AL_OBJ_IIN         0x5001   /* 80 01 Internal Indications */

/***************************************************************************/
/* Octet String Objects */
#define AL_OBJ_OCT         0x6E00   /* 110 xx Octet string */
#define AL_OBJ_OCT_EVT     0x6F00   /* 110 xx Octet string event */

/***************************************************************************/
/* End of Application Layer Data Object Definitions */
/***************************************************************************/

/* Initialize the protocol and registered fields */
static int proto_dnp3 = -1;
static int hf_dnp3_start = -1;
static int hf_dnp3_len = -1;
static int hf_dnp3_ctl = -1;
static int hf_dnp3_ctl_prifunc = -1;
static int hf_dnp3_ctl_secfunc = -1;
static int hf_dnp3_ctl_dir = -1;
static int hf_dnp3_ctl_prm = -1;
static int hf_dnp3_ctl_fcb = -1;
static int hf_dnp3_ctl_fcv = -1;
static int hf_dnp3_ctl_dfc = -1;
static int hf_dnp3_dst = -1;
static int hf_dnp3_src = -1;
static int hf_dnp_hdr_CRC = -1;
static int hf_dnp_hdr_CRC_bad = -1;
static int hf_dnp3_tr_ctl = -1;
static int hf_dnp3_tr_fin = -1;
static int hf_dnp3_tr_fir = -1;
static int hf_dnp3_tr_seq = -1;
static int hf_dnp3_al_ctl = -1;
static int hf_dnp3_al_fir = -1;
static int hf_dnp3_al_fin = -1;
static int hf_dnp3_al_con = -1;
static int hf_dnp3_al_uns = -1;
static int hf_dnp3_al_seq = -1;
static int hf_dnp3_al_func = -1;
/* Added for Application Layer Decoding */
static int hf_dnp3_al_iin = -1;
static int hf_dnp3_al_iin_bmsg = -1;
static int hf_dnp3_al_iin_cls1d = -1;
static int hf_dnp3_al_iin_cls2d = -1;
static int hf_dnp3_al_iin_cls3d = -1;
static int hf_dnp3_al_iin_tsr = -1;
static int hf_dnp3_al_iin_dol = -1;
static int hf_dnp3_al_iin_dt = -1;
static int hf_dnp3_al_iin_rst = -1;
static int hf_dnp3_al_iin_fcni = -1;
static int hf_dnp3_al_iin_obju = -1;
static int hf_dnp3_al_iin_pioor = -1;
static int hf_dnp3_al_iin_ebo = -1;
static int hf_dnp3_al_iin_oae = -1;
static int hf_dnp3_al_iin_cc = -1;
static int hf_dnp3_al_obj = -1;
static int hf_dnp3_al_objq_index = -1;
static int hf_dnp3_al_objq_code = -1;
static int hf_dnp3_al_range_start8 = -1;
static int hf_dnp3_al_range_stop8 = -1;
static int hf_dnp3_al_range_start16 = -1;
static int hf_dnp3_al_range_stop16 = -1;
static int hf_dnp3_al_range_start32 = -1;
static int hf_dnp3_al_range_stop32 = -1;
static int hf_dnp3_al_range_abs8 = -1;
static int hf_dnp3_al_range_abs16 = -1;
static int hf_dnp3_al_range_abs32 = -1;
static int hf_dnp3_al_range_quant8 = -1;
static int hf_dnp3_al_range_quant16 = -1;
static int hf_dnp3_al_range_quant32 = -1;
static int hf_dnp3_al_index8 = -1;
static int hf_dnp3_al_index16 = -1;
static int hf_dnp3_al_index32 = -1;
static int hf_dnp3_al_size8 = -1;
static int hf_dnp3_al_size16 = -1;
static int hf_dnp3_al_size32 = -1;

/*static int hf_dnp3_al_objq = -1;
  static int hf_dnp3_al_nobj = -1; */
/* XXX - unused
static int hf_dnp3_al_ptnum = -1; */
static int hf_dnp3_al_biq_b0 = -1;
static int hf_dnp3_al_biq_b1 = -1;
static int hf_dnp3_al_biq_b2 = -1;
static int hf_dnp3_al_biq_b3 = -1;
static int hf_dnp3_al_biq_b4 = -1;
static int hf_dnp3_al_biq_b5 = -1;
static int hf_dnp3_al_biq_b6 = -1;
static int hf_dnp3_al_biq_b7 = -1;
static int hf_dnp3_al_boq_b0 = -1;
static int hf_dnp3_al_boq_b1 = -1;
static int hf_dnp3_al_boq_b2 = -1;
static int hf_dnp3_al_boq_b3 = -1;
static int hf_dnp3_al_boq_b4 = -1;
static int hf_dnp3_al_boq_b5 = -1;
static int hf_dnp3_al_boq_b6 = -1;
static int hf_dnp3_al_boq_b7 = -1;
static int hf_dnp3_al_ctrq_b0 = -1;
static int hf_dnp3_al_ctrq_b1 = -1;
static int hf_dnp3_al_ctrq_b2 = -1;
static int hf_dnp3_al_ctrq_b3 = -1;
static int hf_dnp3_al_ctrq_b4 = -1;
static int hf_dnp3_al_ctrq_b5 = -1;
static int hf_dnp3_al_ctrq_b6 = -1;
static int hf_dnp3_al_ctrq_b7 = -1;
static int hf_dnp3_al_aiq_b0 = -1;
static int hf_dnp3_al_aiq_b1 = -1;
static int hf_dnp3_al_aiq_b2 = -1;
static int hf_dnp3_al_aiq_b3 = -1;
static int hf_dnp3_al_aiq_b4 = -1;
static int hf_dnp3_al_aiq_b5 = -1;
static int hf_dnp3_al_aiq_b6 = -1;
static int hf_dnp3_al_aiq_b7 = -1;
static int hf_dnp3_al_aoq_b0 = -1;
static int hf_dnp3_al_aoq_b1 = -1;
static int hf_dnp3_al_aoq_b2 = -1;
static int hf_dnp3_al_aoq_b3 = -1;
static int hf_dnp3_al_aoq_b4 = -1;
static int hf_dnp3_al_aoq_b5 = -1;
static int hf_dnp3_al_aoq_b6 = -1;
static int hf_dnp3_al_aoq_b7 = -1;
static int hf_dnp3_al_timestamp = -1;
static int hf_dnp3_al_file_perms = -1;
static int hf_dnp3_al_file_perms_read_owner = -1;
static int hf_dnp3_al_file_perms_write_owner = -1;
static int hf_dnp3_al_file_perms_exec_owner = -1;
static int hf_dnp3_al_file_perms_read_group = -1;
static int hf_dnp3_al_file_perms_write_group = -1;
static int hf_dnp3_al_file_perms_exec_group = -1;
static int hf_dnp3_al_file_perms_read_world = -1;
static int hf_dnp3_al_file_perms_write_world = -1;
static int hf_dnp3_al_file_perms_exec_world = -1;
static int hf_dnp3_al_rel_timestamp = -1;
static int hf_dnp3_al_ana16 = -1;
static int hf_dnp3_al_ana32 = -1;
static int hf_dnp3_al_anaflt = -1;
static int hf_dnp3_al_anadbl = -1;
static int hf_dnp3_al_bit = -1;
static int hf_dnp3_al_2bit = -1;
static int hf_dnp3_al_cnt16 = -1;
static int hf_dnp3_al_cnt32 = -1;
static int hf_dnp3_al_ctrlstatus = -1;
static int hf_dnp3_al_anaout16 = -1;
static int hf_dnp3_al_anaout32 = -1;
static int hf_dnp3_al_anaoutflt = -1;
static int hf_dnp3_al_anaoutdbl = -1;
static int hf_dnp3_al_file_mode = -1;
static int hf_dnp3_al_file_auth = -1;
static int hf_dnp3_al_file_size = -1;
static int hf_dnp3_al_file_maxblk = -1;
static int hf_dnp3_al_file_reqID = -1;
static int hf_dnp3_al_file_handle = -1;
static int hf_dnp3_al_file_status = -1;
static int hf_dnp3_al_file_blocknum = -1;
static int hf_dnp3_al_file_lastblock = -1;
static int hf_dnp3_al_file_data = -1;
static int hf_dnp3_ctlobj_code_c = -1;
static int hf_dnp3_ctlobj_code_m = -1;
static int hf_dnp3_ctlobj_code_tc = -1;

/***************************************************************************/
/* Value String Look-Ups */
/***************************************************************************/
static const value_string dnp3_ctl_func_pri_vals[] = {
  { DL_FUNC_RESET_LINK, "Reset of Remote Link" },
  { DL_FUNC_RESET_PROC, "Reset of User Process" },
  { DL_FUNC_TEST_LINK,  "Test Function For Link" },
  { DL_FUNC_USER_DATA,  "User Data" },
  { DL_FUNC_UNC_DATA,   "Unconfirmed User Data" },
  { DL_FUNC_LINK_STAT,  "Request Link Status" },
  { 0, NULL }
};

static const value_string dnp3_ctl_func_sec_vals[] = {
  { DL_FUNC_ACK,        "ACK" },
  { DL_FUNC_NACK,       "NACK" },
  { DL_FUNC_STAT_LINK,  "Status of Link" },
  { DL_FUNC_NO_FUNC,    "Link Service Not Functioning" },
  { DL_FUNC_NOT_IMPL,   "Link Service Not Used or Implemented" },
  { 0,  NULL }
};

static const value_string dnp3_ctl_flags_pri_vals[] _U_ = {
  { DNP3_CTL_DIR, "DIR" },
  { DNP3_CTL_PRM, "PRM" },
  { DNP3_CTL_FCB, "FCB" },
  { DNP3_CTL_FCV, "FCV" },
  { 0,  NULL }
};

static const value_string dnp3_ctl_flags_sec_vals[] _U_ = {
  { DNP3_CTL_DIR, "DIR" },
  { DNP3_CTL_PRM, "PRM" },
  { DNP3_CTL_RES, "RES" },
  { DNP3_CTL_DFC, "DFC" },
  { 0,  NULL }
};

static const value_string dnp3_tr_flags_vals[] _U_ = {
  { DNP3_TR_FIN,  "FIN" },
  { DNP3_TR_FIR,  "FIR" },
  { 0,  NULL }
};

static const value_string dnp3_al_flags_vals[] _U_ = {
  { DNP3_AL_FIR,  "FIR" },
  { DNP3_AL_FIN,  "FIN" },
  { DNP3_AL_CON,  "CON" },
  { DNP3_AL_UNS,  "UNS" },
  { 0,  NULL }
};

/* Application Layer Function Code Values */
static const value_string dnp3_al_func_vals[] = {
  { AL_FUNC_CONFIRM,    "Confirm" },
  { AL_FUNC_READ,       "Read" },
  { AL_FUNC_WRITE,      "Write" },
  { AL_FUNC_SELECT,     "Select" },
  { AL_FUNC_OPERATE,    "Operate" },
  { AL_FUNC_DIROP,      "Direct Operate" },
  { AL_FUNC_DIROPNACK,  "Direct Operate No Ack" },
  { AL_FUNC_FRZ,        "Immediate Freeze" },
  { AL_FUNC_FRZNACK,    "Immediate Freeze No Ack" },
  { AL_FUNC_FRZCLR,     "Freeze and Clear" },
  { AL_FUNC_FRZCLRNACK, "Freeze and Clear No ACK" },
  { AL_FUNC_FRZT,       "Freeze With Time" },
  { AL_FUNC_FRZTNACK,   "Freeze With Time No ACK" },
  { AL_FUNC_COLDRST,    "Cold Restart" },
  { AL_FUNC_WARMRST,    "Warm Restart" },
  { AL_FUNC_INITDATA,   "Initialize Data" },
  { AL_FUNC_INITAPP,    "Initialize Application" },
  { AL_FUNC_STARTAPP,   "Start Application" },
  { AL_FUNC_STOPAPP,    "Stop Application" },
  { AL_FUNC_SAVECFG,    "Save Configuration" },
  { AL_FUNC_ENSPMSG,    "Enable Spontaneous Messages" },
  { AL_FUNC_DISSPMSG,   "Disable Spontaneous Messages" },
  { AL_FUNC_ASSIGNCL,   "Assign Classes" },
  { AL_FUNC_DELAYMST,   "Delay Measurement" },
  { AL_FUNC_RECCT,      "Record Current Time" },
  { AL_FUNC_OPENFILE,   "Open File" },
  { AL_FUNC_CLOSEFILE,  "Close File" },
  { AL_FUNC_DELETEFILE, "Delete File" },
  { AL_FUNC_GETFILEINF, "Get File Info" },
  { AL_FUNC_AUTHFILE,   "Authenticate File" },
  { AL_FUNC_ABORTFILE,  "Abort File" },
  { AL_FUNC_ACTCNF,     "Activate Config" },
  { AL_FUNC_AUTHREQ,    "Authentication Request" },
  { AL_FUNC_AUTHERR,    "Authentication Error" },
  { AL_FUNC_RESPON,     "Response" },
  { AL_FUNC_UNSOLI,     "Unsolicited Response" },
  { AL_FUNC_AUTHRESP,   "Authentication Response" },
  { 0, NULL }
};
static value_string_ext dnp3_al_func_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_func_vals);

/* Application Layer Internal Indication (IIN) bit Values */
static const value_string dnp3_al_iin_vals[] _U_ = {
  { AL_IIN_BMSG,    "Broadcast message Rx'd" },
  { AL_IIN_CLS1D,   "Class 1 Data Available" },
  { AL_IIN_CLS2D,   "Class 2 Data Available" },
  { AL_IIN_CLS3D,   "Class 3 Data Available" },
  { AL_IIN_TSR,     "Time Sync Required from Master" },
  { AL_IIN_DOL,     "Outputs in Local Mode" },
  { AL_IIN_DT,      "Device Trouble" },
  { AL_IIN_RST,     "Device Restart" },
  { AL_IIN_FCNI,    "Function Code not implemented" },
  { AL_IIN_OBJU,    "Requested Objects Unknown" },
  { AL_IIN_PIOOR,   "Parameters Invalid or Out of Range" },
  { AL_IIN_EBO,     "Event Buffer Overflow" },
  { AL_IIN_OAE,     "Operation Already Executing" },
  { AL_IIN_CC,      "Device Configuration Corrupt" },
  { 0, NULL }
};

/* Application Layer Object Qualifier Index Values When Qualifier Code != 11 */
static const value_string dnp3_al_objq_index_vals[] = {
  { AL_OBJQL_IDX_NI,    "None" },
  { AL_OBJQL_IDX_1O,    "1-Octet Indexing" },
  { AL_OBJQL_IDX_2O,    "2-Octet Indexing" },
  { AL_OBJQL_IDX_4O,    "4-Octet Indexing" },
  { AL_OBJQL_IDX_1OS,   "1-Octet Object Size" },
  { AL_OBJQL_IDX_2OS,   "2-Octet Object Size" },
  { AL_OBJQL_IDX_4OS,   "4-Octet Object Size" },
  { 0, NULL }
};
static value_string_ext dnp3_al_objq_index_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_objq_index_vals);

/* Application Layer Object Qualifier Code Values */
static const value_string dnp3_al_objq_code_vals[] = {
  { AL_OBJQL_CODE_SSI8,     "8-bit Start and Stop Indices" },
  { AL_OBJQL_CODE_SSI16,    "16-bit Start and Stop Indices" },
  { AL_OBJQL_CODE_SSI32,    "32-bit Start and Stop Indices" },
  { AL_OBJQL_CODE_AA8,      "8-bit Absolute Address in Range Field" },
  { AL_OBJQL_CODE_AA16,     "16-bit Absolute Address in Range Field" },
  { AL_OBJQL_CODE_AA32,     "32-bit Absolute Address in Range Field" },
  { AL_OBJQL_CODE_R0,       "No Range Field" },
  { AL_OBJQL_CODE_SF8,      "8-bit Single Field Quantity" },
  { AL_OBJQL_CODE_SF16,     "16-bit Single Field Quantity" },
  { AL_OBJQL_CODE_SF32,     "32-bit Single Field Quantity" },
  { 10,                     "Reserved" },
  { AL_OBJQL_CODE_FF,       "Free-format Qualifier" },
  { 0, NULL }
};
static value_string_ext dnp3_al_objq_code_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_objq_code_vals);

/* Application Layer Data Object Values */
static const value_string dnp3_al_obj_vals[] = {
  { AL_OBJ_BI_ALL,     "Binary Input Default Variation (Obj:01, Var:Default)" },
  { AL_OBJ_BI_1BIT,    "Single-Bit Binary Input (Obj:01, Var:01)" },
  { AL_OBJ_BI_STAT,    "Binary Input With Status (Obj:01, Var:02)" },
  { AL_OBJ_BIC_ALL,    "Binary Input Change Default Variation (Obj:02, Var:Default)" },
  { AL_OBJ_BIC_NOTIME, "Binary Input Change Without Time (Obj:02, Var:01)" },
  { AL_OBJ_BIC_TIME,   "Binary Input Change With Time (Obj:02, Var:02)" },
  { AL_OBJ_BIC_RTIME,  "Binary Input Change With Relative Time (Obj:02, Var:03)" },
  { AL_OBJ_2BI_ALL,    "Double-bit Input Default Variation (Obj:03, Var:Default)" },
  { AL_OBJ_2BI_NF,     "Double-bit Input No Flags (Obj:03, Var:01)" },
  { AL_OBJ_2BI_STAT,   "Double-bit Input With Status (Obj:03, Var:02)" },
  { AL_OBJ_2BIC_NOTIME, "Double-bit Input Change Without Time (Obj:04, Var:01)" },
  { AL_OBJ_2BIC_TIME,  "Double-bit Input Change With Time (Obj:04, Var:02)" },
  { AL_OBJ_2BIC_RTIME, "Double-bit Input Change With Relative Time (Obj:04, Var:03)" },
  { AL_OBJ_BO_ALL,     "Binary Output Default Variation (Obj:10, Var:Default)" },
  { AL_OBJ_BO,         "Binary Output (Obj:10, Var:01)" },
  { AL_OBJ_BO_STAT,    "Binary Output Status (Obj:10, Var:02)" },
  { AL_OBJ_BOC_ALL,    "Binary Output Change Default Variation (Obj:11, Var:Default)" },
  { AL_OBJ_BOC_NOTIME, "Binary Output Change Without Time (Obj:11, Var:01)" },
  { AL_OBJ_BOC_TIME,   "Binary Output Change With Time (Obj:11, Var:02)" },
  { AL_OBJ_CTLOP_BLK,  "Control Relay Output Block (Obj:12, Var:01)" },
  { AL_OBJ_CTR_ALL,    "Binary Counter Default Variation (Obj:20, Var:Default)" },
  { AL_OBJ_CTR_32,     "32-Bit Binary Counter (Obj:20, Var:01)" },
  { AL_OBJ_CTR_16,     "16-Bit Binary Counter (Obj:20, Var:02)" },
  { AL_OBJ_DCTR_32,    "32-Bit Binary Delta Counter (Obj:20, Var:03)" },
  { AL_OBJ_DCTR_16,    "16-Bit Binary Delta Counter (Obj:20, Var:04)" },
  { AL_OBJ_CTR_32NF,   "32-Bit Binary Counter Without Flag (Obj:20, Var:05)" },
  { AL_OBJ_CTR_16NF,   "16-Bit Binary Counter Without Flag (Obj:20, Var:06)" },
  { AL_OBJ_DCTR_32NF,  "32-Bit Binary Delta Counter Without Flag (Obj:20, Var:07)" },
  { AL_OBJ_DCTR_16NF,  "16-Bit Binary Delta Counter Without Flag (Obj:20, Var:08)" },
  { AL_OBJ_FCTR_ALL,   "Frozen Binary Counter Default Variation (Obj:21, Var:Default)" },
  { AL_OBJ_FCTR_32,    "32-Bit Frozen Binary Counter (Obj:21, Var:01)" },
  { AL_OBJ_FCTR_16,    "16-Bit Frozen Binary Counter (Obj:21, Var:02)" },
  { AL_OBJ_FDCTR_32,   "32-Bit Frozen Binary Delta Counter (Obj:21, Var:03)" },
  { AL_OBJ_FDCTR_16,   "16-Bit Frozen Binary Delta Counter (Obj:21, Var:04)" },
  { AL_OBJ_FCTR_32T,   "32-Bit Frozen Binary Counter (Obj:21, Var:01)" },
  { AL_OBJ_FCTR_16T,   "16-Bit Frozen Binary Counter (Obj:21, Var:02)" },
  { AL_OBJ_FDCTR_32T,  "32-Bit Frozen Binary Delta Counter (Obj:21, Var:03)" },
  { AL_OBJ_FDCTR_16T,  "16-Bit Frozen Binary Delta Counter (Obj:21, Var:04)" },
  { AL_OBJ_FCTR_32NF,  "32-Bit Frozen Binary Counter Without Flag (Obj:21, Var:05)" },
  { AL_OBJ_FCTR_16NF,  "16-Bit Frozen Binary Counter Without Flag (Obj:21, Var:06)" },
  { AL_OBJ_FDCTR_32NF, "32-Bit Frozen Binary Delta Counter Without Flag (Obj:21, Var:07)" },
  { AL_OBJ_FDCTR_16NF, "16-Bit Frozen Binary Delta Counter Without Flag (Obj:21, Var:08)" },
  { AL_OBJ_CTRC_ALL,   "Binary Counter Change Default Variation (Obj:22, Var:Default)" },
  { AL_OBJ_CTRC_32,    "32-Bit Counter Change Event w/o Time (Obj:22, Var:01)" },
  { AL_OBJ_CTRC_16,    "16-Bit Counter Change Event w/o Time (Obj:22, Var:02)" },
  { AL_OBJ_DCTRC_32,   "32-Bit Delta Counter Change Event w/o Time (Obj:22, Var:03)" },
  { AL_OBJ_DCTRC_16,   "16-Bit Delta Counter Change Event w/o Time (Obj:22, Var:04)" },
  { AL_OBJ_CTRC_32T,   "32-Bit Counter Change Event with Time (Obj:22, Var:05)" },
  { AL_OBJ_CTRC_16T,   "16-Bit Counter Change Event with Time (Obj:22, Var:06)" },
  { AL_OBJ_DCTRC_32T,  "32-Bit Delta Counter Change Event with Time (Obj:22, Var:07)" },
  { AL_OBJ_DCTRC_16T,  "16-Bit Delta Counter Change Event with Time (Obj:22, Var:08)" },
  { AL_OBJ_FCTRC_ALL,  "Frozen Binary Counter Change Default Variation (Obj:23, Var:Default)" },
  { AL_OBJ_FCTRC_32,   "32-Bit Frozen Counter Change Event w/o Time (Obj:23, Var:01)" },
  { AL_OBJ_FCTRC_16,   "16-Bit Frozen Counter Change Event w/o Time (Obj:23, Var:02)" },
  { AL_OBJ_FDCTRC_32,  "32-Bit Frozen Delta Counter Change Event w/o Time (Obj:23, Var:03)" },
  { AL_OBJ_FDCTRC_16,  "16-Bit Frozen Delta Counter Change Event w/o Time (Obj:23, Var:04)" },
  { AL_OBJ_FCTRC_32T,  "32-Bit Frozen Counter Change Event with Time (Obj:23, Var:05)" },
  { AL_OBJ_FCTRC_16T,  "16-Bit Frozen Counter Change Event with Time (Obj:23, Var:06)" },
  { AL_OBJ_FDCTRC_32T, "32-Bit Frozen Delta Counter Change Event with Time (Obj:23, Var:07)" },
  { AL_OBJ_FDCTRC_16T, "16-Bit Frozen Delta Counter Change Event with Time (Obj:23, Var:08)" },
  { AL_OBJ_AI_ALL,     "Analog Input Default Variation (Obj:30, Var:Default)" },
  { AL_OBJ_AI_32,      "32-Bit Analog Input (Obj:30, Var:01)" },
  { AL_OBJ_AI_16,      "16-Bit Analog Input (Obj:30, Var:02)" },
  { AL_OBJ_AI_32NF,    "32-Bit Analog Input Without Flag (Obj:30, Var:03)" },
  { AL_OBJ_AI_16NF,    "16-Bit Analog Input Without Flag (Obj:30, Var:04)" },
  { AL_OBJ_AI_FLT,     "32-Bit Floating Point Input (Obj:30, Var:05)" },
  { AL_OBJ_AI_DBL,     "64-Bit Floating Point Input (Obj:30, Var:06)" },
  { AL_OBJ_AIF_FLT,    "32-Bit Frozen Floating Point Input (Obj:31, Var:07)" },
  { AL_OBJ_AIF_DBL,    "64-Bit Frozen Floating Point Input (Obj:31, Var:08)" },
  { AL_OBJ_AIC_ALL,    "Analog Input Change Default Variation (Obj:32, Var:Default)" },
  { AL_OBJ_AIC_32NT,   "32-Bit Analog Change Event w/o Time (Obj:32, Var:01)" },
  { AL_OBJ_AIC_16NT,   "16-Bit Analog Change Event w/o Time (Obj:32, Var:02)" },
  { AL_OBJ_AIC_32T,    "32-Bit Analog Change Event with Time (Obj:32, Var:03)" },
  { AL_OBJ_AIC_16T,    "16-Bit Analog Change Event with Time (Obj:32, Var:04)" },
  { AL_OBJ_AIC_FLTNT,  "32-Bit Floating Point Change Event w/o Time (Obj:32, Var:05)" },
  { AL_OBJ_AIC_DBLNT,  "64-Bit Floating Point Change Event w/o Time (Obj:32, Var:06)" },
  { AL_OBJ_AIC_FLTT,   "32-Bit Floating Point Change Event w/ Time (Obj:32, Var:07)" },
  { AL_OBJ_AIC_DBLT,   "64-Bit Floating Point Change Event w/ Time (Obj:32, Var:08)" },
  { AL_OBJ_AIFC_FLTNT, "32-Bit Floating Point Frozen Change Event w/o Time (Obj:33, Var:05)" },
  { AL_OBJ_AIFC_DBLNT, "64-Bit Floating Point Frozen Change Event w/o Time (Obj:33, Var:06)" },
  { AL_OBJ_AIFC_FLTT,  "32-Bit Floating Point Frozen Change Event w/ Time (Obj:33, Var:07)" },
  { AL_OBJ_AIFC_DBLT,  "64-Bit Floating Point Frozen Change Event w/ Time (Obj:33, Var:08)" },
  { AL_OBJ_AIDB_ALL,   "Analog Input Deadband Default Variation (Obj:34, Var:Default)" },
  { AL_OBJ_AIDB_16,    "16-Bit Analog Input Deadband (Obj:34, Var:01)" },
  { AL_OBJ_AIDB_32,    "32-Bit Analog Input Deadband (Obj:34, Var:02)" },
  { AL_OBJ_AIDB_FLT,   "32-Bit Floating Point Analog Input Deadband (Obj:34, Var:03)" },
  { AL_OBJ_AO_ALL,     "Analog Output Default Variation (Obj:40, Var:Default)" },
  { AL_OBJ_AO_32,      "32-Bit Analog Output Status (Obj:40, Var:01)" },
  { AL_OBJ_AO_16,      "16-Bit Analog Output Status (Obj:40, Var:02)" },
  { AL_OBJ_AO_FLT,     "32-Bit Floating Point Output Status (Obj:40, Var:03)" },
  { AL_OBJ_AO_DBL,     "64-Bit Floating Point Output Status (Obj:40, Var:04)" },
  { AL_OBJ_AO_32OPB,   "32-Bit Analog Output Block (Obj:41, Var:01)" },
  { AL_OBJ_AO_16OPB,   "16-Bit Analog Output Block (Obj:41, Var:02)" },
  { AL_OBJ_AO_FLTOPB,  "32-Bit Floating Point Output Block (Obj:41, Var:03)" },
  { AL_OBJ_AO_DBLOPB,  "64-Bit Floating Point Output Block (Obj:41, Var:04)" },
  { AL_OBJ_AOC_ALL,    "Analog Output Event Default Variation (Obj:42, Var:Default)" },
  { AL_OBJ_AOC_32NT,   "32-Bit Analog Output Event w/o Time (Obj:42, Var:01)" },
  { AL_OBJ_AOC_16NT,   "16-Bit Analog Output Event w/o Time (Obj:42, Var:02)" },
  { AL_OBJ_AOC_32T,    "32-Bit Analog Output Event with Time (Obj:42, Var:03)" },
  { AL_OBJ_AOC_16T,    "16-Bit Analog Output Event with Time (Obj:42, Var:04)" },
  { AL_OBJ_AOC_FLTNT,  "32-Bit Floating Point Output Event w/o Time (Obj:42, Var:05)" },
  { AL_OBJ_AOC_DBLNT,  "64-Bit Floating Point Output Event w/o Time (Obj:42, Var:06)" },
  { AL_OBJ_AOC_FLTT,   "32-Bit Floating Point Output Event w/ Time (Obj:42, Var:07)" },
  { AL_OBJ_AOC_DBLT,   "64-Bit Floating Point Output Event w/ Time (Obj:42, Var:08)" },
  { AL_OBJ_TD_ALL,     "Time and Date Default Variations (Obj:50, Var:Default)" },
  { AL_OBJ_TD,         "Time and Date (Obj:50, Var:01)" },
  { AL_OBJ_TDI,        "Time and Date w/Interval (Obj:50, Var:02)" },
  { AL_OBJ_TDR,        "Last Recorded Time and Date (Obj:50, Var:03)" },
  { AL_OBJ_TDCTO,      "Time and Date CTO (Obj:51, Var:01)" },
  { AL_OBJ_TDELAYF,    "Time Delay - Fine (Obj:52, Var:02)" },
  { AL_OBJ_CLASS0,     "Class 0 Data (Obj:60, Var:01)" },
  { AL_OBJ_CLASS1,     "Class 1 Data (Obj:60, Var:02)" },
  { AL_OBJ_CLASS2,     "Class 2 Data (Obj:60, Var:03)" },
  { AL_OBJ_CLASS3,     "Class 3 Data (Obj:60, Var:04)" },
  { AL_OBJ_FILE_CMD,   "File Control - File Command (Obj:70, Var:03)" },
  { AL_OBJ_FILE_STAT,  "File Control - File Status (Obj:70, Var:04)" },
  { AL_OBJ_FILE_TRANS, "File Control - File Transport (Obj:70, Var:05)" },
  { AL_OBJ_FILE_TRAN_ST, "File Control - File Transport Status (Obj:70, Var:06)" },
  { AL_OBJ_IIN,        "Internal Indications (Obj:80, Var:01)" },
  { AL_OBJ_OCT,        "Octet String (Obj:110)" },
  { AL_OBJ_OCT_EVT,    "Octet String Event (Obj:111)" },
  { 0, NULL }
};
static value_string_ext dnp3_al_obj_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_obj_vals);

/* Application Layer Control Code 'Operation Type' Values */
static const value_string dnp3_al_ctlc_code_vals[] = {
  { AL_OBJCTLC_CODE0,     "NUL Operation" },
  { AL_OBJCTLC_CODE1,     "Pulse On" },
  { AL_OBJCTLC_CODE2,     "Pulse Off" },
  { AL_OBJCTLC_CODE3,     "Latch On" },
  { AL_OBJCTLC_CODE4,     "Latch Off" },
  { 0, NULL }
};

/* Application Layer Control Code 'Clear Field' Values */
static const value_string dnp3_al_ctlc_misc_vals[] = {
  { AL_OBJCTLC_QUEUE,     "Queue" },
  { AL_OBJCTLC_CLEAR,     "Clear" },
  { AL_OBJCTLC_NOTSET,    "Not Set" },
  { AL_OBJCTLC_BOTHSET,   "Queue and Clear" },
  { 0, NULL }
};

/* Application Layer Control Code 'Trip Close Code' Values */
static const value_string dnp3_al_ctlc_tc_vals[] = {
  { AL_OBJCTLC_TC0,     "NUL" },
  { AL_OBJCTLC_TC1,     "Close" },
  { AL_OBJCTLC_TC2,     "Trip" },
  { AL_OBJCTLC_TC3,     "Reserved" },
  { 0, NULL }
};

/* Application Layer Control Status Values */
static const value_string dnp3_al_ctl_status_vals[] = {
  { AL_OBJCTL_STAT0,     "Req. Accepted/Init/Queued" },
  { AL_OBJCTL_STAT1,     "Req. Not Accepted; Arm-Timer Expired" },
  { AL_OBJCTL_STAT2,     "Req. Not Accepted; No 'SELECT' Received" },
  { AL_OBJCTL_STAT3,     "Req. Not Accepted; Format Err. in Ctl Req." },
  { AL_OBJCTL_STAT4,     "Ctl Oper. Not Supported For This Point" },
  { AL_OBJCTL_STAT5,     "Req. Not Accepted; Ctrl Queue Full/Point Active" },
  { AL_OBJCTL_STAT6,     "Req. Not Accepted; Ctrl Hardware Problems" },
  { AL_OBJCTL_STAT7,     "Req. Not Accepted; Local/Remote switch in Local" },
  { AL_OBJCTL_STAT8,     "Req. Not Accepted; Too many operations" },
  { AL_OBJCTL_STAT9,     "Req. Not Accepted; Insufficient authorization" },
  { AL_OBJCTL_STAT10,    "Req. Not Accepted; Local automation proc active" },
  { 0, NULL }
};
static value_string_ext dnp3_al_ctl_status_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_ctl_status_vals);

/* Application Layer Binary Input Quality Flag Values */
static const value_string dnp3_al_biflag_vals[] _U_ = {
  { AL_OBJ_BI_FLAG0, "Online" },
  { AL_OBJ_BI_FLAG1, "Restart" },
  { AL_OBJ_BI_FLAG2, "Comm Fail" },
  { AL_OBJ_BI_FLAG3, "Remote Forced" },
  { AL_OBJ_BI_FLAG4, "Locally Forced" },
  { AL_OBJ_BI_FLAG5, "Chatter Filter" },
  { 0, NULL }
};

/* Application Layer Counter Quality Flag Values */
static const value_string dnp3_al_ctrflag_vals[] _U_ = {
  { AL_OBJ_CTR_FLAG0, "Online" },
  { AL_OBJ_CTR_FLAG1, "Restart" },
  { AL_OBJ_CTR_FLAG2, "Comm Fail" },
  { AL_OBJ_CTR_FLAG3, "Remote Forced" },
  { AL_OBJ_CTR_FLAG4, "Locally Forced" },
  { AL_OBJ_CTR_FLAG5, "Roll-Over" },
  { AL_OBJ_CTR_FLAG6, "Discontinuity" },
  { 0, NULL }
};

/* Application Layer Analog Input Quality Flag Values */
static const value_string dnp3_al_aiflag_vals[] _U_ = {
  { AL_OBJ_AI_FLAG0, "Online" },
  { AL_OBJ_AI_FLAG1, "Restart" },
  { AL_OBJ_AI_FLAG2, "Comm Fail" },
  { AL_OBJ_AI_FLAG3, "Remote Forced" },
  { AL_OBJ_AI_FLAG4, "Locally Forced" },
  { AL_OBJ_AI_FLAG5, "Over-Range" },
  { AL_OBJ_AI_FLAG6, "Ref. Error" },
  { 0, NULL }
};

/* Application Layer File Control Mode values */
static const value_string dnp3_al_file_mode_vals[] _U_ = {
  { AL_OBJ_FILE_MODE_NULL,    "NULL" },
  { AL_OBJ_FILE_MODE_READ,    "READ" },
  { AL_OBJ_FILE_MODE_WRITE,   "WRITE" },
  { AL_OBJ_FILE_MODE_APPEND,  "APPEND" },
  { 0, NULL }
};

/* Application Layer File Control Status values */
static const value_string dnp3_al_file_status_vals[] _U_ = {
  { 0,    "SUCCESS" },
  { 1,    "PERMISSION DENIED" },
  { 2,    "INVALID MODE" },
  { 3,    "FILE NOT FOUND" },
  { 4,    "FILE LOCKED" },
  { 5,    "TOO MANY OPEN" },
  { 6,    "INVALID HANDLE" },
  { 7,    "WRITE BLOCK SIZE" },
  { 8,    "COMM LOST" },
  { 9,    "CANNOT ABORT" },
  { 16,   "NOT OPENED" },
  { 17,   "HANDLE EXPIRED" },
  { 18,   "BUFFER OVERRUN" },
  { 19,   "FATAL" },
  { 20,   "BLOCK SEQUENCE" },
  { 255,  "UNDEFINED" },
  { 0, NULL }
};

/* Initialize the subtree pointers */
static gint ett_dnp3 = -1;
static gint ett_dnp3_dl = -1;
static gint ett_dnp3_dl_ctl = -1;
static gint ett_dnp3_tr_ctl = -1;
static gint ett_dnp3_al_data = -1;
static gint ett_dnp3_al = -1;
static gint ett_dnp3_al_ctl = -1;
static gint ett_dnp3_al_obj_point_tcc = -1;

/* Added for Application Layer Decoding */
static gint ett_dnp3_al_iin = -1;
static gint ett_dnp3_al_obj = -1;
static gint ett_dnp3_al_obj_qualifier = -1;
static gint ett_dnp3_al_obj_range = -1;
static gint ett_dnp3_al_objdet = -1;
static gint ett_dnp3_al_obj_quality = -1;
static gint ett_dnp3_al_obj_point = -1;
static gint ett_dnp3_al_obj_point_perms = -1;

/* Tables for reassembly of fragments. */
static GHashTable *al_fragment_table = NULL;
static GHashTable *al_reassembled_table = NULL;
static GHashTable *dl_conversation_table = NULL;

/* Data-Link-Layer Conversation Key Structure */
typedef struct _dl_conversation_key
{
  guint32 conversation; /* TCP / UDP conversation index */
  guint16 src;          /* DNP3.0 Source Address */
  guint16 dst;          /* DNP3.0 Destination Address */
} dl_conversation_key_t;

/* Data-Link-Layer conversation key equality function */
static gint
dl_conversation_equal(gconstpointer v, gconstpointer w)
{
  const dl_conversation_key_t* v1 = (const dl_conversation_key_t*)v;
  const dl_conversation_key_t* v2 = (const dl_conversation_key_t*)w;

  if (v1->conversation == v2->conversation &&
      v1->src == v2->src &&
      v1->dst == v2->dst)
  {
    return 1;
  }

  return 0;
}

/* Data-Link-Layer conversation key hash function */
static guint
dl_conversation_hash(gconstpointer v)
{
  const dl_conversation_key_t *key = (const dl_conversation_key_t*)v;
  guint val;

  val = key->conversation + (key->src << 16) + key->dst;

  return val;
}

/* ************************************************************************* */
/*                   Header values for reassembly                            */
/* ************************************************************************* */
static int   hf_dnp3_fragment  = -1;
static int   hf_dnp3_fragments = -1;
static int   hf_dnp3_fragment_overlap = -1;
static int   hf_dnp3_fragment_overlap_conflict = -1;
static int   hf_dnp3_fragment_multiple_tails = -1;
static int   hf_dnp3_fragment_too_long_fragment = -1;
static int   hf_dnp3_fragment_error = -1;
static int   hf_dnp3_fragment_count = -1;
static int   hf_dnp3_fragment_reassembled_in = -1;
static int   hf_dnp3_fragment_reassembled_length = -1;
static gint ett_dnp3_fragment  = -1;
static gint ett_dnp3_fragments = -1;

static const fragment_items dnp3_frag_items = {
  &ett_dnp3_fragment,
  &ett_dnp3_fragments,
  &hf_dnp3_fragments,
  &hf_dnp3_fragment,
  &hf_dnp3_fragment_overlap,
  &hf_dnp3_fragment_overlap_conflict,
  &hf_dnp3_fragment_multiple_tails,
  &hf_dnp3_fragment_too_long_fragment,
  &hf_dnp3_fragment_error,
  &hf_dnp3_fragment_count,
  &hf_dnp3_fragment_reassembled_in,
  &hf_dnp3_fragment_reassembled_length,
  /* Reassembled data field */
  NULL,
  "DNP 3.0 fragments"
};

/* Conversation stuff, used for tracking application message fragments */
/* the number of entries in the memory chunk array */
#define dnp3_conv_init_count 50

/* Conversation structure */
typedef struct {
  guint conv_seq_number;
} dnp3_conv_t;

/* The conversation sequence number */
static guint seq_number = 0;

/* Heuristically detect  DNP3 over TCP/UDP */
static gboolean dnp3_heuristics = FALSE;
/* desegmentation of DNP3 over TCP */
static gboolean dnp3_desegment = TRUE;

/* Enum for different quality type fields */
enum QUALITY_TYPE {
  BIN_IN,
  BIN_OUT,
  ANA_IN,
  ANA_OUT,
  COUNTER
};

/*****************************************************************/
/*                                                               */
/* CRC LOOKUP TABLE                                              */
/* ================                                              */
/* The following CRC lookup table was generated automagically    */
/* by the Rocksoft^tm Model CRC Algorithm Table Generation       */
/* Program V1.0 using the following model parameters:            */
/*                                                               */
/*    Width   : 2 bytes.                                         */
/*    Poly    : 0x3D65                                           */
/*    Reverse : TRUE.                                            */
/*                                                               */
/* For more information on the Rocksoft^tm Model CRC Algorithm,  */
/* see the document titled "A Painless Guide to CRC Error        */
/* Detection Algorithms" by Ross Williams                        */
/* (ross@guest.adelaide.edu.au.). This document is likely to be  */
/* in the FTP archive "ftp.adelaide.edu.au/pub/rocksoft".        */
/*                                                               */
/*****************************************************************/

static guint16 crctable[256] =
{
 0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
 0xFF89, 0xC9D7, 0x9335, 0xA56B, 0x26F1, 0x10AF, 0x4A4D, 0x7C13,
 0xB26B, 0x8435, 0xDED7, 0xE889, 0x6B13, 0x5D4D, 0x07AF, 0x31F1,
 0x4DE2, 0x7BBC, 0x215E, 0x1700, 0x949A, 0xA2C4, 0xF826, 0xCE78,
 0x29AF, 0x1FF1, 0x4513, 0x734D, 0xF0D7, 0xC689, 0x9C6B, 0xAA35,
 0xD626, 0xE078, 0xBA9A, 0x8CC4, 0x0F5E, 0x3900, 0x63E2, 0x55BC,
 0x9BC4, 0xAD9A, 0xF778, 0xC126, 0x42BC, 0x74E2, 0x2E00, 0x185E,
 0x644D, 0x5213, 0x08F1, 0x3EAF, 0xBD35, 0x8B6B, 0xD189, 0xE7D7,
 0x535E, 0x6500, 0x3FE2, 0x09BC, 0x8A26, 0xBC78, 0xE69A, 0xD0C4,
 0xACD7, 0x9A89, 0xC06B, 0xF635, 0x75AF, 0x43F1, 0x1913, 0x2F4D,
 0xE135, 0xD76B, 0x8D89, 0xBBD7, 0x384D, 0x0E13, 0x54F1, 0x62AF,
 0x1EBC, 0x28E2, 0x7200, 0x445E, 0xC7C4, 0xF19A, 0xAB78, 0x9D26,
 0x7AF1, 0x4CAF, 0x164D, 0x2013, 0xA389, 0x95D7, 0xCF35, 0xF96B,
 0x8578, 0xB326, 0xE9C4, 0xDF9A, 0x5C00, 0x6A5E, 0x30BC, 0x06E2,
 0xC89A, 0xFEC4, 0xA426, 0x9278, 0x11E2, 0x27BC, 0x7D5E, 0x4B00,
 0x3713, 0x014D, 0x5BAF, 0x6DF1, 0xEE6B, 0xD835, 0x82D7, 0xB489,
 0xA6BC, 0x90E2, 0xCA00, 0xFC5E, 0x7FC4, 0x499A, 0x1378, 0x2526,
 0x5935, 0x6F6B, 0x3589, 0x03D7, 0x804D, 0xB613, 0xECF1, 0xDAAF,
 0x14D7, 0x2289, 0x786B, 0x4E35, 0xCDAF, 0xFBF1, 0xA113, 0x974D,
 0xEB5E, 0xDD00, 0x87E2, 0xB1BC, 0x3226, 0x0478, 0x5E9A, 0x68C4,
 0x8F13, 0xB94D, 0xE3AF, 0xD5F1, 0x566B, 0x6035, 0x3AD7, 0x0C89,
 0x709A, 0x46C4, 0x1C26, 0x2A78, 0xA9E2, 0x9FBC, 0xC55E, 0xF300,
 0x3D78, 0x0B26, 0x51C4, 0x679A, 0xE400, 0xD25E, 0x88BC, 0xBEE2,
 0xC2F1, 0xF4AF, 0xAE4D, 0x9813, 0x1B89, 0x2DD7, 0x7735, 0x416B,
 0xF5E2, 0xC3BC, 0x995E, 0xAF00, 0x2C9A, 0x1AC4, 0x4026, 0x7678,
 0x0A6B, 0x3C35, 0x66D7, 0x5089, 0xD313, 0xE54D, 0xBFAF, 0x89F1,
 0x4789, 0x71D7, 0x2B35, 0x1D6B, 0x9EF1, 0xA8AF, 0xF24D, 0xC413,
 0xB800, 0x8E5E, 0xD4BC, 0xE2E2, 0x6178, 0x5726, 0x0DC4, 0x3B9A,
 0xDC4D, 0xEA13, 0xB0F1, 0x86AF, 0x0535, 0x336B, 0x6989, 0x5FD7,
 0x23C4, 0x159A, 0x4F78, 0x7926, 0xFABC, 0xCCE2, 0x9600, 0xA05E,
 0x6E26, 0x5878, 0x029A, 0x34C4, 0xB75E, 0x8100, 0xDBE2, 0xEDBC,
 0x91AF, 0xA7F1, 0xFD13, 0xCB4D, 0x48D7, 0x7E89, 0x246B, 0x1235
};

/*****************************************************************/
/*                   End of CRC Lookup Table                     */
/*****************************************************************/

/* calculates crc given a buffer of characters and a length of buffer */
static guint16
calculateCRC(const void *buf, guint len) {
  guint16 crc = 0;
  const guint8 *p = (const guint8 *)buf;
  while(len-- > 0)
    crc = crctable[(crc ^ *p++) & 0xff] ^ (crc >> 8);
  return ~crc;
}

/*****************************************************************/
/*  Adds text to item, with trailing "," if required             */
/*****************************************************************/
static gboolean
add_item_text(proto_item *item, const gchar *text, gboolean comma_needed)
{
  if (comma_needed) {
    proto_item_append_text(item, ", ");
  }
  proto_item_append_text(item, "%s", text);
  return TRUE;
}

/*****************************************************************/
/*  Application Layer Process Internal Indications (IIN)         */
/*****************************************************************/
static void
dnp3_al_process_iin(tvbuff_t *tvb, int offset, proto_tree *al_tree)
{

  guint16       al_iin;
  proto_item    *tiin;
  proto_tree    *iin_tree = NULL;
  gboolean      comma_needed = FALSE;

  al_iin = tvb_get_ntohs(tvb, offset);

  tiin = proto_tree_add_uint_format(al_tree, hf_dnp3_al_iin, tvb, offset, 2, al_iin,
        "Internal Indications: ");
  if (al_iin & AL_IIN_RST)    comma_needed = add_item_text(tiin, "Device Restart", comma_needed);
  if (al_iin & AL_IIN_DOL)    comma_needed = add_item_text(tiin, "Outputs in Local", comma_needed);
  if (al_iin & AL_IIN_DT)     comma_needed = add_item_text(tiin, "Device Trouble", comma_needed);
  if (al_iin & AL_IIN_TSR)    comma_needed = add_item_text(tiin, "Time Sync Required", comma_needed);
  if (al_iin & AL_IIN_CLS3D)  comma_needed = add_item_text(tiin, "Class 3 Data Available", comma_needed);
  if (al_iin & AL_IIN_CLS2D)  comma_needed = add_item_text(tiin, "Class 2 Data Available", comma_needed);
  if (al_iin & AL_IIN_CLS1D)  comma_needed = add_item_text(tiin, "Class 1 Data Available", comma_needed);
  if (al_iin & AL_IIN_BMSG)   comma_needed = add_item_text(tiin, "Broadcast Message Rx'd", comma_needed);
  if (al_iin & AL_IIN_CC)     comma_needed = add_item_text(tiin, "Device Configuration Corrupt", comma_needed);
  if (al_iin & AL_IIN_OAE)    comma_needed = add_item_text(tiin, "Operation Already Executing", comma_needed);
  if (al_iin & AL_IIN_EBO)    comma_needed = add_item_text(tiin, "Event Buffer Overflow", comma_needed);
  if (al_iin & AL_IIN_PIOOR)  comma_needed = add_item_text(tiin, "Parameters Invalid or Out of Range", comma_needed);
  if (al_iin & AL_IIN_OBJU)   comma_needed = add_item_text(tiin, "Requested Objects Unknown", comma_needed);
  if (al_iin & AL_IIN_FCNI)   /*comma_needed = */add_item_text(tiin, "Function code not implemented", comma_needed);
  proto_item_append_text(tiin, " (0x%04x)", al_iin);

  iin_tree = proto_item_add_subtree(tiin, ett_dnp3_al_iin);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_rst, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_dt, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_dol, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_tsr, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_cls3d, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_cls2d, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_cls1d, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_bmsg, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_cc, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_oae, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_ebo, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_pioor, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_obju, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_fcni, tvb, offset, 2, ENC_BIG_ENDIAN);
}

/*****************************************************************/
/* Function to determine Application Layer Object Index size and */
/* Point address.                                                */
/*****************************************************************/
static int
dnp3_al_obj_procindex(tvbuff_t *tvb, int offset, guint8 al_objq_index, guint32 *al_ptaddr, proto_tree *item_tree)
{
  int indexbytes = 0;
  proto_item *index_item;

  switch (al_objq_index)
  {
    case AL_OBJQL_IDX_NI:        /* No Index */
      indexbytes = 0;
      index_item = proto_tree_add_text(item_tree, tvb, offset, 0, "Point Index: %u", *al_ptaddr);
      PROTO_ITEM_SET_GENERATED(index_item);
      break;
    case AL_OBJQL_IDX_1O:
      *al_ptaddr = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(item_tree, hf_dnp3_al_index8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      indexbytes = 1;
      break;
    case AL_OBJQL_IDX_2O:
      *al_ptaddr = tvb_get_letohs(tvb, offset);
      proto_tree_add_item(item_tree, hf_dnp3_al_index16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      indexbytes = 2;
      break;
    case AL_OBJQL_IDX_4O:
      *al_ptaddr = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(item_tree, hf_dnp3_al_index32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      indexbytes = 4;
      break;
    case AL_OBJQL_IDX_1OS:
      *al_ptaddr = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(item_tree, hf_dnp3_al_size8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      indexbytes = 1;
      break;
    case AL_OBJQL_IDX_2OS:
      *al_ptaddr = tvb_get_letohs(tvb, offset);
      proto_tree_add_item(item_tree, hf_dnp3_al_size16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      indexbytes = 2;
      break;
    case AL_OBJQL_IDX_4OS:
      *al_ptaddr = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(item_tree, hf_dnp3_al_size32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      indexbytes = 4;
      break;
  }
  return indexbytes;
}

/*****************************************************************/
/* Function to add the same string to two separate tree items    */
/*****************************************************************/
static void
dnp3_append_2item_text(proto_item *item1, proto_item *item2, const gchar *text)
{
  proto_item_append_text(item1, "%s", text);
  proto_item_append_text(item2, "%s", text);
}

/*****************************************************************/
/* Function to Determine Application Layer Point Quality Flags & */
/* add Point Quality Flag Sub-Tree                               */
/*****************************************************************/
static void
dnp3_al_obj_quality(tvbuff_t *tvb, int offset, guint8 al_ptflags, proto_tree *point_tree, proto_item *point_item, enum QUALITY_TYPE type)
{

  proto_tree  *quality_tree = NULL;
  proto_item  *quality_item;
  int         hf0 = 0, hf1 = 0, hf2 = 0, hf3 = 0, hf4 = 0, hf5 = 0, hf6 = 0, hf7 = 0;

  /* Common code */
  proto_item_append_text(point_item, " (Quality: ");
  quality_item = proto_tree_add_text(point_tree, tvb, offset, 1, "Quality: ");
  quality_tree = proto_item_add_subtree(quality_item, ett_dnp3_al_obj_quality);

  if (al_ptflags & AL_OBJ_BI_FLAG0) {
    dnp3_append_2item_text(point_item, quality_item, "Online");
  }
  else {
    dnp3_append_2item_text(point_item, quality_item, "Offline");
  }
  if (al_ptflags & AL_OBJ_BI_FLAG1) dnp3_append_2item_text(point_item, quality_item, ", Restart");
  if (al_ptflags & AL_OBJ_BI_FLAG2) dnp3_append_2item_text(point_item, quality_item, ", Comm Fail");
  if (al_ptflags & AL_OBJ_BI_FLAG3) dnp3_append_2item_text(point_item, quality_item, ", Remote Force");
  if (al_ptflags & AL_OBJ_BI_FLAG4) dnp3_append_2item_text(point_item, quality_item, ", Local Force");

  switch (type) {
    case BIN_IN: /* Binary Input Quality flags */
      if (al_ptflags & AL_OBJ_BI_FLAG5) dnp3_append_2item_text(point_item, quality_item, ", Chatter Filter");

      hf0 = hf_dnp3_al_biq_b0;
      hf1 = hf_dnp3_al_biq_b1;
      hf2 = hf_dnp3_al_biq_b2;
      hf3 = hf_dnp3_al_biq_b3;
      hf4 = hf_dnp3_al_biq_b4;
      hf5 = hf_dnp3_al_biq_b5;
      hf6 = hf_dnp3_al_biq_b6;
      hf7 = hf_dnp3_al_biq_b7;
      break;

    case BIN_OUT: /* Binary Output Quality flags */
      hf0 = hf_dnp3_al_boq_b0;
      hf1 = hf_dnp3_al_boq_b1;
      hf2 = hf_dnp3_al_boq_b2;
      hf3 = hf_dnp3_al_boq_b3;
      hf4 = hf_dnp3_al_boq_b4;
      hf5 = hf_dnp3_al_boq_b5;
      hf6 = hf_dnp3_al_boq_b6;
      hf7 = hf_dnp3_al_boq_b7;
      break;

    case ANA_IN: /* Analog Input Quality flags */
      if (al_ptflags & AL_OBJ_AI_FLAG5) dnp3_append_2item_text(point_item, quality_item, ", Over-Range");
      if (al_ptflags & AL_OBJ_AI_FLAG6) dnp3_append_2item_text(point_item, quality_item, ", Reference Check");

      hf0 = hf_dnp3_al_aiq_b0;
      hf1 = hf_dnp3_al_aiq_b1;
      hf2 = hf_dnp3_al_aiq_b2;
      hf3 = hf_dnp3_al_aiq_b3;
      hf4 = hf_dnp3_al_aiq_b4;
      hf5 = hf_dnp3_al_aiq_b5;
      hf6 = hf_dnp3_al_aiq_b6;
      hf7 = hf_dnp3_al_aiq_b7;
      break;

    case ANA_OUT: /* Analog Output Quality flags */
      hf0 = hf_dnp3_al_aoq_b0;
      hf1 = hf_dnp3_al_aoq_b1;
      hf2 = hf_dnp3_al_aoq_b2;
      hf3 = hf_dnp3_al_aoq_b3;
      hf4 = hf_dnp3_al_aoq_b4;
      hf5 = hf_dnp3_al_aoq_b5;
      hf6 = hf_dnp3_al_aoq_b6;
      hf7 = hf_dnp3_al_aoq_b7;
      break;

    case COUNTER: /* Counter Quality flags */
      if (al_ptflags & AL_OBJ_CTR_FLAG5) dnp3_append_2item_text(point_item, quality_item, ", Roll-over");
      if (al_ptflags & AL_OBJ_CTR_FLAG6) dnp3_append_2item_text(point_item, quality_item, ", Discontinuity");

      hf0 = hf_dnp3_al_ctrq_b0;
      hf1 = hf_dnp3_al_ctrq_b1;
      hf2 = hf_dnp3_al_ctrq_b2;
      hf3 = hf_dnp3_al_ctrq_b3;
      hf4 = hf_dnp3_al_ctrq_b4;
      hf5 = hf_dnp3_al_ctrq_b5;
      hf6 = hf_dnp3_al_ctrq_b6;
      hf7 = hf_dnp3_al_ctrq_b7;
      break;
  }

  if (quality_tree != NULL) {
    proto_tree_add_item(quality_tree, hf7, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(quality_tree, hf6, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(quality_tree, hf5, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(quality_tree, hf4, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(quality_tree, hf3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(quality_tree, hf2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(quality_tree, hf1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(quality_tree, hf0, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  }
  proto_item_append_text(point_item, ")");
}

/**********************************************************************/
/* Function to convert DNP3 timestamp to nstime_t value               */
/**********************************************************************/
/* 48-bit Time Format                                                 */
/* MSB      FF       EE       DD       CC       BB       AA      LSB  */
/*       ffffffff eeeeeeee dddddddd cccccccc bbbbbbbb aaaaaaaa        */
/*       47    40 39    32 31    24 23    16 15     8 7      0        */
/*                                                                    */
/* Value is ms since 00:00 on 1/1/1970                                */
/**********************************************************************/
static void
dnp3_al_get_timestamp(nstime_t *timestamp, tvbuff_t *tvb, int data_pos)
{

  guint32    hi, lo;
  guint64    time_ms;

  lo = tvb_get_letohs(tvb, data_pos);
  hi = tvb_get_letohl(tvb, data_pos + 2);

  time_ms = (guint64)hi * 0x10000 + lo;

  timestamp->secs = (long)(time_ms / 1000);
  timestamp->nsecs = (long)(time_ms % 1000) * 1000000;
}

/*****************************************************************/
/*  Desc:    Application Layer Process Object Details            */
/*  Returns: New offset pointer into tvb                         */
/*****************************************************************/
static int
dnp3_al_process_object(tvbuff_t *tvb, packet_info *pinfo, int offset,
                       proto_tree *robj_tree, gboolean header_only,
                       guint16 *al_objtype, nstime_t *al_cto)
{

  guint8        al_2bit, al_objq, al_objq_index, al_objq_code, al_ptflags, al_oct_len=0,
                al_ctlobj_count, al_bi_val, bitindex=0, al_tcc_code;
  guint16       al_obj, al_val16=0, al_ctlobj_stat, al_relms, al_filename_offs, al_filename_len, al_file_ctrl_mode,
                temp;
  guint32       al_val32, al_ptaddr=0, al_ctlobj_on, al_ctlobj_off, file_data_size;
  nstime_t      al_reltime, al_abstime;
  gboolean      al_bit;
  guint         data_pos;
  gfloat        al_valflt;
  gdouble       al_valdbl;
  int           item_num, num_items=0;
  int           orig_offset, start_offset, rangebytes=0, indexbytes=0;
  proto_item    *object_item = NULL, *point_item = NULL, *qualifier_item = NULL, *range_item = NULL, *perms_item = NULL, *tcc_item = NULL;
  proto_tree    *object_tree = NULL, *point_tree, *qualifier_tree, *range_tree, *perms_tree, *tcc_tree;
  const gchar   *ctl_status_str, *al_filename;

  orig_offset = offset;

  /* Application Layer Objects in this Message */
  *al_objtype =
  al_obj = tvb_get_ntohs(tvb, offset);

  /* Special handling for Octet string objects as the variation is the length of the string */
  temp = al_obj & 0xFF00;
  if ((temp == AL_OBJ_OCT) || (temp == AL_OBJ_OCT_EVT )) {
    al_oct_len = al_obj & 0xFF;
    al_obj = temp;
  }

  /* Create Data Objects Detail Tree */
  object_item = proto_tree_add_uint_format(robj_tree, hf_dnp3_al_obj, tvb, offset, 2, al_obj,
                                           "Object(s): %s (0x%04x)",
                                           val_to_str_ext_const(al_obj, &dnp3_al_obj_vals_ext, "Unknown Object - Abort Decoding..."),
                                           al_obj);
  object_tree = proto_item_add_subtree(object_item, ett_dnp3_al_obj);

  offset += 2;

  /* Object Qualifier */
  al_objq = tvb_get_guint8(tvb, offset);
  al_objq_index = al_objq & AL_OBJQ_INDEX;
  al_objq_index = al_objq_index >> 4;
  al_objq_code = al_objq & AL_OBJQ_CODE;

  qualifier_item = proto_tree_add_text(object_tree, tvb, offset, 1, "Qualifier Field, Prefix: %s, Code: %s",
    val_to_str_ext_const(al_objq_index, &dnp3_al_objq_index_vals_ext, "Unknown Index Type"),
    val_to_str_ext_const(al_objq_code, &dnp3_al_objq_code_vals_ext, "Unknown Code Type"));
  qualifier_tree = proto_item_add_subtree(qualifier_item, ett_dnp3_al_obj_qualifier);
  proto_tree_add_item(qualifier_tree, hf_dnp3_al_objq_index, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(qualifier_tree, hf_dnp3_al_objq_code, tvb, offset, 1, ENC_BIG_ENDIAN);

  offset += 1;

  /* Create (possibly synthesized) number of items and range field tree */
  range_item = proto_tree_add_text(object_tree, tvb, offset, 0, "Number of Items: ");
  range_tree = proto_item_add_subtree(range_item, ett_dnp3_al_obj_range);

  switch (al_objq_code)
  {
    case AL_OBJQL_CODE_SSI8:           /* 8-bit Start and Stop Indices in Range Field */
      num_items = ( tvb_get_guint8(tvb, offset+1) - tvb_get_guint8(tvb, offset) + 1);
      PROTO_ITEM_SET_GENERATED(range_item);
      al_ptaddr = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_start8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_stop8, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
      rangebytes = 2;
      break;
    case AL_OBJQL_CODE_SSI16:          /* 16-bit Start and Stop Indices in Range Field */
      num_items = ( tvb_get_letohs(tvb, offset+2) - tvb_get_letohs(tvb, (offset)) + 1);
      PROTO_ITEM_SET_GENERATED(range_item);
      al_ptaddr = tvb_get_letohs(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_start16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_stop16, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
      rangebytes = 4;
      break;
    case AL_OBJQL_CODE_SSI32:          /* 32-bit Start and Stop Indices in Range Field */
      num_items = ( tvb_get_letohl(tvb, offset+4) - tvb_get_letohl(tvb, offset) + 1);
      PROTO_ITEM_SET_GENERATED(range_item);
      al_ptaddr = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_start32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_stop32, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
      rangebytes = 8;
      break;
    case AL_OBJQL_CODE_AA8:            /* 8-bit Absolute Address in Range Field */
      num_items = 1;
      PROTO_ITEM_SET_GENERATED(range_item);
      al_ptaddr = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_abs8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      rangebytes = 1;
      break;
    case AL_OBJQL_CODE_AA16:           /* 16-bit Absolute Address in Range Field */
      num_items = 1;
      PROTO_ITEM_SET_GENERATED(range_item);
      al_ptaddr = tvb_get_letohs(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_abs16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      rangebytes = 2;
      break;
    case AL_OBJQL_CODE_AA32:           /* 32-bit Absolute Address in Range Field */
      num_items = 1;
      PROTO_ITEM_SET_GENERATED(range_item);
      al_ptaddr = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_abs32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      rangebytes = 4;
      break;
    case AL_OBJQL_CODE_SF8:            /* 8-bit Single Field Quantity in Range Field */
      num_items = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_quant8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      rangebytes = 1;
      proto_item_set_len(range_item, rangebytes);
      break;
    case AL_OBJQL_CODE_SF16:           /* 16-bit Single Field Quantity in Range Field */
      num_items = tvb_get_letohs(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_quant16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      rangebytes = 2;
      proto_item_set_len(range_item, rangebytes);
      break;
    case AL_OBJQL_CODE_SF32:           /* 32-bit Single Field Quantity in Range Field */
      num_items = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_quant32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      rangebytes = 4;
      proto_item_set_len(range_item, rangebytes);
      break;
    case AL_OBJQL_CODE_FF:            /* 8 bit object count in Range Field */
      num_items = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_quant8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      rangebytes = 1;
      proto_item_set_len(range_item, rangebytes);
  }
  if (num_items > 0) {
    proto_item_append_text(object_item, ", %d point%s", num_items, plurality(num_items, "", "s"));
  }
  proto_item_append_text(range_item, "%d", num_items);

  if (num_items < 0) {
    proto_item_append_text(range_item, " (bogus)");
    expert_add_info_format(pinfo, range_item, PI_MALFORMED, PI_ERROR, "Negative number of items");
    return tvb_length(tvb);
  }


  offset += rangebytes;

  bitindex = 0; /* Temp variable for cycling through points when object values are encoded into
            bits; primarily objects 0x0101, 0x0301 & 0x1001 */

  /* Only process the point information for replies or items with point index lists */
  if (!header_only || al_objq_index > 0) {
    start_offset = offset;
    for (item_num = 0; item_num < num_items; item_num++)
    {
      /* Create Point item and Process Index */
      if (al_objq_index <= AL_OBJQL_IDX_4O)
        point_item = proto_tree_add_text(object_tree, tvb, offset, -1, "Point Number");
      else
        point_item = proto_tree_add_text(object_tree, tvb, offset, -1, "Object: Size");
      point_tree = proto_item_add_subtree(point_item, ett_dnp3_al_obj_point);

      data_pos = offset;
      indexbytes = dnp3_al_obj_procindex(tvb, offset, al_objq_index, &al_ptaddr, point_tree);
      proto_item_append_text(point_item, " %u", al_ptaddr);
      proto_item_set_len(point_item, indexbytes);
      data_pos += indexbytes;

      if (!header_only || (AL_OBJQL_IDX_1OS <= al_objq_index && al_objq_index <= AL_OBJQL_IDX_4OS)) {
        switch (al_obj)
        {

          case AL_OBJ_BI_ALL:      /* Binary Input Default Variation (Obj:01, Var:Default) */
          case AL_OBJ_BIC_ALL:     /* Binary Input Change Default Variation (Obj:02, Var:Default) */
          case AL_OBJ_BOC_ALL:     /* Binary Output Event Default Variation (Obj:11, Var:Default) */
          case AL_OBJ_2BI_ALL:     /* Double-bit Input Default Variation (Obj:03, Var:Default) */
          case AL_OBJ_CTR_ALL:     /* Binary Counter Default Variation (Obj:20, Var:Default) */
          case AL_OBJ_CTRC_ALL:    /* Binary Counter Change Default Variation (Obj:22 Var:Default) */
          case AL_OBJ_AI_ALL:      /* Analog Input Default Variation (Obj:30, Var:Default) */
          case AL_OBJ_AIC_ALL:     /* Analog Input Change Default Variation (Obj:32 Var:Default) */
          case AL_OBJ_AIDB_ALL:    /* Analog Input Deadband Default Variation (Obj:34, Var:Default) */
          case AL_OBJ_AOC_ALL:     /* Analog Output Event Default Variation (Obj:42 Var:Default) */

            offset = data_pos;
            break;

          case AL_OBJ_BI_1BIT:    /* Single-Bit Binary Input (Obj:01, Var:01) */
          case AL_OBJ_BO:         /* Binary Output (Obj:10, Var:01) */

            /* Reset bit index if we've gone onto the next byte */
            if (bitindex > 7)
            {
              bitindex = 0;
              offset += (indexbytes + 1);
            }

            /* Extract the bit from the packed byte */
            al_bi_val = tvb_get_guint8(tvb, offset);
            al_bit = (al_bi_val & (1 << bitindex)) > 0;

            proto_item_append_text(point_item, ", Value: %u", al_bit);
            proto_tree_add_boolean(point_tree, hf_dnp3_al_bit, tvb, offset, 1, al_bit);
            proto_item_set_len(point_item, indexbytes + 1);

            /* If we've read the last item, then move the offset past this byte */
            if (item_num == (num_items-1))
            {
              offset += (indexbytes + 1);
            }

            break;

          case AL_OBJ_2BI_NF:    /* Double-bit Input No Flags (Obj:03, Var:01) */

            if (bitindex > 3)
            {
              bitindex = 0;
              offset += (indexbytes + 1);
            }

            /* Extract the Double-bit from the packed byte */
            al_bi_val = tvb_get_guint8(tvb, offset);
            al_2bit = ((al_bi_val >> (bitindex << 1)) & 3);

            proto_item_append_text(point_item, ", Value: %u", al_2bit);
            proto_tree_add_uint(point_tree, hf_dnp3_al_2bit, tvb, offset, 1, al_2bit);
            proto_item_set_len(point_item, indexbytes + 1);

            /* If we've read the last item, then move the offset past this byte */
            if (item_num == (num_items-1))
            {
              offset += (indexbytes + 1);
            }

            break;


          case AL_OBJ_BI_STAT:    /* Binary Input With Status (Obj:01, Var:02) */
          case AL_OBJ_BIC_NOTIME: /* Binary Input Change Without Time (Obj:02, Var:01) */
          case AL_OBJ_BO_STAT:    /* Binary Output Status (Obj:10, Var:02) */
          case AL_OBJ_BOC_NOTIME: /* Binary Output Change Without Time (Obj:11, Var:01) */

            /* Get Point Flags */
            al_ptflags = tvb_get_guint8(tvb, data_pos);

            switch (al_obj) {
              case AL_OBJ_BI_STAT:
              case AL_OBJ_BIC_NOTIME:
                dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_IN);
                break;
              case AL_OBJ_BO_STAT:
              case AL_OBJ_BOC_NOTIME:
                dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_OUT);
                break;
            }
            data_pos += 1;

            al_bit = (al_ptflags & AL_OBJ_BI_FLAG7) > 0;
            proto_item_append_text(point_item, ", Value: %u", al_bit);

            proto_item_set_len(point_item, data_pos - offset);

            offset = data_pos;
            break;

          case AL_OBJ_2BI_STAT:    /* Double-bit Input With Status (Obj:03, Var:02) */
          case AL_OBJ_2BIC_NOTIME: /* Double-bit Input Change Without Time (Obj:04, Var:01) */

            /* Get Point Flags */
            al_ptflags = tvb_get_guint8(tvb, data_pos);
            dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_IN);
            data_pos += 1;

            al_2bit = (al_ptflags >> 6) & 3;
            proto_item_append_text(point_item, ", Value: %u", al_2bit);
            proto_item_set_len(point_item, data_pos - offset);

            offset = data_pos;
            break;

          case AL_OBJ_BIC_TIME:   /* Binary Input Change w/ Time (Obj:02, Var:02)  */
          case AL_OBJ_BOC_TIME:   /* Binary Output Change w/ Time (Obj:11, Var:02)  */

            /* Get Point Flags */
            al_ptflags = tvb_get_guint8(tvb, data_pos);
            switch (al_obj) {
              case AL_OBJ_BIC_TIME:
                dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_IN);
                break;
              case AL_OBJ_BOC_TIME:
                dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_OUT);
                break;
            }
            data_pos += 1;

            /* Get timestamp */
            dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
            proto_tree_add_time(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
            data_pos += 6;

            al_bit = (al_ptflags & AL_OBJ_BI_FLAG7) >> 7; /* bit shift 1xxxxxxx -> xxxxxxx1 */
            proto_item_append_text(point_item, ", Value: %u, Timestamp: %s", al_bit, abs_time_to_str(&al_abstime, ABSOLUTE_TIME_UTC, FALSE));
            proto_item_set_len(point_item, data_pos - offset);

            offset = data_pos;
            break;

          case AL_OBJ_2BIC_TIME:   /* Double-bit Input Change w/ Time (Obj:04, Var:02)  */

            /* Get Point Flags */
            al_ptflags = tvb_get_guint8(tvb, data_pos);
            dnp3_al_obj_quality(tvb, (offset+indexbytes), al_ptflags, point_tree, point_item, BIN_IN);
            data_pos += 1;


            /* Get timestamp */
            dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
            proto_tree_add_time(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
            data_pos += 6;

            al_2bit = (al_ptflags >> 6) & 3; /* bit shift 11xxxxxx -> 00000011 */
            proto_item_append_text(point_item, ", Value: %u, Timestamp: %s", al_2bit, abs_time_to_str(&al_abstime, ABSOLUTE_TIME_UTC, FALSE));
            proto_item_set_len(point_item, data_pos - offset);

            offset = data_pos;
            break;

          case AL_OBJ_BIC_RTIME:   /* Binary Input Change w/ Relative Time (Obj:02, Var:03)  */

            /* Get Point Flags */
            al_ptflags = tvb_get_guint8(tvb, data_pos);
            dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_IN);
            data_pos += 1;

            /* Get relative time, and convert to ns_time */
            al_relms = tvb_get_letohs(tvb, data_pos);
            al_reltime.secs = al_relms / 1000;
            al_reltime.nsecs = (al_relms % 1000) * 1000;
            /* Now add to CTO time */
            nstime_sum(&al_abstime, al_cto, &al_reltime);
            proto_tree_add_time(point_tree, hf_dnp3_al_rel_timestamp, tvb, data_pos, 2, &al_reltime);
            data_pos += 2;

            al_bit = (al_ptflags & AL_OBJ_BI_FLAG7) >> 7; /* bit shift 1xxxxxxx -> xxxxxxx1 */
            proto_item_append_text(point_item, ", Value: %u, Timestamp: %s", al_bit, abs_time_to_str(&al_abstime, ABSOLUTE_TIME_UTC, FALSE));
            proto_item_set_len(point_item, data_pos - offset);

            offset = data_pos;
            break;

          case AL_OBJ_CTLOP_BLK:  /* Control Relay Output Block (Obj:12, Var:01) */

            /* Add a expand/collapse for TCC */
            al_tcc_code = tvb_get_guint8(tvb, data_pos);
            tcc_item = proto_tree_add_text(point_tree, tvb, data_pos, 1, "Control Code [0x%02x]",al_tcc_code);
            tcc_tree = proto_item_add_subtree(tcc_item, ett_dnp3_al_obj_point_tcc);

            /* Add the Control Code to the Point number list for quick visual reference as to the operation */
            proto_item_append_text(point_item, " [%s]", val_to_str( (al_tcc_code & AL_OBJCTLC_CODE), dnp3_al_ctlc_code_vals, "Invalid Operation"));

            /* Control Code 'Operation Type' */
            proto_tree_add_item(tcc_tree, hf_dnp3_ctlobj_code_c, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);

            /* Control Code Misc Values */
            proto_tree_add_item(tcc_tree, hf_dnp3_ctlobj_code_m, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);

            /* Control Code 'Trip Close Code' */
            proto_tree_add_item(tcc_tree, hf_dnp3_ctlobj_code_tc, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
            data_pos += 1;

            al_ctlobj_stat = tvb_get_guint8(tvb, data_pos);
            proto_tree_add_item(point_tree, hf_dnp3_al_ctrlstatus, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
            ctl_status_str = val_to_str_ext(al_ctlobj_stat, &dnp3_al_ctl_status_vals_ext, "Invalid Status (0x%02x)");
            data_pos += 1;

            /* Get "Count" Field */
            al_ctlobj_count = tvb_get_guint8(tvb, data_pos);
            data_pos += 1;

            /* Get "On Time" Field */
            al_ctlobj_on = tvb_get_letohl(tvb, data_pos);
            data_pos += 4;

            /* Get "Off Time" Field */
            al_ctlobj_off = tvb_get_letohl(tvb, data_pos);
            data_pos += 4;

            proto_tree_add_text(point_tree, tvb, data_pos - 9, 9,
               "  [Count: %u] [On-Time: %u] [Off-Time: %u] [Status: %s (0x%02x)]",
                   al_ctlobj_count, al_ctlobj_on, al_ctlobj_off, ctl_status_str, al_ctlobj_stat);

            proto_item_set_len(point_item, data_pos - offset);

            offset = data_pos;
            break;

          case AL_OBJ_AO_32OPB:   /* 32-Bit Analog Output Block (Obj:41, Var:01) */
          case AL_OBJ_AO_16OPB:   /* 16-Bit Analog Output Block (Obj:41, Var:02) */
          case AL_OBJ_AO_FLTOPB:  /* 32-Bit Floating Point Output Block (Obj:41, Var:03) */
          case AL_OBJ_AO_DBLOPB:  /* 64-Bit Floating Point Output Block (Obj:41, Var:04) */

            switch (al_obj)
            {
              case AL_OBJ_AO_32OPB:
                al_val32 = tvb_get_letohl(tvb, data_pos);
                proto_item_append_text(point_item, ", Value: %u", al_val32);
                proto_tree_add_item(point_tree, hf_dnp3_al_anaout32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                data_pos += 4;
                break;
              case AL_OBJ_AO_16OPB:
                al_val32 = tvb_get_letohs(tvb, data_pos);
                proto_item_append_text(point_item, ", Value: %u", al_val32);
                proto_tree_add_item(point_tree, hf_dnp3_al_anaout16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
                data_pos += 2;
                break;
              case AL_OBJ_AO_FLTOPB:
                al_valflt = tvb_get_letohieee_float(tvb, data_pos);
                proto_item_append_text(point_item, ", Value: %g", al_valflt);
                proto_tree_add_item(point_tree, hf_dnp3_al_anaoutflt, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                data_pos += 4;
                break;
              case AL_OBJ_AO_DBLOPB:
                al_valdbl = tvb_get_letohieee_double(tvb, data_pos);
                proto_item_append_text(point_item, ", Value: %g", al_valdbl);
                proto_tree_add_item(point_tree, hf_dnp3_al_anaoutdbl, tvb, data_pos, 8, ENC_LITTLE_ENDIAN);
                data_pos += 8;
                break;
            }

            /* Get control status */
            al_ctlobj_stat = tvb_get_guint8(tvb, data_pos);
            ctl_status_str = val_to_str_ext(al_ctlobj_stat, &dnp3_al_ctl_status_vals_ext, "Invalid Status (0x%02x)");
            proto_item_append_text(point_item, " [Status: %s (0x%02x)]", ctl_status_str, al_ctlobj_stat);
            proto_tree_add_item(point_tree, hf_dnp3_al_ctrlstatus, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
            data_pos += 1;

            proto_item_set_len(point_item, data_pos - offset);

            offset = data_pos;
            break;

          case AL_OBJ_CTR_32:     /* 32-Bit Binary Counter (Obj:20, Var:01) */
          case AL_OBJ_CTR_16:     /* 16-Bit Binary Counter (Obj:20, Var:02) */
          case AL_OBJ_DCTR_32:    /* 32-Bit Binary Delta Counter (Obj:20, Var:03) */
          case AL_OBJ_DCTR_16:    /* 16-Bit Binary Delta Counter (Obj:20, Var:04) */
          case AL_OBJ_CTR_32NF:   /* 32-Bit Binary Counter Without Flag (Obj:20, Var:05) */
          case AL_OBJ_CTR_16NF:   /* 16-Bit Binary Counter Without Flag (Obj:20, Var:06) */
          case AL_OBJ_DCTR_32NF:  /* 32-Bit Binary Delta Counter Without Flag (Obj:20, Var:07) */
          case AL_OBJ_DCTR_16NF:  /* 16-Bit Binary Delta Counter Without Flag (Obj:20, Var:08) */
          case AL_OBJ_FCTR_32:    /* 32-Bit Frozen Counter (Obj:21, Var:01) */
          case AL_OBJ_FCTR_16:    /* 16-Bit Frozen Counter (Obj:21, Var:02) */
          case AL_OBJ_FDCTR_32:   /* 21 03 32-Bit Frozen Delta Counter */
          case AL_OBJ_FDCTR_16:   /* 21 04 16-Bit Frozen Delta Counter */
          case AL_OBJ_FCTR_32T:   /* 21 05 32-Bit Frozen Counter w/ Time of Freeze */
          case AL_OBJ_FCTR_16T:   /* 21 06 16-Bit Frozen Counter w/ Time of Freeze */
          case AL_OBJ_FDCTR_32T:  /* 21 07 32-Bit Frozen Delta Counter w/ Time of Freeze */
          case AL_OBJ_FDCTR_16T:  /* 21 08 16-Bit Frozen Delta Counter w/ Time of Freeze */
          case AL_OBJ_FCTR_32NF:  /* 21 09 32-Bit Frozen Counter Without Flag */
          case AL_OBJ_FCTR_16NF:  /* 21 10 16-Bit Frozen Counter Without Flag */
          case AL_OBJ_FDCTR_32NF: /* 21 11 32-Bit Frozen Delta Counter Without Flag */
          case AL_OBJ_FDCTR_16NF: /* 21 12 16-Bit Frozen Delta Counter Without Flag */
          case AL_OBJ_CTRC_32:    /* 32-Bit Counter Change Event w/o Time (Obj:22, Var:01) */
          case AL_OBJ_CTRC_16:    /* 16-Bit Counter Change Event w/o Time (Obj:22, Var:02) */
          case AL_OBJ_DCTRC_32:   /* 32-Bit Delta Counter Change Event w/o Time (Obj:22, Var:03) */
          case AL_OBJ_DCTRC_16:   /* 16-Bit Delta Counter Change Event w/o Time (Obj:22, Var:04) */
          case AL_OBJ_CTRC_32T:   /* 32-Bit Counter Change Event with Time (Obj:22, Var:05) */
          case AL_OBJ_CTRC_16T:   /* 16-Bit Counter Change Event with Time (Obj:22, Var:06) */
          case AL_OBJ_DCTRC_32T:  /* 32-Bit Delta Counter Change Event with Time (Obj:22, Var:07) */
          case AL_OBJ_DCTRC_16T:  /* 16-Bit Delta Counter Change Event with Time (Obj:22, Var:08) */
          case AL_OBJ_FCTRC_32:   /* 21 01 32-Bit Frozen Counter Change Event */
          case AL_OBJ_FCTRC_16:   /* 21 02 16-Bit Frozen Counter Change Event */
          case AL_OBJ_FDCTRC_32:  /* 21 03 32-Bit Frozen Delta Counter Change Event */
          case AL_OBJ_FDCTRC_16:  /* 21 04 16-Bit Frozen Delta Counter Change Event */
          case AL_OBJ_FCTRC_32T:  /* 21 05 32-Bit Frozen Counter Change Event w/ Time of Freeze */
          case AL_OBJ_FCTRC_16T:  /* 21 06 16-Bit Frozen Counter Change Event w/ Time of Freeze */
          case AL_OBJ_FDCTRC_32T: /* 21 07 32-Bit Frozen Delta Counter Change Event w/ Time of Freeze */
          case AL_OBJ_FDCTRC_16T: /* 21 08 16-Bit Frozen Delta Counter Change Event w/ Time of Freeze */

            /* Get Point Flags for those types that have them, it's easier to block out those that don't have flags */
            switch (al_obj)
            {
              case AL_OBJ_CTR_32NF:
              case AL_OBJ_CTR_16NF:
              case AL_OBJ_DCTR_32NF:
              case AL_OBJ_DCTR_16NF:
              case AL_OBJ_FCTR_32NF:
              case AL_OBJ_FCTR_16NF:
              case AL_OBJ_FDCTR_32NF:
              case AL_OBJ_FDCTR_16NF:
                break;

              default:
                al_ptflags = tvb_get_guint8(tvb, data_pos);
                dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, COUNTER);
                data_pos += 1;
                break;
            }

            /* Get Counter values */
            switch (al_obj)
            {
              case AL_OBJ_CTR_32:
              case AL_OBJ_DCTR_32:
              case AL_OBJ_CTR_32NF:
              case AL_OBJ_DCTR_32NF:
              case AL_OBJ_FCTR_32:
              case AL_OBJ_FDCTR_32:
              case AL_OBJ_FCTR_32T:
              case AL_OBJ_FDCTR_32T:
              case AL_OBJ_FCTR_32NF:
              case AL_OBJ_FDCTR_32NF:
              case AL_OBJ_CTRC_32:
              case AL_OBJ_DCTRC_32:
              case AL_OBJ_CTRC_32T:
              case AL_OBJ_DCTRC_32T:
              case AL_OBJ_FCTRC_32:
              case AL_OBJ_FDCTRC_32:
              case AL_OBJ_FCTRC_32T:
              case AL_OBJ_FDCTRC_32T:

                al_val32 = tvb_get_letohl(tvb, data_pos);
                proto_item_append_text(point_item, ", Count: %u", al_val32);
                proto_tree_add_item(point_tree, hf_dnp3_al_cnt32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                data_pos += 4;
                break;

              case AL_OBJ_CTR_16:
              case AL_OBJ_DCTR_16:
              case AL_OBJ_CTR_16NF:
              case AL_OBJ_DCTR_16NF:
              case AL_OBJ_FCTR_16:
              case AL_OBJ_FDCTR_16:
              case AL_OBJ_FCTR_16T:
              case AL_OBJ_FDCTR_16T:
              case AL_OBJ_FCTR_16NF:
              case AL_OBJ_FDCTR_16NF:
              case AL_OBJ_CTRC_16:
              case AL_OBJ_DCTRC_16:
              case AL_OBJ_CTRC_16T:
              case AL_OBJ_DCTRC_16T:
              case AL_OBJ_FCTRC_16:
              case AL_OBJ_FDCTRC_16:
              case AL_OBJ_FCTRC_16T:
              case AL_OBJ_FDCTRC_16T:

                al_val16 = tvb_get_letohs(tvb, data_pos);
                proto_item_append_text(point_item, ", Count: %u", al_val16);
                proto_tree_add_item(point_tree, hf_dnp3_al_cnt16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
                data_pos += 2;
                break;
            }

            /* Get the time for those points that have it */
            switch (al_obj)
            {
              case AL_OBJ_FCTR_32T:
              case AL_OBJ_FCTR_16T:
              case AL_OBJ_FDCTR_32T:
              case AL_OBJ_FDCTR_16T:
              case AL_OBJ_CTRC_32T:
              case AL_OBJ_CTRC_16T:
              case AL_OBJ_DCTRC_32T:
              case AL_OBJ_DCTRC_16T:
              case AL_OBJ_FCTRC_32T:
              case AL_OBJ_FCTRC_16T:
              case AL_OBJ_FDCTRC_32T:
              case AL_OBJ_FDCTRC_16T:
                dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
                proto_item_append_text(point_item, ", Timestamp: %s", abs_time_to_str(&al_abstime, ABSOLUTE_TIME_UTC, FALSE));
                proto_tree_add_time(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
                data_pos += 6;
                break;
            }

            proto_item_set_len(point_item, data_pos - offset);
            offset = data_pos;

            break;

          case AL_OBJ_AI_32:        /* 32-Bit Analog Input (Obj:30, Var:01) */
          case AL_OBJ_AI_16:        /* 16-Bit Analog Input (Obj:30, Var:02) */
          case AL_OBJ_AI_32NF:      /* 32-Bit Analog Input Without Flag (Obj:30, Var:03) */
          case AL_OBJ_AI_16NF:      /* 16-Bit Analog Input Without Flag (Obj:30, Var:04) */
          case AL_OBJ_AI_FLT:       /* 32-Bit Floating Point Input (Obj:30, Var:05) */
          case AL_OBJ_AI_DBL:       /* 64-Bit Floating Point Input (Obj:30, Var:06) */
          case AL_OBJ_AIF_FLT:      /* 32-Bit Frozen Floating Point Input (Obj:31, Var:07) */
          case AL_OBJ_AIF_DBL:      /* 64-Bit Frozen Floating Point Input (Obj:31, Var:08) */
          case AL_OBJ_AIC_32NT:     /* 32-Bit Analog Change Event w/o Time (Obj:32, Var:01) */
          case AL_OBJ_AIC_16NT:     /* 16-Bit Analog Change Event w/o Time (Obj:32, Var:02) */
          case AL_OBJ_AIC_32T:      /* 32-Bit Analog Change Event with Time (Obj:32, Var:03) */
          case AL_OBJ_AIC_16T:      /* 16-Bit Analog Change Event with Time (Obj:32, Var:04) */
          case AL_OBJ_AIC_FLTNT:    /* 32-Bit Floating Point Change Event w/o Time (Obj:32, Var:05) */
          case AL_OBJ_AIC_DBLNT:    /* 64-Bit Floating Point Change Event w/o Time (Obj:32, Var:06) */
          case AL_OBJ_AIC_FLTT:     /* 32-Bit Floating Point Change Event w/ Time (Obj:32, Var:07) */
          case AL_OBJ_AIC_DBLT:     /* 64-Bit Floating Point Change Event w/ Time (Obj:32, Var:08) */
          case AL_OBJ_AIFC_FLTNT:   /* 32-Bit Floating Point Frozen Change Event w/o Time (Obj:33, Var:05) */
          case AL_OBJ_AIFC_DBLNT:   /* 64-Bit Floating Point Frozen Change Event w/o Time (Obj:33, Var:06) */
          case AL_OBJ_AIFC_FLTT:    /* 32-Bit Floating Point Frozen Change Event w/ Time (Obj:33, Var:07) */
          case AL_OBJ_AIFC_DBLT:    /* 64-Bit Floating Point Frozen Change Event w/ Time (Obj:33, Var:08) */
          case AL_OBJ_AIDB_16:      /* 16-Bit Analog Input Deadband (Obj:34, Var:01) */
          case AL_OBJ_AIDB_32:      /* 32-Bit Analog Input Deadband (Obj:34, Var:02) */
          case AL_OBJ_AIDB_FLT:     /* 32-Bit Floating Point Analog Input Deadband (Obj:34, Var:03) */

            /* Get Point Flags for those types that have them */
            switch (al_obj)
            {
              case AL_OBJ_AI_32NF:
              case AL_OBJ_AI_16NF:
              case AL_OBJ_AIDB_16:
              case AL_OBJ_AIDB_32:
              case AL_OBJ_AIDB_FLT:
                break;

              default:
                al_ptflags = tvb_get_guint8(tvb, data_pos);
                dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, ANA_IN);
                data_pos += 1;
                break;
            }

            switch (al_obj)
            {
              case AL_OBJ_AI_32:
              case AL_OBJ_AI_32NF:
              case AL_OBJ_AIC_32NT:
              case AL_OBJ_AIC_32T:
              case AL_OBJ_AIDB_32:

                al_val32 = tvb_get_letohl(tvb, data_pos);
                proto_item_append_text(point_item, ", Value: %u", al_val32);
                proto_tree_add_item(point_tree, hf_dnp3_al_ana32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                data_pos += 4;
                break;

              case AL_OBJ_AI_16:
              case AL_OBJ_AI_16NF:
              case AL_OBJ_AIC_16NT:
              case AL_OBJ_AIC_16T:
              case AL_OBJ_AIDB_16:

                al_val16 = tvb_get_letohs(tvb, data_pos);
                proto_item_append_text(point_item, ", Value: %u", al_val16);
                proto_tree_add_item(point_tree, hf_dnp3_al_ana16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
                data_pos += 2;
                break;

              case AL_OBJ_AI_FLT:
              case AL_OBJ_AIF_FLT:
              case AL_OBJ_AIC_FLTNT:
              case AL_OBJ_AIC_FLTT:
              case AL_OBJ_AIFC_FLTNT:
              case AL_OBJ_AIFC_FLTT:
              case AL_OBJ_AIDB_FLT:

                al_valflt = tvb_get_letohieee_float(tvb, data_pos);
                proto_item_append_text(point_item, ", Value: %g", al_valflt);
                proto_tree_add_item(point_tree, hf_dnp3_al_anaflt, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                data_pos += 4;
                break;

              case AL_OBJ_AI_DBL:
              case AL_OBJ_AIF_DBL:
              case AL_OBJ_AIC_DBLNT:
              case AL_OBJ_AIC_DBLT:
              case AL_OBJ_AIFC_DBLNT:
              case AL_OBJ_AIFC_DBLT:

                al_valdbl = tvb_get_letohieee_double(tvb, data_pos);
                proto_item_append_text(point_item, ", Value: %g", al_valdbl);
                proto_tree_add_item(point_tree, hf_dnp3_al_anadbl, tvb, data_pos, 8, ENC_LITTLE_ENDIAN);
                data_pos += 8;
                break;
            }

            /* Get timestamp */
            switch (al_obj)
            {
              case AL_OBJ_AIC_32T:
              case AL_OBJ_AIC_16T:
              case AL_OBJ_AIC_FLTT:
              case AL_OBJ_AIC_DBLT:
              case AL_OBJ_AIFC_FLTT:
              case AL_OBJ_AIFC_DBLT:
                dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
                proto_item_append_text(point_item, ", Timestamp: %s", abs_time_to_str(&al_abstime, ABSOLUTE_TIME_UTC, FALSE));
                proto_tree_add_time(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
                data_pos += 6;
                break;
            }

            proto_item_set_len(point_item, data_pos - offset);

            offset = data_pos;
            break;

          case AL_OBJ_AO_32:     /* 32-Bit Analog Output Status (Obj:40, Var:01) */
          case AL_OBJ_AO_16:     /* 16-Bit Analog Output Status (Obj:40, Var:02) */
          case AL_OBJ_AO_FLT:    /* 32-Bit Floating Point Output Status (Obj:40, Var:03) */
          case AL_OBJ_AO_DBL:    /* 64-Bit Floating Point Output Status (Obj:40, Var:04) */
          case AL_OBJ_AOC_32NT:  /* 32-Bit Analog Output Event w/o Time (Obj:42, Var:01) */
          case AL_OBJ_AOC_16NT:  /* 16-Bit Analog Output Event w/o Time (Obj:42, Var:02) */
          case AL_OBJ_AOC_32T:   /* 32-Bit Analog Output Event with Time (Obj:42, Var:03) */
          case AL_OBJ_AOC_16T:   /* 16-Bit Analog Output Event with Time (Obj:42, Var:04) */
          case AL_OBJ_AOC_FLTNT: /* 32-Bit Floating Point Output Event w/o Time (Obj:42, Var:05) */
          case AL_OBJ_AOC_DBLNT: /* 64-Bit Floating Point Output Event w/o Time (Obj:42, Var:06) */
          case AL_OBJ_AOC_FLTT:  /* 32-Bit Floating Point Output Event w/ Time (Obj:42, Var:07) */
          case AL_OBJ_AOC_DBLT:  /* 64-Bit Floating Point Output Event w/ Time (Obj:42, Var:08) */

            /* Get Point Flags */
            al_ptflags = tvb_get_guint8(tvb, data_pos);
            dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, ANA_OUT);
            data_pos += 1;

            switch (al_obj)
            {
              case AL_OBJ_AO_32:     /* 32-Bit Analog Output Status (Obj:40, Var:01) */
              case AL_OBJ_AOC_32NT:  /* 32-Bit Analog Output Event w/o Time (Obj:42, Var:01) */
              case AL_OBJ_AOC_32T:   /* 32-Bit Analog Output Event with Time (Obj:42, Var:03) */

                al_val32 = tvb_get_letohl(tvb, data_pos);
                proto_item_append_text(point_item, ", Value: %u", al_val32);
                proto_tree_add_item(point_tree, hf_dnp3_al_anaout32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                data_pos += 4;
                break;

              case AL_OBJ_AO_16:     /* 16-Bit Analog Output Status (Obj:40, Var:02) */
              case AL_OBJ_AOC_16NT:  /* 16-Bit Analog Output Event w/o Time (Obj:42, Var:02) */
              case AL_OBJ_AOC_16T:   /* 16-Bit Analog Output Event with Time (Obj:42, Var:04) */

                al_val16 = tvb_get_letohs(tvb, data_pos);
                proto_item_append_text(point_item, ", Value: %u", al_val16);
                proto_tree_add_item(point_tree, hf_dnp3_al_anaout16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
                data_pos += 2;
                break;

              case AL_OBJ_AO_FLT:     /* 32-Bit Floating Point Output Status (Obj:40, Var:03) */
              case AL_OBJ_AOC_FLTNT:  /* 32-Bit Floating Point Output Event w/o Time (Obj:42, Var:05) */
              case AL_OBJ_AOC_FLTT:   /* 32-Bit Floating Point Output Event w/ Time (Obj:42, Var:07) */

                al_valflt = tvb_get_letohieee_float(tvb, data_pos);
                proto_item_append_text(point_item, ", Value: %g", al_valflt);
                proto_tree_add_item(point_tree, hf_dnp3_al_anaoutflt, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                data_pos += 4;
                break;

              case AL_OBJ_AO_DBL:     /* 64-Bit Floating Point Output Status (Obj:40, Var:04) */
              case AL_OBJ_AOC_DBLNT:  /* 64-Bit Floating Point Output Event w/o Time (Obj:42, Var:06) */
              case AL_OBJ_AOC_DBLT:   /* 64-Bit Floating Point Output Event w/ Time (Obj:42, Var:08) */

                al_valdbl = tvb_get_letohieee_double(tvb, data_pos);
                proto_item_append_text(point_item, ", Value: %g", al_valdbl);
                proto_tree_add_item(point_tree, hf_dnp3_al_anaoutdbl, tvb, data_pos, 8, ENC_LITTLE_ENDIAN);
                data_pos += 8;
                break;
            }

            /* Get timestamp */
            switch (al_obj)
            {
              case AL_OBJ_AOC_32T:
              case AL_OBJ_AOC_16T:
              case AL_OBJ_AOC_FLTT:
              case AL_OBJ_AOC_DBLT:
                dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
                proto_item_append_text(point_item, ", Timestamp: %s", abs_time_to_str(&al_abstime, ABSOLUTE_TIME_UTC, FALSE));
                proto_tree_add_time(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
                data_pos += 6;
                break;
            }

            proto_item_set_len(point_item, data_pos - offset);
            offset = data_pos;

            break;

          case AL_OBJ_TD:    /* Time and Date (Obj:50, Var:01) */
          case AL_OBJ_TDR:   /* Time and Date at Last Recorded Time (Obj:50, Var:03) */
          case AL_OBJ_TDCTO: /* Time and Date CTO (Obj:51, Var:01) */

            dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
            proto_tree_add_time(object_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
            data_pos += 6;
            proto_item_set_len(point_item, data_pos - offset);

            if (al_obj == AL_OBJ_TDCTO) {
              /* Copy the time object to the CTO for any other relative time objects in this response */
              nstime_copy(al_cto, &al_abstime);
            }

            offset = data_pos;
            break;

          case AL_OBJ_TDELAYF: /* Time Delay - Fine (Obj:52, Var:02) */

            al_val16 = tvb_get_letohs(tvb, data_pos);
            proto_tree_add_text(object_tree, tvb, data_pos, 2, "Time Delay: %u ms", al_val16);
            data_pos += 2;
            proto_item_set_len(point_item, data_pos - offset);

            offset = data_pos;
            break;

          case AL_OBJ_CLASS0:  /* Class Data Objects */
          case AL_OBJ_CLASS1:
          case AL_OBJ_CLASS2:
          case AL_OBJ_CLASS3:

            /* No data here */
            offset = data_pos;
            break;

          case AL_OBJ_FILE_CMD: /* File Control - File Command (Obj:70, Var:03) */
            /* File name offset and length */
            al_filename_offs = tvb_get_letohs(tvb, data_pos);
            proto_tree_add_text(point_tree, tvb, data_pos, 2, "File String Offset: %u", al_filename_offs);
            data_pos += 2;
            al_filename_len = tvb_get_letohs(tvb, data_pos);
            proto_tree_add_text(point_tree, tvb, data_pos, 2, "File String Length: %u", al_filename_len);
            data_pos += 2;

            /* Grab the mode as it determines if some of the following fields are relevant */
            al_file_ctrl_mode = tvb_get_letohs(tvb, data_pos + 16);

            /* Creation Time */
            if (al_file_ctrl_mode == AL_OBJ_FILE_MODE_WRITE) {
              dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
              proto_tree_add_time(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
            }
            data_pos += 6;

            /* Perms */
            if (al_file_ctrl_mode == AL_OBJ_FILE_MODE_WRITE) {

              perms_item = proto_tree_add_item(point_tree, hf_dnp3_al_file_perms, tvb, offset, 2, ENC_LITTLE_ENDIAN);

              perms_tree = proto_item_add_subtree(perms_item, ett_dnp3_al_obj_point_perms);
              proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_read_owner, tvb, offset, 2, ENC_LITTLE_ENDIAN);
              proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_write_owner, tvb, offset, 2, ENC_LITTLE_ENDIAN);
              proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_exec_owner, tvb, offset, 2, ENC_LITTLE_ENDIAN);
              proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_read_group, tvb, offset, 2, ENC_LITTLE_ENDIAN);
              proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_write_group, tvb, offset, 2, ENC_LITTLE_ENDIAN);
              proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_exec_group, tvb, offset, 2, ENC_LITTLE_ENDIAN);
              proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_read_world, tvb, offset, 2, ENC_LITTLE_ENDIAN);
              proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_write_world, tvb, offset, 2, ENC_LITTLE_ENDIAN);
              proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_exec_world, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            }
            data_pos += 2;

            /* Auth Key */
            proto_tree_add_item(point_tree, hf_dnp3_al_file_auth, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
            data_pos += 4;

            /* File Size */
            if (al_file_ctrl_mode == AL_OBJ_FILE_MODE_WRITE || al_file_ctrl_mode == AL_OBJ_FILE_MODE_APPEND) {
              proto_tree_add_item(point_tree, hf_dnp3_al_file_size, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
            }
            data_pos += 4;

            /* Mode */
            proto_tree_add_item(point_tree, hf_dnp3_al_file_mode, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
            data_pos += 2;

            /* Max Block Size */
            proto_tree_add_item(point_tree, hf_dnp3_al_file_maxblk, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
            data_pos += 2;

            /* Request ID */
            proto_tree_add_item(point_tree, hf_dnp3_al_file_reqID, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
            data_pos += 2;

            /* Filename */
            if (al_filename_len > 0) {
              al_filename = tvb_get_ephemeral_string(tvb, data_pos, al_filename_len);
              proto_tree_add_text(point_tree, tvb, data_pos, al_filename_len, "File Name: %s", al_filename);
            }
            data_pos += al_filename_len;
            proto_item_set_len(point_item, data_pos - offset);

            offset = data_pos;
            break;

          case AL_OBJ_FILE_STAT: /* File Control - File Status (Obj:70, Var:04) */

            /* File Handle */
            proto_tree_add_item(point_tree, hf_dnp3_al_file_handle, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
            data_pos += 4;

            /* File Size */
            proto_tree_add_item(point_tree, hf_dnp3_al_file_size, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
            data_pos += 4;

            /* Max Block Size */
            proto_tree_add_item(point_tree, hf_dnp3_al_file_maxblk, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
            data_pos += 2;

            /* Request ID */
            proto_tree_add_item(point_tree, hf_dnp3_al_file_reqID, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
            data_pos += 2;

            /* Status code */
            proto_tree_add_item(point_tree, hf_dnp3_al_file_status, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
            data_pos += 1;

            /* Optional text */
            file_data_size = al_ptaddr - (data_pos - offset - indexbytes);
            if ((file_data_size) > 0) {
              proto_tree_add_item(point_tree, hf_dnp3_al_file_data, tvb, data_pos, file_data_size, ENC_NA);
              data_pos += file_data_size;
            }

            proto_item_set_len(point_item, data_pos - offset);

            offset = data_pos;
            break;

          case AL_OBJ_FILE_TRANS: /* File Control - File Transport (Obj:70, Var:05) */

            /* File Handle */
            proto_tree_add_item(point_tree, hf_dnp3_al_file_handle, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
            data_pos += 4;

            /* File block (bits 0 - 30) and last block flag (bit 31) */
            proto_tree_add_item(point_tree, hf_dnp3_al_file_blocknum, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(point_tree, hf_dnp3_al_file_lastblock, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
            data_pos += 4;

            /* File data */
            file_data_size = al_ptaddr - (data_pos - offset - indexbytes);
            if ((file_data_size) > 0) {
              proto_tree_add_item(point_tree, hf_dnp3_al_file_data, tvb, data_pos, file_data_size, ENC_NA);
              data_pos += file_data_size;
            }

            proto_item_set_len(point_item, data_pos - offset);

            offset = data_pos;
            break;

          case AL_OBJ_FILE_TRAN_ST: /* File Control Tansport Status (Obj:70, Var:06) */

            /* File Handle */
            proto_tree_add_item(point_tree, hf_dnp3_al_file_handle, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
            data_pos += 4;

            /* File block (bits 0 - 30) and last block flag (bit 31) */
            proto_tree_add_item(point_tree, hf_dnp3_al_file_blocknum, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(point_tree, hf_dnp3_al_file_lastblock, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
            data_pos += 4;

            /* Status code */
            proto_tree_add_item(point_tree, hf_dnp3_al_file_status, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
            data_pos += 1;

            /* Optional text */
            file_data_size = al_ptaddr - (data_pos - offset - indexbytes);
            if ((file_data_size) > 0) {
              proto_tree_add_item(point_tree, hf_dnp3_al_file_data, tvb, data_pos, file_data_size, ENC_NA);
              data_pos += file_data_size;
            }

            proto_item_set_len(point_item, data_pos - offset);

            offset = data_pos;
            break;

          case AL_OBJ_IIN:     /* IIN Data Object */

            /* Single byte of data here */
            proto_tree_add_text(object_tree, tvb, data_pos, 1, "Value: %u", tvb_get_guint8(tvb, data_pos));
            data_pos += 1;
            proto_item_set_len(point_item, data_pos - offset);

            offset = data_pos;
            break;

          case AL_OBJ_OCT:      /* Octet string */
          case AL_OBJ_OCT_EVT:  /* Octet string event */

            /* read the number of bytes defined by the variation */
            if (al_oct_len > 0) {
              proto_tree_add_text(object_tree, tvb, data_pos, al_oct_len, "Octet String (%u bytes)", al_oct_len);
              data_pos += al_oct_len;
              proto_item_set_len(point_item, data_pos - offset);
            }

            offset = data_pos;
            break;

          default:             /* In case of unknown object */

            proto_tree_add_text(object_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset),
              "Unknown Data Chunk, %u Bytes", tvb_reported_length_remaining(tvb, offset));
            offset = tvb_length(tvb); /* Finish decoding if unknown object is encountered... */
            break;
        }
        /* Increment the bit index for next time */
        bitindex++;

        /* And increment the point address, may be overwritten by an index value */
        al_ptaddr++;
      }
      if (start_offset > offset) {
        expert_add_info_format(pinfo, point_item, PI_MALFORMED, PI_ERROR, "Invalid length");
        offset = tvb_length(tvb); /* Finish decoding if unknown object is encountered... */
      }
    }
  }
  proto_item_set_len(object_item, offset - orig_offset);

  return offset;
}

/*****************************************************************/
/* Application Layer Dissector */
/*****************************************************************/
static int
dissect_dnp3_al(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8        al_ctl, al_seq, al_func, al_class = 0, i;
  guint16       bytes, obj_type;
  guint         data_len = 0, offset = 0;
  proto_item   *ti = NULL, *tc, *t_robj;
  proto_tree   *al_tree = NULL, *field_tree = NULL, *robj_tree = NULL;
  const gchar  *func_code_str;
  nstime_t      al_cto;

  nstime_set_zero (&al_cto);

  data_len = tvb_length(tvb);

  /* Handle the control byte and function code */
  al_ctl = tvb_get_guint8(tvb, offset);
  al_seq = al_ctl & DNP3_AL_SEQ;
  al_func = tvb_get_guint8(tvb, (offset+1));
  func_code_str = val_to_str_ext(al_func, &dnp3_al_func_vals_ext, "Unknown function (0x%02x)");

  /* Clear out lower layer info */
  col_clear(pinfo->cinfo, COL_INFO);
  col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", func_code_str);
  col_set_fence(pinfo->cinfo, COL_INFO);

  /* format up the text representation */
  ti = proto_tree_add_text(tree, tvb, offset, data_len, "Application Layer: (");
  if (al_ctl & DNP3_AL_FIR)  proto_item_append_text(ti, "FIR, ");
  if (al_ctl & DNP3_AL_FIN)  proto_item_append_text(ti, "FIN, ");
  if (al_ctl & DNP3_AL_CON)  proto_item_append_text(ti, "CON, ");
  if (al_ctl & DNP3_AL_UNS)  proto_item_append_text(ti, "UNS, ");
  proto_item_append_text(ti, "Sequence %u, %s)", al_seq, func_code_str);

  /* Add the al tree branch */
  al_tree = proto_item_add_subtree(ti, ett_dnp3_al);

  /* Application Layer control byte subtree */
  tc = proto_tree_add_uint_format(al_tree, hf_dnp3_al_ctl, tvb, offset, 1, al_ctl,
      "Control: 0x%02x (", al_ctl);
  if (al_ctl & DNP3_AL_FIR)  proto_item_append_text(tc, "FIR, ");
  if (al_ctl & DNP3_AL_FIN)  proto_item_append_text(tc, "FIN, ");
  if (al_ctl & DNP3_AL_CON)  proto_item_append_text(tc, "CON, ");
  if (al_ctl & DNP3_AL_UNS)  proto_item_append_text(tc, "UNS, ");
  proto_item_append_text(tc, "Sequence %u)", al_seq);

  field_tree = proto_item_add_subtree(tc, ett_dnp3_al_ctl);
  proto_tree_add_boolean(field_tree, hf_dnp3_al_fir, tvb, offset, 1, al_ctl);
  proto_tree_add_boolean(field_tree, hf_dnp3_al_fin, tvb, offset, 1, al_ctl);
  proto_tree_add_boolean(field_tree, hf_dnp3_al_con, tvb, offset, 1, al_ctl);
  proto_tree_add_boolean(field_tree, hf_dnp3_al_uns, tvb, offset, 1, al_ctl);
  proto_tree_add_item(field_tree, hf_dnp3_al_seq, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

#if 0
  /* If this packet is NOT the final Application Layer Message, exit and continue
     processing the remaining data in the fragment. */
  if (!(al_ctl & DNP3_AL_FIN)) {
    t_robj = proto_tree_add_text(al_tree, tvb, offset, -1, "Buffering User Data Until Final Frame is Received..");
    return 1;
  }
#endif

  /* Application Layer Function Code Byte  */
  proto_tree_add_uint_format(al_tree, hf_dnp3_al_func, tvb, offset, 1, al_func,
    "Function Code: %s (0x%02x)", func_code_str, al_func);
  offset += 1;

  switch (al_func) {

  case AL_FUNC_READ:     /* Read Function Code 0x01 */

  /* Create Read Request Data Objects Tree */
  t_robj = proto_tree_add_text(al_tree, tvb, offset, -1, "READ Request Data Objects");
  robj_tree = proto_item_add_subtree(t_robj, ett_dnp3_al_objdet);

  /* Process Data Object Details */
  while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
    offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, TRUE, &obj_type, &al_cto);

    /* Update class type for each object that was a class read */
    switch(obj_type) {
      case AL_OBJ_CLASS0:
      case AL_OBJ_CLASS1:
      case AL_OBJ_CLASS2:
      case AL_OBJ_CLASS3:
        al_class |= (1 << ((obj_type & 0x0f) - 1));
        break;
      default:
        break;
    }
  }

  /* Update the col info if there were class reads */
  col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Class ");
  for (i = 0; i < 4; i++) {
    if (al_class & (1 << i)) {
      col_append_fstr(pinfo->cinfo, COL_INFO, "%u", i);
    }
  }

  break;

  case AL_FUNC_WRITE:     /* Write Function Code 0x02 */

  /* Create Write Request Data Objects Tree */
  t_robj = proto_tree_add_text(al_tree, tvb, offset, -1, "WRITE Request Data Objects");
  robj_tree = proto_item_add_subtree(t_robj, ett_dnp3_al_objdet);

  /* Process Data Object Details */
  while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
    offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
  }

  break;

  case AL_FUNC_SELECT:     /* Select Function Code 0x03 */

  /* Create Select Request Data Objects Tree */
  t_robj = proto_tree_add_text(al_tree, tvb, offset, -1, "SELECT Request Data Objects");
  robj_tree = proto_item_add_subtree(t_robj, ett_dnp3_al_objdet);

  /* Process Data Object Details */
  while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
    offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
  }

  break;

  case AL_FUNC_OPERATE:    /* Operate Function Code 0x04 */
             /* Functionally identical to 'SELECT' Function Code */

  /* Create Operate Request Data Objects Tree */
  t_robj = proto_tree_add_text(al_tree, tvb, offset, -1, "OPERATE Request Data Objects");
  robj_tree = proto_item_add_subtree(t_robj, ett_dnp3_al_objdet);

  /* Process Data Object Details */
  while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
    offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
  }

  break;

  case AL_FUNC_DIROP:     /* Direct Operate Function Code 0x05 */
            /* Functionally identical to 'SELECT' Function Code */

  /* Create Direct Operate Request Data Objects Tree */
  t_robj = proto_tree_add_text(al_tree, tvb, offset, -1, "DIRECT OPERATE Request Data Objects");
  robj_tree = proto_item_add_subtree(t_robj, ett_dnp3_al_objdet);

  /* Process Data Object Details */
  while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
    offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
  }

  break;

  case AL_FUNC_ENSPMSG:   /* Enable Spontaneous Messages Function Code 0x14 */

  /* Create Enable Spontaneous Messages Data Objects Tree */
  t_robj = proto_tree_add_text(al_tree, tvb, offset, -1, "Enable Spontaneous Msg's Data Objects");
  robj_tree = proto_item_add_subtree(t_robj, ett_dnp3_al_objdet);

  /* Process Data Object Details */
  while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
    offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
  }

  break;

  case AL_FUNC_DISSPMSG:   /* Disable Spontaneous Messages Function Code 0x15 */

  /* Create Disable Spontaneous Messages Data Objects Tree */
  t_robj = proto_tree_add_text(al_tree, tvb, offset, -1, "Disable Spontaneous Msg's Data Objects");
  robj_tree = proto_item_add_subtree(t_robj, ett_dnp3_al_objdet);

  /* Process Data Object Details */
  while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
    offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
  }

  break;

  case AL_FUNC_DELAYMST:  /* Delay Measurement Function Code 0x17 */

  break;

  case AL_FUNC_OPENFILE:        /* Open File Function Code 0x19 */
  case AL_FUNC_CLOSEFILE:       /* Close File Function Code 0x1A */
  case AL_FUNC_DELETEFILE:      /* Delete File Function Code 0x1B */

  /* Create File Data Objects Tree */
  t_robj = proto_tree_add_text(al_tree, tvb, offset, -1, "File Data Objects");
  robj_tree = proto_item_add_subtree(t_robj, ett_dnp3_al_objdet);

  /* Process Data Object Details */
  while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
    offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
  }

  break;

  case AL_FUNC_RESPON:   /* Response Function Code 0x81 */
  case AL_FUNC_UNSOLI:   /* Unsolicited Response Function Code 0x82 */

  /* Application Layer IIN bits req'd if message is a response */
  dnp3_al_process_iin(tvb, offset, al_tree);
  offset += 2;

  /* Ensure there is actual data remaining in the message.
     A response will not contain data following the IIN bits,
     if there is none available */
  bytes = tvb_reported_length_remaining(tvb, offset);
  if (bytes > 0)
  {
    /* Create Response Data Objects Tree */
    t_robj = proto_tree_add_text(al_tree, tvb, offset, -1,"RESPONSE Data Objects");
    robj_tree = proto_item_add_subtree(t_robj, ett_dnp3_al_objdet);

    /* Process Data Object Details */
    while (offset <= (data_len-2)) {  /* 2 octet object code + CRC32 */
      offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
    }

    break;
  }

  default:    /* Unknown Function */

  break;
  }

  return 0;
}

/*****************************************************************/
/* Data Link and Transport layer dissector */
/*****************************************************************/
static void
dissect_dnp3_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
    proto_item        *ti = NULL, *tdl, *tc, *al_chunks, *hidden_item;
    proto_tree        *dnp3_tree = NULL, *dl_tree = NULL, *tr_tree = NULL, *field_tree = NULL, *al_tree = NULL;
    int               offset = 0, temp_offset = 0;
    gboolean          dl_prm, tr_fir, tr_fin;
    guint8            dl_len, dl_ctl, dl_func, tr_ctl, tr_seq;
    const gchar       *func_code_str;
    guint16           dl_dst, dl_src, dl_crc, calc_dl_crc;
    guint8            *tmp = NULL, *tmp_ptr;
    guint8            data_len;
    int               data_offset;
    gboolean          crc_OK = FALSE;
    tvbuff_t          *al_tvb = NULL, *next_tvb;
    guint             i;
    guint             conv_seq_number;
    gboolean          save_fragmented;
    fragment_data     *frag_msg;
    gboolean          update_col_info = TRUE;
    conversation_t    *conversation;
    dnp3_conv_t       *conv_data_ptr;
    dl_conversation_key_t dl_conversation_key;



/* Make entries in Protocol column and Info column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DNP 3.0");

  col_clear(pinfo->cinfo, COL_INFO);

  /* Skip "0x0564" header bytes */
  temp_offset += 2;

  dl_len = tvb_get_guint8(tvb, temp_offset);
  temp_offset += 1;

  dl_ctl = tvb_get_guint8(tvb, temp_offset);
  temp_offset += 1;

  dl_dst = tvb_get_letohs(tvb, temp_offset);
  temp_offset += 2;

  dl_src = tvb_get_letohs(tvb, temp_offset);

  dl_func = dl_ctl & DNP3_CTL_FUNC;
  dl_prm = dl_ctl & DNP3_CTL_PRM;
  func_code_str = val_to_str(dl_func, dl_prm ? dnp3_ctl_func_pri_vals : dnp3_ctl_func_sec_vals,
           "Unknown function (0x%02x)");

  /* Make sure source and dest are always in the info column */
  col_append_fstr(pinfo->cinfo, COL_INFO, "from %u to %u", dl_src, dl_dst);
  col_set_fence(pinfo->cinfo, COL_INFO);
  col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "len=%u, %s", dl_len, func_code_str);

  /* create display subtree for the protocol */
  ti = proto_tree_add_item(tree, proto_dnp3, tvb, offset, -1, ENC_NA);
  dnp3_tree = proto_item_add_subtree(ti, ett_dnp3);

  /* Create Subtree for Data Link Layer */
  tdl = proto_tree_add_text(dnp3_tree, tvb, offset, DNP_HDR_LEN,
        "Data Link Layer, Len: %u, From: %u, To: %u, ", dl_len, dl_src, dl_dst);
  if (dl_prm) {
    if (dl_ctl & DNP3_CTL_DIR) proto_item_append_text(tdl, "DIR, ");
    if (dl_ctl & DNP3_CTL_PRM) proto_item_append_text(tdl, "PRM, ");
    if (dl_ctl & DNP3_CTL_FCB) proto_item_append_text(tdl, "FCB, ");
    if (dl_ctl & DNP3_CTL_FCV) proto_item_append_text(tdl, "FCV, ");
  }
  else {
    if (dl_ctl & DNP3_CTL_DIR) proto_item_append_text(tdl, "DIR, ");
    if (dl_ctl & DNP3_CTL_PRM) proto_item_append_text(tdl, "PRM, ");
    if (dl_ctl & DNP3_CTL_RES) proto_item_append_text(tdl, "RES, ");
    if (dl_ctl & DNP3_CTL_DFC) proto_item_append_text(tdl, "DFC, ");
  }
  proto_item_append_text(tdl, "%s", func_code_str);
  dl_tree = proto_item_add_subtree(tdl, ett_dnp3_dl);

  /* start bytes */
  proto_tree_add_item(dl_tree, hf_dnp3_start, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* add length field */
  proto_tree_add_item(dl_tree, hf_dnp3_len, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  /* Add Control Byte Subtree */
  tc = proto_tree_add_uint_format(dl_tree, hf_dnp3_ctl, tvb, offset, 1, dl_ctl,
          "Control: 0x%02x (", dl_ctl);
  /* Add Text to Control Byte Subtree Header */
  if (dl_prm) {
    if (dl_ctl & DNP3_CTL_DIR) proto_item_append_text(tc, "DIR, ");
    if (dl_ctl & DNP3_CTL_PRM) proto_item_append_text(tc, "PRM, ");
    if (dl_ctl & DNP3_CTL_FCB) proto_item_append_text(tc, "FCB, ");
    if (dl_ctl & DNP3_CTL_FCV) proto_item_append_text(tc, "FCV, ");
  }
  else {
    if (dl_ctl & DNP3_CTL_DIR) proto_item_append_text(tc, "DIR, ");
    if (dl_ctl & DNP3_CTL_PRM) proto_item_append_text(tc, "PRM, ");
    if (dl_ctl & DNP3_CTL_RES) proto_item_append_text(tc, "RES, ");
    if (dl_ctl & DNP3_CTL_DFC) proto_item_append_text(tc, "DFC, ");
  }
  proto_item_append_text(tc, "%s)", func_code_str );
  field_tree = proto_item_add_subtree(tc, ett_dnp3_dl_ctl);

  /* Add Control Byte Subtree Items */
  if (dl_prm) {
    proto_tree_add_item(field_tree, hf_dnp3_ctl_dir, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(field_tree, hf_dnp3_ctl_prm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(field_tree, hf_dnp3_ctl_fcb, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(field_tree, hf_dnp3_ctl_fcv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(field_tree, hf_dnp3_ctl_prifunc, tvb, offset, 1, ENC_BIG_ENDIAN);
  }
  else {
    proto_tree_add_item(field_tree, hf_dnp3_ctl_dir, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(field_tree, hf_dnp3_ctl_prm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(field_tree, hf_dnp3_ctl_dfc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(field_tree, hf_dnp3_ctl_secfunc, tvb, offset, 1, ENC_BIG_ENDIAN);
  }
    offset += 1;

  /* add destination and source addresses */
  proto_tree_add_item(dl_tree, hf_dnp3_dst, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(dl_tree, hf_dnp3_src, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  /* and header CRC */
  dl_crc = tvb_get_letohs(tvb, offset);
  calc_dl_crc = calculateCRC(tvb_get_ptr(tvb, 0, DNP_HDR_LEN - 2), DNP_HDR_LEN - 2);
  if (dl_crc == calc_dl_crc)
    proto_tree_add_uint_format(dl_tree, hf_dnp_hdr_CRC, tvb, offset, 2,
                               dl_crc, "CRC: 0x%04x [correct]", dl_crc);
  else
  {
    hidden_item = proto_tree_add_boolean(dl_tree, hf_dnp_hdr_CRC_bad, tvb,
                                         offset, 2, TRUE);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    proto_tree_add_uint_format(dl_tree, hf_dnp_hdr_CRC, tvb, offset, 2,
                               dl_crc, "CRC: 0x%04x [incorrect, should be 0x%04x]",
                               dl_crc, calc_dl_crc);
  }
  offset += 2;

  /* If the DataLink function is 'Request Link Status' or 'Status of Link',
     or 'Reset Link' we don't expect any Transport or Application Layer Data
     NOTE: This code should probably check what DOES have TR or AL data */
  if ((dl_func != DL_FUNC_LINK_STAT) && (dl_func != DL_FUNC_STAT_LINK) &&
      (dl_func != DL_FUNC_RESET_LINK) && (dl_func != DL_FUNC_ACK))
  {

    /* get the transport layer byte */
    tr_ctl = tvb_get_guint8(tvb, offset);
    tr_seq = tr_ctl & DNP3_TR_SEQ;
    tr_fir = tr_ctl & DNP3_TR_FIR;
    tr_fin = tr_ctl & DNP3_TR_FIN;

    /* Add Transport Layer Tree */
    tc = proto_tree_add_uint_format(dnp3_tree, hf_dnp3_tr_ctl, tvb, offset, 1, tr_ctl,
            "Transport Layer: 0x%02x (", tr_ctl);
    if (tr_fir) proto_item_append_text(tc, "FIR, ");
    if (tr_fin) proto_item_append_text(tc, "FIN, ");
    proto_item_append_text(tc, "Sequence %u)", tr_seq);

    tr_tree = proto_item_add_subtree(tc, ett_dnp3_tr_ctl);
    proto_tree_add_boolean(tr_tree, hf_dnp3_tr_fin, tvb, offset, 1, tr_ctl);
    proto_tree_add_boolean(tr_tree, hf_dnp3_tr_fir, tvb, offset, 1, tr_ctl);
    proto_tree_add_item(tr_tree, hf_dnp3_tr_seq, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Allocate AL chunk tree */
    al_chunks = proto_tree_add_text(tr_tree, tvb, offset + 1, -1, "Application data chunks");
    al_tree = proto_item_add_subtree(al_chunks, ett_dnp3_al_data);

    /* extract the application layer data, validating the CRCs */

    /* XXX - check for dl_len <= 5 */
    data_len = dl_len - 5;
    tmp = g_malloc(data_len);
    tmp_ptr = tmp;
    i = 0;
    data_offset = 1;  /* skip the transport layer byte when assembling chunks */
    while(data_len > 0)
    {
      guint8 chk_size;
      const guint8 *chk_ptr;
      guint16 calc_crc, act_crc;

      chk_size = MIN(data_len, AL_MAX_CHUNK_SIZE);
      chk_ptr = tvb_get_ptr(tvb, offset, chk_size);
      memcpy(tmp_ptr, chk_ptr + data_offset, chk_size - data_offset);
      calc_crc = calculateCRC(chk_ptr, chk_size);
      offset += chk_size;
      tmp_ptr += chk_size - data_offset;
      act_crc = tvb_get_letohs(tvb, offset);
      offset += 2;
      crc_OK = calc_crc == act_crc;
      if (crc_OK)
      {
        proto_tree_add_text(al_tree, tvb, offset - (chk_size + 2), chk_size + 2,
                            "Application Chunk %u Len: %u CRC 0x%04x",
                            i, chk_size, act_crc);
        data_len -= chk_size;
      }
      else
      {
        proto_tree_add_text(al_tree, tvb, offset - (chk_size + 2), chk_size + 2,
                            "Application Chunk %u Len: %u Bad CRC got 0x%04x expected 0x%04x",
                            i, chk_size, act_crc, calc_crc);
        break;
      }
      i++;
      data_offset = 0;  /* copy all of the rest of the chunks */
    }

    /* if all crc OK, set up new tvb */
    if (crc_OK)
    {
      al_tvb = tvb_new_child_real_data(tvb, tmp, (guint) (tmp_ptr-tmp), (gint) (tmp_ptr-tmp));
      tvb_set_free_cb(al_tvb, g_free);

      /* Check for fragmented packet */
      save_fragmented = pinfo->fragmented;
      if (! (tr_fir && tr_fin))
      {
        /* A fragmented packet */
        pinfo->fragmented = TRUE;

        /* Look up the conversation to get the fragment reassembly id */
        conversation = find_or_create_conversation(pinfo);

        /*
         * The TCP/UDP conversation is not sufficient to identify a conversation
         * on a multi-drop DNP network.  Lookup conversation data based on TCP/UDP
         * conversation and the DNP src and dst addresses
         */

        dl_conversation_key.conversation = conversation->index;
        dl_conversation_key.src = dl_src;
        dl_conversation_key.dst = dl_dst;

        conv_data_ptr = (dnp3_conv_t*)g_hash_table_lookup(dl_conversation_table, &dl_conversation_key);

        if(!pinfo->fd->flags.visited && conv_data_ptr == NULL)
        {
          dl_conversation_key_t* new_dl_conversation_key = NULL;
          new_dl_conversation_key = se_alloc(sizeof(dl_conversation_key_t));
          *new_dl_conversation_key = dl_conversation_key;

          conv_data_ptr = se_alloc(sizeof(dnp3_conv_t));

          /*** Increment static global fragment reassembly id ***/
          conv_data_ptr->conv_seq_number = seq_number++;

          g_hash_table_insert(dl_conversation_table, new_dl_conversation_key, conv_data_ptr);
        }

        conv_seq_number = conv_data_ptr->conv_seq_number;

        /*
        * Add the frame to
        * whatever reassembly is in progress, if any, and see
        * if it's done.
        */

        frag_msg = fragment_add_seq_next(al_tvb, 0, pinfo, conv_seq_number,
            al_fragment_table,
            al_reassembled_table,
            tvb_reported_length(al_tvb), /* As this is a constructed tvb, all of it is ok */
            !tr_fin);

        next_tvb = process_reassembled_data(al_tvb, 0, pinfo,
            "Reassembled DNP 3.0 Application Layer message", frag_msg, &dnp3_frag_items,
            &update_col_info, tr_tree);

        if (next_tvb) { /* Reassembled */
          /* We have the complete payload */
          col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Reassembled Application Layer");
        }
        else
        {
          /* We don't have the complete reassembled payload. */
          col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Transport Layer fragment %u ", tr_seq);
        }

      }
      else
      {
        /* No reassembly required */
        next_tvb = al_tvb;
        add_new_data_source(pinfo, next_tvb, "DNP 3.0 Application Layer message");
        col_clear(pinfo->cinfo, COL_INFO);
      }
      pinfo->fragmented = save_fragmented;
    }
    else
    {
      /* CRC error - throw away the data. */
      next_tvb = NULL;
      g_free(tmp);
      proto_tree_add_text(dnp3_tree, tvb, 11, -1, "CRC failed, %u chunks", i);
    }

    if (next_tvb)
      dissect_dnp3_al(next_tvb, pinfo, dnp3_tree);
  }
}

static guint
get_dnp3_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint16 message_len;  /* need 16 bits as total can exceed 255 */
  guint16 data_crc;     /* No. of user data CRC bytes */
  message_len = tvb_get_guint8(tvb, offset + 2);

  /* Add in 2 bytes for header start octets,
            1 byte for len itself,
            2 bytes for header CRC
            data CRC bytes (2 bytes per 16 bytes of data
  */

  data_crc = (guint16)(ceil((message_len - 5) / 16.0)) * 2;
  message_len += 2 + 1 + 2 + data_crc;
  return message_len;
}

static gboolean
dissect_dnp3_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  gint length = tvb_length(tvb);

  /* Check for a dnp packet.  It should begin with 0x0564 */
  if(length < 2 || tvb_get_ntohs(tvb, 0) != 0x0564) {
    /* Not a DNP 3.0 packet, just happened to use the same port */
    return FALSE;
  }

  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, DNP_HDR_LEN,
                   get_dnp3_message_len, dissect_dnp3_message);

  return TRUE;
}

static gboolean
dissect_dnp3_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  gint length = tvb_length(tvb);
  /* Check for a dnp packet.  It should begin with 0x0564 */
  if(length < 2 || tvb_get_ntohs(tvb, 0) != 0x0564) {
    /* Not a DNP 3.0 packet, just happened to use the same port */
    return FALSE;
  }

  dissect_dnp3_message(tvb, pinfo, tree);
  return TRUE;
}

static void
dnp3_init(void)
{
  if (dl_conversation_table)
  {
    g_hash_table_destroy(dl_conversation_table);
  }
  dl_conversation_table = g_hash_table_new(dl_conversation_hash, dl_conversation_equal);

  fragment_table_init(&al_fragment_table);
  reassembled_table_init(&al_reassembled_table);
}

/* Register the protocol with Wireshark */

void
proto_register_dnp3(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_dnp3_start,
    { "Start Bytes", "dnp3.start", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_dnp3_len,
    { "Length", "dnp3.len", FT_UINT8, BASE_DEC, NULL, 0x0, "Frame Data Length", HFILL }},

    { &hf_dnp3_ctl,
    { "Control", "dnp3.ctl", FT_UINT8, BASE_HEX, NULL, 0x0, "Frame Control Byte", HFILL }},

    { &hf_dnp3_ctl_prifunc,
    { "Control Function Code", "dnp3.ctl.prifunc", FT_UINT8, BASE_DEC,
      VALS(dnp3_ctl_func_pri_vals), DNP3_CTL_FUNC, "Frame Control Function Code", HFILL }},

    { &hf_dnp3_ctl_secfunc,
    { "Control Function Code", "dnp3.ctl.secfunc", FT_UINT8, BASE_DEC,
      VALS(dnp3_ctl_func_sec_vals), DNP3_CTL_FUNC, "Frame Control Function Code", HFILL }},

    { &hf_dnp3_ctlobj_code_c,
    { "Operation Type", "dnp3.ctl.op", FT_UINT8, BASE_DEC,
      VALS(dnp3_al_ctlc_code_vals), AL_OBJCTLC_CODE, "Control Code, Operation Type", HFILL }},
            
    { &hf_dnp3_ctlobj_code_m,
    { "Queue / Clear Field", "dnp3.ctl.clr", FT_UINT8, BASE_DEC,
      VALS(dnp3_al_ctlc_misc_vals), AL_OBJCTLC_MISC, "Control Code, Clear Field", HFILL }},
     
    { &hf_dnp3_ctlobj_code_tc,
    { "Trip Control Code", "dnp3.ctl.trip", FT_UINT8, BASE_DEC,
      VALS(dnp3_al_ctlc_tc_vals), AL_OBJCTLC_TC, "Control Code, Trip Close Control", HFILL }},

    { &hf_dnp3_ctl_dir,
    { "Direction", "dnp3.ctl.dir", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_CTL_DIR, NULL, HFILL }},

    { &hf_dnp3_ctl_prm,
    { "Primary", "dnp3.ctl.prm", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_CTL_PRM, NULL, HFILL }},

    { &hf_dnp3_ctl_fcb,
    { "Frame Count Bit", "dnp3.ctl.fcb", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_CTL_FCB, NULL, HFILL }},

    { &hf_dnp3_ctl_fcv,
    { "Frame Count Valid", "dnp3.ctl.fcv", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_CTL_FCV, NULL, HFILL }},

    { &hf_dnp3_ctl_dfc,
    { "Data Flow Control", "dnp3.ctl.dfc", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_CTL_DFC, NULL, HFILL }},

    { &hf_dnp3_dst,
    { "Destination", "dnp3.dst", FT_UINT16, BASE_DEC, NULL, 0x0, "Destination Address", HFILL }},

    { &hf_dnp3_src,
    { "Source", "dnp3.src", FT_UINT16, BASE_DEC, NULL, 0x0, "Source Address", HFILL }},

    { &hf_dnp_hdr_CRC,
    { "CRC", "dnp3.hdr.CRC", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_dnp_hdr_CRC_bad,
    { "Bad CRC", "dnp3.hdr.CRC_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_dnp3_tr_ctl,
    { "Transport Control", "dnp3.tr.ctl", FT_UINT8, BASE_HEX, NULL, 0x0, "Transport Layer Control Byte", HFILL }},

    { &hf_dnp3_tr_fin,
    { "Final", "dnp3.tr.fin", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_TR_FIN, NULL, HFILL }},

    { &hf_dnp3_tr_fir,
    { "First", "dnp3.tr.fir", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_TR_FIR, NULL, HFILL }},

    { &hf_dnp3_tr_seq,
    { "Sequence", "dnp3.tr.seq", FT_UINT8, BASE_DEC, NULL, DNP3_TR_SEQ, "Frame Sequence Number", HFILL }},

    { &hf_dnp3_al_ctl,
    { "Application Control", "dnp3.al.ctl", FT_UINT8, BASE_HEX, NULL, 0x0, "Application Layer Control Byte", HFILL }},

    { &hf_dnp3_al_fir,
    { "First", "dnp3.al.fir", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_AL_FIR, NULL, HFILL }},

    { &hf_dnp3_al_fin,
    { "Final", "dnp3.al.fin", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_AL_FIN, NULL, HFILL }},

    { &hf_dnp3_al_con,
    { "Confirm", "dnp3.al.con", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_AL_CON, NULL, HFILL }},

    { &hf_dnp3_al_uns,
    { "Unsolicited", "dnp3.al.uns", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_AL_UNS, NULL, HFILL }},

    { &hf_dnp3_al_seq,
    { "Sequence", "dnp3.al.seq", FT_UINT8, BASE_DEC, NULL, DNP3_AL_SEQ, "Frame Sequence Number", HFILL }},

    { &hf_dnp3_al_func,
    { "Application Layer Function Code", "dnp3.al.func", FT_UINT8, BASE_DEC|BASE_EXT_STRING,
      &dnp3_al_func_vals_ext, DNP3_AL_FUNC, "Application Function Code", HFILL }},

    { &hf_dnp3_al_iin,
    { "Application Layer IIN bits", "dnp3.al.iin", FT_UINT16, BASE_DEC, NULL, 0x0, "Application Layer IIN", HFILL }},

    { &hf_dnp3_al_iin_bmsg,
    { "Broadcast Msg Rx", "dnp3.al.iin.bmsg", FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_BMSG, NULL, HFILL }},

    { &hf_dnp3_al_iin_cls1d,
    { "Class 1 Data Available", "dnp3.al.iin.cls1d", FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_CLS1D, NULL, HFILL }},

    { &hf_dnp3_al_iin_cls2d,
    { "Class 2 Data Available", "dnp3.al.iin.cls2d", FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_CLS2D, NULL, HFILL }},

    { &hf_dnp3_al_iin_cls3d,
    { "Class 3 Data Available", "dnp3.al.iin.cls3d", FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_CLS3D, NULL, HFILL }},

    { &hf_dnp3_al_iin_tsr,
    { "Time Sync Required", "dnp3.al.iin.tsr", FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_TSR, NULL, HFILL }},

    { &hf_dnp3_al_iin_dol,
    { "Digital Outputs in Local", "dnp3.al.iin.dol", FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_DOL, NULL, HFILL }},

    { &hf_dnp3_al_iin_dt,
    { "Device Trouble", "dnp3.al.iin.dt", FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_DT, NULL, HFILL }},

    { &hf_dnp3_al_iin_rst,
    { "Device Restart", "dnp3.al.iin.rst", FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_RST, NULL, HFILL }},

    { &hf_dnp3_al_iin_fcni,
    { "Function Code not implemented", "dnp3.al.iin.fcni", FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_FCNI, NULL, HFILL }},

    { &hf_dnp3_al_iin_obju,
    { "Requested Objects Unknown", "dnp3.al.iin.obju", FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_OBJU, NULL, HFILL }},

    { &hf_dnp3_al_iin_pioor,
    { "Parameters Invalid or Out of Range", "dnp3.al.iin.pioor", FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_PIOOR, NULL, HFILL }},

    { &hf_dnp3_al_iin_ebo,
    { "Event Buffer Overflow", "dnp3.al.iin.ebo", FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_EBO, NULL, HFILL }},

    { &hf_dnp3_al_iin_oae,
    { "Operation Already Executing", "dnp3.al.iin.oae", FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_OAE, NULL, HFILL }},

    { &hf_dnp3_al_iin_cc,
    { "Configuration Corrupt", "dnp3.al.iin.cc", FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_CC, NULL, HFILL }},

    { &hf_dnp3_al_obj,
    { "Object", "dnp3.al.obj", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &dnp3_al_obj_vals_ext, 0x0, "Application Layer Object", HFILL }},

    { &hf_dnp3_al_objq_index,
    { "Index Prefix", "dnp3.al.objq.index", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_objq_index_vals_ext, AL_OBJQ_INDEX, "Object Index Prefixing", HFILL }},

    { &hf_dnp3_al_objq_code,
    { "Qualifier Code", "dnp3.al.objq.code", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_objq_code_vals_ext, AL_OBJQ_CODE, "Object Qualifier Code", HFILL }},

    { &hf_dnp3_al_range_start8,
    { "Start (8 bit)", "dnp3.al.range.start", FT_UINT8, BASE_DEC, NULL, 0x0, "Object Start Index", HFILL }},

    { &hf_dnp3_al_range_stop8,
    { "Stop (8 bit)", "dnp3.al.range.stop", FT_UINT8, BASE_DEC, NULL, 0x0, "Object Stop Index", HFILL }},

    { &hf_dnp3_al_range_start16,
    { "Start (16 bit)", "dnp3.al.range.start", FT_UINT16, BASE_DEC, NULL, 0x0, "Object Start Index", HFILL }},

    { &hf_dnp3_al_range_stop16,
    { "Stop (16 bit)", "dnp3.al.range.stop", FT_UINT16, BASE_DEC, NULL, 0x0, "Object Stop Index", HFILL }},

    { &hf_dnp3_al_range_start32,
    { "Start (32 bit)", "dnp3.al.range.start", FT_UINT32, BASE_DEC, NULL, 0x0, "Object Start Index", HFILL }},

    { &hf_dnp3_al_range_stop32,
    { "Stop (32 bit)", "dnp3.al.range.stop", FT_UINT32, BASE_DEC, NULL, 0x0, "Object Stop Index", HFILL }},

    { &hf_dnp3_al_range_abs8,
    { "Address (8 bit)", "dnp3.al.range.abs", FT_UINT8, BASE_DEC, NULL, 0x0, "Object Absolute Address", HFILL }},

    { &hf_dnp3_al_range_abs16,
    { "Address (16 bit)", "dnp3.al.range.abs", FT_UINT16, BASE_DEC, NULL, 0x0, "Object Absolute Address", HFILL }},

    { &hf_dnp3_al_range_abs32,
    { "Address (32 bit)", "dnp3.al.range.abs", FT_UINT32, BASE_DEC, NULL, 0x0, "Object Absolute Address", HFILL }},

    { &hf_dnp3_al_range_quant8,
    { "Quantity (8 bit)", "dnp3.al.range.quantity", FT_UINT8, BASE_DEC, NULL, 0x0, "Object Quantity", HFILL }},

    { &hf_dnp3_al_range_quant16,
    { "Quantity (16 bit)", "dnp3.al.range.quantity", FT_UINT16, BASE_DEC, NULL, 0x0, "Object Quantity", HFILL }},

    { &hf_dnp3_al_range_quant32,
    { "Quantity (32 bit)", "dnp3.al.range.quantity", FT_UINT32, BASE_DEC, NULL, 0x0, "Object Quantity", HFILL }},

    { &hf_dnp3_al_index8,
    { "Index (8 bit)", "dnp3.al.index", FT_UINT8, BASE_DEC, NULL, 0x0, "Object Index", HFILL }},

    { &hf_dnp3_al_index16,
    { "Index (16 bit)", "dnp3.al.index", FT_UINT16, BASE_DEC, NULL, 0x0, "Object Index", HFILL }},

    { &hf_dnp3_al_index32,
    { "Index (32 bit)", "dnp3.al.index", FT_UINT32, BASE_DEC, NULL, 0x0, "Object Index", HFILL }},

    /* XXX - unused
    { &hf_dnp3_al_ptnum,
    { "Object Point Number", "dnp3.al.ptnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }}, */

    { &hf_dnp3_al_size8,
    { "Size (8 bit)", "dnp3.al.size", FT_UINT8, BASE_DEC, NULL, 0x0, "Object Size", HFILL }},

    { &hf_dnp3_al_size16,
    { "Size (16 bit)", "dnp3.al.size", FT_UINT16, BASE_DEC, NULL, 0x0, "Object Size", HFILL }},

    { &hf_dnp3_al_size32,
    { "Size (32 bit)", "dnp3.al.size", FT_UINT32, BASE_DEC, NULL, 0x0, "Object Size", HFILL }},

    { &hf_dnp3_al_bit,
    { "Value (bit)", "dnp3.al.bit", FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x1, "Digital Value (1 bit)", HFILL }},

    { &hf_dnp3_al_2bit,
    { "Value (two bit)", "dnp3.al.2bit", FT_UINT8, BASE_DEC, NULL, 0x0, "Digital Value (2 bit)", HFILL }},

    { &hf_dnp3_al_ana16,
    { "Value (16 bit)", "dnp3.al.ana", FT_UINT16, BASE_DEC, NULL, 0x0, "Analog Value (16 bit)", HFILL }},

    { &hf_dnp3_al_ana32,
    { "Value (32 bit)", "dnp3.al.ana", FT_UINT32, BASE_DEC, NULL, 0x0, "Analog Value (32 bit)", HFILL }},

    { &hf_dnp3_al_anaflt,
    { "Value (float)", "dnp3.al.ana", FT_FLOAT, BASE_NONE, NULL, 0x0, "Analog Value (float)", HFILL }},

    { &hf_dnp3_al_anadbl,
    { "Value (double)", "dnp3.al.ana", FT_DOUBLE, BASE_NONE, NULL, 0x0, "Analog Value (double)", HFILL }},

    { &hf_dnp3_al_anaout16,
    { "Output Value (16 bit)", "dnp3.al.anaout", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_dnp3_al_anaout32,
    { "Output Value (32 bit)", "dnp3.al.anaout", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_dnp3_al_anaoutflt,
    { "Output Value (float)", "dnp3.al.anaout", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_dnp3_al_anaoutdbl,
    { "Output (double)", "dnp3.al.anaout", FT_DOUBLE, BASE_NONE, NULL, 0x0, "Output Value (double)", HFILL }},

    { &hf_dnp3_al_cnt16,
    { "Counter (16 bit)", "dnp3.al.cnt", FT_UINT16, BASE_DEC, NULL, 0x0, "Counter Value (16 bit)", HFILL }},

    { &hf_dnp3_al_cnt32,
    { "Counter (32 bit)", "dnp3.al.cnt", FT_UINT32, BASE_DEC, NULL, 0x0, "Counter Value (32 bit)", HFILL }},

    { &hf_dnp3_al_ctrlstatus,
    { "Control Status", "dnp3.al.ctrlstatus", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_ctl_status_vals_ext, 0xff, NULL, HFILL }},

    { &hf_dnp3_al_file_mode,
    { "File Control Mode", "dnp3.al.file.mode", FT_UINT16, BASE_DEC, VALS(dnp3_al_file_mode_vals), 0x0, NULL, HFILL }},

    { &hf_dnp3_al_file_auth,
    { "File Authentication Key", "dnp3.al.file.auth", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_dnp3_al_file_size,
    { "File Size", "dnp3.al.file.size", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_dnp3_al_file_maxblk,
    { "File Max Block Size", "dnp3.al.file.maxblock", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_dnp3_al_file_reqID,
    { "File Request Identifier", "dnp3.al.file.reqID", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_dnp3_al_file_status,
    { "File Control Status", "dnp3.al.file.status", FT_UINT8, BASE_DEC, VALS(dnp3_al_file_status_vals), 0x0, NULL, HFILL }},

    { &hf_dnp3_al_file_handle,
    { "File Handle", "dnp3.al.file.handle", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_dnp3_al_file_blocknum,
    { "File Block Number", "dnp3.al.file.blocknum", FT_UINT32, BASE_HEX, NULL, 0x7fffffff, NULL, HFILL }},

    { &hf_dnp3_al_file_lastblock,
    { "File Last Block", "dnp3.al.file.lastblock", FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x80000000, NULL, HFILL }},

    { &hf_dnp3_al_file_data,
    { "File Data", "dnp3.al.file.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_dnp3_al_biq_b0,
    { "Online", "dnp3.al.biq.b0", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG0, NULL, HFILL }},

    { &hf_dnp3_al_biq_b1,
    { "Restart", "dnp3.al.biq.b1", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG1, NULL, HFILL }},

    { &hf_dnp3_al_biq_b2,
    { "Comm Fail", "dnp3.al.biq.b2", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG2, NULL, HFILL }},

    { &hf_dnp3_al_biq_b3,
    { "Remote Force", "dnp3.al.biq.b3", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG3, NULL, HFILL }},

    { &hf_dnp3_al_biq_b4,
    { "Local Force", "dnp3.al.biq.b4", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG4, NULL, HFILL }},

    { &hf_dnp3_al_biq_b5,
    { "Chatter Filter", "dnp3.al.biq.b5", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG5, NULL, HFILL }},

    { &hf_dnp3_al_biq_b6,
    { "Reserved", "dnp3.al.biq.b6", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG6, NULL, HFILL }},

    { &hf_dnp3_al_biq_b7,
    { "Point Value", "dnp3.al.biq.b7", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG7, NULL, HFILL }},

    { &hf_dnp3_al_boq_b0,
    { "Online", "dnp3.al.boq.b0", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG0, NULL, HFILL }},

    { &hf_dnp3_al_boq_b1,
    { "Restart", "dnp3.al.boq.b1", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG1, NULL, HFILL }},

    { &hf_dnp3_al_boq_b2,
    { "Comm Fail", "dnp3.al.boq.b2", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG2, NULL, HFILL }},

    { &hf_dnp3_al_boq_b3,
    { "Remote Force", "dnp3.al.boq.b3", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG3, NULL, HFILL }},

    { &hf_dnp3_al_boq_b4,
    { "Local Force", "dnp3.al.boq.b4", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG4, NULL, HFILL }},

    { &hf_dnp3_al_boq_b5,
    { "Reserved", "dnp3.al.boq.b5", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG5, NULL, HFILL }},

    { &hf_dnp3_al_boq_b6,
    { "Reserved", "dnp3.al.boq.b6", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG6, NULL, HFILL }},

    { &hf_dnp3_al_boq_b7,
    { "Point Value", "dnp3.al.boq.b7", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG7, NULL, HFILL }},

    { &hf_dnp3_al_ctrq_b0,
    { "Online", "dnp3.al.ctrq.b0", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG0, NULL, HFILL }},

    { &hf_dnp3_al_ctrq_b1,
    { "Restart", "dnp3.al.ctrq.b1", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG1, NULL, HFILL }},

    { &hf_dnp3_al_ctrq_b2,
    { "Comm Fail", "dnp3.al.ctrq.b2", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG2, NULL, HFILL }},

    { &hf_dnp3_al_ctrq_b3,
    { "Remote Force", "dnp3.al.ctrq.b3", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG3, NULL, HFILL }},

    { &hf_dnp3_al_ctrq_b4,
    { "Local Force", "dnp3.al.ctrq.b4", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG4, NULL, HFILL }},

    { &hf_dnp3_al_ctrq_b5,
    { "Roll-Over", "dnp3.al.ctrq.b5", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG5, NULL, HFILL }},

    { &hf_dnp3_al_ctrq_b6,
    { "Discontinuity", "dnp3.al.ctrq.b6", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG6, NULL, HFILL }},

    { &hf_dnp3_al_ctrq_b7,
    { "Reserved", "dnp3.al.ctrq.b7", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG7, NULL, HFILL }},

    { &hf_dnp3_al_aiq_b0,
    { "Online", "dnp3.al.aiq.b0", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG0, NULL, HFILL }},

    { &hf_dnp3_al_aiq_b1,
    { "Restart", "dnp3.al.aiq.b1", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG1, NULL, HFILL }},

    { &hf_dnp3_al_aiq_b2,
    { "Comm Fail", "dnp3.al.aiq.b2", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG2, NULL, HFILL }},

    { &hf_dnp3_al_aiq_b3,
    { "Remote Force", "dnp3.al.aiq.b3", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG3, NULL, HFILL }},

    { &hf_dnp3_al_aiq_b4,
    { "Local Force", "dnp3.al.aiq.b4", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG4, NULL, HFILL }},

    { &hf_dnp3_al_aiq_b5,
    { "Over-Range", "dnp3.al.aiq.b5", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG5, NULL, HFILL }},

    { &hf_dnp3_al_aiq_b6,
    { "Reference Check", "dnp3.al.aiq.b6", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG6, NULL, HFILL }},

    { &hf_dnp3_al_aiq_b7,
    { "Reserved", "dnp3.al.aiq.b7", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG7, NULL, HFILL }},

    { &hf_dnp3_al_aoq_b0,
    { "Online", "dnp3.al.aoq.b0", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG0, NULL, HFILL }},

    { &hf_dnp3_al_aoq_b1,
    { "Restart", "dnp3.al.aoq.b1", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG1, NULL, HFILL }},

    { &hf_dnp3_al_aoq_b2,
    { "Comm Fail", "dnp3.al.aoq.b2", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG2, NULL, HFILL }},

    { &hf_dnp3_al_aoq_b3,
    { "Remote Force", "dnp3.al.aoq.b3", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG3, NULL, HFILL }},

    { &hf_dnp3_al_aoq_b4,
    { "Local Force", "dnp3.al.aoq.b4", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG4, NULL, HFILL }},

    { &hf_dnp3_al_aoq_b5,
    { "Reserved", "dnp3.al.aoq.b5", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG5, NULL, HFILL }},

    { &hf_dnp3_al_aoq_b6,
    { "Reserved", "dnp3.al.aoq.b6", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG6, NULL, HFILL }},

    { &hf_dnp3_al_aoq_b7,
    { "Reserved", "dnp3.al.aoq.b7", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG7, NULL, HFILL }},

    { &hf_dnp3_al_timestamp,
    { "Timestamp", "dnp3.al.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, "Object Timestamp", HFILL }},

    { &hf_dnp3_al_file_perms,
    { "Permissions", "dnp3.al.file.perms", FT_UINT16, BASE_OCT, NULL, 0x0, NULL, HFILL }},

    { &hf_dnp3_al_file_perms_read_owner,
    { "Read permission for owner", "dnp3.al.file.perms.read_owner", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0400, NULL, HFILL }},

    { &hf_dnp3_al_file_perms_write_owner,
    { "Write permission for owner", "dnp3.al.file.perms.write_owner", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0200, NULL, HFILL }},

    { &hf_dnp3_al_file_perms_exec_owner,
    { "Execute permission for owner", "dnp3.al.file.perms.exec_owner", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0100, NULL, HFILL }},

    { &hf_dnp3_al_file_perms_read_group,
    { "Read permission for group", "dnp3.al.file.perms.read_group", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 040, NULL, HFILL }},

    { &hf_dnp3_al_file_perms_write_group,
    { "Write permission for group", "dnp3.al.file.perms.write_group", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 020, NULL, HFILL }},

    { &hf_dnp3_al_file_perms_exec_group,
    { "Execute permission for group", "dnp3.al.file.perms.exec_group", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 010, NULL, HFILL }},

    { &hf_dnp3_al_file_perms_read_world,
    { "Read permission for world", "dnp3.al.file.perms.read_world", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 04, NULL, HFILL }},

    { &hf_dnp3_al_file_perms_write_world,
    { "Write permission for world", "dnp3.al.file.perms.write_world", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 02, NULL, HFILL }},

    { &hf_dnp3_al_file_perms_exec_world,
    { "Execute permission for world", "dnp3.al.file.perms.exec_world", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 01, NULL, HFILL }},

    { &hf_dnp3_al_rel_timestamp,
    { "Relative Timestamp", "dnp3.al.reltimestamp", FT_RELATIVE_TIME, BASE_NONE, NULL, 0, "Object Relative Timestamp", HFILL }},

    { &hf_dnp3_fragment,
    { "DNP 3.0 AL Fragment", "dnp3.al.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0, "DNP 3.0 Application Layer Fragment", HFILL }},

    { &hf_dnp3_fragments,
    { "DNP 3.0 AL Fragments", "dnp3.al.fragments", FT_NONE, BASE_NONE, NULL, 0x0, "DNP 3.0 Application Layer Fragments", HFILL }},

    { &hf_dnp3_fragment_overlap,
    { "Fragment overlap", "dnp3.al.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},

    { &hf_dnp3_fragment_overlap_conflict,
    { "Conflicting data in fragment overlap", "dnp3.al.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "Overlapping fragments contained conflicting data", HFILL }},

    { &hf_dnp3_fragment_multiple_tails,
    { "Multiple tail fragments found", "dnp3.al.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "Several tails were found when defragmenting the packet", HFILL }},

    { &hf_dnp3_fragment_too_long_fragment,
    { "Fragment too long", "dnp3.al.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "Fragment contained data past end of packet", HFILL }},

    { &hf_dnp3_fragment_error,
    { "Defragmentation error", "dnp3.al.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
      "Defragmentation error due to illegal fragments", HFILL }},

    { &hf_dnp3_fragment_count,
    { "Fragment count", "dnp3.al.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_dnp3_fragment_reassembled_in,
    { "Reassembled PDU In Frame", "dnp3.al.fragment.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
      "This PDU is reassembled in this frame", HFILL }},

    { &hf_dnp3_fragment_reassembled_length,
    { "Reassembled DNP length", "dnp3.al.fragment.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
      "The total length of the reassembled payload", HFILL }}
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_dnp3,
    &ett_dnp3_dl,
    &ett_dnp3_dl_ctl,
    &ett_dnp3_tr_ctl,
    &ett_dnp3_al_data,
    &ett_dnp3_al,
    &ett_dnp3_al_ctl,
    &ett_dnp3_al_obj_point_tcc,
    &ett_dnp3_al_iin,
    &ett_dnp3_al_obj,
    &ett_dnp3_al_obj_qualifier,
    &ett_dnp3_al_obj_range,
    &ett_dnp3_al_objdet,
    &ett_dnp3_al_obj_quality,
    &ett_dnp3_al_obj_point,
    &ett_dnp3_al_obj_point_perms,
    &ett_dnp3_fragment,
    &ett_dnp3_fragments
  };
  module_t *dnp3_module;

/* Register protocol init routine */
  register_init_routine(&dnp3_init);

/* Register the protocol name and description */
  proto_dnp3 = proto_register_protocol("Distributed Network Protocol 3.0",
                   "DNP 3.0", "dnp3");

/* Register the dissector so it may be used as a User DLT payload protocol */
  new_register_dissector("dnp3.udp", dissect_dnp3_udp, proto_dnp3);

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_dnp3, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  dnp3_module = prefs_register_protocol(proto_dnp3, NULL);
  prefs_register_bool_preference(dnp3_module, "heuristics",
    "Try to detect DNP 3 heuristically",
    "Whether the DNP3 dissector should try to find DNP 3 packets heuristically.",
    &dnp3_heuristics);
  prefs_register_bool_preference(dnp3_module, "desegment",
    "Reassemble DNP3 messages spanning multiple TCP segments",
    "Whether the DNP3 dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &dnp3_desegment);
}


void
proto_reg_handoff_dnp3(void)
{
  dissector_handle_t dnp3_tcp_handle;
  dissector_handle_t dnp3_udp_handle;

  /* register as heuristic dissector for both TCP and UDP */
  if(dnp3_heuristics){
    heur_dissector_add("tcp", dissect_dnp3_tcp, proto_dnp3);
    heur_dissector_add("udp", dissect_dnp3_udp, proto_dnp3);
  }else{
    heur_dissector_delete("tcp", dissect_dnp3_tcp, proto_dnp3);
    heur_dissector_delete("udp", dissect_dnp3_udp, proto_dnp3);
  }

  dnp3_tcp_handle = new_create_dissector_handle(dissect_dnp3_tcp, proto_dnp3);
  dnp3_udp_handle = new_create_dissector_handle(dissect_dnp3_udp, proto_dnp3);
  dissector_add_uint("tcp.port", TCP_PORT_DNP, dnp3_tcp_handle);
  dissector_add_uint("udp.port", UDP_PORT_DNP, dnp3_udp_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */

