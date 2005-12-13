/* packet-dnp3.c
 * Routines for DNP dissection
 * Copyright 2003, Graham Bloice <graham.bloice@trihedral.com>
 *
 * DNP3.0 Application Layer Object dissection added by Chris Bontje (chrisbontje@shaw.ca)
 * Copyright 2005
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <glib.h>
#include <time.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>

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
 * "DNP V3.00 Application Layer" v0.03 P009-0PD.APP
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

#define DNP3_TR_FIR   0x40
#define DNP3_TR_FIN   0x80
#define DNP3_TR_SEQ   0x3f

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
#define DNP3_AL_CON   0x20
#define DNP3_AL_FIN   0x40
#define DNP3_AL_FIR   0x80
#define DNP3_AL_SEQ   0x1f
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
#define AL_FUNC_RESPON     0x81    /* 129 - Response */
#define AL_FUNC_UNSOLI     0x82    /* 130 - Unsolicited Response */

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
#define AL_IIN_DOL         0x2000   /* Bit 5 - Digital Outputs in Local Mode */
#define AL_IIN_DT          0x4000   /* Bit 6 - Device Trouble */
#define AL_IIN_RST         0x8000   /* Bit 7 - Device Restart */

/* Octet 2 */
                        /* 0x0001      Bit 0 - Reserved */
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
#define AL_OBJQ_INDEX      0x70     /* x111xxxx Masks Index from Qualifier */
#define AL_OBJQ_CODE       0x0F     /* xxxx1111 Masks Code from Qualifier */

/* Index Size (3-bits x111xxxx)            */
/* When Qualifier Code != 11               */
#define AL_OBJQL_IDX_NI    0x00    /* Objects are Packed with no index */
#define AL_OBJQL_IDX_1O    0x01    /* Objects are prefixed w/ 1-octet index */
#define AL_OBJQL_IDX_2O    0x02    /* Objects are prefixed w/ 2-octet index */
#define AL_OBJQL_IDX_4O    0x03    /* Objects are prefixed w/ 4-octet index */
#define AL_OBJQL_IDX_1OS   0x04    /* Objects are prefixed w/ 1-octet object size */
#define AL_OBJQL_IDX_2OS   0x05    /* Objects are prefixed w/ 2-octet object size */
#define AL_OBJQL_IDX_4OS   0x06    /* Objects are prefixed w/ 4-octet object size */

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
#define AL_OBJQL_CODE_FF       0x0B    /* 11 Free-format Qualifier */
                           /*  0x0C       12 Reserved  */
                           /*  0x0D       13 Reserved  */
                           /*  0x0E       14 Reserved  */
                           /*  0x0F       15 Reserved  */

/***************************************************************************/
/* Application Layer Data Object Definitions                               */
/***************************************************************************/
/* Binary Input Objects */
#define AL_OBJ_BI_ALL      0x0100   /* 01 00 Binary Input All Variations */
#define AL_OBJ_BI_1BIT     0x0101   /* 01 01 Single-bit Binary Input */
#define AL_OBJ_BI_STAT     0x0102   /* 01 02 Binary Input With Status */
#define AL_OBJ_BIC_ALL     0x0200   /* 02 00 Binary Input Change All Variations */
#define AL_OBJ_BIC_NOTIME  0x0201   /* 02 01 Binary Input Change Without Time */
#define AL_OBJ_BIC_TIME    0x0202   /* 02 02 Binary Input Change With Time */
#define AL_OBJ_BIC_RTIME   0x0203   /* 02 03 Binary Input Change With Relative Time */

/* Binary Input Quality Flags */
#define AL_OBJ_BI_FLAG0    0x0001   /* Point Online (0=Offline; 1=Online) */
#define AL_OBJ_BI_FLAG1    0x0002   /* Restart (0=Normal; 1=Restart) */
#define AL_OBJ_BI_FLAG2    0x0004   /* Comms Lost (0=Normal; 1=Lost) */
#define AL_OBJ_BI_FLAG3    0x0008   /* Remote Force (0=Normal; 1=Forced) */
#define AL_OBJ_BI_FLAG4    0x0010   /* Local Force (0=Normal; 1=Forced) */
#define AL_OBJ_BI_FLAG5    0x0020   /* Chatter Filter (0=Normal; 1=Filter On) */
#define AL_OBJ_BI_FLAG6    0x0040   /* Reserved */
#define AL_OBJ_BI_FLAG7    0x0080   /* Point State (0=Off; 1=On) */

/***************************************************************************/
/* Binary Output Objects */
#define AL_OBJ_BO          0x0A01   /* 10 01 Binary Output */
#define AL_OBJ_BO_STAT     0x0A02   /* 10 02 Binary Output Status */
#define AL_OBJ_CTLOP_BLK   0x0C01   /* 12 01 Control Relay Output Block */
                        /* 0x0C02      12 02 Pattern Control Block */
                        /* 0x0C03      12 03 Pattern Mask */

#define AL_OBJCTLC_CODE    0x0F    /* Bit-Mask xxxx1111 for Control Code 'Code' */
#define AL_OBJCTLC_MISC    0x30    /* Bit-Mask xx11xxxx for Control Code Misc Values */
#define AL_OBJCTLC_TC      0xC0    /* Bit-Mask 11xxxxxx for Control Code 'Trip/Close' */

#define AL_OBJCTLC_CODE0   0x00    /* xxxx0000 NUL Operation; only process R attribute */
#define AL_OBJCTLC_CODE1   0x01    /* xxxx0001 Pulse On ^On-Time -> vOff-Time, remain off */
#define AL_OBJCTLC_CODE2   0x02    /* xxxx0010 Pulse Off vOff-Time -> ^On-Time, remain on */
#define AL_OBJCTLC_CODE3   0x03    /* xxxx0011 Latch On */
#define AL_OBJCTLC_CODE4   0x04    /* xxxx0100 Latch Off */
                        /* 0x05-0x15  Reserved */

#define AL_OBJCTLC_QUEUE   0x10    /* xxx1xxxx for Control Code 'Queue' */
#define AL_OBJCTLC_CLEAR   0x20    /* xx1xxxxx for Control Code 'Clear' */

#define AL_OBJCTLC_TC0     0x00    /* 00xxxxxx NUL */
#define AL_OBJCTLC_TC1     0x40    /* 01xxxxxx Close */
#define AL_OBJCTLC_TC2     0x80    /* 10xxxxxx Trip */

#define AL_OBJCTL_STAT0    0x00    /* Request Accepted, Initiated or Queued */
#define AL_OBJCTL_STAT1    0x01    /* Request Not Accepted; Arm-timer expired */
#define AL_OBJCTL_STAT2    0x02    /* Request Not Accepted; No 'SELECT' rx'd */
#define AL_OBJCTL_STAT3    0x03    /* Request Not Accepted; Format errors in ctrl request */
#define AL_OBJCTL_STAT4    0x04    /* Control Operation Not Supported for this point */
#define AL_OBJCTL_STAT5    0x05    /* Request Not Accepted; Ctrl Queue full or pt. active */
#define AL_OBJCTL_STAT6    0x06    /* Request Not Accepted; Ctrl HW Problems */

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
#define AL_OBJ_CTR_ALL     0x1400   /* 20 00 Binary Counter All Variations */
#define AL_OBJ_CTR_32      0x1401   /* 20 01 32-Bit Binary Counter */
#define AL_OBJ_CTR_16      0x1402   /* 20 02 16-Bit Binary Counter */
#define AL_OBJ_DCTR_32     0x1403   /* 20 03 32-Bit Delta Counter */
#define AL_OBJ_DCTR_16     0x1404   /* 20 04 16-Bit Delta Counter */
#define AL_OBJ_CTR_32NF    0x1405   /* 20 05 32-Bit Binary Counter Without Flag */
#define AL_OBJ_CTR_16NF    0x1406   /* 20 06 16-Bit Binary Counter Without Flag */
                        /* 0x1407      20 07 32-Bit Delta Counter Without Flag */
                        /* 0x1408      20 08 16-Bit Delta Counter Without Flag */
#define AL_OBJ_FCTR_32     0x1501   /* 21 01 32-Bit Frozen Counter */
#define AL_OBJ_FCTR_16     0x1502   /* 21 02 16-Bit Frozen Counter */
                        /* 0x1503      21 03 32-Bit Frozen Delta Counter */
                        /* 0x1504      21 04 16-Bit Frozen Delta Counter */
                        /* 0x1505      21 05 32-Bit Frozen Counter w/ Time of Freeze */
                        /* 0x1506      21 06 16-Bit Frozen Counter w/ Time of Freeze */
                        /* 0x1507      21 07 32-Bit Frozen Delta Counter w/ Time of Freeze */
                        /* 0x1508      21 08 16-Bit Frozen Delta Counter w/ Time of Freeze */
                        /* 0x1509      21 09 32-Bit Frozen Counter Without Flag */
                        /* 0x1510      21 10 16-Bit Frozen Counter Without Flag */
                        /* 0x1511      21 11 32-Bit Frozen Delta Counter Without Flag */
                        /* 0x1512      21 12 16-Bit Frozen Delta Counter Without Flag */
#define AL_OBJ_CTRC_ALL    0x1600   /* 22 00 Counter Change Event All Variations */
#define AL_OBJ_CTRC_32     0x1601   /* 22 01 32-Bit Counter Change Event w/o Time */
#define AL_OBJ_CTRC_16     0x1602   /* 22 02 16-Bit Counter Change Event w/o Time */
                        /* 0x1603      22 03 32-Bit Delta Counter Change Event w/o Time */
                        /* 0x1604      22 04 16-Bit Delta Counter Change Event w/o Time */
                        /* 0x1605      22 05 32-Bit Counter Change Event With Time */
                        /* 0x1606      22 06 16-Bit Counter Change Event With Time */
                        /* 0x1607      22 07 32-Bit Delta Counter Change Event With Time */
                        /* 0x1608      22 08 16-Bit Delta Counter Change Event With Time */
                        /* 0x1701      23 01 32-Bit Counter Change Event w/o Time */
                        /* 0x1702      23 02 16-Bit Frozen Counter Change Event w/o Time */
                        /* 0x1703      23 03 32-Bit Frozen Delta Counter Change Event w/o Time */

/* Counter Quality Flags */
#define AL_OBJ_CTR_FLAG0   0x0001   /* Point Online (0=Offline; 1=Online) */
#define AL_OBJ_CTR_FLAG1   0x0002   /* Restart (0=Normal; 1=Restart) */
#define AL_OBJ_CTR_FLAG2   0x0004   /* Comms Lost (0=Normal; 1=Lost) */
#define AL_OBJ_CTR_FLAG3   0x0008   /* Remote Force (0=Normal; 1=Forced) */
#define AL_OBJ_CTR_FLAG4   0x0010   /* Local Force (0=Normal; 1=Forced) */
#define AL_OBJ_CTR_FLAG5   0x0020   /* Roll-over (0=Normal; 1=Roll-Over) */
#define AL_OBJ_CTR_FLAG6   0x0040   /* Reserved */
#define AL_OBJ_CTR_FLAG7   0x0080   /* Reserved */

/***************************************************************************/
/* Analog Input Objects */
#define AL_OBJ_AI_ALL      0x1E00   /* 30 00 Analog Input All Variations */
#define AL_OBJ_AI_32       0x1E01   /* 30 01 32-Bit Analog Input */
#define AL_OBJ_AI_16       0x1E02   /* 30 02 16-Bit Analog Input */
#define AL_OBJ_AI_32NF     0x1E03   /* 30 03 32-Bit Analog Input Without Flag */
#define AL_OBJ_AI_16NF     0x1E04   /* 30 04 16-Bit Analog Input Without Flag */
                        /* 0x1F01      31 01 32-Bit Frozen Analog Input */
                        /* 0x1F02      31 02 16-Bit Frozen Analog Input */
                        /* 0x1F03      31 03 32-Bit Frozen Analog Input w/ Time of Freeze */
                        /* 0x1F04      31 04 16-Bit Frozen Analog Input w/ Time of Freeze */
                        /* 0x1F05      31 05 32-Bit Frozen Analog Input Without Flag */
                        /* 0x1F06      31 06 16-Bit Frozen Analog Input Without Flag */
#define AL_OBJ_AIC_ALL     0x2000   /* 32 00 Analog Input Change All Variations */
#define AL_OBJ_AIC_32NT    0x2001   /* 32 01 32-Bit Analog Change Event w/o Time */
#define AL_OBJ_AIC_16NT    0x2002   /* 32 02 16-Bit Analog Change Event w/o Time */
#define AL_OBJ_AIC_32T     0x2003   /* 32 03 32-Bit Analog Change Event w/ Time */
#define AL_OBJ_AIC_16T     0x2004   /* 32 04 16-Bit Analog Change Event w/ Time */
                        /* 0x2101      33 01 32-Bit Frozen Analog Event w/o Time */
                        /* 0x2102      33 02 16-Bit Frozen Analog Event w/o Time */
                        /* 0x2103      33 03 32-Bit Frozen Analog Event w/ Time */
                        /* 0x2104      33 04 16-Bit Frozen Analog Event w/ Time */

/* Analog Input Quality Flags */
#define AL_OBJ_AI_FLAG0    0x0001   /* Point Online (0=Offline; 1=Online) */
#define AL_OBJ_AI_FLAG1    0x0002   /* Restart (0=Normal; 1=Restart) */
#define AL_OBJ_AI_FLAG2    0x0004   /* Comms Lost (0=Normal; 1=Lost) */
#define AL_OBJ_AI_FLAG3    0x0008   /* Remote Force (0=Normal; 1=Forced) */
#define AL_OBJ_AI_FLAG4    0x0010   /* Local Force (0=Normal; 1=Forced) */
#define AL_OBJ_AI_FLAG5    0x0020   /* Over-Range (0=Normal; 1=Over-Range) */
#define AL_OBJ_AI_FLAG6    0x0040   /* Reference Check (0=Normal; 1=Error) */
#define AL_OBJ_AI_FLAG7    0x0080   /* Reserved */

/***************************************************************************/
/* Analog Output Objects */
#define AL_OBJ_AO_32       0x2801   /* 40 01 32-Bit Analog Output Status */
#define AL_OBJ_AO_16       0x2802   /* 40 02 16-Bit Analog Output Status */
#define AL_OBJ_AO_32OPB    0x2901   /* 41 01 32-Bit Analog Output Block */
#define AL_OBJ_AO_16OPB    0x2902   /* 41 02 16-Bit Analog Output Block */

/* Analog Output Quality Flags */
#define AL_OBJ_AO_FLAG0    0x0001   /* Point Online (0=Offline; 1=Online) */
#define AL_OBJ_AO_FLAG1    0x0002   /* Restart (0=Normal; 1=Restart) */
#define AL_OBJ_AO_FLAG2    0x0004   /* Comms Lost (0=Normal; 1=Lost) */
#define AL_OBJ_AO_FLAG3    0x0008   /* Remote Force (0=Normal; 1=Forced) */
#define AL_OBJ_AO_FLAG4    0x0010   /* Reserved */
#define AL_OBJ_AO_FLAG5    0x0020   /* Reserved */
#define AL_OBJ_AO_FLAG6    0x0040   /* Reserved */
#define AL_OBJ_AO_FLAG7    0x0080   /* Reserved */

/***************************************************************************/
/* Time Objects */
#define AL_OBJ_TD          0x3201   /* 50 01 Time and Date */
#define AL_OBJ_TDI         0x3202   /* 50 02 Time and Date w/ Interval */
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
/* Device Objects */
#define AL_OBJ_IIN         0x5001   /* 80 01 Internal Indications */

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
/*static int hf_dnp3_al_objq = -1;
  static int hf_dnp3_al_nobj = -1; */
static int hf_dnp3_al_ptnum = -1;
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

/* ************************************************************************* */
/*                   Header values for reassembly                            */
/* ************************************************************************* */
static int hf_fragments = -1;
static int hf_fragment = -1;
static int hf_fragment_overlap = -1;
static int hf_fragment_overlap_conflict = -1;
static int hf_fragment_multiple_tails = -1;
static int hf_fragment_too_long_fragment = -1;
static int hf_fragment_error = -1;
static int hf_fragment_reassembled_in = -1;

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

static const value_string dnp3_ctl_flags_pri_vals[] = {
  { DNP3_CTL_DIR, "DIR" },
  { DNP3_CTL_PRM, "PRM" },
  { DNP3_CTL_FCB, "FCB" },
  { DNP3_CTL_FCV, "FCV" },
  { 0,  NULL }
};

static const value_string dnp3_ctl_flags_sec_vals[] = {
  { DNP3_CTL_DIR, "DIR" },
  { DNP3_CTL_PRM, "PRM" },
  { DNP3_CTL_RES, "RES" },
  { DNP3_CTL_DFC, "DFC" },
  { 0,  NULL }
};

static const value_string dnp3_tr_flags_vals[] = {
  { DNP3_TR_FIN,  "FIN" },
  { DNP3_TR_FIR,  "FIR" },
  { 0,  NULL }
};

static const value_string dnp3_al_flags_vals[] = {
  { DNP3_AL_FIR,  "FIR" },
  { DNP3_AL_FIN,  "FIN" },
  { DNP3_AL_CON,  "CON" },
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
  { AL_FUNC_RESPON,     "Response" },
  { AL_FUNC_UNSOLI,     "Unsolicited Response" },
  { 0, NULL }
};

/* Application Layer Internal Indication (IIN) bit Values */
static const value_string dnp3_al_iin_vals[] = {
  { AL_IIN_BMSG,    "Broadcast message Rx'd" },
  { AL_IIN_CLS1D,   "Class 1 Data Available" },
  { AL_IIN_CLS2D,   "Class 2 Data Available" },
  { AL_IIN_CLS3D,   "Class 3 Data Available" },
  { AL_IIN_TSR,     "Time Sync Required from Master" },
  { AL_IIN_DOL,     "Digital Outputs in Local Mode" },
  { AL_IIN_DT,      "Device Trouble" },
  { AL_IIN_RST,     "Device Restart" },
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
  { AL_OBJQL_CODE_FF,       "Free-format Qualifier" },
  { 0, NULL }
};

/* Application Layer Data Object Values */
static const value_string dnp3_al_obj_vals[] = {
  { AL_OBJ_BI_ALL,     "Binary Input All Variations (Obj:01, Var:All)" },
  { AL_OBJ_BI_1BIT,    "Single-Bit Binary Input (Obj:01, Var:01)" },
  { AL_OBJ_BI_STAT,    "Binary Input With Status (Obj:01, Var:02)" },
  { AL_OBJ_BIC_ALL,    "Binary Input Change All Variations (Obj:02, Var:All)" },
  { AL_OBJ_BIC_NOTIME, "Binary Input Change Without Time (Obj:02, Var:01)" },
  { AL_OBJ_BIC_TIME,   "Binary Input Change With Time (Obj:02, Var:02)" },
  { AL_OBJ_BIC_RTIME,  "Binary Input Change With Relative Time (Obj:02, Var:03)" },
  { AL_OBJ_BO,         "Binary Output (Obj:10, Var:01)" },
  { AL_OBJ_BO_STAT,    "Binary Output Status (Obj:10, Var:02)" },
  { AL_OBJ_CTLOP_BLK,  "Control Relay Output Block (Obj:12, Var:01)" },
  { AL_OBJ_CTR_ALL,    "Binary Counter All Variations (Obj:20, Var:All)" },
  { AL_OBJ_CTR_32,     "32-Bit Binary Counter (Obj:20, Var:01)" },
  { AL_OBJ_CTR_16,     "16-Bit Binary Counter (Obj:20, Var:02)" },
  { AL_OBJ_CTR_32NF,   "32-Bit Binary Counter Without Flag (Obj:20, Var:05)" },
  { AL_OBJ_CTR_16NF,   "16-Bit Binary Counter Without Flag (Obj:20, Var:06)" },
  { AL_OBJ_FCTR_32,    "32-Bit Frozen Counter (Obj:21, Var:01)"},
  { AL_OBJ_FCTR_16,    "16-Bit Frozen Counter (Obj:21, Var:02)"},
  { AL_OBJ_CTRC_ALL,   "Binary Counter Change All Variations (Obj:22, Var:All)" },
  { AL_OBJ_CTRC_32,    "32-Bit Counter Change Event w/o Time (Obj:22, Var:01)" },
  { AL_OBJ_CTRC_16,    "16-Bit Counter Change Event w/o Time (Obj:22, Var:02)" },
  { AL_OBJ_AI_ALL,     "Analog Input All Variations (Obj:30, Var:All)" },
  { AL_OBJ_AI_32,      "32-Bit Analog Input (Obj:30, Var:01)" },
  { AL_OBJ_AI_16,      "16-Bit Analog Input (Obj:30, Var:02)" },
  { AL_OBJ_AI_32NF,    "32-Bit Analog Input Without Flag (Obj:30, Var:03)" },
  { AL_OBJ_AI_16NF,    "16-Bit Analog Input Without Flag (Obj:30, Var:04)" },
  { AL_OBJ_AIC_ALL,    "Analog Input Change All Variations (Obj:32, Var:All)" },
  { AL_OBJ_AIC_32NT,   "32-Bit Analog Change Event w/o Time (Obj:32, Var:01)" },
  { AL_OBJ_AIC_16NT,   "16-Bit Analog Change Event w/o Time (Obj:32, Var:02)" },
  { AL_OBJ_AIC_32T,    "32-Bit Analog Change Event with Time (Obj:32, Var:03)" },
  { AL_OBJ_AIC_16T,    "16-Bit Analog Change Event with Time (Obj:32, Var:04)" },
  { AL_OBJ_AO_16,      "16-Bit Analog Output Status (Obj:40, Var:02)"},
  { AL_OBJ_TD,         "Time and Date (Obj:50, Var:01)" },
  { AL_OBJ_TDELAYF,    "Time Delay - Fine (Obj:52, Var:02)" },
  { AL_OBJ_CLASS0,     "Class 0 Data (Obj:60, Var:01)" },
  { AL_OBJ_CLASS1,     "Class 1 Data (Obj:60, Var:02)" },
  { AL_OBJ_CLASS2,     "Class 2 Data (Obj:60, Var:03)" },
  { AL_OBJ_CLASS3,     "Class 3 Data (Obj:60, Var:04)" },
  { AL_OBJ_IIN,        "Internal Indications (Obj:80, Var:01)" },
  { 0, NULL }
};

/* Application Layer Control Code 'Code' Values */
static const value_string dnp3_al_ctlc_code_vals[] = {
  { AL_OBJCTLC_CODE0,     "NUL Operation" },
  { AL_OBJCTLC_CODE1,     "Pulse On" },
  { AL_OBJCTLC_CODE2,     "Pulse Off" },
  { AL_OBJCTLC_CODE3,     "Latch On" },
  { AL_OBJCTLC_CODE4,     "Latch Off" },
  { 0, NULL }
};

/* Application Layer Control Code 'Misc' Values */
static const value_string dnp3_al_ctlc_misc_vals[] = {
  { AL_OBJCTLC_QUEUE,     "Queue" },
  { AL_OBJCTLC_CLEAR,     "Clear" },
  { 0, NULL }
};

/* Application Layer Control Code 'Trip/Close' Values */
static const value_string dnp3_al_ctlc_tc_vals[] = {
  { AL_OBJCTLC_TC0,     "NUL" },
  { AL_OBJCTLC_TC1,     "Close" },
  { AL_OBJCTLC_TC2,     "Trip" },
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
  { 0, NULL }
};

/* Application Layer Binary Input Quality Flag Values */
static const value_string dnp3_al_biflag_vals[] = {
  { AL_OBJ_BI_FLAG0, "Online" },
  { AL_OBJ_BI_FLAG1, "Restart" },
  { AL_OBJ_BI_FLAG2, "Comm Fail" },
  { AL_OBJ_BI_FLAG3, "Remote Forced" },
  { AL_OBJ_BI_FLAG4, "Locally Forced" },
  { AL_OBJ_BI_FLAG5, "Chatter Filter" },
  { 0, NULL }
};

/* Application Layer Counter Quality Flag Values */
static const value_string dnp3_al_ctrflag_vals[] = {
  { AL_OBJ_CTR_FLAG0, "Online" },
  { AL_OBJ_CTR_FLAG1, "Restart" },
  { AL_OBJ_CTR_FLAG2, "Comm Fail" },
  { AL_OBJ_CTR_FLAG3, "Remote Forced" },
  { AL_OBJ_CTR_FLAG4, "Locally Forced" },
  { AL_OBJ_CTR_FLAG5, "Roll-Over" },
  { 0, NULL }
};

/* Application Layer Analog Input Quality Flag Values */
static const value_string dnp3_al_aiflag_vals[] = {
  { AL_OBJ_AI_FLAG0, "Online" },
  { AL_OBJ_AI_FLAG1, "Restart" },
  { AL_OBJ_AI_FLAG2, "Comm Fail" },
  { AL_OBJ_AI_FLAG3, "Remote Forced" },
  { AL_OBJ_AI_FLAG4, "Locally Forced" },
  { AL_OBJ_AI_FLAG5, "Over-Range" },
  { AL_OBJ_AI_FLAG6, "Ref. Error" },
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
static gint ett_fragment = -1;
static gint ett_fragments = -1;
/* Added for Application Layer Decoding */
static gint ett_dnp3_al_iin = -1;
static gint ett_dnp3_al_obj = -1;
static gint ett_dnp3_al_obj_qualifier = -1;
static gint ett_dnp3_al_obj_range = -1;
static gint ett_dnp3_al_objdet = -1;
static gint ett_dnp3_al_obj_quality = -1;

/* Tables for reassembly of fragments. */
static GHashTable *al_fragment_table = NULL;
static GHashTable *al_reassembled_table = NULL;

static const fragment_items frag_items = {
  &ett_fragment,
  &ett_fragments,
  &hf_fragments,
  &hf_fragment,
  &hf_fragment_overlap,
  &hf_fragment_overlap_conflict,
  &hf_fragment_multiple_tails,
  &hf_fragment_too_long_fragment,
  &hf_fragment_error,
  &hf_fragment_reassembled_in,
  "fragments"
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
  proto_item_append_text(item, text);
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
  if (al_iin & AL_IIN_DOL)    comma_needed = add_item_text(tiin, "Digital Outputs in Local", comma_needed);
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
  proto_item_append_text(tiin, " (0x%04x)", al_iin);

  iin_tree = proto_item_add_subtree(tiin, ett_dnp3_al_iin);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_rst, tvb, offset, 2, FALSE);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_dt, tvb, offset, 2, FALSE);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_dol, tvb, offset, 2, FALSE);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_tsr, tvb, offset, 2, FALSE);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_cls3d, tvb, offset, 2, FALSE);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_cls2d, tvb, offset, 2, FALSE);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_cls1d, tvb, offset, 2, FALSE);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_bmsg, tvb, offset, 2, FALSE);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_cc, tvb, offset, 2, FALSE);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_oae, tvb, offset, 2, FALSE);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_ebo, tvb, offset, 2, FALSE);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_pioor, tvb, offset, 2, FALSE);
  proto_tree_add_item(iin_tree, hf_dnp3_al_iin_obju, tvb, offset, 2, FALSE);
}

/*****************************************************************/
/* Function to determine Application Layer Object Index size */
/*****************************************************************/
static int
dnp3_al_obj_procindex(tvbuff_t *tvb, int bitindex, int offset, guint8 al_objq_index, guint32 *al_ptaddr)
{
  int indexbytes = 0;

  switch (al_objq_index)
  {
    case AL_OBJQL_IDX_NI:        /* No Index */
     if (bitindex > 0)           /* Increment Address by 1 */
     {
      *al_ptaddr += 1;
     }
    indexbytes = 0;
     break;
    case AL_OBJQL_IDX_1O:
     *al_ptaddr = tvb_get_guint8(tvb, offset);
     indexbytes = 1;
     break;
    case AL_OBJQL_IDX_2O:
     *al_ptaddr = tvb_get_letohs(tvb, offset);
     indexbytes = 2;
     break;
    case AL_OBJQL_IDX_4O:
     *al_ptaddr = tvb_get_letohl(tvb, offset);
     indexbytes = 4;
     break;
  }
  return indexbytes;
}

/*****************************************************************/
/* Function to Determine Application Layer Point Quality Flags & */
/* add Point Quality Flag Sub-Tree */
/*****************************************************************/
static void
dnp3_al_obj_quality(tvbuff_t *tvb, int offset, guint8 al_ptflags, proto_item *t_point, int type)
{

  proto_tree  *quality_tree = NULL;
  int         hf0 = 0, hf1 = 0, hf2 = 0, hf3 = 0, hf4 = 0, hf5 = 0, hf6 = 0, hf7 = 0;

  proto_item_append_text(t_point, "(Quality: ");
  switch (type) {
    case 0: /* Binary Input Quality flags */
      quality_tree = proto_item_add_subtree(t_point, ett_dnp3_al_obj_quality);

      if (al_ptflags & AL_OBJ_BI_FLAG0) {
        proto_item_append_text(t_point, "Online");
      }
      else {
        proto_item_append_text(t_point, "Offline");
      }
      if (al_ptflags & AL_OBJ_BI_FLAG1) proto_item_append_text(t_point, ", Restart");
      if (al_ptflags & AL_OBJ_BI_FLAG2) proto_item_append_text(t_point, ", Comm Fail");
      if (al_ptflags & AL_OBJ_BI_FLAG3) proto_item_append_text(t_point, ", Remote Force");
      if (al_ptflags & AL_OBJ_BI_FLAG4) proto_item_append_text(t_point, ", Local Force");
      if (al_ptflags & AL_OBJ_BI_FLAG5) proto_item_append_text(t_point, ", Chatter Filter");

      hf0 = hf_dnp3_al_biq_b0;
      hf1 = hf_dnp3_al_biq_b1;
      hf2 = hf_dnp3_al_biq_b2;
      hf3 = hf_dnp3_al_biq_b3;
      hf4 = hf_dnp3_al_biq_b4;
      hf5 = hf_dnp3_al_biq_b5;
      hf6 = hf_dnp3_al_biq_b6;
      hf7 = hf_dnp3_al_biq_b7;
      break;

    case 1: /* Binary Output Quality flags */
      quality_tree = proto_item_add_subtree(t_point, ett_dnp3_al_obj_quality);

      if (al_ptflags & AL_OBJ_BO_FLAG0) {
        proto_item_append_text(t_point, "Online");
      }
      else {
        proto_item_append_text(t_point, "Offline");
      }
      if (al_ptflags & AL_OBJ_BO_FLAG1) proto_item_append_text(t_point, ", Restart");
      if (al_ptflags & AL_OBJ_BO_FLAG2) proto_item_append_text(t_point, ", Comm Fail");
      if (al_ptflags & AL_OBJ_BO_FLAG3) proto_item_append_text(t_point, ", Remote Force");
      if (al_ptflags & AL_OBJ_BO_FLAG4) proto_item_append_text(t_point, ", Local Force");

      hf0 = hf_dnp3_al_boq_b0;
      hf1 = hf_dnp3_al_boq_b1;
      hf2 = hf_dnp3_al_boq_b2;
      hf3 = hf_dnp3_al_boq_b3;
      hf4 = hf_dnp3_al_boq_b4;
      hf5 = hf_dnp3_al_boq_b5;
      hf6 = hf_dnp3_al_boq_b6;
      hf7 = hf_dnp3_al_boq_b7;
      break;

    case 2: /* Counter Quality flags */
      quality_tree = proto_item_add_subtree(t_point, ett_dnp3_al_obj_quality);

      if (al_ptflags & AL_OBJ_CTR_FLAG0) {
        proto_item_append_text(t_point, "Online");
      }
      else {
        proto_item_append_text(t_point, "Offline");
      }
      if (al_ptflags & AL_OBJ_CTR_FLAG1) proto_item_append_text(t_point, ", Restart");
      if (al_ptflags & AL_OBJ_CTR_FLAG2) proto_item_append_text(t_point, ", Comm Fail");
      if (al_ptflags & AL_OBJ_CTR_FLAG3) proto_item_append_text(t_point, ", Remote Force");
      if (al_ptflags & AL_OBJ_CTR_FLAG4) proto_item_append_text(t_point, ", Local Force");
      if (al_ptflags & AL_OBJ_CTR_FLAG5) proto_item_append_text(t_point, ", Roll-over");

      hf0 = hf_dnp3_al_ctrq_b0;
      hf1 = hf_dnp3_al_ctrq_b1;
      hf2 = hf_dnp3_al_ctrq_b2;
      hf3 = hf_dnp3_al_ctrq_b3;
      hf4 = hf_dnp3_al_ctrq_b4;
      hf5 = hf_dnp3_al_ctrq_b5;
      hf6 = hf_dnp3_al_ctrq_b6;
      hf7 = hf_dnp3_al_ctrq_b7;
      break;

    case 3: /* Analog Input Quality flags */
      quality_tree = proto_item_add_subtree(t_point, ett_dnp3_al_obj_quality);

      if (al_ptflags & AL_OBJ_AI_FLAG0) {
        proto_item_append_text(t_point, "Online");
      }
      else {
        proto_item_append_text(t_point, "Offline");
      }
      if (al_ptflags & AL_OBJ_AI_FLAG1) proto_item_append_text(t_point, ", Restart");
      if (al_ptflags & AL_OBJ_AI_FLAG2) proto_item_append_text(t_point, ", Comm Fail");
      if (al_ptflags & AL_OBJ_AI_FLAG3) proto_item_append_text(t_point, ", Remote Force");
      if (al_ptflags & AL_OBJ_AI_FLAG4) proto_item_append_text(t_point, ", Local Force");
      if (al_ptflags & AL_OBJ_AI_FLAG5) proto_item_append_text(t_point, ", Over-Range");
      if (al_ptflags & AL_OBJ_AI_FLAG6) proto_item_append_text(t_point, ", Reference Check");

      hf0 = hf_dnp3_al_aiq_b0;
      hf1 = hf_dnp3_al_aiq_b1;
      hf2 = hf_dnp3_al_aiq_b2;
      hf3 = hf_dnp3_al_aiq_b3;
      hf4 = hf_dnp3_al_aiq_b4;
      hf5 = hf_dnp3_al_aiq_b5;
      hf6 = hf_dnp3_al_aiq_b6;
      hf7 = hf_dnp3_al_aiq_b7;
      break;

    case 4: /* Analog Output Quality flags */
      quality_tree = proto_item_add_subtree(t_point, ett_dnp3_al_obj_quality);

      if (al_ptflags & AL_OBJ_AO_FLAG0) {
        proto_item_append_text(t_point, "Online");
      }
      else {
        proto_item_append_text(t_point, "Offline");
      }
      if (al_ptflags & AL_OBJ_AO_FLAG1) proto_item_append_text(t_point, ", Restart");
      if (al_ptflags & AL_OBJ_AO_FLAG2) proto_item_append_text(t_point, ", Comm Fail");
      if (al_ptflags & AL_OBJ_AO_FLAG3) proto_item_append_text(t_point, ", Remote Force");

      hf0 = hf_dnp3_al_aoq_b0;
      hf1 = hf_dnp3_al_aoq_b1;
      hf2 = hf_dnp3_al_aoq_b2;
      hf3 = hf_dnp3_al_aoq_b3;
      hf4 = hf_dnp3_al_aoq_b4;
      hf5 = hf_dnp3_al_aoq_b5;
      hf6 = hf_dnp3_al_aoq_b6;
      hf7 = hf_dnp3_al_aoq_b7;
      break;
  }

  if (quality_tree != NULL) {
    proto_tree_add_item(quality_tree, hf7, tvb, offset, 1, TRUE);
    proto_tree_add_item(quality_tree, hf6, tvb, offset, 1, TRUE);
    proto_tree_add_item(quality_tree, hf5, tvb, offset, 1, TRUE);
    proto_tree_add_item(quality_tree, hf4, tvb, offset, 1, TRUE);
    proto_tree_add_item(quality_tree, hf3, tvb, offset, 1, TRUE);
    proto_tree_add_item(quality_tree, hf2, tvb, offset, 1, TRUE);
    proto_tree_add_item(quality_tree, hf1, tvb, offset, 1, TRUE);
    proto_tree_add_item(quality_tree, hf0, tvb, offset, 1, TRUE);
  }
  proto_item_append_text(t_point, ")");
}

/**********************************************************************/
/* Function to Decode Timestamp From DNP3 Message                     */
/**********************************************************************/
/* 48-bit Time Format                                                 */
/* MSB      FF       EE       DD       CC       BB       AA      LSB  */
/*       ffffffff eeeeeeee dddddddd cccccccc bbbbbbbb aaaaaaaa        */
/*       47    40 39    32 31    24 23    16 15     8 7      0        */
/* Final hex no. should be: 0xAABBCCDDEEFF                            */
/* Epoch time + ms.  dd:mm:yyyy hh:mm:ss.iii                          */
/**********************************************************************/
static char *
dnp3_al_decode_timestamp(tvbuff_t *tvb, int temp_pos, char* buff)
{

  guint32    hi, lo;
  guint64    al_timestamp, time_ms;
  time_t     alts_noms;
  struct tm  *ptm;

  lo = tvb_get_letohs(tvb, temp_pos);
  hi = tvb_get_letohl(tvb, temp_pos + 2);
  al_timestamp = ((gint64)hi * 0x10000 + lo);

  time_ms = al_timestamp % 1000; /* Determine ms from timestamp) */
  al_timestamp = al_timestamp / 1000; /*  Divide 1000 from raw timestamp to remove ms */
  alts_noms = (const long) al_timestamp;
  ptm = gmtime(&alts_noms);

  /*g_snprintf(buff, 25,"%02d/%02d/%4d %02d:%02d:%02d.%03d",(ptm->tm_mon + 1), ptm->tm_mday,
          (ptm->tm_year+1900), ptm->tm_hour, ptm->tm_min, ptm->tm_sec, time_ms); */
  /* Time-stamp in ISO format - perhaps an option should be added for different locales? */
  g_snprintf(buff, 25,"%04d/%02d/%02d %02d:%02d:%02d.%03"PRIu64,(ptm->tm_year+1900),ptm->tm_mday,
          (ptm->tm_mon + 1), ptm->tm_hour, ptm->tm_min, ptm->tm_sec, time_ms);


  return buff;

}

/*****************************************************************/
/*  Desc:    Application Layer Process Object Details            */
/*  Returns: New offset pointer into tvb                         */
/*****************************************************************/
static int
dnp3_al_process_object(tvbuff_t *tvb, int offset, proto_tree *robj_tree)
{

  guint8        al_objq, al_objq_index, al_objq_code, al_ptflags, al_ctlobj_code,
                al_ctlobj_code_c, al_ctlobj_code_m, al_ctlobj_code_tc, al_ctlobj_count, al_bi_val, bitindex=0;
  guint16       al_obj, temp16=0, al_val16=0, al_ctlobj_stat;
  guint32       al_val32, num_items=0, al_ptaddr=0, al_ctlobj_on, al_ctlobj_off;
  gboolean      al_bit;
  guint         temp_pos;
  int           rangebytes=0, indexbytes=0;
  proto_item    *t_objdet = NULL, *t_point = NULL, *qualifier_item = NULL, *range_item = NULL;
  proto_tree    *objdet_tree = NULL, *qualifier_tree, *range_tree;
  const gchar   *ctl_code_str, *ctl_misc_str, *ctl_tc_str, *ctl_status_str;
  gchar         buff[25];

  /* Application Layer Objects in this Message */
  al_obj = tvb_get_ntohs(tvb, offset);

  /* Create Data Objects Detail Tree */
  t_objdet = proto_tree_add_uint_format(robj_tree, hf_dnp3_al_obj, tvb, offset, 2, al_obj,
     "Object(s): %s (0x%04x)", val_to_str(al_obj, dnp3_al_obj_vals, "Unknown Object - Abort Decoding..."), al_obj);
  objdet_tree = proto_item_add_subtree(t_objdet, ett_dnp3_al_obj);

  offset += 2;

  /* Object Qualifier */
  al_objq = tvb_get_guint8(tvb, offset);
  al_objq_index = al_objq & AL_OBJQ_INDEX;
  al_objq_index = al_objq_index >> 4; /* bit-shift to the right by 4 (x111xxxx -> xxxxx111) */
  al_objq_code = al_objq & AL_OBJQ_CODE;

  qualifier_item = proto_tree_add_text(objdet_tree, tvb, offset, 1, "Qualifier Field, Prefix: %s, Code: %s",
    val_to_str(al_objq_index, dnp3_al_objq_index_vals, "Unknown Index Type"),
    val_to_str(al_objq_code, dnp3_al_objq_code_vals, "Unknown Code Type"));
  qualifier_tree = proto_item_add_subtree(qualifier_item, ett_dnp3_al_obj_qualifier);
  proto_tree_add_item(qualifier_tree, hf_dnp3_al_objq_index, tvb, offset, 1, FALSE);
  proto_tree_add_item(qualifier_tree, hf_dnp3_al_objq_code, tvb, offset, 1, FALSE);

  offset += 1;

  /* Create (possibly synthesized) number of items and range field tree */
  range_item = proto_tree_add_text(objdet_tree, tvb, offset, 0, "Number of Items: ");
  range_tree = proto_item_add_subtree(range_item, ett_dnp3_al_obj_range);

  switch (al_objq_code)
  {
    case AL_OBJQL_CODE_SSI8:           /* 8-bit Start and Stop Indices in Range Field */
      num_items = ( tvb_get_guint8(tvb, offset+1) - tvb_get_guint8(tvb, offset) + 1);
      PROTO_ITEM_SET_GENERATED(range_item);
      al_ptaddr = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_start8, tvb, offset, 1, TRUE);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_stop8, tvb, offset + 1, 1, TRUE);
      rangebytes = 2;
      break;
    case AL_OBJQL_CODE_SSI16:          /* 16-bit Start and Stop Indices in Range Field */
      num_items = ( tvb_get_letohs(tvb, offset+2) - tvb_get_letohs(tvb, (offset)) + 1);
      PROTO_ITEM_SET_GENERATED(range_item);
      al_ptaddr = tvb_get_letohs(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_start16, tvb, offset, 2, TRUE);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_stop16, tvb, offset + 2, 2, TRUE);
      rangebytes = 4;
      break;
    case AL_OBJQL_CODE_SSI32:          /* 32-bit Start and Stop Indices in Range Field */
      num_items = ( tvb_get_letohl(tvb, offset+4) - tvb_get_letohl(tvb, offset) + 1);
      PROTO_ITEM_SET_GENERATED(range_item);
      al_ptaddr = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_start32, tvb, offset, 4, TRUE);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_stop32, tvb, offset + 4, 2, TRUE);
      rangebytes = 8;
      break;
    case AL_OBJQL_CODE_AA8:            /* 8-bit Absolute Address in Range Field */
      num_items = 1;
      PROTO_ITEM_SET_GENERATED(range_item);
      al_ptaddr = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_abs8, tvb, offset, 1, TRUE);
      rangebytes = 1;
      break;
    case AL_OBJQL_CODE_AA16:           /* 16-bit Absolute Address in Range Field */
      num_items = 1;
      PROTO_ITEM_SET_GENERATED(range_item);
      al_ptaddr = tvb_get_letohs(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_abs16, tvb, offset, 2, TRUE);
      rangebytes = 2;
      break;
    case AL_OBJQL_CODE_AA32:           /* 32-bit Absolute Address in Range Field */
      num_items = 1;
      PROTO_ITEM_SET_GENERATED(range_item);
      al_ptaddr = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_abs32, tvb, offset, 4, TRUE);
      rangebytes = 4;
      break;
    case AL_OBJQL_CODE_SF8:            /* 8-bit Single Field Quantity in Range Field */
      num_items = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_quant8, tvb, offset, 1, TRUE);
      rangebytes = 1;
      proto_item_set_len(range_item, rangebytes);
      break;
    case AL_OBJQL_CODE_SF16:           /* 16-bit Single Field Quantity in Range Field */
      num_items = tvb_get_letohs(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_quant16, tvb, offset, 2, TRUE);
      rangebytes = 2;
      proto_item_set_len(range_item, rangebytes);
      break;
    case AL_OBJQL_CODE_SF32:           /* 32-bit Single Field Quantity in Range Field */
      num_items = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_quant32, tvb, offset, 4, TRUE);
      rangebytes = 4;
      proto_item_set_len(range_item, rangebytes);
      break;
  }
  proto_item_append_text(range_item, "%d", num_items);

  offset += rangebytes;

  bitindex = 0; /* Temp variable for cycling through points when object values are encoded into
            bits; primarily objects 0x0101 & 0x1001 */

  for (temp16 = 0; temp16 < num_items; temp16++)
  {
    switch (al_obj)
    {

      case AL_OBJ_BI_ALL:      /* Binary Input All Var (Obj:01, Var:All) */
      case AL_OBJ_BIC_ALL:     /* Binary Input Change All Var (Obj:02, Var:All) */
      case AL_OBJ_CTR_ALL:     /* Binary Counter All Var (Obj:20, Var:All) */
      case AL_OBJ_CTRC_ALL:    /* Binary Counter Change All Var (Obj:22 Var:All) */
      case AL_OBJ_AI_ALL:      /* Analog Input All Var (Obj:30, Var:All) */
      case AL_OBJ_AIC_ALL:     /* Analog Input Change All Var (Obj:32 Var:All) */

        indexbytes = dnp3_al_obj_procindex(tvb, bitindex, offset, al_objq_index, &al_ptaddr);
        offset += indexbytes;
        break;

      case AL_OBJ_BI_1BIT:    /* Single-Bit Binary Input (Obj:01, Var:01) */
      case AL_OBJ_BO:         /* Binary Output (Obj:10, Var:01) */

        if (bitindex <= 7)
        {
          al_bi_val = tvb_get_guint8(tvb, offset);
        }
        else /* bitindex > 7 */
        {
          offset += 1;
          al_bi_val = tvb_get_guint8(tvb, offset);
          bitindex = 0;
        }

        /* Extract the bit from the packed byte */
        al_bit = (al_bi_val & (1 << bitindex)) > 0;

        proto_tree_add_uint_format(objdet_tree, hf_dnp3_al_ptnum, tvb, offset, 1, al_ptaddr,
           "Point Number %d, Value: %d", al_ptaddr, al_bit);

        al_ptaddr += 1;

        if (temp16 == (num_items-1))
        {
          offset += 1;
        }

        break;

      case AL_OBJ_BI_STAT:    /* Binary Input With Status (Obj:01, Var:02) */
      case AL_OBJ_BO_STAT:    /* Binary Output Status (Obj:10, Var:02) */

        /* Get Point Flags */
        al_ptflags = tvb_get_guint8(tvb, offset);
        al_bit = (al_ptflags & AL_OBJ_BI_FLAG7) > 0;

        switch (al_obj) {
          case AL_OBJ_BI_STAT:
            t_point = proto_tree_add_uint_format(objdet_tree, hf_dnp3_al_ptnum, tvb, offset, 1, al_ptaddr,
               "Point Number %d ", al_ptaddr);
            dnp3_al_obj_quality(tvb, offset, al_ptflags, t_point, 0);
            proto_item_append_text(t_point, ", Value: %d", al_bit);
            break;
          case AL_OBJ_BO_STAT:
            t_point = proto_tree_add_uint_format(objdet_tree, hf_dnp3_al_ptnum, tvb, offset, 1, al_ptaddr,
               "Point Number %d ", al_ptaddr);
            dnp3_al_obj_quality(tvb, offset, al_ptflags, t_point, 1);
            proto_item_append_text(t_point, ", Value: %d", al_bit);
            break;
        }

        al_ptaddr += 1;
        offset += 1;
        break;

      case AL_OBJ_BIC_TIME:   /* Binary Input Change w/ Time (Obj:02, Var:02)  */

        temp_pos = offset;
        indexbytes = dnp3_al_obj_procindex(tvb, bitindex, offset, al_objq_index, &al_ptaddr);
        temp_pos += indexbytes;

        /* Get Point Flags */
        al_ptflags = tvb_get_guint8(tvb, temp_pos);
        temp_pos += 1;

        al_bit = (al_ptflags & AL_OBJ_BI_FLAG7) >> 7; /* bit shift 1xxxxxxx -> xxxxxxx1 */

        t_point = proto_tree_add_uint_format(objdet_tree, hf_dnp3_al_ptnum, tvb, offset, (indexbytes + 7), al_ptaddr,
          "Point Number %d ", al_ptaddr);
        dnp3_al_obj_quality(tvb, (offset+indexbytes), al_ptflags, t_point, 0);
        proto_item_append_text(t_point, ", Value: %d, Timestamp: %s", al_bit, dnp3_al_decode_timestamp(tvb, temp_pos, buff));

        offset += (indexbytes + 7);

        break;

      case AL_OBJ_CTLOP_BLK:  /* Control Relay Output Block (Obj:12, Var:01) */

        /* Process Index */
        temp_pos = offset;
        indexbytes = dnp3_al_obj_procindex(tvb, bitindex, offset, al_objq_index, &al_ptaddr);
        temp_pos += indexbytes;

        al_ctlobj_code = tvb_get_guint8(tvb, temp_pos);
        temp_pos += 1;

        /* Bit-Mask xxxx1111 for Control Code 'Code' */
        al_ctlobj_code_c = al_ctlobj_code & AL_OBJCTLC_CODE;
        ctl_code_str = val_to_str(al_ctlobj_code_c, dnp3_al_ctlc_code_vals, "Ctrl Code Invalid (0x%02x)");

        /* Bit-Mask xx11xxxx for Control Code Misc Values */
        al_ctlobj_code_m = al_ctlobj_code & AL_OBJCTLC_MISC;
        ctl_misc_str = val_to_str(al_ctlobj_code_m, dnp3_al_ctlc_misc_vals, "");

        /* Bit-Mask 11xxxxxx for Control Code 'Trip/Close' */
        al_ctlobj_code_tc = al_ctlobj_code & AL_OBJCTLC_TC;
        ctl_tc_str = val_to_str(al_ctlobj_code_tc, dnp3_al_ctlc_tc_vals, "");

        /* Get "Count" Field */
        al_ctlobj_count = tvb_get_guint8(tvb, temp_pos);
        temp_pos += 1;

        /* Get "On Time" Field */
        al_ctlobj_on = tvb_get_letohl(tvb, temp_pos);
        temp_pos += 4;

        /* Get "Off Time" Field */
        al_ctlobj_off = tvb_get_letohl(tvb, temp_pos);
        temp_pos += 4;

        al_ctlobj_stat = tvb_get_guint8(tvb, temp_pos);
        ctl_status_str = val_to_str(al_ctlobj_stat, dnp3_al_ctl_status_vals, "Invalid Status (0x%02x)");

        proto_tree_add_uint_format(objdet_tree, hf_dnp3_al_ptnum, tvb, offset, (indexbytes + 11), al_ptaddr,
          "Point Number %d, Control Code: [%s,%s,%s (0x%02x)]",
             al_ptaddr, ctl_code_str, ctl_misc_str, ctl_tc_str, al_ctlobj_code);

        proto_tree_add_text(objdet_tree, tvb, offset, (indexbytes+11),
           "  [Count: %d] [On-Time: %d] [Off-Time: %d] [Status: %s (0x%02x)]",
               al_ctlobj_count, al_ctlobj_on, al_ctlobj_off, ctl_status_str, al_ctlobj_stat);

        offset += (indexbytes + 11);

        break;

      case AL_OBJ_CTR_32:     /* 32-Bit Binary Counter (Obj:20, Var:01) */
      case AL_OBJ_CTR_16:     /* 16-Bit Binary Counter (Obj:20, Var:02) */
      case AL_OBJ_FCTR_32:    /* 32-Bit Frozen Counter (Obj:21, Var:01) */
      case AL_OBJ_FCTR_16:    /* 16-Bit Frozen Counter (Obj:21, Var:02) */
      case AL_OBJ_CTRC_32:    /* 32-Bit Counter Change Event w/o Time (Obj:22, Var:01) */
      case AL_OBJ_CTRC_16:    /* 16-Bit Counter Change Event w/o Time (Obj:22, Var:02) */

        /* Process Index */
        temp_pos = offset;
        indexbytes = dnp3_al_obj_procindex(tvb, bitindex, offset, al_objq_index, &al_ptaddr);
        temp_pos += indexbytes;

        /* Get Point Flags */
        al_ptflags = tvb_get_guint8(tvb, temp_pos);
        temp_pos += 1;

        switch (al_obj)
        {
          case AL_OBJ_CTR_32:
          case AL_OBJ_FCTR_32:
          case AL_OBJ_CTRC_32:

            al_val32 = tvb_get_letohl(tvb, temp_pos);
            t_point = proto_tree_add_uint_format(objdet_tree, hf_dnp3_al_ptnum, tvb, offset, (indexbytes + 5), al_ptaddr,
               "Point Number %d ", al_ptaddr);
            dnp3_al_obj_quality(tvb, (offset+indexbytes), al_ptflags, t_point, 2);
            proto_item_append_text(t_point, ", Value: %d", al_val32);
            offset += (indexbytes + 5);
            break;

          case AL_OBJ_CTR_16:
          case AL_OBJ_FCTR_16:
          case AL_OBJ_CTRC_16:

            al_val16 = tvb_get_letohs(tvb, temp_pos);
            t_point = proto_tree_add_uint_format(objdet_tree, hf_dnp3_al_ptnum, tvb, offset, (indexbytes + 3), al_ptaddr,
               "Point Number %d ", al_ptaddr);
            dnp3_al_obj_quality(tvb, (offset+indexbytes), al_ptflags, t_point, 2);
            proto_item_append_text(t_point, ", Value: %d", al_val16);
            offset += (indexbytes + 3);
            break;
        }

        break;

      case AL_OBJ_AI_32:       /* 32-Bit Analog Input (Obj:30, Var:01) */
      case AL_OBJ_AI_16:       /* 16-Bit Analog Input (Obj:30, Var:02) */
      case AL_OBJ_AIC_32NT:    /* 32-Bit Analog Change Event w/o Time (Obj:32, Var:01) */
      case AL_OBJ_AIC_16NT:    /* 16-Bit Analog Change Event w/o Time (Obj:32, Var:02) */

        /* Process Index */
        temp_pos = offset;
        indexbytes = dnp3_al_obj_procindex(tvb, bitindex, offset, al_objq_index, &al_ptaddr);
        temp_pos += indexbytes;

        /* Get Point Flags */
        al_ptflags = tvb_get_guint8(tvb, temp_pos);
        temp_pos += 1;

        switch (al_obj)
        {
          case AL_OBJ_AI_32:
          case AL_OBJ_AIC_32NT:

            al_val32 = tvb_get_letohl(tvb, temp_pos);
            t_point = proto_tree_add_uint_format(objdet_tree, hf_dnp3_al_ptnum, tvb, offset, (indexbytes + 5), al_ptaddr,
              "Point Number %d ", al_ptaddr);
            dnp3_al_obj_quality(tvb, (offset+indexbytes), al_ptflags, t_point, 3);
            proto_item_append_text(t_point, ", Value: %d", al_val32);
            offset += (indexbytes + 5);
            break;

          case AL_OBJ_AI_16:
          case AL_OBJ_AIC_16NT:

            al_val16 = tvb_get_letohs(tvb, temp_pos);
            t_point = proto_tree_add_uint_format(objdet_tree, hf_dnp3_al_ptnum, tvb, offset, (indexbytes + 3), al_ptaddr,
              "Point Number %d ", al_ptaddr);
            dnp3_al_obj_quality(tvb, (offset+indexbytes), al_ptflags, t_point, 3);
            proto_item_append_text(t_point, ", Value: %d", al_val16);
            offset += (indexbytes + 3);
            break;
        }

        break;

      case AL_OBJ_CTR_32NF:    /* 32-Bit Binary Counter Without Flag (Obj:20, Var:05) */
      case AL_OBJ_CTR_16NF:    /* 16-Bit Binary Counter Without Flag (Obj:20, Var:06) */
      case AL_OBJ_AI_32NF:     /* 32-Bit Analog Input Without Flag (Obj:30, Var:03) */
      case AL_OBJ_AI_16NF:     /* 16-Bit Analog Input Without Flag (Obj:30, Var:04) */

        /* Process Index */
        temp_pos = offset;
        indexbytes = dnp3_al_obj_procindex(tvb, bitindex, offset, al_objq_index, &al_ptaddr);
        temp_pos += indexbytes;

        switch (al_obj)
        {
          case AL_OBJ_CTR_32NF:
          case AL_OBJ_AI_32NF:

            al_val32 = tvb_get_letohl(tvb, temp_pos);
            proto_tree_add_uint_format(objdet_tree, hf_dnp3_al_ptnum, tvb, offset, (indexbytes + 4), al_ptaddr,
              "Point Number %d, Value: %d", al_ptaddr, al_val32);
            offset += (indexbytes + 4);
            break;

          case AL_OBJ_CTR_16NF:
          case AL_OBJ_AI_16NF:

            al_val16 = tvb_get_letohs(tvb, temp_pos);
            proto_tree_add_uint_format(objdet_tree, hf_dnp3_al_ptnum, tvb, offset, (indexbytes + 2), al_ptaddr,
              "Point Number %d, Value: %d", al_ptaddr, al_val16);
            offset += (indexbytes + 2);
            break;
        }

        break;

      case AL_OBJ_AIC_32T:      /* 32-Bit Analog Change Event with Time (Obj:32, Var:03) */
      case AL_OBJ_AIC_16T:      /* 16-Bit Analog Change Event with Time (Obj:32, Var:04) */

        /* Process Index */
        temp_pos = offset;
        indexbytes = dnp3_al_obj_procindex(tvb, bitindex, offset, al_objq_index, &al_ptaddr);
        temp_pos += indexbytes;

        /* Get Point Flags */
        al_ptflags = tvb_get_guint8(tvb, temp_pos);
        temp_pos += 1;

        switch (al_obj)
        {
          case AL_OBJ_AIC_32T:

            al_val32 = tvb_get_letohl(tvb, temp_pos);
            temp_pos += 4;
            t_point = proto_tree_add_uint_format(objdet_tree, hf_dnp3_al_ptnum, tvb, offset, (indexbytes + 11), al_ptaddr,
              "Point Number %d ", al_ptaddr);
            dnp3_al_obj_quality(tvb, (offset+indexbytes), al_ptflags, t_point, 3);
            proto_item_append_text(t_point, ", Value: %d, Timestamp: %s", al_val32, dnp3_al_decode_timestamp(tvb, temp_pos, buff));
            offset += (indexbytes + 11); /* 1byte quality, 4bytes value, 6bytes timestamp */
            break;

          case AL_OBJ_AIC_16T:

            al_val16 = tvb_get_letohs(tvb, temp_pos);
            temp_pos += 2;
            t_point = proto_tree_add_uint_format(objdet_tree, hf_dnp3_al_ptnum, tvb, offset, (indexbytes + 9), al_ptaddr,
              "Point Number %d ", al_ptaddr);
            dnp3_al_obj_quality(tvb, (offset+indexbytes), al_ptflags, t_point, 3);
            proto_item_append_text(t_point, ", Value: %d, Timestamp: %s", al_val16, dnp3_al_decode_timestamp(tvb, temp_pos, buff));
            offset += (indexbytes + 9); /* 1byte quality, 2bytes value, 6bytes timestamp */
            break;
        }

        break;

      case AL_OBJ_AO_16:     /* 16-Bit Analog Output Status (Obj:40, Var:02)" */

        /* Process Index */
        temp_pos = offset;
        indexbytes = dnp3_al_obj_procindex(tvb, bitindex, offset, al_objq_index, &al_ptaddr);
        temp_pos += indexbytes;

        /* Get Point Flags */
        al_ptflags = tvb_get_guint8(tvb, temp_pos);
        temp_pos += 1;

        al_val16 = tvb_get_letohs(tvb, temp_pos);
        t_point = proto_tree_add_uint_format(objdet_tree, hf_dnp3_al_ptnum, tvb, offset, (indexbytes + 3), al_ptaddr,
          "Point Number %d ", al_ptaddr);
        dnp3_al_obj_quality(tvb, (offset+indexbytes), al_ptflags, t_point, 4);
        proto_item_append_text(t_point, ", Value: %d", al_val16);

        offset += (indexbytes + 3);

        break;

      case AL_OBJ_TD:    /* Time and Date (Obj:50, Var:01) */

        proto_tree_add_text(objdet_tree, tvb, offset, (indexbytes+6),
           "Time: %s", dnp3_al_decode_timestamp(tvb, offset, buff));
        offset += (indexbytes + 6);
        break;

      case AL_OBJ_TDELAYF: /* Time Delay - Fine (Obj:52, Var:02) */

        al_val16 = tvb_get_letohs(tvb, offset);
        proto_tree_add_text(objdet_tree, tvb, offset, (indexbytes + 2),"Time Delay: %d ms", al_val16);
        offset += (indexbytes + 2);
        break;

      case AL_OBJ_CLASS0:  /* Class Data Objects */
      case AL_OBJ_CLASS1:
      case AL_OBJ_CLASS2:
      case AL_OBJ_CLASS3:

        /* Process Index */
        indexbytes = dnp3_al_obj_procindex(tvb, bitindex, offset, al_objq_index, &al_ptaddr);
        offset += indexbytes;
        break;

      case AL_OBJ_IIN:     /* IIN Data Object */

        /* Process Index */
        indexbytes = dnp3_al_obj_procindex(tvb, bitindex, offset, al_objq_index, &al_ptaddr);
        offset += indexbytes;
        break;

      default:             /* In case of unknown object */

        proto_tree_add_text(objdet_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset),
          "Unknown Data Chunk, %d Bytes", tvb_reported_length_remaining(tvb, offset));
        offset = tvb_length(tvb); /* Finish decoding if unknown object is encountered... */
        break;
    }

    bitindex += 1;
  }

  return offset;

}

/*****************************************************************/
/* Application Layer Dissector */
/*****************************************************************/
static int
dissect_dnp3_al(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  guint8        al_ctl, al_seq, al_func;
  guint16       bytes;
  gboolean      al_fir, al_fin, al_con;
  guint         data_len = 0, offset = 0;
  proto_item   *ti = NULL, *tc, *t_robj;
  proto_tree   *al_tree = NULL, *field_tree = NULL, *robj_tree = NULL;
  const gchar  *func_code_str;

  data_len = tvb_length(tvb);

  /* Handle the control byte and function code */
  al_ctl = tvb_get_guint8(tvb, offset);
  al_seq = al_ctl & DNP3_AL_SEQ;
  al_fir = al_ctl & DNP3_AL_FIR;
  al_fin = al_ctl & DNP3_AL_FIN;
  al_con = al_ctl & DNP3_AL_CON;
  al_func = tvb_get_guint8(tvb, (offset+1));
  func_code_str = val_to_str(al_func, dnp3_al_func_vals, "Unknown function (0x%02x)");

  if (tree) {
    /* format up the text representation */

    ti = proto_tree_add_text(tree, tvb, offset, data_len, "Application Layer: (");
    if (al_ctl & DNP3_AL_FIR)  proto_item_append_text(ti, "FIR, ");
    if (al_ctl & DNP3_AL_FIN)  proto_item_append_text(ti, "FIN, ");
    if (al_ctl & DNP3_AL_CON)  proto_item_append_text(ti, "CON, ");
    proto_item_append_text(ti, "Sequence %d, %s)", al_seq, func_code_str);

    /* Add the al tree branch */
    al_tree = proto_item_add_subtree(ti, ett_dnp3_al);

    /* Application Layer control byte subtree */
    tc = proto_tree_add_uint_format(al_tree, hf_dnp3_al_ctl, tvb, offset, 1, al_ctl,
            "Control: 0x%02x (", al_ctl);
    if (al_ctl & DNP3_AL_FIR)  proto_item_append_text(tc, "FIR, ");
    if (al_ctl & DNP3_AL_FIN)  proto_item_append_text(tc, "FIN, ");
    if (al_ctl & DNP3_AL_CON)  proto_item_append_text(tc, "CON, ");
    proto_item_append_text(tc, "Sequence %d)", al_seq);

    field_tree = proto_item_add_subtree(tc, ett_dnp3_al_ctl);
    proto_tree_add_boolean(field_tree, hf_dnp3_al_fir, tvb, offset, 1, al_ctl);
    proto_tree_add_boolean(field_tree, hf_dnp3_al_fin, tvb, offset, 1, al_ctl);
    proto_tree_add_boolean(field_tree, hf_dnp3_al_con, tvb, offset, 1, al_ctl);
    proto_tree_add_item(field_tree, hf_dnp3_al_seq, tvb, offset, 1, FALSE);
    offset += 1;

    /* If this packet is NOT the final Application Layer Message, exit and continue
       processing the remaining data in the fragment.
    if (!al_fin)
    {
      t_robj = proto_tree_add_text(al_tree, tvb, offset, -1, "Buffering User Data Until Final Frame is Received..");
      return 1;
    } */

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
          offset = dnp3_al_process_object(tvb, offset, robj_tree);
        }

        break;

      case AL_FUNC_WRITE:     /* Write Function Code 0x02 */

        /* Create Write Request Data Objects Tree */
        t_robj = proto_tree_add_text(al_tree, tvb, offset, -1, "WRITE Request Data Objects");
        robj_tree = proto_item_add_subtree(t_robj, ett_dnp3_al_objdet);

        /* Process Data Object Details */
        while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
          offset = dnp3_al_process_object(tvb, offset, robj_tree);
        }

        break;

      case AL_FUNC_SELECT:     /* Select Function Code 0x03 */

        /* Create Select Request Data Objects Tree */
        t_robj = proto_tree_add_text(al_tree, tvb, offset, -1, "SELECT Request Data Objects");
        robj_tree = proto_item_add_subtree(t_robj, ett_dnp3_al_objdet);

        /* Process Data Object Details */
        while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
          offset = dnp3_al_process_object(tvb, offset, robj_tree);
        }

        break;

      case AL_FUNC_OPERATE:    /* Operate Function Code 0x04 */
                               /* Functionally identical to 'SELECT' Function Code */

        /* Create Operate Request Data Objects Tree */
        t_robj = proto_tree_add_text(al_tree, tvb, offset, -1, "OPERATE Request Data Objects");
        robj_tree = proto_item_add_subtree(t_robj, ett_dnp3_al_objdet);

        /* Process Data Object Details */
        while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
          offset = dnp3_al_process_object(tvb, offset, robj_tree);
        }

        break;

      case AL_FUNC_DIROP:     /* Direct Operate Function Code 0x05 */
                              /* Functionally identical to 'SELECT' Function Code */

        /* Create Direct Operate Request Data Objects Tree */
        t_robj = proto_tree_add_text(al_tree, tvb, offset, -1, "DIRECT OPERATE Request Data Objects");
        robj_tree = proto_item_add_subtree(t_robj, ett_dnp3_al_objdet);

        /* Process Data Object Details */
        while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
          offset = dnp3_al_process_object(tvb, offset, robj_tree);
        }

        break;

      case AL_FUNC_ENSPMSG:   /* Enable Spontaneous Messages Function Code 0x14 */

        /* Create Enable Spontaneous Messages Data Objects Tree */
        t_robj = proto_tree_add_text(al_tree, tvb, offset, -1, "Enable Spontaneous Msg's Data Objects");
        robj_tree = proto_item_add_subtree(t_robj, ett_dnp3_al_objdet);

        /* Process Data Object Details */
        while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
          offset = dnp3_al_process_object(tvb, offset, robj_tree);
        }

        break;

      case AL_FUNC_DELAYMST:  /* Delay Measurement Function Code 0x17 */

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
            offset = dnp3_al_process_object(tvb, offset, robj_tree);
          }

          break;
        }

      default:    /* Unknown Function */

        break;
    }
  }
  else
  {
    offset += 2;  /* No tree, correct offset */
  }

  return 0;
}

/*****************************************************************/
/* Data Link and Transport layer dissector */
/*****************************************************************/
static void
dissect_dnp3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
    proto_item   *ti = NULL, *tdl, *tc, *al_chunks, *frag_tree_item;
    proto_tree   *dnp3_tree = NULL, *dl_tree = NULL, *tr_tree = NULL, *field_tree = NULL, *al_tree = NULL;
    int           offset = 0, temp_offset = 0, al_result = 0;
    gboolean      dl_prm, tr_fir, tr_fin;
    guint8        dl_len, dl_ctl, dl_func, tr_ctl, tr_seq;
    const gchar  *func_code_str;
    guint16       dl_dst, dl_src, dl_crc, calc_dl_crc;
    guint8       *tmp = NULL, *tmp_ptr;
    guint8        data_len;
    int           data_offset;
    gboolean      crc_OK = FALSE;
    tvbuff_t     *al_tvb = NULL;
    guint         i;
    static guint  seq_number = 0;

/* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DNP 3.0");

  if (check_col(pinfo->cinfo, COL_INFO))
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

  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "len=%d, from %d to %d, %s",
            dl_len, dl_src, dl_dst, func_code_str);

  if (tree) {

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_dnp3, tvb, offset, -1, FALSE);
    dnp3_tree = proto_item_add_subtree(ti, ett_dnp3);

    /* Create Subtree for Data Link Layer */
    tdl = proto_tree_add_text(dnp3_tree, tvb, offset, DNP_HDR_LEN,
          "Data Link Layer, Len: %d, From: %d, To: %d, ", dl_len, dl_src, dl_dst);
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
    proto_item_append_text(tdl, func_code_str);
    dl_tree = proto_item_add_subtree(tdl, ett_dnp3_dl);

    /* start bytes */
    proto_tree_add_item(dl_tree, hf_dnp3_start, tvb, offset, 2, FALSE);
    offset += 2;

    /* add length field */
    proto_tree_add_item(dl_tree, hf_dnp3_len, tvb, offset, 1, FALSE);
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
      proto_tree_add_item(field_tree, hf_dnp3_ctl_dir, tvb, offset, 1, TRUE);
      proto_tree_add_item(field_tree, hf_dnp3_ctl_prm, tvb, offset, 1, TRUE);
      proto_tree_add_item(field_tree, hf_dnp3_ctl_fcb, tvb, offset, 1, TRUE);
      proto_tree_add_item(field_tree, hf_dnp3_ctl_fcv, tvb, offset, 1, TRUE);
      proto_tree_add_item(field_tree, hf_dnp3_ctl_prifunc, tvb, offset, 1, FALSE);
    }
    else {
      proto_tree_add_item(field_tree, hf_dnp3_ctl_dir, tvb, offset, 1, TRUE);
      proto_tree_add_item(field_tree, hf_dnp3_ctl_prm, tvb, offset, 1, TRUE);
      proto_tree_add_item(field_tree, hf_dnp3_ctl_dfc, tvb, offset, 1, TRUE);
      proto_tree_add_item(field_tree, hf_dnp3_ctl_secfunc, tvb, offset, 1, FALSE);
    }
      offset += 1;

    /* add destination and source addresses */
    proto_tree_add_item(dl_tree, hf_dnp3_dst, tvb, offset, 2, TRUE);
    offset += 2;
    proto_tree_add_item(dl_tree, hf_dnp3_src, tvb, offset, 2, TRUE);
    offset += 2;

    /* and header CRC */
    dl_crc = tvb_get_letohs(tvb, offset);
    calc_dl_crc = calculateCRC(tvb_get_ptr(tvb, 0, DNP_HDR_LEN - 2), DNP_HDR_LEN - 2);
    if (dl_crc == calc_dl_crc)
      proto_tree_add_uint_format(dl_tree, hf_dnp_hdr_CRC, tvb, offset, 2,
               dl_crc, "CRC: 0x%04x [correct]", dl_crc);
    else
    {
      proto_tree_add_boolean_hidden(dl_tree, hf_dnp_hdr_CRC_bad, tvb,
                  offset, 2, TRUE);
      proto_tree_add_uint_format(dl_tree, hf_dnp_hdr_CRC, tvb,
               offset, 2, dl_crc, "CRC: 0x%04x [incorrect, should be 0x%04x]",
                     dl_crc, calc_dl_crc);
    }
    offset += 2;
  }
  else
  {
    offset += 10; /* No tree so correct offset */
  }

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

    if (tree)
    {
      /* Add Transport Layer Tree */
      tc = proto_tree_add_uint_format(dnp3_tree, hf_dnp3_tr_ctl, tvb, offset, 1, tr_ctl,
              "Transport Layer: 0x%02x (", tr_ctl);
      if (tr_fir) proto_item_append_text(tc, "FIR, ");
      if (tr_fin) proto_item_append_text(tc, "FIN, ");
      proto_item_append_text(tc, "Sequence %d)", tr_seq);

      tr_tree = proto_item_add_subtree(tc, ett_dnp3_tr_ctl);
      proto_tree_add_boolean(tr_tree, hf_dnp3_tr_fin, tvb, offset, 1, tr_ctl);
      proto_tree_add_boolean(tr_tree, hf_dnp3_tr_fir, tvb, offset, 1, tr_ctl);
      proto_tree_add_item(tr_tree, hf_dnp3_tr_seq, tvb, offset, 1, FALSE);
    }

    /* Allocate AL chunk tree */
    if (tree != NULL)
    {
      al_chunks = proto_tree_add_text(tr_tree, tvb, offset + 1, -1, "Application data chunks");
      al_tree = proto_item_add_subtree(al_chunks, ett_dnp3_al_data);
    }

    /* extract the application layer data, validating the CRCs */

    /* XXX - check for dl_len <= 5 */
    data_len = dl_len - 5;  /* XXX - dl_len - 6, as we're no longer including the transport layer byte? */
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
        if (tree)
        {
          proto_tree_add_text(al_tree, tvb, offset - (chk_size + 2), chk_size,
                  "Application Chunk %d Len: %d CRC 0x%04x",
                  i, chk_size, act_crc);
        }
        data_len -= chk_size;
      }
      else
      {
        if (tree)
        {
          proto_tree_add_text(al_tree, tvb, offset - (chk_size + 2), chk_size,
                  "Application Chunk %d Len: %d Bad CRC got 0x%04x expected 0x%04x",
                  i, chk_size, act_crc, calc_crc);
        }
        data_len = 0;
        break;
      }
      i++;
      data_offset = 0;  /* copy all of the rest of the chunks */
    }

    /* if all crc OK, set up new tvb */
    if (crc_OK)
    {
      al_tvb = tvb_new_real_data(tmp, tmp_ptr-tmp, tmp_ptr-tmp);
      tvb_set_free_cb(al_tvb, g_free);
      tvb_set_child_real_data_tvbuff(tvb, al_tvb);

      /* Check for fragmented packet */
      if (! (tr_fir && tr_fin))
      {
        /* A fragmented packet */

        fragment_data *fd_head;

        /* if first fragment, update sequence id */
        if (tr_fir)
        {
          seq_number++;
        }

        /*
        * If we've already seen this frame, look it up in the
        * table of reassembled packets, otherwise add it to
        * whatever reassembly is in progress, if any, and see
        * if it's done.
        */
        fd_head = fragment_add_seq_check(al_tvb, 0, pinfo, seq_number,
                 al_fragment_table,
                 al_reassembled_table,
                 tr_seq,
                 tvb_reported_length(al_tvb),
                 !tr_fin);
        if (fd_head != NULL)
        {
          /* We have the complete payload */
          al_tvb = tvb_new_real_data(fd_head->data, fd_head->len, fd_head->len);
          tvb_set_child_real_data_tvbuff(tvb, al_tvb);
          add_new_data_source(pinfo, al_tvb, "Reassembled DNP 3.0 Application Layer message");

          if (tree)
            /* Show all fragments. */
            show_fragment_seq_tree(fd_head, &frag_items, tr_tree, pinfo, al_tvb, &frag_tree_item);
        }
        else
        {
          /* We don't have the complete reassembled payload. */
          al_tvb = NULL;
          if (check_col (pinfo->cinfo, COL_INFO))
            col_append_str (pinfo->cinfo, COL_INFO,
                " (Application Layer Message unreassembled)");
        }

      }
      else
      {
        /* No reassembly required */
        add_new_data_source(pinfo, al_tvb, "DNP 3.0 Application Layer message");
      }
    }
    else
    {
      /* CRC error - throw away the data. */
      g_free(tmp);
      if (tree)
        proto_tree_add_text(dnp3_tree, tvb, 11, -1, "CRC failed, %d chunks", i);
    }

    if (al_tvb)
    {
      al_result = dissect_dnp3_al(al_tvb, pinfo, dnp3_tree);
    }
  }
}

static void
al_defragment_init(void)
{
  fragment_table_init(&al_fragment_table);
  reassembled_table_init(&al_reassembled_table);
}

/* Register the protocol with Ethereal */

void
proto_register_dnp3(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_dnp3_start,
    { "Start Bytes", "dnp3.start", FT_UINT16, BASE_HEX, NULL, 0x0, "Start Bytes", HFILL }},

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

    { &hf_dnp3_ctl_dir,
    { "Direction", "dnp3.ctl.dir", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_CTL_DIR, "", HFILL }},

    { &hf_dnp3_ctl_prm,
    { "Primary", "dnp3.ctl.prm", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_CTL_PRM, "", HFILL }},

    { &hf_dnp3_ctl_fcb,
    { "Frame Count Bit", "dnp3.ctl.fcb", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_CTL_FCB, "", HFILL }},

    { &hf_dnp3_ctl_fcv,
    { "Frame Count Valid", "dnp3.ctl.fcv", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_CTL_FCV, "", HFILL }},

    { &hf_dnp3_ctl_dfc,
    { "Data Flow Control", "dnp3.ctl.dfc", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_CTL_DFC, "", HFILL }},

    { &hf_dnp3_dst,
    { "Destination", "dnp3.dst", FT_UINT16, BASE_DEC, NULL, 0x0, "Destination Address", HFILL }},

    { &hf_dnp3_src,
    { "Source", "dnp3.src", FT_UINT16, BASE_DEC, NULL, 0x0, "Source Address", HFILL }},

    { &hf_dnp_hdr_CRC,
    { "CRC", "dnp.hdr.CRC", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_dnp_hdr_CRC_bad,
    { "Bad CRC", "dnp.hdr.CRC_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_dnp3_tr_ctl,
    { "Transport Control", "dnp3.tr.ctl", FT_UINT8, BASE_HEX, NULL, 0x0, "Tranport Layer Control Byte", HFILL }},

    { &hf_dnp3_tr_fin,
    { "Final", "dnp3.tr.fin", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_TR_FIN, "", HFILL }},

    { &hf_dnp3_tr_fir,
    { "First", "dnp3.tr.fir", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_TR_FIR, "", HFILL }},

    { &hf_dnp3_tr_seq,
    { "Sequence", "dnp3.tr.seq", FT_UINT8, BASE_DEC, NULL, DNP3_TR_SEQ, "Frame Sequence Number", HFILL }},

    { &hf_dnp3_al_ctl,
    { "Application Control", "dnp3.al.ctl", FT_UINT8, BASE_HEX, NULL, 0x0, "Application Layer Control Byte", HFILL }},

    { &hf_dnp3_al_fir,
    { "First", "dnp3.al.fir", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_AL_FIR, "", HFILL }},

    { &hf_dnp3_al_fin,
    { "Final", "dnp3.al.fin", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_AL_FIN, "", HFILL }},

    { &hf_dnp3_al_con,
    { "Confirm", "dnp3.al.con", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_AL_CON, "", HFILL }},

    { &hf_dnp3_al_seq,
    { "Sequence", "dnp3.al.seq", FT_UINT8, BASE_DEC, NULL, DNP3_AL_SEQ, "Frame Sequence Number", HFILL }},

    { &hf_dnp3_al_func,
    { "Application Layer Function Code", "dnp3.al.func", FT_UINT8, BASE_DEC,
      VALS(dnp3_al_func_vals), DNP3_AL_FUNC, "Application Function Code", HFILL }},

    { &hf_dnp3_al_iin,
    { "Application Layer IIN bits", "dnp3.al.iin", FT_UINT16, BASE_DEC, NULL, 0x0, "Application Layer IIN", HFILL }},

    { &hf_dnp3_al_iin_bmsg,
    { "Broadcast Msg Rx", "dnp3.al.iin.bmsg", FT_BOOLEAN, 16, TFS(&flags_set_truth), AL_IIN_BMSG, "", HFILL }},

    { &hf_dnp3_al_iin_cls1d,
    { "Class 1 Data Available", "dnp3.al.iin.cls1d", FT_BOOLEAN, 16, TFS(&flags_set_truth), AL_IIN_CLS1D, "", HFILL }},

    { &hf_dnp3_al_iin_cls2d,
    { "Class 2 Data Available", "dnp3.al.iin.cls2d", FT_BOOLEAN, 16, TFS(&flags_set_truth), AL_IIN_CLS2D, "", HFILL }},

    { &hf_dnp3_al_iin_cls3d,
    { "Class 3 Data Available", "dnp3.al.iin.cls3d", FT_BOOLEAN, 16, TFS(&flags_set_truth), AL_IIN_CLS3D, "", HFILL }},

    { &hf_dnp3_al_iin_tsr,
    { "Time Sync Required", "dnp3.al.iin.tsr", FT_BOOLEAN, 16, TFS(&flags_set_truth), AL_IIN_TSR, "", HFILL }},

    { &hf_dnp3_al_iin_dol,
    { "Digital Outputs in Local", "dnp3.al.iin.dol", FT_BOOLEAN, 16, TFS(&flags_set_truth), AL_IIN_DOL, "", HFILL }},

    { &hf_dnp3_al_iin_dt,
    { "Device Trouble", "dnp3.al.iin.dt", FT_BOOLEAN, 16, TFS(&flags_set_truth), AL_IIN_DT, "", HFILL }},

    { &hf_dnp3_al_iin_rst,
    { "Device Restart", "dnp3.al.iin.rst", FT_BOOLEAN, 16, TFS(&flags_set_truth), AL_IIN_RST, "", HFILL }},

    { &hf_dnp3_al_iin_obju,
    { "Requested Objects Unknown", "dnp3.al.iin.obju", FT_BOOLEAN, 16, TFS(&flags_set_truth), AL_IIN_OBJU, "", HFILL }},

    { &hf_dnp3_al_iin_pioor,
    { "Parameters Invalid or Out of Range", "dnp3.al.iin.pioor", FT_BOOLEAN, 16, TFS(&flags_set_truth), AL_IIN_PIOOR, "", HFILL }},

    { &hf_dnp3_al_iin_ebo,
    { "Event Buffer Overflow", "dnp3.al.iin.ebo", FT_BOOLEAN, 16, TFS(&flags_set_truth), AL_IIN_EBO, "", HFILL }},

    { &hf_dnp3_al_iin_oae,
    { "Operation Already Executing", "dnp3.al.iin.oae", FT_BOOLEAN, 16, TFS(&flags_set_truth), AL_IIN_OAE, "", HFILL }},

    { &hf_dnp3_al_iin_cc,
    { "Configuration Corrupt", "dnp3.al.iin.cc", FT_BOOLEAN, 16, TFS(&flags_set_truth), AL_IIN_CC, "", HFILL }},

    { &hf_dnp3_al_obj,
    { "Object", "dnp3.al.obj", FT_UINT16, BASE_HEX, VALS(dnp3_al_obj_vals), 0x0, "Application Layer Object", HFILL }},

    { &hf_dnp3_al_objq_index,
    { "Index Prefix", "dnp3.al.objq.index", FT_UINT8, BASE_DEC, VALS(dnp3_al_objq_index_vals), AL_OBJQ_INDEX, "Object Index Prefixing", HFILL }},

    { &hf_dnp3_al_objq_code,
    { "Qualifier Code", "dnp3.al.objq.code", FT_UINT8, BASE_DEC, VALS(dnp3_al_objq_code_vals), AL_OBJQ_CODE, "Object Qualifier Code", HFILL }},

    { &hf_dnp3_al_range_start8,
    { "Start", "dnp3.al.range.start8", FT_UINT8, BASE_DEC, NULL, 0x0, "Object Start Index", HFILL }},

    { &hf_dnp3_al_range_stop8,
    { "Stop", "dnp3.al.range.stop8", FT_UINT8, BASE_DEC, NULL, 0x0, "Object Stop Index", HFILL }},

    { &hf_dnp3_al_range_start16,
    { "Start", "dnp3.al.range.start16", FT_UINT16, BASE_DEC, NULL, 0x0, "Object Start Index", HFILL }},

    { &hf_dnp3_al_range_stop16,
    { "Stop", "dnp3.al.range.stop16", FT_UINT16, BASE_DEC, NULL, 0x0, "Object Stop Index", HFILL }},

    { &hf_dnp3_al_range_start32,
    { "Start", "dnp3.al.range.start32", FT_UINT32, BASE_DEC, NULL, 0x0, "Object Start Index", HFILL }},

    { &hf_dnp3_al_range_stop32,
    { "Stop", "dnp3.al.range.stop32", FT_UINT32, BASE_DEC, NULL, 0x0, "Object Stop Index", HFILL }},

    { &hf_dnp3_al_range_abs8,
    { "Address", "dnp3.al.range.abs8", FT_UINT8, BASE_DEC, NULL, 0x0, "Object Absolute Address", HFILL }},

    { &hf_dnp3_al_range_abs16,
    { "Address", "dnp3.al.range.abs16", FT_UINT16, BASE_DEC, NULL, 0x0, "Object Absolute Address", HFILL }},

    { &hf_dnp3_al_range_abs32,
    { "Address", "dnp3.al.range.abs32", FT_UINT32, BASE_DEC, NULL, 0x0, "Object Absolute Address", HFILL }},

    { &hf_dnp3_al_range_quant8,
    { "Quantity", "dnp3.al.range.quant8", FT_UINT8, BASE_DEC, NULL, 0x0, "Object Quantity", HFILL }},

    { &hf_dnp3_al_range_quant16,
    { "Quantity", "dnp3.al.range.quant16", FT_UINT16, BASE_DEC, NULL, 0x0, "Object Quantity", HFILL }},

    { &hf_dnp3_al_range_quant32,
    { "Quantity", "dnp3.al.range.quant32", FT_UINT32, BASE_DEC, NULL, 0x0, "Object Quantity", HFILL }},

    { &hf_dnp3_al_ptnum,
    { "Object Point Number", "dnp3.al.ptnum", FT_UINT16, BASE_DEC, NULL, 0x0, "Object Point Number", HFILL }},

    { &hf_dnp3_al_biq_b0,
    { "Online", "dnp3.al.biq.b0", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_BI_FLAG0, "", HFILL }},

    { &hf_dnp3_al_biq_b1,
    { "Restart", "dnp3.al.biq.b1", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_BI_FLAG1, "", HFILL }},

    { &hf_dnp3_al_biq_b2,
    { "Comm Fail", "dnp3.al.biq.b2", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_BI_FLAG2, "", HFILL }},

    { &hf_dnp3_al_biq_b3,
    { "Remote Force", "dnp3.al.biq.b3", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_BI_FLAG3, "", HFILL }},

    { &hf_dnp3_al_biq_b4,
    { "Local Force", "dnp3.al.biq.b4", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_BI_FLAG4, "", HFILL }},

    { &hf_dnp3_al_biq_b5,
    { "Chatter Filter", "dnp3.al.biq.b5", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_BI_FLAG5, "", HFILL }},

    { &hf_dnp3_al_biq_b6,
    { "Reserved", "dnp3.al.biq.b6", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_BI_FLAG6, "", HFILL }},

    { &hf_dnp3_al_biq_b7,
    { "Point Value", "dnp3.al.biq.b7", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_BI_FLAG7, "", HFILL }},

    { &hf_dnp3_al_boq_b0,
    { "Online", "dnp3.al.boq.b0", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_BO_FLAG0, "", HFILL }},

    { &hf_dnp3_al_boq_b1,
    { "Restart", "dnp3.al.boq.b1", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_BO_FLAG1, "", HFILL }},

    { &hf_dnp3_al_boq_b2,
    { "Comm Fail", "dnp3.al.boq.b2", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_BO_FLAG2, "", HFILL }},

    { &hf_dnp3_al_boq_b3,
    { "Remote Force", "dnp3.al.boq.b3", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_BO_FLAG3, "", HFILL }},

    { &hf_dnp3_al_boq_b4,
    { "Local Force", "dnp3.al.boq.b4", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_BO_FLAG4, "", HFILL }},

    { &hf_dnp3_al_boq_b5,
    { "Reserved", "dnp3.al.boq.b5", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_BO_FLAG5, "", HFILL }},

    { &hf_dnp3_al_boq_b6,
    { "Reserved", "dnp3.al.boq.b6", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_BO_FLAG6, "", HFILL }},

    { &hf_dnp3_al_boq_b7,
    { "Point Value", "dnp3.al.boq.b7", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_BO_FLAG7, "", HFILL }},

    { &hf_dnp3_al_ctrq_b0,
    { "Online", "dnp3.al.ctrq.b0", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_CTR_FLAG0, "", HFILL }},

    { &hf_dnp3_al_ctrq_b1,
    { "Restart", "dnp3.al.ctrq.b1", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_CTR_FLAG1, "", HFILL }},

    { &hf_dnp3_al_ctrq_b2,
    { "Comm Fail", "dnp3.al.ctrq.b2", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_CTR_FLAG2, "", HFILL }},

    { &hf_dnp3_al_ctrq_b3,
    { "Remote Force", "dnp3.al.ctrq.b3", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_CTR_FLAG3, "", HFILL }},

    { &hf_dnp3_al_ctrq_b4,
    { "Local Force", "dnp3.al.ctrq.b4", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_CTR_FLAG4, "", HFILL }},

    { &hf_dnp3_al_ctrq_b5,
    { "Roll-Over", "dnp3.al.ctrq.b5", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_CTR_FLAG5, "", HFILL }},

    { &hf_dnp3_al_ctrq_b6,
    { "Reserved", "dnp3.al.ctrq.b6", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_CTR_FLAG6, "", HFILL }},

    { &hf_dnp3_al_ctrq_b7,
    { "Reserved", "dnp3.al.ctrq.b7", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_CTR_FLAG7, "", HFILL }},

    { &hf_dnp3_al_aiq_b0,
    { "Online", "dnp3.al.aiq.b0", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_AI_FLAG0, "", HFILL }},

    { &hf_dnp3_al_aiq_b1,
    { "Restart", "dnp3.al.aiq.b1", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_AI_FLAG1, "", HFILL }},

    { &hf_dnp3_al_aiq_b2,
    { "Comm Fail", "dnp3.al.aiq.b2", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_AI_FLAG2, "", HFILL }},

    { &hf_dnp3_al_aiq_b3,
    { "Remote Force", "dnp3.al.aiq.b3", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_AI_FLAG3, "", HFILL }},

    { &hf_dnp3_al_aiq_b4,
    { "Local Force", "dnp3.al.aiq.b4", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_AI_FLAG4, "", HFILL }},

    { &hf_dnp3_al_aiq_b5,
    { "Over-Range", "dnp3.al.aiq.b5", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_AI_FLAG5, "", HFILL }},

    { &hf_dnp3_al_aiq_b6,
    { "Reference Check", "dnp3.al.aiq.b6", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_AI_FLAG6, "", HFILL }},

    { &hf_dnp3_al_aiq_b7,
    { "Reserved", "dnp3.al.aiq.b7", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_AI_FLAG7, "", HFILL }},

    { &hf_dnp3_al_aoq_b0,
    { "Online", "dnp3.al.aoq.b0", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_AO_FLAG0, "", HFILL }},

    { &hf_dnp3_al_aoq_b1,
    { "Restart", "dnp3.al.aoq.b1", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_AO_FLAG1, "", HFILL }},

    { &hf_dnp3_al_aoq_b2,
    { "Comm Fail", "dnp3.al.aoq.b2", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_AO_FLAG2, "", HFILL }},

    { &hf_dnp3_al_aoq_b3,
    { "Remote Force", "dnp3.al.aoq.b3", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_AO_FLAG3, "", HFILL }},

    { &hf_dnp3_al_aoq_b4,
    { "Reserved", "dnp3.al.aoq.b4", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_AO_FLAG4, "", HFILL }},

    { &hf_dnp3_al_aoq_b5,
    { "Reserved", "dnp3.al.aoq.b5", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_AO_FLAG5, "", HFILL }},

    { &hf_dnp3_al_aoq_b6,
    { "Reserved", "dnp3.al.aoq.b6", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_AO_FLAG6, "", HFILL }},

    { &hf_dnp3_al_aoq_b7,
    { "Reserved", "dnp3.al.aoq.b7", FT_BOOLEAN, 8, TFS(&flags_set_truth), AL_OBJ_AO_FLAG7, "", HFILL }},

    { &hf_fragment,
    { "DNP 3.0 AL Fragment", "al.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0, "DNP 3.0 Application Layer Fragment", HFILL }},

    { &hf_fragments,
    { "DNP 3.0 AL Fragments", "al.fragments", FT_NONE, BASE_NONE, NULL, 0x0, "DNP 3.0 Application Layer Fragments", HFILL }},

    { &hf_fragment_overlap,
    { "Fragment overlap", "al.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},

    { &hf_fragment_overlap_conflict,
    { "Conflicting data in fragment overlap", "al.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "Overlapping fragments contained conflicting data", HFILL }},

    { &hf_fragment_multiple_tails,
    { "Multiple tail fragments found", "al.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "Several tails were found when defragmenting the packet", HFILL }},

    { &hf_fragment_too_long_fragment,
    { "Fragment too long", "al.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "Fragment contained data past end of packet", HFILL }},

    { &hf_fragment_error,
    { "Defragmentation error", "al.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
      "Defragmentation error due to illegal fragments", HFILL }},
    { &hf_fragment_reassembled_in,
    { "Reassembled PDU In Frame", "al.fragment.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
      "This PDU is reassembled in this frame", HFILL }}
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
    &ett_dnp3_al_iin,
    &ett_dnp3_al_obj,
    &ett_dnp3_al_obj_qualifier,
    &ett_dnp3_al_obj_range,
    &ett_dnp3_al_objdet,
    &ett_dnp3_al_obj_quality,
    &ett_fragment,
    &ett_fragments
  };

/* Register the protocol name and description */
  proto_dnp3 = proto_register_protocol("Distributed Network Protocol 3.0",
                   "DNP 3.0", "dnp3");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_dnp3, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  al_defragment_init();
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_dnp3(void)
{
  dissector_handle_t dnp3_handle;

  dnp3_handle = create_dissector_handle(dissect_dnp3, proto_dnp3);
  dissector_add("tcp.port", TCP_PORT_DNP, dnp3_handle);
  dissector_add("udp.port", UDP_PORT_DNP, dnp3_handle);
}
