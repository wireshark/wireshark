/* packet-gryphon.h
 *
 * Updated routines for Gryphon protocol packet dissection
 * By Mark C. <markc@dgtech.com>
 * Copyright (C) 2018 DG Technologies, Inc. (Dearborn Group, Inc.) USA
 *
 * Definitions for Gryphon packet disassembly structures and routines
 * By Steve Limkemann <stevelim@dgtech.com>
 * Copyright 1998 Steve Limkemann
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define MSG_HDR_SZ          8
#define CMD_HDR_SZ          4

/* source/destinations: */

#define SD_CARD                 0x01    /* (vehicle) network interface */
#define SD_SERVER               0x02
#define SD_CLIENT               0x03
#define SD_KNOWN                0x10    /* Client ID >= are well known */
#define SD_SCHED                0x10    /* scheduler */
#define SD_SCRIPT               0x20    /* script processor */
#define SD_PGM                  0x21    /* Program loader */
#define SD_USDT                 0x22    /* USDT (Unacknowledged Segmented Data Transfer) */
#define SD_BLM                  0x23    /* Bus Load Monitoring */
#define SD_LIN                  0x24    /* LIN extensions */
#define SD_FLIGHT               0x25    /* Flight Recorder */
#define SD_LOGGER               0x25    /* data logger */
#define SD_RESP                 0x26    /* Message Response */
#define SD_IOPWR                0x27    /* VNG / Compact Gryphon I/O & power */
#define SD_UTIL                 0x28    /* Miscellaneous utility commands   */
#define SD_CNVT                 0x29    /* signal conversion commands */
#define CH_BROADCAST            0xFF    /* broadcast message destination channel */



/* frame types: */
#define GY_FT_CMD               0x01    /* command to initiate some action */
#define GY_FT_RESP              0x02    /* response to a command */
#define GY_FT_DATA              0x03    /* (vehicle) network data */
#define GY_FT_EVENT             0x04    /* notification of an event */
#define GY_FT_MISC              0x05    /* misc data */
#define GY_FT_TEXT              0x06    /* null-terminated ASCII strings */
#define GY_FT_SIG               0x07    /* (vehicle) network signals */



/* generic (all SD type) commands: values 0x00 to 0x3f */

#define CMD_INIT                0x01    /* initialize target */
#define CMD_GET_STAT            0x02    /* request status */
#define CMD_GET_CONFIG          0x03    /* request configuration info */
#define CMD_EVENT_ENABLE        0x04    /* Enable event type */
#define CMD_EVENT_DISABLE       0x05    /* Disable event type */
#define CMD_GET_TIME            0x06    /* Get current value of timestamp */
#define CMD_GET_RXDROP          0x07    /* Get count of Rx msgs dropped */
#define CMD_RESET_RXDROP        0x08    /* Set count of Rx msgs dropped to zero */
#define CMD_BCAST_ON            0x09    /* broadcasts on */
#define CMD_BCAST_OFF           0x0a    /* broadcasts off */
#define CMD_SET_TIME            0x0b    /* set time */

/* SD-type specific commands: should start at 0x40, global uniqueness  */
/* is prefered, but not mandatory. */

/* SD_CARD command types: */

#define CMD_CARD_SET_SPEED      (SD_CARD * 256 + 0x40)    /* set peripheral speed */
#define CMD_CARD_GET_SPEED      (SD_CARD * 256 + 0x41)    /* get peripheral speed */
#define CMD_CARD_SET_FILTER     (SD_CARD * 256 + 0x42)    /* set filter to pass or block all */
#define CMD_CARD_GET_FILTER     (SD_CARD * 256 + 0x43)    /* get a pass/block filter */
#define CMD_CARD_TX             (SD_CARD * 256 + 0x44)    /* transmit message */
#define CMD_CARD_TX_LOOP_ON     (SD_CARD * 256 + 0x45)    /* set transmit loopback on */
#define CMD_CARD_TX_LOOP_OFF    (SD_CARD * 256 + 0x46)    /* set transmit loopback off */
#define CMD_CARD_IOCTL          (SD_CARD * 256 + 0x47)    /* device driver ioctl pass-through */
#define CMD_CARD_ADD_FILTER     (SD_CARD * 256 + 0x48)    /* add a pass/block filter */
#define CMD_CARD_MODIFY_FILTER  (SD_CARD * 256 + 0x49)    /* modify a pass/block filter */
#define CMD_CARD_GET_FILTER_HANDLES (SD_CARD * 256 + 0x4A)/* get a list of filters */
#define CMD_CARD_SET_DEFAULT_FILTER (SD_CARD * 256 + 0x4B)/* set the default action */
#define CMD_CARD_GET_DEFAULT_FILTER (SD_CARD * 256 + 0x4C)/* get the defautl action */
#define CMD_CARD_SET_FILTER_MODE (SD_CARD * 256 + 0x4D)   /* set the client data mode */
#define CMD_CARD_GET_FILTER_MODE (SD_CARD * 256 + 0x4E)   /* get the client data mode */
#define CMD_CARD_GET_EVNAMES    (SD_CARD * 256 + 0x4f)    /* get event names */
#define CMD_CARD_GET_SPEEDS     (SD_CARD * 256 + 0x50)    /* get speed definitions */

/* SD_SERVER command types: */

#define CMD_SERVER_REG          (SD_SERVER * 256 + 0x50)    /* register connection */
#define CMD_SERVER_SET_SORT     (SD_SERVER * 256 + 0x51)    /* set sorting behavior */
#define CMD_SERVER_SET_OPT      (SD_SERVER * 256 + 0x52)    /* set type of optimization */

/* SD_CLIENT command types: */

#define CMD_CLIENT_GET_ID       (SD_CLIENT * 256 + 0x60)    /* get the ID (channel field) of this client? */
#define CMD_CLIENT_SET_ID       (SD_CLIENT * 256 + 0x61)    /* set the ID (channel field) of this client? */
#define CMD_CLIENT_SHUTDOWN     (SD_CLIENT * 256 + 0x62)    /* tell client to die ? */

/* Bus load monitor (SD_BLM) commands: */

#define CMD_BLM_SET_MODE        (SD_BLM * 256 + 0xA0)
#define CMD_BLM_GET_MODE        (SD_BLM * 256 + 0xA1)
#define CMD_BLM_GET_DATA        (SD_BLM * 256 + 0xA2)
#define CMD_BLM_GET_STATS       (SD_BLM * 256 + 0xA3)

/* SD_LIN command types: */
#define CMD_LDF_DESC            (SD_LIN * 256 + 0xB8) /* */
#define CMD_LDF_UPLOAD          (SD_LIN * 256 + 0xB9) /* */
#define CMD_LDF_LIST            (SD_LIN * 256 + 0xBA) /* */
#define CMD_LDF_DELETE          (SD_LIN * 256 + 0xBB) /* */
#define CMD_LDF_PARSE           (SD_LIN * 256 + 0xBC) /* */
#define CMD_GET_LDF_INFO        (SD_LIN * 256 + 0xBD) /* */
#define CMD_GET_NODE_NAMES      (SD_LIN * 256 + 0xBE) /* */
#define CMD_EMULATE_NODES       (SD_LIN * 256 + 0xBF) /* */
#define CMD_GET_FRAMES          (SD_LIN * 256 + 0xB0) /* */
#define CMD_GET_FRAME_INFO      (SD_LIN * 256 + 0xC1) /* */
#define CMD_GET_SIGNAL_INFO     (SD_LIN * 256 + 0xC2) /* */
#define CMD_GET_SIGNAL_DETAIL   (SD_LIN * 256 + 0xC3) /* */
#define CMD_GET_ENCODING_INFO   (SD_LIN * 256 + 0xC4) /* */
#define CMD_GET_SCHEDULES       (SD_LIN * 256 + 0xC5) /* */
#define CMD_START_SCHEDULE      (SD_LIN * 256 + 0xC6) /* */
#define CMD_STOP_SCHEDULE       (SD_LIN * 256 + 0xC7) /* */
#define CMD_STORE_DATA          (SD_LIN * 256 + 0xC8) /* */
#define CMD_SEND_ID             (SD_LIN * 256 + 0xC9) /* */
#define CMD_SEND_ID_DATA        (SD_LIN * 256 + 0xCA) /* */
#define CMD_SAVE_SESSION        (SD_LIN * 256 + 0xCB) /* */
#define CMD_RESTORE_SESSION     (SD_LIN * 256 + 0xCC) /* */
#define CMD_GET_NODE_SIGNALS    (SD_LIN * 256 + 0xCD) /* */

/* signal conversion (SD_CNVT) commands */

#define CMD_CNVT_GET_VALUES         (SD_CNVT * 256 + 0x78) /* LIN Signal Conversion */
#define CMD_CNVT_GET_UNITS          (SD_CNVT * 256 + 0x79) /* LIN Signal Conversion */
#define CMD_CNVT_SET_VALUES         (SD_CNVT * 256 + 0x7A) /* LIN Signal Conversion */
#define CMD_CNVT_DESTROY_SESSION    (SD_CNVT * 256 + 0x7B) /* LIN Signal Conversion */
#define CMD_CNVT_SAVE_SESSION       (SD_CNVT * 256 + 0xCB) /* LIN Signal Conversion */
#define CMD_CNVT_RESTORE_SESSION    (SD_CNVT * 256 + 0xCC) /* LIN Signal Conversion */
#define CMD_CNVT_GET_NODE_SIGNALS   (SD_CNVT * 256 + 0xCD) /* LIN Signal Conversion */

/* Flight recorder (SD_FLIGHT) commands */

#define CMD_FLIGHT_GET_CONFIG   (SD_FLIGHT * 256 + 0x50)    /* get flight recorder channel info */
#define CMD_FLIGHT_START_MON    (SD_FLIGHT * 256 + 0x51)    /* start flight recorder monitoring */
#define CMD_FLIGHT_STOP_MON     (SD_FLIGHT * 256 + 0x52)    /* stop flight recorder monitoring */

/* Message responder (SD_RESP) commands: */
#define CMD_MSGRESP_ADD         (SD_RESP * 256 + 0xB0)
#define CMD_MSGRESP_GET         (SD_RESP * 256 + 0xB1)
#define CMD_MSGRESP_MODIFY      (SD_RESP * 256 + 0xB2)
#define CMD_MSGRESP_GET_HANDLES (SD_RESP * 256 + 0xB3)

/* Program loader (SD_PGM) commands: */

#define CMD_PGM_DESC            (SD_PGM * 256 + 0x90)    /* Describe a program to to uploaded */
#define CMD_PGM_UPLOAD          (SD_PGM * 256 + 0x91)    /* Upload a program to the Gryphon */
#define CMD_PGM_DELETE          (SD_PGM * 256 + 0x92)    /* Delete an uploaded program */
#define CMD_PGM_LIST            (SD_PGM * 256 + 0x93)    /* Get a list of uploaded programs */
#define CMD_PGM_START           (SD_PGM * 256 + 0x94)    /* Start an uploaded program */
#define CMD_PGM_START2          (SD_CLIENT * 256 + 0x94) /* Start an uploaded program */
#define CMD_PGM_STOP            (SD_PGM * 256 + 0x95)    /* Stop an uploaded program */
#define CMD_PGM_STATUS          (SD_PGM * 256 + 0x96)    /* Get the status of an uploaded program */
#define CMD_PGM_OPTIONS         (SD_PGM * 256 + 0x97)    /* Set the upload options */
#define CMD_PGM_FILES           (SD_PGM * 256 + 0x98)    /* Get a list of files & directories */

/* Scheduler (SD_SCHED) target commands: */

#define CMD_SCHED_TX            (SD_SCHED * 256 + 0x70)    /* schedule transmission list */
#define CMD_SCHED_KILL_TX       (SD_SCHED * 256 + 0x71)    /* stop and destroy job */
#define CMD_SCHED_MSG_REPLACE   (SD_SCHED * 256 + 0x72)    /* replace a scheduled message */

/* USDT (SD_USDT) target commands: */

#define CMD_USDT_IOCTL          (SD_USDT * 256 + 0x47)  /* Register/Unregister with USDT */
#define CMD_USDT_REGISTER       (SD_USDT * 256 + 0xB0)  /* Register/Unregister with USDT */
#define CMD_USDT_SET_FUNCTIONAL (SD_USDT * 256 + 0xB1)  /* Set to use extended addressing*/
#define CMD_USDT_SET_STMIN_MULT (SD_USDT * 256 + 0xB2)  /* */
#define CMD_USDT_SET_STMIN_FC   (SD_USDT * 256 + 0xB3)  /* */
#define CMD_USDT_GET_STMIN_FC   (SD_USDT * 256 + 0xB4)  /* */
#define CMD_USDT_SET_BSMAX_FC   (SD_USDT * 256 + 0xB5)  /* */
#define CMD_USDT_GET_BSMAX_FC   (SD_USDT * 256 + 0xB6)  /* */
#define CMD_USDT_REGISTER_NON_LEGACY    (SD_USDT * 256 + 0xB7)    /* Register/Unregister with USDT */
#define CMD_USDT_SET_STMIN_OVERRIDE     (SD_USDT * 256 + 0xB8)  /* */
#define CMD_USDT_GET_STMIN_OVERRIDE     (SD_USDT * 256 + 0xB9)  /* */
#define CMD_USDT_ACTIVATE_STMIN_OVERRIDE (SD_USDT * 256 + 0xBA)  /* */

/* I/O Power (SD_IOPWR) target commands: */

#define CMD_IOPWR_GETINP        (SD_IOPWR * 256 + 0x40) /*  Read current digital inputs  */
#define CMD_IOPWR_GETLATCH      (SD_IOPWR * 256 + 0x41) /*  Read latched digital inputs  */
#define CMD_IOPWR_CLRLATCH      (SD_IOPWR * 256 + 0x42) /*  Read & clear latched inputs  */
#define CMD_IOPWR_GETOUT        (SD_IOPWR * 256 + 0x43) /*  Read digital outputs         */
#define CMD_IOPWR_SETOUT        (SD_IOPWR * 256 + 0x44) /*  Write digital outputs        */
#define CMD_IOPWR_SETBIT        (SD_IOPWR * 256 + 0x45) /*  Set indicated output bit(s)  */
#define CMD_IOPWR_CLRBIT        (SD_IOPWR * 256 + 0x46) /*  Clear indicated output bit(s)*/
#define CMD_IOPWR_GETPOWER      (SD_IOPWR * 256 + 0x47) /*  Read inputs at power on time */

/* Miscellaneous (SD_UTIL) target commands: */

#define CMD_UTIL_SET_INIT_STRATEGY (SD_UTIL * 256 + 0x90) /* set the initialization strategy  */
#define CMD_UTIL_GET_INIT_STRATEGY (SD_UTIL * 256 + 0x91) /* get the initialization strategy  */

/* response frame (FT_RESP) response field definitions: */

#define RESP_OK                 0x00    /* no error */
#define RESP_UNKNOWN_ERR        0x01    /* unknown error */
#define RESP_UNKNOWN_CMD        0x02    /* unrecognised command */
#define RESP_UNSUPPORTED        0x03    /* unsupported command */
#define RESP_INVAL_CHAN         0x04    /* invalid channel specified */
#define RESP_INVAL_DST          0x05    /* invalid destination */
#define RESP_INVAL_PARAM        0x06    /* invalid parameters */
#define RESP_INVAL_MSG          0x07    /* invalid message */
#define RESP_INVAL_LEN          0x08    /* invalid length field */
#define RESP_TX_FAIL            0x09    /* transmit failed */
#define RESP_RX_FAIL            0x0a    /* receive failed */
#define RESP_AUTH_FAIL          0x0b
#define RESP_MEM_ALLOC_ERR      0x0c    /* memory allocation error */
#define RESP_TIMEOUT            0x0d    /* command timed out */
#define RESP_UNAVAILABLE        0x0e
#define RESP_BUF_FULL           0x0f    /* buffer full */
#define RESP_NO_SUCH_JOB        0x10

/* Flight recorder (SD_FLIGHT) target definitions */

#define FR_RESP_AFTER_EVENT         0
#define FR_RESP_AFTER_PERIOD        1
#define FR_IGNORE_DURING_PER        2
#define FR_DEACT_AFTER_PER          0x80
#define FR_DEACT_ON_EVENT           0x40
#define FR_DELETE                   0x20
#define FR_PERIOD_MSGS              0x10

/* Filter data types */

#define FILTER_DATA_TYPE_HEADER_FRAME   0x00
#define FILTER_DATA_TYPE_HEADER         0x01
#define FILTER_DATA_TYPE_DATA           0x02
#define FILTER_DATA_TYPE_EXTRA_DATA     0x03
#define FILTER_EVENT_TYPE_HEADER        0x04
#define FILTER_EVENT_TYPE_DATA          0x05

/* filter flags */

#define FILTER_PASS_FLAG            0x01
#define FILTER_ACTIVE_FLAG          0x02

/* Filter and Frame Responder Condition operators */

#define BIT_FIELD_CHECK         0
#define SVALUE_GT               1
#define SVALUE_GE               2
#define SVALUE_LT               3
#define SVALUE_LE               4
#define VALUE_EQ                5
#define VALUE_NE                6
#define UVALUE_GT               7
#define UVALUE_GE               8
#define UVALUE_LT               9
#define UVALUE_LE               10
#define DIG_LOW_TO_HIGH         11
#define DIG_HIGH_TO_LOW         12
#define DIG_TRANSITION          13

/* Modes available via CMD_CARD_SET_FILTERING_MODE */
#define FILTER_OFF_PASS_ALL     3
#define FILTER_OFF_BLOCK_ALL    4
#define FILTER_ON               5

/* Modes available via CMD_CARD_SET_DEFAULT_FILTER */
#define DEFAULT_FILTER_BLOCK    0
#define DEFAULT_FILTER_PASS     1

/* Actions available via CMD_CARD_MODIFY_FILTER */
#define DELETE_FILTER           0
#define ACTIVATE_FILTER         1
#define DEACTIVATE_FILTER       2

/* Flags to modify how FT_CMD (command) messages are handled            */
/* These values are ORed with FT_CMD and stored in the Frame Header's    */
/* Frame Type field for each response.                                     */
#define DONT_WAIT_FOR_RESP      0x80
#define WAIT_FOR_PREV_RESP      0x40
#define RESPONSE_FLAGS      (DONT_WAIT_FOR_RESP | WAIT_FOR_PREV_RESP)


/* Program loader options */
#define PGM_CONV            1         /* Type of data conversion to perform   */
#define PGM_TYPE            2         /* Type of file                */
#define PGM_BIN             11         /* Binary, no conversion            */
#define PGM_ASCII           12         /* ASCII, convert CR LF to LF        */
#define PGM_PGM             21         /* Executable                */
#define PGM_DATA            22         /* Data                    */




/* IOCTL definitions - comments indicate data size */

#define GINIT           0x11100001
#define GLOOPON         0x11100002
#define GLOOPOFF        0x11100003
#define GGETHWTYPE      0x11100004
#define GGETREG         0x11100005
#define GSETREG         0x11100006
#define GGETRXCOUNT     0x11100007
#define GSETRXCOUNT     0x11100008
#define GGETTXCOUNT     0x11100009
#define GSETTXCOUNT     0x1110000a
#define GGETRXDROP      0x1110000b
#define GSETRXDROP      0x1110000c
#define GGETTXDROP      0x1110000d
#define GSETTXDROP      0x1110000e
#define GGETRXBAD       0x1110000f
#define GGETTXBAD       0x11100011
#define GGETCOUNTS      0x11100013
#define GGETBLMON       0x11100014
#define GSETBLMON       0x11100015
#define GGETERRLEV      0x11100016
#define GSETERRLEV      0x11100017
#define GGETBITRATE     0x11100018
#define GGETRAM         0x11100019
#define GSETRAM         0x1110001a

#define GCANGETBTRS     0x11200001
#define GCANSETBTRS     0x11200002
#define GCANGETBC       0x11200003
#define GCANSETBC       0x11200004
#define GCANGETMODE     0x11200005
#define GCANSETMODE     0x11200006
#define GCANGETTRANS    0x11200009
#define GCANSETTRANS    0x1120000a
#define GCANSENDERR     0x1120000b
#define GCANRGETOBJ     0x11210001
#define GCANRSETSTDID   0x11210002
#define GCANRSETEXTID   0x11210003
#define GCANRSETDATA    0x11210004
#define GCANRENABLE     0x11210005
#define GCANRDISABLE    0x11210006
#define GCANRGETMASKS   0x11210007
#define GCANRSETMASKS   0x11210008
#define GCANSWGETMODE   0x11220001
#define GCANSWSETMODE   0x11220002

#define GDLCGETFOURX    0x11400001
#define GDLCSETFOURX    0x11400002
#define GDLCGETLOAD     0x11400003
#define GDLCSETLOAD     0x11400004
#define GDLCSENDBREAK   0x11400005
#define GDLCABORTTX     0x11400006
#define GDLCGETHDRMODE  0x11400007
#define GDLCSETHDRMODE  0x11400008

#define GHONSLEEP       0x11600001
#define GHONSILENCE     0x11600002

#define GKWPSETPTIMES   0x11700011
#define GKWPSETWTIMES   0x11700010
#define GKWPDOWAKEUP    0x11700008
#define GKWPGETBITTIME  0x11700101
#define GKWPSETBITTIME  0x11700102
#define GKWPSETNODEADDR 0x11700104
#define GKWPGETNODETYPE 0x11700105
#define GKWPSETNODETYPE 0x11700106
#define GKWPSETWAKETYPE 0x11700108
#define GKWPSETTARGADDR 0x1170010a
#define GKWPSETKEYBYTES 0x1170010c
#define GKWPSETSTARTREQ 0x1170010e
#define GKWPSETSTARTRESP 0x11700110
#define GKWPSETPROTOCOL 0x11700112
#define GKWPGETLASTKEYBYTES 0x11700201
#define GKWPSETLASTKEYBYTES 0x11700202

#define GSCPGETBBR      0x11300001
#define GSCPSETBBR      0x11300002
#define GSCPGETID       0x11300003
#define GSCPSETID       0x11300004
#define GSCPADDFUNCID   0x11300005
#define GSCPCLRFUNCID   0x11300006

#define GUBPGETBITRATE      0x11800001
#define GUBPSETBITRATE      0x11800002
#define GUBPGETINTERBYTE    0x11800003
#define GUBPSETINTERBYTE    0x11800004
#define GUBPGETNACKMODE     0x11800005
#define GUBPSETNACKMODE     0x11800006
#define GUBPGETRETRYDELAY   0x11800007
#define GUBPSETRETRYDELAY   0x11800008

#define GRESETHC08          0x11800009
#define GTESTHC08COP        0x1180000A

#define GSJAGETLISTEN           0x11250001
#define GSJASETLISTEN           0x11250002
#define GSJAGETSELFTEST         0x11250003
#define GSJASETSELFTEST         0x11250004
#define GSJAGETXMITONCE         0x11250005
#define GSJASETXMITONCE         0x11250006
#define GSJAGETTRIGSTATE        0x11250007
#define GSJASETTRIGCTRL         0x11250008
#define GSJAGETTRIGCTRL         0x11250009
#define GSJAGETOUTSTATE         0x1125000A
#define GSJASETOUTSTATE         0x1125000B
#define GSJAGETFILTER           0x1125000C
#define GSJASETFILTER           0x1125000D
#define GSJAGETMASK             0x1125000E
#define GSJASETMASK             0x1125000F
#define GSJAGETINTTERM          0x11250010
#define GSJASETINTTERM          0x11250011
#define GSJAGETFTTRANS          0x11250012
#define GSJASETFTTRANS          0x11250013
#define GSJAGETFTERROR          0x11250014

/* LIN driver IOCTLs */
#define GLINGETBITRATE          0x11C00001
#define GLINSETBITRATE          0x11C00002
#define GLINGETBRKSPACE         0x11C00003
#define GLINSETBRKSPACE         0x11C00004
#define GLINGETBRKMARK          0x11C00005
#define GLINSETBRKMARK          0x11C00006
#define GLINGETIDDELAY          0x11C00007
#define GLINSETIDDELAY          0x11C00008
#define GLINGETRESPDELAY        0x11C00009
#define GLINSETRESPDELAY        0x11C0000A
#define GLINGETINTERBYTE        0x11C0000B
#define GLINSETINTERBYTE        0x11C0000C
#define GLINGETWAKEUPDELAY      0x11C0000D
#define GLINSETWAKEUPDELAY      0x11C0000E
#define GLINGETWAKEUPTIMEOUT    0x11C0000F
#define GLINSETWAKEUPTIMEOUT    0x11C00010
#define GLINGETWUTIMOUT3BR      0x11C00011
#define GLINSETWUTIMOUT3BR      0x11C00012
#define GLINSENDWAKEUP          0x11C00013
#define GLINGETMODE             0x11C00014
#define GLINSETMODE             0x11C00015
#define GLINGETSLEW             0x11C00016
#define GLINSETSLEW             0x11C00017
#define GLINADDSCHED            0x11C00018
#define GLINGETSCHED            0x11C00019
#define GLINGETSCHEDSIZE        0x11C0001A
#define GLINDELSCHED            0x11C0001B
#define GLINACTSCHED            0x11C0001C
#define GLINDEACTSCHED          0x11C0001D
#define GLINGETACTSCHED         0x11C0001E
#define GLINGETNUMSCHEDS        0x11C0001F
#define GLINGETSCHEDNAMES       0x11C00020
#define GLINSETFLAGS            0x11C00021
#define GLINGETAUTOCHECKSUM     0x11C00022
#define GLINSETAUTOCHECKSUM     0x11C00023
#define GLINGETAUTOPARITY       0x11C00024
#define GLINSETAUTOPARITY       0x11C00025
#define GLINGETSLAVETABLEENABLE 0x11C00026
#define GLINSETSLAVETABLEENABLE 0x11C00027
#define GLINGETFLAGS            0x11C00028
#define GLINGETWAKEUPMODE       0x11C00029
#define GLINSETWAKEUPMODE       0x11C0002A
#define GLINGETMASTEREVENTENABLE 0x11C0002B     /* 1 */
#define GLINSETMASTEREVENTENABLE 0x11C0002C     /* 1 */
#define GLINGETNSLAVETABLE      0x11C0002D      /* 1 get number of slave table entries */
#define GLINGETSLAVETABLEPIDS   0x11C0002E      /* 1 + n get list of slave table PIDs */
#define GLINGETSLAVETABLE       0x11C0002F      /* var., 4 + n */
#define GLINSETSLAVETABLE       0x11C00030      /* var., 4 + n */
#define GLINCLEARSLAVETABLE     0x11C00031      /* 1 */
#define GLINCLEARALLSLAVETABLE  0x11C00032      /* 0 */
#define GLINGETONESHOT          0x11C00033      /* var., 4 + n */
#define GLINSETONESHOT          0x11C00034      /* var., 4 + n */
#define GLINCLEARONESHOT        0x11C00035      /* 0 */

/* delay driver (real-time scheduler) IOCTLs */
#define GDLYGETHIVALUE  0x11D50001      /* 4 */
#define GDLYSETHIVALUE  0x11D50002      /* 4 set the high water value       */
                                        /*  2 bytes - stream number         */
                                        /*  2 bytes - high water value      */

#define GDLYGETLOVALUE  0x11D50003      /* 4 */
#define GDLYSETLOVALUE  0x11D50004      /* 4 set the low water value        */
                                        /*  2 bytes - stream number         */
                                        /*  2 bytes - low water value       */

#define GDLYGETHITIME   0x11D50005      /* 4 */
#define GDLYSETHITIME   0x11D50006      /* 4 set the high water time        */
                                        /*  2 bytes - stream number         */
                                        /*  2 bytes - high water time (ms)  */

#define GDLYGETLOTIME   0x11D50007      /* 4 */
#define GDLYSETLOTIME   0x11D50008      /* 4 set the low water time         */
                                        /*  2 bytes - stream number         */
                                        /*  2 bytes - low water time (ms)   */

#define GDLYGETLOREPORT 0x11D50009      /* 4 get the low water report flag  */
                                        /*  2 bytes - stream number         */
                                        /*  2 bytes - 1: report when low    */
                                        /*            0: do not report when low*/

#define GDLYFLUSHSTREAM 0x11D5000A      /* 2 flush the delay buffer         */
                                        /*  2 bytes - stream number         */

#define GDLYINITSTREAM  0x11D5000B      /* 2 set default hi & lo water marks*/
                                        /*  2 bytes - stream number         */

#define GDLYPARTIALFLUSHSTREAM 0x11D5000C /* 4 flush the delay buffer       */
                                        /*  2 bytes - stream number         */
                                        /*  2 bytes - data to retain in ms  */


#define GINPGETINP              0x11500001
#define GINPGETLATCH            0x11500002
#define GINPCLRLATCH            0x11500003
#define GOUTGET                 0x11510001
#define GOUTSET                 0x11510002
#define GOUTSETBIT              0x11510003
#define GOUTCLEARBIT            0x11510004
#define GPWRGETWHICH            0x11520001
#define GPWROFF                 0x11520002
#define GPWROFFRESET            0x11520003
#define GPWRRESET            0x11520004


/* Hardware / driver TYPE and SUBTYPE definitions */

#define GDUMMY          0x01    /* Dummy device driver TYPE */
#define GDGDMARKONE     0x01    /* Dummy device driver SUBTYPE */

#define GCAN            0x02    /* CAN TYPE */
#define G82527          0x01    /* 82527 SUBTYPE */
#define GSJA1000        0x02    /* SJA1000 SUBTYPE */
#define G82527SW        0x03    /* 82527 single wire subtype */
#define G82527ISO11992  0x04    /* 82527 ISO11992 subtype */
#define G82527_SINGLECHAN 0x05  /* 82527 single channel */
#define G82527SW_SINGLECHAN 0x06 /* 82527 single wire single channel */
#define G82527ISO11992_SINGLECHAN 0x07 /* 82527 ISO11992 single channel */
#define GSJA1000FT      0x10    /* SJA1000 Fault Tolerant subtype */
#define GSJA1000C       0x11    /* SJA1000 Compact subtype */
#define GSJA1000FT_FO   0x12    /* SJA1000 single chsnnel Fault Tolerant subtype */
#define GSJA1000_BEACON_CANFD 0x1a /* SJA1000 BEACON CAN-FD subtype */
#define GSJA1000_BEACON_SW    0x1b /* SJA1000 BEACON CAN single wire subtype */
#define GSJA1000_BEACON_FT    0x1c /* SJA1000 BEACON CAN Fault Tolerant subtype */

#define GJ1850          0x03    /* 1850 TYPE */
#define GHBCCPAIR       0x01    /* HBCC SUBTYPE */
#define GDLC            0x02    /* GM DLC SUBTYPE */
#define GCHRYSLER       0x03    /* Chrysler SUBTYPE */
#define GDEHC12         0x04    /* DE HC12 KWP/BDLC SUBTYPE */

#define GKWP2000        0x04    /* Keyword protocol 2000 TYPE */
#define GDEHC12KWP      0x01    /* DE HC12 KWP/BDLC card SUBTYPE */

#define GHONDA          0x05    /* Honda UART TYPE */
#define GDGHC08         0x01    /* DG HC08 SUBTYPE */

#define GFORDUBP        0x06    /* FORD UBP TYPE */
#define GDGUBP08        0x01    /* DG HC08 SUBTYPE */

#define GSCI            0x09    /* Chrysler SCI TYPE */
#define G16550SCI       0x01    /* 16550 type UART based card SUBTYPE */

#define GCCD            0x0a    /* Chrysler C2D TYPE */
#define G16550CDP68HC68 0x01    /* 16550 / CDP68HC68S1 card SUBTYPE */

#define GLIN            0x0b    /* LIN TYPE */
#define GDGLIN08        0x01    /* DG HC08 SUBTYPE */
#define GDGLIN_BEACON   0x03    /* DG BEACON LIN SUBTYPE */

typedef struct {
    guint32 cmd;
    guint32 cmd_context;    //typically just guint8, but let's room for expansion/improvement
    guint32 ioctl_command;  //should be more generic, but IOCTL is currently the only user
    guint32 req_frame_num;
    guint32 rsp_frame_num;
    nstime_t req_time;
} gryphon_pkt_info_t;

/* List contains request data  */
typedef struct {
    wmem_list_t *request_frame_data;
} gryphon_conversation;


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
