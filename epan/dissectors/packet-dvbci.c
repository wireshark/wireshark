/* packet-dvbci.c
 * Routines for DVB-CI (Common Interface) dissection
 * Copyright 2011-2012, Martin Kaiser <martin@kaiser.cx>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* This dissector supports DVB-CI as defined in EN50221 and
 * CI+ (www.ci-plus.com).
 * For more details, see http://wiki.wireshark.org/DVB-CI.
 *
 * The pcap input format for this dissector is documented at
 * http://www.kaiser.cx/pcap-dvbci.html.
 */

#include "config.h"

#include <glib.h>
#include <epan/addr_resolv.h>
#include <epan/circuit.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/asn1.h>
#include <epan/dissectors/packet-mpeg-descriptor.h>
#include <epan/dissectors/packet-x509af.h>
#include <epan/dissectors/packet-x509ce.h>

#include "packet-ber.h"

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif


#define AES_BLOCK_LEN 16
#define AES_KEY_LEN 16

/* event byte in the pseudo-header */
#define DATA_CAM_TO_HOST  0xFF
#define DATA_HOST_TO_CAM  0xFE
#define CIS_READ          0xFD
#define COR_WRITE         0xFC
#define HW_EVT            0xFB

#define IS_DATA_TRANSFER(e) (e==DATA_CAM_TO_HOST || e==DATA_HOST_TO_CAM)

/* for [as]pdu_info_t when the message is allowed in either direction */
#define DIRECTION_ANY 0x0

/* source/destination address field */
#define ADDR_HOST "Host"
#define ADDR_CAM  "CAM"

/* hardware event */
#define CAM_IN    0x01
#define CAM_OUT   0x02
#define POWER_ON  0x03
#define POWER_OFF 0x04
#define TS_ROUTE  0x05
#define TS_BYPASS 0x06
#define RESET_H   0x07
#define RESET_L   0x08
#define READY_H   0x09
#define READY_L   0x0A

/* Card Information Structure (CIS) */

/* tuples */
#define CISTPL_NO_LINK       0x14
#define CISTPL_VERS_1        0x15
#define CISTPL_CONFIG        0x1A
#define CISTPL_CFTABLE_ENTRY 0x1B
#define CISTPL_DEVICE_OC     0x1C
#define CISTPL_DEVICE_OA     0x1D
#define CISTPL_MANFID        0x20
#define CISTPL_END           0xFF
/* subtuple */
#define CCSTPL_CIF           0xC0
/* interface types */
#define TPCE_IF_TYPE_MEM     0
#define TPCE_IF_TYPE_IO_MEM  1
#define TPCE_IF_TYPE_CUST0   4
#define TPCE_IF_TYPE_CUST1   5
#define TPCE_IF_TYPE_CUST2   6
#define TPCE_IF_TYPE_CUST3   7

/* link layer */
#define ML_MORE 0x80
#define ML_LAST 0x00

/* sequence id for reassembly of fragmented lpdus
   this can be an arbitrary constant value since lpdus must arrive in order */
#define SEQ_ID_LINK_LAYER  4
/* the same goes for the transport layer */
#define SEQ_ID_TRANSPORT_LAYER  7

/* transport layer */
#define NO_TAG        0x00
#define T_SB          0x80
#define T_RCV         0x81
#define T_CREATE_T_C  0x82
#define T_C_T_C_REPLY 0x83
#define T_DELETE_T_C  0x84
#define T_D_T_C_REPLY 0x85
#define T_REQUEST_T_C 0x86
#define T_NEW_T_C     0x87
#define T_T_C_ERROR   0x88
#define T_DATA_LAST   0xA0
#define T_DATA_MORE   0xA1

#define SB_VAL_MSG_AVAILABLE    0x80
#define SB_VAL_NO_MSG_AVAILABLE 0x00

/* session layer */
#define T_SESSION_NUMBER          0x90
#define T_OPEN_SESSION_REQUEST    0x91
#define T_OPEN_SESSION_RESPONSE   0x92
#define T_CREATE_SESSION          0x93
#define T_CREATE_SESSION_RESPONSE 0x94
#define T_CLOSE_SESSION_REQUEST   0x95
#define T_CLOSE_SESSION_RESPONSE  0x96

/* status for open/create session */
#define SESS_OPENED                   0x00
#define SESS_NOT_OPENED_RES_NON_EXIST 0xF0
#define SESS_NOT_OPENED_RES_UNAVAIL   0xF1
#define SESS_NOT_OPENED_RES_VER_LOWER 0xF2
#define SESS_NOT_OPENED_RES_BUSY      0xF3

/* status for close session */
#define SESS_CLOSED       0x00
#define SESS_NB_NOT_ALLOC 0xF0

/* resource id */
#define RES_ID_TYPE_MASK 0xC0000000
#define RES_CLASS_MASK   0x3FFF0000
#define RES_TYPE_MASK    0x0000FFC0
#define RES_VER_MASK     0x0000003F

/* resource class */
#define RES_CLASS_RM  0x01
#define RES_CLASS_AP  0x02
#define RES_CLASS_CA  0x03
#define RES_CLASS_AUT 0x10
#define RES_CLASS_HC  0x20
#define RES_CLASS_DT  0x24
#define RES_CLASS_MMI 0x40
#define RES_CLASS_AMI 0x41
#define RES_CLASS_LSC 0x60
#define RES_CLASS_CC  0x8C
#define RES_CLASS_HLC 0x8D
#define RES_CLASS_CUP 0x8E
#define RES_CLASS_OPP 0x8F
#define RES_CLASS_SAS 0x96

#define RES_ID_LEN 4 /* bytes */
#define RES_CLASS(_res_id) (_res_id & RES_CLASS_MASK) >> 16
#define RES_VER(_res_id)   (_res_id & RES_VER_MASK)

/* appinfo resource */
#define APP_TYPE_CA  0x1
#define APP_TYPE_EPG 0x2

#define DATA_RATE_72 0x0
#define DATA_RATE_96 0x1

/* ca resource */
#define LIST_MGMT_MORE   0x0
#define LIST_MGMT_FIRST  0x1
#define LIST_MGMT_LAST   0x2
#define LIST_MGMT_ONLY   0x3
#define LIST_MGMT_ADD    0x4
#define LIST_MGMT_UPDATE 0x5

#define CMD_ID_OK_DESCR     0x1
#define CMD_ID_OK_MMI       0x2
#define CMD_ID_QUERY        0x3
#define CMD_ID_NOT_SELECTED 0x4

#define CA_DESC_TAG 0x9

#define CA_ENAB_DESC_OK             0x01
#define CA_ENAB_DESC_OK_PURCHASE    0x02
#define CA_ENAB_DESC_OK_TECH        0x03
#define CA_ENAB_DESC_NG_ENTITLEMENT 0x71
#define CA_ENAB_DESC_NG_TECH        0x73

/* host control resource */
#define HC_STAT_OK            0x0
#define HC_STAT_ERR_DLVRY     0x1
#define HC_STAT_ERR_LOCK      0x2
#define HC_STAT_ERR_BUSY      0x3
#define HC_STAT_ERR_PARAM     0x4
#define HC_STAT_ERR_NOT_FOUND 0x5
#define HC_STAT_ERR_UNKNOWN   0x6

#define HC_RELEASE_OK      0x0
#define HC_RELEASE_REFUSED 0x1

/* mmi resource */
#define CLOSE_MMI_CMD_ID_IMMEDIATE 0x0
#define CLOSE_MMI_CMD_ID_DELAY     0x1

/* only commands and parameters for high-level mmi are supported */
#define DISP_CMD_SET_MMI_MODE 1
#define DISP_CMD_GET_DISP_TBL 2
#define DISP_CMD_GET_INP_TBL  3

#define MMI_MODE_HIGH 1

#define DISP_REP_ID_MMI_MODE_ACK     0x01
#define DISP_REP_ID_DISP_CHAR_TBL    0x02
#define DISP_REP_ID_INP_CHAR_TBL     0x03
#define DISP_REP_ID_UNKNOWN_CMD      0xF0
#define DISP_REP_ID_UNKNOWN_MMI_MODE 0xF1
#define DISP_REP_ID_UNKNOWN_CHAR_TBL 0xF2

#define VISIBLE_ANS 0
#define BLIND_ANS   1

#define ANSW_ID_CANCEL 0x00
#define ANSW_ID_ANSWER 0x01

/* used for answer_text_length, choice_nb and item_nb */
#define NB_UNKNOWN 0xFF

/* character tables, DVB-SI spec annex A.2 */
#define CHAR_TBL_8859_5      0x01
#define CHAR_TBL_8859_6      0x02
#define CHAR_TBL_8859_7      0x03
#define CHAR_TBL_8859_8      0x04
#define CHAR_TBL_8859_9      0x05
#define CHAR_TBL_8859_10     0x06
#define CHAR_TBL_8859_11     0x07
#define CHAR_TBL_8859_13     0x09
#define CHAR_TBL_8859_14     0x0A
#define CHAR_TBL_8859_15     0x0B
#define CHAR_TBL_MULTI_BYTE  0x10
#define CHAR_TBL_ENC_TYPE_ID 0x1F

/* control codes for texts, DVB-SI spec annex A.1 */
#define TEXT_CTRL_EMPH_ON   0x86
#define TEXT_CTRL_EMPH_OFF  0x87
#define TEXT_CTRL_CRLF      0x8A


/* cam upgrade resource */
#define CUP_DELAYED   0x0
#define CUP_IMMEDIATE 0x1

#define CUP_ANS_NO  0x0
#define CUP_ANS_YES 0x1
#define CUP_ANS_ASK 0x2

#define CUP_RESET_PCMCIA 0x0
#define CUP_RESET_CMDIF  0x1
#define CUP_RESET_NONE   0x2

/* content control resource */
#define CC_ID_HOST_ID            0x05
#define CC_ID_CICAM_ID           0x06
#define CC_ID_HOST_BRAND_CERT    0x07
#define CC_ID_CICAM_BRAND_CERT   0x08
#define CC_ID_KP                 0x0C
#define CC_ID_DHPH               0x0D
#define CC_ID_DHPM               0x0E
#define CC_ID_HOST_DEV_CERT      0x0F
#define CC_ID_CICAM_DEV_CERT     0x10
#define CC_ID_SIG_A              0x11
#define CC_ID_SIG_B              0x12
#define CC_ID_AUTH_NONCE         0x13
#define CC_ID_NS_HOST            0x14
#define CC_ID_NS_MODULE          0x15
#define CC_ID_AKH                0x16
#define CC_ID_URI                0x19
#define CC_ID_PROG_NUM           0x1A
#define CC_ID_URI_CNF            0x1B
#define CC_ID_KEY_REGISTER       0x1C
#define CC_ID_URI_VERSIONS       0x1D
#define CC_ID_STATUS_FIELD       0x1E
#define CC_ID_SRM_DATA           0x1F
#define CC_ID_SRM_CONFIRM        0x20
#define CC_ID_CICAM_LICENSE      0x21
#define CC_ID_LICENSE_STATUS     0x22
#define CC_ID_LICENSE_RCV_STATUS 0x23
#define CC_ID_OPERATING_MODE     0x26
#define CC_ID_PINCODE_DATA       0x27
#define CC_ID_REC_START_STATUS   0x28
#define CC_ID_MODE_CHG_STATUS    0x29
#define CC_ID_REC_STOP_STATUS    0x2A

#define CC_KEY_EVEN 0x0
#define CC_KEY_ODD  0x1

#define CC_STATUS_OK                    0x0
#define CC_STATUS_NO_CC_SUPPORT         0x1
#define CC_STATUS_HOST_BUSY             0x2
#define CC_STATUS_AUTH_FAILED_OR_NO_SRM 0x3
#define CC_STATUS_CICAM_BUSY            0x4
#define CC_STATUS_REC_MODE_ERR          0x5

#define CC_SAC_AUTH_AES128_XCBC_MAC 0x0
#define CC_SAC_ENC_AES128_CBC       0x0

#define CC_CAP_NONE               0x0
#define CC_CAP_CAS_PIN            0x1
#define CC_CAP_CAS_FTA_PIN        0x2
#define CC_CAP_CAS_PIN_CACHED     0x3
#define CC_CAP_CAS_FTA_PIN_CACHED 0x4

/* length of DVB-SI utc time field in bytes */
#define UTC_TIME_LEN 5

#define CC_PIN_BAD         0x0
#define CC_PIN_CAM_BUSY    0x1
#define CC_PIN_OK          0x2
#define CC_PIN_UNCONFIRMED 0x3
#define CC_PIN_VB_NOT_REQ  0x4
#define CC_PIN_CSA         0x5

#define CC_OP_MODE_WATCH_BUFFER 0x0
#define CC_OP_MODE_TIMESHIFT    0x1
#define CC_OP_MODE_UNATTENDED   0x2

/* application mmi resource */
#define ACK_CODE_OK        0x1
#define ACK_CODE_WRONG_API 0x2
#define ACK_CODE_API_BUSY  0x3

#define REQ_TYPE_FILE      0x0
#define REQ_TYPE_DATA      0x1
#define REQ_TYPE_FILE_HASH 0x2
#define REQ_TYPE_REQ       0x3

/* lsc resource */
#define COMMS_CMD_ID_CONNECT_ON_CHANNEL    1
#define COMMS_CMD_ID_DISCONNECT_ON_CHANNEL 2
#define COMMS_CMD_ID_SET_PARAMS            3
#define COMMS_CMD_ID_ENQUIRE_STATUS        4
#define COMMS_CMD_ID_GET_NEXT_BUFFER       5

#define CONN_DESC_TEL      1
#define CONN_DESC_CABLE    2
#define CONN_DESC_IP       3
#define CONN_DESC_HOSTNAME 4

#define LSC_DESC_IP       0xCF
#define LSC_DESC_HOSTNAME 0xCD

#define LSC_IPV4 1
#define LSC_IPV6 2

#define LSC_TCP 1
#define LSC_UDP 2

#define COMMS_REP_ID_CONNECT_ACK         1
#define COMMS_REP_ID_DISCONNECT_ACK      2
#define COMMS_REP_ID_SET_PARAMS_ACK      3
#define COMMS_REP_ID_STATUS_REPLY        4
#define COMMS_REP_ID_GET_NEXT_BUFFER_ACK 5
#define COMMS_REP_ID_SEND_ACK            6

#define LSC_RET_OK 0
#define LSC_RET_DISCONNECTED 0
#define LSC_RET_CONNECTED    1
#define LSC_RET_TOO_BIG 0xFE

/* operator profile resource */
#define TABLE_ID_CICAM_NIT 0x40  /* CICAM NIT must be a NIT actual */

/* sas resource */
#define SAS_SESS_STATE_CONNECTED 0
#define SAS_SESS_STATE_NOT_FOUND 1
#define SAS_SESS_STATE_DENIED    2


/* application layer */

#define APDU_TAG_SIZE 3

/* "don't care" value for min_len_field and len_field (this can't be 0) */
#define LEN_FIELD_ANY G_MAXUINT32

static GHashTable *apdu_table = NULL;

typedef struct _apdu_info_t {
    guint32 tag;
    /* the minimum length required for this apdu */
    guint32 min_len_field;
    /* if the apdu has a well-known length, we enforce it here
     * (otherwise, we set this to LEN_FIELD_ANY) */
    guint32 len_field;
    guint8 direction;
    guint16 res_class;
    guint8  res_min_ver;
    void (*dissect_payload)(guint32, gint,
            tvbuff_t *, gint, circuit_t *, packet_info *, proto_tree *);
} apdu_info_t;


void proto_reg_handoff_dvbci(void);

static void
dissect_dvbci_payload_rm(guint32 tag, gint len_field,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree);
static void
dissect_dvbci_payload_ap(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree);
static void
dissect_dvbci_payload_ca(guint32 tag, gint len_field,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree);
static void
dissect_dvbci_payload_aut(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo _U_, proto_tree *tree);
static void
dissect_dvbci_payload_hc(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree);
static void
dissect_dvbci_payload_dt(guint32 tag, gint len_field,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree);
static void
dissect_dvbci_payload_mmi(guint32 tag, gint len_field,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree);
static void
dissect_dvbci_payload_hlc(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree);
static void
dissect_dvbci_payload_cup(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree);
static void
dissect_dvbci_payload_cc(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree);
static void
dissect_dvbci_payload_ami(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree);
static void
dissect_dvbci_payload_lsc(guint32 tag, gint len_field,
        tvbuff_t *tvb, gint offset, circuit_t *circuit,
        packet_info *pinfo, proto_tree *tree);
static void
dissect_dvbci_payload_opp(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree);
static void
dissect_dvbci_payload_sas(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit,
        packet_info *pinfo, proto_tree *tree);


/* apdu defines */
#define T_PROFILE_ENQ                   0x9F8010
#define T_PROFILE                       0x9F8011
#define T_PROFILE_CHANGE                0x9F8012
#define T_APP_INFO_ENQ                  0x9F8020
#define T_APP_INFO                      0x9F8021
#define T_ENTER_MENU                    0x9F8022
#define T_REQUEST_CICAM_RESET           0x9F8023
#define T_DATARATE_INFO                 0x9F8024
#define T_CA_INFO_ENQ                   0x9F8030
#define T_CA_INFO                       0x9F8031
#define T_CA_PMT                        0x9F8032
#define T_CA_PMT_REPLY                  0x9F8033
#define T_AUTH_REQ                      0x9F8200
#define T_AUTH_RESP                     0x9F8201
#define T_TUNE                          0x9F8400
#define T_REPLACE                       0x9F8401
#define T_CLEAR_REPLACE                 0x9F8402
#define T_ASK_RELEASE                   0x9F8403
#define T_TUNE_BROADCAST_REQ            0x9F8404
#define T_TUNE_REPLY                    0x9F8405
#define T_ASK_RELEASE_REPLY             0x9F8406
#define T_DATE_TIME_ENQ                 0x9F8440
#define T_DATE_TIME                     0x9F8441
#define T_CLOSE_MMI                     0x9F8800
#define T_DISPLAY_CONTROL               0x9F8801
#define T_DISPLAY_REPLY                 0x9F8802
#define T_ENQ                           0x9F8807
#define T_ANSW                          0x9F8808
#define T_MENU_LAST                     0x9F8809
#define T_MENU_MORE                     0x9F880A
#define T_MENU_ANSW                     0x9F880B
#define T_LIST_LAST                     0x9F880C
#define T_LIST_MORE                     0x9F880D
#define T_HOST_COUNTRY_ENQ              0x9F8100
#define T_HOST_COUNTRY                  0x9F8101
#define T_HOST_LANGUAGE_ENQ             0x9F8110
#define T_HOST_LANGUAGE                 0x9F8111
#define T_CAM_FIRMWARE_UPGRADE          0x9F9D01
#define T_CAM_FIRMWARE_UPGRADE_REPLY    0x9F9D02
#define T_CAM_FIRMWARE_UPGRADE_PROGRESS 0x9F9D03
#define T_CAM_FIRMWARE_UPGRADE_COMPLETE 0x9F9D04
#define T_CC_OPEN_REQ                   0x9F9001
#define T_CC_OPEN_CNF                   0x9F9002
#define T_CC_DATA_REQ                   0x9F9003
#define T_CC_DATA_CNF                   0x9F9004
#define T_CC_SYNC_REQ                   0x9F9005
#define T_CC_SYNC_CNF                   0x9F9006
#define T_CC_SAC_DATA_REQ               0x9F9007
#define T_CC_SAC_DATA_CNF               0x9F9008
#define T_CC_SAC_SYNC_REQ               0x9F9009
#define T_CC_SAC_SYNC_CNF               0x9F9010
#define T_CC_PIN_CAPABILITIES_REQ       0x9F9011
#define T_CC_PIN_CAPABILITIES_REPLY     0x9F9012
#define T_CC_PIN_CMD                    0x9F9013
#define T_CC_PIN_REPLY                  0x9F9014
#define T_CC_PIN_EVENT                  0x9F9015
#define T_CC_PIN_PLAYBACK               0x9F9016
#define T_CC_PIN_MMI_REQ                0x9F9017
#define T_REQUEST_START                 0x9F8000
#define T_REQUEST_START_ACK             0x9F8001
#define T_FILE_REQUEST                  0x9F8002
#define T_FILE_ACKNOWLEDGE              0x9F8003
#define T_APP_ABORT_REQUEST             0x9F8004
#define T_APP_ABORT_ACK                 0x9F8005
#define T_COMMS_CMD                     0x9F8C00
#define T_COMMS_REPLY                   0x9F8C02
#define T_COMMS_SEND_LAST               0x9F8C03
#define T_COMMS_SEND_MORE               0x9F8C04
#define T_COMMS_RCV_LAST                0x9F8C05
#define T_COMMS_RCV_MORE                0x9F8C06
#define T_OPERATOR_STATUS_REQ           0x9F9C00
#define T_OPERATOR_STATUS               0x9F9C01
#define T_OPERATOR_NIT_REQ              0x9F9C02
#define T_OPERATOR_NIT                  0x9F9C03
#define T_OPERATOR_INFO_REQ             0x9F9C04
#define T_OPERATOR_INFO                 0x9F9C05
#define T_OPERATOR_SEARCH_START         0x9F9C06
#define T_OPERATOR_SEARCH_STATUS        0x9F9C07
#define T_OPERATOR_EXIT                 0x9F9C08
#define T_OPERATOR_TUNE                 0x9F9C09
#define T_OPERATOR_TUNE_STATUS          0x9F9C0A
#define T_OPERATOR_ENTITLEMENT_ACK      0x9F9C0B
#define T_OPERATOR_SEARCH_CANCEL        0x9F9C0C
#define T_SAS_CONNECT_RQST              0x9F9A00
#define T_SAS_CONNECT_CNF               0x9F9A01
#define T_SAS_ASYNC_MSG                 0x9F9A07

/* these are no real apdus, they just use the same format */
#define T_TEXT_LAST             0x9F8803
#define T_TEXT_MORE             0x9F8804
#define T_CONNECTION_DESCRIPTOR 0x9F8C01

#define IS_MENU_APDU(t) (t==T_MENU_MORE || t==T_MENU_LAST)


static const apdu_info_t apdu_info[] = {
    {T_PROFILE_ENQ,         0, 0,             DIRECTION_ANY,    RES_CLASS_RM, 1, NULL},
    {T_PROFILE,             0, LEN_FIELD_ANY, DIRECTION_ANY,    RES_CLASS_RM, 1, dissect_dvbci_payload_rm},
    {T_PROFILE_CHANGE,      0, 0,             DIRECTION_ANY,    RES_CLASS_RM, 1, NULL},

    {T_APP_INFO_ENQ,        0, 0,             DATA_HOST_TO_CAM, RES_CLASS_AP, 1, NULL},
    {T_APP_INFO,            6, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_AP, 1, dissect_dvbci_payload_ap},
    {T_ENTER_MENU,          0, 0,             DATA_HOST_TO_CAM, RES_CLASS_AP, 1, NULL},
    {T_REQUEST_CICAM_RESET, 0, 0,             DATA_CAM_TO_HOST, RES_CLASS_AP, 3, NULL},
    {T_DATARATE_INFO,       0, 1,             DATA_HOST_TO_CAM, RES_CLASS_AP, 3, dissect_dvbci_payload_ap},

    {T_CA_INFO_ENQ,         0, 0,             DATA_HOST_TO_CAM, RES_CLASS_CA, 1, NULL},
    {T_CA_INFO,             0, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_CA, 1, dissect_dvbci_payload_ca},
    {T_CA_PMT,              6, LEN_FIELD_ANY, DATA_HOST_TO_CAM, RES_CLASS_CA, 1, dissect_dvbci_payload_ca},
    {T_CA_PMT_REPLY,        8, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_CA, 1, dissect_dvbci_payload_ca},

    {T_AUTH_REQ,            2, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_AUT, 1, dissect_dvbci_payload_aut},
    {T_AUTH_RESP,           2, LEN_FIELD_ANY, DATA_HOST_TO_CAM, RES_CLASS_AUT, 1, dissect_dvbci_payload_aut},

    {T_TUNE,                0, 8,             DATA_CAM_TO_HOST, RES_CLASS_HC, 1, dissect_dvbci_payload_hc},
    {T_REPLACE,             0, 5,             DATA_CAM_TO_HOST, RES_CLASS_HC, 1, dissect_dvbci_payload_hc},
    {T_CLEAR_REPLACE,       0, 1,             DATA_CAM_TO_HOST, RES_CLASS_HC, 1, dissect_dvbci_payload_hc},
    {T_ASK_RELEASE,         0, 0,             DATA_HOST_TO_CAM, RES_CLASS_HC, 1, NULL},
    {T_TUNE_BROADCAST_REQ,  5, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_HC, 2, dissect_dvbci_payload_hc},
    {T_TUNE_REPLY,          1, 1,             DATA_HOST_TO_CAM, RES_CLASS_HC, 2, dissect_dvbci_payload_hc},
    {T_ASK_RELEASE_REPLY,   1, 1,             DATA_CAM_TO_HOST, RES_CLASS_HC, 2, dissect_dvbci_payload_hc},

    {T_DATE_TIME_ENQ,       0, 1,             DATA_CAM_TO_HOST, RES_CLASS_DT, 1, dissect_dvbci_payload_dt},
    {T_DATE_TIME,           5, LEN_FIELD_ANY, DATA_HOST_TO_CAM, RES_CLASS_DT, 1, dissect_dvbci_payload_dt},

    {T_CLOSE_MMI,           1, LEN_FIELD_ANY, DIRECTION_ANY,    RES_CLASS_MMI, 1, dissect_dvbci_payload_mmi},
    {T_DISPLAY_CONTROL,     1, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_MMI, 1, dissect_dvbci_payload_mmi},
    {T_DISPLAY_REPLY,       1, LEN_FIELD_ANY, DATA_HOST_TO_CAM, RES_CLASS_MMI, 1, dissect_dvbci_payload_mmi},
    {T_ENQ,                 2, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_MMI, 1, dissect_dvbci_payload_mmi},
    {T_ANSW,                1, LEN_FIELD_ANY, DATA_HOST_TO_CAM, RES_CLASS_MMI, 1, dissect_dvbci_payload_mmi},
    {T_MENU_LAST,          13, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_MMI, 1, dissect_dvbci_payload_mmi},
    {T_MENU_MORE,          13, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_MMI, 1, dissect_dvbci_payload_mmi},
    {T_MENU_ANSW,           0, 1,             DATA_HOST_TO_CAM, RES_CLASS_MMI, 1, dissect_dvbci_payload_mmi},
    {T_LIST_LAST,          13, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_MMI, 1, dissect_dvbci_payload_mmi},
    {T_LIST_MORE,          13, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_MMI, 1, dissect_dvbci_payload_mmi},

    {T_HOST_COUNTRY_ENQ,    0, 0,             DATA_CAM_TO_HOST, RES_CLASS_HLC, 1, NULL},
    {T_HOST_COUNTRY,        0, 3,             DATA_HOST_TO_CAM, RES_CLASS_HLC, 1, dissect_dvbci_payload_hlc},
    {T_HOST_LANGUAGE_ENQ,   0, 0,             DATA_CAM_TO_HOST, RES_CLASS_HLC, 1, NULL},
    {T_HOST_LANGUAGE,       0, 3,             DATA_HOST_TO_CAM, RES_CLASS_HLC, 1, dissect_dvbci_payload_hlc},

    {T_CAM_FIRMWARE_UPGRADE,          0, 3, DATA_CAM_TO_HOST, RES_CLASS_CUP, 1, dissect_dvbci_payload_cup},
    {T_CAM_FIRMWARE_UPGRADE_REPLY,    0, 1, DATA_HOST_TO_CAM, RES_CLASS_CUP, 1, dissect_dvbci_payload_cup},
    {T_CAM_FIRMWARE_UPGRADE_PROGRESS, 0, 1, DATA_CAM_TO_HOST, RES_CLASS_CUP, 1, dissect_dvbci_payload_cup},
    {T_CAM_FIRMWARE_UPGRADE_COMPLETE, 0, 1, DATA_CAM_TO_HOST, RES_CLASS_CUP, 1, dissect_dvbci_payload_cup},

    {T_CC_OPEN_REQ,                0,  0,             DATA_CAM_TO_HOST, RES_CLASS_CC, 1, NULL},
    {T_CC_OPEN_CNF,                0,  1,             DATA_HOST_TO_CAM, RES_CLASS_CC, 1, dissect_dvbci_payload_cc},
    {T_CC_DATA_REQ,                3,  LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_CC, 1, dissect_dvbci_payload_cc},
    {T_CC_DATA_CNF,                2,  LEN_FIELD_ANY, DATA_HOST_TO_CAM, RES_CLASS_CC, 1, dissect_dvbci_payload_cc},
    {T_CC_SYNC_REQ,                0,  0,             DATA_CAM_TO_HOST, RES_CLASS_CC, 1, NULL},
    {T_CC_SYNC_CNF,                0,  1,             DATA_HOST_TO_CAM, RES_CLASS_CC, 1, dissect_dvbci_payload_cc},
    {T_CC_SAC_DATA_REQ,            8,  LEN_FIELD_ANY, DIRECTION_ANY,    RES_CLASS_CC, 1, dissect_dvbci_payload_cc},
    {T_CC_SAC_DATA_CNF,            8,  LEN_FIELD_ANY, DIRECTION_ANY,    RES_CLASS_CC, 1, dissect_dvbci_payload_cc},
    {T_CC_SAC_SYNC_REQ,            8,  LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_CC, 1, dissect_dvbci_payload_cc},
    {T_CC_SAC_SYNC_CNF,            8,  LEN_FIELD_ANY, DATA_HOST_TO_CAM, RES_CLASS_CC, 1, dissect_dvbci_payload_cc},
    {T_CC_PIN_CAPABILITIES_REQ,    0,  0,             DATA_HOST_TO_CAM, RES_CLASS_CC, 2, NULL},
    {T_CC_PIN_CAPABILITIES_REPLY,  7,  7,             DATA_CAM_TO_HOST, RES_CLASS_CC, 2, dissect_dvbci_payload_cc},
    {T_CC_PIN_CMD,                 1,  LEN_FIELD_ANY, DATA_HOST_TO_CAM, RES_CLASS_CC, 2, dissect_dvbci_payload_cc},
    {T_CC_PIN_REPLY,               1,  1,             DATA_CAM_TO_HOST, RES_CLASS_CC, 2, dissect_dvbci_payload_cc},
    {T_CC_PIN_EVENT,              25, 25,             DATA_CAM_TO_HOST, RES_CLASS_CC, 2, dissect_dvbci_payload_cc},
    {T_CC_PIN_PLAYBACK,           16, 16,             DATA_HOST_TO_CAM, RES_CLASS_CC, 2, dissect_dvbci_payload_cc},
    {T_CC_PIN_MMI_REQ,             1,  LEN_FIELD_ANY, DATA_HOST_TO_CAM, RES_CLASS_CC, 2, dissect_dvbci_payload_cc},

    {T_REQUEST_START,       2, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_AMI, 1, dissect_dvbci_payload_ami},
    {T_REQUEST_START_ACK,   0, 1,             DATA_HOST_TO_CAM, RES_CLASS_AMI, 1, dissect_dvbci_payload_ami},
    {T_FILE_REQUEST,        1, LEN_FIELD_ANY, DATA_HOST_TO_CAM, RES_CLASS_AMI, 1, dissect_dvbci_payload_ami},
    {T_FILE_ACKNOWLEDGE,    2, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_AMI, 1, dissect_dvbci_payload_ami},
    {T_APP_ABORT_REQUEST,   0, LEN_FIELD_ANY, DIRECTION_ANY,    RES_CLASS_AMI, 1, dissect_dvbci_payload_ami},
    {T_APP_ABORT_ACK,       0, LEN_FIELD_ANY, DIRECTION_ANY,    RES_CLASS_AMI, 1, dissect_dvbci_payload_ami},

    {T_COMMS_CMD,           1, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_LSC, 1, dissect_dvbci_payload_lsc},
    {T_COMMS_REPLY,         0, 2,             DATA_HOST_TO_CAM, RES_CLASS_LSC, 1, dissect_dvbci_payload_lsc},
    {T_COMMS_SEND_LAST,     2, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_LSC, 1, dissect_dvbci_payload_lsc},
    {T_COMMS_SEND_MORE,     2, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_LSC, 1, dissect_dvbci_payload_lsc},
    {T_COMMS_RCV_LAST,      2, LEN_FIELD_ANY, DATA_HOST_TO_CAM, RES_CLASS_LSC, 1, dissect_dvbci_payload_lsc},
    {T_COMMS_RCV_MORE,      2, LEN_FIELD_ANY, DATA_HOST_TO_CAM, RES_CLASS_LSC, 1, dissect_dvbci_payload_lsc},

    {T_OPERATOR_STATUS_REQ,       0, 0,             DATA_HOST_TO_CAM, RES_CLASS_OPP, 1, NULL},
    {T_OPERATOR_STATUS,           0, 6,             DATA_CAM_TO_HOST, RES_CLASS_OPP, 1, dissect_dvbci_payload_opp},
    {T_OPERATOR_NIT_REQ,          0, 0,             DATA_HOST_TO_CAM, RES_CLASS_OPP, 1, NULL},
    {T_OPERATOR_NIT,              2, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_OPP, 1, dissect_dvbci_payload_opp},
    {T_OPERATOR_INFO_REQ,         0, 0,             DATA_HOST_TO_CAM, RES_CLASS_OPP, 1, NULL},
    {T_OPERATOR_INFO,             1, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_OPP, 1, dissect_dvbci_payload_opp},
    {T_OPERATOR_SEARCH_START,     3, LEN_FIELD_ANY, DATA_HOST_TO_CAM, RES_CLASS_OPP, 1, dissect_dvbci_payload_opp},
    {T_OPERATOR_SEARCH_STATUS,    0, 6,             DATA_CAM_TO_HOST, RES_CLASS_OPP, 1, dissect_dvbci_payload_opp},
    {T_OPERATOR_EXIT,             0, 0,             DATA_HOST_TO_CAM, RES_CLASS_OPP, 1, NULL},
    {T_OPERATOR_TUNE,             2, LEN_FIELD_ANY, DATA_CAM_TO_HOST, RES_CLASS_OPP, 1, dissect_dvbci_payload_opp},
    {T_OPERATOR_TUNE_STATUS,      5, LEN_FIELD_ANY, DATA_HOST_TO_CAM, RES_CLASS_OPP, 1, dissect_dvbci_payload_opp},
    {T_OPERATOR_ENTITLEMENT_ACK,  0, 0,             DATA_HOST_TO_CAM, RES_CLASS_OPP, 1, NULL},
    {T_OPERATOR_SEARCH_CANCEL,    0, 0,             DATA_HOST_TO_CAM, RES_CLASS_OPP, 1, NULL},

    {T_SAS_CONNECT_RQST,    0, 8,             DATA_HOST_TO_CAM, RES_CLASS_SAS, 1, dissect_dvbci_payload_sas},
    {T_SAS_CONNECT_CNF,     0, 9,             DATA_CAM_TO_HOST, RES_CLASS_SAS, 1, dissect_dvbci_payload_sas},
    {T_SAS_ASYNC_MSG,       3, LEN_FIELD_ANY, DIRECTION_ANY,    RES_CLASS_SAS, 1, dissect_dvbci_payload_sas}
};

static const value_string dvbci_apdu_tag[] = {
    { T_PROFILE_ENQ,                   "Profile enquiry" },
    { T_PROFILE,                       "Profile information" },
    { T_PROFILE_CHANGE,                "Profile change notification" },
    { T_APP_INFO_ENQ,                  "Application info enquiry" },
    { T_APP_INFO,                      "Application info" },
    { T_ENTER_MENU,                    "Enter menu" },
    { T_REQUEST_CICAM_RESET,           "Request CICAM reset" },
    { T_DATARATE_INFO,                 "Datarate info" },
    { T_CA_INFO_ENQ,                   "CA info enquiry" },
    { T_CA_INFO,                       "CA info" },
    { T_CA_PMT,                        "CA PMT" },
    { T_CA_PMT_REPLY,                  "CA PMT reply" },
    { T_AUTH_REQ,                      "Authentication request" },
    { T_AUTH_RESP,                     "Authentication response" },
    { T_TUNE,                          "Tune" },
    { T_REPLACE,                       "Replace" },
    { T_CLEAR_REPLACE,                 "Clear replace" },
    { T_ASK_RELEASE,                   "Ask release" },
    { T_TUNE_BROADCAST_REQ,            "Tune broadcast request" },
    { T_TUNE_REPLY,                    "Tune reply" },
    { T_ASK_RELEASE_REPLY,             "Ask release reply" },
    { T_DATE_TIME_ENQ,                 "Date-Time enquiry" },
    { T_DATE_TIME,                     "Date-Time" },
    { T_CLOSE_MMI,                     "Close MMI" },
    { T_DISPLAY_CONTROL,               "Display control" },
    { T_DISPLAY_REPLY,                 "Display reply" },
    { T_TEXT_LAST,                     "Text last" },
    { T_TEXT_MORE,                     "Text more" },
    { T_ENQ,                           "Enquiry" },
    { T_ANSW,                          "Answer" },
    { T_MENU_LAST,                     "Menu last" },
    { T_MENU_MORE,                     "Menu more" },
    { T_MENU_ANSW,                     "Menu answer" },
    { T_LIST_LAST,                     "List last" },
    { T_LIST_MORE,                     "List more" },
    { T_HOST_COUNTRY_ENQ,              "Host country enquiry" },
    { T_HOST_COUNTRY,                  "Host country" },
    { T_HOST_LANGUAGE_ENQ,             "Host language enquiry" },
    { T_HOST_LANGUAGE,                 "Host language" },
    { T_CAM_FIRMWARE_UPGRADE,          "CAM firmware upgrade" },
    { T_CAM_FIRMWARE_UPGRADE_REPLY,    "CAM firmware upgrade reply" },
    { T_CAM_FIRMWARE_UPGRADE_PROGRESS, "CAM firmware upgrade progress" },
    { T_CAM_FIRMWARE_UPGRADE_COMPLETE, "CAM firmware upgrade complete" },
    { T_CC_OPEN_REQ,                   "CC open request" },
    { T_CC_OPEN_CNF,                   "CC open confirm" },
    { T_CC_DATA_REQ,                   "CC data request" },
    { T_CC_DATA_CNF,                   "CC data confirm" },
    { T_CC_SYNC_REQ,                   "CC sync request" },
    { T_CC_SYNC_CNF,                   "CC sync confirm" },
    { T_CC_SAC_DATA_REQ,               "CC SAC data request" },
    { T_CC_SAC_DATA_CNF,               "CC SAC data confirm" },
    { T_CC_SAC_SYNC_REQ,               "CC SAC sync request" },
    { T_CC_SAC_SYNC_CNF,               "CC SAC sync confirm" },
    { T_CC_PIN_CAPABILITIES_REQ,       "CC PIN capabilities request" },
    { T_CC_PIN_CAPABILITIES_REPLY,     "CC PIN capabilities reply" },
    { T_CC_PIN_CMD,                    "CC PIN command" },
    { T_CC_PIN_REPLY,                  "CC PIN reply" },
    { T_CC_PIN_EVENT,                  "CC PIN event" },
    { T_CC_PIN_PLAYBACK,               "CC PIN playback" },
    { T_CC_PIN_MMI_REQ,                "CC PIN MMI request" },
    { T_REQUEST_START,                 "Request start" },
    { T_REQUEST_START_ACK,             "Request start ack" },
    { T_FILE_REQUEST,                  "File request" },
    { T_FILE_ACKNOWLEDGE,              "File acknowledge" },
    { T_APP_ABORT_REQUEST,             "App abort request" },
    { T_APP_ABORT_ACK,                 "App abort ack" },
    { T_COMMS_CMD,                     "Comms command" },
    { T_COMMS_REPLY,                   "Comms reply" },
    { T_CONNECTION_DESCRIPTOR,         "Connection descriptor" },
    { T_COMMS_SEND_LAST,               "Comms send last" },
    { T_COMMS_SEND_MORE,               "Comms send more" },
    { T_COMMS_RCV_LAST,                "Comms receive last" },
    { T_COMMS_RCV_MORE,                "Comms receive more" },
    { T_OPERATOR_STATUS_REQ,           "Operator status request" },
    { T_OPERATOR_STATUS,               "Operator status" },
    { T_OPERATOR_NIT_REQ,              "Operator NIT request" },
    { T_OPERATOR_NIT,                  "Operator NIT" },
    { T_OPERATOR_INFO_REQ,             "Operator info request" },
    { T_OPERATOR_INFO,                 "Operator info" },
    { T_OPERATOR_SEARCH_START,         "Operator search start" },
    { T_OPERATOR_SEARCH_STATUS,        "Operator search status" },
    { T_OPERATOR_EXIT,                 "Operator exit" },
    { T_OPERATOR_TUNE,                 "Operator tune" },
    { T_OPERATOR_TUNE_STATUS,          "Operator tune status" },
    { T_OPERATOR_ENTITLEMENT_ACK,      "Operator entitlement acknowledge" },
    { T_OPERATOR_SEARCH_CANCEL,        "Operator search cancel" },
    { T_SAS_CONNECT_RQST,              "SAS connect request" },
    { T_SAS_CONNECT_CNF,               "SAS connect confirm" },
    { T_SAS_ASYNC_MSG,                 "SAS async message" },
    { 0, NULL }
};

/* convert a byte that contains two 4bit BCD digits into a decimal value */
#define BCD44_TO_DEC(x)  (((x&0xf0) >> 4) * 10 + (x&0x0f))

static int proto_dvbci = -1;

static const gchar *dvbci_sek = NULL;
static const gchar *dvbci_siv = NULL;
static gboolean dvbci_dissect_lsc_msg = FALSE;

static dissector_handle_t data_handle;
static dissector_handle_t mpeg_pmt_handle;
static dissector_handle_t dvb_nit_handle;
static dissector_table_t tcp_dissector_table;
static dissector_table_t udp_dissector_table;

static gint ett_dvbci = -1;
static gint ett_dvbci_hdr = -1;
static gint ett_dvbci_cis = -1;
static gint ett_dvbci_cis_tpl = -1;
static gint ett_dvbci_cis_subtpl = -1;
static gint ett_dvbci_link = -1;
static gint ett_dvbci_link_frag = -1;
static gint ett_dvbci_link_frags = -1;
static gint ett_dvbci_transport = -1;
static gint ett_dvbci_transport_frag = -1;
static gint ett_dvbci_transport_frags = -1;
static gint ett_dvbci_session = -1;
static gint ett_dvbci_res = -1;
static gint ett_dvbci_application = -1;
static gint ett_dvbci_es = -1;
static gint ett_dvbci_ca_desc = -1;
static gint ett_dvbci_text = -1;
static gint ett_dvbci_cc_item = -1;
static gint ett_dvbci_sac_msg_body = -1;
static gint ett_dvbci_ami_req_types = -1;
static gint ett_dvbci_lsc_conn_desc = -1;
static gint ett_dvbci_opp_cap_loop = -1;


static int hf_dvbci_event = -1;
static int hf_dvbci_hw_event = -1;
static int hf_dvbci_cor_addr = -1;
static int hf_dvbci_cor_val = -1;
static int hf_dvbci_cis_tpl_code = -1;
static int hf_dvbci_cis_tpl_len = -1;
static int hf_dvbci_cis_tpl_data = -1;
static int hf_dvbci_cis_tpll_v1_major = -1;
static int hf_dvbci_cis_tpll_v1_minor = -1;
static int hf_dvbci_cis_tpll_v1_info_manuf = -1;
static int hf_dvbci_cis_tpll_v1_info_name = -1;
static int hf_dvbci_cis_tpll_v1_info_additional = -1;
static int hf_dvbci_cis_tpll_v1_end = -1;
static int hf_dvbci_cis_tpcc_rfsz = -1;
static int hf_dvbci_cis_tpcc_rmsz = -1;
static int hf_dvbci_cis_tpcc_rasz = -1;
static int hf_dvbci_cis_tpcc_last = -1;
static int hf_dvbci_cis_tpcc_radr = -1;
static int hf_dvbci_cis_tpcc_rmsk = -1;
static int hf_dvbci_cis_st_code = -1;
static int hf_dvbci_cis_st_len = -1;
static int hf_dvbci_cis_stci_ifn_size = -1;
static int hf_dvbci_cis_stci_ifn = -1;
static int hf_dvbci_cis_stci_str = -1;
static int hf_dvbci_cis_tpce_indx_intface = -1;
static int hf_dvbci_cis_tpce_indx_default = -1;
static int hf_dvbci_cis_tpce_indx_cnf_entry = -1;
static int hf_dvbci_cis_tpce_if_type = -1;
static int hf_dvbci_cis_tpce_fs_mem_space = -1;
static int hf_dvbci_cis_tpce_fs_irq = -1;
static int hf_dvbci_cis_tpce_fs_io = -1;
static int hf_dvbci_cis_tplmid_manf = -1;
static int hf_dvbci_cis_tplmid_card = -1;
static int hf_dvbci_buf_size = -1;
static int hf_dvbci_tcid = -1;
static int hf_dvbci_ml = -1;
static int hf_dvbci_l_frags = -1;
static int hf_dvbci_l_frag = -1;
static int hf_dvbci_l_frag_overlap = -1;
static int hf_dvbci_l_frag_overlap_conflicts = -1;
static int hf_dvbci_l_frag_multiple_tails = -1;
static int hf_dvbci_l_frag_too_long_frag = -1;
static int hf_dvbci_l_frag_err = -1;
static int hf_dvbci_l_frag_cnt = -1;
static int hf_dvbci_l_reass_in = -1;
static int hf_dvbci_l_reass_len = -1;
static int hf_dvbci_c_tpdu_tag = -1;
static int hf_dvbci_r_tpdu_tag = -1;
static int hf_dvbci_t_c_id = -1;
static int hf_dvbci_sb_value = -1;
static int hf_dvbci_t_frags = -1;
static int hf_dvbci_t_frag = -1;
static int hf_dvbci_t_frag_overlap = -1;
static int hf_dvbci_t_frag_overlap_conflicts = -1;
static int hf_dvbci_t_frag_multiple_tails = -1;
static int hf_dvbci_t_frag_too_long_frag = -1;
static int hf_dvbci_t_frag_err = -1;
static int hf_dvbci_t_frag_cnt = -1;
static int hf_dvbci_t_reass_in = -1;
static int hf_dvbci_t_reass_len = -1;
static int hf_dvbci_spdu_tag = -1;
static int hf_dvbci_sess_status = -1;
static int hf_dvbci_sess_nb = -1;
static int hf_dvbci_close_sess_status = -1;
static int hf_dvbci_res_id_type = -1;
static int hf_dvbci_res_class = -1;
static int hf_dvbci_res_type = -1;
static int hf_dvbci_res_ver = -1;
static int hf_dvbci_apdu_tag = -1;
static int hf_dvbci_app_type = -1;
static int hf_dvbci_app_manf = -1;
static int hf_dvbci_manf_code = -1;
static int hf_dvbci_menu_str_len = -1;
static int hf_dvbci_data_rate = -1;
static int hf_dvbci_ca_sys_id = -1;
static int hf_dvbci_ca_pmt_list_mgmt = -1;
static int hf_dvbci_prog_num = -1;
static int hf_dvbci_prog_info_len = -1;
static int hf_dvbci_stream_type = -1;
static int hf_dvbci_es_pid = -1;
static int hf_dvbci_es_info_len = -1;
static int hf_dvbci_ca_pmt_cmd_id = -1;
static int hf_dvbci_descr_len = -1;
static int hf_dvbci_ca_pid = -1;
static int hf_dvbci_ca_enable_flag = -1;
static int hf_dvbci_ca_enable = -1;
static int hf_dvbci_auth_proto_id = -1;
static int hf_dvbci_auth_req_bytes = -1;
static int hf_dvbci_auth_resp_bytes = -1;
static int hf_dvbci_network_id = -1;
static int hf_dvbci_original_network_id = -1;
static int hf_dvbci_transport_stream_id = -1;
static int hf_dvbci_service_id = -1;
static int hf_dvbci_replacement_ref = -1;
static int hf_dvbci_replaced_pid = -1;
static int hf_dvbci_replacement_pid = -1;
static int hf_dvbci_pmt_flag = -1;
static int hf_dvbci_hc_desc_loop_len = -1;
static int hf_dvbci_hc_status = -1;
static int hf_dvbci_hc_release_reply = -1;
static int hf_dvbci_resp_intv = -1;
static int hf_dvbci_utc_time = -1;
static int hf_dvbci_local_offset = -1;
static int hf_dvbci_close_mmi_cmd_id = -1;
static int hf_dvbci_close_mmi_delay = -1;
static int hf_dvbci_disp_ctl_cmd = -1;
static int hf_dvbci_mmi_mode = -1;
static int hf_dvbci_disp_rep_id = -1;
static int hf_dvbci_char_tbl = -1;
static int hf_dvbci_blind_ans = -1;
static int hf_dvbci_ans_txt_len = -1;
static int hf_dvbci_text_ctrl = -1;
static int hf_dvbci_ans_id = -1;
static int hf_dvbci_choice_nb = -1;
static int hf_dvbci_choice_ref = -1;
static int hf_dvbci_item_nb = -1;
static int hf_dvbci_host_country = -1;
static int hf_dvbci_host_language = -1;
static int hf_dvbci_cup_type = -1;
static int hf_dvbci_cup_download_time = -1;
static int hf_dvbci_cup_answer = -1;
static int hf_dvbci_cup_progress = -1;
static int hf_dvbci_cup_reset = -1;
static int hf_dvbci_cc_sys_id_bitmask = -1;
static int hf_dvbci_cc_dat_id = -1;
static int hf_dvbci_brand_cert = -1;
static int hf_dvbci_dev_cert = -1;
static int hf_dvbci_uri_ver = -1;
static int hf_dvbci_uri_aps = -1;
static int hf_dvbci_uri_emi = -1;
static int hf_dvbci_uri_ict = -1;
static int hf_dvbci_uri_rct = -1;
static int hf_dvbci_cc_key_register = -1;
static int hf_dvbci_cc_status_field = -1;
static int hf_dvbci_cc_op_mode = -1;
static int hf_dvbci_cc_data = -1;
static int hf_dvbci_sac_msg_ctr = -1;
static int hf_dvbci_sac_proto_ver = -1;
static int hf_dvbci_sac_auth_cip = -1;
static int hf_dvbci_sac_payload_enc = -1;
static int hf_dvbci_sac_enc_cip = -1;
static int hf_dvbci_sac_payload_len = -1;
static int hf_dvbci_sac_enc_body = -1;
static int hf_dvbci_sac_signature = -1;
static int hf_dvbci_rating = -1;
static int hf_dvbci_capability_field = -1;
static int hf_dvbci_pin_chg_time = -1;
static int hf_dvbci_pincode_status = -1;
static int hf_dvbci_cc_prog_num = -1;
static int hf_dvbci_pin_evt_time = -1;
static int hf_dvbci_pin_evt_cent = -1;
static int hf_dvbci_cc_priv_data = -1;
static int hf_dvbci_pincode = -1;
static int hf_dvbci_app_dom_id = -1;
static int hf_dvbci_init_obj = -1;
static int hf_dvbci_ack_code = -1;
static int hf_dvbci_req_type = -1;
static int hf_dvbci_file_hash = -1;
static int hf_dvbci_file_name = -1;
static int hf_dvbci_ami_priv_data = -1;
static int hf_dvbci_req_ok = -1;
static int hf_dvbci_file_ok = -1;
static int hf_dvbci_file_data = -1;
static int hf_dvbci_abort_req_code = -1;
static int hf_dvbci_abort_ack_code = -1;
static int hf_dvbci_phase_id = -1;
static int hf_dvbci_comms_rep_id = -1;
static int hf_dvbci_lsc_buf_size = -1;
static int hf_dvbci_lsc_ret_val = -1;
static int hf_dvbci_comms_cmd_id = -1;
static int hf_dvbci_conn_desc_type = -1;
static int hf_dvbci_lsc_media_tag = -1;
static int hf_dvbci_lsc_media_len = -1;
static int hf_dvbci_lsc_ip_ver = -1;
static int hf_dvbci_lsc_ipv4_addr = -1;
static int hf_dvbci_lsc_ipv6_addr = -1;
static int hf_dvbci_lsc_dst_port = -1;
static int hf_dvbci_lsc_proto = -1;
static int hf_dvbci_lsc_hostname = -1;
static int hf_dvbci_lsc_retry_count = -1;
static int hf_dvbci_lsc_timeout = -1;
static int hf_dvbci_info_ver_op_status = -1;
static int hf_dvbci_nit_ver = -1;
static int hf_dvbci_pro_typ = -1;
static int hf_dvbci_init_flag = -1;
static int hf_dvbci_ent_chg_flag = -1;
static int hf_dvbci_ent_val_flag = -1;
static int hf_dvbci_ref_req_flag = -1;
static int hf_dvbci_err_flag = -1;
static int hf_dvbci_dlv_sys_hint = -1;
static int hf_dvbci_refr_req_date = -1;
static int hf_dvbci_refr_req_time = -1;
static int hf_dvbci_nit_loop_len = -1;
static int hf_dvbci_info_valid = -1;
static int hf_dvbci_info_ver_op_info = -1;
static int hf_dvbci_cicam_onid = -1;
static int hf_dvbci_cicam_id = -1;
static int hf_dvbci_opp_char_tbl_multi = -1;
static int hf_dvbci_opp_char_tbl = -1;
static int hf_dvbci_enc_type_id = -1;
static int hf_dvbci_sdt_rst_trusted = -1;
static int hf_dvbci_eit_rst_trusted = -1;
static int hf_dvbci_eit_pf_usage = -1;
static int hf_dvbci_eit_sch_usage = -1;
static int hf_dvbci_ext_evt_usage = -1;
static int hf_dvbci_sdt_oth_trusted = -1;
static int hf_dvbci_eit_evt_trigger = -1;
static int hf_dvbci_opp_lang_code = -1;
static int hf_dvbci_prof_name = -1;
static int hf_dvbci_unattended = -1;
static int hf_dvbci_opp_srv_type = -1;
static int hf_dvbci_dlv_cap_byte = -1;
static int hf_dvbci_app_cap_bytes = -1;
static int hf_dvbci_desc_num = -1;
static int hf_dvbci_sig_strength = -1;
static int hf_dvbci_sig_qual = -1;
static int hf_dvbci_opp_tune_status = -1;
static int hf_dvbci_opp_desc_loop_len = -1;
static int hf_dvbci_sas_app_id = -1;
static int hf_dvbci_sas_sess_state = -1;
static int hf_dvbci_sas_msg_nb = -1;
static int hf_dvbci_sas_msg_len = -1;

static dissector_table_t sas_msg_dissector_table;

static GHashTable *tpdu_fragment_table = NULL;
static GHashTable *tpdu_reassembled_table = NULL;
static GHashTable *spdu_fragment_table = NULL;
static GHashTable *spdu_reassembled_table = NULL;

static const fragment_items tpdu_frag_items = {
    &ett_dvbci_link_frag,
    &ett_dvbci_link_frags,

    &hf_dvbci_l_frags,
    &hf_dvbci_l_frag,
    &hf_dvbci_l_frag_overlap,
    &hf_dvbci_l_frag_overlap_conflicts,
    &hf_dvbci_l_frag_multiple_tails,
    &hf_dvbci_l_frag_too_long_frag,
    &hf_dvbci_l_frag_err,
    &hf_dvbci_l_frag_cnt,

    &hf_dvbci_l_reass_in,
    &hf_dvbci_l_reass_len,
    /* Reassembled data field */
    NULL,
    "Tpdu fragments"
};
static const fragment_items spdu_frag_items = {
    &ett_dvbci_transport_frag,
    &ett_dvbci_transport_frags,

    &hf_dvbci_t_frags,
    &hf_dvbci_t_frag,
    &hf_dvbci_t_frag_overlap,
    &hf_dvbci_t_frag_overlap_conflicts,
    &hf_dvbci_t_frag_multiple_tails,
    &hf_dvbci_t_frag_too_long_frag,
    &hf_dvbci_t_frag_err,
    &hf_dvbci_t_frag_cnt,

    &hf_dvbci_t_reass_in,
    &hf_dvbci_t_reass_len,
    /* Reassembled data field */
    NULL,
    "Spdu fragments"
};



typedef struct _spdu_info_t {
    guint8 tag;
    guint8 direction;
    guint8 len_field;
} spdu_info_t;

static const value_string dvbci_event[] = {
    { DATA_HOST_TO_CAM,  "data transfer Host -> CAM" },
    { DATA_CAM_TO_HOST,  "data transfer CAM -> Host" },
    { CIS_READ,          "read the Card Information Structure (CIS)" },
    { COR_WRITE,         "write into the Configuration Option Register (COR)" },
    { HW_EVT,            "hardware event" },
    { 0, NULL }
};
static const value_string dvbci_hw_event[] = {
    { CAM_IN,    "CI Module is inserted" },
    { CAM_OUT,   "CI Module is removed" },
    { POWER_ON,  "CI slot power on" },
    { POWER_OFF, "CI slot power off" },
    { TS_ROUTE,  "Transport stream routed through the CI Module" },
    { TS_BYPASS, "Transport stream bypasses the CI Module" },
    { RESET_H,   "Reset pin is high" },
    { RESET_L,   "Reset pin is low" },
    { READY_H,   "Ready pin is high" },
    { READY_L,   "Ready pin is low" },
    { 0, NULL }
};
static const value_string dvbci_cis_tpl_code[] = {
    { CISTPL_NO_LINK, "No-link tuple" },
    { CISTPL_VERS_1, "Level 1 version/product information" },
    { CISTPL_CONFIG, "Configuration for a 16bit PC-Card" },
    { CISTPL_CFTABLE_ENTRY, "Configuration-table entry" },
    { CISTPL_DEVICE_OC, "Device information for Common Memory" },
    { CISTPL_DEVICE_OA, "Device information for Attribute Memory" },
    { CISTPL_MANFID, "Manufacturer indentification string" },
    { CISTPL_END, "End of chain" },
    { 0, NULL }
};
static const value_string dvbci_cis_subtpl_code[] = {
    { CCSTPL_CIF, "Custom interface subtuple" },
    { 0, NULL }
};
static const value_string dvbci_cis_tpce_if_type[] = {
    { TPCE_IF_TYPE_MEM,    "Memory" },
    { TPCE_IF_TYPE_IO_MEM, "I/O and Memory" },
    { TPCE_IF_TYPE_CUST0,  "Custom Interface 0" },
    { TPCE_IF_TYPE_CUST1,  "Custom Interface 1" },
    { TPCE_IF_TYPE_CUST2,  "Custom Interface 2" },
    { TPCE_IF_TYPE_CUST3,  "Custom Interface 3" },
    { 0, NULL }
};
static const value_string dvbci_ml[] = {
    { ML_MORE, "more TPDU fragments pending" },
    { ML_LAST, "last TPDU fragment" },
    { 0, NULL }
};
static const value_string dvbci_c_tpdu[] = {
    { T_RCV, "T_RCV" },
    { T_CREATE_T_C,  "T_create_t_c" },
    { T_DELETE_T_C,  "T_delete_t_c" },
    { T_D_T_C_REPLY, "T_d_t_c_reply" },
    { T_NEW_T_C,     "T_new_t_c" },
    { T_T_C_ERROR,   "T_t_c_error" },
    { T_DATA_LAST,   "T_data_last" },
    { T_DATA_MORE,   "T_data_more" },
    { 0, NULL }
};
static const value_string dvbci_r_tpdu[] = {
    { T_C_T_C_REPLY, "T_c_tc_reply" },
    { T_DELETE_T_C,  "T_delete_t_c" },
    { T_D_T_C_REPLY, "T_d_t_c_reply" },
    { T_REQUEST_T_C, "T_request_t_c" },
    { T_DATA_LAST,   "T_data_last" },
    { T_DATA_MORE,   "T_data_more" },
    { 0, NULL }
};
static const value_string dvbci_sb_value[] = {
    { SB_VAL_MSG_AVAILABLE,    "message available" },
    { SB_VAL_NO_MSG_AVAILABLE, "no message available" },
    { 0, NULL }
};
static const value_string dvbci_spdu_tag[] = {
    { T_SESSION_NUMBER,          "Session Number (payload data)" },
    { T_OPEN_SESSION_REQUEST,    "Open Session Request" },
    { T_OPEN_SESSION_RESPONSE,   "Open Session Response" },
    { T_CREATE_SESSION,          "Create Session" },
    { T_CREATE_SESSION_RESPONSE, "Create Session Response" },
    { T_CLOSE_SESSION_REQUEST,   "Close Session Request" },
    { T_CLOSE_SESSION_RESPONSE,  "Close Session Response" },
    { 0, NULL }
};
static GHashTable *spdu_table = NULL;
static const spdu_info_t spdu_info[] = {
    { T_SESSION_NUMBER,          DIRECTION_ANY, 2 },
    { T_OPEN_SESSION_REQUEST,    DATA_CAM_TO_HOST, 4 },
    { T_OPEN_SESSION_RESPONSE,   DATA_HOST_TO_CAM, 7 },
    { T_CREATE_SESSION,          DATA_HOST_TO_CAM, 6 },
    { T_CREATE_SESSION_RESPONSE, DATA_CAM_TO_HOST, 7 },
    { T_CLOSE_SESSION_REQUEST,   DIRECTION_ANY, 2 },
    { T_CLOSE_SESSION_RESPONSE,  DIRECTION_ANY, 3 }
};
static const value_string dvbci_sess_status[] = {
    { SESS_OPENED,
      "Session opened" },
    { SESS_NOT_OPENED_RES_NON_EXIST,
      "Resource does not exist" },
    { SESS_NOT_OPENED_RES_UNAVAIL,
      "Resource exists but it's unavailable" },
    { SESS_NOT_OPENED_RES_VER_LOWER,
      "Existing resource's version is lower than requested version" },
    { SESS_NOT_OPENED_RES_BUSY,
      "Resource is busy" },
    { 0, NULL }
};
static const value_string dvbci_close_sess_status[] = {
    { SESS_CLOSED,       "Session closed" },
    { SESS_NB_NOT_ALLOC, "Session number not allocated" },
    { 0, NULL }
};
static const value_string dvbci_res_class[] = {
    { RES_CLASS_RM,  "Resource Manager" },
    { RES_CLASS_AP,  "Application Info" },
    { RES_CLASS_CA,  "Conditional Access" },
    { RES_CLASS_AUT, "Authentication" },
    { RES_CLASS_HC,  "Host Control" },
    { RES_CLASS_DT,  "Date-Time" },
    { RES_CLASS_MMI, "Man-machine interface (MMI)" },
    { RES_CLASS_AMI, "Application MMI" },
    { RES_CLASS_LSC, "Low-Speed Communication" },
    { RES_CLASS_CC,  "Content Control" },
    { RES_CLASS_HLC, "Host Language & Country" },
    { RES_CLASS_CUP, "CAM Upgrade" },
    { RES_CLASS_OPP, "Operator Profile" },
    { RES_CLASS_SAS, "Specific Application Support" },
    { 0, NULL }
};
static const value_string dvbci_app_type[] = {
    { APP_TYPE_CA,  "Conditional Access" },
    { APP_TYPE_EPG, "Electronic Progam Guide" },
    { 0, NULL }
};
static const value_string dvbci_data_rate[] = {
    { DATA_RATE_72, "72 Mbit/s" },
    { DATA_RATE_96, "96 Mbit/s" },
    { 0, NULL }
};
static const value_string dvbci_ca_pmt_list_mgmt[] = {
    { LIST_MGMT_MORE,   "more" },
    { LIST_MGMT_FIRST,  "first" },
    { LIST_MGMT_LAST,   "last" },
    { LIST_MGMT_ONLY,   "only" },
    { LIST_MGMT_ADD,    "add" },
    { LIST_MGMT_UPDATE, "update" },
    { 0, NULL }
};
static const value_string dvbci_ca_pmt_cmd_id[] = {
    { CMD_ID_OK_DESCR,     "ok descrambling" },
    { CMD_ID_OK_MMI,       "ok mmi" },
    { CMD_ID_QUERY,        "query" },
    { CMD_ID_NOT_SELECTED, "not selected" },
    { 0, NULL }
};
static const value_string dvbci_ca_enable[] = {
    { CA_ENAB_DESC_OK, "descrambling possible" },
    { CA_ENAB_DESC_OK_PURCHASE,
        "descrambling possible under conditions (purchase dialogue)" },
    { CA_ENAB_DESC_OK_TECH,
        "descrambling possible under conditions (technical dialogue)" },
    { CA_ENAB_DESC_NG_ENTITLEMENT,
        "descrambling not possible (because no entitlement)" },
    { CA_ENAB_DESC_NG_TECH,
        "descrambling not possible (for technical reasons)" },
    { 0, NULL }
};
static const value_string dvbci_hc_status[] = {
    { HC_STAT_OK, "ok" },
    { HC_STAT_ERR_DLVRY, "unsupported delivery system descriptor" },
    { HC_STAT_ERR_LOCK, "tuner not locking" },
    { HC_STAT_ERR_BUSY, "tuner busy" },
    { HC_STAT_ERR_PARAM, "bad or missing parameters" },
    { HC_STAT_ERR_NOT_FOUND, "service not found" },
    { HC_STAT_ERR_UNKNOWN, "unknown error" },
    { 0, NULL }
};
static const value_string dvbci_hc_release_reply[] = {
    { HC_RELEASE_OK, "Host regains control of the tuner" },
    { HC_RELEASE_REFUSED, "CICAM retains control of the tuner" },
    { 0, NULL }
};
static const value_string dvbci_close_mmi_cmd_id[] = {
    { CLOSE_MMI_CMD_ID_IMMEDIATE, "immediate close" },
    { CLOSE_MMI_CMD_ID_DELAY, "delayed close" },
    { 0, NULL }
};
static const value_string dvbci_disp_ctl_cmd[] = {
    { DISP_CMD_SET_MMI_MODE, "set MMI mode" },
    { DISP_CMD_GET_DISP_TBL, "get display character tables" },
    { DISP_CMD_GET_INP_TBL,  "get input character tables" },
    { 0, NULL }
};
static const value_string dvbci_mmi_mode[] = {
    { MMI_MODE_HIGH, "High-level MMI" },
    { 0, NULL }
};
static const value_string dvbci_disp_rep_id[] = {
    { DISP_REP_ID_MMI_MODE_ACK,     "MMI mode acknowledge" },
    { DISP_REP_ID_DISP_CHAR_TBL,    "list display character tables" },
    { DISP_REP_ID_INP_CHAR_TBL,     "list input character tables" },
    { DISP_REP_ID_UNKNOWN_CMD,      "unknown display control command" },
    { DISP_REP_ID_UNKNOWN_MMI_MODE, "unknown MMI mode" },
    { DISP_REP_ID_UNKNOWN_CHAR_TBL, "unknown character table" },
    { 0, NULL }
};
static const value_string dvbci_blind_ans[] = {
    { VISIBLE_ANS, "visible" },
    { BLIND_ANS,   "blind" },
    { 0, NULL }
};
static const value_string dvbci_text_ctrl[] = {
    { TEXT_CTRL_EMPH_ON,  "character emphasis on" },
    { TEXT_CTRL_EMPH_OFF, "character emphasis off" },
    { TEXT_CTRL_CRLF,     "CR/LF" },
    { 0, NULL }
};
static const value_string dvbci_char_tbl[] = {
    { CHAR_TBL_8859_5,      "ISO/IEC 8859-5 (Latin/Cyrillic)" },
    { CHAR_TBL_8859_6,      "ISO/IEC 8859-6 (Latin/Arabic)" },
    { CHAR_TBL_8859_7,      "ISO/IEC 8859-7 (Latin/Greek)" },
    { CHAR_TBL_8859_8,      "ISO/IEC 8859-8 (Latin/Hebrew)" },
    { CHAR_TBL_8859_9,      "ISO/IEC 8859-9 (Latin No. 5)" },
    { CHAR_TBL_8859_10,     "ISO/IEC 8859-10 (Latin No. 6)" },
    { CHAR_TBL_8859_11,     "ISO/IEC 8859-11 (Latin/Thai)" },
    { CHAR_TBL_8859_13,     "ISO/IEC 8859-13 (Latin No. 7)" },
    { CHAR_TBL_8859_14,     "ISO/IEC 8859-14 (Latin No. 8 (Celtic))" },
    { CHAR_TBL_8859_15,     "ISO/IEC 8859-15 (Latin No. 9)" },
    { CHAR_TBL_ENC_TYPE_ID, "defined by encoding_type_id" },
    /* don't add any multi-byte tables (>= 0x10) */
    { 0, NULL }
};
static const value_string dvbci_ans_id[] = {
    { ANSW_ID_CANCEL, "cancel" },
    { ANSW_ID_ANSWER, "answer" },
    { 0, NULL }
};
static const value_string dvbci_cup_type[] = {
    { CUP_DELAYED, "delayed" },
    { CUP_IMMEDIATE, "immediate" },
    { 0, NULL }
};
static const value_string dvbci_cup_answer[] = {
    { CUP_ANS_NO,  "upgrade denied" },
    { CUP_ANS_YES, "upgrade allowed" },
    { CUP_ANS_ASK, "ask the user for permission" },
    { 0, NULL }
};
static const value_string dvbci_cup_reset[] = {
    { CUP_RESET_PCMCIA, "PCMCIA reset" },
    { CUP_RESET_CMDIF,  "CI command interface reset" },
    { CUP_RESET_NONE,   "no reset" },
    { 0, NULL }
};
static const value_string dvbci_cc_dat_id[] = {
    { CC_ID_HOST_ID,            "Host ID" },
    { CC_ID_CICAM_ID,           "Cicam ID" },
    { CC_ID_HOST_BRAND_CERT,    "Host brand certificate" },
    { CC_ID_CICAM_BRAND_CERT,   "Cicam brand certificate" },
    { CC_ID_KP,                 "Key precursor for CCK" },
    { CC_ID_DHPH,               "Host Diffie-Hellman public key" },
    { CC_ID_DHPM,               "Cicam Diffie-Hellman public key" },
    { CC_ID_HOST_DEV_CERT,      "Host device certificate" },
    { CC_ID_CICAM_DEV_CERT,     "Cicam device certificate" },
    { CC_ID_SIG_A,              "Signature of host Diffie-Hellman public key" },
    { CC_ID_SIG_B,              "Signature of cicam Diffie-Hellman public key" },
    { CC_ID_NS_HOST,            "Host nonce" },
    { CC_ID_AUTH_NONCE,         "Nonce for authentication" },
    { CC_ID_NS_MODULE,          "Cicam nonce" },
    { CC_ID_AKH,                "Host authentication key" },
    { CC_ID_URI,                "URI" },
    { CC_ID_PROG_NUM,           "Program number" },
    { CC_ID_URI_CNF,            "URI confirmation" },
    { CC_ID_KEY_REGISTER,       "Key register" },
    { CC_ID_URI_VERSIONS,       "Supported URI versions" },
    { CC_ID_STATUS_FIELD,       "Status field" },
    { CC_ID_SRM_DATA,           "SRM for HDCP" },
    { CC_ID_SRM_CONFIRM,        "SRM confirmation hash" },
    { CC_ID_CICAM_LICENSE,      "License received from the cicam" },
    { CC_ID_LICENSE_STATUS,     "Current status of the license" },
    { CC_ID_LICENSE_RCV_STATUS, "Status of the license exchange" },
    { CC_ID_OPERATING_MODE,     "Operating mode" },
    { CC_ID_PINCODE_DATA,       "Pincode data" },
    { CC_ID_REC_START_STATUS,   "Record start status" },
    { CC_ID_MODE_CHG_STATUS,    "Change operating mode status" },
    { CC_ID_REC_STOP_STATUS,    "Record stop status" },
    { 0, NULL }
};
static const value_string dvbci_cc_key_register[] = {
    { CC_KEY_EVEN,  "Even" },
    { CC_KEY_ODD,   "Odd" },
    { 0, NULL }
};
static const value_string dvbci_cc_status[] = {
    { CC_STATUS_OK,                    "Ok" },
    { CC_STATUS_NO_CC_SUPPORT,         "No CC support" },
    { CC_STATUS_HOST_BUSY,             "Host busy" },
    { CC_STATUS_AUTH_FAILED_OR_NO_SRM, "Authentication failed / SRM not required" },
    { CC_STATUS_CICAM_BUSY,            "CICAM busy" },
    { CC_STATUS_REC_MODE_ERR,          "Recording mode error" },
    { 0, NULL }
};
static const value_string dvbci_cc_sac_auth[] = {
    { CC_SAC_AUTH_AES128_XCBC_MAC, "AES 128 XCBC MAC" },
    { 0, NULL }
};
static const value_string dvbci_cc_sac_enc[] = {
    { CC_SAC_ENC_AES128_CBC, "AES 128 CBC" },
    { 0, NULL }
};
static const value_string dvbci_cc_cap[] = {
    { CC_CAP_NONE,
        "No PIN handling capability" },
    { CC_CAP_CAS_PIN,
        "CAM can do PIN handling on CAS services" },
    { CC_CAP_CAS_FTA_PIN,
        "CAM can do PIN handling on CAS and free services" },
    { CC_CAP_CAS_PIN_CACHED,
        "CAM can do PIN handling on CAS services and supports PIN caching" },
    { CC_CAP_CAS_FTA_PIN_CACHED,
        "CAM can do PIN handling on CAS and free services, supports PIN caching" },
    { 0, NULL }
};
static const value_string dvbci_pincode_status[] = {
    { CC_PIN_BAD,         "Bad pin code" },
    { CC_PIN_CAM_BUSY,    "CAM busy" },
    { CC_PIN_OK,          "Pin code correct" },
    { CC_PIN_UNCONFIRMED, "Pin code unconfirmed" },
    { CC_PIN_VB_NOT_REQ,  "Video blanking not required" },
    { CC_PIN_CSA,         "Content still CSA scrambled" },
    { 0, NULL }
};
static const value_string dvbci_cc_op_mode[] = {
    { CC_OP_MODE_WATCH_BUFFER, "Watch and buffer" },
    { CC_OP_MODE_TIMESHIFT,    "Timeshift" },
    { CC_OP_MODE_UNATTENDED,   "Unattended recording" },
    { 0, NULL }
};
static const value_string dvbci_ack_code[] = {
    { ACK_CODE_OK, "Ok" },
    { ACK_CODE_WRONG_API,  "Application Domain unsupported" },
    { ACK_CODE_API_BUSY,   "Application Domain currently unavailable" },
    { 0, NULL }
};
static const value_string dvbci_req_type[] = {
    { REQ_TYPE_FILE, "File" },
    { REQ_TYPE_DATA, "Data" },
    { REQ_TYPE_FILE_HASH, "FileHash" },
    { REQ_TYPE_REQ, "List supported request types" },
    { 0, NULL }
};
static const value_string dvbci_comms_cmd_id[] = {
    { COMMS_CMD_ID_CONNECT_ON_CHANNEL, "connect on channel" },
    { COMMS_CMD_ID_DISCONNECT_ON_CHANNEL, "disconnect on channel" },
    { COMMS_CMD_ID_SET_PARAMS, "set parameters" },
    { COMMS_CMD_ID_ENQUIRE_STATUS, "status enquiry" },
    { COMMS_CMD_ID_GET_NEXT_BUFFER, "get next buffer" },
    { 0, NULL }
};
static const value_string dvbci_conn_desc_type[] = {
    { CONN_DESC_TEL, "DVB-SI telephone descriptor" },
    { CONN_DESC_CABLE, "cable return channel" },
    { CONN_DESC_IP, "IP descriptor" },
    { CONN_DESC_HOSTNAME, "hostname descriptor" },
    { 0, NULL }
};
static const value_string dvbci_lsc_desc_tag[] = {
    { LSC_DESC_IP, "IP descriptor" },
    { LSC_DESC_HOSTNAME, "hostname descriptor" },
    { 0, NULL }
};
static const value_string dvbci_lsc_ip_ver[] = {
    { LSC_IPV4, "IPv4" },
    { LSC_IPV6, "IPv6" },
    { 0, NULL }
};
static const value_string dvbci_lsc_proto[] = {
    { LSC_TCP, "TCP" },
    { LSC_UDP, "UDP" },
    { 0, NULL }
};
static const value_string dvbci_comms_rep_id[] = {
    { COMMS_REP_ID_CONNECT_ACK, "connect ack" },
    { COMMS_REP_ID_DISCONNECT_ACK, "disconnect ack" },
    { COMMS_REP_ID_SET_PARAMS_ACK, "set parameters ack" },
    { COMMS_REP_ID_STATUS_REPLY, "status reply" },
    { COMMS_REP_ID_GET_NEXT_BUFFER_ACK, "get next buffer ack" },
    { COMMS_REP_ID_SEND_ACK, "send ack" },
    { 0, NULL }
};
static const value_string dvbci_lsc_ret_val[] = {
    { LSC_RET_OK, "ok" },
    { 0, NULL }
};
static const value_string dvbci_lsc_ret_val_connect[] = {
    { LSC_RET_DISCONNECTED, "disconnected" },
    { LSC_RET_CONNECTED, "connected" },
    { 0, NULL }
};
static const value_string dvbci_lsc_ret_val_params[] = {
    { LSC_RET_OK, "ok" },
    { LSC_RET_TOO_BIG, "buffer size too big" },
    { 0, NULL }
};
static const value_string dvbci_sas_sess_state[] = {
    { SAS_SESS_STATE_CONNECTED, "connected" },
    { SAS_SESS_STATE_NOT_FOUND, "application not found" },
    { SAS_SESS_STATE_DENIED, "denied, no more connections available" },
    { 0, NULL }
};


static guint16 buf_size_cam;    /* buffer size proposal by the CAM */
/* buffer size proposal by the host == negotiated buffer size */
static guint16 buf_size_host;

/* this must be a function, not a macro,
   so that we can enforce the return type */
static inline gint16 two_comp_to_int16(guint16 x)
{
   return (x&0x8000) ? -~(x-1) : x;
}


/* initialize/reset per capture state data */
static void
dvbci_init(void)
{
    buf_size_cam  = 0;
    buf_size_host = 0;

    fragment_table_init(&tpdu_fragment_table);
    reassembled_table_init(&tpdu_reassembled_table);
    fragment_table_init(&spdu_fragment_table);
    reassembled_table_init(&spdu_reassembled_table);
}


/* dissect a delivery system descriptor loop
   and the preceding length field
   (used for host control and operator profile)
   return the number of bytes dissected */
static gint
dissect_desc_loop(int len_hf,
        tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    gint offset_start;
    guint16 desc_loop_len;
    guint desc_len;

    offset_start = offset;

    desc_loop_len = tvb_get_ntohs(tvb, offset) & 0x0FFF;
    proto_tree_add_item(tree, len_hf, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    while (offset-offset_start < 2+desc_loop_len) {
        desc_len = proto_mpeg_descriptor_dissect(tvb, offset, tree);
        if (desc_len==0)
            break;
        offset += desc_len;
    }

    return offset-offset_start;
}


/* dissect operator profile's status body, return its length */
static gint
dissect_opp_status_body(tvbuff_t *tvb, gint offset,
        packet_info *pinfo _U_, proto_tree *tree)
{
    gint offset_start;

    offset_start = offset;
    proto_tree_add_item(tree, hf_dvbci_info_ver_op_status,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dvbci_nit_ver,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_dvbci_pro_typ,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dvbci_init_flag,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dvbci_ent_chg_flag,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dvbci_ent_val_flag,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dvbci_ref_req_flag,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_dvbci_err_flag,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dvbci_dlv_sys_hint,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_dvbci_refr_req_date,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_dvbci_refr_req_time,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset-offset_start;
}


/* dissect a capability loop in an operator_search_start apdu */
static gint
dissect_opp_cap_loop(guint8 cap_loop_len, const gchar *title,
        int item_hf, guint item_len,
        tvbuff_t *tvb, gint offset,
        packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti        = NULL;
    proto_tree *loop_tree = NULL;
    guint       i;

    if (!title)
        return -1;
    if (item_len==0 || cap_loop_len%item_len != 0)
        return -1;

    if (tree && cap_loop_len>0) {
        ti = proto_tree_add_text(tree, tvb, offset, cap_loop_len, "%s", title);
        loop_tree = proto_item_add_subtree(ti, ett_dvbci_opp_cap_loop);
    }
    for (i=0; i<cap_loop_len; i+=item_len) {
        proto_tree_add_item(loop_tree, item_hf,
                tvb, offset+i, item_len, ENC_BIG_ENDIAN);
    }

    return cap_loop_len;
}

/* read a utc_time field in an apdu and write it to utc_time
   the encoding of the field is according to DVB-SI specification, section 5.2.5
   16bit modified julian day (MJD), 24bit 6*4bit BCD digits hhmmss
   return the length in bytes or -1 for error */
static gint
read_utc_time(tvbuff_t *tvb, gint offset, nstime_t *utc_time)
{
    gint   bcd_time_offset;     /* start offset of the bcd time in the tvbuff */
    guint8 hour, min, sec;

    if (!utc_time)
        return -1;

    nstime_set_zero(utc_time);
    utc_time->secs = (tvb_get_ntohs(tvb, offset) - 40587) * 86400;
    bcd_time_offset = offset+2;
    hour = BCD44_TO_DEC(tvb_get_guint8(tvb, bcd_time_offset));
    min = BCD44_TO_DEC(tvb_get_guint8(tvb, bcd_time_offset+1));
    sec = BCD44_TO_DEC(tvb_get_guint8(tvb, bcd_time_offset+2));
    if (hour>23 || min>59 || sec>59)
        return -1;

    utc_time->secs += hour*3600 + min*60 + sec;
    return 5;
}


/* dissect age rating byte encoded as defined in
   DVB-SI parental rating descriptor
   returns rating's length in bytes or -1 for error */
static gint
dissect_rating(tvbuff_t *tvb, gint offset,
        packet_info *pinfo _U_, proto_tree *tree)
{
    guint8 rating;

    rating = tvb_get_guint8(tvb, offset);
    if (1<=rating && rating<=0x0F) {
        proto_tree_add_uint_format(tree, hf_dvbci_rating,
                tvb, offset, 1, rating,
                "Rating is %d years (%d+3)", rating+3, rating);
    } else {
        proto_tree_add_uint_format(tree, hf_dvbci_rating,
                tvb, offset, 1, rating,
                "Rating is unknown/undefined (%d)", rating);
    }

    return 1;
}


/* if there's a dissector for the protocol and target port of our
    lsc connection, store it in the lsc session's circuit */
static void
store_lsc_msg_dissector(circuit_t *circuit, guint8 ip_proto, guint16 port)
{
    dissector_handle_t msg_handle = NULL;

    if (!circuit)
        return;

    if (ip_proto==LSC_TCP)
        msg_handle = dissector_get_uint_handle(tcp_dissector_table, port);
    else if (ip_proto==LSC_UDP)
        msg_handle = dissector_get_uint_handle(udp_dissector_table, port);

    circuit_set_dissector(circuit, msg_handle);
}


/* dissect a connection_descriptor for the lsc resource
   returns its length or -1 for error */
static gint
dissect_conn_desc(tvbuff_t *tvb, gint offset,  circuit_t *circuit,
        packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti             = NULL;
    proto_tree *conn_desc_tree = NULL;
    guint32     tag;
    gint        offset_start, offset_body;
    gint        len_field;
    guint8      conn_desc_type;
    guint8      ip_ver, ip_proto;
    guint16     port;
    proto_item *port_item      = NULL;
    gint        hostname_len;

    offset_start = offset;

    tag = tvb_get_ntoh24(tvb, offset);
    if (tag!= T_CONNECTION_DESCRIPTOR)
        return 0;

    if (tree) {
        ti = proto_tree_add_text(tree, tvb,
                        offset_start, -1, "Connection descriptor");
        conn_desc_tree = proto_item_add_subtree(ti, ett_dvbci_lsc_conn_desc);
    }

    proto_tree_add_item(conn_desc_tree, hf_dvbci_apdu_tag,
            tvb, offset, APDU_TAG_SIZE, ENC_BIG_ENDIAN);
    offset += APDU_TAG_SIZE;
    offset = dissect_ber_length(pinfo, conn_desc_tree,
                    tvb, offset, &len_field, NULL);
    offset_body = offset;

    conn_desc_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(conn_desc_tree, hf_dvbci_conn_desc_type,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (conn_desc_type == CONN_DESC_IP) {
        proto_tree_add_item(conn_desc_tree, hf_dvbci_lsc_media_tag,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(conn_desc_tree, hf_dvbci_lsc_media_len,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        ip_ver = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(conn_desc_tree, hf_dvbci_lsc_ip_ver,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        if (ip_ver == LSC_IPV4) {
            offset += FT_IPv6_LEN-FT_IPv4_LEN;
            proto_tree_add_item(conn_desc_tree, hf_dvbci_lsc_ipv4_addr,
                    tvb, offset, FT_IPv4_LEN, ENC_BIG_ENDIAN);
            offset += FT_IPv4_LEN;
        }
        else if (ip_ver == LSC_IPV6) {
            proto_tree_add_item(conn_desc_tree, hf_dvbci_lsc_ipv6_addr,
                    tvb, offset, FT_IPv6_LEN, ENC_NA);
            offset += FT_IPv6_LEN;
        }
        else
            offset += FT_IPv6_LEN;

        port = tvb_get_ntohs(tvb, offset);
        port_item = proto_tree_add_item(conn_desc_tree,
                hf_dvbci_lsc_dst_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset +=2;
        ip_proto = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(conn_desc_tree, hf_dvbci_lsc_proto,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
        offset ++;
        if (port_item) {
            if (ip_proto==LSC_TCP && get_tcp_port(port)) {
                proto_item_append_text(port_item, " (%s)",
                        get_tcp_port(port));
            }
            else if (ip_proto==LSC_UDP && get_udp_port(port)) {
                proto_item_append_text(port_item, " (%s)",
                        get_udp_port(port));
            }
        }
        store_lsc_msg_dissector(circuit, ip_proto, port);

    } else if (conn_desc_type == CONN_DESC_HOSTNAME) {
        proto_tree_add_item(conn_desc_tree, hf_dvbci_lsc_media_tag,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(conn_desc_tree, hf_dvbci_lsc_media_len,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        ip_proto = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(conn_desc_tree, hf_dvbci_lsc_proto,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
        offset ++;
        port = tvb_get_ntohs(tvb, offset);
        port_item = proto_tree_add_item(conn_desc_tree,
                hf_dvbci_lsc_dst_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset +=2;
        if (port_item) {
            if (ip_proto==LSC_TCP && get_tcp_port(port)) {
                proto_item_append_text(port_item, " (%s)",
                        get_tcp_port(port));
            }
            else if (ip_proto==LSC_UDP && get_udp_port(port)) {
                proto_item_append_text(port_item, " (%s)",
                        get_udp_port(port));
            }
        }
        store_lsc_msg_dissector(circuit, ip_proto, port);

        /* everything from here to the descriptor's end is a hostname */
        hostname_len = (offset_body+len_field)-offset;
        proto_tree_add_item(conn_desc_tree, hf_dvbci_lsc_hostname,
                tvb, offset, hostname_len, ENC_ASCII|ENC_NA);
        offset += hostname_len;
    } else {
        proto_tree_add_text(conn_desc_tree, tvb,
                offset, len_field-1, "media specific data");
        offset += len_field-1;
    }

    proto_item_set_len(ti, offset-offset_start);
    return offset-offset_start;
}


/* dissect an item from cc_data_req/cc_data_cnf,
   returns its length or -1 for error */
static gint
dissect_cc_item(tvbuff_t *tvb, gint offset,
        packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti           = NULL;
    proto_tree *cc_item_tree = NULL;
    gint        offset_start;
    guint16     dat_len;
    guint8      dat_id;
    asn1_ctx_t  asn1_ctx;
    int         hf_cert_index;
    guint8      emi;
    guint16     prog_num;
    guint8      status;


    offset_start = offset;
    dat_id = tvb_get_guint8(tvb, offset);
    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset_start, -1, "CC data item: %s",
                val_to_str_const(dat_id, dvbci_cc_dat_id, "unknown"));
        cc_item_tree = proto_item_add_subtree(ti, ett_dvbci_cc_item);
    }
    proto_tree_add_item(cc_item_tree, hf_dvbci_cc_dat_id,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    dat_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(cc_item_tree, tvb, offset, 2, "Length: %d", dat_len);
    offset += 2;
    switch (dat_id) {
        case CC_ID_HOST_BRAND_CERT:
        case CC_ID_CICAM_BRAND_CERT:
        case CC_ID_HOST_DEV_CERT:
        case CC_ID_CICAM_DEV_CERT:
            asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
            hf_cert_index = (dat_id==CC_ID_HOST_BRAND_CERT ||
                             dat_id==CC_ID_CICAM_BRAND_CERT) ?
                hf_dvbci_brand_cert : hf_dvbci_dev_cert;

            /* enable dissection of CI+ specific X.509 extensions
               only for our certificates */
            x509ce_enable_ciplus();
            dissect_x509af_Certificate(FALSE, tvb, offset,
                    &asn1_ctx, cc_item_tree, hf_cert_index);
            x509ce_disable_ciplus();
            break;
        case CC_ID_URI:
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "URI");
            proto_tree_add_item(cc_item_tree, hf_dvbci_uri_ver,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(cc_item_tree, hf_dvbci_uri_aps,
                    tvb, offset+1, 1, ENC_BIG_ENDIAN);
            emi = (tvb_get_guint8(tvb, offset+1) & 0x30) >> 4;
            proto_tree_add_item(cc_item_tree, hf_dvbci_uri_emi,
                    tvb, offset+1, 1, ENC_BIG_ENDIAN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "EMI 0x%x", emi);
            proto_tree_add_item(cc_item_tree, hf_dvbci_uri_ict,
                    tvb, offset+1, 1, ENC_BIG_ENDIAN);
            if (emi==0) {
                proto_tree_add_item(cc_item_tree, hf_dvbci_uri_rct,
                        tvb, offset+1, 1, ENC_BIG_ENDIAN);
            }
            /* digital only token and retention limit will be added */
            break;
        case CC_ID_PROG_NUM:
            prog_num = tvb_get_ntohs(tvb, offset);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                    "Program number 0x%x", prog_num);
            break;
        case CC_ID_KEY_REGISTER:
            proto_tree_add_item(cc_item_tree, hf_dvbci_cc_key_register,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        case CC_ID_STATUS_FIELD:
        case CC_ID_REC_START_STATUS:
        case CC_ID_MODE_CHG_STATUS:
        case CC_ID_REC_STOP_STATUS:
            status = tvb_get_guint8(tvb, offset);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Status: %s",
                    val_to_str_const(status, dvbci_cc_status, "unknown"));
            proto_tree_add_item(cc_item_tree, hf_dvbci_cc_status_field,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        case CC_ID_OPERATING_MODE:
            proto_tree_add_item(cc_item_tree, hf_dvbci_cc_op_mode,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        default:
            proto_tree_add_item(cc_item_tree, hf_dvbci_cc_data,
                    tvb, offset, dat_len, ENC_NA);
            break;
    }
    offset += dat_len;

    proto_item_set_len(ti, offset-offset_start);
    return offset-offset_start;
}


static gint
dissect_cc_data_payload(guint32 tag,  tvbuff_t *tvb, gint offset,
        packet_info *pinfo, proto_tree *tree)
{
    gint   offset_start;
    guint8 i, snd_dat_nbr, req_dat_nbr;
    gint   item_len;

    offset_start = offset;

    proto_tree_add_item(
            tree, hf_dvbci_cc_sys_id_bitmask, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    snd_dat_nbr = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1,
            "Number of sent data items: %d", snd_dat_nbr);
    offset++;
    for(i=0; i<snd_dat_nbr &&
            tvb_reported_length_remaining(tvb, offset)>0; i++) {
        item_len = dissect_cc_item(tvb, offset, pinfo, tree);
        if (item_len < 0)
            return -1;
        offset += item_len;
    }
    if (tag==T_CC_DATA_REQ || tag==T_CC_SAC_DATA_REQ) {
        req_dat_nbr = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1,
                "Number of requested data items: %d", req_dat_nbr);
        offset++;
        for(i=0; i<req_dat_nbr &&
                tvb_reported_length_remaining(tvb, offset)>0; i++) {
            proto_tree_add_item(
                    tree, hf_dvbci_cc_dat_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
        }
    }

    return offset-offset_start;
}


#ifdef HAVE_LIBGCRYPT
/* convert a 0-terminated preference key_string that contains a hex number
 *  into its binary representation
 * e.g. key_string "abcd" will be converted into two bytes 0xab, 0xcd
 * return the number of binary bytes or -1 for error */
static gint
pref_key_string_to_bin(const gchar *key_string, unsigned char **key_bin)
{
    int  key_string_len;
    int  i, j;
    char input[2];

    if (!key_string || !key_bin)
        return -1;
    key_string_len = (int)strlen(key_string);
    if (key_string_len != 2*AES_KEY_LEN)
        return -1;
    *key_bin = (unsigned char*)g_malloc(key_string_len/2);

    j=0;
    for (i=0; i<key_string_len-1; i+=2) {
        input[0] = key_string[0+i];
        input[1] = key_string[1+i];
        /* attention, brackets are required */
        (*key_bin)[j++] = (unsigned char)strtoul((const char*)&input, NULL, 16);
    }

    return key_string_len/2;
}


static tvbuff_t *
decrypt_sac_msg_body(
        guint8 enc_cip, tvbuff_t *encrypted_tvb, gint offset, gint len)
{
    gint             ret;
    gboolean         opened = FALSE;
    gcry_cipher_hd_t cipher;
    gcry_error_t     err;
    gint             clear_len;
    unsigned char    *clear_data = NULL;
    tvbuff_t         *clear_tvb = NULL;
    unsigned char    *sek = NULL, *siv = NULL;

    if (enc_cip != CC_SAC_ENC_AES128_CBC)
        goto end;
    if (len%AES_BLOCK_LEN != 0)
        goto end;

    ret = pref_key_string_to_bin(dvbci_sek, &sek);
    if (ret==-1)
        goto end;
    ret = pref_key_string_to_bin(dvbci_siv, &siv);
    if (ret==-1)
        goto end;

    err = gcry_cipher_open(&cipher, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0);
    if (gcry_err_code (err))
        goto end;
    opened = TRUE;
    err = gcry_cipher_setkey (cipher, sek, AES_KEY_LEN);
    if (gcry_err_code (err))
        goto end;
    err = gcry_cipher_setiv (cipher, siv, AES_BLOCK_LEN);
    if (gcry_err_code (err))
        goto end;

    clear_len = len;
    clear_data = (unsigned char *)g_malloc(clear_len);

    err = gcry_cipher_decrypt (cipher, clear_data, clear_len,
                tvb_get_ephemeral_string(encrypted_tvb, offset, len), len);
    if (gcry_err_code (err))
        goto end;

    clear_tvb = tvb_new_child_real_data(encrypted_tvb,
                        (const guint8 *)clear_data, clear_len, clear_len);
    tvb_set_free_cb(clear_tvb, g_free);

end:
    if (opened)
        gcry_cipher_close (cipher);
    if (sek)
        g_free(sek);
    if (siv)
        g_free(siv);
    if (!clear_tvb && clear_data)
       g_free(clear_data);
    return clear_tvb;
}

#else
/* HAVE_LIBGRYPT is not set */
static tvbuff_t *
decrypt_sac_msg_body(guint8 enc_cip _U_,
        tvbuff_t *encrypted_tvb _U_, gint offset _U_, gint len _U_)
{
    return NULL;
}

#endif


 /* dissect a text string that is encoded according to DVB-SI (EN 300 468) */
static void
dissect_si_string(tvbuff_t *tvb, gint offset, gint str_len,
        packet_info *pinfo, proto_tree *tree, const gchar *title,
        gboolean show_col_info)
{
    guint8      byte0;
    guint8     *si_str = NULL;
    proto_item *pi;

    if (!title)  /* we always have a title for our strings */
        return;
    /* str_len==-1 is not supported, we need an actual length */
    if (str_len<=0)
        return;

    byte0 = tvb_get_guint8(tvb, offset);
    if (byte0>=0x01 && byte0<=0x0F) {
        proto_tree_add_item(tree, hf_dvbci_char_tbl, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        str_len--;
    }
    else if (byte0>=0x10 && byte0 <= 0x1F) {
        pi = proto_tree_add_text(tree, tvb, offset, 1,
                "Invalid/unsupported character table");
        expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                "Character tables with multi-byte encoding are not supported");
        offset++;
        str_len--;
        proto_tree_add_text(tree, tvb, offset, str_len, "encoded text");
        return;
    }
    /* for now, control characters are supported only at the beginning
     * of a string (this should cover all cases found in practice) */
    else if (byte0>=0x80 && byte0<=0x9F) {
        proto_tree_add_item(tree, hf_dvbci_text_ctrl, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        str_len--;
    }

    si_str = tvb_get_ephemeral_string(tvb, offset, str_len);
    if (!si_str)
        return;

    proto_tree_add_text(tree, tvb, offset, str_len, "%s: %s", title, si_str);
    if (show_col_info)
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", si_str);
}


/* dissect ca_enable_flag and ca_enable fields in the ca_pmt_reply
 * return true if descrambling is possible, false otherwise */
static gboolean
dissect_ca_enable(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
        proto_tree *tree)
{
    gboolean desc_ok = FALSE;
    guint8   byte, ca_enab;

    byte = tvb_get_guint8(tvb,offset);
    proto_tree_add_item(tree, hf_dvbci_ca_enable_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (byte&0x80) {
        ca_enab = byte & ~0x80;
        proto_tree_add_item(tree, hf_dvbci_ca_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
        if (ca_enab==CA_ENAB_DESC_OK ||
            ca_enab==CA_ENAB_DESC_OK_PURCHASE ||
            ca_enab==CA_ENAB_DESC_OK_TECH) {
            desc_ok = TRUE;
        }
    }

    return desc_ok;
}


/* dissect a ca descriptor in the ca_pmt */
static gint
dissect_ca_desc(tvbuff_t *tvb, gint offset, packet_info *pinfo,
        proto_tree *tree)
{
    gint        offset_start;
    proto_item *pi;
    guint8      tag, len_byte;
    proto_item *ti           = NULL;
    proto_tree *ca_desc_tree = NULL;

    offset_start = offset;

    tag = tvb_get_guint8(tvb,offset);
    if (tag != CA_DESC_TAG) {
        /* we could skip unknown descriptors and make this a warning */
        pi = proto_tree_add_text(tree, tvb, offset, 1, "Invalid descriptor");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "The ca_pmt shall only contain ca descriptors (tag 0x9)");
        return 0;
    }
    if (tree) {
        ti = proto_tree_add_text(
                tree, tvb, offset_start, -1, "Conditional Access descriptor");
        ca_desc_tree = proto_item_add_subtree(ti, ett_dvbci_ca_desc);
    }
    offset++;

    len_byte = tvb_get_guint8(tvb,offset);
    proto_tree_add_item(
            ca_desc_tree, hf_dvbci_descr_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(
            ca_desc_tree, hf_dvbci_ca_sys_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(
            ca_desc_tree, hf_dvbci_ca_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if ((len_byte-4) != 0) {
        proto_tree_add_text(
                ca_desc_tree, tvb, offset, len_byte-4, "private data");
        offset += (len_byte-4);
    }

    proto_item_set_len(ti, offset-offset_start);
    return offset-offset_start;
}


/* dissect an elementary stream entry in the ca_pmt */
static gint
dissect_es(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti      = NULL;
    proto_tree *es_tree = NULL;
    gint        offset_start, ca_desc_len;
    gint        es_info_len, all_len;

    offset_start = offset;

    if (tree) {
        ti = proto_tree_add_text(
                tree, tvb, offset_start, -1, "Elementary Stream");
        es_tree = proto_item_add_subtree(ti, ett_dvbci_application);
    }

    proto_tree_add_item(
            es_tree, hf_dvbci_stream_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(
            es_tree, hf_dvbci_es_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    es_info_len = tvb_get_ntohs(tvb, offset) & 0x0FFF;
    /* the definition of hf_dvbci_es_info_len also applies the mask */
    proto_tree_add_item(
            es_tree, hf_dvbci_es_info_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (es_info_len != 0) {
        all_len = offset + es_info_len;

        proto_tree_add_item(
                es_tree, hf_dvbci_ca_pmt_cmd_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        while (offset < all_len) {
            ca_desc_len = dissect_ca_desc(tvb, offset, pinfo, es_tree);
            if (ca_desc_len <= 0)
                return -1;
            offset += ca_desc_len;
        }
    }
    else {
        proto_tree_add_text(
                es_tree, tvb, 0, 0,
                "No CA descriptors for this elementary stream");
    }

    proto_item_set_len(ti, offset-offset_start);
    return offset-offset_start;
}

/* dissect a text pseudo-apdu */
static gint
dissect_dvbci_text(const gchar *title, tvbuff_t *tvb, gint offset,
                   packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *text_tree;
    guint32     tag;
    gint        offset_start;
    gint        len_field;

    offset_start = offset;

    if (!title)
        return 0;

    /* check the tag before setting up the tree */
    tag = tvb_get_ntoh24(tvb, offset);
    if (tag!=T_TEXT_LAST && tag!=T_TEXT_MORE)
        return 0;

    ti = proto_tree_add_text(tree, tvb, offset_start, -1, "%s", title);
    text_tree = proto_item_add_subtree(ti, ett_dvbci_text);

    proto_tree_add_item(text_tree, hf_dvbci_apdu_tag,
            tvb, offset, APDU_TAG_SIZE, ENC_BIG_ENDIAN);
    offset += APDU_TAG_SIZE;
    offset = dissect_ber_length(pinfo, text_tree, tvb, offset, &len_field, NULL);
    dissect_si_string(tvb, offset, len_field, pinfo, text_tree, "Text", FALSE);
    offset += len_field;

    proto_item_set_len(ti, offset-offset_start);
    return (offset-offset_start);
}


static proto_item *
dissect_res_id(tvbuff_t *tvb, gint offset, packet_info *pinfo,
        proto_tree *tree, guint32 res_id, gboolean show_col_info)
{
    proto_item *ti       = NULL;
    proto_tree *res_tree = NULL;
    gint        tvb_data_len;

    /* there's two possible inputs for this function
        the resource id is either in a tvbuff_t (tvb!=NULL, res_id==0)
        or in a guint32 (tvb==NULL, res_id!=0) */

    if (tvb) {
        /* resource id comes in via tvbuff */
        if (res_id!=0)
            return NULL;
        res_id = tvb_get_ntohl(tvb, offset);
        tvb_data_len = RES_ID_LEN;
    }
    else {
        /* resource id comes in via guint32 */
        if (res_id==0)
            return NULL;
        /* we'll call proto_tree_add_...( tvb==NULL, offset==0, length==0 )
           this creates a filterable item without any reference to a tvb */
        offset = 0;
        tvb_data_len = 0;
    }

    if (show_col_info) {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s Version %d",
                val_to_str_const(RES_CLASS(res_id), dvbci_res_class,
                    "Invalid Resource class"),
                RES_VER(res_id));
    }

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, tvb_data_len,
                "Resource ID: 0x%04x", res_id);
        res_tree = proto_item_add_subtree(ti, ett_dvbci_res);

        /* parameter "value" == complete resource id,
           RES_..._MASK will be applied by the hf definition */
        proto_tree_add_uint(res_tree, hf_dvbci_res_id_type,
                  tvb, offset, tvb_data_len, res_id);
        proto_tree_add_uint(res_tree, hf_dvbci_res_class,
                  tvb, offset, tvb_data_len, res_id);
        proto_tree_add_uint(res_tree, hf_dvbci_res_type,
                  tvb, offset, tvb_data_len, res_id);
        proto_tree_add_uint(res_tree, hf_dvbci_res_ver,
                  tvb, offset, tvb_data_len, res_id);
    }

    return ti;
}

/* dissect the body of a resource manager apdu */
static void
dissect_dvbci_payload_rm(guint32 tag, gint len_field,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree)
{
    const gchar *tag_str;
    proto_item  *pi;

    if (tag==T_PROFILE) {
        if (len_field % RES_ID_LEN) {
            tag_str = val_to_str(tag, dvbci_apdu_tag, "Unknown: %d");
            pi = proto_tree_add_text(tree, tvb, 0, APDU_TAG_SIZE,
                   "Invalid APDU length field");
            expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                   "Length field for %s must be a multiple of 4 bytes",
                   tag_str);
            return;
        }

        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            dissect_res_id(tvb, offset, pinfo, tree, 0, FALSE);
            offset += RES_ID_LEN;
        }
    }
}

static void
dissect_dvbci_payload_ap(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree)
{
    guint8  menu_str_len;
    guint8 *menu_string;
    guint8  data_rate;

    if (tag==T_APP_INFO) {
        proto_tree_add_item(tree, hf_dvbci_app_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(
                tree, hf_dvbci_app_manf, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        proto_tree_add_item(
                tree, hf_dvbci_manf_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        menu_str_len = tvb_get_guint8(tvb,offset);
        proto_tree_add_item(
                tree, hf_dvbci_menu_str_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* ephemeral -> string is freed automatically when dissection
           of this packet is finished
           tvb_get_ephemeral_string() always returns a 0-terminated string */
        menu_string = tvb_get_ephemeral_string(tvb, offset, menu_str_len);
        if (menu_string) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                    "Module name %s", menu_string);
            proto_tree_add_text(tree, tvb, offset, menu_str_len,
                    "Menu string: %s", menu_string);
        }
    }
    else if (tag== T_DATARATE_INFO) {
        data_rate = tvb_get_guint8(tvb, offset);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s",
                    val_to_str(data_rate, dvbci_data_rate, "unknown (0x%x)"));
        proto_tree_add_item(tree, hf_dvbci_data_rate, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
}

static void
dissect_dvbci_payload_ca(guint32 tag, gint len_field,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree)
{
    const gchar *tag_str;
    proto_item  *pi;
    guint16      prog_num;
    guint8       byte;
    guint        prog_info_len;
    gint         es_info_len, all_len;
    gint         ca_desc_len;
    proto_tree  *es_tree = NULL;
    gboolean     desc_ok = FALSE;


    if (tag==T_CA_INFO) {
        if (len_field % 2) {
            tag_str = val_to_str(tag, dvbci_apdu_tag, "Unknown: %d");
            pi = proto_tree_add_text(tree, tvb, 0, APDU_TAG_SIZE,
                    "Invalid APDU length field");
            expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                    "Length field for %s must be a multiple of 2 bytes",
                    tag_str);
            return;
        }

        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(
                    tree, hf_dvbci_ca_sys_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
    }
    else if (tag==T_CA_PMT) {
        proto_tree_add_item(
                tree, hf_dvbci_ca_pmt_list_mgmt, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        prog_num = tvb_get_ntohs(tvb, offset);
        col_append_sep_fstr(
                pinfo->cinfo, COL_INFO, NULL, "Program number %x", prog_num);
        proto_tree_add_item(
                tree, hf_dvbci_prog_num, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        byte = tvb_get_guint8(tvb,offset);
        proto_tree_add_text(tree, tvb, offset, 1,
                "Version number: 0x%x, Current-next indicator: 0x%x",
                (byte&0x3E) >> 1, byte&0x01);
        offset++;
        prog_info_len = tvb_get_ntohs(tvb, offset) & 0x0FFF;
        /* the definition of hf_dvbci_prog_info_len also applies the mask */
        proto_tree_add_item(
                tree, hf_dvbci_prog_info_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        if (prog_info_len != 0) {
            all_len = offset + prog_info_len;

            proto_tree_add_item(
                    tree, hf_dvbci_ca_pmt_cmd_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            while (offset < all_len) {
                ca_desc_len = dissect_ca_desc(tvb, offset, pinfo, tree);
                if (ca_desc_len <= 0)
                    return;
                offset += ca_desc_len;
            }
        }
        else {
            proto_tree_add_text(
                    tree, tvb, 0, 0, "No CA descriptors at program level");
        }

        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            es_info_len = dissect_es(tvb, offset, pinfo, tree);
            if (es_info_len <= 0)
                return;
            offset += es_info_len;
        }
    }
    else if (tag==T_CA_PMT_REPLY) {
        prog_num = tvb_get_ntohs(tvb, offset);
        col_append_sep_fstr(
                pinfo->cinfo, COL_INFO, NULL, "Program number %x", prog_num);
        proto_tree_add_item(
                tree, hf_dvbci_prog_num, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        byte = tvb_get_guint8(tvb,offset);
        proto_tree_add_text(tree, tvb, offset, 1,
                "Version number: 0x%x, Current-next indicator: 0x%x",
                (byte&0x3E) >> 1, byte&0x01);
        offset++;
        desc_ok |= dissect_ca_enable(tvb, offset, pinfo, tree);
        offset++;
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            /* there's no need to check for tree==NULL */
            pi = proto_tree_add_text(tree, tvb, offset, 3, "Elementary Stream");
            es_tree = proto_item_add_subtree(pi, ett_dvbci_application);

            proto_tree_add_item(es_tree, hf_dvbci_es_pid,
                    tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            desc_ok |= dissect_ca_enable(tvb, offset, pinfo, es_tree);
            offset++;
        }
        if (desc_ok) {
            col_append_sep_fstr(
                pinfo->cinfo, COL_INFO, NULL, "descrambling possible");
        }
     }
}


static void
dissect_dvbci_payload_aut(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo _U_, proto_tree *tree)
{
    gint bytes_len;

    proto_tree_add_item(tree, hf_dvbci_auth_proto_id,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    bytes_len = tvb_reported_length_remaining(tvb, offset);
    if (bytes_len <= 0)
        return;

    if (tag==T_AUTH_REQ) {
        proto_tree_add_item(tree, hf_dvbci_auth_req_bytes,
            tvb, offset, bytes_len, ENC_NA);
    }
    else if (tag==T_AUTH_RESP) {
        proto_tree_add_item(tree, hf_dvbci_auth_resp_bytes,
            tvb, offset, bytes_len, ENC_NA);
    }
}


static void
dissect_dvbci_payload_hc(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree)
{
    proto_item *pi;
    guint16     nid, onid, tsid, svcid;
    guint8      ref;
    guint16     old_pid, new_pid;
    gboolean    pmt_flag;
    gint        desc_loop_len;
    tvbuff_t   *pmt_tvb = NULL;
    guint8      status;


    switch (tag) {
        case T_TUNE:
            nid = tvb_get_ntohs(tvb, offset);
            pi = proto_tree_add_item(
                    tree, hf_dvbci_network_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            if (nid) {
                expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_NOTE,
                        "Network ID is usually ignored by hosts");
            }
            offset += 2;
            onid = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(tree, hf_dvbci_original_network_id,
                    tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            tsid = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(tree, hf_dvbci_transport_stream_id,
                    tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            svcid = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(
                    tree, hf_dvbci_service_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ",
                    "nid 0x%x, onid 0x%x, tsid 0x%x, svcid 0x%x",
                    nid, onid, tsid, svcid);
            break;
        case T_REPLACE:
            ref = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_dvbci_replacement_ref,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            old_pid = tvb_get_ntohs(tvb, offset) & 0x1FFF;
            proto_tree_add_item(tree, hf_dvbci_replaced_pid,
                    tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            new_pid = tvb_get_ntohs(tvb, offset) & 0x1FFF;
            proto_tree_add_item( tree, hf_dvbci_replacement_pid,
                    tvb, offset, 2, ENC_BIG_ENDIAN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ",
                    "ref 0x%x, 0x%x -> 0x%x", ref, old_pid, new_pid);
            break;
        case T_CLEAR_REPLACE:
            ref = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_dvbci_replacement_ref,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "ref 0x%x", ref);
            break;
        case T_TUNE_BROADCAST_REQ:
            pmt_flag = ((tvb_get_guint8(tvb, offset) & 0x01) == 0x01);
            proto_tree_add_item(tree, hf_dvbci_pmt_flag,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(
                    tree, hf_dvbci_service_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            desc_loop_len = dissect_desc_loop(hf_dvbci_hc_desc_loop_len,
                                tvb, offset, pinfo, tree);
            if (desc_loop_len<0)
                break;
            offset += desc_loop_len;
            if (pmt_flag) {
                pmt_tvb = tvb_new_subset_remaining(tvb, offset);
                if (mpeg_pmt_handle) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", ");
                    /* prevent mpeg_pmt dissector from clearing col_info */
                    col_set_fence(pinfo->cinfo, COL_INFO);
                    call_dissector(mpeg_pmt_handle, pmt_tvb, pinfo, tree);
                }
                else
                    call_dissector(data_handle, pmt_tvb, pinfo, tree);
            }
            break;
        case T_TUNE_REPLY:
            status = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_dvbci_hc_status,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ",
                        (status == HC_STAT_OK ?  "ok" : "error"));
            break;
        case T_ASK_RELEASE_REPLY:
            proto_tree_add_item(tree, hf_dvbci_hc_release_reply,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        default:
            break;
    }
}


static void
dissect_dvbci_payload_dt(guint32 tag, gint len_field,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree)
{
    nstime_t     resp_intv;
    proto_item  *pi = NULL;
    const gchar *tag_str;
    gint         time_field_len;
    nstime_t     utc_time;
    gint16       local_offset;  /* field in the apdu */


    if (tag==T_DATE_TIME_ENQ) {
        nstime_set_zero(&resp_intv);
        resp_intv.secs = tvb_get_guint8(tvb, offset);
        pi = proto_tree_add_time_format(tree, hf_dvbci_resp_intv,
                tvb, offset, 1, &resp_intv, "Response interval is %s",
                rel_time_to_str(&resp_intv));
        if (resp_intv.secs==0) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "individual query");
            if (pi)
                proto_item_append_text(pi, " (individual query)");
        }
        else {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                    "update every %s", rel_time_to_str(&resp_intv));
        }
    }
    else if (tag==T_DATE_TIME) {
        if (len_field!=5 && len_field!=7) {
            tag_str = match_strval(tag, dvbci_apdu_tag);
            pi = proto_tree_add_text(tree, tvb, APDU_TAG_SIZE, offset-APDU_TAG_SIZE,
                    "Invalid APDU length field");
            expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                    "Length field for %s must be 5 or 7 bytes", tag_str);
            return;
        }

        time_field_len = read_utc_time(tvb, offset, &utc_time);
        if (time_field_len<0) {
            pi = proto_tree_add_text(
                tree, tvb, offset, 5, "Invalid UTC time field");
            expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "2 bytes MJD, 3 bytes BCD time hhmmss");
            return;
        }
        proto_tree_add_time_format(tree, hf_dvbci_utc_time,
                tvb, offset, time_field_len, &utc_time,
                "%s UTC", abs_time_to_str(&utc_time, ABSOLUTE_TIME_UTC, FALSE));
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s UTC",
                abs_time_to_str(&utc_time, ABSOLUTE_TIME_UTC, FALSE));
        offset += time_field_len;

        if (len_field==7) {
            local_offset = two_comp_to_int16(tvb_get_ntohs(tvb, offset));
            proto_tree_add_int_format(tree, hf_dvbci_local_offset,
                    tvb, offset, 2, local_offset,
                    "offset between UTC and local time is %d minutes",
                    local_offset);
        }
        else {
            proto_tree_add_text(tree, tvb, 0, 0,
                    "Offset between UTC and local time is unknown");
        }
    }
}


static void
dissect_dvbci_payload_mmi(guint32 tag, gint len_field,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree)
{
    gint         offset_start;
    proto_item  *pi;
    guint8       close_mmi_cmd_id;
    guint8       disp_ctl_cmd, disp_rep_id;
    const gchar *disp_ctl_cmd_str = NULL, *disp_rep_id_str = NULL;
    guint8       ans_txt_len;
    guint8       ans_id;
    guint8       choice_or_item_nb;
    gint         text_len;
    guint8       choice_ref;


    offset_start = offset;

    switch(tag) {
        case T_CLOSE_MMI:
            close_mmi_cmd_id = tvb_get_guint8(tvb,offset);
            proto_tree_add_item(tree, hf_dvbci_close_mmi_cmd_id,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            /* apdu layer len field checks are sufficient for "immediate" */
            if (close_mmi_cmd_id == CLOSE_MMI_CMD_ID_DELAY) {
                if (len_field != 2) {
                    pi = proto_tree_add_text(tree, tvb,
                            APDU_TAG_SIZE, offset_start-APDU_TAG_SIZE,
                            "Length field mismatch");
                    expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                            "Length field must be 2");
                    return;
                }
                proto_tree_add_item(tree, hf_dvbci_close_mmi_delay, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
            }
            break;
        case T_DISPLAY_CONTROL:
            disp_ctl_cmd = tvb_get_guint8(tvb,offset);
            disp_ctl_cmd_str = val_to_str_const(disp_ctl_cmd,
                                                dvbci_disp_ctl_cmd, "unknown command");
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ",
                    "%s", disp_ctl_cmd_str);
            proto_tree_add_item(tree, hf_dvbci_disp_ctl_cmd, tvb,
                    offset, 1, ENC_BIG_ENDIAN);
            offset++;
            if (disp_ctl_cmd == DISP_CMD_SET_MMI_MODE)
            {
                proto_tree_add_item(tree, hf_dvbci_mmi_mode, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
                if (len_field != 2) {
                    pi = proto_tree_add_text(tree, tvb,
                            APDU_TAG_SIZE, offset_start-APDU_TAG_SIZE,
                            "Length field mismatch");
                    expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                            "Length field must be 2");
                    return;
                }
            }
            break;
        case T_DISPLAY_REPLY:
            disp_rep_id = tvb_get_guint8(tvb,offset);
            disp_rep_id_str = val_to_str_const(disp_rep_id,
                    dvbci_disp_rep_id, "unknown command");
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ",
                    "%s", disp_rep_id_str);
            proto_tree_add_item(tree, hf_dvbci_disp_rep_id,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            if (disp_rep_id == DISP_REP_ID_MMI_MODE_ACK) {
                proto_tree_add_item(tree, hf_dvbci_mmi_mode,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
            }
            else if (disp_rep_id == DISP_REP_ID_DISP_CHAR_TBL ||
                     disp_rep_id == DISP_REP_ID_INP_CHAR_TBL) {
                while (tvb_reported_length_remaining(tvb, offset) > 0) {
                    proto_tree_add_item(tree, hf_dvbci_char_tbl,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                 }
            }
            break;
        case T_ENQ:
            proto_tree_add_item(tree, hf_dvbci_blind_ans,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            ans_txt_len = tvb_get_guint8(tvb,offset);
            if (ans_txt_len == NB_UNKNOWN) {
                proto_tree_add_text(tree, tvb, offset, 1,
                        "Length of expected answer is unknown");
            }
            else
                proto_tree_add_item(tree, hf_dvbci_ans_txt_len,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            dissect_si_string(tvb, offset,
                    tvb_reported_length_remaining(tvb, offset),
                    pinfo, tree, "Enquiry string", FALSE);
            break;
        case T_ANSW:
            ans_id = tvb_get_guint8(tvb,offset);
            proto_tree_add_item(tree, hf_dvbci_ans_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            if (ans_id == ANSW_ID_ANSWER) {
                dissect_si_string(tvb, offset,
                    tvb_reported_length_remaining(tvb, offset),
                    pinfo, tree, "Answer", TRUE);
            }
            break;
        case T_MENU_LAST:
        case T_MENU_MORE:
        case T_LIST_LAST:
        case T_LIST_MORE:
            choice_or_item_nb = tvb_get_guint8(tvb,offset);
            if (choice_or_item_nb == NB_UNKNOWN)
            {
                proto_tree_add_text(tree, tvb, offset, 1,
                        "Number of items is unknown");
            }
            else
            {
                if (IS_MENU_APDU(tag)) {
                    proto_tree_add_item(
                            tree, hf_dvbci_choice_nb, tvb, offset, 1, ENC_BIG_ENDIAN);
                }
                else {
                    proto_tree_add_item(
                            tree, hf_dvbci_item_nb, tvb, offset, 1, ENC_BIG_ENDIAN);
                }
            }
            offset++;
            text_len = dissect_dvbci_text("Title", tvb, offset, pinfo, tree);
            offset += text_len;
            text_len = dissect_dvbci_text("Sub-title", tvb, offset, pinfo, tree);
            offset += text_len;
            text_len = dissect_dvbci_text("Bottom line", tvb, offset, pinfo, tree);
            offset += text_len;
            while (tvb_reported_length_remaining(tvb, offset) > 0) {
                text_len = dissect_dvbci_text("Item", tvb, offset, pinfo, tree);
                /* minimum is apdu tag + 1 byte len field */
                if (text_len<APDU_TAG_SIZE+1) {
                    pi = proto_tree_add_text(
                            tree, tvb, offset, -1, "Invalid item");
                    expert_add_info_format(
                            pinfo, pi, PI_MALFORMED, PI_ERROR,
                            "Items must be text_more() or text_last() objects");
                    return;
                }
                offset += text_len;
            }
            break;
        case T_MENU_ANSW:
            choice_ref = tvb_get_guint8(tvb,offset);
            if (choice_ref == 0x0) {
                proto_tree_add_text(tree, tvb, offset, 1,
                        "Selection was cancelled.");
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ",
                        "cancelled");
            }
            else {
                proto_tree_add_item(
                        tree, hf_dvbci_choice_ref, tvb, offset, 1, ENC_BIG_ENDIAN);
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ",
                        "Item %d", choice_ref);
            }
            break;
        default:
            break;
    }
}


static void
dissect_dvbci_payload_hlc(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree)
{
  guint8 *str;

  if (tag==T_HOST_COUNTRY) {
      proto_tree_add_item(tree, hf_dvbci_host_country,
              tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_ASCII|ENC_NA);
  }
  else if (tag==T_HOST_LANGUAGE) {
      proto_tree_add_item(tree, hf_dvbci_host_language,
              tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_ASCII|ENC_NA);
  }

  /* both apdus' body is only a country code, this can be shared */
  str = tvb_get_ephemeral_string(tvb, offset,
              tvb_reported_length_remaining(tvb, offset));
  if (str)
      col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s", str);
}


static void
dissect_dvbci_payload_cup(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree)
{
  guint8      upgrade_type;
  guint16     download_time;
  guint8      answer, progress;
  proto_item *pi;

  switch(tag) {
    case T_CAM_FIRMWARE_UPGRADE:
      upgrade_type = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(tree, hf_dvbci_cup_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "(%s)",
                    val_to_str_const(upgrade_type, dvbci_cup_type, "unknown"));
      offset++;
      download_time = tvb_get_ntohs(tvb, offset);
      if (download_time == 0) {
          proto_tree_add_uint_format(tree, hf_dvbci_cup_download_time,
                  tvb, offset, 2, download_time,
                  "estimated download time is unknown");
      }
      else {
          proto_tree_add_uint_format(tree, hf_dvbci_cup_download_time,
                  tvb, offset, 2, download_time,
                  "estimated download time is %d seconds",
                  download_time);
      }
      break;
    case T_CAM_FIRMWARE_UPGRADE_REPLY:
      answer = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(tree, hf_dvbci_cup_answer, tvb, offset, 1, ENC_BIG_ENDIAN);
      col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s",
                    val_to_str_const(answer, dvbci_cup_answer, "unknown"));
      break;
    case T_CAM_FIRMWARE_UPGRADE_PROGRESS:
      progress = tvb_get_guint8(tvb, offset);
      if (progress > 100) {
        pi = proto_tree_add_text(tree, tvb, offset, 1,
                "Invalid value for progress");
        expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                "progress is in percent, value must be between 0 and 100");
      }
      else {
          col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%d%%", progress);
          proto_tree_add_uint_format(tree, hf_dvbci_cup_progress,
                  tvb, offset, 1, progress,
                  "download progress %d%%", progress);
      }
      break;
    case T_CAM_FIRMWARE_UPGRADE_COMPLETE:
      proto_tree_add_item(tree, hf_dvbci_cup_reset, tvb, offset, 1, ENC_BIG_ENDIAN);
      break;
    default:
      break;
  }
}


static void
dissect_dvbci_payload_cc(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree)
{
    guint8      status;
    guint32     msg_ctr;
    guint8      enc_flag, enc_cip;
    proto_item *pi                   = NULL, *ti;
    guint16     sac_payload_len;          /* payload data and padding */
    gint        sac_payload_data_len = 0; /* just payload data */
    tvbuff_t   *clear_sac_body_tvb;
    proto_tree *sac_tree             = NULL;
    nstime_t    utc_time;
    guint8      pin_stat;
    guint8      evt_cent;

    switch(tag) {
        case T_CC_OPEN_CNF:
            proto_tree_add_item(tree, hf_dvbci_cc_sys_id_bitmask,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        case T_CC_DATA_REQ:
        case T_CC_DATA_CNF:
            dissect_cc_data_payload(tag, tvb, offset, pinfo, tree);
            break;
        case T_CC_SYNC_CNF:
            status = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(
                    tree, hf_dvbci_cc_status_field, tvb, offset, 1, ENC_BIG_ENDIAN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s",
                    val_to_str_const(status, dvbci_cc_status, "unknown"));
            break;
        case T_CC_SAC_DATA_REQ:
        case T_CC_SAC_DATA_CNF:
        case T_CC_SAC_SYNC_REQ:
        case T_CC_SAC_SYNC_CNF:
            /* it's not useful to move sac header dissection to a separate
                function, we need enc/auth cipher etc here to handle the body */
            msg_ctr = tvb_get_ntohl(tvb, offset);
            proto_tree_add_item(
                    tree, hf_dvbci_sac_msg_ctr, tvb, offset, 4, ENC_BIG_ENDIAN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                    "message #%d", msg_ctr);
            offset += 4;
            proto_tree_add_item(
                    tree, hf_dvbci_sac_proto_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(
                    tree, hf_dvbci_sac_auth_cip, tvb, offset, 1, ENC_BIG_ENDIAN);
            enc_flag = tvb_get_guint8(tvb, offset) & 0x1;
            proto_tree_add_item(
                    tree, hf_dvbci_sac_payload_enc, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            enc_cip = (tvb_get_guint8(tvb, offset)&0xE0) >> 5;
            proto_tree_add_item(
                    tree, hf_dvbci_sac_enc_cip, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            sac_payload_len = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(
                    tree, hf_dvbci_sac_payload_len, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            if (tvb_reported_length_remaining(tvb, offset) < 0)
                break;
            if (!enc_flag) {
                pi = proto_tree_add_text(tree, tvb, offset,
                        tvb_reported_length_remaining(tvb, offset),
                        "Invalid CI+ SAC message body");
                expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                        "SAC message body must always be encrypted");
                break;
            }
            clear_sac_body_tvb = decrypt_sac_msg_body(enc_cip,
                    tvb, offset, tvb_reported_length_remaining(tvb, offset));
            if (!clear_sac_body_tvb) {
                /* we could not decrypt the sac message body */
                proto_tree_add_item(tree, hf_dvbci_sac_enc_body, tvb, offset,
                        tvb_reported_length_remaining(tvb, offset), ENC_NA);
                break;
            }
            add_new_data_source(pinfo, clear_sac_body_tvb,
                            "Clear SAC message body");
            if (sac_payload_len>0) {
                ti = proto_tree_add_text(tree,
                        clear_sac_body_tvb, 0, sac_payload_len,
                        "SAC message payload");
                sac_tree = proto_item_add_subtree(ti, ett_dvbci_sac_msg_body);
                if (tag==T_CC_SAC_DATA_REQ || tag==T_CC_SAC_DATA_CNF) {
                    sac_payload_data_len = dissect_cc_data_payload(tag,
                        clear_sac_body_tvb, 0, pinfo, sac_tree);
                }
                else if (tag==T_CC_SAC_SYNC_REQ) {
                    sac_payload_data_len = 0;
                }
                else if (tag==T_CC_SAC_SYNC_CNF) {
                    proto_tree_add_item(sac_tree, hf_dvbci_cc_status_field,
                        clear_sac_body_tvb, 0, 1, ENC_BIG_ENDIAN);
                    sac_payload_data_len = 1;
                }

                if (sac_payload_data_len < 0)
                    break;
                if (sac_payload_len > sac_payload_data_len) {
                    proto_tree_add_text(sac_tree, clear_sac_body_tvb,
                            sac_payload_data_len,
                            sac_payload_len-sac_payload_data_len,
                            "padding");
                }
            }
            proto_tree_add_item(tree, hf_dvbci_sac_signature,
                clear_sac_body_tvb, sac_payload_len,
                tvb_reported_length_remaining(clear_sac_body_tvb,
                    sac_payload_len), ENC_NA);
            break;
        case T_CC_PIN_CAPABILITIES_REPLY:
            proto_tree_add_item(tree, hf_dvbci_capability_field,
                    tvb, offset, 1 , ENC_BIG_ENDIAN);
            offset++;
            /* we can't read_utc_time() and check with nstime_is_zero() */
            if (tvb_get_ntoh40(tvb, offset) == 0) {
                proto_tree_add_text(tree, tvb, offset, UTC_TIME_LEN,
                        "CICAM PIN has never been changed");
            }
            else {
                if (read_utc_time(tvb, offset, &utc_time) < 0) {
                    pi = proto_tree_add_text(tree, tvb, offset, UTC_TIME_LEN,
                            "Invalid UTC time field");
                    expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                            "2 bytes MJD, 3 bytes BCD time hhmmss");
                    break;
                }
                else {
                    /* abs_time_to_str() never returns NULL */
                    proto_tree_add_time_format(tree, hf_dvbci_pin_chg_time,
                            tvb, offset, UTC_TIME_LEN, &utc_time,
                            "PIN change time %s UTC",
                            abs_time_to_str(&utc_time, ABSOLUTE_TIME_UTC, FALSE));
                }
            }
            offset += UTC_TIME_LEN;
            dissect_rating(tvb, offset, pinfo, tree);
            break;
        case T_CC_PIN_REPLY:
            pin_stat = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_dvbci_pincode_status,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s",
                    val_to_str_const(pin_stat, dvbci_pincode_status, "unknown"));
            break;
        case T_CC_PIN_EVENT:
            proto_tree_add_item(tree, hf_dvbci_cc_prog_num,
                    tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_dvbci_pincode_status,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            dissect_rating(tvb, offset, pinfo, tree);
            offset++;
            if (read_utc_time(tvb, offset, &utc_time) < 0) {
                pi = proto_tree_add_text(tree, tvb, offset, UTC_TIME_LEN,
                        "Invalid UTC time field");
                expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                        "2 bytes MJD, 3 bytes BCD time hhmmss");
                break;
            }
            else {
                proto_tree_add_time_format(tree, hf_dvbci_pin_evt_time,
                        tvb, offset, UTC_TIME_LEN, &utc_time,
                        "PIN event time %s UTC",
                        abs_time_to_str(&utc_time, ABSOLUTE_TIME_UTC, FALSE));
            }
            offset += UTC_TIME_LEN;
            evt_cent = tvb_get_guint8(tvb, offset);
            if (evt_cent > 100) {
                pi = proto_tree_add_text(tree, tvb, offset, 1,
                "Invalid value for event time centiseconds");
                expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                "Value must be between 0 and 100");
            }
            proto_tree_add_item(tree, hf_dvbci_pin_evt_cent,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            /* length field was already checked by the caller */
            proto_tree_add_item(tree, hf_dvbci_cc_priv_data, tvb, offset,
                    tvb_reported_length_remaining(tvb, offset), ENC_NA);
            break;
        case T_CC_PIN_PLAYBACK:
            dissect_rating(tvb, offset, pinfo, tree);
            offset++;
            /* length field was already checked by the caller */
            proto_tree_add_item(tree, hf_dvbci_cc_priv_data, tvb, offset,
                    tvb_reported_length_remaining(tvb, offset), ENC_NA);
            break;
        case T_CC_PIN_CMD:
        case T_CC_PIN_MMI_REQ:
            proto_tree_add_item(tree, hf_dvbci_pincode, tvb, offset,
                    tvb_reported_length_remaining(tvb, offset),
                    ENC_ASCII|ENC_NA);
            break;
        default:
            break;
    }
}


static void
dissect_dvbci_payload_ami(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree)
{
    guint8      app_dom_id_len, init_obj_len;
    guint8     *app_dom_id;
    guint8      ack_code;
    gboolean    req_ok   = FALSE, file_ok;
    guint8      req_type;
    guint8     *req_str;
    guint8      file_name_len;
    guint8     *file_name_str;
    guint32     file_data_len;
    proto_item *ti       = NULL;
    proto_tree *req_tree = NULL;

    switch(tag) {
        case T_REQUEST_START:
            /* no filter for length items */
            app_dom_id_len = tvb_get_guint8(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 1,
                    "Application Domain Identifier length %d", app_dom_id_len);
            offset++;
            init_obj_len = tvb_get_guint8(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 1,
                    "Initial Object length %d", init_obj_len);
            offset++;
            proto_tree_add_item(tree, hf_dvbci_app_dom_id,
                    tvb, offset, app_dom_id_len, ENC_ASCII|ENC_NA);
            app_dom_id = tvb_get_ephemeral_string(tvb, offset, app_dom_id_len);
            if (app_dom_id) {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ",
                        "for %s", app_dom_id);
            }
            offset += app_dom_id_len;
            proto_tree_add_item(tree, hf_dvbci_init_obj,
                    tvb, offset, init_obj_len, ENC_ASCII|ENC_NA);
            break;
        case T_REQUEST_START_ACK:
            ack_code = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(
                    tree, hf_dvbci_ack_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s",
                    val_to_str_const(ack_code, dvbci_ack_code, "unknown"));
            break;
        case T_FILE_REQUEST:
            req_type = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_dvbci_req_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s",
                    val_to_str_const(req_type, dvbci_req_type, "unknown"));
            offset++;
            if (req_type==REQ_TYPE_FILE_HASH) {
                proto_tree_add_item(tree, hf_dvbci_file_hash,
                        tvb, offset, 16, ENC_NA);
                offset += 16;
            }
            if (tvb_reported_length_remaining(tvb, offset) <= 0)
              break;
            if (req_type==REQ_TYPE_FILE || req_type==REQ_TYPE_FILE_HASH) {
                req_str = tvb_get_ephemeral_string(tvb, offset,
                        tvb_reported_length_remaining(tvb, offset));
                if (!req_str)
                    break;
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", req_str);
                proto_tree_add_string_format_value(tree, hf_dvbci_file_name,
                        tvb, offset, tvb_reported_length_remaining(tvb, offset),
                        req_str, "%s", req_str);
            }
            else if (req_type==REQ_TYPE_DATA) {
                proto_tree_add_item(tree, hf_dvbci_ami_priv_data, tvb, offset,
                        tvb_reported_length_remaining(tvb, offset), ENC_NA);
            }
            break;
        case T_FILE_ACKNOWLEDGE:
            req_type = tvb_get_guint8(tvb, offset+1);
            if (req_type==REQ_TYPE_FILE_HASH) {
                req_ok = ((tvb_get_guint8(tvb, offset) & 0x02) == 0x02);
                proto_tree_add_item(tree, hf_dvbci_req_ok,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
            }
            file_ok = ((tvb_get_guint8(tvb, offset) & 0x01) == 0x01);
            proto_tree_add_item(tree, hf_dvbci_file_ok, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_dvbci_req_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s",
                    val_to_str_const(req_type, dvbci_req_type, "unknown"));
            offset++;
            if (req_type==REQ_TYPE_FILE || req_type==REQ_TYPE_FILE_HASH) {
                file_name_len = tvb_get_guint8(tvb, offset);
                proto_tree_add_text(tree, tvb, offset, 1,
                        "File name length %d", file_name_len);
                offset++;
                file_name_str = tvb_get_ephemeral_string(
                        tvb, offset, file_name_len);
                if (!file_name_str)
                    break;
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ",
                        "%s", file_name_str);
                proto_tree_add_string_format_value(tree, hf_dvbci_file_name,
                        tvb, offset, file_name_len, file_name_str,
                        "%s", file_name_str);
                offset += file_name_len;
                file_data_len = tvb_get_ntohl(tvb, offset);
                proto_tree_add_text(tree, tvb, offset, 4,
                        "File data length %d", file_data_len);
                offset += 4;
                if (file_data_len > 0) {
                    proto_tree_add_item(tree, hf_dvbci_file_data,
                            tvb, offset, file_data_len, ENC_NA);
                }
             }
            else if (req_type==REQ_TYPE_DATA) {
                if (tvb_reported_length_remaining(tvb, offset) <= 0)
                    break;
                proto_tree_add_item(tree, hf_dvbci_ami_priv_data, tvb, offset,
                        tvb_reported_length_remaining(tvb, offset), ENC_NA);
            }
            else if (req_type==REQ_TYPE_REQ) {
                if (tree) {
                    ti = proto_tree_add_text(tree, tvb,
                            offset, tvb_reported_length_remaining(tvb, offset),
                            "Supported request types");
                    req_tree = proto_item_add_subtree(
                            ti, ett_dvbci_ami_req_types);
                }
                while (tvb_reported_length_remaining(tvb, offset) > 0) {
                    proto_tree_add_item(req_tree, hf_dvbci_req_type,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                }
            }

            if (req_type==REQ_TYPE_FILE_HASH && req_ok && !file_ok) {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                        "cached copy is valid");
            }
            break;
        case T_APP_ABORT_REQUEST:
            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                proto_tree_add_item(tree, hf_dvbci_abort_req_code, tvb, offset,
                        tvb_reported_length_remaining(tvb, offset), ENC_NA);
            }
            break;
        case T_APP_ABORT_ACK:
            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                proto_tree_add_item(tree, hf_dvbci_abort_ack_code, tvb, offset,
                        tvb_reported_length_remaining(tvb, offset), ENC_NA);
            }
            break;
        default:
            break;
    }
}


static void
dissect_dvbci_payload_lsc(guint32 tag, gint len_field,
        tvbuff_t *tvb, gint offset, circuit_t *circuit,
        packet_info *pinfo, proto_tree *tree)
{
    gint                offset_start;
    guint8              id, timeout, ret_val, phase_id;
    gint                conn_desc_len, param_len;
    guint16             buf_size;
    proto_item         *pi          = NULL;
    const gchar        *ret_val_str = NULL;
    gint                msg_len;
    tvbuff_t           *msg_tvb;
    dissector_handle_t  msg_handle;

    offset_start = offset;

    switch(tag) {
        case T_COMMS_CMD:
            proto_tree_add_item(tree, hf_dvbci_comms_cmd_id,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            id = tvb_get_guint8(tvb, offset);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s",
                    val_to_str(id, dvbci_comms_cmd_id, "Unknown: %d"));
            offset++;
            switch(id) {
                case COMMS_CMD_ID_CONNECT_ON_CHANNEL:
                    conn_desc_len = dissect_conn_desc(tvb, offset,
                            circuit, pinfo, tree);
                    if (conn_desc_len < 0)
                        break;
                    offset += conn_desc_len;
                    proto_tree_add_item(tree, hf_dvbci_lsc_retry_count,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    timeout = tvb_get_guint8(tvb, offset);
                    if (timeout==0) {
                        proto_tree_add_uint_format(tree, hf_dvbci_lsc_timeout,
                                tvb, offset, 1, timeout, "Infinite timeout");
                    } else {
                        proto_tree_add_uint_format(tree, hf_dvbci_lsc_timeout,
                                tvb, offset, 1, timeout,
                                "Timeout is %d seconds", timeout);
                    }
                    break;
                case COMMS_CMD_ID_DISCONNECT_ON_CHANNEL:
                case COMMS_CMD_ID_ENQUIRE_STATUS:
                    /* len_field == 1 -> only id, no further parameters */
                    if (len_field != 1) {
                        pi = proto_tree_add_text(tree, tvb,
                            APDU_TAG_SIZE, offset_start-APDU_TAG_SIZE,
                            "Length field mismatch");
                        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                            "Length field must be 1");
                    }
                    break;
                case COMMS_CMD_ID_SET_PARAMS:
                    param_len = tvb_reported_length_remaining(tvb, offset);
                    if (param_len == 2)
                        buf_size = (guint16)tvb_get_guint8(tvb, offset);
                    else if (param_len == 3)
                        buf_size = tvb_get_ntohs(tvb, offset);
                    else {
                        pi = proto_tree_add_text(tree, tvb,
                            APDU_TAG_SIZE, offset_start-APDU_TAG_SIZE,
                            "Length field mismatch");
                        /* length field == 1 byte id + param_len */
                        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                            "Length field must be 3 or 4");
                        break;
                    }
                    proto_tree_add_uint_format(tree, hf_dvbci_lsc_buf_size,
                            tvb, offset, param_len-1, buf_size,
                            "buffer size %d bytes", buf_size);
                    offset += param_len-1;
                    timeout = tvb_get_guint8(tvb, offset);
                    proto_tree_add_uint_format(tree, hf_dvbci_lsc_timeout,
                            tvb, offset, 1, timeout,
                            "timeout is %d milliseconds", timeout*10);
                    break;
                case COMMS_CMD_ID_GET_NEXT_BUFFER:
                    phase_id = tvb_get_guint8(tvb, offset);
                    proto_tree_add_uint_format(tree, hf_dvbci_phase_id,
                            tvb, offset, 1, phase_id, "Phase ID %d", phase_id);
                    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                            "received #%d", phase_id);
                    break;
                default:
                    break;
            }
            break;
        case T_COMMS_REPLY:
            proto_tree_add_item(tree, hf_dvbci_comms_rep_id,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            id = tvb_get_guint8(tvb,offset);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s",
                    val_to_str(id, dvbci_comms_rep_id, "Unknown: %d"));
            offset++;
            ret_val = tvb_get_guint8(tvb,offset);
            pi = proto_tree_add_item(tree, hf_dvbci_lsc_ret_val,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            switch (id) {
                case COMMS_REP_ID_SEND_ACK:
                    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ",
                        "sent #%d", ret_val);
                    if (pi)
                        proto_item_append_text(pi, " (sent #%d)", ret_val);
                    break;
                case COMMS_REP_ID_SET_PARAMS_ACK:
                    ret_val_str = val_to_str_const(ret_val,
                            dvbci_lsc_ret_val_params, "unknown/error");
                    break;
                case COMMS_REP_ID_STATUS_REPLY:
                    ret_val_str = val_to_str_const(ret_val,
                            dvbci_lsc_ret_val_connect, "unknown/error");
                    break;
                default:
                    ret_val_str = val_to_str_const(ret_val,
                            dvbci_lsc_ret_val, "unknown/error");
                    break;
            }
            if (ret_val_str) {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ",
                            "%s", ret_val_str);
                if (pi)
                    proto_item_append_text(pi, " (%s)", ret_val_str);
            }
            break;
        case T_COMMS_SEND_LAST:
        case T_COMMS_SEND_MORE:
        case T_COMMS_RCV_LAST:
        case T_COMMS_RCV_MORE:
            phase_id = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(tree, hf_dvbci_phase_id,
                    tvb, offset, 1, phase_id, "Phase ID %d", phase_id);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ",
                    "Phase ID %d", phase_id);
            offset++;
            msg_len = tvb_reported_length_remaining(tvb, offset);
            if (msg_len<=0)
                break;
            msg_tvb = tvb_new_subset(tvb, offset, msg_len, msg_len);
            if (!msg_tvb)
                break;
            if (dvbci_dissect_lsc_msg && circuit && circuit->dissector_handle) {
                msg_handle = circuit->dissector_handle;
                col_append_fstr(pinfo->cinfo, COL_INFO, ", ");
                col_set_fence(pinfo->cinfo, COL_INFO);
                col_append_fstr(pinfo->cinfo, COL_PROTOCOL, ", ");
                col_set_fence(pinfo->cinfo, COL_PROTOCOL);
            }
            else {
                msg_handle = data_handle;
            }
            if (msg_handle)
                call_dissector(msg_handle, msg_tvb, pinfo, tree);
            break;
        default:
            break;
    }
}


static void
dissect_dvbci_payload_opp(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit _U_,
        packet_info *pinfo, proto_tree *tree)
{
    guint16     nit_loop_len, nit_loop_offset;
    tvbuff_t   *nit_loop_tvb, *nit_loop_partial_tvb;
    guint       dvb_nit_bytes;
    guint8      table_id;
    guint8      cap_loop_len;
    gboolean    info_valid;
    guint8      char_tbl;
    guint8      sig_strength, sig_qual;
    proto_item *pi;

    switch(tag) {
        case T_OPERATOR_STATUS:
        case T_OPERATOR_SEARCH_STATUS:
            dissect_opp_status_body(tvb, offset, pinfo, tree);
          break;
        case T_OPERATOR_NIT:
          nit_loop_len = tvb_get_ntohs(tvb, offset);
          proto_tree_add_item(tree, hf_dvbci_nit_loop_len,
                  tvb, offset, 2, ENC_BIG_ENDIAN);
          if (nit_loop_len==0)
              break;
          offset += 2;
          nit_loop_tvb = tvb_new_subset(
                  tvb, offset, nit_loop_len, nit_loop_len);
          nit_loop_offset = 0;
          if (!dvb_nit_handle) {
              call_dissector(data_handle, nit_loop_tvb, pinfo, tree);
              break;
          }
          /* prevent dvb_nit dissector from clearing the dvb-ci infos */
          col_append_fstr(pinfo->cinfo, COL_INFO, ", ");
          col_set_fence(pinfo->cinfo, COL_INFO);
          do {
              table_id = tvb_get_guint8(nit_loop_tvb, nit_loop_offset);
              if (table_id != TABLE_ID_CICAM_NIT) {
                  pi = proto_tree_add_text(tree,
                          nit_loop_tvb, nit_loop_offset, 1,
                          "Invalid table id for the CICAM NIT");
                  expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                          "CICAM NIT must have table id 0x40 (NIT actual)");
              }
              nit_loop_partial_tvb =
                  tvb_new_subset_remaining(nit_loop_tvb, nit_loop_offset);
              dvb_nit_bytes = call_dissector(
                      dvb_nit_handle, nit_loop_partial_tvb, pinfo, tree);
              nit_loop_offset += dvb_nit_bytes;
              /* offsets go from 0 to nit_loop_len-1 */
          } while (dvb_nit_bytes>0 && nit_loop_offset<nit_loop_len-1);
          break;
        case T_OPERATOR_INFO:
          info_valid = ((tvb_get_guint8(tvb, offset) & 0x08) == 0x08);
          proto_tree_add_item(tree, hf_dvbci_info_valid,
                  tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(tree, hf_dvbci_info_ver_op_info,
                  tvb, offset, 1, ENC_BIG_ENDIAN);
          if (!info_valid)
              break;
          offset++;
          proto_tree_add_item(tree, hf_dvbci_cicam_onid,
                  tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;
          proto_tree_add_item(tree, hf_dvbci_cicam_id,
                  tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
          char_tbl = tvb_get_guint8(tvb, offset);
          if (char_tbl==CHAR_TBL_MULTI_BYTE) {
              /* we display this sligthly differently (i.e. clearer)
                 than the CI+ specification ;-) */
              proto_tree_add_item(tree, hf_dvbci_opp_char_tbl_multi,
                  tvb, offset, 3, ENC_BIG_ENDIAN);
              offset += 3;
          }
          else {
              proto_tree_add_item(tree, hf_dvbci_opp_char_tbl,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
              offset++;
              if (char_tbl==CHAR_TBL_ENC_TYPE_ID) {
                  proto_tree_add_item(tree, hf_dvbci_enc_type_id,
                          tvb, offset, 1, ENC_BIG_ENDIAN);
                  offset++;
              }
          }
          proto_tree_add_item(tree, hf_dvbci_sdt_rst_trusted,
                  tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(tree, hf_dvbci_eit_rst_trusted,
                  tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(tree, hf_dvbci_eit_pf_usage,
                  tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(tree, hf_dvbci_eit_sch_usage,
                  tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(tree, hf_dvbci_ext_evt_usage,
                  tvb, offset, 1, ENC_BIG_ENDIAN);
          offset++;
          proto_tree_add_item(tree, hf_dvbci_sdt_oth_trusted,
                  tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(tree, hf_dvbci_eit_evt_trigger,
                  tvb, offset, 1, ENC_BIG_ENDIAN);
          offset++;
          proto_tree_add_item(tree, hf_dvbci_opp_lang_code,
                  tvb, offset, 3, ENC_ASCII|ENC_NA);
          offset += 3;
          /* hf_dvbci_prof_name is an FT_UINT_STRING, one leading len byte */
          proto_tree_add_item(tree, hf_dvbci_prof_name,
              tvb, offset, 1, ENC_ASCII|ENC_NA);
          break;
        case T_OPERATOR_SEARCH_START:
          proto_tree_add_item(tree, hf_dvbci_unattended,
                  tvb, offset, 1, ENC_BIG_ENDIAN);

          /* no filters for the loop lengths, one is 7bit, others are 8bit */
          cap_loop_len = tvb_get_guint8(tvb, offset) & 0x7F;
          proto_tree_add_text(tree, tvb, offset, 1,
                  "Service type loop length: %d", cap_loop_len);
          offset++;
          /* no need for error checking, we continue anyway */
          dissect_opp_cap_loop(cap_loop_len, "Service type loop",
                  hf_dvbci_opp_srv_type, 1, tvb, offset, pinfo, tree);
          offset += cap_loop_len;

          cap_loop_len = tvb_get_guint8(tvb, offset);
          proto_tree_add_text(tree, tvb, offset, 1,
                  "Delivery system capabilities loop length: %d",
                  cap_loop_len);
          offset++;
          dissect_opp_cap_loop(cap_loop_len,
                  "Delivery system capabilities loop",
                  hf_dvbci_dlv_cap_byte, 1,
                  tvb, offset, pinfo, tree);
          offset += cap_loop_len;

          cap_loop_len = tvb_get_guint8(tvb, offset);
          proto_tree_add_text(tree, tvb, offset, 1,
                  "Application capabilities loop length: %d", cap_loop_len);
          dissect_opp_cap_loop(cap_loop_len,
                  "Application capabilities loop",
                  hf_dvbci_app_cap_bytes, 2,
                  tvb, offset, pinfo, tree);
          break;
        case T_OPERATOR_TUNE_STATUS:
          proto_tree_add_item(tree, hf_dvbci_desc_num,
                  tvb, offset, 1, ENC_BIG_ENDIAN);
          offset++;
          sig_strength = tvb_get_guint8(tvb, offset);
          proto_tree_add_item(tree, hf_dvbci_sig_strength,
                  tvb, offset, 1, ENC_BIG_ENDIAN);
          offset++;
          sig_qual = tvb_get_guint8(tvb, offset);
          proto_tree_add_item(tree, hf_dvbci_sig_qual,
                  tvb, offset, 1, ENC_BIG_ENDIAN);
          if (sig_strength>100 || sig_qual>100) {
              pi = proto_tree_add_text(tree, tvb, offset, 1,
                      "Invalid value for signal strength / signal quality");
              expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                      "Values are in percent (0 to 100)");
          }
          offset++;
          proto_tree_add_item(tree, hf_dvbci_opp_tune_status,
                  tvb, offset, 1, ENC_BIG_ENDIAN);
          dissect_desc_loop(hf_dvbci_opp_desc_loop_len,
                  tvb, offset, pinfo, tree);
          break;
        case T_OPERATOR_TUNE:
          dissect_desc_loop(hf_dvbci_opp_desc_loop_len,
                  tvb, offset, pinfo, tree);
          break;
        default:
          break;
    }
}


static void
dissect_dvbci_payload_sas(guint32 tag, gint len_field _U_,
        tvbuff_t *tvb, gint offset, circuit_t *circuit,
        packet_info *pinfo, proto_tree *tree)
{
    gchar   app_id_str[2+16+1]; /* "0x", string of 16 hex digits, trailing 0 */
    guint8  sas_status;
    dissector_handle_t msg_handle;
    guint8  msg_nb;
    guint16 msg_len;
    tvbuff_t *msg_tvb;

    switch(tag) {
        case T_SAS_CONNECT_RQST:
        case T_SAS_CONNECT_CNF:
            g_snprintf(app_id_str, sizeof(app_id_str),
                    "0x%016" G_GINT64_MODIFIER "x", tvb_get_ntoh64(tvb, offset));
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s", app_id_str);
            proto_tree_add_item(tree, hf_dvbci_sas_app_id,
                    tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;
            if (tag == T_SAS_CONNECT_CNF) {
                sas_status = tvb_get_guint8(tvb, offset);
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                        (sas_status == SAS_SESS_STATE_CONNECTED ?
                         "Ok" : "Error"));
                proto_tree_add_item(tree, hf_dvbci_sas_sess_state,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
                if (!circuit)
                    break;
                if (sas_status == SAS_SESS_STATE_CONNECTED) {
                    msg_handle = dissector_get_string_handle(
                            sas_msg_dissector_table, app_id_str);
                    /* this clears the dissector for msg_handle==NULL */
                    circuit_set_dissector(circuit, msg_handle);
                }
                else
                    circuit_set_dissector(circuit, NULL);
            }
            break;
        case T_SAS_ASYNC_MSG:
            msg_nb = tvb_get_guint8(tvb, offset);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ",
                    "Message #%d ", msg_nb);
            proto_tree_add_item(tree, hf_dvbci_sas_msg_nb,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            msg_len = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(tree, hf_dvbci_sas_msg_len,
                    tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            msg_tvb = tvb_new_subset(tvb, offset, msg_len, msg_len);
            msg_handle = (circuit && circuit->dissector_handle) ?
                circuit->dissector_handle : data_handle;
            call_dissector(msg_handle, msg_tvb, pinfo, tree);
            break;
        default:
          break;
    }
}


static void
dissect_dvbci_apdu(tvbuff_t *tvb, circuit_t *circuit,
        packet_info *pinfo, proto_tree *tree, guint8 direction)
{
    proto_item  *ti;
    proto_tree  *app_tree = NULL;
    guint32      apdu_len, tag, len_field;
    const gchar *tag_str;
    gint         offset;
    proto_item  *pi;
    apdu_info_t *ai;
    guint32      apdu_res_id;
    const gchar *ai_res_class_str;


    apdu_len = tvb_reported_length(tvb);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, 0, apdu_len, "Application Layer");
        app_tree = proto_item_add_subtree(ti, ett_dvbci_application);
    }

    tag = tvb_get_ntoh24(tvb, 0);
    tag_str = match_strval(tag, dvbci_apdu_tag);
    offset = APDU_TAG_SIZE;

    col_set_str(pinfo->cinfo, COL_INFO,
            val_to_str_const(tag, dvbci_apdu_tag, "Unknown/invalid APDU"));
    if (tag_str) {
        proto_tree_add_item(
                app_tree, hf_dvbci_apdu_tag, tvb, 0, APDU_TAG_SIZE, ENC_BIG_ENDIAN);
    }
    else {
        pi = proto_tree_add_text(app_tree, tvb, 0, APDU_TAG_SIZE,
                "Invalid or unsupported APDU tag");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "Invalid or unsupported APDU tag");
        return;
    }

    offset = dissect_ber_length(pinfo, app_tree, tvb, offset, &len_field, NULL);
    if ((offset+len_field) > apdu_len) {
        pi = proto_tree_add_text(app_tree, tvb,
                APDU_TAG_SIZE, offset-APDU_TAG_SIZE,
                "Length field mismatch");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "Length field mismatch");
        return;
    }

    ai = (apdu_info_t *)g_hash_table_lookup(apdu_table,
                                            GUINT_TO_POINTER((guint)tag));
    if (!ai) {
        pi = proto_tree_add_text(
                app_tree, tvb, 0, APDU_TAG_SIZE, "Unknown APDU");
        expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                "Dissection of this APDU is not supported");
        return;
    }
    if (ai->direction!=DIRECTION_ANY && ai->direction!=direction) {
        pi = proto_tree_add_text(app_tree, tvb, 0, APDU_TAG_SIZE,
                "Invalid APDU direction");
        if (ai->direction==DATA_HOST_TO_CAM) {
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                    "This APDU must be sent from host to CAM");
        }
        else {
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                    "This APDU must be sent from CAM to host");
        }
        /* don't return, we can continue dissecting the APDU */
    }
    if (ai->min_len_field!=LEN_FIELD_ANY && len_field<ai->min_len_field) {
        pi = proto_tree_add_text(app_tree, tvb, 0, APDU_TAG_SIZE,
                "Invalid APDU length field");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "Minimum length field for %s is %d",
                tag_str, ai->min_len_field);
        return;
    }
    if (ai->len_field!=LEN_FIELD_ANY && len_field!=ai->len_field) {
        pi = proto_tree_add_text(app_tree, tvb, 0, APDU_TAG_SIZE,
                "Invalid APDU length field");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "Length field for %s must be %d", tag_str, ai->len_field);
        return;
    }
    if (circuit) {
        apdu_res_id = GPOINTER_TO_UINT(
                (gpointer)circuit_get_proto_data(circuit, proto_dvbci));

        ai_res_class_str = val_to_str_const(ai->res_class, dvbci_res_class, "Unknown");

        if(RES_CLASS(apdu_res_id) != ai->res_class) {
            pi = proto_tree_add_text(app_tree, tvb, 0, APDU_TAG_SIZE,
                    "Invalid resource class for this apdu");
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                    "%s can only be sent on a %s session",
                    tag_str, ai_res_class_str);
        }
        if(RES_VER(apdu_res_id) < ai->res_min_ver) {
            pi = proto_tree_add_text(app_tree, tvb, 0, APDU_TAG_SIZE,
                    "Invalid resource version for this apdu");
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                    "%s apdu requires at least %s version %d",
                    tag_str, ai_res_class_str, ai->res_min_ver);
        }
        /* don't return, we can continue dissecting the APDU */
    }
    if (ai->len_field!=0) {
        if (!ai->dissect_payload) {
            /* don't display an error, getting here means we have illegal
             * data in apdu_info[] */
            return;
        }
        ai->dissect_payload(
                tag, len_field, tvb, offset, circuit, pinfo, app_tree);
    }
}

static void
dissect_dvbci_spdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint8 direction)
{
    guint32            spdu_len;
    proto_item        *ti          = NULL;
    proto_tree        *sess_tree   = NULL;
    guint8             tag;
    const gchar       *tag_str;
    circuit_t         *circuit     = NULL;
    proto_item        *pi;
    gint               offset;
    guint32            len_field;
    const spdu_info_t *si;
    proto_item        *res_id_it   = NULL;
    guint32            res_id;
    guint16 ssnb                   = 0;  /* session numbers start with 1, 0 is invalid */
    guint8             sess_stat;
    tvbuff_t          *payload_tvb = NULL;
    gint               payload_len;


    spdu_len = tvb_reported_length(tvb);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, 0, -1, "Session Layer");
        sess_tree = proto_item_add_subtree(ti, ett_dvbci_session);
    }

    tag = tvb_get_guint8(tvb,0);
    tag_str = match_strval(tag, dvbci_spdu_tag);
    col_add_str(pinfo->cinfo, COL_INFO,
            val_to_str_const(tag, dvbci_spdu_tag, "Invalid SPDU"));
    if (tag_str) {
        proto_tree_add_item(sess_tree, hf_dvbci_spdu_tag, tvb, 0, 1, ENC_BIG_ENDIAN);
    }
    else {
        pi = proto_tree_add_text(sess_tree, tvb, 0, 1, "Invalid SPDU tag");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "See table 14 in the DVB-CI specification");
        return;
    }

    offset = dissect_ber_length(pinfo, sess_tree, tvb, 1, &len_field, NULL);

    si = (spdu_info_t *)g_hash_table_lookup(spdu_table,
                                            GUINT_TO_POINTER((guint)tag));
    if (!si)
        return;
    if (si->direction!=0 && si->direction!=direction) {
        pi = proto_tree_add_text(sess_tree, tvb, 0, 1,
                "Invalid SPDU direction");
        if (si->direction==DATA_HOST_TO_CAM) {
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                    "This SPDU must be sent from host to CAM");
        }
        else {
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                    "This SPDU must be sent from CAM to host");
        }
    }
    if (si->len_field != len_field) {
        /* offset points to 1st byte after the length field */
        pi = proto_tree_add_text(sess_tree, tvb, 1, offset-1,
                "Invalid SPDU length field");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "Correct length field for %s is %d", tag_str, si->len_field);
        return;
    }

    switch(tag)
    {
        case T_OPEN_SESSION_REQUEST:
            res_id_it = dissect_res_id(tvb, offset, pinfo, sess_tree, 0, TRUE);
            break;
        case T_CREATE_SESSION:
            res_id_it = dissect_res_id(tvb, offset, pinfo, sess_tree, 0, TRUE);
            /* DVB-CI uses network byte order == big endian */
            ssnb = tvb_get_ntohs(tvb, offset+RES_ID_LEN);
            proto_tree_add_item(sess_tree, hf_dvbci_sess_nb,
                    tvb, offset+RES_ID_LEN, 2, ENC_BIG_ENDIAN);
            break;
        case T_OPEN_SESSION_RESPONSE:
        case T_CREATE_SESSION_RESPONSE:
            sess_stat = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(sess_tree, hf_dvbci_sess_status,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            res_id = tvb_get_ntohl(tvb, offset+1);
            res_id_it = dissect_res_id(tvb, offset+1, pinfo, sess_tree, 0, TRUE);
            ssnb = tvb_get_ntohs(tvb, offset+1+RES_ID_LEN);
            proto_tree_add_item(sess_tree, hf_dvbci_sess_nb, tvb,
                    offset+1+RES_ID_LEN, 2, ENC_BIG_ENDIAN);
            if (sess_stat != SESS_OPENED) {
                col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Error");
                break;
            }
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Session opened");
            circuit = circuit_new(CT_DVBCI, (guint32)ssnb, pinfo->fd->num);
            if (circuit) {
                /* we always add the resource id immediately after the circuit
                   was created */
                circuit_add_proto_data(
                        circuit, proto_dvbci, GUINT_TO_POINTER(res_id));
            }
            break;
        case T_CLOSE_SESSION_REQUEST:
            ssnb = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(
                    sess_tree, hf_dvbci_sess_nb, tvb,
                    offset, 2, ENC_BIG_ENDIAN);
            break;
        case T_CLOSE_SESSION_RESPONSE:
            sess_stat = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(
                    sess_tree, hf_dvbci_close_sess_status, tvb,
                    offset, 1, ENC_BIG_ENDIAN);
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
                    sess_stat==SESS_CLOSED ? "Session closed" : "Error");
            ssnb = tvb_get_ntohs(tvb, offset+1);
            proto_tree_add_item(sess_tree, hf_dvbci_sess_nb,
                    tvb, offset+1, 2, ENC_BIG_ENDIAN);
            circuit = find_circuit(CT_DVBCI, (guint32)ssnb, pinfo->fd->num);
            if (circuit)
                close_circuit(circuit, pinfo->fd->num);
            break;
        case T_SESSION_NUMBER:
            ssnb = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(
                    sess_tree, hf_dvbci_sess_nb, tvb,
                    offset, 2, ENC_BIG_ENDIAN);
            payload_len = tvb_reported_length_remaining(tvb, offset+2);
            payload_tvb =
                tvb_new_subset(tvb, offset+2, payload_len, payload_len);
            break;
        default:
            break;
    }

    if (ssnb && !circuit)
        circuit = find_circuit(CT_DVBCI, (guint32)ssnb, pinfo->fd->num);

    /* if the packet contains no resource id, we add the cached id from
       the circuit so that each packet has a resource id that can be
       used for filtering */
    if (circuit && !res_id_it) {
        /* when a circuit is found, it always contains a valid resource id */
        res_id = GPOINTER_TO_UINT(
                (gpointer)circuit_get_proto_data(circuit, proto_dvbci));
        res_id_it = dissect_res_id(NULL, 0, pinfo, sess_tree, res_id, TRUE);
        PROTO_ITEM_SET_GENERATED(res_id_it);
    }

    if (payload_tvb) {
        proto_item_set_len(ti, spdu_len-tvb_reported_length(payload_tvb));
        dissect_dvbci_apdu(payload_tvb, circuit, pinfo, tree, direction);
    }
    else {
        proto_item_set_len(ti, spdu_len);
    }
}

/* dissect the status of an r_tpdu, return its length or -1 for error */
static gint
dissect_dvbci_tpdu_status(tvbuff_t *tvb, gint offset,
        packet_info *pinfo, proto_tree *tree,
        guint8 lpdu_tcid, guint8 r_tpdu_tag)
{
    gint         offset_new, len_start_offset;
    guint8       tag;
    guint32      len_field;
    guint8       t_c_id, sb_value;
    const gchar *sb_str;
    proto_item  *pi;

    offset_new = offset;

    tag = tvb_get_guint8(tvb, offset_new);
    if (tag!=T_SB) {
        pi = proto_tree_add_text(
                tree, tvb, offset_new, 1, "Invalid status tag");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "This must always be T_SB (0x80)");
        return -1;
    }
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "T_SB");
    proto_tree_add_text(tree, tvb, offset_new, 1, "Response TPDU status");
    offset_new++;

    len_start_offset = offset_new;
    offset_new = dissect_ber_length(
            pinfo, tree, tvb, offset_new, &len_field, NULL);
    if (len_field != 2) {
        pi = proto_tree_add_text(
                tree, tvb, len_start_offset, offset_new-len_start_offset,
                "Invalid status length field");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "This must always be 2");

        return -1;
    }

    t_c_id = tvb_get_guint8(tvb, offset_new);
    proto_tree_add_item(tree, hf_dvbci_t_c_id, tvb, offset_new, 1, ENC_BIG_ENDIAN);
    /* tcid in transport header and link layer must only match for data
     * transmission commands */
    if (t_c_id!=lpdu_tcid) {
        if (r_tpdu_tag==NO_TAG ||
                r_tpdu_tag==T_DATA_MORE || r_tpdu_tag==T_DATA_LAST) {

            pi = proto_tree_add_text(tree, tvb, offset_new, 1,
                    "Transport Connection ID mismatch");
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                 "tcid is %d in the transport layer and %d in the link layer",
                    t_c_id, lpdu_tcid);

            return -1;
        }
    }
    offset_new++;

    sb_value = tvb_get_guint8(tvb, offset_new);
    sb_str = match_strval(sb_value, dvbci_sb_value);
    if (sb_str) {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s", sb_str);
        proto_tree_add_item(tree, hf_dvbci_sb_value, tvb,
                offset_new, 1, ENC_BIG_ENDIAN);
    }
    else {
        pi = proto_tree_add_text(tree, tvb, offset_new, 1,
                "Invalid SB_value");
        expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                "Must be 0x00 or 0x80");
    }
    offset_new++;

    return offset_new-offset;
}


/* dissect the header of a c_tpdu or r_tpdu
   return the length of the header (tag, len_field, t_c_id) or -1 for error */
static gint
dissect_dvbci_tpdu_hdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint8 direction, guint8 lpdu_tcid, guint32 tpdu_len,
        guint8 *hdr_tag, guint32 *body_len)
{
    guint8       c_tpdu_tag, r_tpdu_tag, *tag = NULL;
    const gchar *c_tpdu_str, *r_tpdu_str;
    proto_item  *pi;
    gint         offset;
    guint32      len_field;
    guint8       t_c_id;

    if (direction==DATA_HOST_TO_CAM) {
        c_tpdu_tag = tvb_get_guint8(tvb, 0);
        tag = &c_tpdu_tag;
        c_tpdu_str = match_strval(c_tpdu_tag, dvbci_c_tpdu);
        if (c_tpdu_str) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", c_tpdu_str);
            proto_tree_add_item(tree, hf_dvbci_c_tpdu_tag, tvb, 0, 1, ENC_BIG_ENDIAN);
        }
        else {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                    "Invalid Command-TPDU tag");
            pi = proto_tree_add_text(
                    tree, tvb, 0, 1, "Invalid Command-TPDU tag");
            expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                    "see DVB-CI specification, table A.16 for valid values");
            return -1;
        }
    }
    else {
        r_tpdu_tag = tvb_get_guint8(tvb, 0);
        tag = &r_tpdu_tag;
        r_tpdu_str = match_strval(r_tpdu_tag, dvbci_r_tpdu);
        if (r_tpdu_str) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", r_tpdu_str);
            proto_tree_add_item(tree, hf_dvbci_r_tpdu_tag, tvb, 0, 1, ENC_BIG_ENDIAN);
        }
        else {
            if (r_tpdu_tag == T_SB) {
                /* we have an r_tpdu without header and body,
                   it contains only the status part */
                if (hdr_tag)
                    *hdr_tag = NO_TAG;
                if (body_len)
                    *body_len = 0;
                return 0;
            }
            else {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                        "Invalid Response-TPDU tag");
                pi = proto_tree_add_text(
                        tree, tvb, 0, 1, "Invalid Response-TPDU tag");
                expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                   "see DVB-CI specification, table A.16 for valid values");
                return -1;
            }
        }
    }

    offset = dissect_ber_length(pinfo, tree, tvb, 1, &len_field, NULL);
    if (((direction==DATA_HOST_TO_CAM) && ((offset+len_field)!=tpdu_len)) ||
        ((direction==DATA_CAM_TO_HOST) && ((offset+len_field)>tpdu_len))) {
        /* offset points to 1st byte after the length field */
        pi = proto_tree_add_text(
                tree, tvb, 1, offset-1, "Length field mismatch");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "Length field mismatch");
        return -1;
    }

    t_c_id = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_dvbci_t_c_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* tcid in transport header and link layer must only match for
     * data transmission commands */
    if (t_c_id!=lpdu_tcid) {
        if (tag && (*tag==T_RCV || *tag==T_DATA_MORE || *tag==T_DATA_LAST)) {
            pi = proto_tree_add_text(tree, tvb, offset, 1,
                    "Transport Connection ID mismatch");
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
               "tcid is %d in the transport layer and %d in the link layer",
                    t_c_id, lpdu_tcid);
        }
    }
    else {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "tcid %d", t_c_id);
    }
    offset++;

    if (hdr_tag && tag)
        *hdr_tag = *tag;
    if (body_len)
        *body_len = len_field-1;  /* -1 for t_c_id */
    return offset;
}

static void
dissect_dvbci_tpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint8 direction, guint8 lpdu_tcid)
{
    guint32        tpdu_len, body_len;
    proto_item    *ti                     = NULL;
    proto_tree    *trans_tree             = NULL;
    gint           offset, status_len;
    guint8         hdr_tag                = NO_TAG;
    tvbuff_t      *body_tvb, *payload_tvb = NULL;
    proto_item    *pi;
    fragment_data *frag_msg               = NULL;


    tpdu_len = tvb_reported_length(tvb);

    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, 0, -1, "Transport Layer");
        trans_tree = proto_item_add_subtree(ti, ett_dvbci_transport);
    }

    offset = dissect_dvbci_tpdu_hdr(tvb, pinfo, trans_tree, direction,
            lpdu_tcid, tpdu_len, &hdr_tag, &body_len);
    if (offset==-1)
        return;
    proto_item_set_len(ti, offset);
    if ((offset>0) && (body_len!=0)) {
        /* for unfragmented data, the reassembly api behaviour is unclear
            if we put the body part of the tvb into fragment_add_seq_next(),
            process_reassembled_data() returns the remainder of the tvb
            which is body|status part
           if there's more than one fragment, payload_tvb contains only
            the reassembled bodies as expected
           to work around this issue, we use a dedicated body_tvb as
            input to reassembly routines */
        body_tvb = tvb_new_subset(tvb, offset, body_len, body_len);
        frag_msg = fragment_add_seq_next(body_tvb, 0, pinfo,
                SEQ_ID_TRANSPORT_LAYER,
                spdu_fragment_table,
                spdu_reassembled_table,
                body_len,
                hdr_tag == T_DATA_MORE ? 1 : 0);
        payload_tvb = process_reassembled_data(body_tvb, 0, pinfo,
                "Reassembled SPDU", frag_msg, &spdu_frag_items,
                NULL, trans_tree);
        if (!payload_tvb) {
            if (hdr_tag == T_DATA_MORE) {
                pinfo->fragmented = TRUE;
                col_append_fstr(pinfo->cinfo, COL_INFO, " (Message fragment)");
            } else {
                payload_tvb = body_tvb;
            }
        }
        offset += body_len;
    }

    if (direction==DATA_CAM_TO_HOST) {
        /* minimum length of an rtpdu status is 4 bytes */
        if (tpdu_len-offset < 4) {
            pi = proto_tree_add_text(trans_tree, tvb, 0, 0,
                    "Response TPDU's status part is missing");
            expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                    "RTPDU status is mandatory");
            return;
        }
        status_len = dissect_dvbci_tpdu_status(
                tvb, offset, pinfo, trans_tree, lpdu_tcid, hdr_tag);
        if (status_len<0)
            return;
        proto_tree_set_appendix(trans_tree, tvb, offset, status_len);
    }

    if (payload_tvb)
        dissect_dvbci_spdu(payload_tvb, pinfo, tree, direction);
}


static void
dissect_dvbci_lpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint8 direction)
{
    proto_item    *ti;
    proto_tree    *link_tree   = NULL;
    guint32        payload_len;
    guint8         tcid, more_last;
    proto_item    *pi;
    tvbuff_t      *payload_tvb = NULL;
    fragment_data *frag_msg    = NULL;


    payload_len = tvb_reported_length(tvb);

    col_add_str(pinfo->cinfo, COL_INFO, "LPDU");

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, 0, 2, "Link Layer");
        link_tree = proto_item_add_subtree(ti, ett_dvbci_link);
    }

    tcid = tvb_get_guint8(tvb, 0);
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "tcid %d", tcid);
    proto_tree_add_item(link_tree, hf_dvbci_tcid, tvb, 0, 1, ENC_BIG_ENDIAN);

    more_last = tvb_get_guint8(tvb, 1);
    if (match_strval(more_last, dvbci_ml)) {
        proto_tree_add_item(link_tree, hf_dvbci_ml, tvb, 1, 1, ENC_BIG_ENDIAN);
    }
    else {
        pi = proto_tree_add_text(
                link_tree, tvb, 1, 1, "Invalid More/Last indicator");
        expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                "Second byte of an LPDU must be 0x80 or 0x00");
    }

    /* buf_size_host==0 -> we did not capture the buffer size negotiation */
    if (buf_size_host!=0 && payload_len>buf_size_host) {
        pi = proto_tree_add_text(
                link_tree, tvb, 2, payload_len, "Payload too large");
        expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
           "Maximum payload length is the negotiated buffer size (%d bytes)",
                buf_size_host);
    }

    frag_msg = fragment_add_seq_next(tvb, 2, pinfo,
            SEQ_ID_LINK_LAYER,
            tpdu_fragment_table,
            tpdu_reassembled_table,
            tvb_reported_length_remaining(tvb, 2),
            more_last == ML_MORE ? 1 : 0);

    payload_tvb = process_reassembled_data(tvb, 2, pinfo,
            "Reassembled TPDU", frag_msg, &tpdu_frag_items,
            NULL, link_tree);
    if (!payload_tvb) {
        if (more_last == ML_MORE) {
            pinfo->fragmented = TRUE;
            col_append_fstr(pinfo->cinfo, COL_INFO, " (Message fragment)");
       } else
            payload_tvb = tvb_new_subset_remaining(tvb, 2);
    }
    if (payload_tvb)
        dissect_dvbci_tpdu(payload_tvb, pinfo, tree, direction, tcid);
}

/* dissect DVB-CI buffer size negotiation */
static void
dissect_dvbci_buf_neg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint8 direction)
{
    guint16     buf_size;
    proto_item *pi;

    buf_size = tvb_get_ntohs(tvb, 0);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %u bytes",
                 direction == DATA_HOST_TO_CAM ?
                 "negotiated buffer size" : "buffer size proposal",
                 buf_size);

    if (direction == DATA_HOST_TO_CAM) {
        buf_size_host = buf_size;
        proto_tree_add_uint_format(tree, hf_dvbci_buf_size, tvb,
                0, 2, buf_size,
                "Negotiated buffer size: %u bytes", buf_size);
        if (buf_size_host > buf_size_cam) {
            /* ATTENTION:
               wireshark may run through each packet multiple times
               if we didn't check the direction, we'd get the error when
               wireshark runs through the initial CAM packet for the 2nd time
             */
            pi = proto_tree_add_text(tree, tvb, 0, 2,
                    "Illegal buffer size command");
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                                   "Host shall not request a buffer size larger than the CAM proposal");
        }
    }
    else if (direction == DATA_CAM_TO_HOST) {
        buf_size_cam = buf_size;
        proto_tree_add_uint_format(tree, hf_dvbci_buf_size, tvb,
                0, 2, buf_size,
                "Buffer size proposal by the CAM: %u bytes", buf_size);
    }

    if (buf_size < 16) {
        pi = proto_tree_add_text(tree, tvb, 0, 2, "Illegal buffer size");
        expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                "Minimum buffer size is 16 bytes");
    }
}

/* dissect Level 1 version/product information tuple's payload
   data_tvb is a separate tvb for the tuple payload (without tag and len)
   return the number of dissected bytes or -1 for error */
static gint
dissect_dvbci_cis_payload_tpll_v1(tvbuff_t *data_tvb,
        packet_info *pinfo _U_, proto_tree *tree)
{
    gint offset=0, offset_str_end;

    /* the CIS is defined by PCMCIA, all multi-byte values are little endian
       (the rest of DVB-CI is a big-endian protocol) */
    proto_tree_add_item(tree, hf_dvbci_cis_tpll_v1_major,
            data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_dvbci_cis_tpll_v1_minor,
            data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* manufacturer, name and additional infos are 0-terminated strings */
    offset_str_end = tvb_find_guint8(data_tvb, offset, -1, 0x0);
    if (offset_str_end<offset) /* offset_str_end==offset is ok */
        return offset;
    proto_tree_add_item(tree, hf_dvbci_cis_tpll_v1_info_manuf,
            data_tvb, offset, offset_str_end-offset, ENC_ASCII|ENC_NA);
    offset = offset_str_end+1; /* +1 for 0 termination */

    offset_str_end = tvb_find_guint8(data_tvb, offset, -1, 0x0);
    if (offset_str_end<offset)
        return offset;
    proto_tree_add_item(tree, hf_dvbci_cis_tpll_v1_info_name,
            data_tvb, offset, offset_str_end-offset, ENC_ASCII|ENC_NA);
    offset = offset_str_end+1;

    /* the pc-card spec mentions two additional info strings,
        it's unclear if both are mandatory
       >1 because the last byte is the tuple end marker */
    while (tvb_reported_length_remaining(data_tvb, offset)>1) {
        offset_str_end = tvb_find_guint8(data_tvb, offset, -1, 0x0);
        if (offset_str_end<offset)
            break;
        proto_tree_add_item(tree, hf_dvbci_cis_tpll_v1_info_additional,
                data_tvb, offset, offset_str_end-offset, ENC_ASCII|ENC_NA);
        offset = offset_str_end+1;
    }

    proto_tree_add_item(tree, hf_dvbci_cis_tpll_v1_end,
            data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    return offset;
}

static gint
dissect_dvbci_cis_payload_config(tvbuff_t *data_tvb,
        packet_info *pinfo _U_, proto_tree *tree)
{
    gint         offset = 0;
    /* these are the actual sizes, the CIS stores rmsz-1 and rasz-1 */
    guint8       rfsz, rmsz, rasz;
    guint8       st_code, st_len;
    const gchar *st_code_str;
    proto_item  *st_item = NULL;
    proto_tree  *st_tree = NULL;
    guint8       stci_ifn_size;   /* actual size, see comment above */

    rfsz = (tvb_get_guint8(data_tvb, offset)&0xC0) >> 6;
    proto_tree_add_item(tree, hf_dvbci_cis_tpcc_rfsz,
            data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
    rmsz = ((tvb_get_guint8(data_tvb, offset)&0x3C) >> 2) + 1;
    proto_tree_add_item(tree, hf_dvbci_cis_tpcc_rmsz,
            data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
    rasz = (tvb_get_guint8(data_tvb, offset)&0x03) + 1;
    proto_tree_add_item(tree, hf_dvbci_cis_tpcc_rasz,
            data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_dvbci_cis_tpcc_last,
            data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_dvbci_cis_tpcc_radr,
            data_tvb, offset, rasz, ENC_LITTLE_ENDIAN);
    offset += rasz;
    proto_tree_add_item(tree, hf_dvbci_cis_tpcc_rmsk,
            data_tvb, offset, rmsz, ENC_NA);
    offset += rmsz;
    offset += rfsz; /* skip reserved bytes */

    while (tvb_reported_length_remaining(data_tvb, offset) > 0) {
        st_code = tvb_get_guint8(data_tvb, offset);
        st_code_str = val_to_str_const(st_code, dvbci_cis_subtpl_code, "unknown");
        st_item = proto_tree_add_text(tree, data_tvb, offset, -1,
                "Subtuple: %s (0x%x)", st_code_str, st_code);
        st_tree = proto_item_add_subtree(st_item, ett_dvbci_cis_subtpl);
        proto_tree_add_item(st_tree, hf_dvbci_cis_st_code,
            data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        st_len = tvb_get_guint8(data_tvb, offset);
        proto_item_set_len(st_item, 2+st_len); /* tag, len byte, body */
        proto_tree_add_item(st_tree, hf_dvbci_cis_st_len,
            data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        if (st_code == CCSTPL_CIF) {
            stci_ifn_size = ((tvb_get_guint8(data_tvb, offset) & 0xC0)>>6)+1;
            proto_tree_add_item(st_tree, hf_dvbci_cis_stci_ifn_size,
                    data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
            /* don't increment offset,
               size and actual value's LSB share the same byte */
            proto_tree_add_item(st_tree, hf_dvbci_cis_stci_ifn,
                    data_tvb, offset, stci_ifn_size, ENC_LITTLE_ENDIAN);
            offset += stci_ifn_size;
            /* the stci_str field could consist of multiple strings,
               this case is not supported for now */
            proto_tree_add_item(st_tree, hf_dvbci_cis_stci_str,
                    data_tvb, offset, st_len-stci_ifn_size, ENC_ASCII|ENC_NA);
            offset += st_len-stci_ifn_size;
        }
        else {
            /* skip unknown subtuple's content */
            offset += st_len;
        } 
    }

    return offset;
}


static gint
dissect_dvbci_cis_payload_cftable_entry(tvbuff_t *data_tvb,
        packet_info *pinfo _U_, proto_tree *tree)
{
    gint offset = 0;
    gboolean intface_flag;

    intface_flag = ((tvb_get_guint8(data_tvb, offset) & 0x80) == 0x80);
    /* tpce_indx byte */
    proto_tree_add_item(tree, hf_dvbci_cis_tpce_indx_intface,
            data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_dvbci_cis_tpce_indx_default,
            data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_dvbci_cis_tpce_indx_cnf_entry,
            data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    if (intface_flag) {
        /* tpce_if byte */
        proto_tree_add_item(tree, hf_dvbci_cis_tpce_if_type,
            data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
        /* XXX parse other components of tpce_if */
        offset++;
    }

    /* tpce_fs byte: this is present in any case */
    proto_tree_add_item(tree, hf_dvbci_cis_tpce_fs_mem_space,
            data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_dvbci_cis_tpce_fs_irq,
            data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_dvbci_cis_tpce_fs_io,
            data_tvb, offset, 1, ENC_LITTLE_ENDIAN);
    /* XXX parse other components of tpce_fs */
    offset++;

    return offset;
}
 
static void
dissect_dvbci_cis(tvbuff_t *tvb, gint offset,
        packet_info *pinfo, proto_tree *tree)
{
    gint         offset_start;
    proto_tree  *cis_tree = NULL, *tpl_tree = NULL;
    proto_item  *ti_main  = NULL, *ti_tpl;
    guint8       tpl_code;
    const gchar *tpl_code_str = NULL;
    guint8       len_field;
    tvbuff_t    *tpl_data_tvb;

    offset_start = offset;

    ti_main = proto_tree_add_text(tree, tvb, offset, -1,
            "Card Information Structure (CIS)");
    cis_tree = proto_item_add_subtree(ti_main, ett_dvbci_cis);

    do {
        tpl_code = tvb_get_guint8(tvb, offset);
        tpl_code_str = val_to_str_const(tpl_code, dvbci_cis_tpl_code, "unknown");

        ti_tpl = proto_tree_add_text(cis_tree,
                tvb, offset, -1, "CIS tuple: %s", tpl_code_str);
        tpl_tree = proto_item_add_subtree(ti_tpl, ett_dvbci_cis_tpl);

        proto_tree_add_uint_format(tpl_tree, hf_dvbci_cis_tpl_code,
                tvb, offset, 1, tpl_code, "Tuple code: %s (0x%x)",
                tpl_code_str, tpl_code);
        offset++;

        if (tpl_code == CISTPL_END) {
            proto_item_set_len(ti_tpl, 1); /* only tag (no len and content) */
            break;
        }

        len_field = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tpl_tree, hf_dvbci_cis_tpl_len,
                tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        tpl_data_tvb = tvb_new_subset(tvb, offset, len_field, len_field);
        switch (tpl_code) {
            case CISTPL_VERS_1:
                dissect_dvbci_cis_payload_tpll_v1(
                        tpl_data_tvb, pinfo, tpl_tree);
                offset += len_field;
                break;
            case CISTPL_CONFIG:
                dissect_dvbci_cis_payload_config(tpl_data_tvb, pinfo, tpl_tree);
                offset += len_field;
                break;
            case CISTPL_CFTABLE_ENTRY:
                dissect_dvbci_cis_payload_cftable_entry(
                        tpl_data_tvb, pinfo, tpl_tree);
                offset += len_field;
                break;
            case CISTPL_MANFID:
                proto_tree_add_item(tpl_tree, hf_dvbci_cis_tplmid_manf,
                        tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset+=2;
                proto_tree_add_item(tpl_tree, hf_dvbci_cis_tplmid_card,
                        tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset+=2;
                break;
            default:
                if (len_field>0) {
                    proto_tree_add_item(tpl_tree, hf_dvbci_cis_tpl_data,
                            tvb, offset, len_field, ENC_NA);
                }
                offset += len_field;
                break;
        }

        proto_item_set_len(ti_tpl, 2+len_field); /* tag, len byte, content */

    } while (tvb_reported_length_remaining(tvb, offset) > 0);

    proto_item_set_len(ti_main, offset-offset_start);
}


static int
dissect_dvbci(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint         packet_len, offset = 0, offset_ver, offset_evt, offset_len_field;
    guint8       version, event;
    const gchar *event_str;
    guint16      len_field;
    proto_item  *ti, *ti_hdr;
    proto_tree  *dvbci_tree         = NULL, *hdr_tree = NULL;
    tvbuff_t    *payload_tvb;
    guint16      cor_addr;
    guint8       cor_value;
    proto_item  *pi;
    guint8       hw_event;

    if (tvb_length(tvb) < 4)
        return 0;

    offset_ver = offset;
    version = tvb_get_guint8(tvb, offset++);
    if (version != 0)
        return 0;

    offset_evt = offset;
    event = tvb_get_guint8(tvb, offset++);
    event_str = match_strval(event, dvbci_event);
    if (!event_str)
        return 0;

    packet_len = tvb_reported_length(tvb);
    offset_len_field = offset;
    len_field = tvb_get_ntohs(tvb, offset);
    if (len_field != (packet_len-4))
        return 0;
    offset += 2;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DVB-CI");
    col_set_str(pinfo->cinfo, COL_INFO, event_str);

    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_dvbci,
                tvb, 0, packet_len, "DVB Common Interface: %s", event_str);
        dvbci_tree = proto_item_add_subtree(ti, ett_dvbci);
        ti_hdr = proto_tree_add_text(dvbci_tree, tvb, 0, offset, "Pseudo header");
        hdr_tree = proto_item_add_subtree(ti_hdr, ett_dvbci_hdr);
        proto_tree_add_text(hdr_tree, tvb, offset_ver, 1, "Version: %d", version);
        proto_tree_add_item(hdr_tree, hf_dvbci_event, tvb, offset_evt, 1, ENC_BIG_ENDIAN);
        proto_tree_add_text(hdr_tree, tvb, offset_len_field, 2,
                "Length field: %d", len_field);
    }

    if (IS_DATA_TRANSFER(event)) {
        if (event == DATA_HOST_TO_CAM) {
            SET_ADDRESS(&pinfo->src, AT_STRINGZ, (int)strlen(ADDR_HOST)+1, ADDR_HOST);
            SET_ADDRESS(&pinfo->dst, AT_STRINGZ, (int)strlen(ADDR_CAM)+1 , ADDR_CAM);
        }
        else {
            SET_ADDRESS(&pinfo->src, AT_STRINGZ, (int)strlen(ADDR_CAM)+1 , ADDR_CAM);
            SET_ADDRESS(&pinfo->dst, AT_STRINGZ, (int)strlen(ADDR_HOST)+1, ADDR_HOST);
        }

        payload_tvb = tvb_new_subset_remaining( tvb, offset);
        if (len_field == 2) {
            dissect_dvbci_buf_neg(payload_tvb, pinfo, dvbci_tree, event);
        }
        else {
            dissect_dvbci_lpdu(payload_tvb, pinfo, dvbci_tree, event);
        }
    }
    else if (event==COR_WRITE) {
        /* PCAP format for DVB-CI defines COR address as big endian */
        pi = proto_tree_add_item(dvbci_tree, hf_dvbci_cor_addr,
                tvb, offset, 2, ENC_BIG_ENDIAN);
        cor_addr = tvb_get_ntohs(tvb, offset);
        if (cor_addr == 0xFFFF) {
            proto_item_append_text(pi, " (COR address is unknown)");
            col_append_sep_str(pinfo->cinfo, COL_INFO, ": ", "unknown address");
        }
        else if (cor_addr > 0xFFE) {
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
                "COR address must not be greater than 0xFFE (DVB-CI spec, A.5.6)");
        }
        else {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ",
                "address 0x%x", cor_addr);
        }
        offset += 2;
        cor_value = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(dvbci_tree, hf_dvbci_cor_val,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
            "value 0x%x", cor_value);
    }
    else if (event==CIS_READ) {
        dissect_dvbci_cis(tvb, offset, pinfo, dvbci_tree);
    }
    else if (event==HW_EVT) {
        hw_event = tvb_get_guint8(tvb, offset);
        col_set_str(pinfo->cinfo, COL_INFO,
                val_to_str_const(hw_event, dvbci_hw_event, "Invalid hardware event"));
        proto_tree_add_item(dvbci_tree, hf_dvbci_hw_event,
                tvb, offset, 1, ENC_BIG_ENDIAN);
    }

    return packet_len;
}


void
proto_register_dvbci(void)
{
    guint     i;
    module_t *dvbci_module;

    static gint *ett[] = {
        &ett_dvbci,
        &ett_dvbci_hdr,
        &ett_dvbci_cis,
        &ett_dvbci_cis_tpl,
        &ett_dvbci_cis_subtpl,
        &ett_dvbci_link,
        &ett_dvbci_link_frag,
        &ett_dvbci_link_frags,
        &ett_dvbci_transport,
        &ett_dvbci_transport_frag,
        &ett_dvbci_transport_frags,
        &ett_dvbci_session,
        &ett_dvbci_res,
        &ett_dvbci_application,
        &ett_dvbci_es,
        &ett_dvbci_ca_desc,
        &ett_dvbci_text,
        &ett_dvbci_cc_item,
        &ett_dvbci_sac_msg_body,
        &ett_dvbci_ami_req_types,
        &ett_dvbci_lsc_conn_desc,
        &ett_dvbci_opp_cap_loop
    };

    static hf_register_info hf[] = {
        { &hf_dvbci_event,
          { "Event", "dvb-ci.event",
            FT_UINT8, BASE_HEX, VALS(dvbci_event), 0, NULL, HFILL }
        },
        { &hf_dvbci_hw_event,
          { "Hardware event", "dvb-ci.hw_event",
            FT_UINT8, BASE_HEX, VALS(dvbci_hw_event), 0, NULL, HFILL }
        },
        { &hf_dvbci_cor_addr,
          { "COR address", "dvb-ci.cor_address",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cor_val,
          { "COR value", "dvb-ci.cor_value",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpl_code,
          { "CIS tuple code", "dvb-ci.cis.tpl_code",
            FT_UINT8, BASE_HEX, VALS(dvbci_cis_tpl_code), 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpl_len,
          { "Length field", "dvb-ci.cis.tpl_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpl_data,
          { "Tuple data", "dvb-ci.cis.tpl_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpll_v1_major,
          { "Major version number", "dvb-ci.cis.tpll_v1_major",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpll_v1_minor,
          { "Minor version number", "dvb-ci.cis.tpll_v1_minor",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpll_v1_info_manuf,
          { "Manufacturer", "dvb-ci.cis.tpll_v1_info.manufacturer",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpll_v1_info_name,
          { "Name", "dvb-ci.cis.tpll_v1_info.name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpll_v1_info_additional,
          { "Additional info", "dvb-ci.cis.tpll_v1_info.additional",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpll_v1_end,
          { "End of chain", "dvb-ci.cis.tpll_v1_end",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpcc_rfsz,
          { "Size of reserved area", "dvb-ci.cis.tpcc_rfsz",
            FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpcc_rmsz,
          { "Size of TPCC_RMSK field - 1", "dvb-ci.cis.tpcc_rmsz",
            FT_UINT8, BASE_HEX, NULL, 0x3C, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpcc_rasz,
          { "Size of TPCC_RADR - 1", "dvb-ci.cis.tpcc_rasz",
            FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpcc_last,
          { "Index of the last cftable entry", "dvb-ci.cis.tpcc_last",
            FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpcc_radr,
          { "COR base address", "dvb-ci.cis.tpcc_radr",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpcc_rmsk,
          { "Configuration register presence mask", "dvb-ci.cis.tpcc_rmsk",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_st_code,
          { "Subtuple tag", "dvb-ci.cis.st_code",
            FT_UINT8, BASE_HEX, VALS(dvbci_cis_subtpl_code), 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_st_len,
          { "Subtuple length", "dvb-ci.cis.st_len",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_stci_ifn_size,
          { "Size of interface ID number - 1", "dvb-ci.cis.stci_ifn_size",
            FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_dvbci_cis_stci_ifn,
          { "Interface ID number", "dvb-ci.cis.stci_ifn",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_stci_str,
          { "Interface description strings", "dvb-ci.cis.stci_str",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpce_indx_intface,
          { "Intface", "dvb-ci.cis.tpce_indx.intface",
            FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpce_indx_default,
          { "Default", "dvb-ci.cis.tpce_indx.default",
            FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpce_indx_cnf_entry,
          { "Configuration entry number", "dvb-ci.cis.tpce_indx.cnf_entry",
            FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpce_if_type,
          { "Interface type", "dvb-ci.cis.tpce_if.type", FT_UINT8, BASE_HEX,
              VALS(dvbci_cis_tpce_if_type), 0x0F, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpce_fs_mem_space,
          { "Mem space", "dvb-ci.cis.tpce_fs.mem_space",
            FT_UINT8, BASE_HEX, NULL, 0x60, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpce_fs_irq,
          { "IRQ", "dvb-ci.cis.tpce_fs.irq",
            FT_UINT8, BASE_HEX, NULL, 0x10, NULL, HFILL }
        },
        { &hf_dvbci_cis_tpce_fs_io,
          { "IO Space", "dvb-ci.cis.tpce_fs.io",
            FT_UINT8, BASE_HEX, NULL, 0x08, NULL, HFILL }
        },
        { &hf_dvbci_cis_tplmid_manf,
          { "PC Card manufacturer code", "dvb-ci.cis.tplmid_manf",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cis_tplmid_card,
          { "Manufacturer info", "dvb-ci.cis.tplmid_card",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_buf_size,
          { "Buffer Size", "dvb-ci.buf_size",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_tcid,
          { "Transport Connection ID", "dvb-ci.tcid",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_ml,
          { "More/Last indicator", "dvb-ci.more_last",
            FT_UINT8, BASE_HEX, VALS(dvbci_ml), 0, NULL, HFILL }
        },
        /* on the link layer, tpdus are reassembled */
        { &hf_dvbci_l_frags,
          { "Tpdu fragments", "dvb-ci.tpdu_fragments",
           FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_l_frag,
          { "Tpdu fragment", "dvb-ci.tpdu_fragment",
           FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_l_frag_overlap,
          { "Tpdu fragment overlap", "dvb-ci.tpdu_fragment.overlap",
           FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_l_frag_overlap_conflicts,
          { "Tpdu fragment overlapping with conflicting data",
           "dvb-ci.tpdu_fragment.overlap.conflicts",
           FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_l_frag_multiple_tails,
          { "Tpdu has multiple tail fragments",
           "dvb-ci.tpdu_fragment.multiple_tails",
          FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_l_frag_too_long_frag,
          { "Tpdu fragment too long", "dvb-ci.tpdu_fragment.too_long_fragment",
           FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_l_frag_err,
          { "Tpdu defragmentation error", "dvb-ci.tpdu_fragment.error",
           FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_l_frag_cnt,
          { "Tpdu fragment count", "dvb-ci.tpdu_fragment.count",
           FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_l_reass_in,
          { "Tpdu reassembled in", "dvb-ci.tpdu_reassembled.in",
           FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_l_reass_len,
          { "Reassembled tpdu length", "dvb-ci.tpdu_reassembled.length",
           FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_c_tpdu_tag,
          { "Command TPDU Tag", "dvb-ci.c_tpdu_tag",
            FT_UINT8, BASE_HEX, VALS(dvbci_c_tpdu), 0, NULL, HFILL }
        },
        { &hf_dvbci_r_tpdu_tag,
           { "Response TPDU Tag", "dvb-ci.r_tpdu_tag",
             FT_UINT8, BASE_HEX, VALS(dvbci_r_tpdu), 0, NULL, HFILL }
        },
        { &hf_dvbci_t_c_id,
           { "Transport Connection ID", "dvb-ci.t_c_id",
             FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_sb_value,
          { "SB Value", "dvb-ci.sb_value", FT_UINT8, BASE_HEX,
            VALS(dvbci_sb_value), 0, NULL, HFILL } },

        /* on the transport layer, spdus are reassembled */
        { &hf_dvbci_t_frags,
          { "Spdu fragments", "dvb-ci.spdu_fragments",
           FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_t_frag,
          { "Spdu fragment", "dvb-ci.spdu_fragment",
           FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_t_frag_overlap,
          { "Spdu fragment overlap", "dvb-ci.spdu_fragment.overlap",
           FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_t_frag_overlap_conflicts,
          { "Spdu fragment overlapping with conflicting data",
           "dvb-ci.tpdu_fragment.overlap.conflicts",
          FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_t_frag_multiple_tails,
          { "Spdu has multiple tail fragments",
           "dvb-ci.spdu_fragment.multiple_tails",
           FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_t_frag_too_long_frag,
          { "Spdu fragment too long", "dvb-ci.spdu_fragment.too_long_fragment",
           FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_t_frag_err,
          { "Spdu defragmentation error", "dvb-ci.spdu_fragment.error",
           FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_t_frag_cnt,
          { "Spdu fragment count", "dvb-ci.spdu_fragment.count",
           FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_t_reass_in,
          { "Spdu reassembled in", "dvb-ci.spdu_reassembled.in",
           FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_t_reass_len,
          { "Reassembled spdu length", "dvb-ci.spdu_reassembled.length",
           FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_dvbci_spdu_tag,
          { "SPDU Tag", "dvb-ci.spdu_tag",
           FT_UINT8, BASE_HEX, VALS(dvbci_spdu_tag), 0, NULL, HFILL }
        },
        { &hf_dvbci_sess_status,
          { "Session Status", "dvb-ci.session_status",
            FT_UINT8, BASE_HEX, VALS(dvbci_sess_status), 0, NULL, HFILL }
        },
        { &hf_dvbci_sess_nb,
          { "Session Number", "dvb-ci.session_nb",
            FT_UINT16, BASE_DEC, NULL , 0, NULL, HFILL }
        },
        { &hf_dvbci_close_sess_status,
          { "Session Status", "dvb-ci.close_session_status",
            FT_UINT8, BASE_HEX, VALS(dvbci_close_sess_status), 0, NULL, HFILL }
        },
        { &hf_dvbci_res_id_type,
          { "Resource ID Type", "dvb-ci.res.id_type",
            FT_UINT32, BASE_HEX, NULL, RES_ID_TYPE_MASK, NULL, HFILL }
        },
        { &hf_dvbci_res_class,
          { "Resource Class", "dvb-ci.res.class",
            FT_UINT32, BASE_HEX, VALS(dvbci_res_class), RES_CLASS_MASK, NULL, HFILL }
        },
        { &hf_dvbci_res_type,
          { "Resource Type", "dvb-ci.res.type",
            FT_UINT32, BASE_HEX, NULL, RES_TYPE_MASK, NULL, HFILL }
        },
        { &hf_dvbci_res_ver,
          { "Resource Version", "dvb-ci.res.version",
            FT_UINT32, BASE_HEX, NULL, RES_VER_MASK, NULL, HFILL }
        },
        { &hf_dvbci_apdu_tag,
          { "APDU Tag", "dvb-ci.apdu_tag",
            FT_UINT24, BASE_HEX, VALS(dvbci_apdu_tag), 0, NULL, HFILL }
        },
        { &hf_dvbci_app_type,
          { "Application type", "dvb-ci.ap.type",
            FT_UINT8, BASE_HEX, VALS(dvbci_app_type), 0, NULL, HFILL }
        },
        { &hf_dvbci_app_manf,
          { "Application manufacturer", "dvb-ci.ap.manufacturer",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_manf_code,
          { "Manufacturer code", "dvb-ci.ap.manufacturer_code",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_menu_str_len,
          { "Menu string length", "dvb-ci.ap.menu_string_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_data_rate,
          { "Transport stream data rate supported by the host",
            "dvb-ci.ap.data_rate",
            FT_UINT8, BASE_HEX, VALS(dvbci_data_rate), 0, NULL, HFILL }
        },
        { &hf_dvbci_ca_sys_id,
          { "CA system ID", "dvb-ci.ca.ca_system_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_ca_pmt_list_mgmt,
          { "CA PMT list management", "dvb-ci.ca.ca_pmt_list_management",
            FT_UINT8, BASE_HEX, VALS(dvbci_ca_pmt_list_mgmt), 0, NULL,
            HFILL }
        },
        { &hf_dvbci_prog_num,
          { "Program number", "dvb-ci.ca.program_number",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_prog_info_len,
          { "Program info length", "dvb-ci.ca.program_info_length",
            FT_UINT16, BASE_HEX, NULL, 0x0FFF, NULL, HFILL }
        },
        { &hf_dvbci_stream_type,
          { "Stream type", "dvb-ci.ca.stream_type",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_es_pid,
          { "Elementary stream PID", "dvb-ci.ca.elementary_pid",
            FT_UINT16, BASE_HEX, NULL, 0x1FFF, NULL, HFILL }
        },
        { &hf_dvbci_es_info_len,
          { "Elementary stream info length", "dvb-ci.ca.es_info_length",
            FT_UINT16, BASE_HEX, NULL, 0x0FFF, NULL, HFILL }
        },
        { &hf_dvbci_ca_pmt_cmd_id,
          { "CA PMT command ID", "dvb-ci.ca.ca_pmt_cmd_id",
            FT_UINT8, BASE_HEX, VALS(dvbci_ca_pmt_cmd_id), 0, NULL, HFILL }
        },
        { &hf_dvbci_descr_len,
          { "CA descriptor length", "dvb-ci.ca.ca_desc_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_ca_pid,
          { "CA PID", "dvb-ci.ca.ca_pid",
            FT_UINT16, BASE_HEX, NULL, 0x1FFF, NULL, HFILL }
        },
        { &hf_dvbci_ca_enable_flag,
          { "CA enable flag", "dvb-ci.ca.ca_enable_flag",
            FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_dvbci_ca_enable,
          { "CA enable", "dvb-ci.ca.ca_enable",
            FT_UINT8, BASE_HEX, VALS(dvbci_ca_enable), 0x7F, NULL, HFILL }
        },
        { &hf_dvbci_auth_proto_id,
          { "Authentication protocol ID", "dvb-ci.aut.proto_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_auth_req_bytes,
          { "Authentication request data", "dvb-ci.aut.req",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_auth_resp_bytes,
          { "Authentication response data", "dvb-ci.aut.resp",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_network_id,
          { "Network ID", "dvb-ci.hc.nid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_original_network_id,
          { "Original network ID", "dvb-ci.hc.onid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_transport_stream_id,
          { "Transport stream ID", "dvb-ci.hc.tsid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_service_id,
          { "Service ID", "dvb-ci.hc.svcid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_replacement_ref,
          { "Replacement reference", "dvb-ci.hc.replacement_ref",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_replaced_pid,
          { "Replaced PID", "dvb-ci.hc.replaced_pid",
            FT_UINT16, BASE_HEX, NULL, 0x1FFF, NULL, HFILL }
        },
        { &hf_dvbci_replacement_pid,
          { "Replacement PID", "dvb-ci.hc.replacement_pid",
            FT_UINT16, BASE_HEX, NULL, 0x1FFF, NULL, HFILL }
        },
        { &hf_dvbci_pmt_flag,
          { "PMT flag", "dvb-ci.hc.pmt_flag",
            FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL }
        },
        { &hf_dvbci_hc_desc_loop_len,
          { "Descriptor loop length", "dvb-ci.hc.desc_loop_len",
            FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL }
        },
        { &hf_dvbci_hc_status,
          { "Status field", "dvb-ci.hc.status_field",
            FT_UINT8, BASE_HEX, VALS(dvbci_hc_status), 0, NULL, HFILL }
        },
        { &hf_dvbci_hc_release_reply,
          { "Release reply", "dvb-ci.hc.release_reply",
            FT_UINT8, BASE_HEX, VALS(dvbci_hc_release_reply), 0, NULL, HFILL }
        },
        { &hf_dvbci_resp_intv,
          { "Response interval", "dvb-ci.dt.resp_interval",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_utc_time,
          { "UTC time", "dvb-ci.dt.utc_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }
        },

        /* we have to use FT_INT16 instead of FT_RELATIVE_TIME,
           local offset can be negative */
        { &hf_dvbci_local_offset,
          { "Local time offset", "dvb-ci.dt.local_offset",
            FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_close_mmi_cmd_id,
          { "Command ID", "dvb-ci.mmi.close_mmi_cmd_id",
            FT_UINT8, BASE_HEX, VALS(dvbci_close_mmi_cmd_id), 0, NULL, HFILL }
        },
        { &hf_dvbci_close_mmi_delay,
          { "Delay (in sec)", "dvb-ci.mmi.delay",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_disp_ctl_cmd,
          { "Command", "dvb-ci.mmi.disp_ctl_cmd",
            FT_UINT8, BASE_HEX, VALS(dvbci_disp_ctl_cmd), 0, NULL, HFILL }
        },
        { &hf_dvbci_mmi_mode,
          { "MMI mode", "dvb-ci.mmi.mode",
            FT_UINT8, BASE_HEX, VALS(dvbci_mmi_mode), 0, NULL, HFILL }
        },
        { &hf_dvbci_disp_rep_id,
          { "Reply ID", "dvb-ci.mmi.disp_rep_id",
            FT_UINT8, BASE_HEX, VALS(dvbci_disp_rep_id), 0, NULL, HFILL }
        },
        { &hf_dvbci_char_tbl,
          { "Character table", "dvb-ci.mmi.char_tbl",
            FT_UINT8, BASE_HEX, VALS(dvbci_char_tbl), 0, NULL, HFILL }
        },
        { &hf_dvbci_blind_ans,
          { "Blind answer flag", "dvb-ci.mmi.blind_ans",
            FT_UINT8, BASE_HEX, VALS(dvbci_blind_ans), 0x01, NULL, HFILL }
        },
        { &hf_dvbci_ans_txt_len,
          { "Answer text length", "dvb-ci.mmi.ans_txt_len",
            FT_UINT8, BASE_DEC, NULL , 0, NULL, HFILL }
        },
        { &hf_dvbci_text_ctrl,
          { "Text control code", "dvb-ci.mmi.text_ctrl",
            FT_UINT8, BASE_HEX, VALS(dvbci_text_ctrl), 0, NULL, HFILL }
        },
        { &hf_dvbci_ans_id,
          { "Answer ID", "dvb-ci.mmi.ans_id",
            FT_UINT8, BASE_HEX, VALS(dvbci_ans_id) , 0, NULL, HFILL }
        },
        { &hf_dvbci_choice_nb,
          { "Number of menu items", "dvb-ci.mmi.choice_nb",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_choice_ref,
          { "Selected item", "dvb-ci.mmi.choice_ref",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_item_nb,
          { "Number of list items", "dvb-ci.mmi.item_nb",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_host_country,
          { "Host country", "dvb-ci.hlc.country",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_host_language,
          { "Host language", "dvb-ci.hlc.language",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cup_type,
          { "CAM upgrade type", "dvb-ci.cup.type",
            FT_UINT8, BASE_HEX, VALS(dvbci_cup_type), 0, NULL, HFILL }
        },
        { &hf_dvbci_cup_download_time,
          { "Download time", "dvb-ci.cup.download_time",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cup_answer,
          { "CAM upgrade answer", "dvb-ci.cup.answer",
            FT_UINT8, BASE_HEX, VALS(dvbci_cup_answer), 0, NULL, HFILL }
        },
        { &hf_dvbci_cup_progress,
          { "CAM upgrade progress", "dvb-ci.cup.progress",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cup_reset,
          { "requested CAM reset", "dvb-ci.cup.reset",
            FT_UINT8, BASE_HEX, VALS(dvbci_cup_reset), 0, NULL, HFILL }
        },
        { &hf_dvbci_cc_sys_id_bitmask,
          { "CC system id bitmask", "dvb-ci.cc.sys_id_bitmask",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cc_dat_id,
          { "CC datatype id", "dvb-ci.cc.datatype_id",
            FT_UINT8, BASE_HEX, VALS(dvbci_cc_dat_id), 0, NULL, HFILL }
        },
        { &hf_dvbci_brand_cert,
          { "Brand certificate", "dvb-ci.cc.brand_cert",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_dvbci_dev_cert,
          { "Device certificate", "dvb-ci.cc.dev_cert",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_dvbci_uri_ver,
          { "URI version", "dvb-ci.cc.uri.version",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_uri_aps,
          { "APS", "dvb-ci.cc.uri.aps",
            FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_dvbci_uri_emi,
          { "EMI", "dvb-ci.cc.uri.emi",
            FT_UINT8, BASE_HEX, NULL, 0x30, NULL, HFILL }
        },
        { &hf_dvbci_uri_ict,
          { "Image constraint token", "dvb-ci.cc.uri.ict",
            FT_UINT8, BASE_HEX, NULL, 0x08, NULL, HFILL }
        },
        { &hf_dvbci_uri_rct,
          { "Redistribution control trigger (RCT)", "dvb-ci.cc.uri.ict",
            FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL }
        },
        { &hf_dvbci_cc_key_register,
          { "Key register", "dvb-ci.cc.key_register",
            FT_UINT8, BASE_HEX, VALS(dvbci_cc_key_register), 0, NULL, HFILL }
        },
        { &hf_dvbci_cc_status_field,
          { "Status field", "dvb-ci.cc.status_field",
            FT_UINT8, BASE_HEX, VALS(dvbci_cc_status), 0, NULL, HFILL }
        },
        { &hf_dvbci_cc_op_mode,
          { "Operating mode", "dvb-ci.cc.op_mode",
            FT_UINT8, BASE_HEX, VALS(dvbci_cc_op_mode), 0, NULL, HFILL }
        },
        { &hf_dvbci_cc_data,
          { "Data", "dvb-ci.cc.data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_sac_msg_ctr,
          { "Message counter", "dvb-ci.cc.sac.msg_ctr",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_sac_proto_ver,
          { "Protocol version", "dvb-ci.cc.sac.proto_ver",
            FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_dvbci_sac_auth_cip,
          { "Authentication cipher", "dvb-ci.cc.sac.auth_cip",
            FT_UINT8, BASE_HEX, VALS(dvbci_cc_sac_auth), 0x0E, NULL, HFILL }
        },
        { &hf_dvbci_sac_payload_enc,
          { "Payload encryption flag", "dvb-ci.cc.sac.payload_enc",
            FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL }
        },
        { &hf_dvbci_sac_enc_cip,
          { "Encryption cipher", "dvb-ci.cc.sac.enc_cip",
            FT_UINT8, BASE_HEX, VALS(dvbci_cc_sac_enc), 0xE0, NULL, HFILL }
        },
        { &hf_dvbci_sac_payload_len,
          { "Payload length", "dvb-ci.cc.sac.payload_len",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_sac_enc_body,
          { "Encrypted SAC body", "dvb-ci.cc.sac.enc_body",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_sac_signature,
          { "Signature", "dvb-ci.cc.sac.signature",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_rating,
          { "Rating", "dvb-ci.cc.rating",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_capability_field,
          { "Capability field", "dvb-ci.cc.capability_field",
            FT_UINT8, BASE_HEX, VALS(dvbci_cc_cap), 0, NULL, HFILL }
        },
        { &hf_dvbci_pin_chg_time,
          { "PIN change time (UTC)", "dvb-ci.cc.pin_change_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_pincode_status,
          { "Pincode status field", "dvb-ci.cc.pincode_status_field",
            FT_UINT8, BASE_HEX, VALS(dvbci_pincode_status), 0, NULL, HFILL }
        },
        { &hf_dvbci_cc_prog_num,
          { "Program number", "dvb-ci.cc.program_number",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_pin_evt_time,
          { "PIN event time (UTC)", "dvb-ci.cc.pin_event_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_pin_evt_cent,
          { "PIN event time centiseconds", "dvb-ci.cc.pin_event_time_centi",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cc_priv_data,
          { "Private data", "dvb-ci.cc.private_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_pincode,
          { "PIN code", "dvb-ci.cc.pincode",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_app_dom_id,
          { "Application Domain Identifier", "dvb-ci.ami.app_dom_id",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_init_obj,
          { "Initial Object", "dvb-ci.ami.init_obj",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_ack_code,
          { "Acknowledgement", "dvb-ci.ami.ack_code",
            FT_UINT8, BASE_HEX, VALS(dvbci_ack_code), 0, NULL, HFILL }
        },
        { &hf_dvbci_req_type,
          { "Request type", "dvb-ci.ami.req_type",
            FT_UINT8, BASE_HEX, VALS(dvbci_req_type), 0, NULL, HFILL }
        },
        { &hf_dvbci_file_hash,
          { "File hash", "dvb-ci.ami.file_hash",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_file_name,
          { "File name", "dvb-ci.ami.file_name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_ami_priv_data,
          { "Private data", "dvb-ci.ami.private_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_req_ok,
          { "RequestOK", "dvb-ci.ami.request_ok",
            FT_UINT8, BASE_HEX, NULL, 0x02, NULL, HFILL }
        },
        { &hf_dvbci_file_ok,
          { "FileOK", "dvb-ci.ami.file_ok",
            FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL }
        },
        { &hf_dvbci_file_data,
          { "File data", "dvb-ci.ami.file_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_abort_req_code,
          { "Abort request code", "dvb-ci.ami.abort_req_code",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_abort_ack_code,
          { "Abort acknowledgement code", "dvb-ci.ami.abort_ack_code",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_phase_id,
          { "Phase ID", "dvb-ci.lsc.comms_phase_id",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_comms_rep_id,
          { "Comms reply ID", "dvb-ci.lsc.comms_reply_id",
            FT_UINT8, BASE_HEX, VALS(dvbci_comms_rep_id), 0, NULL, HFILL }
        },
        { &hf_dvbci_lsc_buf_size,
          { "Buffer size", "dvb-ci.lsc.buf_size",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_lsc_ret_val,
          { "Return value", "dvb-ci.lsc.return_value",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_comms_cmd_id,
          { "Comms command ID", "dvb-ci.lsc.comms_cmd_id",
            FT_UINT8, BASE_HEX, VALS(dvbci_comms_cmd_id), 0, NULL, HFILL }
        },
        { &hf_dvbci_conn_desc_type,
          { "Type", "dvb-ci.lsc.conn_desc_type",
            FT_UINT8, BASE_HEX, VALS(dvbci_conn_desc_type), 0, NULL, HFILL }
        },
        { &hf_dvbci_lsc_media_tag,
          { "Tag", "dvb-ci.lsc.media_tag",
            FT_UINT8, BASE_HEX, VALS(dvbci_lsc_desc_tag), 0, NULL, HFILL }
        },
        { &hf_dvbci_lsc_media_len,
          { "Length", "dvb-ci.lsc.media_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_lsc_ip_ver,
          { "IP version", "dvb-ci.lsc.ip_version",
            FT_UINT8, BASE_DEC, VALS(dvbci_lsc_ip_ver), 0, NULL, HFILL }
        },
        { &hf_dvbci_lsc_ipv4_addr,
          { "IP address", "dvb-ci.lsc.ipv4_addr",
            FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_lsc_ipv6_addr,
          { "IPv6 address", "dvb-ci.lsc.ipv6_addr",
            FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_lsc_dst_port,
          { "Destination port", "dvb-ci.lsc.dst_port",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_lsc_proto,
          { "Protocol", "dvb-ci.lsc.protocol",
            FT_UINT8, BASE_HEX, VALS(dvbci_lsc_proto), 0, NULL, HFILL }
        },
        { &hf_dvbci_lsc_hostname,
          { "Hostname", "dvb-ci.lsc.hostname",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_lsc_retry_count,
          { "Retry count", "dvb-ci.lsc.retry_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_lsc_timeout,
          { "Timeout", "dvb-ci.lsc.timeout",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },

        /* filter string for hf_dvbci_info_ver_op_status and
         * hf_dvbci_info_ver_op_info below is the same, it seems this is ok */
        { &hf_dvbci_info_ver_op_status,
          { "Info version", "dvb-ci.opp.info_ver",
            FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }
        },
        { &hf_dvbci_nit_ver,
          { "NIT version", "dvb-ci.opp.nit_ver",
            FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }
        },
        { &hf_dvbci_pro_typ,
          { "Profile type", "dvb-ci.opp.profile_type",
            FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_dvbci_init_flag,
          { "Initialized flag", "dvb-ci.opp.init_flag",
            FT_UINT8, BASE_HEX, NULL, 0x20, NULL, HFILL }
        },
        { &hf_dvbci_ent_chg_flag,
          { "Entitlement change flag", "dvb-ci.opp.ent_chg_flag",
            FT_UINT8, BASE_HEX, NULL, 0x10, NULL, HFILL }
        },
        { &hf_dvbci_ent_val_flag,
          { "Entitlement valid flag", "dvb-ci.opp.ent_val_flag",
            FT_UINT8, BASE_HEX, NULL, 0x08, NULL, HFILL }
        },
        { &hf_dvbci_ref_req_flag,
          { "Refresh request flag", "dvb-ci.opp.refresh_req_flag",
            FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL }
        },
        { &hf_dvbci_err_flag,
          { "Error flag", "dvb-ci.opp.err_flag",
            FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_dvbci_dlv_sys_hint,
          { "Delivery system hint", "dvb-ci.opp.dlv_sys_hint",
            FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_dvbci_refr_req_date,
          { "Refresh request date", "dvb-ci.opp.refresh_req_date",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_refr_req_time,
          { "Refresh request time", "dvb-ci.opp.refresh_req_time",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_nit_loop_len,
          { "NIT loop length", "dvb-ci.opp.nit_loop_len",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_info_valid,
          { "Info valid", "dvb-ci.opp.info_valid",
            FT_UINT8, BASE_HEX, NULL, 0x08, NULL, HFILL }
        },
        { &hf_dvbci_info_ver_op_info,
          { "Info version", "dvb-ci.opp.info_ver",
            FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }
        },
        { &hf_dvbci_cicam_onid,
          { "CICAM original network id", "dvb-ci.opp.cicam_onid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_cicam_id,
          { "CICAM ID", "dvb-ci.opp.cicam_id",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_opp_char_tbl_multi,
          { "Multi-byte character table", "dvb-ci.opp.char_tbl_multi",
            FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_opp_char_tbl,
          { "Character code table", "dvb-ci.opp.char_tbl",
            FT_UINT8, BASE_HEX, VALS(dvbci_char_tbl), 0, NULL, HFILL }
        },
        { &hf_dvbci_enc_type_id,
          { "Encoding type ID", "dvb-ci.opp.enc_type_id",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_sdt_rst_trusted,
          { "SDT running status trusted", "dvb-ci.opp.sdt_rst_trusted",
            FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_dvbci_eit_rst_trusted,
          { "EIT running status trusted", "dvb-ci.opp.eit_rst_trusted",
            FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL }
        },
        { &hf_dvbci_eit_pf_usage,
          { "EIT present/following usage", "dvb-ci.opp.eit_pf_usage",
            FT_UINT8, BASE_HEX, NULL, 0x30, NULL, HFILL }
        },
        { &hf_dvbci_eit_sch_usage,
          { "EIT schedule usage", "dvb-ci.opp.eit_sch_usage",
            FT_UINT8, BASE_HEX, NULL, 0x0E, NULL, HFILL }
        },
        { &hf_dvbci_ext_evt_usage,
          { "Extended event usage", "dvb-ci.opp.ext_evt_usage",
            FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL }
        },
        { &hf_dvbci_sdt_oth_trusted,
          { "SDT_other trusted", "dvb-ci.opp.sdt_oth_trusted",
            FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_dvbci_eit_evt_trigger,
          { "EIT event trigger", "dvb-ci.opp.eit_evt_trigger",
            FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL }
        },
        { &hf_dvbci_opp_lang_code,
          { "Language code", "dvb-ci.opp.lang_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_prof_name,
          { "Profile name", "dvb-ci.opp.profile_name",
            FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_unattended,
          { "Unattended flag", "dvb-ci.opp.unattended_flag",
            FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_dvbci_opp_srv_type,
          { "Service type", "dvb-ci.opp.service_type",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_dlv_cap_byte,
          { "Delivery capability byte", "dvb-ci.opp.dlv_cap_byte",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },

        /* the CI+ spec is not particularly clear about this but an
         * application id in the capability loop must always be 2 bytes */
        { &hf_dvbci_app_cap_bytes,
          { "Application capability bytes", "dvb-ci.opp.app_cap_bytes",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_desc_num,
          { "Next unprocessed descriptor number", "dvb-ci.opp.desc_num",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_sig_strength,
          { "Signal strength", "dvb-ci.opp.sig_strength",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_sig_qual,
          { "Signal quality", "dvb-ci.opp.sig_qual",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_opp_tune_status,
          { "Tuning status", "dvb-ci.opp.tune_status",
            FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_dvbci_opp_desc_loop_len,
          { "Descriptor loop length", "dvb-ci.opp.desc_loop_len",
            FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL }
        },
        { &hf_dvbci_sas_app_id,
          { "Application ID", "dvb-ci.sas.app_id",
            FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_sas_sess_state,
          { "Connection state", "dvb-ci.sas.sess_state",
            FT_UINT8, BASE_DEC, VALS(dvbci_sas_sess_state), 0, NULL, HFILL }
        },
        { &hf_dvbci_sas_msg_nb,
          { "Message number", "dvb-ci.sas.msg_nb",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_dvbci_sas_msg_len,
          { "Message length", "dvb-ci.sas.msg_len",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        }
    };

    spdu_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    for(i=0; i<array_length(spdu_info); i++) {
        g_hash_table_insert(spdu_table,
                            GUINT_TO_POINTER((guint)spdu_info[i].tag),
                            (const gpointer)(&spdu_info[i]));
    }

    apdu_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    for(i=0; i<array_length(apdu_info); i++) {
        g_hash_table_insert(apdu_table,
                            GUINT_TO_POINTER((guint)apdu_info[i].tag),
                            (const gpointer)(&apdu_info[i]));
    }

    proto_dvbci = proto_register_protocol(
        "DVB Common Interface", "DVB-CI", "dvb-ci");
    proto_register_field_array(proto_dvbci, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    dvbci_module = prefs_register_protocol(
        proto_dvbci, proto_reg_handoff_dvbci);
    prefs_register_string_preference(dvbci_module,
            "sek", "SAC Encryption Key", "SAC Encryption Key (16 hex bytes)",
            &dvbci_sek);
    prefs_register_string_preference(dvbci_module,
            "siv", "SAC Init Vector", "SAC Init Vector (16 hex bytes)",
            &dvbci_siv);
    prefs_register_bool_preference(dvbci_module,
            "dissect_lsc_msg",
            "Dissect LSC messages",
            "Dissect the content of messages transmitted "
                "on the Low-Speed Communication resource. "
                "This requires a dissector for the protocol and target port "
                "contained in the connection descriptor.",
            &dvbci_dissect_lsc_msg);

    sas_msg_dissector_table = register_dissector_table("dvb-ci.sas.app_id_str",
                "SAS application id", FT_STRING, BASE_NONE);

    register_init_routine(dvbci_init);
}


void
proto_reg_handoff_dvbci(void)
{
    dissector_handle_t dvbci_handle;

    dvbci_handle = new_create_dissector_handle(dissect_dvbci, proto_dvbci);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_DVBCI, dvbci_handle);

    data_handle = find_dissector("data");
    mpeg_pmt_handle = find_dissector("mpeg_pmt");
    dvb_nit_handle = find_dissector("dvb_nit");
    tcp_dissector_table = find_dissector_table("tcp.port");
    udp_dissector_table = find_dissector_table("udp.port");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
