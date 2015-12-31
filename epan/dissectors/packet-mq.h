/* packet-mq.h
 * Routines for IBM WebSphere MQ packet dissection header
 *
 * metatech <metatech@flashmail.com>
 * robionekenobi <robionekenobi@bluewin.ch>
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

#ifndef __PACKET_MQ_H__
#define __PACKET_MQ_H__

#define GET_VALSV(A) mq_##A##_vals
#define GET_VALSV2(A) GET_VALSV(A)
#define DEF_VALSX(A) extern value_string GET_VALSV(A)[]
/* This Macro is used to cast a value_string to a const gchar *
*  Used in value_string MQCFINT_Parse, because this value_string
*  don't return a string for a specific value, but a value_string
*  that can be used in another call to try_val_to_str
*/
#define GET_VALSP(F) (const gchar *)GET_VALSV(F)
#define DEF_VALSB(A) static const value_string GET_VALSV(A)[] = \
{
#define DEF_VALSBX(A) value_string GET_VALSV(A)[] = \
{
#define DEF_VALS1(A)    { (guint32)MQ_##A, #A }
#define DEF_VALS2(A, B) { (guint32)MQ_##A, B }
#define DEF_VALSE \
{ 0, NULL } \
}

/* VALS_EXT_STRING */
#define GET_VALS_EXTV(A) mq_##A##_xvals
#define GET_VALS_EXTP(A) (value_string_ext *)&GET_VALS_EXTV(A)
#define DEF_VALS_EXTB(A) static value_string_ext GET_VALS_EXTV(A) = VALUE_STRING_EXT_INIT(mq_##A##_vals)
#define DEF_VALS_EXTBX(A) value_string_ext GET_VALS_EXTV(A) = VALUE_STRING_EXT_INIT(mq_##A##_vals)
#define DEF_VALS_EXTX(A)  extern value_string_ext GET_VALS_EXTV(A)

/* | BASE_RANGE_STRING, GET_VALRV(RVALS(aaa)) */
#define GET_VALRV(A) mq_##A##_rvals
#define DEF_VALRX(A) extern const range_string GET_VALRV(A)[]
#define GET_VALRP(F) (gchar *)GET_VALRV(F)
#define DEF_VALRB(A) const range_string GET_VALRV(A)[] = \
{
#define DEF_VALR1(A)       { (guint32)MQ_##A, (guint32)MQ_##A, #A }
#define DEF_VALR3(A, B, C) { (guint32)MQ_##A, (guint32)MQ_##B, C }
#define DEF_VALRE \
{ 0, 0, NULL } \
}

typedef struct _mq_ccsid_t
{
    guint32 encod;
    guint32 ccsid;
} mq_ccsid_t;

typedef struct _mq_parm_t
{
    guint32    mq_convID ;
    guint32    mq_rqstID;
    guint32    mq_strucID ;
    guint32    mq_int_enc ;
    guint32    mq_str_enc ;
    guint32    mq_FAPLvl  ;
    guint8     mq_ctlf1   ;
    guint8     mq_ctlf2   ;
    guint8     mq_opcode  ;
    mq_ccsid_t mq_tsh_ccsid;
    mq_ccsid_t mq_id_ccsid;
    mq_ccsid_t mq_md_ccsid;
    mq_ccsid_t mq_dlh_ccsid;
    mq_ccsid_t mq_head_ccsid;
    mq_ccsid_t mq_msgreq_ccsid;
    mq_ccsid_t mq_cur_ccsid;
    guint8     mq_format[8];
    gint32     iOfsEnc;     /* Offset to Message encoding */
    gint32     iOfsCcs;     /* Offset to Message character set */
    gint32     iOfsFmt;     /* Offset to Message format */
} mq_parm_t;

#define MQ_MQCA_XR_VERSION2 2120

#define MQ_0 0
#define MQ_1 1
#define MQ_2 2
#define MQ_3 3
#define MQ_4 4
#define MQ_5 5
#define MQ_6 6
#define MQ_7 7
#define MQ_8 8
#define MQ_9 9

/* Authentication Information Type */
#define MQ_MQAIT_ALL                      0
#define MQ_MQAIT_CRL_LDAP                 1
#define MQ_MQAIT_OCSP                     2
#define MQ_MQAIT_IDPW_OS                  3
#define MQ_MQAIT_IDPW_LDAP                4

/* Buffer To Message Handle Options */
#define MQ_MQBMHO_NONE                    0x00000000
#define MQ_MQBMHO_DELETE_PROPERTIES       0x00000001
/* Begin Options */
#define MQ_MQBO_NONE                      0x00000000

/* Flags */
#define MQ_MQCBCF_NONE                    0x00000000
#define MQ_MQCBCF_READA_BUFFER_EMPTY      0x00000001

/* Callback type */
#define MQ_MQCBCT_START_CALL              1
#define MQ_MQCBCT_STOP_CALL               2
#define MQ_MQCBCT_REGISTER_CALL           3
#define MQ_MQCBCT_DEREGISTER_CALL         4
#define MQ_MQCBCT_EVENT_CALL              5
#define MQ_MQCBCT_MSG_REMOVED             6
#define MQ_MQCBCT_MSG_NOT_REMOVED         7
#define MQ_MQCBCT_MC_EVENT_CALL           8

/* Consumer state */
#define MQ_MQCS_NONE                      0
#define MQ_MQCS_SUSPENDED_TEMPORARY       1
#define MQ_MQCS_SUSPENDED_USER_ACTION     2
#define MQ_MQCS_SUSPENDED                 3
#define MQ_MQCS_STOPPED                   4

/* Reconnect delay */
#define MQ_MQRD_NO_RECONNECT              (-1)
#define MQ_MQRD_NO_DELAY                  0

/* Callback Options */
#define MQ_MQCBDO_NONE                    0x00000000
#define MQ_MQCBDO_START_CALL              0x00000001
#define MQ_MQCBDO_STOP_CALL               0x00000004
#define MQ_MQCBDO_REGISTER_CALL           0x00000100
#define MQ_MQCBDO_DEREGISTER_CALL         0x00000200
#define MQ_MQCBDO_FAIL_IF_QUIESCING       0x00002000
#define MQ_MQCBDO_EVENT_CALL              0x00004000
#define MQ_MQCBDO_MC_EVENT_CALL           0x00008000

/* This is the type of the Callback Function */
#define MQ_MQCBT_MESSAGE_CONSUMER         0x00000001
#define MQ_MQCBT_EVENT_HANDLER            0x00000002

/* Buffer size values */
#define MQ_MQCBD_FULL_MSG_LENGTH          (-1)

/* Variable String Length */
#define MQ_MQVS_NULL_TERMINATED           (-1)

/* Flags */
#define MQ_MQCIH_NONE                     0x00000000
#define MQ_MQCIH_PASS_EXPIRATION          0x00000001
#define MQ_MQCIH_UNLIMITED_EXPIRATION     0x00000000
#define MQ_MQCIH_REPLY_WITHOUT_NULLS      0x00000002
#define MQ_MQCIH_REPLY_WITH_NULLS         0x00000000
#define MQ_MQCIH_SYNC_ON_RETURN           0x00000004
#define MQ_MQCIH_NO_SYNC_ON_RETURN        0x00000000

/* Return Codes */
#define MQ_MQCRC_OK                       0
#define MQ_MQCRC_CICS_EXEC_ERROR          1
#define MQ_MQCRC_MQ_API_ERROR             2
#define MQ_MQCRC_BRIDGE_ERROR             3
#define MQ_MQCRC_BRIDGE_ABEND             4
#define MQ_MQCRC_APPLICATION_ABEND        5
#define MQ_MQCRC_SECURITY_ERROR           6
#define MQ_MQCRC_PROGRAM_NOT_AVAILABLE    7
#define MQ_MQCRC_BRIDGE_TIMEOUT           8
#define MQ_MQCRC_TRANSID_NOT_AVAILABLE    9

/* Unit-of-Work Controls */
#define MQ_MQCUOWC_ONLY                   0x00000111
#define MQ_MQCUOWC_CONTINUE               0x00010000
#define MQ_MQCUOWC_FIRST                  0x00000011
#define MQ_MQCUOWC_MIDDLE                 0x00000010
#define MQ_MQCUOWC_LAST                   0x00000110
#define MQ_MQCUOWC_COMMIT                 0x00000100
#define MQ_MQCUOWC_BACKOUT                0x00001100

/* Get Wait Interval */
#define MQ_MQCGWI_DEFAULT                 (-2)

/* Link Types */
#define MQ_MQCLT_PROGRAM                  1
#define MQ_MQCLT_TRANSACTION              2

/* Output Data Length */
#define MQ_MQCODL_AS_INPUT                (-1)
#define MQ_MQCODL_0                         0
#define MQ_MQCODL_7FFFFFFF                0x7FFFFFFF

/* ADS Descriptors */
#define MQ_MQCADSD_NONE                   0x00000000
#define MQ_MQCADSD_SEND                   0x00000001
#define MQ_MQCADSD_RECV                   0x00000010
#define MQ_MQCADSD_MSGFORMAT              0x00000100

/* Conversational Task Options */
#define MQ_MQCCT_YES                      0x00000001
#define MQ_MQCCT_NO                       0x00000000

/* Task End Status */
#define MQ_MQCTES_NOSYNC                  0x00000000
#define MQ_MQCTES_COMMIT                  0x00000100
#define MQ_MQCTES_BACKOUT                 0x00001100
#define MQ_MQCTES_ENDTASK                 0x00010000

/* Functions */
#define MQ_MQCFUNC_MQCONN                 "CONN"
#define MQ_MQCFUNC_MQGET                  "GET "
#define MQ_MQCFUNC_MQINQ                  "INQ "
#define MQ_MQCFUNC_MQOPEN                 "OPEN"
#define MQ_MQCFUNC_MQPUT                  "PUT "
#define MQ_MQCFUNC_MQPUT1                 "PUT1"
#define MQ_MQCFUNC_NONE                   "    "

/* Start Codes */
#define MQ_MQCSC_START                    "S   "
#define MQ_MQCSC_STARTDATA                "SD  "
#define MQ_MQCSC_TERMINPUT                "TD  "
#define MQ_MQCSC_NONE                     "    "

/* Create Message Handle Options */
#define MQ_MQCMHO_DEFAULT_VALIDATION      0x00000000
#define MQ_MQCMHO_NO_VALIDATION           0x00000001
#define MQ_MQCMHO_VALIDATE                0x00000002
#define MQ_MQCMHO_NONE                    0x00000000

/* Consumer Control Options */
#define MQ_MQCTLO_NONE                    0x00000000
#define MQ_MQCTLO_THREAD_AFFINITY         0x00000001
#define MQ_MQCTLO_FAIL_IF_QUIESCING       0x00002000

/* SuiteB Type */
#define MQ_MQ_SUITE_B_NOT_AVAILABLE       0
#define MQ_MQ_SUITE_B_NONE                1
#define MQ_MQ_SUITE_B_128_BIT             2
#define MQ_MQ_SUITE_B_192_BIT             4

/* Key Reset Count */
#define MQ_MQSCO_RESET_COUNT_DEFAULT      0

/* Certificate Validation Policy Type */
#define MQ_MQ_CERT_VAL_POLICY_DEFAULT     0
#define MQ_MQ_CERT_VAL_POLICY_ANY         0
#define MQ_MQ_CERT_VAL_POLICY_RFC5280     1

/* Authentication Types */
#define MQ_MQCSP_AUTH_NONE                0
#define MQ_MQCSP_AUTH_USER_ID_AND_PWD     1

/* Connect Options */
#define MQ_MQCNO_STANDARD_BINDING         0x00000000
#define MQ_MQCNO_FASTPATH_BINDING         0x00000001
#define MQ_MQCNO_SERIALIZE_CONN_TAG_Q_MGR 0x00000002
#define MQ_MQCNO_SERIALIZE_CONN_TAG_QSG   0x00000004
#define MQ_MQCNO_RESTRICT_CONN_TAG_Q_MGR  0x00000008
#define MQ_MQCNO_RESTRICT_CONN_TAG_QSG    0x00000010
#define MQ_MQCNO_HANDLE_SHARE_NONE        0x00000020
#define MQ_MQCNO_HANDLE_SHARE_BLOCK       0x00000040
#define MQ_MQCNO_HANDLE_SHARE_NO_BLOCK    0x00000080
#define MQ_MQCNO_SHARED_BINDING           0x00000100
#define MQ_MQCNO_ISOLATED_BINDING         0x00000200
#define MQ_MQCNO_LOCAL_BINDING            0x00000400
#define MQ_MQCNO_CLIENT_BINDING           0x00000800
#define MQ_MQCNO_ACCOUNTING_MQI_ENABLED   0x00001000
#define MQ_MQCNO_ACCOUNTING_MQI_DISABLED  0x00002000
#define MQ_MQCNO_ACCOUNTING_Q_ENABLED     0x00004000
#define MQ_MQCNO_ACCOUNTING_Q_DISABLED    0x00008000
#define MQ_MQCNO_NO_CONV_SHARING          0x00010000
#define MQ_MQCNO_ALL_CONVS_SHARE          0x00040000
#define MQ_MQCNO_CD_FOR_OUTPUT_ONLY       0x00080000
#define MQ_MQCNO_USE_CD_SELECTION         0x00100000
#define MQ_MQCNO_RECONNECT_AS_DEF         0x00000000
#define MQ_MQCNO_RECONNECT                0x01000000
#define MQ_MQCNO_RECONNECT_DISABLED       0x02000000
#define MQ_MQCNO_RECONNECT_Q_MGR          0x04000000
#define MQ_MQCNO_ACTIVITY_TRACE_ENABLED   0x08000000
#define MQ_MQCNO_ACTIVITY_TRACE_DISABLED  0x10000000
#define MQ_MQCNO_NONE                     0x00000000

/* Flags */
#define MQ_MQDHF_NEW_MSG_IDS              0x00000001
#define MQ_MQDHF_NONE                     0x00000000

/* Delete Message Handle Options */
#define MQ_MQDMHO_NONE                    0x00000000

/* Delete Message Property Options */
#define MQ_MQDMPO_DEL_FIRST               0x00000000
#define MQ_MQDMPO_DEL_PROP_UNDER_CURSOR   0x00000001
#define MQ_MQDMPO_NONE                    0x00000000

/* Get Message Options */
#define MQ_MQGMO_WAIT                     0x00000001
#define MQ_MQGMO_NO_WAIT                  0x00000000
#define MQ_MQGMO_SET_SIGNAL               0x00000008
#define MQ_MQGMO_FAIL_IF_QUIESCING        0x00002000
#define MQ_MQGMO_SYNCPOINT                0x00000002
#define MQ_MQGMO_SYNCPOINT_IF_PERSISTENT  0x00001000
#define MQ_MQGMO_NO_SYNCPOINT             0x00000004
#define MQ_MQGMO_MARK_SKIP_BACKOUT        0x00000080
#define MQ_MQGMO_BROWSE_FIRST             0x00000010
#define MQ_MQGMO_BROWSE_NEXT              0x00000020
#define MQ_MQGMO_BROWSE_MSG_UNDER_CURSOR  0x00000800
#define MQ_MQGMO_MSG_UNDER_CURSOR         0x00000100
#define MQ_MQGMO_LOCK                     0x00000200
#define MQ_MQGMO_UNLOCK                   0x00000400
#define MQ_MQGMO_ACCEPT_TRUNCATED_MSG     0x00000040
#define MQ_MQGMO_CONVERT                  0x00004000
#define MQ_MQGMO_LOGICAL_ORDER            0x00008000
#define MQ_MQGMO_COMPLETE_MSG             0x00010000
#define MQ_MQGMO_ALL_MSGS_AVAILABLE       0x00020000
#define MQ_MQGMO_ALL_SEGMENTS_AVAILABLE   0x00040000
#define MQ_MQGMO_MARK_BROWSE_HANDLE       0x00100000
#define MQ_MQGMO_MARK_BROWSE_CO_OP        0x00200000
#define MQ_MQGMO_UNMARK_BROWSE_CO_OP      0x00400000
#define MQ_MQGMO_UNMARK_BROWSE_HANDLE     0x00800000
#define MQ_MQGMO_UNMARKED_BROWSE_MSG      0x01000000
#define MQ_MQGMO_PROPERTIES_FORCE_MQRFH2  0x02000000
#define MQ_MQGMO_NO_PROPERTIES            0x04000000
#define MQ_MQGMO_PROPERTIES_IN_HANDLE     0x08000000
#define MQ_MQGMO_PROPERTIES_COMPATIBILITY 0x10000000
#define MQ_MQGMO_PROPERTIES_AS_Q_DEF      0x00000000
#define MQ_MQGMO_NONE                     0x00000000
#define MQ_MQGMO_BROWSE_HANDLE            ( MQ_MQGMO_BROWSE_FIRST \
    | MQ_MQGMO_UNMARKED_BROWSE_MSG \
    | MQ_MQGMO_MARK_BROWSE_HANDLE )
#define MQ_MQGMO_BROWSE_CO_OP             ( MQ_MQGMO_BROWSE_FIRST \
    | MQ_MQGMO_UNMARKED_BROWSE_MSG \
    | MQ:MQGMO_MARK_BROWSE_CO_OP )

/* Wait Interval */
#define MQ_MQWI_UNLIMITED                 (-1)
#define MQ_MQWI_0                           0
#define MQ_MQWI_7FFFFFFF                  0x7FFFFFFF

/* Signal Values */
#define MQ_MQEC_MSG_ARRIVED               2
#define MQ_MQEC_WAIT_INTERVAL_EXPIRED     3
#define MQ_MQEC_WAIT_CANCELED             4
#define MQ_MQEC_Q_MGR_QUIESCING           5
#define MQ_MQEC_CONNECTION_QUIESCING      6

/* Match Options */
#define MQ_MQMO_MATCH_MSG_ID              0x00000001
#define MQ_MQMO_MATCH_CORREL_ID           0x00000002
#define MQ_MQMO_MATCH_GROUP_ID            0x00000004
#define MQ_MQMO_MATCH_MSG_SEQ_NUMBER      0x00000008
#define MQ_MQMO_MATCH_OFFSET              0x00000010
#define MQ_MQMO_MATCH_MSG_TOKEN           0x00000020
#define MQ_MQMO_NONE                      0x00000000

/* LPOO Options */
#define MQ_LPOO_SAVE_IDENTITY_CTXT  0x00000001
#define MQ_LPOO_SAVE_ORIGIN_CTXT    0x00000002
#define MQ_LPOO_SAVE_USER_CTXT      0x00000004

/* Group Status */
#define MQ_MQGS_NOT_IN_GROUP              ' '
#define MQ_MQGS_MSG_IN_GROUP              'G'
#define MQ_MQGS_LAST_MSG_IN_GROUP         'L'

/* Segment Status */
#define MQ_MQSS_NOT_A_SEGMENT             ' '
#define MQ_MQSS_SEGMENT                   'S'
#define MQ_MQSS_LAST_SEGMENT              'L'

/* Segmentation */
#define MQ_MQSEG_INHIBITED                ' '
#define MQ_MQSEG_ALLOWED                  'A'

/* Returned Length */
#define MQ_MQRL_UNDEFINED                 (-1)

/* Flags */
#define MQ_MQIIH_NONE                     0x00000000
#define MQ_MQIIH_PASS_EXPIRATION          0x00000001
#define MQ_MQIIH_UNLIMITED_EXPIRATION     0x00000000
#define MQ_MQIIH_REPLY_FORMAT_NONE        0x00000008
#define MQ_MQIIH_IGNORE_PURG              0x00000010
#define MQ_MQIIH_CM0_REQUEST_RESPONSE     0x00000020

/* Transaction States */
#define MQ_MQITS_IN_CONVERSATION          'C'
#define MQ_MQITS_NOT_IN_CONVERSATION      ' '
#define MQ_MQITS_ARCHITECTED              'A'

/* Commit Modes */
#define MQ_MQICM_COMMIT_THEN_SEND         '0'
#define MQ_MQICM_SEND_THEN_COMMIT         '1'

/* Security Scopes */
#define MQ_MQISS_CHECK                    'C'
#define MQ_MQISS_FULL                     'F'

/* Inquire Message Property Options */
#define MQ_MQIMPO_CONVERT_TYPE            0x00000002
#define MQ_MQIMPO_QUERY_LENGTH            0x00000004
#define MQ_MQIMPO_INQ_FIRST               0x00000000
#define MQ_MQIMPO_INQ_NEXT                0x00000008
#define MQ_MQIMPO_INQ_PROP_UNDER_CURSOR   0x00000010
#define MQ_MQIMPO_CONVERT_VALUE           0x00000020
#define MQ_MQIMPO_NONE                    0x00000000

/* Report Options */
#define MQ_MQRO_EXCEPTION                 0x01000000
#define MQ_MQRO_EXCEPTION_WITH_DATA       0x03000000
#define MQ_MQRO_EXCEPTION_WITH_FULL_DATA  0x07000000
#define MQ_MQRO_EXPIRATION                0x00200000
#define MQ_MQRO_EXPIRATION_WITH_DATA      0x00600000
#define MQ_MQRO_EXPIRATION_WITH_FULL_DATA 0x00E00000
#define MQ_MQRO_COA                       0x00000100
#define MQ_MQRO_COA_WITH_DATA             0x00000300
#define MQ_MQRO_COA_WITH_FULL_DATA        0x00000700
#define MQ_MQRO_COD                       0x00000800
#define MQ_MQRO_COD_WITH_DATA             0x00001800
#define MQ_MQRO_COD_WITH_FULL_DATA        0x00003800
#define MQ_MQRO_PAN                       0x00000001
#define MQ_MQRO_NAN                       0x00000002
#define MQ_MQRO_ACTIVITY                  0x00000004
#define MQ_MQRO_NEW_MSG_ID                0x00000000
#define MQ_MQRO_PASS_MSG_ID               0x00000080
#define MQ_MQRO_COPY_MSG_ID_TO_CORREL_ID  0x00000000
#define MQ_MQRO_PASS_CORREL_ID            0x00000040
#define MQ_MQRO_DEAD_LETTER_Q             0x00000000
#define MQ_MQRO_DISCARD_MSG               0x08000000
#define MQ_MQRO_PASS_DISCARD_AND_EXPIRY   0x00004000
#define MQ_MQRO_NONE                      0x00000000

/* Report Options Masks */
#define MQ_MQRO_REJECT_UNSUP_MASK         0x101C0000
#define MQ_MQRO_ACCEPT_UNSUP_MASK         0xEFE000FF
#define MQ_MQRO_ACCEPT_UNSUP_IF_XMIT_MASK 0x0003FF00

/* Message Types */
#define MQ_MQMT_SYSTEM_FIRST              1
#define MQ_MQMT_REQUEST                   1
#define MQ_MQMT_REPLY                     2
#define MQ_MQMT_DATAGRAM                  8
#define MQ_MQMT_REPORT                    4
#define MQ_MQMT_MQE_FIELDS_FROM_MQE       112
#define MQ_MQMT_MQE_FIELDS                113
#define MQ_MQMT_SYSTEM_LAST               65535
#define MQ_MQMT_APPL_FIRST                65536
#define MQ_MQMT_APPL_LAST                 999999999

/* Expiry */
#define MQ_MQEI_UNLIMITED                 (-1)

/* Feedback Values */
#define MQ_MQFB_NONE                      0
#define MQ_MQFB_SYSTEM_FIRST              1
#define MQ_MQFB_QUIT                      256
#define MQ_MQFB_EXPIRATION                258
#define MQ_MQFB_COA                       259
#define MQ_MQFB_COD                       260
#define MQ_MQFB_CHANNEL_COMPLETED         262
#define MQ_MQFB_CHANNEL_FAIL_RETRY        263
#define MQ_MQFB_CHANNEL_FAIL              264
#define MQ_MQFB_APPL_CANNOT_BE_STARTED    265
#define MQ_MQFB_TM_ERROR                  266
#define MQ_MQFB_APPL_TYPE_ERROR           267
#define MQ_MQFB_STOPPED_BY_MSG_EXIT       268
#define MQ_MQFB_ACTIVITY                  269
#define MQ_MQFB_XMIT_Q_MSG_ERROR          271
#define MQ_MQFB_PAN                       275
#define MQ_MQFB_NAN                       276
#define MQ_MQFB_STOPPED_BY_CHAD_EXIT      277
#define MQ_MQFB_STOPPED_BY_PUBSUB_EXIT    279
#define MQ_MQFB_NOT_A_REPOSITORY_MSG      280
#define MQ_MQFB_BIND_OPEN_CLUSRCVR_DEL    281
#define MQ_MQFB_MAX_ACTIVITIES            282
#define MQ_MQFB_NOT_FORWARDED             283
#define MQ_MQFB_NOT_DELIVERED             284
#define MQ_MQFB_UNSUPPORTED_FORWARDING    285
#define MQ_MQFB_UNSUPPORTED_DELIVERY      286
#define MQ_MQFB_DATA_LENGTH_ZERO          291
#define MQ_MQFB_DATA_LENGTH_NEGATIVE      292
#define MQ_MQFB_DATA_LENGTH_TOO_BIG       293
#define MQ_MQFB_BUFFER_OVERFLOW           294
#define MQ_MQFB_LENGTH_OFF_BY_ONE         295
#define MQ_MQFB_IIH_ERROR                 296
#define MQ_MQFB_NOT_AUTHORIZED_FOR_IMS    298
#define MQ_MQFB_IMS_ERROR                 300
#define MQ_MQFB_IMS_FIRST                 301
#define MQ_MQFB_IMS_LAST                  399
#define MQ_MQFB_CICS_INTERNAL_ERROR       401
#define MQ_MQFB_CICS_NOT_AUTHORIZED       402
#define MQ_MQFB_CICS_BRIDGE_FAILURE       403
#define MQ_MQFB_CICS_CORREL_ID_ERROR      404
#define MQ_MQFB_CICS_CCSID_ERROR          405
#define MQ_MQFB_CICS_ENCODING_ERROR       406
#define MQ_MQFB_CICS_CIH_ERROR            407
#define MQ_MQFB_CICS_UOW_ERROR            408
#define MQ_MQFB_CICS_COMMAREA_ERROR       409
#define MQ_MQFB_CICS_APPL_NOT_STARTED     410
#define MQ_MQFB_CICS_APPL_ABENDED         411
#define MQ_MQFB_CICS_DLQ_ERROR            412
#define MQ_MQFB_CICS_UOW_BACKED_OUT       413
#define MQ_MQFB_PUBLICATIONS_ON_REQUEST   501
#define MQ_MQFB_SUBSCRIBER_IS_PUBLISHER   502
#define MQ_MQFB_MSG_SCOPE_MISMATCH        503
#define MQ_MQFB_SELECTOR_MISMATCH         504
#define MQ_MQFB_NOT_A_GROUPUR_MSG         505
#define MQ_MQFB_IMS_NACK_1A_REASON_FIRST  600
#define MQ_MQFB_IMS_NACK_1A_REASON_LAST   855
#define MQ_MQFB_SYSTEM_LAST               65535
#define MQ_MQFB_APPL_FIRST                65536
#define MQ_MQFB_APPL_LAST                 999999999

/* Encoding */
#define MQ_MQENC_NATIVE                   0x00000222

/* Encoding Masks */
#define MQ_MQENC_INTEGER_MASK             0x0000000F
#define MQ_MQENC_DECIMAL_MASK             0x000000F0
#define MQ_MQENC_FLOAT_MASK               0x00000F00
#define MQ_MQENC_RESERVED_MASK            0xFFFFF000

/* Encodings for Binary Integers */
#define MQ_MQENC_INTEGER_UNDEFINED        0x00000000
#define MQ_MQENC_INTEGER_NORMAL           0x00000001
#define MQ_MQENC_INTEGER_REVERSED         0x00000002

/* Encodings for Packed Decimal Integers */
#define MQ_MQENC_DECIMAL_UNDEFINED        0x00000000
#define MQ_MQENC_DECIMAL_NORMAL           0x00000010
#define MQ_MQENC_DECIMAL_REVERSED         0x00000020

/* Encodings for Floating Point Numbers */
#define MQ_MQENC_FLOAT_UNDEFINED          0x00000000
#define MQ_MQENC_FLOAT_IEEE_NORMAL        0x00000100
#define MQ_MQENC_FLOAT_IEEE_REVERSED      0x00000200
#define MQ_MQENC_FLOAT_S390               0x00000300
#define MQ_MQENC_FLOAT_TNS                0x00000400

/* Encodings for Multicast */
#define MQ_MQENC_NORMAL                   ( MQ_MQENC_FLOAT_IEEE_NORMAL \
    | MQ_MQENC_DECIMAL_NORMAL \
    | MQ_MQENC_INTEGER_NORMAL )
#define MQ_MQENC_REVERSED                 ( MQ_MQENC_FLOAT_IEEE_REVERSED \
    | MQ_MQENC_DECIMAL_REVERSED \
    | MQ_MQENC_INTEGER_REVERSED )
#define MQ_MQENC_S390                     ( MQ_MQENC_FLOAT_S390 \
    | MQ_MQENC_DECIMAL_NORMAL \
    | MQ_MQENC_INTEGER_NORMAL )
#define MQ_MQENC_TNS                      ( MQ_MQENC_FLOAT_TNS \
    | MQ_MQENC_DECIMAL_NORMAL \
    | MQ_MQENC_INTEGER_NORMAL )
#define MQ_MQENC_AS_PUBLISHED             (-1)

/* Coded Character Set Identifiers */
#define MQ_MQCCSI_AS_PUBLISHED            (-4)
#define MQ_MQCCSI_APPL                    (-3)
#define MQ_MQCCSI_INHERIT                 (-2)
#define MQ_MQCCSI_EMBEDDED                (-1)
#define MQ_MQCCSI_UNDEFINED               0
#define MQ_MQCCSI_DEFAULT                 0
#define MQ_MQCCSI_Q_MGR                   0
#define MQ_MQCCSI_1                       1
#define MQ_MQCCSI_65535                   65535

/* Formats */
#define MQ_MQFMT_NONE                     "        "
#define MQ_MQFMT_ADMIN                    "MQADMIN "
#define MQ_MQFMT_AMQP                     "MQAMQP  "
#define MQ_MQFMT_CHANNEL_COMPLETED        "MQCHCOM "
#define MQ_MQFMT_CICS                     "MQCICS  "
#define MQ_MQFMT_COMMAND_1                "MQCMD1  "
#define MQ_MQFMT_COMMAND_2                "MQCMD2  "
#define MQ_MQFMT_DEAD_LETTER_HEADER       "MQDEAD  "
#define MQ_MQFMT_DIST_HEADER              "MQHDIST "
#define MQ_MQFMT_EMBEDDED_PCF             "MQHEPCF "
#define MQ_MQFMT_EVENT                    "MQEVENT "
#define MQ_MQFMT_IMS                      "MQIMS   "
#define MQ_MQFMT_IMS_VAR_STRING           "MQIMSVS "
#define MQ_MQFMT_MD_EXTENSION             "MQHMDE  "
#define MQ_MQFMT_PCF                      "MQPCF   "
#define MQ_MQFMT_REF_MSG_HEADER           "MQHREF  "
#define MQ_MQFMT_RF_HEADER                "MQHRF   "
#define MQ_MQFMT_RF_HEADER_1              "MQHRF   "
#define MQ_MQFMT_RF_HEADER_2              "MQHRF2  "
#define MQ_MQFMT_STRING                   "MQSTR   "
#define MQ_MQFMT_TRIGGER                  "MQTRIG  "
#define MQ_MQFMT_WORK_INFO_HEADER         "MQHWIH  "
#define MQ_MQFMT_XMIT_Q_HEADER            "MQXMIT  "

/* Priority */
#define MQ_MQPRI_PRIORITY_AS_Q_DEF        (-1)
#define MQ_MQPRI_PRIORITY_AS_PARENT       (-2)
#define MQ_MQPRI_PRIORITY_AS_PUBLISHED    (-3)
#define MQ_MQPRI_PRIORITY_AS_TOPIC_DEF    (-1)

/* Persistence Values */
#define MQ_MQPER_PERSISTENCE_AS_PARENT    (-1)
#define MQ_MQPER_NOT_PERSISTENT           0
#define MQ_MQPER_PERSISTENT               1
#define MQ_MQPER_PERSISTENCE_AS_Q_DEF     2
#define MQ_MQPER_PERSISTENCE_AS_TOPIC_DEF 2

/* Put Response Values */
#define MQ_MQPRT_RESPONSE_AS_PARENT       0
#define MQ_MQPRT_SYNC_RESPONSE            1
#define MQ_MQPRT_ASYNC_RESPONSE           2

/* Accounting Token Types */
#define MQ_MQACTT_UNKNOWN                 '\x00'
#define MQ_MQACTT_CICS_LUOW_ID            '\x01'
#define MQ_MQACTT_OS2_DEFAULT             '\x04'
#define MQ_MQACTT_DOS_DEFAULT             '\x05'
#define MQ_MQACTT_UNIX_NUMERIC_ID         '\x06'
#define MQ_MQACTT_OS400_ACCOUNT_TOKEN     '\x08'
#define MQ_MQACTT_WINDOWS_DEFAULT         '\x09'
#define MQ_MQACTT_NT_SECURITY_ID          '\x0B'
#define MQ_MQACTT_USER                    '\x19'

/* Put Application Types */
#define MQ_MQAT_UNKNOWN                   (-1)
#define MQ_MQAT_NO_CONTEXT                0
#define MQ_MQAT_CICS                      1
#define MQ_MQAT_MVS                       2
#define MQ_MQAT_OS390                     2
#define MQ_MQAT_ZOS                       2
#define MQ_MQAT_IMS                       3
#define MQ_MQAT_OS2                       4
#define MQ_MQAT_DOS                       5
#define MQ_MQAT_AIX                       6
#define MQ_MQAT_UNIX                      6
#define MQ_MQAT_QMGR                      7
#define MQ_MQAT_OS400                     8
#define MQ_MQAT_WINDOWS                   9
#define MQ_MQAT_CICS_VSE                  10
#define MQ_MQAT_WINDOWS_NT                11
#define MQ_MQAT_VMS                       12
#define MQ_MQAT_GUARDIAN                  13
#define MQ_MQAT_NSK                       13
#define MQ_MQAT_VOS                       14
#define MQ_MQAT_OPEN_TP1                  15
#define MQ_MQAT_VM                        18
#define MQ_MQAT_IMS_BRIDGE                19
#define MQ_MQAT_XCF                       20
#define MQ_MQAT_CICS_BRIDGE               21
#define MQ_MQAT_NOTES_AGENT               22
#define MQ_MQAT_TPF                       23
#define MQ_MQAT_USER                      25
#define MQ_MQAT_BROKER                    26
#define MQ_MQAT_QMGR_PUBLISH              26
#define MQ_MQAT_JAVA                      28
#define MQ_MQAT_DQM                       29
#define MQ_MQAT_CHANNEL_INITIATOR         30
#define MQ_MQAT_WLM                       31
#define MQ_MQAT_BATCH                     32
#define MQ_MQAT_RRS_BATCH                 33
#define MQ_MQAT_SIB                       34
#define MQ_MQAT_SYSTEM_EXTENSION          35
#define MQ_MQAT_MCAST_PUBLISH             36
#define MQ_MQAT_AMQP                      37
#define MQ_MQAT_DEFAULT                   11

/* Message Flags */
#define MQ_MQMF_SEGMENTATION_INHIBITED    0x00000000
#define MQ_MQMF_SEGMENTATION_ALLOWED      0x00000001
#define MQ_MQMF_MSG_IN_GROUP              0x00000008
#define MQ_MQMF_LAST_MSG_IN_GROUP         0x00000010
#define MQ_MQMF_SEGMENT                   0x00000002
#define MQ_MQMF_LAST_SEGMENT              0x00000004
#define MQ_MQMF_NONE                      0x00000000

/* Message Flags Masks */
#define MQ_MQMF_REJECT_UNSUP_MASK         0x00000FFF
#define MQ_MQMF_ACCEPT_UNSUP_MASK         0xFFF00000
#define MQ_MQMF_ACCEPT_UNSUP_IF_XMIT_MASK 0x000FF000

/* Original Length */
#define MQ_MQOL_UNDEFINED                 (-1)

/* Message Handle To Buffer Options */
#define MQ_MQMHBO_PROPERTIES_IN_MQRFH2    0x00000001
#define MQ_MQMHBO_DELETE_PROPERTIES       0x00000002
#define MQ_MQMHBO_NONE                    0x00000000

/* Obsolete DB2 Messages options on Inquire Group */
#define MQ_MQOM_NO                        0
#define MQ_MQOM_YES                       1

/* Object Types */
#define MQ_MQOT_NONE                      0
#define MQ_MQOT_Q                         1
#define MQ_MQOT_NAMELIST                  2
#define MQ_MQOT_PROCESS                   3
#define MQ_MQOT_STORAGE_CLASS             4
#define MQ_MQOT_Q_MGR                     5
#define MQ_MQOT_CHANNEL                   6
#define MQ_MQOT_AUTH_INFO                 7
#define MQ_MQOT_TOPIC                     8
#define MQ_MQOT_COMM_INFO                 9
#define MQ_MQOT_CF_STRUC                  10
#define MQ_MQOT_LISTENER                  11
#define MQ_MQOT_SERVICE                   12
#define MQ_MQOT_RESERVED_1                999

/* Extended Object Types */
#define MQ_MQOT_ALL                       1001
#define MQ_MQOT_ALIAS_Q                   1002
#define MQ_MQOT_MODEL_Q                   1003
#define MQ_MQOT_LOCAL_Q                   1004
#define MQ_MQOT_REMOTE_Q                  1005
#define MQ_MQOT_SENDER_CHANNEL            1007
#define MQ_MQOT_SERVER_CHANNEL            1008
#define MQ_MQOT_REQUESTER_CHANNEL         1009
#define MQ_MQOT_RECEIVER_CHANNEL          1010
#define MQ_MQOT_CURRENT_CHANNEL           1011
#define MQ_MQOT_SAVED_CHANNEL             1012
#define MQ_MQOT_SVRCONN_CHANNEL           1013
#define MQ_MQOT_CLNTCONN_CHANNEL          1014
#define MQ_MQOT_SHORT_CHANNEL             1015
#define MQ_MQOT_CHLAUTH                   1016
#define MQ_MQOT_REMOTE_Q_MGR_NAME         1017
#define MQ_MQOT_PROT_POLICY               1019
#define MQ_MQOT_TT_CHANNEL                1020
#define MQ_MQOT_AMQP_CHANNEL              1021

/* Property Descriptor Options */
#define MQ_MQPD_NONE                      0x00000000

/* Property Support Options */
#define MQ_MQPD_SUPPORT_OPTIONAL          0x00000001
#define MQ_MQPD_SUPPORT_REQUIRED          0x00100000
#define MQ_MQPD_SUPPORT_REQUIRED_IF_LOCAL 0x00000400
#define MQ_MQPD_REJECT_UNSUP_MASK         0xFFF00000
#define MQ_MQPD_ACCEPT_UNSUP_IF_XMIT_MASK 0x000FFC00
#define MQ_MQPD_ACCEPT_UNSUP_MASK         0x000003FF

/* Property Context */
#define MQ_MQPD_NO_CONTEXT                0x00000000
#define MQ_MQPD_USER_CONTEXT              0x00000001

/* Property Copy Options */
#define MQ_MQCOPY_NONE                    0x00000000
#define MQ_MQCOPY_ALL                     0x00000001
#define MQ_MQCOPY_FORWARD                 0x00000002
#define MQ_MQCOPY_PUBLISH                 0x00000004
#define MQ_MQCOPY_REPLY                   0x00000008
#define MQ_MQCOPY_REPORT                  0x00000010
#define MQ_MQCOPY_DEFAULT                 0x00000016

/* Put Message Options */
#define MQ_MQPMO_SYNCPOINT                0x00000002
#define MQ_MQPMO_NO_SYNCPOINT             0x00000004
#define MQ_MQPMO_DEFAULT_CONTEXT          0x00000020
#define MQ_MQPMO_NEW_MSG_ID               0x00000040
#define MQ_MQPMO_NEW_CORREL_ID            0x00000080
#define MQ_MQPMO_PASS_IDENTITY_CONTEXT    0x00000100
#define MQ_MQPMO_PASS_ALL_CONTEXT         0x00000200
#define MQ_MQPMO_SET_IDENTITY_CONTEXT     0x00000400
#define MQ_MQPMO_SET_ALL_CONTEXT          0x00000800
#define MQ_MQPMO_ALTERNATE_USER_AUTHORITY 0x00001000
#define MQ_MQPMO_FAIL_IF_QUIESCING        0x00002000
#define MQ_MQPMO_NO_CONTEXT               0x00004000
#define MQ_MQPMO_LOGICAL_ORDER            0x00008000
#define MQ_MQPMO_ASYNC_RESPONSE           0x00010000
#define MQ_MQPMO_SYNC_RESPONSE            0x00020000
#define MQ_MQPMO_RESOLVE_LOCAL_Q          0x00040000
#define MQ_MQPMO_WARN_IF_NO_SUBS_MATCHED  0x00080000
#define MQ_MQPMO_RETAIN                   0x00200000
#define MQ_MQPMO_MD_FOR_OUTPUT_ONLY       0x00800000
#define MQ_MQPMO_SCOPE_QMGR               0x04000000
#define MQ_MQPMO_SUPPRESS_REPLYTO         0x08000000
#define MQ_MQPMO_NOT_OWN_SUBS             0x10000000
#define MQ_MQPMO_RESPONSE_AS_Q_DEF        0x00000000
#define MQ_MQPMO_RESPONSE_AS_TOPIC_DEF    0x00000000
#define MQ_MQPMO_NONE                     0x00000000

/* Put Message Options for publish mask */
#define MQ_MQPMO_PUB_OPTIONS_MASK         0x00200000

/* Put Message Record Fields */
#define MQ_MQPMRF_MSG_ID                  0x00000001
#define MQ_MQPMRF_CORREL_ID               0x00000002
#define MQ_MQPMRF_GROUP_ID                0x00000004
#define MQ_MQPMRF_FEEDBACK                0x00000008
#define MQ_MQPMRF_ACCOUNTING_TOKEN        0x00000010
#define MQ_MQPMRF_NONE                    0x00000000

/* Action */
#define MQ_MQACTP_NEW                     0
#define MQ_MQACTP_FORWARD                 1
#define MQ_MQACTP_REPLY                   2
#define MQ_MQACTP_REPORT                  3

/* Flags */
#define MQ_MQRFH_NONE                     0x00000000
#define MQ_MQRFH_NO_FLAGS                 0
#define MQ_MQRFH_FLAGS_RESTRICTED_MASK    0xFFFF0000

/* Flags */
#define MQ_MQRMHF_LAST                    0x00000001
#define MQ_MQRMHF_NOT_LAST                0x00000000

/* Security Identifier Types */
#define MQ_MQSIDT_NONE                    '\x00'
#define MQ_MQSIDT_NT_SECURITY_ID          '\x01'
#define MQ_MQSIDT_WAS_SECURITY_ID         '\x02'

/* Set Message Property Options */
#define MQ_MQSMPO_SET_FIRST               0x00000000
#define MQ_MQSMPO_SET_PROP_UNDER_CURSOR   0x00000001
#define MQ_MQSMPO_SET_PROP_AFTER_CURSOR   0x00000002
#define MQ_MQSMPO_APPEND_PROPERTY         0x00000004
#define MQ_MQSMPO_SET_PROP_BEFORE_CURSOR  0x00000008
#define MQ_MQSMPO_NONE                    0x00000000

/* Connection Handles */
#define MQ_MQHC_DEF_HCONN                 0
#define MQ_MQHC_UNUSABLE_HCONN            (-1)
#define MQ_MQHC_UNASSOCIATED_HCONN        (-3)

/* String Lengths */
#define MQ_MQ_OPERATOR_MESSAGE_LENGTH     4
#define MQ_MQ_ABEND_CODE_LENGTH           4
#define MQ_MQ_ACCOUNTING_TOKEN_LENGTH     32
#define MQ_MQ_APPL_DESC_LENGTH            64
#define MQ_MQ_APPL_IDENTITY_DATA_LENGTH   32
#define MQ_MQ_APPL_NAME_LENGTH            28
#define MQ_MQ_APPL_ORIGIN_DATA_LENGTH     4
#define MQ_MQ_APPL_TAG_LENGTH             28
#define MQ_MQ_ARM_SUFFIX_LENGTH           2
#define MQ_MQ_ATTENTION_ID_LENGTH         4
#define MQ_MQ_AUTH_INFO_CONN_NAME_LENGTH  264
#define MQ_MQ_AUTH_INFO_DESC_LENGTH       64
#define MQ_MQ_AUTH_INFO_NAME_LENGTH       48
#define MQ_MQ_AUTH_INFO_OCSP_URL_LENGTH   256
#define MQ_MQ_AUTHENTICATOR_LENGTH        8
#define MQ_MQ_AUTO_REORG_CATALOG_LENGTH   44
#define MQ_MQ_AUTO_REORG_TIME_LENGTH      4
#define MQ_MQ_BATCH_INTERFACE_ID_LENGTH   8
#define MQ_MQ_BRIDGE_NAME_LENGTH          24
#define MQ_MQ_CANCEL_CODE_LENGTH          4
#define MQ_MQ_CF_STRUC_DESC_LENGTH        64
#define MQ_MQ_CF_STRUC_NAME_LENGTH        12
#define MQ_MQ_CHANNEL_DATE_LENGTH         12
#define MQ_MQ_CHANNEL_DESC_LENGTH         64
#define MQ_MQ_CHANNEL_NAME_LENGTH         20
#define MQ_MQ_CHANNEL_TIME_LENGTH         8
#define MQ_MQ_CHINIT_SERVICE_PARM_LENGTH  32
#define MQ_MQ_CICS_FILE_NAME_LENGTH       8
#define MQ_MQ_CLIENT_ID_LENGTH            23
#define MQ_MQ_CLIENT_USER_ID_LENGTH       1024
#define MQ_MQ_CLUSTER_NAME_LENGTH         48
#define MQ_MQ_COMM_INFO_DESC_LENGTH       64
#define MQ_MQ_COMM_INFO_NAME_LENGTH       48
#define MQ_MQ_CONN_NAME_LENGTH            264
#define MQ_MQ_CONN_TAG_LENGTH             128
#define MQ_MQ_CONNECTION_ID_LENGTH        24
#define MQ_MQ_CORREL_ID_LENGTH            24
#define MQ_MQ_CREATION_DATE_LENGTH        12
#define MQ_MQ_CREATION_TIME_LENGTH        8
#define MQ_MQ_CSP_PASSWORD_LENGTH         256
#define MQ_MQ_DATE_LENGTH                 12
#define MQ_MQ_DISTINGUISHED_NAME_LENGTH   1024
#define MQ_MQ_DNS_GROUP_NAME_LENGTH       18
#define MQ_MQ_EXIT_DATA_LENGTH            32
#define MQ_MQ_EXIT_INFO_NAME_LENGTH       48
#define MQ_MQ_EXIT_NAME_LENGTH            128
#define MQ_MQ_EXIT_PD_AREA_LENGTH         48
#define MQ_MQ_EXIT_USER_AREA_LENGTH       16
#define MQ_MQ_FACILITY_LENGTH             8
#define MQ_MQ_FACILITY_LIKE_LENGTH        4
#define MQ_MQ_FORMAT_LENGTH               8
#define MQ_MQ_FUNCTION_LENGTH             4
#define MQ_MQ_GROUP_ID_LENGTH             24
#define MQ_MQ_APPL_FUNCTION_NAME_LENGTH   10
#define MQ_MQ_INSTALLATION_DESC_LENGTH    64
#define MQ_MQ_INSTALLATION_NAME_LENGTH    16
#define MQ_MQ_INSTALLATION_PATH_LENGTH    256
#define MQ_MQ_JAAS_CONFIG_LENGTH          1024
#define MQ_MQ_LDAP_PASSWORD_LENGTH        32
#define MQ_MQ_LDAP_BASE_DN_LENGTH         1024
#define MQ_MQ_LDAP_FIELD_LENGTH           128
#define MQ_MQ_LDAP_CLASS_LENGTH           128
#define MQ_MQ_LISTENER_NAME_LENGTH        48
#define MQ_MQ_LISTENER_DESC_LENGTH        64
#define MQ_MQ_LOCAL_ADDRESS_LENGTH        48
#define MQ_MQ_LTERM_OVERRIDE_LENGTH       8
#define MQ_MQ_LU_NAME_LENGTH              8
#define MQ_MQ_LUWID_LENGTH                16
#define MQ_MQ_MAX_EXIT_NAME_LENGTH        128
#define MQ_MQ_MAX_MCA_USER_ID_LENGTH      64
#define MQ_MQ_MAX_LDAP_MCA_USER_ID_LENGTH 1024
#define MQ_MQ_MAX_PROPERTY_NAME_LENGTH    4095
#define MQ_MQ_MAX_USER_ID_LENGTH          64
#define MQ_MQ_MCA_JOB_NAME_LENGTH         28
#define MQ_MQ_MCA_NAME_LENGTH             20
#define MQ_MQ_MCA_USER_DATA_LENGTH        32
#define MQ_MQ_MCA_USER_ID_LENGTH          64
#define MQ_MQ_LDAP_MCA_USER_ID_LENGTH     1024
#define MQ_MQ_MFS_MAP_NAME_LENGTH         8
#define MQ_MQ_MODE_NAME_LENGTH            8
#define MQ_MQ_MSG_HEADER_LENGTH           4000
#define MQ_MQ_MSG_ID_LENGTH               24
#define MQ_MQ_MSG_TOKEN_LENGTH            16
#define MQ_MQ_NAMELIST_DESC_LENGTH        64
#define MQ_MQ_NAMELIST_NAME_LENGTH        48
#define MQ_MQ_OBJECT_INSTANCE_ID_LENGTH   24
#define MQ_MQ_OBJECT_NAME_LENGTH          48
#define MQ_MQ_PASS_TICKET_APPL_LENGTH     8
#define MQ_MQ_PASSWORD_LENGTH             12
#define MQ_MQ_PROCESS_APPL_ID_LENGTH      256
#define MQ_MQ_PROCESS_DESC_LENGTH         64
#define MQ_MQ_PROCESS_ENV_DATA_LENGTH     128
#define MQ_MQ_PROCESS_NAME_LENGTH         48
#define MQ_MQ_PROCESS_USER_DATA_LENGTH    128
#define MQ_MQ_PROGRAM_NAME_LENGTH         20
#define MQ_MQ_PUT_APPL_NAME_LENGTH        28
#define MQ_MQ_PUT_DATE_LENGTH             8
#define MQ_MQ_PUT_TIME_LENGTH             8
#define MQ_MQ_Q_DESC_LENGTH               64
#define MQ_MQ_Q_MGR_DESC_LENGTH           64
#define MQ_MQ_Q_MGR_IDENTIFIER_LENGTH     48
#define MQ_MQ_Q_MGR_NAME_LENGTH           48
#define MQ_MQ_Q_NAME_LENGTH               48
#define MQ_MQ_QSG_NAME_LENGTH             4
#define MQ_MQ_REMOTE_SYS_ID_LENGTH        4
#define MQ_MQ_SECURITY_ID_LENGTH          40
#define MQ_MQ_SELECTOR_LENGTH             10240
#define MQ_MQ_SERVICE_ARGS_LENGTH         255
#define MQ_MQ_SERVICE_COMMAND_LENGTH      255
#define MQ_MQ_SERVICE_DESC_LENGTH         64
#define MQ_MQ_SERVICE_NAME_LENGTH         32
#define MQ_MQ_SERVICE_PATH_LENGTH         255
#define MQ_MQ_SERVICE_STEP_LENGTH         8
#define MQ_MQ_SHORT_CONN_NAME_LENGTH      20
#define MQ_MQ_SHORT_DNAME_LENGTH          256
#define MQ_MQ_SSL_CIPHER_SPEC_LENGTH      32
#define MQ_MQ_SSL_CIPHER_SUITE_LENGTH     32
#define MQ_MQ_SSL_CRYPTO_HARDWARE_LENGTH  256
#define MQ_MQ_SSL_HANDSHAKE_STAGE_LENGTH  32
#define MQ_MQ_SSL_KEY_LIBRARY_LENGTH      44
#define MQ_MQ_SSL_KEY_MEMBER_LENGTH       8
#define MQ_MQ_SSL_KEY_REPOSITORY_LENGTH   256
#define MQ_MQ_SSL_PEER_NAME_LENGTH        1024
#define MQ_MQ_SSL_SHORT_PEER_NAME_LENGTH  256
#define MQ_MQ_START_CODE_LENGTH           4
#define MQ_MQ_STORAGE_CLASS_DESC_LENGTH   64
#define MQ_MQ_STORAGE_CLASS_LENGTH        8
#define MQ_MQ_SUB_IDENTITY_LENGTH         128
#define MQ_MQ_SUB_POINT_LENGTH            128
#define MQ_MQ_TCP_NAME_LENGTH             8
#define MQ_MQ_TIME_LENGTH                 8
#define MQ_MQ_TOPIC_DESC_LENGTH           64
#define MQ_MQ_TOPIC_NAME_LENGTH           48
#define MQ_MQ_TOPIC_STR_LENGTH            10240
#define MQ_MQ_TOTAL_EXIT_DATA_LENGTH      999
#define MQ_MQ_TOTAL_EXIT_NAME_LENGTH      999
#define MQ_MQ_TP_NAME_LENGTH              64
#define MQ_MQ_TPIPE_NAME_LENGTH           8
#define MQ_MQ_TRAN_INSTANCE_ID_LENGTH     16
#define MQ_MQ_TRANSACTION_ID_LENGTH       4
#define MQ_MQ_TRIGGER_DATA_LENGTH         64
#define MQ_MQ_TRIGGER_PROGRAM_NAME_LENGTH 8
#define MQ_MQ_TRIGGER_TERM_ID_LENGTH      4
#define MQ_MQ_TRIGGER_TRANS_ID_LENGTH     4
#define MQ_MQ_USER_ID_LENGTH              12
#define MQ_MQ_VERSION_LENGTH              8
#define MQ_MQ_XCF_GROUP_NAME_LENGTH       8
#define MQ_MQ_XCF_MEMBER_NAME_LENGTH      16
#define MQ_MQ_SMDS_NAME_LENGTH            4
#define MQ_MQ_CHLAUTH_DESC_LENGTH         64
#define MQ_MQ_CUSTOM_LENGTH               128
#define MQ_MQ_SUITE_B_SIZE                4
#define MQ_MQ_CERT_LABEL_LENGTH           64

/* Completion Codes */
#define MQ_MQCC_OK                        0
#define MQ_MQCC_WARNING                   1
#define MQ_MQCC_FAILED                    2
#define MQ_MQCC_UNKNOWN                   (-1)

/* Reason Codes */
#define MQ_MQRC_NONE                      0
#define MQ_MQRC_APPL_FIRST                900
#define MQ_MQRC_APPL_LAST                 999
#define MQ_MQRC_ALIAS_BASE_Q_TYPE_ERROR   2001
#define MQ_MQRC_ALREADY_CONNECTED         2002
#define MQ_MQRC_BACKED_OUT                2003
#define MQ_MQRC_BUFFER_ERROR              2004
#define MQ_MQRC_BUFFER_LENGTH_ERROR       2005
#define MQ_MQRC_CHAR_ATTR_LENGTH_ERROR    2006
#define MQ_MQRC_CHAR_ATTRS_ERROR          2007
#define MQ_MQRC_CHAR_ATTRS_TOO_SHORT      2008
#define MQ_MQRC_CONNECTION_BROKEN         2009
#define MQ_MQRC_DATA_LENGTH_ERROR         2010
#define MQ_MQRC_DYNAMIC_Q_NAME_ERROR      2011
#define MQ_MQRC_ENVIRONMENT_ERROR         2012
#define MQ_MQRC_EXPIRY_ERROR              2013
#define MQ_MQRC_FEEDBACK_ERROR            2014
#define MQ_MQRC_GET_INHIBITED             2016
#define MQ_MQRC_HANDLE_NOT_AVAILABLE      2017
#define MQ_MQRC_HCONN_ERROR               2018
#define MQ_MQRC_HOBJ_ERROR                2019
#define MQ_MQRC_INHIBIT_VALUE_ERROR       2020
#define MQ_MQRC_INT_ATTR_COUNT_ERROR      2021
#define MQ_MQRC_INT_ATTR_COUNT_TOO_SMALL  2022
#define MQ_MQRC_INT_ATTRS_ARRAY_ERROR     2023
#define MQ_MQRC_SYNCPOINT_LIMIT_REACHED   2024
#define MQ_MQRC_MAX_CONNS_LIMIT_REACHED   2025
#define MQ_MQRC_MD_ERROR                  2026
#define MQ_MQRC_MISSING_REPLY_TO_Q        2027
#define MQ_MQRC_MSG_TYPE_ERROR            2029
#define MQ_MQRC_MSG_TOO_BIG_FOR_Q         2030
#define MQ_MQRC_MSG_TOO_BIG_FOR_Q_MGR     2031
#define MQ_MQRC_NO_MSG_AVAILABLE          2033
#define MQ_MQRC_NO_MSG_UNDER_CURSOR       2034
#define MQ_MQRC_NOT_AUTHORIZED            2035
#define MQ_MQRC_NOT_OPEN_FOR_BROWSE       2036
#define MQ_MQRC_NOT_OPEN_FOR_INPUT        2037
#define MQ_MQRC_NOT_OPEN_FOR_INQUIRE      2038
#define MQ_MQRC_NOT_OPEN_FOR_OUTPUT       2039
#define MQ_MQRC_NOT_OPEN_FOR_SET          2040
#define MQ_MQRC_OBJECT_CHANGED            2041
#define MQ_MQRC_OBJECT_IN_USE             2042
#define MQ_MQRC_OBJECT_TYPE_ERROR         2043
#define MQ_MQRC_OD_ERROR                  2044
#define MQ_MQRC_OPTION_NOT_VALID_FOR_TYPE 2045
#define MQ_MQRC_OPTIONS_ERROR             2046
#define MQ_MQRC_PERSISTENCE_ERROR         2047
#define MQ_MQRC_PERSISTENT_NOT_ALLOWED    2048
#define MQ_MQRC_PRIORITY_EXCEEDS_MAXIMUM  2049
#define MQ_MQRC_PRIORITY_ERROR            2050
#define MQ_MQRC_PUT_INHIBITED             2051
#define MQ_MQRC_Q_DELETED                 2052
#define MQ_MQRC_Q_FULL                    2053
#define MQ_MQRC_Q_NOT_EMPTY               2055
#define MQ_MQRC_Q_SPACE_NOT_AVAILABLE     2056
#define MQ_MQRC_Q_TYPE_ERROR              2057
#define MQ_MQRC_Q_MGR_NAME_ERROR          2058
#define MQ_MQRC_Q_MGR_NOT_AVAILABLE       2059
#define MQ_MQRC_REPORT_OPTIONS_ERROR      2061
#define MQ_MQRC_SECOND_MARK_NOT_ALLOWED   2062
#define MQ_MQRC_SECURITY_ERROR            2063
#define MQ_MQRC_SELECTOR_COUNT_ERROR      2065
#define MQ_MQRC_SELECTOR_LIMIT_EXCEEDED   2066
#define MQ_MQRC_SELECTOR_ERROR            2067
#define MQ_MQRC_SELECTOR_NOT_FOR_TYPE     2068
#define MQ_MQRC_SIGNAL_OUTSTANDING        2069
#define MQ_MQRC_SIGNAL_REQUEST_ACCEPTED   2070
#define MQ_MQRC_STORAGE_NOT_AVAILABLE     2071
#define MQ_MQRC_SYNCPOINT_NOT_AVAILABLE   2072
#define MQ_MQRC_TRIGGER_CONTROL_ERROR     2075
#define MQ_MQRC_TRIGGER_DEPTH_ERROR       2076
#define MQ_MQRC_TRIGGER_MSG_PRIORITY_ERR  2077
#define MQ_MQRC_TRIGGER_TYPE_ERROR        2078
#define MQ_MQRC_TRUNCATED_MSG_ACCEPTED    2079
#define MQ_MQRC_TRUNCATED_MSG_FAILED      2080
#define MQ_MQRC_UNKNOWN_ALIAS_BASE_Q      2082
#define MQ_MQRC_UNKNOWN_OBJECT_NAME       2085
#define MQ_MQRC_UNKNOWN_OBJECT_Q_MGR      2086
#define MQ_MQRC_UNKNOWN_REMOTE_Q_MGR      2087
#define MQ_MQRC_WAIT_INTERVAL_ERROR       2090
#define MQ_MQRC_XMIT_Q_TYPE_ERROR         2091
#define MQ_MQRC_XMIT_Q_USAGE_ERROR        2092
#define MQ_MQRC_NOT_OPEN_FOR_PASS_ALL     2093
#define MQ_MQRC_NOT_OPEN_FOR_PASS_IDENT   2094
#define MQ_MQRC_NOT_OPEN_FOR_SET_ALL      2095
#define MQ_MQRC_NOT_OPEN_FOR_SET_IDENT    2096
#define MQ_MQRC_CONTEXT_HANDLE_ERROR      2097
#define MQ_MQRC_CONTEXT_NOT_AVAILABLE     2098
#define MQ_MQRC_SIGNAL1_ERROR             2099
#define MQ_MQRC_OBJECT_ALREADY_EXISTS     2100
#define MQ_MQRC_OBJECT_DAMAGED            2101
#define MQ_MQRC_RESOURCE_PROBLEM          2102
#define MQ_MQRC_ANOTHER_Q_MGR_CONNECTED   2103
#define MQ_MQRC_UNKNOWN_REPORT_OPTION     2104
#define MQ_MQRC_STORAGE_CLASS_ERROR       2105
#define MQ_MQRC_COD_NOT_VALID_FOR_XCF_Q   2106
#define MQ_MQRC_XWAIT_CANCELED            2107
#define MQ_MQRC_XWAIT_ERROR               2108
#define MQ_MQRC_SUPPRESSED_BY_EXIT        2109
#define MQ_MQRC_FORMAT_ERROR              2110
#define MQ_MQRC_SOURCE_CCSID_ERROR        2111
#define MQ_MQRC_SOURCE_INTEGER_ENC_ERROR  2112
#define MQ_MQRC_SOURCE_DECIMAL_ENC_ERROR  2113
#define MQ_MQRC_SOURCE_FLOAT_ENC_ERROR    2114
#define MQ_MQRC_TARGET_CCSID_ERROR        2115
#define MQ_MQRC_TARGET_INTEGER_ENC_ERROR  2116
#define MQ_MQRC_TARGET_DECIMAL_ENC_ERROR  2117
#define MQ_MQRC_TARGET_FLOAT_ENC_ERROR    2118
#define MQ_MQRC_NOT_CONVERTED             2119
#define MQ_MQRC_CONVERTED_MSG_TOO_BIG     2120
#define MQ_MQRC_TRUNCATED                 2120
#define MQ_MQRC_NO_EXTERNAL_PARTICIPANTS  2121
#define MQ_MQRC_PARTICIPANT_NOT_AVAILABLE 2122
#define MQ_MQRC_OUTCOME_MIXED             2123
#define MQ_MQRC_OUTCOME_PENDING           2124
#define MQ_MQRC_BRIDGE_STARTED            2125
#define MQ_MQRC_BRIDGE_STOPPED            2126
#define MQ_MQRC_ADAPTER_STORAGE_SHORTAGE  2127
#define MQ_MQRC_UOW_IN_PROGRESS           2128
#define MQ_MQRC_ADAPTER_CONN_LOAD_ERROR   2129
#define MQ_MQRC_ADAPTER_SERV_LOAD_ERROR   2130
#define MQ_MQRC_ADAPTER_DEFS_ERROR        2131
#define MQ_MQRC_ADAPTER_DEFS_LOAD_ERROR   2132
#define MQ_MQRC_ADAPTER_CONV_LOAD_ERROR   2133
#define MQ_MQRC_BO_ERROR                  2134
#define MQ_MQRC_DH_ERROR                  2135
#define MQ_MQRC_MULTIPLE_REASONS          2136
#define MQ_MQRC_OPEN_FAILED               2137
#define MQ_MQRC_ADAPTER_DISC_LOAD_ERROR   2138
#define MQ_MQRC_CNO_ERROR                 2139
#define MQ_MQRC_CICS_WAIT_FAILED          2140
#define MQ_MQRC_DLH_ERROR                 2141
#define MQ_MQRC_HEADER_ERROR              2142
#define MQ_MQRC_SOURCE_LENGTH_ERROR       2143
#define MQ_MQRC_TARGET_LENGTH_ERROR       2144
#define MQ_MQRC_SOURCE_BUFFER_ERROR       2145
#define MQ_MQRC_TARGET_BUFFER_ERROR       2146
#define MQ_MQRC_IIH_ERROR                 2148
#define MQ_MQRC_PCF_ERROR                 2149
#define MQ_MQRC_DBCS_ERROR                2150
#define MQ_MQRC_OBJECT_NAME_ERROR         2152
#define MQ_MQRC_OBJECT_Q_MGR_NAME_ERROR   2153
#define MQ_MQRC_RECS_PRESENT_ERROR        2154
#define MQ_MQRC_OBJECT_RECORDS_ERROR      2155
#define MQ_MQRC_RESPONSE_RECORDS_ERROR    2156
#define MQ_MQRC_ASID_MISMATCH             2157
#define MQ_MQRC_PMO_RECORD_FLAGS_ERROR    2158
#define MQ_MQRC_PUT_MSG_RECORDS_ERROR     2159
#define MQ_MQRC_CONN_ID_IN_USE            2160
#define MQ_MQRC_Q_MGR_QUIESCING           2161
#define MQ_MQRC_Q_MGR_STOPPING            2162
#define MQ_MQRC_DUPLICATE_RECOV_COORD     2163
#define MQ_MQRC_PMO_ERROR                 2173
#define MQ_MQRC_API_EXIT_NOT_FOUND        2182
#define MQ_MQRC_API_EXIT_LOAD_ERROR       2183
#define MQ_MQRC_REMOTE_Q_NAME_ERROR       2184
#define MQ_MQRC_INCONSISTENT_PERSISTENCE  2185
#define MQ_MQRC_GMO_ERROR                 2186
#define MQ_MQRC_CICS_BRIDGE_RESTRICTION   2187
#define MQ_MQRC_STOPPED_BY_CLUSTER_EXIT   2188
#define MQ_MQRC_CLUSTER_RESOLUTION_ERROR  2189
#define MQ_MQRC_CONVERTED_STRING_TOO_BIG  2190
#define MQ_MQRC_TMC_ERROR                 2191
#define MQ_MQRC_PAGESET_FULL              2192
#define MQ_MQRC_STORAGE_MEDIUM_FULL       2192
#define MQ_MQRC_PAGESET_ERROR             2193
#define MQ_MQRC_NAME_NOT_VALID_FOR_TYPE   2194
#define MQ_MQRC_UNEXPECTED_ERROR          2195
#define MQ_MQRC_UNKNOWN_XMIT_Q            2196
#define MQ_MQRC_UNKNOWN_DEF_XMIT_Q        2197
#define MQ_MQRC_DEF_XMIT_Q_TYPE_ERROR     2198
#define MQ_MQRC_DEF_XMIT_Q_USAGE_ERROR    2199
#define MQ_MQRC_MSG_MARKED_BROWSE_CO_OP   2200
#define MQ_MQRC_NAME_IN_USE               2201
#define MQ_MQRC_CONNECTION_QUIESCING      2202
#define MQ_MQRC_CONNECTION_STOPPING       2203
#define MQ_MQRC_ADAPTER_NOT_AVAILABLE     2204
#define MQ_MQRC_MSG_ID_ERROR              2206
#define MQ_MQRC_CORREL_ID_ERROR           2207
#define MQ_MQRC_FILE_SYSTEM_ERROR         2208
#define MQ_MQRC_NO_MSG_LOCKED             2209
#define MQ_MQRC_SOAP_DOTNET_ERROR         2210
#define MQ_MQRC_SOAP_AXIS_ERROR           2211
#define MQ_MQRC_SOAP_URL_ERROR            2212
#define MQ_MQRC_FILE_NOT_AUDITED          2216
#define MQ_MQRC_CONNECTION_NOT_AUTHORIZED 2217
#define MQ_MQRC_MSG_TOO_BIG_FOR_CHANNEL   2218
#define MQ_MQRC_CALL_IN_PROGRESS          2219
#define MQ_MQRC_RMH_ERROR                 2220
#define MQ_MQRC_Q_MGR_ACTIVE              2222
#define MQ_MQRC_Q_MGR_NOT_ACTIVE          2223
#define MQ_MQRC_Q_DEPTH_HIGH              2224
#define MQ_MQRC_Q_DEPTH_LOW               2225
#define MQ_MQRC_Q_SERVICE_INTERVAL_HIGH   2226
#define MQ_MQRC_Q_SERVICE_INTERVAL_OK     2227
#define MQ_MQRC_RFH_HEADER_FIELD_ERROR    2228
#define MQ_MQRC_RAS_PROPERTY_ERROR        2229
#define MQ_MQRC_UNIT_OF_WORK_NOT_STARTED  2232
#define MQ_MQRC_CHANNEL_AUTO_DEF_OK       2233
#define MQ_MQRC_CHANNEL_AUTO_DEF_ERROR    2234
#define MQ_MQRC_CFH_ERROR                 2235
#define MQ_MQRC_CFIL_ERROR                2236
#define MQ_MQRC_CFIN_ERROR                2237
#define MQ_MQRC_CFSL_ERROR                2238
#define MQ_MQRC_CFST_ERROR                2239
#define MQ_MQRC_INCOMPLETE_GROUP          2241
#define MQ_MQRC_INCOMPLETE_MSG            2242
#define MQ_MQRC_INCONSISTENT_CCSIDS       2243
#define MQ_MQRC_INCONSISTENT_ENCODINGS    2244
#define MQ_MQRC_INCONSISTENT_UOW          2245
#define MQ_MQRC_INVALID_MSG_UNDER_CURSOR  2246
#define MQ_MQRC_MATCH_OPTIONS_ERROR       2247
#define MQ_MQRC_MDE_ERROR                 2248
#define MQ_MQRC_MSG_FLAGS_ERROR           2249
#define MQ_MQRC_MSG_SEQ_NUMBER_ERROR      2250
#define MQ_MQRC_OFFSET_ERROR              2251
#define MQ_MQRC_ORIGINAL_LENGTH_ERROR     2252
#define MQ_MQRC_SEGMENT_LENGTH_ZERO       2253
#define MQ_MQRC_UOW_NOT_AVAILABLE         2255
#define MQ_MQRC_WRONG_GMO_VERSION         2256
#define MQ_MQRC_WRONG_MD_VERSION          2257
#define MQ_MQRC_GROUP_ID_ERROR            2258
#define MQ_MQRC_INCONSISTENT_BROWSE       2259
#define MQ_MQRC_XQH_ERROR                 2260
#define MQ_MQRC_SRC_ENV_ERROR             2261
#define MQ_MQRC_SRC_NAME_ERROR            2262
#define MQ_MQRC_DEST_ENV_ERROR            2263
#define MQ_MQRC_DEST_NAME_ERROR           2264
#define MQ_MQRC_TM_ERROR                  2265
#define MQ_MQRC_CLUSTER_EXIT_ERROR        2266
#define MQ_MQRC_CLUSTER_EXIT_LOAD_ERROR   2267
#define MQ_MQRC_CLUSTER_PUT_INHIBITED     2268
#define MQ_MQRC_CLUSTER_RESOURCE_ERROR    2269
#define MQ_MQRC_NO_DESTINATIONS_AVAILABLE 2270
#define MQ_MQRC_CONN_TAG_IN_USE           2271
#define MQ_MQRC_PARTIALLY_CONVERTED       2272
#define MQ_MQRC_CONNECTION_ERROR          2273
#define MQ_MQRC_OPTION_ENVIRONMENT_ERROR  2274
#define MQ_MQRC_CD_ERROR                  2277
#define MQ_MQRC_CLIENT_CONN_ERROR         2278
#define MQ_MQRC_CHANNEL_STOPPED_BY_USER   2279
#define MQ_MQRC_HCONFIG_ERROR             2280
#define MQ_MQRC_FUNCTION_ERROR            2281
#define MQ_MQRC_CHANNEL_STARTED           2282
#define MQ_MQRC_CHANNEL_STOPPED           2283
#define MQ_MQRC_CHANNEL_CONV_ERROR        2284
#define MQ_MQRC_SERVICE_NOT_AVAILABLE     2285
#define MQ_MQRC_INITIALIZATION_FAILED     2286
#define MQ_MQRC_TERMINATION_FAILED        2287
#define MQ_MQRC_UNKNOWN_Q_NAME            2288
#define MQ_MQRC_SERVICE_ERROR             2289
#define MQ_MQRC_Q_ALREADY_EXISTS          2290
#define MQ_MQRC_USER_ID_NOT_AVAILABLE     2291
#define MQ_MQRC_UNKNOWN_ENTITY            2292
#define MQ_MQRC_UNKNOWN_AUTH_ENTITY       2293
#define MQ_MQRC_UNKNOWN_REF_OBJECT        2294
#define MQ_MQRC_CHANNEL_ACTIVATED         2295
#define MQ_MQRC_CHANNEL_NOT_ACTIVATED     2296
#define MQ_MQRC_UOW_CANCELED              2297
#define MQ_MQRC_FUNCTION_NOT_SUPPORTED    2298
#define MQ_MQRC_SELECTOR_TYPE_ERROR       2299
#define MQ_MQRC_COMMAND_TYPE_ERROR        2300
#define MQ_MQRC_MULTIPLE_INSTANCE_ERROR   2301
#define MQ_MQRC_SYSTEM_ITEM_NOT_ALTERABLE 2302
#define MQ_MQRC_BAG_CONVERSION_ERROR      2303
#define MQ_MQRC_SELECTOR_OUT_OF_RANGE     2304
#define MQ_MQRC_SELECTOR_NOT_UNIQUE       2305
#define MQ_MQRC_INDEX_NOT_PRESENT         2306
#define MQ_MQRC_STRING_ERROR              2307
#define MQ_MQRC_ENCODING_NOT_SUPPORTED    2308
#define MQ_MQRC_SELECTOR_NOT_PRESENT      2309
#define MQ_MQRC_OUT_SELECTOR_ERROR        2310
#define MQ_MQRC_STRING_TRUNCATED          2311
#define MQ_MQRC_SELECTOR_WRONG_TYPE       2312
#define MQ_MQRC_INCONSISTENT_ITEM_TYPE    2313
#define MQ_MQRC_INDEX_ERROR               2314
#define MQ_MQRC_SYSTEM_BAG_NOT_ALTERABLE  2315
#define MQ_MQRC_ITEM_COUNT_ERROR          2316
#define MQ_MQRC_FORMAT_NOT_SUPPORTED      2317
#define MQ_MQRC_SELECTOR_NOT_SUPPORTED    2318
#define MQ_MQRC_ITEM_VALUE_ERROR          2319
#define MQ_MQRC_HBAG_ERROR                2320
#define MQ_MQRC_PARAMETER_MISSING         2321
#define MQ_MQRC_CMD_SERVER_NOT_AVAILABLE  2322
#define MQ_MQRC_STRING_LENGTH_ERROR       2323
#define MQ_MQRC_INQUIRY_COMMAND_ERROR     2324
#define MQ_MQRC_NESTED_BAG_NOT_SUPPORTED  2325
#define MQ_MQRC_BAG_WRONG_TYPE            2326
#define MQ_MQRC_ITEM_TYPE_ERROR           2327
#define MQ_MQRC_SYSTEM_BAG_NOT_DELETABLE  2328
#define MQ_MQRC_SYSTEM_ITEM_NOT_DELETABLE 2329
#define MQ_MQRC_CODED_CHAR_SET_ID_ERROR   2330
#define MQ_MQRC_MSG_TOKEN_ERROR           2331
#define MQ_MQRC_MISSING_WIH               2332
#define MQ_MQRC_WIH_ERROR                 2333
#define MQ_MQRC_RFH_ERROR                 2334
#define MQ_MQRC_RFH_STRING_ERROR          2335
#define MQ_MQRC_RFH_COMMAND_ERROR         2336
#define MQ_MQRC_RFH_PARM_ERROR            2337
#define MQ_MQRC_RFH_DUPLICATE_PARM        2338
#define MQ_MQRC_RFH_PARM_MISSING          2339
#define MQ_MQRC_CHAR_CONVERSION_ERROR     2340
#define MQ_MQRC_UCS2_CONVERSION_ERROR     2341
#define MQ_MQRC_DB2_NOT_AVAILABLE         2342
#define MQ_MQRC_OBJECT_NOT_UNIQUE         2343
#define MQ_MQRC_CONN_TAG_NOT_RELEASED     2344
#define MQ_MQRC_CF_NOT_AVAILABLE          2345
#define MQ_MQRC_CF_STRUC_IN_USE           2346
#define MQ_MQRC_CF_STRUC_LIST_HDR_IN_USE  2347
#define MQ_MQRC_CF_STRUC_AUTH_FAILED      2348
#define MQ_MQRC_CF_STRUC_ERROR            2349
#define MQ_MQRC_CONN_TAG_NOT_USABLE       2350
#define MQ_MQRC_GLOBAL_UOW_CONFLICT       2351
#define MQ_MQRC_LOCAL_UOW_CONFLICT        2352
#define MQ_MQRC_HANDLE_IN_USE_FOR_UOW     2353
#define MQ_MQRC_UOW_ENLISTMENT_ERROR      2354
#define MQ_MQRC_UOW_MIX_NOT_SUPPORTED     2355
#define MQ_MQRC_WXP_ERROR                 2356
#define MQ_MQRC_CURRENT_RECORD_ERROR      2357
#define MQ_MQRC_NEXT_OFFSET_ERROR         2358
#define MQ_MQRC_NO_RECORD_AVAILABLE       2359
#define MQ_MQRC_OBJECT_LEVEL_INCOMPATIBLE 2360
#define MQ_MQRC_NEXT_RECORD_ERROR         2361
#define MQ_MQRC_BACKOUT_THRESHOLD_REACHED 2362
#define MQ_MQRC_MSG_NOT_MATCHED           2363
#define MQ_MQRC_JMS_FORMAT_ERROR          2364
#define MQ_MQRC_SEGMENTS_NOT_SUPPORTED    2365
#define MQ_MQRC_WRONG_CF_LEVEL            2366
#define MQ_MQRC_CONFIG_CREATE_OBJECT      2367
#define MQ_MQRC_CONFIG_CHANGE_OBJECT      2368
#define MQ_MQRC_CONFIG_DELETE_OBJECT      2369
#define MQ_MQRC_CONFIG_REFRESH_OBJECT     2370
#define MQ_MQRC_CHANNEL_SSL_ERROR         2371
#define MQ_MQRC_PARTICIPANT_NOT_DEFINED   2372
#define MQ_MQRC_CF_STRUC_FAILED           2373
#define MQ_MQRC_API_EXIT_ERROR            2374
#define MQ_MQRC_API_EXIT_INIT_ERROR       2375
#define MQ_MQRC_API_EXIT_TERM_ERROR       2376
#define MQ_MQRC_EXIT_REASON_ERROR         2377
#define MQ_MQRC_RESERVED_VALUE_ERROR      2378
#define MQ_MQRC_NO_DATA_AVAILABLE         2379
#define MQ_MQRC_SCO_ERROR                 2380
#define MQ_MQRC_KEY_REPOSITORY_ERROR      2381
#define MQ_MQRC_CRYPTO_HARDWARE_ERROR     2382
#define MQ_MQRC_AUTH_INFO_REC_COUNT_ERROR 2383
#define MQ_MQRC_AUTH_INFO_REC_ERROR       2384
#define MQ_MQRC_AIR_ERROR                 2385
#define MQ_MQRC_AUTH_INFO_TYPE_ERROR      2386
#define MQ_MQRC_AUTH_INFO_CONN_NAME_ERROR 2387
#define MQ_MQRC_LDAP_USER_NAME_ERROR      2388
#define MQ_MQRC_LDAP_USER_NAME_LENGTH_ERR 2389
#define MQ_MQRC_LDAP_PASSWORD_ERROR       2390
#define MQ_MQRC_SSL_ALREADY_INITIALIZED   2391
#define MQ_MQRC_SSL_CONFIG_ERROR          2392
#define MQ_MQRC_SSL_INITIALIZATION_ERROR  2393
#define MQ_MQRC_Q_INDEX_TYPE_ERROR        2394
#define MQ_MQRC_CFBS_ERROR                2395
#define MQ_MQRC_SSL_NOT_ALLOWED           2396
#define MQ_MQRC_JSSE_ERROR                2397
#define MQ_MQRC_SSL_PEER_NAME_MISMATCH    2398
#define MQ_MQRC_SSL_PEER_NAME_ERROR       2399
#define MQ_MQRC_UNSUPPORTED_CIPHER_SUITE  2400
#define MQ_MQRC_SSL_CERTIFICATE_REVOKED   2401
#define MQ_MQRC_SSL_CERT_STORE_ERROR      2402
#define MQ_MQRC_CLIENT_EXIT_LOAD_ERROR    2406
#define MQ_MQRC_CLIENT_EXIT_ERROR         2407
#define MQ_MQRC_UOW_COMMITTED             2408
#define MQ_MQRC_SSL_KEY_RESET_ERROR       2409
#define MQ_MQRC_UNKNOWN_COMPONENT_NAME    2410
#define MQ_MQRC_LOGGER_STATUS             2411
#define MQ_MQRC_COMMAND_MQSC              2412
#define MQ_MQRC_COMMAND_PCF               2413
#define MQ_MQRC_CFIF_ERROR                2414
#define MQ_MQRC_CFSF_ERROR                2415
#define MQ_MQRC_CFGR_ERROR                2416
#define MQ_MQRC_MSG_NOT_ALLOWED_IN_GROUP  2417
#define MQ_MQRC_FILTER_OPERATOR_ERROR     2418
#define MQ_MQRC_NESTED_SELECTOR_ERROR     2419
#define MQ_MQRC_EPH_ERROR                 2420
#define MQ_MQRC_RFH_FORMAT_ERROR          2421
#define MQ_MQRC_CFBF_ERROR                2422
#define MQ_MQRC_CLIENT_CHANNEL_CONFLICT   2423
#define MQ_MQRC_SD_ERROR                  2424
#define MQ_MQRC_TOPIC_STRING_ERROR        2425
#define MQ_MQRC_STS_ERROR                 2426
#define MQ_MQRC_NO_SUBSCRIPTION           2428
#define MQ_MQRC_SUBSCRIPTION_IN_USE       2429
#define MQ_MQRC_STAT_TYPE_ERROR           2430
#define MQ_MQRC_SUB_USER_DATA_ERROR       2431
#define MQ_MQRC_SUB_ALREADY_EXISTS        2432
#define MQ_MQRC_IDENTITY_MISMATCH         2434
#define MQ_MQRC_ALTER_SUB_ERROR           2435
#define MQ_MQRC_DURABILITY_NOT_ALLOWED    2436
#define MQ_MQRC_NO_RETAINED_MSG           2437
#define MQ_MQRC_SRO_ERROR                 2438
#define MQ_MQRC_SUB_NAME_ERROR            2440
#define MQ_MQRC_OBJECT_STRING_ERROR       2441
#define MQ_MQRC_PROPERTY_NAME_ERROR       2442
#define MQ_MQRC_SEGMENTATION_NOT_ALLOWED  2443
#define MQ_MQRC_CBD_ERROR                 2444
#define MQ_MQRC_CTLO_ERROR                2445
#define MQ_MQRC_NO_CALLBACKS_ACTIVE       2446
#define MQ_MQRC_CALLBACK_NOT_REGISTERED   2448
#define MQ_MQRC_OPTIONS_CHANGED           2457
#define MQ_MQRC_READ_AHEAD_MSGS           2458
#define MQ_MQRC_SELECTOR_SYNTAX_ERROR     2459
#define MQ_MQRC_HMSG_ERROR                2460
#define MQ_MQRC_CMHO_ERROR                2461
#define MQ_MQRC_DMHO_ERROR                2462
#define MQ_MQRC_SMPO_ERROR                2463
#define MQ_MQRC_IMPO_ERROR                2464
#define MQ_MQRC_PROPERTY_NAME_TOO_BIG     2465
#define MQ_MQRC_PROP_VALUE_NOT_CONVERTED  2466
#define MQ_MQRC_PROP_TYPE_NOT_SUPPORTED   2467
#define MQ_MQRC_PROPERTY_VALUE_TOO_BIG    2469
#define MQ_MQRC_PROP_CONV_NOT_SUPPORTED   2470
#define MQ_MQRC_PROPERTY_NOT_AVAILABLE    2471
#define MQ_MQRC_PROP_NUMBER_FORMAT_ERROR  2472
#define MQ_MQRC_PROPERTY_TYPE_ERROR       2473
#define MQ_MQRC_PROPERTIES_TOO_BIG        2478
#define MQ_MQRC_PUT_NOT_RETAINED          2479
#define MQ_MQRC_ALIAS_TARGTYPE_CHANGED    2480
#define MQ_MQRC_DMPO_ERROR                2481
#define MQ_MQRC_PD_ERROR                  2482
#define MQ_MQRC_CALLBACK_TYPE_ERROR       2483
#define MQ_MQRC_CBD_OPTIONS_ERROR         2484
#define MQ_MQRC_MAX_MSG_LENGTH_ERROR      2485
#define MQ_MQRC_CALLBACK_ROUTINE_ERROR    2486
#define MQ_MQRC_CALLBACK_LINK_ERROR       2487
#define MQ_MQRC_OPERATION_ERROR           2488
#define MQ_MQRC_BMHO_ERROR                2489
#define MQ_MQRC_UNSUPPORTED_PROPERTY      2490
#define MQ_MQRC_PROP_NAME_NOT_CONVERTED   2492
#define MQ_MQRC_GET_ENABLED               2494
#define MQ_MQRC_MODULE_NOT_FOUND          2495
#define MQ_MQRC_MODULE_INVALID            2496
#define MQ_MQRC_MODULE_ENTRY_NOT_FOUND    2497
#define MQ_MQRC_MIXED_CONTENT_NOT_ALLOWED 2498
#define MQ_MQRC_MSG_HANDLE_IN_USE         2499
#define MQ_MQRC_HCONN_ASYNC_ACTIVE        2500
#define MQ_MQRC_MHBO_ERROR                2501
#define MQ_MQRC_PUBLICATION_FAILURE       2502
#define MQ_MQRC_SUB_INHIBITED             2503
#define MQ_MQRC_SELECTOR_ALWAYS_FALSE     2504
#define MQ_MQRC_XEPO_ERROR                2507
#define MQ_MQRC_DURABILITY_NOT_ALTERABLE  2509
#define MQ_MQRC_TOPIC_NOT_ALTERABLE       2510
#define MQ_MQRC_SUBLEVEL_NOT_ALTERABLE    2512
#define MQ_MQRC_PROPERTY_NAME_LENGTH_ERR  2513
#define MQ_MQRC_DUPLICATE_GROUP_SUB       2514
#define MQ_MQRC_GROUPING_NOT_ALTERABLE    2515
#define MQ_MQRC_SELECTOR_INVALID_FOR_TYPE 2516
#define MQ_MQRC_HOBJ_QUIESCED             2517
#define MQ_MQRC_HOBJ_QUIESCED_NO_MSGS     2518
#define MQ_MQRC_SELECTION_STRING_ERROR    2519
#define MQ_MQRC_RES_OBJECT_STRING_ERROR   2520
#define MQ_MQRC_CONNECTION_SUSPENDED      2521
#define MQ_MQRC_INVALID_DESTINATION       2522
#define MQ_MQRC_INVALID_SUBSCRIPTION      2523
#define MQ_MQRC_SELECTOR_NOT_ALTERABLE    2524
#define MQ_MQRC_RETAINED_MSG_Q_ERROR      2525
#define MQ_MQRC_RETAINED_NOT_DELIVERED    2526
#define MQ_MQRC_RFH_RESTRICTED_FORMAT_ERR 2527
#define MQ_MQRC_CONNECTION_STOPPED        2528
#define MQ_MQRC_ASYNC_UOW_CONFLICT        2529
#define MQ_MQRC_ASYNC_XA_CONFLICT         2530
#define MQ_MQRC_PUBSUB_INHIBITED          2531
#define MQ_MQRC_MSG_HANDLE_COPY_FAILURE   2532
#define MQ_MQRC_DEST_CLASS_NOT_ALTERABLE  2533
#define MQ_MQRC_OPERATION_NOT_ALLOWED     2534
#define MQ_MQRC_ACTION_ERROR              2535
#define MQ_MQRC_CHANNEL_NOT_AVAILABLE     2537
#define MQ_MQRC_HOST_NOT_AVAILABLE        2538
#define MQ_MQRC_CHANNEL_CONFIG_ERROR      2539
#define MQ_MQRC_UNKNOWN_CHANNEL_NAME      2540
#define MQ_MQRC_LOOPING_PUBLICATION       2541
#define MQ_MQRC_ALREADY_JOINED            2542
#define MQ_MQRC_STANDBY_Q_MGR             2543
#define MQ_MQRC_RECONNECTING              2544
#define MQ_MQRC_RECONNECTED               2545
#define MQ_MQRC_RECONNECT_QMID_MISMATCH   2546
#define MQ_MQRC_RECONNECT_INCOMPATIBLE    2547
#define MQ_MQRC_RECONNECT_FAILED          2548
#define MQ_MQRC_CALL_INTERRUPTED          2549
#define MQ_MQRC_NO_SUBS_MATCHED           2550
#define MQ_MQRC_SELECTION_NOT_AVAILABLE   2551
#define MQ_MQRC_CHANNEL_SSL_WARNING       2552
#define MQ_MQRC_OCSP_URL_ERROR            2553
#define MQ_MQRC_CONTENT_ERROR             2554
#define MQ_MQRC_RECONNECT_Q_MGR_REQD      2555
#define MQ_MQRC_RECONNECT_TIMED_OUT       2556
#define MQ_MQRC_PUBLISH_EXIT_ERROR        2557
#define MQ_MQRC_COMMINFO_ERROR            2558
#define MQ_MQRC_DEF_SYNCPOINT_INHIBITED   2559
#define MQ_MQRC_MULTICAST_ONLY            2560
#define MQ_MQRC_DATA_SET_NOT_AVAILABLE    2561
#define MQ_MQRC_GROUPING_NOT_ALLOWED      2562
#define MQ_MQRC_GROUP_ADDRESS_ERROR       2563
#define MQ_MQRC_MULTICAST_CONFIG_ERROR    2564
#define MQ_MQRC_MULTICAST_INTERFACE_ERROR 2565
#define MQ_MQRC_MULTICAST_SEND_ERROR      2566
#define MQ_MQRC_MULTICAST_INTERNAL_ERROR  2567
#define MQ_MQRC_CONNECTION_NOT_AVAILABLE  2568
#define MQ_MQRC_SYNCPOINT_NOT_ALLOWED     2569
#define MQ_MQRC_SSL_ALT_PROVIDER_REQUIRED 2570
#define MQ_MQRC_MCAST_PUB_STATUS          2571
#define MQ_MQRC_MCAST_SUB_STATUS          2572
#define MQ_MQRC_PRECONN_EXIT_LOAD_ERROR   2573
#define MQ_MQRC_PRECONN_EXIT_NOT_FOUND    2574
#define MQ_MQRC_PRECONN_EXIT_ERROR        2575
#define MQ_MQRC_CD_ARRAY_ERROR            2576
#define MQ_MQRC_CHANNEL_BLOCKED           2577
#define MQ_MQRC_CHANNEL_BLOCKED_WARNING   2578
#define MQ_MQRC_SUBSCRIPTION_CREATE       2579
#define MQ_MQRC_SUBSCRIPTION_DELETE       2580
#define MQ_MQRC_SUBSCRIPTION_CHANGE       2581
#define MQ_MQRC_SUBSCRIPTION_REFRESH      2582
#define MQ_MQRC_INSTALLATION_MISMATCH     2583
#define MQ_MQRC_NOT_PRIVILEGED            2584
#define MQ_MQRC_PROPERTIES_DISABLED       2586
#define MQ_MQRC_HMSG_NOT_AVAILABLE        2587
#define MQ_MQRC_EXIT_PROPS_NOT_SUPPORTED  2588
#define MQ_MQRC_INSTALLATION_MISSING      2589
#define MQ_MQRC_FASTPATH_NOT_AVAILABLE    2590
#define MQ_MQRC_CIPHER_SPEC_NOT_SUITE_B   2591
#define MQ_MQRC_SUITE_B_ERROR             2592
#define MQ_MQRC_CERT_VAL_POLICY_ERROR     2593
#define MQ_MQRC_PASSWORD_PROTECTION_ERROR 2594
#define MQ_MQRC_CSP_ERROR                 2595
#define MQ_MQRC_CERT_LABEL_NOT_ALLOWED    2596
#define MQ_MQRC_ADMIN_TOPIC_STRING_ERROR  2598
#define MQ_MQRC_AMQP_NOT_AVAILABLE        2599
#define MQ_MQRC_REOPEN_EXCL_INPUT_ERROR   6100
#define MQ_MQRC_REOPEN_INQUIRE_ERROR      6101
#define MQ_MQRC_REOPEN_SAVED_CONTEXT_ERR  6102
#define MQ_MQRC_REOPEN_TEMPORARY_Q_ERROR  6103
#define MQ_MQRC_ATTRIBUTE_LOCKED          6104
#define MQ_MQRC_CURSOR_NOT_VALID          6105
#define MQ_MQRC_ENCODING_ERROR            6106
#define MQ_MQRC_STRUC_ID_ERROR            6107
#define MQ_MQRC_NULL_POINTER              6108
#define MQ_MQRC_NO_CONNECTION_REFERENCE   6109
#define MQ_MQRC_NO_BUFFER                 6110
#define MQ_MQRC_BINARY_DATA_LENGTH_ERROR  6111
#define MQ_MQRC_BUFFER_NOT_AUTOMATIC      6112
#define MQ_MQRC_INSUFFICIENT_BUFFER       6113
#define MQ_MQRC_INSUFFICIENT_DATA         6114
#define MQ_MQRC_DATA_TRUNCATED            6115
#define MQ_MQRC_ZERO_LENGTH               6116
#define MQ_MQRC_NEGATIVE_LENGTH           6117
#define MQ_MQRC_NEGATIVE_OFFSET           6118
#define MQ_MQRC_INCONSISTENT_FORMAT       6119
#define MQ_MQRC_INCONSISTENT_OBJECT_STATE 6120
#define MQ_MQRC_CONTEXT_OBJECT_NOT_VALID  6121
#define MQ_MQRC_CONTEXT_OPEN_ERROR        6122
#define MQ_MQRC_STRUC_LENGTH_ERROR        6123
#define MQ_MQRC_NOT_CONNECTED             6124
#define MQ_MQRC_NOT_OPEN                  6125
#define MQ_MQRC_DISTRIBUTION_LIST_EMPTY   6126
#define MQ_MQRC_INCONSISTENT_OPEN_OPTIONS 6127
#define MQ_MQRC_WRONG_VERSION             6128
#define MQ_MQRC_REFERENCE_ERROR           6129
#define MQ_MQRC_XR_NOT_AVAILABLE          6130

/****************************************************************/
/* Values Related to Queue Attributes                           */
/****************************************************************/

/* Queue Types */
#define MQ_MQQT_LOCAL                     1
#define MQ_MQQT_MODEL                     2
#define MQ_MQQT_ALIAS                     3
#define MQ_MQQT_REMOTE                    6
#define MQ_MQQT_CLUSTER                   7

/* Cluster Queue Types */
#define MQ_MQCQT_LOCAL_Q                  1
#define MQ_MQCQT_ALIAS_Q                  2
#define MQ_MQCQT_REMOTE_Q                 3
#define MQ_MQCQT_Q_MGR_ALIAS              4

/* Extended Queue Types */
#define MQ_MQQT_ALL                       1001

/* Queue Definition Types */
#define MQ_MQQDT_PREDEFINED               1
#define MQ_MQQDT_PERMANENT_DYNAMIC        2
#define MQ_MQQDT_TEMPORARY_DYNAMIC        3
#define MQ_MQQDT_SHARED_DYNAMIC           4

/* Inhibit Get Values */
#define MQ_MQQA_GET_INHIBITED             1
#define MQ_MQQA_GET_ALLOWED               0

/* Inhibit Put Values */
#define MQ_MQQA_PUT_INHIBITED             1
#define MQ_MQQA_PUT_ALLOWED               0

/* Queue Shareability */
#define MQ_MQQA_SHAREABLE                 1
#define MQ_MQQA_NOT_SHAREABLE             0

/* Back-Out Hardening */
#define MQ_MQQA_BACKOUT_HARDENED          1
#define MQ_MQQA_BACKOUT_NOT_HARDENED      0

/* Message Delivery Sequence */
#define MQ_MQMDS_PRIORITY                 0
#define MQ_MQMDS_FIFO                     1

/* Nonpersistent Message Class */
#define MQ_MQNPM_CLASS_NORMAL             0
#define MQ_MQNPM_CLASS_HIGH               10

/* Trigger Controls */
#define MQ_MQTC_OFF                       0
#define MQ_MQTC_ON                        1

/* Trigger Types */
#define MQ_MQTT_NONE                      0
#define MQ_MQTT_FIRST                     1
#define MQ_MQTT_EVERY                     2
#define MQ_MQTT_DEPTH                     3

/* Trigger Restart */
#define MQ_MQTRIGGER_RESTART_NO           0
#define MQ_MQTRIGGER_RESTART_YES          1

/* Queue Usages */
#define MQ_MQUS_NORMAL                    0
#define MQ_MQUS_TRANSMISSION              1

/* Distribution Lists */
#define MQ_MQDL_SUPPORTED                 1
#define MQ_MQDL_NOT_SUPPORTED             0

/* Index Types */
#define MQ_MQIT_NONE                      0
#define MQ_MQIT_MSG_ID                    1
#define MQ_MQIT_CORREL_ID                 2
#define MQ_MQIT_MSG_TOKEN                 4
#define MQ_MQIT_GROUP_ID                  5

/* Default Bindings */
#define MQ_MQBND_BIND_ON_OPEN             0
#define MQ_MQBND_BIND_NOT_FIXED           1
#define MQ_MQBND_BIND_ON_GROUP            2

/* Queue Sharing Group Dispositions */
#define MQ_MQQSGD_ALL                     (-1)
#define MQ_MQQSGD_Q_MGR                   0
#define MQ_MQQSGD_COPY                    1
#define MQ_MQQSGD_SHARED                  2
#define MQ_MQQSGD_GROUP                   3
#define MQ_MQQSGD_PRIVATE                 4
#define MQ_MQQSGD_LIVE                    6

/* Reorganization Controls */
#define MQ_MQREORG_DISABLED               0
#define MQ_MQREORG_ENABLED                1

/* Read Ahead Values */
#define MQ_MQREADA_NO                     0
#define MQ_MQREADA_YES                    1
#define MQ_MQREADA_DISABLED               2
#define MQ_MQREADA_INHIBITED              3
#define MQ_MQREADA_BACKLOG                4

/* Queue and Channel Property Control Values */
#define MQ_MQPROP_COMPATIBILITY           0
#define MQ_MQPROP_NONE                    1
#define MQ_MQPROP_ALL                     2
#define MQ_MQPROP_FORCE_MQRFH2            3
#define MQ_MQPROP_V6COMPAT                4

/****************************************************************/
/* Values Related to Namelist Attributes                        */
/****************************************************************/

/* Name Count */
#define MQ_MQNC_MAX_NAMELIST_NAME_COUNT   256

/* Namelist Types */
#define MQ_MQNT_NONE                      0
#define MQ_MQNT_Q                         1
#define MQ_MQNT_CLUSTER                   2
#define MQ_MQNT_AUTH_INFO                 4
#define MQ_MQNT_ALL                       1001

/****************************************************************/
/* Values Related to CF-Structure Attributes                    */
/****************************************************************/

/* CF Recoverability */
#define MQ_MQCFR_YES                      1
#define MQ_MQCFR_NO                       0

/* CF Automatic Recovery */
#define MQ_MQRECAUTO_NO                   0
#define MQ_MQRECAUTO_YES                  1

/* CF Loss of Connectivity Action */
#define MQ_MQCFCONLOS_TERMINATE           0
#define MQ_MQCFCONLOS_TOLERATE            1
#define MQ_MQCFCONLOS_ASQMGR              2

/****************************************************************/
/* Values Related to Service Attributes                         */
/****************************************************************/

/* Service Types */
#define MQ_MQSVC_TYPE_COMMAND             0
#define MQ_MQSVC_TYPE_SERVER              1

/****************************************************************/
/* Values Related to QueueManager Attributes                    */
/****************************************************************/

/* Adopt New MCA Checks */
#define MQ_MQADOPT_CHECK_NONE             0
#define MQ_MQADOPT_CHECK_ALL              1
#define MQ_MQADOPT_CHECK_Q_MGR_NAME       2
#define MQ_MQADOPT_CHECK_NET_ADDR         4

/* Adopt New MCA Types */
#define MQ_MQADOPT_TYPE_NO                0
#define MQ_MQADOPT_TYPE_ALL               1
#define MQ_MQADOPT_TYPE_SVR               2
#define MQ_MQADOPT_TYPE_SDR               4
#define MQ_MQADOPT_TYPE_RCVR              8
#define MQ_MQADOPT_TYPE_CLUSRCVR          16

/* Autostart */
#define MQ_MQAUTO_START_NO                0
#define MQ_MQAUTO_START_YES               1

/* Channel Auto Definition */
#define MQ_MQCHAD_DISABLED                0
#define MQ_MQCHAD_ENABLED                 1

/* Cluster Workload */
#define MQ_MQCLWL_USEQ_LOCAL              0
#define MQ_MQCLWL_USEQ_ANY                1
#define MQ_MQCLWL_USEQ_AS_Q_MGR           (-3)

/* Command Levels */
#define MQ_MQCMDL_LEVEL_1                 100
#define MQ_MQCMDL_LEVEL_101               101
#define MQ_MQCMDL_LEVEL_110               110
#define MQ_MQCMDL_LEVEL_114               114
#define MQ_MQCMDL_LEVEL_120               120
#define MQ_MQCMDL_LEVEL_200               200
#define MQ_MQCMDL_LEVEL_201               201
#define MQ_MQCMDL_LEVEL_210               210
#define MQ_MQCMDL_LEVEL_211               211
#define MQ_MQCMDL_LEVEL_220               220
#define MQ_MQCMDL_LEVEL_221               221
#define MQ_MQCMDL_LEVEL_230               230
#define MQ_MQCMDL_LEVEL_320               320
#define MQ_MQCMDL_LEVEL_420               420
#define MQ_MQCMDL_LEVEL_500               500
#define MQ_MQCMDL_LEVEL_510               510
#define MQ_MQCMDL_LEVEL_520               520
#define MQ_MQCMDL_LEVEL_530               530
#define MQ_MQCMDL_LEVEL_531               531
#define MQ_MQCMDL_LEVEL_600               600
#define MQ_MQCMDL_LEVEL_700               700
#define MQ_MQCMDL_LEVEL_701               701
#define MQ_MQCMDL_LEVEL_710               710
#define MQ_MQCMDL_LEVEL_711               711
#define MQ_MQCMDL_LEVEL_750               750
#define MQ_MQCMDL_LEVEL_800               800
#define MQ_MQCMDL_LEVEL_801               801
#define MQ_MQCMDL_LEVEL_802               802
#define MQ_MQCMDL_CURRENT_LEVEL           802

/* Command Server Options */
#define MQ_MQCSRV_CONVERT_NO              0
#define MQ_MQCSRV_CONVERT_YES             1
#define MQ_MQCSRV_DLQ_NO                  0
#define MQ_MQCSRV_DLQ_YES                 1

/* DNS WLM */
#define MQ_MQDNSWLM_NO                    0
#define MQ_MQDNSWLM_YES                   1

/* Expiration Scan Interval */
#define MQ_MQEXPI_OFF                     0

/* Intra-Group Queuing */
#define MQ_MQIGQ_DISABLED                 0
#define MQ_MQIGQ_ENABLED                  1

/* Intra-Group Queuing Put Authority */
#define MQ_MQIGQPA_DEFAULT                1
#define MQ_MQIGQPA_CONTEXT                2
#define MQ_MQIGQPA_ONLY_IGQ               3
#define MQ_MQIGQPA_ALTERNATE_OR_IGQ       4

/* IP Address Versions */
#define MQ_MQIPADDR_IPV4                  0
#define MQ_MQIPADDR_IPV6                  1

/* Message Mark-Browse Interval */
#define MQ_MQMMBI_UNLIMITED               (-1)

/* Monitoring Values */
#define MQ_MQMON_NOT_AVAILABLE            (-1)
#define MQ_MQMON_NONE                     (-1)
#define MQ_MQMON_Q_MGR                    (-3)
#define MQ_MQMON_OFF                      0
#define MQ_MQMON_ON                       1
#define MQ_MQMON_DISABLED                 0
#define MQ_MQMON_ENABLED                  1
#define MQ_MQMON_LOW                      17
#define MQ_MQMON_MEDIUM                   33
#define MQ_MQMON_HIGH                     65

/* Application Function Types */
#define MQ_MQFUN_TYPE_UNKNOWN             0
#define MQ_MQFUN_TYPE_JVM                 1
#define MQ_MQFUN_TYPE_PROGRAM             2
#define MQ_MQFUN_TYPE_PROCEDURE           3
#define MQ_MQFUN_TYPE_USERDEF             4
#define MQ_MQFUN_TYPE_COMMAND             5

/* Application Activity Trace Detail */
#define MQ_MQACTV_DETAIL_LOW              1
#define MQ_MQACTV_DETAIL_MEDIUM           2
#define MQ_MQACTV_DETAIL_HIGH             3

/* Platforms */
#define MQ_MQPL_MVS                       1
#define MQ_MQPL_OS390                     1
#define MQ_MQPL_ZOS                       1
#define MQ_MQPL_OS2                       2
#define MQ_MQPL_AIX                       3
#define MQ_MQPL_UNIX                      3
#define MQ_MQPL_OS400                     4
#define MQ_MQPL_WINDOWS                   5
#define MQ_MQPL_WINDOWS_NT                11
#define MQ_MQPL_VMS                       12
#define MQ_MQPL_NSK                       13
#define MQ_MQPL_NSS                       13
#define MQ_MQPL_OPEN_TP1                  15
#define MQ_MQPL_VM                        18
#define MQ_MQPL_TPF                       23
#define MQ_MQPL_VSE                       27
#define MQ_MQPL_APPLIANCE                 28
#define MQ_MQPL_NATIVE                    11

/* Maximum Properties Length */
#define MQ_MQPROP_UNRESTRICTED_LENGTH     (-1)

/* Pub/Sub Mode */
#define MQ_MQPSM_DISABLED                 0
#define MQ_MQPSM_COMPAT                   1
#define MQ_MQPSM_ENABLED                  2

/* Pub/Sub clusters */
#define MQ_MQPSCLUS_DISABLED              0
#define MQ_MQPSCLUS_ENABLED               1

/* Control Options */
#define MQ_MQQMOPT_DISABLED               0
#define MQ_MQQMOPT_ENABLED                1
#define MQ_MQQMOPT_REPLY                  2

/* Receive Timeout Types */
#define MQ_MQRCVTIME_MULTIPLY             0
#define MQ_MQRCVTIME_ADD                  1
#define MQ_MQRCVTIME_EQUAL                2

/* Recording Options */
#define MQ_MQRECORDING_DISABLED           0
#define MQ_MQRECORDING_Q                  1
#define MQ_MQRECORDING_MSG                2

/* Security Case */
#define MQ_MQSCYC_UPPER                   0
#define MQ_MQSCYC_MIXED                   1

/* Shared Queue Queue Manager Name */
#define MQ_MQSQQM_USE                     0
#define MQ_MQSQQM_IGNORE                  1

/* SSL FIPS Requirements */
#define MQ_MQSSL_FIPS_NO                  0
#define MQ_MQSSL_FIPS_YES                 1

/* Syncpoint Availability */
#define MQ_MQSP_AVAILABLE                 1
#define MQ_MQSP_NOT_AVAILABLE             0

/* Service Controls */
#define MQ_MQSVC_CONTROL_Q_MGR            0
#define MQ_MQSVC_CONTROL_Q_MGR_START      1
#define MQ_MQSVC_CONTROL_MANUAL           2

/* Service Status */
#define MQ_MQSVC_STATUS_STOPPED           0
#define MQ_MQSVC_STATUS_STARTING          1
#define MQ_MQSVC_STATUS_RUNNING           2
#define MQ_MQSVC_STATUS_STOPPING          3
#define MQ_MQSVC_STATUS_RETRYING          4

/* TCP Keepalive */
#define MQ_MQTCPKEEP_NO                   0
#define MQ_MQTCPKEEP_YES                  1

/* TCP Stack Types */
#define MQ_MQTCPSTACK_SINGLE              0
#define MQ_MQTCPSTACK_MULTIPLE            1

/* Channel Initiator Trace Autostart */
#define MQ_MQTRAXSTR_NO                   0
#define MQ_MQTRAXSTR_YES                  1

/* Capability */
#define MQ_MQCAP_NOT_SUPPORTED            0
#define MQ_MQCAP_SUPPORTED                1
#define MQ_MQCAP_EXPIRED                  2
/****************************************************************/
/* Values Related to Topic Attributes                           */
/****************************************************************/

/* Persistent/Non-persistent Message Delivery */
#define MQ_MQDLV_AS_PARENT                0
#define MQ_MQDLV_ALL                      1
#define MQ_MQDLV_ALL_DUR                  2
#define MQ_MQDLV_ALL_AVAIL                3

/* Master administration */
#define MQ_MQMASTER_NO                    0
#define MQ_MQMASTER_YES                   1

/* Publish scope */
#define MQ_MQSCOPE_ALL                    0
#define MQ_MQSCOPE_AS_PARENT              1
#define MQ_MQSCOPE_QMGR                   4

/* Durable subscriptions */
#define MQ_MQSUB_DURABLE_AS_PARENT        0
#define MQ_MQSUB_DURABLE_ALLOWED          1
#define MQ_MQSUB_DURABLE_INHIBITED        2

/* Wildcards */
#define MQ_MQTA_BLOCK                     1
#define MQ_MQTA_PASSTHRU                  2

/* Subscriptions Allowed */
#define MQ_MQTA_SUB_AS_PARENT             0
#define MQ_MQTA_SUB_INHIBITED             1
#define MQ_MQTA_SUB_ALLOWED               2

/* Proxy Sub Propagation */
#define MQ_MQTA_PROXY_SUB_FORCE           1
#define MQ_MQTA_PROXY_SUB_FIRSTUSE        2

/* Publications Allowed */
#define MQ_MQTA_PUB_AS_PARENT             0
#define MQ_MQTA_PUB_INHIBITED             1
#define MQ_MQTA_PUB_ALLOWED               2

/* Topic Type */
#define MQ_MQTOPT_LOCAL                   0
#define MQ_MQTOPT_CLUSTER                 1
#define MQ_MQTOPT_ALL                     2

/* Multicast */
#define MQ_MQMC_AS_PARENT                 0
#define MQ_MQMC_ENABLED                   1
#define MQ_MQMC_DISABLED                  2
#define MQ_MQMC_ONLY                      3

/* CommInfo Type */
#define MQ_MQCIT_MULTICAST                1

/****************************************************************/
/* Values Related to Subscription Attributes                    */
/****************************************************************/

/* Destination Class */
#define MQ_MQDC_MANAGED                   1
#define MQ_MQDC_PROVIDED                  2

/* Pub/Sub Message Properties */
#define MQ_MQPSPROP_NONE                  0
#define MQ_MQPSPROP_COMPAT                1
#define MQ_MQPSPROP_RFH2                  2
#define MQ_MQPSPROP_MSGPROP               3

/* Request Only */
#define MQ_MQRU_PUBLISH_ON_REQUEST        1
#define MQ_MQRU_PUBLISH_ALL               2

/* Durable Subscriptions */
#define MQ_MQSUB_DURABLE_ALL              (-1)
#define MQ_MQSUB_DURABLE_YES              1
#define MQ_MQSUB_DURABLE_NO               2

/* Subscription Scope */
#define MQ_MQTSCOPE_QMGR                  1
#define MQ_MQTSCOPE_ALL                   2

/* Variable User ID */
#define MQ_MQVU_FIXED_USER                1
#define MQ_MQVU_ANY_USER                  2

/* Wildcard Schema */
#define MQ_MQWS_DEFAULT                   0
#define MQ_MQWS_CHAR                      1
#define MQ_MQWS_TOPIC                     2

/****************************************************************/
/* Values Related to Channel Authentication Configuration       */
/* Attributes                                                   */
/****************************************************************/

/* User Source Options */
#define MQ_MQUSRC_MAP                     0
#define MQ_MQUSRC_NOACCESS                1
#define MQ_MQUSRC_CHANNEL                 2

/* Warn Options */
#define MQ_MQWARN_YES                     1
#define MQ_MQWARN_NO                      0

/* DSBlock Options */
#define MQ_MQDSB_DEFAULT                  0
#define MQ_MQDSB_8K                       1
#define MQ_MQDSB_16K                      2
#define MQ_MQDSB_32K                      3
#define MQ_MQDSB_64K                      4
#define MQ_MQDSB_128K                     5
#define MQ_MQDSB_256K                     6
#define MQ_MQDSB_512K                     7
#define MQ_MQDSB_1024K                    8
#define MQ_MQDSB_1M                       8

/* DSExpand Options */
#define MQ_MQDSE_DEFAULT                  0
#define MQ_MQDSE_YES                      1
#define MQ_MQDSE_NO                       2

/* OffldUse Options */
#define MQ_MQCFOFFLD_NONE                 0
#define MQ_MQCFOFFLD_SMDS                 1
#define MQ_MQCFOFFLD_DB2                  2
#define MQ_MQCFOFFLD_BOTH                 3

/* Use Dead Letter Queue Options */
#define MQ_MQUSEDLQ_AS_PARENT             0
#define MQ_MQUSEDLQ_NO                    1
#define MQ_MQUSEDLQ_YES                   2

/****************************************************************/
/* Constants for MQ Extended Reach                              */
/****************************************************************/

/* General Constants */
#define MQ_MQ_MQTT_MAX_KEEP_ALIVE         65536
#define MQ_MQ_SSL_KEY_PASSPHRASE_LENGTH   1024

/****************************************************************/
/* Values Related to MQCLOSE Function                           */
/****************************************************************/

/* Object Handle */
#define MQ_MQHO_UNUSABLE_HOBJ             (-1)
#define MQ_MQHO_NONE                      0

/* Close Options */
#define MQ_MQCO_IMMEDIATE                 0x00000000
#define MQ_MQCO_NONE                      0x00000000
#define MQ_MQCO_DELETE                    0x00000001
#define MQ_MQCO_DELETE_PURGE              0x00000002
#define MQ_MQCO_KEEP_SUB                  0x00000004
#define MQ_MQCO_REMOVE_SUB                0x00000008
#define MQ_MQCO_QUIESCE                   0x00000020

/****************************************************************/
/* Values Related to MQCTL and MQCB Functions                   */
/****************************************************************/

/* Operation codes for MQCTL */
#define MQ_MQOP_START                     0x00000001
#define MQ_MQOP_START_WAIT                0x00000002
#define MQ_MQOP_STOP                      0x00000004

/* Operation codes for MQCB */
#define MQ_MQOP_REGISTER                  0x00000100
#define MQ_MQOP_DEREGISTER                0x00000200

/* Operation codes for MQCTL and MQCB */
#define MQ_MQOP_SUSPEND                   0x00010000
#define MQ_MQOP_RESUME                    0x00020000

/****************************************************************/
/* Values Related to MQDLTMH Function                           */
/****************************************************************/

/* Message handle */
#define MQ_MQHM_UNUSABLE_HMSG             (-1)
#define MQ_MQHM_NONE                      0

/****************************************************************/
/* Values Related to MQINQ Function                             */
/****************************************************************/

/* Byte Attribute Selectors */
#define MQ_MQBA_FIRST                     6001
#define MQ_MQBA_LAST                      8000

/* Character Attribute Selectors */
#define MQ_MQCA_ADMIN_TOPIC_NAME          2105
#define MQ_MQCA_ALTERATION_DATE           2027
#define MQ_MQCA_ALTERATION_TIME           2028
#define MQ_MQCA_AMQP_SSL_CIPHER_SUITES    2137
#define MQ_MQCA_AMQP_VERSION              2136
#define MQ_MQCA_APPL_ID                   2001
#define MQ_MQCA_AUTH_INFO_CONN_NAME       2053
#define MQ_MQCA_AUTH_INFO_DESC            2046
#define MQ_MQCA_AUTH_INFO_NAME            2045
#define MQ_MQCA_AUTH_INFO_OCSP_URL        2109
#define MQ_MQCA_AUTO_REORG_CATALOG        2091
#define MQ_MQCA_AUTO_REORG_START_TIME     2090
#define MQ_MQCA_BACKOUT_REQ_Q_NAME        2019
#define MQ_MQCA_BASE_OBJECT_NAME          2002
#define MQ_MQCA_BASE_Q_NAME               2002
#define MQ_MQCA_BATCH_INTERFACE_ID        2068
#define MQ_MQCA_CERT_LABEL                2121
#define MQ_MQCA_CF_STRUC_DESC             2052
#define MQ_MQCA_CF_STRUC_NAME             2039
#define MQ_MQCA_CHANNEL_AUTO_DEF_EXIT     2026
#define MQ_MQCA_CHILD                     2101
#define MQ_MQCA_CHINIT_SERVICE_PARM       2076
#define MQ_MQCA_CHLAUTH_DESC              2118
#define MQ_MQCA_CICS_FILE_NAME            2060
#define MQ_MQCA_CLUSTER_DATE              2037
#define MQ_MQCA_CLUSTER_NAME              2029
#define MQ_MQCA_CLUSTER_NAMELIST          2030
#define MQ_MQCA_CLUSTER_Q_MGR_NAME        2031
#define MQ_MQCA_CLUSTER_TIME              2038
#define MQ_MQCA_CLUSTER_WORKLOAD_DATA     2034
#define MQ_MQCA_CLUSTER_WORKLOAD_EXIT     2033
#define MQ_MQCA_CLUS_CHL_NAME             2124
#define MQ_MQCA_COMMAND_INPUT_Q_NAME      2003
#define MQ_MQCA_COMMAND_REPLY_Q_NAME      2067
#define MQ_MQCA_COMM_INFO_DESC            2111
#define MQ_MQCA_COMM_INFO_NAME            2110
#define MQ_MQCA_CONN_AUTH                 2125
#define MQ_MQCA_CREATION_DATE             2004
#define MQ_MQCA_CREATION_TIME             2005
#define MQ_MQCA_CUSTOM                    2119
#define MQ_MQCA_DEAD_LETTER_Q_NAME        2006
#define MQ_MQCA_DEF_XMIT_Q_NAME           2025
#define MQ_MQCA_DNS_GROUP                 2071
#define MQ_MQCA_ENV_DATA                  2007
#define MQ_MQCA_FIRST                     2001
#define MQ_MQCA_IGQ_USER_ID               2041
#define MQ_MQCA_INITIATION_Q_NAME         2008
#define MQ_MQCA_INSTALLATION_DESC         2115
#define MQ_MQCA_INSTALLATION_NAME         2116
#define MQ_MQCA_INSTALLATION_PATH         2117
#define MQ_MQCA_LAST                      4000
#define MQ_MQCA_LAST_USED                 2137
#define MQ_MQCA_LDAP_BASE_DN_GROUPS       2132
#define MQ_MQCA_LDAP_BASE_DN_USERS        2126
#define MQ_MQCA_LDAP_FIND_GROUP_FIELD     2135
#define MQ_MQCA_LDAP_GROUP_ATTR_FIELD     2134
#define MQ_MQCA_LDAP_GROUP_OBJECT_CLASS   2133
#define MQ_MQCA_LDAP_PASSWORD             2048
#define MQ_MQCA_LDAP_SHORT_USER_FIELD     2127
#define MQ_MQCA_LDAP_USER_ATTR_FIELD      2129
#define MQ_MQCA_LDAP_USER_NAME            2047
#define MQ_MQCA_LDAP_USER_OBJECT_CLASS    2128
#define MQ_MQCA_LU62_ARM_SUFFIX           2074
#define MQ_MQCA_LU_GROUP_NAME             2072
#define MQ_MQCA_LU_NAME                   2073
#define MQ_MQCA_MODEL_DURABLE_Q           2096
#define MQ_MQCA_MODEL_NON_DURABLE_Q       2097
#define MQ_MQCA_MONITOR_Q_NAME            2066
#define MQ_MQCA_NAMELIST_DESC             2009
#define MQ_MQCA_NAMELIST_NAME             2010
#define MQ_MQCA_NAMES                     2020
#define MQ_MQCA_PARENT                    2102
#define MQ_MQCA_PASS_TICKET_APPL          2086
#define MQ_MQCA_POLICY_NAME               2112
#define MQ_MQCA_PROCESS_DESC              2011
#define MQ_MQCA_PROCESS_NAME              2012
#define MQ_MQCA_QSG_CERT_LABEL            2131
#define MQ_MQCA_QSG_NAME                  2040
#define MQ_MQCA_Q_DESC                    2013
#define MQ_MQCA_Q_MGR_DESC                2014
#define MQ_MQCA_Q_MGR_IDENTIFIER          2032
#define MQ_MQCA_Q_MGR_NAME                2015
#define MQ_MQCA_Q_NAME                    2016
#define MQ_MQCA_RECIPIENT_DN              2114
#define MQ_MQCA_REMOTE_Q_MGR_NAME         2017
#define MQ_MQCA_REMOTE_Q_NAME             2018
#define MQ_MQCA_REPOSITORY_NAME           2035
#define MQ_MQCA_REPOSITORY_NAMELIST       2036
#define MQ_MQCA_RESUME_DATE               2098
#define MQ_MQCA_RESUME_TIME               2099
#define MQ_MQCA_SERVICE_DESC              2078
#define MQ_MQCA_SERVICE_NAME              2077
#define MQ_MQCA_SERVICE_START_ARGS        2080
#define MQ_MQCA_SERVICE_START_COMMAND     2079
#define MQ_MQCA_SERVICE_STOP_ARGS         2082
#define MQ_MQCA_SERVICE_STOP_COMMAND      2081
#define MQ_MQCA_SIGNER_DN                 2113
#define MQ_MQCA_SSL_CERT_ISSUER_NAME      2130
#define MQ_MQCA_SSL_CRL_NAMELIST          2050
#define MQ_MQCA_SSL_CRYPTO_HARDWARE       2051
#define MQ_MQCA_SSL_KEY_LIBRARY           2069
#define MQ_MQCA_SSL_KEY_MEMBER            2070
#define MQ_MQCA_SSL_KEY_REPOSITORY        2049
#define MQ_MQCA_STDERR_DESTINATION        2084
#define MQ_MQCA_STDOUT_DESTINATION        2083
#define MQ_MQCA_STORAGE_CLASS             2022
#define MQ_MQCA_STORAGE_CLASS_DESC        2042
#define MQ_MQCA_SYSTEM_LOG_Q_NAME         2065
#define MQ_MQCA_TCP_NAME                  2075
#define MQ_MQCA_TOPIC_DESC                2093
#define MQ_MQCA_TOPIC_NAME                2092
#define MQ_MQCA_TOPIC_STRING              2094
#define MQ_MQCA_TOPIC_STRING_FILTER       2108
#define MQ_MQCA_TPIPE_NAME                2085
#define MQ_MQCA_TRIGGER_CHANNEL_NAME      2064
#define MQ_MQCA_TRIGGER_DATA              2023
#define MQ_MQCA_TRIGGER_PROGRAM_NAME      2062
#define MQ_MQCA_TRIGGER_TERM_ID           2063
#define MQ_MQCA_TRIGGER_TRANS_ID          2061
#define MQ_MQCA_USER_DATA                 2021
#define MQ_MQCA_USER_LIST                 4000
#define MQ_MQCA_VERSION                   2120
#define MQ_MQCA_XCF_GROUP_NAME            2043
#define MQ_MQCA_XCF_MEMBER_NAME           2044
#define MQ_MQCA_XMIT_Q_NAME               2024
#define MQ_MQCA_XR_SSL_CIPHER_SUITES      2123
#define MQ_MQCA_XR_VERSION                2122

/* Integer Attribute Selectors */
#define MQ_MQIA_ACCOUNTING_CONN_OVERRIDE  136
#define MQ_MQIA_ACCOUNTING_INTERVAL       135
#define MQ_MQIA_ACCOUNTING_MQI            133
#define MQ_MQIA_ACCOUNTING_Q              134
#define MQ_MQIA_ACTIVE_CHANNELS           100
#define MQ_MQIA_ACTIVITY_CONN_OVERRIDE    239
#define MQ_MQIA_ACTIVITY_RECORDING        138
#define MQ_MQIA_ACTIVITY_TRACE            240
#define MQ_MQIA_ADOPTNEWMCA_CHECK         102
#define MQ_MQIA_ADOPTNEWMCA_INTERVAL      104
#define MQ_MQIA_ADOPTNEWMCA_TYPE          103
#define MQ_MQIA_ADOPT_CONTEXT             260
#define MQ_MQIA_AMQP_CAPABILITY           265
#define MQ_MQIA_APPL_TYPE                 1
#define MQ_MQIA_ARCHIVE                   60
#define MQ_MQIA_AUTHENTICATION_FAIL_DELAY 259
#define MQ_MQIA_AUTHENTICATION_METHOD     266
#define MQ_MQIA_AUTHORITY_EVENT           47
#define MQ_MQIA_AUTH_INFO_TYPE            66
#define MQ_MQIA_AUTO_REORGANIZATION       173
#define MQ_MQIA_AUTO_REORG_INTERVAL       174
#define MQ_MQIA_BACKOUT_THRESHOLD         22
#define MQ_MQIA_BASE_TYPE                 193
#define MQ_MQIA_BATCH_INTERFACE_AUTO      86
#define MQ_MQIA_BRIDGE_EVENT              74
#define MQ_MQIA_CERT_VAL_POLICY           252
#define MQ_MQIA_CF_CFCONLOS               246
#define MQ_MQIA_CF_LEVEL                  70
#define MQ_MQIA_CF_OFFLDUSE               229
#define MQ_MQIA_CF_OFFLOAD                224
#define MQ_MQIA_CF_OFFLOAD_THRESHOLD1     225
#define MQ_MQIA_CF_OFFLOAD_THRESHOLD2     226
#define MQ_MQIA_CF_OFFLOAD_THRESHOLD3     227
#define MQ_MQIA_CF_RECAUTO                244
#define MQ_MQIA_CF_RECOVER                71
#define MQ_MQIA_CF_SMDS_BUFFERS           228
#define MQ_MQIA_CHANNEL_AUTO_DEF          55
#define MQ_MQIA_CHANNEL_AUTO_DEF_EVENT    56
#define MQ_MQIA_CHANNEL_EVENT             73
#define MQ_MQIA_CHECK_CLIENT_BINDING      258
#define MQ_MQIA_CHECK_LOCAL_BINDING       257
#define MQ_MQIA_CHINIT_ADAPTERS           101
#define MQ_MQIA_CHINIT_CONTROL            119
#define MQ_MQIA_CHINIT_DISPATCHERS        105
#define MQ_MQIA_CHINIT_TRACE_AUTO_START   117
#define MQ_MQIA_CHINIT_TRACE_TABLE_SIZE   118
#define MQ_MQIA_CHLAUTH_RECORDS           248
#define MQ_MQIA_CLUSTER_OBJECT_STATE      256
#define MQ_MQIA_CLUSTER_PUB_ROUTE         255
#define MQ_MQIA_CLUSTER_Q_TYPE            59
#define MQ_MQIA_CLUSTER_WORKLOAD_LENGTH   58
#define MQ_MQIA_CLWL_MRU_CHANNELS         97
#define MQ_MQIA_CLWL_Q_PRIORITY           96
#define MQ_MQIA_CLWL_Q_RANK               95
#define MQ_MQIA_CLWL_USEQ                 98
#define MQ_MQIA_CMD_SERVER_AUTO           87
#define MQ_MQIA_CMD_SERVER_CONTROL        120
#define MQ_MQIA_CMD_SERVER_CONVERT_MSG    88
#define MQ_MQIA_CMD_SERVER_DLQ_MSG        89
#define MQ_MQIA_CODED_CHAR_SET_ID         2
#define MQ_MQIA_COMMAND_EVENT             99
#define MQ_MQIA_COMMAND_LEVEL             31
#define MQ_MQIA_COMM_EVENT                232
#define MQ_MQIA_COMM_INFO_TYPE            223
#define MQ_MQIA_CONFIGURATION_EVENT       51
#define MQ_MQIA_CPI_LEVEL                 27
#define MQ_MQIA_CURRENT_Q_DEPTH           3
#define MQ_MQIA_DEFINITION_TYPE           7
#define MQ_MQIA_DEF_BIND                  61
#define MQ_MQIA_DEF_CLUSTER_XMIT_Q_TYPE   250
#define MQ_MQIA_DEF_INPUT_OPEN_OPTION     4
#define MQ_MQIA_DEF_PERSISTENCE           5
#define MQ_MQIA_DEF_PRIORITY              6
#define MQ_MQIA_DEF_PUT_RESPONSE_TYPE     184
#define MQ_MQIA_DEF_READ_AHEAD            188
#define MQ_MQIA_DISPLAY_TYPE              262
#define MQ_MQIA_DIST_LISTS                34
#define MQ_MQIA_DNS_WLM                   106
#define MQ_MQIA_DURABLE_SUB               175
#define MQ_MQIA_ENCRYPTION_ALGORITHM      237
#define MQ_MQIA_EXPIRY_INTERVAL           39
#define MQ_MQIA_FIRST                     1
#define MQ_MQIA_GROUP_UR                  221
#define MQ_MQIA_HARDEN_GET_BACKOUT        8
#define MQ_MQIA_HIGH_Q_DEPTH              36
#define MQ_MQIA_IGQ_PUT_AUTHORITY         65
#define MQ_MQIA_INDEX_TYPE                57
#define MQ_MQIA_INHIBIT_EVENT             48
#define MQ_MQIA_INHIBIT_GET               9
#define MQ_MQIA_INHIBIT_PUB               181
#define MQ_MQIA_INHIBIT_PUT               10
#define MQ_MQIA_INHIBIT_SUB               182
#define MQ_MQIA_INTRA_GROUP_QUEUING       64
#define MQ_MQIA_IP_ADDRESS_VERSION        93
#define MQ_MQIA_LAST                      2000
#define MQ_MQIA_LAST_USED                 266
#define MQ_MQIA_LDAP_AUTHORMD             263
#define MQ_MQIA_LDAP_NESTGRP              264
#define MQ_MQIA_LDAP_SECURE_COMM          261
#define MQ_MQIA_LISTENER_PORT_NUMBER      85
#define MQ_MQIA_LISTENER_TIMER            107
#define MQ_MQIA_LOCAL_EVENT               49
#define MQ_MQIA_LOGGER_EVENT              94
#define MQ_MQIA_LU62_CHANNELS             108
#define MQ_MQIA_MASTER_ADMIN              186
#define MQ_MQIA_MAX_CHANNELS              109
#define MQ_MQIA_MAX_CLIENTS               172
#define MQ_MQIA_MAX_GLOBAL_LOCKS          83
#define MQ_MQIA_MAX_HANDLES               11
#define MQ_MQIA_MAX_LOCAL_LOCKS           84
#define MQ_MQIA_MAX_MSG_LENGTH            13
#define MQ_MQIA_MAX_OPEN_Q                80
#define MQ_MQIA_MAX_PRIORITY              14
#define MQ_MQIA_MAX_PROPERTIES_LENGTH     192
#define MQ_MQIA_MAX_Q_DEPTH               15
#define MQ_MQIA_MAX_Q_TRIGGERS            90
#define MQ_MQIA_MAX_RECOVERY_TASKS        171
#define MQ_MQIA_MAX_RESPONSES             230
#define MQ_MQIA_MAX_UNCOMMITTED_MSGS      33
#define MQ_MQIA_MCAST_BRIDGE              233
#define MQ_MQIA_MONITORING_AUTO_CLUSSDR   124
#define MQ_MQIA_MONITORING_CHANNEL        122
#define MQ_MQIA_MONITORING_Q              123
#define MQ_MQIA_MONITOR_INTERVAL          81
#define MQ_MQIA_MSG_DELIVERY_SEQUENCE     16
#define MQ_MQIA_MSG_DEQ_COUNT             38
#define MQ_MQIA_MSG_ENQ_COUNT             37
#define MQ_MQIA_MSG_MARK_BROWSE_INTERVAL  68
#define MQ_MQIA_MULTICAST                 176
#define MQ_MQIA_NAMELIST_TYPE             72
#define MQ_MQIA_NAME_COUNT                19
#define MQ_MQIA_NPM_CLASS                 78
#define MQ_MQIA_NPM_DELIVERY              196
#define MQ_MQIA_OPEN_INPUT_COUNT          17
#define MQ_MQIA_OPEN_OUTPUT_COUNT         18
#define MQ_MQIA_OUTBOUND_PORT_MAX         140
#define MQ_MQIA_OUTBOUND_PORT_MIN         110
#define MQ_MQIA_PAGESET_ID                62
#define MQ_MQIA_PERFORMANCE_EVENT         53
#define MQ_MQIA_PLATFORM                  32
#define MQ_MQIA_PM_DELIVERY               195
#define MQ_MQIA_POLICY_VERSION            238
#define MQ_MQIA_PROPERTY_CONTROL          190
#define MQ_MQIA_PROT_POLICY_CAPABILITY    251
#define MQ_MQIA_PROXY_SUB                 199
#define MQ_MQIA_PUBSUB_CLUSTER            249
#define MQ_MQIA_PUBSUB_MAXMSG_RETRY_COUNT 206
#define MQ_MQIA_PUBSUB_MODE               187
#define MQ_MQIA_PUBSUB_NP_MSG             203
#define MQ_MQIA_PUBSUB_NP_RESP            205
#define MQ_MQIA_PUBSUB_SYNC_PT            207
#define MQ_MQIA_PUB_COUNT                 215
#define MQ_MQIA_PUB_SCOPE                 219
#define MQ_MQIA_QMGR_CFCONLOS             245
#define MQ_MQIA_QMOPT_CONS_COMMS_MSGS     155
#define MQ_MQIA_QMOPT_CONS_CRITICAL_MSGS  154
#define MQ_MQIA_QMOPT_CONS_ERROR_MSGS     153
#define MQ_MQIA_QMOPT_CONS_INFO_MSGS      151
#define MQ_MQIA_QMOPT_CONS_REORG_MSGS     156
#define MQ_MQIA_QMOPT_CONS_SYSTEM_MSGS    157
#define MQ_MQIA_QMOPT_CONS_WARNING_MSGS   152
#define MQ_MQIA_QMOPT_CSMT_ON_ERROR       150
#define MQ_MQIA_QMOPT_INTERNAL_DUMP       170
#define MQ_MQIA_QMOPT_LOG_COMMS_MSGS      162
#define MQ_MQIA_QMOPT_LOG_CRITICAL_MSGS   161
#define MQ_MQIA_QMOPT_LOG_ERROR_MSGS      160
#define MQ_MQIA_QMOPT_LOG_INFO_MSGS       158
#define MQ_MQIA_QMOPT_LOG_REORG_MSGS      163
#define MQ_MQIA_QMOPT_LOG_SYSTEM_MSGS     164
#define MQ_MQIA_QMOPT_LOG_WARNING_MSGS    159
#define MQ_MQIA_QMOPT_TRACE_COMMS         166
#define MQ_MQIA_QMOPT_TRACE_CONVERSION    168
#define MQ_MQIA_QMOPT_TRACE_MQI_CALLS     165
#define MQ_MQIA_QMOPT_TRACE_REORG         167
#define MQ_MQIA_QMOPT_TRACE_SYSTEM        169
#define MQ_MQIA_QSG_DISP                  63
#define MQ_MQIA_Q_DEPTH_HIGH_EVENT        43
#define MQ_MQIA_Q_DEPTH_HIGH_LIMIT        40
#define MQ_MQIA_Q_DEPTH_LOW_EVENT         44
#define MQ_MQIA_Q_DEPTH_LOW_LIMIT         41
#define MQ_MQIA_Q_DEPTH_MAX_EVENT         42
#define MQ_MQIA_Q_SERVICE_INTERVAL        54
#define MQ_MQIA_Q_SERVICE_INTERVAL_EVENT  46
#define MQ_MQIA_Q_TYPE                    20
#define MQ_MQIA_Q_USERS                   82
#define MQ_MQIA_READ_AHEAD                189
#define MQ_MQIA_RECEIVE_TIMEOUT           111
#define MQ_MQIA_RECEIVE_TIMEOUT_MIN       113
#define MQ_MQIA_RECEIVE_TIMEOUT_TYPE      112
#define MQ_MQIA_REMOTE_EVENT              50
#define MQ_MQIA_RESPONSE_RESTART_POINT    231
#define MQ_MQIA_RETENTION_INTERVAL        21
#define MQ_MQIA_REVERSE_DNS_LOOKUP        254
#define MQ_MQIA_SCOPE                     45
#define MQ_MQIA_SECURITY_CASE             141
#define MQ_MQIA_SERVICE_CONTROL           139
#define MQ_MQIA_SERVICE_TYPE              121
#define MQ_MQIA_SHAREABILITY              23
#define MQ_MQIA_SHARED_Q_Q_MGR_NAME       77
#define MQ_MQIA_SIGNATURE_ALGORITHM       236
#define MQ_MQIA_SSL_EVENT                 75
#define MQ_MQIA_SSL_FIPS_REQUIRED         92
#define MQ_MQIA_SSL_RESET_COUNT           76
#define MQ_MQIA_SSL_TASKS                 69
#define MQ_MQIA_START_STOP_EVENT          52
#define MQ_MQIA_STATISTICS_AUTO_CLUSSDR   130
#define MQ_MQIA_STATISTICS_CHANNEL        129
#define MQ_MQIA_STATISTICS_INTERVAL       131
#define MQ_MQIA_STATISTICS_MQI            127
#define MQ_MQIA_STATISTICS_Q              128
#define MQ_MQIA_SUB_CONFIGURATION_EVENT   242
#define MQ_MQIA_SUB_COUNT                 204
#define MQ_MQIA_SUB_SCOPE                 218
#define MQ_MQIA_SUITE_B_STRENGTH          247
#define MQ_MQIA_SYNCPOINT                 30
#define MQ_MQIA_TCP_CHANNELS              114
#define MQ_MQIA_TCP_KEEP_ALIVE            115
#define MQ_MQIA_TCP_STACK_TYPE            116
#define MQ_MQIA_TIME_SINCE_RESET          35
#define MQ_MQIA_TOLERATE_UNPROTECTED      235
#define MQ_MQIA_TOPIC_DEF_PERSISTENCE     185
#define MQ_MQIA_TOPIC_NODE_COUNT          253
#define MQ_MQIA_TOPIC_TYPE                208
#define MQ_MQIA_TRACE_ROUTE_RECORDING     137
#define MQ_MQIA_TREE_LIFE_TIME            183
#define MQ_MQIA_TRIGGER_CONTROL           24
#define MQ_MQIA_TRIGGER_DEPTH             29
#define MQ_MQIA_TRIGGER_INTERVAL          25
#define MQ_MQIA_TRIGGER_MSG_PRIORITY      26
#define MQ_MQIA_TRIGGER_RESTART           91
#define MQ_MQIA_TRIGGER_TYPE              28
#define MQ_MQIA_UR_DISP                   222
#define MQ_MQIA_USAGE                     12
#define MQ_MQIA_USER_LIST                 2000
#define MQ_MQIA_USE_DEAD_LETTER_Q         234
#define MQ_MQIA_WILDCARD_OPERATION        216
#define MQ_MQIA_XR_CAPABILITY             243

/* Integer Attribute Values */
#define MQ_MQIAV_NOT_APPLICABLE           (-1)
#define MQ_MQIAV_UNDEFINED                (-2)

/* CommInfo Bridge */
#define MQ_MQMCB_DISABLED                 0
#define MQ_MQMCB_ENABLED                  1

/* Group Attribute Selectors */
#define MQ_MQGA_FIRST                     8001
#define MQ_MQGA_LAST                      9000

/****************************************************************/
/* Values Related to MQOPEN Function                            */
/****************************************************************/

/* Open Options */
#define MQ_MQOO_BIND_AS_Q_DEF             0x00000000
#define MQ_MQOO_READ_AHEAD_AS_Q_DEF       0x00000000
#define MQ_MQOO_INPUT_AS_Q_DEF            0x00000001
#define MQ_MQOO_INPUT_SHARED              0x00000002
#define MQ_MQOO_INPUT_EXCLUSIVE           0x00000004
#define MQ_MQOO_BROWSE                    0x00000008
#define MQ_MQOO_OUTPUT                    0x00000010
#define MQ_MQOO_INQUIRE                   0x00000020
#define MQ_MQOO_SET                       0x00000040
#define MQ_MQOO_SAVE_ALL_CONTEXT          0x00000080
#define MQ_MQOO_PASS_IDENTITY_CONTEXT     0x00000100
#define MQ_MQOO_PASS_ALL_CONTEXT          0x00000200
#define MQ_MQOO_SET_IDENTITY_CONTEXT      0x00000400
#define MQ_MQOO_SET_ALL_CONTEXT           0x00000800
#define MQ_MQOO_ALTERNATE_USER_AUTHORITY  0x00001000
#define MQ_MQOO_FAIL_IF_QUIESCING         0x00002000
#define MQ_MQOO_BIND_ON_OPEN              0x00004000
#define MQ_MQOO_BIND_NOT_FIXED            0x00008000
#define MQ_MQOO_CO_OP                     0x00020000
#define MQ_MQOO_RESOLVE_LOCAL_Q           0x00040000
#define MQ_MQOO_RESOLVE_LOCAL_TOPIC       0x00040000
#define MQ_MQOO_NO_READ_AHEAD             0x00080000
#define MQ_MQOO_READ_AHEAD                0x00100000
#define MQ_MQOO_NO_MULTICAST              0x00200000
#define MQ_MQOO_BIND_ON_GROUP             0x00400000

/* Following used in C++ only */
#define MQ_MQOO_RESOLVE_NAMES             0x00010000

/****************************************************************/
/* Values Related to MQSETMP Function                           */
/****************************************************************/

/* Property data types */
#define MQ_MQTYPE_AS_SET                  0x00000000
#define MQ_MQTYPE_NULL                    0x00000002
#define MQ_MQTYPE_BOOLEAN                 0x00000004
#define MQ_MQTYPE_BYTE_STRING             0x00000008
#define MQ_MQTYPE_INT8                    0x00000010
#define MQ_MQTYPE_INT16                   0x00000020
#define MQ_MQTYPE_INT32                   0x00000040
#define MQ_MQTYPE_LONG                    0x00000040
#define MQ_MQTYPE_INT64                   0x00000080
#define MQ_MQTYPE_FLOAT32                 0x00000100
#define MQ_MQTYPE_FLOAT64                 0x00000200
#define MQ_MQTYPE_STRING                  0x00000400

/* Property value lengths */
#define MQ_MQVL_NULL_TERMINATED           (-1)
#define MQ_MQVL_EMPTY_STRING              0

/****************************************************************/
/* Values Related to MQSTAT Function                            */
/****************************************************************/

/* Stat Options */
#define MQ_MQSTAT_TYPE_ASYNC_ERROR        0
#define MQ_MQSTAT_TYPE_RECONNECTION       1
#define MQ_MQSTAT_TYPE_RECONNECTION_ERROR 2

/****************************************************************/
/* Values Related to MQSUB Function                             */
/****************************************************************/

/* Subscribe Options */
#define MQ_MQSO_NONE                      0x00000000
#define MQ_MQSO_NON_DURABLE               0x00000000
#define MQ_MQSO_READ_AHEAD_AS_Q_DEF       0x00000000
#define MQ_MQSO_ALTER                     0x00000001
#define MQ_MQSO_CREATE                    0x00000002
#define MQ_MQSO_RESUME                    0x00000004
#define MQ_MQSO_DURABLE                   0x00000008
#define MQ_MQSO_GROUP_SUB                 0x00000010
#define MQ_MQSO_MANAGED                   0x00000020
#define MQ_MQSO_SET_IDENTITY_CONTEXT      0x00000040
#define MQ_MQSO_NO_MULTICAST              0x00000080
#define MQ_MQSO_FIXED_USERID              0x00000100
#define MQ_MQSO_ANY_USERID                0x00000200
#define MQ_MQSO_PUBLICATIONS_ON_REQUEST   0x00000800
#define MQ_MQSO_NEW_PUBLICATIONS_ONLY     0x00001000
#define MQ_MQSO_FAIL_IF_QUIESCING         0x00002000
#define MQ_MQSO_ALTERNATE_USER_AUTHORITY  0x00040000
#define MQ_MQSO_WILDCARD_CHAR             0x00100000
#define MQ_MQSO_WILDCARD_TOPIC            0x00200000
#define MQ_MQSO_SET_CORREL_ID             0x00400000
#define MQ_MQSO_SCOPE_QMGR                0x04000000
#define MQ_MQSO_NO_READ_AHEAD             0x08000000
#define MQ_MQSO_READ_AHEAD                0x10000000

/* Command Codes */
#define MQ_MQCMD_NONE                     0
#define MQ_MQCMD_CHANGE_Q_MGR             1
#define MQ_MQCMD_INQUIRE_Q_MGR            2
#define MQ_MQCMD_CHANGE_PROCESS           3
#define MQ_MQCMD_COPY_PROCESS             4
#define MQ_MQCMD_CREATE_PROCESS           5
#define MQ_MQCMD_DELETE_PROCESS           6
#define MQ_MQCMD_INQUIRE_PROCESS          7
#define MQ_MQCMD_CHANGE_Q                 8
#define MQ_MQCMD_CLEAR_Q                  9
#define MQ_MQCMD_COPY_Q                   10
#define MQ_MQCMD_CREATE_Q                 11
#define MQ_MQCMD_DELETE_Q                 12
#define MQ_MQCMD_INQUIRE_Q                13
#define MQ_MQCMD_REFRESH_Q_MGR            16
#define MQ_MQCMD_RESET_Q_STATS            17
#define MQ_MQCMD_INQUIRE_Q_NAMES          18
#define MQ_MQCMD_INQUIRE_PROCESS_NAMES    19
#define MQ_MQCMD_INQUIRE_CHANNEL_NAMES    20
#define MQ_MQCMD_CHANGE_CHANNEL           21
#define MQ_MQCMD_COPY_CHANNEL             22
#define MQ_MQCMD_CREATE_CHANNEL           23
#define MQ_MQCMD_DELETE_CHANNEL           24
#define MQ_MQCMD_INQUIRE_CHANNEL          25
#define MQ_MQCMD_PING_CHANNEL             26
#define MQ_MQCMD_RESET_CHANNEL            27
#define MQ_MQCMD_START_CHANNEL            28
#define MQ_MQCMD_STOP_CHANNEL             29
#define MQ_MQCMD_START_CHANNEL_INIT       30
#define MQ_MQCMD_START_CHANNEL_LISTENER   31
#define MQ_MQCMD_CHANGE_NAMELIST          32
#define MQ_MQCMD_COPY_NAMELIST            33
#define MQ_MQCMD_CREATE_NAMELIST          34
#define MQ_MQCMD_DELETE_NAMELIST          35
#define MQ_MQCMD_INQUIRE_NAMELIST         36
#define MQ_MQCMD_INQUIRE_NAMELIST_NAMES   37
#define MQ_MQCMD_ESCAPE                   38
#define MQ_MQCMD_RESOLVE_CHANNEL          39
#define MQ_MQCMD_PING_Q_MGR               40
#define MQ_MQCMD_INQUIRE_Q_STATUS         41
#define MQ_MQCMD_INQUIRE_CHANNEL_STATUS   42
#define MQ_MQCMD_CONFIG_EVENT             43
#define MQ_MQCMD_Q_MGR_EVENT              44
#define MQ_MQCMD_PERFM_EVENT              45
#define MQ_MQCMD_CHANNEL_EVENT            46
#define MQ_MQCMD_DELETE_PUBLICATION       60
#define MQ_MQCMD_DEREGISTER_PUBLISHER     61
#define MQ_MQCMD_DEREGISTER_SUBSCRIBER    62
#define MQ_MQCMD_PUBLISH                  63
#define MQ_MQCMD_REGISTER_PUBLISHER       64
#define MQ_MQCMD_REGISTER_SUBSCRIBER      65
#define MQ_MQCMD_REQUEST_UPDATE           66
#define MQ_MQCMD_BROKER_INTERNAL          67
#define MQ_MQCMD_ACTIVITY_MSG             69
#define MQ_MQCMD_INQUIRE_CLUSTER_Q_MGR    70
#define MQ_MQCMD_RESUME_Q_MGR_CLUSTER     71
#define MQ_MQCMD_SUSPEND_Q_MGR_CLUSTER    72
#define MQ_MQCMD_REFRESH_CLUSTER          73
#define MQ_MQCMD_RESET_CLUSTER            74
#define MQ_MQCMD_TRACE_ROUTE              75
#define MQ_MQCMD_REFRESH_SECURITY         78
#define MQ_MQCMD_CHANGE_AUTH_INFO         79
#define MQ_MQCMD_COPY_AUTH_INFO           80
#define MQ_MQCMD_CREATE_AUTH_INFO         81
#define MQ_MQCMD_DELETE_AUTH_INFO         82
#define MQ_MQCMD_INQUIRE_AUTH_INFO        83
#define MQ_MQCMD_INQUIRE_AUTH_INFO_NAMES  84
#define MQ_MQCMD_INQUIRE_CONNECTION       85
#define MQ_MQCMD_STOP_CONNECTION          86
#define MQ_MQCMD_INQUIRE_AUTH_RECS        87
#define MQ_MQCMD_INQUIRE_ENTITY_AUTH      88
#define MQ_MQCMD_DELETE_AUTH_REC          89
#define MQ_MQCMD_SET_AUTH_REC             90
#define MQ_MQCMD_LOGGER_EVENT             91
#define MQ_MQCMD_RESET_Q_MGR              92
#define MQ_MQCMD_CHANGE_LISTENER          93
#define MQ_MQCMD_COPY_LISTENER            94
#define MQ_MQCMD_CREATE_LISTENER          95
#define MQ_MQCMD_DELETE_LISTENER          96
#define MQ_MQCMD_INQUIRE_LISTENER         97
#define MQ_MQCMD_INQUIRE_LISTENER_STATUS  98
#define MQ_MQCMD_COMMAND_EVENT            99
#define MQ_MQCMD_CHANGE_SECURITY          100
#define MQ_MQCMD_CHANGE_CF_STRUC          101
#define MQ_MQCMD_CHANGE_STG_CLASS         102
#define MQ_MQCMD_CHANGE_TRACE             103
#define MQ_MQCMD_ARCHIVE_LOG              104
#define MQ_MQCMD_BACKUP_CF_STRUC          105
#define MQ_MQCMD_CREATE_BUFFER_POOL       106
#define MQ_MQCMD_CREATE_PAGE_SET          107
#define MQ_MQCMD_CREATE_CF_STRUC          108
#define MQ_MQCMD_CREATE_STG_CLASS         109
#define MQ_MQCMD_COPY_CF_STRUC            110
#define MQ_MQCMD_COPY_STG_CLASS           111
#define MQ_MQCMD_DELETE_CF_STRUC          112
#define MQ_MQCMD_DELETE_STG_CLASS         113
#define MQ_MQCMD_INQUIRE_ARCHIVE          114
#define MQ_MQCMD_INQUIRE_CF_STRUC         115
#define MQ_MQCMD_INQUIRE_CF_STRUC_STATUS  116
#define MQ_MQCMD_INQUIRE_CMD_SERVER       117
#define MQ_MQCMD_INQUIRE_CHANNEL_INIT     118
#define MQ_MQCMD_INQUIRE_QSG              119
#define MQ_MQCMD_INQUIRE_LOG              120
#define MQ_MQCMD_INQUIRE_SECURITY         121
#define MQ_MQCMD_INQUIRE_STG_CLASS        122
#define MQ_MQCMD_INQUIRE_SYSTEM           123
#define MQ_MQCMD_INQUIRE_THREAD           124
#define MQ_MQCMD_INQUIRE_TRACE            125
#define MQ_MQCMD_INQUIRE_USAGE            126
#define MQ_MQCMD_MOVE_Q                   127
#define MQ_MQCMD_RECOVER_BSDS             128
#define MQ_MQCMD_RECOVER_CF_STRUC         129
#define MQ_MQCMD_RESET_TPIPE              130
#define MQ_MQCMD_RESOLVE_INDOUBT          131
#define MQ_MQCMD_RESUME_Q_MGR             132
#define MQ_MQCMD_REVERIFY_SECURITY        133
#define MQ_MQCMD_SET_ARCHIVE              134
#define MQ_MQCMD_SET_LOG                  136
#define MQ_MQCMD_SET_SYSTEM               137
#define MQ_MQCMD_START_CMD_SERVER         138
#define MQ_MQCMD_START_Q_MGR              139
#define MQ_MQCMD_START_TRACE              140
#define MQ_MQCMD_STOP_CHANNEL_INIT        141
#define MQ_MQCMD_STOP_CHANNEL_LISTENER    142
#define MQ_MQCMD_STOP_CMD_SERVER          143
#define MQ_MQCMD_STOP_Q_MGR               144
#define MQ_MQCMD_STOP_TRACE               145
#define MQ_MQCMD_SUSPEND_Q_MGR            146
#define MQ_MQCMD_INQUIRE_CF_STRUC_NAMES   147
#define MQ_MQCMD_INQUIRE_STG_CLASS_NAMES  148
#define MQ_MQCMD_CHANGE_SERVICE           149
#define MQ_MQCMD_COPY_SERVICE             150
#define MQ_MQCMD_CREATE_SERVICE           151
#define MQ_MQCMD_DELETE_SERVICE           152
#define MQ_MQCMD_INQUIRE_SERVICE          153
#define MQ_MQCMD_INQUIRE_SERVICE_STATUS   154
#define MQ_MQCMD_START_SERVICE            155
#define MQ_MQCMD_STOP_SERVICE             156
#define MQ_MQCMD_DELETE_BUFFER_POOL       157
#define MQ_MQCMD_DELETE_PAGE_SET          158
#define MQ_MQCMD_CHANGE_BUFFER_POOL       159
#define MQ_MQCMD_CHANGE_PAGE_SET          160
#define MQ_MQCMD_INQUIRE_Q_MGR_STATUS     161
#define MQ_MQCMD_CREATE_LOG               162
#define MQ_MQCMD_STATISTICS_MQI           164
#define MQ_MQCMD_STATISTICS_Q             165
#define MQ_MQCMD_STATISTICS_CHANNEL       166
#define MQ_MQCMD_ACCOUNTING_MQI           167
#define MQ_MQCMD_ACCOUNTING_Q             168
#define MQ_MQCMD_INQUIRE_AUTH_SERVICE     169
#define MQ_MQCMD_CHANGE_TOPIC             170
#define MQ_MQCMD_COPY_TOPIC               171
#define MQ_MQCMD_CREATE_TOPIC             172
#define MQ_MQCMD_DELETE_TOPIC             173
#define MQ_MQCMD_INQUIRE_TOPIC            174
#define MQ_MQCMD_INQUIRE_TOPIC_NAMES      175
#define MQ_MQCMD_INQUIRE_SUBSCRIPTION     176
#define MQ_MQCMD_CREATE_SUBSCRIPTION      177
#define MQ_MQCMD_CHANGE_SUBSCRIPTION      178
#define MQ_MQCMD_DELETE_SUBSCRIPTION      179
#define MQ_MQCMD_COPY_SUBSCRIPTION        181
#define MQ_MQCMD_INQUIRE_SUB_STATUS       182
#define MQ_MQCMD_INQUIRE_TOPIC_STATUS     183
#define MQ_MQCMD_CLEAR_TOPIC_STRING       184
#define MQ_MQCMD_INQUIRE_PUBSUB_STATUS    185
#define MQ_MQCMD_INQUIRE_SMDS             186
#define MQ_MQCMD_CHANGE_SMDS              187
#define MQ_MQCMD_RESET_SMDS               188
#define MQ_MQCMD_CREATE_COMM_INFO         190
#define MQ_MQCMD_INQUIRE_COMM_INFO        191
#define MQ_MQCMD_CHANGE_COMM_INFO         192
#define MQ_MQCMD_COPY_COMM_INFO           193
#define MQ_MQCMD_DELETE_COMM_INFO         194
#define MQ_MQCMD_PURGE_CHANNEL            195
#define MQ_MQCMD_MQXR_DIAGNOSTICS         196
#define MQ_MQCMD_START_SMDSCONN           197
#define MQ_MQCMD_STOP_SMDSCONN            198
#define MQ_MQCMD_INQUIRE_SMDSCONN         199
#define MQ_MQCMD_INQUIRE_MQXR_STATUS      200
#define MQ_MQCMD_START_CLIENT_TRACE       201
#define MQ_MQCMD_STOP_CLIENT_TRACE        202
#define MQ_MQCMD_SET_CHLAUTH_REC          203
#define MQ_MQCMD_INQUIRE_CHLAUTH_RECS     204
#define MQ_MQCMD_INQUIRE_PROT_POLICY      205
#define MQ_MQCMD_CREATE_PROT_POLICY       206
#define MQ_MQCMD_DELETE_PROT_POLICY       207
#define MQ_MQCMD_CHANGE_PROT_POLICY       208
#define MQ_MQCMD_ACTIVITY_TRACE           209
#define MQ_MQCMD_RESET_CF_STRUC           213
#define MQ_MQCMD_INQUIRE_XR_CAPABILITY    214
#define MQ_MQCMD_INQUIRE_AMQP_CAPABILITY  216
#define MQ_MQCMD_AMQP_DIAGNOSTICS         217

/* Control Options */
#define MQ_MQCFC_LAST                     1
#define MQ_MQCFC_NOT_LAST                 0

/* Reason Codes */
#define MQ_MQRCCF_CFH_TYPE_ERROR          3001
#define MQ_MQRCCF_CFH_LENGTH_ERROR        3002
#define MQ_MQRCCF_CFH_VERSION_ERROR       3003
#define MQ_MQRCCF_CFH_MSG_SEQ_NUMBER_ERR  3004
#define MQ_MQRCCF_CFH_CONTROL_ERROR       3005
#define MQ_MQRCCF_CFH_PARM_COUNT_ERROR    3006
#define MQ_MQRCCF_CFH_COMMAND_ERROR       3007
#define MQ_MQRCCF_COMMAND_FAILED          3008
#define MQ_MQRCCF_CFIN_LENGTH_ERROR       3009
#define MQ_MQRCCF_CFST_LENGTH_ERROR       3010
#define MQ_MQRCCF_CFST_STRING_LENGTH_ERR  3011
#define MQ_MQRCCF_FORCE_VALUE_ERROR       3012
#define MQ_MQRCCF_STRUCTURE_TYPE_ERROR    3013
#define MQ_MQRCCF_CFIN_PARM_ID_ERROR      3014
#define MQ_MQRCCF_CFST_PARM_ID_ERROR      3015
#define MQ_MQRCCF_MSG_LENGTH_ERROR        3016
#define MQ_MQRCCF_CFIN_DUPLICATE_PARM     3017
#define MQ_MQRCCF_CFST_DUPLICATE_PARM     3018
#define MQ_MQRCCF_PARM_COUNT_TOO_SMALL    3019
#define MQ_MQRCCF_PARM_COUNT_TOO_BIG      3020
#define MQ_MQRCCF_Q_ALREADY_IN_CELL       3021
#define MQ_MQRCCF_Q_TYPE_ERROR            3022
#define MQ_MQRCCF_MD_FORMAT_ERROR         3023
#define MQ_MQRCCF_CFSL_LENGTH_ERROR       3024
#define MQ_MQRCCF_REPLACE_VALUE_ERROR     3025
#define MQ_MQRCCF_CFIL_DUPLICATE_VALUE    3026
#define MQ_MQRCCF_CFIL_COUNT_ERROR        3027
#define MQ_MQRCCF_CFIL_LENGTH_ERROR       3028
#define MQ_MQRCCF_QUIESCE_VALUE_ERROR     3029
#define MQ_MQRCCF_MODE_VALUE_ERROR        3029
#define MQ_MQRCCF_MSG_SEQ_NUMBER_ERROR    3030
#define MQ_MQRCCF_PING_DATA_COUNT_ERROR   3031
#define MQ_MQRCCF_PING_DATA_COMPARE_ERROR 3032
#define MQ_MQRCCF_CFSL_PARM_ID_ERROR      3033
#define MQ_MQRCCF_CHANNEL_TYPE_ERROR      3034
#define MQ_MQRCCF_PARM_SEQUENCE_ERROR     3035
#define MQ_MQRCCF_XMIT_PROTOCOL_TYPE_ERR  3036
#define MQ_MQRCCF_BATCH_SIZE_ERROR        3037
#define MQ_MQRCCF_DISC_INT_ERROR          3038
#define MQ_MQRCCF_SHORT_RETRY_ERROR       3039
#define MQ_MQRCCF_SHORT_TIMER_ERROR       3040
#define MQ_MQRCCF_LONG_RETRY_ERROR        3041
#define MQ_MQRCCF_LONG_TIMER_ERROR        3042
#define MQ_MQRCCF_SEQ_NUMBER_WRAP_ERROR   3043
#define MQ_MQRCCF_MAX_MSG_LENGTH_ERROR    3044
#define MQ_MQRCCF_PUT_AUTH_ERROR          3045
#define MQ_MQRCCF_PURGE_VALUE_ERROR       3046
#define MQ_MQRCCF_CFIL_PARM_ID_ERROR      3047
#define MQ_MQRCCF_MSG_TRUNCATED           3048
#define MQ_MQRCCF_CCSID_ERROR             3049
#define MQ_MQRCCF_ENCODING_ERROR          3050
#define MQ_MQRCCF_QUEUES_VALUE_ERROR      3051
#define MQ_MQRCCF_DATA_CONV_VALUE_ERROR   3052
#define MQ_MQRCCF_INDOUBT_VALUE_ERROR     3053
#define MQ_MQRCCF_ESCAPE_TYPE_ERROR       3054
#define MQ_MQRCCF_REPOS_VALUE_ERROR       3055
#define MQ_MQRCCF_CHANNEL_TABLE_ERROR     3062
#define MQ_MQRCCF_MCA_TYPE_ERROR          3063
#define MQ_MQRCCF_CHL_INST_TYPE_ERROR     3064
#define MQ_MQRCCF_CHL_STATUS_NOT_FOUND    3065
#define MQ_MQRCCF_CFSL_DUPLICATE_PARM     3066
#define MQ_MQRCCF_CFSL_TOTAL_LENGTH_ERROR 3067
#define MQ_MQRCCF_CFSL_COUNT_ERROR        3068
#define MQ_MQRCCF_CFSL_STRING_LENGTH_ERR  3069
#define MQ_MQRCCF_BROKER_DELETED          3070
#define MQ_MQRCCF_STREAM_ERROR            3071
#define MQ_MQRCCF_TOPIC_ERROR             3072
#define MQ_MQRCCF_NOT_REGISTERED          3073
#define MQ_MQRCCF_Q_MGR_NAME_ERROR        3074
#define MQ_MQRCCF_INCORRECT_STREAM        3075
#define MQ_MQRCCF_Q_NAME_ERROR            3076
#define MQ_MQRCCF_NO_RETAINED_MSG         3077
#define MQ_MQRCCF_DUPLICATE_IDENTITY      3078
#define MQ_MQRCCF_INCORRECT_Q             3079
#define MQ_MQRCCF_CORREL_ID_ERROR         3080
#define MQ_MQRCCF_NOT_AUTHORIZED          3081
#define MQ_MQRCCF_UNKNOWN_STREAM          3082
#define MQ_MQRCCF_REG_OPTIONS_ERROR       3083
#define MQ_MQRCCF_PUB_OPTIONS_ERROR       3084
#define MQ_MQRCCF_UNKNOWN_BROKER          3085
#define MQ_MQRCCF_Q_MGR_CCSID_ERROR       3086
#define MQ_MQRCCF_DEL_OPTIONS_ERROR       3087
#define MQ_MQRCCF_CLUSTER_NAME_CONFLICT   3088
#define MQ_MQRCCF_REPOS_NAME_CONFLICT     3089
#define MQ_MQRCCF_CLUSTER_Q_USAGE_ERROR   3090
#define MQ_MQRCCF_ACTION_VALUE_ERROR      3091
#define MQ_MQRCCF_COMMS_LIBRARY_ERROR     3092
#define MQ_MQRCCF_NETBIOS_NAME_ERROR      3093
#define MQ_MQRCCF_BROKER_COMMAND_FAILED   3094
#define MQ_MQRCCF_CFST_CONFLICTING_PARM   3095
#define MQ_MQRCCF_PATH_NOT_VALID          3096
#define MQ_MQRCCF_PARM_SYNTAX_ERROR       3097
#define MQ_MQRCCF_PWD_LENGTH_ERROR        3098
#define MQ_MQRCCF_FILTER_ERROR            3150
#define MQ_MQRCCF_WRONG_USER              3151
#define MQ_MQRCCF_DUPLICATE_SUBSCRIPTION  3152
#define MQ_MQRCCF_SUB_NAME_ERROR          3153
#define MQ_MQRCCF_SUB_IDENTITY_ERROR      3154
#define MQ_MQRCCF_SUBSCRIPTION_IN_USE     3155
#define MQ_MQRCCF_SUBSCRIPTION_LOCKED     3156
#define MQ_MQRCCF_ALREADY_JOINED          3157
#define MQ_MQRCCF_OBJECT_IN_USE           3160
#define MQ_MQRCCF_UNKNOWN_FILE_NAME       3161
#define MQ_MQRCCF_FILE_NOT_AVAILABLE      3162
#define MQ_MQRCCF_DISC_RETRY_ERROR        3163
#define MQ_MQRCCF_ALLOC_RETRY_ERROR       3164
#define MQ_MQRCCF_ALLOC_SLOW_TIMER_ERROR  3165
#define MQ_MQRCCF_ALLOC_FAST_TIMER_ERROR  3166
#define MQ_MQRCCF_PORT_NUMBER_ERROR       3167
#define MQ_MQRCCF_CHL_SYSTEM_NOT_ACTIVE   3168
#define MQ_MQRCCF_ENTITY_NAME_MISSING     3169
#define MQ_MQRCCF_PROFILE_NAME_ERROR      3170
#define MQ_MQRCCF_AUTH_VALUE_ERROR        3171
#define MQ_MQRCCF_AUTH_VALUE_MISSING      3172
#define MQ_MQRCCF_OBJECT_TYPE_MISSING     3173
#define MQ_MQRCCF_CONNECTION_ID_ERROR     3174
#define MQ_MQRCCF_LOG_TYPE_ERROR          3175
#define MQ_MQRCCF_PROGRAM_NOT_AVAILABLE   3176
#define MQ_MQRCCF_PROGRAM_AUTH_FAILED     3177
#define MQ_MQRCCF_NONE_FOUND              3200
#define MQ_MQRCCF_SECURITY_SWITCH_OFF     3201
#define MQ_MQRCCF_SECURITY_REFRESH_FAILED 3202
#define MQ_MQRCCF_PARM_CONFLICT           3203
#define MQ_MQRCCF_COMMAND_INHIBITED       3204
#define MQ_MQRCCF_OBJECT_BEING_DELETED    3205
#define MQ_MQRCCF_STORAGE_CLASS_IN_USE    3207
#define MQ_MQRCCF_OBJECT_NAME_RESTRICTED  3208
#define MQ_MQRCCF_OBJECT_LIMIT_EXCEEDED   3209
#define MQ_MQRCCF_OBJECT_OPEN_FORCE       3210
#define MQ_MQRCCF_DISPOSITION_CONFLICT    3211
#define MQ_MQRCCF_Q_MGR_NOT_IN_QSG        3212
#define MQ_MQRCCF_ATTR_VALUE_FIXED        3213
#define MQ_MQRCCF_NAMELIST_ERROR          3215
#define MQ_MQRCCF_NO_CHANNEL_INITIATOR    3217
#define MQ_MQRCCF_CHANNEL_INITIATOR_ERROR 3218
#define MQ_MQRCCF_COMMAND_LEVEL_CONFLICT  3222
#define MQ_MQRCCF_Q_ATTR_CONFLICT         3223
#define MQ_MQRCCF_EVENTS_DISABLED         3224
#define MQ_MQRCCF_COMMAND_SCOPE_ERROR     3225
#define MQ_MQRCCF_COMMAND_REPLY_ERROR     3226
#define MQ_MQRCCF_FUNCTION_RESTRICTED     3227
#define MQ_MQRCCF_PARM_MISSING            3228
#define MQ_MQRCCF_PARM_VALUE_ERROR        3229
#define MQ_MQRCCF_COMMAND_LENGTH_ERROR    3230
#define MQ_MQRCCF_COMMAND_ORIGIN_ERROR    3231
#define MQ_MQRCCF_LISTENER_CONFLICT       3232
#define MQ_MQRCCF_LISTENER_STARTED        3233
#define MQ_MQRCCF_LISTENER_STOPPED        3234
#define MQ_MQRCCF_CHANNEL_ERROR           3235
#define MQ_MQRCCF_CF_STRUC_ERROR          3236
#define MQ_MQRCCF_UNKNOWN_USER_ID         3237
#define MQ_MQRCCF_UNEXPECTED_ERROR        3238
#define MQ_MQRCCF_NO_XCF_PARTNER          3239
#define MQ_MQRCCF_CFGR_PARM_ID_ERROR      3240
#define MQ_MQRCCF_CFIF_LENGTH_ERROR       3241
#define MQ_MQRCCF_CFIF_OPERATOR_ERROR     3242
#define MQ_MQRCCF_CFIF_PARM_ID_ERROR      3243
#define MQ_MQRCCF_CFSF_FILTER_VAL_LEN_ERR 3244
#define MQ_MQRCCF_CFSF_LENGTH_ERROR       3245
#define MQ_MQRCCF_CFSF_OPERATOR_ERROR     3246
#define MQ_MQRCCF_CFSF_PARM_ID_ERROR      3247
#define MQ_MQRCCF_TOO_MANY_FILTERS        3248
#define MQ_MQRCCF_LISTENER_RUNNING        3249
#define MQ_MQRCCF_LSTR_STATUS_NOT_FOUND   3250
#define MQ_MQRCCF_SERVICE_RUNNING         3251
#define MQ_MQRCCF_SERV_STATUS_NOT_FOUND   3252
#define MQ_MQRCCF_SERVICE_STOPPED         3253
#define MQ_MQRCCF_CFBS_DUPLICATE_PARM     3254
#define MQ_MQRCCF_CFBS_LENGTH_ERROR       3255
#define MQ_MQRCCF_CFBS_PARM_ID_ERROR      3256
#define MQ_MQRCCF_CFBS_STRING_LENGTH_ERR  3257
#define MQ_MQRCCF_CFGR_LENGTH_ERROR       3258
#define MQ_MQRCCF_CFGR_PARM_COUNT_ERROR   3259
#define MQ_MQRCCF_CONN_NOT_STOPPED        3260
#define MQ_MQRCCF_SERVICE_REQUEST_PENDING 3261
#define MQ_MQRCCF_NO_START_CMD            3262
#define MQ_MQRCCF_NO_STOP_CMD             3263
#define MQ_MQRCCF_CFBF_LENGTH_ERROR       3264
#define MQ_MQRCCF_CFBF_PARM_ID_ERROR      3265
#define MQ_MQRCCF_CFBF_OPERATOR_ERROR     3266
#define MQ_MQRCCF_CFBF_FILTER_VAL_LEN_ERR 3267
#define MQ_MQRCCF_LISTENER_STILL_ACTIVE   3268
#define MQ_MQRCCF_DEF_XMIT_Q_CLUS_ERROR   3269
#define MQ_MQRCCF_TOPICSTR_ALREADY_EXISTS 3300
#define MQ_MQRCCF_SHARING_CONVS_ERROR     3301
#define MQ_MQRCCF_SHARING_CONVS_TYPE      3302
#define MQ_MQRCCF_SECURITY_CASE_CONFLICT  3303
#define MQ_MQRCCF_TOPIC_TYPE_ERROR        3305
#define MQ_MQRCCF_MAX_INSTANCES_ERROR     3306
#define MQ_MQRCCF_MAX_INSTS_PER_CLNT_ERR  3307
#define MQ_MQRCCF_TOPIC_STRING_NOT_FOUND  3308
#define MQ_MQRCCF_SUBSCRIPTION_POINT_ERR  3309
#define MQ_MQRCCF_SUB_ALREADY_EXISTS      3311
#define MQ_MQRCCF_UNKNOWN_OBJECT_NAME     3312
#define MQ_MQRCCF_REMOTE_Q_NAME_ERROR     3313
#define MQ_MQRCCF_DURABILITY_NOT_ALLOWED  3314
#define MQ_MQRCCF_HOBJ_ERROR              3315
#define MQ_MQRCCF_DEST_NAME_ERROR         3316
#define MQ_MQRCCF_INVALID_DESTINATION     3317
#define MQ_MQRCCF_PUBSUB_INHIBITED        3318
#define MQ_MQRCCF_GROUPUR_CHECKS_FAILED   3319
#define MQ_MQRCCF_COMM_INFO_TYPE_ERROR    3320
#define MQ_MQRCCF_USE_CLIENT_ID_ERROR     3321
#define MQ_MQRCCF_CLIENT_ID_NOT_FOUND     3322
#define MQ_MQRCCF_CLIENT_ID_ERROR         3323
#define MQ_MQRCCF_PORT_IN_USE             3324
#define MQ_MQRCCF_SSL_ALT_PROVIDER_REQD   3325
#define MQ_MQRCCF_CHLAUTH_TYPE_ERROR      3326
#define MQ_MQRCCF_CHLAUTH_ACTION_ERROR    3327
#define MQ_MQRCCF_POLICY_NOT_FOUND        3328
#define MQ_MQRCCF_ENCRYPTION_ALG_ERROR    3329
#define MQ_MQRCCF_SIGNATURE_ALG_ERROR     3330
#define MQ_MQRCCF_TOLERATION_POL_ERROR    3331
#define MQ_MQRCCF_POLICY_VERSION_ERROR    3332
#define MQ_MQRCCF_RECIPIENT_DN_MISSING    3333
#define MQ_MQRCCF_POLICY_NAME_MISSING     3334
#define MQ_MQRCCF_CHLAUTH_USERSRC_ERROR   3335
#define MQ_MQRCCF_WRONG_CHLAUTH_TYPE      3336
#define MQ_MQRCCF_CHLAUTH_ALREADY_EXISTS  3337
#define MQ_MQRCCF_CHLAUTH_NOT_FOUND       3338
#define MQ_MQRCCF_WRONG_CHLAUTH_ACTION    3339
#define MQ_MQRCCF_WRONG_CHLAUTH_USERSRC   3340
#define MQ_MQRCCF_CHLAUTH_WARN_ERROR      3341
#define MQ_MQRCCF_WRONG_CHLAUTH_MATCH     3342
#define MQ_MQRCCF_IPADDR_RANGE_CONFLICT   3343
#define MQ_MQRCCF_CHLAUTH_MAX_EXCEEDED    3344
#define MQ_MQRCCF_IPADDR_ERROR            3345
#define MQ_MQRCCF_IPADDR_RANGE_ERROR      3346
#define MQ_MQRCCF_PROFILE_NAME_MISSING    3347
#define MQ_MQRCCF_CHLAUTH_CLNTUSER_ERROR  3348
#define MQ_MQRCCF_CHLAUTH_NAME_ERROR      3349
#define MQ_MQRCCF_CHLAUTH_RUNCHECK_ERROR  3350
#define MQ_MQRCCF_CF_STRUC_ALREADY_FAILED 3351
#define MQ_MQRCCF_CFCONLOS_CHECKS_FAILED  3352
#define MQ_MQRCCF_SUITE_B_ERROR           3353
#define MQ_MQRCCF_CHANNEL_NOT_STARTED     3354
#define MQ_MQRCCF_CUSTOM_ERROR            3355
#define MQ_MQRCCF_BACKLOG_OUT_OF_RANGE    3356
#define MQ_MQRCCF_CHLAUTH_DISABLED        3357
#define MQ_MQRCCF_SMDS_REQUIRES_DSGROUP   3358
#define MQ_MQRCCF_PSCLUS_DISABLED_TOPDEF  3359
#define MQ_MQRCCF_PSCLUS_TOPIC_EXISTS     3360
#define MQ_MQRCCF_SSL_CIPHER_SUITE_ERROR  3361
#define MQ_MQRCCF_SOCKET_ERROR            3362
#define MQ_MQRCCF_CLUS_XMIT_Q_USAGE_ERROR 3363
#define MQ_MQRCCF_CERT_VAL_POLICY_ERROR   3364
#define MQ_MQRCCF_INVALID_PROTOCOL        3365
#define MQ_MQRCCF_REVDNS_DISABLED         3366
#define MQ_MQRCCF_CLROUTE_NOT_ALTERABLE   3367
#define MQ_MQRCCF_CLUSTER_TOPIC_CONFLICT  3368
#define MQ_MQRCCF_DEFCLXQ_MODEL_Q_ERROR   3369
#define MQ_MQRCCF_CHLAUTH_CHKCLI_ERROR    3370
#define MQ_MQRCCF_CERT_LABEL_NOT_ALLOWED  3371
#define MQ_MQRCCF_Q_MGR_ATTR_CONFLICT     3372
#define MQ_MQRCCF_ENTITY_TYPE_MISSING     3373
#define MQ_MQRCCF_CLWL_EXIT_NAME_ERROR    3374
#define MQ_MQRCCF_SERVICE_NAME_ERROR      3375
#define MQ_MQRCCF_REMOTE_CHL_TYPE_ERROR   3376
#define MQ_MQRCCF_TOPIC_RESTRICTED        3377
#define MQ_MQRCCF_OBJECT_ALREADY_EXISTS   4001
#define MQ_MQRCCF_OBJECT_WRONG_TYPE       4002
#define MQ_MQRCCF_LIKE_OBJECT_WRONG_TYPE  4003
#define MQ_MQRCCF_OBJECT_OPEN             4004
#define MQ_MQRCCF_ATTR_VALUE_ERROR        4005
#define MQ_MQRCCF_UNKNOWN_Q_MGR           4006
#define MQ_MQRCCF_Q_WRONG_TYPE            4007
#define MQ_MQRCCF_OBJECT_NAME_ERROR       4008
#define MQ_MQRCCF_ALLOCATE_FAILED         4009
#define MQ_MQRCCF_HOST_NOT_AVAILABLE      4010
#define MQ_MQRCCF_CONFIGURATION_ERROR     4011
#define MQ_MQRCCF_CONNECTION_REFUSED      4012
#define MQ_MQRCCF_ENTRY_ERROR             4013
#define MQ_MQRCCF_SEND_FAILED             4014
#define MQ_MQRCCF_RECEIVED_DATA_ERROR     4015
#define MQ_MQRCCF_RECEIVE_FAILED          4016
#define MQ_MQRCCF_CONNECTION_CLOSED       4017
#define MQ_MQRCCF_NO_STORAGE              4018
#define MQ_MQRCCF_NO_COMMS_MANAGER        4019
#define MQ_MQRCCF_LISTENER_NOT_STARTED    4020
#define MQ_MQRCCF_BIND_FAILED             4024
#define MQ_MQRCCF_CHANNEL_INDOUBT         4025
#define MQ_MQRCCF_MQCONN_FAILED           4026
#define MQ_MQRCCF_MQOPEN_FAILED           4027
#define MQ_MQRCCF_MQGET_FAILED            4028
#define MQ_MQRCCF_MQPUT_FAILED            4029
#define MQ_MQRCCF_PING_ERROR              4030
#define MQ_MQRCCF_CHANNEL_IN_USE          4031
#define MQ_MQRCCF_CHANNEL_NOT_FOUND       4032
#define MQ_MQRCCF_UNKNOWN_REMOTE_CHANNEL  4033
#define MQ_MQRCCF_REMOTE_QM_UNAVAILABLE   4034
#define MQ_MQRCCF_REMOTE_QM_TERMINATING   4035
#define MQ_MQRCCF_MQINQ_FAILED            4036
#define MQ_MQRCCF_NOT_XMIT_Q              4037
#define MQ_MQRCCF_CHANNEL_DISABLED        4038
#define MQ_MQRCCF_USER_EXIT_NOT_AVAILABLE 4039
#define MQ_MQRCCF_COMMIT_FAILED           4040
#define MQ_MQRCCF_WRONG_CHANNEL_TYPE      4041
#define MQ_MQRCCF_CHANNEL_ALREADY_EXISTS  4042
#define MQ_MQRCCF_DATA_TOO_LARGE          4043
#define MQ_MQRCCF_CHANNEL_NAME_ERROR      4044
#define MQ_MQRCCF_XMIT_Q_NAME_ERROR       4045
#define MQ_MQRCCF_MCA_NAME_ERROR          4047
#define MQ_MQRCCF_SEND_EXIT_NAME_ERROR    4048
#define MQ_MQRCCF_SEC_EXIT_NAME_ERROR     4049
#define MQ_MQRCCF_MSG_EXIT_NAME_ERROR     4050
#define MQ_MQRCCF_RCV_EXIT_NAME_ERROR     4051
#define MQ_MQRCCF_XMIT_Q_NAME_WRONG_TYPE  4052
#define MQ_MQRCCF_MCA_NAME_WRONG_TYPE     4053
#define MQ_MQRCCF_DISC_INT_WRONG_TYPE     4054
#define MQ_MQRCCF_SHORT_RETRY_WRONG_TYPE  4055
#define MQ_MQRCCF_SHORT_TIMER_WRONG_TYPE  4056
#define MQ_MQRCCF_LONG_RETRY_WRONG_TYPE   4057
#define MQ_MQRCCF_LONG_TIMER_WRONG_TYPE   4058
#define MQ_MQRCCF_PUT_AUTH_WRONG_TYPE     4059
#define MQ_MQRCCF_KEEP_ALIVE_INT_ERROR    4060
#define MQ_MQRCCF_MISSING_CONN_NAME       4061
#define MQ_MQRCCF_CONN_NAME_ERROR         4062
#define MQ_MQRCCF_MQSET_FAILED            4063
#define MQ_MQRCCF_CHANNEL_NOT_ACTIVE      4064
#define MQ_MQRCCF_TERMINATED_BY_SEC_EXIT  4065
#define MQ_MQRCCF_DYNAMIC_Q_SCOPE_ERROR   4067
#define MQ_MQRCCF_CELL_DIR_NOT_AVAILABLE  4068
#define MQ_MQRCCF_MR_COUNT_ERROR          4069
#define MQ_MQRCCF_MR_COUNT_WRONG_TYPE     4070
#define MQ_MQRCCF_MR_EXIT_NAME_ERROR      4071
#define MQ_MQRCCF_MR_EXIT_NAME_WRONG_TYPE 4072
#define MQ_MQRCCF_MR_INTERVAL_ERROR       4073
#define MQ_MQRCCF_MR_INTERVAL_WRONG_TYPE  4074
#define MQ_MQRCCF_NPM_SPEED_ERROR         4075
#define MQ_MQRCCF_NPM_SPEED_WRONG_TYPE    4076
#define MQ_MQRCCF_HB_INTERVAL_ERROR       4077
#define MQ_MQRCCF_HB_INTERVAL_WRONG_TYPE  4078
#define MQ_MQRCCF_CHAD_ERROR              4079
#define MQ_MQRCCF_CHAD_WRONG_TYPE         4080
#define MQ_MQRCCF_CHAD_EVENT_ERROR        4081
#define MQ_MQRCCF_CHAD_EVENT_WRONG_TYPE   4082
#define MQ_MQRCCF_CHAD_EXIT_ERROR         4083
#define MQ_MQRCCF_CHAD_EXIT_WRONG_TYPE    4084
#define MQ_MQRCCF_SUPPRESSED_BY_EXIT      4085
#define MQ_MQRCCF_BATCH_INT_ERROR         4086
#define MQ_MQRCCF_BATCH_INT_WRONG_TYPE    4087
#define MQ_MQRCCF_NET_PRIORITY_ERROR      4088
#define MQ_MQRCCF_NET_PRIORITY_WRONG_TYPE 4089
#define MQ_MQRCCF_CHANNEL_CLOSED          4090
#define MQ_MQRCCF_Q_STATUS_NOT_FOUND      4091
#define MQ_MQRCCF_SSL_CIPHER_SPEC_ERROR   4092
#define MQ_MQRCCF_SSL_PEER_NAME_ERROR     4093
#define MQ_MQRCCF_SSL_CLIENT_AUTH_ERROR   4094
#define MQ_MQRCCF_RETAINED_NOT_SUPPORTED  4095

/* Flags */
#define MQ_MQEPH_NONE                     0x00000000
#define MQ_MQEPH_CCSID_EMBEDDED           0x00000001

/* Filter Operators */
#define MQ_MQCFOP_LESS                    1
#define MQ_MQCFOP_EQUAL                   2
#define MQ_MQCFOP_GREATER                 4
#define MQ_MQCFOP_NOT_LESS                6
#define MQ_MQCFOP_NOT_EQUAL               5
#define MQ_MQCFOP_NOT_GREATER             3
#define MQ_MQCFOP_LIKE                    18
#define MQ_MQCFOP_NOT_LIKE                21
#define MQ_MQCFOP_CONTAINS                10
#define MQ_MQCFOP_EXCLUDES                13
#define MQ_MQCFOP_CONTAINS_GEN            26
#define MQ_MQCFOP_EXCLUDES_GEN            29

/* Types of Structure */
#define MQ_MQCFT_NONE                     0
#define MQ_MQCFT_COMMAND                  1
#define MQ_MQCFT_RESPONSE                 2
#define MQ_MQCFT_INTEGER                  3
#define MQ_MQCFT_STRING                   4
#define MQ_MQCFT_INTEGER_LIST             5
#define MQ_MQCFT_STRING_LIST              6
#define MQ_MQCFT_EVENT                    7
#define MQ_MQCFT_USER                     8
#define MQ_MQCFT_BYTE_STRING              9
#define MQ_MQCFT_TRACE_ROUTE              10
#define MQ_MQCFT_REPORT                   12
#define MQ_MQCFT_INTEGER_FILTER           13
#define MQ_MQCFT_STRING_FILTER            14
#define MQ_MQCFT_BYTE_STRING_FILTER       15
#define MQ_MQCFT_COMMAND_XR               16
#define MQ_MQCFT_XR_MSG                   17
#define MQ_MQCFT_XR_ITEM                  18
#define MQ_MQCFT_XR_SUMMARY               19
#define MQ_MQCFT_GROUP                    20
#define MQ_MQCFT_STATISTICS               21
#define MQ_MQCFT_ACCOUNTING               22
#define MQ_MQCFT_INTEGER64                23
#define MQ_MQCFT_INTEGER64_LIST           25
#define MQ_MQCFT_APP_ACTIVITY             26

/* Major Release Function */
#define MQ_MQOPMODE_COMPAT                0
#define MQ_MQOPMODE_NEW_FUNCTION          1

/****************************************************************/
/* Values Related to Byte Parameter Structures                  */
/****************************************************************/

/* Byte Parameter Types */
#define MQ_MQBACF_FIRST                   7001
#define MQ_MQBACF_EVENT_ACCOUNTING_TOKEN  7001
#define MQ_MQBACF_EVENT_SECURITY_ID       7002
#define MQ_MQBACF_RESPONSE_SET            7003
#define MQ_MQBACF_RESPONSE_ID             7004
#define MQ_MQBACF_EXTERNAL_UOW_ID         7005
#define MQ_MQBACF_CONNECTION_ID           7006
#define MQ_MQBACF_GENERIC_CONNECTION_ID   7007
#define MQ_MQBACF_ORIGIN_UOW_ID           7008
#define MQ_MQBACF_Q_MGR_UOW_ID            7009
#define MQ_MQBACF_ACCOUNTING_TOKEN        7010
#define MQ_MQBACF_CORREL_ID               7011
#define MQ_MQBACF_GROUP_ID                7012
#define MQ_MQBACF_MSG_ID                  7013
#define MQ_MQBACF_CF_LEID                 7014
#define MQ_MQBACF_DESTINATION_CORREL_ID   7015
#define MQ_MQBACF_SUB_ID                  7016
#define MQ_MQBACF_ALTERNATE_SECURITYID    7019
#define MQ_MQBACF_MESSAGE_DATA            7020
#define MQ_MQBACF_MQBO_STRUCT             7021
#define MQ_MQBACF_MQCB_FUNCTION           7022
#define MQ_MQBACF_MQCBC_STRUCT            7023
#define MQ_MQBACF_MQCBD_STRUCT            7024
#define MQ_MQBACF_MQCD_STRUCT             7025
#define MQ_MQBACF_MQCNO_STRUCT            7026
#define MQ_MQBACF_MQGMO_STRUCT            7027
#define MQ_MQBACF_MQMD_STRUCT             7028
#define MQ_MQBACF_MQPMO_STRUCT            7029
#define MQ_MQBACF_MQSD_STRUCT             7030
#define MQ_MQBACF_MQSTS_STRUCT            7031
#define MQ_MQBACF_SUB_CORREL_ID           7032
#define MQ_MQBACF_XA_XID                  7033
#define MQ_MQBACF_XQH_CORREL_ID           7034
#define MQ_MQBACF_XQH_MSG_ID              7035
#define MQ_MQBACF_LAST_USED               7035

/****************************************************************/
/* Values Related to Integer Parameter Structures               */
/****************************************************************/


/* Integer Monitoring Parameter Types */
#define MQ_MQIAMO_FIRST                   701
#define MQ_MQIAMO_AVG_BATCH_SIZE          702
#define MQ_MQIAMO_AVG_Q_TIME              703
#define MQ_MQIAMO64_AVG_Q_TIME            703
#define MQ_MQIAMO_BACKOUTS                704
#define MQ_MQIAMO_BROWSES                 705
#define MQ_MQIAMO_BROWSE_MAX_BYTES        706
#define MQ_MQIAMO_BROWSE_MIN_BYTES        707
#define MQ_MQIAMO_BROWSES_FAILED          708
#define MQ_MQIAMO_CLOSES                  709
#define MQ_MQIAMO_COMMITS                 710
#define MQ_MQIAMO_COMMITS_FAILED          711
#define MQ_MQIAMO_CONNS                   712
#define MQ_MQIAMO_CONNS_MAX               713
#define MQ_MQIAMO_DISCS                   714
#define MQ_MQIAMO_DISCS_IMPLICIT          715
#define MQ_MQIAMO_DISC_TYPE               716
#define MQ_MQIAMO_EXIT_TIME_AVG           717
#define MQ_MQIAMO_EXIT_TIME_MAX           718
#define MQ_MQIAMO_EXIT_TIME_MIN           719
#define MQ_MQIAMO_FULL_BATCHES            720
#define MQ_MQIAMO_GENERATED_MSGS          721
#define MQ_MQIAMO_GETS                    722
#define MQ_MQIAMO_GET_MAX_BYTES           723
#define MQ_MQIAMO_GET_MIN_BYTES           724
#define MQ_MQIAMO_GETS_FAILED             725
#define MQ_MQIAMO_INCOMPLETE_BATCHES      726
#define MQ_MQIAMO_INQS                    727
#define MQ_MQIAMO_MSGS                    728
#define MQ_MQIAMO_NET_TIME_AVG            729
#define MQ_MQIAMO_NET_TIME_MAX            730
#define MQ_MQIAMO_NET_TIME_MIN            731
#define MQ_MQIAMO_OBJECT_COUNT            732
#define MQ_MQIAMO_OPENS                   733
#define MQ_MQIAMO_PUT1S                   734
#define MQ_MQIAMO_PUTS                    735
#define MQ_MQIAMO_PUT_MAX_BYTES           736
#define MQ_MQIAMO_PUT_MIN_BYTES           737
#define MQ_MQIAMO_PUT_RETRIES             738
#define MQ_MQIAMO_Q_MAX_DEPTH             739
#define MQ_MQIAMO_Q_MIN_DEPTH             740
#define MQ_MQIAMO_Q_TIME_AVG              741
#define MQ_MQIAMO64_Q_TIME_AVG            741
#define MQ_MQIAMO_Q_TIME_MAX              742
#define MQ_MQIAMO64_Q_TIME_MAX            742
#define MQ_MQIAMO_Q_TIME_MIN              743
#define MQ_MQIAMO64_Q_TIME_MIN            743
#define MQ_MQIAMO_SETS                    744
#define MQ_MQIAMO64_BROWSE_BYTES          745
#define MQ_MQIAMO64_BYTES                 746
#define MQ_MQIAMO64_GET_BYTES             747
#define MQ_MQIAMO64_PUT_BYTES             748
#define MQ_MQIAMO_CONNS_FAILED            749
#define MQ_MQIAMO_OPENS_FAILED            751
#define MQ_MQIAMO_INQS_FAILED             752
#define MQ_MQIAMO_SETS_FAILED             753
#define MQ_MQIAMO_PUTS_FAILED             754
#define MQ_MQIAMO_PUT1S_FAILED            755
#define MQ_MQIAMO_CLOSES_FAILED           757
#define MQ_MQIAMO_MSGS_EXPIRED            758
#define MQ_MQIAMO_MSGS_NOT_QUEUED         759
#define MQ_MQIAMO_MSGS_PURGED             760
#define MQ_MQIAMO_SUBS_DUR                764
#define MQ_MQIAMO_SUBS_NDUR               765
#define MQ_MQIAMO_SUBS_FAILED             766
#define MQ_MQIAMO_SUBRQS                  767
#define MQ_MQIAMO_SUBRQS_FAILED           768
#define MQ_MQIAMO_CBS                     769
#define MQ_MQIAMO_CBS_FAILED              770
#define MQ_MQIAMO_CTLS                    771
#define MQ_MQIAMO_CTLS_FAILED             772
#define MQ_MQIAMO_STATS                   773
#define MQ_MQIAMO_STATS_FAILED            774
#define MQ_MQIAMO_SUB_DUR_HIGHWATER       775
#define MQ_MQIAMO_SUB_DUR_LOWWATER        776
#define MQ_MQIAMO_SUB_NDUR_HIGHWATER      777
#define MQ_MQIAMO_SUB_NDUR_LOWWATER       778
#define MQ_MQIAMO_TOPIC_PUTS              779
#define MQ_MQIAMO_TOPIC_PUTS_FAILED       780
#define MQ_MQIAMO_TOPIC_PUT1S             781
#define MQ_MQIAMO_TOPIC_PUT1S_FAILED      782
#define MQ_MQIAMO64_TOPIC_PUT_BYTES       783
#define MQ_MQIAMO_PUBLISH_MSG_COUNT       784
#define MQ_MQIAMO64_PUBLISH_MSG_BYTES     785
#define MQ_MQIAMO_UNSUBS_DUR              786
#define MQ_MQIAMO_UNSUBS_NDUR             787
#define MQ_MQIAMO_UNSUBS_FAILED           788
#define MQ_MQIAMO_INTERVAL                789
#define MQ_MQIAMO_MSGS_SENT               790
#define MQ_MQIAMO_BYTES_SENT              791
#define MQ_MQIAMO_REPAIR_BYTES            792
#define MQ_MQIAMO_FEEDBACK_MODE           793
#define MQ_MQIAMO_RELIABILITY_TYPE        794
#define MQ_MQIAMO_LATE_JOIN_MARK          795
#define MQ_MQIAMO_NACKS_RCVD              796
#define MQ_MQIAMO_REPAIR_PKTS             797
#define MQ_MQIAMO_HISTORY_PKTS            798
#define MQ_MQIAMO_PENDING_PKTS            799
#define MQ_MQIAMO_PKT_RATE                800
#define MQ_MQIAMO_MCAST_XMIT_RATE         801
#define MQ_MQIAMO_MCAST_BATCH_TIME        802
#define MQ_MQIAMO_MCAST_HEARTBEAT         803
#define MQ_MQIAMO_DEST_DATA_PORT          804
#define MQ_MQIAMO_DEST_REPAIR_PORT        805
#define MQ_MQIAMO_ACKS_RCVD               806
#define MQ_MQIAMO_ACTIVE_ACKERS           807
#define MQ_MQIAMO_PKTS_SENT               808
#define MQ_MQIAMO_TOTAL_REPAIR_PKTS       809
#define MQ_MQIAMO_TOTAL_PKTS_SENT         810
#define MQ_MQIAMO_TOTAL_MSGS_SENT         811
#define MQ_MQIAMO_TOTAL_BYTES_SENT        812
#define MQ_MQIAMO_NUM_STREAMS             813
#define MQ_MQIAMO_ACK_FEEDBACK            814
#define MQ_MQIAMO_NACK_FEEDBACK           815
#define MQ_MQIAMO_PKTS_LOST               816
#define MQ_MQIAMO_MSGS_RCVD               817
#define MQ_MQIAMO_MSG_BYTES_RCVD          818
#define MQ_MQIAMO_MSGS_DELIVERED          819
#define MQ_MQIAMO_PKTS_PROCESSED          820
#define MQ_MQIAMO_PKTS_DELIVERED          821
#define MQ_MQIAMO_PKTS_DROPPED            822
#define MQ_MQIAMO_PKTS_DUPLICATED         823
#define MQ_MQIAMO_NACKS_CREATED           824
#define MQ_MQIAMO_NACK_PKTS_SENT          825
#define MQ_MQIAMO_REPAIR_PKTS_RQSTD       826
#define MQ_MQIAMO_REPAIR_PKTS_RCVD        827
#define MQ_MQIAMO_PKTS_REPAIRED           828
#define MQ_MQIAMO_TOTAL_MSGS_RCVD         829
#define MQ_MQIAMO_TOTAL_MSG_BYTES_RCVD    830
#define MQ_MQIAMO_TOTAL_REPAIR_PKTS_RCVD  831
#define MQ_MQIAMO_TOTAL_REPAIR_PKTS_RQSTD 832
#define MQ_MQIAMO_TOTAL_MSGS_PROCESSED    833
#define MQ_MQIAMO_TOTAL_MSGS_SELECTED     834
#define MQ_MQIAMO_TOTAL_MSGS_EXPIRED      835
#define MQ_MQIAMO_TOTAL_MSGS_DELIVERED    836
#define MQ_MQIAMO_TOTAL_MSGS_RETURNED     837
#define MQ_MQIAMO64_HIGHRES_TIME          838
#define MQ_MQIAMO_MONITOR_CLASS           839
#define MQ_MQIAMO_MONITOR_TYPE            840
#define MQ_MQIAMO_MONITOR_ELEMENT         841
#define MQ_MQIAMO_MONITOR_DATATYPE        842
#define MQ_MQIAMO_MONITOR_FLAGS           843
#define MQ_MQIAMO64_QMGR_OP_DURATION      844
#define MQ_MQIAMO64_MONITOR_INTERVAL      845
#define MQ_MQIAMO_LAST_USED               845

/* Defined values for MQIAMO_MONITOR_FLAGS */
#define MQ_MQIAMO_MONITOR_FLAGS_NONE      0
#define MQ_MQIAMO_MONITOR_FLAGS_OBJNAME   1

/* Defined values for MQIAMO_MONITOR_DATATYPE */
#define MQ_MQIAMO_MONITOR_UNIT            1
#define MQ_MQIAMO_MONITOR_DELTA           2
#define MQ_MQIAMO_MONITOR_HUNDREDTHS      100
#define MQ_MQIAMO_MONITOR_KB              1024
#define MQ_MQIAMO_MONITOR_PERCENT         10000
#define MQ_MQIAMO_MONITOR_MICROSEC        1000000
#define MQ_MQIAMO_MONITOR_MB              1048576
#define MQ_MQIAMO_MONITOR_GB              100000000

/* Integer Parameter Types */
#define MQ_MQIACF_FIRST                   1001
#define MQ_MQIACF_Q_MGR_ATTRS             1001
#define MQ_MQIACF_Q_ATTRS                 1002
#define MQ_MQIACF_PROCESS_ATTRS           1003
#define MQ_MQIACF_NAMELIST_ATTRS          1004
#define MQ_MQIACF_FORCE                   1005
#define MQ_MQIACF_REPLACE                 1006
#define MQ_MQIACF_PURGE                   1007
#define MQ_MQIACF_QUIESCE                 1008
#define MQ_MQIACF_MODE                    1008
#define MQ_MQIACF_ALL                     1009
#define MQ_MQIACF_EVENT_APPL_TYPE         1010
#define MQ_MQIACF_EVENT_ORIGIN            1011
#define MQ_MQIACF_PARAMETER_ID            1012
#define MQ_MQIACF_ERROR_ID                1013
#define MQ_MQIACF_ERROR_IDENTIFIER        1013
#define MQ_MQIACF_SELECTOR                1014
#define MQ_MQIACF_CHANNEL_ATTRS           1015
#define MQ_MQIACF_OBJECT_TYPE             1016
#define MQ_MQIACF_ESCAPE_TYPE             1017
#define MQ_MQIACF_ERROR_OFFSET            1018
#define MQ_MQIACF_AUTH_INFO_ATTRS         1019
#define MQ_MQIACF_REASON_QUALIFIER        1020
#define MQ_MQIACF_COMMAND                 1021
#define MQ_MQIACF_OPEN_OPTIONS            1022
#define MQ_MQIACF_OPEN_TYPE               1023
#define MQ_MQIACF_PROCESS_ID              1024
#define MQ_MQIACF_THREAD_ID               1025
#define MQ_MQIACF_Q_STATUS_ATTRS          1026
#define MQ_MQIACF_UNCOMMITTED_MSGS        1027
#define MQ_MQIACF_HANDLE_STATE            1028
#define MQ_MQIACF_AUX_ERROR_DATA_INT_1    1070
#define MQ_MQIACF_AUX_ERROR_DATA_INT_2    1071
#define MQ_MQIACF_CONV_REASON_CODE        1072
#define MQ_MQIACF_BRIDGE_TYPE             1073
#define MQ_MQIACF_INQUIRY                 1074
#define MQ_MQIACF_WAIT_INTERVAL           1075
#define MQ_MQIACF_OPTIONS                 1076
#define MQ_MQIACF_BROKER_OPTIONS          1077
#define MQ_MQIACF_REFRESH_TYPE            1078
#define MQ_MQIACF_SEQUENCE_NUMBER         1079
#define MQ_MQIACF_INTEGER_DATA            1080
#define MQ_MQIACF_REGISTRATION_OPTIONS    1081
#define MQ_MQIACF_PUBLICATION_OPTIONS     1082
#define MQ_MQIACF_CLUSTER_INFO            1083
#define MQ_MQIACF_Q_MGR_DEFINITION_TYPE   1084
#define MQ_MQIACF_Q_MGR_TYPE              1085
#define MQ_MQIACF_ACTION                  1086
#define MQ_MQIACF_SUSPEND                 1087
#define MQ_MQIACF_BROKER_COUNT            1088
#define MQ_MQIACF_APPL_COUNT              1089
#define MQ_MQIACF_ANONYMOUS_COUNT         1090
#define MQ_MQIACF_REG_REG_OPTIONS         1091
#define MQ_MQIACF_DELETE_OPTIONS          1092
#define MQ_MQIACF_CLUSTER_Q_MGR_ATTRS     1093
#define MQ_MQIACF_REFRESH_INTERVAL        1094
#define MQ_MQIACF_REFRESH_REPOSITORY      1095
#define MQ_MQIACF_REMOVE_QUEUES           1096
#define MQ_MQIACF_OPEN_INPUT_TYPE         1098
#define MQ_MQIACF_OPEN_OUTPUT             1099
#define MQ_MQIACF_OPEN_SET                1100
#define MQ_MQIACF_OPEN_INQUIRE            1101
#define MQ_MQIACF_OPEN_BROWSE             1102
#define MQ_MQIACF_Q_STATUS_TYPE           1103
#define MQ_MQIACF_Q_HANDLE                1104
#define MQ_MQIACF_Q_STATUS                1105
#define MQ_MQIACF_SECURITY_TYPE           1106
#define MQ_MQIACF_CONNECTION_ATTRS        1107
#define MQ_MQIACF_CONNECT_OPTIONS         1108
#define MQ_MQIACF_CONN_INFO_TYPE          1110
#define MQ_MQIACF_CONN_INFO_CONN          1111
#define MQ_MQIACF_CONN_INFO_HANDLE        1112
#define MQ_MQIACF_CONN_INFO_ALL           1113
#define MQ_MQIACF_AUTH_PROFILE_ATTRS      1114
#define MQ_MQIACF_AUTHORIZATION_LIST      1115
#define MQ_MQIACF_AUTH_ADD_AUTHS          1116
#define MQ_MQIACF_AUTH_REMOVE_AUTHS       1117
#define MQ_MQIACF_ENTITY_TYPE             1118
#define MQ_MQIACF_COMMAND_INFO            1120
#define MQ_MQIACF_CMDSCOPE_Q_MGR_COUNT    1121
#define MQ_MQIACF_Q_MGR_SYSTEM            1122
#define MQ_MQIACF_Q_MGR_EVENT             1123
#define MQ_MQIACF_Q_MGR_DQM               1124
#define MQ_MQIACF_Q_MGR_CLUSTER           1125
#define MQ_MQIACF_QSG_DISPS               1126
#define MQ_MQIACF_UOW_STATE               1128
#define MQ_MQIACF_SECURITY_ITEM           1129
#define MQ_MQIACF_CF_STRUC_STATUS         1130
#define MQ_MQIACF_UOW_TYPE                1132
#define MQ_MQIACF_CF_STRUC_ATTRS          1133
#define MQ_MQIACF_EXCLUDE_INTERVAL        1134
#define MQ_MQIACF_CF_STATUS_TYPE          1135
#define MQ_MQIACF_CF_STATUS_SUMMARY       1136
#define MQ_MQIACF_CF_STATUS_CONNECT       1137
#define MQ_MQIACF_CF_STATUS_BACKUP        1138
#define MQ_MQIACF_CF_STRUC_TYPE           1139
#define MQ_MQIACF_CF_STRUC_SIZE_MAX       1140
#define MQ_MQIACF_CF_STRUC_SIZE_USED      1141
#define MQ_MQIACF_CF_STRUC_ENTRIES_MAX    1142
#define MQ_MQIACF_CF_STRUC_ENTRIES_USED   1143
#define MQ_MQIACF_CF_STRUC_BACKUP_SIZE    1144
#define MQ_MQIACF_MOVE_TYPE               1145
#define MQ_MQIACF_MOVE_TYPE_MOVE          1146
#define MQ_MQIACF_MOVE_TYPE_ADD           1147
#define MQ_MQIACF_Q_MGR_NUMBER            1148
#define MQ_MQIACF_Q_MGR_STATUS            1149
#define MQ_MQIACF_DB2_CONN_STATUS         1150
#define MQ_MQIACF_SECURITY_ATTRS          1151
#define MQ_MQIACF_SECURITY_TIMEOUT        1152
#define MQ_MQIACF_SECURITY_INTERVAL       1153
#define MQ_MQIACF_SECURITY_SWITCH         1154
#define MQ_MQIACF_SECURITY_SETTING        1155
#define MQ_MQIACF_STORAGE_CLASS_ATTRS     1156
#define MQ_MQIACF_USAGE_TYPE              1157
#define MQ_MQIACF_BUFFER_POOL_ID          1158
#define MQ_MQIACF_USAGE_TOTAL_PAGES       1159
#define MQ_MQIACF_USAGE_UNUSED_PAGES      1160
#define MQ_MQIACF_USAGE_PERSIST_PAGES     1161
#define MQ_MQIACF_USAGE_NONPERSIST_PAGES  1162
#define MQ_MQIACF_USAGE_RESTART_EXTENTS   1163
#define MQ_MQIACF_USAGE_EXPAND_COUNT      1164
#define MQ_MQIACF_PAGESET_STATUS          1165
#define MQ_MQIACF_USAGE_TOTAL_BUFFERS     1166
#define MQ_MQIACF_USAGE_DATA_SET_TYPE     1167
#define MQ_MQIACF_USAGE_PAGESET           1168
#define MQ_MQIACF_USAGE_DATA_SET          1169
#define MQ_MQIACF_USAGE_BUFFER_POOL       1170
#define MQ_MQIACF_MOVE_COUNT              1171
#define MQ_MQIACF_EXPIRY_Q_COUNT          1172
#define MQ_MQIACF_CONFIGURATION_OBJECTS   1173
#define MQ_MQIACF_CONFIGURATION_EVENTS    1174
#define MQ_MQIACF_SYSP_TYPE               1175
#define MQ_MQIACF_SYSP_DEALLOC_INTERVAL   1176
#define MQ_MQIACF_SYSP_MAX_ARCHIVE        1177
#define MQ_MQIACF_SYSP_MAX_READ_TAPES     1178
#define MQ_MQIACF_SYSP_IN_BUFFER_SIZE     1179
#define MQ_MQIACF_SYSP_OUT_BUFFER_SIZE    1180
#define MQ_MQIACF_SYSP_OUT_BUFFER_COUNT   1181
#define MQ_MQIACF_SYSP_ARCHIVE            1182
#define MQ_MQIACF_SYSP_DUAL_ACTIVE        1183
#define MQ_MQIACF_SYSP_DUAL_ARCHIVE       1184
#define MQ_MQIACF_SYSP_DUAL_BSDS          1185
#define MQ_MQIACF_SYSP_MAX_CONNS          1186
#define MQ_MQIACF_SYSP_MAX_CONNS_FORE     1187
#define MQ_MQIACF_SYSP_MAX_CONNS_BACK     1188
#define MQ_MQIACF_SYSP_EXIT_INTERVAL      1189
#define MQ_MQIACF_SYSP_EXIT_TASKS         1190
#define MQ_MQIACF_SYSP_CHKPOINT_COUNT     1191
#define MQ_MQIACF_SYSP_OTMA_INTERVAL      1192
#define MQ_MQIACF_SYSP_Q_INDEX_DEFER      1193
#define MQ_MQIACF_SYSP_DB2_TASKS          1194
#define MQ_MQIACF_SYSP_RESLEVEL_AUDIT     1195
#define MQ_MQIACF_SYSP_ROUTING_CODE       1196
#define MQ_MQIACF_SYSP_SMF_ACCOUNTING     1197
#define MQ_MQIACF_SYSP_SMF_STATS          1198
#define MQ_MQIACF_SYSP_SMF_INTERVAL       1199
#define MQ_MQIACF_SYSP_TRACE_CLASS        1200
#define MQ_MQIACF_SYSP_TRACE_SIZE         1201
#define MQ_MQIACF_SYSP_WLM_INTERVAL       1202
#define MQ_MQIACF_SYSP_ALLOC_UNIT         1203
#define MQ_MQIACF_SYSP_ARCHIVE_RETAIN     1204
#define MQ_MQIACF_SYSP_ARCHIVE_WTOR       1205
#define MQ_MQIACF_SYSP_BLOCK_SIZE         1206
#define MQ_MQIACF_SYSP_CATALOG            1207
#define MQ_MQIACF_SYSP_COMPACT            1208
#define MQ_MQIACF_SYSP_ALLOC_PRIMARY      1209
#define MQ_MQIACF_SYSP_ALLOC_SECONDARY    1210
#define MQ_MQIACF_SYSP_PROTECT            1211
#define MQ_MQIACF_SYSP_QUIESCE_INTERVAL   1212
#define MQ_MQIACF_SYSP_TIMESTAMP          1213
#define MQ_MQIACF_SYSP_UNIT_ADDRESS       1214
#define MQ_MQIACF_SYSP_UNIT_STATUS        1215
#define MQ_MQIACF_SYSP_LOG_COPY           1216
#define MQ_MQIACF_SYSP_LOG_USED           1217
#define MQ_MQIACF_SYSP_LOG_SUSPEND        1218
#define MQ_MQIACF_SYSP_OFFLOAD_STATUS     1219
#define MQ_MQIACF_SYSP_TOTAL_LOGS         1220
#define MQ_MQIACF_SYSP_FULL_LOGS          1221
#define MQ_MQIACF_LISTENER_ATTRS          1222
#define MQ_MQIACF_LISTENER_STATUS_ATTRS   1223
#define MQ_MQIACF_SERVICE_ATTRS           1224
#define MQ_MQIACF_SERVICE_STATUS_ATTRS    1225
#define MQ_MQIACF_Q_TIME_INDICATOR        1226
#define MQ_MQIACF_OLDEST_MSG_AGE          1227
#define MQ_MQIACF_AUTH_OPTIONS            1228
#define MQ_MQIACF_Q_MGR_STATUS_ATTRS      1229
#define MQ_MQIACF_CONNECTION_COUNT        1230
#define MQ_MQIACF_Q_MGR_FACILITY          1231
#define MQ_MQIACF_CHINIT_STATUS           1232
#define MQ_MQIACF_CMD_SERVER_STATUS       1233
#define MQ_MQIACF_ROUTE_DETAIL            1234
#define MQ_MQIACF_RECORDED_ACTIVITIES     1235
#define MQ_MQIACF_MAX_ACTIVITIES          1236
#define MQ_MQIACF_DISCONTINUITY_COUNT     1237
#define MQ_MQIACF_ROUTE_ACCUMULATION      1238
#define MQ_MQIACF_ROUTE_DELIVERY          1239
#define MQ_MQIACF_OPERATION_TYPE          1240
#define MQ_MQIACF_BACKOUT_COUNT           1241
#define MQ_MQIACF_COMP_CODE               1242
#define MQ_MQIACF_ENCODING                1243
#define MQ_MQIACF_EXPIRY                  1244
#define MQ_MQIACF_FEEDBACK                1245
#define MQ_MQIACF_MSG_FLAGS               1247
#define MQ_MQIACF_MSG_LENGTH              1248
#define MQ_MQIACF_MSG_TYPE                1249
#define MQ_MQIACF_OFFSET                  1250
#define MQ_MQIACF_ORIGINAL_LENGTH         1251
#define MQ_MQIACF_PERSISTENCE             1252
#define MQ_MQIACF_PRIORITY                1253
#define MQ_MQIACF_REASON_CODE             1254
#define MQ_MQIACF_REPORT                  1255
#define MQ_MQIACF_VERSION                 1256
#define MQ_MQIACF_UNRECORDED_ACTIVITIES   1257
#define MQ_MQIACF_MONITORING              1258
#define MQ_MQIACF_ROUTE_FORWARDING        1259
#define MQ_MQIACF_SERVICE_STATUS          1260
#define MQ_MQIACF_Q_TYPES                 1261
#define MQ_MQIACF_USER_ID_SUPPORT         1262
#define MQ_MQIACF_INTERFACE_VERSION       1263
#define MQ_MQIACF_AUTH_SERVICE_ATTRS      1264
#define MQ_MQIACF_USAGE_EXPAND_TYPE       1265
#define MQ_MQIACF_SYSP_CLUSTER_CACHE      1266
#define MQ_MQIACF_SYSP_DB2_BLOB_TASKS     1267
#define MQ_MQIACF_SYSP_WLM_INT_UNITS      1268
#define MQ_MQIACF_TOPIC_ATTRS             1269
#define MQ_MQIACF_PUBSUB_PROPERTIES       1271
#define MQ_MQIACF_DESTINATION_CLASS       1273
#define MQ_MQIACF_DURABLE_SUBSCRIPTION    1274
#define MQ_MQIACF_SUBSCRIPTION_SCOPE      1275
#define MQ_MQIACF_VARIABLE_USER_ID        1277
#define MQ_MQIACF_REQUEST_ONLY            1280
#define MQ_MQIACF_PUB_PRIORITY            1283
#define MQ_MQIACF_SUB_ATTRS               1287
#define MQ_MQIACF_WILDCARD_SCHEMA         1288
#define MQ_MQIACF_SUB_TYPE                1289
#define MQ_MQIACF_MESSAGE_COUNT           1290
#define MQ_MQIACF_Q_MGR_PUBSUB            1291
#define MQ_MQIACF_Q_MGR_VERSION           1292
#define MQ_MQIACF_SUB_STATUS_ATTRS        1294
#define MQ_MQIACF_TOPIC_STATUS            1295
#define MQ_MQIACF_TOPIC_SUB               1296
#define MQ_MQIACF_TOPIC_PUB               1297
#define MQ_MQIACF_RETAINED_PUBLICATION    1300
#define MQ_MQIACF_TOPIC_STATUS_ATTRS      1301
#define MQ_MQIACF_TOPIC_STATUS_TYPE       1302
#define MQ_MQIACF_SUB_OPTIONS             1303
#define MQ_MQIACF_PUBLISH_COUNT           1304
#define MQ_MQIACF_CLEAR_TYPE              1305
#define MQ_MQIACF_CLEAR_SCOPE             1306
#define MQ_MQIACF_SUB_LEVEL               1307
#define MQ_MQIACF_ASYNC_STATE             1308
#define MQ_MQIACF_SUB_SUMMARY             1309
#define MQ_MQIACF_OBSOLETE_MSGS           1310
#define MQ_MQIACF_PUBSUB_STATUS           1311
#define MQ_MQIACF_PS_STATUS_TYPE          1314
#define MQ_MQIACF_PUBSUB_STATUS_ATTRS     1318
#define MQ_MQIACF_SELECTOR_TYPE           1321
#define MQ_MQIACF_LOG_COMPRESSION         1322
#define MQ_MQIACF_GROUPUR_CHECK_ID        1323
#define MQ_MQIACF_MULC_CAPTURE            1324
#define MQ_MQIACF_PERMIT_STANDBY          1325
#define MQ_MQIACF_OPERATION_MODE          1326
#define MQ_MQIACF_COMM_INFO_ATTRS         1327
#define MQ_MQIACF_CF_SMDS_BLOCK_SIZE      1328
#define MQ_MQIACF_CF_SMDS_EXPAND          1329
#define MQ_MQIACF_USAGE_FREE_BUFF         1330
#define MQ_MQIACF_USAGE_FREE_BUFF_PERC    1331
#define MQ_MQIACF_CF_STRUC_ACCESS         1332
#define MQ_MQIACF_CF_STATUS_SMDS          1333
#define MQ_MQIACF_SMDS_ATTRS              1334
#define MQ_MQIACF_USAGE_SMDS              1335
#define MQ_MQIACF_USAGE_BLOCK_SIZE        1336
#define MQ_MQIACF_USAGE_DATA_BLOCKS       1337
#define MQ_MQIACF_USAGE_EMPTY_BUFFERS     1338
#define MQ_MQIACF_USAGE_INUSE_BUFFERS     1339
#define MQ_MQIACF_USAGE_LOWEST_FREE       1340
#define MQ_MQIACF_USAGE_OFFLOAD_MSGS      1341
#define MQ_MQIACF_USAGE_READS_SAVED       1342
#define MQ_MQIACF_USAGE_SAVED_BUFFERS     1343
#define MQ_MQIACF_USAGE_TOTAL_BLOCKS      1344
#define MQ_MQIACF_USAGE_USED_BLOCKS       1345
#define MQ_MQIACF_USAGE_USED_RATE         1346
#define MQ_MQIACF_USAGE_WAIT_RATE         1347
#define MQ_MQIACF_SMDS_OPENMODE           1348
#define MQ_MQIACF_SMDS_STATUS             1349
#define MQ_MQIACF_SMDS_AVAIL              1350
#define MQ_MQIACF_MCAST_REL_INDICATOR     1351
#define MQ_MQIACF_CHLAUTH_TYPE            1352
#define MQ_MQIACF_MQXR_DIAGNOSTICS_TYPE   1354
#define MQ_MQIACF_CHLAUTH_ATTRS           1355
#define MQ_MQIACF_OPERATION_ID            1356
#define MQ_MQIACF_API_CALLER_TYPE         1357
#define MQ_MQIACF_API_ENVIRONMENT         1358
#define MQ_MQIACF_TRACE_DETAIL            1359
#define MQ_MQIACF_HOBJ                    1360
#define MQ_MQIACF_CALL_TYPE               1361
#define MQ_MQIACF_MQCB_OPERATION          1362
#define MQ_MQIACF_MQCB_TYPE               1363
#define MQ_MQIACF_MQCB_OPTIONS            1364
#define MQ_MQIACF_CLOSE_OPTIONS           1365
#define MQ_MQIACF_CTL_OPERATION           1366
#define MQ_MQIACF_GET_OPTIONS             1367
#define MQ_MQIACF_RECS_PRESENT            1368
#define MQ_MQIACF_KNOWN_DEST_COUNT        1369
#define MQ_MQIACF_UNKNOWN_DEST_COUNT      1370
#define MQ_MQIACF_INVALID_DEST_COUNT      1371
#define MQ_MQIACF_RESOLVED_TYPE           1372
#define MQ_MQIACF_PUT_OPTIONS             1373
#define MQ_MQIACF_BUFFER_LENGTH           1374
#define MQ_MQIACF_TRACE_DATA_LENGTH       1375
#define MQ_MQIACF_SMDS_EXPANDST           1376
#define MQ_MQIACF_STRUC_LENGTH            1377
#define MQ_MQIACF_ITEM_COUNT              1378
#define MQ_MQIACF_EXPIRY_TIME             1379
#define MQ_MQIACF_CONNECT_TIME            1380
#define MQ_MQIACF_DISCONNECT_TIME         1381
#define MQ_MQIACF_HSUB                    1382
#define MQ_MQIACF_SUBRQ_OPTIONS           1383
#define MQ_MQIACF_XA_RMID                 1384
#define MQ_MQIACF_XA_FLAGS                1385
#define MQ_MQIACF_XA_RETCODE              1386
#define MQ_MQIACF_XA_HANDLE               1387
#define MQ_MQIACF_XA_RETVAL               1388
#define MQ_MQIACF_STATUS_TYPE             1389
#define MQ_MQIACF_XA_COUNT                1390
#define MQ_MQIACF_SELECTOR_COUNT          1391
#define MQ_MQIACF_SELECTORS               1392
#define MQ_MQIACF_INTATTR_COUNT           1393
#define MQ_MQIACF_INT_ATTRS               1394
#define MQ_MQIACF_SUBRQ_ACTION            1395
#define MQ_MQIACF_NUM_PUBS                1396
#define MQ_MQIACF_POINTER_SIZE            1397
#define MQ_MQIACF_REMOVE_AUTHREC          1398
#define MQ_MQIACF_XR_ATTRS                1399
#define MQ_MQIACF_APPL_FUNCTION_TYPE      1400
#define MQ_MQIACF_AMQP_ATTRS              1401
#define MQ_MQIACF_EXPORT_TYPE             1402
#define MQ_MQIACF_EXPORT_ATTRS            1403
#define MQ_MQIACF_SYSTEM_OBJECTS          1404
#define MQ_MQIACF_CONNECTION_SWAP         1405
#define MQ_MQIACF_AMQP_DIAGNOSTICS_TYPE   1406
#define MQ_MQIACF_BUFFER_POOL_LOCATION    1408
#define MQ_MQIACF_LDAP_CONNECTION_STATUS  1409
#define MQ_MQIACF_SYSP_MAX_ACE_POOL       1410
#define MQ_MQIACF_PAGECLAS                1411
#define MQ_MQIACF_LAST_USED               1411

/* Access Options */
#define MQ_MQCFACCESS_ENABLED             0
#define MQ_MQCFACCESS_SUSPENDED           1
#define MQ_MQCFACCESS_DISABLED            2

/* Open Mode Options */
#define MQ_MQS_OPENMODE_NONE              0
#define MQ_MQS_OPENMODE_READONLY          1
#define MQ_MQS_OPENMODE_UPDATE            2
#define MQ_MQS_OPENMODE_RECOVERY          3

/* SMDS Status Options */
#define MQ_MQS_STATUS_CLOSED              0
#define MQ_MQS_STATUS_CLOSING             1
#define MQ_MQS_STATUS_OPENING             2
#define MQ_MQS_STATUS_OPEN                3
#define MQ_MQS_STATUS_NOTENABLED          4
#define MQ_MQS_STATUS_ALLOCFAIL           5
#define MQ_MQS_STATUS_OPENFAIL            6
#define MQ_MQS_STATUS_STGFAIL             7
#define MQ_MQS_STATUS_DATAFAIL            8

/* SMDS Availability Options */
#define MQ_MQS_AVAIL_NORMAL               0
#define MQ_MQS_AVAIL_ERROR                1
#define MQ_MQS_AVAIL_STOPPED              2

/* Expandst Options */
#define MQ_MQS_EXPANDST_NORMAL            0
#define MQ_MQS_EXPANDST_FAILED            1
#define MQ_MQS_EXPANDST_MAXIMUM           2

/* Usage SMDS Options */
#define MQ_MQUSAGE_SMDS_AVAILABLE         0
#define MQ_MQUSAGE_SMDS_NO_DATA           1

/* Integer Channel Types */
#define MQ_MQIACH_FIRST                   1501
#define MQ_MQIACH_XMIT_PROTOCOL_TYPE      1501
#define MQ_MQIACH_BATCH_SIZE              1502
#define MQ_MQIACH_DISC_INTERVAL           1503
#define MQ_MQIACH_SHORT_TIMER             1504
#define MQ_MQIACH_SHORT_RETRY             1505
#define MQ_MQIACH_LONG_TIMER              1506
#define MQ_MQIACH_LONG_RETRY              1507
#define MQ_MQIACH_PUT_AUTHORITY           1508
#define MQ_MQIACH_SEQUENCE_NUMBER_WRAP    1509
#define MQ_MQIACH_MAX_MSG_LENGTH          1510
#define MQ_MQIACH_CHANNEL_TYPE            1511
#define MQ_MQIACH_DATA_COUNT              1512
#define MQ_MQIACH_NAME_COUNT              1513
#define MQ_MQIACH_MSG_SEQUENCE_NUMBER     1514
#define MQ_MQIACH_DATA_CONVERSION         1515
#define MQ_MQIACH_IN_DOUBT                1516
#define MQ_MQIACH_MCA_TYPE                1517
#define MQ_MQIACH_SESSION_COUNT           1518
#define MQ_MQIACH_ADAPTER                 1519
#define MQ_MQIACH_COMMAND_COUNT           1520
#define MQ_MQIACH_SOCKET                  1521
#define MQ_MQIACH_PORT                    1522
#define MQ_MQIACH_CHANNEL_INSTANCE_TYPE   1523
#define MQ_MQIACH_CHANNEL_INSTANCE_ATTRS  1524
#define MQ_MQIACH_CHANNEL_ERROR_DATA      1525
#define MQ_MQIACH_CHANNEL_TABLE           1526
#define MQ_MQIACH_CHANNEL_STATUS          1527
#define MQ_MQIACH_INDOUBT_STATUS          1528
#define MQ_MQIACH_LAST_SEQ_NUMBER         1529
#define MQ_MQIACH_LAST_SEQUENCE_NUMBER    1529
#define MQ_MQIACH_CURRENT_MSGS            1531
#define MQ_MQIACH_CURRENT_SEQ_NUMBER      1532
#define MQ_MQIACH_CURRENT_SEQUENCE_NUMBER 1532
#define MQ_MQIACH_SSL_RETURN_CODE         1533
#define MQ_MQIACH_MSGS                    1534
#define MQ_MQIACH_BYTES_SENT              1535
#define MQ_MQIACH_BYTES_RCVD              1536
#define MQ_MQIACH_BYTES_RECEIVED          1536
#define MQ_MQIACH_BATCHES                 1537
#define MQ_MQIACH_BUFFERS_SENT            1538
#define MQ_MQIACH_BUFFERS_RCVD            1539
#define MQ_MQIACH_BUFFERS_RECEIVED        1539
#define MQ_MQIACH_LONG_RETRIES_LEFT       1540
#define MQ_MQIACH_SHORT_RETRIES_LEFT      1541
#define MQ_MQIACH_MCA_STATUS              1542
#define MQ_MQIACH_STOP_REQUESTED          1543
#define MQ_MQIACH_MR_COUNT                1544
#define MQ_MQIACH_MR_INTERVAL             1545
#define MQ_MQIACH_NPM_SPEED               1562
#define MQ_MQIACH_HB_INTERVAL             1563
#define MQ_MQIACH_BATCH_INTERVAL          1564
#define MQ_MQIACH_NETWORK_PRIORITY        1565
#define MQ_MQIACH_KEEP_ALIVE_INTERVAL     1566
#define MQ_MQIACH_BATCH_HB                1567
#define MQ_MQIACH_SSL_CLIENT_AUTH         1568
#define MQ_MQIACH_ALLOC_RETRY             1570
#define MQ_MQIACH_ALLOC_FAST_TIMER        1571
#define MQ_MQIACH_ALLOC_SLOW_TIMER        1572
#define MQ_MQIACH_DISC_RETRY              1573
#define MQ_MQIACH_PORT_NUMBER             1574
#define MQ_MQIACH_HDR_COMPRESSION         1575
#define MQ_MQIACH_MSG_COMPRESSION         1576
#define MQ_MQIACH_CLWL_CHANNEL_RANK       1577
#define MQ_MQIACH_CLWL_CHANNEL_PRIORITY   1578
#define MQ_MQIACH_CLWL_CHANNEL_WEIGHT     1579
#define MQ_MQIACH_CHANNEL_DISP            1580
#define MQ_MQIACH_INBOUND_DISP            1581
#define MQ_MQIACH_CHANNEL_TYPES           1582
#define MQ_MQIACH_ADAPS_STARTED           1583
#define MQ_MQIACH_ADAPS_MAX               1584
#define MQ_MQIACH_DISPS_STARTED           1585
#define MQ_MQIACH_DISPS_MAX               1586
#define MQ_MQIACH_SSLTASKS_STARTED        1587
#define MQ_MQIACH_SSLTASKS_MAX            1588
#define MQ_MQIACH_CURRENT_CHL             1589
#define MQ_MQIACH_CURRENT_CHL_MAX         1590
#define MQ_MQIACH_CURRENT_CHL_TCP         1591
#define MQ_MQIACH_CURRENT_CHL_LU62        1592
#define MQ_MQIACH_ACTIVE_CHL              1593
#define MQ_MQIACH_ACTIVE_CHL_MAX          1594
#define MQ_MQIACH_ACTIVE_CHL_PAUSED       1595
#define MQ_MQIACH_ACTIVE_CHL_STARTED      1596
#define MQ_MQIACH_ACTIVE_CHL_STOPPED      1597
#define MQ_MQIACH_ACTIVE_CHL_RETRY        1598
#define MQ_MQIACH_LISTENER_STATUS         1599
#define MQ_MQIACH_SHARED_CHL_RESTART      1600
#define MQ_MQIACH_LISTENER_CONTROL        1601
#define MQ_MQIACH_BACKLOG                 1602
#define MQ_MQIACH_XMITQ_TIME_INDICATOR    1604
#define MQ_MQIACH_NETWORK_TIME_INDICATOR  1605
#define MQ_MQIACH_EXIT_TIME_INDICATOR     1606
#define MQ_MQIACH_BATCH_SIZE_INDICATOR    1607
#define MQ_MQIACH_XMITQ_MSGS_AVAILABLE    1608
#define MQ_MQIACH_CHANNEL_SUBSTATE        1609
#define MQ_MQIACH_SSL_KEY_RESETS          1610
#define MQ_MQIACH_COMPRESSION_RATE        1611
#define MQ_MQIACH_COMPRESSION_TIME        1612
#define MQ_MQIACH_MAX_XMIT_SIZE           1613
#define MQ_MQIACH_DEF_CHANNEL_DISP        1614
#define MQ_MQIACH_SHARING_CONVERSATIONS   1615
#define MQ_MQIACH_MAX_SHARING_CONVS       1616
#define MQ_MQIACH_CURRENT_SHARING_CONVS   1617
#define MQ_MQIACH_MAX_INSTANCES           1618
#define MQ_MQIACH_MAX_INSTS_PER_CLIENT    1619
#define MQ_MQIACH_CLIENT_CHANNEL_WEIGHT   1620
#define MQ_MQIACH_CONNECTION_AFFINITY     1621
#define MQ_MQIACH_RESET_REQUESTED         1623
#define MQ_MQIACH_BATCH_DATA_LIMIT        1624
#define MQ_MQIACH_MSG_HISTORY             1625
#define MQ_MQIACH_MULTICAST_PROPERTIES    1626
#define MQ_MQIACH_NEW_SUBSCRIBER_HISTORY  1627
#define MQ_MQIACH_MC_HB_INTERVAL          1628
#define MQ_MQIACH_USE_CLIENT_ID           1629
#define MQ_MQIACH_MQTT_KEEP_ALIVE         1630
#define MQ_MQIACH_IN_DOUBT_IN             1631
#define MQ_MQIACH_IN_DOUBT_OUT            1632
#define MQ_MQIACH_MSGS_SENT               1633
#define MQ_MQIACH_MSGS_RECEIVED           1634
#define MQ_MQIACH_MSGS_RCVD               1634
#define MQ_MQIACH_PENDING_OUT             1635
#define MQ_MQIACH_AVAILABLE_CIPHERSPECS   1636
#define MQ_MQIACH_MATCH                   1637
#define MQ_MQIACH_USER_SOURCE             1638
#define MQ_MQIACH_WARNING                 1639
#define MQ_MQIACH_DEF_RECONNECT           1640
#define MQ_MQIACH_CHANNEL_SUMMARY_ATTRS   1642
#define MQ_MQIACH_PROTOCOL                1643
#define MQ_MQIACH_AMQP_KEEP_ALIVE         1644
#define MQ_MQIACH_SECURITY_PROTOCOL       1645
#define MQ_MQIACH_LAST_USED               1645


/****************************************************************/
/* Values Related to Character Parameter Structures             */
/****************************************************************/

/* Character Monitoring Parameter Types */
#define MQ_MQCAMO_FIRST                   2701
#define MQ_MQCAMO_CLOSE_DATE              2701
#define MQ_MQCAMO_CLOSE_TIME              2702
#define MQ_MQCAMO_CONN_DATE               2703
#define MQ_MQCAMO_CONN_TIME               2704
#define MQ_MQCAMO_DISC_DATE               2705
#define MQ_MQCAMO_DISC_TIME               2706
#define MQ_MQCAMO_END_DATE                2707
#define MQ_MQCAMO_END_TIME                2708
#define MQ_MQCAMO_OPEN_DATE               2709
#define MQ_MQCAMO_OPEN_TIME               2710
#define MQ_MQCAMO_START_DATE              2711
#define MQ_MQCAMO_START_TIME              2712
#define MQ_MQCAMO_MONITOR_CLASS           2713
#define MQ_MQCAMO_MONITOR_TYPE            2714
#define MQ_MQCAMO_MONITOR_DESC            2715
#define MQ_MQCAMO_LAST_USED               2715

/* Character Parameter Types */
#define MQ_MQCACF_FIRST                   3001
#define MQ_MQCACF_FROM_Q_NAME             3001
#define MQ_MQCACF_TO_Q_NAME               3002
#define MQ_MQCACF_FROM_PROCESS_NAME       3003
#define MQ_MQCACF_TO_PROCESS_NAME         3004
#define MQ_MQCACF_FROM_NAMELIST_NAME      3005
#define MQ_MQCACF_TO_NAMELIST_NAME        3006
#define MQ_MQCACF_FROM_CHANNEL_NAME       3007
#define MQ_MQCACF_TO_CHANNEL_NAME         3008
#define MQ_MQCACF_FROM_AUTH_INFO_NAME     3009
#define MQ_MQCACF_TO_AUTH_INFO_NAME       3010
#define MQ_MQCACF_Q_NAMES                 3011
#define MQ_MQCACF_PROCESS_NAMES           3012
#define MQ_MQCACF_NAMELIST_NAMES          3013
#define MQ_MQCACF_ESCAPE_TEXT             3014
#define MQ_MQCACF_LOCAL_Q_NAMES           3015
#define MQ_MQCACF_MODEL_Q_NAMES           3016
#define MQ_MQCACF_ALIAS_Q_NAMES           3017
#define MQ_MQCACF_REMOTE_Q_NAMES          3018
#define MQ_MQCACF_SENDER_CHANNEL_NAMES    3019
#define MQ_MQCACF_SERVER_CHANNEL_NAMES    3020
#define MQ_MQCACF_REQUESTER_CHANNEL_NAMES 3021
#define MQ_MQCACF_RECEIVER_CHANNEL_NAMES  3022
#define MQ_MQCACF_OBJECT_Q_MGR_NAME       3023
#define MQ_MQCACF_APPL_NAME               3024
#define MQ_MQCACF_USER_IDENTIFIER         3025
#define MQ_MQCACF_AUX_ERROR_DATA_STR_1    3026
#define MQ_MQCACF_AUX_ERROR_DATA_STR_2    3027
#define MQ_MQCACF_AUX_ERROR_DATA_STR_3    3028
#define MQ_MQCACF_BRIDGE_NAME             3029
#define MQ_MQCACF_STREAM_NAME             3030
#define MQ_MQCACF_TOPIC                   3031
#define MQ_MQCACF_PARENT_Q_MGR_NAME       3032
#define MQ_MQCACF_CORREL_ID               3033
#define MQ_MQCACF_PUBLISH_TIMESTAMP       3034
#define MQ_MQCACF_STRING_DATA             3035
#define MQ_MQCACF_SUPPORTED_STREAM_NAME   3036
#define MQ_MQCACF_REG_TOPIC               3037
#define MQ_MQCACF_REG_TIME                3038
#define MQ_MQCACF_REG_USER_ID             3039
#define MQ_MQCACF_CHILD_Q_MGR_NAME        3040
#define MQ_MQCACF_REG_STREAM_NAME         3041
#define MQ_MQCACF_REG_Q_MGR_NAME          3042
#define MQ_MQCACF_REG_Q_NAME              3043
#define MQ_MQCACF_REG_CORREL_ID           3044
#define MQ_MQCACF_EVENT_USER_ID           3045
#define MQ_MQCACF_OBJECT_NAME             3046
#define MQ_MQCACF_EVENT_Q_MGR             3047
#define MQ_MQCACF_AUTH_INFO_NAMES         3048
#define MQ_MQCACF_EVENT_APPL_IDENTITY     3049
#define MQ_MQCACF_EVENT_APPL_NAME         3050
#define MQ_MQCACF_EVENT_APPL_ORIGIN       3051
#define MQ_MQCACF_SUBSCRIPTION_NAME       3052
#define MQ_MQCACF_REG_SUB_NAME            3053
#define MQ_MQCACF_SUBSCRIPTION_IDENTITY   3054
#define MQ_MQCACF_REG_SUB_IDENTITY        3055
#define MQ_MQCACF_SUBSCRIPTION_USER_DATA  3056
#define MQ_MQCACF_REG_SUB_USER_DATA       3057
#define MQ_MQCACF_APPL_TAG                3058
#define MQ_MQCACF_DATA_SET_NAME           3059
#define MQ_MQCACF_UOW_START_DATE          3060
#define MQ_MQCACF_UOW_START_TIME          3061
#define MQ_MQCACF_UOW_LOG_START_DATE      3062
#define MQ_MQCACF_UOW_LOG_START_TIME      3063
#define MQ_MQCACF_UOW_LOG_EXTENT_NAME     3064
#define MQ_MQCACF_PRINCIPAL_ENTITY_NAMES  3065
#define MQ_MQCACF_GROUP_ENTITY_NAMES      3066
#define MQ_MQCACF_AUTH_PROFILE_NAME       3067
#define MQ_MQCACF_ENTITY_NAME             3068
#define MQ_MQCACF_SERVICE_COMPONENT       3069
#define MQ_MQCACF_RESPONSE_Q_MGR_NAME     3070
#define MQ_MQCACF_CURRENT_LOG_EXTENT_NAME 3071
#define MQ_MQCACF_RESTART_LOG_EXTENT_NAME 3072
#define MQ_MQCACF_MEDIA_LOG_EXTENT_NAME   3073
#define MQ_MQCACF_LOG_PATH                3074
#define MQ_MQCACF_COMMAND_MQSC            3075
#define MQ_MQCACF_Q_MGR_CPF               3076
#define MQ_MQCACF_USAGE_LOG_RBA           3078
#define MQ_MQCACF_USAGE_LOG_LRSN          3079
#define MQ_MQCACF_COMMAND_SCOPE           3080
#define MQ_MQCACF_ASID                    3081
#define MQ_MQCACF_PSB_NAME                3082
#define MQ_MQCACF_PST_ID                  3083
#define MQ_MQCACF_TASK_NUMBER             3084
#define MQ_MQCACF_TRANSACTION_ID          3085
#define MQ_MQCACF_Q_MGR_UOW_ID            3086
#define MQ_MQCACF_ORIGIN_NAME             3088
#define MQ_MQCACF_ENV_INFO                3089
#define MQ_MQCACF_SECURITY_PROFILE        3090
#define MQ_MQCACF_CONFIGURATION_DATE      3091
#define MQ_MQCACF_CONFIGURATION_TIME      3092
#define MQ_MQCACF_FROM_CF_STRUC_NAME      3093
#define MQ_MQCACF_TO_CF_STRUC_NAME        3094
#define MQ_MQCACF_CF_STRUC_NAMES          3095
#define MQ_MQCACF_FAIL_DATE               3096
#define MQ_MQCACF_FAIL_TIME               3097
#define MQ_MQCACF_BACKUP_DATE             3098
#define MQ_MQCACF_BACKUP_TIME             3099
#define MQ_MQCACF_SYSTEM_NAME             3100
#define MQ_MQCACF_CF_STRUC_BACKUP_START   3101
#define MQ_MQCACF_CF_STRUC_BACKUP_END     3102
#define MQ_MQCACF_CF_STRUC_LOG_Q_MGRS     3103
#define MQ_MQCACF_FROM_STORAGE_CLASS      3104
#define MQ_MQCACF_TO_STORAGE_CLASS        3105
#define MQ_MQCACF_STORAGE_CLASS_NAMES     3106
#define MQ_MQCACF_DSG_NAME                3108
#define MQ_MQCACF_DB2_NAME                3109
#define MQ_MQCACF_SYSP_CMD_USER_ID        3110
#define MQ_MQCACF_SYSP_OTMA_GROUP         3111
#define MQ_MQCACF_SYSP_OTMA_MEMBER        3112
#define MQ_MQCACF_SYSP_OTMA_DRU_EXIT      3113
#define MQ_MQCACF_SYSP_OTMA_TPIPE_PFX     3114
#define MQ_MQCACF_SYSP_ARCHIVE_PFX1       3115
#define MQ_MQCACF_SYSP_ARCHIVE_UNIT1      3116
#define MQ_MQCACF_SYSP_LOG_CORREL_ID      3117
#define MQ_MQCACF_SYSP_UNIT_VOLSER        3118
#define MQ_MQCACF_SYSP_Q_MGR_TIME         3119
#define MQ_MQCACF_SYSP_Q_MGR_DATE         3120
#define MQ_MQCACF_SYSP_Q_MGR_RBA          3121
#define MQ_MQCACF_SYSP_LOG_RBA            3122
#define MQ_MQCACF_SYSP_SERVICE            3123
#define MQ_MQCACF_FROM_LISTENER_NAME      3124
#define MQ_MQCACF_TO_LISTENER_NAME        3125
#define MQ_MQCACF_FROM_SERVICE_NAME       3126
#define MQ_MQCACF_TO_SERVICE_NAME         3127
#define MQ_MQCACF_LAST_PUT_DATE           3128
#define MQ_MQCACF_LAST_PUT_TIME           3129
#define MQ_MQCACF_LAST_GET_DATE           3130
#define MQ_MQCACF_LAST_GET_TIME           3131
#define MQ_MQCACF_OPERATION_DATE          3132
#define MQ_MQCACF_OPERATION_TIME          3133
#define MQ_MQCACF_ACTIVITY_DESC           3134
#define MQ_MQCACF_APPL_IDENTITY_DATA      3135
#define MQ_MQCACF_APPL_ORIGIN_DATA        3136
#define MQ_MQCACF_PUT_DATE                3137
#define MQ_MQCACF_PUT_TIME                3138
#define MQ_MQCACF_REPLY_TO_Q              3139
#define MQ_MQCACF_REPLY_TO_Q_MGR          3140
#define MQ_MQCACF_RESOLVED_Q_NAME         3141
#define MQ_MQCACF_STRUC_ID                3142
#define MQ_MQCACF_VALUE_NAME              3143
#define MQ_MQCACF_SERVICE_START_DATE      3144
#define MQ_MQCACF_SERVICE_START_TIME      3145
#define MQ_MQCACF_SYSP_OFFLINE_RBA        3146
#define MQ_MQCACF_SYSP_ARCHIVE_PFX2       3147
#define MQ_MQCACF_SYSP_ARCHIVE_UNIT2      3148
#define MQ_MQCACF_TO_TOPIC_NAME           3149
#define MQ_MQCACF_FROM_TOPIC_NAME         3150
#define MQ_MQCACF_TOPIC_NAMES             3151
#define MQ_MQCACF_SUB_NAME                3152
#define MQ_MQCACF_DESTINATION_Q_MGR       3153
#define MQ_MQCACF_DESTINATION             3154
#define MQ_MQCACF_SUB_USER_ID             3156
#define MQ_MQCACF_SUB_USER_DATA           3159
#define MQ_MQCACF_SUB_SELECTOR            3160
#define MQ_MQCACF_LAST_PUB_DATE           3161
#define MQ_MQCACF_LAST_PUB_TIME           3162
#define MQ_MQCACF_FROM_SUB_NAME           3163
#define MQ_MQCACF_TO_SUB_NAME             3164
#define MQ_MQCACF_LAST_MSG_TIME           3167
#define MQ_MQCACF_LAST_MSG_DATE           3168
#define MQ_MQCACF_SUBSCRIPTION_POINT      3169
#define MQ_MQCACF_FILTER                  3170
#define MQ_MQCACF_NONE                    3171
#define MQ_MQCACF_ADMIN_TOPIC_NAMES       3172
#define MQ_MQCACF_ROUTING_FINGER_PRINT    3173
#define MQ_MQCACF_APPL_DESC               3174
#define MQ_MQCACF_Q_MGR_START_DATE        3175
#define MQ_MQCACF_Q_MGR_START_TIME        3176
#define MQ_MQCACF_FROM_COMM_INFO_NAME     3177
#define MQ_MQCACF_TO_COMM_INFO_NAME       3178
#define MQ_MQCACF_CF_OFFLOAD_SIZE1        3179
#define MQ_MQCACF_CF_OFFLOAD_SIZE2        3180
#define MQ_MQCACF_CF_OFFLOAD_SIZE3        3181
#define MQ_MQCACF_CF_SMDS_GENERIC_NAME    3182
#define MQ_MQCACF_CF_SMDS                 3183
#define MQ_MQCACF_RECOVERY_DATE           3184
#define MQ_MQCACF_RECOVERY_TIME           3185
#define MQ_MQCACF_CF_SMDSCONN             3186
#define MQ_MQCACF_CF_STRUC_NAME           3187
#define MQ_MQCACF_ALTERNATE_USERID        3188
#define MQ_MQCACF_CHAR_ATTRS              3189
#define MQ_MQCACF_DYNAMIC_Q_NAME          3190
#define MQ_MQCACF_HOST_NAME               3191
#define MQ_MQCACF_MQCB_NAME               3192
#define MQ_MQCACF_OBJECT_STRING           3193
#define MQ_MQCACF_RESOLVED_LOCAL_Q_MGR    3194
#define MQ_MQCACF_RESOLVED_LOCAL_Q_NAME   3195
#define MQ_MQCACF_RESOLVED_OBJECT_STRING  3196
#define MQ_MQCACF_RESOLVED_Q_MGR          3197
#define MQ_MQCACF_SELECTION_STRING        3198
#define MQ_MQCACF_XA_INFO                 3199
#define MQ_MQCACF_APPL_FUNCTION           3200
#define MQ_MQCACF_XQH_REMOTE_Q_NAME       3201
#define MQ_MQCACF_XQH_REMOTE_Q_MGR        3202
#define MQ_MQCACF_XQH_PUT_TIME            3203
#define MQ_MQCACF_XQH_PUT_DATE            3204
#define MQ_MQCACF_EXCL_OPERATOR_MESSAGES  3205
#define MQ_MQCACF_CSP_USER_IDENTIFIER     3206
#define MQ_MQCACF_AMQP_CLIENT_ID          3207
#define MQ_MQCACF_LAST_USED               3207

/* Character Channel Parameter Types */
#define MQ_MQCACH_FIRST                   3501
#define MQ_MQCACH_CHANNEL_NAME            3501
#define MQ_MQCACH_DESC                    3502
#define MQ_MQCACH_MODE_NAME               3503
#define MQ_MQCACH_TP_NAME                 3504
#define MQ_MQCACH_XMIT_Q_NAME             3505
#define MQ_MQCACH_CONNECTION_NAME         3506
#define MQ_MQCACH_MCA_NAME                3507
#define MQ_MQCACH_SEC_EXIT_NAME           3508
#define MQ_MQCACH_MSG_EXIT_NAME           3509
#define MQ_MQCACH_SEND_EXIT_NAME          3510
#define MQ_MQCACH_RCV_EXIT_NAME           3511
#define MQ_MQCACH_CHANNEL_NAMES           3512
#define MQ_MQCACH_SEC_EXIT_USER_DATA      3513
#define MQ_MQCACH_MSG_EXIT_USER_DATA      3514
#define MQ_MQCACH_SEND_EXIT_USER_DATA     3515
#define MQ_MQCACH_RCV_EXIT_USER_DATA      3516
#define MQ_MQCACH_USER_ID                 3517
#define MQ_MQCACH_PASSWORD                3518
#define MQ_MQCACH_LOCAL_ADDRESS           3520
#define MQ_MQCACH_LOCAL_NAME              3521
#define MQ_MQCACH_LAST_MSG_TIME           3524
#define MQ_MQCACH_LAST_MSG_DATE           3525
#define MQ_MQCACH_MCA_USER_ID             3527
#define MQ_MQCACH_CHANNEL_START_TIME      3528
#define MQ_MQCACH_CHANNEL_START_DATE      3529
#define MQ_MQCACH_MCA_JOB_NAME            3530
#define MQ_MQCACH_LAST_LUWID              3531
#define MQ_MQCACH_CURRENT_LUWID           3532
#define MQ_MQCACH_FORMAT_NAME             3533
#define MQ_MQCACH_MR_EXIT_NAME            3534
#define MQ_MQCACH_MR_EXIT_USER_DATA       3535
#define MQ_MQCACH_SSL_CIPHER_SPEC         3544
#define MQ_MQCACH_SSL_PEER_NAME           3545
#define MQ_MQCACH_SSL_HANDSHAKE_STAGE     3546
#define MQ_MQCACH_SSL_SHORT_PEER_NAME     3547
#define MQ_MQCACH_REMOTE_APPL_TAG         3548
#define MQ_MQCACH_SSL_CERT_USER_ID        3549
#define MQ_MQCACH_SSL_CERT_ISSUER_NAME    3550
#define MQ_MQCACH_LU_NAME                 3551
#define MQ_MQCACH_IP_ADDRESS              3552
#define MQ_MQCACH_TCP_NAME                3553
#define MQ_MQCACH_LISTENER_NAME           3554
#define MQ_MQCACH_LISTENER_DESC           3555
#define MQ_MQCACH_LISTENER_START_DATE     3556
#define MQ_MQCACH_LISTENER_START_TIME     3557
#define MQ_MQCACH_SSL_KEY_RESET_DATE      3558
#define MQ_MQCACH_SSL_KEY_RESET_TIME      3559
#define MQ_MQCACH_REMOTE_VERSION          3560
#define MQ_MQCACH_REMOTE_PRODUCT          3561
#define MQ_MQCACH_GROUP_ADDRESS           3562
#define MQ_MQCACH_JAAS_CONFIG             3563
#define MQ_MQCACH_CLIENT_ID               3564
#define MQ_MQCACH_SSL_KEY_PASSPHRASE      3565
#define MQ_MQCACH_CONNECTION_NAME_LIST    3566
#define MQ_MQCACH_CLIENT_USER_ID          3567
#define MQ_MQCACH_MCA_USER_ID_LIST        3568
#define MQ_MQCACH_SSL_CIPHER_SUITE        3569
#define MQ_MQCACH_WEBCONTENT_PATH         3570
#define MQ_MQCACH_LAST_USED               3570

/****************************************************************/
/* Values Related to Group Parameter Structures                 */
/****************************************************************/

/* Group Parameter Types */
#define MQ_MQGACF_FIRST                   8001
#define MQ_MQGACF_COMMAND_CONTEXT         8001
#define MQ_MQGACF_COMMAND_DATA            8002
#define MQ_MQGACF_TRACE_ROUTE             8003
#define MQ_MQGACF_OPERATION               8004
#define MQ_MQGACF_ACTIVITY                8005
#define MQ_MQGACF_EMBEDDED_MQMD           8006
#define MQ_MQGACF_MESSAGE                 8007
#define MQ_MQGACF_MQMD                    8008
#define MQ_MQGACF_VALUE_NAMING            8009
#define MQ_MQGACF_Q_ACCOUNTING_DATA       8010
#define MQ_MQGACF_Q_STATISTICS_DATA       8011
#define MQ_MQGACF_CHL_STATISTICS_DATA     8012
#define MQ_MQGACF_ACTIVITY_TRACE          8013
#define MQ_MQGACF_APP_DIST_LIST           8014
#define MQ_MQGACF_MONITOR_CLASS           8015
#define MQ_MQGACF_MONITOR_TYPE            8016
#define MQ_MQGACF_MONITOR_ELEMENT         8017
#define MQ_MQGACF_LAST_USED               8017


/****************************************************************/
/* Parameter Values                                             */
/****************************************************************/

/* Action Options */
#define MQ_MQACT_FORCE_REMOVE             1
#define MQ_MQACT_ADVANCE_LOG              2
#define MQ_MQACT_COLLECT_STATISTICS       3
#define MQ_MQACT_PUBSUB                   4
#define MQ_MQACT_ADD                      5
#define MQ_MQACT_REPLACE                  6
#define MQ_MQACT_REMOVE                   7
#define MQ_MQACT_REMOVEALL                8
#define MQ_MQACT_FAIL                     9

/* Asynchronous State Values */
#define MQ_MQAS_NONE                      0
#define MQ_MQAS_STARTED                   1
#define MQ_MQAS_START_WAIT                2
#define MQ_MQAS_STOPPED                   3
#define MQ_MQAS_SUSPENDED                 4
#define MQ_MQAS_SUSPENDED_TEMPORARY       5
#define MQ_MQAS_ACTIVE                    6
#define MQ_MQAS_INACTIVE                  7

/* Authority Values */
#define MQ_MQAUTH_NONE                    0
#define MQ_MQAUTH_ALT_USER_AUTHORITY      1
#define MQ_MQAUTH_BROWSE                  2
#define MQ_MQAUTH_CHANGE                  3
#define MQ_MQAUTH_CLEAR                   4
#define MQ_MQAUTH_CONNECT                 5
#define MQ_MQAUTH_CREATE                  6
#define MQ_MQAUTH_DELETE                  7
#define MQ_MQAUTH_DISPLAY                 8
#define MQ_MQAUTH_INPUT                   9
#define MQ_MQAUTH_INQUIRE                 10
#define MQ_MQAUTH_OUTPUT                  11
#define MQ_MQAUTH_PASS_ALL_CONTEXT        12
#define MQ_MQAUTH_PASS_IDENTITY_CONTEXT   13
#define MQ_MQAUTH_SET                     14
#define MQ_MQAUTH_SET_ALL_CONTEXT         15
#define MQ_MQAUTH_SET_IDENTITY_CONTEXT    16
#define MQ_MQAUTH_CONTROL                 17
#define MQ_MQAUTH_CONTROL_EXTENDED        18
#define MQ_MQAUTH_PUBLISH                 19
#define MQ_MQAUTH_SUBSCRIBE               20
#define MQ_MQAUTH_RESUME                  21
#define MQ_MQAUTH_SYSTEM                  22
#define MQ_MQAUTH_ALL                     (-1)
#define MQ_MQAUTH_ALL_ADMIN               (-2)
#define MQ_MQAUTH_ALL_MQI                 (-3)

/* Authority Options */
#define MQ_MQAUTHOPT_ENTITY_EXPLICIT      0x00000001
#define MQ_MQAUTHOPT_ENTITY_SET           0x00000002
#define MQ_MQAUTHOPT_NAME_EXPLICIT        0x00000010
#define MQ_MQAUTHOPT_NAME_ALL_MATCHING    0x00000020
#define MQ_MQAUTHOPT_NAME_AS_WILDCARD     0x00000040
#define MQ_MQAUTHOPT_CUMULATIVE           0x00000100
#define MQ_MQAUTHOPT_EXCLUDE_TEMP         0x00000200

/* Bridge Types */
#define MQ_MQBT_OTMA                      1

/* Refresh Repository Options */
#define MQ_MQCFO_REFRESH_REPOSITORY_YES   1
#define MQ_MQCFO_REFRESH_REPOSITORY_NO    0

/* Remove Queues Options */
#define MQ_MQCFO_REMOVE_QUEUES_YES        1
#define MQ_MQCFO_REMOVE_QUEUES_NO         0

/* CHLAUTH Type */
#define MQ_MQCAUT_ALL                     0
#define MQ_MQCAUT_BLOCKUSER               1
#define MQ_MQCAUT_BLOCKADDR               2
#define MQ_MQCAUT_SSLPEERMAP              3
#define MQ_MQCAUT_ADDRESSMAP              4
#define MQ_MQCAUT_USERMAP                 5
#define MQ_MQCAUT_QMGRMAP                 6

/* CF Status */
#define MQ_MQCFSTATUS_NOT_FOUND           0
#define MQ_MQCFSTATUS_ACTIVE              1
#define MQ_MQCFSTATUS_IN_RECOVER          2
#define MQ_MQCFSTATUS_IN_BACKUP           3
#define MQ_MQCFSTATUS_FAILED              4
#define MQ_MQCFSTATUS_NONE                5
#define MQ_MQCFSTATUS_UNKNOWN             6
#define MQ_MQCFSTATUS_RECOVERED           7
#define MQ_MQCFSTATUS_EMPTY               8
#define MQ_MQCFSTATUS_NEW                 9
#define MQ_MQCFSTATUS_ADMIN_INCOMPLETE    20
#define MQ_MQCFSTATUS_NEVER_USED          21
#define MQ_MQCFSTATUS_NO_BACKUP           22
#define MQ_MQCFSTATUS_NOT_FAILED          23
#define MQ_MQCFSTATUS_NOT_RECOVERABLE     24
#define MQ_MQCFSTATUS_XES_ERROR           25

/* CF Types */
#define MQ_MQCFTYPE_APPL                  0
#define MQ_MQCFTYPE_ADMIN                 1

/* Indoubt Status */
#define MQ_MQCHIDS_NOT_INDOUBT            0
#define MQ_MQCHIDS_INDOUBT                1

/* Channel Dispositions */
#define MQ_MQCHLD_ALL                     (-1)
#define MQ_MQCHLD_DEFAULT                 1
#define MQ_MQCHLD_SHARED                  2
#define MQ_MQCHLD_PRIVATE                 4
#define MQ_MQCHLD_FIXSHARED               5

/* Use ClientID */
#define MQ_MQUCI_YES                      1
#define MQ_MQUCI_NO                       0

/* Channel Status */
#define MQ_MQCHS_INACTIVE                 0
#define MQ_MQCHS_BINDING                  1
#define MQ_MQCHS_STARTING                 2
#define MQ_MQCHS_RUNNING                  3
#define MQ_MQCHS_STOPPING                 4
#define MQ_MQCHS_RETRYING                 5
#define MQ_MQCHS_STOPPED                  6
#define MQ_MQCHS_REQUESTING               7
#define MQ_MQCHS_PAUSED                   8
#define MQ_MQCHS_DISCONNECTED             9
#define MQ_MQCHS_INITIALIZING             13
#define MQ_MQCHS_SWITCHING                14

/* Channel Substates */
#define MQ_MQCHSSTATE_OTHER               0
#define MQ_MQCHSSTATE_END_OF_BATCH        100
#define MQ_MQCHSSTATE_SENDING             200
#define MQ_MQCHSSTATE_RECEIVING           300
#define MQ_MQCHSSTATE_SERIALIZING         400
#define MQ_MQCHSSTATE_RESYNCHING          500
#define MQ_MQCHSSTATE_HEARTBEATING        600
#define MQ_MQCHSSTATE_IN_SCYEXIT          700
#define MQ_MQCHSSTATE_IN_RCVEXIT          800
#define MQ_MQCHSSTATE_IN_SENDEXIT         900
#define MQ_MQCHSSTATE_IN_MSGEXIT          1000
#define MQ_MQCHSSTATE_IN_MREXIT           1100
#define MQ_MQCHSSTATE_IN_CHADEXIT         1200
#define MQ_MQCHSSTATE_NET_CONNECTING      1250
#define MQ_MQCHSSTATE_SSL_HANDSHAKING     1300
#define MQ_MQCHSSTATE_NAME_SERVER         1400
#define MQ_MQCHSSTATE_IN_MQPUT            1500
#define MQ_MQCHSSTATE_IN_MQGET            1600
#define MQ_MQCHSSTATE_IN_MQI_CALL         1700
#define MQ_MQCHSSTATE_COMPRESSING         1800

/* Channel Shared Restart Options */
#define MQ_MQCHSH_RESTART_NO              0
#define MQ_MQCHSH_RESTART_YES             1

/* Channel Stop Options */
#define MQ_MQCHSR_STOP_NOT_REQUESTED      0
#define MQ_MQCHSR_STOP_REQUESTED          1

/* Channel reset requested */
#define MQ_MQCHRR_RESET_NOT_REQUESTED     0

/* Channel Table Types */
#define MQ_MQCHTAB_Q_MGR                  1
#define MQ_MQCHTAB_CLNTCONN               2

/* Clear Topic String Scope */
#define MQ_MQCLRS_LOCAL                   1
#define MQ_MQCLRS_GLOBAL                  2

/* Clear Topic String Type */
#define MQ_MQCLRT_RETAINED                1

/* Command Information Values */
#define MQ_MQCMDI_CMDSCOPE_ACCEPTED       1
#define MQ_MQCMDI_CMDSCOPE_GENERATED      2
#define MQ_MQCMDI_CMDSCOPE_COMPLETED      3
#define MQ_MQCMDI_QSG_DISP_COMPLETED      4
#define MQ_MQCMDI_COMMAND_ACCEPTED        5
#define MQ_MQCMDI_CLUSTER_REQUEST_QUEUED  6
#define MQ_MQCMDI_CHANNEL_INIT_STARTED    7
#define MQ_MQCMDI_RECOVER_STARTED         11
#define MQ_MQCMDI_BACKUP_STARTED          12
#define MQ_MQCMDI_RECOVER_COMPLETED       13
#define MQ_MQCMDI_SEC_TIMER_ZERO          14
#define MQ_MQCMDI_REFRESH_CONFIGURATION   16
#define MQ_MQCMDI_SEC_SIGNOFF_ERROR       17
#define MQ_MQCMDI_IMS_BRIDGE_SUSPENDED    18
#define MQ_MQCMDI_DB2_SUSPENDED           19
#define MQ_MQCMDI_DB2_OBSOLETE_MSGS       20
#define MQ_MQCMDI_SEC_UPPERCASE           21
#define MQ_MQCMDI_SEC_MIXEDCASE           22

/* Disconnect Types */
#define MQ_MQDISCONNECT_NORMAL            0
#define MQ_MQDISCONNECT_IMPLICIT          1
#define MQ_MQDISCONNECT_Q_MGR             2

/* Escape Types */
#define MQ_MQET_MQSC                      1

/* Event Origins */
#define MQ_MQEVO_OTHER                    0
#define MQ_MQEVO_CONSOLE                  1
#define MQ_MQEVO_INIT                     2
#define MQ_MQEVO_MSG                      3
#define MQ_MQEVO_MQSET                    4
#define MQ_MQEVO_INTERNAL                 5
#define MQ_MQEVO_MQSUB                    6
#define MQ_MQEVO_CTLMSG                   7

/* Event Recording */
#define MQ_MQEVR_DISABLED                 0
#define MQ_MQEVR_ENABLED                  1
#define MQ_MQEVR_EXCEPTION                2
#define MQ_MQEVR_NO_DISPLAY               3
#define MQ_MQEVR_API_ONLY                 4
#define MQ_MQEVR_ADMIN_ONLY               5
#define MQ_MQEVR_USER_ONLY                6

/* Force Options */
#define MQ_MQFC_YES                       1
#define MQ_MQFC_NO                        0

/* Handle States */
#define MQ_MQHSTATE_INACTIVE              0
#define MQ_MQHSTATE_ACTIVE                1

/* Inbound Dispositions */
#define MQ_MQINBD_Q_MGR                   0
#define MQ_MQINBD_GROUP                   3

/* Indoubt Options */
#define MQ_MQIDO_COMMIT                   1
#define MQ_MQIDO_BACKOUT                  2

/* Match Types */
#define MQ_MQMATCH_GENERIC                0
#define MQ_MQMATCH_RUNCHECK               1
#define MQ_MQMATCH_EXACT                  2
#define MQ_MQMATCH_ALL                    3

/* Message Channel Agent Status */
#define MQ_MQMCAS_STOPPED                 0
#define MQ_MQMCAS_RUNNING                 3

/* Mode Options */
#define MQ_MQMODE_FORCE                   0
#define MQ_MQMODE_QUIESCE                 1
#define MQ_MQMODE_TERMINATE               2

/* Message Level Protection */
#define MQ_MQMLP_TOLERATE_UNPROTECTED_NO  0
#define MQ_MQMLP_TOLERATE_UNPROTECTED_YES 1
#define MQ_MQMLP_ENCRYPTION_ALG_NONE      0
#define MQ_MQMLP_ENCRYPTION_ALG_RC2       1
#define MQ_MQMLP_ENCRYPTION_ALG_DES       2
#define MQ_MQMLP_ENCRYPTION_ALG_3DES      3
#define MQ_MQMLP_ENCRYPTION_ALG_AES128    4
#define MQ_MQMLP_ENCRYPTION_ALG_AES256    5
#define MQ_MQMLP_SIGN_ALG_NONE            0
#define MQ_MQMLP_SIGN_ALG_MD5             1
#define MQ_MQMLP_SIGN_ALG_SHA1            2
#define MQ_MQMLP_SIGN_ALG_SHA224          3
#define MQ_MQMLP_SIGN_ALG_SHA256          4
#define MQ_MQMLP_SIGN_ALG_SHA384          5
#define MQ_MQMLP_SIGN_ALG_SHA512          6

/* Purge Options */
#define MQ_MQPO_YES                       1
#define MQ_MQPO_NO                        0

/* Pub/Sub Status Type */
#define MQ_MQPSST_ALL                     0
#define MQ_MQPSST_LOCAL                   1
#define MQ_MQPSST_PARENT                  2
#define MQ_MQPSST_CHILD                   3

/* Pub/Sub Status */
#define MQ_MQPS_STATUS_INACTIVE           0
#define MQ_MQPS_STATUS_STARTING           1
#define MQ_MQPS_STATUS_STOPPING           2
#define MQ_MQPS_STATUS_ACTIVE             3
#define MQ_MQPS_STATUS_COMPAT             4
#define MQ_MQPS_STATUS_ERROR              5
#define MQ_MQPS_STATUS_REFUSED            6

/* Queue Manager Definition Types */
#define MQ_MQQMDT_EXPLICIT_CLUSTER_SENDER 1
#define MQ_MQQMDT_AUTO_CLUSTER_SENDER     2
#define MQ_MQQMDT_AUTO_EXP_CLUSTER_SENDER 4
#define MQ_MQQMDT_CLUSTER_RECEIVER        3

/* Queue Manager Facility */
#define MQ_MQQMFAC_IMS_BRIDGE             1
#define MQ_MQQMFAC_DB2                    2

/* Queue Manager Status */
#define MQ_MQQMSTA_STARTING               1
#define MQ_MQQMSTA_RUNNING                2
#define MQ_MQQMSTA_QUIESCING              3
#define MQ_MQQMSTA_STANDBY                4

/* Queue Manager Types */
#define MQ_MQQMT_NORMAL                   0
#define MQ_MQQMT_REPOSITORY               1

/* Quiesce Options */
#define MQ_MQQO_YES                       1
#define MQ_MQQO_NO                        0

/* Queue Service-Interval Events */
#define MQ_MQQSIE_NONE                    0
#define MQ_MQQSIE_HIGH                    1
#define MQ_MQQSIE_OK                      2

/* Queue Status Open Types */
#define MQ_MQQSOT_ALL                     1
#define MQ_MQQSOT_INPUT                   2
#define MQ_MQQSOT_OUTPUT                  3

/* QSG Status */
#define MQ_MQQSGS_UNKNOWN                 0
#define MQ_MQQSGS_CREATED                 1
#define MQ_MQQSGS_ACTIVE                  2
#define MQ_MQQSGS_INACTIVE                3
#define MQ_MQQSGS_FAILED                  4
#define MQ_MQQSGS_PENDING                 5

/* Queue Status Open Options for SET, BROWSE, INPUT */
#define MQ_MQQSO_NO                       0
#define MQ_MQQSO_YES                      1
#define MQ_MQQSO_SHARED                   1
#define MQ_MQQSO_EXCLUSIVE                2

/* Queue Status Uncommitted Messages */
#define MQ_MQQSUM_YES                     1
#define MQ_MQQSUM_NO                      0

/* Remove Authority Record Options */
#define MQ_MQRAR_YES                      1
#define MQ_MQRAR_NO                       0

/* Replace Options */
#define MQ_MQRP_YES                       1
#define MQ_MQRP_NO                        0

/* Reason Qualifiers */
#define MQ_MQRQ_CONN_NOT_AUTHORIZED       1
#define MQ_MQRQ_OPEN_NOT_AUTHORIZED       2
#define MQ_MQRQ_CLOSE_NOT_AUTHORIZED      3
#define MQ_MQRQ_CMD_NOT_AUTHORIZED        4
#define MQ_MQRQ_Q_MGR_STOPPING            5
#define MQ_MQRQ_Q_MGR_QUIESCING           6
#define MQ_MQRQ_CHANNEL_STOPPED_OK        7
#define MQ_MQRQ_CHANNEL_STOPPED_ERROR     8
#define MQ_MQRQ_CHANNEL_STOPPED_RETRY     9
#define MQ_MQRQ_CHANNEL_STOPPED_DISABLED  10
#define MQ_MQRQ_BRIDGE_STOPPED_OK         11
#define MQ_MQRQ_BRIDGE_STOPPED_ERROR      12
#define MQ_MQRQ_SSL_HANDSHAKE_ERROR       13
#define MQ_MQRQ_SSL_CIPHER_SPEC_ERROR     14
#define MQ_MQRQ_SSL_CLIENT_AUTH_ERROR     15
#define MQ_MQRQ_SSL_PEER_NAME_ERROR       16
#define MQ_MQRQ_SUB_NOT_AUTHORIZED        17
#define MQ_MQRQ_SUB_DEST_NOT_AUTHORIZED   18
#define MQ_MQRQ_SSL_UNKNOWN_REVOCATION    19
#define MQ_MQRQ_SYS_CONN_NOT_AUTHORIZED   20
#define MQ_MQRQ_CHANNEL_BLOCKED_ADDRESS   21
#define MQ_MQRQ_CHANNEL_BLOCKED_USERID    22
#define MQ_MQRQ_CHANNEL_BLOCKED_NOACCESS  23
#define MQ_MQRQ_MAX_ACTIVE_CHANNELS       24
#define MQ_MQRQ_MAX_CHANNELS              25
#define MQ_MQRQ_SVRCONN_INST_LIMIT        26
#define MQ_MQRQ_CLIENT_INST_LIMIT         27
#define MQ_MQRQ_CAF_NOT_INSTALLED         28
#define MQ_MQRQ_CSP_NOT_AUTHORIZED        29
#define MQ_MQRQ_FAILOVER_PERMITTED        30
#define MQ_MQRQ_FAILOVER_NOT_PERMITTED    31
#define MQ_MQRQ_STANDBY_ACTIVATED         32

/* Refresh Types */
#define MQ_MQRT_CONFIGURATION             1
#define MQ_MQRT_EXPIRY                    2
#define MQ_MQRT_NSPROC                    3
#define MQ_MQRT_PROXYSUB                  4
#define MQ_MQRT_SUB_CONFIGURATION         5

/* Queue Definition Scope */
#define MQ_MQSCO_Q_MGR                    1
#define MQ_MQSCO_CELL                     2

/* Security Items */
#define MQ_MQSECITEM_ALL                  0
#define MQ_MQSECITEM_MQADMIN              1
#define MQ_MQSECITEM_MQNLIST              2
#define MQ_MQSECITEM_MQPROC               3
#define MQ_MQSECITEM_MQQUEUE              4
#define MQ_MQSECITEM_MQCONN               5
#define MQ_MQSECITEM_MQCMDS               6
#define MQ_MQSECITEM_MXADMIN              7
#define MQ_MQSECITEM_MXNLIST              8
#define MQ_MQSECITEM_MXPROC               9
#define MQ_MQSECITEM_MXQUEUE              10
#define MQ_MQSECITEM_MXTOPIC              11

/* Security Switches */
#define MQ_MQSECSW_PROCESS                1
#define MQ_MQSECSW_NAMELIST               2
#define MQ_MQSECSW_Q                      3
#define MQ_MQSECSW_TOPIC                  4
#define MQ_MQSECSW_CONTEXT                6
#define MQ_MQSECSW_ALTERNATE_USER         7
#define MQ_MQSECSW_COMMAND                8
#define MQ_MQSECSW_CONNECTION             9
#define MQ_MQSECSW_SUBSYSTEM              10
#define MQ_MQSECSW_COMMAND_RESOURCES      11
#define MQ_MQSECSW_Q_MGR                  15
#define MQ_MQSECSW_QSG                    16

/* Security Switch States */
#define MQ_MQSECSW_OFF_FOUND              21
#define MQ_MQSECSW_ON_FOUND               22
#define MQ_MQSECSW_OFF_NOT_FOUND          23
#define MQ_MQSECSW_ON_NOT_FOUND           24
#define MQ_MQSECSW_OFF_ERROR              25
#define MQ_MQSECSW_ON_OVERRIDDEN          26

/* Security Types */
#define MQ_MQSECTYPE_AUTHSERV             1
#define MQ_MQSECTYPE_SSL                  2
#define MQ_MQSECTYPE_CLASSES              3
#define MQ_MQSECTYPE_CONNAUTH             4

/* Authentication Validation Types */
#define MQ_MQCHK_OPTIONAL                 0
#define MQ_MQCHK_NONE                     1
#define MQ_MQCHK_REQUIRED_ADMIN           2
#define MQ_MQCHK_REQUIRED                 3
#define MQ_MQCHK_AS_Q_MGR                 4

/* Authentication Adoption Context */
#define MQ_MQADPCTX_NO                    0
#define MQ_MQADPCTX_YES                   1

/* LDAP SSL/TLS Connection State */
#define MQ_MQSECCOMM_NO                   0
#define MQ_MQSECCOMM_YES                  1
#define MQ_MQSECCOMM_ANON                 2

/* LDAP Authorisation Method */
#define MQ_MQLDAP_AUTHORMD_OS             0
#define MQ_MQLDAP_AUTHORMD_SEARCHGRP      1
#define MQ_MQLDAP_AUTHORMD_SEARCHUSR      2

/* LDAP Nested Group Policy */
#define MQ_MQLDAP_NESTGRP_NO              0
#define MQ_MQLDAP_NESTGRP_YES             1

/* Authentication Method */
#define MQ_MQAUTHENTICATE_OS              0
#define MQ_MQAUTHENTICATE_PAM             1

/* QMgr LDAP Connection Status */
#define MQ_MQLDAPC_INACTIVE               0
#define MQ_MQLDAPC_CONNECTED              1
#define MQ_MQLDAPC_ERROR                  2

/* Selector types */
#define MQ_MQSELTYPE_NONE                 0
#define MQ_MQSELTYPE_STANDARD             1
#define MQ_MQSELTYPE_EXTENDED             2

/* CHLAUTH QMGR State */
#define MQ_MQCHLA_DISABLED                0
#define MQ_MQCHLA_ENABLED                 1

/* Transmission queue types */
#define MQ_MQCLXQ_SCTQ                    0
#define MQ_MQCLXQ_CHANNEL                 1

/* Suspend Status */
#define MQ_MQSUS_YES                      1
#define MQ_MQSUS_NO                       0

/* Syncpoint values for Pub/Sub migration */
#define MQ_MQSYNCPOINT_YES                0
#define MQ_MQSYNCPOINT_IFPER              1

/* System Parameter Values */
#define MQ_MQSYSP_NO                      0
#define MQ_MQSYSP_YES                     1
#define MQ_MQSYSP_EXTENDED                2
#define MQ_MQSYSP_TYPE_INITIAL            10
#define MQ_MQSYSP_TYPE_SET                11
#define MQ_MQSYSP_TYPE_LOG_COPY           12
#define MQ_MQSYSP_TYPE_LOG_STATUS         13
#define MQ_MQSYSP_TYPE_ARCHIVE_TAPE       14
#define MQ_MQSYSP_ALLOC_BLK               20
#define MQ_MQSYSP_ALLOC_TRK               21
#define MQ_MQSYSP_ALLOC_CYL               22
#define MQ_MQSYSP_STATUS_BUSY             30
#define MQ_MQSYSP_STATUS_PREMOUNT         31
#define MQ_MQSYSP_STATUS_AVAILABLE        32
#define MQ_MQSYSP_STATUS_UNKNOWN          33
#define MQ_MQSYSP_STATUS_ALLOC_ARCHIVE    34
#define MQ_MQSYSP_STATUS_COPYING_BSDS     35
#define MQ_MQSYSP_STATUS_COPYING_LOG      36

/* Export Type */
#define MQ_MQEXT_ALL                      0
#define MQ_MQEXT_OBJECT                   1
#define MQ_MQEXT_AUTHORITY                2

/* Export Attrs */
#define MQ_MQEXTATTRS_ALL                 0
#define MQ_MQEXTATTRS_NONDEF              1

/* System Objects */
#define MQ_MQSYSOBJ_YES                   0
#define MQ_MQSYSOBJ_NO                    1

/* Subscription Types */
#define MQ_MQSUBTYPE_API                  1
#define MQ_MQSUBTYPE_ADMIN                2
#define MQ_MQSUBTYPE_PROXY                3
#define MQ_MQSUBTYPE_ALL                  (-1)
#define MQ_MQSUBTYPE_USER                 (-2)

/* Time units */
#define MQ_MQTIME_UNIT_MINS               0
#define MQ_MQTIME_UNIT_SECS               1

/* User ID Support */
#define MQ_MQUIDSUPP_NO                   0
#define MQ_MQUIDSUPP_YES                  1

/* Undelivered values for Pub/Sub migration */
#define MQ_MQUNDELIVERED_NORMAL           0
#define MQ_MQUNDELIVERED_SAFE             1
#define MQ_MQUNDELIVERED_DISCARD          2
#define MQ_MQUNDELIVERED_KEEP             3

/* UOW States */
#define MQ_MQUOWST_NONE                   0
#define MQ_MQUOWST_ACTIVE                 1
#define MQ_MQUOWST_PREPARED               2
#define MQ_MQUOWST_UNRESOLVED             3

/* UOW Types */
#define MQ_MQUOWT_Q_MGR                   0
#define MQ_MQUOWT_CICS                    1
#define MQ_MQUOWT_RRS                     2
#define MQ_MQUOWT_IMS                     3
#define MQ_MQUOWT_XA                      4

/* Page Set Usage Values */
#define MQ_MQUSAGE_PS_AVAILABLE           0
#define MQ_MQUSAGE_PS_DEFINED             1
#define MQ_MQUSAGE_PS_OFFLINE             2
#define MQ_MQUSAGE_PS_NOT_DEFINED         3

/* Expand Usage Values */
#define MQ_MQUSAGE_EXPAND_USER            1
#define MQ_MQUSAGE_EXPAND_SYSTEM          2
#define MQ_MQUSAGE_EXPAND_NONE            3

/* Data Set Usage Values */
#define MQ_MQUSAGE_DS_OLDEST_ACTIVE_UOW   10
#define MQ_MQUSAGE_DS_OLDEST_PS_RECOVERY  11
#define MQ_MQUSAGE_DS_OLDEST_CF_RECOVERY  12

/* Multicast Properties Options */
#define MQ_MQMCP_REPLY                    2
#define MQ_MQMCP_USER                     1
#define MQ_MQMCP_NONE                     0
#define MQ_MQMCP_ALL                      (-1)
#define MQ_MQMCP_COMPAT                   (-2)

/* Multicast New Subscriber History Options */
#define MQ_MQNSH_NONE                     0
#define MQ_MQNSH_ALL                      (-1)

/* Activity Operations */
#define MQ_MQOPER_UNKNOWN                 0
#define MQ_MQOPER_BROWSE                  1
#define MQ_MQOPER_DISCARD                 2
#define MQ_MQOPER_GET                     3
#define MQ_MQOPER_PUT                     4
#define MQ_MQOPER_PUT_REPLY               5
#define MQ_MQOPER_PUT_REPORT              6
#define MQ_MQOPER_RECEIVE                 7
#define MQ_MQOPER_SEND                    8
#define MQ_MQOPER_TRANSFORM               9
#define MQ_MQOPER_PUBLISH                 10
#define MQ_MQOPER_EXCLUDED_PUBLISH        11
#define MQ_MQOPER_DISCARDED_PUBLISH       12

/* Trace-route Max Activities (MQIACF_MAX_ACTIVITIES) */
#define MQ_MQROUTE_UNLIMITED_ACTIVITIES   0

/* Trace-route Detail (MQIACF_ROUTE_DETAIL) */
#define MQ_MQROUTE_DETAIL_LOW             0x00000002
#define MQ_MQROUTE_DETAIL_MEDIUM          0x00000008
#define MQ_MQROUTE_DETAIL_HIGH            0x00000020

/* Trace-route Forwarding (MQIACF_ROUTE_FORWARDING) */
#define MQ_MQROUTE_FORWARD_ALL            0x00000100
#define MQ_MQROUTE_FORWARD_IF_SUPPORTED   0x00000200
#define MQ_MQROUTE_FORWARD_REJ_UNSUP_MASK 0xFFFF0000

/* Trace-route Delivery (MQIACF_ROUTE_DELIVERY) */
#define MQ_MQROUTE_DELIVER_YES            0x00001000
#define MQ_MQROUTE_DELIVER_NO             0x00002000
#define MQ_MQROUTE_DELIVER_REJ_UNSUP_MASK 0xFFFF0000

/* Trace-route Accumulation (MQIACF_ROUTE_ACCUMULATION) */
#define MQ_MQROUTE_ACCUMULATE_NONE        0x00010003
#define MQ_MQROUTE_ACCUMULATE_IN_MSG      0x00010004
#define MQ_MQROUTE_ACCUMULATE_AND_REPLY   0x00010005

/* Delete Options */
#define MQ_MQDELO_NONE                    0x00000000
#define MQ_MQDELO_LOCAL                   0x00000004

/* Publication Options */
#define MQ_MQPUBO_NONE                    0x00000000
#define MQ_MQPUBO_CORREL_ID_AS_IDENTITY   0x00000001
#define MQ_MQPUBO_RETAIN_PUBLICATION      0x00000002
#define MQ_MQPUBO_OTHER_SUBSCRIBERS_ONLY  0x00000004
#define MQ_MQPUBO_NO_REGISTRATION         0x00000008
#define MQ_MQPUBO_IS_RETAINED_PUBLICATION 0x00000010

/* Registration Options */
#define MQ_MQREGO_NONE                    0x00000000
#define MQ_MQREGO_CORREL_ID_AS_IDENTITY   0x00000001
#define MQ_MQREGO_ANONYMOUS               0x00000002
#define MQ_MQREGO_LOCAL                   0x00000004
#define MQ_MQREGO_DIRECT_REQUESTS         0x00000008
#define MQ_MQREGO_NEW_PUBLICATIONS_ONLY   0x00000010
#define MQ_MQREGO_PUBLISH_ON_REQUEST_ONLY 0x00000020
#define MQ_MQREGO_DEREGISTER_ALL          0x00000040
#define MQ_MQREGO_INCLUDE_STREAM_NAME     0x00000080
#define MQ_MQREGO_INFORM_IF_RETAINED      0x00000100
#define MQ_MQREGO_DUPLICATES_OK           0x00000200
#define MQ_MQREGO_NON_PERSISTENT          0x00000400
#define MQ_MQREGO_PERSISTENT              0x00000800
#define MQ_MQREGO_PERSISTENT_AS_PUBLISH   0x00001000
#define MQ_MQREGO_PERSISTENT_AS_Q         0x00002000
#define MQ_MQREGO_ADD_NAME                0x00004000
#define MQ_MQREGO_NO_ALTERATION           0x00008000
#define MQ_MQREGO_FULL_RESPONSE           0x00010000
#define MQ_MQREGO_JOIN_SHARED             0x00020000
#define MQ_MQREGO_JOIN_EXCLUSIVE          0x00040000
#define MQ_MQREGO_LEAVE_ONLY              0x00080000
#define MQ_MQREGO_VARIABLE_USER_ID        0x00100000
#define MQ_MQREGO_LOCKED                  0x00200000

/* Grouped Units of Recovery */
#define MQ_MQGUR_DISABLED                 0
#define MQ_MQGUR_ENABLED                  1

/* Measured usage by API */
#define MQ_MQMULC_STANDARD                0
#define MQ_MQMULC_REFINED                 1

/* Multi-instance Queue Managers */
#define MQ_MQSTDBY_NOT_PERMITTED          0
#define MQ_MQSTDBY_PERMITTED              1

/* Channel Types */
#define MQ_MQCHT_SENDER                   1
#define MQ_MQCHT_SERVER                   2
#define MQ_MQCHT_RECEIVER                 3
#define MQ_MQCHT_REQUESTER                4
#define MQ_MQCHT_ALL                      5
#define MQ_MQCHT_CLNTCONN                 6
#define MQ_MQCHT_SVRCONN                  7
#define MQ_MQCHT_CLUSRCVR                 8
#define MQ_MQCHT_CLUSSDR                  9
#define MQ_MQCHT_MQTT                     10

/* Channel Compression */
#define MQ_MQCOMPRESS_NOT_AVAILABLE       (-1)
#define MQ_MQCOMPRESS_NONE                0
#define MQ_MQCOMPRESS_RLE                 1
#define MQ_MQCOMPRESS_ZLIBFAST            2
#define MQ_MQCOMPRESS_ZLIBHIGH            4
#define MQ_MQCOMPRESS_SYSTEM              8
#define MQ_MQCOMPRESS_ANY                 0x0FFFFFFF

/* Transport Types */
#define MQ_MQXPT_ALL                      (-1)
#define MQ_MQXPT_LOCAL                    0
#define MQ_MQXPT_LU62                     1
#define MQ_MQXPT_TCP                      2
#define MQ_MQXPT_NETBIOS                  3
#define MQ_MQXPT_SPX                      4
#define MQ_MQXPT_DECNET                   5
#define MQ_MQXPT_UDP                      6

/* Put Authority */
#define MQ_MQPA_DEFAULT                   1
#define MQ_MQPA_CONTEXT                   2
#define MQ_MQPA_ONLY_MCA                  3
#define MQ_MQPA_ALTERNATE_OR_MCA          4

/* Channel Data Conversion */
#define MQ_MQCDC_SENDER_CONVERSION        1
#define MQ_MQCDC_NO_SENDER_CONVERSION     0

/* MCA Types */
#define MQ_MQMCAT_PROCESS                 1
#define MQ_MQMCAT_THREAD                  2

/* NonPersistent-Message Speeds */
#define MQ_MQNPMS_NORMAL                  1
#define MQ_MQNPMS_FAST                    2

/* SSL Client Authentication */
#define MQ_MQSCA_REQUIRED                 0
#define MQ_MQSCA_OPTIONAL                 1

/* KeepAlive Interval */
#define MQ_MQKAI_AUTO                     (-1)

/* Connection Affinity Values */
#define MQ_MQCAFTY_NONE                   0
#define MQ_MQCAFTY_PREFERRED              1

/* Client Reconnect */
#define MQ_MQRCN_NO                       0
#define MQ_MQRCN_YES                      1
#define MQ_MQRCN_Q_MGR                    2
#define MQ_MQRCN_DISABLED                 3

/* Cluster Cache Types */
#define MQ_MQCLCT_STATIC                  0
#define MQ_MQCLCT_DYNAMIC                 1

 /* Transmission queue types */
#define MQ_MQCLXQ_SCTQ                    0
#define MQ_MQCLXQ_CHANNEL                 1

#endif

extern gint32  strip_trailing_blanks(guint8 *a_str,
                                     guint32 a_size);
extern void    dissect_mqpcf_parm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *mq_tree,
                                  guint offset, guint32 uCount, guint bLittleEndian, gboolean bParse);

DEF_VALSX(mqcc);

DEF_VALS_EXTX(mqat);
DEF_VALS_EXTX(mqcmd);
DEF_VALS_EXTX(mqrc);
DEF_VALS_EXTX(objtype);
DEF_VALS_EXTX(PrmId);
DEF_VALS_EXTX(PrmTyp);
DEF_VALS_EXTX(selector);
DEF_VALS_EXTX(MQCFINT_Parse);

DEF_VALSX(CtlOpt);
DEF_VALSX(mqcft);

DEF_VALSX(FilterOP);
DEF_VALSX(UOWControls);
DEF_VALSX(LinkType);
DEF_VALSX(ADSDescr);
DEF_VALSX(ConvTaskOpt);
DEF_VALSX(TaskEndStatus);

DEF_VALRX(ccsid);
DEF_VALRX(WaitIntv);
DEF_VALRX(OutDataLen);

/*
 * Editor modelines - http://www.wireshark.org/tools/modelines.html
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
