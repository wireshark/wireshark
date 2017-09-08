/* packet-macmgmt.c
 * Routines for docsis Mac Management Header dissection
 * Routines for Upstream Channel Change dissection
 * Routines for Ranging Message dissection
 * Routines for Registration Message dissection
 * Routines for Baseline Privacy Key Management Message dissection
 * Routines for Dynamic Service Addition Message dissection
 * Routines for Dynamic Service Change Request dissection
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
 *
 * Routines for Type 2 UCD Message dissection
 * Copyright 2015, Adrian Simionov <daniel.simionov@gmail.com>
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
 *
 * Routines for Sync Message dissection
 * Routines for REG-REQ-MP dissection
 * Copyright 2007, Bruno Verstuyft  <bruno.verstuyft@excentis.com>
 *
 * Routines for DOCSIS 3.1 OFDM Channel Descriptor dissection.
 * Routines for DOCSIS 3.1 Downstream Profile Descriptor dissection.
 * Routines for Type 51 UCD - DOCSIS 3.1 only - Message dissection
 * Copyright 2016, Bruno Verstuyft <bruno.verstuyft@excentis.com>
 *
 * Routines for DCC Message dissection
 * Routines for DCD Message dissection
 * Copyright 2004, Darryl Hymel <darryl.hymel[AT]arrisi.com>
 *
 * Routines for Type 29 UCD - DOCSIS 2.0 only - Message dissection
 * Copyright 2015, Adrian Simionov <daniel.simionov@gmail.com>
 * Copyright 2003, Brian Wheeler <brian.wheeler[AT]arrisi.com>
 *
 * Routines for Intial Ranging Request Message dissection
 * Copyright 2003, Brian Wheeler <brian.wheeler[AT]arrisi.com>
 *
 * Routines for Baseline Privacy Key Management Attributes dissection
 * Copyright 2017, Adrian Simionov <daniel.simionov@gmail.com>
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
 *
 * Routines for MDD Message dissection
 * Copyright 2014, Adrian Simionov <adrian.simionov@arrisi.com>
 * Copyright 2007, Bruno Verstuyft <bruno.verstuyft@excentis.com>
 *
 * Routines for DOCSIS 3.0 Bonded Intial Ranging Request Message dissection.
 * Copyright 2009, Geoffrey Kimball <gekimbal[AT]cisco.com>
 *
 * Routines for Type 35 UCD - DOCSIS 3.0 only - Message dissection
 * Copyright 2015, Adrian Simionov <daniel.simionov@gmail.com>
 *
 * Routines for DOCSIS 3.0 Dynamic Bonding Change Message dissection.
 * Routines for DOCSIS 3.0 DOCSIS Path Verify Message dissection.
 * Routines for DOCSIS 3.0 CM Control Message dissection.
 * Copyright 2010, Guido Reismueller <g.reismueller[AT]avm.de>
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

#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/utf8_entities.h>
#include "packet-tlv.h"

void proto_register_docsis_mgmt(void);
void proto_reg_handoff_docsis_mgmt(void);

#define MGT_SYNC 1
#define MGT_UCD 2
#define MGT_MAP 3
#define MGT_RNG_REQ 4
#define MGT_RNG_RSP 5
#define MGT_REG_REQ 6
#define MGT_REG_RSP 7
#define MGT_UCC_REQ 8
#define MGT_UCC_RSP 9
#define MGT_TRI_TCD 10
#define MGT_TRI_TSI 11
#define MGT_BPKM_REQ 12
#define MGT_BPKM_RSP 13
#define MGT_REG_ACK 14
#define MGT_DSA_REQ 15
#define MGT_DSA_RSP 16
#define MGT_DSA_ACK 17
#define MGT_DSC_REQ 18
#define MGT_DSC_RSP 19
#define MGT_DSC_ACK 20
#define MGT_DSD_REQ 21
#define MGT_DSD_RSP 22
#define MGT_DCC_REQ 23
#define MGT_DCC_RSP 24
#define MGT_DCC_ACK 25
#define MGT_DCI_REQ 26
#define MGT_DCI_RSP 27
#define MGT_UP_DIS 28
#define MGT_TYPE29UCD 29
#define MGT_INIT_RNG_REQ 30
#define MGT_TEST_REQ 31
#define MGT_DS_CH_DESC 32
#define MGT_MDD 33
#define MGT_B_INIT_RNG_REQ 34
#define MGT_TYPE35UCD 35
#define MGT_DBC_REQ 36
#define MGT_DBC_RSP 37
#define MGT_DBC_ACK 38
#define MGT_DPV_REQ 39
#define MGT_DPV_RSP 40
#define MGT_CM_STATUS 41
#define MGT_CM_CTRL_REQ 42
#define MGT_CM_CTRL_RSP 43
#define MGT_REG_REQ_MP 44
#define MGT_REG_RSP_MP 45
#define MGT_EM_REQ 46
#define MGT_EM_RSP 47
#define MGT_STATUS_ACK 48
#define MGT_OCD 49
#define MGT_DPD 50
#define MGT_TYPE51UCD 51

#define UCD_SYMBOL_RATE 1
#define UCD_FREQUENCY 2
#define UCD_PREAMBLE 3
#define UCD_BURST_DESCR 4
#define UCD_BURST_DESCR5 5
#define UCD_EXT_PREAMBLE 6
#define UCD_SCDMA_MODE_ENABLED 7
#define UCD_SCDMA_SPREADING_INTERVAL 8
#define UCD_SCDMA_CODES_PER_MINI_SLOT 9
#define UCD_SCDMA_ACTIVE_CODES 10
#define UCD_SCDMA_CODE_HOPPING_SEED 11
#define UCD_SCDMA_US_RATIO_NUM 12
#define UCD_SCDMA_US_RATIO_DENOM 13
#define UCD_SCDMA_TIMESTAMP_SNAPSHOT 14
#define UCD_MAINTAIN_POWER_SPECTRAL_DENSITY 15
#define UCD_RANGING_REQUIRED 16
#define UCD_MAX_SCHEDULED_CODES 17
#define UCD_RANGING_HOLD_OFF_PRIORITY_FIELD 18
#define UCD_RANGING_CHANNEL_CLASS_ID 19
#define UCD_SCDMA_SELECTION_ACTIVE_CODES_AND_CODE_HOPPING 20
#define UCD_SCDMA_SELECTION_STRING_FOR_ACTIVE_CODES 21
#define UCD_HIGHER_UCD_FOR_SAME_UCID 22
#define UCD_BURST_DESCR23 23
#define UCD_CHANGE_IND_BITMASK 24
#define UCD_OFDMA_TIMESTAMP_SNAPSHOT 25
#define UCD_OFDMA_CYCLIC_PREFIX_SIZE 26
#define UCD_OFDMA_ROLLOFF_PERIOD_SIZE 27
#define UCD_SUBCARRIER_SPACING 28
#define UCD_CENTER_FREQ_SUBC_0 29
#define UCD_SUBC_EXCL_BAND 30
#define UCD_UNUSED_SUBC_SPEC 31
#define UCD_SYMB_IN_OFDMA_FRAME 32
#define UCD_RAND_SEED 33

#define UCD_MODULATION 1
#define UCD_DIFF_ENCODING 2
#define UCD_PREAMBLE_LEN 3
#define UCD_PREAMBLE_VAL_OFF 4
#define UCD_FEC 5
#define UCD_FEC_CODEWORD 6
#define UCD_SCRAMBLER_SEED 7
#define UCD_MAX_BURST 8
#define UCD_GUARD_TIME 9
#define UCD_LAST_CW_LEN 10
#define UCD_SCRAMBLER_ONOFF 11
#define UCD_RS_INT_DEPTH 12
#define UCD_RS_INT_BLOCK 13
#define UCD_PREAMBLE_TYPE 14
#define UCD_SCMDA_SCRAMBLER_ONOFF 15
#define UCD_SCDMA_CODES_PER_SUBFRAME 16
#define UCD_SCDMA_FRAMER_INT_STEP_SIZE 17
#define UCD_TCM_ENABLED 18
#define UCD_SUBC_INIT_RANG 19
#define UCD_SUBC_FINE_RANG 20
#define UCD_OFDMA_PROFILE 21
#define UCD_OFDMA_IR_POWER_CONTROL 22

#define IUC_REQUEST 1
#define IUC_REQ_DATA 2
#define IUC_INIT_MAINT 3
#define IUC_STATION_MAINT 4
#define IUC_SHORT_DATA_GRANT 5
#define IUC_LONG_DATA_GRANT 6
#define IUC_NULL_IE 7
#define IUC_DATA_ACK 8
#define IUC_ADV_PHY_SHORT_DATA_GRANT 9
#define IUC_ADV_PHY_LONG_DATA_GRANT 10
#define IUC_ADV_PHY_UGS 11
#define IUC_RESERVED12 12
#define IUC_RESERVED13 13
#define IUC_RESERVED14 14
#define IUC_EXPANSION 15

#define RNGRSP_TIMING 1
#define RNGRSP_PWR_LEVEL_ADJ 2
#define RNGRSP_OFFSET_FREQ_ADJ 3
#define RNGRSP_TRANSMIT_EQ_ADJ 4
#define RNGRSP_RANGING_STATUS 5
#define RNGRSP_DOWN_FREQ_OVER 6
#define RNGRSP_UP_CHID_OVER 7

/* BPKM Attributes defined in:
 * http://www.cablemodem.com/downloads/specs/SP-BPI+_I10-030730.pdf
 */
#define BPKM_RESERVED 0
#define BPKM_SERIAL_NUM 1
#define BPKM_MANUFACTURER_ID 2
#define BPKM_MAC_ADDR 3
#define BPKM_RSA_PUB_KEY 4
#define BPKM_CM_ID 5
#define BPKM_DISPLAY_STR 6
#define BPKM_AUTH_KEY 7
#define BPKM_TEK 8
#define BPKM_KEY_LIFETIME 9
#define BPKM_KEY_SEQ_NUM 10
#define BPKM_HMAC_DIGEST 11
#define BPKM_SAID 12
#define BPKM_TEK_PARAM 13
#define BPKM_OBSOLETED 14
#define BPKM_CBC_IV 15
#define BPKM_ERROR_CODE 16
#define BPKM_CA_CERT 17
#define BPKM_CM_CERT 18
#define BPKM_SEC_CAPABILITIES 19
#define BPKM_CRYPTO_SUITE 20
#define BPKM_CRYPTO_SUITE_LIST 21
#define BPKM_BPI_VERSION 22
#define BPKM_SA_DESCRIPTOR 23
#define BPKM_SA_TYPE 24
#define BPKM_SA_QUERY 25
#define BPKM_SA_QUERY_TYPE 26
#define BPKM_IP_ADDRESS 27
#define BPKM_DNLD_PARAMS 28
#define BPKM_VENDOR_DEFINED 127

#define DCCREQ_UP_CHAN_ID 1
#define DCCREQ_DS_PARAMS 2
#define DCCREQ_INIT_TECH 3
#define DCCREQ_UCD_SUB 4
#define DCCREQ_SAID_SUB 6
#define DCCREQ_SF_SUB 7
#define DCCREQ_CMTS_MAC_ADDR 8
#define DCCREQ_KEY_SEQ_NUM 31
#define DCCREQ_HMAC_DIGEST 27

/* Define Downstrean Parameters subtypes
 * These are subtype of DCCREQ_DS_PARAMS (2)
 */

#define DCCREQ_DS_FREQ 1
#define DCCREQ_DS_MOD_TYPE 2
#define DCCREQ_DS_SYM_RATE 3
#define DCCREQ_DS_INTLV_DEPTH 4
#define DCCREQ_DS_CHAN_ID 5
#define DCCREQ_DS_SYNC_SUB 6
#define DCCREQ_DS_OFDM_BLOCK_FREQ 7

/* Define Service Flow Substitution subtypes
 * These are subtypes of DCCREQ_SF_SUB (7)
 */
#define DCCREQ_SF_SFID 1
#define DCCREQ_SF_SID 2
#define DCCREQ_SF_UNSOL_GRANT_TREF 5

#define DCCRSP_CM_JUMP_TIME 1
#define DCCRSP_KEY_SEQ_NUM 31
#define DCCRSP_HMAC_DIGEST 27

/* Define DCC-RSP CM Jump Time subtypes
 * These are subtype of DCCRSP_CM_JUMP_TIME (1)
 */
#define DCCRSP_CM_JUMP_TIME_LENGTH 1
#define DCCRSP_CM_JUMP_TIME_START 2

#define DCCACK_KEY_SEQ_NUM 31
#define DCCACK_HMAC_DIGEST 27

#define DCD_DOWN_CLASSIFIER 23
#define DCD_DSG_RULE 50
#define DCD_DSG_CONFIG 51

/* Define Downstrean Classifier subtypes
 * These are subtype of DCD_DOWN_CLASSIFIER (23)
 */

#define DCD_CFR_ID 2
#define DCD_CFR_RULE_PRI 5
#define DCD_CFR_IP_CLASSIFIER 9

/* Define IP Classifier sub-subtypes
 * These are subtypes of DCD_CFR_IP_CLASSIFIER (23.9)
 */
#define DCD_CFR_IP_SOURCE_ADDR 3
#define DCD_CFR_IP_SOURCE_MASK 4
#define DCD_CFR_IP_DEST_ADDR 5
#define DCD_CFR_IP_DEST_MASK 6
#define DCD_CFR_TCPUDP_SRCPORT_START 7
#define DCD_CFR_TCPUDP_SRCPORT_END 8
#define DCD_CFR_TCPUDP_DSTPORT_START 9
#define DCD_CFR_TCPUDP_DSTPORT_END 10

/* Define DSG Rule subtypes
 * These are subtype of DCD_DSG_RULE (50)
 */

#define DCD_RULE_ID 1
#define DCD_RULE_PRI 2
#define DCD_RULE_UCID_RNG 3
#define DCD_RULE_CLIENT_ID 4
#define DCD_RULE_TUNL_ADDR 5
#define DCD_RULE_CFR_ID 6
#define DCD_RULE_VENDOR_SPEC 43
/* Define DSG Rule Client ID sub-subtypes
 * These are subtypes of DCD_RULE_CLIENT_ID (50.4)
 */
#define DCD_CLID_BCAST_ID 1
#define DCD_CLID_KNOWN_MAC_ADDR 2
#define DCD_CLID_CA_SYS_ID 3
#define DCD_CLID_APP_ID 4

/* Define DSG Configuration subtypes
 * These are subtype of DCD_DSG_CONFIG (51)
 */

#define DCD_CFG_CHAN_LST 1
#define DCD_CFG_TDSG1 2
#define DCD_CFG_TDSG2 3
#define DCD_CFG_TDSG3 4
#define DCD_CFG_TDSG4 5
#define DCD_CFG_VENDOR_SPEC 43

#define DOWNSTREAM_ACTIVE_CHANNEL_LIST 1
#define MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP 2
#define DOWNSTREAM_AMBIGUITY_RESOLUTION_FREQUENCY_LIST 3
#define RECEIVE_CHANNEL_PROFILE_REPORTING_CONTROL 4
#define IP_INITIALIZATION_PARAMETERS 5
#define EARLY_AUTHENTICATION_AND_ENCRYPTION 6
#define UPSTREAM_ACTIVE_CHANNEL_LIST 7
#define UPSTREAM_AMBIGUITY_RESOLUTION_CHANNEL_LIST 8
#define UPSTREAM_FREQUENCY_RANGE 9
#define SYMBOL_CLOCK_LOCKING_INDICATOR 10
#define CM_STATUS_EVENT_CONTROL 11
#define UPSTREAM_TRANSMIT_POWER_REPORTING 12
#define DSG_DA_TO_DSID_ASSOCIATION_ENTRY 13
#define CM_STATUS_EVENT_ENABLE_NON_CHANNEL_SPECIFIC_EVENTS 15
#define EXTENDED_UPSTREAM_TRANSMIT_POWER_SUPPORT 16

/*Downstream Active Channel List*/
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_CHANNEL_ID 1
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_FREQUENCY 2
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_MODULATION_ORDER_ANNEX 3
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_PRIMARY_CAPABLE 4
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK 5
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_MAP_UCD_TRANSPORT_INDICATOR 6
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_OFDM_PLC_PARAMETERS 7

/*Mac Domain Downstream Service Group*/
#define MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_MD_DS_SG_IDENTIFIER 1
#define MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_CHANNEL_IDS 2

/*Modulation Orders*/
#define QAM64 0
#define QAM256 1

/*Annexes*/
#define J83_ANNEX_A 0
#define J83_ANNEX_B 1
#define J83_ANNEX_C 2

/*Primary Capable*/
#define NOT_PRIMARY_CAPABLE 0
#define PRIMARY_CAPABLE 1

/*Can carry MAP and UCD*/
#define CANNOT_CARRY_MAP_UCD 0
#define CAN_CARRY_MAP_UCD 1

/*Receive Channel Profile Reporting Control*/
#define RCP_CENTER_FREQUENCY_SPACING 1
#define VERBOSE_RCP_REPORTING 2

/*Frequency spacing*/
#define ASSUME_6MHZ_CENTER_FREQUENCY_SPACING 0
#define ASSUME_8MHZ_CENTER_FREQUENCY_SPACING 1

/*Verbose RCP reporting*/
#define RCP_NO_VERBOSE_REPORTING 0
#define RCP_VERBOSE_REPORTING 1

/*Sub-TLVs for IP Initialization Parameters*/
#define IP_PROVISIONING_MODE 1
#define PRE_REGISTRATION_DSID 2

/*IP Provisioning Modes*/
#define IPv4_ONLY 0
#define IPv6_ONLY 1
#define IP_ALTERNATE 2
#define DUAL_STACK 3

/*Early authentication and encryption*/
#define EAE_DISABLED 0
#define EAE_ENABLED 1

/*Upstream Active Channel List*/
#define UPSTREAM_ACTIVE_CHANNEL_LIST_UPSTREAM_CHANNEL_ID 1
#define UPSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK 2

/*Upstream Frequency Range*/
#define STANDARD_UPSTREAM_FREQUENCY_RANGE 0
#define EXTENDED_UPSTREAM_FREQUENCY_RANGE 1

/*Symbol Clock Locking Indicator*/
#define NOT_LOCKED_TO_MASTER_CLOCK 0
#define LOCKED_TO_MASTER_CLOCK 1

/*CM-STATUS Event Control */
#define EVENT_TYPE_CODE 1
#define MAXIMUM_EVENT_HOLDOFF_TIMER 2
#define MAXIMUM_NUMBER_OF_REPORTS_PER_EVENT 3

/*CM-STATUS Events*/
#define SECONDARY_CHANNEL_MDD_TIMEOUT 1
#define QAM_FEC_LOCK_FAILURE 2
#define SEQUENCE_OUT_OF_RANGE 3
#define MDD_RECOVERY 4
#define QAM_FEC_LOCK_RECOVERY 5
#define T4_TIMEOUT 6
#define T3_RETRIES_EXCEEDED 7
#define SUCCESFUL_RANGING_AFTER_T3_RETRIES_EXCEEDED 8
#define CM_OPERATING_ON_BATTERY_BACKUP 9
#define CM_RETURNED_TO_AC_POWER 10

/*Upstream Transmit Power Reporting*/
#define CM_DOESNT_REPORT_TRANSMIT_POWER 0
#define CM_REPORTS_TRANSMIT_POWER 1

/*Dsg DA to DSID association entry*/
#define DSG_DA_TO_DSID_ASSOCIATION_DA 1
#define DSG_DA_TO_DSID_ASSOCIATION_DSID 2

/* Define Tukey raised cosine window */
#define TUKEY_0TS 0
#define TUKEY_64TS 1
#define TUKEY_128TS 2
#define TUKEY_192TS 3
#define TUKEY_256TS 4

/* Define Cyclic prefix */
#define CYCLIC_PREFIX_192_TS 0
#define CYCLIC_PREFIX_256_TS 1
#define CYCLIC_PREFIX_512_TS 2
#define CYCLIC_PREFIX_768_TS 3
#define CYCLIC_PREFIX_1024_TS 4

/* Define Sub carrier spacing */
#define SPACING_25KHZ 0
#define SPACING_50KHZ 1

#define SEC_CH_MDD_TIMEOUT      1
#define QAM_FEC_LOCK_FAILURE    2
#define SEQ_OUT_OF_RANGE        3
#define SEC_CH_MDD_RECOVERY     4
#define QAM_FEC_LOCK_RECOVERY   5
#define T4_TIMEOUT              6
#define T3_RETRIES_EXCEEDED     7
#define SUCCESS_RANGING_AFTER_T3_RETRIES_EXCEEDED 8
#define CM_ON_BATTERY           9
#define CM_ON_AC_POWER         10

#define EVENT_DESCR             2
#define EVENT_DS_CH_ID          4
#define EVENT_US_CH_ID          5
#define EVENT_DSID              6

#define CM_CTRL_MUTE 1
#define CM_CTRL_MUTE_TIMEOUT 2
#define CM_CTRL_REINIT 3
#define CM_CTRL_DISABLE_FWD 4
#define CM_CTRL_DS_EVENT 5
#define CM_CTRL_US_EVENT 6
#define CM_CTRL_EVENT 7

#define DS_EVENT_CH_ID 1
#define DS_EVENT_MASK 2

#define US_EVENT_CH_ID 1
#define US_EVENT_MASK 2

#define DISCRETE_FOURIER_TRANSFORM_SIZE 0
#define CYCLIC_PREFIX 1
#define ROLL_OFF 2
#define OFDM_SPECTRUM_LOCATION 3
#define TIME_INTERLEAVING_DEPTH 4
#define SUBCARRIER_ASSIGNMENT_RANGE_LIST 5
#define PRIMARY_CAPABILITY_INDICATOR 6
#define SUBCARRIER_ASSIGNMENT_VECTOR 6

#define SUBCARRIER_ASSIGNMENT_RANGE_CONT 0
#define SUBCARRIER_ASSIGNMENT_RANGE_SKIPBY1 1
#define SUBCARRIER_ASSIGNMENT_LIST 2


static int proto_docsis_mgmt = -1;
static int proto_docsis_sync = -1;
static int proto_docsis_ucd = -1;
static int proto_docsis_map = -1;
static int proto_docsis_rngreq = -1;
static int proto_docsis_rngrsp = -1;
static int proto_docsis_regreq = -1;
static int proto_docsis_regrsp = -1;
static int proto_docsis_uccreq = -1;
static int proto_docsis_uccrsp = -1;
static int proto_docsis_bpkmreq = -1;
static int proto_docsis_bpkmrsp = -1;
static int proto_docsis_regack = -1;
static int proto_docsis_dsareq = -1;
static int proto_docsis_dsarsp = -1;
static int proto_docsis_dsaack = -1;
static int proto_docsis_dscreq = -1;
static int proto_docsis_dscrsp = -1;
static int proto_docsis_dscack = -1;
static int proto_docsis_dsdreq = -1;
static int proto_docsis_dsdrsp = -1;
static int proto_docsis_dccreq = -1;
static int proto_docsis_dccrsp = -1;
static int proto_docsis_dccack = -1;
static int proto_docsis_type29ucd = -1;
static int proto_docsis_intrngreq = -1;
static int proto_docsis_dcd = -1;
static int proto_docsis_mdd = -1;
static int proto_docsis_bintrngreq = -1;
static int proto_docsis_type35ucd = -1;
static int proto_docsis_dbcreq = -1;
static int proto_docsis_dbcrsp = -1;
static int proto_docsis_dbcack = -1;
static int proto_docsis_dpvreq = -1;
static int proto_docsis_dpvrsp = -1;
static int proto_docsis_cmstatus = -1;
static int proto_docsis_cmctrlreq = -1;
static int proto_docsis_cmctrlrsp = -1;
static int proto_docsis_regreqmp = -1;
static int proto_docsis_regrspmp = -1;
static int proto_docsis_ocd = -1;
static int proto_docsis_dpd = -1;
static int proto_docsis_type51ucd = -1;

static int hf_docsis_sync_cmts_timestamp = -1;

static int hf_docsis_ucd_config_ch_cnt = -1;
static int hf_docsis_ucd_mini_slot_size = -1;
static int hf_docsis_ucd_type = -1;
static int hf_docsis_ucd_length = -1;
static int hf_docsis_ucd_burst_type = -1;
static int hf_docsis_ucd_burst_length = -1;
static int hf_docsis_ucd_symbol_rate = -1;
static int hf_docsis_ucd_frequency = -1;
static int hf_docsis_ucd_preamble_pat = -1;
static int hf_docsis_ucd_ext_preamble_pat = -1;
static int hf_docsis_ucd_scdma_mode_enabled = -1;
static int hf_docsis_ucd_scdma_spreading_interval = -1;
static int hf_docsis_ucd_scdma_codes_per_mini_slot = -1;
static int hf_docsis_ucd_scdma_active_codes = -1;
static int hf_docsis_ucd_scdma_code_hopping_seed = -1;
static int hf_docsis_ucd_scdma_us_ratio_num = -1;
static int hf_docsis_ucd_scdma_us_ratio_denom = -1;
static int hf_docsis_ucd_scdma_timestamp_snapshot = -1;
static int hf_docsis_ucd_maintain_power_spectral_density = -1;
static int hf_docsis_ucd_ranging_required = -1;
static int hf_docsis_ucd_max_scheduled_codes = -1;
static int hf_docsis_ucd_rnghoff_cm = -1;
static int hf_docsis_ucd_rnghoff_erouter = -1;
static int hf_docsis_ucd_rnghoff_emta = -1;
static int hf_docsis_ucd_rnghoff_estb = -1;
static int hf_docsis_ucd_rnghoff_rsvd = -1;
static int hf_docsis_ucd_rnghoff_id_ext = -1;
static int hf_docsis_ucd_chan_class_id_cm = -1;
static int hf_docsis_ucd_chan_class_id_erouter = -1;
static int hf_docsis_ucd_chan_class_id_emta = -1;
static int hf_docsis_ucd_chan_class_id_estb = -1;
static int hf_docsis_ucd_chan_class_id_rsvd = -1;
static int hf_docsis_ucd_chan_class_id_id_ext = -1;
static int hf_docsis_ucd_scdma_scrambler_onoff = -1;
static int hf_docsis_ucd_scdma_codes_per_subframe = -1;
static int hf_docsis_ucd_scdma_framer_int_step_size = -1;
static int hf_docsis_ucd_tcm_enabled = -1;
static int hf_docsis_ucd_active_code_hopping = -1;
static int hf_docsis_ucd_higher_ucd_for_same_ucid = -1;
static int hf_docsis_ucd_higher_ucd_for_same_ucid_resv = -1;
static int hf_docsis_ucd_scdma_selection_active_codes = -1;
static int hf_docsis_ucd_iuc = -1;
static int hf_docsis_ucd_change_ind_bitmask_subc_excl_band = -1;
static int hf_docsis_ucd_change_ind_bitmask_unused_subc = -1;
static int hf_docsis_ucd_change_ind_bitmask_other_subc = -1;
static int hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc5 = -1;
static int hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc6 = -1;
static int hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc9 = -1;
static int hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc10 = -1;
static int hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc11 = -1;
static int hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc12 = -1;
static int hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc13 = -1;
static int hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc3_or_4 = -1;
static int hf_docsis_ucd_change_ind_bitmask_reserved = -1;
static int hf_docsis_ucd_ofdma_timestamp_snapshot = -1;
static int hf_docsis_ucd_ofdma_cyclic_prefix_size = -1;
static int hf_docsis_ucd_ofdma_rolloff_period_size = -1;
static int hf_docsis_ucd_subc_spacing = -1;
static int hf_docsis_ucd_cent_freq_subc0 = -1;
static int hf_docsis_ucd_subcarrier_range = -1;
static int hf_docsis_ucd_symb_ofdma_frame = -1;
static int hf_docsis_ucd_rand_seed = -1;

static int hf_docsis_burst_mod_type = -1;
static int hf_docsis_burst_diff_encoding = -1;
static int hf_docsis_burst_preamble_len = -1;
static int hf_docsis_burst_preamble_val_off = -1;
static int hf_docsis_burst_fec = -1;
static int hf_docsis_burst_fec_codeword = -1;
static int hf_docsis_burst_scrambler_seed = -1;
static int hf_docsis_burst_max_burst = -1;
static int hf_docsis_burst_guard_time = -1;
static int hf_docsis_burst_last_cw_len = -1;
static int hf_docsis_burst_scrambler_onoff = -1;
static int hf_docsis_rs_int_depth = -1;
static int hf_docsis_rs_int_block = -1;
static int hf_docsis_preamble_type = -1;
static int hf_docsis_subc_init_rang = -1;
static int hf_docsis_subc_fine_rang = -1;
static int hf_docsis_ofdma_prof_mod_order = -1;
static int hf_docsis_ofdma_prof_pilot_pattern = -1;
static int hf_docsis_ofdma_prof_num_add_minislots = -1;
static int hf_docsis_ofdma_ir_pow_ctrl_start_pow = -1;
static int hf_docsis_ofdma_ir_pow_ctrl_step_size = -1;

static int hf_docsis_map_ucd_count = -1;
static int hf_docsis_map_numie = -1;
static int hf_docsis_map_alloc_start = -1;
static int hf_docsis_map_ack_time = -1;
static int hf_docsis_map_rng_start = -1;
static int hf_docsis_map_rng_end = -1;
static int hf_docsis_map_data_start = -1;
static int hf_docsis_map_data_end = -1;
static int hf_docsis_map_ie = -1;
static int hf_docsis_map_rsvd = -1;
static int hf_docsis_map_sid = -1;
static int hf_docsis_map_iuc = -1;
static int hf_docsis_map_offset = -1;

static int hf_docsis_rngreq_sid = -1;
static int hf_docsis_rngreq_pend_compl = -1;

static int hf_docsis_rngrsp_type = -1;
static int hf_docsis_rngrsp_length = -1;
static int hf_docsis_rngrsp_sid = -1;
static int hf_docsis_rngrsp_timing_adj = -1;
static int hf_docsis_rngrsp_power_adj = -1;
static int hf_docsis_rngrsp_freq_adj = -1;
static int hf_docsis_rngrsp_xmit_eq_adj = -1;
static int hf_docsis_rngrsp_ranging_status = -1;
static int hf_docsis_rngrsp_down_freq_over = -1;
static int hf_docsis_rngrsp_upstream_ch_over = -1;

static int hf_docsis_regreq_sid = -1;
static int hf_docsis_regrsp_sid = -1;
static int hf_docsis_regrsp_response = -1;

static int hf_docsis_bpkm_code = -1;
static int hf_docsis_bpkm_length = -1;
static int hf_docsis_bpkm_ident = -1;
static int hf_docsis_bpkmattr = -1;
static int hf_docsis_bpkmattr_serial_num = -1;
static int hf_docsis_bpkmattr_manf_id = -1;
static int hf_docsis_bpkmattr_mac_addr = -1;
static int hf_docsis_bpkmattr_rsa_pub_key = -1;
static int hf_docsis_bpkmattr_cm_id = -1;
static int hf_docsis_bpkmattr_display_str = -1;
static int hf_docsis_bpkmattr_auth_key = -1;
static int hf_docsis_bpkmattr_tek = -1;
static int hf_docsis_bpkmattr_key_life = -1;
static int hf_docsis_bpkmattr_key_seq = -1;
static int hf_docsis_bpkmattr_hmac_digest = -1;
static int hf_docsis_bpkmattr_said = -1;
static int hf_docsis_bpkmattr_tek_params = -1;
static int hf_docsis_bpkmattr_cbc_iv = -1;
static int hf_docsis_bpkmattr_error_code = -1;
static int hf_docsis_bpkmattr_vendor_def = -1;
static int hf_docsis_bpkmattr_ca_cert = -1;
static int hf_docsis_bpkmattr_cm_cert = -1;
static int hf_docsis_bpkmattr_security_cap = -1;
static int hf_docsis_bpkmattr_crypto_suite = -1;
static int hf_docsis_bpkmattr_crypto_suite_list = -1;
static int hf_docsis_bpkmattr_bpi_version = -1;
static int hf_docsis_bpkmattr_sa_descr = -1;
static int hf_docsis_bpkmattr_sa_type = -1;
static int hf_docsis_bpkmattr_sa_query = -1;
static int hf_docsis_bpkmattr_sa_query_type = -1;
static int hf_docsis_bpkmattr_ip_address = -1;
static int hf_docsis_bpkmattr_download_param = -1;
static int hf_docsis_bpkmattr_type = -1;
static int hf_docsis_bpkmattr_length = -1;

static int hf_docsis_regack_sid = -1;
static int hf_docsis_regack_response = -1;

static int hf_docsis_dsarsp_response = -1;
static int hf_docsis_dsaack_response = -1;

static int hf_docsis_dscrsp_response = -1;
static int hf_docsis_dscack_response = -1;

static int hf_docsis_dsdreq_rsvd = -1;
static int hf_docsis_dsdreq_sfid = -1;

static int hf_docsis_dsdrsp_confcode = -1;
static int hf_docsis_dsdrsp_rsvd = -1;

static int hf_docsis_dccreq_type = -1;
static int hf_docsis_dccreq_length = -1;
static int hf_docsis_dccreq_tran_id = -1;
static int hf_docsis_dccreq_up_chan_id = -1;
static int hf_docsis_dcc_ds_params_subtype = -1;
static int hf_docsis_dcc_ds_params_length = -1;
static int hf_docsis_dccreq_ds_freq = -1;
static int hf_docsis_dccreq_ds_mod_type = -1;
static int hf_docsis_dccreq_ds_sym_rate = -1;
static int hf_docsis_dccreq_ds_intlv_depth_i = -1;
static int hf_docsis_dccreq_ds_intlv_depth_j = -1;
static int hf_docsis_dccreq_ds_chan_id = -1;
static int hf_docsis_dccreq_ds_sync_sub = -1;
static int hf_docsis_dccreq_ds_ofdm_block_freq = -1;
static int hf_docsis_dccreq_init_tech = -1;
static int hf_docsis_dccreq_ucd_sub = -1;
static int hf_docsis_dccreq_said_sub_cur = -1;
static int hf_docsis_dccreq_said_sub_new = -1;
static int hf_docsis_dcc_sf_sub_subtype = -1;
static int hf_docsis_dcc_sf_sub_length = -1;
static int hf_docsis_dccreq_sf_sfid_cur = -1;
static int hf_docsis_dccreq_sf_sfid_new = -1;
static int hf_docsis_dccreq_sf_sid_cur = -1;
static int hf_docsis_dccreq_sf_sid_new = -1;
static int hf_docsis_dccreq_sf_unsol_grant_tref = -1;
static int hf_docsis_dccreq_cmts_mac_addr = -1;
static int hf_docsis_dccreq_key_seq_num = -1;
static int hf_docsis_dccreq_hmac_digest = -1;
static int hf_docsis_dccrsp_conf_code = -1;
static int hf_docsis_dccrsp_type = -1;
static int hf_docsis_dccrsp_length = -1;
static int hf_docsis_dcc_cm_jump_subtype = -1;
static int hf_docsis_dcc_cm_jump_length = -1;
static int hf_docsis_dccrsp_cm_jump_time_length = -1;
static int hf_docsis_dccrsp_cm_jump_time_start = -1;
static int hf_docsis_dccrsp_key_seq_num = -1;
static int hf_docsis_dccrsp_hmac_digest = -1;
static int hf_docsis_dccack_type = -1;
static int hf_docsis_dccack_length = -1;
static int hf_docsis_dccack_key_seq_num = -1;
static int hf_docsis_dccack_hmac_digest = -1;

static int hf_docsis_intrngreq_sid = -1;

static int hf_docsis_dcd_config_ch_cnt = -1;
static int hf_docsis_dcd_num_of_frag = -1;
static int hf_docsis_dcd_frag_sequence_num = -1;
static int hf_docsis_dcd_type = -1;
static int hf_docsis_dcd_length = -1;
static int hf_docsis_dcd_down_classifier_subtype = -1;
static int hf_docsis_dcd_down_classifier_length = -1;
static int hf_docsis_dcd_cfr_id = -1;
static int hf_docsis_dcd_cfr_rule_pri = -1;
static int hf_docsis_dcd_cfr_ip_subtype = -1;
static int hf_docsis_dcd_cfr_ip_length = -1;
static int hf_docsis_dcd_cfr_ip_source_addr = -1;
static int hf_docsis_dcd_cfr_ip_source_mask = -1;
static int hf_docsis_dcd_cfr_ip_dest_addr = -1;
static int hf_docsis_dcd_cfr_ip_dest_mask = -1;
static int hf_docsis_dcd_cfr_tcpudp_srcport_start = -1;
static int hf_docsis_dcd_cfr_tcpudp_srcport_end = -1;
static int hf_docsis_dcd_cfr_tcpudp_dstport_start = -1;
static int hf_docsis_dcd_cfr_tcpudp_dstport_end = -1;
static int hf_docsis_dcd_rule_id = -1;
static int hf_docsis_dcd_rule_pri = -1;
static int hf_docsis_dcd_rule_ucid_list = -1;
static int hf_docsis_dcd_clid_subtype = -1;
static int hf_docsis_dcd_clid_length = -1;
static int hf_docsis_dcd_clid_bcast_id = -1;
static int hf_docsis_dcd_clid_known_mac_addr = -1;
static int hf_docsis_dcd_clid_ca_sys_id = -1;
static int hf_docsis_dcd_clid_app_id = -1;
static int hf_docsis_dcd_dsg_rule_subtype = -1;
static int hf_docsis_dcd_dsg_rule_length = -1;
static int hf_docsis_dcd_rule_tunl_addr = -1;
static int hf_docsis_dcd_rule_cfr_id = -1;
static int hf_docsis_dcd_rule_vendor_spec = -1;
static int hf_docsis_dcd_cfg_subtype = -1;
static int hf_docsis_dcd_cfg_length = -1;
static int hf_docsis_dcd_cfg_chan = -1;
static int hf_docsis_dcd_cfg_tdsg1 = -1;
static int hf_docsis_dcd_cfg_tdsg2 = -1;
static int hf_docsis_dcd_cfg_tdsg3 = -1;
static int hf_docsis_dcd_cfg_tdsg4 = -1;
static int hf_docsis_dcd_cfg_vendor_spec = -1;

static int hf_docsis_mdd_ccc = -1;
static int hf_docsis_mdd_number_of_fragments = -1;
static int hf_docsis_mdd_fragment_sequence_number = -1;
static int hf_docsis_mdd_current_channel_dcid = -1;
static int hf_docsis_mdd_ds_active_channel_list_subtype = -1;
static int hf_docsis_mdd_ds_active_channel_list_length = -1;
static int hf_docsis_mdd_downstream_active_channel_list_channel_id = -1;
static int hf_docsis_mdd_downstream_active_channel_list_frequency = -1;
static int hf_docsis_mdd_downstream_active_channel_list_annex = -1;
static int hf_docsis_mdd_downstream_active_channel_list_modulation_order = -1;
static int hf_docsis_mdd_downstream_active_channel_list_primary_capable = -1;
static int hf_docsis_mdd_downstream_active_channel_list_map_ucd_transport_indicator = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_timeout = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_failure = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_recovery = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_recovery = -1;
static int hf_docsis_mdd_ofdm_plc_parameters = -1;
static int hf_docsis_mdd_ofdm_plc_parameters_tukey_raised_cosine_window = -1;
static int hf_docsis_mdd_ofdm_plc_parameters_cyclic_prefix = -1;
static int hf_docsis_mdd_ofdm_plc_parameters_sub_carrier_spacing = -1;
static int hf_docsis_mdd_up_active_channel_list_subtype = -1;
static int hf_docsis_mdd_up_active_channel_list_length = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_t4_timeout = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_t3_retries_exceeded = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_successful_ranging_after_t3_retries_exceeded = -1;
static int hf_docsis_mdd_ds_service_group_subtype = -1;
static int hf_docsis_mdd_ds_service_group_length = -1;
static int hf_docsis_mdd_mac_domain_downstream_service_group_md_ds_sg_identifier = -1;
static int hf_docsis_mdd_mac_domain_downstream_service_group_channel_id = -1;
static int hf_docsis_mdd_type = -1;
static int hf_docsis_mdd_length = -1;
static int hf_docsis_mdd_downstream_ambiguity_resolution_frequency = -1;
static int hf_docsis_mdd_channel_profile_reporting_control_subtype = -1;
static int hf_docsis_mdd_channel_profile_reporting_control_length = -1;
static int hf_docsis_mdd_rpc_center_frequency_spacing = -1;
static int hf_docsis_mdd_verbose_rcp_reporting = -1;
static int hf_docsis_mdd_ip_init_param_subtype = -1;
static int hf_docsis_mdd_ip_init_param_length = -1;
static int hf_docsis_mdd_ip_provisioning_mode = -1;
static int hf_docsis_mdd_pre_registration_dsid = -1;
static int hf_docsis_mdd_early_authentication_and_encryption = -1;
static int hf_docsis_mdd_upstream_active_channel_list_upstream_channel_id = -1;
static int hf_docsis_mdd_upstream_ambiguity_resolution_channel_list_channel_id = -1;
static int hf_docsis_mdd_upstream_frequency_range = -1;
static int hf_docsis_mdd_symbol_clock_locking_indicator = -1;
static int hf_docsis_mdd_cm_status_event_control_subtype = -1;
static int hf_docsis_mdd_cm_status_event_control_length = -1;
static int hf_docsis_mdd_event_type = -1;
static int hf_docsis_mdd_maximum_event_holdoff_timer = -1;
static int hf_docsis_mdd_maximum_number_of_reports_per_event = -1;
static int hf_docsis_mdd_upstream_transmit_power_reporting = -1;
static int hf_docsis_mdd_dsg_da_to_dsid_subtype = -1;
static int hf_docsis_mdd_dsg_da_to_dsid_length = -1;
static int hf_docsis_mdd_dsg_da_to_dsid_association_da = -1;
static int hf_docsis_mdd_dsg_da_to_dsid_association_dsid = -1;
static int hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events = -1;
static int hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_sequence_out_of_range = -1;
static int hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_operating_on_battery_backup = -1;
static int hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_returned_to_ac_power = -1;
static int hf_docsis_mdd_extended_upstream_transmit_power_support = -1;

static int hf_docsis_bintrngreq_mddsgid = -1;
static int hf_docsis_bintrngreq_capflags = -1;
static int hf_docsis_bintrngreq_capflags_frag = -1;
static int hf_docsis_bintrngreq_capflags_encrypt = -1;

static int hf_docsis_dbcreq_number_of_fragments = -1;
static int hf_docsis_dbcreq_fragment_sequence_number = -1;

static int hf_docsis_dbcrsp_conf_code = -1;

static int hf_docsis_dpv_flags = -1;
static int hf_docsis_dpv_us_sf = -1;
static int hf_docsis_dpv_n = -1;
static int hf_docsis_dpv_start = -1;
static int hf_docsis_dpv_end = -1;
static int hf_docsis_dpv_ts_start = -1;
static int hf_docsis_dpv_ts_end = -1;

static int hf_docsis_cmstatus_e_t_mdd_t = -1;
static int hf_docsis_cmstatus_e_t_qfl_f = -1;
static int hf_docsis_cmstatus_e_t_s_o = -1;
static int hf_docsis_cmstatus_e_t_mdd_r = -1;
static int hf_docsis_cmstatus_e_t_qfl_r = -1;
static int hf_docsis_cmstatus_e_t_t4_t = -1;
static int hf_docsis_cmstatus_e_t_t3_e = -1;
static int hf_docsis_cmstatus_e_t_rng_s = -1;
static int hf_docsis_cmstatus_e_t_cm_b = -1;
static int hf_docsis_cmstatus_e_t_cm_a = -1;
static int hf_docsis_cmstatus_ds_ch_id = -1;
static int hf_docsis_cmstatus_us_ch_id = -1;
static int hf_docsis_cmstatus_dsid = -1;
static int hf_docsis_cmstatus_descr = -1;
static int hf_docsis_cmstatus_tlv_data = -1;
static int hf_docsis_cmstatus_type = -1;
static int hf_docsis_cmstatus_length = -1;

static int hf_docsis_cmctrl_tlv_mute = -1;
static int hf_docsis_cmctrl_tlv_mute_timeout = -1;
static int hf_docsis_cmctrl_tlv_reinit = -1;
static int hf_docsis_cmctrl_tlv_disable_fwd = -1;
static int hf_docsis_cmctrl_tlv_ds_event = -1;
static int hf_docsis_cmctrl_tlv_us_event = -1;
static int hf_docsis_cmctrl_tlv_event = -1;
static int hf_docsis_cmctrlreq_tlv_data = -1;
static int hf_docsis_cmctrlreq_type = -1;
static int hf_docsis_cmctrlreq_length = -1;
static int hf_docsis_cmctrlreq_us_type = -1;
static int hf_docsis_cmctrlreq_us_length = -1;
static int hf_docsis_cmctrl_us_event_ch_id = -1;
static int hf_docsis_cmctrl_us_event_mask = -1;
static int hf_docsis_cmctrl_ds_type = -1;
static int hf_docsis_cmctrl_ds_length = -1;
static int hf_docsis_cmctrl_ds_event_ch_id = -1;
static int hf_docsis_cmctrl_ds_event_mask = -1;

static int hf_docsis_regreqmp_sid = -1;
static int hf_docsis_regreqmp_number_of_fragments = -1;
static int hf_docsis_regreqmp_fragment_sequence_number = -1;
static int hf_docsis_regrspmp_sid = -1;
static int hf_docsis_regrspmp_response = -1;
static int hf_docsis_regrspmp_number_of_fragments = -1;
static int hf_docsis_regrspmp_fragment_sequence_number = -1;

static int hf_docsis_ocd_tlv_unknown = -1;
static int hf_docsis_ocd_ccc = -1;
static int hf_docsis_ocd_tlv_four_trans_size = -1;
static int hf_docsis_ocd_tlv_cycl_pref = -1;
static int hf_docsis_ocd_tlv_roll_off = -1;
static int hf_docsis_ocd_tlv_ofdm_spec_loc = -1;
static int hf_docsis_ocd_tlv_time_int_depth = -1;
static int hf_docsis_ocd_tlv_prim_cap_ind = -1;
static int hf_docsis_ocd_tlv_subc_assign_type = -1;
static int hf_docsis_ocd_tlv_subc_assign_value = -1;
static int hf_docsis_ocd_subc_assign_subc_type = -1;
static int hf_docsis_ocd_subc_assign_range = -1;
static int hf_docsis_ocd_subc_assign_index = -1;
static int hf_docsis_ocd_tlv_data = -1;
static int hf_docsis_ocd_type = -1;
static int hf_docsis_ocd_length = -1;

static int hf_docsis_dpd_tlv_unknown = -1;
static int hf_docsis_dpd_prof_id = -1;
static int hf_docsis_dpd_ccc = -1;
static int hf_docsis_dpd_tlv_subc_assign_type = -1;
static int hf_docsis_dpd_tlv_subc_assign_value = -1;
static int hf_docsis_dpd_subc_assign_range = -1;
static int hf_docsis_dpd_tlv_subc_assign_reserved = -1;
static int hf_docsis_dpd_tlv_subc_assign_modulation = -1;
static int hf_docsis_dpd_subc_assign_index = -1;
static int hf_docsis_dpd_tlv_subc_assign_vector_oddness = -1;
static int hf_docsis_dpd_tlv_subc_assign_vector_reserved = -1;
static int hf_docsis_dpd_tlv_subc_assign_vector_subc_start = -1;
static int hf_docsis_dpd_tlv_subc_assign_vector_modulation_odd = -1;
static int hf_docsis_dpd_tlv_subc_assign_vector_modulation_even = -1;
static int hf_docsis_dpd_tlv_data = -1;
static int hf_docsis_dpd_type = -1;
static int hf_docsis_dpd_length = -1;

static int hf_docsis_mgt_upstream_chid = -1;
static int hf_docsis_mgt_down_chid = -1;
static int hf_docsis_mgt_tranid = -1;
static int hf_docsis_mgt_dst_addr = -1;
static int hf_docsis_mgt_src_addr = -1;
static int hf_docsis_mgt_msg_len = -1;
static int hf_docsis_mgt_dsap = -1;
static int hf_docsis_mgt_ssap = -1;
static int hf_docsis_mgt_control = -1;
static int hf_docsis_mgt_version = -1;
static int hf_docsis_mgt_type = -1;
static int hf_docsis_mgt_rsvd = -1;


static gint ett_docsis_sync = -1;

static gint ett_docsis_ucd = -1;
static gint ett_docsis_tlv = -1;
static gint ett_docsis_burst_tlv = -1;

static gint ett_docsis_map = -1;
static gint ett_docsis_map_ie = -1;

static gint ett_docsis_rngreq = -1;

static gint ett_docsis_rngrsp = -1;
static gint ett_docsis_rngrsptlv = -1;

static gint ett_docsis_regreq = -1;
static gint ett_docsis_regrsp = -1;

static gint ett_docsis_uccreq = -1;
static gint ett_docsis_uccrsp = -1;

static gint ett_docsis_bpkmreq = -1;
static gint ett_docsis_bpkmrsp = -1;
static gint ett_docsis_bpkmattr = -1;
static gint ett_docsis_bpkmattr_cmid = -1;
static gint ett_docsis_bpkmattr_scap = -1;
static gint ett_docsis_bpkmattr_tekp = -1;
static gint ett_docsis_bpkmattr_sadsc = -1;
static gint ett_docsis_bpkmattr_saqry = -1;
static gint ett_docsis_bpkmattr_dnld = -1;
static gint ett_docsis_bpkmattrtlv = -1;

static gint ett_docsis_regack = -1;

static gint ett_docsis_dsareq = -1;
static gint ett_docsis_dsarsp = -1;
static gint ett_docsis_dsaack = -1;

static gint ett_docsis_dscreq = -1;
static gint ett_docsis_dscrsp = -1;
static gint ett_docsis_dscack = -1;

static gint ett_docsis_dsdreq = -1;
static gint ett_docsis_dsdrsp = -1;

static gint ett_docsis_dccreq = -1;
static gint ett_docsis_dccreq_tlv = -1;
static gint ett_docsis_dccreq_ds_params = -1;
static gint ett_docsis_dccreq_sf_sub = -1;
static gint ett_docsis_dccrsp = -1;
static gint ett_docsis_dccrsp_cm_jump_time = -1;
static gint ett_docsis_dccrsp_tlv = -1;
static gint ett_docsis_dccack = -1;
static gint ett_docsis_dccack_tlv = -1;

static gint ett_docsis_intrngreq = -1;

static gint ett_docsis_dcd = -1;
static gint ett_docsis_dcd_cfr = -1;
static gint ett_docsis_dcd_cfr_ip = -1;
static gint ett_docsis_dcd_rule = -1;
static gint ett_docsis_dcd_clid = -1;
static gint ett_docsis_dcd_cfg = -1;
static gint ett_docsis_dcd_tlv = -1;

static gint ett_docsis_mdd = -1;
static gint ett_tlv = -1;
static gint ett_sub_tlv = -1;
static gint ett_docsis_mdd_ds_active_channel_list = -1;
static gint ett_docsis_mdd_ds_service_group = -1;
static gint ett_docsis_mdd_channel_profile_reporting_control = -1;
static gint ett_docsis_mdd_ip_init_param = -1;
static gint ett_docsis_mdd_up_active_channel_list = -1;
static gint ett_docsis_mdd_cm_status_event_control = -1;
static gint ett_docsis_mdd_dsg_da_to_dsid = -1;

static gint ett_docsis_bintrngreq = -1;

static gint ett_docsis_dbcreq = -1;
static gint ett_docsis_dbcrsp = -1;
static gint ett_docsis_dbcack = -1;

static gint ett_docsis_dpvreq = -1;
static gint ett_docsis_dpvrsp = -1;

static gint ett_docsis_cmstatus = -1;
static gint ett_docsis_cmstatus_tlv = -1;
static gint ett_docsis_cmstatus_tlvtlv = -1;

static gint ett_docsis_cmctrlreq = -1;
static gint ett_docsis_cmctrlreq_tlv = -1;
static gint ett_docsis_cmctrlreq_tlvtlv = -1;
static gint ett_docsis_cmctrl_tlv_us_event = -1;
static gint ett_docsis_cmctrl_tlv_ds_event = -1;
static gint ett_docsis_cmctrlrsp = -1;

static gint ett_docsis_regreqmp = -1;
static gint ett_docsis_regrspmp = -1;

static gint ett_docsis_ocd = -1;
static gint ett_docsis_ocd_tlv = -1;
static gint ett_docsis_ocd_tlvtlv = -1;

static gint ett_docsis_dpd = -1;
static gint ett_docsis_dpd_tlv = -1;
static gint ett_docsis_dpd_tlvtlv = -1;
static gint ett_docsis_dpd_tlv_subcarrier_assignment = -1;
static gint ett_docsis_dpd_tlv_subcarrier_assignment_vector = -1;

static gint ett_docsis_mgmt = -1;
static gint ett_mgmt_pay = -1;

static expert_field ei_docsis_mgmt_tlvlen_bad = EI_INIT;
static expert_field ei_docsis_mgmt_tlvtype_unknown = EI_INIT;

static dissector_table_t docsis_mgmt_dissector_table;
static dissector_handle_t docsis_tlv_handle;
static dissector_handle_t docsis_ucd_handle;

static const value_string channel_tlv_vals[] = {
  {UCD_SYMBOL_RATE,  "Symbol Rate"},
  {UCD_FREQUENCY,    "Frequency"},
  {UCD_PREAMBLE,     "Preamble Pattern"},
  {UCD_BURST_DESCR,  "Burst Descriptor Type 4"},
  {UCD_BURST_DESCR5, "Burst Descriptor Type 5"},
  {UCD_EXT_PREAMBLE, "Extended Preamble Pattern"},
  {UCD_SCDMA_MODE_ENABLED, "S-CDMA Mode Enabled"},
  {UCD_SCDMA_SPREADING_INTERVAL, "S-CDMA Spreading Intervals per Frame"},
  {UCD_SCDMA_CODES_PER_MINI_SLOT, "S-CDMA Codes per Mini-slot"},
  {UCD_SCDMA_ACTIVE_CODES, "S-CDMA Number of Active Codes"},
  {UCD_SCDMA_CODE_HOPPING_SEED, "S-CDMA Code Hopping Seed"},
  {UCD_SCDMA_US_RATIO_NUM, "S-CDMA US ratio numerator M"},
  {UCD_SCDMA_US_RATIO_DENOM, "S-CDMA US ratio denominator N"},
  {UCD_SCDMA_TIMESTAMP_SNAPSHOT, "S-CDMA Timestamp Snapshot"},
  {UCD_MAINTAIN_POWER_SPECTRAL_DENSITY, "Maintain Power Spectral Density"},
  {UCD_RANGING_REQUIRED, "Ranging Required"},
  {UCD_MAX_SCHEDULED_CODES, "S-CDMA Maximum Scheduled Codes"},
  {UCD_RANGING_HOLD_OFF_PRIORITY_FIELD, "Ranging Hold-Off Priority Field"},
  {UCD_RANGING_CHANNEL_CLASS_ID, "Ranging Channel Class ID"},
  {UCD_SCDMA_SELECTION_ACTIVE_CODES_AND_CODE_HOPPING, "S-CDMA Selection Mode for Active Codes and Code Hopping"},
  {UCD_SCDMA_SELECTION_STRING_FOR_ACTIVE_CODES, "S-CDMA Selection String for Active Codes"},
  {UCD_HIGHER_UCD_FOR_SAME_UCID,        "Higher UCD for the same UCID present bitmap"},
  {UCD_BURST_DESCR23,                   "Burst Descriptor Type 23"},
  {UCD_CHANGE_IND_BITMASK,              "UCD Change Indicator Bitmask"},
  {UCD_OFDMA_TIMESTAMP_SNAPSHOT,        "OFDMA Timestamp Snapshot"},
  {UCD_OFDMA_CYCLIC_PREFIX_SIZE,        "OFDMA Cyclic Prefix Size"},
  {UCD_OFDMA_ROLLOFF_PERIOD_SIZE,       "OFDMA Rolloff Period Size"},
  {UCD_SUBCARRIER_SPACING,              "Subcarrier Spacing"},
  {UCD_CENTER_FREQ_SUBC_0,              "Center Frequency of Subcarrier 0"},
  {UCD_SUBC_EXCL_BAND,                  "Subcarrier Exclusion Band"},
  {UCD_UNUSED_SUBC_SPEC,                "Unused Subcarrier Specification"},
  {UCD_SYMB_IN_OFDMA_FRAME,             "Symbols in OFDMA frame"},
  {UCD_RAND_SEED,                       "Randomization Seed"},
  {0, NULL}
};

static const value_string burst_tlv_vals[] = {
  {UCD_MODULATION,                      "Modulation Type"},
  {UCD_DIFF_ENCODING,                   "Differential Encoding"},
  {UCD_PREAMBLE_LEN,                    "Preamble Length"},
  {UCD_PREAMBLE_VAL_OFF,                "Preamble Value Offset"},
  {UCD_FEC,                             "FEC Error Correction (T)"},
  {UCD_FEC_CODEWORD,                    "FEC Codeword Information Bytes (k)"},
  {UCD_SCRAMBLER_SEED,                  "Scrambler Seed"},
  {UCD_MAX_BURST,                       "Maximum Burst Size"},
  {UCD_GUARD_TIME,                      "Guard Time Size"},
  {UCD_LAST_CW_LEN,                     "Last Codeword Length"},
  {UCD_SCRAMBLER_ONOFF,                 "Scrambler on/off"},
  {UCD_RS_INT_DEPTH,                    "R-S Interleaver Depth (Ir)"},
  {UCD_RS_INT_BLOCK,                    "R-S Interleaver Block Size (Br)"},
  {UCD_PREAMBLE_TYPE,                   "Preamble Type"},
  {UCD_SCMDA_SCRAMBLER_ONOFF,           "S-CDMA Spreader on/off"},
  {UCD_SCDMA_CODES_PER_SUBFRAME,        "S-CDMA Codes per Subframe"},
  {UCD_SCDMA_FRAMER_INT_STEP_SIZE,      "S-CDMA Framer Interleaving Step Size"},
  {UCD_TCM_ENABLED,                     "TCM Encoding"},
  {UCD_SUBC_INIT_RANG,                  "Subcarriers (Nir) Initial Ranging"},
  {UCD_SUBC_FINE_RANG,                  "Subcarriers (Nfr) Initial Ranging"},
  {UCD_OFDMA_PROFILE,                   "OFDMA Profile"},
  {UCD_OFDMA_IR_POWER_CONTROL,          "OFDMA Power Control (Ir)"},
  {0, NULL}
};

static const value_string mgmt_type_vals[] = {
  {MGT_SYNC,           "Timing Synchronisation"},
  {MGT_UCD,            "Upstream Channel Descriptor"},
  {MGT_TYPE29UCD,      "Upstream Channel Descriptor Type 29"},
  {MGT_TYPE35UCD,      "Upstream Channel Descriptor Type 35"},
  {MGT_MAP,            "Upstream Bandwidth Allocation"},
  {MGT_RNG_REQ,        "Ranging Request"},
  {MGT_RNG_RSP,        "Ranging Response"},
  {MGT_REG_REQ,        "Registration Request"},
  {MGT_REG_RSP,        "Registration Response"},
  {MGT_UCC_REQ,        "Upstream Channel Change Request"},
  {MGT_UCC_RSP,        "Upstream Channel Change Response"},
  {MGT_TRI_TCD,        "Telephony Channel Descriptor"},
  {MGT_TRI_TSI,        "Termination System Information"},
  {MGT_BPKM_REQ,       "Privacy Key Management Request"},
  {MGT_BPKM_RSP,       "Privacy Key Management Response"},
  {MGT_REG_ACK,        "Registration Acknowledge"},
  {MGT_DSA_REQ,        "Dynamic Service Addition Request"},
  {MGT_DSA_RSP,        "Dynamic Service Addition Response"},
  {MGT_DSA_ACK,        "Dynamic Service Addition  Acknowledge"},
  {MGT_DSC_REQ,        "Dynamic Service Change Request"},
  {MGT_DSC_RSP,        "Dynamic Service Change Response"},
  {MGT_DSC_ACK,        "Dynamic Service Change Acknowledge"},
  {MGT_DSD_REQ,        "Dynamic Service Delete Request"},
  {MGT_DSD_RSP,        "Dynamic Service Delete Response"},
  {MGT_DCC_REQ,        "Dynamic Channel Change Request"},
  {MGT_DCC_RSP,        "Dynamic Channel Change Response"},
  {MGT_DCC_ACK,        "Dynamic Channel Change Acknowledge"},
  {MGT_DCI_REQ,        "Device Class Identification Request"},
  {MGT_DCI_RSP,        "Device Class Identification Response"},
  {MGT_UP_DIS,         "Upstream Channel Disable"},
  {MGT_INIT_RNG_REQ,   "Initial Ranging Request"},
  {MGT_TEST_REQ,       "Test Request Message"},
  {MGT_DS_CH_DESC,     "Downstream Channel Descriptor"},
  {MGT_MDD,            "MAC Domain Descriptor"},
  {MGT_B_INIT_RNG_REQ, "Bonded Initial Ranging Request"},
  {MGT_DBC_REQ,        "Dynamic Bonding Change Request"},
  {MGT_DBC_RSP,        "Dynamic Bonding Change Response"},
  {MGT_DBC_ACK,        "Dynamic Bonding Change Acknowledge"},
  {MGT_DPV_REQ,        "DOCSIS Path Verify Request"},
  {MGT_DPV_RSP,        "DOCSIS Path Verify Response"},
  {MGT_CM_STATUS,      "CM Status Report"},
  {MGT_CM_CTRL_REQ,    "CM Control Request"},
  {MGT_CM_CTRL_RSP,    "CM Control Response"},
  {MGT_REG_REQ_MP,     "Multipart Registration Request"},
  {MGT_REG_RSP_MP,     "Multipart Registration Response"},
  {MGT_EM_REQ,         "Energy Management Request"},
  {MGT_EM_RSP,         "Energy Management Response"},
  {MGT_STATUS_ACK,     "Status Report Acknowledge"},
  {MGT_OCD,            "OFDM Channel Descriptor"},
  {MGT_DPD,            "Downstream Profile Descriptor"},
  {0, NULL}
};

static const value_string on_off_vals[] = {
  {1, "On"},
  {2, "Off"},
  {0, NULL}
};

static const value_string inhibit_allow_vals[] = {
  {0, "Inhibit Initial Ranging"},
  {1, "Ranging Allowed"},
  {0, NULL},
};

static const value_string mod_vals[] = {
  {1, "QPSK"},
  {2, "16-QAM"},
  {3, "8-QAM"},
  {4, "32-QAM"},
  {5, "64-QAM"},
  {6, "128-QAM (SCDMA-only)"},
  {7, "Reserved for C-DOCSIS"},
  {0, NULL}
};

static const value_string iuc_vals[] = {
  {IUC_REQUEST,                  "Request"},
  {IUC_REQ_DATA,                 "REQ/Data"},
  {IUC_INIT_MAINT,               "Initial Maintenance"},
  {IUC_STATION_MAINT,            "Station Maintenance"},
  {IUC_SHORT_DATA_GRANT,         "Short Data Grant"},
  {IUC_LONG_DATA_GRANT,          "Long Data Grant"},
  {IUC_NULL_IE,                  "NULL IE"},
  {IUC_DATA_ACK,                 "Data Ack"},
  {IUC_ADV_PHY_SHORT_DATA_GRANT, "Advanced Phy Short Data Grant"},
  {IUC_ADV_PHY_LONG_DATA_GRANT,  "Advanced Phy Long Data Grant"},
  {IUC_ADV_PHY_UGS,              "Advanced Phy UGS"},
  {IUC_RESERVED12,               "Reserved"},
  {IUC_RESERVED13,               "Reserved"},
  {IUC_RESERVED14,               "Reserved"},
  {IUC_EXPANSION,                "Expanded IUC"},
  {0, NULL}
};

static const value_string last_cw_len_vals[] = {
  {1, "Fixed"},
  {2, "Shortened"},
  {0, NULL}
};

static const value_string ranging_req_vals[] = {
  {0, "No ranging required"},
  {1, "Unicast initial ranging required"},
  {2, "Broadcast initial ranging required"},
  {0, NULL}
};

static const value_string rng_stat_vals[] = {
  {1, "Continue"},
  {2, "Abort"},
  {3, "Success"},
  {0, NULL}
};

static const value_string rngrsp_tlv_vals[] = {
  {RNGRSP_TIMING,            "Timing Adjust (6.25us/64)"},
  {RNGRSP_PWR_LEVEL_ADJ,     "Power Level Adjust (0.25dB units)"},
  {RNGRSP_OFFSET_FREQ_ADJ,   "Offset Freq Adjust (Hz)"},
  {RNGRSP_TRANSMIT_EQ_ADJ,   "Transmit Equalisation Adjust"},
  {RNGRSP_RANGING_STATUS,    "Ranging Status"},
  {RNGRSP_DOWN_FREQ_OVER,    "Downstream Frequency Override (Hz)"},
  {RNGRSP_UP_CHID_OVER,      "Upstream Channel ID Override"},
  {0, NULL}
};

static const value_string code_field_vals[] = {
  { 0, "Reserved"},
  { 1, "Reserved"},
  { 2, "Reserved"},
  { 3, "Reserved"},
  { 4, "Auth Request"},
  { 5, "Auth Reply"},
  { 6, "Auth Reject"},
  { 7, "Key Request"},
  { 8, "Key Reply"},
  { 9, "Key Reject"},
  {10, "Auth Invalid"},
  {11, "TEK Invalid"},
  {12, "Authent Info"},
  {13, "Map Request"},
  {14, "Map Reply"},
  {15, "Map Reject"},
  {0, NULL},
};

static const value_string ds_mod_type_vals[] = {
  {0 , "64 QAM"},
  {1 , "256 QAM"},
  {0, NULL}
};

static const value_string ds_sym_rate_vals[] = {
  {0 , "5.056941 Msym/sec"},
  {1 , "5.360537 Msym/sec"},
  {2 , "6.952 Msym/sec"},
  {0, NULL}
};
static const value_string init_tech_vals[] = {
  {0 , "Reinitialize MAC"},
  {1 , "Broadcast Init RNG on new chanbefore normal op"},
  {2 , "Unicast RNG on new chan before normal op"},
  {3 , "Either Unicast or broadcast RNG on new chan before normal op"},
  {4 , "Use new chan directly without re-init or RNG"},
  {0, NULL}
};

static const value_string dcc_tlv_vals[] = {
  {DCCREQ_UP_CHAN_ID, "Up Channel ID"},
  {DCCREQ_DS_PARAMS, "Downstream Params Encodings"},
  {DCCREQ_INIT_TECH, "Initialization Technique"},
  {DCCREQ_UCD_SUB, "UCD Substitution"},
  {DCCREQ_SAID_SUB, "SAID Sub"},
  {DCCREQ_SF_SUB, "Service Flow Substitution Encodings"},
  {DCCREQ_CMTS_MAC_ADDR, "CMTS Mac Address"},
  {DCCREQ_KEY_SEQ_NUM, "Auth Key Sequence Number"},
  {DCCREQ_HMAC_DIGEST, "HMAC-DigestNumber"},
  {0, NULL}
};

static const value_string ds_param_subtlv_vals[] = {
  {DCCREQ_DS_FREQ, "Frequency"},
  {DCCREQ_DS_MOD_TYPE, "Modulation Type"},
  {DCCREQ_DS_SYM_RATE, "Symbol Rate"},
  {DCCREQ_DS_INTLV_DEPTH, "Interleaver Depth"},
  {DCCREQ_DS_CHAN_ID, "Downstream Channel ID"},
  {DCCREQ_DS_SYNC_SUB, "SYNC Substitution"},
  {DCCREQ_DS_OFDM_BLOCK_FREQ, "OFDM Block Frequency"},
  {0, NULL}
};

static const value_string sf_sub_subtlv_vals[] = {
  {DCCREQ_SF_SFID, "SFID"},
  {DCCREQ_SF_SID, "SID"},
  {DCCREQ_SF_UNSOL_GRANT_TREF, "Unsolicited Grant Time Reference"},
  {0, NULL}
};

static const value_string dccrsp_tlv_vals[] = {
  {DCCRSP_CM_JUMP_TIME, "CM Jump Time Encodings"},
  {DCCRSP_KEY_SEQ_NUM, "Auth Key Sequence Number"},
  {DCCRSP_HMAC_DIGEST, "HMAC-Digest Number"},
  {0, NULL}
};

static const value_string cm_jump_subtlv_vals[] = {
  {DCCRSP_CM_JUMP_TIME_LENGTH, "Length of Jump"},
  {DCCRSP_CM_JUMP_TIME_START, "Start Time of Jump"},
  {0, NULL}
};

static const value_string dccack_tlv_vals[] = {
  {DCCACK_HMAC_DIGEST, "HMAC-DigestNumber"},
  {DCCACK_KEY_SEQ_NUM, "Auth Key Sequence Number"},
  {0, NULL}
};

static const value_string max_scheduled_codes_vals[] = {
  {1, "Enabled"},
  {2, "Disabled"},
  {0, NULL}
};

static const value_string dcd_tlv_vals[] = {
  {DCD_DOWN_CLASSIFIER, "DCD_CFR Encodings"},
  {DCD_DSG_RULE, "DCD DSG Rule Encodings"},
  {DCD_DSG_CONFIG, "DCD DSG Config Encodings"},
  {0, NULL}
};

static const value_string dcd_down_classifier_vals[] = {
  {DCD_CFR_ID, "Downstream Classifier Id"},
  {DCD_CFR_RULE_PRI, "Downstream Classifier Rule Priority"},
  {DCD_CFR_IP_CLASSIFIER, "DCD_CFR_IP Encodings"},
  {0, NULL}
};

static const value_string dcd_dsg_rule_vals[] = {
  {DCD_RULE_ID, "DSG Rule Id"},
  {DCD_RULE_PRI, "DSG Rule Priority"},
  {DCD_RULE_UCID_RNG, "DSG Rule UCID Range"},
  {DCD_RULE_CLIENT_ID, "DCD Rule ClientID Encodings"},
  {DCD_RULE_TUNL_ADDR, "DSG Rule Tunnel MAC Address"},
  {DCD_RULE_CFR_ID, "DSG Rule Classifier ID"},
  {DCD_RULE_VENDOR_SPEC, "DSG Rule Vendor Specific Parameters"},
  {0, NULL}
};

static const value_string dcd_clid_vals[] = {
  {DCD_CLID_BCAST_ID, "DSG Rule Client ID Broadcast ID"},
  {DCD_CLID_KNOWN_MAC_ADDR, "DSG Rule Client ID Known MAC Address"},
  {DCD_CLID_CA_SYS_ID, "DSG Rule Client ID CA System ID"},
  {DCD_CLID_APP_ID, "DSG Rule Client ID Application ID"},
  {0, NULL}
};

static const value_string dcd_cfr_ip_vals[] = {
  {DCD_CFR_IP_SOURCE_ADDR, "Downstream Classifier IP Source Address"},
  {DCD_CFR_IP_SOURCE_MASK, "Downstream Classifier IP Source Mask"},
  {DCD_CFR_IP_DEST_ADDR, "Downstream Classifier IP Destination Address"},
  {DCD_CFR_IP_DEST_MASK, "Downstream Classifier IP Destination Mask"},
  {DCD_CFR_TCPUDP_SRCPORT_START, "Downstream Classifier IP TCP/UDP Source Port Start"},
  {DCD_CFR_TCPUDP_SRCPORT_END, "Downstream Classifier IP TCP/UDP Source Port End"},
  {DCD_CFR_TCPUDP_DSTPORT_START, "Downstream Classifier IP TCP/UDP Destination Port Start"},
  {DCD_CFR_TCPUDP_DSTPORT_END, "Downstream Classifier IP TCP/UDP Destination Port End"},
  {0, NULL}
};

static const value_string dcd_cfg_vals[] = {
  {DCD_CFG_CHAN_LST, "DSG Configuration Channel"},
  {DCD_CFG_TDSG1, "DSG Initialization Timeout (Tdsg1)"},
  {DCD_CFG_TDSG2, "DSG Initialization Timeout (Tdsg2)"},
  {DCD_CFG_TDSG3, "DSG Initialization Timeout (Tdsg3)"},
  {DCD_CFG_TDSG4, "DSG Initialization Timeout (Tdsg4)"},
  {DCD_CFG_VENDOR_SPEC, "DSG Configuration Vendor Specific Parameters"},
  {0, NULL}
};

static const value_string J83_annex_vals[] = {
  {J83_ANNEX_A, "J.83 Annex A"},
  {J83_ANNEX_B, "J.83 Annex B"},
  {J83_ANNEX_C, "J.83 Annex C"},
  {0, NULL}
};

static const value_string modulation_order_vals[] = {
  {QAM64,  "64 QAM"},
  {QAM256, "256 QAM"},
  {0, NULL}
};

static const value_string primary_capable_vals[] = {
  {NOT_PRIMARY_CAPABLE, "Channel is not primary-capable"},
  {PRIMARY_CAPABLE,     "channel is primary-capable"},
  {0, NULL}
};

static const value_string map_ucd_transport_indicator_vals[] = {
  {CANNOT_CARRY_MAP_UCD, "Channel cannot carry MAPs and UCDs for the MAC domain for which the MDD is sent"},
  {CAN_CARRY_MAP_UCD,    "Channel can carry MAPs and UCDs for the MAC domain for which the MDD is sent"},
  {0, NULL}
};

static const value_string tukey_raised_cosine_vals[] = {
  {TUKEY_0TS,   "0 microseconds (0 * Ts)"},
  {TUKEY_64TS,  "0.3125 microseconds (64 * Ts)"},
  {TUKEY_128TS, "0.625 microseconds (128 * Ts)"},
  {TUKEY_192TS, "0.9375 microseconds (192 * Ts)"},
  {TUKEY_256TS, "1.25 microseconds (256 * Ts)"},
  {0, NULL}
};

static const value_string cyclic_prefix_vals[] = {
  {CYCLIC_PREFIX_192_TS,  "0.9375 microseconds (192 * Ts)"},
  {CYCLIC_PREFIX_256_TS,  "1.25 microseconds (256 * Ts)"},
  {CYCLIC_PREFIX_512_TS,  "2.5 microseconds (512 * Ts) 3"},
  {CYCLIC_PREFIX_768_TS,  "3.75 microseconds (768 * Ts)"},
  {CYCLIC_PREFIX_1024_TS, "5 microseconds (1024 * Ts)"},
  {0, NULL}
};

static const value_string spacing_vals[] = {
  {SPACING_25KHZ, "25Khz"},
  {SPACING_50KHZ, "50Khz"},
  {0, NULL}
};

static const value_string bpkmattr_tlv_vals[] = {
  {BPKM_RESERVED,           "Reserved"},
  {BPKM_SERIAL_NUM,         "Serial Number"},
  {BPKM_MANUFACTURER_ID,    "Manufacturer Id"},
  {BPKM_MAC_ADDR,           "Mac Address"},
  {BPKM_RSA_PUB_KEY,        "RSA Public Key"},
  {BPKM_CM_ID,              "CM Identification"},
  {BPKM_DISPLAY_STR,        "Display String"},
  {BPKM_AUTH_KEY,           "Auth Key"},
  {BPKM_TEK,                "Traffic Encryption Key"},
  {BPKM_KEY_LIFETIME,       "Key Lifetime"},
  {BPKM_KEY_SEQ_NUM,        "Key Sequence Number"},
  {BPKM_HMAC_DIGEST,        "HMAC Digest"},
  {BPKM_SAID,               "SAID"},
  {BPKM_TEK_PARAM,          "TEK Parameters"},
  {BPKM_OBSOLETED,          "Obsoleted"},
  {BPKM_CBC_IV,             "CBC IV"},
  {BPKM_ERROR_CODE,         "Error Code"},
  {BPKM_CA_CERT,            "CA Certificate"},
  {BPKM_CM_CERT,            "CM Certificate"},
  {BPKM_SEC_CAPABILITIES,   "Security Capabilities"},
  {BPKM_CRYPTO_SUITE,       "Cryptographic Suite"},
  {BPKM_CRYPTO_SUITE_LIST,  "Cryptographic Suite List"},
  {BPKM_BPI_VERSION,        "BPI Version"},
  {BPKM_SA_DESCRIPTOR,      "SA Descriptor"},
  {BPKM_SA_TYPE,            "SA Type"},
  {BPKM_SA_QUERY,           "SA Query"},
  {BPKM_SA_QUERY_TYPE,      "SA Query Type"},
  {BPKM_IP_ADDRESS,         "IP Address"},
  {BPKM_DNLD_PARAMS,        "Download Parameters"},
  {BPKM_VENDOR_DEFINED,     "Vendor Defined"},
  {0, NULL}
};

static const value_string error_code_vals[] = {
  {0, "No Information"},
  {1, "Unauthorized CM"},
  {2, "Unauthorized SAID"},
  {3, "Unsolicited"},
  {4, "Invalid Key Sequence Number"},
  {5, "Message (Key Request) authentication failure"},
  {6, "Permanent Authorization Failure"},
  {7, "Not authorized for requested downstream traffic flow"},
  {8, "Downstream traffic flow not mapped to SAID"},
  {9, "Time of day not acquired"},
  {10, "EAE Disabled"},
  {0, NULL},
};

static const value_string crypto_suite_attr_vals[] = {
  {0x0100, "CBC-Mode 56-bit DES, no data authentication"},
  {0x0200, "CBC-Mode 40-bit DES, no data authentication"},
  {0x0300, "CBC-Mode 128-bit AES, no data authentication"},
  {0, NULL},
};

static const value_string bpi_ver_vals[] = {
  {0, "Reserved"},
  {1, "BPI+"},
  {0, NULL},
};

static const value_string mdd_tlv_vals[] = {
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST,                       "Downstream Active Channel List"},
  {MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP,                  "Mac Domain Downstream Service Group"},
  {DOWNSTREAM_AMBIGUITY_RESOLUTION_FREQUENCY_LIST,       "Downstream Ambiguity Resolution Frequency List "},
  {RECEIVE_CHANNEL_PROFILE_REPORTING_CONTROL ,           "Receive Channel Profile Reporting Control"},
  {IP_INITIALIZATION_PARAMETERS ,                        "IP Initialization Parameters"},
  {EARLY_AUTHENTICATION_AND_ENCRYPTION ,                 "Early Authentication and Encryption"},
  {UPSTREAM_ACTIVE_CHANNEL_LIST ,                        "Upstream Active Channel List"},
  {UPSTREAM_AMBIGUITY_RESOLUTION_CHANNEL_LIST ,          "Upstream Ambiguity Resolution Channel List"},
  {UPSTREAM_FREQUENCY_RANGE  ,                           "Upstream Frequency Range"},
  {SYMBOL_CLOCK_LOCKING_INDICATOR  ,                     "Symbol Clock Locking Indicator"},
  {CM_STATUS_EVENT_CONTROL  ,                            "CM-STATUS Event Control"},
  {UPSTREAM_TRANSMIT_POWER_REPORTING  ,                  "Upstream Transmit Power Reporting"},
  {DSG_DA_TO_DSID_ASSOCIATION_ENTRY  ,                   "DSG DA-to-DSID Association Entry"},
  {CM_STATUS_EVENT_ENABLE_NON_CHANNEL_SPECIFIC_EVENTS  , "CM-STATUS Event Enable for Non-Channel-Specific-Events"},
  {EXTENDED_UPSTREAM_TRANSMIT_POWER_SUPPORT  ,           "Extended Upstream Transmit Power Support"},
  {0, NULL}
};


static const value_string rpc_center_frequency_spacing_vals[] = {
  {ASSUME_6MHZ_CENTER_FREQUENCY_SPACING  , "CM MUST report only Receive Channel Profiles assuming 6 MHz center frequency spacing"},
  {ASSUME_8MHZ_CENTER_FREQUENCY_SPACING  , "CM MUST report only Receive Channel Profiles assuming 8 MHz center frequency spacing"},
  {0, NULL}
};

static const value_string verbose_rpc_reporting_vals[] = {
  {RCP_NO_VERBOSE_REPORTING  , "CM MUST NOT provide verbose reporting of all its Receive Channel Profile(s) (both standard profiles and manufacturers profiles)."},
  {RCP_VERBOSE_REPORTING  ,    "CM MUST provide verbose reporting of Receive Channel Profile(s) (both standard profiles and manufacturers profiles)."},
  {0, NULL}
};

static const value_string ip_provisioning_mode_vals[] = {
  {IPv4_ONLY  ,  "IPv4 Only"},
  {IPv6_ONLY ,   "IPv6 Only"},
  {IP_ALTERNATE, "Alternate"},
  {DUAL_STACK ,  "Dual Stack"},
  {0, NULL}
};

static const value_string eae_vals[] = {
  {EAE_DISABLED  , "early authentication and encryption disabled"},
  {EAE_ENABLED ,   "early authentication and encryption enabled"},
  {0, NULL}
};

static const value_string upstream_frequency_range_vals[] = {
  {STANDARD_UPSTREAM_FREQUENCY_RANGE, "Standard Upstream Frequency Range"},
  {EXTENDED_UPSTREAM_FREQUENCY_RANGE, "Extended Upstream Frequency Range"},
  {0, NULL}
};

static const value_string symbol_clock_locking_indicator_vals[] = {
  {NOT_LOCKED_TO_MASTER_CLOCK, "Symbol Clock is not locked to Master Clock"},
  {LOCKED_TO_MASTER_CLOCK,     "Symbol Clock is locked to Master Clock"},
  {0, NULL}
};

static const value_string symbol_cm_status_event_vals[] = {
  {SECONDARY_CHANNEL_MDD_TIMEOUT,               "Secondary Channel MDD timeout"},
  {QAM_FEC_LOCK_FAILURE,                        "Qam FEC Lock Failure"},
  {SEQUENCE_OUT_OF_RANGE,                       "Sequence out of Range"},
  {MDD_RECOVERY,                                "MDD Recovery"},
  {QAM_FEC_LOCK_RECOVERY,                       "Qam FEC Lock Recovery"},
  {T4_TIMEOUT,                                  "T4 Timeout"},
  {T3_RETRIES_EXCEEDED,                         "T3 Retries Exceeded"},
  {SUCCESFUL_RANGING_AFTER_T3_RETRIES_EXCEEDED, "Successful ranging after T3 Retries Exceeded"},
  {CM_OPERATING_ON_BATTERY_BACKUP,              "CM Operating on Battery Backup"},
  {CM_RETURNED_TO_AC_POWER,                     "CM Returned to AC Power"},
  {0, NULL}
};

static const value_string upstream_transmit_power_reporting_vals[] = {
  {CM_DOESNT_REPORT_TRANSMIT_POWER, "CM does not report transmit power in RNG-REQ, INIT-RNG-REQ, and B-INIT-RNG-REQ messages"},
  {CM_REPORTS_TRANSMIT_POWER,       "CM reports transmit power in RNG-REQ, INIT-RNG-REQ, and B-INIT-RNG-REQ messages"},
  {0, NULL}
};

static const value_string mdd_ds_active_channel_list_vals[] = {
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_CHANNEL_ID, "Channel ID"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_FREQUENCY, "Frequency"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_MODULATION_ORDER_ANNEX, "Annex/Modulation Order"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_PRIMARY_CAPABLE, "Primary Capable"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK, "CM-STATUS Event Enable Bitmask"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_MAP_UCD_TRANSPORT_INDICATOR, "MAP and UCD transport indicator"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_OFDM_PLC_PARAMETERS, "OFDM PLC Parameters"},
  {0, NULL}
};

static const value_string mdd_ds_service_group_vals[] = {
  {MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_MD_DS_SG_IDENTIFIER, "MD-DS-SG Identifier"},
  {MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_CHANNEL_IDS,       "Channel Ids"},
  {0, NULL}
};

static const value_string mdd_channel_profile_reporting_control_vals[] = {
  {RCP_CENTER_FREQUENCY_SPACING, "RPC Center Frequency Spacing"},
  {VERBOSE_RCP_REPORTING,       "Verbose RCP reporting"},
  {0, NULL}
};

static const value_string mdd_ip_init_param_vals[] = {
  {IP_PROVISIONING_MODE, "IP Provisioning Mode"},
  {PRE_REGISTRATION_DSID, "Pre-registration DSID"},
  {0, NULL}
};

static const value_string mdd_up_active_channel_list_vals[] = {
  {UPSTREAM_ACTIVE_CHANNEL_LIST_UPSTREAM_CHANNEL_ID, "Upstream Channel Id"},
  {UPSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK, "CM-STATUS Event Enable Bitmask"},
  {0, NULL}
};

static const value_string mdd_cm_status_event_control_vals[] = {
  {EVENT_TYPE_CODE, "Event Type"},
  {MAXIMUM_EVENT_HOLDOFF_TIMER,    "Maximum Event Holdoff Timer"},
  {MAXIMUM_NUMBER_OF_REPORTS_PER_EVENT,    "Maximum Number of Reports per Event"},
  {0, NULL}
};

static const value_string mdd_cm_dsg_da_to_dsid_vals[] = {
  {DSG_DA_TO_DSID_ASSOCIATION_DA, "Destination Address"},
  {DSG_DA_TO_DSID_ASSOCIATION_DSID, "DSID"},
  {0, NULL}
};

static const value_string tlv20_vals[] = {
  {0, "Selectable active codes mode 1 enabled and code hopping disabled"},
  {1, "Selectable active codes mode 1 enabled and code hopping mode 1 enabled"},
  {2, "Selectable active codes mode 2 enabled and code hopping mode 2 enabled"},
  {3, "Selectable active codes mode 2 enabled and code hopping disabled"},
  {0, NULL}
};

static const value_string cmstatus_tlv_vals[] = {
  {EVENT_DS_CH_ID, "Downstream Channel ID"},
  {EVENT_US_CH_ID, "Upstream Channel ID"},
  {EVENT_DSID, "DSID"},
  {EVENT_DESCR, "Description"},
  {0, NULL}
};

static const value_string cmctrlreq_tlv_vals[] = {
  {CM_CTRL_MUTE, "Upstream Channel RF Mute"},
  {CM_CTRL_MUTE_TIMEOUT, "RF Mute Timeout Interval"},
  {CM_CTRL_REINIT, "CM Reinitialize"},
  {CM_CTRL_DISABLE_FWD, "Disable Forwarding"},
  {CM_CTRL_DS_EVENT, "Override Downstream Events"},
  {CM_CTRL_US_EVENT, "Override Upstream Events"},
  {CM_CTRL_EVENT, "Override Non-Channel-Specific Events"},
  {0, NULL}
};

static const value_string cmctrlreq_us_tlv_vals[] = {
  {US_EVENT_CH_ID, "Upstream Channel ID"},
  {US_EVENT_MASK, "Upstream Status Event Enable Bitmask"},
  {0, NULL}
};

static const value_string cmctrlreq_ds_tlv_vals[] = {
  {DS_EVENT_CH_ID, "Downstream Channel ID"},
  {DS_EVENT_MASK,  "Downstream Status Event Enable Bitmask"},
  {0, NULL}
};


static const value_string docsis_ocd_subc_assign_type_str[] = {
  {0, "range, continuous"},
  {1, "range, skip by 1"},
  {2, "list"},
  {3, "reserved"},
  {0, NULL}
};

static const value_string docsis_ocd_subc_assign_value_str[] = {
  {0, "specific value"},
  {1, "default value"},
  {0, NULL}
};

static const value_string docsis_ocd_subc_assign_subc_type_str[] = {
  {1, "continuous pilot"},
  {16, "excluded subcarriers"},
  {20, "PLC, 16-QAM"},
  {0, NULL}
};

static const value_string docsis_ocd_four_trans_size[] = {
  {0, "4096 subcarriers at 50 kHz spacing"},
  {1, "8192 subcarriers at 25 kHz spacing"},
  {0, NULL}
};

static const value_string docsis_ocd_cyc_prefix[] = {
  {0, "0.9375 "UTF8_MICRO_SIGN"s with 192 samples"},
  {1, "1.25 "UTF8_MICRO_SIGN"s with 256 samples"},
  {2, "2.5 "UTF8_MICRO_SIGN"s with 512 samples"},
  {3, "3.75 "UTF8_MICRO_SIGN"s with 768 samples"},
  {4, "5.0 "UTF8_MICRO_SIGN"s with 1024 samples"},
  {0, NULL}
};

static const value_string docsis_ocd_roll_off[] = {
  {0, "0 "UTF8_MICRO_SIGN"s with 0 samples"},
  {1, "0.3125 "UTF8_MICRO_SIGN"s with 64 samples"},
  {2, "0.625 "UTF8_MICRO_SIGN"s with 128 samples"},
  {3, "0.9375 "UTF8_MICRO_SIGN"s with 192 samples"},
  {4, "1.25 "UTF8_MICRO_SIGN"s with 256 samples"},
  {0, NULL}
};

static const value_string docsis_ocd_prim_cap_ind_str[] = {
  {0, "channel is not primary capable"},
  {1, "channel is primary capable"},
  {0, NULL}
};

static const value_string ocd_tlv_vals[] = {
  {DISCRETE_FOURIER_TRANSFORM_SIZE, "Discrete Fourier Transform Size"},
  {CYCLIC_PREFIX, "Cylic Prefix"},
  {ROLL_OFF, "Roll Off"},
  {OFDM_SPECTRUM_LOCATION, "OFDM Spectrum Location"},
  {TIME_INTERLEAVING_DEPTH, "Time Interleaving Depth"},
  {SUBCARRIER_ASSIGNMENT_RANGE_LIST, "Subcarrier Assignment Range/List"},
  {PRIMARY_CAPABILITY_INDICATOR, "Primary Capable Indicator"},
  {0, NULL}
};

static const value_string docsis_dpd_subc_assign_type_str[] = {
  {0, "range, continuous"},
  {1, "range, skip by 1"},
  {2, "list"},
  {3, "reserved"},
  {0, NULL}
};

static const value_string docsis_dpd_subc_assign_value_str[] = {
  {0, "specific value"},
  {1, "default value"},
  {0, NULL}
};

static const value_string docsis_dpd_subc_assign_modulation_str[] = {
  {0, "zero-bit loaded"},
  {1, "reserved"},
  {2, "QPSK (for NPC profile only)"},
  {3, "reserved"},
  {4, "16-QAM"},
  {5, "reserved"},
  {6, "64-QAM"},
  {7, "128-QAM"},
  {8, "256-QAM"},
  {9, "512-QAM"},
  {10, "1024-QAM"},
  {11, "2048-QAM"},
  {12, "4096-QAM"},
  {13, "8192-QAM"},
  {14, "16384-QAM"},
  {15, "reserved"},
  {0, NULL}
};

static const value_string docsis_dpd_tlv_subc_assign_vector_oddness_str[] = {
  {0, "N is even"},
  {1, "N is odd"},
  {0, NULL}
};

static const value_string docsis_dpd_tlv_subc_assign_vector_modulation_str[] = {
  {0, "zero-bit loaded"},
  {1, "continuous pilot"},
  {2, "QPSK (for NPC profile only)"},
  {3, "reserved"},
  {4, "16-QAM"},
  {5, "reserved"},
  {6, "64-QAM"},
  {7, "128-QAM"},
  {8, "256-QAM"},
  {9, "512-QAM"},
  {10, "1024-QAM"},
  {11, "2048-QAM"},
  {12, "4096-QAM"},
  {13, "8192-QAM"},
  {14, "16384-QAM"},
  {15, "reserved"},
  {0, NULL}
};

static const value_string dpd_tlv_vals[] = {
  {SUBCARRIER_ASSIGNMENT_RANGE_LIST, "Subcarrier Assignment Range/List"},
  {SUBCARRIER_ASSIGNMENT_VECTOR, "Subcarrier Assignment Vector"},
  {0, NULL}
};

static const value_string ofdma_cyclic_prefix_size_vals[] = {
  {1, "96 samples"},
  {2, "128 samples"},
  {3, "160 samples"},
  {4, "192 samples"},
  {5, "224 samples"},
  {6, "256 samples"},
  {7, "288 samples"},
  {8, "320 samples"},
  {9, "384 samples"},
  {10, "512 samples"},
  {11, "640 samples"},
  {0, NULL}
};

static const value_string ofdma_rolloff_period_size_vals[] = {
  {1, "0 samples"},
  {2, "32 samples"},
  {3, "64 samples"},
  {4, "96 samples"},
  {5, "128 samples"},
  {6, "160 samples"},
  {7, "192 samples"},
  {8, "224 samples"},
  {0, NULL}
};

static const value_string subc_spacing_vals[] = {
  {1, "25 kHz (corresponds to 4096 subcarriers and 16 subcarriers per minislot)"},
  {2, "50 kHz (corresponds to 2048 subcarriers and 8 subcarriers per minislot)"},
  {0, NULL}
};

static const value_string ofdma_prof_mod_order[] = {
  {1, "BPSK"},
  {2, "QPSK"},
  {3, "8-QAM"},
  {4, "16-QAM"},
  {5, "32-QAM"},
  {6, "64-QAM"},
  {7, "128-QAM"},
  {8, "256-QAM"},
  {9, "512-QAM"},
  {10, "1024-QAM"},
  {11, "2048-QAM"},
  {12, "4096-QAM"},
  {0, NULL}
};

/* Windows does not allow data copy between dlls */
static const true_false_string mdd_tfs_on_off = { "On", "Off" };
static const true_false_string tfs_ucd_change_ind_vals = {"Changes", "No changes"};

static const true_false_string tfs_allow_inhibit = { "Inhibit Initial Ranging", "Ranging Allowed" };
const true_false_string type35ucd_tfs_present_not_present = { "UCD35 is present for this UCID",
                                                              "UCD35 is not present for this UCID" };

static const value_string unique_unlimited[] = {
  { 0, "Unlimited" },
  {0, NULL}
};

static const unit_name_string local_units_hz = { "Hz", NULL };

static void
ofdma_ir_pow_ctrl_start_pow(char *buf, guint32 value)
{
    g_snprintf(buf, ITEM_LABEL_LENGTH, "%f dBmV/1.6MHz", value/4.0);
}

static void
ofdma_ir_pow_ctrl_step_size(char *buf, guint32 value)
{
    g_snprintf(buf, ITEM_LABEL_LENGTH, "%f dB", value/4.0);
}

static void
subc_assign_range(char *buf, guint32 value)
{
    g_snprintf(buf, ITEM_LABEL_LENGTH, "%u - %u", value >> 16, value &0xFFFF);
}

static int
dissect_sync (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *sync_tree;

  col_set_str(pinfo->cinfo, COL_INFO, "Sync Message");

  it = proto_tree_add_item(tree, proto_docsis_sync, tvb, 0, -1, ENC_NA);
  sync_tree = proto_item_add_subtree (it, ett_docsis_sync);

  proto_tree_add_item (sync_tree, hf_docsis_sync_cmts_timestamp, tvb, 0, 4, ENC_BIG_ENDIAN);

  return tvb_captured_length(tvb);
}

static void
dissect_ucd_burst_descr(tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int pos, guint16 len)
{
  int tlvpos, endtlvpos;
  guint8 tlvtype;
  guint32 i, tlvlen;
  proto_tree *burst_tree;
  proto_item *burst_item, *burst_len_item;

  tlvpos = pos;
  endtlvpos = tlvpos + len;
  proto_tree_add_item (tree, hf_docsis_ucd_iuc, tvb, tlvpos++, 1, ENC_BIG_ENDIAN);
  while (tlvpos < endtlvpos)
  {
    tlvtype = tvb_get_guint8 (tvb, tlvpos);
    burst_tree = proto_tree_add_subtree (tree, tvb, tlvpos, -1,
                                                        ett_docsis_burst_tlv, &burst_item,
                                                        val_to_str(tlvtype, burst_tlv_vals,
                                                        "Unknown TLV (%u)"));
    proto_tree_add_uint (burst_tree, hf_docsis_ucd_burst_type, tvb, tlvpos++, 1, tlvtype);
    burst_len_item = proto_tree_add_item_ret_uint (burst_tree, hf_docsis_ucd_burst_length, tvb, tlvpos++, 1, ENC_NA, &tlvlen);
    proto_item_set_len(burst_item, tlvlen + 2);
    switch (tlvtype)
    {
    case UCD_MODULATION:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_mod_type, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_DIFF_ENCODING:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_diff_encoding, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_PREAMBLE_LEN:
      if (tlvlen == 2)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_preamble_len, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_PREAMBLE_VAL_OFF:
      if (tlvlen == 2)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_preamble_val_off, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_FEC:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_fec, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_FEC_CODEWORD:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_fec_codeword, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_SCRAMBLER_SEED:
      if (tlvlen == 2)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_scrambler_seed, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_MAX_BURST:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_max_burst, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_GUARD_TIME:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_guard_time, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_LAST_CW_LEN:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_last_cw_len, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_SCRAMBLER_ONOFF:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_scrambler_onoff, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_RS_INT_DEPTH:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_rs_int_depth, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_RS_INT_BLOCK:
      if (tlvlen == 2)
      {
        proto_tree_add_item (burst_tree, hf_docsis_rs_int_block, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_PREAMBLE_TYPE:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_preamble_type, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_SCMDA_SCRAMBLER_ONOFF:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_ucd_scdma_scrambler_onoff, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_SCDMA_CODES_PER_SUBFRAME:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_ucd_scdma_codes_per_subframe, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_SCDMA_FRAMER_INT_STEP_SIZE:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_ucd_scdma_framer_int_step_size, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_TCM_ENABLED:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_ucd_tcm_enabled, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_SUBC_INIT_RANG:
      if (tlvlen == 2)
      {
        proto_tree_add_item (burst_tree, hf_docsis_subc_init_rang, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_SUBC_FINE_RANG:
      if (tlvlen == 2)
      {
        proto_tree_add_item (burst_tree, hf_docsis_subc_fine_rang, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_OFDMA_PROFILE:
      if ((tlvlen % 2) == 0)
      {
        for(i =0; i < tlvlen; i+=2) {
          proto_tree_add_item (burst_tree, hf_docsis_ofdma_prof_mod_order, tvb, pos + i, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item (burst_tree, hf_docsis_ofdma_prof_pilot_pattern, tvb, pos + i, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item (burst_tree, hf_docsis_ofdma_prof_num_add_minislots, tvb, pos + i + 1, 1, ENC_BIG_ENDIAN);
        }
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u (even length expected)", tlvlen);
      }
      break;
    case UCD_OFDMA_IR_POWER_CONTROL:
      if (tlvlen == 2)
      {
        proto_tree_add_item (burst_tree, hf_docsis_ofdma_ir_pow_ctrl_start_pow, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        proto_tree_add_item (burst_tree, hf_docsis_ofdma_ir_pow_ctrl_step_size, tvb, pos + 1, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;

    } /* switch(tlvtype) */

  tlvpos += tlvlen;
  } /* while (tlvpos < endtlvpos) */

}

static int
dissect_any_ucd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int proto_id, int type_number)
{
  int pos;
  guint32 i, upchid, length;
  guint8 type, symrate;
  proto_tree *ucd_tree, *tlv_tree;
  proto_item *ucd_item, *tlv_item, *tlv_len_item;

  ucd_item = proto_tree_add_item(tree, proto_id, tvb, 0, -1, ENC_NA);
  ucd_tree = proto_item_add_subtree (ucd_item, ett_docsis_ucd);
  proto_tree_add_item_ret_uint (ucd_tree, hf_docsis_mgt_upstream_chid, tvb, 0, 1, ENC_BIG_ENDIAN, &upchid);
  proto_tree_add_item (ucd_tree, hf_docsis_ucd_config_ch_cnt, tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (ucd_tree, hf_docsis_ucd_mini_slot_size, tvb, 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (ucd_tree, hf_docsis_mgt_down_chid, tvb, 3, 1, ENC_BIG_ENDIAN);

  /* if the upstream Channel ID is 0 then this is for Telephony Return) */
  if (upchid > 0)
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Type %d UCD Message: Channel ID = %u (U%u)", type_number, upchid,
                  upchid - 1);
  else
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Type %d UCD Message: Channel ID = %u (Telephony Return)",
                  type_number, upchid);

  pos = 4;
  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_guint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(ucd_tree, tvb, pos, -1,
                                            ett_docsis_tlv, &tlv_item,
                                            val_to_str(type, channel_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_ucd_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_ucd_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case UCD_SYMBOL_RATE:
      if (length == 1)
      {
        symrate = tvb_get_guint8 (tvb, pos);
        proto_tree_add_uint (tlv_tree, hf_docsis_ucd_symbol_rate, tvb, pos, length, symrate * 160);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_FREQUENCY:
      if (length == 4)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_frequency, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_PREAMBLE:
      proto_tree_add_item (tlv_tree, hf_docsis_ucd_preamble_pat, tvb, pos, length, ENC_NA);
      break;
    case UCD_BURST_DESCR:
    case UCD_BURST_DESCR5: /* DOCSIS 2.0 Upstream Channel Descriptor */
    case UCD_BURST_DESCR23:
      dissect_ucd_burst_descr(tvb, pinfo, tlv_tree, pos, length);
      break;
    case UCD_EXT_PREAMBLE:
      proto_tree_add_item (tlv_tree, hf_docsis_ucd_ext_preamble_pat, tvb, pos, length, ENC_NA);
      break;
    case UCD_SCDMA_MODE_ENABLED:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_mode_enabled, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_SPREADING_INTERVAL:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_spreading_interval, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_CODES_PER_MINI_SLOT:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_codes_per_mini_slot, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_ACTIVE_CODES:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_active_codes, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_CODE_HOPPING_SEED:
      if (length == 2)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_code_hopping_seed, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_US_RATIO_NUM:
      if (length == 2)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_us_ratio_num, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_US_RATIO_DENOM:
      if (length == 2)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_us_ratio_denom, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_TIMESTAMP_SNAPSHOT:
      if (length == 9)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_timestamp_snapshot, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_MAINTAIN_POWER_SPECTRAL_DENSITY:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_maintain_power_spectral_density, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_RANGING_REQUIRED:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_ranging_required, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_MAX_SCHEDULED_CODES:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_max_scheduled_codes, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_RANGING_HOLD_OFF_PRIORITY_FIELD:
      if (length == 4)
      {
        static const int * ucd_rnghoff[] = {
          &hf_docsis_ucd_rnghoff_cm,
          &hf_docsis_ucd_rnghoff_erouter,
          &hf_docsis_ucd_rnghoff_emta,
          &hf_docsis_ucd_rnghoff_estb,
          &hf_docsis_ucd_rnghoff_rsvd,
          &hf_docsis_ucd_rnghoff_id_ext,
          NULL
        };

        proto_tree_add_bitmask_list(tlv_tree, tvb, pos, length, ucd_rnghoff, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_RANGING_CHANNEL_CLASS_ID:
      if (length == 4)
      {
        static const int * ucd_chan_class_id[] = {
          &hf_docsis_ucd_chan_class_id_cm,
          &hf_docsis_ucd_chan_class_id_erouter,
          &hf_docsis_ucd_chan_class_id_emta,
          &hf_docsis_ucd_chan_class_id_estb,
          &hf_docsis_ucd_chan_class_id_rsvd,
          &hf_docsis_ucd_chan_class_id_id_ext,
          NULL
        };

        proto_tree_add_bitmask_list(tlv_tree, tvb, pos, length, ucd_chan_class_id, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_SELECTION_ACTIVE_CODES_AND_CODE_HOPPING:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_active_code_hopping, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_SELECTION_STRING_FOR_ACTIVE_CODES:
      if (length == 16)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_selection_active_codes, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_HIGHER_UCD_FOR_SAME_UCID:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_higher_ucd_for_same_ucid, tvb, pos, length, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_higher_ucd_for_same_ucid_resv, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_CHANGE_IND_BITMASK:
      if (length == 2)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_subc_excl_band, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_unused_subc, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_other_subc, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc5, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc6, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc9, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc10, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc11, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc12, tvb, pos, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc13, tvb, pos, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc3_or_4, tvb, pos, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_reserved, tvb, pos, 1, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_OFDMA_TIMESTAMP_SNAPSHOT:
      if (length == 9)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_ofdma_timestamp_snapshot, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_OFDMA_CYCLIC_PREFIX_SIZE:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_ofdma_cyclic_prefix_size, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_OFDMA_ROLLOFF_PERIOD_SIZE:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_ofdma_rolloff_period_size, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SUBCARRIER_SPACING:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_subc_spacing, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_CENTER_FREQ_SUBC_0:
      if (length == 4)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_cent_freq_subc0, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SUBC_EXCL_BAND:
      if ((length % 4) == 0)
      {
        for(i = 0; i < length; i+=4) {
          proto_tree_add_item (tlv_tree, hf_docsis_ucd_subcarrier_range, tvb, pos+i, 4, ENC_NA);
        }
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_UNUSED_SUBC_SPEC:
      if ((length % 4) == 0)
      {
        for(i = 0; i < length; i+=4) {
          proto_tree_add_item (tlv_tree, hf_docsis_ucd_subcarrier_range, tvb, pos+i, 4, ENC_NA);
        }
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SYMB_IN_OFDMA_FRAME:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_symb_ofdma_frame, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_RAND_SEED:
      if (length == 3)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_rand_seed, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }    /* switch(type) */
    pos += length;
  }      /* tvb_reported_length_remaining(tvb, pos) > 0 */

  return tvb_captured_length(tvb);
}

static int
dissect_ucd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  return dissect_any_ucd(tvb, pinfo, tree, proto_docsis_ucd, MGT_UCD);
}

static int
dissect_map (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  guint32 i, numie, upchid, ucd_count;
  int pos;
  proto_item *it;
  proto_tree *map_tree;
  static const int * ies[] = {
    &hf_docsis_map_sid,
    &hf_docsis_map_iuc,
    &hf_docsis_map_offset,
    NULL
  };

  it = proto_tree_add_item(tree, proto_docsis_map, tvb, 0, -1, ENC_NA);
  map_tree = proto_item_add_subtree (it, ett_docsis_map);

  proto_tree_add_item_ret_uint (map_tree, hf_docsis_mgt_upstream_chid, tvb, 0, 1, ENC_BIG_ENDIAN, &upchid);
  proto_tree_add_item_ret_uint (map_tree, hf_docsis_map_ucd_count, tvb, 1, 1, ENC_BIG_ENDIAN, &ucd_count);
  proto_tree_add_item_ret_uint (map_tree, hf_docsis_map_numie, tvb, 2, 1, ENC_BIG_ENDIAN, &numie);

  if (upchid > 0)
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Map Message:  Channel ID = %u (U%u), UCD Count = %u,  # IE's = %u",
                  upchid, upchid - 1, ucd_count, numie);
  else
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Map Message:  Channel ID = %u (Telephony Return), UCD Count = %u, # IE's = %u",
                  upchid, ucd_count, numie);

  proto_tree_add_item (map_tree, hf_docsis_map_rsvd, tvb, 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (map_tree, hf_docsis_map_alloc_start, tvb, 4, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item (map_tree, hf_docsis_map_ack_time, tvb, 8, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item (map_tree, hf_docsis_map_rng_start, tvb, 12, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (map_tree, hf_docsis_map_rng_end, tvb, 13, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (map_tree, hf_docsis_map_data_start, tvb, 14, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (map_tree, hf_docsis_map_data_end, tvb, 15, 1, ENC_BIG_ENDIAN);

  pos = 16;
  for (i = 0; i < numie; i++)
  {
    proto_tree_add_bitmask_with_flags(map_tree, tvb, pos, hf_docsis_map_ie, ett_docsis_map_ie, ies, ENC_BIG_ENDIAN, BMT_NO_FLAGS);
    pos = pos + 4;
  }

  return tvb_captured_length(tvb);
}

static int
dissect_rngreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *rngreq_tree;
  guint32 sid;

  it = proto_tree_add_item(tree, proto_docsis_rngreq, tvb, 0, -1, ENC_NA);
  rngreq_tree = proto_item_add_subtree (it, ett_docsis_rngreq);
  proto_tree_add_item_ret_uint (rngreq_tree, hf_docsis_rngreq_sid, tvb, 0, 2, ENC_BIG_ENDIAN, &sid);

  if (sid > 0)
    col_add_fstr (pinfo->cinfo, COL_INFO, "Ranging Request: SID = %u",
                      sid);
  else
    col_set_str(pinfo->cinfo, COL_INFO, "Initial Ranging Request SID = 0");

  proto_tree_add_item (rngreq_tree, hf_docsis_mgt_down_chid, tvb, 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (rngreq_tree, hf_docsis_rngreq_pend_compl, tvb, 3, 1, ENC_BIG_ENDIAN);

  return tvb_captured_length(tvb);
}

static int
dissect_rngrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *rngrsp_tree;
  proto_item *rngrsptlv_item;
  proto_tree *rngrsptlv_tree;
  guint8 tlvtype;
  int pos;
  guint tlvlen;
  guint32 sid, upchid;

  it = proto_tree_add_item(tree, proto_docsis_rngrsp, tvb, 0, -1, ENC_NA);
  rngrsp_tree = proto_item_add_subtree (it, ett_docsis_rngrsp);

  proto_tree_add_item_ret_uint (rngrsp_tree, hf_docsis_rngrsp_sid, tvb, 0, 2, ENC_BIG_ENDIAN, &sid);
  proto_tree_add_item_ret_uint (rngrsp_tree, hf_docsis_mgt_upstream_chid, tvb, 2, 1, ENC_BIG_ENDIAN, &upchid);

  if (upchid > 0)
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Ranging Response: SID = %u, Upstream Channel = %u (U%u)",
                  sid, upchid, upchid - 1);
  else
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Ranging Response: SID = %u, Telephony Return", sid);

  pos = 3;
  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    tlvtype = tvb_get_guint8 (tvb, pos);
    rngrsptlv_tree = proto_tree_add_subtree(rngrsp_tree, tvb, pos, -1,
                                  ett_docsis_rngrsptlv, &rngrsptlv_item,
                                  val_to_str(tlvtype, rngrsp_tlv_vals,
                                  "Unknown TLV (%u)"));
    proto_tree_add_uint (rngrsptlv_tree, hf_docsis_rngrsp_type, tvb, pos, 1, tlvtype);
    pos++;
    proto_tree_add_item_ret_uint (rngrsptlv_tree, hf_docsis_rngrsp_length,
                           tvb, pos, 1, ENC_NA, &tlvlen);
    pos++;
    proto_item_set_len(rngrsptlv_item, tlvlen + 2);
    switch (tlvtype)
    {
    case RNGRSP_TIMING:
      if (tlvlen == 4)
      {
        proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_timing_adj, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      }
      break;
    case RNGRSP_PWR_LEVEL_ADJ:
      if (tlvlen == 1)
      {
        proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_power_adj, tvb, pos, tlvlen, ENC_NA);
      }
      break;
    case RNGRSP_OFFSET_FREQ_ADJ:
      if (tlvlen == 2)
      {
        proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_freq_adj, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      }
      break;
    case RNGRSP_TRANSMIT_EQ_ADJ:
      proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_xmit_eq_adj, tvb, pos, tlvlen, ENC_NA);
      break;
    case RNGRSP_RANGING_STATUS:
      if (tlvlen == 1)
      {
        proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_ranging_status, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      }
      break;
    case RNGRSP_DOWN_FREQ_OVER:
      if (tlvlen == 4)
      {
        proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_down_freq_over, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      }
      break;
    case RNGRSP_UP_CHID_OVER:
      if (tlvlen == 1)
      {
        proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_upstream_ch_over, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      }
      break;
    default:
      ;
    }                   /* switch(tlvtype) */
    pos += tlvlen;
  }                       /* while (tvb_reported_length_remaining(tvb, pos) > 0) */
  return tvb_captured_length(tvb);
}

static int
dissect_regreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *regreq_tree;
  guint32 sid;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item(tree, proto_docsis_regreq, tvb, 0, -1, ENC_NA);
  regreq_tree = proto_item_add_subtree (it, ett_docsis_regreq);

  proto_tree_add_item_ret_uint (regreq_tree, hf_docsis_regreq_sid, tvb, 0, 2, ENC_BIG_ENDIAN, &sid);

  col_add_fstr (pinfo->cinfo, COL_INFO, "Registration Request SID = %u", sid);

  /* Call Dissector for Appendix C TlV's */
  next_tvb = tvb_new_subset_remaining (tvb, 2);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, regreq_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_regrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *regrsp_tree;
  guint32 sid, response;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item(tree, proto_docsis_regrsp, tvb, 0, -1, ENC_NA);
  regrsp_tree = proto_item_add_subtree (it, ett_docsis_regrsp);
  proto_tree_add_item_ret_uint (regrsp_tree, hf_docsis_regrsp_sid, tvb, 0, 2, ENC_BIG_ENDIAN, &sid);
  proto_tree_add_item_ret_uint (regrsp_tree, hf_docsis_regrsp_response, tvb, 2, 1, ENC_BIG_ENDIAN, &response);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Registration Response SID = %u (%s)", sid,
                val_to_str_ext (response, &docsis_conf_code_ext, "%d"));

  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 3);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, regrsp_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_uccreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *uccreq_tree;
  guint32 chid;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item (tree, proto_docsis_uccreq, tvb, 0, -1, ENC_NA);
  uccreq_tree = proto_item_add_subtree (it, ett_docsis_uccreq);

  proto_tree_add_item_ret_uint (uccreq_tree, hf_docsis_mgt_upstream_chid, tvb, 0, 1, ENC_BIG_ENDIAN, &chid);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Upstream Channel Change request  Channel ID = %u (U%u)",
                chid, (chid > 0 ? chid - 1 : chid));

  /* call dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 1);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, uccreq_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_uccrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *uccrsp_tree;
  guint32 chid;

  it = proto_tree_add_item(tree, proto_docsis_uccrsp, tvb, 0, -1, ENC_NA);
  uccrsp_tree = proto_item_add_subtree (it, ett_docsis_uccrsp);

  proto_tree_add_item_ret_uint (uccrsp_tree, hf_docsis_mgt_upstream_chid, tvb, 0, 1, ENC_BIG_ENDIAN, &chid);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Upstream Channel Change response  Channel ID = %u (U%u)",
                chid, (chid > 0 ? chid - 1 : chid));

  return tvb_captured_length(tvb);
}

/* The dissect_attrs() function does the actual work to dissect the
 * attributes.  It's called recursively, to dissect embedded attributes
 */
static void
dissect_attrs (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  guint8 type;
  guint32 length;
  int pos = 0;
  gint total_len;
  proto_tree *attr_tree, *attr_subtree;
  proto_item *ti, *tlv_item, *tlv_len_item;
  tvbuff_t *attr_tvb;

  total_len = tvb_reported_length_remaining (tvb, 0);
  while (pos < total_len)
  {
    type = tvb_get_guint8 (tvb, pos);
    attr_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                  ett_docsis_bpkmattrtlv, &tlv_item,
                                  val_to_str(type, bpkmattr_tlv_vals,
                                  "Unknown TLV (%u)"));
    proto_tree_add_uint (attr_tree, hf_docsis_bpkmattr_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (attr_tree, hf_docsis_bpkmattr_length,
                           tvb, pos, 2, ENC_BIG_ENDIAN, &length);
    pos += 2;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case BPKM_RESERVED:
      break;
    case BPKM_SERIAL_NUM:
      proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_serial_num, tvb, pos, length, ENC_ASCII|ENC_NA);
      break;
    case BPKM_MANUFACTURER_ID:
      if (length == 3)
        proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_manf_id, tvb, pos, length, ENC_NA);
      else
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      break;
    case BPKM_MAC_ADDR:
      if (length == 6)
        proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_mac_addr, tvb, pos, length, ENC_NA);
      else
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      break;
    case BPKM_RSA_PUB_KEY:
      proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_rsa_pub_key, tvb, pos, length, ENC_NA);
      break;
    case BPKM_CM_ID:
      ti = proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_cm_id, tvb, pos, length, ENC_NA);
      attr_subtree = proto_item_add_subtree(ti, ett_docsis_bpkmattr_cmid);
      attr_tvb = tvb_new_subset_length (tvb, pos, length);
      dissect_attrs (attr_tvb, pinfo, attr_subtree);
      break;
    case BPKM_DISPLAY_STR:
      proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_display_str, tvb, pos, length, ENC_ASCII|ENC_NA);
      break;
    case BPKM_AUTH_KEY:
      if ((length == 96) || (length == 128) || (length == 256))
        proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_auth_key, tvb, pos, length, ENC_NA);
      else
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      break;
    case BPKM_TEK:
      if (length == 8 || length == 16)
        proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_tek, tvb, pos, length, ENC_NA);
      else
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      break;
    case BPKM_KEY_LIFETIME:
      if (length == 4)
        proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_key_life, tvb, pos, length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      break;
    case BPKM_KEY_SEQ_NUM:
      if (length == 1)
        proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_key_seq, tvb, pos, length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      break;
    case BPKM_HMAC_DIGEST:
      if (length == 20)
        proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_hmac_digest, tvb, pos, length, ENC_NA);
      else
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      break;
    case BPKM_SAID:
      if (length == 2)
        proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_said, tvb, pos, length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      break;
    case BPKM_TEK_PARAM:
      ti = proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_tek_params, tvb, pos, length, ENC_NA);
      attr_subtree = proto_item_add_subtree(ti, ett_docsis_bpkmattr_tekp);
      attr_tvb = tvb_new_subset_length (tvb, pos, length);
      dissect_attrs (attr_tvb, pinfo, attr_subtree);
      break;
    case BPKM_OBSOLETED:
      break;
    case BPKM_CBC_IV:
      if (length == 8 || length == 16)
        proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_cbc_iv, tvb, pos, length, ENC_NA);
      else
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      break;
    case BPKM_ERROR_CODE:
      if (length == 1)
        proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_error_code, tvb, pos, length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      break;
    case BPKM_CA_CERT:
      proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_ca_cert, tvb, pos, length, ENC_NA);
      break;
    case BPKM_CM_CERT:
      proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_cm_cert, tvb, pos, length, ENC_NA);
      break;
    case BPKM_SEC_CAPABILITIES:
      ti = proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_security_cap, tvb, pos, length, ENC_NA);
      attr_subtree = proto_item_add_subtree(ti, ett_docsis_bpkmattr_scap);
      attr_tvb = tvb_new_subset_length (tvb, pos, length);
      dissect_attrs (attr_tvb, pinfo, attr_subtree);
      break;
    case BPKM_CRYPTO_SUITE:
      if (length == 2)
        proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_crypto_suite, tvb, pos, length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      break;
    case BPKM_CRYPTO_SUITE_LIST:
      proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_crypto_suite_list, tvb, pos, length, ENC_NA);
      break;
    case BPKM_BPI_VERSION:
      if (length == 1)
        proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_bpi_version, tvb, pos, length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      break;
    case BPKM_SA_DESCRIPTOR:
      ti = proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_sa_descr, tvb, pos, length, ENC_NA);
      attr_subtree = proto_item_add_subtree(ti, ett_docsis_bpkmattr_sadsc);
      attr_tvb = tvb_new_subset_length (tvb, pos, length);
      dissect_attrs (attr_tvb, pinfo, attr_subtree);
      break;
    case BPKM_SA_TYPE:
      if (length == 1)
        proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_sa_type, tvb, pos, length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      break;
    case BPKM_SA_QUERY:
      ti = proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_sa_query, tvb, pos, length, ENC_NA);
      attr_subtree = proto_item_add_subtree(ti, ett_docsis_bpkmattr_saqry);
      attr_tvb = tvb_new_subset_length (tvb, pos, length);
      dissect_attrs (attr_tvb, pinfo, attr_subtree);
      break;
    case BPKM_SA_QUERY_TYPE:
      if (length == 1)
        proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_sa_query_type, tvb, pos, length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      break;
    case BPKM_IP_ADDRESS:
      if (length == 4)
        proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_ip_address, tvb, pos, length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      break;
    case BPKM_VENDOR_DEFINED:
      proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_vendor_def, tvb, pos, length, ENC_NA);
      break;
    case BPKM_DNLD_PARAMS:
      ti = proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_download_param, tvb, pos, length, ENC_NA);
      attr_subtree = proto_item_add_subtree(ti, ett_docsis_bpkmattr_dnld);
      attr_tvb = tvb_new_subset_length (tvb, pos, length);
      dissect_attrs (attr_tvb, pinfo, attr_subtree);
      break;
    default:
      proto_tree_add_item (attr_tree, hf_docsis_bpkmattr_vendor_def, tvb, pos, length, ENC_NA);
      break;
    }

    pos += length;            /* switch */
  }                           /* while */
}

static int
dissect_bpkmreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *bpkmreq_tree, *bpkmattr_tree;
  guint32 code;
  tvbuff_t *attrs_tvb;

  it = proto_tree_add_item(tree, proto_docsis_bpkmreq, tvb, 0, -1, ENC_NA);
  bpkmreq_tree = proto_item_add_subtree (it, ett_docsis_bpkmreq);
  proto_tree_add_item_ret_uint (bpkmreq_tree, hf_docsis_bpkm_code, tvb, 0, 1,
                           ENC_BIG_ENDIAN, &code);

  col_add_fstr (pinfo->cinfo, COL_INFO, "BPKM Request (%s)",
                val_to_str (code, code_field_vals, "%d"));

  proto_tree_add_item (bpkmreq_tree, hf_docsis_bpkm_ident, tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (bpkmreq_tree, hf_docsis_bpkm_length, tvb, 2, 2, ENC_BIG_ENDIAN);
  it = proto_tree_add_item(bpkmreq_tree, hf_docsis_bpkmattr, tvb, 4, tvb_reported_length_remaining(tvb, 4), ENC_NA);
  bpkmattr_tree = proto_item_add_subtree (it, ett_docsis_bpkmattr);

  attrs_tvb = tvb_new_subset_remaining (tvb, 4);
  dissect_attrs(attrs_tvb, pinfo, bpkmattr_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_bpkmrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *bpkmrsp_tree, *bpkmattr_tree;
  guint32 code;
  tvbuff_t *attrs_tvb;

  it = proto_tree_add_item(tree, proto_docsis_bpkmrsp, tvb, 0, -1, ENC_NA);
  bpkmrsp_tree = proto_item_add_subtree (it, ett_docsis_bpkmrsp);

  proto_tree_add_item_ret_uint (bpkmrsp_tree, hf_docsis_bpkm_code, tvb, 0, 1, ENC_BIG_ENDIAN, &code);

  col_add_fstr (pinfo->cinfo, COL_INFO, "BPKM Response (%s)",
                val_to_str (code, code_field_vals, "Unknown code %u"));

  proto_tree_add_item (bpkmrsp_tree, hf_docsis_bpkm_ident, tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (bpkmrsp_tree, hf_docsis_bpkm_length, tvb, 2, 2, ENC_BIG_ENDIAN);
  it = proto_tree_add_item(bpkmrsp_tree, hf_docsis_bpkmattr, tvb, 4, tvb_reported_length_remaining(tvb, 4), ENC_NA);
  bpkmattr_tree = proto_item_add_subtree (it, ett_docsis_bpkmattr);

  attrs_tvb = tvb_new_subset_remaining (tvb, 4);
  dissect_attrs(attrs_tvb, pinfo, bpkmattr_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_regack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *regack_tree;
  guint32 sid, response;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item (tree, proto_docsis_regack, tvb, 0, -1, ENC_NA);
  regack_tree = proto_item_add_subtree (it, ett_docsis_regack);

  proto_tree_add_item_ret_uint (regack_tree, hf_docsis_regack_sid, tvb, 0, 2, ENC_BIG_ENDIAN, &sid);
  proto_tree_add_item_ret_uint (regack_tree, hf_docsis_regack_response, tvb, 2, 1, ENC_BIG_ENDIAN, &response);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Registration Acknowledge SID = %u (%s)", sid,
                val_to_str_ext (response, &docsis_conf_code_ext, "%d"));

  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 3);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, regack_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dsareq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dsareq_tree;
  guint32 transid;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item(tree, proto_docsis_dsareq, tvb, 0, -1, ENC_NA);
  dsareq_tree = proto_item_add_subtree (it, ett_docsis_dsareq);

  proto_tree_add_item_ret_uint (dsareq_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Addition Request Tran-id = %u", transid);

  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 2);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dsareq_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dsarsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dsarsp_tree;
  guint32 transid, response;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item (tree, proto_docsis_dsarsp, tvb, 0, -1, ENC_NA);
  dsarsp_tree = proto_item_add_subtree (it, ett_docsis_dsarsp);
  proto_tree_add_item_ret_uint (dsarsp_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);
  proto_tree_add_item_ret_uint (dsarsp_tree, hf_docsis_dsarsp_response, tvb, 2, 1, ENC_BIG_ENDIAN, &response);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Add Response ID = %u (%s)", transid,
                val_to_str_ext (response, &docsis_conf_code_ext, "%d"));

  /* Call dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 3);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dsarsp_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dsaack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dsaack_tree;
  guint32 transid, response;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item (tree, proto_docsis_dsaack, tvb, 0, -1, ENC_NA);
  dsaack_tree = proto_item_add_subtree (it, ett_docsis_dsaack);
  proto_tree_add_item_ret_uint (dsaack_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);
  proto_tree_add_item_ret_uint (dsaack_tree, hf_docsis_dsaack_response, tvb, 2, 1, ENC_BIG_ENDIAN, &response);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Add Ack ID = %u (%s)", transid,
                val_to_str_ext (response, &docsis_conf_code_ext, "%d"));

  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 3);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dsaack_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dscreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dscreq_tree;
  guint32 transid;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item (tree, proto_docsis_dscreq, tvb, 0, -1, ENC_NA);
  dscreq_tree = proto_item_add_subtree (it, ett_docsis_dscreq);

  proto_tree_add_item_ret_uint (dscreq_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Change Request Tran-id = %u", transid);

  /* Call dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 2);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dscreq_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dscrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dscrsp_tree;
  guint32 transid, response;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item(tree, proto_docsis_dscrsp, tvb, 0, -1, ENC_NA);
  dscrsp_tree = proto_item_add_subtree (it, ett_docsis_dscrsp);
  proto_tree_add_item_ret_uint (dscrsp_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);
  proto_tree_add_item_ret_uint (dscrsp_tree, hf_docsis_dscrsp_response, tvb, 2, 1, ENC_BIG_ENDIAN, &response);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Change Response ID = %u (%s)", transid,
                val_to_str_ext (response, &docsis_conf_code_ext, "%d"));

  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 3);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dscrsp_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dscack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dscack_tree;
  guint32 transid, response;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item(tree, proto_docsis_dscack, tvb, 0, -1, ENC_NA);
  dscack_tree = proto_item_add_subtree (it, ett_docsis_dscack);

  proto_tree_add_item_ret_uint (dscack_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);
  proto_tree_add_item_ret_uint (dscack_tree, hf_docsis_dscack_response, tvb, 2, 1, ENC_BIG_ENDIAN, &response);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Change Ack ID = %u (%s)", transid,
                val_to_str_ext (response, &docsis_conf_code_ext, "%d"));

  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 3);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dscack_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dsdreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dsdreq_tree;
  guint32 transid;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item (tree, proto_docsis_dsdreq, tvb, 0, -1, ENC_NA);
  dsdreq_tree = proto_item_add_subtree (it, ett_docsis_dsdreq);

  proto_tree_add_item_ret_uint (dsdreq_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Delete Request Tran-id = %u", transid);

  proto_tree_add_item (dsdreq_tree, hf_docsis_dsdreq_rsvd, tvb, 2, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item (dsdreq_tree, hf_docsis_dsdreq_sfid, tvb, 4, 4, ENC_BIG_ENDIAN);

  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 8);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dsdreq_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dsdrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dsdrsp_tree;
  guint32 tranid, confcode;

  it = proto_tree_add_item(tree, proto_docsis_dsdrsp, tvb, 0, -1, ENC_NA);
  dsdrsp_tree = proto_item_add_subtree (it, ett_docsis_dsdrsp);
  proto_tree_add_item_ret_uint (dsdrsp_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &tranid);
  proto_tree_add_item_ret_uint (dsdrsp_tree, hf_docsis_dsdrsp_confcode, tvb, 2, 1, ENC_BIG_ENDIAN, &confcode);
  proto_tree_add_item (dsdrsp_tree, hf_docsis_dsdrsp_rsvd, tvb, 3, 1, ENC_BIG_ENDIAN);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Delete Response Tran id = %u (%s)",
                tranid, val_to_str_ext (confcode, &docsis_conf_code_ext, "%d"));

  return tvb_captured_length(tvb);
}

static void
dissect_dccreq_ds_params (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *dcc_tree;
  proto_item *dcc_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    dcc_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dccreq_ds_params, &dcc_item,
                                            val_to_str(type, ds_param_subtlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcc_tree, hf_docsis_dcc_ds_params_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcc_tree, hf_docsis_dcc_ds_params_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcc_item, length + 2);

    switch (type)
    {
    case DCCREQ_DS_FREQ:
      if (length == 4)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_freq, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_DS_MOD_TYPE:
      if (length == 1)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_mod_type, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_DS_SYM_RATE:
      if (length == 1)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_sym_rate, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_DS_INTLV_DEPTH:
      if (length == 2)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_intlv_depth_i, tvb, pos, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_intlv_depth_j, tvb, pos + 1, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_DS_CHAN_ID:
      if (length == 1)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_chan_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_DS_SYNC_SUB:
      if (length == 1)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_sync_sub, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_DS_OFDM_BLOCK_FREQ:
      if (length == 4)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_ofdm_block_freq, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }

    pos += length;
  }
}

static void
dissect_dccreq_sf_sub (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *dcc_tree;
  proto_item *dcc_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    dcc_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dccreq_sf_sub, &dcc_item,
                                            val_to_str(type, sf_sub_subtlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcc_tree, hf_docsis_dcc_sf_sub_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcc_tree, hf_docsis_dcc_sf_sub_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcc_item, length + 2);

    switch (type)
    {
    case DCCREQ_SF_SFID:
      if (length == 8)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_sf_sfid_cur, tvb, pos, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_sf_sfid_new, tvb, pos + 4, 4, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_SF_SID:
      if (length == 4)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_sf_sid_cur, tvb, pos, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_sf_sid_new, tvb, pos + 2, 2, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_SF_UNSOL_GRANT_TREF:
      if (length == 4)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_sf_unsol_grant_tref, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }

    pos += length;
  }
}

static int
dissect_dccreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  guint16 pos;
  guint8 type;
  guint32 length;
  proto_tree *dcc_tree, *tlv_tree;
  proto_item *dcc_item, *tlv_item, *tlv_len_item;

  col_set_str(pinfo->cinfo, COL_INFO, "DCC-REQ Message");

  dcc_item = proto_tree_add_item (tree, proto_docsis_dccreq, tvb, 0, -1, ENC_NA);
  dcc_tree = proto_item_add_subtree (dcc_item, ett_docsis_dccreq);

  proto_tree_add_item (dcc_tree, hf_docsis_dccreq_tran_id, tvb, 0, 2, ENC_BIG_ENDIAN);

  pos = 2;
  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_guint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(dcc_tree, tvb, pos, -1,
                                            ett_docsis_dccreq_tlv, &tlv_item,
                                            val_to_str(type, dcc_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_dccreq_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_dccreq_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case DCCREQ_UP_CHAN_ID:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccreq_up_chan_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_DS_PARAMS:
      dissect_dccreq_ds_params (tvb, pinfo, tlv_tree, pos, length);
      break;
    case DCCREQ_INIT_TECH:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccreq_init_tech, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_UCD_SUB:
      proto_tree_add_item (tlv_tree, hf_docsis_dccreq_ucd_sub, tvb, pos, length, ENC_NA);
      break;
    case DCCREQ_SAID_SUB:
      if (length == 4)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccreq_said_sub_cur, tvb, pos, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (tlv_tree, hf_docsis_dccreq_said_sub_new, tvb, pos + 2, 2, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_SF_SUB:
      dissect_dccreq_sf_sub (tvb, pinfo, tlv_tree, pos, length );
      break;
    case DCCREQ_CMTS_MAC_ADDR:
      if (length == 6)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccreq_cmts_mac_addr, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_KEY_SEQ_NUM:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccreq_key_seq_num, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_HMAC_DIGEST:
      if (length == 20)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccreq_hmac_digest, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }       /* switch(type) */
    pos += length;
  }         /* (tvb_reported_length_remaining(tvb, pos) > 0) */
  return tvb_captured_length(tvb);
}

static void
dissect_dccrsp_cm_jump_time (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *dcc_tree;
  proto_item *dcc_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    dcc_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dccrsp_cm_jump_time, &dcc_item,
                                            val_to_str(type, cm_jump_subtlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcc_tree, hf_docsis_dcc_cm_jump_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcc_tree, hf_docsis_dcc_cm_jump_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcc_item, length + 2);

    switch (type)
    {
    case DCCRSP_CM_JUMP_TIME_LENGTH:
      if (length == 4)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccrsp_cm_jump_time_length, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCRSP_CM_JUMP_TIME_START:
      if (length == 8)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccrsp_cm_jump_time_start, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }

    pos += length;
  }
}

static int
dissect_dccrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  guint16 pos;
  guint8 type;
  guint32 length;
  proto_tree *dcc_tree, *tlv_tree;
  proto_item *dcc_item, *tlv_item, *tlv_len_item;

  col_set_str(pinfo->cinfo, COL_INFO, "DCC-RSP Message");

  dcc_item = proto_tree_add_item (tree, proto_docsis_dccrsp, tvb, 0, -1, ENC_NA);
  dcc_tree = proto_item_add_subtree (dcc_item, ett_docsis_dccrsp);
  proto_tree_add_item (dcc_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item (dcc_tree, hf_docsis_dccrsp_conf_code, tvb, 2, 1, ENC_BIG_ENDIAN);

  pos = 3;
  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_guint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(dcc_tree, tvb, pos, -1,
                                            ett_docsis_dccrsp_tlv, &tlv_item,
                                            val_to_str(type, dccrsp_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_dccrsp_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_dccrsp_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case DCCRSP_CM_JUMP_TIME:
      dissect_dccrsp_cm_jump_time (tvb, pinfo, tlv_tree, pos, length );
      break;
    case DCCRSP_KEY_SEQ_NUM:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccrsp_key_seq_num, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCRSP_HMAC_DIGEST:
      if (length == 20)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccrsp_hmac_digest, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }      /* switch(type) */

    pos += length;
  }       /* while (tvb_reported_length_remaining(tvb, pos) > 0) */

  return tvb_captured_length(tvb);
}

static int
dissect_dccack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  guint16 pos;
  guint8 type;
  guint32 length;
  proto_tree *dcc_tree, *tlv_tree;
  proto_item *dcc_item, *tlv_item, *tlv_len_item;

  col_set_str(pinfo->cinfo, COL_INFO, "DCC-ACK Message");

  dcc_item = proto_tree_add_item(tree, proto_docsis_dccack, tvb, 0, -1, ENC_NA);
  dcc_tree = proto_item_add_subtree (dcc_item, ett_docsis_dccack);
  proto_tree_add_item (dcc_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN);

  pos = 2;
  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_guint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(dcc_tree, tvb, pos, -1,
                                            ett_docsis_dccack_tlv, &tlv_item,
                                            val_to_str(type, dccack_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_dccack_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_dccack_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case DCCACK_KEY_SEQ_NUM:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccack_key_seq_num, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCACK_HMAC_DIGEST:
      if (length == 20)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccack_hmac_digest, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }      /* switch(type) */

    pos += length;
  }        /*   while (tvb_reported_length_remaining(tvb, pos) > 0) */

  return tvb_captured_length(tvb);
}

static int
dissect_type29ucd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  return dissect_any_ucd(tvb, pinfo, tree, proto_docsis_type29ucd, MGT_TYPE29UCD);
}

static int
dissect_intrngreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *intrngreq_item;
  proto_tree *intrngreq_tree;
  guint32 sid;

  intrngreq_item = proto_tree_add_item(tree, proto_docsis_intrngreq, tvb, 0, -1, ENC_NA);
  intrngreq_tree = proto_item_add_subtree (intrngreq_item, ett_docsis_intrngreq);

  proto_tree_add_item_ret_uint (intrngreq_tree, hf_docsis_intrngreq_sid, tvb, 0, 2, ENC_BIG_ENDIAN, &sid);
  col_add_fstr (pinfo->cinfo, COL_INFO, "Initial Ranging Request: SID = %u",sid);

  proto_tree_add_item (intrngreq_tree, hf_docsis_mgt_down_chid, tvb, 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (intrngreq_tree, hf_docsis_mgt_upstream_chid, tvb, 3, 1, ENC_BIG_ENDIAN);

  return tvb_captured_length(tvb);
}

static void
dissect_dcd_dsg_cfg (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *dcd_tree;
  proto_tree *dcd_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    dcd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dcd_cfg, &dcd_item,
                                            val_to_str(type, dcd_cfg_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcd_tree, hf_docsis_dcd_cfg_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcd_tree, hf_docsis_dcd_cfg_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcd_item, length + 2);

    switch (type)
    {
    case DCD_CFG_CHAN_LST:
      if (length == 4)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfg_chan, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFG_TDSG1:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfg_tdsg1, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFG_TDSG2:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfg_tdsg2, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFG_TDSG3:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfg_tdsg3, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFG_TDSG4:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfg_tdsg4, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFG_VENDOR_SPEC:
      proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfg_vendor_spec, tvb, pos, length, ENC_NA);
      break;

    }

    pos += length;
  }
}

static void
dissect_dcd_down_classifier_ip (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *dcd_tree;
  proto_tree *dcd_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    dcd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dcd_cfr_ip, &dcd_item,
                                            val_to_str(type, dcd_cfr_ip_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcd_tree, hf_docsis_dcd_cfr_ip_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcd_tree, hf_docsis_dcd_cfr_ip_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcd_item, length + 2);

    switch (type)
    {
    case DCD_CFR_IP_SOURCE_ADDR:
      if (length == 4)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_ip_source_addr, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_IP_SOURCE_MASK:
      if (length == 4)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_ip_source_mask, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_IP_DEST_ADDR:
      if (length == 4)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_ip_dest_addr, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_IP_DEST_MASK:
      if (length == 4)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_ip_dest_mask, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_TCPUDP_SRCPORT_START:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_tcpudp_srcport_start, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_TCPUDP_SRCPORT_END:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_tcpudp_srcport_end, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_TCPUDP_DSTPORT_START:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_tcpudp_dstport_start, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_TCPUDP_DSTPORT_END:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_tcpudp_dstport_end, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }

    pos += length;
  }
}

static void
dissect_dcd_clid (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *dcd_tree;
  proto_tree *dcd_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    dcd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dcd_clid, &dcd_item,
                                            val_to_str(type, dcd_clid_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcd_tree, hf_docsis_dcd_clid_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcd_tree, hf_docsis_dcd_clid_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcd_item, length + 2);

    switch (type)
    {
    case DCD_CLID_BCAST_ID:
      if (length == 2)
      {
        proto_tree_add_item(dcd_tree, hf_docsis_dcd_clid_bcast_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CLID_KNOWN_MAC_ADDR:
      if (length == 6)
      {
       proto_tree_add_item (dcd_tree, hf_docsis_dcd_clid_known_mac_addr, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CLID_CA_SYS_ID:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_clid_ca_sys_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CLID_APP_ID:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_clid_app_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }

    pos += length;
  }
}

static void
dissect_dcd_dsg_rule (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *dcd_tree;
  proto_tree *dcd_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    dcd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dcd_rule, &dcd_item,
                                            val_to_str(type, dcd_dsg_rule_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcd_tree, hf_docsis_dcd_dsg_rule_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcd_tree, hf_docsis_dcd_dsg_rule_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcd_item, length + 2);

    switch (type)
    {
    case DCD_RULE_ID:
      if (length == 1)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_rule_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_RULE_PRI:
      if (length == 1)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_rule_pri, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_RULE_UCID_RNG:
      proto_tree_add_item (dcd_tree, hf_docsis_dcd_rule_ucid_list, tvb, pos, length, ENC_NA);
      break;
    case DCD_RULE_CLIENT_ID:
      dissect_dcd_clid (tvb, pinfo, dcd_tree, pos, length );
      break;
    case DCD_RULE_TUNL_ADDR:
      if (length == 6)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_rule_tunl_addr, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_RULE_CFR_ID:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_rule_cfr_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_RULE_VENDOR_SPEC:
      proto_tree_add_item (dcd_tree, hf_docsis_dcd_rule_vendor_spec, tvb, pos, length, ENC_NA);
      break;

    }

    pos += length;
  }
}

static void
dissect_dcd_down_classifier (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *dcd_tree;
  proto_tree *dcd_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    dcd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dcd_cfr, &dcd_item,
                                            val_to_str(type, dcd_down_classifier_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcd_tree, hf_docsis_dcd_down_classifier_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcd_tree, hf_docsis_dcd_down_classifier_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcd_item, length + 2);

    switch (type)
    {
    case DCD_CFR_ID:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_RULE_PRI:
      if (length == 1)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_rule_pri, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_IP_CLASSIFIER:
      dissect_dcd_down_classifier_ip (tvb , pinfo , dcd_tree , pos , length );
      break;
    }

    pos += length;
  }
}

static int
dissect_dcd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  guint16 pos;
  guint8 type;
  guint32 length;
  proto_tree *dcd_tree, *tlv_tree;
  proto_item *dcd_item, *tlv_item;

  col_set_str(pinfo->cinfo, COL_INFO, "DCD Message: ");

  dcd_item = proto_tree_add_item(tree, proto_docsis_dcd, tvb, 0, -1, ENC_NA);
  dcd_tree = proto_item_add_subtree (dcd_item, ett_docsis_dcd);
  proto_tree_add_item (dcd_tree, hf_docsis_dcd_config_ch_cnt, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (dcd_tree, hf_docsis_dcd_num_of_frag, tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (dcd_tree, hf_docsis_dcd_frag_sequence_num, tvb, 2, 1, ENC_BIG_ENDIAN);

  pos = 3;
  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_guint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(dcd_tree, tvb, pos, -1,
                                            ett_docsis_dcd_tlv, &tlv_item,
                                            val_to_str(type, dcd_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_dcd_type, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_dcd_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case DCD_DOWN_CLASSIFIER:
      dissect_dcd_down_classifier (tvb, pinfo, tlv_tree, pos, length);
      break;
    case DCD_DSG_RULE:
      dissect_dcd_dsg_rule (tvb, pinfo, tlv_tree, pos, length);
      break;
    case DCD_DSG_CONFIG:
      dissect_dcd_dsg_cfg (tvb, pinfo, tlv_tree, pos, length);
      break;
    }     /* switch(type) */

     pos += length;
  }       /* while (tvb_reported_length_remaining(tvb, pos) > 0) */

  return tvb_captured_length(tvb);
}

static void
dissect_mdd_ds_active_channel_list(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;
  static const int * order_annex[] = {
    &hf_docsis_mdd_downstream_active_channel_list_modulation_order,
    &hf_docsis_mdd_downstream_active_channel_list_annex,
    NULL
  };
  static const int * cm_status_event[] = {
    &hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_timeout,
    &hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_failure,
    &hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_recovery,
    &hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_recovery,
    NULL
  };
  static const int * ofdm_plc_parameters[] = {
    &hf_docsis_mdd_ofdm_plc_parameters_tukey_raised_cosine_window,
    &hf_docsis_mdd_ofdm_plc_parameters_cyclic_prefix,
    &hf_docsis_mdd_ofdm_plc_parameters_sub_carrier_spacing,
    NULL
  };

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_ds_active_channel_list, &mdd_item,
                                            val_to_str(type, mdd_ds_active_channel_list_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_ds_active_channel_list_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_ds_active_channel_list_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_CHANNEL_ID:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_downstream_active_channel_list_channel_id, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_FREQUENCY:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_downstream_active_channel_list_frequency, tvb, pos, 4, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_MODULATION_ORDER_ANNEX:
      proto_tree_add_bitmask_list(mdd_tree, tvb, pos, 1, order_annex, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_PRIMARY_CAPABLE:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_downstream_active_channel_list_primary_capable, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK:
      proto_tree_add_bitmask(mdd_tree, tvb, pos, hf_docsis_mdd_cm_status_event_enable_bitmask, ett_sub_tlv, cm_status_event, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_MAP_UCD_TRANSPORT_INDICATOR:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_downstream_active_channel_list_map_ucd_transport_indicator, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_OFDM_PLC_PARAMETERS:
      proto_tree_add_bitmask(mdd_tree, tvb, pos, hf_docsis_mdd_ofdm_plc_parameters, ett_sub_tlv, ofdm_plc_parameters, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_ds_service_group(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 i, length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_ds_service_group, &mdd_item,
                                            val_to_str(type, mdd_ds_service_group_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_ds_service_group_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_ds_service_group_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_MD_DS_SG_IDENTIFIER:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_mac_domain_downstream_service_group_md_ds_sg_identifier, tvb, pos, 1, ENC_BIG_ENDIAN);
     break;
    case MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_CHANNEL_IDS:
      for (i = 0; i < length; i++) {
        proto_tree_add_item (mdd_tree, hf_docsis_mdd_mac_domain_downstream_service_group_channel_id, tvb, pos + i , 1, ENC_BIG_ENDIAN);
      }
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_channel_profile_reporting_control(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_channel_profile_reporting_control, &mdd_item,
                                            val_to_str(type, mdd_channel_profile_reporting_control_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_channel_profile_reporting_control_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_channel_profile_reporting_control_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case RCP_CENTER_FREQUENCY_SPACING:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_rpc_center_frequency_spacing, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case VERBOSE_RCP_REPORTING:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_verbose_rcp_reporting, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_ip_init_param(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_ip_init_param, &mdd_item,
                                            val_to_str(type, mdd_ip_init_param_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_ip_init_param_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_ip_init_param_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case IP_PROVISIONING_MODE:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_ip_provisioning_mode, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case PRE_REGISTRATION_DSID:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_pre_registration_dsid, tvb, pos, 3, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_upstream_active_channel_list(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;
  static const int * cm_status_event[] = {
    &hf_docsis_mdd_cm_status_event_enable_bitmask_t4_timeout,
    &hf_docsis_mdd_cm_status_event_enable_bitmask_t3_retries_exceeded,
    &hf_docsis_mdd_cm_status_event_enable_bitmask_successful_ranging_after_t3_retries_exceeded,
    NULL
  };

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_up_active_channel_list, &mdd_item,
                                            val_to_str(type, mdd_up_active_channel_list_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_up_active_channel_list_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_up_active_channel_list_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case UPSTREAM_ACTIVE_CHANNEL_LIST_UPSTREAM_CHANNEL_ID:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_upstream_active_channel_list_upstream_channel_id, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case UPSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK:
      proto_tree_add_bitmask(mdd_tree, tvb, pos, hf_docsis_mdd_cm_status_event_enable_bitmask, ett_sub_tlv, cm_status_event, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_cm_status_event_control(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length, timer;
  proto_tree *mdd_tree;
  proto_item *mdd_item, *text_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_cm_status_event_control, &mdd_item,
                                            val_to_str(type, mdd_cm_status_event_control_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_cm_status_event_control_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_cm_status_event_control_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case EVENT_TYPE_CODE:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_event_type, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case MAXIMUM_EVENT_HOLDOFF_TIMER:
      text_item = proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_maximum_event_holdoff_timer, tvb, pos, 2, ENC_BIG_ENDIAN, &timer);
      proto_item_append_text(text_item, " (%d ms)", timer * 20);
      break;
    case MAXIMUM_NUMBER_OF_REPORTS_PER_EVENT:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_maximum_number_of_reports_per_event, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_dsg_da_to_dsid(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_dsg_da_to_dsid, &mdd_item,
                                            val_to_str(type, mdd_cm_dsg_da_to_dsid_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_dsg_da_to_dsid_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_dsg_da_to_dsid_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case DSG_DA_TO_DSID_ASSOCIATION_DA:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_dsg_da_to_dsid_association_da, tvb, pos, 6, ENC_NA);
      break;
    case DSG_DA_TO_DSID_ASSOCIATION_DSID:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_dsg_da_to_dsid_association_dsid, tvb, pos, 3, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static int
dissect_mdd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *mdd_tree;

  int pos;
  guint8 type;
  guint32 i, length;
  proto_tree *tlv_tree;
  proto_item *tlv_item;
  static const int * non_channel_events[] = {
      &hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_sequence_out_of_range,
      &hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_operating_on_battery_backup,
      &hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_returned_to_ac_power,
      NULL
  };

  col_set_str(pinfo->cinfo, COL_INFO, "MDD Message:");

  it = proto_tree_add_item (tree, proto_docsis_mdd, tvb, 0, -1,ENC_NA);
  mdd_tree = proto_item_add_subtree (it, ett_docsis_mdd);

  proto_tree_add_item (mdd_tree, hf_docsis_mdd_ccc, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mdd_tree, hf_docsis_mdd_number_of_fragments, tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mdd_tree, hf_docsis_mdd_fragment_sequence_number, tvb, 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mdd_tree, hf_docsis_mdd_current_channel_dcid, tvb, 3, 1, ENC_BIG_ENDIAN);

  /*TLVs...*/
  pos = 4;
  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_guint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(mdd_tree, tvb, pos, -1,
                                            ett_tlv, &tlv_item,
                                            val_to_str(type, mdd_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_mdd_type, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_mdd_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch(type)
    {
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST:
      dissect_mdd_ds_active_channel_list(tvb, pinfo, tlv_tree, pos, length );
      break;
    case MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP:
      dissect_mdd_ds_service_group(tvb, pinfo, tlv_tree, pos, length );
      break;
    case DOWNSTREAM_AMBIGUITY_RESOLUTION_FREQUENCY_LIST:
      for (i = 0; i < length; i+=4) {
        proto_tree_add_item (tlv_tree, hf_docsis_mdd_downstream_ambiguity_resolution_frequency, tvb, pos + i, 4, ENC_BIG_ENDIAN);
      }
      break;
    case RECEIVE_CHANNEL_PROFILE_REPORTING_CONTROL:
      dissect_mdd_channel_profile_reporting_control(tvb, pinfo, tlv_tree, pos, length );
      break;
    case IP_INITIALIZATION_PARAMETERS:
      dissect_mdd_ip_init_param(tvb, pinfo, tlv_tree, pos, length );
      break;
    case EARLY_AUTHENTICATION_AND_ENCRYPTION:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_early_authentication_and_encryption, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case UPSTREAM_ACTIVE_CHANNEL_LIST:
      dissect_mdd_upstream_active_channel_list(tvb, pinfo, tlv_tree, pos, length );
      break;
    case UPSTREAM_AMBIGUITY_RESOLUTION_CHANNEL_LIST:
      for (i = 0; i < length; i++) {
        proto_tree_add_item (tlv_tree, hf_docsis_mdd_upstream_ambiguity_resolution_channel_list_channel_id, tvb, pos + i , 1, ENC_BIG_ENDIAN);
      }
      break;
    case UPSTREAM_FREQUENCY_RANGE:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_upstream_frequency_range, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case SYMBOL_CLOCK_LOCKING_INDICATOR:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_symbol_clock_locking_indicator, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case CM_STATUS_EVENT_CONTROL:
      dissect_mdd_cm_status_event_control(tvb, pinfo, tlv_tree, pos, length );
      break;
    case UPSTREAM_TRANSMIT_POWER_REPORTING:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_upstream_transmit_power_reporting, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case DSG_DA_TO_DSID_ASSOCIATION_ENTRY:
      dissect_mdd_dsg_da_to_dsid(tvb, pinfo, tlv_tree, pos, length );
      break;
    case CM_STATUS_EVENT_ENABLE_NON_CHANNEL_SPECIFIC_EVENTS:
      proto_tree_add_bitmask(tlv_tree, tvb, pos, hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events, ett_sub_tlv, non_channel_events, ENC_BIG_ENDIAN);
      break;
    case EXTENDED_UPSTREAM_TRANSMIT_POWER_SUPPORT:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_extended_upstream_transmit_power_support, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }

  return tvb_captured_length(tvb);
}

static int
dissect_bintrngreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *bintrngreq_item;
  proto_tree *bintrngreq_tree;
  guint16 md_ds_sg_id;
  guint16 offset = 0;

  md_ds_sg_id = tvb_get_ntohs (tvb, 0);

  col_add_fstr (pinfo->cinfo, COL_INFO, "Bonded Ranging Request: MD-DS-SG-ID = %u (0x%X)",
                md_ds_sg_id, md_ds_sg_id );

  bintrngreq_item = proto_tree_add_item(tree, proto_docsis_bintrngreq, tvb, offset, -1, ENC_NA);
  bintrngreq_tree = proto_item_add_subtree (bintrngreq_item, ett_docsis_bintrngreq);
  proto_tree_add_item (bintrngreq_tree, hf_docsis_bintrngreq_capflags, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item( bintrngreq_tree, hf_docsis_bintrngreq_capflags_frag, tvb, offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item( bintrngreq_tree, hf_docsis_bintrngreq_capflags_encrypt, tvb, offset, 1, ENC_BIG_ENDIAN );
  offset++;
  proto_tree_add_item (bintrngreq_tree, hf_docsis_bintrngreq_mddsgid, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  proto_tree_add_item (bintrngreq_tree, hf_docsis_mgt_down_chid, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  proto_tree_add_item (bintrngreq_tree, hf_docsis_mgt_upstream_chid, tvb, offset, 1, ENC_BIG_ENDIAN);

  return tvb_captured_length(tvb);
}

static int
dissect_type35ucd(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  return dissect_any_ucd(tvb, pinfo, tree, proto_docsis_type35ucd, MGT_TYPE35UCD);
}

static int
dissect_dbcreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *dbcreq_item;
  proto_tree *dbcreq_tree;
  guint32 transid;
  tvbuff_t *next_tvb;

  dbcreq_item = proto_tree_add_item(tree, proto_docsis_dbcreq, tvb, 0, -1, ENC_NA);
  dbcreq_tree = proto_item_add_subtree (dbcreq_item, ett_docsis_dbcreq);
  proto_tree_add_item_ret_uint(dbcreq_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);
  proto_tree_add_item( dbcreq_tree, hf_docsis_dbcreq_number_of_fragments, tvb, 2, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item( dbcreq_tree, hf_docsis_dbcreq_fragment_sequence_number, tvb, 3, 1, ENC_BIG_ENDIAN );

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Bonding Change Request: Tran-Id = %u", transid);

  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 4);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dbcreq_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dbcrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *dbcrsp_item;
  proto_tree *dbcrsp_tree;
  guint32 transid, confcode;
  tvbuff_t *next_tvb;

  dbcrsp_item = proto_tree_add_item(tree, proto_docsis_dbcrsp, tvb, 0, -1, ENC_NA);
  dbcrsp_tree = proto_item_add_subtree (dbcrsp_item, ett_docsis_dbcrsp);
  proto_tree_add_item_ret_uint(dbcrsp_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);
  proto_tree_add_item_ret_uint( dbcrsp_tree, hf_docsis_dbcrsp_conf_code, tvb, 2, 1, ENC_BIG_ENDIAN, &confcode);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Bonding Change Response: Tran-Id = %u (%s)", transid,
                val_to_str_ext (confcode, &docsis_conf_code_ext, "%d"));

  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 3);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dbcrsp_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dbcack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *dbcack_item;
  proto_tree *dbcack_tree = NULL;
  guint16 transid;
  tvbuff_t *next_tvb;

  transid = tvb_get_ntohs (tvb, 0);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Bonding Change Acknowledge: Tran-Id = %u", transid);

  dbcack_item = proto_tree_add_item(tree, proto_docsis_dbcack, tvb, 0, -1, ENC_NA);
  dbcack_tree = proto_item_add_subtree (dbcack_item, ett_docsis_dbcack);
  proto_tree_add_item (dbcack_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN);

  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 2);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dbcack_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dpvreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dpvreq_tree;
  guint32 transid, dschan;

  it = proto_tree_add_item(tree, proto_docsis_dpvreq, tvb, 0, -1, ENC_NA);
  dpvreq_tree = proto_item_add_subtree (it, ett_docsis_dpvreq);
  proto_tree_add_item_ret_uint (dpvreq_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);
  proto_tree_add_item_ret_uint (dpvreq_tree, hf_docsis_mgt_down_chid, tvb, 2, 1, ENC_BIG_ENDIAN, &dschan);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "DOCSIS Path Verify Request: Transaction-Id = %u DS-Ch %d",
                transid, dschan);

  proto_tree_add_item (dpvreq_tree, hf_docsis_dpv_flags, tvb, 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvreq_tree, hf_docsis_dpv_us_sf, tvb, 4, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvreq_tree, hf_docsis_dpv_n, tvb, 8, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvreq_tree, hf_docsis_dpv_start, tvb, 10, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvreq_tree, hf_docsis_dpv_end, tvb, 11, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvreq_tree, hf_docsis_dpv_ts_start, tvb, 12, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvreq_tree, hf_docsis_dpv_ts_end, tvb, 16, 4, ENC_BIG_ENDIAN);

  return tvb_captured_length(tvb);
}

static int
dissect_dpvrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dpvrsp_tree = NULL;
  guint32 transid, dschan;

  it = proto_tree_add_item (tree, proto_docsis_dpvrsp, tvb, 0, -1, ENC_NA);
  dpvrsp_tree = proto_item_add_subtree (it, ett_docsis_dpvrsp);
  proto_tree_add_item_ret_uint (dpvrsp_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);
  proto_tree_add_item_ret_uint (dpvrsp_tree, hf_docsis_mgt_down_chid, tvb, 2, 1, ENC_BIG_ENDIAN, &dschan);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "DOCSIS Path Verify Response: Transaction-Id = %u DS-Ch %d",
                transid, dschan);

  proto_tree_add_item (dpvrsp_tree, hf_docsis_dpv_flags, tvb, 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvrsp_tree, hf_docsis_dpv_us_sf, tvb, 4, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvrsp_tree, hf_docsis_dpv_n, tvb, 8, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvrsp_tree, hf_docsis_dpv_start, tvb, 10, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvrsp_tree, hf_docsis_dpv_end, tvb, 11, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvrsp_tree, hf_docsis_dpv_ts_start, tvb, 12, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvrsp_tree, hf_docsis_dpv_ts_end, tvb, 16, 4, ENC_BIG_ENDIAN);

  return tvb_captured_length(tvb);
}

static void
dissect_cmstatus_tlv (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree)
{
  proto_item *it, *tlv_item, *tlv_len_item;
  proto_tree *tlv_tree;
  guint16 pos = 0;
  guint8 type;
  guint32 length;

  it = proto_tree_add_item(tree, hf_docsis_cmstatus_tlv_data, tvb, 0, tvb_reported_length(tvb), ENC_NA);
  tlv_tree = proto_item_add_subtree (it, ett_docsis_cmstatus_tlv);

  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_guint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(tlv_tree, tvb, pos, -1,
                                            ett_docsis_cmstatus_tlvtlv, &tlv_item,
                                            val_to_str(type, cmstatus_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_cmstatus_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_cmstatus_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case EVENT_DS_CH_ID:
      if (length == 3)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_cmstatus_ds_ch_id, tvb, pos + 1, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;

    case EVENT_US_CH_ID:
      if (length == 3)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_cmstatus_us_ch_id, tvb, pos + 1, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;

    case EVENT_DSID:
      if (length == 5)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_cmstatus_dsid, tvb, pos + 1, 3, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;

    case EVENT_DESCR:
      if (length >= 3 && length <= 82)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_cmstatus_descr, tvb, pos + 1, length - 2, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    } /* switch */
      pos += length;
  } /* while */
}

static int
dissect_cmstatus (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *cmstatus_tree;
  guint32 transid;
  guint8 event_type;
  tvbuff_t* next_tvb;

  it = proto_tree_add_item(tree, proto_docsis_cmstatus, tvb, 0, -1, ENC_NA);
  cmstatus_tree = proto_item_add_subtree (it, ett_docsis_cmstatus);
  proto_tree_add_item_ret_uint (cmstatus_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);

  col_add_fstr (pinfo->cinfo, COL_INFO, "CM-STATUS Report: Transaction ID = %u", transid);

  event_type = tvb_get_guint8 (tvb, 2);
  switch (event_type)
  {
  case SEC_CH_MDD_TIMEOUT:
    proto_tree_add_item (cmstatus_tree, hf_docsis_cmstatus_e_t_mdd_t, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case QAM_FEC_LOCK_FAILURE:
    proto_tree_add_item (cmstatus_tree, hf_docsis_cmstatus_e_t_qfl_f, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case SEQ_OUT_OF_RANGE:
    proto_tree_add_item (cmstatus_tree, hf_docsis_cmstatus_e_t_s_o, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case SEC_CH_MDD_RECOVERY:
    proto_tree_add_item (cmstatus_tree, hf_docsis_cmstatus_e_t_mdd_r, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case QAM_FEC_LOCK_RECOVERY:
    proto_tree_add_item (cmstatus_tree, hf_docsis_cmstatus_e_t_qfl_r, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case T4_TIMEOUT:
    proto_tree_add_item (cmstatus_tree, hf_docsis_cmstatus_e_t_t4_t, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case T3_RETRIES_EXCEEDED:
    proto_tree_add_item (cmstatus_tree, hf_docsis_cmstatus_e_t_t3_e, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

   case SUCCESS_RANGING_AFTER_T3_RETRIES_EXCEEDED:
    proto_tree_add_item (cmstatus_tree, hf_docsis_cmstatus_e_t_rng_s, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case CM_ON_BATTERY:
    proto_tree_add_item (cmstatus_tree, hf_docsis_cmstatus_e_t_cm_b, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case CM_ON_AC_POWER:
    proto_tree_add_item (cmstatus_tree, hf_docsis_cmstatus_e_t_cm_a, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;
  } /* switch */

  /* Call Dissector TLV's */
  next_tvb = tvb_new_subset_remaining(tvb, 3);
  dissect_cmstatus_tlv(next_tvb, pinfo, cmstatus_tree);
  return tvb_captured_length(tvb);
}

static void
dissect_ds_event(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *event_tree;
  proto_item *event_item, *tlv_len_item;
  int pos = start;

  while (pos < (start + len))
  {
    type = tvb_get_guint8 (tvb, pos);
    event_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_cmctrl_tlv_ds_event, &event_item,
                                            val_to_str(type, cmctrlreq_ds_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (event_tree, hf_docsis_cmctrl_ds_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (event_tree, hf_docsis_cmctrl_ds_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(event_item, length + 2);

    switch (type)
    {
    case DS_EVENT_CH_ID:
      if (length == 1)
      {
        proto_tree_add_item (event_tree, hf_docsis_cmctrl_ds_event_ch_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DS_EVENT_MASK:
      if (length == 2)
      {
        proto_tree_add_item (event_tree, hf_docsis_cmctrl_ds_event_mask, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }          /* switch */

    pos += length;
  }            /* while */
}

static void
dissect_us_event(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *event_tree;
  proto_item *event_item, *tlv_len_item;
  int pos = start;

  while (pos < (start + len))
  {
    type = tvb_get_guint8 (tvb, pos);
    event_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_cmctrl_tlv_us_event, &event_item,
                                            val_to_str(type, cmctrlreq_us_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (event_tree, hf_docsis_cmctrlreq_us_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (event_tree, hf_docsis_cmctrlreq_us_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(event_item, length + 2);

    switch (type)
    {
    case US_EVENT_CH_ID:
      if (length == 1)
      {
        proto_tree_add_item (event_tree, hf_docsis_cmctrl_us_event_ch_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case US_EVENT_MASK:
      if (length == 2)
      {
        proto_tree_add_item (event_tree, hf_docsis_cmctrl_us_event_mask, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }                   /* switch */
      pos += length;
  }                     /* while */
}

static void
dissect_cmctrlreq_tlv(tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree)
{
  proto_item *it, *tlv_item, *tlv_len_item;
  proto_tree *tlv_tree;
  guint16 pos = 0;
  guint8 type;
  guint32 length;

  it = proto_tree_add_item(tree, hf_docsis_cmctrlreq_tlv_data, tvb, 0, tvb_reported_length(tvb), ENC_NA);
  tlv_tree = proto_item_add_subtree (it, ett_docsis_cmctrlreq_tlv);

  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_guint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(tlv_tree, tvb, pos, -1,
                                            ett_docsis_cmctrlreq_tlvtlv, &tlv_item,
                                            val_to_str(type, cmctrlreq_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_cmctrlreq_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_cmctrlreq_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case CM_CTRL_MUTE:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_cmctrl_tlv_mute, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case CM_CTRL_MUTE_TIMEOUT:
      if (length == 4 || length == 1) /* response TLV always with len 1 */
      {
        proto_tree_add_item (tlv_tree, hf_docsis_cmctrl_tlv_mute_timeout, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case CM_CTRL_REINIT:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_cmctrl_tlv_reinit, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case CM_CTRL_DISABLE_FWD:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_cmctrl_tlv_disable_fwd, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case CM_CTRL_DS_EVENT:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_cmctrl_tlv_ds_event, tvb, pos, length, ENC_NA);
      }
      else
      {
        dissect_ds_event(tvb, pinfo, tlv_tree, pos, length);
      }
      break;
    case CM_CTRL_US_EVENT:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_cmctrl_tlv_us_event, tvb, pos, length, ENC_NA);
      }
      else
      {
        dissect_us_event(tvb, pinfo, tlv_tree, pos, length);
      }
      break;
    case CM_CTRL_EVENT:
      if (length == 2 || length == 1) /* response TLV always with len 1 */
      {
        proto_tree_add_item (tlv_tree, hf_docsis_cmctrl_tlv_event, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;

    } /* switch */

    pos += length;
  }
}

static int
dissect_cmctrlreq(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *cmctrlreq_tree;
  guint32 transid;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item (tree, proto_docsis_cmctrlreq, tvb, 0, -1, ENC_NA);
  cmctrlreq_tree = proto_item_add_subtree (it, ett_docsis_cmctrlreq);
  proto_tree_add_item_ret_uint (cmctrlreq_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "CM Control Request: Transaction-Id = %u", transid);

  next_tvb = tvb_new_subset_remaining(tvb, 2);
  dissect_cmctrlreq_tlv(next_tvb, pinfo, cmctrlreq_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_cmctrlrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *cmctrlrsp_tree;
  guint32 transid;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item(tree, proto_docsis_cmctrlrsp, tvb, 0, -1, ENC_NA);
  cmctrlrsp_tree = proto_item_add_subtree (it, ett_docsis_cmctrlrsp);
  proto_tree_add_item_ret_uint (cmctrlrsp_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "CM Control Response: Transaction-Id = %u", transid);

  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 2);
  dissect_cmctrlreq_tlv(next_tvb, pinfo, cmctrlrsp_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_regreqmp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *regreqmp_tree;
  tvbuff_t *next_tvb;

  col_set_str(pinfo->cinfo, COL_INFO, "REG-REQ-MP Message:");

  it = proto_tree_add_item(tree, proto_docsis_regreqmp, tvb, 0, -1, ENC_NA);
  regreqmp_tree = proto_item_add_subtree (it, ett_docsis_regreqmp);

  proto_tree_add_item (regreqmp_tree, hf_docsis_regreqmp_sid, tvb, 0, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item (regreqmp_tree, hf_docsis_regreqmp_number_of_fragments, tvb, 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (regreqmp_tree, hf_docsis_regreqmp_fragment_sequence_number, tvb, 3, 1, ENC_BIG_ENDIAN);

  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 4);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, regreqmp_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_regrspmp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *regrspmp_tree;
  tvbuff_t *next_tvb;

  col_set_str(pinfo->cinfo, COL_INFO, "REG-RSP-MP Message:");

  it = proto_tree_add_item(tree, proto_docsis_regrspmp, tvb, 0, -1, ENC_NA);
  regrspmp_tree = proto_item_add_subtree (it, ett_docsis_regrspmp);

  proto_tree_add_item (regrspmp_tree, hf_docsis_regrspmp_sid, tvb, 0, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item (regrspmp_tree, hf_docsis_regrspmp_response, tvb, 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (regrspmp_tree, hf_docsis_regrspmp_number_of_fragments, tvb, 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (regrspmp_tree, hf_docsis_regrspmp_fragment_sequence_number, tvb, 4, 1, ENC_BIG_ENDIAN);

  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 5);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, regrspmp_tree);
  return tvb_captured_length(tvb);
}

static void
dissect_subcarrier_assignment_range_list(tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, guint16 pos, guint32 len)
{
  proto_item* type_item;
  guint32 i, subcarrier_assignment_type;

  type_item = proto_tree_add_item_ret_uint (tree, hf_docsis_ocd_tlv_subc_assign_type, tvb, pos, 1, ENC_BIG_ENDIAN, &subcarrier_assignment_type);
  proto_tree_add_item (tree, hf_docsis_ocd_tlv_subc_assign_value, tvb, pos, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (tree, hf_docsis_ocd_subc_assign_subc_type, tvb, pos, 1, ENC_BIG_ENDIAN);
  pos++;

  switch (subcarrier_assignment_type) {
    case SUBCARRIER_ASSIGNMENT_RANGE_CONT:
    case SUBCARRIER_ASSIGNMENT_RANGE_SKIPBY1:
      proto_tree_add_item (tree, hf_docsis_ocd_subc_assign_range, tvb, pos, 4, ENC_BIG_ENDIAN);
      break;
    case SUBCARRIER_ASSIGNMENT_LIST:
      for (i = 0; i < len/2; ++i) {
        proto_tree_add_item (tree, hf_docsis_ocd_subc_assign_index, tvb, pos, 2, ENC_BIG_ENDIAN);
        pos += 2;
      }
      break;
    default:
      expert_add_info_format(pinfo, type_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown subcarrier assignment type %d", subcarrier_assignment_type);
      break;
  }
}

static void
dissect_ocd_tlv (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree)
{
  proto_item *it, *tlv_item, *tlv_len_item;
  proto_tree *tlv_tree;
  guint16 pos = 0;
  guint8 type;
  guint32 length;

  it = proto_tree_add_item(tree, hf_docsis_ocd_tlv_data, tvb, 0, tvb_reported_length(tvb), ENC_NA);
  tlv_tree = proto_item_add_subtree (it, ett_docsis_ocd_tlv);

  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_guint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(tlv_tree, tvb, pos, -1,
                                            ett_docsis_ocd_tlvtlv, &tlv_item,
                                            val_to_str(type, ocd_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_ocd_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_ocd_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case DISCRETE_FOURIER_TRANSFORM_SIZE:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ocd_tlv_four_trans_size, tvb, pos, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case CYCLIC_PREFIX:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ocd_tlv_cycl_pref, tvb, pos, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case ROLL_OFF:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ocd_tlv_roll_off, tvb, pos, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case OFDM_SPECTRUM_LOCATION:
      if (length == 4)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ocd_tlv_ofdm_spec_loc, tvb, pos, 4, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case TIME_INTERLEAVING_DEPTH:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ocd_tlv_time_int_depth, tvb, pos, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case SUBCARRIER_ASSIGNMENT_RANGE_LIST:
      if (length >= 5)
      {
        dissect_subcarrier_assignment_range_list(tvb, pinfo, tlv_tree, pos, length);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case PRIMARY_CAPABILITY_INDICATOR:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ocd_tlv_prim_cap_ind, tvb, pos, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    default:
      proto_tree_add_item (tlv_tree, hf_docsis_ocd_tlv_unknown, tvb, pos - 2, length+2, ENC_NA);
      break;
    } /* switch */
    pos += length;
  } /* while */
}

static int
dissect_ocd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *ocd_tree;
  tvbuff_t *next_tvb;
  guint32 downstream_channel_id, configuration_change_count;

  it = proto_tree_add_item(tree, proto_docsis_ocd, tvb, 0, -1, ENC_NA);
  ocd_tree = proto_item_add_subtree (it, ett_docsis_ocd);

  proto_tree_add_item_ret_uint (ocd_tree, hf_docsis_mgt_down_chid, tvb, 0, 1, ENC_BIG_ENDIAN, &downstream_channel_id);
  proto_tree_add_item_ret_uint (ocd_tree, hf_docsis_ocd_ccc, tvb, 1, 1, ENC_BIG_ENDIAN, &configuration_change_count);

  col_add_fstr (pinfo->cinfo, COL_INFO, "OCD: DS CH ID: %u, CCC: %u", downstream_channel_id, configuration_change_count);

  /* Call Dissector TLV's */
  next_tvb = tvb_new_subset_remaining(tvb, 2);
  dissect_ocd_tlv(next_tvb, pinfo, ocd_tree);

  return tvb_captured_length(tvb);
}

static void
dissect_dpd_subcarrier_assignment_range_list(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint pos, guint len)
{
  guint32 i, subcarrier_assignment_type;
  proto_item* type_item;

  type_item = proto_tree_add_item_ret_uint (tree, hf_docsis_dpd_tlv_subc_assign_type, tvb, pos, 1, ENC_BIG_ENDIAN, &subcarrier_assignment_type);
  proto_tree_add_item (tree, hf_docsis_dpd_tlv_subc_assign_value, tvb, pos, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (tree, hf_docsis_dpd_tlv_subc_assign_reserved, tvb, pos, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (tree, hf_docsis_dpd_tlv_subc_assign_modulation, tvb, pos, 1, ENC_BIG_ENDIAN);
  pos++;

  switch (subcarrier_assignment_type)
  {
    case SUBCARRIER_ASSIGNMENT_RANGE_CONT:
    case SUBCARRIER_ASSIGNMENT_RANGE_SKIPBY1:
      proto_tree_add_item (tree, hf_docsis_dpd_subc_assign_range, tvb, pos, 4, ENC_BIG_ENDIAN);
      break;
    case SUBCARRIER_ASSIGNMENT_LIST:
      for (i = 0; i < len/2; ++i) {
        proto_tree_add_item (tree, hf_docsis_dpd_subc_assign_index, tvb, pos, 2, ENC_BIG_ENDIAN);
        pos += 2;
      }
      break;
    default:
      expert_add_info_format(pinfo, type_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown subcarrier assignment type: %u", subcarrier_assignment_type);
      break;
  }
}

static void
dissect_dpd_subcarrier_assignment_vector(tvbuff_t * tvb, proto_tree * tree, guint start, guint len)
{
  guint32 subcarrier_assignment_vector_oddness;
  guint vector_index;

  proto_tree_add_item_ret_uint (tree, hf_docsis_dpd_tlv_subc_assign_vector_oddness, tvb, start, 1, ENC_BIG_ENDIAN, &subcarrier_assignment_vector_oddness);
  proto_tree_add_item (tree, hf_docsis_dpd_tlv_subc_assign_vector_reserved, tvb, start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (tree, hf_docsis_dpd_tlv_subc_assign_vector_subc_start, tvb, start, 2, ENC_BIG_ENDIAN);

  for(vector_index = 0; vector_index < len; ++vector_index)
  {
    proto_tree_add_item (tree, hf_docsis_dpd_tlv_subc_assign_vector_modulation_odd, tvb, start + 2 + vector_index, 1, ENC_BIG_ENDIAN);
    if (!((vector_index == len -1) && subcarrier_assignment_vector_oddness))
    {
      proto_tree_add_item (tree, hf_docsis_dpd_tlv_subc_assign_vector_modulation_even, tvb, start + 2 + vector_index, 1, ENC_BIG_ENDIAN);
    }
  }
}


static void
dissect_dpd_tlv (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *it, *tlv_item, *tlv_len_item;
  proto_tree *tlv_tree;
  guint pos = 0;
  guint length;
  guint8 type;

  it = proto_tree_add_item(tree, hf_docsis_dpd_tlv_data, tvb, 0, tvb_reported_length(tvb), ENC_NA);
  tlv_tree = proto_item_add_subtree (it, ett_docsis_dpd_tlv);

  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_guint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(tlv_tree, tvb, pos, -1,
                                            ett_docsis_dpd_tlvtlv, &tlv_item,
                                            val_to_str(type, dpd_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_dpd_type, tvb, pos, 1, type);
    pos++;
    if (type != SUBCARRIER_ASSIGNMENT_VECTOR)
    {
      tlv_len_item = proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_dpd_length, tvb, pos, 1, ENC_NA, &length);
      pos++;
      proto_item_set_len(tlv_item, length + 2);
    }

    switch (type)
    {
    case SUBCARRIER_ASSIGNMENT_RANGE_LIST:
      if (length >= 5)
      {
        dissect_dpd_subcarrier_assignment_range_list(tvb, pinfo, tlv_tree, pos, length);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case SUBCARRIER_ASSIGNMENT_VECTOR:
      /*FOR THIS TYPE, LENGTH IS 2 BYTES INSTEAD OF 1 */
      tlv_len_item = proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_dpd_length, tvb, pos, 2, ENC_BIG_ENDIAN, &length);
      pos += 2;
      proto_item_set_len(tlv_item, length + 2);
      if (length >=2)
      {
        dissect_dpd_subcarrier_assignment_vector(tvb, tlv_tree, pos, length);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    default:
      proto_tree_add_item (tlv_tree, hf_docsis_dpd_tlv_unknown, tvb, pos - 2, length+2, ENC_NA);
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV: %u", type);
      break;
    } /* switch */
    pos += length;
  } /* while */
}

static int
dissect_dpd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data  _U_)
{
  proto_item *it;
  proto_tree *dpd_tree;
  tvbuff_t *next_tvb;

  guint32 downstream_channel_id, profile_identifier, configuration_change_count;

  it = proto_tree_add_item(tree, proto_docsis_dpd, tvb, 0, -1, ENC_NA);
  dpd_tree = proto_item_add_subtree (it, ett_docsis_dpd);
  proto_tree_add_item_ret_uint (dpd_tree, hf_docsis_mgt_down_chid, tvb, 0, 1, ENC_BIG_ENDIAN, &downstream_channel_id);
  proto_tree_add_item_ret_uint (dpd_tree, hf_docsis_dpd_prof_id, tvb, 1, 1, ENC_BIG_ENDIAN, &profile_identifier);
  proto_tree_add_item_ret_uint (dpd_tree, hf_docsis_dpd_ccc, tvb, 2, 1, ENC_BIG_ENDIAN, &configuration_change_count);

  col_add_fstr (pinfo->cinfo, COL_INFO, "DPD: DS CH ID: %u, Profile ID: %u, CCC: %u", downstream_channel_id, profile_identifier, configuration_change_count);

  /* Call Dissector TLV's */
  next_tvb = tvb_new_subset_remaining(tvb, 3);
  dissect_dpd_tlv(next_tvb, pinfo, dpd_tree);

  return tvb_captured_length(tvb);
}

static int
dissect_type51ucd(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  return dissect_any_ucd(tvb, pinfo, tree, proto_docsis_type51ucd, MGT_TYPE51UCD);
}

static int
dissect_macmgmt (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  guint32 type, msg_len;
  proto_item *mgt_hdr_it;
  proto_tree *mgt_hdr_tree;
  tvbuff_t *payload_tvb;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, "DOCSIS MGMT");

  col_clear(pinfo->cinfo, COL_INFO);

  set_address_tvb (&pinfo->dl_src, AT_ETHER, 6, tvb, 6);
  copy_address_shallow(&pinfo->src, &pinfo->dl_src);
  set_address_tvb (&pinfo->dl_dst, AT_ETHER, 6, tvb, 0);
  copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);

  mgt_hdr_it = proto_tree_add_item (tree, proto_docsis_mgmt, tvb, 0, 20, ENC_NA);
  mgt_hdr_tree = proto_item_add_subtree (mgt_hdr_it, ett_docsis_mgmt);
  proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_dst_addr, tvb, 0, 6, ENC_NA);
  proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_src_addr, tvb, 6, 6, ENC_NA);
  proto_tree_add_item_ret_uint (mgt_hdr_tree, hf_docsis_mgt_msg_len, tvb, 12, 2, ENC_BIG_ENDIAN, &msg_len);
  proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_dsap, tvb, 14, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_ssap, tvb, 15, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_control, tvb, 16, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_version, tvb, 17, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_uint (mgt_hdr_tree, hf_docsis_mgt_type, tvb, 18, 1, ENC_BIG_ENDIAN, &type);
  proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_rsvd, tvb, 19, 1, ENC_BIG_ENDIAN);

  /* Code to Call subdissector */
  /* sub-dissectors are based on the type field */
  payload_tvb = tvb_new_subset_length (tvb, 20, msg_len - 6);

  if (!dissector_try_uint(docsis_mgmt_dissector_table, type, payload_tvb, pinfo, tree))
    call_data_dissector(payload_tvb, pinfo, tree);

  return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_docsis_mgmt (void)
{
  static hf_register_info hf[] = {
      /* Sync Message */
    {&hf_docsis_sync_cmts_timestamp,
     {"CMTS Timestamp", "docsis_sync.cmts_timestamp",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Sync CMTS Timestamp", HFILL}
    },
    /* UCD */
    {&hf_docsis_ucd_config_ch_cnt,
     {"Config Change Count", "docsis_ucd.confcngcnt",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Configuration Change Count", HFILL}
    },
    {&hf_docsis_ucd_mini_slot_size,
     {"Mini Slot Size (6.25us TimeTicks)", "docsis_ucd.mslotsize",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_type,
     {"Type", "docsis_ucd.type",
      FT_UINT8, BASE_DEC, VALS(channel_tlv_vals), 0x0,
      "Channel TLV type", HFILL}
    },
    {&hf_docsis_ucd_length,
     {"Length", "docsis_ucd.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Channel TLV length", HFILL}
    },
    {&hf_docsis_ucd_burst_type,
     {"Type", "docsis_ucd.burst.tlvtype",
      FT_UINT8, BASE_DEC, VALS(burst_tlv_vals), 0x0,
      "Burst TLV type", HFILL}
    },
    {&hf_docsis_ucd_burst_length,
     {"Length", "docsis_ucd.burst.tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Burst TLV length", HFILL}
    },
    {&hf_docsis_ucd_symbol_rate,
     {"Symbol Rate (ksym/sec)", "docsis_ucd.symrate",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Symbol Rate", HFILL}
    },
    {&hf_docsis_ucd_frequency,
     {"Frequency (Hz)", "docsis_ucd.freq",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Upstream Center Frequency", HFILL}
    },
    {&hf_docsis_ucd_preamble_pat,
     {"Preamble Pattern", "docsis_ucd.preamble",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Preamble Superstring", HFILL}
    },
    {&hf_docsis_ucd_ext_preamble_pat,
     {"Extended Preamble Pattern", "docsis_ucd.extpreamble",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Extended Preamble Superstring", HFILL}
    },
    {&hf_docsis_ucd_scdma_mode_enabled,
     {"S-CDMA Mode Enabled", "docsis_ucd.scdma",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_spreading_interval,
     {"SCDMA Spreading Interval", "docsis_ucd.scdmaspreadinginterval",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_codes_per_mini_slot,
     {"SCDMA Codes per mini slot", "docsis_ucd.scdmacodesperminislot",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_active_codes,
     {"SCDMA Active Codes", "docsis_ucd.scdmaactivecodes",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_code_hopping_seed,
     {"SCDMA Code Hopping Seed", "docsis_ucd.scdmacodehoppingseed",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_us_ratio_num,
     {"SCDMA US Ratio Numerator", "docsis_ucd.scdmausrationum",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_us_ratio_denom,
     {"SCDMA US Ratio Denominator", "docsis_ucd.scdmausratiodenom",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_timestamp_snapshot,
     {"SCDMA Timestamp Snapshot", "docsis_ucd.scdmatimestamp",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_maintain_power_spectral_density,
     {"Maintain Power Spectral Density", "docsis_ucd.maintpower",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_ranging_required,
     {"Ranging Required", "docsis_ucd.rangingreq",
      FT_UINT8, BASE_DEC, VALS (ranging_req_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_max_scheduled_codes,
     {"S-CDMA Max Scheduled Codes", "docsis_ucd.scdmamaxcodes",
      FT_UINT8, BASE_DEC, VALS (max_scheduled_codes_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_rnghoff_cm,
     {"Ranging Hold-Off (CM)","docsis_ucd.rnghoffcm",
      FT_BOOLEAN, 32, TFS(&tfs_allow_inhibit), 0x1,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_rnghoff_erouter,
     {"Ranging Hold-Off (eRouter)",
      "docsis_ucd.rnghofferouter",
      FT_BOOLEAN, 32, TFS(&tfs_allow_inhibit), 0x2,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_rnghoff_emta,
     {"Ranging Hold-Off (eMTA or EDVA)",
      "docsis_ucd.rnghoffemta",
      FT_BOOLEAN, 32, TFS(&tfs_allow_inhibit), 0x4,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_rnghoff_estb,
     {"Ranging Hold-Off (DSG/eSTB)",
      "docsis_ucd.rnghoffestb",
      FT_BOOLEAN, 32, TFS(&tfs_allow_inhibit), 0x8,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_rnghoff_rsvd,
     {"Reserved",
      "docsis_ucd.rnghoffrsvd",
      FT_UINT32, BASE_HEX, NULL, 0xFFF0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_rnghoff_id_ext,
     {"CM Ranging Class ID Extension",
      "docsis_ucd.rngidext",
      FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_chan_class_id_cm,
     {"Channel Class ID (CM)","docsis_ucd.classidcm",
      FT_UINT32, BASE_DEC, VALS (inhibit_allow_vals), 0x1,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_chan_class_id_erouter,
     {"Channel Class ID (eRouter)",
      "docsis_ucd.classiderouter",
      FT_UINT32, BASE_DEC, VALS (inhibit_allow_vals), 0x2,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_chan_class_id_emta,
     {"Channel Class ID (eMTA or EDVA)",
      "docsis_ucd.classidemta",
      FT_UINT32, BASE_DEC, VALS (inhibit_allow_vals), 0x4,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_chan_class_id_estb,
     {"Channel Class ID (DSG/eSTB)",
      "docsis_ucd.classidestb",
      FT_UINT32, BASE_DEC, VALS (inhibit_allow_vals), 0x8,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_chan_class_id_rsvd,
     {"Reserved",
      "docsis_ucd.classidrsvd",
      FT_UINT32, BASE_HEX, NULL, 0xFFF0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_chan_class_id_id_ext,
     {"CM Ranging Class ID Extension",
      "docsis_ucd.classidext",
      FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_subc_excl_band,
     {"UCD Change Indicator Bitmask: Subcarrier Exclusion Band TLV", "docsis_ucd.burst.ucd_change_ind_bitmask_subc_excl_band",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x01,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_unused_subc,
     {"UCD Change Indicator Bitmask: Unused Subcarrier Specification TLV", "docsis_ucd.burst.ucd_change_ind_bitmask_unused_subc",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x02,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_other_subc,
     {"UCD Change Indicator Bitmask: Other than Subcarrier Exclusion Band and Unused Subcarrier Specification TLV", "docsis_ucd.burst.ucd_change_ind_bitmask_other_subc",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x04,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc5,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC5", "docsis_ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc5",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x08,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc6,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC6", "docsis_ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc6",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x10,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc9,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC9", "docsis_ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc9",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x20,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc10,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC10", "docsis_ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc10",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x40,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc11,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC11", "docsis_ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc11",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x80,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc12,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC12", "docsis_ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc12",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x01,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc13,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC13", "docsis_ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc13",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x02,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc3_or_4,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC3 or IUC4", "docsis_ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc3_or_4",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x04,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_reserved,
     {"UCD Change Indicator Bitmask: Reserved", "docsis_ucd.burst.ucd_change_ind_bitmask_reserved",
      FT_UINT8, BASE_HEX, NULL, 0xF8,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_ofdma_timestamp_snapshot,
     {"OFDMA Timestamp Snapshot", "docsis_ucd.ofdma_timestamp_snapshot",
      FT_BYTES, BASE_NONE, NULL, 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_ofdma_cyclic_prefix_size,
     {"OFDMA Cyclic Prefix Size", "docsis_ucd.ofdma_cyclic_prefix_size",
      FT_UINT8, BASE_DEC, VALS(ofdma_cyclic_prefix_size_vals), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_ofdma_rolloff_period_size,
     {"OFDMA Rolloff Period Size", "docsis_ucd.ofdma_rolloff_period_size",
      FT_UINT8, BASE_DEC, VALS(ofdma_rolloff_period_size_vals), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_subc_spacing,
     {"Subcarrier Spacing", "docsis_ucd.subc_spacing",
      FT_UINT8, BASE_DEC, VALS(subc_spacing_vals), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_cent_freq_subc0,
     {"Center Frequency of Subcarrier 0", "docsis_ucd.cent_freq_subc0",
      FT_UINT8, BASE_DEC, NULL, 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_subcarrier_range,
     {"Subcarrier range", "docsis_ucd.subc_range",
      FT_UINT32, BASE_CUSTOM, CF_FUNC(subc_assign_range), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_symb_ofdma_frame,
     {"Symbols in OFDMA frame", "docsis_ucd.symb_ofdma_frame",
      FT_UINT8, BASE_DEC, NULL, 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_rand_seed,
     {"Randomization Seed", "docsis_ucd.rand_seed",
      FT_BYTES, BASE_NONE, NULL, 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_iuc,
     {"Interval Usage Code", "docsis_ucd.iuc",
      FT_UINT8, BASE_DEC, VALS (iuc_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_mod_type,
     {"Modulation Type", "docsis_ucd.burst.modtype",
      FT_UINT8, BASE_DEC, VALS (mod_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_diff_encoding,
     {"Differential Encoding", "docsis_ucd.burst.diffenc",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_preamble_len,
     {"Preamble Length (Bits)", "docsis_ucd.burst.preamble_len",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_preamble_val_off,
     {"Preamble Offset (Bits)", "docsis_ucd.burst.preamble_off",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_fec,
     {"FEC (T)", "docsis_ucd.burst.fec",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "FEC (T) Codeword Parity Bits = 2^T", HFILL}
    },
    {&hf_docsis_burst_fec_codeword,
     {"FEC Codeword Info bytes (k)", "docsis_ucd.burst.fec_codeword",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_scrambler_seed,
     {"Scrambler Seed", "docsis_ucd.burst.scrambler_seed",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "Burst Descriptor", HFILL}
    },
    {&hf_docsis_burst_max_burst,
     {"Max Burst Size (Minislots)", "docsis_ucd.burst.maxburst",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_guard_time,
     {"Guard Time Size (Symbol Times)", "docsis_ucd.burst.guardtime",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Guard Time Size", HFILL}
    },
    {&hf_docsis_burst_last_cw_len,
     {"Last Codeword Length", "docsis_ucd.burst.last_cw_len",
      FT_UINT8, BASE_DEC, VALS (last_cw_len_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_scrambler_onoff,
     {"Scrambler On/Off", "docsis_ucd.burst.scrambleronoff",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rs_int_depth,
     {"RS Interleaver Depth", "docsis_ucd.burst.rsintdepth",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "R-S Interleaver Depth", HFILL}
    },
    {&hf_docsis_rs_int_block,
     {"RS Interleaver Block Size", "docsis_ucd.burst.rsintblock",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "R-S Interleaver Block", HFILL}
    },
    {&hf_docsis_preamble_type,
     {"Preamble Type", "docsis_ucd.burst.preambletype",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_scrambler_onoff,
     {"Scrambler On/Off", "docsis_ucd.burst.scdmascrambleronoff",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      "SCDMA Scrambler On/Off", HFILL}
    },
    {&hf_docsis_ucd_scdma_codes_per_subframe,
     {"SCDMA Codes per Subframe", "docsis_ucd.burst.scdmacodespersubframe",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_framer_int_step_size,
     {"SCDMA Framer Interleaving Step Size", "docsis_ucd.burst.scdmaframerintstepsize",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_tcm_enabled,
     {"TCM Enabled", "docsis_ucd.burst.tcmenabled",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_active_code_hopping,
     {"S-CDMA Selection Mode for Active Codes and Code Hopping", "docsis_ucd.selectcodehop",
      FT_UINT8, BASE_DEC, VALS (tlv20_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_selection_active_codes,
     {"S-CDMA Selection String for Active Codes", "docsis_ucd.selectcode",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_higher_ucd_for_same_ucid,
     {"Higher UCD for the same UCID", "docsis_ucd.highucdpresent",
      FT_BOOLEAN, 8, TFS(&type35ucd_tfs_present_not_present), 0x1,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_higher_ucd_for_same_ucid_resv,
     {"Reserved", "docsis_ucd.highucdresv",
      FT_UINT8, BASE_HEX, NULL, 0xFE,
      NULL, HFILL}
    },
    {&hf_docsis_subc_init_rang,
     {"Subcarriers (Nir) Initial Ranging", "docsis_ucd.burst.subc_init_rang",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_subc_fine_rang,
     {"Subcarriers (Nfr) Fine Ranging", "docsis_ucd.burst.subc_fine_rang",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ofdma_prof_mod_order,
     {"OFDMA Profile: modulation", "docsis_ucd.burst.ofma_prof_mod_order",
      FT_UINT8, BASE_DEC, VALS(ofdma_prof_mod_order), 0xF0,
      NULL, HFILL}
    },
    {&hf_docsis_ofdma_prof_pilot_pattern,
     {"OFDMA Profile: pilot pattern", "docsis_ucd.burst.ofma_prof_pilot_pattern",
      FT_UINT8, BASE_DEC, NULL, 0x0F,
      NULL, HFILL}
    },
    {&hf_docsis_ofdma_prof_num_add_minislots,
     {"OFDMA Profile: Additional Minislots that have identical bit-loading and pilot pattern index", "docsis_ucd.burst.ofma_prof_add_minislots",
      FT_UINT8, BASE_DEC, NULL, 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ofdma_ir_pow_ctrl_start_pow,
     {"OFDMA IR Power Control Starting Power Level", "docsis_ucd.burst.ofma_ir_pow_ctrl_start_pow",
      FT_UINT8, BASE_CUSTOM, CF_FUNC(ofdma_ir_pow_ctrl_start_pow), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ofdma_ir_pow_ctrl_step_size,
     {"OFDMA IR Power Control Step Size", "docsis_ucd.burst.ofma_ir_pow_ctrl_step_size",
      FT_UINT8, BASE_CUSTOM, CF_FUNC(ofdma_ir_pow_ctrl_step_size), 0x00,
      NULL, HFILL}
    },
    /* MAP */
    {&hf_docsis_map_ucd_count,
     {"UCD Count", "docsis_map.ucdcount",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Map UCD Count", HFILL}
    },
    {&hf_docsis_map_numie,
     {"Number of IE's", "docsis_map.numie",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Number of Information Elements", HFILL}
    },
    {&hf_docsis_map_alloc_start,
     {"Alloc Start Time (minislots)", "docsis_map.allocstart",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_map_ack_time,
     {"ACK Time (minislots)", "docsis_map.acktime",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_map_rng_start,
     {"Ranging Backoff Start", "docsis_map.rng_start",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_map_rng_end,
     {"Ranging Backoff End", "docsis_map.rng_end",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_map_data_start,
     {"Data Backoff Start", "docsis_map.data_start",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_map_data_end,
     {"Data Backoff End", "docsis_map.data_end",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_map_ie,
     {"Information Element", "docsis_map.ie",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_map_rsvd,
     {"Reserved", "docsis_map.rsvd",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "Reserved Byte", HFILL}
    },
    {&hf_docsis_map_sid,
     {"Service Identifier", "docsis_map.sid",
      FT_UINT32, BASE_DEC, NULL, 0xFFFC0000,
      NULL, HFILL}
    },
    {&hf_docsis_map_iuc,
     {"Interval Usage Code", "docsis_map.iuc",
      FT_UINT32, BASE_DEC, VALS(iuc_vals), 0x0003c000,
      NULL, HFILL}
    },
    {&hf_docsis_map_offset,
     {"Offset", "docsis_map.offset",
      FT_UINT32, BASE_DEC, NULL, 0x00003fff,
      NULL, HFILL}
    },
    /* RNG-REQ */
    {&hf_docsis_rngreq_sid,
     {"Service Identifier", "docsis_rngreq.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rngreq_pend_compl,
     {"Pending Till Complete", "docsis_rngreq.pendcomp",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Upstream Channel ID", HFILL}
    },
    /* RNG-RSP */
    {&hf_docsis_rngrsp_type,
     {"Type", "docsis_rngrsp.type",
      FT_UINT8, BASE_DEC, VALS(rngrsp_tlv_vals), 0x0,
      "TLV Type", HFILL}
     },
    {&hf_docsis_rngrsp_length,
     {"Length", "docsis_rngrsp.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "TLV Length", HFILL}
     },
    {&hf_docsis_rngrsp_sid,
     {"Service Identifier", "docsis_rngrsp.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_rngrsp_timing_adj,
     {"Timing Adjust (6.25us/64)", "docsis_rngrsp.timingadj",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Timing Adjust", HFILL}
     },
    {&hf_docsis_rngrsp_power_adj,
     {"Power Level Adjust (0.25dB units)", "docsis_rngrsp.poweradj",
      FT_INT8, BASE_DEC, NULL, 0x0,
      "Power Level Adjust", HFILL}
     },
    {&hf_docsis_rngrsp_freq_adj,
     {"Offset Freq Adjust (Hz)", "docsis_rngrsp.freqadj",
      FT_INT16, BASE_DEC, NULL, 0x0,
      "Frequency Adjust", HFILL}
     },
    {&hf_docsis_rngrsp_xmit_eq_adj,
     {"Transmit Equalisation Adjust", "docsis_rngrsp.xmit_eq_adj",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Timing Equalisation Adjust", HFILL}
     },
    {&hf_docsis_rngrsp_ranging_status,
     {"Ranging Status", "docsis_rngrsp.rng_stat",
      FT_UINT8, BASE_DEC, VALS (rng_stat_vals), 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_rngrsp_down_freq_over,
     {"Downstream Frequency Override (Hz)", "docsis_rngrsp.freq_over",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Downstream Frequency Override", HFILL}
     },
    {&hf_docsis_rngrsp_upstream_ch_over,
     {"Upstream Channel ID Override", "docsis_rngrsp.chid_override",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
     /* REG_REQ */
    {&hf_docsis_regreq_sid,
     {"Service Identifier", "docsis_regreq.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
     /* REG_RSP */
    {&hf_docsis_regrsp_sid,
     {"Service Identifier", "docsis_regrsp.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_regrsp_response,
     {"Response Code", "docsis_regrsp.respnse",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    /* BPKM */
    {&hf_docsis_bpkm_code,
     {"BPKM Code", "docsis_bpkm.code",
      FT_UINT8, BASE_DEC, VALS (code_field_vals), 0x0,
      "BPKM Request Message", HFILL}
    },
    {&hf_docsis_bpkm_ident,
     {"BPKM Identifier", "docsis_bpkm.ident",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr,
     {"BPKM Attributes", "docsis_bpkm.attr",
      FT_BYTES, BASE_NONE|BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkm_length,
     {"BPKM Length", "docsis_bpkm.length",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_serial_num,
     {"Serial Number", "docsis_bpkm.attr.serialnum",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_manf_id,
     {"Manufacturer Id", "docsis_bpkm.attr.manfid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_mac_addr,
     {"Mac Address", "docsis_bpkm.attr.macaddr",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_rsa_pub_key,
     {"RSA Public Key", "docsis_bpkm.attr.rsa_pub_key",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cm_id,
     {"CM Identification", "docsis_bpkm.attr.cmid",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_display_str,
     {"Display String", "docsis_bpkm.attr.dispstr",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_auth_key,
     {"Auth Key", "docsis_bpkm.attr.auth_key",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_tek,
     {"Traffic Encryption Key", "docsis_bpkm.attr.tek",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_key_life,
     {"Key Lifetime(s)", "docsis_bpkm.attr.keylife",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_key_seq,
     {"Key Sequence Number", "docsis_bpkm.attr.keyseq",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_hmac_digest,
     {"HMAC Digest", "docsis_bpkm.attr.hmacdigest",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_said,
     {"SAID", "docsis_bpkm.attr.said",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Security Association ID", HFILL}
    },
    {&hf_docsis_bpkmattr_tek_params,
     {"TEK Parameters", "docsis_bpkm.attr.tekparams",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cbc_iv,
     {"CBC IV", "docsis_bpkm.attr.cbciv",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Cypher Block Chaining", HFILL}
    },
    {&hf_docsis_bpkmattr_error_code,
     {"Error Code", "docsis_bpkm.attr.errcode",
      FT_UINT8, BASE_DEC, VALS (error_code_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_vendor_def,
     {"Vendor Defined", "docsis_bpkm.attr.vendordef",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_ca_cert,
     {"CA Certificate", "docsis_bpkm.attr.cacert",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cm_cert,
     {"CM Certificate", "docsis_bpkm.attr.cmcert",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_security_cap,
     {"Security Capabilities", "docsis_bpkm.attr.seccap",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_crypto_suite,
     {"Cryptographic Suite", "docsis_bpkm.attr.cryptosuite",
      FT_UINT16, BASE_HEX, VALS(crypto_suite_attr_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_crypto_suite_list,
     {"Cryptographic Suite List", "docsis_bpkm.attr.crypto_suite_lst",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_bpi_version,
     {"BPI Version", "docsis_bpkm.attr.bpiver",
      FT_UINT8, BASE_DEC, VALS (bpi_ver_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_sa_descr,
     {"SA Descriptor", "docsis_bpkm.attr.sadescr",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_sa_type,
     {"SA Type", "docsis_bpkm.attr.satype",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_sa_query,
     {"SA Query", "docsis_bpkm.attr.saquery",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_sa_query_type,
     {"SA Query Type", "docsis_bpkm.attr.saquery_type",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_ip_address,
     {"IP Address", "docsis_bpkm.attr.ipaddr",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_download_param,
     {"Download Parameters", "docsis_bpkm.attr.dnld_params",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_type,
     {"Type", "docsis_bpkm.attr.type",
      FT_UINT8, BASE_DEC, VALS(bpkmattr_tlv_vals), 0x0,
      "TLV Type", HFILL}
     },
    {&hf_docsis_bpkmattr_length,
     {"Length", "docsis_bpkm.attr.length",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "TLV Length", HFILL}
     },
    /* REG-ACK */
    {&hf_docsis_regack_sid,
     {"Service Identifier", "docsis_regack.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_regack_response,
     {"Response Code", "docsis_regack.respnse",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    /* DAS-RSP */
    {&hf_docsis_dsarsp_response,
     {"Confirmation Code", "docsis_dsarsp.confcode",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dsaack_response,
     {"Confirmation Code", "docsis_dsaack.confcode",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    /* DSC-RSP */
    {&hf_docsis_dscrsp_response,
     {"Confirmation Code", "docsis_dscrsp.confcode",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dscack_response,
     {"Confirmation Code", "docsis_dscack.confcode",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    /* DSD-REQ */
    {&hf_docsis_dsdreq_rsvd,
     {"Reserved", "docsis_dsdreq.rsvd",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dsdreq_sfid,
     {"Service Flow ID", "docsis_dsdreq.sfid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    /* DSD-RSP */
    {&hf_docsis_dsdrsp_confcode,
     {"Confirmation Code", "docsis_dsdrsp.confcode",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dsdrsp_rsvd,
     {"Reserved", "docsis_dsdrsp.rsvd",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    /* DCC-REQ */
    {&hf_docsis_dccreq_type,
     {
      "Type",
      "docsis_dccreq.tlvtype",
      FT_UINT8, BASE_DEC, VALS(dcc_tlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccreq_length,
     {
      "Length",
      "docsis_dccreq.tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccreq_tran_id ,
     {
       "Transaction ID",
       "docsis_dccreq.tran_id",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_up_chan_id ,
     {
       "Up Channel ID",
       "docsis_dccreq.up_chan_id",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcc_ds_params_subtype,
     {
      "Type",
      "docsis_dccreq.ds_tlvtype",
      FT_UINT8, BASE_DEC, VALS(ds_param_subtlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcc_ds_params_length,
     {
      "Length",
      "docsis_dccreq.ds_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccreq_ds_freq ,
     {
       "Frequency",
       "docsis_dccreq.ds_freq",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_ds_mod_type ,
     {
       "Modulation Type",
       "docsis_dccreq.ds_mod_type",
       FT_UINT8, BASE_DEC, VALS (ds_mod_type_vals), 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_ds_sym_rate ,
     {
       "Symbol Rate",
       "docsis_dccreq.ds_sym_rate",
       FT_UINT8, BASE_DEC, VALS (ds_sym_rate_vals), 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_ds_intlv_depth_i ,
     {
       "Interleaver Depth I Value",
       "docsis_dccreq.ds_intlv_depth_i",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_ds_intlv_depth_j ,
     {
       "Interleaver Depth J Value",
       "docsis_dccreq.ds_intlv_depth_j",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_ds_chan_id ,
     {
       "Downstream Channel ID",
       "docsis_dccreq.ds_chan_id",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_ds_sync_sub ,
     {
       "SYNC Substitution",
       "docsis_dccreq.ds_sync_sub",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_ds_ofdm_block_freq ,
     {
       "OFDM Block Frequency",
       "docsis_dccreq.ds_ofdm_block_freq",
       FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &local_units_hz, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_init_tech ,
     {
       "Initialization Technique",
       "docsis_dccreq.init_tech",
       FT_UINT8, BASE_DEC, VALS (init_tech_vals), 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_ucd_sub ,
     {
       "UCD Substitution",
       "docsis_dccreq.ucd_sub",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_said_sub_cur ,
     {
       "SAID Sub - Current Value",
       "docsis_dccreq.said_sub_cur",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_said_sub_new ,
     {
       "SAID Sub - New Value",
       "docsis_dccreq.said_sub_new",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcc_sf_sub_subtype,
     {
      "Type",
      "docsis_dccreq.sf_tlvtype",
      FT_UINT8, BASE_DEC, VALS(sf_sub_subtlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcc_sf_sub_length,
     {
      "Length",
      "docsis_dccreq.sf_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccreq_sf_sfid_cur ,
     {
       "SF Sub - SFID Current Value",
       "docsis_dccreq.sf_sfid_cur",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_sf_sfid_new ,
     {
       "SF Sub - SFID New Value",
       "docsis_dccreq.sf_sfid_new",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_sf_sid_cur ,
     {
       "SF Sub - SID Current Value",
       "docsis_dccreq.sf_sid_cur",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_sf_sid_new ,
     {
       "SF Sub - SID New Value",
       "docsis_dccreq.sf_sid_new",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_sf_unsol_grant_tref ,
     {
       "SF Sub - Unsolicited Grant Time Reference",
       "docsis_dccreq.sf_unsol_grant_tref",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_cmts_mac_addr ,
     {
       "CMTS Mac Address",
       "docsis_dccreq.cmts_mac_addr",
       FT_ETHER, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_key_seq_num ,
     {
       "Auth Key Sequence Number",
       "docsis_dccreq.key_seq_num",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_hmac_digest ,
     {
       "HMAC-DigestNumber",
       "docsis_dccreq.hmac_digest",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    /* DCC-RSP */
    {&hf_docsis_dccrsp_conf_code ,
     {
       "Confirmation Code",
       "docsis_dccrsp.conf_code",
       FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccrsp_type,
     {
      "Type",
      "docsis_dccrsp.tlvtype",
      FT_UINT8, BASE_DEC, VALS(dccrsp_tlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccrsp_length,
     {
      "Length",
      "docsis_dccrsp.tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcc_cm_jump_subtype,
     {
      "Type",
      "docsis_dccrsp.cm_jump_tlvtype",
      FT_UINT8, BASE_DEC, VALS(cm_jump_subtlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcc_cm_jump_length,
     {
      "Length",
      "docsis_dccrsp.cm_jump_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccrsp_cm_jump_time_length ,
     {
       "Length of Jump",
       "docsis_dccrsp.cm_jump_time_length",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccrsp_cm_jump_time_start ,
     {
       "Start Time of Jump",
       "docsis_dccrsp.cm_jump_time_start",
       FT_UINT64, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccrsp_key_seq_num ,
     {
       "Auth Key Sequence Number",
       "docsis_dccrsp.key_seq_num",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccrsp_hmac_digest ,
     {
       "HMAC-Digest Number",
       "docsis_dccrsp.hmac_digest",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    /* DCC-ACK */
    {&hf_docsis_dccack_type,
     {
      "Type",
      "docsis_dccack.tlvtype",
      FT_UINT8, BASE_DEC, VALS(dccack_tlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccack_length,
     {
      "Length",
      "docsis_dccack.tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccack_key_seq_num ,
     {
       "Auth Key Sequence Number",
       "docsis_dccack.key_seq_num",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccack_hmac_digest ,
     {
       "HMAC-DigestNumber",
       "docsis_dccack.hmac_digest",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    /* INIT_RNG_REQ */
    {&hf_docsis_intrngreq_sid,
     {"Service Identifier", "docsis_intrngreq.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    /* DCD */
    {&hf_docsis_dcd_config_ch_cnt,
     {
       "Configuration Change Count",
       "docsis_dcd.config_ch_cnt",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_num_of_frag,
     {
       "Number of Fragments",
       "docsis_dcd.num_of_frag",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_frag_sequence_num,
     {
       "Fragment Sequence Number",
       "docsis_dcd.frag_sequence_num",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_type,
     {
      "Type",
      "docsis_dcd.tlvtype",
      FT_UINT8, BASE_DEC, VALS(dcd_tlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_length,
     {
      "Length",
      "docsis_dcd.tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_down_classifier_subtype,
     {
      "Type",
      "docsis_dcd.down_classifier_tlvtype",
      FT_UINT8, BASE_DEC, VALS(dcd_down_classifier_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_down_classifier_length,
     {
      "Length",
      "docsis_dcd.down_classifier_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_cfr_id,
     {
       "Downstream Classifier Id",
       "docsis_dcd.cfr_id",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_rule_pri,
     {
       "Downstream Classifier Rule Priority",
       "docsis_dcd.cfr_rule_pri",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_ip_subtype,
     {
      "Type",
      "docsis_dcd.cfr_ip_tlvtype",
      FT_UINT8, BASE_DEC, VALS(dcd_cfr_ip_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_cfr_ip_length,
     {
      "Length",
      "docsis_dcd.cfr_ip_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_cfr_ip_source_addr,
     {
       "Downstream Classifier IP Source Address",
       "docsis_dcd.cfr_ip_source_addr",
       FT_IPv4, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_ip_source_mask,
     {
       "Downstream Classifier IP Source Mask",
       "docsis_dcd.cfr_ip_source_mask",
       FT_IPv4, BASE_NETMASK, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_ip_dest_addr,
     {
       "Downstream Classifier IP Destination Address",
       "docsis_dcd.cfr_ip_dest_addr",
       FT_IPv4, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_ip_dest_mask,
     {
       "Downstream Classifier IP Destination Mask",
       "docsis_dcd.cfr_ip_dest_mask",
       FT_IPv4, BASE_NETMASK, NULL, 0x0,
       "Downstream Classifier IP Destination Address",
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_tcpudp_srcport_start,
     {
       "Downstream Classifier IP TCP/UDP Source Port Start",
       "docsis_dcd.cfr_ip_tcpudp_srcport_start",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_tcpudp_srcport_end,
     {
       "Downstream Classifier IP TCP/UDP Source Port End",
       "docsis_dcd.cfr_ip_tcpudp_srcport_end",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_tcpudp_dstport_start,
     {
       "Downstream Classifier IP TCP/UDP Destination Port Start",
       "docsis_dcd.cfr_ip_tcpudp_dstport_start",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_tcpudp_dstport_end,
     {
       "Downstream Classifier IP TCP/UDP Destination Port End",
       "docsis_dcd.cfr_ip_tcpudp_dstport_end",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_rule_id,
     {
       "DSG Rule Id",
       "docsis_dcd.rule_id",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_rule_pri,
     {
       "DSG Rule Priority",
       "docsis_dcd.rule_pri",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_rule_ucid_list,
     {
       "DSG Rule UCID Range",
       "docsis_dcd.rule_ucid_list",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_clid_subtype,
     {
      "Type",
      "docsis_dcd.clid_tlvtype",
      FT_UINT8, BASE_DEC, VALS(dcd_clid_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_clid_length,
     {
      "Length",
      "docsis_dcd.clid_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_clid_bcast_id,
     {
       "DSG Rule Client ID Broadcast ID",
       "docsis_dcd.clid_bcast_id",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_clid_known_mac_addr,
     {
       "DSG Rule Client ID Known MAC Address",
       "docsis_dcd.clid_known_mac_addr",
       FT_ETHER, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_clid_ca_sys_id,
     {
       "DSG Rule Client ID CA System ID",
       "docsis_dcd.clid_ca_sys_id",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_clid_app_id,
     {
       "DSG Rule Client ID Application ID",
       "docsis_dcd.clid_app_id",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_dsg_rule_subtype,
     {
      "Type",
      "docsis_dcd.rule_tlvtype",
      FT_UINT8, BASE_DEC, VALS(dcd_dsg_rule_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_dsg_rule_length,
     {
      "Length",
      "docsis_dcd.rule_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_rule_tunl_addr,
     {
       "DSG Rule Tunnel MAC Address",
       "docsis_dcd.rule_tunl_addr",
       FT_ETHER, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_rule_cfr_id,
     {
       "DSG Rule Classifier ID",
       "docsis_dcd.rule_cfr_id",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_rule_vendor_spec,
     {
       "DSG Rule Vendor Specific Parameters",
       "docsis_dcd.rule_vendor_spec",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfg_subtype,
     {
      "Type",
      "docsis_dcd.cfg_tlvtype",
      FT_UINT8, BASE_DEC, VALS(dcd_cfg_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_cfg_length,
     {
      "Length",
      "docsis_dcd.cfg_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_cfg_chan,
     {
       "DSG Configuration Channel",
       "docsis_dcd.cfg_chan",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfg_tdsg1,
     {
       "DSG Initialization Timeout (Tdsg1)",
       "docsis_dcd.cfg_tdsg1",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfg_tdsg2,
     {
       "DSG Operational Timeout (Tdsg2)",
       "docsis_dcd.cfg_tdsg2",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfg_tdsg3,
     {
       "DSG Two-Way Retry Timer (Tdsg3)",
       "docsis_dcd.cfg_tdsg3",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfg_tdsg4,
     {
       "DSG One-Way Retry Timer (Tdsg4)",
       "docsis_dcd.cfg_tdsg4",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfg_vendor_spec,
     {
       "DSG Configuration Vendor Specific Parameters",
       "docsis_dcd.cfg_vendor_spec",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    /* MDD */
    {&hf_docsis_mdd_ccc,
     {"Configuration Change Count", "docsis_mdd.ccc",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Configuration Change Count", HFILL}
    },
    {&hf_docsis_mdd_number_of_fragments,
     {"Number of Fragments", "docsis_mdd.number_of_fragments",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Number of Fragments", HFILL}
    },
    {&hf_docsis_mdd_fragment_sequence_number,
     {"Fragment Sequence Number", "docsis_mdd.fragment_sequence_number",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Fragment Sequence Number", HFILL}
    },
    {&hf_docsis_mdd_current_channel_dcid,
     {"Current Channel DCID", "docsis_mdd.current_channel_dcid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Current Channel DCID", HFILL}
    },
    {&hf_docsis_mdd_ds_active_channel_list_subtype,
     {"Type", "docsis_mdd.downstream_active_channel_list_tlvtype",
      FT_UINT8, BASE_DEC, VALS(mdd_ds_active_channel_list_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_ds_active_channel_list_length,
     {"Length", "docsis_mdd.downstream_active_channel_list_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_channel_id,
     {"Channel ID", "docsis_mdd.downstream_active_channel_list_channel_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Downstream Active Channel List Channel ID", HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_frequency,
     {"Frequency", "docsis_mdd.downstream_active_channel_list_frequency",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Mdd Downstream Active Channel List Frequency", HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_annex,
     {"Annex", "docsis_mdd.downstream_active_channel_list_annex",
      FT_UINT8, BASE_DEC, VALS(J83_annex_vals), 0xF0,
      "Mdd Downstream Active Channel List Annex", HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_modulation_order,
     {"Modulation Order", "docsis_mdd.downstream_active_channel_list_modulation_order",
      FT_UINT8, BASE_DEC, VALS(modulation_order_vals), 0x0F,
      "Mdd Downstream Active Channel List Modulation Order", HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_primary_capable,
     {"Primary Capable", "docsis_mdd.downstream_active_channel_list_primary_capable",
      FT_UINT8, BASE_DEC, VALS(primary_capable_vals), 0x0,
      "Mdd Downstream Active Channel List Primary Capable", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask,
     {"CM-STATUS Event Enable Bitmask", "docsis_mdd.cm_status_event_enable_bitmask",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_timeout,
     {"MDD Timeout", "docsis_mdd.downstream_active_channel_list_mdd_timeout",
      FT_UINT16, BASE_DEC, NULL, 0x0002,
      "Mdd Downstream Active Channel List MDD Timeout", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_failure,
     {"QAM/FEC Lock Failure", "docsis_mdd.cm_status_event_enable_bitmask_qam_fec_lock_failure",
      FT_UINT16, BASE_DEC, NULL, 0x0004,
      "Mdd Downstream Active Channel List QAM/FEC Lock Failure", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_recovery,
     {"MDD Recovery", "docsis_mdd.cm_status_event_enable_bitmask_mdd_recovery",
      FT_UINT16, BASE_DEC, NULL, 0x0010,
      "CM-STATUS event MDD Recovery", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_recovery,
     {"QAM/FEC Lock Recovery", "docsis_mdd.cm_status_event_enable_bitmask_qam_fec_lock_recovery",
      FT_UINT16, BASE_DEC, NULL, 0x0020,
      "CM-STATUS event QAM/FEC Lock Recovery", HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_map_ucd_transport_indicator,
     {"MAP and UCD transport indicator", "docsis_mdd.downstream_active_channel_list_map_ucd_transport_indicator",
      FT_UINT8, BASE_DEC, VALS(map_ucd_transport_indicator_vals), 0x0,
      "Mdd Downstream Active Channel List MAP and UCD Transport Indicator", HFILL}
    },
    {&hf_docsis_mdd_ofdm_plc_parameters,
     {"OFDM PLC Parameters", "docsis_mdd.ofdm_plc_parameters",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_ofdm_plc_parameters_tukey_raised_cosine_window,
     {"Tukey raised cosine window", "docsis_mdd.ofdm_plc_parameters_tukey_raised_cosine_window",
      FT_UINT8, BASE_DEC, VALS(tukey_raised_cosine_vals), 0x07,
      "OFDM PLC Parameters Tukey raised cosine window", HFILL}
    },
    {&hf_docsis_mdd_ofdm_plc_parameters_cyclic_prefix,
     {"Cyclic prefix", "docsis_mdd.ofdm_plc_parameters_cyclic_prefix",
      FT_UINT8, BASE_DEC, VALS(cyclic_prefix_vals), 0x38,
      "OFDM PLC parameters Cyclic prefix", HFILL}
    },
    {&hf_docsis_mdd_ofdm_plc_parameters_sub_carrier_spacing,
     {"Sub carrier spacing", "docsis_mdd.ofdm_plc_parameters_sub_carrier_spacing",
      FT_UINT8, BASE_DEC, VALS(spacing_vals), 0x40,
      "OFDM PLC parameters Sub carrier spacing", HFILL}
    },
    {&hf_docsis_mdd_up_active_channel_list_subtype,
     {"Type", "docsis_mdd.up_active_channel_list_tlvtype",
      FT_UINT8, BASE_DEC, VALS(mdd_up_active_channel_list_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_up_active_channel_list_length,
     {"Length", "docsis_mdd.up_active_channel_list_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_t4_timeout,
     {"T4 timeout", "docsis_mdd.cm_status_event_enable_bitmask_t4_timeout",
      FT_UINT16, BASE_DEC, NULL, 0x0040,
      "CM-STATUS event T4 timeout", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_t3_retries_exceeded,
     {"T3 Retries Exceeded", "docsis_mdd.cm_status_event_enable_bitmask_t3_retries_exceeded",
      FT_UINT16, BASE_DEC, NULL, 0x0080,
      "CM-STATUS event T3 Retries Exceeded", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_successful_ranging_after_t3_retries_exceeded,
     {"Successful Ranging after T3 Retries Exceeded", "docsis_mdd.cm_status_event_enable_bitmask_successful_ranging_after_t3_retries_exceeded",
      FT_UINT16, BASE_DEC, NULL, 0x0100,
      "CM-STATUS event Successful Ranging after T3 Retries Exceeded", HFILL}
    },
    {&hf_docsis_mdd_mac_domain_downstream_service_group_channel_id,
     {"Channel Id", "docsis_mdd.mac_domain_downstream_service_group_channel_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Mac Domain Downstream Service Group Channel Id", HFILL}
    },
    {&hf_docsis_mdd_ds_service_group_subtype,
     {"Type", "docsis_mdd.ds_service_group_type",
      FT_UINT8, BASE_DEC, VALS(mdd_ds_service_group_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_ds_service_group_length,
     {"Length", "docsis_mdd.ds_service_group_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_mac_domain_downstream_service_group_md_ds_sg_identifier,
     {"MD-DS-SG Identifier", "docsis_mdd.mac_domain_downstream_service_group_md_ds_sg_identifier",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Mac Domain Downstream Service Group MD-DS-SG Identifier", HFILL}
    },
    {&hf_docsis_mdd_type,
     {"Type", "docsis_mdd.type",
      FT_UINT8, BASE_DEC, VALS(mdd_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_length,
     {"Length", "docsis_mdd.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_downstream_ambiguity_resolution_frequency,
     {"Frequency", "docsis_mdd.downstream_ambiguity_resolution_frequency",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Mdd Downstream Ambiguity Resolution frequency", HFILL}
    },
    {&hf_docsis_mdd_channel_profile_reporting_control_subtype,
     {"Type", "docsis_mdd.channel_profile_reporting_control_type",
      FT_UINT8, BASE_DEC, VALS(mdd_channel_profile_reporting_control_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_channel_profile_reporting_control_length,
     {"Length", "docsis_mdd.channel_profile_reporting_control_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_rpc_center_frequency_spacing,
     {"RPC Center Frequency Spacing", "docsis_mdd.rpc_center_frequency_spacing",
      FT_UINT8, BASE_DEC, VALS(rpc_center_frequency_spacing_vals), 0x0,
      "Mdd RPC Center Frequency Spacing", HFILL}
    },
    {&hf_docsis_mdd_verbose_rcp_reporting,
     {"Verbose RCP reporting", "docsis_mdd.verbose_rpc_reporting",
      FT_UINT8, BASE_DEC, VALS(verbose_rpc_reporting_vals), 0x0,
      "Mdd Verbose RPC Reporting", HFILL}
    },
    {&hf_docsis_mdd_ip_init_param_subtype,
     {"Type", "docsis_mdd.ip_init_param_type",
      FT_UINT8, BASE_DEC, VALS(mdd_ip_init_param_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_ip_init_param_length,
     {"Length", "docsis_mdd.ip_init_param_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_ip_provisioning_mode,
     {"IP Provisioning Mode", "docsis_mdd.ip_provisioning_mode",
      FT_UINT8, BASE_DEC, VALS(ip_provisioning_mode_vals), 0x0,
      "Mdd IP Provisioning Mode", HFILL}
    },
    {&hf_docsis_mdd_pre_registration_dsid,
     {"Pre-registration DSID", "docsis_mdd.pre_registration_dsid",
      FT_UINT24, BASE_DEC, NULL, 0x0FFFFF,
      "Mdd Pre-registration DSID", HFILL}
    },
    {&hf_docsis_mdd_early_authentication_and_encryption,
     {"Early Authentication and Encryption", "docsis_mdd.early_authentication_and_encryption",
      FT_UINT8, BASE_DEC, VALS(eae_vals), 0x0,
      "Mdd Early Authentication and Encryption", HFILL}
    },
    {&hf_docsis_mdd_upstream_active_channel_list_upstream_channel_id,
     {"Upstream Channel Id", "docsis_mdd.upstream_active_channel_list_upstream_channel_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Upstream Active Channel List Upstream Channel Id", HFILL}
    },
    {&hf_docsis_mdd_upstream_ambiguity_resolution_channel_list_channel_id,
     {"Channel Id", "docsis_mdd.upstream_ambiguity_resolution_channel_list_channel_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Mac Domain Upstream Ambiguity Resolution Channel List Channel Id", HFILL}
    },
    {&hf_docsis_mdd_upstream_frequency_range,
     {"Upstream Frequency Range", "docsis_mdd.upstream_frequency_range",
      FT_UINT8, BASE_DEC, VALS(upstream_frequency_range_vals), 0x0,
      "Mdd Upstream Frequency Range", HFILL}
    },
    {&hf_docsis_mdd_symbol_clock_locking_indicator,
     {"Symbol Clock Locking Indicator", "docsis_mdd.symbol_clock_locking_indicator",
      FT_UINT8, BASE_DEC, VALS(symbol_clock_locking_indicator_vals), 0x0,
      "Mdd Symbol Clock Locking Indicator", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_control_subtype,
     {"Type", "docsis_mdd.cm_status_event_control_type",
      FT_UINT8, BASE_DEC, VALS(mdd_cm_status_event_control_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_control_length,
     {"Length", "docsis_mdd.cm_status_event_control_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_event_type,
     {"Event Type", "docsis_mdd.event_type",
      FT_UINT8, BASE_DEC, VALS(symbol_cm_status_event_vals), 0x0,
      "Mdd CM-STATUS Event Type", HFILL}
    },
    {&hf_docsis_mdd_maximum_event_holdoff_timer,
     {"Maximum Event Holdoff Timer (units of 20 ms)", "docsis_mdd.maximum_event_holdoff_timer",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Mdd Maximum Event Holdoff Timer", HFILL}
    },
    {&hf_docsis_mdd_maximum_number_of_reports_per_event,
     {"Maximum Number of Reports per Event", "docsis_mdd.maximum_number_of_reports_per_event",
      FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS, VALS(unique_unlimited), 0x0,
      "Mdd Maximum Number of Reports per Event", HFILL}
    },
    {&hf_docsis_mdd_upstream_transmit_power_reporting,
     {"Upstream Transmit Power Reporting", "docsis_mdd.upstream_transmit_power_reporting",
      FT_UINT8, BASE_DEC, VALS(upstream_transmit_power_reporting_vals), 0x0,
      "Mdd Upstream Transmit Power Reporting", HFILL}
    },
    {&hf_docsis_mdd_dsg_da_to_dsid_subtype,
     {"Type", "docsis_mdd.dsg_da_to_dsid_type",
      FT_UINT8, BASE_DEC, VALS(mdd_cm_dsg_da_to_dsid_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_dsg_da_to_dsid_length,
     {"Length", "docsis_mdd.dsg_da_to_dsid_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_dsg_da_to_dsid_association_da,
     {"Destination Address", "docsis_mdd.dsg_da_to_dsid_association_da",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      "Mdd DSG DA to DSID association Destination Address", HFILL}
    },
    {&hf_docsis_mdd_dsg_da_to_dsid_association_dsid,
     {"DSID", "docsis_mdd.dsg_da_to_dsid_association_dsid",
      FT_UINT24, BASE_DEC, NULL, 0x0FFFFF,
      "Mdd Mdd DSG DA to DSID association DSID", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events,
     {"CM-STATUS Event Enable Bitmask for Non-Channel-Specific Events", "docsis_mdd.cm_status_event_enable_non_channel_specific_events",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_sequence_out_of_range,
     {"Sequence out of range", "docsis_mdd.cm_status_event_enable_non_channel_specific_events_sequence_out_of_range",
      FT_UINT16, BASE_DEC, NULL, 0x0008,
      "CM-STATUS event non-channel-event Sequence out of range", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_operating_on_battery_backup,
     {"CM operating on battery backup", "docsis_mdd.cm_status_event_enable_non_channel_specific_events_cm_operating_on_battery_backup",
      FT_UINT16, BASE_DEC, NULL, 0x0200,
      "CM-STATUS event non-channel-event Cm operating on battery backup", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_returned_to_ac_power,
     {"Returned to AC power", "docsis_mdd.cm_status_event_enable_non_channel_specific_events_cm_returned_to_ac_power",
      FT_UINT16, BASE_DEC, NULL, 0x0400,
      "CM-STATUS event non-channel-event Cm returned to AC power", HFILL}
    },
    {&hf_docsis_mdd_extended_upstream_transmit_power_support,
     { "Extended Upstream Transmit Power Support", "docsis_mdd.extended_upstream_transmit_power_support",
       FT_BOOLEAN, BASE_NONE, TFS(&mdd_tfs_on_off), 0x0,
       "Mdd Extended Upstream Transmit Power Support", HFILL}
    },
    /* B_INIT_RNG_REQ */
    {&hf_docsis_bintrngreq_capflags,
     {"Capability Flags", "docsis_bintrngreq.capflags",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bintrngreq_capflags_frag,
     {"Pre-3.0 Fragmentation", "docsis_bintrngreq.capflags.frag",
      FT_BOOLEAN, 8, NULL, (1<<7),
      "Pre-3.0 DOCSIS fragmentation is supported prior to registration", HFILL }
    },
    {&hf_docsis_bintrngreq_capflags_encrypt,
     {"Early Auth. & Encrypt", "docsis_bintrngreq.capflags.encrypt",
      FT_BOOLEAN, 8, NULL, (1<<6),
      "Early Authentication and Encryption supported", HFILL }
    },
    {&hf_docsis_bintrngreq_mddsgid,
     {"MD-DS-SG-ID", "docsis_bintrngreq.mddsgid",
      FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
      "MAC Domain Downstream Service Group Identifier", HFILL}
    },
    /* DBC_REQ */
    {&hf_docsis_dbcreq_number_of_fragments,
     {"Number of Fragments", "docsis_dbcreq.number_of_fragments",
      FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dbcreq_fragment_sequence_number,
     {"Fragment Seq No", "docsis_dbcreq.fragment_sequence_number",
      FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    /* DBC_RSP */
    {&hf_docsis_dbcrsp_conf_code,
     {"Confirmation Code", "docsis_dbcrsp.conf_code",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    /* DPV_REQ/RSP */
    {&hf_docsis_dpv_flags,
     {"Flags", "docsis_dpv.flags",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpv_us_sf,
     {"Upstream Service Flow ID", "docsis_dpv.us_sf",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpv_n,
     {"N (Measurement avaraging factor)", "docsis_dpv.n",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpv_start,
     {"Start Reference Point", "docsis_dpv.start",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpv_end,
     {"End Reference Point", "docsis_dpv.end",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpv_ts_start,
     {"Timestamp Start", "docsis_dpv.ts_start",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpv_ts_end,
     {"Timestamp End", "docsis_dpv.ts_end",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    /* CM Status */
    {&hf_docsis_cmstatus_e_t_mdd_t,
     {"Secondary Channel MDD timeout", "docsis_cmstatus.mdd_timeout", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_qfl_f,
     {"QAM/FEC lock failure", "docsis_cmstatus.qam_fec_lock_failure", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_s_o,
     {"Sequence out-of-range", "docsis_cmstatus.sequence_out_of_range", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_mdd_r,
     {"Secondary Channel MDD Recovery", "docsis_cmstatus.mdd_recovery", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_qfl_r,
     {"QAM/FEC Lock Recovery", "docsis_cmstatus.qam_fec_lock_recovery", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_t4_t,
     {"T4 timeout", "docsis_cmstatus.t4_timeout", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_t3_e,
     {"T3 retries exceeded", "docsis_cmstatus.t3_retries_exceeded", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_rng_s,
     {"Successful ranging after T3 retries exceeded", "docsis_cmstatus.successful_ranging_after_t3_retries_exceeded", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_cm_b,
     {"CM operating on battery backup", "docsis_cmstatus.cm_on_battery", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_cm_a,
     {"CM returned to A/C power", "docsis_cmstatus.cm_on_ac_power", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_descr,
     {"Description", "docsis_cmstatus.description",FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_ds_ch_id,
     {"Downstream Channel ID", "docsis_cmstatus.ds_chid",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_us_ch_id,
     {"Upstream Channel ID", "docsis_cmstatus.us_chid",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_dsid,
     {"DSID", "docsis_cmstatus.dsid", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_tlv_data,
     {"TLV Data", "docsis_cmstatus.tlv_data", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_type,
     {"Type", "docsis_cmstatus.type",FT_UINT8, BASE_DEC, VALS(cmstatus_tlv_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_length,
     {"Length", "docsis_cmstatus.length",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    /* CM_CTRL_REQ */
    {&hf_docsis_cmctrl_tlv_mute,
     {"Upstream Channel RF Mute", "docsis_cmctrl.mute",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_tlv_mute_timeout,
     {"RF Mute Timeout Interval", "docsis_cmctrl.mute_timeout",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_tlv_reinit,
     {"CM Reinitialize", "docsis_cmctrl.reinit",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_tlv_disable_fwd,
     {"Disable Forwarding", "docsis_cmctrl.disable_fwd",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_tlv_ds_event,
     {"Override Downstream Events", "docsis_cmctrl.ds_event",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_tlv_us_event,
     {"Override Upstream Events", "docsis_cmctrl.us_event",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_tlv_event,
     {"Override Non-Channel-Specific Events", "docsis_cmctrl.event",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrlreq_tlv_data,
     {"TLV Data", "docsis_cmctrl.tlv_data",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrlreq_type,
     {"Type", "docsis_cmctrl.tlv_type",
      FT_UINT8, BASE_DEC, VALS(cmctrlreq_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrlreq_length,
     {"Length", "docsis_cmctrl.tlv_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrlreq_us_type,
     {"Type", "docsis_cmctrl.us_event_type",
      FT_UINT8, BASE_DEC, VALS(cmctrlreq_us_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrlreq_us_length,
     {"Length", "docsis_cmctrl.us_event_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_us_event_ch_id,
     {"Upstream Channel ID", "docsis_cmctrl.us_event.chid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_us_event_mask,
     {"Upstream Status Event Enable Bitmask", "docsis_cmctrl.us_event.mask",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_ds_type,
     {"Type", "docsis_cmctrl.ds_event_type",
      FT_UINT8, BASE_DEC, VALS(cmctrlreq_ds_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_ds_length,
     {"Length", "docsis_cmctrl.ds_event_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_ds_event_ch_id,
     {"Downstream Channel ID", "docsis_cmctrl.ds_event.chid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_ds_event_mask,
     {"Downstream Status Event Enable Bitmask", "docsis_cmctrl.ds_event.mask",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    /* REG_REQ_MP */
    {&hf_docsis_regreqmp_sid,
     {"Sid", "docsis_regreqmp.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Reg-Req-Mp Sid", HFILL}
    },
    {&hf_docsis_regreqmp_number_of_fragments,
     {"Number of Fragments", "docsis_regreqmp.number_of_fragments",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reg-Req-Mp Number of Fragments", HFILL}
    },
    {&hf_docsis_regreqmp_fragment_sequence_number,
     {"Fragment Sequence Number", "docsis_regreqmp.fragment_sequence_number",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reg-Req-Mp Fragment Sequence Number", HFILL}
    },
    /* REG_RSP_MP */
    {&hf_docsis_regrspmp_sid,
     {"Sid", "docsis_regrspmp.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Reg-Rsp-Mp Sid", HFILL}
    },
    {&hf_docsis_regrspmp_response,
     {"Response", "docsis_regrspmp.response",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reg-Rsp-Mp Response", HFILL}
    },
    {&hf_docsis_regrspmp_number_of_fragments,
     {"Number of Fragments", "docsis_regrspmp.number_of_fragments",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reg-Rsp-Mp Number of Fragments", HFILL}
    },
    {&hf_docsis_regrspmp_fragment_sequence_number,
     {"Fragment Sequence Number", "docsis_regrspmp.fragment_sequence_number",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reg-Rsp-Mp Fragment Sequence Number", HFILL}
    },
    /* OCD */
    {&hf_docsis_ocd_tlv_unknown,
      {"Unknown TLV", "docsis_ocd.unknown_tlv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_ccc,
      {"Configuration Change Count", "docsis_ocd.ccc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_four_trans_size,
      {"Discrete Fourier Transform Size", "docsis_ocd.tlv.four_trans_size", FT_UINT8, BASE_DEC, VALS (docsis_ocd_four_trans_size), 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_cycl_pref,
      {"Cylic Prefix", "docsis_ocd.tlv.cyc_pref", FT_UINT8, BASE_DEC, VALS (docsis_ocd_cyc_prefix), 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_roll_off,
      {"Roll Off", "docsis_ocd.tlv.roll_off", FT_UINT8, BASE_DEC, VALS (docsis_ocd_roll_off), 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_ofdm_spec_loc,
      {"OFDM Spectrum Location", "docsis_ocd.tlv.ofdm_spec_loc", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &local_units_hz, 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_time_int_depth,
      {"Time Interleaving Depth", "docsis_ocd.tlv.time_int_depth", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_prim_cap_ind,
      {"Primary Capable Indicator", "docsis_ocd.tlv.prim_cap_ind", FT_UINT8, BASE_DEC, VALS(docsis_ocd_prim_cap_ind_str), 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_subc_assign_type,
      {"Assignment type", "docsis_ocd.tlv.subc_assign.type", FT_UINT8, BASE_DEC, VALS(docsis_ocd_subc_assign_type_str), 0xC0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_subc_assign_value,
      {"Assignment value", "docsis_ocd.tlv.subc_assign.value", FT_UINT8, BASE_DEC, VALS(docsis_ocd_subc_assign_value_str), 0x20, NULL, HFILL}
    },
    {&hf_docsis_ocd_subc_assign_subc_type,
      {"Subcarrier Type", "docsis_ocd.tlv.subc_assign.subc_type", FT_UINT8, BASE_DEC, VALS(docsis_ocd_subc_assign_subc_type_str), 0x1F, NULL, HFILL}
    },
    {&hf_docsis_ocd_subc_assign_range,
      {"Subcarrier index range", "docsis_ocd.tlv.subc_assign.range", FT_UINT32, BASE_CUSTOM, CF_FUNC(subc_assign_range), 0x00, NULL, HFILL}
    },
    {&hf_docsis_ocd_subc_assign_index,
      {"Subcarrier index", "docsis_ocd.tlv.subc_assign.index", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_data,
     {"TLV Data", "docsis_ocd.tlv_data", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_type,
     {"Type", "docsis_ocd.type",FT_UINT8, BASE_DEC, VALS(ocd_tlv_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_length,
     {"Length", "docsis_ocd.length",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    /* DPD */
    {&hf_docsis_dpd_tlv_unknown,
     {"Unknown TLV", "docsis_dpd.unknown_tlv",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpd_prof_id,
     {"Profile Identifier", "docsis_dpd.prof_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_dpd_ccc,
     {"Configuration Change Count", "docsis_dpd.ccc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_type,
      {"Subcarrier Assignment Type", "docsis_dpd.tlv.subc_assign.type", FT_UINT8, BASE_DEC, VALS(docsis_dpd_subc_assign_type_str), 0xC0, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_value,
      {"Subcarrier Assignment Value", "docsis_dpd.tlv.subc_assign.value", FT_UINT8, BASE_DEC, VALS(docsis_dpd_subc_assign_value_str), 0x20, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_reserved,
      {"reserved", "docsis_dpd.tlv.subc_assign.reserved", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_modulation,
     {"Subcarrier Assignment Modulation", "docsis_dpd.tlv.subc_assign.modulation", FT_UINT8, BASE_DEC, VALS(docsis_dpd_subc_assign_modulation_str), 0x0F, NULL, HFILL}
    },
    {&hf_docsis_dpd_subc_assign_range,
     {"Subcarrier index range", "docsis_dpd.tlv.subc_assign.range", FT_UINT32, BASE_CUSTOM, CF_FUNC(subc_assign_range), 0x00, NULL, HFILL}
    },
    {&hf_docsis_dpd_subc_assign_index,
     {"Subcarrier index", "docsis_dpd.tlv.subc_assign.index", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_vector_oddness,
     {"Odd or even", "docsis_dpd.tlv.subc_assign_vect.oddness", FT_UINT8, BASE_DEC, VALS(docsis_dpd_tlv_subc_assign_vector_oddness_str), 0x80, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_vector_reserved,
     {"Reserved", "docsis_dpd.tlv.subc_assign_vect.reserved", FT_UINT8, BASE_DEC, NULL, 0x60, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_vector_subc_start,
     {"Subcarrier start", "docsis_dpd.tlv.subc_assign_vect.subc_start", FT_UINT16, BASE_DEC, NULL, 0x1FFF, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_vector_modulation_odd,
     {"Modulation", "docsis_dpd.tlv.subc_assign_vect.modulation", FT_UINT8, BASE_DEC, VALS(docsis_dpd_tlv_subc_assign_vector_modulation_str), 0xF0, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_vector_modulation_even,
     {"Modulation", "docsis_dpd.tlv.subc_assign_vect.modulation", FT_UINT8, BASE_DEC, VALS(docsis_dpd_tlv_subc_assign_vector_modulation_str), 0x0F, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_data,
     {"TLV Data", "docsis_dpd.tlv_data", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_dpd_type,
     {"Type", "docsis_dpd.type",FT_UINT8, BASE_DEC, VALS(dpd_tlv_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_dpd_length,
     {"Length", "docsis_dpd.length",FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    /* MAC Management */
    {&hf_docsis_mgt_upstream_chid,
     {"Upstream Channel ID", "docsis_mgmt.upchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_down_chid,
     {"Downstream Channel ID", "docsis_ucd.downchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Management Message", HFILL}
    },
    {&hf_docsis_mgt_tranid,
     {"Transaction Id", "docsis_mgmt.tranid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_dst_addr,
     {"Destination Address", "docsis_mgmt.dst",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_src_addr,
     {"Source Address", "docsis_mgmt.src",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_msg_len,
     {"Message Length - DSAP to End (Bytes)", "docsis_mgmt.msglen",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_dsap,
     {"DSAP", "docsis_mgmt.dsap",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "Destination SAP", HFILL}
    },
    {&hf_docsis_mgt_ssap,
     {"SSAP", "docsis_mgmt.ssap",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "Source SAP", HFILL}
    },
    {&hf_docsis_mgt_control,
     {"Control", "docsis_mgmt.control",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_version,
     {"Version", "docsis_mgmt.version",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_type,
     {"Type", "docsis_mgmt.type",
      FT_UINT8, BASE_DEC, VALS (mgmt_type_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_rsvd,
     {"Reserved", "docsis_mgmt.rsvd",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
  };

  static gint *ett[] = {
    &ett_docsis_sync,
    &ett_docsis_ucd,
    &ett_docsis_tlv,
    &ett_docsis_burst_tlv,
    &ett_docsis_map,
    &ett_docsis_map_ie,
    &ett_docsis_rngreq,
    &ett_docsis_rngrsp,
    &ett_docsis_rngrsptlv,
    &ett_docsis_regreq,
    &ett_docsis_regrsp,
    &ett_docsis_uccreq,
    &ett_docsis_uccrsp,
    &ett_docsis_bpkmreq,
    &ett_docsis_bpkmrsp,
    &ett_docsis_bpkmattr,
    &ett_docsis_bpkmattr_cmid,
    &ett_docsis_bpkmattr_scap,
    &ett_docsis_bpkmattr_tekp,
    &ett_docsis_bpkmattr_sadsc,
    &ett_docsis_bpkmattr_saqry,
    &ett_docsis_bpkmattr_dnld,
    &ett_docsis_bpkmattrtlv,
    &ett_docsis_regack,
    &ett_docsis_dsareq,
    &ett_docsis_dsarsp,
    &ett_docsis_dsaack,
    &ett_docsis_dscreq,
    &ett_docsis_dscrsp,
    &ett_docsis_dscack,
    &ett_docsis_dsdreq,
    &ett_docsis_dsdrsp,
    &ett_docsis_dccreq,
    &ett_docsis_dccreq_sf_sub,
    &ett_docsis_dccreq_ds_params,
    &ett_docsis_dccreq_tlv,
    &ett_docsis_dccrsp,
    &ett_docsis_dccrsp_cm_jump_time,
    &ett_docsis_dccrsp_tlv,
    &ett_docsis_dccack,
    &ett_docsis_dccack_tlv,
    &ett_docsis_intrngreq,
    &ett_docsis_dcd,
    &ett_docsis_dcd_cfr,
    &ett_docsis_dcd_cfr_ip,
    &ett_docsis_dcd_rule,
    &ett_docsis_dcd_clid,
    &ett_docsis_dcd_cfg,
    &ett_docsis_dcd_tlv,
    &ett_docsis_mdd,
    &ett_tlv,
    &ett_sub_tlv,
    &ett_docsis_mdd_ds_active_channel_list,
    &ett_docsis_mdd_ds_service_group,
    &ett_docsis_mdd_channel_profile_reporting_control,
    &ett_docsis_mdd_ip_init_param,
    &ett_docsis_mdd_up_active_channel_list,
    &ett_docsis_mdd_cm_status_event_control,
    &ett_docsis_mdd_dsg_da_to_dsid,
    &ett_docsis_bintrngreq,
    &ett_docsis_dbcreq,
    &ett_docsis_dbcrsp,
    &ett_docsis_dbcack,
    &ett_docsis_dpvreq,
    &ett_docsis_dpvrsp,
    &ett_docsis_cmstatus,
    &ett_docsis_cmstatus_tlv,
    &ett_docsis_cmstatus_tlvtlv,
    &ett_docsis_cmctrlreq,
    &ett_docsis_cmctrlreq_tlv,
    &ett_docsis_cmctrlreq_tlvtlv,
    &ett_docsis_cmctrl_tlv_us_event,
    &ett_docsis_cmctrl_tlv_ds_event,
    &ett_docsis_cmctrlrsp,
    &ett_docsis_regreqmp,
    &ett_docsis_regrspmp,
    &ett_docsis_ocd,
    &ett_docsis_ocd_tlv,
    &ett_docsis_ocd_tlvtlv,
    &ett_docsis_dpd,
    &ett_docsis_dpd_tlv,
    &ett_docsis_dpd_tlvtlv,
    &ett_docsis_dpd_tlv_subcarrier_assignment,
    &ett_docsis_dpd_tlv_subcarrier_assignment_vector,
    &ett_docsis_mgmt,
    &ett_mgmt_pay,
  };

  static ei_register_info ei[] = {
    {&ei_docsis_mgmt_tlvlen_bad, {"docsis_mgmt.tlvlenbad", PI_MALFORMED, PI_ERROR, "Bad TLV length", EXPFILL}},
    {&ei_docsis_mgmt_tlvtype_unknown, { "docsis_mgmt.tlvtypeunknown", PI_PROTOCOL, PI_WARN, "Unknown TLV type", EXPFILL}},
   };

  expert_module_t* expert_docsis_mgmt;

  proto_docsis_mgmt = proto_register_protocol ("DOCSIS Mac Management", "DOCSIS MAC MGMT", "docsis_mgmt");

  proto_register_field_array (proto_docsis_mgmt, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  expert_docsis_mgmt = expert_register_protocol(proto_docsis_mgmt);
  expert_register_field_array(expert_docsis_mgmt, ei, array_length(ei));

  docsis_mgmt_dissector_table = register_dissector_table ("docsis_mgmt",
                                                          "DOCSIS Mac Management", proto_docsis_mgmt,
                                                          FT_UINT8, BASE_DEC);

  /* Register Mac Management commands as their own protocols so we can get the name of the option */
  proto_docsis_sync = proto_register_protocol_in_name_only("DOCSIS Synchronisation Message", "SYNC Message", "docsis_sync", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_ucd = proto_register_protocol_in_name_only("DOCSIS Upstream Channel Descriptor", "DOCSIS UCD", "docsis_ucd", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_map = proto_register_protocol_in_name_only("DOCSIS Upstream Bandwidth Allocation", "DOCSIS MAP", "docsis_map", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_rngreq = proto_register_protocol_in_name_only("DOCSIS Range Request Message", "DOCSIS RNG-REQ", "docsis_rngreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_rngrsp = proto_register_protocol_in_name_only("DOCSIS Ranging Response", "DOCSIS RNG-RSP", "docsis_rngrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_regreq = proto_register_protocol_in_name_only("DOCSIS Registration Requests", "DOCSIS REG-REQ", "docsis_regreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_regrsp = proto_register_protocol_in_name_only("DOCSIS Registration Responses", "DOCSIS REG-RSP", "docsis_regrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_uccreq = proto_register_protocol_in_name_only("DOCSIS Upstream Channel Change Request", "DOCSIS UCC-REQ", "docsis_uccreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_uccrsp = proto_register_protocol_in_name_only("DOCSIS Upstream Channel Change Response", "DOCSIS UCC-RSP", "docsis_uccrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_bpkmreq = proto_register_protocol_in_name_only("DOCSIS Baseline Privacy Key Management Request", "DOCSIS BPKM-REQ", "docsis_bpkm.req", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_bpkmrsp = proto_register_protocol_in_name_only("DOCSIS Baseline Privacy Key Management Response", "DOCSIS BPKM-RSP", "docsis_bpkm.rsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_regack = proto_register_protocol_in_name_only("DOCSIS Registration Acknowledge", "DOCSIS REG-ACK", "docsis_regack", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dsareq = proto_register_protocol_in_name_only("DOCSIS Dynamic Service Addition Request", "DOCSIS DSA-REQ", "docsis_dsareq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dsarsp = proto_register_protocol_in_name_only("DOCSIS Dynamic Service Addition Response", "DOCSIS DSA-RSP", "docsis_dsarsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dsaack = proto_register_protocol_in_name_only("DOCSIS Dynamic Service Addition Acknowledge", "DOCSIS DSA-ACK", "docsis_dsaack", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dscreq = proto_register_protocol_in_name_only("DOCSIS Dynamic Service Change Request", "DOCSIS DSC-REQ", "docsis_dscreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dscrsp = proto_register_protocol_in_name_only("DOCSIS Dynamic Service Change Response", "DOCSIS DSC-RSP", "docsis_dscrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dscack = proto_register_protocol_in_name_only("DOCSIS Dynamic Service Change Acknowledgement", "DOCSIS DSC-ACK", "docsis_dscack", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dsdreq = proto_register_protocol_in_name_only("DOCSIS Dynamic Service Delete Request", "DOCSIS DSD-REQ", "docsis_dsdreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dsdrsp = proto_register_protocol_in_name_only("DOCSIS Dynamic Service Delete Response", "DOCSIS DSD-RSP", "docsis_dsdrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dccreq = proto_register_protocol_in_name_only("DOCSIS Downstream Channel Change Request", "DOCSIS DCC-REQ", "docsis_dccreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dccrsp = proto_register_protocol_in_name_only("DOCSIS Downstream Channel Change Response", "DOCSIS DCC-RSP", "docsis_dccrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dccack = proto_register_protocol_in_name_only("DOCSIS Downstream Channel Change Acknowledge", "DOCSIS DCC-ACK", "docsis_dccack", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_type29ucd = proto_register_protocol_in_name_only("DOCSIS Upstream Channel Descriptor Type 29", "DOCSIS type29ucd", "docsis_type29ucd", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_intrngreq = proto_register_protocol_in_name_only("DOCSIS Initial Ranging Message", "DOCSIS INT-RNG-REQ", "docsis_intrngreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dcd = proto_register_protocol_in_name_only("DOCSIS Downstream Channel Descriptor", "DOCSIS DCD", "docsis_dcd", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_mdd = proto_register_protocol_in_name_only("DOCSIS Mac Domain Description", "DOCSIS Mdd", "docsis_mdd", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_bintrngreq = proto_register_protocol_in_name_only("DOCSIS Bonded Initial Ranging Message", "DOCSIS B-INT-RNG-REQ", "docsis_bintrngreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_type35ucd = proto_register_protocol_in_name_only("DOCSIS Upstream Channel Descriptor Type 35", "DOCSIS type35ucd", "docsis_type35ucd", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dbcreq = proto_register_protocol_in_name_only("DOCSIS Dynamic Bonding Change Request", "DOCSIS DBC-REQ", "docsis_dbcreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dbcrsp = proto_register_protocol_in_name_only("DOCSIS Dynamic Bonding Change Response", "DOCSIS DBC-RSP", "docsis_dbcrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dbcack = proto_register_protocol_in_name_only("DOCSIS Dynamic Bonding Change Acknowledge", "DOCSIS DBC-ACK", "docsis_dbcack", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dpvreq = proto_register_protocol_in_name_only("DOCSIS Path Verify Request", "DOCSIS DPV-REQ", "docsis_dpv.req", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dpvrsp = proto_register_protocol_in_name_only("DOCSIS Path Verify Response", "DOCSIS DPV-RSP", "docsis_dpv.rsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_cmstatus = proto_register_protocol_in_name_only("DOCSIS CM-STATUS Report", "DOCSIS CM-STATUS", "docsis_cmstatus", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_cmctrlreq = proto_register_protocol_in_name_only("DOCSIS CM Control Request", "DOCSIS CM-CTRL-REQ", "docsis_cmctrl.req", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_cmctrlrsp = proto_register_protocol_in_name_only("DOCSIS CM Control Response", "DOCSIS CM-CTRL-RSP", "docsis_cmctrlrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_regreqmp = proto_register_protocol_in_name_only("DOCSIS Registration Request Multipart", "DOCSIS Reg-Req-Mp", "docsis_regreqmp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_regrspmp = proto_register_protocol_in_name_only("DOCSIS Registration Response Multipart", "DOCSIS Reg-Rsp-Mp", "docsis_regrspmp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_ocd = proto_register_protocol_in_name_only("DOCSIS OFDM Channel Descriptor", "DOCSIS OCD", "docsis_ocd", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dpd = proto_register_protocol_in_name_only("DOCSIS Downstream Profile Descriptor", "DOCSIS DPD", "docsis_dpd", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_type51ucd = proto_register_protocol_in_name_only("DOCSIS Upstream Channel Descriptor Type 51", "DOCSIS type51ucd", "docsis_type51ucd", proto_docsis_mgmt, FT_BYTES);

  register_dissector ("docsis_mgmt", dissect_macmgmt, proto_docsis_mgmt);
  docsis_ucd_handle = register_dissector ("docsis_ucd", dissect_ucd, proto_docsis_ucd);
}

void
proto_reg_handoff_docsis_mgmt (void)
{
  /* Create dissection function handles for all Mac Management commands */
  dissector_add_uint ("docsis_mgmt", MGT_SYNC, create_dissector_handle( dissect_sync, proto_docsis_sync ));
  dissector_add_uint ("docsis_mgmt", MGT_UCD, docsis_ucd_handle);
  dissector_add_uint ("docsis_mgmt", MGT_MAP, create_dissector_handle( dissect_map, proto_docsis_map ));
  dissector_add_uint ("docsis_mgmt", MGT_RNG_REQ, create_dissector_handle( dissect_rngreq, proto_docsis_rngreq ));
  dissector_add_uint ("docsis_mgmt", MGT_RNG_RSP, create_dissector_handle( dissect_rngrsp, proto_docsis_rngrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_REG_REQ, create_dissector_handle( dissect_regreq, proto_docsis_regreq ));
  dissector_add_uint ("docsis_mgmt", MGT_REG_RSP, create_dissector_handle( dissect_regrsp, proto_docsis_regrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_UCC_REQ, create_dissector_handle( dissect_uccreq, proto_docsis_uccreq ));
  dissector_add_uint ("docsis_mgmt", MGT_UCC_RSP, create_dissector_handle( dissect_uccrsp, proto_docsis_uccrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_BPKM_REQ, create_dissector_handle( dissect_bpkmreq, proto_docsis_bpkmreq ));
  dissector_add_uint ("docsis_mgmt", MGT_BPKM_RSP, create_dissector_handle( dissect_bpkmrsp, proto_docsis_bpkmrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_REG_ACK, create_dissector_handle( dissect_regack, proto_docsis_regack ));
  dissector_add_uint ("docsis_mgmt", MGT_DSA_REQ, create_dissector_handle( dissect_dsareq, proto_docsis_dsareq ));
  dissector_add_uint ("docsis_mgmt", MGT_DSA_RSP, create_dissector_handle( dissect_dsarsp, proto_docsis_dsarsp ));
  dissector_add_uint ("docsis_mgmt", MGT_DSA_ACK, create_dissector_handle( dissect_dsaack, proto_docsis_dsaack ));
  dissector_add_uint ("docsis_mgmt", MGT_DSC_REQ, create_dissector_handle( dissect_dscreq, proto_docsis_dscreq ));
  dissector_add_uint ("docsis_mgmt", MGT_DSC_RSP, create_dissector_handle( dissect_dscrsp, proto_docsis_dscrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_DSC_ACK, create_dissector_handle( dissect_dscack, proto_docsis_dscack ));
  dissector_add_uint ("docsis_mgmt", MGT_DSD_REQ, create_dissector_handle( dissect_dsdreq, proto_docsis_dsdreq ));
  dissector_add_uint ("docsis_mgmt", MGT_DSD_RSP, create_dissector_handle( dissect_dsdrsp, proto_docsis_dsdrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_DCC_REQ, create_dissector_handle( dissect_dccreq, proto_docsis_dccreq ));
  dissector_add_uint ("docsis_mgmt", MGT_DCC_RSP, create_dissector_handle( dissect_dccrsp, proto_docsis_dccrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_DCC_ACK, create_dissector_handle( dissect_dccack, proto_docsis_dccack ));
  dissector_add_uint ("docsis_mgmt", MGT_TYPE29UCD, create_dissector_handle( dissect_type29ucd, proto_docsis_type29ucd ));
  dissector_add_uint ("docsis_mgmt", MGT_INIT_RNG_REQ, create_dissector_handle( dissect_intrngreq, proto_docsis_intrngreq ));
  dissector_add_uint ("docsis_mgmt", MGT_DS_CH_DESC, create_dissector_handle( dissect_dcd, proto_docsis_dcd ));
  dissector_add_uint ("docsis_mgmt", MGT_MDD, create_dissector_handle( dissect_mdd, proto_docsis_mdd ));
  dissector_add_uint ("docsis_mgmt", MGT_B_INIT_RNG_REQ, create_dissector_handle( dissect_bintrngreq, proto_docsis_bintrngreq ));
  dissector_add_uint ("docsis_mgmt", MGT_TYPE35UCD, create_dissector_handle( dissect_type35ucd, proto_docsis_type35ucd ));
  dissector_add_uint ("docsis_mgmt", MGT_DBC_REQ, create_dissector_handle( dissect_dbcreq, proto_docsis_dbcreq ));
  dissector_add_uint ("docsis_mgmt", MGT_DBC_RSP, create_dissector_handle( dissect_dbcrsp, proto_docsis_dbcrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_DBC_ACK, create_dissector_handle( dissect_dbcack, proto_docsis_dbcack ));
  dissector_add_uint ("docsis_mgmt", MGT_DPV_REQ, create_dissector_handle( dissect_dpvreq, proto_docsis_dpvreq ));
  dissector_add_uint ("docsis_mgmt", MGT_DPV_RSP, create_dissector_handle( dissect_dpvrsp, proto_docsis_dpvrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_CM_STATUS, create_dissector_handle( dissect_cmstatus, proto_docsis_cmstatus ));
  dissector_add_uint ("docsis_mgmt", MGT_CM_CTRL_REQ, create_dissector_handle( dissect_cmctrlreq, proto_docsis_cmctrlreq ));
  dissector_add_uint ("docsis_mgmt", MGT_CM_CTRL_RSP, create_dissector_handle( dissect_cmctrlrsp, proto_docsis_cmctrlrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_REG_REQ_MP, create_dissector_handle( dissect_regreqmp, proto_docsis_regreqmp ));
  dissector_add_uint ("docsis_mgmt", MGT_REG_RSP_MP, create_dissector_handle( dissect_regrspmp, proto_docsis_regrspmp ));
  dissector_add_uint ("docsis_mgmt", MGT_OCD, create_dissector_handle( dissect_ocd, proto_docsis_ocd ));
  dissector_add_uint ("docsis_mgmt", MGT_DPD, create_dissector_handle( dissect_dpd, proto_docsis_dpd ));
  dissector_add_uint ("docsis_mgmt", MGT_TYPE51UCD, create_dissector_handle( dissect_type51ucd, proto_docsis_type51ucd ));

  docsis_tlv_handle = find_dissector ("docsis_tlv");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
