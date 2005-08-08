/* packet-csm-encaps.c
 * Routines for CSM_ENCAPS dissection
 * Copyright 2005, Angelo Bannack <angelo.bannack@siemens.com>
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2003 Gerald Combs
 *
 * Copied from packet-ans.c
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif



#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/tap.h>

#include <epan/proto.h>
#include <etypes.h>





#define OPCODE_NOOP	             0x0000
#define OPCODE_CONTROL_PACKET    0x0001
#define OPCODE_RELIABLE_DATA     0x0002


#define CSM_ENCAPS_CTRL_ACK		         0x80
#define CSM_ENCAPS_CTRL_ACK_SUPRESS		 0x40
#define CSM_ENCAPS_CTRL_ACK_TO_HOST	     0x20
#define CSM_ENCAPS_CTRL_ENDIAN		     0x01



#define CSM_ENCAPS_TYPE_CHANGE			     0x00
#define CSM_ENCAPS_TYPE_QUERY			     0x01
#define CSM_ENCAPS_TYPE_RESPONSE		     0x02
#define CSM_ENCAPS_TYPE_INDICATION		     0x03
#define CSM_ENCAPS_TYPE_QUERY_RESPONSE	     0x04
#define CSM_ENCAPS_TYPE_INDICATION_RESPONSE  0x05


const value_string opcode_vals[] = {
	{ OPCODE_NOOP,           "No Operation" },
	{ OPCODE_CONTROL_PACKET, "Control Packet" },
	{ OPCODE_RELIABLE_DATA,  "Reliable Data Transfer" },
	{ 0,       NULL }
};

const value_string function_code_vals[] = {
	{0x0000, " "},
	{0x0001, "IRM_AVAILABLE"},
	{0x0002, "IRM_SPUCONVTABLE"},
	{0x0004, "REDIRECT OVER CSM_ENCAPS OVER IP/UDP"},
	{0x000B, "CNDDETSP"},
	{0x0010, "SUPVSR_CREATE_CHANNEL"},
	{0x0011, "SUPVSR_DESTROY_CHANNEL"},
	{0x0013, "SPU_FEATURES_CONTROL"},
	{0x0021, "SUPVSR_GET_ARM_CODE_VERSION"},
	{0x0022, "SUPVSR_GET_SPU_CODE_VERSION"},
	{0x0023, "SUPVSR_RUN_CHECKSUM"},
	{0x0031, "SUPVSR_GET_DEVICE_TYPE"},
	{0x0036, "SET_TSA"},
	{0x00EE, "Reset Indication"},
	{0x00EF, "DIAG_Discarded"},
	{0x00FB, "DIAG_CMD_TRACE"},
	{0x0100, "SET_ETH_HDR"},
	{0x0101, "GET_ETH_HDR"},
	{0x0103, "SET_RTO"},
	{0x0104, "ETH_SERVICE_CONFIG"},
	{0x0107, "SPECIALPKT_HANDLING_SERVICE_CONFIG"},
	{0x0108, "SPECIALPKT_HANDLING_INDICATION_ETH"},
	{0x0109, "SPECIALPKT_HANDLING_GEN_ETH"},
	{0x010A, "CSME_MULTI_CMD"},
	{0x010B, "SPECIALPKT_HANDLING_INDICATION_IP"},
	{0x010C, "SPECIALPKT_HANDLING_GEN_IPoAAL5"},
	{0x0300, "SET_IP_HDR_DEVICE"},
	{0x0301, "GET_IP_HDR_DEVICE"},
	{0x0302, "IP_SERVICE_CONFIG"},
	{0x0303, "IP_ADDRESS"},
	{0x0304, "ICMP_SERVICE_CONFIG"},
	{0x0305, "ICMP_INDICATION"},
	{0x0306, "IP_OPTIONS"},
	{0x0307, "IP_REDIRECT_OPTIONS_CFG"},
	{0x0308, "IP_REDIRECT_INIT_SESSION"},
	{0x0309, "IP_REDIRECT_SET_LAYER3_HDR"},
	{0x030A, "IP_REDIRECT_SET_LAYER2_HDR"},
	{0x030B, "IP_REDIRECT_SRCHDRCHG_IND"},
	{0x0405, "TDM_ENABLE_BUS"},
	{0x0406, "LATENCY_LEVEL"},
	{0x0407, "SUPVSR_SETUP_TDM_PARAMS"},
	{0x0408, "EXT_CLOCK_STATUS"},
	{0x040D, "RUN_VBE"},
	{0x040E, "VBE_RESULT Indication"},
	{0x0410, "SUPVSR_GET_DEVICE_VERSION"},
	{0x0411, "SUPVSR_GET_ARM_CLK"},
	{0x0412, "SUPVSR_GET_SPU_CLK"},
	{0x0417, "TDM_SELECT_BUS_MODE"},
	{0x0419, "STANDBY_CONFIG for Redundancy"},
	{0x041B, "DEVICE_SET_COUNTRY_CODE"},
	{0x041C, "CP_SET_COUNTRY_CODE_PARAMS"},
	{0x0424, "SUPVSR_SET_TS_MODE"},
	{0x0425, "SUPVSR_SET_PCM_LAW"},
	{0x0500, "SET_ALT_HDR_DEVICE"},
	{0x0E00, "DIAG_TDM_RX"},
	{0x0E01, "DIAG_TDM_TX"},
	{0x70FF, "IUUP_QUERY_BASICDIAG"},
	{0x8000, "VoIP_VOPENA"},
	{0x8001, "VoIP_VCEOPT"},
	{0x8002, "VoIP_DTMFOPT"},
	{0x8003, "FAXOPT"},
	{0x8004, "FAXQUAL"},
	{0x8005, "VoIP_DGAIN"},
	{0x8006, "VoIP_ECHOCAN"},
	{0x8007, "VoIP_RPPH"},
	{0x8008, "VoIP_ECGAIN"},
	{0x8009, "VoIP_TONEGEN"},
	{0x800A, "VoIP_SSRCFILT"},
	{0x800B, "VoIP_RTPSUPP"},
	{0x800C, "VoIP_RTCPSTAT"},
	{0x800D, "VoIP_TONEDET"},
	{0x800E, "VoIP_SSRCCHG"},
	{0x800F, "VoIP_PTCHNG"},
	{0x8010, "VoIP_TCMPLT"},
	{0x8011, "FAXSTATE"},
	{0x8012, "VoIP_LOOPBACK"},
	{0x8014, "VoIP_TONEOFF"},
	{0x8017, "VoIP_EVENTDET"},
	{0x8018, "VoIP_PTMNG"},
	{0x8019, "VoIP_SEQREST"},
	{0x801A, "VoIP_VINFOTMR"},
	{0x801B, "FINFOTMR"},
	{0x801C, "VoIP_VINFOIND"},
	{0x801D, "FINFOIND"},
	{0x801E, "VoIP_SENDNTE"},
	{0x801F, "VoIP_NTECMPLT"},
	{0x8020, "VoIP_NTERCVD"},
	{0x8021, "VoIP_DTMFDPAR"},
	{0x8021, "VoIP_TDPARAM"},
	{0x8026, "FAXLVL"},
	{0x8027, "VoIP_SSRCVIOL"},
	{0x8029, "VoIP_SS7COT"},
	{0x8029, "VoIP_SS7COT"},
	{0x802B, "VoIP_PTSET"},
	{0x802C, "VoIP_PTMNGRXOVR"},
	{0x802D, "VoIP_PTSETRXOVR"},
	{0x802E, "VoIP_CNTRYCODE"},
	{0x8032, "FAXPAGESTAT"},
	{0x8034, "VoIP_DTMFTUNE"},
	{0x8039, "CND_ONHOOK_GEN"},
	{0x803A, "CND_SET_PARAMS"},
	{0x803B, "CND_OFFHOOK_GEN"},
	{0x803C, "CND_STOP"},
	{0x803D, "CND_DONE"},
	{0x803F, "VCEFEC"},
	{0x8046, "CIPHER_AES_OPT"},
	{0x8047, "CIPHER_nDES_OPT"},
	{0x8048, "CIPHER_RC4_OPT"},
	{0x8049, "CIPHER_MMH_OPT"},
	{0x804A, "CIPHER_HMAC_OPT"},
	{0x805A, "VoIP_CNTRYCODE"},
	{0x805B, "VoIP_TONECTRL"},
	{0x805B, "VoIP_TONECTRL"},
	{0x805C, "VoIP_REMDET"},
	{0x805D, "VoIP_SIGDET"},
	{0x806E, "VoIP_PROGRAM_TONE_ENGINE"},
	{0x806F, "VoIP_PROGRAM_CADENCE_ENGINE"},
	{0x8084, "VoIP_INDCTRL"},
	{0x8090, "JBOPT"},
	{0x8091, "EC_CONTROL"},
	{0x8092, "VoIP_TONE_RELAY_OPTION"},
	{0x8093, "CNDONDTMFGEN"},
	{0x8094, "CNDONDTMFSTOP"},
	{0x8095, "CNDONDTMFTUNE"},
	{0x8096, "CNDONDTMFDONE"},
	{0x80A0, "RTCP_ENA"},
	{0x80A1, "RTCP_SDES_CNAME"},
	{0x80A5, "RTCP_IND_SR"},
	{0x80A6, "RTCP_IND_RR"},
	{0x80A7, "RTCP_IND_SDES_CNAME"},
	{0x80A8, "RTCP_IND_BYE"},
	{0x80A9, "RTCP_APP"},
	{0x80AA, "RTCP_IND_APP"},
	{0x80AB, "RTCP_NTP_TIMESTAMP"},
	{0x80AC, "RTCP_PACKET_GENERATION_GRANULARITY"},
	{0x80AD, "CNDRXMSG"},
	{0x80AF, "VOCODER_STATUS"},
	{0x80B0, "VoIP_CDMA_MODES "},
	{0x80B1, "CNDDETCTL"},
	{0x80D1, "VoIP_AGCSET"},
	{0x80D1, "VOIP_AGCSET_ACK"},
	{0x80F0, "DIAG_TDM"},
	{0x8700, "VoIP_SRCHDRCHNG"},
	{0x9000, "SET_IP_HDR_CHANNEL"},
	{0x9001, "GET_IP_HDR_CHANNEL"},
	{0x9010, "SET_ETH_HDR_CHAN"},
	{0x9020, "SET_ALT_HDR_ CHANNEL"},
	{0x9200, "THC_REDIRECT_RX"},
	{0x9201, "THC_MODE_ENABLE"},
	{0x9202, "THC_GEN_PKT"},
	{0x9300, "SET_SPI_TDM_BUS"},
	{0x9301, "SET_SPI_TDM_INTERRUPT"},
	{0x9302, "ENABLE_SPI_TDM"},
	{0x9303, "WRITE_TO_SPI"},
	{0x9304, "READ_FROM_SPI"},
	{0x9305, "EVENT_INDICATION_FROM_SPI"},
	{0x9306, "EVENT_PROCESS_DONE_TO_SPI"},
	{0x9310, "CONF_CREATE_CONFERENCE"},
	{0x9311, "CONF_DESTROY_CONFERENCE"},
	{0x9312, "CONF_CREATE_PARTICIPANT"},
	{0x9313, "CONF_DESTROY_PARTICIPANT"},
	{0x9314, "CONF_MUTE_PARTICIPANT"},
	{0x9315, "CONF_PUT_PARTICIPANT_ON_HOLD"},
	{0x9316, "CONF_SPECIFY_DOMINANT_TALKERS"},
	{0x9316, "CONF_SPECIFY_DOMINANT_TALKERS _ACK"},
	{0x9330, "MDIO_BUS_WRITE"},
	{0x9331, "MDIO_BUS_READ"},
	{0x9400, "VOIP_SET_CHANNEL_MODE"},
	{0x9402, "SYNCDAT"},
	{0x9403, "SYNCEOF"},
	{0x9404, "SET_FLOWCON"},
	{ 0,       NULL }
};


const value_string class_type_vals[] = {
	{0x03D4, "SUPVSR_READY"},
	{0x0535, "CSM_ENCAPS_STATISTICS"},
	{0x0400, "ERRIND"},
	{0x0402, "BYTEREAD"},
	{0x0403, "BYTEWRITE"},
	{0x0404, "FIFOREAD"},
	{0x0405, "FIFOWRITE"},
	{0x0406, "PROGSTART"},
	{0x040A, "WORDREAD"},
	{0x040B, "WORDWRITE"},
	{0x040C, "SET_CLOCK"},
	{0x040D, "SET_SDRAM_PARAMS"},
	{0x040F, "SET_CS_PARAMS"},
	{0x0411, "GET_VERSION"},
	{0x0414, "CMD_ACK"},
	{0x0415, "SET_ARM_CLKMODE"},
	{0x0416, "DOUBLE_WORDREAD"},
	{0x0417, "DOUBLE_WORDWRITE"},
	{0x0419, "FIFOWRITE_BURST"},
	{0x041B, "MAAS_ASSIGN"},
	{0x0500, "ETH_STATISTICS"},
	{0x0501, "ARP_STATISTICS"},
	{0x0105, "VoIP_RTCP"},
	{0x0106, "VoIP_PLYDLY"},
	{0x0107, "VoIP_PLYERR"},
	{0x0108, "VoIP_PKTTX"},
	{0x0109, "VoIP_PKTRX"},
	{0x010A, "VoIP_VCELVL"},
	{0x010B, "VoIP_FAXTXRX"},
	{0x010C, "VoIP_FAXPLY"},
	{0x010D, "VoIP_FAXDSP"},
	{0x010E, "VoIP_VCEINFO"},
	{0x020F, "VoIP_T38INFO"},
	{0x0210, "VoIP_CONFSUM"},
	{ 0,      NULL }
};



const value_string exclusive_to_host_vals[] = {
	{0x0108, "SPECIALPKT_HANDLING_INDICATION_ETH"},
	{0x010B, "SPECIALPKT_HANDLING_INDICATION_IP"},
	{0x800E, "VoIP_SSRCCHG"},
	{0x800D, "VoIP_TONEDET"},
	{0x800F, "VoIP_PTCHNG"},
	{0x8010, "VoIP_TCMPLT"},
	{0x801D, "FINFOIND"},
	{0x8017, "VoIP_EVENTDET"},
	{0x801C, "VoIP_VINFOIND"},
	{0x8027, "VoIP_SSRCVIOL"},
	{0x803D, "CND_DONE"},
	{0x80A7, "RTCP_IND_SDES_CNAM"},
	{0x80A8, "RTCP_IND_BYE"},
	{0x80A9, "RTCP_APP"},
	{0x80AA, "RTCP_IND_APP"},
	{0x8700, "VoIP_SRCHDRCHNG"},
	{0x9305, "EVENT_INDICATION_FROM_SPI"},
	{ 0,      NULL }
};

const value_string exclusive_to_host_ct_vals[] = {
	{0x03D4, "SUPVSR_READY"},
	{0x0400, "ERRIND"},
	{0x0414, "BRM_CMD_ACK"},
	{ 0,      NULL }
};


const value_string error_vals[] = {
	{0x0000, "CNF_OK"},
	{0x0001, "CNF_ERROR_UNSPEC"},
	{0x0002, "CNF_ERROR_RTPHEADER"},
	{0x0003, "CNF_ERROR_PT"},
	{0x0004, "CNF_ERROR_EXTENC"},
	{0x0005, "CNF_ERROR_HARDRST"},
	{0x0006, "CNF_ERROR_DOWNLOAD"},
	{0x0007, "CNF_ERROR_CODECI"},
	{0x0008, "CNF_ERROR_NEWC"},
	{0x0009, "CNF_ERROR_ECINIT"},
	{0x000A, "CNF_ERROR_ENCAPS"},
	{0x000B, "CNF_ERROR_G727"},
	{0x000C, "CNF_ERROR_TDTINI"},
	{0x000D, "CNF_ERROR_TDRINI"},
	{0x000E, "CNF_ERROR_VOPUNDEF"},
	{0x0010, "CNF_ERROR_FNOTSUPP"},
	{0x0011, "CNF_ERROR_FNOSSRC"},
	{0x0012, "CNF_ERROR_FREDSSRC"},
	{0x0013, "CNF_ERROR_FNOROOM"},
	{0x0014, "CNF_ERROR_FDUP"},
	{0x0015, "CNF_ERROR_FVAD"},
	{0x0016, "CNF_ERROR_FAUTO"},
	{0x0017, "CNF_ERROR_REDFORK"},
	{0x0020, "CNF_ERROR_VOPENA_NOIPCLIENT"},
	{0x0021, "CNF_ERROR_VOPENA_REG_RTP_NO_IPLAYER"},
	{0x0022, "CNF_ERROR_VOPENA_REG_RTP_NO_LOWERLAYER"},
	{0x0023, "CNF_ERROR_VOPENA_REG_RTP_NO_MORECLIENTS"},
	{0x0024, "CNF_ERROR_VOPENA_REG_RTP_DUPLICATION"},
	{0x0025, "CNF_ERROR_VOPENA_REG_RTCP_NO_IPLAYER"},
	{0x0026, "CNF_ERROR_VOPENA_REG_RTCP_NO_LOWERLAYER"},
	{0x0027, "CNF_ERROR_VOPENA_REG_RTCP_NO_MORECLIENTS"},
	{0x0028, "CNF_ERROR_VOPENA_REG_RTCP_DUPLICATION"},
	{0x002B, "CNF_ERROR_VCEOPT_NOIPCLIENT"},
	{0x002C, "CNF_ERROR_VCEOPT_NOETHCLIENT"},
	{0x002D, "CNF_ERROR_VOPENA_PACKET_LEN"},
	{0x002E, "CNF_ERROR_FIFO_LEN"},
	{0x002F, "CNF_ERROR_PARAM_OUT_OF_RANGE"},
	{0x0030, "CNF_ERROR_PARAM2_OUT_OF_RANGE"},
	{0x0031, "CNF_ERROR_FOPENA_REGISSUE_FOIP_INDEX"},
	{0x0032, "CNF_ERROR_IPV4_DEREG"},
	{0x0033, "CNF_ERROR_PARAM_INVALID_VALUE"},
	{0x0040, "CNF_ERR_TDM_MODE_NOT_FOURBUS"},
	{0x0041, "CNF_ERR_TDM_BUS_OUT_OF_RANGE_FOURBUS_MODE"},
	{0x0042, "CNF_ERR_TDM_BUS_OUT_OF_RANGE_TWOBUS_MODE"},
	{0x0043, "CNF_ERR_TDM_BUS_OUT_OF_RANGE_ONEBUS_MODE"},
	{0x0044, "CNF_ERR_TDM_CONFIG_PARMS_FAILED_FOURBUS_MODE_OLD"},
	{0x0045, "CNF_ERR_TDM_CONFIG_PARMS_FAILED_FOURBUS_MODE_NEW"},
	{0x0046, "CNF_ERR_TDM_CONFIG_PARMS_FAILED_TWOBUS_MODE"},
	{0x0047, "CNF_ERR_TDM_CONFIG_PARMS_FAILED_ONEBUS_MODE"},
	{0x0048, "CNF_ERR_TDM_PARAMS_INVALID_BUS_MODE"},
	{0x0049, "CNF_ERR_TDM_SELECT_INVALID_BUS_MODE"},
	{0x004A, "CNF_ERR_TDM_INVALID_CMD_LEN"},
	{0x004B, "CNF_ERR_TDM_CONFIG_PARMS_FAILED_SETUP_MULT_INSTANCE"},
	{0x004C, "CNF_ERR_TDM_CONFIG_PARMS_FAILED_SELECT_MULT_INSTANCE"},
	{0x004D, "CNF_ERR_TSDRIVE_INVALID_CMD_LEN"},
	{0x004E, "CNF_ERR_TSDRIVE_INVALID_PARAM"},
	{0x004F, "CNF_ERR_TSDRIVE_CHAN_ALREADY_CREATED"},
	{0x005C, "CNF_ERR_TSDRIVE_INVALID_FOR_MIRO"},
	{0x0050, "CNF_ERR_SPI_NOT_CHAGALL"},
	{0x0051, "CNF_ERR_SPI_ENQUEUE_READ_CMD_FAILED"},
	{0x0052, "CNF_ERR_SPI_ENQUEUE_WRITE_CMD_FAILED"},
	{0x0053, "CNF_ERR_SPI_BUS_OUT_OF_RANGE"},
	{0x0054, "CNF_ERR_SPI_INCORRECT_BUS_MODE"},
	{0x0055, "CNF_ERR_SPI_IRQSIZE_ZERO"},
	{0x0056, "CNF_ERR_SPI_IRQSIZE_TOO_LARGE"},
	{0x0057, "CNF_ERR_SPI_IRQSIZE_NOT_SUBMULTIPLE"},
	{0x0058, "CNF_ERR_SPI_TDM_RELEASE_FAILED"},
	{0x0059, "CNF_ERR_SPI_TDM_GRAB_FAILED"},
	{0x005A, "CNF_ERR_SPI_TDM_QUEUE_INIT_FAILED"},
	{0x005B, "CNF_ERR_SPI_TASK_CREATION_FAILED"},
	{0x0060, "CNF_ERR_THC_MIRO_DEVICE"},
	{0x0061, "CNF_ERR_THC_CHAN_NOT_ACTIVE"},
	{0x0062, "CNF_ERR_THC_CHAN_NOT_G711"},
	{0x0063, "CNF_ERR_THC_NOT_THC"},
	{0x0064, "CNF_ERR_THC_PEER_CHAN_NULL"},
	{0x0065, "CNF_ERR_THC_NOT_SAME_CPU"},
	{0x0066, "CNF_ERR_THC_NOT_SAME_CODING"},
	{0x0067, "CNF_ERR_THC_HAIRPIN_NULL"},
	{0x0068, "CNF_ERR_THC_CMD_INVALID_FOR_THC"},
	{0x0069, "CNF_ERR_PASSTHRU"},
	{0x006A, "CNF_ERR_CRBT_VCEOPT_INVALID_PARAM"},
	{0x006B, "CNF_ERR_COMPLEX_CADENCE_ENGINE_FORMAT_ERROR"},
	{0x006C, "CNF_ERR_TONEGEN_CURRENTLY_RUNNING"},
	{0x0102, "CNF_ERROR_CID_RANGE"},
	{0x0103, "CNF_ERROR_NO_VPIVCI"},
	{0x0104, "CNF_ERROR_PHY_NUMBER"},
	{0x0105, "CNF_ERROR_VOICE_FT"},
	{0x0106, "CNF_ERROR_SILENCE_FT"},
	{0x0107, "CNF_ERROR_CPS_REG"},
	{0x0108, "CNF_ERROR_CPS_REG_CID_OUT_OF_RANGE"},
	{0x0109, "CNF_ERROR_CPS_REG_INVALID_VPIVCI"},
	{0x010A, "CNF_ERROR_CPS_REG_VCC_OUT_OF_RANGE"},
	{0x010B, "CNF_ERROR_CPS_REG_VCC_USED"},
	{0x010C, "CNF_ERROR_CPS_REG_VCC_MISMATCH"},
	{0x010D, "CNF_ERROR_CPS_REG_CID_USED"},
	{0x010E, "CNF_ERROR_CPS_REG_NO_CPS_LAYER"},
	{0x010F, "CNF_ERROR_CPS_REG_ATM_RT_REG"},
	{0x0110, "CNF_ERROR_CPS_REG_INVALID_VCC"},
	{0x0111, "CNF_ERROR_CPS_DEREG"},
	{0x0112, "CNF_ERROR_CPS_PACKET_LEN"},
	{0x0120, "CNF_ERROR_UNSUPPORTED_PROFILE"},
	{0x0121, "CNF_ERROR_EMPTY_PROFILE"},
	{0x0122, "CNF_ERROR_AAL2_ACTIVE"},
	{0x0123, "CNF_ERROR_PROFILE_TYPE"},
	{0x0124, "CNF_ERROR_PROFILE_SIZE"},
	{0x0125, "CNF_ERROR_PROFILE_USED"},
	{0x0126, "CNF_ERROR_INVALID_VOICE_FT"},
	{0x0127, "CNF_ERROR_INVALID_UUI"},
	{0x0128, "CNF_ERROR_INVALID_LI"},
	{0x0129, "CNF_ERROR_PROFILE_CONFLICT"},
	{0x012A, "CNF_ERROR_CPS_MSGLEN"},
	{0x012B, "CNF_ERROR_CPS_NOMEM"},
	{0x012C, "CNF_ERROR_CPS_NOCLIENT"},
	{0x012D, "CNF_ERROR_CPS_MODE"},
	{0x012E, "CNF_ERROR_CPS_TOO_MANY_CLIENT"},
	{0x012F, "CNF_ERROR_CPS_TIMER"},
	{0x0130, "CNF_ERROR_FEATURE_NOTKEYED"},
	{0x0202, "CNF_ERROR_ATM_REGISTRATION"},
	{0x0203, "CNF_ERROR_ATM_LAYER_DOWN"},
	{0x0204, "CNF_ERROR_N_VALUE"},
	{0x0205, "CNF_ERROR_AUTO_VPI_VCI"},
	{0x0206, "CNF_ERROR_LEN_MSG"},
	{0x0207, "CNF_ERROR_ATM_DEREGISTRATION"},
	{0x0208, "CNF_ERROR_AAL1_UNKNOWN_FUNC"},
	{0x0209, "CNF_ERROR_AAL1_VOICE_INACTIVE"},
	{0x020A, "CNF_ERROR_AAL1_TONEOFF"},
	{0x020B, "CNF_ERROR_AAL1_CADENCE"},
	{0x020C, "CNF_ERROR_AAL1_FREQ"},
	{0x020D, "CNF_ERROR_AAL1_TONEGEN"},
	{0x020E, "CNF_ERROR_AAL1_GAIN"},
	{0x020F, "CNF_ERROR_AAL1_TAILLEN"},
	{0x0210, "CNF_ERROR_AAL1_MODE"},
	{0x0211, "CNF_ERROR_AAL1_LB_ICHAN_SWITCH"},
	{0x0212, "CNF_ERROR_AAL1_LB_SELF"},
	{0x0213, "CNF_ERROR_AAL1_LB_POST_ONTHEFLY"},
	{0x0214, "CNF_ERROR_AAL1_LB_ICHAN_ONTHEFLY"},
	{0x0215, "CNF_ERROR_AAL1_LB_ICHAN_SELF"},
	{0x0216, "CNF_ERROR_AAL1_LB_ONTHEFLY"},
	{0x0217, "CNF_ERROR_AAL1_LB_NO_DEST"},
	{0x0218, "CNF_ERROR_AAL1_LB_NOT_IMPLEMENTED"},
	{0x0219, "CNF_ERROR_AAL1_LB_NO_FPGA"},
	{0x0302, "CNF_ERROR_CCS_CID_RANGE"},
	{0x0303, "CNF_ERROR_CCS_AUTO_VPI_VCI"},
	{0x0304, "CNF_ERROR_ON_INIT_CHANNEL"},
	{0x0305, "CNF_ERROR_CCS_LEN_MSG"},
	{0x0306, "CNF_ERROR_CCS_CPS_REG"},
	{0x0307, "CNF_ERROR_CCS_MSG_NOT_SENT"},
	{0x0308, "CNF_ERROR_CCS_UNKNOWN_FUNC"},
	{0x0309, "CNF_ERROR_CCS_CHAN_ENABLED"},
	{0x0402, "CNF_ERROR_CDMA_MSG_LEN"},
	{0x0403, "CNF_ERROR_CDMA_PHY_NUMBER"},
	{0x0404, "CNF_ERROR_CDMA_VOICE_FT"},
	{0x0405, "CNF_ERROR_CDMA_GPS_OFFSET"},
	{0x0406, "CNF_ERROR_CDMA_MODE_OF_OPERATION"},
	{0x0407, "CNF_ERROR_CDMA_DATA_SERVICE_RATE"},
	{0x0408, "CNF_ERROR_CDMA_GPS_SYNC_SERVICE_DOWN"},
	{0x0409, "CNF_ERROR_CDMA_DESCRIPTOR"},
	{0x040A, "CNF_ERROR_CDMA_AAL5_REG_SERVICE_DOWN"},
	{0x040B, "CNF_ERROR_CDMA_AAL5_REG_MAX_CLIENTS"},
	{0x040C, "CNF_ERROR_CDMA_AAL5_REG_ALLOC_CLIENT"},
	{0x040D, "CNF_ERROR_CDMA_AAL5_REG_ATM_REGISTRATION"},
	{0x040D, "CNF_ERROR_CDMA_AAL5_DEREG,"},
	{0x040E, "CNF_ERROR_CDMA_AAL5_DEREG_SERVICE_DOWN"},
	{0x040F, "CNF_ERROR_CDMA_AAL5_DEREG_NO_REGISTERED_CLIENT"},
	{0x0410, "CNF_ERROR_CDMA_AAL5_DEREG_CLIENT_NOT_FOUND"},
	{0x0411, "CNF_ERROR_CDMA_MEMORY"},
	{0x0502, "CNF_ERROR_FOIP_MSG_LEN"},
	{0x0503, "CNF_ERROR_FOIP_LEVEL"},
	{0x0504, "CNF_ERROR_FOIP_DEREG"},
	{0x0505, "CNF_ERROR_FOIP_COD_INVALID"},
	{0x0506, "CNF_ERROR_FOIP_LIM_INVALID"},
	{0x0507, "CNF_ERROR_FOIP_PACKINT_SIZE"},
	{0x0508, "CNF_ERROR_FOIP_PACKINT_GRANULARITY"},
	{0x0602, "CNF_ERROR_AAL5OPT_MSG_LEN"},
	{0x0603, "CNF_ERROR_AAL5OPT_CLIENT_DESCRIPTOR"},
	{0x0603, "CNF_ERROR_AAL5OPT_AAL5_REG,"},
	{0x0604, "CNF_ERROR_AAL5OPT_AAL5_REG_SERVICE_DOWN"},
	{0x0605, "CNF_ERROR_AAL5OPT_AAL5_REG_MAX_CLIENTS"},
	{0x0606, "CNF_ERROR_AAL5OPT_AAL5_REG_ALLOC_CLIENT"},
	{0x0607, "CNF_ERROR_AAL5OPT_AAL5_REG_ATM_REGISTRATION"},
	{0x0608, "CNF_ERROR_AAL5OPT_AAL5_REG_RFC_ENCAP"},
	{0x0609, "CNF_ERROR_AAL5OPT_AAL5_DEREG_SERVICE_DOWN"},
	{0x060A, "CNF_ERROR_AAL5OPT_AAL5_DEREG_NO_REGISTERED_CLIENT"},
	{0x060B, "CNF_ERROR_AAL5OPT_AAL5_DEREG_CLIENT_NOT_FOUND"},
	{0x060C, "CNF_ERROR_AAL5OPT_INIT"},
	{0x060D, "CNF_ERROR_AAL5OPT_ARM0"},
	{0x060E, "CNF_ERROR_AAL5OPT_DESCRIPTOR"},
	{0x060F, "CNF_ERROR_AAL5OPT_DEVICEDESC"},
	{0x0702, "CNF_ERROR_CIPHER_ALGO_NOT_DEFINED"},
	{0x0703, "CNF_ERROR_CIPHER_BAD_KEY_SIZE"},
	{0x0704, "CNF_ERROR_CIPHER_ERROR1"},
	{0x0705, "CNF_ERROR_CIPHER_ERROR2"},
	{0x0706, "CNF_ERROR_CIPHER_BAD_MODE"},
	{0x0707, "CNF_ERROR_CIPHER_BAD_PADDING_METHOD"},
	{0x0708, "CNF_ERROR_CIPHER_BAD_MAC_KEY_SIZE"},
	{0x0709, "CNF_ERROR_CIPHER_BAD_PACKETCABLE_MODE"},
	{0x070A, "CNF_ERROR_CIPHER_NOT_IMPLEMENTED"},
	{0x070B, "CNF_ERROR_CIPHER_BAD_FIFO_LENGTH"},
	{0x070C, "CNF_ERROR_CIPHER_DSPLIB"},
	{0x070D, "CNF_ERROR_AUTHENTICATION_BAD_PACKETCABLE_MODE"},
	{0x070E, "CNF_ERROR_CIPHER_ALLOC"},
	{0x070F, "CNF_ERROR_AUTHENTICATION_ALLOC"},
	{0x0710, "CNF_ERROR_CIPHER_BAD_CIPHER_LAYER"},
	{0x0711, "CNF_ERROR_AUTHENTICATION_BAD_HASHING_FUNCTION"},
	{0x0712, "CNF_ERROR_AUTHENTICATION_BAD_MAC_SIZE"},
	{0x0713, "CNF_ERROR_CIPHER_KEY_SCHEDULED"},
	{0x0714, "CNF_ERROR_CIPHER_REDUNDANCY"},
	{0x0715, "CNF_ERROR_CIPHER_NOT_ENABLED"},
	{0x0800, "CNF_ERROR_DESTROY_INVALID_CHAN"},
	{0x0801, "CNF_ERROR_DESTROY_ACTIVE_CHAN"},
	{0x0901, "CNF_ERROR_IUUP_UNSPEC"},
	{0x0902, "CNF_ERROR_IUUP_INIT_RFCI_INCORRECT"},
	{0x0903, "CNF_ERROR_IUUP_INIT_PDU_INCORRECT"},
	{0x0904, "CNF_ERROR_IUUP_INIT_MV_NOTSUPPORTED"},
	{0x0905, "CNF_ERROR_IUUP_INIT_SDU_SIZE_INCORRECT"},
	{0x0906, "CNF_ERROR_IUUP_RATE_NUM_RFCI_INCORRECT"},
	{0x0907, "CNF_ERROR_IUUP_RATE_RFCI_NOT_ENABLE"},
	{0x0908, "CNF_ERROR_IUUP_TA_NOT_POSSIBLE"},
	{0x0909, "CNF_ERROR_IUUP_TA_NOT_SUPPORTED"},
	{0x090A, "CNF_ERROR_IUUP_SVC_MV_INCORRECT"},
	{0x090B, "CNF_ERROR_IUUP_PROCEDURE_ACTIVE"},
	{0x090C, "CNF_ERROR_IUUP_LENGTH_TOO_BIG"},
	{0x090D, "CNF_ERROR_IUUP_NOT_UP"},
	{0x0981, "CNF_ERROR_TFO_UNSPEC"},
	{0x0982, "CNF_ERROR_TFO_NO_MEM"},
	{0x0983, "CNF_ERROR_TFO_QUEUE_FULL"},
	{0x0984, "CNF_ERROR_TFO_QUEUE_EMPTY"},
	{0x0985, "CNF_ERROR_TFO_EXIST"},
	{0x0986, "CNF_ERROR_TFO_NOT_CREATED"},
	{0x0987, "CNF_ERROR_TFO_NO_ACCESS"},
	{0x0988, "CNF_ERROR_TFO_LENGTH_INCORRECT"},
	{0x0A00, "CNF_ERROR_SET_ETH_UNK_ID"},
	{0x0A01, "CNF_ERROR_SET_ETH_TOO_SHORT"},
	{0x0A02, "CNF_ERROR_SET_RTO_UNK_OPCODE"},
	{0x0A03, "CNF_ERROR_SET_RTO_UNK_ACTIVE"},
	{0x0A04, "CNF_ERROR_ARP_NO_ETH_LAYER"},
	{0x0A05, "CNF_ERROR_CSME_MCP_ACTIVE"},
	{0x0A06, "CNF_ERROR_CSME_MCP_REG_NO_IPLAYER"},
	{0x0A07, "CNF_ERROR_CSME_MCP_REG_NO_LOWERLAYER"},
	{0x0A08, "CNF_ERROR_CSME_MCP_REG_NO_MORECLIENTS"},
	{0x0A09, "CNF_ERROR_CSME_MCP_REG_DUPLICATION"},
	{0x0A0B, "CNF_ERROR_CSME_MCP_NO_ETH"},
	{0x0A0C, "CNF_ERROR_CSME_MRDT_ACTIVE"},
	{0x0A0D, "CNF_ERROR_CSME_MRDT_REG_NO_IPLAYER"},
	{0x0A0E, "CNF_ERROR_CSME_MRDT_REG_NO_LOWERLAYER"},
	{0x0A0F, "CNF_ERROR_CSME_MRDT_REG_NO_MORECLIENTS"},
	{0x0A10, "CNF_ERROR_CSME_MRDT_REG_DUPLICATION"},
	{0x0A12, "CNF_ERROR_CSME_MRDT_NO_ETH"},
	{0x0A13, "CNF_ERROR_CSME_UNK_OPCODE"},
	{0x0A15, "CNF_ERROR_SPECIALPKT_HANDLING_TOOMANY"},
	{0x0A16, "CNF_ERROR_ARP_CHAGALL"},
	{0x0A17, "CNF_ERROR_ARP_MSG_LEN"},
	{0x0A18, "CNF_ERROR_CSME_NO_CONTEXT"},
	{0x0A19, "CNF_ERROR_ETH_CLIENT_INUSE"},
	{0x0A1A, "CNF_ERROR_ETH_CLIENT_CANTREG"},
	{0x0A1B, "CNF_ERROR_ETH_CLIENT_CANTCHANGE"},
	{0x0A1C, "CNF_ERROR_ETH_NO_CONTEXT"},
	{0x0A1D, "CNF_ERROR_IPV4_NO_CONTEXT"},
	{0x0A1E, "CNF_ERROR_VCID_NO_CONTEXT"},
	{0x0A1F, "CNF_ERROR_ETH_INIT"},
	{0x0A20, "CNF_ERROR_ETH_NO_HANDLE"},
	{0x0A21, "CNF_ERROR_CHAN_MAC_NE_DEVICE"},
	{0x0A22, "CNF_ERROR_WRONG_PACKET_TYPE"},
	{0x0A23, "CNF_ERROR_BAD_FRAME_SIZE"},
	{0x0A24, "CNF_ERROR_SPECIALPKT_NO_MEM"},
	{0x0A26, "CNF_ERROR_AAL5_IPv4_NOT_REG"},
	{0x0A30, "CNF_ERROR_CSME_ODIAG_REG_NO_IPLAYER"},
	{0x0A31, "CNF_ERROR_CSME_ODIAG_REG_NO_LOWERLAYER"},
	{0x0A32, "CNF_ERROR_CSME_ODIAG_REG_NO_MORECLIENTS"},
	{0x0A33, "CNF_ERROR_CSME_ODIAG_REG_DUPLICATION"},
	{0x0B00, "CNF_ERROR_ICMP_NO_IP_LAYER"},
	{0x0B01, "CNF_ERROR_ICMP_BADTTL"},
	{0x0B02, "CNF_ERROR_IP_ADDRESS_NO_IP_LAYER"},
	{0x0B03, "CNF_ERROR_IP_ADDRESS_BAD_IP_ADDRESS"},
	{0x0B04, "CNF_ERROR_IP_ADDRESS_IPCLIENT_REG"},
	{0x0B05, "CNF_ERROR_SET_IP_UNKSERVICEID"},
	{0x0B06, "CNF_ERROR_SET_IP_TOOSHORT"},
	{0x0B07, "CNF_ERROR_SET_IP_IPADDRESS_NOTSET"},
	{0x0B08, "CNF_ERROR_SET_IP_BADHEADER"},
	{0x0B09, "CNF_ERROR_SET_IP_BADTTL"},
	{0x0B0A, "CNF_ERROR_SET_IP_UNKPROT"},
	{0x0B0B, "CNF_ERROR_SET_IP_ODDRTP_PORT"},
	{0x0B0C, "CNF_ERROR_SET_IP_REG_RTP_NO_IPLAYER"},
	{0x0B0D, "CNF_ERROR_SET_IP_REG_RTP_NO_LOWERLAYER"},
	{0x0B0E, "CNF_ERROR_SET_IP_REG_RTP_NO_MORECLIENTS"},
	{0x0B0F, "CNF_ERROR_SET_IP_REG_RTP_DUPLICATION"},
	{0x0B11, "CNF_ERROR_SET_IP_EVENRTCP_PORT"},
	{0x0B12, "CNF_ERROR_SET_IP_REG_RTCP_NO_IPLAYER"},
	{0x0B13, "CNF_ERROR_SET_IP_REG_RTCP_NO_LOWERLAYER"},
	{0x0B14, "CNF_ERROR_SET_IP_REG_RTCP_NO_MORECLIENTS"},
	{0x0B15, "CNF_ERROR_SET_IP_REG_RTCP_DUPLICATION"},
	{0x0B16, "CNF_ERROR_SET_IP_REG_FOIP_NO_IPLAYER"},
	{0x0B17, "CNF_ERROR_SET_IP_REG_FOIP_NO_LOWERLAYER"},
	{0x0B18, "CNF_ERROR_SET_IP_REG_FOIP_NO_MORECLIENTS"},
	{0x0B19, "CNF_ERROR_SET_IP_REG_FOIP_DUPLICATION"},
	{0x0B1A, "CNF_ERROR_COMMAND_NEEDS_VOPENA_RTP"},
	{0x0B1B, "CNF_ERROR_COMMAND_NEEDS_VOPENA_SIGNAL"},
	{0x0B1C, "CNF_ERROR_SS7COT_ERROR"},
	{0x0B1D, "CNF_ERROR_CND_DATA_INVALID"},
	{0x0B1E, "CNF_ERROR_NOT_MAX_INFO_COUNT"},
	{0x0C02, "CNF_ERROR_ATM_SERVICE_ERROR"},
	{0x0C03, "CNF_ERROR_ATM_SERVICE_BW_EXCEEDED"},
	{0x0C04, "CNF_ERROR_ATM_SERVICE_VPI_OUT_OF_RANGE"},
	{0x0C05, "CNF_ERROR_ATM_SERVICE_VCI_OUT_OF_RANGE"},
	{0x0C06, "CNF_ERROR_ATM_SERVICE_VPCI_NB_NOT_P2"},
	{0x0C07, "CNF_ERROR_ATM_SERVICE_VPCI_NB_OUT_OF_RANGE"},
	{0x0C08, "CNF_ERROR_ATM_SERVICE_HANDLE_NOT_REGISTERED"},
	{0x0C09, "CNF_ERROR_ATM_SERVICE_NO_VCC_TOS"},
	{0x0C0A, "CNF_ERROR_ATM_SERVICE_CONFIG_NOT_ALLOWED"},
	{0x0C0B, "CNF_ERROR_ATM_SERVICE_ETH_DOWN"},
	{0x0C0C, "CNF_ERROR_ATM_SERVICE_SLAVE_MODE_ONLY"},
	{0x0C0D, "CNF_ERROR_ATM_SERVICE_CANNOT_ALLOC"},
	{0x0C0E, "CNF_ERROR_ATM_MSG_LEN"},
	{0x0C0F, "CNF_ERROR_ATM_UNKNOWN_FUNC"},
	{0x0C10, "CNF_ERROR_ATM_NO_UTP"},
	{0x0C11, "CNF_ERROR_ATM_NOT_SUPPORTED"},
	{0x0C12, "CNF_ERROR_ATM_MEMORY"},
	{0x0C13, "CNF_ERROR_ATM_CELL_NOT_SENT"},
	{0x0C14, "CNF_ERROR_NOT_LGESSIG"},
	{0x0C15, "CNF_ERROR_ATM_LAYER_NOT_CONFIGURED"},
	{0x0D00, "CNF_ERROR_PUI_MSG_LEN"},
	{0x0D01, "CNF_ERROR_PUI_NOT_INITIALIZED"},
	{0x0D02, "CNF_ERROR_PUI_MODE_NOT_SET"},
	{0x0D03, "CNF_ERROR_PUI_CONFIGURED"},
	{0x0D04, "CNF_ERROR_PUI_DATABUSW"},
	{0x0D05, "CNF_ERROR_PUI_HANDSHAKE"},
	{0x0D06, "CNF_ERROR_PUI_NUM_ROUTING_TAGS"},
	{0x0D07, "CNF_ERROR_PUI_ROUTING_TAGS_ODD"},
	{0x0D08, "CNF_ERROR_PUI_STRAPCONFIG"},
	{0x0D09, "CNF_ERROR_PUI_NON_SYMETRIC_ADDRESS"},
	{0x0D0A, "CNF_ERROR_PUI_INVALID_PHY_ADDRESS"},
	{0x0D0B, "CNF_ERROR_PUI_UNKNOWN_MODE"},
	{0x0D0C, "CNF_ERROR_OPTIPHY_LEN"},
	{0x0D0D, "CNF_ERROR_OPTIPHY_INIT"},
	{0x0D0E, "CNF_ERROR_OPTIPHY_CFG"},
	{0x0D0F, "CNF_ERROR_OPTIPHY_LOOPBACK"},
	{0x0D10, "CNF_ERROR_POS_CLIENT_INIT"},
	{0x0D11, "CNF_ERROR_POS_CLIENT_CANT_DEREG"},
	{0x0E00, "CNF_ERR_CONF_MAXNO_CREATED"},
	{0x0E01, "CNF_ERR_CONF_INVALID_CPU"},
	{0x0E02, "CNF_ERR_CONF_DESTROY_CONF_FAILED"},
	{0x0E03, "CNF_ERR_CONF_INVALID_CMD_LEN"},
	{0x0E04, "CNF_ERR_CONF_INVALID_PART_TYPE"},
	{0x0E05, "CNF_ERR_CONF_VALIDITY_CHECK_FAILED"},
	{0x0E06, "CNF_ERR_CONF_DELETE_PART_FAILED"},
	{0x0E07, "CNF_ERR_CONF_NO_MIXER"},
	{0x0E08, "CNF_ERR_CONF_MUTE_PART_FAILED"},
	{0x0E09, "CNF_ERR_CONF_HOLD_PART_FAILED"},
	{0x0E0A, "CNF_ERR_CONF_NO_MORE_CHANS"},
	{0x0E0B, "CNF_ERR_CONF_NOT_SAME_CPU"},
	{0x0E0C, "CNF_ERR_CONF_MAXNO_PARTS_CREATED"},
	{0x0E0D, "CNF_ERR_CONF_MAX_RSP_SLOTS"},
	{0x0E0E, "CNF_ERR_CONF_INCORRECT_FRAME_SIZE"},
	{0x0E0F, "CNF_ERR_CONF_NO_MUTE"},
	{0x0E10, "CNF_ERR_CONF_NO_HOLD"},
	{0x0E11, "CNF_ERR_CONF_NO_DESTROY"},
	{0x0E12, "CNF_ERR_CONF_CMD_INVALID_FOR_LSP"},
	{0x0E13, "CNF_ERR_CONF_CMD_INVALID_FOR_RSP"},
	{0x0E14, "CNF_ERR_CONF_CMD_DESTROY_INVALID_FOR_CONF"},
	{0x0E15, "CNF_ERR_CONF_CMD_NONZERO_PARTICIPANTS"},
	{0x0E16, "CNF_ERR_CONF_CMD_DOMTALK_INVALID_FOR_MIRO"},
	{0x0E17, "CNF_ERR_CONF_CMD_SPECIFY_DOMTALK_FAILED"},
	{0x0E18, "CNF_ERR_CONF_CMD_DOMTALK_NOT_SUPPORTED"},
	{0x0E19, "CNF_ERR_CONF_CMD_DOMTALK_PARAM_INVALID_VALUE"},
	{0x0E1A, "CNF_ERR_CONF_CMD_NSC_RSP_NOT_ALLOWED"},
	{0x0E1B, "CNF_ERR_CONF_CMD_NSC_LSP_NOT_SAME_BUS"},
	{0x0E1C, "CNF_ERR_CONF_CMD_NSC_NOT_SUPPORTED"},
	{0x0E1D, "CNF_ERR_CONF_CMD_NSC_PARAM_INVALID_VALUE"},
	{0x0E1E, "CNF_ERR_CONF_CMD_NSC_NONZERO_CONFS"},
	{0x0E1F, "CNF_ERR_CONF_CMD_NSC_DGAIN_PART_FAILED"},
	{0x0E20, "CNF_ERR_CONF_CMD_NSC_NO_DGAIN"},
	{0x0E21, "CNF_ERR_CONF_CMD_NSC_INVALID_FOR_MIRO"},
	{0x0E22, "CNF_ERR_CONF_CMD_INVALID_FOR_RSP_WTC"},
	{0x0E23, "CNF_ERR_CONF_CMD_NSC_MAX_WTC_CREATED"},
	{0x0F00, "CNF_ERR_AGC_INVALID_FOR_MIRO"},
	{0x0F01, "CNF_ERR_AGC_NOT_SUPPORTED"},
	{0x0F02, "CNF_ERR_AGC_PARAM_INVALID_VALUE"},
	{0x1000, "CNF_ERR_SELECTNIF_MAX_VALUE"},
	{0x1001, "CNF_ERROR_NIF_INIT"},
	{0x1002, "CNF_ERROR_PL_MAX_RULES"},
	{0x1003, "CNF_ERROR_PL_MAX_PROTO"},
	{0x1004, "CNF_ERROR_PL_INVALID_ACTION"},
	{0x1005, "CNF_ERROR_PL_INVALID_DESTINATION"},
	{0x1006, "CNF_ERROR_VID_INVALID"},
	{0x1007, "CNF_ERROR_PORT_INIT"},
	{0x1008, "CNF_ERROR_PORT_ALLOC"},
	{0x1009, "CNF_ERROR_PORT_VALUE"},
	{0x100A, "CNF_ERROR_PORT_INITIALIZED"},
	{0x100B, "CNF_ERROR_PORT_NOT_INITIALIZED"},
	{0x100C, "CNF_ERROR_PORT_INVALID"},
	{0x100D, "CNF_ERROR_PORT_VIRTUAL"},
	{0x100E, "CNF_ERROR_PORT_NULL"},
	{0x100F, "CNF_ERROR_PORT_NOT_FREE"},
	{0x1010, "CNF_ERROR_NIF_ALLOC"},
	{0x1011, "CNF_ERROR_NIF_NOT_INITIALIZED"},
	{0x1012, "CNF_ERROR_NIF_NOT_SELECTED"},
	{0x1013, "CNF_ERROR_CONTEXT_NULL"},
	{0x1014, "CNF_ERROR_DESTINATION_NULL"},
	{0x1015, "CNF_ERROR_PKT_NULL"},
	{0x7800, "CNF_ERROR_DIAG_0"},
	{0x7801, "CNF_ERROR_DIAG_1"},
	{0x7802, "CNF_ERROR_DIAG_2"},
	{0x7803, "CNF_ERROR_DIAG_ethreg1"},
	{0x7804, "CNF_ERROR_DIAG_ethreg2"},
	{0x7805, "CNF_ERROR_DIAG_ethreg3"},
	{0x7806, "CNF_ERROR_DIAG_nofacility"},
	{0x8000, "CNF_ERROR_INVALID_DTMF_DIGIT"},
	{0x8001, "CNF_ERROR_DISABLE_BAD_PT"},
	{0x8002, "CNF_ERROR_BAD_FRAME_BUF_LEN"},
	{0x8003, "CNF_ERROR_NO_FRAME_CTRL"},
	{0x8004, "CNF_ERROR_TONEOFF"},
	{0x8005, "CNF_ERROR_TG_TONEGEN"},
	{0x8006, "CNF_ERROR_TG_FREQ"},
	{0x8007, "CNF_ERROR_NO_PROT_WITH_RELAY"},
	{0x8008, "CNF_ERROR_CADENCE"},
	{0x8009, "CNF_ERROR_VOICE_INACTIVE"},
	{0x800A, "CNF_ERROR_LB_ICHAN_SWITCH"},
	{0x800B, "CNF_ERROR_LB_SELF"},
	{0x800C, "CNF_ERROR_LB_POST_ONTHEFLY"},
	{0x800D, "CNF_ERROR_LB_ICHAN_ONTHEFLY"},
	{0x800E, "CNF_ERROR_LB_ICHAN_SELF"},
	{0x800F, "CNF_ERROR_LB_ONTHEFLY"},
	{0x8010, "CNF_ERROR_LB_NO_DEST"},
	{0x8011, "CNF_ERROR_LB_NOT_IMPLEMENTED"},
	{0x8012, "CNF_ERROR_LB_NO_FPGA"},
	{0x8013, "CNF_ERR_NO_HIGHWAY"},
	{0x8014, "CNF_ERR_WRONG_HIGHWAY"},
	{0x8015, "CNF_ERR_NO_CHANGE_CHAN_IN_SVSR"},
	{0x8016, "CNF_ERR_NO_SPEECH_PROC"},
	{0x8017, "CNF_ERR_CHAGALL"},
	{0x8018, "CNF_ERR_NO_DIAGQRYCB"},
	{0x8019, "CNF_ERR_NO_DIAGENACB"},
	{0x801A, "CNF_ERR_NO_CFGCHANGECB"},
	{0x801B, "CNF_ERR_NO_CFGQUERYCB"},
	{0x801C, "CNF_ERR_NO_STATCB"},
	{0x801D, "DELAYED_ACK"},
	{0xFFA5, "ERR_SPU_FEATURE_NOT_ENABLED"},
	{0xFFA6, "ERR_DSPDIAG_INVCODECID"},
	{0xFFA7, "ERR_CHANNELS_NOT_RUNNING"},
	{0xFFA8, "ERR_VBE_CONFIG"},
	{0xFFA9, "ERR_HEARTBEAT_SIZE"},
	{0xFFAA, "ERR_STAGGER_SIZE"},
	{0xFFAB, "ERR_MAX_SIZE"},
	{0xFFAC, "ERR_CHANNELS_RUNNING"},
	{0xFFAD, "ERR_UNKNOWN_FUNCTION"},
	{0xFFAE, "ERR_COMMAND_LEN"},
	{0xFFAF, "ERR_RTXC_TASK_CREATE_FAILURE"},
	{0xFFBD, "ERR_TDMDRV_INVTS"},
	{0xFFBE, "ERR_TDMDRV_INVBUSID"},
	{0xFFBF, "ERR_TDMDRV_INVBUFSZ"},
	{0xFFCF, "ERR_SPEECH_NO_SUCH_CODEC"},
	{0xFFDE, "ERR_CHANCTRL_NO_SUCH_CHAN"},
	{0xFFDF, "ERR_CHANCTRL_NEED_ARM1_RES"},
	{0xFFEB, "ERR_RM_NO_SPU_MIPS_AVAILABLE"},
	{0xFFEC, "ERR_RM_NO_ARM1_MIPS_AVAILABLE"},
	{0xFFED, "ERR_RM_NO_ARM0_MIPS_AVAILABLE"},
	{0xFFEE, "ERR_RM_NO_ARM_MIPS_AVAILABLE"},
	{0xFFEF, "ERR_RM_NEED_ARM1_RES"},
	{0xFFF1, "ERR_MALLOC_GENERIC"},
	{0xFFF2, "DELAYED_VOIPCONFIG_ACK"},
	{0xFFF3, "ERR_OUT_OF_RANGE"},
	{0xFFF4, "ERR_MALLOC_IRAM_LOCAL_NCNB_HEAP"},
	{0xFFF5, "ERR_MALLOC_IRAM_LOCAL_HEAP"},
	{0xFFF6, "ERR_MALLOC_IRAM_GLOBAL_NCNB_HEAP"},
	{0xFFF7, "ERR_MALLOC_IRAM_GLOBAL_HEAP"},
	{0xFFF8, "ERR_MALLOC_ERAM_LOCAL_NCNB_HEAP"},
	{0xFFF9, "ERR_MALLOC_ERAM_LOCAL_HEAP"},
	{0xFFFA, "ERR_MALLOC_ERAM_GLOBAL_NCNB_HEAP"},
	{0xFFFB, "ERR_MALLOC_ERAM_GLOBAL_HEAP"},
	{0xFFFC, "ERR_MALLOC_SDRAM_LOCAL_NCNB_HEAP"},
	{0xFFFD, "ERR_MALLOC_SDRAM_LOCAL_HEAP"},
	{0xFFFE, "ERR_MALLOC_SDRAM_GLOBAL_NCNB_HEAP"},
	{0xFFFF, "ERR_MALLOC_SDRAM_GLOBAL_HEAP "},
	{ 0,      NULL }
};



/* Initialize the protocol and registered fields */
static int proto_csm_encaps            = -1;

static int hf_csm_encaps_opcode	          = -1;
static int hf_csm_encaps_seq              = -1;
static int hf_csm_encaps_ctrl             = -1;
static int hf_csm_encaps_ctrl_endian      = -1;
static int hf_csm_encaps_ctrl_ack         = -1;
static int hf_csm_encaps_ctrl_ack_supress = -1;
static int hf_csm_encaps_channel          = -1;
static int hf_csm_encaps_index            = -1;
static int hf_csm_encaps_length           = -1;
static int hf_csm_encaps_class            = -1;
static int hf_csm_encaps_type             = -1;
static int hf_csm_encaps_function_code    = -1;
static int hf_csm_encaps_reserved         = -1;
static int hf_csm_encaps_param_error      = -1;
static int hf_csm_encaps_param1           = -1;
static int hf_csm_encaps_param2           = -1;
static int hf_csm_encaps_param3           = -1;
static int hf_csm_encaps_param4           = -1;
static int hf_csm_encaps_param5           = -1;
static int hf_csm_encaps_param6           = -1;
static int hf_csm_encaps_param7           = -1;
static int hf_csm_encaps_param8           = -1;
static int hf_csm_encaps_param9           = -1;
static int hf_csm_encaps_param10          = -1;
static int hf_csm_encaps_param11          = -1;
static int hf_csm_encaps_param12          = -1;
static int hf_csm_encaps_param13          = -1;
static int hf_csm_encaps_param14          = -1;
static int hf_csm_encaps_param15          = -1;
static int hf_csm_encaps_param16          = -1;
static int hf_csm_encaps_param17          = -1;
static int hf_csm_encaps_param18          = -1;
static int hf_csm_encaps_param19          = -1;
static int hf_csm_encaps_param20          = -1;
static int hf_csm_encaps_param21          = -1;
static int hf_csm_encaps_param22          = -1;
static int hf_csm_encaps_param23          = -1;
static int hf_csm_encaps_param24          = -1;
static int hf_csm_encaps_param25          = -1;
static int hf_csm_encaps_param26          = -1;
static int hf_csm_encaps_param27          = -1;
static int hf_csm_encaps_param28          = -1;
static int hf_csm_encaps_param29          = -1;
static int hf_csm_encaps_param30          = -1;
static int hf_csm_encaps_param            = -1;


/* Initialize the subtree pointers */
static gint ett_csm_encaps         = -1;
static gint ett_csm_encaps_control = -1;

gchar *csm_fc(guint16 fc, guint16 ct);
gboolean csm_to_host(guint16 fc, guint16 ct);

/* returns the command name */
gchar *csm_fc(guint16 fc, guint16 ct)
{
	gchar find=0;
	guint16 i=0;
	gchar str[256];


	if (fc == 0x0000)
	{
		while (find==0)
		{
			if (class_type_vals[i].strptr == NULL)
			{
				sprintf(str, "Unknow: (0x%04X)", ct);
				find=1;
			}

			else if (class_type_vals[i].value == ct)
			{
				sprintf(str, "%s", class_type_vals[i].strptr);
				find=1;
			}
			i++;
		}
	}

	else
	{
		while (find==0)
		{
			if (function_code_vals[i].strptr == NULL)
			{
				sprintf(str, "Unknow: (0x%04X)", fc);
				find=1;
			}

			else if (function_code_vals[i].value == fc)
			{
				sprintf(str, "%s", function_code_vals[i].strptr);
				find=1;
			}
			i++;
		}
	}
	return (gchar *) g_strdup(str);
}



/* check to see if the message is an exclusive message send to host */
gboolean csm_to_host(guint16 fc, guint16 ct)
{
	guint16 i=0;

	if (fc == 0x0000)
	{
		while (1)
		{
			if (exclusive_to_host_ct_vals[i].strptr == NULL)
				return FALSE;
			else if (exclusive_to_host_ct_vals[i].value == ct)
				return TRUE;
			i++;
		}
	}

	else
	{
		while (1)
		{
			if (exclusive_to_host_vals[i].strptr == NULL)
				return FALSE;
			else if (exclusive_to_host_vals[i].value == fc)
				return TRUE;
			i++;
		}
	}
	return FALSE;
}



/* Code to actually dissect the packets */
static void
dissect_csm_encaps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item  *ti, *subitem;
	proto_tree  *csm_encaps_tree = NULL;
	proto_tree  *csm_encaps_control_tree = NULL;
	guint16      function_code, channel, class_type;
	guint8       control, type, sequence, length;
	gint         i;
	gboolean     show_error_param= FALSE;
	gchar       *col_str;


	function_code = tvb_get_letohs(tvb, 10);
	control = tvb_get_guint8(tvb, 3);

	class_type= tvb_get_guint8(tvb, 9);
	class_type= class_type<<8;
	class_type|= tvb_get_guint8(tvb, 8);

	type = tvb_get_guint8(tvb, 8);
	sequence = tvb_get_guint8(tvb, 2);
	length = tvb_get_guint8(tvb, 6);
	channel = tvb_get_ntohs(tvb, 4);


	if (CSM_ENCAPS_CTRL_ACK&control)
		show_error_param= FALSE;
	else
	{
		if (csm_to_host(function_code, class_type)) /* exclusive messages to host */
			show_error_param= FALSE;
		else
		{
			if (type == CSM_ENCAPS_TYPE_RESPONSE)
				show_error_param= TRUE;
			else
				show_error_param= FALSE;
		}
	}


	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "CSM_ENCAPS");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);


		if (CSM_ENCAPS_CTRL_ACK&control)
		{
			if (CSM_ENCAPS_CTRL_ACK_TO_HOST&control)
				col_append_fstr(pinfo->cinfo, COL_INFO, "<-- ACK Packet, Channel: 0x%04X, Sequence: %d - (To Host)", channel, sequence);
			else
				col_append_fstr(pinfo->cinfo, COL_INFO, "--> ACK Packet, Channel: 0x%04X, Sequence: %d - (From Host)", channel, sequence);
		}
		else
		{
			col_str = csm_fc(function_code, class_type);
			if ((type == CSM_ENCAPS_TYPE_RESPONSE) || (csm_to_host(function_code, class_type)))
				col_append_fstr(pinfo->cinfo, COL_INFO, "<-- %s, Channel: 0x%04X, Sequence: %d - (To Host)", col_str, channel, sequence);
			else
				col_append_fstr(pinfo->cinfo, COL_INFO, "--> %s, Channel: 0x%04X, Sequence: %d - (From Host)", col_str, channel, sequence);
			g_free(col_str);
		}
	}


	if (tree) {
		ti = proto_tree_add_item(tree, proto_csm_encaps, tvb, 0, -1, FALSE);
		csm_encaps_tree = proto_item_add_subtree(ti, ett_csm_encaps);




		proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_opcode, tvb, 0, 2, FALSE);
		proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_seq, tvb, 2, 1, FALSE);

		subitem = proto_tree_add_uint(csm_encaps_tree, hf_csm_encaps_ctrl, tvb, 3, 1, control);
		csm_encaps_control_tree = proto_item_add_subtree(subitem, ett_csm_encaps_control);

		    proto_tree_add_boolean(csm_encaps_control_tree, hf_csm_encaps_ctrl_ack, tvb, 3, 1, control);
    		proto_tree_add_boolean(csm_encaps_control_tree, hf_csm_encaps_ctrl_ack_supress, tvb, 3, 1, control);
		    proto_tree_add_boolean(csm_encaps_control_tree, hf_csm_encaps_ctrl_endian, tvb, 3, 1, control);

		proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_channel, tvb, 4, 2, FALSE);
		proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_length, tvb, 6, 1, FALSE);
		proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_index, tvb, 7, 1, FALSE);
		proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_class, tvb, 9, 1, FALSE);
		proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_type, tvb, 8, 1, FALSE);
		proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_function_code, tvb, 10, 2, TRUE);

		i=6;

		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_reserved, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length)
		{
			if (show_error_param)
				proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param_error, tvb, 12 + i-6, 2, TRUE);
			else
				proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param1, tvb, 12 + i-6, 2, TRUE);
			i+=2;
		}
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param2, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param3, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param4, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param5, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param6, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param7, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param8, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param9, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param10, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param11, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param12, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param13, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param14, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param15, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param16, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param17, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param18, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param19, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param20, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param21, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param22, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param23, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param24, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param25, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param26, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param27, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param28, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param29, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param30, tvb, 12 + i-6, 2, TRUE); i+=2;

		for (; i<length; i+=2)
			proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param, tvb, 12 + i-6, 2, TRUE);
	}
}


void
proto_register_csm_encaps(void)
{
	static struct true_false_string control_endian_bit      = {"Little Endian","Big Endian"};
	static struct true_false_string control_ack_bit         = {"ACK Packet", "Message Packet"};
	static struct true_false_string control_ack_supress_bit = {"ACK Supressed", "ACK Required"};


	static hf_register_info hf[] = {
		{ &hf_csm_encaps_opcode,
			{ "Opcode", "csm_encaps.opcode",
				FT_UINT16, BASE_HEX, VALS(opcode_vals), 0,
				"CSM_ENCAPS Opcode", HFILL }
		},
		{ &hf_csm_encaps_seq,
			{ "Sequence Number", "csm_encaps.seq_num",
				FT_UINT8, BASE_DEC, NULL, 0,
				"CSM_ENCAPS Sequence Number", HFILL }
		},

		{ &hf_csm_encaps_ctrl,
			{ "Control", "csm_encaps.ctrl",
				FT_UINT8, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Control", HFILL }
		},

		{ &hf_csm_encaps_ctrl_ack,
		   { "Packet Bit",	"csm_encaps.ctrl.ack",
		        FT_BOOLEAN, 8, TFS(&control_ack_bit), CSM_ENCAPS_CTRL_ACK,
		        "Message Packet/ACK Packet", HFILL }
		},
		{ &hf_csm_encaps_ctrl_ack_supress,
		   { "ACK Supress Bit",	"csm_encaps.ctrl.ack_supress",
		        FT_BOOLEAN, 8, TFS(&control_ack_supress_bit), CSM_ENCAPS_CTRL_ACK_SUPRESS,
		        "ACK Required/ACK Supressed", HFILL }
		},
		{ &hf_csm_encaps_ctrl_endian,
		   { "Endian Bit",	"csm_encaps.ctrl.endian",
		        FT_BOOLEAN, 8, TFS(&control_endian_bit), CSM_ENCAPS_CTRL_ENDIAN,
		        "Little Endian/Big Endian", HFILL }
		},


		{ &hf_csm_encaps_channel,
			{ "Channel Number", "csm_encaps.channel",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Channel Number", HFILL }
		},
		{ &hf_csm_encaps_index,
			{ "Index", "csm_encaps.index",
				FT_UINT8, BASE_DEC, NULL, 0,
				"CSM_ENCAPS Index", HFILL }
		},
		{ &hf_csm_encaps_length,
			{ "Length", "csm_encaps.length",
				FT_UINT8, BASE_DEC, NULL, 0,
				"CSM_ENCAPS Length", HFILL }
		},
		{ &hf_csm_encaps_class,
			{ "Class", "csm_encaps.class",
				FT_UINT8, BASE_DEC, NULL, 0,
				"CSM_ENCAPS Class", HFILL }
		},
		{ &hf_csm_encaps_type,
			{ "Type", "csm_encaps.type",
				FT_UINT8, BASE_DEC, NULL, 0,
				"CSM_ENCAPS Type", HFILL }
		},
		{ &hf_csm_encaps_function_code,
			{ "Function Code", "csm_encaps.function_code",
				FT_UINT16, BASE_HEX, VALS(function_code_vals), 0,
				"CSM_ENCAPS Function Code", HFILL }
		},
		{ &hf_csm_encaps_reserved,
			{ "Reserved", "csm_encaps.reserved",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Reserved", HFILL }
		},
		{ &hf_csm_encaps_param_error,
			{ "Parameter 1", "csm_encaps.param1",
				FT_UINT16, BASE_HEX, VALS(error_vals), 0,
				"CSM_ENCAPS Parameter 1", HFILL }
		},
		{ &hf_csm_encaps_param1,
			{ "Parameter 1", "csm_encaps.param1",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 1", HFILL }
		},
		{ &hf_csm_encaps_param2,
			{ "Parameter 2", "csm_encaps.param2",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 2", HFILL }
		},
		{ &hf_csm_encaps_param3,
			{ "Parameter 3", "csm_encaps.param3",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 3", HFILL }
		},
		{ &hf_csm_encaps_param4,
			{ "Parameter 4", "csm_encaps.param4",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 4", HFILL }
		},
		{ &hf_csm_encaps_param5,
			{ "Parameter 5", "csm_encaps.param5",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 5", HFILL }
		},
		{ &hf_csm_encaps_param6,
			{ "Parameter 6", "csm_encaps.param6",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 6", HFILL }
		},
		{ &hf_csm_encaps_param7,
			{ "Parameter 7", "csm_encaps.param7",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 7", HFILL }
		},
		{ &hf_csm_encaps_param8,
			{ "Parameter 8", "csm_encaps.param8",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 8", HFILL }
		},
		{ &hf_csm_encaps_param9,
			{ "Parameter 9", "csm_encaps.param9",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 9", HFILL }
		},
		{ &hf_csm_encaps_param10,
			{ "Parameter 10", "csm_encaps.param10",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 10", HFILL }
		},
		{ &hf_csm_encaps_param11,
			{ "Parameter 11", "csm_encaps.param11",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 11", HFILL }
		},
		{ &hf_csm_encaps_param12,
			{ "Parameter 12", "csm_encaps.param12",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 12", HFILL }
		},
		{ &hf_csm_encaps_param13,
			{ "Parameter 13", "csm_encaps.param13",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 13", HFILL }
		},
		{ &hf_csm_encaps_param14,
			{ "Parameter 14", "csm_encaps.param14",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 14", HFILL }
		},
		{ &hf_csm_encaps_param15,
			{ "Parameter 15", "csm_encaps.param15",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 15", HFILL }
		},
		{ &hf_csm_encaps_param16,
			{ "Parameter 16", "csm_encaps.param16",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 16", HFILL }
		},
		{ &hf_csm_encaps_param17,
			{ "Parameter 17", "csm_encaps.param17",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 17", HFILL }
		},
		{ &hf_csm_encaps_param18,
			{ "Parameter 18", "csm_encaps.param18",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 18", HFILL }
		},
		{ &hf_csm_encaps_param19,
			{ "Parameter 19", "csm_encaps.param19",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 19", HFILL }
		},
		{ &hf_csm_encaps_param20,
			{ "Parameter 20", "csm_encaps.param20",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 20", HFILL }
		},
		{ &hf_csm_encaps_param21,
			{ "Parameter 21", "csm_encaps.param21",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 21", HFILL }
		},
		{ &hf_csm_encaps_param22,
			{ "Parameter 22", "csm_encaps.param22",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 22", HFILL }
		},
		{ &hf_csm_encaps_param23,
			{ "Parameter 23", "csm_encaps.param23",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 23", HFILL }
		},
		{ &hf_csm_encaps_param24,
			{ "Parameter 24", "csm_encaps.param24",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 24", HFILL }
		},
		{ &hf_csm_encaps_param25,
			{ "Parameter 25", "csm_encaps.param25",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 25", HFILL }
		},
		{ &hf_csm_encaps_param26,
			{ "Parameter 26", "csm_encaps.param26",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 26", HFILL }
		},
		{ &hf_csm_encaps_param27,
			{ "Parameter 27", "csm_encaps.param27",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 27", HFILL }
		},
		{ &hf_csm_encaps_param28,
			{ "Parameter 28", "csm_encaps.param28",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 28", HFILL }
		},
		{ &hf_csm_encaps_param29,
			{ "Parameter 29", "csm_encaps.param29",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 29", HFILL }
		},
		{ &hf_csm_encaps_param30,
			{ "Parameter 30", "csm_encaps.param30",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 30", HFILL }
		},
		{ &hf_csm_encaps_param,
			{ "Parameter", "csm_encaps.param",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter", HFILL }
		},
	};

	static gint *ett[] = {
		&ett_csm_encaps,
		&ett_csm_encaps_control
	};

	proto_csm_encaps = proto_register_protocol("CSM_ENCAPS", "CSM_ENCAPS", "csm_encaps");
	proto_register_field_array(proto_csm_encaps, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_csm_encaps(void)
{
	dissector_handle_t csm_encaps_handle;

	csm_encaps_handle = create_dissector_handle(dissect_csm_encaps, proto_csm_encaps);
	dissector_add("ethertype", ETHERTYPE_CSM_ENCAPS, csm_encaps_handle);
}
