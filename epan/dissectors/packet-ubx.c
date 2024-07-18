/* packet-ubx.c
 * u-blox UBX protocol dissection.
 *
 * By Timo Warns <timo.warns@gmail.com>
 * Copyright 2023 Timo Warns
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/unit_strings.h>
#include <wsutil/utf8_entities.h>
#include <wsutil/pint.h>

#include "packet-ubx.h"
#include "packet-sbas_l1.h"

/*
 * Dissects the UBX protocol of u-blox GNSS receivers as defined by the
 * u-blox 8 / u-blox M8 receiver description.
 */

/* mapping from UBX message class / id to mnemonics */
static const value_string UBX_MSG_CLASS_ID[] = {
    {UBX_ACK_ACK, "UBX-ACK-ACK"},
    {UBX_ACK_NAK, "UBX-ACK-NAK"},
    {UBX_AID_ALM, "UBX-AID-ALM"},
    {UBX_AID_AOP, "UBX-AID-AOP"},
    {UBX_AID_EPH, "UBX-AID-EPH"},
    {UBX_AID_HUI, "UBX-AID-HUI"},
    {UBX_AID_INI, "UBX-AID-INI"},
    {UBX_CFG_ANT, "UBX-CFG-ANT"},
    {UBX_CFG_BATCH, "UBX-CFG-BATCH"},
    {UBX_CFG_CFG, "UBX-CFG-CFG"},
    {UBX_CFG_DAT, "UBX-CFG-DAT"},
    {UBX_CFG_DGNSS, "UBX-CFG-DGNSS"},
    {UBX_CFG_DOSC, "UBX-CFG-DOSC"},
    {UBX_CFG_ESFALG, "UBX-CFG-ESFALG"},
    {UBX_CFG_ESFA, "UBX-CFG-ESFA"},
    {UBX_CFG_ESFG, "UBX-CFG-ESFG"},
    {UBX_CFG_ESFWT, "UBX-CFG-ESFWT"},
    {UBX_CFG_ESRC, "UBX-CFG-ESRC"},
    {UBX_CFG_GEOFENCE, "UBX-CFG-GEOFENCE"},
    {UBX_CFG_GNSS, "UBX-CFG-GNSS"},
    {UBX_CFG_HNR, "UBX-CFG-HNR"},
    {UBX_CFG_INF, "UBX-CFG-INF"},
    {UBX_CFG_ITFM, "UBX-CFG-ITFM"},
    {UBX_CFG_LOGFILTER, "UBX-CFG-LOGFILTER"},
    {UBX_CFG_MSG, "UBX-CFG-MSG"},
    {UBX_CFG_NAV5, "UBX-CFG-NAV5"},
    {UBX_CFG_NAVX5, "UBX-CFG-NAVX5"},
    {UBX_CFG_NMEA, "UBX-CFG-NMEA"},
    {UBX_CFG_ODO, "UBX-CFG-ODO"},
    {UBX_CFG_PM2, "UBX-CFG-PM2"},
    {UBX_CFG_PMS, "UBX-CFG-PMS"},
    {UBX_CFG_PRT, "UBX-CFG-PRT"},
    {UBX_CFG_PWR, "UBX-CFG-PWR"},
    {UBX_CFG_RATE, "UBX-CFG-RATE"},
    {UBX_CFG_RINV, "UBX-CFG-RINV"},
    {UBX_CFG_RST, "UBX-CFG-RST"},
    {UBX_CFG_RXM, "UBX-CFG-RXM"},
    {UBX_CFG_SBAS, "UBX-CFG-SBAS"},
    {UBX_CFG_SENIF, "UBX-CFG-SENIF"},
    {UBX_CFG_SLAS, "UBX-CFG-SLAS"},
    {UBX_CFG_SMGR, "UBX-CFG-SMGR"},
    {UBX_CFG_SPT, "UBX-CFG-SPT"},
    {UBX_CFG_TMODE2, "UBX-CFG-TMODE2"},
    {UBX_CFG_TMODE3, "UBX-CFG-TMODE3"},
    {UBX_CFG_TP5, "UBX-CFG-TP5"},
    {UBX_CFG_TXSLOT, "UBX-CFG-TXSLOT"},
    {UBX_CFG_USB, "UBX-CFG-USB"},
    {UBX_ESF_ALG, "UBX-ESF-ALG"},
    {UBX_ESF_INS, "UBX-ESF-INS"},
    {UBX_ESF_MEAS, "UBX-ESF-MEAS"},
    {UBX_ESF_RAW, "UBX-ESF-RAW"},
    {UBX_ESF_STATUS, "UBX-ESF-STATUS"},
    {UBX_HNR_ATT, "UBX-HNR-ATT"},
    {UBX_HNR_INS, "UBX-HNR-INS"},
    {UBX_HNR_PVT, "UBX-HNR-PVT"},
    {UBX_INF_DEBUG, "UBX-INF-DEBUG"},
    {UBX_INF_ERROR, "UBX-INF-ERROR"},
    {UBX_INF_NOTICE, "UBX-INF-NOTICE"},
    {UBX_INF_TEST, "UBX-INF-TEST"},
    {UBX_INF_WARNING, "UBX-INF-WARNING"},
    {UBX_LOG_BATCH, "UBX-LOG-BATCH"},
    {UBX_LOG_CREATE, "UBX-LOG-CREATE"},
    {UBX_LOG_ERASE, "UBX-LOG-ERASE"},
    {UBX_LOG_FINDTIME, "UBX-LOG-FINDTIME"},
    {UBX_LOG_INFO, "UBX-LOG-INFO"},
    {UBX_LOG_RETRIEVEBATCH, "UBX-LOG-RETRIEVEBATCH"},
    {UBX_LOG_RETRIEVEPOSEXTRA, "UBX-LOG-RETRIEVEPOSEXTRA"},
    {UBX_LOG_RETRIEVEPOS, "UBX-LOG-RETRIEVEPOS"},
    {UBX_LOG_RETRIEVESTRING, "UBX-LOG-RETRIEVESTRING"},
    {UBX_LOG_RETRIEVE, "UBX-LOG-RETRIEVE"},
    {UBX_LOG_STRING, "UBX-LOG-STRING"},
    {UBX_MGA_ACK_DATA0, "UBX-MGA-ACK-DATA0"},
    {UBX_MGA_ANO, "UBX-MGA-ANO"},
    {UBX_MGA_BDS, "UBX-MGA-BDS"},
    {UBX_MGA_DBD, "UBX-MGA-DBD"},
    {UBX_MGA_FLASH, "UBX-MGA-FLASH"},
    {UBX_MGA_GAL, "UBX-MGA-GAL"},
    {UBX_MGA_GLO, "UBX-MGA-GLO"},
    {UBX_MGA_GPS, "UBX-MGA-GPS"},
    {UBX_MGA_INI, "UBX-MGA-INI"},
    {UBX_MGA_QZSS, "UBX-MGA-QZSS"},
    {UBX_MON_BATCH, "UBX-MON-BATCH"},
    {UBX_MON_GNSS, "UBX-MON-GNSS"},
    {UBX_MON_HW2, "UBX-MON-HW2"},
    {UBX_MON_HW, "UBX-MON-HW"},
    {UBX_MON_IO, "UBX-MON-IO"},
    {UBX_MON_MSGPP, "UBX-MON-MSGPP"},
    {UBX_MON_PATCH, "UBX-MON-PATCH"},
    {UBX_MON_RXBUF, "UBX-MON-RXBUF"},
    {UBX_MON_RXR, "UBX-MON-RXR"},
    {UBX_MON_SMGR, "UBX-MON-SMGR"},
    {UBX_MON_SPT, "UBX-MON-SPT"},
    {UBX_MON_TXBUF, "UBX-MON-TXBUF"},
    {UBX_MON_VER, "UBX-MON-VER"},
    {UBX_NAV_AOPSTATUS, "UBX-NAV-AOPSTATUS"},
    {UBX_NAV_ATT, "UBX-NAV-ATT"},
    {UBX_NAV_CLOCK, "UBX-NAV-CLOCK"},
    {UBX_NAV_COV, "UBX-NAV-COV"},
    {UBX_NAV_DGPS, "UBX-NAV-DGPS"},
    {UBX_NAV_DOP, "UBX-NAV-DOP"},
    {UBX_NAV_EELL, "UBX-NAV-EELL"},
    {UBX_NAV_EOE, "UBX-NAV-EOE"},
    {UBX_NAV_GEOFENCE, "UBX-NAV-GEOFENCE"},
    {UBX_NAV_HPPOSECEF, "UBX-NAV-HPPOSECEF"},
    {UBX_NAV_HPPOSLLH, "UBX-NAV-HPPOSLLH"},
    {UBX_NAV_NMI, "UBX-NAV-NMI"},
    {UBX_NAV_ODO, "UBX-NAV-ODO"},
    {UBX_NAV_ORB, "UBX-NAV-ORB"},
    {UBX_NAV_POSECEF, "UBX-NAV-POSECEF"},
    {UBX_NAV_POSLLH, "UBX-NAV-POSLLH"},
    {UBX_NAV_PVT, "UBX-NAV-PVT"},
    {UBX_NAV_RELPOSNED, "UBX-NAV-RELPOSNED"},
    {UBX_NAV_RESETODO, "UBX-NAV-RESETODO"},
    {UBX_NAV_SAT, "UBX-NAV-SAT"},
    {UBX_NAV_SBAS, "UBX-NAV-SBAS"},
    {UBX_NAV_SLAS, "UBX-NAV-SLAS"},
    {UBX_NAV_SOL, "UBX-NAV-SOL"},
    {UBX_NAV_STATUS, "UBX-NAV-STATUS"},
    {UBX_NAV_SVINFO, "UBX-NAV-SVINFO"},
    {UBX_NAV_SVIN, "UBX-NAV-SVIN"},
    {UBX_NAV_TIMEBDS, "UBX-NAV-TIMEBDS"},
    {UBX_NAV_TIMEGAL, "UBX-NAV-TIMEGAL"},
    {UBX_NAV_TIMEGLO, "UBX-NAV-TIMEGLO"},
    {UBX_NAV_TIMEGPS, "UBX-NAV-TIMEGPS"},
    {UBX_NAV_TIMELS, "UBX-NAV-TIMELS"},
    {UBX_NAV_TIMEUTC, "UBX-NAV-TIMEUTC"},
    {UBX_NAV_VELECEF, "UBX-NAV-VELECEF"},
    {UBX_NAV_VELNED, "UBX-NAV-VELNED"},
    {UBX_RXM_IMES, "UBX-RXM-IMES"},
    {UBX_RXM_MEASX, "UBX-RXM-MEASX"},
    {UBX_RXM_PMREQ, "UBX-RXM-PMREQ"},
    {UBX_RXM_RAWX, "UBX-RXM-RAWX"},
    {UBX_RXM_RLM, "UBX-RXM-RLM"},
    {UBX_RXM_RTCM, "UBX-RXM-RTCM"},
    {UBX_RXM_SFRBX, "UBX-RXM-SFRBX"},
    {UBX_RXM_SVSI, "UBX-RXM-SVSI"},
    {UBX_SEC_UNIQID, "UBX-SEC-UNIQID"},
    {UBX_TIM_DOSC, "UBX-TIM-DOSC"},
    {UBX_TIM_FCHG, "UBX-TIM-FCHG"},
    {UBX_TIM_HOC, "UBX-TIM-HOC"},
    {UBX_TIM_SMEAS, "UBX-TIM-SMEAS"},
    {UBX_TIM_SVIN, "UBX-TIM-SVIN"},
    {UBX_TIM_TM2, "UBX-TIM-TM2"},
    {UBX_TIM_TOS, "UBX-TIM-TOS"},
    {UBX_TIM_TP, "UBX-TIM-TP"},
    {UBX_TIM_VCOCAL, "UBX-TIM-VCOCAL"},
    {UBX_TIM_VRFY, "UBX-TIM-VRFY"},
    {UBX_UPD_SOS, "UBX-UPD-SOS"},
    {0, NULL},
};

static const value_string UBX_GNSS_ID[] = {
    {GNSS_ID_GPS,     "GPS"},
    {GNSS_ID_SBAS,    "SBAS"},
    {GNSS_ID_GALILEO, "Galileo"},
    {GNSS_ID_BEIDOU,  "Beidou"},
    {GNSS_ID_IMES,    "IMES"},
    {GNSS_ID_QZSS,    "QZSS"},
    {GNSS_ID_GLONASS, "Glonass"},
    {0, NULL},
};

/* mapping from correction age id to description */
static const value_string UBX_LAST_CORRECTION_AGE[] = {
    {0, "not available"},
    {1, "age between 0 and 1 second"},
    {2, "age between 1 (inclusive) and 2 seconds"},
    {3, "age between 2 (inclusive) and 5 seconds"},
    {4, "age between 5 (inclusive) and 10 seconds"},
    {5, "age between 10 (inclusive) and 15 seconds"},
    {6, "age between 15 (inclusive) and 20 seconds"},
    {7, "age between 20 (inclusive) and 30 seconds"},
    {8, "age between 30 (inclusive) and 45 seconds"},
    {9, "age between 45 (inclusive) and 60 seconds"},
    {10, "age between 60 (inclusive) and 90 seconds"},
    {11, "age between 90 (inclusive) and 120 seconds"},
    {12, "age greater or equal than 120 seconds"},
    {13, "age greater or equal than 120 seconds"},
    {14, "age greater or equal than 120 seconds"},
    {15, "age greater or equal than 120 seconds"},
    {0, NULL}
};

/* mapping from GNSS fix type id to description */
static const value_string UBX_GNSS_FIX_TYPE[] = {
    {0, "no fix"},
    {1, "dead reckoning only"},
    {2, "2D-fix"},
    {3, "3D-fix"},
    {4, "GNSS + dead reckoning combined"},
    {5, "time only fix"},
    {0, NULL}
};

/* signal quality indicator description */
static const value_string UBX_SIGNAL_QUALITY_INDICATOR[] = {
    {0, "no signal"},
    {1, "searching signal"},
    {2, "signal acquired"},
    {3, "signal detected but unusable"},
    {4, "code locked and time synchronized"},
    {5, "code and carrier locked and time synchronized"},
    {6, "code and carrier locked and time synchronized"},
    {7, "code and carrier locked and time synchronized"},
    {0, NULL}
};

/* signal health description */
static const value_string UBX_SIGNAL_HEALTH[] = {
    {0, "unknown"},
    {1, "healthy"},
    {2, "unhealthy"},
    {0, NULL}
};

/* orbit source description */
static const value_string UBX_ORBIT_SOURCE[] = {
    {0, "no orbit information available"},
    {1, "ephemeris is used"},
    {2, "almanac is used"},
    {3, "AssistNow Offline orbit is used"},
    {4, "AssistNow Autonomous orbit is used"},
    {5, "other orbit information is used"},
    {6, "other orbit information is used"},
    {7, "other orbit information is used"},
    {0, NULL}
};

/* CFG-GNSS GPS sigCfgMsk */
static const value_string UBX_CFG_GNSS_GPS_SIGCFGMASK[] = {
    {0x01, "GPS L1C/A"},
    {0x10, "GPS L2C"},
    {0, NULL}
};

/* CFG-GNSS SBAS sigCfgMsk */
static const value_string UBX_CFG_GNSS_SBAS_SIGCFGMASK[] = {
    {0x01, "SBAS L1C/A"},
    {0, NULL}
};

/* CFG-GNSS Galileo sigCfgMsk */
static const value_string UBX_CFG_GNSS_GAL_SIGCFGMASK[] = {
    {0x01, "Galileo E1"},
    {0x20, "Galileo E5b"},
    {0, NULL}
};

/* CFG-GNSS BeiDou sigCfgMsk */
static const value_string UBX_CFG_GNSS_BDS_SIGCFGMASK[] = {
    {0x01, "BeiDou B1I"},
    {0x10, "BeiDou B2I"},
    {0, NULL}
};

/* CFG-GNSS IMES sigCfgMsk */
static const value_string UBX_CFG_GNSS_IMES_SIGCFGMASK[] = {
    {0x01, "IMES L1"},
    {0, NULL}
};

/* CFG-GNSS QZSS sigCfgMsk */
static const value_string UBX_CFG_GNSS_QZSS_SIGCFGMASK[] = {
    {0x01, "QZSS L1C/A"},
    {0x04, "QZSS L1S"},
    {0x10, "QZSS L2C"},
    {0, NULL}
};

/* CFG-GNSS Glonass sigCfgMsk */
static const value_string UBX_CFG_GNSS_GLO_SIGCFGMASK[] = {
    {0x01, "Glonass L1"},
    {0x10, "Glonass L2"},
    {0, NULL}
};

/* UBX-RXM-MEASX Multipath index */
static const value_string UBX_RXM_MEASX_MULTIPATH_INDEX[] = {
    {0x0, "not measured"},
    {0x1, "low"},
    {0x2, "medium"},
    {0x3, "high"},
    {0, NULL}
};

/* SBAS mode */
static const value_string UBX_SBAS_MODE[] = {
    {0, "Disabled"},
    {1, "Enabled integrity"},
    {3, "Enabled test mode"},
    {0, NULL}
};

/* SBAS system */
static const value_string UBX_SBAS_SYSTEM[] = {
    {-1, "Unknown"},
    {0, "WAAS"},
    {1, "EGNOS"},
    {2, "MSAS"},
    {3, "GAGAN"},
    {16, "GPS"},
    {0, NULL}
};

/* SBAS testbed description */
static const value_string UBX_SBAS_TESTBED[] = {
    {0, "Ignore data when in test mode (SBAS msg 0)"},
    {1, "Use data anyhow"},
    {0, NULL}
};

/* UTC standard identifier */
static const value_string UBX_UTC_STD_ID[] = {
    {0, "Information not available"},
    {1, "Communications Research Laboratory (CRL), Tokyo, Japan"},
    {2, "National Institute of Standards and Technology (NIST)"},
    {3, "U.S. Naval Observatory (USNO)"},
    {4, "International Bureau of Weights and Measures (BIPM)"},
    {5, "European laboratories"},
    {6, "Former Soviet Union (SU)"},
    {7, "National Time Service Center (NTSC), China"},
    {15, "Unknown"},
    {0, NULL}
};

/* Initialize the protocol and registered fields */
static int proto_ubx;

static int hf_ubx_preamble;
static int hf_ubx_msg_class_id;
static int hf_ubx_payload_len;
static int hf_ubx_chksum;

static int hf_ubx_ack_ack;
static int hf_ubx_ack_ack_msg_class_id;

static int hf_ubx_ack_nak;
static int hf_ubx_ack_nak_msg_class_id;

static int hf_ubx_cfg_gnss;
static int hf_ubx_cfg_gnss_version;
static int hf_ubx_cfg_gnss_numtrkchhw;
static int hf_ubx_cfg_gnss_numtrkchuse;
static int hf_ubx_cfg_gnss_numconfigblocks;
static int hf_ubx_cfg_gnss_blk_gnssid;
static int hf_ubx_cfg_gnss_blk_restrkch;
static int hf_ubx_cfg_gnss_blk_maxtrkch;
static int hf_ubx_cfg_gnss_blk_reserved1;
static int hf_ubx_cfg_gnss_blk_enable;
static int hf_ubx_cfg_gnss_blk_sigcfgmask;
static int hf_ubx_cfg_gnss_blk_gps_sigcfgmask;
static int hf_ubx_cfg_gnss_blk_sbas_sigcfgmask;
static int hf_ubx_cfg_gnss_blk_gal_sigcfgmask;
static int hf_ubx_cfg_gnss_blk_bds_sigcfgmask;
static int hf_ubx_cfg_gnss_blk_imes_sigcfgmask;
static int hf_ubx_cfg_gnss_blk_qzss_sigcfgmask;
static int hf_ubx_cfg_gnss_blk_glo_sigcfgmask;

static int hf_ubx_cfg_sbas;
static int hf_ubx_cfg_sbas_mode;
static int hf_ubx_cfg_sbas_mode_enabled;
static int hf_ubx_cfg_sbas_mode_test;
static int hf_ubx_cfg_sbas_usage_range;
static int hf_ubx_cfg_sbas_usage_diffcorr;
static int hf_ubx_cfg_sbas_usage_integrity;
static int hf_ubx_cfg_sbas_max_sbas;
static int hf_ubx_cfg_sbas_scanmode_prn158;
static int hf_ubx_cfg_sbas_scanmode_prn157;
static int hf_ubx_cfg_sbas_scanmode_prn156;
static int hf_ubx_cfg_sbas_scanmode_prn155;
static int hf_ubx_cfg_sbas_scanmode_prn154;
static int hf_ubx_cfg_sbas_scanmode_prn153;
static int hf_ubx_cfg_sbas_scanmode_prn152;
static int hf_ubx_cfg_sbas_scanmode_prn151;
static int hf_ubx_cfg_sbas_scanmode_prn150;
static int hf_ubx_cfg_sbas_scanmode_prn149;
static int hf_ubx_cfg_sbas_scanmode_prn148;
static int hf_ubx_cfg_sbas_scanmode_prn147;
static int hf_ubx_cfg_sbas_scanmode_prn146;
static int hf_ubx_cfg_sbas_scanmode_prn145;
static int hf_ubx_cfg_sbas_scanmode_prn144;
static int hf_ubx_cfg_sbas_scanmode_prn143;
static int hf_ubx_cfg_sbas_scanmode_prn142;
static int hf_ubx_cfg_sbas_scanmode_prn141;
static int hf_ubx_cfg_sbas_scanmode_prn140;
static int hf_ubx_cfg_sbas_scanmode_prn139;
static int hf_ubx_cfg_sbas_scanmode_prn138;
static int hf_ubx_cfg_sbas_scanmode_prn137;
static int hf_ubx_cfg_sbas_scanmode_prn136;
static int hf_ubx_cfg_sbas_scanmode_prn135;
static int hf_ubx_cfg_sbas_scanmode_prn134;
static int hf_ubx_cfg_sbas_scanmode_prn133;
static int hf_ubx_cfg_sbas_scanmode_prn132;
static int hf_ubx_cfg_sbas_scanmode_prn131;
static int hf_ubx_cfg_sbas_scanmode_prn130;
static int hf_ubx_cfg_sbas_scanmode_prn129;
static int hf_ubx_cfg_sbas_scanmode_prn128;
static int hf_ubx_cfg_sbas_scanmode_prn127;
static int hf_ubx_cfg_sbas_scanmode_prn126;
static int hf_ubx_cfg_sbas_scanmode_prn125;
static int hf_ubx_cfg_sbas_scanmode_prn124;
static int hf_ubx_cfg_sbas_scanmode_prn123;
static int hf_ubx_cfg_sbas_scanmode_prn122;
static int hf_ubx_cfg_sbas_scanmode_prn121;
static int hf_ubx_cfg_sbas_scanmode_prn120;

static int * const ubx_cfg_sbas_mode_fields[] = {
    &hf_ubx_cfg_sbas_mode_enabled,
    &hf_ubx_cfg_sbas_mode_test,
    NULL
};

static int hf_ubx_nav_dop;
static int hf_ubx_nav_dop_itow;
static int hf_ubx_nav_dop_gdop;
static int hf_ubx_nav_dop_pdop;
static int hf_ubx_nav_dop_tdop;
static int hf_ubx_nav_dop_vdop;
static int hf_ubx_nav_dop_hdop;
static int hf_ubx_nav_dop_ndop;
static int hf_ubx_nav_dop_edop;

static int hf_ubx_nav_eoe;
static int hf_ubx_nav_eoe_itow;

static int hf_ubx_nav_odo;
static int hf_ubx_nav_odo_version;
static int hf_ubx_nav_odo_reserved1;
static int hf_ubx_nav_odo_itow;
static int hf_ubx_nav_odo_distance;
static int hf_ubx_nav_odo_totaldistance;
static int hf_ubx_nav_odo_distancestd;

static int hf_ubx_nav_posecef;
static int hf_ubx_nav_posecef_itow;
static int hf_ubx_nav_posecef_ecefx;
static int hf_ubx_nav_posecef_ecefy;
static int hf_ubx_nav_posecef_ecefz;
static int hf_ubx_nav_posecef_pacc;

static int hf_ubx_nav_pvt;
static int hf_ubx_nav_pvt_itow;
static int hf_ubx_nav_pvt_year;
static int hf_ubx_nav_pvt_month;
static int hf_ubx_nav_pvt_day;
static int hf_ubx_nav_pvt_hour;
static int hf_ubx_nav_pvt_min;
static int hf_ubx_nav_pvt_sec;
static int hf_ubx_nav_pvt_valid;
static int hf_ubx_nav_pvt_validmag;
static int hf_ubx_nav_pvt_fullyresolved;
static int hf_ubx_nav_pvt_validtime;
static int hf_ubx_nav_pvt_validdate;
static int hf_ubx_nav_pvt_tacc;
static int hf_ubx_nav_pvt_nano;
static int hf_ubx_nav_pvt_fixtype;
static int hf_ubx_nav_pvt_flags;
static int hf_ubx_nav_pvt_headvehvalid;
static int hf_ubx_nav_pvt_psmstate;
static int hf_ubx_nav_pvt_diffsoln;
static int hf_ubx_nav_pvt_gnssfixok;
static int hf_ubx_nav_pvt_flags2;
static int hf_ubx_nav_pvt_confirmedtime;
static int hf_ubx_nav_pvt_confirmeddate;
static int hf_ubx_nav_pvt_confirmedavai;
static int hf_ubx_nav_pvt_numsv;
static int hf_ubx_nav_pvt_lon;
static int hf_ubx_nav_pvt_lat;
static int hf_ubx_nav_pvt_height;
static int hf_ubx_nav_pvt_hmsl;
static int hf_ubx_nav_pvt_hacc;
static int hf_ubx_nav_pvt_vacc;
static int hf_ubx_nav_pvt_veln;
static int hf_ubx_nav_pvt_vele;
static int hf_ubx_nav_pvt_veld;
static int hf_ubx_nav_pvt_gspeed;
static int hf_ubx_nav_pvt_headmot;
static int hf_ubx_nav_pvt_sacc;
static int hf_ubx_nav_pvt_headacc;
static int hf_ubx_nav_pvt_pdop;
static int hf_ubx_nav_pvt_lastcorrectionage;
static int hf_ubx_nav_pvt_invalidllh;
static int hf_ubx_nav_pvt_reserved1;
static int hf_ubx_nav_pvt_headveh;
static int hf_ubx_nav_pvt_magdec;
static int hf_ubx_nav_pvt_magacc;

static int * const ubx_nav_pvt_valid_fields[] = {
    &hf_ubx_nav_pvt_validdate,
    &hf_ubx_nav_pvt_validtime,
    &hf_ubx_nav_pvt_fullyresolved,
    &hf_ubx_nav_pvt_validmag,
    NULL
};

static int * const ubx_nav_pvt_flags_fields[] = {
    &hf_ubx_nav_pvt_gnssfixok,
    &hf_ubx_nav_pvt_diffsoln,
    &hf_ubx_nav_pvt_psmstate,
    &hf_ubx_nav_pvt_headvehvalid,
    NULL
};

static int * const ubx_nav_pvt_flags2_fields[] = {
    &hf_ubx_nav_pvt_confirmedavai,
    &hf_ubx_nav_pvt_confirmeddate,
    &hf_ubx_nav_pvt_confirmedtime,
    NULL
};

static int hf_ubx_nav_sat;
static int hf_ubx_nav_sat_itow;
static int hf_ubx_nav_sat_version;
static int hf_ubx_nav_sat_num_svs;
static int hf_ubx_nav_sat_reserved1;
static int hf_ubx_nav_sat_gnss_id;
static int hf_ubx_nav_sat_sv_id;
static int hf_ubx_nav_sat_cn0;
static int hf_ubx_nav_sat_elev;
static int hf_ubx_nav_sat_azim;
static int hf_ubx_nav_sat_pr_res;
static int hf_ubx_nav_sat_flags;
static int hf_ubx_nav_sat_quality_ind;
static int hf_ubx_nav_sat_sv_used;
static int hf_ubx_nav_sat_health;
static int hf_ubx_nav_sat_diff_corr;
static int hf_ubx_nav_sat_smoothed;
static int hf_ubx_nav_sat_orbit_src;
static int hf_ubx_nav_sat_eph_avail;
static int hf_ubx_nav_sat_alm_avail;
static int hf_ubx_nav_sat_ano_avail;
static int hf_ubx_nav_sat_aop_avail;
static int hf_ubx_nav_sat_sbas_corr_used;
static int hf_ubx_nav_sat_rtcm_corr_used;
static int hf_ubx_nav_sat_slas_corr_used;
static int hf_ubx_nav_sat_spartn_corr_used;
static int hf_ubx_nav_sat_pr_corr_used;
static int hf_ubx_nav_sat_cr_corr_used;
static int hf_ubx_nav_sat_do_corr_used;

static int * const ubx_nav_sat_flags_fields[] = {
    &hf_ubx_nav_sat_quality_ind,
    &hf_ubx_nav_sat_sv_used,
    &hf_ubx_nav_sat_health,
    &hf_ubx_nav_sat_diff_corr,
    &hf_ubx_nav_sat_smoothed,
    &hf_ubx_nav_sat_orbit_src,
    &hf_ubx_nav_sat_eph_avail,
    &hf_ubx_nav_sat_alm_avail,
    &hf_ubx_nav_sat_ano_avail,
    &hf_ubx_nav_sat_aop_avail,
    &hf_ubx_nav_sat_sbas_corr_used,
    &hf_ubx_nav_sat_rtcm_corr_used,
    &hf_ubx_nav_sat_slas_corr_used,
    &hf_ubx_nav_sat_spartn_corr_used,
    &hf_ubx_nav_sat_pr_corr_used,
    &hf_ubx_nav_sat_cr_corr_used,
    &hf_ubx_nav_sat_do_corr_used,
    NULL
};

static int hf_ubx_nav_sbas;
static int hf_ubx_nav_sbas_itow;
static int hf_ubx_nav_sbas_geo;
static int hf_ubx_nav_sbas_mode;
static int hf_ubx_nav_sbas_sys;
static int hf_ubx_nav_sbas_service;
static int hf_ubx_nav_sbas_service_ranging;
static int hf_ubx_nav_sbas_service_corrections;
static int hf_ubx_nav_sbas_service_integrity;
static int hf_ubx_nav_sbas_service_testmode;
static int hf_ubx_nav_sbas_service_bad;
static int hf_ubx_nav_sbas_cnt;
static int hf_ubx_nav_sbas_reserved1;
static int hf_ubx_nav_sbas_sv_id;
static int hf_ubx_nav_sbas_flags;
static int hf_ubx_nav_sbas_udre;
static int hf_ubx_nav_sbas_sv_sys;
static int hf_ubx_nav_sbas_sv_service;
static int hf_ubx_nav_sbas_reserved2;
static int hf_ubx_nav_sbas_prc;
static int hf_ubx_nav_sbas_reserved3;
static int hf_ubx_nav_sbas_ic;

static int * const ubx_nav_sbas_service_fields[] = {
    &hf_ubx_nav_sbas_service_ranging,
    &hf_ubx_nav_sbas_service_corrections,
    &hf_ubx_nav_sbas_service_integrity,
    &hf_ubx_nav_sbas_service_testmode,
    &hf_ubx_nav_sbas_service_bad,
    NULL
};

static int hf_ubx_nav_timegps;
static int hf_ubx_nav_timegps_itow;
static int hf_ubx_nav_timegps_ftow;
static int hf_ubx_nav_timegps_week;
static int hf_ubx_nav_timegps_leaps;
static int hf_ubx_nav_timegps_valid;
static int hf_ubx_nav_timegps_leapsvalid;
static int hf_ubx_nav_timegps_weekvalid;
static int hf_ubx_nav_timegps_towvalid;
static int hf_ubx_nav_timegps_tacc;

static int * const ubx_nav_timegps_valid_fields[] = {
    &hf_ubx_nav_timegps_towvalid,
    &hf_ubx_nav_timegps_weekvalid,
    &hf_ubx_nav_timegps_leapsvalid,
    NULL
};

static int hf_ubx_nav_timeutc;
static int hf_ubx_nav_timeutc_itow;
static int hf_ubx_nav_timeutc_tacc;
static int hf_ubx_nav_timeutc_nano;
static int hf_ubx_nav_timeutc_year;
static int hf_ubx_nav_timeutc_month;
static int hf_ubx_nav_timeutc_day;
static int hf_ubx_nav_timeutc_hour;
static int hf_ubx_nav_timeutc_min;
static int hf_ubx_nav_timeutc_sec;
static int hf_ubx_nav_timeutc_valid;
static int hf_ubx_nav_timeutc_validtow;
static int hf_ubx_nav_timeutc_validwkn;
static int hf_ubx_nav_timeutc_validutc;
static int hf_ubx_nav_timeutc_utcstandard;

static int * const ubx_nav_timeutc_valid_fields[] = {
    &hf_ubx_nav_timeutc_validtow,
    &hf_ubx_nav_timeutc_validwkn,
    &hf_ubx_nav_timeutc_validutc,
    &hf_ubx_nav_timeutc_utcstandard,
    NULL
};

static int hf_ubx_nav_velecef;
static int hf_ubx_nav_velecef_itow;
static int hf_ubx_nav_velecef_ecefvx;
static int hf_ubx_nav_velecef_ecefvy;
static int hf_ubx_nav_velecef_ecefvz;
static int hf_ubx_nav_velecef_sacc;

static int hf_ubx_rxm_measx;
static int hf_ubx_rxm_measx_version;
static int hf_ubx_rxm_measx_reserved1;
static int hf_ubx_rxm_measx_gpstow;
static int hf_ubx_rxm_measx_glotow;
static int hf_ubx_rxm_measx_bdstow;
static int hf_ubx_rxm_measx_reserved2;
static int hf_ubx_rxm_measx_qzsstow;
static int hf_ubx_rxm_measx_gpstowacc;
static int hf_ubx_rxm_measx_glotowacc;
static int hf_ubx_rxm_measx_bdstowacc;
static int hf_ubx_rxm_measx_reserved3;
static int hf_ubx_rxm_measx_qzsstowacc;
static int hf_ubx_rxm_measx_numsv;
static int hf_ubx_rxm_measx_flags_towset;
static int hf_ubx_rxm_measx_reserved4;
static int hf_ubx_rxm_measx_gnssid;
static int hf_ubx_rxm_measx_svid;
static int hf_ubx_rxm_measx_cn0;
static int hf_ubx_rxm_measx_mpathindic;
static int hf_ubx_rxm_measx_dopplerms;
static int hf_ubx_rxm_measx_dopplerhz;
static int hf_ubx_rxm_measx_wholechips;
static int hf_ubx_rxm_measx_fracchips;
static int hf_ubx_rxm_measx_codephase;
static int hf_ubx_rxm_measx_intcodephase;
static int hf_ubx_rxm_measx_pseurangermserr;
static int hf_ubx_rxm_measx_reserved5;

static int hf_ubx_rxm_rawx;
static int hf_ubx_rxm_rawx_rcvtow;
static int hf_ubx_rxm_rawx_week;
static int hf_ubx_rxm_rawx_leaps;
static int hf_ubx_rxm_rawx_nummeas;
static int hf_ubx_rxm_rawx_recstat;
static int hf_ubx_rxm_rawx_recstat_leapsec;
static int hf_ubx_rxm_rawx_recstat_clkreset;
static int hf_ubx_rxm_rawx_version;
static int hf_ubx_rxm_rawx_reserved1;
static int hf_ubx_rxm_rawx_prmes;
static int hf_ubx_rxm_rawx_cpmes;
static int hf_ubx_rxm_rawx_domes;
static int hf_ubx_rxm_rawx_gnssid;
static int hf_ubx_rxm_rawx_svid;
static int hf_ubx_rxm_rawx_sigid;
static int hf_ubx_rxm_rawx_freqid;
static int hf_ubx_rxm_rawx_locktime;
static int hf_ubx_rxm_rawx_cn0;
static int hf_ubx_rxm_rawx_prstdev;
static int hf_ubx_rxm_rawx_cpstdev;
static int hf_ubx_rxm_rawx_dostdev;
static int hf_ubx_rxm_rawx_trkstat;
static int hf_ubx_rxm_rawx_trkstat_prvalid;
static int hf_ubx_rxm_rawx_trkstat_cpvalid;
static int hf_ubx_rxm_rawx_trkstat_halfcyc;
static int hf_ubx_rxm_rawx_trkstat_subhalfcyc;
static int hf_ubx_rxm_rawx_reserved2;

static int * const ubx_rxm_rawx_recstat_fields[] = {
    &hf_ubx_rxm_rawx_recstat_leapsec,
    &hf_ubx_rxm_rawx_recstat_clkreset,
    NULL
};

static int * const ubx_rxm_rawx_trkstat_fields[] = {
    &hf_ubx_rxm_rawx_trkstat_prvalid,
    &hf_ubx_rxm_rawx_trkstat_cpvalid,
    &hf_ubx_rxm_rawx_trkstat_halfcyc,
    &hf_ubx_rxm_rawx_trkstat_subhalfcyc,
    NULL
};

static int hf_ubx_rxm_sfrbx;
static int hf_ubx_rxm_sfrbx_gnssid;
static int hf_ubx_rxm_sfrbx_svid;
static int hf_ubx_rxm_sfrbx_sigid;
static int hf_ubx_rxm_sfrbx_freqid;
static int hf_ubx_rxm_sfrbx_numwords;
static int hf_ubx_rxm_sfrbx_chn;
static int hf_ubx_rxm_sfrbx_version;
static int hf_ubx_rxm_sfrbx_dwrd;
static int hf_ubx_rxm_sfrbx_reserved1;
static int hf_ubx_rxm_sfrbx_reserved2;
static int hf_ubx_rxm_sfrbx_reserved3;

static dissector_table_t ubx_class_id_dissector_table;
static dissector_table_t ubx_gnssid_dissector_table;

static expert_field ei_ubx_chksum;

static int ett_ubx;
static int ett_ubx_ack_ack;
static int ett_ubx_ack_nak;
static int ett_ubx_cfg_gnss;
static int ett_ubx_cfg_gnss_block[255];
static int ett_ubx_cfg_sbas;
static int ett_ubx_cfg_sbas_mode;
static int ett_ubx_cfg_sbas_scanmode;
static int ett_ubx_nav_dop;
static int ett_ubx_nav_eoe;
static int ett_ubx_nav_odo;
static int ett_ubx_nav_posecef;
static int ett_ubx_nav_pvt;
static int ett_ubx_nav_pvt_datetime;
static int ett_ubx_nav_pvt_valid;
static int ett_ubx_nav_pvt_flags;
static int ett_ubx_nav_pvt_flags2;
static int ett_ubx_nav_sat;
static int ett_ubx_nav_sat_sv_info[255];
static int ett_ubx_nav_sat_flags;
static int ett_ubx_nav_sbas;
static int ett_ubx_nav_sbas_service;
static int ett_ubx_nav_sbas_sv_info[255];
static int ett_ubx_nav_timegps;
static int ett_ubx_nav_timegps_tow;
static int ett_ubx_nav_timegps_valid;
static int ett_ubx_nav_timeutc;
static int ett_ubx_nav_timeutc_valid;
static int ett_ubx_nav_velecef;
static int ett_ubx_rxm_measx;
static int ett_ubx_rxm_measx_meas[255];
static int ett_ubx_rxm_rawx;
static int ett_ubx_rxm_rawx_recstat;
static int ett_ubx_rxm_rawx_trkstat;
static int ett_ubx_rxm_rawx_meas[255];
static int ett_ubx_rxm_sfrbx;

static dissector_handle_t ubx_handle;

/* compute the checksum for a UBX message (Fletcher 8-bit by RFC 1145 */
static uint16_t chksum_fletcher_8(const uint8_t *data, const int len) {
    uint8_t ck_a = 0, ck_b = 0;
    int i;

    for (i = 0; i < len; i++) {
        ck_a += data[i];
        ck_b += ck_a;
    }

    return (ck_b << 8) | ck_a;
}

/* Format code phase */
static void fmt_codephase(char *label, uint32_t p) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d * 2^-21 ms", p);
}

/* Format carrier phase standard deviation */
static void fmt_cpstdev(char *label, uint32_t p) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d.%03d cycles", (p * 4) / 1000, (p * 4) % 1000);
}

/* Format magnetic declination */
static void fmt_decl(char *label, int32_t d) {
    if (d >= 0) {
        snprintf(label, ITEM_LABEL_LENGTH, "%d.%02d%s", d / 100, d % 100,
                UTF8_DEGREE_SIGN);
    }
    else {
        snprintf(label, ITEM_LABEL_LENGTH, "-%d.%02d%s", -d / 100, -d % 100,
                UTF8_DEGREE_SIGN);
    }
}

/* Format magnetic declination accuracy */
static void fmt_decl_acc(char *label, uint32_t a) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d.%02d%s", a / 100,
            a % 100, UTF8_DEGREE_SIGN);
}

/* Format Dilution of Precision */
static void fmt_dop(char *label, uint32_t dop) {
    snprintf(label, ITEM_LABEL_LENGTH, "%i.%02i", dop / 100, dop % 100);
}

/* Format Doppler measurement in m/s */
static void fmt_dopplerms(char *label, int32_t d) {
    if (d >= 0) {
        snprintf(label, ITEM_LABEL_LENGTH, "%d.%02d m/s", d * 4 / 100, (d * 4) % 100);
    }
    else {
        snprintf(label, ITEM_LABEL_LENGTH, "-%d.%02d m/s", -d * 4 / 100, (-d * 4) % 100);
    }
}

/* Format Doppler measurement in Hz */
static void fmt_dopplerhz(char *label, int32_t d) {
    if (d >= 0) {
        snprintf(label, ITEM_LABEL_LENGTH, "%d.%01d Hz", d * 2 / 10, (d * 2) % 10);
    }
    else {
        snprintf(label, ITEM_LABEL_LENGTH, "-%d.%01d Hz", -d * 2 / 10, (-d * 2) % 10);
    }
}

/* Format Doppler standard deviation */
static void fmt_dostdev(char *label, uint32_t p) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d.%03d Hz", (1 << p) * 2 / 1000, ((1 << p) * 2) % 1000);
}

/* Format heading */
static void fmt_heading(char *label, int32_t h) {
    if (h >= 0) {
        snprintf(label, ITEM_LABEL_LENGTH, "%d.%05d%s", h / 100000, h % 100000,
                UTF8_DEGREE_SIGN);
    }
    else {
        snprintf(label, ITEM_LABEL_LENGTH, "-%d.%05d%s", -h / 100000,
                -h % 100000, UTF8_DEGREE_SIGN);
    }
}

/* Format heading accuracy */
static void fmt_heading_acc(char *label, uint32_t a) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d.%05d%s", a / 100000,
            a % 100000, UTF8_DEGREE_SIGN);
}

/* Format latitude or longitude */
static void fmt_lat_lon(char *label, int32_t l) {
    if (l >= 0) {
        snprintf(label, ITEM_LABEL_LENGTH, "%d.%07d%s", l / 10000000,
                l % 10000000, UTF8_DEGREE_SIGN);
    }
    else {
        snprintf(label, ITEM_LABEL_LENGTH, "-%d.%07d%s", -l / 10000000,
                -l % 10000000, UTF8_DEGREE_SIGN);
    }
}

/* Format pseudo-range residuals */
static void fmt_pr_res(char *label, int32_t p) {
    if (p >= 0) {
        snprintf(label, ITEM_LABEL_LENGTH, "%d.%01dm", p / 10, p % 10);
    }
    else {
        snprintf(label, ITEM_LABEL_LENGTH, "-%d.%01dm", -p / 10, -p % 10);
    }
}

/* Format pseudo-range standard deviation */
static void fmt_prstdev(char *label, uint32_t p) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d.%02dm", (1 << p) / 100, (1 << p) % 100);
}

/* Format measurement reference time accuracy */
static void fmt_towacc(char *label, uint32_t p) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d.%04dms", p / 16, (p * 10000 / 16) % 10000);
}

/* Dissect UBX message */
static int dissect_ubx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    tvbuff_t *next_tvb;
    uint32_t msg_class_id, payload_len, cmp_chksum;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX");
    col_clear(pinfo->cinfo, COL_INFO);

    payload_len = tvb_get_uint16(tvb, 4, ENC_LITTLE_ENDIAN);

    proto_item *ti = proto_tree_add_item(tree, proto_ubx, tvb, 0,
            UBX_HEADER_SIZE + payload_len + UBX_CHKSUM_SIZE, ENC_NA);
    proto_tree *ubx_tree = proto_item_add_subtree(ti, ett_ubx);

    // dissect the registered fields
    proto_tree_add_item(ubx_tree, hf_ubx_preamble,
            tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(ubx_tree, hf_ubx_msg_class_id,
            tvb, 2, 2, ENC_BIG_ENDIAN, &msg_class_id);
    proto_tree_add_item(ubx_tree, hf_ubx_payload_len,
            tvb, 4, 2, ENC_LITTLE_ENDIAN);

    // checksum
    cmp_chksum = chksum_fletcher_8(
            (uint8_t *)tvb_memdup(pinfo->pool, tvb, 2, UBX_HEADER_SIZE + payload_len - 2),
            UBX_HEADER_SIZE + payload_len - 2);
    proto_tree_add_checksum(ubx_tree,
            tvb, UBX_HEADER_SIZE + payload_len,
            hf_ubx_chksum, -1, &ei_ubx_chksum, NULL, cmp_chksum,
            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);

    // send the payload to the next dissector
    next_tvb = tvb_new_subset_length(tvb, UBX_HEADER_SIZE, payload_len);
    if (!dissector_try_uint(ubx_class_id_dissector_table, msg_class_id,
                next_tvb, pinfo, tree)) {
        call_data_dissector(next_tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

/* Dissect UBX-ACK-ACK message */
static int dissect_ubx_ack_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-ACK-ACK");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_ack_ack, tvb, 0, 2, ENC_NA);
    proto_tree *ubx_ack_ack_tree = proto_item_add_subtree(ti, ett_ubx_ack_ack);

    // dissect the registered fields
    proto_tree_add_item(ubx_ack_ack_tree, hf_ubx_ack_ack_msg_class_id,
            tvb, 0, 2, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect UBX-ACK-NAK message */
static int dissect_ubx_ack_nak(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-ACK-NAK");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_ack_nak, tvb, 0, 2, ENC_NA);
    proto_tree *ubx_ack_nak_tree = proto_item_add_subtree(ti, ett_ubx_ack_nak);

    // dissect the registered fields
    proto_tree_add_item(ubx_ack_nak_tree, hf_ubx_ack_nak_msg_class_id,
            tvb, 0, 2, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect UBX-CFG-SBAS message */
static int dissect_ubx_cfg_gnss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    uint8_t i, num_config_blocks;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-CFG-GNSS");
    col_clear(pinfo->cinfo, COL_INFO);

    num_config_blocks = tvb_get_uint8(tvb, 3);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_cfg_gnss,
            tvb, 0, 4 + 8 * num_config_blocks, ENC_NA);
    proto_tree *ubx_cfg_gnss_tree = proto_item_add_subtree(ti, ett_ubx_cfg_gnss);

    // dissect the registered fields
    proto_tree_add_item(ubx_cfg_gnss_tree, hf_ubx_cfg_gnss_version,
            tvb, 0, 1, ENC_NA);
    proto_tree_add_item(ubx_cfg_gnss_tree, hf_ubx_cfg_gnss_numtrkchhw,
            tvb, 1, 1, ENC_NA);
    proto_tree_add_item(ubx_cfg_gnss_tree, hf_ubx_cfg_gnss_numtrkchuse,
            tvb, 2, 1, ENC_NA);
    proto_tree_add_item(ubx_cfg_gnss_tree, hf_ubx_cfg_gnss_numconfigblocks,
            tvb, 3, 1, ENC_NA);

    for (i = 0; i < num_config_blocks; i++) {
        const uint8_t gnss_id = tvb_get_uint8(tvb, 4 + 8 * i);
        const uint8_t res_trk_ch = tvb_get_uint8(tvb, 5 + 8 * i);
        const uint8_t max_trk_ch = tvb_get_uint8(tvb, 6 + 8 * i);

        proto_tree *gnss_blk_tree = proto_tree_add_subtree_format(ubx_cfg_gnss_tree,
                tvb, 4 + 8 * i, 8, ett_ubx_cfg_gnss_block[i], NULL,
                "%-7s (Res Trk Ch %2d, Max Trk Ch %2d)",
                val_to_str_const(gnss_id, UBX_GNSS_ID, "Unknown GNSS ID"),
                res_trk_ch, max_trk_ch);

        proto_tree_add_item(gnss_blk_tree, hf_ubx_cfg_gnss_blk_gnssid,
            tvb,  4 + 8 * i, 1, ENC_NA);
        proto_tree_add_item(gnss_blk_tree, hf_ubx_cfg_gnss_blk_restrkch,
            tvb,  5 + 8 * i, 1, ENC_NA);
        proto_tree_add_item(gnss_blk_tree, hf_ubx_cfg_gnss_blk_maxtrkch,
            tvb,  6 + 8 * i, 1, ENC_NA);
        proto_tree_add_item(gnss_blk_tree, hf_ubx_cfg_gnss_blk_reserved1,
            tvb,  7 + 8 * i, 1, ENC_NA);
        proto_tree_add_item(gnss_blk_tree, hf_ubx_cfg_gnss_blk_enable,
            tvb,  8 + 8 * i, 4, ENC_LITTLE_ENDIAN);

        int hf;
        switch (gnss_id) {
            case GNSS_ID_GPS:
                hf = hf_ubx_cfg_gnss_blk_gps_sigcfgmask;
                break;
            case GNSS_ID_SBAS:
                hf = hf_ubx_cfg_gnss_blk_sbas_sigcfgmask;
                break;
            case GNSS_ID_GALILEO:
                hf = hf_ubx_cfg_gnss_blk_gal_sigcfgmask;
                break;
            case GNSS_ID_BEIDOU:
                hf = hf_ubx_cfg_gnss_blk_bds_sigcfgmask;
                break;
            case GNSS_ID_IMES:
                hf = hf_ubx_cfg_gnss_blk_imes_sigcfgmask;
                break;
            case GNSS_ID_QZSS:
                hf = hf_ubx_cfg_gnss_blk_qzss_sigcfgmask;
                break;
            case GNSS_ID_GLONASS:
                hf = hf_ubx_cfg_gnss_blk_glo_sigcfgmask;
                break;
            default:
                hf = hf_ubx_cfg_gnss_blk_sigcfgmask;
        }
        proto_tree_add_item(gnss_blk_tree, hf,
            tvb,  8 + 8 * i, 4, ENC_LITTLE_ENDIAN);
    }

    return tvb_captured_length(tvb);
}

/* Dissect UBX-CFG-SBAS message */
static int dissect_ubx_cfg_sbas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-CFG-SBAS");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_cfg_sbas, tvb, 0, 2, ENC_NA);
    proto_tree *ubx_cfg_sbas_tree = proto_item_add_subtree(ti, ett_ubx_cfg_sbas);

    // dissect the registered fields
    proto_tree_add_bitmask(ubx_cfg_sbas_tree, tvb, 0, hf_ubx_cfg_sbas_mode,
            ett_ubx_cfg_sbas_mode, ubx_cfg_sbas_mode_fields, ENC_NA);
    proto_tree_add_item(ubx_cfg_sbas_tree, hf_ubx_cfg_sbas_usage_range,
            tvb, 1, 1, ENC_NA);
    proto_tree_add_item(ubx_cfg_sbas_tree, hf_ubx_cfg_sbas_usage_diffcorr,
            tvb, 1, 1, ENC_NA);
    proto_tree_add_item(ubx_cfg_sbas_tree, hf_ubx_cfg_sbas_usage_integrity,
            tvb, 1, 1, ENC_NA);
    proto_tree_add_item(ubx_cfg_sbas_tree, hf_ubx_cfg_sbas_max_sbas,
            tvb, 2, 1, ENC_NA);

    // scanmode bitmask
    proto_tree *scanmode_tree = proto_tree_add_subtree(ubx_cfg_sbas_tree,
            tvb, 3, 5, ett_ubx_cfg_sbas_scanmode, NULL, "Scanmode bitmask");
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn120,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn121,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn122,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn123,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn124,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn125,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn126,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn127,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn128,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn129,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn130,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn131,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn132,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn133,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn134,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn135,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn136,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn137,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn138,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn139,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn140,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn141,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn142,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn143,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn144,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn145,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn146,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn147,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn148,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn149,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn150,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn151,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn152,
            tvb, 3, 1, ENC_NA);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn153,
            tvb, 3, 1, ENC_NA);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn154,
            tvb, 3, 1, ENC_NA);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn155,
            tvb, 3, 1, ENC_NA);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn156,
            tvb, 3, 1, ENC_NA);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn157,
            tvb, 3, 1, ENC_NA);
    proto_tree_add_item(scanmode_tree, hf_ubx_cfg_sbas_scanmode_prn158,
            tvb, 3, 1, ENC_NA);

    return tvb_captured_length(tvb);
}

/* Dissect UBX-NAV-DOP message */
static int dissect_ubx_nav_dop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-NAV-DOP");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_nav_dop,
            tvb, 0, 18, ENC_NA);
    proto_tree *ubx_nav_dop_tree = proto_item_add_subtree(ti, ett_ubx_nav_dop);

    // dissect the registered fields
    proto_tree_add_item(ubx_nav_dop_tree, hf_ubx_nav_dop_itow,
            tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_dop_tree, hf_ubx_nav_dop_gdop, tvb,  4, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_dop_tree, hf_ubx_nav_dop_pdop, tvb,  6, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_dop_tree, hf_ubx_nav_dop_tdop, tvb,  8, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_dop_tree, hf_ubx_nav_dop_vdop, tvb, 10, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_dop_tree, hf_ubx_nav_dop_hdop, tvb, 12, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_dop_tree, hf_ubx_nav_dop_ndop, tvb, 14, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_dop_tree, hf_ubx_nav_dop_edop, tvb, 16, 2, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect UBX-NAV-EOE message */
static int dissect_ubx_nav_eoe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-NAV-EOE");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_nav_eoe,
            tvb, 0, 4, ENC_NA);
    proto_tree *ubx_nav_eoe_tree = proto_item_add_subtree(ti, ett_ubx_nav_eoe);

    // dissect the registered fields
    proto_tree_add_item(ubx_nav_eoe_tree, hf_ubx_nav_eoe_itow,
            tvb, 0, 4, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect UBX-NAV-ODO message */
static int dissect_ubx_nav_odo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-NAV-ODO");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_nav_odo,
            tvb, 0, 20, ENC_NA);
    proto_tree *ubx_nav_odo_tree = proto_item_add_subtree(ti, ett_ubx_nav_odo);

    // dissect the registered fields
    proto_tree_add_item(ubx_nav_odo_tree, hf_ubx_nav_odo_version,
            tvb, 0, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_odo_tree, hf_ubx_nav_odo_reserved1,
            tvb, 1, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_odo_tree, hf_ubx_nav_odo_itow,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_odo_tree, hf_ubx_nav_odo_distance,
            tvb, 8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_odo_tree, hf_ubx_nav_odo_totaldistance,
            tvb, 12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_odo_tree, hf_ubx_nav_odo_distancestd,
            tvb, 16, 4, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect UBX-NAV-POSECEF message */
static int dissect_ubx_nav_posecef(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-NAV-POSECEF");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_nav_posecef,
            tvb, 0, 20, ENC_NA);
    proto_tree *ubx_nav_posecef_tree = proto_item_add_subtree(ti, ett_ubx_nav_posecef);

    // dissect the registered fields
    proto_tree_add_item(ubx_nav_posecef_tree, hf_ubx_nav_posecef_itow,
            tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_posecef_tree, hf_ubx_nav_posecef_ecefx,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_posecef_tree, hf_ubx_nav_posecef_ecefy,
            tvb, 8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_posecef_tree, hf_ubx_nav_posecef_ecefz,
            tvb, 12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_posecef_tree, hf_ubx_nav_posecef_pacc,
            tvb, 16, 4, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect UBX-NAV-PVT message */
static int dissect_ubx_nav_pvt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-NAV-PVT");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_nav_pvt,
            tvb, 0, 92, ENC_NA);
    proto_tree *ubx_nav_pvt_tree = proto_item_add_subtree(ti, ett_ubx_nav_pvt);

    // dissect the registered fields
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_itow,
            tvb, 0, 4, ENC_LITTLE_ENDIAN);

    // dissect date & time
    uint16_t year = tvb_get_int16(tvb, 4, ENC_LITTLE_ENDIAN);
    uint8_t month = tvb_get_int8(tvb, 6);
    uint8_t day = tvb_get_int8(tvb, 7);
    uint8_t hour = tvb_get_int8(tvb, 8);
    uint8_t min = tvb_get_int8(tvb, 9);
    uint8_t sec = tvb_get_int8(tvb, 10);
    proto_tree *datetime_tree = proto_tree_add_subtree_format(ubx_nav_pvt_tree,
            tvb, 4, 7, ett_ubx_nav_pvt_datetime, NULL,
            "Date/time: %04d-%02d-%02d %02d:%02d:%02d",
            year, month, day, hour, min, sec);
    proto_tree_add_item(datetime_tree, hf_ubx_nav_pvt_year,
            tvb, 4, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(datetime_tree, hf_ubx_nav_pvt_month,
            tvb, 6, 1, ENC_NA);
    proto_tree_add_item(datetime_tree, hf_ubx_nav_pvt_day,
            tvb, 7, 1, ENC_NA);
    proto_tree_add_item(datetime_tree, hf_ubx_nav_pvt_hour,
            tvb, 8, 1, ENC_NA);
    proto_tree_add_item(datetime_tree, hf_ubx_nav_pvt_min,
            tvb, 9, 1, ENC_NA);
    proto_tree_add_item(datetime_tree, hf_ubx_nav_pvt_sec,
            tvb, 10, 1, ENC_NA);

    proto_tree_add_bitmask(ubx_nav_pvt_tree, tvb, 11, hf_ubx_nav_pvt_valid,
            ett_ubx_nav_pvt_valid, ubx_nav_pvt_valid_fields, ENC_NA);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_tacc,
            tvb, 12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_nano,
            tvb, 16, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_fixtype,
            tvb, 20, 1, ENC_NA);
    proto_tree_add_bitmask(ubx_nav_pvt_tree, tvb, 21, hf_ubx_nav_pvt_flags,
            ett_ubx_nav_pvt_flags, ubx_nav_pvt_flags_fields, ENC_NA);
    proto_tree_add_bitmask(ubx_nav_pvt_tree, tvb, 22, hf_ubx_nav_pvt_flags2,
            ett_ubx_nav_pvt_flags2, ubx_nav_pvt_flags2_fields, ENC_NA);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_numsv,
            tvb, 23, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_lon,
            tvb, 24, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_lat,
            tvb, 28, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_height,
            tvb, 32, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_hmsl,
            tvb, 36, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_hacc,
            tvb, 40, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_vacc,
            tvb, 44, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_veln,
            tvb, 48, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_vele,
            tvb, 52, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_veld,
            tvb, 56, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_gspeed,
            tvb, 60, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_headmot,
            tvb, 64, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_sacc,
            tvb, 68, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_headacc,
            tvb, 72, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_pdop,
            tvb, 76, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_invalidllh,
            tvb, 78, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_lastcorrectionage,
            tvb, 78, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_reserved1,
            tvb, 80, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_headveh,
            tvb, 84, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_magdec,
            tvb, 88, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_magacc,
            tvb, 90, 2, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect UBX-NAV-SAT message */
static int dissect_ubx_nav_sat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    uint16_t i;
    uint32_t num_svs;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-NAV-SAT");
    col_clear(pinfo->cinfo, COL_INFO);

    num_svs = tvb_get_uint8(tvb, 5);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_nav_sat,
            tvb, 0, 8 + 12 * num_svs, ENC_NA);
    proto_tree *ubx_nav_sat_tree = proto_item_add_subtree(ti, ett_ubx_nav_sat);

    // dissect the registered fields
    proto_tree_add_item(ubx_nav_sat_tree, hf_ubx_nav_sat_itow,
            tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_sat_tree, hf_ubx_nav_sat_version,
            tvb, 4, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_sat_tree, hf_ubx_nav_sat_num_svs,
            tvb, 5, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_sat_tree, hf_ubx_nav_sat_reserved1,
            tvb, 6, 2, ENC_NA);

    for (i = 0; i < num_svs; i++) {
        const uint8_t gnss_id = tvb_get_uint8(tvb, 8 + 12 * i);
        const uint8_t sv_id = tvb_get_uint8(tvb, 9 + 12 * i);
        const uint32_t used = (tvb_get_uint32(tvb, 16 + 12 * i, ENC_LITTLE_ENDIAN) & 0x0008) >> 3;

        proto_tree *sv_info_tree = proto_tree_add_subtree_format(ubx_nav_sat_tree,
                tvb, 8 + 12 * i, 12, ett_ubx_nav_sat_sv_info[i], NULL,
                "%-7s / SV ID %3d, used %d",
                val_to_str_const(gnss_id, UBX_GNSS_ID, "Unknown GNSS ID"),
                sv_id, used);

        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_gnss_id,
            tvb,  8 + 12 * i, 1, ENC_NA);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_sv_id,
            tvb,  9 + 12 * i, 1, ENC_NA);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_cn0,
            tvb, 10 + 12 * i, 1, ENC_NA);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_elev,
            tvb, 11 + 12 * i, 1, ENC_NA);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_azim,
            tvb, 12 + 12 * i, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_pr_res,
            tvb, 14 + 12 * i, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_bitmask(sv_info_tree, tvb, 16 + 12 * i,
                hf_ubx_nav_sat_flags, ett_ubx_nav_sat_flags,
                ubx_nav_sat_flags_fields, ENC_LITTLE_ENDIAN);
    }

    return tvb_captured_length(tvb);
}

/* Dissect UBX-NAV-SBAS message */
static int dissect_ubx_nav_sbas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    uint16_t i;
    uint32_t num_svs;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-NAV-SBAS");
    col_clear(pinfo->cinfo, COL_INFO);

    num_svs = tvb_get_uint8(tvb, 8);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_nav_sbas,
            tvb, 0, 12 + 12 * num_svs, ENC_NA);
    proto_tree *ubx_nav_sbas_tree = proto_item_add_subtree(ti, ett_ubx_nav_sbas);

    proto_tree_add_item(ubx_nav_sbas_tree, hf_ubx_nav_sbas_itow,
            tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_sbas_tree, hf_ubx_nav_sbas_geo,
            tvb, 4, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_sbas_tree, hf_ubx_nav_sbas_mode,
            tvb, 5, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_sbas_tree, hf_ubx_nav_sbas_sys,
            tvb, 6, 1, ENC_NA);
    proto_tree_add_bitmask(ubx_nav_sbas_tree, tvb, 7, hf_ubx_nav_sbas_service,
            ett_ubx_nav_sbas_service, ubx_nav_sbas_service_fields, ENC_NA);
    proto_tree_add_item(ubx_nav_sbas_tree, hf_ubx_nav_sbas_cnt,
            tvb, 8, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_sbas_tree, hf_ubx_nav_sbas_reserved1,
            tvb, 9, 3, ENC_LITTLE_ENDIAN);

    for (i = 0; i < num_svs; i++) {
        const uint8_t sv_id = tvb_get_uint8(tvb, 12 + 12 * i);

        proto_tree *sv_info_tree = proto_tree_add_subtree_format(ubx_nav_sbas_tree,
                tvb, 12 + 12 * i, 12, ett_ubx_nav_sbas_sv_info[i], NULL,
                "SV ID %3d", sv_id);

        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sbas_sv_id,
            tvb,  12 + 12 * i, 1, ENC_NA);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sbas_flags,
            tvb,  13 + 12 * i, 1, ENC_NA);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sbas_udre,
            tvb,  14 + 12 * i, 1, ENC_NA);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sbas_sv_sys,
            tvb,  15 + 12 * i, 1, ENC_NA);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sbas_sv_service,
            tvb,  16 + 12 * i, 1, ENC_NA);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sbas_reserved2,
            tvb,  17 + 12 * i, 1, ENC_NA);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sbas_prc,
            tvb,  18 + 12 * i, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sbas_reserved3,
            tvb,  20 + 12 * i, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sbas_ic,
            tvb,  22 + 12 * i, 2, ENC_LITTLE_ENDIAN);
    }

    return tvb_captured_length(tvb);
}

/* Dissect UBX-NAV-TIMEGPS message */
static int dissect_ubx_nav_timegps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    uint32_t itow;
    int32_t ftow;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-NAV-TIMEGPS");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_nav_timegps,
            tvb, 0, 16, ENC_NA);
    proto_tree *ubx_nav_timegps_tree = proto_item_add_subtree(ti, ett_ubx_nav_timegps);

    // dissect the registered fields
    itow = tvb_get_uint32(tvb, 0, ENC_LITTLE_ENDIAN);
    ftow = tvb_get_int32(tvb, 4, ENC_LITTLE_ENDIAN);
    ftow = (itow % 1000) * 1000000 + ftow;
    itow = itow / 1000;
    if (ftow < 0) {
        itow = itow - 1;
        ftow = 1000000000 + ftow;
    }
    proto_tree *tow_tree = proto_tree_add_subtree_format(ubx_nav_timegps_tree,
            tvb, 0, 8, ett_ubx_nav_timegps_tow, NULL, "TOW: %d.%09ds", itow, ftow);
    proto_tree_add_item(tow_tree, hf_ubx_nav_timegps_itow,
            tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tow_tree, hf_ubx_nav_timegps_ftow,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(ubx_nav_timegps_tree, hf_ubx_nav_timegps_week,
            tvb, 8, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_timegps_tree, hf_ubx_nav_timegps_leaps,
            tvb, 10, 1, ENC_NA);
    proto_tree_add_bitmask(ubx_nav_timegps_tree, tvb, 11,
            hf_ubx_nav_timegps_valid, ett_ubx_nav_timegps_valid,
            ubx_nav_timegps_valid_fields, ENC_NA);
    proto_tree_add_item(ubx_nav_timegps_tree, hf_ubx_nav_timegps_tacc,
            tvb, 12, 4, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect UBX-NAV-TIMEUTC message */
static int dissect_ubx_nav_timeutc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-NAV-TIMEUTC");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_nav_timeutc,
            tvb, 0, 20, ENC_NA);
    proto_tree *ubx_nav_timeutc_tree = proto_item_add_subtree(ti, ett_ubx_nav_timeutc);

    proto_tree_add_item(ubx_nav_timeutc_tree, hf_ubx_nav_timeutc_itow,
            tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_timeutc_tree, hf_ubx_nav_timeutc_tacc,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_timeutc_tree, hf_ubx_nav_timeutc_nano,
            tvb, 8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_timeutc_tree, hf_ubx_nav_timeutc_year,
            tvb, 12, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_timeutc_tree, hf_ubx_nav_timeutc_month,
            tvb, 14, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_timeutc_tree, hf_ubx_nav_timeutc_day,
            tvb, 15, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_timeutc_tree, hf_ubx_nav_timeutc_hour,
            tvb, 16, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_timeutc_tree, hf_ubx_nav_timeutc_min,
            tvb, 17, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_timeutc_tree, hf_ubx_nav_timeutc_sec,
            tvb, 18, 1, ENC_NA);
    proto_tree_add_bitmask(ubx_nav_timeutc_tree, tvb, 19,
            hf_ubx_nav_timeutc_valid, ett_ubx_nav_timeutc_valid,
            ubx_nav_timeutc_valid_fields, ENC_NA);

    return tvb_captured_length(tvb);
}

/* Dissect UBX-NAV-VELECEF message */
static int dissect_ubx_nav_velecef(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-NAV-VELECEF");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_nav_velecef,
            tvb, 0, 20, ENC_NA);
    proto_tree *ubx_nav_velecef_tree = proto_item_add_subtree(ti, ett_ubx_nav_velecef);

    // dissect the registered fields
    proto_tree_add_item(ubx_nav_velecef_tree, hf_ubx_nav_velecef_itow,
            tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_velecef_tree, hf_ubx_nav_velecef_ecefvx,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_velecef_tree, hf_ubx_nav_velecef_ecefvy,
            tvb, 8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_velecef_tree, hf_ubx_nav_velecef_ecefvz,
            tvb, 12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_velecef_tree, hf_ubx_nav_velecef_sacc,
            tvb, 16, 4, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect UBX-RXM-MEASX message */
static int dissect_ubx_rxm_measx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    uint32_t i, numsv;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-RXM-MEASX");
    col_clear(pinfo->cinfo, COL_INFO);

    numsv = tvb_get_uint8(tvb, 34);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_rxm_measx,
            tvb, 0, 44 + numsv * 24, ENC_NA);
    proto_tree *ubx_rxm_measx_tree = proto_item_add_subtree(ti, ett_ubx_rxm_measx);

    proto_tree_add_item(ubx_rxm_measx_tree, hf_ubx_rxm_measx_version,
            tvb, 0, 1, ENC_NA);
    proto_tree_add_item(ubx_rxm_measx_tree, hf_ubx_rxm_measx_reserved1,
            tvb, 1, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_rxm_measx_tree, hf_ubx_rxm_measx_gpstow,
            tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_rxm_measx_tree, hf_ubx_rxm_measx_glotow,
            tvb, 8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_rxm_measx_tree, hf_ubx_rxm_measx_bdstow,
            tvb, 12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_rxm_measx_tree, hf_ubx_rxm_measx_reserved2,
            tvb, 16, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_rxm_measx_tree, hf_ubx_rxm_measx_qzsstow,
            tvb, 20, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_rxm_measx_tree, hf_ubx_rxm_measx_gpstowacc,
            tvb, 24, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_rxm_measx_tree, hf_ubx_rxm_measx_glotowacc,
            tvb, 26, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_rxm_measx_tree, hf_ubx_rxm_measx_bdstowacc,
            tvb, 28, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_rxm_measx_tree, hf_ubx_rxm_measx_reserved3,
            tvb, 30, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_rxm_measx_tree, hf_ubx_rxm_measx_qzsstowacc,
            tvb, 32, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_rxm_measx_tree, hf_ubx_rxm_measx_numsv,
            tvb, 34, 1, ENC_NA);
    proto_tree_add_item(ubx_rxm_measx_tree, hf_ubx_rxm_measx_flags_towset,
            tvb, 35, 1, ENC_NA);
    proto_tree_add_item(ubx_rxm_measx_tree, hf_ubx_rxm_measx_reserved4,
            tvb, 36, 8, ENC_LITTLE_ENDIAN);

    for (i = 0; i < numsv; i++) {
        const uint8_t gnss_id = tvb_get_uint8(tvb, 44 + 24 * i);
        const uint8_t sv_id = tvb_get_uint8(tvb, 45 + 24 * i);
        const uint8_t cn0 = tvb_get_uint8(tvb, 46 + 24 * i);

        proto_tree *meas_tree = proto_tree_add_subtree_format(ubx_rxm_measx_tree,
                tvb, 44 + 24 * i, 24, ett_ubx_rxm_measx_meas[i], NULL,
                "%-7s / SV ID %3d / C/N0 %d dB-Hz",
                val_to_str_const(gnss_id, UBX_GNSS_ID, "Unknown GNSS ID"),
                sv_id, cn0);

        proto_tree_add_item(meas_tree, hf_ubx_rxm_measx_gnssid,
                tvb, 44 + 24 * i, 1, ENC_NA);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_measx_svid,
                tvb, 45 + 24 * i, 1, ENC_NA);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_measx_cn0,
                tvb, 46 + 24 * i, 1, ENC_NA);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_measx_mpathindic,
                tvb, 47 + 24 * i, 1, ENC_NA);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_measx_dopplerms,
                tvb, 48 + 24 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_measx_dopplerhz,
                tvb, 52 + 24 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_measx_wholechips,
                tvb, 56 + 24 * i, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_measx_fracchips,
                tvb, 58 + 24 * i, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_measx_codephase,
                tvb, 60 + 24 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_measx_intcodephase,
                tvb, 64 + 24 * i, 1, ENC_NA);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_measx_pseurangermserr,
                tvb, 65 + 24 * i, 1, ENC_NA);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_measx_reserved5,
                tvb, 66 + 24 * i, 2, ENC_LITTLE_ENDIAN);
    }

    return tvb_captured_length(tvb);
}

/* Dissect UBX-RXM-RAWX message */
static int dissect_ubx_rxm_rawx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    uint32_t i, nummeas;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-RXM-RAWX");
    col_clear(pinfo->cinfo, COL_INFO);

    nummeas = tvb_get_uint8(tvb, 11);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_rxm_rawx,
            tvb, 0, 16 + nummeas * 32, ENC_NA);
    proto_tree *ubx_rxm_rawx_tree = proto_item_add_subtree(ti, ett_ubx_rxm_rawx);

    proto_tree_add_item(ubx_rxm_rawx_tree, hf_ubx_rxm_rawx_rcvtow,
            tvb, 0, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_rxm_rawx_tree, hf_ubx_rxm_rawx_week,
            tvb, 8, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_rxm_rawx_tree, hf_ubx_rxm_rawx_leaps,
            tvb, 10, 1, ENC_NA);
    proto_tree_add_item(ubx_rxm_rawx_tree, hf_ubx_rxm_rawx_nummeas,
            tvb, 11, 1, ENC_NA);
    proto_tree_add_bitmask(ubx_rxm_rawx_tree, tvb, 12,
            hf_ubx_rxm_rawx_recstat, ett_ubx_rxm_rawx_recstat,
            ubx_rxm_rawx_recstat_fields, ENC_NA);
    proto_tree_add_item(ubx_rxm_rawx_tree, hf_ubx_rxm_rawx_version,
            tvb, 13, 1, ENC_NA);
    proto_tree_add_item(ubx_rxm_rawx_tree, hf_ubx_rxm_rawx_reserved1,
            tvb, 14, 2, ENC_LITTLE_ENDIAN);

    for (i = 0; i < nummeas; i++) {
        const uint8_t gnss_id = tvb_get_uint8(tvb, 36 + 32 * i);
        const uint8_t sv_id = tvb_get_uint8(tvb, 37 + 32 * i);
        const uint8_t cn0 = tvb_get_uint8(tvb, 42 + 32 * i);

        proto_tree *meas_tree = proto_tree_add_subtree_format(ubx_rxm_rawx_tree,
                tvb, 16 + 32 * i, 32, ett_ubx_rxm_rawx_meas[i], NULL,
                "%-7s / SV ID %3d / C/N0 %d dB-Hz",
                val_to_str_const(gnss_id, UBX_GNSS_ID, "Unknown GNSS ID"),
                sv_id, cn0);

        proto_tree_add_item(meas_tree, hf_ubx_rxm_rawx_prmes,
                tvb, 16 + 32 * i, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_rawx_cpmes,
                tvb, 24 + 32 * i, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_rawx_domes,
                tvb, 32 + 32 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_rawx_gnssid,
                tvb, 36 + 32 * i, 1, ENC_NA);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_rawx_svid,
                tvb, 37 + 32 * i, 1, ENC_NA);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_rawx_sigid,
                tvb, 38 + 32 * i, 1, ENC_NA);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_rawx_freqid,
                tvb, 39 + 32 * i, 1, ENC_NA);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_rawx_locktime,
                tvb, 40 + 32 * i, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_rawx_cn0,
                tvb, 42 + 32 * i, 1, ENC_NA);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_rawx_prstdev,
                tvb, 43 + 32 * i, 1, ENC_NA);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_rawx_cpstdev,
                tvb, 44 + 32 * i, 1, ENC_NA);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_rawx_dostdev,
                tvb, 45 + 32 * i, 1, ENC_NA);
        proto_tree_add_bitmask(meas_tree, tvb, 46,
                hf_ubx_rxm_rawx_trkstat, ett_ubx_rxm_rawx_trkstat,
                ubx_rxm_rawx_trkstat_fields, ENC_NA);
        proto_tree_add_item(meas_tree, hf_ubx_rxm_rawx_reserved2,
                tvb, 47 + 32 * i, 1, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

/* Dissect UBX-RXM-SFRBX message */
static int dissect_ubx_rxm_sfrbx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    tvbuff_t *next_tvb;
    uint8_t *buf;
    uint8_t i;
    uint32_t gnssid, numwords, version;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-RXM-SFRBX");
    col_clear(pinfo->cinfo, COL_INFO);

    // get length of the payload and protocol version
    numwords = tvb_get_uint8(tvb, 4);
    version = tvb_get_uint8(tvb, 6);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_rxm_sfrbx,
            tvb, 0, 8 + numwords * 4, ENC_NA);
    proto_tree *ubx_rxm_sfrbx_tree = proto_item_add_subtree(ti, ett_ubx_rxm_sfrbx);

    proto_tree_add_item_ret_uint(ubx_rxm_sfrbx_tree, hf_ubx_rxm_sfrbx_gnssid,
            tvb, 0, 1, ENC_NA, &gnssid);
    proto_tree_add_item(ubx_rxm_sfrbx_tree, hf_ubx_rxm_sfrbx_svid,
            tvb, 1, 1, ENC_NA);
    switch(version) {
        case 0x01: proto_tree_add_item(ubx_rxm_sfrbx_tree,
                           hf_ubx_rxm_sfrbx_reserved1, tvb, 2, 1, ENC_NA);
                   break;
        case 0x02: proto_tree_add_item(ubx_rxm_sfrbx_tree,
                           hf_ubx_rxm_sfrbx_sigid, tvb, 2, 1, ENC_NA);
                   break;
    }
    proto_tree_add_item(ubx_rxm_sfrbx_tree, hf_ubx_rxm_sfrbx_freqid,
            tvb, 3, 1, ENC_NA);
    proto_tree_add_item(ubx_rxm_sfrbx_tree, hf_ubx_rxm_sfrbx_numwords,
            tvb, 4, 1, ENC_NA);
    switch(version) {
        case 0x01: proto_tree_add_item(ubx_rxm_sfrbx_tree,
                           hf_ubx_rxm_sfrbx_reserved2, tvb, 5, 1, ENC_NA);
                   break;
        case 0x02: proto_tree_add_item(ubx_rxm_sfrbx_tree,
                           hf_ubx_rxm_sfrbx_chn, tvb, 5, 1, ENC_NA);
                   break;
    }
    proto_tree_add_item(ubx_rxm_sfrbx_tree, hf_ubx_rxm_sfrbx_version,
            tvb, 6, 1, ENC_NA);
    switch(version) {
        case 0x01: proto_tree_add_item(ubx_rxm_sfrbx_tree,
                           hf_ubx_rxm_sfrbx_reserved3, tvb, 7, 1, ENC_NA);
                   break;
        case 0x02: proto_tree_add_item(ubx_rxm_sfrbx_tree,
                           hf_ubx_rxm_sfrbx_reserved1, tvb, 7, 1, ENC_NA);
                   break;
    }
    proto_tree_add_item(ubx_rxm_sfrbx_tree, hf_ubx_rxm_sfrbx_dwrd,
            tvb, 8, numwords * 4, ENC_NA);

    if (gnssid == GNSS_ID_GPS) {
        // send the GPS nav msg (preprocessed by UBX) to the next dissector
        next_tvb = tvb_new_subset_length(tvb, 8, 4 * numwords);
    }
    else {
        // UBX-RXM-SFRBX has the nav msg encoded in little endian. As this is not
        // convenient for dissection, map to big endian and add as new data source.
        buf = wmem_alloc(pinfo->pool, numwords * 4);
        for (i = 0; i < numwords; i++) {
            phton32(buf + 4 * i, tvb_get_uint32(tvb, 8 + i * 4, ENC_LITTLE_ENDIAN));
        }
        next_tvb = tvb_new_child_real_data(tvb, (uint8_t *)buf, numwords * 4, numwords * 4);
        add_new_data_source(pinfo, next_tvb, "GNSS navigation message");
    }

    // send the nav msg to the next dissector
    if (!dissector_try_uint(ubx_gnssid_dissector_table, gnssid, next_tvb, pinfo, tree)) {
        call_data_dissector(next_tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

void proto_register_ubx(void) {
    static hf_register_info hf[] = {
        {&hf_ubx_preamble,
            {"Preamble", "ubx.preamble",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_msg_class_id,
            {"Msg Class & ID", "ubx.msg_class_id",
                FT_UINT16, BASE_HEX, VALS(UBX_MSG_CLASS_ID), 0x0, NULL, HFILL}},
        {&hf_ubx_payload_len,
            {"Payload Length", "ubx.payload_len",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_chksum,
            {"Checksum", "ubx.checksum",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        // ACK-ACK
        {&hf_ubx_ack_ack,
            {"UBX-ACK-ACK", "ubx.ack.ack",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_ack_ack_msg_class_id,
            {"Msg Class & ID", "ubx.ack.ack.msg_class_id",
                FT_UINT16, BASE_HEX, VALS(UBX_MSG_CLASS_ID), 0x0, NULL, HFILL}},

        // ACK-NAK
        {&hf_ubx_ack_nak,
            {"UBX-ACK-NAK", "ubx.ack.nak",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_ack_nak_msg_class_id,
            {"Msg Class & ID", "ubx.ack.nak.msg_class_id",
                FT_UINT16, BASE_HEX, VALS(UBX_MSG_CLASS_ID), 0x0, NULL, HFILL}},

        // CFG-GNSS
        {&hf_ubx_cfg_gnss,
            {"UBX-CFG-GNSS", "ubx.cfg.gnss",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_version,
            {"Version", "ubx.cfg.gnss.version",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_numtrkchhw,
            {"Number of tracking channels available in hardware", "ubx.cfg.gnss.numtrkchhw",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_numtrkchuse,
            {"Number of tracking channels to use", "ubx.cfg.gnss.numtrkchuse",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_numconfigblocks,
            {"Number of configuration blocks following", "ubx.cfg.gnss.numconfigblocks",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_blk_gnssid,
            {"GNSS ID", "ubx.cfg.gnss.gnssid",
                FT_UINT8, BASE_DEC, VALS(UBX_GNSS_ID), 0x0, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_blk_restrkch,
            {"Number of reserved (minimum) tracking channels", "ubx.cfg.gnss.restrkch",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_blk_maxtrkch,
            {"Maximum number of tracking channels", "ubx.cfg.gnss.maxtrkch",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_blk_reserved1,
            {"Reserved", "ubx.cfg.gnss.reserved1",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_blk_enable,
            {"Enabled", "ubx.cfg.gnss.enabled",
                FT_UINT32, BASE_HEX, NULL, 0x00000001, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_blk_sigcfgmask,
            {"Signal configuration mask", "ubx.cfg.gnss.sigcfgmask",
                FT_UINT32, BASE_HEX, NULL, 0x00ff0000, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_blk_gps_sigcfgmask,
            {"Signal configuration mask", "ubx.cfg.gnss.sigcfgmask",
                FT_UINT32, BASE_HEX, VALS(UBX_CFG_GNSS_GPS_SIGCFGMASK), 0x00ff0000, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_blk_sbas_sigcfgmask,
            {"Signal configuration mask", "ubx.cfg.gnss.sigcfgmask",
                FT_UINT32, BASE_HEX, VALS(UBX_CFG_GNSS_SBAS_SIGCFGMASK), 0x00ff0000, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_blk_gal_sigcfgmask,
            {"Signal configuration mask", "ubx.cfg.gnss.sigcfgmask",
                FT_UINT32, BASE_HEX, VALS(UBX_CFG_GNSS_GAL_SIGCFGMASK), 0x00ff0000, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_blk_bds_sigcfgmask,
            {"Signal configuration mask", "ubx.cfg.gnss.sigcfgmask",
                FT_UINT32, BASE_HEX, VALS(UBX_CFG_GNSS_BDS_SIGCFGMASK), 0x00ff0000, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_blk_imes_sigcfgmask,
            {"Signal configuration mask", "ubx.cfg.gnss.sigcfgmask",
                FT_UINT32, BASE_HEX, VALS(UBX_CFG_GNSS_IMES_SIGCFGMASK), 0x00ff0000, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_blk_qzss_sigcfgmask,
            {"Signal configuration mask", "ubx.cfg.gnss.sigcfgmask",
                FT_UINT32, BASE_HEX, VALS(UBX_CFG_GNSS_QZSS_SIGCFGMASK), 0x00ff0000, NULL, HFILL}},
        {&hf_ubx_cfg_gnss_blk_glo_sigcfgmask,
            {"Signal configuration mask", "ubx.cfg.gnss.sigcfgmask",
                FT_UINT32, BASE_HEX, VALS(UBX_CFG_GNSS_GLO_SIGCFGMASK), 0x00ff0000, NULL, HFILL}},

        // CFG-SBAS
        {&hf_ubx_cfg_sbas,
            {"UBX-CFG-SBAS", "ubx.cfg.sbas",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_mode,
            {"SBAS mode", "ubx.cfg.sbas.mode",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_mode_enabled,
            {"SBAS enabled", "ubx.cfg.sbas.mode.enabled",
                FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_mode_test,
            {"SBAS testbed", "ubx.cfg.sbas.mode.test",
                FT_UINT8, BASE_HEX, VALS(UBX_SBAS_TESTBED), 0x02, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_usage_range,
            {"Use SBAS GEOs as a ranging source (for navigation)", "ubx.cfg.sbas.usage.range",
                FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_usage_diffcorr,
            {"Use SBAS differential corrections", "ubx.cfg.sbas.usage.diffcorr",
                FT_UINT8, BASE_HEX, NULL, 0x02, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_usage_integrity,
            {"Use SBAS integrity information", "ubx.cfg.sbas.usage.integrity",
                FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_max_sbas,
            {"Maximum number of SBAS prioritized tracking channels to use", "ubx.cfg.sbas.maxsbas",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn158,
            {"PRN 158", "ubx.cfg.sbas.scanmode.prn158",
                FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn157,
            {"PRN 157", "ubx.cfg.sbas.scanmode.prn157",
                FT_UINT8, BASE_HEX, NULL, 0x20, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn156,
            {"PRN 156", "ubx.cfg.sbas.scanmode.prn156",
                FT_UINT8, BASE_HEX, NULL, 0x10, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn155,
            {"PRN 155", "ubx.cfg.sbas.scanmode.prn155",
                FT_UINT8, BASE_HEX, NULL, 0x08, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn154,
            {"PRN 154", "ubx.cfg.sbas.scanmode.prn154",
                FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn153,
            {"PRN 153", "ubx.cfg.sbas.scanmode.prn153",
                FT_UINT8, BASE_HEX, NULL, 0x02, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn152,
            {"PRN 152", "ubx.cfg.sbas.scanmode.prn152",
                FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn151,
            {"PRN 151", "ubx.cfg.sbas.scanmode.prn151",
                FT_UINT32, BASE_HEX, NULL, 0x80000000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn150,
            {"PRN 150", "ubx.cfg.sbas.scanmode.prn150",
                FT_UINT32, BASE_HEX, NULL, 0x40000000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn149,
            {"PRN 149", "ubx.cfg.sbas.scanmode.prn149",
                FT_UINT32, BASE_HEX, NULL, 0x20000000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn148,
            {"PRN 148", "ubx.cfg.sbas.scanmode.prn148",
                FT_UINT32, BASE_HEX, NULL, 0x10000000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn147,
            {"PRN 147", "ubx.cfg.sbas.scanmode.prn147",
                FT_UINT32, BASE_HEX, NULL, 0x08000000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn146,
            {"PRN 146", "ubx.cfg.sbas.scanmode.prn146",
                FT_UINT32, BASE_HEX, NULL, 0x04000000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn145,
            {"PRN 145", "ubx.cfg.sbas.scanmode.prn145",
                FT_UINT32, BASE_HEX, NULL, 0x02000000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn144,
            {"PRN 144", "ubx.cfg.sbas.scanmode.prn144",
                FT_UINT32, BASE_HEX, NULL, 0x01000000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn143,
            {"PRN 143", "ubx.cfg.sbas.scanmode.prn143",
                FT_UINT32, BASE_HEX, NULL, 0x00800000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn142,
            {"PRN 142", "ubx.cfg.sbas.scanmode.prn142",
                FT_UINT32, BASE_HEX, NULL, 0x00400000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn141,
            {"PRN 141", "ubx.cfg.sbas.scanmode.prn141",
                FT_UINT32, BASE_HEX, NULL, 0x00200000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn140,
            {"PRN 140", "ubx.cfg.sbas.scanmode.prn140",
                FT_UINT32, BASE_HEX, NULL, 0x00100000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn139,
            {"PRN 139", "ubx.cfg.sbas.scanmode.prn139",
                FT_UINT32, BASE_HEX, NULL, 0x00080000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn138,
            {"PRN 138", "ubx.cfg.sbas.scanmode.prn138",
                FT_UINT32, BASE_HEX, NULL, 0x00040000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn137,
            {"PRN 137", "ubx.cfg.sbas.scanmode.prn137",
                FT_UINT32, BASE_HEX, NULL, 0x00020000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn136,
            {"PRN 136", "ubx.cfg.sbas.scanmode.prn136",
                FT_UINT32, BASE_HEX, NULL, 0x00010000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn135,
            {"PRN 135", "ubx.cfg.sbas.scanmode.prn135",
                FT_UINT32, BASE_HEX, NULL, 0x00008000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn134,
            {"PRN 134", "ubx.cfg.sbas.scanmode.prn134",
                FT_UINT32, BASE_HEX, NULL, 0x00004000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn133,
            {"PRN 133", "ubx.cfg.sbas.scanmode.prn133",
                FT_UINT32, BASE_HEX, NULL, 0x00002000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn132,
            {"PRN 132", "ubx.cfg.sbas.scanmode.prn132",
                FT_UINT32, BASE_HEX, NULL, 0x00001000, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn131,
            {"PRN 131", "ubx.cfg.sbas.scanmode.prn131",
                FT_UINT32, BASE_HEX, NULL, 0x00000800, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn130,
            {"PRN 130", "ubx.cfg.sbas.scanmode.prn130",
                FT_UINT32, BASE_HEX, NULL, 0x00000400, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn129,
            {"PRN 129", "ubx.cfg.sbas.scanmode.prn129",
                FT_UINT32, BASE_HEX, NULL, 0x00000200, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn128,
            {"PRN 128", "ubx.cfg.sbas.scanmode.prn128",
                FT_UINT32, BASE_HEX, NULL, 0x00000100, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn127,
            {"PRN 127", "ubx.cfg.sbas.scanmode.prn127",
                FT_UINT32, BASE_HEX, NULL, 0x00000080, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn126,
            {"PRN 126", "ubx.cfg.sbas.scanmode.prn126",
                FT_UINT32, BASE_HEX, NULL, 0x00000040, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn125,
            {"PRN 125", "ubx.cfg.sbas.scanmode.prn125",
                FT_UINT32, BASE_HEX, NULL, 0x00000020, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn124,
            {"PRN 124", "ubx.cfg.sbas.scanmode.prn124",
                FT_UINT32, BASE_HEX, NULL, 0x00000010, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn123,
            {"PRN 123", "ubx.cfg.sbas.scanmode.prn123",
                FT_UINT32, BASE_HEX, NULL, 0x00000008, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn122,
            {"PRN 122", "ubx.cfg.sbas.scanmode.prn122",
                FT_UINT32, BASE_HEX, NULL, 0x00000004, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn121,
            {"PRN 121", "ubx.cfg.sbas.scanmode.prn121",
                FT_UINT32, BASE_HEX, NULL, 0x00000002, NULL, HFILL}},
        {&hf_ubx_cfg_sbas_scanmode_prn120,
            {"PRN 120", "ubx.cfg.sbas.scanmode.prn120",
                FT_UINT32, BASE_HEX, NULL, 0x00000001, NULL, HFILL}},

        // NAV-DOP
        {&hf_ubx_nav_dop,
            {"UBX-NAV-DOP", "ubx.nav.dop",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_dop_itow,
            {"iTOW", "ubx.nav.dop.itow",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_dop_gdop,
            {"Geometric DOP", "ubx.nav.dop.gdop",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_dop), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_dop_pdop,
            {"Position DOP", "ubx.nav.dop.pdop",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_dop), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_dop_tdop,
            {"Time DOP", "ubx.nav.dop.tdop",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_dop), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_dop_vdop,
            {"Vertical DOP", "ubx.nav.dop.vdop",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_dop), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_dop_hdop,
            {"Horizontal DOP", "ubx.nav.dop.hdop",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_dop), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_dop_ndop,
            {"Northing DOP", "ubx.nav.dop.ndop",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_dop), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_dop_edop,
            {"Easting DOP", "ubx.nav.dop.edop",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_dop), 0x0, NULL, HFILL}},

        // NAV-EOE
        {&hf_ubx_nav_eoe,
            {"UBX-NAV-EOE", "ubx.nav.eoe",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_eoe_itow,
            {"iTOW", "ubx.nav.eoe.itow",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},

        // NAV-ODO
        {&hf_ubx_nav_odo,
            {"UBX-NAV-ODO", "ubx.nav.odo",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_odo_version,
            {"Version", "ubx.nav.odo.version",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_odo_reserved1,
            {"Reserved", "ubx.nav.odo.reserved1",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_odo_itow,
            {"iTOW", "ubx.nav.odo.itow",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_odo_distance,
            {"Ground distance since last reset", "ubx.nav.odo.distance",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_meter_meters, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_odo_totaldistance,
            {"Total cumulative ground distance", "ubx.nav.odo.totaldistance",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_meter_meters, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_odo_distancestd,
            {"Ground distance accuracy (1-sigma)", "ubx.nav.odo.distancestd",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_meter_meters, 0x0, NULL, HFILL}},

        // NAV-POSECEF
        {&hf_ubx_nav_posecef,
            {"UBX-NAV-POSECEF", "ubx.nav.posecef",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_posecef_itow,
            {"iTOW", "ubx.nav.posecef.itow",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_posecef_ecefx,
            {"ECEF X coordinate", "ubx.nav.posecef.ecefx",
                FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_centimeters, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_posecef_ecefy,
            {"ECEF Y coordinate", "ubx.nav.posecef.ecefy",
                FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_centimeters, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_posecef_ecefz,
            {"ECEF Z coordinate", "ubx.nav.posecef.ecefz",
                FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_centimeters, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_posecef_pacc,
            {"Position accuracy estimate", "ubx.nav.posecef.pacc",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_centimeters, 0x0, NULL, HFILL}},

        // NAV-PVT
        {&hf_ubx_nav_pvt,
            {"UBX-NAV-PVT", "ubx.nav.pvt",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_itow,
            {"iTOW", "ubx.nav.pvt.itow",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_year,
            {"Year", "ubx.nav.pvt.year",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_month,
            {"Month", "ubx.nav.pvt.month",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_day,
            {"Day", "ubx.nav.pvt.day",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_hour,
            {"Hour", "ubx.nav.pvt.hour",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_min,
            {"Minute", "ubx.nav.pvt.min",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_sec,
            {"Seconds", "ubx.nav.pvt.sec",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_valid,
            {"Validity flags", "ubx.nav.pvt.valid",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_validmag,
            {"Valid magnetic declination", "ubx.nav.pvt.valid.validmag",
                FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}},
        {&hf_ubx_nav_pvt_fullyresolved,
            {"UTC time of day fully resolved", "ubx.nav.pvt.valid.fullyresolved",
                FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}},
        {&hf_ubx_nav_pvt_validtime,
            {"valid UTC time of day", "ubx.nav.pvt.valid.validtime",
                FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}},
        {&hf_ubx_nav_pvt_validdate,
            {"valid UTC date", "ubx.nav.pvt.valid.validdate",
                FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}},
        {&hf_ubx_nav_pvt_tacc,
            {"Time accuracy estimate", "ubx.nav.pvt.tacc",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_nanoseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_nano,
            {"UTC fraction of second", "ubx.nav.pvt.nano",
                FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_nanoseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_fixtype,
            {"GNSS fix type", "ubx.nav.pvt.fixtype",
                FT_UINT8, BASE_DEC, VALS(UBX_GNSS_FIX_TYPE), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_flags,
            {"Fix status flags", "ubx.nav.pvt.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_headvehvalid,
            {"heading of vehicle is valid", "ubx.nav.pvt.flags.headvehvalid",
                FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}},
        {&hf_ubx_nav_pvt_psmstate,
            {"PSM state", "ubx.nav.pvt.flags.psmstate",
                FT_UINT8, BASE_DEC, NULL, 0x1c, NULL, HFILL}},
        {&hf_ubx_nav_pvt_diffsoln,
            {"differential corrections were applied", "ubx.nav.pvt.flags.diffsoln",
                FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}},
        {&hf_ubx_nav_pvt_gnssfixok,
            {"valid fix", "ubx.nav.pvt.flags.gnssfixok",
                FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}},
        {&hf_ubx_nav_pvt_flags2,
            {"Additional flags", "ubx.nav.pvt.flags2",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_confirmedtime,
            {"UTC time of day could be confirmed", "ubx.nav.pvt.flags2.confirmedtime",
                FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},
        {&hf_ubx_nav_pvt_confirmeddate,
            {"UTC date could be validated", "ubx.nav.pvt.flags2.confirmeddate",
                FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}},
        {&hf_ubx_nav_pvt_confirmedavai,
            {"information about UTC date and time of day validity confirmation is available", "ubx.nav.pvt.flags2.confirmedavai",
                FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}},
        {&hf_ubx_nav_pvt_numsv,
            {"Number of satellite vehicles used in Nav solution", "ubx.nav.pvt.numsv",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_lon,
            {"Longitude", "ubx.nav.pvt.lon",
                FT_INT32, BASE_CUSTOM, CF_FUNC(&fmt_lat_lon), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_lat,
            {"Latitude", "ubx.nav.pvt.lat",
                FT_INT32, BASE_CUSTOM, CF_FUNC(&fmt_lat_lon), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_height,
            {"Height above ellipsoid", "ubx.nav.pvt.height",
                FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_millimeters, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_hmsl,
            {"Height above mean sea level", "ubx.nav.pvt.hmsl",
                FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_millimeters, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_hacc,
            {"Horizontal accuracy estimate", "ubx.nav.pvt.hacc",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_millimeters, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_vacc,
            {"Vertical accuracy estimate", "ubx.nav.pvt.vacc",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_millimeters, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_veln,
            {"NED north velocity", "ubx.nav.pvt.veln",
                FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_mm_s, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_vele,
            {"NED east velocity", "ubx.nav.pvt.vele",
                FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_mm_s, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_veld,
            {"NED down velocity", "ubx.nav.pvt.veld",
                FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_mm_s, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_gspeed,
            {"Ground speed (2-D)", "ubx.nav.pvt.gspeed",
                FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_mm_s, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_headmot,
            {"Heading of motion (2-D)", "ubx.nav.pvt.headmot",
                FT_INT32, BASE_CUSTOM, CF_FUNC(&fmt_heading), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_sacc,
            {"Speed accuracy estimate", "ubx.nav.pvt.sacc",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_mm_s, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_headacc,
            {"Heading accuracy estimate", "ubx.nav.pvt.headacc",
                FT_UINT32, BASE_CUSTOM, CF_FUNC(&fmt_heading_acc), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_pdop,
            {"Position DOP", "ubx.nav.pvt.pdop",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_dop), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_lastcorrectionage,
            {"Age of the most recently received differential correction", "ubx.nav.pvt.lastcorrectionage",
                FT_UINT16, BASE_DEC, VALS(UBX_LAST_CORRECTION_AGE), 0x001e, NULL, HFILL}},
        {&hf_ubx_nav_pvt_invalidllh,
            {"Invalid lon, lat, height, and hMSL", "ubx.nav.pvt.invalidllh",
                FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL}},
        {&hf_ubx_nav_pvt_reserved1,
            {"Reserved 1", "ubx.nav.pvt.reserved1",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_headveh,
            {"Heading of vehicle (2-D)", "ubx.nav.pvt.headveh",
                FT_INT32, BASE_CUSTOM, CF_FUNC(&fmt_heading), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_magdec,
            {"Magnetic declination", "ubx.nav.pvt.magdec",
                FT_INT16, BASE_CUSTOM, CF_FUNC(&fmt_decl), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_pvt_magacc,
            {"Magnetic declination accuracy", "ubx.nav.pvt.magacc",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_decl_acc), 0x0, NULL, HFILL}},

        // NAV-SAT
        {&hf_ubx_nav_sat,
            {"UBX-NAV-SAT", "ubx.nav.sat",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sat_itow,
            {"iTOW", "ubx.nav.sat.itow",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sat_version,
            {"Version", "ubx.nav.sat.version",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sat_num_svs,
            {"Number of satellites", "ubx.nav.sat.num_svs",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sat_reserved1,
            {"Reserved", "ubx.nav.sat.reserved1",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sat_gnss_id,
            {"GNSS ID", "ubx.nav.sat.gnss_id",
                FT_UINT8, BASE_DEC, VALS(UBX_GNSS_ID), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sat_sv_id,
            {"SV ID", "ubx.nav.sat.sv_id",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sat_cn0,
            {"C/N0", "ubx.nav.sat.cn0",
                FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_dbhz, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sat_elev,
            {"Elevation", "ubx.nav.sat.elev",
                FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sat_azim,
            {"Azimuth", "ubx.nav.sat.azim",
                FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sat_pr_res,
            {"Pseudorange residual", "ubx.nav.sat.pr_res",
                FT_INT16, BASE_CUSTOM, CF_FUNC(&fmt_pr_res), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sat_flags,
            {"Bitmask", "ubx.nav.sat.flags",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sat_quality_ind,
            {"Signal quality indicator", "ubx.nav.sat.flags.quality_ind",
                FT_UINT32, BASE_HEX, VALS(UBX_SIGNAL_QUALITY_INDICATOR), 0x00000007, NULL, HFILL}},
        {&hf_ubx_nav_sat_sv_used,
            {"Signal used for navigation", "ubx.nav.sat.flags.sv_used",
                FT_UINT32, BASE_HEX, NULL, 0x00000008, NULL, HFILL}},
        {&hf_ubx_nav_sat_health,
            {"Signal health", "ubx.nav.sat.flags.health",
                FT_UINT32, BASE_HEX, VALS(UBX_SIGNAL_HEALTH), 0x00000030, NULL, HFILL}},
        {&hf_ubx_nav_sat_diff_corr,
            {"Differential correction available", "ubx.nav.sat.flags.diff_corr",
                FT_UINT32, BASE_HEX, NULL, 0x00000040, NULL, HFILL}},
        {&hf_ubx_nav_sat_smoothed,
            {"Carrier smoothed pseudorange used", "ubx.nav.sat.flags.smoothed",
                FT_UINT32, BASE_HEX, NULL, 0x00000080, NULL, HFILL}},
        {&hf_ubx_nav_sat_orbit_src,
            {"Orbit source", "ubx.nav.sat.flags.orbit_src",
                FT_UINT32, BASE_HEX, VALS(UBX_ORBIT_SOURCE), 0x00000700, NULL, HFILL}},
        {&hf_ubx_nav_sat_eph_avail,
            {"Ephemeris available", "ubx.nav.sat.flags.eph_avail",
                FT_UINT32, BASE_HEX, NULL, 0x00000800, NULL, HFILL}},
        {&hf_ubx_nav_sat_alm_avail,
            {"Almanac available", "ubx.nav.sat.flags.alm_avail",
                FT_UINT32, BASE_HEX, NULL, 0x00001000, NULL, HFILL}},
        {&hf_ubx_nav_sat_ano_avail,
            {"AssistNow Offline data available", "ubx.nav.sat.flags.ano_avail",
                FT_UINT32, BASE_HEX, NULL, 0x00002000, NULL, HFILL}},
        {&hf_ubx_nav_sat_aop_avail,
            {"AssistNow Autonomous data available", "ubx.nav.sat.flags.aop_avail",
                FT_UINT32, BASE_HEX, NULL, 0x00004000, NULL, HFILL}},
        {&hf_ubx_nav_sat_sbas_corr_used,
            {"SBAS corrections used", "ubx.nav.sat.flags.sbas_corr_used",
                FT_UINT32, BASE_HEX, NULL, 0x00010000, NULL, HFILL}},
        {&hf_ubx_nav_sat_rtcm_corr_used,
            {"RTCM corrections used", "ubx.nav.sat.flags.rtcm_corr_used",
                FT_UINT32, BASE_HEX, NULL, 0x00020000, NULL, HFILL}},
        {&hf_ubx_nav_sat_slas_corr_used,
            {"QZSS SLAS corrections used", "ubx.nav.sat.flags.slas_corr_used",
                FT_UINT32, BASE_HEX, NULL, 0x00040000, NULL, HFILL}},
        {&hf_ubx_nav_sat_spartn_corr_used,
            {"SPARTN corrections used", "ubx.nav.sat.flags.spartn_corr_used",
                FT_UINT32, BASE_HEX, NULL, 0x00080000, NULL, HFILL}},
        {&hf_ubx_nav_sat_pr_corr_used,
            {"Pseudorange corrections used", "ubx.nav.sat.flags.pr_corr_used",
                FT_UINT32, BASE_HEX, NULL, 0x00100000, NULL, HFILL}},
        {&hf_ubx_nav_sat_cr_corr_used,
            {"Carrier range corrections used", "ubx.nav.sat.flags.cr_corr_used",
                FT_UINT32, BASE_HEX, NULL, 0x00200000, NULL, HFILL}},
        {&hf_ubx_nav_sat_do_corr_used,
            {"Range rate (Doppler) corrections used", "ubx.nav.sat.flags.do_corr_used",
                FT_UINT32, BASE_HEX, NULL, 0x00400000, NULL, HFILL}},

        // NAV-SBAS
        {&hf_ubx_nav_sbas,
            {"UBX-NAV-SBAS", "ubx.nav.sbas",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sbas_itow,
            {"iTOW", "ubx.nav.sbas.itow",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sbas_geo,
            {"GEO PRN", "ubx.nav.sbas.geo",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sbas_mode,
            {"SBAS Mode", "ubx.nav.sbas.mode",
                FT_UINT8, BASE_DEC, VALS(UBX_SBAS_MODE), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sbas_sys,
            {"SBAS System", "ubx.nav.sbas.sys",
                FT_INT8, BASE_DEC, VALS(UBX_SBAS_SYSTEM), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sbas_service,
            {"SBAS Services available", "ubx.nav.sbas.service",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sbas_service_ranging,
            {"GEO may be used as ranging source", "ubx.nav.sbas.service.ranging",
                FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}},
        {&hf_ubx_nav_sbas_service_corrections,
            {"GEO is providing correction data", "ubx.nav.sbas.service.corrections",
                FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}},
        {&hf_ubx_nav_sbas_service_integrity,
            {"GEO is providing integrity", "ubx.nav.sbas.service.integrity",
                FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}},
        {&hf_ubx_nav_sbas_service_testmode,
            {"GEO is in test mode", "ubx.nav.sbas.service.testmode",
                FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}},
        {&hf_ubx_nav_sbas_service_bad,
            {"Problem with signal or broadcast data indicated", "ubx.nav.sbas.service.bad",
                FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}},
        {&hf_ubx_nav_sbas_cnt,
            {"Number of SV data following", "ubx.nav.sbas.cnt",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sbas_reserved1,
            {"Reserved", "ubx.nav.sbas.reserved1",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sbas_sv_id,
            {"SV ID", "ubx.nav.sbas.sv_id",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sbas_flags,
            {"Flags", "ubx.nav.sbas.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sbas_udre,
            {"Monitoring status", "ubx.nav.sbas.udre",
                FT_UINT8, BASE_DEC, VALS(UDREI_EVALUATION), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sbas_sv_sys,
            {"System", "ubx.nav.sbas.sv_sys",
                FT_INT8, BASE_DEC, VALS(UBX_SBAS_SYSTEM), 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sbas_sv_service,
            {"Service", "ubx.nav.sbas.sv_service",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sbas_reserved2,
            {"Reserved", "ubx.nav.sbas.reserved2",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sbas_prc,
            {"Pseudo Range correction", "ubx.nav.sbas.prc",
                FT_INT16, BASE_DEC|BASE_UNIT_STRING, &units_centimeter_centimeters, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sbas_reserved3,
            {"Reserved", "ubx.nav.sbas.reserved3",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_sbas_ic,
            {"Ionosphere correction", "ubx.nav.sbas.ic",
                FT_INT16, BASE_DEC|BASE_UNIT_STRING, &units_centimeter_centimeters, 0x0, NULL, HFILL}},

        // NAV-TIMEGPS
        {&hf_ubx_nav_timegps,
            {"UBX-NAV-TIMEGPS", "ubx.nav.timegps",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timegps_itow,
            {"iTOW", "ubx.nav.timegps.itow",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timegps_ftow,
            {"fTOW", "ubx.nav.timegps.ftow",
                FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_nanoseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timegps_week,
            {"GPS week", "ubx.nav.timegps.week",
                FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timegps_leaps,
            {"GPS leap seconds", "ubx.nav.timegps.leaps",
                FT_INT8, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timegps_valid,
            {"Validity flags", "ubx.nav.timegps.valid",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timegps_towvalid,
            {"Valid GPS time of week", "ubx.nav.timegps.valid.towvalid",
                FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}},
        {&hf_ubx_nav_timegps_weekvalid,
            {"Valid GPS week number", "ubx.nav.timegps.valid.weekvalid",
                FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}},
        {&hf_ubx_nav_timegps_leapsvalid,
            {"Valid GPS leap seconds", "ubx.nav.timegps.valid.leapsvalid",
                FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}},
        {&hf_ubx_nav_timegps_tacc,
            {"Time accuracy estimate", "ubx.nav.timegps.tacc",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0x0, NULL, HFILL}},

        // NAV-TIMEUTC
        {&hf_ubx_nav_timeutc,
            {"UBX-NAV-TIMEUTC", "ubx.nav.timeutc",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timeutc_itow,
            {"iTOW", "ubx.nav.timeutc.itow",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timeutc_tacc,
            {"Time accuracy estimate (UTC)", "ubx.nav.timeutc.tacc",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_nanoseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timeutc_nano,
            {"Fraction of second (UTC)", "ubx.nav.timeutc.nano",
                FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_nanoseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timeutc_year,
            {"Year", "ubx.nav.timeutc.year",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timeutc_month,
            {"Month", "ubx.nav.timeutc.month",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timeutc_day,
            {"Day", "ubx.nav.timeutc.day",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timeutc_hour,
            {"Hour of day", "ubx.nav.timeutc.hour",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timeutc_min,
            {"Minute of hour", "ubx.nav.timeutc.min",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timeutc_sec,
            {"Seconds of minute", "ubx.nav.timeutc.sec",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timeutc_valid,
            {"Validity flags", "ubx.nav.timeutc.valid",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_timeutc_validtow,
            {"Valid Time of Week", "ubx.nav.timeutc.valid.validtow",
                FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}},
        {&hf_ubx_nav_timeutc_validwkn,
            {"Valid Week Number", "ubx.nav.timeutc.valid.validwkn",
                FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}},
        {&hf_ubx_nav_timeutc_validutc,
            {"Valid UTC Time", "ubx.nav.timeutc.valid.validutc",
                FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}},
        {&hf_ubx_nav_timeutc_utcstandard,
            {"utcStandard", "ubx.nav.timeutc.valid.utcstandard",
                FT_UINT8, BASE_DEC, VALS(UBX_UTC_STD_ID), 0xf0, NULL, HFILL}},

        // NAV-VELECEF
        {&hf_ubx_nav_velecef,
            {"UBX-NAV-VELECEF", "ubx.nav.velecef",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_velecef_itow,
            {"iTOW", "ubx.nav.velecef.itow",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_velecef_ecefvx,
            {"ECEF X velocity", "ubx.nav.velecef.ecefvx",
                FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_cm_s, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_velecef_ecefvy,
            {"ECEF Y velocity", "ubx.nav.velecef.ecefvy",
                FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_cm_s, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_velecef_ecefvz,
            {"ECEF Z velocity", "ubx.nav.velecef.ecefvz",
                FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_cm_s, 0x0, NULL, HFILL}},
        {&hf_ubx_nav_velecef_sacc,
            {"Speed accuracy estimate", "ubx.nav.velecef.sacc",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_cm_s, 0x0, NULL, HFILL}},

        // RXM-MEASX
        {&hf_ubx_rxm_measx,
            {"UBX-RXM-MEASX", "ubx.rxm.measx",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_version,
            {"Message version", "ubx.rxm.measx.version",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_reserved1,
            {"Reserved", "ubx.rxm.measx.reserved1",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_gpstow,
            {"GPS measurement reference time", "ubx.rxm.measx.gpstow",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_glotow,
            {"GLONASS measurement reference time", "ubx.rxm.measx.glotow",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_bdstow,
            {"BeiDou measurement reference time", "ubx.rxm.measx.bdstow",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_reserved2,
            {"Reserved", "ubx.rxm.measx.reserved2",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_qzsstow,
            {"QZSS measurement reference time", "ubx.rxm.measx.qzsstow",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_gpstowacc,
            {"GPS measurement reference time accuracy", "ubx.rxm.measx.gpstowacc",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_towacc), 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_glotowacc,
            {"GLONASS measurement reference time accuracy", "ubx.rxm.measx.glotowacc",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_towacc), 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_bdstowacc,
            {"BeiDou measurement reference time accuracy", "ubx.rxm.measx.bdstowacc",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_towacc), 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_reserved3,
            {"Reserved", "ubx.rxm.measx.reserved3",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_qzsstowacc,
            {"QZSS measurement reference time accuracy", "ubx.rxm.measx.qzsstowacc",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_towacc), 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_numsv,
            {"Number of satellites in repeated block", "ubx.rxm.measx.numsv",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_flags_towset,
            {"TOW set", "ubx.rxm.measx.flags.towset",
                FT_BOOLEAN, 2, NULL, 0x03, NULL, HFILL}},
        {&hf_ubx_rxm_measx_reserved4,
            {"Reserved", "ubx.rxm.measx.reserved4",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_gnssid,
            {"GNSS ID", "ubx.rxm.measx.gnssid",
                FT_UINT8, BASE_DEC, VALS(UBX_GNSS_ID), 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_svid,
            {"Satellite ID", "ubx.rxm.measx.svid",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_cn0,
            {"C/N0", "ubx.rxm.measx.cn0",
                FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_dbhz, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_mpathindic,
            {"multipath index", "ubx.rxm.measx.mpathindic",
                FT_UINT8, BASE_DEC, VALS(UBX_RXM_MEASX_MULTIPATH_INDEX), 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_dopplerms,
            {"Doppler measurement", "ubx.rxm.measx.dopplerms",
                FT_INT32, BASE_CUSTOM, CF_FUNC(&fmt_dopplerms), 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_dopplerhz,
            {"Doppler measurement", "ubx.rxm.measx.dopplerhz",
                FT_INT32, BASE_CUSTOM, CF_FUNC(&fmt_dopplerhz), 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_wholechips,
            {"whole value of the code phase measurement", "ubx.rxm.measx.wholechips",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_fracchips,
            {"fractional value of the code phase measurement", "ubx.rxm.measx.fracchips",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_codephase,
            {"Code phase", "ubx.rxm.measx.codephase",
                FT_UINT32, BASE_CUSTOM, CF_FUNC(&fmt_codephase), 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_intcodephase,
            {"integer (part of) the code phase", "ubx.rxm.measx.intcodephase",
                FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_pseurangermserr,
            {"pseudorange RMS error index", "ubx.rxm.measx.pseurangermserr",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_measx_reserved5,
            {"Reserved", "ubx.rxm.measx.reserved5",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        // RXM-RAWX
        {&hf_ubx_rxm_rawx,
            {"UBX-RXM-RAWX", "ubx.rxm.rawx",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_rcvtow,
            {"Measurement time of week in receiver local time", "ubx.rxm.rawx.rcvtow",
                FT_DOUBLE, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_week,
            {"GPS week number in receiver local time", "ubx.rxm.rawx.week",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_leaps,
            {"GPS leap seconds", "ubx.rxm.rawx.leaps",
                FT_INT8, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_nummeas,
            {"Number of measurements to follow", "ubx.rxm.rawx.nummeas",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_recstat,
            {"Receiver tracking status bitfield", "ubx.rxm.rawx.recstat",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_recstat_leapsec,
            {"Leap seconds have been determined", "ubx.rxm.rawx.recstat.leapsec",
                FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_recstat_clkreset,
            {"Clock reset applied", "ubx.rxm.rawx.recstat.clkreset",
                FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_version,
            {"Message version", "ubx.rxm.rawx.version",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_reserved1,
            {"Reserved", "ubx.rxm.rawx.reserved1",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_prmes,
            {"Pseudorange measurement", "ubx.rxm.rawx.prmes",
                FT_DOUBLE, BASE_DEC|BASE_UNIT_STRING, &units_meter_meters, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_cpmes,
            {"Carrier phase measurement", "ubx.rxm.rawx.cpmes",
                FT_DOUBLE, BASE_DEC|BASE_UNIT_STRING, &units_cycle_cycles, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_domes,
            {"Doppler measurement", "ubx.rxm.rawx.domes",
                FT_FLOAT, BASE_DEC|BASE_UNIT_STRING, &units_hz, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_gnssid,
            {"GNSS ID", "ubx.rxm.rawx.gnssid",
                FT_UINT8, BASE_DEC, VALS(UBX_GNSS_ID), 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_svid,
            {"Satellite ID", "ubx.rxm.rawx.svid",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_sigid,
            {"Signal ID", "ubx.rxm.rawx.sigid",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_freqid,
            {"Frequency ID", "ubx.rxm.rawx.freqid",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_locktime,
            {"Carrier phase locktime counter", "ubx.rxm.rawx.locktime",
                FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_cn0,
            {"C/N0", "ubx.rxm.rawx.cn0",
                FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_dbhz, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_prstdev,
            {"Estimated pseudorange measurement standard deviation", "ubx.rxm.rawx.prstdev",
                FT_UINT8, BASE_CUSTOM, CF_FUNC(&fmt_prstdev), 0x0f, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_cpstdev,
            {"Estimated carrier phase measurement standard deviation", "ubx.rxm.rawx.cpstdev",
                FT_UINT8, BASE_CUSTOM, CF_FUNC(&fmt_cpstdev), 0x0f, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_dostdev,
            {"Estimated Doppler measurement standard deviation", "ubx.rxm.rawx.dostdev",
                FT_UINT8, BASE_CUSTOM, CF_FUNC(&fmt_dostdev), 0x0f, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_trkstat,
            {"Tracking status bitfield", "ubx.rxm.rawx.trkstat",
                FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_trkstat_prvalid,
            {"Pseudorange valid", "ubx.rxm.rawx.trkstat.prvalid",
                FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_trkstat_cpvalid,
            {"Carrier phase valid", "ubx.rxm.rawx.trkstat.cpvalid",
                FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_trkstat_halfcyc,
            {"Half cycle valid", "ubx.rxm.rawx.trkstat.halfcyc",
                FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_trkstat_subhalfcyc,
            {"Half cycle subtracted from phase", "ubx.rxm.rawx.trkstat.subhalfcyc",
                FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}},
        {&hf_ubx_rxm_rawx_reserved2,
            {"Reserved", "ubx.rxm.rawx.reserved2",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        // RXM-SFRBX
        {&hf_ubx_rxm_sfrbx,
            {"UBX-RXM-SFRBX", "ubx.rxm.sfrbx",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_sfrbx_gnssid,
            {"GNSS ID", "ubx.rxm.sfrbx.gnssid",
                FT_UINT8, BASE_DEC, VALS(UBX_GNSS_ID), 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_sfrbx_svid,
            {"Satellite ID", "ubx.rxm.sfrbx.svid",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_sfrbx_sigid,
            {"Signal identifier", "ubx.rxm.sfrbx.sigid",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_sfrbx_freqid,
            {"Frequency identifier", "ubx.rxm.sfrbx.freqid",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_sfrbx_numwords,
            {"Number of data words", "ubx.rxm.sfrbx.numwords",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_sfrbx_chn,
            {"Tracking channel number", "ubx.rxm.sfrbx.chn",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_sfrbx_version,
            {"Message version", "ubx.rxm.sfrbx.version",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_sfrbx_dwrd,
            {"Data words (little endian)", "ubx.rxm.sfrbx.dwrd",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_sfrbx_reserved1,
            {"Reserved 1", "ubx.rxm.sfrbx.reserved1",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_sfrbx_reserved2,
            {"Reserved 2", "ubx.rxm.sfrbx.reserved2",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_ubx_rxm_sfrbx_reserved3,
            {"Reserved 3", "ubx.rxm.sfrbx.reserved3",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    };

    expert_module_t *expert_ubx;

    static ei_register_info ei[] = {
        {&ei_ubx_chksum, {"ubx.chksum", PI_CHECKSUM, PI_WARN, "Chksum", EXPFILL}},
    };

    static int *ett_part[] = {
        &ett_ubx,
        &ett_ubx_ack_ack,
        &ett_ubx_ack_nak,
        &ett_ubx_cfg_gnss,
        &ett_ubx_cfg_sbas,
        &ett_ubx_cfg_sbas_mode,
        &ett_ubx_cfg_sbas_scanmode,
        &ett_ubx_nav_dop,
        &ett_ubx_nav_eoe,
        &ett_ubx_nav_odo,
        &ett_ubx_nav_posecef,
        &ett_ubx_nav_pvt,
        &ett_ubx_nav_pvt_datetime,
        &ett_ubx_nav_pvt_valid,
        &ett_ubx_nav_pvt_flags,
        &ett_ubx_nav_pvt_flags2,
        &ett_ubx_nav_sat,
        &ett_ubx_nav_sat_flags,
        &ett_ubx_nav_sbas,
        &ett_ubx_nav_sbas_service,
        &ett_ubx_nav_timegps,
        &ett_ubx_nav_timegps_tow,
        &ett_ubx_nav_timegps_valid,
        &ett_ubx_nav_timeutc,
        &ett_ubx_nav_timeutc_valid,
        &ett_ubx_nav_velecef,
        &ett_ubx_rxm_measx,
        &ett_ubx_rxm_rawx,
        &ett_ubx_rxm_rawx_recstat,
        &ett_ubx_rxm_rawx_trkstat,
        &ett_ubx_rxm_sfrbx,
    };

    static int *ett[array_length(ett_part)
        + array_length(ett_ubx_nav_sat_sv_info)
        + array_length(ett_ubx_cfg_gnss_block)
        + array_length(ett_ubx_nav_sbas_sv_info)
        + array_length(ett_ubx_rxm_rawx_meas)
        + array_length(ett_ubx_rxm_measx_meas)];

    // fill ett with elements from ett_part,
    // pointers to ett_ubx_nav_sat_sv_info elements,
    // pointers to ett_ubx_cfg_gnss_block elements,
    // pointers to ett_ubx_nav_sbas_sv_info elements,
    // pointers to ett_ubx_rxm_rawx_meas elements, and
    // pointers to ett_ubx_rxm_measx_meas elements
    uint16_t i;
    for (i = 0; i < array_length(ett_part); i++) {
        ett[i] = ett_part[i];
    }
    for (i = 0; i < array_length(ett_ubx_nav_sat_sv_info); i++) {
        ett[i + array_length(ett_part)] = &ett_ubx_nav_sat_sv_info[i];
    }
    for (i = 0; i < array_length(ett_ubx_cfg_gnss_block); i++) {
        ett[i + array_length(ett_part) + array_length(ett_ubx_nav_sat_sv_info)]
            = &ett_ubx_cfg_gnss_block[i];
    }
    for (i = 0; i < array_length(ett_ubx_nav_sbas_sv_info); i++) {
        ett[i + array_length(ett_part) + array_length(ett_ubx_nav_sat_sv_info)
            + array_length(ett_ubx_cfg_gnss_block)]
            = &ett_ubx_nav_sbas_sv_info[i];
    }
    for (i = 0; i < array_length(ett_ubx_rxm_rawx_meas); i++) {
        ett[i + array_length(ett_part) + array_length(ett_ubx_nav_sat_sv_info)
            + array_length(ett_ubx_cfg_gnss_block)
            + array_length(ett_ubx_nav_sbas_sv_info)]
            = &ett_ubx_rxm_rawx_meas[i];
    }
    for (i = 0; i < array_length(ett_ubx_rxm_measx_meas); i++) {
        ett[i + array_length(ett_part) + array_length(ett_ubx_nav_sat_sv_info)
            + array_length(ett_ubx_cfg_gnss_block)
            + array_length(ett_ubx_nav_sbas_sv_info)
            + array_length(ett_ubx_rxm_rawx_meas)]
            = &ett_ubx_rxm_measx_meas[i];
    }

    proto_ubx = proto_register_protocol("UBX Protocol", "UBX", "ubx");

    ubx_handle = register_dissector("ubx", dissect_ubx, proto_ubx);

    proto_register_field_array(proto_ubx, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_ubx = expert_register_protocol(proto_ubx);
    expert_register_field_array(expert_ubx, ei, array_length(ei));

    ubx_class_id_dissector_table = register_dissector_table("ubx.msg_class_id",
            "UBX Message Class & ID", proto_ubx, FT_UINT16, BASE_HEX);
    ubx_gnssid_dissector_table = register_dissector_table("ubx.rxm.sfrbx.gnssid",
            "UBX-RXM-SFRBX GNSS Type ID", proto_ubx,
            FT_UINT8, BASE_DEC);
}

void proto_reg_handoff_ubx(void) {
    UBX_REGISTER_DISSECTOR(dissect_ubx_ack_ack,     UBX_ACK_ACK);
    UBX_REGISTER_DISSECTOR(dissect_ubx_ack_nak,     UBX_ACK_NAK);
    UBX_REGISTER_DISSECTOR(dissect_ubx_cfg_gnss,    UBX_CFG_GNSS);
    UBX_REGISTER_DISSECTOR(dissect_ubx_cfg_sbas,    UBX_CFG_SBAS);
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_dop,     UBX_NAV_DOP);
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_eoe,     UBX_NAV_EOE);
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_odo,     UBX_NAV_ODO);
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_posecef, UBX_NAV_POSECEF);
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_pvt,     UBX_NAV_PVT);
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_sat,     UBX_NAV_SAT);
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_sbas,    UBX_NAV_SBAS);
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_timegps, UBX_NAV_TIMEGPS);
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_timeutc, UBX_NAV_TIMEUTC);
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_velecef, UBX_NAV_VELECEF);
    UBX_REGISTER_DISSECTOR(dissect_ubx_rxm_measx,   UBX_RXM_MEASX);
    UBX_REGISTER_DISSECTOR(dissect_ubx_rxm_rawx,    UBX_RXM_RAWX);
    UBX_REGISTER_DISSECTOR(dissect_ubx_rxm_sfrbx,   UBX_RXM_SFRBX);
}
