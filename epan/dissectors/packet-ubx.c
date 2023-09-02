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

/* mapping UBX GNSS IDs to constellation name */
static const value_string UBX_GNSS_ID[] = {
    {0, "GPS"},
    {1, "SBAS"},
    {2, "Galileo"},
    {3, "Beidou"},
    {4, "IMES"},
    {5, "QZSS"},
    {6, "Glonass"},
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

/* Initialize the protocol and registered fields */
static int proto_ubx = -1;

static int hf_ubx_preamble      = -1;
static int hf_ubx_msg_class_id  = -1;
static int hf_ubx_payload_len   = -1;
static int hf_ubx_chksum        = -1;

static int hf_ubx_nav_dop      = -1;
static int hf_ubx_nav_dop_itow = -1;
static int hf_ubx_nav_dop_gdop = -1;
static int hf_ubx_nav_dop_pdop = -1;
static int hf_ubx_nav_dop_tdop = -1;
static int hf_ubx_nav_dop_vdop = -1;
static int hf_ubx_nav_dop_hdop = -1;
static int hf_ubx_nav_dop_ndop = -1;
static int hf_ubx_nav_dop_edop = -1;

static int hf_ubx_nav_eoe      = -1;
static int hf_ubx_nav_eoe_itow = -1;

static int hf_ubx_nav_posecef       = -1;
static int hf_ubx_nav_posecef_itow  = -1;
static int hf_ubx_nav_posecef_ecefx = -1;
static int hf_ubx_nav_posecef_ecefy = -1;
static int hf_ubx_nav_posecef_ecefz = -1;
static int hf_ubx_nav_posecef_pacc  = -1;

static int hf_ubx_nav_pvt                   = -1;
static int hf_ubx_nav_pvt_itow              = -1;
static int hf_ubx_nav_pvt_year              = -1;
static int hf_ubx_nav_pvt_month             = -1;
static int hf_ubx_nav_pvt_day               = -1;
static int hf_ubx_nav_pvt_hour              = -1;
static int hf_ubx_nav_pvt_min               = -1;
static int hf_ubx_nav_pvt_sec               = -1;
static int hf_ubx_nav_pvt_validmag          = -1;
static int hf_ubx_nav_pvt_fullyresolved     = -1;
static int hf_ubx_nav_pvt_validtime         = -1;
static int hf_ubx_nav_pvt_validdate         = -1;
static int hf_ubx_nav_pvt_tacc              = -1;
static int hf_ubx_nav_pvt_nano              = -1;
static int hf_ubx_nav_pvt_fixtype           = -1;
static int hf_ubx_nav_pvt_headvehvalid      = -1;
static int hf_ubx_nav_pvt_psmstate          = -1;
static int hf_ubx_nav_pvt_diffsoln          = -1;
static int hf_ubx_nav_pvt_gnssfixok         = -1;
static int hf_ubx_nav_pvt_confirmedtime     = -1;
static int hf_ubx_nav_pvt_confirmeddate     = -1;
static int hf_ubx_nav_pvt_confirmedavai     = -1;
static int hf_ubx_nav_pvt_numsv             = -1;
static int hf_ubx_nav_pvt_lon               = -1;
static int hf_ubx_nav_pvt_lat               = -1;
static int hf_ubx_nav_pvt_height            = -1;
static int hf_ubx_nav_pvt_hmsl              = -1;
static int hf_ubx_nav_pvt_hacc              = -1;
static int hf_ubx_nav_pvt_vacc              = -1;
static int hf_ubx_nav_pvt_veln              = -1;
static int hf_ubx_nav_pvt_vele              = -1;
static int hf_ubx_nav_pvt_veld              = -1;
static int hf_ubx_nav_pvt_gspeed            = -1;
static int hf_ubx_nav_pvt_headmot           = -1;
static int hf_ubx_nav_pvt_sacc              = -1;
static int hf_ubx_nav_pvt_headacc           = -1;
static int hf_ubx_nav_pvt_pdop              = -1;
static int hf_ubx_nav_pvt_lastcorrectionage = -1;
static int hf_ubx_nav_pvt_invalidllh        = -1;
static int hf_ubx_nav_pvt_reserved1         = -1;
static int hf_ubx_nav_pvt_headveh           = -1;
static int hf_ubx_nav_pvt_magdec            = -1;
static int hf_ubx_nav_pvt_magacc            = -1;

static int hf_ubx_nav_sat                  = -1;
static int hf_ubx_nav_sat_itow             = -1;
static int hf_ubx_nav_sat_version          = -1;
static int hf_ubx_nav_sat_num_svs          = -1;
static int hf_ubx_nav_sat_reserved1        = -1;
static int hf_ubx_nav_sat_gnss_id          = -1;
static int hf_ubx_nav_sat_sv_id            = -1;
static int hf_ubx_nav_sat_cn0              = -1;
static int hf_ubx_nav_sat_elev             = -1;
static int hf_ubx_nav_sat_azim             = -1;
static int hf_ubx_nav_sat_pr_res           = -1;
static int hf_ubx_nav_sat_quality_ind      = -1;
static int hf_ubx_nav_sat_sv_used          = -1;
static int hf_ubx_nav_sat_health           = -1;
static int hf_ubx_nav_sat_diff_corr        = -1;
static int hf_ubx_nav_sat_smoothed         = -1;
static int hf_ubx_nav_sat_orbit_src        = -1;
static int hf_ubx_nav_sat_eph_avail        = -1;
static int hf_ubx_nav_sat_alm_avail        = -1;
static int hf_ubx_nav_sat_ano_avail        = -1;
static int hf_ubx_nav_sat_aop_avail        = -1;
static int hf_ubx_nav_sat_sbas_corr_used   = -1;
static int hf_ubx_nav_sat_rtcm_corr_used   = -1;
static int hf_ubx_nav_sat_slas_corr_used   = -1;
static int hf_ubx_nav_sat_spartn_corr_used = -1;
static int hf_ubx_nav_sat_pr_corr_used     = -1;
static int hf_ubx_nav_sat_cr_corr_used     = -1;
static int hf_ubx_nav_sat_do_corr_used     = -1;
static int hf_ubx_nav_sat_clas_corr_used   = -1;

static int hf_ubx_nav_timegps            = -1;
static int hf_ubx_nav_timegps_itow       = -1;
static int hf_ubx_nav_timegps_ftow       = -1;
static int hf_ubx_nav_timegps_week       = -1;
static int hf_ubx_nav_timegps_leaps      = -1;
static int hf_ubx_nav_timegps_leapsvalid = -1;
static int hf_ubx_nav_timegps_weekvalid  = -1;
static int hf_ubx_nav_timegps_towvalid   = -1;
static int hf_ubx_nav_timegps_tacc       = -1;

static int hf_ubx_nav_velecef        = -1;
static int hf_ubx_nav_velecef_itow   = -1;
static int hf_ubx_nav_velecef_ecefvx = -1;
static int hf_ubx_nav_velecef_ecefvy = -1;
static int hf_ubx_nav_velecef_ecefvz = -1;
static int hf_ubx_nav_velecef_sacc   = -1;

static int hf_ubx_rxm_sfrbx           = -1;
static int hf_ubx_rxm_sfrbx_gnssid    = -1;
static int hf_ubx_rxm_sfrbx_svid      = -1;
static int hf_ubx_rxm_sfrbx_sigid     = -1;
static int hf_ubx_rxm_sfrbx_freqid    = -1;
static int hf_ubx_rxm_sfrbx_numwords  = -1;
static int hf_ubx_rxm_sfrbx_chn       = -1;
static int hf_ubx_rxm_sfrbx_version   = -1;
static int hf_ubx_rxm_sfrbx_dwrd      = -1;
static int hf_ubx_rxm_sfrbx_reserved1 = -1;
static int hf_ubx_rxm_sfrbx_reserved2 = -1;
static int hf_ubx_rxm_sfrbx_reserved3 = -1;

static dissector_table_t ubx_class_id_dissector_table;
static dissector_table_t ubx_gnssid_dissector_table;

static expert_field ei_ubx_chksum = EI_INIT;

static int ett_ubx                   = -1;
static int ett_ubx_nav_dop           = -1;
static int ett_ubx_nav_eoe           = -1;
static int ett_ubx_nav_posecef       = -1;
static int ett_ubx_nav_pvt           = -1;
static int ett_ubx_nav_pvt_datetime  = -1;
static int ett_ubx_nav_sat           = -1;
static int ett_ubx_nav_sat_sv_info[] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};
static int ett_ubx_nav_timegps       = -1;
static int ett_ubx_nav_timegps_tow   = -1;
static int ett_ubx_nav_velecef       = -1;
static int ett_ubx_rxm_sfrbx = -1;

static dissector_handle_t ubx_handle;

/* compute the checksum for a UBX message (Fletcher 8-bit by RFC 1145 */
static guint16 chksum_fletcher_8(const guint8 *data, const gint len) {
    guint8 ck_a = 0, ck_b = 0;
    gint i;

    for (i = 0; i < len; i++) {
        ck_a += data[i];
        ck_b += ck_a;
    }

    return (ck_b << 8) | ck_a;
}

/* Format magnetic declination */
static void fmt_decl(gchar *label, gint32 d) {
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
static void fmt_decl_acc(gchar *label, guint32 a) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d.%02d%s", a / 100,
            a % 100, UTF8_DEGREE_SIGN);
}

/* Format Dillution of Precision */
static void fmt_dop(gchar *label, guint32 dop) {
    snprintf(label, ITEM_LABEL_LENGTH, "%i.%02i", dop / 100, dop % 100);
}

/* Format heading */
static void fmt_heading(gchar *label, gint32 h) {
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
static void fmt_heading_acc(gchar *label, guint32 a) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d.%05d%s", a / 100000,
            a % 100000, UTF8_DEGREE_SIGN);
}

/* Format latitude or longitude */
static void fmt_lat_lon(gchar *label, gint32 l) {
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
static void fmt_pr_res(gchar *label, gint32 p) {
    if (p >= 0) {
        snprintf(label, ITEM_LABEL_LENGTH, "%d.%01dm", p / 10, p % 10);
    }
    else {
        snprintf(label, ITEM_LABEL_LENGTH, "-%d.%01dm", -p / 10, -p % 10);
    }
}

/* Dissect UBX message */
static int dissect_ubx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    tvbuff_t *next_tvb;
    guint32 msg_class_id, payload_len, cmp_chksum;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX");
    col_clear(pinfo->cinfo, COL_INFO);

    payload_len = tvb_get_guint16(tvb, 4, ENC_LITTLE_ENDIAN);

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
            (guint8 *)tvb_memdup(pinfo->pool, tvb, 2, UBX_HEADER_SIZE + payload_len - 2),
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
    guint16 year = tvb_get_gint16(tvb, 4, ENC_LITTLE_ENDIAN);
    guint8 month = tvb_get_gint8(tvb, 6);
    guint8 day = tvb_get_gint8(tvb, 7);
    guint8 hour = tvb_get_gint8(tvb, 8);
    guint8 min = tvb_get_gint8(tvb, 9);
    guint8 sec = tvb_get_gint8(tvb, 10);
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

    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_validdate,
            tvb, 11, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_validtime,
            tvb, 11, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_fullyresolved,
            tvb, 11, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_validmag,
            tvb, 11, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_tacc,
            tvb, 12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_nano,
            tvb, 16, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_fixtype,
            tvb, 20, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_gnssfixok,
            tvb, 21, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_diffsoln,
            tvb, 21, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_psmstate,
            tvb, 21, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_headvehvalid,
            tvb, 21, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_confirmedavai,
            tvb, 22, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_confirmeddate,
            tvb, 22, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_pvt_tree, hf_ubx_nav_pvt_confirmedtime,
            tvb, 22, 1, ENC_NA);
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
    guint16 i;
    guint32 num_svs;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-NAV-SAT");
    col_clear(pinfo->cinfo, COL_INFO);

    num_svs = tvb_get_guint8(tvb, 5);

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
        const guint8 gnss_id = tvb_get_guint8(tvb, 8 + 12 * i);
        const guint8 sv_id = tvb_get_guint8(tvb, 9 + 12 * i);
        const guint32 used = (tvb_get_guint32(tvb, 16 + 12 * i, ENC_LITTLE_ENDIAN) & 0x0008) >> 3;

        proto_tree *sv_info_tree = proto_tree_add_subtree_format(ubx_nav_sat_tree,
                tvb, 8 + 12 * i, 9, ett_ubx_nav_sat_sv_info[i], NULL,
                "GNSS ID %d, SV ID %3d, used %d", gnss_id, sv_id, used);

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
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_quality_ind,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_sv_used,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_health,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_diff_corr,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_smoothed,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_orbit_src,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_eph_avail,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_alm_avail,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_ano_avail,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_aop_avail,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_sbas_corr_used,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_rtcm_corr_used,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_slas_corr_used,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_spartn_corr_used,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_pr_corr_used,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_cr_corr_used,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_do_corr_used,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sv_info_tree, hf_ubx_nav_sat_clas_corr_used,
            tvb, 16 + 12 * i, 4, ENC_LITTLE_ENDIAN);
    }

    return tvb_captured_length(tvb);
}

/* Dissect UBX-NAV-TIMEGPS message */
static int dissect_ubx_nav_timegps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    guint32 itow;
    gint32 ftow;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-NAV-TIMEGPS");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_nav_timegps,
            tvb, 0, 16, ENC_NA);
    proto_tree *ubx_nav_timegps_tree = proto_item_add_subtree(ti, ett_ubx_nav_timegps);

    // dissect the registered fields
    itow = tvb_get_guint32(tvb, 0, ENC_LITTLE_ENDIAN);
    ftow = tvb_get_gint32(tvb, 4, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(ubx_nav_timegps_tree, hf_ubx_nav_timegps_towvalid,
            tvb, 11, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_timegps_tree, hf_ubx_nav_timegps_weekvalid,
            tvb, 11, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_timegps_tree, hf_ubx_nav_timegps_leapsvalid,
            tvb, 11, 1, ENC_NA);
    proto_tree_add_item(ubx_nav_timegps_tree, hf_ubx_nav_timegps_tacc,
            tvb, 12, 4, ENC_LITTLE_ENDIAN);

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

/* Dissect UBX-RXM-SFRBX message */
static int dissect_ubx_rxm_sfrbx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    tvbuff_t *next_tvb;
    guint8 *buf;
    guint8 i;
    guint32 gnssid, numwords, version;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBX-RXM-SFRBX");
    col_clear(pinfo->cinfo, COL_INFO);

    // get length of the payload and protocol version
    numwords = tvb_get_guint8(tvb, 4);
    version = tvb_get_guint8(tvb, 6);

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
            phton32(buf + 4 * i, tvb_get_guint32(tvb, 8 + i * 4, ENC_LITTLE_ENDIAN));
        }
        next_tvb = tvb_new_child_real_data(tvb, (guint8 *)buf, numwords * 4, numwords * 4);
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
        {&hf_ubx_nav_pvt_validmag,
            {"Valid magnetic declination", "ubx.nav.pvt.validmag",
                FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}},
        {&hf_ubx_nav_pvt_fullyresolved,
            {"UTC time of day fully resolved", "ubx.nav.pvt.fullyresolved",
                FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}},
        {&hf_ubx_nav_pvt_validtime,
            {"valid UTC time of day", "ubx.nav.pvt.validtime",
                FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}},
        {&hf_ubx_nav_pvt_validdate,
            {"valid UTC date", "ubx.nav.pvt.validdate",
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
        {&hf_ubx_nav_pvt_headvehvalid,
            {"heading of vehicle is valid", "ubx.nav.pvt.headvehvalid",
                FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}},
        {&hf_ubx_nav_pvt_psmstate,
            {"PSM state", "ubx.nav.pvt.psmstate",
                FT_UINT8, BASE_DEC, NULL, 0x1c, NULL, HFILL}},
        {&hf_ubx_nav_pvt_diffsoln,
            {"differential corrections were applied", "ubx.nav.pvt.diffsoln",
                FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}},
        {&hf_ubx_nav_pvt_gnssfixok,
            {"valid fix", "ubx.nav.pvt.gnssfixok",
                FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}},
        {&hf_ubx_nav_pvt_confirmedtime,
            {"UTC time of day could be confirmed", "ubx.nav.pvt.confirmedtime",
                FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},
        {&hf_ubx_nav_pvt_confirmeddate,
            {"UTC date could be validated", "ubx.nav.pvt.confirmeddate",
                FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}},
        {&hf_ubx_nav_pvt_confirmedavai,
            {"information about UTC date and time of day validity confirmation is available", "ubx.nav.pvt.confirmedavai",
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
        {&hf_ubx_nav_sat_quality_ind,
            {"Signal quality indicator", "ubx.nav.sat.quality_ind",
                FT_UINT32, BASE_HEX, VALS(UBX_SIGNAL_QUALITY_INDICATOR), 0x00000007, NULL, HFILL}},
        {&hf_ubx_nav_sat_sv_used,
            {"Signal used for navigation", "ubx.nav.sat.sv_used",
                FT_UINT32, BASE_HEX, NULL, 0x00000008, NULL, HFILL}},
        {&hf_ubx_nav_sat_health,
            {"Signal health", "ubx.nav.sat.health",
                FT_UINT32, BASE_HEX, VALS(UBX_SIGNAL_HEALTH), 0x00000030, NULL, HFILL}},
        {&hf_ubx_nav_sat_diff_corr,
            {"Differential correction available", "ubx.nav.sat.diff_corr",
                FT_UINT32, BASE_HEX, NULL, 0x00000040, NULL, HFILL}},
        {&hf_ubx_nav_sat_smoothed,
            {"Carrier smoothed pseudorange used", "ubx.nav.sat.smoothed",
                FT_UINT32, BASE_HEX, NULL, 0x00000080, NULL, HFILL}},
        {&hf_ubx_nav_sat_orbit_src,
            {"Orbit source", "ubx.nav.sat.orbit_src",
                FT_UINT32, BASE_HEX, VALS(UBX_ORBIT_SOURCE), 0x00000700, NULL, HFILL}},
        {&hf_ubx_nav_sat_eph_avail,
            {"Ephemeris available", "ubx.nav.sat.eph_avail",
                FT_UINT32, BASE_HEX, NULL, 0x00000800, NULL, HFILL}},
        {&hf_ubx_nav_sat_alm_avail,
            {"Almanac available", "ubx.nav.sat.alm_avail",
                FT_UINT32, BASE_HEX, NULL, 0x00001000, NULL, HFILL}},
        {&hf_ubx_nav_sat_ano_avail,
            {"AssistNow Offline data available", "ubx.nav.sat.ano_avail",
                FT_UINT32, BASE_HEX, NULL, 0x00002000, NULL, HFILL}},
        {&hf_ubx_nav_sat_aop_avail,
            {"AssistNow Autonomous data available", "ubx.nav.sat.aop_avail",
                FT_UINT32, BASE_HEX, NULL, 0x00004000, NULL, HFILL}},
        {&hf_ubx_nav_sat_sbas_corr_used,
            {"SBAS corrections used", "ubx.nav.sat.sbas_corr_used",
                FT_UINT32, BASE_HEX, NULL, 0x00010000, NULL, HFILL}},
        {&hf_ubx_nav_sat_rtcm_corr_used,
            {"RTCM corrections used", "ubx.nav.sat.rtcm_corr_used",
                FT_UINT32, BASE_HEX, NULL, 0x00020000, NULL, HFILL}},
        {&hf_ubx_nav_sat_slas_corr_used,
            {"QZSS SLAS corrections used", "ubx.nav.sat.slas_corr_used",
                FT_UINT32, BASE_HEX, NULL, 0x00040000, NULL, HFILL}},
        {&hf_ubx_nav_sat_spartn_corr_used,
            {"SPARTN corrections used", "ubx.nav.sat.spartn_corr_used",
                FT_UINT32, BASE_HEX, NULL, 0x00080000, NULL, HFILL}},
        {&hf_ubx_nav_sat_pr_corr_used,
            {"Pseudorange corrections used", "ubx.nav.sat.pr_corr_used",
                FT_UINT32, BASE_HEX, NULL, 0x00100000, NULL, HFILL}},
        {&hf_ubx_nav_sat_cr_corr_used,
            {"Carrier range corrections used", "ubx.nav.sat.cr_corr_used",
                FT_UINT32, BASE_HEX, NULL, 0x00200000, NULL, HFILL}},
        {&hf_ubx_nav_sat_do_corr_used,
            {"Range rate (Doppler) corrections used", "ubx.nav.sat.do_corr_used",
                FT_UINT32, BASE_HEX, NULL, 0x00400000, NULL, HFILL}},
        {&hf_ubx_nav_sat_clas_corr_used,
            {"CLAS corrections used", "ubx.nav.sat.clas_corr_used",
                FT_UINT32, BASE_HEX, NULL, 0x00800000, NULL, HFILL}},

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
        {&hf_ubx_nav_timegps_towvalid,
            {"Valid GPS time of week", "ubx.nav.timegps.towvalid",
                FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}},
        {&hf_ubx_nav_timegps_weekvalid,
            {"Valid GPS week number", "ubx.nav.timegps.weekvalid",
                FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}},
        {&hf_ubx_nav_timegps_leapsvalid,
            {"Valid GPS leap seconds", "ubx.nav.timegps.leapsvalid",
                FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}},
        {&hf_ubx_nav_timegps_tacc,
            {"Time accuracy estimate", "ubx.nav.timegps.tacc",
                FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0x0, NULL, HFILL}},

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

    static gint *ett_part[] = {
        &ett_ubx,
        &ett_ubx_nav_dop,
        &ett_ubx_nav_eoe,
        &ett_ubx_nav_posecef,
        &ett_ubx_nav_pvt,
        &ett_ubx_nav_pvt_datetime,
        &ett_ubx_nav_sat,
        &ett_ubx_nav_timegps,
        &ett_ubx_nav_timegps_tow,
        &ett_ubx_nav_velecef,
        &ett_ubx_rxm_sfrbx,
    };

    static gint *ett[array_length(ett_part) + array_length(ett_ubx_nav_sat_sv_info)];

    // fill ett with elements from ett_part and pointers to ett_ubx_nav_sat_sv_info elements
    guint16 i;
    for (i = 0; i < array_length(ett_part); i++) {
        ett[i] = ett_part[i];
    }
    for (i = 0; i < array_length(ett_ubx_nav_sat_sv_info); i++) {
        ett[i + array_length(ett_part)] = &ett_ubx_nav_sat_sv_info[i];
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
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_dop,     UBX_NAV_DOP);
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_eoe,     UBX_NAV_EOE);
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_posecef, UBX_NAV_POSECEF);
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_pvt,     UBX_NAV_PVT);
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_sat,     UBX_NAV_SAT);
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_timegps, UBX_NAV_TIMEGPS);
    UBX_REGISTER_DISSECTOR(dissect_ubx_nav_velecef, UBX_NAV_VELECEF);
    UBX_REGISTER_DISSECTOR(dissect_ubx_rxm_sfrbx,   UBX_RXM_SFRBX);
}
