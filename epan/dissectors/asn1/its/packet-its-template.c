/* packet-its-template.c
 *
 * Intelligent Transport Systems Applications dissectors
 * Coyright 2018, C. Guerber <cguerber@yahoo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/*
 * Implemented:
 * CA (CAM)                           ETSI EN 302 637-2   V1.4.1 (2019-01)
 * DEN (DENM)                         ETSI EN 302 637-3   V1.3.0 (2018-08)
 * RLT (MAPEM)                        ETSI TS 103 301     V1.2.1 (2018-08)
 * TLM (SPATEM)                       ETSI TS 103 301     V1.2.1 (2018-08)
 * IVI (IVIM)                         ETSI TS 103 301     V1.2.1 (2018-08)
 * TLC (SREM)                         ETSI TS 103 301     V1.2.1 (2018-08)
 * TLC (SSEM)                         ETSI TS 103 301     V1.2.1 (2018-08)
 * EVCSN POI (EVCSN POI message)      ETSI TS 101 556-1
 * TPG (TRM, TCM, VDRM, VDPM, EOFM)   ETSI TS 101 556-2
 * Charging (EV-RSR, SRM, SCM)        ETSI TS 101 556-3
 * GPC (RTCMEM)                       ETSI TS 103 301
 * VA (VAM)                           ETSI TS 103 300-3   V2.2.1 (2023-02)
 *
 * Not supported:
 * SA (SAEM)                          ETSI TS 102 890-1
 * CTL (CTLM)                         ETSI TS 102 941
 * CRL (CRLM)                         ETSI TS 102 941
 * Certificate request                ETSI TS 102 941
 * MCD (MCDM)                         ETSI TS 103 152
 */
#include "config.h"

#include <math.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>
#include <epan/exceptions.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include <wsutil/utf8_entities.h>
#include "packet-ber.h"
#include "packet-per.h"

#include "packet-its.h"
#include "packet-ieee1609dot2.h"

/*
 * Well Known Ports definitions as per:
 *
 * ETSI TS 103 248 v1.2.1 (2018-08)
 * Intelligent Transport Systems (ITS);
 * GeoNetworking;
 * Port Numbers for the Basic Transport Protocol (BTP)
 *
 * BTP port   Facilities service      Related standard
 * number     or Application
 * values
 * 2001       CA (CAM)                ETSI EN 302 637-2  V1.4.1 (2019-01)
 * 2002       DEN (DENM)              ETSI EN 302 637-3
 * 2003       RLT (MAPEM)             ETSI TS 103 301     V1.2.1 (2018-08)
 * 2004       TLM (SPATEM)            ETSI TS 103 301     V1.2.1 (2018-08)
 * 2005       SA (SAEM)               ETSI TS 102 890-1
 * 2006       IVI (IVIM)              ETSI TS 103 301     V1.2.1 (2018-08)
 * 2007       TLC (SREM)              ETSI TS 103 301     V1.2.1 (2018-08)
 * 2008       TLC (SSEM)              ETSI TS 103 301     V1.2.1 (2018-08)
 * 2009       Allocated               Allocated for "Intelligent Transport
 *                                    System (ITS); Vehicular Communications;
 *                                    Basic Set of Applications; Specification
 *                                    of the Collective Perception Service"
 * 2010       EVCSN POI (EVCSN POI    ETSI TS 101 556-1
 *            message)
 * 2011       TPG (TRM, TCM, VDRM,    ETSI TS 101 556-2
 *            VDPM, EOFM)
 * 2012       Charging (EV-RSR,       ETSI TS 101 556-3
 *            SRM, SCM)
 * 2013       GPC (RTCMEM)            ETSI TS 103 301     V1.2.1 (2018-08)
 * 2014       CTL (CTLM)              ETSI TS 102 941
 * 2015       CRL (CRLM)              ETSI TS 102 941
 * 2016       Certificate request     ETSI TS 102 941
 * 2017       MCD (MCDM)              ETSI TS 103 152
 * 2018       VA (VAM)                ETSI TS 103 300-3   V2.2.1 (2023-02)
 */

// Applications Well Known Ports
#define ITS_WKP_CA         2001
#define ITS_WKP_DEN        2002
#define ITS_WKP_RLT        2003
#define ITS_WKP_TLM        2004
#define ITS_WKP_SA         2005
#define ITS_WKP_IVI        2006
#define ITS_WKP_TLC_SREM   2007
#define ITS_WKP_TLC_SSEM   2008
#define ITS_WKP_CPS        2009
#define ITS_WKP_EVCSN      2010
#define ITS_WKP_TPG        2011
#define ITS_WKP_CHARGING   2012
#define ITS_WKP_GPC        2013
#define ITS_WKP_CTL        2014
#define ITS_WKP_CRL        2015
#define ITS_WKP_CERTIF_REQ 2016
#define ITS_WKP_MCD        2017
#define ITS_WKP_VA         2018

/*
 * Prototypes
 */
void proto_reg_handoff_its(void);
void proto_register_its(void);

static dissector_handle_t its_handle;

static expert_field ei_its_no_sub_dis;

// TAP
static int its_tap;

// Protocols
static int proto_its;
static int proto_its_denm;
static int proto_its_denmv1;
static int proto_its_cam;
static int proto_its_camv1;
static int proto_its_evcsn;
static int proto_its_evrsr;
static int proto_its_ivimv1;
static int proto_its_ivim;
static int proto_its_tistpg;
static int proto_its_ssem;
static int proto_its_srem;
static int proto_its_rtcmemv1;
static int proto_its_rtcmem;
static int proto_its_mapemv1;
static int proto_its_mapem;
static int proto_its_spatemv1;
static int proto_its_spatem;
static int proto_its_cpm;
static int proto_its_imzm;
static int proto_its_vam;
static int proto_addgrpc;

/*
 * DENM SSP
 */
static int hf_denmssp_version;
static int hf_denmssp_flags;
static int hf_denmssp_trafficCondition;
static int hf_denmssp_accident;
static int hf_denmssp_roadworks;
static int hf_denmssp_adverseWeatherConditionAdhesion;
static int hf_denmssp_hazardousLocationSurfaceCondition;
static int hf_denmssp_hazardousLocationObstacleOnTheRoad;
static int hf_denmssp_hazardousLocationAnimalOnTheRoad;
static int hf_denmssp_humanPresenceOnTheRoad;
static int hf_denmssp_wrongWayDriving;
static int hf_denmssp_rescueAndRecoveryWorkInProgress;
static int hf_denmssp_ExtremeWeatherCondition;
static int hf_denmssp_adverseWeatherConditionVisibility;
static int hf_denmssp_adverseWeatherConditionPrecipitation;
static int hf_denmssp_slowVehicle;
static int hf_denmssp_dangerousEndOfQueue;
static int hf_denmssp_vehicleBreakdown;
static int hf_denmssp_postCrash;
static int hf_denmssp_humanProblem;
static int hf_denmssp_stationaryVehicle;
static int hf_denmssp_emergencyVehicleApproaching;
static int hf_denmssp_hazardousLocationDangerousCurve;
static int hf_denmssp_collisionRisk;
static int hf_denmssp_signalViolation;
static int hf_denmssp_dangerousSituation;

/*
 * CAM SSP
 */
static int hf_camssp_version;
static int hf_camssp_flags;
static int hf_camssp_cenDsrcTollingZone;
static int hf_camssp_publicTransport;
static int hf_camssp_specialTransport;
static int hf_camssp_dangerousGoods;
static int hf_camssp_roadwork;
static int hf_camssp_rescue;
static int hf_camssp_emergency;
static int hf_camssp_safetyCar;
static int hf_camssp_closedLanes;
static int hf_camssp_requestForRightOfWay;
static int hf_camssp_requestForFreeCrossingAtATrafficLight;
static int hf_camssp_noPassing;
static int hf_camssp_noPassingForTrucks;
static int hf_camssp_speedLimit;
static int hf_camssp_reserved;

static int ett_denmssp_flags;
static int ett_camssp_flags;

// Subdissectors
static dissector_table_t its_version_subdissector_table;
static dissector_table_t its_msgid_subdissector_table;
static dissector_table_t regionid_subdissector_table;
static dissector_table_t cpmcontainer_subdissector_table;
static dissector_table_t cam_pt_activation_table;

typedef struct its_private_data {
    enum regext_type_enum type;
    uint32_t region_id;
    uint32_t cause_code;
} its_private_data_t;

typedef struct its_pt_activation_data {
    uint32_t type;
    tvbuff_t *data;
} its_pt_activation_data_t;

static its_header_t*
its_get_private_data(packet_info* pinfo)
{
    its_header_t* its_hdr = (its_header_t*)p_get_proto_data(pinfo->pool, pinfo, proto_its, 0);
    if (!its_hdr) {
        its_hdr = wmem_new0(pinfo->pool, its_header_t);
        p_add_proto_data(pinfo->pool, pinfo, proto_its, 0, its_hdr);
    }
    return its_hdr;
}

// Specific dissector for content of open type for regional extensions
static int dissect_regextval_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    its_private_data_t *re = (its_private_data_t*)data;
    // XXX What to do when region_id = noRegion? Test length is zero?
    if (!dissector_try_uint_new(regionid_subdissector_table, ((uint32_t) re->region_id<<16) + (uint32_t) re->type, tvb, pinfo, tree, false, NULL))
        call_data_dissector(tvb, pinfo, tree);
    return tvb_captured_length(tvb);
}

// Specific dissector for content of open type for regional extensions
static int dissect_cpmcontainers_pdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    // XXX What to do when region_id = noRegion? Test length is zero?
    if (!dissector_try_uint_new(cpmcontainer_subdissector_table, its_get_private_data(pinfo)->CpmContainerId, tvb, pinfo, tree, false, NULL))
        call_data_dissector(tvb, pinfo, tree);
    return tvb_captured_length(tvb);
}




static int dissect_denmssp_pdu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    static int * const denmssp_flags[] = {
        &hf_denmssp_trafficCondition,
        &hf_denmssp_accident,
        &hf_denmssp_roadworks,
        &hf_denmssp_adverseWeatherConditionAdhesion,
        &hf_denmssp_hazardousLocationSurfaceCondition,
        &hf_denmssp_hazardousLocationObstacleOnTheRoad,
        &hf_denmssp_hazardousLocationAnimalOnTheRoad,
        &hf_denmssp_humanPresenceOnTheRoad,
        &hf_denmssp_wrongWayDriving,
        &hf_denmssp_rescueAndRecoveryWorkInProgress,
        &hf_denmssp_ExtremeWeatherCondition,
        &hf_denmssp_adverseWeatherConditionVisibility,
        &hf_denmssp_adverseWeatherConditionPrecipitation,
        &hf_denmssp_slowVehicle,
        &hf_denmssp_dangerousEndOfQueue,
        &hf_denmssp_vehicleBreakdown,
        &hf_denmssp_postCrash,
        &hf_denmssp_humanProblem,
        &hf_denmssp_stationaryVehicle,
        &hf_denmssp_emergencyVehicleApproaching,
        &hf_denmssp_hazardousLocationDangerousCurve,
        &hf_denmssp_collisionRisk,
        &hf_denmssp_signalViolation,
        &hf_denmssp_dangerousSituation,
        NULL
    };

    uint32_t version;

    proto_tree_add_item_ret_uint(tree, hf_denmssp_version, tvb, 0, 1, ENC_BIG_ENDIAN, &version);
    if (version == 1) {
        proto_tree_add_bitmask(tree, tvb, 1, hf_denmssp_flags, ett_denmssp_flags, denmssp_flags, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}

static int dissect_camssp_pdu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    static int * const camssp_flags[] = {
        &hf_camssp_cenDsrcTollingZone,
        &hf_camssp_publicTransport,
        &hf_camssp_specialTransport,
        &hf_camssp_dangerousGoods,
        &hf_camssp_roadwork,
        &hf_camssp_rescue,
        &hf_camssp_emergency,
        &hf_camssp_safetyCar,
        &hf_camssp_closedLanes,
        &hf_camssp_requestForRightOfWay,
        &hf_camssp_requestForFreeCrossingAtATrafficLight,
        &hf_camssp_noPassing,
        &hf_camssp_noPassingForTrucks,
        &hf_camssp_speedLimit,
        &hf_camssp_reserved,
        NULL
    };

    uint32_t version;

    proto_tree_add_item_ret_uint(tree, hf_camssp_version, tvb, 0, 1, ENC_BIG_ENDIAN, &version);
    if (version == 1) {
        proto_tree_add_bitmask(tree, tvb, 1, hf_camssp_flags, ett_camssp_flags, camssp_flags, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}

// Generated by asn2wrs
#include "packet-its-hf.c"

static int ett_its;

#include "packet-its-ett.c"

// Deal with cause/subcause code management
static struct { CauseCodeType_enum cause; int* hf; } cause_to_subcause[] = {
    { trafficCondition, &hf_its_trafficCondition1 },
    { accident, &hf_its_accident2 },
    { roadworks, &hf_its_roadworks3 },
    { adverseWeatherCondition_Precipitation, &hf_its_adverseWeatherCondition_Precipitation19 },
    { adverseWeatherCondition_Visibility, &hf_its_adverseWeatherCondition_Visibility18 },
    { adverseWeatherCondition_Adhesion, &hf_its_adverseWeatherCondition_Adhesion6 },
    { adverseWeatherCondition_ExtremeWeatherCondition, &hf_its_adverseWeatherCondition_ExtremeWeatherCondition17 },
    { hazardousLocation_AnimalOnTheRoad, &hf_its_hazardousLocation_AnimalOnTheRoad11 },
    { hazardousLocation_ObstacleOnTheRoad, &hf_its_hazardousLocation_ObstacleOnTheRoad10 },
    { hazardousLocation_SurfaceCondition, &hf_its_hazardousLocation_SurfaceCondition9 },
    { hazardousLocation_DangerousCurve, &hf_its_hazardousLocation_DangerousCurve96 },
    { humanPresenceOnTheRoad, &hf_its_humanPresenceOnTheRoad12 },
    { wrongWayDriving, &hf_its_wrongWayDriving14 },
    { rescueAndRecoveryWorkInProgress, &hf_its_rescueAndRecoveryWorkInProgress15 },
    { slowVehicle, &hf_its_slowVehicle26 },
    { dangerousEndOfQueue, &hf_its_dangerousEndOfQueue27 },
    { vehicleBreakdown, &hf_its_vehicleBreakdown91 },
    { postCrash, &hf_its_postCrash92 },
    { humanProblem, &hf_its_humanProblem93 },
    { stationaryVehicle, &hf_its_stationaryVehicle94 },
    { emergencyVehicleApproaching, &hf_its_emergencyVehicleApproaching95 },
    { collisionRisk, &hf_its_collisionRisk97 },
    { signalViolation, &hf_its_signalViolation98 },
    { dangerousSituation, &hf_its_dangerousSituation99 },
    { 0, NULL },
};

static int*
find_subcause_from_cause(CauseCodeType_enum cause)
{
    int idx = 0;

    while (cause_to_subcause[idx].hf && (cause_to_subcause[idx].cause != cause))
        idx++;

    return cause_to_subcause[idx].hf?cause_to_subcause[idx].hf:&hf_its_subCauseCode;
}

static unsigned char ita2_ascii[32] = {
    '\0', 'T', '\r', 'O', ' ', 'H', 'N', 'M', '\n', 'L', 'R', 'G', 'I', 'P', 'C', 'V',
    'E', 'Z', 'D', 'B', 'S', 'Y', 'F', 'X', 'A', 'W', 'J', '\0', 'U', 'Q', 'K'
};

static void
append_country_code_fmt(proto_item *item, tvbuff_t *val_tvb)
{
  uint16_t v = tvb_get_uint16(val_tvb, 0, ENC_BIG_ENDIAN);
  v >>= 6;  /* 10 bits */
  uint16_t v1 = (v >> 5) & 0x1F;
  uint16_t v2 = v & 0x1F;
  proto_item_append_text(item, " - %c%c", ita2_ascii[v1], ita2_ascii[v2]);
}

#include "packet-its-fn.c"

static void
its_latitude_fmt(char *s, uint32_t v)
{
  int32_t lat = (int32_t)v;
  if (lat == 900000001) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", lat);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%u°%u'%.3f\"%c (%d)",
               abs(lat) / 10000000,
               abs(lat) % 10000000 * 6 / 1000000,
               abs(lat) % 10000000 * 6 % 1000000 * 6.0 / 100000.0,
               (lat >= 0) ? 'N' : 'S',
               lat);
  }
}

static void
its_longitude_fmt(char *s, uint32_t v)
{
  int32_t lng = (int32_t)v;
  if (lng == 1800000001) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", lng);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%u°%u'%.3f\"%c (%d)",
               abs(lng) / 10000000,
               abs(lng) % 10000000 * 6 / 1000000,
               abs(lng) % 10000000 * 6 % 1000000 * 6.0 / 100000.0,
               (lng >= 0) ? 'E' : 'W',
               lng);
  }
}

static void
its_altitude_fmt(char *s, uint32_t v)
{
  int32_t alt = (int32_t)v;
  if (alt == 800001) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", alt);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.2fm (%d)", alt * 0.01, alt);
  }
}

static void
its_delta_latitude_fmt(char *s, uint32_t v)
{
  int32_t lat = (int32_t)v;
  if (lat == 131072) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", lat);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%u°%u'%.3f\"%c (%d)",
               abs(lat) / 10000000,
               abs(lat) % 10000000 * 6 / 1000000,
               abs(lat) % 10000000 * 6 % 1000000 * 6.0 / 100000.0,
               (lat >= 0) ? 'N' : 'S',
               lat);
  }
}

static void
its_delta_longitude_fmt(char *s, uint32_t v)
{
  int32_t lng = (int32_t)v;
  if (lng == 131072) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", lng);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%u°%u'%.3f\"%c (%d)",
               abs(lng) / 10000000,
               abs(lng) % 10000000 * 6 / 1000000,
               abs(lng) % 10000000 * 6 % 1000000 * 6.0 / 100000.0,
               (lng >= 0) ? 'E' : 'W',
               lng);
  }
}

static void
its_delta_altitude_fmt(char *s, uint32_t v)
{
  int32_t alt = (int32_t)v;
  if (alt == 12800) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", alt);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.2fm (%d)", alt * 0.01, alt);
  }
}

static void
its_path_delta_time_fmt(char *s, uint32_t v)
{
  int32_t dt = (int32_t)v;
  snprintf(s, ITEM_LABEL_LENGTH, "%.2fs (%d)", dt * 0.01, dt);
}


static void
its_sax_length_fmt(char *s, uint32_t v)
{
  if (v == 4095) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", v);
  } else if (v == 4094) {
    snprintf(s, ITEM_LABEL_LENGTH, "outOfRange (%d)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.2fm (%d)", v * 0.01, v);
  }
}

static void
its_heading_value_fmt(char *s, uint32_t v)
{
  const char *p = try_val_to_str(v, VALS(its_HeadingValue_vals));
  if (p) {
    snprintf(s, ITEM_LABEL_LENGTH, "%s (%d)", p, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1f° (%d)", v * 0.1, v);
  }
}

static void
its_heading_confidence_fmt(char *s, uint32_t v)
{
  if (v == 127) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", v);
  } else if (v == 126) {
    snprintf(s, ITEM_LABEL_LENGTH, "outOfRange (%d)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1f° (%d)", v * 0.1, v);
  }
}

static void
its_speed_value_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "standstill (%d)", v);
  } else if (v == 16383) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", v);
  } else {
    double vms = v * 0.01;
    snprintf(s, ITEM_LABEL_LENGTH, "%.2fm/s = %.1fkm/h (%d)",
            vms, vms * 3.6, v);
  }
}

static void
its_speed_confidence_fmt(char *s, uint32_t v)
{
  if (v == 127) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", v);
  } else if (v == 126) {
    snprintf(s, ITEM_LABEL_LENGTH, "outOfRange (%d)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.2fm/s (%d)", v * 0.01, v);
  }
}

static void
its_speed_limit_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%dkm/h (%d)", v, v);
}

static void
its_vehicle_length_value_fmt(char *s, uint32_t v)
{
  if (v == 1023) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", v);
  } else if (v == 1022) {
    snprintf(s, ITEM_LABEL_LENGTH, "outOfRange (%d)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fm (%d)", v * 0.1, v);
  }
}

static void
its_vehicle_width_fmt(char *s, uint32_t v)
{
  if (v == 62) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", v);
  } else if (v == 61) {
    snprintf(s, ITEM_LABEL_LENGTH, "outOfRange (%d)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fm (%d)", v * 0.1, v);
  }
}

static void
its_acceleration_value_fmt(char *s, uint32_t v)
{
  int32_t acc = (int32_t)v;
  if (acc == 161) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fm/s² (%d)", acc * 0.1, acc);
  }
}

static void
its_acceleration_confidence_fmt(char *s, uint32_t v)
{
  if (v == 102) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", v);
  } else if (v == 101) {
    snprintf(s, ITEM_LABEL_LENGTH, "outOfRange (%d)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fm/s² (%d)", v * 0.1, v);
  }
}

static void
its_curvature_value_fmt(char *s, uint32_t v)
{
  int32_t curv = (int32_t)v;
  if (curv == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "straight (%d)", v);
  } else if (curv == 30001) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.3fm %s (%d)",
               30000.0 / curv,
               (curv > 0) ? "left" : "right",
               curv);
  }
}

static void
its_yaw_rate_value_fmt(char *s, uint32_t v)
{
  int32_t yaw = (int32_t)v;
  if (yaw == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "straight (%d)", v);
  } else if (yaw == 32767) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.2f°/s %s (%d)",
               yaw * 0.01,
               (yaw > 0) ? "left" : "right",
               yaw);
  }
}

static void
its_swa_value_fmt(char *s, uint32_t v)
{
  int32_t swa = (int32_t)v;
  if (swa == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "straight (%d)", v);
  } else if (swa == 512) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1f° %s (%d)",
               swa * 1.5,
               (swa > 0) ? "left" : "right",
               swa);
  }
}

static void
its_swa_confidence_fmt(char *s, uint32_t v)
{
  if (v == 127) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", v);
  } else if (v == 126) {
    snprintf(s, ITEM_LABEL_LENGTH, "outOfRange (%d)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1f° (%d)", v * 1.5, v);
  }
}

static void
dsrc_moi_fmt(char *s, uint32_t v)
{
  if (v == 527040) {
    snprintf(s, ITEM_LABEL_LENGTH, "invalid (%d)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%ud %02u:%02u (%d)",
            v / 1440, v % 1440 / 60, v % 60, v);
  }
}

static void
dsrc_dsecond_fmt(char *s, uint32_t v)
{
  if (v == 65535) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", v);
  } else if ((61000 <= v) && (v <= 65534)) {
    snprintf(s, ITEM_LABEL_LENGTH, "reserved (%d)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%02u.%03u (%d)",
            v / 1000, v % 1000, v);
  }
}

static void
dsrc_time_mark_fmt(char *s, uint32_t v)
{
  if (v == 36001) {
    snprintf(s, ITEM_LABEL_LENGTH, "unknown (%d)", v);
  } else if (v == 36000) {
    snprintf(s, ITEM_LABEL_LENGTH, "moreThanHour (%d)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%02u:%02u.%u (%d)",
            v / 600, v % 600 / 10, v % 10, v);
  }
}

static void
its_timestamp_fmt(char *s, uint64_t v)
{
  time_t secs = v / 1000 + 1072915200 - 5;
  struct tm *tm = gmtime(&secs);
  snprintf(s, ITEM_LABEL_LENGTH, "%u-%02u-%02u %02u:%02u:%02u.%03u (%" PRIu64 ")",
    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, (uint32_t)(v % 1000), v
  );
}

static void
its_validity_duration_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%02u:%02u:%02u (%d)",
          v / 3600, v % 3600 / 60, v % 60, v);
}

static const value_string dsrc_TimeIntervalConfidence_vals[] = {
  {   0, "21% probability" },
  {   1, "36% probability" },
  {   2, "47% probability" },
  {   3, "56% probability" },
  {   4, "62% probability" },
  {   5, "68% probability" },
  {   6, "73% probability" },
  {   7, "77% probability" },
  {   8, "81% probability" },
  {   9, "85% probability" },
  {  10, "88% probability" },
  {  11, "91% probability" },
  {  12, "94% probability" },
  {  13, "96% probability" },
  {  14, "98% probability" },
  {  15, "10% probability" },
  { 0, NULL }
};

static void
dsrc_velocity_fmt(char *s, uint32_t v)
{
  if (v == 8191) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", v);
  } else {
    double vms = v * 0.02;
    snprintf(s, ITEM_LABEL_LENGTH, "%.2fm/s = %ukm/h (%d)",
            vms, (int)lround(vms * 3.6), v);
  }
}

static void
dsrc_angle_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.2f° (%d)", v * 0.0125, v);
}

static void
dsrc_delta_time_fmt(char *s, uint32_t v)
{
  int32_t dt = (int32_t)v;
  if (dt == -122) {
    snprintf(s, ITEM_LABEL_LENGTH, "unknown (%d)", dt);
  } else if (dt == -121) {
    snprintf(s, ITEM_LABEL_LENGTH, "moreThanMinus20Minutes (%d)", dt);
  } else if (dt == 121) {
    snprintf(s, ITEM_LABEL_LENGTH, "moreThanPlus20Minutes (%d)", dt);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%s%d:%02u (%d)",
            (dt < 0) ? "-" : "", abs(dt) / 6, abs(dt) % 6 * 10, dt);
  }
}


static void
cpm_object_dimension_value_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fm (%d)", v * 0.1, v);
}

//static void
//cpm_object_dimension_confidence_fmt(char *s, uint32_t v)
//{
//  if (v == 102) {
//    snprintf(s, ITEM_LABEL_LENGTH, "unavailable (%d)", v);
//  } else if (v == 101) {
//    snprintf(s, ITEM_LABEL_LENGTH, "outOfRange (%d)", v);
//  } else {
//    snprintf(s, ITEM_LABEL_LENGTH, "%.2fm (%d)", v * 0.01, v);
//  }
//}

static int
dissect_its_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  proto_item *its_item;
  proto_tree *its_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ITS");
  col_clear(pinfo->cinfo, COL_INFO);

  its_item = proto_tree_add_item(tree, proto_its, tvb, 0, -1, ENC_NA);
  its_tree = proto_item_add_subtree(its_item, ett_its);

  return dissect_its_ItsPduHeader_PDU(tvb, pinfo, its_tree, data);
}

// Decode As...
static void
its_msgid_prompt(packet_info *pinfo, char *result)
{
    uint32_t msgid = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, hf_its_messageId, pinfo->curr_layer_num));

    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "MsgId (%s%u)", UTF8_RIGHTWARDS_ARROW, msgid);
}

static void *
its_msgid_value(packet_info *pinfo)
{
    return p_get_proto_data(pinfo->pool, pinfo, hf_its_messageId, pinfo->curr_layer_num);
}

// Registration of protocols
void proto_register_its(void)
{
    static hf_register_info hf_its[] = {
        #include "packet-its-hfarr.c"


    /*
     * DENM SSP
     */
    { &hf_denmssp_version, { "Version", "its.ssp.denm.version", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_denmssp_flags, { "Allowed to sign", "its.ssp.denm.flags", FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL }},
    { &hf_denmssp_trafficCondition,
        { "trafficCondition",                     "its.denm.ssp.trafficCondition",
            FT_UINT24, BASE_DEC, NULL, 0x800000, NULL, HFILL }},
    { &hf_denmssp_accident,
        { "accident",                             "its.denm.ssp.accident",
            FT_UINT24, BASE_DEC, NULL, 0x400000, NULL, HFILL }},
    { &hf_denmssp_roadworks,
        { "roadworks",                            "its.denm.ssp.roadworks",
            FT_UINT24, BASE_DEC, NULL, 0x200000, NULL, HFILL }},
    { &hf_denmssp_adverseWeatherConditionAdhesion,
        { "adverseWeatherConditionAdhesion",      "its.denm.ssp.advWxConditionAdhesion",
            FT_UINT24, BASE_DEC, NULL, 0x100000, NULL, HFILL }},
    { &hf_denmssp_hazardousLocationSurfaceCondition,
        { "hazardousLocationSurfaceCondition",    "its.denm.ssp.hazLocationSurfaceCondition",
            FT_UINT24, BASE_DEC, NULL, 0x080000, NULL, HFILL }},
    { &hf_denmssp_hazardousLocationObstacleOnTheRoad,
        { "hazardousLocationObstacleOnTheRoad",   "its.denm.ssp.hazLocationObstacleOnTheRoad",
            FT_UINT24, BASE_DEC, NULL, 0x040000, NULL, HFILL }},
    { &hf_denmssp_hazardousLocationAnimalOnTheRoad,
        { "hazardousLocationAnimalOnTheRoad",     "its.denm.ssp.hazLocationAnimalOnTheRoad",
            FT_UINT24, BASE_DEC, NULL, 0x020000, NULL, HFILL }},
    { &hf_denmssp_humanPresenceOnTheRoad,
        { "humanPresenceOnTheRoad",               "its.denm.ssp.humanPresenceOnTheRoad",
            FT_UINT24, BASE_DEC, NULL, 0x010000, NULL, HFILL }},
    { &hf_denmssp_wrongWayDriving,
        { "wrongWayDriving",                      "its.denm.ssp.wrongWayDriving",
            FT_UINT24, BASE_DEC, NULL, 0x008000, NULL, HFILL }},
    { &hf_denmssp_rescueAndRecoveryWorkInProgress,
        { "rescueAndRecoveryWorkInProgress",      "its.denm.ssp.rescueAndRecoveryWorkInProgress",
            FT_UINT24, BASE_DEC, NULL, 0x004000, NULL, HFILL }},
    { &hf_denmssp_ExtremeWeatherCondition,
        { "ExtremeWeatherCondition",              "its.denm.ssp.ExtremeWxCondition",
            FT_UINT24, BASE_DEC, NULL, 0x002000, NULL, HFILL }},
    { &hf_denmssp_adverseWeatherConditionVisibility,
        { "adverseWeatherConditionVisibility",    "its.denm.ssp.advWxConditionVisibility",
            FT_UINT24, BASE_DEC, NULL, 0x001000, NULL, HFILL }},
    { &hf_denmssp_adverseWeatherConditionPrecipitation,
        { "adverseWeatherConditionPrecipitation", "its.denm.ssp.advWxConditionPrecipitation",
            FT_UINT24, BASE_DEC, NULL, 0x000800, NULL, HFILL }},
    { &hf_denmssp_slowVehicle,
        { "slowVehicle",                          "its.denm.ssp.slowVehicle",
            FT_UINT24, BASE_DEC, NULL, 0x000400, NULL, HFILL }},
    { &hf_denmssp_dangerousEndOfQueue,
        { "dangerousEndOfQueue",                  "its.denm.ssp.dangerousEndOfQueue",
            FT_UINT24, BASE_DEC, NULL, 0x000200, NULL, HFILL }},
    { &hf_denmssp_vehicleBreakdown,
        { "vehicleBreakdown",                     "its.denm.ssp.vehicleBreakdown",
            FT_UINT24, BASE_DEC, NULL, 0x000100, NULL, HFILL }},
    { &hf_denmssp_postCrash,
        { "postCrash",                            "its.denm.ssp.postCrash",
            FT_UINT24, BASE_DEC, NULL, 0x000080, NULL, HFILL }},
    { &hf_denmssp_humanProblem,
        { "humanProblem",                         "its.denm.ssp.humanProblem",
            FT_UINT24, BASE_DEC, NULL, 0x000040, NULL, HFILL }},
    { &hf_denmssp_stationaryVehicle,
        { "stationaryVehicle",                    "its.denm.ssp.stationaryVehicle",
            FT_UINT24, BASE_DEC, NULL, 0x000020, NULL, HFILL }},
    { &hf_denmssp_emergencyVehicleApproaching,
        { "emergencyVehicleApproaching",          "its.denm.ssp.emergencyVehicleApproaching",
            FT_UINT24, BASE_DEC, NULL, 0x000010, NULL, HFILL }},
    { &hf_denmssp_hazardousLocationDangerousCurve,
        { "hazardousLocationDangerousCurve",      "its.denm.ssp.hazLocationDangerousCurve",
            FT_UINT24, BASE_DEC, NULL, 0x000008, NULL, HFILL }},
    { &hf_denmssp_collisionRisk,
        { "collisionRisk",                        "its.denm.ssp.collisionRisk",
            FT_UINT24, BASE_DEC, NULL, 0x000004, NULL, HFILL }},
    { &hf_denmssp_signalViolation,
        { "signalViolation",                      "its.denm.ssp.signalViolation",
            FT_UINT24, BASE_DEC, NULL, 0x000002, NULL, HFILL }},
    { &hf_denmssp_dangerousSituation,
        { "dangerousSituation",                   "its.denm.ssp.dangerousSituation",
            FT_UINT24, BASE_DEC, NULL, 0x000001, NULL, HFILL }},

    /*
     * CAM SSP
     */
    { &hf_camssp_version, { "Version", "its.ssp.cam.version", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_camssp_flags, { "Allowed to sign", "its.ssp.cam.flags", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
    { &hf_camssp_cenDsrcTollingZone, { "cenDsrcTollingZone", "its.ssp.cam.cenDsrcTollingZone", FT_UINT16, BASE_DEC, NULL, 0x8000, NULL, HFILL }},
    { &hf_camssp_publicTransport, { "publicTransport", "its.ssp.cam.publicTransport", FT_UINT16, BASE_DEC, NULL, 0x4000, NULL, HFILL }},
    { &hf_camssp_specialTransport, { "specialTransport", "its.ssp.cam.specialTransport", FT_UINT16, BASE_DEC, NULL, 0x2000, NULL, HFILL }},
    { &hf_camssp_dangerousGoods, { "dangerousGoods", "its.ssp.cam.dangerousGoods", FT_UINT16, BASE_DEC, NULL, 0x1000, NULL, HFILL }},
    { &hf_camssp_roadwork, { "roadwork", "its.ssp.cam.roadwork", FT_UINT16, BASE_DEC, NULL, 0x0800, NULL, HFILL }},
    { &hf_camssp_rescue, { "rescue", "its.ssp.cam.rescue", FT_UINT16, BASE_DEC, NULL, 0x0400, NULL, HFILL }},
    { &hf_camssp_emergency, { "emergency", "its.ssp.cam.emergency", FT_UINT16, BASE_DEC, NULL, 0x0200, NULL, HFILL }},
    { &hf_camssp_safetyCar, { "safetyCar", "its.ssp.cam.safetyCar", FT_UINT16, BASE_DEC, NULL, 0x0100, NULL, HFILL }},
    { &hf_camssp_closedLanes, { "closedLanes", "its.ssp.cam.closedLanes", FT_UINT16, BASE_DEC, NULL, 0x0080, NULL, HFILL }},
    { &hf_camssp_requestForRightOfWay, { "requestForRightOfWay", "its.ssp.cam.requestForRightOfWay", FT_UINT16, BASE_DEC, NULL, 0x0040, NULL, HFILL }},
    { &hf_camssp_requestForFreeCrossingAtATrafficLight, { "reqFreeCrossTrafLight", "its.ssp.cam.requestForFreeCrossingAtATrafficLight", FT_UINT16, BASE_DEC, NULL, 0x0020, NULL, HFILL }},
    { &hf_camssp_noPassing, { "noPassing", "its.ssp.cam.noPassing", FT_UINT16, BASE_DEC, NULL, 0x0010, NULL, HFILL }},
    { &hf_camssp_noPassingForTrucks, { "noPassingForTrucks", "its.ssp.cam.noPassingForTrucks", FT_UINT16, BASE_DEC, NULL, 0x0008, NULL, HFILL }},
    { &hf_camssp_speedLimit, { "speedLimit", "its.ssp.cam.speedLimit", FT_UINT16, BASE_DEC, NULL, 0x0004, NULL, HFILL }},
    { &hf_camssp_reserved, { "reserved", "its.ssp.cam.reserved", FT_UINT16, BASE_DEC, NULL, 0x0003, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_its,
        &ett_denmssp_flags,
        &ett_camssp_flags,
        #include "packet-its-ettarr.c"
    };

    static ei_register_info ei[] = {
    { &ei_its_no_sub_dis, { "its.no_subdissector", PI_PROTOCOL, PI_NOTE, "No subdissector found for this Message id/protocol version combination", EXPFILL }},
    };

    expert_module_t* expert_its;

    proto_its = proto_register_protocol("Intelligent Transport Systems", "ITS", "its");

    proto_register_field_array(proto_its, hf_its, array_length(hf_its));

    proto_register_subtree_array(ett, array_length(ett));

    expert_its = expert_register_protocol(proto_its);

    expert_register_field_array(expert_its, ei, array_length(ei));

    its_handle = register_dissector("its", dissect_its_PDU, proto_its);

    // Register subdissector table
    its_version_subdissector_table = register_dissector_table("its.version", "ITS version", proto_its, FT_UINT8, BASE_DEC);
    its_msgid_subdissector_table = register_dissector_table("its.msg_id", "ITS message id", proto_its, FT_UINT32, BASE_DEC);
    regionid_subdissector_table = register_dissector_table("dsrc.regionid", "DSRC RegionId", proto_its, FT_UINT32, BASE_DEC);
    cpmcontainer_subdissector_table = register_dissector_table("cpm.container", "CPM Containers id", proto_its, FT_UINT32, BASE_DEC);
    cam_pt_activation_table = register_dissector_table("cam.ptat", "CAM PtActivationType", proto_its, FT_UINT32, BASE_DEC);

    proto_its_denm = proto_register_protocol_in_name_only("ITS message - DENM", "DENM", "its.message.denm", proto_its, FT_BYTES);
    proto_its_denmv1 = proto_register_protocol_in_name_only("ITS message - DENMv1", "DENMv1", "its.message.denmv1", proto_its, FT_BYTES);
    proto_its_cam = proto_register_protocol_in_name_only("ITS message - CAM", "CAM", "its.message.cam", proto_its, FT_BYTES);
    proto_its_camv1 = proto_register_protocol_in_name_only("ITS message - CAMv1", "CAMv1", "its.message.camv1", proto_its, FT_BYTES);
    proto_its_spatemv1 = proto_register_protocol_in_name_only("ITS message - SPATEMv1", "SPATEMv1", "its.message.spatemv1", proto_its, FT_BYTES);
    proto_its_spatem = proto_register_protocol_in_name_only("ITS message - SPATEM", "SPATEM", "its.message.spatem", proto_its, FT_BYTES);
    proto_its_mapemv1 = proto_register_protocol_in_name_only("ITS message - MAPEMv1", "MAPEMv1", "its.message.mapemv1", proto_its, FT_BYTES);
    proto_its_mapem = proto_register_protocol_in_name_only("ITS message - MAPEM", "MAPEM", "its.message.mapem", proto_its, FT_BYTES);
    proto_its_ivimv1 = proto_register_protocol_in_name_only("ITS message - IVIMv1", "IVIMv1", "its.message.ivimv1", proto_its, FT_BYTES);
    proto_its_ivim = proto_register_protocol_in_name_only("ITS message - IVIM", "IVIM", "its.message.ivim", proto_its, FT_BYTES);
    proto_its_evrsr = proto_register_protocol_in_name_only("ITS message - EVRSR", "EVRSR", "its.message.evrsr", proto_its, FT_BYTES);
    proto_its_srem = proto_register_protocol_in_name_only("ITS message - SREM", "SREM", "its.message.srem", proto_its, FT_BYTES);
    proto_its_ssem = proto_register_protocol_in_name_only("ITS message - SSEM", "SSEM", "its.message.ssem", proto_its, FT_BYTES);
    proto_its_rtcmemv1 = proto_register_protocol_in_name_only("ITS message - RTCMEMv1", "RTCMEMv1", "its.message.rtcmemv1", proto_its, FT_BYTES);
    proto_its_rtcmem = proto_register_protocol_in_name_only("ITS message - RTCMEM", "RTCMEM", "its.message.rtcmem", proto_its, FT_BYTES);
    proto_its_evcsn = proto_register_protocol_in_name_only("ITS message - EVCSN", "EVCSN", "its.message.evcsn", proto_its, FT_BYTES);
    proto_its_tistpg = proto_register_protocol_in_name_only("ITS message - TISTPG", "TISTPG", "its.message.tistpg", proto_its, FT_BYTES);
    proto_its_cpm = proto_register_protocol_in_name_only("ITS message - CPM", "CPM", "its.message.cpm", proto_its, FT_BYTES);
    proto_its_vam = proto_register_protocol_in_name_only("ITS message - VAM", "VAM", "its.message.vam", proto_its, FT_BYTES);
    proto_its_imzm = proto_register_protocol_in_name_only("ITS message - IMZM", "IMZM", "its.message.imzm", proto_its, FT_BYTES);

    proto_addgrpc = proto_register_protocol_in_name_only("DSRC Addition Grp C (EU)", "ADDGRPC", "dsrc.addgrpc", proto_its, FT_BYTES);

    // Decode as
    static build_valid_func its_da_build_value[1] = {its_msgid_value};
    static decode_as_value_t its_da_values = {its_msgid_prompt, 1, its_da_build_value};
    static decode_as_t its_da = {"its", "its.msg_id", 1, 0, &its_da_values, NULL, NULL,
                                    decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    register_decode_as(&its_da);

    its_tap = register_tap("its");
}

#define BTP_SUBDISS_SZ 2
#define BTP_PORTS_SZ   13

#define ITS_CAM_PROT_VER 2
#define ITS_CAM_PROT_VERv1 1
#define ITS_DENM_PROT_VER 2
#define ITS_DENM_PROT_VERv1 1
#define ITS_SPATEM_PROT_VERv1 1
#define ITS_SPATEM_PROT_VER 2
#define ITS_MAPEM_PROT_VERv1 1
#define ITS_MAPEM_PROT_VER 2
#define ITS_IVIM_PROT_VERv1 1
#define ITS_IVIM_PROT_VER 2
#define ITS_SREM_PROT_VER 2
#define ITS_SSEM_PROT_VER 2
#define ITS_RTCMEM_PROT_VERv1 1
#define ITS_RTCMEM_PROT_VER 2
#define ITS_TIS_TPG_PROT_VER 1
#define ITS_CPM_PROT_VER 2
#define ITS_VAM_PROT_VER 2
#define ITS_IMZM_PROT_VER 2

void proto_reg_handoff_its(void)
{
    static const char *subdissector[BTP_SUBDISS_SZ] = { "btpa.port", "btpb.port" };
    static const uint16_t ports[BTP_PORTS_SZ] = { ITS_WKP_DEN, ITS_WKP_CA, ITS_WKP_EVCSN, ITS_WKP_CHARGING, ITS_WKP_IVI, ITS_WKP_TPG, ITS_WKP_TLC_SSEM, ITS_WKP_GPC, ITS_WKP_TLC_SREM, ITS_WKP_RLT, ITS_WKP_TLM, ITS_WKP_CPS, ITS_WKP_VA };
    int sdIdx, pIdx;

    // Register well known ports to btp subdissector table (BTP A and B)
    for (sdIdx=0; sdIdx < BTP_SUBDISS_SZ; sdIdx++) {
        for (pIdx=0; pIdx < BTP_PORTS_SZ; pIdx++) {
            dissector_add_uint(subdissector[sdIdx], ports[pIdx], its_handle);
        }
    }

    // Enable decode as for its pdu's send via udp
    dissector_add_for_decode_as("udp.port", its_handle);

    dissector_add_uint("its.msg_id", (ITS_DENM_PROT_VER << 16) + ITS_DENM,          create_dissector_handle(dissect_denm_DenmPayload_PDU, proto_its_denm ));
    dissector_add_uint("its.msg_id", (ITS_DENM_PROT_VERv1 << 16) + ITS_DENM,        create_dissector_handle(dissect_denmv1_DecentralizedEnvironmentalNotificationMessageV1_PDU, proto_its_denmv1 ));
    dissector_add_uint("its.msg_id", (ITS_CAM_PROT_VER << 16) + ITS_CAM,            create_dissector_handle( dissect_cam_CamPayload_PDU, proto_its_cam ));
    dissector_add_uint("its.msg_id", (ITS_CAM_PROT_VERv1 << 16) + ITS_CAM,          create_dissector_handle( dissect_camv1_CoopAwarenessV1_PDU, proto_its_camv1));
    dissector_add_uint("its.msg_id", (ITS_SPATEM_PROT_VERv1 << 16) + ITS_SPATEM,    create_dissector_handle( dissect_dsrc_SPAT_PDU, proto_its_spatemv1 ));
    dissector_add_uint("its.msg_id", (ITS_SPATEM_PROT_VER << 16) + ITS_SPATEM,      create_dissector_handle( dissect_dsrc_SPAT_PDU, proto_its_spatem ));
    dissector_add_uint("its.msg_id", (ITS_MAPEM_PROT_VERv1 << 16) + ITS_MAPEM,      create_dissector_handle( dissect_dsrc_MapData_PDU, proto_its_mapemv1 ));
    dissector_add_uint("its.msg_id", (ITS_MAPEM_PROT_VER << 16) + ITS_MAPEM,        create_dissector_handle( dissect_dsrc_MapData_PDU, proto_its_mapem ));
    dissector_add_uint("its.msg_id", (ITS_IVIM_PROT_VERv1 << 16) + ITS_IVIM,        create_dissector_handle( dissect_ivi_IviStructure_PDU, proto_its_ivimv1 ));
    dissector_add_uint("its.msg_id", (ITS_IVIM_PROT_VER << 16) + ITS_IVIM,          create_dissector_handle( dissect_ivi_IviStructure_PDU, proto_its_ivim ));
    dissector_add_uint("its.msg_id", ITS_RFU1  ,                                    create_dissector_handle( dissect_evrsr_EV_RSR_MessageBody_PDU, proto_its_evrsr ));
    dissector_add_uint("its.msg_id", (ITS_SREM_PROT_VER << 16) + ITS_SREM,          create_dissector_handle( dissect_dsrc_SignalRequestMessage_PDU, proto_its_srem ));
    dissector_add_uint("its.msg_id", (ITS_SSEM_PROT_VER << 16) + ITS_SSEM,          create_dissector_handle( dissect_dsrc_SignalStatusMessage_PDU, proto_its_ssem ));
    dissector_add_uint("its.msg_id", (ITS_RTCMEM_PROT_VERv1 << 16) + ITS_RTCMEM,    create_dissector_handle( dissect_dsrc_RTCMcorrections_PDU, proto_its_rtcmemv1));
    dissector_add_uint("its.msg_id", (ITS_RTCMEM_PROT_VER << 16) + ITS_RTCMEM,      create_dissector_handle(dissect_dsrc_RTCMcorrections_PDU, proto_its_rtcmem));
    dissector_add_uint("its.msg_id", ITS_EVCSN,                                     create_dissector_handle( dissect_evcsn_EVChargingSpotNotificationPOIMessage_PDU, proto_its_evcsn ));
    dissector_add_uint("its.msg_id", (ITS_TIS_TPG_PROT_VER << 16) + ITS_RFU2,       create_dissector_handle( dissect_tistpg_TisTpgTransaction_PDU, proto_its_tistpg ));
    dissector_add_uint("its.msg_id", (ITS_CPM_PROT_VER << 16) + ITS_CPM,            create_dissector_handle(dissect_cpm_CpmPayload_PDU, proto_its_cpm));
    dissector_add_uint("its.msg_id", (ITS_IMZM_PROT_VER << 16) + ITS_IMZM,          create_dissector_handle(dissect_imzm_InterferenceManagementZoneMessage_PDU, proto_its_imzm));
    dissector_add_uint("its.msg_id", (ITS_VAM_PROT_VER << 16) + ITS_VAM,            create_dissector_handle(dissect_vam_VruAwareness_PDU, proto_its_vam));

    /* Missing definitions: ITS_POI, ITS_SAEM */

    dissector_add_uint("dsrc.regionid", (addGrpC<<16)+Reg_ConnectionManeuverAssist, create_dissector_handle(dissect_AddGrpC_ConnectionManeuverAssist_addGrpC_PDU, proto_addgrpc ));
    dissector_add_uint("dsrc.regionid", (addGrpC<<16)+Reg_GenericLane, create_dissector_handle(dissect_AddGrpC_ConnectionTrajectory_addGrpC_PDU, proto_addgrpc ));
    dissector_add_uint("dsrc.regionid", (addGrpC<<16)+Reg_NodeAttributeSetXY, create_dissector_handle(dissect_AddGrpC_NodeAttributeSet_addGrpC_PDU, proto_addgrpc ));
    dissector_add_uint("dsrc.regionid", (addGrpC<<16)+Reg_IntersectionState, create_dissector_handle(dissect_AddGrpC_IntersectionState_addGrpC_PDU, proto_addgrpc ));
    dissector_add_uint("dsrc.regionid", (addGrpC<<16)+Reg_MapData,create_dissector_handle(dissect_AddGrpC_MapData_addGrpC_PDU, proto_addgrpc ));
    dissector_add_uint("dsrc.regionid", (addGrpC<<16)+Reg_Position3D, create_dissector_handle(dissect_AddGrpC_Position3D_addGrpC_PDU, proto_addgrpc ));
    dissector_add_uint("dsrc.regionid", (addGrpC<<16)+Reg_RestrictionUserType, create_dissector_handle(dissect_AddGrpC_RestrictionUserType_addGrpC_PDU, proto_addgrpc ));
    dissector_add_uint("dsrc.regionid", (addGrpC<<16)+Reg_SignalStatusPackage, create_dissector_handle(dissect_AddGrpC_SignalStatusPackage_addGrpC_PDU, proto_addgrpc ));
    dissector_add_uint("dsrc.regionid", (addGrpC<<16)+Reg_LaneAttributes, create_dissector_handle(dissect_AddGrpC_LaneAttributes_addGrpC_PDU, proto_addgrpc ));
    dissector_add_uint("dsrc.regionid", (addGrpC<<16)+Reg_MovementEvent, create_dissector_handle(dissect_AddGrpC_MovementEvent_addGrpC_PDU, proto_addgrpc ));
    dissector_add_uint("dsrc.regionid", (addGrpC<<16)+Reg_RequestorDescription, create_dissector_handle(dissect_AddGrpC_RequestorDescription_addGrpC_PDU, proto_addgrpc ));

    dissector_add_uint("ieee1609dot2.ssp", psid_den_basic_services, create_dissector_handle(dissect_denmssp_pdu, proto_its_denm));
    dissector_add_uint("ieee1609dot2.ssp", psid_ca_basic_services,  create_dissector_handle(dissect_camssp_pdu, proto_its_cam));
    dissector_add_uint("geonw.ssp", psid_den_basic_services, create_dissector_handle(dissect_denmssp_pdu, proto_its_denm));
    dissector_add_uint("geonw.ssp", psid_ca_basic_services,  create_dissector_handle(dissect_camssp_pdu, proto_its_cam));

    dissector_add_uint("cpm.container", 1, create_dissector_handle(dissect_cpm_OriginatingVehicleContainer_PDU, proto_its_cpm));
    dissector_add_uint("cpm.container", 2, create_dissector_handle(dissect_cpm_OriginatingRsuContainer_PDU, proto_its_cpm));
    dissector_add_uint("cpm.container", 3, create_dissector_handle(dissect_cpm_SensorInformationContainer_PDU, proto_its_cpm));
    dissector_add_uint("cpm.container", 4, create_dissector_handle(dissect_cpm_PerceptionRegionContainer_PDU, proto_its_cpm));
    dissector_add_uint("cpm.container", 5, create_dissector_handle(dissect_cpm_PerceivedObjectContainer_PDU, proto_its_cpm));
}

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
