/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-its.h                                                               */
/* asn2wrs.py -q -L -o its -c ./its.cnf -s ./packet-its-template -D . -O ../.. ETSI-ITS-CDD.asn ITS-ContainerV1.asn ISO_TS_14816.asn ISO_TS_14906_Application.asn ISO_TS_19091.asn GDD.asn ISO19321IVIv2.asn ETSI_TS_103301.asn CAMv1.asn CAM-PDU-Descriptions.asn DENMv1.asn DENM-PDU-Descriptions.asn TIS_TPG_Transactions_Descriptions.asn EVCSN-PDU-Descriptions.asn EV-RSR-PDU-Descriptions.asn CPM-OriginatingStationContainers.asn CPM-PDU-Descriptions.asn CPM-PerceivedObjectContainer.asn CPM-PerceptionRegionContainer.asn CPM-SensorInformationContainer.asn VAM-PDU-Descriptions.asn IMZM-PDU-Descriptions.asn */

/* packet-its-template.h
 *
 * Intelligent Transport Systems Applications dissectors
 * C. Guerber <cguerber@yahoo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ITS_H__
#define __PACKET_ITS_H__


/* --- Module ETSI-ITS-CDD --- --- ---                                        */


/* --- Module ITS-ContainerV1 --- --- ---                                     */


/* --- Module AVIAEINumberingAndDataStructures --- --- ---                    */


/* --- Module EfcDsrcApplication --- --- ---                                  */


/* --- Module DSRC --- --- ---                                                */


/* --- Module AddGrpC --- --- ---                                             */


/* --- Module REGION --- --- ---                                              */


/* --- Module GDD --- --- ---                                                 */


/* --- Module IVI --- --- ---                                                 */


/* --- Module SPATEM-PDU-Descriptions --- --- ---                             */


/* --- Module MAPEM-PDU-Descriptions --- --- ---                              */


/* --- Module IVIM-PDU-Descriptions --- --- ---                               */


/* --- Module SREM-PDU-Descriptions --- --- ---                               */


/* --- Module SSEM-PDU-Descriptions --- --- ---                               */


/* --- Module RTCMEM-PDU-Descriptions --- --- ---                             */


/* --- Module CAMv1-PDU-Descriptions --- --- ---                              */


/* --- Module CAM-PDU-Descriptions --- --- ---                                */


/* --- Module DENMv1-PDU-Descriptions --- --- ---                             */


/* --- Module DENM-PDU-Description --- --- ---                                */


/* --- Module TIS-TPG-Transactions-Descriptions --- --- ---                   */


/* --- Module EVCSN-PDU-Descriptions --- --- ---                              */


/* --- Module EV-RechargingSpotReservation-PDU-Descriptions --- --- ---       */


/* --- Module CPM-OriginatingStationContainers --- --- ---                    */


/* --- Module CPM-PDU-Descriptions --- --- ---                                */


/* --- Module CPM-PerceivedObjectContainer --- --- ---                        */


/* --- Module CPM-PerceptionRegionContainer --- --- ---                       */


/* --- Module CPM-SensorInformationContainer --- --- ---                      */


/* --- Module VAM-PDU-Descriptions --- --- ---                                */


/* --- Module IMZM-PDU-Descriptions --- --- ---                               */



/* --- Module ETSI-ITS-CDD --- --- ---                                        */


typedef enum _CauseCodeType_enum {
  trafficCondition =   1,
  accident     =   2,
  roadworks    =   3,
  impassability =   5,
  adverseWeatherCondition_Adhesion =   6,
  aquaplaning  =   7,
  hazardousLocation_SurfaceCondition =   9,
  hazardousLocation_ObstacleOnTheRoad =  10,
  hazardousLocation_AnimalOnTheRoad =  11,
  humanPresenceOnTheRoad =  12,
  wrongWayDriving =  14,
  rescueAndRecoveryWorkInProgress =  15,
  adverseWeatherCondition_ExtremeWeatherCondition =  17,
  adverseWeatherCondition_Visibility =  18,
  adverseWeatherCondition_Precipitation =  19,
  violence     =  20,
  slowVehicle  =  26,
  dangerousEndOfQueue =  27,
  publicTransportVehicleApproaching =  28,
  vehicleBreakdown =  91,
  postCrash    =  92,
  humanProblem =  93,
  stationaryVehicle =  94,
  emergencyVehicleApproaching =  95,
  hazardousLocation_DangerousCurve =  96,
  collisionRisk =  97,
  signalViolation =  98,
  dangerousSituation =  99,
  railwayLevelCrossing = 100
} CauseCodeType_enum;

/* enumerated values for MessageId */
#define ITS_DENM       1
#define ITS_CAM        2
#define ITS_POIM       3
#define ITS_SPATEM     4
#define ITS_MAPEM      5
#define ITS_IVIM       6
#define ITS_RFU1       7
#define ITS_RFU2       8
#define ITS_SREM       9
#define ITS_SSEM      10
#define ITS_EVCSN     11
#define ITS_SAEM      12
#define ITS_RTCMEM    13
#define ITS_CPM       14
#define ITS_IMZM      15
#define ITS_VAM       16
#define ITS_DSM       17
#define ITS_PCIM      18
#define ITS_PCVM      19
#define ITS_MCM       20
#define ITS_PAM       21

/* --- Module ITS-ContainerV1 --- --- ---                                     */


/* --- Module AVIAEINumberingAndDataStructures --- --- ---                    */


/* --- Module EfcDsrcApplication --- --- ---                                  */


/* --- Module DSRC --- --- ---                                                */

#define mapData                        18
#define rtcmCorrections                28
#define signalPhaseAndTimingMessage    19
#define signalRequestMessage           29
#define signalStatusMessage            30

typedef enum _RegionId_enum {
  noRegion     =   0,
  addGrpA      =   1,
  addGrpB      =   2,
  addGrpC      =   3
} RegionId_enum;

/* --- Module AddGrpC --- --- ---                                             */


/* --- Module REGION --- --- ---                                              */


/* --- Module GDD --- --- ---                                                 */


/* --- Module IVI --- --- ---                                                 */


/* --- Module SPATEM-PDU-Descriptions --- --- ---                             */


/* --- Module MAPEM-PDU-Descriptions --- --- ---                              */


/* --- Module IVIM-PDU-Descriptions --- --- ---                               */


/* --- Module SREM-PDU-Descriptions --- --- ---                               */


/* --- Module SSEM-PDU-Descriptions --- --- ---                               */


/* --- Module RTCMEM-PDU-Descriptions --- --- ---                             */


/* --- Module CAMv1-PDU-Descriptions --- --- ---                              */


/* --- Module CAM-PDU-Descriptions --- --- ---                                */


/* --- Module DENMv1-PDU-Descriptions --- --- ---                             */

#define defaultValidity                600

/* --- Module DENM-PDU-Description --- --- ---                                */

#define defaultValidity                600

/* --- Module TIS-TPG-Transactions-Descriptions --- --- ---                   */


/* --- Module EVCSN-PDU-Descriptions --- --- ---                              */


/* --- Module EV-RechargingSpotReservation-PDU-Descriptions --- --- ---       */


/* --- Module CPM-OriginatingStationContainers --- --- ---                    */


/* --- Module CPM-PDU-Descriptions --- --- ---                                */


/* --- Module CPM-PerceivedObjectContainer --- --- ---                        */


/* --- Module CPM-PerceptionRegionContainer --- --- ---                       */


/* --- Module CPM-SensorInformationContainer --- --- ---                      */


/* --- Module VAM-PDU-Descriptions --- --- ---                                */


/* --- Module IMZM-PDU-Descriptions --- --- ---                               */


typedef struct its_header {
    uint32_t version;
    uint32_t msgId;
    uint32_t stationId;
    uint32_t CpmContainerId;
} its_header_t;




enum regext_type_enum {
    Reg_AdvisorySpeed,
    Reg_ComputedLane,
    Reg_ConnectionManeuverAssist,
    Reg_GenericLane,
    Reg_IntersectionGeometry,
    Reg_IntersectionState,
    Reg_LaneAttributes,
    Reg_LaneDataAttribute,
    Reg_MapData,
    Reg_MovementEvent,
    Reg_MovementState,
    Reg_NodeAttributeSetLL,
    Reg_NodeAttributeSetXY,
    Reg_NodeOffsetPointLL,
    Reg_NodeOffsetPointXY,
    Reg_Position3D,
    Reg_RequestorDescription,
    Reg_RequestorType,
    Reg_RestrictionUserType,
    Reg_RoadSegment,
    Reg_SignalControlZone,
    Reg_SignalRequest,
    Reg_SignalRequestMessage,
    Reg_SignalRequestPackage,
    Reg_SignalStatus,
    Reg_SignalStatusMessage,
    Reg_SignalStatusPackage,
    Reg_SPAT,
    Reg_RTCMcorrections,
};

#endif /* __PACKET_ITS_H__ */
