/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-its.h                                                               */
/* asn2wrs.py -o its -c ./its.cnf -s ./packet-its-template -D . -O ../.. ITS-Container.asn ITS-ContainerV1.asn ISO_TS_14816.asn ISO_TS_24534-3.asn ISO_TS_17419.asn ISO_TS_14906_Application.asn ISO_TS_19091.asn GDD.asn ISO19321IVIv2.asn ETSI_TS_103301.asn CAMv1.asn CAM.asn DENMv1.asn DENM.asn TIS_TPG_Transactions_Descriptions.asn EVCSN-PDU-Descriptions.asn EV-RSR-PDU-Descriptions.asn */

/* Input file: packet-its-template.h */

#line 1 "./asn1/its/packet-its-template.h"
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


/*--- Included file: packet-its-exp.h ---*/
#line 1 "./asn1/its/packet-its-exp.h"

/* --- Module ITS-Container --- --- ---                                       */


/* --- Module ITS-ContainerV1 --- --- ---                                     */


/* --- Module AVIAEINumberingAndDataStructures --- --- ---                    */


/* --- Module ElectronicRegistrationIdentificationVehicleDataModule --- --- --- */


/* --- Module CITSapplMgmtIDs --- --- ---                                     */


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


/* --- Module DENM-PDU-Descriptions --- --- ---                               */


/* --- Module TIS-TPG-Transactions-Descriptions --- --- ---                   */


/* --- Module EVCSN-PDU-Descriptions --- --- ---                              */


/* --- Module EV-RechargingSpotReservation-PDU-Descriptions --- --- ---       */


/*--- End of included file: packet-its-exp.h ---*/
#line 17 "./asn1/its/packet-its-template.h"


/*--- Included file: packet-its-val.h ---*/
#line 1 "./asn1/its/packet-its-val.h"

/* --- Module ITS-Container --- --- ---                                       */


/* enumerated values for T_messageID */
#define ITS_DENM       1
#define ITS_CAM        2
#define ITS_POI        3
#define ITS_SPATEM     4
#define ITS_MAPEM      5
#define ITS_IVIM       6
#define ITS_EV_RSR     7
#define ITS_TISTPGTRANSACTION   8
#define ITS_SREM       9
#define ITS_SSEM      10
#define ITS_EVCSN     11
#define ITS_SAEM      12
#define ITS_RTCMEM    13

typedef enum _CauseCodeType_enum {
  reserved     =   0,
  trafficCondition =   1,
  accident     =   2,
  roadworks    =   3,
  impassability =   5,
  adverseWeatherCondition_Adhesion =   6,
  aquaplannning =   7,
  hazardousLocation_SurfaceCondition =   9,
  hazardousLocation_ObstacleOnTheRoad =  10,
  hazardousLocation_AnimalOnTheRoad =  11,
  humanPresenceOnTheRoad =  12,
  wrongWayDriving =  14,
  rescueAndRecoveryWorkInProgress =  15,
  adverseWeatherCondition_ExtremeWeatherCondition =  17,
  adverseWeatherCondition_Visibility =  18,
  adverseWeatherCondition_Precipitation =  19,
  slowVehicle  =  26,
  dangerousEndOfQueue =  27,
  vehicleBreakdown =  91,
  postCrash    =  92,
  humanProblem =  93,
  stationaryVehicle =  94,
  emergencyVehicleApproaching =  95,
  hazardousLocation_DangerousCurve =  96,
  collisionRisk =  97,
  signalViolation =  98,
  dangerousSituation =  99
} CauseCodeType_enum;

/* --- Module ITS-ContainerV1 --- --- ---                                     */


/* --- Module AVIAEINumberingAndDataStructures --- --- ---                    */


/* --- Module ElectronicRegistrationIdentificationVehicleDataModule --- --- --- */


/* --- Module CITSapplMgmtIDs --- --- ---                                     */


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

/* --- Module DENM-PDU-Descriptions --- --- ---                               */

#define defaultValidity                600

/* --- Module TIS-TPG-Transactions-Descriptions --- --- ---                   */


/* --- Module EVCSN-PDU-Descriptions --- --- ---                              */


/* --- Module EV-RechargingSpotReservation-PDU-Descriptions --- --- ---       */


/*--- End of included file: packet-its-val.h ---*/
#line 19 "./asn1/its/packet-its-template.h"

typedef struct its_header {
    guint32 version;
    guint32 msgId;
    guint32 stationId;
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
