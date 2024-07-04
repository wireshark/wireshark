/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ieee1609dot2.h                                                      */
/* asn2wrs.py -q -L -p ieee1609dot2 -c ./ieee1609dot2.cnf -s ./packet-ieee1609dot2-template -D . -O ../.. IEEE1609dot2BaseTypes.asn Ieee1609Dot2CrlBaseTypes.asn Ieee1609Dot2Crl.asn Ieee1609Dot2.asn IEEE1609dot12.asn */

/* packet-IEEE1609dot2.h
 * Routines for IEEE 1609.2
 * Copyright 2018, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _IEEE1609DOT2_H_
#define _IEEE1609DOT2_H_

#include "ws_symbol_export.h"

#define p2pcd8ByteLearningRequestId    1

typedef enum _Psid_enum {
  psid_system  =   0,
  psid_electronic_fee_collection =   1,
  psid_freight_fleet_management =   2,
  psid_public_transport =   3,
  psid_traffic_traveller_information =   4,
  psid_traffic_control =   5,
  psid_parking_management =   6,
  psid_geographic_road_database =   7,
  psid_medium_range_preinformation =   8,
  psid_man_machine_interface =   9,
  psid_intersystem_interface =  10,
  psid_automatic_vehicle_identification =  11,
  psid_emergency_warning =  12,
  psid_private =  13,
  psid_multi_purpose_payment =  14,
  psid_dsrc_resource_manager =  15,
  psid_after_theft_systems =  16,
  psid_cruise_assist_highway_system =  17,
  psid_multi_purpose_information_system =  18,
  psid_multi_mobile_information_system =  19,
  psid_efc_compliance_check_communication_applications =  20,
  psid_efc_localisation_augmentation_communication_applications =  21,
  psid_iso_cen_dsrc_applications_0x16 =  22,
  psid_iso_cen_dsrc_applications_0x17 =  23,
  psid_iso_cen_dsrc_applications_0x18 =  24,
  psid_iso_cen_dsrc_applications_0x19 =  25,
  psid_iso_cen_dsrc_applications_0x1a =  26,
  psid_iso_cen_dsrc_applications_0x1b =  27,
  psid_iso_cen_dsrc_applications_0x1c =  28,
  psid_private_use_0x1d =  29,
  psid_private_use_0x1e =  30,
  psid_iso_cen_dsrc_applications_0x1f =  31,
  psid_vehicle_to_vehicle_safety_and_awarenesss =  32,
  psid_limited_sensor_vehicle_to_vehicle_safety_and_awarenesss =  33,
  psid_tracked_vehicle_safety_and_awarenesss =  34,
  psid_wave_security_managements =  35,
  psid_ca_basic_services =  36,
  psid_den_basic_services =  37,
  psid_misbehavior_reporting_for_common_applications =  38,
  psid_vulnerable_road_users_safety_applications =  39,
  psid_testings = 127,
  psid_differential_gps_corrections_uncompressed = 128,
  psid_differential_gps_corrections_compressed = 129,
  psid_intersection_safety_and_awareness = 130,
  psid_traveller_information_and_roadside_signage = 131,
  psid_mobile_probe_exchanges = 132,
  psid_emergency_and_erratic_vehicles_present_in_roadway = 133,
  psid_remote_management_protocol_execution = 134,
  psid_wave_service_advertisement = 135,
  psid_peer_to_peer_distribution_of_security_management_information = 136,
  psid_traffic_light_manoeuver_service = 137,
  psid_road_and_lane_topology_service = 138,
  psid_infrastructure_to_vehicle_information_service = 139,
  psid_traffic_light_control_requests_service = 140,
  psid_geonetworking_management_communications = 141,
  psid_certificate_revocation_list_application = 256,
  psid_traffic_light_control_status_service = 637,
  psid_collective_perception_service = 639,
  psid_vehicle_initiated_distress_notivication = 16514,
  psid_fast_service_advertisement_protocol = 2113664,
  psid_its_station_internal_management_communications_protocol = 2113665,
  psid_veniam_delay_tolerant_networking = 2113666,
  psid_transcore_software_update = 2113667,
  psid_sra_private_applications_0x204084 = 2113668,
  psid_sra_private_applications_0x204085 = 2113669,
  psid_sra_private_applications_0x204086 = 2113670,
  psid_sra_private_applications_0x204087 = 2113671,
  psid_ipv6_routing = 270549118
} Psid_enum;

/*
 * When dissecting IEEE1609.2 structure containing only unsecured data, no PSID
 * is provided inside. Caller has to provide a ITS-AID/PSID before calling the
 * dissector to have a chance to dissect the data part.
 * For signed data, PSID is provided and the caller do not have to provide the
 * PSID. If he does, the provided PSID takes precedence on the PSID inside the
 * structure.
 */
WS_DLL_PUBLIC
void ieee1609dot2_set_next_default_psid(packet_info *pinfo, uint32_t psid);

WS_DLL_PUBLIC const val64_string ieee1609dot2_Psid_vals[];

#endif /* _IEEE1609DOT2_H_ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
