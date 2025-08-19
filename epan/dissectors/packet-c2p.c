/* packet-c2p.c
 * Commsignia Capture Protocol dissector
 * Copyright 2025, (C) Commsignia Ltd.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/unit_strings.h>
#include <inttypes.h>


/**
Possible values for Transmission State StationInfo parameter
@note Data element is used to provide the current state of the vehicle transmission
*/
typedef enum sti_transmission_state_t {
    STI_TRANSMISSION_STATE_NEUTRAL = 0,                     /**< Neutral state */
    STI_TRANSMISSION_PARK,                                  /**< Parking state */
    STI_TRANSMISSION_FWD_GEARS,                             /**< Forward gears */
    STI_TRANSMISSION_REVERSE_GEARS                          /**< Reverse gears */
} sti_transmission_state_t;

/**
Possible values for Auxiliary Brake StationInfo parameter
@note The status of the auxiliary brakes (sometimes referred to as the
      parking brake) of the vehicle. The auxiliary brakes are in a fully
      released (Off) state or in an engaged or in the process of
      being engaged (On) state

@see Dedicated Short Range Communications (DSRC) Message Set Dictionary
     SAE J2735_201603 Chapter 7.14 DE_AuxiliaryBrakeStatus
*/
typedef enum sti_aux_brakes_t {
    STI_AUX_BRAKES_OFF = 0,                                 /**< Vehicle's Aux Brakes are off */
    STI_AUX_BRAKES_ON                                       /**< Vehicle's Aux Brakes are on (engaged) */
} sti_aux_brakes_t;

/**
Possible values for Vehicle Length Confidence StationInfo parameter
@note To indicate whether the presence of a trailer is detectable or
      whether its length is included in a reported vehicle length value.

@see Intelligent Transport Systemst (ITS); User and application requirements
     ETSI TS 102 894-2 V1.3.1; Part2; Annex 91 - DE_VehicleLengthConfidenceIndication
*/
typedef enum sti_vehicle_length_conf_t {
    STI_VEHICLE_LENGTH_CONF_NO_TRAILER = 0,                 /**< No trailer is present */
    STI_VEHICLE_LENGTH_CONF_TRAILER_WITH_LENGTH,            /**< Trailer present with known length */
    STI_VEHICLE_LENGTH_CONF_TRAILER_WITH_NA_LENGTH,         /**< Trailer present with unknown length */
    STI_VEHICLE_LENGTH_CONF_TRAILER_PRESENCE_IS_UNK         /**< Trailer presence is unknown */
} sti_vehicle_length_conf_t;

/**
Possible values for Dangerous Goods StationInfo parameter
@note Indicates the type of the dangerous goods being carried by a heavy vehicle.

@see European Agreement (Applicable as from 1 January 2011): "Concerning the International Carriage
     of Dangerous Goods by Road" part II, chapter 2.1.1.1
@see Available at http://www.unece.org/trans/danger/publi/adr/adr2011/11ContentsE.html
*/
typedef enum sti_dangerous_good_t {
    STI_DANGEROUS_GOODS_EXPLOSIVES1 = 0,                    /**< Explosive substance type 1 */
    STI_DANGEROUS_GOODS_EXPLOSIVES2,                        /**< Explosive substance type 2 */
    STI_DANGEROUS_GOODS_EXPLOSIVES3,                        /**< Explosive substance type 3 */
    STI_DANGEROUS_GOODS_EXPLOSIVES4,                        /**< Explosive substance type 4 */
    STI_DANGEROUS_GOODS_EXPLOSIVES5,                        /**< Explosive substance type 5 */
    STI_DANGEROUS_GOODS_EXPLOSIVES6,                        /**< Explosive substance type 6 */
    STI_DANGEROUS_GOODS_FLAMMABLE_GASES,                    /**< Flammable gases */
    STI_DANGEROUS_GOODS_NON_FLAMMABLE_GASES,                /**< Non flammable gases */
    STI_DANGEROUS_GOODS_TOXIC_GASES,                        /**< Toxic gases */
    STI_DANGEROUS_GOODS_FLAMMABLE_LIQUIDS,                  /**< Flammable liquids */
    STI_DANGEROUS_GOODS_FLAMMABLE_SOLIDS,                   /**< Flammable solids */
    STI_DANGEROUS_GOODS_SUBSTANCES_SPONTAIN_COMBUSTION,     /**< Substances liable to spontaneous combustion */
    STI_DANGEROUS_GOODS_SUBSTANCES_FLAMBLE_CONTACT_WATER,   /**< Substances emitting flammable gases upon contact with water */
    STI_DANGEROUS_GOODS_OXIDIZING_SUBSTANCES,               /**< Oxidizing substances */
    STI_DANGEROUS_GOODS_ORGANIC_PEROXIDES,                  /**< Organic peroxides */
    STI_DANGEROUS_GOODS_TOXIC_SUBSTANCES,                   /**< Toxic substances */
    STI_DANGEROUS_GOODS_INFECTIOUS_SUBSTANCES,              /**< Infectious substances */
    STI_DANGEROUS_GOODS_RADIOACTIVE_MATERIAL,               /**< Radioactive material */
    STI_DANGEROUS_GOODS_CORROSIVE_SUBSTANCES,               /**< Corrosive substances */
    STI_DANGEROUS_GOODS_MISC_DANGEROUS_SUBSTANCES           /**< Miscellaneous dangerous substances */
} sti_dangerous_good_t;

/**
Possible values for Station type parameter
@note Not to be confused with vehicle role. It may seem redundant,
      but while class doesn't change for the lifetime of the vehicle,
      role may change based on what it's doing currently.
@note It is used to provide a common classification system to categorize DSRC
      equipped devices for various cross-cutting uses. Several other
      classification systems in this data dictionary can be used to provide
      more domain specific detail when required.

@see Dedicated Short Range Communications (DSRC) Message Set Dictionary
     SAE J2735_201603 Chapter 7.15 DE_BasicVehicleClass
*/
typedef enum sti_station_type_t {
    STI_STATION_TYPE_UNK = 0,                              /**< Not equipped, not known or unavailable */
    STI_STATION_TYPE_SPECIAL,                              /**< Special use */
    STI_STATION_TYPE_PASSENGER_UNK,                        /**< Unknown type passenger vehicle */
    STI_STATION_TYPE_PASSENGER_OTHER,                      /**< Other type passenger vehicle */
    STI_STATION_TYPE_LIGHT_TRUCK_UNK,                      /**< Unknown type light truck */
    STI_STATION_TYPE_LIGHT_TRUCK_OTHER,                    /**< Other type light truck */
    STI_STATION_TYPE_TRUCK_UNK,                            /**< Unknown type truck */
    STI_STATION_TYPE_TRUCK_OTHER,                          /**< Other type truck */
    STI_STATION_TYPE_TRUCK_AXLE_CNT_2,                     /**< Two axle, six tire single units */
    STI_STATION_TYPE_TRUCK_AXLE_CNT_3,                     /**< Three axle single units */
    STI_STATION_TYPE_TRUCK_AXLE_CNT_4,                     /**< Four or more axle single unit */
    STI_STATION_TYPE_TRUCK_AXLE_CNT_4_TRAILER,             /**< Four or less axle single trailer */
    STI_STATION_TYPE_TRUCK_AXLE_CNT_5_TRAILER,             /**< Five or less axle single trailer */
    STI_STATION_TYPE_TRUCK_AXLE_CNT_6_TRAILER,             /**< Six or more axle single trailer */
    STI_STATION_TYPE_TRUCK_AXLE_CNT_5_MULTI_TRAILER,       /**< Five or less axle multi-trailer */
    STI_STATION_TYPE_TRUCK_AXLE_CNT_6_MULTI_TRAILER,       /**< Six axle multi-trailer */
    STI_STATION_TYPE_TRUCK_AXLE_CNT_7_MULTI_TRAILER,       /**< Seven or more axle multi-trailer */
    STI_STATION_TYPE_MOTORCYCLE_UNK,                       /**< Unknown type motorcycle */
    STI_STATION_TYPE_MOTORCYCLE_OTHER,                     /**< Other type motorcycle */
    STI_STATION_TYPE_MOTORCYCLE_CRUISER_STANDARD,          /**< Cruiser standard motorcycle */
    STI_STATION_TYPE_MOTORCYCLE_SPORT_UNCLAD,              /**< Unclad sport motorcycle */
    STI_STATION_TYPE_MOTORCYCLE_SPORT_TOURING,             /**< Sport touring motorcycle */
    STI_STATION_TYPE_MOTORCYCLE_SUPER_SPORT,               /**< Super sport motorcycle */
    STI_STATION_TYPE_MOTORCYCLE_TOURING,                   /**< Touring motorcycle */
    STI_STATION_TYPE_MOTORCYCLE_TRIKE,                     /**< Trike motorcycle */
    STI_STATION_TYPE_MOTORCYCLE_WITH_PASSENGERS,           /**< Motorcycle with passengers */
    STI_STATION_TYPE_TRANSIT_UNK,                          /**< Unknown type transit */
    STI_STATION_TYPE_TRANSIT_OTHER,                        /**< Other type transit */
    STI_STATION_TYPE_TRANSIT_BRT,                          /**< Bus rapid transit */
    STI_STATION_TYPE_TRANSIT_EXPRESS_BUS,                  /**< Express bus */
    STI_STATION_TYPE_TRANSIT_LOCAL_BUS,                    /**< Local bus */
    STI_STATION_TYPE_TRANSIT_SCHOOL_BUS,                   /**< School bus */
    STI_STATION_TYPE_TRANSIT_FIXED_GUIDE_WAY,              /**< Fixed guideway transit, like tram */
    STI_STATION_TYPE_TRANSIT_PARATRANSIT,                  /**< Paratransit */
    STI_STATION_TYPE_TRANSIT_PARATRANSIT_AMBULANCE,        /**< Paratransit ambulance */
    STI_STATION_TYPE_EMERGENCY_UNK,                        /**< Unknown type emergency vehicle */
    STI_STATION_TYPE_EMERGENCY_OTHER,                      /**< Other type emergency vehicle */
    STI_STATION_TYPE_EMERGENCY_FIRE_LIGHT,                 /**< Light fire emergency vehicle */
    STI_STATION_TYPE_EMERGENCY_FIRE_HEAVY,                 /**< Heavy fire emergency vehicle */
    STI_STATION_TYPE_EMERGENCY_FIRE_PARAMEDIC,             /**< Fire paramedic emergency vehicle */
    STI_STATION_TYPE_EMERGENCY_FIRE_AMBULANCE,             /**< Fire ambulance emergency vehicle */
    STI_STATION_TYPE_EMERGENCY_POLICE_LIGHT,               /**< Light police emergency vehicle */
    STI_STATION_TYPE_EMERGENCY_POLICE_HEAVY,               /**< Heavy police emergency vehicle */
    STI_STATION_TYPE_EMERGENCY_OTHER_RESPONDER,            /**< Other type responder emergency vehicle */
    STI_STATION_TYPE_EMERGENCY_OTHER_AMBULANCE,            /**< Other type ambulance emergency vehicle */
    STI_STATION_TYPE_OTHER_UNK,                            /**< DSRC equipped unknown type other traveler */
    STI_STATION_TYPE_OTHER_OTHER,                          /**< DSRC equipped other type other traveler */
    STI_STATION_TYPE_OTHER_PEDESTRIAN,                     /**< DSRC equipped other type pedestrian */
    STI_STATION_TYPE_OTHER_VISUALLY_DISABLED,              /**< DSRC equipped visually disabled other traveler */
    STI_STATION_TYPE_OTHER_PHYSICALLY_DISABLED,            /**< DSRC equipped physically disabled other traveler */
    STI_STATION_TYPE_OTHER_BICYCLE,                        /**< DSRC equipped bicycle */
    STI_STATION_TYPE_OTHER_VULNERABLE_ROADWORKER,          /**< DSRC equipped vulnerable road worker */
    STI_STATION_TYPE_INFRASTRUCTURE_UNK,                   /**< DSRC equipped unknown type device */
    STI_STATION_TYPE_INFRASTRUCTURE_FIXED,                 /**< DSRC equipped fixed device, typically Road Side Units (RSU) */
    STI_STATION_TYPE_INFRASTRUCTURE_MOVABLE,               /**< DSRC equipped movable device */
    STI_STATION_TYPE_EQUIPPED_CARGO_TRAILER,               /**< DSRC equipped cargo trailer */
    STI_STATION_TYPE_LIGHT_VRU_VEHICLE,                    /**< Micrmomobility users (EU CDD release 2) */
    STI_STATION_TYPE_ANIMAL                                /**< DSRC equipped animals (EU CDD release 2) */
} sti_station_type_t;

/**
Possible values for Basic Vehicle Role StationInfo parameter
@note Not to be confused with vehicle class. It may seem redundant,
      but while class doesn't change for the lifetime of the vehicle,
      role may change based on what it's doing currently,
      e.g. simple passenger vehicle can be a safety car while it's in service,
      but a basic vehicle when it's not.

@see Intelligent Transport Systemst (ITS); User and application requirements
     ETSI TS 102 894-2 V1.3.1; Part2; Annex 94 - DE_VehicleRole
@see Dedicated Short Range Communications (DSRC) Message Set Dictionary
     SAE J2735_201603 Chapter 7.16 DE_BasicVehicleRole
*/
typedef enum sti_vehicle_role_t {
    STI_VEHICLE_ROLE_BASIC_VEHICLE = 0,                     /**< Default vehicle role as indicated by the vehicle type */
    STI_VEHICLE_ROLE_PUBLIC_TRANSPORT,                      /**< Vehicle is used to operate public transport service */
    STI_VEHICLE_ROLE_SPECIAL_TRANSPORT,                     /**< Vehicle is used for special transport purpose, like oversized trucks */
    STI_VEHICLE_ROLE_DANGEROUS_GOODS,                       /**< Vehicle is used for dangerous goods transportation */
    STI_VEHICLE_ROLE_ROAD_WORK,                             /**< Vehicle is used to realize roadwork or road maintenance mission */
    STI_VEHICLE_ROLE_RESCUE,                                /**< Vehicle is used for rescue purpose in case of an accident, like as a towing service */
    STI_VEHICLE_ROLE_EMERGENCY,                             /**< Vehicle is used for emergency mission, like ambulance, fire brigade */
    STI_VEHICLE_ROLE_SAFETY_CAR,                            /**< Vehicle is used for public safety, like patrol */
    STI_VEHICLE_ROLE_TRUCK,                                 /**< Heavy trucks with additional BSM rights and obligations */
    STI_VEHICLE_ROLE_MOTORCYCLE,                            /**< Motorcycle role */
    STI_VEHICLE_ROLE_ROAD_SIDE_SOURCE,                      /**< For infrastructure generated calls such as fire house, rail infrastructure, roadwork site, etc. */
    STI_VEHICLE_ROLE_POLICE,                                /**< Police role */
    STI_VEHICLE_ROLE_FIRE,                                  /**< Fire role */
    STI_VEHICLE_ROLE_AMBULANCE,                             /**< (does not include private para-transit etc.) */
    STI_VEHICLE_ROLE_DOT,                                   /**< All roadwork vehicles */
    STI_VEHICLE_ROLE_TRANSIT,                               /**< All transit vehicles */
    STI_VEHICLE_ROLE_SLOW_MOVING,                           /**< Also include oversize etc. */
    STI_VEHICLE_ROLE_STOP_N_GO,                             /**< To include trash trucks, school buses and others that routinely disturb the free flow of traffic */
    STI_VEHICLE_ROLE_CYCLIST,                               /**< Cyclist role */
    STI_VEHICLE_ROLE_PEDESTRIAN,                            /**< Also includes those with mobility limitations */
    STI_VEHICLE_ROLE_NON_MOTORIZED,                         /**< other, such as horse drawn */
    STI_VEHICLE_ROLE_MILITARY,                              /**< Military role */
    STI_VEHICLE_ROLE_AGRICULTURE,                           /**< Vehicle is used for agriculture, like farm tractor */
    STI_VEHICLE_ROLE_COMMERCIAL,                            /**< Vehicle is used for transportation of commercial goods */
    STI_VEHICLE_ROLE_ROAD_OPERATOR,                         /**< Vehicle is used in road operator missions */
    STI_VEHICLE_ROLE_TAXI                                   /**< Vehicle is used to provide an authorized taxi service */
} sti_vehicle_role_t;

/**
Possible values for Weather Precipitation Situation StationInfo parameter
@note Describes the weather situation in terms of precipitation.
*/
typedef enum sti_weather_precip_situation_t {
    STI_WEATHER_PRECIP_SITUATON_OTHER = 0,                  /**< Other type precipitation */
    STI_WEATHER_PRECIP_SITUATON_UNK,                        /**< Unknown type precipitation */
    STI_WEATHER_PRECIP_SITUATON_NO_PRECIP,                  /**< No precipitation */
    STI_WEATHER_PRECIP_SITUATON_UNK_SLIGHT,                 /**< Unknown type slight precipitation */
    STI_WEATHER_PRECIP_SITUATON_UNK_MODERATE,               /**< Unknown type moderate precipitation */
    STI_WEATHER_PRECIP_SITUATON_UNK_HEAVY,                  /**< Unknown type heavy precipitation */
    STI_WEATHER_PRECIP_SITUATON_SNOW_SLIGHT,                /**< Slight snow precipitation */
    STI_WEATHER_PRECIP_SITUATON_SNOW_MODERATE,              /**< Moderate snow precipitation */
    STI_WEATHER_PRECIP_SITUATON_SNOW_HEAVY,                 /**< Heavy snow precipitation */
    STI_WEATHER_PRECIP_SITUATON_RAIN_SLIGHT,                /**< Slight rain precipitation */
    STI_WEATHER_PRECIP_SITUATON_RAIN_MODERATE,              /**< Moderate rain precipitation */
    STI_WEATHER_PRECIP_SITUATON_RAIN_HEAVY,                 /**< Heavy rain precipitation */
    STI_WEATHER_PRECIP_SITUATON_FROZEN_PRECIP_SLIGHT,       /**< Slight frozen precipitation */
    STI_WEATHER_PRECIP_SITUATON_FROZEN_PRECIP_MODERATE,     /**< Moderate frozen precipitation */
    STI_WEATHER_PRECIP_SITUATON_FROZEN_PRECIP_HEAVY         /**< Heavy frozen precipitation */
} sti_weather_precip_situation_t;

/**
Possible values for Wiper State StationInfo parameter
@note It is intended to inform other users whether or not it was
      raining/snowing at the vehicle's location at the time it was taken.
      The element also includes whether the wipers were turned on manually
      (driver activated) or automatically (rain sensor activated) to provide
      additional information as to driving conditions in the area of the vehicle.

@see Dedicated Short Range Communications (DSRC) Message Set Dictionary
     SAE J2735_201603 Chapter 7.227 DE_WiperStatus
*/
typedef enum sti_wiper_state_t {
    STI_WIPER_STATE_OFF = 0,                                /**< Off state */
    STI_WIPER_STATE_INTERMITTENT,                           /**< Intermittent state */
    STI_WIPER_STATE_LOW,                                    /**< Low state */
    STI_WIPER_STATE_HIGH,                                   /**< High state */
    STI_WIPER_STATE_WASHER_IN_USE,                          /**< Washer in use */
    STI_WIPER_STATE_AUTO                                    /**< Auto wiper state */
} sti_wiper_state_t;

/**
Possible values for Lightbar StationInfo parameter
@note It is intended to inform if any sort of additional visible
      lighting-alerting system is currently in use by a vehicle.
      This includes light bars and the various symbols they can indicate
      as well as arrow boards, flashing lights (including back up alerts),
      and any other form of lighting not found on normal vehicles of this type
      or related to safety systems. Used to reflect any type or style of visual
      alerting when a vehicle is progressing and transmitting DSRC messages
      to other nearby vehicles about its path.
*/
typedef enum sti_lightbar_t {
    STI_LIGHTBAR_NOT_IN_USE = 0,                            /**< There is a lightbar, but it is currently not in use */
    STI_LIGHTBAR_IN_USE,                                    /**< Lightbar in use */
    STI_LIGHTBAR_YELLOW_CAUTION_LIGHTS,                     /**< Yellow caution lights */
    STI_LIGHTBAR_SCHOOL_BUS_LIGHTS,                         /**< School bus lights */
    STI_LIGHTBAR_ARROW_SIGNS_ACTIVE,                        /**< Arrow signs active */
    STI_LIGHTBAR_SLOW_MOVING_VEHICLE,                       /**< Slow moving vehicle lights */
    STI_LIGHTBAR_FREQ_STOPS                                 /**< Freq stops */
} sti_lightbar_t;

/**
Possible values for Siren StationInfo parameter
@note A data element which is set if any sort of audible alarm is being
      emitted from the vehicle. This includes various common sirens as well
      as backup beepers and other slow speed maneuvering alerts.

@see Dedicated Short Range Communications (DSRC) Message Set Dictionary
     SAE J2735_201603 Chapter 7.174 DE_SirenInUse
*/
typedef enum sti_siren_t {
    STI_SIREN_NOT_IN_USE = 0,                               /**< Siren not in use */
    STI_SIREN_IN_USE                                        /**< Siren in use */
} sti_siren_t;

/**
Possible values for Lane Position StationInfo parameter
@note Data frame is used to provide information regarding
      what lane a subject vehicle (or other object) is in.
      ETSI TS 102 894-2 V1.3.1 supports only 13 lanes.
*/
typedef enum sti_lane_pos_t {
    STI_LANE_POSITION_INNER_HARD_SHOULDER = 0,              /**< Inner hard shoulder position */
    STI_LANE_POSITION_INNERMOST_DRIVING_LANE,               /**< Innermost driving lane */
    STI_LANE_POSITION_SECOND_LANE_FROM_INSIDE,              /**< Second lane from inside */
    STI_LANE_POSITION_THIRD_LANE_FROM_INSIDE,               /**< Third lane from inside */
    STI_LANE_POSITION_FOURTH_LANE_FROM_INSIDE,              /**< Fourth lane from inside */
    STI_LANE_POSITION_FIFTH_LANE_FROM_INSIDE,               /**< Fifth lane from inside */
    STI_LANE_POSITION_SIXTH_LANE_FROM_INSIDE,               /**< Sixth lane from inside */
    STI_LANE_POSITION_SEVENTH_LANE_FROM_INSIDE,             /**< Seventh lane from inside */
    STI_LANE_POSITION_EIGHTH_LANE_FROM_INSIDE,              /**< Eighth lane from inside */
    STI_LANE_POSITION_NINTH_LANE_FROM_INSIDE,               /**< Ninth lane from inside */
    STI_LANE_POSITION_TENTH_LANE_FROM_INSIDE,               /**< Tenth lane from inside */
    STI_LANE_POSITION_ELEVENTH_LANE_FROM_INSIDE,            /**< Eleventh lane from inside */
    STI_LANE_POSITION_TWELFTH_LANE_FROM_INSIDE,             /**< Twelfth lane from inside */
    STI_LANE_POSITION_THIRTEENTH_LANE_FROM_INSIDE,          /**< Thirteenth lane from inside */
    STI_LANE_POSITION_FOURTEENTH_LANE_FROM_INSIDE,          /**< Fourteenth lane from inside */
    STI_LANE_POSITION_FIFTEENTH_LANE_FROM_INSIDE,           /**< Fifteenth lane from inside */
    STI_LANE_POSITION_SIXTEENTH_LANE_FROM_INSIDE,           /**< Sixteenth lane from inside */
    STI_LANE_POSITION_SEVENTEENTH_LANE_FROM_INSIDE,         /**< Seventeenth lane from inside */
    STI_LANE_POSITION_EIGHTEENTH_LANE_FROM_INSIDE,          /**< Eighteenth lane from inside */
    STI_LANE_POSITION_NINETEENTH_LANE_FROM_INSIDE,          /**< Nineteenth lane from inside */
    STI_LANE_POSITION_TWENTIETH_LANE_FROM_INSIDE,           /**< Twentieth lane from inside */
    STI_LANE_POSITION_TWENTY_FIRST_LANE_FROM_INSIDE,        /**< Twenty-first lane from inside */
    STI_LANE_POSITION_TWENTY_SECOND_LANE_FROM_INSIDE,       /**< Twenty-second lane from inside */
    STI_LANE_POSITION_TWENTY_THIRD_LANE_FROM_INSIDE,        /**< Twenty-third lane from inside */
    STI_LANE_POSITION_TWENTY_FOURTH_LANE_FROM_INSIDE,       /**< Twenty-fourth lane from inside */
    STI_LANE_POSITION_TWENTY_FIFTH_LANE_FROM_INSIDE,        /**< Twenty-fifth lane from inside */
    STI_LANE_POSITION_TWENTY_SIXTH_LANE_FROM_INSIDE,        /**< Twenty-sixth lane from inside */
    STI_LANE_POSITION_TWENTY_SEVENTH_LANE_FROM_INSIDE,      /**< Twenty-seventh lane from inside */
    STI_LANE_POSITION_TWENTY_EIGHTH_LANE_FROM_INSIDE,       /**< Twenty-eighth lane from inside */
    STI_LANE_POSITION_TWENTY_NINTH_LANE_FROM_INSIDE,        /**< Twenty-ninth lane from inside */
    STI_LANE_POSITION_THIRTIETH_LANE_FROM_INSIDE,           /**< Thirtieth lane from inside */
    STI_LANE_POSITION_THIRTY_FIRST_LANE_FROM_INSIDE,        /**< Thirty-first lane from inside */
    STI_LANE_POSITION_THIRTY_SECOND_LANE_FROM_INSIDE,       /**< Thirty-second lane from inside */
    STI_LANE_POSITION_OUTER_HARD_SHOULDER,                  /**< Outer hard shoulder position */
    STI_LANE_POSITION_OFF_THE_ROAD                          /**< Off the road position */
} sti_lane_pos_t;

/**
Possible values for fuel type
*/
typedef enum sti_fuel_type_t {
    STI_FUEL_TYPE_GASOLINE = 0,                             /**< Gasoline fuel type */
    STI_FUEL_TYPE_ETHANOL,                                  /**< Ethanol fuel type */
    STI_FUEL_TYPE_DIESEL,                                   /**< Diesel fuel type */
    STI_FUEL_TYPE_ELECTRIC,                                 /**< Electric fuel type */
    STI_FUEL_TYPE_HYBRID,                                   /**< Hybrid fuel type */
    STI_FUEL_TYPE_HYDROGEN,                                 /**< Hydrogen fuel type */
    STI_FUEL_TYPE_NAT_GAS_LIQUID,                           /**< NAT gas liquefied fuel type */
    STI_FUEL_TYPE_NAT_GAS_COMP,                             /**< NAT gas compressed fuel type */
    STI_FUEL_TYPE_PROPANE,                                  /**< Propane fuel type */
} sti_fuel_type_t;

/**
Possible values for environment area type
*/
typedef enum sti_area_type_t {
    STI_AREA_TYPE_RURAL = 0,                                /**< Rural area */
    STI_AREA_TYPE_URBAN,                                    /**< Urban area */
} sti_area_type_t;

/**
Possible values for door state related StationInfo parameters
*/
typedef enum sti_door_state_t {
    STI_DOOR_STATE_NA = 0,                                  /**< N/A state */
    STI_DOOR_STATE_CLOSED,                                  /**< Closed state */
    STI_DOOR_STATE_OPEN,                                    /**< Open state */
} sti_door_state_t;

/**
Possible values for belt buckle state related StationInfo parameters
*/
typedef enum sti_belt_buckle_status_t {
    STI_BELT_BUCKLE_DISCONNECTED = 0,                       /**< Belt buckle is disconnected */
    STI_BELT_BUCKLE_CONNECTED,                              /**< Belt buckle is connected */
} sti_belt_buckle_status_t;

/**
Possible values for Transmission type
*/
typedef enum sti_transmission_type_t {
    STI_TRANSMISSION_TYPE_AUTOMATIC = 0,                    /**< Transmission type is automatic */
    STI_TRANSMISSION_TYPE_MANUAL,                           /**< Transmission type is manual */
} sti_transmission_type_t;

/**
Possible values for presence of physical separation between own and oncoming lanes of the road/highway
*/
typedef enum sti_physical_road_separation_t {
    STI_PHYSICAL_ROAD_SEPARATION_NOT_PRESENT = 0,           /**< Physical separation is not present */
    STI_PHYSICAL_ROAD_SEPARATION_PRESENT                    /**< Physical separation is present */
} sti_physical_road_separation_t;

/**
Possible values for RoadClass parameter
*/
typedef enum sti_road_class_t {
    STI_ROAD_CLASS_UNKNOWN = 0,                             /**< Unknown road class */
    STI_ROAD_CLASS_MOTORWAY,                                /**< Motorway road class */
    STI_ROAD_CLASS_COUNTRY_ROAD,                            /**< Country road road class */
    STI_ROAD_CLASS_LOCAL_ROAD,                              /**< Local road road class */
} sti_road_class_t;

/**
Possible values for rule of the road
*/
typedef enum sti_road_rule_t {
    STI_ROAD_RULE_RIGHT_HAND_TRAFFIC = 0,                   /**< Right-hand traffic */
    STI_ROAD_RULE_LEFT_HAND_TRAFFIC,                        /**< Left-hand traffic */
} sti_road_rule_t;

/**
Possible values for StationInfo parameters which have two states
*/
typedef enum sti_state_t {
    STI_STATE_OFF = 0,                                      /**< Off state */
    STI_STATE_ON                                            /**< On state */
} sti_state_t;

/**
Possible values for StationInfo parameters which have three states
*/
typedef enum sti_tristate_t {
    STI_TRISTATE_OFF = 0,                                   /**< Off state */
    STI_TRISTATE_ON,                                        /**< On or active (but not engaged) state */
    STI_TRISTATE_ENGAGED                                    /**< Engaged state */
} sti_tristate_t;


typedef enum sti_type_t {

    /**
    Transmission state
    @type [enum]
    @see sti_transmission_state_t
    */
    STI_TRANSMISSION_STATE = 0,

    /**
    Steering wheel angle.
    @note Do not confuse with driving wheel angle.
          The steering wheel is what the driver holds in their hands,
          the driving wheel is what touches the ground.
    @type [angle]
    @unit [0.001 degree] CCW positive
    */
    STI_STEERING_WHEEL_ANGLE,

    /**
    Steering wheel angle confidence
    @type [angle]
    @unit [0.001 degree]
    */
    STI_STEERING_WHEEL_ANGLE_CONF,

    /**
    Steering wheel angle rate
    @type [angular velocity]
    @unit [0.001 degree/second]
    */
    STI_STEERING_WHEEL_ANGLE_RATE,

    /**
    Driving wheel angle
    @note Do not confuse with steering wheel angle.
          The steering wheel is what the driver holds in their hands,
          the driving wheel is what touches the ground.
    @type [angle]
    @unit [0.001 degree]
    */
    STI_DRIVING_WHEEL_ANGLE,

    /**
    Longitudinal acceleration
    @type [acceleration]
    @unit [mm/s^2]
    */
    STI_LONG_ACC,

    /**
    Longitudinal acceleration confidence
    @type [acceleration]
    @unit [mm/s^2]
    */
    STI_LONG_ACC_CONF,

    /**
    Lateral acceleration
    @type [acceleration]
    @unit [mm/s^2]
    */
    STI_LAT_ACC,

    /**
    Lateral acceleration confidence
    @type [acceleration]
    @unit [mm/s^2]
    */
    STI_LAT_ACC_CONF,

    /**
    Vertical acceleration
    @note If the car is standing still, this should be 0, i.e.
          gravity is not included in this value.
    @type [acceleration]
    @unit [mm/s^2]
    */
    STI_VERT_ACC,

    /**
    Vertical acceleration confidence
    @type [acceleration]
    @unit [mm/s^2]
    */
    STI_VERT_ACC_CONF,

    /**
    Yaw rate
    @type [angular velocity]
    @unit [0.001 degree/second] CCW positive
    */
    STI_YAW_RATE,

    /**
    Yaw rate confidence
    @type [angular velocity]
    @unit [0.001 degree/second]
    */
    STI_YAW_RATE_CONF,

    /**
    Front left brake applied pressure
    @type [thousandths]
    @unit [parts-per-thousand]
    */
    STI_BRAKE_STATUS_LEFT_FRONT,

    /**
    Rear left brake applied pressure
    @type [thousandths]
    @unit [parts-per-thousand]
    */
    STI_BRAKE_STATUS_LEFT_REAR,

    /**
    Front right brake applied pressure
    @type [thousandths]
    @unit [parts-per-thousand]
    */
    STI_BRAKE_STATUS_RIGHT_FRONT,

    /**
    Rear right brake applied pressure
    @type [thousandths]
    @unit [parts-per-thousand]
    */
    STI_BRAKE_STATUS_RIGHT_REAR,

    /**
    Traction control status
    @type [enum]
    @see sti_tristate_t
    */
    STI_TRACTION_CONTROL_STATUS,

    /**
    Anti-lock braking system status
    @type [enum]
    @see sti_tristate_t
    */
    STI_ABS,

    /**
    Stability control status
    @type [enum]
    @see sti_tristate_t
    */
    STI_STABILITY_CONTROL_STATUS,

    /**
    Emergency brake status, also known as 'Brake boost'
    @type [enum]
    @see sti_state_t
    */
    STI_EMERGENCY_BRAKE,

    /**
    Auxiliary brake status
    @type [enum]
    @see sti_aux_brakes_t
    */
    STI_AUX_BRAKES,

    /**
    Vehicle width
    @note The width shall be the widest point of the vehicle with all
          factory installed equipment.
    @type [length]
    @unit [mm]
    */
    STI_VEHICLE_WIDTH,

    /**
    Vehicle length
    @note The length of the vehicle measured from the edge of the front
          bumper to the edge of the rear bumper.
    @type [length]
    @unit [mm]
    */
    STI_VEHICLE_LENGTH,

    /**
    Vehicle length confidence
    @type [enum]
    @see sti_vehicle_length_conf_t
    */
    STI_VEHICLE_LENGTH_CONF,

    /**
    Vehicle height
    @type [length]
    @unit [mm]
    */
    STI_VEHICLE_HEIGHT,

    /**
    Vehicle mass
    @type [mass]
    @unit [gram]
    */
    STI_VEHICLE_MASS,

    /**
    Stop line violated
    @type [enum]
    @see sti_state_t
    */
    STI_EV_STOP_LINE_VIOLATED,

    /**
    Dangerous goods present
    @note Indicates the type of the dangerous goods being carried by a heavy vehicle.
    @type [enum]
    @see sti_dangerous_good_t
    */
    STI_DANGEROUS_GOODS,

    /**
    Flat tire
    @type [enum]
    @see sti_state_t
    */
    STI_EV_FLAT_TIRE,

    /**
    Disabled vehicle
    @note An equipped vehicle that has self-declared that it is not
          performing all designed/intended functions and/or operations.
          Such a vehicle may be moving or may be stationary.
    @type [enum]
    @see sti_state_t
    */
    STI_EV_DISABLED_VEHICLE,

    /**
    Airbag deployed
    @type [enum]
    @see sti_state_t
    */
    STI_EV_AIRBAG_DEPLOYED,

    /**
    Low beam headlight status
    @type [enum]
    @see sti_state_t
    */
    STI_EXT_LIGHT_LOWBEAM_HEAD,

    /**
    High beam headlight status
    @type [enum]
    @see sti_state_t
    */
    STI_EXT_LIGHT_HIGHBEAM_HEAD,

    /**
    Left turn signal status
    @note Keep in mind that this signal should be
          a stable 'on', and should not be blinking
    @type [enum]
    @see sti_state_t
    */
    STI_EXT_LIGHT_LEFT_TURN_SIGNAL,

    /**
    Right turn signal status
    @note Keep in mind that this signal should be
          a stable 'on', and should not be blinking
    @type [enum]
    @see sti_state_t
    */
    STI_EXT_LIGHT_RIGHT_TURN_SIGNAL,

    /**
    Hazard light status status
    @note Keep in mind that this signal should be
          a stable 'on', and should not be blinking.
          This value is independent from the turn signal and signifies
          the button itself on the dashboard. If this value cannot be
          obtained independently, it should be manually set to 'on' if
          both turn signals are 'on'.
    @type [enum]
    @see sti_state_t
    */
    STI_EXT_LIGHT_HAZARD_LIGHT,

    /**
    Auto light control status status
    @type [enum]
    @see sti_state_t
    */
    STI_EXT_LIGHT_AUTO_LIGHT_CONTROL,

    /**
    Daytime running light status
    @type [enum]
    @see sti_state_t
    */
    STI_EXT_LIGHT_DAYTIME_RUNNING,

    /**
    Fog light status
    @type [enum]
    @see sti_state_t
    */
    STI_EXT_LIGHT_FOG,

    /**
    Parking light status
    @type [enum]
    @see sti_state_t
    */
    STI_EXT_LIGHT_PARKING,

    /**
    Reverse light status
    @type [enum]
    @see sti_state_t
    */
    STI_EXT_LIGHT_REVERSE,

    /**
    Station type
    @note Not to be confused with vehicle role. It may seem redundant,
          but while class doesn't change for the lifetime of the vehicle,
          role may change based on what it's doing currently.
    @type [enum]
    @see sti_station_type_t
    */
    STI_STATION_TYPE,

    /**
    Vehicle role
    @note Not to be confused with vehicle class. It may seem redundant,
          but while class doesn't change for the lifetime of the vehicle,
          role may change based on what it's doing currently,
          e.g. simple passenger vehicle can be a safety car while it's in service,
          but a basic vehicle when it's not.
    @type [enum]
    @see sti_vehicle_role_t
    */
    STI_VEHICLE_ROLE,

    /**
    Height of the front bumper
    @type [length]
    @unit [mm]
    */
    STI_BUMPER_HEIGHT_FRONT,

    /**
    Height of the rear bumper
    @type [length]
    @unit [mm]
    */
    STI_BUMPER_HEIGHT_REAR,

    /**
    Rain rate
    @type [rate]
    @unit [0.1 g/s/m^2]
    */
    STI_WEATHER_RAIN_RATE,

    /**
    Rain sensor
    @note Describes the current sensor reading normalized to a 0-1000 range,
          where 0 is completely dry, and 1000 is the highest rain value the
          sensor is capable of detecting.
          Note that this is independent from STI_WEATHER_PRECIP_SITUATON,
          which is more of a semantic value. If both are needed, they need to
          be set individually.
    @type [thousandths]
    @unit [parts-per-thousand]
    */
    STI_RAIN_SENSOR,

    /**
    Precipitation situation
    @note Describes the weather situation in terms of precipitation.
    @type [enum]
    @see sti_weather_precip_situation_t
    */
    STI_WEATHER_PRECIP_SITUATON,

    /**
    Solar radiation
    @type [solar irradiance]
    @unit [J/m^2]
    */
    STI_WEATHER_SOLAR_RADIATION,

    /**
    Coefficient of friction
    @type [thousandths]
    @unit [parts-per-thousand]
    */
    STI_WEATHER_COEF_FRICTION,

    /**
    Ambient air temperature
    @type [temperature]
    @unit [0.1C°]
    */
    STI_WEATHER_AIR_TEMP,

    /**
    Ambient air pressure
    @type [pressure]
    @unit [Pascal]
    */
    STI_WEATHER_AIR_PRESSURE,

    /**
    Front wiper state
    @type [enum]
    @see sti_wiper_state_t
    */
    STI_WIPER_STATE_FRONT,

    /**
    Rear wiper state
    @type [enum]
    @see sti_wiper_state_t
    */
    STI_WIPER_STATE_REAR,

    /**
    Front wiper rate
    @note Usually only makes sense if the wiper state is also set to a
          correct value. This has to be done manually.
    @type [rate]
    @unit [sweeps/minute]
    */
    STI_WIPER_RATE_FRONT,

    /**
    Rear wiper rate
    @note Usually only makes sense if the wiper state is also set to a
          correct value. This has to be done manually.
    @type [rate]
    @unit [sweeps/minute]
    */
    STI_WIPER_RATE_REAR,

    /**
    Embarkation status
    @type [enum]
    @see sti_state_t
    */
    STI_EMBARKATION_STATUS,

    /**
    Lightbar status
    @note It is intended to inform if any sort of additional visible
          lighting-alerting system is currently in use by a vehicle.
    @type [enum]
    @see sti_lightbar_t
    */
    STI_LIGHTBAR,

    /**
    Siren status
    @note A data element which is set if any sort of audible alarm is being
          emitted from the vehicle.
    @type [enum]
    @see sti_siren_t
    */
    STI_SIREN,

    /**
    Accelerator pedal position
    @type [thousandths]
    @unit [parts-per-thousand]
    */
    STI_ACCELERATOR_PEDAL,

    /**
    Brake pedal position
    @type [thousandths]
    @unit [parts-per-thousand]
    */
    STI_BRAKE_PEDAL,

    /**
    Collision warning
    @type [enum]
    @see sti_state_t
    */
    STI_COLLISION_WARNING,

    /**
    Adaptive cruise control status
    @type [enum]
    @see sti_state_t
    */
    STI_ADAPTIVE_CRUISE_CONTROL,

    /**
    Cruise control status
    @type [enum]
    @see sti_state_t
    */
    STI_CRUISE_CONTROL,

    /**
    Speed limiter status
    @type [enum]
    @see sti_state_t
    */
    STI_SPEED_LIMITER,

    /**
    Lane position
    @type [enum]
    @see sti_lane_pos_t
    */
    STI_LANE_POSITION,

    /**
    Trailer weight
    @type [weight]
    @unit [g]
    */
    STI_TRAILER_WEIGHT,

    /**
    Front left door state
    @type [enum]
    @see sti_door_state_t
    */
    STI_DOOR_STATE_FRONT_LEFT,

    /**
    Front right door state
    @type [enum]
    @see sti_door_state_t
    */
    STI_DOOR_STATE_FRONT_RIGHT,

    /**
    Rear left door state
    @type [enum]
    @see sti_door_state_t
    */
    STI_DOOR_STATE_REAR_LEFT,

    /**
    Rear right door state
    @type [enum]
    @see sti_door_state_t
    */
    STI_DOOR_STATE_REAR_RIGHT,

    /**
    Bonnet state
    @type [enum]
    @see sti_door_state_t
    */
    STI_DOOR_STATE_BONNET,

    /**
    Trunk state
    @type [enum]
    @see sti_door_state_t
    */
    STI_DOOR_STATE_TRUNK,

    /**
    Fuel type
    @type [enum]
    @see sti_fuel_type_t
    */
    STI_FUEL_TYPE,

    /**
    Road class
    @type [enum]
    @see sti_road_class_t
    */
    STI_ROAD_CLASS,

    /**
    Area type
    @type [enum]
    @see sti_area_type_t
    */
    STI_AREA_TYPE,

    /**
    Automatic emergency brake status
    @type [enum]
    @see sti_state_t
    */
    STI_AUTOMATIC_EMERGENCY_BRAKE,

    /**
    Reversible Occupant Restraint System status (e.g. reversible belt-tightener)
    @note Activate when any of the applicable system is active.
    @type [enum]
    @see sti_state_t
    */
    STI_REVERSIBLE_OCCUPANT_RESTRAINT_SYSTEM,

    /**
    A red warning light is active in the vehicle. (See ECE 121)
    @type [enum]
    @see sti_state_t
    */
    STI_RED_WARNING_ACTIVE,

    /**
    First row belt buckle status on the driver side.
    @type [enum]
    @see sti_belt_buckle_status_t
    */
    STI_BELT_BUCKLE_ROW1_DRIVER,

    /**
    First row belt buckle status on the middle.
    @type [enum]
    @see sti_belt_buckle_status_t
    */
    STI_BELT_BUCKLE_ROW1_MIDDLE,

    /**
    First row belt buckle status on the passenger side.
    @type [enum]
    @see sti_belt_buckle_status_t
    */
    STI_BELT_BUCKLE_ROW1_PASSENGER,

    /**
    Second row belt buckle status on the driver side.
    @type [enum]
    @see sti_belt_buckle_status_t
    */
    STI_BELT_BUCKLE_ROW2_DRIVER,

    /**
    Second row belt buckle status on the middle.
    @type [enum]
    @see sti_belt_buckle_status_t
    */
    STI_BELT_BUCKLE_ROW2_MIDDLE,

    /**
    Second row belt buckle status on the passenger side.
    @type [enum]
    @see sti_belt_buckle_status_t
    */
    STI_BELT_BUCKLE_ROW2_PASSENGER,

    /**
    Third row belt buckle status on the driver side.
    @type [enum]
    @see sti_belt_buckle_status_t
    */
    STI_BELT_BUCKLE_ROW3_DRIVER,

    /**
    Third row belt buckle status on the middle.
    @type [enum]
    @see sti_belt_buckle_status_t
    */
    STI_BELT_BUCKLE_ROW3_MIDDLE,

    /**
    Third row belt buckle status on the passenger side.
    @type [enum]
    @see sti_belt_buckle_status_t
    */
    STI_BELT_BUCKLE_ROW3_PASSENGER,

    /**
    Ignition status of the vehicle. (terminal 15)
    @type [enum]
    @see sti_state_t
    */
    STI_IGNITION,

    /**
    Type of the transmission. (automatic or manual)
    @type [enum]
    @see sti_transmission_type_t
    */
    STI_TRANSMISSION_TYPE,

    /**
    Presence of physical separation between own and oncoming lanes of the road/highway
    @type [enum]
    @see sti_physical_road_separation_t
    */
    STI_PHYSICAL_ROAD_SEPARATION,

    /**
    An eCall has been triggered manually by an occupant of the vehicle by the eCall
    button.
    @type [enum]
    @see sti_state_t
    */
    STI_MANUAL_ECALL,

    /**
    Low severity crash crash is detected without the activation of an irreversible occupant
    restraint system. (e.g. high-voltage battery cut-off, door unlock)
    @type [enum]
    @see sti_state_t
    */
    STI_LOW_SEVERITY_CRASH,

    /**
    Pedestrian collision is detected with the activation of at least one irreversible
    pedestrian-protection system. (e.g. pop-up bonnet, outside airbag)
    @type [enum]
    @see sti_state_t
    */
    STI_PEDESTRIAN_COLLISION,

    /**
    High severity crash is detected with the activation of at least one irreversible
    occupant-restraint system. (e.g. pyrotechnic belt-tightener, airbag)
    @type [enum]
    @see sti_state_t
    */
    STI_HIGH_SEVERITY_CRASH,

    /**
    Rule of the road. (e.g. right-hand traffic, left-hand traffic)
    @type [enum]
    @see sti_state_t
    */
    STI_ROAD_RULE,

    /**
    Jackknife.
    @type [enum]
    @see sti_state_t
    */
    STI_EV_JACKKNIFE,

    /**
    Project specific STI values.
    @type [integer]
    @unit [varying]
    */
    STI_PROJECT_00 = 128,
    STI_PROJECT_01,
    STI_PROJECT_02,
    STI_PROJECT_03,
    STI_PROJECT_04,
    STI_PROJECT_05,
    STI_PROJECT_06,
    STI_PROJECT_07,
    STI_PROJECT_08,
    STI_PROJECT_09,
    STI_PROJECT_10,
    STI_PROJECT_11,
    STI_PROJECT_12,
    STI_PROJECT_13,
    STI_PROJECT_14,
    STI_PROJECT_15,
    STI_PROJECT_16,
    STI_PROJECT_17,
    STI_PROJECT_18,
    STI_PROJECT_19,
    STI_PROJECT_20,
    STI_PROJECT_21,
    STI_PROJECT_22,
    STI_PROJECT_23,
    STI_PROJECT_24,
    STI_PROJECT_25,
    STI_PROJECT_26,
    STI_PROJECT_27,
    STI_PROJECT_28,
    STI_PROJECT_29,
    STI_PROJECT_30,
    STI_PROJECT_31,

    /** Number of STI types, do not use as a parameter */
    STI_TYPE_LAST
} sti_type_t;


static int proto_desc;
static int ett_c2p;
static dissector_handle_t ieee80211_handle;

static int hf_c2p_version_desc;
static int hf_c2p_type_desc;
static int hf_c2p_tst_sec_desc;
static int hf_c2p_tst_msec_desc;
static int hf_c2p_primary_channel_desc;
static int hf_c2p_secondary_channel_desc;
static int hf_c2p_used_interface_desc;
static int hf_c2p_datarate_desc;
static int hf_c2p_antenna_desc;
static int hf_c2p_latitude_desc;
static int hf_c2p_longitude_desc;
static int hf_c2p_altitude_desc;
static int hf_c2p_speed_desc;
static int hf_c2p_heading_desc;
static int hf_c2p_semi_major_conf_desc;
static int hf_c2p_semi_minor_conf_desc;
static int hf_c2p_semi_major_ori_desc;
static int hf_c2p_alttitude_acc_desc;
static int hf_c2p_heading_acc_desc;
static int hf_c2p_speed_acc_desc;
static int hf_c2p_rssi_ant_1_desc;
static int hf_c2p_rssi_ant_2_desc;
static int hf_c2p_noise_ant_1_desc;
static int hf_c2p_noise_ant_2_desc;
static int hf_c2p_cbr_ant_1_desc;
static int hf_c2p_cbr_ant_2_desc;
static int hf_c2p_tx_power_desc;
static int hf_c2p_cv2x_tx_power_desc;
static int hf_c2p_tssi_ant_1_desc;
static int hf_c2p_tssi_ant_2_desc;
static int hf_c2p_sps_desc;
static int hf_c2p_sps_port_desc;
static int hf_c2p_event_port_desc;
static int hf_c2p_bw_res_v2xid_desc;
static int hf_c2p_bw_res_period_interval_ms_desc;
static int hf_c2p_bw_res_tx_reservation_size_bytes_desc;
static int hf_c2p_bw_res_tx_priority_desc;
static int hf_c2p_socket_index_desc;
static int hf_c2p_ethertype_desc;
static int hf_c2p_rssi_desc;
static int hf_c2p_nav_fix_is_valid_desc;
static int hf_c2p_gps_timestamp_desc;
static int hf_c2p_sti_length_desc;
static int hf_c2p_sti_type_desc;
static int hf_c2p_sti_value_angle_desc;
static int hf_c2p_sti_value_acceleration_desc;
static int hf_c2p_sti_value_angular_velocity_desc;
static int hf_c2p_sti_value_thousandths_desc;
static int hf_c2p_sti_value_length_desc;
static int hf_c2p_sti_value_mass_desc;
static int hf_c2p_sti_value_rain_rate_desc;
static int hf_c2p_sti_value_solar_irradiance_desc;
static int hf_c2p_sti_value_temperature_desc;
static int hf_c2p_sti_value_pressure_desc;
static int hf_c2p_sti_value_sweep_rate_desc;
static int hf_c2p_sti_value_integer_desc;
static int hf_c2p_sti_value_transmission_state_desc;
static int hf_c2p_sti_value_aux_breaks_desc;
static int hf_c2p_sti_value_vehicle_length_conf_desc;
static int hf_c2p_sti_value_dangerous_goods_desc;
static int hf_c2p_sti_value_station_type_desc;
static int hf_c2p_sti_value_vehicle_role_desc;
static int hf_c2p_sti_value_weather_precip_situation_desc;
static int hf_c2p_sti_value_wiper_state_desc;
static int hf_c2p_sti_value_door_state_desc;
static int hf_c2p_sti_value_fuel_type_desc;
static int hf_c2p_sti_value_road_class_desc;
static int hf_c2p_sti_value_road_rule_desc;
static int hf_c2p_sti_value_area_type_desc;
static int hf_c2p_sti_value_belt_buckle_status_desc;
static int hf_c2p_sti_value_transmission_type_desc;
static int hf_c2p_sti_value_physical_road_separation_desc;
static int hf_c2p_sti_value_siren_desc;
static int hf_c2p_sti_value_lightbar_desc;
static int hf_c2p_sti_value_lane_position_desc;
static int hf_c2p_sti_value_state_desc;
static int hf_c2p_sti_value_tristate_desc;


#define C2P_TYPE_DSRC_RX        1UL
#define C2P_TYPE_DSRC_TX        2UL
#define C2P_TYPE_NAV            3UL
#define C2P_TYPE_CAN            4UL
#define C2P_TYPE_STI            5UL
#define C2P_TYPE_POTI           6UL
#define C2P_TYPE_CV2X_RX        7UL
#define C2P_TYPE_CV2X_TX        8UL

enum { C2P_TYPES_NUM = 9UL };

static const value_string c2p_types[C2P_TYPES_NUM] = {
    { C2P_TYPE_DSRC_RX, "Received DSRC Packet" },
    { C2P_TYPE_DSRC_TX, "Transmitted DSRC Packet" },
    { C2P_TYPE_NAV, "Navigation" },
    { C2P_TYPE_CAN, "CAN" },
    { C2P_TYPE_STI, "StationInfo" },
    { C2P_TYPE_POTI, "Position & Timing" },
    { C2P_TYPE_CV2X_RX, "Received CV2X Packet" },
    { C2P_TYPE_CV2X_TX, "Transmitted CV2X Packet" },
    { 0, NULL }
};

enum { HEADING_PREDEFINED_VALUES_NUM = 7UL };

static const value_string heading_predefined_values[HEADING_PREDEFINED_VALUES_NUM] = {
    { 0, "wgs84North" },
    { 900, "wgs84East" },
    { 1800, "wgs84South" },
    { 2700, "wgs84West" },
    { 3600, "Unavailable" },
    { 3601, "Unavailable" },
    { 0, NULL }
};

static const val64_string sti_transmission_state_types[5] = {
    { STI_TRANSMISSION_STATE_NEUTRAL, "Neutral" },
    { STI_TRANSMISSION_PARK, "Parking" },
    { STI_TRANSMISSION_FWD_GEARS, "Forward gears" },
    { STI_TRANSMISSION_REVERSE_GEARS, "Reverse gears" },
    { 0, NULL }
};

static const val64_string sti_aux_breaks_types[3] = {
    { STI_AUX_BRAKES_OFF, "Off" },
    { STI_AUX_BRAKES_ON, "On" },
    { 0, NULL }
};

static const val64_string sti_vehicle_length_conf_types[5] = {
    { STI_VEHICLE_LENGTH_CONF_NO_TRAILER, "No trailer" },
    { STI_VEHICLE_LENGTH_CONF_TRAILER_WITH_LENGTH, "Trailer with known length" },
    { STI_VEHICLE_LENGTH_CONF_TRAILER_WITH_NA_LENGTH, "Trailer with unknown length" },
    { STI_VEHICLE_LENGTH_CONF_TRAILER_PRESENCE_IS_UNK, "Trailer presence unknown" },
    { 0, NULL }
};

static const val64_string sti_dangerous_goods_types[21] = {
    { STI_DANGEROUS_GOODS_EXPLOSIVES1, "Explosive substance type 1" },
    { STI_DANGEROUS_GOODS_EXPLOSIVES2, "Explosive substance type 2" },
    { STI_DANGEROUS_GOODS_EXPLOSIVES3, "Explosive substance type 3" },
    { STI_DANGEROUS_GOODS_EXPLOSIVES4, "Explosive substance type 4" },
    { STI_DANGEROUS_GOODS_EXPLOSIVES5, "Explosive substance type 5" },
    { STI_DANGEROUS_GOODS_EXPLOSIVES6, "Explosive substance type 6" },
    { STI_DANGEROUS_GOODS_FLAMMABLE_GASES, "Flammable gases" },
    { STI_DANGEROUS_GOODS_NON_FLAMMABLE_GASES, "Non flammable gases" },
    { STI_DANGEROUS_GOODS_TOXIC_GASES, "Toxic gases" },
    { STI_DANGEROUS_GOODS_FLAMMABLE_LIQUIDS, "Flammable liquids" },
    { STI_DANGEROUS_GOODS_FLAMMABLE_SOLIDS, "Flammable solids" },
    { STI_DANGEROUS_GOODS_SUBSTANCES_SPONTAIN_COMBUSTION, "Substances liable to spontaneous combustion" },
    { STI_DANGEROUS_GOODS_SUBSTANCES_FLAMBLE_CONTACT_WATER, "Substances emitting flammable gases upon contact with water" },
    { STI_DANGEROUS_GOODS_OXIDIZING_SUBSTANCES, "Oxidizing substances" },
    { STI_DANGEROUS_GOODS_ORGANIC_PEROXIDES, "Organic peroxides" },
    { STI_DANGEROUS_GOODS_TOXIC_SUBSTANCES, "Toxic substances" },
    { STI_DANGEROUS_GOODS_INFECTIOUS_SUBSTANCES, "Infectious substances" },
    { STI_DANGEROUS_GOODS_RADIOACTIVE_MATERIAL, "Radioactive material" },
    { STI_DANGEROUS_GOODS_CORROSIVE_SUBSTANCES, "Corrosive substances" },
    { STI_DANGEROUS_GOODS_MISC_DANGEROUS_SUBSTANCES, "Miscellaneous dangerous substances" },
    { 0, NULL }
};

static const val64_string sti_station_type_types[59] = {
    { STI_STATION_TYPE_UNK, "Unknown" },
    { STI_STATION_TYPE_SPECIAL, "Special" },
    { STI_STATION_TYPE_PASSENGER_UNK, "Unknown type passenger vehicle" },
    { STI_STATION_TYPE_PASSENGER_OTHER, "Other type passenger vehicle" },
    { STI_STATION_TYPE_LIGHT_TRUCK_UNK, "Unknown type light truck" },
    { STI_STATION_TYPE_LIGHT_TRUCK_OTHER, "Other type light truck" },
    { STI_STATION_TYPE_TRUCK_UNK, "Unknown type truck" },
    { STI_STATION_TYPE_TRUCK_OTHER, "Other type truck" },
    { STI_STATION_TYPE_TRUCK_AXLE_CNT_2, "Two axle, six tire single units" },
    { STI_STATION_TYPE_TRUCK_AXLE_CNT_3, "Three axle single units" },
    { STI_STATION_TYPE_TRUCK_AXLE_CNT_4, "Four or more axle single unit" },
    { STI_STATION_TYPE_TRUCK_AXLE_CNT_4_TRAILER, "Four or less axle single trailer" },
    { STI_STATION_TYPE_TRUCK_AXLE_CNT_5_TRAILER, "Five or less axle single trailer" },
    { STI_STATION_TYPE_TRUCK_AXLE_CNT_6_TRAILER, "Six or more axle single trailer" },
    { STI_STATION_TYPE_TRUCK_AXLE_CNT_5_MULTI_TRAILER, "Five or less axle multi-trailer" },
    { STI_STATION_TYPE_TRUCK_AXLE_CNT_6_MULTI_TRAILER, "Six axle multi-trailer" },
    { STI_STATION_TYPE_TRUCK_AXLE_CNT_7_MULTI_TRAILER, "Seven or more axle multi-trailer" },
    { STI_STATION_TYPE_MOTORCYCLE_UNK, "Unknown type motorcycle" },
    { STI_STATION_TYPE_MOTORCYCLE_OTHER, "Other type motorcycle" },
    { STI_STATION_TYPE_MOTORCYCLE_CRUISER_STANDARD, "Cruiser standard motorcycle" },
    { STI_STATION_TYPE_MOTORCYCLE_SPORT_UNCLAD, "Unclad sport motorcycle" },
    { STI_STATION_TYPE_MOTORCYCLE_SPORT_TOURING, "Sport touring motorcycle" },
    { STI_STATION_TYPE_MOTORCYCLE_SUPER_SPORT, "Super sport motorcycle" },
    { STI_STATION_TYPE_MOTORCYCLE_TOURING, "Touring motorcycle" },
    { STI_STATION_TYPE_MOTORCYCLE_TRIKE, "Trike motorcycle" },
    { STI_STATION_TYPE_MOTORCYCLE_WITH_PASSENGERS, "Motorcycle with passengers" },
    { STI_STATION_TYPE_TRANSIT_UNK, "Unknown type transit" },
    { STI_STATION_TYPE_TRANSIT_OTHER, "Other type transit" },
    { STI_STATION_TYPE_TRANSIT_BRT, "Bus rapid transit" },
    { STI_STATION_TYPE_TRANSIT_EXPRESS_BUS, "Express bus" },
    { STI_STATION_TYPE_TRANSIT_LOCAL_BUS, "Local bus" },
    { STI_STATION_TYPE_TRANSIT_SCHOOL_BUS, "School bus" },
    { STI_STATION_TYPE_TRANSIT_FIXED_GUIDE_WAY, "Fixed guideway transit, like tram" },
    { STI_STATION_TYPE_TRANSIT_PARATRANSIT, "Paratransit" },
    { STI_STATION_TYPE_TRANSIT_PARATRANSIT_AMBULANCE, "Paratransit ambulance" },
    { STI_STATION_TYPE_EMERGENCY_UNK, "Unknown type emergency vehicle" },
    { STI_STATION_TYPE_EMERGENCY_OTHER, "Other type emergency vehicle" },
    { STI_STATION_TYPE_EMERGENCY_FIRE_LIGHT, "Light fire emergency vehicle" },
    { STI_STATION_TYPE_EMERGENCY_FIRE_HEAVY, "Heavy fire emergency vehicle" },
    { STI_STATION_TYPE_EMERGENCY_FIRE_PARAMEDIC, "Fire paramedic emergency vehicle" },
    { STI_STATION_TYPE_EMERGENCY_FIRE_AMBULANCE, "Fire ambulance emergency vehicle" },
    { STI_STATION_TYPE_EMERGENCY_POLICE_LIGHT, "Light police emergency vehicle" },
    { STI_STATION_TYPE_EMERGENCY_POLICE_HEAVY, "Heavy police emergency vehicle" },
    { STI_STATION_TYPE_EMERGENCY_OTHER_RESPONDER, "Other type responder emergency vehicle" },
    { STI_STATION_TYPE_EMERGENCY_OTHER_AMBULANCE, "Other type ambulance emergency vehicle" },
    { STI_STATION_TYPE_OTHER_UNK, "Unknown type other traveler" },
    { STI_STATION_TYPE_OTHER_OTHER, "Other type other traveler" },
    { STI_STATION_TYPE_OTHER_PEDESTRIAN, "Other type pedestrian" },
    { STI_STATION_TYPE_OTHER_VISUALLY_DISABLED, "Visually disabled other traveler" },
    { STI_STATION_TYPE_OTHER_PHYSICALLY_DISABLED, "Physically disabled other traveler" },
    { STI_STATION_TYPE_OTHER_BICYCLE, "Bicycle" },
    { STI_STATION_TYPE_OTHER_VULNERABLE_ROADWORKER, "Vulnerable road worker" },
    { STI_STATION_TYPE_INFRASTRUCTURE_UNK, "Unknown type infrastructure" },
    { STI_STATION_TYPE_INFRASTRUCTURE_FIXED, "Fixed infrastructure" },
    { STI_STATION_TYPE_INFRASTRUCTURE_MOVABLE, "Movable device" },
    { STI_STATION_TYPE_EQUIPPED_CARGO_TRAILER, "Cargo trailer" },
    { STI_STATION_TYPE_LIGHT_VRU_VEHICLE, "Vulnerable road worker" },
    { STI_STATION_TYPE_ANIMAL, "Animal" },
    { 0, NULL }
};


static const val64_string sti_vehicle_role_types[27] = {
    { STI_VEHICLE_ROLE_BASIC_VEHICLE, "Basic vehicle" },
    { STI_VEHICLE_ROLE_PUBLIC_TRANSPORT, "Public transport" },
    { STI_VEHICLE_ROLE_SPECIAL_TRANSPORT, "Special transport" },
    { STI_VEHICLE_ROLE_DANGEROUS_GOODS, "Dangerous goods" },
    { STI_VEHICLE_ROLE_ROAD_WORK, "Roadwork" },
    { STI_VEHICLE_ROLE_RESCUE, "Rescue" },
    { STI_VEHICLE_ROLE_EMERGENCY, "Emergency" },
    { STI_VEHICLE_ROLE_SAFETY_CAR, "Safety car" },
    { STI_VEHICLE_ROLE_TRUCK, "Truck" },
    { STI_VEHICLE_ROLE_MOTORCYCLE, "Motorcycle" },
    { STI_VEHICLE_ROLE_ROAD_SIDE_SOURCE, "RSU" },
    { STI_VEHICLE_ROLE_POLICE, "Police" },
    { STI_VEHICLE_ROLE_FIRE, "Fire" },
    { STI_VEHICLE_ROLE_AMBULANCE, "Ambulance" },
    { STI_VEHICLE_ROLE_DOT, "DoT" },
    { STI_VEHICLE_ROLE_TRANSIT, "Transit" },
    { STI_VEHICLE_ROLE_SLOW_MOVING, "Slow moving" },
    { STI_VEHICLE_ROLE_STOP_N_GO, "Stop 'n' Go" },
    { STI_VEHICLE_ROLE_CYCLIST, "Cyclist" },
    { STI_VEHICLE_ROLE_PEDESTRIAN, "Pedestrian" },
    { STI_VEHICLE_ROLE_NON_MOTORIZED, "Non motorized" },
    { STI_VEHICLE_ROLE_MILITARY, "Military" },
    { STI_VEHICLE_ROLE_AGRICULTURE, "Agriculture" },
    { STI_VEHICLE_ROLE_COMMERCIAL, "Commercial" },
    { STI_VEHICLE_ROLE_ROAD_OPERATOR, "Road operator" },
    { STI_VEHICLE_ROLE_TAXI, "Taxi" },
    { 0, NULL }
};

static const val64_string sti_weather_precip_situation_types[16] = {
    { STI_WEATHER_PRECIP_SITUATON_OTHER, "Other type precipitation" },
    { STI_WEATHER_PRECIP_SITUATON_UNK, "Unknown type precipitation" },
    { STI_WEATHER_PRECIP_SITUATON_NO_PRECIP, "No precipitation" },
    { STI_WEATHER_PRECIP_SITUATON_UNK_SLIGHT, "Unknown type slight precipitation" },
    { STI_WEATHER_PRECIP_SITUATON_UNK_MODERATE, "Unknown type moderate precipitation" },
    { STI_WEATHER_PRECIP_SITUATON_UNK_HEAVY, "Unknown type heavy precipitation" },
    { STI_WEATHER_PRECIP_SITUATON_SNOW_SLIGHT, "Slight snow precipitation" },
    { STI_WEATHER_PRECIP_SITUATON_SNOW_MODERATE, "Moderate snow precipitation" },
    { STI_WEATHER_PRECIP_SITUATON_SNOW_HEAVY, "Heavy snow precipitation" },
    { STI_WEATHER_PRECIP_SITUATON_RAIN_SLIGHT, "Slight rain precipitation" },
    { STI_WEATHER_PRECIP_SITUATON_RAIN_MODERATE, "Moderate rain precipitation" },
    { STI_WEATHER_PRECIP_SITUATON_RAIN_HEAVY, "Heavy rain precipitation" },
    { STI_WEATHER_PRECIP_SITUATON_FROZEN_PRECIP_SLIGHT, "Slight frozen precipitation" },
    { STI_WEATHER_PRECIP_SITUATON_FROZEN_PRECIP_MODERATE, "Moderate frozen precipitation" },
    { STI_WEATHER_PRECIP_SITUATON_FROZEN_PRECIP_HEAVY, "Heavy frozen precipitation" },
    { 0, NULL }
};

static const val64_string sti_wiper_state_types[7] = {
    { STI_WIPER_STATE_OFF, "Off" },
    { STI_WIPER_STATE_INTERMITTENT, "Intermittent" },
    { STI_WIPER_STATE_LOW, "Low" },
    { STI_WIPER_STATE_HIGH, "High" },
    { STI_WIPER_STATE_WASHER_IN_USE, "Washer in use" },
    { STI_WIPER_STATE_AUTO, "Auto" },
    { 0, NULL }
};

static const val64_string sti_lightbar_types[8] = {
    { STI_LIGHTBAR_NOT_IN_USE, "Not in use" },
    { STI_LIGHTBAR_IN_USE, "In use" },
    { STI_LIGHTBAR_YELLOW_CAUTION_LIGHTS, "Yellow caution lights" },
    { STI_LIGHTBAR_SCHOOL_BUS_LIGHTS, "School bus lights" },
    { STI_LIGHTBAR_ARROW_SIGNS_ACTIVE, "Arrow signs active" },
    { STI_LIGHTBAR_SLOW_MOVING_VEHICLE, "Slow moving vehicle lights" },
    { STI_LIGHTBAR_FREQ_STOPS, "Frequent stops" },
    { 0, NULL }
};

static const val64_string sti_door_state_types[4] = {
    { STI_DOOR_STATE_NA, "Unknown" },
    { STI_DOOR_STATE_CLOSED, "Closed" },
    { STI_DOOR_STATE_OPEN, "Open" },
    { 0, NULL }
};

static const val64_string sti_fuel_type_types[10] = {
    { STI_FUEL_TYPE_GASOLINE, "Gasoline" },
    { STI_FUEL_TYPE_ETHANOL, "Ethanol" },
    { STI_FUEL_TYPE_DIESEL, "Diesel" },
    { STI_FUEL_TYPE_ELECTRIC, "Electric" },
    { STI_FUEL_TYPE_HYBRID, "Hybrid" },
    { STI_FUEL_TYPE_HYDROGEN, "Hydrogen" },
    { STI_FUEL_TYPE_NAT_GAS_LIQUID, "NAT gas liquefied" },
    { STI_FUEL_TYPE_NAT_GAS_COMP, "NAT gas compressed" },
    { STI_FUEL_TYPE_PROPANE, "Propane" },
    { 0, NULL }
};

static const val64_string sti_road_class_types[5] = {
    { STI_ROAD_CLASS_UNKNOWN, "Unknown" },
    { STI_ROAD_CLASS_MOTORWAY, "Motorway" },
    { STI_ROAD_CLASS_COUNTRY_ROAD, "Country road" },
    { STI_ROAD_CLASS_LOCAL_ROAD, "Local road" },
    { 0, NULL }
};

static const val64_string sti_road_rule_types[3] = {
    { STI_ROAD_RULE_RIGHT_HAND_TRAFFIC, "Right hand traffic" },
    { STI_ROAD_RULE_LEFT_HAND_TRAFFIC, "Left hand traffic" },
    { 0, NULL }
};

static const val64_string sti_area_type_types[3] = {
    { STI_AREA_TYPE_RURAL, "Rural" },
    { STI_AREA_TYPE_URBAN, "Urban" },
    { 0, NULL }
};

static const val64_string sti_belt_buckle_status_types[3] = {
    { STI_BELT_BUCKLE_DISCONNECTED, "Disconnected" },
    { STI_BELT_BUCKLE_CONNECTED, "Connected" },
    { 0, NULL }
};

static const val64_string sti_transmission_type_types[3] = {
    { STI_TRANSMISSION_TYPE_AUTOMATIC, "Automatic" },
    { STI_TRANSMISSION_TYPE_MANUAL, "Manual" },
    { 0, NULL }
};

static const val64_string sti_physical_road_separation_types[3] = {
    { STI_PHYSICAL_ROAD_SEPARATION_NOT_PRESENT, "Not present" },
    { STI_PHYSICAL_ROAD_SEPARATION_PRESENT, "Present" },
    { 0, NULL }
};

static const val64_string sti_siren_types[3] = {
    { STI_SIREN_NOT_IN_USE, "Not in use" },
    { STI_SIREN_IN_USE, "In use" },
    { 0, NULL }
};

static const val64_string sti_lane_position_types[36] = {
    { STI_LANE_POSITION_INNER_HARD_SHOULDER, "Inner hard shoulder position" },
    { STI_LANE_POSITION_INNERMOST_DRIVING_LANE, "Innermost driving lane" },
    { STI_LANE_POSITION_SECOND_LANE_FROM_INSIDE, "Second lane from inside" },
    { STI_LANE_POSITION_THIRD_LANE_FROM_INSIDE, "Third lane from inside" },
    { STI_LANE_POSITION_FOURTH_LANE_FROM_INSIDE, "Fourth lane from inside" },
    { STI_LANE_POSITION_FIFTH_LANE_FROM_INSIDE, "Fifth lane from inside" },
    { STI_LANE_POSITION_SIXTH_LANE_FROM_INSIDE, "Sixth lane from inside" },
    { STI_LANE_POSITION_SEVENTH_LANE_FROM_INSIDE, "Seventh lane from inside" },
    { STI_LANE_POSITION_EIGHTH_LANE_FROM_INSIDE, "Eighth lane from inside" },
    { STI_LANE_POSITION_NINTH_LANE_FROM_INSIDE, "Ninth lane from inside" },
    { STI_LANE_POSITION_TENTH_LANE_FROM_INSIDE, "Tenth lane from inside" },
    { STI_LANE_POSITION_ELEVENTH_LANE_FROM_INSIDE, "Eleventh lane from inside" },
    { STI_LANE_POSITION_TWELFTH_LANE_FROM_INSIDE, "Twelfth lane from inside" },
    { STI_LANE_POSITION_THIRTEENTH_LANE_FROM_INSIDE, "Thirteenth lane from inside" },
    { STI_LANE_POSITION_FOURTEENTH_LANE_FROM_INSIDE, "Fourteenth lane from inside" },
    { STI_LANE_POSITION_FIFTEENTH_LANE_FROM_INSIDE, "Fifteenth lane from inside" },
    { STI_LANE_POSITION_SIXTEENTH_LANE_FROM_INSIDE, "Sixteenth lane from inside" },
    { STI_LANE_POSITION_SEVENTEENTH_LANE_FROM_INSIDE, "Seventeenth lane from inside" },
    { STI_LANE_POSITION_EIGHTEENTH_LANE_FROM_INSIDE, "Eighteenth lane from inside" },
    { STI_LANE_POSITION_NINETEENTH_LANE_FROM_INSIDE, "Nineteenth lane from inside" },
    { STI_LANE_POSITION_TWENTIETH_LANE_FROM_INSIDE, "Twentieth lane from inside" },
    { STI_LANE_POSITION_TWENTY_FIRST_LANE_FROM_INSIDE, "Twenty-first lane from inside" },
    { STI_LANE_POSITION_TWENTY_SECOND_LANE_FROM_INSIDE, "Twenty-second lane from inside" },
    { STI_LANE_POSITION_TWENTY_THIRD_LANE_FROM_INSIDE, "Twenty-third lane from inside" },
    { STI_LANE_POSITION_TWENTY_FOURTH_LANE_FROM_INSIDE, "Twenty-fourth lane from inside" },
    { STI_LANE_POSITION_TWENTY_FIFTH_LANE_FROM_INSIDE, "Twenty-fifth lane from inside" },
    { STI_LANE_POSITION_TWENTY_SIXTH_LANE_FROM_INSIDE, "Twenty-sixth lane from inside" },
    { STI_LANE_POSITION_TWENTY_SEVENTH_LANE_FROM_INSIDE, "Twenty-seventh lane from inside" },
    { STI_LANE_POSITION_TWENTY_EIGHTH_LANE_FROM_INSIDE, "Twenty-eighth lane from inside" },
    { STI_LANE_POSITION_TWENTY_NINTH_LANE_FROM_INSIDE, "Twenty-ninth lane from inside" },
    { STI_LANE_POSITION_THIRTIETH_LANE_FROM_INSIDE, "Thirtieth lane from inside" },
    { STI_LANE_POSITION_THIRTY_FIRST_LANE_FROM_INSIDE, "Thirty-first lane from inside" },
    { STI_LANE_POSITION_THIRTY_SECOND_LANE_FROM_INSIDE, "Thirty-second lane from inside" },
    { STI_LANE_POSITION_OUTER_HARD_SHOULDER, "Outer hard shoulder position" },
    { STI_LANE_POSITION_OFF_THE_ROAD, "Off the road position" },
    { 0, NULL }
};

static const val64_string sti_state_types[3] = {
    { STI_STATE_OFF, "Off" },
    { STI_STATE_ON, "On" },
    { 0, NULL }
};

static const val64_string sti_tristate_types[4] = {
    { STI_TRISTATE_OFF, "Off" },
    { STI_TRISTATE_ON, "On (but not engaged)" },
    { STI_TRISTATE_ENGAGED, "Engaged" },
    { 0, NULL }
};

static const value_string sti_types[STI_TYPE_LAST + 1] = {
    { STI_TRANSMISSION_STATE, "Transmission state" },
    { STI_STEERING_WHEEL_ANGLE, "Steering wheel angle" },
    { STI_STEERING_WHEEL_ANGLE_CONF, "Steering wheel angle confidence" },
    { STI_STEERING_WHEEL_ANGLE_RATE, "Steering wheel angle rate" },
    { STI_DRIVING_WHEEL_ANGLE, "Driving wheel angle" },
    { STI_LONG_ACC, "Longitudinal acceleration" },
    { STI_LONG_ACC_CONF, "Longitudinal acceleration confidence" },
    { STI_LAT_ACC, "Lateral acceleration" },
    { STI_LAT_ACC_CONF, "Lateral acceleration confidence" },
    { STI_VERT_ACC, "Vertical acceleration" },
    { STI_VERT_ACC_CONF, "Vertical acceleration confidence" },
    { STI_YAW_RATE, "Yaw rate" },
    { STI_YAW_RATE_CONF, "Yaw rate confidence" },
    { STI_BRAKE_STATUS_LEFT_FRONT, "Front left brake applied pressure" },
    { STI_BRAKE_STATUS_LEFT_REAR, "Rear left brake applied pressure" },
    { STI_BRAKE_STATUS_RIGHT_FRONT, "Front right brake applied pressure" },
    { STI_BRAKE_STATUS_RIGHT_REAR, "Rear right brake applied pressure" },
    { STI_TRACTION_CONTROL_STATUS, "Traction control status" },
    { STI_ABS, "Anti-lock braking system status" },
    { STI_STABILITY_CONTROL_STATUS, "Stability control status" },
    { STI_EMERGENCY_BRAKE, "Emergency brake status, also known as 'Brake boost'" },
    { STI_AUX_BRAKES, "Auxiliary brake status" },
    { STI_VEHICLE_WIDTH, "Vehicle width" },
    { STI_VEHICLE_LENGTH, "Vehicle length" },
    { STI_VEHICLE_LENGTH_CONF, "Vehicle length confidence" },
    { STI_VEHICLE_HEIGHT, "Vehicle height" },
    { STI_VEHICLE_MASS, "Vehicle mass" },
    { STI_EV_STOP_LINE_VIOLATED, "Stop line violated" },
    { STI_DANGEROUS_GOODS, "Dangerous goods present" },
    { STI_EV_FLAT_TIRE, "Flat tire" },
    { STI_EV_DISABLED_VEHICLE, "Disabled vehicle" },
    { STI_EV_AIRBAG_DEPLOYED, "Airbag deployed" },
    { STI_EXT_LIGHT_LOWBEAM_HEAD, "Low beam headlight" },
    { STI_EXT_LIGHT_HIGHBEAM_HEAD, "High beam headlight" },
    { STI_EXT_LIGHT_LEFT_TURN_SIGNAL, "Left turn signal" },
    { STI_EXT_LIGHT_RIGHT_TURN_SIGNAL, "Right turn signal" },
    { STI_EXT_LIGHT_HAZARD_LIGHT, "Hazard light" },
    { STI_EXT_LIGHT_AUTO_LIGHT_CONTROL, "Auto light control" },
    { STI_EXT_LIGHT_DAYTIME_RUNNING, "Daytime running light" },
    { STI_EXT_LIGHT_FOG, "Fog light" },
    { STI_EXT_LIGHT_PARKING, "Parking light" },
    { STI_EXT_LIGHT_REVERSE, "Reverse light" },
    { STI_STATION_TYPE, "Station type" },
    { STI_VEHICLE_ROLE, "Vehicle role" },
    { STI_BUMPER_HEIGHT_FRONT, "Height of the front bumper" },
    { STI_BUMPER_HEIGHT_REAR, "Height of the rear bumper" },
    { STI_WEATHER_RAIN_RATE, "Rain rate" },
    { STI_RAIN_SENSOR, "Rain sensor" },
    { STI_WEATHER_PRECIP_SITUATON, "Precipitation situation" },
    { STI_WEATHER_SOLAR_RADIATION, "Solar radiation" },
    { STI_WEATHER_COEF_FRICTION, "Coefficient of friction" },
    { STI_WEATHER_AIR_TEMP, "Ambient air temperature" },
    { STI_WEATHER_AIR_PRESSURE, "Ambient air pressure" },
    { STI_WIPER_STATE_FRONT, "Front wiper state" },
    { STI_WIPER_STATE_REAR, "Rear wiper state" },
    { STI_WIPER_RATE_FRONT, "Front wiper rate" },
    { STI_WIPER_RATE_REAR, "Rear wiper rate" },
    { STI_EMBARKATION_STATUS, "Embarkation status" },
    { STI_LIGHTBAR, "Lightbar status" },
    { STI_SIREN, "Siren status" },
    { STI_ACCELERATOR_PEDAL, "Accelerator pedal position" },
    { STI_BRAKE_PEDAL, "Brake pedal position" },
    { STI_COLLISION_WARNING, "Collision warning" },
    { STI_ADAPTIVE_CRUISE_CONTROL, "Adaptive cruise control status" },
    { STI_CRUISE_CONTROL, "Cruise control status" },
    { STI_SPEED_LIMITER, "Speed limiter status" },
    { STI_LANE_POSITION, "Lane position" },
    { STI_TRAILER_WEIGHT, "Trailer weight" },
    { STI_DOOR_STATE_FRONT_LEFT, "Front left door state" },
    { STI_DOOR_STATE_FRONT_RIGHT, "Front right door state" },
    { STI_DOOR_STATE_REAR_LEFT, "Rear left door state" },
    { STI_DOOR_STATE_REAR_RIGHT, "Rear right door state" },
    { STI_DOOR_STATE_BONNET, "Bonnet state" },
    { STI_DOOR_STATE_TRUNK, "Trunk state" },
    { STI_FUEL_TYPE, "Fuel type" },
    { STI_ROAD_CLASS, "Road class" },
    { STI_ROAD_RULE, "Road rule" },
    { STI_AREA_TYPE, "Area type" },
    { STI_AUTOMATIC_EMERGENCY_BRAKE, "Automatic emergency brake status" },
    { STI_REVERSIBLE_OCCUPANT_RESTRAINT_SYSTEM, "Reversible Occupant Restraint System status" },
    { STI_RED_WARNING_ACTIVE, "A red warning light is active in the vehicle" },
    { STI_BELT_BUCKLE_ROW1_DRIVER, "First row belt buckle status on the driver side" },
    { STI_BELT_BUCKLE_ROW1_MIDDLE, "First row belt buckle status on the middle" },
    { STI_BELT_BUCKLE_ROW1_PASSENGER, "First row belt buckle status on the passenger side" },
    { STI_BELT_BUCKLE_ROW2_DRIVER, "Second row belt buckle status on the driver side" },
    { STI_BELT_BUCKLE_ROW2_MIDDLE, "Second row belt buckle status on the middle" },
    { STI_BELT_BUCKLE_ROW2_PASSENGER, "Second row belt buckle status on the passenger side" },
    { STI_BELT_BUCKLE_ROW3_DRIVER, "Third row belt buckle status on the driver side" },
    { STI_BELT_BUCKLE_ROW3_MIDDLE, "Third row belt buckle status on the middle" },
    { STI_BELT_BUCKLE_ROW3_PASSENGER, "Third row belt buckle status on the passenger side" },
    { STI_IGNITION, "Ignition status" },
    { STI_TRANSMISSION_TYPE, "Type of the transmission" },
    { STI_PHYSICAL_ROAD_SEPARATION, "Presence of physical separation between own and oncoming lanes of the road/highway" },
    { STI_MANUAL_ECALL, "Manual eCall triggered" },
    { STI_LOW_SEVERITY_CRASH, "Low severity crash" },
    { STI_PEDESTRIAN_COLLISION, "Pedestrian collision" },
    { STI_HIGH_SEVERITY_CRASH, "High severity crash" },
    { STI_EV_JACKKNIFE, "Jackknife" },
    { STI_PROJECT_00, "Project #0" },
    { STI_PROJECT_01, "Project #1" },
    { STI_PROJECT_02, "Project #2" },
    { STI_PROJECT_03, "Project #3" },
    { STI_PROJECT_04, "Project #4" },
    { STI_PROJECT_05, "Project #5" },
    { STI_PROJECT_06, "Project #6" },
    { STI_PROJECT_07, "Project #7" },
    { STI_PROJECT_08, "Project #8" },
    { STI_PROJECT_09, "Project #9" },
    { STI_PROJECT_10, "Project #10" },
    { STI_PROJECT_11, "Project #11" },
    { STI_PROJECT_12, "Project #12" },
    { STI_PROJECT_13, "Project #13" },
    { STI_PROJECT_14, "Project #14" },
    { STI_PROJECT_15, "Project #15" },
    { STI_PROJECT_16, "Project #16" },
    { STI_PROJECT_17, "Project #17" },
    { STI_PROJECT_18, "Project #18" },
    { STI_PROJECT_19, "Project #19" },
    { STI_PROJECT_20, "Project #20" },
    { STI_PROJECT_21, "Project #21" },
    { STI_PROJECT_22, "Project #22" },
    { STI_PROJECT_23, "Project #23" },
    { STI_PROJECT_24, "Project #24" },
    { STI_PROJECT_25, "Project #25" },
    { STI_PROJECT_26, "Project #26" },
    { STI_PROJECT_27, "Project #27" },
    { STI_PROJECT_28, "Project #28" },
    { STI_PROJECT_29, "Project #29" },
    { STI_PROJECT_30, "Project #30" },
    { STI_PROJECT_31, "Project #31" },
    { 0, NULL }
};


/** STI parameters to hf_index mapping */
static int* sti_params[STI_TYPE_LAST] = {
    [STI_TRANSMISSION_STATE] = &hf_c2p_sti_value_transmission_state_desc,
    [STI_STEERING_WHEEL_ANGLE] = &hf_c2p_sti_value_angle_desc,
    [STI_STEERING_WHEEL_ANGLE_CONF] = &hf_c2p_sti_value_angle_desc,
    [STI_STEERING_WHEEL_ANGLE_RATE] = &hf_c2p_sti_value_angular_velocity_desc,
    [STI_DRIVING_WHEEL_ANGLE] = &hf_c2p_sti_value_angle_desc,
    [STI_LONG_ACC] = &hf_c2p_sti_value_acceleration_desc,
    [STI_LONG_ACC_CONF] = &hf_c2p_sti_value_acceleration_desc,
    [STI_LAT_ACC] = &hf_c2p_sti_value_acceleration_desc,
    [STI_LAT_ACC_CONF] = &hf_c2p_sti_value_acceleration_desc,
    [STI_VERT_ACC] = &hf_c2p_sti_value_acceleration_desc,
    [STI_VERT_ACC_CONF] = &hf_c2p_sti_value_acceleration_desc,
    [STI_YAW_RATE] = &hf_c2p_sti_value_angular_velocity_desc,
    [STI_YAW_RATE_CONF] = &hf_c2p_sti_value_angular_velocity_desc,
    [STI_BRAKE_STATUS_LEFT_FRONT] = &hf_c2p_sti_value_thousandths_desc,
    [STI_BRAKE_STATUS_LEFT_REAR] = &hf_c2p_sti_value_thousandths_desc,
    [STI_BRAKE_STATUS_RIGHT_FRONT] = &hf_c2p_sti_value_thousandths_desc,
    [STI_BRAKE_STATUS_RIGHT_REAR] = &hf_c2p_sti_value_thousandths_desc,
    [STI_TRACTION_CONTROL_STATUS] = &hf_c2p_sti_value_tristate_desc,
    [STI_ABS] = &hf_c2p_sti_value_tristate_desc,
    [STI_STABILITY_CONTROL_STATUS] = &hf_c2p_sti_value_tristate_desc,
    [STI_EMERGENCY_BRAKE] = &hf_c2p_sti_value_state_desc,
    [STI_AUX_BRAKES] = &hf_c2p_sti_value_aux_breaks_desc,
    [STI_VEHICLE_WIDTH] = &hf_c2p_sti_value_length_desc,
    [STI_VEHICLE_LENGTH] = &hf_c2p_sti_value_length_desc,
    [STI_VEHICLE_LENGTH_CONF] = &hf_c2p_sti_value_vehicle_length_conf_desc,
    [STI_VEHICLE_HEIGHT] = &hf_c2p_sti_value_length_desc,
    [STI_VEHICLE_MASS] = &hf_c2p_sti_value_mass_desc,
    [STI_EV_STOP_LINE_VIOLATED] = &hf_c2p_sti_value_state_desc,
    [STI_DANGEROUS_GOODS] = &hf_c2p_sti_value_dangerous_goods_desc,
    [STI_EV_FLAT_TIRE] = &hf_c2p_sti_value_state_desc,
    [STI_EV_DISABLED_VEHICLE] = &hf_c2p_sti_value_state_desc,
    [STI_EV_AIRBAG_DEPLOYED] = &hf_c2p_sti_value_state_desc,
    [STI_EXT_LIGHT_LOWBEAM_HEAD] = &hf_c2p_sti_value_state_desc,
    [STI_EXT_LIGHT_HIGHBEAM_HEAD] = &hf_c2p_sti_value_state_desc,
    [STI_EXT_LIGHT_LEFT_TURN_SIGNAL] = &hf_c2p_sti_value_state_desc,
    [STI_EXT_LIGHT_RIGHT_TURN_SIGNAL] = &hf_c2p_sti_value_state_desc,
    [STI_EXT_LIGHT_HAZARD_LIGHT] = &hf_c2p_sti_value_state_desc,
    [STI_EXT_LIGHT_AUTO_LIGHT_CONTROL] = &hf_c2p_sti_value_state_desc,
    [STI_EXT_LIGHT_DAYTIME_RUNNING] = &hf_c2p_sti_value_state_desc,
    [STI_EXT_LIGHT_FOG] = &hf_c2p_sti_value_state_desc,
    [STI_EXT_LIGHT_PARKING] = &hf_c2p_sti_value_state_desc,
    [STI_EXT_LIGHT_REVERSE] = &hf_c2p_sti_value_state_desc,
    [STI_STATION_TYPE] = &hf_c2p_sti_value_station_type_desc,
    [STI_VEHICLE_ROLE] = &hf_c2p_sti_value_vehicle_role_desc,
    [STI_BUMPER_HEIGHT_FRONT] = &hf_c2p_sti_value_length_desc,
    [STI_BUMPER_HEIGHT_REAR] = &hf_c2p_sti_value_length_desc,
    [STI_WEATHER_RAIN_RATE] = &hf_c2p_sti_value_rain_rate_desc,
    [STI_RAIN_SENSOR] = &hf_c2p_sti_value_thousandths_desc,
    [STI_WEATHER_PRECIP_SITUATON] = &hf_c2p_sti_value_weather_precip_situation_desc,
    [STI_WEATHER_SOLAR_RADIATION] = &hf_c2p_sti_value_solar_irradiance_desc,
    [STI_WEATHER_COEF_FRICTION] = &hf_c2p_sti_value_thousandths_desc,
    [STI_WEATHER_AIR_TEMP] = &hf_c2p_sti_value_temperature_desc,
    [STI_WEATHER_AIR_PRESSURE] = &hf_c2p_sti_value_pressure_desc,
    [STI_WIPER_STATE_FRONT] = &hf_c2p_sti_value_wiper_state_desc,
    [STI_WIPER_STATE_REAR] = &hf_c2p_sti_value_wiper_state_desc,
    [STI_WIPER_RATE_FRONT] = &hf_c2p_sti_value_sweep_rate_desc,
    [STI_WIPER_RATE_REAR] = &hf_c2p_sti_value_sweep_rate_desc,
    [STI_EMBARKATION_STATUS] = &hf_c2p_sti_value_state_desc,
    [STI_LIGHTBAR] = &hf_c2p_sti_value_lightbar_desc,
    [STI_SIREN] = &hf_c2p_sti_value_siren_desc,
    [STI_ACCELERATOR_PEDAL] = &hf_c2p_sti_value_thousandths_desc,
    [STI_BRAKE_PEDAL] = &hf_c2p_sti_value_thousandths_desc,
    [STI_COLLISION_WARNING] = &hf_c2p_sti_value_state_desc,
    [STI_ADAPTIVE_CRUISE_CONTROL] = &hf_c2p_sti_value_state_desc,
    [STI_CRUISE_CONTROL] = &hf_c2p_sti_value_state_desc,
    [STI_SPEED_LIMITER] = &hf_c2p_sti_value_state_desc,
    [STI_LANE_POSITION] = &hf_c2p_sti_value_lane_position_desc,
    [STI_TRAILER_WEIGHT] = &hf_c2p_sti_value_mass_desc,
    [STI_DOOR_STATE_FRONT_LEFT] = &hf_c2p_sti_value_door_state_desc,
    [STI_DOOR_STATE_FRONT_RIGHT] = &hf_c2p_sti_value_door_state_desc,
    [STI_DOOR_STATE_REAR_LEFT] = &hf_c2p_sti_value_door_state_desc,
    [STI_DOOR_STATE_REAR_RIGHT] = &hf_c2p_sti_value_door_state_desc,
    [STI_DOOR_STATE_BONNET] = &hf_c2p_sti_value_door_state_desc,
    [STI_DOOR_STATE_TRUNK] = &hf_c2p_sti_value_door_state_desc,
    [STI_FUEL_TYPE] = &hf_c2p_sti_value_fuel_type_desc,
    [STI_ROAD_CLASS] = &hf_c2p_sti_value_road_class_desc,
    [STI_ROAD_RULE] = &hf_c2p_sti_value_road_rule_desc,
    [STI_AREA_TYPE] = &hf_c2p_sti_value_area_type_desc,
    [STI_AUTOMATIC_EMERGENCY_BRAKE] = &hf_c2p_sti_value_state_desc,
    [STI_REVERSIBLE_OCCUPANT_RESTRAINT_SYSTEM] = &hf_c2p_sti_value_state_desc,
    [STI_RED_WARNING_ACTIVE] = &hf_c2p_sti_value_state_desc,
    [STI_BELT_BUCKLE_ROW1_DRIVER] = &hf_c2p_sti_value_belt_buckle_status_desc,
    [STI_BELT_BUCKLE_ROW1_MIDDLE] = &hf_c2p_sti_value_belt_buckle_status_desc,
    [STI_BELT_BUCKLE_ROW1_PASSENGER] = &hf_c2p_sti_value_belt_buckle_status_desc,
    [STI_BELT_BUCKLE_ROW2_DRIVER] = &hf_c2p_sti_value_belt_buckle_status_desc,
    [STI_BELT_BUCKLE_ROW2_MIDDLE] = &hf_c2p_sti_value_belt_buckle_status_desc,
    [STI_BELT_BUCKLE_ROW2_PASSENGER] = &hf_c2p_sti_value_belt_buckle_status_desc,
    [STI_BELT_BUCKLE_ROW3_DRIVER] = &hf_c2p_sti_value_belt_buckle_status_desc,
    [STI_BELT_BUCKLE_ROW3_MIDDLE] = &hf_c2p_sti_value_belt_buckle_status_desc,
    [STI_BELT_BUCKLE_ROW3_PASSENGER] = &hf_c2p_sti_value_belt_buckle_status_desc,
    [STI_IGNITION] = &hf_c2p_sti_value_state_desc,
    [STI_TRANSMISSION_TYPE] = &hf_c2p_sti_value_transmission_type_desc,
    [STI_PHYSICAL_ROAD_SEPARATION] = &hf_c2p_sti_value_physical_road_separation_desc,
    [STI_MANUAL_ECALL] = &hf_c2p_sti_value_state_desc,
    [STI_LOW_SEVERITY_CRASH] = &hf_c2p_sti_value_state_desc,
    [STI_PEDESTRIAN_COLLISION] = &hf_c2p_sti_value_state_desc,
    [STI_HIGH_SEVERITY_CRASH] = &hf_c2p_sti_value_state_desc,
    [STI_EV_JACKKNIFE] = &hf_c2p_sti_value_state_desc,
    [STI_PROJECT_00] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_01] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_02] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_03] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_04] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_05] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_06] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_07] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_08] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_09] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_10] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_11] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_12] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_13] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_14] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_15] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_16] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_17] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_18] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_19] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_20] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_21] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_22] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_23] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_24] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_25] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_26] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_27] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_28] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_29] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_30] = &hf_c2p_sti_value_integer_desc,
    [STI_PROJECT_31] = &hf_c2p_sti_value_integer_desc,
};

static void set_tst_proto_item_info(tvbuff_t* tvb, int offset, proto_item* ti)
{
    if((NULL != tvb) && (NULL != ti)) {
        uint32_t tst_sec = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
        uint32_t tst_msec = tvb_get_uint32(tvb, offset + 4, ENC_BIG_ENDIAN);

        static const time_t TIME_2004_IN_ABSTIME = 1072915200ULL;
        time_t timestamp = tst_sec + TIME_2004_IN_ABSTIME;
        struct tm* utc_time = gmtime(&timestamp);

        enum { TIMETAMP_STR_MAX_LEN = 128UL };
        char timestamp_str[TIMETAMP_STR_MAX_LEN] = {0};
        strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", utc_time);

        proto_item_append_text(ti, " - %s.%lu GMT", timestamp_str, (unsigned long)tst_msec);
    }
}

static void channel_format(char* string, uint32_t value)
{
    static const uint8_t CHANNEL_NA = 0U;

    if(CHANNEL_NA == value) {
        snprintf(string, ITEM_LABEL_LENGTH, "Unavailable (%d)", value);
    } else {
        snprintf(string, ITEM_LABEL_LENGTH, "%u", value);
    }
}

static void datarate_format(char* string, uint32_t value)
{
    static const uint8_t DATARATE_NA = 0U;

    if(DATARATE_NA == value) {
        snprintf(string, ITEM_LABEL_LENGTH, "Unavailable (%d)", value);
    } else {
        static const uint32_t DATARATE_500_KBPS_TO_KBPS_FACTOR = 500UL;
        uint32_t value_kbps = value * DATARATE_500_KBPS_TO_KBPS_FACTOR;
        snprintf(string, ITEM_LABEL_LENGTH, "%lu Kbps (%u)", (unsigned long)value_kbps, value);
    }
}

static void latitude_format(char* string, uint32_t value)
{
    int32_t lat = (int32_t)value;
    static const int32_t LATITUDE_NA = 900000001L;

    if(LATITUDE_NA == lat) {
        snprintf(string, ITEM_LABEL_LENGTH, "Unavailable (%ld)", (long int)lat);
    } else {
        snprintf(string, ITEM_LABEL_LENGTH, "%u°%u'%.3f\"%c (%d)",
                 abs(lat) / 10000000,
                 abs(lat) % 10000000 * 6 / 1000000,
                 abs(lat) % 10000000 * 6 % 1000000 * 6.0 / 100000.0,
                 (lat >= 0) ? 'N' : 'S',
                 lat);
    }
}

static void longitude_format(char* string, uint32_t value)
{
    int32_t lon = (int32_t)value;
    static const int32_t LONGITUDE_NA = 1800000001L;

    if(LONGITUDE_NA == lon) {
        snprintf(string, ITEM_LABEL_LENGTH, "Unavailable (%ld)", (long int)lon);
    } else {
        snprintf(string, ITEM_LABEL_LENGTH, "%u°%u'%.3f\"%c (%d)",
                 abs(lon) / 10000000,
                 abs(lon) % 10000000 * 6 / 1000000,
                 abs(lon) % 10000000 * 6 % 1000000 * 6.0 / 100000.0,
                 (lon >= 0) ? 'E' : 'W',
                 lon);
    }
}

static void altitude_format(char* string, uint32_t value)
{
    int32_t alt = (int32_t)value;
    static const int32_t ALTIITUDE_NA = 800001L;

    if(ALTIITUDE_NA == alt) {
        snprintf(string, ITEM_LABEL_LENGTH, "Unavailable (%ld)", (long int)alt);
    } else {
        static const double FACTOR_0P01_M_TO_M_FACTOR = 0.01;

        double value_m = alt * FACTOR_0P01_M_TO_M_FACTOR;

        snprintf(string, ITEM_LABEL_LENGTH, "%.2f m (%ld)", value_m, (long int)alt);
    }
}

static void speed_format(char* string, uint32_t value)
{
    static const uint32_t SPEED_STANDSTILL = 0UL;
    static const uint32_t SPEED_NA = 16383UL;

    if(SPEED_STANDSTILL == value) {
        snprintf(string, ITEM_LABEL_LENGTH, "Standstill (%lu)", (unsigned long)value);
    } else if(SPEED_NA == value) {
        snprintf(string, ITEM_LABEL_LENGTH, "Unavailable (%lu)", (unsigned long)value);
    } else {
        static const double FACTOR_0P01_MPS_TO_MPS_FACTOR = 0.01;
        static const double FACTOR_MPS_TO_KMPH_FACTOR = 3.6;

        double v_mps = value * FACTOR_0P01_MPS_TO_MPS_FACTOR;
        double v_kmph = v_mps * FACTOR_MPS_TO_KMPH_FACTOR;

        snprintf(string,
                 ITEM_LABEL_LENGTH,
                 "%.2f m/s = %.1f km/h (%lu)",
                 v_mps,
                 v_kmph,
                 (unsigned long)value);
    }
}

static void heading_format(char* string, uint32_t value)
{
    const char* p = try_val_to_str(value, VALS(heading_predefined_values));
    if(NULL != p) {
        snprintf(string, ITEM_LABEL_LENGTH, "%s (%lu)", p, (unsigned long)value);
    } else {
        static const double FACTOR_0P1_DEG_TO_DEG_FACTOR = 0.1;
        double value_deg = value * FACTOR_0P1_DEG_TO_DEG_FACTOR;

        snprintf(string, ITEM_LABEL_LENGTH, "%.1f° (%lu)", value_deg, (unsigned long)value);
    }
}

static void semi_axis_format(char* string, uint32_t value)
{
    static const uint16_t SEMI_AXIS_NA = 4095U;
    static const uint16_t SEMI_AXIS_OOR = 4094U;

    if(SEMI_AXIS_NA == value) {
        snprintf(string, ITEM_LABEL_LENGTH, "Unavailable (%lu)", (unsigned long)value);
    } else if(SEMI_AXIS_OOR == value) {
        snprintf(string, ITEM_LABEL_LENGTH, "Out of range (%lu)", (unsigned long)value);
    } else {
        static const double FACTOR_0P01_M_TO_M_FACTOR = 0.01;

        double value_m = value * FACTOR_0P01_M_TO_M_FACTOR;
        snprintf(string, ITEM_LABEL_LENGTH, "%.2f m (%lu)", value_m, (unsigned long)value);
    }
}

static void altitude_acc_format(char* string, uint32_t value)
{
    static const uint16_t ALTITUDE_ACC_NA = 65535U;

    if(ALTITUDE_ACC_NA == value) {
        snprintf(string, ITEM_LABEL_LENGTH, "Unavailable (%lu)", (unsigned long)value);
    } else {
        static const double FACTOR_0P01_M_TO_M_FACTOR = 0.01;

        double value_m = value * FACTOR_0P01_M_TO_M_FACTOR;
        snprintf(string, ITEM_LABEL_LENGTH, "%.2f m (%lu)", value_m, (unsigned long)value);
    }
}

static void heading_acc_format(char* string, uint32_t value)
{
    static const uint16_t HEADING_ACC_NA = 127U;

    if(HEADING_ACC_NA == value) {
        snprintf(string, ITEM_LABEL_LENGTH, "Unavailable (%lu)", (unsigned long)value);
    } else {
        static const double FACTOR_0P1_DEG_TO_DEG_FACTOR = 0.1;
        double value_deg = value * FACTOR_0P1_DEG_TO_DEG_FACTOR;

        snprintf(string, ITEM_LABEL_LENGTH, "%.1f° (%lu)", value_deg, (unsigned long)value);
    }
}

static void speed_acc_format(char* string, uint32_t value)
{
    static const uint16_t SPEED_ACC_NA = 127U;

    if(SPEED_ACC_NA == value) {
        snprintf(string, ITEM_LABEL_LENGTH, "Unavailable (%lu)", (unsigned long)value);
    } else {
        static const double FACTOR_0P01_MPS_TO_MPS_FACTOR = 0.01;
        static const double FACTOR_MPS_TO_KMPH_FACTOR = 3.6;

        double v_mps = value * FACTOR_0P01_MPS_TO_MPS_FACTOR;
        double v_kmph = v_mps * FACTOR_MPS_TO_KMPH_FACTOR;

        snprintf(string,
                 ITEM_LABEL_LENGTH,
                 "%.2f m/s = %.1f km/h (%lu)",
                 v_mps,
                 v_kmph,
                 (unsigned long)value);
    }
}

static void power_format(char* string, uint32_t value)
{
    int8_t rssi = (int8_t)value;
    static const int8_t RSSI_NA = 127;

    if(RSSI_NA == rssi) {
        snprintf(string, ITEM_LABEL_LENGTH, "Unavailable (%d)", rssi);
    } else {
        snprintf(string, ITEM_LABEL_LENGTH, "%d dBm", rssi);
    }
}

static void cv2x_tx_power_format(char* string, int32_t value)
{
    static const int32_t POWER_NA = INT16_MAX;

    if(POWER_NA == value) {
        snprintf(string, ITEM_LABEL_LENGTH, "Unavailable (%ld)", (long)value);
    } else {
        snprintf(string, ITEM_LABEL_LENGTH, "%ld dBm", (long)value);
    }
}

static const value_string priority_format_vals[] = {
    {0, "Highest priority"},
    {1, "Level 1 priority"},
    {2, "Level 2 priority"},
    {3, "Level 3 priority"},
    {4, "Level 4 priority"},
    {5, "Level 5 priority"},
    {6, "Level 6 priority"},
    {7, "Lowest priority"},
    {0, NULL}
};

static void cbr_format(char* string, uint32_t value)
{
    static const uint16_t CBR_NA = 1001U;

    if(CBR_NA == value) {
        snprintf(string, ITEM_LABEL_LENGTH, "Unavailable (%lu)", (unsigned long)value);
    } else {
        static const double FACTOR_0P1_PERC_TO_PERC_FACTOR = 0.1;
        double value_perc = value * FACTOR_0P1_PERC_TO_PERC_FACTOR;

        snprintf(string, ITEM_LABEL_LENGTH, "%.1f %% (%lu)", value_perc, (unsigned long)value);
    }
}

static void gps_timestamp_format(char* string, uint64_t value)
{
    static const uint64_t GPS_TIMESTAMP_NA = 0U;

    if(GPS_TIMESTAMP_NA == value) {
        snprintf(string, ITEM_LABEL_LENGTH, "Unavailable (%" PRIu64 ")", value);
    } else {
        time_t timestamp = value / 1000ULL;
        uint32_t tst_msec = value % 1000UL;
        struct tm* utc_time = gmtime(&timestamp);

        enum { TIMETAMP_STR_MAX_LEN = 128UL };
        char timestamp_str[TIMETAMP_STR_MAX_LEN] = {0};
        strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", utc_time);

        snprintf(string,
                 ITEM_LABEL_LENGTH,
                 "%s.%lu GMT (%" PRIu64 ")",
                 timestamp_str,
                 (unsigned long)tst_msec,
                 value);
    }
}

static bool sti_value_common_format(char* string, int64_t value)
{
    bool formatted = true;
    static const int64_t STI_VALUE_NA = INT64_MIN;
    static const int64_t STI_VALUE_OOR_MIN = INT64_MIN + INT64_C(1);
    static const int64_t STI_VALUE_OOR_MAX = INT64_MAX;

    if(STI_VALUE_NA == value) {
        snprintf(string, ITEM_LABEL_LENGTH, "Unavailable (%" PRId64 ")", value);
    } else if(STI_VALUE_OOR_MIN == value) {
        snprintf(string,
                 ITEM_LABEL_LENGTH,
                 "Out of range (minimum) (%" PRId64 ")",
                 value);
    } else if(STI_VALUE_OOR_MAX == value) {
        snprintf(string,
                 ITEM_LABEL_LENGTH,
                 "Out of range (maximum) (%" PRId64 ")",
                 value);
    } else {
        formatted = false;
    }

    return formatted;
}


static void sti_value_angle_format(char* string, int64_t value)
{
    if(!sti_value_common_format(string, value)) {
        static const double FACTOR_0P001_DEG_TO_DEG_FACTOR = 0.001;
        double value_deg = value * FACTOR_0P001_DEG_TO_DEG_FACTOR;

        snprintf(string,
                 ITEM_LABEL_LENGTH,
                 "%.3f° (%" PRId64 ")",
                 value_deg,
                 value);
    }
}

static void sti_value_acceleration_format(char* string, int64_t value)
{
    if(!sti_value_common_format(string, value)) {
        static const double MMPS2_TO_MPS2_FACTOR = 0.001;
        double value_mps2 = value * MMPS2_TO_MPS2_FACTOR;

        snprintf(string,
                 ITEM_LABEL_LENGTH,
                 "%.3f m/s² (%" PRId64 ")",
                 value_mps2,
                 value);
    }
}

static void sti_value_angular_velocity_format(char* string, int64_t value)
{
    if(!sti_value_common_format(string, value)) {
        static const double FACTOR_0P001_DEGPS_TO_DEGPS_FACTOR = 0.001;
        double value_degps = value * FACTOR_0P001_DEGPS_TO_DEGPS_FACTOR;

        snprintf(string,
                 ITEM_LABEL_LENGTH,
                 "%.3f°/s (%" PRId64 ")",
                 value_degps,
                 value);
    }
}

static void sti_value_thousandths_format(char* string, int64_t value)
{
    if(!sti_value_common_format(string, value)) {
        static const double THOUSANDTHS_TO_PERCENT_FACTOR = 0.1;
        double value_percent = value * THOUSANDTHS_TO_PERCENT_FACTOR;

        snprintf(string,
                ITEM_LABEL_LENGTH,
                "%.3f%% (%" PRId64 ")",
                value_percent,
                value);
    }
}

static void sti_value_length_format(char* string, int64_t value)
{
    if(!sti_value_common_format(string, value)) {
        static const double MM_TO_M_FACTOR = 0.001;
        double value_m = value * MM_TO_M_FACTOR;

        snprintf(string,
                 ITEM_LABEL_LENGTH,
                 "%.3f m (%" PRId64 ")",
                 value_m,
                 value);
    }
}

static void sti_value_mass_format(char* string, int64_t value)
{
    if(!sti_value_common_format(string, value)) {
        static const double G_TO_KG_FACTOR = 0.001;
        double value_kg = value * G_TO_KG_FACTOR;

        snprintf(string,
                 ITEM_LABEL_LENGTH,
                 "%.3f kg (%" PRId64 ")",
                 value_kg,
                 value);
    }
}

static void sti_value_rain_rate_format(char* string, int64_t value)
{
    if(!sti_value_common_format(string, value)) {
        snprintf(string,
                 ITEM_LABEL_LENGTH,
                 "%" PRId64 " g/s/m²",
                 value);
    }
}

static void sti_value_solar_irradiance_format(char* string, int64_t value)
{
    if(!sti_value_common_format(string, value)) {
        snprintf(string,
                 ITEM_LABEL_LENGTH,
                 "%" PRId64 " J/m²",
                 value);
    }
}

static void sti_value_temperature_format(char* string, int64_t value)
{
    if(!sti_value_common_format(string, value)) {
        static const double FACTOR_0P1_DEG_TO_DEG_FACTOR = 0.1;
        double value_deg = value * FACTOR_0P1_DEG_TO_DEG_FACTOR;

        snprintf(string,
                 ITEM_LABEL_LENGTH,
                 "%.1f° (%" PRId64 ")",
                 value_deg,
                 value);
    }
}

static void sti_value_pressure_format(char* string, int64_t value)
{
    if(!sti_value_common_format(string, value)) {
        snprintf(string,
                 ITEM_LABEL_LENGTH,
                 "%" PRId64 " Pa",
                 value);
    }
}

static void sti_value_sweep_rate_format(char* string, int64_t value)
{
    if(!sti_value_common_format(string, value)) {
        snprintf(string,
                 ITEM_LABEL_LENGTH,
                 "%" PRId64 " sweeps/min",
                 value);
    }
}

static void sti_value_integer_format(char* string, int64_t value)
{
    if(!sti_value_common_format(string, value)) {
        snprintf(string,
                 ITEM_LABEL_LENGTH,
                 "%" PRId64,
                 value);
    }
}

static int dissect_dsrc_rx(tvbuff_t* tvb, proto_tree* c2p_tree, packet_info* pinfo)
{
    int offset = 0;

    proto_tree_add_item(c2p_tree, hf_c2p_primary_channel_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_secondary_channel_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_used_interface_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_datarate_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_antenna_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_latitude_desc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(c2p_tree, hf_c2p_longitude_desc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(c2p_tree, hf_c2p_speed_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(c2p_tree, hf_c2p_heading_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(c2p_tree, hf_c2p_rssi_ant_1_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_rssi_ant_2_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_noise_ant_1_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_noise_ant_2_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_cbr_ant_1_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(c2p_tree, hf_c2p_cbr_ant_2_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if(NULL != ieee80211_handle) {
        proto_tree* root_tree = proto_tree_get_root(c2p_tree);
        tvbuff_t* next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(ieee80211_handle, next_tvb, pinfo, root_tree);
    }

    return offset;
}

static int dissect_dsrc_tx(tvbuff_t* tvb, proto_tree* c2p_tree, packet_info* pinfo)
{
    int offset = 0;

    proto_tree_add_item(c2p_tree, hf_c2p_primary_channel_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_secondary_channel_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_used_interface_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_datarate_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_antenna_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_latitude_desc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(c2p_tree, hf_c2p_longitude_desc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(c2p_tree, hf_c2p_speed_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(c2p_tree, hf_c2p_heading_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(c2p_tree, hf_c2p_tx_power_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_tssi_ant_1_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_tssi_ant_2_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if(NULL != ieee80211_handle) {
        proto_tree* root_tree = proto_tree_get_root(c2p_tree);
        tvbuff_t* next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(ieee80211_handle, next_tvb, pinfo, root_tree);
    }

    return offset;
}

static int dissect_cv2x_tx(tvbuff_t* tvb, proto_tree* c2p_tree, packet_info* pinfo)
{
    int offset = 0;

    proto_tree_add_item(c2p_tree, hf_c2p_sps_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_sps_port_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(c2p_tree, hf_c2p_event_port_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(c2p_tree, hf_c2p_cv2x_tx_power_desc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(c2p_tree, hf_c2p_bw_res_v2xid_desc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(c2p_tree, hf_c2p_bw_res_period_interval_ms_desc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(c2p_tree, hf_c2p_bw_res_tx_reservation_size_bytes_desc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(c2p_tree, hf_c2p_bw_res_tx_priority_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if(NULL != ieee80211_handle) {
        proto_tree* root_tree = proto_tree_get_root(c2p_tree);
        tvbuff_t* next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(ieee80211_handle, next_tvb, pinfo, root_tree);
    }

    return offset;
}

static int dissect_cv2x_rx(tvbuff_t* tvb, proto_tree* c2p_tree, packet_info* pinfo)
{
    int offset = 0;

    proto_tree_add_item(c2p_tree, hf_c2p_socket_index_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_ethertype_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(c2p_tree, hf_c2p_rssi_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_datarate_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if(NULL != ieee80211_handle) {
        proto_tree* root_tree = proto_tree_get_root(c2p_tree);
        tvbuff_t* next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(ieee80211_handle, next_tvb, pinfo, root_tree);
    }

    return offset;
}

static int dissect_nav(tvbuff_t* tvb, proto_tree* c2p_tree)
{
    int offset = 0;

    proto_tree_add_item(c2p_tree, hf_c2p_nav_fix_is_valid_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(c2p_tree, hf_c2p_gps_timestamp_desc, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(c2p_tree, hf_c2p_latitude_desc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(c2p_tree, hf_c2p_longitude_desc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(c2p_tree, hf_c2p_altitude_desc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(c2p_tree, hf_c2p_heading_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(c2p_tree, hf_c2p_speed_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(c2p_tree, hf_c2p_semi_major_conf_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(c2p_tree, hf_c2p_semi_minor_conf_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(c2p_tree, hf_c2p_semi_major_ori_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(c2p_tree, hf_c2p_alttitude_acc_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(c2p_tree, hf_c2p_heading_acc_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(c2p_tree, hf_c2p_speed_acc_desc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static int dissect_sti(tvbuff_t* tvb, proto_tree* c2p_tree, packet_info* pinfo)
{
    int offset = 0;

    uint32_t length = tvb_get_uint32(tvb, 0, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(c2p_tree, hf_c2p_sti_length_desc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    for(uint32_t i = 0UL; i < length; ++i) {
        char* str_display;
        str_display = wmem_strdup_printf(pinfo->pool, "STI #%lu", (unsigned long)i);
        /* STI item length is 4 bytes of type and 8 bytes of value */
        static const int STI_ITEM_LEN = 12UL;
        proto_tree* subtree = proto_tree_add_subtree(c2p_tree,
                                                     tvb,
                                                     offset,
                                                     STI_ITEM_LEN,
                                                     ett_c2p,
                                                     NULL,
                                                     str_display);
        sti_type_t sti_type = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(subtree,
                            hf_c2p_sti_type_desc,
                            tvb,
                            offset,
                            4,
                            ENC_LITTLE_ENDIAN);
        offset += 4;

        int hf_index = hf_c2p_sti_value_integer_desc;

        if((sti_type < array_length(sti_params)) && (sti_params[sti_type] != NULL)) {
            hf_index = *(sti_params[sti_type]);
        }

        proto_tree_add_item(subtree,
                            hf_index,
                            tvb,
                            offset,
                            8,
                            ENC_LITTLE_ENDIAN);
        offset += 8;
    }

    return offset;
}

static int dissect_c2p(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    int offset = 0;
    uint32_t type, version;
    char* str_type;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "C2P");
    col_clear(pinfo->cinfo, COL_INFO);


    proto_item* ti = proto_tree_add_item(tree, proto_desc, tvb, 0, -1, ENC_NA);

    proto_tree* c2p_tree = proto_item_add_subtree(ti, ett_c2p);

    /* Version & type */
    proto_tree_add_item_ret_uint(c2p_tree, hf_c2p_version_desc, tvb, offset, 1, ENC_BIG_ENDIAN, &version);
    proto_tree_add_item_ret_uint(c2p_tree, hf_c2p_type_desc, tvb, offset, 1, ENC_BIG_ENDIAN, &type);
    str_type = val_to_str(pinfo->pool, type, c2p_types, "Unknown (%d)");
    proto_item_append_text(ti, ", Type: %s", str_type);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type: %s", str_type);
    offset += 1;

    /* Timestamp */
    proto_tree* c2p_tst_tree = proto_tree_add_subtree(c2p_tree,
                                                      tvb,
                                                      offset,
                                                      -1,
                                                      ett_c2p,
                                                      NULL,
                                                      "Timestamp");

    set_tst_proto_item_info(tvb, offset, c2p_tst_tree);

    proto_tree_add_item(c2p_tst_tree, hf_c2p_tst_sec_desc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(c2p_tst_tree, hf_c2p_tst_msec_desc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Set 'Timestamp' length */
    proto_item_set_len(c2p_tst_tree, 8);

    /* Dissect the rest depending on type */
    tvbuff_t* next_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, -1);

    static uint8_t C2P_VERSION_0 = 0U;
    static uint8_t C2P_VERSION_1 = 1U;
    static uint8_t C2P_VERSION_2 = 2U;

    (void)C2P_VERSION_0;

    if(C2P_VERSION_1 == version) {
        switch(type) {
        case C2P_TYPE_DSRC_RX:
            offset += dissect_dsrc_rx(next_tvb, c2p_tree, pinfo);
            break;
        case C2P_TYPE_DSRC_TX:
            offset += dissect_dsrc_tx(next_tvb, c2p_tree, pinfo);
            break;
        case C2P_TYPE_NAV:
            offset += dissect_nav(next_tvb, c2p_tree);
            break;
        case C2P_TYPE_CV2X_RX:
            offset += dissect_cv2x_rx(next_tvb, c2p_tree, pinfo);
            break;
        case C2P_TYPE_CV2X_TX:
            offset += dissect_cv2x_tx(next_tvb, c2p_tree, pinfo);
            break;
        default:
            break;
        }
    } else if(C2P_VERSION_2 == version) {
        switch(type) {
        case C2P_TYPE_STI:
            offset += dissect_sti(next_tvb, c2p_tree, pinfo);
            break;
        default:
            break;
        }
    }

    /* Set C2P length */
    proto_item_set_len(ti, offset);

    return offset;
}

void proto_register_c2p(void)
{
    static hf_register_info header_fields[] = {
        {
            &hf_c2p_version_desc,
            {
                "Version",
                "c2p.version",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0xF0,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_type_desc,
            {
                "Type",
                "c2p.type",
                FT_UINT8,
                BASE_DEC,
                VALS(c2p_types),
                0x0F,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_tst_sec_desc,
            {
                "Seconds",
                "c2p.tst.sec",
                FT_UINT32,
                BASE_DEC | BASE_UNIT_STRING,
                UNS(&units_seconds),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_tst_msec_desc,
            {
                "Milliseconds",
                "c2p.tst.msec",
                FT_UINT32,
                BASE_DEC | BASE_UNIT_STRING,
                UNS(&units_milliseconds),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_primary_channel_desc,
            {
                "Primary channel",
                "c2p.primary_channel",
                FT_UINT8,
                BASE_CUSTOM,
                CF_FUNC(channel_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_secondary_channel_desc,
            {
                "Secondary channel",
                "c2p.secondary_channel",
                FT_UINT8,
                BASE_CUSTOM,
                CF_FUNC(channel_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_used_interface_desc,
            {
                "Used interface",
                "c2p.used_interface",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_datarate_desc,
            {
                "Datarate",
                "c2p.datarate",
                FT_UINT8,
                BASE_CUSTOM,
                CF_FUNC(datarate_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_antenna_desc,
            {
                "Used antenna",
                "c2p.used_antenna",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_latitude_desc,
            {
                "Latitude",
                "c2p.latitude",
                FT_INT32,
                BASE_CUSTOM,
                CF_FUNC(latitude_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_longitude_desc,
            {
                "Longitude",
                "c2p.longitude",
                FT_INT32,
                BASE_CUSTOM,
                CF_FUNC(longitude_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_altitude_desc,
            {
                "Altitude",
                "c2p.altitude",
                FT_INT32,
                BASE_CUSTOM,
                CF_FUNC(altitude_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_speed_desc,
            {
                "Speed",
                "c2p.speed",
                FT_UINT16,
                BASE_CUSTOM,
                CF_FUNC(speed_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_heading_desc,
            {
                "Heading",
                "c2p.heading",
                FT_UINT16,
                BASE_CUSTOM,
                CF_FUNC(heading_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_semi_major_conf_desc,
            {
                "Semi major confidence",
                "c2p.semi_major_conf",
                FT_UINT16,
                BASE_CUSTOM,
                CF_FUNC(semi_axis_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_semi_minor_conf_desc,
            {
                "Semi minor confidence",
                "c2p.semi_minor_conf",
                FT_UINT16,
                BASE_CUSTOM,
                CF_FUNC(semi_axis_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_semi_major_ori_desc,
            {
                "Semi major orientation",
                "c2p.semi_major_orientation",
                FT_UINT16,
                BASE_CUSTOM,
                CF_FUNC(heading_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_alttitude_acc_desc,
            {
                "Altitude accuracy",
                "c2p.altitude_accuracy",
                FT_UINT16,
                BASE_CUSTOM,
                CF_FUNC(altitude_acc_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_heading_acc_desc,
            {
                "Heading accuracy",
                "c2p.heading_accuracy",
                FT_UINT16,
                BASE_CUSTOM,
                CF_FUNC(heading_acc_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_speed_acc_desc,
            {
                "Speed accuracy",
                "c2p.speed_accuracy",
                FT_UINT16,
                BASE_CUSTOM,
                CF_FUNC(speed_acc_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_rssi_ant_1_desc,
            {
                "RSSI on antenna #1",
                "c2p.rssi_antenna1",
                FT_INT8,
                BASE_CUSTOM,
                CF_FUNC(power_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_rssi_ant_2_desc,
            {
                "RSSI on antenna #2",
                "c2p.rssi_antenna2",
                FT_INT8,
                BASE_CUSTOM,
                CF_FUNC(power_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_noise_ant_1_desc,
            {
                "Noise on antenna #1",
                "c2p.noise_antenna1",
                FT_INT8,
                BASE_CUSTOM,
                CF_FUNC(power_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_noise_ant_2_desc,
            {
                "Noise on antenna #2",
                "c2p.noise_antenna2",
                FT_INT8,
                BASE_CUSTOM,
                CF_FUNC(power_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_cbr_ant_1_desc,
            {
                "CBR on antenna #1",
                "c2p.cbr_antenna1",
                FT_UINT16,
                BASE_CUSTOM,
                CF_FUNC(cbr_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_cbr_ant_2_desc,
            {
                "CBR on antenna #2",
                "c2p.cbr_antenna2",
                FT_UINT16,
                BASE_CUSTOM,
                CF_FUNC(cbr_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_tx_power_desc,
            {
                "Transmission power",
                "c2p.tx_power",
                FT_INT8,
                BASE_CUSTOM,
                CF_FUNC(power_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_tssi_ant_1_desc,
            {
                "TSSI on antenna #1",
                "c2p.tssi_antenna1",
                FT_INT8,
                BASE_CUSTOM,
                CF_FUNC(power_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_tssi_ant_2_desc,
            {
                "TSSI on antenna #2",
                "c2p.tssi_antenna2",
                FT_INT8,
                BASE_CUSTOM,
                CF_FUNC(power_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sps_desc,
            {
                "Is SPS port",
                "c2p.cv2x_sps",
                FT_BOOLEAN,
                BASE_NONE,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sps_port_desc,
            {
                "SPS port",
                "c2p.cv2x_sps_port",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_event_port_desc,
            {
                "Event port",
                "c2p.cv2x_event_port",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_cv2x_tx_power_desc,
            {
                "Transmission power",
                "c2p.tx_power",
                FT_INT32,
                BASE_CUSTOM,
                CF_FUNC(cv2x_tx_power_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_bw_res_v2xid_desc,
            {
                "V2X ID",
                "c2p.cv2x_id",
                FT_INT32,
                BASE_DEC,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_bw_res_period_interval_ms_desc,
            {
                "Bandwidth-reserved periodicity interval",
                "c2p.cv2x_bw_res_period_interval",
                FT_INT32,
                BASE_DEC | BASE_UNIT_STRING,
                UNS(&units_seconds),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_bw_res_tx_reservation_size_bytes_desc,
            {
                "Tx bandwidth sent bytes",
                "c2p.cv2x_bw_res_tx_reservation_size_bytes",
                FT_INT32,
                BASE_DEC,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_bw_res_tx_priority_desc,
            {
                "Preserved SPS Tx priority'",
                "c2p.cv2x_bw_res_tx_priority",
                FT_UINT8,
                BASE_DEC,
                VALS(priority_format_vals),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_socket_index_desc,
            {
                "Socket index",
                "c2p.cv2x_socket_index",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_ethertype_desc,
            {
                "Ethernet header type",
                "c2p.cv2x_ethertype",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_rssi_desc,
            {
                "RSSI",
                "c2p.cv2x_rssi",
                FT_INT8,
                BASE_CUSTOM,
                CF_FUNC(power_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_nav_fix_is_valid_desc,
            {
                "Is valid",
                "c2p.nav_fix_is_valid",
                FT_BOOLEAN,
                BASE_NONE,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_gps_timestamp_desc,
            {
                "GPS timestamp",
                "c2p.gps_timestamp",
                FT_UINT64,
                BASE_CUSTOM,
                CF_FUNC(gps_timestamp_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_length_desc,
            {
                "Number of STI parameters",
                "c2p.sti_length",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_type_desc,
            {
                "Type",
                "c2p.sti_type",
                FT_UINT32,
                BASE_DEC,
                VALS(sti_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_angle_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_CUSTOM,
                CF_FUNC(sti_value_angle_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_acceleration_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_CUSTOM,
                CF_FUNC(sti_value_acceleration_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_angular_velocity_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_CUSTOM,
                CF_FUNC(sti_value_angular_velocity_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_thousandths_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_CUSTOM,
                CF_FUNC(sti_value_thousandths_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_length_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_CUSTOM,
                CF_FUNC(sti_value_length_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_mass_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_CUSTOM,
                CF_FUNC(sti_value_mass_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_rain_rate_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_CUSTOM,
                CF_FUNC(sti_value_rain_rate_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_solar_irradiance_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_CUSTOM,
                CF_FUNC(sti_value_solar_irradiance_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_temperature_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_CUSTOM,
                CF_FUNC(sti_value_temperature_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_pressure_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_CUSTOM,
                CF_FUNC(sti_value_pressure_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_sweep_rate_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_CUSTOM,
                CF_FUNC(sti_value_sweep_rate_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_integer_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_CUSTOM,
                CF_FUNC(sti_value_integer_format),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_transmission_state_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_transmission_state_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_aux_breaks_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_aux_breaks_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_vehicle_length_conf_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_vehicle_length_conf_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_dangerous_goods_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_dangerous_goods_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_station_type_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_station_type_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_vehicle_role_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_vehicle_role_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_weather_precip_situation_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_weather_precip_situation_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_wiper_state_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_wiper_state_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_door_state_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_door_state_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_fuel_type_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_fuel_type_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_road_class_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_road_class_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_road_rule_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_road_rule_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_area_type_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_area_type_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_belt_buckle_status_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_belt_buckle_status_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_transmission_type_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_transmission_type_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_physical_road_separation_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_physical_road_separation_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_siren_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_siren_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_lightbar_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_lightbar_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_lane_position_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_lane_position_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_state_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_state_types),
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_c2p_sti_value_tristate_desc,
            {
                "Value",
                "c2p.sti_value",
                FT_INT64,
                BASE_DEC|BASE_VAL64_STRING,
                VALS64(sti_tristate_types),
                0x00,
                NULL,
                HFILL
            }
        },
    };

    int* ett[] = {
        &ett_c2p
    };

    static const char* C2P_PROTOCOL_NAME = "C2P (Commsignia Capture Protocol)";
    static const char* C2P_PROTOCOL_SHORT_NAME = "C2P";
    static const char* C2P_FILTER_NAME = "c2p";

    proto_desc = proto_register_protocol(C2P_PROTOCOL_NAME,
                                         C2P_PROTOCOL_SHORT_NAME,
                                         C2P_FILTER_NAME);

    proto_register_field_array(proto_desc, header_fields, array_length(header_fields));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_c2p(void)
{
    dissector_handle_t c2p_handle = NULL;

    c2p_handle = create_dissector_handle(dissect_c2p, proto_desc);

    ieee80211_handle = find_dissector_add_dependency("wlan", proto_desc);

    static const uint32_t C2P_PORT = 7943UL;
    static const char* UDP_PORT_NAME = "udp.port";

    dissector_add_uint(UDP_PORT_NAME, C2P_PORT, c2p_handle);
}

