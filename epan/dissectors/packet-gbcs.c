/* packet-gbcs.c
 *
 * Dissector for Great Britain Companion Specification (GBCS) used in the Smart Metering Equipment Technical Specifications (SMETS)
 *
 * The Smart Metering Equipment Technical Specifications (SMETS) requires that Gas Smart Metering Equipment (GSME), and Electricity
 * Smart Metering Equipment (ESME) including variants, meet the requirements described in
 * the Great Britain Companion Specification (GBCS).
 *
 * GBCS messages are end-to-end and contains ZigBee, DLMS or ASN.1 formatted payloads. The GBCS messages are transported via IP
 * or via the ZigBee Tunneling cluster.
 *
 * https://smartenergycodecompany.co.uk/document-download-centre/download-info/gbcs-v2-1/
 *
 * Sample capture is attached in Bug 15381
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/dissectors/packet-ber.h>
#include <epan/dissectors/packet-zbee.h>
#include <epan/dissectors/packet-zbee-nwk.h>
#include <epan/dissectors/packet-zbee-zcl.h>
#include <epan/dissectors/packet-zbee-aps.h>
#include <wsutil/time_util.h>

#define gbcs_message_code_names_VALUE_STRING_LIST(XXX) \
    XXX(GBCS_MESSAGE_CCS01,      0x0001, "CCS01 Add Device to CHF device log") \
    XXX(GBCS_MESSAGE_CCS02,      0x0002, "CCS02 Remove device from CHF device log") \
    XXX(GBCS_MESSAGE_CCS03,      0x0003, "CCS03 Restore CHF Device Log") \
    XXX(GBCS_MESSAGE_CCS05CCS04, 0x0004, "CCS05/CCS04 Read CHF device log / Check HAN communications (by reading the CHF Communications Store)") \
    XXX(GBCS_MESSAGE_CS01A,      0x0007, "CS01a Apply Pre-payment Top Up to an ESME") \
    XXX(GBCS_MESSAGE_CS02A,      0x0008, "CS02a Provide Security Credentials Details") \
    XXX(GBCS_MESSAGE_CS02C,      0x000A, "CS02c Issue Security Credentials ") \
    XXX(GBCS_MESSAGE_CS02D,      0x000B, "CS02d Update Device Certificates on Device") \
    XXX(GBCS_MESSAGE_CS02E,      0x000C, "CS02e Provide Device Certificates from Device ") \
    XXX(GBCS_MESSAGE_CS03A1,     0x000D, "CS03a1 Method A Join (Meter)") \
    XXX(GBCS_MESSAGE_CS03B,      0x000E, "CS03b Method B Join") \
    XXX(GBCS_MESSAGE_CS04AC,     0x000F, "CS04ac Method A or C Unjoin") \
    XXX(GBCS_MESSAGE_CS04B,      0x0010, "CS04b Method B Unjoin") \
    XXX(GBCS_MESSAGE_CS06,       0x0012, "CS06 Activate Firmware") \
    XXX(GBCS_MESSAGE_CS07,       0x0013, "CS07 Read Device Join Details") \
    XXX(GBCS_MESSAGE_CS10A,      0x0014, "CS10a Read ZigBee Device Event Log") \
    XXX(GBCS_MESSAGE_CS11,       0x0015, "CS11 Clear ZigBee Device Event Log") \
    XXX(GBCS_MESSAGE_CS14,       0x0018, "CS14 Device Addition To / Removal From HAN Whitelist Alerts") \
    XXX(GBCS_MESSAGE_ECS01A,     0x0019, "ECS01a Set Tariff and Price on ESME") \
    XXX(GBCS_MESSAGE_ECS02,      0x001A, "ECS02 Set ESME Payment Mode to Credit") \
    XXX(GBCS_MESSAGE_ECS03,      0x001B, "ECS03 Set ESME Payment Mode to Pre-payment") \
    XXX(GBCS_MESSAGE_ECS04A,     0x001C, "ECS04a Adjust Meter Balance on the ESME") \
    XXX(GBCS_MESSAGE_ECS05,      0x001D, "ECS05 Reset Tariff Block Counter Matrix") \
    XXX(GBCS_MESSAGE_ECS07,      0x001E, "ECS07 Manage Debt on the ESME") \
    XXX(GBCS_MESSAGE_ECS08,      0x001F, "ECS08 Update Pre-payment Configuration on ESME") \
    XXX(GBCS_MESSAGE_ECS09,      0x0020, "ECS09 Activate Emergency Credit Remotely on ESME") \
    XXX(GBCS_MESSAGE_ECS10,      0x0021, "ECS10 Send Message to ESME") \
    XXX(GBCS_MESSAGE_ECS12,      0x0022, "ECS12 Set Change of Tenancy date on ESME") \
    XXX(GBCS_MESSAGE_ECS14,      0x0023, "ECS14 Disable Privacy PIN Protection on ESME") \
    XXX(GBCS_MESSAGE_ECS15A,     0x0024, "ECS15a Clear ESME Event Log") \
    XXX(GBCS_MESSAGE_ECS16,      0x0025, "ECS16 Write Supplier Contact Details on ESME") \
    XXX(GBCS_MESSAGE_ECS17A,     0x0026, "ECS17a Read ESME Energy Registers (Export Energy)") \
    XXX(GBCS_MESSAGE_ECS17B,     0x0027, "ECS17b Read ESME Energy Registers (Import Energy)") \
    XXX(GBCS_MESSAGE_ECS17C,     0x0028, "ECS17c Read ESME Energy Registers (Power)") \
    XXX(GBCS_MESSAGE_ECS17D,     0x0029, "ECS17d Read ESME Energy Register (TOU)") \
    XXX(GBCS_MESSAGE_ECS17E,     0x002A, "ECS17e Read ESME Energy Register (TOU with Blocks)") \
    XXX(GBCS_MESSAGE_ECS18A,     0x002B, "ECS18a Read Maximum Demand Registers (export)") \
    XXX(GBCS_MESSAGE_ECS18B,     0x002C, "ECS18b Read Maximum Demand Registers (import)") \
    XXX(GBCS_MESSAGE_ECS19,      0x002D, "ECS19 Read ESME Pre-payment Registers") \
    XXX(GBCS_MESSAGE_ECS20A,     0x002E, "ECS20a Read ESME Billing Data Log (payment based debt payments)") \
    XXX(GBCS_MESSAGE_ECS20B,     0x002F, "ECS20b Read ESME Billing Data Log (change of mode / tariff triggered exc export)") \
    XXX(GBCS_MESSAGE_ECS20C,     0x0030, "ECS20c Read ESME Billing Data Log (billing calendar triggered exc export)") \
    XXX(GBCS_MESSAGE_ECS21A,     0x0033, "ECS21a Read Electricity Daily Read Log (exc export)") \
    XXX(GBCS_MESSAGE_ECS21B,     0x0034, "ECS21b Read Electricity (Pre-payment) Daily Read Log") \
    XXX(GBCS_MESSAGE_ECS21C,     0x0035, "ECS21c Read Electricity Daily Read Log (export only)") \
    XXX(GBCS_MESSAGE_ECS22A,     0x0036, "ECS22a Read Electricity Half Hour Profile Data (export)") \
    XXX(GBCS_MESSAGE_ECS22B,     0x0037, "ECS22b Read Electricity Half Hour Profile Data (active import)") \
    XXX(GBCS_MESSAGE_ECS22C,     0x0038, "ECS22c Read Electricity Half Hour Profile Data (reactive import)") \
    XXX(GBCS_MESSAGE_ECS23,      0x0039, "ECS23 Read Voltage Operational Data") \
    XXX(GBCS_MESSAGE_ECS24,      0x003A, "ECS24 Read ESME Tariff Data") \
    XXX(GBCS_MESSAGE_ECS26A,     0x003B, "ECS26a Read ESME Configuration Data Pre-payment") \
    XXX(GBCS_MESSAGE_ECS26B,     0x003C, "ECS26b Read ESME Configuration Voltage Data") \
    XXX(GBCS_MESSAGE_ECS26C,     0x003D, "ECS26c Read ESME Configuration Data Device Information  (randomisation)") \
    XXX(GBCS_MESSAGE_ECS26D,     0x003E, "ECS26d Read ESME Configuration Data Device Information (Billing Calendar)") \
    XXX(GBCS_MESSAGE_ECS26E,     0x003F, "ECS26e Read ESME Configuration Data Device Information (device identity exc MPAN)") \
    XXX(GBCS_MESSAGE_ECS26F,     0x0040, "ECS26f Read ESME Configuration Data Device Information (instantaneous power thresholds)") \
    XXX(GBCS_MESSAGE_ECS27,      0x0042, "ECS27 Read ESME Load Limit Data") \
    XXX(GBCS_MESSAGE_ECS28A,     0x0043, "ECS28a Set Load Limit Configurations - General Settings") \
    XXX(GBCS_MESSAGE_ECS28B,     0x0044, "ECS28b Set Load Limit Configuration Counter Reset") \
    XXX(GBCS_MESSAGE_ECS29A,     0x0045, "ECS29a Set Voltage Configurations on ESME") \
    XXX(GBCS_MESSAGE_ECS30,      0x0046, "ECS30 Set Billing Calendar on the ESME") \
    XXX(GBCS_MESSAGE_ECS34,      0x0047, "ECS34 Set Instantaneous Power Threshold Configuration") \
    XXX(GBCS_MESSAGE_ECS35A,     0x0048, "ECS35a Read ESME Event Log") \
    XXX(GBCS_MESSAGE_ECS35B,     0x0049, "ECS35b Read ESME Security Log") \
    XXX(GBCS_MESSAGE_ECS37,      0x004A, "ECS37 Set Maximum Demand Configurable Time Period") \
    XXX(GBCS_MESSAGE_ECS38,      0x004B, "ECS38 Update Randomised Offset Limit") \
    XXX(GBCS_MESSAGE_ECS39A,     0x004C, "ECS39a Set MPAN Value on the ESME") \
    XXX(GBCS_MESSAGE_ECS39B,     0x004D, "ECS39b Set Export MPAN Value on the ESME") \
    XXX(GBCS_MESSAGE_ECS40,      0x004E, "ECS40 Read MPAN Value on the ESME") \
    XXX(GBCS_MESSAGE_ECS42,      0x004F, "ECS42 Remotely Close the Load Switch on the ESME") \
    XXX(GBCS_MESSAGE_ECS43,      0x0050, "ECS43 Remotely Open the Load Switch on the ESME") \
    XXX(GBCS_MESSAGE_ECS44,      0x0051, "ECS44 Arm Load Switch in ESME") \
    XXX(GBCS_MESSAGE_ECS45,      0x0052, "ECS45 Read Status of Load Switch in the ESME") \
    XXX(GBCS_MESSAGE_ECS46A,     0x0053, "ECS46a Set HC ALCS or ALCS Labels in ESME") \
    XXX(GBCS_MESSAGE_ECS46C,     0x0054, "ECS46c Set HC ALCS and ALCS configuration in ESME (excluding labels)") \
    XXX(GBCS_MESSAGE_ECS47,      0x0055, "ECS47 Set or Reset HC ALCS or ALCS State") \
    XXX(GBCS_MESSAGE_ECS50,      0x0058, "ECS50 Send CIN to ESME") \
    XXX(GBCS_MESSAGE_ECS52,      0x0059, "ECS52 Read ESME/Comms Hub Firmware Version") \
    XXX(GBCS_MESSAGE_ECS57,      0x005A, "ECS57 Reset ESME Maximum Demand Registers") \
    XXX(GBCS_MESSAGE_ECS61C,     0x005E, "ECS61c Read Boost Button Data from ESME") \
    XXX(GBCS_MESSAGE_ECS62,      0x005F, "ECS62 Set ALCS and Boost Button Association") \
    XXX(GBCS_MESSAGE_ECS66,      0x0060, "ECS66 Read ESME Daily Consumption Log") \
    XXX(GBCS_MESSAGE_ECS68,      0x0061, "ECS68 ESME Critical Sensitive Alert (Billing Data Log)") \
    XXX(GBCS_MESSAGE_ECS70,      0x0062, "ECS70 Set Clock on ESME") \
    XXX(GBCS_MESSAGE_ECS80,      0x0067, "ECS80 Supply Outage Restore Alert from ESME") \
    XXX(GBCS_MESSAGE_ECS81,      0x0068, "ECS81 Set Supply Tamper State on ESME") \
    XXX(GBCS_MESSAGE_ECS82,      0x0069, "ECS82 Read Meter Balance for ESME") \
    XXX(GBCS_MESSAGE_GCS01A,     0x006B, "GCS01a Set Tariff and Price on GSME") \
    XXX(GBCS_MESSAGE_GCS02,      0x006C, "GCS02 Set GSME Payment Mode to Credit") \
    XXX(GBCS_MESSAGE_GCS03,      0x006D, "GCS03 Set GSME Payment Mode to Pre-payment") \
    XXX(GBCS_MESSAGE_GCS04,      0x006E, "GCS04 Manage Debt on the GSME") \
    XXX(GBCS_MESSAGE_GCS05,      0x006F, "GCS05 Update Pre-payment Configurations on GSME") \
    XXX(GBCS_MESSAGE_GCS06,      0x0070, "GCS06 Activate Emergency Credit Remotely on GSME") \
    XXX(GBCS_MESSAGE_GCS07,      0x0071, "GCS07 Send Message to GSME") \
    XXX(GBCS_MESSAGE_GCS09,      0x0072, "GCS09 Set Change of Tenancy date on GPF") \
    XXX(GBCS_MESSAGE_GCS11,      0x0073, "GCS11 Disable Privacy PIN Protection on GSME") \
    XXX(GBCS_MESSAGE_GCS13A,     0x0074, "GCS13a Read GSME Consumption Register") \
    XXX(GBCS_MESSAGE_GCS14,      0x0075, "GCS14 Read GSME Pre-payment Register(s)") \
    XXX(GBCS_MESSAGE_GCS15C,     0x0076, "GCS15c Read GSME Billing Data Log (billing calendar triggered)") \
    XXX(GBCS_MESSAGE_GCS16A,     0x0077, "GCS16a Read GSME Daily Read log(s)") \
    XXX(GBCS_MESSAGE_GCS17,      0x0078, "GCS17 Read GSME Profile Data Log") \
    XXX(GBCS_MESSAGE_GCS18,      0x0079, "GCS18 Read Gas Network Data Log") \
    XXX(GBCS_MESSAGE_GCS21A,     0x007B, "GCS21a Read Gas Configuration Data Device Information") \
    XXX(GBCS_MESSAGE_GCS23,      0x007C, "GCS23 Set CV and Conversion Factor Value(s) on the GSME") \
    XXX(GBCS_MESSAGE_GCS24,      0x007D, "GCS24 Set Uncontrolled Gas Flow Rate and Supply Tamper State on the GSME") \
    XXX(GBCS_MESSAGE_GCS25,      0x007E, "GCS25 Set Billing Calendar on the GSME") \
    XXX(GBCS_MESSAGE_GCS28,      0x007F, "GCS28 Set Clock on GSME") \
    XXX(GBCS_MESSAGE_GCS31,      0x0080, "GCS31 Start Network Data Log on GSME") \
    XXX(GBCS_MESSAGE_GCS32,      0x0081, "GCS32 Remotely close the valve in the GSME") \
    XXX(GBCS_MESSAGE_GCS33,      0x0082, "GCS33 Read GSME Valve Status") \
    XXX(GBCS_MESSAGE_GCS36,      0x0083, "GCS36 Send CIN to GSME") \
    XXX(GBCS_MESSAGE_GCS38,      0x0084, "GCS38 Read GSME Firmware Version") \
    XXX(GBCS_MESSAGE_GCS39,      0x0085, "GCS39 Arm Valve in GSME") \
    XXX(GBCS_MESSAGE_GCS40A,     0x0086, "GCS40a Adjust Pre-payment Mode Meter Balance on the GSME") \
    XXX(GBCS_MESSAGE_GCS41,      0x0087, "GCS41 Set MPRN Value on the GSME") \
    XXX(GBCS_MESSAGE_GCS44,      0x0088, "GCS44 Write Contact Details on GSME") \
    XXX(GBCS_MESSAGE_GCS46,      0x0089, "GCS46 Read MPRN on the GSME") \
    XXX(GBCS_MESSAGE_GCS53,      0x008B, "GCS53 Push Billing Data Log as an Alert") \
    XXX(GBCS_MESSAGE_GCS59,      0x008C, "GCS59 Restore GPF Device Log") \
    XXX(GBCS_MESSAGE_GCS60,      0x008D, "GCS60 Read Meter Balance for GSME") \
    XXX(GBCS_MESSAGE_PCS02,      0x0090, "PCS02 Activate Emergency Credit on GSME from PPMID") \
    XXX(GBCS_MESSAGE_ECS26I,     0x0092, "ECS26i Read Configuration Data Device Information (CHF identity)") \
    XXX(GBCS_MESSAGE_ECS35C,     0x0093, "ECS35c Read CHF Event Log") \
    XXX(GBCS_MESSAGE_ECS35D,     0x0094, "ECS35d Read CHF Security Log") \
    XXX(GBCS_MESSAGE_GCS16B,     0x0096, "GCS16b Read GSME Daily Read log(s) (pre-payment)") \
    XXX(GBCS_MESSAGE_CS01B,      0x0097, "CS01b Apply Pre-payment Top Up to a GSME") \
    XXX(GBCS_MESSAGE_PCS01,      0x009B, "PCS01 Apply Pre-payment Top Up to a GSME using PPMID") \
    XXX(GBCS_MESSAGE_GCS21D,     0x009D, "GCS21d Read GSME Configuration Data Device Information (BillingCalendar)") \
    XXX(GBCS_MESSAGE_GCS21E,     0x009E, "GCS21e Read GSME/GPF Configuration Data Device Information (device identity)") \
    XXX(GBCS_MESSAGE_GCS21F,     0x009F, "GCS21f Read GSME Tariff Data") \
    XXX(GBCS_MESSAGE_GCS61,      0x00A0, "GCS61 Read gas Daily Consumption Log") \
    XXX(GBCS_MESSAGE_CS10B,      0x00A1, "CS10b Read ZigBee Device Security Log") \
    XXX(GBCS_MESSAGE_ECS01B,     0x00A2, "ECS01b Set Price on ESME") \
    XXX(GBCS_MESSAGE_GCS01B,     0x00A3, "GCS01b Set Price on GSME") \
    XXX(GBCS_MESSAGE_CS03A2,     0x00AB, "CS03a2 Method A Join (non Meter)") \
    XXX(GBCS_MESSAGE_ECS25A,     0x00AC, "ECS25a Set Alert Behaviours - ESME - Supplier") \
    XXX(GBCS_MESSAGE_GCS20,      0x00AD, "GCS20 Set Alert Behaviours - GSME") \
    XXX(GBCS_MESSAGE_ECS29B,     0x00AE, "ECS29b Set Voltage Configurations on ESME - 3ph") \
    XXX(GBCS_MESSAGE_CS03C,      0x00AF, "CS03c Method C Join") \
    XXX(GBCS_MESSAGE_ECS25B,     0x00B0, "ECS25b Set Alert Behaviours - ESME - Network Operator") \
    XXX(GBCS_MESSAGE_GCS62,      0x00B2, "GCS62 Backup GPF Device Log") \
    XXX(GBCS_MESSAGE_ECS04B,     0x00B3, "ECS04b Reset Meter Balance on the ESME") \
    XXX(GBCS_MESSAGE_GCS40B,     0x00B4, "GCS40b Reset Pre-payment Mode Meter Balance on the GSME") \
    XXX(GBCS_MESSAGE_GCS21B,     0x00B5, "GCS21b Read GSME Configuration Data Pre-payment") \
    XXX(GBCS_MESSAGE_GCS13C,     0x00B6, "GCS13c Read GSME Register (TOU)") \
    XXX(GBCS_MESSAGE_ECS01C,     0x00B7, "ECS01c Set Tariff and Price on ESME secondary") \
    XXX(GBCS_MESSAGE_GCS13B,     0x00B8, "GCS13b Read GSME Block Counters") \
    XXX(GBCS_MESSAGE_ECS35E,     0x00B9, "ECS35e Read ESME Power Event Log") \
    XXX(GBCS_MESSAGE_ECS35F,     0x00BA, "ECS35f Read ALCS Event Log") \
    XXX(GBCS_MESSAGE_ECS61A,     0x00BB, "ECS61a Read HC ALCS and ALCS Data from ESME") \
    XXX(GBCS_MESSAGE_ECS23B,     0x00BC, "ECS23b Read Voltage Operational Data -3 Phase") \
    XXX(GBCS_MESSAGE_ECS24B,     0x00BD, "ECS24b Read ESME Tariff Data - second element") \
    XXX(GBCS_MESSAGE_ECS26J,     0x00BE, "ECS26j Read ESME Configuration Data Device Information (Payment Mode)") \
    XXX(GBCS_MESSAGE_GCS21J,     0x00BF, "GCS21j Read GSME Configuration Data Device Information (Payment Mode)") \
    XXX(GBCS_MESSAGE_GCS40C,     0x00C0, "GCS40c Adjust Credit Mode Meter Balance on the GSME") \
    XXX(GBCS_MESSAGE_ECS15C,     0x00C1, "ECS15c Clear ALCS Event Log") \
    XXX(GBCS_MESSAGE_GCS40D,     0x00C2, "GCS40d Reset Credit Mode Meter Balance on the GSME") \
    XXX(GBCS_MESSAGE_GCS15B,     0x00C3, "GCS15b Read GSME Billing Data Log (change of mode / tariff triggered)") \
    XXX(GBCS_MESSAGE_GCS15D,     0x00C4, "GCS15d Read GSME Billing Data Log (payment-based debt payments) ") \
    XXX(GBCS_MESSAGE_GCS15E,     0x00C5, "GCS15e Read GSME Billing Data Log (pre-payment credits)") \
    XXX(GBCS_MESSAGE_ECS26K,     0x00C6, "ECS26k Read ESME Configuration Voltage Data - 3 phase") \
    XXX(GBCS_MESSAGE_ECS01D,     0x00C7, "ECS01d Set Price on ESME secondary") \
    XXX(GBCS_MESSAGE_ECS20D,     0x00C9, "ECS20d Read ESME Billing Data Log (pre-payment credits)") \
    XXX(GBCS_MESSAGE_ALERT_00CA, 0x00CA, "Futured Dated Firmware Activation Alert") \
    XXX(GBCS_MESSAGE_ALERT_00CB, 0x00CB, "Futured Dated Updated Security Credentials Alert") \
    XXX(GBCS_MESSAGE_ALERT_00CC, 0x00CC, "Future Dated Execution Of Instruction Alert (DLMS COSEM)") \
    XXX(GBCS_MESSAGE_ALERT_00CD, 0x00CD, "Future Dated Execution Of Instruction Alert (GBZ)") \
    XXX(GBCS_MESSAGE_ALERT_00CE, 0x00CE, "Firmware Distribution Receipt Alert (ESME or Comms Hub)") \
    XXX(GBCS_MESSAGE_ALERT_00CF, 0x00CF, "Firmware Distribution Receipt Alert (GSME)") \
    XXX(GBCS_MESSAGE_ECS29C,     0x00D1, "ECS29c Set Voltage Configurations on ESME without counter reset") \
    XXX(GBCS_MESSAGE_ECS29D,     0x00D2, "ECS29d Set Voltage Configurations on polyphase ESME without counter reset") \
    XXX(GBCS_MESSAGE_ECS29E,     0x00D3, "ECS29e Reset RMS Voltage Counters on ESME") \
    XXX(GBCS_MESSAGE_ECS29F,     0x00D4, "ECS29f Reset RMS Voltage Counters on polyphase ESME") \
    XXX(GBCS_MESSAGE_ALERT_00D5, 0x00D5, "Failure to Deliver Remote Party Message to ESME Alert") \
    XXX(GBCS_MESSAGE_ECS30A,     0x00D7, "ECS30a Set Billing Calendar on the ESME - all periodicities") \
    XXX(GBCS_MESSAGE_GCS25A,     0x00D8, "GCS25a Set Billing Calendar on the GSME - all periodicities") \
    XXX(GBCS_MESSAGE_ECS26L,     0x00D9, "ECS26l Read ESME Configuration Data Device Information (Billing Calendar - all periodicities)") \
    XXX(GBCS_MESSAGE_GCS21K,     0x00DA, "GCS21k Read GSME Configuration Data Device Information (BillingCalendar - all periodicities)") \
    XXX(GBCS_MESSAGE_ECS48,      0x00DB, "ECS48 Configure daily resetting of Tariff Block Counter Matrix") \
    XXX(GBCS_MESSAGE_ECS08A,     0x00DE, "ECS08a Update Pre-payment Configuration on ESME") \
    XXX(GBCS_MESSAGE_ECS25A1,    0x00EA, "ECS25a1 Set Event Behaviours - ESME to HAN Device - Supplier") \
    XXX(GBCS_MESSAGE_ECS25A2,    0x00EB, "ECS25a2 Set Event Behaviours - ESME audible alarm - Supplier") \
    XXX(GBCS_MESSAGE_ECS25A3,    0x00EC, "ECS25a3 Set Event Behaviours - ESME logging - Supplier") \
    XXX(GBCS_MESSAGE_ECS25B3,    0x00ED, "ECS25b3 Set Event Behaviours - ESME logging - Network Operator") \
    XXX(GBCS_MESSAGE_ECS25R1,    0x00EE, "ECS25r1 Read non-critical event and alert behaviours - ESME-  Supplier") \
    XXX(GBCS_MESSAGE_ECS25R2,    0x00EF, "ECS25r2 Read non-critical event and alert behaviours - ESME-  Network Operator") \
    XXX(GBCS_MESSAGE_ALERT_00F0, 0x00F0, "Meter Integrity Issue Warning Alert - ESME") \
    XXX(GBCS_MESSAGE_GCS20R,     0x00F1, "GCS20r Read non-critical event and alert behaviours - GSME-  Supplier") \
    XXX(GBCS_MESSAGE_ALERT_00F2, 0x00F2, "Meter Integrity Issue Warning Alert - GSME") \
    XXX(GBCS_MESSAGE_ECS26M,     0x00F9, "ECS26m Read ESME Configuration Data Device Information (identity, type and supply tamper state)") \
    XXX(GBCS_MESSAGE_ECS26N,     0x00FA, "ECS26n Read CHF Configuration Data Device Information (CH identity and type)") \
    XXX(GBCS_MESSAGE_GCS21M,     0x00FB, "GCS21m Read GSME Configuration Data Device Information (identity, type and supply tamper / depletion state)") \
    XXX(GBCS_USECASE_GCS24A,     0x00FC, "GCS24a Set Uncontrolled Gas Flow Rate at greater resolution and Supply Tamper State on the GSME") \
    XXX(GBCS_MESSAGE_CS02B0,     0x0100, "CS02b Update Security Credentials - rootBySupplier") \
    XXX(GBCS_MESSAGE_CS02B1,     0x0101, "CS02b Update Security Credentials - rootByWanProvider") \
    XXX(GBCS_MESSAGE_CS02B2,     0x0102, "CS02b Update Security Credentials - supplierBySupplier") \
    XXX(GBCS_MESSAGE_CS02B3,     0x0103, "CS02b Update Security Credentials - networkOperatorByNetworkOperator") \
    XXX(GBCS_MESSAGE_CS02B4,     0x0104, "CS02b Update Security Credentials - accessControlBrokerByACB") \
    XXX(GBCS_MESSAGE_CS02B5,     0x0105, "CS02b Update Security Credentials - wanProviderByWanProvider") \
    XXX(GBCS_MESSAGE_CS02B6,     0x0106, "CS02b Update Security Credentials - transCoSByTransCoS") \
    XXX(GBCS_MESSAGE_CS02B7,     0x0107, "CS02b Update Security Credentials - supplierByTransCoS") \
    XXX(GBCS_MESSAGE_CS02B8,     0x0108, "CS02b Update Security Credentials - anyExceptAbnormalRootByRecovery") \
    XXX(GBCS_MESSAGE_CS02B9,     0x0109, "CS02b Update Security Credentials - anyByContingency") \
    XXX(GBCS_MESSAGE_DBCH01,     0x010A, "DBCH01 Read CHF Sub GHz Channel") \
    XXX(GBCS_MESSAGE_DBCH02,     0x010B, "DBCH02 Read CHF Sub GHz Channel Log") \
    XXX(GBCS_MESSAGE_DBCH03,     0x010C, "DBCH03 Read CHF Sub GHz Configuration") \
    XXX(GBCS_MESSAGE_DBCH04,     0x010D, "DBCH04 Set CHF Sub GHz Configuration") \
    XXX(GBCS_MESSAGE_DBCH05,     0x010E, "DBCH05 Request CHF Sub GHz Channel Scan") \
    XXX(GBCS_MESSAGE_CCS06,      0x010F, "CCS06 Read CHF device log and check HAN communications") \
    XXX(GBCS_MESSAGE_DBCH06,     0x0110, "DBCH06 Limited Duty Cycle Action Taken Sub GHz Alert") \
    XXX(GBCS_MESSAGE_DBCH07,     0x0111, "DBCH07 Sub GHz Sub GHz Channel Changed Sub GHz Alert") \
    XXX(GBCS_MESSAGE_DBCH08,     0x0112, "DBCH08 Sub GHz Channel Scan Request Assessment Outcome Sub GHz Alert") \
    XXX(GBCS_MESSAGE_DBCH09,     0x0113, "DBCH09 Sub GHz Configuration Changed Sub GHz Alert") \
    XXX(GBCS_MESSAGE_DBCH10,     0x0114, "DBCH10 Message Discarded Due to Duty Cycle Management Sub GHz Alert") \
    XXX(GBCS_MESSAGE_DBCH11,     0x0115, "DBCH11 No More Sub GHz Device Capacity Sub GHz Alert") \
    XXX(GBCS_MESSAGE_PECS01,     0x0116, "PECS01 Apply Pre-payment Top Up to an ESME using PPMID") \
    XXX(GBCS_MESSAGE_PECS02,     0x0117, "PECS02 Activate Emergency Credit on ESME from PPMID") \
    XXX(GBCS_MESSAGE_PECS03,     0x0118, "PECS03 Request to Enable ESME Supply from PPMID") \
    XXX(GBCS_MESSAGE_HECS01,     0x0119, "HECS01 Request Control of a HAN Connected Auxiliary Load Control Switch from HCALCS") \
    XXX(GBCS_MESSAGE_ALERT_1000, 0x1000, "Generic Critical Alert") \
    XXX(GBCS_MESSAGE_ALERT_1001, 0x1001, "Generic Non Critical Alert")

VALUE_STRING_ARRAY(gbcs_message_code_names);
static value_string_ext gbcs_message_code_names_ext = VALUE_STRING_EXT_INIT(gbcs_message_code_names);

#define gbcs_message_cra_names_VALUE_STRING_LIST(XXX) \
    XXX(GBCS_MESSAGE_CRA_COMMAND,                               0x01, "Command" ) \
    XXX(GBCS_MESSAGE_CRA_RESPONSE,                              0x02, "Response" ) \
    XXX(GBCS_MESSAGE_CRA_ALERT,                                 0x03, "Alert" )

VALUE_STRING_ENUM(gbcs_message_cra_names);
VALUE_STRING_ARRAY(gbcs_message_cra_names);

static void
dlms_date_time(tvbuff_t *tvb, guint offset, nstime_t *date_time)
{
    //TODO Handle DLMS date never
    struct tm tm;

    tm.tm_wday = 0;
    tm.tm_yday = 0;
    tm.tm_isdst = -1;

    tm.tm_year = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN) - 1900;
    offset += 2;

    tm.tm_mon = tvb_get_guint8(tvb, offset) - 1; // tm.tm_mon [0-11]
    offset += 1;

    tm.tm_mday = tvb_get_guint8(tvb, offset);
    offset += 1;

    offset += 1; //Skip week day

    tm.tm_hour = tvb_get_guint8(tvb, offset);
    offset += 1;

    tm.tm_min = tvb_get_guint8(tvb, offset);
    offset += 1;

    tm.tm_sec = tvb_get_guint8(tvb, offset);

    date_time->secs = mktime_utc(&tm);
    date_time->nsecs = 0;
}

/* ########################################################################## */
/* #### GBCS GBZ ############################################################ */
/* ########################################################################## */

#define GBCS_GBZ_MAX_COMPONENTS                                         31 // GCS16a
#define GBCS_GBZ_MAC_LENGTH                                             12

#define GBCS_GBZ_EXTENDED_HEADER_CONTROL_FROM_DATE_TIME_PRESENT         0x10
#define GBCS_GBZ_EXTENDED_HEADER_CONTROL_LAST_COMPONENT                 0x01
#define GBCS_GBZ_EXTENDED_HEADER_CONTROL_ENCRYPTED_COMPONENT            0x02

#define gbcs_gbz_alert_code_names_VALUE_STRING_LIST(XXX) \
    XXX(GBCS_GBZ_ALERT_AVERAGE_RMS_VOLTAGE_ABOVE_AVERAGE_RMS_OVER_VOL_1,0x8002, "Average RMS Voltage above Average RMS Over Voltage Threshold (current value above threshold; previous value below threhsold)") \
    XXX(GBCS_GBZ_ALERT_AVERAGE_RMS_VOLTAGE_ABOVE_AVERAGE_RMS_OVER_VOL_2,0x8003, "Average RMS Voltage above Average RMS Over Voltage Threshold  on Phase 1 (current value above threshold; previous value below threhsold)") \
    XXX(GBCS_GBZ_ALERT_AVERAGE_RMS_VOLTAGE_ABOVE_AVERAGE_RMS_OVER_VOL_3,0x8004, "Average RMS Voltage above Average RMS Over Voltage Threshold  on Phase 2 (current value above threshold; previous value below threhsold)") \
    XXX(GBCS_GBZ_ALERT_AVERAGE_RMS_VOLTAGE_ABOVE_AVERAGE_RMS_OVER_VOL_4,0x8005, "Average RMS Voltage above Average RMS Over Voltage Threshold  on Phase 3 (current value above threshold; previous value below threhsold)") \
    XXX(GBCS_GBZ_ALERT_AVERAGE_RMS_VOLTAGE_BELOW_AVERAGE_RMS_UNDER_VO_1,0x8006, "Average RMS Voltage below Average RMS Under Voltage Threshold (current value below threshold; previous value above threhsold)") \
    XXX(GBCS_GBZ_ALERT_AVERAGE_RMS_VOLTAGE_BELOW_AVERAGE_RMS_UNDER_VO_2,0x8007, "Average RMS Voltage below Average RMS Under Voltage Threshold on Phase 1 (current value below threshold; previous value above threhsold)") \
    XXX(GBCS_GBZ_ALERT_AVERAGE_RMS_VOLTAGE_BELOW_AVERAGE_RMS_UNDER_VO_3,0x8008, "Average RMS Voltage below Average RMS Under Voltage Threshold on Phase 2 (current value below threshold; previous value above threhsold)") \
    XXX(GBCS_GBZ_ALERT_AVERAGE_RMS_VOLTAGE_BELOW_AVERAGE_RMS_UNDER_VO_4,0x8009, "Average RMS Voltage below Average RMS Under Voltage Threshold on Phase 3 (current value below threshold; previous value above threhsold)") \
    XXX(GBCS_GBZ_ALERT_OVER_CURRENT,                                    0x8010, "Over Current") \
    XXX(GBCS_GBZ_ALERT_OVER_CURRENT_L1,                                 0x8011, "Over Current L1") \
    XXX(GBCS_GBZ_ALERT_OVER_CURRENT_L3,                                 0x8013, "Over Current L3") \
    XXX(GBCS_GBZ_ALERT_POWER_FACTOR_THRESHOLD_BELOW,                    0x8014, "Power Factor Threshold Below") \
    XXX(GBCS_GBZ_ALERT_POWER_FACTOR_THRESHOLD_OK,                       0x8015, "Power Factor Threshold Ok") \
    XXX(GBCS_GBZ_ALERT_OVER_CURRENT_L2,                                 0x8016, "Over Current L2") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_ABOVE_EXTREME_OVER_VOLTAGE_THRESHO_1,0x8020, "RMS Voltage above Extreme Over Voltage Threshold (voltage rises above for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_ABOVE_EXTREME_OVER_VOLTAGE_THRESHO_2,0x8021, "RMS Voltage above Extreme Over Voltage Threshold on Phase 1 (voltage rises above for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_ABOVE_EXTREME_OVER_VOLTAGE_THRESHO_3,0x8022, "RMS Voltage above Extreme Over Voltage Threshold on Phase 2 (voltage rises above for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_ABOVE_EXTREME_OVER_VOLTAGE_THRESHO_4,0x8023, "RMS Voltage above Extreme Over Voltage Threshold on Phase 3 (voltage rises above for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_ABOVE_VOLTAGE_SWELL_THRESHOLD_VOLT_1,0x8024, "RMS Voltage above Voltage Swell Threshold (voltage rises above for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_ABOVE_VOLTAGE_SWELL_THRESHOLD_ON_P_2,0x8025, "RMS Voltage above Voltage Swell Threshold on Phase 1 (voltage rises above for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_ABOVE_VOLTAGE_SWELL_THRESHOLD_ON_P_3,0x8026, "RMS Voltage above Voltage Swell Threshold on Phase 2 (voltage rises above for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_ABOVE_VOLTAGE_SWELL_THRESHOLD_ON_P_4,0x8027, "RMS Voltage above Voltage Swell Threshold on Phase 3 (voltage rises above for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_BELOW_EXTREME_UNDER_VOLTAGE_THRESH_1,0x8028, "RMS Voltage below Extreme Under Voltage Threshold (voltage falls below for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_BELOW_EXTREME_UNDER_VOLTAGE_THRESH_2,0x8029, "RMS Voltage below Extreme Under Voltage Threshold on Phase 1 (voltage falls below for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_BELOW_EXTREME_UNDER_VOLTAGE_THRESH_3,0x802A, "RMS Voltage below Extreme Under Voltage Threshold on Phase 2 (voltage falls below for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_BELOW_EXTREME_UNDER_VOLTAGE_THRESH_4,0x802B, "RMS Voltage below Extreme Under Voltage Threshold on Phase 3 (voltage falls below for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_BELOW_VOLTAGE_SAG_THRESHOLD_VOLTA_1, 0x802C, "RMS Voltage below Voltage Sag Threshold (voltage falls below for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_BELOW_VOLTAGE_SAG_THRESHOLD_ON_PHA_1,0x802D, "RMS Voltage below Voltage Sag Threshold on Phase 1 (voltage falls below for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_BELOW_VOLTAGE_SAG_THRESHOLD_ON_PHA_2,0x802E, "RMS Voltage below Voltage Sag Threshold on Phase 2 (voltage falls below for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_BELOW_VOLTAGE_SAG_THRESHOLD_ON_PHA_3,0x802F, "RMS Voltage below Voltage Sag Threshold on Phase 3 (voltage falls below for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_GPF_DEVICE_LOG_CHANGED,                          0x8071, "GPF Device Log Changed") \
    XXX(GBCS_GBZ_ALERT_AVERAGE_RMS_VOLTAGE_BELOW_AVERAGE_RMS_OVER_VOL_1,0x8085, "Average RMS Voltage below Average RMS Over Voltage Threshold (current value below threshold; previous value above threhsold)") \
    XXX(GBCS_GBZ_ALERT_AVERAGE_RMS_VOLTAGE_BELOW_AVERAGE_RMS_OVER_VOL_2,0x8086, "Average RMS Voltage below Average RMS Over Voltage Threshold on Phase 1 (current value below threshold; previous value above threhsold)") \
    XXX(GBCS_GBZ_ALERT_AVERAGE_RMS_VOLTAGE_BELOW_AVERAGE_RMS_OVER_VOL_3,0x8087, "Average RMS Voltage below Average RMS Over Voltage Threshold on Phase 2 (current value below threshold; previous value above threhsold)") \
    XXX(GBCS_GBZ_ALERT_AVERAGE_RMS_VOLTAGE_BELOW_AVERAGE_RMS_OVER_VOL_4,0x8088, "Average RMS Voltage below Average RMS Over Voltage Threshold on Phase 3 (current value below threshold; previous value above threhsold)") \
    XXX(GBCS_GBZ_ALERT_AVERAGE_RMS_VOLTAGE_ABOVE_AVERAGE_RMS_UNDER_VO_1,0x8089, "Average RMS Voltage above Average RMS Under Voltage Threshold (current value above threshold; previous value below threhsold)") \
    XXX(GBCS_GBZ_ALERT_AVERAGE_RMS_VOLTAGE_ABOVE_AVERAGE_RMS_UNDER_VO_2,0x808A, "Average RMS Voltage above Average RMS Under Voltage Threshold on Phase 1 (current value above threshold; previous value below threhsold)") \
    XXX(GBCS_GBZ_ALERT_AVERAGE_RMS_VOLTAGE_ABOVE_AVERAGE_RMS_UNDER_VO_3,0x808B, "Average RMS Voltage above Average RMS Under Voltage Threshold on Phase 2 (current value above threshold; previous value below threhsold)") \
    XXX(GBCS_GBZ_ALERT_AVERAGE_RMS_VOLTAGE_ABOVE_AVERAGE_RMS_UNDER_VO_4,0x808C, "Average RMS Voltage above Average RMS Under Voltage Threshold on Phase 3 (current value above threshold; previous value below threhsold)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_ABOVE_EXTREME_OVER_VOLTAGE_THRESHO_5,0x808D, "RMS Voltage above Extreme Over Voltage Threshold (voltage returns below for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_ABOVE_EXTREME_OVER_VOLTAGE_THRESHO_6,0x808E, "RMS Voltage above Extreme Over Voltage Threshold on Phase 1 (voltage returns below for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_ABOVE_EXTREME_OVER_VOLTAGE_THRESHO_7,0x808F, "RMS Voltage above Extreme Over Voltage Threshold on Phase 2 (voltage returns below for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_ABOVE_EXTREME_OVER_VOLTAGE_THRESHO_8,0x8090, "RMS Voltage above Extreme Over Voltage Threshold on Phase 3 (voltage returns below for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_ABOVE_VOLTAGE_SWELL_THRESHOLD_VOLT_2,0x8091, "RMS Voltage above Voltage Swell Threshold (voltage returns below for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_ABOVE_VOLTAGE_SWELL_THRESHOLD_ON_P_1,0x8092, "RMS Voltage above Voltage Swell Threshold on Phase 1 (voltage returns below for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_ABOVE_VOLTAGE_SWELL_THRESHOLD_ON_P_5,0x8093, "RMS Voltage above Voltage Swell Threshold on Phase 2 (voltage returns below for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_ABOVE_VOLTAGE_SWELL_THRESHOLD_ON_P_6,0x8094, "RMS Voltage above Voltage Swell Threshold on Phase 3 (voltage returns below for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_BELOW_EXTREME_UNDER_VOLTAGE_THRESH_5,0x8095, "RMS Voltage below Extreme Under Voltage Threshold (voltage returns above for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_BELOW_EXTREME_UNDER_VOLTAGE_THRESH_6,0x8096, "RMS Voltage below Extreme Under Voltage Threshold on Phase 1 (voltage returns above for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_BELOW_EXTREME_UNDER_VOLTAGE_THRESH_7,0x8097, "RMS Voltage below Extreme Under Voltage Threshold on Phase 2 (voltage returns above for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_BELOW_EXTREME_UNDER_VOLTAGE_THRESH_8,0x8098, "RMS Voltage below Extreme Under Voltage Threshold on Phase 3 (voltage returns above for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_BELOW_VOLTAGE_SAG_THRESHOLD_VOLTA_2, 0x8099, "RMS Voltage below Voltage Sag Threshold (voltage returns above for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_BELOW_VOLTAGE_SAG_THRESHOLD_ON_PHA_4,0x809A, "RMS Voltage below Voltage Sag Threshold on Phase 1 (voltage returns above for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_BELOW_VOLTAGE_SAG_THRESHOLD_ON_PHA_5,0x809B, "RMS Voltage below Voltage Sag Threshold on Phase 2 (voltage returns above for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_RMS_VOLTAGE_BELOW_VOLTAGE_SAG_THRESHOLD_ON_PHA_6,0x809C, "RMS Voltage below Voltage Sag Threshold on Phase 3 (voltage returns above for longer than the configurable period)") \
    XXX(GBCS_GBZ_ALERT_COMBINED_CREDIT_BELOW_LOW_CREDIT_THRESHOLD_PREPA,0x810D, "Combined Credit Below Low Credit Threshold (prepayment mode)") \
    XXX(GBCS_GBZ_ALERT_CREDIT_ADDED_LOCALLY,                            0x810E, "Credit Added Locally") \
    XXX(GBCS_GBZ_ALERT_EMERGENCY_CREDIT_HAS_BECOME_AVAILABLE_PREPAYMENT,0x8119, "Emergency Credit Has Become Available (prepayment mode)") \
    XXX(GBCS_GBZ_ALERT_FAILURE_IN_CHANGING_OR_MAINTAINING_HCALCS_OR_A_1,0x811A, "Failure in changing or maintaining HCALCS or ALCS state") \
    XXX(GBCS_GBZ_ALERT_SUCCESS_IN_CHANGING_OR_MAINTAINING_HCALCS_OR_A_2,0x8131, "Success in changing or maintaining HCALCS or ALCS state") \
    XXX(GBCS_GBZ_ALERT_CLOCK_ADJUSTED_WITHIN_TOLERANCE,                 0x8145, "Clock adjusted (within tolerance)") \
    XXX(GBCS_GBZ_ALERT_IMMEDIATE_HAN_INTERFACE_COMMAND_RECEIVED_AND_SUC,0x8154, "Immediate HAN Interface Command Received and Successfully Actioned") \
    XXX(GBCS_GBZ_ALERT_IMMEDIATE_HAN_INTERFACE_COMMAND_RECEIVED_BUT_NOT,0x8155, "Immediate HAN Interface Command Received but not Successfully Actioned") \
    XXX(GBCS_GBZ_ALERT_USER_INTERFACE_COMMAND_INPUT_AND_SUCCESSFULLY_AC,0x8161, "User Interface Command Input and Successfully Actioned") \
    XXX(GBCS_GBZ_ALERT_USER_INTERFACE_COMMAND_INPUT_BUT_NOT_SUCCESSFULL,0x8162, "User Interface Command Input but not Successfully Actioned") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_DISABLED_THEN_ARMED_ACTIVATE_EMERGENCY,   0x8168, "Supply Disabled then Armed - Activate Emergency Credit triggered") \
    XXX(GBCS_GBZ_ALERT_DEVICE_JOINED_SMHAN,                             0x8183, "Device joined SMHAN") \
    XXX(GBCS_GBZ_ALERT_VALVE_TESTED,                                    0x8184, "Valve tested") \
    XXX(GBCS_GBZ_ALERT_GSME_COMMAND_NOT_RETRIEVED,                      0x819D, "GSME Command Not Retrieved") \
    XXX(GBCS_GBZ_ALERT_TAP_OFF_MESSAGE_RESPONSE_OR_ALERT_FAILURE,       0x819E, "Tap Off Message Response or Alert Failure") \
    XXX(GBCS_GBZ_ALERT_SMART_METER_INTEGRITY_ISSUE_WARNING,             0x81A0, "Smart Meter Integrity Issue Warning") \
    XXX(GBCS_GBZ_ALERT_BATTERY_COVER_CLOSED,                            0x81A1, "Battery Cover Closed") \
    XXX(GBCS_GBZ_ALERT_CH_CONNECTED_TO_ESME,                            0x81A2, "CH Connected to ESME") \
    XXX(GBCS_GBZ_ALERT_CH_DISCONNECTED_FROM_ESME,                       0x81A3, "CH Disconnected from ESME") \
    XXX(GBCS_GBZ_ALERT_CLOSE_TUNNEL_COMMAND_REJECTED,                   0x81A4, "Close Tunnel Command Rejected") \
    XXX(GBCS_GBZ_ALERT_COMMUNICATION_FROM_LOCAL_PORT_EG_OPTICAL,        0x81A5, "Communication From Local Port (e.g. Optical)") \
    XXX(GBCS_GBZ_ALERT_CUSTOMER_ACKNOWLEDGED_MESSAGE_ON_HAN_DEVICE,     0x81A6, "Customer Acknowledged Message on HAN Device") \
    XXX(GBCS_GBZ_ALERT_DEBT_COLLECTION_COMPLETED_TIME_DEBT_1,           0x81A7, "Debt Collection Completed - Time Debt 1") \
    XXX(GBCS_GBZ_ALERT_DEBT_COLLECTION_COMPLETED_TIME_DEBT_2,           0x81A8, "Debt Collection Completed - Time Debt 2") \
    XXX(GBCS_GBZ_ALERT_DEBT_COLLECTION_COMPLETED_PAYMENT_DEBT,          0x81A9, "Debt Collection Completed - Payment Debt") \
    XXX(GBCS_GBZ_ALERT_EMERGENCY_CREDIT_EXHAUSTED,                      0x81AA, "Emergency Credit Exhausted") \
    XXX(GBCS_GBZ_ALERT_EMERGENCY_CREDIT_ACTIVATED,                      0x81AB, "Emergency Credit Activated") \
    XXX(GBCS_GBZ_ALERT_ERROR_MEASUREMENT_FAULT,                         0x81AC, "Error Measurement Fault") \
    XXX(GBCS_GBZ_ALERT_ERROR_METROLOGY_FIRMWARE_VERIFICATION_FAILURE,   0x81AD, "Error Metrology Firmware Verification Failure") \
    XXX(GBCS_GBZ_ALERT_ERROR_NON_VOLATILE_MEMORY,                       0x81AE, "Error Non Volatile Memory") \
    XXX(GBCS_GBZ_ALERT_ERROR_PROGRAM_EXECUTION,                         0x81AF, "Error Program Execution") \
    XXX(GBCS_GBZ_ALERT_ERROR_PROGRAM_STORAGE,                           0x81B0, "Error Program Storage") \
    XXX(GBCS_GBZ_ALERT_ERROR_RAM,                                       0x81B1, "Error RAM") \
    XXX(GBCS_GBZ_ALERT_ERROR_UNEXPECTED_HARDWARE_RESET,                 0x81B2, "Error Unexpected Hardware Reset") \
    XXX(GBCS_GBZ_ALERT_ERROR_WATCHDOG,                                  0x81B3, "Error Watchdog ") \
    XXX(GBCS_GBZ_ALERT_EXCESS_GAS_FLOW_BEYOND_METER_CAPACITY,           0x81B4, "Excess Gas Flow Beyond Meter Capacity") \
    XXX(GBCS_GBZ_ALERT_FLOW_SENSOR_DETECTS_AIR_IN_GAS_FLOW,             0x81B5, "Flow Sensor Detects Air in Gas Flow") \
    XXX(GBCS_GBZ_ALERT_FLOW_SENSOR_DETECTS_REVERSE_FLOW_OF_GAS,         0x81B6, "Flow Sensor Detects Reverse Flow of Gas") \
    XXX(GBCS_GBZ_ALERT_INCORRECT_PHASE_SEQUENCING,                      0x81B7, "Incorrect phase sequencing") \
    XXX(GBCS_GBZ_ALERT_INCORRECT_POLARITY,                              0x81B8, "Incorrect Polarity") \
    XXX(GBCS_GBZ_ALERT_METER_COVER_CLOSED,                              0x81B9, "Meter Cover Closed") \
    XXX(GBCS_GBZ_ALERT_REQUEST_TUNNEL_COMMAND_REJECTED,                 0x81BA, "Request Tunnel Command Rejected") \
    XXX(GBCS_GBZ_ALERT_REVERSE_CURRENT,                                 0x81BB, "Reverse Current") \
    XXX(GBCS_GBZ_ALERT_STRONG_MAGNETIC_FIELD_REMOVED,                   0x81BC, "Strong Magnetic Field Removed") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_CONNECT_FAILURE_VALVE_OR_LOAD_SWITCH,     0x81BD, "Supply Connect Failure (Valve or Load Switch)") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_DISABLED_THEN_LOCKED_SUPPLY_TAMPER_STATE, 0x81BE, "Supply Disabled Then Locked - Supply Tamper State Cause") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_DISABLED_THEN_ARMED_UNCONTROLLED_GAS_FLOW,0x81BF, "Supply Disabled Then Armed - Uncontrolled Gas Flow Rate") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_DISCONNECT_FAILURE_VALVE_OR_LOAD_SWITCH,  0x81C0, "Supply Disconnect Failure (Valve or Load Switch)") \
    XXX(GBCS_GBZ_ALERT_TERMINAL_COVER_CLOSED,                           0x81C1, "Terminal Cover Closed") \
    XXX(GBCS_GBZ_ALERT_TILT_TAMPER_ENDED,                               0x81C2, "Tilt Tamper Ended") \
    XXX(GBCS_GBZ_ALERT_TILT_TAMPER,                                     0x81C3, "Tilt Tamper") \
    XXX(GBCS_GBZ_ALERT_UTRN_MANUAL_ENTRY_SUSPENDED,                     0x81C4, "UTRN Manual Entry Suspended") \
    XXX(GBCS_GBZ_ALERT_UTRN_REJECTED_AS_LOCKED_OUT,                     0x81C5, "UTRN rejected as locked out") \
    XXX(GBCS_GBZ_ALERT_CLOCK_NOT_ADJUSTED_OUTSIDE_TOLERANCE,            0x81C6, "Clock not adjusted (outside tolerance)") \
    XXX(GBCS_GBZ_ALERT_ACTIVE_POWER_IMPORT_ABOVE_LOAD_LIMIT_THRESHOLD,  0x8F01, "Active Power Import above Load Limit Threshold") \
    XXX(GBCS_GBZ_ALERT_BILLING_DATA_LOG_UPDATED,                        0x8F0A, "Billing Data Log Updated") \
    XXX(GBCS_GBZ_ALERT_CLOCK_NOT_ADJUSTED_ADJUSTMENT_GREATER_THAN_10_SE,0x8F0C, "Clock not adjusted (adjustment greater than 10 seconds)") \
    XXX(GBCS_GBZ_ALERT_CREDIT_BELOW_DISABLEMENT_THRESHOLD_PREPAYMENT_MO,0x8F0F, "Credit Below Disablement Threshold (prepayment mode)") \
    XXX(GBCS_GBZ_ALERT_CHF_DEVICE_LOG_CHANGED,                          0x8F12, "CHF Device Log Changed") \
    XXX(GBCS_GBZ_ALERT_FIRMWARE_VERIFICATION_FAILED_AT_POWER_ON,        0x8F1B, "Firmware Verification Failed At Power On") \
    XXX(GBCS_GBZ_ALERT_FIRMWARE_VERIFICATION_FAILED,                    0x8F1C, "Firmware Verification Failed") \
    XXX(GBCS_GBZ_ALERT_GSME_POWER_SUPPLY_LOSS,                          0x8F1D, "GSME Power Supply Loss") \
    XXX(GBCS_GBZ_ALERT_INTEGRITY_CHECK_OF_CONTENT_OR_FORMAT_OF_COMMAND, 0x8F1E, "Integrity check of content or format of command failed") \
    XXX(GBCS_GBZ_ALERT_LOW_BATTERY_CAPACITY,                            0x8F1F, "Low Battery Capacity") \
    XXX(GBCS_GBZ_ALERT_LIMITED_DUTY_CYCLE_ACTION_TAKEN,                 0x8F20, "Limited Duty Cycle Action Taken") \
    XXX(GBCS_GBZ_ALERT_DUTY_CYCLE_FALL_BELOW_NORMAL_LIMITED,            0x8F21, "Duty Cycle fallen below Normal-Limited Duty Cycle Threshold") \
    XXX(GBCS_GBZ_ALERT_CRITICAL_DUTY_CYCLE_ACTION_TAKEN,                0x8F22, "Critical Duty Cycle Action Taken") \
    XXX(GBCS_GBZ_ALERT_DUTY_CYCLE_FALL_BELOW_LIMITED_CRITICAL,          0x8F23, "Duty Cycle fallen below Limited-Critical Duty Cycle Threshold") \
    XXX(GBCS_GBZ_ALERT_REGULATED_DUTY_CYCLE_ACTION_TAKEN,               0x8F24, "Regulated Duty Cycle Action Taken") \
    XXX(GBCS_GBZ_ALERT_DUTY_CYCLE_FALL_BELOW_CRITICAL_REGULATED,        0x8F25, "Duty Cycle fallen below Critical-Regulated Duty Cycle Threshold") \
    XXX(GBCS_GBZ_ALERT_SUB_GHZ_CHANNEL_CHANGED,                         0x8F26, "Sub GHz Channel Changed") \
    XXX(GBCS_GBZ_ALERT_SUB_GHZ_CHANNEL_SCAN_INITIATED,                  0x8F27, "Sub GHz Channel Scan initiated") \
    XXX(GBCS_GBZ_ALERT_SUB_GHZ_CHANNEL_SCAN_REQUEST_ASSESSMENT_OUTCOME, 0x8F28, "Sub GHz Channel Scan Request Assessment Outcome") \
    XXX(GBCS_GBZ_ALERT_THREE_LOST_GSME_SEARCHES_FAILED,                 0x8F29, "Three Lost GSME Searches Failed") \
    XXX(GBCS_GBZ_ALERT_SUB_GHZ_CONFIGURATION_CHANGED,                   0x8F2A, "Sub GHz Configuration Changed") \
    XXX(GBCS_GBZ_ALERT_SUB_GHZ_CHANNEL_NOT_CHANGED_DUE_TO_FREQUENCY_AGI,0x8F2B, "Sub GHz Channel not changed due to Frequency Agility Parameters") \
    XXX(GBCS_GBZ_ALERT_MESSAGE_DISCARDED_DUE_TO_DUTY_CYCLE_MANAGEMENT,  0x8F2C, "Message Discarded Due to Duty Cycle Management") \
    XXX(GBCS_GBZ_ALERT_NO_MORE_SUB_GHZ_DEVICE_CAPACITY,                 0x8F2D, "No More Sub GHz Device Capacity") \
    XXX(GBCS_GBZ_ALERT_SOURCE_DOES_NOT_HAVE_AUTHORITY_FOR_COMMAND,      0x8F30, "Source Does not have Authority for Command") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_ARMED,                                    0x8F32, "Supply Armed") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_DISABLED_THEN_ARMED_LOAD_LIMIT_TRIGGERED, 0x8F33, "Supply Disabled then Armed - Load Limit triggered") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_ENABLED_AFTER_LOAD_LIMIT_RESTORATION_PERI,0x8F34, "Supply Enabled after Load Limit Restoration Period (Load Limit triggered)") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_OUTAGE_RESTORED,                          0x8F35, "Supply Outage Restored") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_OUTAGE_RESTORED_OUTAGE_3_MINUTES,         0x8F36, "Supply Outage Restored - Outage >= 3 minutes") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_OUTAGE_RESTORED_ON_PHASE_1,               0x8F37, "Supply Outage Restored on Phase 1") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_OUTAGE_RESTORED_ON_PHASE_1_RESTORED_OUTAG,0x8F38, "Supply Outage Restored on Phase 1 Restored - Outage >= 3 minutes") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_OUTAGE_RESTORED_ON_PHASE_2_RESTORED,      0x8F39, "Supply Outage Restored on Phase 2 Restored") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_OUTAGE_RESTORED_ON_PHASE_2_RESTORED_OUTAG,0x8F3A, "Supply Outage Restored on Phase 2 Restored - Outage >= 3 minutes") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_OUTAGE_RESTORED_ON_PHASE_3_RESTORED,      0x8F3B, "Supply Outage Restored on Phase 3 Restored") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_OUTAGE_RESTORED_ON_PHASE_3_RESTORED_OUTAG,0x8F3C, "Supply Outage Restored on Phase 3 Restored - Outage >= 3 minutes") \
    XXX(GBCS_GBZ_ALERT_TRUSTED_SOURCE_AUTHENTICATION_FAILURE,           0x8F3D, "Trusted Source Authentication Failure") \
    XXX(GBCS_GBZ_ALERT_UNAUTHORISED_COMMUNICATION_ACCESS_ATTEMPTED,     0x8F3E, "Unauthorised Communication Access attempted") \
    XXX(GBCS_GBZ_ALERT_UNAUTHORISED_PHYSICAL_ACCESS_TAMPER_DETECT,      0x8F3F, "Unauthorised Physical Access - Tamper Detect") \
    XXX(GBCS_GBZ_ALERT_CHANGE_IN_THE_EXECUTING_FIRMWARE_VERSION,        0x8F43, "Change in the executing Firmware version") \
    XXX(GBCS_GBZ_ALERT_CREDIT_WOULD_CAUSE_METER_BALANCE_TO_EXCEED_MAXIM,0x8F47, "Credit would cause Meter Balance to exceed  Maximum Meter Balance Threshold") \
    XXX(GBCS_GBZ_ALERT_DEVICE_JOINING_FAILED,                           0x8F48, "Device joining failed") \
    XXX(GBCS_GBZ_ALERT_DEVICE_JOINING_SUCCEEDED,                        0x8F49, "Device joining succeeded ") \
    XXX(GBCS_GBZ_ALERT_DEVICE_UNJOINING_FAILED,                         0x8F4A, "Device Unjoining failed ") \
    XXX(GBCS_GBZ_ALERT_DEVICE_UNJOINING_SUCCEEDED,                      0x8F4B, "Device Unjoining succeeded ") \
    XXX(GBCS_GBZ_ALERT_DEVICE_OWN_DIGITAL_SIGNING_CERT_REPLACEME_FAILED,0x8F4C, "Device's own Digital Signing Certificate replacement failed") \
    XXX(GBCS_GBZ_ALERT_DEVICE_OWN_DIGITAL_SIGNING_CERT_REPLACEME_SUCCES,0x8F4D, "Device's own Digital Signing Certificate replacement succeeded") \
    XXX(GBCS_GBZ_ALERT_DEVICE_OWN_KEY_AGREEMENT_CERTIFICATE_REP_FAILED, 0x8F4E, "Device's own Key Agreement Certificate replacement failed") \
    XXX(GBCS_GBZ_ALERT_DEVICE_OWN_KEY_AGREEMENT_CERTIFICATE_REP_SUCCEED,0x8F4F, "Device's own Key Agreement Certificate replacement succeeded") \
    XXX(GBCS_GBZ_ALERT_DUPLICATE_UTRN_ENTERED,                          0x8F51, "Duplicate UTRN entered") \
    XXX(GBCS_GBZ_ALERT_EVENT_LOG_CLEARED,                               0x8F52, "Event Log Cleared") \
    XXX(GBCS_GBZ_ALERT_FAILED_AUTHENTICATION_OR_AUTHORISATION_NOT_COVER,0x8F53, "Failed Authentication or Authorisation not covered by other codes") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_INTERRUPTED,                              0x8F57, "Supply interrupted") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_INTERRUPTED_ON_PHASE_1,                   0x8F58, "Supply interrupted on Phase 1") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_INTERRUPTED_ON_PHASE_2,                   0x8F59, "Supply interrupted on Phase 2") \
    XXX(GBCS_GBZ_ALERT_SUPPLY_INTERRUPTED_ON_PHASE_3,                   0x8F5A, "Supply interrupted on Phase 3") \
    XXX(GBCS_GBZ_ALERT_UTRN_EXCEEDS_MAXIMUM_CREDIT_THRESHOLD,           0x8F5B, "UTRN exceeds Maximum Credit Threshold") \
    XXX(GBCS_GBZ_ALERT_UNUSUAL_NUMBERS_OF_MALFORMED_OUT_OF_ORDER_OR_UNE,0x8F60, "Unusual numbers of malformed, out-of-order or unexpected Commands received") \
    XXX(GBCS_GBZ_ALERT_UTRN_NOT_AUTHENTIC,                              0x8F63, "UTRN not Authentic") \
    XXX(GBCS_GBZ_ALERT_UTRN_NOT_FOR_THIS_DEVICE,                        0x8F64, "UTRN not for this Device") \
    XXX(GBCS_GBZ_ALERT_FUTURE_DATE_HAN_INTERFACE_CMD_SUCCESS_ACTIONED,  0x8F66, "Future date HAN Interface Command Successfully Actioned") \
    XXX(GBCS_GBZ_ALERT_FUTURE_DATE_HAN_INTERFACE_CMD_NOT_SUCCESS_ACTION,0x8F67, "Future date HAN Interface Command not Successfully Actioned") \
    XXX(GBCS_GBZ_ALERT_DEVICE_COMMISSIONED,                             0x8F69, "Device commissioned") \
    XXX(GBCS_GBZ_ALERT_UPDATE_SECURITY_CREDENTIALS,                     0x8F70, "Update Security Credentials") \
    XXX(GBCS_GBZ_ALERT_FIRMWARE_VERIFICATION_SUCCESSFUL,                0x8F72, "Firmware Verification Successful") \
    XXX(GBCS_GBZ_ALERT_UNAUTHORISED_PHYSICAL_ACCESS_BATTERY_COVER_REMOV,0x8F73, "Unauthorised Physical Access - Battery Cover Removed") \
    XXX(GBCS_GBZ_ALERT_UNAUTHORISED_PHYSICAL_ACCESS_METER_COVER_REMOVED,0x8F74, "Unauthorised Physical Access - Meter Cover Removed") \
    XXX(GBCS_GBZ_ALERT_UNAUTHORISED_PHYSICAL_ACCESS_STRONG_MAGNETIC_FIE,0x8F75, "Unauthorised Physical Access - Strong Magnetic field") \
    XXX(GBCS_GBZ_ALERT_UNAUTHORISED_PHYSICAL_ACCESS_TERMINAL_COVER_REMO,0x8F76, "Unauthorised Physical Access - Terminal Cover Removed") \
    XXX(GBCS_GBZ_ALERT_UNAUTHORISED_PHYSICAL_ACCESS_SECOND_TERMINAL_COV,0x8F77, "Unauthorised Physical Access - Second Terminal Cover Removed") \
    XXX(GBCS_GBZ_ALERT_UNAUTHORISED_PHYSICAL_ACCESS_OTHER,              0x8F78, "Unauthorised Physical Access - Other") \
    XXX(GBCS_GBZ_ALERT_REMAINING_BATTERY_CAPACITY_RESET,                0x8F82, "Remaining Battery Capacity reset") \
    XXX(GBCS_GBZ_ALERT_DISABLEMENT_OF_SUPPLY_INS_CREDIT_SUSPENDED,      0x8F83, "Disablement of Supply due to insufficient credit has been suspended") \
    XXX(GBCS_GBZ_ALERT_FAILURE_TO_DELIVER_REMOTE_PARTY_MESSAGE_TO_ESME, 0x8F84, "Failure to Deliver Remote Party Message to ESME")

VALUE_STRING_ENUM(gbcs_gbz_alert_code_names);
VALUE_STRING_ARRAY(gbcs_gbz_alert_code_names);
static value_string_ext gbcs_gbz_alert_code_names_ext = VALUE_STRING_EXT_INIT(gbcs_gbz_alert_code_names);

#define gbcs_gbz_integrity_issue_warning_names_VALUE_STRING_LIST(XXX) \
    XXX(GBCS_GBZ_INTEGRITY_ISSUE_WARNING_OTHER,                         0x0000, "Other" ) \
    XXX(GBCS_GBZ_INTEGRITY_ISSUE_WARNING_ERROR_NON_VOLATILE_MEMORY,     0x0001, "Error Non Volatile Memory" ) \
    XXX(GBCS_GBZ_INTEGRITY_ISSUE_WARNING_ERROR_PROGRAM_EXECUTION,       0x0002, "Error Program Execution" ) \
    XXX(GBCS_GBZ_INTEGRITY_ISSUE_WARNING_ERROR_PROGRAM_STORAGE,         0x0003, "Error Program Storage" ) \
    XXX(GBCS_GBZ_INTEGRITY_ISSUE_WARNING_ERROR_RAM,                     0x0004, "Error RAM" ) \
    XXX(GBCS_GBZ_INTEGRITY_ISSUE_WARNING_ERROR_UNEXPECTED_HW_RESET,     0x0005, "Error Unexpected Hardware Reset" ) \
    XXX(GBCS_GBZ_INTEGRITY_ISSUE_WARNING_ERROR_WATCHDOG,                0x0006, "Error Watchdog" ) \
    XXX(GBCS_GBZ_INTEGRITY_ISSUE_WARNING_ERROR_MET_FW_VERIFICATION_FAIL,0x0007, "Error Metrology Firmware Verification Failure" ) \
    XXX(GBCS_GBZ_INTEGRITY_ISSUE_WARNING_ERROR_MEASUREMENT_FAULT,       0x0008, "Error Measurement Fault" ) \
    XXX(GBCS_GBZ_INTEGRITY_ISSUE_WARNING_UNSPEC_SMART_METER_OP_INT_ERR, 0x0009, "Unspecified Smart Meter Operational Integrity Error" )

VALUE_STRING_ENUM(gbcs_gbz_integrity_issue_warning_names);
VALUE_STRING_ARRAY(gbcs_gbz_integrity_issue_warning_names);

#define gbcs_gbz_user_interface_command_names_VALUE_STRING_LIST(XXX) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_ACTIVATE_BOOST_PERIOD,          0x0001, "Activate Boost Period" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_ACTIVATE_EMERGENCY_CREDIT_PIN,  0x0002, "Activate Emergency Credit [PIN]" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_ADD_CREDIT,                     0x0005, "Add Credit" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_ALLOW_ACCESS_TO_USER_INTERFACE, 0x0008, "Allow Access to User Interface" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_CANCEL_BOOST_PERIOD,            0x000A, "Cancel Boost Period" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_CHECK_FOR_HAN_INTERFACE_CMD,    0x000B, "Check for HAN Interface Commands" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_DISABLE_PRIV_PIN_PROTEC_PIN,    0x000C, "Disable Privacy PIN Protection [PIN]" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_ENABLE_SUPPLY_PIN,              0x000E, "Enable Supply [PIN]" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_EXTEND_BOOST_PERIOD,            0x000F, "Extend Boost Period" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_SET_PRIVACY_PIN_PIN,            0x0012, "Set Privacy PIN [PIN]" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_TEST_AUX_LOAD_CONTROL_SWITCH_1, 0x0013, "Test Auxiliary Load Control Switch 1" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_TEST_AUX_LOAD_CONTROL_SWITCH_2, 0x0014, "Test Auxiliary Load Control Switch 2" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_TEST_AUX_LOAD_CONTROL_SWITCH_3, 0x0015, "Test Auxiliary Load Control Switch 3" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_TEST_AUX_LOAD_CONTROL_SWITCH_4, 0x0016, "Test Auxiliary Load Control Switch 4" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_TEST_AUX_LOAD_CONTROL_SWITCH_5, 0x0017, "Test Auxiliary Load Control Switch 5" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_TEST_VALVE,                     0x0018, "Test Valve" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_RESET_REMAIN_BATTERY_CAPACITY,  0x0019, "Reset Remaining Battery Capacity" ) \
    XXX(GBCS_GBZ_USER_INTERFACE_COMMAND_FIND_AND_JOIN_SMHAN,            0x001A, "Find and Join SMHAN" )

VALUE_STRING_ENUM(gbcs_gbz_user_interface_command_names);
VALUE_STRING_ARRAY(gbcs_gbz_user_interface_command_names);

static dissector_handle_t zcl_handle;

static int proto_gbcs_gbz = -1;

static int hf_gbcs_gbz_profile_id = -1;
static int hf_gbcs_gbz_components = -1;
static int hf_gbcs_gbz_extended_header_control = -1;
static int hf_gbcs_gbz_extended_header_cluster = -1;
static int hf_gbcs_gbz_extended_header_length = -1;
static int hf_gbcs_gbz_alert_code = -1;
static int hf_gbcs_gbz_timestamp = -1;
static int hf_gbcs_gbz_firmware_alert_start = -1;
static int hf_gbcs_gbz_firmware_hash = -1;
static int hf_gbcs_gbz_future_alert_start = -1;
static int hf_gbcs_gbz_message_code = -1;
static int hf_gbcs_gbz_originator_counter = -1;
static int hf_gbcs_gbz_frame_control = -1;
static int hf_gbcs_gbz_command_id = -1;
static int hf_gbcs_gbz_integrity_issue_warning = -1;
static int hf_gbcs_gbz_user_interface_command = -1;
static int hf_gbcs_gbz_from_date_time = -1;
static int hf_gbcs_gbz_additional_header_control = -1;
static int hf_gbcs_gbz_additional_frame_counter = -1;
static int hf_gbcs_gbz_transaction = -1;
static int hf_gbcs_gbz_length_of_ciphered_information = -1;
static int hf_gbcs_gbz_security_control = -1;
static int hf_gbcs_gbz_invocation_counter = -1;
static int hf_gbcs_gbz_encrypted_payload = -1;
static int hf_gbcs_gbz_mac = -1;

static gint ett_gbcs_gbz = -1;
static gint ett_gbcs_gbz_components[GBCS_GBZ_MAX_COMPONENTS];

static expert_field ei_gbcs_gbz_invalid_length = EI_INIT;

void proto_register_gbcs_gbz(void);
void proto_reg_handoff_gbcs_gbz(void);

static void dissect_gbcs_gbz_component(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint component_index)
{
    proto_item *ti;
    proto_tree *component_tree;
    guint32 component_len;
    guint32 cluster;
    gboolean fromdatetime_present;
    gboolean encryption_present;
    guint32 extended_header_control;

    if (component_index > GBCS_GBZ_MAX_COMPONENTS - 1) {
        component_index = GBCS_GBZ_MAX_COMPONENTS - 1;
    }

    component_tree = proto_tree_add_subtree(tree, tvb, *offset, 1, ett_gbcs_gbz_components[component_index], &ti, "Use Case Component");

    proto_tree_add_item_ret_uint(component_tree, hf_gbcs_gbz_extended_header_control, tvb, *offset, 1, ENC_NA, &extended_header_control);
    fromdatetime_present = extended_header_control & GBCS_GBZ_EXTENDED_HEADER_CONTROL_FROM_DATE_TIME_PRESENT;
    encryption_present = extended_header_control & GBCS_GBZ_EXTENDED_HEADER_CONTROL_ENCRYPTED_COMPONENT;
    *offset += 1;

    proto_tree_add_item_ret_uint(component_tree, hf_gbcs_gbz_extended_header_cluster, tvb, *offset, 2, ENC_BIG_ENDIAN, &cluster);
    *offset += 2;

    proto_tree_add_item_ret_uint(component_tree, hf_gbcs_gbz_extended_header_length, tvb, *offset, 2, ENC_BIG_ENDIAN, &component_len);
    *offset += 2;

    if ((gint)component_len > tvb_reported_length_remaining(tvb, *offset)) {
        expert_add_info(pinfo, tree, &ei_gbcs_gbz_invalid_length);
    }

    if (fromdatetime_present) {
        nstime_t timestamp;

        timestamp.secs = (time_t)tvb_get_ntohl(tvb, *offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
        timestamp.nsecs = 0;
        proto_tree_add_time(component_tree, hf_gbcs_gbz_from_date_time, tvb, *offset, 4, &timestamp);
        *offset += 4;
        component_len -= 4;
    }
    if (encryption_present) {
        proto_tree_add_item(component_tree, hf_gbcs_gbz_additional_header_control, tvb, *offset, 1, ENC_NA);
        *offset += 1;
        component_len -= 1;

        proto_tree_add_item(component_tree, hf_gbcs_gbz_additional_frame_counter, tvb, *offset, 1, ENC_NA);
        *offset += 1;
        component_len -= 1;
    }
    proto_tree_add_item(component_tree, hf_gbcs_gbz_frame_control, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    component_len -= 1;

    proto_tree_add_item(component_tree, hf_gbcs_gbz_transaction, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    component_len -= 1;

    proto_tree_add_item(component_tree, hf_gbcs_gbz_command_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    component_len -= 1;

    if (encryption_present) {
        proto_tree_add_item(component_tree, hf_gbcs_gbz_length_of_ciphered_information, tvb, *offset, 2, ENC_BIG_ENDIAN);
        *offset += 2;
        component_len -= 2;

        proto_tree_add_item(component_tree, hf_gbcs_gbz_security_control, tvb, *offset, 1, ENC_NA);
        *offset += 1;
        component_len -= 1;

        proto_tree_add_item(component_tree, hf_gbcs_gbz_invocation_counter, tvb, *offset, 4, ENC_BIG_ENDIAN);
        *offset += 4;
        component_len -= 4;

        if (component_len < GBCS_GBZ_MAC_LENGTH) {
            expert_add_info(pinfo, tree, &ei_gbcs_gbz_invalid_length);
        }

        proto_tree_add_item(component_tree, hf_gbcs_gbz_encrypted_payload, tvb, *offset, component_len - GBCS_GBZ_MAC_LENGTH, ENC_NA);
        *offset += component_len - GBCS_GBZ_MAC_LENGTH;

        proto_tree_add_item(component_tree, hf_gbcs_gbz_mac, tvb, *offset, GBCS_GBZ_MAC_LENGTH, ENC_NA);
        *offset += GBCS_GBZ_MAC_LENGTH;
    }
    else if (zcl_handle) {
        zbee_nwk_packet nwk;
        tvbuff_t *payload_tvb;
        const gchar *text;
        wmem_strbuf_t *strbuf;

        text = col_get_text(pinfo->cinfo, COL_INFO);
        if (text) {
            strbuf = wmem_strbuf_new(wmem_packet_scope(), text);
        }
        nwk.cluster_id = cluster;
        payload_tvb = tvb_new_subset_length(tvb, *offset - 3, component_len + 3);
        call_dissector_with_data(zcl_handle, payload_tvb, pinfo, component_tree, &nwk);
        if (text) {
            col_add_str(pinfo->cinfo, COL_INFO, wmem_strbuf_get_str(strbuf));
        }
        *offset += component_len;
    }
    proto_item_set_end(ti, tvb, *offset);
}

static int dissect_gbcs_gbz(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *ti;
    proto_tree *gbz_tree;
    guint offset = 0;
    guint8 cra = *(guint8*)data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GBCS GBZ");

    ti = proto_tree_add_item(tree, proto_gbcs_gbz, tvb, 0, -1, ENC_NA);
    gbz_tree = proto_item_add_subtree(ti, ett_gbcs_gbz);

    proto_tree_add_item(gbz_tree, hf_gbcs_gbz_profile_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(gbz_tree, hf_gbcs_gbz_components, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (cra == GBCS_MESSAGE_CRA_ALERT) {
        nstime_t timestamp;
        guint32 alert_code;

        proto_tree_add_item_ret_uint(gbz_tree, hf_gbcs_gbz_alert_code, tvb, offset, 2, ENC_BIG_ENDIAN, &alert_code);
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str_ext_const(alert_code, &gbcs_gbz_alert_code_names_ext, "Unknown alert"));
        offset += 2;

        timestamp.secs = (time_t)tvb_get_ntohl(tvb, offset) + ZBEE_ZCL_NSTIME_UTC_OFFSET;
        timestamp.nsecs = 0;
        proto_tree_add_time(gbz_tree, hf_gbcs_gbz_timestamp, tvb, offset, 4, &timestamp);
        offset += 4;

        switch (alert_code) {
        case GBCS_GBZ_ALERT_FIRMWARE_VERIFICATION_FAILED:
        case GBCS_GBZ_ALERT_FIRMWARE_VERIFICATION_SUCCESSFUL:
            proto_tree_add_item(gbz_tree, hf_gbcs_gbz_firmware_alert_start, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(gbz_tree, hf_gbcs_gbz_firmware_hash, tvb, offset, 32, ENC_NA);
            offset += 32;
            break;
        case GBCS_GBZ_ALERT_FUTURE_DATE_HAN_INTERFACE_CMD_SUCCESS_ACTIONED:
        case GBCS_GBZ_ALERT_FUTURE_DATE_HAN_INTERFACE_CMD_NOT_SUCCESS_ACTION:
            if (tvb_get_guint8(tvb, offset) == 0x0E) {
                proto_tree_add_item(gbz_tree, hf_gbcs_gbz_future_alert_start, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(gbz_tree, hf_gbcs_gbz_message_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                proto_tree_add_item(gbz_tree, hf_gbcs_gbz_originator_counter, tvb, offset, 8, ENC_BIG_ENDIAN);
                offset += 8;

                proto_tree_add_item(gbz_tree, hf_gbcs_gbz_extended_header_cluster, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                proto_tree_add_item(gbz_tree, hf_gbcs_gbz_frame_control, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(gbz_tree, hf_gbcs_gbz_command_id, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            break;
        case GBCS_GBZ_ALERT_BILLING_DATA_LOG_UPDATED:
            dissect_gbcs_gbz_component(tvb, pinfo, gbz_tree, &offset, 0);
            break;
        case GBCS_GBZ_ALERT_USER_INTERFACE_COMMAND_INPUT_AND_SUCCESSFULLY_AC:
        case GBCS_GBZ_ALERT_USER_INTERFACE_COMMAND_INPUT_BUT_NOT_SUCCESSFULL:
            proto_tree_add_item(gbz_tree, hf_gbcs_gbz_user_interface_command, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case GBCS_GBZ_ALERT_SMART_METER_INTEGRITY_ISSUE_WARNING:
            proto_tree_add_item(gbz_tree, hf_gbcs_gbz_integrity_issue_warning, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        default:
            break;
        }
    }
    else {
        guint component_index = 0;

        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            dissect_gbcs_gbz_component(tvb, pinfo, gbz_tree, &offset, component_index++);
        }
    }

    return tvb_captured_length(tvb);
}

void proto_register_gbcs_gbz(void)
{
    static hf_register_info hf[] = {
        {&hf_gbcs_gbz_profile_id,
            {"Profile ID", "gbcs_gbz.profile_id",
             FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_components,
            {"Total number of GBZ Use Case Specific Component(s)", "gbcs_gbz.components",
              FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_extended_header_control,
            {"Extended Header Control Field", "gbcs_gbz.extended_header_control",
              FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_extended_header_cluster,
            {"Extended Header Cluster ID", "gbcs_gbz.extended_header_cluster",
              FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_aps_cid_names), 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_extended_header_length,
            {"Extended Header Length", "gbcs_gbz.extended_header_length",
              FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_alert_code,
            {"Alert Code", "gbcs_gbz.alert_code",
              FT_UINT16, BASE_HEX | BASE_EXT_STRING, &gbcs_gbz_alert_code_names_ext, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_timestamp,
            {"Timestamp", "gbcs_gbz.timestamp",
             FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_firmware_alert_start,
            {"Firmware Alert Start", "gbcs_gbz.firmware_alert_start",
             FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_firmware_hash,
            {"Calculated Manufacture Image Hash", "gbcs_gbz.firmware_hash",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_future_alert_start,
            {"Future Dated Command Alert Start", "gbcs_gbz.future_alert_start",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_message_code,
            {"Message Code", "gbcs_gbz.message_code",
             FT_UINT16, BASE_HEX | BASE_EXT_STRING, &gbcs_message_code_names_ext, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_originator_counter,
            {"Originator Counter", "gbcs_gbz.originator_counter",
             FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_frame_control,
            {"Frame Control", "gbcs_gbz.frame_control",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_command_id,
            {"Command Identifier", "gbcs_gbz.command_id",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_integrity_issue_warning,
            {"Integrity Issue Warning", "gbcs_gbz.integrity_issue_warning",
             FT_UINT16, BASE_HEX, VALS(gbcs_gbz_integrity_issue_warning_names), 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_user_interface_command,
            {"User Interface Command", "gbcs_gbz.user_interface_command",
             FT_UINT16, BASE_HEX, VALS(gbcs_gbz_user_interface_command_names), 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_from_date_time,
            {"From Date Time", "gbcs_gbz.from_date_time",
             FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_additional_header_control,
            {"Additional Header Control", "gbcs_gbz.additional_header_control",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_additional_frame_counter,
            {"Additional Header Frame Counter", "gbcs_gbz.additional_frame_counter",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_transaction,
            {"Transaction Sequence Number", "gbcs_gbz.transaction",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_length_of_ciphered_information,
            {"Length of Ciphered Information", "gbcs_gbz.length_of_ciphered_information",
             FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_security_control,
            {"Security Control", "gbcs_gbz.security_control",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_invocation_counter,
            {"Invocation Counter", "gbcs_gbz.invocation_counter",
             FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_encrypted_payload,
            {"Encrypted ZCL Payload", "gbcs_gbz.encrypted_payload",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_gbz_mac,
            {"Encrypted ZCL MAC", "gbcs_gbz.mac",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        }
    };

    static gint *ett[1 + GBCS_GBZ_MAX_COMPONENTS];

    gint j = 0;
    ett[j++] = &ett_gbcs_gbz;
    for (gint i = 0; i < GBCS_GBZ_MAX_COMPONENTS; i++, j++) {
        ett_gbcs_gbz_components[i] = -1;
        ett[j] = &ett_gbcs_gbz_components[i];
    }

    expert_module_t* expert_gbcs_gbz;
    static ei_register_info ei[] = {
        { &ei_gbcs_gbz_invalid_length,
            { "gbcs_gbz.invalid_length", PI_PROTOCOL, PI_WARN, "Invalid length", EXPFILL }}
    };

    proto_gbcs_gbz = proto_register_protocol("GBCS GBZ", "GBCS GBZ", "gbcs_gbz");
    register_dissector("gbcs_gbz", dissect_gbcs_gbz, proto_gbcs_gbz);
    proto_register_field_array(proto_gbcs_gbz, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_gbcs_gbz = expert_register_protocol(proto_gbcs_gbz);
    expert_register_field_array(expert_gbcs_gbz, ei, array_length(ei));
}

void proto_reg_handoff_gbcs_gbz(void)
{
    zcl_handle = find_dissector(ZBEE_PROTOABBREV_ZCL);
}

/* ########################################################################## */
/* #### GBCS Tunnel ######################################################### */
/* ########################################################################## */

#define gbcs_tunnel_command_names_VALUE_STRING_LIST(XXX) \
    XXX(GBCS_TUNNEL_COMMAND_GET,                                0x01, "GET" ) \
    XXX(GBCS_TUNNEL_COMMAND_GET_RESPONSE,                       0x02, "GET-RESPONSE" ) \
    XXX(GBCS_TUNNEL_COMMAND_PUT,                                0x03, "PUT" )

VALUE_STRING_ENUM(gbcs_tunnel_command_names);
VALUE_STRING_ARRAY(gbcs_tunnel_command_names);

static dissector_handle_t gbcs_message_handle;

static int proto_gbcs_tunnel = -1;

static int hf_gbcs_tunnel_command = -1;
static int hf_gbcs_tunnel_remaining = -1;

static gint ett_gbcs_tunnel = -1;

void proto_register_gbcs_tunnel(void);
void proto_reg_handoff_gbcs_tunnel(void);

static int dissect_gbcs_tunnel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint offset = 0;
    guint8 command;

    command = tvb_get_guint8(tvb, offset);
    switch (command) {
        case GBCS_TUNNEL_COMMAND_GET:
        case GBCS_TUNNEL_COMMAND_GET_RESPONSE:
        case GBCS_TUNNEL_COMMAND_PUT: {
            proto_item *ti;
            proto_tree *tunnel_tree;

            col_set_str(pinfo->cinfo, COL_PROTOCOL, "GBCS Tunnel");

            ti = proto_tree_add_item(tree, proto_gbcs_tunnel, tvb, offset, -1, ENC_NA);
            tunnel_tree = proto_item_add_subtree(ti, ett_gbcs_tunnel);

            col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(command, gbcs_tunnel_command_names, "Unknown Command"));
            proto_tree_add_item(tunnel_tree, hf_gbcs_tunnel_command, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (command == GBCS_TUNNEL_COMMAND_GET_RESPONSE) {
                proto_tree_add_item(tunnel_tree, hf_gbcs_tunnel_remaining, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            break;
        }

        default:
            /* No tunnel header */
            col_clear(pinfo->cinfo, COL_INFO);
            break;
    }

    if (command != GBCS_TUNNEL_COMMAND_GET && tvb_reported_length_remaining(tvb, offset) > 0) {
        tvbuff_t *payload_tvb = tvb_new_subset_remaining(tvb, offset);

        if (gbcs_message_handle != NULL) {
            call_dissector_with_data(gbcs_message_handle, payload_tvb, pinfo, tree, NULL);
        }
        else {
            call_data_dissector(payload_tvb, pinfo, tree);
        }
    }

    return tvb_captured_length(tvb);
}

static gboolean
dissect_gbcs_tunnel_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    switch (tvb_get_guint8(tvb, 0)) {
        case GBCS_TUNNEL_COMMAND_GET:
        case GBCS_TUNNEL_COMMAND_PUT:
        case GBCS_TUNNEL_COMMAND_GET_RESPONSE:
        case 0xDD:
        case 0xDF:
            dissect_gbcs_tunnel(tvb, pinfo, tree, data);
            return TRUE;

        default:
            return FALSE;
    }
}

void proto_register_gbcs_tunnel(void)
{
    static hf_register_info hf[] = {
        {&hf_gbcs_tunnel_command,
            {"Transfer data command", "gbcs_tunnel.command",
             FT_UINT8, BASE_HEX, VALS(gbcs_tunnel_command_names), 0x0, NULL, HFILL}
        },
        {&hf_gbcs_tunnel_remaining,
            {"Remaining messages", "gbcs_tunnel.remaining",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        }
    };

    static gint *ett[] = {
        &ett_gbcs_tunnel,
    };

    proto_gbcs_tunnel = proto_register_protocol("GBCS Tunnel", "GBCS Tunnel", "gbcs_tunnel");
    register_dissector("gbcs_tunnel", dissect_gbcs_tunnel, proto_gbcs_tunnel);
    proto_register_field_array(proto_gbcs_tunnel, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_gbcs_tunnel(void)
{
    gbcs_message_handle = find_dissector("gbcs_message");
    heur_dissector_add("zbee_zcl_se.tun", dissect_gbcs_tunnel_heur, "GBCS over ZigBee SE Tunneling", "gbcs_zbee_zcl_se.tun", proto_gbcs_tunnel, HEURISTIC_ENABLE);
}

/* ########################################################################## */
/* #### GBCS Message ######################################################### */
/* ########################################################################## */

#define GBCS_MESSAGE_GENERAL_CIPHERING                          0xDD
#define GBCS_MESSAGE_GENERAL_SIGNING                            0xDF
#define GBCS_MESSAGE_ACCESS_REQUEST                             0xD9
#define GBCS_MESSAGE_ACCESS_RESPONSE                            0xDA
#define GBCS_MESSAGE_DATA_NOTIFICATION                          0x0F
#define GBCS_MESSAGE_GENERAL_BLOCK_TRANSFER                     0xE0

#define GBCS_MESSAGE_TRANSACTION_ID_LENGTH                      9
#define GBCS_MESSAGE_DLMS_DATE_TIME_LENGTH                      12
#define GBCS_MESSAGE_KRP_LENGTH                                 64
#define GBCS_MESSAGE_MAC_LENGTH                                 12

#define GBCS_MESSAGE_GBT_BLOCK_CONTROL_LAST_BLOCK               0x80
#define GBCS_MESSAGE_GBT_BLOCK_CONTROL_STREAMING                0x40
#define GBCS_MESSAGE_GBT_BLOCK_CONTROL_WINDOW                   0x3F

static dissector_handle_t gbcs_gbcs_handle;
static dissector_handle_t gbcs_gbz_handle;
static dissector_handle_t gbcs_ber_handle;

static int proto_gbcs_message = -1;

static int hf_gbcs_message_element_length = -1;
static int hf_gbcs_message_mac_header_general_ciphering = -1;
static int hf_gbcs_message_mac_header_cra_flag = -1;
static int hf_gbcs_message_mac_header_originator_counter = -1;
static int hf_gbcs_message_mac_header_business_originator_id = -1;
static int hf_gbcs_message_mac_header_business_target_id = -1;
static int hf_gbcs_message_mac_header_date_time = -1;
static int hf_gbcs_message_mac_header_other_info = -1;
static int hf_gbcs_message_mac_header_key_info = -1;
static int hf_gbcs_message_mac_header_security_control_byte = -1;
static int hf_gbcs_message_mac_header_invocation_counter = -1;
static int hf_gbcs_message_grouping_header_general_signing = -1;
static int hf_gbcs_message_grouping_header_cra_flag = -1;
static int hf_gbcs_message_grouping_header_originator_counter = -1;
static int hf_gbcs_message_grouping_header_business_originator_id = -1;
static int hf_gbcs_message_grouping_header_business_target_id = -1;
static int hf_gbcs_message_grouping_header_date_time = -1;
static int hf_gbcs_message_grouping_header_message_code = -1;
static int hf_gbcs_message_grouping_header_supplementary_remote_party_id = -1;
static int hf_gbcs_message_grouping_header_supplementary_remote_party_counter = -1;
static int hf_gbcs_message_grouping_header_supplementary_originator_counter = -1;
static int hf_gbcs_message_grouping_header_supplementary_remote_party_ka_certificate = -1;
static int hf_gbcs_message_krp = -1;
static int hf_gbcs_message_mac = -1;
static int hf_gbcs_message_routing_header_general_ciphering = -1;
static int hf_gbcs_message_routing_header_cra_flag = -1;
static int hf_gbcs_message_routing_header_originator_counter = -1;
static int hf_gbcs_message_routing_header_business_originator_id = -1;
static int hf_gbcs_message_routing_header_business_target_id = -1;
static int hf_gbcs_message_routing_header_date_time = -1;
static int hf_gbcs_message_routing_header_message_code = -1;
static int hf_gbcs_message_routing_header_key_info = -1;
static int hf_gbcs_message_routing_header_security_control_byte = -1;
static int hf_gbcs_message_routing_header_invocation_counter = -1;
static int hf_gbcs_message_gbt_header_general_block_transfer = -1;
static int hf_gbcs_message_gbt_header_block_control = -1;
static int hf_gbcs_message_gbt_header_block_control_last_block = -1;
static int hf_gbcs_message_gbt_header_block_control_streaming = -1;
static int hf_gbcs_message_gbt_header_block_control_window = -1;
static int hf_gbcs_message_gbt_header_block_number = -1;
static int hf_gbcs_message_gbt_header_block_number_ack = -1;
static int hf_gbcs_message_gbt_blocks = -1;
static int hf_gbcs_message_gbt_block = -1;
static int hf_gbcs_message_gbt_block_overlap = -1;
static int hf_gbcs_message_gbt_block_overlap_conflicts = -1;
static int hf_gbcs_message_gbt_block_multiple_tails = -1;
static int hf_gbcs_message_gbt_block_too_long_fragment = -1;
static int hf_gbcs_message_gbt_block_error = -1;
static int hf_gbcs_message_gbt_block_count = -1;
static int hf_gbcs_message_gbt_reassembled_in = -1;
static int hf_gbcs_message_gbt_reassembled_length = -1;

static gint ett_gbcs_message = -1;
static gint ett_gbcs_message_element = -1;
static gint ett_gbcs_message_mac_header = -1;
static gint ett_gbcs_message_grouping_header = -1;
static gint ett_gbcs_message_grouping_header_other_info = -1;
static gint ett_gbcs_message_routing_header = -1;
static gint ett_gbcs_message_routing_header_other_info = -1;
static gint ett_gbcs_message_gbt_header = -1;
static gint ett_gbcs_message_gbt_header_block_control = -1;
static gint ett_gbcs_message_gbt_fragment = -1;
static gint ett_gbcs_message_gbt_fragments = -1;
static gint ett_gbcs_message_asn1 = -1;
static gint ett_gbcs_message_dlms = -1;

static reassembly_table gbcs_message_gbt_reassembly_table;

static const fragment_items gbcs_message_gbt_frag_items = {
    /* Fragment subtrees */
    &ett_gbcs_message_gbt_fragment,
    &ett_gbcs_message_gbt_fragments,
    /* Fragment fields */
    &hf_gbcs_message_gbt_blocks,
    &hf_gbcs_message_gbt_block,
    &hf_gbcs_message_gbt_block_overlap,
    &hf_gbcs_message_gbt_block_overlap_conflicts,
    &hf_gbcs_message_gbt_block_multiple_tails,
    &hf_gbcs_message_gbt_block_too_long_fragment,
    &hf_gbcs_message_gbt_block_error,
    &hf_gbcs_message_gbt_block_count,
    /* Reassembled in field */
    &hf_gbcs_message_gbt_reassembled_in,
    /* Reassembled length field */
    &hf_gbcs_message_gbt_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "GBT fragments"
};

void proto_register_gbcs_message(void);
void proto_reg_handoff_gbcs_message(void);

static void
dissect_gbcs_message_element(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset)
{
    proto_tree *element_tree;
    proto_item *tree_ti, *value_ti;
    guint len;

    element_tree = proto_tree_add_subtree(tree, tvb, *offset, 1, ett_gbcs_message_element, &tree_ti, "");

    proto_tree_add_item_ret_uint(element_tree, hf_gbcs_message_element_length, tvb, *offset, 1, ENC_NA, &len);
    *offset += 1;

    if (len > 0) {
        value_ti = proto_tree_add_item(element_tree, hfindex, tvb, *offset, len, ENC_BIG_ENDIAN);
        if (value_ti) {
            gchar *label;

            label = (char*)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
            proto_item_fill_label(PITEM_FINFO(value_ti), label);
            proto_item_append_text(tree_ti, "%s", label);
        }
        *offset += len;
        proto_item_set_end(tree_ti, tvb, *offset);
    }
    else {
        proto_item_append_text(tree_ti, "%s: <none>", proto_registrar_get_name(hfindex));
    }
}

static void
dissect_gbcs_message_element_transaction_id(proto_tree *tree, int hfindex_cra_flag, int hfindex_originator_counter, tvbuff_t *tvb, guint *offset)
{
    proto_tree *element_tree;
    proto_item *tree_ti, *value_ti;
    guint len;

    element_tree = proto_tree_add_subtree(tree, tvb, *offset, 1, ett_gbcs_message_element, &tree_ti, "");

    proto_tree_add_item_ret_uint(element_tree, hf_gbcs_message_element_length, tvb, *offset, 1, ENC_NA, &len);
    *offset += 1;

    if (len > 0) {
        value_ti = proto_tree_add_item(element_tree, hfindex_cra_flag, tvb, *offset, 1, ENC_NA);
        if (value_ti) {
            gchar *label;

            label = (char*)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
            proto_item_fill_label(PITEM_FINFO(value_ti), label);
            label = strstr(label, ": ") + 2;
            proto_item_append_text(tree_ti, "Transaction ID: %s", label);
        }
        *offset += 1;

        value_ti = proto_tree_add_item(element_tree, hfindex_originator_counter, tvb, *offset, 8, ENC_BIG_ENDIAN);
        if (value_ti) {
            gchar *label;

            label = (char*)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
            proto_item_fill_label(PITEM_FINFO(value_ti), label);
            label = strstr(label, ": ") + 2;
            proto_item_append_text(tree_ti, ", %s", label);
        }
        *offset += 8;
        proto_item_set_end(tree_ti, tvb, *offset);
    }
    else {
        proto_item_append_text(tree_ti, "Transaction ID: <none>");
    }
}

static void
dissect_gbcs_message_element_date_time(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset)
{
    proto_tree *element_tree;
    proto_item *tree_ti, *value_ti;
    guint len;

    element_tree = proto_tree_add_subtree(tree, tvb, *offset, 1, ett_gbcs_message_element, &tree_ti, "");

    proto_tree_add_item_ret_uint(element_tree, hf_gbcs_message_element_length, tvb, *offset, 1, ENC_NA, &len);
    *offset += 1;

    if (len > 0) {
        nstime_t date_time;

        dlms_date_time(tvb, *offset, &date_time);
        value_ti = proto_tree_add_time(element_tree, hfindex, tvb, *offset, GBCS_MESSAGE_DLMS_DATE_TIME_LENGTH, &date_time);
        if (value_ti) {
            gchar *label;

            label = (char*)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
            proto_item_fill_label(PITEM_FINFO(value_ti), label);
            proto_item_append_text(tree_ti, "%s", label);
        }
        *offset += GBCS_MESSAGE_DLMS_DATE_TIME_LENGTH;

        proto_item_set_end(tree_ti, tvb, *offset);
    }
    else {
        proto_item_append_text(tree_ti, "%s: <none>", proto_registrar_get_name(hfindex));
    }
}

static void
dissect_gbcs_message_mac_header(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_item *ti;
    proto_tree *mac_header_tree;
    guint len, offset_start;

    mac_header_tree = proto_tree_add_subtree(tree, tvb, *offset, 1, ett_gbcs_message_mac_header, &ti, "MAC Header");

    proto_tree_add_item(mac_header_tree, hf_gbcs_message_mac_header_general_ciphering, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    dissect_gbcs_message_element_transaction_id(mac_header_tree, hf_gbcs_message_mac_header_cra_flag,
                                                hf_gbcs_message_mac_header_originator_counter, tvb, offset); // transaction-id - always none
    dissect_gbcs_message_element(mac_header_tree, hf_gbcs_message_mac_header_business_originator_id, tvb, offset); // originator-system-title - always none
    dissect_gbcs_message_element(mac_header_tree, hf_gbcs_message_mac_header_business_target_id, tvb, offset); // recipient-system-title - always none
    dissect_gbcs_message_element_date_time(mac_header_tree, hf_gbcs_message_mac_header_date_time, tvb, offset); // date-time - always none
    dissect_gbcs_message_element(mac_header_tree, hf_gbcs_message_mac_header_other_info, tvb, offset); // other-information - always none
    dissect_gbcs_message_element(mac_header_tree, hf_gbcs_message_mac_header_key_info, tvb, offset); // key-info - always none

    offset_start = *offset;
    *offset = get_ber_length(tvb, *offset, &len, NULL);
    proto_tree_add_uint(mac_header_tree, hf_gbcs_message_element_length, tvb, offset_start, *offset - offset_start, len);

    proto_tree_add_item(mac_header_tree, hf_gbcs_message_mac_header_security_control_byte, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(mac_header_tree, hf_gbcs_message_mac_header_invocation_counter, tvb, *offset, 4, ENC_BIG_ENDIAN);
    *offset += 4;

    proto_item_set_end(ti, tvb, *offset);
}

static void
dissect_gbcs_message_grouping_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint *len, guint8 *cra)
{
    proto_item *grouping_header_ti, *other_info_ti;
    proto_tree *grouping_header_tree, *other_info_tree;
    guint other_info_len;
    guint offset_start;
    guint32 message_code;

    grouping_header_tree = proto_tree_add_subtree(tree, tvb, *offset, 1, ett_gbcs_message_grouping_header, &grouping_header_ti, "Grouping Header");

    proto_tree_add_item(grouping_header_tree, hf_gbcs_message_grouping_header_general_signing, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    *cra = tvb_get_guint8(tvb, *offset + 1);
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str_const(*cra, gbcs_message_cra_names, "Unknown CRA"));
    dissect_gbcs_message_element_transaction_id(grouping_header_tree,
            hf_gbcs_message_grouping_header_cra_flag, hf_gbcs_message_grouping_header_originator_counter, tvb, offset);

    dissect_gbcs_message_element(grouping_header_tree, hf_gbcs_message_grouping_header_business_originator_id, tvb, offset);

    dissect_gbcs_message_element(grouping_header_tree, hf_gbcs_message_grouping_header_business_target_id, tvb, offset);

    dissect_gbcs_message_element_date_time(grouping_header_tree, hf_gbcs_message_grouping_header_date_time, tvb, offset);

    other_info_tree = proto_tree_add_subtree(grouping_header_tree, tvb,
            *offset, 1, ett_gbcs_message_grouping_header_other_info, &other_info_ti, "Other Information");

    offset_start = *offset;
    *offset = get_ber_length(tvb, *offset, &other_info_len, NULL);
    proto_tree_add_uint(other_info_tree, hf_gbcs_message_element_length, tvb, offset_start, *offset - offset_start, other_info_len);

    proto_tree_add_item_ret_uint(other_info_tree, hf_gbcs_message_grouping_header_message_code,
            tvb, *offset, 2, ENC_BIG_ENDIAN, &message_code);
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str_ext_const(message_code, &gbcs_message_code_names_ext, "Unknown Use Case"));
    *offset += 2;
    other_info_len -= 2;

    if (other_info_len > 0) {
        proto_tree_add_item(other_info_tree, hf_gbcs_message_grouping_header_supplementary_remote_party_id,
                tvb, *offset, 8, ENC_BIG_ENDIAN);
        *offset += 8;
        other_info_len -= 8;
    }

    if (other_info_len > 0) {
        proto_tree_add_item(other_info_tree, hf_gbcs_message_grouping_header_supplementary_remote_party_counter,
                tvb, *offset, 8, ENC_BIG_ENDIAN);
        *offset += 8;
        other_info_len -= 8;
    }

    if (other_info_len > 0) {
        proto_tree_add_item(other_info_tree, hf_gbcs_message_grouping_header_supplementary_originator_counter,
                tvb, *offset, 8, ENC_BIG_ENDIAN);
        *offset += 8;
        other_info_len -= 8;
    }

    if (other_info_len > 0) {
        proto_tree_add_item(other_info_tree, hf_gbcs_message_grouping_header_supplementary_remote_party_ka_certificate,
                tvb, *offset, other_info_len, ENC_NA);
        *offset += other_info_len;
        other_info_len -= other_info_len;
    }

    proto_item_set_end(other_info_ti, tvb, *offset);

    offset_start = *offset;
    *offset = get_ber_length(tvb, *offset, len, NULL);
    proto_tree_add_uint(grouping_header_tree, hf_gbcs_message_element_length, tvb, offset_start, *offset - offset_start, *len);

    proto_item_set_end(grouping_header_ti, tvb, *offset);
}

static void
dissect_gbcs_message_routing_header(tvbuff_t *tvb, proto_tree *tree, guint *offset,
        guint64 *business_originator, guint64 *originator_counter)
{
    proto_item *routing_header_ti, *other_info_ti;
    proto_tree *routing_header_tree, *other_info_tree;
    guint other_info_len;
    guint len, offset_start;

    routing_header_tree = proto_tree_add_subtree(tree, tvb, *offset, 1, ett_gbcs_message_routing_header, &routing_header_ti, "Routing Header");

    proto_tree_add_item(routing_header_tree, hf_gbcs_message_routing_header_general_ciphering, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    *originator_counter = tvb_get_guint64(tvb, *offset + 2, ENC_BIG_ENDIAN);
    dissect_gbcs_message_element_transaction_id(routing_header_tree,
            hf_gbcs_message_routing_header_cra_flag, hf_gbcs_message_routing_header_originator_counter, tvb, offset);

    *business_originator = tvb_get_guint64(tvb, *offset + 1, ENC_BIG_ENDIAN);
    dissect_gbcs_message_element(routing_header_tree, hf_gbcs_message_routing_header_business_originator_id, tvb, offset);

    dissect_gbcs_message_element(routing_header_tree, hf_gbcs_message_routing_header_business_target_id, tvb, offset);

    dissect_gbcs_message_element_date_time(routing_header_tree, hf_gbcs_message_routing_header_date_time, tvb, offset); // date-time - always none

    other_info_tree = proto_tree_add_subtree(routing_header_tree, tvb,
            *offset, 1, ett_gbcs_message_routing_header_other_info, &other_info_ti, "Other Information");

    offset_start = *offset;
    *offset = get_ber_length(tvb, *offset, &other_info_len, NULL);
    proto_tree_add_uint(other_info_tree, hf_gbcs_message_element_length, tvb, offset_start, *offset - offset_start, other_info_len);

    proto_tree_add_item(other_info_tree, hf_gbcs_message_routing_header_message_code, tvb, *offset, 2, ENC_BIG_ENDIAN);
    *offset += 2;

    dissect_gbcs_message_element(routing_header_tree, hf_gbcs_message_routing_header_key_info, tvb, offset); // key-info - always none

    offset_start = *offset;
    *offset = get_ber_length(tvb, *offset, &len, NULL);
    proto_tree_add_uint(routing_header_tree, hf_gbcs_message_element_length, tvb, offset_start, *offset - offset_start, len);

    proto_tree_add_item(routing_header_tree, hf_gbcs_message_routing_header_security_control_byte, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(routing_header_tree, hf_gbcs_message_routing_header_invocation_counter, tvb, *offset, 4, ENC_BIG_ENDIAN);
    *offset += 4;

    proto_item_set_end(routing_header_ti, tvb, *offset);
}

static void
dissect_gbcs_message_gbt_header(tvbuff_t *tvb, proto_tree *tree, guint *offset,
        guint *len, guint16 *block_number, gboolean *last)
{
    proto_item *ti;
    proto_tree *gbt_header_tree;
    guint offset_start;

    gbt_header_tree = proto_tree_add_subtree(tree, tvb, *offset, 1, ett_gbcs_message_gbt_header, &ti, "GBT Header");

    proto_tree_add_item(gbt_header_tree, hf_gbcs_message_gbt_header_general_block_transfer, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    static int* const block_control[] = {
            &hf_gbcs_message_gbt_header_block_control_last_block,
            &hf_gbcs_message_gbt_header_block_control_streaming,
            &hf_gbcs_message_gbt_header_block_control_window,
            NULL
    };

    *last = tvb_get_guint8(tvb, *offset) & GBCS_MESSAGE_GBT_BLOCK_CONTROL_LAST_BLOCK;
    proto_tree_add_bitmask(gbt_header_tree, tvb, *offset, hf_gbcs_message_gbt_header_block_control,
            ett_gbcs_message_gbt_header_block_control, block_control, ENC_BIG_ENDIAN);
    *offset += 1;

    *block_number = tvb_get_guint16(tvb, *offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(gbt_header_tree, hf_gbcs_message_gbt_header_block_number, tvb, *offset, 2, ENC_BIG_ENDIAN);
    *offset += 2;

    proto_tree_add_item(gbt_header_tree, hf_gbcs_message_gbt_header_block_number_ack, tvb, *offset, 2, ENC_BIG_ENDIAN);
    *offset += 2;

    offset_start = *offset;
    *offset = get_ber_length(tvb, *offset, len, NULL);
    proto_tree_add_uint(gbt_header_tree, hf_gbcs_message_element_length, tvb, offset_start, *offset - offset_start, *len);

    proto_item_set_end(ti, tvb, *offset);
}

static void
dissect_gbcs_gbt_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint len, guint64 business_originator,
        guint64 originator_counter, guint16 block_number, gboolean last)
{
    guint32 msg_id;
    fragment_head *frag_msg = NULL;
    tvbuff_t *new_tvb;

    pinfo->fragmented = TRUE;

    msg_id = ((guint32)business_originator << 8) | ((guint32)originator_counter & 0xFF);

    frag_msg = fragment_add_seq_check(&gbcs_message_gbt_reassembly_table,
            tvb, *offset, pinfo, msg_id, NULL, block_number - 1, len, !last);

    new_tvb = process_reassembled_data(tvb, *offset, pinfo,
            "Reassembled GBT", frag_msg, &gbcs_message_gbt_frag_items, NULL, tree);

    if (new_tvb) {
        /* The reassembly handler defragmented the message, and created a new tvbuff */
        call_dissector_with_data(gbcs_gbcs_handle, new_tvb, pinfo, proto_tree_get_parent_tree(tree), NULL);
    }
    else {
        /* The reassembly handler could not defragment the message yet */
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "GBT block %d", block_number);
        call_data_dissector(tvb_new_subset_length(tvb, *offset, len), pinfo, proto_tree_get_parent_tree(tree));
    }

    *offset += len;
}

static void
dissect_gbcs_message_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint len, guint8 cra)
{
    tvbuff_t *payload_tvb = tvb_new_subset_length(tvb, *offset, len);

    if (gbcs_gbz_handle != NULL && tvb_get_ntohs(payload_tvb, 0) == ZBEE_PROFILE_SE) {
        // Dissect GBZ payload
        call_dissector_with_data(gbcs_gbz_handle, payload_tvb, pinfo, tree, &cra);
    }
    else if (tvb_get_guint8(payload_tvb, 0) == GBCS_MESSAGE_ACCESS_REQUEST
            || tvb_get_guint8(payload_tvb, 0) == GBCS_MESSAGE_ACCESS_RESPONSE
            || tvb_get_guint8(payload_tvb, 0) == GBCS_MESSAGE_DATA_NOTIFICATION) {
        //TODO Dissect DLMS payload
        proto_tree *dlms_tree;

        dlms_tree = proto_tree_add_subtree(tree, payload_tvb, 0, len, ett_gbcs_message_dlms, NULL, "GBCS DLMS");
        call_data_dissector(payload_tvb, pinfo, dlms_tree);
    }
    else {
        // If it isn't GBZ or DLMS, then it is ASN.1
        const gchar *text;
        wmem_strbuf_t *strbuf;
        proto_tree *asn1_tree;

        text = col_get_text(pinfo->cinfo, COL_INFO);
        if (text) {
            strbuf = wmem_strbuf_new(wmem_packet_scope(), text);
        }
        asn1_tree = proto_tree_add_subtree(tree, payload_tvb, 0, len, ett_gbcs_message_asn1, NULL, "GBCS ASN.1");
        call_dissector(gbcs_ber_handle, payload_tvb, pinfo, asn1_tree);
        if (text) {
            col_add_str(pinfo->cinfo, COL_INFO, wmem_strbuf_get_str(strbuf));
        }
    }

    *offset += len;
}

static void
dissect_gbcs_message_krp(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    dissect_gbcs_message_element(tree, hf_gbcs_message_krp, tvb, offset);
}

static void
dissect_gbcs_message_mac(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree_add_item(tree, hf_gbcs_message_mac, tvb, *offset, GBCS_MESSAGE_MAC_LENGTH, ENC_NA);
    *offset += GBCS_MESSAGE_MAC_LENGTH;
}

static int
dissect_gbcs_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *gbcs_message_tree;
    guint offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GBCS Message");

    ti = proto_tree_add_item(tree, proto_gbcs_message, tvb, offset, -1, ENC_NA);
    gbcs_message_tree = proto_item_add_subtree(ti, ett_gbcs_message);

    if ((tvb_get_guint8(tvb, offset) == GBCS_MESSAGE_GENERAL_CIPHERING && tvb_get_guint8(tvb, offset + 1) == 0)
            || tvb_get_guint8(tvb, offset) == GBCS_MESSAGE_GENERAL_SIGNING) {
        // Normal GBCS message
        gboolean mac = tvb_get_guint8(tvb, offset) == GBCS_MESSAGE_GENERAL_CIPHERING;
        guint grouping_len;
        guint8 grouping_cra;

        if (mac) {
            dissect_gbcs_message_mac_header(tvb, gbcs_message_tree, &offset);
        }

        dissect_gbcs_message_grouping_header(tvb, pinfo, gbcs_message_tree, &offset, &grouping_len, &grouping_cra);

        dissect_gbcs_message_payload(tvb, pinfo, tree, &offset, grouping_len, grouping_cra);

        dissect_gbcs_message_krp(tvb, gbcs_message_tree, &offset);

        if (mac) {
            dissect_gbcs_message_mac(tvb, gbcs_message_tree, &offset);
        }
    }
    else if (tvb_get_guint8(tvb, offset) == GBCS_MESSAGE_GENERAL_CIPHERING && tvb_get_guint8(tvb, offset + 1) == 0x09) {
        // GBCS General Block Transfer
        guint gbt_len;
        guint64 business_originator;
        guint64 originator_counter;
        guint16 block_number;
        gboolean last;

        dissect_gbcs_message_routing_header(tvb, gbcs_message_tree, &offset, &business_originator, &originator_counter);

        dissect_gbcs_message_gbt_header(tvb, gbcs_message_tree, &offset, &gbt_len, &block_number, &last);

        if (gbt_len > 0) { // GBT Ack contains no data
            dissect_gbcs_gbt_payload(tvb, pinfo, gbcs_message_tree, &offset, gbt_len, business_originator, originator_counter, block_number, last);
        }
    }

    proto_item_set_end(ti, tvb, offset);

    return tvb_captured_length(tvb);
}

void proto_register_gbcs_message(void)
{
    static hf_register_info hf[] = {
        {&hf_gbcs_message_element_length,
            {"Length", "gbcs_message.element_length",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_mac_header_general_ciphering,
            {"General Ciphering", "gbcs_message.mac_header.general_ciphering",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_mac_header_cra_flag,
            {"CRA Flag", "gbcs_message.mac_header.cra_flag",
             FT_UINT8, BASE_HEX, VALS(gbcs_message_cra_names), 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_mac_header_originator_counter,
            {"Originator Counter", "gbcs_message.mac_header.originator_counter",
             FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_mac_header_business_originator_id,
            {"Business Originator ID", "gbcs_message.mac_header.business_originator_id",
             FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_mac_header_business_target_id,
            {"Business Target ID", "gbcs_message.mac_header.business_target_id",
             FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_mac_header_date_time,
            {"Date Time", "gbcs_message.mac_header.date_time",
             FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_mac_header_other_info,
            {"Other-Information", "gbcs_message.mac_header.other_info",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_mac_header_key_info,
            {"Key-Info", "gbcs_message.mac_header.key_info",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_mac_header_security_control_byte,
            {"Security Control Byte", "gbcs_message.mac_header.security_control_byte",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_mac_header_invocation_counter,
            {"Invocation Counter", "gbcs_message.mac_header.invocation_counter",
             FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_grouping_header_general_signing,
            {"General Signing", "gbcs_message.grouping_header.general_signing",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_grouping_header_cra_flag,
            {"CRA Flag", "gbcs_message.grouping_header.cra_flag",
             FT_UINT8, BASE_HEX, VALS(gbcs_message_cra_names), 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_grouping_header_originator_counter,
            {"Originator Counter", "gbcs_message.grouping_header.originator_counter",
             FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_grouping_header_business_originator_id,
            {"Business Originator ID", "gbcs_message.grouping_header.business_originator_id",
             FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_grouping_header_business_target_id,
            {"Business Target ID", "gbcs_message.grouping_header.business_target_id",
             FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_grouping_header_date_time,
            {"Date Time", "gbcs_message.grouping_header.date_time",
             FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_grouping_header_message_code,
            {"Message Code", "gbcs_message.grouping_header.message_code",
             FT_UINT16, BASE_HEX | BASE_EXT_STRING, &gbcs_message_code_names_ext, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_grouping_header_supplementary_remote_party_id,
            {"Supplementary Remote Party ID", "gbcs_message.grouping_header.supplementary_remote_party_id",
             FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_grouping_header_supplementary_remote_party_counter,
            {"Supplementary Remote Party Counter", "gbcs_message.grouping_header.supplementary_remote_party_counter",
             FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_grouping_header_supplementary_originator_counter,
            {"Supplementary Originator Counter", "gbcs_message.grouping_header.supplementary_remote_party_originator_counter",
             FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_grouping_header_supplementary_remote_party_ka_certificate,
            {"Certificate", "gbcs_message.grouping_header.supplementary_remote_party_ka_certificate",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_krp,
            {"KRP", "gbcs_message.krp",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_mac,
            {"MAC", "gbcs_message.mac",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_routing_header_general_ciphering,
            {"General Ciphering", "gbcs_message.routing_header.general_ciphering",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_routing_header_cra_flag,
            {"CRA Flag", "gbcs_message.routing_header.cra_flag",
             FT_UINT8, BASE_HEX, VALS(gbcs_message_cra_names), 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_routing_header_originator_counter,
            {"Originator Counter", "gbcs_message.routing_header.originator_counter",
             FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_routing_header_business_originator_id,
            {"Business Originator ID", "gbcs_message.routing_header.business_originator_id",
             FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_routing_header_business_target_id,
            {"Business Target ID", "gbcs_message.routing_header.business_target_id",
             FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_routing_header_date_time,
            {"Date Time", "gbcs_message.routing_header.date_time",
             FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_routing_header_key_info,
            {"Key-Info", "gbcs_message.routing_header.key_info",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_routing_header_message_code,
            {"Message Code", "gbcs_message.routing_header.message_code",
             FT_UINT16, BASE_HEX | BASE_EXT_STRING, &gbcs_message_code_names_ext, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_routing_header_security_control_byte,
            {"Security Control Byte", "gbcs_message.routing_header.security_control_byte",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_routing_header_invocation_counter,
            {"Invocation Counter", "gbcs_message.routing_header.invocation_counter",
             FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_gbt_header_general_block_transfer,
            {"General Block Transfer", "gbcs_message.gbt_header.general_block_transfer",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_gbt_header_block_control,
            {"Block Control", "gbcs_message.gbt_header.block_control",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_gbt_header_block_control_last_block,
            {"Last Block", "gbcs_message.gbt_header.block_control.last_block",
             FT_BOOLEAN, 8, NULL, GBCS_MESSAGE_GBT_BLOCK_CONTROL_LAST_BLOCK, NULL, HFILL }
        },
        {&hf_gbcs_message_gbt_header_block_control_streaming,
            {"Streaming", "gbcs_message.gbt_header.block_control.streaming",
             FT_BOOLEAN, 8, NULL, GBCS_MESSAGE_GBT_BLOCK_CONTROL_STREAMING, NULL, HFILL }
        },
        {&hf_gbcs_message_gbt_header_block_control_window,
            {"Window", "gbcs_message.gbt_header.block_control.window",
             FT_UINT8, BASE_DEC, NULL, GBCS_MESSAGE_GBT_BLOCK_CONTROL_WINDOW, NULL, HFILL}
        },
        {&hf_gbcs_message_gbt_header_block_number,
            {"Block Number", "gbcs_message.gbt_header.block_number",
             FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gbcs_message_gbt_header_block_number_ack,
            {"Block Number Ack", "gbcs_message.gbt_header.block_number_ack",
             FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_gbcs_message_gbt_blocks,
            { "Message blocks", "gbcs_message.gbt.blocks",
             FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_gbcs_message_gbt_block,
            { "Message block", "gbcs_message.gbt.block",
             FT_FRAMENUM, BASE_NONE, NULL, 0x0,NULL, HFILL}
        },
        { &hf_gbcs_message_gbt_block_overlap,
            { "Message block overlap", "gbcs_message.gbt.block.overlap",
             FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_gbcs_message_gbt_block_overlap_conflicts,
            { "Message block overlapping with conflicting data", "gbcs_message.gbt.block.overlap.conflicts",
             FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_gbcs_message_gbt_block_multiple_tails,
            { "Message has multiple tail blocks", "gbcs_message.gbt.block.multiple_tails",
             FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_gbcs_message_gbt_block_too_long_fragment,
            { "Message block too long", "gbcs_message.gbt.block.too_long_fragment",
             FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_gbcs_message_gbt_block_error,
            { "Message defragmentation error", "gbcs_message.gbt.block.error",
             FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_gbcs_message_gbt_block_count,
            { "Message block count", "gbcs_message.gbt.block.count",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_gbcs_message_gbt_reassembled_in,
            { "Reassembled in", "gbcs_message.gbt.reassembled.in",
             FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_gbcs_message_gbt_reassembled_length,
            { "Reassembled GBT length", "gbcs_message.gbt.reassembled.length",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        }
    };

    static gint *ett[] = {
        &ett_gbcs_message,
        &ett_gbcs_message_element,
        &ett_gbcs_message_mac_header,
        &ett_gbcs_message_grouping_header,
        &ett_gbcs_message_grouping_header_other_info,
        &ett_gbcs_message_routing_header,
        &ett_gbcs_message_routing_header_other_info,
        &ett_gbcs_message_gbt_header,
        &ett_gbcs_message_gbt_header_block_control,
        &ett_gbcs_message_gbt_fragment,
        &ett_gbcs_message_gbt_fragments,
        &ett_gbcs_message_asn1,
        &ett_gbcs_message_dlms
    };

    proto_gbcs_message = proto_register_protocol("GBCS Message", "GBCS Message", "gbcs_message");
    gbcs_gbcs_handle = register_dissector("gbcs_message", dissect_gbcs_message, proto_gbcs_message);
    proto_register_field_array(proto_gbcs_message, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    reassembly_table_register(&gbcs_message_gbt_reassembly_table, &addresses_reassembly_table_functions);
}

void proto_reg_handoff_gbcs_message(void)
{
    gbcs_gbz_handle = find_dissector("gbcs_gbz");
    gbcs_ber_handle = find_dissector("ber");
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
