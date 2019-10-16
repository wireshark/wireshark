/* packet-hl7.c
 * Routines for Health Level 7 (HL7) dissection: HL7 messages wrapped in
 * MLLP session layer as specified in 'HL7 Implementation Guide for HL7
 * version 2.3.1, appendix C "Lower Layer Protocols", section C.4.3.
 *
 * Copyright 2016 Francesco Fondelli <francesco dot fondelli, gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * TODO:
 * - HL7 messages are most commonly strings with strict ASCII encoding.
 *   However, Unicode or UTF-8 encodings are possible (?). This dissector
 *   lacks support for non-ASCII encodings.
 * - Component and sub-component expansion (not sure is necessary).
 * - Handling delimiter characters in data, i.e. escape sequences support.
 * - Add event type human readable strings.
 * - Improve heuristic detection logic: can a message start with FHS? HLLB
 *   encapsulation? Some common TCP ports besides the one assigned by IANA?
 * - Use GHashTable for lookup segment type description instead of linear
 *   search.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include <stdio.h>

void proto_register_hl7(void);
void proto_reg_handoff_hl7(void);

/* 2575 is registered at IANA for HL7 */
#define TCP_PORT_HL7 2575
#define LLP_SOB 0x0B /* Start Of Block byte */
#define LLP_EOB 0x1C0D /* End Of Block byte + \r */

struct msh {                    // typical/default values
    char field_separator;       // '|'
    char component_separator;   // '^'
    char repetition_separator;  // '~'
    char escape_character;      // '\'
    char subcomponent_separator;// '&'
    char message_type[4];
    char trigger_event[4];
};

dissector_handle_t hl7_handle;
dissector_handle_t hl7_heur_handle;

static int proto_hl7 = -1;

static gint hf_hl7_raw = -1;
static gint hf_hl7_raw_segment = -1;
static gint hf_hl7_llp_sob = -1;
static gint hf_hl7_llp_eob = -1;
static gint hf_hl7_message_type = -1;
static gint hf_hl7_event_type = -1;
static gint hf_hl7_segment = -1;
static gint hf_hl7_field = -1;

static gint ett_hl7 = -1;
static gint ett_hl7_segment = -1;

static expert_field ei_hl7_malformed = EI_INIT;

/* FF: global_hl7_raw determines whether we are going to display
 * the raw text of the HL7 message (like SIP and MEGACO dissectors) */
static gboolean global_hl7_raw = FALSE;

/* FF: global_hl7_llp determines whether we are going to display
 * the LLP block markers */
static gboolean global_hl7_llp = FALSE;

/* as per Health Level Seven, Version 2.6, appendix A */
static const string_string hl7_msg_type_vals[] = {
    { "ACK", "General acknowledgment" },
    { "ADT", "Admit Discharge Transfer" },
    { "BAR", "Add/change billing account" },
    { "BPS", "Blood product dispense status" },
    { "BRP", "Blood product dispense status acknowledgement" },
    { "BRT", "Blood product transfusion/disposition acknowledgement" },
    { "BTS", "Blood product transfusion/disposition" },
    { "CRM", "Clinical study registration" },
    { "CSU", "Unsolicited study data" },
    { "DFT", "Detail financial transactions" },
    { "EAC", "Automated equipment command" },
    { "EAN", "Automated equipment notification" },
    { "EAR", "Automated equipment response" },
    { "EHC", "Health Care Invoice" },
    { "ESR", "Automated equipment status update acknowledgment" },
    { "ESU", "Automated equipment status update" },
    { "INR", "Automated equipment inventory request" },
    { "INU", "Automated equipment inventory update" },
    { "LSR", "Automated equipment log/service request" },
    { "LSU", "Automated equipment log/service update" },
    { "MDM", "Medical document management" },
    { "MFN", "Master files notification" },
    { "NMD", "Application management data" },
    { "NMQ", "Application management query" },
    { "OMB", "Blood product order" },
    { "OMD", "Dietary order" },
    { "OMG", "General clinical order" },
    { "OMI", "Imaging order" },
    { "OML", "Laboratory order" },
    { "OMN", "Non-stock requisition order" },
    { "OMP", "Pharmacy/treatment order" },
    { "OMS", "Stock requisition order" },
    { "OPL", "Population/Location-Based Laboratory Order" },
    { "OPR", "Population/Location-Based Laboratory Order Acknowledgment" },
    { "OPU", "Unsolicited Population/Location-Based Laboratory Observation" },
    { "ORB", "Blood product order acknowledgement" },
    { "ORD", "Dietary order acknowledgment" },
    { "ORF", "Query for results of observation" },
    { "ORG", "General clinical order acknowledgment" },
    { "ORI", "Imaging order acknowledgement" },
    { "ORL", "Laboratory acknowledgment (unsolicited)" },
    { "ORM", "Pharmacy/treatment order" },
    { "ORN", "Non-stock requisition - General order acknowledgment" },
    { "ORP", "Pharmacy/treatment order acknowledgment" },
    { "ORR", "General order response response to any ORM" },
    { "ORS", "Stock requisition - Order acknowledgment" },
    { "ORU", "Unsolicited transmission of an observation" },
    { "OSQ", "Query response for order status" },
    { "OUL", "Unsolicited laboratory observation" },
    { "PEX", "Product experience" },
    { "PGL", "Patient goal" },
    { "PIN", "Patient insurance information" },
    { "PMU", "Add personnel record" },
    { "PPG", "Patient pathway (goal-oriented)" },
    { "PPP", "Patient pathway (problem-oriented)" },
    { "PPR", "Patient problem" },
    { "PPT", "Patient pathway goal-oriented response" },
    { "PPV", "Patient goal response" },
    { "PRR", "Patient problem response" },
    { "PTR", "Patient pathway problem-oriented response" },
    { "QBP", "Query by parameter" },
    { "QCN", "Cancel query" },
    { "QRY", "Query, original mode" },
    { "QSB", "Create subscription" },
    { "QSX", "Cancel subscription/acknowledge" },
    { "QVR", "Query for previous events" },
    { "RAR", "Pharmacy/treatment administration information" },
    { "RAS", "Pharmacy/treatment administration" },
    { "RDE", "Pharmacy/treatment encoded order" },
    { "RDS", "Pharmacy/treatment dispense" },
    { "RDY", "Display based response" },
    { "REF", "Patient referral" },
    { "RER", "Pharmacy/treatment encoded order information" },
    { "RGV", "Pharmacy/treatment give" },
    { "ROR", "Pharmacy/treatment order response" },
    { "RQA", "Request patient authorization" },
    { "RQC", "Request clinical information" },
    { "RQI", "Request patient information" },
    { "RQP", "Request patient demographics" },
    { "RRA", "Pharmacy/treatment administration acknowledgment" },
    { "RRD", "Pharmacy/treatment dispense acknowledgment" },
    { "RRE", "Pharmacy/treatment encoded order acknowledgment" },
    { "RRG", "Pharmacy/treatment give acknowledgment" },
    { "RSP", "Segment pattern response" },
    { "RTB", "Tabular response" },
    { "SCN", "Notification of Anti-Microbial Device Cycle Data" },
    { "SDN", "Notification of Anti-Microbial Device Data" },
    { "SDR", "Sterilization anti-microbial device data request" },
    { "SIU", "Schedule information unsolicited" },
    { "SLN", "Notification of New Sterilization Lot" },
    { "SLR", "Sterilization lot request" },
    { "SMD", "Sterilization anti-microbial device cycle data request" },
    { "SQM", "Schedule query" },
    { "SRM", "Schedule request" },
    { "SSR", "Specimen status request" },
    { "SSU", "Specimen status update" },
    { "STC", "Notification of Sterilization Configuration" },
    { "STI", "Sterilization item request" },
    { "SUR", "Summary product experience report" },
    { "TCR", "Automated equipment test code settings request" },
    { "TCU", "Automated equipment test code settings update" },
    { "VXQ", "Query for vaccination record" },
    { "VXR", "Vaccination record response" },
    { "VXU", "Unsolicited vaccination record update" },
    { "VXX", "Response for vaccination query with multiple PID matches" },
    { NULL, NULL }
};

/* as per Health Level Seven, Version 2.6, appendix A */
static const string_string hl7_seg_type_vals[] = {
    { "ABS", "Abstract" },
    { "ACC", "Accident" },
    { "ADD", "Addendum" },
    { "ADJ", "Adjustment" },
    { "AFF", "Professional Affiliation" },
    { "AIG", "Appointment Information - General Resource" },
    { "AIL", "Appointment Information - Location Resource" },
    { "AIP", "Appointment Information - Personnel Resource" },
    { "AIS", "Appointment Information" },
    { "AL1", "Patient Allergy Information" },
    { "APR", "Appointment Preferences" },
    { "ARQ", "Appointment Request" },
    { "ARV", "Access Restriction" },
    { "AUT", "Authorization Information" },
    { "BHS", "Batch Header" },
    { "BLC", "Blood Code" },
    { "BLG", "Billing" },
    { "BPO", "Blood product order" },
    { "BPX", "Blood product dispense status" },
    { "BTS", "Batch Trailer" },
    { "BTX", "Blood Product Transfusion/Disposition" },
    { "CDM", "Charge Description Master" },
    { "CER", "Certificate Detail" },
    { "CM0", "Clinical Study Master" },
    { "CM1", "Clinical Study Phase Master" },
    { "CM2", "Clinical Study Schedule Master" },
    { "CNS", "Clear Notification" },
    { "CON", "Consent Segment" },
    { "CSP", "Clinical Study Phase" },
    { "CSR", "Clinical Study Registration" },
    { "CSS", "Clinical Study Data Schedule Segment" },
    { "CTD", "Contact Data" },
    { "CTI", "Clinical Trial Identification" },
    { "DB1", "Disability" },
    { "DG1", "Diagnosis" },
    { "DMI", "DRG Master File Information" },
    { "DRG", "Diagnosis Related Group" },
    { "DSC", "Continuation Pointer" },
    { "DSP", "Display Data" },
    { "ECD", "Equipment Command" },
    { "ECR", "Equipment Command Response" },
    { "EDE", "Encapsulated Data (wrong segment)" },
    { "EDU", "Educational Detail" },
    { "EQP", "Equipment/log Service" },
    { "EQU", "Equipment Detail" },
    { "ERR", "Error" },
    { "EVN", "Event Type" },
    { "FAC", "Facility" },
    { "FHS", "File Header" },
    { "FT1", "Financial Transaction" },
    { "FTS", "File Trailer" },
    { "GOL", "Goal Detail" },
    { "GP1", "Grouping/Reimbursement - Visit" },
    { "GP2", "Grouping/Reimbursement - Procedure Line Item" },
    { "GT1", "Guarantor" },
    { "IAM", "Patient Adverse Reaction Information" },
    { "IIM", "Inventory Item Master" },
    { "ILT", "Material Lot" },
    { "IN1", "Insurance" },
    { "IN2", "Insurance Additional Information" },
    { "IN3", "Insurance Additional Information, Certification" },
    { "INV", "Inventory Detail" },
    { "IPC", "Imaging Procedure Control Segment" },
    { "IPR", "Invoice Processing Results" },
    { "ISD", "Interaction Status Detail" },
    { "ITM", "Material Item" },
    { "IVC", "Invoice Segment" },
    { "IVT", "Material Location" },
    { "LAN", "Language Detail" },
    { "LCC", "Location Charge Code" },
    { "LCH", "Location Characteristic" },
    { "LDP", "Location Department" },
    { "LOC", "Location Identification" },
    { "LRL", "Location Relationship" },
    { "MFA", "Master File Acknowledgment" },
    { "MFE", "Master File Entry" },
    { "MFI", "Master File Identification" },
    { "MRG", "Merge Patient Information" },
    { "MSA", "Message Acknowledgment" },
    { "MSH", "Message Header" },
    { "NCK", "System Clock" },
    { "NDS", "Notification Detail" },
    { "NK1", "Next of Kin - Associated Parties" },
    { "NPU", "Bed Status Update" },
    { "NSC", "Application Status Change" },
    { "NST", "Application control level statistics" },
    { "NTE", "Notes and Comments" },
    { "OBR", "Observation Request" },
    { "OBX", "Observation/Result" },
    { "ODS", "Dietary Orders, Supplements, and Preferences" },
    { "ODT", "Diet Tray Instructions" },
    { "OM1", "General Segment" },
    { "OM2", "Numeric Observation" },
    { "OM3", "Categorical Service/Test/Observation" },
    { "OM4", "Observations that Require Specimens" },
    { "OM5", "Observation Batteries (Sets)" },
    { "OM6", "Observations that are Calculated from Other" },
    { "OM7", "Additional Basic Attributes" },
    { "ORC", "Common Order" },
    { "ORG", "Practitioner Organization Unit" },
    { "OVR", "Override Segment" },
    { "PCE", "Patient Charge Cost Center Exceptions" },
    { "PCR", "Possible Causal Relationship" },
    { "PD1", "Patient Additional Demographic" },
    { "PDA", "Patient Death and Autopsy" },
    { "PDC", "Product Detail Country" },
    { "PEO", "Product Experience Observation" },
    { "PES", "Product Experience Sender" },
    { "PID", "Patient Identification" },
    { "PKG", "Item Packaging" },
    { "PMT", "Payment Information" },
    { "PR1", "Procedures" },
    { "PRA", "Practitioner Detail" },
    { "PRB", "Problem Details" },
    { "PRC", "Pricing" },
    { "PRD", "Provider Data" },
    { "PSG", "Product/Service Group" },
    { "PSH", "Product Summary Header" },
    { "PSL", "Product/Service Line Item" },
    { "PSS", "Product/Service Section" },
    { "PTH", "Pathway" },
    { "PV1", "Patient Visit" },
    { "PV2", "Patient Visit - Additional Information" },
    { "PYE", "Payee Information" },
    { "QAK", "Query Acknowledgment" },
    { "QID", "Query Identification" },
    { "QPD", "Query Parameter Definition" },
    { "QRD", "Original-Style Query Definition" },
    { "QRF", "Original style query filter" },
    { "QRI", "Query Response Instance" },
    { "RCP", "Response Control Parameter" },
    { "RDF", "Table Row Definition" },
    { "RDT", "Table Row Data" },
    { "REL", "Clinical Relationship Segment" },
    { "RF1", "Referral Information" },
    { "RFI", "Request for Information" },
    { "RGS", "Resource Group" },
    { "RMI", "Risk Management Incident" },
    { "ROL", "Role" },
    { "RQ1", "Requisition Detail-1" },
    { "RQD", "Requisition Detail" },
    { "RXA", "Pharmacy/Treatment Administration" },
    { "RXC", "Pharmacy/Treatment Component Order" },
    { "RXD", "Pharmacy/Treatment Dispense" },
    { "RXE", "Pharmacy/Treatment Encoded Order" },
    { "RXG", "Pharmacy/Treatment Give" },
    { "RXO", "Pharmacy/Treatment Order" },
    { "RXR", "Pharmacy/Treatment Route" },
    { "SAC", "Specimen Container detail" },
    { "SCD", "Anti-Microbial Cycle Data" },
    { "SCH", "Scheduling Activity Information" },
    { "SCP", "Sterilizer Configuration Notification (Anti-Microbial Devices)" },
    { "SDD", "Sterilization Device Data" },
    { "SFT", "Software Segment" },
    { "SID", "Substance Identifier" },
    { "SLT", "Sterilization Lot" },
    { "SPM", "Specimen" },
    { "STF", "Staff Identification" },
    { "STZ", "Sterilization Parameter" },
    { "TCC", "Test Code Configuration" },
    { "TCD", "Test Code Detail" },
    { "TQ1", "Timing/Quantity" },
    { "TQ2", "Timing/Quantity Relationship" },
    { "TXA", "Transcription Document Header" },
    { "UAC", "User Authentication Credential Segment" },
    { "UB1", "UB82" },
    { "UB2", "UB92 Data" },
    { "URD", "Results/update Definition" },
    { "URS", "Unsolicited Selection" },
    { "VAR", "Variance" },
    { "VND", "Purchasing Vendor" },
    { NULL, NULL }
};

/* as per Health Level Seven, Version 2.6, appendix A */
static const string_string hl7_event_type_vals[] = {
    { "A01", "Admit/visit notification" },
    { "A02", "Transfer a patient" },
    { "A03", "Discharge/end visit" },
    { "A04", "Register a patient" },
    { "A05", "Pre-admit a patient" },
    { "A06", "Change an outpatient to an inpatient" },
    { "A07", "Change an inpatient to an outpatient" },
    { "A08", "Update patient information" },
    { "A09", "Patient departing - tracking" },
    { "A10", "Patient arriving - tracking" },
    { "A11", "Cancel admit/visit notification" },
    { "A12", "Cancel transfer" },
    { "A13", "Cancel discharge/end visit" },
    { "A14", "Pending admit" },
    { "A15", "Pending transfer" },
    { "A16", "Pending discharge" },
    { "A17", "Swap patients" },
    { "A18", "Merge patient information" },
    { "A19", "Patient query" },
    { "A20", "Bed status update" },
    { "A21", "Patient goes on a \"leave of absence\"" },
    { "A22", "Patient returns from a \"leave of absence\"" },
    { "A23", "Delete a patient record" },
    { "A24", "Link patient information" },
    { "A25", "Cancel pending discharge " },
    { "A26", "Cancel pending transfer" },
    { "A27", "Cancel pending admit" },
    { "A28", "Add person information" },
    { "A29", "Delete person information" },
    { "A30", "Merge person information" },
    { "A31", "Update person information" },
    { "A32", "Cancel patient arriving" },
    { "A33", "Cancel patient departing" },
    { "A34", "Merge patient information - patient ID only" },
    { "A35", "Merge patient information - account number only" },
    { "A36", "Merge patient information - patient ID and account number" },
    { "A37", "Unlink patient information" },
    { "A38", "Cancel pre-admit" },
    { "A39", "Merge person - patient ID" },
    { "A40", "Merge patient - patient identifier list" },
    { "A41", "Merge account - patient account number" },
    { "A42", "Merge visit - visit number" },
    { "A43", "Move patient information - patient identifier list" },
    { "A44", "Move account information - patient account number" },
    { "A45", "Move visit information - visit number" },
    { "A46", "Change patient ID" },
    { "A47", "Change patient identifier list" },
    { "A48", "Change alternate patient ID" },
    { "A49", "Change patient account number" },
    { "A50", "Change visit number" },
    { "A51", "Change alternate visit ID" },
    { "A52", "Cancel leave of absence for a patient" },
    { "A53", "Cancel patient returns from a leave of absence" },
    { "A54", "Change attending doctor" },
    { "A55", "Cancel change attending doctor" },
    { "A60", "Update allergy information" },
    { "A61", "Change consulting doctor" },
    { "A62", "Cancel change consulting doctor" },
    { "B01", "Add personnel record" },
    { "B02", "Update personnel record" },
    { "B03", "Delete personnel re cord" },
    { "B04", "Active practicing person" },
    { "B05", "Deactivate practicing person" },
    { "B06", "Terminate practicing person" },
    { "B07", "Grant Certificate/Permission" },
    { "B08", "Revoke Certificate/Permission" },
    { "C01", "Register a patient on a clinical trial" },
    { "C02", "Cancel a patient registration on clinical trial" },
    { "C03", "Correct/update registration information" },
    { "C04", "Patient has gone off a clinical trial" },
    { "C05", "Patient enters phase of clinical trial" },
    { "C06", "Cancel patient entering a phase" },
    { "C07", "Correct/update phase information" },
    { "C08", "Patient has gone off phase of clinical trial" },
    { "C09", "Automated time intervals for reporting" },
    { "C10", "Patient completes the clinical trial" },
    { "C11", "Patient completes a phase of the clinical trial" },
    { "C12", "Update/correction of patient order/result information" },
    { "E01", "Submit HealthCare Services Invoice" },
    { "E02", "Cancel HealthCare Services Invoice" },
    { "E03", "HealthCare Services Invoice Status" },
    { "E04", "Re-Assess HealthCare Services Invoice Request" },
    { "E10", "Edit/Adjudication Results" },
    { "E12", "Request Additional Information" },
    { "E13", "Additional Information Response" },
    { "E15", "Payment/Remittance Advice" },
    { "E20", "Submit Authorization Request" },
    { "E21", "Cancel Authorization Request" },
    { "E22", "Authorization Request Status" },
    { "E24", "Authorization Response " },
    { "E30", "Submit Health Document related to Authorization Request" },
    { "E31", "Cancel Health Document related to Authorization Request" },
    { "I01", "Request for insurance information" },
    { "I02", "Request/receipt of patient selection display list" },
    { "I03", "Request/receipt of patient selection list" },
    { "I04", "Request for patient demographic data" },
    { "I05", "Request for patient clinical information" },
    { "I06", "Request/receipt of clinical data listing" },
    { "I07", "Unsolicited insurance information" },
    { "I08", "Request for treatment authorization information" },
    { "I09", "Request for modification to an authorization" },
    { "I10", "Request for resubmission of an authorization" },
    { "I11", "Request for cancellation of an authorization" },
    { "I12", "Patient referral" },
    { "I13", "Modify patient referral" },
    { "I14", "Cancel patient referral" },
    { "I15", "Request patient referral status" },
    { "J01", "Cancel query/acknowledge message" },
    { "J02", "Cancel subscription/acknowledge message" },
    { "K11", "Segment pattern response in response to QBP^Q11" },
    { "K13", "Tabular response in response to QBP^Q13" },
    { "K15", "Display response in response to QBP^Q15" },
    { "K21", "Get person demographics response" },
    { "K22", "Find candidates response" },
    { "K23", "Get corresponding identifiers response" },
    { "K24", "Allocate identifiers response" },
    { "K25", "Personnel Information by Segment Response" },
    { "K31", "Dispense History Response" },
    { "M01", "Master file not otherwise specified" },
    { "M02", "Master file - staff practitioner " },
    { "M03", "Master file - test/observation" },
    { "M04", "Master files charge description" },
    { "M05", "Patient location master file" },
    { "M06", "Clinical study with phases and schedules master file" },
    { "M07", "Clinical study without phases but with schedules master file" },
    { "M08", "Test/observation (numeric) master file" },
    { "M09", "Test/observation (categorical) master file" },
    { "M10", "Test /observation batteries master file" },
    { "M11", "Test/calculated observations master file" },
    { "M12", "Master file notification message" },
    { "M13", "Master file notification - general" },
    { "M14", "Master file notification - site defined" },
    { "M15", "Inventory item master file notification" },
    { "M16", "Master File Notification Inventory Item Enhanced" },
    { "M17", "Master File Message" },
    { "N01", "Application management query message" },
    { "N02", "Application management data message (unsolicited)" },
    { "O01", "Order message" },
    { "O02", "Order response" },
    { "O03", "Diet order" },
    { "O04", "Diet order acknowledgment" },
    { "O05", "Stock requisition order" },
    { "O06", "Stock requisition acknowledgment" },
    { "O07", "Non-stock requisition order" },
    { "O08", "Non-stock requisition acknowledgment" },
    { "O09", "Pharmacy/treatment order" },
    { "O10", "Pharmacy/treatment order acknowledgment" },
    { "O11", "Pharmacy/treatment encoded order" },
    { "O12", "Pharmacy/treatment encoded order acknowledgment " },
    { "O13", "Pharmacy/treatment dispense" },
    { "O14", "Pharmacy/treatment dispense acknowledgment" },
    { "O15", "Pharmacy/treatment give" },
    { "O16", "Pharmacy/treatment give acknowledgment" },
    { "O17", "Pharmacy/treatment administration" },
    { "O18", "Pharmacy/treatment administration acknowledgment" },
    { "O19", "General clinical order" },
    { "O20", "General clinical order response" },
    { "O21", "Laboratory order" },
    { "O22", "General laboratory order response message to any OML" },
    { "O23", "Imaging order" },
    { "O24", "Imaging order response message to any OMI" },
    { "O25", "Pharmacy/treatment refill authorization request" },
    { "O26", "Pharmacy/Treatment Refill Authorization Acknowledgement" },
    { "O27", "Blood product order" },
    { "O28", "Blood product order acknowledgment" },
    { "O29", "Blood product dispense status" },
    { "O30", "Blood product dispense status acknowledgment" },
    { "O31", "Blood product transfusion/disposition" },
    { "O32", "Blood product transfusion/disposition acknowledgment" },
    { "O33", "Laboratory order for multiple orders related to a single specimen" },
    { "O34", "Laboratory order response message to a multiple order related to single specimen OML" },
    { "O35", "Laboratory order for multiple orders related to a single container of a specimen" },
    { "O36", "Laboratory order response message to a single container of a specimen OML" },
    { "O37", "Population/Location-Based Laboratory Order Message" },
    { "O38", "Population/Location-Based Laboratory Order Acknowledgment Message" },
    { "P01", "Add patient accounts" },
    { "P02", "Purge patient accounts" },
    { "P03", "Post detail financial transaction " },
    { "P04", "Generate bill and A/R statements" },
    { "P05", "Update account" },
    { "P06", "End account" },
    { "P07", "Unsolicited initial individual product experience report" },
    { "P08", "Unsolicited update individual product experience report" },
    { "P09", "Summary product experience report" },
    { "P10", "Transmit Ambulatory Payment Classification" },
    { "P11", "Post Detail Financial Transactions" },
    { "P12", "Update Diagnosis/Procedure" },
    { "PC1", "PC/problem add" },
    { "PC2", "PC/problem update" },
    { "PC3", "PC/problem delete" },
    { "PC4", "PC/problem query" },
    { "PC5", "PC/problem response" },
    { "PC6", "PC/goal add" },
    { "PC7", "PC/goal update" },
    { "PC8", "PC/goal delete" },
    { "PC9", "PC/goal query" },
    { "PCA", "PC/goal response" },
    { "PCB", "PC/pathway (problem-oriented) add" },
    { "PCC", "PC/pathway (problem-oriented) update" },
    { "PCD", "PC/pathway (problem-oriented) delete" },
    { "PCE", "PC/pathway (problem-oriented) query" },
    { "PCF", "PC/pathway (problem-oriented) query response" },
    { "PCG", "PC/pathway (goal-oriented) add" },
    { "PCH", "PC/pathway (goal-oriented) update" },
    { "PCJ", "PC/pathway (goal-oriented) delete" },
    { "PCK", "PC/pathway (goal-oriented) query" },
    { "PCL", "PC/pathway (goal-oriented) query response" },
    { "Q01", "Query sent for immediate response" },
    { "Q02", "Query sent for deferred response" },
    { "Q03", "Deferred response to a query" },
    { "Q05", "Unsolicited display update message" },
    { "Q06", "Query for order status" },
    { "Q11", "Query by parameter requesting an RSP segment pattern response" },
    { "Q13", "Query by parameter requesting an RTB tabular response" },
    { "Q15", "Query by parameter requesting an RDY display response" },
    { "Q16", "Create subscription" },
    { "Q17", "Query for previous events" },
    { "Q21", "Get person demographics" },
    { "Q22", "Find candidates" },
    { "Q23", "Get corresponding identifiers" },
    { "Q24", "Allocate identifiers" },
    { "Q25", "Personnel Information by Segment Query" },
    { "Q26", "Pharmacy/treatment order response" },
    { "Q27", "Pharmacy/treatment administration information" },
    { "Q28", "Pharmacy/treatment dispense information" },
    { "Q29", "Pharmacy/treatment encoded order information" },
    { "Q30", "Pharmacy/treatment dose information" },
    { "Q31", "Query Dispense history" },
    { "R01", "Unsolicited transmission of an observation message" },
    { "R02", "Query for results of observation" },
    { "R04", "Response to query; transmission of requested observation" },
    { "R21", "Unsolicited laboratory observation" },
    { "R22", "Unsolicited Specimen Oriented Observation Message" },
    { "R23", "Unsolicited Specimen Container Oriented Observation Message" },
    { "R24", "Unsolicited Order Oriented Observation Message" },
    { "R25", "Unsolicited Population/Location-Based Laboratory Observation Message" },
    { "R30", "Unsolicited Point-Of-Care Observation Message Without Existing Order - Place An Order" },
    { "R31", "Unsolicited New Point-Of-Care Observation Message - Search For An Order" },
    { "R32", "Unsolicited Pre-Ordered Point-Of-Care Observation" },
    { "ROR", "Pharmacy prescription order query response" },
    { "S01", "Request new appointment booking" },
    { "S02", "Request appointment rescheduling" },
    { "S03", "Request appointment modification" },
    { "S04", "Request appointment cancellation" },
    { "S05", "Request appointment discontinuation" },
    { "S06", "Request appointment deletion" },
    { "S07", "Request addition of service/resource on appointment" },
    { "S08", "Request modification of service/resource on appointment" },
    { "S09", "Request cancellation of service/resource on appointment" },
    { "S10", "Request discontinuation of service/resource on appointment" },
    { "S11", "Request deletion of service/resource on appointment" },
    { "S12", "Notification of new appointment booking" },
    { "S13", "Notification of appointment rescheduling" },
    { "S14", "Notification of appointment modification" },
    { "S15", "Notification of appointment cancellation" },
    { "S16", "Notification of appointment discontinuation" },
    { "S17", "Notification of appointment deletion" },
    { "S18", "Notification of addition of service/resource on appointment" },
    { "S19", "Notification of modification of service/resource on appointment" },
    { "S20", "Notification of cancellation of service/resource on appointment" },
    { "S21", "Notification of discontinuation of service/resource on appointment" },
    { "S22", "Notification of deletion of service/resource on appointment" },
    { "S23", "Notification of blocked schedule time slot(s)" },
    { "S24", "Notification of opened (\"unblocked\") schedule time slot(s)" },
    { "S25", "Schedule query message and response" },
    { "S26", "Notification that patient did not show up for schedule appointment" },
    { "S28", "Request new sterilization lot " },
    { "S29", "Request Sterilization lot deletion" },
    { "S30", "Request item" },
    { "S31", "Request anti-microbial device data" },
    { "S32", "Request anti-microbial device cycle data" },
    { "S33", "Notification of sterilization configuration" },
    { "S34", "Notification of sterilization lot" },
    { "S35", "Notification of sterilization lot deletion" },
    { "S36", "Notification of anti-microbial device data" },
    { "S37", "Notification of anti-microbial device cycle data" },
    { "T01", "Original document notification" },
    { "T02", "Original document notification and content" },
    { "T03", "Document status change notification" },
    { "T04", "Document status change notification and content" },
    { "T05", "Document addendum notification" },
    { "T06", "Document addendum notification and content" },
    { "T07", "Document edit notification" },
    { "T08", "Document edit notification and content" },
    { "T09", "Document replacement notification" },
    { "T10", "Document replacement notification and content" },
    { "T11", "Document cancel notification" },
    { "T12", "Document query" },
    { "U01", "Automated equipment status update" },
    { "U02", "Automated equipment status request" },
    { "U03", "Specimen status update" },
    { "U04", "specimen status request" },
    { "U05", "Automated equipment inventory update" },
    { "U06", "Automated equipment inventory request" },
    { "U07", "Automated equipment command" },
    { "U08", "Automated equipment response" },
    { "U09", "Automated equipment notification " },
    { "U10", "Automated equipment test code settings update" },
    { "U11", "Automated equipment test code settings request" },
    { "U12", "Automated equipment log/service update" },
    { "U13", "Automated equipment log/service request" },
    { "V01", "Query for vaccination record" },
    { "V02", "Response to vaccination query returning multiple PID matches" },
    { "V03", "Vaccination record response" },
    { "V04", "Unsolicited vaccination record update" },
    { "W01", "Waveform result, unsolicited transmission of requested information" },
    { "W02", "Waveform result, response to query " },
    { NULL, NULL }
};

static gboolean
event_present(const struct msh *msh) {
    return msh->trigger_event[0] == 0 ? FALSE : TRUE;
}

static int
parse_msh(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset,
          struct msh *msh)
{
    gint segment_len = -1;
    gint end_of_segment_offset = -1;
    gint field_separator_offset = -1;
    gint field_number = 0;

    /* initialize msh */
    msh->trigger_event[0] ='\0';
    msh->message_type[0] = '\0';

    /* e.g. MSH|^~\&|||||||XZY^IJK|||||||\r */
    field_number = 1;
    offset += 3; // skip 'MSH'
    msh->field_separator = tvb_get_guint8(tvb, offset);
    offset += 1;
    msh->component_separator = tvb_get_guint8(tvb, offset);
    offset += 1;
    msh->repetition_separator = tvb_get_guint8(tvb, offset);
    offset += 1;
    msh->escape_character = tvb_get_guint8(tvb, offset);
    offset += 1;
    msh->subcomponent_separator = tvb_get_guint8(tvb, offset);
    offset += 1;
    field_number++;

    /* FF: even if HL7 2.3.1 says each segment must be terminated with CR
     * we look either for a CR or an LF or both (I did find a system out
     * there that uses both) */
    segment_len = tvb_find_line_end(tvb, offset, -1, NULL, TRUE);
    if (segment_len == -1) {
        expert_add_info_format(pinfo, NULL, &ei_hl7_malformed,
                               "Segments must be terminated with CR");
        return -1;
    }
    end_of_segment_offset = offset + segment_len;

    while (offset < end_of_segment_offset) {
        field_separator_offset =
            tvb_find_guint8(tvb, offset, end_of_segment_offset - offset,
                            msh->field_separator);
        if (field_separator_offset == -1) {
            if (field_number < 9) {
                expert_add_info_format(pinfo, NULL, &ei_hl7_malformed,
                                       "MSH must have at least 9 fields");
                return -1;
            }
            return 0;
        }
        field_number++;
        offset = field_separator_offset + 1;
        if (tvb_get_guint8(tvb, offset) == msh->field_separator) {
            /* skip the empty field '||' */
            continue;
        }
        if (field_number == 9) { /* 9th field is the message type[^event] */
            msh->message_type[0] = tvb_get_guint8(tvb, offset);
            msh->message_type[1] = tvb_get_guint8(tvb, offset + 1);
            msh->message_type[2] = tvb_get_guint8(tvb, offset + 2);
            msh->message_type[3] = '\0';
            if (tree) {
                proto_item *hidden_item;
                hidden_item = proto_tree_add_item(tree, hf_hl7_message_type,
                                                  tvb, offset, 3,
                                                  ENC_ASCII|ENC_NA);
                proto_item_set_hidden(hidden_item);
            }
            if (tvb_get_guint8(tvb, offset + 3) == msh->component_separator) {
                msh->trigger_event[0] = tvb_get_guint8(tvb, offset + 4);
                msh->trigger_event[1] = tvb_get_guint8(tvb, offset + 5);
                msh->trigger_event[2] = tvb_get_guint8(tvb, offset + 6);
                msh->trigger_event[3] = '\0';
                if (tree) {
                    proto_item *hidden_item;
                    hidden_item = proto_tree_add_item(tree, hf_hl7_event_type,
                                                      tvb, offset + 4, 3,
                                                      ENC_ASCII|ENC_NA);
                    proto_item_set_hidden(hidden_item);
                }
            }
        }
    }
    return 0;
}

static void
dissect_hl7_segment(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_,
                    gint offset, gint segment_len, gint segment_len_crlf _U_,
                    const struct msh *msh _U_)
{
    /* segment layout xyz|a|b||||c|d\rxyz|a|b|c||||d... */
    proto_tree *segment_tree = NULL;
    proto_item *ti = NULL;
    char *field_str = NULL;
    gint end_of_segment_offset = 0;
    gint field_separator_offset = 0;
    gint field_num = 0;
    gint field_len = 0;
    gint segment_consumed = 0;
    gboolean last_field = FALSE;

    /* calculate where the segment ends */
    end_of_segment_offset = offset + segment_len;

    /* iterate over any fields */
    while (offset < end_of_segment_offset) {

        field_num++;

        /* get next '|' offset */
        field_separator_offset =
            tvb_find_guint8(tvb, offset,
                            segment_len - segment_consumed,
                            msh->field_separator);

        if (field_separator_offset == -1) {
            /* we do not have a field separator */
            if (segment_consumed != segment_len) {
                /* this is the last field */
                last_field = TRUE;
                field_len = segment_len - segment_consumed;
                segment_consumed += field_len + 1;
            } else {
                /* end of tvb or reached maxlen (i.e. end of segment) */
                return;
            }
        } else {
            /* we have a field separator */
            /* calc field length and the amount of segment data consumed */
            field_len = field_separator_offset - offset;
            segment_consumed += field_len + 1;
        }

        /* skip empty fields '||' */
        if (field_len == 0) {
            /* move the offset after the separator, pointing to the next field */
            offset = field_separator_offset + 1;
            continue;
        }

        /* process the field (the 1st one generate a node in the tree view) */
        if (field_num == 1) {
            char *segment_type_id = NULL;
            segment_type_id = tvb_get_string_enc(wmem_packet_scope(),
                                                 tvb, offset, 3, ENC_ASCII);
            ti = proto_tree_add_item(tree, hf_hl7_segment,
                                     tvb, offset, segment_len_crlf,
                                     ENC_ASCII|ENC_NA);
            proto_item_set_text(ti, "%s (%s)", segment_type_id,
                                str_to_str(segment_type_id, hl7_seg_type_vals,
                                           "Unknown Segment"));
            segment_tree = proto_item_add_subtree(ti, ett_hl7_segment);
            if (global_hl7_raw) {
                proto_tree_add_item(segment_tree, hf_hl7_raw_segment, tvb, offset,
                                    segment_len_crlf, ENC_ASCII|ENC_NA);
            }
        }
        field_str = tvb_get_string_enc(wmem_packet_scope(),
                                       tvb, offset, field_len, ENC_ASCII);
        ti = proto_tree_add_item(segment_tree, hf_hl7_field,
                                 tvb, offset, field_len, ENC_ASCII|ENC_NA);
        proto_item_set_text(ti, "field %d: %s", field_num, field_str);

        /* if this is the last field we are done */
        if (last_field) {
            return;
        }

        /* move the offset after the separator, pointing to the next field */
        offset = field_separator_offset + 1;
    }
}

static void
dissect_hl7_message(tvbuff_t *tvb, guint tvb_offset, gint len,
                    packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint offset = tvb_offset;
    guint sob_offset = offset;
    guint eob_offset = offset + len - 2;
    proto_tree *hl7_tree = NULL;
    proto_item *ti = NULL;
    struct msh msh;
    int ret = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HL7");
    col_clear(pinfo->cinfo, COL_INFO);

    ret = parse_msh(tvb, pinfo, tree, offset + 1, &msh);

    if (ret == -1)
        return;

    /* enrich info column */
    if (event_present(&msh)) {
        if (offset == 0) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s (%s)",
                            msh.message_type,
                            msh.trigger_event);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s (%s)",
                            msh.message_type,
                            msh.trigger_event);
        }
    } else {
        if (offset == 0) {
            col_append_str(pinfo->cinfo, COL_INFO,
                            msh.message_type);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                            msh.message_type);
        }
    }
    /* set a fence so that subsequent col_clear calls will
     * not wipe out col information regarding this PDU */
    col_set_fence(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_hl7, tvb, offset, len, ENC_NA);
    if (event_present(&msh)) {
        proto_item_append_text(ti, ", Type: %s, Event: %s",
                               str_to_str(msh.message_type,
                                          hl7_msg_type_vals, "Unknown"),
                               str_to_str(msh.trigger_event,
                                          hl7_event_type_vals, "Unknown"));
    } else {
        proto_item_append_text(ti, ", Type: %s",
                               str_to_str(msh.message_type,
                                          hl7_msg_type_vals, "Unknown"));
    }
    hl7_tree = proto_item_add_subtree(ti, ett_hl7);
    /* SOB */
    if (global_hl7_llp) {
        proto_tree_add_item(hl7_tree, hf_hl7_llp_sob, tvb, sob_offset, 1, ENC_NA);
    }
    offset++;
    if (global_hl7_raw) {
        proto_tree_add_item(hl7_tree, hf_hl7_raw, tvb, offset, len - 3,
                            ENC_ASCII|ENC_NA);
    }

    /* body */
    while (offset < eob_offset) {
        gint next_offset = -1;
        gint segment_len = -1;
        gint segment_len_crlf = -1;
        /* FF: even if HL7 2.3.1 says each segment must be terminated with CR
         * we look either for a CR or an LF or both (I did find a system out
         * there that uses both) */
        segment_len = tvb_find_line_end(tvb, offset, -1, &next_offset, TRUE);
        if (segment_len == -1) {
            expert_add_info_format(pinfo, NULL, &ei_hl7_malformed,
                                   "Segments must be terminated with CR");
            return;
        }
        segment_len_crlf = next_offset - offset;
        dissect_hl7_segment(tvb, pinfo, hl7_tree,
                            offset, segment_len, segment_len_crlf, &msh);
        offset += segment_len_crlf;
    }
    /* EOB */
    if (global_hl7_llp) {
        proto_tree_add_item(hl7_tree, hf_hl7_llp_eob, tvb, eob_offset, 2,
                            ENC_BIG_ENDIAN);
    }
}

static int
dissect_hl7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint offset = 0;

    while (offset < tvb_reported_length(tvb)) {
        gint available = tvb_reported_length_remaining(tvb, offset);
        gint llp_eob_offset = tvb_find_guint16(tvb, offset, offset + available, LLP_EOB);

        if (llp_eob_offset == -1) {
            /* we ran out of data: ask for more */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return (offset + available);
        }

        /* tvb_find_ utilities return the *start* of the signature, here we
         * take care of the LLP_EOB bytes */
        gint llp_block_len = llp_eob_offset - offset + 2;

        /* FF: nasty case, check whether the capture started after the SOB
         * transmission. If this is the case we display these trailing bytes
         * as 'Data' and we will dissect the next complete message.
         */
        if (tvb_get_guint8(tvb, 0) != LLP_SOB) {
            tvbuff_t *new_tvb = tvb_new_subset_remaining(tvb, offset);
            call_data_dissector(new_tvb, pinfo, tree);
            return (offset + available);
        }

        /* FF: ok we got a complete LLP block '0x0B HL7-message 0x1C 0x0D',
         * do the dissection */
        dissect_hl7_message(tvb, offset, llp_block_len, pinfo, tree, data);
        offset += (guint)llp_block_len;
    }

    /* if we get here, then the end of the tvb matched with the end of a
       HL7 message. Happy days. */
    return tvb_captured_length(tvb);
}

static gboolean
dissect_hl7_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    conversation_t *conversation = NULL;

    /* heuristic is based on first 5 bytes analisys, we assume
       0x0B + "MSH|" is good enough */
    if ((tvb_reported_length_remaining(tvb, 0) < 5) ||
        (tvb_get_guint8(tvb, 0) != LLP_SOB) ||
        (tvb_strncaseeql(tvb, 1, "MSH|", 4) != 0)) {
        return FALSE;
    }

    /* heuristic test passed, associate the non-heuristic port based
     * dissector function above with this flow for further processing,
     * the conversation framework will do the rest */
    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, hl7_handle);

    /* Note Well!
     * If this PDU is complete everything is fine, the engine will call
     * dissect_hl7() providing the same data we have in this tvb.
     * If the PDU is *not* complete - i.e. we have only the first
     * fragment in this tvb - then dissect_hl7() will get only the
     * next bytes, hence the first PDU will not be properly displayed.
     * To fix this case we need to tell the dissector engine that we
     * need more data (desegment_len = MORE) and that we want
     * to continue the next processing from the beginning of the PDU
     * (desegment_offset = 0) because we did not consume/dissect
     * anything in this cycle. */
    gint llp_eob_offset = tvb_find_guint16(tvb, 0, -1, LLP_EOB);

    if (llp_eob_offset == -1) {
        pinfo->desegment_offset = 0;
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
    }

    return TRUE;
}

void
proto_reg_handoff_hl7(void)
{
    /* register as heuristic dissector for TCP */
    hl7_heur_handle = create_dissector_handle(dissect_hl7_heur, proto_hl7);
    heur_dissector_add("tcp", dissect_hl7_heur, "HL7 over TCP",
                       "hl7_tcp", proto_hl7, HEURISTIC_ENABLE);

    /* register as normal dissector for TCP well-known port */
    hl7_handle = create_dissector_handle(dissect_hl7, proto_hl7);
    dissector_add_uint_with_preference("tcp.port", TCP_PORT_HL7, hl7_handle);
}

void
proto_register_hl7(void)
{
    static hf_register_info hl7f_info[] = {
        { &hf_hl7_raw,
          { "raw message", "hl7.raw", FT_STRING,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_hl7_llp_sob,
          { "LLP Start Of Block", "hl7.llp.sob", FT_UINT8,
            BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_hl7_llp_eob,
          { "LLP End Of Block", "hl7.llp.eob", FT_UINT16,
            BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_hl7_raw_segment,
          { "raw segment", "hl7.raw.segment", FT_STRING,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_hl7_segment,
          { "xyz", "hl7.segment", FT_STRING,
            BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hl7_message_type,
          { "xyz", "hl7.message.type", FT_STRING,
            BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hl7_event_type,
          { "xyz", "hl7.event.type", FT_STRING,
            BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hl7_field,
          { "xyz", "hl7.field", FT_STRING,
            BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_hl7,
        &ett_hl7_segment,
    };

    static ei_register_info ei[] = {
        { &ei_hl7_malformed, { "hl7.malformed", PI_MALFORMED, PI_WARN, "Malformed", EXPFILL }},
    };

    expert_module_t *expert_hl7 = NULL;
    module_t *hl7_module = NULL;

    proto_hl7 = proto_register_protocol("Health Level Seven", "HL7", "hl7");
    proto_register_field_array(proto_hl7, hl7f_info, array_length(hl7f_info));
    proto_register_subtree_array(ett, array_length(ett));
    expert_hl7 = expert_register_protocol(proto_hl7);
    expert_register_field_array(expert_hl7, ei, array_length(ei));
    hl7_module = prefs_register_protocol(proto_hl7, NULL);
    prefs_register_bool_preference(hl7_module, "display_raw",
                                   "Display raw text for HL7 message",
                                   "Specifies that the raw text of the "
                                   "HL7 message should be displayed "
                                   "in addition to the dissection tree",
                                   &global_hl7_raw);
    prefs_register_bool_preference(hl7_module, "display_llp",
                                   "Display LLP markers (Start/End Of Block)",
                                   "Specifies that the LLP session information "
                                   "should be displayed (Start/End Of Block) "
                                   "in addition to the dissection tree",
                                   &global_hl7_llp);
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
