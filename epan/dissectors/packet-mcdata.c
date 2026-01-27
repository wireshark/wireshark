/* packet-mcdata.c
 * Routines for MCData dissection.
 * 3GPP TS 24.282 V18.8.0 MCData
 *
 * TODO:
 *      Add support for OFF-NETWORK message and notification
 *      Add support for DEFERRED LIST ACCESS messages
 *      Add support for FD NETWORK NOTIFICATION message
 *      Add support for GROUP EMERGENCY ALERT messages
 *      Add support for COMMUNICATION RELEASE message
 *
 * Copyright 2026, Stefan Wenk
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <gmodule.h>

/* Protocol and Field Handles */
static int proto_mcdata = -1;
static int hf_mcdata_message_auth;
static int hf_mcdata_message_protected;
static int hf_mcdata_message_type;
static int hf_mcdata_num_payloads;
static int hf_mcdata_payload_len;
static int hf_mcdata_payload_cont_type;
static int hf_mcdata_payload_val_text;
static int hf_mcdata_payload_val_bytes;
static int hf_mcdata_status_val;
static int hf_mcdata_date_time;
static int hf_mcdata_conv_id;
static int hf_mcdata_message_id;
static int hf_mcdata_sds_disposition_req_iei;
static int hf_mcdata_sds_disposition_req_type;
static int hf_mcdata_fd_disposition_req_iei;
static int hf_mcdata_fd_disposition_req_type;
static int hf_mcdata_mandatory_download_iei;
static int hf_mcdata_mandatory_download_value;
static int hf_mcdata_general_iei;
static int hf_mcdata_in_reply_to_message_id;
static int hf_mcdata_application_id;
static int hf_mcdata_sds_disp_not_type;
static int hf_mcdata_fd_disp_not_type;
static int hf_mcdata_metadata;
static int hf_mcdata_ext_app_id_cont_type;
static int hf_mcdata_ext_app_id_data;
static int hf_mcdata_user_location;
static int hf_mcdata_org_name;
static int hf_mcdata_deffered_fd_sig_payload;
static int hf_mcdata_user_ID;
static int hf_mcdata_termination_info_type;
static int hf_mcdata_ext_response_type_iei;
static int hf_mcdata_ext_response_type_value;
static int hf_mcdata_release_response_type_iei;
static int hf_mcdata_release_response_type_val;
static int hf_mcdata_notification_type;
static int hf_mcdata_app_metadata_container;
static int hf_mcdata_group_id;

static int ett_mcdata   = -1;

static expert_field ei_malformed_length;

static ei_register_info expertitems[] = {
    {&ei_malformed_length, {"mcdata.malformed.length", PI_MALFORMED, PI_ERROR, "Malformed length", EXPFILL}},
};

// Table 15.2.2-1
static const value_string message_type_vals[] = {
    { 1,    "SDS SIGNALLING PAYLOAD" },
    { 2,    "FD SIGNALLING PAYLOAD" },
    { 3,    "DATA PAYLOAD" },
    { 5,    "SDS NOTIFICATION" },
    { 6,    "FD NOTIFICATION" },
    { 7,    "SDS OFF-NETWORK MESSAGE" },
    { 8,    "SDS OFF-NETWORK NOTIFICATION" },
    { 9,    "FD NETWORK NOTIFICATION" },
    { 10,   "COMMUNICATION RELEASE" },
    { 11,   "DEFERRED LIST ACCESS REQUEST" },
    { 12,   "DEFERRED LIST ACCESS RESPONSE" },
    { 13,   "FD HTTP TERMINATION" },
    { 17,   "GROUP EMERGENCY ALERT" },
    { 18,   "GROUP EMERGENCY ALERT ACK" },
    { 19,   "GROUP EMERGENCY ALERT CANCEL" },
    { 20,   "GROUP EMERGENCY ALERT CANCEL ACK" },
    { 0, NULL }
};

//
static const value_string payload_content_type_vals[] = {
    { 1,    "TEXT" },
    { 2,    "BINARY" },
    { 3,    "HYPERLINKS" },
    { 4,    "FILEURL" },
    { 5,    "LOCATION" },
    { 6,    "ENHANCED STATUS" },
    { 7,    "Value allocated for use in interworking" },
    { 8,    "LOCATION ALTITUDE" },
    { 9,    "LOCATION TIMESTAMP" },
    { 10,   "CODED TEXT" },
    { 0, NULL }
};

// Table 15.2.3-1
static const value_string sds_disposition_req_type_vals[] = {
    { 1,    "DELIVERY" },
    { 2,    "READ" },
    { 3,    "DELIVERY AND READ" },
    { 0, NULL }
};

// Table 15.2.4-1
static const value_string fd_disposition_req_type_vals[] = {
    { 1,    "FILE DOWNLOAD COMPLETED UPDATE" },
    { 0, NULL }
};

// Table 15.2.16-1
static const value_string mand_download_vals[] = {
    { 1,    "MANDATORY DOWNLOAD" },
    { 0, NULL }
};

// Table 15.2.24-2
static const value_string ext_app_id_content_type_vals[] = {
    { 1,    "TEXT" },
    { 2,    "URI" },
    { 0, NULL }
};

static const value_string mcdata_general_iei_vals[] = {
    // TV IEIs
    { 0x21,    "InReplyTo message ID" },
    { 0x22,    "Application ID" },
    { 0x51,    "Sender MCData user ID" },
    { 0x52,    "Deferred FD signalling payload" },
    { 0x53,    "Application metadata container" },
    // TLV IEIs
    { 0x78,    "Payload" },
    { 0x79,    "Metadata" },
    { 0x7B,    "MCData group ID" },
    { 0x7C,    "Recipient MCData user ID" },
    { 0x7D,    "Extended application ID" },
    { 0x7E,    "User location" },
    { 0x7F,    "Organization name" },
    { 0, NULL }
};

static const value_string application_id_value_vals[] = {
    { 1,    "BROADBAND CALLOUT" },
    { 0, NULL }
};

// Table 15.2.5-1
static const value_string sds_disp_not_type_vals[] = {
    { 1,    "UNDELIVERED" },
    { 2,    "DELIVERED" },
    { 3,    "READ" },
    { 4,    "DELIVERED AND READ" },
    { 5,    "DISPOSITION  PREVENTED BY SYSTEM" },
    { 0, NULL }
};

// Table 15.2.6-1
static const value_string fd_disp_not_type_vals[] = {
    { 1,    "FILE DOWNLOAD REQUEST ACCEPTED" },
    { 2,    "FILE DOWNLOAD REQUEST REJECTED" },
    { 3,    "FILE DOWNLOAD COMPLETED" },
    { 4,    "FILE DOWNLOAD DEFERRED" },
    { 0, NULL }
};

// Table 15.2.22-1
static const value_string term_info_type_vals[] = {
    { 1,    "TERMINATION REQUEST" },
    { 2,    "TERMINATION RESPONSE" },
    { 3,    "TRANSMISSION STOPPED" },
    { 4,    "INTENT TO RELEASE COMM OVER HTTP" },
    { 5,    "EXTENSION REQUEST FOR COMM OVER HTTP" },
    { 6,    "EXTENSION RESPONSE FOR COMM OVER HTTP" },
    { 7,    "AUTH USER TERMINATION REQUEST FOR COMM OVER HTTP" },
    { 0, NULL }
};

// Table 15.2.21-1
static const value_string ext_respone_type_value_vals[] = {
    { 1,    "ACCEPTED" },
    { 2,    "REJECTED" },
    { 0, NULL }
};

// Table 15.2.23-1
static const value_string rel_respone_type_vals[] = {
    { 1,    "RELEASE SUCCESS" },
    { 2,    "RELEASE FAILED" },
    { 0, NULL }
};

// Table 15.2.18-1
static const value_string notification_type_vals[] = {
    { 1,    "FILE EXPIRED UNAVAILABLE TO DOWNLOAD" },
    { 2,    "FILE DELETED UNAVAILABLE TO DOWNLOAD" },
    { 0, NULL }
};


static unsigned dissect_payload(unsigned offset, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    uint16_t len;
    proto_tree_add_item_ret_uint16(tree, hf_mcdata_payload_len,  tvb, offset, 2, ENC_BIG_ENDIAN, &len);
    offset += 2;
    if ((tvb_reported_length_remaining(tvb, offset) < len) || len < 1) {
        expert_add_info(pinfo, tree, &ei_malformed_length);
        return len;
    }
    uint8_t payload_cont_type;
    proto_tree_add_item_ret_uint8(tree, hf_mcdata_payload_cont_type, tvb, offset, 1, ENC_BIG_ENDIAN, &payload_cont_type);
    offset += 1;
    switch (payload_cont_type) {
        case 1:  // TEXT
        case 3:  // HYPERLINKS
        case 4:  // FILEURL
        case 10: // CODED TEXT
            proto_tree_add_item(tree, hf_mcdata_payload_val_text,  tvb, offset, len - 1, ENC_UTF_8);
            break;
        case 6:  // ENHANCED STATUS
            proto_tree_add_item(tree, hf_mcdata_status_val,  tvb, offset, 2, ENC_BIG_ENDIAN);
            break;
        case 7:  // Value allocated for use in interworking
            //Todo: Usage of this value is described in 3GPP TS 29.582
            proto_tree_add_item(tree, hf_mcdata_payload_val_bytes,  tvb, offset, len - 1, ENC_NA);
            break;
        case 8:  // LOCATION ALTITUDE
            //Todo: The length of the location altitude payload content is 2 bytes coded as in clause 6.3 in 3GPP TS 23.032
            proto_tree_add_item(tree, hf_mcdata_payload_val_bytes,  tvb, offset, len - 1, ENC_NA);
            break;
        case 9:  // LOCATION TIMESTAMP
            //Todo: The length of location timestamp is contained as a binary value in the first octet of the payload
            proto_tree_add_item(tree, hf_mcdata_payload_val_bytes,  tvb, offset, len - 1, ENC_NA);
            break;
        default:
            proto_tree_add_item(tree, hf_mcdata_payload_val_bytes,  tvb, offset, len - 1, ENC_NA);
            break;
    }
    return len + 2;
}

static int dissect_signalling_payload(uint8_t message_type, tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree, unsigned decoded_len ) {
    unsigned offset = 0;

    proto_tree_add_item(tree, hf_mcdata_message_auth, tvb,  offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mcdata_message_protected, tvb,  offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mcdata_message_type, tvb,  offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (message_type == 5){ // SDS NOTIFICATION
        proto_tree_add_item(tree, hf_mcdata_sds_disp_not_type, tvb,  offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
    if (message_type == 6) { // FD NOTIFICATION
        proto_tree_add_item(tree, hf_mcdata_fd_disp_not_type, tvb,  offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
    if (message_type == 9) { // FD NETWORK NOTIFICATION
        proto_tree_add_item(tree, hf_mcdata_notification_type, tvb,  offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
    if (message_type !=13 ) { // FD HTTP TERMINATION
        proto_tree_add_item(tree, hf_mcdata_date_time, tvb, offset, 5, ENC_TIME_SECS|ENC_BIG_ENDIAN);
        offset += 5;
    }
    proto_tree_add_item(tree, hf_mcdata_conv_id,  tvb, offset, FT_GUID_LEN, ENC_BIG_ENDIAN);
    offset += FT_GUID_LEN;
    proto_tree_add_item(tree, hf_mcdata_message_id,  tvb, offset, FT_GUID_LEN, ENC_BIG_ENDIAN);
    offset += FT_GUID_LEN;
    if (message_type ==13 ) { // FD HTTP TERMINATION
        proto_tree_add_item(tree, hf_mcdata_termination_info_type, tvb,  offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    while (offset < decoded_len) {
        unsigned iei = tvb_get_uint8(tvb, offset);
        if ((iei & 0xF0) == 0x80) {  // SDS disposition request type
            proto_tree_add_item(tree, hf_mcdata_sds_disposition_req_iei,  tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mcdata_sds_disposition_req_type,  tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else if ((iei & 0xF0) == 0x90) {  // FD disposition request type
            proto_tree_add_item(tree, hf_mcdata_fd_disposition_req_iei,  tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mcdata_fd_disposition_req_type,  tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else if ((iei & 0xF0) == 0xA0) {  // Mandatory download
            proto_tree_add_item(tree, hf_mcdata_mandatory_download_iei,  tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mcdata_mandatory_download_value,  tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else if ((iei & 0xF0) == 0xC0) {  // Extension Response Type
            proto_tree_add_item(tree, hf_mcdata_ext_response_type_iei,  tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mcdata_ext_response_type_value,  tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else if ((iei & 0xF0) == 0xD0) {  // Release Response Type
            proto_tree_add_item(tree, hf_mcdata_release_response_type_iei,  tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mcdata_release_response_type_val,  tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else {
            proto_tree_add_item(tree, hf_mcdata_general_iei,  tvb, offset, 1, ENC_NA);
            offset += 1;
            uint16_t len;
            switch (iei) {
                case 0x21:  {  // InReplyTo message ID
                    proto_tree_add_item(tree, hf_mcdata_in_reply_to_message_id, tvb, offset, FT_GUID_LEN, ENC_BIG_ENDIAN);
                    offset += FT_GUID_LEN;
                    break;
                }
                case 0x22:  {  // Application ID
                    proto_tree_add_item(tree, hf_mcdata_application_id, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    break;
                }
                case 0x51:  {  // Sender MCData user ID
                    proto_tree_add_item_ret_uint16 (tree, hf_mcdata_payload_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len) ;
                    if (tvb_reported_length_remaining(tvb, offset + 2) < (unsigned) len) {
                        expert_add_info(pinfo, tree, &ei_malformed_length);
                        return len;
                    }
                    proto_tree_add_item(tree, hf_mcdata_user_ID,  tvb, offset + 2, len , ENC_UTF_8);
                    offset += len + 2;
                    break;
                }
                case 0x52:  {  // Deferred FD signalling payload
                    proto_tree_add_item_ret_uint16 (tree, hf_mcdata_payload_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
                    if (tvb_reported_length_remaining(tvb, offset + 2) < (unsigned) len) {
                        expert_add_info(pinfo, tree, &ei_malformed_length);
                        return len;
                    }
                    proto_tree_add_item(tree, hf_mcdata_deffered_fd_sig_payload,  tvb, offset + 2, len , ENC_NA);
                    offset += len + 2;
                    break;
                }
                case 0x53:  {  // Application metadata container
                    proto_tree_add_item_ret_uint16 (tree, hf_mcdata_payload_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
                    if (tvb_reported_length_remaining(tvb, offset + 2) < (unsigned) len) {
                        expert_add_info(pinfo, tree, &ei_malformed_length);
                        return len;
                    }
                    proto_tree_add_item(tree, hf_mcdata_app_metadata_container,  tvb, offset + 2, len , ENC_UTF_8);
                    offset += len + 2;
                    break;
                }
                case 0x78:  {  // Payload
                    offset += dissect_payload(offset, tvb, pinfo, tree);
                    break;
                }
                case 0x79:  {  // Metadata
                    proto_tree_add_item_ret_uint16 (tree, hf_mcdata_payload_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
                    if (tvb_reported_length_remaining(tvb, offset + 2) < (unsigned) len) {
                        expert_add_info(pinfo, tree, &ei_malformed_length);
                        return len;
                    }
                    proto_tree_add_item(tree, hf_mcdata_metadata,  tvb, offset + 2, len , ENC_UTF_8);
                    offset += len + 2;
                    break;
                }
                case 0x7B:  {  // MCData group ID
                    proto_tree_add_item_ret_uint16 (tree, hf_mcdata_payload_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
                    if (tvb_reported_length_remaining(tvb, offset + 2) < (unsigned) len) {
                        expert_add_info(pinfo, tree, &ei_malformed_length);
                        return len;
                    }
                    proto_tree_add_item(tree, hf_mcdata_group_id,  tvb, offset + 2, len , ENC_NA);
                    offset += len + 2;
                    break;
                }
                case 0x7C:  {  // Recipient MCData user ID
                    proto_tree_add_item_ret_uint16 (tree, hf_mcdata_payload_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
                    if (tvb_reported_length_remaining(tvb, offset + 2) < (unsigned) len) {
                        expert_add_info(pinfo, tree, &ei_malformed_length);
                        return len;
                    }
                    proto_tree_add_item(tree, hf_mcdata_user_ID,  tvb, offset + 2, len , ENC_UTF_8);
                    offset += len + 2;
                    break;
                }
                case 0x7D:  {  // Extended application ID
                    proto_tree_add_item_ret_uint16 (tree, hf_mcdata_payload_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
                    if (tvb_reported_length_remaining(tvb, offset + 3) < (unsigned) len) {
                        expert_add_info(pinfo, tree, &ei_malformed_length);
                        return len;
                    }
                    proto_tree_add_item(tree, hf_mcdata_ext_app_id_cont_type, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_mcdata_ext_app_id_data, tvb, offset + 3, len - 1, ENC_UTF_8);
                    offset += len + 3;
                    break;
                }
                case 0x7E:  {  // User location
                    proto_tree_add_item_ret_uint16 (tree, hf_mcdata_payload_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
                    if (tvb_reported_length_remaining(tvb, offset + 2) < (unsigned) len) {
                        expert_add_info(pinfo, tree, &ei_malformed_length);
                        return len;
                    }
                    // Todo: The User location information element contains the LocationInfo structure defined in clause 7.4 of 3GPP TS 29.199-09
                    proto_tree_add_item(tree, hf_mcdata_user_location, tvb, offset + 2, len , ENC_NA);
                    offset += len + 2;
                    break;
                }
                case 0x7F:  {  // Organization name
                    proto_tree_add_item_ret_uint16 (tree, hf_mcdata_payload_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
                    if (tvb_reported_length_remaining(tvb, offset + 2) < (unsigned) len) {
                        expert_add_info(pinfo, tree, &ei_malformed_length);
                        return len;
                    }
                    proto_tree_add_item(tree, hf_mcdata_org_name,  tvb, offset + 2, len , ENC_UTF_8);
                    offset += len + 2;
                    break;
                }
            }
        }

    }

    return offset;
}

/* Dissector Implementation */
static int dissect_mcdata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    unsigned offset = 0;
    unsigned decoded_len = tvb_captured_length(tvb);
    uint8_t message_type = tvb_get_uint8(tvb, offset) & 0x3F;

    add_new_data_source(pinfo, tvb, "MCData");
    proto_item *ti = proto_tree_add_item(tree, proto_mcdata, tvb, 0, -1, ENC_NA);
    proto_tree *mcdata_tree = proto_item_add_subtree(ti, ett_mcdata);

    switch (message_type) {
        case 1: // SDS SIGNALLING PAYLOAD
            col_append_str(pinfo->cinfo, COL_INFO, "| SDS Signalling Payload");
            offset += dissect_signalling_payload(message_type, tvb, pinfo, mcdata_tree, decoded_len);
            break;
        case 2: // FD SIGNALLING PAYLOAD
            col_append_str(pinfo->cinfo, COL_INFO, "| FD Signalling Payload");
            offset += dissect_signalling_payload(message_type, tvb, pinfo, mcdata_tree, decoded_len);
            break;
        case 3: // DATA PAYLOAD
            col_append_str(pinfo->cinfo, COL_INFO, "| Data Payload");
            proto_tree_add_item(mcdata_tree, hf_mcdata_message_auth, tvb,  offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mcdata_tree, hf_mcdata_message_protected, tvb,  offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mcdata_tree, hf_mcdata_message_type, tvb,  offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(mcdata_tree, hf_mcdata_num_payloads, tvb,  offset, 1, ENC_BIG_ENDIAN);
            uint8_t num_payload = tvb_get_uint8(tvb, offset);
            offset += 1;
            for (uint8_t i=1; i<=num_payload; i++)  {
               proto_tree_add_item(mcdata_tree, hf_mcdata_general_iei,  tvb, offset, 1, ENC_NA);
               offset += 1;
               offset += dissect_payload(offset, tvb, pinfo, mcdata_tree);
            }
            break;
        case 5: // SDS NOTIFICATION
            col_append_str(pinfo->cinfo, COL_INFO, "| SDS Notification");
            offset += dissect_signalling_payload(message_type, tvb, pinfo, mcdata_tree, decoded_len);
            break;
        case 6: // FD NOTIFICATION
            col_append_str(pinfo->cinfo, COL_INFO, "| FD Notification");
            offset += dissect_signalling_payload(message_type, tvb, pinfo, mcdata_tree, decoded_len);
            break;
        case 7: // SDS OFF-NETWORK MESSAGE
            col_append_str(pinfo->cinfo, COL_INFO, "| SDS Off-Network Message");
            break;
        case 8: // SDS OFF-NETWORK NOTIFICATION
            col_append_str(pinfo->cinfo, COL_INFO, "| SDS Off-Network Notification");
            break;
        case 9: // FD NETWORK NOTIFICATION
            col_append_str(pinfo->cinfo, COL_INFO, "| FD Network Notification");
            offset += dissect_signalling_payload(message_type, tvb, pinfo, mcdata_tree, decoded_len);
            break;
        case 10: // COMMUNICATION RELEASE
            col_append_str(pinfo->cinfo, COL_INFO, "| Communication Release");
            break;
        case 11: // DEFERRED LIST ACCESS REQUEST
            col_append_str(pinfo->cinfo, COL_INFO, "| Deferred list access request");
            break;
        case 12:  // DEFERRED LIST ACCESS RESPONSE
            col_append_str(pinfo->cinfo, COL_INFO, "| Deferred list access response");
            break;
        case 13: // FD HTTP TERMINATION
            col_append_str(pinfo->cinfo, COL_INFO, "| FD HTTP termination");
            offset += dissect_signalling_payload(message_type, tvb, pinfo, mcdata_tree, decoded_len);
            break;
        case 17: // GROUP EMERGENCY ALERT
            col_append_str(pinfo->cinfo, COL_INFO, "| Group emergency alert");
            break;
        case 18: // GROUP EMERGENCY ALERT ACK
            col_append_str(pinfo->cinfo, COL_INFO, "| Group emergency alert ack");
            break;
        case 19: // GROUP EMERGENCY ALERT CANCEL
            col_append_str(pinfo->cinfo, COL_INFO, "| Group emergency alert cancel");
            break;
        case 20: // GROUP EMERGENCY ALERT CANCEL ACK
            col_append_str(pinfo->cinfo, COL_INFO, "| Group emergency alert cancel ack");
            break;
        default:
            col_append_str(pinfo->cinfo, COL_INFO, "| Unknown Message Type");
            break;
    }

    return tvb_captured_length(tvb);
}

/* Registration */
void proto_register_mcdata(void) {
    static hf_register_info hf[] = {
        { &hf_mcdata_message_auth,              { "Message authenticated", "mcdata.message.authenticated", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
        { &hf_mcdata_message_protected,         { "Message protected", "mcdata.message.protected", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
        { &hf_mcdata_message_type,              { "Message type", "mcdata.message.type", FT_UINT8, BASE_DEC, VALS(message_type_vals), 0x3F, NULL, HFILL }},
        { &hf_mcdata_num_payloads,              { "Number of payloads", "mcdata.pl.num.payloads",  FT_UINT8, BASE_DEC,  NULL, 0x0, NULL, HFILL }},
        { &hf_mcdata_payload_len,               { "Payload length", "mcdata.pl.payload.len",  FT_UINT16, BASE_DEC,  NULL, 0x0, NULL, HFILL }},
        { &hf_mcdata_payload_cont_type,         { "Payload content type", "mcdata.pl.payload.content.type",  FT_UINT8, BASE_DEC,  VALS(payload_content_type_vals), 0x0, NULL, HFILL }},
        { &hf_mcdata_payload_val_text,          { "Payload text value",  "mcdata.pl.payload.text.val",  FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mcdata_payload_val_bytes,         { "Payload value",  "mcdata.pl.payload.val", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mcdata_status_val,                { "Enhanced status value", "mcdata.pl.status.val",  FT_UINT16, BASE_DEC,  NULL, 0x0, NULL, HFILL }},
        { &hf_mcdata_date_time,                 { "Date and time", "mcdata.sig.date.and.time",   FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,NULL, HFILL }},
        { &hf_mcdata_conv_id,                   { "Conversation ID", "mcdata.sig.conv.id",   FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mcdata_message_id,                { "Message ID", "mcdata.sig.message.id",   FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mcdata_sds_disposition_req_iei,   { "SDS disposition request IEI", "mcdata.sig.sds.disp.req.iei", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }},
        { &hf_mcdata_sds_disposition_req_type,  { "SDS disposition request type", "mcdata.sig.sds.disp.req.type", FT_UINT8, BASE_DEC, VALS(sds_disposition_req_type_vals), 0x0F, NULL, HFILL }},
        { &hf_mcdata_fd_disposition_req_iei,    { "FD disposition request IEI", "mcdata.sig.fd.disp.req.iei", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }},
        { &hf_mcdata_fd_disposition_req_type,   { "FD disposition request type", "mcdata.sig.fd.disp.req.type", FT_UINT8, BASE_DEC, VALS(fd_disposition_req_type_vals), 0x0F, NULL, HFILL }},
        { &hf_mcdata_mandatory_download_iei,    { "Mandatory download IEI", "mcdata.sig.mand.download.iei", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }},
        { &hf_mcdata_mandatory_download_value,  { "Mandatory download value", "mcdata.sig.mand.download.value", FT_UINT8, BASE_DEC, VALS(mand_download_vals), 0x0F, NULL, HFILL }},
        { &hf_mcdata_general_iei,               { "MCData general IEI", "mcdata.general.iei", FT_UINT8, BASE_HEX, VALS(mcdata_general_iei_vals), 0x0, NULL, HFILL }},
        { &hf_mcdata_in_reply_to_message_id,    { "In reply to message ID", "mcdata.sig.in.reply.to.message.id",   FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mcdata_application_id,            { "Application ID value", "mcdata.sig.appl.id.value", FT_UINT8, BASE_DEC, VALS(application_id_value_vals), 0x0, NULL, HFILL }},
        { &hf_mcdata_sds_disp_not_type,         { "SDS disposition notification type", "mcdata.sig.sds.disp.not.type", FT_UINT8, BASE_DEC, VALS(sds_disp_not_type_vals), 0, NULL, HFILL }},
        { &hf_mcdata_fd_disp_not_type,          { "FD disposition notification type", "mcdata.sig.fd.disp.not.type", FT_UINT8, BASE_DEC, VALS(fd_disp_not_type_vals), 0, NULL, HFILL }},
        { &hf_mcdata_metadata,                  { "Metadata",  "mcdata.sig.metadata",  FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mcdata_ext_app_id_cont_type,      { "Extended application id content type", "mcdata.sig.ext.app.id.cont.type", FT_UINT8, BASE_HEX, VALS(ext_app_id_content_type_vals), 0x0, NULL, HFILL }},
        { &hf_mcdata_ext_app_id_data,           { "Extended application id data", "mcdata.sig.ext.app.id.data", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mcdata_user_location,             { "User location", "mcdata.sig.user.location",   FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mcdata_org_name,                  { "Organization name",  "mcdata.org.name",  FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mcdata_deffered_fd_sig_payload,   { "Deferred FD signalling payload", "mcdata.sig.def.fd.sig.payload",   FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mcdata_user_ID,                   { "MCData user ID", "mcdata.sig.user.id",   FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mcdata_termination_info_type,     { "Termination information type", "mcdata.sig.term.info.type", FT_UINT8, BASE_DEC, VALS(term_info_type_vals), 0, NULL, HFILL }},
        { &hf_mcdata_ext_response_type_iei,     { "Extension response type IEI", "mcdata.sig.ext.resp.type.iei", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }},
        { &hf_mcdata_ext_response_type_value,   { "Extension response type value", "mcdata.sig.ext.resp.type.value", FT_UINT8, BASE_HEX, VALS(ext_respone_type_value_vals), 0xF0, NULL, HFILL }},
        { &hf_mcdata_release_response_type_iei, { "Release response type IEI", "mcdata.sig.rel.resp.type.iei", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }},
        { &hf_mcdata_release_response_type_val, { "Release response type value", "mcdata.sig.rel.resp.type.value", FT_UINT8, BASE_HEX, VALS(rel_respone_type_vals), 0xF0, NULL, HFILL }},
        { &hf_mcdata_notification_type,         { "Notification type", "mcdata.sig.notification.type", FT_UINT8, BASE_DEC, VALS(notification_type_vals), 0, NULL, HFILL }},
        { &hf_mcdata_app_metadata_container,    { "Application metadata container",  "mcdata.sig.metadata.container",  FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mcdata_group_id,                  { "MCData group id", "mcdata.sig.mcdata.group.id",   FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };
    static int *ett[] = { &ett_mcdata };

    proto_mcdata = proto_register_protocol("Mission critical data", "MCData", "mcdata");
    proto_register_field_array(proto_mcdata, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t *expert = expert_register_protocol(proto_mcdata);
    expert_register_field_array(expert, expertitems, array_length(expertitems));

}

void proto_reg_handoff_mcdata(void) {
    static dissector_handle_t mcdata_handle;
    mcdata_handle = create_dissector_handle(dissect_mcdata, proto_mcdata);
    dissector_add_string("media_type", "application/vnd.3gpp.mcdata-payload", mcdata_handle);
    dissector_add_string("media_type", "application/vnd.3gpp.mcdata-signalling", mcdata_handle);
    // The protocol never appears on top of UDP in the wild, but we allow it for testing purposes using "Decode As":
    dissector_add_for_decode_as_with_preference("udp.port", mcdata_handle);
}
