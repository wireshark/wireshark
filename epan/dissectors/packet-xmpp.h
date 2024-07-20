/* packet-xmpp.h
 *
 * Copyright 2011, Mariusz Okroj <okrojmariusz[]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_XMPP_H
#define PACKET_XMPP_H

#include <epan/expert.h>

#define ETT_UNKNOWN_LEN 20

/*#define XMPP_DEBUG*/

extern int proto_xmpp;

extern int hf_xmpp_xmlns;
extern int hf_xmpp_id;
extern int hf_xmpp_from;
extern int hf_xmpp_to;
extern int hf_xmpp_type;
extern int hf_xmpp_cdata;
extern int hf_xmpp_attribute;

extern int hf_xmpp_iq;


extern int hf_xmpp_query;
extern int hf_xmpp_query_node;

extern int hf_xmpp_query_item;
extern int hf_xmpp_query_item_jid;
extern int hf_xmpp_query_item_name;
extern int hf_xmpp_query_item_subscription;
extern int hf_xmpp_query_item_ask;
extern int hf_xmpp_query_item_group;
extern int hf_xmpp_query_item_node;
extern int hf_xmpp_query_item_approved;

extern int hf_xmpp_query_identity;
extern int hf_xmpp_query_identity_category;
extern int hf_xmpp_query_identity_type;
extern int hf_xmpp_query_identity_name;

extern int hf_xmpp_query_feature;

extern int hf_xmpp_query_streamhost;
extern int hf_xmpp_query_streamhost_used;
extern int hf_xmpp_query_activate;
extern int hf_xmpp_query_udpsuccess;

extern int hf_xmpp_error;
extern int hf_xmpp_error_type;
extern int hf_xmpp_error_code;
extern int hf_xmpp_error_condition;
extern int hf_xmpp_error_text;

extern int hf_xmpp_iq_bind;
extern int hf_xmpp_iq_bind_jid;
extern int hf_xmpp_iq_bind_resource;

extern int hf_xmpp_services;
extern int hf_xmpp_channel;

extern int hf_xmpp_iq_session;
extern int hf_xmpp_features;

extern int hf_xmpp_vcard;
extern int hf_xmpp_vcard_x_update;


extern int hf_xmpp_jingle;
extern int hf_xmpp_jingle_sid;
extern int hf_xmpp_jingle_initiator;
extern int hf_xmpp_jingle_responder;
extern int hf_xmpp_jingle_action;

extern int hf_xmpp_jingle_content;
extern int hf_xmpp_jingle_content_creator;
extern int hf_xmpp_jingle_content_name;
extern int hf_xmpp_jingle_content_disposition;
extern int hf_xmpp_jingle_content_senders;

extern int hf_xmpp_jingle_content_description;
extern int hf_xmpp_jingle_content_description_media;
extern int hf_xmpp_jingle_content_description_ssrc;

extern int hf_xmpp_jingle_cont_desc_payload;
extern int hf_xmpp_jingle_cont_desc_payload_id;
extern int hf_xmpp_jingle_cont_desc_payload_channels;
extern int hf_xmpp_jingle_cont_desc_payload_clockrate;
extern int hf_xmpp_jingle_cont_desc_payload_maxptime;
extern int hf_xmpp_jingle_cont_desc_payload_name;
extern int hf_xmpp_jingle_cont_desc_payload_ptime;

extern int hf_xmpp_jingle_cont_desc_payload_param;
extern int hf_xmpp_jingle_cont_desc_payload_param_value;
extern int hf_xmpp_jingle_cont_desc_payload_param_name;

extern int hf_xmpp_jingle_cont_desc_enc;
extern int hf_xmpp_jingle_cont_desc_enc_zrtp_hash;
extern int hf_xmpp_jingle_cont_desc_enc_crypto;

extern int hf_xmpp_jingle_cont_desc_rtp_hdr;
extern int hf_xmpp_jingle_cont_desc_bandwidth;

extern int hf_xmpp_jingle_cont_trans;
extern int hf_xmpp_jingle_cont_trans_pwd;
extern int hf_xmpp_jingle_cont_trans_ufrag;

extern int hf_xmpp_jingle_cont_trans_cand;
extern int hf_xmpp_jingle_cont_trans_rem_cand;

extern int hf_xmpp_jingle_cont_trans_activated;
extern int hf_xmpp_jingle_cont_trans_candidate_used;
extern int hf_xmpp_jingle_cont_trans_candidate_error;
extern int hf_xmpp_jingle_cont_trans_proxy_error;

extern int hf_xmpp_jingle_reason;
extern int hf_xmpp_jingle_reason_condition;
extern int hf_xmpp_jingle_reason_text;

extern int hf_xmpp_jingle_rtp_info;

extern int hf_xmpp_jingle_file_transfer_offer;
extern int hf_xmpp_jingle_file_transfer_request;
extern int hf_xmpp_jingle_file_transfer_received;
extern int hf_xmpp_jingle_file_transfer_abort;
extern int hf_xmpp_jingle_file_transfer_checksum;

extern int hf_xmpp_si;
extern int hf_xmpp_si_file;

extern int hf_xmpp_iq_feature_neg;
extern int hf_xmpp_x_data;
extern int hf_xmpp_x_data_field;
extern int hf_xmpp_x_data_field_value;
extern int hf_xmpp_x_data_instructions;
extern int hf_xmpp_muc_user_status;

extern int hf_xmpp_message;
extern int hf_xmpp_message_chatstate;

extern int hf_xmpp_message_thread;
extern int hf_xmpp_message_thread_parent;

extern int hf_xmpp_message_body;
extern int hf_xmpp_message_subject;

extern int hf_xmpp_ibb_open;
extern int hf_xmpp_ibb_close;
extern int hf_xmpp_ibb_data;

extern int hf_xmpp_delay;

extern int hf_xmpp_x_event;
extern int hf_xmpp_x_event_condition;

extern int hf_xmpp_presence;
extern int hf_xmpp_presence_show;
extern int hf_xmpp_presence_status;
extern int hf_xmpp_presence_caps;

extern int hf_xmpp_auth;
extern int hf_xmpp_failure;
extern int hf_xmpp_failure_text;
extern int hf_xmpp_stream;
extern int hf_xmpp_starttls;
extern int hf_xmpp_proceed;
extern int hf_xmpp_xml_header_version;
extern int hf_xmpp_stream_end;


extern int hf_xmpp_muc_x;
extern int hf_xmpp_muc_user_x;
extern int hf_xmpp_muc_user_item;
extern int hf_xmpp_muc_user_invite;

extern int hf_xmpp_gtalk_session;
extern int hf_xmpp_gtalk_session_type;
extern int hf_xmpp_gtalk;
extern int hf_xmpp_gtalk_setting;
extern int hf_xmpp_gtalk_setting_element;
extern int hf_xmpp_gtalk_nosave_x;
extern int hf_xmpp_gtalk_mail_mailbox;
extern int hf_xmpp_gtalk_mail_new_mail;
extern int hf_xmpp_gtalk_transport_p2p;
extern int hf_xmpp_gtalk_mail_snippet;
extern int hf_xmpp_gtalk_status_status_list;

extern int hf_xmpp_conf_info;
extern int hf_xmpp_conf_info_sid;

extern int hf_xmpp_unknown;
extern int hf_xmpp_unknown_attr;

extern int hf_xmpp_response_in;
extern int hf_xmpp_response_to;
extern int hf_xmpp_jingle_session;
extern int hf_xmpp_ibb;

extern int hf_xmpp_ping;
extern int hf_xmpp_hashes;

extern int hf_xmpp_jitsi_inputevt;
extern int hf_xmpp_jitsi_inputevt_rmt_ctrl;

extern int ett_xmpp_iq;
extern int ett_xmpp_query;
extern int ett_xmpp_query_item;
extern int ett_xmpp_query_identity;

extern int ett_xmpp_query_streamhost;
extern int ett_xmpp_query_streamhost_used;
extern int ett_xmpp_query_udpsuccess;

extern int ett_xmpp_iq_bind;
extern int ett_xmpp_iq_session;
extern int ett_xmpp_vcard;
extern int ett_xmpp_vcard_x_update;

extern int ett_xmpp_jingle;
extern int ett_xmpp_jingle_content;
extern int ett_xmpp_jingle_content_description;
extern int ett_xmpp_jingle_cont_desc_enc;
extern int ett_xmpp_jingle_cont_desc_enc_zrtp_hash;
extern int ett_xmpp_jingle_cont_desc_enc_crypto;
extern int ett_xmpp_jingle_cont_desc_rtp_hdr;
extern int ett_xmpp_jingle_cont_desc_bandwidth;
extern int ett_xmpp_jingle_cont_desc_payload;
extern int ett_xmpp_jingle_cont_desc_payload_param;
extern int ett_xmpp_jingle_cont_trans;
extern int ett_xmpp_jingle_cont_trans_cand;
extern int ett_xmpp_jingle_cont_trans_rem_cand;
extern int ett_xmpp_jingle_reason;
extern int ett_xmpp_jingle_rtp_info;
extern int ett_xmpp_jingle_file_transfer_offer;
extern int ett_xmpp_jingle_file_transfer_request;
extern int ett_xmpp_jingle_file_transfer_received;
extern int ett_xmpp_jingle_file_transfer_abort;
extern int ett_xmpp_jingle_file_transfer_checksum;
extern int ett_xmpp_jingle_file_transfer_file;

extern int ett_xmpp_services;
extern int ett_xmpp_services_relay;
extern int ett_xmpp_channel;

extern int ett_xmpp_si;
extern int ett_xmpp_si_file;
extern int ett_xmpp_si_file_range;

extern int ett_xmpp_iq_feature_neg;
extern int ett_xmpp_x_data;
extern int ett_xmpp_x_data_field;
extern int ett_xmpp_x_data_field_value;

extern int ett_xmpp_ibb_open;
extern int ett_xmpp_ibb_close;
extern int ett_xmpp_ibb_data;

extern int ett_xmpp_delay;

extern int ett_xmpp_x_event;

extern int ett_xmpp_message;
extern int ett_xmpp_message_thread;
extern int ett_xmpp_message_body;
extern int ett_xmpp_message_subject;

extern int ett_xmpp_presence;
extern int ett_xmpp_presence_status;
extern int ett_xmpp_presence_caps;

extern int ett_xmpp_auth;
extern int ett_xmpp_failure;
extern int ett_xmpp_stream;
extern int ett_xmpp_features;
extern int ett_xmpp_features_mechanisms;
extern int ett_xmpp_proceed;
extern int ett_xmpp_starttls;

extern int ett_xmpp_muc_x;
extern int ett_xmpp_muc_hist;
extern int ett_xmpp_muc_user_x;
extern int ett_xmpp_muc_user_item;
extern int ett_xmpp_muc_user_invite;

extern int ett_xmpp_gtalk_session;
extern int ett_xmpp_gtalk_session_desc;
extern int ett_xmpp_gtalk_session_desc_payload;
extern int ett_xmpp_gtalk_session_cand;
extern int ett_xmpp_gtalk_session_reason;
extern int ett_xmpp_gtalk_jingleinfo_stun;
extern int ett_xmpp_gtalk_jingleinfo_server;
extern int ett_xmpp_gtalk_jingleinfo_relay;
extern int ett_xmpp_gtalk_jingleinfo_relay_serv;
extern int ett_xmpp_gtalk_setting;
extern int ett_xmpp_gtalk_nosave_x;
extern int ett_xmpp_gtalk_mail_mailbox;
extern int ett_xmpp_gtalk_mail_mail_info;
extern int ett_xmpp_gtalk_mail_senders;
extern int ett_xmpp_gtalk_mail_sender;
extern int ett_xmpp_gtalk_status_status_list;
extern int ett_xmpp_gtalk_transport_p2p;
extern int ett_xmpp_gtalk_transport_p2p_cand;


extern int ett_xmpp_conf_info;
extern int ett_xmpp_conf_desc;
extern int ett_xmpp_conf_state;
extern int ett_xmpp_conf_users;
extern int ett_xmpp_conf_user;
extern int ett_xmpp_conf_endpoint;
extern int ett_xmpp_conf_media;

extern int ett_xmpp_ping;
extern int ett_xmpp_hashes;
extern int ett_xmpp_hashes_hash;

extern int ett_xmpp_jitsi_inputevt;
extern int ett_xmpp_jitsi_inputevt_rmt_ctrl;

extern int ett_unknown[ETT_UNKNOWN_LEN];

extern expert_field ei_xmpp_starttls_missing;
extern expert_field ei_xmpp_response;
extern expert_field ei_xmpp_proceed_already_in_frame;
extern expert_field ei_xmpp_starttls_already_in_frame;
extern expert_field ei_xmpp_packet_without_response;
extern expert_field ei_xmpp_unknown_element;
extern expert_field ei_xmpp_field_unexpected_value;
extern expert_field ei_xmpp_unknown_attribute;
extern expert_field ei_xmpp_required_attribute;


#endif /* PACKET_XMPP_H */

