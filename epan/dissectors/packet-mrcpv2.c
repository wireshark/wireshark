/* packet-mrcpv2.c
 * Routines for Media Resource Control Protocol Version 2 (MRCPv2) dissection
 * Copyright 2012, Zeljko Ancimer  <zancimer[AT]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 * Based on RFC 6787
 *
 * TODO:
 * - TLS has not been tested
 * - MRCP conversation (similar to VoIP Calls)
 * - convert header value into the correct types (numbers, booleans,...);
 *   currently all values are treated as strings so one has to be
 *   careful with the usage of filters; to do this, one has to go through
 *   the mrcp draft and look for the definition of each header (see
 *   chapter titled "15. ABNF Normative Definition")
 */
#include "config.h"

/* Include only as needed */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>

#include <wsutil/str_util.h>

void proto_register_mrcpv2(void);
void proto_reg_handoff_mrcpv2(void);

/* mrcp-version SP message-length */
/*   mrcp-version = "MRCP" "/" 1*2DIGIT "." 1*2DIGIT  ==> up to 10 chars */
/*   SP ==> whitespace, 1 char */
/*   message-length = 1*19DIGIT  ==> up to 19 chars */
/*   total = 10 + 1 + 19 = 30 */

/* min length to determine MRCPv2 version */
#define MRCPV2_MIN_LENGTH    10
/* min length to determine MRCPv2 PDU length */
#define MRCPV2_MIN_PDU_LEN   30

/* line type */
typedef enum {
    REQUEST_LINE,
    RESPONSE_LINE,
    EVENT_LINE,
    UNKNOWN_LINE
} LINE_TYPE;

/* header type */
typedef enum {
    UNKNOWN =                               0,
    ABORT_MODEL =                           1,
    ABORT_PHRASE_ENROLLMENT =               2,
    ABORT_VERIFICATION =                    3,
    ACCEPT =                                4,
    ACCEPT_CHARSET =                        5,
    ACTIVE_REQUEST_ID_LIST =                6,
    ADAPT_MODEL =                           7,
    AUDIO_FETCH_HINT =                      8,
    CACHE_CONTROL =                         9,
    CANCEL_IF_QUEUE =                       10,
    CAPTURE_ON_SPEECH =                     11,
    CHANNEL_IDENTIFIER =                    12,
    CLASH_THRESHOLD =                       13,
    CLEAR_DTMF_BUFFER =                     14,
    COMPLETION_CAUSE =                      15,
    COMPLETION_REASON =                     16,
    CONFIDENCE_THRESHOLD =                  17,
    CONFUSABLE_PHRASES_URI =                18,
    CONSISTENCY_THRESHOLD =                 19,
    CONTENT_BASE =                          20,
    CONTENT_ENCODING =                      21,
    CONTENT_ID =                            22,
    CONTENT_LENGTH =                        23,
    CONTENT_LOCATION =                      24,
    CONTENT_TYPE =                          25,
    DTMF_BUFFER_TIME =                      26,
    DTMF_INTERDIGIT_TIMEOUT =               27,
    DTMF_TERM_CHAR =                        28,
    DTMF_TERM_TIMEOUT =                     29,
    EARLY_NO_MATCH =                        30,
    ENROLL_UTTERANCE =                      31,
    FAILED_URI =                            32,
    FAILED_URI_CAUSE =                      33,
    FETCH_HINT =                            34,
    FETCH_TIMEOUT =                         35,
    FINAL_SILENCE =                         36,
    HOTWORD_MAX_DURATION =                  37,
    HOTWORD_MIN_DURATION =                  38,
    INPUT_TYPE =                            39,
    INPUT_WAVEFORM_URI =                    40,
    INTERPRET_TEXT =                        41,
    JUMP_SIZE =                             42,
    KILL_ON_BARGE_IN =                      43,
    LEXICON_SEARCH_ORDER =                  44,
    LOAD_LEXICON =                          45,
    LOGGING_TAG =                           46,
    MAX_TIME =                              47,
    MEDIA_TYPE =                            48,
    MIN_VERIFICATION_SCORE =                49,
    N_BEST_LIST_LENGTH =                    50,
    NEW_AUDIO_CHANNEL =                     51,
    NEW_PHRASE_ID =                         52,
    NO_INPUT_TIMEOUT =                      53,
    NUM_MAX_VERIFICATION_PHRASES =          54,
    NUM_MIN_CONSISTENT_PRONUNCIATIONS =     55,
    NUM_MIN_VERIFICATION_PHRASES =          56,
    PERSONAL_GRAMMAR_URI =                  57,
    PHRASE_ID =                             58,
    PHRASE_NL =                             59,
    PROSODY_CONTOUR =                       60,
    PROSODY_DURATION =                      61,
    PROSODY_PITCH =                         62,
    PROSODY_RANGE =                         63,
    PROSODY_RATE =                          64,
    PROSODY_VOLUME =                        65,
    PROXY_SYNC_ID =                         66,
    RECOGNITION_MODE =                      67,
    RECOGNITION_TIMEOUT =                   68,
    RECOGNIZER_CONTEXT_BLOCK =              69,
    RECORD_URI =                            70,
    REPOSITORY_URI =                        71,
    SAVE_BEST_WAVEFORM =                    72,
    SAVE_WAVEFORM =                         73,
    SENSITIVITY_LEVEL =                     74,
    SET_COOKIE =                            75,
    SPEAK_LENGTH =                          76,
    SPEAK_RESTART =                         77,
    SPEAKER_PROFILE =                       78,
    SPEECH_COMPLETE_TIMEOUT =               79,
    SPEECH_INCOMPLETE_TIMEOUT =             80,
    SPEECH_LANGUAGE =                       81,
    SPEECH_MARKER =                         82,
    SPEED_VS_ACCURACY =                     83,
    START_INPUT_TIMERS =                    84,
    TRIM_LENGTH =                           85,
    VENDOR_SPECIFIC_PARAMETERS =            86,
    VER_BUFFER_UTTERANCE =                  87,
    VERIFICATION_MODE =                     88,
    VOICE_AGE =                             89,
    VOICE_GENDER =                          90,
    VOICE_NAME =                            91,
    VOICE_VARIANT =                         92,
    VOICEPRINT_EXISTS =                     93,
    VOICEPRINT_IDENTIFIER =                 94,
    WAVEFORM_URI =                          95,
    WEIGHT =                                96
} HEADER_TYPE;

static const value_string header_type_vals[] = {
    { ABORT_MODEL,                          "abort-model" },
    { ABORT_PHRASE_ENROLLMENT,              "abort-phrase-enrollment" },
    { ABORT_VERIFICATION,                   "abort-verification" },
    { ACCEPT,                               "accept" },
    { ACCEPT_CHARSET,                       "accept-charset" },
    { ACTIVE_REQUEST_ID_LIST,               "active-request-id-list" },
    { ADAPT_MODEL,                          "adapt-model" },
    { AUDIO_FETCH_HINT,                     "audio-fetch-hint" },
    { CACHE_CONTROL,                        "cache-control" },
    { CANCEL_IF_QUEUE,                      "cancel-if-queue" },
    { CAPTURE_ON_SPEECH,                    "capture-on-speech" },
    { CHANNEL_IDENTIFIER,                   "channel-identifier" },
    { CLASH_THRESHOLD,                      "clash-threshold" },
    { CLEAR_DTMF_BUFFER,                    "clear-dtmf-buffer" },
    { COMPLETION_CAUSE,                     "completion-cause" },
    { COMPLETION_REASON,                    "completion-reason" },
    { CONFIDENCE_THRESHOLD,                 "confidence-threshold" },
    { CONFUSABLE_PHRASES_URI,               "confusable-phrases-uri" },
    { CONSISTENCY_THRESHOLD,                "consistency-threshold" },
    { CONTENT_BASE,                         "content-base" },
    { CONTENT_ENCODING,                     "content-encoding" },
    { CONTENT_ID,                           "content-id" },
    { CONTENT_LENGTH,                       "content-length" },
    { CONTENT_LOCATION,                     "content-location" },
    { CONTENT_TYPE,                         "content-type" },
    { DTMF_BUFFER_TIME,                     "dtmf-buffer-time" },
    { DTMF_INTERDIGIT_TIMEOUT,              "dtmf-interdigit-timeout" },
    { DTMF_TERM_CHAR,                       "dtmf-term-char" },
    { DTMF_TERM_TIMEOUT,                    "dtmf-term-timeout" },
    { EARLY_NO_MATCH,                       "early-no-match" },
    { ENROLL_UTTERANCE,                     "enroll-utterance" },
    { FAILED_URI,                           "failed-uri" },
    { FAILED_URI_CAUSE,                     "failed-uri-cause" },
    { FETCH_HINT,                           "fetch-hint" },
    { FETCH_TIMEOUT,                        "fetch-timeout" },
    { FINAL_SILENCE,                        "final-silence" },
    { HOTWORD_MAX_DURATION,                 "hotword-max-duration" },
    { HOTWORD_MIN_DURATION,                 "hotword-min-duration" },
    { INPUT_TYPE,                           "input-type" },
    { INPUT_WAVEFORM_URI,                   "input-waveform-uri" },
    { INTERPRET_TEXT,                       "interpret-text" },
    { JUMP_SIZE,                            "jump-size" },
    { KILL_ON_BARGE_IN,                     "kill-on-barge-in" },
    { LEXICON_SEARCH_ORDER,                 "lexicon-search-order" },
    { LOAD_LEXICON,                         "load-lexicon" },
    { LOGGING_TAG,                          "logging-tag" },
    { MAX_TIME,                             "max-time" },
    { MEDIA_TYPE,                           "media-type" },
    { MIN_VERIFICATION_SCORE,               "min-verification-score" },
    { N_BEST_LIST_LENGTH,                   "n-best-list-length" },
    { NEW_AUDIO_CHANNEL,                    "new-audio-channel" },
    { NEW_PHRASE_ID,                        "new-phrase-id" },
    { NO_INPUT_TIMEOUT,                     "no-input-timeout" },
    { NUM_MAX_VERIFICATION_PHRASES,         "num-max-verification-phrases" },
    { NUM_MIN_CONSISTENT_PRONUNCIATIONS,    "num-min-consistent-pronunciations" },
    { NUM_MIN_VERIFICATION_PHRASES,         "num-min-verification-phrases" },
    { PERSONAL_GRAMMAR_URI,                 "personal-grammar-uri" },
    { PHRASE_ID,                            "phrase-id" },
    { PHRASE_NL,                            "phrase-nl" },
    { PROSODY_CONTOUR,                      "prosody-contour" },
    { PROSODY_DURATION,                     "prosody-duration" },
    { PROSODY_PITCH,                        "prosody-pitch" },
    { PROSODY_RANGE,                        "prosody-range" },
    { PROSODY_RATE,                         "prosody-rate" },
    { PROSODY_VOLUME,                       "prosody-volume" },
    { PROXY_SYNC_ID,                        "proxy-sync-id" },
    { RECOGNITION_MODE,                     "recognition-mode" },
    { RECOGNITION_TIMEOUT,                  "recognition-timeout" },
    { RECOGNIZER_CONTEXT_BLOCK,             "recognizer-context-block" },
    { RECORD_URI,                           "record-uri" },
    { REPOSITORY_URI,                       "repository-uri" },
    { SAVE_BEST_WAVEFORM,                   "save-best-waveform" },
    { SAVE_WAVEFORM,                        "save-waveform" },
    { SENSITIVITY_LEVEL,                    "sensitivity-level" },
    { SET_COOKIE,                           "set-cookie" },
    { SPEAK_LENGTH,                         "speak-length" },
    { SPEAK_RESTART,                        "speak-restart" },
    { SPEAKER_PROFILE,                      "speaker-profile" },
    { SPEECH_COMPLETE_TIMEOUT,              "speech-complete-timeout" },
    { SPEECH_INCOMPLETE_TIMEOUT,            "speech-incomplete-timeout" },
    { SPEECH_LANGUAGE,                      "speech-language" },
    { SPEECH_MARKER,                        "speech-marker" },
    { SPEED_VS_ACCURACY,                    "speed-vs-accuracy" },
    { START_INPUT_TIMERS,                   "start-input-timers" },
    { TRIM_LENGTH,                          "trim-length" },
    { VENDOR_SPECIFIC_PARAMETERS,           "vendor-specific-parameters" },
    { VER_BUFFER_UTTERANCE,                 "ver-buffer-utterance" },
    { VERIFICATION_MODE,                    "verification-mode" },
    { VOICE_AGE,                            "voice-age" },
    { VOICE_GENDER,                         "voice-gender" },
    { VOICE_NAME,                           "voice-name" },
    { VOICE_VARIANT,                        "voice-variant" },
    { VOICEPRINT_EXISTS,                    "voiceprint-exists" },
    { VOICEPRINT_IDENTIFIER,                "voiceprint-identifier" },
    { WAVEFORM_URI,                         "waveform-uri" },
    { WEIGHT,                               "weight" },
    { 0,    NULL }
};

/* Initialize the protocol and registered fields */
static int proto_mrcpv2 = -1;
static int hf_mrcpv2_Request_Line = -1;
static int hf_mrcpv2_Response_Line = -1;
static int hf_mrcpv2_Event_Line = -1;
static int hf_mrcpv2_Unknown_Message = -1;
static int hf_mrcpv2_Unknown_Header = -1;
static int hf_mrcpv2_Data = -1;
static int hf_mrcpv2_Method = -1;
static int hf_mrcpv2_Event = -1;
static int hf_mrcpv2_version = -1;
static int hf_mrcpv2_message_length = -1;
static int hf_mrcpv2_request_id = -1;
static int hf_mrcpv2_status_code = -1;
static int hf_mrcpv2_request_state = -1;
static int hf_mrcpv2_Abort_Model = -1;
static int hf_mrcpv2_Abort_Phrase_Enrollment = -1;
static int hf_mrcpv2_Abort_Verification = -1;
static int hf_mrcpv2_Accept = -1;
static int hf_mrcpv2_Accept_Charset = -1;
static int hf_mrcpv2_Active_Request_Id_List = -1;
static int hf_mrcpv2_Adapt_Model = -1;
static int hf_mrcpv2_Audio_Fetch_Hint = -1;
static int hf_mrcpv2_Cache_Control = -1;
static int hf_mrcpv2_Cancel_If_Queue = -1;
static int hf_mrcpv2_Capture_On_Speech = -1;
static int hf_mrcpv2_Channel_Identifier = -1;
static int hf_mrcpv2_Clash_Threshold = -1;
static int hf_mrcpv2_Clear_Dtmf_Buffer = -1;
static int hf_mrcpv2_Completion_Cause = -1;
static int hf_mrcpv2_Completion_Reason = -1;
static int hf_mrcpv2_Confidence_Threshold = -1;
static int hf_mrcpv2_Confusable_Phrases_URI = -1;
static int hf_mrcpv2_Consistency_Threshold = -1;
static int hf_mrcpv2_Content_Base = -1;
static int hf_mrcpv2_Content_Encoding = -1;
static int hf_mrcpv2_Content_ID = -1;
static int hf_mrcpv2_Content_Length = -1;
static int hf_mrcpv2_Content_Location = -1;
static int hf_mrcpv2_Content_Type = -1;
static int hf_mrcpv2_Dtmf_Buffer_Time = -1;
static int hf_mrcpv2_Dtmf_Interdigit_Timeout = -1;
static int hf_mrcpv2_Dtmf_Term_Char = -1;
static int hf_mrcpv2_Dtmf_Term_Timeout = -1;
static int hf_mrcpv2_Early_No_Match = -1;
static int hf_mrcpv2_Enroll_Utterance = -1;
static int hf_mrcpv2_Failed_URI = -1;
static int hf_mrcpv2_Failed_URI_Cause = -1;
static int hf_mrcpv2_Fetch_Hint = -1;
static int hf_mrcpv2_Fetch_Timeout = -1;
static int hf_mrcpv2_Final_Silence = -1;
static int hf_mrcpv2_Hotword_Max_Duration = -1;
static int hf_mrcpv2_Hotword_Min_Duration = -1;
static int hf_mrcpv2_Input_Type = -1;
static int hf_mrcpv2_Input_Waveform_URI = -1;
static int hf_mrcpv2_Interpret_Text = -1;
static int hf_mrcpv2_Jump_Size = -1;
static int hf_mrcpv2_Kill_On_Barge_In = -1;
static int hf_mrcpv2_Lexicon_Search_Order = -1;
static int hf_mrcpv2_Load_Lexicon = -1;
static int hf_mrcpv2_Logging_Tag = -1;
static int hf_mrcpv2_Max_Time = -1;
static int hf_mrcpv2_Media_Type = -1;
static int hf_mrcpv2_Min_Verification_Score = -1;
static int hf_mrcpv2_N_Best_List_Length = -1;
static int hf_mrcpv2_New_Audio_Channel = -1;
static int hf_mrcpv2_New_Phrase_ID = -1;
static int hf_mrcpv2_No_Input_Timeout = -1;
static int hf_mrcpv2_Num_Max_Verification_Phrases = -1;
static int hf_mrcpv2_Num_Min_Consistent_Pronunciations = -1;
static int hf_mrcpv2_Num_Min_Verification_Phrases = -1;
static int hf_mrcpv2_Personal_Grammar_URI = -1;
static int hf_mrcpv2_Phrase_ID = -1;
static int hf_mrcpv2_Phrase_NL = -1;
static int hf_mrcpv2_Prosody_Contour = -1;
static int hf_mrcpv2_Prosody_Duration = -1;
static int hf_mrcpv2_Prosody_Pitch = -1;
static int hf_mrcpv2_Prosody_Range = -1;
static int hf_mrcpv2_Prosody_Rate = -1;
static int hf_mrcpv2_Prosody_Volume = -1;
static int hf_mrcpv2_Proxy_Sync_Id = -1;
static int hf_mrcpv2_Recognition_Mode = -1;
static int hf_mrcpv2_Recognition_Timeout = -1;
static int hf_mrcpv2_Recognizer_Context_Block = -1;
static int hf_mrcpv2_Record_URI = -1;
static int hf_mrcpv2_Repository_URI = -1;
static int hf_mrcpv2_Save_Best_Waveform = -1;
static int hf_mrcpv2_Save_Waveform = -1;
static int hf_mrcpv2_Sensitivity_Level = -1;
static int hf_mrcpv2_Set_Cookie = -1;
static int hf_mrcpv2_Speak_Length = -1;
static int hf_mrcpv2_Speak_Restart = -1;
static int hf_mrcpv2_Speaker_Profile = -1;
static int hf_mrcpv2_Speech_Complete_Timeout = -1;
static int hf_mrcpv2_Speech_Incomplete_Timeout = -1;
static int hf_mrcpv2_Speech_Language = -1;
static int hf_mrcpv2_Speech_Marker = -1;
static int hf_mrcpv2_Speed_Vs_Accuracy = -1;
static int hf_mrcpv2_Start_Input_Timers = -1;
static int hf_mrcpv2_Trim_Length = -1;
static int hf_mrcpv2_Vendor_Specific_Parameters = -1;
static int hf_mrcpv2_Ver_Buffer_Utterance = -1;
static int hf_mrcpv2_Verification_Mode = -1;
static int hf_mrcpv2_Voice_Age = -1;
static int hf_mrcpv2_Voice_Gender = -1;
static int hf_mrcpv2_Voice_Name = -1;
static int hf_mrcpv2_Voice_Variant = -1;
static int hf_mrcpv2_Voiceprint_Exists = -1;
static int hf_mrcpv2_Voiceprint_Identifier = -1;
static int hf_mrcpv2_Waveform_URI = -1;
static int hf_mrcpv2_Weight = -1;

/* Global MRCPv2 port pref */
#define TCP_DEFAULT_RANGE "6075, 30000-30200"
static range_t *global_mrcpv2_tcp_range = NULL;
static range_t *mrcpv2_tcp_range = NULL;

/* Initialize the subtree pointers */
static gint ett_mrcpv2 = -1;
static gint ett_Request_Line = -1;
static gint ett_Response_Line = -1;
static gint ett_Event_Line = -1;
static gint ett_Status_Code = -1;

/* format status code description */
static const string_string status_code_vals[] = {
    { "200", "Success" },
    { "201", "Success with some optional header fields ignored" },
    { "401", "Client Failure: Method not allowed" },
    { "402", "Client Failure: Method not valid in this state" },
    { "403", "Client Failure: Unsupported header field" },
    { "404", "Client Failure: Illegal value for header field. This is the error for a syntax violation." },
    { "405", "Client Failure: Resource not allocated for this session or does not exist" },
    { "406", "Client Failure: Mandatory Header Field Missing" },
    { "407", "Client Failure: Method or Operation Failed (e.g., Grammar compilation failed in the recognizer. Detailed cause codes might be available through a resource specific header.)" },
    { "408", "Client Failure: Unrecognized or unsupported message entity" },
    { "409", "Client Failure: Unsupported Header Field Value. This is a value that is syntactically legal but exceeds the implementation's capabilities or expectations." },
    { "410", "Client Failure: Non-Monotonic or Out of order sequence number in request." },
    { "501", "Server Failure: Server Internal Error" },
    { "502", "Server Failure: Protocol Version not supported" },
    { "503", "Server Failure: Reserved for future assignment" },
    { "504", "Server Failure: Message too large" },
    { "", NULL }
};

/* Code to actually dissect the packets */
static int
dissect_mrcpv2_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *mrcpv2_tree;
    gint next_offset, linelen;
    gint tvb_len;
    gint pdu_size;
    gint offset;
    gint value_offset;
    gint str_len;
    gchar helper_str[256];
    gchar *header_name;
    gchar *header_value;
    LINE_TYPE line_type = UNKNOWN_LINE;
    HEADER_TYPE header_type;
    gint colon_offset;
    gint content_length;
    const value_string *p = NULL;
    proto_item *line_item = NULL;
    proto_item *request_line_item = NULL;
    proto_item *response_line_item = NULL;
    proto_item *event_line_item = NULL;
    proto_item *status_code_item = NULL;

    gint sp_start;
    gint sp_end;
    guint8 *field1;
    guint8 *field2;
    guint8 *field3;
    guint8 *field4;
    guint8 *field5 = NULL;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MRCPv2");

    offset = 0;
    if (tree) {
        tvb_len = tvb_length(tvb);

        ti = proto_tree_add_item(tree, proto_mrcpv2, tvb, 0, -1, ENC_UTF_8);
        mrcpv2_tree = proto_item_add_subtree(ti, ett_mrcpv2);

        /* get first line */
        linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);

        /*  find out MRCP message type:

            request-line    = mrcp-version SP message-length SP method-name SP request-id CRLF
            response-line    = mrcp-version SP message-length SP request-id  SP status-code SP request-state CRLF
            event-line    = mrcp-version SP message-length SP event-name  SP request-id  SP request-state CRLF
        */
        /* version */
        sp_end = tvb_find_guint8(tvb, 0, linelen, ' ');
        if ((sp_end == -1) || (sp_end > tvb_len) || (sp_end > linelen))
            return -1;
        field1 = tvb_get_string_enc(wmem_packet_scope(), tvb, 0, sp_end, ENC_ASCII);
        sp_start = sp_end + 1;

        /* length */
        sp_end = tvb_find_guint8(tvb, sp_start, linelen - sp_start, ' ');
        if ((sp_end == -1) || (sp_end > tvb_len) || (sp_end > linelen))
            return -1;
        field2 = tvb_get_string_enc(wmem_packet_scope(), tvb, sp_start, sp_end - sp_start, ENC_ASCII);
        sp_start = sp_end + 1;

        /* method, request ID or event */
        sp_end = tvb_find_guint8(tvb, sp_start, linelen - sp_start, ' ');
        if ((sp_end == -1) || (sp_end > tvb_len) || (sp_end > linelen))
            return -1;
        field3 = tvb_get_string_enc(wmem_packet_scope(), tvb, sp_start, sp_end - sp_start, ENC_ASCII);
        sp_start = sp_end + 1;

        /* request ID or status code */
        sp_end = tvb_find_guint8(tvb, sp_start, linelen - sp_start, ' ');
        if (sp_end == -1)
        {
            field4 = tvb_get_string_enc(wmem_packet_scope(), tvb, sp_start, linelen - sp_start, ENC_ASCII);
            line_type = REQUEST_LINE; /* only request line has 4 parameters */
        }
        else
        {
            if ((sp_end > tvb_len) || (sp_end > linelen))
                return -1;
            field4 = tvb_get_string_enc(wmem_packet_scope(), tvb, sp_start, sp_end - sp_start, ENC_ASCII);

            if (isdigit(field3[0])) /* request ID is number, so it has to be response */
                line_type = RESPONSE_LINE;
            else
                line_type = EVENT_LINE;

            sp_start = sp_end + 1;
            sp_end = linelen;
            if ((sp_end > tvb_len) || (sp_end > linelen))
                return -1;
            field5 = tvb_get_string_enc(wmem_packet_scope(), tvb, sp_start, sp_end - sp_start, ENC_ASCII);
        }

        /* check pdu size */
        pdu_size = atoi(field2);
        if (pdu_size > tvb_len)
            return -1;

        /* process MRCP header line */
        switch(line_type){
        case REQUEST_LINE:
        {
            col_set_str(pinfo->cinfo, COL_INFO, "Request: ");
            line_item = proto_tree_add_item(mrcpv2_tree, hf_mrcpv2_Request_Line, tvb, offset, linelen, ENC_UTF_8|ENC_NA);
            request_line_item = proto_item_add_subtree(line_item, ett_Request_Line);
            /* version */
            str_len = (gint)strlen(field1);
            proto_tree_add_item(request_line_item, hf_mrcpv2_version, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
            offset += str_len + 1; /* add SP */
            /* message length */
            str_len = (gint)strlen(field2);
            proto_tree_add_item(request_line_item, hf_mrcpv2_message_length, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
            offset += str_len + 1; /* add SP */
            /* method name */
            col_append_str(pinfo->cinfo, COL_INFO, field3);
            str_len = (gint)strlen(field3);
            proto_tree_add_item(request_line_item, hf_mrcpv2_Method, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
            offset += str_len + 1; /* add SP */
            /* request ID */
            str_len = (gint)strlen(field4);
            proto_tree_add_item(request_line_item, hf_mrcpv2_request_id, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
            /*offset += str_len + 2;*/ /* add CRLF */
        }
        break;
        case RESPONSE_LINE:
        {
            col_set_str(pinfo->cinfo, COL_INFO, "Response: ");
            line_item = proto_tree_add_item(mrcpv2_tree, hf_mrcpv2_Response_Line, tvb, offset, linelen, ENC_UTF_8|ENC_NA);
            response_line_item = proto_item_add_subtree(line_item, ett_Response_Line);
            /* version */
            str_len = (gint)strlen(field1);
            proto_tree_add_item(response_line_item, hf_mrcpv2_version, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
            offset += str_len + 1; /* add SP */
            /* message length */
            str_len = (gint)strlen(field2);
            proto_tree_add_item(response_line_item, hf_mrcpv2_message_length, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
            offset += str_len + 1; /* add SP */
            /* request ID */
            str_len = (gint)strlen(field3);
            proto_tree_add_item(response_line_item, hf_mrcpv2_request_id, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
            offset += str_len + 1; /* add SP */
            /* status code */
            str_len = (gint)strlen(field4);
            status_code_item = proto_tree_add_item(response_line_item, hf_mrcpv2_status_code, tvb, offset,
                str_len, ENC_UTF_8|ENC_NA);
            proto_item_append_text(status_code_item, " %s", str_to_str(field4, status_code_vals, "Unknown Status Code"));
            offset += str_len + 1; /* add SP */
            /* request state */
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) %s", field4, field5);
            str_len = (gint)strlen(field5);
            proto_tree_add_item(response_line_item, hf_mrcpv2_request_state, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
            /*offset += str_len + 2;*/ /* add CRLF */
        }
        break;
        case EVENT_LINE:
        {
            col_set_str(pinfo->cinfo, COL_INFO, "Event: ");
            line_item = proto_tree_add_item(mrcpv2_tree, hf_mrcpv2_Event_Line, tvb, offset, linelen, ENC_UTF_8|ENC_NA);
            event_line_item = proto_item_add_subtree(line_item, ett_Event_Line);
            /* version */
            str_len = (gint)strlen(field1);
            proto_tree_add_item(event_line_item, hf_mrcpv2_version, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
            offset += str_len + 1; /* add SP */
            /* message length */
            str_len = (gint)strlen(field2);
            proto_tree_add_item(event_line_item, hf_mrcpv2_message_length, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
            offset += str_len + 1; /* add SP */
            /* event name */
            col_append_str(pinfo->cinfo, COL_INFO, field3);
            str_len = (gint)strlen(field3);
            proto_tree_add_item(event_line_item, hf_mrcpv2_Event, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
            offset += str_len + 1; /* add SP */
            /* request ID */
            str_len = (gint)strlen(field4);
            proto_tree_add_item(event_line_item, hf_mrcpv2_request_id, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
            offset += str_len + 1; /* add SP */
            /* request state */
            str_len = (gint)strlen(field5);
            proto_tree_add_item(event_line_item, hf_mrcpv2_request_state, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
            /*offset += str_len + 2;*/ /* add CRLF */
        }
        break;
        default:
        {
            /* mark whole packet as unknown and return */
            col_set_str(pinfo->cinfo, COL_INFO, "UNKNOWN message");
            proto_tree_add_item(mrcpv2_tree, hf_mrcpv2_Unknown_Message, tvb, offset, tvb_len, ENC_UTF_8|ENC_NA);
            return tvb_len;
        }
        }

        /* process the rest of the header lines here */
        content_length = 0;
        while (next_offset < tvb_len)
        {
            /* get next line */
            offset = next_offset;
            linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);

            /* blank line separates msg header and msg body */
            if (linelen == 0)
            {
                if (content_length > 0)
                { /* content length > 0 and CRLF detected, this has to be msg body */
                    offset += 2; /* skip separating CRLF */
                    proto_tree_add_string_format(mrcpv2_tree, hf_mrcpv2_Data, tvb, offset, tvb_len - offset,
                        helper_str, "Message data: %s", tvb_format_text(tvb, offset, tvb_len - offset));
                    next_offset = tvb_len; /* we are done */
                }
                continue;
            }

            /* get header type and its value */
            colon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
            if (colon_offset == -1)
            { /* header type should end with ':' */
                proto_tree_add_item(mrcpv2_tree, hf_mrcpv2_Unknown_Header, tvb, offset, linelen, ENC_UTF_8|ENC_NA);
                continue;
            }
            header_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, colon_offset - offset, ENC_ASCII);
            ascii_strdown_inplace(header_name);
            value_offset = tvb_skip_wsp(tvb, colon_offset + 1, offset + linelen - (colon_offset + 1));
            header_value = tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, offset + linelen - value_offset, ENC_ASCII);

            /* find out header type */
            header_type = UNKNOWN;
            for (p = header_type_vals; p->strptr != NULL; ++p)
            {
                if (strncmp(p->strptr, header_name, strlen(p->strptr)) == 0)
                {
                    header_type = (HEADER_TYPE)p->value;
                    break;
                }
            }

            /* add header type and value into the tree */
            switch (header_type)
            {
                case ABORT_MODEL:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Abort_Model, tvb, offset, linelen, header_value);
                    break;
                case ABORT_PHRASE_ENROLLMENT:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Abort_Phrase_Enrollment, tvb, offset, linelen, header_value);
                    break;
                case ABORT_VERIFICATION:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Abort_Verification, tvb, offset, linelen, header_value);
                    break;
                case ACCEPT:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Accept, tvb, offset, linelen, header_value);
                    break;
                case ACCEPT_CHARSET:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Accept_Charset, tvb, offset, linelen, header_value);
                    break;
                case ACTIVE_REQUEST_ID_LIST:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Active_Request_Id_List, tvb, offset, linelen, header_value);
                    break;
                case ADAPT_MODEL:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Adapt_Model, tvb, offset, linelen, header_value);
                    break;
                case AUDIO_FETCH_HINT:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Audio_Fetch_Hint, tvb, offset, linelen, header_value);
                    break;
                case CACHE_CONTROL:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Cache_Control, tvb, offset, linelen, header_value);
                    break;
                case CANCEL_IF_QUEUE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Cancel_If_Queue, tvb, offset, linelen, header_value);
                    break;
                case CAPTURE_ON_SPEECH:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Capture_On_Speech, tvb, offset, linelen, header_value);
                    break;
                case CHANNEL_IDENTIFIER:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Channel_Identifier, tvb, offset, linelen, header_value);
                    break;
                case CLASH_THRESHOLD:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Clash_Threshold, tvb, offset, linelen, header_value);
                    break;
                case CLEAR_DTMF_BUFFER:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Clear_Dtmf_Buffer, tvb, offset, linelen, header_value);
                    break;
                case COMPLETION_CAUSE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Completion_Cause, tvb, offset, linelen, header_value);
                    break;
                case COMPLETION_REASON:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Completion_Reason, tvb, offset, linelen, header_value);
                    break;
                case CONFIDENCE_THRESHOLD:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Confidence_Threshold, tvb, offset, linelen, header_value);
                    break;
                case CONFUSABLE_PHRASES_URI:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Confusable_Phrases_URI, tvb, offset, linelen, header_value);
                    break;
                case CONSISTENCY_THRESHOLD:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Consistency_Threshold, tvb, offset, linelen, header_value);
                    break;
                case CONTENT_BASE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Content_Base, tvb, offset, linelen, header_value);
                    break;
                case CONTENT_ENCODING:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Content_Encoding, tvb, offset, linelen, header_value);
                    break;
                case CONTENT_ID:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Content_ID, tvb, offset, linelen, header_value);
                    break;
                case CONTENT_LENGTH:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Content_Length, tvb, offset, linelen, header_value);
                    /* if content length is > 0, then there are some data after the headers */
                    content_length = atoi(header_value);
                    break;
                case CONTENT_LOCATION:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Content_Location, tvb, offset, linelen, header_value);
                    break;
                case CONTENT_TYPE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Content_Type, tvb, offset, linelen, header_value);
                    break;
                case DTMF_BUFFER_TIME:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Dtmf_Buffer_Time, tvb, offset, linelen, header_value);
                    break;
                case DTMF_INTERDIGIT_TIMEOUT:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Dtmf_Interdigit_Timeout, tvb, offset, linelen, header_value);
                    break;
                case DTMF_TERM_CHAR:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Dtmf_Term_Char, tvb, offset, linelen, header_value);
                    break;
                case DTMF_TERM_TIMEOUT:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Dtmf_Term_Timeout, tvb, offset, linelen, header_value);
                    break;
                case EARLY_NO_MATCH:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Early_No_Match, tvb, offset, linelen, header_value);
                    break;
                case ENROLL_UTTERANCE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Enroll_Utterance, tvb, offset, linelen, header_value);
                    break;
                case FAILED_URI:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Failed_URI, tvb, offset, linelen, header_value);
                    break;
                case FAILED_URI_CAUSE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Failed_URI_Cause, tvb, offset, linelen, header_value);
                    break;
                case FETCH_HINT:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Fetch_Hint, tvb, offset, linelen, header_value);
                    break;
                case FETCH_TIMEOUT:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Fetch_Timeout, tvb, offset, linelen, header_value);
                    break;
                case FINAL_SILENCE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Final_Silence, tvb, offset, linelen, header_value);
                    break;
                case HOTWORD_MAX_DURATION:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Hotword_Max_Duration, tvb, offset, linelen, header_value);
                    break;
                case HOTWORD_MIN_DURATION:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Hotword_Min_Duration, tvb, offset, linelen, header_value);
                    break;
                case INPUT_TYPE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Input_Type, tvb, offset, linelen, header_value);
                    break;
                case INPUT_WAVEFORM_URI:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Input_Waveform_URI, tvb, offset, linelen, header_value);
                    break;
                case INTERPRET_TEXT:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Interpret_Text, tvb, offset, linelen, header_value);
                    break;
                case JUMP_SIZE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Jump_Size, tvb, offset, linelen, header_value);
                    break;
                case KILL_ON_BARGE_IN:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Kill_On_Barge_In, tvb, offset, linelen, header_value);
                    break;
                case LEXICON_SEARCH_ORDER:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Lexicon_Search_Order, tvb, offset, linelen, header_value);
                    break;
                case LOAD_LEXICON:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Load_Lexicon, tvb, offset, linelen, header_value);
                    break;
                case LOGGING_TAG:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Logging_Tag, tvb, offset, linelen, header_value);
                    break;
                case MAX_TIME:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Max_Time, tvb, offset, linelen, header_value);
                    break;
                case MEDIA_TYPE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Media_Type, tvb, offset, linelen, header_value);
                    break;
                case MIN_VERIFICATION_SCORE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Min_Verification_Score, tvb, offset, linelen, header_value);
                    break;
                case N_BEST_LIST_LENGTH:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_N_Best_List_Length, tvb, offset, linelen, header_value);
                    break;
                case NEW_AUDIO_CHANNEL:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_New_Audio_Channel, tvb, offset, linelen, header_value);
                    break;
                case NEW_PHRASE_ID:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_New_Phrase_ID, tvb, offset, linelen, header_value);
                    break;
                case NO_INPUT_TIMEOUT:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_No_Input_Timeout, tvb, offset, linelen, header_value);
                    break;
                case NUM_MAX_VERIFICATION_PHRASES:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Num_Max_Verification_Phrases, tvb, offset, linelen, header_value);
                    break;
                case NUM_MIN_CONSISTENT_PRONUNCIATIONS:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Num_Min_Consistent_Pronunciations, tvb, offset, linelen, header_value);
                    break;
                case NUM_MIN_VERIFICATION_PHRASES:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Num_Min_Verification_Phrases, tvb, offset, linelen, header_value);
                    break;
                case PERSONAL_GRAMMAR_URI:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Personal_Grammar_URI, tvb, offset, linelen, header_value);
                    break;
                case PHRASE_ID:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Phrase_ID, tvb, offset, linelen, header_value);
                    break;
                case PHRASE_NL:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Phrase_NL, tvb, offset, linelen, header_value);
                    break;
                case PROSODY_CONTOUR:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Prosody_Contour, tvb, offset, linelen, header_value);
                    break;
                case PROSODY_DURATION:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Prosody_Duration, tvb, offset, linelen, header_value);
                    break;
                case PROSODY_PITCH:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Prosody_Pitch, tvb, offset, linelen, header_value);
                    break;
                case PROSODY_RANGE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Prosody_Range, tvb, offset, linelen, header_value);
                    break;
                case PROSODY_RATE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Prosody_Rate, tvb, offset, linelen, header_value);
                    break;
                case PROSODY_VOLUME:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Prosody_Volume, tvb, offset, linelen, header_value);
                    break;
                case PROXY_SYNC_ID:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Proxy_Sync_Id, tvb, offset, linelen, header_value);
                    break;
                case RECOGNITION_MODE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Recognition_Mode, tvb, offset, linelen, header_value);
                    break;
                case RECOGNITION_TIMEOUT:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Recognition_Timeout, tvb, offset, linelen, header_value);
                    break;
                case RECOGNIZER_CONTEXT_BLOCK:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Recognizer_Context_Block, tvb, offset, linelen, header_value);
                    break;
                case RECORD_URI:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Record_URI, tvb, offset, linelen, header_value);
                    break;
                case REPOSITORY_URI:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Repository_URI, tvb, offset, linelen, header_value);
                    break;
                case SAVE_BEST_WAVEFORM:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Save_Best_Waveform, tvb, offset, linelen, header_value);
                    break;
                case SAVE_WAVEFORM:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Save_Waveform, tvb, offset, linelen, header_value);
                    break;
                case SENSITIVITY_LEVEL:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Sensitivity_Level, tvb, offset, linelen, header_value);
                    break;
                case SET_COOKIE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Set_Cookie, tvb, offset, linelen, header_value);
                    break;
                case SPEAK_LENGTH:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Speak_Length, tvb, offset, linelen, header_value);
                    break;
                case SPEAK_RESTART:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Speak_Restart, tvb, offset, linelen, header_value);
                    break;
                case SPEAKER_PROFILE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Speaker_Profile, tvb, offset, linelen, header_value);
                    break;
                case SPEECH_COMPLETE_TIMEOUT:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Speech_Complete_Timeout, tvb, offset, linelen, header_value);
                    break;
                case SPEECH_INCOMPLETE_TIMEOUT:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Speech_Incomplete_Timeout, tvb, offset, linelen, header_value);
                    break;
                case SPEECH_LANGUAGE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Speech_Language, tvb, offset, linelen, header_value);
                    break;
                case SPEECH_MARKER:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Speech_Marker, tvb, offset, linelen, header_value);
                    break;
                case SPEED_VS_ACCURACY:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Speed_Vs_Accuracy, tvb, offset, linelen, header_value);
                    break;
                case START_INPUT_TIMERS:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Start_Input_Timers, tvb, offset, linelen, header_value);
                    break;
                case TRIM_LENGTH:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Trim_Length, tvb, offset, linelen, header_value);
                    break;
                case VENDOR_SPECIFIC_PARAMETERS:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Vendor_Specific_Parameters, tvb, offset, linelen, header_value);
                    break;
                case VER_BUFFER_UTTERANCE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Ver_Buffer_Utterance, tvb, offset, linelen, header_value);
                    break;
                case VERIFICATION_MODE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Verification_Mode, tvb, offset, linelen, header_value);
                    break;
                case VOICE_AGE:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Voice_Age, tvb, offset, linelen, header_value);
                    break;
                case VOICE_GENDER:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Voice_Gender, tvb, offset, linelen, header_value);
                    break;
                case VOICE_NAME:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Voice_Name, tvb, offset, linelen, header_value);
                    break;
                case VOICE_VARIANT:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Voice_Variant, tvb, offset, linelen, header_value);
                    break;
                case VOICEPRINT_EXISTS:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Voiceprint_Exists, tvb, offset, linelen, header_value);
                    break;
                case VOICEPRINT_IDENTIFIER:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Voiceprint_Identifier, tvb, offset, linelen, header_value);
                    break;
                case WAVEFORM_URI:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Waveform_URI, tvb, offset, linelen, header_value);
                    break;
                case WEIGHT:
                    proto_tree_add_string(mrcpv2_tree, hf_mrcpv2_Weight, tvb, offset, linelen, header_value);
                    break;
                default:
                    proto_tree_add_item(mrcpv2_tree, hf_mrcpv2_Unknown_Header, tvb, offset, linelen, ENC_UTF_8|ENC_NA);
                    break;
            }
        }
    }

    /* Return the amount of data this dissector was able to dissect */
    return tvb_length(tvb);
}

/* get the length of the MRCP message */
static guint
get_mrcpv2_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    gint len_start;
    gint len_end;
    guint8 *msg_len;
    guint num_msg_len;

    /* first string is version */
    len_start = tvb_find_guint8(tvb, offset, MRCPV2_MIN_PDU_LEN, ' ');
    if (len_start == -1)
        return 0;
    len_start += 1; /* skip whitespace */

    /* second string is message length */
    len_end = tvb_find_guint8(tvb, len_start, MRCPV2_MIN_PDU_LEN - len_start, ' ');
    if (len_end == -1)
        msg_len = tvb_get_string_enc(wmem_packet_scope(), tvb, len_start, MRCPV2_MIN_PDU_LEN - len_start, ENC_ASCII);
    else
        msg_len = tvb_get_string_enc(wmem_packet_scope(), tvb, len_start, len_end - len_start, ENC_ASCII);

    num_msg_len = atoi(msg_len);
    return num_msg_len;
}

static int
dissect_mrcpv2_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_mrcpv2_common(tvb, pinfo, tree);
}

static int
dissect_mrcpv2_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gint len;
    gint value_size;
    guint8 *version;
    guint8 *major;
    guint8 *minor;
    gint slash_offset;
    gint dot_offset;
    gint sp_offset;
    int value;

    len = tvb_length(tvb);
    if (len < MRCPV2_MIN_LENGTH) /* too short, can't conclude if it's mrcp */
        return 0;

    /* we are looking for MRCP string */
    slash_offset = tvb_find_guint8(tvb, 0, MRCPV2_MIN_LENGTH, '/');
    if (slash_offset != 4)
        return 0;
    version = tvb_get_string_enc(wmem_packet_scope(), tvb, 0, slash_offset, ENC_ASCII);
    if (strcmp(version, "MRCP") != 0)
        return 0;

    /* get first digit after the '/'; it should be 2 */
    dot_offset = tvb_find_guint8(tvb, slash_offset + 1, MRCPV2_MIN_LENGTH - slash_offset - 1, '.');
    if (dot_offset == -1)
        return 0;
    value_size = dot_offset - slash_offset - 1;
    if ((value_size != 1) && (value_size != 2))
        return 0;
    major = tvb_get_string_enc(wmem_packet_scope(), tvb, slash_offset + 1, dot_offset - 1, ENC_ASCII);
    value = atoi(major);
    if (value != 2)
        return 0;

    /* get second digit, it should be 0 */
    sp_offset = tvb_find_guint8(tvb, dot_offset + 1, MRCPV2_MIN_LENGTH - dot_offset - 1, ' ');
    if (sp_offset == -1)
    {
        minor = tvb_get_string_enc(wmem_packet_scope(), tvb, dot_offset + 1, MRCPV2_MIN_LENGTH - dot_offset - 1, ENC_ASCII);
        len = MRCPV2_MIN_LENGTH;
    }
    else
    {
        minor = tvb_get_string_enc(wmem_packet_scope(), tvb, dot_offset + 1, MRCPV2_MIN_LENGTH - sp_offset - 1, ENC_ASCII);
        len = sp_offset;
    }
    value = atoi(minor);
    if (value != 0)
        return 0;

    /* if we are here, then we have MRCP v 2.0 protocol, so proceed with the dissection */
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, MRCPV2_MIN_PDU_LEN,
                    get_mrcpv2_pdu_len,
                    dissect_mrcpv2_tcp_pdu, data);
    return len;
}

void
proto_register_mrcpv2(void)
{
    module_t *mrcpv2_module;

    static hf_register_info hf[] = {
        { &hf_mrcpv2_Request_Line,
            { "Request-Line", "mrcpv2.Request-Line",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mrcpv2_Response_Line,
            { "Response-Line", "mrcpv2.Response-Line",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mrcpv2_Event_Line,
            { "Event-Line", "mrcpv2.Event-Line",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mrcpv2_Unknown_Message,
            { "Unknown Message", "mrcpv2.Unknown-Message",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mrcpv2_Unknown_Header,
            { "Unknown Header", "mrcpv2.Unknown-Header",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mrcpv2_Data,
            { "Data", "mrcpv2.Data",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mrcpv2_Method,
            { "Method", "mrcpv2.Method",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mrcpv2_Event,
            { "Event", "mrcpv2.Event",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mrcpv2_version,
            { "Version", "mrcpv2.Version",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mrcpv2_message_length,
            { "Message Length", "mrcpv2.msg_len",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mrcpv2_request_id,
            { "Request ID", "mrcpv2.reqID",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mrcpv2_status_code,
            { "Status Code", "mrcpv2.status_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mrcpv2_request_state,
            { "Request State", "mrcpv2.request_state",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mrcpv2_Abort_Model,
            { "Abort-Model", "mrcpv2.Abort-Model",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Abort_Phrase_Enrollment,
            { "Abort-Phrase-Enrollment", "mrcpv2.Abort-Phrase-Enrollment",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Abort_Verification,
            { "Abort-Verification", "mrcpv2.Abort-Verification",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Accept,
            { "Accept", "mrcpv2.Accept",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Accept_Charset,
            { "Accept-Charset", "mrcpv2.Accept-Charset",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Active_Request_Id_List,
            { "Active-Request-Id-List", "mrcpv2.Active-Request-Id-List",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Adapt_Model,
            { "Adapt-Model", "mrcpv2.Adapt-Model",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Audio_Fetch_Hint,
            { "Audio-Fetch-Hint", "mrcpv2.Audio-Fetch-Hint",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Cache_Control,
            { "Cache-Control", "mrcpv2.Cache-Control",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Cancel_If_Queue,
            { "Cancel-If-Queue", "mrcpv2.Cancel-If-Queue",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Capture_On_Speech,
            { "Capture-On-Speech", "mrcpv2.Capture-On-Speech",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Channel_Identifier,
            { "Channel-Identifier", "mrcpv2.Channel-Identifier",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Clash_Threshold,
            { "Clash-Threshold", "mrcpv2.Clash-Threshold",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Clear_Dtmf_Buffer,
            { "Clear-Dtmf-Buffer", "mrcpv2.Clear-Dtmf-Buffer",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Completion_Cause,
            { "Completion-Cause", "mrcpv2.Completion-Cause",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Completion_Reason,
            { "Completion-Reason", "mrcpv2.Completion-Reason",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Confidence_Threshold,
            { "Confidence-Threshold", "mrcpv2.Confidence-Threshold",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Confusable_Phrases_URI,
            { "Confusable-Phrases-URI", "mrcpv2.Confusable-Phrases-URI",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Consistency_Threshold,
            { "Consistency-Threshold", "mrcpv2.Consistency-Threshold",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Content_Base,
            { "Content-Base", "mrcpv2.Content-Base",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Content_Encoding,
            { "Content-Encoding", "mrcpv2.Content-Encoding",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Content_ID,
            { "Content-ID", "mrcpv2.Content-ID",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Content_Length,
            { "Content-Length", "mrcpv2.Content-Length",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Content_Location,
            { "Content-Location", "mrcpv2.Content-Location",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Content_Type,
            { "Content-Type", "mrcpv2.Content-Type",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Dtmf_Buffer_Time,
            { "Dtmf-Buffer-Time", "mrcpv2.Dtmf-Buffer-Time",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Dtmf_Interdigit_Timeout,
            { "Dtmf-Interdigit-Timeout", "mrcpv2.Dtmf-Interdigit-Timeout",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Dtmf_Term_Char,
            { "Dtmf-Term-Char", "mrcpv2.Dtmf-Term-Char",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Dtmf_Term_Timeout,
            { "Dtmf-Term-Timeout", "mrcpv2.Dtmf-Term-Timeout",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Early_No_Match,
            { "Early-No-Match", "mrcpv2.Early-No-Match",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Enroll_Utterance,
            { "Enroll-Utterance", "mrcpv2.Enroll-Utterance",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Failed_URI,
            { "Failed-URI", "mrcpv2.Failed-URI",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Failed_URI_Cause,
            { "Failed-URI-Cause", "mrcpv2.Failed-URI-Cause",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Fetch_Hint,
            { "Fetch-Hint", "mrcpv2.Fetch-Hint",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Fetch_Timeout,
            { "Fetch-Timeout", "mrcpv2.Fetch-Timeout",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Final_Silence,
            { "Final-Silence", "mrcpv2.Final-Silence",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Hotword_Max_Duration,
            { "Hotword-Max-Duration", "mrcpv2.Hotword-Max-Duration",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Hotword_Min_Duration,
            { "Hotword-Min-Duration", "mrcpv2.Hotword-Min-Duration",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Input_Type,
            { "Input-Type", "mrcpv2.Input-Type",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Input_Waveform_URI,
            { "Input-Waveform-URI", "mrcpv2.Input-Waveform-URI",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Interpret_Text,
            { "Interpret-Text", "mrcpv2.Interpret-Text",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Jump_Size,
            { "Jump-Size", "mrcpv2.Jump-Size",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Kill_On_Barge_In,
            { "Kill-On-Barge-In", "mrcpv2.Kill-On-Barge-In",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Lexicon_Search_Order,
            { "Lexicon-Search-Order", "mrcpv2.Lexicon-Search-Order",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Load_Lexicon,
            { "Load-Lexicon", "mrcpv2.Load-Lexicon",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Logging_Tag,
            { "Logging-Tag", "mrcpv2.Logging-Tag",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Max_Time,
            { "Max-Time", "mrcpv2.Max-Time",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Media_Type,
            { "Media-Type", "mrcpv2.Media-Type",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Min_Verification_Score,
            { "Min-Verification-Score", "mrcpv2.Min-Verification-Score",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_N_Best_List_Length,
            { "N-Best-List-Length", "mrcpv2.N-Best-List-Length",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_New_Audio_Channel,
            { "New-Audio-Channel", "mrcpv2.New-Audio-Channel",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_New_Phrase_ID,
            { "New-Phrase-ID", "mrcpv2.New-Phrase-ID",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_No_Input_Timeout,
            { "No-Input-Timeout", "mrcpv2.No-Input-Timeout",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Num_Max_Verification_Phrases,
            { "Num-Max-Verification-Phrases", "mrcpv2.Num-Max-Verification-Phrases",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Num_Min_Consistent_Pronunciations,
            { "Num-Min-Consistent-Pronunciations", "mrcpv2.Num-Min-Consistent-Pronunciations",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Num_Min_Verification_Phrases,
            { "Num-Min-Verification-Phrases", "mrcpv2.Num-Min-Verification-Phrases",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Personal_Grammar_URI,
            { "Personal-Grammar-URI", "mrcpv2.Personal-Grammar-URI",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Phrase_ID,
            { "Phrase-ID", "mrcpv2.Phrase-ID",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Phrase_NL,
            { "Phrase-NL", "mrcpv2.Phrase-NL",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Prosody_Contour,
            { "Prosody-Contour", "mrcpv2.Prosody-Contour",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Prosody_Duration,
            { "Prosody-Duration", "mrcpv2.Prosody-Duration",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Prosody_Pitch,
            { "Prosody-Pitch", "mrcpv2.Prosody-Pitch",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Prosody_Range,
            { "Prosody-Range", "mrcpv2.Prosody-Range",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Prosody_Rate,
            { "Prosody-Rate", "mrcpv2.Prosody-Rate",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Prosody_Volume,
            { "Prosody-Volume", "mrcpv2.Prosody-Volume",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Proxy_Sync_Id,
            { "Proxy-Sync-Id", "mrcpv2.Proxy-Sync-Id",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Recognition_Mode,
            { "Recognition-Mode", "mrcpv2.Recognition-Mode",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Recognition_Timeout,
            { "Recognition-Timeout", "mrcpv2.Recognition-Timeout",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Recognizer_Context_Block,
            { "Recognizer-Context-Block", "mrcpv2.Recognizer-Context-Block",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Record_URI,
            { "Record-URI", "mrcpv2.Record-URI",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Repository_URI,
            { "Repository-URI", "mrcpv2.Repository-URI",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Save_Best_Waveform,
            { "Save-Best-Waveform", "mrcpv2.Save-Best-Waveform",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Save_Waveform,
            { "Save-Waveform", "mrcpv2.Save-Waveform",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Sensitivity_Level,
            { "Sensitivity-Level", "mrcpv2.Sensitivity-Level",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Set_Cookie,
            { "Set-Cookie", "mrcpv2.Set-Cookie",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Speak_Length,
            { "Speak-Length", "mrcpv2.Speak-Length",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Speak_Restart,
            { "Speak-Restart", "mrcpv2.Speak-Restart",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Speaker_Profile,
            { "Speaker-Profile", "mrcpv2.Speaker-Profile",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Speech_Complete_Timeout,
            { "Speech-Complete-Timeout", "mrcpv2.Speech-Complete-Timeout",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Speech_Incomplete_Timeout,
            { "Speech-Incomplete-Timeout", "mrcpv2.Speech-Incomplete-Timeout",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Speech_Language,
            { "Speech-Language", "mrcpv2.Speech-Language",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Speech_Marker,
            { "Speech-Marker", "mrcpv2.Speech-Marker",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Speed_Vs_Accuracy,
            { "Speed-Vs-Accuracy", "mrcpv2.Speed-Vs-Accuracy",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Start_Input_Timers,
            { "Start-Input-Timers", "mrcpv2.Start-Input-Timers",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Trim_Length,
            { "Trim-Length", "mrcpv2.Trim-Length",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Vendor_Specific_Parameters,
            { "Vendor-Specific-Parameters", "mrcpv2.Vendor-Specific-Parameters",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Ver_Buffer_Utterance,
            { "Ver-Buffer-Utterance", "mrcpv2.Ver-Buffer-Utterance",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Verification_Mode,
            { "Verification-Mode", "mrcpv2.Verification-Mode",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Voice_Age,
            { "Voice-Age", "mrcpv2.Voice-Age",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Voice_Gender,
            { "Voice-Gender", "mrcpv2.Voice-Gender",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Voice_Name,
            { "Voice-Name", "mrcpv2.Voice-Name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Voice_Variant,
            { "Voice-Variant", "mrcpv2.Voice-Variant",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Voiceprint_Exists,
            { "Voiceprint-Exists", "mrcpv2.Voiceprint-Exists",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Voiceprint_Identifier,
            { "Voiceprint-Identifier", "mrcpv2.Voiceprint-Identifier",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Waveform_URI,
            { "Waveform-URI", "mrcpv2.Waveform-URI",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mrcpv2_Weight,
            { "Weight", "mrcpv2.Weight",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL },
        }
    };

    static gint *ett[] = {
        &ett_mrcpv2,
        &ett_Request_Line,
        &ett_Response_Line,
        &ett_Event_Line,
        &ett_Status_Code
    };

    range_convert_str(&global_mrcpv2_tcp_range, TCP_DEFAULT_RANGE, 65535);
    mrcpv2_tcp_range = range_empty();	

    proto_mrcpv2 = proto_register_protocol(
        "Media Resource Control Protocol Version 2 (MRCPv2)",
        "MRCPv2",
        "mrcpv2");

    proto_register_field_array(proto_mrcpv2, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    mrcpv2_module = prefs_register_protocol(proto_mrcpv2, proto_reg_handoff_mrcpv2);

    prefs_register_obsolete_preference(mrcpv2_module, "tcp.port");	
    prefs_register_range_preference(mrcpv2_module, "tcp.port_range", "MRCPv2 TCP Port",
         "MRCPv2 TCP Ports Range",
         &global_mrcpv2_tcp_range, 65535);
}

void
proto_reg_handoff_mrcpv2(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t mrcpv2_handle;

    if (!initialized) {
        mrcpv2_handle = new_create_dissector_handle(dissect_mrcpv2_tcp, proto_mrcpv2);
        initialized = TRUE;
    } else {
        dissector_delete_uint_range ("tcp.port", mrcpv2_tcp_range, mrcpv2_handle);
        g_free (mrcpv2_tcp_range);
    }

    mrcpv2_tcp_range = range_copy (global_mrcpv2_tcp_range);
    dissector_add_uint_range ("tcp.port", mrcpv2_tcp_range, mrcpv2_handle);
}
/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
