/* packet-usb-i1d3.c
 * Dissects the X-Rite i1 Display Pro (and derivatives) USB protocol
 * Copyright 2016, Etienne Dechamps <etienne@edechamps.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This code dissects the USB protocol used for communicating with a
 * X-Rite i1 Display Pro colorimeter, as well as similar hardware such
 * as ColorMunki Display.
 *
 * Note that this protocol is proprietary and no public specification
 * exists. This code is largely based on Graeme Gill's reverse
 * engineering work for ArgyllCMS (see spectro/i1d3.c in the ArgyllCMS
 * source code).
 *
 * Because some aspects of the protocol are not yet fully understood,
 * this dissector might fail to properly parse some packets, especially
 * in unusual scenarios such as error conditions and the like.
 */

#include <config.h>
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/expert.h>

void proto_register_usb_i1d3(void);
void proto_reg_handoff_usb_i1d3(void);

#define USB_I1D3_PACKET_LENGTH (64)
#define USB_I1D3_CLOCK_FREQUENCY (12e6)  // 12 MHz
#define USB_I1D3_LED_OFFTIME_FACTOR (USB_I1D3_CLOCK_FREQUENCY / (1 << 19))
#define USB_I1D3_LED_ONTIME_FACTOR (USB_I1D3_CLOCK_FREQUENCY / (1 << 19))
#define USB_I1D3_LED_ONTIME_FADE_FACTOR (USB_I1D3_CLOCK_FREQUENCY / (1 << 23))

static int proto_usb_i1d3 = -1;
static int ett_usb_i1d3 = -1;
static int ett_usb_i1d3_measured_duration = -1;
static int ett_usb_i1d3_requested_edge_count = -1;

static int hf_usb_i1d3_challenge_response = -1;
static int hf_usb_i1d3_challenge_data = -1;
static int hf_usb_i1d3_challenge_decode_key = -1;
static int hf_usb_i1d3_challenge_encode_key = -1;
static int hf_usb_i1d3_command_code = -1;
static int hf_usb_i1d3_diffuser_position = -1;
static int hf_usb_i1d3_echoed_command_code = -1;
static int hf_usb_i1d3_firmdate = -1;
static int hf_usb_i1d3_firmver = -1;
static int hf_usb_i1d3_information = -1;
static int hf_usb_i1d3_measured_duration = -1;
static int hf_usb_i1d3_measured_duration_red = -1;
static int hf_usb_i1d3_measured_duration_green = -1;
static int hf_usb_i1d3_measured_duration_blue = -1;
static int hf_usb_i1d3_measured_edge_count = -1;
static int hf_usb_i1d3_measured_edge_count_red = -1;
static int hf_usb_i1d3_measured_edge_count_green = -1;
static int hf_usb_i1d3_measured_edge_count_blue = -1;
static int hf_usb_i1d3_led_mode = -1;
static int hf_usb_i1d3_led_offtime = -1;
static int hf_usb_i1d3_led_ontime = -1;
static int hf_usb_i1d3_led_pulse_count = -1;
static int hf_usb_i1d3_locked = -1;
static int hf_usb_i1d3_prodname = -1;
static int hf_usb_i1d3_prodtype = -1;
static int hf_usb_i1d3_request_in = -1;
static int hf_usb_i1d3_requested_edge_count = -1;
static int hf_usb_i1d3_requested_edge_count_red = -1;
static int hf_usb_i1d3_requested_edge_count_green = -1;
static int hf_usb_i1d3_requested_edge_count_blue = -1;
static int hf_usb_i1d3_requested_integration_time = -1;
static int hf_usb_i1d3_response_code = -1;
static int hf_usb_i1d3_response_in = -1;
static int hf_usb_i1d3_readextee_data = -1;
static int hf_usb_i1d3_readextee_offset = -1;
static int hf_usb_i1d3_readextee_length = -1;
static int hf_usb_i1d3_readintee_data = -1;
static int hf_usb_i1d3_readintee_offset = -1;
static int hf_usb_i1d3_readintee_length = -1;
static int hf_usb_i1d3_status = -1;
static int hf_usb_i1d3_unlock_result = -1;

static expert_field ei_usb_i1d3_echoed_command_code_mismatch = EI_INIT;
static expert_field ei_usb_i1d3_error = EI_INIT;
static expert_field ei_usb_i1d3_unexpected_response = EI_INIT;
static expert_field ei_usb_i1d3_unknown_command = EI_INIT;
static expert_field ei_usb_i1d3_unknown_diffuser_position = EI_INIT;
static expert_field ei_usb_i1d3_unlock_failed = EI_INIT;
static expert_field ei_usb_i1d3_unusual_length = EI_INIT;

// Derived from ArgyllCMS spectro/i1d3.c.
typedef enum _usb_i1d3_command_code {
    USB_I1D3_GET_INFO      = 0x0000,
    USB_I1D3_STATUS        = 0x0001,
    USB_I1D3_PRODNAME      = 0x0010,
    USB_I1D3_PRODTYPE      = 0x0011,
    USB_I1D3_FIRMVER       = 0x0012,
    USB_I1D3_FIRMDATE      = 0x0013,
    USB_I1D3_LOCKED        = 0x0020,
    USB_I1D3_MEASURE1      = 0x0100,
    USB_I1D3_MEASURE2      = 0x0200,
    USB_I1D3_READINTEE     = 0x0800,
    USB_I1D3_READEXTEE     = 0x1200,
    USB_I1D3_SETLED        = 0x2100,
    USB_I1D3_RD_SENSOR     = 0x9300,
    USB_I1D3_GET_DIFF      = 0x9400,
    USB_I1D3_LOCKCHAL      = 0x9900,
    USB_I1D3_LOCKRESP      = 0x9a00,
    USB_I1D3_RELOCK        = 0x9b00,
} usb_i1d3_command_code;
static const value_string usb_i1d3_command_code_strings[] = {
    {USB_I1D3_GET_INFO,    "Get information"},
    {USB_I1D3_STATUS,      "Get status"},
    {USB_I1D3_PRODNAME,    "Get product name"},
    {USB_I1D3_PRODTYPE,    "Get product type"},
    {USB_I1D3_FIRMVER,     "Get firmware version"},
    {USB_I1D3_FIRMDATE,    "Get firmware date"},
    {USB_I1D3_LOCKED,      "Get locked status"},
    {USB_I1D3_MEASURE1,    "Make measurement (fixed integration time)"},
    {USB_I1D3_MEASURE2,    "Make measurement (fixed edge count)"},
    {USB_I1D3_READINTEE,   "Read internal EEPROM"},
    {USB_I1D3_READEXTEE,   "Read external EEPROM"},
    {USB_I1D3_SETLED,      "Set LED state"},
    {USB_I1D3_RD_SENSOR,   "Read analog sensor"},
    {USB_I1D3_GET_DIFF,    "Get diffuser position"},
    {USB_I1D3_LOCKCHAL,    "Request lock challenge"},
    {USB_I1D3_LOCKRESP,    "Unlock"},
    {USB_I1D3_RELOCK,      "Relock"},
    {0, NULL}
};

typedef enum _usb_i1d3_led_mode {
    USB_I1D3_LED_BLINK         = 1,
    USB_I1D3_LED_BLINK_FADE_ON = 3,
} usb_i1d3_led_mode;
static const value_string usb_i1d3_led_mode_strings[] = {
    {USB_I1D3_LED_BLINK, "Blink"},
    {USB_I1D3_LED_BLINK_FADE_ON, "Blink, fade on"},
    {0, NULL}
};

typedef enum _usb_i1d3_diffuser_position {
    USB_I1D3_DIFFUSER_DISPLAY = 0,
    USB_I1D3_DIFFUSER_AMBIENT = 1,
} usb_i1d3_diffuser_position;
static const value_string usb_i1d3_diffuser_position_strings[] = {
    {USB_I1D3_DIFFUSER_DISPLAY, "Display"},
    {USB_I1D3_DIFFUSER_AMBIENT, "Ambient"},
    {0, NULL}
};

typedef struct _usb_i1d3_transaction_t {
    guint32 request;
    guint32 response;
    guint32 command_code;
    guint32 offset;
    guint32 length;
} usb_i1d3_transaction_t;

typedef struct _usb_i1d3_conversation_t {
    wmem_map_t *request_to_transaction;
    wmem_map_t *response_to_transaction;
    guint32 previous_packet;
} usb_i1d3_conversation_t;

static const unit_name_string units_cycle_cycles = { " cycle", " cycles" };
static const unit_name_string units_edge_edges = { " edge", " edges" };
static const unit_name_string units_pulse_pulses = { " pulse", " pulses" };

static usb_i1d3_conversation_t *usb_i1d3_get_conversation(packet_info *pinfo) {
    conversation_t *conversation = find_or_create_conversation(pinfo);
    usb_i1d3_conversation_t* i1d3_conversation =
        (usb_i1d3_conversation_t *)conversation_get_proto_data(
                conversation, proto_usb_i1d3);
    if (!i1d3_conversation) {
        i1d3_conversation = wmem_new0(
                wmem_file_scope(), usb_i1d3_conversation_t);
        i1d3_conversation->request_to_transaction = wmem_map_new(
                wmem_file_scope(), g_direct_hash, g_direct_equal);
        i1d3_conversation->response_to_transaction = wmem_map_new(
                wmem_file_scope(), g_direct_hash, g_direct_equal);
        conversation_add_proto_data(
                conversation, proto_usb_i1d3, i1d3_conversation);
    }
    return i1d3_conversation;
}

static usb_i1d3_transaction_t *usb_i1d3_create_transaction(
        usb_i1d3_conversation_t *conversation, guint32 request) {
    usb_i1d3_transaction_t *transaction = wmem_new0(
            wmem_file_scope(), usb_i1d3_transaction_t);
    transaction->request = request;
    wmem_map_insert(
            conversation->request_to_transaction,
            GUINT_TO_POINTER(transaction->request), (void *)transaction);
    return transaction;
}

static void dissect_usb_i1d3_command(
        tvbuff_t *tvb, packet_info *pinfo,
        usb_i1d3_conversation_t *conversation, proto_tree *tree) {
    // Parsing the command code is a bit tricky: if the most significant
    // byte is non-zero, the command code is the most significant byte,
    // *and* the next byte is the first byte of the payload.
    guint32 command_code = tvb_get_ntohs(tvb, 0);
    guint32 command_code_msb = command_code & 0xff00;
    gint command_code_length = 2;
    if (command_code_msb) {
        command_code = command_code_msb;
        command_code_length = 1;
    }
    proto_item *command_code_item = proto_tree_add_uint(
            tree, hf_usb_i1d3_command_code, tvb, 0, command_code_length,
            command_code);

    usb_i1d3_transaction_t *transaction;
    if (!PINFO_FD_VISITED(pinfo)) {
        transaction = usb_i1d3_create_transaction(conversation, pinfo->num);
        transaction->command_code = command_code;
    } else {
        transaction = (usb_i1d3_transaction_t *)wmem_map_lookup(
                conversation->request_to_transaction,
                GUINT_TO_POINTER(pinfo->num));
    }
    DISSECTOR_ASSERT(transaction);

    if (transaction->response != 0) {
        proto_item *response_item = proto_tree_add_uint(
                tree, hf_usb_i1d3_response_in, tvb, 0, 0,
                transaction->response);
        proto_item_set_generated(response_item);
    }

    const gchar *command_code_string = try_val_to_str(
            command_code, usb_i1d3_command_code_strings);
    if (command_code_string) {
        col_set_str(pinfo->cinfo, COL_INFO, command_code_string);
    } else {
        expert_add_info(pinfo, command_code_item,
                &ei_usb_i1d3_unknown_command);
        col_set_str(pinfo->cinfo, COL_INFO, "Unknown command");
    }

    switch (command_code) {
        case USB_I1D3_LOCKRESP: {
            // TODO: verify that the challenge response is correct
            proto_tree_add_item(
                    tree, hf_usb_i1d3_challenge_response, tvb, 24, 16, ENC_NA);
            break;
        }

        case USB_I1D3_READINTEE: {
            guint32 offset, length;
            proto_tree_add_item_ret_uint(
                    tree, hf_usb_i1d3_readintee_offset, tvb,
                    1, 1, ENC_NA, &offset);
            proto_tree_add_item_ret_uint(
                    tree, hf_usb_i1d3_readintee_length, tvb,
                    2, 1, ENC_NA, &length);
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s (offset: %u, length: %u)",
                    command_code_string, offset, length);
            if (!PINFO_FD_VISITED(pinfo)) {
                transaction->offset = offset;
                transaction->length = length;
            }
            break;
        }

        case USB_I1D3_READEXTEE: {
            guint32 offset, length;
            proto_tree_add_item_ret_uint(
                    tree, hf_usb_i1d3_readextee_offset, tvb,
                    1, 2, ENC_BIG_ENDIAN, &offset);
            proto_tree_add_item_ret_uint(
                    tree, hf_usb_i1d3_readextee_length, tvb,
                    3, 1, ENC_NA, &length);
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s (offset: %u, length: %u)",
                    command_code_string, offset, length);
            if (!PINFO_FD_VISITED(pinfo)) {
                transaction->offset = offset;
                transaction->length = length;
            }
            break;
        }

        case USB_I1D3_MEASURE1: {
            guint32 integration_time;
            proto_item *integration_time_item = proto_tree_add_item_ret_uint(
                    tree, hf_usb_i1d3_requested_integration_time, tvb, 1, 4,
                    ENC_LITTLE_ENDIAN, &integration_time);
            double integration_time_seconds =
                integration_time / USB_I1D3_CLOCK_FREQUENCY;
            proto_item_append_text(
                    integration_time_item,
                    " [%.6f seconds]", integration_time_seconds);
            col_add_fstr(pinfo->cinfo, COL_INFO,
                    "Measure for %.6fs", integration_time_seconds);
            break;
        }
        case USB_I1D3_MEASURE2: {
            proto_item *edge_count_item = proto_tree_add_item(
                    tree, hf_usb_i1d3_requested_edge_count, tvb, 1, 6, ENC_NA);
            proto_tree *edge_count_tree = proto_item_add_subtree(
                    edge_count_item, ett_usb_i1d3_requested_edge_count);
            guint32 edge_count_red, edge_count_green, edge_count_blue;
            proto_tree_add_item_ret_uint(
                    edge_count_tree, hf_usb_i1d3_requested_edge_count_red, tvb,
                    1, 2, ENC_LITTLE_ENDIAN, &edge_count_red);
            proto_tree_add_item_ret_uint(
                    edge_count_tree, hf_usb_i1d3_requested_edge_count_green, tvb,
                    3, 2, ENC_LITTLE_ENDIAN, &edge_count_green);
            proto_tree_add_item_ret_uint(
                    edge_count_tree, hf_usb_i1d3_requested_edge_count_blue, tvb,
                    5, 2, ENC_LITTLE_ENDIAN, &edge_count_blue);
            proto_item_append_text(
                    edge_count_item, ": R%u G%u B%u",
                    edge_count_red, edge_count_green, edge_count_blue);
            col_add_fstr(pinfo->cinfo, COL_INFO, "Measure R%u G%u B%u edges",
                    edge_count_red, edge_count_green, edge_count_blue);
            break;
        }
        case USB_I1D3_SETLED: {
            guint32 led_mode, led_offtime, led_ontime, pulse_count;
            proto_tree_add_item_ret_uint(
                    tree, hf_usb_i1d3_led_mode, tvb, 1, 1, ENC_NA, &led_mode);
            proto_item *led_offtime_item = proto_tree_add_item_ret_uint(
                    tree, hf_usb_i1d3_led_offtime, tvb, 2, 1, ENC_NA,
                    &led_offtime);
            double led_offtime_seconds =
                led_offtime / USB_I1D3_LED_OFFTIME_FACTOR;
            proto_item_append_text(
                    led_offtime_item, " [%.6f seconds]", led_offtime_seconds);
            proto_item *led_ontime_item = proto_tree_add_item_ret_uint(
                    tree, hf_usb_i1d3_led_ontime, tvb, 3, 1, ENC_NA,
                    &led_ontime);
            double led_ontime_seconds =
                led_ontime / ((led_mode == USB_I1D3_LED_BLINK) ?
                        USB_I1D3_LED_ONTIME_FACTOR :
                        USB_I1D3_LED_ONTIME_FADE_FACTOR);
            proto_item_append_text(
                    led_ontime_item, " [%.6f seconds]", led_ontime_seconds);
            proto_item *pulse_count_item = proto_tree_add_item_ret_uint(
                    tree, hf_usb_i1d3_led_pulse_count, tvb, 4, 1, ENC_NA,
                    &pulse_count);
            if (pulse_count == 0x80) {
                proto_item_append_text(pulse_count_item, " [infinity]");
                col_add_fstr(pinfo->cinfo, COL_INFO,
                        "Pulse LED off (%.6fs) and on (%.6fs%s) "
                        "indefinitely", led_offtime_seconds, led_ontime_seconds,
                        (led_mode == USB_I1D3_LED_BLINK_FADE_ON) ?
                        " fading" : "");
            } else {
                col_add_fstr(pinfo->cinfo, COL_INFO,
                        "Pulse LED off (%.6fs) and on (%.6fs%s) "
                        "%u times", led_offtime_seconds, led_ontime_seconds,
                        (led_mode == USB_I1D3_LED_BLINK_FADE_ON) ?
                        " fading" : "", pulse_count);
            }
        }
    }
}

static void dissect_usb_i1d3_response(
        tvbuff_t *tvb, packet_info *pinfo,
        usb_i1d3_conversation_t *conversation, proto_tree *tree) {
    // The response packet does not contain any information about the command
    // it is a response to, so we need to reconstruct this information using the
    // previous packet that we saw.
    //
    // Note: currently, for simplicity's sake, this assumes that there is only
    // one inflight request at any given time - in other words, that there is no
    // pipelining going on. It is not clear if the device would even be able to
    // service more than one request at the same time in the first place.
    usb_i1d3_transaction_t *transaction;
    if (!PINFO_FD_VISITED(pinfo)) {
        transaction = (usb_i1d3_transaction_t *)wmem_map_lookup(
                conversation->request_to_transaction,
                GUINT_TO_POINTER(conversation->previous_packet));
        if (transaction) {
            DISSECTOR_ASSERT(transaction->response == 0);
            transaction->response = pinfo->num;
            wmem_map_insert(
                    conversation->response_to_transaction,
                    GUINT_TO_POINTER(transaction->response),
                    (void *)transaction);
        }
    } else {
        // After the first pass, we can't use previous_packet anymore since
        // there is no guarantee the dissector is called in order, so we use
        // the reverse mapping that we populated above.
        transaction = (usb_i1d3_transaction_t *)wmem_map_lookup(
                conversation->response_to_transaction,
                GUINT_TO_POINTER(pinfo->num));
    }
    if (transaction) {
        DISSECTOR_ASSERT(transaction->response == pinfo->num);
        DISSECTOR_ASSERT(transaction->request != 0);
    }

    proto_item *request_item = proto_tree_add_uint(
            tree, hf_usb_i1d3_request_in, tvb, 0, 0,
            transaction ? transaction->request : 0);
    proto_item_set_generated(request_item);
    if (!transaction) {
        expert_add_info(pinfo, request_item, &ei_usb_i1d3_unexpected_response);
    } else {
        proto_item *command_code_item = proto_tree_add_uint(
                tree, hf_usb_i1d3_command_code, tvb, 0, 0,
                transaction->command_code);
        proto_item_set_generated(command_code_item);
    }

    const gchar *command_string = transaction ? try_val_to_str(
            transaction->command_code, usb_i1d3_command_code_strings) : NULL;
    if (!command_string) command_string = "unknown";

    guint32 response_code;
    proto_item *response_code_item = proto_tree_add_item_ret_uint(
            tree, hf_usb_i1d3_response_code, tvb, 0, 1, ENC_NA, &response_code);
    proto_item_append_text(
            response_code_item, " (%s)", (response_code == 0) ? "OK" : "error");
    if (response_code != 0) {
        col_add_fstr(
                pinfo->cinfo, COL_INFO, "Error code %u (%s)",
                response_code, command_string);
        expert_add_info(pinfo, response_code_item, &ei_usb_i1d3_error);
        return;
    }

    col_add_fstr(pinfo->cinfo, COL_INFO, "OK (%s)", command_string);

    if (!transaction) return;

    // As mentioned in ArgyllCMS spectro/i1d3.c, the second byte is usually the
    // first byte of the command code, except for GET_DIFF.
    if (transaction->command_code != USB_I1D3_GET_DIFF) {
        guint32 echoed_command_code;
        proto_item *echoed_command_code_item = proto_tree_add_item_ret_uint(
                tree, hf_usb_i1d3_echoed_command_code, tvb, 1, 1, ENC_NA,
                &echoed_command_code);
        guint8 expected_command_code = transaction->command_code >> 8;
        proto_item_append_text(
                echoed_command_code_item, " [expected 0x%02x]",
                expected_command_code);
        if (echoed_command_code != expected_command_code) {
            expert_add_info(
                    pinfo, echoed_command_code_item,
                    &ei_usb_i1d3_echoed_command_code_mismatch);
        }
    }

    switch (transaction->command_code) {
        case USB_I1D3_GET_INFO: {
            const guint8 *information;
            proto_tree_add_item_ret_string(
                    tree, hf_usb_i1d3_information, tvb, 2, -1,
                    ENC_ASCII | ENC_NA, wmem_packet_scope(), &information);
            col_add_fstr(
                    pinfo->cinfo, COL_INFO, "Information: %s", information);
            break;
        }
        case USB_I1D3_STATUS: {
            guint32 status;
            proto_item *status_item = proto_tree_add_item_ret_uint(
                    tree, hf_usb_i1d3_status, tvb, 2, 3, ENC_BIG_ENDIAN,
                    &status);
            const gchar *status_string =
                ((status & 0xff00ff) != 0 || (status & 0x00ff00) >= 5) ?
                "OK" : "Bad";
            proto_item_append_text(status_item, " [%s]", status_string);
            col_add_fstr(
                     pinfo->cinfo, COL_INFO, "Status: 0x%06x (%s)",
                     status, status_string);
            break;
        }
        case USB_I1D3_PRODNAME: {
            const guint8 *prodname;
            proto_tree_add_item_ret_string(
                    tree, hf_usb_i1d3_prodname, tvb, 2, -1,
                    ENC_ASCII | ENC_NA, wmem_packet_scope(), &prodname);
            col_add_fstr(pinfo->cinfo, COL_INFO, "Product name: %s", prodname);
            break;
        }
        case USB_I1D3_PRODTYPE: {
            guint32 prodtype;
            proto_tree_add_item_ret_uint(
                    tree, hf_usb_i1d3_prodtype, tvb, 3, 2, ENC_BIG_ENDIAN,
                    &prodtype);
            col_add_fstr(
                    pinfo->cinfo, COL_INFO, "Product type: 0x%04x",
                    prodtype);
            break;
        }
        case USB_I1D3_FIRMVER: {
            const guint8 *firmver;
            proto_tree_add_item_ret_string(
                    tree, hf_usb_i1d3_firmver, tvb, 2, -1,
                    ENC_ASCII | ENC_NA, wmem_packet_scope(), &firmver);
            col_add_fstr(
                    pinfo->cinfo, COL_INFO, "Firmware version: %s", firmver);
            break;
        }
        case USB_I1D3_FIRMDATE: {
            const guint8 *firmdate;
            proto_tree_add_item_ret_string(
                    tree, hf_usb_i1d3_firmdate, tvb, 2, -1,
                    ENC_ASCII | ENC_NA, wmem_packet_scope(), &firmdate);
            col_add_fstr(pinfo->cinfo, COL_INFO, "Firmware date: %s", firmdate);
            break;
        }
        case USB_I1D3_LOCKED: {
            guint32 locked;
            proto_item *locked_item = proto_tree_add_item_ret_uint(
                    tree, hf_usb_i1d3_locked, tvb, 2, 2, ENC_BIG_ENDIAN,
                    &locked);
            const gchar *locked_string =
                ((locked & 0xff00) != 0 || (locked & 0x00ff) == 0) ?
                "Unlocked" : "Locked";
            proto_item_append_text(locked_item, " [%s]", locked_string);
            col_add_fstr(
                     pinfo->cinfo, COL_INFO, "Locked status: 0x%04x (%s)",
                     locked, locked_string);
            break;
        }
        case USB_I1D3_MEASURE1: {
            proto_item *edge_count_item = proto_tree_add_item(
                    tree, hf_usb_i1d3_measured_edge_count, tvb, 2, 12, ENC_NA);
            proto_tree *edge_count_tree = proto_item_add_subtree(
                    edge_count_item, ett_usb_i1d3_requested_edge_count);
            guint32 edge_count_red, edge_count_green, edge_count_blue;
            proto_tree_add_item_ret_uint(
                    edge_count_tree, hf_usb_i1d3_measured_edge_count_red, tvb,
                    2, 4, ENC_LITTLE_ENDIAN, &edge_count_red);
            proto_tree_add_item_ret_uint(
                    edge_count_tree, hf_usb_i1d3_measured_edge_count_green, tvb,
                    6, 4, ENC_LITTLE_ENDIAN, &edge_count_green);
            proto_tree_add_item_ret_uint(
                    edge_count_tree, hf_usb_i1d3_measured_edge_count_blue, tvb,
                    10, 4, ENC_LITTLE_ENDIAN, &edge_count_blue);
            proto_item_append_text(
                    edge_count_item, ": R%u G%u B%u",
                    edge_count_red, edge_count_green, edge_count_blue);
            col_add_fstr(pinfo->cinfo, COL_INFO, "Measured R%u G%u B%u edges",
                    edge_count_red, edge_count_green, edge_count_blue);
            break;
        }
        case USB_I1D3_MEASURE2: {
            proto_item *duration_item = proto_tree_add_item(
                    tree, hf_usb_i1d3_measured_duration, tvb, 2, 12, ENC_NA);
            proto_tree *duration_tree = proto_item_add_subtree(
                    duration_item, ett_usb_i1d3_measured_duration);
            guint32 duration_red, duration_green, duration_blue;
            proto_item *duration_red_item = proto_tree_add_item_ret_uint(
                    duration_tree, hf_usb_i1d3_measured_duration_red,
                    tvb, 2, 4, ENC_LITTLE_ENDIAN, &duration_red);
            double duration_red_seconds =
                duration_red / USB_I1D3_CLOCK_FREQUENCY;
            proto_item_append_text(
                    duration_red_item,
                    " [%.6f seconds]", duration_red_seconds);
            proto_item *duration_green_item = proto_tree_add_item_ret_uint(
                    duration_tree, hf_usb_i1d3_measured_duration_green,
                    tvb, 6, 4, ENC_LITTLE_ENDIAN, &duration_green);
            double duration_green_seconds =
                duration_green / USB_I1D3_CLOCK_FREQUENCY;
            proto_item_append_text(
                    duration_green_item,
                    " [%.6f seconds]", duration_green_seconds);
            proto_item *duration_blue_item = proto_tree_add_item_ret_uint(
                    duration_tree, hf_usb_i1d3_measured_duration_blue,
                    tvb, 10, 4, ENC_LITTLE_ENDIAN, &duration_blue);
            double duration_blue_seconds =
                duration_blue / USB_I1D3_CLOCK_FREQUENCY;
            proto_item_append_text(
                    duration_blue_item,
                    " [%.6f seconds]", duration_blue_seconds);
            proto_item_append_text(
                    duration_item, ": R%.6fs G%.6fs B%.6fs",
                    duration_red_seconds, duration_green_seconds,
                    duration_blue_seconds);
            col_add_fstr(pinfo->cinfo, COL_INFO,
                    "Measured R%.6fs G%.6fs B%.6fs",
                    duration_red_seconds, duration_green_seconds,
                    duration_blue_seconds);
            break;
        }
        case USB_I1D3_READINTEE: {
            proto_item *offset_item = proto_tree_add_uint(
                    tree, hf_usb_i1d3_readintee_offset, tvb, 0, 0,
                    transaction->offset);
            proto_item_set_generated(offset_item);
            proto_item *length_item = proto_tree_add_uint(
                    tree, hf_usb_i1d3_readintee_length, tvb, 0, 0,
                    transaction->length);
            proto_item_set_generated(length_item);
            proto_tree_add_item(
                tree, hf_usb_i1d3_readintee_data, tvb,
                4, transaction->length, ENC_NA);
            col_add_fstr(
                pinfo->cinfo, COL_INFO,
                "Internal EEPROM data (offset: %u, length: %u)",
                transaction->offset, transaction->length);
            break;
        }
        case USB_I1D3_READEXTEE: {
            proto_item *offset_item = proto_tree_add_uint(
                    tree, hf_usb_i1d3_readextee_offset, tvb, 0, 0,
                    transaction->offset);
            proto_item_set_generated(offset_item);
            proto_item *length_item = proto_tree_add_uint(
                    tree, hf_usb_i1d3_readextee_length, tvb, 0, 0,
                    transaction->length);
            proto_item_set_generated(length_item);
            proto_tree_add_item(
                tree, hf_usb_i1d3_readextee_data, tvb,
                5, transaction->length, ENC_NA);
            col_add_fstr(
                pinfo->cinfo, COL_INFO,
                "External EEPROM data (offset: %u, length: %u)",
                transaction->offset, transaction->length);
            break;
        }
        case USB_I1D3_GET_DIFF: {
            guint32 diffuser_position;
            proto_item *diffuser_position_item = proto_tree_add_item_ret_uint(
                    tree, hf_usb_i1d3_diffuser_position, tvb,
                    1, 1, ENC_NA, &diffuser_position);
            const char *diffuser_position_string = try_val_to_str(
                    diffuser_position, usb_i1d3_diffuser_position_strings);
            if (!diffuser_position_string) {
                expert_add_info(
                        pinfo, diffuser_position_item,
                        &ei_usb_i1d3_unknown_diffuser_position);
            }
            col_add_fstr(
                pinfo->cinfo, COL_INFO, "Diffuser position: %s",
                diffuser_position_string ?
                diffuser_position_string : "unknown");
            break;
        }
        case USB_I1D3_LOCKCHAL: {
            proto_tree_add_item(
                    tree, hf_usb_i1d3_challenge_encode_key, tvb, 2, 1, ENC_NA);
            proto_tree_add_item(
                    tree, hf_usb_i1d3_challenge_decode_key, tvb, 3, 1, ENC_NA);
            proto_tree_add_item(
                    tree, hf_usb_i1d3_challenge_data, tvb, 35, 8, ENC_NA);
            break;
        }
        case USB_I1D3_LOCKRESP: {
            guint32 unlock_result;
            proto_item *unlock_result_item = proto_tree_add_item_ret_uint(
                    tree, hf_usb_i1d3_unlock_result, tvb, 2, 1, ENC_NA,
                    &unlock_result);
            int unlock_successful = unlock_result == 0x77;
            const gchar *unlock_result_string = unlock_successful ?
                "Successfully unlocked" : "Failed to unlock";
            proto_item_append_text(
                    unlock_result_item, " [%s]", unlock_result_string);
            if (!unlock_successful) {
                expert_add_info(
                        pinfo, unlock_result_item, &ei_usb_i1d3_unlock_failed);
            }
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s", unlock_result_string);
            break;
        }
    }
}

static int dissect_usb_i1d3(
        tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    if ((pinfo->p2p_dir == P2P_DIR_SENT && pinfo->destport == 0) ||
        (pinfo->p2p_dir == P2P_DIR_RECV && pinfo->srcport == 0)) {
        // The device describes itself as HID class, even though the actual
        // protocol doesn't seem to be based on HID at all. However that means
        // the device will receive (and respond) to some basic HID requests,
        // such as GET_DESCRIPTOR. These HID requests will go to endpoint 0,
        // while actual communication takes place on endpoint 1. Therefore, if
        // we get handed a packet going to/from endpoint 0, reject it and let
        // the HID dissector handle it.
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "i1d3");

    proto_item *usb_i1d3_item = proto_tree_add_item(
            tree, proto_usb_i1d3, tvb, 0, -1, ENC_NA);
    proto_tree *usb_i1d3_tree = proto_item_add_subtree(
            usb_i1d3_item, ett_usb_i1d3);

    // All i1d3 packets seen in the while are fixed-length, with padding added
    // as necessary. It is not clear if using a different length is valid or
    // not.
    if (tvb_reported_length(tvb) != USB_I1D3_PACKET_LENGTH) {
        expert_add_info(pinfo, usb_i1d3_item, &ei_usb_i1d3_unusual_length);
    }

    col_clear(pinfo->cinfo, COL_INFO);
    usb_i1d3_conversation_t *conversation = usb_i1d3_get_conversation(pinfo);
    if (pinfo->p2p_dir == P2P_DIR_SENT) {
        dissect_usb_i1d3_command(tvb, pinfo, conversation, usb_i1d3_tree);
    } else if (pinfo->p2p_dir == P2P_DIR_RECV) {
        dissect_usb_i1d3_response(tvb, pinfo, conversation, usb_i1d3_tree);
    } else {
        DISSECTOR_ASSERT(0);
    }
    conversation->previous_packet = pinfo->num;

    return tvb_captured_length(tvb);
}

void proto_register_usb_i1d3(void)
{
    proto_usb_i1d3 = proto_register_protocol(
            "X-Rite i1 Display Pro (and derivatives) USB protocol",
            "X-Rite i1 Display Pro", "i1d3");

    static gint *ett[] = {
        &ett_usb_i1d3,
        &ett_usb_i1d3_measured_duration,
        &ett_usb_i1d3_requested_edge_count,
    };
    static hf_register_info hf[] = {
        { &hf_usb_i1d3_challenge_response,
            { "Challenge response", "i1d3.challenge_response",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_challenge_data,
            { "Challenge data", "i1d3.challenge_data",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_challenge_decode_key,
            { "Challenge decode XOR value", "i1d3.challenge_decode_key",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_challenge_encode_key,
            { "Challenge encode XOR value", "i1d3.challenge_encode_key",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_command_code,
            { "Command code", "i1d3.command.code", FT_UINT16, BASE_HEX,
                VALS(usb_i1d3_command_code_strings), 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_diffuser_position,
            { "Diffuser position", "i1d3.diffuser_position", FT_UINT8, BASE_DEC,
                VALS(usb_i1d3_diffuser_position_strings), 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_echoed_command_code,
            { "Echoed command code", "i1d3.echoed_command.code", FT_UINT8,
                BASE_HEX, NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_firmdate,
            { "Firmware date", "i1d3.firmdate", FT_STRINGZ, BASE_NONE,
                NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_firmver,
            { "Firmware version", "i1d3.firmver", FT_STRINGZ, BASE_NONE,
                NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_information,
            { "Information", "i1d3.information", FT_STRINGZ, BASE_NONE,
                NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_measured_duration,
            { "Measured duration", "i1d3.measured_duration",
                FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_measured_duration_red,
            { "Red channel",
                "i1d3.measured_duration.red", FT_UINT32,
                BASE_DEC|BASE_UNIT_STRING, &units_cycle_cycles,
                0, NULL, HFILL },
        },
        { &hf_usb_i1d3_measured_duration_green,
            { "Green channel",
                "i1d3.measured_duration.green", FT_UINT32,
                BASE_DEC|BASE_UNIT_STRING, &units_cycle_cycles,
                0, NULL, HFILL },
        },
        { &hf_usb_i1d3_measured_duration_blue,
            { "Blue channel",
                "i1d3.measured_duration.blue", FT_UINT32,
                BASE_DEC|BASE_UNIT_STRING, &units_cycle_cycles,
                0, NULL, HFILL },
        },
        { &hf_usb_i1d3_measured_edge_count,
            { "Measured edge count", "i1d3.measured_edge_count",
                FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_measured_edge_count_red,
            { "Red channel",
                "i1d3.measured_edge_count.red", FT_UINT32,
                BASE_DEC|BASE_UNIT_STRING, &units_edge_edges,
                0, NULL, HFILL },
        },
        { &hf_usb_i1d3_measured_edge_count_green,
            { "Green channel",
                "i1d3.measured_edge_count.green", FT_UINT32,
                BASE_DEC|BASE_UNIT_STRING, &units_edge_edges,
                0, NULL, HFILL },
        },
        { &hf_usb_i1d3_measured_edge_count_blue,
            { "Blue channel",
                "i1d3.measured_edge_count.blue", FT_UINT32,
                BASE_DEC|BASE_UNIT_STRING, &units_edge_edges,
                0, NULL, HFILL },
        },
        { &hf_usb_i1d3_led_mode,
            { "LED mode", "i1d3.led_mode", FT_UINT8, BASE_DEC,
                VALS(usb_i1d3_led_mode_strings), 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_led_offtime,
            { "LED off time", "i1d3.led_offtime", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_led_ontime,
            { "LED on time", "i1d3.led_ontime", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_led_pulse_count,
            { "LED pulse count", "i1d3.led_pulse_count", FT_UINT8,
                BASE_DEC|BASE_UNIT_STRING, &units_pulse_pulses,
                0, NULL, HFILL },
        },
        { &hf_usb_i1d3_locked,
            { "Lock status", "i1d3.locked",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_prodname,
            { "Product name", "i1d3.prodname", FT_STRINGZ, BASE_NONE,
                NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_prodtype,
            { "Product type", "i1d3.prodtype", FT_UINT16, BASE_HEX,
                NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_request_in,
            { "Request in frame", "i1d3.request_in",
                FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST),
                0, NULL, HFILL }
        },
        { &hf_usb_i1d3_requested_edge_count,
            { "Requested edge count", "i1d3.requested_edge_count",
                FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_requested_edge_count_red,
            { "Red channel",
                "i1d3.requested_edge_count.red", FT_UINT16,
                BASE_DEC|BASE_UNIT_STRING, &units_edge_edges,
                0, NULL, HFILL },
        },
        { &hf_usb_i1d3_requested_edge_count_green,
            { "Green channel",
                "i1d3.requested_edge_count.green", FT_UINT16,
                BASE_DEC|BASE_UNIT_STRING, &units_edge_edges,
                0, NULL, HFILL },
        },
        { &hf_usb_i1d3_requested_edge_count_blue,
            { "Blue channel",
                "i1d3.requested_edge_count.blue", FT_UINT16,
                BASE_DEC|BASE_UNIT_STRING, &units_edge_edges,
                0, NULL, HFILL },
        },
        { &hf_usb_i1d3_requested_integration_time,
            { "Requested integration time",
                "i1d3.requested_integration_time", FT_UINT32,
                BASE_DEC|BASE_UNIT_STRING, &units_cycle_cycles,
                0, NULL, HFILL },
        },
        { &hf_usb_i1d3_response_code,
            { "Response code",
                "i1d3.response_code", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_response_in,
            { "Response in frame", "i1d3.response_in",
                FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE),
                0, NULL, HFILL }
        },
        { &hf_usb_i1d3_readintee_data,
            { "Internal EEPROM data", "i1d3.readintee_data",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_readintee_offset,
            { "Internal EEPROM read offset", "i1d3.readintee_offset",
                FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes,
                0, NULL, HFILL },
        },
        { &hf_usb_i1d3_readintee_length,
            { "Internal EEPROM read length", "i1d3.readintee_length",
                FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes,
                0, NULL, HFILL },
        },
        { &hf_usb_i1d3_readextee_data,
            { "External EEPROM data", "i1d3.readextee_data",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_readextee_offset,
            { "External EEPROM read offset", "i1d3.readextee_offset",
                FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes,
                0, NULL, HFILL },
        },
        { &hf_usb_i1d3_readextee_length,
            { "External EEPROM read length", "i1d3.readextee_length",
                FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes,
                0, NULL, HFILL },
        },
        { &hf_usb_i1d3_status,
            { "Status", "i1d3.status",
                FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL },
        },
        { &hf_usb_i1d3_unlock_result,
            { "Unlock result", "i1d3.unlock_result",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL },
        },
    };
    static ei_register_info ei[] = {
        { &ei_usb_i1d3_echoed_command_code_mismatch,
            { "i1d3.echoed_command_code_mismatch", PI_PROTOCOL, PI_ERROR,
                "Echoed command code does not match request", EXPFILL }
        },
        { &ei_usb_i1d3_error,
            { "i1d3.error", PI_RESPONSE_CODE, PI_NOTE,
                "Error response code", EXPFILL }
        },
        { &ei_usb_i1d3_unexpected_response,
            { "i1d3.unexpected_response", PI_SEQUENCE, PI_WARN,
                "Could not match response to a request", EXPFILL }
        },
        { &ei_usb_i1d3_unknown_command,
            { "i1d3.unknown_command", PI_MALFORMED, PI_ERROR,
                "Unknown command code", EXPFILL }
        },
        { &ei_usb_i1d3_unknown_diffuser_position,
            { "i1d3.unknown_diffuser_position", PI_MALFORMED, PI_ERROR,
                "Unknown diffuser position code", EXPFILL }
        },
        { &ei_usb_i1d3_unlock_failed,
            { "i1d3.unlock_failed", PI_RESPONSE_CODE, PI_NOTE,
                "Failed to unlock device", EXPFILL }
        },
        { &ei_usb_i1d3_unusual_length,
            { "i1d3.unusual_length", PI_PROTOCOL, PI_WARN,
                "Packet has unusual length", EXPFILL }
        },
    };

    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_usb_i1d3, hf, array_length(hf));
    expert_module_t *expert_usb_i1d3 = expert_register_protocol(
            proto_usb_i1d3);
    expert_register_field_array(expert_usb_i1d3, ei, array_length(ei));
}

void proto_reg_handoff_usb_i1d3(void) {
    dissector_handle_t usb_i1d3_dissector = create_dissector_handle(
            dissect_usb_i1d3, proto_usb_i1d3);
    dissector_add_for_decode_as("usb.device", usb_i1d3_dissector);
    dissector_add_uint("usb.product", 0x7655020, usb_i1d3_dissector);
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
