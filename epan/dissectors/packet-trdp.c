/* packet-trdp.c
 * Routines for trdp packet dissection
 *
 * The Train Real-Time Data Protocol (TRDP) is defined in IEC 61375-2-3. The
 * protocol is used to exchange Train Communication Network (TCN) process data
 * and message data.
 *
 * Copyright Bombardier Transportation Inc. or its subsidiaries and others, 2013. Florian Weispfenning
 * Copyright Universität Rostock, 2019 (substantial changes leading to GLib-only version). Thorsten Schulz
 * Copyright Stadler Deutschland GmbH, 2022-2025. Thorsten Schulz
 *
 * The new display-filter approach contains aspects and code
 * snippets from the wimaxasncp dissector by Stephen Croll.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/prefs.h>
#include <epan/crc32-tvb.h>
#include <epan/column-utils.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/expert.h>
#include <epan/strutil.h>
#include <wsutil/report_message.h>
#include <wsutil/filesystem.h>
#include "packet-trdp-dict.h"


/* packet-trdp-env.c */
/*
 * The SC-32 generator polynomial
 */
static const uint32_t sctab[256] = {
    0x00000000U, 0xF4ACFB13U, 0x1DF50D35U, 0xE959F626U, 0x3BEA1A6AU,
    0xCF46E179U, 0x261F175FU, 0xD2B3EC4CU, 0x77D434D4U, 0x8378CFC7U,
    0x6A2139E1U, 0x9E8DC2F2U, 0x4C3E2EBEU, 0xB892D5ADU, 0x51CB238BU,
    0xA567D898U, 0xEFA869A8U, 0x1B0492BBU, 0xF25D649DU, 0x06F19F8EU,
    0xD44273C2U, 0x20EE88D1U, 0xC9B77EF7U, 0x3D1B85E4U, 0x987C5D7CU,
    0x6CD0A66FU, 0x85895049U, 0x7125AB5AU, 0xA3964716U, 0x573ABC05U,
    0xBE634A23U, 0x4ACFB130U, 0x2BFC2843U, 0xDF50D350U, 0x36092576U,
    0xC2A5DE65U, 0x10163229U, 0xE4BAC93AU, 0x0DE33F1CU, 0xF94FC40FU,
    0x5C281C97U, 0xA884E784U, 0x41DD11A2U, 0xB571EAB1U, 0x67C206FDU,
    0x936EFDEEU, 0x7A370BC8U, 0x8E9BF0DBU, 0xC45441EBU, 0x30F8BAF8U,
    0xD9A14CDEU, 0x2D0DB7CDU, 0xFFBE5B81U, 0x0B12A092U, 0xE24B56B4U,
    0x16E7ADA7U, 0xB380753FU, 0x472C8E2CU, 0xAE75780AU, 0x5AD98319U,
    0x886A6F55U, 0x7CC69446U, 0x959F6260U, 0x61339973U, 0x57F85086U,
    0xA354AB95U, 0x4A0D5DB3U, 0xBEA1A6A0U, 0x6C124AECU, 0x98BEB1FFU,
    0x71E747D9U, 0x854BBCCAU, 0x202C6452U, 0xD4809F41U, 0x3DD96967U,
    0xC9759274U, 0x1BC67E38U, 0xEF6A852BU, 0x0633730DU, 0xF29F881EU,
    0xB850392EU, 0x4CFCC23DU, 0xA5A5341BU, 0x5109CF08U, 0x83BA2344U,
    0x7716D857U, 0x9E4F2E71U, 0x6AE3D562U, 0xCF840DFAU, 0x3B28F6E9U,
    0xD27100CFU, 0x26DDFBDCU, 0xF46E1790U, 0x00C2EC83U, 0xE99B1AA5U,
    0x1D37E1B6U, 0x7C0478C5U, 0x88A883D6U, 0x61F175F0U, 0x955D8EE3U,
    0x47EE62AFU, 0xB34299BCU, 0x5A1B6F9AU, 0xAEB79489U, 0x0BD04C11U,
    0xFF7CB702U, 0x16254124U, 0xE289BA37U, 0x303A567BU, 0xC496AD68U,
    0x2DCF5B4EU, 0xD963A05DU, 0x93AC116DU, 0x6700EA7EU, 0x8E591C58U,
    0x7AF5E74BU, 0xA8460B07U, 0x5CEAF014U, 0xB5B30632U, 0x411FFD21U,
    0xE47825B9U, 0x10D4DEAAU, 0xF98D288CU, 0x0D21D39FU, 0xDF923FD3U,
    0x2B3EC4C0U, 0xC26732E6U, 0x36CBC9F5U, 0xAFF0A10CU, 0x5B5C5A1FU,
    0xB205AC39U, 0x46A9572AU, 0x941ABB66U, 0x60B64075U, 0x89EFB653U,
    0x7D434D40U, 0xD82495D8U, 0x2C886ECBU, 0xC5D198EDU, 0x317D63FEU,
    0xE3CE8FB2U, 0x176274A1U, 0xFE3B8287U, 0x0A977994U, 0x4058C8A4U,
    0xB4F433B7U, 0x5DADC591U, 0xA9013E82U, 0x7BB2D2CEU, 0x8F1E29DDU,
    0x6647DFFBU, 0x92EB24E8U, 0x378CFC70U, 0xC3200763U, 0x2A79F145U,
    0xDED50A56U, 0x0C66E61AU, 0xF8CA1D09U, 0x1193EB2FU, 0xE53F103CU,
    0x840C894FU, 0x70A0725CU, 0x99F9847AU, 0x6D557F69U, 0xBFE69325U,
    0x4B4A6836U, 0xA2139E10U, 0x56BF6503U, 0xF3D8BD9BU, 0x07744688U,
    0xEE2DB0AEU, 0x1A814BBDU, 0xC832A7F1U, 0x3C9E5CE2U, 0xD5C7AAC4U,
    0x216B51D7U, 0x6BA4E0E7U, 0x9F081BF4U, 0x7651EDD2U, 0x82FD16C1U,
    0x504EFA8DU, 0xA4E2019EU, 0x4DBBF7B8U, 0xB9170CABU, 0x1C70D433U,
    0xE8DC2F20U, 0x0185D906U, 0xF5292215U, 0x279ACE59U, 0xD336354AU,
    0x3A6FC36CU, 0xCEC3387FU, 0xF808F18AU, 0x0CA40A99U, 0xE5FDFCBFU,
    0x115107ACU, 0xC3E2EBE0U, 0x374E10F3U, 0xDE17E6D5U, 0x2ABB1DC6U,
    0x8FDCC55EU, 0x7B703E4DU, 0x9229C86BU, 0x66853378U, 0xB436DF34U,
    0x409A2427U, 0xA9C3D201U, 0x5D6F2912U, 0x17A09822U, 0xE30C6331U,
    0x0A559517U, 0xFEF96E04U, 0x2C4A8248U, 0xD8E6795BU, 0x31BF8F7DU,
    0xC513746EU, 0x6074ACF6U, 0x94D857E5U, 0x7D81A1C3U, 0x892D5AD0U,
    0x5B9EB69CU, 0xAF324D8FU, 0x466BBBA9U, 0xB2C740BAU, 0xD3F4D9C9U,
    0x275822DAU, 0xCE01D4FCU, 0x3AAD2FEFU, 0xE81EC3A3U, 0x1CB238B0U,
    0xF5EBCE96U, 0x01473585U, 0xA420ED1DU, 0x508C160EU, 0xB9D5E028U,
    0x4D791B3BU, 0x9FCAF777U, 0x6B660C64U, 0x823FFA42U, 0x76930151U,
    0x3C5CB061U, 0xC8F04B72U, 0x21A9BD54U, 0xD5054647U, 0x07B6AA0BU,
    0xF31A5118U, 0x1A43A73EU, 0xEEEF5C2DU, 0x4B8884B5U, 0xBF247FA6U,
    0x567D8980U, 0xA2D17293U, 0x70629EDFU, 0x84CE65CCU, 0x6D9793EAU,
    0x993B68F9U };

uint32_t trdp_sc32(const uint8_t buf[], uint32_t len, uint32_t sc) {
    uint32_t i;

    for (i = 0; i < len; i++) {
        sc = sctab[((uint32_t)(sc >> 24) ^ buf[i]) & 0xff] ^ (sc << 8);
    }
    return sc;
}

int32_t trdp_dissect_width(uint32_t type) {
    switch (type) {
    case TRDP_BITSET8: // BITSET8     1
    case TRDP_CHAR8:   // CHAR8		2	char, can be used also as UTF8
    case TRDP_INT8:    // INT8		4	Signed integer, 8 bit
    case TRDP_UINT8:   // UINT8		8	Unsigned integer, 8 bit
        return 1;
    case TRDP_UTF16:  // UTF16		3	Unicode UTF-16 character
    case TRDP_INT16:  // INT16		5	Signed integer, 16 bit
    case TRDP_UINT16: // UINT16		9	Unsigned integer, 16 bit
        return 2;
    case TRDP_INT32:      // INT32		6	Signed integer, 32 bit
    case TRDP_UINT32:     // UINT32		10	Unsigned integer, 32 bit
    case TRDP_REAL32:     // REAL32		12	Floating point real, 32 bit
    case TRDP_TIMEDATE32: // TIMEDATE32	14	32 bit UNIX time
    case TRDP_SC32:       // SC32		17	SC-32, 32 bit
        return 4;
    case TRDP_INT64:      // INT64		7	Signed integer, 64 bit
    case TRDP_UINT64:     // UINT64		11	Unsigned integer, 64 bit
    case TRDP_REAL64:     // REAL64		13	Floating point real, 64 bit
    case TRDP_TIMEDATE64: // TIMEDATE64	16	32 bit seconds and 32 bit
        // microseconds
        return 8;
    case TRDP_TIMEDATE48: // TIMEDATE48	15	48 bit TCN time (32 bit seconds
        // and 16 bit ticks)
        return 6;
    case TRDP_UUID:       // UUID         18      UUID, not official but improves handling in WS
        return 16;
    default:
        return -1;
    }
}
/* end packet-trdp-env.c */

#define API_TRACE                                                              \
  ws_noisy("%s:%d : %s\n", __FILE__, __LINE__, __FUNCTION__)

/* Reply status indication names
 * Signed int: <0: NOK; 0: OK; >0: user reply status
 * (taken from TRDP-EKE) */

static const value_string reply_status_names[] = {
    {-1, "Reserved"},
    {-2, "Session abort"},
    {-3, "No replier instance (at replier side)"},
    {-4, "No memory (at replier side)"},
    {-5, "No memory (local)"},
    {-6, "No reply"},
    {-7, "Not all replies"},
    {-8, "No confirm"},
    {-9, "Reserved"},
    {-10, "Sending failed"},
    {0, "Ok"},
    {0, NULL}};

/* TRDP-packet-type map */
static const char *trdp_types[] = {
    "Pr", "PD Request",
    "Pp", "PD Reply  ",
    "Pe", "PD Error  ",
    "Pd", "PD Data   ",
    "Mn", "MD Notification (Req. w/o reply)",
    "Mr", "MD Request with reply",
    "Mp", "MD Reply ( w/o confrm)",
    "Mq", "MD Reply (with confrm)",
    "Mc", "MD Confirm",
    "Me", "MD error  ",
    NULL, "Unknown TRDP Type"
};

/* Initialize the protocol and registered fields */
static int proto_trdp = -1;
static dissector_handle_t trdp_handle;
static dissector_handle_t trdp_TCP_handle;

void proto_reg_handoff_trdp(void);
void proto_register_trdp(void);

/*For All*/
static int hf_trdp_sequencecounter;  /*uint32*/
static int hf_trdp_protocolversion;  /*uint16*/
static int hf_trdp_type;             /*uint16*/
static int hf_trdp_etb_topocount;    /*uint32*/
static int hf_trdp_op_trn_topocount; /*uint32*/
static int hf_trdp_comid;            /*uint32*/
static int hf_trdp_datasetlength;    /*uint16*/
static int hf_trdp_padding;          /*bytes */

/*For All (user data)*/
static int hf_trdp_fcs_head;      /*uint32*/
static int hf_trdp_fcs_head_calc; /*uint32*/
static int hf_trdp_userdata;      /* userdata */

/*needed only for PD messages*/
static int hf_trdp_reserved;               /*uint32*/
static int hf_trdp_reply_comid; /*uint32*/ /*for MD-family only*/
static int hf_trdp_reply_ipaddress;        /*uint32*/

/* needed only for MD messages*/
static int hf_trdp_replystatus;    /*uint32*/
static int hf_trdp_sessionid;      /*uuid*/
static int hf_trdp_replytimeout;   /*uint32*/
static int hf_trdp_sourceURI;      /*string*/
static int hf_trdp_destinationURI; /*string*/

/* Needed for dynamic content (Generated from convert_proto_tree_add_text.pl) */
//static int hf_trdp_dataset_id;

static bool g_basexml = TRUE;
static const char *g_customTrdpDictionary; // XML Config Files String from ..Edit/Preference menu
static unsigned int g_pd_port = TRDP_DEFAULT_UDP_PD_PORT;
static unsigned int g_md_port = TRDP_DEFAULT_UDPTCP_MD_PORT;
static bool g_scaled = TRUE;
static bool g_strings_are_LE;
static bool g_uids_are_LE;
static bool g_char8_is_utf8 = TRUE;
static bool g_0strings;
static bool g_time_local = TRUE;
static bool g_time_raw;
static int g_bitset_subtype = TRDP_BITSUBTYPE_BOOL8;
static int g_endian_subtype = TRDP_ENDSUBTYPE_BIG;
static unsigned int g_sid = TRDP_DEFAULT_SC32_SID;

/* Initialize the subtree pointers */
static int ett_trdp = -1;

/* Expert fields */
static expert_field ei_trdp_type_unkown;
static expert_field ei_trdp_packet_small;
static expert_field ei_trdp_userdata_empty;
static expert_field ei_trdp_userdata_wrong;
static expert_field ei_trdp_config_notparsed;
static expert_field ei_trdp_padding_not_zero;
static expert_field ei_trdp_array_wrong;
static expert_field ei_trdp_faulty_antivalent;
static expert_field ei_trdp_reserved_not_zero;
static expert_field ei_trdp_sdtv2_safetycode;

/* static container for dynamic fields and subtree handles */
static struct {
    wmem_array_t *hf;
    wmem_array_t *ett;
} trdp_build_dict;

static TrdpDict *pTrdpParser;

/******************************************************************************
 * Local Functions
 */

/**
 * @internal
 * Compares the found CRC in a package with a calculated version
 *
 * @param tvb           dissected package
 * @param pinfo         Necessary to mark status of this packet
 * @param trdp_tree     tree, where the information will be added as child
 * @param offset        the offset in the package where the (32bit) CRC is stored
 * @param data_start    start where the data begins, the CRC should be calculated from
 * @param data_end      end where the data stops, the CRC should be calculated from
 */
static void add_crc2tree(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *trdp_tree, uint32_t offset, uint32_t data_start, uint32_t data_end) {
    uint32_t calced_crc, package_crc, length;
    /* this must always fit */
    if (data_start > data_end) return;

    length = data_end - data_start;

    package_crc = tvb_get_ntohl(tvb, offset);
    calced_crc = g_ntohl(crc32_ccitt_tvb_offset(tvb, data_start, length));

    if (package_crc == calced_crc) {
        proto_tree_add_uint_format_value(trdp_tree, hf_trdp_fcs_head, tvb, offset, 4, package_crc, "0x%04x [correct]", package_crc);
    } else {
        proto_tree_add_uint_format_value(trdp_tree, hf_trdp_fcs_head, tvb, offset, 4, package_crc, "0x%04x [mismatch]", package_crc);
        proto_tree_add_uint_format_value(trdp_tree, hf_trdp_fcs_head_calc, tvb, offset, 4, calced_crc, "0x%04x [mismatch]", calced_crc);
    }
}

/* @fn *static void checkPaddingAndOffset(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset)
 *
 * @brief Check for correct padding
 *
 * @param[in]   tvb     Buffer with the captured data
 * @param[in]   pinfo   Necessary to mark status of this packet
 * @param[in]   tree    The information is appended
 * @param[in]   offset  Actual offset where the padding starts
 *
 * @return position in the buffer
 */
static int32_t checkPaddingAndOffset(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset) {
    int32_t remainingBytes;
    bool isPaddingZero = TRUE;

    remainingBytes = tvb_reported_length_remaining(tvb, offset);
    ws_noisy("The remaining bytes are %d (padding=%d)", remainingBytes, remainingBytes%4);

    if (remainingBytes < 0) { /* There is no space for user data */
        return offset;
    } else if (remainingBytes > 0) {
        for (int i = 0; i < remainingBytes; i++) {
            if (tvb_get_uint8(tvb, offset + i) != 0) {
                isPaddingZero = FALSE;
                break;
            }
        }
        proto_tree_add_bytes_format_value(tree, hf_trdp_padding, tvb, offset, remainingBytes, NULL, "%s", (isPaddingZero ? "[ok]" : "not zero"));

        /* Mark this packet in the statistics also as "not perfect" */
        if (!isPaddingZero) expert_add_info_format(pinfo, tree, &ei_trdp_padding_not_zero, "Padding not zero");
    }
    return remainingBytes + TRDP_FCS_LENGTH;
}

/** @fn uint32_t dissect_trdp_generic_body(tvbuff_t *tvb, packet_info *pinfo,
 * proto_tree *trdp_tree, proto_tree *trdpRootNode, uint32_t trdp_comid, uint32_t
 * offset, unsigned int clength, uint8_t dataset_level, const char *title, const int32_t
 * arr_idx )
 *
 * @brief Extract all information from the userdata (uses the parsebody module for unmarshalling)
 *
 * @param tvb               buffer
 * @param pinfo             info for the packet
 * @param trdp_tree         to which the information are added
 * @param trdpRootNode      Root node of the view of an TRDP packet (Necessary, as this function will be called recursively)
 * @param trdp_comid        the already extracted comId
 * @param offset            where the userdata starts in the TRDP packet
 * @param clength           Amount of bytes, that are transported for the users
 * @param dataset_level     is set to 0 for the beginning
 * @param title             presents the instance-name of the dataset for the sub-tree
 * @param arr_idx           index for presentation when a dataset occurs in an array element
 *
 * @return the actual offset in the packet
 */
// NOLINTNEXTLINE(misc-no-recursion) -- increment_dissection_depth() is used as guard
static uint32_t dissect_trdp_generic_body(
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *trdp_tree, proto_tree *trdpRootNode, uint32_t trdp_comid,
    uint32_t offset, unsigned int clength, uint8_t dataset_level, const char *title, const int32_t arr_idx)
{

    uint32_t start_offset = offset; /* mark beginning of the userdata in pkg */
    int length;
    const Dataset *ds = NULL;
    proto_tree *trdp_userdata = NULL;
    proto_tree *userdata_element = NULL;
    proto_item *pi = NULL;
    int array_index;
    int element_count = 0;

    /* make the userdata accessible for wireshark */
    if (!dataset_level) {
        if (!clength) return checkPaddingAndOffset(tvb, pinfo, trdp_tree, offset);

        pi = proto_tree_add_item(trdp_tree, hf_trdp_userdata, tvb, offset, clength, ENC_NA);

        ws_debug("Searching for comid %u", trdp_comid);
        const ComId *com = TrdpDict_lookup_ComId(pTrdpParser, trdp_comid);

        if (!com) {
            offset += clength;
            return checkPaddingAndOffset(tvb, pinfo, trdp_tree, offset);
        } else
            ds = com->linkedDS;

        /* so far, length was all userdata received, but this is not true for
         * sub-datasets. */
        /* but here we can check it works out */
        length = ds ? ds->size : -1;

        if (length < 0) { /* No valid configuration for this ComId available */
            proto_tree_add_expert_format(trdp_userdata, pinfo, &ei_trdp_userdata_empty, tvb, offset, clength,
                                         "Userdata should be empty or was incomplete, cannot parse. Check xml-config.");
            ws_debug("No Dataset, %d byte of userdata -> end offset is %d [dataset-level: %d]", clength, offset, dataset_level);
            offset += clength;
            return checkPaddingAndOffset(tvb, pinfo, trdp_tree, offset);
        }
    } else {

        ws_debug("Searching for dataset %u", trdp_comid);
        ds = TrdpDict_get_Dataset(pTrdpParser, trdp_comid /* <- datasetID */);

        length = ds ? ds->size : -1;
        if (length < 0) { /* this should actually not happen, ie. should be caught
                             in initial comID-round */
            proto_tree_add_expert_format(trdp_userdata, pinfo, &ei_trdp_userdata_empty, tvb, offset, length,
                                         "Userdata should be empty or was incomplete, cannot parse. Check xml-config.");
            return offset;
        }
    }

    ws_debug("%s aka %u ([%d] octets)", ds->name, ds->datasetId, length);
    trdp_userdata = (arr_idx >= 0)
                  ? proto_tree_add_subtree_format(trdp_tree, tvb, offset, length ? length : -1, ds->ett_id, &pi, "%s.%d", title, arr_idx)
                  : (ds->source /* if custom, show its dataset-id*/
                      ? proto_tree_add_subtree_format(trdp_tree, tvb, offset, length ? length : -1, ds->ett_id, &pi, "%s: %s (%d)", title, ds->name, ds->datasetId)
                      : proto_tree_add_subtree_format(trdp_tree, tvb, offset, length ? length : -1, ds->ett_id, &pi, "%s: %s", title, ds->name));

    array_index = 0;
    int potential_array_size = -1;
    for (Element *el = ds->listOfElements; el; el = el->next) {

        ws_debug("[%d] Offset %5d ----> Element: type=%2d "
                 "%s\tname=%s\tarray-size=%d\tunit=%s\tscale=%f\toffset=%d",
                 dataset_level, offset, el->type.id, el->type.name, el->name,
                 el->array_size, el->unit, el->scale, el->offset);

        // at startup of a new item, check if it is an array or not
        int remainder = 0;
        element_count = el->array_size;

        if (!element_count) { // handle variable element count

            if (g_0strings && (el->type.id == TRDP_CHAR8 || el->type.id == TRDP_UTF16)) {
                /* handle the special elements CHAR8 and UTF16: */

            } else {
                element_count = potential_array_size;

                if (element_count < 1) {

                    if (element_count == 0) {
                        potential_array_size = -1;
                        continue; /* if, at the end of the day, the array is intentionally 0, skip the element */
                    } else {
                        expert_add_info_format(pinfo, trdp_tree, &ei_trdp_array_wrong, "%s : was introduced by an unsupported length field. (%d)", el->name, potential_array_size);
                        return 0; /* in this case, the whole packet is garbled */
                    }
                } else {
                    ws_debug("[%d] Offset %5d Dynamic array, with %d elements found", dataset_level, offset, element_count);
                }

                // check if the specified amount could be found in the package
                remainder = tvb_reported_length_remaining(tvb, offset);
                if (remainder < TrdpDict_element_size(el, element_count)) {
                    expert_add_info_format(pinfo, trdp_tree, &ei_trdp_userdata_wrong, "%s : has %d elements [%d byte each], but only %d left", el->name, element_count, TrdpDict_element_size(el, 1), remainder);
                    element_count = 0;
                }
            }
        }
        if (element_count > 1) {
            ws_debug("[%d] Offset %5d -- Array found, expecting %d elements using %d bytes", dataset_level, offset, element_count, TrdpDict_element_size(el, element_count));
        }

        /* For an array, inject a new node in the graphical dissector, tree (also the extracted dynamic information, see above are added) */
        userdata_element = ((element_count == 1) || (el->type.id == TRDP_CHAR8) || (el->type.id == TRDP_UTF16)) /* for single line */
                         ? trdp_userdata           /* take existing branch */
                         : proto_tree_add_subtree_format( trdp_userdata, tvb, offset,
                                                          TrdpDict_element_size(el, element_count),
                                                          el->ett_id, &pi,
                                                          "%s (%d) : %s[%d]", el->type.name, el->type.id, el->name, element_count);

        do {
            int64_t vals = 0;
            uint64_t valu = 0;
            const char *text = NULL;
            unsigned int slen = 0;
            unsigned int bytelen = 0;
            double real64 = 0;
            nstime_t nstime = {0, 0};
            char bits[TRDP_BITSUBTYPE_BITS+1];
            uint32_t package_crc = 0;
            uint32_t calced_crc, buff_length;
            uint8_t *pBuff;
            e_guid_t guid;

            switch (el->type.id) {

            case TRDP_BITSET8:
                switch (el->type.subtype) {
                case TRDP_BITSUBTYPE_BOOL8:
                    valu = tvb_get_uint8(tvb, offset);
                    proto_tree_add_boolean(userdata_element, el->hf_id, tvb, offset, el->width, (uint32_t)valu);
                    offset += el->width;
                break;
                case TRDP_BITSUBTYPE_BITSET8:
                    if (!el->bitfields) {
                        valu = tvb_get_uint8(tvb, offset);
                        bits[sizeof(bits) - 1] = 0;
                        uint64_t v = valu;
                        for (int i = sizeof(bits) - 1; i--; v >>= 1) bits[i] = v & 1 ? '1' : '.';
                        proto_tree_add_uint_format_value(userdata_element, el->hf_id, tvb, offset, el->width, (uint32_t)valu,
                                                         "0x%#02x ( %s )", (uint32_t)valu, bits);
                    } else {
                        proto_tree_add_bitmask(userdata_element, tvb, offset, el->hf_id, el->bits_ett_id, el->bitfields, ENC_BIG_ENDIAN);
                    }
                    offset += el->width;
                    break;
                case TRDP_BITSUBTYPE_ANTIVALENT8:
                    valu = tvb_get_uint8(tvb, offset);
                    switch (valu) {
                    case 1:
                        proto_tree_add_boolean(userdata_element, el->hf_id, tvb, offset, el->width, (uint32_t)FALSE);
                        break;

                    case 2:
                        proto_tree_add_boolean(userdata_element, el->hf_id, tvb, offset, el->width, (uint32_t)TRUE);
                        break;

                    default:
                        proto_tree_add_expert_format(userdata_element, pinfo, &ei_trdp_faulty_antivalent, tvb, offset, el->width,
                                                     "%#2x is an invalid ANTIVALENT8 value.", (uint32_t)valu);
                        break;
                    }
                    offset += el->width;
                    break;
                }
                break;

            case TRDP_CHAR8:
                bytelen = (element_count || !g_0strings) ? (unsigned int)element_count : tvb_strsize(tvb, offset);
                slen = (element_count || !g_0strings) ? bytelen : (bytelen - 1);
                text = (g_char8_is_utf8 && element_count > 1)
                           ? (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, slen, ENC_UTF_8)
                           : tvb_format_text(pinfo->pool, tvb, offset, slen);

                if (element_count == 1)
                    proto_tree_add_string(userdata_element, el->hf_id, tvb, offset, bytelen, text);
                else
                    proto_tree_add_string_format_value(userdata_element, el->hf_id, tvb, offset, bytelen, text, "[%d] \"%s\"", slen, text);
                offset += bytelen;
                element_count = 1;
                break;

            case TRDP_UTF16:
                bytelen = (element_count || !g_0strings) ? (unsigned int)(2 * element_count) : tvb_unicode_strsize(tvb, offset);
                slen = (element_count || !g_0strings) ? bytelen : (bytelen - 2);
                text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, slen, ENC_UTF_16 | (g_strings_are_LE ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN));
                proto_tree_add_string_format_value(userdata_element, el->hf_id, tvb, offset, bytelen, text, "[%d] \"%s\"", slen / 2, text);
                offset += bytelen;
                element_count = 1;
                break;

            case TRDP_INT8:
                vals = tvb_get_int8(tvb, offset);
                break;

            case TRDP_INT16:
                vals = el->type.subtype == TRDP_ENDSUBTYPE_LIT ? tvb_get_letohis(tvb, offset) : tvb_get_ntohis(tvb, offset);
                break;

            case TRDP_INT32:
                vals = el->type.subtype == TRDP_ENDSUBTYPE_LIT ? tvb_get_letohil(tvb, offset) : tvb_get_ntohil(tvb, offset);
                break;

            case TRDP_INT64:
                vals = el->type.subtype == TRDP_ENDSUBTYPE_LIT ? tvb_get_letohi64(tvb, offset) : tvb_get_ntohi64(tvb, offset);
                break;

            case TRDP_UINT8:
                valu = tvb_get_uint8(tvb, offset);
                break;

            case TRDP_UINT16:
                valu = el->type.subtype == TRDP_ENDSUBTYPE_LIT ? tvb_get_letohs(tvb, offset) : tvb_get_ntohs(tvb, offset);
                break;

            case TRDP_UINT32:
                valu = el->type.subtype == TRDP_ENDSUBTYPE_LIT ? tvb_get_letohl(tvb, offset) : tvb_get_ntohl(tvb, offset);
                break;

            case TRDP_UINT64:
                valu = el->type.subtype == TRDP_ENDSUBTYPE_LIT ? tvb_get_letoh64(tvb, offset) : tvb_get_ntoh64(tvb, offset);
                break;

            case TRDP_REAL32:
                real64 = el->type.subtype == TRDP_ENDSUBTYPE_LIT ? tvb_get_letohieee_float(tvb, offset) : tvb_get_ntohieee_float(tvb, offset);
                break;

            case TRDP_REAL64:
                real64 = el->type.subtype == TRDP_ENDSUBTYPE_LIT ? tvb_get_letohieee_double(tvb, offset) : tvb_get_ntohieee_double(tvb, offset);
                break;

            case TRDP_TIMEDATE32:
                /* This should be time_t from general understanding, which is UNIX time,
                 * seconds since 1970 time_t is a signed long in modern POSIX ABIs, ie.
                 * often s64! However, vos_types.h defines this as u32, which may
                 * introduce some odd complications -- later. IEC61375-2-1 says for
                 * UNIX-time: SIGNED32 - ok, will respect!
                 */
                vals = tvb_get_ntohil(tvb, offset);
                nstime.secs = (long int)vals;
                break;

            case TRDP_TIMEDATE48:
                vals = tvb_get_ntohil(tvb, offset);
                nstime.secs = (time_t)vals;
                valu = tvb_get_ntohs(tvb, offset + 4);
                nstime.nsecs = (int)(valu * (1000000000ULL / 256ULL)) / 256;
                break;

            case TRDP_TIMEDATE64:
                vals = tvb_get_ntohil(tvb, offset);
                nstime.secs = (time_t)vals;
                vals = tvb_get_ntohil(tvb, offset + 4);
                nstime.nsecs = (int)vals * 1000;
                break;

            case TRDP_SC32:
                package_crc = tvb_get_ntohl(tvb, offset);
                break;

            case TRDP_UUID:
                tvb_get_guid(tvb, offset, &guid, (g_uids_are_LE ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN));
                break;

            default:
                ws_debug("Unique type %d for %s", el->type.id, el->name);
                /* safe guard against excessive recursion of datasets.
                 * This should have been handled at dictionary reading. If it breaks here, it is some weired bug.
                 */
                /* use wireshark's own protection. However, in the current dev-build of WS this value's (gui.max_tree_depth) default was much higher. */
                /* be aware that each array introduces an extra level, as well as other protocol layers */
                increment_dissection_depth(pinfo);

                // NOLINTNEXTLINE(misc-no-recursion)
                offset = dissect_trdp_generic_body( tvb, pinfo, userdata_element, trdpRootNode, el->type.id, offset, length - (offset - start_offset),
                                                    dataset_level + 1, el->name, (element_count != 1) ? array_index : -1);
                decrement_dissection_depth(pinfo);

                if (offset == 0) return offset; /* break dissecting, if things went sideways */
                break;
            }

            switch (el->type.id) {

            /* case TRDP_INT8 ... TRDP_INT64: */
            case TRDP_INT8:
            case TRDP_INT16:
            case TRDP_INT32:
            case TRDP_INT64:

                if (g_ascii_strcasecmp(el->unit, "hide0") == 0) {
                    if (vals != 0) proto_tree_add_expert_format(userdata_element, pinfo, &ei_trdp_reserved_not_zero,
                                           tvb, offset, el->width, "Element is not zero (%" G_GINT64_FORMAT ").", vals);
                } else if (el->scale && g_scaled) {
                    double formated_value = vals * el->scale + el->offset;
                    proto_tree_add_double_format_value(userdata_element, el->hf_id, tvb, offset, el->width, formated_value,
                                                       "%lg %s (raw=%" G_GINT64_FORMAT ")", formated_value, el->unit, vals);
                } else {
                    if (g_scaled) vals += el->offset;
                    proto_tree_add_int64(userdata_element, el->hf_id, tvb, offset, el->width, vals);
                }
                offset += el->width;
                break;

            /* case TRDP_UINT8 ... TRDP_UINT64: */
            case TRDP_UINT8:
            case TRDP_UINT16:
            case TRDP_UINT32:
            case TRDP_UINT64:
                if (g_ascii_strcasecmp(el->unit, "hide0") == 0) {
                    if (valu != 0) proto_tree_add_expert_format(userdata_element, pinfo, &ei_trdp_reserved_not_zero,
                        tvb, offset, el->width, "Element is not zero (%" G_GUINT64_FORMAT ").", valu);
                } else if (g_ascii_strcasecmp(el->unit, "version") == 0) {
                    proto_tree_add_uint_format_value(userdata_element, el->hf_id, tvb, offset, el->width, (uint32_t)valu, "%02"PRId64".%02"PRId64"", (valu >> 8) & 0xff, (valu >> 0) & 0xff);
                } else if (el->scale && g_scaled) {
                    double formated_value = valu * el->scale + el->offset;
                    proto_tree_add_double_format_value(userdata_element, el->hf_id, tvb, offset, el->width, formated_value,
                                                       "%lg %s (raw=%" G_GUINT64_FORMAT ")", formated_value, el->unit, valu);
                } else {
                    if (g_scaled) valu += el->offset;
                    proto_tree_add_uint64(userdata_element, el->hf_id, tvb, offset, el->width, valu);
                }
                offset += el->width;
                break;

            case TRDP_REAL32:
            case TRDP_REAL64:
                if (el->scale && g_scaled) {
                    double formated_value = real64 * el->scale + el->offset;
                    proto_tree_add_double_format_value(userdata_element, el->hf_id, tvb, offset, el->width, formated_value,
                                                       "%lg %s (raw=%lf)", formated_value, el->unit, real64);
                } else {
                    if (g_scaled) real64 += el->offset;
                    proto_tree_add_double(userdata_element, el->hf_id, tvb, offset, el->width, real64);
                }
                offset += el->width;
                break;

            /* case TRDP_TIMEDATE32 ... TRDP_TIMEDATE64: */
            case TRDP_TIMEDATE32:
            case TRDP_TIMEDATE48:
            case TRDP_TIMEDATE64:
                /* Is it allowed to have offset / scale?? I am not going to scale
                 * seconds, but there could be use for an offset, esp. when misused as
                 * relative time. */
                if (g_scaled) nstime.secs += el->offset;
                if (g_time_raw) {
                    switch (el->type.id) {
                    case TRDP_TIMEDATE32:
                        proto_tree_add_time_format_value(userdata_element, el->hf_id, tvb, offset, el->width, &nstime,
                                                         "%ji seconds", (intmax_t)nstime.secs);
                    break;
                    case TRDP_TIMEDATE48:
                        proto_tree_add_time_format_value(userdata_element, el->hf_id, tvb, offset, el->width, &nstime,
                                                         "%ji.%05ld seconds (=%" G_GUINT64_FORMAT " ticks)", (intmax_t)nstime.secs, (nstime.nsecs + 5000L) / 10000L, valu);
                    break;
                    case TRDP_TIMEDATE64:
                        proto_tree_add_time_format_value(userdata_element, el->hf_id, tvb, offset, el->width, &nstime,
                                                         "%ji.%06ld seconds", (intmax_t)nstime.secs, nstime.nsecs / 1000L);
                    break;

                    }
                } else
                    proto_tree_add_time(userdata_element, el->hf_id, tvb, offset, el->width, &nstime);

                offset += el->width;
                break;

            case TRDP_SC32:
                buff_length = tvb_get_ntohl(tvb, TRDP_HEADER_OFFSET_DATASETLENGTH) - TRDP_SC32_LENGTH;
                pBuff = (uint8_t *)g_malloc(buff_length);
                if (pBuff != NULL) {
                    tvb_memcpy(tvb, pBuff, TRDP_HEADER_PD_OFFSET_DATA, buff_length);
                    calced_crc = trdp_sc32(pBuff, buff_length, (uint32_t)(g_sid & 0xFFFFFFFF));
                    if (package_crc == calced_crc) {
                        proto_tree_add_uint_format_value(userdata_element, el->hf_id, tvb, offset, el->width, package_crc, "0x%04x [correct]", package_crc);
                    } else {
                        proto_tree_add_uint_format_value(userdata_element, el->hf_id, tvb, offset, el->width, package_crc, "0x%04x [incorrect, should be 0x%04x]", package_crc, calced_crc);
                        proto_tree_add_expert_format(userdata_element, pinfo, &ei_trdp_sdtv2_safetycode, tvb, offset, el->width, "0x%04x is an incorrect SC32 value.", (uint32_t)package_crc);
                    }
                    g_free(pBuff);
                }
                offset += el->width;
                break;
            case TRDP_UUID:
                proto_tree_add_guid(userdata_element, el->hf_id, tvb, offset, el->width, &guid);
                offset += el->width;
                break;
            }

            if (array_index || element_count != 1) {
                /* handle arrays */
                ws_debug( "[%d / %d]", array_index, element_count);
                if (++array_index >= element_count) {
                    array_index = 0;
                    userdata_element = trdp_userdata;
                }
                potential_array_size = -1;
            } else {
                ws_debug("[%d / %d], (type=%d) val-u=%" G_GUINT64_FORMAT " val-s=%" G_GINT64_FORMAT ".", array_index, element_count, el->type.id, valu, vals);

                potential_array_size = (el->type.id < TRDP_INT8 || el->type.id > TRDP_UINT64) ? -1 : (el->type.id >= TRDP_UINT8 ? (int)valu : (int)vals);
            }

        } while (array_index);
    }

    /* Check padding of the body */
    if (!dataset_level) offset = checkPaddingAndOffset(tvb, pinfo, trdpRootNode, offset);

    return offset;
}

static void add_dataset_reg_info(Dataset *ds);

/**
 * @internal
 * Extract all information from the userdata (uses the parsebody module for
 * unmarshalling)
 *
 * @param tvb               buffer
 * @param packet            info for tht packet
 * @param tree              to which the information are added
 * @param trdp_comid        the already extracted comId
 * @param offset            where the userdata starts in the TRDP package
 *
 * @return size of the user data
 */
static uint32_t dissect_trdp_body(tvbuff_t *tvb, packet_info *pinfo, proto_tree *trdp_tree, uint32_t trdp_comid, uint32_t offset, uint32_t length) {
    API_TRACE;
    return dissect_trdp_generic_body(tvb, pinfo, trdp_tree, trdp_tree, trdp_comid, offset, length, 0 /* level of cascaded datasets*/, "dataset", -1);
}

/**
 * @internal
 * Build the special header for PD and MD datasets (and calls the function to extract the userdata)
 *
 * @param tvb               buffer
 * @param pinfo             info for tht packet
 * @param tree              to which the information are added
 * @param trdp_comid        the already extracted comId
 * @param offset            where the userdata starts in the TRDP package
 *
 * @return size of the user data
 */
static uint32_t build_trdp_tree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item **ti_type, uint32_t trdp_comid, char *trdp_string) {
    proto_item *ti = NULL;
    proto_tree *trdp_tree = NULL;
    proto_item *_ti_type_tmp = NULL;
    proto_item **pti_type = ti_type ? ti_type : &_ti_type_tmp;

    uint32_t datasetlength = 0;
    uint32_t pdu_size = 0;

    API_TRACE;

    /* when the package is big enough extract some data. */
    if (tvb_reported_length_remaining(tvb, 0) > TRDP_HEADER_PD_OFFSET_RESERVED) {
        ti = proto_tree_add_item(tree, proto_trdp, tvb, 0, -1, ENC_NA);
        trdp_tree = proto_item_add_subtree(ti, ett_trdp);

        proto_tree_add_item(trdp_tree, hf_trdp_sequencecounter, tvb, TRDP_HEADER_OFFSET_SEQCNT, 4, ENC_BIG_ENDIAN);
        int verMain = tvb_get_uint8(tvb, TRDP_HEADER_OFFSET_PROTOVER);
        int verSub = tvb_get_uint8(tvb, (TRDP_HEADER_OFFSET_PROTOVER + 1));
        proto_tree_add_bytes_format_value(trdp_tree, hf_trdp_protocolversion, tvb, 4, 2, NULL, "%d.%d", verMain, verSub);

        *pti_type = proto_tree_add_item(trdp_tree, hf_trdp_type,      tvb, TRDP_HEADER_OFFSET_TYPE, 2, ENC_ASCII);
        proto_tree_add_item(trdp_tree, hf_trdp_comid,            tvb, TRDP_HEADER_OFFSET_COMID, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(trdp_tree, hf_trdp_etb_topocount,    tvb, TRDP_HEADER_OFFSET_ETB_TOPOCNT, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(trdp_tree, hf_trdp_op_trn_topocount, tvb, TRDP_HEADER_OFFSET_OP_TRN_TOPOCNT, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(trdp_tree, hf_trdp_datasetlength,    tvb, TRDP_HEADER_OFFSET_DATASETLENGTH, 4, ENC_BIG_ENDIAN);
        datasetlength = tvb_get_ntohl(tvb, TRDP_HEADER_OFFSET_DATASETLENGTH);
    } else {
        expert_add_info_format(pinfo, tree, &ei_trdp_packet_small, "Packet too small for header information");
    }

    if (trdp_string) {
        switch (trdp_string[0]) {
        case 'P':
            /* PD specific stuff */
            proto_tree_add_item(trdp_tree, hf_trdp_reserved,        tvb, TRDP_HEADER_PD_OFFSET_RESERVED, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(trdp_tree, hf_trdp_reply_comid,     tvb, TRDP_HEADER_PD_OFFSET_REPLY_COMID, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(trdp_tree, hf_trdp_reply_ipaddress, tvb, TRDP_HEADER_PD_OFFSET_REPLY_IPADDR, 4, ENC_BIG_ENDIAN);
            add_crc2tree(tvb, pinfo, trdp_tree, TRDP_HEADER_PD_OFFSET_FCSHEAD, 0, TRDP_HEADER_PD_OFFSET_FCSHEAD);
            pdu_size = dissect_trdp_body(tvb, pinfo, trdp_tree, trdp_comid, TRDP_HEADER_PD_OFFSET_DATA, datasetlength);
            break;
        case 'M':
            /* MD specific stuff */
            proto_tree_add_item(trdp_tree, hf_trdp_replystatus,     tvb, TRDP_HEADER_MD_OFFSET_REPLY_STATUS, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(trdp_tree, hf_trdp_sessionid,       tvb, TRDP_HEADER_MD_SESSIONID0, 16, ENC_BIG_ENDIAN);
            proto_tree_add_item(trdp_tree, hf_trdp_replytimeout,    tvb, TRDP_HEADER_MD_REPLY_TIMEOUT, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(trdp_tree, hf_trdp_sourceURI,       tvb, TRDP_HEADER_MD_SRC_URI, 32, ENC_ASCII);
            proto_tree_add_item(trdp_tree, hf_trdp_destinationURI,  tvb, TRDP_HEADER_MD_DEST_URI, 32, ENC_ASCII);
            add_crc2tree(tvb, pinfo, trdp_tree, TRDP_HEADER_MD_OFFSET_FCSHEAD, 0, TRDP_HEADER_MD_OFFSET_FCSHEAD);
            pdu_size = dissect_trdp_body(tvb, pinfo, trdp_tree, trdp_comid,  TRDP_HEADER_MD_OFFSET_DATA, datasetlength);
            break;
        default:
            break;
        }
    }
    return pdu_size;
}

int dissect_trdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    uint32_t    trdp_comid = 0;
    char       *trdp_string = NULL;
    uint32_t    parsed_size = 0U;
    proto_item *ti_type = NULL;

    /* Load header fields and dictionary if not already done */
    if (hf_trdp_type <= 0) {
        proto_registrar_get_byname("trdp.type");
    }

    /* Make entries in Protocol column ... */
    if (col_get_writable(pinfo->cinfo, COL_PROTOCOL)) col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_TRDP);

    /* and "info" column on summary display */
    if (col_get_writable(pinfo->cinfo, COL_INFO))     col_clear(pinfo->cinfo, COL_INFO);

    /* Read required values from the package: */
    trdp_string = (char *)tvb_format_text(pinfo->pool, tvb, TRDP_HEADER_OFFSET_TYPE, 2);
    trdp_comid  = tvb_get_ntohl(tvb, TRDP_HEADER_OFFSET_COMID);

    /* Telegram that fits into one packet, or the header of huge telegram, that was reassembled */
    parsed_size = build_trdp_tree(tvb, pinfo, tree, &ti_type, trdp_comid, trdp_string);
    if (tree == NULL) ws_debug("Dissector did not get a tree passed (type=%s, comid=%u, parsed=%u).", trdp_string, trdp_comid, parsed_size);

    /* Append the packet type into the information description */
    if (col_get_writable(pinfo->cinfo, COL_INFO)) {
        /* Display a info line */
        col_append_fstr(pinfo->cinfo, COL_INFO, "comId: %5u ", trdp_comid);

        /* look-up the packet-type name */
        const char **tt = trdp_types;
        while (*tt && strcmp(trdp_string, *tt)) tt+=2;
        col_append_str(pinfo->cinfo, COL_INFO, *(tt+1));
        if (!*tt) expert_add_info_format(pinfo, ti_type, &ei_trdp_type_unkown, "Unknown TRDP Type: %s", trdp_string);

        /* Help with high-level name of ComId / Dataset */
        const ComId *comId = TrdpDict_lookup_ComId(pTrdpParser, trdp_comid);
        if (comId) {
            if (comId->name && *comId->name) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", comId->name);
            } else if (comId->linkedDS) {
                if (*comId->linkedDS->name) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]", comId->linkedDS->name);
                } else {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%u]", comId->linkedDS->datasetId);
                }
            }
        } else {
            const char* name = TrdpDict_lookup_ComId_Name(pTrdpParser, trdp_comid);
            if (name) col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", name);
        }
    }
    ws_debug("Returning a parsed_size=%d", parsed_size); // tvb_captured_length(tvb)
    return parsed_size;
}

/** @fn static unsigned int get_trdp_tcp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
 *  @internal
 *  @brief retrieve the expected size of the transmitted packet.
 */
static unsigned int get_trdp_tcp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_) {
    unsigned int datasetlength   = (unsigned int)tvb_get_ntohl(tvb, offset + TRDP_HEADER_OFFSET_DATASETLENGTH);
    unsigned int without_padding = datasetlength + TRDP_MD_HEADERLENGTH/* + TRDP_FCS_LENGTH*/;
    ws_debug("get_trdp_tcp_message_len (datasetlength=%d w/ padding=%d tvb_reported_length=%d / captured=%d)", datasetlength, (without_padding + 3) & (~3), tvb_reported_length(tvb), tvb_captured_length(tvb));
    return (without_padding + 3) & (~3); /* round up to add padding */
}

/**
 * @internal
 * Code to analyze the actual TRDP packet, transmitted via TCP
 *
 * @param tvb       buffer
 * @param pinfo     info for the packet
 * @param tree      to which the information are added
 * @param data      Collected information
 *
 * @return length
 */
static int dissect_trdp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    API_TRACE;
    if (!tvb_bytes_exist(tvb, 0, TRDP_MD_HEADERLENGTH)) {
        ws_debug("Missing enough bytes %d/%d", tvb_captured_length(tvb), TRDP_MD_HEADERLENGTH);
        return 0;
    }

    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, TRDP_MD_HEADERLENGTH, get_trdp_tcp_message_len, dissect_trdp, data);

    return tvb_reported_length(tvb);
}

/* ========================================================================= */
/* Register the protocol fields and subtrees with Wireshark
 * (strongly inspired by the wimaxasncp plugin)
 */

/* ========================================================================= */
/* Modify the given string to make a suitable display filter                 */
/*                                             copied from wimaxasncp plugin */
static char *alnumerize(char *name) {
    char *r = name; /* read pointer */
    char *w = name; /* write pointer */
    char c;

    for (; (c = *r); ++r) {
        if (g_ascii_isalnum(c) || c == '_' || c == '.') { /* These characters are fine - copy them */
            *(w++) = c;
        } else if (c == ' ' || c == '-' || c == '/') {
            if (w == name)       continue; /* Skip these others if haven't written any characters out yet */
            if (*(w - 1) == '_') continue; /* Skip if we would produce multiple adjacent '_'s */

            *(w++) = '_'; /* OK, replace with underscore */
        }
        /* Other undesirable characters are just skipped */
    }
    *w = '\0'; /* Terminate and return modified string */
    return name;
}

/* ========================================================================= */

static void add_reg_info(int *hf_ptr, const char *name, const char *abbrev, enum ftenum type, int display, int bitmask, const char *blurb) {

    hf_register_info hf = {hf_ptr, {name, abbrev, type, display, NULL, bitmask, blurb, HFILL}};

    wmem_array_append_one(trdp_build_dict.hf, hf);
}

/* ========================================================================= */

static void add_element_reg_info(const char *parentName, Element *el) {
    char *name;
    char *abbrev;
    const char *blurb;
    int *pett_id = &el->ett_id;

    name = g_strdup(el->name);
    abbrev = alnumerize(g_strdup_printf(PROTO_FILTERNAME_TRDP_PDU ".%s.%s", parentName, el->name));

    if (el->scale || el->offset) {
        blurb = g_strdup_printf("An element of type=%s(%u) scaling *%4g plus offset %+0d in unit %s",
                                el->type.name, el->type.id, el->scale ? el->scale : 1.0, el->offset, el->unit);
    } else {
        blurb = g_strdup_printf("An element of type=%s(%u) with unit %s",
                                el->type.name, el->type.id, el->unit);
    }

    if (!((el->array_size == 1) || (el->type.id == TRDP_CHAR8) || (el->type.id == TRDP_UTF16))) {
        wmem_array_append_one(trdp_build_dict.ett, pett_id);
    }

    switch (el->type.id) {
        case TRDP_BITSET8:
            if (el->type.subtype == TRDP_BITSUBTYPE_BITSET8) {
                /* TODO an Array of bitsets is currently not supported */
                if (el->bits /*&& el->array_size == 1*/) {
                    int **bitfields = el->bitfields;
                    int *pb_ett_id = &el->bits_ett_id;
                    wmem_array_append_one(trdp_build_dict.ett, pb_ett_id);
                    for (int i=0;i<TRDP_BITSUBTYPE_BITS;i++) {
                        if (*el->bits[i].name) {
                            char* abbrev2 = alnumerize(g_strdup_printf(PROTO_FILTERNAME_TRDP_PDU ".%s.%s.%s", parentName, el->name, el->bits[i].name));
                            add_reg_info( &el->bits[i].hf_id, el->bits[i].name, abbrev2, FT_BOOLEAN, 8, 1<<i, NULL);
                            *bitfields = &el->bits[i].hf_id;
                            bitfields++;
                        }
                    }
                }
                add_reg_info(&el->hf_id, name, abbrev, FT_UINT8, BASE_HEX, 0, NULL);
            } else {
                add_reg_info(&el->hf_id, name, abbrev, FT_BOOLEAN, 8, 0, blurb);
            }
            break;
        case TRDP_CHAR8:
        case TRDP_UTF16:
            add_reg_info(&el->hf_id, name, abbrev, el->array_size ? FT_STRING : FT_STRINGZ, BASE_NONE, 0, blurb);
            break;

        /*    case TRDP_INT8 ... TRDP_INT64: not supported in MSVC :( */
        case TRDP_INT8:
        case TRDP_INT16:
        case TRDP_INT32:
        case TRDP_INT64:
            if (el->scale && g_scaled) {
                add_reg_info(&el->hf_id, name, abbrev, FT_DOUBLE, BASE_NONE, 0, blurb);
            } else
                add_reg_info(&el->hf_id, name, abbrev, FT_INT64, BASE_DEC, 0, blurb);
            break;

        /*    case TRDP_UINT8 ... TRDP_UINT64: */
        case TRDP_UINT8:
        case TRDP_UINT16:
        case TRDP_UINT32:
        case TRDP_UINT64:
            if (g_ascii_strcasecmp(el->unit, "version") == 0) {
                add_reg_info(&el->hf_id, name, abbrev, FT_UINT16, BASE_HEX, 0, blurb);
            } else if (el->scale && g_scaled) {
                add_reg_info(&el->hf_id, name, abbrev, FT_DOUBLE, BASE_NONE, 0, blurb);
            } else
                add_reg_info(&el->hf_id, name, abbrev, FT_UINT64, BASE_DEC, 0, blurb);
            break;

        case TRDP_REAL32:
        case TRDP_REAL64:
            add_reg_info(&el->hf_id, name, abbrev, FT_DOUBLE, BASE_NONE, 0, blurb);
            break;

        /*    case TRDP_TIMEDATE32 ... TRDP_TIMEDATE64:*/
        case TRDP_TIMEDATE32:
        case TRDP_TIMEDATE48:
        case TRDP_TIMEDATE64:
        /*  add_reg_info( &el->hf_id, name, abbrev, FT_DOUBLE, BASE_NONE, 0, blurb );*/
            add_reg_info(&el->hf_id, name, abbrev, g_time_raw ? FT_RELATIVE_TIME : FT_ABSOLUTE_TIME,
                                                   g_time_raw ? 0 : (g_time_local ? ABSOLUTE_TIME_LOCAL : ABSOLUTE_TIME_UTC), 0, blurb);
            break;

        case TRDP_SC32:
            add_reg_info(&el->hf_id, name, abbrev, FT_UINT32, BASE_HEX, 0, blurb);
            break;

        case TRDP_UUID:
            add_reg_info(&el->hf_id, name, abbrev, FT_GUID, BASE_NONE, 0, blurb);
            break;

        default:
            add_reg_info(&el->hf_id, name, abbrev, FT_BYTES, BASE_NONE, 0, blurb);

        /* as long as I do not track the hierarchy, do not recurse */
        /* add_dataset_reg_info(el->linkedDS); */
    }
}

static void add_dataset_reg_info(Dataset *ds) {
    int *pett_id = &ds->ett_id;

    for (Element *el = ds->listOfElements; el; el = el->next) add_element_reg_info(ds->name, el);

    if (ds->listOfElements)  wmem_array_append_one(trdp_build_dict.ett, pett_id);
}

static void register_trdp_fields(const char *prefix _U_) {
    API_TRACE;

    /* List of header fields. */
    static hf_register_info hf_base[] = {
        /* All the general fields for the header */
        // clang-format off
        {&hf_trdp_sequencecounter, {"sequenceCounter", "trdp.sequencecounter", FT_UINT32, BASE_DEC,  NULL, 0x0, "", HFILL}},
        {&hf_trdp_protocolversion, {"protocolVersion", "trdp.protocolversion", FT_BYTES,  BASE_NONE, NULL, 0x0, "", HFILL}},
        {&hf_trdp_type,            {"msgtype", "trdp.type", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL}},
        {&hf_trdp_comid,           {"comId", "trdp.comid", FT_UINT32, BASE_DEC,  NULL, 0x0, "", HFILL}},
        {&hf_trdp_etb_topocount,   {"etbTopoCnt", "trdp.etbtopocnt", FT_UINT32, BASE_DEC,  NULL, 0x0, "", HFILL}},
        {&hf_trdp_op_trn_topocount,{"opTrnTopoCnt", "trdp.optrntopocnt", FT_UINT32, BASE_DEC,  NULL, 0x0, "", HFILL}},
        {&hf_trdp_datasetlength,   {"datasetLength", "trdp.datasetlength", FT_UINT32, BASE_DEC,  NULL, 0x0, "", HFILL}},
        {&hf_trdp_padding,         {"padding", "trdp.padding", FT_BYTES,  BASE_NONE, NULL, 0x0, "", HFILL}},

        /* PD specific stuff */
        {&hf_trdp_reserved,        {"reserved", "trdp.reserved", FT_UINT32, BASE_DEC,  NULL, 0x0, "", HFILL}},
        {&hf_trdp_reply_comid,     {"replyComId", "trdp.replycomid", FT_UINT32, BASE_DEC,  NULL, 0x0, "", HFILL}}, /* only in PD request */
        {&hf_trdp_reply_ipaddress, {"replyIpAddress", "trdp.replyip", FT_IPv4,   BASE_NONE, NULL, 0x0, "", HFILL}},

        /* MD specific stuff */
        {&hf_trdp_replystatus,     {"replyStatus", "trdp.replystatus", FT_INT32,  BASE_DEC,  VALS(reply_status_names), 0x0, "", HFILL}},
        {&hf_trdp_sessionid,       {"sessionUUID", "trdp.sessionid", FT_GUID,   BASE_NONE, NULL, 0x0, "", HFILL}},
        {&hf_trdp_replytimeout,    {"replyTimeout", "trdp.replytimeout", FT_UINT32, BASE_DEC,  NULL, 0x0, "", HFILL}},
        {&hf_trdp_sourceURI,       {"sourceUri", "trdp.sourceUri", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL}},
        {&hf_trdp_destinationURI,  {"destinationURI", "trdp.destinationUri", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL}},
        {&hf_trdp_userdata,        {"dataset", "trdp.rawdata", FT_BYTES,  BASE_NONE, NULL, 0x0, "", HFILL}},

        /* The checksum for the header (the trdp.fcsheadcalc is only set, if the
         calculated FCS differs) */
        {&hf_trdp_fcs_head,        {"headerFcs", "trdp.fcshead", FT_UINT32, BASE_HEX,  NULL, 0x0, "", HFILL}},
        {&hf_trdp_fcs_head_calc,   {"calculatedHeaderFcs", "trdp.fcsheadcalc", FT_UINT32, BASE_HEX,  NULL, 0x0, "", HFILL}},

        // clang-format on
    };

    /* Setup protocol subtree array */
    static int *ett_base[] = {
        &ett_trdp,
    };

    /* ------------------------------------------------------------------------
     * load the XML dictionary
     * ------------------------------------------------------------------------
     */

    if (pTrdpParser != NULL) {
        /* currently the GUI callbacks are w/o effect, so always clear the filter expression */
//        plugin_if_apply_filter("" /* empty filter */, TRUE /* apply immediately */);
        TrdpDict_delete(pTrdpParser, proto_trdp);
        proto_free_deregistered_fields();
    }

    ws_info("TRDP custom dictionary is '%s' (proto=%d).", g_customTrdpDictionary, proto_trdp);
    API_TRACE;

    GError *err = NULL;
    char *basepath = g_basexml ? get_datafile_path("trdp", epan_get_environment_prefix()) : NULL;
    pTrdpParser = TrdpDict_new(basepath, g_customTrdpDictionary, g_bitset_subtype, g_endian_subtype, &err);

    API_TRACE;
    if (err) {
        report_failure("TRDP | XML input failed [%d]:\n%s", err->code, err->message);
        g_error_free(err);
    }

    g_free(basepath);

    /* ------------------------------------------------------------------------
     * build the hf and ett dictionary entries
     * ------------------------------------------------------------------------
     */

    if (trdp_build_dict.hf)  wmem_free(wmem_epan_scope(), trdp_build_dict.hf);

    if (trdp_build_dict.ett) wmem_free(wmem_epan_scope(), trdp_build_dict.ett);

    trdp_build_dict.hf =  wmem_array_new(wmem_epan_scope(), sizeof(hf_register_info));
    trdp_build_dict.ett = wmem_array_new(wmem_epan_scope(), sizeof(int *));

    if (hf_trdp_type <= 0) {
        proto_register_field_array(proto_trdp, hf_base, array_length(hf_base));
        proto_register_subtree_array(ett_base, array_length(ett_base));
    }

    if (pTrdpParser) {
        /* arrays use the same hf */
        /* don't care about comID linkage, as I really want to index all datasets,
         * regardless of their hierarchy */
        for (Dataset *ds = pTrdpParser->mTableDataset; ds; ds = ds->next) add_dataset_reg_info(ds);
    }

    /* Required function calls to register the header fields and subtrees used */

    proto_register_field_array(proto_trdp, (hf_register_info *)wmem_array_get_raw(trdp_build_dict.hf), wmem_array_get_count(trdp_build_dict.hf));

    proto_register_subtree_array((int **)wmem_array_get_raw(trdp_build_dict.ett), wmem_array_get_count(trdp_build_dict.ett));
}

void proto_reg_handoff_trdp(void) {
    static bool initialized = FALSE;
    static unsigned int pd_port=0;
    static unsigned int md_port=0;
    API_TRACE;

    if (initialized == FALSE) {
        initialized = TRUE;
    } else {
        if (pd_port != g_pd_port) {
            dissector_delete_uint("udp.port", pd_port, trdp_handle);
        }
        if (md_port != g_md_port) {
            dissector_delete_uint("udp.port", md_port, trdp_handle);
            dissector_delete_uint("tcp.port", md_port, trdp_TCP_handle);
        }
    }
    if (pd_port != g_pd_port) {
        pd_port = g_pd_port;
        dissector_add_uint_with_preference("udp.port", pd_port, trdp_handle);
    }
    if (md_port != g_md_port) {
        md_port = g_md_port;
        dissector_add_uint_with_preference("udp.port", md_port, trdp_handle);
        dissector_add_uint_with_preference("tcp.port", md_port, trdp_TCP_handle);
    }

    /* Reload header fields and dictionary but only, if it's been in use before */
    if (hf_trdp_type > 0) register_trdp_fields(NULL);
}

void proto_register_trdp(void) {
    module_t *trdp_module;

    enum_val_t *bitsetenumvals;
    gsize bitset_offset = 0;
    gsize bitset_types = 0;

    while (ElBasics[bitset_offset].id              != TRDP_BITSET8) bitset_offset++;
    while (ElBasics[bitset_offset+bitset_types].id == TRDP_BITSET8) bitset_types++;

    bitsetenumvals = wmem_alloc0_array(wmem_epan_scope(),enum_val_t, bitset_types + 1);
    for (gsize i = 0; i < bitset_types; i++) {
        bitsetenumvals[i].description = ElBasics[i].name;
        bitsetenumvals[i].name = wmem_ascii_strdown(wmem_epan_scope(), ElBasics[i].name, -1);
        bitsetenumvals[i].value = (int)ElBasics[i].subtype;
    }

    enum_val_t *endianenumvals = wmem_alloc0_array(wmem_epan_scope(), enum_val_t, 2 + 1);
    endianenumvals[0].description = "BE";
    endianenumvals[0].name = "be";
    endianenumvals[0].value = TRDP_ENDSUBTYPE_BIG;
    endianenumvals[1].description = "LE (non-standard)";
    endianenumvals[1].name = "le";
    endianenumvals[1].value = TRDP_ENDSUBTYPE_LIT;

    API_TRACE;

    /* Register the protocol name and description */
    proto_trdp      = proto_register_protocol(PROTO_NAME_TRDP, PROTO_TAG_TRDP, PROTO_FILTERNAME_TRDP);
    trdp_handle     = register_dissector(PROTO_DISSECTORNAME_TRDP,    (dissector_t)dissect_trdp,     proto_trdp);
    trdp_TCP_handle = register_dissector(PROTO_DISSECTORNAME_TRDPTCP, (dissector_t)dissect_trdp_tcp, proto_trdp);
    /* Delay registration of com-id and dataset-id definitions */
    proto_register_prefix("trdp", register_trdp_fields);

    trdp_module     = prefs_register_protocol(proto_trdp, proto_reg_handoff_trdp);

    /* Register the preference */
    prefs_register_static_text_preference( trdp_module, "dissector_summary",
        "Version 20251123",
        NULL);

    prefs_register_bool_preference( trdp_module, "basexml",
        "Load basic set of comIDs and dataset definitions",
        "When ticked, basic definitions of 61375-2-3 are loaded. If that conflicts with your use or your definitions "
        "- untick. If there's a bug or data missing, please file an issue.",
        &g_basexml);

    prefs_register_filename_preference( trdp_module, "configfile",
        "Custom TRDP configuration file",
        "Custom TRDP configuration file",
        &g_customTrdpDictionary, FALSE);

    prefs_set_preference_effect_fields(trdp_module, "configfile");

    prefs_register_static_text_preference( trdp_module, "xml_summary",
        "If you need to include multiple files, chose a file, then manually remove the filename part above only leaving the folder path. You cannot choose a "
        "folder by itself in the dialog. Be sure, not to have conflicting versions of datasets or com-ids in that target folder - the file parser will be pesky.",
        NULL);

    prefs_register_enum_preference( trdp_module, "bitset.subtype",
        "Select default sub-type for TRDP-Element type 1",
        "Type 1 can be interpreted differently, as BOOL, ANTIVALENT or BITSET. Select the fallback, if the element type is not given literally.",
        &g_bitset_subtype, bitsetenumvals, FALSE);

    prefs_set_preference_effect_fields( trdp_module, "bitset.subtype");

    prefs_register_enum_preference( trdp_module, "numeric.subtype",
        "Select default byte-order for TRDP-Element types (5-7,9-13)",
        "Number types can be interpreted differently, as BE or LE (non-standard). Select the fallback, if the element type is not given literally.",
        &g_endian_subtype, endianenumvals, FALSE);

    prefs_set_preference_effect_fields( trdp_module, "numeric.subtype");

    prefs_register_bool_preference( trdp_module, "time.local",
        "Display time-types as local time, untick for UTC / no offsets.",
        "Time types should be based on UTC. When ticked, Wireshark adds on local timezone offset. Untick if you like UTC to be displayed, or the source is not UTC.",
        &g_time_local);

    prefs_register_bool_preference( trdp_module, "time.raw",
        "Display time-types as raw seconds, not absolute time.",
        "Time types should be absolute time since the UNIX-Epoch. When ticked, they are shown as seconds.",
        &g_time_raw);

    prefs_register_bool_preference( trdp_module, "0strings",
        "Variable-length CHAR8 and UTF16 arrays are 0-terminated. (non-standard)",
        "When ticked, the length of a variable-length string (array-size=0) is calculated from searching for a terminator instead of using a previous length element.",
        &g_0strings);

    prefs_register_bool_preference( trdp_module, "char8utf8",
        "Interpret CHAR8 arrays as UTF-8.",
        "When ticked, CHAR8 arrays are interpreted as UTF-8 string. If it fails, an exception is thrown. Untick if you need to see weird ASCII as C-escapes.",
        &g_char8_is_utf8);

    prefs_register_bool_preference( trdp_module, "strings.le",
        "Interpret UTF-16 strings with Little-Endian wire format. (non-standard)",
        "When ticked, UTF16 arrays are interpreted as Little-Endian encoding.",
        &g_strings_are_LE);

    prefs_register_bool_preference( trdp_module, "scaled",
        "Use scaled value for filter.",
        "When ticked, uses scaled values for filtering and display, otherwise the raw value.",
        &g_scaled);

    prefs_register_uint_preference( trdp_module, "pd.udp.port",
        "PD message Port",
        "UDP port for PD messages (Default port is " TRDP_DEFAULT_STR_PD_PORT ")",
        10 /*base */, &g_pd_port);

    prefs_register_uint_preference( trdp_module, "md.udptcp.port",
        "MD message Port",
        "UDP and TCP port for MD messages (Default port is " TRDP_DEFAULT_STR_MD_PORT ")",
        10 /*base */, &g_md_port);

    prefs_register_uint_preference( trdp_module, "sdtv2.sid",
        "SDTv2 SID (SC-32 Initial Value)",
        "SDTv2 SID (Initial Value) for SC-32 calculation (Default is " TRDP_DEFAULT_STR_SC32_SID ")",
        16 /*base */, &g_sid);

    /* abandon legacy prefs */
    prefs_register_obsolete_preference( trdp_module, "udp.port");
    prefs_register_obsolete_preference( trdp_module, "tcp.port");

    /* Register expert information */
    expert_module_t *expert_trdp;
    static ei_register_info ei[] = {
        {&ei_trdp_type_unkown,      {"trdp.type_unkown",       PI_UNDECODED, PI_WARN, "TRDP type unkown", EXPFILL}},
        {&ei_trdp_packet_small,     {"trdp.packet_size",       PI_UNDECODED, PI_WARN, "TRDP packet too small", EXPFILL}},
        {&ei_trdp_userdata_empty,   {"trdp.userdata_empty",    PI_UNDECODED, PI_WARN, "TRDP user data is empty", EXPFILL}},
        {&ei_trdp_userdata_wrong,   {"trdp.userdata_wrong",    PI_UNDECODED, PI_WARN, "TRDP user data has wrong format", EXPFILL}},
        {&ei_trdp_config_notparsed, {"trdp.config_unparsable", PI_UNDECODED, PI_WARN, "TRDP XML configuration cannot be parsed", EXPFILL}},
        {&ei_trdp_padding_not_zero, {"trdp.padding_non_zero",  PI_MALFORMED, PI_WARN, "TRDP Padding not filled with zero", EXPFILL}},
        {&ei_trdp_array_wrong,      {"trdp.array",             PI_MALFORMED, PI_WARN, "Dynamic array has unsupported datatype for length", EXPFILL}},
        {&ei_trdp_faulty_antivalent,{"trdp.faulty_antivalent", PI_MALFORMED, PI_WARN, "Data contains faulty antivalent value.", EXPFILL}},
        {&ei_trdp_reserved_not_zero,{"trdp.reserved_non_zero", PI_MALFORMED, PI_WARN, "Reserved attribute is not zero", EXPFILL}},
        {&ei_trdp_sdtv2_safetycode, {"trdp.sdtv2_safetycode",  PI_CHECKSUM, PI_ERROR, "SDTv2 SafetyCode check error.", EXPFILL}},
    };

    expert_trdp = expert_register_protocol(proto_trdp);
    expert_register_field_array(expert_trdp, ei, array_length(ei));
}
