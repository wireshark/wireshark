/* packet-tibia.c
 * Routines for Tibia/OTServ login and game protocol dissection
 *
 * Copyright 2017, Ahmad Fatoum <ahmad[AT]a3f.at>
 *
 * A dissector for:
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/* Tibia (https://tibia.com) is a Massively Multiplayer Online Role-Playing
 * Game (MMORPG) by Cipsoft GmbH.
 *
 * Three official clients exist: The current Qt-based 11.0+ client,
 * the old C++ client used from Tibia 7.0 till 10.99 and the Flash client.
 * The latter two are being phased out. They use the same protocol,
 * except that the session key for the Flash client is transported alongside
 * the character list over HTTPS. It's possible this is done in the same manner
 * as in the native client from 10.74 up. We don't support the Flash client.
 *
 * The dissector supports Tibia versions from 7.0 (2001) till
 * 11.00 (2016-10-12). Tibia has an active open source server emulator
 * community (OTServ) that still makes use of older versions and surpasses
 * the official servers in popularity, therefore compatibility with older
 * protocol iterations should be maintained.
 *
 * Transport is over TCP, with recent versions encrypting player interaction
 * with XTEA. Authentication and key exchange is done with a hard-coded
 * RSA public key in the client.
 *
 * Two protocols are dissected: The Tibia login protocol and the Tibia game
 * protocol. Traditionally, login servers were stateless and only responsible
 * for providing the addresses of the game servers alongside the character
 * list upon successful authentication. Then a new authentication request
 * (this time with character selection) is sent to the game server.
 * That way, a client who knows the game server address can very well skip
 * the login server entirely. Starting with 10.61, this is no longer possible,
 * as the login server provides a session key that needs to be sent to the
 * game server.
 *
 * Starting with Tibia 7.61, login server requests can't be reliably
 * differentiated from game server requests. Therefore we apply some heuristics
 * to classify packets.
 *
 * Starting with Tibia 11.01, a web service takes the role of the login server.
 * Starting with Tibia 11.11, the Adler32 checksum was replaced by a 32-bit
 * sequence number. The most significant bit indicates whether the packet was
 * DEFLATE-compressed. These features are not yet supported.
 *
 * Packets from and to the game server contain commands. Commands are
 * identified by the first octet and are variable in length. The dissector has
 * most command names hard-coded. However, a complete implementation of the
 * game protocol is unlikely.
 *
 * The RSA private key usually used by OTServ is hard-coded in. Server
 * administrators may add their own private key in PEM or PKCS#12 format over
 * an UAT. For servers where the private key is indeed private (like
 * for official servers), the symmetric XTEA key (retrievable by memory
 * peeking or MitM) may be provided to the dissector via UAT.
 *
 * Unsurprisingly, no official specification of the protocol exist, following
 * resources have been written by the community:
 *
 * - OTServ: Community effort to replicate a Tibia Server.
 * - Outcast: A Tibia client implementation of the game protocol as of 2006.
 *            Comes with a PDF spec written by Khaos
 * - TibiaAPI: Bot framework, containing a listing of commands as of 2009
 * - TFS: OTServ-Fork which is kept up-to-date with most of the official protocol
 * - otclient: Open Source implementation of an up-to-date Tibia client
 *
 * An official slide set by Cipsoft detailing the architecture of Tibia
 * from Game Developers Conference Europe 2011 is also available:
 * http://www.gdcvault.com/play/1014908/Inside-Tibia-The-Technical-Infrastructure
 *
 * The login protocol, as implemented here, has been inferred from network
 * footage and game client execution traces and was written from scratch.
 * The listing of game protocol commands were taken from TibiaAPI and Khaos' spec
 * No code of Cipsoft GmbH was used.
 *
 * Tibia is a registered trademark of Cipsoft GmbH.
 */

#include "config.h"
#include <epan/packet.h>
#include "packet-tcp.h"
#include <wsutil/adler32.h>
#include <epan/address.h>
#include <epan/to_str.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/conversation.h>
#include <epan/value_string.h>
#include <epan/expert.h>
#include <epan/address.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/report_message.h>
#include <wsutil/xtea.h>
#include <wsutil/strtoi.h>
#include <wsutil/rsa.h>
#include <errno.h>
#include <epan/ws_printf.h>
#include <epan/ptvcursor.h>

void proto_register_tibia(void);
void proto_reg_handoff_tibia(void);

/* preferences */
static gboolean try_otserv_key          = TRUE,
                show_char_name          = TRUE,
                show_acc_info           = TRUE,
                show_xtea_key           = FALSE,
                dissect_game_commands   = FALSE,
                reassemble_tcp_segments = TRUE;

/* User Access Tables */
#if HAVE_LIBGNUTLS
struct rsakey {
    address addr;
    guint16 port;

    gcry_sexp_t privkey;
};
GHashTable *rsakeys;

struct rsakeys_assoc {
    char *ipaddr;
    char *port;

    char *keyfile;
    char *password;
};

UAT_CSTRING_CB_DEF(rsakeylist_uats,  ipaddr,   struct rsakeys_assoc)
UAT_CSTRING_CB_DEF(rsakeylist_uats,  port,     struct rsakeys_assoc)
UAT_FILENAME_CB_DEF(rsakeylist_uats, keyfile,  struct rsakeys_assoc)
UAT_CSTRING_CB_DEF(rsakeylist_uats,  password, struct rsakeys_assoc)

static void rsakey_free(void *_rsakey);

static uat_t *rsakeys_uat = NULL;
static struct rsakeys_assoc  *rsakeylist_uats = NULL;
static guint nrsakeys = 0;
#endif

#define XTEA_KEY_LEN 16

struct xteakeys_assoc {
    guint32 framenum;

    char *key;
};
GHashTable *xteakeys;

static void *xteakeys_copy_cb(void *, const void *, size_t);
static void xteakeys_free_cb(void *);
static void xtea_parse_uat(void);
static gboolean xteakeys_uat_fld_key_chk_cb(void *, const char *, guint, const void *, const void *, char **);

UAT_DEC_CB_DEF(xteakeylist_uats, framenum, struct xteakeys_assoc)
UAT_CSTRING_CB_DEF(xteakeylist_uats, key, struct xteakeys_assoc)

static uat_t *xteakeys_uat = NULL;
static struct xteakeys_assoc *xteakeylist_uats = NULL;
static guint nxteakeys = 0;

#define COND_POISONED     0x1
#define COND_BURNING      0x2
#define COND_ELECTROCUTED 0x4
#define COND_DRUNK        0x8
#define COND_MANASHIELD   0x10
#define COND_PARALYZED    0x20
#define COND_HASTE        0x40
#define COND_BATTLE       0x80
#define COND_DROWNING     0x100
#define COND_FREEZING     0x200
#define COND_DAZZLED      0x400
#define COND_CURSED       0x800
#define COND_BUFF         0x1000
#define COND_PZBLOCK      0x2000
#define COND_PZ           0x4000
#define COND_BLEEDING     0x8000
#define COND_HUNGRY       0x10000

/* The login server has been traditionally on 7171,
 * For OTServ, the game server often listens on the same IP/port,
 * but occasionally on 7172. Official Tibia doesn't host login and
 * game servers on the same IP address
 */

#define TIBIA_DEFAULT_TCP_PORT_RANGE "7171,7172"

static gint proto_tibia = -1;

static gint hf_tibia_len                     = -1;
static gint hf_tibia_nonce                   = -1;
static gint hf_tibia_adler32                 = -1;
static gint hf_tibia_adler32_status          = -1;
static gint hf_tibia_os                      = -1;
static gint hf_tibia_proto_version           = -1;
static gint hf_tibia_client_version          = -1;
static gint hf_tibia_file_versions           = -1;
static gint hf_tibia_file_version_spr        = -1;
static gint hf_tibia_file_version_dat        = -1;
static gint hf_tibia_file_version_pic        = -1;
static gint hf_tibia_game_preview_state      = -1;
static gint hf_tibia_content_revision        = -1;
static gint hf_tibia_undecoded_rsa_data      = -1;
static gint hf_tibia_undecoded_xtea_data     = -1;
static gint hf_tibia_unknown                 = -1;
static gint hf_tibia_xtea_key                = -1;
static gint hf_tibia_loginflags_gm           = -1;
static gint hf_tibia_acc_name                = -1;
static gint hf_tibia_acc_number              = -1;
static gint hf_tibia_session_key             = -1;
static gint hf_tibia_char_name               = -1;
static gint hf_tibia_acc_pass                = -1;
static gint hf_tibia_char_name_convo         = -1;
static gint hf_tibia_acc_name_convo          = -1;
static gint hf_tibia_acc_pass_convo          = -1;
static gint hf_tibia_session_key_convo       = -1;

static gint hf_tibia_client_info             = -1;
static gint hf_tibia_client_locale           = -1;
static gint hf_tibia_client_locale_id        = -1;
static gint hf_tibia_client_locale_name      = -1;
static gint hf_tibia_client_ram              = -1;
static gint hf_tibia_client_cpu              = -1;
static gint hf_tibia_client_cpu_name         = -1;
static gint hf_tibia_client_clock            = -1;
static gint hf_tibia_client_clock2           = -1;
static gint hf_tibia_client_gpu              = -1;
static gint hf_tibia_client_vram             = -1;
static gint hf_tibia_client_resolution       = -1;
static gint hf_tibia_client_resolution_x     = -1;
static gint hf_tibia_client_resolution_y     = -1;
static gint hf_tibia_client_resolution_hz    = -1;

static gint hf_tibia_payload_len             = -1;
static gint hf_tibia_loginserv_command       = -1;
static gint hf_tibia_gameserv_command        = -1;
static gint hf_tibia_client_command          = -1;

static gint hf_tibia_motd                    = -1;
static gint hf_tibia_dlg_error               = -1;
static gint hf_tibia_dlg_info                = -1;

static gint hf_tibia_charlist                = -1;
static gint hf_tibia_charlist_length         = -1;
static gint hf_tibia_charlist_entry_name     = -1;
static gint hf_tibia_charlist_entry_world    = -1;
static gint hf_tibia_charlist_entry_ip       = -1;
static gint hf_tibia_charlist_entry_port     = -1;

static gint hf_tibia_worldlist               = -1;
static gint hf_tibia_worldlist_length        = -1;
static gint hf_tibia_worldlist_entry_name    = -1;
static gint hf_tibia_worldlist_entry_ip      = -1;
static gint hf_tibia_worldlist_entry_port    = -1;
static gint hf_tibia_worldlist_entry_preview = -1;
static gint hf_tibia_worldlist_entry_id      = -1;
static gint hf_tibia_pacc_days               = -1;

static gint hf_tibia_channel_id              = -1;
static gint hf_tibia_channel_name            = -1;

static gint hf_tibia_char_cond               = -1;
static gint hf_tibia_char_cond_poisoned      = -1;
static gint hf_tibia_char_cond_burning       = -1;
static gint hf_tibia_char_cond_electrocuted  = -1;
static gint hf_tibia_char_cond_drunk         = -1;
static gint hf_tibia_char_cond_manashield    = -1;
static gint hf_tibia_char_cond_paralyzed     = -1;
static gint hf_tibia_char_cond_haste         = -1;
static gint hf_tibia_char_cond_battle        = -1;
static gint hf_tibia_char_cond_drowning      = -1;
static gint hf_tibia_char_cond_freezing      = -1;
static gint hf_tibia_char_cond_dazzled       = -1;
static gint hf_tibia_char_cond_cursed        = -1;
static gint hf_tibia_char_cond_buff          = -1;
static gint hf_tibia_char_cond_pzblock       = -1;
static gint hf_tibia_char_cond_pz            = -1;
static gint hf_tibia_char_cond_bleeding      = -1;
static gint hf_tibia_char_cond_hungry        = -1;

static int * const char_conds[] = {
    &hf_tibia_char_cond_poisoned,
    &hf_tibia_char_cond_burning,
    &hf_tibia_char_cond_electrocuted,
    &hf_tibia_char_cond_drunk,
    &hf_tibia_char_cond_manashield,
    &hf_tibia_char_cond_paralyzed,
    &hf_tibia_char_cond_haste,
    &hf_tibia_char_cond_battle,
    &hf_tibia_char_cond_drowning,
    &hf_tibia_char_cond_freezing,
    &hf_tibia_char_cond_dazzled,
    &hf_tibia_char_cond_cursed,
    &hf_tibia_char_cond_buff,
    &hf_tibia_char_cond_pzblock,
    &hf_tibia_char_cond_pz,
    &hf_tibia_char_cond_bleeding,
    &hf_tibia_char_cond_hungry,
    NULL
};

static gint hf_tibia_chat_msg            = -1;
static gint hf_tibia_speech_type         = -1;

static gint hf_tibia_coords_x            = -1;
static gint hf_tibia_coords_y            = -1;
static gint hf_tibia_coords_z            = -1;
static gint hf_tibia_coords              = -1;
static gint hf_tibia_stackpos            = -1;

#if 0
static gint hf_tibia_item                = -1;
#endif
static gint hf_tibia_container           = -1;
static gint hf_tibia_container_icon      = -1;
static gint hf_tibia_container_slot      = -1;
static gint hf_tibia_container_slots     = -1;
static gint hf_tibia_inventory           = -1;
static gint hf_tibia_vip                 = -1;
static gint hf_tibia_vip_online          = -1;
static gint hf_tibia_player              = -1;
static gint hf_tibia_creature            = -1;
static gint hf_tibia_creature_health     = -1;
static gint hf_tibia_window              = -1;
static gint hf_tibia_window_icon         = -1;
static gint hf_tibia_window_textlen      = -1;
static gint hf_tibia_window_text         = -1;

static gint hf_tibia_light_level         = -1;
static gint hf_tibia_light_color         = -1;
static gint hf_tibia_magic_effect_id     = -1;
static gint hf_tibia_animated_text_color = -1;
static gint hf_tibia_animated_text       = -1;
static gint hf_tibia_projectile          = -1;
static gint hf_tibia_squarecolor         = -1;
static gint hf_tibia_textmsg_class       = -1;
static gint hf_tibia_textmsg             = -1;
static gint hf_tibia_walk_dir            = -1;


static gint ett_tibia               = -1;
static gint ett_command             = -1;
static gint ett_file_versions       = -1;
static gint ett_client_info         = -1;
static gint ett_locale              = -1;
static gint ett_cpu                 = -1;
static gint ett_resolution          = -1;
static gint ett_charlist            = -1;
static gint ett_worldlist           = -1;
static gint ett_char                = -1;
static gint ett_world               = -1;
static gint ett_coords              = -1;
static gint ett_char_cond           = -1;


static expert_field ei_xtea_len_toobig               = EI_INIT;
static expert_field ei_adler32_checksum_bad          = EI_INIT;
static expert_field ei_rsa_plaintext_no_leading_zero = EI_INIT;
static expert_field ei_rsa_ciphertext_too_short      = EI_INIT;
static expert_field ei_rsa_decrypt_failed            = EI_INIT;


struct proto_traits {
    guint32 adler32:1, rsa:1, compression:1, xtea:1, login_webservice:1, acc_name:1, nonce:1,
            extra_gpu_info:1, gmbyte:1, hwinfo:1;
    guint32 outfit_addons:1, stamina:1, lvl_on_msg:1;
    guint32 ping:1, client_version:1, game_preview:1, auth_token:1, session_key:1;
    guint32 game_content_revision:1, worldlist_in_charlist:1;
    guint string_enc;
};

struct tibia_convo {
    guint32 xtea_key[XTEA_KEY_LEN / sizeof (guint32)];
    guint32 xtea_framenum;
    const guint8 *acc, *pass, *char_name, *session_key;
    struct proto_traits has;

    guint16 proto_version;
    guint8 loginserv_is_peer :1;
    guint16 clientport;
    guint16 servport;

    gcry_sexp_t privkey;
};

static struct proto_traits
get_version_traits(guint16 version)
{
    struct proto_traits has;
    memset(&has, 0, sizeof has);
    has.gmbyte = TRUE; /* Not sure when the GM byte first appeared */
    has.string_enc = ENC_ISO_8859_1;

    if (version >= 761) /* 761 was a test client. 770 was the first release */
        has.xtea = has.rsa = TRUE;
    if (version >= 780)
        has.outfit_addons = has.stamina = has.lvl_on_msg = TRUE;
    if (version >= 830)
        has.adler32 = has.acc_name = TRUE;
    if (version >= 841)
        has.hwinfo = has.nonce = TRUE;
    if (version >= 953)
        has.ping = TRUE;
    if (version >= 980)
        has.client_version = has.game_preview = TRUE;
    if (version >= 1010)
        has.worldlist_in_charlist = TRUE;
    if (version >= 1061)
        has.extra_gpu_info = TRUE;
    if (version >= 1071)
        has.game_content_revision = TRUE;
    if (version >= 1072)
        has.auth_token = TRUE;
    if (version >= 1074)
        has.session_key = TRUE;
    if (version >= 1101)
        has.login_webservice = TRUE;
    if (version >= 1111) {
        has.compression = TRUE; /* with DEFLATE */
        has.adler32 = FALSE;
    }
#if 0 /* With the legacy client being phased out, maybe Unicode support incoming? */
    if (version >= 11xy)
        has.string_enc = ENC_UTF_8;
#endif

    return has;
}

static guint16
get_version_get_charlist_packet_size(struct proto_traits *has)
{
    guint16 size = 2;
    if (has->adler32 || has->compression)
        size += 4;
    size += 17;
    if (has->extra_gpu_info)
        size += 222;
    if (has->rsa)
        size += 128;

    return size;
}
static guint16
get_version_char_login_packet_size(struct proto_traits *has)
{
    guint16 size = 2;
    if (has->adler32 || has->compression)
        size += 4;
    size += 5;
    if (has->client_version)
        size += 4;
    if (has->game_content_revision)
        size += 2;
    if (has->game_preview)
        size += 1;
    if (has->rsa)
        size += 128;

    return size;
}


#define XTEA_FROM_UAT 0
#define XTEA_UNKNOWN  0xFFFFFFFF

static struct tibia_convo *
tibia_get_convo(packet_info *pinfo)
{
    conversation_t *epan_conversation = find_or_create_conversation(pinfo);

    struct tibia_convo *convo = (struct tibia_convo*)conversation_get_proto_data(epan_conversation, proto_tibia);

    if (!convo) {
        address *servaddr;
        convo = wmem_new0(wmem_file_scope(), struct tibia_convo);

        /* FIXME there gotta be a cleaner way... */
        if (pinfo->srcport >= 0xC000) {
            convo->clientport = pinfo->srcport;

            convo->servport = pinfo->destport;
            servaddr = &pinfo->dst;
        } else {
            convo->clientport = pinfo->destport;

            convo->servport = pinfo->srcport;
            servaddr = &pinfo->src;
        }
        (void)servaddr;
#ifdef HAVE_LIBGNUTLS
        struct rsakey rsa_key;
        rsa_key.port = convo->servport;
        rsa_key.addr = *servaddr;
        convo->privkey = (gcry_sexp_t)g_hash_table_lookup(rsakeys, &rsa_key);
#endif
        convo->xtea_framenum = XTEA_UNKNOWN;

        conversation_add_proto_data(epan_conversation, proto_tibia, (void *)convo);
    }

    if (convo->xtea_framenum == XTEA_UNKNOWN) {
        guint8 *xtea_key = (guint8*)g_hash_table_lookup(xteakeys, GUINT_TO_POINTER(pinfo->num));
        if (xtea_key) {
            memcpy(convo->xtea_key, xtea_key, XTEA_KEY_LEN);
            convo->xtea_framenum = XTEA_FROM_UAT;
        }
    }

    return convo;
}

static guint32
ipv4tonl(const char *str)
{
        guint32 ipaddr = 0;
        for (int octet = 0; octet < 4; octet++) {
            ws_strtou8(str, &str, &((guint8*)&ipaddr)[octet]);
            str++;
        }
        return ipaddr;
}

static void
register_gameserv_addr(struct tibia_convo *convo, guint32 ipaddr, guint16 port)
{
    (void)convo; (void)ipaddr; (void)port;
#if HAVE_LIBGNUTLS
    /* Game servers in the list inherit the same RSA key as the login server */
    if (convo->has.rsa) {
        struct rsakey *entry = g_new(struct rsakey, 1);
        alloc_address_wmem(NULL, &entry->addr, AT_IPv4, sizeof ipaddr, &ipaddr);
        entry->port = port;
        entry->privkey = NULL;
        if (g_hash_table_lookup(rsakeys, entry) == NULL) {
            entry->privkey = convo->privkey;
            g_hash_table_insert(rsakeys, entry, entry->privkey);
        } else {
            rsakey_free(entry);
        }
    }

    /* TODO Mark all communication with the IP/Port pair above
     * as Tibia communication. How?
     */
#endif
}

static gcry_sexp_t otserv_key;
static gcry_sexp_t
convo_get_privkey(struct tibia_convo *convo)
{
    return convo->privkey ? convo->privkey
         : try_otserv_key ? otserv_key
         : NULL;
}

enum client_cmd {
    /* from TibiaAPI */
    C_GET_CHARLIST          = 0x01,
    C_LOGIN_CHAR            = 0x0A,
    C_LOGOUT                = 0x14, /* I think this is a 7.7+ thing */
    C_PONG                  = 0x1E,

    C_AUTO_WALK             = 0x64,
    C_GO_NORTH              = 0x65,
    C_GO_EAST               = 0x66,
    C_GO_SOUTH              = 0x67,
    C_GO_WEST               = 0x68,
    C_AUTO_WALK_CANCEL      = 0x69,
    C_GO_NE                 = 0x6A,
    C_GO_SE                 = 0x6B,
    C_GO_SW                 = 0x6C,
    C_GO_NW                 = 0x6D,
    C_TURN_NORTH            = 0x6F,
    C_TURN_EAST             = 0x70,
    C_TURN_SOUTH            = 0x71,
    C_TURN_WEST             = 0x72,
    C_MOVE_ITEM             = 0x78,
    C_SHOP_BUY              = 0x7A,
    C_SHOP_SELL             = 0x7B,
    C_SHOP_CLOSE            = 0x7C,
    C_ITEM_USE              = 0x82,
    C_ITEM_USE_ON           = 0x83,
    C_ITEM_USE_BATTLELIST   = 0x84,
    C_ITEM_ROTATE           = 0x85,
    C_CONTAINER_CLOSE       = 0x87,
    C_CONTAINER_OPEN_PARENT = 0x88,
    C_LOOK_AT               = 0x8C,
    C_PLAYER_SPEECH         = 0x96,
    C_CHANNEL_LIST          = 0x97,
    C_CHANNEL_OPEN          = 0x98,
    C_CHANNEL_CLOSE         = 0x99,
    C_PRIVATE_CHANNEL_OPEN  = 0x9A,
    C_NPC_CHANNEL_CLOSE     = 0x9E,
    C_FIGHT_MODES           = 0xA0,
    C_ATTACK                = 0xA1,
    C_FOLLOW                = 0xA2,
    C_CANCEL_GO             = 0xBE,
    C_TILE_UPDATE           = 0xC9,
    C_CONTAINER_UPDATE      = 0xCA,
    C_SET_OUTFIT            = 0xD3,
    C_VIP_ADD               = 0xDC,
    C_VIP_REMOVE            = 0xDD
 };

static const value_string from_client_packet_types[] = {
    { C_GET_CHARLIST,     "Charlist request" },
    { C_LOGIN_CHAR,       "Character login" },

    { C_LOGOUT,           "Logout" },
    { C_PONG,             "Pong" },

    { C_AUTO_WALK,        "Map walk" },
    { C_GO_NORTH,         "Go north"},
    { C_GO_EAST,          "Go east"},
    { C_GO_SOUTH,         "Go south"},
    { C_GO_WEST,          "Go west"},
    { C_AUTO_WALK_CANCEL, "Map walk cancel" },
    { C_GO_NE,            "Go north-east"},
    { C_GO_SE,            "Go south-east"},
    { C_GO_SW,            "Go south-west"},
    { C_GO_NW,            "Go north-west"},

    { C_TURN_NORTH,      "Turn north" },
    { C_TURN_EAST,       "Turn east" },
    { C_TURN_SOUTH,      "Turn south" },
    { C_TURN_WEST,       "Turn west" },
    { C_MOVE_ITEM,       "Move item" },
    { C_SHOP_BUY,        "Buy in shop" },
    { C_SHOP_SELL,       "Sell in shop" },
    { C_SHOP_CLOSE,      "Close shop" },
    { C_ITEM_USE,        "Use item" },
    { C_ITEM_USE_ON,     "Use item on" },
    { C_ITEM_USE_BATTLELIST,   "Use item on battle list" },
    { C_ITEM_ROTATE,           "Rotate item" },

    { C_CONTAINER_CLOSE,       "Close container" },
    { C_CONTAINER_OPEN_PARENT, "Open parent container" },
    { C_LOOK_AT,               "Look at" },
    { C_PLAYER_SPEECH,         "Speech" },
    { C_CHANNEL_LIST,          "List channels" },
    { C_CHANNEL_OPEN,          "Open public channel" },
    { C_CHANNEL_CLOSE,         "close channel" },
    { C_PRIVATE_CHANNEL_OPEN,  "Open private channel" },
    { C_NPC_CHANNEL_CLOSE,     "Open NPC channel" },
    { C_FIGHT_MODES,           "Set fight modes" },
    { C_ATTACK,                "Attack" },
    { C_FOLLOW,                "Follow" },
    { C_CANCEL_GO,             "Cancel go" },
    { C_TILE_UPDATE,           "Update tile" },
    { C_CONTAINER_UPDATE,      "Update container" },
    { C_SET_OUTFIT,            "Set outfit" },
    { C_VIP_ADD,               "Add VIP" },
    { C_VIP_REMOVE,            "Remove VIP" },

    { 0, NULL }
};

static value_string_ext from_client_packet_types_ext = VALUE_STRING_EXT_INIT(from_client_packet_types);

enum loginserv_cmd {
    LOGINSERV_DLG_ERROR    = 0x0A,
    LOGINSERV_DLG_ERROR2   = 0x0B,
    LOGINSERV_DLG_MOTD     = 0x14,
    LOGINSERV_SESSION_KEY  = 0x28,
    LOGINSERV_DLG_CHARLIST = 0x64
};

static const value_string from_loginserv_packet_types[] = {
    { LOGINSERV_DLG_ERROR,    "Error" },
    { LOGINSERV_DLG_ERROR2,   "Error" },
    { LOGINSERV_DLG_MOTD,     "MOTD" },
    { LOGINSERV_SESSION_KEY,  "Session key" },
    { LOGINSERV_DLG_CHARLIST, "Charlist" },

    { 0, NULL }
};

enum gameserv_cmd {
    /* Credit to Khaos (OBJECT Networks). Values and comments extracted from PDF table */
    S_MAPINIT =                0x0A, /* Long playerCreatureId Int unknownU16 (Byte reportBugs?) */
    S_GMACTIONS =              0x0B, /* Used to be 32 unknown bytes, but with GMs removed it                                      might not be in use anymore */
    S_DLG_ERROR =              0x14, /* String errorMessage */
    S_DLG_INFO =               0x15,
    S_DLG_TOOMANYPLAYERS =     0x16,
    S_PING =                   0x1E,
    S_NONCE =                  0x1F,
    S_PLAYERLOC =              0x64, /* Coord pos */
    S_GO_NORTH =               0x65, /* MapDescription (18,1) */
    S_GO_EAST =                0x66, /* MapDescription (1,14) */
    S_GO_SOUTH =               0x67, /* MapDescription (18,1) */
    S_GO_WEST =                0x68, /* MapDescription (1,14) */
    S_TILEUPDATE =             0x69, /* Coord pos TileDescription td */
    S_ADDITEM =                0x6a, /* Coord pos ThingDescription thing */
    S_REPLACEITEM =            0x6b, /* Coord pos Byte stackpos ThingDescription thing */
    S_REMOVEITEM =             0x6c, /* Coord pos Byte stackpos */
    S_MOVE_THING =             0x6d,
    S_CONTAINER =              0x6e, /* Byte index Short containerIcon Byte slotCount ThingDescription item */
    S_CONTAINERCLOSE =         0x6f, /* Byte index */
    S_ADDITEMCONTAINER =       0x70, /* Byte index ThingDescription itm */
    S_TRANSFORMITEMCONTAINER = 0x71, /* Byte index Byte slot */
    S_REMOVEITEMCONTAINER =    0x72, /* Byte index Byte slot */
    S_INVENTORYEMPTY =         0x78, /* Byte invSlot */
    S_INVENTORYITEM =          0x79, /* Byte invSlot ThingDescription itm */
    S_TRADEREQ =               0x7d, /* String otherperson Byte slotCount ThingDescription itm */
    S_TRADEACK =               0x7e, /* String otherperson Byte slotCount ThingDescription itm */
    S_TRADECLOSE =             0x7f,
    S_LIGHTLEVEL =             0x82, /* Byte lightlevel Byte lightcolor */
    S_MAGIC_EFFECT =           0x83,
    S_ANIMATEDTEXT =           0x84, /* Coord pos Byte color String message */
    S_DISTANCESHOT =           0x85, /* Coord pos1 Byte stackposition Coord pos2 */
    S_CREATURESQUARE =         0x86, /* Long creatureid Byte squarecolor */
    S_CREATURE_HEALTH =        0x8C,
    S_CREATURELIGHT =          0x8d, /* Long creatureid Byte ? Byte ? */
    S_SETOUTFIT =              0x8e, /* Long creatureid Byte lookType Byte headType Byte bodyType Byte legsType Byte feetType // can extended look go here too? */
    S_CREATURESPEED =          0x8f, /* YIKES! I didnt handle this! */
    S_TEXTWINDOW =             0x96, /* Long windowId Byte icon Byte maxlength String message */
    S_STATUSMSG =              0xA0, /* Status status */
    S_SKILLS =                 0xA1, /* Skills skills */
    S_PLAYER_CONDITION =       0xA2,
    S_CANCELATTACK =           0xA3,
    S_SPEAK =                  0xAA,
    S_CHANNELSDIALOG =         0xAB, /* Byte channelCount (Int channelId String channelName) */
    S_CHANNEL_OPEN =           0xAC,
    S_OPENPRIV =               0xAD, /* String playerName */
    S_TEXTMESSAGE =            0xB4, /* Byte msgClass String string */
    S_CANCELWALK =             0xB5, /* Byte direction */
    S_FLOORUP =                0xBE, /* Advanced topic; read separate text */
    S_FLOORDOWN =              0xBF, /* Advanced topic; read separate text */
    S_OUTFITLIST =             0xC8, /* Byte lookType Byte headType Byte bodyType Byte legsType Byte feetType Byte firstModel Byte lastModel */
    S_VIPADD =                 0xD2, /* long guid string name byte isonline */
    S_VIPLOGIN =               0xD3, /* long guid */
    S_VIPLOGOUT =              0xD4  /* long guid*/
};
static const value_string from_gameserv_packet_types[] = {

    { S_MAPINIT,            "Initialize map" },
    { S_GMACTIONS,          "GM actions" },
    { S_DLG_ERROR,          "Error" },
    { S_DLG_INFO,           "Info" },
    { S_DLG_TOOMANYPLAYERS, "Too many players" },
    { S_PING,               "Ping" },
    { S_NONCE,              "Nonce" },
    { S_PLAYERLOC,      "Set player location" },
    { S_GO_NORTH,       "Go north" },
    { S_GO_EAST,        "Go east" },
    { S_GO_SOUTH,       "Go south" },
    { S_GO_WEST,        "Go west" },
    { S_TILEUPDATE,     "Update tile" },
    { S_ADDITEM,        "Add item" },
    { S_REPLACEITEM,    "Replace item" },
    { S_REMOVEITEM,     "Remove item" },
    { S_MOVE_THING,     "Move thing" },
    { S_CONTAINER,      "Open container" },
    { S_CONTAINERCLOSE, "Close container" },

    { S_ADDITEMCONTAINER,       "Add item in container" },
    { S_TRANSFORMITEMCONTAINER, "Transform item in container" },
    { S_REMOVEITEMCONTAINER,    "Remove item in container" },

    { S_INVENTORYEMPTY,   "Inventory empty" },
    { S_INVENTORYITEM,    "Inventory item" },
    { S_TRADEREQ,         "Trade request" },
    { S_TRADEACK,         "Trade acknowledge" },
    { S_TRADECLOSE,       "Trade over" },
    { S_LIGHTLEVEL,       "Light level" },
    { S_MAGIC_EFFECT,     "Magic effect" },
    { S_ANIMATEDTEXT,     "Animated text" },
    { S_DISTANCESHOT,     "Distance shot" },
    { S_CREATURESQUARE,   "Creature square" },
    { S_CREATURE_HEALTH,  "Creature health" },
    { S_CREATURELIGHT,    "Creature light" },
    { S_SETOUTFIT,        "Set outfit" },
    { S_CREATURESPEED,    "Set creature speed" },
    { S_TEXTWINDOW,       "Text window" },
    { S_STATUSMSG,        "Status message" },
    { S_SKILLS,           "Skills" },
    { S_PLAYER_CONDITION, "Player condition" },
    { S_CANCELATTACK,     "Cancel attack" },
    { S_SPEAK,            "Creature speech" },
    { S_CHANNELSDIALOG,   "Channels dialog" },
    { S_CHANNEL_OPEN,     "Channel open" },
    { S_OPENPRIV,         "Private channel open" },
    { S_TEXTMESSAGE,      "Text message" },
    { S_CANCELWALK,       "Cancel walk" },
    { S_FLOORUP,          "Floor +1" },
    { S_FLOORDOWN,        "Floor -1" },
    { S_OUTFITLIST,       "Outfit list" },
    { S_VIPADD,           "Add VIP" },
    { S_VIPLOGIN,         "VIP login" },
    { S_VIPLOGOUT,        "VIP logout" },

    { 0, NULL }
};

static value_string_ext from_gameserv_packet_types_ext = VALUE_STRING_EXT_INIT(from_gameserv_packet_types);

static const unit_name_string mb_unit = {"MB", NULL};

static int
dissect_loginserv_packet(struct tibia_convo *convo, tvbuff_t *tvb, int offset, int len, packet_info *pinfo, proto_tree *tree, gboolean first_fragment )
{
    ptvcursor_t *ptvc = ptvcursor_new(pinfo->pool, tree, tvb, offset);

    col_append_str(pinfo->cinfo, COL_INFO, first_fragment ? " commands:" : ",");
    len += offset;

    if (ptvcursor_current_offset(ptvc) < len) {
        for (;;) {
            int cmd = tvb_get_guint8(tvb, ptvcursor_current_offset(ptvc));
            ptvcursor_add_with_subtree(ptvc, hf_tibia_loginserv_command, 1, convo->has.string_enc, ett_command);
            ptvcursor_advance(ptvc, 1);

            switch ((enum loginserv_cmd)cmd) {
                case LOGINSERV_DLG_ERROR:
                case LOGINSERV_DLG_ERROR2:
                    ptvcursor_add(ptvc, hf_tibia_dlg_error, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc);
                    break;
                case LOGINSERV_DLG_MOTD:
                    ptvcursor_add(ptvc, hf_tibia_motd, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc);
                    break;
                case LOGINSERV_SESSION_KEY:
                    ptvcursor_add(ptvc, hf_tibia_session_key, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc);
                    break;
                case LOGINSERV_DLG_CHARLIST:
                    if (convo->has.worldlist_in_charlist) {
                        guint8 world_count = tvb_get_guint8(tvb, ptvcursor_current_offset(ptvc));
                        ptvcursor_add(ptvc, hf_tibia_worldlist_length, 1, ENC_NA);
                        /* Empty character list? */
                        if (world_count) {
                            ptvcursor_add_with_subtree(ptvc, hf_tibia_worldlist, SUBTREE_UNDEFINED_LENGTH, ENC_NA, ett_worldlist);
                            while (world_count--) {
                                proto_item *it = ptvcursor_add(ptvc, hf_tibia_worldlist_entry_id, 1, ENC_NA);
                                ptvcursor_push_subtree(ptvc, it, ett_world);

                                ptvcursor_add(ptvc, hf_tibia_worldlist_entry_name, 2, convo->has.string_enc | ENC_LITTLE_ENDIAN);
                                guint ipv4addr_len = tvb_get_letohs(tvb, ptvcursor_current_offset(ptvc));
                                char *ipv4addr_str = (char*)tvb_get_string_enc(pinfo->pool, tvb, ptvcursor_current_offset(ptvc) + 2, ipv4addr_len, ENC_LITTLE_ENDIAN | convo->has.string_enc);
                                guint32 ipv4addr = ipv4tonl(ipv4addr_str);
                                ptvcursor_add(ptvc, hf_tibia_worldlist_entry_ip, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc);
                                guint16 port = tvb_get_letohs(tvb, ptvcursor_current_offset(ptvc));
                                ptvcursor_add(ptvc, hf_tibia_worldlist_entry_port, 2, ENC_LITTLE_ENDIAN);
                                ptvcursor_add(ptvc, hf_tibia_worldlist_entry_preview, 1, ENC_NA);

                                ptvcursor_pop_subtree(ptvc);

                                register_gameserv_addr(convo, ipv4addr, port);
                            }
                            ptvcursor_pop_subtree(ptvc);
                        }

                        guint8 char_count = tvb_get_guint8(tvb, ptvcursor_current_offset(ptvc));
                        ptvcursor_add(ptvc, hf_tibia_charlist_length, 1, ENC_NA);
                        if (char_count) {
                            ptvcursor_add_with_subtree(ptvc, hf_tibia_charlist, SUBTREE_UNDEFINED_LENGTH, ENC_NA, ett_charlist);
                            while (char_count--) {
                                proto_item *it = ptvcursor_add(ptvc, hf_tibia_worldlist_entry_id, 1, ENC_NA);
                                ptvcursor_push_subtree(ptvc, it, ett_char);
                                ptvcursor_add(ptvc, hf_tibia_charlist_entry_name, 2, convo->has.string_enc | ENC_LITTLE_ENDIAN);


                                ptvcursor_pop_subtree(ptvc);
                            }
                            ptvcursor_pop_subtree(ptvc);
                        }
                    } else {
                        guint8 char_count = tvb_get_guint8(tvb, ptvcursor_current_offset(ptvc));
                        ptvcursor_add(ptvc, hf_tibia_charlist_length, 1, ENC_NA);
                        if (char_count) {
                            ptvcursor_add_with_subtree(ptvc, hf_tibia_charlist, SUBTREE_UNDEFINED_LENGTH, ENC_NA, ett_charlist);

                            while (char_count--) {
                                proto_item *it = ptvcursor_add(ptvc, hf_tibia_charlist_entry_name, 2, convo->has.string_enc | ENC_LITTLE_ENDIAN);
                                ptvcursor_push_subtree(ptvc, it, ett_char);

                                ptvcursor_add(ptvc, hf_tibia_charlist_entry_world, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc);

                                guint32 ipv4addr = tvb_get_ipv4(tvb, ptvcursor_current_offset(ptvc));
                                ptvcursor_add(ptvc, hf_tibia_charlist_entry_ip, 4, ENC_BIG_ENDIAN);

                                guint16 port = tvb_get_letohs(tvb, ptvcursor_current_offset(ptvc));
                                ptvcursor_add(ptvc, hf_tibia_charlist_entry_port, 2, ENC_BIG_ENDIAN);


                                ptvcursor_pop_subtree(ptvc);

                                register_gameserv_addr(convo, ipv4addr, port);
                            }

                            ptvcursor_pop_subtree(ptvc);
                        }

                        ptvcursor_add(ptvc, hf_tibia_pacc_days, 2, ENC_LITTLE_ENDIAN);
                    }
                    break;
                default:
                    offset = ptvcursor_current_offset(ptvc);
                    call_data_dissector(tvb_new_subset_length(tvb, offset, len - offset), pinfo, ptvcursor_tree(ptvc));
                    ptvcursor_advance(ptvc, len - offset);
            }

            ptvcursor_pop_subtree(ptvc);

            col_append_fstr(pinfo->cinfo, COL_INFO, " %s (0x%x)",
                    val_to_str(cmd, from_loginserv_packet_types, "Unknown"), cmd);

            if (ptvcursor_current_offset(ptvc) >= len)
                break;

            col_append_str(pinfo->cinfo, COL_INFO, ",");
        }
    }

    offset = ptvcursor_current_offset(ptvc);
    ptvcursor_free(ptvc);

    return offset;
}

static void
dissect_coord(ptvcursor_t *ptvc, gboolean with_stackpos)
{
    tvbuff_t *tvb;
    proto_tree *tree;
    int offset;

    guint32 x, y, z, stackpos;
    proto_item *coords_tuple = ptvcursor_add_with_subtree(ptvc, hf_tibia_coords, SUBTREE_UNDEFINED_LENGTH, ENC_NA, ett_coords);
    {
        tvb = ptvcursor_tvbuff(ptvc);
        tree = ptvcursor_tree(ptvc);
        offset = ptvcursor_current_offset(ptvc);

        proto_tree_add_item_ret_uint(tree, hf_tibia_coords_x, tvb, offset, 2, ENC_LITTLE_ENDIAN, &x);
        offset += 2;
        proto_tree_add_item_ret_uint(tree, hf_tibia_coords_y, tvb, offset, 2, ENC_LITTLE_ENDIAN, &y);
        offset += 2;
        proto_tree_add_item_ret_uint(tree, hf_tibia_coords_z, tvb, offset, 1, ENC_NA, &z);
        offset += 1;

        ptvcursor_advance(ptvc, 5);
    }
    if (with_stackpos) {
        proto_tree_add_item_ret_uint(tree, hf_tibia_stackpos, tvb, offset, 1, ENC_NA, &stackpos);
        proto_item_set_text(coords_tuple, "Coordinates: (%u, %u, %u)[%u]", x, y, z, stackpos);
        ptvcursor_advance(ptvc, 1);
    } else {
        proto_item_set_text(coords_tuple, "Coordinates: (%u, %u, %u)", x, y, z);
    }

    ptvcursor_pop_subtree(ptvc);
}


static int
dissect_gameserv_packet(struct tibia_convo *convo, tvbuff_t *tvb, int offset, int len, packet_info *pinfo, proto_tree *tree, gboolean first_fragment)
{
    ptvcursor_t *ptvc = ptvcursor_new(pinfo->pool, tree, tvb, offset);

    col_append_str(pinfo->cinfo, COL_INFO, first_fragment ? " commands:" : ",");
    len += offset;

    if (ptvcursor_current_offset(ptvc) < len) {
        for (;;) {
            int cmd = tvb_get_guint8(tvb, ptvcursor_current_offset(ptvc));
            ptvcursor_add_with_subtree(ptvc, hf_tibia_gameserv_command, 1, convo->has.string_enc, ett_command);
            ptvcursor_advance(ptvc, 1);

            switch ((enum gameserv_cmd)cmd) {
                case S_DLG_INFO:
                case S_DLG_ERROR:
                case S_DLG_TOOMANYPLAYERS:
                    ptvcursor_add(ptvc, cmd == S_DLG_ERROR ? hf_tibia_dlg_error : hf_tibia_dlg_info, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc);
                    break;
                case S_GMACTIONS: /* 0x0B, Used to be 32 unknown bytes, but with GMs removed it                                     might not be in use anymore */
                    ptvcursor_add(ptvc, hf_tibia_unknown, 32, ENC_NA);
                    break;
                case S_PLAYERLOC: /* 0x64,Coord pos */
                    dissect_coord(ptvc, FALSE);
                    break;
                case S_TILEUPDATE: /* 0x69,Coord pos TileDescription td */
                    dissect_coord(ptvc, FALSE);
                    ptvcursor_add(ptvc, hf_tibia_unknown, len - ptvcursor_current_offset(ptvc), ENC_NA);
                    break;
                case S_ADDITEM: /* 0x6a,Coord pos ThingDescription thing */
                    dissect_coord(ptvc, FALSE);
                    ptvcursor_add(ptvc, hf_tibia_unknown, len - ptvcursor_current_offset(ptvc), ENC_NA);
                    break;
                case S_REPLACEITEM: /* 0x6b,Coord pos Byte stackpos ThingDescription thing */
                    dissect_coord(ptvc, TRUE);
                    ptvcursor_add(ptvc, hf_tibia_unknown, len - ptvcursor_current_offset(ptvc), ENC_NA);
                    break;
                case S_REMOVEITEM: /* 0x6c,Coord pos Byte stackpos */
                    dissect_coord(ptvc, TRUE);
                    break;
                case S_MOVE_THING: /* 0x6d, */
                    dissect_coord(ptvc, TRUE);
                    dissect_coord(ptvc, FALSE);
                    break;
                case S_CONTAINER: /* 0x6e,Byte index Short containerIcon Byte slotCount ThingDescription item */
                    ptvcursor_add(ptvc, hf_tibia_container, 1, ENC_NA);
                    ptvcursor_add(ptvc, hf_tibia_container_icon, 2, ENC_LITTLE_ENDIAN);
                    ptvcursor_add(ptvc, hf_tibia_container_slots, 2, ENC_LITTLE_ENDIAN);
                    ptvcursor_add(ptvc, hf_tibia_unknown, len - ptvcursor_current_offset(ptvc), ENC_NA);
                    break;
                case S_CONTAINERCLOSE: /* 0x6f,Byte index */
                    ptvcursor_add(ptvc, hf_tibia_container, 1, ENC_NA);
                    break;
                case S_ADDITEMCONTAINER: /* 0x70,Byte index ThingDescription itm */
                    ptvcursor_add(ptvc, hf_tibia_container, 1, ENC_NA);
                    ptvcursor_add(ptvc, hf_tibia_unknown, len - ptvcursor_current_offset(ptvc), ENC_NA);
                    break;
                case S_TRANSFORMITEMCONTAINER:/* 0x71,Byte index Byte slot */
                    ptvcursor_add(ptvc, hf_tibia_container, 1, ENC_NA);
                    ptvcursor_add(ptvc, hf_tibia_container_slot, 1, ENC_NA);
                    break;
                case S_REMOVEITEMCONTAINER: /* 0x72,Byte index Byte slot */
                    ptvcursor_add(ptvc, hf_tibia_container, 1, ENC_NA);
                    ptvcursor_add(ptvc, hf_tibia_container_slot, 1, ENC_NA);
                    break;
                case S_INVENTORYEMPTY: /* 0x78,Byte invSlot */
                    ptvcursor_add(ptvc, hf_tibia_inventory, 1, ENC_NA);
                    break;
                case S_INVENTORYITEM: /* 0x79,Byte invSlot ThingDescription itm */
                    ptvcursor_add(ptvc, hf_tibia_inventory, 1, ENC_NA);
                    ptvcursor_add(ptvc, hf_tibia_unknown, len - ptvcursor_current_offset(ptvc), ENC_NA);
                    break;
                case S_TRADEREQ: /* 0x7d,String otherperson Byte slotCount ThingDescription itm */
                    ptvcursor_add(ptvc, hf_tibia_player, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc);
                    ptvcursor_add(ptvc, hf_tibia_inventory, 1, ENC_NA);
                    ptvcursor_add(ptvc, hf_tibia_unknown, len - ptvcursor_current_offset(ptvc), ENC_NA);
                    break;
                case S_TRADEACK: /* 0x7e,String otherperson Byte slotCount ThingDescription itm */
                    ptvcursor_add(ptvc, hf_tibia_player, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc);
                    ptvcursor_add(ptvc, hf_tibia_inventory, 1, ENC_NA);
                    ptvcursor_add(ptvc, hf_tibia_unknown, len - ptvcursor_current_offset(ptvc), ENC_NA);
                    break;

                case S_TRADECLOSE: /* 0x7f, */
                    break;
                case S_LIGHTLEVEL: /* 0x82,Byte lightlevel Byte lightcolor */
                    ptvcursor_add(ptvc, hf_tibia_light_level, 1, ENC_NA);
                    ptvcursor_add(ptvc, hf_tibia_light_color, 1, ENC_NA);
                    break;
                case S_MAGIC_EFFECT: /* 0x83, */
                    dissect_coord(ptvc, FALSE);
                    ptvcursor_add(ptvc, hf_tibia_magic_effect_id, 1, ENC_NA);
                    break;
                case S_ANIMATEDTEXT: /* 0x84,Coord pos Byte color String message */
                    dissect_coord(ptvc, FALSE);
                    ptvcursor_add(ptvc, hf_tibia_animated_text_color, 1, ENC_NA);
                    ptvcursor_add(ptvc, hf_tibia_animated_text, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc);
                    break;
                case S_DISTANCESHOT: /* 0x85,Coord pos1 Byte stackposition Coord pos2 */
                    dissect_coord(ptvc, FALSE);
                    ptvcursor_add(ptvc, hf_tibia_projectile, 4, ENC_LITTLE_ENDIAN);
                    dissect_coord(ptvc, FALSE);
                    break;
                case S_CREATURESQUARE: /* 0x86,Long creatureid Byte squarecolor */
                    ptvcursor_add(ptvc, hf_tibia_creature, 4, ENC_LITTLE_ENDIAN);
                    ptvcursor_add(ptvc, hf_tibia_squarecolor, 1, ENC_NA);
                    break;
                case S_CREATURE_HEALTH: /* 0x8C, */
                    ptvcursor_add(ptvc, hf_tibia_creature, 1, ENC_LITTLE_ENDIAN);
                    ptvcursor_add(ptvc, hf_tibia_creature_health, 1, ENC_NA);
                    break;
                case S_CREATURELIGHT: /* 0x8d,Long creatureid Byte ? Byte ? */
                    ptvcursor_add(ptvc, hf_tibia_creature, 1, ENC_LITTLE_ENDIAN);
                    ptvcursor_add(ptvc, hf_tibia_unknown, 2, ENC_NA);
                    break;
                case S_SETOUTFIT: /* 0x8e,Long creatureid Byte lookType Byte headType Byte bodyType Byte legsType Byte feetType // can extended look go here too? */
                    ptvcursor_add(ptvc, hf_tibia_creature, 1, ENC_LITTLE_ENDIAN);
                    ptvcursor_add(ptvc, hf_tibia_unknown, len - ptvcursor_current_offset(ptvc), ENC_NA);
                    break;
                case S_TEXTWINDOW: /* 0x96,Long windowId Byte icon Byte maxlength String message */
                    ptvcursor_add(ptvc, hf_tibia_window, 4, ENC_LITTLE_ENDIAN);
                    ptvcursor_add(ptvc, hf_tibia_window_icon, 1, ENC_NA);
                    ptvcursor_add(ptvc, hf_tibia_window_textlen, 1, ENC_NA);
                    ptvcursor_add(ptvc, hf_tibia_window_text, 1, ENC_LITTLE_ENDIAN | convo->has.string_enc);
                    break;
                case S_PLAYER_CONDITION: /* 0xA2, */
                    proto_tree_add_bitmask(ptvcursor_tree(ptvc), ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc), hf_tibia_char_cond, ett_char_cond, char_conds, ENC_LITTLE_ENDIAN);
                    ptvcursor_advance(ptvc, 4);
                    break;
                case S_CANCELATTACK: /* 0xA3, */
                    break;
                case S_CHANNEL_OPEN:
                    ptvcursor_add(ptvc, hf_tibia_channel_id, 2, ENC_LITTLE_ENDIAN);
                    ptvcursor_add(ptvc, hf_tibia_channel_name, 2, ENC_LITTLE_ENDIAN|convo->has.string_enc);
                    ptvcursor_add(ptvc, hf_tibia_unknown, 4, ENC_NA);
                    break;
                case S_OPENPRIV: /* 0xAD,String playerName */
                    ptvcursor_add(ptvc, hf_tibia_player, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc);
                    break;
                case S_TEXTMESSAGE: /* 0xB4,Byte msgClass String string */
                    ptvcursor_add(ptvc, hf_tibia_textmsg_class, 1, ENC_NA);
                    ptvcursor_add(ptvc, hf_tibia_textmsg, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc);
                    break;
                case S_CANCELWALK: /* 0xB5,Byte direction */
                    ptvcursor_add(ptvc, hf_tibia_walk_dir, 1, ENC_NA);
                    break;
                case S_VIPADD: /* 0xd2,long guid string name byte isonline */
                    ptvcursor_add(ptvc, hf_tibia_vip, 4, ENC_LITTLE_ENDIAN);
                    ptvcursor_add(ptvc, hf_tibia_player, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc);
                    ptvcursor_add(ptvc, hf_tibia_vip_online, 1, ENC_NA);
                    break;
                case S_VIPLOGIN: /* 0xd3,long guid */
                    ptvcursor_add(ptvc, hf_tibia_vip, 4, ENC_LITTLE_ENDIAN);
                    break;
                case S_VIPLOGOUT: /* 0xd4long guid*/
                    ptvcursor_add(ptvc, hf_tibia_vip, 4, ENC_LITTLE_ENDIAN);
                    break;
                case S_PING:
                    break;
                case S_NONCE: /* 0x1F, */
                    ptvcursor_add(ptvc, hf_tibia_nonce, 5, ENC_NA);
                    break;

                case S_MAPINIT: /* 0x0A, Long playerCreatureId Int unknownU16 (Byte reportBugs?) */
                case S_OUTFITLIST: /* 0xC8,Byte lookType Byte headType Byte bodyType Byte legsType Byte feetType Byte firstModel Byte lastModel */
                    /* TODO This changed with mounts and outfit */
                case S_FLOORUP: /* 0xBE,Advanced topic; read separate text */
                case S_FLOORDOWN: /* 0xBF,Advanced topic; read separate text */
                case S_SPEAK: /* 0xAA, */
                case S_CHANNELSDIALOG: /* 0xAB,Byte channelCount (Int channelId String channelName) */
                case S_STATUSMSG: /* 0xA0,Status status */
                case S_SKILLS: /* 0xA1,Skills skills */
                case S_CREATURESPEED: /* 0x8f,YIKES! I didnt handle this! */
                case S_GO_NORTH: /* 0x65,MapDescription (18,1) */
                case S_GO_EAST: /* 0x66,MapDescription (1,14) */
                case S_GO_SOUTH: /* 0x67,MapDescription (18,1) */
                case S_GO_WEST: /* 0x68,MapDescription (1,14) */
                default:
                    offset = ptvcursor_current_offset(ptvc);
                    call_data_dissector(tvb_new_subset_length(tvb, offset, len - offset), pinfo, ptvcursor_tree(ptvc));
                    ptvcursor_advance(ptvc, len - offset);
            }


            ptvcursor_pop_subtree(ptvc);

            col_append_fstr(pinfo->cinfo, COL_INFO, " %s (0x%x)",
                    val_to_str(cmd, from_gameserv_packet_types, "Unknown"), cmd);

            if (ptvcursor_current_offset(ptvc) >= len)
                break;

            col_append_str(pinfo->cinfo, COL_INFO, ",");
        }
    }

    offset = ptvcursor_current_offset(ptvc);
    ptvcursor_free(ptvc);

    return offset;
}

static int
dissect_client_packet(struct tibia_convo *convo, tvbuff_t *tvb, int offset, int len, packet_info *pinfo, proto_tree *tree, gboolean first_fragment)
{
    ptvcursor_t *ptvc = ptvcursor_new(pinfo->pool, tree, tvb, offset);

    col_append_str(pinfo->cinfo, COL_INFO, first_fragment ? " commands:" : ",");
    len += offset;

    if (ptvcursor_current_offset(ptvc) < len) {
        for (;;) {
            int cmd = tvb_get_guint8(tvb, ptvcursor_current_offset(ptvc));
            ptvcursor_add_with_subtree(ptvc, hf_tibia_client_command, 1, convo->has.string_enc, ett_command);
            ptvcursor_advance(ptvc, 1);

            switch ((enum client_cmd)cmd) {
                case C_PLAYER_SPEECH: {
                    guint8 type = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));

                    ptvcursor_add(ptvc, hf_tibia_speech_type, 1, ENC_NA);
                    if (type == 0x7)
                        ptvcursor_add(ptvc, hf_tibia_channel_id, 2, ENC_LITTLE_ENDIAN);
                    ptvcursor_add(ptvc, hf_tibia_chat_msg, 2, ENC_LITTLE_ENDIAN|convo->has.string_enc);
                    }
                    break;
                case C_PONG:
                    break;
                default:
                    offset = ptvcursor_current_offset(ptvc);
                    call_data_dissector(tvb_new_subset_length(tvb, offset, len - offset), pinfo, ptvcursor_tree(ptvc));
                    ptvcursor_advance(ptvc, len - offset);
            }

            ptvcursor_pop_subtree(ptvc);

            col_append_fstr(pinfo->cinfo, COL_INFO, " %s (0x%x)",
                    val_to_str(cmd, from_client_packet_types, "Unknown"), cmd);

            if (ptvcursor_current_offset(ptvc) >= len)
                break;

            col_append_str(pinfo->cinfo, COL_INFO, ",");
        }
    }

    offset = ptvcursor_current_offset(ptvc);
    ptvcursor_free(ptvc);

    return offset;
}

static int
dissect_game_packet(struct tibia_convo *convo, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, gboolean is_xtea_encrypted, gboolean first_fragment)
{
    proto_item *ti = NULL;
    int len = tvb_captured_length_remaining(tvb, offset);

    if (show_acc_info) {
        if (convo->has.session_key) {
            if (convo->session_key) {
                ti = proto_tree_add_string(tree, hf_tibia_session_key_convo, tvb, offset, 0, (const char*)convo->session_key);
                proto_item_set_generated(ti);
            }
        } else {
            if (convo->acc) {
                ti = proto_tree_add_string(tree, hf_tibia_acc_name_convo, tvb, offset, 0, (const char*)convo->acc);
                proto_item_set_generated(ti);
            }

            if (convo->pass) {
                ti = proto_tree_add_string(tree, hf_tibia_acc_pass_convo, tvb, offset, 0, (const char*)convo->pass);
                proto_item_set_generated(ti);
            }
        }
    }

    if (show_char_name && convo->char_name) {
        ti = proto_tree_add_string(tree, hf_tibia_char_name_convo, tvb, offset, 0, (const char*)convo->char_name);
        proto_item_set_generated(ti);
    }

    if (is_xtea_encrypted) {
        if (pinfo->num > convo->xtea_framenum) {
            if (show_xtea_key && convo->has.xtea) {
                ti = proto_tree_add_bytes_with_length(tree, hf_tibia_xtea_key, tvb, 0, 0, (guint8*)convo->xtea_key, XTEA_KEY_LEN);
                proto_item_set_generated(ti);
            }

            int end = offset + len;

            if (len % 8 != 0)
                return -1;

            guint8 *decrypted_buffer = (guint8*)wmem_alloc(pinfo->pool, len);

            for (guint8 *dstblock = decrypted_buffer; offset < end; offset += 8) {
                decrypt_xtea_le_ecb(dstblock, tvb_get_ptr(tvb, offset, 8), convo->xtea_key, 32);
                dstblock += 8;
            }

            tvb = tvb_new_child_real_data(tvb, decrypted_buffer, len, len);
            add_new_data_source(pinfo, tvb, "Decrypted Game Data");

            offset = 0;
        } else {
            proto_tree_add_item(tree, hf_tibia_undecoded_xtea_data, tvb, offset, len, ENC_NA);
            return offset;
        }
    }
    if (convo->has.xtea) {
        len = tvb_get_letohs(tvb, offset);
        ti = proto_tree_add_item(tree, hf_tibia_payload_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        if (len > tvb_captured_length_remaining(tvb, offset)) {
            expert_add_info(pinfo, ti, &ei_xtea_len_toobig);
            return offset;
        }
    }


    if (pinfo->srcport == convo->servport && convo->loginserv_is_peer)
        return dissect_loginserv_packet(convo, tvb, offset, len, pinfo, tree, first_fragment);

    if (!dissect_game_commands) {
        call_data_dissector(tvb_new_subset_length(tvb, offset, len), pinfo, tree);
        return offset + len;
    }

    if (pinfo->srcport == convo->servport)
        return dissect_gameserv_packet(convo, tvb, offset, len, pinfo, tree, first_fragment);
    else
        return dissect_client_packet(convo, tvb, offset, len, pinfo, tree, first_fragment);
}

static int
dissect_tibia(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *fragment_num)
{
    tvbuff_t *tvb_decrypted = tvb;
    gboolean is_xtea_encrypted = FALSE;
    enum { TIBIA_GAMESERV, TIBIA_LOGINSERV } serv = TIBIA_GAMESERV;
    guint16 plen = tvb_get_letohs(tvb, 0) + 2;

    /* if announced length != real length it's not a tibia packet */
    if (tvb_reported_length_remaining(tvb, 0) != plen)
        return 0;

    struct tibia_convo *convo = tibia_get_convo(pinfo);

    int offset = 2;
    int a32len = tvb_reported_length_remaining(tvb, offset + 4);
    guint32 packet_cksum = tvb_get_letohl(tvb, offset);
    guint32 computed_cksum = GUINT32_TO_LE(adler32_bytes(tvb_get_ptr(tvb, offset + 4, a32len), a32len));
    convo->has.adler32 = packet_cksum == computed_cksum;
    if (convo->has.adler32)
        offset += 4;

    /* FIXME Tibia >=11.11 has a sequence number instead, this is yet unhandled */

    /* Is it a nonce? */
    if (tvb_get_letohs(tvb, offset) == plen - offset - 2
            && tvb_get_guint8(tvb, offset+2) == S_NONCE) {
        /* Don't do anything. We'll handle it as unencrypted game command later */
    } else {
        guint8 cmd;
        guint16 version;
        struct proto_traits version_has;
        cmd = tvb_get_guint8(tvb, offset);
        offset += 1;
        offset += 2; /* OS */
        version = tvb_get_letohs(tvb, offset);
        version_has = get_version_traits(version);

        switch(cmd) {
            case C_GET_CHARLIST:
                if ((700 <= version && version <= 760 && !convo->has.adler32 && 25 <= plen && plen <= 54)
                        || get_version_get_charlist_packet_size(&version_has) == plen) {
                    serv = TIBIA_LOGINSERV;
                    convo->loginserv_is_peer = TRUE;
                }
                break;
            case C_LOGIN_CHAR:
                /* The outcast client I tried, zero-pads the 760 login request.
                 * I don't think the Cipsoft client ever did this.
                 */
                if ((700 <= version && version <= 760 && !convo->has.adler32 && 25 <= plen && plen <= 54)
                        ||  get_version_char_login_packet_size(&version_has) == plen)
                    serv = TIBIA_LOGINSERV;
                break;
            default:
                is_xtea_encrypted = convo->has.xtea;
        }
    }


    offset = 0; /* With the version extracted, let's build the tree */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Tibia");
    if (GPOINTER_TO_UINT(fragment_num) == 1) {
        /* We don't want to repeat ourselves in the info column if there are fragments */
        if (serv == TIBIA_LOGINSERV)
            col_set_str(pinfo->cinfo, COL_INFO, "Login");
        else if (pinfo->srcport == convo->servport)
            col_set_str(pinfo->cinfo, COL_INFO, "Server");
        else
            col_set_str(pinfo->cinfo, COL_INFO, "Client");

    }

    proto_item *ti = proto_tree_add_item(tree, proto_tibia, tvb, 0, -1, ENC_NA);
    proto_tree *tibia_tree = proto_item_add_subtree(ti, ett_tibia);

    proto_tree_add_item(tibia_tree, hf_tibia_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    if (convo->has.adler32) {
        proto_tree_add_checksum(tibia_tree, tvb, offset, hf_tibia_adler32, hf_tibia_adler32_status, &ei_adler32_checksum_bad, pinfo, computed_cksum, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
        offset += 4;
    } else if (convo->has.compression) {
        offset += 4;
    }

    if (serv == TIBIA_GAMESERV)
        return dissect_game_packet(convo, tvb, offset, pinfo, tibia_tree, is_xtea_encrypted, GPOINTER_TO_UINT(fragment_num) == 1);

    proto_tree_add_item(tibia_tree, hf_tibia_client_command, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tibia_tree, hf_tibia_os, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    convo->proto_version = tvb_get_letohs(tvb, offset);
    convo->has = get_version_traits(convo->proto_version);
    proto_tree_add_item(tibia_tree, hf_tibia_proto_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    if (convo->has.client_version) {
        proto_tree_add_item(tibia_tree, hf_tibia_client_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    if (convo->loginserv_is_peer) {
        proto_tree *vertree;
        /* The first 4 bytes of the client's tibia.pic, tibia.dat and tibia.spr files */
        proto_item *subti = proto_tree_add_item(tibia_tree, hf_tibia_file_versions, tvb, offset, 12, ENC_NA);
        vertree = proto_item_add_subtree(subti, ett_file_versions);
        proto_tree_add_item(vertree, hf_tibia_file_version_spr, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(vertree, hf_tibia_file_version_dat, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(vertree, hf_tibia_file_version_pic, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    } else if (convo->has.game_content_revision) {
        proto_tree_add_item(tibia_tree, hf_tibia_content_revision, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    if (convo->has.game_preview) {
        proto_tree_add_item(tibia_tree, hf_tibia_game_preview_state, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    int rsa1_end = 0; /* End of first RSA block */
    if (convo->has.rsa) {
        gcry_sexp_t privkey;
        if (!(privkey = convo_get_privkey(convo))) {
            proto_tree_add_item(tibia_tree, hf_tibia_undecoded_rsa_data, tvb, offset, plen - offset, ENC_NA);
            return offset;
        }

        guint ciphertext_len = tvb_captured_length_remaining(tvb, offset);
        if (ciphertext_len < 128) {
            expert_add_info(pinfo, ti, &ei_rsa_ciphertext_too_short);
            return offset;
        }
        rsa1_end = offset + 128;
        guint8 *payload = (guint8*)tvb_memdup(pinfo->pool, tvb, offset, 128);

        char *err = NULL;
        size_t payload_len;
        if (!(payload_len = rsa_decrypt_inplace(128, payload, privkey, FALSE, &err))) {
            expert_add_info_format(pinfo, ti, &ei_rsa_decrypt_failed, "Decrypting RSA block failed: %s", err);
            g_free(err);
            return offset;
        }
        size_t leading_zeroes = 128 - payload_len;
        memmove(payload + leading_zeroes, payload, payload_len);
        memset(payload, 0x00, leading_zeroes);

        tvb_decrypted = tvb_new_child_real_data(tvb, payload, 128, 128);
        add_new_data_source(pinfo, tvb_decrypted, "Decrypted Login Data");

        if (tvb_get_guint8(tvb_decrypted, 0) != 0x00) {
            expert_add_info(pinfo, ti, &ei_rsa_plaintext_no_leading_zero);
            return offset;
        }

        offset = 1;

        tvb_memcpy(tvb_decrypted, convo->xtea_key, 1, XTEA_KEY_LEN);
        proto_tree_add_item(tibia_tree, hf_tibia_xtea_key, tvb_decrypted, 1, XTEA_KEY_LEN, ENC_NA);
        offset += XTEA_KEY_LEN;
        convo->xtea_framenum = pinfo->num;
    }

    if (!convo->loginserv_is_peer && convo->has.gmbyte) {
        proto_tree_add_item(tibia_tree, hf_tibia_loginflags_gm, tvb_decrypted, offset, 1, ENC_NA);
        offset += 1;
    }

    int len;
    if (convo->has.session_key && !convo->loginserv_is_peer) {
        /* OTServs I tested against use "$acc\n$pacc" as session key */
        if (convo->session_key) {
            proto_tree_add_item_ret_length(tibia_tree, hf_tibia_session_key, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc, &len);
        } else {
            proto_tree_add_item_ret_string_and_length(tibia_tree, hf_tibia_session_key, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc, wmem_file_scope(), &convo->session_key, &len);
        }
        offset += len;
    } else if (convo->has.acc_name) {
        if (convo->acc) {
            proto_tree_add_item_ret_length(tibia_tree, hf_tibia_acc_name, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc, &len);
        } else {
            proto_tree_add_item_ret_string_and_length(tibia_tree, hf_tibia_acc_name, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc, wmem_file_scope(), &convo->acc, &len);
        }
        offset += len;
    } else /* account number */ {
        char *accnum = wmem_strdup_printf(pinfo->pool, "%" PRIu32, tvb_get_letohl(tvb_decrypted, offset));
        proto_tree_add_string(tibia_tree, hf_tibia_acc_number, tvb_decrypted, offset, 4, accnum);
        if (!convo->acc)
            convo->acc = (guint8*)wmem_strdup(wmem_file_scope(), accnum);
        offset += 4;
    }

    if (!convo->loginserv_is_peer) {
        if (convo->char_name) {
            proto_tree_add_item_ret_length(tibia_tree, hf_tibia_char_name, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc, &len);
        } else {
            proto_tree_add_item_ret_string_and_length(tibia_tree, hf_tibia_char_name, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc, wmem_file_scope(), &convo->char_name, &len);
        }
        offset += len;
    }

    if (!convo->has.session_key || convo->loginserv_is_peer) {
        if (convo->pass) {
            proto_tree_add_item_ret_length(tibia_tree, hf_tibia_acc_pass, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc, &len);
        } else {
            proto_tree_add_item_ret_string_and_length(tibia_tree, hf_tibia_acc_pass, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN | convo->has.string_enc, wmem_file_scope(), &convo->pass, &len);
        }
        offset += len;
    }

    if (convo->loginserv_is_peer && convo->has.hwinfo) {
        proto_item *item;
        proto_tree *infotree, *subtree;

        item = proto_tree_add_item(tibia_tree, hf_tibia_client_info, tvb_decrypted, offset, 47, ENC_NA);
        infotree = proto_item_add_subtree(item, ett_client_info);

        /* Subtree { */
        guint locale_id;
        const guint8 *locale_name;

        item = proto_tree_add_item(infotree, hf_tibia_client_locale, tvb_decrypted, offset, 4, ENC_NA);
        subtree = proto_item_add_subtree(item, ett_locale);

        proto_tree_add_item_ret_uint(subtree, hf_tibia_client_locale_id, tvb_decrypted, offset, 1, ENC_NA, &locale_id);
        offset += 1;

        proto_tree_add_item_ret_string(subtree, hf_tibia_client_locale_name, tvb_decrypted, offset, 3, convo->has.string_enc|ENC_NA, pinfo->pool, &locale_name);
        offset += 3;
        proto_item_set_text(item, "Locale: %s (0x%X)", locale_name, locale_id);
        /* } */

        proto_tree_add_item(infotree, hf_tibia_client_ram, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(infotree, hf_tibia_unknown, tvb_decrypted, offset, 6, ENC_NA);
        offset += 6;

        /* Subtree { */
        guint clock1, clock2;
        const guint8 *cpu;

        item = proto_tree_add_item(infotree, hf_tibia_client_cpu, tvb_decrypted, offset, 15, ENC_NA);
        subtree = proto_item_add_subtree(item, ett_cpu);

        proto_tree_add_item_ret_string(subtree, hf_tibia_client_cpu_name, tvb_decrypted, offset, 9, convo->has.string_enc|ENC_NA, pinfo->pool, &cpu);
        offset += 9;

        proto_tree_add_item(subtree, hf_tibia_unknown, tvb_decrypted, offset, 2, ENC_NA);
        offset += 2;

        proto_tree_add_item_ret_uint(subtree, hf_tibia_client_clock, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN, &clock1);
        offset += 2;

        proto_tree_add_item_ret_uint(subtree, hf_tibia_client_clock2, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN, &clock2);
        offset += 2;

        proto_item_set_text(item, "CPU: %s (%uMhz/%uMhz)", cpu, clock2, clock1);
        /* } */


        proto_tree_add_item(infotree, hf_tibia_unknown, tvb_decrypted, offset, 4, ENC_NA);
        offset += 4;

        proto_tree_add_item(infotree, hf_tibia_client_gpu, tvb_decrypted, offset, 9, convo->has.string_enc|ENC_NA);
        offset += 9;

        proto_tree_add_item(infotree, hf_tibia_client_vram, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /* Subtree { */
        guint x, y, hz;

        item = proto_tree_add_item(infotree, hf_tibia_client_resolution, tvb_decrypted, offset, 5, ENC_NA);
        subtree = proto_item_add_subtree(item, ett_resolution);

        proto_tree_add_item_ret_uint(subtree, hf_tibia_client_resolution_x, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN, &x);
        offset += 2;
        proto_tree_add_item_ret_uint(subtree, hf_tibia_client_resolution_y, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN, &y);
        offset += 2;
        proto_tree_add_item_ret_uint(subtree, hf_tibia_client_resolution_hz, tvb_decrypted, offset, 1, ENC_LITTLE_ENDIAN, &hz);
        offset += 1;

        proto_item_set_text(item, "Resolution: %ux%u @ %uHz", x, y, hz);
        /* } */

    } else if (!convo->loginserv_is_peer && convo->has.nonce) {
        proto_tree_add_item(tibia_tree, hf_tibia_nonce, tvb_decrypted, offset, 5, ENC_NA);
        offset += 5;
    }

    if (convo->has.rsa) {
        /* Undecoded hardware info maybe */
        call_data_dissector(tvb_new_subset_length(tvb_decrypted, offset, 128 - offset), pinfo, tibia_tree);
    }

    if (rsa1_end)
        offset = rsa1_end;

    if (offset != plen) {
        /* TODO Extended GPU info and authentication token (RSA-encrypted again) */
        call_data_dissector(tvb_new_subset_length(tvb, offset, plen - offset), pinfo, tibia_tree);
    }
    return plen;
}

static const value_string operating_systems[] = {
    { 2, "Windows" },
    { 0, NULL }
};

static const value_string speech_types[] = {
    { 0x1, "Say" },
    { 0x2, "Whisper" },
    { 0x3, "Yell" },
    { 0x7, "Public Channel" },
    { 0, NULL }
};

#if defined(HAVE_LIBGNUTLS)
static guint
rsakey_hash(gconstpointer _rsakey)
{
    const struct rsakey *rsakey = (const struct rsakey *)_rsakey;
    return add_address_to_hash(rsakey->port, &rsakey->addr);
}

static gboolean
rsakey_equal(gconstpointer _a, gconstpointer _b)
{
    const struct rsakey *a = (const struct rsakey *)_a,
                        *b = (const struct rsakey *)_b;
    return a->port == b->port && addresses_equal(&a->addr, &b->addr);
}
static void
rsakey_free(void *_rsakey)
{
    struct rsakey *rsakey = (struct rsakey *)_rsakey;

    /* gcry_sexp_release(rsakey->privkey); */ /* private key may be shared. */
    free_address_wmem(NULL, &rsakey->addr);
    g_free(rsakey);
}

static void
rsa_parse_uat(void)
{
    g_hash_table_remove_all(rsakeys);

    for (guint i = 0; i < nrsakeys; i++) {
        struct rsakeys_assoc *uats = &rsakeylist_uats[i];

        /* try to load keys file first */
        FILE *fp = ws_fopen(uats->keyfile, "rb");
        if (!fp) {
            report_open_failure(uats->keyfile, errno, FALSE);
            return;
        }

        gnutls_x509_privkey_t priv_key;
        char *err = NULL;
        if (*uats->password) {
            priv_key = rsa_load_pkcs12(fp, uats->password, &err);
            if (err) {
                report_failure("%s\n", err);
                g_free(err);
            }
        } else {
            priv_key = rsa_load_pem_key(fp, &err);
            if (err) {
                report_failure("%s\n", err);
                g_free(err);
            }
        }
        fclose(fp);

        if (!priv_key) {
            report_failure("Can't load private key from %s\n", uats->keyfile);
            return;
        }

        struct rsakey *entry;
        guint32 ipaddr;
        gcry_sexp_t private_key = rsa_privkey_to_sexp(priv_key, &err);
        if (!private_key) {
            g_free(err);
            report_failure("Can't extract private key parameters for %s", uats->keyfile);
            goto end;
        }

        entry = g_new(struct rsakey, 1);
        ws_strtou16(uats->port, NULL, &entry->port);
        ipaddr = ipv4tonl(uats->ipaddr);
        alloc_address_wmem(NULL, &entry->addr, AT_IPv4, sizeof ipaddr, &ipaddr);
        entry->privkey = private_key;


        g_hash_table_insert(rsakeys, entry, entry->privkey);

end:
        gnutls_x509_privkey_deinit(priv_key);
    }
}

static void
rsakeys_free_cb(void *r)
{
    struct rsakeys_assoc *h = (struct rsakeys_assoc *)r;

    g_free(h->ipaddr);
    g_free(h->port);
    g_free(h->keyfile);
    g_free(h->password);
}

static void*
rsakeys_copy_cb(void *dst_, const void *src_, size_t len _U_)
{
    const struct rsakeys_assoc *src = (const struct rsakeys_assoc *)src_;
    struct rsakeys_assoc       *dst = (struct rsakeys_assoc *)dst_;

    dst->ipaddr    = g_strdup(src->ipaddr);
    dst->port      = g_strdup(src->port);
    dst->keyfile   = g_strdup(src->keyfile);
    dst->password  = g_strdup(src->password);

    return dst;
}

static gboolean
rsakeys_uat_fld_ip_chk_cb(void* r _U_, const char* ipaddr, guint len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    /* There are no Tibia IPv6 servers, although Tibia 11.0+'s Protocol in theory supports it */
    if (ipaddr && g_hostname_is_ip_address(ipaddr) && strchr(ipaddr, '.')) {
        *err = NULL;
        return TRUE;
    }

    *err = ws_strdup_printf("No IPv4 address given.");
    return FALSE;
}

static gboolean
rsakeys_uat_fld_port_chk_cb(void *_record _U_, const char *str, guint len _U_, const void *chk_data _U_, const void *fld_data _U_, char **err)
{
    guint16 val;
    if (!ws_strtou16(str, NULL, &val)) {
        *err = g_strdup("Invalid argument. Expected a decimal between [0-65535]");
        return FALSE;
    }
    *err = NULL;
    return TRUE;
}

static gboolean
rsakeys_uat_fld_fileopen_chk_cb(void* r _U_, const char* p, guint len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    if (p && *p) {
        ws_statb64 st;
        if (ws_stat64(p, &st) != 0) {
            *err = ws_strdup_printf("File '%s' does not exist or access is denied.", p);
            return FALSE;
        }
    } else {
        *err = g_strdup("No filename given.");
        return FALSE;
    }

    *err = NULL;
    return TRUE;
}

static gboolean
rsakeys_uat_fld_password_chk_cb(void *r, const char *p, guint len _U_, const void *u1 _U_, const void *u2 _U_, char **err)
{
    if (p && *p) {
        struct rsakeys_assoc *f = (struct rsakeys_assoc *)r;
        FILE *fp = ws_fopen(f->keyfile, "rb");
        if (fp) {
            char *msg = NULL;
            gnutls_x509_privkey_t priv_key = rsa_load_pkcs12(fp, p, &msg);
            if (!priv_key) {
                fclose(fp);
                *err = ws_strdup_printf("Could not load PKCS#12 key file: %s", msg);
                g_free(msg);
                return FALSE;
            }
            g_free(msg);
            gnutls_x509_privkey_deinit(priv_key);
            fclose(fp);
        } else {
            *err = ws_strdup_printf("Leave this field blank if the keyfile is not PKCS#12.");
            return FALSE;
        }
    }

    *err = NULL;
    return TRUE;
}
#endif

static void
xtea_parse_uat(void)
{
    g_hash_table_remove_all(xteakeys);

    for (guint i = 0; i < nxteakeys; i++) {
        guint key_idx = 0;
        guint8 *key = (guint8*)g_malloc(XTEA_KEY_LEN);

        for (const char *str = xteakeylist_uats[i].key; str[0] && str[1] && key_idx < XTEA_KEY_LEN; str++) {
            if (g_ascii_ispunct(*str))
                continue;

            key[key_idx++] = (g_ascii_xdigit_value(str[0]) << 4)
                           +  g_ascii_xdigit_value(str[1]);
            str++;
        }

        g_hash_table_insert(xteakeys, GUINT_TO_POINTER(xteakeylist_uats[i].framenum), key);
    }
}

static void
xteakeys_free_cb(void *r)
{
    struct xteakeys_assoc *h = (struct xteakeys_assoc *)r;

    g_free(h->key);
}

static void*
xteakeys_copy_cb(void *dst_, const void *src_, size_t len _U_)
{
    const struct xteakeys_assoc *src = (const struct xteakeys_assoc *)src_;
    struct xteakeys_assoc       *dst = (struct xteakeys_assoc *)dst_;

    dst->framenum = src->framenum;
    dst->key      = g_strdup(src->key);

    return dst;
}

static gboolean
xteakeys_uat_fld_key_chk_cb(void *r _U_, const char *key, guint len, const void *u1 _U_, const void *u2 _U_, char **err)
{
    if (len >= XTEA_KEY_LEN*2) {
        gsize i = 0;

        do {
            if (g_ascii_ispunct(*key))
                continue;
            if (!g_ascii_isxdigit(*key))
                break;
            i++;
        } while (*++key);

        if (*key == '\0' && i == 2*XTEA_KEY_LEN) {
            *err = NULL;
            return TRUE;
        }
    }

    *err = ws_strdup_printf("XTEA keys are 32 character long hex strings.");
    return FALSE;
}


void
proto_register_tibia(void)
{
    static hf_register_info hf[] = {
        { &hf_tibia_len,
            { "Packet length", "tibia.len",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_adler32,
            { "Adler32 checksum", "tibia.checksum",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_adler32_status,
            { "Checksum status", "tibia.checksum.status",
                FT_UINT8, BASE_NONE,
                VALS(proto_checksum_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_nonce,
            { "Game server nonce", "tibia.nonce",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_os,
            { "Operating system", "tibia.os",
                FT_UINT16, BASE_HEX,
                VALS(operating_systems), 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_proto_version,
            { "Protocol version", "tibia.version",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_version,
            { "Client version", "tibia.client_version",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_file_versions,
            { "File versions", "tibia.version.files",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_file_version_spr,
            { "Tibia.spr version", "tibia.version.spr",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_file_version_dat,
            { "Tibia.dat version", "tibia.version.dat",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_file_version_pic,
            { "Tibia.pic version", "tibia.version.pic",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_content_revision,
            { "Content revision", "tibia.version.content",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_undecoded_rsa_data,
            { "RSA-encrypted login data", "tibia.rsa_data",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_undecoded_xtea_data,
            { "XTEA-encrypted game data", "tibia.xtea_data",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_unknown,
            { "Unknown Data", "tibia.unknown",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_xtea_key,
            { "Symmetric key (XTEA)", "tibia.xtea",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_loginflags_gm,
            { "Gamemaster", "tibia.login.flags.gm",
                FT_BOOLEAN, 8,
                NULL, 0x1,
                NULL, HFILL }
        },
        { &hf_tibia_game_preview_state,
            { "Game Preview State", "tibia.login.flags.preview",
                FT_BOOLEAN, 8,
                NULL, 0x1,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond,
          {"Character Condition", "tibia.cond",
                FT_UINT32, BASE_HEX,
                NULL, 0,
                NULL, HFILL}
        },
        { &hf_tibia_char_cond_poisoned,
            { "Poisoned", "tibia.cond.poisoned",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_POISONED,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond_burning,
            { "Burning", "tibia.cond.burning",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_BURNING,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond_electrocuted,
            { "Electrocuted", "tibia.cond.electrocuted",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_ELECTROCUTED,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond_drunk,
            { "Drunk", "tibia.cond.drunk",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_DRUNK,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond_manashield, /* Utamo Vita */
            { "Mana Shield", "tibia.cond.manashield",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_MANASHIELD,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond_paralyzed,
            { "Paralyzed", "tibia.cond.paralyzed",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_PARALYZED,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond_haste,
            { "Haste", "tibia.cond.haste",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_HASTE,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond_battle,
            { "Battle lock", "tibia.cond.battle",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_BATTLE,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond_drowning,
            { "Drowning", "tibia.cond.drowning",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_DROWNING,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond_freezing,
            { "Freezing", "tibia.cond.freezing",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_FREEZING,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond_dazzled,
            { "Dazzled", "tibia.cond.dazzled",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_DAZZLED,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond_cursed,
            { "Cursed", "tibia.cond.cursed",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_CURSED,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond_buff, /* e.g. after casting Utura */
            { "Buff", "tibia.cond.buff",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_BUFF,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond_pzblock, /* Blocked from entering PZ */
            { "Protection Zone Block", "tibia.cond.pzblock",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_PZBLOCK,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond_pz,
            { "Protection Zone", "tibia.cond.pz",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_PZ,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond_bleeding,
            { "Bleeding", "tibia.cond.bleeding",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_BLEEDING,
                NULL, HFILL }
        },
        { &hf_tibia_char_cond_hungry,
            { "Hungry", "tibia.cond.hungry",
                FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), COND_HUNGRY,
                NULL, HFILL }
        },
        { &hf_tibia_acc_name,
            { "Account", "tibia.acc",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_acc_number,
            { "Account", "tibia.acc",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_session_key,
            { "Session key", "tibia.session_key",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_char_name,
            { "Character name", "tibia.char",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_acc_pass,
            { "Password", "tibia.pass",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_char_name_convo,
            { "Character name", "tibia.char",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_acc_name_convo,
            { "Account", "tibia.acc",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_acc_pass_convo,
            { "Password", "tibia.pass",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_session_key_convo,
            { "Session key", "tibia.session_key",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_info,
            { "Client information", "tibia.client.info",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_locale,
            { "Locale", "tibia.client.locale",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_locale_id,
            { "Locale ID", "tibia.client.locale.id",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_locale_name,
            { "Locale", "tibia.client.locale.name",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_ram,
            { "Total RAM", "tibia.client.ram",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_cpu,
            { "CPU", "tibia.client.cpu",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_cpu_name,
            { "CPU", "tibia.client.cpu.name",
                FT_STRINGZ, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_clock,
            { "CPU clock", "tibia.client.cpu.clock",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_clock2,
            { "CPU clock2", "tibia.client.cpu.clock2",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_gpu,
            { "GPU", "tibia.client.gpu",
                FT_STRINGZ, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_vram,
            { "Video RAM", "tibia.client.vram",
                FT_UINT8, BASE_DEC|BASE_UNIT_STRING,
                &mb_unit, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_resolution,
            { "Screen resolution", "tibia.client.resolution",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_resolution_x,
            { "Horizontal resolution", "tibia.client.resolution.x",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_resolution_y,
            { "Vertical resolution", "tibia.client.resolution.y",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_resolution_hz,
            { "Refresh rate", "tibia.client.resolution.hz",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_payload_len,
            { "Payload length", "tibia.payload.len",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_loginserv_command,
            { "Command", "tibia.cmd",
                FT_UINT8, BASE_HEX,
                VALS(from_loginserv_packet_types), 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_gameserv_command,
            { "Command", "tibia.cmd",
                FT_UINT8, BASE_HEX|BASE_EXT_STRING,
                &from_gameserv_packet_types_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_client_command,
            { "Command", "tibia.cmd",
                FT_UINT8, BASE_HEX|BASE_EXT_STRING,
                &from_client_packet_types_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_motd,
            { "Message of the day", "tibia.motd",
                FT_UINT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_dlg_error,
            { "Error message", "tibia.login.err",
                FT_UINT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_dlg_info,
            { "Info message", "tibia.login.info",
                FT_UINT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_charlist,
            { "Character list", "tibia.charlist",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_charlist_length,
            { "Character count", "tibia.charlist.count",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_charlist_entry_name,
            { "Character name", "tibia.charlist.name",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_charlist_entry_world,
            { "World", "tibia.charlist.world",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_charlist_entry_ip,
            { "IP", "tibia.charlist.ip",
                FT_IPv4, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_charlist_entry_port,
            { "Port", "tibia.charlist.port",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_worldlist,
            { "World list", "tibia.worldlist",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_worldlist_entry_name,
            { "World", "tibia.worldlist.name",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_worldlist_length,
            { "World count", "tibia.worldlist.count",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_worldlist_entry_id,
            { "World ID", "tibia.worldlist.id",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_worldlist_entry_ip,
            { "IP", "tibia.worldlist.ip",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_worldlist_entry_port,
            { "Port", "tibia.worldlist.port",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_worldlist_entry_preview,
            { "Preview State", "tibia.worldlist.preview",
                FT_BOOLEAN, 8,
                NULL, 0x1,
                NULL, HFILL }
        },
        { &hf_tibia_pacc_days,
            { "Premium days left", "tibia.pacc",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_channel_id,
            { "Channel id", "tibia.channel.id",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_channel_name,
            { "Channel name", "tibia.channel",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_speech_type,
            { "Type", "tibia.speechtype",
                FT_UINT8, BASE_HEX,
                VALS(speech_types), 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_chat_msg,
            { "Message", "tibia.msg",
                FT_UINT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_coords_x,
            { "X-Coordinate", "tibia.coord.x",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_coords_y,
            { "Y-Coordinate", "tibia.coords.y",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_coords_z,
            { "Z-Coordinate", "tibia.coords.z",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_coords,
            { "Coordinates", "tibia.coords",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_stackpos,
            { "Stack position", "tibia.coords.stackpos",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
#if 0
        { &hf_tibia_item,
            { "Item ID", "tibia.item",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
#endif
        { &hf_tibia_container,
            { "Container index", "tibia.container",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_container_icon,
            { "Container icon", "tibia.container.icon",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_container_slot,
            { "Container slot", "tibia.container.slot",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_container_slots,
            { "Container slots", "tibia.container.slots",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_inventory,
            { "Inventory slot", "tibia.inventory",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_vip,
            { "VIP GUID", "tibia.vip",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_vip_online,
            { "Online", "tibia.vip.online",
                FT_BOOLEAN, 8,
                NULL, 0x1,
                NULL, HFILL }
        },
        { &hf_tibia_player,
            { "Player name", "tibia.player",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_creature,
            { "Creature", "tibia.creature",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_creature_health,
            { "Creature", "tibia.creature.health",
                FT_UINT8, BASE_DEC|BASE_UNIT_STRING,
                &units_percent, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_window,
            { "Window", "tibia.window",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_window_icon,
            { "Window Icon", "tibia.window.icon",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_window_textlen,
            { "Window Text Length", "tibia.window.text.len",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_window_text,
            { "Window Text", "tibia.window.text",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_squarecolor,
            { "Square Color", "tibia.creature.square",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_light_color,
            { "Light Color", "tibia.light.color",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_light_level,
            { "Light Level", "tibia.light.level",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_magic_effect_id,
            { "Magic Effect", "tibia.magic_effect",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_animated_text_color,
            { "Text Color", "tibia.animated_text.color",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_animated_text,
            { "Text", "tibia.animated_text",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_textmsg_class,
            { "Text Message Class", "tibia.textmsg.class",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_textmsg,
            { "Text", "tibia.textmsg",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_projectile,
            { "Projectile", "tibia.projectile",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_tibia_walk_dir,
            { "Walk Direction", "tibia.walk_dir",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_tibia,
        &ett_command,
        &ett_file_versions,
        &ett_client_info,
        &ett_locale,
        &ett_cpu,
        &ett_resolution,
        &ett_charlist,
        &ett_char,
        &ett_worldlist,
        &ett_world,
        &ett_coords,
        &ett_char_cond,
    };

    static ei_register_info ei[] = {
        { &ei_xtea_len_toobig,
            { "tibia.error.xtea.length.toobig", PI_DECRYPTION, PI_ERROR,
                "XTEA-encrypted length exceeds packet", EXPFILL }
        },
        { &ei_adler32_checksum_bad, { "tibia.error.checksum_bad", PI_CHECKSUM, PI_ERROR,
                "Bad checksum", EXPFILL }
        },
        { &ei_rsa_plaintext_no_leading_zero,
            { "tibia.error.rsa", PI_DECRYPTION, PI_ERROR,
                "First byte after RSA decryption must be zero", EXPFILL }
        },
        { &ei_rsa_ciphertext_too_short,
            { "tibia.error.rsa.length.tooshort", PI_DECRYPTION, PI_ERROR,
                "RSA-encrypted data is at least 128 byte long", EXPFILL }
        },
        { &ei_rsa_decrypt_failed,
            { "tibia.error.rsa.failed", PI_DECRYPTION, PI_ERROR,
                "Decrypting RSA block failed", EXPFILL }
        },
    };

    proto_tibia = proto_register_protocol (
            "Tibia Protocol", /* name */
            "Tibia",          /* short name */
            "tibia"           /* abbrev */
            );
    proto_register_field_array(proto_tibia, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert_tibia = expert_register_protocol(proto_tibia);
    expert_register_field_array (expert_tibia, ei, array_length (ei));

    module_t *tibia_module = prefs_register_protocol(proto_tibia, NULL);

    prefs_register_bool_preference(tibia_module, "try_otserv_key", "Try OTServ's RSA key",
        "Try the default RSA key in use by nearly all Open Tibia servers", &try_otserv_key);

    prefs_register_bool_preference(tibia_module, "show_char_name", "Show character name for each packet",
        "Shows active character for every packet", &show_char_name);
    prefs_register_bool_preference(tibia_module, "show_acc_info", "Show account info for each packet",
        "Shows account name/password or session key for every packet", &show_acc_info);
    prefs_register_bool_preference(tibia_module, "show_xtea_key", "Show symmetric key used for each packet",
        "Shows which XTEA key was applied for a packet", &show_xtea_key);
    prefs_register_bool_preference(tibia_module, "dissect_game_commands", "Attempt dissection of game packet commands",
        "Only decrypt packets and dissect login packets. Pass game commands to the data dissector", &dissect_game_commands);
    prefs_register_bool_preference(tibia_module, "reassemble_tcp_segments",
                                   "Reassemble Tibia packets spanning multiple TCP segments",
                                   "Whether the Tibia dissector should reassemble packets spanning multiple TCP segments."
                                   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &reassemble_tcp_segments);


#ifdef HAVE_LIBGNUTLS
    static uat_field_t rsakeylist_uats_flds[] = {
        UAT_FLD_CSTRING_OTHER(rsakeylist_uats, ipaddr, "IP address", rsakeys_uat_fld_ip_chk_cb, "IPv4 address"),
        UAT_FLD_CSTRING_OTHER(rsakeylist_uats, port, "Port", rsakeys_uat_fld_port_chk_cb, "Port Number"),
        UAT_FLD_FILENAME_OTHER(rsakeylist_uats, keyfile, "Key File", rsakeys_uat_fld_fileopen_chk_cb, "Private keyfile."),
        UAT_FLD_CSTRING_OTHER(rsakeylist_uats, password,"Password", rsakeys_uat_fld_password_chk_cb, "Password (for keyfile)"),
        UAT_END_FIELDS
    };

    rsakeys_uat = uat_new("RSA Keys",
            sizeof(struct rsakeys_assoc),
            "tibia_rsa_keys",        /* filename */
            TRUE,                    /* from_profile */
            &rsakeylist_uats,        /* data_ptr */
            &nrsakeys,               /* numitems_ptr */
            UAT_AFFECTS_DISSECTION,
            NULL,
            rsakeys_copy_cb,
            NULL,
            rsakeys_free_cb,
            rsa_parse_uat,
            NULL,
            rsakeylist_uats_flds);
    prefs_register_uat_preference(tibia_module, "rsakey_table",
            "RSA keys list",
            "A table of RSA keys for decrypting protocols newer than 7.61",
            rsakeys_uat
    );

    rsakeys = g_hash_table_new_full(rsakey_hash, rsakey_equal, rsakey_free, NULL);
#endif

    static uat_field_t xteakeylist_uats_flds[] = {
        UAT_FLD_DEC(xteakeylist_uats, framenum, "Frame Number", "XTEA key"),
        UAT_FLD_CSTRING_OTHER(xteakeylist_uats, key, "XTEA Key", xteakeys_uat_fld_key_chk_cb, "Symmetric (XTEA) key"),
        UAT_END_FIELDS
    };

    xteakeys_uat = uat_new("XTEA Keys",
            sizeof(struct xteakeys_assoc),
            "tibia_xtea_keys",       /* filename */
            TRUE,                    /* from_profile */
            &xteakeylist_uats,       /* data_ptr */
            &nxteakeys,              /* numitems_ptr */
            UAT_AFFECTS_DISSECTION,
            NULL,
            xteakeys_copy_cb,
            NULL,
            xteakeys_free_cb,
            xtea_parse_uat,
            NULL,
            xteakeylist_uats_flds);
    prefs_register_uat_preference(tibia_module, "xteakey_table",
            "XTEA keys list",
            "A table of XTEA keys for decrypting protocols newer than 7.61",
            xteakeys_uat
    );

    xteakeys = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

    /* TODO best way to store this in source? */
    const char sexp[] =
        "(private-key (rsa"
        "(n #9b646903b45b07ac956568d87353bd7165139dd7940703b03e6dd079399661b4a837aa60561d7ccb9452fa0080594909882ab5bca58a1a1b35f8b1059b72b1212611c6152ad3dbb3cfbee7adc142a75d3d75971509c321c5c24a5bd51fd460f01b4e15beb0de1930528a5d3f15c1e3cbf5c401d6777e10acaab33dbe8d5b7ff5#)"
        "(e #010001#)"
        "(d #428bd3b5346daf71a761106f71a43102f8c857d6549c54660bb6378b52b0261399de8ce648bac410e2ea4e0a1ced1fac2756331220ca6db7ad7b5d440b7828865856e7aa6d8f45837feee9b4a3a0aa21322a1e2ab75b1825e786cf81a28a8a09a1e28519db64ff9baf311e850c2bfa1fb7b08a056cc337f7df443761aefe8d81#)"
        "(p #91b37307abe12c05a1b78754746cda444177a784b035cbb96c945affdc022d21da4bd25a4eae259638153e9d73c97c89092096a459e5d16bcadd07fa9d504885#)"
        "(q #0111071b206bafb9c7a2287d7c8d17a42e32abee88dfe9520692b5439d9675817ff4f8c94a4abcd4b5f88e220f3a8658e39247a46c6983d85618fd891001a0acb1#)"
        "(u #6b21cd5e373fe462a22061b44a41fd01738a3892e0bd8728dbb5b5d86e7675235a469fea3266412fe9a659f486144c1e593d56eb3f6cfc7b2edb83ba8e95403a#)"
        "))";

    gcry_error_t err = gcry_sexp_new(&otserv_key, sexp, 0, 1);
    if (err)
        report_failure("Loading OTServ RSA key failed: %s/%s\n", gcry_strerror(err), gcry_strsource(err));
}

static guint
get_dissect_tibia_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return tvb_get_letohs(tvb, offset) + 2;
}

static int
dissect_tibia_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    static guint32 packet_num, fragment_num;

    if (!packet_num) packet_num = pinfo->num;
    if (packet_num != pinfo->num) {
        fragment_num = 0;
        packet_num = pinfo->num;
    }

    fragment_num++;


    tcp_dissect_pdus(tvb, pinfo, tree, reassemble_tcp_segments, 2,
               get_dissect_tibia_len, dissect_tibia, GUINT_TO_POINTER(fragment_num));
    return tvb_reported_length(tvb);
}

void
proto_reg_handoff_tibia(void)
{
    dissector_handle_t tibia_handle = create_dissector_handle(dissect_tibia_tcp, proto_tibia);

    dissector_add_uint_range_with_preference("tcp.port", TIBIA_DEFAULT_TCP_PORT_RANGE, tibia_handle);
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
