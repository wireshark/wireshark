/* packet-woww.c
 * Routines for World of Warcraft World dissection
 * Copyright 2021, Gtker <woww@gtker.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The protocol is used for World of Warcraft World packets.
 * These are seen when a client is connected to a world server and plays the game.
 * The WOW protocol (no extra W) packets are Login packets, and they are handled in
 * the packet-wow.c file.
 *
 * More info on world packets and login packets:
 * https://wowdev.wiki/World_Packet
 * https://wowdev.wiki/Login_Packet
 *
 * Currently this dissector is valid for 1.12.x, the most popular Vanilla version.
 *
 * All World packets contain a header with:
 * * A 16 bit big endian size field.
 * * A (32 or 16 bit) little endian opcode field.
 * Server to client opcodes are 16 bits while client to server opcodes are 32 bits.
 *
 * All world packets other than SMSG_AUTH_CHALLENGE and CMSG_AUTH_SESSION have
 * "encrypted" headers based on a 40 byte session key, however it is relatively
 * easily broken.
 *
 * SMSG packets are Server messages (from server) and CMSG packets are Client messages
 * (from client). MSG packets can be either.
 *
 * # SESSION KEY DEDUCTION:
 *
 * The header is encrypted through the formula `E = (x ^ S) + L` where:
 * * E is the encrypted value.
 * * x is the plain unencrypted value.
 * * S is a byte of the session key.
 * * L is the last encrypted value.
 *
 * The header is decrypted through the formula `x = (E - L) ^ S` with the same values.
 *
 * Notably, this allows us to deduce the session key value S if we know what the
 * unencrypted value x is. The L value is simply the last encrypted value sent.
 *
 * Fortunately, the client sends opcodes as 32bit little endian values, but there are no
 * opcodes that use the two most significant bytes meaning we can always count on them being 0.
 * This means we can now deduce the session key value S through `S = 0 ^ (E - L)` (where 0 is x).
 * Because of this we can deduce 2 bytes of the session key every client packet.
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/wmem_scopes.h>

void proto_reg_handoff_woww(void);
void proto_register_woww(void);

static int proto_woww = -1;

/* Fields that all packets have */
static int hf_woww_size = -1;
static int hf_woww_opcode = -1;

/* SMSG_AUTH_CHALLENGE */
static int hf_woww_challenge_seed = -1;

/* CMSG_AUTH_SESSION */
static int hf_woww_build = -1;
static int hf_woww_server_id = -1;
static int hf_woww_account_name = -1;
static int hf_woww_client_proof = -1;
static int hf_woww_decompressed_addon_size = -1;
static int hf_woww_addon_info = -1;

/* SMSG_CHAR_ENUM */
static int hf_woww_amount_of_characters = -1;
static int hf_woww_character_guid = -1;
static int hf_woww_character_skin = -1;
static int hf_woww_character_face = -1;
static int hf_woww_character_hairstyle = -1;
static int hf_woww_character_haircolor = -1;
static int hf_woww_character_facialhair = -1;
static int hf_woww_character_zone = -1;
static int hf_woww_character_map = -1;
static int hf_woww_character_guild_id = -1;
static int hf_woww_character_flags = -1;
static int hf_woww_character_first_login = -1;
static int hf_woww_character_pet_display_id = -1;
static int hf_woww_character_pet_level = -1;
static int hf_woww_character_pet_family = -1;
static int hf_woww_character_equipment_display_id = -1;
static int hf_woww_character_equipment_inventory_type = -1;

/* SMSG_TUTORIAL_FLAGS */
static int hf_woww_tutorial_flag = -1;

/* CMSG_PING */
static int hf_woww_latency = -1;
/* CMSG_PING and SMSG_PONG */
static int hf_woww_sequence_id = -1;

/* Multiple */
static int hf_woww_character_level = -1;
static int hf_woww_character_position_x = -1;
static int hf_woww_character_position_y = -1;
static int hf_woww_character_position_z = -1;
static int hf_woww_character_orientation = -1;
static int hf_woww_result = -1;
static int hf_woww_character_name = -1;
static int hf_woww_realm_name = -1;
static int hf_woww_character_race = -1;
static int hf_woww_character_class = -1;
static int hf_woww_character_gender = -1;

#define WOWW_TCP_PORT 8085

#define WOWW_CLIENT_TO_SERVER pinfo->destport == WOWW_TCP_PORT
#define WOWW_SERVER_TO_CLIENT pinfo->srcport  == WOWW_TCP_PORT

// Allocate 8 because tree wants 32 bit aligned data
#define WOWW_HEADER_ARRAY_ALLOC_SIZE 8

// The session key is the result of two SHA-1 hashes appended, so it is
// _always_ 40 bytes.
#define WOWW_SESSION_KEY_LENGTH 40

static gint ett_woww = -1;
static gint ett_message = -1;
static gint ett_character = -1;

// Packets that do not have at least a u16 size field and a u16 opcode field are not valid.
#define WOWW_MIN_LENGTH 4

// A participant can either be the server or a client.
typedef struct WowwParticipant {
    // The previous encrypted value sent. Persists through headers.
    guint8 last_encrypted_value;
    // Index into the session key. Must always be in [0; WOWW_SESSION_KEY_LENGTH - 1].
    // Named idx because there's a check for 'index'
    guint8 idx;
    // The first header is unencrypted. Tracks if that header has been encountered.
    gboolean unencrypted_packet_encountered;
    // If a server message is unable to be fully decrypted we stop decrypting any
    // any more, since it's impossible to know if the PDU contains multiple messages
    // and thus how many times the session key index should be incremented.
    guint64 stopped_at;
} WowwParticipant_t;

typedef struct WowwConversation {
    // Secret session key known to the client and host.
    guint8 session_key[WOWW_SESSION_KEY_LENGTH];
    // Which values of the session key have been deduced.
    bool known_indices[WOWW_SESSION_KEY_LENGTH];
    // Cache headers that have already been decrypted to save time
    // as well as reduce headaches from out of order packets.
    wmem_map_t* decrypted_headers;
    // Packets that are not fully decryptable when received will need
    // to be decrypted later.
    wmem_map_t* headers_need_decryption;
    // The client and server will have different indices/last values
    // because they send different amounts of packets and with different
    // header lengths.
    WowwParticipant_t client;
    WowwParticipant_t server;
} WowwConversation_t;

typedef struct {
    // Index into the session key, named idx because there's a check for 'index'
    guint8 idx;
    guint8 last_encrypted_value;
} WowwPreviousValues_t;

typedef struct {
    guint8 size[2];
    guint8 opcode[];
} WowwDecryptedHeader_t;

typedef enum {
    HUMAN = 1,
    ORC = 2,
    DWARF = 3,
    NIGHT_ELF = 4,
    UNDEAD = 5,
    TAUREN = 6,
    GNOME = 7,
    TROLL = 8,
    GOBLIN = 9,
} races;

static const value_string races_strings[] = {
    { HUMAN, "Human" },
    { ORC, "Orc" },
    { DWARF, "Dwarf" },
    { NIGHT_ELF, "Night Elf" },
    { UNDEAD, "Undead" },
    { TAUREN, "Tauren" },
    { GNOME, "Gnome" },
    { TROLL, "Troll" },
    { GOBLIN, "Goblin" },
    { 0, NULL }
};

typedef enum {
    WARRIOR = 1,
    PALADIN = 2,
    HUNTER = 3,
    ROGUE = 4,
    PRIEST = 5,
    SHAMAN = 6,
    MAGE = 7,
    WARLOCK = 8,
    DRUID = 9,
} classes;

static const value_string classes_strings[] = {
        { WARRIOR, "Warrior" },
        { PALADIN, "Paladin" },
        { HUNTER, "Hunter" },
        { ROGUE, "Rogue" },
        { PRIEST, "Priest" },
        { SHAMAN, "Shaman" },
        { MAGE, "Mage" },
        { WARLOCK, "Warlock" },
        { DRUID, "Druid" },
        { 0, NULL }
};

typedef enum {
    MALE = 0,
    FEMALE = 1,
} genders;

static const value_string genders_strings[] = {
        { MALE, "Male" },
        { FEMALE, "Female" },
        { 0, NULL }
};

typedef enum {
    RESPONSE_SUCCESS = 0x00,
    RESPONSE_FAILURE = 0x01,
    RESPONSE_CANCELLED = 0x02,
    RESPONSE_DISCONNECTED = 0x03,
    RESPONSE_FAILED_TO_CONNECT = 0x04,
    RESPONSE_CONNECTED = 0x05,
    RESPONSE_VERSION_MISMATCH = 0x06,
    CSTATUS_CONNECTING = 0x07,
    CSTATUS_NEGOTIATING_SECURITY = 0x08,
    CSTATUS_NEGOTIATION_COMPLETE = 0x09,
    CSTATUS_NEGOTIATION_FAILED = 0x0A,
    CSTATUS_AUTHENTICATING = 0x0B,
    AUTH_OK = 0x0C,
    AUTH_FAILED = 0x0D,
    AUTH_REJECT = 0x0E,
    AUTH_BAD_SERVER_PROOF = 0x0F,
    AUTH_UNAVAILABLE = 0x10,
    AUTH_SYSTEM_ERROR = 0x11,
    AUTH_BILLING_ERROR = 0x12,
    AUTH_BILLING_EXPIRED = 0x13,
    AUTH_VERSION_MISMATCH = 0x14,
    AUTH_UNKNOWN_ACCOUNT = 0x15,
    AUTH_INCORRECT_PASSWORD = 0x16,
    AUTH_SESSION_EXPIRED = 0x17,
    AUTH_SERVER_SHUTTING_DOWN = 0x18,
    AUTH_ALREADY_LOGGING_IN = 0x19,
    AUTH_LOGIN_SERVER_NOT_FOUND = 0x1A,
    AUTH_WAIT_QUEUE = 0x1B,
    AUTH_BANNED = 0x1C,
    AUTH_ALREADY_ONLINE = 0x1D,
    AUTH_NO_TIME = 0x1E,
    AUTH_DB_BUSY = 0x1F,
    AUTH_SUSPENDED = 0x20,
    AUTH_PARENTAL_CONTROL = 0x21,
    REALM_LIST_IN_PROGRESS = 0x22,
    REALM_LIST_SUCCESS = 0x23,
    REALM_LIST_FAILED = 0x24,
    REALM_LIST_INVALID = 0x25,
    REALM_LIST_REALM_NOT_FOUND = 0x26,
    ACCOUNT_CREATE_IN_PROGRESS = 0x27,
    ACCOUNT_CREATE_SUCCESS = 0x28,
    ACCOUNT_CREATE_FAILED = 0x29,
    CHAR_LIST_RETRIEVING = 0x2A,
    CHAR_LIST_RETRIEVED = 0x2B,
    CHAR_LIST_FAILED = 0x2C,
    CHAR_CREATE_IN_PROGRESS = 0x2D,
    CHAR_CREATE_SUCCESS = 0x2E,
    CHAR_CREATE_ERROR = 0x2F,
    CHAR_CREATE_FAILED = 0x30,
    CHAR_CREATE_NAME_IN_USE = 0x31,
    CHAR_CREATE_DISABLED = 0x32,
    CHAR_CREATE_PVP_TEAMS_VIOLATION = 0x33,
    CHAR_CREATE_SERVER_LIMIT = 0x34,
    CHAR_CREATE_ACCOUNT_LIMIT = 0x35,
    CHAR_CREATE_SERVER_QUEUE = 0x36,
    CHAR_CREATE_ONLY_EXISTING = 0x37,
    CHAR_DELETE_IN_PROGRESS = 0x38,
    CHAR_DELETE_SUCCESS = 0x39,
    CHAR_DELETE_FAILED = 0x3A,
    CHAR_DELETE_FAILED_LOCKED_FOR_TRANSFER = 0x3B,
    CHAR_LOGIN_IN_PROGRESS = 0x3C,
    CHAR_LOGIN_SUCCESS = 0x3D,
    CHAR_LOGIN_NO_WORLD = 0x3E,
    CHAR_LOGIN_DUPLICATE_CHARACTER = 0x3F,
    CHAR_LOGIN_NO_INSTANCES = 0x40,
    CHAR_LOGIN_FAILED = 0x41,
    CHAR_LOGIN_DISABLED = 0x42,
    CHAR_LOGIN_NO_CHARACTER = 0x43,
    CHAR_LOGIN_LOCKED_FOR_TRANSFER = 0x44,
    CHAR_NAME_NO_NAME = 0x45,
    CHAR_NAME_TOO_SHORT = 0x46,
    CHAR_NAME_TOO_LONG = 0x47,
    CHAR_NAME_ONLY_LETTERS = 0x48,
    CHAR_NAME_MIXED_LANGUAGES = 0x49,
    CHAR_NAME_PROFANE = 0x4A,
    CHAR_NAME_RESERVED = 0x4B,
    CHAR_NAME_INVALID_APOSTROPHE = 0x4C,
    CHAR_NAME_MULTIPLE_APOSTROPHES = 0x4D,
    CHAR_NAME_THREE_CONSECUTIVE = 0x4E,
    CHAR_NAME_INVALID_SPACE = 0x4F,
    CHAR_NAME_SUCCESS = 0x50,
    CHAR_NAME_FAILURE = 0x51
} account_result_values;

static const value_string account_result_strings[] = {
    { RESPONSE_SUCCESS, "RESPONSE_SUCCESS" },
    { RESPONSE_FAILURE, "RESPONSE_FAILURE" },
    { RESPONSE_CANCELLED, "RESPONSE_CANCELLED" },
    { RESPONSE_DISCONNECTED, "RESPONSE_DISCONNECTED" },
    { RESPONSE_FAILED_TO_CONNECT, "RESPONSE_FAILED_TO_CONNECT" },
    { RESPONSE_CONNECTED, "RESPONSE_CONNECTED" },
    { RESPONSE_VERSION_MISMATCH, "RESPONSE_VERSION_MISMATCH" },
    { CSTATUS_CONNECTING, "CSTATUS_CONNECTING" },
    { CSTATUS_NEGOTIATING_SECURITY, "CSTATUS_NEGOTIATING_SECURITY" },
    { CSTATUS_NEGOTIATION_COMPLETE, "CSTATUS_NEGOTIATION_COMPLETE" },
    { CSTATUS_NEGOTIATION_FAILED, "CSTATUS_NEGOTIATION_FAILED" },
    { CSTATUS_AUTHENTICATING, "CSTATUS_AUTHENTICATING" },
    { AUTH_OK, "AUTH_OK" },
    { AUTH_FAILED, "AUTH_FAILED" },
    { AUTH_REJECT, "AUTH_REJECT" },
    { AUTH_BAD_SERVER_PROOF, "AUTH_BAD_SERVER_PROOF" },
    { AUTH_UNAVAILABLE, "AUTH_UNAVAILABLE" },
    { AUTH_SYSTEM_ERROR, "AUTH_SYSTEM_ERROR" },
    { AUTH_BILLING_ERROR, "AUTH_BILLING_ERROR" },
    { AUTH_BILLING_EXPIRED, "AUTH_BILLING_EXPIRED" },
    { AUTH_VERSION_MISMATCH, "AUTH_VERSION_MISMATCH" },
    { AUTH_UNKNOWN_ACCOUNT, "AUTH_UNKNOWN_ACCOUNT" },
    { AUTH_INCORRECT_PASSWORD, "AUTH_INCORRECT_PASSWORD" },
    { AUTH_SESSION_EXPIRED, "AUTH_SESSION_EXPIRED" },
    { AUTH_SERVER_SHUTTING_DOWN, "AUTH_SERVER_SHUTTING_DOWN" },
    { AUTH_ALREADY_LOGGING_IN, "AUTH_ALREADY_LOGGING_IN" },
    { AUTH_LOGIN_SERVER_NOT_FOUND, "AUTH_LOGIN_SERVER_NOT_FOUND" },
    { AUTH_WAIT_QUEUE, "AUTH_WAIT_QUEUE" },
    { AUTH_BANNED, "AUTH_BANNED" },
    { AUTH_ALREADY_ONLINE, "AUTH_ALREADY_ONLINE" },
    { AUTH_NO_TIME, "AUTH_NO_TIME" },
    { AUTH_DB_BUSY, "AUTH_DB_BUSY" },
    { AUTH_SUSPENDED, "AUTH_SUSPENDED" },
    { AUTH_PARENTAL_CONTROL, "AUTH_PARENTAL_CONTROL" },
    { REALM_LIST_IN_PROGRESS, "REALM_LIST_IN_PROGRESS" },
    { REALM_LIST_SUCCESS, "REALM_LIST_SUCCESS" },
    { REALM_LIST_FAILED, "REALM_LIST_FAILED" },
    { REALM_LIST_INVALID, "REALM_LIST_INVALID" },
    { REALM_LIST_REALM_NOT_FOUND, "REALM_LIST_REALM_NOT_FOUND" },
    { ACCOUNT_CREATE_IN_PROGRESS, "ACCOUNT_CREATE_IN_PROGRESS" },
    { ACCOUNT_CREATE_SUCCESS, "ACCOUNT_CREATE_SUCCESS" },
    { ACCOUNT_CREATE_FAILED, "ACCOUNT_CREATE_FAILED" },
    { CHAR_LIST_RETRIEVING, "CHAR_LIST_RETRIEVING" },
    { CHAR_LIST_RETRIEVED, "CHAR_LIST_RETRIEVED" },
    { CHAR_LIST_FAILED, "CHAR_LIST_FAILED" },
    { CHAR_CREATE_IN_PROGRESS, "CHAR_CREATE_IN_PROGRESS" },
    { CHAR_CREATE_SUCCESS, "CHAR_CREATE_SUCCESS" },
    { CHAR_CREATE_ERROR, "CHAR_CREATE_ERROR" },
    { CHAR_CREATE_FAILED, "CHAR_CREATE_FAILED" },
    { CHAR_CREATE_NAME_IN_USE, "CHAR_CREATE_NAME_IN_USE" },
    { CHAR_CREATE_DISABLED, "CHAR_CREATE_DISABLED" },
    { CHAR_CREATE_PVP_TEAMS_VIOLATION, "CHAR_CREATE_PVP_TEAMS_VIOLATION" },
    { CHAR_CREATE_SERVER_LIMIT, "CHAR_CREATE_SERVER_LIMIT" },
    { CHAR_CREATE_ACCOUNT_LIMIT, "CHAR_CREATE_ACCOUNT_LIMIT" },
    { CHAR_CREATE_SERVER_QUEUE, "CHAR_CREATE_SERVER_QUEUE" },
    { CHAR_CREATE_ONLY_EXISTING, "CHAR_CREATE_ONLY_EXISTING" },
    { CHAR_DELETE_IN_PROGRESS, "CHAR_DELETE_IN_PROGRESS" },
    { CHAR_DELETE_SUCCESS, "CHAR_DELETE_SUCCESS" },
    { CHAR_DELETE_FAILED, "CHAR_DELETE_FAILED" },
    { CHAR_DELETE_FAILED_LOCKED_FOR_TRANSFER, "CHAR_DELETE_FAILED_LOCKED_FOR_TRANSFER" },
    { CHAR_LOGIN_IN_PROGRESS, "CHAR_LOGIN_IN_PROGRESS" },
    { CHAR_LOGIN_SUCCESS, "CHAR_LOGIN_SUCCESS" },
    { CHAR_LOGIN_NO_WORLD, "CHAR_LOGIN_NO_WORLD" },
    { CHAR_LOGIN_DUPLICATE_CHARACTER, "CHAR_LOGIN_DUPLICATE_CHARACTER" },
    { CHAR_LOGIN_NO_INSTANCES, "CHAR_LOGIN_NO_INSTANCES" },
    { CHAR_LOGIN_FAILED, "CHAR_LOGIN_FAILED" },
    { CHAR_LOGIN_DISABLED, "CHAR_LOGIN_DISABLED" },
    { CHAR_LOGIN_NO_CHARACTER, "CHAR_LOGIN_NO_CHARACTER" },
    { CHAR_LOGIN_LOCKED_FOR_TRANSFER, "CHAR_LOGIN_LOCKED_FOR_TRANSFER" },
    { CHAR_NAME_NO_NAME, "CHAR_NAME_NO_NAME" },
    { CHAR_NAME_TOO_SHORT, "CHAR_NAME_TOO_SHORT" },
    { CHAR_NAME_TOO_LONG, "CHAR_NAME_TOO_LONG" },
    { CHAR_NAME_ONLY_LETTERS, "CHAR_NAME_ONLY_LETTERS" },
    { CHAR_NAME_MIXED_LANGUAGES, "CHAR_NAME_MIXED_LANGUAGES" },
    { CHAR_NAME_PROFANE, "CHAR_NAME_PROFANE" },
    { CHAR_NAME_RESERVED, "CHAR_NAME_RESERVED" },
    { CHAR_NAME_INVALID_APOSTROPHE, "CHAR_NAME_INVALID_APOSTROPHE" },
    { CHAR_NAME_MULTIPLE_APOSTROPHES, "CHAR_NAME_MULTIPLE_APOSTROPHES" },
    { CHAR_NAME_THREE_CONSECUTIVE, "CHAR_NAME_THREE_CONSECUTIVE" },
    { CHAR_NAME_INVALID_SPACE, "CHAR_NAME_INVALID_SPACE" },
    { CHAR_NAME_SUCCESS, "CHAR_NAME_SUCCESS" },
    { CHAR_NAME_FAILURE, "CHAR_NAME_FAILURE" },
    { 0, NULL }
};

// All existing opcodes for 1.12.x
typedef enum
{
    MSG_NULL_ACTION                                 = 0x000,
    CMSG_BOOTME                                     = 0x001,
    CMSG_DBLOOKUP                                   = 0x002,
    SMSG_DBLOOKUP                                   = 0x003,
    CMSG_QUERY_OBJECT_POSITION                      = 0x004,
    SMSG_QUERY_OBJECT_POSITION                      = 0x005,
    CMSG_QUERY_OBJECT_ROTATION                      = 0x006,
    SMSG_QUERY_OBJECT_ROTATION                      = 0x007,
    CMSG_WORLD_TELEPORT                             = 0x008,
    CMSG_TELEPORT_TO_UNIT                           = 0x009,
    CMSG_ZONE_MAP                                   = 0x00A,
    SMSG_ZONE_MAP                                   = 0x00B,
    CMSG_DEBUG_CHANGECELLZONE                       = 0x00C,
    CMSG_EMBLAZON_TABARD_OBSOLETE                   = 0x00D,
    CMSG_UNEMBLAZON_TABARD_OBSOLETE                 = 0x00E,
    CMSG_RECHARGE                                   = 0x00F,
    CMSG_LEARN_SPELL                                = 0x010,
    CMSG_CREATEMONSTER                              = 0x011,
    CMSG_DESTROYMONSTER                             = 0x012,
    CMSG_CREATEITEM                                 = 0x013,
    CMSG_CREATEGAMEOBJECT                           = 0x014,
    SMSG_CHECK_FOR_BOTS                             = 0x015,
    CMSG_MAKEMONSTERATTACKGUID                      = 0x016,
    CMSG_BOT_DETECTED2                              = 0x017,
    CMSG_FORCEACTION                                = 0x018,
    CMSG_FORCEACTIONONOTHER                         = 0x019,
    CMSG_FORCEACTIONSHOW                            = 0x01A,
    SMSG_FORCEACTIONSHOW                            = 0x01B,
    CMSG_PETGODMODE                                 = 0x01C,
    SMSG_PETGODMODE                                 = 0x01D,
    SMSG_DEBUGINFOSPELLMISS_OBSOLETE                = 0x01E,
    CMSG_WEATHER_SPEED_CHEAT                        = 0x01F,
    CMSG_UNDRESSPLAYER                              = 0x020,
    CMSG_BEASTMASTER                                = 0x021,
    CMSG_GODMODE                                    = 0x022,
    SMSG_GODMODE                                    = 0x023,
    CMSG_CHEAT_SETMONEY                             = 0x024,
    CMSG_LEVEL_CHEAT                                = 0x025,
    CMSG_PET_LEVEL_CHEAT                            = 0x026,
    CMSG_SET_WORLDSTATE                             = 0x027,
    CMSG_COOLDOWN_CHEAT                             = 0x028,
    CMSG_USE_SKILL_CHEAT                            = 0x029,
    CMSG_FLAG_QUEST                                 = 0x02A,
    CMSG_FLAG_QUEST_FINISH                          = 0x02B,
    CMSG_CLEAR_QUEST                                = 0x02C,
    CMSG_SEND_EVENT                                 = 0x02D,
    CMSG_DEBUG_AISTATE                              = 0x02E,
    SMSG_DEBUG_AISTATE                              = 0x02F,
    CMSG_DISABLE_PVP_CHEAT                          = 0x030,
    CMSG_ADVANCE_SPAWN_TIME                         = 0x031,
    CMSG_PVP_PORT_OBSOLETE                          = 0x032,
    CMSG_AUTH_SRP6_BEGIN                            = 0x033,
    CMSG_AUTH_SRP6_PROOF                            = 0x034,
    CMSG_AUTH_SRP6_RECODE                           = 0x035,
    CMSG_CHAR_CREATE                                = 0x036,
    CMSG_CHAR_ENUM                                  = 0x037,
    CMSG_CHAR_DELETE                                = 0x038,
    SMSG_AUTH_SRP6_RESPONSE                         = 0x039,
    SMSG_CHAR_CREATE                                = 0x03A,
    SMSG_CHAR_ENUM                                  = 0x03B,
    SMSG_CHAR_DELETE                                = 0x03C,
    CMSG_PLAYER_LOGIN                               = 0x03D,
    SMSG_NEW_WORLD                                  = 0x03E,
    SMSG_TRANSFER_PENDING                           = 0x03F,
    SMSG_TRANSFER_ABORTED                           = 0x040,
    SMSG_CHARACTER_LOGIN_FAILED                     = 0x041,
    SMSG_LOGIN_SETTIMESPEED                         = 0x042,
    SMSG_GAMETIME_UPDATE                            = 0x043,
    CMSG_GAMETIME_SET                               = 0x044,
    SMSG_GAMETIME_SET                               = 0x045,
    CMSG_GAMESPEED_SET                              = 0x046,
    SMSG_GAMESPEED_SET                              = 0x047,
    CMSG_SERVERTIME                                 = 0x048,
    SMSG_SERVERTIME                                 = 0x049,
    CMSG_PLAYER_LOGOUT                              = 0x04A,
    CMSG_LOGOUT_REQUEST                             = 0x04B,
    SMSG_LOGOUT_RESPONSE                            = 0x04C,
    SMSG_LOGOUT_COMPLETE                            = 0x04D,
    CMSG_LOGOUT_CANCEL                              = 0x04E,
    SMSG_LOGOUT_CANCEL_ACK                          = 0x04F,
    CMSG_NAME_QUERY                                 = 0x050,
    SMSG_NAME_QUERY_RESPONSE                        = 0x051,
    CMSG_PET_NAME_QUERY                             = 0x052,
    SMSG_PET_NAME_QUERY_RESPONSE                    = 0x053,
    CMSG_GUILD_QUERY                                = 0x054,
    SMSG_GUILD_QUERY_RESPONSE                       = 0x055,
    CMSG_ITEM_QUERY_SINGLE                          = 0x056,
    CMSG_ITEM_QUERY_MULTIPLE                        = 0x057,
    SMSG_ITEM_QUERY_SINGLE_RESPONSE                 = 0x058,
    SMSG_ITEM_QUERY_MULTIPLE_RESPONSE               = 0x059,
    CMSG_PAGE_TEXT_QUERY                            = 0x05A,
    SMSG_PAGE_TEXT_QUERY_RESPONSE                   = 0x05B,
    CMSG_QUEST_QUERY                                = 0x05C,
    SMSG_QUEST_QUERY_RESPONSE                       = 0x05D,
    CMSG_GAMEOBJECT_QUERY                           = 0x05E,
    SMSG_GAMEOBJECT_QUERY_RESPONSE                  = 0x05F,
    CMSG_CREATURE_QUERY                             = 0x060,
    SMSG_CREATURE_QUERY_RESPONSE                    = 0x061,
    CMSG_WHO                                        = 0x062,
    SMSG_WHO                                        = 0x063,
    CMSG_WHOIS                                      = 0x064,
    SMSG_WHOIS                                      = 0x065,
    CMSG_FRIEND_LIST                                = 0x066,
    SMSG_FRIEND_LIST                                = 0x067,
    SMSG_FRIEND_STATUS                              = 0x068,
    CMSG_ADD_FRIEND                                 = 0x069,
    CMSG_DEL_FRIEND                                 = 0x06A,
    SMSG_IGNORE_LIST                                = 0x06B,
    CMSG_ADD_IGNORE                                 = 0x06C,
    CMSG_DEL_IGNORE                                 = 0x06D,
    CMSG_GROUP_INVITE                               = 0x06E,
    SMSG_GROUP_INVITE                               = 0x06F,
    CMSG_GROUP_CANCEL                               = 0x070,
    SMSG_GROUP_CANCEL                               = 0x071,
    CMSG_GROUP_ACCEPT                               = 0x072,
    CMSG_GROUP_DECLINE                              = 0x073,
    SMSG_GROUP_DECLINE                              = 0x074,
    CMSG_GROUP_UNINVITE                             = 0x075,
    CMSG_GROUP_UNINVITE_GUID                        = 0x076,
    SMSG_GROUP_UNINVITE                             = 0x077,
    CMSG_GROUP_SET_LEADER                           = 0x078,
    SMSG_GROUP_SET_LEADER                           = 0x079,
    CMSG_LOOT_METHOD                                = 0x07A,
    CMSG_GROUP_DISBAND                              = 0x07B,
    SMSG_GROUP_DESTROYED                            = 0x07C,
    SMSG_GROUP_LIST                                 = 0x07D,
    SMSG_PARTY_MEMBER_STATS                         = 0x07E,
    SMSG_PARTY_COMMAND_RESULT                       = 0x07F,
    UMSG_UPDATE_GROUP_MEMBERS                       = 0x080,
    CMSG_GUILD_CREATE                               = 0x081,
    CMSG_GUILD_INVITE                               = 0x082,
    SMSG_GUILD_INVITE                               = 0x083,
    CMSG_GUILD_ACCEPT                               = 0x084,
    CMSG_GUILD_DECLINE                              = 0x085,
    SMSG_GUILD_DECLINE                              = 0x086,
    CMSG_GUILD_INFO                                 = 0x087,
    SMSG_GUILD_INFO                                 = 0x088,
    CMSG_GUILD_ROSTER                               = 0x089,
    SMSG_GUILD_ROSTER                               = 0x08A,
    CMSG_GUILD_PROMOTE                              = 0x08B,
    CMSG_GUILD_DEMOTE                               = 0x08C,
    CMSG_GUILD_LEAVE                                = 0x08D,
    CMSG_GUILD_REMOVE                               = 0x08E,
    CMSG_GUILD_DISBAND                              = 0x08F,
    CMSG_GUILD_LEADER                               = 0x090,
    CMSG_GUILD_MOTD                                 = 0x091,
    SMSG_GUILD_EVENT                                = 0x092,
    SMSG_GUILD_COMMAND_RESULT                       = 0x093,
    UMSG_UPDATE_GUILD                               = 0x094,
    CMSG_MESSAGECHAT                                = 0x095,
    SMSG_MESSAGECHAT                                = 0x096,
    CMSG_JOIN_CHANNEL                               = 0x097,
    CMSG_LEAVE_CHANNEL                              = 0x098,
    SMSG_CHANNEL_NOTIFY                             = 0x099,
    CMSG_CHANNEL_LIST                               = 0x09A,
    SMSG_CHANNEL_LIST                               = 0x09B,
    CMSG_CHANNEL_PASSWORD                           = 0x09C,
    CMSG_CHANNEL_SET_OWNER                          = 0x09D,
    CMSG_CHANNEL_OWNER                              = 0x09E,
    CMSG_CHANNEL_MODERATOR                          = 0x09F,
    CMSG_CHANNEL_UNMODERATOR                        = 0x0A0,
    CMSG_CHANNEL_MUTE                               = 0x0A1,
    CMSG_CHANNEL_UNMUTE                             = 0x0A2,
    CMSG_CHANNEL_INVITE                             = 0x0A3,
    CMSG_CHANNEL_KICK                               = 0x0A4,
    CMSG_CHANNEL_BAN                                = 0x0A5,
    CMSG_CHANNEL_UNBAN                              = 0x0A6,
    CMSG_CHANNEL_ANNOUNCEMENTS                      = 0x0A7,
    CMSG_CHANNEL_MODERATE                           = 0x0A8,
    SMSG_UPDATE_OBJECT                              = 0x0A9,
    SMSG_DESTROY_OBJECT                             = 0x0AA,
    CMSG_USE_ITEM                                   = 0x0AB,
    CMSG_OPEN_ITEM                                  = 0x0AC,
    CMSG_READ_ITEM                                  = 0x0AD,
    SMSG_READ_ITEM_OK                               = 0x0AE,
    SMSG_READ_ITEM_FAILED                           = 0x0AF,
    SMSG_ITEM_COOLDOWN                              = 0x0B0,
    CMSG_GAMEOBJ_USE                                = 0x0B1,
    CMSG_GAMEOBJ_CHAIR_USE_OBSOLETE                 = 0x0B2,
    SMSG_GAMEOBJECT_CUSTOM_ANIM                     = 0x0B3,
    CMSG_AREATRIGGER                                = 0x0B4,
    MSG_MOVE_START_FORWARD                          = 0x0B5,
    MSG_MOVE_START_BACKWARD                         = 0x0B6,
    MSG_MOVE_STOP                                   = 0x0B7,
    MSG_MOVE_START_STRAFE_LEFT                      = 0x0B8,
    MSG_MOVE_START_STRAFE_RIGHT                     = 0x0B9,
    MSG_MOVE_STOP_STRAFE                            = 0x0BA,
    MSG_MOVE_JUMP                                   = 0x0BB,
    MSG_MOVE_START_TURN_LEFT                        = 0x0BC,
    MSG_MOVE_START_TURN_RIGHT                       = 0x0BD,
    MSG_MOVE_STOP_TURN                              = 0x0BE,
    MSG_MOVE_START_PITCH_UP                         = 0x0BF,
    MSG_MOVE_START_PITCH_DOWN                       = 0x0C0,
    MSG_MOVE_STOP_PITCH                             = 0x0C1,
    MSG_MOVE_SET_RUN_MODE                           = 0x0C2,
    MSG_MOVE_SET_WALK_MODE                          = 0x0C3,
    MSG_MOVE_TOGGLE_LOGGING                         = 0x0C4,
    MSG_MOVE_TELEPORT                               = 0x0C5,
    MSG_MOVE_TELEPORT_CHEAT                         = 0x0C6,
    MSG_MOVE_TELEPORT_ACK                           = 0x0C7,
    MSG_MOVE_TOGGLE_FALL_LOGGING                    = 0x0C8,
    MSG_MOVE_FALL_LAND                              = 0x0C9,
    MSG_MOVE_START_SWIM                             = 0x0CA,
    MSG_MOVE_STOP_SWIM                              = 0x0CB,
    MSG_MOVE_SET_RUN_SPEED_CHEAT                    = 0x0CC,
    MSG_MOVE_SET_RUN_SPEED                          = 0x0CD,
    MSG_MOVE_SET_RUN_BACK_SPEED_CHEAT               = 0x0CE,
    MSG_MOVE_SET_RUN_BACK_SPEED                     = 0x0CF,
    MSG_MOVE_SET_WALK_SPEED_CHEAT                   = 0x0D0,
    MSG_MOVE_SET_WALK_SPEED                         = 0x0D1,
    MSG_MOVE_SET_SWIM_SPEED_CHEAT                   = 0x0D2,
    MSG_MOVE_SET_SWIM_SPEED                         = 0x0D3,
    MSG_MOVE_SET_SWIM_BACK_SPEED_CHEAT              = 0x0D4,
    MSG_MOVE_SET_SWIM_BACK_SPEED                    = 0x0D5,
    MSG_MOVE_SET_ALL_SPEED_CHEAT                    = 0x0D6,
    MSG_MOVE_SET_TURN_RATE_CHEAT                    = 0x0D7,
    MSG_MOVE_SET_TURN_RATE                          = 0x0D8,
    MSG_MOVE_TOGGLE_COLLISION_CHEAT                 = 0x0D9,
    MSG_MOVE_SET_FACING                             = 0x0DA,
    MSG_MOVE_SET_PITCH                              = 0x0DB,
    MSG_MOVE_WORLDPORT_ACK                          = 0x0DC,
    SMSG_MONSTER_MOVE                               = 0x0DD,
    SMSG_MOVE_WATER_WALK                            = 0x0DE,
    SMSG_MOVE_LAND_WALK                             = 0x0DF,
    MSG_MOVE_SET_RAW_POSITION_ACK                   = 0x0E0,
    CMSG_MOVE_SET_RAW_POSITION                      = 0x0E1,
    SMSG_FORCE_RUN_SPEED_CHANGE                     = 0x0E2,
    CMSG_FORCE_RUN_SPEED_CHANGE_ACK                 = 0x0E3,
    SMSG_FORCE_RUN_BACK_SPEED_CHANGE                = 0x0E4,
    CMSG_FORCE_RUN_BACK_SPEED_CHANGE_ACK            = 0x0E5,
    SMSG_FORCE_SWIM_SPEED_CHANGE                    = 0x0E6,
    CMSG_FORCE_SWIM_SPEED_CHANGE_ACK                = 0x0E7,
    SMSG_FORCE_MOVE_ROOT                            = 0x0E8,
    CMSG_FORCE_MOVE_ROOT_ACK                        = 0x0E9,
    SMSG_FORCE_MOVE_UNROOT                          = 0x0EA,
    CMSG_FORCE_MOVE_UNROOT_ACK                      = 0x0EB,
    MSG_MOVE_ROOT                                   = 0x0EC,
    MSG_MOVE_UNROOT                                 = 0x0ED,
    MSG_MOVE_HEARTBEAT                              = 0x0EE,
    SMSG_MOVE_KNOCK_BACK                            = 0x0EF,
    CMSG_MOVE_KNOCK_BACK_ACK                        = 0x0F0,
    MSG_MOVE_KNOCK_BACK                             = 0x0F1,
    SMSG_MOVE_FEATHER_FALL                          = 0x0F2,
    SMSG_MOVE_NORMAL_FALL                           = 0x0F3,
    SMSG_MOVE_SET_HOVER                             = 0x0F4,
    SMSG_MOVE_UNSET_HOVER                           = 0x0F5,
    CMSG_MOVE_HOVER_ACK                             = 0x0F6,
    MSG_MOVE_HOVER                                  = 0x0F7,
    CMSG_TRIGGER_CINEMATIC_CHEAT                    = 0x0F8,
    CMSG_OPENING_CINEMATIC                          = 0x0F9,
    SMSG_TRIGGER_CINEMATIC                          = 0x0FA,
    CMSG_NEXT_CINEMATIC_CAMERA                      = 0x0FB,
    CMSG_COMPLETE_CINEMATIC                         = 0x0FC,
    SMSG_TUTORIAL_FLAGS                             = 0x0FD,
    CMSG_TUTORIAL_FLAG                              = 0x0FE,
    CMSG_TUTORIAL_CLEAR                             = 0x0FF,
    CMSG_TUTORIAL_RESET                             = 0x100,
    CMSG_STANDSTATECHANGE                           = 0x101,
    CMSG_EMOTE                                      = 0x102,
    SMSG_EMOTE                                      = 0x103,
    CMSG_TEXT_EMOTE                                 = 0x104,
    SMSG_TEXT_EMOTE                                 = 0x105,
    CMSG_AUTOEQUIP_GROUND_ITEM                      = 0x106,
    CMSG_AUTOSTORE_GROUND_ITEM                      = 0x107,
    CMSG_AUTOSTORE_LOOT_ITEM                        = 0x108,
    CMSG_STORE_LOOT_IN_SLOT                         = 0x109,
    CMSG_AUTOEQUIP_ITEM                             = 0x10A,
    CMSG_AUTOSTORE_BAG_ITEM                         = 0x10B,
    CMSG_SWAP_ITEM                                  = 0x10C,
    CMSG_SWAP_INV_ITEM                              = 0x10D,
    CMSG_SPLIT_ITEM                                 = 0x10E,
    CMSG_AUTOEQUIP_ITEM_SLOT                        = 0x10F,
    OBSOLETE_DROP_ITEM                              = 0x110,
    CMSG_DESTROYITEM                                = 0x111,
    SMSG_INVENTORY_CHANGE_FAILURE                   = 0x112,
    SMSG_OPEN_CONTAINER                             = 0x113,
    CMSG_INSPECT                                    = 0x114,
    SMSG_INSPECT                                    = 0x115,
    CMSG_INITIATE_TRADE                             = 0x116,
    CMSG_BEGIN_TRADE                                = 0x117,
    CMSG_BUSY_TRADE                                 = 0x118,
    CMSG_IGNORE_TRADE                               = 0x119,
    CMSG_ACCEPT_TRADE                               = 0x11A,
    CMSG_UNACCEPT_TRADE                             = 0x11B,
    CMSG_CANCEL_TRADE                               = 0x11C,
    CMSG_SET_TRADE_ITEM                             = 0x11D,
    CMSG_CLEAR_TRADE_ITEM                           = 0x11E,
    CMSG_SET_TRADE_GOLD                             = 0x11F,
    SMSG_TRADE_STATUS                               = 0x120,
    SMSG_TRADE_STATUS_EXTENDED                      = 0x121,
    SMSG_INITIALIZE_FACTIONS                        = 0x122,
    SMSG_SET_FACTION_VISIBLE                        = 0x123,
    SMSG_SET_FACTION_STANDING                       = 0x124,
    CMSG_SET_FACTION_ATWAR                          = 0x125,
    CMSG_SET_FACTION_CHEAT                          = 0x126,
    SMSG_SET_PROFICIENCY                            = 0x127,
    CMSG_SET_ACTION_BUTTON                          = 0x128,
    SMSG_ACTION_BUTTONS                             = 0x129,
    SMSG_INITIAL_SPELLS                             = 0x12A,
    SMSG_LEARNED_SPELL                              = 0x12B,
    SMSG_SUPERCEDED_SPELL                           = 0x12C,
    CMSG_NEW_SPELL_SLOT                             = 0x12D,
    CMSG_CAST_SPELL                                 = 0x12E,
    CMSG_CANCEL_CAST                                = 0x12F,
    SMSG_CAST_FAILED                                = 0x130,
    SMSG_SPELL_START                                = 0x131,
    SMSG_SPELL_GO                                   = 0x132,
    SMSG_SPELL_FAILURE                              = 0x133,
    SMSG_SPELL_COOLDOWN                             = 0x134,
    SMSG_COOLDOWN_EVENT                             = 0x135,
    CMSG_CANCEL_AURA                                = 0x136,
    SMSG_UPDATE_AURA_DURATION                       = 0x137,
    SMSG_PET_CAST_FAILED                            = 0x138,
    MSG_CHANNEL_START                               = 0x139,
    MSG_CHANNEL_UPDATE                              = 0x13A,
    CMSG_CANCEL_CHANNELLING                         = 0x13B,
    SMSG_AI_REACTION                                = 0x13C,
    CMSG_SET_SELECTION                              = 0x13D,
    CMSG_SET_TARGET_OBSOLETE                        = 0x13E,
    CMSG_UNUSED                                     = 0x13F,
    CMSG_UNUSED2                                    = 0x140,
    CMSG_ATTACKSWING                                = 0x141,
    CMSG_ATTACKSTOP                                 = 0x142,
    SMSG_ATTACKSTART                                = 0x143,
    SMSG_ATTACKSTOP                                 = 0x144,
    SMSG_ATTACKSWING_NOTINRANGE                     = 0x145,
    SMSG_ATTACKSWING_BADFACING                      = 0x146,
    SMSG_ATTACKSWING_NOTSTANDING                    = 0x147,
    SMSG_ATTACKSWING_DEADTARGET                     = 0x148,
    SMSG_ATTACKSWING_CANT_ATTACK                    = 0x149,
    SMSG_ATTACKERSTATEUPDATE                        = 0x14A,
    SMSG_VICTIMSTATEUPDATE_OBSOLETE                 = 0x14B,
    SMSG_DAMAGE_DONE_OBSOLETE                       = 0x14C,
    SMSG_DAMAGE_TAKEN_OBSOLETE                      = 0x14D,
    SMSG_CANCEL_COMBAT                              = 0x14E,
    SMSG_PLAYER_COMBAT_XP_GAIN_OBSOLETE             = 0x14F,
    SMSG_SPELLHEALLOG                               = 0x150,
    SMSG_SPELLENERGIZELOG                           = 0x151,
    CMSG_SHEATHE_OBSOLETE                           = 0x152,
    CMSG_SAVE_PLAYER                                = 0x153,
    CMSG_SETDEATHBINDPOINT                          = 0x154,
    SMSG_BINDPOINTUPDATE                            = 0x155,
    CMSG_GETDEATHBINDZONE                           = 0x156,
    SMSG_BINDZONEREPLY                              = 0x157,
    SMSG_PLAYERBOUND                                = 0x158,
    SMSG_CLIENT_CONTROL_UPDATE                      = 0x159,
    CMSG_REPOP_REQUEST                              = 0x15A,
    SMSG_RESURRECT_REQUEST                          = 0x15B,
    CMSG_RESURRECT_RESPONSE                         = 0x15C,
    CMSG_LOOT                                       = 0x15D,
    CMSG_LOOT_MONEY                                 = 0x15E,
    CMSG_LOOT_RELEASE                               = 0x15F,
    SMSG_LOOT_RESPONSE                              = 0x160,
    SMSG_LOOT_RELEASE_RESPONSE                      = 0x161,
    SMSG_LOOT_REMOVED                               = 0x162,
    SMSG_LOOT_MONEY_NOTIFY                          = 0x163,
    SMSG_LOOT_ITEM_NOTIFY                           = 0x164,
    SMSG_LOOT_CLEAR_MONEY                           = 0x165,
    SMSG_ITEM_PUSH_RESULT                           = 0x166,
    SMSG_DUEL_REQUESTED                             = 0x167,
    SMSG_DUEL_OUTOFBOUNDS                           = 0x168,
    SMSG_DUEL_INBOUNDS                              = 0x169,
    SMSG_DUEL_COMPLETE                              = 0x16A,
    SMSG_DUEL_WINNER                                = 0x16B,
    CMSG_DUEL_ACCEPTED                              = 0x16C,
    CMSG_DUEL_CANCELLED                             = 0x16D,
    SMSG_MOUNTRESULT                                = 0x16E,
    SMSG_DISMOUNTRESULT                             = 0x16F,
    SMSG_PUREMOUNT_CANCELLED_OBSOLETE               = 0x170,
    CMSG_MOUNTSPECIAL_ANIM                          = 0x171,
    SMSG_MOUNTSPECIAL_ANIM                          = 0x172,
    SMSG_PET_TAME_FAILURE                           = 0x173,
    CMSG_PET_SET_ACTION                             = 0x174,
    CMSG_PET_ACTION                                 = 0x175,
    CMSG_PET_ABANDON                                = 0x176,
    CMSG_PET_RENAME                                 = 0x177,
    SMSG_PET_NAME_INVALID                           = 0x178,
    SMSG_PET_SPELLS                                 = 0x179,
    SMSG_PET_MODE                                   = 0x17A,
    CMSG_GOSSIP_HELLO                               = 0x17B,
    CMSG_GOSSIP_SELECT_OPTION                       = 0x17C,
    SMSG_GOSSIP_MESSAGE                             = 0x17D,
    SMSG_GOSSIP_COMPLETE                            = 0x17E,
    CMSG_NPC_TEXT_QUERY                             = 0x17F,
    SMSG_NPC_TEXT_UPDATE                            = 0x180,
    SMSG_NPC_WONT_TALK                              = 0x181,
    CMSG_QUESTGIVER_STATUS_QUERY                    = 0x182,
    SMSG_QUESTGIVER_STATUS                          = 0x183,
    CMSG_QUESTGIVER_HELLO                           = 0x184,
    SMSG_QUESTGIVER_QUEST_LIST                      = 0x185,
    CMSG_QUESTGIVER_QUERY_QUEST                     = 0x186,
    CMSG_QUESTGIVER_QUEST_AUTOLAUNCH                = 0x187,
    SMSG_QUESTGIVER_QUEST_DETAILS                   = 0x188,
    CMSG_QUESTGIVER_ACCEPT_QUEST                    = 0x189,
    CMSG_QUESTGIVER_COMPLETE_QUEST                  = 0x18A,
    SMSG_QUESTGIVER_REQUEST_ITEMS                   = 0x18B,
    CMSG_QUESTGIVER_REQUEST_REWARD                  = 0x18C,
    SMSG_QUESTGIVER_OFFER_REWARD                    = 0x18D,
    CMSG_QUESTGIVER_CHOOSE_REWARD                   = 0x18E,
    SMSG_QUESTGIVER_QUEST_INVALID                   = 0x18F,
    CMSG_QUESTGIVER_CANCEL                          = 0x190,
    SMSG_QUESTGIVER_QUEST_COMPLETE                  = 0x191,
    SMSG_QUESTGIVER_QUEST_FAILED                    = 0x192,
    CMSG_QUESTLOG_SWAP_QUEST                        = 0x193,
    CMSG_QUESTLOG_REMOVE_QUEST                      = 0x194,
    SMSG_QUESTLOG_FULL                              = 0x195,
    SMSG_QUESTUPDATE_FAILED                         = 0x196,
    SMSG_QUESTUPDATE_FAILEDTIMER                    = 0x197,
    SMSG_QUESTUPDATE_COMPLETE                       = 0x198,
    SMSG_QUESTUPDATE_ADD_KILL                       = 0x199,
    SMSG_QUESTUPDATE_ADD_ITEM                       = 0x19A,
    CMSG_QUEST_CONFIRM_ACCEPT                       = 0x19B,
    SMSG_QUEST_CONFIRM_ACCEPT                       = 0x19C,
    CMSG_PUSHQUESTTOPARTY                           = 0x19D,
    CMSG_LIST_INVENTORY                             = 0x19E,
    SMSG_LIST_INVENTORY                             = 0x19F,
    CMSG_SELL_ITEM                                  = 0x1A0,
    SMSG_SELL_ITEM                                  = 0x1A1,
    CMSG_BUY_ITEM                                   = 0x1A2,
    CMSG_BUY_ITEM_IN_SLOT                           = 0x1A3,
    SMSG_BUY_ITEM                                   = 0x1A4,
    SMSG_BUY_FAILED                                 = 0x1A5,
    CMSG_TAXICLEARALLNODES                          = 0x1A6,
    CMSG_TAXIENABLEALLNODES                         = 0x1A7,
    CMSG_TAXISHOWNODES                              = 0x1A8,
    SMSG_SHOWTAXINODES                              = 0x1A9,
    CMSG_TAXINODE_STATUS_QUERY                      = 0x1AA,
    SMSG_TAXINODE_STATUS                            = 0x1AB,
    CMSG_TAXIQUERYAVAILABLENODES                    = 0x1AC,
    CMSG_ACTIVATETAXI                               = 0x1AD,
    SMSG_ACTIVATETAXIREPLY                          = 0x1AE,
    SMSG_NEW_TAXI_PATH                              = 0x1AF,
    CMSG_TRAINER_LIST                               = 0x1B0,
    SMSG_TRAINER_LIST                               = 0x1B1,
    CMSG_TRAINER_BUY_SPELL                          = 0x1B2,
    SMSG_TRAINER_BUY_SUCCEEDED                      = 0x1B3,
    SMSG_TRAINER_BUY_FAILED                         = 0x1B4,
    CMSG_BINDER_ACTIVATE                            = 0x1B5,
    SMSG_PLAYERBINDERROR                            = 0x1B6,
    CMSG_BANKER_ACTIVATE                            = 0x1B7,
    SMSG_SHOW_BANK                                  = 0x1B8,
    CMSG_BUY_BANK_SLOT                              = 0x1B9,
    SMSG_BUY_BANK_SLOT_RESULT                       = 0x1BA,
    CMSG_PETITION_SHOWLIST                          = 0x1BB,
    SMSG_PETITION_SHOWLIST                          = 0x1BC,
    CMSG_PETITION_BUY                               = 0x1BD,
    CMSG_PETITION_SHOW_SIGNATURES                   = 0x1BE,
    SMSG_PETITION_SHOW_SIGNATURES                   = 0x1BF,
    CMSG_PETITION_SIGN                              = 0x1C0,
    SMSG_PETITION_SIGN_RESULTS                      = 0x1C1,
    MSG_PETITION_DECLINE                            = 0x1C2,
    CMSG_OFFER_PETITION                             = 0x1C3,
    CMSG_TURN_IN_PETITION                           = 0x1C4,
    SMSG_TURN_IN_PETITION_RESULTS                   = 0x1C5,
    CMSG_PETITION_QUERY                             = 0x1C6,
    SMSG_PETITION_QUERY_RESPONSE                    = 0x1C7,
    SMSG_FISH_NOT_HOOKED                            = 0x1C8,
    SMSG_FISH_ESCAPED                               = 0x1C9,
    CMSG_BUG                                        = 0x1CA,
    SMSG_NOTIFICATION                               = 0x1CB,
    CMSG_PLAYED_TIME                                = 0x1CC,
    SMSG_PLAYED_TIME                                = 0x1CD,
    CMSG_QUERY_TIME                                 = 0x1CE,
    SMSG_QUERY_TIME_RESPONSE                        = 0x1CF,
    SMSG_LOG_XPGAIN                                 = 0x1D0,
    SMSG_AURACASTLOG                                = 0x1D1,
    CMSG_RECLAIM_CORPSE                             = 0x1D2,
    CMSG_WRAP_ITEM                                  = 0x1D3,
    SMSG_LEVELUP_INFO                               = 0x1D4,
    MSG_MINIMAP_PING                                = 0x1D5,
    SMSG_RESISTLOG                                  = 0x1D6,
    SMSG_ENCHANTMENTLOG                             = 0x1D7,
    CMSG_SET_SKILL_CHEAT                            = 0x1D8,
    SMSG_START_MIRROR_TIMER                         = 0x1D9,
    SMSG_PAUSE_MIRROR_TIMER                         = 0x1DA,
    SMSG_STOP_MIRROR_TIMER                          = 0x1DB,
    CMSG_PING                                       = 0x1DC,
    SMSG_PONG                                       = 0x1DD,
    SMSG_CLEAR_COOLDOWN                             = 0x1DE,
    SMSG_GAMEOBJECT_PAGETEXT                        = 0x1DF,
    CMSG_SETSHEATHED                                = 0x1E0,
    SMSG_COOLDOWN_CHEAT                             = 0x1E1,
    SMSG_SPELL_DELAYED                              = 0x1E2,
    CMSG_PLAYER_MACRO_OBSOLETE                      = 0x1E3,
    SMSG_PLAYER_MACRO_OBSOLETE                      = 0x1E4,
    CMSG_GHOST                                      = 0x1E5,
    CMSG_GM_INVIS                                   = 0x1E6,
    SMSG_INVALID_PROMOTION_CODE                     = 0x1E7,
    MSG_GM_BIND_OTHER                               = 0x1E8,
    MSG_GM_SUMMON                                   = 0x1E9,
    SMSG_ITEM_TIME_UPDATE                           = 0x1EA,
    SMSG_ITEM_ENCHANT_TIME_UPDATE                   = 0x1EB,
    SMSG_AUTH_CHALLENGE                             = 0x1EC,
    CMSG_AUTH_SESSION                               = 0x1ED,
    SMSG_AUTH_RESPONSE                              = 0x1EE,
    MSG_GM_SHOWLABEL                                = 0x1EF,
    CMSG_PET_CAST_SPELL                             = 0x1F0,
    MSG_SAVE_GUILD_EMBLEM                           = 0x1F1,
    MSG_TABARDVENDOR_ACTIVATE                       = 0x1F2,
    SMSG_PLAY_SPELL_VISUAL                          = 0x1F3,
    CMSG_ZONEUPDATE                                 = 0x1F4,
    SMSG_PARTYKILLLOG                               = 0x1F5,
    SMSG_COMPRESSED_UPDATE_OBJECT                   = 0x1F6,
    SMSG_PLAY_SPELL_IMPACT                          = 0x1F7,
    SMSG_EXPLORATION_EXPERIENCE                     = 0x1F8,
    CMSG_GM_SET_SECURITY_GROUP                      = 0x1F9,
    CMSG_GM_NUKE                                    = 0x1FA,
    MSG_RANDOM_ROLL                                 = 0x1FB,
    SMSG_ENVIRONMENTALDAMAGELOG                     = 0x1FC,
    CMSG_RWHOIS_OBSOLETE                            = 0x1FD,
    SMSG_RWHOIS                                     = 0x1FE,
    MSG_LOOKING_FOR_GROUP                           = 0x1FF,
    CMSG_SET_LOOKING_FOR_GROUP                      = 0x200,
    CMSG_UNLEARN_SPELL                              = 0x201,
    CMSG_UNLEARN_SKILL                              = 0x202,
    SMSG_REMOVED_SPELL                              = 0x203,
    CMSG_DECHARGE                                   = 0x204,
    CMSG_GMTICKET_CREATE                            = 0x205,
    SMSG_GMTICKET_CREATE                            = 0x206,
    CMSG_GMTICKET_UPDATETEXT                        = 0x207,
    SMSG_GMTICKET_UPDATETEXT                        = 0x208,
    SMSG_ACCOUNT_DATA_TIMES                         = 0x209,
    CMSG_REQUEST_ACCOUNT_DATA                       = 0x20A,
    CMSG_UPDATE_ACCOUNT_DATA                        = 0x20B,
    SMSG_UPDATE_ACCOUNT_DATA                        = 0x20C,
    SMSG_CLEAR_FAR_SIGHT_IMMEDIATE                  = 0x20D,
    SMSG_POWERGAINLOG_OBSOLETE                      = 0x20E,
    CMSG_GM_TEACH                                   = 0x20F,
    CMSG_GM_CREATE_ITEM_TARGET                      = 0x210,
    CMSG_GMTICKET_GETTICKET                         = 0x211,
    SMSG_GMTICKET_GETTICKET                         = 0x212,
    CMSG_UNLEARN_TALENTS                            = 0x213,
    SMSG_GAMEOBJECT_SPAWN_ANIM_OBSOLETE             = 0x214,
    SMSG_GAMEOBJECT_DESPAWN_ANIM                    = 0x215,
    MSG_CORPSE_QUERY                                = 0x216,
    CMSG_GMTICKET_DELETETICKET                      = 0x217,
    SMSG_GMTICKET_DELETETICKET                      = 0x218,
    SMSG_CHAT_WRONG_FACTION                         = 0x219,
    CMSG_GMTICKET_SYSTEMSTATUS                      = 0x21A,
    SMSG_GMTICKET_SYSTEMSTATUS                      = 0x21B,
    CMSG_SPIRIT_HEALER_ACTIVATE                     = 0x21C,
    CMSG_SET_STAT_CHEAT                             = 0x21D,
    SMSG_SET_REST_START                             = 0x21E,
    CMSG_SKILL_BUY_STEP                             = 0x21F,
    CMSG_SKILL_BUY_RANK                             = 0x220,
    CMSG_XP_CHEAT                                   = 0x221,
    SMSG_SPIRIT_HEALER_CONFIRM                      = 0x222,
    CMSG_CHARACTER_POINT_CHEAT                      = 0x223,
    SMSG_GOSSIP_POI                                 = 0x224,
    CMSG_CHAT_IGNORED                               = 0x225,
    CMSG_GM_VISION                                  = 0x226,
    CMSG_SERVER_COMMAND                             = 0x227,
    CMSG_GM_SILENCE                                 = 0x228,
    CMSG_GM_REVEALTO                                = 0x229,
    CMSG_GM_RESURRECT                               = 0x22A,
    CMSG_GM_SUMMONMOB                               = 0x22B,
    CMSG_GM_MOVECORPSE                              = 0x22C,
    CMSG_GM_FREEZE                                  = 0x22D,
    CMSG_GM_UBERINVIS                               = 0x22E,
    CMSG_GM_REQUEST_PLAYER_INFO                     = 0x22F,
    SMSG_GM_PLAYER_INFO                             = 0x230,
    CMSG_GUILD_RANK                                 = 0x231,
    CMSG_GUILD_ADD_RANK                             = 0x232,
    CMSG_GUILD_DEL_RANK                             = 0x233,
    CMSG_GUILD_SET_PUBLIC_NOTE                      = 0x234,
    CMSG_GUILD_SET_OFFICER_NOTE                     = 0x235,
    SMSG_LOGIN_VERIFY_WORLD                         = 0x236,
    CMSG_CLEAR_EXPLORATION                          = 0x237,
    CMSG_SEND_MAIL                                  = 0x238,
    SMSG_SEND_MAIL_RESULT                           = 0x239,
    CMSG_GET_MAIL_LIST                              = 0x23A,
    SMSG_MAIL_LIST_RESULT                           = 0x23B,
    CMSG_BATTLEFIELD_LIST                           = 0x23C,
    SMSG_BATTLEFIELD_LIST                           = 0x23D,
    CMSG_BATTLEFIELD_JOIN                           = 0x23E,
    SMSG_BATTLEFIELD_WIN_OBSOLETE                   = 0x23F,
    SMSG_BATTLEFIELD_LOSE_OBSOLETE                  = 0x240,
    CMSG_TAXICLEARNODE                              = 0x241,
    CMSG_TAXIENABLENODE                             = 0x242,
    CMSG_ITEM_TEXT_QUERY                            = 0x243,
    SMSG_ITEM_TEXT_QUERY_RESPONSE                   = 0x244,
    CMSG_MAIL_TAKE_MONEY                            = 0x245,
    CMSG_MAIL_TAKE_ITEM                             = 0x246,
    CMSG_MAIL_MARK_AS_READ                          = 0x247,
    CMSG_MAIL_RETURN_TO_SENDER                      = 0x248,
    CMSG_MAIL_DELETE                                = 0x249,
    CMSG_MAIL_CREATE_TEXT_ITEM                      = 0x24A,
    SMSG_SPELLLOGMISS                               = 0x24B,
    SMSG_SPELLLOGEXECUTE                            = 0x24C,
    SMSG_DEBUGAURAPROC                              = 0x24D,
    SMSG_PERIODICAURALOG                            = 0x24E,
    SMSG_SPELLDAMAGESHIELD                          = 0x24F,
    SMSG_SPELLNONMELEEDAMAGELOG                     = 0x250,
    CMSG_LEARN_TALENT                               = 0x251,
    SMSG_RESURRECT_FAILED                           = 0x252,
    CMSG_TOGGLE_PVP                                 = 0x253,
    SMSG_ZONE_UNDER_ATTACK                          = 0x254,
    MSG_AUCTION_HELLO                               = 0x255,
    CMSG_AUCTION_SELL_ITEM                          = 0x256,
    CMSG_AUCTION_REMOVE_ITEM                        = 0x257,
    CMSG_AUCTION_LIST_ITEMS                         = 0x258,
    CMSG_AUCTION_LIST_OWNER_ITEMS                   = 0x259,
    CMSG_AUCTION_PLACE_BID                          = 0x25A,
    SMSG_AUCTION_COMMAND_RESULT                     = 0x25B,
    SMSG_AUCTION_LIST_RESULT                        = 0x25C,
    SMSG_AUCTION_OWNER_LIST_RESULT                  = 0x25D,
    SMSG_AUCTION_BIDDER_NOTIFICATION                = 0x25E,
    SMSG_AUCTION_OWNER_NOTIFICATION                 = 0x25F,
    SMSG_PROCRESIST                                 = 0x260,
    SMSG_STANDSTATE_CHANGE_FAILURE_OBSOLETE         = 0x261,
    SMSG_DISPEL_FAILED                              = 0x262,
    SMSG_SPELLORDAMAGE_IMMUNE                       = 0x263,
    CMSG_AUCTION_LIST_BIDDER_ITEMS                  = 0x264,
    SMSG_AUCTION_BIDDER_LIST_RESULT                 = 0x265,
    SMSG_SET_FLAT_SPELL_MODIFIER                    = 0x266,
    SMSG_SET_PCT_SPELL_MODIFIER                     = 0x267,
    CMSG_SET_AMMO                                   = 0x268,
    SMSG_CORPSE_RECLAIM_DELAY                       = 0x269,
    CMSG_SET_ACTIVE_MOVER                           = 0x26A,
    CMSG_PET_CANCEL_AURA                            = 0x26B,
    CMSG_PLAYER_AI_CHEAT                            = 0x26C,
    CMSG_CANCEL_AUTO_REPEAT_SPELL                   = 0x26D,
    MSG_GM_ACCOUNT_ONLINE                           = 0x26E,
    MSG_LIST_STABLED_PETS                           = 0x26F,
    CMSG_STABLE_PET                                 = 0x270,
    CMSG_UNSTABLE_PET                               = 0x271,
    CMSG_BUY_STABLE_SLOT                            = 0x272,
    SMSG_STABLE_RESULT                              = 0x273,
    CMSG_STABLE_REVIVE_PET                          = 0x274,
    CMSG_STABLE_SWAP_PET                            = 0x275,
    MSG_QUEST_PUSH_RESULT                           = 0x276,
    SMSG_PLAY_MUSIC                                 = 0x277,
    SMSG_PLAY_OBJECT_SOUND                          = 0x278,
    CMSG_REQUEST_PET_INFO                           = 0x279,
    CMSG_FAR_SIGHT                                  = 0x27A,
    SMSG_SPELLDISPELLOG                             = 0x27B,
    SMSG_DAMAGE_CALC_LOG                            = 0x27C,
    CMSG_ENABLE_DAMAGE_LOG                          = 0x27D,
    CMSG_GROUP_CHANGE_SUB_GROUP                     = 0x27E,
    CMSG_REQUEST_PARTY_MEMBER_STATS                 = 0x27F,
    CMSG_GROUP_SWAP_SUB_GROUP                       = 0x280,
    CMSG_RESET_FACTION_CHEAT                        = 0x281,
    CMSG_AUTOSTORE_BANK_ITEM                        = 0x282,
    CMSG_AUTOBANK_ITEM                              = 0x283,
    MSG_QUERY_NEXT_MAIL_TIME                        = 0x284,
    SMSG_RECEIVED_MAIL                              = 0x285,
    SMSG_RAID_GROUP_ONLY                            = 0x286,
    CMSG_SET_DURABILITY_CHEAT                       = 0x287,
    CMSG_SET_PVP_RANK_CHEAT                         = 0x288,
    CMSG_ADD_PVP_MEDAL_CHEAT                        = 0x289,
    CMSG_DEL_PVP_MEDAL_CHEAT                        = 0x28A,
    CMSG_SET_PVP_TITLE                              = 0x28B,
    SMSG_PVP_CREDIT                                 = 0x28C,
    SMSG_AUCTION_REMOVED_NOTIFICATION               = 0x28D,
    CMSG_GROUP_RAID_CONVERT                         = 0x28E,
    CMSG_GROUP_ASSISTANT_LEADER                     = 0x28F,
    CMSG_BUYBACK_ITEM                               = 0x290,
    SMSG_SERVER_MESSAGE                             = 0x291,
    CMSG_MEETINGSTONE_JOIN                          = 0x292,
    CMSG_MEETINGSTONE_LEAVE                         = 0x293,
    CMSG_MEETINGSTONE_CHEAT                         = 0x294,
    SMSG_MEETINGSTONE_SETQUEUE                      = 0x295,
    CMSG_MEETINGSTONE_INFO                          = 0x296,
    SMSG_MEETINGSTONE_COMPLETE                      = 0x297,
    SMSG_MEETINGSTONE_IN_PROGRESS                   = 0x298,
    SMSG_MEETINGSTONE_MEMBER_ADDED                  = 0x299,
    CMSG_GMTICKETSYSTEM_TOGGLE                      = 0x29A,
    CMSG_CANCEL_GROWTH_AURA                         = 0x29B,
    SMSG_CANCEL_AUTO_REPEAT                         = 0x29C,
    SMSG_STANDSTATE_UPDATE                          = 0x29D,
    SMSG_LOOT_ALL_PASSED                            = 0x29E,
    SMSG_LOOT_ROLL_WON                              = 0x29F,
    CMSG_LOOT_ROLL                                  = 0x2A0,
    SMSG_LOOT_START_ROLL                            = 0x2A1,
    SMSG_LOOT_ROLL                                  = 0x2A2,
    CMSG_LOOT_MASTER_GIVE                           = 0x2A3,
    SMSG_LOOT_MASTER_LIST                           = 0x2A4,
    SMSG_SET_FORCED_REACTIONS                       = 0x2A5,
    SMSG_SPELL_FAILED_OTHER                         = 0x2A6,
    SMSG_GAMEOBJECT_RESET_STATE                     = 0x2A7,
    CMSG_REPAIR_ITEM                                = 0x2A8,
    SMSG_CHAT_PLAYER_NOT_FOUND                      = 0x2A9,
    MSG_TALENT_WIPE_CONFIRM                         = 0x2AA,
    SMSG_SUMMON_REQUEST                             = 0x2AB,
    CMSG_SUMMON_RESPONSE                            = 0x2AC,
    MSG_MOVE_TOGGLE_GRAVITY_CHEAT                   = 0x2AD,
    SMSG_MONSTER_MOVE_TRANSPORT                     = 0x2AE,
    SMSG_PET_BROKEN                                 = 0x2AF,
    MSG_MOVE_FEATHER_FALL                           = 0x2B0,
    MSG_MOVE_WATER_WALK                             = 0x2B1,
    CMSG_SERVER_BROADCAST                           = 0x2B2,
    CMSG_SELF_RES                                   = 0x2B3,
    SMSG_FEIGN_DEATH_RESISTED                       = 0x2B4,
    CMSG_RUN_SCRIPT                                 = 0x2B5,
    SMSG_SCRIPT_MESSAGE                             = 0x2B6,
    SMSG_DUEL_COUNTDOWN                             = 0x2B7,
    SMSG_AREA_TRIGGER_MESSAGE                       = 0x2B8,
    CMSG_TOGGLE_HELM                                = 0x2B9,
    CMSG_TOGGLE_CLOAK                               = 0x2BA,
    SMSG_MEETINGSTONE_JOINFAILED                    = 0x2BB,
    SMSG_PLAYER_SKINNED                             = 0x2BC,
    SMSG_DURABILITY_DAMAGE_DEATH                    = 0x2BD,
    CMSG_SET_EXPLORATION                            = 0x2BE,
    CMSG_SET_ACTIONBAR_TOGGLES                      = 0x2BF,
    UMSG_DELETE_GUILD_CHARTER                       = 0x2C0,
    MSG_PETITION_RENAME                             = 0x2C1,
    SMSG_INIT_WORLD_STATES                          = 0x2C2,
    SMSG_UPDATE_WORLD_STATE                         = 0x2C3,
    CMSG_ITEM_NAME_QUERY                            = 0x2C4,
    SMSG_ITEM_NAME_QUERY_RESPONSE                   = 0x2C5,
    SMSG_PET_ACTION_FEEDBACK                        = 0x2C6,
    CMSG_CHAR_RENAME                                = 0x2C7,
    SMSG_CHAR_RENAME                                = 0x2C8,
    CMSG_MOVE_SPLINE_DONE                           = 0x2C9,
    CMSG_MOVE_FALL_RESET                            = 0x2CA,
    SMSG_INSTANCE_SAVE_CREATED                      = 0x2CB,
    SMSG_RAID_INSTANCE_INFO                         = 0x2CC,
    CMSG_REQUEST_RAID_INFO                          = 0x2CD,
    CMSG_MOVE_TIME_SKIPPED                          = 0x2CE,
    CMSG_MOVE_FEATHER_FALL_ACK                      = 0x2CF,
    CMSG_MOVE_WATER_WALK_ACK                        = 0x2D0,
    CMSG_MOVE_NOT_ACTIVE_MOVER                      = 0x2D1,
    SMSG_PLAY_SOUND                                 = 0x2D2,
    CMSG_BATTLEFIELD_STATUS                         = 0x2D3,
    SMSG_BATTLEFIELD_STATUS                         = 0x2D4,
    CMSG_BATTLEFIELD_PORT                           = 0x2D5,
    MSG_INSPECT_HONOR_STATS                         = 0x2D6,
    CMSG_BATTLEMASTER_HELLO                         = 0x2D7,
    CMSG_MOVE_START_SWIM_CHEAT                      = 0x2D8,
    CMSG_MOVE_STOP_SWIM_CHEAT                       = 0x2D9,
    SMSG_FORCE_WALK_SPEED_CHANGE                    = 0x2DA,
    CMSG_FORCE_WALK_SPEED_CHANGE_ACK                = 0x2DB,
    SMSG_FORCE_SWIM_BACK_SPEED_CHANGE               = 0x2DC,
    CMSG_FORCE_SWIM_BACK_SPEED_CHANGE_ACK           = 0x2DD,
    SMSG_FORCE_TURN_RATE_CHANGE                     = 0x2DE,
    CMSG_FORCE_TURN_RATE_CHANGE_ACK                 = 0x2DF,
    MSG_PVP_LOG_DATA                                = 0x2E0,
    CMSG_LEAVE_BATTLEFIELD                          = 0x2E1,
    CMSG_AREA_SPIRIT_HEALER_QUERY                   = 0x2E2,
    CMSG_AREA_SPIRIT_HEALER_QUEUE                   = 0x2E3,
    SMSG_AREA_SPIRIT_HEALER_TIME                    = 0x2E4,
    CMSG_GM_UNTEACH                                 = 0x2E5,
    SMSG_WARDEN_DATA                                = 0x2E6,
    CMSG_WARDEN_DATA                                = 0x2E7,
    SMSG_GROUP_JOINED_BATTLEGROUND                  = 0x2E8,
    MSG_BATTLEGROUND_PLAYER_POSITIONS               = 0x2E9,
    CMSG_PET_STOP_ATTACK                            = 0x2EA,
    SMSG_BINDER_CONFIRM                             = 0x2EB,
    SMSG_BATTLEGROUND_PLAYER_JOINED                 = 0x2EC,
    SMSG_BATTLEGROUND_PLAYER_LEFT                   = 0x2ED,
    CMSG_BATTLEMASTER_JOIN                          = 0x2EE,
    SMSG_ADDON_INFO                                 = 0x2EF,
    CMSG_PET_UNLEARN                                = 0x2F0,
    SMSG_PET_UNLEARN_CONFIRM                        = 0x2F1,
    SMSG_PARTY_MEMBER_STATS_FULL                    = 0x2F2,
    CMSG_PET_SPELL_AUTOCAST                         = 0x2F3,
    SMSG_WEATHER                                    = 0x2F4,
    SMSG_PLAY_TIME_WARNING                          = 0x2F5,
    SMSG_MINIGAME_SETUP                             = 0x2F6,
    SMSG_MINIGAME_STATE                             = 0x2F7,
    CMSG_MINIGAME_MOVE                              = 0x2F8,
    SMSG_MINIGAME_MOVE_FAILED                       = 0x2F9,
    SMSG_RAID_INSTANCE_MESSAGE                      = 0x2FA,
    SMSG_COMPRESSED_MOVES                           = 0x2FB,
    CMSG_GUILD_INFO_TEXT                            = 0x2FC,
    SMSG_CHAT_RESTRICTED                            = 0x2FD,
    SMSG_SPLINE_SET_RUN_SPEED                       = 0x2FE,
    SMSG_SPLINE_SET_RUN_BACK_SPEED                  = 0x2FF,
    SMSG_SPLINE_SET_SWIM_SPEED                      = 0x300,
    SMSG_SPLINE_SET_WALK_SPEED                      = 0x301,
    SMSG_SPLINE_SET_SWIM_BACK_SPEED                 = 0x302,
    SMSG_SPLINE_SET_TURN_RATE                       = 0x303,
    SMSG_SPLINE_MOVE_UNROOT                         = 0x304,
    SMSG_SPLINE_MOVE_FEATHER_FALL                   = 0x305,
    SMSG_SPLINE_MOVE_NORMAL_FALL                    = 0x306,
    SMSG_SPLINE_MOVE_SET_HOVER                      = 0x307,
    SMSG_SPLINE_MOVE_UNSET_HOVER                    = 0x308,
    SMSG_SPLINE_MOVE_WATER_WALK                     = 0x309,
    SMSG_SPLINE_MOVE_LAND_WALK                      = 0x30A,
    SMSG_SPLINE_MOVE_START_SWIM                     = 0x30B,
    SMSG_SPLINE_MOVE_STOP_SWIM                      = 0x30C,
    SMSG_SPLINE_MOVE_SET_RUN_MODE                   = 0x30D,
    SMSG_SPLINE_MOVE_SET_WALK_MODE                  = 0x30E,
    CMSG_GM_NUKE_ACCOUNT                            = 0x30F,
    MSG_GM_DESTROY_CORPSE                           = 0x310,
    CMSG_GM_DESTROY_ONLINE_CORPSE                   = 0x311,
    CMSG_ACTIVATETAXIEXPRESS                        = 0x312,
    SMSG_SET_FACTION_ATWAR                          = 0x313,
    SMSG_GAMETIMEBIAS_SET                           = 0x314,
    CMSG_DEBUG_ACTIONS_START                        = 0x315,
    CMSG_DEBUG_ACTIONS_STOP                         = 0x316,
    CMSG_SET_FACTION_INACTIVE                       = 0x317,
    CMSG_SET_WATCHED_FACTION                        = 0x318,
    MSG_MOVE_TIME_SKIPPED                           = 0x319,
    SMSG_SPLINE_MOVE_ROOT                           = 0x31A,
    CMSG_SET_EXPLORATION_ALL                        = 0x31B,
    SMSG_INVALIDATE_PLAYER                          = 0x31C,
    CMSG_RESET_INSTANCES                            = 0x31D,
    SMSG_INSTANCE_RESET                             = 0x31E,
    SMSG_INSTANCE_RESET_FAILED                      = 0x31F,
    SMSG_UPDATE_LAST_INSTANCE                       = 0x320,
    MSG_RAID_TARGET_UPDATE                          = 0x321,
    MSG_RAID_READY_CHECK                            = 0x322,
    CMSG_LUA_USAGE                                  = 0x323,
    SMSG_PET_ACTION_SOUND                           = 0x324,
    SMSG_PET_DISMISS_SOUND                          = 0x325,
    SMSG_GHOSTEE_GONE                               = 0x326,
    CMSG_GM_UPDATE_TICKET_STATUS                    = 0x327,
    SMSG_GM_TICKET_STATUS_UPDATE                    = 0x328,
    CMSG_GMSURVEY_SUBMIT                            = 0x32A,
    SMSG_UPDATE_INSTANCE_OWNERSHIP                  = 0x32B,
    CMSG_IGNORE_KNOCKBACK_CHEAT                     = 0x32C,
    SMSG_CHAT_PLAYER_AMBIGUOUS                      = 0x32D,
    MSG_DELAY_GHOST_TELEPORT                        = 0x32E,
    SMSG_SPELLINSTAKILLLOG                          = 0x32F,
    SMSG_SPELL_UPDATE_CHAIN_TARGETS                 = 0x330,
    CMSG_CHAT_FILTERED                              = 0x331,
    SMSG_EXPECTED_SPAM_RECORDS                      = 0x332,
    SMSG_SPELLSTEALLOG                              = 0x333,
    CMSG_LOTTERY_QUERY_OBSOLETE                     = 0x334,
    SMSG_LOTTERY_QUERY_RESULT_OBSOLETE              = 0x335,
    CMSG_BUY_LOTTERY_TICKET_OBSOLETE                = 0x336,
    SMSG_LOTTERY_RESULT_OBSOLETE                    = 0x337,
    SMSG_CHARACTER_PROFILE                          = 0x338,
    SMSG_CHARACTER_PROFILE_REALM_CONNECTED          = 0x339,
    SMSG_DEFENSE_MESSAGE                            = 0x33A,
    MSG_GM_RESETINSTANCELIMIT                       = 0x33C,
    SMSG_MOTD                                       = 0x33D,
    SMSG_MOVE_SET_FLIGHT                            = 0x33E,
    SMSG_MOVE_UNSET_FLIGHT                          = 0x33F,
    CMSG_MOVE_FLIGHT_ACK                            = 0x340,
    MSG_MOVE_START_SWIM_CHEAT                       = 0x341,
    MSG_MOVE_STOP_SWIM_CHEAT                        = 0x342,
    CMSG_CANCEL_MOUNT_AURA                          = 0x375,
    CMSG_CANCEL_TEMP_ENCHANTMENT                    = 0x379,
    CMSG_MAELSTROM_INVALIDATE_CACHE                 = 0x387,
    CMSG_SET_TAXI_BENCHMARK_MODE                    = 0x389,
    CMSG_MOVE_CHNG_TRANSPORT                        = 0x38D,
    MSG_PARTY_ASSIGNMENT                            = 0x38E,
    SMSG_OFFER_PETITION_ERROR                       = 0x38F,
    SMSG_RESET_FAILED_NOTIFY                        = 0x396,
    SMSG_REAL_GROUP_UPDATE                          = 0x397,
    SMSG_INIT_EXTRA_AURA_INFO                       = 0x3A3,
    SMSG_SET_EXTRA_AURA_INFO                        = 0x3A4,
    SMSG_SET_EXTRA_AURA_INFO_NEED_UPDATE            = 0x3A5,
    SMSG_SPELL_CHANCE_PROC_LOG                      = 0x3AA,
    CMSG_MOVE_SET_RUN_SPEED                         = 0x3AB,
    SMSG_DISMOUNT                                   = 0x3AC,
    MSG_RAID_READY_CHECK_CONFIRM                    = 0x3AE,
    SMSG_CLEAR_TARGET                               = 0x3BE,
    CMSG_BOT_DETECTED                               = 0x3BF,
    SMSG_KICK_REASON                                = 0x3C4,
    MSG_RAID_READY_CHECK_FINISHED                   = 0x3C5,
    CMSG_TARGET_CAST                                = 0x3CF,
    CMSG_TARGET_SCRIPT_CAST                         = 0x3D0,
    CMSG_CHANNEL_DISPLAY_LIST                       = 0x3D1,
    CMSG_GET_CHANNEL_MEMBER_COUNT                   = 0x3D3,
    SMSG_CHANNEL_MEMBER_COUNT                       = 0x3D4,
    CMSG_DEBUG_LIST_TARGETS                         = 0x3D7,
    SMSG_DEBUG_LIST_TARGETS                         = 0x3D8,
    CMSG_PARTY_SILENCE                              = 0x3DC,
    CMSG_PARTY_UNSILENCE                            = 0x3DD,
    MSG_NOTIFY_PARTY_SQUELCH                        = 0x3DE,
    SMSG_COMSAT_RECONNECT_TRY                       = 0x3DF,
    SMSG_COMSAT_DISCONNECT                          = 0x3E0,
    SMSG_COMSAT_CONNECT_FAIL                        = 0x3E1,
    CMSG_SET_CHANNEL_WATCH                          = 0x3EE,
    SMSG_USERLIST_ADD                               = 0x3EF,
    SMSG_USERLIST_REMOVE                            = 0x3F0,
    SMSG_USERLIST_UPDATE                            = 0x3F1,
    CMSG_CLEAR_CHANNEL_WATCH                        = 0x3F2,
    SMSG_GOGOGO_OBSOLETE                            = 0x3F4,
    SMSG_ECHO_PARTY_SQUELCH                         = 0x3F5,
    CMSG_SPELLCLICK                                 = 0x3F7,
    SMSG_LOOT_LIST                                  = 0x3F8,
    MSG_GUILD_PERMISSIONS                           = 0x3FC,
    MSG_GUILD_EVENT_LOG_QUERY                       = 0x3FE,
    CMSG_MAELSTROM_RENAME_GUILD                     = 0x3FF,
    CMSG_GET_MIRRORIMAGE_DATA                       = 0x400,
    SMSG_MIRRORIMAGE_DATA                           = 0x401,
    SMSG_FORCE_DISPLAY_UPDATE                       = 0x402,
    SMSG_SPELL_CHANCE_RESIST_PUSHBACK               = 0x403,
    CMSG_IGNORE_DIMINISHING_RETURNS_CHEAT           = 0x404,
    SMSG_IGNORE_DIMINISHING_RETURNS_CHEAT           = 0x405,
    CMSG_KEEP_ALIVE                                 = 0x406,
    SMSG_RAID_READY_CHECK_ERROR                     = 0x407,
    CMSG_OPT_OUT_OF_LOOT                            = 0x408,
    CMSG_SET_GRANTABLE_LEVELS                       = 0x40B,
    CMSG_GRANT_LEVEL                                = 0x40C,
    CMSG_DECLINE_CHANNEL_INVITE                     = 0x40F,
    CMSG_GROUPACTION_THROTTLED                      = 0x410,
    SMSG_OVERRIDE_LIGHT                             = 0x411,
    SMSG_TOTEM_CREATED                              = 0x412,
    CMSG_TOTEM_DESTROYED                            = 0x413,
    CMSG_EXPIRE_RAID_INSTANCE                       = 0x414,
    CMSG_NO_SPELL_VARIANCE                          = 0x415,
    CMSG_QUESTGIVER_STATUS_MULTIPLE_QUERY           = 0x416,
    SMSG_QUESTGIVER_STATUS_MULTIPLE                 = 0x417,
    CMSG_QUERY_SERVER_BUCK_DATA                     = 0x41A,
    CMSG_CLEAR_SERVER_BUCK_DATA                     = 0x41B,
    SMSG_SERVER_BUCK_DATA                           = 0x41C,
    SMSG_SEND_UNLEARN_SPELLS                        = 0x41D,
    SMSG_PROPOSE_LEVEL_GRANT                        = 0x41E,
    CMSG_ACCEPT_LEVEL_GRANT                         = 0x41F,
    SMSG_REFER_A_FRIEND_FAILURE                     = 0x420,
    SMSG_SUMMON_CANCEL                              = 0x423
} world_packets;

static const value_string world_packet_strings[] = {
    { MSG_NULL_ACTION, "MSG_NULL_ACTION" },
    { CMSG_BOOTME, "CMSG_BOOTME" },
    { CMSG_DBLOOKUP, "CMSG_DBLOOKUP" },
    { SMSG_DBLOOKUP, "SMSG_DBLOOKUP" },
    { CMSG_QUERY_OBJECT_POSITION, "CMSG_QUERY_OBJECT_POSITION" },
    { SMSG_QUERY_OBJECT_POSITION, "SMSG_QUERY_OBJECT_POSITION" },
    { CMSG_QUERY_OBJECT_ROTATION, "CMSG_QUERY_OBJECT_ROTATION" },
    { SMSG_QUERY_OBJECT_ROTATION, "SMSG_QUERY_OBJECT_ROTATION" },
    { CMSG_WORLD_TELEPORT, "CMSG_WORLD_TELEPORT" },
    { CMSG_TELEPORT_TO_UNIT, "CMSG_TELEPORT_TO_UNIT" },
    { CMSG_ZONE_MAP, "CMSG_ZONE_MAP" },
    { SMSG_ZONE_MAP, "SMSG_ZONE_MAP" },
    { CMSG_DEBUG_CHANGECELLZONE, "CMSG_DEBUG_CHANGECELLZONE" },
    { CMSG_EMBLAZON_TABARD_OBSOLETE, "CMSG_EMBLAZON_TABARD_OBSOLETE" },
    { CMSG_UNEMBLAZON_TABARD_OBSOLETE, "CMSG_UNEMBLAZON_TABARD_OBSOLETE" },
    { CMSG_RECHARGE, "CMSG_RECHARGE" },
    { CMSG_LEARN_SPELL, "CMSG_LEARN_SPELL" },
    { CMSG_CREATEMONSTER, "CMSG_CREATEMONSTER" },
    { CMSG_DESTROYMONSTER, "CMSG_DESTROYMONSTER" },
    { CMSG_CREATEITEM, "CMSG_CREATEITEM" },
    { CMSG_CREATEGAMEOBJECT, "CMSG_CREATEGAMEOBJECT" },
    { SMSG_CHECK_FOR_BOTS, "SMSG_CHECK_FOR_BOTS" },
    { CMSG_MAKEMONSTERATTACKGUID, "CMSG_MAKEMONSTERATTACKGUID" },
    { CMSG_BOT_DETECTED2, "CMSG_BOT_DETECTED2" },
    { CMSG_FORCEACTION, "CMSG_FORCEACTION" },
    { CMSG_FORCEACTIONONOTHER, "CMSG_FORCEACTIONONOTHER" },
    { CMSG_FORCEACTIONSHOW, "CMSG_FORCEACTIONSHOW" },
    { SMSG_FORCEACTIONSHOW, "SMSG_FORCEACTIONSHOW" },
    { CMSG_PETGODMODE, "CMSG_PETGODMODE" },
    { SMSG_PETGODMODE, "SMSG_PETGODMODE" },
    { SMSG_DEBUGINFOSPELLMISS_OBSOLETE, "SMSG_DEBUGINFOSPELLMISS_OBSOLETE" },
    { CMSG_WEATHER_SPEED_CHEAT, "CMSG_WEATHER_SPEED_CHEAT" },
    { CMSG_UNDRESSPLAYER, "CMSG_UNDRESSPLAYER" },
    { CMSG_BEASTMASTER, "CMSG_BEASTMASTER" },
    { CMSG_GODMODE, "CMSG_GODMODE" },
    { SMSG_GODMODE, "SMSG_GODMODE" },
    { CMSG_CHEAT_SETMONEY, "CMSG_CHEAT_SETMONEY" },
    { CMSG_LEVEL_CHEAT, "CMSG_LEVEL_CHEAT" },
    { CMSG_PET_LEVEL_CHEAT, "CMSG_PET_LEVEL_CHEAT" },
    { CMSG_SET_WORLDSTATE, "CMSG_SET_WORLDSTATE" },
    { CMSG_COOLDOWN_CHEAT, "CMSG_COOLDOWN_CHEAT" },
    { CMSG_USE_SKILL_CHEAT, "CMSG_USE_SKILL_CHEAT" },
    { CMSG_FLAG_QUEST, "CMSG_FLAG_QUEST" },
    { CMSG_FLAG_QUEST_FINISH, "CMSG_FLAG_QUEST_FINISH" },
    { CMSG_CLEAR_QUEST, "CMSG_CLEAR_QUEST" },
    { CMSG_SEND_EVENT, "CMSG_SEND_EVENT" },
    { CMSG_DEBUG_AISTATE, "CMSG_DEBUG_AISTATE" },
    { SMSG_DEBUG_AISTATE, "SMSG_DEBUG_AISTATE" },
    { CMSG_DISABLE_PVP_CHEAT, "CMSG_DISABLE_PVP_CHEAT" },
    { CMSG_ADVANCE_SPAWN_TIME, "CMSG_ADVANCE_SPAWN_TIME" },
    { CMSG_PVP_PORT_OBSOLETE, "CMSG_PVP_PORT_OBSOLETE" },
    { CMSG_AUTH_SRP6_BEGIN, "CMSG_AUTH_SRP6_BEGIN" },
    { CMSG_AUTH_SRP6_PROOF, "CMSG_AUTH_SRP6_PROOF" },
    { CMSG_AUTH_SRP6_RECODE, "CMSG_AUTH_SRP6_RECODE" },
    { CMSG_CHAR_CREATE, "CMSG_CHAR_CREATE" },
    { CMSG_CHAR_ENUM, "CMSG_CHAR_ENUM" },
    { CMSG_CHAR_DELETE, "CMSG_CHAR_DELETE" },
    { SMSG_AUTH_SRP6_RESPONSE, "SMSG_AUTH_SRP6_RESPONSE" },
    { SMSG_CHAR_CREATE, "SMSG_CHAR_CREATE" },
    { SMSG_CHAR_ENUM, "SMSG_CHAR_ENUM" },
    { SMSG_CHAR_DELETE, "SMSG_CHAR_DELETE" },
    { CMSG_PLAYER_LOGIN, "CMSG_PLAYER_LOGIN" },
    { SMSG_NEW_WORLD, "SMSG_NEW_WORLD" },
    { SMSG_TRANSFER_PENDING, "SMSG_TRANSFER_PENDING" },
    { SMSG_TRANSFER_ABORTED, "SMSG_TRANSFER_ABORTED" },
    { SMSG_CHARACTER_LOGIN_FAILED, "SMSG_CHARACTER_LOGIN_FAILED" },
    { SMSG_LOGIN_SETTIMESPEED, "SMSG_LOGIN_SETTIMESPEED" },
    { SMSG_GAMETIME_UPDATE, "SMSG_GAMETIME_UPDATE" },
    { CMSG_GAMETIME_SET, "CMSG_GAMETIME_SET" },
    { SMSG_GAMETIME_SET, "SMSG_GAMETIME_SET" },
    { CMSG_GAMESPEED_SET, "CMSG_GAMESPEED_SET" },
    { SMSG_GAMESPEED_SET, "SMSG_GAMESPEED_SET" },
    { CMSG_SERVERTIME, "CMSG_SERVERTIME" },
    { SMSG_SERVERTIME, "SMSG_SERVERTIME" },
    { CMSG_PLAYER_LOGOUT, "CMSG_PLAYER_LOGOUT" },
    { CMSG_LOGOUT_REQUEST, "CMSG_LOGOUT_REQUEST" },
    { SMSG_LOGOUT_RESPONSE, "SMSG_LOGOUT_RESPONSE" },
    { SMSG_LOGOUT_COMPLETE, "SMSG_LOGOUT_COMPLETE" },
    { CMSG_LOGOUT_CANCEL, "CMSG_LOGOUT_CANCEL" },
    { SMSG_LOGOUT_CANCEL_ACK, "SMSG_LOGOUT_CANCEL_ACK" },
    { CMSG_NAME_QUERY, "CMSG_NAME_QUERY" },
    { SMSG_NAME_QUERY_RESPONSE, "SMSG_NAME_QUERY_RESPONSE" },
    { CMSG_PET_NAME_QUERY, "CMSG_PET_NAME_QUERY" },
    { SMSG_PET_NAME_QUERY_RESPONSE, "SMSG_PET_NAME_QUERY_RESPONSE" },
    { CMSG_GUILD_QUERY, "CMSG_GUILD_QUERY" },
    { SMSG_GUILD_QUERY_RESPONSE, "SMSG_GUILD_QUERY_RESPONSE" },
    { CMSG_ITEM_QUERY_SINGLE, "CMSG_ITEM_QUERY_SINGLE" },
    { CMSG_ITEM_QUERY_MULTIPLE, "CMSG_ITEM_QUERY_MULTIPLE" },
    { SMSG_ITEM_QUERY_SINGLE_RESPONSE, "SMSG_ITEM_QUERY_SINGLE_RESPONSE" },
    { SMSG_ITEM_QUERY_MULTIPLE_RESPONSE, "SMSG_ITEM_QUERY_MULTIPLE_RESPONSE" },
    { CMSG_PAGE_TEXT_QUERY, "CMSG_PAGE_TEXT_QUERY" },
    { SMSG_PAGE_TEXT_QUERY_RESPONSE, "SMSG_PAGE_TEXT_QUERY_RESPONSE" },
    { CMSG_QUEST_QUERY, "CMSG_QUEST_QUERY" },
    { SMSG_QUEST_QUERY_RESPONSE, "SMSG_QUEST_QUERY_RESPONSE" },
    { CMSG_GAMEOBJECT_QUERY, "CMSG_GAMEOBJECT_QUERY" },
    { SMSG_GAMEOBJECT_QUERY_RESPONSE, "SMSG_GAMEOBJECT_QUERY_RESPONSE" },
    { CMSG_CREATURE_QUERY, "CMSG_CREATURE_QUERY" },
    { SMSG_CREATURE_QUERY_RESPONSE, "SMSG_CREATURE_QUERY_RESPONSE" },
    { CMSG_WHO, "CMSG_WHO" },
    { SMSG_WHO, "SMSG_WHO" },
    { CMSG_WHOIS, "CMSG_WHOIS" },
    { SMSG_WHOIS, "SMSG_WHOIS" },
    { CMSG_FRIEND_LIST, "CMSG_FRIEND_LIST" },
    { SMSG_FRIEND_LIST, "SMSG_FRIEND_LIST" },
    { SMSG_FRIEND_STATUS, "SMSG_FRIEND_STATUS" },
    { CMSG_ADD_FRIEND, "CMSG_ADD_FRIEND" },
    { CMSG_DEL_FRIEND, "CMSG_DEL_FRIEND" },
    { SMSG_IGNORE_LIST, "SMSG_IGNORE_LIST" },
    { CMSG_ADD_IGNORE, "CMSG_ADD_IGNORE" },
    { CMSG_DEL_IGNORE, "CMSG_DEL_IGNORE" },
    { CMSG_GROUP_INVITE, "CMSG_GROUP_INVITE" },
    { SMSG_GROUP_INVITE, "SMSG_GROUP_INVITE" },
    { CMSG_GROUP_CANCEL, "CMSG_GROUP_CANCEL" },
    { SMSG_GROUP_CANCEL, "SMSG_GROUP_CANCEL" },
    { CMSG_GROUP_ACCEPT, "CMSG_GROUP_ACCEPT" },
    { CMSG_GROUP_DECLINE, "CMSG_GROUP_DECLINE" },
    { SMSG_GROUP_DECLINE, "SMSG_GROUP_DECLINE" },
    { CMSG_GROUP_UNINVITE, "CMSG_GROUP_UNINVITE" },
    { CMSG_GROUP_UNINVITE_GUID, "CMSG_GROUP_UNINVITE_GUID" },
    { SMSG_GROUP_UNINVITE, "SMSG_GROUP_UNINVITE" },
    { CMSG_GROUP_SET_LEADER, "CMSG_GROUP_SET_LEADER" },
    { SMSG_GROUP_SET_LEADER, "SMSG_GROUP_SET_LEADER" },
    { CMSG_LOOT_METHOD, "CMSG_LOOT_METHOD" },
    { CMSG_GROUP_DISBAND, "CMSG_GROUP_DISBAND" },
    { SMSG_GROUP_DESTROYED, "SMSG_GROUP_DESTROYED" },
    { SMSG_GROUP_LIST, "SMSG_GROUP_LIST" },
    { SMSG_PARTY_MEMBER_STATS, "SMSG_PARTY_MEMBER_STATS" },
    { SMSG_PARTY_COMMAND_RESULT, "SMSG_PARTY_COMMAND_RESULT" },
    { UMSG_UPDATE_GROUP_MEMBERS, "UMSG_UPDATE_GROUP_MEMBERS" },
    { CMSG_GUILD_CREATE, "CMSG_GUILD_CREATE" },
    { CMSG_GUILD_INVITE, "CMSG_GUILD_INVITE" },
    { SMSG_GUILD_INVITE, "SMSG_GUILD_INVITE" },
    { CMSG_GUILD_ACCEPT, "CMSG_GUILD_ACCEPT" },
    { CMSG_GUILD_DECLINE, "CMSG_GUILD_DECLINE" },
    { SMSG_GUILD_DECLINE, "SMSG_GUILD_DECLINE" },
    { CMSG_GUILD_INFO, "CMSG_GUILD_INFO" },
    { SMSG_GUILD_INFO, "SMSG_GUILD_INFO" },
    { CMSG_GUILD_ROSTER, "CMSG_GUILD_ROSTER" },
    { SMSG_GUILD_ROSTER, "SMSG_GUILD_ROSTER" },
    { CMSG_GUILD_PROMOTE, "CMSG_GUILD_PROMOTE" },
    { CMSG_GUILD_DEMOTE, "CMSG_GUILD_DEMOTE" },
    { CMSG_GUILD_LEAVE, "CMSG_GUILD_LEAVE" },
    { CMSG_GUILD_REMOVE, "CMSG_GUILD_REMOVE" },
    { CMSG_GUILD_DISBAND, "CMSG_GUILD_DISBAND" },
    { CMSG_GUILD_LEADER, "CMSG_GUILD_LEADER" },
    { CMSG_GUILD_MOTD, "CMSG_GUILD_MOTD" },
    { SMSG_GUILD_EVENT, "SMSG_GUILD_EVENT" },
    { SMSG_GUILD_COMMAND_RESULT, "SMSG_GUILD_COMMAND_RESULT" },
    { UMSG_UPDATE_GUILD, "UMSG_UPDATE_GUILD" },
    { CMSG_MESSAGECHAT, "CMSG_MESSAGECHAT" },
    { SMSG_MESSAGECHAT, "SMSG_MESSAGECHAT" },
    { CMSG_JOIN_CHANNEL, "CMSG_JOIN_CHANNEL" },
    { CMSG_LEAVE_CHANNEL, "CMSG_LEAVE_CHANNEL" },
    { SMSG_CHANNEL_NOTIFY, "SMSG_CHANNEL_NOTIFY" },
    { CMSG_CHANNEL_LIST, "CMSG_CHANNEL_LIST" },
    { SMSG_CHANNEL_LIST, "SMSG_CHANNEL_LIST" },
    { CMSG_CHANNEL_PASSWORD, "CMSG_CHANNEL_PASSWORD" },
    { CMSG_CHANNEL_SET_OWNER, "CMSG_CHANNEL_SET_OWNER" },
    { CMSG_CHANNEL_OWNER, "CMSG_CHANNEL_OWNER" },
    { CMSG_CHANNEL_MODERATOR, "CMSG_CHANNEL_MODERATOR" },
    { CMSG_CHANNEL_UNMODERATOR, "CMSG_CHANNEL_UNMODERATOR" },
    { CMSG_CHANNEL_MUTE, "CMSG_CHANNEL_MUTE" },
    { CMSG_CHANNEL_UNMUTE, "CMSG_CHANNEL_UNMUTE" },
    { CMSG_CHANNEL_INVITE, "CMSG_CHANNEL_INVITE" },
    { CMSG_CHANNEL_KICK, "CMSG_CHANNEL_KICK" },
    { CMSG_CHANNEL_BAN, "CMSG_CHANNEL_BAN" },
    { CMSG_CHANNEL_UNBAN, "CMSG_CHANNEL_UNBAN" },
    { CMSG_CHANNEL_ANNOUNCEMENTS, "CMSG_CHANNEL_ANNOUNCEMENTS" },
    { CMSG_CHANNEL_MODERATE, "CMSG_CHANNEL_MODERATE" },
    { SMSG_UPDATE_OBJECT, "SMSG_UPDATE_OBJECT" },
    { SMSG_DESTROY_OBJECT, "SMSG_DESTROY_OBJECT" },
    { CMSG_USE_ITEM, "CMSG_USE_ITEM" },
    { CMSG_OPEN_ITEM, "CMSG_OPEN_ITEM" },
    { CMSG_READ_ITEM, "CMSG_READ_ITEM" },
    { SMSG_READ_ITEM_OK, "SMSG_READ_ITEM_OK" },
    { SMSG_READ_ITEM_FAILED, "SMSG_READ_ITEM_FAILED" },
    { SMSG_ITEM_COOLDOWN, "SMSG_ITEM_COOLDOWN" },
    { CMSG_GAMEOBJ_USE, "CMSG_GAMEOBJ_USE" },
    { CMSG_GAMEOBJ_CHAIR_USE_OBSOLETE, "CMSG_GAMEOBJ_CHAIR_USE_OBSOLETE" },
    { SMSG_GAMEOBJECT_CUSTOM_ANIM, "SMSG_GAMEOBJECT_CUSTOM_ANIM" },
    { CMSG_AREATRIGGER, "CMSG_AREATRIGGER" },
    { MSG_MOVE_START_FORWARD, "MSG_MOVE_START_FORWARD" },
    { MSG_MOVE_START_BACKWARD, "MSG_MOVE_START_BACKWARD" },
    { MSG_MOVE_STOP, "MSG_MOVE_STOP" },
    { MSG_MOVE_START_STRAFE_LEFT, "MSG_MOVE_START_STRAFE_LEFT" },
    { MSG_MOVE_START_STRAFE_RIGHT, "MSG_MOVE_START_STRAFE_RIGHT" },
    { MSG_MOVE_STOP_STRAFE, "MSG_MOVE_STOP_STRAFE" },
    { MSG_MOVE_JUMP, "MSG_MOVE_JUMP" },
    { MSG_MOVE_START_TURN_LEFT, "MSG_MOVE_START_TURN_LEFT" },
    { MSG_MOVE_START_TURN_RIGHT, "MSG_MOVE_START_TURN_RIGHT" },
    { MSG_MOVE_STOP_TURN, "MSG_MOVE_STOP_TURN" },
    { MSG_MOVE_START_PITCH_UP, "MSG_MOVE_START_PITCH_UP" },
    { MSG_MOVE_START_PITCH_DOWN, "MSG_MOVE_START_PITCH_DOWN" },
    { MSG_MOVE_STOP_PITCH, "MSG_MOVE_STOP_PITCH" },
    { MSG_MOVE_SET_RUN_MODE, "MSG_MOVE_SET_RUN_MODE" },
    { MSG_MOVE_SET_WALK_MODE, "MSG_MOVE_SET_WALK_MODE" },
    { MSG_MOVE_TOGGLE_LOGGING, "MSG_MOVE_TOGGLE_LOGGING" },
    { MSG_MOVE_TELEPORT, "MSG_MOVE_TELEPORT" },
    { MSG_MOVE_TELEPORT_CHEAT, "MSG_MOVE_TELEPORT_CHEAT" },
    { MSG_MOVE_TELEPORT_ACK, "MSG_MOVE_TELEPORT_ACK" },
    { MSG_MOVE_TOGGLE_FALL_LOGGING, "MSG_MOVE_TOGGLE_FALL_LOGGING" },
    { MSG_MOVE_FALL_LAND, "MSG_MOVE_FALL_LAND" },
    { MSG_MOVE_START_SWIM, "MSG_MOVE_START_SWIM" },
    { MSG_MOVE_STOP_SWIM, "MSG_MOVE_STOP_SWIM" },
    { MSG_MOVE_SET_RUN_SPEED_CHEAT, "MSG_MOVE_SET_RUN_SPEED_CHEAT" },
    { MSG_MOVE_SET_RUN_SPEED, "MSG_MOVE_SET_RUN_SPEED" },
    { MSG_MOVE_SET_RUN_BACK_SPEED_CHEAT, "MSG_MOVE_SET_RUN_BACK_SPEED_CHEAT" },
    { MSG_MOVE_SET_RUN_BACK_SPEED, "MSG_MOVE_SET_RUN_BACK_SPEED" },
    { MSG_MOVE_SET_WALK_SPEED_CHEAT, "MSG_MOVE_SET_WALK_SPEED_CHEAT" },
    { MSG_MOVE_SET_WALK_SPEED, "MSG_MOVE_SET_WALK_SPEED" },
    { MSG_MOVE_SET_SWIM_SPEED_CHEAT, "MSG_MOVE_SET_SWIM_SPEED_CHEAT" },
    { MSG_MOVE_SET_SWIM_SPEED, "MSG_MOVE_SET_SWIM_SPEED" },
    { MSG_MOVE_SET_SWIM_BACK_SPEED_CHEAT, "MSG_MOVE_SET_SWIM_BACK_SPEED_CHEAT" },
    { MSG_MOVE_SET_SWIM_BACK_SPEED, "MSG_MOVE_SET_SWIM_BACK_SPEED" },
    { MSG_MOVE_SET_ALL_SPEED_CHEAT, "MSG_MOVE_SET_ALL_SPEED_CHEAT" },
    { MSG_MOVE_SET_TURN_RATE_CHEAT, "MSG_MOVE_SET_TURN_RATE_CHEAT" },
    { MSG_MOVE_SET_TURN_RATE, "MSG_MOVE_SET_TURN_RATE" },
    { MSG_MOVE_TOGGLE_COLLISION_CHEAT, "MSG_MOVE_TOGGLE_COLLISION_CHEAT" },
    { MSG_MOVE_SET_FACING, "MSG_MOVE_SET_FACING" },
    { MSG_MOVE_SET_PITCH, "MSG_MOVE_SET_PITCH" },
    { MSG_MOVE_WORLDPORT_ACK, "MSG_MOVE_WORLDPORT_ACK" },
    { SMSG_MONSTER_MOVE, "SMSG_MONSTER_MOVE" },
    { SMSG_MOVE_WATER_WALK, "SMSG_MOVE_WATER_WALK" },
    { SMSG_MOVE_LAND_WALK, "SMSG_MOVE_LAND_WALK" },
    { MSG_MOVE_SET_RAW_POSITION_ACK, "MSG_MOVE_SET_RAW_POSITION_ACK" },
    { CMSG_MOVE_SET_RAW_POSITION, "CMSG_MOVE_SET_RAW_POSITION" },
    { SMSG_FORCE_RUN_SPEED_CHANGE, "SMSG_FORCE_RUN_SPEED_CHANGE" },
    { CMSG_FORCE_RUN_SPEED_CHANGE_ACK, "CMSG_FORCE_RUN_SPEED_CHANGE_ACK" },
    { SMSG_FORCE_RUN_BACK_SPEED_CHANGE, "SMSG_FORCE_RUN_BACK_SPEED_CHANGE" },
    { CMSG_FORCE_RUN_BACK_SPEED_CHANGE_ACK, "CMSG_FORCE_RUN_BACK_SPEED_CHANGE_ACK" },
    { SMSG_FORCE_SWIM_SPEED_CHANGE, "SMSG_FORCE_SWIM_SPEED_CHANGE" },
    { CMSG_FORCE_SWIM_SPEED_CHANGE_ACK, "CMSG_FORCE_SWIM_SPEED_CHANGE_ACK" },
    { SMSG_FORCE_MOVE_ROOT, "SMSG_FORCE_MOVE_ROOT" },
    { CMSG_FORCE_MOVE_ROOT_ACK, "CMSG_FORCE_MOVE_ROOT_ACK" },
    { SMSG_FORCE_MOVE_UNROOT, "SMSG_FORCE_MOVE_UNROOT" },
    { CMSG_FORCE_MOVE_UNROOT_ACK, "CMSG_FORCE_MOVE_UNROOT_ACK" },
    { MSG_MOVE_ROOT, "MSG_MOVE_ROOT" },
    { MSG_MOVE_UNROOT, "MSG_MOVE_UNROOT" },
    { MSG_MOVE_HEARTBEAT, "MSG_MOVE_HEARTBEAT" },
    { SMSG_MOVE_KNOCK_BACK, "SMSG_MOVE_KNOCK_BACK" },
    { CMSG_MOVE_KNOCK_BACK_ACK, "CMSG_MOVE_KNOCK_BACK_ACK" },
    { MSG_MOVE_KNOCK_BACK, "MSG_MOVE_KNOCK_BACK" },
    { SMSG_MOVE_FEATHER_FALL, "SMSG_MOVE_FEATHER_FALL" },
    { SMSG_MOVE_NORMAL_FALL, "SMSG_MOVE_NORMAL_FALL" },
    { SMSG_MOVE_SET_HOVER, "SMSG_MOVE_SET_HOVER" },
    { SMSG_MOVE_UNSET_HOVER, "SMSG_MOVE_UNSET_HOVER" },
    { CMSG_MOVE_HOVER_ACK, "CMSG_MOVE_HOVER_ACK" },
    { MSG_MOVE_HOVER, "MSG_MOVE_HOVER" },
    { CMSG_TRIGGER_CINEMATIC_CHEAT, "CMSG_TRIGGER_CINEMATIC_CHEAT" },
    { CMSG_OPENING_CINEMATIC, "CMSG_OPENING_CINEMATIC" },
    { SMSG_TRIGGER_CINEMATIC, "SMSG_TRIGGER_CINEMATIC" },
    { CMSG_NEXT_CINEMATIC_CAMERA, "CMSG_NEXT_CINEMATIC_CAMERA" },
    { CMSG_COMPLETE_CINEMATIC, "CMSG_COMPLETE_CINEMATIC" },
    { SMSG_TUTORIAL_FLAGS, "SMSG_TUTORIAL_FLAGS" },
    { CMSG_TUTORIAL_FLAG, "CMSG_TUTORIAL_FLAG" },
    { CMSG_TUTORIAL_CLEAR, "CMSG_TUTORIAL_CLEAR" },
    { CMSG_TUTORIAL_RESET, "CMSG_TUTORIAL_RESET" },
    { CMSG_STANDSTATECHANGE, "CMSG_STANDSTATECHANGE" },
    { CMSG_EMOTE, "CMSG_EMOTE" },
    { SMSG_EMOTE, "SMSG_EMOTE" },
    { CMSG_TEXT_EMOTE, "CMSG_TEXT_EMOTE" },
    { SMSG_TEXT_EMOTE, "SMSG_TEXT_EMOTE" },
    { CMSG_AUTOEQUIP_GROUND_ITEM, "CMSG_AUTOEQUIP_GROUND_ITEM" },
    { CMSG_AUTOSTORE_GROUND_ITEM, "CMSG_AUTOSTORE_GROUND_ITEM" },
    { CMSG_AUTOSTORE_LOOT_ITEM, "CMSG_AUTOSTORE_LOOT_ITEM" },
    { CMSG_STORE_LOOT_IN_SLOT, "CMSG_STORE_LOOT_IN_SLOT" },
    { CMSG_AUTOEQUIP_ITEM, "CMSG_AUTOEQUIP_ITEM" },
    { CMSG_AUTOSTORE_BAG_ITEM, "CMSG_AUTOSTORE_BAG_ITEM" },
    { CMSG_SWAP_ITEM, "CMSG_SWAP_ITEM" },
    { CMSG_SWAP_INV_ITEM, "CMSG_SWAP_INV_ITEM" },
    { CMSG_SPLIT_ITEM, "CMSG_SPLIT_ITEM" },
    { CMSG_AUTOEQUIP_ITEM_SLOT, "CMSG_AUTOEQUIP_ITEM_SLOT" },
    { OBSOLETE_DROP_ITEM, "OBSOLETE_DROP_ITEM" },
    { CMSG_DESTROYITEM, "CMSG_DESTROYITEM" },
    { SMSG_INVENTORY_CHANGE_FAILURE, "SMSG_INVENTORY_CHANGE_FAILURE" },
    { SMSG_OPEN_CONTAINER, "SMSG_OPEN_CONTAINER" },
    { CMSG_INSPECT, "CMSG_INSPECT" },
    { SMSG_INSPECT, "SMSG_INSPECT" },
    { CMSG_INITIATE_TRADE, "CMSG_INITIATE_TRADE" },
    { CMSG_BEGIN_TRADE, "CMSG_BEGIN_TRADE" },
    { CMSG_BUSY_TRADE, "CMSG_BUSY_TRADE" },
    { CMSG_IGNORE_TRADE, "CMSG_IGNORE_TRADE" },
    { CMSG_ACCEPT_TRADE, "CMSG_ACCEPT_TRADE" },
    { CMSG_UNACCEPT_TRADE, "CMSG_UNACCEPT_TRADE" },
    { CMSG_CANCEL_TRADE, "CMSG_CANCEL_TRADE" },
    { CMSG_SET_TRADE_ITEM, "CMSG_SET_TRADE_ITEM" },
    { CMSG_CLEAR_TRADE_ITEM, "CMSG_CLEAR_TRADE_ITEM" },
    { CMSG_SET_TRADE_GOLD, "CMSG_SET_TRADE_GOLD" },
    { SMSG_TRADE_STATUS, "SMSG_TRADE_STATUS" },
    { SMSG_TRADE_STATUS_EXTENDED, "SMSG_TRADE_STATUS_EXTENDED" },
    { SMSG_INITIALIZE_FACTIONS, "SMSG_INITIALIZE_FACTIONS" },
    { SMSG_SET_FACTION_VISIBLE, "SMSG_SET_FACTION_VISIBLE" },
    { SMSG_SET_FACTION_STANDING, "SMSG_SET_FACTION_STANDING" },
    { CMSG_SET_FACTION_ATWAR, "CMSG_SET_FACTION_ATWAR" },
    { CMSG_SET_FACTION_CHEAT, "CMSG_SET_FACTION_CHEAT" },
    { SMSG_SET_PROFICIENCY, "SMSG_SET_PROFICIENCY" },
    { CMSG_SET_ACTION_BUTTON, "CMSG_SET_ACTION_BUTTON" },
    { SMSG_ACTION_BUTTONS, "SMSG_ACTION_BUTTONS" },
    { SMSG_INITIAL_SPELLS, "SMSG_INITIAL_SPELLS" },
    { SMSG_LEARNED_SPELL, "SMSG_LEARNED_SPELL" },
    { SMSG_SUPERCEDED_SPELL, "SMSG_SUPERCEDED_SPELL" },
    { CMSG_NEW_SPELL_SLOT, "CMSG_NEW_SPELL_SLOT" },
    { CMSG_CAST_SPELL, "CMSG_CAST_SPELL" },
    { CMSG_CANCEL_CAST, "CMSG_CANCEL_CAST" },
    { SMSG_CAST_FAILED, "SMSG_CAST_FAILED" },
    { SMSG_SPELL_START, "SMSG_SPELL_START" },
    { SMSG_SPELL_GO, "SMSG_SPELL_GO" },
    { SMSG_SPELL_FAILURE, "SMSG_SPELL_FAILURE" },
    { SMSG_SPELL_COOLDOWN, "SMSG_SPELL_COOLDOWN" },
    { SMSG_COOLDOWN_EVENT, "SMSG_COOLDOWN_EVENT" },
    { CMSG_CANCEL_AURA, "CMSG_CANCEL_AURA" },
    { SMSG_UPDATE_AURA_DURATION, "SMSG_UPDATE_AURA_DURATION" },
    { SMSG_PET_CAST_FAILED, "SMSG_PET_CAST_FAILED" },
    { MSG_CHANNEL_START, "MSG_CHANNEL_START" },
    { MSG_CHANNEL_UPDATE, "MSG_CHANNEL_UPDATE" },
    { CMSG_CANCEL_CHANNELLING, "CMSG_CANCEL_CHANNELLING" },
    { SMSG_AI_REACTION, "SMSG_AI_REACTION" },
    { CMSG_SET_SELECTION, "CMSG_SET_SELECTION" },
    { CMSG_SET_TARGET_OBSOLETE, "CMSG_SET_TARGET_OBSOLETE" },
    { CMSG_UNUSED, "CMSG_UNUSED" },
    { CMSG_UNUSED2, "CMSG_UNUSED2" },
    { CMSG_ATTACKSWING, "CMSG_ATTACKSWING" },
    { CMSG_ATTACKSTOP, "CMSG_ATTACKSTOP" },
    { SMSG_ATTACKSTART, "SMSG_ATTACKSTART" },
    { SMSG_ATTACKSTOP, "SMSG_ATTACKSTOP" },
    { SMSG_ATTACKSWING_NOTINRANGE, "SMSG_ATTACKSWING_NOTINRANGE" },
    { SMSG_ATTACKSWING_BADFACING, "SMSG_ATTACKSWING_BADFACING" },
    { SMSG_ATTACKSWING_NOTSTANDING, "SMSG_ATTACKSWING_NOTSTANDING" },
    { SMSG_ATTACKSWING_DEADTARGET, "SMSG_ATTACKSWING_DEADTARGET" },
    { SMSG_ATTACKSWING_CANT_ATTACK, "SMSG_ATTACKSWING_CANT_ATTACK" },
    { SMSG_ATTACKERSTATEUPDATE, "SMSG_ATTACKERSTATEUPDATE" },
    { SMSG_VICTIMSTATEUPDATE_OBSOLETE, "SMSG_VICTIMSTATEUPDATE_OBSOLETE" },
    { SMSG_DAMAGE_DONE_OBSOLETE, "SMSG_DAMAGE_DONE_OBSOLETE" },
    { SMSG_DAMAGE_TAKEN_OBSOLETE, "SMSG_DAMAGE_TAKEN_OBSOLETE" },
    { SMSG_CANCEL_COMBAT, "SMSG_CANCEL_COMBAT" },
    { SMSG_PLAYER_COMBAT_XP_GAIN_OBSOLETE, "SMSG_PLAYER_COMBAT_XP_GAIN_OBSOLETE" },
    { SMSG_SPELLHEALLOG, "SMSG_SPELLHEALLOG" },
    { SMSG_SPELLENERGIZELOG, "SMSG_SPELLENERGIZELOG" },
    { CMSG_SHEATHE_OBSOLETE, "CMSG_SHEATHE_OBSOLETE" },
    { CMSG_SAVE_PLAYER, "CMSG_SAVE_PLAYER" },
    { CMSG_SETDEATHBINDPOINT, "CMSG_SETDEATHBINDPOINT" },
    { SMSG_BINDPOINTUPDATE, "SMSG_BINDPOINTUPDATE" },
    { CMSG_GETDEATHBINDZONE, "CMSG_GETDEATHBINDZONE" },
    { SMSG_BINDZONEREPLY, "SMSG_BINDZONEREPLY" },
    { SMSG_PLAYERBOUND, "SMSG_PLAYERBOUND" },
    { SMSG_CLIENT_CONTROL_UPDATE, "SMSG_CLIENT_CONTROL_UPDATE" },
    { CMSG_REPOP_REQUEST, "CMSG_REPOP_REQUEST" },
    { SMSG_RESURRECT_REQUEST, "SMSG_RESURRECT_REQUEST" },
    { CMSG_RESURRECT_RESPONSE, "CMSG_RESURRECT_RESPONSE" },
    { CMSG_LOOT, "CMSG_LOOT" },
    { CMSG_LOOT_MONEY, "CMSG_LOOT_MONEY" },
    { CMSG_LOOT_RELEASE, "CMSG_LOOT_RELEASE" },
    { SMSG_LOOT_RESPONSE, "SMSG_LOOT_RESPONSE" },
    { SMSG_LOOT_RELEASE_RESPONSE, "SMSG_LOOT_RELEASE_RESPONSE" },
    { SMSG_LOOT_REMOVED, "SMSG_LOOT_REMOVED" },
    { SMSG_LOOT_MONEY_NOTIFY, "SMSG_LOOT_MONEY_NOTIFY" },
    { SMSG_LOOT_ITEM_NOTIFY, "SMSG_LOOT_ITEM_NOTIFY" },
    { SMSG_LOOT_CLEAR_MONEY, "SMSG_LOOT_CLEAR_MONEY" },
    { SMSG_ITEM_PUSH_RESULT, "SMSG_ITEM_PUSH_RESULT" },
    { SMSG_DUEL_REQUESTED, "SMSG_DUEL_REQUESTED" },
    { SMSG_DUEL_OUTOFBOUNDS, "SMSG_DUEL_OUTOFBOUNDS" },
    { SMSG_DUEL_INBOUNDS, "SMSG_DUEL_INBOUNDS" },
    { SMSG_DUEL_COMPLETE, "SMSG_DUEL_COMPLETE" },
    { SMSG_DUEL_WINNER, "SMSG_DUEL_WINNER" },
    { CMSG_DUEL_ACCEPTED, "CMSG_DUEL_ACCEPTED" },
    { CMSG_DUEL_CANCELLED, "CMSG_DUEL_CANCELLED" },
    { SMSG_MOUNTRESULT, "SMSG_MOUNTRESULT" },
    { SMSG_DISMOUNTRESULT, "SMSG_DISMOUNTRESULT" },
    { SMSG_PUREMOUNT_CANCELLED_OBSOLETE, "SMSG_PUREMOUNT_CANCELLED_OBSOLETE" },
    { CMSG_MOUNTSPECIAL_ANIM, "CMSG_MOUNTSPECIAL_ANIM" },
    { SMSG_MOUNTSPECIAL_ANIM, "SMSG_MOUNTSPECIAL_ANIM" },
    { SMSG_PET_TAME_FAILURE, "SMSG_PET_TAME_FAILURE" },
    { CMSG_PET_SET_ACTION, "CMSG_PET_SET_ACTION" },
    { CMSG_PET_ACTION, "CMSG_PET_ACTION" },
    { CMSG_PET_ABANDON, "CMSG_PET_ABANDON" },
    { CMSG_PET_RENAME, "CMSG_PET_RENAME" },
    { SMSG_PET_NAME_INVALID, "SMSG_PET_NAME_INVALID" },
    { SMSG_PET_SPELLS, "SMSG_PET_SPELLS" },
    { SMSG_PET_MODE, "SMSG_PET_MODE" },
    { CMSG_GOSSIP_HELLO, "CMSG_GOSSIP_HELLO" },
    { CMSG_GOSSIP_SELECT_OPTION, "CMSG_GOSSIP_SELECT_OPTION" },
    { SMSG_GOSSIP_MESSAGE, "SMSG_GOSSIP_MESSAGE" },
    { SMSG_GOSSIP_COMPLETE, "SMSG_GOSSIP_COMPLETE" },
    { CMSG_NPC_TEXT_QUERY, "CMSG_NPC_TEXT_QUERY" },
    { SMSG_NPC_TEXT_UPDATE, "SMSG_NPC_TEXT_UPDATE" },
    { SMSG_NPC_WONT_TALK, "SMSG_NPC_WONT_TALK" },
    { CMSG_QUESTGIVER_STATUS_QUERY, "CMSG_QUESTGIVER_STATUS_QUERY" },
    { SMSG_QUESTGIVER_STATUS, "SMSG_QUESTGIVER_STATUS" },
    { CMSG_QUESTGIVER_HELLO, "CMSG_QUESTGIVER_HELLO" },
    { SMSG_QUESTGIVER_QUEST_LIST, "SMSG_QUESTGIVER_QUEST_LIST" },
    { CMSG_QUESTGIVER_QUERY_QUEST, "CMSG_QUESTGIVER_QUERY_QUEST" },
    { CMSG_QUESTGIVER_QUEST_AUTOLAUNCH, "CMSG_QUESTGIVER_QUEST_AUTOLAUNCH" },
    { SMSG_QUESTGIVER_QUEST_DETAILS, "SMSG_QUESTGIVER_QUEST_DETAILS" },
    { CMSG_QUESTGIVER_ACCEPT_QUEST, "CMSG_QUESTGIVER_ACCEPT_QUEST" },
    { CMSG_QUESTGIVER_COMPLETE_QUEST, "CMSG_QUESTGIVER_COMPLETE_QUEST" },
    { SMSG_QUESTGIVER_REQUEST_ITEMS, "SMSG_QUESTGIVER_REQUEST_ITEMS" },
    { CMSG_QUESTGIVER_REQUEST_REWARD, "CMSG_QUESTGIVER_REQUEST_REWARD" },
    { SMSG_QUESTGIVER_OFFER_REWARD, "SMSG_QUESTGIVER_OFFER_REWARD" },
    { CMSG_QUESTGIVER_CHOOSE_REWARD, "CMSG_QUESTGIVER_CHOOSE_REWARD" },
    { SMSG_QUESTGIVER_QUEST_INVALID, "SMSG_QUESTGIVER_QUEST_INVALID" },
    { CMSG_QUESTGIVER_CANCEL, "CMSG_QUESTGIVER_CANCEL" },
    { SMSG_QUESTGIVER_QUEST_COMPLETE, "SMSG_QUESTGIVER_QUEST_COMPLETE" },
    { SMSG_QUESTGIVER_QUEST_FAILED, "SMSG_QUESTGIVER_QUEST_FAILED" },
    { CMSG_QUESTLOG_SWAP_QUEST, "CMSG_QUESTLOG_SWAP_QUEST" },
    { CMSG_QUESTLOG_REMOVE_QUEST, "CMSG_QUESTLOG_REMOVE_QUEST" },
    { SMSG_QUESTLOG_FULL, "SMSG_QUESTLOG_FULL" },
    { SMSG_QUESTUPDATE_FAILED, "SMSG_QUESTUPDATE_FAILED" },
    { SMSG_QUESTUPDATE_FAILEDTIMER, "SMSG_QUESTUPDATE_FAILEDTIMER" },
    { SMSG_QUESTUPDATE_COMPLETE, "SMSG_QUESTUPDATE_COMPLETE" },
    { SMSG_QUESTUPDATE_ADD_KILL, "SMSG_QUESTUPDATE_ADD_KILL" },
    { SMSG_QUESTUPDATE_ADD_ITEM, "SMSG_QUESTUPDATE_ADD_ITEM" },
    { CMSG_QUEST_CONFIRM_ACCEPT, "CMSG_QUEST_CONFIRM_ACCEPT" },
    { SMSG_QUEST_CONFIRM_ACCEPT, "SMSG_QUEST_CONFIRM_ACCEPT" },
    { CMSG_PUSHQUESTTOPARTY, "CMSG_PUSHQUESTTOPARTY" },
    { CMSG_LIST_INVENTORY, "CMSG_LIST_INVENTORY" },
    { SMSG_LIST_INVENTORY, "SMSG_LIST_INVENTORY" },
    { CMSG_SELL_ITEM, "CMSG_SELL_ITEM" },
    { SMSG_SELL_ITEM, "SMSG_SELL_ITEM" },
    { CMSG_BUY_ITEM, "CMSG_BUY_ITEM" },
    { CMSG_BUY_ITEM_IN_SLOT, "CMSG_BUY_ITEM_IN_SLOT" },
    { SMSG_BUY_ITEM, "SMSG_BUY_ITEM" },
    { SMSG_BUY_FAILED, "SMSG_BUY_FAILED" },
    { CMSG_TAXICLEARALLNODES, "CMSG_TAXICLEARALLNODES" },
    { CMSG_TAXIENABLEALLNODES, "CMSG_TAXIENABLEALLNODES" },
    { CMSG_TAXISHOWNODES, "CMSG_TAXISHOWNODES" },
    { SMSG_SHOWTAXINODES, "SMSG_SHOWTAXINODES" },
    { CMSG_TAXINODE_STATUS_QUERY, "CMSG_TAXINODE_STATUS_QUERY" },
    { SMSG_TAXINODE_STATUS, "SMSG_TAXINODE_STATUS" },
    { CMSG_TAXIQUERYAVAILABLENODES, "CMSG_TAXIQUERYAVAILABLENODES" },
    { CMSG_ACTIVATETAXI, "CMSG_ACTIVATETAXI" },
    { SMSG_ACTIVATETAXIREPLY, "SMSG_ACTIVATETAXIREPLY" },
    { SMSG_NEW_TAXI_PATH, "SMSG_NEW_TAXI_PATH" },
    { CMSG_TRAINER_LIST, "CMSG_TRAINER_LIST" },
    { SMSG_TRAINER_LIST, "SMSG_TRAINER_LIST" },
    { CMSG_TRAINER_BUY_SPELL, "CMSG_TRAINER_BUY_SPELL" },
    { SMSG_TRAINER_BUY_SUCCEEDED, "SMSG_TRAINER_BUY_SUCCEEDED" },
    { SMSG_TRAINER_BUY_FAILED, "SMSG_TRAINER_BUY_FAILED" },
    { CMSG_BINDER_ACTIVATE, "CMSG_BINDER_ACTIVATE" },
    { SMSG_PLAYERBINDERROR, "SMSG_PLAYERBINDERROR" },
    { CMSG_BANKER_ACTIVATE, "CMSG_BANKER_ACTIVATE" },
    { SMSG_SHOW_BANK, "SMSG_SHOW_BANK" },
    { CMSG_BUY_BANK_SLOT, "CMSG_BUY_BANK_SLOT" },
    { SMSG_BUY_BANK_SLOT_RESULT, "SMSG_BUY_BANK_SLOT_RESULT" },
    { CMSG_PETITION_SHOWLIST, "CMSG_PETITION_SHOWLIST" },
    { SMSG_PETITION_SHOWLIST, "SMSG_PETITION_SHOWLIST" },
    { CMSG_PETITION_BUY, "CMSG_PETITION_BUY" },
    { CMSG_PETITION_SHOW_SIGNATURES, "CMSG_PETITION_SHOW_SIGNATURES" },
    { SMSG_PETITION_SHOW_SIGNATURES, "SMSG_PETITION_SHOW_SIGNATURES" },
    { CMSG_PETITION_SIGN, "CMSG_PETITION_SIGN" },
    { SMSG_PETITION_SIGN_RESULTS, "SMSG_PETITION_SIGN_RESULTS" },
    { MSG_PETITION_DECLINE, "MSG_PETITION_DECLINE" },
    { CMSG_OFFER_PETITION, "CMSG_OFFER_PETITION" },
    { CMSG_TURN_IN_PETITION, "CMSG_TURN_IN_PETITION" },
    { SMSG_TURN_IN_PETITION_RESULTS, "SMSG_TURN_IN_PETITION_RESULTS" },
    { CMSG_PETITION_QUERY, "CMSG_PETITION_QUERY" },
    { SMSG_PETITION_QUERY_RESPONSE, "SMSG_PETITION_QUERY_RESPONSE" },
    { SMSG_FISH_NOT_HOOKED, "SMSG_FISH_NOT_HOOKED" },
    { SMSG_FISH_ESCAPED, "SMSG_FISH_ESCAPED" },
    { CMSG_BUG, "CMSG_BUG" },
    { SMSG_NOTIFICATION, "SMSG_NOTIFICATION" },
    { CMSG_PLAYED_TIME, "CMSG_PLAYED_TIME" },
    { SMSG_PLAYED_TIME, "SMSG_PLAYED_TIME" },
    { CMSG_QUERY_TIME, "CMSG_QUERY_TIME" },
    { SMSG_QUERY_TIME_RESPONSE, "SMSG_QUERY_TIME_RESPONSE" },
    { SMSG_LOG_XPGAIN, "SMSG_LOG_XPGAIN" },
    { SMSG_AURACASTLOG, "SMSG_AURACASTLOG" },
    { CMSG_RECLAIM_CORPSE, "CMSG_RECLAIM_CORPSE" },
    { CMSG_WRAP_ITEM, "CMSG_WRAP_ITEM" },
    { SMSG_LEVELUP_INFO, "SMSG_LEVELUP_INFO" },
    { MSG_MINIMAP_PING, "MSG_MINIMAP_PING" },
    { SMSG_RESISTLOG, "SMSG_RESISTLOG" },
    { SMSG_ENCHANTMENTLOG, "SMSG_ENCHANTMENTLOG" },
    { CMSG_SET_SKILL_CHEAT, "CMSG_SET_SKILL_CHEAT" },
    { SMSG_START_MIRROR_TIMER, "SMSG_START_MIRROR_TIMER" },
    { SMSG_PAUSE_MIRROR_TIMER, "SMSG_PAUSE_MIRROR_TIMER" },
    { SMSG_STOP_MIRROR_TIMER, "SMSG_STOP_MIRROR_TIMER" },
    { CMSG_PING, "CMSG_PING" },
    { SMSG_PONG, "SMSG_PONG" },
    { SMSG_CLEAR_COOLDOWN, "SMSG_CLEAR_COOLDOWN" },
    { SMSG_GAMEOBJECT_PAGETEXT, "SMSG_GAMEOBJECT_PAGETEXT" },
    { CMSG_SETSHEATHED, "CMSG_SETSHEATHED" },
    { SMSG_COOLDOWN_CHEAT, "SMSG_COOLDOWN_CHEAT" },
    { SMSG_SPELL_DELAYED, "SMSG_SPELL_DELAYED" },
    { CMSG_PLAYER_MACRO_OBSOLETE, "CMSG_PLAYER_MACRO_OBSOLETE" },
    { SMSG_PLAYER_MACRO_OBSOLETE, "SMSG_PLAYER_MACRO_OBSOLETE" },
    { CMSG_GHOST, "CMSG_GHOST" },
    { CMSG_GM_INVIS, "CMSG_GM_INVIS" },
    { SMSG_INVALID_PROMOTION_CODE, "SMSG_INVALID_PROMOTION_CODE" },
    { MSG_GM_BIND_OTHER, "MSG_GM_BIND_OTHER" },
    { MSG_GM_SUMMON, "MSG_GM_SUMMON" },
    { SMSG_ITEM_TIME_UPDATE, "SMSG_ITEM_TIME_UPDATE" },
    { SMSG_ITEM_ENCHANT_TIME_UPDATE, "SMSG_ITEM_ENCHANT_TIME_UPDATE" },
    { SMSG_AUTH_CHALLENGE, "SMSG_AUTH_CHALLENGE" },
    { CMSG_AUTH_SESSION, "CMSG_AUTH_SESSION" },
    { SMSG_AUTH_RESPONSE, "SMSG_AUTH_RESPONSE" },
    { MSG_GM_SHOWLABEL, "MSG_GM_SHOWLABEL" },
    { CMSG_PET_CAST_SPELL, "CMSG_PET_CAST_SPELL" },
    { MSG_SAVE_GUILD_EMBLEM, "MSG_SAVE_GUILD_EMBLEM" },
    { MSG_TABARDVENDOR_ACTIVATE, "MSG_TABARDVENDOR_ACTIVATE" },
    { SMSG_PLAY_SPELL_VISUAL, "SMSG_PLAY_SPELL_VISUAL" },
    { CMSG_ZONEUPDATE, "CMSG_ZONEUPDATE" },
    { SMSG_PARTYKILLLOG, "SMSG_PARTYKILLLOG" },
    { SMSG_COMPRESSED_UPDATE_OBJECT, "SMSG_COMPRESSED_UPDATE_OBJECT" },
    { SMSG_PLAY_SPELL_IMPACT, "SMSG_PLAY_SPELL_IMPACT" },
    { SMSG_EXPLORATION_EXPERIENCE, "SMSG_EXPLORATION_EXPERIENCE" },
    { CMSG_GM_SET_SECURITY_GROUP, "CMSG_GM_SET_SECURITY_GROUP" },
    { CMSG_GM_NUKE, "CMSG_GM_NUKE" },
    { MSG_RANDOM_ROLL, "MSG_RANDOM_ROLL" },
    { SMSG_ENVIRONMENTALDAMAGELOG, "SMSG_ENVIRONMENTALDAMAGELOG" },
    { CMSG_RWHOIS_OBSOLETE, "CMSG_RWHOIS_OBSOLETE" },
    { SMSG_RWHOIS, "SMSG_RWHOIS" },
    { MSG_LOOKING_FOR_GROUP, "MSG_LOOKING_FOR_GROUP" },
    { CMSG_SET_LOOKING_FOR_GROUP, "CMSG_SET_LOOKING_FOR_GROUP" },
    { CMSG_UNLEARN_SPELL, "CMSG_UNLEARN_SPELL" },
    { CMSG_UNLEARN_SKILL, "CMSG_UNLEARN_SKILL" },
    { SMSG_REMOVED_SPELL, "SMSG_REMOVED_SPELL" },
    { CMSG_DECHARGE, "CMSG_DECHARGE" },
    { CMSG_GMTICKET_CREATE, "CMSG_GMTICKET_CREATE" },
    { SMSG_GMTICKET_CREATE, "SMSG_GMTICKET_CREATE" },
    { CMSG_GMTICKET_UPDATETEXT, "CMSG_GMTICKET_UPDATETEXT" },
    { SMSG_GMTICKET_UPDATETEXT, "SMSG_GMTICKET_UPDATETEXT" },
    { SMSG_ACCOUNT_DATA_TIMES, "SMSG_ACCOUNT_DATA_TIMES" },
    { CMSG_REQUEST_ACCOUNT_DATA, "CMSG_REQUEST_ACCOUNT_DATA" },
    { CMSG_UPDATE_ACCOUNT_DATA, "CMSG_UPDATE_ACCOUNT_DATA" },
    { SMSG_UPDATE_ACCOUNT_DATA, "SMSG_UPDATE_ACCOUNT_DATA" },
    { SMSG_CLEAR_FAR_SIGHT_IMMEDIATE, "SMSG_CLEAR_FAR_SIGHT_IMMEDIATE" },
    { SMSG_POWERGAINLOG_OBSOLETE, "SMSG_POWERGAINLOG_OBSOLETE" },
    { CMSG_GM_TEACH, "CMSG_GM_TEACH" },
    { CMSG_GM_CREATE_ITEM_TARGET, "CMSG_GM_CREATE_ITEM_TARGET" },
    { CMSG_GMTICKET_GETTICKET, "CMSG_GMTICKET_GETTICKET" },
    { SMSG_GMTICKET_GETTICKET, "SMSG_GMTICKET_GETTICKET" },
    { CMSG_UNLEARN_TALENTS, "CMSG_UNLEARN_TALENTS" },
    { SMSG_GAMEOBJECT_SPAWN_ANIM_OBSOLETE, "SMSG_GAMEOBJECT_SPAWN_ANIM_OBSOLETE" },
    { SMSG_GAMEOBJECT_DESPAWN_ANIM, "SMSG_GAMEOBJECT_DESPAWN_ANIM" },
    { MSG_CORPSE_QUERY, "MSG_CORPSE_QUERY" },
    { CMSG_GMTICKET_DELETETICKET, "CMSG_GMTICKET_DELETETICKET" },
    { SMSG_GMTICKET_DELETETICKET, "SMSG_GMTICKET_DELETETICKET" },
    { SMSG_CHAT_WRONG_FACTION, "SMSG_CHAT_WRONG_FACTION" },
    { CMSG_GMTICKET_SYSTEMSTATUS, "CMSG_GMTICKET_SYSTEMSTATUS" },
    { SMSG_GMTICKET_SYSTEMSTATUS, "SMSG_GMTICKET_SYSTEMSTATUS" },
    { CMSG_SPIRIT_HEALER_ACTIVATE, "CMSG_SPIRIT_HEALER_ACTIVATE" },
    { CMSG_SET_STAT_CHEAT, "CMSG_SET_STAT_CHEAT" },
    { SMSG_SET_REST_START, "SMSG_SET_REST_START" },
    { CMSG_SKILL_BUY_STEP, "CMSG_SKILL_BUY_STEP" },
    { CMSG_SKILL_BUY_RANK, "CMSG_SKILL_BUY_RANK" },
    { CMSG_XP_CHEAT, "CMSG_XP_CHEAT" },
    { SMSG_SPIRIT_HEALER_CONFIRM, "SMSG_SPIRIT_HEALER_CONFIRM" },
    { CMSG_CHARACTER_POINT_CHEAT, "CMSG_CHARACTER_POINT_CHEAT" },
    { SMSG_GOSSIP_POI, "SMSG_GOSSIP_POI" },
    { CMSG_CHAT_IGNORED, "CMSG_CHAT_IGNORED" },
    { CMSG_GM_VISION, "CMSG_GM_VISION" },
    { CMSG_SERVER_COMMAND, "CMSG_SERVER_COMMAND" },
    { CMSG_GM_SILENCE, "CMSG_GM_SILENCE" },
    { CMSG_GM_REVEALTO, "CMSG_GM_REVEALTO" },
    { CMSG_GM_RESURRECT, "CMSG_GM_RESURRECT" },
    { CMSG_GM_SUMMONMOB, "CMSG_GM_SUMMONMOB" },
    { CMSG_GM_MOVECORPSE, "CMSG_GM_MOVECORPSE" },
    { CMSG_GM_FREEZE, "CMSG_GM_FREEZE" },
    { CMSG_GM_UBERINVIS, "CMSG_GM_UBERINVIS" },
    { CMSG_GM_REQUEST_PLAYER_INFO, "CMSG_GM_REQUEST_PLAYER_INFO" },
    { SMSG_GM_PLAYER_INFO, "SMSG_GM_PLAYER_INFO" },
    { CMSG_GUILD_RANK, "CMSG_GUILD_RANK" },
    { CMSG_GUILD_ADD_RANK, "CMSG_GUILD_ADD_RANK" },
    { CMSG_GUILD_DEL_RANK, "CMSG_GUILD_DEL_RANK" },
    { CMSG_GUILD_SET_PUBLIC_NOTE, "CMSG_GUILD_SET_PUBLIC_NOTE" },
    { CMSG_GUILD_SET_OFFICER_NOTE, "CMSG_GUILD_SET_OFFICER_NOTE" },
    { SMSG_LOGIN_VERIFY_WORLD, "SMSG_LOGIN_VERIFY_WORLD" },
    { CMSG_CLEAR_EXPLORATION, "CMSG_CLEAR_EXPLORATION" },
    { CMSG_SEND_MAIL, "CMSG_SEND_MAIL" },
    { SMSG_SEND_MAIL_RESULT, "SMSG_SEND_MAIL_RESULT" },
    { CMSG_GET_MAIL_LIST, "CMSG_GET_MAIL_LIST" },
    { SMSG_MAIL_LIST_RESULT, "SMSG_MAIL_LIST_RESULT" },
    { CMSG_BATTLEFIELD_LIST, "CMSG_BATTLEFIELD_LIST" },
    { SMSG_BATTLEFIELD_LIST, "SMSG_BATTLEFIELD_LIST" },
    { CMSG_BATTLEFIELD_JOIN, "CMSG_BATTLEFIELD_JOIN" },
    { SMSG_BATTLEFIELD_WIN_OBSOLETE, "SMSG_BATTLEFIELD_WIN_OBSOLETE" },
    { SMSG_BATTLEFIELD_LOSE_OBSOLETE, "SMSG_BATTLEFIELD_LOSE_OBSOLETE" },
    { CMSG_TAXICLEARNODE, "CMSG_TAXICLEARNODE" },
    { CMSG_TAXIENABLENODE, "CMSG_TAXIENABLENODE" },
    { CMSG_ITEM_TEXT_QUERY, "CMSG_ITEM_TEXT_QUERY" },
    { SMSG_ITEM_TEXT_QUERY_RESPONSE, "SMSG_ITEM_TEXT_QUERY_RESPONSE" },
    { CMSG_MAIL_TAKE_MONEY, "CMSG_MAIL_TAKE_MONEY" },
    { CMSG_MAIL_TAKE_ITEM, "CMSG_MAIL_TAKE_ITEM" },
    { CMSG_MAIL_MARK_AS_READ, "CMSG_MAIL_MARK_AS_READ" },
    { CMSG_MAIL_RETURN_TO_SENDER, "CMSG_MAIL_RETURN_TO_SENDER" },
    { CMSG_MAIL_DELETE, "CMSG_MAIL_DELETE" },
    { CMSG_MAIL_CREATE_TEXT_ITEM, "CMSG_MAIL_CREATE_TEXT_ITEM" },
    { SMSG_SPELLLOGMISS, "SMSG_SPELLLOGMISS" },
    { SMSG_SPELLLOGEXECUTE, "SMSG_SPELLLOGEXECUTE" },
    { SMSG_DEBUGAURAPROC, "SMSG_DEBUGAURAPROC" },
    { SMSG_PERIODICAURALOG, "SMSG_PERIODICAURALOG" },
    { SMSG_SPELLDAMAGESHIELD, "SMSG_SPELLDAMAGESHIELD" },
    { SMSG_SPELLNONMELEEDAMAGELOG, "SMSG_SPELLNONMELEEDAMAGELOG" },
    { CMSG_LEARN_TALENT, "CMSG_LEARN_TALENT" },
    { SMSG_RESURRECT_FAILED, "SMSG_RESURRECT_FAILED" },
    { CMSG_TOGGLE_PVP, "CMSG_TOGGLE_PVP" },
    { SMSG_ZONE_UNDER_ATTACK, "SMSG_ZONE_UNDER_ATTACK" },
    { MSG_AUCTION_HELLO, "MSG_AUCTION_HELLO" },
    { CMSG_AUCTION_SELL_ITEM, "CMSG_AUCTION_SELL_ITEM" },
    { CMSG_AUCTION_REMOVE_ITEM, "CMSG_AUCTION_REMOVE_ITEM" },
    { CMSG_AUCTION_LIST_ITEMS, "CMSG_AUCTION_LIST_ITEMS" },
    { CMSG_AUCTION_LIST_OWNER_ITEMS, "CMSG_AUCTION_LIST_OWNER_ITEMS" },
    { CMSG_AUCTION_PLACE_BID, "CMSG_AUCTION_PLACE_BID" },
    { SMSG_AUCTION_COMMAND_RESULT, "SMSG_AUCTION_COMMAND_RESULT" },
    { SMSG_AUCTION_LIST_RESULT, "SMSG_AUCTION_LIST_RESULT" },
    { SMSG_AUCTION_OWNER_LIST_RESULT, "SMSG_AUCTION_OWNER_LIST_RESULT" },
    { SMSG_AUCTION_BIDDER_NOTIFICATION, "SMSG_AUCTION_BIDDER_NOTIFICATION" },
    { SMSG_AUCTION_OWNER_NOTIFICATION, "SMSG_AUCTION_OWNER_NOTIFICATION" },
    { SMSG_PROCRESIST, "SMSG_PROCRESIST" },
    { SMSG_STANDSTATE_CHANGE_FAILURE_OBSOLETE, "SMSG_STANDSTATE_CHANGE_FAILURE_OBSOLETE" },
    { SMSG_DISPEL_FAILED, "SMSG_DISPEL_FAILED" },
    { SMSG_SPELLORDAMAGE_IMMUNE, "SMSG_SPELLORDAMAGE_IMMUNE" },
    { CMSG_AUCTION_LIST_BIDDER_ITEMS, "CMSG_AUCTION_LIST_BIDDER_ITEMS" },
    { SMSG_AUCTION_BIDDER_LIST_RESULT, "SMSG_AUCTION_BIDDER_LIST_RESULT" },
    { SMSG_SET_FLAT_SPELL_MODIFIER, "SMSG_SET_FLAT_SPELL_MODIFIER" },
    { SMSG_SET_PCT_SPELL_MODIFIER, "SMSG_SET_PCT_SPELL_MODIFIER" },
    { CMSG_SET_AMMO, "CMSG_SET_AMMO" },
    { SMSG_CORPSE_RECLAIM_DELAY, "SMSG_CORPSE_RECLAIM_DELAY" },
    { CMSG_SET_ACTIVE_MOVER, "CMSG_SET_ACTIVE_MOVER" },
    { CMSG_PET_CANCEL_AURA, "CMSG_PET_CANCEL_AURA" },
    { CMSG_PLAYER_AI_CHEAT, "CMSG_PLAYER_AI_CHEAT" },
    { CMSG_CANCEL_AUTO_REPEAT_SPELL, "CMSG_CANCEL_AUTO_REPEAT_SPELL" },
    { MSG_GM_ACCOUNT_ONLINE, "MSG_GM_ACCOUNT_ONLINE" },
    { MSG_LIST_STABLED_PETS, "MSG_LIST_STABLED_PETS" },
    { CMSG_STABLE_PET, "CMSG_STABLE_PET" },
    { CMSG_UNSTABLE_PET, "CMSG_UNSTABLE_PET" },
    { CMSG_BUY_STABLE_SLOT, "CMSG_BUY_STABLE_SLOT" },
    { SMSG_STABLE_RESULT, "SMSG_STABLE_RESULT" },
    { CMSG_STABLE_REVIVE_PET, "CMSG_STABLE_REVIVE_PET" },
    { CMSG_STABLE_SWAP_PET, "CMSG_STABLE_SWAP_PET" },
    { MSG_QUEST_PUSH_RESULT, "MSG_QUEST_PUSH_RESULT" },
    { SMSG_PLAY_MUSIC, "SMSG_PLAY_MUSIC" },
    { SMSG_PLAY_OBJECT_SOUND, "SMSG_PLAY_OBJECT_SOUND" },
    { CMSG_REQUEST_PET_INFO, "CMSG_REQUEST_PET_INFO" },
    { CMSG_FAR_SIGHT, "CMSG_FAR_SIGHT" },
    { SMSG_SPELLDISPELLOG, "SMSG_SPELLDISPELLOG" },
    { SMSG_DAMAGE_CALC_LOG, "SMSG_DAMAGE_CALC_LOG" },
    { CMSG_ENABLE_DAMAGE_LOG, "CMSG_ENABLE_DAMAGE_LOG" },
    { CMSG_GROUP_CHANGE_SUB_GROUP, "CMSG_GROUP_CHANGE_SUB_GROUP" },
    { CMSG_REQUEST_PARTY_MEMBER_STATS, "CMSG_REQUEST_PARTY_MEMBER_STATS" },
    { CMSG_GROUP_SWAP_SUB_GROUP, "CMSG_GROUP_SWAP_SUB_GROUP" },
    { CMSG_RESET_FACTION_CHEAT, "CMSG_RESET_FACTION_CHEAT" },
    { CMSG_AUTOSTORE_BANK_ITEM, "CMSG_AUTOSTORE_BANK_ITEM" },
    { CMSG_AUTOBANK_ITEM, "CMSG_AUTOBANK_ITEM" },
    { MSG_QUERY_NEXT_MAIL_TIME, "MSG_QUERY_NEXT_MAIL_TIME" },
    { SMSG_RECEIVED_MAIL, "SMSG_RECEIVED_MAIL" },
    { SMSG_RAID_GROUP_ONLY, "SMSG_RAID_GROUP_ONLY" },
    { CMSG_SET_DURABILITY_CHEAT, "CMSG_SET_DURABILITY_CHEAT" },
    { CMSG_SET_PVP_RANK_CHEAT, "CMSG_SET_PVP_RANK_CHEAT" },
    { CMSG_ADD_PVP_MEDAL_CHEAT, "CMSG_ADD_PVP_MEDAL_CHEAT" },
    { CMSG_DEL_PVP_MEDAL_CHEAT, "CMSG_DEL_PVP_MEDAL_CHEAT" },
    { CMSG_SET_PVP_TITLE, "CMSG_SET_PVP_TITLE" },
    { SMSG_PVP_CREDIT, "SMSG_PVP_CREDIT" },
    { SMSG_AUCTION_REMOVED_NOTIFICATION, "SMSG_AUCTION_REMOVED_NOTIFICATION" },
    { CMSG_GROUP_RAID_CONVERT, "CMSG_GROUP_RAID_CONVERT" },
    { CMSG_GROUP_ASSISTANT_LEADER, "CMSG_GROUP_ASSISTANT_LEADER" },
    { CMSG_BUYBACK_ITEM, "CMSG_BUYBACK_ITEM" },
    { SMSG_SERVER_MESSAGE, "SMSG_SERVER_MESSAGE" },
    { CMSG_MEETINGSTONE_JOIN, "CMSG_MEETINGSTONE_JOIN" },
    { CMSG_MEETINGSTONE_LEAVE, "CMSG_MEETINGSTONE_LEAVE" },
    { CMSG_MEETINGSTONE_CHEAT, "CMSG_MEETINGSTONE_CHEAT" },
    { SMSG_MEETINGSTONE_SETQUEUE, "SMSG_MEETINGSTONE_SETQUEUE" },
    { CMSG_MEETINGSTONE_INFO, "CMSG_MEETINGSTONE_INFO" },
    { SMSG_MEETINGSTONE_COMPLETE, "SMSG_MEETINGSTONE_COMPLETE" },
    { SMSG_MEETINGSTONE_IN_PROGRESS, "SMSG_MEETINGSTONE_IN_PROGRESS" },
    { SMSG_MEETINGSTONE_MEMBER_ADDED, "SMSG_MEETINGSTONE_MEMBER_ADDED" },
    { CMSG_GMTICKETSYSTEM_TOGGLE, "CMSG_GMTICKETSYSTEM_TOGGLE" },
    { CMSG_CANCEL_GROWTH_AURA, "CMSG_CANCEL_GROWTH_AURA" },
    { SMSG_CANCEL_AUTO_REPEAT, "SMSG_CANCEL_AUTO_REPEAT" },
    { SMSG_STANDSTATE_UPDATE, "SMSG_STANDSTATE_UPDATE" },
    { SMSG_LOOT_ALL_PASSED, "SMSG_LOOT_ALL_PASSED" },
    { SMSG_LOOT_ROLL_WON, "SMSG_LOOT_ROLL_WON" },
    { CMSG_LOOT_ROLL, "CMSG_LOOT_ROLL" },
    { SMSG_LOOT_START_ROLL, "SMSG_LOOT_START_ROLL" },
    { SMSG_LOOT_ROLL, "SMSG_LOOT_ROLL" },
    { CMSG_LOOT_MASTER_GIVE, "CMSG_LOOT_MASTER_GIVE" },
    { SMSG_LOOT_MASTER_LIST, "SMSG_LOOT_MASTER_LIST" },
    { SMSG_SET_FORCED_REACTIONS, "SMSG_SET_FORCED_REACTIONS" },
    { SMSG_SPELL_FAILED_OTHER, "SMSG_SPELL_FAILED_OTHER" },
    { SMSG_GAMEOBJECT_RESET_STATE, "SMSG_GAMEOBJECT_RESET_STATE" },
    { CMSG_REPAIR_ITEM, "CMSG_REPAIR_ITEM" },
    { SMSG_CHAT_PLAYER_NOT_FOUND, "SMSG_CHAT_PLAYER_NOT_FOUND" },
    { MSG_TALENT_WIPE_CONFIRM, "MSG_TALENT_WIPE_CONFIRM" },
    { SMSG_SUMMON_REQUEST, "SMSG_SUMMON_REQUEST" },
    { CMSG_SUMMON_RESPONSE, "CMSG_SUMMON_RESPONSE" },
    { MSG_MOVE_TOGGLE_GRAVITY_CHEAT, "MSG_MOVE_TOGGLE_GRAVITY_CHEAT" },
    { SMSG_MONSTER_MOVE_TRANSPORT, "SMSG_MONSTER_MOVE_TRANSPORT" },
    { SMSG_PET_BROKEN, "SMSG_PET_BROKEN" },
    { MSG_MOVE_FEATHER_FALL, "MSG_MOVE_FEATHER_FALL" },
    { MSG_MOVE_WATER_WALK, "MSG_MOVE_WATER_WALK" },
    { CMSG_SERVER_BROADCAST, "CMSG_SERVER_BROADCAST" },
    { CMSG_SELF_RES, "CMSG_SELF_RES" },
    { SMSG_FEIGN_DEATH_RESISTED, "SMSG_FEIGN_DEATH_RESISTED" },
    { CMSG_RUN_SCRIPT, "CMSG_RUN_SCRIPT" },
    { SMSG_SCRIPT_MESSAGE, "SMSG_SCRIPT_MESSAGE" },
    { SMSG_DUEL_COUNTDOWN, "SMSG_DUEL_COUNTDOWN" },
    { SMSG_AREA_TRIGGER_MESSAGE, "SMSG_AREA_TRIGGER_MESSAGE" },
    { CMSG_TOGGLE_HELM, "CMSG_TOGGLE_HELM" },
    { CMSG_TOGGLE_CLOAK, "CMSG_TOGGLE_CLOAK" },
    { SMSG_MEETINGSTONE_JOINFAILED, "SMSG_MEETINGSTONE_JOINFAILED" },
    { SMSG_PLAYER_SKINNED, "SMSG_PLAYER_SKINNED" },
    { SMSG_DURABILITY_DAMAGE_DEATH, "SMSG_DURABILITY_DAMAGE_DEATH" },
    { CMSG_SET_EXPLORATION, "CMSG_SET_EXPLORATION" },
    { CMSG_SET_ACTIONBAR_TOGGLES, "CMSG_SET_ACTIONBAR_TOGGLES" },
    { UMSG_DELETE_GUILD_CHARTER, "UMSG_DELETE_GUILD_CHARTER" },
    { MSG_PETITION_RENAME, "MSG_PETITION_RENAME" },
    { SMSG_INIT_WORLD_STATES, "SMSG_INIT_WORLD_STATES" },
    { SMSG_UPDATE_WORLD_STATE, "SMSG_UPDATE_WORLD_STATE" },
    { CMSG_ITEM_NAME_QUERY, "CMSG_ITEM_NAME_QUERY" },
    { SMSG_ITEM_NAME_QUERY_RESPONSE, "SMSG_ITEM_NAME_QUERY_RESPONSE" },
    { SMSG_PET_ACTION_FEEDBACK, "SMSG_PET_ACTION_FEEDBACK" },
    { CMSG_CHAR_RENAME, "CMSG_CHAR_RENAME" },
    { SMSG_CHAR_RENAME, "SMSG_CHAR_RENAME" },
    { CMSG_MOVE_SPLINE_DONE, "CMSG_MOVE_SPLINE_DONE" },
    { CMSG_MOVE_FALL_RESET, "CMSG_MOVE_FALL_RESET" },
    { SMSG_INSTANCE_SAVE_CREATED, "SMSG_INSTANCE_SAVE_CREATED" },
    { SMSG_RAID_INSTANCE_INFO, "SMSG_RAID_INSTANCE_INFO" },
    { CMSG_REQUEST_RAID_INFO, "CMSG_REQUEST_RAID_INFO" },
    { CMSG_MOVE_TIME_SKIPPED, "CMSG_MOVE_TIME_SKIPPED" },
    { CMSG_MOVE_FEATHER_FALL_ACK, "CMSG_MOVE_FEATHER_FALL_ACK" },
    { CMSG_MOVE_WATER_WALK_ACK, "CMSG_MOVE_WATER_WALK_ACK" },
    { CMSG_MOVE_NOT_ACTIVE_MOVER, "CMSG_MOVE_NOT_ACTIVE_MOVER" },
    { SMSG_PLAY_SOUND, "SMSG_PLAY_SOUND" },
    { CMSG_BATTLEFIELD_STATUS, "CMSG_BATTLEFIELD_STATUS" },
    { SMSG_BATTLEFIELD_STATUS, "SMSG_BATTLEFIELD_STATUS" },
    { CMSG_BATTLEFIELD_PORT, "CMSG_BATTLEFIELD_PORT" },
    { MSG_INSPECT_HONOR_STATS, "MSG_INSPECT_HONOR_STATS" },
    { CMSG_BATTLEMASTER_HELLO, "CMSG_BATTLEMASTER_HELLO" },
    { CMSG_MOVE_START_SWIM_CHEAT, "CMSG_MOVE_START_SWIM_CHEAT" },
    { CMSG_MOVE_STOP_SWIM_CHEAT, "CMSG_MOVE_STOP_SWIM_CHEAT" },
    { SMSG_FORCE_WALK_SPEED_CHANGE, "SMSG_FORCE_WALK_SPEED_CHANGE" },
    { CMSG_FORCE_WALK_SPEED_CHANGE_ACK, "CMSG_FORCE_WALK_SPEED_CHANGE_ACK" },
    { SMSG_FORCE_SWIM_BACK_SPEED_CHANGE, "SMSG_FORCE_SWIM_BACK_SPEED_CHANGE" },
    { CMSG_FORCE_SWIM_BACK_SPEED_CHANGE_ACK, "CMSG_FORCE_SWIM_BACK_SPEED_CHANGE_ACK" },
    { SMSG_FORCE_TURN_RATE_CHANGE, "SMSG_FORCE_TURN_RATE_CHANGE" },
    { CMSG_FORCE_TURN_RATE_CHANGE_ACK, "CMSG_FORCE_TURN_RATE_CHANGE_ACK" },
    { MSG_PVP_LOG_DATA, "MSG_PVP_LOG_DATA" },
    { CMSG_LEAVE_BATTLEFIELD, "CMSG_LEAVE_BATTLEFIELD" },
    { CMSG_AREA_SPIRIT_HEALER_QUERY, "CMSG_AREA_SPIRIT_HEALER_QUERY" },
    { CMSG_AREA_SPIRIT_HEALER_QUEUE, "CMSG_AREA_SPIRIT_HEALER_QUEUE" },
    { SMSG_AREA_SPIRIT_HEALER_TIME, "SMSG_AREA_SPIRIT_HEALER_TIME" },
    { CMSG_GM_UNTEACH, "CMSG_GM_UNTEACH" },
    { SMSG_WARDEN_DATA, "SMSG_WARDEN_DATA" },
    { CMSG_WARDEN_DATA, "CMSG_WARDEN_DATA" },
    { SMSG_GROUP_JOINED_BATTLEGROUND, "SMSG_GROUP_JOINED_BATTLEGROUND" },
    { MSG_BATTLEGROUND_PLAYER_POSITIONS, "MSG_BATTLEGROUND_PLAYER_POSITIONS" },
    { CMSG_PET_STOP_ATTACK, "CMSG_PET_STOP_ATTACK" },
    { SMSG_BINDER_CONFIRM, "SMSG_BINDER_CONFIRM" },
    { SMSG_BATTLEGROUND_PLAYER_JOINED, "SMSG_BATTLEGROUND_PLAYER_JOINED" },
    { SMSG_BATTLEGROUND_PLAYER_LEFT, "SMSG_BATTLEGROUND_PLAYER_LEFT" },
    { CMSG_BATTLEMASTER_JOIN, "CMSG_BATTLEMASTER_JOIN" },
    { SMSG_ADDON_INFO, "SMSG_ADDON_INFO" },
    { CMSG_PET_UNLEARN, "CMSG_PET_UNLEARN" },
    { SMSG_PET_UNLEARN_CONFIRM, "SMSG_PET_UNLEARN_CONFIRM" },
    { SMSG_PARTY_MEMBER_STATS_FULL, "SMSG_PARTY_MEMBER_STATS_FULL" },
    { CMSG_PET_SPELL_AUTOCAST, "CMSG_PET_SPELL_AUTOCAST" },
    { SMSG_WEATHER, "SMSG_WEATHER" },
    { SMSG_PLAY_TIME_WARNING, "SMSG_PLAY_TIME_WARNING" },
    { SMSG_MINIGAME_SETUP, "SMSG_MINIGAME_SETUP" },
    { SMSG_MINIGAME_STATE, "SMSG_MINIGAME_STATE" },
    { CMSG_MINIGAME_MOVE, "CMSG_MINIGAME_MOVE" },
    { SMSG_MINIGAME_MOVE_FAILED, "SMSG_MINIGAME_MOVE_FAILED" },
    { SMSG_RAID_INSTANCE_MESSAGE, "SMSG_RAID_INSTANCE_MESSAGE" },
    { SMSG_COMPRESSED_MOVES, "SMSG_COMPRESSED_MOVES" },
    { CMSG_GUILD_INFO_TEXT, "CMSG_GUILD_INFO_TEXT" },
    { SMSG_CHAT_RESTRICTED, "SMSG_CHAT_RESTRICTED" },
    { SMSG_SPLINE_SET_RUN_SPEED, "SMSG_SPLINE_SET_RUN_SPEED" },
    { SMSG_SPLINE_SET_RUN_BACK_SPEED, "SMSG_SPLINE_SET_RUN_BACK_SPEED" },
    { SMSG_SPLINE_SET_SWIM_SPEED, "SMSG_SPLINE_SET_SWIM_SPEED" },
    { SMSG_SPLINE_SET_WALK_SPEED, "SMSG_SPLINE_SET_WALK_SPEED" },
    { SMSG_SPLINE_SET_SWIM_BACK_SPEED, "SMSG_SPLINE_SET_SWIM_BACK_SPEED" },
    { SMSG_SPLINE_SET_TURN_RATE, "SMSG_SPLINE_SET_TURN_RATE" },
    { SMSG_SPLINE_MOVE_UNROOT, "SMSG_SPLINE_MOVE_UNROOT" },
    { SMSG_SPLINE_MOVE_FEATHER_FALL, "SMSG_SPLINE_MOVE_FEATHER_FALL" },
    { SMSG_SPLINE_MOVE_NORMAL_FALL, "SMSG_SPLINE_MOVE_NORMAL_FALL" },
    { SMSG_SPLINE_MOVE_SET_HOVER, "SMSG_SPLINE_MOVE_SET_HOVER" },
    { SMSG_SPLINE_MOVE_UNSET_HOVER, "SMSG_SPLINE_MOVE_UNSET_HOVER" },
    { SMSG_SPLINE_MOVE_WATER_WALK, "SMSG_SPLINE_MOVE_WATER_WALK" },
    { SMSG_SPLINE_MOVE_LAND_WALK, "SMSG_SPLINE_MOVE_LAND_WALK" },
    { SMSG_SPLINE_MOVE_START_SWIM, "SMSG_SPLINE_MOVE_START_SWIM" },
    { SMSG_SPLINE_MOVE_STOP_SWIM, "SMSG_SPLINE_MOVE_STOP_SWIM" },
    { SMSG_SPLINE_MOVE_SET_RUN_MODE, "SMSG_SPLINE_MOVE_SET_RUN_MODE" },
    { SMSG_SPLINE_MOVE_SET_WALK_MODE, "SMSG_SPLINE_MOVE_SET_WALK_MODE" },
    { CMSG_GM_NUKE_ACCOUNT, "CMSG_GM_NUKE_ACCOUNT" },
    { MSG_GM_DESTROY_CORPSE, "MSG_GM_DESTROY_CORPSE" },
    { CMSG_GM_DESTROY_ONLINE_CORPSE, "CMSG_GM_DESTROY_ONLINE_CORPSE" },
    { CMSG_ACTIVATETAXIEXPRESS, "CMSG_ACTIVATETAXIEXPRESS" },
    { SMSG_SET_FACTION_ATWAR, "SMSG_SET_FACTION_ATWAR" },
    { SMSG_GAMETIMEBIAS_SET, "SMSG_GAMETIMEBIAS_SET" },
    { CMSG_DEBUG_ACTIONS_START, "CMSG_DEBUG_ACTIONS_START" },
    { CMSG_DEBUG_ACTIONS_STOP, "CMSG_DEBUG_ACTIONS_STOP" },
    { CMSG_SET_FACTION_INACTIVE, "CMSG_SET_FACTION_INACTIVE" },
    { CMSG_SET_WATCHED_FACTION, "CMSG_SET_WATCHED_FACTION" },
    { MSG_MOVE_TIME_SKIPPED, "MSG_MOVE_TIME_SKIPPED" },
    { SMSG_SPLINE_MOVE_ROOT, "SMSG_SPLINE_MOVE_ROOT" },
    { CMSG_SET_EXPLORATION_ALL, "CMSG_SET_EXPLORATION_ALL" },
    { SMSG_INVALIDATE_PLAYER, "SMSG_INVALIDATE_PLAYER" },
    { CMSG_RESET_INSTANCES, "CMSG_RESET_INSTANCES" },
    { SMSG_INSTANCE_RESET, "SMSG_INSTANCE_RESET" },
    { SMSG_INSTANCE_RESET_FAILED, "SMSG_INSTANCE_RESET_FAILED" },
    { SMSG_UPDATE_LAST_INSTANCE, "SMSG_UPDATE_LAST_INSTANCE" },
    { MSG_RAID_TARGET_UPDATE, "MSG_RAID_TARGET_UPDATE" },
    { MSG_RAID_READY_CHECK, "MSG_RAID_READY_CHECK" },
    { CMSG_LUA_USAGE, "CMSG_LUA_USAGE" },
    { SMSG_PET_ACTION_SOUND, "SMSG_PET_ACTION_SOUND" },
    { SMSG_PET_DISMISS_SOUND, "SMSG_PET_DISMISS_SOUND" },
    { SMSG_GHOSTEE_GONE, "SMSG_GHOSTEE_GONE" },
    { CMSG_GM_UPDATE_TICKET_STATUS, "CMSG_GM_UPDATE_TICKET_STATUS" },
    { SMSG_GM_TICKET_STATUS_UPDATE, "SMSG_GM_TICKET_STATUS_UPDATE" },
    { CMSG_GMSURVEY_SUBMIT, "CMSG_GMSURVEY_SUBMIT" },
    { SMSG_UPDATE_INSTANCE_OWNERSHIP, "SMSG_UPDATE_INSTANCE_OWNERSHIP" },
    { CMSG_IGNORE_KNOCKBACK_CHEAT, "CMSG_IGNORE_KNOCKBACK_CHEAT" },
    { SMSG_CHAT_PLAYER_AMBIGUOUS, "SMSG_CHAT_PLAYER_AMBIGUOUS" },
    { MSG_DELAY_GHOST_TELEPORT, "MSG_DELAY_GHOST_TELEPORT" },
    { SMSG_SPELLINSTAKILLLOG, "SMSG_SPELLINSTAKILLLOG" },
    { SMSG_SPELL_UPDATE_CHAIN_TARGETS, "SMSG_SPELL_UPDATE_CHAIN_TARGETS" },
    { CMSG_CHAT_FILTERED, "CMSG_CHAT_FILTERED" },
    { SMSG_EXPECTED_SPAM_RECORDS, "SMSG_EXPECTED_SPAM_RECORDS" },
    { SMSG_SPELLSTEALLOG, "SMSG_SPELLSTEALLOG" },
    { CMSG_LOTTERY_QUERY_OBSOLETE, "CMSG_LOTTERY_QUERY_OBSOLETE" },
    { SMSG_LOTTERY_QUERY_RESULT_OBSOLETE, "SMSG_LOTTERY_QUERY_RESULT_OBSOLETE" },
    { CMSG_BUY_LOTTERY_TICKET_OBSOLETE, "CMSG_BUY_LOTTERY_TICKET_OBSOLETE" },
    { SMSG_LOTTERY_RESULT_OBSOLETE, "SMSG_LOTTERY_RESULT_OBSOLETE" },
    { SMSG_CHARACTER_PROFILE, "SMSG_CHARACTER_PROFILE" },
    { SMSG_CHARACTER_PROFILE_REALM_CONNECTED, "SMSG_CHARACTER_PROFILE_REALM_CONNECTED" },
    { SMSG_DEFENSE_MESSAGE, "SMSG_DEFENSE_MESSAGE" },
    { MSG_GM_RESETINSTANCELIMIT, "MSG_GM_RESETINSTANCELIMIT" },
    { SMSG_MOTD, "SMSG_MOTD" },
    { SMSG_MOVE_SET_FLIGHT, "SMSG_MOVE_SET_FLIGHT" },
    { SMSG_MOVE_UNSET_FLIGHT, "SMSG_MOVE_UNSET_FLIGHT" },
    { CMSG_MOVE_FLIGHT_ACK, "CMSG_MOVE_FLIGHT_ACK" },
    { MSG_MOVE_START_SWIM_CHEAT, "MSG_MOVE_START_SWIM_CHEAT" },
    { MSG_MOVE_STOP_SWIM_CHEAT, "MSG_MOVE_STOP_SWIM_CHEAT" },
    { CMSG_CANCEL_MOUNT_AURA, "CMSG_CANCEL_MOUNT_AURA" },
    { CMSG_CANCEL_TEMP_ENCHANTMENT, "CMSG_CANCEL_TEMP_ENCHANTMENT" },
    { CMSG_MAELSTROM_INVALIDATE_CACHE, "CMSG_MAELSTROM_INVALIDATE_CACHE" },
    { CMSG_SET_TAXI_BENCHMARK_MODE, "CMSG_SET_TAXI_BENCHMARK_MODE" },
    { CMSG_MOVE_CHNG_TRANSPORT, "CMSG_MOVE_CHNG_TRANSPORT" },
    { MSG_PARTY_ASSIGNMENT, "MSG_PARTY_ASSIGNMENT" },
    { SMSG_OFFER_PETITION_ERROR, "SMSG_OFFER_PETITION_ERROR" },
    { SMSG_RESET_FAILED_NOTIFY, "SMSG_RESET_FAILED_NOTIFY" },
    { SMSG_REAL_GROUP_UPDATE, "SMSG_REAL_GROUP_UPDATE" },
    { SMSG_INIT_EXTRA_AURA_INFO, "SMSG_INIT_EXTRA_AURA_INFO" },
    { SMSG_SET_EXTRA_AURA_INFO, "SMSG_SET_EXTRA_AURA_INFO" },
    { SMSG_SET_EXTRA_AURA_INFO_NEED_UPDATE, "SMSG_SET_EXTRA_AURA_INFO_NEED_UPDATE" },
    { SMSG_SPELL_CHANCE_PROC_LOG, "SMSG_SPELL_CHANCE_PROC_LOG" },
    { CMSG_MOVE_SET_RUN_SPEED, "CMSG_MOVE_SET_RUN_SPEED" },
    { SMSG_DISMOUNT, "SMSG_DISMOUNT" },
    { MSG_RAID_READY_CHECK_CONFIRM, "MSG_RAID_READY_CHECK_CONFIRM" },
    { SMSG_CLEAR_TARGET, "SMSG_CLEAR_TARGET" },
    { CMSG_BOT_DETECTED, "CMSG_BOT_DETECTED" },
    { SMSG_KICK_REASON, "SMSG_KICK_REASON" },
    { MSG_RAID_READY_CHECK_FINISHED, "MSG_RAID_READY_CHECK_FINISHED" },
    { CMSG_TARGET_CAST, "CMSG_TARGET_CAST" },
    { CMSG_TARGET_SCRIPT_CAST, "CMSG_TARGET_SCRIPT_CAST" },
    { CMSG_CHANNEL_DISPLAY_LIST, "CMSG_CHANNEL_DISPLAY_LIST" },
    { CMSG_GET_CHANNEL_MEMBER_COUNT, "CMSG_GET_CHANNEL_MEMBER_COUNT" },
    { SMSG_CHANNEL_MEMBER_COUNT, "SMSG_CHANNEL_MEMBER_COUNT" },
    { CMSG_DEBUG_LIST_TARGETS, "CMSG_DEBUG_LIST_TARGETS" },
    { SMSG_DEBUG_LIST_TARGETS, "SMSG_DEBUG_LIST_TARGETS" },
    { CMSG_PARTY_SILENCE, "CMSG_PARTY_SILENCE" },
    { CMSG_PARTY_UNSILENCE, "CMSG_PARTY_UNSILENCE" },
    { MSG_NOTIFY_PARTY_SQUELCH, "MSG_NOTIFY_PARTY_SQUELCH" },
    { SMSG_COMSAT_RECONNECT_TRY, "SMSG_COMSAT_RECONNECT_TRY" },
    { SMSG_COMSAT_DISCONNECT, "SMSG_COMSAT_DISCONNECT" },
    { SMSG_COMSAT_CONNECT_FAIL, "SMSG_COMSAT_CONNECT_FAIL" },
    { CMSG_SET_CHANNEL_WATCH, "CMSG_SET_CHANNEL_WATCH" },
    { SMSG_USERLIST_ADD, "SMSG_USERLIST_ADD" },
    { SMSG_USERLIST_REMOVE, "SMSG_USERLIST_REMOVE" },
    { SMSG_USERLIST_UPDATE, "SMSG_USERLIST_UPDATE" },
    { CMSG_CLEAR_CHANNEL_WATCH, "CMSG_CLEAR_CHANNEL_WATCH" },
    { SMSG_GOGOGO_OBSOLETE, "SMSG_GOGOGO_OBSOLETE" },
    { SMSG_ECHO_PARTY_SQUELCH, "SMSG_ECHO_PARTY_SQUELCH" },
    { CMSG_SPELLCLICK, "CMSG_SPELLCLICK" },
    { SMSG_LOOT_LIST, "SMSG_LOOT_LIST" },
    { MSG_GUILD_PERMISSIONS, "MSG_GUILD_PERMISSIONS" },
    { MSG_GUILD_EVENT_LOG_QUERY, "MSG_GUILD_EVENT_LOG_QUERY" },
    { CMSG_MAELSTROM_RENAME_GUILD, "CMSG_MAELSTROM_RENAME_GUILD" },
    { CMSG_GET_MIRRORIMAGE_DATA, "CMSG_GET_MIRRORIMAGE_DATA" },
    { SMSG_MIRRORIMAGE_DATA, "SMSG_MIRRORIMAGE_DATA" },
    { SMSG_FORCE_DISPLAY_UPDATE, "SMSG_FORCE_DISPLAY_UPDATE" },
    { SMSG_SPELL_CHANCE_RESIST_PUSHBACK, "SMSG_SPELL_CHANCE_RESIST_PUSHBACK" },
    { CMSG_IGNORE_DIMINISHING_RETURNS_CHEAT, "CMSG_IGNORE_DIMINISHING_RETURNS_CHEAT" },
    { SMSG_IGNORE_DIMINISHING_RETURNS_CHEAT, "SMSG_IGNORE_DIMINISHING_RETURNS_CHEAT" },
    { CMSG_KEEP_ALIVE, "CMSG_KEEP_ALIVE" },
    { SMSG_RAID_READY_CHECK_ERROR, "SMSG_RAID_READY_CHECK_ERROR" },
    { CMSG_OPT_OUT_OF_LOOT, "CMSG_OPT_OUT_OF_LOOT" },
    { CMSG_SET_GRANTABLE_LEVELS, "CMSG_SET_GRANTABLE_LEVELS" },
    { CMSG_GRANT_LEVEL, "CMSG_GRANT_LEVEL" },
    { CMSG_DECLINE_CHANNEL_INVITE, "CMSG_DECLINE_CHANNEL_INVITE" },
    { CMSG_GROUPACTION_THROTTLED, "CMSG_GROUPACTION_THROTTLED" },
    { SMSG_OVERRIDE_LIGHT, "SMSG_OVERRIDE_LIGHT" },
    { SMSG_TOTEM_CREATED, "SMSG_TOTEM_CREATED" },
    { CMSG_TOTEM_DESTROYED, "CMSG_TOTEM_DESTROYED" },
    { CMSG_EXPIRE_RAID_INSTANCE, "CMSG_EXPIRE_RAID_INSTANCE" },
    { CMSG_NO_SPELL_VARIANCE, "CMSG_NO_SPELL_VARIANCE" },
    { CMSG_QUESTGIVER_STATUS_MULTIPLE_QUERY, "CMSG_QUESTGIVER_STATUS_MULTIPLE_QUERY" },
    { SMSG_QUESTGIVER_STATUS_MULTIPLE, "SMSG_QUESTGIVER_STATUS_MULTIPLE" },
    { CMSG_QUERY_SERVER_BUCK_DATA, "CMSG_QUERY_SERVER_BUCK_DATA" },
    { CMSG_CLEAR_SERVER_BUCK_DATA, "CMSG_CLEAR_SERVER_BUCK_DATA" },
    { SMSG_SERVER_BUCK_DATA, "SMSG_SERVER_BUCK_DATA" },
    { SMSG_SEND_UNLEARN_SPELLS, "SMSG_SEND_UNLEARN_SPELLS" },
    { SMSG_PROPOSE_LEVEL_GRANT, "SMSG_PROPOSE_LEVEL_GRANT" },
    { CMSG_ACCEPT_LEVEL_GRANT, "CMSG_ACCEPT_LEVEL_GRANT" },
    { SMSG_REFER_A_FRIEND_FAILURE, "SMSG_REFER_A_FRIEND_FAILURE" },
    { SMSG_SUMMON_CANCEL, "SMSG_SUMMON_CANCEL" },
    { 0, NULL }
};

/*! Decrypts the header after the session key has been deducted as described in the top level comment. */
static guint8*
get_decrypted_header(const guint8 session_key[WOWW_SESSION_KEY_LENGTH],
                     guint8* idx,
                     guint8* last_encrypted_value,
                     const guint8* header,
                     guint8 header_size) {
    guint8* decrypted_header = wmem_alloc0(wmem_file_scope(), WOWW_HEADER_ARRAY_ALLOC_SIZE);

    for (guint8 i = 0; i < header_size; i++) {

        // x = (E - L) ^ S as described in top level comment
        decrypted_header[i] = (header[i] - *last_encrypted_value) ^ session_key[*idx];

        *last_encrypted_value = header[i];
        *idx = (*idx + 1) % WOWW_SESSION_KEY_LENGTH;
    }

    return decrypted_header;
}

/*! Deduces the session key values as described in the top level comment. */
static void
deduce_header(guint8 session_key[WOWW_SESSION_KEY_LENGTH],
              bool known_indices[WOWW_SESSION_KEY_LENGTH],
              const guint8* header,
              WowwParticipant_t* participant) {
    // Skip size field (2 bytes) and 2 least significant bytes of opcode field
    participant->idx = (participant->idx + 2 + 2) % WOWW_SESSION_KEY_LENGTH;
    // Set last encrypted value to what it's supposed to be
    participant->last_encrypted_value = header[3];

    // 0 ^ (E - L) as described in top level comment
    session_key[participant->idx] = 0 ^ (header[4] - participant->last_encrypted_value);
    known_indices[participant->idx] = true;
    participant->idx = (participant->idx + 1) % WOWW_SESSION_KEY_LENGTH;
    participant->last_encrypted_value = header[4];

    session_key[participant->idx] = 0 ^ (header[5] - participant->last_encrypted_value);
    known_indices[participant->idx] = true;
    participant->idx = (participant->idx + 1) % WOWW_SESSION_KEY_LENGTH;
    participant->last_encrypted_value = header[5];
}

/*! Returns true if all necessary values of the session key are fully known. */
static gboolean
session_key_is_fully_deduced(const bool known_indices[WOWW_SESSION_KEY_LENGTH],
                             guint8 header_length,
                             guint8 start_index) {
    gboolean fully_deduced = true;
    for (guint8 i = 0; i < header_length; i++) {
        if (!known_indices[(start_index + i) % WOWW_SESSION_KEY_LENGTH]) {
            fully_deduced = false;
        }
    }
    return fully_deduced;
}

/*! Returns either a pointer to a valid decrypted header, or NULL if no such header exists yet. */
static WowwDecryptedHeader_t*
handle_packet_header(packet_info* pinfo,
                     tvbuff_t* tvb,
                     WowwParticipant_t* participant,
                     WowwConversation_t* wowwConversation,
                     guint8 headerSize,
                     guint8 index_in_pdu,
                     gint tvb_offset) {
    guint64 key = ((guint64)index_in_pdu << 32) | pinfo->num;

    guint8* decrypted_header = wmem_map_lookup(wowwConversation->decrypted_headers, &key);

    if (decrypted_header) {
        // Header has already been decrypted
        return (WowwDecryptedHeader_t*)decrypted_header;
    }

    if (participant->stopped_at != 0 && participant->stopped_at != key) {
        // We can't continue decrypt further server messages since we
        // don't know the status of the session key index for any message
        // except the last one we couldn't decrypt.
        return NULL;
    }

    // First time we see this header, we need to decrypt it
    guint8* header = wmem_alloc0(wmem_packet_scope(), WOWW_HEADER_ARRAY_ALLOC_SIZE);
    for (int i = 0; i < headerSize; i++) {
        header[i] = tvb_get_guint8(tvb, tvb_offset + i);
    }

    // If we're seeing the first header
    if (!participant->unencrypted_packet_encountered) {
        // Packet is unencrypted, no need to do anything

        // There is only one unencrypted header each for server and client
        participant->unencrypted_packet_encountered = true;

        decrypted_header = wmem_alloc0(wmem_file_scope(), WOWW_HEADER_ARRAY_ALLOC_SIZE);
        memcpy(decrypted_header, header, headerSize);

        guint64* allocated_key = wmem_alloc0(wmem_file_scope(), sizeof(guint64));
        *allocated_key = key;

        wmem_map_insert(wowwConversation->decrypted_headers, allocated_key, decrypted_header);

        return (WowwDecryptedHeader_t*)decrypted_header;
    }

    WowwPreviousValues_t * original_header_values = wmem_map_lookup(wowwConversation->headers_need_decryption, &key);

    if (original_header_values && !session_key_is_fully_deduced(wowwConversation->known_indices, headerSize, original_header_values->idx)) {
        // If we have seen the header before AND
        // we still can't decrypt it
        // there's nothing to do but wait until we get more information
        return NULL;
    }

    if (!original_header_values && !session_key_is_fully_deduced(wowwConversation->known_indices, headerSize, participant->idx)) {
        // If we haven't seen the header before AND
        // we can't decrypt it now
        // we make sure it gets decrypted later
        WowwPreviousValues_t* array_index = wmem_alloc0(wmem_file_scope(), sizeof(WowwPreviousValues_t));
        array_index->idx = participant->idx;
        array_index->last_encrypted_value = participant->last_encrypted_value;

        guint64* allocated_key = wmem_alloc0(wmem_file_scope(), sizeof(guint64));
        *allocated_key = key;

        wmem_map_insert(wowwConversation->headers_need_decryption, allocated_key, array_index);

        // If it's a server header we can use it to deduce the session key
        if (WOWW_CLIENT_TO_SERVER) {
            deduce_header(wowwConversation->session_key, wowwConversation->known_indices, header, participant);
        } else {
            // We don't know if this PDU contains several messages or just one, so we need
            // to stop parsing server messages until we have fully decrypted this one.
            participant->stopped_at = key;
            // Skip the packet, but remember to acknowledge that values changed
            participant->idx = (participant->idx + headerSize) % WOWW_SESSION_KEY_LENGTH;
            participant->last_encrypted_value = header[headerSize - 1];
        }

        return NULL;
    }

    guint8* idx = &participant->idx;
    guint8* last_encrypted_value = &participant->last_encrypted_value;

    // If this is an out of order packet we must use the original state
    if (original_header_values) {
        // We can now (as best as possible) assume that decryption
        // is in the right place.
        participant->stopped_at = 0;
        // We do not care about how these values are mutated since
        // they are never going to be used again.
        idx = &original_header_values->idx;
        last_encrypted_value = &original_header_values->last_encrypted_value;

        // No need to decrypt it again
        wmem_map_remove(wowwConversation->headers_need_decryption, &key);
    }

    decrypted_header = get_decrypted_header(wowwConversation->session_key,
                                            idx,
                                            last_encrypted_value,
                                            header,
                                            headerSize);

    guint64* allocated_key = wmem_alloc0(wmem_file_scope(), sizeof(guint64));
    *allocated_key = key;

    // The header has been fully decrypted, cache it for future use
    wmem_map_insert(wowwConversation->decrypted_headers, allocated_key, decrypted_header);

    return (WowwDecryptedHeader_t*)decrypted_header;
}

static gint32
get_null_terminated_string_length( tvbuff_t* tvb,
                                   gint32 offset)
{
    const gint32 maximum_length = 255;
    for (gint32 length = 0; length < maximum_length; length++) {
        guint8 character = tvb_get_guint8(tvb, offset + length);
        if (character == 0) {
            // Include the null character in the length
            return length + 1;
        }
    }

    return 0;
}

static void
parse_SMSG_CHAR_ENUM(proto_tree* tree,
                     tvbuff_t* tvb,
                     gint32 offset)
{
    gint32 len = 1;
    guint8 amount_of_characters = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_woww_amount_of_characters, tvb,
                        offset, len, ENC_NA);
    offset += len;
    for (guint8 i = 0; i < amount_of_characters; i++) {
        const gint length_of_id = 8;
        const gint length_of_fields_after_name = 150;
        // Set the tree name now and append extra info to it later when we get it
        guint8* character_name = tvb_get_stringz_enc(wmem_packet_scope(), tvb,
                                                     offset + length_of_id,
                                                     &len, ENC_UTF_8);
        proto_tree* char_tree = proto_tree_add_subtree(tree,
                                                       tvb,
                                                       offset,
                                                       length_of_id + len + length_of_fields_after_name,
                                                       ett_character,
                                                       NULL,
                                                       character_name);

        len = length_of_id;
        proto_tree_add_item(char_tree, hf_woww_character_guid, tvb,
                            offset, len, ENC_LITTLE_ENDIAN);
        offset += len;

        len = get_null_terminated_string_length(tvb, offset);
        proto_tree_add_item(char_tree, hf_woww_character_name, tvb,
                            offset, len, ENC_UTF_8|ENC_NA);
        offset += len;

        len = 1;
        guint8 race = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(char_tree, hf_woww_character_race, tvb,
                            offset, len, ENC_NA);
        offset += len;

        guint8 class = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(char_tree, hf_woww_character_class, tvb,
                            offset, len, ENC_NA);
        offset += len;

        proto_tree_add_item(char_tree, hf_woww_character_gender, tvb,
                            offset, len, ENC_NA);
        offset += len;

        proto_tree_add_item(char_tree, hf_woww_character_skin, tvb,
                            offset, len, ENC_NA);
        offset += len;

        proto_tree_add_item(char_tree, hf_woww_character_face, tvb,
                            offset, len, ENC_NA);
        offset += len;

        proto_tree_add_item(char_tree, hf_woww_character_hairstyle, tvb,
                            offset, len, ENC_NA);
        offset += len;

        proto_tree_add_item(char_tree, hf_woww_character_haircolor, tvb,
                            offset, len, ENC_NA);
        offset += len;

        proto_tree_add_item(char_tree, hf_woww_character_facialhair, tvb,
                            offset, len, ENC_NA);
        offset += len;

        guint8 level = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(char_tree, hf_woww_character_level, tvb,
                            offset, len, ENC_NA);
        offset += len;

        proto_item_append_text(char_tree,
                               " (%i %s %s)",
                               level,
                               val_to_str_const(race, races_strings, "Unknown"),
                               val_to_str_const(class, classes_strings, "Unknown"));

        len = 4;
        proto_tree_add_item(char_tree, hf_woww_character_zone, tvb,
                            offset, len, ENC_LITTLE_ENDIAN);
        offset += len;

        proto_tree_add_item(char_tree, hf_woww_character_map, tvb,
                            offset, len, ENC_LITTLE_ENDIAN);
        offset += len;

        proto_tree_add_item(char_tree, hf_woww_character_position_x, tvb,
                            offset, len, ENC_LITTLE_ENDIAN);
        offset += len;

        proto_tree_add_item(char_tree, hf_woww_character_position_y, tvb,
                            offset, len, ENC_LITTLE_ENDIAN);
        offset += len;

        proto_tree_add_item(char_tree, hf_woww_character_position_z, tvb,
                            offset, len, ENC_LITTLE_ENDIAN);
        offset += len;

        proto_tree_add_item(char_tree, hf_woww_character_guild_id, tvb,
                            offset, len, ENC_LITTLE_ENDIAN);
        offset += len;

        proto_tree_add_item(char_tree, hf_woww_character_flags, tvb,
                            offset, len, ENC_LITTLE_ENDIAN);
        offset += len;

        len = 1;
        proto_tree_add_item(char_tree, hf_woww_character_first_login, tvb,
                            offset, len, ENC_NA);
        offset += len;

        len = 4;
        proto_tree_add_item(char_tree, hf_woww_character_pet_display_id, tvb,
                            offset, len, ENC_NA);
        offset += len;

        proto_tree_add_item(char_tree, hf_woww_character_pet_level, tvb,
                            offset, len, ENC_NA);
        offset += len;

        proto_tree_add_item(char_tree, hf_woww_character_pet_family, tvb,
                            offset, len, ENC_NA);
        offset += len;

        proto_tree* equipment_tree = proto_tree_add_subtree(char_tree,
                                                            tvb,
                                                            offset,
                                                            19 * 5,
                                                            ett_character,
                                                            NULL,
                                                            "Equipment");

        for (gint equipment_slot = 0; equipment_slot < 20; equipment_slot++) {
            len = 4;
            proto_tree_add_item(equipment_tree, hf_woww_character_equipment_display_id, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            offset += len;

            len = 1;
            proto_tree_add_item(equipment_tree, hf_woww_character_equipment_inventory_type, tvb,
                                offset, len, ENC_NA);
            offset += len;
        }
    }
}

static void
add_body_fields(guint32 opcode,
                proto_tree* tree,
                tvbuff_t* tvb,
                gint32 offset,
                gint32 offset_packet_end)
{
    gint32 len = 0;
    switch (opcode) {
        case SMSG_AUTH_CHALLENGE:
            len = 4;
            proto_tree_add_item(tree, hf_woww_challenge_seed, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            break;
        case CMSG_AUTH_SESSION:
            len = 4;
            proto_tree_add_item(tree, hf_woww_build, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            offset += len;

            proto_tree_add_item(tree, hf_woww_server_id, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            offset += len;

            len = get_null_terminated_string_length(tvb, offset);
            proto_tree_add_item(tree, hf_woww_account_name, tvb,
                                offset, len, ENC_UTF_8|ENC_NA);
            offset += len;

            len = 4;
            proto_tree_add_item(tree, hf_woww_challenge_seed, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            offset += len;

            len = 20;
            proto_tree_add_item(tree, hf_woww_client_proof, tvb,
                                offset, len, ENC_NA);
            offset += len;

            len = 4;
            proto_tree_add_item(tree, hf_woww_decompressed_addon_size, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            offset += len;

            len = offset_packet_end - offset;
            proto_tree_add_item(tree, hf_woww_addon_info, tvb,
                                offset, len, ENC_NA);
            break;
        case SMSG_AUTH_RESPONSE:
            len = 4;
            proto_tree_add_item(tree, hf_woww_result, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            // There might more fields depending on the value in login_result.
            // Not implemented currently because they aren't that important.
            break;
        case SMSG_CHAR_ENUM:
            parse_SMSG_CHAR_ENUM(tree, tvb, offset);
            break;
        case CMSG_SET_SELECTION:
            /* Fallthrough */
        case CMSG_CHAR_DELETE:
            /* Fallthrough */
        case CMSG_SET_ACTIVE_MOVER:
            /* Fallthrough */
        case CMSG_NAME_QUERY:
            /* Fallthrough */
        case CMSG_PLAYER_LOGIN:
            len = 8;
            proto_tree_add_item(tree, hf_woww_character_guid, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            break;
        case SMSG_LOGIN_VERIFY_WORLD:
            len = 4;
            proto_tree_add_item(tree, hf_woww_character_map, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            offset += len;
            proto_tree_add_item(tree, hf_woww_character_position_x, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            offset += len;
            proto_tree_add_item(tree, hf_woww_character_position_y, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            offset += len;
            proto_tree_add_item(tree, hf_woww_character_position_z, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            offset += len;
            proto_tree_add_item(tree, hf_woww_character_orientation, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            offset += len;
            break;
        case SMSG_TUTORIAL_FLAGS:
            len = 4;
            for (gint i = 0; i < 8; i++) {
                proto_tree_add_item(tree, hf_woww_tutorial_flag, tvb,
                                    offset, len, ENC_LITTLE_ENDIAN);
                offset += len;
            }
            break;
        case CMSG_PING:
            len = 4;
            proto_tree_add_item(tree, hf_woww_sequence_id, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            offset += len;
            proto_tree_add_item(tree, hf_woww_latency, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            break;
        case SMSG_PONG:
            len = 4;
            proto_tree_add_item(tree, hf_woww_sequence_id, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            break;
        case SMSG_CHARACTER_LOGIN_FAILED:
            /* Fallthrough */
        case SMSG_CHAR_DELETE:
            /* Fallthrough */
        case SMSG_CHAR_CREATE:
            len = 1;
            proto_tree_add_item(tree, hf_woww_result, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            break;
        case SMSG_NAME_QUERY_RESPONSE:
            len = 8;
            proto_tree_add_item(tree, hf_woww_character_guid, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            offset += len;

            len = get_null_terminated_string_length(tvb, offset);
            proto_tree_add_item(tree, hf_woww_character_name, tvb,
                                offset, len, ENC_UTF_8|ENC_NA);
            offset += len;

            len = get_null_terminated_string_length(tvb, offset);
            proto_tree_add_item(tree, hf_woww_realm_name, tvb,
                                offset, len, ENC_UTF_8|ENC_NA);
            offset += len;

            len = 4;
            proto_tree_add_item(tree, hf_woww_character_race, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            offset += len;

            proto_tree_add_item(tree, hf_woww_character_gender, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            offset += len;

            proto_tree_add_item(tree, hf_woww_character_class, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            break;
        case CMSG_CHAR_RENAME:
            len = 8;
            proto_tree_add_item(tree, hf_woww_character_guid, tvb,
                                offset, len, ENC_LITTLE_ENDIAN);
            offset += len;

            len = get_null_terminated_string_length(tvb, offset);
            proto_tree_add_item(tree, hf_woww_realm_name, tvb,
                                offset, len, ENC_UTF_8|ENC_NA);
            offset += len;
            break;
        default:
            break;
    }
}

static gint
add_header_to_tree(WowwDecryptedHeader_t* decrypted_header,
                   proto_tree* tree,
                   tvbuff_t* tvb,
                   packet_info* pinfo,
                   guint8 headerSize,
                   gint start_offset)
{
    const guint16 size_field_width = 2;
    // Size field does not count in the reported size, so we need to add it.
    const guint16 packet_size = (decrypted_header->size[0] << 8 | decrypted_header->size[1]) + size_field_width;

    proto_tree* ti = proto_tree_add_item(tree, proto_woww, tvb, start_offset, packet_size, ENC_NA);

    proto_tree* woww_tree = proto_item_add_subtree(ti, ett_message);

    // Add to tree
    tvbuff_t *next_tvb = tvb_new_child_real_data(tvb, (guint8*)decrypted_header, headerSize, headerSize);
    add_new_data_source(pinfo, next_tvb, "Decrypted Header");

    // We're indexing into another tvb
    gint offset = 0;
    gint len = size_field_width;
    proto_tree_add_item(woww_tree, hf_woww_size, next_tvb,
                        offset, len, ENC_BIG_ENDIAN);
    offset += len;

    guint32 opcode = 0;
    if (WOWW_SERVER_TO_CLIENT) {
        len = 2;
        opcode = tvb_get_guint16(next_tvb, offset, ENC_LITTLE_ENDIAN);
    } else if (WOWW_CLIENT_TO_SERVER) {
        len = 4;
        opcode = tvb_get_guint32(next_tvb, offset, ENC_LITTLE_ENDIAN);
    }

    proto_tree_add_item(woww_tree, hf_woww_opcode, next_tvb,
                        offset, len, ENC_LITTLE_ENDIAN);
    offset += len;

    if (start_offset == 0) {
        // First message
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(opcode,
                                                             world_packet_strings,
                                                             "Encrypted Header"));
    }
    else {
        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(opcode,
                                                                world_packet_strings,
                                                                "Encrypted Header"));
    }

    proto_item_set_text(woww_tree, "%s", val_to_str_const(opcode,
                                                    world_packet_strings,
                                                    "Encrypted Header"));

    gint offset_packet_end = start_offset + (gint)packet_size;

    // Remember to go back to original tvb
    add_body_fields(opcode, woww_tree, tvb, start_offset + headerSize, offset_packet_end);

    return offset_packet_end;
}

static int
dissect_woww(tvbuff_t *tvb,
             packet_info *pinfo,
             proto_tree *tree,
             void *data _U_)
{
    if (tvb_reported_length(tvb) < WOWW_MIN_LENGTH)
        return 0;

    if (tvb_captured_length(tvb) < 1)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WOWW");

    col_set_str(pinfo->cinfo, COL_INFO, "Session Key Not Known Yet");

    // Get conversation data
    conversation_t* conv = find_or_create_conversation(pinfo);
    WowwConversation_t* wowwConversation = (WowwConversation_t *)conversation_get_proto_data(conv,
                                                                                             proto_woww);
    if (wowwConversation == NULL) {
        // Assume that file scope means for the lifetime of the dissection
        wowwConversation = (WowwConversation_t*) wmem_new0(wmem_file_scope(), WowwConversation_t);
        conversation_add_proto_data(conv, proto_woww, wowwConversation);
        wowwConversation->decrypted_headers = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
        wowwConversation->headers_need_decryption = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
    }

    // Isolate session key for packet
    WowwParticipant_t* participant;
    guint8 headerSize = 4;

    if (WOWW_SERVER_TO_CLIENT) {
        participant = &wowwConversation->server;
        headerSize = 4;
    } else {
        participant = &wowwConversation->client;
        headerSize = 6;
    }

    proto_tree* ti = proto_tree_add_item(tree, proto_woww, tvb, 0, -1, ENC_NA);

    proto_tree* woww_tree = proto_item_add_subtree(ti, ett_woww);

    gint pdu_offset = 0;
    gint reported_length = (gint)tvb_reported_length(tvb);
    guint8 header_index = 0;
    do {
        WowwDecryptedHeader_t* decrypted_header = handle_packet_header(pinfo, tvb, participant, wowwConversation, headerSize, header_index, pdu_offset);
        if (!decrypted_header) {
            return tvb_captured_length(tvb);
        }

        pdu_offset = add_header_to_tree(decrypted_header, woww_tree, tvb, pinfo, headerSize, pdu_offset);

        header_index++;
    } while (pdu_offset < reported_length);

    return tvb_captured_length(tvb);
}

void
proto_register_woww(void)
{
    static hf_register_info hf[] = {
        { &hf_woww_size,
          { "Size", "woww.size",
            FT_UINT16, BASE_HEX_DEC, NULL, 0,
            "Size of the packet including opcode field but not including size field", HFILL }
        },
        { &hf_woww_opcode,
          { "Opcode", "woww.opcode",
            FT_UINT32, BASE_HEX, VALS(world_packet_strings), 0,
            "Opcode of the packet", HFILL }
        },
        { &hf_woww_challenge_seed,
          { "Challenge Seed", "woww.challenge_seed",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Seed used to verify session key", HFILL }
        },
        { &hf_woww_server_id,
          { "Server Id", "woww.server_id",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Id of the server the client is connecting to", HFILL }
        },
        { &hf_woww_build,
          { "Client Build", "woww.client_build",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Client build/revision", HFILL }
        },
        { &hf_woww_client_proof,
          { "Client Proof", "woww.client_proof",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Client proof calculated using seeds and session key", HFILL }
        },
        { &hf_woww_decompressed_addon_size,
          { "Decompressed Addon Size", "woww.decompressed_addon_size",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Size of the Addon Info after decompression", HFILL }
        },
        { &hf_woww_addon_info,
          { "Compressed Addon Info", "woww.addon_info",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_woww_account_name,
          { "Account Name", "woww.account_name",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_woww_result,
          { "Result", "woww.result",
            FT_UINT32, BASE_HEX, VALS(account_result_strings), 0,
            NULL, HFILL }
        },
        { &hf_woww_amount_of_characters,
          { "Amount of Characters", "woww.amount_of_characters",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_woww_character_guid,
            { "Character GUID", "woww.character_guid",
              FT_UINT64, BASE_HEX_DEC, NULL, 0,
              "Globally Unique Identifier of character", HFILL }
        },
        { &hf_woww_character_name,
            { "Character Name", "woww.character_name",
              FT_STRINGZ, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_realm_name,
            { "Realm Name", "woww.realm_name",
              FT_STRINGZ, BASE_NONE, NULL, 0,
              "Optional realm name shown after the character name", HFILL }
        },
        { &hf_woww_character_race,
            { "Race", "woww.race",
              FT_UINT8, BASE_HEX, VALS(races_strings), 0,
              NULL, HFILL }
        },
        { &hf_woww_character_class,
            { "Class", "woww.class",
              FT_UINT8, BASE_HEX, VALS(classes_strings), 0,
              NULL, HFILL }
        },
        { &hf_woww_character_gender,
            { "Gender", "woww.gender",
              FT_UINT8, BASE_HEX, VALS(genders_strings), 0,
              NULL, HFILL }
        },
        { &hf_woww_character_skin,
            { "Skin Color", "woww.skin",
              FT_UINT8, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_face,
            { "Face", "woww.face",
              FT_UINT8, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_hairstyle,
            { "Hair Style", "woww.hairstyle",
              FT_UINT8, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_haircolor,
            { "Hair Color", "woww.haircolor",
              FT_UINT8, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_facialhair,
            { "Facial Hair/Accessory", "woww.facialhair",
              FT_UINT8, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_level,
            { "Level", "woww.level",
              FT_UINT8, BASE_DEC_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_zone,
            { "Zone", "woww.zone",
              FT_UINT32, BASE_DEC_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_map,
            { "Map", "woww.map",
              FT_UINT32, BASE_DEC_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_position_x,
            { "Position X", "woww.position_x",
              FT_FLOAT, BASE_FLOAT, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_position_y,
            { "Position Y", "woww.position_y",
              FT_FLOAT, BASE_FLOAT, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_position_z,
            { "Position Z", "woww.position_z",
              FT_FLOAT, BASE_FLOAT, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_orientation,
            { "Orientation", "woww.orientation",
              FT_FLOAT, BASE_FLOAT, NULL, 0,
              "Heading in degrees, with 0 being north", HFILL }
        },
        { &hf_woww_character_guild_id,
            { "Guild ID", "woww.guild_id",
              FT_UINT32, BASE_HEX_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_flags,
            { "Character Flags", "woww.character_flags",
              FT_UINT32, BASE_HEX_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_first_login,
            { "First Login", "woww.first_login",
              FT_UINT32, BASE_HEX_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_pet_display_id,
            { "Pet Display Id", "woww.pet_display_id",
              FT_UINT32, BASE_HEX_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_pet_level,
            { "Pet Level", "woww.pet_level",
              FT_UINT32, BASE_HEX_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_pet_family,
            { "Pet Family", "woww.pet_family",
              FT_UINT32, BASE_HEX_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_equipment_display_id,
            { "Display ID", "woww.equipment_display_id",
              FT_UINT32, BASE_HEX_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_character_equipment_inventory_type,
            { "Inventory Type", "woww.equipment_inventory_type",
              FT_UINT8, BASE_HEX_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_tutorial_flag,
            { "Tutorial Flag", "woww.tutorial_flag",
              FT_UINT32, BASE_HEX_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_sequence_id,
            { "Sequence Id", "woww.sequence_id",
              FT_UINT32, BASE_HEX_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_woww_latency,
            { "Latency", "woww.latency",
              FT_UINT32, BASE_HEX_DEC, NULL, 0,
              "Round time in milliseconds", HFILL }
        },
    };

    static gint *ett[] = {
        &ett_woww,
        &ett_message,
        &ett_character
    };

    proto_woww = proto_register_protocol("World of Warcraft World",
            "WOWW", "woww");

    proto_register_field_array(proto_woww, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    prefs_register_protocol(proto_woww,
            NULL);

}

void
proto_reg_handoff_woww(void)
{
    dissector_handle_t woww_handle = create_dissector_handle(dissect_woww, proto_woww);
    dissector_add_uint_with_preference("tcp.port", WOWW_TCP_PORT, woww_handle);
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
