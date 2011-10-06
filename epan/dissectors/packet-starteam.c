/* packet-starteam.c
 * Routines for Borland StarTeam packet dissection
 *
 * metatech <metatech[AT]flashmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*  StarTeam in a nutshell
*
*   StarTeam is a Software Change & Configuration Management Tool (like CVS)
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include "packet-tcp.h"

static int proto_starteam = -1;

static int hf_starteam_mdh_session_tag = -1;
static int hf_starteam_mdh_ctimestamp = -1;
static int hf_starteam_mdh_flags = -1;
static int hf_starteam_mdh_keyid = -1;
static int hf_starteam_mdh_reserved = -1;
static int hf_starteam_ph_signature = -1;
static int hf_starteam_ph_packet_size = -1;
static int hf_starteam_ph_data_size = -1;
static int hf_starteam_ph_data_flags = -1;
static int hf_starteam_id_revision_level = -1;
static int hf_starteam_id_client = -1;
static int hf_starteam_id_connect = -1;
static int hf_starteam_id_component = -1;
static int hf_starteam_id_command = -1;
static int hf_starteam_id_command_time = -1;
static int hf_starteam_id_command_userid = -1;
static int hf_starteam_data_data = -1;

static gint ett_starteam = -1;
static gint ett_starteam_mdh = -1;
static gint ett_starteam_ph = -1;
static gint ett_starteam_id = -1;
static gint ett_starteam_data = -1;

static dissector_handle_t starteam_tcp_handle;

static gboolean starteam_desegment = TRUE;

#define STARTEAM_MAGIC    0x416C616E /* "Alan" */

#define STARTEAM_SRVR_CMD_GET_SESSION_TAG                      1
#define STARTEAM_SRVR_CMD_GET_REQUIRED_ENCRYPTION_LEVEL        2
#define STARTEAM_SRVR_CMD_GET_SERVER_PARAMS                    3
#define STARTEAM_SRVR_CMD_SERVER_CONNECT                       4
#define STARTEAM_SRVR_CMD_SERVER_RECONNECT                     5
#define STARTEAM_SRVR_CMD_BEGIN_LOGIN                          10
#define STARTEAM_SRVR_CMD_KEY_EXCHANGE_PHASE0                  11
#define STARTEAM_SRVR_CMD_KEY_EXCHANGE_PHASE12                 12
#define STARTEAM_SRVR_CMD_KEY_EXCHANGE_PHASE3                  13
#define STARTEAM_SRVR_CMD_SERVER_LOGIN                         14
#define STARTEAM_SRVR_CMD_GET_PROJECT_LIST                     1001
#define STARTEAM_SRVR_CMD_GET_PROJECT_VIEWS                    1002
#define STARTEAM_SRVR_CMD_PROJECT_LOGIN                        1011
#define STARTEAM_SRVR_CMD_PROJECT_LOGOUT                       1013
#define STARTEAM_PROJ_CMD_LIST_SET_READ                        1014
#define STARTEAM_PROJ_CMD_LIST_ADD_ATTACHMENT                  1015
#define STARTEAM_PROJ_CMD_LIST_GET_ATTACHMENT                  1016
#define STARTEAM_PROJ_CMD_LIST_REMOVE_ATTACHMENT               1017
#define STARTEAM_PROJ_CMD_MAIL_LIST_ITEMS                      1018
#define STARTEAM_PROJ_CMD_LIST_ANY_NEWITEMS                    1020
#define STARTEAM_PROJ_CMD_LIST_GET_NEWITEMS                    1021
#define STARTEAM_SRVR_CMD_RELEASE_CLIENT                       1021
#define STARTEAM_SRVR_CMD_UPDATE_SERVER_INFO                   1022
#define STARTEAM_SRVR_CMD_GET_USAGE_DATA                       1023
#define STARTEAM_SRVR_CMD_GET_LICENSE_INFO                     1024
#define STARTEAM_PROJ_CMD_FILTER_ADD                           1030
#define STARTEAM_PROJ_CMD_FILTER_MODIFY                        1031
#define STARTEAM_PROJ_CMD_FILTER_GET                           1032
#define STARTEAM_PROJ_CMD_FILTER_GET_LIST                      1033
#define STARTEAM_PROJ_CMD_FILTER_DELETE                        1034
#define STARTEAM_PROJ_CMD_QUERY_ADD                            1035
#define STARTEAM_PROJ_CMD_QUERY_MODIFY                         1036
#define STARTEAM_PROJ_CMD_QUERY_GET                            1037
#define STARTEAM_PROJ_CMD_QUERY_GET_LIST                       1038
#define STARTEAM_PROJ_CMD_QUERY_DELETE                         1039
#define STARTEAM_PROJ_GET_FILTER_CLASS_ID                      1040
#define STARTEAM_PROJ_GET_QUERY_CLASS_ID                       1041
#define STARTEAM_SRVR_CMD_PROJECT_CREATE                       1051
#define STARTEAM_SRVR_CMD_PROJECT_OPEN                         1052
#define STARTEAM_SRVR_CMD_PROJECT_CLOSE                        1053
#define STARTEAM_PROJ_CMD_CATALOG_LOADALL                      1151
#define STARTEAM_PROJ_CMD_CATALOG_LOADSET                      1152
#define STARTEAM_PROJ_CMD_CATALOG_LOADREGISTEREDCLASSES        1154
#define STARTEAM_PROJ_CMD_REFRESH_CLASS_INFO                   1160
#define STARTEAM_PROJ_CMD_ADD_CUSTOM_FIELD_CLASS_INFO          1161
#define STARTEAM_PROJ_CMD_MODIFY_FIELD_CLASS_INFO              1162
#define STARTEAM_PROJ_CMD_ADD_CUSTOM_FIELD_CLASS_INFO_EX       1163
#define STARTEAM_PROJ_CMD_GET_FOLDER_ITEMS                     2001
#define STARTEAM_SRVR_CMD_GET_USERS_AND_GROUPS                 2001
#define STARTEAM_PROJ_CMD_REFRESH_ITEMS                        2002
#define STARTEAM_PROJ_CMD_GET_ITEM                             2003
#define STARTEAM_SRVR_CMD_GET_EMAIL_USERS                      2003
#define STARTEAM_PROJ_CMD_UPDATE_ITEM                          2004
#define STARTEAM_PROJ_CMD_DELETE_ITEM                          2005
#define STARTEAM_PROJ_CMD_SET_ITEM_LOCK                        2006
#define STARTEAM_PROJ_CMD_DELETE_TREE_ITEM                     2007
#define STARTEAM_PROJ_CMD_GET_ITEM_HISTORY                     2010
#define STARTEAM_SRVR_CMD_GET_USER_PERSONAL_INFO               2011
#define STARTEAM_SRVR_CMD_SET_USER_PERSONAL_INFO               2012
#define STARTEAM_SRVR_CMD_SET_USER_PASSWORD                    2013
#define STARTEAM_PROJ_CMD_MOVE_ITEMS                           2020
#define STARTEAM_PROJ_CMD_MOVE_TREE_ITEMS                      2021
#define STARTEAM_SRVR_CMD_GET_GROUP_INFO                       2021
#define STARTEAM_PROJ_CMD_SHARE_ITEMS                          2022
#define STARTEAM_SRVR_CMD_ADD_EDIT_GROUP_INFO                  2022
#define STARTEAM_PROJ_CMD_SHARE_TREE_ITEMS                     2023
#define STARTEAM_SRVR_CMD_DROP_GROUP                           2023
#define STARTEAM_SRVR_CMD_GET_USER_INFO                        2024
#define STARTEAM_SRVR_CMD_ADD_EDIT_USER_INFO                   2025
#define STARTEAM_SRVR_CMD_DROP_USER                            2026
#define STARTEAM_SRVR_CMD_GET_MIN_PASSWORD_LENGTH              2027
#define STARTEAM_SRVR_CMD_USER_ADMIN_OPERATION                 2028
#define STARTEAM_SRVR_CMD_ACCESS_CHECK                         2029
#define STARTEAM_PROJ_CMD_GET_COMMON_ANCESTOR_ITEM             2030
#define STARTEAM_SRVR_CMD_ACCESS_TEST                          2030
#define STARTEAM_PROJ_CMD_UPDATE_REVISION_COMMENT              2031
#define STARTEAM_SRVR_CMD_GET_MAIN_LOG_LAST64K                 2031
#define STARTEAM_SRVR_CMD_GET_SERVER_CONFIG                    2032
#define STARTEAM_SRVR_CMD_SET_SERVER_CONFIG                    2033
#define STARTEAM_SRVR_CMD_GET_SERVER_ACL                       2034
#define STARTEAM_SRVR_CMD_DROP_SERVER_ACL                      2035
#define STARTEAM_SRVR_CMD_SET_SERVER_ACL                       2036
#define STARTEAM_SRVR_CMD_GET_SYSTEM_POLICY                    2037
#define STARTEAM_SRVR_CMD_SET_SYSTEM_POLICY                    2038
#define STARTEAM_SRVR_CMD_GET_SECURITY_LOG                     2039
#define STARTEAM_SRVR_CMD_GET_SERVER_COMMAND_STATS             2040
#define STARTEAM_SRVR_CMD_SET_SERVER_COMMAND_MODE              2041
#define STARTEAM_SRVR_CMD_SHUTDOWN                             2042
#define STARTEAM_SRVR_CMD_RESTART                              2043
#define STARTEAM_SRVR_CMD_GET_SERVER_COMMAND_MODE              2045
#define STARTEAM_SRVR_CMD_GET_LOG                              2046
#define STARTEAM_SRVR_CMD_GET_COMPONENT_LIST                   2050
#define STARTEAM_SRVR_CMD_GET_GROUP_MEMBERS                    2060
#define STARTEAM_PROJ_CMD_GET_ITEMS_VERSIONS                   5001
#define STARTEAM_SRVR_CMD_VALIDATE_VSS_INI_PATH                9034
#define STARTEAM_SRVR_CMD_VALIDATE_PVCS_CFG_PATH               9035
#define STARTEAM_SRVR_CMD_GET_VSS_PROJECT_TREE                 9036
#define STARTEAM_SRVR_CMD_GET_ALL_PVCS_ARCHIVES                9037
#define STARTEAM_SRVR_CMD_INITIALIZE_FOREIGN_ACCESS            9038
#define STARTEAM_SRVR_CMD_SET_FOREIGN_PROJECT_PW               9039
#define STARTEAM_PROJ_CMD_PING                                 10001
#define STARTEAM_PROJ_CMD_SET_LOCALE                           10005
#define STARTEAM_PROJ_CMD_GET_CONTAINER_ACL                    10011
#define STARTEAM_PROJ_CMD_SET_CONTAINER_ACL                    10012
#define STARTEAM_PROJ_CMD_GET_CONTAINER_LEVEL_ACL              10013
#define STARTEAM_PROJ_CMD_SET_CONTAINER_LEVEL_ACL              10014
#define STARTEAM_PROJ_CMD_GET_OBJECT_ACL                       10015
#define STARTEAM_PROJ_CMD_SET_OBJECT_ACL                       10016
#define STARTEAM_PROJ_CMD_ITEM_ACCESS_CHECK                    10017
#define STARTEAM_PROJ_CMD_ITEM_ACCESS_TEST                     10018
#define STARTEAM_PROJ_CMD_GET_OWNER                            10019
#define STARTEAM_PROJ_CMD_ACQUIRE_OWNERSHIP                    10020
#define STARTEAM_PROJ_CMD_GET_FOLDERS                          10021
#define STARTEAM_PROJ_CMD_ADD_FOLDERS                          10023
#define STARTEAM_PROJ_CMD_DELETE_FOLDER                        10024
#define STARTEAM_PROJ_CMD_MOVE_FOLDER                          10025
#define STARTEAM_PROJ_CMD_SHARE_FOLDER                         10026
#define STARTEAM_PROJ_CMD_CONTAINER_ACCESS_CHECK               10031
#define STARTEAM_PROJ_CMD_CONTAINER_ACCESS_TEST                10032
#define STARTEAM_PROJ_CMD_GET_OBJECT2_ACL                      10035
#define STARTEAM_PROJ_CMD_SET_OBJECT2_ACL                      10036
#define STARTEAM_PROJ_CMD_OBJECT_ACCESS_CHECK                  10037
#define STARTEAM_PROJ_CMD_OBJECT_ACCESS_TEST                   10038
#define STARTEAM_PROJ_CMD_GET_OBJECT_OWNER                     10039
#define STARTEAM_PROJ_CMD_ACQUIRE_OBJECT_OWNERSHIP             10040
#define STARTEAM_PROJ_CMD_GET_FOLDER_PROPERTIES                10053
#define STARTEAM_PROJ_CMD_SET_FOLDER_PROPERTIES                10054
#define STARTEAM_PROJ_CMD_GET_ITEM_PROPERTIES                  10060
#define STARTEAM_PROJ_CMD_SET_ITEM_PROPERTIES                  10061
#define STARTEAM_PROJ_CMD_GET_ITEM_REFERENCES                  10062
#define STARTEAM_PROJ_CMD_GET_ITEM_REFERENCE                   10063
#define STARTEAM_PROJ_CMD_GET_ITEM_REVISIONS                   10065
#define STARTEAM_PROJ_CMD_DELETE_PROJECT                       10083
#define STARTEAM_PROJ_CMD_GET_PROJECT_PROPERTIES               10085
#define STARTEAM_PROJ_CMD_SET_PROJECT_PROPERTIES               10086
#define STARTEAM_PROJ_CMD_GET_VIEW_INFO                        10090
#define STARTEAM_PROJ_CMD_ADD_VIEW                             10091
#define STARTEAM_PROJ_CMD_GET_VIEWS                            10092
#define STARTEAM_PROJ_CMD_GET_VIEW_PROPERTIES                  10093
#define STARTEAM_PROJ_CMD_SET_VIEW_PROPERTIES                  10094
#define STARTEAM_PROJ_CMD_DELETE_VIEW                          10095
#define STARTEAM_PROJ_CMD_SWITCH_VIEW                          10098
#define STARTEAM_PROJ_CMD_SWITCH_VIEW_CONFIG                   10099
#define STARTEAM_PROJ_CMD_GET_FOLDER_PATH                      10100
#define STARTEAM_FILE_CMD_CHECKOUT                             10104
#define STARTEAM_FILE_CMD_GET_SYNC_INFO                        10111
#define STARTEAM_FILE_CMD_DELETE_SYNC_INFO                     10112
#define STARTEAM_FILE_CMD_GET_PATH_IDS                         10117
#define STARTEAM_FILE_CMD_SYNC_UPDATE_ALL_INFO                 10119
#define STARTEAM_FILE_CMD_RESYNC_FILE                          10121
#define STARTEAM_FILE_CMD_CONVERT_ARCHIVE                      10122
#define STARTEAM_FILE_CMD_ARCHIVE_CONVERSION                   10123
#define STARTEAM_FILE_CMD_READ_PVCS_ARCHIVES                   10130
#define STARTEAM_FILE_CMD_ADD_PVCS_ARCHIVES                    10131
#define STARTEAM_FILE_CMD_ADD_PVCS_BRANCHES                    10132
#define STARTEAM_FILE_CMD_FINISH_NEW_PVCS_PROJECT              10133
#define STARTEAM_FILE_CMD_GET_NUMBER_VSS_ARCHIVES              10134
#define STARTEAM_FILE_CMD_READ_VSS_ARCHIVES                    10135
#define STARTEAM_FILE_CMD_ADD_VSS_ARCHIVE_TO_FOLDER            10136
#define STARTEAM_FILE_CMD_FINISH_NEW_VSS_PROJECT               10137
#define STARTEAM_FILE_CMD_REFRESH_FOREIGN_FOLDER               10138
#define STARTEAM_FILE_CMD_START_GO_NATIVE                      10139
#define STARTEAM_FILE_CMD_GET_PROJECT_TYPE                     10141
#define STARTEAM_FILE_CMD_SET_FOREIGN_PROJECT_PW               10142
#define STARTEAM_FILE_CMD_INTERNAL_NESTED_COMMAND              10143
#define STARTEAM_PROJ_CMD_LABEL_GET_INFO                       10201
#define STARTEAM_PROJ_CMD_LABEL_GET_PROPERTIES                 10202
#define STARTEAM_PROJ_CMD_LABEL_SET_PROPERTIES                 10203
#define STARTEAM_PROJ_CMD_LABEL_CREATE                         10205
#define STARTEAM_PROJ_CMD_LABEL_DELETE                         10206
#define STARTEAM_PROJ_CMD_LABEL_ATTACH                         10207
#define STARTEAM_PROJ_CMD_LABEL_MOVE                           10208
#define STARTEAM_PROJ_CMD_LABEL_DETACH                         10209
#define STARTEAM_PROJ_CMD_LABEL_GET_INFO_EX                    10221
#define STARTEAM_PROJ_CMD_LABEL_CREATE_EX                      10222
#define STARTEAM_PROJ_CMD_LABEL_ATTACH_EX                      10223
#define STARTEAM_PROJ_CMD_LABEL_ATTACH_ITEMS                   10224
#define STARTEAM_PROJ_CMD_LABEL_DETACH_EX                      10225
#define STARTEAM_PROJ_CMD_LABEL_DETACH_ITEMS                   10226
#define STARTEAM_PROJ_CMD_LABEL_GETITEMIDS                     10229
#define STARTEAM_PROJ_CMD_LINK_GET_INFO                        10300
#define STARTEAM_PROJ_CMD_LINK_CREATE                          10301
#define STARTEAM_PROJ_CMD_LINK_DELETE                          10302
#define STARTEAM_PROJ_CMD_LINK_UPDATE_PROPERTIES               10310
#define STARTEAM_PROJ_CMD_LINK_UPDATE_PINS                     10311
#define STARTEAM_PROJ_CMD_PROMOTION_GET                        10400
#define STARTEAM_PROJ_CMD_PROMOTION_SET                        10401
#define STARTEAM_TASK_CMD_GET_WORKRECS                         10402
#define STARTEAM_TASK_CMD_ADD_WORKREC                          10403
#define STARTEAM_TASK_CMD_UPDATE_WORKREC                       10404
#define STARTEAM_TASK_CMD_DELETE_WORKREC                       10405
#define STARTEAM_TASK_CMD_DELETE_TASK_PREDECESSOR              10408
#define STARTEAM_TASK_CMD_GET_TASK_DEPENDENCIES                10409
#define STARTEAM_TASK_CMD_ADD_TASK_PREDECESSOR                 10410
#define STARTEAM_TASK_CMD_UPDATE_TASK_PREDECESSOR              10411
#define STARTEAM_PROJ_CMD_VIEW_COMPARE_GET_FOLDER_DETAILS      20070
#define STARTEAM_PROJ_CMD_VIEW_COMPARE_RELATE_ITEMS            20071

#define STARTEAM_TEXT_MDH   "Message Data Header"
#define STARTEAM_TEXT_PH    "Packet Header"
#define STARTEAM_TEXT_ID    "ID"
#define STARTEAM_TEXT_DATA  "Data"

static const value_string starteam_opcode_vals[] = {
  { STARTEAM_SRVR_CMD_GET_SESSION_TAG,                      "SRVR_CMD_GET_SESSION_TAG" },
  { STARTEAM_SRVR_CMD_GET_REQUIRED_ENCRYPTION_LEVEL,        "SRVR_CMD_GET_REQUIRED_ENCRYPTION_LEVEL" },
  { STARTEAM_SRVR_CMD_GET_SERVER_PARAMS,                    "SRVR_CMD_GET_SERVER_PARAMS" },
  { STARTEAM_SRVR_CMD_SERVER_CONNECT,                       "SRVR_CMD_SERVER_CONNECT" },
  { STARTEAM_SRVR_CMD_SERVER_RECONNECT,                     "SRVR_CMD_SERVER_RECONNECT" },
  { STARTEAM_SRVR_CMD_BEGIN_LOGIN,                          "SRVR_CMD_BEGIN_LOGIN" },
  { STARTEAM_SRVR_CMD_KEY_EXCHANGE_PHASE0,                  "SRVR_CMD_KEY_EXCHANGE_PHASE0" },
  { STARTEAM_SRVR_CMD_KEY_EXCHANGE_PHASE12,                 "SRVR_CMD_KEY_EXCHANGE_PHASE12" },
  { STARTEAM_SRVR_CMD_KEY_EXCHANGE_PHASE3,                  "SRVR_CMD_KEY_EXCHANGE_PHASE3" },
  { STARTEAM_SRVR_CMD_SERVER_LOGIN,                         "SRVR_CMD_SERVER_LOGIN" },
  { STARTEAM_SRVR_CMD_GET_PROJECT_LIST,                     "SRVR_CMD_GET_PROJECT_LIST" },
  { STARTEAM_SRVR_CMD_GET_PROJECT_VIEWS,                    "SRVR_CMD_GET_PROJECT_VIEWS" },
  { STARTEAM_SRVR_CMD_PROJECT_LOGIN,                        "SRVR_CMD_PROJECT_LOGIN" },
  { STARTEAM_SRVR_CMD_PROJECT_LOGOUT,                       "SRVR_CMD_PROJECT_LOGOUT" },
  { STARTEAM_PROJ_CMD_LIST_SET_READ,                        "PROJ_CMD_LIST_SET_READ" },
  { STARTEAM_PROJ_CMD_LIST_ADD_ATTACHMENT,                  "PROJ_CMD_LIST_ADD_ATTACHMENT" },
  { STARTEAM_PROJ_CMD_LIST_GET_ATTACHMENT,                  "PROJ_CMD_LIST_GET_ATTACHMENT" },
  { STARTEAM_PROJ_CMD_LIST_REMOVE_ATTACHMENT,               "PROJ_CMD_LIST_REMOVE_ATTACHMENT" },
  { STARTEAM_PROJ_CMD_MAIL_LIST_ITEMS,                      "PROJ_CMD_MAIL_LIST_ITEMS" },
  { STARTEAM_PROJ_CMD_LIST_ANY_NEWITEMS,                    "PROJ_CMD_LIST_ANY_NEWITEMS" },
  { STARTEAM_PROJ_CMD_LIST_GET_NEWITEMS,                    "PROJ_CMD_LIST_GET_NEWITEMS" },
  { STARTEAM_SRVR_CMD_RELEASE_CLIENT,                       "SRVR_CMD_RELEASE_CLIENT" },
  { STARTEAM_SRVR_CMD_UPDATE_SERVER_INFO,                   "SRVR_CMD_UPDATE_SERVER_INFO" },
  { STARTEAM_SRVR_CMD_GET_USAGE_DATA,                       "SRVR_CMD_GET_USAGE_DATA" },
  { STARTEAM_SRVR_CMD_GET_LICENSE_INFO,                     "SRVR_CMD_GET_LICENSE_INFO" },
  { STARTEAM_PROJ_CMD_FILTER_ADD,                           "PROJ_CMD_FILTER_ADD" },
  { STARTEAM_PROJ_CMD_FILTER_MODIFY,                        "PROJ_CMD_FILTER_MODIFY" },
  { STARTEAM_PROJ_CMD_FILTER_GET,                           "PROJ_CMD_FILTER_GET" },
  { STARTEAM_PROJ_CMD_FILTER_GET_LIST,                      "PROJ_CMD_FILTER_GET_LIST" },
  { STARTEAM_PROJ_CMD_FILTER_DELETE,                        "PROJ_CMD_FILTER_DELETE" },
  { STARTEAM_PROJ_CMD_QUERY_ADD,                            "PROJ_CMD_QUERY_ADD" },
  { STARTEAM_PROJ_CMD_QUERY_MODIFY,                         "PROJ_CMD_QUERY_MODIFY" },
  { STARTEAM_PROJ_CMD_QUERY_GET,                            "PROJ_CMD_QUERY_GET" },
  { STARTEAM_PROJ_CMD_QUERY_GET_LIST,                       "PROJ_CMD_QUERY_GET_LIST" },
  { STARTEAM_PROJ_CMD_QUERY_DELETE,                         "PROJ_CMD_QUERY_DELETE" },
  { STARTEAM_PROJ_GET_FILTER_CLASS_ID,                      "PROJ_GET_FILTER_CLASS_ID" },
  { STARTEAM_PROJ_GET_QUERY_CLASS_ID,                       "PROJ_GET_QUERY_CLASS_ID" },
  { STARTEAM_SRVR_CMD_PROJECT_CREATE,                       "SRVR_CMD_PROJECT_CREATE" },
  { STARTEAM_SRVR_CMD_PROJECT_OPEN,                         "SRVR_CMD_PROJECT_OPEN" },
  { STARTEAM_SRVR_CMD_PROJECT_CLOSE,                        "SRVR_CMD_PROJECT_CLOSE" },
  { STARTEAM_PROJ_CMD_CATALOG_LOADALL,                      "PROJ_CMD_CATALOG_LOADALL" },
  { STARTEAM_PROJ_CMD_CATALOG_LOADSET,                      "PROJ_CMD_CATALOG_LOADSET" },
  { STARTEAM_PROJ_CMD_CATALOG_LOADREGISTEREDCLASSES,        "PROJ_CMD_CATALOG_LOADREGISTEREDCLASSES" },
  { STARTEAM_PROJ_CMD_REFRESH_CLASS_INFO,                   "PROJ_CMD_REFRESH_CLASS_INFO" },
  { STARTEAM_PROJ_CMD_ADD_CUSTOM_FIELD_CLASS_INFO,          "PROJ_CMD_ADD_CUSTOM_FIELD_CLASS_INFO" },
  { STARTEAM_PROJ_CMD_MODIFY_FIELD_CLASS_INFO,              "PROJ_CMD_MODIFY_FIELD_CLASS_INFO" },
  { STARTEAM_PROJ_CMD_ADD_CUSTOM_FIELD_CLASS_INFO_EX,       "PROJ_CMD_ADD_CUSTOM_FIELD_CLASS_INFO_EX" },
  { STARTEAM_PROJ_CMD_GET_FOLDER_ITEMS,                     "PROJ_CMD_GET_FOLDER_ITEMS" },
  { STARTEAM_SRVR_CMD_GET_USERS_AND_GROUPS,                 "SRVR_CMD_GET_USERS_AND_GROUPS" },
  { STARTEAM_PROJ_CMD_REFRESH_ITEMS,                        "PROJ_CMD_REFRESH_ITEMS" },
  { STARTEAM_PROJ_CMD_GET_ITEM,                             "PROJ_CMD_GET_ITEM" },
  { STARTEAM_SRVR_CMD_GET_EMAIL_USERS,                      "SRVR_CMD_GET_EMAIL_USERS" },
  { STARTEAM_PROJ_CMD_UPDATE_ITEM,                          "PROJ_CMD_UPDATE_ITEM" },
  { STARTEAM_PROJ_CMD_DELETE_ITEM,                          "PROJ_CMD_DELETE_ITEM" },
  { STARTEAM_PROJ_CMD_SET_ITEM_LOCK,                        "PROJ_CMD_SET_ITEM_LOCK" },
  { STARTEAM_PROJ_CMD_DELETE_TREE_ITEM,                     "PROJ_CMD_DELETE_TREE_ITEM" },
  { STARTEAM_PROJ_CMD_GET_ITEM_HISTORY,                     "PROJ_CMD_GET_ITEM_HISTORY" },
  { STARTEAM_SRVR_CMD_GET_USER_PERSONAL_INFO,               "SRVR_CMD_GET_USER_PERSONAL_INFO" },
  { STARTEAM_SRVR_CMD_SET_USER_PERSONAL_INFO,               "SRVR_CMD_SET_USER_PERSONAL_INFO" },
  { STARTEAM_SRVR_CMD_SET_USER_PASSWORD,                    "SRVR_CMD_SET_USER_PASSWORD" },
  { STARTEAM_PROJ_CMD_MOVE_ITEMS,                           "PROJ_CMD_MOVE_ITEMS" },
  { STARTEAM_PROJ_CMD_MOVE_TREE_ITEMS,                      "PROJ_CMD_MOVE_TREE_ITEMS" },
  { STARTEAM_SRVR_CMD_GET_GROUP_INFO,                       "SRVR_CMD_GET_GROUP_INFO" },
  { STARTEAM_PROJ_CMD_SHARE_ITEMS,                          "PROJ_CMD_SHARE_ITEMS" },
  { STARTEAM_SRVR_CMD_ADD_EDIT_GROUP_INFO,                  "SRVR_CMD_ADD_EDIT_GROUP_INFO" },
  { STARTEAM_PROJ_CMD_SHARE_TREE_ITEMS,                     "PROJ_CMD_SHARE_TREE_ITEMS" },
  { STARTEAM_SRVR_CMD_DROP_GROUP,                           "SRVR_CMD_DROP_GROUP" },
  { STARTEAM_SRVR_CMD_GET_USER_INFO,                        "SRVR_CMD_GET_USER_INFO" },
  { STARTEAM_SRVR_CMD_ADD_EDIT_USER_INFO,                   "SRVR_CMD_ADD_EDIT_USER_INFO" },
  { STARTEAM_SRVR_CMD_DROP_USER,                            "SRVR_CMD_DROP_USER" },
  { STARTEAM_SRVR_CMD_GET_MIN_PASSWORD_LENGTH,              "SRVR_CMD_GET_MIN_PASSWORD_LENGTH" },
  { STARTEAM_SRVR_CMD_USER_ADMIN_OPERATION,                 "SRVR_CMD_USER_ADMIN_OPERATION" },
  { STARTEAM_SRVR_CMD_ACCESS_CHECK,                         "SRVR_CMD_ACCESS_CHECK" },
  { STARTEAM_PROJ_CMD_GET_COMMON_ANCESTOR_ITEM,             "PROJ_CMD_GET_COMMON_ANCESTOR_ITEM" },
  { STARTEAM_SRVR_CMD_ACCESS_TEST,                          "SRVR_CMD_ACCESS_TEST" },
  { STARTEAM_PROJ_CMD_UPDATE_REVISION_COMMENT,              "PROJ_CMD_UPDATE_REVISION_COMMENT" },
  { STARTEAM_SRVR_CMD_GET_MAIN_LOG_LAST64K,                 "SRVR_CMD_GET_MAIN_LOG_LAST64K" },
  { STARTEAM_SRVR_CMD_GET_SERVER_CONFIG,                    "SRVR_CMD_GET_SERVER_CONFIG" },
  { STARTEAM_SRVR_CMD_SET_SERVER_CONFIG,                    "SRVR_CMD_SET_SERVER_CONFIG" },
  { STARTEAM_SRVR_CMD_GET_SERVER_ACL,                       "SRVR_CMD_GET_SERVER_ACL" },
  { STARTEAM_SRVR_CMD_DROP_SERVER_ACL,                      "SRVR_CMD_DROP_SERVER_ACL" },
  { STARTEAM_SRVR_CMD_SET_SERVER_ACL,                       "SRVR_CMD_SET_SERVER_ACL" },
  { STARTEAM_SRVR_CMD_GET_SYSTEM_POLICY,                    "SRVR_CMD_GET_SYSTEM_POLICY" },
  { STARTEAM_SRVR_CMD_SET_SYSTEM_POLICY,                    "SRVR_CMD_SET_SYSTEM_POLICY" },
  { STARTEAM_SRVR_CMD_GET_SECURITY_LOG,                     "SRVR_CMD_GET_SECURITY_LOG" },
  { STARTEAM_SRVR_CMD_GET_SERVER_COMMAND_STATS,             "SRVR_CMD_GET_SERVER_COMMAND_STATS" },
  { STARTEAM_SRVR_CMD_SET_SERVER_COMMAND_MODE,              "SRVR_CMD_SET_SERVER_COMMAND_MODE" },
  { STARTEAM_SRVR_CMD_SHUTDOWN,                             "SRVR_CMD_SHUTDOWN" },
  { STARTEAM_SRVR_CMD_RESTART,                              "SRVR_CMD_RESTART" },
  { STARTEAM_SRVR_CMD_GET_SERVER_COMMAND_MODE,              "SRVR_CMD_GET_SERVER_COMMAND_MODE" },
  { STARTEAM_SRVR_CMD_GET_LOG,                              "SRVR_CMD_GET_LOG" },
  { STARTEAM_SRVR_CMD_GET_COMPONENT_LIST,                   "SRVR_CMD_GET_COMPONENT_LIST" },
  { STARTEAM_SRVR_CMD_GET_GROUP_MEMBERS,                    "SRVR_CMD_GET_GROUP_MEMBERS" },
  { STARTEAM_PROJ_CMD_GET_ITEMS_VERSIONS,                   "PROJ_CMD_GET_ITEMS_VERSIONS" },
  { STARTEAM_SRVR_CMD_VALIDATE_VSS_INI_PATH,                "SRVR_CMD_VALIDATE_VSS_INI_PATH" },
  { STARTEAM_SRVR_CMD_VALIDATE_PVCS_CFG_PATH,               "SRVR_CMD_VALIDATE_PVCS_CFG_PATH" },
  { STARTEAM_SRVR_CMD_GET_VSS_PROJECT_TREE,                 "SRVR_CMD_GET_VSS_PROJECT_TREE" },
  { STARTEAM_SRVR_CMD_GET_ALL_PVCS_ARCHIVES,                "SRVR_CMD_GET_ALL_PVCS_ARCHIVES" },
  { STARTEAM_SRVR_CMD_INITIALIZE_FOREIGN_ACCESS,            "SRVR_CMD_INITIALIZE_FOREIGN_ACCESS" },
  { STARTEAM_SRVR_CMD_SET_FOREIGN_PROJECT_PW,               "SRVR_CMD_SET_FOREIGN_PROJECT_PW" },
  { STARTEAM_PROJ_CMD_PING,                                 "PROJ_CMD_PING" },
  { STARTEAM_PROJ_CMD_SET_LOCALE,                           "PROJ_CMD_SET_LOCALE" },
  { STARTEAM_PROJ_CMD_GET_CONTAINER_ACL,                    "PROJ_CMD_GET_CONTAINER_ACL" },
  { STARTEAM_PROJ_CMD_SET_CONTAINER_ACL,                    "PROJ_CMD_SET_CONTAINER_ACL" },
  { STARTEAM_PROJ_CMD_GET_CONTAINER_LEVEL_ACL,              "PROJ_CMD_GET_CONTAINER_LEVEL_ACL" },
  { STARTEAM_PROJ_CMD_SET_CONTAINER_LEVEL_ACL,              "PROJ_CMD_SET_CONTAINER_LEVEL_ACL" },
  { STARTEAM_PROJ_CMD_GET_OBJECT_ACL,                       "PROJ_CMD_GET_OBJECT_ACL" },
  { STARTEAM_PROJ_CMD_SET_OBJECT_ACL,                       "PROJ_CMD_SET_OBJECT_ACL" },
  { STARTEAM_PROJ_CMD_ITEM_ACCESS_CHECK,                    "PROJ_CMD_ITEM_ACCESS_CHECK" },
  { STARTEAM_PROJ_CMD_ITEM_ACCESS_TEST,                     "PROJ_CMD_ITEM_ACCESS_TEST" },
  { STARTEAM_PROJ_CMD_GET_OWNER,                            "PROJ_CMD_GET_OWNER" },
  { STARTEAM_PROJ_CMD_ACQUIRE_OWNERSHIP,                    "PROJ_CMD_ACQUIRE_OWNERSHIP" },
  { STARTEAM_PROJ_CMD_GET_FOLDERS,                          "PROJ_CMD_GET_FOLDERS" },
  { STARTEAM_PROJ_CMD_ADD_FOLDERS,                          "PROJ_CMD_ADD_FOLDERS" },
  { STARTEAM_PROJ_CMD_DELETE_FOLDER,                        "PROJ_CMD_DELETE_FOLDER" },
  { STARTEAM_PROJ_CMD_MOVE_FOLDER,                          "PROJ_CMD_MOVE_FOLDER" },
  { STARTEAM_PROJ_CMD_SHARE_FOLDER,                         "PROJ_CMD_SHARE_FOLDER" },
  { STARTEAM_PROJ_CMD_CONTAINER_ACCESS_CHECK,               "PROJ_CMD_CONTAINER_ACCESS_CHECK" },
  { STARTEAM_PROJ_CMD_CONTAINER_ACCESS_TEST,                "PROJ_CMD_CONTAINER_ACCESS_TEST" },
  { STARTEAM_PROJ_CMD_GET_OBJECT2_ACL,                      "PROJ_CMD_GET_OBJECT2_ACL" },
  { STARTEAM_PROJ_CMD_SET_OBJECT2_ACL,                      "PROJ_CMD_SET_OBJECT2_ACL" },
  { STARTEAM_PROJ_CMD_OBJECT_ACCESS_CHECK,                  "PROJ_CMD_OBJECT_ACCESS_CHECK" },
  { STARTEAM_PROJ_CMD_OBJECT_ACCESS_TEST,                   "PROJ_CMD_OBJECT_ACCESS_TEST" },
  { STARTEAM_PROJ_CMD_GET_OBJECT_OWNER,                     "PROJ_CMD_GET_OBJECT_OWNER" },
  { STARTEAM_PROJ_CMD_ACQUIRE_OBJECT_OWNERSHIP,             "PROJ_CMD_ACQUIRE_OBJECT_OWNERSHIP" },
  { STARTEAM_PROJ_CMD_GET_FOLDER_PROPERTIES,                "PROJ_CMD_GET_FOLDER_PROPERTIES" },
  { STARTEAM_PROJ_CMD_SET_FOLDER_PROPERTIES,                "PROJ_CMD_SET_FOLDER_PROPERTIES" },
  { STARTEAM_PROJ_CMD_GET_ITEM_PROPERTIES,                  "PROJ_CMD_GET_ITEM_PROPERTIES" },
  { STARTEAM_PROJ_CMD_SET_ITEM_PROPERTIES,                  "PROJ_CMD_SET_ITEM_PROPERTIES" },
  { STARTEAM_PROJ_CMD_GET_ITEM_REFERENCES,                  "PROJ_CMD_GET_ITEM_REFERENCES" },
  { STARTEAM_PROJ_CMD_GET_ITEM_REFERENCE,                   "PROJ_CMD_GET_ITEM_REFERENCE" },
  { STARTEAM_PROJ_CMD_GET_ITEM_REVISIONS,                   "PROJ_CMD_GET_ITEM_REVISIONS" },
  { STARTEAM_PROJ_CMD_DELETE_PROJECT,                       "PROJ_CMD_DELETE_PROJECT" },
  { STARTEAM_PROJ_CMD_GET_PROJECT_PROPERTIES,               "PROJ_CMD_GET_PROJECT_PROPERTIES" },
  { STARTEAM_PROJ_CMD_SET_PROJECT_PROPERTIES,               "PROJ_CMD_SET_PROJECT_PROPERTIES" },
  { STARTEAM_PROJ_CMD_GET_VIEW_INFO,                        "PROJ_CMD_GET_VIEW_INFO" },
  { STARTEAM_PROJ_CMD_ADD_VIEW,                             "PROJ_CMD_ADD_VIEW" },
  { STARTEAM_PROJ_CMD_GET_VIEWS,                            "PROJ_CMD_GET_VIEWS" },
  { STARTEAM_PROJ_CMD_GET_VIEW_PROPERTIES,                  "PROJ_CMD_GET_VIEW_PROPERTIES" },
  { STARTEAM_PROJ_CMD_SET_VIEW_PROPERTIES,                  "PROJ_CMD_SET_VIEW_PROPERTIES" },
  { STARTEAM_PROJ_CMD_DELETE_VIEW,                          "PROJ_CMD_DELETE_VIEW" },
  { STARTEAM_PROJ_CMD_SWITCH_VIEW,                          "PROJ_CMD_SWITCH_VIEW" },
  { STARTEAM_PROJ_CMD_SWITCH_VIEW_CONFIG,                   "PROJ_CMD_SWITCH_VIEW_CONFIG" },
  { STARTEAM_PROJ_CMD_GET_FOLDER_PATH,                      "PROJ_CMD_GET_FOLDER_PATH" },
  { STARTEAM_FILE_CMD_CHECKOUT,                             "FILE_CMD_CHECKOUT" },
  { STARTEAM_FILE_CMD_GET_SYNC_INFO,                        "FILE_CMD_GET_SYNC_INFO" },
  { STARTEAM_FILE_CMD_DELETE_SYNC_INFO,                     "FILE_CMD_DELETE_SYNC_INFO" },
  { STARTEAM_FILE_CMD_GET_PATH_IDS,                         "FILE_CMD_GET_PATH_IDS" },
  { STARTEAM_FILE_CMD_SYNC_UPDATE_ALL_INFO,                 "FILE_CMD_SYNC_UPDATE_ALL_INFO" },
  { STARTEAM_FILE_CMD_RESYNC_FILE,                          "FILE_CMD_RESYNC_FILE" },
  { STARTEAM_FILE_CMD_CONVERT_ARCHIVE,                      "FILE_CMD_CONVERT_ARCHIVE" },
  { STARTEAM_FILE_CMD_ARCHIVE_CONVERSION,                   "FILE_CMD_ARCHIVE_CONVERSION" },
  { STARTEAM_FILE_CMD_READ_PVCS_ARCHIVES,                   "FILE_CMD_READ_PVCS_ARCHIVES" },
  { STARTEAM_FILE_CMD_ADD_PVCS_ARCHIVES,                    "FILE_CMD_ADD_PVCS_ARCHIVES" },
  { STARTEAM_FILE_CMD_ADD_PVCS_BRANCHES,                    "FILE_CMD_ADD_PVCS_BRANCHES" },
  { STARTEAM_FILE_CMD_FINISH_NEW_PVCS_PROJECT,              "FILE_CMD_FINISH_NEW_PVCS_PROJECT" },
  { STARTEAM_FILE_CMD_GET_NUMBER_VSS_ARCHIVES,              "FILE_CMD_GET_NUMBER_VSS_ARCHIVES" },
  { STARTEAM_FILE_CMD_READ_VSS_ARCHIVES,                    "FILE_CMD_READ_VSS_ARCHIVES" },
  { STARTEAM_FILE_CMD_ADD_VSS_ARCHIVE_TO_FOLDER,            "FILE_CMD_ADD_VSS_ARCHIVE_TO_FOLDER" },
  { STARTEAM_FILE_CMD_FINISH_NEW_VSS_PROJECT,               "FILE_CMD_FINISH_NEW_VSS_PROJECT" },
  { STARTEAM_FILE_CMD_REFRESH_FOREIGN_FOLDER,               "FILE_CMD_REFRESH_FOREIGN_FOLDER" },
  { STARTEAM_FILE_CMD_START_GO_NATIVE,                      "FILE_CMD_START_GO_NATIVE" },
  { STARTEAM_FILE_CMD_GET_PROJECT_TYPE,                     "FILE_CMD_GET_PROJECT_TYPE" },
  { STARTEAM_FILE_CMD_SET_FOREIGN_PROJECT_PW,               "FILE_CMD_SET_FOREIGN_PROJECT_PW" },
  { STARTEAM_FILE_CMD_INTERNAL_NESTED_COMMAND,              "FILE_CMD_INTERNAL_NESTED_COMMAND" },
  { STARTEAM_PROJ_CMD_LABEL_GET_INFO,                       "PROJ_CMD_LABEL_GET_INFO" },
  { STARTEAM_PROJ_CMD_LABEL_GET_PROPERTIES,                 "PROJ_CMD_LABEL_GET_PROPERTIES" },
  { STARTEAM_PROJ_CMD_LABEL_SET_PROPERTIES,                 "PROJ_CMD_LABEL_SET_PROPERTIES" },
  { STARTEAM_PROJ_CMD_LABEL_CREATE,                         "PROJ_CMD_LABEL_CREATE" },
  { STARTEAM_PROJ_CMD_LABEL_DELETE,                         "PROJ_CMD_LABEL_DELETE" },
  { STARTEAM_PROJ_CMD_LABEL_ATTACH,                         "PROJ_CMD_LABEL_ATTACH" },
  { STARTEAM_PROJ_CMD_LABEL_MOVE,                           "PROJ_CMD_LABEL_MOVE" },
  { STARTEAM_PROJ_CMD_LABEL_DETACH,                         "PROJ_CMD_LABEL_DETACH" },
  { STARTEAM_PROJ_CMD_LABEL_GET_INFO_EX,                    "PROJ_CMD_LABEL_GET_INFO_EX" },
  { STARTEAM_PROJ_CMD_LABEL_CREATE_EX,                      "PROJ_CMD_LABEL_CREATE_EX" },
  { STARTEAM_PROJ_CMD_LABEL_ATTACH_EX,                      "PROJ_CMD_LABEL_ATTACH_EX" },
  { STARTEAM_PROJ_CMD_LABEL_ATTACH_ITEMS,                   "PROJ_CMD_LABEL_ATTACH_ITEMS" },
  { STARTEAM_PROJ_CMD_LABEL_DETACH_EX,                      "PROJ_CMD_LABEL_DETACH_EX" },
  { STARTEAM_PROJ_CMD_LABEL_DETACH_ITEMS,                   "PROJ_CMD_LABEL_DETACH_ITEMS" },
  { STARTEAM_PROJ_CMD_LABEL_GETITEMIDS,                     "PROJ_CMD_LABEL_GETITEMIDS" },
  { STARTEAM_PROJ_CMD_LINK_GET_INFO,                        "PROJ_CMD_LINK_GET_INFO" },
  { STARTEAM_PROJ_CMD_LINK_CREATE,                          "PROJ_CMD_LINK_CREATE" },
  { STARTEAM_PROJ_CMD_LINK_DELETE,                          "PROJ_CMD_LINK_DELETE" },
  { STARTEAM_PROJ_CMD_LINK_UPDATE_PROPERTIES,               "PROJ_CMD_LINK_UPDATE_PROPERTIES" },
  { STARTEAM_PROJ_CMD_LINK_UPDATE_PINS,                     "PROJ_CMD_LINK_UPDATE_PINS" },
  { STARTEAM_PROJ_CMD_PROMOTION_GET,                        "PROJ_CMD_PROMOTION_GET" },
  { STARTEAM_PROJ_CMD_PROMOTION_SET,                        "PROJ_CMD_PROMOTION_SET" },
  { STARTEAM_TASK_CMD_GET_WORKRECS,                         "TASK_CMD_GET_WORKRECS" },
  { STARTEAM_TASK_CMD_ADD_WORKREC,                          "TASK_CMD_ADD_WORKREC" },
  { STARTEAM_TASK_CMD_UPDATE_WORKREC,                       "TASK_CMD_UPDATE_WORKREC" },
  { STARTEAM_TASK_CMD_DELETE_WORKREC,                       "TASK_CMD_DELETE_WORKREC" },
  { STARTEAM_TASK_CMD_DELETE_TASK_PREDECESSOR,              "TASK_CMD_DELETE_TASK_PREDECESSOR" },
  { STARTEAM_TASK_CMD_GET_TASK_DEPENDENCIES,                "TASK_CMD_GET_TASK_DEPENDENCIES" },
  { STARTEAM_TASK_CMD_ADD_TASK_PREDECESSOR,                 "TASK_CMD_ADD_TASK_PREDECESSOR" },
  { STARTEAM_TASK_CMD_UPDATE_TASK_PREDECESSOR,              "TASK_CMD_UPDATE_TASK_PREDECESSOR" },
  { STARTEAM_PROJ_CMD_VIEW_COMPARE_GET_FOLDER_DETAILS,      "PROJ_CMD_VIEW_COMPARE_GET_FOLDER_DETAILS" },
  { STARTEAM_PROJ_CMD_VIEW_COMPARE_RELATE_ITEMS,            "PROJ_CMD_VIEW_COMPARE_RELATE_ITEMS" },
  { 0,          NULL }
};

static value_string_ext starteam_opcode_vals_ext = VALUE_STRING_EXT_INIT(starteam_opcode_vals);

static gint iPreviousFrameNumber = -1;

static void
starteam_init(void)
{
  iPreviousFrameNumber = -1;
}

static void
dissect_starteam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  gint offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "StarTeam");

  if(check_col(pinfo->cinfo, COL_INFO)){
    /* This is a trick to know whether this is the first PDU in this packet or not */
    if(iPreviousFrameNumber != (gint) pinfo->fd->num){
      col_clear(pinfo->cinfo, COL_INFO);
    } else {
      col_append_str(pinfo->cinfo, COL_INFO, " | ");
    }
  }
  iPreviousFrameNumber = pinfo->fd->num;
  if(tvb_length(tvb) >= 16){
    guint32 iCommand = 0;
    gboolean bRequest = FALSE;
    if(tvb_get_ntohl(tvb, offset + 0) == STARTEAM_MAGIC){
      /* This packet is a response */
      bRequest = FALSE;
      if(check_col(pinfo->cinfo, COL_INFO)){
        col_append_fstr(pinfo->cinfo, COL_INFO, "Reply: %d bytes", tvb_length(tvb));
      }
    } else if(tvb_length_remaining(tvb, offset) >= 28 && tvb_get_ntohl(tvb, offset + 20) == STARTEAM_MAGIC){
      /* This packet is a request */
      bRequest = TRUE;
      if(tvb_length_remaining(tvb, offset) >= 66){
        iCommand = tvb_get_letohl(tvb, offset + 62);
      }
      if(check_col(pinfo->cinfo, COL_INFO)){
        col_append_str(pinfo->cinfo, COL_INFO,
                       val_to_str_ext(iCommand, &starteam_opcode_vals_ext, "Unknown (0x%02x)"));
      }
    }

    if(tree){
      proto_tree *starteam_tree;
      proto_tree *starteamroot_tree;
      proto_item *ti;

      ti = proto_tree_add_item(tree, proto_starteam, tvb, offset, -1, FALSE);
      if (bRequest) proto_item_append_text(ti, " (%s)",
                                           val_to_str_ext(iCommand, &starteam_opcode_vals_ext, "Unknown (0x%02x)"));
      starteamroot_tree = proto_item_add_subtree(ti, ett_starteam);

      if(bRequest){
        if(tvb_length_remaining(tvb, offset) >= 20){
          ti = proto_tree_add_text(starteamroot_tree, tvb, offset, 20, STARTEAM_TEXT_MDH);
          starteam_tree = proto_item_add_subtree(ti, ett_starteam_mdh);

          proto_tree_add_item(starteam_tree, hf_starteam_mdh_session_tag, tvb, offset + 0, 4, ENC_LITTLE_ENDIAN);
          proto_tree_add_item(starteam_tree, hf_starteam_mdh_ctimestamp, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
          proto_tree_add_item(starteam_tree, hf_starteam_mdh_flags, tvb, offset + 8, 4, ENC_LITTLE_ENDIAN);
          proto_tree_add_item(starteam_tree, hf_starteam_mdh_keyid, tvb, offset + 12, 4, ENC_LITTLE_ENDIAN);
          proto_tree_add_item(starteam_tree, hf_starteam_mdh_reserved, tvb, offset + 16, 4, ENC_LITTLE_ENDIAN);
          offset += 20;
        }
      }

      if(tvb_length_remaining(tvb, offset) >= 16){
        ti = proto_tree_add_text(starteamroot_tree, tvb, offset, 16, STARTEAM_TEXT_PH);
        starteam_tree = proto_item_add_subtree(ti, ett_starteam_ph);

        proto_tree_add_item(starteam_tree, hf_starteam_ph_signature, tvb, offset + 0, 4, FALSE);
        proto_tree_add_item(starteam_tree, hf_starteam_ph_packet_size, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(starteam_tree, hf_starteam_ph_data_size, tvb, offset + 8, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(starteam_tree, hf_starteam_ph_data_flags, tvb, offset + 12, 4, ENC_LITTLE_ENDIAN);
        offset += 16;

        if(bRequest){
          if(tvb_length_remaining(tvb, offset) >= 38){
            ti = proto_tree_add_text(starteamroot_tree, tvb, offset, 38, STARTEAM_TEXT_ID);
            starteam_tree = proto_item_add_subtree(ti, ett_starteam_id);

            proto_tree_add_item(starteam_tree, hf_starteam_id_revision_level, tvb, offset + 0, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(starteam_tree, hf_starteam_id_client, tvb, offset + 2, 16, TRUE);
            proto_tree_add_item(starteam_tree, hf_starteam_id_connect, tvb, offset + 18, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(starteam_tree, hf_starteam_id_component, tvb, offset + 22, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(starteam_tree, hf_starteam_id_command, tvb, offset + 26, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(starteam_tree, hf_starteam_id_command_time, tvb, offset + 30, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(starteam_tree, hf_starteam_id_command_userid, tvb, offset + 34, 4, ENC_LITTLE_ENDIAN);
            offset += 38;
          }
        }
        if(tvb_length_remaining(tvb, offset) > 0){
          ti = proto_tree_add_text(starteamroot_tree, tvb, offset, -1, STARTEAM_TEXT_DATA);
          starteam_tree = proto_item_add_subtree(ti, ett_starteam_data);
          proto_tree_add_item(starteam_tree, hf_starteam_data_data, tvb, offset, tvb_length_remaining(tvb, offset), TRUE);
        }
      }
    }
  }
}

static guint
get_starteam_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint32 iPDULength = 0;
  if(tvb_length_remaining(tvb, offset) >= 8 && tvb_get_ntohl(tvb, offset + 0) == STARTEAM_MAGIC){
    /* Response */
    iPDULength = tvb_get_letohl(tvb, offset + 4) + 16;
  } else if(tvb_length_remaining(tvb, offset) >= 28 && tvb_get_ntohl(tvb, offset + 20) == STARTEAM_MAGIC){
    /* Request */
    iPDULength = tvb_get_letohl(tvb, offset + 24) + 36;
  }
  return iPDULength;
}

static void
dissect_starteam_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tcp_dissect_pdus(tvb, pinfo, tree, starteam_desegment, 8, get_starteam_pdu_len, dissect_starteam);
}


static gboolean
dissect_starteam_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if(tvb_length(tvb) >= 32){
    gint iOffsetLengths = -1;
    if(tvb_get_ntohl(tvb, 0) == STARTEAM_MAGIC){
      iOffsetLengths = 4;
    } else if(tvb_get_ntohl(tvb, 20) == STARTEAM_MAGIC){
      iOffsetLengths = 24;
    }
    if(iOffsetLengths != -1){
      guint32 iLengthPacket;
      guint32 iLengthData;
      iLengthPacket = tvb_get_letohl(tvb, iOffsetLengths);
      iLengthData   = tvb_get_letohl(tvb, iOffsetLengths + 4);

      if(iLengthPacket == iLengthData){
        /* Register this dissector for this conversation */
        conversation_t  *conversation = NULL;
        conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, starteam_tcp_handle);

        /* Dissect the packet */
        dissect_starteam(tvb, pinfo, tree);
        return TRUE;
      }
    }
  }
  return FALSE;
}

void
proto_register_starteam(void)
{
  static hf_register_info hf[] = {
   { &hf_starteam_mdh_session_tag,
      { "Session tag", "starteam.mdh.stag", FT_UINT32, BASE_DEC, NULL, 0x0, "MDH session tag", HFILL }},

   { &hf_starteam_mdh_ctimestamp,
      { "Client timestamp", "starteam.mdh.ctimestamp", FT_UINT32, BASE_DEC, NULL, 0x0, "MDH client timestamp", HFILL }},

   { &hf_starteam_mdh_flags,
      { "Flags", "starteam.mdh.flags", FT_UINT32, BASE_HEX, NULL, 0x0, "MDH flags", HFILL }},

   { &hf_starteam_mdh_keyid,
      { "Key ID", "starteam.mdh.keyid", FT_UINT32, BASE_HEX, NULL, 0x0, "MDH key ID", HFILL }},

   { &hf_starteam_mdh_reserved,
      { "Reserved", "starteam.mdh.reserved", FT_UINT32, BASE_HEX, NULL, 0x0, "MDH reserved", HFILL }},

   { &hf_starteam_ph_signature,
      { "Signature", "starteam.ph.signature", FT_STRINGZ, BASE_NONE, NULL, 0x0, "PH signature", HFILL }},

   { &hf_starteam_ph_packet_size,
      { "Packet size", "starteam.ph.psize", FT_UINT32, BASE_DEC, NULL, 0x0, "PH packet size", HFILL }},

   { &hf_starteam_ph_data_size,
      { "Data size", "starteam.ph.dsize", FT_UINT32, BASE_DEC, NULL, 0x0, "PH data size", HFILL }},

   { &hf_starteam_ph_data_flags,
      { "Flags", "starteam.ph.flags", FT_UINT32, BASE_HEX, NULL, 0x0, "PH flags", HFILL }},

   { &hf_starteam_id_revision_level,
      { "Revision level", "starteam.id.level", FT_UINT16, BASE_DEC, NULL, 0x0, "ID revision level", HFILL }},

   { &hf_starteam_id_client,
      { "Client ID", "starteam.id.client", FT_STRINGZ, BASE_NONE, NULL, 0x0, "ID client ID", HFILL }},

   { &hf_starteam_id_connect,
      { "Connect ID", "starteam.id.connect", FT_UINT32, BASE_HEX, NULL, 0x0, "ID connect ID", HFILL }},

   { &hf_starteam_id_component,
      { "Component ID", "starteam.id.component", FT_UINT32, BASE_DEC, NULL, 0x0, "ID component ID", HFILL }},

   { &hf_starteam_id_command,
      { "Command ID", "starteam.id.command", FT_UINT32, BASE_DEC|BASE_EXT_STRING, &starteam_opcode_vals_ext, 0x0, "ID command ID", HFILL }},

   { &hf_starteam_id_command_time,
      { "Command time", "starteam.id.commandtime", FT_UINT32, BASE_HEX, NULL, 0x0, "ID command time", HFILL }},

   { &hf_starteam_id_command_userid,
      { "Command user ID", "starteam.id.commanduserid", FT_UINT32, BASE_HEX, NULL, 0x0, "ID command user ID", HFILL }},

   { &hf_starteam_data_data,
      { "Data", "starteam.data", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }}
  };
  static gint *ett[] = {
    &ett_starteam,
    &ett_starteam_mdh,
    &ett_starteam_ph,
    &ett_starteam_id,
    &ett_starteam_data
  };

  module_t *starteam_module;

  proto_starteam = proto_register_protocol("StarTeam", "StarTeam", "starteam");
  proto_register_field_array(proto_starteam, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  starteam_module = prefs_register_protocol(proto_starteam, NULL);
  prefs_register_bool_preference(starteam_module, "desegment",
    "Reassemble StarTeam messages spanning multiple TCP segments",
    "Whether the StarTeam dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &starteam_desegment);
  register_init_routine(&starteam_init);
}

void
proto_reg_handoff_starteam(void)
{
  heur_dissector_add("tcp", dissect_starteam_heur, proto_starteam);
  starteam_tcp_handle = create_dissector_handle(dissect_starteam_tcp, proto_starteam);
}
