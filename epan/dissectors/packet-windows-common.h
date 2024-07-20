/* packet-windows-common.h
 * Declarations for dissecting various Windows data types
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_WINDOWS_COMMON_H__
#define __PACKET_WINDOWS_COMMON_H__

#include "ws_symbol_export.h"
#include "packet-dcerpc.h"

/* Win32 errors.
 * These defines specify the WERR error codes often encountered in ms DCE/RPC
 * interfaces (those that do not return NT status that is)
 *
 * The list is generated from the samba doserr.h file by running :
     (echo "#include \"doserr.h\"";echo "#define W_ERROR(x) x";cat doserr.h | grep "^#define WERR" | grep -v "FOOBAR" | sed -e "s/^#define[ \t]//" | while read WERR junk;do echo int foo${WERR}=${WERR}";" ; done ) | cpp | grep "^int foo" | sed -e "s/^int foo/#define /" -e "s/=/ /" -e "s/;$//"
 *
 * [11/18/2013] The WERR_errors list was hand-edited to have all values be decimal, and then sorted by value.
 *
 * [11/19/2013] XXX - The samba doserr.h file no longer contains any WERR related entries.
 *                    WERR_errors list below left as is for now.
 */
#define WERR_errors_VALUE_STRING_LIST(XXX) \
    XXX( WERR_OK                                           , 0         ) /* 0x00000000 */ \
    XXX( WERR_INVALID_FUNCTION                             , 1         ) /* 0x00000001 */ \
    XXX( WERR_FILE_NOT_FOUND                               , 2         ) /* 0x00000002 */ \
    XXX( WERR_PATH_NOT_FOUND                               , 3         ) /* 0x00000003 */ \
    XXX( WERR_TOO_MANY_OPEN_FILES                          , 4         ) /* 0x00000004 */ \
    XXX( WERR_ACCESS_DENIED                                , 5         ) /* 0x00000005 */ \
    XXX( WERR_INVALID_HANDLE                               , 6         ) /* 0x00000006 */ \
    XXX( WERR_ARENA_TRASHED                                , 7         ) /* 0x00000007 */ \
    XXX( WERR_NOT_ENOUGH_MEMORY                            , 8         ) /* 0x00000008 */ \
    XXX( WERR_INVALID_BLOCK                                , 9         ) /* 0x00000009 */ \
    XXX( WERR_BAD_ENVIRONMENT                              , 10        ) /* 0x0000000a */ \
    XXX( WERR_BAD_FORMAT                                   , 11        ) /* 0x0000000b */ \
    XXX( WERR_INVALID_ACCESS                               , 12        ) /* 0x0000000c */ \
    XXX( WERR_INVALID_DATA                                 , 13        ) /* 0x0000000d */ \
    XXX( WERR_OUTOFMEMORY                                  , 14        ) /* 0x0000000e */ \
    XXX( WERR_INVALID_DRIVE                                , 15        ) /* 0x0000000f */ \
    XXX( WERR_CURRENT_DIRECTORY                            , 16        ) /* 0x00000010 */ \
    XXX( WERR_NOT_SAME_DEVICE                              , 17        ) /* 0x00000011 */ \
    XXX( WERR_NO_MORE_FILES                                , 18        ) /* 0x00000012 */ \
    XXX( WERR_WRITE_PROTECT                                , 19        ) /* 0x00000013 */ \
    XXX( WERR_BAD_UNIT                                     , 20        ) /* 0x00000014 */ \
    XXX( WERR_NOT_READY                                    , 21        ) /* 0x00000015 */ \
    XXX( WERR_BAD_COMMAND                                  , 22        ) /* 0x00000016 */ \
    XXX( WERR_CRC                                          , 23        ) /* 0x00000017 */ \
    XXX( WERR_BAD_LENGTH                                   , 24        ) /* 0x00000018 */ \
    XXX( WERR_SEEK                                         , 25        ) /* 0x00000019 */ \
    XXX( WERR_NOT_DOS_DISK                                 , 26        ) /* 0x0000001a */ \
    XXX( WERR_SECTOR_NOT_FOUND                             , 27        ) /* 0x0000001b */ \
    XXX( WERR_OUT_OF_PAPER                                 , 28        ) /* 0x0000001c */ \
    XXX( WERR_WRITE_FAULT                                  , 29        ) /* 0x0000001d */ \
    XXX( WERR_READ_FAULT                                   , 30        ) /* 0x0000001e */ \
    XXX( WERR_GEN_FAILURE                                  , 31        ) /* 0x0000001f */ \
    XXX( WERR_SHARING_VIOLATION                            , 32        ) /* 0x00000020 */ \
    XXX( WERR_LOCK_VIOLATION                               , 33        ) /* 0x00000021 */ \
    XXX( WERR_WRONG_DISK                                   , 34        ) /* 0x00000022 */ \
    XXX( WERR_CM_NO_MORE_HW_PROFILES                       , 35        ) /* 0x00000023 */ \
    XXX( WERR_SHARING_BUFFER_EXCEEDED                      , 36        ) /* 0x00000024 */ \
    XXX( WERR_CM_NO_SUCH_VALUE                             , 37        ) /* 0x00000025 */ \
    XXX( WERR_HANDLE_EOF                                   , 38        ) /* 0x00000026 */ \
    XXX( WERR_HANDLE_DISK_FULL                             , 39        ) /* 0x00000027 */ \
    XXX( WERR_NOT_SUPPORTED                                , 50        ) /* 0x00000032 */ \
    XXX( WERR_REM_NOT_LIST                                 , 51        ) /* 0x00000033 */ \
    XXX( WERR_DUP_NAME                                     , 52        ) /* 0x00000034 */ \
    XXX( WERR_BAD_NETPATH                                  , 53        ) /* 0x00000035 */ \
    XXX( WERR_NETWORK_BUSY                                 , 54        ) /* 0x00000036 */ \
    XXX( WERR_DEV_NOT_EXIST                                , 55        ) /* 0x00000037 */ \
    XXX( WERR_TOO_MANY_CMDS                                , 56        ) /* 0x00000038 */ \
    XXX( WERR_ADAP_HDW_ERR                                 , 57        ) /* 0x00000039 */ \
    XXX( WERR_BAD_NET_RESP                                 , 58        ) /* 0x0000003a */ \
    XXX( WERR_UNEXP_NET_ERR                                , 59        ) /* 0x0000003b */ \
    XXX( WERR_BAD_REM_ADAP                                 , 60        ) /* 0x0000003c */ \
    XXX( WERR_PRINTQ_FULL                                  , 61        ) /* 0x0000003d */ \
    XXX( WERR_NO_SPOOL_SPACE                               , 62        ) /* 0x0000003e */ \
    XXX( WERR_PRINT_CANCELLED                              , 63        ) /* 0x0000003f */ \
    XXX( WERR_NETNAME_DELETED                              , 64        ) /* 0x00000040 */ \
    XXX( WERR_NETWORK_ACCESS_DENIED                        , 65        ) /* 0x00000041 */ \
    XXX( WERR_BAD_DEV_TYPE                                 , 66        ) /* 0x00000042 */ \
    XXX( WERR_BAD_NET_NAME                                 , 67        ) /* 0x00000043 */ \
    XXX( WERR_TOO_MANY_NAMES                               , 68        ) /* 0x00000044 */ \
    XXX( WERR_TOO_MANY_SESS                                , 69        ) /* 0x00000045 */ \
    XXX( WERR_SHARING_PAUSED                               , 70        ) /* 0x00000046 */ \
    XXX( WERR_REQ_NOT_ACCEP                                , 71        ) /* 0x00000047 */ \
    XXX( WERR_REDIR_PAUSED                                 , 72        ) /* 0x00000048 */ \
    XXX( WERR_FILE_EXISTS                                  , 80        ) /* 0x00000050 */ \
    XXX( WERR_CANNOT_MAKE                                  , 82        ) /* 0x00000052 */ \
    XXX( WERR_FAIL_I24                                     , 83        ) /* 0x00000053 */ \
    XXX( WERR_OUT_OF_STRUCTURES                            , 84        ) /* 0x00000054 */ \
    XXX( WERR_ALREADY_ASSIGNED                             , 85        ) /* 0x00000055 */ \
    XXX( WERR_INVALID_PASSWORD                             , 86        ) /* 0x00000056 */ \
    XXX( WERR_INVALID_PARAMETER                            , 87        ) /* 0x00000057 */ \
    XXX( WERR_NET_WRITE_FAULT                              , 88        ) /* 0x00000058 */ \
    XXX( WERR_NO_PROC_SLOTS                                , 89        ) /* 0x00000059 */ \
    XXX( WERR_TOO_MANY_SEMAPHORES                          , 100       ) /* 0x00000064 */ \
    XXX( WERR_EXCL_SEM_ALREADY_OWNED                       , 101       ) /* 0x00000065 */ \
    XXX( WERR_SEM_IS_SET                                   , 102       ) /* 0x00000066 */ \
    XXX( WERR_TOO_MANY_SEM_REQUESTS                        , 103       ) /* 0x00000067 */ \
    XXX( WERR_INVALID_AT_INTERRUPT_TIME                    , 104       ) /* 0x00000068 */ \
    XXX( WERR_SEM_OWNER_DIED                               , 105       ) /* 0x00000069 */ \
    XXX( WERR_SEM_USER_LIMIT                               , 106       ) /* 0x0000006a */ \
    XXX( WERR_DISK_CHANGE                                  , 107       ) /* 0x0000006b */ \
    XXX( WERR_DRIVE_LOCKED                                 , 108       ) /* 0x0000006c */ \
    XXX( WERR_BROKEN_PIPE                                  , 109       ) /* 0x0000006d */ \
    XXX( WERR_OPEN_FAILED                                  , 110       ) /* 0x0000006e */ \
    XXX( WERR_BUFFER_OVERFLOW                              , 111       ) /* 0x0000006f */ \
    XXX( WERR_DISK_FULL                                    , 112       ) /* 0x00000070 */ \
    XXX( WERR_NO_MORE_SEARCH_HANDLES                       , 113       ) /* 0x00000071 */ \
    XXX( WERR_INVALID_TARGET_HANDLE                        , 114       ) /* 0x00000072 */ \
    XXX( WERR_INVALID_CATEGORY                             , 117       ) /* 0x00000075 */ \
    XXX( WERR_INVALID_VERIFY_SWITCH                        , 118       ) /* 0x00000076 */ \
    XXX( WERR_BAD_DRIVER_LEVEL                             , 119       ) /* 0x00000077 */ \
    XXX( WERR_CALL_NOT_IMPLEMENTED                         , 120       ) /* 0x00000078 */ \
    XXX( WERR_SEM_TIMEOUT                                  , 121       ) /* 0x00000079 */ \
    XXX( WERR_INSUFFICIENT_BUFFER                          , 122       ) /* 0x0000007a */ \
    XXX( WERR_INVALID_NAME                                 , 123       ) /* 0x0000007b */ \
    XXX( WERR_INVALID_LEVEL                                , 124       ) /* 0x0000007c */ \
    XXX( WERR_NO_VOLUME_LABEL                              , 125       ) /* 0x0000007d */ \
    XXX( WERR_MOD_NOT_FOUND                                , 126       ) /* 0x0000007e */ \
    XXX( WERR_PROC_NOT_FOUND                               , 127       ) /* 0x0000007f */ \
    XXX( WERR_WAIT_NO_CHILDREN                             , 128       ) /* 0x00000080 */ \
    XXX( WERR_CHILD_NOT_COMPLETE                           , 129       ) /* 0x00000081 */ \
    XXX( WERR_DIRECT_ACCESS_HANDLE                         , 130       ) /* 0x00000082 */ \
    XXX( WERR_NEGATIVE_SEEK                                , 131       ) /* 0x00000083 */ \
    XXX( WERR_SEEK_ON_DEVICE                               , 132       ) /* 0x00000084 */ \
    XXX( WERR_NOT_SUBSTED                                  , 137       ) /* 0x00000089 */ \
    XXX( WERR_JOIN_TO_JOIN                                 , 138       ) /* 0x0000008a */ \
    XXX( WERR_SUBST_TO_SUBST                               , 139       ) /* 0x0000008b */ \
    XXX( WERR_JOIN_TO_SUBST                                , 140       ) /* 0x0000008c */ \
    XXX( WERR_SAME_DRIVE                                   , 143       ) /* 0x0000008f */ \
    XXX( WERR_DIR_NOT_ROOT                                 , 144       ) /* 0x00000090 */ \
    XXX( WERR_DIR_NOT_EMPTY                                , 145       ) /* 0x00000091 */ \
    XXX( WERR_IS_SUBST_PATH                                , 146       ) /* 0x00000092 */ \
    XXX( WERR_IS_JOIN_PATH                                 , 147       ) /* 0x00000093 */ \
    XXX( WERR_PATH_BUSY                                    , 148       ) /* 0x00000094 */ \
    XXX( WERR_IS_SUBST_TARGET                              , 149       ) /* 0x00000095 */ \
    XXX( WERR_SYSTEM_TRACE                                 , 150       ) /* 0x00000096 */ \
    XXX( WERR_INVALID_EVENT_COUNT                          , 151       ) /* 0x00000097 */ \
    XXX( WERR_TOO_MANY_MUXWAITERS                          , 152       ) /* 0x00000098 */ \
    XXX( WERR_INVALID_LIST_FORMAT                          , 153       ) /* 0x00000099 */ \
    XXX( WERR_LABEL_TOO_LONG                               , 154       ) /* 0x0000009a */ \
    XXX( WERR_TOO_MANY_TCBS                                , 155       ) /* 0x0000009b */ \
    XXX( WERR_SIGNAL_REFUSED                               , 156       ) /* 0x0000009c */ \
    XXX( WERR_DISCARDED                                    , 157       ) /* 0x0000009d */ \
    XXX( WERR_NOT_LOCKED                                   , 158       ) /* 0x0000009e */ \
    XXX( WERR_BAD_THREADID_ADDR                            , 159       ) /* 0x0000009f */ \
    XXX( WERR_BAD_ARGUMENTS                                , 160       ) /* 0x000000a0 */ \
    XXX( WERR_BAD_PATHNAME                                 , 161       ) /* 0x000000a1 */ \
    XXX( WERR_SIGNAL_PENDING                               , 162       ) /* 0x000000a2 */ \
    XXX( WERR_MAX_THRDS_REACHED                            , 164       ) /* 0x000000a4 */ \
    XXX( WERR_LOCK_FAILED                                  , 167       ) /* 0x000000a7 */ \
    XXX( WERR_BUSY                                         , 170       ) /* 0x000000aa */ \
    XXX( WERR_CANCEL_VIOLATION                             , 173       ) /* 0x000000ad */ \
    XXX( WERR_ATOMIC_LOCKS_NOT_SUPPORTED                   , 174       ) /* 0x000000ae */ \
    XXX( WERR_INVALID_SEGMENT_NUMBER                       , 180       ) /* 0x000000b4 */ \
    XXX( WERR_INVALID_ORDINAL                              , 182       ) /* 0x000000b6 */ \
    XXX( WERR_ALREADY_EXISTS                               , 183       ) /* 0x000000b7 */ \
    XXX( WERR_INVALID_FLAG_NUMBER                          , 186       ) /* 0x000000ba */ \
    XXX( WERR_SEM_NOT_FOUND                                , 187       ) /* 0x000000bb */ \
    XXX( WERR_INVALID_STARTING_CODESEG                     , 188       ) /* 0x000000bc */ \
    XXX( WERR_INVALID_STACKSEG                             , 189       ) /* 0x000000bd */ \
    XXX( WERR_INVALID_MODULETYPE                           , 190       ) /* 0x000000be */ \
    XXX( WERR_INVALID_EXE_SIGNATURE                        , 191       ) /* 0x000000bf */ \
    XXX( WERR_EXE_MARKED_INVALID                           , 192       ) /* 0x000000c0 */ \
    XXX( WERR_BAD_EXE_FORMAT                               , 193       ) /* 0x000000c1 */ \
    XXX( WERR_ITERATED_DATA_EXCEEDS_64K                    , 194       ) /* 0x000000c2 */ \
    XXX( WERR_INVALID_MINALLOCSIZE                         , 195       ) /* 0x000000c3 */ \
    XXX( WERR_DYNLINK_FROM_INVALID_RING                    , 196       ) /* 0x000000c4 */ \
    XXX( WERR_IOPL_NOT_ENABLED                             , 197       ) /* 0x000000c5 */ \
    XXX( WERR_INVALID_SEGDPL                               , 198       ) /* 0x000000c6 */ \
    XXX( WERR_AUTODATASEG_EXCEEDS_64K                      , 199       ) /* 0x000000c7 */ \
    XXX( WERR_RING2SEG_MUST_BE_MOVABLE                     , 200       ) /* 0x000000c8 */ \
    XXX( WERR_RELOC_CHAIN_XEEDS_SEGLIM                     , 201       ) /* 0x000000c9 */ \
    XXX( WERR_INFLOOP_IN_RELOC_CHAIN                       , 202       ) /* 0x000000ca */ \
    XXX( WERR_ENVVAR_NOT_FOUND                             , 203       ) /* 0x000000cb */ \
    XXX( WERR_NO_SIGNAL_SENT                               , 205       ) /* 0x000000cd */ \
    XXX( WERR_FILENAME_EXCED_RANGE                         , 206       ) /* 0x000000ce */ \
    XXX( WERR_RING2_STACK_IN_USE                           , 207       ) /* 0x000000cf */ \
    XXX( WERR_META_EXPANSION_TOO_LONG                      , 208       ) /* 0x000000d0 */ \
    XXX( WERR_INVALID_SIGNAL_NUMBER                        , 209       ) /* 0x000000d1 */ \
    XXX( WERR_THREAD_1_INACTIVE                            , 210       ) /* 0x000000d2 */ \
    XXX( WERR_LOCKED                                       , 212       ) /* 0x000000d4 */ \
    XXX( WERR_TOO_MANY_MODULES                             , 214       ) /* 0x000000d6 */ \
    XXX( WERR_NESTING_NOT_ALLOWED                          , 215       ) /* 0x000000d7 */ \
    XXX( WERR_EXE_MACHINE_TYPE_MISMATCH                    , 216       ) /* 0x000000d8 */ \
    XXX( WERR_EXE_CANNOT_MODIFY_SIGNED_BINARY              , 217       ) /* 0x000000d9 */ \
    XXX( WERR_EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY       , 218       ) /* 0x000000da */ \
    XXX( WERR_FILE_CHECKED_OUT                             , 220       ) /* 0x000000dc */ \
    XXX( WERR_CHECKOUT_REQUIRED                            , 221       ) /* 0x000000dd */ \
    XXX( WERR_BAD_FILE_TYPE                                , 222       ) /* 0x000000de */ \
    XXX( WERR_FILE_TOO_LARGE                               , 223       ) /* 0x000000df */ \
    XXX( WERR_FORMS_AUTH_REQUIRED                          , 224       ) /* 0x000000e0 */ \
    XXX( WERR_VIRUS_INFECTED                               , 225       ) /* 0x000000e1 */ \
    XXX( WERR_VIRUS_DELETED                                , 226       ) /* 0x000000e2 */ \
    XXX( WERR_PIPE_LOCAL                                   , 229       ) /* 0x000000e5 */ \
    XXX( WERR_BAD_PIPE                                     , 230       ) /* 0x000000e6 */ \
    XXX( WERR_PIPE_BUSY                                    , 231       ) /* 0x000000e7 */ \
    XXX( WERR_NO_DATA                                      , 232       ) /* 0x000000e8 */ \
    XXX( WERR_PIPE_NOT_CONNECTED                           , 233       ) /* 0x000000e9 */ \
    XXX( WERR_MORE_DATA                                    , 234       ) /* 0x000000ea */ \
    XXX( WERR_VC_DISCONNECTED                              , 240       ) /* 0x000000f0 */ \
    XXX( WERR_INVALID_EA_NAME                              , 254       ) /* 0x000000fe */ \
    XXX( WERR_EA_LIST_INCONSISTENT                         , 255       ) /* 0x000000ff */ \
    XXX( WERR_WAIT_TIMEOUT                                 , 258       ) /* 0x00000102 */ \
    XXX( WERR_NO_MORE_ITEMS                                , 259       ) /* 0x00000103 */ \
    XXX( WERR_STATUS_MORE_ENTRIES                          , 261       ) /* 0x00000105 */ \
    XXX( WERR_CANNOT_COPY                                  , 266       ) /* 0x0000010a */ \
    XXX( WERR_DIRECTORY                                    , 267       ) /* 0x0000010b */ \
    XXX( WERR_EAS_DIDNT_FIT                                , 275       ) /* 0x00000113 */ \
    XXX( WERR_EA_FILE_CORRUPT                              , 276       ) /* 0x00000114 */ \
    XXX( WERR_EA_TABLE_FULL                                , 277       ) /* 0x00000115 */ \
    XXX( WERR_INVALID_EA_HANDLE                            , 278       ) /* 0x00000116 */ \
    XXX( WERR_EAS_NOT_SUPPORTED                            , 282       ) /* 0x0000011a */ \
    XXX( WERR_NOT_OWNER                                    , 288       ) /* 0x00000120 */ \
    XXX( WERR_TOO_MANY_POSTS                               , 298       ) /* 0x0000012a */ \
    XXX( WERR_PARTIAL_COPY                                 , 299       ) /* 0x0000012b */ \
    XXX( WERR_OPLOCK_NOT_GRANTED                           , 300       ) /* 0x0000012c */ \
    XXX( WERR_INVALID_OPLOCK_PROTOCOL                      , 301       ) /* 0x0000012d */ \
    XXX( WERR_DISK_TOO_FRAGMENTED                          , 302       ) /* 0x0000012e */ \
    XXX( WERR_DELETE_PENDING                               , 303       ) /* 0x0000012f */ \
    XXX( WERR_MR_MID_NOT_FOUND                             , 317       ) /* 0x0000013d */ \
    XXX( WERR_SCOPE_NOT_FOUND                              , 318       ) /* 0x0000013e */ \
    XXX( WERR_FAIL_NOACTION_REBOOT                         , 350       ) /* 0x0000015e */ \
    XXX( WERR_FAIL_SHUTDOWN                                , 351       ) /* 0x0000015f */ \
    XXX( WERR_FAIL_RESTART                                 , 352       ) /* 0x00000160 */ \
    XXX( WERR_MAX_SESSIONS_REACHED                         , 353       ) /* 0x00000161 */ \
    XXX( WERR_THREAD_MODE_ALREADY_BACKGROUND               , 400       ) /* 0x00000190 */ \
    XXX( WERR_THREAD_MODE_NOT_BACKGROUND                   , 401       ) /* 0x00000191 */ \
    XXX( WERR_PROCESS_MODE_ALREADY_BACKGROUND              , 402       ) /* 0x00000192 */ \
    XXX( WERR_PROCESS_MODE_NOT_BACKGROUND                  , 403       ) /* 0x00000193 */ \
    XXX( WERR_INVALID_ADDRESS                              , 487       ) /* 0x000001e7 */ \
    XXX( WERR_USER_PROFILE_LOAD                            , 500       ) /* 0x000001f4 */ \
    XXX( WERR_ARITHMETIC_OVERFLOW                          , 534       ) /* 0x00000216 */ \
    XXX( WERR_PIPE_CONNECTED                               , 535       ) /* 0x00000217 */ \
    XXX( WERR_PIPE_LISTENING                               , 536       ) /* 0x00000218 */ \
    XXX( WERR_VERIFIER_STOP                                , 537       ) /* 0x00000219 */ \
    XXX( WERR_ABIOS_ERROR                                  , 538       ) /* 0x0000021a */ \
    XXX( WERR_WX86_WARNING                                 , 539       ) /* 0x0000021b */ \
    XXX( WERR_WX86_ERROR                                   , 540       ) /* 0x0000021c */ \
    XXX( WERR_TIMER_NOT_CANCELED                           , 541       ) /* 0x0000021d */ \
    XXX( WERR_UNWIND                                       , 542       ) /* 0x0000021e */ \
    XXX( WERR_BAD_STACK                                    , 543       ) /* 0x0000021f */ \
    XXX( WERR_INVALID_UNWIND_TARGET                        , 544       ) /* 0x00000220 */ \
    XXX( WERR_INVALID_PORT_ATTRIBUTES                      , 545       ) /* 0x00000221 */ \
    XXX( WERR_PORT_MESSAGE_TOO_LONG                        , 546       ) /* 0x00000222 */ \
    XXX( WERR_INVALID_QUOTA_LOWER                          , 547       ) /* 0x00000223 */ \
    XXX( WERR_DEVICE_ALREADY_ATTACHED                      , 548       ) /* 0x00000224 */ \
    XXX( WERR_INSTRUCTION_MISALIGNMENT                     , 549       ) /* 0x00000225 */ \
    XXX( WERR_PROFILING_NOT_STARTED                        , 550       ) /* 0x00000226 */ \
    XXX( WERR_PROFILING_NOT_STOPPED                        , 551       ) /* 0x00000227 */ \
    XXX( WERR_COULD_NOT_INTERPRET                          , 552       ) /* 0x00000228 */ \
    XXX( WERR_PROFILING_AT_LIMIT                           , 553       ) /* 0x00000229 */ \
    XXX( WERR_CANT_WAIT                                    , 554       ) /* 0x0000022a */ \
    XXX( WERR_CANT_TERMINATE_SELF                          , 555       ) /* 0x0000022b */ \
    XXX( WERR_UNEXPECTED_MM_CREATE_ERR                     , 556       ) /* 0x0000022c */ \
    XXX( WERR_UNEXPECTED_MM_MAP_ERROR                      , 557       ) /* 0x0000022d */ \
    XXX( WERR_UNEXPECTED_MM_EXTEND_ERR                     , 558       ) /* 0x0000022e */ \
    XXX( WERR_BAD_FUNCTION_TABLE                           , 559       ) /* 0x0000022f */ \
    XXX( WERR_NO_GUID_TRANSLATION                          , 560       ) /* 0x00000230 */ \
    XXX( WERR_INVALID_LDT_SIZE                             , 561       ) /* 0x00000231 */ \
    XXX( WERR_INVALID_LDT_OFFSET                           , 563       ) /* 0x00000233 */ \
    XXX( WERR_INVALID_LDT_DESCRIPTOR                       , 564       ) /* 0x00000234 */ \
    XXX( WERR_TOO_MANY_THREADS                             , 565       ) /* 0x00000235 */ \
    XXX( WERR_THREAD_NOT_IN_PROCESS                        , 566       ) /* 0x00000236 */ \
    XXX( WERR_PAGEFILE_QUOTA_EXCEEDED                      , 567       ) /* 0x00000237 */ \
    XXX( WERR_LOGON_SERVER_CONFLICT                        , 568       ) /* 0x00000238 */ \
    XXX( WERR_SYNCHRONIZATION_REQUIRED                     , 569       ) /* 0x00000239 */ \
    XXX( WERR_NET_OPEN_FAILED                              , 570       ) /* 0x0000023a */ \
    XXX( WERR_IO_PRIVILEGE_FAILED                          , 571       ) /* 0x0000023b */ \
    XXX( WERR_CONTROL_C_EXIT                               , 572       ) /* 0x0000023c */ \
    XXX( WERR_MISSING_SYSTEMFILE                           , 573       ) /* 0x0000023d */ \
    XXX( WERR_UNHANDLED_EXCEPTION                          , 574       ) /* 0x0000023e */ \
    XXX( WERR_APP_INIT_FAILURE                             , 575       ) /* 0x0000023f */ \
    XXX( WERR_PAGEFILE_CREATE_FAILED                       , 576       ) /* 0x00000240 */ \
    XXX( WERR_INVALID_IMAGE_HASH                           , 577       ) /* 0x00000241 */ \
    XXX( WERR_NO_PAGEFILE                                  , 578       ) /* 0x00000242 */ \
    XXX( WERR_ILLEGAL_FLOAT_CONTEXT                        , 579       ) /* 0x00000243 */ \
    XXX( WERR_NO_EVENT_PAIR                                , 580       ) /* 0x00000244 */ \
    XXX( WERR_DOMAIN_CTRLR_CONFIG_ERROR                    , 581       ) /* 0x00000245 */ \
    XXX( WERR_ILLEGAL_CHARACTER                            , 582       ) /* 0x00000246 */ \
    XXX( WERR_UNDEFINED_CHARACTER                          , 583       ) /* 0x00000247 */ \
    XXX( WERR_FLOPPY_VOLUME                                , 584       ) /* 0x00000248 */ \
    XXX( WERR_BIOS_FAILED_TO_CONNECT_INTERRUPT             , 585       ) /* 0x00000249 */ \
    XXX( WERR_BACKUP_CONTROLLER                            , 586       ) /* 0x0000024a */ \
    XXX( WERR_MUTANT_LIMIT_EXCEEDED                        , 587       ) /* 0x0000024b */ \
    XXX( WERR_FS_DRIVER_REQUIRED                           , 588       ) /* 0x0000024c */ \
    XXX( WERR_CANNOT_LOAD_REGISTRY_FILE                    , 589       ) /* 0x0000024d */ \
    XXX( WERR_DEBUG_ATTACH_FAILED                          , 590       ) /* 0x0000024e */ \
    XXX( WERR_SYSTEM_PROCESS_TERMINATED                    , 591       ) /* 0x0000024f */ \
    XXX( WERR_DATA_NOT_ACCEPTED                            , 592       ) /* 0x00000250 */ \
    XXX( WERR_VDM_HARD_ERROR                               , 593       ) /* 0x00000251 */ \
    XXX( WERR_DRIVER_CANCEL_TIMEOUT                        , 594       ) /* 0x00000252 */ \
    XXX( WERR_REPLY_MESSAGE_MISMATCH                       , 595       ) /* 0x00000253 */ \
    XXX( WERR_LOST_WRITEBEHIND_DATA                        , 596       ) /* 0x00000254 */ \
    XXX( WERR_CLIENT_SERVER_PARAMETERS_INVALID             , 597       ) /* 0x00000255 */ \
    XXX( WERR_NOT_TINY_STREAM                              , 598       ) /* 0x00000256 */ \
    XXX( WERR_STACK_OVERFLOW_READ                          , 599       ) /* 0x00000257 */ \
    XXX( WERR_CONVERT_TO_LARGE                             , 600       ) /* 0x00000258 */ \
    XXX( WERR_FOUND_OUT_OF_SCOPE                           , 601       ) /* 0x00000259 */ \
    XXX( WERR_ALLOCATE_BUCKET                              , 602       ) /* 0x0000025a */ \
    XXX( WERR_MARSHALL_OVERFLOW                            , 603       ) /* 0x0000025b */ \
    XXX( WERR_INVALID_VARIANT                              , 604       ) /* 0x0000025c */ \
    XXX( WERR_BAD_COMPRESSION_BUFFER                       , 605       ) /* 0x0000025d */ \
    XXX( WERR_AUDIT_FAILED                                 , 606       ) /* 0x0000025e */ \
    XXX( WERR_TIMER_RESOLUTION_NOT_SET                     , 607       ) /* 0x0000025f */ \
    XXX( WERR_INSUFFICIENT_LOGON_INFO                      , 608       ) /* 0x00000260 */ \
    XXX( WERR_BAD_DLL_ENTRYPOINT                           , 609       ) /* 0x00000261 */ \
    XXX( WERR_BAD_SERVICE_ENTRYPOINT                       , 610       ) /* 0x00000262 */ \
    XXX( WERR_IP_ADDRESS_CONFLICT1                         , 611       ) /* 0x00000263 */ \
    XXX( WERR_IP_ADDRESS_CONFLICT2                         , 612       ) /* 0x00000264 */ \
    XXX( WERR_REGISTRY_QUOTA_LIMIT                         , 613       ) /* 0x00000265 */ \
    XXX( WERR_NO_CALLBACK_ACTIVE                           , 614       ) /* 0x00000266 */ \
    XXX( WERR_PWD_TOO_SHORT                                , 615       ) /* 0x00000267 */ \
    XXX( WERR_PWD_TOO_RECENT                               , 616       ) /* 0x00000268 */ \
    XXX( WERR_PWD_HISTORY_CONFLICT                         , 617       ) /* 0x00000269 */ \
    XXX( WERR_UNSUPPORTED_COMPRESSION                      , 618       ) /* 0x0000026a */ \
    XXX( WERR_INVALID_HW_PROFILE                           , 619       ) /* 0x0000026b */ \
    XXX( WERR_INVALID_PLUGPLAY_DEVICE_PATH                 , 620       ) /* 0x0000026c */ \
    XXX( WERR_QUOTA_LIST_INCONSISTENT                      , 621       ) /* 0x0000026d */ \
    XXX( WERR_EVALUATION_EXPIRATION                        , 622       ) /* 0x0000026e */ \
    XXX( WERR_ILLEGAL_DLL_RELOCATION                       , 623       ) /* 0x0000026f */ \
    XXX( WERR_DLL_INIT_FAILED_LOGOFF                       , 624       ) /* 0x00000270 */ \
    XXX( WERR_VALIDATE_CONTINUE                            , 625       ) /* 0x00000271 */ \
    XXX( WERR_NO_MORE_MATCHES                              , 626       ) /* 0x00000272 */ \
    XXX( WERR_RANGE_LIST_CONFLICT                          , 627       ) /* 0x00000273 */ \
    XXX( WERR_SERVER_SID_MISMATCH                          , 628       ) /* 0x00000274 */ \
    XXX( WERR_CANT_ENABLE_DENY_ONLY                        , 629       ) /* 0x00000275 */ \
    XXX( WERR_FLOAT_MULTIPLE_FAULTS                        , 630       ) /* 0x00000276 */ \
    XXX( WERR_FLOAT_MULTIPLE_TRAPS                         , 631       ) /* 0x00000277 */ \
    XXX( WERR_NOINTERFACE                                  , 632       ) /* 0x00000278 */ \
    XXX( WERR_DRIVER_FAILED_SLEEP                          , 633       ) /* 0x00000279 */ \
    XXX( WERR_CORRUPT_SYSTEM_FILE                          , 634       ) /* 0x0000027a */ \
    XXX( WERR_COMMITMENT_MINIMUM                           , 635       ) /* 0x0000027b */ \
    XXX( WERR_PNP_RESTART_ENUMERATION                      , 636       ) /* 0x0000027c */ \
    XXX( WERR_SYSTEM_IMAGE_BAD_SIGNATURE                   , 637       ) /* 0x0000027d */ \
    XXX( WERR_PNP_REBOOT_REQUIRED                          , 638       ) /* 0x0000027e */ \
    XXX( WERR_INSUFFICIENT_POWER                           , 639       ) /* 0x0000027f */ \
    XXX( WERR_MULTIPLE_FAULT_VIOLATION                     , 640       ) /* 0x00000280 */ \
    XXX( WERR_SYSTEM_SHUTDOWN                              , 641       ) /* 0x00000281 */ \
    XXX( WERR_PORT_NOT_SET                                 , 642       ) /* 0x00000282 */ \
    XXX( WERR_DS_VERSION_CHECK_FAILURE                     , 643       ) /* 0x00000283 */ \
    XXX( WERR_RANGE_NOT_FOUND                              , 644       ) /* 0x00000284 */ \
    XXX( WERR_NOT_SAFE_MODE_DRIVER                         , 646       ) /* 0x00000286 */ \
    XXX( WERR_FAILED_DRIVER_ENTRY                          , 647       ) /* 0x00000287 */ \
    XXX( WERR_DEVICE_ENUMERATION_ERROR                     , 648       ) /* 0x00000288 */ \
    XXX( WERR_MOUNT_POINT_NOT_RESOLVED                     , 649       ) /* 0x00000289 */ \
    XXX( WERR_INVALID_DEVICE_OBJECT_PARAMETER              , 650       ) /* 0x0000028a */ \
    XXX( WERR_MCA_OCCURED                                  , 651       ) /* 0x0000028b */ \
    XXX( WERR_DRIVER_DATABASE_ERROR                        , 652       ) /* 0x0000028c */ \
    XXX( WERR_SYSTEM_HIVE_TOO_LARGE                        , 653       ) /* 0x0000028d */ \
    XXX( WERR_DRIVER_FAILED_PRIOR_UNLOAD                   , 654       ) /* 0x0000028e */ \
    XXX( WERR_VOLSNAP_PREPARE_HIBERNATE                    , 655       ) /* 0x0000028f */ \
    XXX( WERR_HIBERNATION_FAILURE                          , 656       ) /* 0x00000290 */ \
    XXX( WERR_FILE_SYSTEM_LIMITATION                       , 665       ) /* 0x00000299 */ \
    XXX( WERR_ASSERTION_FAILURE                            , 668       ) /* 0x0000029c */ \
    XXX( WERR_ACPI_ERROR                                   , 669       ) /* 0x0000029d */ \
    XXX( WERR_WOW_ASSERTION                                , 670       ) /* 0x0000029e */ \
    XXX( WERR_PNP_BAD_MPS_TABLE                            , 671       ) /* 0x0000029f */ \
    XXX( WERR_PNP_TRANSLATION_FAILED                       , 672       ) /* 0x000002a0 */ \
    XXX( WERR_PNP_IRQ_TRANSLATION_FAILED                   , 673       ) /* 0x000002a1 */ \
    XXX( WERR_PNP_INVALID_ID                               , 674       ) /* 0x000002a2 */ \
    XXX( WERR_WAKE_SYSTEM_DEBUGGER                         , 675       ) /* 0x000002a3 */ \
    XXX( WERR_HANDLES_CLOSED                               , 676       ) /* 0x000002a4 */ \
    XXX( WERR_EXTRANEOUS_INFORMATION                       , 677       ) /* 0x000002a5 */ \
    XXX( WERR_RXACT_COMMIT_NECESSARY                       , 678       ) /* 0x000002a6 */ \
    XXX( WERR_MEDIA_CHECK                                  , 679       ) /* 0x000002a7 */ \
    XXX( WERR_GUID_SUBSTITUTION_MADE                       , 680       ) /* 0x000002a8 */ \
    XXX( WERR_STOPPED_ON_SYMLINK                           , 681       ) /* 0x000002a9 */ \
    XXX( WERR_LONGJUMP                                     , 682       ) /* 0x000002aa */ \
    XXX( WERR_PLUGPLAY_QUERY_VETOED                        , 683       ) /* 0x000002ab */ \
    XXX( WERR_UNWIND_CONSOLIDATE                           , 684       ) /* 0x000002ac */ \
    XXX( WERR_REGISTRY_HIVE_RECOVERED                      , 685       ) /* 0x000002ad */ \
    XXX( WERR_DLL_MIGHT_BE_INSECURE                        , 686       ) /* 0x000002ae */ \
    XXX( WERR_DLL_MIGHT_BE_INCOMPATIBLE                    , 687       ) /* 0x000002af */ \
    XXX( WERR_DBG_EXCEPTION_NOT_HANDLED                    , 688       ) /* 0x000002b0 */ \
    XXX( WERR_DBG_REPLY_LATER                              , 689       ) /* 0x000002b1 */ \
    XXX( WERR_DBG_UNABLE_TO_PROVIDE_HANDLE                 , 690       ) /* 0x000002b2 */ \
    XXX( WERR_DBG_TERMINATE_THREAD                         , 691       ) /* 0x000002b3 */ \
    XXX( WERR_DBG_TERMINATE_PROCESS                        , 692       ) /* 0x000002b4 */ \
    XXX( WERR_DBG_CONTROL_C                                , 693       ) /* 0x000002b5 */ \
    XXX( WERR_DBG_PRINTEXCEPTION_C                         , 694       ) /* 0x000002b6 */ \
    XXX( WERR_DBG_RIPEXCEPTION                             , 695       ) /* 0x000002b7 */ \
    XXX( WERR_DBG_CONTROL_BREAK                            , 696       ) /* 0x000002b8 */ \
    XXX( WERR_DBG_COMMAND_EXCEPTION                        , 697       ) /* 0x000002b9 */ \
    XXX( WERR_OBJECT_NAME_EXISTS                           , 698       ) /* 0x000002ba */ \
    XXX( WERR_THREAD_WAS_SUSPENDED                         , 699       ) /* 0x000002bb */ \
    XXX( WERR_IMAGE_NOT_AT_BASE                            , 700       ) /* 0x000002bc */ \
    XXX( WERR_RXACT_STATE_CREATED                          , 701       ) /* 0x000002bd */ \
    XXX( WERR_SEGMENT_NOTIFICATION                         , 702       ) /* 0x000002be */ \
    XXX( WERR_BAD_CURRENT_DIRECTORY                        , 703       ) /* 0x000002bf */ \
    XXX( WERR_FT_READ_RECOVERY_FROM_BACKUP                 , 704       ) /* 0x000002c0 */ \
    XXX( WERR_FT_WRITE_RECOVERY                            , 705       ) /* 0x000002c1 */ \
    XXX( WERR_IMAGE_MACHINE_TYPE_MISMATCH                  , 706       ) /* 0x000002c2 */ \
    XXX( WERR_RECEIVE_PARTIAL                              , 707       ) /* 0x000002c3 */ \
    XXX( WERR_RECEIVE_EXPEDITED                            , 708       ) /* 0x000002c4 */ \
    XXX( WERR_RECEIVE_PARTIAL_EXPEDITED                    , 709       ) /* 0x000002c5 */ \
    XXX( WERR_EVENT_DONE                                   , 710       ) /* 0x000002c6 */ \
    XXX( WERR_EVENT_PENDING                                , 711       ) /* 0x000002c7 */ \
    XXX( WERR_CHECKING_FILE_SYSTEM                         , 712       ) /* 0x000002c8 */ \
    XXX( WERR_FATAL_APP_EXIT                               , 713       ) /* 0x000002c9 */ \
    XXX( WERR_PREDEFINED_HANDLE                            , 714       ) /* 0x000002ca */ \
    XXX( WERR_WAS_UNLOCKED                                 , 715       ) /* 0x000002cb */ \
    XXX( WERR_SERVICE_NOTIFICATION                         , 716       ) /* 0x000002cc */ \
    XXX( WERR_WAS_LOCKED                                   , 717       ) /* 0x000002cd */ \
    XXX( WERR_LOG_HARD_ERROR                               , 718       ) /* 0x000002ce */ \
    XXX( WERR_ALREADY_WIN32                                , 719       ) /* 0x000002cf */ \
    XXX( WERR_IMAGE_MACHINE_TYPE_MISMATCH_EXE              , 720       ) /* 0x000002d0 */ \
    XXX( WERR_NO_YIELD_PERFORMED                           , 721       ) /* 0x000002d1 */ \
    XXX( WERR_TIMER_RESUME_IGNORED                         , 722       ) /* 0x000002d2 */ \
    XXX( WERR_ARBITRATION_UNHANDLED                        , 723       ) /* 0x000002d3 */ \
    XXX( WERR_CARDBUS_NOT_SUPPORTED                        , 724       ) /* 0x000002d4 */ \
    XXX( WERR_MP_PROCESSOR_MISMATCH                        , 725       ) /* 0x000002d5 */ \
    XXX( WERR_HIBERNATED                                   , 726       ) /* 0x000002d6 */ \
    XXX( WERR_RESUME_HIBERNATION                           , 727       ) /* 0x000002d7 */ \
    XXX( WERR_FIRMWARE_UPDATED                             , 728       ) /* 0x000002d8 */ \
    XXX( WERR_DRIVERS_LEAKING_LOCKED_PAGES                 , 729       ) /* 0x000002d9 */ \
    XXX( WERR_WAKE_SYSTEM                                  , 730       ) /* 0x000002da */ \
    XXX( WERR_WAIT_1                                       , 731       ) /* 0x000002db */ \
    XXX( WERR_WAIT_2                                       , 732       ) /* 0x000002dc */ \
    XXX( WERR_WAIT_3                                       , 733       ) /* 0x000002dd */ \
    XXX( WERR_WAIT_63                                      , 734       ) /* 0x000002de */ \
    XXX( WERR_ABANDONED_WAIT_0                             , 735       ) /* 0x000002df */ \
    XXX( WERR_ABANDONED_WAIT_63                            , 736       ) /* 0x000002e0 */ \
    XXX( WERR_USER_APC                                     , 737       ) /* 0x000002e1 */ \
    XXX( WERR_KERNEL_APC                                   , 738       ) /* 0x000002e2 */ \
    XXX( WERR_ALERTED                                      , 739       ) /* 0x000002e3 */ \
    XXX( WERR_ELEVATION_REQUIRED                           , 740       ) /* 0x000002e4 */ \
    XXX( WERR_REPARSE                                      , 741       ) /* 0x000002e5 */ \
    XXX( WERR_OPLOCK_BREAK_IN_PROGRESS                     , 742       ) /* 0x000002e6 */ \
    XXX( WERR_VOLUME_MOUNTED                               , 743       ) /* 0x000002e7 */ \
    XXX( WERR_RXACT_COMMITTED                              , 744       ) /* 0x000002e8 */ \
    XXX( WERR_NOTIFY_CLEANUP                               , 745       ) /* 0x000002e9 */ \
    XXX( WERR_PRIMARY_TRANSPORT_CONNECT_FAILED             , 746       ) /* 0x000002ea */ \
    XXX( WERR_PAGE_FAULT_TRANSITION                        , 747       ) /* 0x000002eb */ \
    XXX( WERR_PAGE_FAULT_DEMAND_ZERO                       , 748       ) /* 0x000002ec */ \
    XXX( WERR_PAGE_FAULT_COPY_ON_WRITE                     , 749       ) /* 0x000002ed */ \
    XXX( WERR_PAGE_FAULT_GUARD_PAGE                        , 750       ) /* 0x000002ee */ \
    XXX( WERR_PAGE_FAULT_PAGING_FILE                       , 751       ) /* 0x000002ef */ \
    XXX( WERR_CACHE_PAGE_LOCKED                            , 752       ) /* 0x000002f0 */ \
    XXX( WERR_CRASH_DUMP                                   , 753       ) /* 0x000002f1 */ \
    XXX( WERR_BUFFER_ALL_ZEROS                             , 754       ) /* 0x000002f2 */ \
    XXX( WERR_REPARSE_OBJECT                               , 755       ) /* 0x000002f3 */ \
    XXX( WERR_RESOURCE_REQUIREMENTS_CHANGED                , 756       ) /* 0x000002f4 */ \
    XXX( WERR_TRANSLATION_COMPLETE                         , 757       ) /* 0x000002f5 */ \
    XXX( WERR_NOTHING_TO_TERMINATE                         , 758       ) /* 0x000002f6 */ \
    XXX( WERR_PROCESS_NOT_IN_JOB                           , 759       ) /* 0x000002f7 */ \
    XXX( WERR_PROCESS_IN_JOB                               , 760       ) /* 0x000002f8 */ \
    XXX( WERR_VOLSNAP_HIBERNATE_READY                      , 761       ) /* 0x000002f9 */ \
    XXX( WERR_FSFILTER_OP_COMPLETED_SUCCESSFULLY           , 762       ) /* 0x000002fa */ \
    XXX( WERR_INTERRUPT_VECTOR_ALREADY_CONNECTED           , 763       ) /* 0x000002fb */ \
    XXX( WERR_INTERRUPT_STILL_CONNECTED                    , 764       ) /* 0x000002fc */ \
    XXX( WERR_WAIT_FOR_OPLOCK                              , 765       ) /* 0x000002fd */ \
    XXX( WERR_DBG_EXCEPTION_HANDLED                        , 766       ) /* 0x000002fe */ \
    XXX( WERR_DBG_CONTINUE                                 , 767       ) /* 0x000002ff */ \
    XXX( WERR_CALLBACK_POP_STACK                           , 768       ) /* 0x00000300 */ \
    XXX( WERR_COMPRESSION_DISABLED                         , 769       ) /* 0x00000301 */ \
    XXX( WERR_CANTFETCHBACKWARDS                           , 770       ) /* 0x00000302 */ \
    XXX( WERR_CANTSCROLLBACKWARDS                          , 771       ) /* 0x00000303 */ \
    XXX( WERR_ROWSNOTRELEASED                              , 772       ) /* 0x00000304 */ \
    XXX( WERR_BAD_ACCESSOR_FLAGS                           , 773       ) /* 0x00000305 */ \
    XXX( WERR_ERRORS_ENCOUNTERED                           , 774       ) /* 0x00000306 */ \
    XXX( WERR_NOT_CAPABLE                                  , 775       ) /* 0x00000307 */ \
    XXX( WERR_REQUEST_OUT_OF_SEQUENCE                      , 776       ) /* 0x00000308 */ \
    XXX( WERR_VERSION_PARSE_ERROR                          , 777       ) /* 0x00000309 */ \
    XXX( WERR_BADSTARTPOSITION                             , 778       ) /* 0x0000030a */ \
    XXX( WERR_MEMORY_HARDWARE                              , 779       ) /* 0x0000030b */ \
    XXX( WERR_DISK_REPAIR_DISABLED                         , 780       ) /* 0x0000030c */ \
    XXX( WERR_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE, 781       ) /* 0x0000030d */ \
    XXX( WERR_SYSTEM_POWERSTATE_TRANSITION                 , 782       ) /* 0x0000030e */ \
    XXX( WERR_SYSTEM_POWERSTATE_COMPLEX_TRANSITION         , 783       ) /* 0x0000030f */ \
    XXX( WERR_MCA_EXCEPTION                                , 784       ) /* 0x00000310 */ \
    XXX( WERR_ACCESS_AUDIT_BY_POLICY                       , 785       ) /* 0x00000311 */ \
    XXX( WERR_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY        , 786       ) /* 0x00000312 */ \
    XXX( WERR_ABANDON_HIBERFILE                            , 787       ) /* 0x00000313 */ \
    XXX( WERR_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED   , 788       ) /* 0x00000314 */ \
    XXX( WERR_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR   , 789       ) /* 0x00000315 */ \
    XXX( WERR_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR       , 790       ) /* 0x00000316 */ \
    XXX( WERR_EA_ACCESS_DENIED                             , 994       ) /* 0x000003e2 */ \
    XXX( WERR_OPERATION_ABORTED                            , 995       ) /* 0x000003e3 */ \
    XXX( WERR_IO_INCOMPLETE                                , 996       ) /* 0x000003e4 */ \
    XXX( WERR_IO_PENDING                                   , 997       ) /* 0x000003e5 */ \
    XXX( WERR_NOACCESS                                     , 998       ) /* 0x000003e6 */ \
    XXX( WERR_SWAPERROR                                    , 999       ) /* 0x000003e7 */ \
    XXX( WERR_STACK_OVERFLOW                               , 1001      ) /* 0x000003e9 */ \
    XXX( WERR_INVALID_MESSAGE                              , 1002      ) /* 0x000003ea */ \
    XXX( WERR_CAN_NOT_COMPLETE                             , 1003      ) /* 0x000003eb */ \
    XXX( WERR_INVALID_FLAGS                                , 1004      ) /* 0x000003ec */ \
    XXX( WERR_UNRECOGNIZED_VOLUME                          , 1005      ) /* 0x000003ed */ \
    XXX( WERR_FILE_INVALID                                 , 1006      ) /* 0x000003ee */ \
    XXX( WERR_FULLSCREEN_MODE                              , 1007      ) /* 0x000003ef */ \
    XXX( WERR_NO_TOKEN                                     , 1008      ) /* 0x000003f0 */ \
    XXX( WERR_BADDB                                        , 1009      ) /* 0x000003f1 */ \
    XXX( WERR_BADKEY                                       , 1010      ) /* 0x000003f2 */ \
    XXX( WERR_CANTOPEN                                     , 1011      ) /* 0x000003f3 */ \
    XXX( WERR_CANTREAD                                     , 1012      ) /* 0x000003f4 */ \
    XXX( WERR_CANTWRITE                                    , 1013      ) /* 0x000003f5 */ \
    XXX( WERR_REGISTRY_RECOVERED                           , 1014      ) /* 0x000003f6 */ \
    XXX( WERR_REGISTRY_CORRUPT                             , 1015      ) /* 0x000003f7 */ \
    XXX( WERR_REGISTRY_IO_FAILED                           , 1016      ) /* 0x000003f8 */ \
    XXX( WERR_NOT_REGISTRY_FILE                            , 1017      ) /* 0x000003f9 */ \
    XXX( WERR_KEY_DELETED                                  , 1018      ) /* 0x000003fa */ \
    XXX( WERR_NO_LOG_SPACE                                 , 1019      ) /* 0x000003fb */ \
    XXX( WERR_KEY_HAS_CHILDREN                             , 1020      ) /* 0x000003fc */ \
    XXX( WERR_CHILD_MUST_BE_VOLATILE                       , 1021      ) /* 0x000003fd */ \
    XXX( WERR_NOTIFY_ENUM_DIR                              , 1022      ) /* 0x000003fe */ \
    XXX( WERR_DEPENDENT_SERVICES_RUNNING                   , 1051      ) /* 0x0000041b */ \
    XXX( WERR_INVALID_SERVICE_CONTROL                      , 1052      ) /* 0x0000041c */ \
    XXX( WERR_SERVICE_REQUEST_TIMEOUT                      , 1053      ) /* 0x0000041d */ \
    XXX( WERR_SERVICE_NO_THREAD                            , 1054      ) /* 0x0000041e */ \
    XXX( WERR_SERVICE_DATABASE_LOCKED                      , 1055      ) /* 0x0000041f */ \
    XXX( WERR_SERVICE_ALREADY_RUNNING                      , 1056      ) /* 0x00000420 */ \
    XXX( WERR_INVALID_SERVICE_ACCOUNT                      , 1057      ) /* 0x00000421 */ \
    XXX( WERR_SERVICE_DISABLED                             , 1058      ) /* 0x00000422 */ \
    XXX( WERR_CIRCULAR_DEPENDENCY                          , 1059      ) /* 0x00000423 */ \
    XXX( WERR_SERVICE_DOES_NOT_EXIST                       , 1060      ) /* 0x00000424 */ \
    XXX( WERR_SERVICE_CANNOT_ACCEPT_CTRL                   , 1061      ) /* 0x00000425 */ \
    XXX( WERR_SERVICE_NOT_ACTIVE                           , 1062      ) /* 0x00000426 */ \
    XXX( WERR_FAILED_SERVICE_CONTROLLER_CONNECT            , 1063      ) /* 0x00000427 */ \
    XXX( WERR_EXCEPTION_IN_SERVICE                         , 1064      ) /* 0x00000428 */ \
    XXX( WERR_DATABASE_DOES_NOT_EXIST                      , 1065      ) /* 0x00000429 */ \
    XXX( WERR_SERVICE_SPECIFIC_ERROR                       , 1066      ) /* 0x0000042a */ \
    XXX( WERR_PROCESS_ABORTED                              , 1067      ) /* 0x0000042b */ \
    XXX( WERR_SERVICE_DEPENDENCY_FAIL                      , 1068      ) /* 0x0000042c */ \
    XXX( WERR_SERVICE_LOGON_FAILED                         , 1069      ) /* 0x0000042d */ \
    XXX( WERR_SERVICE_START_HANG                           , 1070      ) /* 0x0000042e */ \
    XXX( WERR_INVALID_SERVICE_LOCK                         , 1071      ) /* 0x0000042f */ \
    XXX( WERR_SERVICE_MARKED_FOR_DELETE                    , 1072      ) /* 0x00000430 */ \
    XXX( WERR_SERVICE_EXISTS                               , 1073      ) /* 0x00000431 */ \
    XXX( WERR_ALREADY_RUNNING_LKG                          , 1074      ) /* 0x00000432 */ \
    XXX( WERR_SERVICE_DEPENDENCY_DELETED                   , 1075      ) /* 0x00000433 */ \
    XXX( WERR_BOOT_ALREADY_ACCEPTED                        , 1076      ) /* 0x00000434 */ \
    XXX( WERR_SERVICE_NEVER_STARTED                        , 1077      ) /* 0x00000435 */ \
    XXX( WERR_DUPLICATE_SERVICE_NAME                       , 1078      ) /* 0x00000436 */ \
    XXX( WERR_DIFFERENT_SERVICE_ACCOUNT                    , 1079      ) /* 0x00000437 */ \
    XXX( WERR_CANNOT_DETECT_DRIVER_FAILURE                 , 1080      ) /* 0x00000438 */ \
    XXX( WERR_CANNOT_DETECT_PROCESS_ABORT                  , 1081      ) /* 0x00000439 */ \
    XXX( WERR_NO_RECOVERY_PROGRAM                          , 1082      ) /* 0x0000043a */ \
    XXX( WERR_SERVICE_NOT_IN_EXE                           , 1083      ) /* 0x0000043b */ \
    XXX( WERR_NOT_SAFEBOOT_SERVICE                         , 1084      ) /* 0x0000043c */ \
    XXX( WERR_END_OF_MEDIA                                 , 1100      ) /* 0x0000044c */ \
    XXX( WERR_FILEMARK_DETECTED                            , 1101      ) /* 0x0000044d */ \
    XXX( WERR_BEGINNING_OF_MEDIA                           , 1102      ) /* 0x0000044e */ \
    XXX( WERR_SETMARK_DETECTED                             , 1103      ) /* 0x0000044f */ \
    XXX( WERR_NO_DATA_DETECTED                             , 1104      ) /* 0x00000450 */ \
    XXX( WERR_PARTITION_FAILURE                            , 1105      ) /* 0x00000451 */ \
    XXX( WERR_INVALID_BLOCK_LENGTH                         , 1106      ) /* 0x00000452 */ \
    XXX( WERR_DEVICE_NOT_PARTITIONED                       , 1107      ) /* 0x00000453 */ \
    XXX( WERR_UNABLE_TO_LOCK_MEDIA                         , 1108      ) /* 0x00000454 */ \
    XXX( WERR_UNABLE_TO_UNLOAD_MEDIA                       , 1109      ) /* 0x00000455 */ \
    XXX( WERR_MEDIA_CHANGED                                , 1110      ) /* 0x00000456 */ \
    XXX( WERR_BUS_RESET                                    , 1111      ) /* 0x00000457 */ \
    XXX( WERR_NO_MEDIA_IN_DRIVE                            , 1112      ) /* 0x00000458 */ \
    XXX( WERR_NO_UNICODE_TRANSLATION                       , 1113      ) /* 0x00000459 */ \
    XXX( WERR_DLL_INIT_FAILED                              , 1114      ) /* 0x0000045a */ \
    XXX( WERR_SHUTDOWN_IN_PROGRESS                         , 1115      ) /* 0x0000045b */ \
    XXX( WERR_NO_SHUTDOWN_IN_PROGRESS                      , 1116      ) /* 0x0000045c */ \
    XXX( WERR_IO_DEVICE                                    , 1117      ) /* 0x0000045d */ \
    XXX( WERR_SERIAL_NO_DEVICE                             , 1118      ) /* 0x0000045e */ \
    XXX( WERR_IRQ_BUSY                                     , 1119      ) /* 0x0000045f */ \
    XXX( WERR_MORE_WRITES                                  , 1120      ) /* 0x00000460 */ \
    XXX( WERR_COUNTER_TIMEOUT                              , 1121      ) /* 0x00000461 */ \
    XXX( WERR_FLOPPY_ID_MARK_NOT_FOUND                     , 1122      ) /* 0x00000462 */ \
    XXX( WERR_FLOPPY_WRONG_CYLINDER                        , 1123      ) /* 0x00000463 */ \
    XXX( WERR_FLOPPY_UNKNOWN_ERROR                         , 1124      ) /* 0x00000464 */ \
    XXX( WERR_FLOPPY_BAD_REGISTERS                         , 1125      ) /* 0x00000465 */ \
    XXX( WERR_DISK_RECALIBRATE_FAILED                      , 1126      ) /* 0x00000466 */ \
    XXX( WERR_DISK_OPERATION_FAILED                        , 1127      ) /* 0x00000467 */ \
    XXX( WERR_DISK_RESET_FAILED                            , 1128      ) /* 0x00000468 */ \
    XXX( WERR_EOM_OVERFLOW                                 , 1129      ) /* 0x00000469 */ \
    XXX( WERR_NOT_ENOUGH_SERVER_MEMORY                     , 1130      ) /* 0x0000046a */ \
    XXX( WERR_POSSIBLE_DEADLOCK                            , 1131      ) /* 0x0000046b */ \
    XXX( WERR_MAPPED_ALIGNMENT                             , 1132      ) /* 0x0000046c */ \
    XXX( WERR_SET_POWER_STATE_VETOED                       , 1140      ) /* 0x00000474 */ \
    XXX( WERR_SET_POWER_STATE_FAILED                       , 1141      ) /* 0x00000475 */ \
    XXX( WERR_TOO_MANY_LINKS                               , 1142      ) /* 0x00000476 */ \
    XXX( WERR_OLD_WIN_VERSION                              , 1150      ) /* 0x0000047e */ \
    XXX( WERR_APP_WRONG_OS                                 , 1151      ) /* 0x0000047f */ \
    XXX( WERR_SINGLE_INSTANCE_APP                          , 1152      ) /* 0x00000480 */ \
    XXX( WERR_RMODE_APP                                    , 1153      ) /* 0x00000481 */ \
    XXX( WERR_INVALID_DLL                                  , 1154      ) /* 0x00000482 */ \
    XXX( WERR_NO_ASSOCIATION                               , 1155      ) /* 0x00000483 */ \
    XXX( WERR_DDE_FAIL                                     , 1156      ) /* 0x00000484 */ \
    XXX( WERR_DLL_NOT_FOUND                                , 1157      ) /* 0x00000485 */ \
    XXX( WERR_NO_MORE_USER_HANDLES                         , 1158      ) /* 0x00000486 */ \
    XXX( WERR_MESSAGE_SYNC_ONLY                            , 1159      ) /* 0x00000487 */ \
    XXX( WERR_SOURCE_ELEMENT_EMPTY                         , 1160      ) /* 0x00000488 */ \
    XXX( WERR_DESTINATION_ELEMENT_FULL                     , 1161      ) /* 0x00000489 */ \
    XXX( WERR_ILLEGAL_ELEMENT_ADDRESS                      , 1162      ) /* 0x0000048a */ \
    XXX( WERR_MAGAZINE_NOT_PRESENT                         , 1163      ) /* 0x0000048b */ \
    XXX( WERR_DEVICE_REINITIALIZATION_NEEDED               , 1164      ) /* 0x0000048c */ \
    XXX( WERR_DEVICE_REQUIRES_CLEANING                     , 1165      ) /* 0x0000048d */ \
    XXX( WERR_DEVICE_DOOR_OPEN                             , 1166      ) /* 0x0000048e */ \
    XXX( WERR_DEVICE_NOT_CONNECTED                         , 1167      ) /* 0x0000048f */ \
    XXX( WERR_NOT_FOUND                                    , 1168      ) /* 0x00000490 */ \
    XXX( WERR_NO_MATCH                                     , 1169      ) /* 0x00000491 */ \
    XXX( WERR_SET_NOT_FOUND                                , 1170      ) /* 0x00000492 */ \
    XXX( WERR_POINT_NOT_FOUND                              , 1171      ) /* 0x00000493 */ \
    XXX( WERR_NO_TRACKING_SERVICE                          , 1172      ) /* 0x00000494 */ \
    XXX( WERR_NO_VOLUME_ID                                 , 1173      ) /* 0x00000495 */ \
    XXX( WERR_UNABLE_TO_REMOVE_REPLACED                    , 1175      ) /* 0x00000497 */ \
    XXX( WERR_UNABLE_TO_MOVE_REPLACEMENT                   , 1176      ) /* 0x00000498 */ \
    XXX( WERR_UNABLE_TO_MOVE_REPLACEMENT_2                 , 1177      ) /* 0x00000499 */ \
    XXX( WERR_JOURNAL_DELETE_IN_PROGRESS                   , 1178      ) /* 0x0000049a */ \
    XXX( WERR_JOURNAL_NOT_ACTIVE                           , 1179      ) /* 0x0000049b */ \
    XXX( WERR_POTENTIAL_FILE_FOUND                         , 1180      ) /* 0x0000049c */ \
    XXX( WERR_JOURNAL_ENTRY_DELETED                        , 1181      ) /* 0x0000049d */ \
    XXX( WERR_SHUTDOWN_IS_SCHEDULED                        , 1190      ) /* 0x000004a6 */ \
    XXX( WERR_SHUTDOWN_USERS_LOGGED_ON                     , 1191      ) /* 0x000004a7 */ \
    XXX( WERR_BAD_DEVICE                                   , 1200      ) /* 0x000004b0 */ \
    XXX( WERR_CONNECTION_UNAVAIL                           , 1201      ) /* 0x000004b1 */ \
    XXX( WERR_DEVICE_ALREADY_REMEMBERED                    , 1202      ) /* 0x000004b2 */ \
    XXX( WERR_NO_NET_OR_BAD_PATH                           , 1203      ) /* 0x000004b3 */ \
    XXX( WERR_BAD_PROVIDER                                 , 1204      ) /* 0x000004b4 */ \
    XXX( WERR_CANNOT_OPEN_PROFILE                          , 1205      ) /* 0x000004b5 */ \
    XXX( WERR_BAD_PROFILE                                  , 1206      ) /* 0x000004b6 */ \
    XXX( WERR_NOT_CONTAINER                                , 1207      ) /* 0x000004b7 */ \
    XXX( WERR_EXTENDED_ERROR                               , 1208      ) /* 0x000004b8 */ \
    XXX( WERR_INVALID_GROUPNAME                            , 1209      ) /* 0x000004b9 */ \
    XXX( WERR_INVALID_COMPUTERNAME                         , 1210      ) /* 0x000004ba */ \
    XXX( WERR_INVALID_EVENTNAME                            , 1211      ) /* 0x000004bb */ \
    XXX( WERR_INVALID_DOMAINNAME                           , 1212      ) /* 0x000004bc */ \
    XXX( WERR_INVALID_SERVICENAME                          , 1213      ) /* 0x000004bd */ \
    XXX( WERR_INVALID_NETNAME                              , 1214      ) /* 0x000004be */ \
    XXX( WERR_INVALID_SHARENAME                            , 1215      ) /* 0x000004bf */ \
    XXX( WERR_INVALID_PASSWORDNAME                         , 1216      ) /* 0x000004c0 */ \
    XXX( WERR_INVALID_MESSAGENAME                          , 1217      ) /* 0x000004c1 */ \
    XXX( WERR_INVALID_MESSAGEDEST                          , 1218      ) /* 0x000004c2 */ \
    XXX( WERR_SESSION_CREDENTIAL_CONFLICT                  , 1219      ) /* 0x000004c3 */ \
    XXX( WERR_REMOTE_SESSION_LIMIT_EXCEEDED                , 1220      ) /* 0x000004c4 */ \
    XXX( WERR_DUP_DOMAINNAME                               , 1221      ) /* 0x000004c5 */ \
    XXX( WERR_NO_NETWORK                                   , 1222      ) /* 0x000004c6 */ \
    XXX( WERR_CANCELLED                                    , 1223      ) /* 0x000004c7 */ \
    XXX( WERR_USER_MAPPED_FILE                             , 1224      ) /* 0x000004c8 */ \
    XXX( WERR_CONNECTION_REFUSED                           , 1225      ) /* 0x000004c9 */ \
    XXX( WERR_GRACEFUL_DISCONNECT                          , 1226      ) /* 0x000004ca */ \
    XXX( WERR_ADDRESS_ALREADY_ASSOCIATED                   , 1227      ) /* 0x000004cb */ \
    XXX( WERR_ADDRESS_NOT_ASSOCIATED                       , 1228      ) /* 0x000004cc */ \
    XXX( WERR_CONNECTION_INVALID                           , 1229      ) /* 0x000004cd */ \
    XXX( WERR_CONNECTION_ACTIVE                            , 1230      ) /* 0x000004ce */ \
    XXX( WERR_NETWORK_UNREACHABLE                          , 1231      ) /* 0x000004cf */ \
    XXX( WERR_HOST_UNREACHABLE                             , 1232      ) /* 0x000004d0 */ \
    XXX( WERR_PROTOCOL_UNREACHABLE                         , 1233      ) /* 0x000004d1 */ \
    XXX( WERR_PORT_UNREACHABLE                             , 1234      ) /* 0x000004d2 */ \
    XXX( WERR_REQUEST_ABORTED                              , 1235      ) /* 0x000004d3 */ \
    XXX( WERR_CONNECTION_ABORTED                           , 1236      ) /* 0x000004d4 */ \
    XXX( WERR_RETRY                                        , 1237      ) /* 0x000004d5 */ \
    XXX( WERR_CONNECTION_COUNT_LIMIT                       , 1238      ) /* 0x000004d6 */ \
    XXX( WERR_LOGIN_TIME_RESTRICTION                       , 1239      ) /* 0x000004d7 */ \
    XXX( WERR_LOGIN_WKSTA_RESTRICTION                      , 1240      ) /* 0x000004d8 */ \
    XXX( WERR_INCORRECT_ADDRESS                            , 1241      ) /* 0x000004d9 */ \
    XXX( WERR_ALREADY_REGISTERED                           , 1242      ) /* 0x000004da */ \
    XXX( WERR_SERVICE_NOT_FOUND                            , 1243      ) /* 0x000004db */ \
    XXX( WERR_NOT_AUTHENTICATED                            , 1244      ) /* 0x000004dc */ \
    XXX( WERR_NOT_LOGGED_ON                                , 1245      ) /* 0x000004dd */ \
    XXX( WERR_CONTINUE                                     , 1246      ) /* 0x000004de */ \
    XXX( WERR_ALREADY_INITIALIZED                          , 1247      ) /* 0x000004df */ \
    XXX( WERR_NO_MORE_DEVICES                              , 1248      ) /* 0x000004e0 */ \
    XXX( WERR_NO_SUCH_SITE                                 , 1249      ) /* 0x000004e1 */ \
    XXX( WERR_DOMAIN_CONTROLLER_EXISTS                     , 1250      ) /* 0x000004e2 */ \
    XXX( WERR_ONLY_IF_CONNECTED                            , 1251      ) /* 0x000004e3 */ \
    XXX( WERR_OVERRIDE_NOCHANGES                           , 1252      ) /* 0x000004e4 */ \
    XXX( WERR_BAD_USER_PROFILE                             , 1253      ) /* 0x000004e5 */ \
    XXX( WERR_NOT_SUPPORTED_ON_SBS                         , 1254      ) /* 0x000004e6 */ \
    XXX( WERR_SERVER_SHUTDOWN_IN_PROGRESS                  , 1255      ) /* 0x000004e7 */ \
    XXX( WERR_HOST_DOWN                                    , 1256      ) /* 0x000004e8 */ \
    XXX( WERR_NON_ACCOUNT_SID                              , 1257      ) /* 0x000004e9 */ \
    XXX( WERR_NON_DOMAIN_SID                               , 1258      ) /* 0x000004ea */ \
    XXX( WERR_APPHELP_BLOCK                                , 1259      ) /* 0x000004eb */ \
    XXX( WERR_ACCESS_DISABLED_BY_POLICY                    , 1260      ) /* 0x000004ec */ \
    XXX( WERR_REG_NAT_CONSUMPTION                          , 1261      ) /* 0x000004ed */ \
    XXX( WERR_CSCSHARE_OFFLINE                             , 1262      ) /* 0x000004ee */ \
    XXX( WERR_PKINIT_FAILURE                               , 1263      ) /* 0x000004ef */ \
    XXX( WERR_SMARTCARD_SUBSYSTEM_FAILURE                  , 1264      ) /* 0x000004f0 */ \
    XXX( WERR_DOWNGRADE_DETECTED                           , 1265      ) /* 0x000004f1 */ \
    XXX( WERR_MACHINE_LOCKED                               , 1271      ) /* 0x000004f7 */ \
    XXX( WERR_CALLBACK_SUPPLIED_INVALID_DATA               , 1273      ) /* 0x000004f9 */ \
    XXX( WERR_SYNC_FOREGROUND_REFRESH_REQUIRED             , 1274      ) /* 0x000004fa */ \
    XXX( WERR_DRIVER_BLOCKED                               , 1275      ) /* 0x000004fb */ \
    XXX( WERR_INVALID_IMPORT_OF_NON_DLL                    , 1276      ) /* 0x000004fc */ \
    XXX( WERR_ACCESS_DISABLED_WEBBLADE                     , 1277      ) /* 0x000004fd */ \
    XXX( WERR_ACCESS_DISABLED_WEBBLADE_TAMPER              , 1278      ) /* 0x000004fe */ \
    XXX( WERR_RECOVERY_FAILURE                             , 1279      ) /* 0x000004ff */ \
    XXX( WERR_ALREADY_FIBER                                , 1280      ) /* 0x00000500 */ \
    XXX( WERR_ALREADY_THREAD                               , 1281      ) /* 0x00000501 */ \
    XXX( WERR_STACK_BUFFER_OVERRUN                         , 1282      ) /* 0x00000502 */ \
    XXX( WERR_PARAMETER_QUOTA_EXCEEDED                     , 1283      ) /* 0x00000503 */ \
    XXX( WERR_DEBUGGER_INACTIVE                            , 1284      ) /* 0x00000504 */ \
    XXX( WERR_DELAY_LOAD_FAILED                            , 1285      ) /* 0x00000505 */ \
    XXX( WERR_VDM_DISALLOWED                               , 1286      ) /* 0x00000506 */ \
    XXX( WERR_UNIDENTIFIED_ERROR                           , 1287      ) /* 0x00000507 */ \
    XXX( WERR_BEYOND_VDL                                   , 1289      ) /* 0x00000509 */ \
    XXX( WERR_INCOMPATIBLE_SERVICE_SID_TYPE                , 1290      ) /* 0x0000050a */ \
    XXX( WERR_DRIVER_PROCESS_TERMINATED                    , 1291      ) /* 0x0000050b */ \
    XXX( WERR_IMPLEMENTATION_LIMIT                         , 1292      ) /* 0x0000050c */ \
    XXX( WERR_PROCESS_IS_PROTECTED                         , 1293      ) /* 0x0000050d */ \
    XXX( WERR_SERVICE_NOTIFY_CLIENT_LAGGING                , 1294      ) /* 0x0000050e */ \
    XXX( WERR_DISK_QUOTA_EXCEEDED                          , 1295      ) /* 0x0000050f */ \
    XXX( WERR_CONTENT_BLOCKED                              , 1296      ) /* 0x00000510 */ \
    XXX( WERR_INCOMPATIBLE_SERVICE_PRIVILEGE               , 1297      ) /* 0x00000511 */ \
    XXX( WERR_INVALID_LABEL                                , 1299      ) /* 0x00000513 */ \
    XXX( WERR_NOT_ALL_ASSIGNED                             , 1300      ) /* 0x00000514 */ \
    XXX( WERR_SOME_NOT_MAPPED                              , 1301      ) /* 0x00000515 */ \
    XXX( WERR_NO_QUOTAS_FOR_ACCOUNT                        , 1302      ) /* 0x00000516 */ \
    XXX( WERR_LOCAL_USER_SESSION_KEY                       , 1303      ) /* 0x00000517 */ \
    XXX( WERR_NULL_LM_PASSWORD                             , 1304      ) /* 0x00000518 */ \
    XXX( WERR_UNKNOWN_REVISION                             , 1305      ) /* 0x00000519 */ \
    XXX( WERR_REVISION_MISMATCH                            , 1306      ) /* 0x0000051a */ \
    XXX( WERR_INVALID_OWNER                                , 1307      ) /* 0x0000051b */ \
    XXX( WERR_INVALID_PRIMARY_GROUP                        , 1308      ) /* 0x0000051c */ \
    XXX( WERR_NO_IMPERSONATION_TOKEN                       , 1309      ) /* 0x0000051d */ \
    XXX( WERR_CANT_DISABLE_MANDATORY                       , 1310      ) /* 0x0000051e */ \
    XXX( WERR_NO_LOGON_SERVERS                             , 1311      ) /* 0x0000051f */ \
    XXX( WERR_NO_SUCH_LOGON_SESSION                        , 1312      ) /* 0x00000520 */ \
    XXX( WERR_NO_SUCH_PRIVILEGE                            , 1313      ) /* 0x00000521 */ \
    XXX( WERR_PRIVILEGE_NOT_HELD                           , 1314      ) /* 0x00000522 */ \
    XXX( WERR_INVALID_ACCOUNT_NAME                         , 1315      ) /* 0x00000523 */ \
    XXX( WERR_USER_EXISTS                                  , 1316      ) /* 0x00000524 */ \
    XXX( WERR_NO_SUCH_USER                                 , 1317      ) /* 0x00000525 */ \
    XXX( WERR_GROUP_EXISTS                                 , 1318      ) /* 0x00000526 */ \
    XXX( WERR_NO_SUCH_GROUP                                , 1319      ) /* 0x00000527 */ \
    XXX( WERR_MEMBER_IN_GROUP                              , 1320      ) /* 0x00000528 */ \
    XXX( WERR_MEMBER_NOT_IN_GROUP                          , 1321      ) /* 0x00000529 */ \
    XXX( WERR_LAST_ADMIN                                   , 1322      ) /* 0x0000052a */ \
    XXX( WERR_WRONG_PASSWORD                               , 1323      ) /* 0x0000052b */ \
    XXX( WERR_ILL_FORMED_PASSWORD                          , 1324      ) /* 0x0000052c */ \
    XXX( WERR_PASSWORD_RESTRICTION                         , 1325      ) /* 0x0000052d */ \
    XXX( WERR_LOGON_FAILURE                                , 1326      ) /* 0x0000052e */ \
    XXX( WERR_ACCOUNT_RESTRICTION                          , 1327      ) /* 0x0000052f */ \
    XXX( WERR_INVALID_LOGON_HOURS                          , 1328      ) /* 0x00000530 */ \
    XXX( WERR_INVALID_WORKSTATION                          , 1329      ) /* 0x00000531 */ \
    XXX( WERR_PASSWORD_EXPIRED                             , 1330      ) /* 0x00000532 */ \
    XXX( WERR_ACCOUNT_DISABLED                             , 1331      ) /* 0x00000533 */ \
    XXX( WERR_NONE_MAPPED                                  , 1332      ) /* 0x00000534 */ \
    XXX( WERR_TOO_MANY_LUIDS_REQUESTED                     , 1333      ) /* 0x00000535 */ \
    XXX( WERR_LUIDS_EXHAUSTED                              , 1334      ) /* 0x00000536 */ \
    XXX( WERR_INVALID_SUB_AUTHORITY                        , 1335      ) /* 0x00000537 */ \
    XXX( WERR_INVALID_ACL                                  , 1336      ) /* 0x00000538 */ \
    XXX( WERR_INVALID_SID                                  , 1337      ) /* 0x00000539 */ \
    XXX( WERR_INVALID_SECURITY_DESCR                       , 1338      ) /* 0x0000053a */ \
    XXX( WERR_BAD_INHERITANCE_ACL                          , 1340      ) /* 0x0000053c */ \
    XXX( WERR_SERVER_DISABLED                              , 1341      ) /* 0x0000053d */ \
    XXX( WERR_SERVER_NOT_DISABLED                          , 1342      ) /* 0x0000053e */ \
    XXX( WERR_INVALID_ID_AUTHORITY                         , 1343      ) /* 0x0000053f */ \
    XXX( WERR_ALLOTTED_SPACE_EXCEEDED                      , 1344      ) /* 0x00000540 */ \
    XXX( WERR_INVALID_GROUP_ATTRIBUTES                     , 1345      ) /* 0x00000541 */ \
    XXX( WERR_BAD_IMPERSONATION_LEVEL                      , 1346      ) /* 0x00000542 */ \
    XXX( WERR_CANT_OPEN_ANONYMOUS                          , 1347      ) /* 0x00000543 */ \
    XXX( WERR_BAD_VALIDATION_CLASS                         , 1348      ) /* 0x00000544 */ \
    XXX( WERR_BAD_TOKEN_TYPE                               , 1349      ) /* 0x00000545 */ \
    XXX( WERR_NO_SECURITY_ON_OBJECT                        , 1350      ) /* 0x00000546 */ \
    XXX( WERR_CANT_ACCESS_DOMAIN_INFO                      , 1351      ) /* 0x00000547 */ \
    XXX( WERR_INVALID_SERVER_STATE                         , 1352      ) /* 0x00000548 */ \
    XXX( WERR_INVALID_DOMAIN_STATE                         , 1353      ) /* 0x00000549 */ \
    XXX( WERR_INVALID_DOMAIN_ROLE                          , 1354      ) /* 0x0000054a */ \
    XXX( WERR_NO_SUCH_DOMAIN                               , 1355      ) /* 0x0000054b */ \
    XXX( WERR_DOMAIN_EXISTS                                , 1356      ) /* 0x0000054c */ \
    XXX( WERR_DOMAIN_LIMIT_EXCEEDED                        , 1357      ) /* 0x0000054d */ \
    XXX( WERR_INTERNAL_DB_CORRUPTION                       , 1358      ) /* 0x0000054e */ \
    XXX( WERR_INTERNAL_ERROR                               , 1359      ) /* 0x0000054f */ \
    XXX( WERR_GENERIC_NOT_MAPPED                           , 1360      ) /* 0x00000550 */ \
    XXX( WERR_BAD_DESCRIPTOR_FORMAT                        , 1361      ) /* 0x00000551 */ \
    XXX( WERR_NOT_LOGON_PROCESS                            , 1362      ) /* 0x00000552 */ \
    XXX( WERR_LOGON_SESSION_EXISTS                         , 1363      ) /* 0x00000553 */ \
    XXX( WERR_NO_SUCH_PACKAGE                              , 1364      ) /* 0x00000554 */ \
    XXX( WERR_BAD_LOGON_SESSION_STATE                      , 1365      ) /* 0x00000555 */ \
    XXX( WERR_LOGON_SESSION_COLLISION                      , 1366      ) /* 0x00000556 */ \
    XXX( WERR_INVALID_LOGON_TYPE                           , 1367      ) /* 0x00000557 */ \
    XXX( WERR_CANNOT_IMPERSONATE                           , 1368      ) /* 0x00000558 */ \
    XXX( WERR_RXACT_INVALID_STATE                          , 1369      ) /* 0x00000559 */ \
    XXX( WERR_RXACT_COMMIT_FAILURE                         , 1370      ) /* 0x0000055a */ \
    XXX( WERR_SPECIAL_ACCOUNT                              , 1371      ) /* 0x0000055b */ \
    XXX( WERR_SPECIAL_GROUP                                , 1372      ) /* 0x0000055c */ \
    XXX( WERR_SPECIAL_USER                                 , 1373      ) /* 0x0000055d */ \
    XXX( WERR_MEMBERS_PRIMARY_GROUP                        , 1374      ) /* 0x0000055e */ \
    XXX( WERR_TOKEN_ALREADY_IN_USE                         , 1375      ) /* 0x0000055f */ \
    XXX( WERR_NO_SUCH_ALIAS                                , 1376      ) /* 0x00000560 */ \
    XXX( WERR_MEMBER_NOT_IN_ALIAS                          , 1377      ) /* 0x00000561 */ \
    XXX( WERR_MEMBER_IN_ALIAS                              , 1378      ) /* 0x00000562 */ \
    XXX( WERR_ALIAS_EXISTS                                 , 1379      ) /* 0x00000563 */ \
    XXX( WERR_LOGON_NOT_GRANTED                            , 1380      ) /* 0x00000564 */ \
    XXX( WERR_TOO_MANY_SECRETS                             , 1381      ) /* 0x00000565 */ \
    XXX( WERR_SECRET_TOO_LONG                              , 1382      ) /* 0x00000566 */ \
    XXX( WERR_INTERNAL_DB_ERROR                            , 1383      ) /* 0x00000567 */ \
    XXX( WERR_TOO_MANY_CONTEXT_IDS                         , 1384      ) /* 0x00000568 */ \
    XXX( WERR_LOGON_TYPE_NOT_GRANTED                       , 1385      ) /* 0x00000569 */ \
    XXX( WERR_NT_CROSS_ENCRYPTION_REQUIRED                 , 1386      ) /* 0x0000056a */ \
    XXX( WERR_NO_SUCH_MEMBER                               , 1387      ) /* 0x0000056b */ \
    XXX( WERR_INVALID_MEMBER                               , 1388      ) /* 0x0000056c */ \
    XXX( WERR_TOO_MANY_SIDS                                , 1389      ) /* 0x0000056d */ \
    XXX( WERR_LM_CROSS_ENCRYPTION_REQUIRED                 , 1390      ) /* 0x0000056e */ \
    XXX( WERR_NO_INHERITANCE                               , 1391      ) /* 0x0000056f */ \
    XXX( WERR_FILE_CORRUPT                                 , 1392      ) /* 0x00000570 */ \
    XXX( WERR_DISK_CORRUPT                                 , 1393      ) /* 0x00000571 */ \
    XXX( WERR_NO_USER_SESSION_KEY                          , 1394      ) /* 0x00000572 */ \
    XXX( WERR_LICENSE_QUOTA_EXCEEDED                       , 1395      ) /* 0x00000573 */ \
    XXX( WERR_WRONG_TARGET_NAME                            , 1396      ) /* 0x00000574 */ \
    XXX( WERR_MUTUAL_AUTH_FAILED                           , 1397      ) /* 0x00000575 */ \
    XXX( WERR_TIME_SKEW                                    , 1398      ) /* 0x00000576 */ \
    XXX( WERR_CURRENT_DOMAIN_NOT_ALLOWED                   , 1399      ) /* 0x00000577 */ \
    XXX( WERR_INVALID_WINDOW_HANDLE                        , 1400      ) /* 0x00000578 */ \
    XXX( WERR_INVALID_MENU_HANDLE                          , 1401      ) /* 0x00000579 */ \
    XXX( WERR_INVALID_CURSOR_HANDLE                        , 1402      ) /* 0x0000057a */ \
    XXX( WERR_INVALID_ACCEL_HANDLE                         , 1403      ) /* 0x0000057b */ \
    XXX( WERR_INVALID_HOOK_HANDLE                          , 1404      ) /* 0x0000057c */ \
    XXX( WERR_INVALID_DWP_HANDLE                           , 1405      ) /* 0x0000057d */ \
    XXX( WERR_TLW_WITH_WSCHILD                             , 1406      ) /* 0x0000057e */ \
    XXX( WERR_CANNOT_FIND_WND_CLASS                        , 1407      ) /* 0x0000057f */ \
    XXX( WERR_WINDOW_OF_OTHER_THREAD                       , 1408      ) /* 0x00000580 */ \
    XXX( WERR_HOTKEY_ALREADY_REGISTERED                    , 1409      ) /* 0x00000581 */ \
    XXX( WERR_CLASS_ALREADY_EXISTS                         , 1410      ) /* 0x00000582 */ \
    XXX( WERR_CLASS_DOES_NOT_EXIST                         , 1411      ) /* 0x00000583 */ \
    XXX( WERR_CLASS_HAS_WINDOWS                            , 1412      ) /* 0x00000584 */ \
    XXX( WERR_INVALID_INDEX                                , 1413      ) /* 0x00000585 */ \
    XXX( WERR_INVALID_ICON_HANDLE                          , 1414      ) /* 0x00000586 */ \
    XXX( WERR_PRIVATE_DIALOG_INDEX                         , 1415      ) /* 0x00000587 */ \
    XXX( WERR_LISTBOX_ID_NOT_FOUND                         , 1416      ) /* 0x00000588 */ \
    XXX( WERR_NO_WILDCARD_CHARACTERS                       , 1417      ) /* 0x00000589 */ \
    XXX( WERR_CLIPBOARD_NOT_OPEN                           , 1418      ) /* 0x0000058a */ \
    XXX( WERR_HOTKEY_NOT_REGISTERED                        , 1419      ) /* 0x0000058b */ \
    XXX( WERR_WINDOW_NOT_DIALOG                            , 1420      ) /* 0x0000058c */ \
    XXX( WERR_CONTROL_ID_NOT_FOUND                         , 1421      ) /* 0x0000058d */ \
    XXX( WERR_INVALID_COMBOBOX_MESSAGE                     , 1422      ) /* 0x0000058e */ \
    XXX( WERR_WINDOW_NOT_COMBOBOX                          , 1423      ) /* 0x0000058f */ \
    XXX( WERR_INVALID_EDIT_HEIGHT                          , 1424      ) /* 0x00000590 */ \
    XXX( WERR_DC_NOT_FOUND                                 , 1425      ) /* 0x00000591 */ \
    XXX( WERR_INVALID_HOOK_FILTER                          , 1426      ) /* 0x00000592 */ \
    XXX( WERR_INVALID_FILTER_PROC                          , 1427      ) /* 0x00000593 */ \
    XXX( WERR_HOOK_NEEDS_HMOD                              , 1428      ) /* 0x00000594 */ \
    XXX( WERR_GLOBAL_ONLY_HOOK                             , 1429      ) /* 0x00000595 */ \
    XXX( WERR_JOURNAL_HOOK_SET                             , 1430      ) /* 0x00000596 */ \
    XXX( WERR_HOOK_NOT_INSTALLED                           , 1431      ) /* 0x00000597 */ \
    XXX( WERR_INVALID_LB_MESSAGE                           , 1432      ) /* 0x00000598 */ \
    XXX( WERR_SETCOUNT_ON_BAD_LB                           , 1433      ) /* 0x00000599 */ \
    XXX( WERR_LB_WITHOUT_TABSTOPS                          , 1434      ) /* 0x0000059a */ \
    XXX( WERR_DESTROY_OBJECT_OF_OTHER_THREAD               , 1435      ) /* 0x0000059b */ \
    XXX( WERR_CHILD_WINDOW_MENU                            , 1436      ) /* 0x0000059c */ \
    XXX( WERR_NO_SYSTEM_MENU                               , 1437      ) /* 0x0000059d */ \
    XXX( WERR_INVALID_MSGBOX_STYLE                         , 1438      ) /* 0x0000059e */ \
    XXX( WERR_INVALID_SPI_VALUE                            , 1439      ) /* 0x0000059f */ \
    XXX( WERR_SCREEN_ALREADY_LOCKED                        , 1440      ) /* 0x000005a0 */ \
    XXX( WERR_HWNDS_HAVE_DIFF_PARENT                       , 1441      ) /* 0x000005a1 */ \
    XXX( WERR_NOT_CHILD_WINDOW                             , 1442      ) /* 0x000005a2 */ \
    XXX( WERR_INVALID_GW_COMMAND                           , 1443      ) /* 0x000005a3 */ \
    XXX( WERR_INVALID_THREAD_ID                            , 1444      ) /* 0x000005a4 */ \
    XXX( WERR_NON_MDICHILD_WINDOW                          , 1445      ) /* 0x000005a5 */ \
    XXX( WERR_POPUP_ALREADY_ACTIVE                         , 1446      ) /* 0x000005a6 */ \
    XXX( WERR_NO_SCROLLBARS                                , 1447      ) /* 0x000005a7 */ \
    XXX( WERR_INVALID_SCROLLBAR_RANGE                      , 1448      ) /* 0x000005a8 */ \
    XXX( WERR_INVALID_SHOWWIN_COMMAND                      , 1449      ) /* 0x000005a9 */ \
    XXX( WERR_NO_SYSTEM_RESOURCES                          , 1450      ) /* 0x000005aa */ \
    XXX( WERR_NONPAGED_SYSTEM_RESOURCES                    , 1451      ) /* 0x000005ab */ \
    XXX( WERR_PAGED_SYSTEM_RESOURCES                       , 1452      ) /* 0x000005ac */ \
    XXX( WERR_WORKING_SET_QUOTA                            , 1453      ) /* 0x000005ad */ \
    XXX( WERR_PAGEFILE_QUOTA                               , 1454      ) /* 0x000005ae */ \
    XXX( WERR_COMMITMENT_LIMIT                             , 1455      ) /* 0x000005af */ \
    XXX( WERR_MENU_ITEM_NOT_FOUND                          , 1456      ) /* 0x000005b0 */ \
    XXX( WERR_INVALID_KEYBOARD_HANDLE                      , 1457      ) /* 0x000005b1 */ \
    XXX( WERR_HOOK_TYPE_NOT_ALLOWED                        , 1458      ) /* 0x000005b2 */ \
    XXX( WERR_REQUIRES_INTERACTIVE_WINDOWSTATION           , 1459      ) /* 0x000005b3 */ \
    XXX( WERR_TIMEOUT                                      , 1460      ) /* 0x000005b4 */ \
    XXX( WERR_INVALID_MONITOR_HANDLE                       , 1461      ) /* 0x000005b5 */ \
    XXX( WERR_INCORRECT_SIZE                               , 1462      ) /* 0x000005b6 */ \
    XXX( WERR_SYMLINK_CLASS_DISABLED                       , 1463      ) /* 0x000005b7 */ \
    XXX( WERR_SYMLINK_NOT_SUPPORTED                        , 1464      ) /* 0x000005b8 */ \
    XXX( WERR_EVENTLOG_FILE_CORRUPT                        , 1500      ) /* 0x000005dc */ \
    XXX( WERR_EVENTLOG_CANT_START                          , 1501      ) /* 0x000005dd */ \
    XXX( WERR_LOG_FILE_FULL                                , 1502      ) /* 0x000005de */ \
    XXX( WERR_EVENTLOG_FILE_CHANGED                        , 1503      ) /* 0x000005df */ \
    XXX( WERR_INVALID_TASK_NAME                            , 1550      ) /* 0x0000060e */ \
    XXX( WERR_INVALID_TASK_INDEX                           , 1551      ) /* 0x0000060f */ \
    XXX( WERR_THREAD_ALREADY_IN_TASK                       , 1552      ) /* 0x00000610 */ \
    XXX( WERR_INSTALL_SERVICE_FAILURE                      , 1601      ) /* 0x00000641 */ \
    XXX( WERR_INSTALL_USEREXIT                             , 1602      ) /* 0x00000642 */ \
    XXX( WERR_INSTALL_FAILURE                              , 1603      ) /* 0x00000643 */ \
    XXX( WERR_INSTALL_SUSPEND                              , 1604      ) /* 0x00000644 */ \
    XXX( WERR_UNKNOWN_PRODUCT                              , 1605      ) /* 0x00000645 */ \
    XXX( WERR_UNKNOWN_FEATURE                              , 1606      ) /* 0x00000646 */ \
    XXX( WERR_UNKNOWN_COMPONENT                            , 1607      ) /* 0x00000647 */ \
    XXX( WERR_UNKNOWN_PROPERTY                             , 1608      ) /* 0x00000648 */ \
    XXX( WERR_INVALID_HANDLE_STATE                         , 1609      ) /* 0x00000649 */ \
    XXX( WERR_BAD_CONFIGURATION                            , 1610      ) /* 0x0000064a */ \
    XXX( WERR_INDEX_ABSENT                                 , 1611      ) /* 0x0000064b */ \
    XXX( WERR_INSTALL_SOURCE_ABSENT                        , 1612      ) /* 0x0000064c */ \
    XXX( WERR_INSTALL_PACKAGE_VERSION                      , 1613      ) /* 0x0000064d */ \
    XXX( WERR_PRODUCT_UNINSTALLED                          , 1614      ) /* 0x0000064e */ \
    XXX( WERR_BAD_QUERY_SYNTAX                             , 1615      ) /* 0x0000064f */ \
    XXX( WERR_INVALID_FIELD                                , 1616      ) /* 0x00000650 */ \
    XXX( WERR_DEVICE_REMOVED                               , 1617      ) /* 0x00000651 */ \
    XXX( WERR_INSTALL_ALREADY_RUNNING                      , 1618      ) /* 0x00000652 */ \
    XXX( WERR_INSTALL_PACKAGE_OPEN_FAILED                  , 1619      ) /* 0x00000653 */ \
    XXX( WERR_INSTALL_PACKAGE_INVALID                      , 1620      ) /* 0x00000654 */ \
    XXX( WERR_INSTALL_UI_FAILURE                           , 1621      ) /* 0x00000655 */ \
    XXX( WERR_INSTALL_LOG_FAILURE                          , 1622      ) /* 0x00000656 */ \
    XXX( WERR_INSTALL_LANGUAGE_UNSUPPORTED                 , 1623      ) /* 0x00000657 */ \
    XXX( WERR_INSTALL_TRANSFORM_FAILURE                    , 1624      ) /* 0x00000658 */ \
    XXX( WERR_INSTALL_PACKAGE_REJECTED                     , 1625      ) /* 0x00000659 */ \
    XXX( WERR_FUNCTION_NOT_CALLED                          , 1626      ) /* 0x0000065a */ \
    XXX( WERR_FUNCTION_FAILED                              , 1627      ) /* 0x0000065b */ \
    XXX( WERR_INVALID_TABLE                                , 1628      ) /* 0x0000065c */ \
    XXX( WERR_DATATYPE_MISMATCH                            , 1629      ) /* 0x0000065d */ \
    XXX( WERR_UNSUPPORTED_TYPE                             , 1630      ) /* 0x0000065e */ \
    XXX( WERR_CREATE_FAILED                                , 1631      ) /* 0x0000065f */ \
    XXX( WERR_INSTALL_TEMP_UNWRITABLE                      , 1632      ) /* 0x00000660 */ \
    XXX( WERR_INSTALL_PLATFORM_UNSUPPORTED                 , 1633      ) /* 0x00000661 */ \
    XXX( WERR_INSTALL_NOTUSED                              , 1634      ) /* 0x00000662 */ \
    XXX( WERR_PATCH_PACKAGE_OPEN_FAILED                    , 1635      ) /* 0x00000663 */ \
    XXX( WERR_PATCH_PACKAGE_INVALID                        , 1636      ) /* 0x00000664 */ \
    XXX( WERR_PATCH_PACKAGE_UNSUPPORTED                    , 1637      ) /* 0x00000665 */ \
    XXX( WERR_PRODUCT_VERSION                              , 1638      ) /* 0x00000666 */ \
    XXX( WERR_INVALID_COMMAND_LINE                         , 1639      ) /* 0x00000667 */ \
    XXX( WERR_INSTALL_REMOTE_DISALLOWED                    , 1640      ) /* 0x00000668 */ \
    XXX( WERR_SUCCESS_REBOOT_INITIATED                     , 1641      ) /* 0x00000669 */ \
    XXX( WERR_PATCH_TARGET_NOT_FOUND                       , 1642      ) /* 0x0000066a */ \
    XXX( WERR_PATCH_PACKAGE_REJECTED                       , 1643      ) /* 0x0000066b */ \
    XXX( WERR_INSTALL_TRANSFORM_REJECTED                   , 1644      ) /* 0x0000066c */ \
    XXX( WERR_INSTALL_REMOTE_PROHIBITED                    , 1645      ) /* 0x0000066d */ \
    XXX( WERR_PATCH_REMOVAL_UNSUPPORTED                    , 1646      ) /* 0x0000066e */ \
    XXX( WERR_UNKNOWN_PATCH                                , 1647      ) /* 0x0000066f */ \
    XXX( WERR_PATCH_NO_SEQUENCE                            , 1648      ) /* 0x00000670 */ \
    XXX( WERR_PATCH_REMOVAL_DISALLOWED                     , 1649      ) /* 0x00000671 */ \
    XXX( WERR_INVALID_PATCH_XML                            , 1650      ) /* 0x00000672 */ \
    XXX( WERR_PATCH_MANAGED_ADVERTISED_PRODUCT             , 1651      ) /* 0x00000673 */ \
    XXX( WERR_INSTALL_SERVICE_SAFEBOOT                     , 1652      ) /* 0x00000674 */ \
    XXX( WERR_RPC_S_INVALID_STRING_BINDING                 , 1700      ) /* 0x000006a4 */ \
    XXX( WERR_RPC_S_WRONG_KIND_OF_BINDING                  , 1701      ) /* 0x000006a5 */ \
    XXX( WERR_RPC_S_INVALID_BINDING                        , 1702      ) /* 0x000006a6 */ \
    XXX( WERR_RPC_S_PROTSEQ_NOT_SUPPORTED                  , 1703      ) /* 0x000006a7 */ \
    XXX( WERR_RPC_S_INVALID_RPC_PROTSEQ                    , 1704      ) /* 0x000006a8 */ \
    XXX( WERR_RPC_S_INVALID_STRING_UUID                    , 1705      ) /* 0x000006a9 */ \
    XXX( WERR_RPC_S_INVALID_ENDPOINT_FORMAT                , 1706      ) /* 0x000006aa */ \
    XXX( WERR_RPC_S_INVALID_NET_ADDR                       , 1707      ) /* 0x000006ab */ \
    XXX( WERR_RPC_S_NO_ENDPOINT_FOUND                      , 1708      ) /* 0x000006ac */ \
    XXX( WERR_RPC_S_INVALID_TIMEOUT                        , 1709      ) /* 0x000006ad */ \
    XXX( WERR_RPC_S_OBJECT_NOT_FOUND                       , 1710      ) /* 0x000006ae */ \
    XXX( WERR_RPC_S_ALREADY_REGISTERED                     , 1711      ) /* 0x000006af */ \
    XXX( WERR_RPC_S_TYPE_ALREADY_REGISTERED                , 1712      ) /* 0x000006b0 */ \
    XXX( WERR_RPC_S_ALREADY_LISTENING                      , 1713      ) /* 0x000006b1 */ \
    XXX( WERR_RPC_S_NO_PROTSEQS_REGISTERED                 , 1714      ) /* 0x000006b2 */ \
    XXX( WERR_RPC_S_NOT_LISTENING                          , 1715      ) /* 0x000006b3 */ \
    XXX( WERR_RPC_S_UNKNOWN_MGR_TYPE                       , 1716      ) /* 0x000006b4 */ \
    XXX( WERR_RPC_S_UNKNOWN_IF                             , 1717      ) /* 0x000006b5 */ \
    XXX( WERR_RPC_S_NO_BINDINGS                            , 1718      ) /* 0x000006b6 */ \
    XXX( WERR_RPC_S_NO_PROTSEQS                            , 1719      ) /* 0x000006b7 */ \
    XXX( WERR_RPC_S_CANT_CREATE_ENDPOINT                   , 1720      ) /* 0x000006b8 */ \
    XXX( WERR_RPC_S_OUT_OF_RESOURCES                       , 1721      ) /* 0x000006b9 */ \
    XXX( WERR_RPC_S_SERVER_UNAVAILABLE                     , 1722      ) /* 0x000006ba */ \
    XXX( WERR_RPC_S_SERVER_TOO_BUSY                        , 1723      ) /* 0x000006bb */ \
    XXX( WERR_RPC_S_INVALID_NETWORK_OPTIONS                , 1724      ) /* 0x000006bc */ \
    XXX( WERR_RPC_S_NO_CALL_ACTIVE                         , 1725      ) /* 0x000006bd */ \
    XXX( WERR_RPC_S_CALL_FAILED                            , 1726      ) /* 0x000006be */ \
    XXX( WERR_RPC_S_CALL_FAILED_DNE                        , 1727      ) /* 0x000006bf */ \
    XXX( WERR_RPC_S_PROTOCOL_ERROR                         , 1728      ) /* 0x000006c0 */ \
    XXX( WERR_RPC_S_PROXY_ACCESS_DENIED                    , 1729      ) /* 0x000006c1 */ \
    XXX( WERR_RPC_S_UNSUPPORTED_TRANS_SYN                  , 1730      ) /* 0x000006c2 */ \
    XXX( WERR_RPC_S_UNSUPPORTED_TYPE                       , 1732      ) /* 0x000006c4 */ \
    XXX( WERR_RPC_S_INVALID_TAG                            , 1733      ) /* 0x000006c5 */ \
    XXX( WERR_RPC_S_INVALID_BOUND                          , 1734      ) /* 0x000006c6 */ \
    XXX( WERR_RPC_S_NO_ENTRY_NAME                          , 1735      ) /* 0x000006c7 */ \
    XXX( WERR_RPC_S_INVALID_NAME_SYNTAX                    , 1736      ) /* 0x000006c8 */ \
    XXX( WERR_RPC_S_UNSUPPORTED_NAME_SYNTAX                , 1737      ) /* 0x000006c9 */ \
    XXX( WERR_RPC_S_UUID_NO_ADDRESS                        , 1739      ) /* 0x000006cb */ \
    XXX( WERR_RPC_S_DUPLICATE_ENDPOINT                     , 1740      ) /* 0x000006cc */ \
    XXX( WERR_RPC_S_UNKNOWN_AUTHN_TYPE                     , 1741      ) /* 0x000006cd */ \
    XXX( WERR_RPC_S_MAX_CALLS_TOO_SMALL                    , 1742      ) /* 0x000006ce */ \
    XXX( WERR_RPC_S_STRING_TOO_LONG                        , 1743      ) /* 0x000006cf */ \
    XXX( WERR_RPC_S_PROTSEQ_NOT_FOUND                      , 1744      ) /* 0x000006d0 */ \
    XXX( WERR_RPC_S_PROCNUM_OUT_OF_RANGE                   , 1745      ) /* 0x000006d1 */ \
    XXX( WERR_RPC_S_BINDING_HAS_NO_AUTH                    , 1746      ) /* 0x000006d2 */ \
    XXX( WERR_RPC_S_UNKNOWN_AUTHN_SERVICE                  , 1747      ) /* 0x000006d3 */ \
    XXX( WERR_RPC_S_UNKNOWN_AUTHN_LEVEL                    , 1748      ) /* 0x000006d4 */ \
    XXX( WERR_RPC_S_INVALID_AUTH_IDENTITY                  , 1749      ) /* 0x000006d5 */ \
    XXX( WERR_RPC_S_UNKNOWN_AUTHZ_SERVICE                  , 1750      ) /* 0x000006d6 */ \
    XXX( WERR_EPT_S_INVALID_ENTRY                          , 1751      ) /* 0x000006d7 */ \
    XXX( WERR_EPT_S_CANT_PERFORM_OP                        , 1752      ) /* 0x000006d8 */ \
    XXX( WERR_EPT_S_NOT_REGISTERED                         , 1753      ) /* 0x000006d9 */ \
    XXX( WERR_RPC_S_NOTHING_TO_EXPORT                      , 1754      ) /* 0x000006da */ \
    XXX( WERR_RPC_S_INCOMPLETE_NAME                        , 1755      ) /* 0x000006db */ \
    XXX( WERR_RPC_S_INVALID_VERS_OPTION                    , 1756      ) /* 0x000006dc */ \
    XXX( WERR_RPC_S_NO_MORE_MEMBERS                        , 1757      ) /* 0x000006dd */ \
    XXX( WERR_RPC_S_NOT_ALL_OBJS_UNEXPORTED                , 1758      ) /* 0x000006de */ \
    XXX( WERR_RPC_S_INTERFACE_NOT_FOUND                    , 1759      ) /* 0x000006df */ \
    XXX( WERR_RPC_S_ENTRY_ALREADY_EXISTS                   , 1760      ) /* 0x000006e0 */ \
    XXX( WERR_RPC_S_ENTRY_NOT_FOUND                        , 1761      ) /* 0x000006e1 */ \
    XXX( WERR_RPC_S_NAME_SERVICE_UNAVAILABLE               , 1762      ) /* 0x000006e2 */ \
    XXX( WERR_RPC_S_INVALID_NAF_ID                         , 1763      ) /* 0x000006e3 */ \
    XXX( WERR_RPC_S_CANNOT_SUPPORT                         , 1764      ) /* 0x000006e4 */ \
    XXX( WERR_RPC_S_NO_CONTEXT_AVAILABLE                   , 1765      ) /* 0x000006e5 */ \
    XXX( WERR_RPC_S_INTERNAL_ERROR                         , 1766      ) /* 0x000006e6 */ \
    XXX( WERR_RPC_S_ZERO_DIVIDE                            , 1767      ) /* 0x000006e7 */ \
    XXX( WERR_RPC_S_ADDRESS_ERROR                          , 1768      ) /* 0x000006e8 */ \
    XXX( WERR_RPC_S_FP_DIV_ZERO                            , 1769      ) /* 0x000006e9 */ \
    XXX( WERR_RPC_S_FP_UNDERFLOW                           , 1770      ) /* 0x000006ea */ \
    XXX( WERR_RPC_S_FP_OVERFLOW                            , 1771      ) /* 0x000006eb */ \
    XXX( WERR_RPC_X_NO_MORE_ENTRIES                        , 1772      ) /* 0x000006ec */ \
    XXX( WERR_RPC_X_SS_CHAR_TRANS_OPEN_FAIL                , 1773      ) /* 0x000006ed */ \
    XXX( WERR_RPC_X_SS_CHAR_TRANS_SHORT_FILE               , 1774      ) /* 0x000006ee */ \
    XXX( WERR_RPC_X_SS_IN_NULL_CONTEXT                     , 1775      ) /* 0x000006ef */ \
    XXX( WERR_RPC_X_SS_CONTEXT_DAMAGED                     , 1777      ) /* 0x000006f1 */ \
    XXX( WERR_RPC_X_SS_HANDLES_MISMATCH                    , 1778      ) /* 0x000006f2 */ \
    XXX( WERR_RPC_X_SS_CANNOT_GET_CALL_HANDLE              , 1779      ) /* 0x000006f3 */ \
    XXX( WERR_RPC_X_NULL_REF_POINTER                       , 1780      ) /* 0x000006f4 */ \
    XXX( WERR_RPC_X_ENUM_VALUE_OUT_OF_RANGE                , 1781      ) /* 0x000006f5 */ \
    XXX( WERR_RPC_X_BYTE_COUNT_TOO_SMALL                   , 1782      ) /* 0x000006f6 */ \
    XXX( WERR_RPC_X_BAD_STUB_DATA                          , 1783      ) /* 0x000006f7 */ \
    XXX( WERR_INVALID_USER_BUFFER                          , 1784      ) /* 0x000006f8 */ \
    XXX( WERR_UNRECOGNIZED_MEDIA                           , 1785      ) /* 0x000006f9 */ \
    XXX( WERR_NO_TRUST_LSA_SECRET                          , 1786      ) /* 0x000006fa */ \
    XXX( WERR_NO_TRUST_SAM_ACCOUNT                         , 1787      ) /* 0x000006fb */ \
    XXX( WERR_TRUSTED_DOMAIN_FAILURE                       , 1788      ) /* 0x000006fc */ \
    XXX( WERR_TRUSTED_RELATIONSHIP_FAILURE                 , 1789      ) /* 0x000006fd */ \
    XXX( WERR_TRUST_FAILURE                                , 1790      ) /* 0x000006fe */ \
    XXX( WERR_RPC_S_CALL_IN_PROGRESS                       , 1791      ) /* 0x000006ff */ \
    XXX( WERR_NETLOGON_NOT_STARTED                         , 1792      ) /* 0x00000700 */ \
    XXX( WERR_ACCOUNT_EXPIRED                              , 1793      ) /* 0x00000701 */ \
    XXX( WERR_REDIRECTOR_HAS_OPEN_HANDLES                  , 1794      ) /* 0x00000702 */ \
    XXX( WERR_PRINTER_DRIVER_ALREADY_INSTALLED             , 1795      ) /* 0x00000703 */ \
    XXX( WERR_UNKNOWN_PORT                                 , 1796      ) /* 0x00000704 */ \
    XXX( WERR_UNKNOWN_PRINTER_DRIVER                       , 1797      ) /* 0x00000705 */ \
    XXX( WERR_UNKNOWN_PRINTPROCESSOR                       , 1798      ) /* 0x00000706 */ \
    XXX( WERR_INVALID_SEPARATOR_FILE                       , 1799      ) /* 0x00000707 */ \
    XXX( WERR_INVALID_PRIORITY                             , 1800      ) /* 0x00000708 */ \
    XXX( WERR_INVALID_PRINTER_NAME                         , 1801      ) /* 0x00000709 */ \
    XXX( WERR_PRINTER_ALREADY_EXISTS                       , 1802      ) /* 0x0000070a */ \
    XXX( WERR_INVALID_PRINTER_COMMAND                      , 1803      ) /* 0x0000070b */ \
    XXX( WERR_INVALID_DATATYPE                             , 1804      ) /* 0x0000070c */ \
    XXX( WERR_INVALID_ENVIRONMENT                          , 1805      ) /* 0x0000070d */ \
    XXX( WERR_RPC_S_NO_MORE_BINDINGS                       , 1806      ) /* 0x0000070e */ \
    XXX( WERR_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT            , 1807      ) /* 0x0000070f */ \
    XXX( WERR_NOLOGON_WORKSTATION_TRUST_ACCOUNT            , 1808      ) /* 0x00000710 */ \
    XXX( WERR_NOLOGON_SERVER_TRUST_ACCOUNT                 , 1809      ) /* 0x00000711 */ \
    XXX( WERR_DOMAIN_TRUST_INCONSISTENT                    , 1810      ) /* 0x00000712 */ \
    XXX( WERR_SERVER_HAS_OPEN_HANDLES                      , 1811      ) /* 0x00000713 */ \
    XXX( WERR_RESOURCE_DATA_NOT_FOUND                      , 1812      ) /* 0x00000714 */ \
    XXX( WERR_RESOURCE_TYPE_NOT_FOUND                      , 1813      ) /* 0x00000715 */ \
    XXX( WERR_RESOURCE_NAME_NOT_FOUND                      , 1814      ) /* 0x00000716 */ \
    XXX( WERR_RESOURCE_LANG_NOT_FOUND                      , 1815      ) /* 0x00000717 */ \
    XXX( WERR_NOT_ENOUGH_QUOTA                             , 1816      ) /* 0x00000718 */ \
    XXX( WERR_RPC_S_NO_INTERFACES                          , 1817      ) /* 0x00000719 */ \
    XXX( WERR_RPC_S_CALL_CANCELLED                         , 1818      ) /* 0x0000071a */ \
    XXX( WERR_RPC_S_BINDING_INCOMPLETE                     , 1819      ) /* 0x0000071b */ \
    XXX( WERR_RPC_S_COMM_FAILURE                           , 1820      ) /* 0x0000071c */ \
    XXX( WERR_RPC_S_UNSUPPORTED_AUTHN_LEVEL                , 1821      ) /* 0x0000071d */ \
    XXX( WERR_RPC_S_NO_PRINC_NAME                          , 1822      ) /* 0x0000071e */ \
    XXX( WERR_RPC_S_NOT_RPC_ERROR                          , 1823      ) /* 0x0000071f */ \
    XXX( WERR_RPC_S_UUID_LOCAL_ONLY                        , 1824      ) /* 0x00000720 */ \
    XXX( WERR_RPC_S_SEC_PKG_ERROR                          , 1825      ) /* 0x00000721 */ \
    XXX( WERR_RPC_S_NOT_CANCELLED                          , 1826      ) /* 0x00000722 */ \
    XXX( WERR_RPC_X_INVALID_ES_ACTION                      , 1827      ) /* 0x00000723 */ \
    XXX( WERR_RPC_X_WRONG_ES_VERSION                       , 1828      ) /* 0x00000724 */ \
    XXX( WERR_RPC_X_WRONG_STUB_VERSION                     , 1829      ) /* 0x00000725 */ \
    XXX( WERR_RPC_X_INVALID_PIPE_OBJECT                    , 1830      ) /* 0x00000726 */ \
    XXX( WERR_RPC_X_WRONG_PIPE_ORDER                       , 1831      ) /* 0x00000727 */ \
    XXX( WERR_RPC_X_WRONG_PIPE_VERSION                     , 1832      ) /* 0x00000728 */ \
    XXX( WERR_RPC_S_GROUP_MEMBER_NOT_FOUND                 , 1898      ) /* 0x0000076a */ \
    XXX( WERR_EPT_S_CANT_CREATE                            , 1899      ) /* 0x0000076b */ \
    XXX( WERR_RPC_S_INVALID_OBJECT                         , 1900      ) /* 0x0000076c */ \
    XXX( WERR_INVALID_TIME                                 , 1901      ) /* 0x0000076d */ \
    XXX( WERR_INVALID_FORM_NAME                            , 1902      ) /* 0x0000076e */ \
    XXX( WERR_INVALID_FORM_SIZE                            , 1903      ) /* 0x0000076f */ \
    XXX( WERR_ALREADY_WAITING                              , 1904      ) /* 0x00000770 */ \
    XXX( WERR_PRINTER_DELETED                              , 1905      ) /* 0x00000771 */ \
    XXX( WERR_INVALID_PRINTER_STATE                        , 1906      ) /* 0x00000772 */ \
    XXX( WERR_PASSWORD_MUST_CHANGE                         , 1907      ) /* 0x00000773 */ \
    XXX( WERR_DOMAIN_CONTROLLER_NOT_FOUND                  , 1908      ) /* 0x00000774 */ \
    XXX( WERR_ACCOUNT_LOCKED_OUT                           , 1909      ) /* 0x00000775 */ \
    XXX( WERR_OR_INVALID_OXID                              , 1910      ) /* 0x00000776 */ \
    XXX( WERR_OR_INVALID_OID                               , 1911      ) /* 0x00000777 */ \
    XXX( WERR_OR_INVALID_SET                               , 1912      ) /* 0x00000778 */ \
    XXX( WERR_RPC_S_SEND_INCOMPLETE                        , 1913      ) /* 0x00000779 */ \
    XXX( WERR_RPC_S_INVALID_ASYNC_HANDLE                   , 1914      ) /* 0x0000077a */ \
    XXX( WERR_RPC_S_INVALID_ASYNC_CALL                     , 1915      ) /* 0x0000077b */ \
    XXX( WERR_RPC_X_PIPE_CLOSED                            , 1916      ) /* 0x0000077c */ \
    XXX( WERR_RPC_X_PIPE_DISCIPLINE_ERROR                  , 1917      ) /* 0x0000077d */ \
    XXX( WERR_RPC_X_PIPE_EMPTY                             , 1918      ) /* 0x0000077e */ \
    XXX( WERR_NO_SITENAME                                  , 1919      ) /* 0x0000077f */ \
    XXX( WERR_CANT_ACCESS_FILE                             , 1920      ) /* 0x00000780 */ \
    XXX( WERR_CANT_RESOLVE_FILENAME                        , 1921      ) /* 0x00000781 */ \
    XXX( WERR_RPC_S_ENTRY_TYPE_MISMATCH                    , 1922      ) /* 0x00000782 */ \
    XXX( WERR_RPC_S_NOT_ALL_OBJS_EXPORTED                  , 1923      ) /* 0x00000783 */ \
    XXX( WERR_RPC_S_INTERFACE_NOT_EXPORTED                 , 1924      ) /* 0x00000784 */ \
    XXX( WERR_RPC_S_PROFILE_NOT_ADDED                      , 1925      ) /* 0x00000785 */ \
    XXX( WERR_RPC_S_PRF_ELT_NOT_ADDED                      , 1926      ) /* 0x00000786 */ \
    XXX( WERR_RPC_S_PRF_ELT_NOT_REMOVED                    , 1927      ) /* 0x00000787 */ \
    XXX( WERR_RPC_S_GRP_ELT_NOT_ADDED                      , 1928      ) /* 0x00000788 */ \
    XXX( WERR_RPC_S_GRP_ELT_NOT_REMOVED                    , 1929      ) /* 0x00000789 */ \
    XXX( WERR_KM_DRIVER_BLOCKED                            , 1930      ) /* 0x0000078a */ \
    XXX( WERR_CONTEXT_EXPIRED                              , 1931      ) /* 0x0000078b */ \
    XXX( WERR_PER_USER_TRUST_QUOTA_EXCEEDED                , 1932      ) /* 0x0000078c */ \
    XXX( WERR_ALL_USER_TRUST_QUOTA_EXCEEDED                , 1933      ) /* 0x0000078d */ \
    XXX( WERR_USER_DELETE_TRUST_QUOTA_EXCEEDED             , 1934      ) /* 0x0000078e */ \
    XXX( WERR_AUTHENTICATION_FIREWALL_FAILED               , 1935      ) /* 0x0000078f */ \
    XXX( WERR_REMOTE_PRINT_CONNECTIONS_BLOCKED             , 1936      ) /* 0x00000790 */ \
    XXX( WERR_INVALID_PIXEL_FORMAT                         , 2000      ) /* 0x000007d0 */ \
    XXX( WERR_BAD_DRIVER                                   , 2001      ) /* 0x000007d1 */ \
    XXX( WERR_INVALID_WINDOW_STYLE                         , 2002      ) /* 0x000007d2 */ \
    XXX( WERR_METAFILE_NOT_SUPPORTED                       , 2003      ) /* 0x000007d3 */ \
    XXX( WERR_TRANSFORM_NOT_SUPPORTED                      , 2004      ) /* 0x000007d4 */ \
    XXX( WERR_CLIPPING_NOT_SUPPORTED                       , 2005      ) /* 0x000007d5 */ \
    XXX( WERR_INVALID_CMM                                  , 2010      ) /* 0x000007da */ \
    XXX( WERR_INVALID_PROFILE                              , 2011      ) /* 0x000007db */ \
    XXX( WERR_TAG_NOT_FOUND                                , 2012      ) /* 0x000007dc */ \
    XXX( WERR_TAG_NOT_PRESENT                              , 2013      ) /* 0x000007dd */ \
    XXX( WERR_DUPLICATE_TAG                                , 2014      ) /* 0x000007de */ \
    XXX( WERR_PROFILE_NOT_ASSOCIATED_WITH_DEVICE           , 2015      ) /* 0x000007df */ \
    XXX( WERR_PROFILE_NOT_FOUND                            , 2016      ) /* 0x000007e0 */ \
    XXX( WERR_INVALID_COLORSPACE                           , 2017      ) /* 0x000007e1 */ \
    XXX( WERR_ICM_NOT_ENABLED                              , 2018      ) /* 0x000007e2 */ \
    XXX( WERR_DELETING_ICM_XFORM                           , 2019      ) /* 0x000007e3 */ \
    XXX( WERR_INVALID_TRANSFORM                            , 2020      ) /* 0x000007e4 */ \
    XXX( WERR_COLORSPACE_MISMATCH                          , 2021      ) /* 0x000007e5 */ \
    XXX( WERR_INVALID_COLORINDEX                           , 2022      ) /* 0x000007e6 */ \
    XXX( WERR_PROFILE_DOES_NOT_MATCH_DEVICE                , 2023      ) /* 0x000007e7 */ \
    XXX( WERR_NERR_NETNOTSTARTED                           , 2102      ) /* 0x00000836 */ \
    XXX( WERR_NERR_UNKNOWNSERVER                           , 2103      ) /* 0x00000837 */ \
    XXX( WERR_NERR_SHAREMEM                                , 2104      ) /* 0x00000838 */ \
    XXX( WERR_NERR_NONETWORKRESOURCE                       , 2105      ) /* 0x00000839 */ \
    XXX( WERR_NERR_REMOTEONLY                              , 2106      ) /* 0x0000083a */ \
    XXX( WERR_NERR_DEVNOTREDIRECTED                        , 2107      ) /* 0x0000083b */ \
    XXX( WERR_CONNECTED_OTHER_PASSWORD                     , 2108      ) /* 0x0000083c */ \
    XXX( WERR_CONNECTED_OTHER_PASSWORD_DEFAULT             , 2109      ) /* 0x0000083d */ \
    XXX( WERR_NERR_SERVERNOTSTARTED                        , 2114      ) /* 0x00000842 */ \
    XXX( WERR_NERR_ITEMNOTFOUND                            , 2115      ) /* 0x00000843 */ \
    XXX( WERR_NERR_UNKNOWNDEVDIR                           , 2116      ) /* 0x00000844 */ \
    XXX( WERR_NERR_REDIRECTEDPATH                          , 2117      ) /* 0x00000845 */ \
    XXX( WERR_NERR_DUPLICATESHARE                          , 2118      ) /* 0x00000846 */ \
    XXX( WERR_NERR_NOROOM                                  , 2119      ) /* 0x00000847 */ \
    XXX( WERR_NERR_TOOMANYITEMS                            , 2121      ) /* 0x00000849 */ \
    XXX( WERR_NERR_INVALIDMAXUSERS                         , 2122      ) /* 0x0000084a */ \
    XXX( WERR_NERR_BUFTOOSMALL                             , 2123      ) /* 0x0000084b */ \
    XXX( WERR_NERR_REMOTEERR                               , 2127      ) /* 0x0000084f */ \
    XXX( WERR_NERR_LANMANINIERROR                          , 2131      ) /* 0x00000853 */ \
    XXX( WERR_NERR_NETWORKERROR                            , 2136      ) /* 0x00000858 */ \
    XXX( WERR_NERR_WKSTAINCONSISTENTSTATE                  , 2137      ) /* 0x00000859 */ \
    XXX( WERR_NERR_WKSTANOTSTARTED                         , 2138      ) /* 0x0000085a */ \
    XXX( WERR_NERR_BROWSERNOTSTARTED                       , 2139      ) /* 0x0000085b */ \
    XXX( WERR_NERR_INTERNALERROR                           , 2140      ) /* 0x0000085c */ \
    XXX( WERR_NERR_BADTRANSACTCONFIG                       , 2141      ) /* 0x0000085d */ \
    XXX( WERR_NERR_INVALIDAPI                              , 2142      ) /* 0x0000085e */ \
    XXX( WERR_NERR_BADEVENTNAME                            , 2143      ) /* 0x0000085f */ \
    XXX( WERR_NERR_DUPNAMEREBOOT                           , 2144      ) /* 0x00000860 */ \
    XXX( WERR_NERR_CFGCOMPNOTFOUND                         , 2146      ) /* 0x00000862 */ \
    XXX( WERR_NERR_CFGPARAMNOTFOUND                        , 2147      ) /* 0x00000863 */ \
    XXX( WERR_NERR_LINETOOLONG                             , 2149      ) /* 0x00000865 */ \
    XXX( WERR_NERR_QNOTFOUND                               , 2150      ) /* 0x00000866 */ \
    XXX( WERR_NERR_JOBNOTFOUND                             , 2151      ) /* 0x00000867 */ \
    XXX( WERR_NERR_DESTNOTFOUND                            , 2152      ) /* 0x00000868 */ \
    XXX( WERR_NERR_DESTEXISTS                              , 2153      ) /* 0x00000869 */ \
    XXX( WERR_NERR_QEXISTS                                 , 2154      ) /* 0x0000086a */ \
    XXX( WERR_NERR_QNOROOM                                 , 2155      ) /* 0x0000086b */ \
    XXX( WERR_NERR_JOBNOROOM                               , 2156      ) /* 0x0000086c */ \
    XXX( WERR_NERR_DESTNOROOM                              , 2157      ) /* 0x0000086d */ \
    XXX( WERR_NERR_DESTIDLE                                , 2158      ) /* 0x0000086e */ \
    XXX( WERR_NERR_DESTINVALIDOP                           , 2159      ) /* 0x0000086f */ \
    XXX( WERR_NERR_PROCNORESPOND                           , 2160      ) /* 0x00000870 */ \
    XXX( WERR_NERR_SPOOLERNOTLOADED                        , 2161      ) /* 0x00000871 */ \
    XXX( WERR_NERR_DESTINVALIDSTATE                        , 2162      ) /* 0x00000872 */ \
    XXX( WERR_NERR_QINVALIDSTATE                           , 2163      ) /* 0x00000873 */ \
    XXX( WERR_NERR_JOBINVALIDSTATE                         , 2164      ) /* 0x00000874 */ \
    XXX( WERR_NERR_SPOOLNOMEMORY                           , 2165      ) /* 0x00000875 */ \
    XXX( WERR_NERR_DRIVERNOTFOUND                          , 2166      ) /* 0x00000876 */ \
    XXX( WERR_NERR_DATATYPEINVALID                         , 2167      ) /* 0x00000877 */ \
    XXX( WERR_NERR_PROCNOTFOUND                            , 2168      ) /* 0x00000878 */ \
    XXX( WERR_NERR_SERVICETABLELOCKED                      , 2180      ) /* 0x00000884 */ \
    XXX( WERR_NERR_SERVICETABLEFULL                        , 2181      ) /* 0x00000885 */ \
    XXX( WERR_NERR_SERVICEINSTALLED                        , 2182      ) /* 0x00000886 */ \
    XXX( WERR_NERR_SERVICEENTRYLOCKED                      , 2183      ) /* 0x00000887 */ \
    XXX( WERR_NERR_SERVICENOTINSTALLED                     , 2184      ) /* 0x00000888 */ \
    XXX( WERR_NERR_BADSERVICENAME                          , 2185      ) /* 0x00000889 */ \
    XXX( WERR_NERR_SERVICECTLTIMEOUT                       , 2186      ) /* 0x0000088a */ \
    XXX( WERR_NERR_SERVICECTLBUSY                          , 2187      ) /* 0x0000088b */ \
    XXX( WERR_NERR_BADSERVICEPROGNAME                      , 2188      ) /* 0x0000088c */ \
    XXX( WERR_NERR_SERVICENOTCTRL                          , 2189      ) /* 0x0000088d */ \
    XXX( WERR_NERR_SERVICEKILLPROC                         , 2190      ) /* 0x0000088e */ \
    XXX( WERR_NERR_SERVICECTLNOTVALID                      , 2191      ) /* 0x0000088f */ \
    XXX( WERR_NERR_NOTINDISPATCHTBL                        , 2192      ) /* 0x00000890 */ \
    XXX( WERR_NERR_BADCONTROLRECV                          , 2193      ) /* 0x00000891 */ \
    XXX( WERR_NERR_SERVICENOTSTARTING                      , 2194      ) /* 0x00000892 */ \
    XXX( WERR_NERR_ALREADYLOGGEDON                         , 2200      ) /* 0x00000898 */ \
    XXX( WERR_NERR_NOTLOGGEDON                             , 2201      ) /* 0x00000899 */ \
    XXX( WERR_NERR_BADUSERNAME                             , 2202      ) /* 0x0000089a */ \
    XXX( WERR_NERR_BADPASSWORD                             , 2203      ) /* 0x0000089b */ \
    XXX( WERR_NERR_UNABLETOADDNAME_W                       , 2204      ) /* 0x0000089c */ \
    XXX( WERR_NERR_UNABLETOADDNAME_F                       , 2205      ) /* 0x0000089d */ \
    XXX( WERR_NERR_UNABLETODELNAME_W                       , 2206      ) /* 0x0000089e */ \
    XXX( WERR_NERR_UNABLETODELNAME_F                       , 2207      ) /* 0x0000089f */ \
    XXX( WERR_NERR_LOGONSPAUSED                            , 2209      ) /* 0x000008a1 */ \
    XXX( WERR_NERR_LOGONSERVERCONFLICT                     , 2210      ) /* 0x000008a2 */ \
    XXX( WERR_NERR_LOGONNOUSERPATH                         , 2211      ) /* 0x000008a3 */ \
    XXX( WERR_NERR_LOGONSCRIPTERROR                        , 2212      ) /* 0x000008a4 */ \
    XXX( WERR_NERR_STANDALONELOGON                         , 2214      ) /* 0x000008a6 */ \
    XXX( WERR_NERR_LOGONSERVERNOTFOUND                     , 2215      ) /* 0x000008a7 */ \
    XXX( WERR_NERR_LOGONDOMAINEXISTS                       , 2216      ) /* 0x000008a8 */ \
    XXX( WERR_NERR_NONVALIDATEDLOGON                       , 2217      ) /* 0x000008a9 */ \
    XXX( WERR_NERR_ACFNOTFOUND                             , 2219      ) /* 0x000008ab */ \
    XXX( WERR_NERR_GROUPNOTFOUND                           , 2220      ) /* 0x000008ac */ \
    XXX( WERR_NERR_USERNOTFOUND                            , 2221      ) /* 0x000008ad */ \
    XXX( WERR_NERR_RESOURCENOTFOUND                        , 2222      ) /* 0x000008ae */ \
    XXX( WERR_NERR_GROUPEXISTS                             , 2223      ) /* 0x000008af */ \
    XXX( WERR_NERR_USEREXISTS                              , 2224      ) /* 0x000008b0 */ \
    XXX( WERR_NERR_RESOURCEEXISTS                          , 2225      ) /* 0x000008b1 */ \
    XXX( WERR_NERR_NOTPRIMARY                              , 2226      ) /* 0x000008b2 */ \
    XXX( WERR_NERR_ACFNOTLOADED                            , 2227      ) /* 0x000008b3 */ \
    XXX( WERR_NERR_ACFNOROOM                               , 2228      ) /* 0x000008b4 */ \
    XXX( WERR_NERR_ACFFILEIOFAIL                           , 2229      ) /* 0x000008b5 */ \
    XXX( WERR_NERR_ACFTOOMANYLISTS                         , 2230      ) /* 0x000008b6 */ \
    XXX( WERR_NERR_USERLOGON                               , 2231      ) /* 0x000008b7 */ \
    XXX( WERR_NERR_ACFNOPARENT                             , 2232      ) /* 0x000008b8 */ \
    XXX( WERR_NERR_CANNOTGROWSEGMENT                       , 2233      ) /* 0x000008b9 */ \
    XXX( WERR_NERR_SPEGROUPOP                              , 2234      ) /* 0x000008ba */ \
    XXX( WERR_NERR_NOTINCACHE                              , 2235      ) /* 0x000008bb */ \
    XXX( WERR_NERR_USERINGROUP                             , 2236      ) /* 0x000008bc */ \
    XXX( WERR_NERR_USERNOTINGROUP                          , 2237      ) /* 0x000008bd */ \
    XXX( WERR_NERR_ACCOUNTUNDEFINED                        , 2238      ) /* 0x000008be */ \
    XXX( WERR_NERR_ACCOUNTEXPIRED                          , 2239      ) /* 0x000008bf */ \
    XXX( WERR_NERR_INVALIDWORKSTATION                      , 2240      ) /* 0x000008c0 */ \
    XXX( WERR_NERR_INVALIDLOGONHOURS                       , 2241      ) /* 0x000008c1 */ \
    XXX( WERR_NERR_PASSWORDEXPIRED                         , 2242      ) /* 0x000008c2 */ \
    XXX( WERR_NERR_PASSWORDCANTCHANGE                      , 2243      ) /* 0x000008c3 */ \
    XXX( WERR_NERR_PASSWORDHISTCONFLICT                    , 2244      ) /* 0x000008c4 */ \
    XXX( WERR_NERR_PASSWORDTOOSHORT                        , 2245      ) /* 0x000008c5 */ \
    XXX( WERR_NERR_PASSWORDTOORECENT                       , 2246      ) /* 0x000008c6 */ \
    XXX( WERR_NERR_INVALIDDATABASE                         , 2247      ) /* 0x000008c7 */ \
    XXX( WERR_NERR_DATABASEUPTODATE                        , 2248      ) /* 0x000008c8 */ \
    XXX( WERR_NERR_SYNCREQUIRED                            , 2249      ) /* 0x000008c9 */ \
    XXX( WERR_NERR_USENOTFOUND                             , 2250      ) /* 0x000008ca */ \
    XXX( WERR_NERR_BADASGTYPE                              , 2251      ) /* 0x000008cb */ \
    XXX( WERR_NERR_DEVICEISSHARED                          , 2252      ) /* 0x000008cc */ \
    XXX( WERR_NERR_NOCOMPUTERNAME                          , 2270      ) /* 0x000008de */ \
    XXX( WERR_NERR_MSGALREADYSTARTED                       , 2271      ) /* 0x000008df */ \
    XXX( WERR_NERR_MSGINITFAILED                           , 2272      ) /* 0x000008e0 */ \
    XXX( WERR_NERR_NAMENOTFOUND                            , 2273      ) /* 0x000008e1 */ \
    XXX( WERR_NERR_ALREADYFORWARDED                        , 2274      ) /* 0x000008e2 */ \
    XXX( WERR_NERR_ADDFORWARDED                            , 2275      ) /* 0x000008e3 */ \
    XXX( WERR_NERR_ALREADYEXISTS                           , 2276      ) /* 0x000008e4 */ \
    XXX( WERR_NERR_TOOMANYNAMES                            , 2277      ) /* 0x000008e5 */ \
    XXX( WERR_NERR_DELCOMPUTERNAME                         , 2278      ) /* 0x000008e6 */ \
    XXX( WERR_NERR_LOCALFORWARD                            , 2279      ) /* 0x000008e7 */ \
    XXX( WERR_NERR_GRPMSGPROCESSOR                         , 2280      ) /* 0x000008e8 */ \
    XXX( WERR_NERR_PAUSEDREMOTE                            , 2281      ) /* 0x000008e9 */ \
    XXX( WERR_NERR_BADRECEIVE                              , 2282      ) /* 0x000008ea */ \
    XXX( WERR_NERR_NAMEINUSE                               , 2283      ) /* 0x000008eb */ \
    XXX( WERR_NERR_MSGNOTSTARTED                           , 2284      ) /* 0x000008ec */ \
    XXX( WERR_NERR_NOTLOCALNAME                            , 2285      ) /* 0x000008ed */ \
    XXX( WERR_NERR_NOFORWARDNAME                           , 2286      ) /* 0x000008ee */ \
    XXX( WERR_NERR_REMOTEFULL                              , 2287      ) /* 0x000008ef */ \
    XXX( WERR_NERR_NAMENOTFORWARDED                        , 2288      ) /* 0x000008f0 */ \
    XXX( WERR_NERR_TRUNCATEDBROADCAST                      , 2289      ) /* 0x000008f1 */ \
    XXX( WERR_NERR_INVALIDDEVICE                           , 2294      ) /* 0x000008f6 */ \
    XXX( WERR_NERR_WRITEFAULT                              , 2295      ) /* 0x000008f7 */ \
    XXX( WERR_NERR_DUPLICATENAME                           , 2297      ) /* 0x000008f9 */ \
    XXX( WERR_NERR_DELETELATER                             , 2298      ) /* 0x000008fa */ \
    XXX( WERR_NERR_INCOMPLETEDEL                           , 2299      ) /* 0x000008fb */ \
    XXX( WERR_NERR_MULTIPLENETS                            , 2300      ) /* 0x000008fc */ \
    XXX( WERR_NERR_NETNAMENOTFOUND                         , 2310      ) /* 0x00000906 */ \
    XXX( WERR_NERR_DEVICENOTSHARED                         , 2311      ) /* 0x00000907 */ \
    XXX( WERR_NERR_CLIENTNAMENOTFOUND                      , 2312      ) /* 0x00000908 */ \
    XXX( WERR_NERR_FILEIDNOTFOUND                          , 2314      ) /* 0x0000090a */ \
    XXX( WERR_NERR_EXECFAILURE                             , 2315      ) /* 0x0000090b */ \
    XXX( WERR_NERR_TMPFILE                                 , 2316      ) /* 0x0000090c */ \
    XXX( WERR_NERR_TOOMUCHDATA                             , 2317      ) /* 0x0000090d */ \
    XXX( WERR_NERR_DEVICESHARECONFLICT                     , 2318      ) /* 0x0000090e */ \
    XXX( WERR_NERR_BROWSERTABLEINCOMPLETE                  , 2319      ) /* 0x0000090f */ \
    XXX( WERR_NERR_NOTLOCALDOMAIN                          , 2320      ) /* 0x00000910 */ \
    XXX( WERR_NERR_ISDFSSHARE                              , 2321      ) /* 0x00000911 */ \
    XXX( WERR_NERR_DEVINVALIDOPCODE                        , 2331      ) /* 0x0000091b */ \
    XXX( WERR_NERR_DEVNOTFOUND                             , 2332      ) /* 0x0000091c */ \
    XXX( WERR_NERR_DEVNOTOPEN                              , 2333      ) /* 0x0000091d */ \
    XXX( WERR_NERR_BADQUEUEDEVSTRING                       , 2334      ) /* 0x0000091e */ \
    XXX( WERR_NERR_BADQUEUEPRIORITY                        , 2335      ) /* 0x0000091f */ \
    XXX( WERR_NERR_NOCOMMDEVS                              , 2337      ) /* 0x00000921 */ \
    XXX( WERR_NERR_QUEUENOTFOUND                           , 2338      ) /* 0x00000922 */ \
    XXX( WERR_NERR_BADDEVSTRING                            , 2340      ) /* 0x00000924 */ \
    XXX( WERR_NERR_BADDEV                                  , 2341      ) /* 0x00000925 */ \
    XXX( WERR_NERR_INUSEBYSPOOLER                          , 2342      ) /* 0x00000926 */ \
    XXX( WERR_NERR_COMMDEVINUSE                            , 2343      ) /* 0x00000927 */ \
    XXX( WERR_NERR_INVALIDCOMPUTER                         , 2351      ) /* 0x0000092f */ \
    XXX( WERR_NERR_MAXLENEXCEEDED                          , 2354      ) /* 0x00000932 */ \
    XXX( WERR_NERR_BADCOMPONENT                            , 2356      ) /* 0x00000934 */ \
    XXX( WERR_NERR_CANTTYPE                                , 2357      ) /* 0x00000935 */ \
    XXX( WERR_NERR_TOOMANYENTRIES                          , 2362      ) /* 0x0000093a */ \
    XXX( WERR_NERR_PROFILEFILETOOBIG                       , 2370      ) /* 0x00000942 */ \
    XXX( WERR_NERR_PROFILEOFFSET                           , 2371      ) /* 0x00000943 */ \
    XXX( WERR_NERR_PROFILECLEANUP                          , 2372      ) /* 0x00000944 */ \
    XXX( WERR_NERR_PROFILEUNKNOWNCMD                       , 2373      ) /* 0x00000945 */ \
    XXX( WERR_NERR_PROFILELOADERR                          , 2374      ) /* 0x00000946 */ \
    XXX( WERR_NERR_PROFILESAVEERR                          , 2375      ) /* 0x00000947 */ \
    XXX( WERR_NERR_LOGOVERFLOW                             , 2377      ) /* 0x00000949 */ \
    XXX( WERR_NERR_LOGFILECHANGED                          , 2378      ) /* 0x0000094a */ \
    XXX( WERR_NERR_LOGFILECORRUPT                          , 2379      ) /* 0x0000094b */ \
    XXX( WERR_NERR_SOURCEISDIR                             , 2380      ) /* 0x0000094c */ \
    XXX( WERR_NERR_BADSOURCE                               , 2381      ) /* 0x0000094d */ \
    XXX( WERR_NERR_BADDEST                                 , 2382      ) /* 0x0000094e */ \
    XXX( WERR_NERR_DIFFERENTSERVERS                        , 2383      ) /* 0x0000094f */ \
    XXX( WERR_NERR_RUNSRVPAUSED                            , 2385      ) /* 0x00000951 */ \
    XXX( WERR_NERR_ERRCOMMRUNSRV                           , 2389      ) /* 0x00000955 */ \
    XXX( WERR_NERR_ERROREXECINGGHOST                       , 2391      ) /* 0x00000957 */ \
    XXX( WERR_NERR_SHARENOTFOUND                           , 2392      ) /* 0x00000958 */ \
    XXX( WERR_NERR_INVALIDLANA                             , 2400      ) /* 0x00000960 */ \
    XXX( WERR_NERR_OPENFILES                               , 2401      ) /* 0x00000961 */ \
    XXX( WERR_NERR_ACTIVECONNS                             , 2402      ) /* 0x00000962 */ \
    XXX( WERR_NERR_BADPASSWORDCORE                         , 2403      ) /* 0x00000963 */ \
    XXX( WERR_NERR_DEVINUSE                                , 2404      ) /* 0x00000964 */ \
    XXX( WERR_NERR_LOCALDRIVE                              , 2405      ) /* 0x00000965 */ \
    XXX( WERR_NERR_ALERTEXISTS                             , 2430      ) /* 0x0000097e */ \
    XXX( WERR_NERR_TOOMANYALERTS                           , 2431      ) /* 0x0000097f */ \
    XXX( WERR_NERR_NOSUCHALERT                             , 2432      ) /* 0x00000980 */ \
    XXX( WERR_NERR_BADRECIPIENT                            , 2433      ) /* 0x00000981 */ \
    XXX( WERR_NERR_ACCTLIMITEXCEEDED                       , 2434      ) /* 0x00000982 */ \
    XXX( WERR_NERR_INVALIDLOGSEEK                          , 2440      ) /* 0x00000988 */ \
    XXX( WERR_NERR_BADUASCONFIG                            , 2450      ) /* 0x00000992 */ \
    XXX( WERR_NERR_INVALIDUASOP                            , 2451      ) /* 0x00000993 */ \
    XXX( WERR_NERR_LASTADMIN                               , 2452      ) /* 0x00000994 */ \
    XXX( WERR_NERR_DCNOTFOUND                              , 2453      ) /* 0x00000995 */ \
    XXX( WERR_NERR_LOGONTRACKINGERROR                      , 2454      ) /* 0x00000996 */ \
    XXX( WERR_NERR_NETLOGONNOTSTARTED                      , 2455      ) /* 0x00000997 */ \
    XXX( WERR_NERR_CANNOTGROWUASFILE                       , 2456      ) /* 0x00000998 */ \
    XXX( WERR_NERR_TIMEDIFFATDC                            , 2457      ) /* 0x00000999 */ \
    XXX( WERR_NERR_PASSWORDMISMATCH                        , 2458      ) /* 0x0000099a */ \
    XXX( WERR_NERR_NOSUCHSERVER                            , 2460      ) /* 0x0000099c */ \
    XXX( WERR_NERR_NOSUCHSESSION                           , 2461      ) /* 0x0000099d */ \
    XXX( WERR_NERR_NOSUCHCONNECTION                        , 2462      ) /* 0x0000099e */ \
    XXX( WERR_NERR_TOOMANYSERVERS                          , 2463      ) /* 0x0000099f */ \
    XXX( WERR_NERR_TOOMANYSESSIONS                         , 2464      ) /* 0x000009a0 */ \
    XXX( WERR_NERR_TOOMANYCONNECTIONS                      , 2465      ) /* 0x000009a1 */ \
    XXX( WERR_NERR_TOOMANYFILES                            , 2466      ) /* 0x000009a2 */ \
    XXX( WERR_NERR_NOALTERNATESERVERS                      , 2467      ) /* 0x000009a3 */ \
    XXX( WERR_NERR_TRYDOWNLEVEL                            , 2470      ) /* 0x000009a6 */ \
    XXX( WERR_NERR_UPSDRIVERNOTSTARTED                     , 2480      ) /* 0x000009b0 */ \
    XXX( WERR_NERR_UPSINVALIDCONFIG                        , 2481      ) /* 0x000009b1 */ \
    XXX( WERR_NERR_UPSINVALIDCOMMPORT                      , 2482      ) /* 0x000009b2 */ \
    XXX( WERR_NERR_UPSSIGNALASSERTED                       , 2483      ) /* 0x000009b3 */ \
    XXX( WERR_NERR_UPSSHUTDOWNFAILED                       , 2484      ) /* 0x000009b4 */ \
    XXX( WERR_NERR_BADDOSRETCODE                           , 2500      ) /* 0x000009c4 */ \
    XXX( WERR_NERR_PROGNEEDSEXTRAMEM                       , 2501      ) /* 0x000009c5 */ \
    XXX( WERR_NERR_BADDOSFUNCTION                          , 2502      ) /* 0x000009c6 */ \
    XXX( WERR_NERR_REMOTEBOOTFAILED                        , 2503      ) /* 0x000009c7 */ \
    XXX( WERR_NERR_BADFILECHECKSUM                         , 2504      ) /* 0x000009c8 */ \
    XXX( WERR_NERR_NORPLBOOTSYSTEM                         , 2505      ) /* 0x000009c9 */ \
    XXX( WERR_NERR_RPLLOADRNETBIOSERR                      , 2506      ) /* 0x000009ca */ \
    XXX( WERR_NERR_RPLLOADRDISKERR                         , 2507      ) /* 0x000009cb */ \
    XXX( WERR_NERR_IMAGEPARAMERR                           , 2508      ) /* 0x000009cc */ \
    XXX( WERR_NERR_TOOMANYIMAGEPARAMS                      , 2509      ) /* 0x000009cd */ \
    XXX( WERR_NERR_NONDOSFLOPPYUSED                        , 2510      ) /* 0x000009ce */ \
    XXX( WERR_NERR_RPLBOOTRESTART                          , 2511      ) /* 0x000009cf */ \
    XXX( WERR_NERR_RPLSRVRCALLFAILED                       , 2512      ) /* 0x000009d0 */ \
    XXX( WERR_NERR_CANTCONNECTRPLSRVR                      , 2513      ) /* 0x000009d1 */ \
    XXX( WERR_NERR_CANTOPENIMAGEFILE                       , 2514      ) /* 0x000009d2 */ \
    XXX( WERR_NERR_CALLINGRPLSRVR                          , 2515      ) /* 0x000009d3 */ \
    XXX( WERR_NERR_STARTINGRPLBOOT                         , 2516      ) /* 0x000009d4 */ \
    XXX( WERR_NERR_RPLBOOTSERVICETERM                      , 2517      ) /* 0x000009d5 */ \
    XXX( WERR_NERR_RPLBOOTSTARTFAILED                      , 2518      ) /* 0x000009d6 */ \
    XXX( WERR_NERR_RPL_CONNECTED                           , 2519      ) /* 0x000009d7 */ \
    XXX( WERR_NERR_BROWSERCONFIGUREDTONOTRUN               , 2550      ) /* 0x000009f6 */ \
    XXX( WERR_NERR_RPLNOADAPTERSSTARTED                    , 2610      ) /* 0x00000a32 */ \
    XXX( WERR_NERR_RPLBADREGISTRY                          , 2611      ) /* 0x00000a33 */ \
    XXX( WERR_NERR_RPLBADDATABASE                          , 2612      ) /* 0x00000a34 */ \
    XXX( WERR_NERR_RPLRPLFILESSHARE                        , 2613      ) /* 0x00000a35 */ \
    XXX( WERR_NERR_RPLNOTRPLSERVER                         , 2614      ) /* 0x00000a36 */ \
    XXX( WERR_NERR_RPLCANNOTENUM                           , 2615      ) /* 0x00000a37 */ \
    XXX( WERR_NERR_RPLWKSTAINFOCORRUPTED                   , 2616      ) /* 0x00000a38 */ \
    XXX( WERR_NERR_RPLWKSTANOTFOUND                        , 2617      ) /* 0x00000a39 */ \
    XXX( WERR_NERR_RPLWKSTANAMEUNAVAILABLE                 , 2618      ) /* 0x00000a3a */ \
    XXX( WERR_NERR_RPLPROFILEINFOCORRUPTED                 , 2619      ) /* 0x00000a3b */ \
    XXX( WERR_NERR_RPLPROFILENOTFOUND                      , 2620      ) /* 0x00000a3c */ \
    XXX( WERR_NERR_RPLPROFILENAMEUNAVAILABLE               , 2621      ) /* 0x00000a3d */ \
    XXX( WERR_NERR_RPLPROFILENOTEMPTY                      , 2622      ) /* 0x00000a3e */ \
    XXX( WERR_NERR_RPLCONFIGINFOCORRUPTED                  , 2623      ) /* 0x00000a3f */ \
    XXX( WERR_NERR_RPLCONFIGNOTFOUND                       , 2624      ) /* 0x00000a40 */ \
    XXX( WERR_NERR_RPLADAPTERINFOCORRUPTED                 , 2625      ) /* 0x00000a41 */ \
    XXX( WERR_NERR_RPLINTERNAL                             , 2626      ) /* 0x00000a42 */ \
    XXX( WERR_NERR_RPLVENDORINFOCORRUPTED                  , 2627      ) /* 0x00000a43 */ \
    XXX( WERR_NERR_RPLBOOTINFOCORRUPTED                    , 2628      ) /* 0x00000a44 */ \
    XXX( WERR_NERR_RPLWKSTANEEDSUSERACCT                   , 2629      ) /* 0x00000a45 */ \
    XXX( WERR_NERR_RPLNEEDSRPLUSERACCT                     , 2630      ) /* 0x00000a46 */ \
    XXX( WERR_NERR_RPLBOOTNOTFOUND                         , 2631      ) /* 0x00000a47 */ \
    XXX( WERR_NERR_RPLINCOMPATIBLEPROFILE                  , 2632      ) /* 0x00000a48 */ \
    XXX( WERR_NERR_RPLADAPTERNAMEUNAVAILABLE               , 2633      ) /* 0x00000a49 */ \
    XXX( WERR_NERR_RPLCONFIGNOTEMPTY                       , 2634      ) /* 0x00000a4a */ \
    XXX( WERR_NERR_RPLBOOTINUSE                            , 2635      ) /* 0x00000a4b */ \
    XXX( WERR_NERR_RPLBACKUPDATABASE                       , 2636      ) /* 0x00000a4c */ \
    XXX( WERR_NERR_RPLADAPTERNOTFOUND                      , 2637      ) /* 0x00000a4d */ \
    XXX( WERR_NERR_RPLVENDORNOTFOUND                       , 2638      ) /* 0x00000a4e */ \
    XXX( WERR_NERR_RPLVENDORNAMEUNAVAILABLE                , 2639      ) /* 0x00000a4f */ \
    XXX( WERR_NERR_RPLBOOTNAMEUNAVAILABLE                  , 2640      ) /* 0x00000a50 */ \
    XXX( WERR_NERR_RPLCONFIGNAMEUNAVAILABLE                , 2641      ) /* 0x00000a51 */ \
    XXX( WERR_NERR_DFSINTERNALCORRUPTION                   , 2660      ) /* 0x00000a64 */ \
    XXX( WERR_NERR_DFSVOLUMEDATACORRUPT                    , 2661      ) /* 0x00000a65 */ \
    XXX( WERR_NERR_DFSNOSUCHVOLUME                         , 2662      ) /* 0x00000a66 */ \
    XXX( WERR_NERR_DFSVOLUMEALREADYEXISTS                  , 2663      ) /* 0x00000a67 */ \
    XXX( WERR_NERR_DFSALREADYSHARED                        , 2664      ) /* 0x00000a68 */ \
    XXX( WERR_NERR_DFSNOSUCHSHARE                          , 2665      ) /* 0x00000a69 */ \
    XXX( WERR_NERR_DFSNOTALEAFVOLUME                       , 2666      ) /* 0x00000a6a */ \
    XXX( WERR_NERR_DFSLEAFVOLUME                           , 2667      ) /* 0x00000a6b */ \
    XXX( WERR_NERR_DFSVOLUMEHASMULTIPLESERVERS             , 2668      ) /* 0x00000a6c */ \
    XXX( WERR_NERR_DFSCANTCREATEJUNCTIONPOINT              , 2669      ) /* 0x00000a6d */ \
    XXX( WERR_NERR_DFSSERVERNOTDFSAWARE                    , 2670      ) /* 0x00000a6e */ \
    XXX( WERR_NERR_DFSBADRENAMEPATH                        , 2671      ) /* 0x00000a6f */ \
    XXX( WERR_NERR_DFSVOLUMEISOFFLINE                      , 2672      ) /* 0x00000a70 */ \
    XXX( WERR_NERR_DFSNOSUCHSERVER                         , 2673      ) /* 0x00000a71 */ \
    XXX( WERR_NERR_DFSCYCLICALNAME                         , 2674      ) /* 0x00000a72 */ \
    XXX( WERR_NERR_DFSNOTSUPPORTEDINSERVERDFS              , 2675      ) /* 0x00000a73 */ \
    XXX( WERR_NERR_DFSDUPLICATESERVICE                     , 2676      ) /* 0x00000a74 */ \
    XXX( WERR_NERR_DFSCANTREMOVELASTSERVERSHARE            , 2677      ) /* 0x00000a75 */ \
    XXX( WERR_NERR_DFSVOLUMEISINTERDFS                     , 2678      ) /* 0x00000a76 */ \
    XXX( WERR_NERR_DFSINCONSISTENT                         , 2679      ) /* 0x00000a77 */ \
    XXX( WERR_NERR_DFSSERVERUPGRADED                       , 2680      ) /* 0x00000a78 */ \
    XXX( WERR_NERR_DFSDATAISIDENTICAL                      , 2681      ) /* 0x00000a79 */ \
    XXX( WERR_NERR_DFSCANTREMOVEDFSROOT                    , 2682      ) /* 0x00000a7a */ \
    XXX( WERR_NERR_DFSCHILDORPARENTINDFS                   , 2683      ) /* 0x00000a7b */ \
    XXX( WERR_NERR_DFSINTERNALERROR                        , 2690      ) /* 0x00000a82 */ \
    XXX( WERR_NERR_SETUPALREADYJOINED                      , 2691      ) /* 0x00000a83 */ \
    XXX( WERR_NERR_SETUPNOTJOINED                          , 2692      ) /* 0x00000a84 */ \
    XXX( WERR_NERR_SETUPDOMAINCONTROLLER                   , 2693      ) /* 0x00000a85 */ \
    XXX( WERR_NERR_DEFAULTJOINREQUIRED                     , 2694      ) /* 0x00000a86 */ \
    XXX( WERR_NERR_INVALIDWORKGROUPNAME                    , 2695      ) /* 0x00000a87 */ \
    XXX( WERR_NERR_NAMEUSESINCOMPATIBLECODEPAGE            , 2696      ) /* 0x00000a88 */ \
    XXX( WERR_NERR_COMPUTERACCOUNTNOTFOUND                 , 2697      ) /* 0x00000a89 */ \
    XXX( WERR_NERR_PERSONALSKU                             , 2698      ) /* 0x00000a8a */ \
    XXX( WERR_NERR_PASSWORDMUSTCHANGE                      , 2701      ) /* 0x00000a8d */ \
    XXX( WERR_NERR_ACCOUNTLOCKEDOUT                        , 2702      ) /* 0x00000a8e */ \
    XXX( WERR_NERR_PASSWORDTOOLONG                         , 2703      ) /* 0x00000a8f */ \
    XXX( WERR_NERR_PASSWORDNOTCOMPLEXENOUGH                , 2704      ) /* 0x00000a90 */ \
    XXX( WERR_NERR_PASSWORDFILTERERROR                     , 2705      ) /* 0x00000a91 */ \
    XXX( WERR_UNKNOWN_PRINT_MONITOR                        , 3000      ) /* 0x00000bb8 */ \
    XXX( WERR_PRINTER_DRIVER_IN_USE                        , 3001      ) /* 0x00000bb9 */ \
    XXX( WERR_SPOOL_FILE_NOT_FOUND                         , 3002      ) /* 0x00000bba */ \
    XXX( WERR_SPL_NO_STARTDOC                              , 3003      ) /* 0x00000bbb */ \
    XXX( WERR_SPL_NO_ADDJOB                                , 3004      ) /* 0x00000bbc */ \
    XXX( WERR_PRINT_PROCESSOR_ALREADY_INSTALLED            , 3005      ) /* 0x00000bbd */ \
    XXX( WERR_PRINT_MONITOR_ALREADY_INSTALLED              , 3006      ) /* 0x00000bbe */ \
    XXX( WERR_INVALID_PRINT_MONITOR                        , 3007      ) /* 0x00000bbf */ \
    XXX( WERR_PRINT_MONITOR_IN_USE                         , 3008      ) /* 0x00000bc0 */ \
    XXX( WERR_PRINTER_HAS_JOBS_QUEUED                      , 3009      ) /* 0x00000bc1 */ \
    XXX( WERR_SUCCESS_REBOOT_REQUIRED                      , 3010      ) /* 0x00000bc2 */ \
    XXX( WERR_SUCCESS_RESTART_REQUIRED                     , 3011      ) /* 0x00000bc3 */ \
    XXX( WERR_PRINTER_NOT_FOUND                            , 3012      ) /* 0x00000bc4 */ \
    XXX( WERR_PRINTER_DRIVER_WARNED                        , 3013      ) /* 0x00000bc5 */ \
    XXX( WERR_PRINTER_DRIVER_BLOCKED                       , 3014      ) /* 0x00000bc6 */ \
    XXX( WERR_PRINTER_DRIVER_PACKAGE_IN_USE                , 3015      ) /* 0x00000bc7 */ \
    XXX( WERR_CORE_DRIVER_PACKAGE_NOT_FOUND                , 3016      ) /* 0x00000bc8 */ \
    XXX( WERR_FAIL_REBOOT_REQUIRED                         , 3017      ) /* 0x00000bc9 */ \
    XXX( WERR_FAIL_REBOOT_INITIATED                        , 3018      ) /* 0x00000bca */ \
    XXX( WERR_IO_REISSUE_AS_CACHED                         , 3950      ) /* 0x00000f6e */ \
    XXX( WERR_WINS_INTERNAL                                , 4000      ) /* 0x00000fa0 */ \
    XXX( WERR_CAN_NOT_DEL_LOCAL_WINS                       , 4001      ) /* 0x00000fa1 */ \
    XXX( WERR_STATIC_INIT                                  , 4002      ) /* 0x00000fa2 */ \
    XXX( WERR_INC_BACKUP                                   , 4003      ) /* 0x00000fa3 */ \
    XXX( WERR_FULL_BACKUP                                  , 4004      ) /* 0x00000fa4 */ \
    XXX( WERR_REC_NON_EXISTENT                             , 4005      ) /* 0x00000fa5 */ \
    XXX( WERR_RPL_NOT_ALLOWED                              , 4006      ) /* 0x00000fa6 */ \
    XXX( WERR_DHCP_ADDRESS_CONFLICT                        , 4100      ) /* 0x00001004 */ \
    XXX( WERR_WMI_GUID_NOT_FOUND                           , 4200      ) /* 0x00001068 */ \
    XXX( WERR_WMI_INSTANCE_NOT_FOUND                       , 4201      ) /* 0x00001069 */ \
    XXX( WERR_WMI_ITEMID_NOT_FOUND                         , 4202      ) /* 0x0000106a */ \
    XXX( WERR_WMI_TRY_AGAIN                                , 4203      ) /* 0x0000106b */ \
    XXX( WERR_WMI_DP_NOT_FOUND                             , 4204      ) /* 0x0000106c */ \
    XXX( WERR_WMI_UNRESOLVED_INSTANCE_REF                  , 4205      ) /* 0x0000106d */ \
    XXX( WERR_WMI_ALREADY_ENABLED                          , 4206      ) /* 0x0000106e */ \
    XXX( WERR_WMI_GUID_DISCONNECTED                        , 4207      ) /* 0x0000106f */ \
    XXX( WERR_WMI_SERVER_UNAVAILABLE                       , 4208      ) /* 0x00001070 */ \
    XXX( WERR_WMI_DP_FAILED                                , 4209      ) /* 0x00001071 */ \
    XXX( WERR_WMI_INVALID_MOF                              , 4210      ) /* 0x00001072 */ \
    XXX( WERR_WMI_INVALID_REGINFO                          , 4211      ) /* 0x00001073 */ \
    XXX( WERR_WMI_ALREADY_DISABLED                         , 4212      ) /* 0x00001074 */ \
    XXX( WERR_WMI_READ_ONLY                                , 4213      ) /* 0x00001075 */ \
    XXX( WERR_WMI_SET_FAILURE                              , 4214      ) /* 0x00001076 */ \
    XXX( WERR_INVALID_MEDIA                                , 4300      ) /* 0x000010cc */ \
    XXX( WERR_INVALID_LIBRARY                              , 4301      ) /* 0x000010cd */ \
    XXX( WERR_INVALID_MEDIA_POOL                           , 4302      ) /* 0x000010ce */ \
    XXX( WERR_DRIVE_MEDIA_MISMATCH                         , 4303      ) /* 0x000010cf */ \
    XXX( WERR_MEDIA_OFFLINE                                , 4304      ) /* 0x000010d0 */ \
    XXX( WERR_LIBRARY_OFFLINE                              , 4305      ) /* 0x000010d1 */ \
    XXX( WERR_EMPTY                                        , 4306      ) /* 0x000010d2 */ \
    XXX( WERR_NOT_EMPTY                                    , 4307      ) /* 0x000010d3 */ \
    XXX( WERR_MEDIA_UNAVAILABLE                            , 4308      ) /* 0x000010d4 */ \
    XXX( WERR_RESOURCE_DISABLED                            , 4309      ) /* 0x000010d5 */ \
    XXX( WERR_INVALID_CLEANER                              , 4310      ) /* 0x000010d6 */ \
    XXX( WERR_UNABLE_TO_CLEAN                              , 4311      ) /* 0x000010d7 */ \
    XXX( WERR_OBJECT_NOT_FOUND                             , 4312      ) /* 0x000010d8 */ \
    XXX( WERR_DATABASE_FAILURE                             , 4313      ) /* 0x000010d9 */ \
    XXX( WERR_DATABASE_FULL                                , 4314      ) /* 0x000010da */ \
    XXX( WERR_MEDIA_INCOMPATIBLE                           , 4315      ) /* 0x000010db */ \
    XXX( WERR_RESOURCE_NOT_PRESENT                         , 4316      ) /* 0x000010dc */ \
    XXX( WERR_INVALID_OPERATION                            , 4317      ) /* 0x000010dd */ \
    XXX( WERR_MEDIA_NOT_AVAILABLE                          , 4318      ) /* 0x000010de */ \
    XXX( WERR_DEVICE_NOT_AVAILABLE                         , 4319      ) /* 0x000010df */ \
    XXX( WERR_REQUEST_REFUSED                              , 4320      ) /* 0x000010e0 */ \
    XXX( WERR_INVALID_DRIVE_OBJECT                         , 4321      ) /* 0x000010e1 */ \
    XXX( WERR_LIBRARY_FULL                                 , 4322      ) /* 0x000010e2 */ \
    XXX( WERR_MEDIUM_NOT_ACCESSIBLE                        , 4323      ) /* 0x000010e3 */ \
    XXX( WERR_UNABLE_TO_LOAD_MEDIUM                        , 4324      ) /* 0x000010e4 */ \
    XXX( WERR_UNABLE_TO_INVENTORY_DRIVE                    , 4325      ) /* 0x000010e5 */ \
    XXX( WERR_UNABLE_TO_INVENTORY_SLOT                     , 4326      ) /* 0x000010e6 */ \
    XXX( WERR_UNABLE_TO_INVENTORY_TRANSPORT                , 4327      ) /* 0x000010e7 */ \
    XXX( WERR_TRANSPORT_FULL                               , 4328      ) /* 0x000010e8 */ \
    XXX( WERR_CONTROLLING_IEPORT                           , 4329      ) /* 0x000010e9 */ \
    XXX( WERR_UNABLE_TO_EJECT_MOUNTED_MEDIA                , 4330      ) /* 0x000010ea */ \
    XXX( WERR_CLEANER_SLOT_SET                             , 4331      ) /* 0x000010eb */ \
    XXX( WERR_CLEANER_SLOT_NOT_SET                         , 4332      ) /* 0x000010ec */ \
    XXX( WERR_CLEANER_CARTRIDGE_SPENT                      , 4333      ) /* 0x000010ed */ \
    XXX( WERR_UNEXPECTED_OMID                              , 4334      ) /* 0x000010ee */ \
    XXX( WERR_CANT_DELETE_LAST_ITEM                        , 4335      ) /* 0x000010ef */ \
    XXX( WERR_MESSAGE_EXCEEDS_MAX_SIZE                     , 4336      ) /* 0x000010f0 */ \
    XXX( WERR_VOLUME_CONTAINS_SYS_FILES                    , 4337      ) /* 0x000010f1 */ \
    XXX( WERR_INDIGENOUS_TYPE                              , 4338      ) /* 0x000010f2 */ \
    XXX( WERR_NO_SUPPORTING_DRIVES                         , 4339      ) /* 0x000010f3 */ \
    XXX( WERR_CLEANER_CARTRIDGE_INSTALLED                  , 4340      ) /* 0x000010f4 */ \
    XXX( WERR_IEPORT_FULL                                  , 4341      ) /* 0x000010f5 */ \
    XXX( WERR_FILE_OFFLINE                                 , 4350      ) /* 0x000010fe */ \
    XXX( WERR_REMOTE_STORAGE_NOT_ACTIVE                    , 4351      ) /* 0x000010ff */ \
    XXX( WERR_REMOTE_STORAGE_MEDIA_ERROR                   , 4352      ) /* 0x00001100 */ \
    XXX( WERR_NOT_A_REPARSE_POINT                          , 4390      ) /* 0x00001126 */ \
    XXX( WERR_REPARSE_ATTRIBUTE_CONFLICT                   , 4391      ) /* 0x00001127 */ \
    XXX( WERR_INVALID_REPARSE_DATA                         , 4392      ) /* 0x00001128 */ \
    XXX( WERR_REPARSE_TAG_INVALID                          , 4393      ) /* 0x00001129 */ \
    XXX( WERR_REPARSE_TAG_MISMATCH                         , 4394      ) /* 0x0000112a */ \
    XXX( WERR_VOLUME_NOT_SIS_ENABLED                       , 4500      ) /* 0x00001194 */ \
    XXX( WERR_DEPENDENT_RESOURCE_EXISTS                    , 5001      ) /* 0x00001389 */ \
    XXX( WERR_DEPENDENCY_NOT_FOUND                         , 5002      ) /* 0x0000138a */ \
    XXX( WERR_DEPENDENCY_ALREADY_EXISTS                    , 5003      ) /* 0x0000138b */ \
    XXX( WERR_RESOURCE_NOT_ONLINE                          , 5004      ) /* 0x0000138c */ \
    XXX( WERR_HOST_NODE_NOT_AVAILABLE                      , 5005      ) /* 0x0000138d */ \
    XXX( WERR_RESOURCE_NOT_AVAILABLE                       , 5006      ) /* 0x0000138e */ \
    XXX( WERR_RESOURCE_NOT_FOUND                           , 5007      ) /* 0x0000138f */ \
    XXX( WERR_SHUTDOWN_CLUSTER                             , 5008      ) /* 0x00001390 */ \
    XXX( WERR_CANT_EVICT_ACTIVE_NODE                       , 5009      ) /* 0x00001391 */ \
    XXX( WERR_OBJECT_ALREADY_EXISTS                        , 5010      ) /* 0x00001392 */ \
    XXX( WERR_OBJECT_IN_LIST                               , 5011      ) /* 0x00001393 */ \
    XXX( WERR_GROUP_NOT_AVAILABLE                          , 5012      ) /* 0x00001394 */ \
    XXX( WERR_GROUP_NOT_FOUND                              , 5013      ) /* 0x00001395 */ \
    XXX( WERR_GROUP_NOT_ONLINE                             , 5014      ) /* 0x00001396 */ \
    XXX( WERR_HOST_NODE_NOT_RESOURCE_OWNER                 , 5015      ) /* 0x00001397 */ \
    XXX( WERR_HOST_NODE_NOT_GROUP_OWNER                    , 5016      ) /* 0x00001398 */ \
    XXX( WERR_RESMON_CREATE_FAILED                         , 5017      ) /* 0x00001399 */ \
    XXX( WERR_RESMON_ONLINE_FAILED                         , 5018      ) /* 0x0000139a */ \
    XXX( WERR_RESOURCE_ONLINE                              , 5019      ) /* 0x0000139b */ \
    XXX( WERR_QUORUM_RESOURCE                              , 5020      ) /* 0x0000139c */ \
    XXX( WERR_NOT_QUORUM_CAPABLE                           , 5021      ) /* 0x0000139d */ \
    XXX( WERR_CLUSTER_SHUTTING_DOWN                        , 5022      ) /* 0x0000139e */ \
    XXX( WERR_INVALID_STATE                                , 5023      ) /* 0x0000139f */ \
    XXX( WERR_RESOURCE_PROPERTIES_STORED                   , 5024      ) /* 0x000013a0 */ \
    XXX( WERR_NOT_QUORUM_CLASS                             , 5025      ) /* 0x000013a1 */ \
    XXX( WERR_CORE_RESOURCE                                , 5026      ) /* 0x000013a2 */ \
    XXX( WERR_QUORUM_RESOURCE_ONLINE_FAILED                , 5027      ) /* 0x000013a3 */ \
    XXX( WERR_QUORUMLOG_OPEN_FAILED                        , 5028      ) /* 0x000013a4 */ \
    XXX( WERR_CLUSTERLOG_CORRUPT                           , 5029      ) /* 0x000013a5 */ \
    XXX( WERR_CLUSTERLOG_RECORD_EXCEEDS_MAXSIZE            , 5030      ) /* 0x000013a6 */ \
    XXX( WERR_CLUSTERLOG_EXCEEDS_MAXSIZE                   , 5031      ) /* 0x000013a7 */ \
    XXX( WERR_CLUSTERLOG_CHKPOINT_NOT_FOUND                , 5032      ) /* 0x000013a8 */ \
    XXX( WERR_CLUSTERLOG_NOT_ENOUGH_SPACE                  , 5033      ) /* 0x000013a9 */ \
    XXX( WERR_QUORUM_OWNER_ALIVE                           , 5034      ) /* 0x000013aa */ \
    XXX( WERR_NETWORK_NOT_AVAILABLE                        , 5035      ) /* 0x000013ab */ \
    XXX( WERR_NODE_NOT_AVAILABLE                           , 5036      ) /* 0x000013ac */ \
    XXX( WERR_ALL_NODES_NOT_AVAILABLE                      , 5037      ) /* 0x000013ad */ \
    XXX( WERR_RESOURCE_FAILED                              , 5038      ) /* 0x000013ae */ \
    XXX( WERR_CLUSTER_INVALID_NODE                         , 5039      ) /* 0x000013af */ \
    XXX( WERR_CLUSTER_NODE_EXISTS                          , 5040      ) /* 0x000013b0 */ \
    XXX( WERR_CLUSTER_JOIN_IN_PROGRESS                     , 5041      ) /* 0x000013b1 */ \
    XXX( WERR_CLUSTER_NODE_NOT_FOUND                       , 5042      ) /* 0x000013b2 */ \
    XXX( WERR_CLUSTER_LOCAL_NODE_NOT_FOUND                 , 5043      ) /* 0x000013b3 */ \
    XXX( WERR_CLUSTER_NETWORK_EXISTS                       , 5044      ) /* 0x000013b4 */ \
    XXX( WERR_CLUSTER_NETWORK_NOT_FOUND                    , 5045      ) /* 0x000013b5 */ \
    XXX( WERR_CLUSTER_NETINTERFACE_EXISTS                  , 5046      ) /* 0x000013b6 */ \
    XXX( WERR_CLUSTER_NETINTERFACE_NOT_FOUND               , 5047      ) /* 0x000013b7 */ \
    XXX( WERR_CLUSTER_INVALID_REQUEST                      , 5048      ) /* 0x000013b8 */ \
    XXX( WERR_CLUSTER_INVALID_NETWORK_PROVIDER             , 5049      ) /* 0x000013b9 */ \
    XXX( WERR_CLUSTER_NODE_DOWN                            , 5050      ) /* 0x000013ba */ \
    XXX( WERR_CLUSTER_NODE_UNREACHABLE                     , 5051      ) /* 0x000013bb */ \
    XXX( WERR_CLUSTER_NODE_NOT_MEMBER                      , 5052      ) /* 0x000013bc */ \
    XXX( WERR_CLUSTER_JOIN_NOT_IN_PROGRESS                 , 5053      ) /* 0x000013bd */ \
    XXX( WERR_CLUSTER_INVALID_NETWORK                      , 5054      ) /* 0x000013be */ \
    XXX( WERR_CLUSTER_NODE_UP                              , 5056      ) /* 0x000013c0 */ \
    XXX( WERR_CLUSTER_IPADDR_IN_USE                        , 5057      ) /* 0x000013c1 */ \
    XXX( WERR_CLUSTER_NODE_NOT_PAUSED                      , 5058      ) /* 0x000013c2 */ \
    XXX( WERR_CLUSTER_NO_SECURITY_CONTEXT                  , 5059      ) /* 0x000013c3 */ \
    XXX( WERR_CLUSTER_NETWORK_NOT_INTERNAL                 , 5060      ) /* 0x000013c4 */ \
    XXX( WERR_CLUSTER_NODE_ALREADY_UP                      , 5061      ) /* 0x000013c5 */ \
    XXX( WERR_CLUSTER_NODE_ALREADY_DOWN                    , 5062      ) /* 0x000013c6 */ \
    XXX( WERR_CLUSTER_NETWORK_ALREADY_ONLINE               , 5063      ) /* 0x000013c7 */ \
    XXX( WERR_CLUSTER_NETWORK_ALREADY_OFFLINE              , 5064      ) /* 0x000013c8 */ \
    XXX( WERR_CLUSTER_NODE_ALREADY_MEMBER                  , 5065      ) /* 0x000013c9 */ \
    XXX( WERR_CLUSTER_LAST_INTERNAL_NETWORK                , 5066      ) /* 0x000013ca */ \
    XXX( WERR_CLUSTER_NETWORK_HAS_DEPENDENTS               , 5067      ) /* 0x000013cb */ \
    XXX( WERR_INVALID_OPERATION_ON_QUORUM                  , 5068      ) /* 0x000013cc */ \
    XXX( WERR_DEPENDENCY_NOT_ALLOWED                       , 5069      ) /* 0x000013cd */ \
    XXX( WERR_CLUSTER_NODE_PAUSED                          , 5070      ) /* 0x000013ce */ \
    XXX( WERR_NODE_CANT_HOST_RESOURCE                      , 5071      ) /* 0x000013cf */ \
    XXX( WERR_CLUSTER_NODE_NOT_READY                       , 5072      ) /* 0x000013d0 */ \
    XXX( WERR_CLUSTER_NODE_SHUTTING_DOWN                   , 5073      ) /* 0x000013d1 */ \
    XXX( WERR_CLUSTER_JOIN_ABORTED                         , 5074      ) /* 0x000013d2 */ \
    XXX( WERR_CLUSTER_INCOMPATIBLE_VERSIONS                , 5075      ) /* 0x000013d3 */ \
    XXX( WERR_CLUSTER_MAXNUM_OF_RESOURCES_EXCEEDED         , 5076      ) /* 0x000013d4 */ \
    XXX( WERR_CLUSTER_SYSTEM_CONFIG_CHANGED                , 5077      ) /* 0x000013d5 */ \
    XXX( WERR_CLUSTER_RESOURCE_TYPE_NOT_FOUND              , 5078      ) /* 0x000013d6 */ \
    XXX( WERR_CLUSTER_RESTYPE_NOT_SUPPORTED                , 5079      ) /* 0x000013d7 */ \
    XXX( WERR_CLUSTER_RESNAME_NOT_FOUND                    , 5080      ) /* 0x000013d8 */ \
    XXX( WERR_CLUSTER_NO_RPC_PACKAGES_REGISTERED           , 5081      ) /* 0x000013d9 */ \
    XXX( WERR_CLUSTER_OWNER_NOT_IN_PREFLIST                , 5082      ) /* 0x000013da */ \
    XXX( WERR_CLUSTER_DATABASE_SEQMISMATCH                 , 5083      ) /* 0x000013db */ \
    XXX( WERR_RESMON_INVALID_STATE                         , 5084      ) /* 0x000013dc */ \
    XXX( WERR_CLUSTER_GUM_NOT_LOCKER                       , 5085      ) /* 0x000013dd */ \
    XXX( WERR_QUORUM_DISK_NOT_FOUND                        , 5086      ) /* 0x000013de */ \
    XXX( WERR_DATABASE_BACKUP_CORRUPT                      , 5087      ) /* 0x000013df */ \
    XXX( WERR_CLUSTER_NODE_ALREADY_HAS_DFS_ROOT            , 5088      ) /* 0x000013e0 */ \
    XXX( WERR_RESOURCE_PROPERTY_UNCHANGEABLE               , 5089      ) /* 0x000013e1 */ \
    XXX( WERR_CLUSTER_MEMBERSHIP_INVALID_STATE             , 5890      ) /* 0x00001702 */ \
    XXX( WERR_CLUSTER_QUORUMLOG_NOT_FOUND                  , 5891      ) /* 0x00001703 */ \
    XXX( WERR_CLUSTER_MEMBERSHIP_HALT                      , 5892      ) /* 0x00001704 */ \
    XXX( WERR_CLUSTER_INSTANCE_ID_MISMATCH                 , 5893      ) /* 0x00001705 */ \
    XXX( WERR_CLUSTER_NETWORK_NOT_FOUND_FOR_IP             , 5894      ) /* 0x00001706 */ \
    XXX( WERR_CLUSTER_PROPERTY_DATA_TYPE_MISMATCH          , 5895      ) /* 0x00001707 */ \
    XXX( WERR_CLUSTER_EVICT_WITHOUT_CLEANUP                , 5896      ) /* 0x00001708 */ \
    XXX( WERR_CLUSTER_PARAMETER_MISMATCH                   , 5897      ) /* 0x00001709 */ \
    XXX( WERR_NODE_CANNOT_BE_CLUSTERED                     , 5898      ) /* 0x0000170a */ \
    XXX( WERR_CLUSTER_WRONG_OS_VERSION                     , 5899      ) /* 0x0000170b */ \
    XXX( WERR_CLUSTER_CANT_CREATE_DUP_CLUSTER_NAME         , 5900      ) /* 0x0000170c */ \
    XXX( WERR_CLUSCFG_ALREADY_COMMITTED                    , 5901      ) /* 0x0000170d */ \
    XXX( WERR_CLUSCFG_ROLLBACK_FAILED                      , 5902      ) /* 0x0000170e */ \
    XXX( WERR_CLUSCFG_SYSTEM_DISK_DRIVE_LETTER_CONFLICT    , 5903      ) /* 0x0000170f */ \
    XXX( WERR_CLUSTER_OLD_VERSION                          , 5904      ) /* 0x00001710 */ \
    XXX( WERR_CLUSTER_MISMATCHED_COMPUTER_ACCT_NAME        , 5905      ) /* 0x00001711 */ \
    XXX( WERR_CLUSTER_NO_NET_ADAPTERS                      , 5906      ) /* 0x00001712 */ \
    XXX( WERR_CLUSTER_POISONED                             , 5907      ) /* 0x00001713 */ \
    XXX( WERR_CLUSTER_GROUP_MOVING                         , 5908      ) /* 0x00001714 */ \
    XXX( WERR_CLUSTER_RESOURCE_TYPE_BUSY                   , 5909      ) /* 0x00001715 */ \
    XXX( WERR_RESOURCE_CALL_TIMED_OUT                      , 5910      ) /* 0x00001716 */ \
    XXX( WERR_INVALID_CLUSTER_IPV6_ADDRESS                 , 5911      ) /* 0x00001717 */ \
    XXX( WERR_CLUSTER_INTERNAL_INVALID_FUNCTION            , 5912      ) /* 0x00001718 */ \
    XXX( WERR_CLUSTER_PARAMETER_OUT_OF_BOUNDS              , 5913      ) /* 0x00001719 */ \
    XXX( WERR_CLUSTER_PARTIAL_SEND                         , 5914      ) /* 0x0000171a */ \
    XXX( WERR_CLUSTER_REGISTRY_INVALID_FUNCTION            , 5915      ) /* 0x0000171b */ \
    XXX( WERR_CLUSTER_INVALID_STRING_TERMINATION           , 5916      ) /* 0x0000171c */ \
    XXX( WERR_CLUSTER_INVALID_STRING_FORMAT                , 5917      ) /* 0x0000171d */ \
    XXX( WERR_CLUSTER_DATABASE_TRANSACTION_IN_PROGRESS     , 5918      ) /* 0x0000171e */ \
    XXX( WERR_CLUSTER_DATABASE_TRANSACTION_NOT_IN_PROGRESS , 5919      ) /* 0x0000171f */ \
    XXX( WERR_CLUSTER_NULL_DATA                            , 5920      ) /* 0x00001720 */ \
    XXX( WERR_CLUSTER_PARTIAL_READ                         , 5921      ) /* 0x00001721 */ \
    XXX( WERR_CLUSTER_PARTIAL_WRITE                        , 5922      ) /* 0x00001722 */ \
    XXX( WERR_CLUSTER_CANT_DESERIALIZE_DATA                , 5923      ) /* 0x00001723 */ \
    XXX( WERR_DEPENDENT_RESOURCE_PROPERTY_CONFLICT         , 5924      ) /* 0x00001724 */ \
    XXX( WERR_CLUSTER_NO_QUORUM                            , 5925      ) /* 0x00001725 */ \
    XXX( WERR_CLUSTER_INVALID_IPV6_NETWORK                 , 5926      ) /* 0x00001726 */ \
    XXX( WERR_CLUSTER_INVALID_IPV6_TUNNEL_NETWORK          , 5927      ) /* 0x00001727 */ \
    XXX( WERR_QUORUM_NOT_ALLOWED_IN_THIS_GROUP             , 5928      ) /* 0x00001728 */ \
    XXX( WERR_ENCRYPTION_FAILED                            , 6000      ) /* 0x00001770 */ \
    XXX( WERR_DECRYPTION_FAILED                            , 6001      ) /* 0x00001771 */ \
    XXX( WERR_FILE_ENCRYPTED                               , 6002      ) /* 0x00001772 */ \
    XXX( WERR_NO_RECOVERY_POLICY                           , 6003      ) /* 0x00001773 */ \
    XXX( WERR_NO_EFS                                       , 6004      ) /* 0x00001774 */ \
    XXX( WERR_WRONG_EFS                                    , 6005      ) /* 0x00001775 */ \
    XXX( WERR_NO_USER_KEYS                                 , 6006      ) /* 0x00001776 */ \
    XXX( WERR_FILE_NOT_ENCRYPTED                           , 6007      ) /* 0x00001777 */ \
    XXX( WERR_NOT_EXPORT_FORMAT                            , 6008      ) /* 0x00001778 */ \
    XXX( WERR_FILE_READ_ONLY                               , 6009      ) /* 0x00001779 */ \
    XXX( WERR_DIR_EFS_DISALLOWED                           , 6010      ) /* 0x0000177a */ \
    XXX( WERR_EFS_SERVER_NOT_TRUSTED                       , 6011      ) /* 0x0000177b */ \
    XXX( WERR_BAD_RECOVERY_POLICY                          , 6012      ) /* 0x0000177c */ \
    XXX( WERR_EFS_ALG_BLOB_TOO_BIG                         , 6013      ) /* 0x0000177d */ \
    XXX( WERR_VOLUME_NOT_SUPPORT_EFS                       , 6014      ) /* 0x0000177e */ \
    XXX( WERR_EFS_DISABLED                                 , 6015      ) /* 0x0000177f */ \
    XXX( WERR_EFS_VERSION_NOT_SUPPORT                      , 6016      ) /* 0x00001780 */ \
    XXX( WERR_CS_ENCRYPTION_INVALID_SERVER_RESPONSE        , 6017      ) /* 0x00001781 */ \
    XXX( WERR_CS_ENCRYPTION_UNSUPPORTED_SERVER             , 6018      ) /* 0x00001782 */ \
    XXX( WERR_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE        , 6019      ) /* 0x00001783 */ \
    XXX( WERR_CS_ENCRYPTION_NEW_ENCRYPTED_FILE             , 6020      ) /* 0x00001784 */ \
    XXX( WERR_CS_ENCRYPTION_FILE_NOT_CSE                   , 6021      ) /* 0x00001785 */ \
    XXX( WERR_NO_BROWSER_SERVERS_FOUND                     , 6118      ) /* 0x000017e6 */ \
    XXX( WERR_LOG_SECTOR_INVALID                           , 6600      ) /* 0x000019c8 */ \
    XXX( WERR_LOG_SECTOR_PARITY_INVALID                    , 6601      ) /* 0x000019c9 */ \
    XXX( WERR_LOG_SECTOR_REMAPPED                          , 6602      ) /* 0x000019ca */ \
    XXX( WERR_LOG_BLOCK_INCOMPLETE                         , 6603      ) /* 0x000019cb */ \
    XXX( WERR_LOG_INVALID_RANGE                            , 6604      ) /* 0x000019cc */ \
    XXX( WERR_LOG_BLOCKS_EXHAUSTED                         , 6605      ) /* 0x000019cd */ \
    XXX( WERR_LOG_READ_CONTEXT_INVALID                     , 6606      ) /* 0x000019ce */ \
    XXX( WERR_LOG_RESTART_INVALID                          , 6607      ) /* 0x000019cf */ \
    XXX( WERR_LOG_BLOCK_VERSION                            , 6608      ) /* 0x000019d0 */ \
    XXX( WERR_LOG_BLOCK_INVALID                            , 6609      ) /* 0x000019d1 */ \
    XXX( WERR_LOG_READ_MODE_INVALID                        , 6610      ) /* 0x000019d2 */ \
    XXX( WERR_LOG_NO_RESTART                               , 6611      ) /* 0x000019d3 */ \
    XXX( WERR_LOG_METADATA_CORRUPT                         , 6612      ) /* 0x000019d4 */ \
    XXX( WERR_LOG_METADATA_INVALID                         , 6613      ) /* 0x000019d5 */ \
    XXX( WERR_LOG_METADATA_INCONSISTENT                    , 6614      ) /* 0x000019d6 */ \
    XXX( WERR_LOG_RESERVATION_INVALID                      , 6615      ) /* 0x000019d7 */ \
    XXX( WERR_LOG_CANT_DELETE                              , 6616      ) /* 0x000019d8 */ \
    XXX( WERR_LOG_CONTAINER_LIMIT_EXCEEDED                 , 6617      ) /* 0x000019d9 */ \
    XXX( WERR_LOG_START_OF_LOG                             , 6618      ) /* 0x000019da */ \
    XXX( WERR_LOG_POLICY_ALREADY_INSTALLED                 , 6619      ) /* 0x000019db */ \
    XXX( WERR_LOG_POLICY_NOT_INSTALLED                     , 6620      ) /* 0x000019dc */ \
    XXX( WERR_LOG_POLICY_INVALID                           , 6621      ) /* 0x000019dd */ \
    XXX( WERR_LOG_POLICY_CONFLICT                          , 6622      ) /* 0x000019de */ \
    XXX( WERR_LOG_PINNED_ARCHIVE_TAIL                      , 6623      ) /* 0x000019df */ \
    XXX( WERR_LOG_RECORD_NONEXISTENT                       , 6624      ) /* 0x000019e0 */ \
    XXX( WERR_LOG_RECORDS_RESERVED_INVALID                 , 6625      ) /* 0x000019e1 */ \
    XXX( WERR_LOG_SPACE_RESERVED_INVALID                   , 6626      ) /* 0x000019e2 */ \
    XXX( WERR_LOG_TAIL_INVALID                             , 6627      ) /* 0x000019e3 */ \
    XXX( WERR_LOG_FULL                                     , 6628      ) /* 0x000019e4 */ \
    XXX( WERR_COULD_NOT_RESIZE_LOG                         , 6629      ) /* 0x000019e5 */ \
    XXX( WERR_LOG_MULTIPLEXED                              , 6630      ) /* 0x000019e6 */ \
    XXX( WERR_LOG_DEDICATED                                , 6631      ) /* 0x000019e7 */ \
    XXX( WERR_LOG_ARCHIVE_NOT_IN_PROGRESS                  , 6632      ) /* 0x000019e8 */ \
    XXX( WERR_LOG_ARCHIVE_IN_PROGRESS                      , 6633      ) /* 0x000019e9 */ \
    XXX( WERR_LOG_EPHEMERAL                                , 6634      ) /* 0x000019ea */ \
    XXX( WERR_LOG_NOT_ENOUGH_CONTAINERS                    , 6635      ) /* 0x000019eb */ \
    XXX( WERR_LOG_CLIENT_ALREADY_REGISTERED                , 6636      ) /* 0x000019ec */ \
    XXX( WERR_LOG_CLIENT_NOT_REGISTERED                    , 6637      ) /* 0x000019ed */ \
    XXX( WERR_LOG_FULL_HANDLER_IN_PROGRESS                 , 6638      ) /* 0x000019ee */ \
    XXX( WERR_LOG_CONTAINER_READ_FAILED                    , 6639      ) /* 0x000019ef */ \
    XXX( WERR_LOG_CONTAINER_WRITE_FAILED                   , 6640      ) /* 0x000019f0 */ \
    XXX( WERR_LOG_CONTAINER_OPEN_FAILED                    , 6641      ) /* 0x000019f1 */ \
    XXX( WERR_LOG_CONTAINER_STATE_INVALID                  , 6642      ) /* 0x000019f2 */ \
    XXX( WERR_LOG_STATE_INVALID                            , 6643      ) /* 0x000019f3 */ \
    XXX( WERR_LOG_PINNED                                   , 6644      ) /* 0x000019f4 */ \
    XXX( WERR_LOG_METADATA_FLUSH_FAILED                    , 6645      ) /* 0x000019f5 */ \
    XXX( WERR_LOG_INCONSISTENT_SECURITY                    , 6646      ) /* 0x000019f6 */ \
    XXX( WERR_LOG_APPENDED_FLUSH_FAILED                    , 6647      ) /* 0x000019f7 */ \
    XXX( WERR_LOG_PINNED_RESERVATION                       , 6648      ) /* 0x000019f8 */ \
    XXX( WERR_INVALID_TRANSACTION                          , 6700      ) /* 0x00001a2c */ \
    XXX( WERR_TRANSACTION_NOT_ACTIVE                       , 6701      ) /* 0x00001a2d */ \
    XXX( WERR_TRANSACTION_REQUEST_NOT_VALID                , 6702      ) /* 0x00001a2e */ \
    XXX( WERR_TRANSACTION_NOT_REQUESTED                    , 6703      ) /* 0x00001a2f */ \
    XXX( WERR_TRANSACTION_ALREADY_ABORTED                  , 6704      ) /* 0x00001a30 */ \
    XXX( WERR_TRANSACTION_ALREADY_COMMITTED                , 6705      ) /* 0x00001a31 */ \
    XXX( WERR_TM_INITIALIZATION_FAILED                     , 6706      ) /* 0x00001a32 */ \
    XXX( WERR_RESOURCEMANAGER_READ_ONLY                    , 6707      ) /* 0x00001a33 */ \
    XXX( WERR_TRANSACTION_NOT_JOINED                       , 6708      ) /* 0x00001a34 */ \
    XXX( WERR_TRANSACTION_SUPERIOR_EXISTS                  , 6709      ) /* 0x00001a35 */ \
    XXX( WERR_CRM_PROTOCOL_ALREADY_EXISTS                  , 6710      ) /* 0x00001a36 */ \
    XXX( WERR_TRANSACTION_PROPAGATION_FAILED               , 6711      ) /* 0x00001a37 */ \
    XXX( WERR_CRM_PROTOCOL_NOT_FOUND                       , 6712      ) /* 0x00001a38 */ \
    XXX( WERR_TRANSACTION_INVALID_MARSHALL_BUFFER          , 6713      ) /* 0x00001a39 */ \
    XXX( WERR_CURRENT_TRANSACTION_NOT_VALID                , 6714      ) /* 0x00001a3a */ \
    XXX( WERR_TRANSACTION_NOT_FOUND                        , 6715      ) /* 0x00001a3b */ \
    XXX( WERR_RESOURCEMANAGER_NOT_FOUND                    , 6716      ) /* 0x00001a3c */ \
    XXX( WERR_ENLISTMENT_NOT_FOUND                         , 6717      ) /* 0x00001a3d */ \
    XXX( WERR_TRANSACTIONMANAGER_NOT_FOUND                 , 6718      ) /* 0x00001a3e */ \
    XXX( WERR_TRANSACTIONMANAGER_NOT_ONLINE                , 6719      ) /* 0x00001a3f */ \
    XXX( WERR_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION   , 6720      ) /* 0x00001a40 */ \
    XXX( WERR_TRANSACTIONAL_CONFLICT                       , 6800      ) /* 0x00001a90 */ \
    XXX( WERR_RM_NOT_ACTIVE                                , 6801      ) /* 0x00001a91 */ \
    XXX( WERR_RM_METADATA_CORRUPT                          , 6802      ) /* 0x00001a92 */ \
    XXX( WERR_DIRECTORY_NOT_RM                             , 6803      ) /* 0x00001a93 */ \
    XXX( WERR_TRANSACTIONS_UNSUPPORTED_REMOTE              , 6805      ) /* 0x00001a95 */ \
    XXX( WERR_LOG_RESIZE_INVALID_SIZE                      , 6806      ) /* 0x00001a96 */ \
    XXX( WERR_OBJECT_NO_LONGER_EXISTS                      , 6807      ) /* 0x00001a97 */ \
    XXX( WERR_STREAM_MINIVERSION_NOT_FOUND                 , 6808      ) /* 0x00001a98 */ \
    XXX( WERR_STREAM_MINIVERSION_NOT_VALID                 , 6809      ) /* 0x00001a99 */ \
    XXX( WERR_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION, 6810      ) /* 0x00001a9a */ \
    XXX( WERR_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT     , 6811      ) /* 0x00001a9b */ \
    XXX( WERR_CANT_CREATE_MORE_STREAM_MINIVERSIONS         , 6812      ) /* 0x00001a9c */ \
    XXX( WERR_REMOTE_FILE_VERSION_MISMATCH                 , 6814      ) /* 0x00001a9e */ \
    XXX( WERR_HANDLE_NO_LONGER_VALID                       , 6815      ) /* 0x00001a9f */ \
    XXX( WERR_NO_TXF_METADATA                              , 6816      ) /* 0x00001aa0 */ \
    XXX( WERR_LOG_CORRUPTION_DETECTED                      , 6817      ) /* 0x00001aa1 */ \
    XXX( WERR_CANT_RECOVER_WITH_HANDLE_OPEN                , 6818      ) /* 0x00001aa2 */ \
    XXX( WERR_RM_DISCONNECTED                              , 6819      ) /* 0x00001aa3 */ \
    XXX( WERR_ENLISTMENT_NOT_SUPERIOR                      , 6820      ) /* 0x00001aa4 */ \
    XXX( WERR_RECOVERY_NOT_NEEDED                          , 6821      ) /* 0x00001aa5 */ \
    XXX( WERR_RM_ALREADY_STARTED                           , 6822      ) /* 0x00001aa6 */ \
    XXX( WERR_FILE_IDENTITY_NOT_PERSISTENT                 , 6823      ) /* 0x00001aa7 */ \
    XXX( WERR_CANT_BREAK_TRANSACTIONAL_DEPENDENCY          , 6824      ) /* 0x00001aa8 */ \
    XXX( WERR_CANT_CROSS_RM_BOUNDARY                       , 6825      ) /* 0x00001aa9 */ \
    XXX( WERR_TXF_DIR_NOT_EMPTY                            , 6826      ) /* 0x00001aaa */ \
    XXX( WERR_INDOUBT_TRANSACTIONS_EXIST                   , 6827      ) /* 0x00001aab */ \
    XXX( WERR_TM_VOLATILE                                  , 6828      ) /* 0x00001aac */ \
    XXX( WERR_ROLLBACK_TIMER_EXPIRED                       , 6829      ) /* 0x00001aad */ \
    XXX( WERR_TXF_ATTRIBUTE_CORRUPT                        , 6830      ) /* 0x00001aae */ \
    XXX( WERR_EFS_NOT_ALLOWED_IN_TRANSACTION               , 6831      ) /* 0x00001aaf */ \
    XXX( WERR_TRANSACTIONAL_OPEN_NOT_ALLOWED               , 6832      ) /* 0x00001ab0 */ \
    XXX( WERR_LOG_GROWTH_FAILED                            , 6833      ) /* 0x00001ab1 */ \
    XXX( WERR_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE        , 6834      ) /* 0x00001ab2 */ \
    XXX( WERR_TXF_METADATA_ALREADY_PRESENT                 , 6835      ) /* 0x00001ab3 */ \
    XXX( WERR_TRANSACTION_SCOPE_CALLBACKS_NOT_SET          , 6836      ) /* 0x00001ab4 */ \
    XXX( WERR_TRANSACTION_REQUIRED_PROMOTION               , 6837      ) /* 0x00001ab5 */ \
    XXX( WERR_CANNOT_EXECUTE_FILE_IN_TRANSACTION           , 6838      ) /* 0x00001ab6 */ \
    XXX( WERR_TRANSACTIONS_NOT_FROZEN                      , 6839      ) /* 0x00001ab7 */ \
    XXX( WERR_TRANSACTION_FREEZE_IN_PROGRESS               , 6840      ) /* 0x00001ab8 */ \
    XXX( WERR_NOT_SNAPSHOT_VOLUME                          , 6841      ) /* 0x00001ab9 */ \
    XXX( WERR_NO_SAVEPOINT_WITH_OPEN_FILES                 , 6842      ) /* 0x00001aba */ \
    XXX( WERR_DATA_LOST_REPAIR                             , 6843      ) /* 0x00001abb */ \
    XXX( WERR_SPARSE_NOT_ALLOWED_IN_TRANSACTION            , 6844      ) /* 0x00001abc */ \
    XXX( WERR_TM_IDENTITY_MISMATCH                         , 6845      ) /* 0x00001abd */ \
    XXX( WERR_FLOATED_SECTION                              , 6846      ) /* 0x00001abe */ \
    XXX( WERR_CANNOT_ACCEPT_TRANSACTED_WORK                , 6847      ) /* 0x00001abf */ \
    XXX( WERR_CANNOT_ABORT_TRANSACTIONS                    , 6848      ) /* 0x00001ac0 */ \
    XXX( WERR_CTX_WINSTATION_NAME_INVALID                  , 7001      ) /* 0x00001b59 */ \
    XXX( WERR_CTX_INVALID_PD                               , 7002      ) /* 0x00001b5a */ \
    XXX( WERR_CTX_PD_NOT_FOUND                             , 7003      ) /* 0x00001b5b */ \
    XXX( WERR_CTX_WD_NOT_FOUND                             , 7004      ) /* 0x00001b5c */ \
    XXX( WERR_CTX_CANNOT_MAKE_EVENTLOG_ENTRY               , 7005      ) /* 0x00001b5d */ \
    XXX( WERR_CTX_SERVICE_NAME_COLLISION                   , 7006      ) /* 0x00001b5e */ \
    XXX( WERR_CTX_CLOSE_PENDING                            , 7007      ) /* 0x00001b5f */ \
    XXX( WERR_CTX_NO_OUTBUF                                , 7008      ) /* 0x00001b60 */ \
    XXX( WERR_CTX_MODEM_INF_NOT_FOUND                      , 7009      ) /* 0x00001b61 */ \
    XXX( WERR_CTX_INVALID_MODEMNAME                        , 7010      ) /* 0x00001b62 */ \
    XXX( WERR_CTX_MODEM_RESPONSE_ERROR                     , 7011      ) /* 0x00001b63 */ \
    XXX( WERR_CTX_MODEM_RESPONSE_TIMEOUT                   , 7012      ) /* 0x00001b64 */ \
    XXX( WERR_CTX_MODEM_RESPONSE_NO_CARRIER                , 7013      ) /* 0x00001b65 */ \
    XXX( WERR_CTX_MODEM_RESPONSE_NO_DIALTONE               , 7014      ) /* 0x00001b66 */ \
    XXX( WERR_CTX_MODEM_RESPONSE_BUSY                      , 7015      ) /* 0x00001b67 */ \
    XXX( WERR_CTX_MODEM_RESPONSE_VOICE                     , 7016      ) /* 0x00001b68 */ \
    XXX( WERR_CTX_TD_ERROR                                 , 7017      ) /* 0x00001b69 */ \
    XXX( WERR_CTX_WINSTATION_NOT_FOUND                     , 7022      ) /* 0x00001b6e */ \
    XXX( WERR_CTX_WINSTATION_ALREADY_EXISTS                , 7023      ) /* 0x00001b6f */ \
    XXX( WERR_CTX_WINSTATION_BUSY                          , 7024      ) /* 0x00001b70 */ \
    XXX( WERR_CTX_BAD_VIDEO_MODE                           , 7025      ) /* 0x00001b71 */ \
    XXX( WERR_CTX_GRAPHICS_INVALID                         , 7035      ) /* 0x00001b7b */ \
    XXX( WERR_CTX_LOGON_DISABLED                           , 7037      ) /* 0x00001b7d */ \
    XXX( WERR_CTX_NOT_CONSOLE                              , 7038      ) /* 0x00001b7e */ \
    XXX( WERR_CTX_CLIENT_QUERY_TIMEOUT                     , 7040      ) /* 0x00001b80 */ \
    XXX( WERR_CTX_CONSOLE_DISCONNECT                       , 7041      ) /* 0x00001b81 */ \
    XXX( WERR_CTX_CONSOLE_CONNECT                          , 7042      ) /* 0x00001b82 */ \
    XXX( WERR_CTX_SHADOW_DENIED                            , 7044      ) /* 0x00001b84 */ \
    XXX( WERR_CTX_WINSTATION_ACCESS_DENIED                 , 7045      ) /* 0x00001b85 */ \
    XXX( WERR_CTX_INVALID_WD                               , 7049      ) /* 0x00001b89 */ \
    XXX( WERR_CTX_SHADOW_INVALID                           , 7050      ) /* 0x00001b8a */ \
    XXX( WERR_CTX_SHADOW_DISABLED                          , 7051      ) /* 0x00001b8b */ \
    XXX( WERR_CTX_CLIENT_LICENSE_IN_USE                    , 7052      ) /* 0x00001b8c */ \
    XXX( WERR_CTX_CLIENT_LICENSE_NOT_SET                   , 7053      ) /* 0x00001b8d */ \
    XXX( WERR_CTX_LICENSE_NOT_AVAILABLE                    , 7054      ) /* 0x00001b8e */ \
    XXX( WERR_CTX_LICENSE_CLIENT_INVALID                   , 7055      ) /* 0x00001b8f */ \
    XXX( WERR_CTX_LICENSE_EXPIRED                          , 7056      ) /* 0x00001b90 */ \
    XXX( WERR_CTX_SHADOW_NOT_RUNNING                       , 7057      ) /* 0x00001b91 */ \
    XXX( WERR_CTX_SHADOW_ENDED_BY_MODE_CHANGE              , 7058      ) /* 0x00001b92 */ \
    XXX( WERR_ACTIVATION_COUNT_EXCEEDED                    , 7059      ) /* 0x00001b93 */ \
    XXX( WERR_CTX_WINSTATIONS_DISABLED                     , 7060      ) /* 0x00001b94 */ \
    XXX( WERR_CTX_ENCRYPTION_LEVEL_REQUIRED                , 7061      ) /* 0x00001b95 */ \
    XXX( WERR_CTX_SESSION_IN_USE                           , 7062      ) /* 0x00001b96 */ \
    XXX( WERR_CTX_NO_FORCE_LOGOFF                          , 7063      ) /* 0x00001b97 */ \
    XXX( WERR_CTX_ACCOUNT_RESTRICTION                      , 7064      ) /* 0x00001b98 */ \
    XXX( WERR_RDP_PROTOCOL_ERROR                           , 7065      ) /* 0x00001b99 */ \
    XXX( WERR_CTX_CDM_CONNECT                              , 7066      ) /* 0x00001b9a */ \
    XXX( WERR_CTX_CDM_DISCONNECT                           , 7067      ) /* 0x00001b9b */ \
    XXX( WERR_CTX_SECURITY_LAYER_ERROR                     , 7068      ) /* 0x00001b9c */ \
    XXX( WERR_TS_INCOMPATIBLE_SESSIONS                     , 7069      ) /* 0x00001b9d */ \
    XXX( WERR_FRS_ERR_INVALID_API_SEQUENCE                 , 8001      ) /* 0x00001f41 */ \
    XXX( WERR_FRS_ERR_STARTING_SERVICE                     , 8002      ) /* 0x00001f42 */ \
    XXX( WERR_FRS_ERR_STOPPING_SERVICE                     , 8003      ) /* 0x00001f43 */ \
    XXX( WERR_FRS_ERR_INTERNAL_API                         , 8004      ) /* 0x00001f44 */ \
    XXX( WERR_FRS_ERR_INTERNAL                             , 8005      ) /* 0x00001f45 */ \
    XXX( WERR_FRS_ERR_SERVICE_COMM                         , 8006      ) /* 0x00001f46 */ \
    XXX( WERR_FRS_ERR_INSUFFICIENT_PRIV                    , 8007      ) /* 0x00001f47 */ \
    XXX( WERR_FRS_ERR_AUTHENTICATION                       , 8008      ) /* 0x00001f48 */ \
    XXX( WERR_FRS_ERR_PARENT_INSUFFICIENT_PRIV             , 8009      ) /* 0x00001f49 */ \
    XXX( WERR_FRS_ERR_PARENT_AUTHENTICATION                , 8010      ) /* 0x00001f4a */ \
    XXX( WERR_FRS_ERR_CHILD_TO_PARENT_COMM                 , 8011      ) /* 0x00001f4b */ \
    XXX( WERR_FRS_ERR_PARENT_TO_CHILD_COMM                 , 8012      ) /* 0x00001f4c */ \
    XXX( WERR_FRS_ERR_SYSVOL_POPULATE                      , 8013      ) /* 0x00001f4d */ \
    XXX( WERR_FRS_ERR_SYSVOL_POPULATE_TIMEOUT              , 8014      ) /* 0x00001f4e */ \
    XXX( WERR_FRS_ERR_SYSVOL_IS_BUSY                       , 8015      ) /* 0x00001f4f */ \
    XXX( WERR_FRS_ERR_SYSVOL_DEMOTE                        , 8016      ) /* 0x00001f50 */ \
    XXX( WERR_FRS_ERR_INVALID_SERVICE_PARAMETER            , 8017      ) /* 0x00001f51 */ \
    XXX( WERR_DS_NOT_INSTALLED                             , 8200      ) /* 0x00002008 */ \
    XXX( WERR_DS_MEMBERSHIP_EVALUATED_LOCALLY              , 8201      ) /* 0x00002009 */ \
    XXX( WERR_DS_NO_ATTRIBUTE_OR_VALUE                     , 8202      ) /* 0x0000200a */ \
    XXX( WERR_DS_INVALID_ATTRIBUTE_SYNTAX                  , 8203      ) /* 0x0000200b */ \
    XXX( WERR_DS_ATTRIBUTE_TYPE_UNDEFINED                  , 8204      ) /* 0x0000200c */ \
    XXX( WERR_DS_ATTRIBUTE_OR_VALUE_EXISTS                 , 8205      ) /* 0x0000200d */ \
    XXX( WERR_DS_BUSY                                      , 8206      ) /* 0x0000200e */ \
    XXX( WERR_DS_UNAVAILABLE                               , 8207      ) /* 0x0000200f */ \
    XXX( WERR_DS_NO_RIDS_ALLOCATED                         , 8208      ) /* 0x00002010 */ \
    XXX( WERR_DS_NO_MORE_RIDS                              , 8209      ) /* 0x00002011 */ \
    XXX( WERR_DS_INCORRECT_ROLE_OWNER                      , 8210      ) /* 0x00002012 */ \
    XXX( WERR_DS_RIDMGR_INIT_ERROR                         , 8211      ) /* 0x00002013 */ \
    XXX( WERR_DS_OBJ_CLASS_VIOLATION                       , 8212      ) /* 0x00002014 */ \
    XXX( WERR_DS_CANT_ON_NON_LEAF                          , 8213      ) /* 0x00002015 */ \
    XXX( WERR_DS_CANT_ON_RDN                               , 8214      ) /* 0x00002016 */ \
    XXX( WERR_DS_CANT_MOD_OBJ_CLASS                        , 8215      ) /* 0x00002017 */ \
    XXX( WERR_DS_CROSS_DOM_MOVE_ERROR                      , 8216      ) /* 0x00002018 */ \
    XXX( WERR_DS_GC_NOT_AVAILABLE                          , 8217      ) /* 0x00002019 */ \
    XXX( WERR_SHARED_POLICY                                , 8218      ) /* 0x0000201a */ \
    XXX( WERR_POLICY_OBJECT_NOT_FOUND                      , 8219      ) /* 0x0000201b */ \
    XXX( WERR_POLICY_ONLY_IN_DS                            , 8220      ) /* 0x0000201c */ \
    XXX( WERR_PROMOTION_ACTIVE                             , 8221      ) /* 0x0000201d */ \
    XXX( WERR_NO_PROMOTION_ACTIVE                          , 8222      ) /* 0x0000201e */ \
    XXX( WERR_DS_OPERATIONS_ERROR                          , 8224      ) /* 0x00002020 */ \
    XXX( WERR_DS_PROTOCOL_ERROR                            , 8225      ) /* 0x00002021 */ \
    XXX( WERR_DS_TIMELIMIT_EXCEEDED                        , 8226      ) /* 0x00002022 */ \
    XXX( WERR_DS_SIZELIMIT_EXCEEDED                        , 8227      ) /* 0x00002023 */ \
    XXX( WERR_DS_ADMIN_LIMIT_EXCEEDED                      , 8228      ) /* 0x00002024 */ \
    XXX( WERR_DS_COMPARE_FALSE                             , 8229      ) /* 0x00002025 */ \
    XXX( WERR_DS_COMPARE_TRUE                              , 8230      ) /* 0x00002026 */ \
    XXX( WERR_DS_AUTH_METHOD_NOT_SUPPORTED                 , 8231      ) /* 0x00002027 */ \
    XXX( WERR_DS_STRONG_AUTH_REQUIRED                      , 8232      ) /* 0x00002028 */ \
    XXX( WERR_DS_INAPPROPRIATE_AUTH                        , 8233      ) /* 0x00002029 */ \
    XXX( WERR_DS_AUTH_UNKNOWN                              , 8234      ) /* 0x0000202a */ \
    XXX( WERR_DS_REFERRAL                                  , 8235      ) /* 0x0000202b */ \
    XXX( WERR_DS_UNAVAILABLE_CRIT_EXTENSION                , 8236      ) /* 0x0000202c */ \
    XXX( WERR_DS_CONFIDENTIALITY_REQUIRED                  , 8237      ) /* 0x0000202d */ \
    XXX( WERR_DS_INAPPROPRIATE_MATCHING                    , 8238      ) /* 0x0000202e */ \
    XXX( WERR_DS_CONSTRAINT_VIOLATION                      , 8239      ) /* 0x0000202f */ \
    XXX( WERR_DS_NO_SUCH_OBJECT                            , 8240      ) /* 0x00002030 */ \
    XXX( WERR_DS_ALIAS_PROBLEM                             , 8241      ) /* 0x00002031 */ \
    XXX( WERR_DS_INVALID_DN_SYNTAX                         , 8242      ) /* 0x00002032 */ \
    XXX( WERR_DS_IS_LEAF                                   , 8243      ) /* 0x00002033 */ \
    XXX( WERR_DS_ALIAS_DEREF_PROBLEM                       , 8244      ) /* 0x00002034 */ \
    XXX( WERR_DS_UNWILLING_TO_PERFORM                      , 8245      ) /* 0x00002035 */ \
    XXX( WERR_DS_LOOP_DETECT                               , 8246      ) /* 0x00002036 */ \
    XXX( WERR_DS_NAMING_VIOLATION                          , 8247      ) /* 0x00002037 */ \
    XXX( WERR_DS_OBJECT_RESULTS_TOO_LARGE                  , 8248      ) /* 0x00002038 */ \
    XXX( WERR_DS_AFFECTS_MULTIPLE_DSAS                     , 8249      ) /* 0x00002039 */ \
    XXX( WERR_DS_SERVER_DOWN                               , 8250      ) /* 0x0000203a */ \
    XXX( WERR_DS_LOCAL_ERROR                               , 8251      ) /* 0x0000203b */ \
    XXX( WERR_DS_ENCODING_ERROR                            , 8252      ) /* 0x0000203c */ \
    XXX( WERR_DS_DECODING_ERROR                            , 8253      ) /* 0x0000203d */ \
    XXX( WERR_DS_FILTER_UNKNOWN                            , 8254      ) /* 0x0000203e */ \
    XXX( WERR_DS_PARAM_ERROR                               , 8255      ) /* 0x0000203f */ \
    XXX( WERR_DS_NOT_SUPPORTED                             , 8256      ) /* 0x00002040 */ \
    XXX( WERR_DS_NO_RESULTS_RETURNED                       , 8257      ) /* 0x00002041 */ \
    XXX( WERR_DS_CONTROL_NOT_FOUND                         , 8258      ) /* 0x00002042 */ \
    XXX( WERR_DS_CLIENT_LOOP                               , 8259      ) /* 0x00002043 */ \
    XXX( WERR_DS_REFERRAL_LIMIT_EXCEEDED                   , 8260      ) /* 0x00002044 */ \
    XXX( WERR_DS_SORT_CONTROL_MISSING                      , 8261      ) /* 0x00002045 */ \
    XXX( WERR_DS_OFFSET_RANGE_ERROR                        , 8262      ) /* 0x00002046 */ \
    XXX( WERR_DS_ROOT_MUST_BE_NC                           , 8301      ) /* 0x0000206d */ \
    XXX( WERR_DS_ADD_REPLICA_INHIBITED                     , 8302      ) /* 0x0000206e */ \
    XXX( WERR_DS_ATT_NOT_DEF_IN_SCHEMA                     , 8303      ) /* 0x0000206f */ \
    XXX( WERR_DS_MAX_OBJ_SIZE_EXCEEDED                     , 8304      ) /* 0x00002070 */ \
    XXX( WERR_DS_OBJ_STRING_NAME_EXISTS                    , 8305      ) /* 0x00002071 */ \
    XXX( WERR_DS_NO_RDN_DEFINED_IN_SCHEMA                  , 8306      ) /* 0x00002072 */ \
    XXX( WERR_DS_RDN_DOESNT_MATCH_SCHEMA                   , 8307      ) /* 0x00002073 */ \
    XXX( WERR_DS_NO_REQUESTED_ATTS_FOUND                   , 8308      ) /* 0x00002074 */ \
    XXX( WERR_DS_USER_BUFFER_TO_SMALL                      , 8309      ) /* 0x00002075 */ \
    XXX( WERR_DS_ATT_IS_NOT_ON_OBJ                         , 8310      ) /* 0x00002076 */ \
    XXX( WERR_DS_ILLEGAL_MOD_OPERATION                     , 8311      ) /* 0x00002077 */ \
    XXX( WERR_DS_OBJ_TOO_LARGE                             , 8312      ) /* 0x00002078 */ \
    XXX( WERR_DS_BAD_INSTANCE_TYPE                         , 8313      ) /* 0x00002079 */ \
    XXX( WERR_DS_MASTERDSA_REQUIRED                        , 8314      ) /* 0x0000207a */ \
    XXX( WERR_DS_OBJECT_CLASS_REQUIRED                     , 8315      ) /* 0x0000207b */ \
    XXX( WERR_DS_MISSING_REQUIRED_ATT                      , 8316      ) /* 0x0000207c */ \
    XXX( WERR_DS_ATT_NOT_DEF_FOR_CLASS                     , 8317      ) /* 0x0000207d */ \
    XXX( WERR_DS_ATT_ALREADY_EXISTS                        , 8318      ) /* 0x0000207e */ \
    XXX( WERR_DS_CANT_ADD_ATT_VALUES                       , 8320      ) /* 0x00002080 */ \
    XXX( WERR_DS_SINGLE_VALUE_CONSTRAINT                   , 8321      ) /* 0x00002081 */ \
    XXX( WERR_DS_RANGE_CONSTRAINT                          , 8322      ) /* 0x00002082 */ \
    XXX( WERR_DS_ATT_VAL_ALREADY_EXISTS                    , 8323      ) /* 0x00002083 */ \
    XXX( WERR_DS_CANT_REM_MISSING_ATT                      , 8324      ) /* 0x00002084 */ \
    XXX( WERR_DS_CANT_REM_MISSING_ATT_VAL                  , 8325      ) /* 0x00002085 */ \
    XXX( WERR_DS_ROOT_CANT_BE_SUBREF                       , 8326      ) /* 0x00002086 */ \
    XXX( WERR_DS_NO_CHAINING                               , 8327      ) /* 0x00002087 */ \
    XXX( WERR_DS_NO_CHAINED_EVAL                           , 8328      ) /* 0x00002088 */ \
    XXX( WERR_DS_NO_PARENT_OBJECT                          , 8329      ) /* 0x00002089 */ \
    XXX( WERR_DS_PARENT_IS_AN_ALIAS                        , 8330      ) /* 0x0000208a */ \
    XXX( WERR_DS_CANT_MIX_MASTER_AND_REPS                  , 8331      ) /* 0x0000208b */ \
    XXX( WERR_DS_CHILDREN_EXIST                            , 8332      ) /* 0x0000208c */ \
    XXX( WERR_DS_OBJ_NOT_FOUND                             , 8333      ) /* 0x0000208d */ \
    XXX( WERR_DS_ALIASED_OBJ_MISSING                       , 8334      ) /* 0x0000208e */ \
    XXX( WERR_DS_BAD_NAME_SYNTAX                           , 8335      ) /* 0x0000208f */ \
    XXX( WERR_DS_ALIAS_POINTS_TO_ALIAS                     , 8336      ) /* 0x00002090 */ \
    XXX( WERR_DS_CANT_DEREF_ALIAS                          , 8337      ) /* 0x00002091 */ \
    XXX( WERR_DS_OUT_OF_SCOPE                              , 8338      ) /* 0x00002092 */ \
    XXX( WERR_DS_OBJECT_BEING_REMOVED                      , 8339      ) /* 0x00002093 */ \
    XXX( WERR_DS_CANT_DELETE_DSA_OBJ                       , 8340      ) /* 0x00002094 */ \
    XXX( WERR_DS_GENERIC_ERROR                             , 8341      ) /* 0x00002095 */ \
    XXX( WERR_DS_DSA_MUST_BE_INT_MASTER                    , 8342      ) /* 0x00002096 */ \
    XXX( WERR_DS_CLASS_NOT_DSA                             , 8343      ) /* 0x00002097 */ \
    XXX( WERR_DS_INSUFF_ACCESS_RIGHTS                      , 8344      ) /* 0x00002098 */ \
    XXX( WERR_DS_ILLEGAL_SUPERIOR                          , 8345      ) /* 0x00002099 */ \
    XXX( WERR_DS_ATTRIBUTE_OWNED_BY_SAM                    , 8346      ) /* 0x0000209a */ \
    XXX( WERR_DS_NAME_TOO_MANY_PARTS                       , 8347      ) /* 0x0000209b */ \
    XXX( WERR_DS_NAME_TOO_LONG                             , 8348      ) /* 0x0000209c */ \
    XXX( WERR_DS_NAME_VALUE_TOO_LONG                       , 8349      ) /* 0x0000209d */ \
    XXX( WERR_DS_NAME_UNPARSEABLE                          , 8350      ) /* 0x0000209e */ \
    XXX( WERR_DS_NAME_TYPE_UNKNOWN                         , 8351      ) /* 0x0000209f */ \
    XXX( WERR_DS_NOT_AN_OBJECT                             , 8352      ) /* 0x000020a0 */ \
    XXX( WERR_DS_SEC_DESC_TOO_SHORT                        , 8353      ) /* 0x000020a1 */ \
    XXX( WERR_DS_SEC_DESC_INVALID                          , 8354      ) /* 0x000020a2 */ \
    XXX( WERR_DS_NO_DELETED_NAME                           , 8355      ) /* 0x000020a3 */ \
    XXX( WERR_DS_SUBREF_MUST_HAVE_PARENT                   , 8356      ) /* 0x000020a4 */ \
    XXX( WERR_DS_NCNAME_MUST_BE_NC                         , 8357      ) /* 0x000020a5 */ \
    XXX( WERR_DS_CANT_ADD_SYSTEM_ONLY                      , 8358      ) /* 0x000020a6 */ \
    XXX( WERR_DS_CLASS_MUST_BE_CONCRETE                    , 8359      ) /* 0x000020a7 */ \
    XXX( WERR_DS_INVALID_DMD                               , 8360      ) /* 0x000020a8 */ \
    XXX( WERR_DS_OBJ_GUID_EXISTS                           , 8361      ) /* 0x000020a9 */ \
    XXX( WERR_DS_NOT_ON_BACKLINK                           , 8362      ) /* 0x000020aa */ \
    XXX( WERR_DS_NO_CROSSREF_FOR_NC                        , 8363      ) /* 0x000020ab */ \
    XXX( WERR_DS_SHUTTING_DOWN                             , 8364      ) /* 0x000020ac */ \
    XXX( WERR_DS_UNKNOWN_OPERATION                         , 8365      ) /* 0x000020ad */ \
    XXX( WERR_DS_INVALID_ROLE_OWNER                        , 8366      ) /* 0x000020ae */ \
    XXX( WERR_DS_COULDNT_CONTACT_FSMO                      , 8367      ) /* 0x000020af */ \
    XXX( WERR_DS_CROSS_NC_DN_RENAME                        , 8368      ) /* 0x000020b0 */ \
    XXX( WERR_DS_CANT_MOD_SYSTEM_ONLY                      , 8369      ) /* 0x000020b1 */ \
    XXX( WERR_DS_REPLICATOR_ONLY                           , 8370      ) /* 0x000020b2 */ \
    XXX( WERR_DS_OBJ_CLASS_NOT_DEFINED                     , 8371      ) /* 0x000020b3 */ \
    XXX( WERR_DS_OBJ_CLASS_NOT_SUBCLASS                    , 8372      ) /* 0x000020b4 */ \
    XXX( WERR_DS_NAME_REFERENCE_INVALID                    , 8373      ) /* 0x000020b5 */ \
    XXX( WERR_DS_CROSS_REF_EXISTS                          , 8374      ) /* 0x000020b6 */ \
    XXX( WERR_DS_CANT_DEL_MASTER_CROSSREF                  , 8375      ) /* 0x000020b7 */ \
    XXX( WERR_DS_SUBTREE_NOTIFY_NOT_NC_HEAD                , 8376      ) /* 0x000020b8 */ \
    XXX( WERR_DS_NOTIFY_FILTER_TOO_COMPLEX                 , 8377      ) /* 0x000020b9 */ \
    XXX( WERR_DS_DUP_RDN                                   , 8378      ) /* 0x000020ba */ \
    XXX( WERR_DS_DUP_OID                                   , 8379      ) /* 0x000020bb */ \
    XXX( WERR_DS_DUP_MAPI_ID                               , 8380      ) /* 0x000020bc */ \
    XXX( WERR_DS_DUP_SCHEMA_ID_GUID                        , 8381      ) /* 0x000020bd */ \
    XXX( WERR_DS_DUP_LDAP_DISPLAY_NAME                     , 8382      ) /* 0x000020be */ \
    XXX( WERR_DS_SEMANTIC_ATT_TEST                         , 8383      ) /* 0x000020bf */ \
    XXX( WERR_DS_SYNTAX_MISMATCH                           , 8384      ) /* 0x000020c0 */ \
    XXX( WERR_DS_EXISTS_IN_MUST_HAVE                       , 8385      ) /* 0x000020c1 */ \
    XXX( WERR_DS_EXISTS_IN_MAY_HAVE                        , 8386      ) /* 0x000020c2 */ \
    XXX( WERR_DS_NONEXISTENT_MAY_HAVE                      , 8387      ) /* 0x000020c3 */ \
    XXX( WERR_DS_NONEXISTENT_MUST_HAVE                     , 8388      ) /* 0x000020c4 */ \
    XXX( WERR_DS_AUX_CLS_TEST_FAIL                         , 8389      ) /* 0x000020c5 */ \
    XXX( WERR_DS_NONEXISTENT_POSS_SUP                      , 8390      ) /* 0x000020c6 */ \
    XXX( WERR_DS_SUB_CLS_TEST_FAIL                         , 8391      ) /* 0x000020c7 */ \
    XXX( WERR_DS_BAD_RDN_ATT_ID_SYNTAX                     , 8392      ) /* 0x000020c8 */ \
    XXX( WERR_DS_EXISTS_IN_AUX_CLS                         , 8393      ) /* 0x000020c9 */ \
    XXX( WERR_DS_EXISTS_IN_SUB_CLS                         , 8394      ) /* 0x000020ca */ \
    XXX( WERR_DS_EXISTS_IN_POSS_SUP                        , 8395      ) /* 0x000020cb */ \
    XXX( WERR_DS_RECALCSCHEMA_FAILED                       , 8396      ) /* 0x000020cc */ \
    XXX( WERR_DS_TREE_DELETE_NOT_FINISHED                  , 8397      ) /* 0x000020cd */ \
    XXX( WERR_DS_CANT_DELETE                               , 8398      ) /* 0x000020ce */ \
    XXX( WERR_DS_ATT_SCHEMA_REQ_ID                         , 8399      ) /* 0x000020cf */ \
    XXX( WERR_DS_BAD_ATT_SCHEMA_SYNTAX                     , 8400      ) /* 0x000020d0 */ \
    XXX( WERR_DS_CANT_CACHE_ATT                            , 8401      ) /* 0x000020d1 */ \
    XXX( WERR_DS_CANT_CACHE_CLASS                          , 8402      ) /* 0x000020d2 */ \
    XXX( WERR_DS_CANT_REMOVE_ATT_CACHE                     , 8403      ) /* 0x000020d3 */ \
    XXX( WERR_DS_CANT_REMOVE_CLASS_CACHE                   , 8404      ) /* 0x000020d4 */ \
    XXX( WERR_DS_CANT_RETRIEVE_DN                          , 8405      ) /* 0x000020d5 */ \
    XXX( WERR_DS_MISSING_SUPREF                            , 8406      ) /* 0x000020d6 */ \
    XXX( WERR_DS_CANT_RETRIEVE_INSTANCE                    , 8407      ) /* 0x000020d7 */ \
    XXX( WERR_DS_CODE_INCONSISTENCY                        , 8408      ) /* 0x000020d8 */ \
    XXX( WERR_DS_DATABASE_ERROR                            , 8409      ) /* 0x000020d9 */ \
    XXX( WERR_DS_MISSING_EXPECTED_ATT                      , 8411      ) /* 0x000020db */ \
    XXX( WERR_DS_NCNAME_MISSING_CR_REF                     , 8412      ) /* 0x000020dc */ \
    XXX( WERR_DS_SECURITY_CHECKING_ERROR                   , 8413      ) /* 0x000020dd */ \
    XXX( WERR_DS_SCHEMA_NOT_LOADED                         , 8414      ) /* 0x000020de */ \
    XXX( WERR_DS_SCHEMA_ALLOC_FAILED                       , 8415      ) /* 0x000020df */ \
    XXX( WERR_DS_ATT_SCHEMA_REQ_SYNTAX                     , 8416      ) /* 0x000020e0 */ \
    XXX( WERR_DS_GCVERIFY_ERROR                            , 8417      ) /* 0x000020e1 */ \
    XXX( WERR_DS_DRA_SCHEMA_MISMATCH                       , 8418      ) /* 0x000020e2 */ \
    XXX( WERR_DS_CANT_FIND_DSA_OBJ                         , 8419      ) /* 0x000020e3 */ \
    XXX( WERR_DS_CANT_FIND_EXPECTED_NC                     , 8420      ) /* 0x000020e4 */ \
    XXX( WERR_DS_CANT_FIND_NC_IN_CACHE                     , 8421      ) /* 0x000020e5 */ \
    XXX( WERR_DS_CANT_RETRIEVE_CHILD                       , 8422      ) /* 0x000020e6 */ \
    XXX( WERR_DS_SECURITY_ILLEGAL_MODIFY                   , 8423      ) /* 0x000020e7 */ \
    XXX( WERR_DS_CANT_REPLACE_HIDDEN_REC                   , 8424      ) /* 0x000020e8 */ \
    XXX( WERR_DS_BAD_HIERARCHY_FILE                        , 8425      ) /* 0x000020e9 */ \
    XXX( WERR_DS_BUILD_HIERARCHY_TABLE_FAILED              , 8426      ) /* 0x000020ea */ \
    XXX( WERR_DS_CONFIG_PARAM_MISSING                      , 8427      ) /* 0x000020eb */ \
    XXX( WERR_DS_COUNTING_AB_INDICES_FAILED                , 8428      ) /* 0x000020ec */ \
    XXX( WERR_DS_HIERARCHY_TABLE_MALLOC_FAILED             , 8429      ) /* 0x000020ed */ \
    XXX( WERR_DS_INTERNAL_FAILURE                          , 8430      ) /* 0x000020ee */ \
    XXX( WERR_DS_UNKNOWN_ERROR                             , 8431      ) /* 0x000020ef */ \
    XXX( WERR_DS_ROOT_REQUIRES_CLASS_TOP                   , 8432      ) /* 0x000020f0 */ \
    XXX( WERR_DS_REFUSING_FSMO_ROLES                       , 8433      ) /* 0x000020f1 */ \
    XXX( WERR_DS_MISSING_FSMO_SETTINGS                     , 8434      ) /* 0x000020f2 */ \
    XXX( WERR_DS_UNABLE_TO_SURRENDER_ROLES                 , 8435      ) /* 0x000020f3 */ \
    XXX( WERR_DS_DRA_GENERIC                               , 8436      ) /* 0x000020f4 */ \
    XXX( WERR_DS_DRA_INVALID_PARAMETER                     , 8437      ) /* 0x000020f5 */ \
    XXX( WERR_DS_DRA_BUSY                                  , 8438      ) /* 0x000020f6 */ \
    XXX( WERR_DS_DRA_BAD_DN                                , 8439      ) /* 0x000020f7 */ \
    XXX( WERR_DS_DRA_BAD_NC                                , 8440      ) /* 0x000020f8 */ \
    XXX( WERR_DS_DRA_DN_EXISTS                             , 8441      ) /* 0x000020f9 */ \
    XXX( WERR_DS_DRA_INTERNAL_ERROR                        , 8442      ) /* 0x000020fa */ \
    XXX( WERR_DS_DRA_INCONSISTENT_DIT                      , 8443      ) /* 0x000020fb */ \
    XXX( WERR_DS_DRA_CONNECTION_FAILED                     , 8444      ) /* 0x000020fc */ \
    XXX( WERR_DS_DRA_BAD_INSTANCE_TYPE                     , 8445      ) /* 0x000020fd */ \
    XXX( WERR_DS_DRA_OUT_OF_MEM                            , 8446      ) /* 0x000020fe */ \
    XXX( WERR_DS_DRA_MAIL_PROBLEM                          , 8447      ) /* 0x000020ff */ \
    XXX( WERR_DS_DRA_REF_ALREADY_EXISTS                    , 8448      ) /* 0x00002100 */ \
    XXX( WERR_DS_DRA_REF_NOT_FOUND                         , 8449      ) /* 0x00002101 */ \
    XXX( WERR_DS_DRA_OBJ_IS_REP_SOURCE                     , 8450      ) /* 0x00002102 */ \
    XXX( WERR_DS_DRA_DB_ERROR                              , 8451      ) /* 0x00002103 */ \
    XXX( WERR_DS_DRA_NO_REPLICA                            , 8452      ) /* 0x00002104 */ \
    XXX( WERR_DS_DRA_ACCESS_DENIED                         , 8453      ) /* 0x00002105 */ \
    XXX( WERR_DS_DRA_NOT_SUPPORTED                         , 8454      ) /* 0x00002106 */ \
    XXX( WERR_DS_DRA_RPC_CANCELLED                         , 8455      ) /* 0x00002107 */ \
    XXX( WERR_DS_DRA_SOURCE_DISABLED                       , 8456      ) /* 0x00002108 */ \
    XXX( WERR_DS_DRA_SINK_DISABLED                         , 8457      ) /* 0x00002109 */ \
    XXX( WERR_DS_DRA_NAME_COLLISION                        , 8458      ) /* 0x0000210a */ \
    XXX( WERR_DS_DRA_SOURCE_REINSTALLED                    , 8459      ) /* 0x0000210b */ \
    XXX( WERR_DS_DRA_MISSING_PARENT                        , 8460      ) /* 0x0000210c */ \
    XXX( WERR_DS_DRA_PREEMPTED                             , 8461      ) /* 0x0000210d */ \
    XXX( WERR_DS_DRA_ABANDON_SYNC                          , 8462      ) /* 0x0000210e */ \
    XXX( WERR_DS_DRA_SHUTDOWN                              , 8463      ) /* 0x0000210f */ \
    XXX( WERR_DS_DRA_INCOMPATIBLE_PARTIAL_SET              , 8464      ) /* 0x00002110 */ \
    XXX( WERR_DS_DRA_SOURCE_IS_PARTIAL_REPLICA             , 8465      ) /* 0x00002111 */ \
    XXX( WERR_DS_DRA_EXTN_CONNECTION_FAILED                , 8466      ) /* 0x00002112 */ \
    XXX( WERR_DS_INSTALL_SCHEMA_MISMATCH                   , 8467      ) /* 0x00002113 */ \
    XXX( WERR_DS_DUP_LINK_ID                               , 8468      ) /* 0x00002114 */ \
    XXX( WERR_DS_NAME_ERROR_RESOLVING                      , 8469      ) /* 0x00002115 */ \
    XXX( WERR_DS_NAME_ERROR_NOT_FOUND                      , 8470      ) /* 0x00002116 */ \
    XXX( WERR_DS_NAME_ERROR_NOT_UNIQUE                     , 8471      ) /* 0x00002117 */ \
    XXX( WERR_DS_NAME_ERROR_NO_MAPPING                     , 8472      ) /* 0x00002118 */ \
    XXX( WERR_DS_NAME_ERROR_DOMAIN_ONLY                    , 8473      ) /* 0x00002119 */ \
    XXX( WERR_DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING         , 8474      ) /* 0x0000211a */ \
    XXX( WERR_DS_CONSTRUCTED_ATT_MOD                       , 8475      ) /* 0x0000211b */ \
    XXX( WERR_DS_WRONG_OM_OBJ_CLASS                        , 8476      ) /* 0x0000211c */ \
    XXX( WERR_DS_DRA_REPL_PENDING                          , 8477      ) /* 0x0000211d */ \
    XXX( WERR_DS_DS_REQUIRED                               , 8478      ) /* 0x0000211e */ \
    XXX( WERR_DS_INVALID_LDAP_DISPLAY_NAME                 , 8479      ) /* 0x0000211f */ \
    XXX( WERR_DS_NON_BASE_SEARCH                           , 8480      ) /* 0x00002120 */ \
    XXX( WERR_DS_CANT_RETRIEVE_ATTS                        , 8481      ) /* 0x00002121 */ \
    XXX( WERR_DS_BACKLINK_WITHOUT_LINK                     , 8482      ) /* 0x00002122 */ \
    XXX( WERR_DS_EPOCH_MISMATCH                            , 8483      ) /* 0x00002123 */ \
    XXX( WERR_DS_SRC_NAME_MISMATCH                         , 8484      ) /* 0x00002124 */ \
    XXX( WERR_DS_SRC_AND_DST_NC_IDENTICAL                  , 8485      ) /* 0x00002125 */ \
    XXX( WERR_DS_DST_NC_MISMATCH                           , 8486      ) /* 0x00002126 */ \
    XXX( WERR_DS_NOT_AUTHORITIVE_FOR_DST_NC                , 8487      ) /* 0x00002127 */ \
    XXX( WERR_DS_SRC_GUID_MISMATCH                         , 8488      ) /* 0x00002128 */ \
    XXX( WERR_DS_CANT_MOVE_DELETED_OBJECT                  , 8489      ) /* 0x00002129 */ \
    XXX( WERR_DS_PDC_OPERATION_IN_PROGRESS                 , 8490      ) /* 0x0000212a */ \
    XXX( WERR_DS_CROSS_DOMAIN_CLEANUP_REQD                 , 8491      ) /* 0x0000212b */ \
    XXX( WERR_DS_ILLEGAL_XDOM_MOVE_OPERATION               , 8492      ) /* 0x0000212c */ \
    XXX( WERR_DS_CANT_WITH_ACCT_GROUP_MEMBERSHPS           , 8493      ) /* 0x0000212d */ \
    XXX( WERR_DS_NC_MUST_HAVE_NC_PARENT                    , 8494      ) /* 0x0000212e */ \
    XXX( WERR_DS_CR_IMPOSSIBLE_TO_VALIDATE                 , 8495      ) /* 0x0000212f */ \
    XXX( WERR_DS_DST_DOMAIN_NOT_NATIVE                     , 8496      ) /* 0x00002130 */ \
    XXX( WERR_DS_MISSING_INFRASTRUCTURE_CONTAINER          , 8497      ) /* 0x00002131 */ \
    XXX( WERR_DS_CANT_MOVE_ACCOUNT_GROUP                   , 8498      ) /* 0x00002132 */ \
    XXX( WERR_DS_CANT_MOVE_RESOURCE_GROUP                  , 8499      ) /* 0x00002133 */ \
    XXX( WERR_DS_INVALID_SEARCH_FLAG                       , 8500      ) /* 0x00002134 */ \
    XXX( WERR_DS_NO_TREE_DELETE_ABOVE_NC                   , 8501      ) /* 0x00002135 */ \
    XXX( WERR_DS_COULDNT_LOCK_TREE_FOR_DELETE              , 8502      ) /* 0x00002136 */ \
    XXX( WERR_DS_COULDNT_IDENTIFY_OBJECTS_FOR_TREE_DELETE  , 8503      ) /* 0x00002137 */ \
    XXX( WERR_DS_SAM_INIT_FAILURE                          , 8504      ) /* 0x00002138 */ \
    XXX( WERR_DS_SENSITIVE_GROUP_VIOLATION                 , 8505      ) /* 0x00002139 */ \
    XXX( WERR_DS_CANT_MOD_PRIMARYGROUPID                   , 8506      ) /* 0x0000213a */ \
    XXX( WERR_DS_ILLEGAL_BASE_SCHEMA_MOD                   , 8507      ) /* 0x0000213b */ \
    XXX( WERR_DS_NONSAFE_SCHEMA_CHANGE                     , 8508      ) /* 0x0000213c */ \
    XXX( WERR_DS_SCHEMA_UPDATE_DISALLOWED                  , 8509      ) /* 0x0000213d */ \
    XXX( WERR_DS_CANT_CREATE_UNDER_SCHEMA                  , 8510      ) /* 0x0000213e */ \
    XXX( WERR_DS_INVALID_GROUP_TYPE                        , 8513      ) /* 0x00002141 */ \
    XXX( WERR_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN        , 8514      ) /* 0x00002142 */ \
    XXX( WERR_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN         , 8515      ) /* 0x00002143 */ \
    XXX( WERR_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER             , 8516      ) /* 0x00002144 */ \
    XXX( WERR_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER         , 8517      ) /* 0x00002145 */ \
    XXX( WERR_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER          , 8518      ) /* 0x00002146 */ \
    XXX( WERR_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER       , 8519      ) /* 0x00002147 */ \
    XXX( WERR_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER  , 8520      ) /* 0x00002148 */ \
    XXX( WERR_DS_HAVE_PRIMARY_MEMBERS                      , 8521      ) /* 0x00002149 */ \
    XXX( WERR_DS_STRING_SD_CONVERSION_FAILED               , 8522      ) /* 0x0000214a */ \
    XXX( WERR_DS_NAMING_MASTER_GC                          , 8523      ) /* 0x0000214b */ \
    XXX( WERR_DS_DNS_LOOKUP_FAILURE                        , 8524      ) /* 0x0000214c */ \
    XXX( WERR_DS_COULDNT_UPDATE_SPNS                       , 8525      ) /* 0x0000214d */ \
    XXX( WERR_DS_CANT_RETRIEVE_SD                          , 8526      ) /* 0x0000214e */ \
    XXX( WERR_DS_KEY_NOT_UNIQUE                            , 8527      ) /* 0x0000214f */ \
    XXX( WERR_DS_WRONG_LINKED_ATT_SYNTAX                   , 8528      ) /* 0x00002150 */ \
    XXX( WERR_DS_SAM_NEED_BOOTKEY_PASSWORD                 , 8529      ) /* 0x00002151 */ \
    XXX( WERR_DS_SAM_NEED_BOOTKEY_FLOPPY                   , 8530      ) /* 0x00002152 */ \
    XXX( WERR_DS_CANT_START                                , 8531      ) /* 0x00002153 */ \
    XXX( WERR_DS_INIT_FAILURE                              , 8532      ) /* 0x00002154 */ \
    XXX( WERR_DS_NO_PKT_PRIVACY_ON_CONNECTION              , 8533      ) /* 0x00002155 */ \
    XXX( WERR_DS_SOURCE_DOMAIN_IN_FOREST                   , 8534      ) /* 0x00002156 */ \
    XXX( WERR_DS_DESTINATION_DOMAIN_NOT_IN_FOREST          , 8535      ) /* 0x00002157 */ \
    XXX( WERR_DS_DESTINATION_AUDITING_NOT_ENABLED          , 8536      ) /* 0x00002158 */ \
    XXX( WERR_DS_CANT_FIND_DC_FOR_SRC_DOMAIN               , 8537      ) /* 0x00002159 */ \
    XXX( WERR_DS_SRC_OBJ_NOT_GROUP_OR_USER                 , 8538      ) /* 0x0000215a */ \
    XXX( WERR_DS_SRC_SID_EXISTS_IN_FOREST                  , 8539      ) /* 0x0000215b */ \
    XXX( WERR_DS_SRC_AND_DST_OBJECT_CLASS_MISMATCH         , 8540      ) /* 0x0000215c */ \
    XXX( WERR_SAM_INIT_FAILURE                             , 8541      ) /* 0x0000215d */ \
    XXX( WERR_DS_DRA_SCHEMA_INFO_SHIP                      , 8542      ) /* 0x0000215e */ \
    XXX( WERR_DS_DRA_SCHEMA_CONFLICT                       , 8543      ) /* 0x0000215f */ \
    XXX( WERR_DS_DRA_EARLIER_SCHEMA_CONFLICT               , 8544      ) /* 0x00002160 */ \
    XXX( WERR_DS_DRA_OBJ_NC_MISMATCH                       , 8545      ) /* 0x00002161 */ \
    XXX( WERR_DS_NC_STILL_HAS_DSAS                         , 8546      ) /* 0x00002162 */ \
    XXX( WERR_DS_GC_REQUIRED                               , 8547      ) /* 0x00002163 */ \
    XXX( WERR_DS_LOCAL_MEMBER_OF_LOCAL_ONLY                , 8548      ) /* 0x00002164 */ \
    XXX( WERR_DS_NO_FPO_IN_UNIVERSAL_GROUPS                , 8549      ) /* 0x00002165 */ \
    XXX( WERR_DS_CANT_ADD_TO_GC                            , 8550      ) /* 0x00002166 */ \
    XXX( WERR_DS_NO_CHECKPOINT_WITH_PDC                    , 8551      ) /* 0x00002167 */ \
    XXX( WERR_DS_SOURCE_AUDITING_NOT_ENABLED               , 8552      ) /* 0x00002168 */ \
    XXX( WERR_DS_CANT_CREATE_IN_NONDOMAIN_NC               , 8553      ) /* 0x00002169 */ \
    XXX( WERR_DS_INVALID_NAME_FOR_SPN                      , 8554      ) /* 0x0000216a */ \
    XXX( WERR_DS_FILTER_USES_CONTRUCTED_ATTRS              , 8555      ) /* 0x0000216b */ \
    XXX( WERR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED            , 8557      ) /* 0x0000216d */ \
    XXX( WERR_DS_MUST_BE_RUN_ON_DST_DC                     , 8558      ) /* 0x0000216e */ \
    XXX( WERR_DS_SRC_DC_MUST_BE_SP4_OR_GREATER             , 8559      ) /* 0x0000216f */ \
    XXX( WERR_DS_CANT_TREE_DELETE_CRITICAL_OBJ             , 8560      ) /* 0x00002170 */ \
    XXX( WERR_DS_INIT_FAILURE_CONSOLE                      , 8561      ) /* 0x00002171 */ \
    XXX( WERR_DS_SAM_INIT_FAILURE_CONSOLE                  , 8562      ) /* 0x00002172 */ \
    XXX( WERR_DS_FOREST_VERSION_TOO_HIGH                   , 8563      ) /* 0x00002173 */ \
    XXX( WERR_DS_DOMAIN_VERSION_TOO_HIGH                   , 8564      ) /* 0x00002174 */ \
    XXX( WERR_DS_FOREST_VERSION_TOO_LOW                    , 8565      ) /* 0x00002175 */ \
    XXX( WERR_DS_DOMAIN_VERSION_TOO_LOW                    , 8566      ) /* 0x00002176 */ \
    XXX( WERR_DS_INCOMPATIBLE_VERSION                      , 8567      ) /* 0x00002177 */ \
    XXX( WERR_DS_LOW_DSA_VERSION                           , 8568      ) /* 0x00002178 */ \
    XXX( WERR_DS_NO_BEHAVIOR_VERSION_IN_MIXEDDOMAIN        , 8569      ) /* 0x00002179 */ \
    XXX( WERR_DS_NOT_SUPPORTED_SORT_ORDER                  , 8570      ) /* 0x0000217a */ \
    XXX( WERR_DS_NAME_NOT_UNIQUE                           , 8571      ) /* 0x0000217b */ \
    XXX( WERR_DS_MACHINE_ACCOUNT_CREATED_PRENT4            , 8572      ) /* 0x0000217c */ \
    XXX( WERR_DS_OUT_OF_VERSION_STORE                      , 8573      ) /* 0x0000217d */ \
    XXX( WERR_DS_INCOMPATIBLE_CONTROLS_USED                , 8574      ) /* 0x0000217e */ \
    XXX( WERR_DS_NO_REF_DOMAIN                             , 8575      ) /* 0x0000217f */ \
    XXX( WERR_DS_RESERVED_LINK_ID                          , 8576      ) /* 0x00002180 */ \
    XXX( WERR_DS_LINK_ID_NOT_AVAILABLE                     , 8577      ) /* 0x00002181 */ \
    XXX( WERR_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER             , 8578      ) /* 0x00002182 */ \
    XXX( WERR_DS_MODIFYDN_DISALLOWED_BY_INSTANCE_TYPE      , 8579      ) /* 0x00002183 */ \
    XXX( WERR_DS_NO_OBJECT_MOVE_IN_SCHEMA_NC               , 8580      ) /* 0x00002184 */ \
    XXX( WERR_DS_MODIFYDN_DISALLOWED_BY_FLAG               , 8581      ) /* 0x00002185 */ \
    XXX( WERR_DS_MODIFYDN_WRONG_GRANDPARENT                , 8582      ) /* 0x00002186 */ \
    XXX( WERR_DS_NAME_ERROR_TRUST_REFERRAL                 , 8583      ) /* 0x00002187 */ \
    XXX( WERR_NOT_SUPPORTED_ON_STANDARD_SERVER             , 8584      ) /* 0x00002188 */ \
    XXX( WERR_DS_CANT_ACCESS_REMOTE_PART_OF_AD             , 8585      ) /* 0x00002189 */ \
    XXX( WERR_DS_CR_IMPOSSIBLE_TO_VALIDATE_V2              , 8586      ) /* 0x0000218a */ \
    XXX( WERR_DS_THREAD_LIMIT_EXCEEDED                     , 8587      ) /* 0x0000218b */ \
    XXX( WERR_DS_NOT_CLOSEST                               , 8588      ) /* 0x0000218c */ \
    XXX( WERR_DS_SINGLE_USER_MODE_FAILED                   , 8590      ) /* 0x0000218e */ \
    XXX( WERR_DS_NTDSCRIPT_SYNTAX_ERROR                    , 8591      ) /* 0x0000218f */ \
    XXX( WERR_DS_NTDSCRIPT_PROCESS_ERROR                   , 8592      ) /* 0x00002190 */ \
    XXX( WERR_DS_DIFFERENT_REPL_EPOCHS                     , 8593      ) /* 0x00002191 */ \
    XXX( WERR_DS_DRS_EXTENSIONS_CHANGED                    , 8594      ) /* 0x00002192 */ \
    XXX( WERR_DS_REPLICA_SET_CHANGE_NOT_ALLOWED_ON_DISABLED_CR, 8595      ) /* 0x00002193 */ \
    XXX( WERR_DS_NO_MSDS_INTID                             , 8596      ) /* 0x00002194 */ \
    XXX( WERR_DS_DUP_MSDS_INTID                            , 8597      ) /* 0x00002195 */ \
    XXX( WERR_DS_EXISTS_IN_RDNATTID                        , 8598      ) /* 0x00002196 */ \
    XXX( WERR_DS_AUTHORIZATION_FAILED                      , 8599      ) /* 0x00002197 */ \
    XXX( WERR_DS_INVALID_SCRIPT                            , 8600      ) /* 0x00002198 */ \
    XXX( WERR_DS_REMOTE_CROSSREF_OP_FAILED                 , 8601      ) /* 0x00002199 */ \
    XXX( WERR_DS_CROSS_REF_BUSY                            , 8602      ) /* 0x0000219a */ \
    XXX( WERR_DS_CANT_DERIVE_SPN_FOR_DELETED_DOMAIN        , 8603      ) /* 0x0000219b */ \
    XXX( WERR_DS_CANT_DEMOTE_WITH_WRITEABLE_NC             , 8604      ) /* 0x0000219c */ \
    XXX( WERR_DS_DUPLICATE_ID_FOUND                        , 8605      ) /* 0x0000219d */ \
    XXX( WERR_DS_INSUFFICIENT_ATTR_TO_CREATE_OBJECT        , 8606      ) /* 0x0000219e */ \
    XXX( WERR_DS_GROUP_CONVERSION_ERROR                    , 8607      ) /* 0x0000219f */ \
    XXX( WERR_DS_CANT_MOVE_APP_BASIC_GROUP                 , 8608      ) /* 0x000021a0 */ \
    XXX( WERR_DS_CANT_MOVE_APP_QUERY_GROUP                 , 8609      ) /* 0x000021a1 */ \
    XXX( WERR_DS_ROLE_NOT_VERIFIED                         , 8610      ) /* 0x000021a2 */ \
    XXX( WERR_DS_WKO_CONTAINER_CANNOT_BE_SPECIAL           , 8611      ) /* 0x000021a3 */ \
    XXX( WERR_DS_DOMAIN_RENAME_IN_PROGRESS                 , 8612      ) /* 0x000021a4 */ \
    XXX( WERR_DS_EXISTING_AD_CHILD_NC                      , 8613      ) /* 0x000021a5 */ \
    XXX( WERR_DS_REPL_LIFETIME_EXCEEDED                    , 8614      ) /* 0x000021a6 */ \
    XXX( WERR_DS_DISALLOWED_IN_SYSTEM_CONTAINER            , 8615      ) /* 0x000021a7 */ \
    XXX( WERR_DS_LDAP_SEND_QUEUE_FULL                      , 8616      ) /* 0x000021a8 */ \
    XXX( WERR_DS_DRA_OUT_SCHEDULE_WINDOW                   , 8617      ) /* 0x000021a9 */ \
    XXX( WERR_DS_POLICY_NOT_KNOWN                          , 8618      ) /* 0x000021aa */ \
    XXX( WERR_NO_SITE_SETTINGS_OBJECT                      , 8619      ) /* 0x000021ab */ \
    XXX( WERR_NO_SECRETS                                   , 8620      ) /* 0x000021ac */ \
    XXX( WERR_NO_WRITABLE_DC_FOUND                         , 8621      ) /* 0x000021ad */ \
    XXX( WERR_DS_NO_SERVER_OBJECT                          , 8622      ) /* 0x000021ae */ \
    XXX( WERR_DS_NO_NTDSA_OBJECT                           , 8623      ) /* 0x000021af */ \
    XXX( WERR_DS_NON_ASQ_SEARCH                            , 8624      ) /* 0x000021b0 */ \
    XXX( WERR_DS_AUDIT_FAILURE                             , 8625      ) /* 0x000021b1 */ \
    XXX( WERR_DS_INVALID_SEARCH_FLAG_SUBTREE               , 8626      ) /* 0x000021b2 */ \
    XXX( WERR_DS_INVALID_SEARCH_FLAG_TUPLE                 , 8627      ) /* 0x000021b3 */ \
    XXX( WERR_DS_HIGH_DSA_VERSION                          , 8642      ) /* 0x000021c2 */ \
    XXX( WERR_DS_SPN_VALUE_NOT_UNIQUE_IN_FOREST            , 8647      ) /* 0x000021c7 */ \
    XXX( WERR_DS_UPN_VALUE_NOT_UNIQUE_IN_FOREST            , 8648      ) /* 0x000021c8 */ \
    XXX( WERR_DNS_ERROR_RCODE_FORMAT_ERROR                 , 9001      ) /* 0x00002329 */ \
    XXX( WERR_DNS_ERROR_RCODE_SERVER_FAILURE               , 9002      ) /* 0x0000232a */ \
    XXX( WERR_DNS_ERROR_RCODE_NAME_ERROR                   , 9003      ) /* 0x0000232b */ \
    XXX( WERR_DNS_ERROR_RCODE_NOT_IMPLEMENTED              , 9004      ) /* 0x0000232c */ \
    XXX( WERR_DNS_ERROR_RCODE_REFUSED                      , 9005      ) /* 0x0000232d */ \
    XXX( WERR_DNS_ERROR_RCODE_YXDOMAIN                     , 9006      ) /* 0x0000232e */ \
    XXX( WERR_DNS_ERROR_RCODE_YXRRSET                      , 9007      ) /* 0x0000232f */ \
    XXX( WERR_DNS_ERROR_RCODE_NXRRSET                      , 9008      ) /* 0x00002330 */ \
    XXX( WERR_DNS_ERROR_RCODE_NOTAUTH                      , 9009      ) /* 0x00002331 */ \
    XXX( WERR_DNS_ERROR_RCODE_NOTZONE                      , 9010      ) /* 0x00002332 */ \
    XXX( WERR_DNS_ERROR_RCODE_BADSIG                       , 9016      ) /* 0x00002338 */ \
    XXX( WERR_DNS_ERROR_RCODE_BADKEY                       , 9017      ) /* 0x00002339 */ \
    XXX( WERR_DNS_ERROR_RCODE_BADTIME                      , 9018      ) /* 0x0000233a */ \
    XXX( WERR_DNS_ERROR_KEYMASTER_REQUIRED                 , 9101      ) /* 0x0000238d */ \
    XXX( WERR_DNS_ERROR_NOT_ALLOWED_ON_SIGNED_ZONE         , 9102      ) /* 0x0000238e */ \
    XXX( WERR_DNS_ERROR_INVALID_NSEC3_PARAMETERS           , 9103      ) /* 0x0000238f */ \
    XXX( WERR_DNS_ERROR_NOT_ENOUGH_SIGNING_KEY_DESCRIPTORS , 9104      ) /* 0x00002390 */ \
    XXX( WERR_DNS_ERROR_UNSUPPORTED_ALGORITHM              , 9105      ) /* 0x00002391 */ \
    XXX( WERR_DNS_ERROR_INVALID_KEY_SIZE                   , 9106      ) /* 0x00002392 */ \
    XXX( WERR_DNS_ERROR_SIGNING_KEY_NOT_ACCESSIBLE         , 9107      ) /* 0x00002393 */ \
    XXX( WERR_DNS_ERROR_KSP_DOES_NOT_SUPPORT_PROTECTION    , 9108      ) /* 0x00002394 */ \
    XXX( WERR_DNS_ERROR_UNEXPECTED_DATA_PROTECTION_ERROR   , 9109      ) /* 0x00002395 */ \
    XXX( WERR_DNS_ERROR_UNEXPECTED_CNG_ERROR               , 9110      ) /* 0x00002396 */ \
    XXX( WERR_DNS_ERROR_UNKNOWN_SIGNING_PARAMETER_VERSION  , 9111      ) /* 0x00002397 */ \
    XXX( WERR_DNS_ERROR_KSP_NOT_ACCESSIBLE                 , 9112      ) /* 0x00002398 */ \
    XXX( WERR_DNS_ERROR_TOO_MANY_SKDS                      , 9113      ) /* 0x00002399 */ \
    XXX( WERR_DNS_ERROR_INVALID_ROLLOVER_PERIOD            , 9114      ) /* 0x0000239a */ \
    XXX( WERR_DNS_ERROR_INVALID_INITIAL_ROLLOVER_OFFSET    , 9115      ) /* 0x0000239b */ \
    XXX( WERR_DNS_ERROR_ROLLOVER_IN_PROGRESS               , 9116      ) /* 0x0000239c */ \
    XXX( WERR_DNS_ERROR_STANDBY_KEY_NOT_PRESENT            , 9117      ) /* 0x0000239d */ \
    XXX( WERR_DNS_ERROR_NOT_ALLOWED_ON_ZSK                 , 9118      ) /* 0x0000239e */ \
    XXX( WERR_DNS_ERROR_NOT_ALLOWED_ON_ACTIVE_SKD          , 9119      ) /* 0x0000239f */ \
    XXX( WERR_DNS_ERROR_ROLLOVER_ALREADY_QUEUED            , 9120      ) /* 0x000023a0 */ \
    XXX( WERR_DNS_ERROR_NOT_ALLOWED_ON_UNSIGNED_ZONE       , 9121      ) /* 0x000023a1 */ \
    XXX( WERR_DNS_ERROR_BAD_KEYMASTER                      , 9122      ) /* 0x000023a2 */ \
    XXX( WERR_DNS_ERROR_INVALID_SIGNATURE_VALIDITY_PERIOD  , 9123      ) /* 0x000023a3 */ \
    XXX( WERR_DNS_ERROR_INVALID_NSEC3_ITERATION_COUNT      , 9124      ) /* 0x000023a4 */ \
    XXX( WERR_DNS_ERROR_DNSSEC_IS_DISABLED                 , 9125      ) /* 0x000023a5 */ \
    XXX( WERR_DNS_ERROR_INVALID_XML                        , 9126      ) /* 0x000023a6 */ \
    XXX( WERR_DNS_ERROR_NO_VALID_TRUST_ANCHORS             , 9127      ) /* 0x000023a7 */ \
    XXX( WERR_DNS_ERROR_ROLLOVER_NOT_POKEABLE              , 9128      ) /* 0x000023a8 */ \
    XXX( WERR_DNS_ERROR_NSEC3_NAME_COLLISION               , 9129      ) /* 0x000023a9 */ \
    XXX( WERR_DNS_INFO_NO_RECORDS                          , 9501      ) /* 0x0000251d */ \
    XXX( WERR_DNS_ERROR_BAD_PACKET                         , 9502      ) /* 0x0000251e */ \
    XXX( WERR_DNS_ERROR_NO_PACKET                          , 9503      ) /* 0x0000251f */ \
    XXX( WERR_DNS_ERROR_RCODE                              , 9504      ) /* 0x00002520 */ \
    XXX( WERR_DNS_ERROR_UNSECURE_PACKET                    , 9505      ) /* 0x00002521 */ \
    XXX( WERR_DNS_REQUEST_PENDING                          , 9506      ) /* 0x00002522 */ \
    XXX( WERR_DNS_ERROR_INVALID_TYPE                       , 9551      ) /* 0x0000254f */ \
    XXX( WERR_DNS_ERROR_INVALID_IP_ADDRESS                 , 9552      ) /* 0x00002550 */ \
    XXX( WERR_DNS_ERROR_INVALID_PROPERTY                   , 9553      ) /* 0x00002551 */ \
    XXX( WERR_DNS_ERROR_TRY_AGAIN_LATER                    , 9554      ) /* 0x00002552 */ \
    XXX( WERR_DNS_ERROR_NOT_UNIQUE                         , 9555      ) /* 0x00002553 */ \
    XXX( WERR_DNS_ERROR_NON_RFC_NAME                       , 9556      ) /* 0x00002554 */ \
    XXX( WERR_DNS_STATUS_FQDN                              , 9557      ) /* 0x00002555 */ \
    XXX( WERR_DNS_STATUS_DOTTED_NAME                       , 9558      ) /* 0x00002556 */ \
    XXX( WERR_DNS_STATUS_SINGLE_PART_NAME                  , 9559      ) /* 0x00002557 */ \
    XXX( WERR_DNS_ERROR_INVALID_NAME_CHAR                  , 9560      ) /* 0x00002558 */ \
    XXX( WERR_DNS_ERROR_NUMERIC_NAME                       , 9561      ) /* 0x00002559 */ \
    XXX( WERR_DNS_ERROR_NOT_ALLOWED_ON_ROOT_SERVER         , 9562      ) /* 0x0000255a */ \
    XXX( WERR_DNS_ERROR_NOT_ALLOWED_UNDER_DELEGATION       , 9563      ) /* 0x0000255b */ \
    XXX( WERR_DNS_ERROR_CANNOT_FIND_ROOT_HINTS             , 9564      ) /* 0x0000255c */ \
    XXX( WERR_DNS_ERROR_INCONSISTENT_ROOT_HINTS            , 9565      ) /* 0x0000255d */ \
    XXX( WERR_DNS_ERROR_DWORD_VALUE_TOO_SMALL              , 9566      ) /* 0x0000255e */ \
    XXX( WERR_DNS_ERROR_DWORD_VALUE_TOO_LARGE              , 9567      ) /* 0x0000255f */ \
    XXX( WERR_DNS_ERROR_BACKGROUND_LOADING                 , 9568      ) /* 0x00002560 */ \
    XXX( WERR_DNS_ERROR_NOT_ALLOWED_ON_RODC                , 9569      ) /* 0x00002561 */ \
    XXX( WERR_DNS_ERROR_NOT_ALLOWED_UNDER_DNAME            , 9570      ) /* 0x00002562 */ \
    XXX( WERR_DNS_ERROR_DELEGATION_REQUIRED                , 9571      ) /* 0x00002563 */ \
    XXX( WERR_DNS_ERROR_INVALID_POLICY_TABLE               , 9572      ) /* 0x00002564 */ \
    XXX( WERR_DNS_ERROR_ZONE_DOES_NOT_EXIST                , 9601      ) /* 0x00002581 */ \
    XXX( WERR_DNS_ERROR_NO_ZONE_INFO                       , 9602      ) /* 0x00002582 */ \
    XXX( WERR_DNS_ERROR_INVALID_ZONE_OPERATION             , 9603      ) /* 0x00002583 */ \
    XXX( WERR_DNS_ERROR_ZONE_CONFIGURATION_ERROR           , 9604      ) /* 0x00002584 */ \
    XXX( WERR_DNS_ERROR_ZONE_HAS_NO_SOA_RECORD             , 9605      ) /* 0x00002585 */ \
    XXX( WERR_DNS_ERROR_ZONE_HAS_NO_NS_RECORDS             , 9606      ) /* 0x00002586 */ \
    XXX( WERR_DNS_ERROR_ZONE_LOCKED                        , 9607      ) /* 0x00002587 */ \
    XXX( WERR_DNS_ERROR_ZONE_CREATION_FAILED               , 9608      ) /* 0x00002588 */ \
    XXX( WERR_DNS_ERROR_ZONE_ALREADY_EXISTS                , 9609      ) /* 0x00002589 */ \
    XXX( WERR_DNS_ERROR_AUTOZONE_ALREADY_EXISTS            , 9610      ) /* 0x0000258a */ \
    XXX( WERR_DNS_ERROR_INVALID_ZONE_TYPE                  , 9611      ) /* 0x0000258b */ \
    XXX( WERR_DNS_ERROR_SECONDARY_REQUIRES_MASTER_IP       , 9612      ) /* 0x0000258c */ \
    XXX( WERR_DNS_ERROR_ZONE_NOT_SECONDARY                 , 9613      ) /* 0x0000258d */ \
    XXX( WERR_DNS_ERROR_NEED_SECONDARY_ADDRESSES           , 9614      ) /* 0x0000258e */ \
    XXX( WERR_DNS_ERROR_WINS_INIT_FAILED                   , 9615      ) /* 0x0000258f */ \
    XXX( WERR_DNS_ERROR_NEED_WINS_SERVERS                  , 9616      ) /* 0x00002590 */ \
    XXX( WERR_DNS_ERROR_NBSTAT_INIT_FAILED                 , 9617      ) /* 0x00002591 */ \
    XXX( WERR_DNS_ERROR_SOA_DELETE_INVALID                 , 9618      ) /* 0x00002592 */ \
    XXX( WERR_DNS_ERROR_FORWARDER_ALREADY_EXISTS           , 9619      ) /* 0x00002593 */ \
    XXX( WERR_DNS_ERROR_ZONE_REQUIRES_MASTER_IP            , 9620      ) /* 0x00002594 */ \
    XXX( WERR_DNS_ERROR_ZONE_IS_SHUTDOWN                   , 9621      ) /* 0x00002595 */ \
    XXX( WERR_DNS_ERROR_PRIMARY_REQUIRES_DATAFILE          , 9651      ) /* 0x000025b3 */ \
    XXX( WERR_DNS_ERROR_INVALID_DATAFILE_NAME              , 9652      ) /* 0x000025b4 */ \
    XXX( WERR_DNS_ERROR_DATAFILE_OPEN_FAILURE              , 9653      ) /* 0x000025b5 */ \
    XXX( WERR_DNS_ERROR_FILE_WRITEBACK_FAILED              , 9654      ) /* 0x000025b6 */ \
    XXX( WERR_DNS_ERROR_DATAFILE_PARSING                   , 9655      ) /* 0x000025b7 */ \
    XXX( WERR_DNS_ERROR_RECORD_DOES_NOT_EXIST              , 9701      ) /* 0x000025e5 */ \
    XXX( WERR_DNS_ERROR_RECORD_FORMAT                      , 9702      ) /* 0x000025e6 */ \
    XXX( WERR_DNS_ERROR_NODE_CREATION_FAILED               , 9703      ) /* 0x000025e7 */ \
    XXX( WERR_DNS_ERROR_UNKNOWN_RECORD_TYPE                , 9704      ) /* 0x000025e8 */ \
    XXX( WERR_DNS_ERROR_RECORD_TIMED_OUT                   , 9705      ) /* 0x000025e9 */ \
    XXX( WERR_DNS_ERROR_NAME_NOT_IN_ZONE                   , 9706      ) /* 0x000025ea */ \
    XXX( WERR_DNS_ERROR_CNAME_LOOP                         , 9707      ) /* 0x000025eb */ \
    XXX( WERR_DNS_ERROR_NODE_IS_CNAME                      , 9708      ) /* 0x000025ec */ \
    XXX( WERR_DNS_ERROR_CNAME_COLLISION                    , 9709      ) /* 0x000025ed */ \
    XXX( WERR_DNS_ERROR_RECORD_ONLY_AT_ZONE_ROOT           , 9710      ) /* 0x000025ee */ \
    XXX( WERR_DNS_ERROR_RECORD_ALREADY_EXISTS              , 9711      ) /* 0x000025ef */ \
    XXX( WERR_DNS_ERROR_SECONDARY_DATA                     , 9712      ) /* 0x000025f0 */ \
    XXX( WERR_DNS_ERROR_NO_CREATE_CACHE_DATA               , 9713      ) /* 0x000025f1 */ \
    XXX( WERR_DNS_ERROR_NAME_DOES_NOT_EXIST                , 9714      ) /* 0x000025f2 */ \
    XXX( WERR_DNS_WARNING_PTR_CREATE_FAILED                , 9715      ) /* 0x000025f3 */ \
    XXX( WERR_DNS_WARNING_DOMAIN_UNDELETED                 , 9716      ) /* 0x000025f4 */ \
    XXX( WERR_DNS_ERROR_DS_UNAVAILABLE                     , 9717      ) /* 0x000025f5 */ \
    XXX( WERR_DNS_ERROR_DS_ZONE_ALREADY_EXISTS             , 9718      ) /* 0x000025f6 */ \
    XXX( WERR_DNS_ERROR_NO_BOOTFILE_IF_DS_ZONE             , 9719      ) /* 0x000025f7 */ \
    XXX( WERR_DNS_ERROR_NODE_IS_DNMAE                      , 9720      ) /* 0x000025f8 */ \
    XXX( WERR_DNS_ERROR_DNAME_COLLISION                    , 9721      ) /* 0x000025f9 */ \
    XXX( WERR_DNS_ERROR_ALIAS_LOOP                         , 9722      ) /* 0x000025fa */ \
    XXX( WERR_DNS_INFO_AXFR_COMPLETE                       , 9751      ) /* 0x00002617 */ \
    XXX( WERR_DNS_ERROR_AXFR                               , 9752      ) /* 0x00002618 */ \
    XXX( WERR_DNS_INFO_ADDED_LOCAL_WINS                    , 9753      ) /* 0x00002619 */ \
    XXX( WERR_DNS_STATUS_CONTINUE_NEEDED                   , 9801      ) /* 0x00002649 */ \
    XXX( WERR_DNS_ERROR_NO_TCPIP                           , 9851      ) /* 0x0000267b */ \
    XXX( WERR_DNS_ERROR_NO_DNS_SERVERS                     , 9852      ) /* 0x0000267c */ \
    XXX( WERR_DNS_ERROR_DP_DOES_NOT_EXIST                  , 9901      ) /* 0x000026ad */ \
    XXX( WERR_DNS_ERROR_DP_ALREADY_EXISTS                  , 9902      ) /* 0x000026ae */ \
    XXX( WERR_DNS_ERROR_DP_NOT_ENLISTED                    , 9903      ) /* 0x000026af */ \
    XXX( WERR_DNS_ERROR_DP_ALREADY_ENLISTED                , 9904      ) /* 0x000026b0 */ \
    XXX( WERR_DNS_ERROR_DP_NOT_AVAILABLE                   , 9905      ) /* 0x000026b1 */ \
    XXX( WERR_DNS_ERROR_DP_FSMO_ERROR                      , 9906      ) /* 0x000026b2 */ \
    XXX( WERR_IPSEC_QM_POLICY_EXISTS                       , 13000     ) /* 0x000032c8 */ \
    XXX( WERR_IPSEC_QM_POLICY_NOT_FOUND                    , 13001     ) /* 0x000032c9 */ \
    XXX( WERR_IPSEC_QM_POLICY_IN_USE                       , 13002     ) /* 0x000032ca */ \
    XXX( WERR_IPSEC_MM_POLICY_EXISTS                       , 13003     ) /* 0x000032cb */ \
    XXX( WERR_IPSEC_MM_POLICY_NOT_FOUND                    , 13004     ) /* 0x000032cc */ \
    XXX( WERR_IPSEC_MM_POLICY_IN_USE                       , 13005     ) /* 0x000032cd */ \
    XXX( WERR_IPSEC_MM_FILTER_EXISTS                       , 13006     ) /* 0x000032ce */ \
    XXX( WERR_IPSEC_MM_FILTER_NOT_FOUND                    , 13007     ) /* 0x000032cf */ \
    XXX( WERR_IPSEC_TRANSPORT_FILTER_EXISTS                , 13008     ) /* 0x000032d0 */ \
    XXX( WERR_IPSEC_TRANSPORT_FILTER_NOT_FOUND             , 13009     ) /* 0x000032d1 */ \
    XXX( WERR_IPSEC_MM_AUTH_EXISTS                         , 13010     ) /* 0x000032d2 */ \
    XXX( WERR_IPSEC_MM_AUTH_NOT_FOUND                      , 13011     ) /* 0x000032d3 */ \
    XXX( WERR_IPSEC_MM_AUTH_IN_USE                         , 13012     ) /* 0x000032d4 */ \
    XXX( WERR_IPSEC_DEFAULT_MM_POLICY_NOT_FOUND            , 13013     ) /* 0x000032d5 */ \
    XXX( WERR_IPSEC_DEFAULT_MM_AUTH_NOT_FOUND              , 13014     ) /* 0x000032d6 */ \
    XXX( WERR_IPSEC_DEFAULT_QM_POLICY_NOT_FOUND            , 13015     ) /* 0x000032d7 */ \
    XXX( WERR_IPSEC_TUNNEL_FILTER_EXISTS                   , 13016     ) /* 0x000032d8 */ \
    XXX( WERR_IPSEC_TUNNEL_FILTER_NOT_FOUND                , 13017     ) /* 0x000032d9 */ \
    XXX( WERR_IPSEC_MM_FILTER_PENDING_DELETION             , 13018     ) /* 0x000032da */ \
    XXX( WERR_IPSEC_TRANSPORT_FILTER_ENDING_DELETION       , 13019     ) /* 0x000032db */ \
    XXX( WERR_IPSEC_TUNNEL_FILTER_PENDING_DELETION         , 13020     ) /* 0x000032dc */ \
    XXX( WERR_IPSEC_MM_POLICY_PENDING_ELETION              , 13021     ) /* 0x000032dd */ \
    XXX( WERR_IPSEC_MM_AUTH_PENDING_DELETION               , 13022     ) /* 0x000032de */ \
    XXX( WERR_IPSEC_QM_POLICY_PENDING_DELETION             , 13023     ) /* 0x000032df */ \
    XXX( WERR_IPSEC_IKE_NEG_STATUS_BEGIN                   , 13800     ) /* 0x000035e8 */ \
    XXX( WERR_IPSEC_IKE_AUTH_FAIL                          , 13801     ) /* 0x000035e9 */ \
    XXX( WERR_IPSEC_IKE_ATTRIB_FAIL                        , 13802     ) /* 0x000035ea */ \
    XXX( WERR_IPSEC_IKE_NEGOTIATION_PENDING                , 13803     ) /* 0x000035eb */ \
    XXX( WERR_IPSEC_IKE_GENERAL_PROCESSING_ERROR           , 13804     ) /* 0x000035ec */ \
    XXX( WERR_IPSEC_IKE_TIMED_OUT                          , 13805     ) /* 0x000035ed */ \
    XXX( WERR_IPSEC_IKE_NO_CERT                            , 13806     ) /* 0x000035ee */ \
    XXX( WERR_IPSEC_IKE_SA_DELETED                         , 13807     ) /* 0x000035ef */ \
    XXX( WERR_IPSEC_IKE_SA_REAPED                          , 13808     ) /* 0x000035f0 */ \
    XXX( WERR_IPSEC_IKE_MM_ACQUIRE_DROP                    , 13809     ) /* 0x000035f1 */ \
    XXX( WERR_IPSEC_IKE_QM_ACQUIRE_DROP                    , 13810     ) /* 0x000035f2 */ \
    XXX( WERR_IPSEC_IKE_QUEUE_DROP_MM                      , 13811     ) /* 0x000035f3 */ \
    XXX( WERR_IPSEC_IKE_QUEUE_DROP_NO_MM                   , 13812     ) /* 0x000035f4 */ \
    XXX( WERR_IPSEC_IKE_DROP_NO_RESPONSE                   , 13813     ) /* 0x000035f5 */ \
    XXX( WERR_IPSEC_IKE_MM_DELAY_DROP                      , 13814     ) /* 0x000035f6 */ \
    XXX( WERR_IPSEC_IKE_QM_DELAY_DROP                      , 13815     ) /* 0x000035f7 */ \
    XXX( WERR_IPSEC_IKE_ERROR                              , 13816     ) /* 0x000035f8 */ \
    XXX( WERR_IPSEC_IKE_CRL_FAILED                         , 13817     ) /* 0x000035f9 */ \
    XXX( WERR_IPSEC_IKE_INVALID_KEY_USAGE                  , 13818     ) /* 0x000035fa */ \
    XXX( WERR_IPSEC_IKE_INVALID_CERT_TYPE                  , 13819     ) /* 0x000035fb */ \
    XXX( WERR_IPSEC_IKE_NO_PRIVATE_KEY                     , 13820     ) /* 0x000035fc */ \
    XXX( WERR_IPSEC_IKE_DH_FAIL                            , 13822     ) /* 0x000035fe */ \
    XXX( WERR_IPSEC_IKE_INVALID_HEADER                     , 13824     ) /* 0x00003600 */ \
    XXX( WERR_IPSEC_IKE_NO_POLICY                          , 13825     ) /* 0x00003601 */ \
    XXX( WERR_IPSEC_IKE_INVALID_SIGNATURE                  , 13826     ) /* 0x00003602 */ \
    XXX( WERR_IPSEC_IKE_KERBEROS_ERROR                     , 13827     ) /* 0x00003603 */ \
    XXX( WERR_IPSEC_IKE_NO_PUBLIC_KEY                      , 13828     ) /* 0x00003604 */ \
    XXX( WERR_IPSEC_IKE_PROCESS_ERR                        , 13829     ) /* 0x00003605 */ \
    XXX( WERR_IPSEC_IKE_PROCESS_ERR_SA                     , 13830     ) /* 0x00003606 */ \
    XXX( WERR_IPSEC_IKE_PROCESS_ERR_PROP                   , 13831     ) /* 0x00003607 */ \
    XXX( WERR_IPSEC_IKE_PROCESS_ERR_TRANS                  , 13832     ) /* 0x00003608 */ \
    XXX( WERR_IPSEC_IKE_PROCESS_ERR_KE                     , 13833     ) /* 0x00003609 */ \
    XXX( WERR_IPSEC_IKE_PROCESS_ERR_ID                     , 13834     ) /* 0x0000360a */ \
    XXX( WERR_IPSEC_IKE_PROCESS_ERR_CERT                   , 13835     ) /* 0x0000360b */ \
    XXX( WERR_IPSEC_IKE_PROCESS_ERR_CERT_REQ               , 13836     ) /* 0x0000360c */ \
    XXX( WERR_IPSEC_IKE_PROCESS_ERR_HASH                   , 13837     ) /* 0x0000360d */ \
    XXX( WERR_IPSEC_IKE_PROCESS_ERR_SIG                    , 13838     ) /* 0x0000360e */ \
    XXX( WERR_IPSEC_IKE_PROCESS_ERR_NONCE                  , 13839     ) /* 0x0000360f */ \
    XXX( WERR_IPSEC_IKE_PROCESS_ERR_NOTIFY                 , 13840     ) /* 0x00003610 */ \
    XXX( WERR_IPSEC_IKE_PROCESS_ERR_DELETE                 , 13841     ) /* 0x00003611 */ \
    XXX( WERR_IPSEC_IKE_PROCESS_ERR_VENDOR                 , 13842     ) /* 0x00003612 */ \
    XXX( WERR_IPSEC_IKE_INVALID_PAYLOAD                    , 13843     ) /* 0x00003613 */ \
    XXX( WERR_IPSEC_IKE_LOAD_SOFT_SA                       , 13844     ) /* 0x00003614 */ \
    XXX( WERR_IPSEC_IKE_SOFT_SA_TORN_DOWN                  , 13845     ) /* 0x00003615 */ \
    XXX( WERR_IPSEC_IKE_INVALID_COOKIE                     , 13846     ) /* 0x00003616 */ \
    XXX( WERR_IPSEC_IKE_NO_PEER_CERT                       , 13847     ) /* 0x00003617 */ \
    XXX( WERR_IPSEC_IKE_PEER_CRL_FAILED                    , 13848     ) /* 0x00003618 */ \
    XXX( WERR_IPSEC_IKE_POLICY_CHANGE                      , 13849     ) /* 0x00003619 */ \
    XXX( WERR_IPSEC_IKE_NO_MM_POLICY                       , 13850     ) /* 0x0000361a */ \
    XXX( WERR_IPSEC_IKE_NOTCBPRIV                          , 13851     ) /* 0x0000361b */ \
    XXX( WERR_IPSEC_IKE_SECLOADFAIL                        , 13852     ) /* 0x0000361c */ \
    XXX( WERR_IPSEC_IKE_FAILSSPINIT                        , 13853     ) /* 0x0000361d */ \
    XXX( WERR_IPSEC_IKE_FAILQUERYSSP                       , 13854     ) /* 0x0000361e */ \
    XXX( WERR_IPSEC_IKE_SRVACQFAIL                         , 13855     ) /* 0x0000361f */ \
    XXX( WERR_IPSEC_IKE_SRVQUERYCRED                       , 13856     ) /* 0x00003620 */ \
    XXX( WERR_IPSEC_IKE_GETSPIFAIL                         , 13857     ) /* 0x00003621 */ \
    XXX( WERR_IPSEC_IKE_INVALID_FILTER                     , 13858     ) /* 0x00003622 */ \
    XXX( WERR_IPSEC_IKE_OUT_OF_MEMORY                      , 13859     ) /* 0x00003623 */ \
    XXX( WERR_IPSEC_IKE_ADD_UPDATE_KEY_FAILED              , 13860     ) /* 0x00003624 */ \
    XXX( WERR_IPSEC_IKE_INVALID_POLICY                     , 13861     ) /* 0x00003625 */ \
    XXX( WERR_IPSEC_IKE_UNKNOWN_DOI                        , 13862     ) /* 0x00003626 */ \
    XXX( WERR_IPSEC_IKE_INVALID_SITUATION                  , 13863     ) /* 0x00003627 */ \
    XXX( WERR_IPSEC_IKE_DH_FAILURE                         , 13864     ) /* 0x00003628 */ \
    XXX( WERR_IPSEC_IKE_INVALID_GROUP                      , 13865     ) /* 0x00003629 */ \
    XXX( WERR_IPSEC_IKE_ENCRYPT                            , 13866     ) /* 0x0000362a */ \
    XXX( WERR_IPSEC_IKE_DECRYPT                            , 13867     ) /* 0x0000362b */ \
    XXX( WERR_IPSEC_IKE_POLICY_MATCH                       , 13868     ) /* 0x0000362c */ \
    XXX( WERR_IPSEC_IKE_UNSUPPORTED_ID                     , 13869     ) /* 0x0000362d */ \
    XXX( WERR_IPSEC_IKE_INVALID_HASH                       , 13870     ) /* 0x0000362e */ \
    XXX( WERR_IPSEC_IKE_INVALID_HASH_ALG                   , 13871     ) /* 0x0000362f */ \
    XXX( WERR_IPSEC_IKE_INVALID_HASH_SIZE                  , 13872     ) /* 0x00003630 */ \
    XXX( WERR_IPSEC_IKE_INVALID_ENCRYPT_ALG                , 13873     ) /* 0x00003631 */ \
    XXX( WERR_IPSEC_IKE_INVALID_AUTH_ALG                   , 13874     ) /* 0x00003632 */ \
    XXX( WERR_IPSEC_IKE_INVALID_SIG                        , 13875     ) /* 0x00003633 */ \
    XXX( WERR_IPSEC_IKE_LOAD_FAILED                        , 13876     ) /* 0x00003634 */ \
    XXX( WERR_IPSEC_IKE_RPC_DELETE                         , 13877     ) /* 0x00003635 */ \
    XXX( WERR_IPSEC_IKE_BENIGN_REINIT                      , 13878     ) /* 0x00003636 */ \
    XXX( WERR_IPSEC_IKE_INVALID_RESPONDER_LIFETIME_NOTIFY  , 13879     ) /* 0x00003637 */ \
    XXX( WERR_IPSEC_IKE_INVALID_CERT_KEYLEN                , 13881     ) /* 0x00003639 */ \
    XXX( WERR_IPSEC_IKE_MM_LIMIT                           , 13882     ) /* 0x0000363a */ \
    XXX( WERR_IPSEC_IKE_NEGOTIATION_DISABLED               , 13883     ) /* 0x0000363b */ \
    XXX( WERR_IPSEC_IKE_QM_LIMIT                           , 13884     ) /* 0x0000363c */ \
    XXX( WERR_IPSEC_IKE_MM_EXPIRED                         , 13885     ) /* 0x0000363d */ \
    XXX( WERR_IPSEC_IKE_PEER_MM_ASSUMED_INVALID            , 13886     ) /* 0x0000363e */ \
    XXX( WERR_IPSEC_IKE_CERT_CHAIN_POLICY_MISMATCH         , 13887     ) /* 0x0000363f */ \
    XXX( WERR_IPSEC_IKE_UNEXPECTED_MESSAGE_ID              , 13888     ) /* 0x00003640 */ \
    XXX( WERR_IPSEC_IKE_INVALID_UMATTS                     , 13889     ) /* 0x00003641 */ \
    XXX( WERR_IPSEC_IKE_DOS_COOKIE_SENT                    , 13890     ) /* 0x00003642 */ \
    XXX( WERR_IPSEC_IKE_SHUTTING_DOWN                      , 13891     ) /* 0x00003643 */ \
    XXX( WERR_IPSEC_IKE_CGA_AUTH_FAILED                    , 13892     ) /* 0x00003644 */ \
    XXX( WERR_IPSEC_IKE_PROCESS_ERR_NATOA                  , 13893     ) /* 0x00003645 */ \
    XXX( WERR_IPSEC_IKE_INVALID_MM_FOR_QM                  , 13894     ) /* 0x00003646 */ \
    XXX( WERR_IPSEC_IKE_QM_EXPIRED                         , 13895     ) /* 0x00003647 */ \
    XXX( WERR_IPSEC_IKE_TOO_MANY_FILTERS                   , 13896     ) /* 0x00003648 */ \
    XXX( WERR_IPSEC_IKE_NEG_STATUS_END                     , 13897     ) /* 0x00003649 */ \
    XXX( WERR_SXS_SECTION_NOT_FOUND                        , 14000     ) /* 0x000036b0 */ \
    XXX( WERR_SXS_CANT_GEN_ACTCTX                          , 14001     ) /* 0x000036b1 */ \
    XXX( WERR_SXS_INVALID_ACTCTXDATA_FORMAT                , 14002     ) /* 0x000036b2 */ \
    XXX( WERR_SXS_ASSEMBLY_NOT_FOUND                       , 14003     ) /* 0x000036b3 */ \
    XXX( WERR_SXS_MANIFEST_FORMAT_ERROR                    , 14004     ) /* 0x000036b4 */ \
    XXX( WERR_SXS_MANIFEST_PARSE_ERROR                     , 14005     ) /* 0x000036b5 */ \
    XXX( WERR_SXS_ACTIVATION_CONTEXT_DISABLED              , 14006     ) /* 0x000036b6 */ \
    XXX( WERR_SXS_KEY_NOT_FOUND                            , 14007     ) /* 0x000036b7 */ \
    XXX( WERR_SXS_VERSION_CONFLICT                         , 14008     ) /* 0x000036b8 */ \
    XXX( WERR_SXS_WRONG_SECTION_TYPE                       , 14009     ) /* 0x000036b9 */ \
    XXX( WERR_SXS_THREAD_QUERIES_DISABLED                  , 14010     ) /* 0x000036ba */ \
    XXX( WERR_SXS_PROCESS_DEFAULT_ALREADY_SET              , 14011     ) /* 0x000036bb */ \
    XXX( WERR_SXS_UNKNOWN_ENCODING_GROUP                   , 14012     ) /* 0x000036bc */ \
    XXX( WERR_SXS_UNKNOWN_ENCODING                         , 14013     ) /* 0x000036bd */ \
    XXX( WERR_SXS_INVALID_XML_NAMESPACE_URI                , 14014     ) /* 0x000036be */ \
    XXX( WERR_SXS_ROOT_MANIFEST_DEPENDENCY_OT_INSTALLED    , 14015     ) /* 0x000036bf */ \
    XXX( WERR_SXS_LEAF_MANIFEST_DEPENDENCY_NOT_INSTALLED   , 14016     ) /* 0x000036c0 */ \
    XXX( WERR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE      , 14017     ) /* 0x000036c1 */ \
    XXX( WERR_SXS_MANIFEST_MISSING_REQUIRED_DEFAULT_NAMESPACE, 14018     ) /* 0x000036c2 */ \
    XXX( WERR_SXS_MANIFEST_INVALID_REQUIRED_DEFAULT_NAMESPACE, 14019     ) /* 0x000036c3 */ \
    XXX( WERR_SXS_PRIVATE_MANIFEST_CROSS_PATH_WITH_REPARSE_POINT, 14020     ) /* 0x000036c4 */ \
    XXX( WERR_SXS_DUPLICATE_DLL_NAME                       , 14021     ) /* 0x000036c5 */ \
    XXX( WERR_SXS_DUPLICATE_WINDOWCLASS_NAME               , 14022     ) /* 0x000036c6 */ \
    XXX( WERR_SXS_DUPLICATE_CLSID                          , 14023     ) /* 0x000036c7 */ \
    XXX( WERR_SXS_DUPLICATE_IID                            , 14024     ) /* 0x000036c8 */ \
    XXX( WERR_SXS_DUPLICATE_TLBID                          , 14025     ) /* 0x000036c9 */ \
    XXX( WERR_SXS_DUPLICATE_PROGID                         , 14026     ) /* 0x000036ca */ \
    XXX( WERR_SXS_DUPLICATE_ASSEMBLY_NAME                  , 14027     ) /* 0x000036cb */ \
    XXX( WERR_SXS_FILE_HASH_MISMATCH                       , 14028     ) /* 0x000036cc */ \
    XXX( WERR_SXS_POLICY_PARSE_ERROR                       , 14029     ) /* 0x000036cd */ \
    XXX( WERR_SXS_XML_E_MISSINGQUOTE                       , 14030     ) /* 0x000036ce */ \
    XXX( WERR_SXS_XML_E_COMMENTSYNTAX                      , 14031     ) /* 0x000036cf */ \
    XXX( WERR_SXS_XML_E_BADSTARTNAMECHAR                   , 14032     ) /* 0x000036d0 */ \
    XXX( WERR_SXS_XML_E_BADNAMECHAR                        , 14033     ) /* 0x000036d1 */ \
    XXX( WERR_SXS_XML_E_BADCHARINSTRING                    , 14034     ) /* 0x000036d2 */ \
    XXX( WERR_SXS_XML_E_XMLDECLSYNTAX                      , 14035     ) /* 0x000036d3 */ \
    XXX( WERR_SXS_XML_E_BADCHARDATA                        , 14036     ) /* 0x000036d4 */ \
    XXX( WERR_SXS_XML_E_MISSINGWHITESPACE                  , 14037     ) /* 0x000036d5 */ \
    XXX( WERR_SXS_XML_E_EXPECTINGTAGEND                    , 14038     ) /* 0x000036d6 */ \
    XXX( WERR_SXS_XML_E_MISSINGSEMICOLON                   , 14039     ) /* 0x000036d7 */ \
    XXX( WERR_SXS_XML_E_UNBALANCEDPAREN                    , 14040     ) /* 0x000036d8 */ \
    XXX( WERR_SXS_XML_E_INTERNALERROR                      , 14041     ) /* 0x000036d9 */ \
    XXX( WERR_SXS_XML_E_UNEXPECTED_WHITESPACE              , 14042     ) /* 0x000036da */ \
    XXX( WERR_SXS_XML_E_INCOMPLETE_ENCODING                , 14043     ) /* 0x000036db */ \
    XXX( WERR_SXS_XML_E_MISSING_PAREN                      , 14044     ) /* 0x000036dc */ \
    XXX( WERR_SXS_XML_E_EXPECTINGCLOSEQUOTE                , 14045     ) /* 0x000036dd */ \
    XXX( WERR_SXS_XML_E_MULTIPLE_COLONS                    , 14046     ) /* 0x000036de */ \
    XXX( WERR_SXS_XML_E_INVALID_DECIMAL                    , 14047     ) /* 0x000036df */ \
    XXX( WERR_SXS_XML_E_INVALID_HEXIDECIMAL                , 14048     ) /* 0x000036e0 */ \
    XXX( WERR_SXS_XML_E_INVALID_UNICODE                    , 14049     ) /* 0x000036e1 */ \
    XXX( WERR_SXS_XML_E_WHITESPACEORQUESTIONMARK           , 14050     ) /* 0x000036e2 */ \
    XXX( WERR_SXS_XML_E_UNEXPECTEDENDTAG                   , 14051     ) /* 0x000036e3 */ \
    XXX( WERR_SXS_XML_E_UNCLOSEDTAG                        , 14052     ) /* 0x000036e4 */ \
    XXX( WERR_SXS_XML_E_DUPLICATEATTRIBUTE                 , 14053     ) /* 0x000036e5 */ \
    XXX( WERR_SXS_XML_E_MULTIPLEROOTS                      , 14054     ) /* 0x000036e6 */ \
    XXX( WERR_SXS_XML_E_INVALIDATROOTLEVEL                 , 14055     ) /* 0x000036e7 */ \
    XXX( WERR_SXS_XML_E_BADXMLDECL                         , 14056     ) /* 0x000036e8 */ \
    XXX( WERR_SXS_XML_E_MISSINGROOT                        , 14057     ) /* 0x000036e9 */ \
    XXX( WERR_SXS_XML_E_UNEXPECTEDEOF                      , 14058     ) /* 0x000036ea */ \
    XXX( WERR_SXS_XML_E_BADPEREFINSUBSET                   , 14059     ) /* 0x000036eb */ \
    XXX( WERR_SXS_XML_E_UNCLOSEDSTARTTAG                   , 14060     ) /* 0x000036ec */ \
    XXX( WERR_SXS_XML_E_UNCLOSEDENDTAG                     , 14061     ) /* 0x000036ed */ \
    XXX( WERR_SXS_XML_E_UNCLOSEDSTRING                     , 14062     ) /* 0x000036ee */ \
    XXX( WERR_SXS_XML_E_UNCLOSEDCOMMENT                    , 14063     ) /* 0x000036ef */ \
    XXX( WERR_SXS_XML_E_UNCLOSEDDECL                       , 14064     ) /* 0x000036f0 */ \
    XXX( WERR_SXS_XML_E_UNCLOSEDCDATA                      , 14065     ) /* 0x000036f1 */ \
    XXX( WERR_SXS_XML_E_RESERVEDNAMESPACE                  , 14066     ) /* 0x000036f2 */ \
    XXX( WERR_SXS_XML_E_INVALIDENCODING                    , 14067     ) /* 0x000036f3 */ \
    XXX( WERR_SXS_XML_E_INVALIDSWITCH                      , 14068     ) /* 0x000036f4 */ \
    XXX( WERR_SXS_XML_E_BADXMLCASE                         , 14069     ) /* 0x000036f5 */ \
    XXX( WERR_SXS_XML_E_INVALID_STANDALONE                 , 14070     ) /* 0x000036f6 */ \
    XXX( WERR_SXS_XML_E_UNEXPECTED_STANDALONE              , 14071     ) /* 0x000036f7 */ \
    XXX( WERR_SXS_XML_E_INVALID_VERSION                    , 14072     ) /* 0x000036f8 */ \
    XXX( WERR_SXS_XML_E_MISSINGEQUALS                      , 14073     ) /* 0x000036f9 */ \
    XXX( WERR_SXS_PROTECTION_RECOVERY_FAILED               , 14074     ) /* 0x000036fa */ \
    XXX( WERR_SXS_PROTECTION_PUBLIC_KEY_OO_SHORT           , 14075     ) /* 0x000036fb */ \
    XXX( WERR_SXS_PROTECTION_CATALOG_NOT_VALID             , 14076     ) /* 0x000036fc */ \
    XXX( WERR_SXS_UNTRANSLATABLE_HRESULT                   , 14077     ) /* 0x000036fd */ \
    XXX( WERR_SXS_PROTECTION_CATALOG_FILE_MISSING          , 14078     ) /* 0x000036fe */ \
    XXX( WERR_SXS_MISSING_ASSEMBLY_IDENTITY_ATTRIBUTE      , 14079     ) /* 0x000036ff */ \
    XXX( WERR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE_NAME , 14080     ) /* 0x00003700 */ \
    XXX( WERR_SXS_ASSEMBLY_MISSING                         , 14081     ) /* 0x00003701 */ \
    XXX( WERR_SXS_CORRUPT_ACTIVATION_STACK                 , 14082     ) /* 0x00003702 */ \
    XXX( WERR_SXS_CORRUPTION                               , 14083     ) /* 0x00003703 */ \
    XXX( WERR_SXS_EARLY_DEACTIVATION                       , 14084     ) /* 0x00003704 */ \
    XXX( WERR_SXS_INVALID_DEACTIVATION                     , 14085     ) /* 0x00003705 */ \
    XXX( WERR_SXS_MULTIPLE_DEACTIVATION                    , 14086     ) /* 0x00003706 */ \
    XXX( WERR_SXS_PROCESS_TERMINATION_REQUESTED            , 14087     ) /* 0x00003707 */ \
    XXX( WERR_SXS_RELEASE_ACTIVATION_ONTEXT                , 14088     ) /* 0x00003708 */ \
    XXX( WERR_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY  , 14089     ) /* 0x00003709 */ \
    XXX( WERR_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE         , 14090     ) /* 0x0000370a */ \
    XXX( WERR_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME          , 14091     ) /* 0x0000370b */ \
    XXX( WERR_SXS_IDENTITY_DUPLICATE_ATTRIBUTE             , 14092     ) /* 0x0000370c */ \
    XXX( WERR_SXS_IDENTITY_PARSE_ERROR                     , 14093     ) /* 0x0000370d */ \
    XXX( WERR_MALFORMED_SUBSTITUTION_STRING                , 14094     ) /* 0x0000370e */ \
    XXX( WERR_SXS_INCORRECT_PUBLIC_KEY_OKEN                , 14095     ) /* 0x0000370f */ \
    XXX( WERR_UNMAPPED_SUBSTITUTION_STRING                 , 14096     ) /* 0x00003710 */ \
    XXX( WERR_SXS_ASSEMBLY_NOT_LOCKED                      , 14097     ) /* 0x00003711 */ \
    XXX( WERR_SXS_COMPONENT_STORE_CORRUPT                  , 14098     ) /* 0x00003712 */ \
    XXX( WERR_ADVANCED_INSTALLER_FAILED                    , 14099     ) /* 0x00003713 */ \
    XXX( WERR_XML_ENCODING_MISMATCH                        , 14100     ) /* 0x00003714 */ \
    XXX( WERR_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT, 14101     ) /* 0x00003715 */ \
    XXX( WERR_SXS_IDENTITIES_DIFFERENT                     , 14102     ) /* 0x00003716 */ \
    XXX( WERR_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT             , 14103     ) /* 0x00003717 */ \
    XXX( WERR_SXS_FILE_NOT_PART_OF_ASSEMBLY                , 14104     ) /* 0x00003718 */ \
    XXX( WERR_SXS_MANIFEST_TOO_BIG                         , 14105     ) /* 0x00003719 */ \
    XXX( WERR_SXS_SETTING_NOT_REGISTERED                   , 14106     ) /* 0x0000371a */ \
    XXX( WERR_SXS_TRANSACTION_CLOSURE_INCOMPLETE           , 14107     ) /* 0x0000371b */ \
    XXX( WERR_EVT_INVALID_CHANNEL_PATH                     , 15000     ) /* 0x00003a98 */ \
    XXX( WERR_EVT_INVALID_QUERY                            , 15001     ) /* 0x00003a99 */ \
    XXX( WERR_EVT_PUBLISHER_METADATA_NOT_FOUND             , 15002     ) /* 0x00003a9a */ \
    XXX( WERR_EVT_EVENT_TEMPLATE_NOT_FOUND                 , 15003     ) /* 0x00003a9b */ \
    XXX( WERR_EVT_INVALID_PUBLISHER_NAME                   , 15004     ) /* 0x00003a9c */ \
    XXX( WERR_EVT_INVALID_EVENT_DATA                       , 15005     ) /* 0x00003a9d */ \
    XXX( WERR_EVT_CHANNEL_NOT_FOUND                        , 15007     ) /* 0x00003a9f */ \
    XXX( WERR_EVT_MALFORMED_XML_TEXT                       , 15008     ) /* 0x00003aa0 */ \
    XXX( WERR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL           , 15009     ) /* 0x00003aa1 */ \
    XXX( WERR_EVT_CONFIGURATION_ERROR                      , 15010     ) /* 0x00003aa2 */ \
    XXX( WERR_EVT_QUERY_RESULT_STALE                       , 15011     ) /* 0x00003aa3 */ \
    XXX( WERR_EVT_QUERY_RESULT_INVALID_POSITION            , 15012     ) /* 0x00003aa4 */ \
    XXX( WERR_EVT_NON_VALIDATING_MSXML                     , 15013     ) /* 0x00003aa5 */ \
    XXX( WERR_EVT_FILTER_ALREADYSCOPED                     , 15014     ) /* 0x00003aa6 */ \
    XXX( WERR_EVT_FILTER_NOTELTSET                         , 15015     ) /* 0x00003aa7 */ \
    XXX( WERR_EVT_FILTER_INVARG                            , 15016     ) /* 0x00003aa8 */ \
    XXX( WERR_EVT_FILTER_INVTEST                           , 15017     ) /* 0x00003aa9 */ \
    XXX( WERR_EVT_FILTER_INVTYPE                           , 15018     ) /* 0x00003aaa */ \
    XXX( WERR_EVT_FILTER_PARSEERR                          , 15019     ) /* 0x00003aab */ \
    XXX( WERR_EVT_FILTER_UNSUPPORTEDOP                     , 15020     ) /* 0x00003aac */ \
    XXX( WERR_EVT_FILTER_UNEXPECTEDTOKEN                   , 15021     ) /* 0x00003aad */ \
    XXX( WERR_EVT_INVALID_OPERATION_OVER_ENABLED_DIRECT_CHANNEL, 15022     ) /* 0x00003aae */ \
    XXX( WERR_EVT_INVALID_CHANNEL_PROPERTY_VALUE           , 15023     ) /* 0x00003aaf */ \
    XXX( WERR_EVT_INVALID_PUBLISHER_PROPERTY_VALUE         , 15024     ) /* 0x00003ab0 */ \
    XXX( WERR_EVT_CHANNEL_CANNOT_ACTIVATE                  , 15025     ) /* 0x00003ab1 */ \
    XXX( WERR_EVT_FILTER_TOO_COMPLEX                       , 15026     ) /* 0x00003ab2 */ \
    XXX( WERR_EVT_MESSAGE_NOT_FOUND                        , 15027     ) /* 0x00003ab3 */ \
    XXX( WERR_EVT_MESSAGE_ID_NOT_FOUND                     , 15028     ) /* 0x00003ab4 */ \
    XXX( WERR_EVT_UNRESOLVED_VALUE_INSERT                  , 15029     ) /* 0x00003ab5 */ \
    XXX( WERR_EVT_UNRESOLVED_PARAMETER_INSERT              , 15030     ) /* 0x00003ab6 */ \
    XXX( WERR_EVT_MAX_INSERTS_REACHED                      , 15031     ) /* 0x00003ab7 */ \
    XXX( WERR_EVT_EVENT_DEFINITION_NOT_OUND                , 15032     ) /* 0x00003ab8 */ \
    XXX( WERR_EVT_MESSAGE_LOCALE_NOT_FOUND                 , 15033     ) /* 0x00003ab9 */ \
    XXX( WERR_EVT_VERSION_TOO_OLD                          , 15034     ) /* 0x00003aba */ \
    XXX( WERR_EVT_VERSION_TOO_NEW                          , 15035     ) /* 0x00003abb */ \
    XXX( WERR_EVT_CANNOT_OPEN_CHANNEL_OF_QUERY             , 15036     ) /* 0x00003abc */ \
    XXX( WERR_EVT_PUBLISHER_DISABLED                       , 15037     ) /* 0x00003abd */ \
    XXX( WERR_EC_SUBSCRIPTION_CANNOT_ACTIVATE              , 15080     ) /* 0x00003ae8 */ \
    XXX( WERR_EC_LOG_DISABLED                              , 15081     ) /* 0x00003ae9 */ \
    XXX( WERR_MUI_FILE_NOT_FOUND                           , 15100     ) /* 0x00003afc */ \
    XXX( WERR_MUI_INVALID_FILE                             , 15101     ) /* 0x00003afd */ \
    XXX( WERR_MUI_INVALID_RC_CONFIG                        , 15102     ) /* 0x00003afe */ \
    XXX( WERR_MUI_INVALID_LOCALE_NAME                      , 15103     ) /* 0x00003aff */ \
    XXX( WERR_MUI_INVALID_ULTIMATEFALLBACK_NAME            , 15104     ) /* 0x00003b00 */ \
    XXX( WERR_MUI_FILE_NOT_LOADED                          , 15105     ) /* 0x00003b01 */ \
    XXX( WERR_RESOURCE_ENUM_USER_STOP                      , 15106     ) /* 0x00003b02 */ \
    XXX( WERR_MUI_INTLSETTINGS_UILANG_NOT_INSTALLED        , 15107     ) /* 0x00003b03 */ \
    XXX( WERR_MUI_INTLSETTINGS_INVALID_LOCALE_NAME         , 15108     ) /* 0x00003b04 */ \
    XXX( WERR_MCA_INVALID_CAPABILITIES_STRING              , 15200     ) /* 0x00003b60 */ \
    XXX( WERR_MCA_INVALID_VCP_VERSION                      , 15201     ) /* 0x00003b61 */ \
    XXX( WERR_MCA_MONITOR_VIOLATES_MCCS_SPECIFICATION      , 15202     ) /* 0x00003b62 */ \
    XXX( WERR_MCA_MCCS_VERSION_MISMATCH                    , 15203     ) /* 0x00003b63 */ \
    XXX( WERR_MCA_UNSUPPORTED_MCCS_VERSION                 , 15204     ) /* 0x00003b64 */ \
    XXX( WERR_MCA_INTERNAL_ERROR                           , 15205     ) /* 0x00003b65 */ \
    XXX( WERR_MCA_INVALID_TECHNOLOGY_TYPE_RETURNED         , 15206     ) /* 0x00003b66 */ \
    XXX( WERR_MCA_UNSUPPORTED_COLOR_TEMPERATURE            , 15207     ) /* 0x00003b67 */ \
    XXX( WERR_AMBIGUOUS_SYSTEM_DEVICE                      , 15250     ) /* 0x00003b92 */ \
    XXX( WERR_SYSTEM_DEVICE_NOT_FOUND                      , 15299     ) /* 0x00003bc3 */

extern value_string_ext WERR_errors_ext;

/* Win32 errors.
 * These defines specify the HRES error codes often encountered in ms DCE/RPC
 * interfaces (those that do not return NT status that is)
 *
 */

#define HRES_errors_VALUE_STRING_LIST(XXX) \
   XXX( HRES_STG_S_CONVERTED        , 197120U) /* 0x00030200 */ \
   XXX( HRES_STG_S_BLOCK        , 197121U) /* 0x00030201 */ \
   XXX( HRES_STG_S_RETRYNOW        , 197122U) /* 0x00030202 */ \
   XXX( HRES_STG_S_MONITORING        , 197123U) /* 0x00030203 */ \
   XXX( HRES_STG_S_MULTIPLEOPENS        , 197124U) /* 0x00030204 */ \
   XXX( HRES_STG_S_CONSOLIDATIONFAILED        , 197125U) /* 0x00030205 */ \
   XXX( HRES_STG_S_CANNOTCONSOLIDATE        , 197126U) /* 0x00030206 */ \
   XXX( HRES_OLE_S_USEREG        , 262144U) /* 0x00040000 */ \
   XXX( HRES_OLE_S_STATIC        , 262145U) /* 0x00040001 */ \
   XXX( HRES_OLE_S_MAC_CLIPFORMAT        , 262146U) /* 0x00040002 */ \
   XXX( HRES_DRAGDROP_S_DROP        , 262400U) /* 0x00040100 */ \
   XXX( HRES_DRAGDROP_S_CANCEL        , 262401U) /* 0x00040101 */ \
   XXX( HRES_DRAGDROP_S_USEDEFAULTCURSORS     , 262402U) /* 0x00040102 */ \
   XXX( HRES_DATA_S_SAMEFORMATETC        , 262448U) /* 0x00040130 */ \
   XXX( HRES_VIEW_S_ALREADY_FROZEN        , 262464U) /* 0x00040140 */ \
   XXX( HRES_CACHE_S_FORMATETC_NOTSUPPORTED     , 262512U) /* 0x00040170 */ \
   XXX( HRES_CACHE_S_SAMECACHE        , 262513U) /* 0x00040171 */ \
   XXX( HRES_CACHE_S_SOMECACHES_NOTUPDATED     , 262514U) /* 0x00040172 */ \
   XXX( HRES_OLEOBJ_S_INVALIDVERB        , 262528U) /* 0x00040180 */ \
   XXX( HRES_OLEOBJ_S_CANNOT_DOVERB_NOW        , 262529U) /* 0x00040181 */ \
   XXX( HRES_OLEOBJ_S_INVALIDHWND        , 262530U) /* 0x00040182 */ \
   XXX( HRES_INPLACE_S_TRUNCATED        , 262560U) /* 0x000401a0 */ \
   XXX( HRES_CONVERT10_S_NO_PRESENTATION     , 262592U) /* 0x000401c0 */ \
   XXX( HRES_MK_S_REDUCED_TO_SELF        , 262626U) /* 0x000401e2 */ \
   XXX( HRES_MK_S_ME        , 262628U) /* 0x000401e4 */ \
   XXX( HRES_MK_S_HIM        , 262629U) /* 0x000401e5 */ \
   XXX( HRES_MK_S_US        , 262630U) /* 0x000401e6 */ \
   XXX( HRES_MK_S_MONIKERALREADYREGISTERED     , 262631U) /* 0x000401e7 */ \
   XXX( HRES_EVENT_S_SOME_SUBSCRIBERS_FAILED     , 262656U) /* 0x00040200 */ \
   XXX( HRES_EVENT_S_NOSUBSCRIBERS        , 262658U) /* 0x00040202 */ \
   XXX( HRES_SCHED_S_TASK_READY        , 267008U) /* 0x00041300 */ \
   XXX( HRES_SCHED_S_TASK_RUNNING        , 267009U) /* 0x00041301 */ \
   XXX( HRES_SCHED_S_TASK_DISABLED        , 267010U) /* 0x00041302 */ \
   XXX( HRES_SCHED_S_TASK_HAS_NOT_RUN        , 267011U) /* 0x00041303 */ \
   XXX( HRES_SCHED_S_TASK_NO_MORE_RUNS        , 267012U) /* 0x00041304 */ \
   XXX( HRES_SCHED_S_TASK_NOT_SCHEDULED        , 267013U) /* 0x00041305 */ \
   XXX( HRES_SCHED_S_TASK_TERMINATED        , 267014U) /* 0x00041306 */ \
   XXX( HRES_SCHED_S_TASK_NO_VALID_TRIGGERS     , 267015U) /* 0x00041307 */ \
   XXX( HRES_SCHED_S_EVENT_TRIGGER        , 267016U) /* 0x00041308 */ \
   XXX( HRES_SCHED_S_SOME_TRIGGERS_FAILED     , 267035U) /* 0x0004131b */ \
   XXX( HRES_SCHED_S_BATCH_LOGON_PROBLEM     , 267036U) /* 0x0004131c */ \
   XXX( HRES_XACT_S_ASYNC        , 315392U) /* 0x0004d000 */ \
   XXX( HRES_XACT_S_READONLY        , 315394U) /* 0x0004d002 */ \
   XXX( HRES_XACT_S_SOMENORETAIN        , 315395U) /* 0x0004d003 */ \
   XXX( HRES_XACT_S_OKINFORM        , 315396U) /* 0x0004d004 */ \
   XXX( HRES_XACT_S_MADECHANGESCONTENT        , 315397U) /* 0x0004d005 */ \
   XXX( HRES_XACT_S_MADECHANGESINFORM        , 315398U) /* 0x0004d006 */ \
   XXX( HRES_XACT_S_ALLNORETAIN        , 315399U) /* 0x0004d007 */ \
   XXX( HRES_XACT_S_ABORTING        , 315400U) /* 0x0004d008 */ \
   XXX( HRES_XACT_S_SINGLEPHASE        , 315401U) /* 0x0004d009 */ \
   XXX( HRES_XACT_S_LOCALLY_OK        , 315402U) /* 0x0004d00a */ \
   XXX( HRES_XACT_S_LASTRESOURCEMANAGER        , 315408U) /* 0x0004d010 */ \
   XXX( HRES_CO_S_NOTALLINTERFACES        , 524306U) /* 0x00080012 */ \
   XXX( HRES_CO_S_MACHINENAMENOTFOUND        , 524307U) /* 0x00080013 */ \
   XXX( HRES_SEC_I_CONTINUE_NEEDED        , 590610U) /* 0x00090312 */ \
   XXX( HRES_SEC_I_COMPLETE_NEEDED        , 590611U) /* 0x00090313 */ \
   XXX( HRES_SEC_I_COMPLETE_AND_CONTINUE     , 590612U) /* 0x00090314 */ \
   XXX( HRES_SEC_I_LOCAL_LOGON        , 590613U) /* 0x00090315 */ \
   XXX( HRES_SEC_I_CONTEXT_EXPIRED        , 590615U) /* 0x00090317 */ \
   XXX( HRES_SEC_I_INCOMPLETE_CREDENTIALS     , 590624U) /* 0x00090320 */ \
   XXX( HRES_SEC_I_RENEGOTIATE        , 590625U) /* 0x00090321 */ \
   XXX( HRES_SEC_I_NO_LSA_CONTEXT        , 590627U) /* 0x00090323 */ \
   XXX( HRES_SEC_I_SIGNATURE_NEEDED        , 590684U) /* 0x0009035c */ \
   XXX( HRES_CRYPT_I_NEW_PROTECTION_REQUIRED     , 593938U) /* 0x00091012 */ \
   XXX( HRES_NS_S_CALLPENDING        , 851968U) /* 0x000d0000 */ \
   XXX( HRES_NS_S_CALLABORTED        , 851969U) /* 0x000d0001 */ \
   XXX( HRES_NS_S_STREAM_TRUNCATED        , 851970U) /* 0x000d0002 */ \
   XXX( HRES_NS_S_REBUFFERING        , 854984U) /* 0x000d0bc8 */ \
   XXX( HRES_NS_S_DEGRADING_QUALITY        , 854985U) /* 0x000d0bc9 */ \
   XXX( HRES_NS_S_TRANSCRYPTOR_EOF        , 855003U) /* 0x000d0bdb */ \
   XXX( HRES_NS_S_WMP_UI_VERSIONMISMATCH     , 856040U) /* 0x000d0fe8 */ \
   XXX( HRES_NS_S_WMP_EXCEPTION        , 856041U) /* 0x000d0fe9 */ \
   XXX( HRES_NS_S_WMP_LOADED_GIF_IMAGE        , 856128U) /* 0x000d1040 */ \
   XXX( HRES_NS_S_WMP_LOADED_PNG_IMAGE        , 856129U) /* 0x000d1041 */ \
   XXX( HRES_NS_S_WMP_LOADED_BMP_IMAGE        , 856130U) /* 0x000d1042 */ \
   XXX( HRES_NS_S_WMP_LOADED_JPG_IMAGE        , 856131U) /* 0x000d1043 */ \
   XXX( HRES_NS_S_WMG_FORCE_DROP_FRAME        , 856143U) /* 0x000d104f */ \
   XXX( HRES_NS_S_WMR_ALREADYRENDERED        , 856159U) /* 0x000d105f */ \
   XXX( HRES_NS_S_WMR_PINTYPEPARTIALMATCH     , 856160U) /* 0x000d1060 */ \
   XXX( HRES_NS_S_WMR_PINTYPEFULLMATCH        , 856161U) /* 0x000d1061 */ \
   XXX( HRES_NS_S_WMG_ADVISE_DROP_FRAME        , 856166U) /* 0x000d1066 */ \
   XXX( HRES_NS_S_WMG_ADVISE_DROP_TO_KEYFRAME     , 856167U) /* 0x000d1067 */ \
   XXX( HRES_NS_S_NEED_TO_BUY_BURN_RIGHTS     , 856283U) /* 0x000d10db */ \
   XXX( HRES_NS_S_WMPCORE_PLAYLISTCLEARABORT     , 856318U) /* 0x000d10fe */ \
   XXX( HRES_NS_S_WMPCORE_PLAYLISTREMOVEITEMABORT  , 856319U) /* 0x000d10ff */ \
   XXX( HRES_NS_S_WMPCORE_PLAYLIST_CREATION_PENDING , 856322U) /* 0x000d1102 */ \
   XXX( HRES_NS_S_WMPCORE_MEDIA_VALIDATION_PENDING  , 856323U) /* 0x000d1103 */ \
   XXX( HRES_NS_S_WMPCORE_PLAYLIST_REPEAT_SECONDARY_SEGMENTS_IGNORED, 856324U) /* 0x000d1104 */ \
   XXX( HRES_NS_S_WMPCORE_COMMAND_NOT_AVAILABLE     , 856325U) /* 0x000d1105 */ \
   XXX( HRES_NS_S_WMPCORE_PLAYLIST_NAME_AUTO_GENERATED  , 856326U) /* 0x000d1106 */ \
   XXX( HRES_NS_S_WMPCORE_PLAYLIST_IMPORT_MISSING_ITEMS, 856327U) /* 0x000d1107 */ \
   XXX( HRES_NS_S_WMPCORE_PLAYLIST_COLLAPSED_TO_SINGLE_MEDIA, 856328U) /* 0x000d1108 */ \
   XXX( HRES_NS_S_WMPCORE_MEDIA_CHILD_PLAYLIST_OPEN_PENDING, 856329U) /* 0x000d1109 */ \
   XXX( HRES_NS_S_WMPCORE_MORE_NODES_AVAIABLE     , 856330U) /* 0x000d110a */ \
   XXX( HRES_NS_S_WMPBR_SUCCESS        , 856373U) /* 0x000d1135 */ \
   XXX( HRES_NS_S_WMPBR_PARTIALSUCCESS        , 856374U) /* 0x000d1136 */ \
   XXX( HRES_NS_S_WMPEFFECT_TRANSPARENT        , 856388U) /* 0x000d1144 */ \
   XXX( HRES_NS_S_WMPEFFECT_OPAQUE        , 856389U) /* 0x000d1145 */ \
   XXX( HRES_NS_S_OPERATION_PENDING        , 856398U) /* 0x000d114e */ \
   XXX( HRES_NS_S_TRACK_BUY_REQUIRES_ALBUM_PURCHASE , 856921U) /* 0x000d1359 */ \
   XXX( HRES_NS_S_NAVIGATION_COMPLETE_WITH_ERRORS   , 856926U) /* 0x000d135e */ \
   XXX( HRES_NS_S_TRACK_ALREADY_DOWNLOADED     , 856929U) /* 0x000d1361 */ \
   XXX( HRES_NS_S_PUBLISHING_POINT_STARTED_WITH_FAILED_SINKS, 857369U) /* 0x000d1519 */ \
   XXX( HRES_NS_S_DRM_LICENSE_ACQUIRED        , 861990U) /* 0x000d2726 */ \
   XXX( HRES_NS_S_DRM_INDIVIDUALIZED        , 861991U) /* 0x000d2727 */ \
   XXX( HRES_NS_S_DRM_MONITOR_CANCELLED        , 862022U) /* 0x000d2746 */ \
   XXX( HRES_NS_S_DRM_ACQUIRE_CANCELLED        , 862023U) /* 0x000d2747 */ \
   XXX( HRES_NS_S_DRM_BURNABLE_TRACK        , 862062U) /* 0x000d276e */ \
   XXX( HRES_NS_S_DRM_BURNABLE_TRACK_WITH_PLAYLIST_RESTRICTION, 862063U) /* 0x000d276f */ \
   XXX( HRES_NS_S_DRM_NEEDS_INDIVIDUALIZATION     , 862174U) /* 0x000d27de */ \
   XXX( HRES_NS_S_REBOOT_RECOMMENDED        , 862968U) /* 0x000d2af8 */ \
   XXX( HRES_NS_S_REBOOT_REQUIRED        , 862969U) /* 0x000d2af9 */ \
   XXX( HRES_NS_S_EOSRECEDING        , 864009U) /* 0x000d2f09 */ \
   XXX( HRES_NS_S_CHANGENOTICE        , 864013U) /* 0x000d2f0d */ \
   XXX( HRES_ERROR_FLT_IO_COMPLETE        , 2031617U) /* 0x001f0001 */ \
   XXX( HRES_ERROR_GRAPHICS_MODE_NOT_PINNED     , 2499335U) /* 0x00262307 */ \
   XXX( HRES_ERROR_GRAPHICS_NO_PREFERRED_MODE     , 2499358U) /* 0x0026231e */ \
   XXX( HRES_ERROR_GRAPHICS_DATASET_IS_EMPTY     , 2499403U) /* 0x0026234b */ \
   XXX( HRES_ERROR_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET, 2499404U) /* 0x0026234c */ \
   XXX( HRES_ERROR_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED, 2499409U) /* 0x00262351 */ \
   XXX( HRES_PLA_S_PROPERTY_IGNORED        , 3145984U) /* 0x00300100 */ \
   XXX( HRES_ERROR_NDIS_INDICATION_REQUIRED     , 3407873U) /* 0x00340001 */ \
   XXX( HRES_TRK_S_OUT_OF_SYNC        , 233492736U) /* 0x0dead100 */ \
   XXX( HRES_TRK_VOLUME_NOT_FOUND        , 233492738U) /* 0x0dead102 */ \
   XXX( HRES_TRK_VOLUME_NOT_OWNED        , 233492739U) /* 0x0dead103 */ \
   XXX( HRES_TRK_S_NOTIFICATION_QUOTA_EXCEEDED     , 233492743U) /* 0x0dead107 */ \
   XXX( HRES_NS_I_TIGER_START        , 1074593871U) /* 0x400d004f */ \
   XXX( HRES_NS_I_CUB_START        , 1074593873U) /* 0x400d0051 */ \
   XXX( HRES_NS_I_CUB_RUNNING        , 1074593874U) /* 0x400d0052 */ \
   XXX( HRES_NS_I_DISK_START        , 1074593876U) /* 0x400d0054 */ \
   XXX( HRES_NS_I_DISK_REBUILD_STARTED        , 1074593878U) /* 0x400d0056 */ \
   XXX( HRES_NS_I_DISK_REBUILD_FINISHED        , 1074593879U) /* 0x400d0057 */ \
   XXX( HRES_NS_I_DISK_REBUILD_ABORTED        , 1074593880U) /* 0x400d0058 */ \
   XXX( HRES_NS_I_LIMIT_FUNNELS        , 1074593881U) /* 0x400d0059 */ \
   XXX( HRES_NS_I_START_DISK        , 1074593882U) /* 0x400d005a */ \
   XXX( HRES_NS_I_STOP_DISK        , 1074593883U) /* 0x400d005b */ \
   XXX( HRES_NS_I_STOP_CUB        , 1074593884U) /* 0x400d005c */ \
   XXX( HRES_NS_I_KILL_USERSESSION        , 1074593885U) /* 0x400d005d */ \
   XXX( HRES_NS_I_KILL_CONNECTION        , 1074593886U) /* 0x400d005e */ \
   XXX( HRES_NS_I_REBUILD_DISK        , 1074593887U) /* 0x400d005f */ \
   XXX( HRES_MCMADM_I_NO_EVENTS        , 1074593897U) /* 0x400d0069 */ \
   XXX( HRES_NS_I_LOGGING_FAILED        , 1074593902U) /* 0x400d006e */ \
   XXX( HRES_NS_I_LIMIT_BANDWIDTH        , 1074593904U) /* 0x400d0070 */ \
   XXX( HRES_NS_I_CUB_UNFAIL_LINK        , 1074594193U) /* 0x400d0191 */ \
   XXX( HRES_NS_I_RESTRIPE_START        , 1074594195U) /* 0x400d0193 */ \
   XXX( HRES_NS_I_RESTRIPE_DONE        , 1074594196U) /* 0x400d0194 */ \
   XXX( HRES_NS_I_RESTRIPE_DISK_OUT        , 1074594198U) /* 0x400d0196 */ \
   XXX( HRES_NS_I_RESTRIPE_CUB_OUT        , 1074594199U) /* 0x400d0197 */ \
   XXX( HRES_NS_I_DISK_STOP        , 1074594200U) /* 0x400d0198 */ \
   XXX( HRES_NS_I_PLAYLIST_CHANGE_RECEDING     , 1074599102U) /* 0x400d14be */ \
   XXX( HRES_NS_I_RECONNECTED        , 1074605823U) /* 0x400d2eff */ \
   XXX( HRES_NS_I_NOLOG_STOP        , 1074605825U) /* 0x400d2f01 */ \
   XXX( HRES_NS_I_EXISTING_PACKETIZER        , 1074605827U) /* 0x400d2f03 */ \
   XXX( HRES_NS_I_MANUAL_PROXY        , 1074605828U) /* 0x400d2f04 */ \
   XXX( HRES_ERROR_GRAPHICS_DRIVER_MISMATCH     , 1076240393U) /* 0x40262009 */ \
   XXX( HRES_ERROR_GRAPHICS_UNKNOWN_CHILD_STATUS    , 1076241455U) /* 0x4026242f */ \
   XXX( HRES_ERROR_GRAPHICS_LEADLINK_START_DEFERRED , 1076241463U) /* 0x40262437 */ \
   XXX( HRES_ERROR_GRAPHICS_POLLING_TOO_FREQUENTLY  , 1076241465U) /* 0x40262439 */ \
   XXX( HRES_ERROR_GRAPHICS_START_DEFERRED     , 1076241466U) /* 0x4026243a */ \
   XXX( HRES_E_PENDING          , 2147483658U) /* 0x8000000a */ \
   XXX( HRES_E_NOTIMPL          , 2147500033U) /* 0x80004001 */ \
   XXX( HRES_E_NOINTERFACE        , 2147500034U) /* 0x80004002 */ \
   XXX( HRES_E_POINTER          , 2147500035U) /* 0x80004003 */ \
   XXX( HRES_E_ABORT            , 2147500036U) /* 0x80004004 */ \
   XXX( HRES_E_FAIL         , 2147500037U) /* 0x80004005 */ \
   XXX( HRES_CO_E_INIT_TLS        , 2147500038U) /* 0x80004006 */ \
   XXX( HRES_CO_E_INIT_SHARED_ALLOCATOR        , 2147500039U) /* 0x80004007 */ \
   XXX( HRES_CO_E_INIT_MEMORY_ALLOCATOR        , 2147500040U) /* 0x80004008 */ \
   XXX( HRES_CO_E_INIT_CLASS_CACHE        , 2147500041U) /* 0x80004009 */ \
   XXX( HRES_CO_E_INIT_RPC_CHANNEL        , 2147500042U) /* 0x8000400a */ \
   XXX( HRES_CO_E_INIT_TLS_SET_CHANNEL_CONTROL     , 2147500043U) /* 0x8000400b */ \
   XXX( HRES_CO_E_INIT_TLS_CHANNEL_CONTROL     , 2147500044U) /* 0x8000400c */ \
   XXX( HRES_CO_E_INIT_UNACCEPTED_USER_ALLOCATOR  , 2147500045U) /* 0x8000400d */ \
   XXX( HRES_CO_E_INIT_SCM_MUTEX_EXISTS        , 2147500046U) /* 0x8000400e */ \
   XXX( HRES_CO_E_INIT_SCM_FILE_MAPPING_EXISTS     , 2147500047U) /* 0x8000400f */ \
   XXX( HRES_CO_E_INIT_SCM_MAP_VIEW_OF_FILE     , 2147500048U) /* 0x80004010 */ \
   XXX( HRES_CO_E_INIT_SCM_EXEC_FAILURE        , 2147500049U) /* 0x80004011 */ \
   XXX( HRES_CO_E_INIT_ONLY_SINGLE_THREADED     , 2147500050U) /* 0x80004012 */ \
   XXX( HRES_CO_E_CANT_REMOTE        , 2147500051U) /* 0x80004013 */ \
   XXX( HRES_CO_E_BAD_SERVER_NAME        , 2147500052U) /* 0x80004014 */ \
   XXX( HRES_CO_E_WRONG_SERVER_IDENTITY        , 2147500053U) /* 0x80004015 */ \
   XXX( HRES_CO_E_OLE1DDE_DISABLED        , 2147500054U) /* 0x80004016 */ \
   XXX( HRES_CO_E_RUNAS_SYNTAX        , 2147500055U) /* 0x80004017 */ \
   XXX( HRES_CO_E_CREATEPROCESS_FAILURE        , 2147500056U) /* 0x80004018 */ \
   XXX( HRES_CO_E_RUNAS_CREATEPROCESS_FAILURE     , 2147500057U) /* 0x80004019 */ \
   XXX( HRES_CO_E_RUNAS_LOGON_FAILURE        , 2147500058U) /* 0x8000401a */ \
   XXX( HRES_CO_E_LAUNCH_PERMSSION_DENIED     , 2147500059U) /* 0x8000401b */ \
   XXX( HRES_CO_E_START_SERVICE_FAILURE        , 2147500060U) /* 0x8000401c */ \
   XXX( HRES_CO_E_REMOTE_COMMUNICATION_FAILURE     , 2147500061U) /* 0x8000401d */ \
   XXX( HRES_CO_E_SERVER_START_TIMEOUT        , 2147500062U) /* 0x8000401e */ \
   XXX( HRES_CO_E_CLSREG_INCONSISTENT        , 2147500063U) /* 0x8000401f */ \
   XXX( HRES_CO_E_IIDREG_INCONSISTENT        , 2147500064U) /* 0x80004020 */ \
   XXX( HRES_CO_E_NOT_SUPPORTED        , 2147500065U) /* 0x80004021 */ \
   XXX( HRES_CO_E_RELOAD_DLL        , 2147500066U) /* 0x80004022 */ \
   XXX( HRES_CO_E_MSI_ERROR        , 2147500067U) /* 0x80004023 */ \
   XXX( HRES_CO_E_ATTEMPT_TO_CREATE_OUTSIDE_CLIENT_CONTEXT, 2147500068U) /* 0x80004024 */ \
   XXX( HRES_CO_E_SERVER_PAUSED        , 2147500069U) /* 0x80004025 */ \
   XXX( HRES_CO_E_SERVER_NOT_PAUSED        , 2147500070U) /* 0x80004026 */ \
   XXX( HRES_CO_E_CLASS_DISABLED        , 2147500071U) /* 0x80004027 */ \
   XXX( HRES_CO_E_CLRNOTAVAILABLE        , 2147500072U) /* 0x80004028 */ \
   XXX( HRES_CO_E_ASYNC_WORK_REJECTED        , 2147500073U) /* 0x80004029 */ \
   XXX( HRES_CO_E_SERVER_INIT_TIMEOUT        , 2147500074U) /* 0x8000402a */ \
   XXX( HRES_CO_E_NO_SECCTX_IN_ACTIVATE        , 2147500075U) /* 0x8000402b */ \
   XXX( HRES_CO_E_TRACKER_CONFIG        , 2147500080U) /* 0x80004030 */ \
   XXX( HRES_CO_E_THREADPOOL_CONFIG        , 2147500081U) /* 0x80004031 */ \
   XXX( HRES_CO_E_SXS_CONFIG        , 2147500082U) /* 0x80004032 */ \
   XXX( HRES_CO_E_MALFORMED_SPN        , 2147500083U) /* 0x80004033 */ \
   XXX( HRES_E_UNEXPECTED        , 2147549183U) /* 0x8000ffff */ \
   XXX( HRES_RPC_E_CALL_REJECTED        , 2147549185U) /* 0x80010001 */ \
   XXX( HRES_RPC_E_CALL_CANCELED        , 2147549186U) /* 0x80010002 */ \
   XXX( HRES_RPC_E_CANTPOST_INSENDCALL        , 2147549187U) /* 0x80010003 */ \
   XXX( HRES_RPC_E_CANTCALLOUT_INASYNCCALL     , 2147549188U) /* 0x80010004 */ \
   XXX( HRES_RPC_E_CANTCALLOUT_INEXTERNALCALL     , 2147549189U) /* 0x80010005 */ \
   XXX( HRES_RPC_E_CONNECTION_TERMINATED     , 2147549190U) /* 0x80010006 */ \
   XXX( HRES_RPC_E_SERVER_DIED        , 2147549191U) /* 0x80010007 */ \
   XXX( HRES_RPC_E_CLIENT_DIED        , 2147549192U) /* 0x80010008 */ \
   XXX( HRES_RPC_E_INVALID_DATAPACKET        , 2147549193U) /* 0x80010009 */ \
   XXX( HRES_RPC_E_CANTTRANSMIT_CALL        , 2147549194U) /* 0x8001000a */ \
   XXX( HRES_RPC_E_CLIENT_CANTMARSHAL_DATA     , 2147549195U) /* 0x8001000b */ \
   XXX( HRES_RPC_E_CLIENT_CANTUNMARSHAL_DATA     , 2147549196U) /* 0x8001000c */ \
   XXX( HRES_RPC_E_SERVER_CANTMARSHAL_DATA     , 2147549197U) /* 0x8001000d */ \
   XXX( HRES_RPC_E_SERVER_CANTUNMARSHAL_DATA     , 2147549198U) /* 0x8001000e */ \
   XXX( HRES_RPC_E_INVALID_DATA        , 2147549199U) /* 0x8001000f */ \
   XXX( HRES_RPC_E_INVALID_PARAMETER        , 2147549200U) /* 0x80010010 */ \
   XXX( HRES_RPC_E_CANTCALLOUT_AGAIN        , 2147549201U) /* 0x80010011 */ \
   XXX( HRES_RPC_E_SERVER_DIED_DNE        , 2147549202U) /* 0x80010012 */ \
   XXX( HRES_RPC_E_SYS_CALL_FAILED        , 2147549440U) /* 0x80010100 */ \
   XXX( HRES_RPC_E_OUT_OF_RESOURCES        , 2147549441U) /* 0x80010101 */ \
   XXX( HRES_RPC_E_ATTEMPTED_MULTITHREAD     , 2147549442U) /* 0x80010102 */ \
   XXX( HRES_RPC_E_NOT_REGISTERED        , 2147549443U) /* 0x80010103 */ \
   XXX( HRES_RPC_E_FAULT        , 2147549444U) /* 0x80010104 */ \
   XXX( HRES_RPC_E_SERVERFAULT        , 2147549445U) /* 0x80010105 */ \
   XXX( HRES_RPC_E_CHANGED_MODE        , 2147549446U) /* 0x80010106 */ \
   XXX( HRES_RPC_E_INVALIDMETHOD        , 2147549447U) /* 0x80010107 */ \
   XXX( HRES_RPC_E_DISCONNECTED        , 2147549448U) /* 0x80010108 */ \
   XXX( HRES_RPC_E_RETRY        , 2147549449U) /* 0x80010109 */ \
   XXX( HRES_RPC_E_SERVERCALL_RETRYLATER     , 2147549450U) /* 0x8001010a */ \
   XXX( HRES_RPC_E_SERVERCALL_REJECTED        , 2147549451U) /* 0x8001010b */ \
   XXX( HRES_RPC_E_INVALID_CALLDATA        , 2147549452U) /* 0x8001010c */ \
   XXX( HRES_RPC_E_CANTCALLOUT_ININPUTSYNCCALL     , 2147549453U) /* 0x8001010d */ \
   XXX( HRES_RPC_E_WRONG_THREAD        , 2147549454U) /* 0x8001010e */ \
   XXX( HRES_RPC_E_THREAD_NOT_INIT        , 2147549455U) /* 0x8001010f */ \
   XXX( HRES_RPC_E_VERSION_MISMATCH        , 2147549456U) /* 0x80010110 */ \
   XXX( HRES_RPC_E_INVALID_HEADER        , 2147549457U) /* 0x80010111 */ \
   XXX( HRES_RPC_E_INVALID_EXTENSION        , 2147549458U) /* 0x80010112 */ \
   XXX( HRES_RPC_E_INVALID_IPID        , 2147549459U) /* 0x80010113 */ \
   XXX( HRES_RPC_E_INVALID_OBJECT        , 2147549460U) /* 0x80010114 */ \
   XXX( HRES_RPC_S_CALLPENDING        , 2147549461U) /* 0x80010115 */ \
   XXX( HRES_RPC_S_WAITONTIMER        , 2147549462U) /* 0x80010116 */ \
   XXX( HRES_RPC_E_CALL_COMPLETE        , 2147549463U) /* 0x80010117 */ \
   XXX( HRES_RPC_E_UNSECURE_CALL        , 2147549464U) /* 0x80010118 */ \
   XXX( HRES_RPC_E_TOO_LATE        , 2147549465U) /* 0x80010119 */ \
   XXX( HRES_RPC_E_NO_GOOD_SECURITY_PACKAGES     , 2147549466U) /* 0x8001011a */ \
   XXX( HRES_RPC_E_ACCESS_DENIED        , 2147549467U) /* 0x8001011b */ \
   XXX( HRES_RPC_E_REMOTE_DISABLED        , 2147549468U) /* 0x8001011c */ \
   XXX( HRES_RPC_E_INVALID_OBJREF        , 2147549469U) /* 0x8001011d */ \
   XXX( HRES_RPC_E_NO_CONTEXT        , 2147549470U) /* 0x8001011e */ \
   XXX( HRES_RPC_E_TIMEOUT        , 2147549471U) /* 0x8001011f */ \
   XXX( HRES_RPC_E_NO_SYNC        , 2147549472U) /* 0x80010120 */ \
   XXX( HRES_RPC_E_FULLSIC_REQUIRED        , 2147549473U) /* 0x80010121 */ \
   XXX( HRES_RPC_E_INVALID_STD_NAME        , 2147549474U) /* 0x80010122 */ \
   XXX( HRES_CO_E_FAILEDTOIMPERSONATE        , 2147549475U) /* 0x80010123 */ \
   XXX( HRES_CO_E_FAILEDTOGETSECCTX        , 2147549476U) /* 0x80010124 */ \
   XXX( HRES_CO_E_FAILEDTOOPENTHREADTOKEN     , 2147549477U) /* 0x80010125 */ \
   XXX( HRES_CO_E_FAILEDTOGETTOKENINFO        , 2147549478U) /* 0x80010126 */ \
   XXX( HRES_CO_E_TRUSTEEDOESNTMATCHCLIENT     , 2147549479U) /* 0x80010127 */ \
   XXX( HRES_CO_E_FAILEDTOQUERYCLIENTBLANKET     , 2147549480U) /* 0x80010128 */ \
   XXX( HRES_CO_E_FAILEDTOSETDACL        , 2147549481U) /* 0x80010129 */ \
   XXX( HRES_CO_E_ACCESSCHECKFAILED        , 2147549482U) /* 0x8001012a */ \
   XXX( HRES_CO_E_NETACCESSAPIFAILED        , 2147549483U) /* 0x8001012b */ \
   XXX( HRES_CO_E_WRONGTRUSTEENAMESYNTAX     , 2147549484U) /* 0x8001012c */ \
   XXX( HRES_CO_E_INVALIDSID        , 2147549485U) /* 0x8001012d */ \
   XXX( HRES_CO_E_CONVERSIONFAILED        , 2147549486U) /* 0x8001012e */ \
   XXX( HRES_CO_E_NOMATCHINGSIDFOUND        , 2147549487U) /* 0x8001012f */ \
   XXX( HRES_CO_E_LOOKUPACCSIDFAILED        , 2147549488U) /* 0x80010130 */ \
   XXX( HRES_CO_E_NOMATCHINGNAMEFOUND        , 2147549489U) /* 0x80010131 */ \
   XXX( HRES_CO_E_LOOKUPACCNAMEFAILED        , 2147549490U) /* 0x80010132 */ \
   XXX( HRES_CO_E_SETSERLHNDLFAILED        , 2147549491U) /* 0x80010133 */ \
   XXX( HRES_CO_E_FAILEDTOGETWINDIR        , 2147549492U) /* 0x80010134 */ \
   XXX( HRES_CO_E_PATHTOOLONG        , 2147549493U) /* 0x80010135 */ \
   XXX( HRES_CO_E_FAILEDTOGENUUID        , 2147549494U) /* 0x80010136 */ \
   XXX( HRES_CO_E_FAILEDTOCREATEFILE        , 2147549495U) /* 0x80010137 */ \
   XXX( HRES_CO_E_FAILEDTOCLOSEHANDLE        , 2147549496U) /* 0x80010138 */ \
   XXX( HRES_CO_E_EXCEEDSYSACLLIMIT        , 2147549497U) /* 0x80010139 */ \
   XXX( HRES_CO_E_ACESINWRONGORDER        , 2147549498U) /* 0x8001013a */ \
   XXX( HRES_CO_E_INCOMPATIBLESTREAMVERSION     , 2147549499U) /* 0x8001013b */ \
   XXX( HRES_CO_E_FAILEDTOOPENPROCESSTOKEN     , 2147549500U) /* 0x8001013c */ \
   XXX( HRES_CO_E_DECODEFAILED        , 2147549501U) /* 0x8001013d */ \
   XXX( HRES_CO_E_ACNOTINITIALIZED        , 2147549503U) /* 0x8001013f */ \
   XXX( HRES_CO_E_CANCEL_DISABLED        , 2147549504U) /* 0x80010140 */ \
   XXX( HRES_RPC_E_UNEXPECTED        , 2147614719U) /* 0x8001ffff */ \
   XXX( HRES_DISP_E_UNKNOWNINTERFACE        , 2147614721U) /* 0x80020001 */ \
   XXX( HRES_DISP_E_MEMBERNOTFOUND        , 2147614723U) /* 0x80020003 */ \
   XXX( HRES_DISP_E_PARAMNOTFOUND        , 2147614724U) /* 0x80020004 */ \
   XXX( HRES_DISP_E_TYPEMISMATCH        , 2147614725U) /* 0x80020005 */ \
   XXX( HRES_DISP_E_UNKNOWNNAME        , 2147614726U) /* 0x80020006 */ \
   XXX( HRES_DISP_E_NONAMEDARGS        , 2147614727U) /* 0x80020007 */ \
   XXX( HRES_DISP_E_BADVARTYPE        , 2147614728U) /* 0x80020008 */ \
   XXX( HRES_DISP_E_EXCEPTION        , 2147614729U) /* 0x80020009 */ \
   XXX( HRES_DISP_E_OVERFLOW        , 2147614730U) /* 0x8002000a */ \
   XXX( HRES_DISP_E_BADINDEX        , 2147614731U) /* 0x8002000b */ \
   XXX( HRES_DISP_E_UNKNOWNLCID        , 2147614732U) /* 0x8002000c */ \
   XXX( HRES_DISP_E_ARRAYISLOCKED        , 2147614733U) /* 0x8002000d */ \
   XXX( HRES_DISP_E_BADPARAMCOUNT        , 2147614734U) /* 0x8002000e */ \
   XXX( HRES_DISP_E_PARAMNOTOPTIONAL        , 2147614735U) /* 0x8002000f */ \
   XXX( HRES_DISP_E_BADCALLEE        , 2147614736U) /* 0x80020010 */ \
   XXX( HRES_DISP_E_NOTACOLLECTION        , 2147614737U) /* 0x80020011 */ \
   XXX( HRES_DISP_E_DIVBYZERO        , 2147614738U) /* 0x80020012 */ \
   XXX( HRES_DISP_E_BUFFERTOOSMALL        , 2147614739U) /* 0x80020013 */ \
   XXX( HRES_TYPE_E_BUFFERTOOSMALL        , 2147647510U) /* 0x80028016 */ \
   XXX( HRES_TYPE_E_FIELDNOTFOUND        , 2147647511U) /* 0x80028017 */ \
   XXX( HRES_TYPE_E_INVDATAREAD        , 2147647512U) /* 0x80028018 */ \
   XXX( HRES_TYPE_E_UNSUPFORMAT        , 2147647513U) /* 0x80028019 */ \
   XXX( HRES_TYPE_E_REGISTRYACCESS        , 2147647516U) /* 0x8002801c */ \
   XXX( HRES_TYPE_E_LIBNOTREGISTERED        , 2147647517U) /* 0x8002801d */ \
   XXX( HRES_TYPE_E_UNDEFINEDTYPE        , 2147647527U) /* 0x80028027 */ \
   XXX( HRES_TYPE_E_QUALIFIEDNAMEDISALLOWED     , 2147647528U) /* 0x80028028 */ \
   XXX( HRES_TYPE_E_INVALIDSTATE        , 2147647529U) /* 0x80028029 */ \
   XXX( HRES_TYPE_E_WRONGTYPEKIND        , 2147647530U) /* 0x8002802a */ \
   XXX( HRES_TYPE_E_ELEMENTNOTFOUND        , 2147647531U) /* 0x8002802b */ \
   XXX( HRES_TYPE_E_AMBIGUOUSNAME        , 2147647532U) /* 0x8002802c */ \
   XXX( HRES_TYPE_E_NAMECONFLICT        , 2147647533U) /* 0x8002802d */ \
   XXX( HRES_TYPE_E_UNKNOWNLCID        , 2147647534U) /* 0x8002802e */ \
   XXX( HRES_TYPE_E_DLLFUNCTIONNOTFOUND        , 2147647535U) /* 0x8002802f */ \
   XXX( HRES_TYPE_E_BADMODULEKIND        , 2147649725U) /* 0x800288bd */ \
   XXX( HRES_TYPE_E_SIZETOOBIG        , 2147649733U) /* 0x800288c5 */ \
   XXX( HRES_TYPE_E_DUPLICATEID        , 2147649734U) /* 0x800288c6 */ \
   XXX( HRES_TYPE_E_INVALIDID        , 2147649743U) /* 0x800288cf */ \
   XXX( HRES_TYPE_E_TYPEMISMATCH        , 2147650720U) /* 0x80028ca0 */ \
   XXX( HRES_TYPE_E_OUTOFBOUNDS        , 2147650721U) /* 0x80028ca1 */ \
   XXX( HRES_TYPE_E_IOERROR        , 2147650722U) /* 0x80028ca2 */ \
   XXX( HRES_TYPE_E_CANTCREATETMPFILE        , 2147650723U) /* 0x80028ca3 */ \
   XXX( HRES_TYPE_E_CANTLOADLIBRARY        , 2147654730U) /* 0x80029c4a */ \
   XXX( HRES_TYPE_E_INCONSISTENTPROPFUNCS     , 2147654787U) /* 0x80029c83 */ \
   XXX( HRES_TYPE_E_CIRCULARTYPE        , 2147654788U) /* 0x80029c84 */ \
   XXX( HRES_STG_E_INVALIDFUNCTION        , 2147680257U) /* 0x80030001 */ \
   XXX( HRES_STG_E_FILENOTFOUND        , 2147680258U) /* 0x80030002 */ \
   XXX( HRES_STG_E_PATHNOTFOUND        , 2147680259U) /* 0x80030003 */ \
   XXX( HRES_STG_E_TOOMANYOPENFILES        , 2147680260U) /* 0x80030004 */ \
   XXX( HRES_STG_E_ACCESSDENIED        , 2147680261U) /* 0x80030005 */ \
   XXX( HRES_STG_E_INVALIDHANDLE        , 2147680262U) /* 0x80030006 */ \
   XXX( HRES_STG_E_INSUFFICIENTMEMORY        , 2147680264U) /* 0x80030008 */ \
   XXX( HRES_STG_E_INVALIDPOINTER        , 2147680265U) /* 0x80030009 */ \
   XXX( HRES_STG_E_NOMOREFILES        , 2147680274U) /* 0x80030012 */ \
   XXX( HRES_STG_E_DISKISWRITEPROTECTED        , 2147680275U) /* 0x80030013 */ \
   XXX( HRES_STG_E_SEEKERROR        , 2147680281U) /* 0x80030019 */ \
   XXX( HRES_STG_E_WRITEFAULT        , 2147680285U) /* 0x8003001d */ \
   XXX( HRES_STG_E_READFAULT        , 2147680286U) /* 0x8003001e */ \
   XXX( HRES_STG_E_SHAREVIOLATION        , 2147680288U) /* 0x80030020 */ \
   XXX( HRES_STG_E_LOCKVIOLATION        , 2147680289U) /* 0x80030021 */ \
   XXX( HRES_STG_E_FILEALREADYEXISTS        , 2147680336U) /* 0x80030050 */ \
   XXX( HRES_STG_E_INVALIDPARAMETER        , 2147680343U) /* 0x80030057 */ \
   XXX( HRES_STG_E_MEDIUMFULL        , 2147680368U) /* 0x80030070 */ \
   XXX( HRES_STG_E_PROPSETMISMATCHED        , 2147680496U) /* 0x800300f0 */ \
   XXX( HRES_STG_E_ABNORMALAPIEXIT        , 2147680506U) /* 0x800300fa */ \
   XXX( HRES_STG_E_INVALIDHEADER        , 2147680507U) /* 0x800300fb */ \
   XXX( HRES_STG_E_INVALIDNAME        , 2147680508U) /* 0x800300fc */ \
   XXX( HRES_STG_E_UNKNOWN        , 2147680509U) /* 0x800300fd */ \
   XXX( HRES_STG_E_UNIMPLEMENTEDFUNCTION     , 2147680510U) /* 0x800300fe */ \
   XXX( HRES_STG_E_INVALIDFLAG        , 2147680511U) /* 0x800300ff */ \
   XXX( HRES_STG_E_INUSE        , 2147680512U) /* 0x80030100 */ \
   XXX( HRES_STG_E_NOTCURRENT        , 2147680513U) /* 0x80030101 */ \
   XXX( HRES_STG_E_REVERTED        , 2147680514U) /* 0x80030102 */ \
   XXX( HRES_STG_E_CANTSAVE        , 2147680515U) /* 0x80030103 */ \
   XXX( HRES_STG_E_OLDFORMAT        , 2147680516U) /* 0x80030104 */ \
   XXX( HRES_STG_E_OLDDLL        , 2147680517U) /* 0x80030105 */ \
   XXX( HRES_STG_E_SHAREREQUIRED        , 2147680518U) /* 0x80030106 */ \
   XXX( HRES_STG_E_NOTFILEBASEDSTORAGE        , 2147680519U) /* 0x80030107 */ \
   XXX( HRES_STG_E_EXTANTMARSHALLINGS        , 2147680520U) /* 0x80030108 */ \
   XXX( HRES_STG_E_DOCFILECORRUPT        , 2147680521U) /* 0x80030109 */ \
   XXX( HRES_STG_E_BADBASEADDRESS        , 2147680528U) /* 0x80030110 */ \
   XXX( HRES_STG_E_DOCFILETOOLARGE        , 2147680529U) /* 0x80030111 */ \
   XXX( HRES_STG_E_NOTSIMPLEFORMAT        , 2147680530U) /* 0x80030112 */ \
   XXX( HRES_STG_E_INCOMPLETE        , 2147680769U) /* 0x80030201 */ \
   XXX( HRES_STG_E_TERMINATED        , 2147680770U) /* 0x80030202 */ \
   XXX( HRES_STG_E_STATUS_COPY_PROTECTION_FAILURE  , 2147681029U) /* 0x80030305 */ \
   XXX( HRES_STG_E_CSS_AUTHENTICATION_FAILURE     , 2147681030U) /* 0x80030306 */ \
   XXX( HRES_STG_E_CSS_KEY_NOT_PRESENT        , 2147681031U) /* 0x80030307 */ \
   XXX( HRES_STG_E_CSS_KEY_NOT_ESTABLISHED     , 2147681032U) /* 0x80030308 */ \
   XXX( HRES_STG_E_CSS_SCRAMBLED_SECTOR        , 2147681033U) /* 0x80030309 */ \
   XXX( HRES_STG_E_CSS_REGION_MISMATCH        , 2147681034U) /* 0x8003030a */ \
   XXX( HRES_STG_E_RESETS_EXHAUSTED        , 2147681035U) /* 0x8003030b */ \
   XXX( HRES_OLE_E_OLEVERB        , 2147745792U) /* 0x80040000 */ \
   XXX( HRES_OLE_E_ADVF           , 2147745793U) /* 0x80040001 */ \
   XXX( HRES_OLE_E_ENUM_NOMORE        , 2147745794U) /* 0x80040002 */ \
   XXX( HRES_OLE_E_ADVISENOTSUPPORTED        , 2147745795U) /* 0x80040003 */ \
   XXX( HRES_OLE_E_NOCONNECTION        , 2147745796U) /* 0x80040004 */ \
   XXX( HRES_OLE_E_NOTRUNNING        , 2147745797U) /* 0x80040005 */ \
   XXX( HRES_OLE_E_NOCACHE        , 2147745798U) /* 0x80040006 */ \
   XXX( HRES_OLE_E_BLANK        , 2147745799U) /* 0x80040007 */ \
   XXX( HRES_OLE_E_CLASSDIFF        , 2147745800U) /* 0x80040008 */ \
   XXX( HRES_OLE_E_CANT_GETMONIKER        , 2147745801U) /* 0x80040009 */ \
   XXX( HRES_OLE_E_CANT_BINDTOSOURCE        , 2147745802U) /* 0x8004000a */ \
   XXX( HRES_OLE_E_STATIC        , 2147745803U) /* 0x8004000b */ \
   XXX( HRES_OLE_E_PROMPTSAVECANCELLED        , 2147745804U) /* 0x8004000c */ \
   XXX( HRES_OLE_E_INVALIDRECT        , 2147745805U) /* 0x8004000d */ \
   XXX( HRES_OLE_E_WRONGCOMPOBJ        , 2147745806U) /* 0x8004000e */ \
   XXX( HRES_OLE_E_INVALIDHWND        , 2147745807U) /* 0x8004000f */ \
   XXX( HRES_OLE_E_NOT_INPLACEACTIVE        , 2147745808U) /* 0x80040010 */ \
   XXX( HRES_OLE_E_CANTCONVERT        , 2147745809U) /* 0x80040011 */ \
   XXX( HRES_OLE_E_NOSTORAGE        , 2147745810U) /* 0x80040012 */ \
   XXX( HRES_DV_E_FORMATETC        , 2147745892U) /* 0x80040064 */ \
   XXX( HRES_DV_E_DVTARGETDEVICE        , 2147745893U) /* 0x80040065 */ \
   XXX( HRES_DV_E_STGMEDIUM        , 2147745894U) /* 0x80040066 */ \
   XXX( HRES_DV_E_STATDATA        , 2147745895U) /* 0x80040067 */ \
   XXX( HRES_DV_E_LINDEX        , 2147745896U) /* 0x80040068 */ \
   XXX( HRES_DV_E_TYMED         , 2147745897U) /* 0x80040069 */ \
   XXX( HRES_DV_E_CLIPFORMAT        , 2147745898U) /* 0x8004006a */ \
   XXX( HRES_DV_E_DVASPECT        , 2147745899U) /* 0x8004006b */ \
   XXX( HRES_DV_E_DVTARGETDEVICE_SIZE        , 2147745900U) /* 0x8004006c */ \
   XXX( HRES_DV_E_NOIVIEWOBJECT        , 2147745901U) /* 0x8004006d */ \
   XXX( HRES_DRAGDROP_E_NOTREGISTERED        , 2147746048U) /* 0x80040100 */ \
   XXX( HRES_DRAGDROP_E_ALREADYREGISTERED     , 2147746049U) /* 0x80040101 */ \
   XXX( HRES_DRAGDROP_E_INVALIDHWND        , 2147746050U) /* 0x80040102 */ \
   XXX( HRES_CLASS_E_NOAGGREGATION        , 2147746064U) /* 0x80040110 */ \
   XXX( HRES_CLASS_E_CLASSNOTAVAILABLE        , 2147746065U) /* 0x80040111 */ \
   XXX( HRES_CLASS_E_NOTLICENSED        , 2147746066U) /* 0x80040112 */ \
   XXX( HRES_VIEW_E_DRAW        , 2147746112U) /* 0x80040140 */ \
   XXX( HRES_REGDB_E_READREGDB        , 2147746128U) /* 0x80040150 */ \
   XXX( HRES_REGDB_E_WRITEREGDB        , 2147746129U) /* 0x80040151 */ \
   XXX( HRES_REGDB_E_KEYMISSING        , 2147746130U) /* 0x80040152 */ \
   XXX( HRES_REGDB_E_INVALIDVALUE        , 2147746131U) /* 0x80040153 */ \
   XXX( HRES_REGDB_E_CLASSNOTREG        , 2147746132U) /* 0x80040154 */ \
   XXX( HRES_REGDB_E_IIDNOTREG        , 2147746133U) /* 0x80040155 */ \
   XXX( HRES_REGDB_E_BADTHREADINGMODEL        , 2147746134U) /* 0x80040156 */ \
   XXX( HRES_CAT_E_CATIDNOEXIST        , 2147746144U) /* 0x80040160 */ \
   XXX( HRES_CAT_E_NODESCRIPTION        , 2147746145U) /* 0x80040161 */ \
   XXX( HRES_CS_E_PACKAGE_NOTFOUND        , 2147746148U) /* 0x80040164 */ \
   XXX( HRES_CS_E_NOT_DELETABLE        , 2147746149U) /* 0x80040165 */ \
   XXX( HRES_CS_E_CLASS_NOTFOUND        , 2147746150U) /* 0x80040166 */ \
   XXX( HRES_CS_E_INVALID_VERSION        , 2147746151U) /* 0x80040167 */ \
   XXX( HRES_CS_E_NO_CLASSSTORE        , 2147746152U) /* 0x80040168 */ \
   XXX( HRES_CS_E_OBJECT_NOTFOUND        , 2147746153U) /* 0x80040169 */ \
   XXX( HRES_CS_E_OBJECT_ALREADY_EXISTS        , 2147746154U) /* 0x8004016a */ \
   XXX( HRES_CS_E_INVALID_PATH        , 2147746155U) /* 0x8004016b */ \
   XXX( HRES_CS_E_NETWORK_ERROR        , 2147746156U) /* 0x8004016c */ \
   XXX( HRES_CS_E_ADMIN_LIMIT_EXCEEDED        , 2147746157U) /* 0x8004016d */ \
   XXX( HRES_CS_E_SCHEMA_MISMATCH        , 2147746158U) /* 0x8004016e */ \
   XXX( HRES_CS_E_INTERNAL_ERROR        , 2147746159U) /* 0x8004016f */ \
   XXX( HRES_CACHE_E_NOCACHE_UPDATED        , 2147746160U) /* 0x80040170 */ \
   XXX( HRES_OLEOBJ_E_NOVERBS        , 2147746176U) /* 0x80040180 */ \
   XXX( HRES_OLEOBJ_E_INVALIDVERB        , 2147746177U) /* 0x80040181 */ \
   XXX( HRES_INPLACE_E_NOTUNDOABLE        , 2147746208U) /* 0x800401a0 */ \
   XXX( HRES_INPLACE_E_NOTOOLSPACE        , 2147746209U) /* 0x800401a1 */ \
   XXX( HRES_CONVERT10_E_OLESTREAM_GET        , 2147746240U) /* 0x800401c0 */ \
   XXX( HRES_CONVERT10_E_OLESTREAM_PUT        , 2147746241U) /* 0x800401c1 */ \
   XXX( HRES_CONVERT10_E_OLESTREAM_FMT        , 2147746242U) /* 0x800401c2 */ \
   XXX( HRES_CONVERT10_E_OLESTREAM_BITMAP_TO_DIB   , 2147746243U) /* 0x800401c3 */ \
   XXX( HRES_CONVERT10_E_STG_FMT        , 2147746244U) /* 0x800401c4 */ \
   XXX( HRES_CONVERT10_E_STG_NO_STD_STREAM     , 2147746245U) /* 0x800401c5 */ \
   XXX( HRES_CONVERT10_E_STG_DIB_TO_BITMAP     , 2147746246U) /* 0x800401c6 */ \
   XXX( HRES_CLIPBRD_E_CANT_OPEN        , 2147746256U) /* 0x800401d0 */ \
   XXX( HRES_CLIPBRD_E_CANT_EMPTY        , 2147746257U) /* 0x800401d1 */ \
   XXX( HRES_CLIPBRD_E_CANT_SET        , 2147746258U) /* 0x800401d2 */ \
   XXX( HRES_CLIPBRD_E_BAD_DATA        , 2147746259U) /* 0x800401d3 */ \
   XXX( HRES_CLIPBRD_E_CANT_CLOSE        , 2147746260U) /* 0x800401d4 */ \
   XXX( HRES_MK_E_CONNECTMANUALLY        , 2147746272U) /* 0x800401e0 */ \
   XXX( HRES_MK_E_EXCEEDEDDEADLINE        , 2147746273U) /* 0x800401e1 */ \
   XXX( HRES_MK_E_NEEDGENERIC        , 2147746274U) /* 0x800401e2 */ \
   XXX( HRES_MK_E_UNAVAILABLE        , 2147746275U) /* 0x800401e3 */ \
   XXX( HRES_MK_E_SYNTAX        , 2147746276U) /* 0x800401e4 */ \
   XXX( HRES_MK_E_NOOBJECT        , 2147746277U) /* 0x800401e5 */ \
   XXX( HRES_MK_E_INVALIDEXTENSION        , 2147746278U) /* 0x800401e6 */ \
   XXX( HRES_MK_E_INTERMEDIATEINTERFACENOTSUPPORTED , 2147746279U) /* 0x800401e7 */ \
   XXX( HRES_MK_E_NOTBINDABLE        , 2147746280U) /* 0x800401e8 */ \
   XXX( HRES_MK_E_NOTBOUND        , 2147746281U) /* 0x800401e9 */ \
   XXX( HRES_MK_E_CANTOPENFILE        , 2147746282U) /* 0x800401ea */ \
   XXX( HRES_MK_E_MUSTBOTHERUSER        , 2147746283U) /* 0x800401eb */ \
   XXX( HRES_MK_E_NOINVERSE        , 2147746284U) /* 0x800401ec */ \
   XXX( HRES_MK_E_NOSTORAGE        , 2147746285U) /* 0x800401ed */ \
   XXX( HRES_MK_E_NOPREFIX        , 2147746286U) /* 0x800401ee */ \
   XXX( HRES_MK_E_ENUMERATION_FAILED        , 2147746287U) /* 0x800401ef */ \
   XXX( HRES_CO_E_NOTINITIALIZED        , 2147746288U) /* 0x800401f0 */ \
   XXX( HRES_CO_E_ALREADYINITIALIZED        , 2147746289U) /* 0x800401f1 */ \
   XXX( HRES_CO_E_CANTDETERMINECLASS        , 2147746290U) /* 0x800401f2 */ \
   XXX( HRES_CO_E_CLASSSTRING        , 2147746291U) /* 0x800401f3 */ \
   XXX( HRES_CO_E_IIDSTRING        , 2147746292U) /* 0x800401f4 */ \
   XXX( HRES_CO_E_APPNOTFOUND        , 2147746293U) /* 0x800401f5 */ \
   XXX( HRES_CO_E_APPSINGLEUSE        , 2147746294U) /* 0x800401f6 */ \
   XXX( HRES_CO_E_ERRORINAPP        , 2147746295U) /* 0x800401f7 */ \
   XXX( HRES_CO_E_DLLNOTFOUND        , 2147746296U) /* 0x800401f8 */ \
   XXX( HRES_CO_E_ERRORINDLL        , 2147746297U) /* 0x800401f9 */ \
   XXX( HRES_CO_E_WRONGOSFORAPP        , 2147746298U) /* 0x800401fa */ \
   XXX( HRES_CO_E_OBJNOTREG        , 2147746299U) /* 0x800401fb */ \
   XXX( HRES_CO_E_OBJISREG        , 2147746300U) /* 0x800401fc */ \
   XXX( HRES_CO_E_OBJNOTCONNECTED        , 2147746301U) /* 0x800401fd */ \
   XXX( HRES_CO_E_APPDIDNTREG        , 2147746302U) /* 0x800401fe */ \
   XXX( HRES_CO_E_RELEASED        , 2147746303U) /* 0x800401ff */ \
   XXX( HRES_EVENT_E_ALL_SUBSCRIBERS_FAILED     , 2147746305U) /* 0x80040201 */ \
   XXX( HRES_EVENT_E_QUERYSYNTAX        , 2147746307U) /* 0x80040203 */ \
   XXX( HRES_EVENT_E_QUERYFIELD        , 2147746308U) /* 0x80040204 */ \
   XXX( HRES_EVENT_E_INTERNALEXCEPTION        , 2147746309U) /* 0x80040205 */ \
   XXX( HRES_EVENT_E_INTERNALERROR        , 2147746310U) /* 0x80040206 */ \
   XXX( HRES_EVENT_E_INVALID_PER_USER_SID     , 2147746311U) /* 0x80040207 */ \
   XXX( HRES_EVENT_E_USER_EXCEPTION        , 2147746312U) /* 0x80040208 */ \
   XXX( HRES_EVENT_E_TOO_MANY_METHODS        , 2147746313U) /* 0x80040209 */ \
   XXX( HRES_EVENT_E_MISSING_EVENTCLASS        , 2147746314U) /* 0x8004020a */ \
   XXX( HRES_EVENT_E_NOT_ALL_REMOVED        , 2147746315U) /* 0x8004020b */ \
   XXX( HRES_EVENT_E_COMPLUS_NOT_INSTALLED     , 2147746316U) /* 0x8004020c */ \
   XXX( HRES_EVENT_E_CANT_MODIFY_OR_DELETE_UNCONFIGURED_OBJECT, 2147746317U) /* 0x8004020d */ \
   XXX( HRES_EVENT_E_CANT_MODIFY_OR_DELETE_CONFIGURED_OBJECT, 2147746318U) /* 0x8004020e */ \
   XXX( HRES_EVENT_E_INVALID_EVENT_CLASS_PARTITION  , 2147746319U) /* 0x8004020f */ \
   XXX( HRES_EVENT_E_PER_USER_SID_NOT_LOGGED_ON     , 2147746320U) /* 0x80040210 */ \
   XXX( HRES_SCHED_E_TRIGGER_NOT_FOUND        , 2147750665U) /* 0x80041309 */ \
   XXX( HRES_SCHED_E_TASK_NOT_READY        , 2147750666U) /* 0x8004130a */ \
   XXX( HRES_SCHED_E_TASK_NOT_RUNNING        , 2147750667U) /* 0x8004130b */ \
   XXX( HRES_SCHED_E_SERVICE_NOT_INSTALLED     , 2147750668U) /* 0x8004130c */ \
   XXX( HRES_SCHED_E_CANNOT_OPEN_TASK        , 2147750669U) /* 0x8004130d */ \
   XXX( HRES_SCHED_E_INVALID_TASK        , 2147750670U) /* 0x8004130e */ \
   XXX( HRES_SCHED_E_ACCOUNT_INFORMATION_NOT_SET  , 2147750671U) /* 0x8004130f */ \
   XXX( HRES_SCHED_E_ACCOUNT_NAME_NOT_FOUND     , 2147750672U) /* 0x80041310 */ \
   XXX( HRES_SCHED_E_ACCOUNT_DBASE_CORRUPT     , 2147750673U) /* 0x80041311 */ \
   XXX( HRES_SCHED_E_NO_SECURITY_SERVICES     , 2147750674U) /* 0x80041312 */ \
   XXX( HRES_SCHED_E_UNKNOWN_OBJECT_VERSION     , 2147750675U) /* 0x80041313 */ \
   XXX( HRES_SCHED_E_UNSUPPORTED_ACCOUNT_OPTION     , 2147750676U) /* 0x80041314 */ \
   XXX( HRES_SCHED_E_SERVICE_NOT_RUNNING     , 2147750677U) /* 0x80041315 */ \
   XXX( HRES_SCHED_E_UNEXPECTEDNODE        , 2147750678U) /* 0x80041316 */ \
   XXX( HRES_SCHED_E_NAMESPACE        , 2147750679U) /* 0x80041317 */ \
   XXX( HRES_SCHED_E_INVALIDVALUE        , 2147750680U) /* 0x80041318 */ \
   XXX( HRES_SCHED_E_MISSINGNODE        , 2147750681U) /* 0x80041319 */ \
   XXX( HRES_SCHED_E_MALFORMEDXML        , 2147750682U) /* 0x8004131a */ \
   XXX( HRES_SCHED_E_TOO_MANY_NODES        , 2147750685U) /* 0x8004131d */ \
   XXX( HRES_SCHED_E_PAST_END_BOUNDARY        , 2147750686U) /* 0x8004131e */ \
   XXX( HRES_SCHED_E_ALREADY_RUNNING        , 2147750687U) /* 0x8004131f */ \
   XXX( HRES_SCHED_E_USER_NOT_LOGGED_ON        , 2147750688U) /* 0x80041320 */ \
   XXX( HRES_SCHED_E_INVALID_TASK_HASH        , 2147750689U) /* 0x80041321 */ \
   XXX( HRES_SCHED_E_SERVICE_NOT_AVAILABLE     , 2147750690U) /* 0x80041322 */ \
   XXX( HRES_SCHED_E_SERVICE_TOO_BUSY        , 2147750691U) /* 0x80041323 */ \
   XXX( HRES_SCHED_E_TASK_ATTEMPTED        , 2147750692U) /* 0x80041324 */ \
   XXX( HRES_XACT_E_ALREADYOTHERSINGLEPHASE     , 2147799040U) /* 0x8004d000 */ \
   XXX( HRES_XACT_E_CANTRETAIN        , 2147799041U) /* 0x8004d001 */ \
   XXX( HRES_XACT_E_COMMITFAILED        , 2147799042U) /* 0x8004d002 */ \
   XXX( HRES_XACT_E_COMMITPREVENTED        , 2147799043U) /* 0x8004d003 */ \
   XXX( HRES_XACT_E_HEURISTICABORT        , 2147799044U) /* 0x8004d004 */ \
   XXX( HRES_XACT_E_HEURISTICCOMMIT        , 2147799045U) /* 0x8004d005 */ \
   XXX( HRES_XACT_E_HEURISTICDAMAGE        , 2147799046U) /* 0x8004d006 */ \
   XXX( HRES_XACT_E_HEURISTICDANGER        , 2147799047U) /* 0x8004d007 */ \
   XXX( HRES_XACT_E_ISOLATIONLEVEL        , 2147799048U) /* 0x8004d008 */ \
   XXX( HRES_XACT_E_NOASYNC        , 2147799049U) /* 0x8004d009 */ \
   XXX( HRES_XACT_E_NOENLIST        , 2147799050U) /* 0x8004d00a */ \
   XXX( HRES_XACT_E_NOISORETAIN        , 2147799051U) /* 0x8004d00b */ \
   XXX( HRES_XACT_E_NORESOURCE        , 2147799052U) /* 0x8004d00c */ \
   XXX( HRES_XACT_E_NOTCURRENT        , 2147799053U) /* 0x8004d00d */ \
   XXX( HRES_XACT_E_NOTRANSACTION        , 2147799054U) /* 0x8004d00e */ \
   XXX( HRES_XACT_E_NOTSUPPORTED        , 2147799055U) /* 0x8004d00f */ \
   XXX( HRES_XACT_E_UNKNOWNRMGRID        , 2147799056U) /* 0x8004d010 */ \
   XXX( HRES_XACT_E_WRONGSTATE        , 2147799057U) /* 0x8004d011 */ \
   XXX( HRES_XACT_E_WRONGUOW        , 2147799058U) /* 0x8004d012 */ \
   XXX( HRES_XACT_E_XTIONEXISTS        , 2147799059U) /* 0x8004d013 */ \
   XXX( HRES_XACT_E_NOIMPORTOBJECT        , 2147799060U) /* 0x8004d014 */ \
   XXX( HRES_XACT_E_INVALIDCOOKIE        , 2147799061U) /* 0x8004d015 */ \
   XXX( HRES_XACT_E_INDOUBT        , 2147799062U) /* 0x8004d016 */ \
   XXX( HRES_XACT_E_NOTIMEOUT        , 2147799063U) /* 0x8004d017 */ \
   XXX( HRES_XACT_E_ALREADYINPROGRESS        , 2147799064U) /* 0x8004d018 */ \
   XXX( HRES_XACT_E_ABORTED        , 2147799065U) /* 0x8004d019 */ \
   XXX( HRES_XACT_E_LOGFULL        , 2147799066U) /* 0x8004d01a */ \
   XXX( HRES_XACT_E_TMNOTAVAILABLE        , 2147799067U) /* 0x8004d01b */ \
   XXX( HRES_XACT_E_CONNECTION_DOWN        , 2147799068U) /* 0x8004d01c */ \
   XXX( HRES_XACT_E_CONNECTION_DENIED        , 2147799069U) /* 0x8004d01d */ \
   XXX( HRES_XACT_E_REENLISTTIMEOUT        , 2147799070U) /* 0x8004d01e */ \
   XXX( HRES_XACT_E_TIP_CONNECT_FAILED        , 2147799071U) /* 0x8004d01f */ \
   XXX( HRES_XACT_E_TIP_PROTOCOL_ERROR        , 2147799072U) /* 0x8004d020 */ \
   XXX( HRES_XACT_E_TIP_PULL_FAILED        , 2147799073U) /* 0x8004d021 */ \
   XXX( HRES_XACT_E_DEST_TMNOTAVAILABLE        , 2147799074U) /* 0x8004d022 */ \
   XXX( HRES_XACT_E_TIP_DISABLED        , 2147799075U) /* 0x8004d023 */ \
   XXX( HRES_XACT_E_NETWORK_TX_DISABLED        , 2147799076U) /* 0x8004d024 */ \
   XXX( HRES_XACT_E_PARTNER_NETWORK_TX_DISABLED     , 2147799077U) /* 0x8004d025 */ \
   XXX( HRES_XACT_E_XA_TX_DISABLED        , 2147799078U) /* 0x8004d026 */ \
   XXX( HRES_XACT_E_UNABLE_TO_READ_DTC_CONFIG     , 2147799079U) /* 0x8004d027 */ \
   XXX( HRES_XACT_E_UNABLE_TO_LOAD_DTC_PROXY     , 2147799080U) /* 0x8004d028 */ \
   XXX( HRES_XACT_E_ABORTING        , 2147799081U) /* 0x8004d029 */ \
   XXX( HRES_XACT_E_CLERKNOTFOUND        , 2147799168U) /* 0x8004d080 */ \
   XXX( HRES_XACT_E_CLERKEXISTS        , 2147799169U) /* 0x8004d081 */ \
   XXX( HRES_XACT_E_RECOVERYINPROGRESS        , 2147799170U) /* 0x8004d082 */ \
   XXX( HRES_XACT_E_TRANSACTIONCLOSED        , 2147799171U) /* 0x8004d083 */ \
   XXX( HRES_XACT_E_INVALIDLSN        , 2147799172U) /* 0x8004d084 */ \
   XXX( HRES_XACT_E_REPLAYREQUEST        , 2147799173U) /* 0x8004d085 */ \
   XXX( HRES_XACT_E_CONNECTION_REQUEST_DENIED     , 2147799296U) /* 0x8004d100 */ \
   XXX( HRES_XACT_E_TOOMANY_ENLISTMENTS        , 2147799297U) /* 0x8004d101 */ \
   XXX( HRES_XACT_E_DUPLICATE_GUID        , 2147799298U) /* 0x8004d102 */ \
   XXX( HRES_XACT_E_NOTSINGLEPHASE        , 2147799299U) /* 0x8004d103 */ \
   XXX( HRES_XACT_E_RECOVERYALREADYDONE        , 2147799300U) /* 0x8004d104 */ \
   XXX( HRES_XACT_E_PROTOCOL        , 2147799301U) /* 0x8004d105 */ \
   XXX( HRES_XACT_E_RM_FAILURE        , 2147799302U) /* 0x8004d106 */ \
   XXX( HRES_XACT_E_RECOVERY_FAILED        , 2147799303U) /* 0x8004d107 */ \
   XXX( HRES_XACT_E_LU_NOT_FOUND        , 2147799304U) /* 0x8004d108 */ \
   XXX( HRES_XACT_E_DUPLICATE_LU        , 2147799305U) /* 0x8004d109 */ \
   XXX( HRES_XACT_E_LU_NOT_CONNECTED        , 2147799306U) /* 0x8004d10a */ \
   XXX( HRES_XACT_E_DUPLICATE_TRANSID        , 2147799307U) /* 0x8004d10b */ \
   XXX( HRES_XACT_E_LU_BUSY        , 2147799308U) /* 0x8004d10c */ \
   XXX( HRES_XACT_E_LU_NO_RECOVERY_PROCESS     , 2147799309U) /* 0x8004d10d */ \
   XXX( HRES_XACT_E_LU_DOWN        , 2147799310U) /* 0x8004d10e */ \
   XXX( HRES_XACT_E_LU_RECOVERING        , 2147799311U) /* 0x8004d10f */ \
   XXX( HRES_XACT_E_LU_RECOVERY_MISMATCH     , 2147799312U) /* 0x8004d110 */ \
   XXX( HRES_XACT_E_RM_UNAVAILABLE        , 2147799313U) /* 0x8004d111 */ \
   XXX( HRES_CONTEXT_E_ABORTED        , 2147803138U) /* 0x8004e002 */ \
   XXX( HRES_CONTEXT_E_ABORTING        , 2147803139U) /* 0x8004e003 */ \
   XXX( HRES_CONTEXT_E_NOCONTEXT        , 2147803140U) /* 0x8004e004 */ \
   XXX( HRES_CONTEXT_E_WOULD_DEADLOCK        , 2147803141U) /* 0x8004e005 */ \
   XXX( HRES_CONTEXT_E_SYNCH_TIMEOUT        , 2147803142U) /* 0x8004e006 */ \
   XXX( HRES_CONTEXT_E_OLDREF        , 2147803143U) /* 0x8004e007 */ \
   XXX( HRES_CONTEXT_E_ROLENOTFOUND        , 2147803148U) /* 0x8004e00c */ \
   XXX( HRES_CONTEXT_E_TMNOTAVAILABLE        , 2147803151U) /* 0x8004e00f */ \
   XXX( HRES_CO_E_ACTIVATIONFAILED        , 2147803169U) /* 0x8004e021 */ \
   XXX( HRES_CO_E_ACTIVATIONFAILED_EVENTLOGGED     , 2147803170U) /* 0x8004e022 */ \
   XXX( HRES_CO_E_ACTIVATIONFAILED_CATALOGERROR     , 2147803171U) /* 0x8004e023 */ \
   XXX( HRES_CO_E_ACTIVATIONFAILED_TIMEOUT     , 2147803172U) /* 0x8004e024 */ \
   XXX( HRES_CO_E_INITIALIZATIONFAILED        , 2147803173U) /* 0x8004e025 */ \
   XXX( HRES_CONTEXT_E_NOJIT        , 2147803174U) /* 0x8004e026 */ \
   XXX( HRES_CONTEXT_E_NOTRANSACTION        , 2147803175U) /* 0x8004e027 */ \
   XXX( HRES_CO_E_THREADINGMODEL_CHANGED     , 2147803176U) /* 0x8004e028 */ \
   XXX( HRES_CO_E_NOIISINTRINSICS        , 2147803177U) /* 0x8004e029 */ \
   XXX( HRES_CO_E_NOCOOKIES        , 2147803178U) /* 0x8004e02a */ \
   XXX( HRES_CO_E_DBERROR        , 2147803179U) /* 0x8004e02b */ \
   XXX( HRES_CO_E_NOTPOOLED        , 2147803180U) /* 0x8004e02c */ \
   XXX( HRES_CO_E_NOTCONSTRUCTED        , 2147803181U) /* 0x8004e02d */ \
   XXX( HRES_CO_E_NOSYNCHRONIZATION        , 2147803182U) /* 0x8004e02e */ \
   XXX( HRES_CO_E_ISOLEVELMISMATCH        , 2147803183U) /* 0x8004e02f */ \
   XXX( HRES_CO_E_CALL_OUT_OF_TX_SCOPE_NOT_ALLOWED  , 2147803184U) /* 0x8004e030 */ \
   XXX( HRES_CO_E_EXIT_TRANSACTION_SCOPE_NOT_CALLED  , 2147803185U) /* 0x8004e031 */ \
   XXX( HRES_E_ACCESSDENIED        , 2147942405U) /* 0x80070005 */ \
   XXX( HRES_E_OUTOFMEMORY        , 2147942414U) /* 0x8007000e */ \
   XXX( HRES_ERROR_NOT_SUPPORTED        , 2147942450U) /* 0x80070032 */ \
   XXX( HRES_E_INVALIDARG        , 2147942487U) /* 0x80070057 */ \
   XXX( HRES_CO_E_CLASS_CREATE_FAILED        , 2148007937U) /* 0x80080001 */ \
   XXX( HRES_CO_E_SCM_ERROR        , 2148007938U) /* 0x80080002 */ \
   XXX( HRES_CO_E_SCM_RPC_FAILURE        , 2148007939U) /* 0x80080003 */ \
   XXX( HRES_CO_E_BAD_PATH        , 2148007940U) /* 0x80080004 */ \
   XXX( HRES_CO_E_SERVER_EXEC_FAILURE        , 2148007941U) /* 0x80080005 */ \
   XXX( HRES_CO_E_OBJSRV_RPC_FAILURE        , 2148007942U) /* 0x80080006 */ \
   XXX( HRES_MK_E_NO_NORMALIZED        , 2148007943U) /* 0x80080007 */ \
   XXX( HRES_CO_E_SERVER_STOPPING        , 2148007944U) /* 0x80080008 */ \
   XXX( HRES_MEM_E_INVALID_ROOT        , 2148007945U) /* 0x80080009 */ \
   XXX( HRES_MEM_E_INVALID_LINK        , 2148007952U) /* 0x80080010 */ \
   XXX( HRES_MEM_E_INVALID_SIZE        , 2148007953U) /* 0x80080011 */ \
   XXX( HRES_CO_E_MISSING_DISPLAYNAME        , 2148007957U) /* 0x80080015 */ \
   XXX( HRES_CO_E_RUNAS_VALUE_MUST_BE_AAA     , 2148007958U) /* 0x80080016 */ \
   XXX( HRES_CO_E_ELEVATION_DISABLED        , 2148007959U) /* 0x80080017 */ \
   XXX( HRES_NTE_BAD_UID        , 2148073473U) /* 0x80090001 */ \
   XXX( HRES_NTE_BAD_HASH        , 2148073474U) /* 0x80090002 */ \
   XXX( HRES_NTE_BAD_KEY        , 2148073475U) /* 0x80090003 */ \
   XXX( HRES_NTE_BAD_LEN        , 2148073476U) /* 0x80090004 */ \
   XXX( HRES_NTE_BAD_DATA        , 2148073477U) /* 0x80090005 */ \
   XXX( HRES_NTE_BAD_SIGNATURE        , 2148073478U) /* 0x80090006 */ \
   XXX( HRES_NTE_BAD_VER        , 2148073479U) /* 0x80090007 */ \
   XXX( HRES_NTE_BAD_ALGID        , 2148073480U) /* 0x80090008 */ \
   XXX( HRES_NTE_BAD_FLAGS        , 2148073481U) /* 0x80090009 */ \
   XXX( HRES_NTE_BAD_TYPE        , 2148073482U) /* 0x8009000a */ \
   XXX( HRES_NTE_BAD_KEY_STATE        , 2148073483U) /* 0x8009000b */ \
   XXX( HRES_NTE_BAD_HASH_STATE        , 2148073484U) /* 0x8009000c */ \
   XXX( HRES_NTE_NO_KEY          , 2148073485U) /* 0x8009000d */ \
   XXX( HRES_NTE_NO_MEMORY        , 2148073486U) /* 0x8009000e */ \
   XXX( HRES_NTE_EXISTS          , 2148073487U) /* 0x8009000f */ \
   XXX( HRES_NTE_PERM          , 2148073488U) /* 0x80090010 */ \
   XXX( HRES_NTE_NOT_FOUND        , 2148073489U) /* 0x80090011 */ \
   XXX( HRES_NTE_DOUBLE_ENCRYPT        , 2148073490U) /* 0x80090012 */ \
   XXX( HRES_NTE_BAD_PROVIDER        , 2148073491U) /* 0x80090013 */ \
   XXX( HRES_NTE_BAD_PROV_TYPE        , 2148073492U) /* 0x80090014 */ \
   XXX( HRES_NTE_BAD_PUBLIC_KEY        , 2148073493U) /* 0x80090015 */ \
   XXX( HRES_NTE_BAD_KEYSET        , 2148073494U) /* 0x80090016 */ \
   XXX( HRES_NTE_PROV_TYPE_NOT_DEF        , 2148073495U) /* 0x80090017 */ \
   XXX( HRES_NTE_PROV_TYPE_ENTRY_BAD        , 2148073496U) /* 0x80090018 */ \
   XXX( HRES_NTE_KEYSET_NOT_DEF        , 2148073497U) /* 0x80090019 */ \
   XXX( HRES_NTE_KEYSET_ENTRY_BAD        , 2148073498U) /* 0x8009001a */ \
   XXX( HRES_NTE_PROV_TYPE_NO_MATCH        , 2148073499U) /* 0x8009001b */ \
   XXX( HRES_NTE_SIGNATURE_FILE_BAD        , 2148073500U) /* 0x8009001c */ \
   XXX( HRES_NTE_PROVIDER_DLL_FAIL        , 2148073501U) /* 0x8009001d */ \
   XXX( HRES_NTE_PROV_DLL_NOT_FOUND        , 2148073502U) /* 0x8009001e */ \
   XXX( HRES_NTE_BAD_KEYSET_PARAM        , 2148073503U) /* 0x8009001f */ \
   XXX( HRES_NTE_FAIL           , 2148073504U) /* 0x80090020 */ \
   XXX( HRES_NTE_SYS_ERR        , 2148073505U) /* 0x80090021 */ \
   XXX( HRES_NTE_SILENT_CONTEXT        , 2148073506U) /* 0x80090022 */ \
   XXX( HRES_NTE_TOKEN_KEYSET_STORAGE_FULL     , 2148073507U) /* 0x80090023 */ \
   XXX( HRES_NTE_TEMPORARY_PROFILE        , 2148073508U) /* 0x80090024 */ \
   XXX( HRES_NTE_FIXEDPARAMETER        , 2148073509U) /* 0x80090025 */ \
   XXX( HRES_NTE_INVALID_HANDLE        , 2148073510U) /* 0x80090026 */ \
   XXX( HRES_NTE_INVALID_PARAMETER        , 2148073511U) /* 0x80090027 */ \
   XXX( HRES_NTE_BUFFER_TOO_SMALL        , 2148073512U) /* 0x80090028 */ \
   XXX( HRES_NTE_NOT_SUPPORTED        , 2148073513U) /* 0x80090029 */ \
   XXX( HRES_NTE_NO_MORE_ITEMS        , 2148073514U) /* 0x8009002a */ \
   XXX( HRES_NTE_BUFFERS_OVERLAP        , 2148073515U) /* 0x8009002b */ \
   XXX( HRES_NTE_DECRYPTION_FAILURE        , 2148073516U) /* 0x8009002c */ \
   XXX( HRES_NTE_INTERNAL_ERROR        , 2148073517U) /* 0x8009002d */ \
   XXX( HRES_NTE_UI_REQUIRED        , 2148073518U) /* 0x8009002e */ \
   XXX( HRES_NTE_HMAC_NOT_SUPPORTED        , 2148073519U) /* 0x8009002f */ \
   XXX( HRES_SEC_E_INSUFFICIENT_MEMORY        , 2148074240U) /* 0x80090300 */ \
   XXX( HRES_SEC_E_INVALID_HANDLE        , 2148074241U) /* 0x80090301 */ \
   XXX( HRES_SEC_E_UNSUPPORTED_FUNCTION        , 2148074242U) /* 0x80090302 */ \
   XXX( HRES_SEC_E_TARGET_UNKNOWN        , 2148074243U) /* 0x80090303 */ \
   XXX( HRES_SEC_E_INTERNAL_ERROR        , 2148074244U) /* 0x80090304 */ \
   XXX( HRES_SEC_E_SECPKG_NOT_FOUND        , 2148074245U) /* 0x80090305 */ \
   XXX( HRES_SEC_E_NOT_OWNER        , 2148074246U) /* 0x80090306 */ \
   XXX( HRES_SEC_E_CANNOT_INSTALL        , 2148074247U) /* 0x80090307 */ \
   XXX( HRES_SEC_E_INVALID_TOKEN        , 2148074248U) /* 0x80090308 */ \
   XXX( HRES_SEC_E_CANNOT_PACK        , 2148074249U) /* 0x80090309 */ \
   XXX( HRES_SEC_E_QOP_NOT_SUPPORTED        , 2148074250U) /* 0x8009030a */ \
   XXX( HRES_SEC_E_NO_IMPERSONATION        , 2148074251U) /* 0x8009030b */ \
   XXX( HRES_SEC_E_LOGON_DENIED        , 2148074252U) /* 0x8009030c */ \
   XXX( HRES_SEC_E_UNKNOWN_CREDENTIALS        , 2148074253U) /* 0x8009030d */ \
   XXX( HRES_SEC_E_NO_CREDENTIALS        , 2148074254U) /* 0x8009030e */ \
   XXX( HRES_SEC_E_MESSAGE_ALTERED        , 2148074255U) /* 0x8009030f */ \
   XXX( HRES_SEC_E_OUT_OF_SEQUENCE        , 2148074256U) /* 0x80090310 */ \
   XXX( HRES_SEC_E_NO_AUTHENTICATING_AUTHORITY     , 2148074257U) /* 0x80090311 */ \
   XXX( HRES_SEC_E_BAD_PKGID        , 2148074262U) /* 0x80090316 */ \
   XXX( HRES_SEC_E_CONTEXT_EXPIRED        , 2148074263U) /* 0x80090317 */ \
   XXX( HRES_SEC_E_INCOMPLETE_MESSAGE        , 2148074264U) /* 0x80090318 */ \
   XXX( HRES_SEC_E_INCOMPLETE_CREDENTIALS     , 2148074272U) /* 0x80090320 */ \
   XXX( HRES_SEC_E_BUFFER_TOO_SMALL        , 2148074273U) /* 0x80090321 */ \
   XXX( HRES_SEC_E_WRONG_PRINCIPAL        , 2148074274U) /* 0x80090322 */ \
   XXX( HRES_SEC_E_TIME_SKEW        , 2148074276U) /* 0x80090324 */ \
   XXX( HRES_SEC_E_UNTRUSTED_ROOT        , 2148074277U) /* 0x80090325 */ \
   XXX( HRES_SEC_E_ILLEGAL_MESSAGE        , 2148074278U) /* 0x80090326 */ \
   XXX( HRES_SEC_E_CERT_UNKNOWN        , 2148074279U) /* 0x80090327 */ \
   XXX( HRES_SEC_E_CERT_EXPIRED        , 2148074280U) /* 0x80090328 */ \
   XXX( HRES_SEC_E_ENCRYPT_FAILURE        , 2148074281U) /* 0x80090329 */ \
   XXX( HRES_SEC_E_DECRYPT_FAILURE        , 2148074288U) /* 0x80090330 */ \
   XXX( HRES_SEC_E_ALGORITHM_MISMATCH        , 2148074289U) /* 0x80090331 */ \
   XXX( HRES_SEC_E_SECURITY_QOS_FAILED        , 2148074290U) /* 0x80090332 */ \
   XXX( HRES_SEC_E_UNFINISHED_CONTEXT_DELETED     , 2148074291U) /* 0x80090333 */ \
   XXX( HRES_SEC_E_NO_TGT_REPLY        , 2148074292U) /* 0x80090334 */ \
   XXX( HRES_SEC_E_NO_IP_ADDRESSES        , 2148074293U) /* 0x80090335 */ \
   XXX( HRES_SEC_E_WRONG_CREDENTIAL_HANDLE     , 2148074294U) /* 0x80090336 */ \
   XXX( HRES_SEC_E_CRYPTO_SYSTEM_INVALID     , 2148074295U) /* 0x80090337 */ \
   XXX( HRES_SEC_E_MAX_REFERRALS_EXCEEDED     , 2148074296U) /* 0x80090338 */ \
   XXX( HRES_SEC_E_MUST_BE_KDC        , 2148074297U) /* 0x80090339 */ \
   XXX( HRES_SEC_E_STRONG_CRYPTO_NOT_SUPPORTED     , 2148074298U) /* 0x8009033a */ \
   XXX( HRES_SEC_E_TOO_MANY_PRINCIPALS        , 2148074299U) /* 0x8009033b */ \
   XXX( HRES_SEC_E_NO_PA_DATA        , 2148074300U) /* 0x8009033c */ \
   XXX( HRES_SEC_E_PKINIT_NAME_MISMATCH        , 2148074301U) /* 0x8009033d */ \
   XXX( HRES_SEC_E_SMARTCARD_LOGON_REQUIRED     , 2148074302U) /* 0x8009033e */ \
   XXX( HRES_SEC_E_SHUTDOWN_IN_PROGRESS        , 2148074303U) /* 0x8009033f */ \
   XXX( HRES_SEC_E_KDC_INVALID_REQUEST        , 2148074304U) /* 0x80090340 */ \
   XXX( HRES_SEC_E_KDC_UNABLE_TO_REFER        , 2148074305U) /* 0x80090341 */ \
   XXX( HRES_SEC_E_KDC_UNKNOWN_ETYPE        , 2148074306U) /* 0x80090342 */ \
   XXX( HRES_SEC_E_UNSUPPORTED_PREAUTH        , 2148074307U) /* 0x80090343 */ \
   XXX( HRES_SEC_E_DELEGATION_REQUIRED        , 2148074309U) /* 0x80090345 */ \
   XXX( HRES_SEC_E_BAD_BINDINGS        , 2148074310U) /* 0x80090346 */ \
   XXX( HRES_SEC_E_MULTIPLE_ACCOUNTS        , 2148074311U) /* 0x80090347 */ \
   XXX( HRES_SEC_E_NO_KERB_KEY        , 2148074312U) /* 0x80090348 */ \
   XXX( HRES_SEC_E_CERT_WRONG_USAGE        , 2148074313U) /* 0x80090349 */ \
   XXX( HRES_SEC_E_DOWNGRADE_DETECTED        , 2148074320U) /* 0x80090350 */ \
   XXX( HRES_SEC_E_SMARTCARD_CERT_REVOKED     , 2148074321U) /* 0x80090351 */ \
   XXX( HRES_SEC_E_ISSUING_CA_UNTRUSTED        , 2148074322U) /* 0x80090352 */ \
   XXX( HRES_SEC_E_REVOCATION_OFFLINE_C        , 2148074323U) /* 0x80090353 */ \
   XXX( HRES_SEC_E_PKINIT_CLIENT_FAILURE     , 2148074324U) /* 0x80090354 */ \
   XXX( HRES_SEC_E_SMARTCARD_CERT_EXPIRED     , 2148074325U) /* 0x80090355 */ \
   XXX( HRES_SEC_E_NO_S4U_PROT_SUPPORT        , 2148074326U) /* 0x80090356 */ \
   XXX( HRES_SEC_E_CROSSREALM_DELEGATION_FAILURE  , 2148074327U) /* 0x80090357 */ \
   XXX( HRES_SEC_E_REVOCATION_OFFLINE_KDC     , 2148074328U) /* 0x80090358 */ \
   XXX( HRES_SEC_E_ISSUING_CA_UNTRUSTED_KDC     , 2148074329U) /* 0x80090359 */ \
   XXX( HRES_SEC_E_KDC_CERT_EXPIRED        , 2148074330U) /* 0x8009035a */ \
   XXX( HRES_SEC_E_KDC_CERT_REVOKED        , 2148074331U) /* 0x8009035b */ \
   XXX( HRES_SEC_E_INVALID_PARAMETER        , 2148074333U) /* 0x8009035d */ \
   XXX( HRES_SEC_E_DELEGATION_POLICY        , 2148074334U) /* 0x8009035e */ \
   XXX( HRES_SEC_E_POLICY_NLTM_ONLY        , 2148074335U) /* 0x8009035f */ \
   XXX( HRES_CRYPT_E_MSG_ERROR        , 2148077569U) /* 0x80091001 */ \
   XXX( HRES_CRYPT_E_UNKNOWN_ALGO        , 2148077570U) /* 0x80091002 */ \
   XXX( HRES_CRYPT_E_OID_FORMAT        , 2148077571U) /* 0x80091003 */ \
   XXX( HRES_CRYPT_E_INVALID_MSG_TYPE        , 2148077572U) /* 0x80091004 */ \
   XXX( HRES_CRYPT_E_UNEXPECTED_ENCODING     , 2148077573U) /* 0x80091005 */ \
   XXX( HRES_CRYPT_E_AUTH_ATTR_MISSING        , 2148077574U) /* 0x80091006 */ \
   XXX( HRES_CRYPT_E_HASH_VALUE        , 2148077575U) /* 0x80091007 */ \
   XXX( HRES_CRYPT_E_INVALID_INDEX        , 2148077576U) /* 0x80091008 */ \
   XXX( HRES_CRYPT_E_ALREADY_DECRYPTED        , 2148077577U) /* 0x80091009 */ \
   XXX( HRES_CRYPT_E_NOT_DECRYPTED        , 2148077578U) /* 0x8009100a */ \
   XXX( HRES_CRYPT_E_RECIPIENT_NOT_FOUND     , 2148077579U) /* 0x8009100b */ \
   XXX( HRES_CRYPT_E_CONTROL_TYPE        , 2148077580U) /* 0x8009100c */ \
   XXX( HRES_CRYPT_E_ISSUER_SERIALNUMBER     , 2148077581U) /* 0x8009100d */ \
   XXX( HRES_CRYPT_E_SIGNER_NOT_FOUND        , 2148077582U) /* 0x8009100e */ \
   XXX( HRES_CRYPT_E_ATTRIBUTES_MISSING        , 2148077583U) /* 0x8009100f */ \
   XXX( HRES_CRYPT_E_STREAM_MSG_NOT_READY     , 2148077584U) /* 0x80091010 */ \
   XXX( HRES_CRYPT_E_STREAM_INSUFFICIENT_DATA     , 2148077585U) /* 0x80091011 */ \
   XXX( HRES_CRYPT_E_BAD_LEN        , 2148081665U) /* 0x80092001 */ \
   XXX( HRES_CRYPT_E_BAD_ENCODE        , 2148081666U) /* 0x80092002 */ \
   XXX( HRES_CRYPT_E_FILE_ERROR        , 2148081667U) /* 0x80092003 */ \
   XXX( HRES_CRYPT_E_NOT_FOUND        , 2148081668U) /* 0x80092004 */ \
   XXX( HRES_CRYPT_E_EXISTS        , 2148081669U) /* 0x80092005 */ \
   XXX( HRES_CRYPT_E_NO_PROVIDER        , 2148081670U) /* 0x80092006 */ \
   XXX( HRES_CRYPT_E_SELF_SIGNED        , 2148081671U) /* 0x80092007 */ \
   XXX( HRES_CRYPT_E_DELETED_PREV        , 2148081672U) /* 0x80092008 */ \
   XXX( HRES_CRYPT_E_NO_MATCH        , 2148081673U) /* 0x80092009 */ \
   XXX( HRES_CRYPT_E_UNEXPECTED_MSG_TYPE     , 2148081674U) /* 0x8009200a */ \
   XXX( HRES_CRYPT_E_NO_KEY_PROPERTY        , 2148081675U) /* 0x8009200b */ \
   XXX( HRES_CRYPT_E_NO_DECRYPT_CERT        , 2148081676U) /* 0x8009200c */ \
   XXX( HRES_CRYPT_E_BAD_MSG        , 2148081677U) /* 0x8009200d */ \
   XXX( HRES_CRYPT_E_NO_SIGNER        , 2148081678U) /* 0x8009200e */ \
   XXX( HRES_CRYPT_E_PENDING_CLOSE        , 2148081679U) /* 0x8009200f */ \
   XXX( HRES_CRYPT_E_REVOKED        , 2148081680U) /* 0x80092010 */ \
   XXX( HRES_CRYPT_E_NO_REVOCATION_DLL        , 2148081681U) /* 0x80092011 */ \
   XXX( HRES_CRYPT_E_NO_REVOCATION_CHECK     , 2148081682U) /* 0x80092012 */ \
   XXX( HRES_CRYPT_E_REVOCATION_OFFLINE        , 2148081683U) /* 0x80092013 */ \
   XXX( HRES_CRYPT_E_NOT_IN_REVOCATION_DATABASE     , 2148081684U) /* 0x80092014 */ \
   XXX( HRES_CRYPT_E_INVALID_NUMERIC_STRING     , 2148081696U) /* 0x80092020 */ \
   XXX( HRES_CRYPT_E_INVALID_PRINTABLE_STRING     , 2148081697U) /* 0x80092021 */ \
   XXX( HRES_CRYPT_E_INVALID_IA5_STRING        , 2148081698U) /* 0x80092022 */ \
   XXX( HRES_CRYPT_E_INVALID_X500_STRING     , 2148081699U) /* 0x80092023 */ \
   XXX( HRES_CRYPT_E_NOT_CHAR_STRING        , 2148081700U) /* 0x80092024 */ \
   XXX( HRES_CRYPT_E_FILERESIZED        , 2148081701U) /* 0x80092025 */ \
   XXX( HRES_CRYPT_E_SECURITY_SETTINGS        , 2148081702U) /* 0x80092026 */ \
   XXX( HRES_CRYPT_E_NO_VERIFY_USAGE_DLL     , 2148081703U) /* 0x80092027 */ \
   XXX( HRES_CRYPT_E_NO_VERIFY_USAGE_CHECK     , 2148081704U) /* 0x80092028 */ \
   XXX( HRES_CRYPT_E_VERIFY_USAGE_OFFLINE     , 2148081705U) /* 0x80092029 */ \
   XXX( HRES_CRYPT_E_NOT_IN_CTL        , 2148081706U) /* 0x8009202a */ \
   XXX( HRES_CRYPT_E_NO_TRUSTED_SIGNER        , 2148081707U) /* 0x8009202b */ \
   XXX( HRES_CRYPT_E_MISSING_PUBKEY_PARA     , 2148081708U) /* 0x8009202c */ \
   XXX( HRES_CRYPT_E_OSS_ERROR        , 2148085760U) /* 0x80093000 */ \
   XXX( HRES_OSS_MORE_BUF        , 2148085761U) /* 0x80093001 */ \
   XXX( HRES_OSS_NEGATIVE_UINTEGER        , 2148085762U) /* 0x80093002 */ \
   XXX( HRES_OSS_PDU_RANGE        , 2148085763U) /* 0x80093003 */ \
   XXX( HRES_OSS_MORE_INPUT        , 2148085764U) /* 0x80093004 */ \
   XXX( HRES_OSS_DATA_ERROR        , 2148085765U) /* 0x80093005 */ \
   XXX( HRES_OSS_BAD_ARG        , 2148085766U) /* 0x80093006 */ \
   XXX( HRES_OSS_BAD_VERSION        , 2148085767U) /* 0x80093007 */ \
   XXX( HRES_OSS_OUT_MEMORY        , 2148085768U) /* 0x80093008 */ \
   XXX( HRES_OSS_PDU_MISMATCH        , 2148085769U) /* 0x80093009 */ \
   XXX( HRES_OSS_LIMITED        , 2148085770U) /* 0x8009300a */ \
   XXX( HRES_OSS_BAD_PTR        , 2148085771U) /* 0x8009300b */ \
   XXX( HRES_OSS_BAD_TIME        , 2148085772U) /* 0x8009300c */ \
   XXX( HRES_OSS_INDEFINITE_NOT_SUPPORTED     , 2148085773U) /* 0x8009300d */ \
   XXX( HRES_OSS_MEM_ERROR        , 2148085774U) /* 0x8009300e */ \
   XXX( HRES_OSS_BAD_TABLE        , 2148085775U) /* 0x8009300f */ \
   XXX( HRES_OSS_TOO_LONG        , 2148085776U) /* 0x80093010 */ \
   XXX( HRES_OSS_CONSTRAINT_VIOLATED        , 2148085777U) /* 0x80093011 */ \
   XXX( HRES_OSS_FATAL_ERROR        , 2148085778U) /* 0x80093012 */ \
   XXX( HRES_OSS_ACCESS_SERIALIZATION_ERROR     , 2148085779U) /* 0x80093013 */ \
   XXX( HRES_OSS_NULL_TBL        , 2148085780U) /* 0x80093014 */ \
   XXX( HRES_OSS_NULL_FCN        , 2148085781U) /* 0x80093015 */ \
   XXX( HRES_OSS_BAD_ENCRULES        , 2148085782U) /* 0x80093016 */ \
   XXX( HRES_OSS_UNAVAIL_ENCRULES        , 2148085783U) /* 0x80093017 */ \
   XXX( HRES_OSS_CANT_OPEN_TRACE_WINDOW        , 2148085784U) /* 0x80093018 */ \
   XXX( HRES_OSS_UNIMPLEMENTED        , 2148085785U) /* 0x80093019 */ \
   XXX( HRES_OSS_OID_DLL_NOT_LINKED        , 2148085786U) /* 0x8009301a */ \
   XXX( HRES_OSS_CANT_OPEN_TRACE_FILE        , 2148085787U) /* 0x8009301b */ \
   XXX( HRES_OSS_TRACE_FILE_ALREADY_OPEN     , 2148085788U) /* 0x8009301c */ \
   XXX( HRES_OSS_TABLE_MISMATCH        , 2148085789U) /* 0x8009301d */ \
   XXX( HRES_OSS_TYPE_NOT_SUPPORTED        , 2148085790U) /* 0x8009301e */ \
   XXX( HRES_OSS_REAL_DLL_NOT_LINKED        , 2148085791U) /* 0x8009301f */ \
   XXX( HRES_OSS_REAL_CODE_NOT_LINKED        , 2148085792U) /* 0x80093020 */ \
   XXX( HRES_OSS_OUT_OF_RANGE        , 2148085793U) /* 0x80093021 */ \
   XXX( HRES_OSS_COPIER_DLL_NOT_LINKED        , 2148085794U) /* 0x80093022 */ \
   XXX( HRES_OSS_CONSTRAINT_DLL_NOT_LINKED     , 2148085795U) /* 0x80093023 */ \
   XXX( HRES_OSS_COMPARATOR_DLL_NOT_LINKED     , 2148085796U) /* 0x80093024 */ \
   XXX( HRES_OSS_COMPARATOR_CODE_NOT_LINKED     , 2148085797U) /* 0x80093025 */ \
   XXX( HRES_OSS_MEM_MGR_DLL_NOT_LINKED        , 2148085798U) /* 0x80093026 */ \
   XXX( HRES_OSS_PDV_DLL_NOT_LINKED        , 2148085799U) /* 0x80093027 */ \
   XXX( HRES_OSS_PDV_CODE_NOT_LINKED        , 2148085800U) /* 0x80093028 */ \
   XXX( HRES_OSS_API_DLL_NOT_LINKED        , 2148085801U) /* 0x80093029 */ \
   XXX( HRES_OSS_BERDER_DLL_NOT_LINKED        , 2148085802U) /* 0x8009302a */ \
   XXX( HRES_OSS_PER_DLL_NOT_LINKED        , 2148085803U) /* 0x8009302b */ \
   XXX( HRES_OSS_OPEN_TYPE_ERROR        , 2148085804U) /* 0x8009302c */ \
   XXX( HRES_OSS_MUTEX_NOT_CREATED        , 2148085805U) /* 0x8009302d */ \
   XXX( HRES_OSS_CANT_CLOSE_TRACE_FILE        , 2148085806U) /* 0x8009302e */ \
   XXX( HRES_CRYPT_E_ASN1_ERROR        , 2148086016U) /* 0x80093100 */ \
   XXX( HRES_CRYPT_E_ASN1_INTERNAL        , 2148086017U) /* 0x80093101 */ \
   XXX( HRES_CRYPT_E_ASN1_EOD        , 2148086018U) /* 0x80093102 */ \
   XXX( HRES_CRYPT_E_ASN1_CORRUPT        , 2148086019U) /* 0x80093103 */ \
   XXX( HRES_CRYPT_E_ASN1_LARGE        , 2148086020U) /* 0x80093104 */ \
   XXX( HRES_CRYPT_E_ASN1_CONSTRAINT        , 2148086021U) /* 0x80093105 */ \
   XXX( HRES_CRYPT_E_ASN1_MEMORY        , 2148086022U) /* 0x80093106 */ \
   XXX( HRES_CRYPT_E_ASN1_OVERFLOW        , 2148086023U) /* 0x80093107 */ \
   XXX( HRES_CRYPT_E_ASN1_BADPDU        , 2148086024U) /* 0x80093108 */ \
   XXX( HRES_CRYPT_E_ASN1_BADARGS        , 2148086025U) /* 0x80093109 */ \
   XXX( HRES_CRYPT_E_ASN1_BADREAL        , 2148086026U) /* 0x8009310a */ \
   XXX( HRES_CRYPT_E_ASN1_BADTAG        , 2148086027U) /* 0x8009310b */ \
   XXX( HRES_CRYPT_E_ASN1_CHOICE        , 2148086028U) /* 0x8009310c */ \
   XXX( HRES_CRYPT_E_ASN1_RULE        , 2148086029U) /* 0x8009310d */ \
   XXX( HRES_CRYPT_E_ASN1_UTF8        , 2148086030U) /* 0x8009310e */ \
   XXX( HRES_CRYPT_E_ASN1_PDU_TYPE        , 2148086067U) /* 0x80093133 */ \
   XXX( HRES_CRYPT_E_ASN1_NYI        , 2148086068U) /* 0x80093134 */ \
   XXX( HRES_CRYPT_E_ASN1_EXTENDED        , 2148086273U) /* 0x80093201 */ \
   XXX( HRES_CRYPT_E_ASN1_NOEOD        , 2148086274U) /* 0x80093202 */ \
   XXX( HRES_CERTSRV_E_BAD_REQUESTSUBJECT     , 2148089857U) /* 0x80094001 */ \
   XXX( HRES_CERTSRV_E_NO_REQUEST        , 2148089858U) /* 0x80094002 */ \
   XXX( HRES_CERTSRV_E_BAD_REQUESTSTATUS     , 2148089859U) /* 0x80094003 */ \
   XXX( HRES_CERTSRV_E_PROPERTY_EMPTY        , 2148089860U) /* 0x80094004 */ \
   XXX( HRES_CERTSRV_E_INVALID_CA_CERTIFICATE     , 2148089861U) /* 0x80094005 */ \
   XXX( HRES_CERTSRV_E_SERVER_SUSPENDED        , 2148089862U) /* 0x80094006 */ \
   XXX( HRES_CERTSRV_E_ENCODING_LENGTH        , 2148089863U) /* 0x80094007 */ \
   XXX( HRES_CERTSRV_E_ROLECONFLICT        , 2148089864U) /* 0x80094008 */ \
   XXX( HRES_CERTSRV_E_RESTRICTEDOFFICER     , 2148089865U) /* 0x80094009 */ \
   XXX( HRES_CERTSRV_E_KEY_ARCHIVAL_NOT_CONFIGURED  , 2148089866U) /* 0x8009400a */ \
   XXX( HRES_CERTSRV_E_NO_VALID_KRA        , 2148089867U) /* 0x8009400b */ \
   XXX( HRES_CERTSRV_E_BAD_REQUEST_KEY_ARCHIVAL     , 2148089868U) /* 0x8009400c */ \
   XXX( HRES_CERTSRV_E_NO_CAADMIN_DEFINED     , 2148089869U) /* 0x8009400d */ \
   XXX( HRES_CERTSRV_E_BAD_RENEWAL_CERT_ATTRIBUTE  , 2148089870U) /* 0x8009400e */ \
   XXX( HRES_CERTSRV_E_NO_DB_SESSIONS        , 2148089871U) /* 0x8009400f */ \
   XXX( HRES_CERTSRV_E_ALIGNMENT_FAULT        , 2148089872U) /* 0x80094010 */ \
   XXX( HRES_CERTSRV_E_ENROLL_DENIED        , 2148089873U) /* 0x80094011 */ \
   XXX( HRES_CERTSRV_E_TEMPLATE_DENIED        , 2148089874U) /* 0x80094012 */ \
   XXX( HRES_CERTSRV_E_DOWNLEVEL_DC_SSL_OR_UPGRADE  , 2148089875U) /* 0x80094013 */ \
   XXX( HRES_CERTSRV_E_UNSUPPORTED_CERT_TYPE     , 2148091904U) /* 0x80094800 */ \
   XXX( HRES_CERTSRV_E_NO_CERT_TYPE        , 2148091905U) /* 0x80094801 */ \
   XXX( HRES_CERTSRV_E_TEMPLATE_CONFLICT     , 2148091906U) /* 0x80094802 */ \
   XXX( HRES_CERTSRV_E_SUBJECT_ALT_NAME_REQUIRED , 2148091907U) /* 0x80094803 */ \
   XXX( HRES_CERTSRV_E_ARCHIVED_KEY_REQUIRED     , 2148091908U) /* 0x80094804 */ \
   XXX( HRES_CERTSRV_E_SMIME_REQUIRED        , 2148091909U) /* 0x80094805 */ \
   XXX( HRES_CERTSRV_E_BAD_RENEWAL_SUBJECT     , 2148091910U) /* 0x80094806 */ \
   XXX( HRES_CERTSRV_E_BAD_TEMPLATE_VERSION     , 2148091911U) /* 0x80094807 */ \
   XXX( HRES_CERTSRV_E_TEMPLATE_POLICY_REQUIRED     , 2148091912U) /* 0x80094808 */ \
   XXX( HRES_CERTSRV_E_SIGNATURE_POLICY_REQUIRED , 2148091913U) /* 0x80094809 */ \
   XXX( HRES_CERTSRV_E_SIGNATURE_COUNT        , 2148091914U) /* 0x8009480a */ \
   XXX( HRES_CERTSRV_E_SIGNATURE_REJECTED     , 2148091915U) /* 0x8009480b */ \
   XXX( HRES_CERTSRV_E_ISSUANCE_POLICY_REQUIRED     , 2148091916U) /* 0x8009480c */ \
   XXX( HRES_CERTSRV_E_SUBJECT_UPN_REQUIRED     , 2148091917U) /* 0x8009480d */ \
   XXX( HRES_CERTSRV_E_SUBJECT_DIRECTORY_GUID_REQUIRED  , 2148091918U) /* 0x8009480e */ \
   XXX( HRES_CERTSRV_E_SUBJECT_DNS_REQUIRED     , 2148091919U) /* 0x8009480f */ \
   XXX( HRES_CERTSRV_E_ARCHIVED_KEY_UNEXPECTED     , 2148091920U) /* 0x80094810 */ \
   XXX( HRES_CERTSRV_E_KEY_LENGTH        , 2148091921U) /* 0x80094811 */ \
   XXX( HRES_CERTSRV_E_SUBJECT_EMAIL_REQUIRED     , 2148091922U) /* 0x80094812 */ \
   XXX( HRES_CERTSRV_E_UNKNOWN_CERT_TYPE     , 2148091923U) /* 0x80094813 */ \
   XXX( HRES_CERTSRV_E_CERT_TYPE_OVERLAP     , 2148091924U) /* 0x80094814 */ \
   XXX( HRES_CERTSRV_E_TOO_MANY_SIGNATURES     , 2148091925U) /* 0x80094815 */ \
   XXX( HRES_CERTSRV_E_RENEWAL_BAD_PUBLIC_KEY     , 2148091926U) /* 0x80094816 */ \
   XXX( HRES_CERTSRV_E_INVALID_EK        , 2148091927U) /* 0x80094817 */ \
   XXX( HRES_CERTSRV_E_KEY_ATTESTATION        , 2148091930U) /* 0x8009481a */ \
   XXX( HRES_XENROLL_E_KEY_NOT_EXPORTABLE     , 2148093952U) /* 0x80095000 */ \
   XXX( HRES_XENROLL_E_CANNOT_ADD_ROOT_CERT     , 2148093953U) /* 0x80095001 */ \
   XXX( HRES_XENROLL_E_RESPONSE_KA_HASH_NOT_FOUND   , 2148093954U) /* 0x80095002 */ \
   XXX( HRES_XENROLL_E_RESPONSE_UNEXPECTED_KA_HASH  , 2148093955U) /* 0x80095003 */ \
   XXX( HRES_XENROLL_E_RESPONSE_KA_HASH_MISMATCH    , 2148093956U) /* 0x80095004 */ \
   XXX( HRES_XENROLL_E_KEYSPEC_SMIME_MISMATCH     , 2148093957U) /* 0x80095005 */ \
   XXX( HRES_TRUST_E_SYSTEM_ERROR        , 2148098049U) /* 0x80096001 */ \
   XXX( HRES_TRUST_E_NO_SIGNER_CERT        , 2148098050U) /* 0x80096002 */ \
   XXX( HRES_TRUST_E_COUNTER_SIGNER        , 2148098051U) /* 0x80096003 */ \
   XXX( HRES_TRUST_E_CERT_SIGNATURE        , 2148098052U) /* 0x80096004 */ \
   XXX( HRES_TRUST_E_TIME_STAMP        , 2148098053U) /* 0x80096005 */ \
   XXX( HRES_TRUST_E_BAD_DIGEST        , 2148098064U) /* 0x80096010 */ \
   XXX( HRES_TRUST_E_BASIC_CONSTRAINTS        , 2148098073U) /* 0x80096019 */ \
   XXX( HRES_TRUST_E_FINANCIAL_CRITERIA        , 2148098078U) /* 0x8009601e */ \
   XXX( HRES_MSSIPOTF_E_OUTOFMEMRANGE        , 2148102145U) /* 0x80097001 */ \
   XXX( HRES_MSSIPOTF_E_CANTGETOBJECT        , 2148102146U) /* 0x80097002 */ \
   XXX( HRES_MSSIPOTF_E_NOHEADTABLE        , 2148102147U) /* 0x80097003 */ \
   XXX( HRES_MSSIPOTF_E_BAD_MAGICNUMBER        , 2148102148U) /* 0x80097004 */ \
   XXX( HRES_MSSIPOTF_E_BAD_OFFSET_TABLE     , 2148102149U) /* 0x80097005 */ \
   XXX( HRES_MSSIPOTF_E_TABLE_TAGORDER        , 2148102150U) /* 0x80097006 */ \
   XXX( HRES_MSSIPOTF_E_TABLE_LONGWORD        , 2148102151U) /* 0x80097007 */ \
   XXX( HRES_MSSIPOTF_E_BAD_FIRST_TABLE_PLACEMENT  , 2148102152U) /* 0x80097008 */ \
   XXX( HRES_MSSIPOTF_E_TABLES_OVERLAP        , 2148102153U) /* 0x80097009 */ \
   XXX( HRES_MSSIPOTF_E_TABLE_PADBYTES        , 2148102154U) /* 0x8009700a */ \
   XXX( HRES_MSSIPOTF_E_FILETOOSMALL        , 2148102155U) /* 0x8009700b */ \
   XXX( HRES_MSSIPOTF_E_TABLE_CHECKSUM        , 2148102156U) /* 0x8009700c */ \
   XXX( HRES_MSSIPOTF_E_FILE_CHECKSUM        , 2148102157U) /* 0x8009700d */ \
   XXX( HRES_MSSIPOTF_E_FAILED_POLICY        , 2148102160U) /* 0x80097010 */ \
   XXX( HRES_MSSIPOTF_E_FAILED_HINTS_CHECK     , 2148102161U) /* 0x80097011 */ \
   XXX( HRES_MSSIPOTF_E_NOT_OPENTYPE        , 2148102162U) /* 0x80097012 */ \
   XXX( HRES_MSSIPOTF_E_FILE        , 2148102163U) /* 0x80097013 */ \
   XXX( HRES_MSSIPOTF_E_CRYPT        , 2148102164U) /* 0x80097014 */ \
   XXX( HRES_MSSIPOTF_E_BADVERSION        , 2148102165U) /* 0x80097015 */ \
   XXX( HRES_MSSIPOTF_E_DSIG_STRUCTURE        , 2148102166U) /* 0x80097016 */ \
   XXX( HRES_MSSIPOTF_E_PCONST_CHECK        , 2148102167U) /* 0x80097017 */ \
   XXX( HRES_MSSIPOTF_E_STRUCTURE        , 2148102168U) /* 0x80097018 */ \
   XXX( HRES_ERROR_CRED_REQUIRES_CONFIRMATION     , 2148102169U) /* 0x80097019 */ \
   XXX( HRES_TRUST_E_PROVIDER_UNKNOWN        , 2148204545U) /* 0x800b0001 */ \
   XXX( HRES_TRUST_E_ACTION_UNKNOWN        , 2148204546U) /* 0x800b0002 */ \
   XXX( HRES_TRUST_E_SUBJECT_FORM_UNKNOWN     , 2148204547U) /* 0x800b0003 */ \
   XXX( HRES_TRUST_E_SUBJECT_NOT_TRUSTED     , 2148204548U) /* 0x800b0004 */ \
   XXX( HRES_DIGSIG_E_ENCODE        , 2148204549U) /* 0x800b0005 */ \
   XXX( HRES_DIGSIG_E_DECODE        , 2148204550U) /* 0x800b0006 */ \
   XXX( HRES_DIGSIG_E_EXTENSIBILITY        , 2148204551U) /* 0x800b0007 */ \
   XXX( HRES_DIGSIG_E_CRYPTO        , 2148204552U) /* 0x800b0008 */ \
   XXX( HRES_PERSIST_E_SIZEDEFINITE        , 2148204553U) /* 0x800b0009 */ \
   XXX( HRES_PERSIST_E_SIZEINDEFINITE        , 2148204554U) /* 0x800b000a */ \
   XXX( HRES_PERSIST_E_NOTSELFSIZING        , 2148204555U) /* 0x800b000b */ \
   XXX( HRES_TRUST_E_NOSIGNATURE        , 2148204800U) /* 0x800b0100 */ \
   XXX( HRES_CERT_E_EXPIRED        , 2148204801U) /* 0x800b0101 */ \
   XXX( HRES_CERT_E_VALIDITYPERIODNESTING     , 2148204802U) /* 0x800b0102 */ \
   XXX( HRES_CERT_E_ROLE        , 2148204803U) /* 0x800b0103 */ \
   XXX( HRES_CERT_E_PATHLENCONST        , 2148204804U) /* 0x800b0104 */ \
   XXX( HRES_CERT_E_CRITICAL        , 2148204805U) /* 0x800b0105 */ \
   XXX( HRES_CERT_E_PURPOSE        , 2148204806U) /* 0x800b0106 */ \
   XXX( HRES_CERT_E_ISSUERCHAINING        , 2148204807U) /* 0x800b0107 */ \
   XXX( HRES_CERT_E_MALFORMED        , 2148204808U) /* 0x800b0108 */ \
   XXX( HRES_CERT_E_UNTRUSTEDROOT        , 2148204809U) /* 0x800b0109 */ \
   XXX( HRES_CERT_E_CHAINING        , 2148204810U) /* 0x800b010a */ \
   XXX( HRES_TRUST_E_FAIL        , 2148204811U) /* 0x800b010b */ \
   XXX( HRES_CERT_E_REVOKED        , 2148204812U) /* 0x800b010c */ \
   XXX( HRES_CERT_E_UNTRUSTEDTESTROOT        , 2148204813U) /* 0x800b010d */ \
   XXX( HRES_CERT_E_REVOCATION_FAILURE        , 2148204814U) /* 0x800b010e */ \
   XXX( HRES_CERT_E_CN_NO_MATCH        , 2148204815U) /* 0x800b010f */ \
   XXX( HRES_CERT_E_WRONG_USAGE        , 2148204816U) /* 0x800b0110 */ \
   XXX( HRES_TRUST_E_EXPLICIT_DISTRUST        , 2148204817U) /* 0x800b0111 */ \
   XXX( HRES_CERT_E_UNTRUSTEDCA        , 2148204818U) /* 0x800b0112 */ \
   XXX( HRES_CERT_E_INVALID_POLICY        , 2148204819U) /* 0x800b0113 */ \
   XXX( HRES_CERT_E_INVALID_NAME        , 2148204820U) /* 0x800b0114 */ \
   XXX( HRES_NS_W_SERVER_BANDWIDTH_LIMIT     , 2148335619U) /* 0x800d0003 */ \
   XXX( HRES_NS_W_FILE_BANDWIDTH_LIMIT        , 2148335620U) /* 0x800d0004 */ \
   XXX( HRES_NS_W_UNKNOWN_EVENT        , 2148335712U) /* 0x800d0060 */ \
   XXX( HRES_NS_I_CATATONIC_FAILURE        , 2148336025U) /* 0x800d0199 */ \
   XXX( HRES_NS_I_CATATONIC_AUTO_UNFAIL        , 2148336026U) /* 0x800d019a */ \
   XXX( HRES_SPAPI_E_EXPECTED_SECTION_NAME     , 2148466688U) /* 0x800f0000 */ \
   XXX( HRES_SPAPI_E_BAD_SECTION_NAME_LINE     , 2148466689U) /* 0x800f0001 */ \
   XXX( HRES_SPAPI_E_SECTION_NAME_TOO_LONG     , 2148466690U) /* 0x800f0002 */ \
   XXX( HRES_SPAPI_E_GENERAL_SYNTAX        , 2148466691U) /* 0x800f0003 */ \
   XXX( HRES_SPAPI_E_WRONG_INF_STYLE        , 2148466944U) /* 0x800f0100 */ \
   XXX( HRES_SPAPI_E_SECTION_NOT_FOUND        , 2148466945U) /* 0x800f0101 */ \
   XXX( HRES_SPAPI_E_LINE_NOT_FOUND        , 2148466946U) /* 0x800f0102 */ \
   XXX( HRES_SPAPI_E_NO_BACKUP        , 2148466947U) /* 0x800f0103 */ \
   XXX( HRES_SPAPI_E_NO_ASSOCIATED_CLASS     , 2148467200U) /* 0x800f0200 */ \
   XXX( HRES_SPAPI_E_CLASS_MISMATCH        , 2148467201U) /* 0x800f0201 */ \
   XXX( HRES_SPAPI_E_DUPLICATE_FOUND        , 2148467202U) /* 0x800f0202 */ \
   XXX( HRES_SPAPI_E_NO_DRIVER_SELECTED        , 2148467203U) /* 0x800f0203 */ \
   XXX( HRES_SPAPI_E_KEY_DOES_NOT_EXIST        , 2148467204U) /* 0x800f0204 */ \
   XXX( HRES_SPAPI_E_INVALID_DEVINST_NAME     , 2148467205U) /* 0x800f0205 */ \
   XXX( HRES_SPAPI_E_INVALID_CLASS        , 2148467206U) /* 0x800f0206 */ \
   XXX( HRES_SPAPI_E_DEVINST_ALREADY_EXISTS     , 2148467207U) /* 0x800f0207 */ \
   XXX( HRES_SPAPI_E_DEVINFO_NOT_REGISTERED     , 2148467208U) /* 0x800f0208 */ \
   XXX( HRES_SPAPI_E_INVALID_REG_PROPERTY     , 2148467209U) /* 0x800f0209 */ \
   XXX( HRES_SPAPI_E_NO_INF        , 2148467210U) /* 0x800f020a */ \
   XXX( HRES_SPAPI_E_NO_SUCH_DEVINST        , 2148467211U) /* 0x800f020b */ \
   XXX( HRES_SPAPI_E_CANT_LOAD_CLASS_ICON     , 2148467212U) /* 0x800f020c */ \
   XXX( HRES_SPAPI_E_INVALID_CLASS_INSTALLER     , 2148467213U) /* 0x800f020d */ \
   XXX( HRES_SPAPI_E_DI_DO_DEFAULT        , 2148467214U) /* 0x800f020e */ \
   XXX( HRES_SPAPI_E_DI_NOFILECOPY        , 2148467215U) /* 0x800f020f */ \
   XXX( HRES_SPAPI_E_INVALID_HWPROFILE        , 2148467216U) /* 0x800f0210 */ \
   XXX( HRES_SPAPI_E_NO_DEVICE_SELECTED        , 2148467217U) /* 0x800f0211 */ \
   XXX( HRES_SPAPI_E_DEVINFO_LIST_LOCKED     , 2148467218U) /* 0x800f0212 */ \
   XXX( HRES_SPAPI_E_DEVINFO_DATA_LOCKED     , 2148467219U) /* 0x800f0213 */ \
   XXX( HRES_SPAPI_E_DI_BAD_PATH        , 2148467220U) /* 0x800f0214 */ \
   XXX( HRES_SPAPI_E_NO_CLASSINSTALL_PARAMS     , 2148467221U) /* 0x800f0215 */ \
   XXX( HRES_SPAPI_E_FILEQUEUE_LOCKED        , 2148467222U) /* 0x800f0216 */ \
   XXX( HRES_SPAPI_E_BAD_SERVICE_INSTALLSECT     , 2148467223U) /* 0x800f0217 */ \
   XXX( HRES_SPAPI_E_NO_CLASS_DRIVER_LIST     , 2148467224U) /* 0x800f0218 */ \
   XXX( HRES_SPAPI_E_NO_ASSOCIATED_SERVICE     , 2148467225U) /* 0x800f0219 */ \
   XXX( HRES_SPAPI_E_NO_DEFAULT_DEVICE_INTERFACE  , 2148467226U) /* 0x800f021a */ \
   XXX( HRES_SPAPI_E_DEVICE_INTERFACE_ACTIVE     , 2148467227U) /* 0x800f021b */ \
   XXX( HRES_SPAPI_E_DEVICE_INTERFACE_REMOVED     , 2148467228U) /* 0x800f021c */ \
   XXX( HRES_SPAPI_E_BAD_INTERFACE_INSTALLSECT     , 2148467229U) /* 0x800f021d */ \
   XXX( HRES_SPAPI_E_NO_SUCH_INTERFACE_CLASS     , 2148467230U) /* 0x800f021e */ \
   XXX( HRES_SPAPI_E_INVALID_REFERENCE_STRING     , 2148467231U) /* 0x800f021f */ \
   XXX( HRES_SPAPI_E_INVALID_MACHINENAME     , 2148467232U) /* 0x800f0220 */ \
   XXX( HRES_SPAPI_E_REMOTE_COMM_FAILURE     , 2148467233U) /* 0x800f0221 */ \
   XXX( HRES_SPAPI_E_MACHINE_UNAVAILABLE     , 2148467234U) /* 0x800f0222 */ \
   XXX( HRES_SPAPI_E_NO_CONFIGMGR_SERVICES     , 2148467235U) /* 0x800f0223 */ \
   XXX( HRES_SPAPI_E_INVALID_PROPPAGE_PROVIDER     , 2148467236U) /* 0x800f0224 */ \
   XXX( HRES_SPAPI_E_NO_SUCH_DEVICE_INTERFACE     , 2148467237U) /* 0x800f0225 */ \
   XXX( HRES_SPAPI_E_DI_POSTPROCESSING_REQUIRED     , 2148467238U) /* 0x800f0226 */ \
   XXX( HRES_SPAPI_E_INVALID_COINSTALLER     , 2148467239U) /* 0x800f0227 */ \
   XXX( HRES_SPAPI_E_NO_COMPAT_DRIVERS        , 2148467240U) /* 0x800f0228 */ \
   XXX( HRES_SPAPI_E_NO_DEVICE_ICON        , 2148467241U) /* 0x800f0229 */ \
   XXX( HRES_SPAPI_E_INVALID_INF_LOGCONFIG     , 2148467242U) /* 0x800f022a */ \
   XXX( HRES_SPAPI_E_DI_DONT_INSTALL        , 2148467243U) /* 0x800f022b */ \
   XXX( HRES_SPAPI_E_INVALID_FILTER_DRIVER     , 2148467244U) /* 0x800f022c */ \
   XXX( HRES_SPAPI_E_NON_WINDOWS_NT_DRIVER     , 2148467245U) /* 0x800f022d */ \
   XXX( HRES_SPAPI_E_NON_WINDOWS_DRIVER        , 2148467246U) /* 0x800f022e */ \
   XXX( HRES_SPAPI_E_NO_CATALOG_FOR_OEM_INF     , 2148467247U) /* 0x800f022f */ \
   XXX( HRES_SPAPI_E_DEVINSTALL_QUEUE_NONNATIVE     , 2148467248U) /* 0x800f0230 */ \
   XXX( HRES_SPAPI_E_NOT_DISABLEABLE        , 2148467249U) /* 0x800f0231 */ \
   XXX( HRES_SPAPI_E_CANT_REMOVE_DEVINST     , 2148467250U) /* 0x800f0232 */ \
   XXX( HRES_SPAPI_E_INVALID_TARGET        , 2148467251U) /* 0x800f0233 */ \
   XXX( HRES_SPAPI_E_DRIVER_NONNATIVE        , 2148467252U) /* 0x800f0234 */ \
   XXX( HRES_SPAPI_E_IN_WOW64        , 2148467253U) /* 0x800f0235 */ \
   XXX( HRES_SPAPI_E_SET_SYSTEM_RESTORE_POINT     , 2148467254U) /* 0x800f0236 */ \
   XXX( HRES_SPAPI_E_INCORRECTLY_COPIED_INF     , 2148467255U) /* 0x800f0237 */ \
   XXX( HRES_SPAPI_E_SCE_DISABLED        , 2148467256U) /* 0x800f0238 */ \
   XXX( HRES_SPAPI_E_UNKNOWN_EXCEPTION        , 2148467257U) /* 0x800f0239 */ \
   XXX( HRES_SPAPI_E_PNP_REGISTRY_ERROR        , 2148467258U) /* 0x800f023a */ \
   XXX( HRES_SPAPI_E_REMOTE_REQUEST_UNSUPPORTED     , 2148467259U) /* 0x800f023b */ \
   XXX( HRES_SPAPI_E_NOT_AN_INSTALLED_OEM_INF     , 2148467260U) /* 0x800f023c */ \
   XXX( HRES_SPAPI_E_INF_IN_USE_BY_DEVICES     , 2148467261U) /* 0x800f023d */ \
   XXX( HRES_SPAPI_E_DI_FUNCTION_OBSOLETE     , 2148467262U) /* 0x800f023e */ \
   XXX( HRES_SPAPI_E_NO_AUTHENTICODE_CATALOG     , 2148467263U) /* 0x800f023f */ \
   XXX( HRES_SPAPI_E_AUTHENTICODE_DISALLOWED     , 2148467264U) /* 0x800f0240 */ \
   XXX( HRES_SPAPI_E_AUTHENTICODE_TRUSTED_PUBLISHER , 2148467265U) /* 0x800f0241 */ \
   XXX( HRES_SPAPI_E_AUTHENTICODE_TRUST_NOT_ESTABLISHED, 2148467266U) /* 0x800f0242 */ \
   XXX( HRES_SPAPI_E_AUTHENTICODE_PUBLISHER_NOT_TRUSTED, 2148467267U) /* 0x800f0243 */ \
   XXX( HRES_SPAPI_E_SIGNATURE_OSATTRIBUTE_MISMATCH , 2148467268U) /* 0x800f0244 */ \
   XXX( HRES_SPAPI_E_ONLY_VALIDATE_VIA_AUTHENTICODE , 2148467269U) /* 0x800f0245 */ \
   XXX( HRES_SPAPI_E_DEVICE_INSTALLER_NOT_READY     , 2148467270U) /* 0x800f0246 */ \
   XXX( HRES_SPAPI_E_DRIVER_STORE_ADD_FAILED     , 2148467271U) /* 0x800f0247 */ \
   XXX( HRES_SPAPI_E_DEVICE_INSTALL_BLOCKED     , 2148467272U) /* 0x800f0248 */ \
   XXX( HRES_SPAPI_E_DRIVER_INSTALL_BLOCKED     , 2148467273U) /* 0x800f0249 */ \
   XXX( HRES_SPAPI_E_WRONG_INF_TYPE        , 2148467274U) /* 0x800f024a */ \
   XXX( HRES_SPAPI_E_FILE_HASH_NOT_IN_CATALOG     , 2148467275U) /* 0x800f024b */ \
   XXX( HRES_SPAPI_E_DRIVER_STORE_DELETE_FAILED     , 2148467276U) /* 0x800f024c */ \
   XXX( HRES_SPAPI_E_UNRECOVERABLE_STACK_OVERFLOW   , 2148467456U) /* 0x800f0300 */ \
   XXX( HRES_SPAPI_E_ERROR_NOT_INSTALLED     , 2148470784U) /* 0x800f1000 */ \
   XXX( HRES_SCARD_F_INTERNAL_ERROR        , 2148532225U) /* 0x80100001 */ \
   XXX( HRES_SCARD_E_CANCELLED        , 2148532226U) /* 0x80100002 */ \
   XXX( HRES_SCARD_E_INVALID_HANDLE        , 2148532227U) /* 0x80100003 */ \
   XXX( HRES_SCARD_E_INVALID_PARAMETER        , 2148532228U) /* 0x80100004 */ \
   XXX( HRES_SCARD_E_INVALID_TARGET        , 2148532229U) /* 0x80100005 */ \
   XXX( HRES_SCARD_E_NO_MEMORY        , 2148532230U) /* 0x80100006 */ \
   XXX( HRES_SCARD_F_WAITED_TOO_LONG        , 2148532231U) /* 0x80100007 */ \
   XXX( HRES_SCARD_E_INSUFFICIENT_BUFFER     , 2148532232U) /* 0x80100008 */ \
   XXX( HRES_SCARD_E_UNKNOWN_READER        , 2148532233U) /* 0x80100009 */ \
   XXX( HRES_SCARD_E_TIMEOUT        , 2148532234U) /* 0x8010000a */ \
   XXX( HRES_SCARD_E_SHARING_VIOLATION        , 2148532235U) /* 0x8010000b */ \
   XXX( HRES_SCARD_E_NO_SMARTCARD        , 2148532236U) /* 0x8010000c */ \
   XXX( HRES_SCARD_E_UNKNOWN_CARD        , 2148532237U) /* 0x8010000d */ \
   XXX( HRES_SCARD_E_CANT_DISPOSE        , 2148532238U) /* 0x8010000e */ \
   XXX( HRES_SCARD_E_PROTO_MISMATCH        , 2148532239U) /* 0x8010000f */ \
   XXX( HRES_SCARD_E_NOT_READY        , 2148532240U) /* 0x80100010 */ \
   XXX( HRES_SCARD_E_INVALID_VALUE        , 2148532241U) /* 0x80100011 */ \
   XXX( HRES_SCARD_E_SYSTEM_CANCELLED        , 2148532242U) /* 0x80100012 */ \
   XXX( HRES_SCARD_F_COMM_ERROR        , 2148532243U) /* 0x80100013 */ \
   XXX( HRES_SCARD_F_UNKNOWN_ERROR        , 2148532244U) /* 0x80100014 */ \
   XXX( HRES_SCARD_E_INVALID_ATR        , 2148532245U) /* 0x80100015 */ \
   XXX( HRES_SCARD_E_NOT_TRANSACTED        , 2148532246U) /* 0x80100016 */ \
   XXX( HRES_SCARD_E_READER_UNAVAILABLE        , 2148532247U) /* 0x80100017 */ \
   XXX( HRES_SCARD_P_SHUTDOWN        , 2148532248U) /* 0x80100018 */ \
   XXX( HRES_SCARD_E_PCI_TOO_SMALL        , 2148532249U) /* 0x80100019 */ \
   XXX( HRES_SCARD_E_READER_UNSUPPORTED        , 2148532250U) /* 0x8010001a */ \
   XXX( HRES_SCARD_E_DUPLICATE_READER        , 2148532251U) /* 0x8010001b */ \
   XXX( HRES_SCARD_E_CARD_UNSUPPORTED        , 2148532252U) /* 0x8010001c */ \
   XXX( HRES_SCARD_E_NO_SERVICE        , 2148532253U) /* 0x8010001d */ \
   XXX( HRES_SCARD_E_SERVICE_STOPPED        , 2148532254U) /* 0x8010001e */ \
   XXX( HRES_SCARD_E_UNEXPECTED        , 2148532255U) /* 0x8010001f */ \
   XXX( HRES_SCARD_E_ICC_INSTALLATION        , 2148532256U) /* 0x80100020 */ \
   XXX( HRES_SCARD_E_ICC_CREATEORDER        , 2148532257U) /* 0x80100021 */ \
   XXX( HRES_SCARD_E_UNSUPPORTED_FEATURE     , 2148532258U) /* 0x80100022 */ \
   XXX( HRES_SCARD_E_DIR_NOT_FOUND        , 2148532259U) /* 0x80100023 */ \
   XXX( HRES_SCARD_E_FILE_NOT_FOUND        , 2148532260U) /* 0x80100024 */ \
   XXX( HRES_SCARD_E_NO_DIR        , 2148532261U) /* 0x80100025 */ \
   XXX( HRES_SCARD_E_NO_FILE        , 2148532262U) /* 0x80100026 */ \
   XXX( HRES_SCARD_E_NO_ACCESS        , 2148532263U) /* 0x80100027 */ \
   XXX( HRES_SCARD_E_WRITE_TOO_MANY        , 2148532264U) /* 0x80100028 */ \
   XXX( HRES_SCARD_E_BAD_SEEK        , 2148532265U) /* 0x80100029 */ \
   XXX( HRES_SCARD_E_INVALID_CHV        , 2148532266U) /* 0x8010002a */ \
   XXX( HRES_SCARD_E_UNKNOWN_RES_MNG        , 2148532267U) /* 0x8010002b */ \
   XXX( HRES_SCARD_E_NO_SUCH_CERTIFICATE     , 2148532268U) /* 0x8010002c */ \
   XXX( HRES_SCARD_E_CERTIFICATE_UNAVAILABLE     , 2148532269U) /* 0x8010002d */ \
   XXX( HRES_SCARD_E_NO_READERS_AVAILABLE     , 2148532270U) /* 0x8010002e */ \
   XXX( HRES_SCARD_E_COMM_DATA_LOST        , 2148532271U) /* 0x8010002f */ \
   XXX( HRES_SCARD_E_NO_KEY_CONTAINER        , 2148532272U) /* 0x80100030 */ \
   XXX( HRES_SCARD_E_SERVER_TOO_BUSY        , 2148532273U) /* 0x80100031 */ \
   XXX( HRES_SCARD_W_UNSUPPORTED_CARD        , 2148532325U) /* 0x80100065 */ \
   XXX( HRES_SCARD_W_UNRESPONSIVE_CARD        , 2148532326U) /* 0x80100066 */ \
   XXX( HRES_SCARD_W_UNPOWERED_CARD        , 2148532327U) /* 0x80100067 */ \
   XXX( HRES_SCARD_W_RESET_CARD        , 2148532328U) /* 0x80100068 */ \
   XXX( HRES_SCARD_W_REMOVED_CARD        , 2148532329U) /* 0x80100069 */ \
   XXX( HRES_SCARD_W_SECURITY_VIOLATION        , 2148532330U) /* 0x8010006a */ \
   XXX( HRES_SCARD_W_WRONG_CHV        , 2148532331U) /* 0x8010006b */ \
   XXX( HRES_SCARD_W_CHV_BLOCKED        , 2148532332U) /* 0x8010006c */ \
   XXX( HRES_SCARD_W_EOF        , 2148532333U) /* 0x8010006d */ \
   XXX( HRES_SCARD_W_CANCELLED_BY_USER        , 2148532334U) /* 0x8010006e */ \
   XXX( HRES_SCARD_W_CARD_NOT_AUTHENTICATED     , 2148532335U) /* 0x8010006f */ \
   XXX( HRES_COMADMIN_E_OBJECTERRORS        , 2148598785U) /* 0x80110401 */ \
   XXX( HRES_COMADMIN_E_OBJECTINVALID        , 2148598786U) /* 0x80110402 */ \
   XXX( HRES_COMADMIN_E_KEYMISSING        , 2148598787U) /* 0x80110403 */ \
   XXX( HRES_COMADMIN_E_ALREADYINSTALLED     , 2148598788U) /* 0x80110404 */ \
   XXX( HRES_COMADMIN_E_APP_FILE_WRITEFAIL     , 2148598791U) /* 0x80110407 */ \
   XXX( HRES_COMADMIN_E_APP_FILE_READFAIL     , 2148598792U) /* 0x80110408 */ \
   XXX( HRES_COMADMIN_E_APP_FILE_VERSION     , 2148598793U) /* 0x80110409 */ \
   XXX( HRES_COMADMIN_E_BADPATH        , 2148598794U) /* 0x8011040a */ \
   XXX( HRES_COMADMIN_E_APPLICATIONEXISTS     , 2148598795U) /* 0x8011040b */ \
   XXX( HRES_COMADMIN_E_ROLEEXISTS        , 2148598796U) /* 0x8011040c */ \
   XXX( HRES_COMADMIN_E_CANTCOPYFILE        , 2148598797U) /* 0x8011040d */ \
   XXX( HRES_COMADMIN_E_NOUSER        , 2148598799U) /* 0x8011040f */ \
   XXX( HRES_COMADMIN_E_INVALIDUSERIDS        , 2148598800U) /* 0x80110410 */ \
   XXX( HRES_COMADMIN_E_NOREGISTRYCLSID        , 2148598801U) /* 0x80110411 */ \
   XXX( HRES_COMADMIN_E_BADREGISTRYPROGID     , 2148598802U) /* 0x80110412 */ \
   XXX( HRES_COMADMIN_E_AUTHENTICATIONLEVEL     , 2148598803U) /* 0x80110413 */ \
   XXX( HRES_COMADMIN_E_USERPASSWDNOTVALID     , 2148598804U) /* 0x80110414 */ \
   XXX( HRES_COMADMIN_E_CLSIDORIIDMISMATCH     , 2148598808U) /* 0x80110418 */ \
   XXX( HRES_COMADMIN_E_REMOTEINTERFACE        , 2148598809U) /* 0x80110419 */ \
   XXX( HRES_COMADMIN_E_DLLREGISTERSERVER     , 2148598810U) /* 0x8011041a */ \
   XXX( HRES_COMADMIN_E_NOSERVERSHARE        , 2148598811U) /* 0x8011041b */ \
   XXX( HRES_COMADMIN_E_DLLLOADFAILED        , 2148598813U) /* 0x8011041d */ \
   XXX( HRES_COMADMIN_E_BADREGISTRYLIBID     , 2148598814U) /* 0x8011041e */ \
   XXX( HRES_COMADMIN_E_APPDIRNOTFOUND        , 2148598815U) /* 0x8011041f */ \
   XXX( HRES_COMADMIN_E_REGISTRARFAILED        , 2148598819U) /* 0x80110423 */ \
   XXX( HRES_COMADMIN_E_COMPFILE_DOESNOTEXIST     , 2148598820U) /* 0x80110424 */ \
   XXX( HRES_COMADMIN_E_COMPFILE_LOADDLLFAIL     , 2148598821U) /* 0x80110425 */ \
   XXX( HRES_COMADMIN_E_COMPFILE_GETCLASSOBJ     , 2148598822U) /* 0x80110426 */ \
   XXX( HRES_COMADMIN_E_COMPFILE_CLASSNOTAVAIL     , 2148598823U) /* 0x80110427 */ \
   XXX( HRES_COMADMIN_E_COMPFILE_BADTLB        , 2148598824U) /* 0x80110428 */ \
   XXX( HRES_COMADMIN_E_COMPFILE_NOTINSTALLABLE     , 2148598825U) /* 0x80110429 */ \
   XXX( HRES_COMADMIN_E_NOTCHANGEABLE        , 2148598826U) /* 0x8011042a */ \
   XXX( HRES_COMADMIN_E_NOTDELETEABLE        , 2148598827U) /* 0x8011042b */ \
   XXX( HRES_COMADMIN_E_SESSION        , 2148598828U) /* 0x8011042c */ \
   XXX( HRES_COMADMIN_E_COMP_MOVE_LOCKED     , 2148598829U) /* 0x8011042d */ \
   XXX( HRES_COMADMIN_E_COMP_MOVE_BAD_DEST     , 2148598830U) /* 0x8011042e */ \
   XXX( HRES_COMADMIN_E_REGISTERTLB        , 2148598832U) /* 0x80110430 */ \
   XXX( HRES_COMADMIN_E_SYSTEMAPP        , 2148598835U) /* 0x80110433 */ \
   XXX( HRES_COMADMIN_E_COMPFILE_NOREGISTRAR     , 2148598836U) /* 0x80110434 */ \
   XXX( HRES_COMADMIN_E_COREQCOMPINSTALLED     , 2148598837U) /* 0x80110435 */ \
   XXX( HRES_COMADMIN_E_SERVICENOTINSTALLED     , 2148598838U) /* 0x80110436 */ \
   XXX( HRES_COMADMIN_E_PROPERTYSAVEFAILED     , 2148598839U) /* 0x80110437 */ \
   XXX( HRES_COMADMIN_E_OBJECTEXISTS        , 2148598840U) /* 0x80110438 */ \
   XXX( HRES_COMADMIN_E_COMPONENTEXISTS        , 2148598841U) /* 0x80110439 */ \
   XXX( HRES_COMADMIN_E_REGFILE_CORRUPT        , 2148598843U) /* 0x8011043b */ \
   XXX( HRES_COMADMIN_E_PROPERTY_OVERFLOW     , 2148598844U) /* 0x8011043c */ \
   XXX( HRES_COMADMIN_E_NOTINREGISTRY        , 2148598846U) /* 0x8011043e */ \
   XXX( HRES_COMADMIN_E_OBJECTNOTPOOLABLE     , 2148598847U) /* 0x8011043f */ \
   XXX( HRES_COMADMIN_E_APPLID_MATCHES_CLSID     , 2148598854U) /* 0x80110446 */ \
   XXX( HRES_COMADMIN_E_ROLE_DOES_NOT_EXIST     , 2148598855U) /* 0x80110447 */ \
   XXX( HRES_COMADMIN_E_START_APP_NEEDS_COMPONENTS  , 2148598856U) /* 0x80110448 */ \
   XXX( HRES_COMADMIN_E_REQUIRES_DIFFERENT_PLATFORM , 2148598857U) /* 0x80110449 */ \
   XXX( HRES_COMADMIN_E_CAN_NOT_EXPORT_APP_PROXY    , 2148598858U) /* 0x8011044a */ \
   XXX( HRES_COMADMIN_E_CAN_NOT_START_APP     , 2148598859U) /* 0x8011044b */ \
   XXX( HRES_COMADMIN_E_CAN_NOT_EXPORT_SYS_APP     , 2148598860U) /* 0x8011044c */ \
   XXX( HRES_COMADMIN_E_CANT_SUBSCRIBE_TO_COMPONENT , 2148598861U) /* 0x8011044d */ \
   XXX( HRES_COMADMIN_E_EVENTCLASS_CANT_BE_SUBSCRIBER , 2148598862U) /* 0x8011044e */ \
   XXX( HRES_COMADMIN_E_LIB_APP_PROXY_INCOMPATIBLE , 2148598863U) /* 0x8011044f */ \
   XXX( HRES_COMADMIN_E_BASE_PARTITION_ONLY     , 2148598864U) /* 0x80110450 */ \
   XXX( HRES_COMADMIN_E_START_APP_DISABLED     , 2148598865U) /* 0x80110451 */ \
   XXX( HRES_COMADMIN_E_CAT_DUPLICATE_PARTITION_NAME  , 2148598871U) /* 0x80110457 */ \
   XXX( HRES_COMADMIN_E_CAT_INVALID_PARTITION_NAME , 2148598872U) /* 0x80110458 */ \
   XXX( HRES_COMADMIN_E_CAT_PARTITION_IN_USE     , 2148598873U) /* 0x80110459 */ \
   XXX( HRES_COMADMIN_E_FILE_PARTITION_DUPLICATE_FILES , 2148598874U) /* 0x8011045a */ \
   XXX( HRES_COMADMIN_E_CAT_IMPORTED_COMPONENTS_NOT_ALLOWED, 2148598875U) /* 0x8011045b */ \
   XXX( HRES_COMADMIN_E_AMBIGUOUS_APPLICATION_NAME  , 2148598876U) /* 0x8011045c */ \
   XXX( HRES_COMADMIN_E_AMBIGUOUS_PARTITION_NAME   , 2148598877U) /* 0x8011045d */ \
   XXX( HRES_COMADMIN_E_REGDB_NOTINITIALIZED     , 2148598898U) /* 0x80110472 */ \
   XXX( HRES_COMADMIN_E_REGDB_NOTOPEN        , 2148598899U) /* 0x80110473 */ \
   XXX( HRES_COMADMIN_E_REGDB_SYSTEMERR        , 2148598900U) /* 0x80110474 */ \
   XXX( HRES_COMADMIN_E_REGDB_ALREADYRUNNING     , 2148598901U) /* 0x80110475 */ \
   XXX( HRES_COMADMIN_E_MIG_VERSIONNOTSUPPORTED     , 2148598912U) /* 0x80110480 */ \
   XXX( HRES_COMADMIN_E_MIG_SCHEMANOTFOUND     , 2148598913U) /* 0x80110481 */ \
   XXX( HRES_COMADMIN_E_CAT_BITNESSMISMATCH     , 2148598914U) /* 0x80110482 */ \
   XXX( HRES_COMADMIN_E_CAT_UNACCEPTABLEBITNESS     , 2148598915U) /* 0x80110483 */ \
   XXX( HRES_COMADMIN_E_CAT_WRONGAPPBITNESS     , 2148598916U) /* 0x80110484 */ \
   XXX( HRES_COMADMIN_E_CAT_PAUSE_RESUME_NOT_SUPPORTED , 2148598917U) /* 0x80110485 */ \
   XXX( HRES_COMADMIN_E_CAT_SERVERFAULT        , 2148598918U) /* 0x80110486 */ \
   XXX( HRES_COMQC_E_APPLICATION_NOT_QUEUED     , 2148599296U) /* 0x80110600 */ \
   XXX( HRES_COMQC_E_NO_QUEUEABLE_INTERFACES     , 2148599297U) /* 0x80110601 */ \
   XXX( HRES_COMQC_E_QUEUING_SERVICE_NOT_AVAILABLE  , 2148599298U) /* 0x80110602 */ \
   XXX( HRES_COMQC_E_NO_IPERSISTSTREAM        , 2148599299U) /* 0x80110603 */ \
   XXX( HRES_COMQC_E_BAD_MESSAGE        , 2148599300U) /* 0x80110604 */ \
   XXX( HRES_COMQC_E_UNAUTHENTICATED        , 2148599301U) /* 0x80110605 */ \
   XXX( HRES_COMQC_E_UNTRUSTED_ENQUEUER        , 2148599302U) /* 0x80110606 */ \
   XXX( HRES_MSDTC_E_DUPLICATE_RESOURCE        , 2148599553U) /* 0x80110701 */ \
   XXX( HRES_COMADMIN_E_OBJECT_PARENT_MISSING     , 2148599816U) /* 0x80110808 */ \
   XXX( HRES_COMADMIN_E_OBJECT_DOES_NOT_EXIST     , 2148599817U) /* 0x80110809 */ \
   XXX( HRES_COMADMIN_E_APP_NOT_RUNNING        , 2148599818U) /* 0x8011080a */ \
   XXX( HRES_COMADMIN_E_INVALID_PARTITION     , 2148599819U) /* 0x8011080b */ \
   XXX( HRES_COMADMIN_E_SVCAPP_NOT_POOLABLE_OR_RECYCLABLE, 2148599821U) /* 0x8011080d */ \
   XXX( HRES_COMADMIN_E_USER_IN_SET        , 2148599822U) /* 0x8011080e */ \
   XXX( HRES_COMADMIN_E_CANTRECYCLELIBRARYAPPS     , 2148599823U) /* 0x8011080f */ \
   XXX( HRES_COMADMIN_E_CANTRECYCLESERVICEAPPS     , 2148599825U) /* 0x80110811 */ \
   XXX( HRES_COMADMIN_E_PROCESSALREADYRECYCLED     , 2148599826U) /* 0x80110812 */ \
   XXX( HRES_COMADMIN_E_PAUSEDPROCESSMAYNOTBERECYCLED  , 2148599827U) /* 0x80110813 */ \
   XXX( HRES_COMADMIN_E_CANTMAKEINPROCSERVICE     , 2148599828U) /* 0x80110814 */ \
   XXX( HRES_COMADMIN_E_PROGIDINUSEBYCLSID     , 2148599829U) /* 0x80110815 */ \
   XXX( HRES_COMADMIN_E_DEFAULT_PARTITION_NOT_IN_SET  , 2148599830U) /* 0x80110816 */ \
   XXX( HRES_COMADMIN_E_RECYCLEDPROCESSMAYNOTBEPAUSED  , 2148599831U) /* 0x80110817 */ \
   XXX( HRES_COMADMIN_E_PARTITION_ACCESSDENIED     , 2148599832U) /* 0x80110818 */ \
   XXX( HRES_COMADMIN_E_PARTITION_MSI_ONLY     , 2148599833U) /* 0x80110819 */ \
   XXX( HRES_COMADMIN_E_LEGACYCOMPS_NOT_ALLOWED_IN_1_0_FORMAT, 2148599834U) /* 0x8011081a */ \
   XXX( HRES_COMADMIN_E_LEGACYCOMPS_NOT_ALLOWED_IN_NONBASE_PARTITIONS, 2148599835U) /* 0x8011081b */ \
   XXX( HRES_COMADMIN_E_COMP_MOVE_SOURCE     , 2148599836U) /* 0x8011081c */ \
   XXX( HRES_COMADMIN_E_COMP_MOVE_DEST        , 2148599837U) /* 0x8011081d */ \
   XXX( HRES_COMADMIN_E_COMP_MOVE_PRIVATE     , 2148599838U) /* 0x8011081e */ \
   XXX( HRES_COMADMIN_E_BASEPARTITION_REQUIRED_IN_SET  , 2148599839U) /* 0x8011081f */ \
   XXX( HRES_COMADMIN_E_CANNOT_ALIAS_EVENTCLASS     , 2148599840U) /* 0x80110820 */ \
   XXX( HRES_COMADMIN_E_PRIVATE_ACCESSDENIED     , 2148599841U) /* 0x80110821 */ \
   XXX( HRES_COMADMIN_E_SAFERINVALID        , 2148599842U) /* 0x80110822 */ \
   XXX( HRES_COMADMIN_E_REGISTRY_ACCESSDENIED     , 2148599843U) /* 0x80110823 */ \
   XXX( HRES_COMADMIN_E_PARTITIONS_DISABLED     , 2148599844U) /* 0x80110824 */ \
   XXX( HRES_ERROR_FLT_NO_HANDLER_DEFINED     , 2149515265U) /* 0x801f0001 */ \
   XXX( HRES_ERROR_FLT_CONTEXT_ALREADY_DEFINED     , 2149515266U) /* 0x801f0002 */ \
   XXX( HRES_ERROR_FLT_INVALID_ASYNCHRONOUS_REQUEST , 2149515267U) /* 0x801f0003 */ \
   XXX( HRES_ERROR_FLT_DISALLOW_FAST_IO        , 2149515268U) /* 0x801f0004 */ \
   XXX( HRES_ERROR_FLT_INVALID_NAME_REQUEST     , 2149515269U) /* 0x801f0005 */ \
   XXX( HRES_ERROR_FLT_NOT_SAFE_TO_POST_OPERATION , 2149515270U) /* 0x801f0006 */ \
   XXX( HRES_ERROR_FLT_NOT_INITIALIZED        , 2149515271U) /* 0x801f0007 */ \
   XXX( HRES_ERROR_FLT_FILTER_NOT_READY        , 2149515272U) /* 0x801f0008 */ \
   XXX( HRES_ERROR_FLT_POST_OPERATION_CLEANUP     , 2149515273U) /* 0x801f0009 */ \
   XXX( HRES_ERROR_FLT_INTERNAL_ERROR        , 2149515274U) /* 0x801f000a */ \
   XXX( HRES_ERROR_FLT_DELETING_OBJECT        , 2149515275U) /* 0x801f000b */ \
   XXX( HRES_ERROR_FLT_MUST_BE_NONPAGED_POOL     , 2149515276U) /* 0x801f000c */ \
   XXX( HRES_ERROR_FLT_DUPLICATE_ENTRY        , 2149515277U) /* 0x801f000d */ \
   XXX( HRES_ERROR_FLT_CBDQ_DISABLED        , 2149515278U) /* 0x801f000e */ \
   XXX( HRES_ERROR_FLT_DO_NOT_ATTACH        , 2149515279U) /* 0x801f000f */ \
   XXX( HRES_ERROR_FLT_DO_NOT_DETACH        , 2149515280U) /* 0x801f0010 */ \
   XXX( HRES_ERROR_FLT_INSTANCE_ALTITUDE_COLLISION  , 2149515281U) /* 0x801f0011 */ \
   XXX( HRES_ERROR_FLT_INSTANCE_NAME_COLLISION     , 2149515282U) /* 0x801f0012 */ \
   XXX( HRES_ERROR_FLT_FILTER_NOT_FOUND        , 2149515283U) /* 0x801f0013 */ \
   XXX( HRES_ERROR_FLT_VOLUME_NOT_FOUND        , 2149515284U) /* 0x801f0014 */ \
   XXX( HRES_ERROR_FLT_INSTANCE_NOT_FOUND     , 2149515285U) /* 0x801f0015 */ \
   XXX( HRES_ERROR_FLT_CONTEXT_ALLOCATION_NOT_FOUND , 2149515286U) /* 0x801f0016 */ \
   XXX( HRES_ERROR_FLT_INVALID_CONTEXT_REGISTRATION , 2149515287U) /* 0x801f0017 */ \
   XXX( HRES_ERROR_FLT_NAME_CACHE_MISS        , 2149515288U) /* 0x801f0018 */ \
   XXX( HRES_ERROR_FLT_NO_DEVICE_OBJECT        , 2149515289U) /* 0x801f0019 */ \
   XXX( HRES_ERROR_FLT_VOLUME_ALREADY_MOUNTED     , 2149515290U) /* 0x801f001a */ \
   XXX( HRES_ERROR_FLT_ALREADY_ENLISTED        , 2149515291U) /* 0x801f001b */ \
   XXX( HRES_ERROR_FLT_CONTEXT_ALREADY_LINKED     , 2149515292U) /* 0x801f001c */ \
   XXX( HRES_ERROR_FLT_NO_WAITER_FOR_REPLY     , 2149515296U) /* 0x801f0020 */ \
   XXX( HRES_ERROR_HUNG_DISPLAY_DRIVER_THREAD     , 2149974017U) /* 0x80260001 */ \
   XXX( HRES_ERROR_MONITOR_NO_DESCRIPTOR     , 2149978113U) /* 0x80261001 */ \
   XXX( HRES_ERROR_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT  , 2149978114U) /* 0x80261002 */ \
   XXX( HRES_DWM_E_COMPOSITIONDISABLED        , 2149986305U) /* 0x80263001 */ \
   XXX( HRES_DWM_E_REMOTING_NOT_SUPPORTED     , 2149986306U) /* 0x80263002 */ \
   XXX( HRES_DWM_E_NO_REDIRECTION_SURFACE_AVAILABLE , 2149986307U) /* 0x80263003 */ \
   XXX( HRES_DWM_E_NOT_QUEUING_PRESENTS        , 2149986308U) /* 0x80263004 */ \
   XXX( HRES_TPM_E_ERROR_MASK        , 2150105088U) /* 0x80280000 */ \
   XXX( HRES_TPM_E_AUTHFAIL        , 2150105089U) /* 0x80280001 */ \
   XXX( HRES_TPM_E_BADINDEX        , 2150105090U) /* 0x80280002 */ \
   XXX( HRES_TPM_E_BAD_PARAMETER        , 2150105091U) /* 0x80280003 */ \
   XXX( HRES_TPM_E_AUDITFAILURE        , 2150105092U) /* 0x80280004 */ \
   XXX( HRES_TPM_E_CLEAR_DISABLED        , 2150105093U) /* 0x80280005 */ \
   XXX( HRES_TPM_E_DEACTIVATED        , 2150105094U) /* 0x80280006 */ \
   XXX( HRES_TPM_E_DISABLED        , 2150105095U) /* 0x80280007 */ \
   XXX( HRES_TPM_E_DISABLED_CMD        , 2150105096U) /* 0x80280008 */ \
   XXX( HRES_TPM_E_FAIL          , 2150105097U) /* 0x80280009 */ \
   XXX( HRES_TPM_E_BAD_ORDINAL        , 2150105098U) /* 0x8028000a */ \
   XXX( HRES_TPM_E_INSTALL_DISABLED        , 2150105099U) /* 0x8028000b */ \
   XXX( HRES_TPM_E_INVALID_KEYHANDLE        , 2150105100U) /* 0x8028000c */ \
   XXX( HRES_TPM_E_KEYNOTFOUND        , 2150105101U) /* 0x8028000d */ \
   XXX( HRES_TPM_E_INAPPROPRIATE_ENC        , 2150105102U) /* 0x8028000e */ \
   XXX( HRES_TPM_E_MIGRATEFAIL        , 2150105103U) /* 0x8028000f */ \
   XXX( HRES_TPM_E_INVALID_PCR_INFO        , 2150105104U) /* 0x80280010 */ \
   XXX( HRES_TPM_E_NOSPACE        , 2150105105U) /* 0x80280011 */ \
   XXX( HRES_TPM_E_NOSRK        , 2150105106U) /* 0x80280012 */ \
   XXX( HRES_TPM_E_NOTSEALED_BLOB        , 2150105107U) /* 0x80280013 */ \
   XXX( HRES_TPM_E_OWNER_SET        , 2150105108U) /* 0x80280014 */ \
   XXX( HRES_TPM_E_RESOURCES        , 2150105109U) /* 0x80280015 */ \
   XXX( HRES_TPM_E_SHORTRANDOM        , 2150105110U) /* 0x80280016 */ \
   XXX( HRES_TPM_E_SIZE          , 2150105111U) /* 0x80280017 */ \
   XXX( HRES_TPM_E_WRONGPCRVAL        , 2150105112U) /* 0x80280018 */ \
   XXX( HRES_TPM_E_BAD_PARAM_SIZE        , 2150105113U) /* 0x80280019 */ \
   XXX( HRES_TPM_E_SHA_THREAD        , 2150105114U) /* 0x8028001a */ \
   XXX( HRES_TPM_E_SHA_ERROR        , 2150105115U) /* 0x8028001b */ \
   XXX( HRES_TPM_E_FAILEDSELFTEST        , 2150105116U) /* 0x8028001c */ \
   XXX( HRES_TPM_E_AUTH2FAIL        , 2150105117U) /* 0x8028001d */ \
   XXX( HRES_TPM_E_BADTAG        , 2150105118U) /* 0x8028001e */ \
   XXX( HRES_TPM_E_IOERROR        , 2150105119U) /* 0x8028001f */ \
   XXX( HRES_TPM_E_ENCRYPT_ERROR        , 2150105120U) /* 0x80280020 */ \
   XXX( HRES_TPM_E_DECRYPT_ERROR        , 2150105121U) /* 0x80280021 */ \
   XXX( HRES_TPM_E_INVALID_AUTHHANDLE        , 2150105122U) /* 0x80280022 */ \
   XXX( HRES_TPM_E_NO_ENDORSEMENT        , 2150105123U) /* 0x80280023 */ \
   XXX( HRES_TPM_E_INVALID_KEYUSAGE        , 2150105124U) /* 0x80280024 */ \
   XXX( HRES_TPM_E_WRONG_ENTITYTYPE        , 2150105125U) /* 0x80280025 */ \
   XXX( HRES_TPM_E_INVALID_POSTINIT        , 2150105126U) /* 0x80280026 */ \
   XXX( HRES_TPM_E_INAPPROPRIATE_SIG        , 2150105127U) /* 0x80280027 */ \
   XXX( HRES_TPM_E_BAD_KEY_PROPERTY        , 2150105128U) /* 0x80280028 */ \
   XXX( HRES_TPM_E_BAD_MIGRATION        , 2150105129U) /* 0x80280029 */ \
   XXX( HRES_TPM_E_BAD_SCHEME        , 2150105130U) /* 0x8028002a */ \
   XXX( HRES_TPM_E_BAD_DATASIZE        , 2150105131U) /* 0x8028002b */ \
   XXX( HRES_TPM_E_BAD_MODE        , 2150105132U) /* 0x8028002c */ \
   XXX( HRES_TPM_E_BAD_PRESENCE        , 2150105133U) /* 0x8028002d */ \
   XXX( HRES_TPM_E_BAD_VERSION        , 2150105134U) /* 0x8028002e */ \
   XXX( HRES_TPM_E_NO_WRAP_TRANSPORT        , 2150105135U) /* 0x8028002f */ \
   XXX( HRES_TPM_E_AUDITFAIL_UNSUCCESSFUL     , 2150105136U) /* 0x80280030 */ \
   XXX( HRES_TPM_E_AUDITFAIL_SUCCESSFUL        , 2150105137U) /* 0x80280031 */ \
   XXX( HRES_TPM_E_NOTRESETABLE        , 2150105138U) /* 0x80280032 */ \
   XXX( HRES_TPM_E_NOTLOCAL        , 2150105139U) /* 0x80280033 */ \
   XXX( HRES_TPM_E_BAD_TYPE        , 2150105140U) /* 0x80280034 */ \
   XXX( HRES_TPM_E_INVALID_RESOURCE        , 2150105141U) /* 0x80280035 */ \
   XXX( HRES_TPM_E_NOTFIPS        , 2150105142U) /* 0x80280036 */ \
   XXX( HRES_TPM_E_INVALID_FAMILY        , 2150105143U) /* 0x80280037 */ \
   XXX( HRES_TPM_E_NO_NV_PERMISSION        , 2150105144U) /* 0x80280038 */ \
   XXX( HRES_TPM_E_REQUIRES_SIGN        , 2150105145U) /* 0x80280039 */ \
   XXX( HRES_TPM_E_KEY_NOTSUPPORTED        , 2150105146U) /* 0x8028003a */ \
   XXX( HRES_TPM_E_AUTH_CONFLICT        , 2150105147U) /* 0x8028003b */ \
   XXX( HRES_TPM_E_AREA_LOCKED        , 2150105148U) /* 0x8028003c */ \
   XXX( HRES_TPM_E_BAD_LOCALITY        , 2150105149U) /* 0x8028003d */ \
   XXX( HRES_TPM_E_READ_ONLY        , 2150105150U) /* 0x8028003e */ \
   XXX( HRES_TPM_E_PER_NOWRITE        , 2150105151U) /* 0x8028003f */ \
   XXX( HRES_TPM_E_FAMILYCOUNT        , 2150105152U) /* 0x80280040 */ \
   XXX( HRES_TPM_E_WRITE_LOCKED        , 2150105153U) /* 0x80280041 */ \
   XXX( HRES_TPM_E_BAD_ATTRIBUTES        , 2150105154U) /* 0x80280042 */ \
   XXX( HRES_TPM_E_INVALID_STRUCTURE        , 2150105155U) /* 0x80280043 */ \
   XXX( HRES_TPM_E_KEY_OWNER_CONTROL        , 2150105156U) /* 0x80280044 */ \
   XXX( HRES_TPM_E_BAD_COUNTER        , 2150105157U) /* 0x80280045 */ \
   XXX( HRES_TPM_E_NOT_FULLWRITE        , 2150105158U) /* 0x80280046 */ \
   XXX( HRES_TPM_E_CONTEXT_GAP        , 2150105159U) /* 0x80280047 */ \
   XXX( HRES_TPM_E_MAXNVWRITES        , 2150105160U) /* 0x80280048 */ \
   XXX( HRES_TPM_E_NOOPERATOR        , 2150105161U) /* 0x80280049 */ \
   XXX( HRES_TPM_E_RESOURCEMISSING        , 2150105162U) /* 0x8028004a */ \
   XXX( HRES_TPM_E_DELEGATE_LOCK        , 2150105163U) /* 0x8028004b */ \
   XXX( HRES_TPM_E_DELEGATE_FAMILY        , 2150105164U) /* 0x8028004c */ \
   XXX( HRES_TPM_E_DELEGATE_ADMIN        , 2150105165U) /* 0x8028004d */ \
   XXX( HRES_TPM_E_TRANSPORT_NOTEXCLUSIVE     , 2150105166U) /* 0x8028004e */ \
   XXX( HRES_TPM_E_OWNER_CONTROL        , 2150105167U) /* 0x8028004f */ \
   XXX( HRES_TPM_E_DAA_RESOURCES        , 2150105168U) /* 0x80280050 */ \
   XXX( HRES_TPM_E_DAA_INPUT_DATA0        , 2150105169U) /* 0x80280051 */ \
   XXX( HRES_TPM_E_DAA_INPUT_DATA1        , 2150105170U) /* 0x80280052 */ \
   XXX( HRES_TPM_E_DAA_ISSUER_SETTINGS        , 2150105171U) /* 0x80280053 */ \
   XXX( HRES_TPM_E_DAA_TPM_SETTINGS        , 2150105172U) /* 0x80280054 */ \
   XXX( HRES_TPM_E_DAA_STAGE        , 2150105173U) /* 0x80280055 */ \
   XXX( HRES_TPM_E_DAA_ISSUER_VALIDITY        , 2150105174U) /* 0x80280056 */ \
   XXX( HRES_TPM_E_DAA_WRONG_W        , 2150105175U) /* 0x80280057 */ \
   XXX( HRES_TPM_E_BAD_HANDLE        , 2150105176U) /* 0x80280058 */ \
   XXX( HRES_TPM_E_BAD_DELEGATE        , 2150105177U) /* 0x80280059 */ \
   XXX( HRES_TPM_E_BADCONTEXT        , 2150105178U) /* 0x8028005a */ \
   XXX( HRES_TPM_E_TOOMANYCONTEXTS        , 2150105179U) /* 0x8028005b */ \
   XXX( HRES_TPM_E_MA_TICKET_SIGNATURE        , 2150105180U) /* 0x8028005c */ \
   XXX( HRES_TPM_E_MA_DESTINATION        , 2150105181U) /* 0x8028005d */ \
   XXX( HRES_TPM_E_MA_SOURCE        , 2150105182U) /* 0x8028005e */ \
   XXX( HRES_TPM_E_MA_AUTHORITY        , 2150105183U) /* 0x8028005f */ \
   XXX( HRES_TPM_E_PERMANENTEK        , 2150105185U) /* 0x80280061 */ \
   XXX( HRES_TPM_E_BAD_SIGNATURE        , 2150105186U) /* 0x80280062 */ \
   XXX( HRES_TPM_E_NOCONTEXTSPACE        , 2150105187U) /* 0x80280063 */ \
   XXX( HRES_TPM_E_COMMAND_BLOCKED        , 2150106112U) /* 0x80280400 */ \
   XXX( HRES_TPM_E_INVALID_HANDLE        , 2150106113U) /* 0x80280401 */ \
   XXX( HRES_TPM_E_DUPLICATE_VHANDLE        , 2150106114U) /* 0x80280402 */ \
   XXX( HRES_TPM_E_EMBEDDED_COMMAND_BLOCKED     , 2150106115U) /* 0x80280403 */ \
   XXX( HRES_TPM_E_EMBEDDED_COMMAND_UNSUPPORTED     , 2150106116U) /* 0x80280404 */ \
   XXX( HRES_TPM_E_RETRY        , 2150107136U) /* 0x80280800 */ \
   XXX( HRES_TPM_E_NEEDS_SELFTEST        , 2150107137U) /* 0x80280801 */ \
   XXX( HRES_TPM_E_DOING_SELFTEST        , 2150107138U) /* 0x80280802 */ \
   XXX( HRES_TPM_E_DEFEND_LOCK_RUNNING        , 2150107139U) /* 0x80280803 */ \
   XXX( HRES_TBS_E_INTERNAL_ERROR        , 2150121473U) /* 0x80284001 */ \
   XXX( HRES_TBS_E_BAD_PARAMETER        , 2150121474U) /* 0x80284002 */ \
   XXX( HRES_TBS_E_INVALID_OUTPUT_POINTER     , 2150121475U) /* 0x80284003 */ \
   XXX( HRES_TBS_E_INVALID_CONTEXT        , 2150121476U) /* 0x80284004 */ \
   XXX( HRES_TBS_E_INSUFFICIENT_BUFFER        , 2150121477U) /* 0x80284005 */ \
   XXX( HRES_TBS_E_IOERROR        , 2150121478U) /* 0x80284006 */ \
   XXX( HRES_TBS_E_INVALID_CONTEXT_PARAM     , 2150121479U) /* 0x80284007 */ \
   XXX( HRES_TBS_E_SERVICE_NOT_RUNNING        , 2150121480U) /* 0x80284008 */ \
   XXX( HRES_TBS_E_TOO_MANY_TBS_CONTEXTS     , 2150121481U) /* 0x80284009 */ \
   XXX( HRES_TBS_E_TOO_MANY_RESOURCES        , 2150121482U) /* 0x8028400a */ \
   XXX( HRES_TBS_E_SERVICE_START_PENDING     , 2150121483U) /* 0x8028400b */ \
   XXX( HRES_TBS_E_PPI_NOT_SUPPORTED        , 2150121484U) /* 0x8028400c */ \
   XXX( HRES_TBS_E_COMMAND_CANCELED        , 2150121485U) /* 0x8028400d */ \
   XXX( HRES_TBS_E_BUFFER_TOO_LARGE        , 2150121486U) /* 0x8028400e */ \
   XXX( HRES_TPMAPI_E_INVALID_STATE        , 2150170880U) /* 0x80290100 */ \
   XXX( HRES_TPMAPI_E_NOT_ENOUGH_DATA        , 2150170881U) /* 0x80290101 */ \
   XXX( HRES_TPMAPI_E_TOO_MUCH_DATA        , 2150170882U) /* 0x80290102 */ \
   XXX( HRES_TPMAPI_E_INVALID_OUTPUT_POINTER     , 2150170883U) /* 0x80290103 */ \
   XXX( HRES_TPMAPI_E_INVALID_PARAMETER        , 2150170884U) /* 0x80290104 */ \
   XXX( HRES_TPMAPI_E_OUT_OF_MEMORY        , 2150170885U) /* 0x80290105 */ \
   XXX( HRES_TPMAPI_E_BUFFER_TOO_SMALL        , 2150170886U) /* 0x80290106 */ \
   XXX( HRES_TPMAPI_E_INTERNAL_ERROR        , 2150170887U) /* 0x80290107 */ \
   XXX( HRES_TPMAPI_E_ACCESS_DENIED        , 2150170888U) /* 0x80290108 */ \
   XXX( HRES_TPMAPI_E_AUTHORIZATION_FAILED     , 2150170889U) /* 0x80290109 */ \
   XXX( HRES_TPMAPI_E_INVALID_CONTEXT_HANDLE     , 2150170890U) /* 0x8029010a */ \
   XXX( HRES_TPMAPI_E_TBS_COMMUNICATION_ERROR     , 2150170891U) /* 0x8029010b */ \
   XXX( HRES_TPMAPI_E_TPM_COMMAND_ERROR        , 2150170892U) /* 0x8029010c */ \
   XXX( HRES_TPMAPI_E_MESSAGE_TOO_LARGE        , 2150170893U) /* 0x8029010d */ \
   XXX( HRES_TPMAPI_E_INVALID_ENCODING        , 2150170894U) /* 0x8029010e */ \
   XXX( HRES_TPMAPI_E_INVALID_KEY_SIZE        , 2150170895U) /* 0x8029010f */ \
   XXX( HRES_TPMAPI_E_ENCRYPTION_FAILED        , 2150170896U) /* 0x80290110 */ \
   XXX( HRES_TPMAPI_E_INVALID_KEY_PARAMS     , 2150170897U) /* 0x80290111 */ \
   XXX( HRES_TPMAPI_E_INVALID_MIGRATION_AUTHORIZATION_BLOB, 2150170898U) /* 0x80290112 */ \
   XXX( HRES_TPMAPI_E_INVALID_PCR_INDEX        , 2150170899U) /* 0x80290113 */ \
   XXX( HRES_TPMAPI_E_INVALID_DELEGATE_BLOB     , 2150170900U) /* 0x80290114 */ \
   XXX( HRES_TPMAPI_E_INVALID_CONTEXT_PARAMS     , 2150170901U) /* 0x80290115 */ \
   XXX( HRES_TPMAPI_E_INVALID_KEY_BLOB        , 2150170902U) /* 0x80290116 */ \
   XXX( HRES_TPMAPI_E_INVALID_PCR_DATA        , 2150170903U) /* 0x80290117 */ \
   XXX( HRES_TPMAPI_E_INVALID_OWNER_AUTH     , 2150170904U) /* 0x80290118 */ \
   XXX( HRES_TBSIMP_E_BUFFER_TOO_SMALL        , 2150171136U) /* 0x80290200 */ \
   XXX( HRES_TBSIMP_E_CLEANUP_FAILED        , 2150171137U) /* 0x80290201 */ \
   XXX( HRES_TBSIMP_E_INVALID_CONTEXT_HANDLE     , 2150171138U) /* 0x80290202 */ \
   XXX( HRES_TBSIMP_E_INVALID_CONTEXT_PARAM     , 2150171139U) /* 0x80290203 */ \
   XXX( HRES_TBSIMP_E_TPM_ERROR        , 2150171140U) /* 0x80290204 */ \
   XXX( HRES_TBSIMP_E_HASH_BAD_KEY        , 2150171141U) /* 0x80290205 */ \
   XXX( HRES_TBSIMP_E_DUPLICATE_VHANDLE        , 2150171142U) /* 0x80290206 */ \
   XXX( HRES_TBSIMP_E_INVALID_OUTPUT_POINTER     , 2150171143U) /* 0x80290207 */ \
   XXX( HRES_TBSIMP_E_INVALID_PARAMETER        , 2150171144U) /* 0x80290208 */ \
   XXX( HRES_TBSIMP_E_RPC_INIT_FAILED        , 2150171145U) /* 0x80290209 */ \
   XXX( HRES_TBSIMP_E_SCHEDULER_NOT_RUNNING     , 2150171146U) /* 0x8029020a */ \
   XXX( HRES_TBSIMP_E_COMMAND_CANCELED        , 2150171147U) /* 0x8029020b */ \
   XXX( HRES_TBSIMP_E_OUT_OF_MEMORY        , 2150171148U) /* 0x8029020c */ \
   XXX( HRES_TBSIMP_E_LIST_NO_MORE_ITEMS     , 2150171149U) /* 0x8029020d */ \
   XXX( HRES_TBSIMP_E_LIST_NOT_FOUND        , 2150171150U) /* 0x8029020e */ \
   XXX( HRES_TBSIMP_E_NOT_ENOUGH_SPACE        , 2150171151U) /* 0x8029020f */ \
   XXX( HRES_TBSIMP_E_NOT_ENOUGH_TPM_CONTEXTS     , 2150171152U) /* 0x80290210 */ \
   XXX( HRES_TBSIMP_E_COMMAND_FAILED        , 2150171153U) /* 0x80290211 */ \
   XXX( HRES_TBSIMP_E_UNKNOWN_ORDINAL        , 2150171154U) /* 0x80290212 */ \
   XXX( HRES_TBSIMP_E_RESOURCE_EXPIRED        , 2150171155U) /* 0x80290213 */ \
   XXX( HRES_TBSIMP_E_INVALID_RESOURCE        , 2150171156U) /* 0x80290214 */ \
   XXX( HRES_TBSIMP_E_NOTHING_TO_UNLOAD        , 2150171157U) /* 0x80290215 */ \
   XXX( HRES_TBSIMP_E_HASH_TABLE_FULL        , 2150171158U) /* 0x80290216 */ \
   XXX( HRES_TBSIMP_E_TOO_MANY_TBS_CONTEXTS     , 2150171159U) /* 0x80290217 */ \
   XXX( HRES_TBSIMP_E_TOO_MANY_RESOURCES     , 2150171160U) /* 0x80290218 */ \
   XXX( HRES_TBSIMP_E_PPI_NOT_SUPPORTED        , 2150171161U) /* 0x80290219 */ \
   XXX( HRES_TBSIMP_E_TPM_INCOMPATIBLE        , 2150171162U) /* 0x8029021a */ \
   XXX( HRES_TPM_E_PPI_ACPI_FAILURE        , 2150171392U) /* 0x80290300 */ \
   XXX( HRES_TPM_E_PPI_USER_ABORT        , 2150171393U) /* 0x80290301 */ \
   XXX( HRES_TPM_E_PPI_BIOS_FAILURE        , 2150171394U) /* 0x80290302 */ \
   XXX( HRES_TPM_E_PPI_NOT_SUPPORTED        , 2150171395U) /* 0x80290303 */ \
   XXX( HRES_PLA_E_DCS_NOT_FOUND        , 2150629378U) /* 0x80300002 */ \
   XXX( HRES_PLA_E_TOO_MANY_FOLDERS        , 2150629445U) /* 0x80300045 */ \
   XXX( HRES_PLA_E_NO_MIN_DISK        , 2150629488U) /* 0x80300070 */ \
   XXX( HRES_PLA_E_DCS_IN_USE        , 2150629546U) /* 0x803000aa */ \
   XXX( HRES_PLA_E_DCS_ALREADY_EXISTS        , 2150629559U) /* 0x803000b7 */ \
   XXX( HRES_PLA_E_PROPERTY_CONFLICT        , 2150629633U) /* 0x80300101 */ \
   XXX( HRES_PLA_E_DCS_SINGLETON_REQUIRED     , 2150629634U) /* 0x80300102 */ \
   XXX( HRES_PLA_E_CREDENTIALS_REQUIRED        , 2150629635U) /* 0x80300103 */ \
   XXX( HRES_PLA_E_DCS_NOT_RUNNING        , 2150629636U) /* 0x80300104 */ \
   XXX( HRES_PLA_E_CONFLICT_INCL_EXCL_API     , 2150629637U) /* 0x80300105 */ \
   XXX( HRES_PLA_E_NETWORK_EXE_NOT_VALID     , 2150629638U) /* 0x80300106 */ \
   XXX( HRES_PLA_E_EXE_ALREADY_CONFIGURED     , 2150629639U) /* 0x80300107 */ \
   XXX( HRES_PLA_E_EXE_PATH_NOT_VALID        , 2150629640U) /* 0x80300108 */ \
   XXX( HRES_PLA_E_DC_ALREADY_EXISTS        , 2150629641U) /* 0x80300109 */ \
   XXX( HRES_PLA_E_DCS_START_WAIT_TIMEOUT     , 2150629642U) /* 0x8030010a */ \
   XXX( HRES_PLA_E_DC_START_WAIT_TIMEOUT     , 2150629643U) /* 0x8030010b */ \
   XXX( HRES_PLA_E_REPORT_WAIT_TIMEOUT        , 2150629644U) /* 0x8030010c */ \
   XXX( HRES_PLA_E_NO_DUPLICATES        , 2150629645U) /* 0x8030010d */ \
   XXX( HRES_PLA_E_EXE_FULL_PATH_REQUIRED     , 2150629646U) /* 0x8030010e */ \
   XXX( HRES_PLA_E_INVALID_SESSION_NAME        , 2150629647U) /* 0x8030010f */ \
   XXX( HRES_PLA_E_PLA_CHANNEL_NOT_ENABLED     , 2150629648U) /* 0x80300110 */ \
   XXX( HRES_PLA_E_TASKSCHED_CHANNEL_NOT_ENABLED  , 2150629649U) /* 0x80300111 */ \
   XXX( HRES_FVE_E_LOCKED_VOLUME        , 2150694912U) /* 0x80310000 */ \
   XXX( HRES_FVE_E_NOT_ENCRYPTED        , 2150694913U) /* 0x80310001 */ \
   XXX( HRES_FVE_E_NO_TPM_BIOS        , 2150694914U) /* 0x80310002 */ \
   XXX( HRES_FVE_E_NO_MBR_METRIC        , 2150694915U) /* 0x80310003 */ \
   XXX( HRES_FVE_E_NO_BOOTSECTOR_METRIC        , 2150694916U) /* 0x80310004 */ \
   XXX( HRES_FVE_E_NO_BOOTMGR_METRIC        , 2150694917U) /* 0x80310005 */ \
   XXX( HRES_FVE_E_WRONG_BOOTMGR        , 2150694918U) /* 0x80310006 */ \
   XXX( HRES_FVE_E_SECURE_KEY_REQUIRED        , 2150694919U) /* 0x80310007 */ \
   XXX( HRES_FVE_E_NOT_ACTIVATED        , 2150694920U) /* 0x80310008 */ \
   XXX( HRES_FVE_E_ACTION_NOT_ALLOWED        , 2150694921U) /* 0x80310009 */ \
   XXX( HRES_FVE_E_AD_SCHEMA_NOT_INSTALLED     , 2150694922U) /* 0x8031000a */ \
   XXX( HRES_FVE_E_AD_INVALID_DATATYPE        , 2150694923U) /* 0x8031000b */ \
   XXX( HRES_FVE_E_AD_INVALID_DATASIZE        , 2150694924U) /* 0x8031000c */ \
   XXX( HRES_FVE_E_AD_NO_VALUES        , 2150694925U) /* 0x8031000d */ \
   XXX( HRES_FVE_E_AD_ATTR_NOT_SET        , 2150694926U) /* 0x8031000e */ \
   XXX( HRES_FVE_E_AD_GUID_NOT_FOUND        , 2150694927U) /* 0x8031000f */ \
   XXX( HRES_FVE_E_BAD_INFORMATION        , 2150694928U) /* 0x80310010 */ \
   XXX( HRES_FVE_E_TOO_SMALL        , 2150694929U) /* 0x80310011 */ \
   XXX( HRES_FVE_E_SYSTEM_VOLUME        , 2150694930U) /* 0x80310012 */ \
   XXX( HRES_FVE_E_FAILED_WRONG_FS        , 2150694931U) /* 0x80310013 */ \
   XXX( HRES_FVE_E_FAILED_BAD_FS        , 2150694932U) /* 0x80310014 */ \
   XXX( HRES_FVE_E_NOT_SUPPORTED        , 2150694933U) /* 0x80310015 */ \
   XXX( HRES_FVE_E_BAD_DATA        , 2150694934U) /* 0x80310016 */ \
   XXX( HRES_FVE_E_VOLUME_NOT_BOUND        , 2150694935U) /* 0x80310017 */ \
   XXX( HRES_FVE_E_TPM_NOT_OWNED        , 2150694936U) /* 0x80310018 */ \
   XXX( HRES_FVE_E_NOT_DATA_VOLUME        , 2150694937U) /* 0x80310019 */ \
   XXX( HRES_FVE_E_AD_INSUFFICIENT_BUFFER     , 2150694938U) /* 0x8031001a */ \
   XXX( HRES_FVE_E_CONV_READ        , 2150694939U) /* 0x8031001b */ \
   XXX( HRES_FVE_E_CONV_WRITE        , 2150694940U) /* 0x8031001c */ \
   XXX( HRES_FVE_E_KEY_REQUIRED        , 2150694941U) /* 0x8031001d */ \
   XXX( HRES_FVE_E_CLUSTERING_NOT_SUPPORTED     , 2150694942U) /* 0x8031001e */ \
   XXX( HRES_FVE_E_VOLUME_BOUND_ALREADY        , 2150694943U) /* 0x8031001f */ \
   XXX( HRES_FVE_E_OS_NOT_PROTECTED        , 2150694944U) /* 0x80310020 */ \
   XXX( HRES_FVE_E_PROTECTION_DISABLED        , 2150694945U) /* 0x80310021 */ \
   XXX( HRES_FVE_E_RECOVERY_KEY_REQUIRED     , 2150694946U) /* 0x80310022 */ \
   XXX( HRES_FVE_E_FOREIGN_VOLUME        , 2150694947U) /* 0x80310023 */ \
   XXX( HRES_FVE_E_OVERLAPPED_UPDATE        , 2150694948U) /* 0x80310024 */ \
   XXX( HRES_FVE_E_TPM_SRK_AUTH_NOT_ZERO     , 2150694949U) /* 0x80310025 */ \
   XXX( HRES_FVE_E_FAILED_SECTOR_SIZE        , 2150694950U) /* 0x80310026 */ \
   XXX( HRES_FVE_E_FAILED_AUTHENTICATION     , 2150694951U) /* 0x80310027 */ \
   XXX( HRES_FVE_E_NOT_OS_VOLUME        , 2150694952U) /* 0x80310028 */ \
   XXX( HRES_FVE_E_AUTOUNLOCK_ENABLED        , 2150694953U) /* 0x80310029 */ \
   XXX( HRES_FVE_E_WRONG_BOOTSECTOR        , 2150694954U) /* 0x8031002a */ \
   XXX( HRES_FVE_E_WRONG_SYSTEM_FS        , 2150694955U) /* 0x8031002b */ \
   XXX( HRES_FVE_E_POLICY_PASSWORD_REQUIRED     , 2150694956U) /* 0x8031002c */ \
   XXX( HRES_FVE_E_CANNOT_SET_FVEK_ENCRYPTED     , 2150694957U) /* 0x8031002d */ \
   XXX( HRES_FVE_E_CANNOT_ENCRYPT_NO_KEY     , 2150694958U) /* 0x8031002e */ \
   XXX( HRES_FVE_E_BOOTABLE_CDDVD        , 2150694960U) /* 0x80310030 */ \
   XXX( HRES_FVE_E_PROTECTOR_EXISTS        , 2150694961U) /* 0x80310031 */ \
   XXX( HRES_FVE_E_RELATIVE_PATH        , 2150694962U) /* 0x80310032 */ \
   XXX( HRES_FWP_E_CALLOUT_NOT_FOUND        , 2150760449U) /* 0x80320001 */ \
   XXX( HRES_FWP_E_CONDITION_NOT_FOUND        , 2150760450U) /* 0x80320002 */ \
   XXX( HRES_FWP_E_FILTER_NOT_FOUND        , 2150760451U) /* 0x80320003 */ \
   XXX( HRES_FWP_E_LAYER_NOT_FOUND        , 2150760452U) /* 0x80320004 */ \
   XXX( HRES_FWP_E_PROVIDER_NOT_FOUND        , 2150760453U) /* 0x80320005 */ \
   XXX( HRES_FWP_E_PROVIDER_CONTEXT_NOT_FOUND     , 2150760454U) /* 0x80320006 */ \
   XXX( HRES_FWP_E_SUBLAYER_NOT_FOUND        , 2150760455U) /* 0x80320007 */ \
   XXX( HRES_FWP_E_NOT_FOUND        , 2150760456U) /* 0x80320008 */ \
   XXX( HRES_FWP_E_ALREADY_EXISTS        , 2150760457U) /* 0x80320009 */ \
   XXX( HRES_FWP_E_IN_USE        , 2150760458U) /* 0x8032000a */ \
   XXX( HRES_FWP_E_DYNAMIC_SESSION_IN_PROGRESS     , 2150760459U) /* 0x8032000b */ \
   XXX( HRES_FWP_E_WRONG_SESSION        , 2150760460U) /* 0x8032000c */ \
   XXX( HRES_FWP_E_NO_TXN_IN_PROGRESS        , 2150760461U) /* 0x8032000d */ \
   XXX( HRES_FWP_E_TXN_IN_PROGRESS        , 2150760462U) /* 0x8032000e */ \
   XXX( HRES_FWP_E_TXN_ABORTED        , 2150760463U) /* 0x8032000f */ \
   XXX( HRES_FWP_E_SESSION_ABORTED        , 2150760464U) /* 0x80320010 */ \
   XXX( HRES_FWP_E_INCOMPATIBLE_TXN        , 2150760465U) /* 0x80320011 */ \
   XXX( HRES_FWP_E_TIMEOUT        , 2150760466U) /* 0x80320012 */ \
   XXX( HRES_FWP_E_NET_EVENTS_DISABLED        , 2150760467U) /* 0x80320013 */ \
   XXX( HRES_FWP_E_INCOMPATIBLE_LAYER        , 2150760468U) /* 0x80320014 */ \
   XXX( HRES_FWP_E_KM_CLIENTS_ONLY        , 2150760469U) /* 0x80320015 */ \
   XXX( HRES_FWP_E_LIFETIME_MISMATCH        , 2150760470U) /* 0x80320016 */ \
   XXX( HRES_FWP_E_BUILTIN_OBJECT        , 2150760471U) /* 0x80320017 */ \
   XXX( HRES_FWP_E_TOO_MANY_BOOTTIME_FILTERS     , 2150760472U) /* 0x80320018 */ \
   XXX( HRES_FWP_E_NOTIFICATION_DROPPED        , 2150760473U) /* 0x80320019 */ \
   XXX( HRES_FWP_E_TRAFFIC_MISMATCH        , 2150760474U) /* 0x8032001a */ \
   XXX( HRES_FWP_E_INCOMPATIBLE_SA_STATE     , 2150760475U) /* 0x8032001b */ \
   XXX( HRES_FWP_E_NULL_POINTER        , 2150760476U) /* 0x8032001c */ \
   XXX( HRES_FWP_E_INVALID_ENUMERATOR        , 2150760477U) /* 0x8032001d */ \
   XXX( HRES_FWP_E_INVALID_FLAGS        , 2150760478U) /* 0x8032001e */ \
   XXX( HRES_FWP_E_INVALID_NET_MASK        , 2150760479U) /* 0x8032001f */ \
   XXX( HRES_FWP_E_INVALID_RANGE        , 2150760480U) /* 0x80320020 */ \
   XXX( HRES_FWP_E_INVALID_INTERVAL        , 2150760481U) /* 0x80320021 */ \
   XXX( HRES_FWP_E_ZERO_LENGTH_ARRAY        , 2150760482U) /* 0x80320022 */ \
   XXX( HRES_FWP_E_NULL_DISPLAY_NAME        , 2150760483U) /* 0x80320023 */ \
   XXX( HRES_FWP_E_INVALID_ACTION_TYPE        , 2150760484U) /* 0x80320024 */ \
   XXX( HRES_FWP_E_INVALID_WEIGHT        , 2150760485U) /* 0x80320025 */ \
   XXX( HRES_FWP_E_MATCH_TYPE_MISMATCH        , 2150760486U) /* 0x80320026 */ \
   XXX( HRES_FWP_E_TYPE_MISMATCH        , 2150760487U) /* 0x80320027 */ \
   XXX( HRES_FWP_E_OUT_OF_BOUNDS        , 2150760488U) /* 0x80320028 */ \
   XXX( HRES_FWP_E_RESERVED        , 2150760489U) /* 0x80320029 */ \
   XXX( HRES_FWP_E_DUPLICATE_CONDITION        , 2150760490U) /* 0x8032002a */ \
   XXX( HRES_FWP_E_DUPLICATE_KEYMOD        , 2150760491U) /* 0x8032002b */ \
   XXX( HRES_FWP_E_ACTION_INCOMPATIBLE_WITH_LAYER  , 2150760492U) /* 0x8032002c */ \
   XXX( HRES_FWP_E_ACTION_INCOMPATIBLE_WITH_SUBLAYER  , 2150760493U) /* 0x8032002d */ \
   XXX( HRES_FWP_E_CONTEXT_INCOMPATIBLE_WITH_LAYER  , 2150760494U) /* 0x8032002e */ \
   XXX( HRES_FWP_E_CONTEXT_INCOMPATIBLE_WITH_CALLOUT  , 2150760495U) /* 0x8032002f */ \
   XXX( HRES_FWP_E_INCOMPATIBLE_AUTH_METHOD     , 2150760496U) /* 0x80320030 */ \
   XXX( HRES_FWP_E_INCOMPATIBLE_DH_GROUP     , 2150760497U) /* 0x80320031 */ \
   XXX( HRES_FWP_E_EM_NOT_SUPPORTED        , 2150760498U) /* 0x80320032 */ \
   XXX( HRES_FWP_E_NEVER_MATCH        , 2150760499U) /* 0x80320033 */ \
   XXX( HRES_FWP_E_PROVIDER_CONTEXT_MISMATCH     , 2150760500U) /* 0x80320034 */ \
   XXX( HRES_FWP_E_INVALID_PARAMETER        , 2150760501U) /* 0x80320035 */ \
   XXX( HRES_FWP_E_TOO_MANY_SUBLAYERS        , 2150760502U) /* 0x80320036 */ \
   XXX( HRES_FWP_E_CALLOUT_NOTIFICATION_FAILED     , 2150760503U) /* 0x80320037 */ \
   XXX( HRES_FWP_E_INCOMPATIBLE_AUTH_CONFIG     , 2150760504U) /* 0x80320038 */ \
   XXX( HRES_FWP_E_INCOMPATIBLE_CIPHER_CONFIG     , 2150760505U) /* 0x80320039 */ \
   XXX( HRES_ERROR_NDIS_INTERFACE_CLOSING     , 2150891522U) /* 0x80340002 */ \
   XXX( HRES_ERROR_NDIS_BAD_VERSION        , 2150891524U) /* 0x80340004 */ \
   XXX( HRES_ERROR_NDIS_BAD_CHARACTERISTICS     , 2150891525U) /* 0x80340005 */ \
   XXX( HRES_ERROR_NDIS_ADAPTER_NOT_FOUND     , 2150891526U) /* 0x80340006 */ \
   XXX( HRES_ERROR_NDIS_OPEN_FAILED        , 2150891527U) /* 0x80340007 */ \
   XXX( HRES_ERROR_NDIS_DEVICE_FAILED        , 2150891528U) /* 0x80340008 */ \
   XXX( HRES_ERROR_NDIS_MULTICAST_FULL        , 2150891529U) /* 0x80340009 */ \
   XXX( HRES_ERROR_NDIS_MULTICAST_EXISTS     , 2150891530U) /* 0x8034000a */ \
   XXX( HRES_ERROR_NDIS_MULTICAST_NOT_FOUND     , 2150891531U) /* 0x8034000b */ \
   XXX( HRES_ERROR_NDIS_REQUEST_ABORTED        , 2150891532U) /* 0x8034000c */ \
   XXX( HRES_ERROR_NDIS_RESET_IN_PROGRESS     , 2150891533U) /* 0x8034000d */ \
   XXX( HRES_ERROR_NDIS_INVALID_PACKET        , 2150891535U) /* 0x8034000f */ \
   XXX( HRES_ERROR_NDIS_INVALID_DEVICE_REQUEST     , 2150891536U) /* 0x80340010 */ \
   XXX( HRES_ERROR_NDIS_ADAPTER_NOT_READY     , 2150891537U) /* 0x80340011 */ \
   XXX( HRES_ERROR_NDIS_INVALID_LENGTH        , 2150891540U) /* 0x80340014 */ \
   XXX( HRES_ERROR_NDIS_INVALID_DATA        , 2150891541U) /* 0x80340015 */ \
   XXX( HRES_ERROR_NDIS_BUFFER_TOO_SHORT     , 2150891542U) /* 0x80340016 */ \
   XXX( HRES_ERROR_NDIS_INVALID_OID        , 2150891543U) /* 0x80340017 */ \
   XXX( HRES_ERROR_NDIS_ADAPTER_REMOVED        , 2150891544U) /* 0x80340018 */ \
   XXX( HRES_ERROR_NDIS_UNSUPPORTED_MEDIA     , 2150891545U) /* 0x80340019 */ \
   XXX( HRES_ERROR_NDIS_GROUP_ADDRESS_IN_USE     , 2150891546U) /* 0x8034001a */ \
   XXX( HRES_ERROR_NDIS_FILE_NOT_FOUND        , 2150891547U) /* 0x8034001b */ \
   XXX( HRES_ERROR_NDIS_ERROR_READING_FILE     , 2150891548U) /* 0x8034001c */ \
   XXX( HRES_ERROR_NDIS_ALREADY_MAPPED        , 2150891549U) /* 0x8034001d */ \
   XXX( HRES_ERROR_NDIS_RESOURCE_CONFLICT     , 2150891550U) /* 0x8034001e */ \
   XXX( HRES_ERROR_NDIS_MEDIA_DISCONNECTED     , 2150891551U) /* 0x8034001f */ \
   XXX( HRES_ERROR_NDIS_INVALID_ADDRESS        , 2150891554U) /* 0x80340022 */ \
   XXX( HRES_ERROR_NDIS_PAUSED        , 2150891562U) /* 0x8034002a */ \
   XXX( HRES_ERROR_NDIS_INTERFACE_NOT_FOUND     , 2150891563U) /* 0x8034002b */ \
   XXX( HRES_ERROR_NDIS_UNSUPPORTED_REVISION     , 2150891564U) /* 0x8034002c */ \
   XXX( HRES_ERROR_NDIS_INVALID_PORT        , 2150891565U) /* 0x8034002d */ \
   XXX( HRES_ERROR_NDIS_INVALID_PORT_STATE     , 2150891566U) /* 0x8034002e */ \
   XXX( HRES_ERROR_NDIS_NOT_SUPPORTED        , 2150891707U) /* 0x803400bb */ \
   XXX( HRES_ERROR_NDIS_DOT11_AUTO_CONFIG_ENABLED  , 2150899712U) /* 0x80342000 */ \
   XXX( HRES_ERROR_NDIS_DOT11_MEDIA_IN_USE     , 2150899713U) /* 0x80342001 */ \
   XXX( HRES_ERROR_NDIS_DOT11_POWER_STATE_INVALID  , 2150899714U) /* 0x80342002 */ \
   XXX( HRES_TRK_E_NOT_FOUND        , 2380976155U) /* 0x8dead01b */ \
   XXX( HRES_TRK_E_VOLUME_QUOTA_EXCEEDED     , 2380976156U) /* 0x8dead01c */ \
   XXX( HRES_TRK_SERVER_TOO_BUSY        , 2380976158U) /* 0x8dead01e */ \
   XXX( HRES_ERROR_AUDITING_DISABLED        , 3221815297U) /* 0xc0090001 */ \
   XXX( HRES_ERROR_ALL_SIDS_FILTERED        , 3221815298U) /* 0xc0090002 */ \
   XXX( HRES_ERROR_BIZRULES_NOT_ENABLED        , 3221815299U) /* 0xc0090003 */ \
   XXX( HRES_NS_E_NOCONNECTION        , 3222077445U) /* 0xc00d0005 */ \
   XXX( HRES_NS_E_CANNOTCONNECT        , 3222077446U) /* 0xc00d0006 */ \
   XXX( HRES_NS_E_CANNOTDESTROYTITLE        , 3222077447U) /* 0xc00d0007 */ \
   XXX( HRES_NS_E_CANNOTRENAMETITLE        , 3222077448U) /* 0xc00d0008 */ \
   XXX( HRES_NS_E_CANNOTOFFLINEDISK        , 3222077449U) /* 0xc00d0009 */ \
   XXX( HRES_NS_E_CANNOTONLINEDISK        , 3222077450U) /* 0xc00d000a */ \
   XXX( HRES_NS_E_NOREGISTEREDWALKER        , 3222077451U) /* 0xc00d000b */ \
   XXX( HRES_NS_E_NOFUNNEL        , 3222077452U) /* 0xc00d000c */ \
   XXX( HRES_NS_E_NO_LOCALPLAY        , 3222077453U) /* 0xc00d000d */ \
   XXX( HRES_NS_E_NETWORK_BUSY        , 3222077454U) /* 0xc00d000e */ \
   XXX( HRES_NS_E_TOO_MANY_SESS        , 3222077455U) /* 0xc00d000f */ \
   XXX( HRES_NS_E_ALREADY_CONNECTED        , 3222077456U) /* 0xc00d0010 */ \
   XXX( HRES_NS_E_INVALID_INDEX        , 3222077457U) /* 0xc00d0011 */ \
   XXX( HRES_NS_E_PROTOCOL_MISMATCH        , 3222077458U) /* 0xc00d0012 */ \
   XXX( HRES_NS_E_TIMEOUT        , 3222077459U) /* 0xc00d0013 */ \
   XXX( HRES_NS_E_NET_WRITE        , 3222077460U) /* 0xc00d0014 */ \
   XXX( HRES_NS_E_NET_READ        , 3222077461U) /* 0xc00d0015 */ \
   XXX( HRES_NS_E_DISK_WRITE        , 3222077462U) /* 0xc00d0016 */ \
   XXX( HRES_NS_E_DISK_READ        , 3222077463U) /* 0xc00d0017 */ \
   XXX( HRES_NS_E_FILE_WRITE        , 3222077464U) /* 0xc00d0018 */ \
   XXX( HRES_NS_E_FILE_READ        , 3222077465U) /* 0xc00d0019 */ \
   XXX( HRES_NS_E_FILE_NOT_FOUND        , 3222077466U) /* 0xc00d001a */ \
   XXX( HRES_NS_E_FILE_EXISTS        , 3222077467U) /* 0xc00d001b */ \
   XXX( HRES_NS_E_INVALID_NAME        , 3222077468U) /* 0xc00d001c */ \
   XXX( HRES_NS_E_FILE_OPEN_FAILED        , 3222077469U) /* 0xc00d001d */ \
   XXX( HRES_NS_E_FILE_ALLOCATION_FAILED     , 3222077470U) /* 0xc00d001e */ \
   XXX( HRES_NS_E_FILE_INIT_FAILED        , 3222077471U) /* 0xc00d001f */ \
   XXX( HRES_NS_E_FILE_PLAY_FAILED        , 3222077472U) /* 0xc00d0020 */ \
   XXX( HRES_NS_E_SET_DISK_UID_FAILED        , 3222077473U) /* 0xc00d0021 */ \
   XXX( HRES_NS_E_INDUCED        , 3222077474U) /* 0xc00d0022 */ \
   XXX( HRES_NS_E_CCLINK_DOWN        , 3222077475U) /* 0xc00d0023 */ \
   XXX( HRES_NS_E_INTERNAL        , 3222077476U) /* 0xc00d0024 */ \
   XXX( HRES_NS_E_BUSY          , 3222077477U) /* 0xc00d0025 */ \
   XXX( HRES_NS_E_UNRECOGNIZED_STREAM_TYPE     , 3222077478U) /* 0xc00d0026 */ \
   XXX( HRES_NS_E_NETWORK_SERVICE_FAILURE     , 3222077479U) /* 0xc00d0027 */ \
   XXX( HRES_NS_E_NETWORK_RESOURCE_FAILURE     , 3222077480U) /* 0xc00d0028 */ \
   XXX( HRES_NS_E_CONNECTION_FAILURE        , 3222077481U) /* 0xc00d0029 */ \
   XXX( HRES_NS_E_SHUTDOWN        , 3222077482U) /* 0xc00d002a */ \
   XXX( HRES_NS_E_INVALID_REQUEST        , 3222077483U) /* 0xc00d002b */ \
   XXX( HRES_NS_E_INSUFFICIENT_BANDWIDTH     , 3222077484U) /* 0xc00d002c */ \
   XXX( HRES_NS_E_NOT_REBUILDING        , 3222077485U) /* 0xc00d002d */ \
   XXX( HRES_NS_E_LATE_OPERATION        , 3222077486U) /* 0xc00d002e */ \
   XXX( HRES_NS_E_INVALID_DATA        , 3222077487U) /* 0xc00d002f */ \
   XXX( HRES_NS_E_FILE_BANDWIDTH_LIMIT        , 3222077488U) /* 0xc00d0030 */ \
   XXX( HRES_NS_E_OPEN_FILE_LIMIT        , 3222077489U) /* 0xc00d0031 */ \
   XXX( HRES_NS_E_BAD_CONTROL_DATA        , 3222077490U) /* 0xc00d0032 */ \
   XXX( HRES_NS_E_NO_STREAM        , 3222077491U) /* 0xc00d0033 */ \
   XXX( HRES_NS_E_STREAM_END        , 3222077492U) /* 0xc00d0034 */ \
   XXX( HRES_NS_E_SERVER_NOT_FOUND        , 3222077493U) /* 0xc00d0035 */ \
   XXX( HRES_NS_E_DUPLICATE_NAME        , 3222077494U) /* 0xc00d0036 */ \
   XXX( HRES_NS_E_DUPLICATE_ADDRESS        , 3222077495U) /* 0xc00d0037 */ \
   XXX( HRES_NS_E_BAD_MULTICAST_ADDRESS        , 3222077496U) /* 0xc00d0038 */ \
   XXX( HRES_NS_E_BAD_ADAPTER_ADDRESS        , 3222077497U) /* 0xc00d0039 */ \
   XXX( HRES_NS_E_BAD_DELIVERY_MODE        , 3222077498U) /* 0xc00d003a */ \
   XXX( HRES_NS_E_INVALID_CHANNEL        , 3222077499U) /* 0xc00d003b */ \
   XXX( HRES_NS_E_INVALID_STREAM        , 3222077500U) /* 0xc00d003c */ \
   XXX( HRES_NS_E_INVALID_ARCHIVE        , 3222077501U) /* 0xc00d003d */ \
   XXX( HRES_NS_E_NOTITLES        , 3222077502U) /* 0xc00d003e */ \
   XXX( HRES_NS_E_INVALID_CLIENT        , 3222077503U) /* 0xc00d003f */ \
   XXX( HRES_NS_E_INVALID_BLACKHOLE_ADDRESS     , 3222077504U) /* 0xc00d0040 */ \
   XXX( HRES_NS_E_INCOMPATIBLE_FORMAT        , 3222077505U) /* 0xc00d0041 */ \
   XXX( HRES_NS_E_INVALID_KEY        , 3222077506U) /* 0xc00d0042 */ \
   XXX( HRES_NS_E_INVALID_PORT        , 3222077507U) /* 0xc00d0043 */ \
   XXX( HRES_NS_E_INVALID_TTL        , 3222077508U) /* 0xc00d0044 */ \
   XXX( HRES_NS_E_STRIDE_REFUSED        , 3222077509U) /* 0xc00d0045 */ \
   XXX( HRES_NS_E_MMSAUTOSERVER_CANTFINDWALKER     , 3222077510U) /* 0xc00d0046 */ \
   XXX( HRES_NS_E_MAX_BITRATE        , 3222077511U) /* 0xc00d0047 */ \
   XXX( HRES_NS_E_LOGFILEPERIOD        , 3222077512U) /* 0xc00d0048 */ \
   XXX( HRES_NS_E_MAX_CLIENTS        , 3222077513U) /* 0xc00d0049 */ \
   XXX( HRES_NS_E_LOG_FILE_SIZE        , 3222077514U) /* 0xc00d004a */ \
   XXX( HRES_NS_E_MAX_FILERATE        , 3222077515U) /* 0xc00d004b */ \
   XXX( HRES_NS_E_WALKER_UNKNOWN        , 3222077516U) /* 0xc00d004c */ \
   XXX( HRES_NS_E_WALKER_SERVER        , 3222077517U) /* 0xc00d004d */ \
   XXX( HRES_NS_E_WALKER_USAGE        , 3222077518U) /* 0xc00d004e */ \
   XXX( HRES_NS_E_TIGER_FAIL        , 3222077520U) /* 0xc00d0050 */ \
   XXX( HRES_NS_E_CUB_FAIL        , 3222077523U) /* 0xc00d0053 */ \
   XXX( HRES_NS_E_DISK_FAIL        , 3222077525U) /* 0xc00d0055 */ \
   XXX( HRES_NS_E_MAX_FUNNELS_ALERT        , 3222077536U) /* 0xc00d0060 */ \
   XXX( HRES_NS_E_ALLOCATE_FILE_FAIL        , 3222077537U) /* 0xc00d0061 */ \
   XXX( HRES_NS_E_PAGING_ERROR        , 3222077538U) /* 0xc00d0062 */ \
   XXX( HRES_NS_E_BAD_BLOCK0_VERSION        , 3222077539U) /* 0xc00d0063 */ \
   XXX( HRES_NS_E_BAD_DISK_UID        , 3222077540U) /* 0xc00d0064 */ \
   XXX( HRES_NS_E_BAD_FSMAJOR_VERSION        , 3222077541U) /* 0xc00d0065 */ \
   XXX( HRES_NS_E_BAD_STAMPNUMBER        , 3222077542U) /* 0xc00d0066 */ \
   XXX( HRES_NS_E_PARTIALLY_REBUILT_DISK     , 3222077543U) /* 0xc00d0067 */ \
   XXX( HRES_NS_E_ENACTPLAN_GIVEUP        , 3222077544U) /* 0xc00d0068 */ \
   XXX( HRES_MCMADM_E_REGKEY_NOT_FOUND        , 3222077546U) /* 0xc00d006a */ \
   XXX( HRES_NS_E_NO_FORMATS        , 3222077547U) /* 0xc00d006b */ \
   XXX( HRES_NS_E_NO_REFERENCES        , 3222077548U) /* 0xc00d006c */ \
   XXX( HRES_NS_E_WAVE_OPEN        , 3222077549U) /* 0xc00d006d */ \
   XXX( HRES_NS_E_CANNOTCONNECTEVENTS        , 3222077551U) /* 0xc00d006f */ \
   XXX( HRES_NS_E_NO_DEVICE        , 3222077553U) /* 0xc00d0071 */ \
   XXX( HRES_NS_E_NO_SPECIFIED_DEVICE        , 3222077554U) /* 0xc00d0072 */ \
   XXX( HRES_NS_E_MONITOR_GIVEUP        , 3222077640U) /* 0xc00d00c8 */ \
   XXX( HRES_NS_E_REMIRRORED_DISK        , 3222077641U) /* 0xc00d00c9 */ \
   XXX( HRES_NS_E_INSUFFICIENT_DATA        , 3222077642U) /* 0xc00d00ca */ \
   XXX( HRES_NS_E_ASSERT        , 3222077643U) /* 0xc00d00cb */ \
   XXX( HRES_NS_E_BAD_ADAPTER_NAME        , 3222077644U) /* 0xc00d00cc */ \
   XXX( HRES_NS_E_NOT_LICENSED        , 3222077645U) /* 0xc00d00cd */ \
   XXX( HRES_NS_E_NO_SERVER_CONTACT        , 3222077646U) /* 0xc00d00ce */ \
   XXX( HRES_NS_E_TOO_MANY_TITLES        , 3222077647U) /* 0xc00d00cf */ \
   XXX( HRES_NS_E_TITLE_SIZE_EXCEEDED        , 3222077648U) /* 0xc00d00d0 */ \
   XXX( HRES_NS_E_UDP_DISABLED        , 3222077649U) /* 0xc00d00d1 */ \
   XXX( HRES_NS_E_TCP_DISABLED        , 3222077650U) /* 0xc00d00d2 */ \
   XXX( HRES_NS_E_HTTP_DISABLED        , 3222077651U) /* 0xc00d00d3 */ \
   XXX( HRES_NS_E_LICENSE_EXPIRED        , 3222077652U) /* 0xc00d00d4 */ \
   XXX( HRES_NS_E_TITLE_BITRATE        , 3222077653U) /* 0xc00d00d5 */ \
   XXX( HRES_NS_E_EMPTY_PROGRAM_NAME        , 3222077654U) /* 0xc00d00d6 */ \
   XXX( HRES_NS_E_MISSING_CHANNEL        , 3222077655U) /* 0xc00d00d7 */ \
   XXX( HRES_NS_E_NO_CHANNELS        , 3222077656U) /* 0xc00d00d8 */ \
   XXX( HRES_NS_E_INVALID_INDEX2        , 3222077657U) /* 0xc00d00d9 */ \
   XXX( HRES_NS_E_CUB_FAIL_LINK        , 3222077840U) /* 0xc00d0190 */ \
   XXX( HRES_NS_E_BAD_CUB_UID        , 3222077842U) /* 0xc00d0192 */ \
   XXX( HRES_NS_E_GLITCH_MODE        , 3222077845U) /* 0xc00d0195 */ \
   XXX( HRES_NS_E_NO_MEDIA_PROTOCOL        , 3222077851U) /* 0xc00d019b */ \
   XXX( HRES_NS_E_NOTHING_TO_DO        , 3222079473U) /* 0xc00d07f1 */ \
   XXX( HRES_NS_E_NO_MULTICAST        , 3222079474U) /* 0xc00d07f2 */ \
   XXX( HRES_NS_E_INVALID_INPUT_FORMAT        , 3222080440U) /* 0xc00d0bb8 */ \
   XXX( HRES_NS_E_MSAUDIO_NOT_INSTALLED        , 3222080441U) /* 0xc00d0bb9 */ \
   XXX( HRES_NS_E_UNEXPECTED_MSAUDIO_ERROR     , 3222080442U) /* 0xc00d0bba */ \
   XXX( HRES_NS_E_INVALID_OUTPUT_FORMAT        , 3222080443U) /* 0xc00d0bbb */ \
   XXX( HRES_NS_E_NOT_CONFIGURED        , 3222080444U) /* 0xc00d0bbc */ \
   XXX( HRES_NS_E_PROTECTED_CONTENT        , 3222080445U) /* 0xc00d0bbd */ \
   XXX( HRES_NS_E_LICENSE_REQUIRED        , 3222080446U) /* 0xc00d0bbe */ \
   XXX( HRES_NS_E_TAMPERED_CONTENT        , 3222080447U) /* 0xc00d0bbf */ \
   XXX( HRES_NS_E_LICENSE_OUTOFDATE        , 3222080448U) /* 0xc00d0bc0 */ \
   XXX( HRES_NS_E_LICENSE_INCORRECT_RIGHTS     , 3222080449U) /* 0xc00d0bc1 */ \
   XXX( HRES_NS_E_AUDIO_CODEC_NOT_INSTALLED     , 3222080450U) /* 0xc00d0bc2 */ \
   XXX( HRES_NS_E_AUDIO_CODEC_ERROR        , 3222080451U) /* 0xc00d0bc3 */ \
   XXX( HRES_NS_E_VIDEO_CODEC_NOT_INSTALLED     , 3222080452U) /* 0xc00d0bc4 */ \
   XXX( HRES_NS_E_VIDEO_CODEC_ERROR        , 3222080453U) /* 0xc00d0bc5 */ \
   XXX( HRES_NS_E_INVALIDPROFILE        , 3222080454U) /* 0xc00d0bc6 */ \
   XXX( HRES_NS_E_INCOMPATIBLE_VERSION        , 3222080455U) /* 0xc00d0bc7 */ \
   XXX( HRES_NS_E_OFFLINE_MODE        , 3222080458U) /* 0xc00d0bca */ \
   XXX( HRES_NS_E_NOT_CONNECTED        , 3222080459U) /* 0xc00d0bcb */ \
   XXX( HRES_NS_E_TOO_MUCH_DATA        , 3222080460U) /* 0xc00d0bcc */ \
   XXX( HRES_NS_E_UNSUPPORTED_PROPERTY        , 3222080461U) /* 0xc00d0bcd */ \
   XXX( HRES_NS_E_8BIT_WAVE_UNSUPPORTED        , 3222080462U) /* 0xc00d0bce */ \
   XXX( HRES_NS_E_NO_MORE_SAMPLES        , 3222080463U) /* 0xc00d0bcf */ \
   XXX( HRES_NS_E_INVALID_SAMPLING_RATE        , 3222080464U) /* 0xc00d0bd0 */ \
   XXX( HRES_NS_E_MAX_PACKET_SIZE_TOO_SMALL     , 3222080465U) /* 0xc00d0bd1 */ \
   XXX( HRES_NS_E_LATE_PACKET        , 3222080466U) /* 0xc00d0bd2 */ \
   XXX( HRES_NS_E_DUPLICATE_PACKET        , 3222080467U) /* 0xc00d0bd3 */ \
   XXX( HRES_NS_E_SDK_BUFFERTOOSMALL        , 3222080468U) /* 0xc00d0bd4 */ \
   XXX( HRES_NS_E_INVALID_NUM_PASSES        , 3222080469U) /* 0xc00d0bd5 */ \
   XXX( HRES_NS_E_ATTRIBUTE_READ_ONLY        , 3222080470U) /* 0xc00d0bd6 */ \
   XXX( HRES_NS_E_ATTRIBUTE_NOT_ALLOWED        , 3222080471U) /* 0xc00d0bd7 */ \
   XXX( HRES_NS_E_INVALID_EDL        , 3222080472U) /* 0xc00d0bd8 */ \
   XXX( HRES_NS_E_DATA_UNIT_EXTENSION_TOO_LARGE     , 3222080473U) /* 0xc00d0bd9 */ \
   XXX( HRES_NS_E_CODEC_DMO_ERROR        , 3222080474U) /* 0xc00d0bda */ \
   XXX( HRES_NS_E_FEATURE_DISABLED_BY_GROUP_POLICY  , 3222080476U) /* 0xc00d0bdc */ \
   XXX( HRES_NS_E_FEATURE_DISABLED_IN_SKU     , 3222080477U) /* 0xc00d0bdd */ \
   XXX( HRES_NS_E_NO_CD          , 3222081440U) /* 0xc00d0fa0 */ \
   XXX( HRES_NS_E_CANT_READ_DIGITAL        , 3222081441U) /* 0xc00d0fa1 */ \
   XXX( HRES_NS_E_DEVICE_DISCONNECTED        , 3222081442U) /* 0xc00d0fa2 */ \
   XXX( HRES_NS_E_DEVICE_NOT_SUPPORT_FORMAT     , 3222081443U) /* 0xc00d0fa3 */ \
   XXX( HRES_NS_E_SLOW_READ_DIGITAL        , 3222081444U) /* 0xc00d0fa4 */ \
   XXX( HRES_NS_E_MIXER_INVALID_LINE        , 3222081445U) /* 0xc00d0fa5 */ \
   XXX( HRES_NS_E_MIXER_INVALID_CONTROL        , 3222081446U) /* 0xc00d0fa6 */ \
   XXX( HRES_NS_E_MIXER_INVALID_VALUE        , 3222081447U) /* 0xc00d0fa7 */ \
   XXX( HRES_NS_E_MIXER_UNKNOWN_MMRESULT     , 3222081448U) /* 0xc00d0fa8 */ \
   XXX( HRES_NS_E_USER_STOP        , 3222081449U) /* 0xc00d0fa9 */ \
   XXX( HRES_NS_E_MP3_FORMAT_NOT_FOUND        , 3222081450U) /* 0xc00d0faa */ \
   XXX( HRES_NS_E_CD_READ_ERROR_NO_CORRECTION     , 3222081451U) /* 0xc00d0fab */ \
   XXX( HRES_NS_E_CD_READ_ERROR        , 3222081452U) /* 0xc00d0fac */ \
   XXX( HRES_NS_E_CD_SLOW_COPY        , 3222081453U) /* 0xc00d0fad */ \
   XXX( HRES_NS_E_CD_COPYTO_CD        , 3222081454U) /* 0xc00d0fae */ \
   XXX( HRES_NS_E_MIXER_NODRIVER        , 3222081455U) /* 0xc00d0faf */ \
   XXX( HRES_NS_E_REDBOOK_ENABLED_WHILE_COPYING     , 3222081456U) /* 0xc00d0fb0 */ \
   XXX( HRES_NS_E_CD_REFRESH        , 3222081457U) /* 0xc00d0fb1 */ \
   XXX( HRES_NS_E_CD_DRIVER_PROBLEM        , 3222081458U) /* 0xc00d0fb2 */ \
   XXX( HRES_NS_E_WONT_DO_DIGITAL        , 3222081459U) /* 0xc00d0fb3 */ \
   XXX( HRES_NS_E_WMPXML_NOERROR        , 3222081460U) /* 0xc00d0fb4 */ \
   XXX( HRES_NS_E_WMPXML_ENDOFDATA        , 3222081461U) /* 0xc00d0fb5 */ \
   XXX( HRES_NS_E_WMPXML_PARSEERROR        , 3222081462U) /* 0xc00d0fb6 */ \
   XXX( HRES_NS_E_WMPXML_ATTRIBUTENOTFOUND     , 3222081463U) /* 0xc00d0fb7 */ \
   XXX( HRES_NS_E_WMPXML_PINOTFOUND        , 3222081464U) /* 0xc00d0fb8 */ \
   XXX( HRES_NS_E_WMPXML_EMPTYDOC        , 3222081465U) /* 0xc00d0fb9 */ \
   XXX( HRES_NS_E_WMP_PATH_ALREADY_IN_LIBRARY     , 3222081466U) /* 0xc00d0fba */ \
   XXX( HRES_NS_E_WMP_FILESCANALREADYSTARTED     , 3222081470U) /* 0xc00d0fbe */ \
   XXX( HRES_NS_E_WMP_HME_INVALIDOBJECTID     , 3222081471U) /* 0xc00d0fbf */ \
   XXX( HRES_NS_E_WMP_MF_CODE_EXPIRED        , 3222081472U) /* 0xc00d0fc0 */ \
   XXX( HRES_NS_E_WMP_HME_NOTSEARCHABLEFORITEMS     , 3222081473U) /* 0xc00d0fc1 */ \
   XXX( HRES_NS_E_WMP_ADDTOLIBRARY_FAILED     , 3222081479U) /* 0xc00d0fc7 */ \
   XXX( HRES_NS_E_WMP_WINDOWSAPIFAILURE        , 3222081480U) /* 0xc00d0fc8 */ \
   XXX( HRES_NS_E_WMP_RECORDING_NOT_ALLOWED     , 3222081481U) /* 0xc00d0fc9 */ \
   XXX( HRES_NS_E_DEVICE_NOT_READY        , 3222081482U) /* 0xc00d0fca */ \
   XXX( HRES_NS_E_DAMAGED_FILE        , 3222081483U) /* 0xc00d0fcb */ \
   XXX( HRES_NS_E_MPDB_GENERIC        , 3222081484U) /* 0xc00d0fcc */ \
   XXX( HRES_NS_E_FILE_FAILED_CHECKS        , 3222081485U) /* 0xc00d0fcd */ \
   XXX( HRES_NS_E_MEDIA_LIBRARY_FAILED        , 3222081486U) /* 0xc00d0fce */ \
   XXX( HRES_NS_E_SHARING_VIOLATION        , 3222081487U) /* 0xc00d0fcf */ \
   XXX( HRES_NS_E_NO_ERROR_STRING_FOUND        , 3222081488U) /* 0xc00d0fd0 */ \
   XXX( HRES_NS_E_WMPOCX_NO_REMOTE_CORE        , 3222081489U) /* 0xc00d0fd1 */ \
   XXX( HRES_NS_E_WMPOCX_NO_ACTIVE_CORE        , 3222081490U) /* 0xc00d0fd2 */ \
   XXX( HRES_NS_E_WMPOCX_NOT_RUNNING_REMOTELY     , 3222081491U) /* 0xc00d0fd3 */ \
   XXX( HRES_NS_E_WMPOCX_NO_REMOTE_WINDOW     , 3222081492U) /* 0xc00d0fd4 */ \
   XXX( HRES_NS_E_WMPOCX_ERRORMANAGERNOTAVAILABLE  , 3222081493U) /* 0xc00d0fd5 */ \
   XXX( HRES_NS_E_PLUGIN_NOTSHUTDOWN        , 3222081494U) /* 0xc00d0fd6 */ \
   XXX( HRES_NS_E_WMP_CANNOT_FIND_FOLDER     , 3222081495U) /* 0xc00d0fd7 */ \
   XXX( HRES_NS_E_WMP_STREAMING_RECORDING_NOT_ALLOWED  , 3222081496U) /* 0xc00d0fd8 */ \
   XXX( HRES_NS_E_WMP_PLUGINDLL_NOTFOUND     , 3222081497U) /* 0xc00d0fd9 */ \
   XXX( HRES_NS_E_NEED_TO_ASK_USER        , 3222081498U) /* 0xc00d0fda */ \
   XXX( HRES_NS_E_WMPOCX_PLAYER_NOT_DOCKED     , 3222081499U) /* 0xc00d0fdb */ \
   XXX( HRES_NS_E_WMP_EXTERNAL_NOTREADY        , 3222081500U) /* 0xc00d0fdc */ \
   XXX( HRES_NS_E_WMP_MLS_STALE_DATA        , 3222081501U) /* 0xc00d0fdd */ \
   XXX( HRES_NS_E_WMP_UI_SUBCONTROLSNOTSUPPORTED  , 3222081502U) /* 0xc00d0fde */ \
   XXX( HRES_NS_E_WMP_UI_VERSIONMISMATCH     , 3222081503U) /* 0xc00d0fdf */ \
   XXX( HRES_NS_E_WMP_UI_NOTATHEMEFILE        , 3222081504U) /* 0xc00d0fe0 */ \
   XXX( HRES_NS_E_WMP_UI_SUBELEMENTNOTFOUND     , 3222081505U) /* 0xc00d0fe1 */ \
   XXX( HRES_NS_E_WMP_UI_VERSIONPARSE        , 3222081506U) /* 0xc00d0fe2 */ \
   XXX( HRES_NS_E_WMP_UI_VIEWIDNOTFOUND        , 3222081507U) /* 0xc00d0fe3 */ \
   XXX( HRES_NS_E_WMP_UI_PASSTHROUGH        , 3222081508U) /* 0xc00d0fe4 */ \
   XXX( HRES_NS_E_WMP_UI_OBJECTNOTFOUND        , 3222081509U) /* 0xc00d0fe5 */ \
   XXX( HRES_NS_E_WMP_UI_SECONDHANDLER        , 3222081510U) /* 0xc00d0fe6 */ \
   XXX( HRES_NS_E_WMP_UI_NOSKININZIP        , 3222081511U) /* 0xc00d0fe7 */ \
   XXX( HRES_NS_E_WMP_URLDOWNLOADFAILED        , 3222081514U) /* 0xc00d0fea */ \
   XXX( HRES_NS_E_WMPOCX_UNABLE_TO_LOAD_SKIN     , 3222081515U) /* 0xc00d0feb */ \
   XXX( HRES_NS_E_WMP_INVALID_SKIN        , 3222081516U) /* 0xc00d0fec */ \
   XXX( HRES_NS_E_WMP_SENDMAILFAILED        , 3222081517U) /* 0xc00d0fed */ \
   XXX( HRES_NS_E_WMP_LOCKEDINSKINMODE        , 3222081518U) /* 0xc00d0fee */ \
   XXX( HRES_NS_E_WMP_FAILED_TO_SAVE_FILE     , 3222081519U) /* 0xc00d0fef */ \
   XXX( HRES_NS_E_WMP_SAVEAS_READONLY        , 3222081520U) /* 0xc00d0ff0 */ \
   XXX( HRES_NS_E_WMP_FAILED_TO_SAVE_PLAYLIST     , 3222081521U) /* 0xc00d0ff1 */ \
   XXX( HRES_NS_E_WMP_FAILED_TO_OPEN_WMD     , 3222081522U) /* 0xc00d0ff2 */ \
   XXX( HRES_NS_E_WMP_CANT_PLAY_PROTECTED     , 3222081523U) /* 0xc00d0ff3 */ \
   XXX( HRES_NS_E_SHARING_STATE_OUT_OF_SYNC     , 3222081524U) /* 0xc00d0ff4 */ \
   XXX( HRES_NS_E_WMPOCX_REMOTE_PLAYER_ALREADY_RUNNING  , 3222081530U) /* 0xc00d0ffa */ \
   XXX( HRES_NS_E_WMP_RBC_JPGMAPPINGIMAGE     , 3222081540U) /* 0xc00d1004 */ \
   XXX( HRES_NS_E_WMP_JPGTRANSPARENCY        , 3222081541U) /* 0xc00d1005 */ \
   XXX( HRES_NS_E_WMP_INVALID_MAX_VAL        , 3222081545U) /* 0xc00d1009 */ \
   XXX( HRES_NS_E_WMP_INVALID_MIN_VAL        , 3222081546U) /* 0xc00d100a */ \
   XXX( HRES_NS_E_WMP_CS_JPGPOSITIONIMAGE     , 3222081550U) /* 0xc00d100e */ \
   XXX( HRES_NS_E_WMP_CS_NOTEVENLYDIVISIBLE     , 3222081551U) /* 0xc00d100f */ \
   XXX( HRES_NS_E_WMPZIP_NOTAZIPFILE        , 3222081560U) /* 0xc00d1018 */ \
   XXX( HRES_NS_E_WMPZIP_CORRUPT        , 3222081561U) /* 0xc00d1019 */ \
   XXX( HRES_NS_E_WMPZIP_FILENOTFOUND        , 3222081562U) /* 0xc00d101a */ \
   XXX( HRES_NS_E_WMP_IMAGE_FILETYPE_UNSUPPORTED  , 3222081570U) /* 0xc00d1022 */ \
   XXX( HRES_NS_E_WMP_IMAGE_INVALID_FORMAT     , 3222081571U) /* 0xc00d1023 */ \
   XXX( HRES_NS_E_WMP_GIF_UNEXPECTED_ENDOFFILE     , 3222081572U) /* 0xc00d1024 */ \
   XXX( HRES_NS_E_WMP_GIF_INVALID_FORMAT     , 3222081573U) /* 0xc00d1025 */ \
   XXX( HRES_NS_E_WMP_GIF_BAD_VERSION_NUMBER     , 3222081574U) /* 0xc00d1026 */ \
   XXX( HRES_NS_E_WMP_GIF_NO_IMAGE_IN_FILE     , 3222081575U) /* 0xc00d1027 */ \
   XXX( HRES_NS_E_WMP_PNG_INVALIDFORMAT        , 3222081576U) /* 0xc00d1028 */ \
   XXX( HRES_NS_E_WMP_PNG_UNSUPPORTED_BITDEPTH     , 3222081577U) /* 0xc00d1029 */ \
   XXX( HRES_NS_E_WMP_PNG_UNSUPPORTED_COMPRESSION  , 3222081578U) /* 0xc00d102a */ \
   XXX( HRES_NS_E_WMP_PNG_UNSUPPORTED_FILTER     , 3222081579U) /* 0xc00d102b */ \
   XXX( HRES_NS_E_WMP_PNG_UNSUPPORTED_INTERLACE     , 3222081580U) /* 0xc00d102c */ \
   XXX( HRES_NS_E_WMP_PNG_UNSUPPORTED_BAD_CRC     , 3222081581U) /* 0xc00d102d */ \
   XXX( HRES_NS_E_WMP_BMP_INVALID_BITMASK     , 3222081582U) /* 0xc00d102e */ \
   XXX( HRES_NS_E_WMP_BMP_TOPDOWN_DIB_UNSUPPORTED  , 3222081583U) /* 0xc00d102f */ \
   XXX( HRES_NS_E_WMP_BMP_BITMAP_NOT_CREATED     , 3222081584U) /* 0xc00d1030 */ \
   XXX( HRES_NS_E_WMP_BMP_COMPRESSION_UNSUPPORTED  , 3222081585U) /* 0xc00d1031 */ \
   XXX( HRES_NS_E_WMP_BMP_INVALID_FORMAT     , 3222081586U) /* 0xc00d1032 */ \
   XXX( HRES_NS_E_WMP_JPG_JERR_ARITHCODING_NOTIMPL  , 3222081587U) /* 0xc00d1033 */ \
   XXX( HRES_NS_E_WMP_JPG_INVALID_FORMAT     , 3222081588U) /* 0xc00d1034 */ \
   XXX( HRES_NS_E_WMP_JPG_BAD_DCTSIZE        , 3222081589U) /* 0xc00d1035 */ \
   XXX( HRES_NS_E_WMP_JPG_BAD_VERSION_NUMBER     , 3222081590U) /* 0xc00d1036 */ \
   XXX( HRES_NS_E_WMP_JPG_BAD_PRECISION        , 3222081591U) /* 0xc00d1037 */ \
   XXX( HRES_NS_E_WMP_JPG_CCIR601_NOTIMPL     , 3222081592U) /* 0xc00d1038 */ \
   XXX( HRES_NS_E_WMP_JPG_NO_IMAGE_IN_FILE     , 3222081593U) /* 0xc00d1039 */ \
   XXX( HRES_NS_E_WMP_JPG_READ_ERROR        , 3222081594U) /* 0xc00d103a */ \
   XXX( HRES_NS_E_WMP_JPG_FRACT_SAMPLE_NOTIMPL     , 3222081595U) /* 0xc00d103b */ \
   XXX( HRES_NS_E_WMP_JPG_IMAGE_TOO_BIG        , 3222081596U) /* 0xc00d103c */ \
   XXX( HRES_NS_E_WMP_JPG_UNEXPECTED_ENDOFFILE     , 3222081597U) /* 0xc00d103d */ \
   XXX( HRES_NS_E_WMP_JPG_SOF_UNSUPPORTED     , 3222081598U) /* 0xc00d103e */ \
   XXX( HRES_NS_E_WMP_JPG_UNKNOWN_MARKER     , 3222081599U) /* 0xc00d103f */ \
   XXX( HRES_NS_E_WMP_FAILED_TO_OPEN_IMAGE     , 3222081604U) /* 0xc00d1044 */ \
   XXX( HRES_NS_E_WMP_DAI_SONGTOOSHORT        , 3222081609U) /* 0xc00d1049 */ \
   XXX( HRES_NS_E_WMG_RATEUNAVAILABLE        , 3222081610U) /* 0xc00d104a */ \
   XXX( HRES_NS_E_WMG_PLUGINUNAVAILABLE        , 3222081611U) /* 0xc00d104b */ \
   XXX( HRES_NS_E_WMG_CANNOTQUEUE        , 3222081612U) /* 0xc00d104c */ \
   XXX( HRES_NS_E_WMG_PREROLLLICENSEACQUISITIONNOTALLOWED, 3222081613U) /* 0xc00d104d */ \
   XXX( HRES_NS_E_WMG_UNEXPECTEDPREROLLSTATUS     , 3222081614U) /* 0xc00d104e */ \
   XXX( HRES_NS_E_WMG_INVALID_COPP_CERTIFICATE     , 3222081617U) /* 0xc00d1051 */ \
   XXX( HRES_NS_E_WMG_COPP_SECURITY_INVALID     , 3222081618U) /* 0xc00d1052 */ \
   XXX( HRES_NS_E_WMG_COPP_UNSUPPORTED        , 3222081619U) /* 0xc00d1053 */ \
   XXX( HRES_NS_E_WMG_INVALIDSTATE        , 3222081620U) /* 0xc00d1054 */ \
   XXX( HRES_NS_E_WMG_SINKALREADYEXISTS        , 3222081621U) /* 0xc00d1055 */ \
   XXX( HRES_NS_E_WMG_NOSDKINTERFACE        , 3222081622U) /* 0xc00d1056 */ \
   XXX( HRES_NS_E_WMG_NOTALLOUTPUTSRENDERED     , 3222081623U) /* 0xc00d1057 */ \
   XXX( HRES_NS_E_WMG_FILETRANSFERNOTALLOWED     , 3222081624U) /* 0xc00d1058 */ \
   XXX( HRES_NS_E_WMR_UNSUPPORTEDSTREAM        , 3222081625U) /* 0xc00d1059 */ \
   XXX( HRES_NS_E_WMR_PINNOTFOUND        , 3222081626U) /* 0xc00d105a */ \
   XXX( HRES_NS_E_WMR_WAITINGONFORMATSWITCH     , 3222081627U) /* 0xc00d105b */ \
   XXX( HRES_NS_E_WMR_NOSOURCEFILTER        , 3222081628U) /* 0xc00d105c */ \
   XXX( HRES_NS_E_WMR_PINTYPENOMATCH        , 3222081629U) /* 0xc00d105d */ \
   XXX( HRES_NS_E_WMR_NOCALLBACKAVAILABLE     , 3222081630U) /* 0xc00d105e */ \
   XXX( HRES_NS_E_WMR_SAMPLEPROPERTYNOTSET     , 3222081634U) /* 0xc00d1062 */ \
   XXX( HRES_NS_E_WMR_CANNOT_RENDER_BINARY_STREAM  , 3222081635U) /* 0xc00d1063 */ \
   XXX( HRES_NS_E_WMG_LICENSE_TAMPERED        , 3222081636U) /* 0xc00d1064 */ \
   XXX( HRES_NS_E_WMR_WILLNOT_RENDER_BINARY_STREAM  , 3222081637U) /* 0xc00d1065 */ \
   XXX( HRES_NS_E_WMX_UNRECOGNIZED_PLAYLIST_FORMAT  , 3222081640U) /* 0xc00d1068 */ \
   XXX( HRES_NS_E_ASX_INVALIDFORMAT        , 3222081641U) /* 0xc00d1069 */ \
   XXX( HRES_NS_E_ASX_INVALIDVERSION        , 3222081642U) /* 0xc00d106a */ \
   XXX( HRES_NS_E_ASX_INVALID_REPEAT_BLOCK     , 3222081643U) /* 0xc00d106b */ \
   XXX( HRES_NS_E_ASX_NOTHING_TO_WRITE        , 3222081644U) /* 0xc00d106c */ \
   XXX( HRES_NS_E_URLLIST_INVALIDFORMAT        , 3222081645U) /* 0xc00d106d */ \
   XXX( HRES_NS_E_WMX_ATTRIBUTE_DOES_NOT_EXIST     , 3222081646U) /* 0xc00d106e */ \
   XXX( HRES_NS_E_WMX_ATTRIBUTE_ALREADY_EXISTS     , 3222081647U) /* 0xc00d106f */ \
   XXX( HRES_NS_E_WMX_ATTRIBUTE_UNRETRIEVABLE     , 3222081648U) /* 0xc00d1070 */ \
   XXX( HRES_NS_E_WMX_ITEM_DOES_NOT_EXIST     , 3222081649U) /* 0xc00d1071 */ \
   XXX( HRES_NS_E_WMX_ITEM_TYPE_ILLEGAL        , 3222081650U) /* 0xc00d1072 */ \
   XXX( HRES_NS_E_WMX_ITEM_UNSETTABLE        , 3222081651U) /* 0xc00d1073 */ \
   XXX( HRES_NS_E_WMX_PLAYLIST_EMPTY        , 3222081652U) /* 0xc00d1074 */ \
   XXX( HRES_NS_E_MLS_SMARTPLAYLIST_FILTER_NOT_REGISTERED, 3222081653U) /* 0xc00d1075 */ \
   XXX( HRES_NS_E_WMX_INVALID_FORMAT_OVER_NESTING  , 3222081654U) /* 0xc00d1076 */ \
   XXX( HRES_NS_E_WMPCORE_NOSOURCEURLSTRING     , 3222081660U) /* 0xc00d107c */ \
   XXX( HRES_NS_E_WMPCORE_COCREATEFAILEDFORGITOBJECT  , 3222081661U) /* 0xc00d107d */ \
   XXX( HRES_NS_E_WMPCORE_FAILEDTOGETMARSHALLEDEVENTHANDLERINTERFACE, 3222081662U) /* 0xc00d107e */ \
   XXX( HRES_NS_E_WMPCORE_BUFFERTOOSMALL     , 3222081663U) /* 0xc00d107f */ \
   XXX( HRES_NS_E_WMPCORE_UNAVAILABLE        , 3222081664U) /* 0xc00d1080 */ \
   XXX( HRES_NS_E_WMPCORE_INVALIDPLAYLISTMODE     , 3222081665U) /* 0xc00d1081 */ \
   XXX( HRES_NS_E_WMPCORE_ITEMNOTINPLAYLIST     , 3222081670U) /* 0xc00d1086 */ \
   XXX( HRES_NS_E_WMPCORE_PLAYLISTEMPTY        , 3222081671U) /* 0xc00d1087 */ \
   XXX( HRES_NS_E_WMPCORE_NOBROWSER        , 3222081672U) /* 0xc00d1088 */ \
   XXX( HRES_NS_E_WMPCORE_UNRECOGNIZED_MEDIA_URL  , 3222081673U) /* 0xc00d1089 */ \
   XXX( HRES_NS_E_WMPCORE_GRAPH_NOT_IN_LIST     , 3222081674U) /* 0xc00d108a */ \
   XXX( HRES_NS_E_WMPCORE_PLAYLIST_EMPTY_OR_SINGLE_MEDIA, 3222081675U) /* 0xc00d108b */ \
   XXX( HRES_NS_E_WMPCORE_ERRORSINKNOTREGISTERED  , 3222081676U) /* 0xc00d108c */ \
   XXX( HRES_NS_E_WMPCORE_ERRORMANAGERNOTAVAILABLE  , 3222081677U) /* 0xc00d108d */ \
   XXX( HRES_NS_E_WMPCORE_WEBHELPFAILED        , 3222081678U) /* 0xc00d108e */ \
   XXX( HRES_NS_E_WMPCORE_MEDIA_ERROR_RESUME_FAILED  , 3222081679U) /* 0xc00d108f */ \
   XXX( HRES_NS_E_WMPCORE_NO_REF_IN_ENTRY     , 3222081680U) /* 0xc00d1090 */ \
   XXX( HRES_NS_E_WMPCORE_WMX_LIST_ATTRIBUTE_NAME_EMPTY, 3222081681U) /* 0xc00d1091 */ \
   XXX( HRES_NS_E_WMPCORE_WMX_LIST_ATTRIBUTE_NAME_ILLEGAL, 3222081682U) /* 0xc00d1092 */ \
   XXX( HRES_NS_E_WMPCORE_WMX_LIST_ATTRIBUTE_VALUE_EMPTY, 3222081683U) /* 0xc00d1093 */ \
   XXX( HRES_NS_E_WMPCORE_WMX_LIST_ATTRIBUTE_VALUE_ILLEGAL, 3222081684U) /* 0xc00d1094 */ \
   XXX( HRES_NS_E_WMPCORE_WMX_LIST_ITEM_ATTRIBUTE_NAME_EMPTY, 3222081685U) /* 0xc00d1095 */ \
   XXX( HRES_NS_E_WMPCORE_WMX_LIST_ITEM_ATTRIBUTE_NAME_ILLEGAL, 3222081686U) /* 0xc00d1096 */ \
   XXX( HRES_NS_E_WMPCORE_WMX_LIST_ITEM_ATTRIBUTE_VALUE_EMPTY, 3222081687U) /* 0xc00d1097 */ \
   XXX( HRES_NS_E_WMPCORE_LIST_ENTRY_NO_REF     , 3222081688U) /* 0xc00d1098 */ \
   XXX( HRES_NS_E_WMPCORE_MISNAMED_FILE        , 3222081689U) /* 0xc00d1099 */ \
   XXX( HRES_NS_E_WMPCORE_CODEC_NOT_TRUSTED     , 3222081690U) /* 0xc00d109a */ \
   XXX( HRES_NS_E_WMPCORE_CODEC_NOT_FOUND     , 3222081691U) /* 0xc00d109b */ \
   XXX( HRES_NS_E_WMPCORE_CODEC_DOWNLOAD_NOT_ALLOWED  , 3222081692U) /* 0xc00d109c */ \
   XXX( HRES_NS_E_WMPCORE_ERROR_DOWNLOADING_PLAYLIST  , 3222081693U) /* 0xc00d109d */ \
   XXX( HRES_NS_E_WMPCORE_FAILED_TO_BUILD_PLAYLIST  , 3222081694U) /* 0xc00d109e */ \
   XXX( HRES_NS_E_WMPCORE_PLAYLIST_ITEM_ALTERNATE_NONE  , 3222081695U) /* 0xc00d109f */ \
   XXX( HRES_NS_E_WMPCORE_PLAYLIST_ITEM_ALTERNATE_EXHAUSTED, 3222081696U) /* 0xc00d10a0 */ \
   XXX( HRES_NS_E_WMPCORE_PLAYLIST_ITEM_ALTERNATE_NAME_NOT_FOUND, 3222081697U) /* 0xc00d10a1 */ \
   XXX( HRES_NS_E_WMPCORE_PLAYLIST_ITEM_ALTERNATE_MORPH_FAILED, 3222081698U) /* 0xc00d10a2 */ \
   XXX( HRES_NS_E_WMPCORE_PLAYLIST_ITEM_ALTERNATE_INIT_FAILED, 3222081699U) /* 0xc00d10a3 */ \
   XXX( HRES_NS_E_WMPCORE_MEDIA_ALTERNATE_REF_EMPTY  , 3222081700U) /* 0xc00d10a4 */ \
   XXX( HRES_NS_E_WMPCORE_PLAYLIST_NO_EVENT_NAME  , 3222081701U) /* 0xc00d10a5 */ \
   XXX( HRES_NS_E_WMPCORE_PLAYLIST_EVENT_ATTRIBUTE_ABSENT, 3222081702U) /* 0xc00d10a6 */ \
   XXX( HRES_NS_E_WMPCORE_PLAYLIST_EVENT_EMPTY     , 3222081703U) /* 0xc00d10a7 */ \
   XXX( HRES_NS_E_WMPCORE_PLAYLIST_STACK_EMPTY     , 3222081704U) /* 0xc00d10a8 */ \
   XXX( HRES_NS_E_WMPCORE_CURRENT_MEDIA_NOT_ACTIVE  , 3222081705U) /* 0xc00d10a9 */ \
   XXX( HRES_NS_E_WMPCORE_USER_CANCEL        , 3222081707U) /* 0xc00d10ab */ \
   XXX( HRES_NS_E_WMPCORE_PLAYLIST_REPEAT_EMPTY     , 3222081708U) /* 0xc00d10ac */ \
   XXX( HRES_NS_E_WMPCORE_PLAYLIST_REPEAT_START_MEDIA_NONE, 3222081709U) /* 0xc00d10ad */ \
   XXX( HRES_NS_E_WMPCORE_PLAYLIST_REPEAT_END_MEDIA_NONE, 3222081710U) /* 0xc00d10ae */ \
   XXX( HRES_NS_E_WMPCORE_INVALID_PLAYLIST_URL     , 3222081711U) /* 0xc00d10af */ \
   XXX( HRES_NS_E_WMPCORE_MISMATCHED_RUNTIME     , 3222081712U) /* 0xc00d10b0 */ \
   XXX( HRES_NS_E_WMPCORE_PLAYLIST_IMPORT_FAILED_NO_ITEMS, 3222081713U) /* 0xc00d10b1 */ \
   XXX( HRES_NS_E_WMPCORE_VIDEO_TRANSFORM_FILTER_INSERTION, 3222081714U) /* 0xc00d10b2 */ \
   XXX( HRES_NS_E_WMPCORE_MEDIA_UNAVAILABLE     , 3222081715U) /* 0xc00d10b3 */ \
   XXX( HRES_NS_E_WMPCORE_WMX_ENTRYREF_NO_REF     , 3222081716U) /* 0xc00d10b4 */ \
   XXX( HRES_NS_E_WMPCORE_NO_PLAYABLE_MEDIA_IN_PLAYLIST, 3222081717U) /* 0xc00d10b5 */ \
   XXX( HRES_NS_E_WMPCORE_PLAYLIST_EMPTY_NESTED_PLAYLIST_SKIPPED_ITEMS, 3222081718U) /* 0xc00d10b6 */ \
   XXX( HRES_NS_E_WMPCORE_BUSY        , 3222081719U) /* 0xc00d10b7 */ \
   XXX( HRES_NS_E_WMPCORE_MEDIA_CHILD_PLAYLIST_UNAVAILABLE, 3222081720U) /* 0xc00d10b8 */ \
   XXX( HRES_NS_E_WMPCORE_MEDIA_NO_CHILD_PLAYLIST  , 3222081721U) /* 0xc00d10b9 */ \
   XXX( HRES_NS_E_WMPCORE_FILE_NOT_FOUND     , 3222081722U) /* 0xc00d10ba */ \
   XXX( HRES_NS_E_WMPCORE_TEMP_FILE_NOT_FOUND     , 3222081723U) /* 0xc00d10bb */ \
   XXX( HRES_NS_E_WMDM_REVOKED        , 3222081724U) /* 0xc00d10bc */ \
   XXX( HRES_NS_E_DDRAW_GENERIC        , 3222081725U) /* 0xc00d10bd */ \
   XXX( HRES_NS_E_DISPLAY_MODE_CHANGE_FAILED     , 3222081726U) /* 0xc00d10be */ \
   XXX( HRES_NS_E_PLAYLIST_CONTAINS_ERRORS     , 3222081727U) /* 0xc00d10bf */ \
   XXX( HRES_NS_E_CHANGING_PROXY_NAME        , 3222081728U) /* 0xc00d10c0 */ \
   XXX( HRES_NS_E_CHANGING_PROXY_PORT        , 3222081729U) /* 0xc00d10c1 */ \
   XXX( HRES_NS_E_CHANGING_PROXY_EXCEPTIONLIST     , 3222081730U) /* 0xc00d10c2 */ \
   XXX( HRES_NS_E_CHANGING_PROXYBYPASS        , 3222081731U) /* 0xc00d10c3 */ \
   XXX( HRES_NS_E_CHANGING_PROXY_PROTOCOL_NOT_FOUND  , 3222081732U) /* 0xc00d10c4 */ \
   XXX( HRES_NS_E_GRAPH_NOAUDIOLANGUAGE        , 3222081733U) /* 0xc00d10c5 */ \
   XXX( HRES_NS_E_GRAPH_NOAUDIOLANGUAGESELECTED     , 3222081734U) /* 0xc00d10c6 */ \
   XXX( HRES_NS_E_CORECD_NOTAMEDIACD        , 3222081735U) /* 0xc00d10c7 */ \
   XXX( HRES_NS_E_WMPCORE_MEDIA_URL_TOO_LONG     , 3222081736U) /* 0xc00d10c8 */ \
   XXX( HRES_NS_E_WMPFLASH_CANT_FIND_COM_SERVER     , 3222081737U) /* 0xc00d10c9 */ \
   XXX( HRES_NS_E_WMPFLASH_INCOMPATIBLEVERSION     , 3222081738U) /* 0xc00d10ca */ \
   XXX( HRES_NS_E_WMPOCXGRAPH_IE_DISALLOWS_ACTIVEX_CONTROLS, 3222081739U) /* 0xc00d10cb */ \
   XXX( HRES_NS_E_NEED_CORE_REFERENCE        , 3222081740U) /* 0xc00d10cc */ \
   XXX( HRES_NS_E_MEDIACD_READ_ERROR        , 3222081741U) /* 0xc00d10cd */ \
   XXX( HRES_NS_E_IE_DISALLOWS_ACTIVEX_CONTROLS     , 3222081742U) /* 0xc00d10ce */ \
   XXX( HRES_NS_E_FLASH_PLAYBACK_NOT_ALLOWED     , 3222081743U) /* 0xc00d10cf */ \
   XXX( HRES_NS_E_UNABLE_TO_CREATE_RIP_LOCATION     , 3222081744U) /* 0xc00d10d0 */ \
   XXX( HRES_NS_E_WMPCORE_SOME_CODECS_MISSING     , 3222081745U) /* 0xc00d10d1 */ \
   XXX( HRES_NS_E_WMP_RIP_FAILED        , 3222081746U) /* 0xc00d10d2 */ \
   XXX( HRES_NS_E_WMP_FAILED_TO_RIP_TRACK     , 3222081747U) /* 0xc00d10d3 */ \
   XXX( HRES_NS_E_WMP_ERASE_FAILED        , 3222081748U) /* 0xc00d10d4 */ \
   XXX( HRES_NS_E_WMP_FORMAT_FAILED        , 3222081749U) /* 0xc00d10d5 */ \
   XXX( HRES_NS_E_WMP_CANNOT_BURN_NON_LOCAL_FILE  , 3222081750U) /* 0xc00d10d6 */ \
   XXX( HRES_NS_E_WMP_FILE_TYPE_CANNOT_BURN_TO_AUDIO_CD, 3222081751U) /* 0xc00d10d7 */ \
   XXX( HRES_NS_E_WMP_FILE_DOES_NOT_FIT_ON_CD     , 3222081752U) /* 0xc00d10d8 */ \
   XXX( HRES_NS_E_WMP_FILE_NO_DURATION        , 3222081753U) /* 0xc00d10d9 */ \
   XXX( HRES_NS_E_PDA_FAILED_TO_BURN        , 3222081754U) /* 0xc00d10da */ \
   XXX( HRES_NS_E_FAILED_DOWNLOAD_ABORT_BURN     , 3222081756U) /* 0xc00d10dc */ \
   XXX( HRES_NS_E_WMPCORE_DEVICE_DRIVERS_MISSING  , 3222081757U) /* 0xc00d10dd */ \
   XXX( HRES_NS_E_WMPIM_USEROFFLINE        , 3222081830U) /* 0xc00d1126 */ \
   XXX( HRES_NS_E_WMPIM_USERCANCELED        , 3222081831U) /* 0xc00d1127 */ \
   XXX( HRES_NS_E_WMPIM_DIALUPFAILED        , 3222081832U) /* 0xc00d1128 */ \
   XXX( HRES_NS_E_WINSOCK_ERROR_STRING        , 3222081833U) /* 0xc00d1129 */ \
   XXX( HRES_NS_E_WMPBR_NOLISTENER        , 3222081840U) /* 0xc00d1130 */ \
   XXX( HRES_NS_E_WMPBR_BACKUPCANCEL        , 3222081841U) /* 0xc00d1131 */ \
   XXX( HRES_NS_E_WMPBR_RESTORECANCEL        , 3222081842U) /* 0xc00d1132 */ \
   XXX( HRES_NS_E_WMPBR_ERRORWITHURL        , 3222081843U) /* 0xc00d1133 */ \
   XXX( HRES_NS_E_WMPBR_NAMECOLLISION        , 3222081844U) /* 0xc00d1134 */ \
   XXX( HRES_NS_E_WMPBR_DRIVE_INVALID        , 3222081847U) /* 0xc00d1137 */ \
   XXX( HRES_NS_E_WMPBR_BACKUPRESTOREFAILED     , 3222081848U) /* 0xc00d1138 */ \
   XXX( HRES_NS_E_WMP_CONVERT_FILE_FAILED     , 3222081880U) /* 0xc00d1158 */ \
   XXX( HRES_NS_E_WMP_CONVERT_NO_RIGHTS_ERRORURL  , 3222081881U) /* 0xc00d1159 */ \
   XXX( HRES_NS_E_WMP_CONVERT_NO_RIGHTS_NOERRORURL  , 3222081882U) /* 0xc00d115a */ \
   XXX( HRES_NS_E_WMP_CONVERT_FILE_CORRUPT     , 3222081883U) /* 0xc00d115b */ \
   XXX( HRES_NS_E_WMP_CONVERT_PLUGIN_UNAVAILABLE_ERRORURL, 3222081884U) /* 0xc00d115c */ \
   XXX( HRES_NS_E_WMP_CONVERT_PLUGIN_UNAVAILABLE_NOERRORURL, 3222081885U) /* 0xc00d115d */ \
   XXX( HRES_NS_E_WMP_CONVERT_PLUGIN_UNKNOWN_FILE_OWNER, 3222081886U) /* 0xc00d115e */ \
   XXX( HRES_NS_E_DVD_DISC_COPY_PROTECT_OUTPUT_NS  , 3222081888U) /* 0xc00d1160 */ \
   XXX( HRES_NS_E_DVD_DISC_COPY_PROTECT_OUTPUT_FAILED  , 3222081889U) /* 0xc00d1161 */ \
   XXX( HRES_NS_E_DVD_NO_SUBPICTURE_STREAM     , 3222081890U) /* 0xc00d1162 */ \
   XXX( HRES_NS_E_DVD_COPY_PROTECT        , 3222081891U) /* 0xc00d1163 */ \
   XXX( HRES_NS_E_DVD_AUTHORING_PROBLEM        , 3222081892U) /* 0xc00d1164 */ \
   XXX( HRES_NS_E_DVD_INVALID_DISC_REGION     , 3222081893U) /* 0xc00d1165 */ \
   XXX( HRES_NS_E_DVD_COMPATIBLE_VIDEO_CARD     , 3222081894U) /* 0xc00d1166 */ \
   XXX( HRES_NS_E_DVD_MACROVISION        , 3222081895U) /* 0xc00d1167 */ \
   XXX( HRES_NS_E_DVD_SYSTEM_DECODER_REGION     , 3222081896U) /* 0xc00d1168 */ \
   XXX( HRES_NS_E_DVD_DISC_DECODER_REGION     , 3222081897U) /* 0xc00d1169 */ \
   XXX( HRES_NS_E_DVD_NO_VIDEO_STREAM        , 3222081898U) /* 0xc00d116a */ \
   XXX( HRES_NS_E_DVD_NO_AUDIO_STREAM        , 3222081899U) /* 0xc00d116b */ \
   XXX( HRES_NS_E_DVD_GRAPH_BUILDING        , 3222081900U) /* 0xc00d116c */ \
   XXX( HRES_NS_E_DVD_NO_DECODER        , 3222081901U) /* 0xc00d116d */ \
   XXX( HRES_NS_E_DVD_PARENTAL        , 3222081902U) /* 0xc00d116e */ \
   XXX( HRES_NS_E_DVD_CANNOT_JUMP        , 3222081903U) /* 0xc00d116f */ \
   XXX( HRES_NS_E_DVD_DEVICE_CONTENTION        , 3222081904U) /* 0xc00d1170 */ \
   XXX( HRES_NS_E_DVD_NO_VIDEO_MEMORY        , 3222081905U) /* 0xc00d1171 */ \
   XXX( HRES_NS_E_DVD_CANNOT_COPY_PROTECTED     , 3222081906U) /* 0xc00d1172 */ \
   XXX( HRES_NS_E_DVD_REQUIRED_PROPERTY_NOT_SET     , 3222081907U) /* 0xc00d1173 */ \
   XXX( HRES_NS_E_DVD_INVALID_TITLE_CHAPTER     , 3222081908U) /* 0xc00d1174 */ \
   XXX( HRES_NS_E_NO_CD_BURNER        , 3222081910U) /* 0xc00d1176 */ \
   XXX( HRES_NS_E_DEVICE_IS_NOT_READY        , 3222081911U) /* 0xc00d1177 */ \
   XXX( HRES_NS_E_PDA_UNSUPPORTED_FORMAT     , 3222081912U) /* 0xc00d1178 */ \
   XXX( HRES_NS_E_NO_PDA        , 3222081913U) /* 0xc00d1179 */ \
   XXX( HRES_NS_E_PDA_UNSPECIFIED_ERROR        , 3222081914U) /* 0xc00d117a */ \
   XXX( HRES_NS_E_MEMSTORAGE_BAD_DATA        , 3222081915U) /* 0xc00d117b */ \
   XXX( HRES_NS_E_PDA_FAIL_SELECT_DEVICE     , 3222081916U) /* 0xc00d117c */ \
   XXX( HRES_NS_E_PDA_FAIL_READ_WAVE_FILE     , 3222081917U) /* 0xc00d117d */ \
   XXX( HRES_NS_E_IMAPI_LOSSOFSTREAMING        , 3222081918U) /* 0xc00d117e */ \
   XXX( HRES_NS_E_PDA_DEVICE_FULL        , 3222081919U) /* 0xc00d117f */ \
   XXX( HRES_NS_E_FAIL_LAUNCH_ROXIO_PLUGIN     , 3222081920U) /* 0xc00d1180 */ \
   XXX( HRES_NS_E_PDA_DEVICE_FULL_IN_SESSION     , 3222081921U) /* 0xc00d1181 */ \
   XXX( HRES_NS_E_IMAPI_MEDIUM_INVALIDTYPE     , 3222081922U) /* 0xc00d1182 */ \
   XXX( HRES_NS_E_PDA_MANUALDEVICE        , 3222081923U) /* 0xc00d1183 */ \
   XXX( HRES_NS_E_PDA_PARTNERSHIPNOTEXIST     , 3222081924U) /* 0xc00d1184 */ \
   XXX( HRES_NS_E_PDA_CANNOT_CREATE_ADDITIONAL_SYNC_RELATIONSHIP, 3222081925U) /* 0xc00d1185 */ \
   XXX( HRES_NS_E_PDA_NO_TRANSCODE_OF_DRM     , 3222081926U) /* 0xc00d1186 */ \
   XXX( HRES_NS_E_PDA_TRANSCODECACHEFULL     , 3222081927U) /* 0xc00d1187 */ \
   XXX( HRES_NS_E_PDA_TOO_MANY_FILE_COLLISIONS     , 3222081928U) /* 0xc00d1188 */ \
   XXX( HRES_NS_E_PDA_CANNOT_TRANSCODE        , 3222081929U) /* 0xc00d1189 */ \
   XXX( HRES_NS_E_PDA_TOO_MANY_FILES_IN_DIRECTORY  , 3222081930U) /* 0xc00d118a */ \
   XXX( HRES_NS_E_PROCESSINGSHOWSYNCWIZARD     , 3222081931U) /* 0xc00d118b */ \
   XXX( HRES_NS_E_PDA_TRANSCODE_NOT_PERMITTED     , 3222081932U) /* 0xc00d118c */ \
   XXX( HRES_NS_E_PDA_INITIALIZINGDEVICES     , 3222081933U) /* 0xc00d118d */ \
   XXX( HRES_NS_E_PDA_OBSOLETE_SP        , 3222081934U) /* 0xc00d118e */ \
   XXX( HRES_NS_E_PDA_TITLE_COLLISION        , 3222081935U) /* 0xc00d118f */ \
   XXX( HRES_NS_E_PDA_DEVICESUPPORTDISABLED     , 3222081936U) /* 0xc00d1190 */ \
   XXX( HRES_NS_E_PDA_NO_LONGER_AVAILABLE     , 3222081937U) /* 0xc00d1191 */ \
   XXX( HRES_NS_E_PDA_ENCODER_NOT_RESPONDING     , 3222081938U) /* 0xc00d1192 */ \
   XXX( HRES_NS_E_PDA_CANNOT_SYNC_FROM_LOCATION     , 3222081939U) /* 0xc00d1193 */ \
   XXX( HRES_NS_E_WMP_PROTOCOL_PROBLEM        , 3222081940U) /* 0xc00d1194 */ \
   XXX( HRES_NS_E_WMP_NO_DISK_SPACE        , 3222081941U) /* 0xc00d1195 */ \
   XXX( HRES_NS_E_WMP_LOGON_FAILURE        , 3222081942U) /* 0xc00d1196 */ \
   XXX( HRES_NS_E_WMP_CANNOT_FIND_FILE        , 3222081943U) /* 0xc00d1197 */ \
   XXX( HRES_NS_E_WMP_SERVER_INACCESSIBLE     , 3222081944U) /* 0xc00d1198 */ \
   XXX( HRES_NS_E_WMP_UNSUPPORTED_FORMAT     , 3222081945U) /* 0xc00d1199 */ \
   XXX( HRES_NS_E_WMP_DSHOW_UNSUPPORTED_FORMAT     , 3222081946U) /* 0xc00d119a */ \
   XXX( HRES_NS_E_WMP_PLAYLIST_EXISTS        , 3222081947U) /* 0xc00d119b */ \
   XXX( HRES_NS_E_WMP_NONMEDIA_FILES        , 3222081948U) /* 0xc00d119c */ \
   XXX( HRES_NS_E_WMP_INVALID_ASX        , 3222081949U) /* 0xc00d119d */ \
   XXX( HRES_NS_E_WMP_ALREADY_IN_USE        , 3222081950U) /* 0xc00d119e */ \
   XXX( HRES_NS_E_WMP_IMAPI_FAILURE        , 3222081951U) /* 0xc00d119f */ \
   XXX( HRES_NS_E_WMP_WMDM_FAILURE        , 3222081952U) /* 0xc00d11a0 */ \
   XXX( HRES_NS_E_WMP_CODEC_NEEDED_WITH_4CC     , 3222081953U) /* 0xc00d11a1 */ \
   XXX( HRES_NS_E_WMP_CODEC_NEEDED_WITH_FORMATTAG  , 3222081954U) /* 0xc00d11a2 */ \
   XXX( HRES_NS_E_WMP_MSSAP_NOT_AVAILABLE     , 3222081955U) /* 0xc00d11a3 */ \
   XXX( HRES_NS_E_WMP_WMDM_INTERFACEDEAD     , 3222081956U) /* 0xc00d11a4 */ \
   XXX( HRES_NS_E_WMP_WMDM_NOTCERTIFIED        , 3222081957U) /* 0xc00d11a5 */ \
   XXX( HRES_NS_E_WMP_WMDM_LICENSE_NOTEXIST     , 3222081958U) /* 0xc00d11a6 */ \
   XXX( HRES_NS_E_WMP_WMDM_LICENSE_EXPIRED     , 3222081959U) /* 0xc00d11a7 */ \
   XXX( HRES_NS_E_WMP_WMDM_BUSY        , 3222081960U) /* 0xc00d11a8 */ \
   XXX( HRES_NS_E_WMP_WMDM_NORIGHTS        , 3222081961U) /* 0xc00d11a9 */ \
   XXX( HRES_NS_E_WMP_WMDM_INCORRECT_RIGHTS     , 3222081962U) /* 0xc00d11aa */ \
   XXX( HRES_NS_E_WMP_IMAPI_GENERIC        , 3222081963U) /* 0xc00d11ab */ \
   XXX( HRES_NS_E_WMP_IMAPI_DEVICE_NOTPRESENT     , 3222081965U) /* 0xc00d11ad */ \
   XXX( HRES_NS_E_WMP_IMAPI_DEVICE_BUSY        , 3222081966U) /* 0xc00d11ae */ \
   XXX( HRES_NS_E_WMP_IMAPI_LOSS_OF_STREAMING     , 3222081967U) /* 0xc00d11af */ \
   XXX( HRES_NS_E_WMP_SERVER_UNAVAILABLE     , 3222081968U) /* 0xc00d11b0 */ \
   XXX( HRES_NS_E_WMP_FILE_OPEN_FAILED        , 3222081969U) /* 0xc00d11b1 */ \
   XXX( HRES_NS_E_WMP_VERIFY_ONLINE        , 3222081970U) /* 0xc00d11b2 */ \
   XXX( HRES_NS_E_WMP_SERVER_NOT_RESPONDING     , 3222081971U) /* 0xc00d11b3 */ \
   XXX( HRES_NS_E_WMP_DRM_CORRUPT_BACKUP     , 3222081972U) /* 0xc00d11b4 */ \
   XXX( HRES_NS_E_WMP_DRM_LICENSE_SERVER_UNAVAILABLE  , 3222081973U) /* 0xc00d11b5 */ \
   XXX( HRES_NS_E_WMP_NETWORK_FIREWALL        , 3222081974U) /* 0xc00d11b6 */ \
   XXX( HRES_NS_E_WMP_NO_REMOVABLE_MEDIA     , 3222081975U) /* 0xc00d11b7 */ \
   XXX( HRES_NS_E_WMP_PROXY_CONNECT_TIMEOUT     , 3222081976U) /* 0xc00d11b8 */ \
   XXX( HRES_NS_E_WMP_NEED_UPGRADE        , 3222081977U) /* 0xc00d11b9 */ \
   XXX( HRES_NS_E_WMP_AUDIO_HW_PROBLEM        , 3222081978U) /* 0xc00d11ba */ \
   XXX( HRES_NS_E_WMP_INVALID_PROTOCOL        , 3222081979U) /* 0xc00d11bb */ \
   XXX( HRES_NS_E_WMP_INVALID_LIBRARY_ADD     , 3222081980U) /* 0xc00d11bc */ \
   XXX( HRES_NS_E_WMP_MMS_NOT_SUPPORTED        , 3222081981U) /* 0xc00d11bd */ \
   XXX( HRES_NS_E_WMP_NO_PROTOCOLS_SELECTED     , 3222081982U) /* 0xc00d11be */ \
   XXX( HRES_NS_E_WMP_GOFULLSCREEN_FAILED     , 3222081983U) /* 0xc00d11bf */ \
   XXX( HRES_NS_E_WMP_NETWORK_ERROR        , 3222081984U) /* 0xc00d11c0 */ \
   XXX( HRES_NS_E_WMP_CONNECT_TIMEOUT        , 3222081985U) /* 0xc00d11c1 */ \
   XXX( HRES_NS_E_WMP_MULTICAST_DISABLED     , 3222081986U) /* 0xc00d11c2 */ \
   XXX( HRES_NS_E_WMP_SERVER_DNS_TIMEOUT     , 3222081987U) /* 0xc00d11c3 */ \
   XXX( HRES_NS_E_WMP_PROXY_NOT_FOUND        , 3222081988U) /* 0xc00d11c4 */ \
   XXX( HRES_NS_E_WMP_TAMPERED_CONTENT        , 3222081989U) /* 0xc00d11c5 */ \
   XXX( HRES_NS_E_WMP_OUTOFMEMORY        , 3222081990U) /* 0xc00d11c6 */ \
   XXX( HRES_NS_E_WMP_AUDIO_CODEC_NOT_INSTALLED     , 3222081991U) /* 0xc00d11c7 */ \
   XXX( HRES_NS_E_WMP_VIDEO_CODEC_NOT_INSTALLED     , 3222081992U) /* 0xc00d11c8 */ \
   XXX( HRES_NS_E_WMP_IMAPI_DEVICE_INVALIDTYPE     , 3222081993U) /* 0xc00d11c9 */ \
   XXX( HRES_NS_E_WMP_DRM_DRIVER_AUTH_FAILURE     , 3222081994U) /* 0xc00d11ca */ \
   XXX( HRES_NS_E_WMP_NETWORK_RESOURCE_FAILURE     , 3222081995U) /* 0xc00d11cb */ \
   XXX( HRES_NS_E_WMP_UPGRADE_APPLICATION     , 3222081996U) /* 0xc00d11cc */ \
   XXX( HRES_NS_E_WMP_UNKNOWN_ERROR        , 3222081997U) /* 0xc00d11cd */ \
   XXX( HRES_NS_E_WMP_INVALID_KEY        , 3222081998U) /* 0xc00d11ce */ \
   XXX( HRES_NS_E_WMP_CD_ANOTHER_USER        , 3222081999U) /* 0xc00d11cf */ \
   XXX( HRES_NS_E_WMP_DRM_NEEDS_AUTHORIZATION     , 3222082000U) /* 0xc00d11d0 */ \
   XXX( HRES_NS_E_WMP_BAD_DRIVER        , 3222082001U) /* 0xc00d11d1 */ \
   XXX( HRES_NS_E_WMP_ACCESS_DENIED        , 3222082002U) /* 0xc00d11d2 */ \
   XXX( HRES_NS_E_WMP_LICENSE_RESTRICTS        , 3222082003U) /* 0xc00d11d3 */ \
   XXX( HRES_NS_E_WMP_INVALID_REQUEST        , 3222082004U) /* 0xc00d11d4 */ \
   XXX( HRES_NS_E_WMP_CD_STASH_NO_SPACE        , 3222082005U) /* 0xc00d11d5 */ \
   XXX( HRES_NS_E_WMP_DRM_NEW_HARDWARE        , 3222082006U) /* 0xc00d11d6 */ \
   XXX( HRES_NS_E_WMP_DRM_INVALID_SIG        , 3222082007U) /* 0xc00d11d7 */ \
   XXX( HRES_NS_E_WMP_DRM_CANNOT_RESTORE     , 3222082008U) /* 0xc00d11d8 */ \
   XXX( HRES_NS_E_WMP_BURN_DISC_OVERFLOW     , 3222082009U) /* 0xc00d11d9 */ \
   XXX( HRES_NS_E_WMP_DRM_GENERIC_LICENSE_FAILURE  , 3222082010U) /* 0xc00d11da */ \
   XXX( HRES_NS_E_WMP_DRM_NO_SECURE_CLOCK     , 3222082011U) /* 0xc00d11db */ \
   XXX( HRES_NS_E_WMP_DRM_NO_RIGHTS        , 3222082012U) /* 0xc00d11dc */ \
   XXX( HRES_NS_E_WMP_DRM_INDIV_FAILED        , 3222082013U) /* 0xc00d11dd */ \
   XXX( HRES_NS_E_WMP_SERVER_NONEWCONNECTIONS     , 3222082014U) /* 0xc00d11de */ \
   XXX( HRES_NS_E_WMP_MULTIPLE_ERROR_IN_PLAYLIST  , 3222082015U) /* 0xc00d11df */ \
   XXX( HRES_NS_E_WMP_IMAPI2_ERASE_FAIL        , 3222082016U) /* 0xc00d11e0 */ \
   XXX( HRES_NS_E_WMP_IMAPI2_ERASE_DEVICE_BUSY     , 3222082017U) /* 0xc00d11e1 */ \
   XXX( HRES_NS_E_WMP_DRM_COMPONENT_FAILURE     , 3222082018U) /* 0xc00d11e2 */ \
   XXX( HRES_NS_E_WMP_DRM_NO_DEVICE_CERT     , 3222082019U) /* 0xc00d11e3 */ \
   XXX( HRES_NS_E_WMP_SERVER_SECURITY_ERROR     , 3222082020U) /* 0xc00d11e4 */ \
   XXX( HRES_NS_E_WMP_AUDIO_DEVICE_LOST        , 3222082021U) /* 0xc00d11e5 */ \
   XXX( HRES_NS_E_WMP_IMAPI_MEDIA_INCOMPATIBLE     , 3222082022U) /* 0xc00d11e6 */ \
   XXX( HRES_NS_E_SYNCWIZ_DEVICE_FULL        , 3222082030U) /* 0xc00d11ee */ \
   XXX( HRES_NS_E_SYNCWIZ_CANNOT_CHANGE_SETTINGS  , 3222082031U) /* 0xc00d11ef */ \
   XXX( HRES_NS_E_TRANSCODE_DELETECACHEERROR     , 3222082032U) /* 0xc00d11f0 */ \
   XXX( HRES_NS_E_CD_NO_BUFFERS_READ        , 3222082040U) /* 0xc00d11f8 */ \
   XXX( HRES_NS_E_CD_EMPTY_TRACK_QUEUE        , 3222082041U) /* 0xc00d11f9 */ \
   XXX( HRES_NS_E_CD_NO_READER        , 3222082042U) /* 0xc00d11fa */ \
   XXX( HRES_NS_E_CD_ISRC_INVALID        , 3222082043U) /* 0xc00d11fb */ \
   XXX( HRES_NS_E_CD_MEDIA_CATALOG_NUMBER_INVALID  , 3222082044U) /* 0xc00d11fc */ \
   XXX( HRES_NS_E_SLOW_READ_DIGITAL_WITH_ERRORCORRECTION, 3222082045U) /* 0xc00d11fd */ \
   XXX( HRES_NS_E_CD_SPEEDDETECT_NOT_ENOUGH_READS  , 3222082046U) /* 0xc00d11fe */ \
   XXX( HRES_NS_E_CD_QUEUEING_DISABLED        , 3222082047U) /* 0xc00d11ff */ \
   XXX( HRES_NS_E_WMP_DRM_ACQUIRING_LICENSE     , 3222082050U) /* 0xc00d1202 */ \
   XXX( HRES_NS_E_WMP_DRM_LICENSE_EXPIRED     , 3222082051U) /* 0xc00d1203 */ \
   XXX( HRES_NS_E_WMP_DRM_LICENSE_NOTACQUIRED     , 3222082052U) /* 0xc00d1204 */ \
   XXX( HRES_NS_E_WMP_DRM_LICENSE_NOTENABLED     , 3222082053U) /* 0xc00d1205 */ \
   XXX( HRES_NS_E_WMP_DRM_LICENSE_UNUSABLE     , 3222082054U) /* 0xc00d1206 */ \
   XXX( HRES_NS_E_WMP_DRM_LICENSE_CONTENT_REVOKED  , 3222082055U) /* 0xc00d1207 */ \
   XXX( HRES_NS_E_WMP_DRM_LICENSE_NOSAP        , 3222082056U) /* 0xc00d1208 */ \
   XXX( HRES_NS_E_WMP_DRM_UNABLE_TO_ACQUIRE_LICENSE  , 3222082057U) /* 0xc00d1209 */ \
   XXX( HRES_NS_E_WMP_LICENSE_REQUIRED        , 3222082058U) /* 0xc00d120a */ \
   XXX( HRES_NS_E_WMP_PROTECTED_CONTENT        , 3222082059U) /* 0xc00d120b */ \
   XXX( HRES_NS_E_WMP_POLICY_VALUE_NOT_CONFIGURED  , 3222082090U) /* 0xc00d122a */ \
   XXX( HRES_NS_E_PDA_CANNOT_SYNC_FROM_INTERNET     , 3222082100U) /* 0xc00d1234 */ \
   XXX( HRES_NS_E_PDA_CANNOT_SYNC_INVALID_PLAYLIST  , 3222082101U) /* 0xc00d1235 */ \
   XXX( HRES_NS_E_PDA_FAILED_TO_SYNCHRONIZE_FILE  , 3222082102U) /* 0xc00d1236 */ \
   XXX( HRES_NS_E_PDA_SYNC_FAILED        , 3222082103U) /* 0xc00d1237 */ \
   XXX( HRES_NS_E_PDA_DELETE_FAILED        , 3222082104U) /* 0xc00d1238 */ \
   XXX( HRES_NS_E_PDA_FAILED_TO_RETRIEVE_FILE     , 3222082105U) /* 0xc00d1239 */ \
   XXX( HRES_NS_E_PDA_DEVICE_NOT_RESPONDING     , 3222082106U) /* 0xc00d123a */ \
   XXX( HRES_NS_E_PDA_FAILED_TO_TRANSCODE_PHOTO     , 3222082107U) /* 0xc00d123b */ \
   XXX( HRES_NS_E_PDA_FAILED_TO_ENCRYPT_TRANSCODED_FILE, 3222082108U) /* 0xc00d123c */ \
   XXX( HRES_NS_E_PDA_CANNOT_TRANSCODE_TO_AUDIO     , 3222082109U) /* 0xc00d123d */ \
   XXX( HRES_NS_E_PDA_CANNOT_TRANSCODE_TO_VIDEO     , 3222082110U) /* 0xc00d123e */ \
   XXX( HRES_NS_E_PDA_CANNOT_TRANSCODE_TO_IMAGE     , 3222082111U) /* 0xc00d123f */ \
   XXX( HRES_NS_E_PDA_RETRIEVED_FILE_FILENAME_TOO_LONG  , 3222082112U) /* 0xc00d1240 */ \
   XXX( HRES_NS_E_PDA_CEWMDM_DRM_ERROR        , 3222082113U) /* 0xc00d1241 */ \
   XXX( HRES_NS_E_INCOMPLETE_PLAYLIST        , 3222082114U) /* 0xc00d1242 */ \
   XXX( HRES_NS_E_PDA_SYNC_RUNNING        , 3222082115U) /* 0xc00d1243 */ \
   XXX( HRES_NS_E_PDA_SYNC_LOGIN_ERROR        , 3222082116U) /* 0xc00d1244 */ \
   XXX( HRES_NS_E_PDA_TRANSCODE_CODEC_NOT_FOUND     , 3222082117U) /* 0xc00d1245 */ \
   XXX( HRES_NS_E_CANNOT_SYNC_DRM_TO_NON_JANUS_DEVICE  , 3222082118U) /* 0xc00d1246 */ \
   XXX( HRES_NS_E_CANNOT_SYNC_PREVIOUS_SYNC_RUNNING  , 3222082119U) /* 0xc00d1247 */ \
   XXX( HRES_NS_E_WMP_HWND_NOTFOUND        , 3222082140U) /* 0xc00d125c */ \
   XXX( HRES_NS_E_BKGDOWNLOAD_WRONG_NO_FILES     , 3222082141U) /* 0xc00d125d */ \
   XXX( HRES_NS_E_BKGDOWNLOAD_COMPLETECANCELLEDJOB  , 3222082142U) /* 0xc00d125e */ \
   XXX( HRES_NS_E_BKGDOWNLOAD_CANCELCOMPLETEDJOB  , 3222082143U) /* 0xc00d125f */ \
   XXX( HRES_NS_E_BKGDOWNLOAD_NOJOBPOINTER     , 3222082144U) /* 0xc00d1260 */ \
   XXX( HRES_NS_E_BKGDOWNLOAD_INVALIDJOBSIGNATURE  , 3222082145U) /* 0xc00d1261 */ \
   XXX( HRES_NS_E_BKGDOWNLOAD_FAILED_TO_CREATE_TEMPFILE, 3222082146U) /* 0xc00d1262 */ \
   XXX( HRES_NS_E_BKGDOWNLOAD_PLUGIN_FAILEDINITIALIZE  , 3222082147U) /* 0xc00d1263 */ \
   XXX( HRES_NS_E_BKGDOWNLOAD_PLUGIN_FAILEDTOMOVEFILE  , 3222082148U) /* 0xc00d1264 */ \
   XXX( HRES_NS_E_BKGDOWNLOAD_CALLFUNCFAILED     , 3222082149U) /* 0xc00d1265 */ \
   XXX( HRES_NS_E_BKGDOWNLOAD_CALLFUNCTIMEOUT     , 3222082150U) /* 0xc00d1266 */ \
   XXX( HRES_NS_E_BKGDOWNLOAD_CALLFUNCENDED     , 3222082151U) /* 0xc00d1267 */ \
   XXX( HRES_NS_E_BKGDOWNLOAD_WMDUNPACKFAILED     , 3222082152U) /* 0xc00d1268 */ \
   XXX( HRES_NS_E_BKGDOWNLOAD_FAILEDINITIALIZE     , 3222082153U) /* 0xc00d1269 */ \
   XXX( HRES_NS_E_INTERFACE_NOT_REGISTERED_IN_GIT  , 3222082154U) /* 0xc00d126a */ \
   XXX( HRES_NS_E_BKGDOWNLOAD_INVALID_FILE_NAME     , 3222082155U) /* 0xc00d126b */ \
   XXX( HRES_NS_E_IMAGE_DOWNLOAD_FAILED        , 3222082190U) /* 0xc00d128e */ \
   XXX( HRES_NS_E_WMP_UDRM_NOUSERLIST        , 3222082240U) /* 0xc00d12c0 */ \
   XXX( HRES_NS_E_WMP_DRM_NOT_ACQUIRING        , 3222082241U) /* 0xc00d12c1 */ \
   XXX( HRES_NS_E_WMP_BSTR_TOO_LONG        , 3222082290U) /* 0xc00d12f2 */ \
   XXX( HRES_NS_E_WMP_AUTOPLAY_INVALID_STATE     , 3222082300U) /* 0xc00d12fc */ \
   XXX( HRES_NS_E_WMP_COMPONENT_REVOKED        , 3222082310U) /* 0xc00d1306 */ \
   XXX( HRES_NS_E_CURL_NOTSAFE        , 3222082340U) /* 0xc00d1324 */ \
   XXX( HRES_NS_E_CURL_INVALIDCHAR        , 3222082341U) /* 0xc00d1325 */ \
   XXX( HRES_NS_E_CURL_INVALIDHOSTNAME        , 3222082342U) /* 0xc00d1326 */ \
   XXX( HRES_NS_E_CURL_INVALIDPATH        , 3222082343U) /* 0xc00d1327 */ \
   XXX( HRES_NS_E_CURL_INVALIDSCHEME        , 3222082344U) /* 0xc00d1328 */ \
   XXX( HRES_NS_E_CURL_INVALIDURL        , 3222082345U) /* 0xc00d1329 */ \
   XXX( HRES_NS_E_CURL_CANTWALK        , 3222082347U) /* 0xc00d132b */ \
   XXX( HRES_NS_E_CURL_INVALIDPORT        , 3222082348U) /* 0xc00d132c */ \
   XXX( HRES_NS_E_CURLHELPER_NOTADIRECTORY     , 3222082349U) /* 0xc00d132d */ \
   XXX( HRES_NS_E_CURLHELPER_NOTAFILE        , 3222082350U) /* 0xc00d132e */ \
   XXX( HRES_NS_E_CURL_CANTDECODE        , 3222082351U) /* 0xc00d132f */ \
   XXX( HRES_NS_E_CURLHELPER_NOTRELATIVE     , 3222082352U) /* 0xc00d1330 */ \
   XXX( HRES_NS_E_CURL_INVALIDBUFFERSIZE     , 3222082353U) /* 0xc00d1331 */ \
   XXX( HRES_NS_E_SUBSCRIPTIONSERVICE_PLAYBACK_DISALLOWED, 3222082390U) /* 0xc00d1356 */ \
   XXX( HRES_NS_E_CANNOT_BUY_OR_DOWNLOAD_FROM_MULTIPLE_SERVICES, 3222082391U) /* 0xc00d1357 */ \
   XXX( HRES_NS_E_CANNOT_BUY_OR_DOWNLOAD_CONTENT  , 3222082392U) /* 0xc00d1358 */ \
   XXX( HRES_NS_E_NOT_CONTENT_PARTNER_TRACK     , 3222082394U) /* 0xc00d135a */ \
   XXX( HRES_NS_E_TRACK_DOWNLOAD_REQUIRES_ALBUM_PURCHASE, 3222082395U) /* 0xc00d135b */ \
   XXX( HRES_NS_E_TRACK_DOWNLOAD_REQUIRES_PURCHASE  , 3222082396U) /* 0xc00d135c */ \
   XXX( HRES_NS_E_TRACK_PURCHASE_MAXIMUM_EXCEEDED  , 3222082397U) /* 0xc00d135d */ \
   XXX( HRES_NS_E_SUBSCRIPTIONSERVICE_LOGIN_FAILED  , 3222082399U) /* 0xc00d135f */ \
   XXX( HRES_NS_E_SUBSCRIPTIONSERVICE_DOWNLOAD_TIMEOUT  , 3222082400U) /* 0xc00d1360 */ \
   XXX( HRES_NS_E_CONTENT_PARTNER_STILL_INITIALIZING  , 3222082402U) /* 0xc00d1362 */ \
   XXX( HRES_NS_E_OPEN_CONTAINING_FOLDER_FAILED     , 3222082403U) /* 0xc00d1363 */ \
   XXX( HRES_NS_E_ADVANCEDEDIT_TOO_MANY_PICTURES  , 3222082410U) /* 0xc00d136a */ \
   XXX( HRES_NS_E_REDIRECT        , 3222082440U) /* 0xc00d1388 */ \
   XXX( HRES_NS_E_STALE_PRESENTATION        , 3222082441U) /* 0xc00d1389 */ \
   XXX( HRES_NS_E_NAMESPACE_WRONG_PERSIST     , 3222082442U) /* 0xc00d138a */ \
   XXX( HRES_NS_E_NAMESPACE_WRONG_TYPE        , 3222082443U) /* 0xc00d138b */ \
   XXX( HRES_NS_E_NAMESPACE_NODE_CONFLICT     , 3222082444U) /* 0xc00d138c */ \
   XXX( HRES_NS_E_NAMESPACE_NODE_NOT_FOUND     , 3222082445U) /* 0xc00d138d */ \
   XXX( HRES_NS_E_NAMESPACE_BUFFER_TOO_SMALL     , 3222082446U) /* 0xc00d138e */ \
   XXX( HRES_NS_E_NAMESPACE_TOO_MANY_CALLBACKS     , 3222082447U) /* 0xc00d138f */ \
   XXX( HRES_NS_E_NAMESPACE_DUPLICATE_CALLBACK     , 3222082448U) /* 0xc00d1390 */ \
   XXX( HRES_NS_E_NAMESPACE_CALLBACK_NOT_FOUND     , 3222082449U) /* 0xc00d1391 */ \
   XXX( HRES_NS_E_NAMESPACE_NAME_TOO_LONG     , 3222082450U) /* 0xc00d1392 */ \
   XXX( HRES_NS_E_NAMESPACE_DUPLICATE_NAME     , 3222082451U) /* 0xc00d1393 */ \
   XXX( HRES_NS_E_NAMESPACE_EMPTY_NAME        , 3222082452U) /* 0xc00d1394 */ \
   XXX( HRES_NS_E_NAMESPACE_INDEX_TOO_LARGE     , 3222082453U) /* 0xc00d1395 */ \
   XXX( HRES_NS_E_NAMESPACE_BAD_NAME        , 3222082454U) /* 0xc00d1396 */ \
   XXX( HRES_NS_E_NAMESPACE_WRONG_SECURITY     , 3222082455U) /* 0xc00d1397 */ \
   XXX( HRES_NS_E_CACHE_ARCHIVE_CONFLICT     , 3222082540U) /* 0xc00d13ec */ \
   XXX( HRES_NS_E_CACHE_ORIGIN_SERVER_NOT_FOUND     , 3222082541U) /* 0xc00d13ed */ \
   XXX( HRES_NS_E_CACHE_ORIGIN_SERVER_TIMEOUT     , 3222082542U) /* 0xc00d13ee */ \
   XXX( HRES_NS_E_CACHE_NOT_BROADCAST        , 3222082543U) /* 0xc00d13ef */ \
   XXX( HRES_NS_E_CACHE_CANNOT_BE_CACHED     , 3222082544U) /* 0xc00d13f0 */ \
   XXX( HRES_NS_E_CACHE_NOT_MODIFIED        , 3222082545U) /* 0xc00d13f1 */ \
   XXX( HRES_NS_E_CANNOT_REMOVE_PUBLISHING_POINT  , 3222082640U) /* 0xc00d1450 */ \
   XXX( HRES_NS_E_CANNOT_REMOVE_PLUGIN        , 3222082641U) /* 0xc00d1451 */ \
   XXX( HRES_NS_E_WRONG_PUBLISHING_POINT_TYPE     , 3222082642U) /* 0xc00d1452 */ \
   XXX( HRES_NS_E_UNSUPPORTED_LOAD_TYPE        , 3222082643U) /* 0xc00d1453 */ \
   XXX( HRES_NS_E_INVALID_PLUGIN_LOAD_TYPE_CONFIGURATION, 3222082644U) /* 0xc00d1454 */ \
   XXX( HRES_NS_E_INVALID_PUBLISHING_POINT_NAME     , 3222082645U) /* 0xc00d1455 */ \
   XXX( HRES_NS_E_TOO_MANY_MULTICAST_SINKS     , 3222082646U) /* 0xc00d1456 */ \
   XXX( HRES_NS_E_PUBLISHING_POINT_INVALID_REQUEST_WHILE_STARTED, 3222082647U) /* 0xc00d1457 */ \
   XXX( HRES_NS_E_MULTICAST_PLUGIN_NOT_ENABLED     , 3222082648U) /* 0xc00d1458 */ \
   XXX( HRES_NS_E_INVALID_OPERATING_SYSTEM_VERSION  , 3222082649U) /* 0xc00d1459 */ \
   XXX( HRES_NS_E_PUBLISHING_POINT_REMOVED     , 3222082650U) /* 0xc00d145a */ \
   XXX( HRES_NS_E_INVALID_PUSH_PUBLISHING_POINT_START_REQUEST, 3222082651U) /* 0xc00d145b */ \
   XXX( HRES_NS_E_UNSUPPORTED_LANGUAGE        , 3222082652U) /* 0xc00d145c */ \
   XXX( HRES_NS_E_WRONG_OS_VERSION        , 3222082653U) /* 0xc00d145d */ \
   XXX( HRES_NS_E_PUBLISHING_POINT_STOPPED     , 3222082654U) /* 0xc00d145e */ \
   XXX( HRES_NS_E_PLAYLIST_ENTRY_ALREADY_PLAYING  , 3222082740U) /* 0xc00d14b4 */ \
   XXX( HRES_NS_E_EMPTY_PLAYLIST        , 3222082741U) /* 0xc00d14b5 */ \
   XXX( HRES_NS_E_PLAYLIST_PARSE_FAILURE     , 3222082742U) /* 0xc00d14b6 */ \
   XXX( HRES_NS_E_PLAYLIST_UNSUPPORTED_ENTRY     , 3222082743U) /* 0xc00d14b7 */ \
   XXX( HRES_NS_E_PLAYLIST_ENTRY_NOT_IN_PLAYLIST  , 3222082744U) /* 0xc00d14b8 */ \
   XXX( HRES_NS_E_PLAYLIST_ENTRY_SEEK        , 3222082745U) /* 0xc00d14b9 */ \
   XXX( HRES_NS_E_PLAYLIST_RECURSIVE_PLAYLISTS     , 3222082746U) /* 0xc00d14ba */ \
   XXX( HRES_NS_E_PLAYLIST_TOO_MANY_NESTED_PLAYLISTS  , 3222082747U) /* 0xc00d14bb */ \
   XXX( HRES_NS_E_PLAYLIST_SHUTDOWN        , 3222082748U) /* 0xc00d14bc */ \
   XXX( HRES_NS_E_PLAYLIST_END_RECEDING        , 3222082749U) /* 0xc00d14bd */ \
   XXX( HRES_NS_E_DATAPATH_NO_SINK        , 3222082840U) /* 0xc00d1518 */ \
   XXX( HRES_NS_E_INVALID_PUSH_TEMPLATE        , 3222082842U) /* 0xc00d151a */ \
   XXX( HRES_NS_E_INVALID_PUSH_PUBLISHING_POINT     , 3222082843U) /* 0xc00d151b */ \
   XXX( HRES_NS_E_CRITICAL_ERROR        , 3222082844U) /* 0xc00d151c */ \
   XXX( HRES_NS_E_NO_NEW_CONNECTIONS        , 3222082845U) /* 0xc00d151d */ \
   XXX( HRES_NS_E_WSX_INVALID_VERSION        , 3222082846U) /* 0xc00d151e */ \
   XXX( HRES_NS_E_HEADER_MISMATCH        , 3222082847U) /* 0xc00d151f */ \
   XXX( HRES_NS_E_PUSH_DUPLICATE_PUBLISHING_POINT_NAME  , 3222082848U) /* 0xc00d1520 */ \
   XXX( HRES_NS_E_NO_SCRIPT_ENGINE        , 3222082940U) /* 0xc00d157c */ \
   XXX( HRES_NS_E_PLUGIN_ERROR_REPORTED        , 3222082941U) /* 0xc00d157d */ \
   XXX( HRES_NS_E_SOURCE_PLUGIN_NOT_FOUND     , 3222082942U) /* 0xc00d157e */ \
   XXX( HRES_NS_E_PLAYLIST_PLUGIN_NOT_FOUND     , 3222082943U) /* 0xc00d157f */ \
   XXX( HRES_NS_E_DATA_SOURCE_ENUMERATION_NOT_SUPPORTED, 3222082944U) /* 0xc00d1580 */ \
   XXX( HRES_NS_E_MEDIA_PARSER_INVALID_FORMAT     , 3222082945U) /* 0xc00d1581 */ \
   XXX( HRES_NS_E_SCRIPT_DEBUGGER_NOT_INSTALLED     , 3222082946U) /* 0xc00d1582 */ \
   XXX( HRES_NS_E_FEATURE_REQUIRES_ENTERPRISE_SERVER  , 3222082947U) /* 0xc00d1583 */ \
   XXX( HRES_NS_E_WIZARD_RUNNING        , 3222082948U) /* 0xc00d1584 */ \
   XXX( HRES_NS_E_INVALID_LOG_URL        , 3222082949U) /* 0xc00d1585 */ \
   XXX( HRES_NS_E_INVALID_MTU_RANGE        , 3222082950U) /* 0xc00d1586 */ \
   XXX( HRES_NS_E_INVALID_PLAY_STATISTICS     , 3222082951U) /* 0xc00d1587 */ \
   XXX( HRES_NS_E_LOG_NEED_TO_BE_SKIPPED     , 3222082952U) /* 0xc00d1588 */ \
   XXX( HRES_NS_E_HTTP_TEXT_DATACONTAINER_SIZE_LIMIT_EXCEEDED, 3222082953U) /* 0xc00d1589 */ \
   XXX( HRES_NS_E_PORT_IN_USE        , 3222082954U) /* 0xc00d158a */ \
   XXX( HRES_NS_E_PORT_IN_USE_HTTP        , 3222082955U) /* 0xc00d158b */ \
   XXX( HRES_NS_E_HTTP_TEXT_DATACONTAINER_INVALID_SERVER_RESPONSE, 3222082956U) /* 0xc00d158c */ \
   XXX( HRES_NS_E_ARCHIVE_REACH_QUOTA        , 3222082957U) /* 0xc00d158d */ \
   XXX( HRES_NS_E_ARCHIVE_ABORT_DUE_TO_BCAST     , 3222082958U) /* 0xc00d158e */ \
   XXX( HRES_NS_E_ARCHIVE_GAP_DETECTED        , 3222082959U) /* 0xc00d158f */ \
   XXX( HRES_NS_E_AUTHORIZATION_FILE_NOT_FOUND     , 3222082960U) /* 0xc00d1590 */ \
   XXX( HRES_NS_E_BAD_MARKIN        , 3222084440U) /* 0xc00d1b58 */ \
   XXX( HRES_NS_E_BAD_MARKOUT        , 3222084441U) /* 0xc00d1b59 */ \
   XXX( HRES_NS_E_NOMATCHING_MEDIASOURCE     , 3222084442U) /* 0xc00d1b5a */ \
   XXX( HRES_NS_E_UNSUPPORTED_SOURCETYPE     , 3222084443U) /* 0xc00d1b5b */ \
   XXX( HRES_NS_E_TOO_MANY_AUDIO        , 3222084444U) /* 0xc00d1b5c */ \
   XXX( HRES_NS_E_TOO_MANY_VIDEO        , 3222084445U) /* 0xc00d1b5d */ \
   XXX( HRES_NS_E_NOMATCHING_ELEMENT        , 3222084446U) /* 0xc00d1b5e */ \
   XXX( HRES_NS_E_MISMATCHED_MEDIACONTENT     , 3222084447U) /* 0xc00d1b5f */ \
   XXX( HRES_NS_E_CANNOT_DELETE_ACTIVE_SOURCEGROUP  , 3222084448U) /* 0xc00d1b60 */ \
   XXX( HRES_NS_E_AUDIODEVICE_BUSY        , 3222084449U) /* 0xc00d1b61 */ \
   XXX( HRES_NS_E_AUDIODEVICE_UNEXPECTED     , 3222084450U) /* 0xc00d1b62 */ \
   XXX( HRES_NS_E_AUDIODEVICE_BADFORMAT        , 3222084451U) /* 0xc00d1b63 */ \
   XXX( HRES_NS_E_VIDEODEVICE_BUSY        , 3222084452U) /* 0xc00d1b64 */ \
   XXX( HRES_NS_E_VIDEODEVICE_UNEXPECTED     , 3222084453U) /* 0xc00d1b65 */ \
   XXX( HRES_NS_E_INVALIDCALL_WHILE_ENCODER_RUNNING  , 3222084454U) /* 0xc00d1b66 */ \
   XXX( HRES_NS_E_NO_PROFILE_IN_SOURCEGROUP     , 3222084455U) /* 0xc00d1b67 */ \
   XXX( HRES_NS_E_VIDEODRIVER_UNSTABLE        , 3222084456U) /* 0xc00d1b68 */ \
   XXX( HRES_NS_E_VIDCAPSTARTFAILED        , 3222084457U) /* 0xc00d1b69 */ \
   XXX( HRES_NS_E_VIDSOURCECOMPRESSION        , 3222084458U) /* 0xc00d1b6a */ \
   XXX( HRES_NS_E_VIDSOURCESIZE        , 3222084459U) /* 0xc00d1b6b */ \
   XXX( HRES_NS_E_ICMQUERYFORMAT        , 3222084460U) /* 0xc00d1b6c */ \
   XXX( HRES_NS_E_VIDCAPCREATEWINDOW        , 3222084461U) /* 0xc00d1b6d */ \
   XXX( HRES_NS_E_VIDCAPDRVINUSE        , 3222084462U) /* 0xc00d1b6e */ \
   XXX( HRES_NS_E_NO_MEDIAFORMAT_IN_SOURCE     , 3222084463U) /* 0xc00d1b6f */ \
   XXX( HRES_NS_E_NO_VALID_OUTPUT_STREAM     , 3222084464U) /* 0xc00d1b70 */ \
   XXX( HRES_NS_E_NO_VALID_SOURCE_PLUGIN     , 3222084465U) /* 0xc00d1b71 */ \
   XXX( HRES_NS_E_NO_ACTIVE_SOURCEGROUP        , 3222084466U) /* 0xc00d1b72 */ \
   XXX( HRES_NS_E_NO_SCRIPT_STREAM        , 3222084467U) /* 0xc00d1b73 */ \
   XXX( HRES_NS_E_INVALIDCALL_WHILE_ARCHIVAL_RUNNING  , 3222084468U) /* 0xc00d1b74 */ \
   XXX( HRES_NS_E_INVALIDPACKETSIZE        , 3222084469U) /* 0xc00d1b75 */ \
   XXX( HRES_NS_E_PLUGIN_CLSID_INVALID        , 3222084470U) /* 0xc00d1b76 */ \
   XXX( HRES_NS_E_UNSUPPORTED_ARCHIVETYPE     , 3222084471U) /* 0xc00d1b77 */ \
   XXX( HRES_NS_E_UNSUPPORTED_ARCHIVEOPERATION     , 3222084472U) /* 0xc00d1b78 */ \
   XXX( HRES_NS_E_ARCHIVE_FILENAME_NOTSET     , 3222084473U) /* 0xc00d1b79 */ \
   XXX( HRES_NS_E_SOURCEGROUP_NOTPREPARED     , 3222084474U) /* 0xc00d1b7a */ \
   XXX( HRES_NS_E_PROFILE_MISMATCH        , 3222084475U) /* 0xc00d1b7b */ \
   XXX( HRES_NS_E_INCORRECTCLIPSETTINGS        , 3222084476U) /* 0xc00d1b7c */ \
   XXX( HRES_NS_E_NOSTATSAVAILABLE        , 3222084477U) /* 0xc00d1b7d */ \
   XXX( HRES_NS_E_NOTARCHIVING        , 3222084478U) /* 0xc00d1b7e */ \
   XXX( HRES_NS_E_INVALIDCALL_WHILE_ENCODER_STOPPED  , 3222084479U) /* 0xc00d1b7f */ \
   XXX( HRES_NS_E_NOSOURCEGROUPS        , 3222084480U) /* 0xc00d1b80 */ \
   XXX( HRES_NS_E_INVALIDINPUTFPS        , 3222084481U) /* 0xc00d1b81 */ \
   XXX( HRES_NS_E_NO_DATAVIEW_SUPPORT        , 3222084482U) /* 0xc00d1b82 */ \
   XXX( HRES_NS_E_CODEC_UNAVAILABLE        , 3222084483U) /* 0xc00d1b83 */ \
   XXX( HRES_NS_E_ARCHIVE_SAME_AS_INPUT        , 3222084484U) /* 0xc00d1b84 */ \
   XXX( HRES_NS_E_SOURCE_NOTSPECIFIED        , 3222084485U) /* 0xc00d1b85 */ \
   XXX( HRES_NS_E_NO_REALTIME_TIMECOMPRESSION     , 3222084486U) /* 0xc00d1b86 */ \
   XXX( HRES_NS_E_UNSUPPORTED_ENCODER_DEVICE     , 3222084487U) /* 0xc00d1b87 */ \
   XXX( HRES_NS_E_UNEXPECTED_DISPLAY_SETTINGS     , 3222084488U) /* 0xc00d1b88 */ \
   XXX( HRES_NS_E_NO_AUDIODATA        , 3222084489U) /* 0xc00d1b89 */ \
   XXX( HRES_NS_E_INPUTSOURCE_PROBLEM        , 3222084490U) /* 0xc00d1b8a */ \
   XXX( HRES_NS_E_WME_VERSION_MISMATCH        , 3222084491U) /* 0xc00d1b8b */ \
   XXX( HRES_NS_E_NO_REALTIME_PREPROCESS     , 3222084492U) /* 0xc00d1b8c */ \
   XXX( HRES_NS_E_NO_REPEAT_PREPROCESS        , 3222084493U) /* 0xc00d1b8d */ \
   XXX( HRES_NS_E_CANNOT_PAUSE_LIVEBROADCAST     , 3222084494U) /* 0xc00d1b8e */ \
   XXX( HRES_NS_E_DRM_PROFILE_NOT_SET        , 3222084495U) /* 0xc00d1b8f */ \
   XXX( HRES_NS_E_DUPLICATE_DRMPROFILE        , 3222084496U) /* 0xc00d1b90 */ \
   XXX( HRES_NS_E_INVALID_DEVICE        , 3222084497U) /* 0xc00d1b91 */ \
   XXX( HRES_NS_E_SPEECHEDL_ON_NON_MIXEDMODE     , 3222084498U) /* 0xc00d1b92 */ \
   XXX( HRES_NS_E_DRM_PASSWORD_TOO_LONG        , 3222084499U) /* 0xc00d1b93 */ \
   XXX( HRES_NS_E_DEVCONTROL_FAILED_SEEK     , 3222084500U) /* 0xc00d1b94 */ \
   XXX( HRES_NS_E_INTERLACE_REQUIRE_SAMESIZE     , 3222084501U) /* 0xc00d1b95 */ \
   XXX( HRES_NS_E_TOO_MANY_DEVICECONTROL     , 3222084502U) /* 0xc00d1b96 */ \
   XXX( HRES_NS_E_NO_MULTIPASS_FOR_LIVEDEVICE     , 3222084503U) /* 0xc00d1b97 */ \
   XXX( HRES_NS_E_MISSING_AUDIENCE        , 3222084504U) /* 0xc00d1b98 */ \
   XXX( HRES_NS_E_AUDIENCE_CONTENTTYPE_MISMATCH     , 3222084505U) /* 0xc00d1b99 */ \
   XXX( HRES_NS_E_MISSING_SOURCE_INDEX        , 3222084506U) /* 0xc00d1b9a */ \
   XXX( HRES_NS_E_NUM_LANGUAGE_MISMATCH        , 3222084507U) /* 0xc00d1b9b */ \
   XXX( HRES_NS_E_LANGUAGE_MISMATCH        , 3222084508U) /* 0xc00d1b9c */ \
   XXX( HRES_NS_E_VBRMODE_MISMATCH        , 3222084509U) /* 0xc00d1b9d */ \
   XXX( HRES_NS_E_INVALID_INPUT_AUDIENCE_INDEX     , 3222084510U) /* 0xc00d1b9e */ \
   XXX( HRES_NS_E_INVALID_INPUT_LANGUAGE     , 3222084511U) /* 0xc00d1b9f */ \
   XXX( HRES_NS_E_INVALID_INPUT_STREAM        , 3222084512U) /* 0xc00d1ba0 */ \
   XXX( HRES_NS_E_EXPECT_MONO_WAV_INPUT        , 3222084513U) /* 0xc00d1ba1 */ \
   XXX( HRES_NS_E_INPUT_WAVFORMAT_MISMATCH     , 3222084514U) /* 0xc00d1ba2 */ \
   XXX( HRES_NS_E_RECORDQ_DISK_FULL        , 3222084515U) /* 0xc00d1ba3 */ \
   XXX( HRES_NS_E_NO_PAL_INVERSE_TELECINE     , 3222084516U) /* 0xc00d1ba4 */ \
   XXX( HRES_NS_E_ACTIVE_SG_DEVICE_DISCONNECTED     , 3222084517U) /* 0xc00d1ba5 */ \
   XXX( HRES_NS_E_ACTIVE_SG_DEVICE_CONTROL_DISCONNECTED, 3222084518U) /* 0xc00d1ba6 */ \
   XXX( HRES_NS_E_NO_FRAMES_SUBMITTED_TO_ANALYZER  , 3222084519U) /* 0xc00d1ba7 */ \
   XXX( HRES_NS_E_INPUT_DOESNOT_SUPPORT_SMPTE     , 3222084520U) /* 0xc00d1ba8 */ \
   XXX( HRES_NS_E_NO_SMPTE_WITH_MULTIPLE_SOURCEGROUPS  , 3222084521U) /* 0xc00d1ba9 */ \
   XXX( HRES_NS_E_BAD_CONTENTEDL        , 3222084522U) /* 0xc00d1baa */ \
   XXX( HRES_NS_E_INTERLACEMODE_MISMATCH     , 3222084523U) /* 0xc00d1bab */ \
   XXX( HRES_NS_E_NONSQUAREPIXELMODE_MISMATCH     , 3222084524U) /* 0xc00d1bac */ \
   XXX( HRES_NS_E_SMPTEMODE_MISMATCH        , 3222084525U) /* 0xc00d1bad */ \
   XXX( HRES_NS_E_END_OF_TAPE        , 3222084526U) /* 0xc00d1bae */ \
   XXX( HRES_NS_E_NO_MEDIA_IN_AUDIENCE        , 3222084527U) /* 0xc00d1baf */ \
   XXX( HRES_NS_E_NO_AUDIENCES        , 3222084528U) /* 0xc00d1bb0 */ \
   XXX( HRES_NS_E_NO_AUDIO_COMPAT        , 3222084529U) /* 0xc00d1bb1 */ \
   XXX( HRES_NS_E_INVALID_VBR_COMPAT        , 3222084530U) /* 0xc00d1bb2 */ \
   XXX( HRES_NS_E_NO_PROFILE_NAME        , 3222084531U) /* 0xc00d1bb3 */ \
   XXX( HRES_NS_E_INVALID_VBR_WITH_UNCOMP     , 3222084532U) /* 0xc00d1bb4 */ \
   XXX( HRES_NS_E_MULTIPLE_VBR_AUDIENCES     , 3222084533U) /* 0xc00d1bb5 */ \
   XXX( HRES_NS_E_UNCOMP_COMP_COMBINATION     , 3222084534U) /* 0xc00d1bb6 */ \
   XXX( HRES_NS_E_MULTIPLE_AUDIO_CODECS        , 3222084535U) /* 0xc00d1bb7 */ \
   XXX( HRES_NS_E_MULTIPLE_AUDIO_FORMATS     , 3222084536U) /* 0xc00d1bb8 */ \
   XXX( HRES_NS_E_AUDIO_BITRATE_STEPDOWN     , 3222084537U) /* 0xc00d1bb9 */ \
   XXX( HRES_NS_E_INVALID_AUDIO_PEAKRATE     , 3222084538U) /* 0xc00d1bba */ \
   XXX( HRES_NS_E_INVALID_AUDIO_PEAKRATE_2     , 3222084539U) /* 0xc00d1bbb */ \
   XXX( HRES_NS_E_INVALID_AUDIO_BUFFERMAX     , 3222084540U) /* 0xc00d1bbc */ \
   XXX( HRES_NS_E_MULTIPLE_VIDEO_CODECS        , 3222084541U) /* 0xc00d1bbd */ \
   XXX( HRES_NS_E_MULTIPLE_VIDEO_SIZES        , 3222084542U) /* 0xc00d1bbe */ \
   XXX( HRES_NS_E_INVALID_VIDEO_BITRATE        , 3222084543U) /* 0xc00d1bbf */ \
   XXX( HRES_NS_E_VIDEO_BITRATE_STEPDOWN     , 3222084544U) /* 0xc00d1bc0 */ \
   XXX( HRES_NS_E_INVALID_VIDEO_PEAKRATE     , 3222084545U) /* 0xc00d1bc1 */ \
   XXX( HRES_NS_E_INVALID_VIDEO_PEAKRATE_2     , 3222084546U) /* 0xc00d1bc2 */ \
   XXX( HRES_NS_E_INVALID_VIDEO_WIDTH        , 3222084547U) /* 0xc00d1bc3 */ \
   XXX( HRES_NS_E_INVALID_VIDEO_HEIGHT        , 3222084548U) /* 0xc00d1bc4 */ \
   XXX( HRES_NS_E_INVALID_VIDEO_FPS        , 3222084549U) /* 0xc00d1bc5 */ \
   XXX( HRES_NS_E_INVALID_VIDEO_KEYFRAME     , 3222084550U) /* 0xc00d1bc6 */ \
   XXX( HRES_NS_E_INVALID_VIDEO_IQUALITY     , 3222084551U) /* 0xc00d1bc7 */ \
   XXX( HRES_NS_E_INVALID_VIDEO_CQUALITY     , 3222084552U) /* 0xc00d1bc8 */ \
   XXX( HRES_NS_E_INVALID_VIDEO_BUFFER        , 3222084553U) /* 0xc00d1bc9 */ \
   XXX( HRES_NS_E_INVALID_VIDEO_BUFFERMAX     , 3222084554U) /* 0xc00d1bca */ \
   XXX( HRES_NS_E_INVALID_VIDEO_BUFFERMAX_2     , 3222084555U) /* 0xc00d1bcb */ \
   XXX( HRES_NS_E_INVALID_VIDEO_WIDTH_ALIGN     , 3222084556U) /* 0xc00d1bcc */ \
   XXX( HRES_NS_E_INVALID_VIDEO_HEIGHT_ALIGN     , 3222084557U) /* 0xc00d1bcd */ \
   XXX( HRES_NS_E_MULTIPLE_SCRIPT_BITRATES     , 3222084558U) /* 0xc00d1bce */ \
   XXX( HRES_NS_E_INVALID_SCRIPT_BITRATE     , 3222084559U) /* 0xc00d1bcf */ \
   XXX( HRES_NS_E_MULTIPLE_FILE_BITRATES     , 3222084560U) /* 0xc00d1bd0 */ \
   XXX( HRES_NS_E_INVALID_FILE_BITRATE        , 3222084561U) /* 0xc00d1bd1 */ \
   XXX( HRES_NS_E_SAME_AS_INPUT_COMBINATION     , 3222084562U) /* 0xc00d1bd2 */ \
   XXX( HRES_NS_E_SOURCE_CANNOT_LOOP        , 3222084563U) /* 0xc00d1bd3 */ \
   XXX( HRES_NS_E_INVALID_FOLDDOWN_COEFFICIENTS     , 3222084564U) /* 0xc00d1bd4 */ \
   XXX( HRES_NS_E_DRMPROFILE_NOTFOUND        , 3222084565U) /* 0xc00d1bd5 */ \
   XXX( HRES_NS_E_INVALID_TIMECODE        , 3222084566U) /* 0xc00d1bd6 */ \
   XXX( HRES_NS_E_NO_AUDIO_TIMECOMPRESSION     , 3222084567U) /* 0xc00d1bd7 */ \
   XXX( HRES_NS_E_NO_TWOPASS_TIMECOMPRESSION     , 3222084568U) /* 0xc00d1bd8 */ \
   XXX( HRES_NS_E_TIMECODE_REQUIRES_VIDEOSTREAM     , 3222084569U) /* 0xc00d1bd9 */ \
   XXX( HRES_NS_E_NO_MBR_WITH_TIMECODE        , 3222084570U) /* 0xc00d1bda */ \
   XXX( HRES_NS_E_INVALID_INTERLACEMODE        , 3222084571U) /* 0xc00d1bdb */ \
   XXX( HRES_NS_E_INVALID_INTERLACE_COMPAT     , 3222084572U) /* 0xc00d1bdc */ \
   XXX( HRES_NS_E_INVALID_NONSQUAREPIXEL_COMPAT     , 3222084573U) /* 0xc00d1bdd */ \
   XXX( HRES_NS_E_INVALID_SOURCE_WITH_DEVICE_CONTROL  , 3222084574U) /* 0xc00d1bde */ \
   XXX( HRES_NS_E_CANNOT_GENERATE_BROADCAST_INFO_FOR_QUALITYVBR, 3222084575U) /* 0xc00d1bdf */ \
   XXX( HRES_NS_E_EXCEED_MAX_DRM_PROFILE_LIMIT     , 3222084576U) /* 0xc00d1be0 */ \
   XXX( HRES_NS_E_DEVICECONTROL_UNSTABLE     , 3222084577U) /* 0xc00d1be1 */ \
   XXX( HRES_NS_E_INVALID_PIXEL_ASPECT_RATIO     , 3222084578U) /* 0xc00d1be2 */ \
   XXX( HRES_NS_E_AUDIENCE__LANGUAGE_CONTENTTYPE_MISMATCH, 3222084579U) /* 0xc00d1be3 */ \
   XXX( HRES_NS_E_INVALID_PROFILE_CONTENTTYPE     , 3222084580U) /* 0xc00d1be4 */ \
   XXX( HRES_NS_E_TRANSFORM_PLUGIN_NOT_FOUND     , 3222084581U) /* 0xc00d1be5 */ \
   XXX( HRES_NS_E_TRANSFORM_PLUGIN_INVALID     , 3222084582U) /* 0xc00d1be6 */ \
   XXX( HRES_NS_E_EDL_REQUIRED_FOR_DEVICE_MULTIPASS  , 3222084583U) /* 0xc00d1be7 */ \
   XXX( HRES_NS_E_INVALID_VIDEO_WIDTH_FOR_INTERLACED_ENCODING, 3222084584U) /* 0xc00d1be8 */ \
   XXX( HRES_NS_E_MARKIN_UNSUPPORTED        , 3222084585U) /* 0xc00d1be9 */ \
   XXX( HRES_NS_E_DRM_INVALID_APPLICATION     , 3222087441U) /* 0xc00d2711 */ \
   XXX( HRES_NS_E_DRM_LICENSE_STORE_ERROR     , 3222087442U) /* 0xc00d2712 */ \
   XXX( HRES_NS_E_DRM_SECURE_STORE_ERROR     , 3222087443U) /* 0xc00d2713 */ \
   XXX( HRES_NS_E_DRM_LICENSE_STORE_SAVE_ERROR     , 3222087444U) /* 0xc00d2714 */ \
   XXX( HRES_NS_E_DRM_SECURE_STORE_UNLOCK_ERROR     , 3222087445U) /* 0xc00d2715 */ \
   XXX( HRES_NS_E_DRM_INVALID_CONTENT        , 3222087446U) /* 0xc00d2716 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_OPEN_LICENSE     , 3222087447U) /* 0xc00d2717 */ \
   XXX( HRES_NS_E_DRM_INVALID_LICENSE        , 3222087448U) /* 0xc00d2718 */ \
   XXX( HRES_NS_E_DRM_INVALID_MACHINE        , 3222087449U) /* 0xc00d2719 */ \
   XXX( HRES_NS_E_DRM_ENUM_LICENSE_FAILED     , 3222087451U) /* 0xc00d271b */ \
   XXX( HRES_NS_E_DRM_INVALID_LICENSE_REQUEST     , 3222087452U) /* 0xc00d271c */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_INITIALIZE     , 3222087453U) /* 0xc00d271d */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_ACQUIRE_LICENSE     , 3222087454U) /* 0xc00d271e */ \
   XXX( HRES_NS_E_DRM_INVALID_LICENSE_ACQUIRED     , 3222087455U) /* 0xc00d271f */ \
   XXX( HRES_NS_E_DRM_NO_RIGHTS        , 3222087456U) /* 0xc00d2720 */ \
   XXX( HRES_NS_E_DRM_KEY_ERROR        , 3222087457U) /* 0xc00d2721 */ \
   XXX( HRES_NS_E_DRM_ENCRYPT_ERROR        , 3222087458U) /* 0xc00d2722 */ \
   XXX( HRES_NS_E_DRM_DECRYPT_ERROR        , 3222087459U) /* 0xc00d2723 */ \
   XXX( HRES_NS_E_DRM_LICENSE_INVALID_XML     , 3222087461U) /* 0xc00d2725 */ \
   XXX( HRES_NS_E_DRM_NEEDS_INDIVIDUALIZATION     , 3222087464U) /* 0xc00d2728 */ \
   XXX( HRES_NS_E_DRM_ALREADY_INDIVIDUALIZED     , 3222087465U) /* 0xc00d2729 */ \
   XXX( HRES_NS_E_DRM_ACTION_NOT_QUERIED     , 3222087466U) /* 0xc00d272a */ \
   XXX( HRES_NS_E_DRM_ACQUIRING_LICENSE        , 3222087467U) /* 0xc00d272b */ \
   XXX( HRES_NS_E_DRM_INDIVIDUALIZING        , 3222087468U) /* 0xc00d272c */ \
   XXX( HRES_NS_E_BACKUP_RESTORE_FAILURE     , 3222087469U) /* 0xc00d272d */ \
   XXX( HRES_NS_E_BACKUP_RESTORE_BAD_REQUEST_ID     , 3222087470U) /* 0xc00d272e */ \
   XXX( HRES_NS_E_DRM_PARAMETERS_MISMATCHED     , 3222087471U) /* 0xc00d272f */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_LICENSE_OBJECT  , 3222087472U) /* 0xc00d2730 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_INDI_OBJECT  , 3222087473U) /* 0xc00d2731 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_ENCRYPT_OBJECT  , 3222087474U) /* 0xc00d2732 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_DECRYPT_OBJECT  , 3222087475U) /* 0xc00d2733 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_PROPERTIES_OBJECT, 3222087476U) /* 0xc00d2734 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_BACKUP_OBJECT  , 3222087477U) /* 0xc00d2735 */ \
   XXX( HRES_NS_E_DRM_INDIVIDUALIZE_ERROR     , 3222087478U) /* 0xc00d2736 */ \
   XXX( HRES_NS_E_DRM_LICENSE_OPEN_ERROR     , 3222087479U) /* 0xc00d2737 */ \
   XXX( HRES_NS_E_DRM_LICENSE_CLOSE_ERROR     , 3222087480U) /* 0xc00d2738 */ \
   XXX( HRES_NS_E_DRM_GET_LICENSE_ERROR        , 3222087481U) /* 0xc00d2739 */ \
   XXX( HRES_NS_E_DRM_QUERY_ERROR        , 3222087482U) /* 0xc00d273a */ \
   XXX( HRES_NS_E_DRM_REPORT_ERROR        , 3222087483U) /* 0xc00d273b */ \
   XXX( HRES_NS_E_DRM_GET_LICENSESTRING_ERROR     , 3222087484U) /* 0xc00d273c */ \
   XXX( HRES_NS_E_DRM_GET_CONTENTSTRING_ERROR     , 3222087485U) /* 0xc00d273d */ \
   XXX( HRES_NS_E_DRM_MONITOR_ERROR        , 3222087486U) /* 0xc00d273e */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_SET_PARAMETER     , 3222087487U) /* 0xc00d273f */ \
   XXX( HRES_NS_E_DRM_INVALID_APPDATA        , 3222087488U) /* 0xc00d2740 */ \
   XXX( HRES_NS_E_DRM_INVALID_APPDATA_VERSION     , 3222087489U) /* 0xc00d2741 */ \
   XXX( HRES_NS_E_DRM_BACKUP_EXISTS        , 3222087490U) /* 0xc00d2742 */ \
   XXX( HRES_NS_E_DRM_BACKUP_CORRUPT        , 3222087491U) /* 0xc00d2743 */ \
   XXX( HRES_NS_E_DRM_BACKUPRESTORE_BUSY     , 3222087492U) /* 0xc00d2744 */ \
   XXX( HRES_NS_E_BACKUP_RESTORE_BAD_DATA     , 3222087493U) /* 0xc00d2745 */ \
   XXX( HRES_NS_E_DRM_LICENSE_UNUSABLE        , 3222087496U) /* 0xc00d2748 */ \
   XXX( HRES_NS_E_DRM_INVALID_PROPERTY        , 3222087497U) /* 0xc00d2749 */ \
   XXX( HRES_NS_E_DRM_SECURE_STORE_NOT_FOUND     , 3222087498U) /* 0xc00d274a */ \
   XXX( HRES_NS_E_DRM_CACHED_CONTENT_ERROR     , 3222087499U) /* 0xc00d274b */ \
   XXX( HRES_NS_E_DRM_INDIVIDUALIZATION_INCOMPLETE  , 3222087500U) /* 0xc00d274c */ \
   XXX( HRES_NS_E_DRM_DRIVER_AUTH_FAILURE     , 3222087501U) /* 0xc00d274d */ \
   XXX( HRES_NS_E_DRM_NEED_UPGRADE_MSSAP     , 3222087502U) /* 0xc00d274e */ \
   XXX( HRES_NS_E_DRM_REOPEN_CONTENT        , 3222087503U) /* 0xc00d274f */ \
   XXX( HRES_NS_E_DRM_DRIVER_DIGIOUT_FAILURE     , 3222087504U) /* 0xc00d2750 */ \
   XXX( HRES_NS_E_DRM_INVALID_SECURESTORE_PASSWORD  , 3222087505U) /* 0xc00d2751 */ \
   XXX( HRES_NS_E_DRM_APPCERT_REVOKED        , 3222087506U) /* 0xc00d2752 */ \
   XXX( HRES_NS_E_DRM_RESTORE_FRAUD        , 3222087507U) /* 0xc00d2753 */ \
   XXX( HRES_NS_E_DRM_HARDWARE_INCONSISTENT     , 3222087508U) /* 0xc00d2754 */ \
   XXX( HRES_NS_E_DRM_SDMI_TRIGGER        , 3222087509U) /* 0xc00d2755 */ \
   XXX( HRES_NS_E_DRM_SDMI_NOMORECOPIES        , 3222087510U) /* 0xc00d2756 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_HEADER_OBJECT  , 3222087511U) /* 0xc00d2757 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_KEYS_OBJECT  , 3222087512U) /* 0xc00d2758 */ \
   XXX( HRES_NS_E_DRM_LICENSE_NOTACQUIRED     , 3222087513U) /* 0xc00d2759 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_CODING_OBJECT  , 3222087514U) /* 0xc00d275a */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_STATE_DATA_OBJECT, 3222087515U) /* 0xc00d275b */ \
   XXX( HRES_NS_E_DRM_BUFFER_TOO_SMALL        , 3222087516U) /* 0xc00d275c */ \
   XXX( HRES_NS_E_DRM_UNSUPPORTED_PROPERTY     , 3222087517U) /* 0xc00d275d */ \
   XXX( HRES_NS_E_DRM_ERROR_BAD_NET_RESP     , 3222087518U) /* 0xc00d275e */ \
   XXX( HRES_NS_E_DRM_STORE_NOTALLSTORED     , 3222087519U) /* 0xc00d275f */ \
   XXX( HRES_NS_E_DRM_SECURITY_COMPONENT_SIGNATURE_INVALID, 3222087520U) /* 0xc00d2760 */ \
   XXX( HRES_NS_E_DRM_INVALID_DATA        , 3222087521U) /* 0xc00d2761 */ \
   XXX( HRES_NS_E_DRM_POLICY_DISABLE_ONLINE     , 3222087522U) /* 0xc00d2762 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_AUTHENTICATION_OBJECT, 3222087523U) /* 0xc00d2763 */ \
   XXX( HRES_NS_E_DRM_NOT_CONFIGURED        , 3222087524U) /* 0xc00d2764 */ \
   XXX( HRES_NS_E_DRM_DEVICE_ACTIVATION_CANCELED  , 3222087525U) /* 0xc00d2765 */ \
   XXX( HRES_NS_E_BACKUP_RESTORE_TOO_MANY_RESETS  , 3222087526U) /* 0xc00d2766 */ \
   XXX( HRES_NS_E_DRM_DEBUGGING_NOT_ALLOWED     , 3222087527U) /* 0xc00d2767 */ \
   XXX( HRES_NS_E_DRM_OPERATION_CANCELED     , 3222087528U) /* 0xc00d2768 */ \
   XXX( HRES_NS_E_DRM_RESTRICTIONS_NOT_RETRIEVED  , 3222087529U) /* 0xc00d2769 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_PLAYLIST_OBJECT  , 3222087530U) /* 0xc00d276a */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_PLAYLIST_BURN_OBJECT, 3222087531U) /* 0xc00d276b */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_DEVICE_REGISTRATION_OBJECT, 3222087532U) /* 0xc00d276c */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_METERING_OBJECT  , 3222087533U) /* 0xc00d276d */ \
   XXX( HRES_NS_E_DRM_TRACK_EXCEEDED_PLAYLIST_RESTICTION, 3222087536U) /* 0xc00d2770 */ \
   XXX( HRES_NS_E_DRM_TRACK_EXCEEDED_TRACKBURN_RESTRICTION, 3222087537U) /* 0xc00d2771 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_GET_DEVICE_CERT     , 3222087538U) /* 0xc00d2772 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_GET_SECURE_CLOCK  , 3222087539U) /* 0xc00d2773 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_SET_SECURE_CLOCK  , 3222087540U) /* 0xc00d2774 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_GET_SECURE_CLOCK_FROM_SERVER, 3222087541U) /* 0xc00d2775 */ \
   XXX( HRES_NS_E_DRM_POLICY_METERING_DISABLED     , 3222087542U) /* 0xc00d2776 */ \
   XXX( HRES_NS_E_DRM_TRANSFER_CHAINED_LICENSES_UNSUPPORTED, 3222087543U) /* 0xc00d2777 */ \
   XXX( HRES_NS_E_DRM_SDK_VERSIONMISMATCH     , 3222087544U) /* 0xc00d2778 */ \
   XXX( HRES_NS_E_DRM_LIC_NEEDS_DEVICE_CLOCK_SET  , 3222087545U) /* 0xc00d2779 */ \
   XXX( HRES_NS_E_LICENSE_HEADER_MISSING_URL     , 3222087546U) /* 0xc00d277a */ \
   XXX( HRES_NS_E_DEVICE_NOT_WMDRM_DEVICE     , 3222087547U) /* 0xc00d277b */ \
   XXX( HRES_NS_E_DRM_INVALID_APPCERT        , 3222087548U) /* 0xc00d277c */ \
   XXX( HRES_NS_E_DRM_PROTOCOL_FORCEFUL_TERMINATION_ON_PETITION, 3222087549U) /* 0xc00d277d */ \
   XXX( HRES_NS_E_DRM_PROTOCOL_FORCEFUL_TERMINATION_ON_CHALLENGE, 3222087550U) /* 0xc00d277e */ \
   XXX( HRES_NS_E_DRM_CHECKPOINT_FAILED        , 3222087551U) /* 0xc00d277f */ \
   XXX( HRES_NS_E_DRM_BB_UNABLE_TO_INITIALIZE     , 3222087552U) /* 0xc00d2780 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_LOAD_HARDWARE_ID  , 3222087553U) /* 0xc00d2781 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_OPEN_DATA_STORE     , 3222087554U) /* 0xc00d2782 */ \
   XXX( HRES_NS_E_DRM_DATASTORE_CORRUPT        , 3222087555U) /* 0xc00d2783 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_INMEMORYSTORE_OBJECT, 3222087556U) /* 0xc00d2784 */ \
   XXX( HRES_NS_E_DRM_STUBLIB_REQUIRED        , 3222087557U) /* 0xc00d2785 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_CERTIFICATE_OBJECT, 3222087558U) /* 0xc00d2786 */ \
   XXX( HRES_NS_E_DRM_MIGRATION_TARGET_NOT_ONLINE  , 3222087559U) /* 0xc00d2787 */ \
   XXX( HRES_NS_E_DRM_INVALID_MIGRATION_IMAGE     , 3222087560U) /* 0xc00d2788 */ \
   XXX( HRES_NS_E_DRM_MIGRATION_TARGET_STATES_CORRUPTED, 3222087561U) /* 0xc00d2789 */ \
   XXX( HRES_NS_E_DRM_MIGRATION_IMPORTER_NOT_AVAILABLE  , 3222087562U) /* 0xc00d278a */ \
   XXX( HRES_NS_DRM_E_MIGRATION_UPGRADE_WITH_DIFF_SID  , 3222087563U) /* 0xc00d278b */ \
   XXX( HRES_NS_DRM_E_MIGRATION_SOURCE_MACHINE_IN_USE  , 3222087564U) /* 0xc00d278c */ \
   XXX( HRES_NS_DRM_E_MIGRATION_TARGET_MACHINE_LESS_THAN_LH, 3222087565U) /* 0xc00d278d */ \
   XXX( HRES_NS_DRM_E_MIGRATION_IMAGE_ALREADY_EXISTS  , 3222087566U) /* 0xc00d278e */ \
   XXX( HRES_NS_E_DRM_HARDWAREID_MISMATCH     , 3222087567U) /* 0xc00d278f */ \
   XXX( HRES_NS_E_INVALID_DRMV2CLT_STUBLIB     , 3222087568U) /* 0xc00d2790 */ \
   XXX( HRES_NS_E_DRM_MIGRATION_INVALID_LEGACYV2_DATA  , 3222087569U) /* 0xc00d2791 */ \
   XXX( HRES_NS_E_DRM_MIGRATION_LICENSE_ALREADY_EXISTS  , 3222087570U) /* 0xc00d2792 */ \
   XXX( HRES_NS_E_DRM_MIGRATION_INVALID_LEGACYV2_SST_PASSWORD, 3222087571U) /* 0xc00d2793 */ \
   XXX( HRES_NS_E_DRM_MIGRATION_NOT_SUPPORTED     , 3222087572U) /* 0xc00d2794 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_CREATE_MIGRATION_IMPORTER_OBJECT, 3222087573U) /* 0xc00d2795 */ \
   XXX( HRES_NS_E_DRM_CHECKPOINT_MISMATCH     , 3222087574U) /* 0xc00d2796 */ \
   XXX( HRES_NS_E_DRM_CHECKPOINT_CORRUPT     , 3222087575U) /* 0xc00d2797 */ \
   XXX( HRES_NS_E_REG_FLUSH_FAILURE        , 3222087576U) /* 0xc00d2798 */ \
   XXX( HRES_NS_E_HDS_KEY_MISMATCH        , 3222087577U) /* 0xc00d2799 */ \
   XXX( HRES_NS_E_DRM_MIGRATION_OPERATION_CANCELLED  , 3222087578U) /* 0xc00d279a */ \
   XXX( HRES_NS_E_DRM_MIGRATION_OBJECT_IN_USE     , 3222087579U) /* 0xc00d279b */ \
   XXX( HRES_NS_E_DRM_MALFORMED_CONTENT_HEADER     , 3222087580U) /* 0xc00d279c */ \
   XXX( HRES_NS_E_DRM_LICENSE_EXPIRED        , 3222087640U) /* 0xc00d27d8 */ \
   XXX( HRES_NS_E_DRM_LICENSE_NOTENABLED     , 3222087641U) /* 0xc00d27d9 */ \
   XXX( HRES_NS_E_DRM_LICENSE_APPSECLOW        , 3222087642U) /* 0xc00d27da */ \
   XXX( HRES_NS_E_DRM_STORE_NEEDINDI        , 3222087643U) /* 0xc00d27db */ \
   XXX( HRES_NS_E_DRM_STORE_NOTALLOWED        , 3222087644U) /* 0xc00d27dc */ \
   XXX( HRES_NS_E_DRM_LICENSE_APP_NOTALLOWED     , 3222087645U) /* 0xc00d27dd */ \
   XXX( HRES_NS_E_DRM_LICENSE_CERT_EXPIRED     , 3222087647U) /* 0xc00d27df */ \
   XXX( HRES_NS_E_DRM_LICENSE_SECLOW        , 3222087648U) /* 0xc00d27e0 */ \
   XXX( HRES_NS_E_DRM_LICENSE_CONTENT_REVOKED     , 3222087649U) /* 0xc00d27e1 */ \
   XXX( HRES_NS_E_DRM_DEVICE_NOT_REGISTERED     , 3222087650U) /* 0xc00d27e2 */ \
   XXX( HRES_NS_E_DRM_LICENSE_NOSAP        , 3222087690U) /* 0xc00d280a */ \
   XXX( HRES_NS_E_DRM_LICENSE_NOSVP        , 3222087691U) /* 0xc00d280b */ \
   XXX( HRES_NS_E_DRM_LICENSE_NOWDM        , 3222087692U) /* 0xc00d280c */ \
   XXX( HRES_NS_E_DRM_LICENSE_NOTRUSTEDCODEC     , 3222087693U) /* 0xc00d280d */ \
   XXX( HRES_NS_E_DRM_SOURCEID_NOT_SUPPORTED     , 3222087694U) /* 0xc00d280e */ \
   XXX( HRES_NS_E_DRM_NEEDS_UPGRADE_TEMPFILE     , 3222087741U) /* 0xc00d283d */ \
   XXX( HRES_NS_E_DRM_NEED_UPGRADE_PD        , 3222087742U) /* 0xc00d283e */ \
   XXX( HRES_NS_E_DRM_SIGNATURE_FAILURE        , 3222087743U) /* 0xc00d283f */ \
   XXX( HRES_NS_E_DRM_LICENSE_SERVER_INFO_MISSING  , 3222087744U) /* 0xc00d2840 */ \
   XXX( HRES_NS_E_DRM_BUSY        , 3222087745U) /* 0xc00d2841 */ \
   XXX( HRES_NS_E_DRM_PD_TOO_MANY_DEVICES     , 3222087746U) /* 0xc00d2842 */ \
   XXX( HRES_NS_E_DRM_INDIV_FRAUD        , 3222087747U) /* 0xc00d2843 */ \
   XXX( HRES_NS_E_DRM_INDIV_NO_CABS        , 3222087748U) /* 0xc00d2844 */ \
   XXX( HRES_NS_E_DRM_INDIV_SERVICE_UNAVAILABLE     , 3222087749U) /* 0xc00d2845 */ \
   XXX( HRES_NS_E_DRM_RESTORE_SERVICE_UNAVAILABLE  , 3222087750U) /* 0xc00d2846 */ \
   XXX( HRES_NS_E_DRM_CLIENT_CODE_EXPIRED     , 3222087751U) /* 0xc00d2847 */ \
   XXX( HRES_NS_E_DRM_NO_UPLINK_LICENSE        , 3222087752U) /* 0xc00d2848 */ \
   XXX( HRES_NS_E_DRM_INVALID_KID        , 3222087753U) /* 0xc00d2849 */ \
   XXX( HRES_NS_E_DRM_LICENSE_INITIALIZATION_ERROR  , 3222087754U) /* 0xc00d284a */ \
   XXX( HRES_NS_E_DRM_CHAIN_TOO_LONG        , 3222087756U) /* 0xc00d284c */ \
   XXX( HRES_NS_E_DRM_UNSUPPORTED_ALGORITHM     , 3222087757U) /* 0xc00d284d */ \
   XXX( HRES_NS_E_DRM_LICENSE_DELETION_ERROR     , 3222087758U) /* 0xc00d284e */ \
   XXX( HRES_NS_E_DRM_INVALID_CERTIFICATE     , 3222087840U) /* 0xc00d28a0 */ \
   XXX( HRES_NS_E_DRM_CERTIFICATE_REVOKED     , 3222087841U) /* 0xc00d28a1 */ \
   XXX( HRES_NS_E_DRM_LICENSE_UNAVAILABLE     , 3222087842U) /* 0xc00d28a2 */ \
   XXX( HRES_NS_E_DRM_DEVICE_LIMIT_REACHED     , 3222087843U) /* 0xc00d28a3 */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_VERIFY_PROXIMITY  , 3222087844U) /* 0xc00d28a4 */ \
   XXX( HRES_NS_E_DRM_MUST_REGISTER        , 3222087845U) /* 0xc00d28a5 */ \
   XXX( HRES_NS_E_DRM_MUST_APPROVE        , 3222087846U) /* 0xc00d28a6 */ \
   XXX( HRES_NS_E_DRM_MUST_REVALIDATE        , 3222087847U) /* 0xc00d28a7 */ \
   XXX( HRES_NS_E_DRM_INVALID_PROXIMITY_RESPONSE  , 3222087848U) /* 0xc00d28a8 */ \
   XXX( HRES_NS_E_DRM_INVALID_SESSION        , 3222087849U) /* 0xc00d28a9 */ \
   XXX( HRES_NS_E_DRM_DEVICE_NOT_OPEN        , 3222087850U) /* 0xc00d28aa */ \
   XXX( HRES_NS_E_DRM_DEVICE_ALREADY_REGISTERED     , 3222087851U) /* 0xc00d28ab */ \
   XXX( HRES_NS_E_DRM_UNSUPPORTED_PROTOCOL_VERSION  , 3222087852U) /* 0xc00d28ac */ \
   XXX( HRES_NS_E_DRM_UNSUPPORTED_ACTION     , 3222087853U) /* 0xc00d28ad */ \
   XXX( HRES_NS_E_DRM_CERTIFICATE_SECURITY_LEVEL_INADEQUATE, 3222087854U) /* 0xc00d28ae */ \
   XXX( HRES_NS_E_DRM_UNABLE_TO_OPEN_PORT     , 3222087855U) /* 0xc00d28af */ \
   XXX( HRES_NS_E_DRM_BAD_REQUEST        , 3222087856U) /* 0xc00d28b0 */ \
   XXX( HRES_NS_E_DRM_INVALID_CRL        , 3222087857U) /* 0xc00d28b1 */ \
   XXX( HRES_NS_E_DRM_ATTRIBUTE_TOO_LONG     , 3222087858U) /* 0xc00d28b2 */ \
   XXX( HRES_NS_E_DRM_EXPIRED_LICENSEBLOB     , 3222087859U) /* 0xc00d28b3 */ \
   XXX( HRES_NS_E_DRM_INVALID_LICENSEBLOB     , 3222087860U) /* 0xc00d28b4 */ \
   XXX( HRES_NS_E_DRM_INCLUSION_LIST_REQUIRED     , 3222087861U) /* 0xc00d28b5 */ \
   XXX( HRES_NS_E_DRM_DRMV2CLT_REVOKED        , 3222087862U) /* 0xc00d28b6 */ \
   XXX( HRES_NS_E_DRM_RIV_TOO_SMALL        , 3222087863U) /* 0xc00d28b7 */ \
   XXX( HRES_NS_E_OUTPUT_PROTECTION_LEVEL_UNSUPPORTED  , 3222087940U) /* 0xc00d2904 */ \
   XXX( HRES_NS_E_COMPRESSED_DIGITAL_VIDEO_PROTECTION_LEVEL_UNSUPPORTED, 3222087941U) /* 0xc00d2905 */ \
   XXX( HRES_NS_E_UNCOMPRESSED_DIGITAL_VIDEO_PROTECTION_LEVEL_UNSUPPORTED, 3222087942U) /* 0xc00d2906 */ \
   XXX( HRES_NS_E_ANALOG_VIDEO_PROTECTION_LEVEL_UNSUPPORTED, 3222087943U) /* 0xc00d2907 */ \
   XXX( HRES_NS_E_COMPRESSED_DIGITAL_AUDIO_PROTECTION_LEVEL_UNSUPPORTED, 3222087944U) /* 0xc00d2908 */ \
   XXX( HRES_NS_E_UNCOMPRESSED_DIGITAL_AUDIO_PROTECTION_LEVEL_UNSUPPORTED, 3222087945U) /* 0xc00d2909 */ \
   XXX( HRES_NS_E_OUTPUT_PROTECTION_SCHEME_UNSUPPORTED  , 3222087946U) /* 0xc00d290a */ \
   XXX( HRES_NS_E_REBOOT_RECOMMENDED        , 3222088442U) /* 0xc00d2afa */ \
   XXX( HRES_NS_E_REBOOT_REQUIRED        , 3222088443U) /* 0xc00d2afb */ \
   XXX( HRES_NS_E_SETUP_INCOMPLETE        , 3222088444U) /* 0xc00d2afc */ \
   XXX( HRES_NS_E_SETUP_DRM_MIGRATION_FAILED     , 3222088445U) /* 0xc00d2afd */ \
   XXX( HRES_NS_E_SETUP_IGNORABLE_FAILURE     , 3222088446U) /* 0xc00d2afe */ \
   XXX( HRES_NS_E_SETUP_DRM_MIGRATION_FAILED_AND_IGNORABLE_FAILURE, 3222088447U) /* 0xc00d2aff */ \
   XXX( HRES_NS_E_SETUP_BLOCKED        , 3222088448U) /* 0xc00d2b00 */ \
   XXX( HRES_NS_E_UNKNOWN_PROTOCOL        , 3222089440U) /* 0xc00d2ee0 */ \
   XXX( HRES_NS_E_REDIRECT_TO_PROXY        , 3222089441U) /* 0xc00d2ee1 */ \
   XXX( HRES_NS_E_INTERNAL_SERVER_ERROR        , 3222089442U) /* 0xc00d2ee2 */ \
   XXX( HRES_NS_E_BAD_REQUEST        , 3222089443U) /* 0xc00d2ee3 */ \
   XXX( HRES_NS_E_ERROR_FROM_PROXY        , 3222089444U) /* 0xc00d2ee4 */ \
   XXX( HRES_NS_E_PROXY_TIMEOUT        , 3222089445U) /* 0xc00d2ee5 */ \
   XXX( HRES_NS_E_SERVER_UNAVAILABLE        , 3222089446U) /* 0xc00d2ee6 */ \
   XXX( HRES_NS_E_REFUSED_BY_SERVER        , 3222089447U) /* 0xc00d2ee7 */ \
   XXX( HRES_NS_E_INCOMPATIBLE_SERVER        , 3222089448U) /* 0xc00d2ee8 */ \
   XXX( HRES_NS_E_MULTICAST_DISABLED        , 3222089449U) /* 0xc00d2ee9 */ \
   XXX( HRES_NS_E_INVALID_REDIRECT        , 3222089450U) /* 0xc00d2eea */ \
   XXX( HRES_NS_E_ALL_PROTOCOLS_DISABLED     , 3222089451U) /* 0xc00d2eeb */ \
   XXX( HRES_NS_E_MSBD_NO_LONGER_SUPPORTED     , 3222089452U) /* 0xc00d2eec */ \
   XXX( HRES_NS_E_PROXY_NOT_FOUND        , 3222089453U) /* 0xc00d2eed */ \
   XXX( HRES_NS_E_CANNOT_CONNECT_TO_PROXY     , 3222089454U) /* 0xc00d2eee */ \
   XXX( HRES_NS_E_SERVER_DNS_TIMEOUT        , 3222089455U) /* 0xc00d2eef */ \
   XXX( HRES_NS_E_PROXY_DNS_TIMEOUT        , 3222089456U) /* 0xc00d2ef0 */ \
   XXX( HRES_NS_E_CLOSED_ON_SUSPEND        , 3222089457U) /* 0xc00d2ef1 */ \
   XXX( HRES_NS_E_CANNOT_READ_PLAYLIST_FROM_MEDIASERVER, 3222089458U) /* 0xc00d2ef2 */ \
   XXX( HRES_NS_E_SESSION_NOT_FOUND        , 3222089459U) /* 0xc00d2ef3 */ \
   XXX( HRES_NS_E_REQUIRE_STREAMING_CLIENT     , 3222089460U) /* 0xc00d2ef4 */ \
   XXX( HRES_NS_E_PLAYLIST_ENTRY_HAS_CHANGED     , 3222089461U) /* 0xc00d2ef5 */ \
   XXX( HRES_NS_E_PROXY_ACCESSDENIED        , 3222089462U) /* 0xc00d2ef6 */ \
   XXX( HRES_NS_E_PROXY_SOURCE_ACCESSDENIED     , 3222089463U) /* 0xc00d2ef7 */ \
   XXX( HRES_NS_E_NETWORK_SINK_WRITE        , 3222089464U) /* 0xc00d2ef8 */ \
   XXX( HRES_NS_E_FIREWALL        , 3222089465U) /* 0xc00d2ef9 */ \
   XXX( HRES_NS_E_MMS_NOT_SUPPORTED        , 3222089466U) /* 0xc00d2efa */ \
   XXX( HRES_NS_E_SERVER_ACCESSDENIED        , 3222089467U) /* 0xc00d2efb */ \
   XXX( HRES_NS_E_RESOURCE_GONE        , 3222089468U) /* 0xc00d2efc */ \
   XXX( HRES_NS_E_NO_EXISTING_PACKETIZER     , 3222089469U) /* 0xc00d2efd */ \
   XXX( HRES_NS_E_BAD_SYNTAX_IN_SERVER_RESPONSE     , 3222089470U) /* 0xc00d2efe */ \
   XXX( HRES_NS_E_RESET_SOCKET_CONNECTION     , 3222089472U) /* 0xc00d2f00 */ \
   XXX( HRES_NS_E_TOO_MANY_HOPS        , 3222089474U) /* 0xc00d2f02 */ \
   XXX( HRES_NS_E_TOO_MUCH_DATA_FROM_SERVER     , 3222089477U) /* 0xc00d2f05 */ \
   XXX( HRES_NS_E_CONNECT_TIMEOUT        , 3222089478U) /* 0xc00d2f06 */ \
   XXX( HRES_NS_E_PROXY_CONNECT_TIMEOUT        , 3222089479U) /* 0xc00d2f07 */ \
   XXX( HRES_NS_E_SESSION_INVALID        , 3222089480U) /* 0xc00d2f08 */ \
   XXX( HRES_NS_E_PACKETSINK_UNKNOWN_FEC_STREAM     , 3222089482U) /* 0xc00d2f0a */ \
   XXX( HRES_NS_E_PUSH_CANNOTCONNECT        , 3222089483U) /* 0xc00d2f0b */ \
   XXX( HRES_NS_E_INCOMPATIBLE_PUSH_SERVER     , 3222089484U) /* 0xc00d2f0c */ \
   XXX( HRES_NS_E_END_OF_PLAYLIST        , 3222090440U) /* 0xc00d32c8 */ \
   XXX( HRES_NS_E_USE_FILE_SOURCE        , 3222090441U) /* 0xc00d32c9 */ \
   XXX( HRES_NS_E_PROPERTY_NOT_FOUND        , 3222090442U) /* 0xc00d32ca */ \
   XXX( HRES_NS_E_PROPERTY_READ_ONLY        , 3222090444U) /* 0xc00d32cc */ \
   XXX( HRES_NS_E_TABLE_KEY_NOT_FOUND        , 3222090445U) /* 0xc00d32cd */ \
   XXX( HRES_NS_E_INVALID_QUERY_OPERATOR     , 3222090447U) /* 0xc00d32cf */ \
   XXX( HRES_NS_E_INVALID_QUERY_PROPERTY     , 3222090448U) /* 0xc00d32d0 */ \
   XXX( HRES_NS_E_PROPERTY_NOT_SUPPORTED     , 3222090450U) /* 0xc00d32d2 */ \
   XXX( HRES_NS_E_SCHEMA_CLASSIFY_FAILURE     , 3222090452U) /* 0xc00d32d4 */ \
   XXX( HRES_NS_E_METADATA_FORMAT_NOT_SUPPORTED     , 3222090453U) /* 0xc00d32d5 */ \
   XXX( HRES_NS_E_METADATA_NO_EDITING_CAPABILITY  , 3222090454U) /* 0xc00d32d6 */ \
   XXX( HRES_NS_E_METADATA_CANNOT_SET_LOCALE     , 3222090455U) /* 0xc00d32d7 */ \
   XXX( HRES_NS_E_METADATA_LANGUAGE_NOT_SUPORTED  , 3222090456U) /* 0xc00d32d8 */ \
   XXX( HRES_NS_E_METADATA_NO_RFC1766_NAME_FOR_LOCALE  , 3222090457U) /* 0xc00d32d9 */ \
   XXX( HRES_NS_E_METADATA_NOT_AVAILABLE     , 3222090458U) /* 0xc00d32da */ \
   XXX( HRES_NS_E_METADATA_CACHE_DATA_NOT_AVAILABLE  , 3222090459U) /* 0xc00d32db */ \
   XXX( HRES_NS_E_METADATA_INVALID_DOCUMENT_TYPE  , 3222090460U) /* 0xc00d32dc */ \
   XXX( HRES_NS_E_METADATA_IDENTIFIER_NOT_AVAILABLE  , 3222090461U) /* 0xc00d32dd */ \
   XXX( HRES_NS_E_METADATA_CANNOT_RETRIEVE_FROM_OFFLINE_CACHE, 3222090462U) /* 0xc00d32de */ \
   XXX( HRES_ERROR_MONITOR_INVALID_DESCRIPTOR_CHECKSUM  , 3223719939U) /* 0xc0261003 */ \
   XXX( HRES_ERROR_MONITOR_INVALID_STANDARD_TIMING_BLOCK, 3223719940U) /* 0xc0261004 */ \
   XXX( HRES_ERROR_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED, 3223719941U) /* 0xc0261005 */ \
   XXX( HRES_ERROR_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK, 3223719942U) /* 0xc0261006 */ \
   XXX( HRES_ERROR_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK, 3223719943U) /* 0xc0261007 */ \
   XXX( HRES_ERROR_MONITOR_NO_MORE_DESCRIPTOR_DATA  , 3223719944U) /* 0xc0261008 */ \
   XXX( HRES_ERROR_MONITOR_INVALID_DETAILED_TIMING_BLOCK, 3223719945U) /* 0xc0261009 */ \
   XXX( HRES_ERROR_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER  , 3223724032U) /* 0xc0262000 */ \
   XXX( HRES_ERROR_GRAPHICS_INSUFFICIENT_DMA_BUFFER  , 3223724033U) /* 0xc0262001 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_DISPLAY_ADAPTER  , 3223724034U) /* 0xc0262002 */ \
   XXX( HRES_ERROR_GRAPHICS_ADAPTER_WAS_RESET     , 3223724035U) /* 0xc0262003 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_DRIVER_MODEL  , 3223724036U) /* 0xc0262004 */ \
   XXX( HRES_ERROR_GRAPHICS_PRESENT_MODE_CHANGED  , 3223724037U) /* 0xc0262005 */ \
   XXX( HRES_ERROR_GRAPHICS_PRESENT_OCCLUDED     , 3223724038U) /* 0xc0262006 */ \
   XXX( HRES_ERROR_GRAPHICS_PRESENT_DENIED     , 3223724039U) /* 0xc0262007 */ \
   XXX( HRES_ERROR_GRAPHICS_CANNOTCOLORCONVERT     , 3223724040U) /* 0xc0262008 */ \
   XXX( HRES_ERROR_GRAPHICS_NO_VIDEO_MEMORY     , 3223724288U) /* 0xc0262100 */ \
   XXX( HRES_ERROR_GRAPHICS_CANT_LOCK_MEMORY     , 3223724289U) /* 0xc0262101 */ \
   XXX( HRES_ERROR_GRAPHICS_ALLOCATION_BUSY     , 3223724290U) /* 0xc0262102 */ \
   XXX( HRES_ERROR_GRAPHICS_TOO_MANY_REFERENCES     , 3223724291U) /* 0xc0262103 */ \
   XXX( HRES_ERROR_GRAPHICS_TRY_AGAIN_LATER     , 3223724292U) /* 0xc0262104 */ \
   XXX( HRES_ERROR_GRAPHICS_TRY_AGAIN_NOW     , 3223724293U) /* 0xc0262105 */ \
   XXX( HRES_ERROR_GRAPHICS_ALLOCATION_INVALID     , 3223724294U) /* 0xc0262106 */ \
   XXX( HRES_ERROR_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE, 3223724295U) /* 0xc0262107 */ \
   XXX( HRES_ERROR_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED, 3223724296U) /* 0xc0262108 */ \
   XXX( HRES_ERROR_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION, 3223724297U) /* 0xc0262109 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_ALLOCATION_USAGE  , 3223724304U) /* 0xc0262110 */ \
   XXX( HRES_ERROR_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION, 3223724305U) /* 0xc0262111 */ \
   XXX( HRES_ERROR_GRAPHICS_ALLOCATION_CLOSED     , 3223724306U) /* 0xc0262112 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_ALLOCATION_INSTANCE, 3223724307U) /* 0xc0262113 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_ALLOCATION_HANDLE  , 3223724308U) /* 0xc0262114 */ \
   XXX( HRES_ERROR_GRAPHICS_WRONG_ALLOCATION_DEVICE  , 3223724309U) /* 0xc0262115 */ \
   XXX( HRES_ERROR_GRAPHICS_ALLOCATION_CONTENT_LOST  , 3223724310U) /* 0xc0262116 */ \
   XXX( HRES_ERROR_GRAPHICS_GPU_EXCEPTION_ON_DEVICE  , 3223724544U) /* 0xc0262200 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_VIDPN_TOPOLOGY  , 3223724800U) /* 0xc0262300 */ \
   XXX( HRES_ERROR_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED, 3223724801U) /* 0xc0262301 */ \
   XXX( HRES_ERROR_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED, 3223724802U) /* 0xc0262302 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_VIDPN     , 3223724803U) /* 0xc0262303 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE, 3223724804U) /* 0xc0262304 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET, 3223724805U) /* 0xc0262305 */ \
   XXX( HRES_ERROR_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED, 3223724806U) /* 0xc0262306 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_VIDPN_SOURCEMODESET, 3223724808U) /* 0xc0262308 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_VIDPN_TARGETMODESET, 3223724809U) /* 0xc0262309 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_FREQUENCY     , 3223724810U) /* 0xc026230a */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_ACTIVE_REGION  , 3223724811U) /* 0xc026230b */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_TOTAL_REGION  , 3223724812U) /* 0xc026230c */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE, 3223724816U) /* 0xc0262310 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE, 3223724817U) /* 0xc0262311 */ \
   XXX( HRES_ERROR_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET, 3223724818U) /* 0xc0262312 */ \
   XXX( HRES_ERROR_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY  , 3223724819U) /* 0xc0262313 */ \
   XXX( HRES_ERROR_GRAPHICS_MODE_ALREADY_IN_MODESET  , 3223724820U) /* 0xc0262314 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET, 3223724821U) /* 0xc0262315 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET, 3223724822U) /* 0xc0262316 */ \
   XXX( HRES_ERROR_GRAPHICS_SOURCE_ALREADY_IN_SET  , 3223724823U) /* 0xc0262317 */ \
   XXX( HRES_ERROR_GRAPHICS_TARGET_ALREADY_IN_SET  , 3223724824U) /* 0xc0262318 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_VIDPN_PRESENT_PATH  , 3223724825U) /* 0xc0262319 */ \
   XXX( HRES_ERROR_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY, 3223724826U) /* 0xc026231a */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET, 3223724827U) /* 0xc026231b */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE, 3223724828U) /* 0xc026231c */ \
   XXX( HRES_ERROR_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET  , 3223724829U) /* 0xc026231d */ \
   XXX( HRES_ERROR_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET, 3223724831U) /* 0xc026231f */ \
   XXX( HRES_ERROR_GRAPHICS_STALE_MODESET     , 3223724832U) /* 0xc0262320 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_MONITOR_SOURCEMODESET, 3223724833U) /* 0xc0262321 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_MONITOR_SOURCE_MODE, 3223724834U) /* 0xc0262322 */ \
   XXX( HRES_ERROR_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN, 3223724835U) /* 0xc0262323 */ \
   XXX( HRES_ERROR_GRAPHICS_MODE_ID_MUST_BE_UNIQUE  , 3223724836U) /* 0xc0262324 */ \
   XXX( HRES_ERROR_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION, 3223724837U) /* 0xc0262325 */ \
   XXX( HRES_ERROR_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES, 3223724838U) /* 0xc0262326 */ \
   XXX( HRES_ERROR_GRAPHICS_PATH_NOT_IN_TOPOLOGY  , 3223724839U) /* 0xc0262327 */ \
   XXX( HRES_ERROR_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE, 3223724840U) /* 0xc0262328 */ \
   XXX( HRES_ERROR_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET, 3223724841U) /* 0xc0262329 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_MONITORDESCRIPTORSET, 3223724842U) /* 0xc026232a */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_MONITORDESCRIPTOR  , 3223724843U) /* 0xc026232b */ \
   XXX( HRES_ERROR_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET, 3223724844U) /* 0xc026232c */ \
   XXX( HRES_ERROR_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET, 3223724845U) /* 0xc026232d */ \
   XXX( HRES_ERROR_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE, 3223724846U) /* 0xc026232e */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE, 3223724847U) /* 0xc026232f */ \
   XXX( HRES_ERROR_GRAPHICS_RESOURCES_NOT_RELATED  , 3223724848U) /* 0xc0262330 */ \
   XXX( HRES_ERROR_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE  , 3223724849U) /* 0xc0262331 */ \
   XXX( HRES_ERROR_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE  , 3223724850U) /* 0xc0262332 */ \
   XXX( HRES_ERROR_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET  , 3223724851U) /* 0xc0262333 */ \
   XXX( HRES_ERROR_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER, 3223724852U) /* 0xc0262334 */ \
   XXX( HRES_ERROR_GRAPHICS_NO_VIDPNMGR        , 3223724853U) /* 0xc0262335 */ \
   XXX( HRES_ERROR_GRAPHICS_NO_ACTIVE_VIDPN     , 3223724854U) /* 0xc0262336 */ \
   XXX( HRES_ERROR_GRAPHICS_STALE_VIDPN_TOPOLOGY  , 3223724855U) /* 0xc0262337 */ \
   XXX( HRES_ERROR_GRAPHICS_MONITOR_NOT_CONNECTED  , 3223724856U) /* 0xc0262338 */ \
   XXX( HRES_ERROR_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY  , 3223724857U) /* 0xc0262339 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE, 3223724858U) /* 0xc026233a */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_VISIBLEREGION_SIZE  , 3223724859U) /* 0xc026233b */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_STRIDE     , 3223724860U) /* 0xc026233c */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_PIXELFORMAT     , 3223724861U) /* 0xc026233d */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_COLORBASIS     , 3223724862U) /* 0xc026233e */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_PIXELVALUEACCESSMODE, 3223724863U) /* 0xc026233f */ \
   XXX( HRES_ERROR_GRAPHICS_TARGET_NOT_IN_TOPOLOGY  , 3223724864U) /* 0xc0262340 */ \
   XXX( HRES_ERROR_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT, 3223724865U) /* 0xc0262341 */ \
   XXX( HRES_ERROR_GRAPHICS_VIDPN_SOURCE_IN_USE     , 3223724866U) /* 0xc0262342 */ \
   XXX( HRES_ERROR_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN  , 3223724867U) /* 0xc0262343 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL, 3223724868U) /* 0xc0262344 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION, 3223724869U) /* 0xc0262345 */ \
   XXX( HRES_ERROR_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED, 3223724870U) /* 0xc0262346 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_GAMMA_RAMP     , 3223724871U) /* 0xc0262347 */ \
   XXX( HRES_ERROR_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED  , 3223724872U) /* 0xc0262348 */ \
   XXX( HRES_ERROR_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED, 3223724873U) /* 0xc0262349 */ \
   XXX( HRES_ERROR_GRAPHICS_MODE_NOT_IN_MODESET     , 3223724874U) /* 0xc026234a */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON, 3223724877U) /* 0xc026234d */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_PATH_CONTENT_TYPE  , 3223724878U) /* 0xc026234e */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_COPYPROTECTION_TYPE, 3223724879U) /* 0xc026234f */ \
   XXX( HRES_ERROR_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS, 3223724880U) /* 0xc0262350 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_SCANLINE_ORDERING  , 3223724882U) /* 0xc0262352 */ \
   XXX( HRES_ERROR_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED, 3223724883U) /* 0xc0262353 */ \
   XXX( HRES_ERROR_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS, 3223724884U) /* 0xc0262354 */ \
   XXX( HRES_ERROR_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT, 3223724885U) /* 0xc0262355 */ \
   XXX( HRES_ERROR_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM, 3223724886U) /* 0xc0262356 */ \
   XXX( HRES_ERROR_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED, 3223725056U) /* 0xc0262400 */ \
   XXX( HRES_ERROR_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED, 3223725057U) /* 0xc0262401 */ \
   XXX( HRES_ERROR_GRAPHICS_NOT_A_LINKED_ADAPTER  , 3223725104U) /* 0xc0262430 */ \
   XXX( HRES_ERROR_GRAPHICS_LEADLINK_NOT_ENUMERATED  , 3223725105U) /* 0xc0262431 */ \
   XXX( HRES_ERROR_GRAPHICS_CHAINLINKS_NOT_ENUMERATED  , 3223725106U) /* 0xc0262432 */ \
   XXX( HRES_ERROR_GRAPHICS_ADAPTER_CHAIN_NOT_READY  , 3223725107U) /* 0xc0262433 */ \
   XXX( HRES_ERROR_GRAPHICS_CHAINLINKS_NOT_STARTED  , 3223725108U) /* 0xc0262434 */ \
   XXX( HRES_ERROR_GRAPHICS_CHAINLINKS_NOT_POWERED_ON  , 3223725109U) /* 0xc0262435 */ \
   XXX( HRES_ERROR_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE, 3223725110U) /* 0xc0262436 */ \
   XXX( HRES_ERROR_GRAPHICS_NOT_POST_DEVICE_DRIVER  , 3223725112U) /* 0xc0262438 */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_NOT_SUPPORTED     , 3223725312U) /* 0xc0262500 */ \
   XXX( HRES_ERROR_GRAPHICS_COPP_NOT_SUPPORTED     , 3223725313U) /* 0xc0262501 */ \
   XXX( HRES_ERROR_GRAPHICS_UAB_NOT_SUPPORTED     , 3223725314U) /* 0xc0262502 */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS, 3223725315U) /* 0xc0262503 */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_PARAMETER_ARRAY_TOO_SMALL, 3223725316U) /* 0xc0262504 */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_NO_VIDEO_OUTPUTS_EXIST  , 3223725317U) /* 0xc0262505 */ \
   XXX( HRES_ERROR_GRAPHICS_PVP_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME, 3223725318U) /* 0xc0262506 */ \
   XXX( HRES_ERROR_GRAPHICS_PVP_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP, 3223725319U) /* 0xc0262507 */ \
   XXX( HRES_ERROR_GRAPHICS_PVP_MIRRORING_DEVICES_NOT_SUPPORTED, 3223725320U) /* 0xc0262508 */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_INVALID_POINTER     , 3223725322U) /* 0xc026250a */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_INTERNAL_ERROR     , 3223725323U) /* 0xc026250b */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_INVALID_HANDLE     , 3223725324U) /* 0xc026250c */ \
   XXX( HRES_ERROR_GRAPHICS_PVP_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE, 3223725325U) /* 0xc026250d */ \
   XXX( HRES_ERROR_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH, 3223725326U) /* 0xc026250e */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_SPANNING_MODE_ENABLED  , 3223725327U) /* 0xc026250f */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_THEATER_MODE_ENABLED  , 3223725328U) /* 0xc0262510 */ \
   XXX( HRES_ERROR_GRAPHICS_PVP_HFS_FAILED     , 3223725329U) /* 0xc0262511 */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_INVALID_SRM     , 3223725330U) /* 0xc0262512 */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP, 3223725331U) /* 0xc0262513 */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP, 3223725332U) /* 0xc0262514 */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA, 3223725333U) /* 0xc0262515 */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_HDCP_SRM_NEVER_SET  , 3223725334U) /* 0xc0262516 */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_RESOLUTION_TOO_HIGH  , 3223725335U) /* 0xc0262517 */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE, 3223725336U) /* 0xc0262518 */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_VIDEO_OUTPUT_NO_LONGER_EXISTS, 3223725337U) /* 0xc0262519 */ \
   XXX( HRES_ERROR_GRAPHICS_OPM_SESSION_TYPE_CHANGE_IN_PROGRESS, 3223725338U) /* 0xc026251a */ \
   XXX( HRES_ERROR_GRAPHICS_I2C_NOT_SUPPORTED     , 3223725440U) /* 0xc0262580 */ \
   XXX( HRES_ERROR_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST  , 3223725441U) /* 0xc0262581 */ \
   XXX( HRES_ERROR_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA, 3223725442U) /* 0xc0262582 */ \
   XXX( HRES_ERROR_GRAPHICS_I2C_ERROR_RECEIVING_DATA  , 3223725443U) /* 0xc0262583 */ \
   XXX( HRES_ERROR_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED  , 3223725444U) /* 0xc0262584 */ \
   XXX( HRES_ERROR_GRAPHICS_DDCCI_INVALID_DATA     , 3223725445U) /* 0xc0262585 */ \
   XXX( HRES_ERROR_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE, 3223725446U) /* 0xc0262586 */ \
   XXX( HRES_ERROR_GRAPHICS_MCA_INVALID_CAPABILITIES_STRING, 3223725447U) /* 0xc0262587 */ \
   XXX( HRES_ERROR_GRAPHICS_MCA_INTERNAL_ERROR     , 3223725448U) /* 0xc0262588 */ \
   XXX( HRES_ERROR_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND, 3223725449U) /* 0xc0262589 */ \
   XXX( HRES_ERROR_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH, 3223725450U) /* 0xc026258a */ \
   XXX( HRES_ERROR_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM, 3223725451U) /* 0xc026258b */ \
   XXX( HRES_ERROR_GRAPHICS_PMEA_INVALID_MONITOR  , 3223725526U) /* 0xc02625d6 */ \
   XXX( HRES_ERROR_GRAPHICS_PMEA_INVALID_D3D_DEVICE  , 3223725527U) /* 0xc02625d7 */ \
   XXX( HRES_ERROR_GRAPHICS_DDCCI_CURRENT_CURRENT_VALUE_GREATER_THAN_MAXIMUM_VALUE, 3223725528U) /* 0xc02625d8 */ \
   XXX( HRES_ERROR_GRAPHICS_MCA_INVALID_VCP_VERSION  , 3223725529U) /* 0xc02625d9 */ \
   XXX( HRES_ERROR_GRAPHICS_MCA_MONITOR_VIOLATES_MCCS_SPECIFICATION, 3223725530U) /* 0xc02625da */ \
   XXX( HRES_ERROR_GRAPHICS_MCA_MCCS_VERSION_MISMATCH  , 3223725531U) /* 0xc02625db */ \
   XXX( HRES_ERROR_GRAPHICS_MCA_UNSUPPORTED_MCCS_VERSION, 3223725532U) /* 0xc02625dc */ \
   XXX( HRES_ERROR_GRAPHICS_MCA_INVALID_TECHNOLOGY_TYPE_RETURNED, 3223725534U) /* 0xc02625de */ \
   XXX( HRES_ERROR_GRAPHICS_MCA_UNSUPPORTED_COLOR_TEMPERATURE, 3223725535U) /* 0xc02625df */ \
   XXX( HRES_ERROR_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED, 3223725536U) /* 0xc02625e0 */ \

extern value_string_ext HRES_errors_ext;


/*
 * DOS error codes used by other dissectors.
 * At least some of these are from the SMB X/Open spec, as errors for
 * the ERRDOS error class, but they might be error codes returned from
 * DOS.
 */

#define DOS_errors_VALUE_STRING_LIST(XXX) \
    XXX( SMBE_DOS_success,                           0, "Success") \
    XXX( SMBE_DOS_badfunc,                           1, "Invalid function (or system call)") \
    XXX( SMBE_DOS_badfile,                           2, "File not found (pathname error)") \
    XXX( SMBE_DOS_badpath,                           3, "Directory not found") \
    XXX( SMBE_DOS_nofids,                            4, "Too many open files") \
    XXX( SMBE_DOS_noaccess,                          5, "Access denied") \
    XXX( SMBE_DOS_badfid,                            6, "Invalid fid") \
    XXX( SMBE_DOS_badmcb,                            7, "Memory control blocks destroyed") /* ??? */ \
    XXX( SMBE_DOS_nomem,                             8, "Out of memory") \
    XXX( SMBE_DOS_badmem,                            9, "Invalid memory block address") \
    XXX( SMBE_DOS_badenv,                           10, "Invalid environment") \
    XXX( SMBE_DOS_badformat,                        11, "Invalid format")  /* ??? */ \
    XXX( SMBE_DOS_badaccess,                        12, "Invalid open mode") \
    XXX( SMBE_DOS_baddata,                          13, "Invalid data (only from ioctl call)") \
    XXX( SMBE_DOS_res,                              14, "Reserved error code?")              /* out of memory ? */ \
    XXX( SMBE_DOS_baddrive,                         15, "Invalid drive") \
    XXX( SMBE_DOS_remcd,                            16, "Attempt to delete current directory") \
    XXX( SMBE_DOS_diffdevice,                       17, "Rename/move across different filesystems") \
    XXX( SMBE_DOS_nofiles,                          18, "No more files found in file search") \
    XXX( SMBE_DOS_general,                          31, "General failure")                   /* Also "SMBE_HRD" */ \
    XXX( SMBE_DOS_badshare,                         32, "Share mode on file conflict with open mode") \
    XXX( SMBE_DOS_lock,                             33, "Lock request conflicts with existing lock") \
    XXX( SMBE_DOS_unsup,                            50, "Request unsupported, returned by Win 95") /* RJS 20Jun98 */ \
    XXX( SMBE_DOS_netnamedel,                       64, "Network name deleted or not available") \
    XXX( SMBE_DOS_noipc,                            66, "Don't support ipc")   \
    XXX( SMBE_DOS_nosuchshare,                      67, "Requested share does not exist") \
    XXX( SMBE_DOS_filexists,                        80, "File in operation already exists") \
    XXX( SMBE_DOS_invalidparam,                     87, "Invalid parameter") \
    XXX( SMBE_DOS_cannotopen,                      110, "Cannot open the file specified") \
    XXX( SMBE_DOS_bufferoverflow,                  111, "Buffer overflow") \
    XXX( SMBE_DOS_insufficientbuffer,              122, "Insufficient buffer") \
    XXX( SMBE_DOS_invalidname,                     123, "Invalid name") \
    XXX( SMBE_DOS_unknownlevel,                    124, "Unknown info level") \
    XXX( SMBE_DOS_notlocked,                       158, "This region is not locked by this locking context.") \
    XXX( SMBE_DOS_invalidpath,                     161, "Invalid Path") \
    XXX( SMBE_DOS_cancelviolation,                 173, "Cancel violation") \
    XXX( SMBE_DOS_noatomiclocks,                   174, "No atomic clocks") \
    XXX( SMBE_DOS_alreadyexists,                   183, "File already exists") /* 'rename" ? */ \
    XXX( SMBE_DOS_badpipe,                         230, "Named pipe invalid") \
    XXX( SMBE_DOS_pipebusy,                        231, "All instances of pipe are busy") \
    XXX( SMBE_DOS_pipeclosing,                     232, "Named pipe close in progress") \
    XXX( SMBE_DOS_notconnected,                    233, "No process on other end of named pipe") \
    XXX( SMBE_DOS_moredata,                        234, "More data to be returned") \
    XXX( SMBE_DOS_eainconsistent,                  255, "ea inconsistent") /* from EMC */ \
    XXX( SMBE_DOS_nomoreitems,                     259, "No more items") \
    XXX( SMBE_DOS_baddirectory,                    267, "Invalid directory name in a path.") \
    XXX( SMBE_DOS_eas_didnt_fit,                   275, "Extended attributes didn't fit") \
    XXX( SMBE_DOS_eas_nsup,                        282, "Extended attributes not supported") \
    XXX( SMBE_DOS_notify_buf_small,               1022, "Buffer too small to return change notify.") \
    XXX( SMBE_DOS_invalidowner,                   1307, "Invalid security descriptor owner") /* NT printer driver system only */ \
    XXX( SMBE_DOS_logonfailure,                   1326, "Unknown username or bad password") \
    XXX( SMBE_DOS_invalidsecuritydescriptor,      1338, "Invalid security descriptor")       /* NT printer driver system only */ \
    XXX( SMBE_DOS_serverunavailable,              1722, "Server unavailable") \
    XXX( SMBE_DOS_driveralreadyinstalled,         1795, "Printer driver already installed")  /* NT printer driver system only */ \
    XXX( SMBE_DOS_unknownprinterport,             1796, "Error unknown port")                /* NT printer driver system only */ \
    XXX( SMBE_DOS_unknownprinterdriver,           1797, "Unknown printer driver")            /* NT printer driver system only */ \
    XXX( SMBE_DOS_unknownprintprocessor,          1798, "Unknown print processor")           /* NT printer driver system only */ \
    XXX( SMBE_DOS_invalidseparatorfile,           1799, "Invalid separator file")            /* NT printer driver system only */ \
    XXX( SMBE_DOS_invalidjobpriority,             1800, "Invalid priority")                  /* NT printer driver system only */ \
    XXX( SMBE_DOS_invalidprintername,             1801, "Invalid printer name")              /* NT printer driver system only */ \
    XXX( SMBE_DOS_printeralreadyexists,           1802, "Printer already exists")            /* NT printer driver system only */ \
    XXX( SMBE_DOS_invalidprintercommand,          1803, "Invalid printer command")           /* NT printer driver system only */ \
    XXX( SMBE_DOS_invaliddatatype,                1804, "Invalid datatype")                  /* NT printer driver system only */ \
    XXX( SMBE_DOS_invalidenvironment,             1805, "Invalid environment")               /* NT printer driver system only */ \
    XXX( SMBE_DOS_invalidformsize,                1903, "Invalid form size")                 /* NT printer driver system only */ \
    XXX( SMBE_DOS_buftoosmall,                    2123, "Buffer too small") \
    XXX( SMBE_DOS_unknownipc,                     2142, "Unknown IPC Operation") \
    XXX( SMBE_DOS_nosuchprintjob,                 2151, "No such print job")                 /* NT printer driver system only ?? */ \
    XXX( SMBE_DOS_invgroup,                       2455, "Invalid Group") \
    XXX( SMBE_DOS_unknownprintmonitor,            3000, "Unknown print monitor")             /* NT printer driver system only */ \
    XXX( SMBE_DOS_printerdriverinuse,             3001, "Printer driver in use")             /* NT printer driver system only */ \
    XXX( SMBE_DOS_spoolfilenotfound,              3002, "Spool file not found")              /* NT printer driver system only */ \
    XXX( SMBE_DOS_nostartdoc,                     3003, "Error_spl_no_startdoc")             /* NT printer driver system only */ \
    XXX( SMBE_DOS_noaddjob,                       3004, "Spl no addjob")                     /* NT printer driver system only */ \
    XXX( SMBE_DOS_printprocessoralreadyinstalled, 3005, "Print processor already installed") /* NT printer driver system only */ \
    XXX( SMBE_DOS_printmonitoralreadyinstalled,   3006, "Print monitor already installed")   /* NT printer driver system only */ \
    XXX( SMBE_DOS_invalidprintmonitor,            3007, "Invalid print monitor")             /* NT printer driver system only */ \
    XXX( SMBE_DOS_printmonitorinuse,              3008, "Print monitor in use")              /* NT printer driver system only */ \
    XXX( SMBE_DOS_printerhasjobsqueued,           3009, "Printer has jobs queued")           /* NT printer driver system only */

VALUE_STRING_ENUM(DOS_errors);
extern value_string_ext DOS_errors_ext;

/*
 * NT error codes used by other dissectors.
 */
extern value_string_ext NT_errors_ext;

extern value_string_ext ms_country_codes_ext;

WS_DLL_PUBLIC
int dissect_nt_64bit_time(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_date);
WS_DLL_PUBLIC
int dissect_nt_64bit_time_opt(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_date, bool onesec_resolution);
WS_DLL_PUBLIC
int dissect_nt_64bit_time_ex(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_date, proto_item **createdItem, bool onesec_resolution);

/*
 *  SIDs and RIDs
 */

typedef struct _sid_strings {
	const char* sid;
	const char* name;
} sid_strings;

/* Dissect a NT SID.  Label it with 'name' and return a string version
 * of the SID in the 'sid_str' parameter which has a packet lifetime
 * scope and should NOT be freed by the caller. hf_sid can be -1 if
 * the caller doesn't care what name is used and then "nt.sid" will be
 * the default instead. If the caller wants a more appropriate hf
 * field, it will just pass a FT_STRING hf field here
 */

WS_DLL_PUBLIC
int dissect_nt_sid(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
		   const char *name, char **sid_str, int hf_sid);

WS_DLL_PUBLIC
int dissect_nt_sid_ret_item(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                            const char *name, char **sid_str, int hf_sid,
                            proto_item **item_ret);

/*
 * Stuff for dissecting NT access masks
 */

/*
 * Access mask values
 */

/* Generic rights */

#define GENERIC_RIGHTS_MASK    0xF0000000

#define GENERIC_ALL_ACCESS     0x10000000
#define GENERIC_EXECUTE_ACCESS 0x20000000
#define GENERIC_WRITE_ACCESS   0x40000000
#define GENERIC_READ_ACCESS    0x80000000

/* Misc/reserved */

#define ACCESS_SACL_ACCESS     0x00800000
#define SYSTEM_SECURITY_ACCESS 0x01000000
#define MAXIMUM_ALLOWED_ACCESS 0x02000000

/* Standard rights */

#define STANDARD_RIGHTS_MASK 0x00FF0000

#define DELETE_ACCESS        0x00010000
#define READ_CONTROL_ACCESS  0x00020000
#define WRITE_DAC_ACCESS     0x00040000
#define WRITE_OWNER_ACCESS   0x00080000
#define SYNCHRONIZE_ACCESS   0x00100000

/* Specific rights */

#define SPECIFIC_RIGHTS_MASK 0x0000FFFF /* Specific rights defined per-object */

typedef void (nt_access_mask_fn_t)(tvbuff_t *tvb, int offset,
				   proto_tree *tree, uint32_t access);

/* Map generic access permissions to specific permissions */

struct generic_mapping {
	uint32_t generic_read;
	uint32_t generic_write;
	uint32_t generic_execute;
	uint32_t generic_all;
};

/* Map standard access permissions to specific permissions */

struct standard_mapping {
	uint32_t std_read;
	uint32_t std_write;
	uint32_t std_execute;
	uint32_t std_all;
};

struct access_mask_info {
	const char *specific_rights_name;
	nt_access_mask_fn_t *specific_rights_fn;
	struct generic_mapping *generic_mapping;
	struct standard_mapping *standard_mapping;
};

int
dissect_nt_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo,
		       proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex,
		       struct access_mask_info *ami,
		       uint32_t *perms);

int
dissect_nt_sec_desc(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *parent_tree, uint8_t *drep,
		    bool len_supplied, int len,
		    struct access_mask_info *ami);

void
proto_do_register_windows_common(int proto_smb);

int
dissect_nt_security_information(tvbuff_t *tvb, int offset, proto_tree *parent_tree);

#endif

