/* packet-assa_r3.c
 * Routines for R3 packet dissection
 * Copyright (c) 2009 Assa Abloy USA <jcwren[AT]assaabloyusa.com>
 *
 * R3 is an electronic lock management protocol for configuring operational
 *  parameters, adding/removing/altering users, dumping log files, etc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/dissectors/packet-tcp.h>

#if 0
/* */
/*  System limits */
/* */
#define MAX_USERS            2400
#define MAX_TIMEZONES          32
#define MAX_EXCEPTIONS         64
#define MAX_EXCEPTIONGROUPS    64
#define MAX_EVENTENTRIES    10000
#define MAX_DECLINEDENTRIES   500
#define MAX_ALARMENTRIES      200
#endif

/*
 *  Enumerations
 */
typedef enum
{
  ACCESSMODE_NONE = 0,        /* 0 - No access mode (not used, not legal, I think) */
  ACCESSMODE_PRIMARYONLY,     /* 1 - Primary only */
  ACCESSMODE_PRIMARYORAUX,    /* 2 - Primary or aux field */
  ACCESSMODE_PRIMARYANDAUX,   /* 3 - Primary and aux field */
  ACCESSMODE_PRIMARYTHENAUX,  /* 4 - Primary required first, then aux */
  ACCESSMODE_LAST             /* 5 - Dummy, for range checking */
}
accessMode_e;

typedef enum
{
  ADDUSERPARAMTYPE_DISPOSITION = 0,   /*  0 - What we're supposed to do (add, delete, etc) */
  ADDUSERPARAMTYPE_USERNO,            /*  1 - User to manage (user number, U16) */
  ADDUSERPARAMTYPE_ACCESSALWAYS,      /*  2 - Access always (boolean) */
  ADDUSERPARAMTYPE_ACCESSMODE,        /*  3 - Access type (accessMode_e) */
  ADDUSERPARAMTYPE_CACHED,            /*  4 - Entry is managed by cache system (boolean) */
  ADDUSERPARAMTYPE_USERTYPE,          /*  5 - User type (userType_e) */
  ADDUSERPARAMTYPE_PRIMARYFIELD,      /*  6 - Primary field (MAX_CREDENTIALBYTES) */
  ADDUSERPARAMTYPE_PRIMARYFIELDTYPE,  /*  7 - Primary field type (fieldType_e); */
  ADDUSERPARAMTYPE_AUXFIELD,          /*  8 - Auxiliary field (MAX_CREDENTIALBYTES) */
  ADDUSERPARAMTYPE_AUXFIELDTYPE,      /*  9 - Auxiliary field type (fieldType_e) */
  ADDUSERPARAMTYPE_TIMEZONE,          /* 10 - Timezone bitmap (U32) */
  ADDUSERPARAMTYPE_EXPIREON,          /* 11 - Date on which user no longer granted access, if non-0 */
  ADDUSERPARAMTYPE_USECOUNT,          /* 12 - Use count */
  ADDUSERPARAMTYPE_EXCEPTIONGROUP,    /* 13 - Exception group */
  ADDUSERPARAMTYPE_LAST
}
addUserParamType_e;

typedef enum
{
  ALARMID_NONE = 0,       /* 0 - No alarm */
  ALARMID_VALIDIN,        /* 1 - Valid entry */
  ALARMID_DENIEDACCESS,   /* 2 - Denied access (bad credential) */
  ALARMID_SECURED,        /* 3 - Door closed & secured (only seen after alarms 3 or 4) */
  ALARMID_DOORFORCED,     /* 4 - Door forced */
  ALARMID_KEYOVERRIDE,    /* 5 - Key override */
  ALARMID_INVALIDENTRY,   /* 6 - Door open but invalid entry (key used?) */
  ALARMID_DOORAJAR,       /* 7 - Door ajar (needs .ja woman with Engrish accent) */
  ALARMID_LOWBATTERY,     /* 8 - Low battery alarm */
  ALARMID_RXHELD,         /* 9 - RX held */
  ALARMID_LAST
}
alarmID_e;

typedef enum
{
  CAPABILITIES_USERS = 0,         /* 0 - Number of users supported */
  CAPABILITIES_TIMEZONES,         /* 1 - Number of timezone supported */
  CAPABILITIES_EXCEPTIONS,        /* 2 - Number of exceptions supported */
  CAPABILITIES_EXCEPTIONGROUPS,   /* 3 - Number of exception groups supported */
  CAPABILITIES_EVENTLOG,          /* 4 - Number of event log entries supported */
  CAPABILITIES_DECLINEDLOG,       /* 5 - Number of declined log entries supported */
  CAPABILITIES_ALARMLOG,          /* 6 - Number of alarm log entries supported */
  CAPABILITIES_TOTALEVENTS,       /* 7 - Total events (EVENT_LAST - 1) */
  CAPABILITIES_LAST
}
capabilities_e;

typedef enum
{
  CHECKSUMRESULT_CONFIGURATIONNVRAM = 0,  /*  0 - Checksum results of the configuration NVRAM */
  CHECKSUMRESULT_EXCEPTIONS,              /*  1 - Checksum results of the exceptions NVRAM */
  CHECKSUMRESULT_EXCEPTIONGROUPS,         /*  2 - Checksum results of the exception groups NVRAM */
  CHECKSUMRESULT_TZCALENDARS,             /*  3 - Checksum results of the time zone calendar NVRAM */
  CHECKSUMRESULT_TIMEZONES,               /*  4 - Checksum results of the time zone NVRAM */
  CHECKSUMRESULT_USERS,                   /*  5 - Checksum results of the users NVRAM */
  CHECKSUMRESULT_CACHELRU,                /*  6 - Checksum results of the cache LRU */
  CHECKSUMRESULT_LAST
}
checksumResult_e;

typedef enum
{
  CMD_RESPONSE = 0,               /*  0 - Response to command */
  CMD_HANDSHAKE,                  /*  1 - Establish session */
  CMD_KILLSESSION,                /*  2 - Kill session */
  CMD_QUERYSERIALNUMBER,          /*  3 - Query serial number */
  CMD_QUERYVERSION,               /*  4 - Query version */
  CMD_SETDATETIME,                /*  5 - Set date and time */
  CMD_QUERYDATETIME,              /*  6 - Query date and time */
  CMD_SETCONFIG,                  /*  7 - Set configuration options */
  CMD_GETCONFIG,                  /*  8 - Read configuration options  */
  CMD_MANAGEUSER,                 /*  9 - Manage users (add/delete/replace/update) */
  CMD_DELETEUSERS,                /* 10 - Delete users (all/most/cached) */
  CMD_DEFINEEXCEPTION,            /* 11 - Define exception (old block holiday) */
  CMD_DEFINEEXCEPTIONGROUP,       /* 12 - Define exception group */
  CMD_DEFINECALENDAR,             /* 13 - Define calendar */
  CMD_DEFINETIMEZONE,             /* 14 - Define time zone */
  CMD_RMTAUTHRETRY,               /* 15 - Remote authorization retry */
  CMD_FILTERS,                    /* 16 - Event log filter configuration */
  CMD_ALARMCONFIGURE,             /* 17 - Alarm condition configuration */
  CMD_EVENTLOGDUMP,               /* 18 - Dump event log */
  CMD_DECLINEDLOGDUMP,            /* 19 - Dump declined log */
  CMD_ALARMLOGDUMP,               /* 20 - Dump alarm log */
  CMD_DOWNLOADFIRMWARE,           /* 21 - Download firmware */
  CMD_DOWNLOADFIRMWARETIMEOUT,    /* 22 - Download firmware timeout (internal command only) */
  CMD_POWERTABLESELECTION,        /* 23 - Power table selection */
  CMD_CLEARNVRAM,                 /* 24 - Clear nvram (config/event log/declined log/etc) */
  CMD_DPAC,                       /* 25 - DPAC manipulation commands */
  CMD_SELFTEST,                   /* 26 - Selftest (heh) */
  CMD_RESET,                      /* 27 - Restart controller */
  CMD_LOGWRITE,                   /* 28 - Write event to event log */
  CMD_MFGCOMMAND,                 /* 29 - Manufacturing commands */
  CMD_NVRAMBACKUP,                /* 30 - Backup/restore/erase NVRAM */
  CMD_EXTENDEDRESPONSE,           /* 31 - Response to command (extended version) */
  CMD_LAST
}
cmdCommand_e;

typedef enum
{
  CMDMFG_SETSERIALNUMBER = 0,   /*  0 - Set serial number */
  CMDMFG_SETCRYPTKEY,           /*  1 - Set encryption key */
  CMDMFG_DUMPNVRAM,             /*  2 - Dump NVRAM */
  CMDMFG_TERMINAL,              /*  3 - DPAC terminal mode */
  CMDMFG_REMOTEUNLOCK,          /*  4 - Remote unlock (only on 'd' builds) */
  CMDMFG_AUXCTLRVERSION,        /*  5 - Request version of auxiliary controller */
  CMDMFG_IOPINS,                /*  6 - Read I/O pin states */
  CMDMFG_ADCS,                  /*  7 - Read ADC values */
  CMDMFG_HARDWAREID,            /*  8 - Read hardware ID and CPU ID */
  CMDMFG_CHECKPOINTLOGDUMP,     /*  9 - Dump checkpoint log */
  CMDMFG_CHECKPOINTLOGCLEAR,    /* 10 - Clear checkpoint log */
  CMDMFG_READREGISTERS,         /* 11 - Read selected CPU registers */
  CMDMFG_FORCEOPTIONS,          /* 12 - Force I/O lines to certain states */
  CMDMFG_COMMUSER,              /* 13 - Fake a comm user entry */
  CMDMFG_DUMPKEYPAD,            /* 14 - Dump keypad debugging buffer */
  CMDMFG_BATTERYCHECK,          /* 15 - Force battery check */
  CMDMFG_RAMREFRESH,            /* 16 - Refresh RAM variables from NVRAM */
  CMDMFG_TASKFLAGS,             /* 17 - Dump task flags */
  CMDMFG_TIMERCHAIN,            /* 18 - Dump active timer chains */
  CMDMFG_PEEKPOKE,              /* 19 - Peek/poke CPU RAM memory */
  CMDMFG_LOCKSTATE,             /* 20 - Display global gLockState variable */
  CMDMFG_CAPABILITIES,          /* 21 - Read firmware capabilities (# users/event log entries, etc) */
  CMDMFG_DUMPM41T81,            /* 22 - Dump M41T81 RTC registers */
  CMDMFG_DEBUGLOGDUMP,          /* 23 - Dump debugging log */
  CMDMFG_DEBUGLOGCLEAR,         /* 24 - Clear debugging log */
  CMDMFG_TESTWDT,               /* 25 - Test watchdog */
  CMDMFG_QUERYCKSUM,            /* 26 - Query NVRAM checksum value */
  CMDMFG_VALIDATECHECKSUMS,     /* 27 - Validate checksums */
  CMDMFG_REBUILDLRUCACHE,       /* 28 - Rebuild LRC cache */
  CMDMFG_TZUPDATE,              /* 29 - Send TZCHANGE to tod.c */
  CMDMFG_TESTPRESERVE,          /* 30 - Test preserve save/restore code */
  CMDMFG_MORTISESTATELOGDUMP,   /* 31 - Dump the mortise state log */
  CMDMFG_MORTISESTATELOGCLEAR,  /* 32 - Clear the mortise state log */
  CMDMFG_MORTISEPINS,           /* 33 - Display current mortise pin status */
  CMDMFG_HALTANDCATCHFIRE,      /* 34 - Stop processor (optionally catch fire) */
  CMDMFG_LAST
}
cmdMfgCommand_e;

typedef enum
{
  CONFIGITEM_SERIAL_NUMBER = 0,           /*    0 - Ye olde serial number */
  CONFIGITEM_CRYPT_KEY,                   /*    1 - The encryption/decryption key */
  CONFIGITEM_HARDWARE_OPTIONS_MFG,        /*    2 - Bit map of hardware options at manufacturing time (hardwareOptions_e) */
  CONFIGITEM_HARDWARE_OPTIONS,            /*    3 - Bit map of hardware options at runtime time (hardwareOptions_e) */
  CONFIGITEM_NVRAM_CHANGES,               /*    4 - Log of NVRAM changes since reset (which blocks were reset) */

  CONFIGITEM_NVRAMDIRTY,                  /*    5 - NVRAM is (or might be) dirty */
  CONFIGITEM_NVRAM_WV,                    /*    6 - NVRAM write verify (I2C parts only) */
  CONFIGITEM_ENABLE_WDT,                  /*    7 - If true, and OPT_WATCHDOG enabled, enables WDT */
  CONFIGITEM_EARLY_ACK,                   /*    8 - Generates early RESPONSE_COMMANDRECEIVED message for commands that take some time */
  CONFIGITEM_CONSOLE_AES_ONLY,            /*    9 - If set, requires AES encryption on serial communications */
  CONFIGITEM_RADIO_AES_ONLY,              /*   10 - If set, requires AES encryption on radio communications */
  CONFIGITEM_NDRLE,                       /*   11 - RLE (Run Length Encoding) NVRAM dump enable/disable */
  CONFIGITEM_SOMF,                        /*   12 - Stop on mortise failure */
  CONFIGITEM_NOGAF,                       /*   13 - Prevents what should be fatal errors from being fatal (i.e, No One Gives A Flip) */
  CONFIGITEM_CARD_READER_POWER,           /*   14 - External mag reader power supply control */
  CONFIGITEM_PROX_ENABLE,                 /*   15 - Prox into permanent sleep mode */
  CONFIGITEM_CKSUMCONFIG,                 /*   16 - Configuration NVRAM checksum enable/disable  */
  CONFIGITEM_DAILY_BATTERY_CHECK,         /*   17 - Enable/disable daily battery check */
  CONFIGITEM_DAILY_BATTERY_CHECK_HOUR,    /*   18 - If daily battery check enabled, top of the hour to check at */
  CONFIGITEM_BATTERY_LOW,                 /*   19 - Return low battery status (TRUE = low) */

  CONFIGITEM_LRU_HEAD,                    /*   20 - Cache LRU head pointer */
  CONFIGITEM_LRU_TAIL,                    /*   21 - Cache LRU tail pointer */
  CONFIGITEM_RTC_CALIBRATION,             /*   22 - Signed 6 bit value written to M41T81 calibration register */
  CONFIGITEM_ACVREQUESTER,                /*   23 - Auxiliary controller version requester (fromDevice_e, internal variable) */
  CONFIGITEM_LOCAL_LED,                   /*   24 - Local LED function assignment */

  CONFIGITEM_ERRCNT_XORLEN,               /*   25 - Error counter for XOR length not matching in protocol.c */
  CONFIGITEM_ERRCNT_CRC,                  /*   26 - Error counter for bad CRC in protocol.c */
  CONFIGITEM_ERRCNT_NOTSIGIL,             /*   27 - Error counter for character received was not sigil in protocol.c */
  CONFIGITEM_ERRCNT_TIMEOUT,              /*   28 - Error counter for timeout in protocol.c */
  CONFIGITEM_ERRCNT_TOOLONG,              /*   29 - Error counter for packet too long in protocol.c */
  CONFIGITEM_ERRCNT_TOOSHORT,             /*   30 - Error counter for packet too short in protocol.c */
  CONFIGITEM_ERRCNT_HITDEFAULT,           /*   31 - Error counter for hitting default handler in protocol.c */
  CONFIGITEM_ERRCNT_OVERRUN,              /*   32 - Error counter for serial buffer overrun in serial.c */
  CONFIGITEM_ERRCNT_UARTFE,               /*   33 - Error counter for UART framing error in serial.c */
  CONFIGITEM_ERRCNT_UARTOE,               /*   34 - Error counter for UART overrun error in serial.c */

  CONFIGITEM_DST_SET,                     /*   35 - Daylight savings time currently active */
  CONFIGITEM_DST_MODE,                    /*   36 - Determines if repeating month/date, repeating month/day, or specific month/date (dstMode_e) */
  CONFIGITEM_DST_FORWARD_MONTH,           /*   37 - Month to skip forward on (1-12) (DSTMODE_REPEATINGDATE, DSTMODE_REPEATINGDOW, DSTMODE_ONETIMEDATE) */
  CONFIGITEM_DST_FORWARD_DOM,             /*   38 - Day of month to skip forward on (1-31) (DSTMODE_REPEATINGDATE, DSTMODE_ONETIMEDATE) */
  CONFIGITEM_DST_FORWARD_OOD,             /*   39 - Occurence number of CONFIGITEM_DST_FORWARD_DOW to skip forward on (1-5)  (DSTMODE_REPEATINGDOW) */
  CONFIGITEM_DST_FORWARD_DOW,             /*   40 - Day of week to skip forward on (1-7) (DSTMODE_REPEATINGDOW) */
  CONFIGITEM_DST_FORWARD_HOUR,            /*   41 - Hour of day of month to skip forward on (0-23) (DSTMODE_REPEATINGDATE, DSTMODE_REPEATINGDOW, DSTMODE_ONETIMEDATE) */
  CONFIGITEM_DST_FORWARD_MINUTE,          /*   42 - Hour of day of month to skip forward on (0-23) (DSTMODE_REPEATINGDATE, DSTMODE_REPEATINGDOW, DSTMODE_ONETIMEDATE) */
  CONFIGITEM_DST_FORWARD_ADJUST,          /*   43 - Number of minutes to move forward */
  CONFIGITEM_DST_BACK_MONTH,              /*   44 - Month to fall back on (1-12) (DSTMODE_REPEATINGDATE, DSTMODE_REPEATINGDAY, DSTMODE_ONETIMEDATE) */
  CONFIGITEM_DST_BACK_DOM,                /*   45 - Day of month to fall back on (1-31) (DSTMODE_REPEATINGDATE, DSTMODE_ONETIMEDATE) */
  CONFIGITEM_DST_BACK_OOD,                /*   46 - Occurence number of CONFIGITEM_DST_BACK_DOW to fall back on (1-5)  (DSTMODE_REPEATINGDOW) */
  CONFIGITEM_DST_BACK_DOW,                /*   47 - Day of week to fall back on (1-7) (DSTMODE_REPEATINGDATE, DSTMODE_ONETIMEDATE) */
  CONFIGITEM_DST_BACK_HOUR,               /*   48 - Hour of day of month to fall back on (0-23) (DSTMODE_REPEATINGDATE, DSTMODE_REPEATINGDOW, DSTMODE_ONETIMEDATE) */
  CONFIGITEM_DST_BACK_MINUTE,             /*   49 - Hour of day of month to fall back on (0-23) (DSTMODE_REPEATINGDATE, DSTMODE_REPEATINGDOW, DSTMODE_ONETIMEDATE) */
  CONFIGITEM_DST_BACK_ADJUST,             /*   50 - Number of minutes to move backwards */

  CONFIGITEM_EVENTLOG_ZEROMEM,            /*   51 - If set, event log memory is zeroed when event log cleared */
  CONFIGITEM_EVENTLOG_BEGIN,              /*   52 - Beginning record number when event log cleared */
  CONFIGITEM_EVENTLOG_RECORD,             /*   53 - Next event log record to write */
  CONFIGITEM_EVENTLOG_ENTRIES,            /*   54 - Number of entries in event log */
  CONFIGITEM_EVENTLOG_WARNDEVICE,         /*   55 - Event log warning device */
  CONFIGITEM_EVENTLOG_WARNEVERY,          /*   56 - Warn at every 'n' records (more or less) */
  CONFIGITEM_EVENTLOG_RMTDEVICE,          /*   57 - Device event log entries copied to (fromDevice_e) */

  CONFIGITEM_DECLINEDLOG_ZEROMEM,         /*   58 - If set, declined log memory is zeroed when declined log cleared */
  CONFIGITEM_DECLINEDLOG_BEGIN,           /*   59 - Beginning record number when declined log cleared */
  CONFIGITEM_DECLINEDLOG_RECORD,          /*   60 - Next declined log record to write */
  CONFIGITEM_DECLINEDLOG_ENTRIES,         /*   61 - Number of entries in declined log */
  CONFIGITEM_DECLINEDLOG_WARNDEVICE,      /*   62 - Declined record warning device */
  CONFIGITEM_DECLINEDLOG_WARNEVERY,       /*   63 - Warn at every 'n' records (more or less) */
  CONFIGITEM_DECLINEDLOG_RMTDEVICE,       /*   64 - Device declined entries copied to (fromDevice_e) */

  CONFIGITEM_ALARMLOG_ZEROMEM,            /*   65 - If set, alarm log memory is zeroed when alarm log cleared */
  CONFIGITEM_ALARMLOG_BEGIN,              /*   66 - Beginning record number when alarm log cleared */
  CONFIGITEM_ALARMLOG_RECORD,             /*   67 - Next alarm log record to write */
  CONFIGITEM_ALARMLOG_ENTRIES,            /*   68 - Number of entries in alarm log */
  CONFIGITEM_ALARMLOG_WARNDEVICE,         /*   69 - Alarm record warning device */
  CONFIGITEM_ALARMLOG_WARNEVERY,          /*   70 - Warn at every 'n' records (more or less) */
  CONFIGITEM_ALARMLOG_RMTDEVICE,          /*   71 - Device alarm entries copied to (fromDevice_e) */

  CONFIGITEM_VISIBLE_FEEDBACK,            /*   72 - Visible feedback on keypad presses enabled */
  CONFIGITEM_AUDIBLE_FEEDBACK,            /*   73 - Audible feedback on keypad presses enabled */
  CONFIGITEM_VISIBLE_INDICATORS,          /*   74 - Visible indicators on all actions (run dark) */
  CONFIGITEM_AUDIBLE_INDICATORS,          /*   75 - Audible indicators on all actions (run silent) */
  CONFIGITEM_2NDPINDURATION,              /*   76 - Number of seconds to wait for second PIN */
  CONFIGITEM_LOCKOUT_ATTEMPTS,            /*   77 - Number of pin/prox/magcard attempts before lockout */
  CONFIGITEM_LOCKOUT_DURATION,            /*   78 - Duration of lockout, in penta-seconds */
  CONFIGITEM_KEYPAD_INACTIVITY,           /*   79 - Duration in seconds with no key entries before key buffer cleared */
  CONFIGITEM_ICIDLE_DURATION,             /*   80 - If last credential was invalid, invalid attempt counter reset after this many seconds */
  CONFIGITEM_WRITE_DECLINED_LOG,          /*   81 - Declined log writing enable/disable */
  CONFIGITEM_LOW_BATTERY_INDICATOR,       /*   82 - Low battery audio/visual indicator enable/disable */

  CONFIGITEM_PANIC_MODE,                  /*   83 - Enable/disable panic mode */

  CONFIGITEM_TIMEZONE_ENABLE,             /*   84 - Timezones enabled (applies to users, not passage modes) */
  CONFIGITEM_EXCEPTION_ENABLE,            /*   85 - Exceptions enabled (applies to users and passage modes) */
  CONFIGITEM_AUTOUNLOCK_ENABLE,           /*   86 - Auto-unlocking (schedule based) enabled */

  CONFIGITEM_LOCK_PRIORITY_EMERGENCY,     /*   87 - DPAC/PWM lock priority for emergency users (lockPriority_e) */
  CONFIGITEM_LOCK_PRIORITY_SUPERVISOR,    /*   88 - DPAC/PWM lock priority for supervisors (lockPriority_e) */
  CONFIGITEM_LOCK_PRIORITY_USER,          /*   89 - DPAC/PWM lock priority for users (lockPriority_e) */
  CONFIGITEM_LOCK_PRIORITY_PASSAGE,       /*   90 - DPAC/PWM lock priority for passage mode (lockPriority_e) */
  CONFIGITEM_LOCK_PRIORITY_PANIC,         /*   91 - DPAC/PWM lock priority for panic mode/panic users (lockPriority_e) */
  CONFIGITEM_LOCK_PRIORITY_LOCKOUT,       /*   92 - DPAC/PWM lock priority for remote unlock (lockPriority_e) */
  CONFIGITEM_LOCK_PRIORITY_RELOCK,        /*   93 - DPAC/PWM lock priority for remote unlock (lockPriority_e) */
  CONFIGITEM_LOCK_PRIORITY_BOLTTHROWN,    /*   94 - DPAC/PWM lock priority for bolt thrown (lockPriority_e) */
  CONFIGITEM_LOCK_PRIORITY_CONFIGCHANGE,  /*   95 - DPAC/PWM lock priority for configuration change (CONFIGITEM_LOCK_TYPE) (lockPriority_e) */
  CONFIGITEM_LOCK_PRIORITY_REMOTE,        /*   96 - DPAC/PWM lock priority for remote unlock (lockPriority_e) */
  CONFIGITEM_LOCK_TYPE,                   /*   97 - Type of lock (PWM, electric, magnetic) */
  CONFIGITEM_DOUBLE_PULSE,                /*   98 - Lock double pulse enabled */
  CONFIGITEM_DOUBLE_DELAY,                /*   99 - Delay between double pulses, in centiseconds */
  CONFIGITEM_MOTOR_DURATION,              /*  100 - Duration lock motor to run, in centiseconds */
  CONFIGITEM_MORTISE_TYPE,                /*  101 - Type of mortise connected to controller */
  CONFIGITEM_UNLOCK_TIME,                 /*  102 - Normal unlock duration  in seconds */
  CONFIGITEM_EXT_UNLOCK_TIME,             /*  103 - Extended unlock duration, in seconds */
  CONFIGITEM_DOOR_AJAR_TIME,              /*  104 - Time before door considered stuck open, in seconds */

  CONFIGITEM_SESSION_TIMEOUT,             /*  105 - Session timeout, in seconds */
  CONFIGITEM_RETRY_ON_TIMEOUT,            /*  106 - Retry lock-initiated sessions if comm session timed out (instead of terminated by remote end) */

  CONFIGITEM_UNSOLICITED_ENCRYPT,         /*  107 - Unsolicited messages are encrypted (encryptionScheme_e) */
  CONFIGITEM_RMT_AUTH_TIMEOUT,            /*  108 - Seconds to wait for remote authorization timeout (0 = no remote auth) */
  CONFIGITEM_RMT_AUTH_DEVICE,             /*  109 - Device remote authorization requests sent over (fromDevice_e) */
  CONFIGITEM_ALARM_DEVICE,                /*  110 - Device alarm condition connects via */
  CONFIGITEM_NOTIFY_DEVICE,               /*  111 - Notify user device */
  CONFIGITEM_COMMUSER_DEVICE,             /*  112 - Device comm user connects via */
  CONFIGITEM_SCHEDULER_DEVICE,            /*  113 - Device scheduler connects via */

  CONFIGITEM_SCHEDULER_TYPE,              /*  114 - Scheduling algorithm to use (schedulerType_e) */
  CONFIGITEM_SCHEDULER_AWAKE,             /*  115 - Number of decaseconds scheduler is awake for */
  CONFIGITEM_SCHEDULER_PERIOD,            /*  116 - Interval in minutes between scheduled wakeups (SCHEDULERTYPE_SIMPLE) */
  CONFIGITEM_SCHEDULER_HOD,               /*  117 - Hour of day map (SCHEDULERTYPE_HOD) */
  CONFIGITEM_SCHEDULER_DOW,               /*  118 - Day of month map (SCHEDULERTYPE_DOW) */
  CONFIGITEM_SCHEDULER_DOM,               /*  119 - Day of month map (SCHEDULERTYPE_DOM) */
  CONFIGITEM_SCHEDULER_HM1,               /*  120 - On at hour:minute #1 */
  CONFIGITEM_SCHEDULER_HM2,               /*  121 - On at hour:minute #2 */
  CONFIGITEM_SCHEDULER_HM3,               /*  122 - On at hour:minute #3 */
  CONFIGITEM_SCHEDULER_HM4,               /*  123 - On at hour:minute #4 */

  CONFIGITEM_RADIO_TYPE,                  /*  124 - Radio type (None, DPAC, WiPort, etc) */
  CONFIGITEM_RADIO_MODE,                  /*  125 - Radio mode (DPAC=active/passive) */
  CONFIGITEM_RADIO_TIMEOUT,               /*  126 - Number of seconds before we decide server didn't hear us (only in RADIOMODE_LOCKINITIATED) */
  CONFIGITEM_RADIO_ATTEMPTS,              /*  127 - Number of times to attempt connection to server (only in RADIOMODE_LOCKINITIATED) */
  CONFIGITEM_RADIO_HOUSEKEEPING,          /*  128 - Time we allow for radio housekeeping (associate with AP, etc) */
  CONFIGITEM_RADIO_LEAPUSERNAME,          /*  129 - LEAP username */
  CONFIGITEM_RADIO_LEAPPASSWORD,          /*  130 - LEAP password */

  CONFIGITEM_INHIBIT_VOLTAGE,             /*  131 - Voltage when battery is considered dead */
  CONFIGITEM_LOW_VOLTAGE,                 /*  132 - Voltage when battery is considered low */
  CONFIGITEM_PT_RANGE_1,                  /*  133 - Power table for 0.00 to 5.99 volts */
  CONFIGITEM_PT_RANGE_2,                  /*  134 - Power table for 6.00 to 6.49 volts */
  CONFIGITEM_PT_RANGE_3,                  /*  135 - Power table for 6.50 to 6.99 volts */
  CONFIGITEM_PT_RANGE_4,                  /*  136 - Power table for 7.00 to 7.49 volts */
  CONFIGITEM_PT_RANGE_5,                  /*  137 - Power table for 7.50 to 7.99 volts */
  CONFIGITEM_PT_RANGE_6,                  /*  138 - Power table for 8.00 to 8.49 volts */
  CONFIGITEM_PT_RANGE_7,                  /*  139 - Power table for 8.50 to 8.99 volts */
  CONFIGITEM_PT_RANGE_8,                  /*  140 - Power table for 9.00 and up volts */

  CONFIGITEM_MAGCARD_IFS,                 /*  141 - Include field separator character in returned data */
  CONFIGITEM_MAGCARD_FIELDS,              /*  142 - Mag card fields to include */
  CONFIGITEM_MAGCARD_OFFSET,              /*  143 - Offset into concatenated field */
  CONFIGITEM_MAGCARD_DIGITS,              /*  144 - Number of digits to return past offset */

  CONFIGITEM_ALARMS,                      /*  145 - Alarms (not writable) */
  CONFIGITEM_FILTERS,                     /*  146 - Event filter storage (not writable) */
  CONFIGITEM_ALARMSTATE,                  /*  147 - Current alarm state (alarmID_e) */
  CONFIGITEM_DOORSTATE,                   /*  148 - Current door state (doorState_e) */

  CONFIGITEM_DPACDEBUG,                   /*  149 - Enable DPAC debug events to event log */
  CONFIGITEM_FAILOPENSECURE,              /*  150 - Fail open (false) or secure (true) on battery dead */

  CONFIGITEM_REPLACED_VOLTAGE,            /*  151 - If battery above this voltage, it's been replaced */

  CONFIGITEM_RX_HELD_TIME,                /*  152 - If RX held longer than this, sent RX held alarm */
  CONFIGITEM_PACKET_TIMEOUT,              /*  153 - Time (in seconds) that a complete packet must arrive in */

  CONFIGITEM_EXTENDEDRESPONSE,            /*  154 - Enables extended response (which includes original sequence number) */
  CONFIGITEM_PASSAGEMODEINDICATOR,        /*  155 - When lock in passage mode, LEDs show denied if set, granted if cleared (Squish #1133) */

  CONFIGITEM_PFMRETURNTIME,               /*  156 - Number of seconds power must be present to exit power fail death loop */

  CONFIGITEM_LAST                          /*  Must be last item defined (All non-virtual items added above) */

#if 0 /* XXX: unused ? */
  ,
  CONFIGITEM_MAGIC_FIRST = 239,           /*  Next item is first magic command */
  CONFIGITEM_MAGIC_USERFIELD,             /*  240 - Virtual command to delete PIN '8989', add user '8989' */
  CONFIGITEM_MAGIC_USERADD,               /*  241 - Virtual command to add a user (PIN only) */
  CONFIGITEM_MAGIC_USERDELETE,            /*  242 - Virtual command to delete a user */
  CONFIGITEM_MAGIC_NVRAMBACKUP,           /*  243 - Virtual command to backup NVRAM to FLASH */
  CONFIGITEM_MAGIC_NVRAMRESTORE,          /*  244 - Virtual command to restore NVRAM from FLASH */
  CONFIGITEM_MAGIC_NVRAMERASE,            /*  245 - Virtual command to erase backed-up NVRAM */
  CONFIGITEM_MAGIC_LAST                   /*  *Really* the last item */
#endif
}
configItem_e;

typedef enum
{
  DELETEUSERS_ALL = 0,    /* 0 - Delete ALL users, including master and emergency, restores default users */
  DELETEUSERS_CACHED,     /* 1 - Delete only cached users */
  DELETEUSERS_LAST
}
deleteUsers_e;

typedef enum
{
  DISPOSITION_ADD = 0,    /* 0 - Add, must not exist (by user number only) */
  DISPOSITION_REPLACE,    /* 1 - Replace, (add, but overwrite if necessary) */
  DISPOSITION_UPDATE,     /* 2 - Update, must already exist */
  DISPOSITION_DELETE,     /* 3 - Delete, exists or not is irrelevant */
  DISPOSITION_RETRIEVE,   /* 4 - Retrieve, must exist */
  DISPOSITION_LAST
}
disposition_e;

#if 0
typedef enum
{
  DOORSTATE_NONE = 0,       /* 0 - No door state available */
  DOORSTATE_SECURED,        /* 1 - Door closed & secured */
  DOORSTATE_DOORFORCED,     /* 2 - Door forced */
  DOORSTATE_KEYOVERRIDE,    /* 3 - Key override */
  DOORSTATE_DOORAJAR,       /* 4 - Door ajar  */
  DOORSTATE_LAST
}
doorState_e;
#endif

#if 0
typedef enum
{
  DSTMODE_NONE,           /* 0 - Automatic DST switching disabled */
  DSTMODE_REPEATINGDOM,   /* 1 - Particular day on a particular month (Apr 2nd) */
  DSTMODE_REPEATINGDOW,   /* 2 - Day of week on a particular week of a particular month (Sunday of last week of April) */
  DSTMODE_ONETIMEDOM,     /* 3 - Like DSTMODE_REPEATINGDOM, but clears CONFIGITEM_DST_[FORWARD|BACK][MONTH|DAY] items */
  DSTMODE_ONETIMEDOW,     /* 4 - Like DSTMODE_REPEATINGDOW, but clears CONFIGITEM_DST_[FORWARD|BACK][MONTH|OOD|DOW] items */
  DSTMODE_LAST
}
dstMode_e;
#endif

typedef enum
{
  ENCRYPTIONSCHEME_NONE = 0,  /* 0 - No encryption */
  ENCRYPTIONSCHEME_ROLLING,   /* 1 - XOR with crypt key, shift each byte */
  ENCRYPTIONSCHEME_SN,        /* 2 - XOR with serial number, shift each byte */
  ENCRYPTIONSCHEME_AESIV,     /* 3 - AES implementation (set initial vector) */
  ENCRYPTIONSCHEME_AES,       /* 4 - AES implementation */
  ENCRYPTIONSCHEME_LAST
}
encryptionScheme_e;

typedef enum
{
  EVENT_INVALIDPIN = 0,       /*   0 - Entered PIN was invalid */
  EVENT_USER,                 /*   1 - Regular user has been granted access */
  EVENT_ONETIME,              /*   2 - One-time user has been granted access */
  EVENT_PASSAGEBEGIN,         /*   3 - Lock has unlocked because of auto-unlock mode */
  EVENT_PASSAGEEND,           /*   4 - Lock has relocked because of auto-unlock mode */
  EVENT_BADTIME,              /*   5 - Access attempted outside of allowed time/date */
  EVENT_LOCKEDOUT,            /*   6 - Access attempted during panic or lockout */
  EVENT_LOWBATTERY,           /*   7 - Battery is low */
  EVENT_DEADBATTERY,          /*   8 - Battery is dead */
  EVENT_BATTERYREPLACED,      /*   9 - Battery has been replaced */
  EVENT_USERADDED,            /*  10 - User added or changed */
  EVENT_USERDELETED,          /*  11 - User deleted */
  EVENT_EMERGENCY,            /*  12 - The emergency code was entered */
  EVENT_PANIC,                /*  13 - Somebody pushed the panic button */
  EVENT_RELOCK,               /*  14 - Relock code was entered */
  EVENT_LOCKOUTBEGIN,         /*  15 - Lockout code was entered */
  EVENT_LOCKOUTEND,           /*  16 - Lockout code was entered again */
  EVENT_RESET,                /*  17 - Lock was reset (restarted) */
  EVENT_DATETIMESET,          /*  18 - System date & time was set */
  EVENT_LOGCLEARED,           /*  19 - Event log cleared */
  EVENT_DBRESET,              /*  20 - User database reset */
  EVENT_COMMSTARTED,          /*  21 - Communications session started */
  EVENT_COMMENDED,            /*  22 - Communications session ended */
  EVENT_FIRMWAREABORT,        /*  23 - A firmware update aborted */
  EVENT_FIRMWAREERROR,        /*  24 - A firmware update encountered an error */
  EVENT_FIRMWARETIMEOUT,      /*  25 - Timeout expecting firmware download data record */
  EVENT_DSTFALLBACK,          /*  26 - Clock set back */
  EVENT_DSTSPRINGFORWARD,     /*  27 - Clock set forward */
  EVENT_BOLTTHROWN,           /*  28 - Bolt thrown */
  EVENT_BOLTRETRACTED,        /*  29 - Bolt retracted */
  EVENT_MASTERCODE,           /*  30 - Master code entered (clears panic, relock, and lockout) */
  EVENT_COMMUSER,             /*  31 - A comm user was activated */
  EVENT_DPACDISABLED,         /*  32 - DPAC disabled */
  EVENT_NOTIFY,               /*  33 - Notify user has been granted access */
  EVENT_EXPIRED,              /*  34 - Expired user attempted access */
  EVENT_SUPERVISOR,           /*  35 - The supervisor code was entered */
  EVENT_MCCENTER,             /*  36 - Entered MCC programming mode */
  EVENT_MCCEXIT,              /*  37 - Exited MCC programming mode */
  EVENT_SERIALRXOVERRUN,      /*  38 - Serial receiver overrun */
  EVENT_DPACRXOVERRUN,        /*  39 - DPAC receiver overrun */
  EVENT_NVRAMPBCLEAR,         /*  40 - NVRAM cleared by pushybutton */
  EVENT_NVRAMLAYOUTCHANGE,    /*  41 - NVRAM cleared by revision */
  EVENT_NVRAMOK,              /*  42 - NVRAM wasn't changed */
  EVENT_USERREPLACED,         /*  43 - User replaced */
  EVENT_RADIOTIMEOUT,         /*  44 - Radio timed out waiting for remote login */
  EVENT_SUSPENDEDUSER,        /*  45 - Suspended user attempted access */
  EVENT_USERUPDATED,          /*  46 - User updated */
  EVENT_DOORBOLTED,           /*  47 - Access denied because door is bolted */
  EVENT_PANICACTIVE,          /*  48 - Access denied because lock is in panic mode */
  EVENT_PASSAGEACTIVE,        /*  49 - Access denied because lock is in passage mode */
  EVENT_PASSAGEINACTIVE,      /*  50 - Access denied because lock is not in passage mode */
  EVENT_BADACCESSMODE,        /*  51 - Access denied because access mode is wierd */
  EVENT_CLOCKERR,             /*  52 - Error reading RTC */
  EVENT_REMOTEUNLOCK,         /*  53 - Remote unlock */
  EVENT_TZHAUDISABLED,        /*  54 - Time zone, exceptions, and auto-unlock functionality disabled */
  EVENT_EVENTLOGWRAPPED,      /*  55 - Event log wrapped */
  EVENT_DECLINEDLOGWRAPPED,   /*  56 - Declined log wrapped */
  EVENT_ALARMLOGWRAPPED,      /*  57 - Alarm log wrapped */
  EVENT_RADIOBUSYEMERGENCY,   /*  58 - Access denied because radio is busy */
  EVENT_RADIOBUSYSUPERVISOR,  /*  59 - Access denied because radio is busy */
  EVENT_RADIOBUSYONETIME,     /*  60 - Access denied because radio is busy */
  EVENT_RADIOBUSYUSER,        /*  61 - Access denied because radio is busy */
  EVENT_RADIOBUSYPANIC,       /*  62 - Access denied because radio is busy */
  EVENT_RADIOBUSYREX,         /*  63 - Access denied because radio is busy */
  EVENT_RADIOBUSYLOCKOUT,     /*  64 - Access denied because radio is busy */
  EVENT_RADIOBUSYRELOCK,      /*  65 - Access denied because radio is busy */
  EVENT_BATTERYCHECKHELDOFF,  /*  66 - Battery check was not performed (user number says why) */
  EVENT_RMTAUTHREQUEST,       /*  67 - Remote authorization request made */
  EVENT_FIRMWAREUPDATE,       /*  68 - A firmware update was attempted, and succeeded */
  EVENT_FIRMWAREUPDATEFAILED, /*  69 - A firmware update was attempted, and failed */
  EVENT_MSMFAILURE,           /*  70 - Mortise state machine failure */
  EVENT_CLOCKRESET,           /*  71 - The RTC was reset, likely due to ESD */
  EVENT_POWERFAIL,            /*  72 - Power Fail Monitor (PFM) circuit triggered */
  EVENT_DPAC501WENTSTUPID,    /*  73 - DPAC-501 failed to release CTS on power up */
  /*
   * These are all internal debugging events.  Real events should go before these.
   */
  EVENT_CHECKSUMCONFIG,       /*  74 - Performing checksum on configuration NVRAM */
  EVENT_CHECKSUMTZ,           /*  75 - Performing checksum on timezone data NVRAM */
  EVENT_DEBUG,                /*  76 - Debug event, could mean anything (programmer discretion) */
  EVENT_LAST                  /*  77 - Everything must go before this entry */
}
event_e;

typedef enum
{
  FIELDTYPE_NONE = 0,   /* 0 - Field contains nothing */
  FIELDTYPE_PIN,        /* 1 - Field contains PIN */
  FIELDTYPE_PROX,       /* 2 - Field contains Prox card */
  FIELDTYPE_MAGCARD,    /* 3 - Field contains mag card */
  FIELDTYPE_LAST
}
fieldType_e;

#if 0
typedef enum
{
  FILTERMODE_NORMAL = 0,  /* 0 - Filters events specified */
  FILTERMODE_INVERT,      /* 1 - Filters events not specified */
  FILTERMODE_LAST
}
filterMode_e;
#endif

typedef enum
{
  FILTERSELECT_RECORDING = 0,   /* 0 - Recording filters */
  FILTERSELECT_REPORTING,       /* 1 - Reporting filters */
  FILTERSELECT_LAST
}
filterSelect_e;


/* XXX: enum vals don't all match vals in comments ??? */
typedef enum
{
  FORCEITEM_RADIOPOWER = 0,   /*  0 - Radio power */
  FORCEITEM_RADIOENABLE,      /*  1 - Radio enable */
  FORCEITEM_LEDRED,           /*  2 - Red keypad LED */
  FORCEITEM_LEDGREEN,         /*  3 - Green keypad LED */
  FORCEITEM_LEDYELLOW,        /*  4 - Yellow keypad LED */
  FORCEITEM_PIEZO,            /*  5 - Keypad peizo */
  FORCEITEM_MAGPOWER,         /*  6 - Mag card reader power supply */
  FORCEITEM_MAGLEDA,          /*  7 - Mag card LED A (usually red) */
  FORCEITEM_MAGLEDB,          /*  8 - Mag card LED B (usually green) */
  FORCEITEM_PROXPOWER,        /* 13 - Prox circuitry power (opamps, etc) */
  FORCEITEM_PROXPING,         /* 14 - Prox PIC12F629 ping/sleep mode */
  FORCEITEM_PROXMODE,         /* 15 - Prox ping/read mode (selects 50hz/125KHz filters) */
  FORCEITEM_I2CPOWER,         /* 16 - I2C power */
  FORCEITEM_MOTORARUN,        /* 17 - Motor A run (to H-bridge) */
  FORCEITEM_MOTORBRUN,        /* 18 - Motor B run (to H-bridge) */
  FORCEITEM_VMON,             /* 19 - VMon (ADC 0 battery sense) */
  FORCEITEM_PROX,             /* 20 - Prox test mode (continuous 125KHz read) */
  FORCEITEM_MORTISETEST,      /* 21 - Force mortise into test mode */
  FORCEITEM_KEYPADTEST,       /* 22 - Force keypad into test mode */
  FORCEITEM_MAGTEST,          /* 23 - Force mag card test mode */
  FORCEITEM_PROXTEST,         /* 24 - Force prox card test mode */
  FORCEITEM_ICLASSPOWER,      /* 25 - iClass Prox power */
  FORCEITEM_ICLASSRESET,      /* 26 - iClass Prox reset */
  FORCEITEM_LAST
}
forceItem_e;

typedef enum
{
  FROMDEVICE_NONE = 0,      /* 0 - Used to indicate no device */
  FROMDEVICE_INTERNAL,      /* 1 - Generated internally */
  FROMDEVICE_KEYPAD,        /* 2 - Generated from keypad */
  FROMDEVICE_CONSOLE,       /* 3 - Generated from console */
  FROMDEVICE_WIFI,          /* 4 - Generated from wi-fi (DPAC) */
  FROMDEVICE_LAST
}
fromDevice_e;

#if 0
typedef enum
{
  HARDWAREOPTIONS_NONE         = 0x0000,   /* No options installed (?!) */
  HARDWAREOPTIONS_CLOCK        = 0x0001,   /* Has RTC installed (always set) */
  HARDWAREOPTIONS_CONSOLE      = 0x0002,   /* Has serial console (always set) */
  HARDWAREOPTIONS_KEYPAD       = 0x0004,   /* Has keypad installed */
  HARDWAREOPTIONS_PROXREADER   = 0x0008,   /* Has Prox card circuitry installed */
  HARDWAREOPTIONS_MAGREADER    = 0x0010,   /* Has magnetic card reader attached */
  HARDWAREOPTIONS_1WIRE        = 0x0020,   /* Has Dallas 1-wire interface installed */
  HARDWAREOPTIONS_WIFI         = 0x0040,   /* Has WiFi module installed (DPAC only, for now) */
  HARDWAREOPTIONS_RS485        = 0x0080,   /* Has RS-485 optioning (RS-232 assumed if not) */
  HARDWAREOPTIONS_IR           = 0x0100,   /* Has IR LED communications interface installed */
  HARDWAREOPTIONS_PUSHBUTTON   = 0x0200,   /* Has MCC pushbutton */
  HARDWAREOPTIONS_WATCHDOG     = 0x0400,   /* Has watchdog option compiled in */
  HARDWAREOPTIONS_ICLASSREADER = 0x0800,   /* Has iClass OEM75 prox reader installed */
  HARDWAREOPTIONS_AVAIL1000    = 0x1000,   /* Not defined */
  HARDWAREOPTIONS_AVAIL2000    = 0x2000,   /* Not defined */
  HARDWAREOPTIONS_AVAIL4000    = 0x4000,   /* Not defined */
  HARDWAREOPTIONS_AVAIL8000    = 0x8000,   /* Not defined */

  HARDWAREOPTIONS_RADIO        = (HARDWAREOPTIONS_WIFI),

  HARDWAREOPTIONS_LAST         = 0xffff    /* Place holder, don't use */
}
hardwareOptions_e;
#endif

#if 0
typedef enum
{
  LOCALLED_NONE = 0,      /*  0 - No assignment */
  LOCALLED_RADIOPOWER,    /*  1 - Follows radio power supply (lit=power on) */
  LOCALLED_LOCKUNLOCKED,  /*  2 - Follows strike state (lit=locked) */
  LOCALLED_I2CPOWER,      /*  3 - Follows I2C power (lit=power on) */
  LOCALLED_AUTHCONSOLE,   /*  4 - Follows authorization from console port (lit=authorized) */
  LOCALLED_AUTHWIFI,      /*  5 - Follows authorization from Wifi port (lit=authorized) */
  LOCALLED_BATTERYLOW,    /*  6 - Follows battery low status (lit=low) */
  LOCALLED_BATTERYDEAD,   /*  7 - Follows battery dead status (lit=battery dead) */
  LOCALLED_PROXREADY,     /*  8 - Follows Prox ready to read (lit=ready) */
  LOCALLED_APACQUIRED,    /*  9 - Follows WAP acquired via DPAC (lit=acquired) */
  LOCALLED_PASSMODE,      /* 10 - Follows DPAC entering pass mode (lit=pass mode successful) */
  LOCALLED_PROXREAD,      /* 11 - Follows receiving a prox read event (PROXCARDEVENT_READCARD) */
  LOCALLED_CONNECTED,     /* 12 - Follows the DPAC interrupt line, indicating connection status */
  LOCALLED_DPACCTSTIMER,  /* 13 - Follows DPAC CTS line, if asserted more than 5 seconds */
  LOCALLED_PFMCHARGING,   /* 14 - Follows the state of the PFM super-cap charger */
  LOCALLED_LAST
}
localLED_e;
#endif

#if 0
typedef enum
{
  LOCKPRIORITY_NONE = 0,      /* 0 - Radio is not shut down for motor run, access not denied if radio is on */
  LOCKPRIORITY_DPAC,          /* 1 - Radio is not shut down for motor run, access denied if radio is on */
  LOCKPRIORITY_LOCK,          /* 2 - Radio is shut down for motor run, access not denied if radio is on */
  LOCKPRIORITY_LAST
}
lockPriority_e;
#endif

#if 0
typedef enum
{
  LOCKTYPE_NONE = 0,          /* 0 - No lock present */
  LOCKTYPE_PWM,               /* 1 - PWM motor */
  LOCKTYPE_ELECTRIC_STRIKE,   /* 2 - Electric strike (normally de-energized, uses Motor A side of H-bridge) */
  LOCKTYPE_MAGNETIC_LOCK,     /* 3 - Magnetic lock (normally energized, uses Motor A side of H-bridge) */
  LOCKTYPE_RELAY,             /* 4 - Relay (normally de-energized, uses Motor B side of H-bridge) */
  LOCKTYPE_LAST
}
lockType_e;
#endif

typedef enum
{
  MFGFIELD_IOPINS = 0,            /*  0 - Contains data about the state of the IO pins */
  MFGFIELD_ADCS,                  /*  1 - Contains raw ADC data */
  MFGFIELD_HARDWAREID,            /*  2 - Contains hardware ID & revision of PIC */
  MFGFIELD_CHECKPOINTLOG,         /*  3 - Contains the checkpoint log data */
  MFGFIELD_CPUREGISTERS,          /*  4 - Contains the contents of selected PIC registers */
  MFGFIELD_TASKFLAGS,             /*  5 - Contains a list of all task flag values */
  MFGFIELD_TIMERCHAIN,            /*  6 - Contains a complete list of all active timers (timerData_t) */
  MFGFIELD_PEEKPOKE,              /*  7 - Contains results of peeking memory (U8, U16, U32, or string) */
  MFGFIELD_LOCKSTATE,             /*  8 - Contains the current passage mode flags (lockState_t) */
  MFGFIELD_CAPABILITIES,          /*  9 - Contains lock capability info (# users, event log entries, etc) */
  MFGFIELD_DUMPM41T81,            /* 10 - Contains a complete dump of the M41T81 RTC registers */
  MFGFIELD_NVRAMCHECKSUMVALUE,    /* 11 - Contains the 32-bit NVRAM checksum value */
  MFGFIELD_CHECKSUMRESULTS,       /* 12 - Contains results from checksumming exceptions, exceptiong roups, time zone calendars and time zones */
  MFGFIELD_MORTISESTATELOG,       /* 13 - Contains the last 32 mortise state changes */
  MFGFIELD_MORTISEPINS,           /* 14 - Contains the mortise pin status (S1,S2,S3,S4) */
  MFGFIELD_KEYPADCHAR,            /* 15 - Contains a character from the keypad */
  MFGFIELD_MAGCARD,               /* 16 - Contains mag card data */
  MFGFIELD_PROXCARD,              /* 17 - Contains prox card data */
  MFGFIELD_LAST
}
mfgField_e;

typedef enum
{
  MORTISETYPE_NONE = 0,           /*  0 - No mortise installed */
  MORTISETYPE_S82276,             /*  1 - Sargent 82276 mortise (A) */
  MORTISETYPE_S82277,             /*  2 - Sargent 82277 mortise, no cylinder (B) */
  MORTISETYPE_S82278,             /*  3 - Sargent 82278 mortise, no deadbolt (C) */
  MORTISETYPE_S82279,             /*  4 - Sargent 82279 mortise, no cylinder or deadbolt (D) */
  MORTISETYPE_S10G77,             /*  5 - Sargent 10G77 bored lock body (E) */
  MORTISETYPE_S8877,              /*  6 - Sargent 8877 mortise exit device (F) */
  MORTISETYPE_S8878,              /*  7 - Sargent 8878 mortise exit device, no cylinder (G) */
  MORTISETYPE_S8977,              /*  8 - Sargent 8977 mortise exit device (H) */
  MORTISETYPE_S8978,              /*  9 - Sargent 8978 mortise exit device, no cylinder (I) */
  MORTISETYPE_CRML20x36,          /* 10 - Corbin-Russwin ML20736/ML20836 mortise (J) */
  MORTISETYPE_CRML20x35,          /* 11 - Corbin-Russwin ML20735/ML20835 mortise, no cylinder (K) */
  MORTISETYPE_CRML20x34,          /* 12 - Corbin-Russwin ML20734/ML20834 mortise, no deadbolt (L) */
  MORTISETYPE_CRML20x33,          /* 13 - Corbin-Russwin ML20733/ML20833 mortise, no cylinder or deadbolt (M) */
  MORTISETYPE_CRCL33x34,          /* 14 - Corbin-Russwin CL33734/CL33834 bored lock body (N) */
  MORTISETYPE_CR9X34,             /* 15 - Corbin-Russwin 9734/9834 bored lock body (O) */
  MORTISETYPE_CR9X33,             /* 16 - Corbin-Russwin 9833/9833 bored lock body, no cylinder (P) */
  MORTISETYPE_CR9MX34,            /* 17 - Corbin-Russwin 9M734/9M834 bored lock body (Q) */
  MORTISETYPE_CR9MX33,            /* 18 - Corbin-Russwin 9M733/9M833 bored lock body, no cylinder (R) */
  MORTISETYPE_LAST
}
mortiseType_e;

#if 0
typedef enum
{
  NVRAMCLEAROPTIONS_NONE            = 0x0000,   /* Place holder */
  NVRAMCLEAROPTIONS_CFGINSTALLER    = 0x0001,   /* Options settable by the installer (lock type, etc) */
  NVRAMCLEAROPTIONS_CFGADMIN        = 0x0002,   /* Options settable by the lock administrator (time, date, etc) */
  NVRAMCLEAROPTIONS_EXCEPTIONS      = 0x0004,   /* The exceptions definitions */
  NVRAMCLEAROPTIONS_EXCEPTIONGROUPS = 0x0008,   /* The exception group definitions */
  NVRAMCLEAROPTIONS_CALENDARS       = 0x0010,   /* The timezones calendar definitions */
  NVRAMCLEAROPTIONS_TIMEZONES       = 0x0020,   /* The timezones definitions */
  NVRAMCLEAROPTIONS_FILTERS         = 0x0040,   /* Recording filters */
  NVRAMCLEAROPTIONS_EVENTLOG        = 0x0080,   /* The event log */
  NVRAMCLEAROPTIONS_USERDATA        = 0x0100,   /* The actual user database */
  NVRAMCLEAROPTIONS_DECLINEDLOG     = 0x0200,   /* Declined credentials log */
  NVRAMCLEAROPTIONS_ALARMLOG        = 0x0400,   /* Alarm log */
  NVRAMCLEAROPTIONS_LRUCACHE        = 0x0800,   /* LRU cache for remote authorization (status, user doesn't clear explicitly) */
  NVRAMCLEAROPTIONS_DBHASH          = 0x1000,   /* User database hash (status, user doesn't clear explicitly) */
  NVRAMCLEAROPTIONS_CFGSYSTEM       = 0x2000,   /* Factory settable options, system variables (status, user doesn't clear explicitly) */
  NVRAMCLEAROPTIONS_AVAIL4000       = 0x4000,   /* Unused */
  NVRAMCLEAROPTIONS_ALL             = 0x7fff,   /* All of the above */
  NVRAMCLEAROPTIONS_USEBACKUP       = 0x8000    /* If set, installer and admin options are set according from NVRAM backup (if valid) */
}
nvramClearOptions_e;
#endif

#if 0
typedef enum
{
  NVRAMCOMMAND_BACKUP = 0,  /* 0 - Backup NVRAM to backup region */
  NVRAMCOMMAND_ERASE,       /* 1 - Erase backup region */
  NVRAMCOMMAND_RESTORE,     /* 2 - Restore NVRAM from backup region */
  NVRAMCOMMAND_LAST
}
nvramCommand_e;
#endif

#if 0
typedef enum
{
  NVRAMDUMPSELECT_ALL = 0,  /* 0 - Dump all */
  NVRAMDUMPSELECT_PIC,      /* 1 - Dump NVRAM on PIC */
  NVRAMDUMPSELECT_USER,     /* 2 - Dump I2C NVRAM containing user data, exceptions, exception groups, calendars, timezones */
  NVRAMDUMPSELECT_EVENT,    /* 3 - Dump I2C NVRAM containing event log, declined log, alarm log, LRU cache */
  NVRAMDUMPSELECT_LAST
}
nvramDumpSelect_e;
#endif

typedef enum
{
  PEEKPOKE_READU8 = 0,      /* 0 - Read 8 bit value */
  PEEKPOKE_READU16,         /* 1 - Read 16 bit value */
  PEEKPOKE_READU24,         /* 2 - Read 24 bit value */
  PEEKPOKE_READU32,         /* 3 - Read 32 bit value */
  PEEKPOKE_READSTRING,      /* 4 - Read 'n' 8 bit values */
  PEEKPOKE_WRITEU8,         /* 5 - Write 8 bit value */
  PEEKPOKE_WRITEU16,        /* 6 - Write 16 bit value */
  PEEKPOKE_WRITEU24,        /* 7 - Write 24 bit value */
  PEEKPOKE_WRITEU32,        /* 8 - Write 32 bit value */
  PEEKPOKE_WRITESTRING,     /* 9 - Write 'n' 8 bit values */
  PEEKPOKE_LAST
}
peekPoke_e;

typedef enum
{
  PPMISOURCE_NONE = 0,     /* 0 - PPMI came from nowhere (not set) */
  PPMISOURCE_PIN,          /* 1 - PPMI came from PIN */
  PPMISOURCE_PROX,         /* 2 - PPMI came from Prox */
  PPMISOURCE_MAGCARD,      /* 3 - PPMI came from mag card */
  PPMISOURCE_LAST
}
ppmiSource_e;

#if 0
typedef enum
{
  RADIOMODE_HOSTINITIATED = 0,  /* 0 - DPAC in listen mode (default) */
  RADIOMODE_LOCKINITIATED,      /* 1 - DPAC in pass-through mode */
  RADIOMODE_LAST
}
radioMode_e;
#endif

#if 0
typedef enum
{
  RADIOTYPE_NONE = 0,     /* 0 - No radio present */
  RADIOTYPE_WIPORTNR,     /* 1 - WiPortNR */
  RADIOTYPE_DPAC80211B,   /* 2 - DPAC 802.11b */
  RADIOTYPE_DPAC80211BG,  /* 3 - DPAC 802.11bg */
  RADIOTYPE_LAST
}
radioType_e;
#endif

typedef enum
{
  RESPONSETYPE_OK = 0,                /*  0 - All is well */
  RESPONSETYPE_ERROR,                 /*  1 - Generic error */
  RESPONSETYPE_HASDATA,               /*  2 - Response has data */
  RESPONSETYPE_NOHANDLER,             /*  3 - Command requested with no handler (internal error) */
  RESPONSETYPE_NOSESSION,             /*  4 - No session established */
  RESPONSETYPE_BADCOMMAND,            /*  5 - Bad command value */
  RESPONSETYPE_BADPARAMETER,          /*  6 - Bad parameter (can mean a lot of things) */
  RESPONSETYPE_BADPARAMETERLEN,       /*  7 - Bad parameter length (too short, too long) */
  RESPONSETYPE_MISSINGPARAMETER,      /*  8 - Missing parameter (something was required, what'd you forget?) */
  RESPONSETYPE_DUPLICATEPARAMETER,    /*  9 - Parameter supplied more than once (D'oh!) */
  RESPONSETYPE_PARAMETERCONFLICT,     /* 10 - Parameters conflict (usually mutually exclusive items) */
  RESPONSETYPE_BADDEVICE,             /* 11 - Bad device (command came from a device that's not allowed) */
  RESPONSETYPE_NVRAMERROR,            /* 12 - Hardware problem... */
  RESPONSETYPE_NVRAMERRORNOACK,       /* 13 - Hardware problem... */
  RESPONSETYPE_NVRAMERRORNOACK32,     /* 14 - Hardware problem... */
  RESPONSETYPE_NOTI2CADDRESS,         /* 15 - Illegal I2C address in i2cStart */
  RESPONSETYPE_FIRMWAREERROR,         /* 16 - Generic firmware upload error (can mean lots of things) */
  RESPONSETYPE_DUMPINPROGRESS,        /* 17 - Can't do something, a dump is in progress */
  RESPONSETYPE_INTERNALERROR,         /* 18 - Something Bad Happened(tm) */
  RESPONSETYPE_NOTIMPLEMENTED,        /* 19 - Command or function not implemented */
  RESPONSETYPE_PINFORMATERROR,        /* 20 - Error in formatting of PIN (non hex character) */
  RESPONSETYPE_PINEXISTS,             /* 21 - PIN already exists in database */
  RESPONSETYPE_PINNOTFOUND,           /* 22 - PIN wasn't found (actionManageUsers) */
  RESPONSETYPE_USERACTIVE,            /* 23 - The record for this user is active (not deleted or free) */
  RESPONSETYPE_USERINACTIVE,          /* 24 - The record for this user is inactive (not in use) */
  RESPONSETYPE_PARENTNOTFOUND,        /* 25 - Users parent couldn't be found (used internally by dbmgr.c) */
  RESPONSETYPE_NOCHAIN,               /* 26 - No users in chain (used internally by dbmgr.c) */
  RESPONSETYPE_CAUGHTINLOOP,          /* 27 - Caught in a loop somewhere */
  RESPONSETYPE_EVENTFILTERED,         /* 28 - Event record was filtered (eventlog.c) */
  RESPONSETYPE_PAYLOADTOOLARGE,       /* 29 - Message payload too large (protocol.c) */
  RESPONSETYPE_ENDOFDATA,             /* 30 - No more data (used internally by eventlog.c) */
  RESPONSETYPE_RMTAUTHREJECTED,       /* 31 - Remote authorization rejected (lockmgr.c) */
  RESPONSETYPE_NVRAMVERSIONERROR,     /* 32 - NVRAM version doesn't match expected value */
  RESPONSETYPE_NOHARDWARE,            /* 33 - Operation requested for unsupported hardware */
  RESPONSETYPE_SCHEDULERCONFLICT,     /* 34 - Scheduler not in correct mode for this operation */
  RESPONSETYPE_NVRAMWRITEERROR,       /* 35 - NVRAM write compare error */
  RESPONSETYPE_DECLINEDFILTERED,      /* 36 - Declined record was filtered (declinedlog.c) */
  RESPONSETYPE_NECONFIGPARM,          /* 37 - Non-existent configuration parameter */
  RESPONSETYPE_FLASHERASEERROR,       /* 38 - Error erasing FLASH */
  RESPONSETYPE_FLASHWRITEERROR,       /* 39 - Error writing FLASH */
  RESPONSETYPE_BADNVBACKUP,           /* 40 - NVBackup length doesn't match sizeof (configParametersNV_t) */
  RESPONSETYPE_EARLYACK,              /* 41 - Sent prior to long commands if CONFIGITEM_EARLYACK set */
  RESPONSETYPE_ALARMFILTERED,         /* 42 - Alarm record was filtered (alarm.c) */
  RESPONSETYPE_ACVFAILURE,            /* 43 - Auxiliary controller version request failure */
  RESPONSETYPE_USERCHECKSUMERROR,     /* 44 - User checksum value error */
  RESPONSETYPE_CHECKSUMERROR,         /* 45 - Generic checksum error  */
  RESPONSETYPE_RTCSQWFAILURE,         /* 46 - RTC isn't generating square wave */
  RESPONSETYPE_PRIORITYSHUTDOWN,      /* 47 - Session terminated early because lock has priority over communications */
  RESPONSETYPE_NOTMODIFIABLE,         /* 48 - Configuration parameter is not user modifiable */
  RESPONSETYPE_CANTPRESERVE,          /* 49 - Can't preserve configuration (config.c, not enough space) */
  RESPONSETYPE_INPASSAGEMODE,         /* 50 - Lock is in passage mode, can't do remote unlock */
  RESPONSETYPE_LAST
#if 0
  ,
  /*
   *  These should not be exposed to the user
   */
  RESPONSETYPE_NOREPLY,               /* 51 - Do not send a reply, subroutine is posting it's own */
  RESPONSETYPE_TAKEABREAK,            /* 52 - Intermediate return result, when log searches taking too long */
  RESPONSETYPE_DPACBLOCKS,            /* 53 - PWM lock, battery powered, DPAC takes priority */
  RESPONSETYPE_ACKNAKTIMEOUT,         /* 54 - Added for console.c, not used in lock firmware */
  RESPONSETYPE_UNKNOWNCPUSPEED        /* 55 - Unknown CPU speed (utils.c, utilCalculateClockRate()) */
#endif
}
responseType_e;

#if 0
typedef enum
{
  SCHEDULERTYPE_HARDON = 0,   /* 0 - Radio is always on */
  SCHEDULERTYPE_SIMPLE,       /* 1 - Simple 'x' minutes off, 'y' seconds on scheduler */
  SCHEDULERTYPE_DOM,          /* 2 - Day of month scheduling  */
  SCHEDULERTYPE_DOW,          /* 3 - Day of week scheduling  */
  SCHEDULERTYPE_COMMUSER,     /* 4 - Only a comm user triggers power on */
  SCHEDULERTYPE_HOD,          /* 5 - Hour of day scheduling */
  SCHEDULERTYPE_OFF,          /* 6 - Nothing wakes up radio */
  SCHEDULERTYPE_LAST
}
schedulerType_e;
#endif

typedef enum
{
  TIMEZONEMODE_NORMAL = 0,  /* 0 - Timezone is applied to user, no auto unlocking */
  TIMEZONEMODE_EXCLUSION,   /* 1 - User NOT permitted access if in this zone at this time */
  TIMEZONEMODE_AUTOTIME,    /* 2 - Auto unlock at the start of the TZ, lock at end */
  TIMEZONEMODE_AUTOFPT,     /* 3 - Unlock on first person through, lock at end */
  TIMEZONEMODE_UAPM,        /* 4 - Permits user activated passage mode when active */
  TIMEZONEMODE_LAST
}
timeZoneMode_e;

#if 0
typedef enum
{
  UNLOCKMODE_NORMAL = 0,  /* 0 - Normal unlock (CONFIGITEM_UNLOCK_TIME duration) */
  UNLOCKMODE_UNLOCK,      /* 1 - Unlock, switching to passage mode */
  UNLOCKMODE_LOCK,        /* 2 - Lock, regardless of mode */
  UNLOCKMODE_LAST
}
unlockMode_e;
#endif

/* XXX: enum vals don't all match vals in comments ??? */
typedef enum
{
  UPSTREAMCOMMAND_RESERVED = 0,       /*  0 - Not used */
  UPSTREAMCOMMAND_DEBUGMSG,           /*  1 - Debug message (zero terminated) */
  UPSTREAMCOMMAND_QUERYVERSION,       /*  2 - Version string (zero terminated) */
  UPSTREAMCOMMAND_QUERYDATETIME,      /*  3 - Current date/time */
  UPSTREAMCOMMAND_QUERYSERIALNUMBER,  /*  5 - Serial number (MAX_SERIALNUM_LENGTH bytes) */
  UPSTREAMCOMMAND_DUMPEVENTLOG,       /*  6 - Event log record */
  UPSTREAMCOMMAND_DUMPNVRAM,          /*  7 - NVRAM dump record */
  UPSTREAMCOMMAND_RMTAUTHREQUEST,     /*  8 - Remote authorization request */
  UPSTREAMCOMMAND_RETRIEVEUSER,       /*  9 - Retrieve user record */
  UPSTREAMCOMMAND_QUERYCONFIG,        /* 10 - Query configuration */
  UPSTREAMCOMMAND_RMTEVENTLOGRECORD,  /* 11 - Remote event log record */
  UPSTREAMCOMMAND_DPAC,               /* 12 - DPAC related message */
  UPSTREAMCOMMAND_NOTIFY,             /* 14 - Notify user message */
  UPSTREAMCOMMAND_MFG,                /* 15 - Manufacturing data */
  UPSTREAMCOMMAND_EVENTLOGWARNING,    /* 16 - Event log warning level message */
  UPSTREAMCOMMAND_DUMPNVRAMRLE,       /* 17 - Run Length Encoded (RLE) NVRAM dump record */
  UPSTREAMCOMMAND_RMTDECLINEDRECORD,  /* 18 - Remote declined log record */
  UPSTREAMCOMMAND_DECLINEDWARNING,    /* 19 - Declined log warning level message */
  UPSTREAMCOMMAND_DUMPDECLINEDLOG,    /* 20 - Declined log record dump */
  UPSTREAMCOMMAND_RMTALARMRECORD,     /* 21 - Remote alarm log record */
  UPSTREAMCOMMAND_ALARMWARNING,       /* 22 - Alarm log warning level message */
  UPSTREAMCOMMAND_DUMPALARMLOG,       /* 23 - Alarm log record dump */
  UPSTREAMCOMMAND_CONNECTSCHEDULER,   /* 24 - Connection because of scheduler, contains serial number */
  UPSTREAMCOMMAND_CONNECTCOMMUSER,    /* 25 - Connection because of comm user, contains serial number */
  UPSTREAMCOMMAND_CONNECTALARM,       /* 26 - Connection because of alarm event, contains serial number */
  UPSTREAMCOMMAND_DUMPDEBUGLOG,       /* 27 - Debug log dump record */
  UPSTREAMCOMMAND_LAST
}
upstreamCommand_e;

/* XXX: enum vals don't all match vals in comments ??? */
typedef enum
{
  UPSTREAMFIELD_NOTUSED = 0,          /*  0 - Not used */
  UPSTREAMFIELD_SERIALNUMBER,         /*  1 - Contains unit serial number */
  UPSTREAMFIELD_NAR,                  /*  2 - Contains 16 bit Next Available Record */
  UPSTREAMFIELD_ENTRYDEVICE,          /*  3 - Contains a ppmSource_e */
  UPSTREAMFIELD_PPMIFIELDTYPE,        /*  4 - Contains a type of _PIN (auxFieldType_e) */
  UPSTREAMFIELD_PIN,                  /*  5 - Contains a PIN, Prox, mag key  */
  UPSTREAMFIELD_SEQUENCENUMBER,       /*  6 - Contains 16 bit sequence number */
  UPSTREAMFIELD_RESPONSEWINDOW,       /*  7 - Contains 8 bit response window (number of seconds) */
  UPSTREAMFIELD_USERNUMBER,           /*  8 - Contains 16 bit user number */
  UPSTREAMFIELD_VERSION,              /*  9 - Contains version string */
  UPSTREAMFIELD_EVENTLOGRECORD,       /* 10 - Contains eventLog_e event log record */
  UPSTREAMFIELD_DATETIME,             /* 11 - Contains 8 byte date/time data */
  UPSTREAMFIELD_EVENTLOGRECORDCOUNT,  /* 17 - Contains number of event log records */
  UPSTREAMFIELD_DECLINEDRECORDCOUNT,  /* 20 - Contains number of declined log records */
  UPSTREAMFIELD_DECLINEDRECORD,       /* 21 - Contains declinedLog_t declined log record */
  UPSTREAMFIELD_USERTYPE,             /* 23 - Contains the user type (master, emergency, normal, etc) */
  UPSTREAMFIELD_ACCESSALWAYS,         /* 24 - Contains the access always mode (true, false) */
  UPSTREAMFIELD_CACHED,               /* 25 - Contains the cached flag (true, false) */
  UPSTREAMFIELD_PRIMARYFIELDTYPE,     /* 26 - Contains the primary field type (pin, prox, mag) */
  UPSTREAMFIELD_AUXFIELDTYPE,         /* 27 - Contains the aux field type (pin, prox, mag) */
  UPSTREAMFIELD_ACCESSMODE,           /* 28 - Contains the access mode (aux only, aux + pin, aux or pin, etc) */
  UPSTREAMFIELD_EXPIREON,             /* 29 - Contains the date the user expires on (00/00/00 if not set) */
  UPSTREAMFIELD_USECOUNT,             /* 30 - Contains the use count (if user type is ONE_TIME) */
  UPSTREAMFIELD_TIMEZONE,             /* 31 - Contains the timezone bit map */
  UPSTREAMFIELD_EXCEPTIONGROUP,       /* 32 - Contains the exception group */
  UPSTREAMFIELD_PRIMARYPIN,           /* 33 - Contains the primary PPMI (ASCII, 0 terminated) */
  UPSTREAMFIELD_AUXPIN,               /* 34 - Contains the aux PPMI (ASCII, 0 terminated) */
  UPSTREAMFIELD_ALARMRECORDCOUNT,     /* 35 - Contains number of alarm log records */
  UPSTREAMFIELD_ALARMRECORD,          /* 36 - Contains alarmLog_t alarm log record */
  UPSTREAMFIELD_AUXCTLRVERSION,       /* 37 - Contains the version number of the auxiliary controller */
  UPSTREAMFIELD_LAST
}
upstreamField_e;

typedef enum
{
  USERTYPE_NONE = 0,    /*  0 - No user */
  USERTYPE_MASTER,      /*  1 - Master user (clears panic, relock, lockout and auto open) */
  USERTYPE_EMERGENCY,   /*  2 - Opens door regardless of state */
  USERTYPE_SUPERVISOR,  /*  3 - Like emergency user, except won't unlock when in panic mode */
  USERTYPE_USER,        /*  4 - Generic user */
  USERTYPE_EXTENDED,    /*  5 - Same as _USER, but strike can be kept open longer */
  USERTYPE_PASSAGE,     /*  6 - Toggles strike between passage and non-passage modes */
  USERTYPE_ONETIME,     /*  7 - User may be used one time */
  USERTYPE_PANIC,       /*  8 - Locks down locks, no user except master valid */
  USERTYPE_LOCKOUT,     /*  9 - Locks out regular, extended, passage, one time, and notify users */
  USERTYPE_RELOCK,      /* 10 - Relock cancels passage mode, but can't unlock */
  USERTYPE_NOTIFY,      /* 11 - Same as _USER, only sends unsolicited message to server */
  USERTYPE_COMM,        /* 12 - Kicks a communications sessions off if not running _HARDON scheduler */
  USERTYPE_SUSPENDED,   /* 13 - User is suspended */
  USERTYPE_LAST
}
userType_e;


/*
 *  Wireshark ID of the R3 protocol
 */
static gint proto_r3 = -1;

/*
 *  Packet variables
 */
static gint hf_r3_tildex3ds = -1;           /* Got ~~~ds */

static gint hf_r3_header = -1;              /* Packet header */
static gint hf_r3_payload = -1;             /* Packet payload */
static gint hf_r3_tail = -1;                /* Packet tail */

static gint hf_r3_sigil = -1;               /* Packet sigil */
static gint hf_r3_address = -1;             /* Packet address */
static gint hf_r3_packetnumber = -1;        /* Packet number */
static gint hf_r3_packetlength = -1;        /* Packet length */
static gint hf_r3_encryption = -1;          /* Packet encryption scheme */
static gint hf_r3_crc = -1;                 /* Packet CRC */
static gint hf_r3_crc_bad = -1;             /* Packet CRC bad (for filtering) */
static gint hf_r3_xor = -1;                 /* Packet Xor */
static gint hf_r3_xor_bad = -1;             /* Packet Xor bad (for filtering) */

static gint hf_r3_commandlength = -1;       /* Command length */
static gint hf_r3_command = -1;             /* Command (cmdCommand_e) */
static gint hf_r3_commanddata = -1;         /* Command data (not always present) */

static gint hf_r3_commandmfglength = -1;    /* Mfg Command length */
static gint hf_r3_commandmfg = -1;          /* Mfg Command (cmdCommand_e) */
/*static gint hf_r3_commandmfgdata = -1;*/    /* Mfg Command data (not always present) */

static gint hf_r3_responselength = -1;      /* Response length */
static gint hf_r3_responsecommand = -1;     /* Response command */
static gint hf_r3_responsetype = -1;        /* Response type (responseType_e) */
static gint hf_r3_responsetocommand = -1;   /* Response to command (cmdCommand_e) */
/*static gint hf_r3_responsedata = -1;*/       /* Response data (not always present) */

static gint hf_r3_upstreamcommand = -1;

static gint hf_r3_upstreamfield = -1;       /* Upstream field (length + type + data) */
static gint hf_r3_upstreamfieldlength = -1; /* Upstream field length */
static gint hf_r3_upstreamfieldtype = -1;   /* Upstream field type (upstreamField_e) */
/*static gint hf_r3_upstreamfielddatalen = -1;*/         /* Upstream field data length */
static gint hf_r3_upstreamfielderror = -1;  /* Upstream field is unknown type */
static gint hf_r3_upstreamfieldarray[UPSTREAMFIELD_LAST];

static gint hf_r3_configitems = -1;
static gint hf_r3_configitem = -1;
/*static gint hf_r3_configfield = -1;*/
static gint hf_r3_configitemlength = -1;
static gint hf_r3_configitemtype = -1;
static gint hf_r3_configitemdata = -1;
static gint hf_r3_configitemdata_bool = -1;
static gint hf_r3_configitemdata_8 = -1;
static gint hf_r3_configitemdata_16 = -1;
static gint hf_r3_configitemdata_32 = -1;
static gint hf_r3_configitemdata_string = -1;

static gint hf_r3_timezonearray [32];

static gint hf_r3_expireon_year = -1;
static gint hf_r3_expireon_month = -1;
static gint hf_r3_expireon_day = -1;

static gint hf_r3_datetime_year = -1;
static gint hf_r3_datetime_month = -1;
static gint hf_r3_datetime_day = -1;
static gint hf_r3_datetime_dow = -1;
static gint hf_r3_datetime_hours = -1;
static gint hf_r3_datetime_minutes = -1;
static gint hf_r3_datetime_seconds = -1;
static gint hf_r3_datetime_dst = -1;

static gint hf_r3_eventlog_recordnumber = -1;
static gint hf_r3_eventlog_year = -1;
static gint hf_r3_eventlog_month = -1;
static gint hf_r3_eventlog_day = -1;
static gint hf_r3_eventlog_hour = -1;
static gint hf_r3_eventlog_minute = -1;
static gint hf_r3_eventlog_second = -1;
static gint hf_r3_eventlog_usernumber = -1;
static gint hf_r3_eventlog_event = -1;

static gint hf_r3_declinedlog_recordnumber = -1;
static gint hf_r3_declinedlog_year = -1;
static gint hf_r3_declinedlog_month = -1;
static gint hf_r3_declinedlog_day = -1;
static gint hf_r3_declinedlog_hour = -1;
static gint hf_r3_declinedlog_minute = -1;
static gint hf_r3_declinedlog_second = -1;
static gint hf_r3_declinedlog_usernumber = -1;
static gint hf_r3_declinedlog_cred1type = -1;
static gint hf_r3_declinedlog_cred2type = -1;
static gint hf_r3_declinedlog_cred1 = -1;
static gint hf_r3_declinedlog_cred2 = -1;

static gint hf_r3_alarmlog_recordnumber = -1;
static gint hf_r3_alarmlog_year = -1;
static gint hf_r3_alarmlog_month = -1;
static gint hf_r3_alarmlog_day = -1;
static gint hf_r3_alarmlog_hour = -1;
static gint hf_r3_alarmlog_minute = -1;
static gint hf_r3_alarmlog_second = -1;
static gint hf_r3_alarmlog_id = -1;
static gint hf_r3_alarmlog_usernumber = -1;

static gint hf_r3_debugmsg = -1;

static gint hf_r3_setdate_year = -1;
static gint hf_r3_setdate_month = -1;
static gint hf_r3_setdate_day = -1;
static gint hf_r3_setdate_dow = -1;
static gint hf_r3_setdate_hours = -1;
static gint hf_r3_setdate_minutes = -1;
static gint hf_r3_setdate_seconds = -1;

static gint hf_r3_deleteusers = -1;

static gint hf_r3_defineexception_number = -1;
static gint hf_r3_defineexception_startdate_month = -1;
static gint hf_r3_defineexception_startdate_day = -1;
static gint hf_r3_defineexception_startdate_hours = -1;
static gint hf_r3_defineexception_startdate_minutes = -1;
static gint hf_r3_defineexception_enddate_month = -1;
static gint hf_r3_defineexception_enddate_day = -1;
static gint hf_r3_defineexception_enddate_hours = -1;
static gint hf_r3_defineexception_enddate_minutes = -1;

static gint hf_r3_defineexceptiongroup_number = -1;
static gint hf_r3_defineexceptiongroup_bits = -1;

static gint hf_r3_definecalendar_number = -1;
static gint hf_r3_definecalendar_bits = -1;

static gint hf_r3_definetimezone_number = -1;
static gint hf_r3_definetimezone_starttime_hours = -1;
static gint hf_r3_definetimezone_starttime_minutes = -1;
static gint hf_r3_definetimezone_endtime_hours = -1;
static gint hf_r3_definetimezone_endtime_minutes = -1;
static gint hf_r3_definetimezone_daymap [7];
static gint hf_r3_definetimezone_exceptiongroup = -1;
static gint hf_r3_definetimezone_mode = -1;
static gint hf_r3_definetimezone_calendar = -1;

static gint hf_r3_rmtauthretry_sequence = -1;
static gint hf_r3_rmtauthretry_retry = -1;

static gint hf_r3_eventlogdump_starttime_year = -1;
static gint hf_r3_eventlogdump_starttime_month = -1;
static gint hf_r3_eventlogdump_starttime_day = -1;
static gint hf_r3_eventlogdump_starttime_hours = -1;
static gint hf_r3_eventlogdump_starttime_minutes = -1;
static gint hf_r3_eventlogdump_endtime_year = -1;
static gint hf_r3_eventlogdump_endtime_month = -1;
static gint hf_r3_eventlogdump_endtime_day = -1;
static gint hf_r3_eventlogdump_endtime_hours = -1;
static gint hf_r3_eventlogdump_endtime_minutes = -1;
static gint hf_r3_eventlogdump_user = -1;

static gint hf_r3_declinedlogdump_starttime_year = -1;
static gint hf_r3_declinedlogdump_starttime_month = -1;
static gint hf_r3_declinedlogdump_starttime_day = -1;
static gint hf_r3_declinedlogdump_starttime_hours = -1;
static gint hf_r3_declinedlogdump_starttime_minutes = -1;
static gint hf_r3_declinedlogdump_endtime_year = -1;
static gint hf_r3_declinedlogdump_endtime_month = -1;
static gint hf_r3_declinedlogdump_endtime_day = -1;
static gint hf_r3_declinedlogdump_endtime_hours = -1;
static gint hf_r3_declinedlogdump_endtime_minutes = -1;

static gint hf_r3_alarmlogdump_starttime_year = -1;
static gint hf_r3_alarmlogdump_starttime_month = -1;
static gint hf_r3_alarmlogdump_starttime_day = -1;
static gint hf_r3_alarmlogdump_starttime_hours = -1;
static gint hf_r3_alarmlogdump_starttime_minutes = -1;
static gint hf_r3_alarmlogdump_endtime_year = -1;
static gint hf_r3_alarmlogdump_endtime_month = -1;
static gint hf_r3_alarmlogdump_endtime_day = -1;
static gint hf_r3_alarmlogdump_endtime_hours = -1;
static gint hf_r3_alarmlogdump_endtime_minutes = -1;

static gint hf_r3_nvramclearoptions [16];

static gint hf_r3_writeeventlog_user = -1;
static gint hf_r3_writeeventlog_event = -1;

static gint hf_r3_powertableselection = -1;

static gint hf_r3_filter_type = -1;
static gint hf_r3_filter_list = -1;

static gint hf_r3_alarm_length = -1;
static gint hf_r3_alarm_id = -1;
static gint hf_r3_alarm_state = -1;

static gint hf_r3_dpac_action = -1;
static gint hf_r3_dpac_waittime = -1;
static gint hf_r3_dpac_command = -1;

static gint hf_r3_dpacreply_stuff = -1;
static gint hf_r3_dpacreply_length = -1;
static gint hf_r3_dpacreply_reply = -1;

static gint hf_r3_mfgfield_length = -1;
static gint hf_r3_mfgfield = -1;
/*static gint hf_r3_mfgfield_data = -1;*/

static gint hf_r3_mfgsetserialnumber = -1;
static gint hf_r3_mfgsetcryptkey = -1;
static gint hf_r3_mfgdumpnvram = -1;
static gint hf_r3_mfgremoteunlock = -1;
static gint hf_r3_mfgtestpreserve = -1;

static gint hf_r3_adc [8];

static gint hf_r3_hardwareid_board = -1;
static gint hf_r3_hardwareid_cpuid = -1;
static gint hf_r3_hardwareid_cpurev = -1;

static gint hf_r3_testkeypad = -1;
static gint hf_r3_testmagcard = -1;
static gint hf_r3_testproxcard = -1;

static gint hf_r3_nvramdump_record = -1;
static gint hf_r3_nvramdump_length = -1;
static gint hf_r3_nvramdump_data = -1;

static gint hf_r3_nvramdumprle_record = -1;
static gint hf_r3_nvramdumprle_length = -1;
static gint hf_r3_nvramdumprle_data = -1;

static gint hf_r3_iopins_lat = -1;
static gint hf_r3_iopins_port = -1;
static gint hf_r3_iopins_tris = -1;

static gint hf_r3_mortisepins_s1 = -1;
static gint hf_r3_mortisepins_s2 = -1;
static gint hf_r3_mortisepins_s3 = -1;
static gint hf_r3_mortisepins_s4 = -1;

static gint hf_r3_checksumresults = -1;
static gint hf_r3_checksumresults_field = -1;
static gint hf_r3_checksumresults_length = -1;
static gint hf_r3_checksumresults_state = -1;

static gint hf_r3_forceoptions_length = -1;
static gint hf_r3_forceoptions_item = -1;
static gint hf_r3_forceoptions_state_8= -1;
static gint hf_r3_forceoptions_state_16 = -1;
static gint hf_r3_forceoptions_state_24 = -1;
static gint hf_r3_forceoptions_state_32 = -1;

static gint hf_r3_peekpoke_operation = -1;
static gint hf_r3_peekpoke_address = -1;
static gint hf_r3_peekpoke_length = -1;
static gint hf_r3_peekpoke_poke8 = -1;
static gint hf_r3_peekpoke_poke16 = -1;
static gint hf_r3_peekpoke_poke24 = -1;
static gint hf_r3_peekpoke_poke32 = -1;
static gint hf_r3_peekpoke_pokestring = -1;

static gint hf_r3_firmwaredownload_length = -1;
static gint hf_r3_firmwaredownload_record = -1;
static gint hf_r3_firmwaredownload_action = -1;
static gint hf_r3_firmwaredownload_timeout = -1;
static gint hf_r3_firmwaredownload_nvram = -1;
static gint hf_r3_firmwaredownload_address = -1;
static gint hf_r3_firmwaredownload_bytes = -1;
static gint hf_r3_firmwaredownload_data = -1;
static gint hf_r3_firmwaredownload_crc = -1;
static gint hf_r3_firmwaredownload_crc_bad = -1;

static gint hf_r3_nvramchecksumvalue = -1;
static gint hf_r3_nvramchecksumvalue_fixup = -1;

static gint hf_r3_capabilities = -1;
static gint hf_r3_capabilities_length = -1;
static gint hf_r3_capabilities_type = -1;
static gint hf_r3_capabilities_value = -1;

static gint hf_r3_lockstate_passage = -1;
static gint hf_r3_lockstate_panic = -1;
static gint hf_r3_lockstate_lockout = -1;
static gint hf_r3_lockstate_relock = -1;
static gint hf_r3_lockstate_autoopen = -1;
static gint hf_r3_lockstate_nextauto = -1;
static gint hf_r3_lockstate_lockstate = -1;
static gint hf_r3_lockstate_wantstate = -1;
static gint hf_r3_lockstate_remote = -1;
static gint hf_r3_lockstate_update = -1;
static gint hf_r3_lockstate_exceptionspresent = -1;
static gint hf_r3_lockstate_exceptionsactive = -1;
static gint hf_r3_lockstate_timezonespresent = -1;
static gint hf_r3_lockstate_timezonesactive = -1;
static gint hf_r3_lockstate_autounlockspresent = -1;
static gint hf_r3_lockstate_autounlocksactive = -1;
static gint hf_r3_lockstate_uapmspresent = -1;
static gint hf_r3_lockstate_uapmsactive = -1;
static gint hf_r3_lockstate_uapmrelockspresent = -1;
static gint hf_r3_lockstate_uapmreslocksactive = -1;
static gint hf_r3_lockstate_nvramprotect = -1;
static gint hf_r3_lockstate_nvramchecksum = -1;

/*static gint hf_r3_mortisestatelog = -1;*/
static gint hf_r3_mortisestatelog_pointer = -1;
static gint hf_r3_mortisestatelog_mortisetype = -1;
static gint hf_r3_mortisestatelog_waiting = -1;
static gint hf_r3_mortisestatelog_state = -1;
static gint hf_r3_mortisestatelog_last = -1;
static gint hf_r3_mortisestatelog_event = -1;

static gint hf_r3_timerchain_newtick = -1;
static gint hf_r3_timerchain_currentboundary = -1;
static gint hf_r3_timerchain_tasktag = -1;
static gint hf_r3_timerchain_address = -1;
static gint hf_r3_timerchain_reload = -1;
static gint hf_r3_timerchain_boundary = -1;
static gint hf_r3_timerchain_count = -1;
static gint hf_r3_timerchain_flags = -1;

static gint hf_r3_taskflags_taskid = -1;
static gint hf_r3_taskflags_flags = -1;

static gint hf_r3_checkpointlog_entryptr = -1;
static gint hf_r3_checkpointlog_rcon = -1;
static gint hf_r3_checkpointlog_checkpoint = -1;

static gint hf_r3_cpuregisters_intcon = -1;
static gint hf_r3_cpuregisters_intcon2 = -1;
static gint hf_r3_cpuregisters_intcon3 = -1;
static gint hf_r3_cpuregisters_pir1 = -1;
static gint hf_r3_cpuregisters_pir2 = -1;
static gint hf_r3_cpuregisters_pir3 = -1;
static gint hf_r3_cpuregisters_pie1 = -1;
static gint hf_r3_cpuregisters_pie2 = -1;
static gint hf_r3_cpuregisters_pie3 = -1;
static gint hf_r3_cpuregisters_ipr1 = -1;
static gint hf_r3_cpuregisters_ipr2 = -1;
static gint hf_r3_cpuregisters_ipr3 = -1;
static gint hf_r3_cpuregisters_rcon = -1;
static gint hf_r3_cpuregisters_osccon = -1;
static gint hf_r3_cpuregisters_rcsta = -1;
static gint hf_r3_cpuregisters_txsta = -1;
static gint hf_r3_cpuregisters_rcsta2 = -1;
static gint hf_r3_cpuregisters_txsta2 = -1;
static gint hf_r3_cpuregisters_wdtcon = -1;

static gint hf_r3_cpuregisters_intcon_rbif = -1;
static gint hf_r3_cpuregisters_intcon_int0if = -1;
static gint hf_r3_cpuregisters_intcon_tmr0if = -1;
static gint hf_r3_cpuregisters_intcon_rbie = -1;
static gint hf_r3_cpuregisters_intcon_int0ie = -1;
static gint hf_r3_cpuregisters_intcon_tmr0ie = -1;
static gint hf_r3_cpuregisters_intcon_giel = -1;
static gint hf_r3_cpuregisters_intcon_gieh = -1;
static gint hf_r3_cpuregisters_intcon2_rbip = -1;
static gint hf_r3_cpuregisters_intcon2_int3ip = -1;
static gint hf_r3_cpuregisters_intcon2_tmr0ip = -1;
static gint hf_r3_cpuregisters_intcon2_intedg3 = -1;
static gint hf_r3_cpuregisters_intcon2_intedg2 = -1;
static gint hf_r3_cpuregisters_intcon2_intedg1 = -1;
static gint hf_r3_cpuregisters_intcon2_intedg0 = -1;
static gint hf_r3_cpuregisters_intcon2_rbpu = -1;
static gint hf_r3_cpuregisters_intcon3_int1if = -1;
static gint hf_r3_cpuregisters_intcon3_int2if = -1;
static gint hf_r3_cpuregisters_intcon3_int3if = -1;
static gint hf_r3_cpuregisters_intcon3_int1ie = -1;
static gint hf_r3_cpuregisters_intcon3_int2ie = -1;
static gint hf_r3_cpuregisters_intcon3_int3ie = -1;
static gint hf_r3_cpuregisters_intcon3_int1ip = -1;
static gint hf_r3_cpuregisters_intcon3_int2ip = -1;
static gint hf_r3_cpuregisters_pir1_tmr1if = -1;
static gint hf_r3_cpuregisters_pir1_tmr2if = -1;
static gint hf_r3_cpuregisters_pir1_ccp1if = -1;
static gint hf_r3_cpuregisters_pir1_ssp1if = -1;
static gint hf_r3_cpuregisters_pir1_tx1if = -1;
static gint hf_r3_cpuregisters_pir1_rc1if = -1;
static gint hf_r3_cpuregisters_pir1_adif = -1;
static gint hf_r3_cpuregisters_pir1_pspif = -1;
static gint hf_r3_cpuregisters_pir2_ccp2if = -1;
static gint hf_r3_cpuregisters_pir2_tmr3if = -1;
static gint hf_r3_cpuregisters_pir2_hlvdif = -1;
static gint hf_r3_cpuregisters_pir2_bcl1if = -1;
static gint hf_r3_cpuregisters_pir2_eeif = -1;
static gint hf_r3_cpuregisters_pir2_unused5 = -1;
static gint hf_r3_cpuregisters_pir2_cmif = -1;
static gint hf_r3_cpuregisters_pir2_oscfif = -1;
static gint hf_r3_cpuregisters_pir3_ccp3if = -1;
static gint hf_r3_cpuregisters_pir3_ccp4if = -1;
static gint hf_r3_cpuregisters_pir3_ccp5if = -1;
static gint hf_r3_cpuregisters_pir3_tmr4if = -1;
static gint hf_r3_cpuregisters_pir3_tx2if = -1;
static gint hf_r3_cpuregisters_pir3_rc2if = -1;
static gint hf_r3_cpuregisters_pir3_bcl2if = -1;
static gint hf_r3_cpuregisters_pir3_ssp2if = -1;
static gint hf_r3_cpuregisters_pie1_tmr1ie = -1;
static gint hf_r3_cpuregisters_pie1_tmr2ie = -1;
static gint hf_r3_cpuregisters_pie1_ccp1ie = -1;
static gint hf_r3_cpuregisters_pie1_ssp1ie = -1;
static gint hf_r3_cpuregisters_pie1_tx1ie = -1;
static gint hf_r3_cpuregisters_pie1_rc1ie = -1;
static gint hf_r3_cpuregisters_pie1_adie = -1;
static gint hf_r3_cpuregisters_pie1_pspie = -1;
static gint hf_r3_cpuregisters_pie2_oscfie = -1;
static gint hf_r3_cpuregisters_pie2_cmie = -1;
static gint hf_r3_cpuregisters_pie2_unused2 = -1;
static gint hf_r3_cpuregisters_pie2_eeie = -1;
static gint hf_r3_cpuregisters_pie2_bcl1ie = -1;
static gint hf_r3_cpuregisters_pie2_hlvdie = -1;
static gint hf_r3_cpuregisters_pie2_tmr3ie = -1;
static gint hf_r3_cpuregisters_pie2_ccp2ie = -1;
static gint hf_r3_cpuregisters_pie3_ccp3ie = -1;
static gint hf_r3_cpuregisters_pie3_ccp4ie = -1;
static gint hf_r3_cpuregisters_pie3_ccp5ie = -1;
static gint hf_r3_cpuregisters_pie3_tmr4ie = -1;
static gint hf_r3_cpuregisters_pie3_tx2ie = -1;
static gint hf_r3_cpuregisters_pie3_rc2ie = -1;
static gint hf_r3_cpuregisters_pie3_bcl2ie = -1;
static gint hf_r3_cpuregisters_pie3_ssp2ie = -1;
static gint hf_r3_cpuregisters_ipr1_tmr1ip = -1;
static gint hf_r3_cpuregisters_ipr1_tmr2ip = -1;
static gint hf_r3_cpuregisters_ipr1_ccp1ip = -1;
static gint hf_r3_cpuregisters_ipr1_ssp1ip = -1;
static gint hf_r3_cpuregisters_ipr1_tx1ip = -1;
static gint hf_r3_cpuregisters_ipr1_rc1ip = -1;
static gint hf_r3_cpuregisters_ipr1_adip = -1;
static gint hf_r3_cpuregisters_ipr1_pspip = -1;
static gint hf_r3_cpuregisters_ipr2_ccp2ip = -1;
static gint hf_r3_cpuregisters_ipr2_tmr3ip = -1;
static gint hf_r3_cpuregisters_ipr2_hlvdip = -1;
static gint hf_r3_cpuregisters_ipr2_bcl1ip = -1;
static gint hf_r3_cpuregisters_ipr2_eeip = -1;
static gint hf_r3_cpuregisters_ipr2_unused5 = -1;
static gint hf_r3_cpuregisters_ipr2_cmip = -1;
static gint hf_r3_cpuregisters_ipr2_oscfip = -1;
static gint hf_r3_cpuregisters_ipr3_ccp2ip = -1;
static gint hf_r3_cpuregisters_ipr3_ccp4ip = -1;
static gint hf_r3_cpuregisters_ipr3_ccp5ip = -1;
static gint hf_r3_cpuregisters_ipr3_tmr4ip = -1;
static gint hf_r3_cpuregisters_ipr3_tx2ip = -1;
static gint hf_r3_cpuregisters_ipr3_rc2ip = -1;
static gint hf_r3_cpuregisters_ipr3_bcl2ip = -1;
static gint hf_r3_cpuregisters_ipr3_ssp2ip = -1;
static gint hf_r3_cpuregisters_rcon_bor = -1;
static gint hf_r3_cpuregisters_rcon_por = -1;
static gint hf_r3_cpuregisters_rcon_pd = -1;
static gint hf_r3_cpuregisters_rcon_to = -1;
static gint hf_r3_cpuregisters_rcon_unused4 = -1;
static gint hf_r3_cpuregisters_rcon_ri = -1;
static gint hf_r3_cpuregisters_rcon_sboren = -1;
static gint hf_r3_cpuregisters_rcon_ipen = -1;
static gint hf_r3_cpuregisters_osccon_scs0 = -1;
static gint hf_r3_cpuregisters_osccon_scs1 = -1;
static gint hf_r3_cpuregisters_osccon_iofs = -1;
static gint hf_r3_cpuregisters_osccon_osts = -1;
static gint hf_r3_cpuregisters_osccon_ircf0 = -1;
static gint hf_r3_cpuregisters_osccon_ircf1 = -1;
static gint hf_r3_cpuregisters_osccon_ircf2 = -1;
static gint hf_r3_cpuregisters_osccon_idlen = -1;
static gint hf_r3_cpuregisters_rcsta_rx9d = -1;
static gint hf_r3_cpuregisters_rcsta_oerr = -1;
static gint hf_r3_cpuregisters_rcsta_ferr = -1;
static gint hf_r3_cpuregisters_rcsta_adden = -1;
static gint hf_r3_cpuregisters_rcsta_cren = -1;
static gint hf_r3_cpuregisters_rcsta_sren = -1;
static gint hf_r3_cpuregisters_rcsta_rx9 = -1;
static gint hf_r3_cpuregisters_rcsta_spen = -1;
static gint hf_r3_cpuregisters_txsta_tx9d = -1;
static gint hf_r3_cpuregisters_txsta_trmt = -1;
static gint hf_r3_cpuregisters_txsta_brgh = -1;
static gint hf_r3_cpuregisters_txsta_sendb = -1;
static gint hf_r3_cpuregisters_txsta_sync = -1;
static gint hf_r3_cpuregisters_txsta_txen = -1;
static gint hf_r3_cpuregisters_txsta_tx9 = -1;
static gint hf_r3_cpuregisters_txsta_csrc = -1;
static gint hf_r3_cpuregisters_rcsta2_rx9d = -1;
static gint hf_r3_cpuregisters_rcsta2_oerr = -1;
static gint hf_r3_cpuregisters_rcsta2_ferr = -1;
static gint hf_r3_cpuregisters_rcsta2_adden = -1;
static gint hf_r3_cpuregisters_rcsta2_cren = -1;
static gint hf_r3_cpuregisters_rcsta2_sren = -1;
static gint hf_r3_cpuregisters_rcsta2_rx9 = -1;
static gint hf_r3_cpuregisters_rcsta2_spen = -1;
static gint hf_r3_cpuregisters_txsta2_tx9d = -1;
static gint hf_r3_cpuregisters_txsta2_trmt = -1;
static gint hf_r3_cpuregisters_txsta2_brgh = -1;
static gint hf_r3_cpuregisters_txsta2_sendb = -1;
static gint hf_r3_cpuregisters_txsta2_sync = -1;
static gint hf_r3_cpuregisters_txsta2_txen = -1;
static gint hf_r3_cpuregisters_txsta2_tx9 = -1;
static gint hf_r3_cpuregisters_txsta2_csrc = -1;
static gint hf_r3_cpuregisters_wdtcon_swdten = -1;
static gint hf_r3_cpuregisters_wdtcon_unused1 = -1;
static gint hf_r3_cpuregisters_wdtcon_unused2 = -1;
static gint hf_r3_cpuregisters_wdtcon_unused3 = -1;
static gint hf_r3_cpuregisters_wdtcon_unused4 = -1;
static gint hf_r3_cpuregisters_wdtcon_unused5 = -1;
static gint hf_r3_cpuregisters_wdtcon_unused6 = -1;
static gint hf_r3_cpuregisters_wdtcon_unused7 = -1;

static gint hf_r3_dumpm41t81_reg00 = -1;
static gint hf_r3_dumpm41t81_reg01 = -1;
static gint hf_r3_dumpm41t81_reg02 = -1;
static gint hf_r3_dumpm41t81_reg03 = -1;
static gint hf_r3_dumpm41t81_reg04 = -1;
static gint hf_r3_dumpm41t81_reg05 = -1;
static gint hf_r3_dumpm41t81_reg06 = -1;
static gint hf_r3_dumpm41t81_reg07 = -1;
static gint hf_r3_dumpm41t81_reg08 = -1;
static gint hf_r3_dumpm41t81_reg09 = -1;
static gint hf_r3_dumpm41t81_reg0a = -1;
static gint hf_r3_dumpm41t81_reg0b = -1;
static gint hf_r3_dumpm41t81_reg0c = -1;
static gint hf_r3_dumpm41t81_reg0d = -1;
static gint hf_r3_dumpm41t81_reg0e = -1;
static gint hf_r3_dumpm41t81_reg0f = -1;
static gint hf_r3_dumpm41t81_reg10 = -1;
static gint hf_r3_dumpm41t81_reg11 = -1;
static gint hf_r3_dumpm41t81_reg12 = -1;
static gint hf_r3_dumpm41t81_reg13 = -1;

static gint hf_r3_dumpm41t81_reg00_sec1 = -1;
static gint hf_r3_dumpm41t81_reg00_sec01 = -1;
static gint hf_r3_dumpm41t81_reg01_st = -1;
static gint hf_r3_dumpm41t81_reg01_10sec = -1;
static gint hf_r3_dumpm41t81_reg01_1sec = -1;
static gint hf_r3_dumpm41t81_reg02_notused = -1;
static gint hf_r3_dumpm41t81_reg02_10min = -1;
static gint hf_r3_dumpm41t81_reg02_1min = -1;
static gint hf_r3_dumpm41t81_reg03_cbe = -1;
static gint hf_r3_dumpm41t81_reg03_cb = -1;
static gint hf_r3_dumpm41t81_reg03_10hour = -1;
static gint hf_r3_dumpm41t81_reg03_1hour = -1;
static gint hf_r3_dumpm41t81_reg04_notused = -1;
static gint hf_r3_dumpm41t81_reg04_dow = -1;
static gint hf_r3_dumpm41t81_reg05_notused = -1;
static gint hf_r3_dumpm41t81_reg05_10day = -1;
static gint hf_r3_dumpm41t81_reg05_1day = -1;
static gint hf_r3_dumpm41t81_reg06_notused = -1;
static gint hf_r3_dumpm41t81_reg06_10month = -1;
static gint hf_r3_dumpm41t81_reg06_1month = -1;
static gint hf_r3_dumpm41t81_reg07_10year = -1;
static gint hf_r3_dumpm41t81_reg07_1year = -1;
static gint hf_r3_dumpm41t81_reg08_out = -1;
static gint hf_r3_dumpm41t81_reg08_ft = -1;
static gint hf_r3_dumpm41t81_reg08_s = -1;
static gint hf_r3_dumpm41t81_reg08_cal = -1;
static gint hf_r3_dumpm41t81_reg09_notused = -1;
static gint hf_r3_dumpm41t81_reg09_bmb = -1;
static gint hf_r3_dumpm41t81_reg09_rb = -1;
static gint hf_r3_dumpm41t81_reg0a_afe = -1;
static gint hf_r3_dumpm41t81_reg0a_sqwe = -1;
static gint hf_r3_dumpm41t81_reg0a_abe = -1;
static gint hf_r3_dumpm41t81_reg0a_10monthalm = -1;
static gint hf_r3_dumpm41t81_reg0a_1monthalm = -1;
static gint hf_r3_dumpm41t81_reg0b_rpt5 = -1;
static gint hf_r3_dumpm41t81_reg0b_rpt4 = -1;
static gint hf_r3_dumpm41t81_reg0b_10dayalm = -1;
static gint hf_r3_dumpm41t81_reg0b_1dayalm = -1;
static gint hf_r3_dumpm41t81_reg0c_rpt3 = -1;
static gint hf_r3_dumpm41t81_reg0c_ht = -1;
static gint hf_r3_dumpm41t81_reg0c_10houralm = -1;
static gint hf_r3_dumpm41t81_reg0c_1houralm = -1;
static gint hf_r3_dumpm41t81_reg0d_rpt2 = -1;
static gint hf_r3_dumpm41t81_reg0d_10minalm = -1;
static gint hf_r3_dumpm41t81_reg0d_1minalm = -1;
static gint hf_r3_dumpm41t81_reg0e_rpt1 = -1;
static gint hf_r3_dumpm41t81_reg0e_10secalm = -1;
static gint hf_r3_dumpm41t81_reg0e_1secalm = -1;
static gint hf_r3_dumpm41t81_reg0f_wdf = -1;
static gint hf_r3_dumpm41t81_reg0f_af = -1;
static gint hf_r3_dumpm41t81_reg0f_notused = -1;
static gint hf_r3_dumpm41t81_reg10_notused = -1;
static gint hf_r3_dumpm41t81_reg11_notused = -1;
static gint hf_r3_dumpm41t81_reg12_notused = -1;
static gint hf_r3_dumpm41t81_reg13_rs = -1;
static gint hf_r3_dumpm41t81_reg13_notused = -1;

static gint hf_r3_debuglog_recordnumber = -1;
static gint hf_r3_debuglog_flags = -1;
static gint hf_r3_debuglog_tick = -1;

static gint hf_r3_adduserparamtype = -1;
static gint hf_r3_adduserparamtypelength = -1;
static gint hf_r3_adduserparamtypetype = -1;
/*static gint hf_r3_adduserparamtypedatalen = -1;*/
/*static gint hf_r3_adduserparamtypeerror = -1;*/
static gint hf_r3_adduserparamtypearray [ADDUSERPARAMTYPE_LAST];

static gint ett_r3 = -1;
static gint ett_r3header = -1;
static gint ett_r3tail = -1;
static gint ett_r3payload = -1;
static gint ett_r3cmd = -1;
static gint ett_r3configitem = -1;
static gint ett_r3upstreamcommand = -1;
static gint ett_r3upstreamfield = -1;
static gint ett_r3timezone = -1;
static gint ett_r3expireon = -1;
static gint ett_r3datetime = -1;
static gint ett_r3eventlogrecord = -1;
static gint ett_r3declinedlogrecord = -1;
static gint ett_r3alarmlogrecord = -1;
static gint ett_r3debugmsg = -1;
static gint ett_r3defineexceptionstartdate = -1;
static gint ett_r3defineexceptionenddate = -1;
static gint ett_r3defineexceptiongroupbits = -1;
static gint ett_r3definecalendarmonth [13] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
static gint ett_r3definetimezonestarttime = -1;
static gint ett_r3definetimezoneendtime = -1;
static gint ett_r3definetimezonedaymap = -1;
static gint ett_r3eventlogdumpstarttime = -1;
static gint ett_r3eventlogdumpendtime = -1;
static gint ett_r3declinedlogdumpstarttime = -1;
static gint ett_r3declinedlogdumpendtime = -1;
static gint ett_r3alarmlogdumpstarttime = -1;
static gint ett_r3alarmlogdumpendtime = -1;
static gint ett_r3clearnvram = -1;
static gint ett_r3filters = -1;
static gint ett_r3alarmlist = -1;
static gint ett_r3alarmcfg = -1;
static gint ett_r3commandmfg = -1;
static gint ett_r3serialnumber = -1;
static gint ett_r3iopins = -1;
static gint ett_r3checksumresults = -1;
static gint ett_r3checksumresultsfield = -1;
static gint ett_r3forceoptions = -1;
static gint ett_r3peekpoke = -1;
static gint ett_r3downloadfirmware = -1;
static gint ett_r3capabilities = -1;
static gint ett_r3lockstate = -1;
static gint ett_r3mortisestatelog = -1;
static gint ett_r3timerchain = -1;
static gint ett_r3taskflags = -1;
static gint ett_r3taskflagsentry = -1;
static gint ett_r3checkpointlog = -1;
static gint ett_r3checkpointlogentry = -1;
static gint ett_r3cpuregisters = -1;
static gint ett_r3cpuregister = -1;
static gint ett_r3m41t81registers = -1;
static gint ett_r3m41t81register = -1;
static gint ett_r3debuglogrecord = -1;
static gint ett_r3setdatetime = -1;
static gint ett_r3manageuser = -1;


/*
 *  Indicates next command to be processed as a manufacturing command
 */
static gint mfgCommandFlag = FALSE;

/*
 *  Some enums that don't exist in public.h and should
 */
typedef enum
{
  CHECKPOINT_NONE = 0,
  CHECKPOINT_ADC,
  CHECKPOINT_DPAC1,
  CHECKPOINT_DPAC2,
  CHECKPOINT_I2C1,
  CHECKPOINT_I2C2,
  CHECKPOINT_I2C3,
  CHECKPOINT_I2C4,
  CHECKPOINT_I2C5,
  CHECKPOINT_I2C6,
  CHECKPOINT_I2C7,
  CHECKPOINT_I2C8,
  CHECKPOINT_I2C9,
  CHECKPOINT_I2C10,
  CHECKPOINT_I2C11,
  CHECKPOINT_I2C12,
  CHECKPOINT_I2C13,
  CHECKPOINT_I2C14,
  CHECKPOINT_I2C15,
  CHECKPOINT_I2C16,
  CHECKPOINT_I2C17,
  CHECKPOINT_I2C18,
  CHECKPOINT_I2C19,
  CHECKPOINT_I2C20,
  CHECKPOINT_I2C21,
  CHECKPOINT_I2C22,
  CHECKPOINT_I2C23,
  CHECKPOINT_I2C24,
  CHECKPOINT_I2C25,
  CHECKPOINT_I2C26,
  CHECKPOINT_I2C27,
  CHECKPOINT_I2C28,
  CHECKPOINT_I2C29,
  CHECKPOINT_I2C30,
  CHECKPOINT_I2C31,
  CHECKPOINT_I2C32,
  CHECKPOINT_I2C33,
  CHECKPOINT_I2C34,
  CHECKPOINT_I2C35,
  CHECKPOINT_I2C36,
  CHECKPOINT_I2C37,
  CHECKPOINT_I2C38,
  CHECKPOINT_I2C39,
  CHECKPOINT_I2C40,
  CHECKPOINT_I2C41,
  CHECKPOINT_I2C42,
  CHECKPOINT_I2C43,
  CHECKPOINT_I2C44,
  CHECKPOINT_I2C45,
  CHECKPOINT_NVRAM,
  CHECKPOINT_SERIAL1,
  CHECKPOINT_SERIAL2,
  CHECKPOINT_SERIAL3,
  CHECKPOINT_WANDERING,
  CHECKPOINT_STRAYHPINT,
  CHECKPOINT_STRAYLPINT,
  CHECKPOINT_TESTWDT,
  CHECKPOINT_DPACDEBUG,
  CHECKPOINT_LAST
}
checkPoint_e;

typedef enum
{
  CONFIGTYPE_NONE = 0,
  CONFIGTYPE_BOOL,
  CONFIGTYPE_8,
  CONFIGTYPE_16,
  CONFIGTYPE_32,
  CONFIGTYPE_STRING,
  CONFIGTYPE_LAST
}
configType_e;

typedef enum
{
  DOWNLOADFIRMWARE_START = 0,
  DOWNLOADFIRMWARE_DATA,
  DOWNLOADFIRMWARE_COMPLETE,
  DOWNLOADFIRMWARE_ABORT,
  DOWNLOADFIRMWARE_RESET,
  DOWNLOADFIRMWARE_LAST
}
downloadFirmware_e;

typedef enum
{
  MORTISEEVENT_DX_THROWN = 0,
  MORTISEEVENT_DX_RETRACTED,
  MORTISEEVENT_LX_RETRACTED,
  MORTISEEVENT_LX_EXTENDED,
  MORTISEEVENT_AX_EXTENDED,
  MORTISEEVENT_AX_RETRACTED,
  MORTISEEVENT_RX_DEPRESSED,
  MORTISEEVENT_RX_RELEASED,
  MORTISEEVENT_PX_OPEN,
  MORTISEEVENT_PX_CLOSED,
  MORTISEEVENT_MX_UNLOCKED,
  MORTISEEVENT_MX_LOCKED,
  MORTISEEVENT_LAST,
  MORTISEEVENT_IGNORE
}
mortiseEvent_e;

/*
 *  Print things with nice textual names
 */
static const value_string r3_accessmodenames [] =
{
  { ACCESSMODE_NONE,            "ACCESMODE_NONE" },
  { ACCESSMODE_PRIMARYONLY,     "ACCESSMODE_PRIMARYONLY" },
  { ACCESSMODE_PRIMARYORAUX,    "ACCESSMODE_PRIMARYORAUX" },
  { ACCESSMODE_PRIMARYANDAUX,   "ACCESSMODE_PRIMARYANDAUX" },
  { ACCESSMODE_PRIMARYTHENAUX,  "ACCESSMODE_PRIMARYTHENAUX" },
  { 0,                          NULL }
};
static value_string_ext r3_accessmodenames_ext = VALUE_STRING_EXT_INIT(r3_accessmodenames);

static const value_string r3_adduserparamtypenames [] =
{
  { ADDUSERPARAMTYPE_DISPOSITION,      "ADDUSERPARAMTYPE_DISPOSITION" },
  { ADDUSERPARAMTYPE_USERNO,           "ADDUSERPARAMTYPE_USERNO" },
  { ADDUSERPARAMTYPE_ACCESSALWAYS,     "ADDUSERPARAMTYPE_ACCESSALWAYS" },
  { ADDUSERPARAMTYPE_ACCESSMODE,       "ADDUSERPARAMTYPE_ACCESSMODE" },
  { ADDUSERPARAMTYPE_CACHED,           "ADDUSERPARAMTYPE_CACHED" },
  { ADDUSERPARAMTYPE_USERTYPE,         "ADDUSERPARAMTYPE_USERTYPE" },
  { ADDUSERPARAMTYPE_PRIMARYFIELD,     "ADDUSERPARAMTYPE_PRIMARYFIELD" },
  { ADDUSERPARAMTYPE_PRIMARYFIELDTYPE, "ADDUSERPARAMTYPE_PRIMARYFIELDTYPE" },
  { ADDUSERPARAMTYPE_AUXFIELD,         "ADDUSERPARAMTYPE_AUXFIELD" },
  { ADDUSERPARAMTYPE_AUXFIELDTYPE,     "ADDUSERPARAMTYPE_AUXFIELDTYPE" },
  { ADDUSERPARAMTYPE_TIMEZONE,         "ADDUSERPARAMTYPE_TIMEZONE" },
  { ADDUSERPARAMTYPE_EXPIREON,         "ADDUSERPARAMTYPE_EXPIREON" },
  { ADDUSERPARAMTYPE_USECOUNT,         "ADDUSERPARAMTYPE_USECOUNT" },
  { ADDUSERPARAMTYPE_EXCEPTIONGROUP,   "ADDUSERPARAMTYPE_EXCEPTIONGROUP" },
  { 0,                                 NULL }
};
static value_string_ext r3_adduserparamtypenames_ext = VALUE_STRING_EXT_INIT(r3_adduserparamtypenames);

static const value_string r3_alarmidnames [] =
{
  { ALARMID_NONE,         "ALARMID_NONE" },
  { ALARMID_VALIDIN,      "ALARMID_VALIDIN" },
  { ALARMID_DENIEDACCESS, "ALARMID_DENIEDACCESS" },
  { ALARMID_SECURED,      "ALARMID_SECURED" },
  { ALARMID_DOORFORCED,   "ALARMID_DOORFORCED" },
  { ALARMID_KEYOVERRIDE,  "ALARMID_KEYOVERRIDE" },
  { ALARMID_INVALIDENTRY, "ALARMID_INVALIDENTRY" },
  { ALARMID_DOORAJAR,     "ALARMID_DOORAJAR" },
  { ALARMID_LOWBATTERY,   "ALARMID_LOWBATTERY" },
  { ALARMID_RXHELD,       "ALARMID_RXHELD" },
  { 0,                    NULL }
};
static value_string_ext r3_alarmidnames_ext = VALUE_STRING_EXT_INIT(r3_alarmidnames);

static const value_string r3_capabilitiesnames [] =
{
  { CAPABILITIES_USERS,           "CAPABILITIES_USERS" },
  { CAPABILITIES_TIMEZONES,       "CAPABILITIES_TIMEZONES" },
  { CAPABILITIES_EXCEPTIONS,      "CAPABILITIES_EXCEPTIONS" },
  { CAPABILITIES_EXCEPTIONGROUPS, "CAPABILITIES_EXCEPTIONGROUPS" },
  { CAPABILITIES_EVENTLOG,        "CAPABILITIES_EVENTLOG" },
  { CAPABILITIES_DECLINEDLOG,     "CAPABILITIES_DECLINEDLOG" },
  { CAPABILITIES_ALARMLOG,        "CAPABILITIES_ALARMLOG" },
  { CAPABILITIES_TOTALEVENTS,     "CAPABILITIES_TOTALEVENTS" },
  { 0,                            NULL }
};
static value_string_ext r3_capabilitiesnames_ext = VALUE_STRING_EXT_INIT(r3_capabilitiesnames);

static const value_string r3_checkpointnames [] =
{
  { CHECKPOINT_NONE,       "CHECKPOINT_NONE" },
  { CHECKPOINT_ADC,        "CHECKPOINT_ADC" },
  { CHECKPOINT_DPAC1,      "CHECKPOINT_DPAC1" },
  { CHECKPOINT_DPAC2,      "CHECKPOINT_DPAC2" },
  { CHECKPOINT_I2C1,       "CHECKPOINT_I2C1" },
  { CHECKPOINT_I2C2,       "CHECKPOINT_I2C2" },
  { CHECKPOINT_I2C3,       "CHECKPOINT_I2C3" },
  { CHECKPOINT_I2C4,       "CHECKPOINT_I2C4" },
  { CHECKPOINT_I2C5,       "CHECKPOINT_I2C5" },
  { CHECKPOINT_I2C6,       "CHECKPOINT_I2C6" },
  { CHECKPOINT_I2C7,       "CHECKPOINT_I2C7" },
  { CHECKPOINT_I2C8,       "CHECKPOINT_I2C8" },
  { CHECKPOINT_I2C9,       "CHECKPOINT_I2C9" },
  { CHECKPOINT_I2C10,      "CHECKPOINT_I2C10" },
  { CHECKPOINT_I2C11,      "CHECKPOINT_I2C11" },
  { CHECKPOINT_I2C12,      "CHECKPOINT_I2C12" },
  { CHECKPOINT_I2C13,      "CHECKPOINT_I2C13" },
  { CHECKPOINT_I2C14,      "CHECKPOINT_I2C14" },
  { CHECKPOINT_I2C15,      "CHECKPOINT_I2C15" },
  { CHECKPOINT_I2C16,      "CHECKPOINT_I2C16" },
  { CHECKPOINT_I2C17,      "CHECKPOINT_I2C17" },
  { CHECKPOINT_I2C18,      "CHECKPOINT_I2C18" },
  { CHECKPOINT_I2C19,      "CHECKPOINT_I2C19" },
  { CHECKPOINT_I2C20,      "CHECKPOINT_I2C20" },
  { CHECKPOINT_I2C21,      "CHECKPOINT_I2C21" },
  { CHECKPOINT_I2C22,      "CHECKPOINT_I2C22" },
  { CHECKPOINT_I2C23,      "CHECKPOINT_I2C23" },
  { CHECKPOINT_I2C24,      "CHECKPOINT_I2C24" },
  { CHECKPOINT_I2C25,      "CHECKPOINT_I2C25" },
  { CHECKPOINT_I2C26,      "CHECKPOINT_I2C26" },
  { CHECKPOINT_I2C27,      "CHECKPOINT_I2C27" },
  { CHECKPOINT_I2C28,      "CHECKPOINT_I2C28" },
  { CHECKPOINT_I2C29,      "CHECKPOINT_I2C29" },
  { CHECKPOINT_I2C30,      "CHECKPOINT_I2C30" },
  { CHECKPOINT_I2C31,      "CHECKPOINT_I2C31" },
  { CHECKPOINT_I2C32,      "CHECKPOINT_I2C32" },
  { CHECKPOINT_I2C33,      "CHECKPOINT_I2C33" },
  { CHECKPOINT_I2C34,      "CHECKPOINT_I2C34" },
  { CHECKPOINT_I2C35,      "CHECKPOINT_I2C35" },
  { CHECKPOINT_I2C36,      "CHECKPOINT_I2C36" },
  { CHECKPOINT_I2C37,      "CHECKPOINT_I2C37" },
  { CHECKPOINT_I2C38,      "CHECKPOINT_I2C38" },
  { CHECKPOINT_I2C39,      "CHECKPOINT_I2C39" },
  { CHECKPOINT_I2C40,      "CHECKPOINT_I2C40" },
  { CHECKPOINT_I2C41,      "CHECKPOINT_I2C41" },
  { CHECKPOINT_I2C42,      "CHECKPOINT_I2C42" },
  { CHECKPOINT_I2C43,      "CHECKPOINT_I2C43" },
  { CHECKPOINT_I2C44,      "CHECKPOINT_I2C44" },
  { CHECKPOINT_I2C45,      "CHECKPOINT_I2C45" },
  { CHECKPOINT_NVRAM,      "CHECKPOINT_NVRAM" },
  { CHECKPOINT_SERIAL1,    "CHECKPOINT_SERIAL1" },
  { CHECKPOINT_SERIAL2,    "CHECKPOINT_SERIAL2" },
  { CHECKPOINT_SERIAL3,    "CHECKPOINT_SERIAL3" },
  { CHECKPOINT_WANDERING,  "CHECKPOINT_WANDERING" },
  { CHECKPOINT_STRAYHPINT, "CHECKPOINT_STRAYHPINT" },
  { CHECKPOINT_STRAYLPINT, "CHECKPOINT_STRAYLPINT" },
  { CHECKPOINT_TESTWDT,    "CHECKPOINT_TESTWDT" },
  { CHECKPOINT_DPACDEBUG,  "CHECKPOINT_DPACDEBUG" },
  { 0,                     NULL }
};
static value_string_ext r3_checkpointnames_ext = VALUE_STRING_EXT_INIT(r3_checkpointnames);

static const value_string r3_checksumresultnames [] =
{
  { CHECKSUMRESULT_CONFIGURATIONNVRAM,  "CHECKSUMRESULT_CONFIGURATIONNVRAM" },
  { CHECKSUMRESULT_EXCEPTIONS,          "CHECKSUMRESULT_EXCEPTIONS" },
  { CHECKSUMRESULT_EXCEPTIONGROUPS,     "CHECKSUMRESULT_EXCEPTIONGROUPS" },
  { CHECKSUMRESULT_TZCALENDARS,         "CHECKSUMRESULT_TZCALENDARS" },
  { CHECKSUMRESULT_TIMEZONES,           "CHECKSUMRESULT_TIMEZONES" },
  { CHECKSUMRESULT_USERS,               "CHECKSUMRESULT_USERS" },
  { CHECKSUMRESULT_CACHELRU,            "CHECKSUMRESULT_CACHELRU" },
  { 0,                                  NULL }
};
static value_string_ext r3_checksumresultnames_ext = VALUE_STRING_EXT_INIT(r3_checksumresultnames);

static const value_string r3_cmdnames [] =
{
  { CMD_RESPONSE,                  "CMD_RESPONSE" },
  { CMD_HANDSHAKE,                 "CMD_HANDSHAKE" },
  { CMD_KILLSESSION,               "CMD_KILLSESSION" },
  { CMD_QUERYSERIALNUMBER,         "CMD_QUERYSERIALNUMBER" },
  { CMD_QUERYVERSION,              "CMD_QUERYVERSION" },
  { CMD_SETDATETIME,               "CMD_SETDATETIME" },
  { CMD_QUERYDATETIME,             "CMD_QUERYDATETIME" },
  { CMD_SETCONFIG,                 "CMD_SETCONFIG" },
  { CMD_GETCONFIG,                 "CMD_GETCONFIG" },
  { CMD_MANAGEUSER,                "CMD_MANAGEUSER" },
  { CMD_DELETEUSERS,               "CMD_DELETEUSERS" },
  { CMD_DEFINEEXCEPTION,           "CMD_DEFINEEXCEPTION" },
  { CMD_DEFINEEXCEPTIONGROUP,      "CMD_DEFINEEXCEPTIONGROUP" },
  { CMD_DEFINECALENDAR,            "CMD_DEFINECALENDAR" },
  { CMD_DEFINETIMEZONE,            "CMD_DEFINETIMEZONE" },
  { CMD_RMTAUTHRETRY,              "CMD_RMTAUTHRETRY" },
  { CMD_FILTERS,                   "CMD_FILTERS" },
  { CMD_ALARMCONFIGURE,            "CMD_ALARMCONFIGURE" },
  { CMD_EVENTLOGDUMP,              "CMD_EVENTLOGDUMP" },
  { CMD_DECLINEDLOGDUMP,           "CMD_DECLINEDLOGDUMP" },
  { CMD_ALARMLOGDUMP,              "CMD_ALARMLOGDUMP" },
  { CMD_DOWNLOADFIRMWARE,          "CMD_DOWNLOADFIRMWARE" },
  { CMD_DOWNLOADFIRMWARETIMEOUT,   "CMD_DOWNLOADFIRMWARETIMEOUT" },
  { CMD_POWERTABLESELECTION,       "CMD_POWERTABLESELECTION" },
  { CMD_CLEARNVRAM,                "CMD_CLEARNVRAM" },
  { CMD_DPAC,                      "CMD_DPAC" },
  { CMD_SELFTEST,                  "CMD_SELFTEST" },
  { CMD_RESET,                     "CMD_RESET" },
  { CMD_LOGWRITE,                  "CMD_LOGWRITE" },
  { CMD_MFGCOMMAND,                "CMD_MFGCOMMAND" },
  { CMD_NVRAMBACKUP,               "CMD_NVRAMBACKUP" },
  { CMD_EXTENDEDRESPONSE,          "CMD_EXTENDEDRESPONSE" },
  { 0,                             NULL }
};
static value_string_ext r3_cmdnames_ext = VALUE_STRING_EXT_INIT(r3_cmdnames);

static const value_string r3_cmdmfgnames [] =
{
  { CMDMFG_SETSERIALNUMBER,       "CMDMFG_SETSERIALNUMBER" },
  { CMDMFG_SETCRYPTKEY,           "CMDMFG_SETCRYPTKEY" },
  { CMDMFG_DUMPNVRAM,             "CMDMFG_DUMPNVRAM" },
  { CMDMFG_TERMINAL,              "CMDMFG_TERMINAL" },
  { CMDMFG_REMOTEUNLOCK,          "CMDMFG_REMOTEUNLOCK" },
  { CMDMFG_AUXCTLRVERSION,        "CMDMFG_AUXCTLRVERSION" },
  { CMDMFG_IOPINS,                "CMDMFG_IOPINS" },
  { CMDMFG_ADCS,                  "CMDMFG_ADCS" },
  { CMDMFG_HARDWAREID,            "CMDMFG_HARDWAREID" },
  { CMDMFG_CHECKPOINTLOGDUMP,     "CMDMFG_CHECKPOINTLOGDUMP" },
  { CMDMFG_CHECKPOINTLOGCLEAR,    "CMDMFG_CHECKPOINTLOGCLEAR" },
  { CMDMFG_READREGISTERS,         "CMDMFG_READREGISTERS" },
  { CMDMFG_FORCEOPTIONS,          "CMDMFG_FORCEOPTIONS" },
  { CMDMFG_COMMUSER,              "CMDMFG_COMMUSER" },
  { CMDMFG_DUMPKEYPAD,            "CMDMFG_DUMPKEYPAD" },
  { CMDMFG_BATTERYCHECK,          "CMDMFG_BATTERYCHECK" },
  { CMDMFG_RAMREFRESH,            "CMDMFG_RAMREFRESH" },
  { CMDMFG_TASKFLAGS,             "CMDMFG_TASKFLAGS" },
  { CMDMFG_TIMERCHAIN,            "CMDMFG_TIMERCHAIN" },
  { CMDMFG_PEEKPOKE,              "CMDMFG_PEEKPOKE" },
  { CMDMFG_LOCKSTATE,             "CMDMFG_LOCKSTATE" },
  { CMDMFG_CAPABILITIES,          "CMDMFG_CAPABILITIES" },
  { CMDMFG_DUMPM41T81,            "CMDMFG_DUMPM41T81" },
  { CMDMFG_DEBUGLOGDUMP,          "CMDMFG_DEBUGLOGDUMP" },
  { CMDMFG_DEBUGLOGCLEAR,         "CMDMFG_DEBUGLOGCLEAR" },
  { CMDMFG_TESTWDT,               "CMDMFG_TESTWDT" },
  { CMDMFG_QUERYCKSUM,            "CMDMFG_QUERYCKSUM" },
  { CMDMFG_VALIDATECHECKSUMS,     "CMDMFG_VALIDATECHECKSUMS" },
  { CMDMFG_REBUILDLRUCACHE,       "CMDMFG_REBUILDLRUCACHE" },
  { CMDMFG_TZUPDATE,              "CMDMFG_TZUPDATE" },
  { CMDMFG_TESTPRESERVE,          "CMDMFG_TESTPRESERVE" },
  { CMDMFG_MORTISESTATELOGDUMP,   "CMDMFG_MORTISESTATELOGDUMP" },
  { CMDMFG_MORTISESTATELOGCLEAR,  "CMDMFG_MORTISESTATELOGCLEAR" },
  { CMDMFG_MORTISEPINS,           "CMDMFG_MORTISEPINS" },
  { CMDMFG_HALTANDCATCHFIRE,      "CMDMFG_HALTANDCATCHFIRE" },
  { 0,                            NULL }
};
static value_string_ext r3_cmdmfgnames_ext = VALUE_STRING_EXT_INIT(r3_cmdmfgnames);

static const value_string r3_configitemnames [] =
{
  { CONFIGITEM_SERIAL_NUMBER,               "CONFIGITEM_SERIAL_NUMBER" },
  { CONFIGITEM_CRYPT_KEY,                   "CONFIGITEM_CRYPT_KEY" },
  { CONFIGITEM_HARDWARE_OPTIONS_MFG,        "CONFIGITEM_HARDWARE_OPTIONS_MFG" },
  { CONFIGITEM_HARDWARE_OPTIONS,            "CONFIGITEM_HARDWARE_OPTIONS" },
  { CONFIGITEM_NVRAM_CHANGES,               "CONFIGITEM_NVRAM_CHANGES" },
  { CONFIGITEM_NVRAMDIRTY,                  "CONFIGITEM_NVRAMDIRTY" },
  { CONFIGITEM_NVRAM_WV,                    "CONFIGITEM_NVRAM_WV" },
  { CONFIGITEM_ENABLE_WDT,                  "CONFIGITEM_ENABLE_WDT" },
  { CONFIGITEM_EARLY_ACK,                   "CONFIGITEM_EARLY_ACK" },
  { CONFIGITEM_CONSOLE_AES_ONLY,            "CONFIGITEM_CONSOLE_AES_ONLY" },
  { CONFIGITEM_RADIO_AES_ONLY,              "CONFIGITEM_RADIO_AES_ONLY" },
  { CONFIGITEM_NDRLE,                       "CONFIGITEM_NDRLE" },
  { CONFIGITEM_SOMF,                        "CONFIGITEM_SOMF" },
  { CONFIGITEM_NOGAF,                       "CONFIGITEM_NOGAF" },
  { CONFIGITEM_CARD_READER_POWER,           "CONFIGITEM_CARD_READER_POWER" },
  { CONFIGITEM_PROX_ENABLE,                 "CONFIGITEM_PROX_ENABLE" },
  { CONFIGITEM_CKSUMCONFIG,                 "CONFIGITEM_CKSUMCONFIG" },
  { CONFIGITEM_DAILY_BATTERY_CHECK,         "CONFIGITEM_DAILY_BATTERY_CHECK" },
  { CONFIGITEM_DAILY_BATTERY_CHECK_HOUR,    "CONFIGITEM_DAILY_BATTERY_CHECK_HOUR" },
  { CONFIGITEM_BATTERY_LOW,                 "CONFIGITEM_BATTERY_LOW" },
  { CONFIGITEM_LRU_HEAD,                    "CONFIGITEM_LRU_HEAD" },
  { CONFIGITEM_LRU_TAIL,                    "CONFIGITEM_LRU_TAIL" },
  { CONFIGITEM_RTC_CALIBRATION,             "CONFIGITEM_RTC_CALIBRATION" },
  { CONFIGITEM_ACVREQUESTER,                "CONFIGITEM_ACVREQUESTER" },
  { CONFIGITEM_LOCAL_LED,                   "CONFIGITEM_LOCAL_LED" },
  { CONFIGITEM_ERRCNT_XORLEN,               "CONFIGITEM_ERRCNT_XORLEN" },
  { CONFIGITEM_ERRCNT_CRC,                  "CONFIGITEM_ERRCNT_CRC" },
  { CONFIGITEM_ERRCNT_NOTSIGIL,             "CONFIGITEM_ERRCNT_NOTSIGIL" },
  { CONFIGITEM_ERRCNT_TIMEOUT,              "CONFIGITEM_ERRCNT_TIMEOUT" },
  { CONFIGITEM_ERRCNT_TOOLONG,              "CONFIGITEM_ERRCNT_TOOLONG" },
  { CONFIGITEM_ERRCNT_TOOSHORT,             "CONFIGITEM_ERRCNT_TOOSHORT" },
  { CONFIGITEM_ERRCNT_HITDEFAULT,           "CONFIGITEM_ERRCNT_HITDEFAULT" },
  { CONFIGITEM_ERRCNT_OVERRUN,              "CONFIGITEM_ERRCNT_OVERRUN" },
  { CONFIGITEM_ERRCNT_UARTFE,               "CONFIGITEM_ERRCNT_UARTFE" },
  { CONFIGITEM_ERRCNT_UARTOE,               "CONFIGITEM_ERRCNT_UARTOE" },
  { CONFIGITEM_DST_SET,                     "CONFIGITEM_DST_SET" },
  { CONFIGITEM_DST_MODE,                    "CONFIGITEM_DST_MODE" },
  { CONFIGITEM_DST_FORWARD_MONTH,           "CONFIGITEM_DST_FORWARD_MONTH" },
  { CONFIGITEM_DST_FORWARD_DOM,             "CONFIGITEM_DST_FORWARD_DOM" },
  { CONFIGITEM_DST_FORWARD_OOD,             "CONFIGITEM_DST_FORWARD_OOD" },
  { CONFIGITEM_DST_FORWARD_DOW,             "CONFIGITEM_DST_FORWARD_DOW" },
  { CONFIGITEM_DST_FORWARD_HOUR,            "CONFIGITEM_DST_FORWARD_HOUR" },
  { CONFIGITEM_DST_FORWARD_MINUTE,          "CONFIGITEM_DST_FORWARD_MINUTE" },
  { CONFIGITEM_DST_FORWARD_ADJUST,          "CONFIGITEM_DST_FORWARD_ADJUST" },
  { CONFIGITEM_DST_BACK_MONTH,              "CONFIGITEM_DST_BACK_MONTH" },
  { CONFIGITEM_DST_BACK_DOM,                "CONFIGITEM_DST_BACK_DOM" },
  { CONFIGITEM_DST_BACK_OOD,                "CONFIGITEM_DST_BACK_OOD" },
  { CONFIGITEM_DST_BACK_DOW,                "CONFIGITEM_DST_BACK_DOW" },
  { CONFIGITEM_DST_BACK_HOUR,               "CONFIGITEM_DST_BACK_HOUR" },
  { CONFIGITEM_DST_BACK_MINUTE,             "CONFIGITEM_DST_BACK_MINUTE" },
  { CONFIGITEM_DST_BACK_ADJUST,             "CONFIGITEM_DST_BACK_ADJUST" },
  { CONFIGITEM_EVENTLOG_ZEROMEM,            "CONFIGITEM_EVENTLOG_ZEROMEM" },
  { CONFIGITEM_EVENTLOG_BEGIN,              "CONFIGITEM_EVENTLOG_BEGIN" },
  { CONFIGITEM_EVENTLOG_RECORD,             "CONFIGITEM_EVENTLOG_RECORD" },
  { CONFIGITEM_EVENTLOG_ENTRIES,            "CONFIGITEM_EVENTLOG_ENTRIES" },
  { CONFIGITEM_EVENTLOG_WARNDEVICE,         "CONFIGITEM_EVENTLOG_WARNDEVICE" },
  { CONFIGITEM_EVENTLOG_WARNEVERY,          "CONFIGITEM_EVENTLOG_WARNEVERY" },
  { CONFIGITEM_EVENTLOG_RMTDEVICE,          "CONFIGITEM_EVENTLOG_RMTDEVICE" },
  { CONFIGITEM_DECLINEDLOG_ZEROMEM,         "CONFIGITEM_DECLINEDLOG_ZEROMEM" },
  { CONFIGITEM_DECLINEDLOG_BEGIN,           "CONFIGITEM_DECLINEDLOG_BEGIN" },
  { CONFIGITEM_DECLINEDLOG_RECORD,          "CONFIGITEM_DECLINEDLOG_RECORD" },
  { CONFIGITEM_DECLINEDLOG_ENTRIES,         "CONFIGITEM_DECLINEDLOG_ENTRIES" },
  { CONFIGITEM_DECLINEDLOG_WARNDEVICE,      "CONFIGITEM_DECLINEDLOG_WARNDEVICE" },
  { CONFIGITEM_DECLINEDLOG_WARNEVERY,       "CONFIGITEM_DECLINEDLOG_WARNEVERY" },
  { CONFIGITEM_DECLINEDLOG_RMTDEVICE,       "CONFIGITEM_DECLINEDLOG_RMTDEVICE" },
  { CONFIGITEM_ALARMLOG_ZEROMEM,            "CONFIGITEM_ALARMLOG_ZEROMEM" },
  { CONFIGITEM_ALARMLOG_BEGIN,              "CONFIGITEM_ALARMLOG_BEGIN" },
  { CONFIGITEM_ALARMLOG_RECORD,             "CONFIGITEM_ALARMLOG_RECORD" },
  { CONFIGITEM_ALARMLOG_ENTRIES,            "CONFIGITEM_ALARMLOG_ENTRIES" },
  { CONFIGITEM_ALARMLOG_WARNDEVICE,         "CONFIGITEM_ALARMLOG_WARNDEVICE" },
  { CONFIGITEM_ALARMLOG_WARNEVERY,          "CONFIGITEM_ALARMLOG_WARNEVERY" },
  { CONFIGITEM_ALARMLOG_RMTDEVICE,          "CONFIGITEM_ALARMLOG_RMTDEVICE" },
  { CONFIGITEM_VISIBLE_FEEDBACK,            "CONFIGITEM_VISIBLE_FEEDBACK" },
  { CONFIGITEM_AUDIBLE_FEEDBACK,            "CONFIGITEM_AUDIBLE_FEEDBACK" },
  { CONFIGITEM_VISIBLE_INDICATORS,          "CONFIGITEM_VISIBLE_INDICATORS" },
  { CONFIGITEM_AUDIBLE_INDICATORS,          "CONFIGITEM_AUDIBLE_INDICATORS" },
  { CONFIGITEM_2NDPINDURATION,              "CONFIGITEM_2NDPINDURATION" },
  { CONFIGITEM_LOCKOUT_ATTEMPTS,            "CONFIGITEM_LOCKOUT_ATTEMPTS" },
  { CONFIGITEM_LOCKOUT_DURATION,            "CONFIGITEM_LOCKOUT_DURATION" },
  { CONFIGITEM_KEYPAD_INACTIVITY,           "CONFIGITEM_KEYPAD_INACTIVITY" },
  { CONFIGITEM_ICIDLE_DURATION,             "CONFIGITEM_ICIDLE_DURATION" },
  { CONFIGITEM_WRITE_DECLINED_LOG,          "CONFIGITEM_WRITE_DECLINED_LOG" },
  { CONFIGITEM_LOW_BATTERY_INDICATOR,       "CONFIGITEM_LOW_BATTERY_INDICATOR" },
  { CONFIGITEM_PANIC_MODE,                  "CONFIGITEM_PANIC_MODE" },
  { CONFIGITEM_TIMEZONE_ENABLE,             "CONFIGITEM_TIMEZONE_ENABLE" },
  { CONFIGITEM_EXCEPTION_ENABLE,            "CONFIGITEM_EXCEPTION_ENABLE" },
  { CONFIGITEM_AUTOUNLOCK_ENABLE,           "CONFIGITEM_AUTOUNLOCK_ENABLE" },
  { CONFIGITEM_LOCK_PRIORITY_EMERGENCY,     "CONFIGITEM_LOCK_PRIORITY_EMERGENCY" },
  { CONFIGITEM_LOCK_PRIORITY_SUPERVISOR,    "CONFIGITEM_LOCK_PRIORITY_SUPERVISOR" },
  { CONFIGITEM_LOCK_PRIORITY_USER,          "CONFIGITEM_LOCK_PRIORITY_USER" },
  { CONFIGITEM_LOCK_PRIORITY_PASSAGE,       "CONFIGITEM_LOCK_PRIORITY_PASSAGE" },
  { CONFIGITEM_LOCK_PRIORITY_PANIC,         "CONFIGITEM_LOCK_PRIORITY_PANIC" },
  { CONFIGITEM_LOCK_PRIORITY_LOCKOUT,       "CONFIGITEM_LOCK_PRIORITY_LOCKOUT" },
  { CONFIGITEM_LOCK_PRIORITY_RELOCK,        "CONFIGITEM_LOCK_PRIORITY_RELOCK" },
  { CONFIGITEM_LOCK_PRIORITY_BOLTTHROWN,    "CONFIGITEM_LOCK_PRIORITY_BOLTTHROWN" },
  { CONFIGITEM_LOCK_PRIORITY_CONFIGCHANGE,  "CONFIGITEM_LOCK_PRIORITY_CONFIGCHANGE" },
  { CONFIGITEM_LOCK_PRIORITY_REMOTE,        "CONFIGITEM_LOCK_PRIORITY_REMOTE" },
  { CONFIGITEM_LOCK_TYPE,                   "CONFIGITEM_LOCK_TYPE" },
  { CONFIGITEM_DOUBLE_PULSE,                "CONFIGITEM_DOUBLE_PULSE" },
  { CONFIGITEM_DOUBLE_DELAY,                "CONFIGITEM_DOUBLE_DELAY" },
  { CONFIGITEM_MOTOR_DURATION,              "CONFIGITEM_MOTOR_DURATION" },
  { CONFIGITEM_MORTISE_TYPE,                "CONFIGITEM_MORTISE_TYPE" },
  { CONFIGITEM_UNLOCK_TIME,                 "CONFIGITEM_UNLOCK_TIME" },
  { CONFIGITEM_EXT_UNLOCK_TIME,             "CONFIGITEM_EXT_UNLOCK_TIME" },
  { CONFIGITEM_DOOR_AJAR_TIME,              "CONFIGITEM_DOOR_AJAR_TIME" },
  { CONFIGITEM_SESSION_TIMEOUT,             "CONFIGITEM_SESSION_TIMEOUT" },
  { CONFIGITEM_RETRY_ON_TIMEOUT,            "CONFIGITEM_RETRY_ON_TIMEOUT" },
  { CONFIGITEM_UNSOLICITED_ENCRYPT,         "CONFIGITEM_UNSOLICITED_ENCRYPT" },
  { CONFIGITEM_RMT_AUTH_TIMEOUT,            "CONFIGITEM_RMT_AUTH_TIMEOUT" },
  { CONFIGITEM_RMT_AUTH_DEVICE,             "CONFIGITEM_RMT_AUTH_DEVICE" },
  { CONFIGITEM_ALARM_DEVICE,                "CONFIGITEM_ALARM_DEVICE" },
  { CONFIGITEM_NOTIFY_DEVICE,               "CONFIGITEM_NOTIFY_DEVICE" },
  { CONFIGITEM_COMMUSER_DEVICE,             "CONFIGITEM_COMMUSER_DEVICE" },
  { CONFIGITEM_SCHEDULER_DEVICE,            "CONFIGITEM_SCHEDULER_DEVICE" },
  { CONFIGITEM_SCHEDULER_TYPE,              "CONFIGITEM_SCHEDULER_TYPE" },
  { CONFIGITEM_SCHEDULER_AWAKE,             "CONFIGITEM_SCHEDULER_AWAKE" },
  { CONFIGITEM_SCHEDULER_PERIOD,            "CONFIGITEM_SCHEDULER_PERIOD" },
  { CONFIGITEM_SCHEDULER_HOD,               "CONFIGITEM_SCHEDULER_HOD" },
  { CONFIGITEM_SCHEDULER_DOW,               "CONFIGITEM_SCHEDULER_DOW" },
  { CONFIGITEM_SCHEDULER_DOM,               "CONFIGITEM_SCHEDULER_DOM" },
  { CONFIGITEM_SCHEDULER_HM1,               "CONFIGITEM_SCHEDULER_HM1" },
  { CONFIGITEM_SCHEDULER_HM2,               "CONFIGITEM_SCHEDULER_HM2" },
  { CONFIGITEM_SCHEDULER_HM3,               "CONFIGITEM_SCHEDULER_HM3" },
  { CONFIGITEM_SCHEDULER_HM4,               "CONFIGITEM_SCHEDULER_HM4" },
  { CONFIGITEM_RADIO_TYPE,                  "CONFIGITEM_RADIO_TYPE" },
  { CONFIGITEM_RADIO_MODE,                  "CONFIGITEM_RADIO_MODE" },
  { CONFIGITEM_RADIO_TIMEOUT,               "CONFIGITEM_RADIO_TIMEOUT" },
  { CONFIGITEM_RADIO_ATTEMPTS,              "CONFIGITEM_RADIO_ATTEMPTS" },
  { CONFIGITEM_RADIO_HOUSEKEEPING,          "CONFIGITEM_RADIO_HOUSEKEEPING" },
  { CONFIGITEM_RADIO_LEAPUSERNAME,          "CONFIGITEM_RADIO_LEAPUSERNAME" },
  { CONFIGITEM_RADIO_LEAPPASSWORD,          "CONFIGITEM_RADIO_LEAPPASSWORD" },
  { CONFIGITEM_INHIBIT_VOLTAGE,             "CONFIGITEM_INHIBIT_VOLTAGE" },
  { CONFIGITEM_LOW_VOLTAGE,                 "CONFIGITEM_LOW_VOLTAGE" },
  { CONFIGITEM_PT_RANGE_1,                  "CONFIGITEM_PT_RANGE_1" },
  { CONFIGITEM_PT_RANGE_2,                  "CONFIGITEM_PT_RANGE_2" },
  { CONFIGITEM_PT_RANGE_3,                  "CONFIGITEM_PT_RANGE_3" },
  { CONFIGITEM_PT_RANGE_4,                  "CONFIGITEM_PT_RANGE_4" },
  { CONFIGITEM_PT_RANGE_5,                  "CONFIGITEM_PT_RANGE_5" },
  { CONFIGITEM_PT_RANGE_6,                  "CONFIGITEM_PT_RANGE_6" },
  { CONFIGITEM_PT_RANGE_7,                  "CONFIGITEM_PT_RANGE_7" },
  { CONFIGITEM_PT_RANGE_8,                  "CONFIGITEM_PT_RANGE_8" },
  { CONFIGITEM_MAGCARD_IFS,                 "CONFIGITEM_MAGCARD_IFS" },
  { CONFIGITEM_MAGCARD_FIELDS,              "CONFIGITEM_MAGCARD_FIELDS" },
  { CONFIGITEM_MAGCARD_OFFSET,              "CONFIGITEM_MAGCARD_OFFSET" },
  { CONFIGITEM_MAGCARD_DIGITS,              "CONFIGITEM_MAGCARD_DIGITS" },
  { CONFIGITEM_ALARMS,                      "CONFIGITEM_ALARMS" },
  { CONFIGITEM_FILTERS,                     "CONFIGITEM_FILTERS" },
  { CONFIGITEM_ALARMSTATE,                  "CONFIGITEM_ALARMSTATE" },
  { CONFIGITEM_DOORSTATE,                   "CONFIGITEM_DOORSTATE" },
  { CONFIGITEM_DPACDEBUG,                   "CONFIGITEM_DPACDEBUG" },
  { CONFIGITEM_FAILOPENSECURE,              "CONFIGITEM_FAILOPENSECURE" },
  { CONFIGITEM_REPLACED_VOLTAGE,            "CONFIGITEM_REPLACED_VOLTAGE" },
  { CONFIGITEM_RX_HELD_TIME,                "CONFIGITEM_RX_HELD_TIME" },
  { CONFIGITEM_PACKET_TIMEOUT,              "CONFIGITEM_PACKET_TIMEOUT" },
  { CONFIGITEM_EXTENDEDRESPONSE,            "CONFIGITEM_EXTENDEDRESPONSE" },
  { CONFIGITEM_PASSAGEMODEINDICATOR,        "CONFIGITEM_PASSAGEMODEINDICATOR" },
  { CONFIGITEM_PFMRETURNTIME,               "CONFIGITEM_PFMRETURNTIME" },
  { 0,                                      NULL }
};
static value_string_ext r3_configitemnames_ext = VALUE_STRING_EXT_INIT(r3_configitemnames);

static const value_string r3_configtypenames [] =
{
  { CONFIGTYPE_NONE,    "CONFIGTYPE_NONE" },
  { CONFIGTYPE_BOOL,    "CONFIGTYPE_BOOL" },
  { CONFIGTYPE_8,       "CONFIGTYPE_8" },
  { CONFIGTYPE_16,      "CONFIGTYPE_16" },
  { CONFIGTYPE_32,      "CONFIGTYPE_32" },
  { CONFIGTYPE_STRING,  "CONFIGTYPE_STRING" },
  { 0,                  NULL }
};
static value_string_ext r3_configtypenames_ext = VALUE_STRING_EXT_INIT(r3_configtypenames);

static const value_string r3_dispositionnames [] =
{
  { DISPOSITION_ADD,      "DISPOSITION_ADD" },
  { DISPOSITION_REPLACE,  "DISPOSITION_REPLACE" },
  { DISPOSITION_UPDATE,   "DISPOSITION_UPDATE" },
  { DISPOSITION_DELETE,   "DISPOSITION_DELETE" },
  { DISPOSITION_RETRIEVE, "DISPOSITION_RETRIEVE" },
  { 0,                    NULL }
};
static value_string_ext r3_dispositionnames_ext = VALUE_STRING_EXT_INIT(r3_dispositionnames);

static const value_string r3_deleteusersnames [] =
{
  { DELETEUSERS_ALL,    "DELETEUSER_ALL" },
  { DELETEUSERS_CACHED, "DELETEUSER_CACHED" },
  { 0,                  NULL }
};
static value_string_ext r3_deleteusersnames_ext = VALUE_STRING_EXT_INIT(r3_deleteusersnames);

static const value_string r3_downloadfirmwarenames [] =
{
  { DOWNLOADFIRMWARE_START,    "DOWNLOADFIRMWARE_START" },
  { DOWNLOADFIRMWARE_DATA,     "DOWNLOADFIRMWARE_DATA" },
  { DOWNLOADFIRMWARE_COMPLETE, "DOWNLOADFIRMWARE_COMPLETE" },
  { DOWNLOADFIRMWARE_ABORT,    "DOWNLOADFIRMWARE_ABORT" },
  { DOWNLOADFIRMWARE_RESET,    "DOWNLOADFIRMWARE_RESET" },
  { 0,                         NULL }
};
static value_string_ext r3_downloadfirmwarenames_ext = VALUE_STRING_EXT_INIT(r3_downloadfirmwarenames);

static const value_string r3_encryptionschemenames [] =
{
  { ENCRYPTIONSCHEME_NONE,    "ENCRYPTIONSCHEME_NONE" },
  { ENCRYPTIONSCHEME_ROLLING, "ENCRYPTIONSCHEME_ROLLING" },
  { ENCRYPTIONSCHEME_SN,      "ENCRYPTIONSCHEME_SN" },
  { ENCRYPTIONSCHEME_AESIV,   "ENCRYPTIONSCHEME_AESIV" },
  { ENCRYPTIONSCHEME_AES,     "ENCRYPTIONSCHEME_AES" },
  { 0,                        NULL }
};
static value_string_ext r3_encryptionschemenames_ext = VALUE_STRING_EXT_INIT(r3_encryptionschemenames);

static const value_string r3_eventnames [] =
{
  { EVENT_INVALIDPIN,           "EVENT_INVALIDPIN" },
  { EVENT_USER,                 "EVENT_USER" },
  { EVENT_ONETIME,              "EVENT_ONETIME" },
  { EVENT_PASSAGEBEGIN,         "EVENT_PASSAGEBEGIN" },
  { EVENT_PASSAGEEND,           "EVENT_PASSAGEEND" },
  { EVENT_BADTIME,              "EVENT_BADTIME" },
  { EVENT_LOCKEDOUT,            "EVENT_LOCKEDOUT" },
  { EVENT_LOWBATTERY,           "EVENT_LOWBATTERY" },
  { EVENT_DEADBATTERY,          "EVENT_DEADBATTERY" },
  { EVENT_BATTERYREPLACED,      "EVENT_BATTERYREPLACED" },
  { EVENT_USERADDED,            "EVENT_USERADDED" },
  { EVENT_USERDELETED,          "EVENT_USERDELETED" },
  { EVENT_EMERGENCY,            "EVENT_EMERGENCY" },
  { EVENT_PANIC,                "EVENT_PANIC" },
  { EVENT_RELOCK,               "EVENT_RELOCK" },
  { EVENT_LOCKOUTBEGIN,         "EVENT_LOCKOUTBEGIN" },
  { EVENT_LOCKOUTEND,           "EVENT_LOCKOUTEND" },
  { EVENT_RESET,                "EVENT_RESET" },
  { EVENT_DATETIMESET,          "EVENT_DATETIMESET" },
  { EVENT_LOGCLEARED,           "EVENT_LOGCLEARED" },
  { EVENT_DBRESET,              "EVENT_DBRESET" },
  { EVENT_COMMSTARTED,          "EVENT_COMMSTARTED" },
  { EVENT_COMMENDED,            "EVENT_COMMENDED" },
  { EVENT_FIRMWAREABORT,        "EVENT_FIRMWAREABORT" },
  { EVENT_FIRMWAREERROR,        "EVENT_FIRMWAREERROR" },
  { EVENT_FIRMWARETIMEOUT,      "EVENT_FIRMWARETIMEOUT" },
  { EVENT_DSTFALLBACK,          "EVENT_DSTFALLBACK" },
  { EVENT_DSTSPRINGFORWARD,     "EVENT_DSTSPRINGFORWARD" },
  { EVENT_BOLTTHROWN,           "EVENT_BOLTTHROWN" },
  { EVENT_BOLTRETRACTED,        "EVENT_BOLTRETRACTED" },
  { EVENT_MASTERCODE,           "EVENT_MASTERCODE" },
  { EVENT_COMMUSER,             "EVENT_COMMUSER" },
  { EVENT_DPACDISABLED,         "EVENT_DPACDISABLED" },
  { EVENT_NOTIFY,               "EVENT_NOTIFY" },
  { EVENT_EXPIRED,              "EVENT_EXPIRED" },
  { EVENT_SUPERVISOR,           "EVENT_SUPERVISOR" },
  { EVENT_MCCENTER,             "EVENT_MCCENTER" },
  { EVENT_MCCEXIT,              "EVENT_MCCEXIT" },
  { EVENT_SERIALRXOVERRUN,      "EVENT_SERIALRXOVERRUN" },
  { EVENT_DPACRXOVERRUN,        "EVENT_DPACRXOVERRUN" },
  { EVENT_NVRAMPBCLEAR,         "EVENT_NVRAMPBCLEAR" },
  { EVENT_NVRAMLAYOUTCHANGE,    "EVENT_NVRAMLAYOUTCHANGE" },
  { EVENT_NVRAMOK,              "EVENT_NVRAMOK" },
  { EVENT_USERREPLACED,         "EVENT_USERREPLACED" },
  { EVENT_RADIOTIMEOUT,         "EVENT_RADIOTIMEOUT" },
  { EVENT_SUSPENDEDUSER,        "EVENT_SUSPENDEDUSER" },
  { EVENT_USERUPDATED,          "EVENT_USERUPDATED" },
  { EVENT_DOORBOLTED,           "EVENT_DOORBOLTED" },
  { EVENT_PANICACTIVE,          "EVENT_PANICACTIVE" },
  { EVENT_PASSAGEACTIVE,        "EVENT_PASSAGEACTIVE" },
  { EVENT_PASSAGEINACTIVE,      "EVENT_PASSAGEINACTIVE" },
  { EVENT_BADACCESSMODE,        "EVENT_BADACCESSMODE" },
  { EVENT_CLOCKERR,             "EVENT_CLOCKERR" },
  { EVENT_REMOTEUNLOCK,         "EVENT_REMOTEUNLOCK" },
  { EVENT_TZHAUDISABLED,        "EVENT_TZHAUDISABLED" },
  { EVENT_EVENTLOGWRAPPED,      "EVENT_EVENTLOGWRAPPED" },
  { EVENT_DECLINEDLOGWRAPPED,   "EVENT_DECLINEDLOGWRAPPED" },
  { EVENT_ALARMLOGWRAPPED,      "EVENT_ALARMLOGWRAPPED" },
  { EVENT_RADIOBUSYEMERGENCY,   "EVENT_RADIOBUSYEMERGENCY" },
  { EVENT_RADIOBUSYSUPERVISOR,  "EVENT_RADIOBUSYSUPERVISOR" },
  { EVENT_RADIOBUSYONETIME,     "EVENT_RADIOBUSYONETIME" },
  { EVENT_RADIOBUSYUSER,        "EVENT_RADIOBUSYUSER" },
  { EVENT_RADIOBUSYPANIC,       "EVENT_RADIOBUSYPANIC" },
  { EVENT_RADIOBUSYREX,         "EVENT_RADIOBUSYREX" },
  { EVENT_RADIOBUSYLOCKOUT,     "EVENT_RADIOBUSYLOCKOUT" },
  { EVENT_RADIOBUSYRELOCK,      "EVENT_RADIOBUSYRELOCK" },
  { EVENT_BATTERYCHECKHELDOFF,  "EVENT_BATTERYCHECKHELDOFF" },
  { EVENT_RMTAUTHREQUEST,       "EVENT_RMTAUTHREQUEST" },
  { EVENT_FIRMWAREUPDATE,       "EVENT_FIRMWAREUPDATE" },
  { EVENT_FIRMWAREUPDATEFAILED, "EVENT_FIRMWAREUPDATEFAILED" },
  { EVENT_MSMFAILURE,           "EVENT_MSMFAILURE" },
  { EVENT_CLOCKRESET,           "EVENT_CLOCKRESET" },
  { EVENT_POWERFAIL,            "EVENT_POWERFAIL" },
  { EVENT_DPAC501WENTSTUPID,    "EVENT_DPAC501WENTSTUPID" },
  { EVENT_CHECKSUMCONFIG,       "EVENT_CHECKSUMCONFIG" },
  { EVENT_CHECKSUMTZ,           "EVENT_CHECKSUMTZ" },
  { EVENT_DEBUG,                "EVENT_DEBUG" },
  { 0,                          NULL }
};
static value_string_ext r3_eventnames_ext = VALUE_STRING_EXT_INIT(r3_eventnames);

static const value_string r3_fieldtypenames [] =
{
  { FIELDTYPE_NONE,     "FIELDTYPE_NONE" },
  { FIELDTYPE_PIN,      "FIELDTYPE_PIN" },
  { FIELDTYPE_PROX,     "FIELDTYPE_PROX" },
  { FIELDTYPE_MAGCARD,  "FIELDTYPE_MAGCARD" },
  { 0,                  NULL }
};
static value_string_ext r3_fieldtypenames_ext = VALUE_STRING_EXT_INIT(r3_fieldtypenames);

static const value_string r3_filtereventnames [] =
{
  { EVENT_INVALIDPIN,           "EVENT_INVALIDPIN" },
  { EVENT_USER,                 "EVENT_USER" },
  { EVENT_ONETIME,              "EVENT_ONETIME" },
  { EVENT_PASSAGEBEGIN,         "EVENT_PASSAGEBEGIN" },
  { EVENT_PASSAGEEND,           "EVENT_PASSAGEEND" },
  { EVENT_BADTIME,              "EVENT_BADTIME" },
  { EVENT_LOCKEDOUT,            "EVENT_LOCKEDOUT" },
  { EVENT_LOWBATTERY,           "EVENT_LOWBATTERY" },
  { EVENT_DEADBATTERY,          "EVENT_DEADBATTERY" },
  { EVENT_BATTERYREPLACED,      "EVENT_BATTERYREPLACED" },
  { EVENT_USERADDED,            "EVENT_USERADDED" },
  { EVENT_USERDELETED,          "EVENT_USERDELETED" },
  { EVENT_EMERGENCY,            "EVENT_EMERGENCY" },
  { EVENT_PANIC,                "EVENT_PANIC" },
  { EVENT_RELOCK,               "EVENT_RELOCK" },
  { EVENT_LOCKOUTBEGIN,         "EVENT_LOCKOUTBEGIN" },
  { EVENT_LOCKOUTEND,           "EVENT_LOCKOUTEND" },
  { EVENT_RESET,                "EVENT_RESET" },
  { EVENT_DATETIMESET,          "EVENT_DATETIMESET" },
  { EVENT_LOGCLEARED,           "EVENT_LOGCLEARED" },
  { EVENT_DBRESET,              "EVENT_DBRESET" },
  { EVENT_COMMSTARTED,          "EVENT_COMMSTARTED" },
  { EVENT_COMMENDED,            "EVENT_COMMENDED" },
  { EVENT_FIRMWAREABORT,        "EVENT_FIRMWAREABORT" },
  { EVENT_FIRMWAREERROR,        "EVENT_FIRMWAREERROR" },
  { EVENT_FIRMWARETIMEOUT,      "EVENT_FIRMWARETIMEOUT" },
  { EVENT_DSTFALLBACK,          "EVENT_DSTFALLBACK" },
  { EVENT_DSTSPRINGFORWARD,     "EVENT_DSTSPRINGFORWARD" },
  { EVENT_BOLTTHROWN,           "EVENT_BOLTTHROWN" },
  { EVENT_BOLTRETRACTED,        "EVENT_BOLTRETRACTED" },
  { EVENT_MASTERCODE,           "EVENT_MASTERCODE" },
  { EVENT_COMMUSER,             "EVENT_COMMUSER" },
  { EVENT_DPACDISABLED,         "EVENT_DPACDISABLED" },
  { EVENT_NOTIFY,               "EVENT_NOTIFY" },
  { EVENT_EXPIRED,              "EVENT_EXPIRED" },
  { EVENT_SUPERVISOR,           "EVENT_SUPERVISOR" },
  { EVENT_MCCENTER,             "EVENT_MCCENTER" },
  { EVENT_MCCEXIT,              "EVENT_MCCEXIT" },
  { EVENT_SERIALRXOVERRUN,      "EVENT_SERIALRXOVERRUN" },
  { EVENT_DPACRXOVERRUN,        "EVENT_DPACRXOVERRUN" },
  { EVENT_NVRAMPBCLEAR,         "EVENT_NVRAMPBCLEAR" },
  { EVENT_NVRAMLAYOUTCHANGE,    "EVENT_NVRAMLAYOUTCHANGE" },
  { EVENT_NVRAMOK,              "EVENT_NVRAMOK" },
  { EVENT_USERREPLACED,         "EVENT_USERREPLACED" },
  { EVENT_RADIOTIMEOUT,         "EVENT_RADIOTIMEOUT" },
  { EVENT_SUSPENDEDUSER,        "EVENT_SUSPENDEDUSER" },
  { EVENT_USERUPDATED,          "EVENT_USERUPDATED" },
  { EVENT_DOORBOLTED,           "EVENT_DOORBOLTED" },
  { EVENT_PANICACTIVE,          "EVENT_PANICACTIVE" },
  { EVENT_PASSAGEACTIVE,        "EVENT_PASSAGEACTIVE" },
  { EVENT_PASSAGEINACTIVE,      "EVENT_PASSAGEINACTIVE" },
  { EVENT_BADACCESSMODE,        "EVENT_BADACCESSMODE" },
  { EVENT_CLOCKERR,             "EVENT_CLOCKERR" },
  { EVENT_REMOTEUNLOCK,         "EVENT_REMOTEUNLOCK" },
  { EVENT_TZHAUDISABLED,        "EVENT_TZHAUDISABLED" },
  { EVENT_EVENTLOGWRAPPED,      "EVENT_EVENTLOGWRAPPED" },
  { EVENT_DECLINEDLOGWRAPPED,   "EVENT_DECLINEDLOGWRAPPED" },
  { EVENT_ALARMLOGWRAPPED,      "EVENT_ALARMLOGWRAPPED" },
  { EVENT_RADIOBUSYEMERGENCY,   "EVENT_RADIOBUSYEMERGENCY" },
  { EVENT_RADIOBUSYSUPERVISOR,  "EVENT_RADIOBUSYSUPERVISOR" },
  { EVENT_RADIOBUSYONETIME,     "EVENT_RADIOBUSYONETIME" },
  { EVENT_RADIOBUSYUSER,        "EVENT_RADIOBUSYUSER" },
  { EVENT_RADIOBUSYPANIC,       "EVENT_RADIOBUSYPANIC" },
  { EVENT_RADIOBUSYREX,         "EVENT_RADIOBUSYREX" },
  { EVENT_RADIOBUSYLOCKOUT,     "EVENT_RADIOBUSYLOCKOUT" },
  { EVENT_RADIOBUSYRELOCK,      "EVENT_RADIOBUSYRELOCK" },
  { EVENT_BATTERYCHECKHELDOFF,  "EVENT_BATTERYCHECKHELDOFF" },
  { EVENT_RMTAUTHREQUEST,       "EVENT_RMTAUTHREQUEST" },
  { EVENT_FIRMWAREUPDATE,       "EVENT_FIRMWAREUPDATE" },
  { EVENT_FIRMWAREUPDATEFAILED, "EVENT_FIRMWAREUPDATEFAILED" },
  { EVENT_MSMFAILURE,           "EVENT_MSMFAILURE" },
  { EVENT_CLOCKRESET,           "EVENT_CLOCKRESET" },
  { EVENT_POWERFAIL,            "EVENT_POWERFAIL" },
  { EVENT_DPAC501WENTSTUPID,    "EVENT_DPAC501WENTSTUPID" },
  { EVENT_CHECKSUMCONFIG,       "EVENT_CHECKSUMCONFIG" },
  { EVENT_CHECKSUMTZ,           "EVENT_CHECKSUMTZ" },
  { EVENT_DEBUG,                "EVENT_DEBUG" },
  { 0xfe,                       "(Enable All Filters)" },
  { 0xff,                       "(Disable All Filters)" },
  { 0,                          NULL }
};
static value_string_ext r3_filtereventnames_ext = VALUE_STRING_EXT_INIT(r3_filtereventnames);

static const value_string r3_filtertypenames [] =
{
  { FILTERSELECT_RECORDING, "FILTERSELECT_RECORDING" },
  { FILTERSELECT_REPORTING, "FILTERSELECT_REPORTING" },
  { 0,                      NULL }
};
static value_string_ext r3_filtertypenames_ext = VALUE_STRING_EXT_INIT(r3_filtertypenames);

static const value_string r3_forceitemnames [] =
{
  { FORCEITEM_RADIOPOWER,  "FORCEITEM_RADIOPOWER" },
  { FORCEITEM_RADIOENABLE, "FORCEITEM_RADIOENABLE" },
  { FORCEITEM_LEDRED,      "FORCEITEM_LEDRED" },
  { FORCEITEM_LEDGREEN,    "FORCEITEM_LEDGREEN" },
  { FORCEITEM_LEDYELLOW,   "FORCEITEM_LEDYELLOW" },
  { FORCEITEM_PIEZO,       "FORCEITEM_PIEZO" },
  { FORCEITEM_MAGPOWER,    "FORCEITEM_MAGPOWER" },
  { FORCEITEM_MAGLEDA,     "FORCEITEM_MAGLEDA" },
  { FORCEITEM_MAGLEDB,     "FORCEITEM_MAGLEDB" },
  { FORCEITEM_PROXPOWER,   "FORCEITEM_PROXPOWER" },
  { FORCEITEM_PROXPING,    "FORCEITEM_PROXPING" },
  { FORCEITEM_PROXMODE,    "FORCEITEM_PROXMODE" },
  { FORCEITEM_I2CPOWER,    "FORCEITEM_I2CPOWER" },
  { FORCEITEM_MOTORARUN,   "FORCEITEM_MOTORARUN" },
  { FORCEITEM_MOTORBRUN,   "FORCEITEM_MOTORBRUN" },
  { FORCEITEM_VMON,        "FORCEITEM_VMON" },
  { FORCEITEM_PROX,        "FORCEITEM_PROX" },
  { FORCEITEM_MORTISETEST, "FORCEITEM_MORTISETEST" },
  { FORCEITEM_KEYPADTEST,  "FORCEITEM_KEYPADTEST" },
  { FORCEITEM_MAGTEST,     "FORCEITEM_MAGTEST" },
  { FORCEITEM_PROXTEST,    "FORCEITEM_PROXTEST" },
  { 0,                     NULL }
};
static value_string_ext r3_forceitemnames_ext = VALUE_STRING_EXT_INIT(r3_forceitemnames);

static const value_string r3_mfgfieldnames [] =
{
  { MFGFIELD_IOPINS,              "MFGFIELD_IOPINS" },
  { MFGFIELD_ADCS,                "MFGFIELD_ADCS" },
  { MFGFIELD_HARDWAREID,          "MFGFIELD_HARDWAREID" },
  { MFGFIELD_CHECKPOINTLOG,       "MFGFIELD_CHECKPOINTLOG" },
  { MFGFIELD_CPUREGISTERS,        "MFGFIELD_CPUREGISTERS" },
  { MFGFIELD_TASKFLAGS,           "MFGFIELD_TASKFLAGS" },
  { MFGFIELD_TIMERCHAIN,          "MFGFIELD_TIMERCHAIN" },
  { MFGFIELD_PEEKPOKE,            "MFGFIELD_PEEKPOKE" },
  { MFGFIELD_LOCKSTATE,           "MFGFIELD_LOCKSTATE" },
  { MFGFIELD_CAPABILITIES,        "MFGFIELD_CAPABILITIES" },
  { MFGFIELD_DUMPM41T81,          "MFGFIELD_DUMPM41T81" },
  { MFGFIELD_NVRAMCHECKSUMVALUE,  "MFGFIELD_NVRAMCHECKSUMVALUE" },
  { MFGFIELD_CHECKSUMRESULTS,     "MFGFIELD_CHECKSUMRESULTS" },
  { MFGFIELD_MORTISESTATELOG,     "MFGFIELD_MORTISESTATELOG" },
  { MFGFIELD_MORTISEPINS,         "MFGFIELD_MORTISEPINS" },
  { MFGFIELD_KEYPADCHAR,          "MFGFIELD_KEYPADCHAR" },
  { MFGFIELD_MAGCARD,             "MFGFIELD_MAGCARD" },
  { MFGFIELD_PROXCARD,            "MFGFIELD_PROXCARD" },
  { 0,                            NULL }
};
static value_string_ext r3_mfgfieldnames_ext = VALUE_STRING_EXT_INIT(r3_mfgfieldnames);

static const value_string r3_mortiseeventnames [] =
{
  { MORTISEEVENT_DX_THROWN,    "MORTISEEVENT_DX_THROWN" },
  { MORTISEEVENT_DX_RETRACTED, "MORTISEEVENT_DX_RETRACTED" },
  { MORTISEEVENT_LX_RETRACTED, "MORTISEEVENT_LX_RETRACTED" },
  { MORTISEEVENT_LX_EXTENDED,  "MORTISEEVENT_LX_EXTENDED" },
  { MORTISEEVENT_AX_EXTENDED,  "MORTISEEVENT_AX_EXTENDED" },
  { MORTISEEVENT_AX_RETRACTED, "MORTISEEVENT_AX_RETRACTED" },
  { MORTISEEVENT_RX_DEPRESSED, "MORTISEEVENT_RX_DEPRESSED" },
  { MORTISEEVENT_RX_RELEASED,  "MORTISEEVENT_RX_RELEASED" },
  { MORTISEEVENT_PX_OPEN,      "MORTISEEVENT_PX_OPEN" },
  { MORTISEEVENT_PX_CLOSED,    "MORTISEEVENT_PX_CLOSED" },
  { MORTISEEVENT_MX_UNLOCKED,  "MORTISEEVENT_MX_UNLOCKED" },
  { MORTISEEVENT_MX_LOCKED,    "MORTISEEVENT_MX_LOCKED" },
  { MORTISEEVENT_LAST,         "MORTISEEVENT_LAST" },
  { MORTISEEVENT_IGNORE,       "MORTISEEVENT_IGNORE" },
  { 0,                         NULL }
};
static value_string_ext r3_mortiseeventnames_ext = VALUE_STRING_EXT_INIT(r3_mortiseeventnames);

static const value_string r3_mortisetypenames [] =
{
  { MORTISETYPE_NONE,      "MORTISETYPE_NONE" },
  { MORTISETYPE_S82276,    "MORTISETYPE_S82276" },
  { MORTISETYPE_S82277,    "MORTISETYPE_S82277" },
  { MORTISETYPE_S82278,    "MORTISETYPE_S82278" },
  { MORTISETYPE_S82279,    "MORTISETYPE_S82279" },
  { MORTISETYPE_S10G77,    "MORTISETYPE_S10G77" },
  { MORTISETYPE_S8877,     "MORTISETYPE_S8877" },
  { MORTISETYPE_S8878,     "MORTISETYPE_S8878" },
  { MORTISETYPE_S8977,     "MORTISETYPE_S8977" },
  { MORTISETYPE_S8978,     "MORTISETYPE_S8978" },
  { MORTISETYPE_CRML20x36, "MORTISETYPE_CRML20x36" },
  { MORTISETYPE_CRML20x35, "MORTISETYPE_CRML20x35" },
  { MORTISETYPE_CRML20x34, "MORTISETYPE_CRML20x34" },
  { MORTISETYPE_CRML20x33, "MORTISETYPE_CRML20x33" },
  { MORTISETYPE_CRCL33x34, "MORTISETYPE_CRCL33x34" },
  { MORTISETYPE_CR9X34,    "MORTISETYPE_CR9X34" },
  { MORTISETYPE_CR9X33,    "MORTISETYPE_CR9X33" },
  { MORTISETYPE_CR9MX34,   "MORTISETYPE_CR9MX34" },
  { MORTISETYPE_CR9MX33,   "MORTISETYPE_CR9MX33" },
  { 0,                     NULL }
};
static value_string_ext r3_mortisetypenames_ext = VALUE_STRING_EXT_INIT(r3_mortisetypenames);

static const value_string r3_peekpokenames [] =
{
  { PEEKPOKE_READU8,      "PEEKPOKE_READU8" },
  { PEEKPOKE_READU16,     "PEEKPOKE_READU16" },
  { PEEKPOKE_READU24,     "PEEKPOKE_READU24" },
  { PEEKPOKE_READU32,     "PEEKPOKE_READU32" },
  { PEEKPOKE_READSTRING,  "PEEKPOKE_READSTRING" },
  { PEEKPOKE_WRITEU8,     "PEEKPOKE_WRITEU8" },
  { PEEKPOKE_WRITEU16,    "PEEKPOKE_WRITEU16" },
  { PEEKPOKE_WRITEU24,    "PEEKPOKE_WRITEU24" },
  { PEEKPOKE_WRITEU32,    "PEEKPOKE_WRITEU32" },
  { PEEKPOKE_WRITESTRING, "PEEKPOKE_WRITESTRING" },
  { 0,                    NULL }
};
static value_string_ext r3_peekpokenames_ext = VALUE_STRING_EXT_INIT(r3_peekpokenames);

static const value_string r3_ppmisourcenames [] =
{
  { PPMISOURCE_NONE,    "PPMISOURCE_NONE" },
  { PPMISOURCE_PIN,     "PPMISOURCE_PIN" },
  { PPMISOURCE_PROX,    "PPMISOURCE_PROX" },
  { PPMISOURCE_MAGCARD, "PPMISOURCE_MAGCARD" },
  { 0,                  NULL }
};
static value_string_ext r3_ppmisourcenames_ext = VALUE_STRING_EXT_INIT(r3_ppmisourcenames);

static const value_string r3_responsetypenames [] =
{
  { RESPONSETYPE_OK,                  "RESPONSETYPE_OK" },
  { RESPONSETYPE_ERROR,               "RESPONSETYPE_ERROR" },
  { RESPONSETYPE_HASDATA,             "RESPONSETYPE_HASDATA" },
  { RESPONSETYPE_NOHANDLER,           "RESPONSETYPE_NOHANDLER" },
  { RESPONSETYPE_NOSESSION,           "RESPONSETYPE_NOSESSION" },
  { RESPONSETYPE_BADCOMMAND,          "RESPONSETYPE_BADCOMMAND" },
  { RESPONSETYPE_BADPARAMETER,        "RESPONSETYPE_BADPARAMETER" },
  { RESPONSETYPE_BADPARAMETERLEN,     "RESPONSETYPE_BADPARAMETERLEN" },
  { RESPONSETYPE_MISSINGPARAMETER,    "RESPONSETYPE_MISSINGPARAMETER" },
  { RESPONSETYPE_DUPLICATEPARAMETER,  "RESPONSETYPE_DUPLICATEPARAMETER" },
  { RESPONSETYPE_PARAMETERCONFLICT,   "RESPONSETYPE_PARAMETERCONFLICT" },
  { RESPONSETYPE_BADDEVICE,           "RESPONSETYPE_BADDEVICE" },
  { RESPONSETYPE_NVRAMERROR,          "RESPONSETYPE_NVRAMERROR" },
  { RESPONSETYPE_NVRAMERRORNOACK,     "RESPONSETYPE_NVRAMERRORNOACK" },
  { RESPONSETYPE_NVRAMERRORNOACK32,   "RESPONSETYPE_NVRAMERRORNOACK32" },
  { RESPONSETYPE_NOTI2CADDRESS,       "RESPONSETYPE_NOTI2CADDRESS" },
  { RESPONSETYPE_FIRMWAREERROR,       "RESPONSETYPE_FIRMWAREERROR" },
  { RESPONSETYPE_DUMPINPROGRESS,      "RESPONSETYPE_DUMPINPROGRESS" },
  { RESPONSETYPE_INTERNALERROR,       "RESPONSETYPE_INTERNALERROR" },
  { RESPONSETYPE_NOTIMPLEMENTED,      "RESPONSETYPE_NOTIMPLEMENTED" },
  { RESPONSETYPE_PINFORMATERROR,      "RESPONSETYPE_PINFORMATERROR" },
  { RESPONSETYPE_PINEXISTS,           "RESPONSETYPE_PINEXISTS" },
  { RESPONSETYPE_PINNOTFOUND,         "RESPONSETYPE_PINNOTFOUND" },
  { RESPONSETYPE_USERACTIVE,          "RESPONSETYPE_USERACTIVE" },
  { RESPONSETYPE_USERINACTIVE,        "RESPONSETYPE_USERINACTIVE" },
  { RESPONSETYPE_PARENTNOTFOUND,      "RESPONSETYPE_PARENTNOTFOUND" },
  { RESPONSETYPE_NOCHAIN,             "RESPONSETYPE_NOCHAIN" },
  { RESPONSETYPE_CAUGHTINLOOP,        "RESPONSETYPE_CAUGHTINLOOP" },
  { RESPONSETYPE_EVENTFILTERED,       "RESPONSETYPE_EVENTFILTERED" },
  { RESPONSETYPE_PAYLOADTOOLARGE,     "RESPONSETYPE_PAYLOADTOOLARGE" },
  { RESPONSETYPE_ENDOFDATA,           "RESPONSETYPE_ENDOFDATA" },
  { RESPONSETYPE_RMTAUTHREJECTED,     "RESPONSETYPE_RMTAUTHREJECTED" },
  { RESPONSETYPE_NVRAMVERSIONERROR,   "RESPONSETYPE_NVRAMVERSIONERROR" },
  { RESPONSETYPE_NOHARDWARE,          "RESPONSETYPE_NOHARDWARE" },
  { RESPONSETYPE_SCHEDULERCONFLICT,   "RESPONSETYPE_SCHEDULERCONFLICT" },
  { RESPONSETYPE_NVRAMWRITEERROR,     "RESPONSETYPE_NVRAMWRITEERROR" },
  { RESPONSETYPE_DECLINEDFILTERED,    "RESPONSETYPE_DECLINEDFILTERED" },
  { RESPONSETYPE_NECONFIGPARM,        "RESPONSETYPE_NECONFIGPARM" },
  { RESPONSETYPE_FLASHERASEERROR,     "RESPONSETYPE_FLASHERASEERROR" },
  { RESPONSETYPE_FLASHWRITEERROR,     "RESPONSETYPE_FLASHWRITEERROR" },
  { RESPONSETYPE_BADNVBACKUP,         "RESPONSETYPE_BADNVBACKUP" },
  { RESPONSETYPE_EARLYACK,            "RESPONSETYPE_EARLYACK" },
  { RESPONSETYPE_ALARMFILTERED,       "RESPONSETYPE_ALARMFILTERED" },
  { RESPONSETYPE_ACVFAILURE,          "RESPONSETYPE_ACVFAILURE" },
  { RESPONSETYPE_USERCHECKSUMERROR,   "RESPONSETYPE_USERCHECKSUMERROR" },
  { RESPONSETYPE_CHECKSUMERROR,       "RESPONSETYPE_CHECKSUMERROR" },
  { RESPONSETYPE_RTCSQWFAILURE,       "RESPONSETYPE_RTCSQWFAILURE" },
  { RESPONSETYPE_PRIORITYSHUTDOWN,    "RESPONSETYPE_PRIORITYSHUTDOWN" },
  { RESPONSETYPE_NOTMODIFIABLE,       "RESPONSETYPE_NOTMODIFIABLE" },
  { RESPONSETYPE_CANTPRESERVE,        "RESPONSETYPE_CANTPRESERVE" },
  { RESPONSETYPE_INPASSAGEMODE,       "RESPONSETYPE_INPASSAGEMODE" },
  { 0,                                NULL }
};
static value_string_ext r3_responsetypenames_ext = VALUE_STRING_EXT_INIT(r3_responsetypenames);

static const value_string r3_timezonemodenames [] =
{
  { TIMEZONEMODE_NORMAL,    "TIMEZONEMODE_NORMAL" },
  { TIMEZONEMODE_EXCLUSION, "TIMEZONEMODE_EXCLUSION" },
  { TIMEZONEMODE_AUTOTIME,  "TIMEZONEMODE_AUTOTIME" },
  { TIMEZONEMODE_AUTOFPT,   "TIMEZONEMODE_AUTOFPT" },
  { TIMEZONEMODE_UAPM,      "TIMEZONEMODE_UAPM" },
  { 0,                      NULL }
};
static value_string_ext r3_timezonemodenames_ext = VALUE_STRING_EXT_INIT(r3_timezonemodenames);

static const value_string r3_upstreamcommandnames [] =
{
  { UPSTREAMCOMMAND_RESERVED,           "UPSTREAMCOMMAND_RESERVED" },
  { UPSTREAMCOMMAND_DEBUGMSG,           "UPSTREAMCOMMAND_DEBUGMSG" },
  { UPSTREAMCOMMAND_QUERYVERSION,       "UPSTREAMCOMMAND_QUERYVERSION" },
  { UPSTREAMCOMMAND_QUERYDATETIME,      "UPSTREAMCOMMAND_QUERYDATETIME" },
  { UPSTREAMCOMMAND_QUERYSERIALNUMBER,  "UPSTREAMCOMMAND_QUERYSERIALNUMBER" },
  { UPSTREAMCOMMAND_DUMPEVENTLOG,       "UPSTREAMCOMMAND_DUMPEVENTLOG" },
  { UPSTREAMCOMMAND_DUMPNVRAM,          "UPSTREAMCOMMAND_DUMPNVRAM" },
  { UPSTREAMCOMMAND_RMTAUTHREQUEST,     "UPSTREAMCOMMAND_RMTAUTHREQUEST" },
  { UPSTREAMCOMMAND_RETRIEVEUSER,       "UPSTREAMCOMMAND_RETRIEVEUSER" },
  { UPSTREAMCOMMAND_QUERYCONFIG,        "UPSTREAMCOMMAND_QUERYCONFIG" },
  { UPSTREAMCOMMAND_RMTEVENTLOGRECORD,  "UPSTREAMCOMMAND_RMTEVENTLOGRECORD" },
  { UPSTREAMCOMMAND_DPAC,               "UPSTREAMCOMMAND_DPAC" },
  { UPSTREAMCOMMAND_NOTIFY,             "UPSTREAMCOMMAND_NOTIFY" },
  { UPSTREAMCOMMAND_MFG,                "UPSTREAMCOMMAND_MFG" },
  { UPSTREAMCOMMAND_EVENTLOGWARNING,    "UPSTREAMCOMMAND_EVENTLOGWARNING" },
  { UPSTREAMCOMMAND_DUMPNVRAMRLE,       "UPSTREAMCOMMAND_DUMPNVRAMRLE" },
  { UPSTREAMCOMMAND_RMTDECLINEDRECORD,  "UPSTREAMCOMMAND_RMTDECLINEDRECORD" },
  { UPSTREAMCOMMAND_DECLINEDWARNING,    "UPSTREAMCOMMAND_DECLINEDWARNING" },
  { UPSTREAMCOMMAND_DUMPDECLINEDLOG,    "UPSTREAMCOMMAND_DUMPDECLINEDLOG" },
  { UPSTREAMCOMMAND_RMTALARMRECORD,     "UPSTREAMCOMMAND_RMTALARMRECORD" },
  { UPSTREAMCOMMAND_ALARMWARNING,       "UPSTREAMCOMMAND_ALARMWARNING" },
  { UPSTREAMCOMMAND_DUMPALARMLOG,       "UPSTREAMCOMMAND_DUMPALARMLOG" },
  { UPSTREAMCOMMAND_CONNECTSCHEDULER,   "UPSTREAMCOMMAND_CONNECTSCHEDULER" },
  { UPSTREAMCOMMAND_CONNECTCOMMUSER,    "UPSTREAMCOMMAND_CONNECTCOMMUSER" },
  { UPSTREAMCOMMAND_CONNECTALARM,       "UPSTREAMCOMMAND_CONNECTALARM" },
  { UPSTREAMCOMMAND_DUMPDEBUGLOG,       "UPSTREAMCOMMAND_DUMPDEBUGLOG" },
  { 0,                                  NULL }
};
static value_string_ext r3_upstreamcommandnames_ext = VALUE_STRING_EXT_INIT(r3_upstreamcommandnames);

static const value_string r3_upstreamfieldnames [] =
{
  { UPSTREAMFIELD_NOTUSED,              "UPSTREAMFIELD_NOTUSED" },
  { UPSTREAMFIELD_SERIALNUMBER,         "UPSTREAMFIELD_SERIALNUMBER" },
  { UPSTREAMFIELD_NAR,                  "UPSTREAMFIELD_NAR" },
  { UPSTREAMFIELD_ENTRYDEVICE,          "UPSTREAMFIELD_ENTRYDEVICE" },
  { UPSTREAMFIELD_PPMIFIELDTYPE,        "UPSTREAMFIELD_PPMIFIELDTYPE" },
  { UPSTREAMFIELD_PIN,                  "UPSTREAMFIELD_PIN" },
  { UPSTREAMFIELD_SEQUENCENUMBER,       "UPSTREAMFIELD_SEQUENCENUMBER" },
  { UPSTREAMFIELD_RESPONSEWINDOW,       "UPSTREAMFIELD_RESPONSEWINDOW" },
  { UPSTREAMFIELD_USERNUMBER,           "UPSTREAMFIELD_USERNUMBER" },
  { UPSTREAMFIELD_VERSION,              "UPSTREAMFIELD_VERSION" },
  { UPSTREAMFIELD_EVENTLOGRECORD,       "UPSTREAMFIELD_EVENTLOGRECORD" },
  { UPSTREAMFIELD_DATETIME,             "UPSTREAMFIELD_DATETIME" },
  { UPSTREAMFIELD_EVENTLOGRECORDCOUNT,  "UPSTREAMFIELD_EVENTLOGRECORDCOUNT" },
  { UPSTREAMFIELD_DECLINEDRECORDCOUNT,  "UPSTREAMFIELD_DECLINEDRECORDCOUNT" },
  { UPSTREAMFIELD_DECLINEDRECORD,       "UPSTREAMFIELD_DECLINEDRECORD" },
  { UPSTREAMFIELD_USERTYPE,             "UPSTREAMFIELD_USERTYPE" },
  { UPSTREAMFIELD_ACCESSALWAYS,         "UPSTREAMFIELD_ACCESSALWAYS" },
  { UPSTREAMFIELD_CACHED,               "UPSTREAMFIELD_CACHED" },
  { UPSTREAMFIELD_PRIMARYFIELDTYPE,     "UPSTREAMFIELD_PRIMARYFIELDTYPE" },
  { UPSTREAMFIELD_AUXFIELDTYPE,         "UPSTREAMFIELD_AUXFIELDTYPE" },
  { UPSTREAMFIELD_ACCESSMODE,           "UPSTREAMFIELD_ACCESSMODE" },
  { UPSTREAMFIELD_EXPIREON,             "UPSTREAMFIELD_EXPIREON" },
  { UPSTREAMFIELD_USECOUNT,             "UPSTREAMFIELD_USECOUNT" },
  { UPSTREAMFIELD_TIMEZONE,             "UPSTREAMFIELD_TIMEZONE" },
  { UPSTREAMFIELD_EXCEPTIONGROUP,       "UPSTREAMFIELD_EXCEPTIONGROUP" },
  { UPSTREAMFIELD_PRIMARYPIN,           "UPSTREAMFIELD_PRIMARYPIN" },
  { UPSTREAMFIELD_AUXPIN,               "UPSTREAMFIELD_AUXPIN" },
  { UPSTREAMFIELD_ALARMRECORDCOUNT,     "UPSTREAMFIELD_ALARMRECORDCOUNT" },
  { UPSTREAMFIELD_ALARMRECORD,          "UPSTREAMFIELD_ALARMRECORD" },
  { UPSTREAMFIELD_AUXCTLRVERSION,       "UPSTREAMFIELD_AUXCTLRVERSION" },
  { 0,                                  NULL }
};
static value_string_ext r3_upstreamfieldnames_ext = VALUE_STRING_EXT_INIT(r3_upstreamfieldnames);

static const value_string r3_usertypenames [] =
{
  { USERTYPE_NONE,        "USERTYPE_NONE" },
  { USERTYPE_MASTER,      "USERTYPE_MASTER" },
  { USERTYPE_EMERGENCY,   "USERTYPE_EMERGENCY" },
  { USERTYPE_SUPERVISOR,  "USERTYPE_SUPERVISOR" },
  { USERTYPE_USER,        "USERTYPE_USER" },
  { USERTYPE_EXTENDED,    "USERTYPE_EXTENDED" },
  { USERTYPE_PASSAGE,     "USERTYPE_PASSAGE" },
  { USERTYPE_ONETIME,     "USERTYPE_ONETIME" },
  { USERTYPE_PANIC,       "USERTYPE_PANIC" },
  { USERTYPE_LOCKOUT,     "USERTYPE_LOCKOUT" },
  { USERTYPE_RELOCK,      "USERTYPE_RELOCK" },
  { USERTYPE_NOTIFY,      "USERTYPE_NOTIFY" },
  { USERTYPE_COMM,        "USERTYPE_COMM" },
  { USERTYPE_SUSPENDED,   "USERTYPE_SUSPENDED" },
  { 0,                    NULL }
};
static value_string_ext r3_usertypenames_ext = VALUE_STRING_EXT_INIT(r3_usertypenames);

static const value_string r3_mfgnvramdumpnames [] =
{
  {  0, "All" },
  {  1, "PIC" },
  {  2, "User" },
  {  3, "Event" },
  {  0, NULL }
};
static value_string_ext r3_mfgnvramdumpnames_ext = VALUE_STRING_EXT_INIT(r3_mfgnvramdumpnames);

static const value_string r3_mfgremoteunlocknames [] =
{
  {  0, "Normal" },
  {  1, "Unlock" },
  {  2, "Lock" },
  {  0, NULL }
};
static value_string_ext r3_mfgremoteunlocknames_ext = VALUE_STRING_EXT_INIT(r3_mfgremoteunlocknames);

static const value_string r3_mfgtestpreservenames [] =
{
  {  0, "Save" },
  {  1, "Restore" },
  {  0, NULL }
};
static value_string_ext r3_mfgtestpreservenames_ext = VALUE_STRING_EXT_INIT(r3_mfgtestpreservenames);

static const value_string r3_daynames [] =
{
  { 0,  "Sunday" },
  { 1,  "Monday" },
  { 2,  "Tueday" },
  { 3,  "Wednesday" },
  { 4,  "Thursday" },
  { 5,  "Friday" },
  { 6,  "Saturday" },
  { 0,  NULL }
};
static value_string_ext r3_daynames_ext = VALUE_STRING_EXT_INIT(r3_daynames);

static const value_string r3_monthnames [] =
{
  {  0, "ERROR!" },
  {  1, "January" },
  {  2, "February" },
  {  3, "March" },
  {  4, "April" },
  {  5, "May" },
  {  6, "June" },
  {  7, "July" },
  {  8, "August" },
  {  9, "September" },
  { 10, "October" },
  { 11, "November" },
  { 12, "December" },
  {  0, NULL }
};
static value_string_ext r3_monthnames_ext = VALUE_STRING_EXT_INIT(r3_monthnames);

static const value_string r3_monthdaynames [] =
{
  {  0, "ERROR!" },
  {  1, " 1st" },
  {  2, " 2nd" },
  {  3, " 3rd" },
  {  4, " 4th" },
  {  5, " 5th" },
  {  6, " 6th" },
  {  7, " 7th" },
  {  8, " 8th" },
  {  9, " 9th" },
  { 10, "10th" },
  { 11, "11th" },
  { 12, "12th" },
  { 13, "13th" },
  { 14, "14th" },
  { 15, "15th" },
  { 16, "16th" },
  { 17, "17th" },
  { 18, "18th" },
  { 19, "19th" },
  { 20, "20th" },
  { 21, "21st" },
  { 22, "22nd" },
  { 23, "23rd" },
  { 24, "24th" },
  { 25, "25th" },
  { 26, "26th" },
  { 27, "27th" },
  { 28, "28th" },
  { 29, "29th" },
  { 30, "30th" },
  { 31, "31st" },
  {  0, NULL   }
};
static value_string_ext r3_monthdaynames_ext = VALUE_STRING_EXT_INIT(r3_monthdaynames);

static const value_string r3_powertablenames [] =
{
  {  1, "CONFIGITEM_PT_RANGE_1..CONFIGITEM_PT_RANGE_8 = {12, 11, 11, 10, 10,  9,  9,  8}" },
  {  2, "CONFIGITEM_PT_RANGE_1..CONFIGITEM_PT_RANGE_8 = {12, 11, 11, 10, 10,  9,  9,  8}" },
  {  3, "CONFIGITEM_PT_RANGE_1..CONFIGITEM_PT_RANGE_8 = {12, 11, 11, 10, 10,  9,  9,  8}" },
  {  4, "CONFIGITEM_PT_RANGE_1..CONFIGITEM_PT_RANGE_8 = {12, 11, 11, 10, 10,  9,  9,  8}" },
  {  5, "CONFIGITEM_PT_RANGE_1..CONFIGITEM_PT_RANGE_8 = {13, 12, 12, 11, 11, 10, 10,  9}" },
  {  6, "CONFIGITEM_PT_RANGE_1..CONFIGITEM_PT_RANGE_8 = {14, 13, 13, 12, 12, 11, 11, 10}" },
  {  7, "CONFIGITEM_PT_RANGE_1..CONFIGITEM_PT_RANGE_8 = {15, 14, 14, 13, 13, 12, 12, 11}" },
  {  8, "CONFIGITEM_PT_RANGE_1..CONFIGITEM_PT_RANGE_8 = {16, 15, 15, 14, 14, 13, 13, 12}" },
  {  0, NULL }
};
static value_string_ext r3_powertablenames_ext = VALUE_STRING_EXT_INIT(r3_powertablenames);

static const true_false_string tfs_rmtauthretry_flags =
{
  "Retry",
  "Deny"
};

static const true_false_string tfs_mortisepins_flags =
{
  "High",
  "Low"
};

static const true_false_string tfs_errornoerror_flags =
{
  "Error",
  "No Error"
};

static const string_string r3_snmanufacturernames [] =
{
  { "IT", "ITS" },
  { "KC", "Kimchuk" },
  { NULL, NULL }
};

static const string_string r3_snyearnames [] =
{
  { "5",  "2005" },
  { "6",  "2006" },
  { "7",  "2007" },
  { "8",  "2008" },
  { "9",  "2009" },
  { "0",  "2010" },
  { "1",  "2011" },
  { "2",  "2012" },
  { "3",  "2013" },
  { "4",  "2014" },
  { NULL, NULL }
};

static const string_string r3_snmodelnames [] =
{
  { "H",  "Sx controller" },
  { "J",  "Px controller" },
  { "D",  "PG offline interface board" },
  { "E",  "Px online interface board" },
  { "N",  "Ethernet-PD board" },
  { "O",  "CAM board" },
  { NULL, NULL }
};

static const string_string r3_sngroupnames [] =
{
  { "S",  "Sargent" },
  { "P",  "Persona" },
  { "C",  "Corbin-Russwin" },
  { NULL, NULL }
};

static const string_string r3_snnidnames [] =
{
  { "A",  "Ethernet" },
  { "B",  "DPAC 802.11b" },
  { "C",  "DPAC 802.11bg" },
  { "D",  "Zigbee" },
  { "E",  "GPRS" },
  { NULL, NULL }
};

static const string_string r3_snhidnames [] =
{
  { "00", "[None]" },
  { "01", "Keypad" },
  { "02", "eProx" },
  { "03", "eProx, Keypad" },
  { "04", "iProx" },
  { "05", "iProx, Keypad" },
  { "06", "iProx, eProx" },
  { "07", "iProx, eProx, Keypad" },
  { "08", "Mag Card" },
  { "09", "Mag Card, Keypad" },
  { "0a", "Mag Card, eProx" },
  { "0b", "Mag Card, eProx, Keypad" },
  { "0c", "Mag Card, iProx" },
  { "0d", "Mag Card, iProx, Keypad" },
  { "0e", "Mag Card, iProx, eProx" },
  { "0f", "Mag Card, iProx, eProx, Keypad" },
  { "10", "Biometric" },
  { "11", "Biometric, Keypad" },
  { "12", "Biometric, eProx" },
  { "13", "Biometric, eProx, Keypad" },
  { "14", "Biometric, iProx" },
  { "15", "Biometric, iProx, Keypad" },
  { "16", "Biometric, iProx, eProx" },
  { "17", "Biometric, iProx, eProx, Keypad" },
  { "18", "Biometric, Mag Card" },
  { "19", "Biometric, Mag Card, Keypad" },
  { "1a", "Biometric, Mag Card, eProx" },
  { "1b", "Biometric, Mag Card, eProx, Keypad" },
  { "1c", "Biometric, Mag Card, iProx" },
  { "1d", "Biometric, Mag Card, iProx, Keypad" },
  { "1e", "Biometric, Mag Card, iProx, eProx" },
  { "1f", "Biometric, Mag Card, iProx, eProx, Keypad" },
  { NULL, NULL }
};

static const string_string r3_snpowersupplynames [] =
{
  { "A",  "Batteries" },
  { "B",  "External power" },
  { "C",  "Power over Ethernet" },
  { "D",  "External power w/ backup" },
  { "E",  "Power over Ethernet w/ backup" },
  { NULL, NULL }
};

static const string_string r3_snmortisenames [] =
{
  { "A",  "Sargent 82276 mortise" },
  { "B",  "Sargent 82277 mortise" },
  { "C",  "Sargent 82278 mortise" },
  { "D",  "Sargent 82279 mortise" },
  { "E",  "Sargent 10G77 bored" },
  { "F",  "Sargent 8877 exit" },
  { "G",  "Sargent 8878 exit" },
  { "H",  "Sargent 8977 exit" },
  { "I",  "Sargent 8878 exit" },
  { "J",  "Corbin-Russwin ML20736/ML20836 mortise" },
  { "K",  "Corbin-Russwin ML20735/ML20835 mortise" },
  { "L",  "Corbin-Russwin ML20734/ML20834 mortise" },
  { "M",  "Corbin-Russwin ML20733/ML20833 mortise" },
  { "N",  "Corbin-Russwin CL33734/CL33834 bored" },
  { "O",  "Corbin-Russwin 9734/9834 exit" },
  { "P",  "Corbin-Russwin 9733/9833 exit" },
  { "Q",  "Corbin-Russwin 9M734/9M834 exit" },
  { "R",  "Corbin-Russwin 9M733/9M833 exit" },
  { NULL, NULL }
};

/*
 *  Mapping table so dissect_r3_cmd_setconfig() knows what the configuration item type is
 */
static configType_e configMap [] =
{
  /* CONFIGITEM_SERIAL_NUMBER */               CONFIGTYPE_STRING,
  /* CONFIGITEM_CRYPT_KEY */                   CONFIGTYPE_STRING,
  /* CONFIGITEM_HARDWARE_OPTIONS_MFG */        CONFIGTYPE_16,
  /* CONFIGITEM_HARDWARE_OPTIONS */            CONFIGTYPE_16,
  /* CONFIGITEM_NVRAM_CHANGES */               CONFIGTYPE_16,
  /* CONFIGITEM_NVRAMDIRTY */                  CONFIGTYPE_BOOL,
  /* CONFIGITEM_NVRAM_WV */                    CONFIGTYPE_BOOL,
  /* CONFIGITEM_ENABLE_WDT */                  CONFIGTYPE_BOOL,
  /* CONFIGITEM_EARLY_ACK */                   CONFIGTYPE_BOOL,
  /* CONFIGITEM_CONSOLE_AES_ONLY */            CONFIGTYPE_BOOL,
  /* CONFIGITEM_RADIO_AES_ONLY */              CONFIGTYPE_BOOL,
  /* CONFIGITEM_NDRLE */                       CONFIGTYPE_BOOL,
  /* CONFIGITEM_SOMF */                        CONFIGTYPE_BOOL,
  /* CONFIGITEM_NOGAF */                       CONFIGTYPE_BOOL,
  /* CONFIGITEM_CARD_READER_POWER */           CONFIGTYPE_BOOL,
  /* CONFIGITEM_PROX_ENABLE */                 CONFIGTYPE_BOOL,
  /* CONFIGITEM_CKSUMCONFIG */                 CONFIGTYPE_BOOL,
  /* CONFIGITEM_DAILY_BATTERY_CHECK */         CONFIGTYPE_BOOL,
  /* CONFIGITEM_DAILY_BATTERY_CHECK_HOUR */    CONFIGTYPE_8,
  /* CONFIGITEM_BATTERY_LOW */                 CONFIGTYPE_BOOL,
  /* CONFIGITEM_LRU_HEAD */                    CONFIGTYPE_16,
  /* CONFIGITEM_LRU_TAIL */                    CONFIGTYPE_16,
  /* CONFIGITEM_RTC_CALIBRATION */             CONFIGTYPE_8,
  /* CONFIGITEM_ACVREQUESTER */                CONFIGTYPE_8,
  /* CONFIGITEM_LOCAL_LED */                   CONFIGTYPE_8,
  /* CONFIGITEM_ERRCNT_XORLEN */               CONFIGTYPE_16,
  /* CONFIGITEM_ERRCNT_CRC */                  CONFIGTYPE_16,
  /* CONFIGITEM_ERRCNT_NOTSIGIL */             CONFIGTYPE_16,
  /* CONFIGITEM_ERRCNT_TIMEOUT */              CONFIGTYPE_16,
  /* CONFIGITEM_ERRCNT_TOOLONG */              CONFIGTYPE_16,
  /* CONFIGITEM_ERRCNT_TOOSHORT */             CONFIGTYPE_16,
  /* CONFIGITEM_ERRCNT_HITDEFAULT */           CONFIGTYPE_16,
  /* CONFIGITEM_ERRCNT_OVERRUN */              CONFIGTYPE_16,
  /* CONFIGITEM_ERRCNT_UARTFE */               CONFIGTYPE_16,
  /* CONFIGITEM_ERRCNT_UARTOE */               CONFIGTYPE_16,
  /* CONFIGITEM_DST_SET */                     CONFIGTYPE_BOOL,
  /* CONFIGITEM_DST_MODE */                    CONFIGTYPE_8,
  /* CONFIGITEM_DST_FORWARD_MONTH */           CONFIGTYPE_8,
  /* CONFIGITEM_DST_FORWARD_DOM */             CONFIGTYPE_8,
  /* CONFIGITEM_DST_FORWARD_OOD */             CONFIGTYPE_8,
  /* CONFIGITEM_DST_FORWARD_DOW */             CONFIGTYPE_8,
  /* CONFIGITEM_DST_FORWARD_HOUR */            CONFIGTYPE_8,
  /* CONFIGITEM_DST_FORWARD_MINUTE */          CONFIGTYPE_8,
  /* CONFIGITEM_DST_FORWARD_ADJUST */          CONFIGTYPE_8,
  /* CONFIGITEM_DST_BACK_MONTH */              CONFIGTYPE_8,
  /* CONFIGITEM_DST_BACK_DOM */                CONFIGTYPE_8,
  /* CONFIGITEM_DST_BACK_OOD */                CONFIGTYPE_8,
  /* CONFIGITEM_DST_BACK_DOW */                CONFIGTYPE_8,
  /* CONFIGITEM_DST_BACK_HOUR */               CONFIGTYPE_8,
  /* CONFIGITEM_DST_BACK_MINUTE */             CONFIGTYPE_8,
  /* CONFIGITEM_DST_BACK_ADJUST */             CONFIGTYPE_8,
  /* CONFIGITEM_EVENTLOG_ZEROMEM */            CONFIGTYPE_BOOL,
  /* CONFIGITEM_EVENTLOG_BEGIN */              CONFIGTYPE_16,
  /* CONFIGITEM_EVENTLOG_RECORD */             CONFIGTYPE_16,
  /* CONFIGITEM_EVENTLOG_ENTRIES */            CONFIGTYPE_16,
  /* CONFIGITEM_EVENTLOG_WARNDEVICE */         CONFIGTYPE_8,
  /* CONFIGITEM_EVENTLOG_WARNEVERY */          CONFIGTYPE_16,
  /* CONFIGITEM_EVENTLOG_RMTDEVICE */          CONFIGTYPE_8,
  /* CONFIGITEM_DECLINEDLOG_ZEROMEM */         CONFIGTYPE_BOOL,
  /* CONFIGITEM_DECLINEDLOG_BEGIN */           CONFIGTYPE_16,
  /* CONFIGITEM_DECLINEDLOG_RECORD */          CONFIGTYPE_16,
  /* CONFIGITEM_DECLINEDLOG_ENTRIES */         CONFIGTYPE_16,
  /* CONFIGITEM_DECLINEDLOG_WARNDEVICE */      CONFIGTYPE_8,
  /* CONFIGITEM_DECLINEDLOG_WARNEVERY */       CONFIGTYPE_16,
  /* CONFIGITEM_DECLINEDLOG_RMTDEVICE */       CONFIGTYPE_8,
  /* CONFIGITEM_ALARMLOG_ZEROMEM */            CONFIGTYPE_BOOL,
  /* CONFIGITEM_ALARMLOG_BEGIN */              CONFIGTYPE_16,
  /* CONFIGITEM_ALARMLOG_RECORD */             CONFIGTYPE_16,
  /* CONFIGITEM_ALARMLOG_ENTRIES */            CONFIGTYPE_16,
  /* CONFIGITEM_ALARMLOG_WARNDEVICE */         CONFIGTYPE_8,
  /* CONFIGITEM_ALARMLOG_WARNEVERY */          CONFIGTYPE_16,
  /* CONFIGITEM_ALARMLOG_RMTDEVICE */          CONFIGTYPE_8,
  /* CONFIGITEM_VISIBLE_FEEDBACK */            CONFIGTYPE_BOOL,
  /* CONFIGITEM_AUDIBLE_FEEDBACK */            CONFIGTYPE_BOOL,
  /* CONFIGITEM_VISIBLE_INDICATORS */          CONFIGTYPE_BOOL,
  /* CONFIGITEM_AUDIBLE_INDICATORS */          CONFIGTYPE_BOOL,
  /* CONFIGITEM_2NDPINDURATION */              CONFIGTYPE_8,
  /* CONFIGITEM_LOCKOUT_ATTEMPTS */            CONFIGTYPE_8,
  /* CONFIGITEM_LOCKOUT_DURATION */            CONFIGTYPE_8,
  /* CONFIGITEM_KEYPAD_INACTIVITY */           CONFIGTYPE_8,
  /* CONFIGITEM_ICIDLE_DURATION */             CONFIGTYPE_8,
  /* CONFIGITEM_WRITE_DECLINED_LOG */          CONFIGTYPE_BOOL,
  /* CONFIGITEM_LOW_BATTERY_INDICATOR */       CONFIGTYPE_BOOL,
  /* CONFIGITEM_PANIC_MODE */                  CONFIGTYPE_BOOL,
  /* CONFIGITEM_TIMEZONE_ENABLE */             CONFIGTYPE_BOOL,
  /* CONFIGITEM_EXCEPTION_ENABLE */            CONFIGTYPE_BOOL,
  /* CONFIGITEM_AUTOUNLOCK_ENABLE */           CONFIGTYPE_BOOL,
  /* CONFIGITEM_LOCK_PRIORITY_EMERGENCY */     CONFIGTYPE_8,
  /* CONFIGITEM_LOCK_PRIORITY_SUPERVISOR */    CONFIGTYPE_8,
  /* CONFIGITEM_LOCK_PRIORITY_USER */          CONFIGTYPE_8,
  /* CONFIGITEM_LOCK_PRIORITY_PASSAGE */       CONFIGTYPE_8,
  /* CONFIGITEM_LOCK_PRIORITY_PANIC */         CONFIGTYPE_8,
  /* CONFIGITEM_LOCK_PRIORITY_LOCKOUT */       CONFIGTYPE_8,
  /* CONFIGITEM_LOCK_PRIORITY_RELOCK */        CONFIGTYPE_8,
  /* CONFIGITEM_LOCK_PRIORITY_BOLTTHROWN */    CONFIGTYPE_8,
  /* CONFIGITEM_LOCK_PRIORITY_CONFIGCHANGE */  CONFIGTYPE_8,
  /* CONFIGITEM_LOCK_PRIORITY_REMOTE */        CONFIGTYPE_8,
  /* CONFIGITEM_LOCK_TYPE */                   CONFIGTYPE_8,
  /* CONFIGITEM_DOUBLE_PULSE */                CONFIGTYPE_BOOL,
  /* CONFIGITEM_DOUBLE_DELAY */                CONFIGTYPE_8,
  /* CONFIGITEM_MOTOR_DURATION */              CONFIGTYPE_8,
  /* CONFIGITEM_MORTISE_TYPE */                CONFIGTYPE_8,
  /* CONFIGITEM_UNLOCK_TIME */                 CONFIGTYPE_8,
  /* CONFIGITEM_EXT_UNLOCK_TIME */             CONFIGTYPE_8,
  /* CONFIGITEM_DOOR_AJAR_TIME */              CONFIGTYPE_8,
  /* CONFIGITEM_SESSION_TIMEOUT */             CONFIGTYPE_8,
  /* CONFIGITEM_RETRY_ON_TIMEOUT */            CONFIGTYPE_BOOL,
  /* CONFIGITEM_UNSOLICITED_ENCRYPT */         CONFIGTYPE_8,
  /* CONFIGITEM_RMT_AUTH_TIMEOUT */            CONFIGTYPE_8,
  /* CONFIGITEM_RMT_AUTH_DEVICE */             CONFIGTYPE_8,
  /* CONFIGITEM_ALARM_DEVICE */                CONFIGTYPE_8,
  /* CONFIGITEM_NOTIFY_DEVICE */               CONFIGTYPE_8,
  /* CONFIGITEM_COMMUSER_DEVICE */             CONFIGTYPE_8,
  /* CONFIGITEM_SCHEDULER_DEVICE */            CONFIGTYPE_8,
  /* CONFIGITEM_SCHEDULER_TYPE */              CONFIGTYPE_8,
  /* CONFIGITEM_SCHEDULER_AWAKE */             CONFIGTYPE_8,
  /* CONFIGITEM_SCHEDULER_PERIOD */            CONFIGTYPE_16,
  /* CONFIGITEM_SCHEDULER_HOD */               CONFIGTYPE_STRING,
  /* CONFIGITEM_SCHEDULER_DOW */               CONFIGTYPE_8,
  /* CONFIGITEM_SCHEDULER_DOM */               CONFIGTYPE_32,
  /* CONFIGITEM_SCHEDULER_HM1 */               CONFIGTYPE_16,
  /* CONFIGITEM_SCHEDULER_HM2 */               CONFIGTYPE_16,
  /* CONFIGITEM_SCHEDULER_HM3 */               CONFIGTYPE_16,
  /* CONFIGITEM_SCHEDULER_HM4 */               CONFIGTYPE_16,
  /* CONFIGITEM_RADIO_TYPE */                  CONFIGTYPE_8,
  /* CONFIGITEM_RADIO_MODE */                  CONFIGTYPE_8,
  /* CONFIGITEM_RADIO_TIMEOUT */               CONFIGTYPE_8,
  /* CONFIGITEM_RADIO_ATTEMPTS */              CONFIGTYPE_8,
  /* CONFIGITEM_RADIO_HOUSEKEEPING */          CONFIGTYPE_8,
  /* CONFIGITEM_RADIO_LEAPUSERNAME */          CONFIGTYPE_STRING,
  /* CONFIGITEM_RADIO_LEAPPASSWORD */          CONFIGTYPE_STRING,
  /* CONFIGITEM_INHIBIT_VOLTAGE */             CONFIGTYPE_8,
  /* CONFIGITEM_LOW_VOLTAGE */                 CONFIGTYPE_8,
  /* CONFIGITEM_PT_RANGE_1 */                  CONFIGTYPE_8,
  /* CONFIGITEM_PT_RANGE_2 */                  CONFIGTYPE_8,
  /* CONFIGITEM_PT_RANGE_3 */                  CONFIGTYPE_8,
  /* CONFIGITEM_PT_RANGE_4 */                  CONFIGTYPE_8,
  /* CONFIGITEM_PT_RANGE_5 */                  CONFIGTYPE_8,
  /* CONFIGITEM_PT_RANGE_6 */                  CONFIGTYPE_8,
  /* CONFIGITEM_PT_RANGE_7 */                  CONFIGTYPE_8,
  /* CONFIGITEM_PT_RANGE_8 */                  CONFIGTYPE_8,
  /* CONFIGITEM_MAGCARD_IFS */                 CONFIGTYPE_BOOL,
  /* CONFIGITEM_MAGCARD_FIELDS */              CONFIGTYPE_8,
  /* CONFIGITEM_MAGCARD_OFFSET */              CONFIGTYPE_8,
  /* CONFIGITEM_MAGCARD_DIGITS */              CONFIGTYPE_8,
  /* CONFIGITEM_ALARMS */                      CONFIGTYPE_STRING,
  /* CONFIGITEM_FILTERS */                     CONFIGTYPE_STRING,
  /* CONFIGITEM_ALARMSTATE */                  CONFIGTYPE_8,
  /* CONFIGITEM_DOORSTATE */                   CONFIGTYPE_8,
  /* CONFIGITEM_DPACDEBUG */                   CONFIGTYPE_BOOL,
  /* CONFIGITEM_FAILOPENSECURE */              CONFIGTYPE_BOOL,
  /* CONFIGITEM_REPLACED_VOLTAGE */            CONFIGTYPE_8,
  /* CONFIGITEM_RX_HELD_TIME */                CONFIGTYPE_8,
  /* CONFIGITEM_PACKET_TIMEOUT */              CONFIGTYPE_8,
  /* CONFIGITEM_EXTENDEDRESPONSE */            CONFIGTYPE_BOOL,
  /* CONFIGITEM_PASSAGEMODEINDICATOR */        CONFIGTYPE_BOOL,
  /* CONFIGITEM_PFMRETURNTIME */               CONFIGTYPE_8
};


/*
 *  Dissectors for each command
 */
static void dissect_r3_cmd_response (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_handshake (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_killsession (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_queryserialnumber (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_queryversion (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_setdatetime (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_querydatetime (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_setconfig (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_getconfig (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_manageuser (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_deleteusers (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_defineexception (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_defineexceptiongroup (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_definecalendar (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_definetimezone (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_rmtauthretry (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_filters (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_alarmconfigure (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_eventlogdump (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_declinedlogdump (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_alarmlogdump (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_downloadfirmware (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_downloadfirmwaretimeout (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_powertableselection (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_clearnvram (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_dpac (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_selftest (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_reset (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_logwrite (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_mfgcommand (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_nvrambackup (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmd_extendedresponse (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);

static void (*r3command_dissect []) (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *r3_tree) =
{
  /* CMD_RESPONSE */                dissect_r3_cmd_response,
  /* CMD_HANDSHAKE */               dissect_r3_cmd_handshake,
  /* CMD_KILLSESSION */             dissect_r3_cmd_killsession,
  /* CMD_QUERYSERIALNUMBER */       dissect_r3_cmd_queryserialnumber,
  /* CMD_QUERYVERSION */            dissect_r3_cmd_queryversion,
  /* CMD_SETDATETIME */             dissect_r3_cmd_setdatetime,
  /* CMD_QUERYDATETIME */           dissect_r3_cmd_querydatetime,
  /* CMD_SETCONFIG */               dissect_r3_cmd_setconfig,
  /* CMD_GETCONFIG */               dissect_r3_cmd_getconfig,
  /* CMD_MANAGEUSER */              dissect_r3_cmd_manageuser,
  /* CMD_DELETEUSERS */             dissect_r3_cmd_deleteusers,
  /* CMD_DEFINEEXCEPTION */         dissect_r3_cmd_defineexception,
  /* CMD_DEFINEEXCEPTIONGROUP */    dissect_r3_cmd_defineexceptiongroup,
  /* CMD_DEFINECALENDAR */          dissect_r3_cmd_definecalendar,
  /* CMD_DEFINETIMEZONE */          dissect_r3_cmd_definetimezone,
  /* CMD_RMTAUTHRETRY */            dissect_r3_cmd_rmtauthretry,
  /* CMD_FILTERS */                 dissect_r3_cmd_filters,
  /* CMD_ALARMCONFIGURE */          dissect_r3_cmd_alarmconfigure,
  /* CMD_EVENTLOGDUMP */            dissect_r3_cmd_eventlogdump,
  /* CMD_DECLINEDLOGDUMP */         dissect_r3_cmd_declinedlogdump,
  /* CMD_ALARMLOGDUMP */            dissect_r3_cmd_alarmlogdump,
  /* CMD_DOWNLOADFIRMWARE */        dissect_r3_cmd_downloadfirmware,
  /* CMD_DOWNLOADFIRMWARETIMEOUT */ dissect_r3_cmd_downloadfirmwaretimeout,
  /* CMD_POWERTABLESELECTION */     dissect_r3_cmd_powertableselection,
  /* CMD_CLEARNVRAM */              dissect_r3_cmd_clearnvram,
  /* CMD_DPAC */                    dissect_r3_cmd_dpac,
  /* CMD_SELFTEST */                dissect_r3_cmd_selftest,
  /* CMD_RESET */                   dissect_r3_cmd_reset,
  /* CMD_LOGWRITE */                dissect_r3_cmd_logwrite,
  /* CMD_MFGCOMMAND */              dissect_r3_cmd_mfgcommand,
  /* CMD_NVRAMBACKUP */             dissect_r3_cmd_nvrambackup,
  /* CMD_EXTENDEDRESPONSE */        dissect_r3_cmd_extendedresponse
};

static void dissect_r3_cmdmfg_setserialnumber (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_setcryptkey (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_dumpnvram (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_terminal (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_remoteunlock (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_auxctlrversion (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_iopins (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_adcs (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_hardwareid (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_checkpointlogdump (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_checkpointlogclear (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_readregisters (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_forceoptions (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_commuser (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_dumpkeypad (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_batterycheck (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_ramrefresh (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_taskflags (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_timerchain (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_peekpoke (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_lockstate (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_capabilities (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_dumpm41t81 (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_debuglogdump (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_debuglogclear (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_testwdt (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_querycksum (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_validatechecksums (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_rebuildlrucache (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_tzupdate (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_testpreserve (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_mortisestatelogdump (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_mortisestatelogclear (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_mortisepins (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_cmdmfg_haltandcatchfire (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);

static void (*r3commandmfg_dissect []) (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *r3_tree) =
{
  /* CMDMFG_SETSERIALNUMBER */       dissect_r3_cmdmfg_setserialnumber,
  /* CMDMFG_SETCRYPTKEY */           dissect_r3_cmdmfg_setcryptkey,
  /* CMDMFG_DUMPNVRAM */             dissect_r3_cmdmfg_dumpnvram,
  /* CMDMFG_TERMINAL */              dissect_r3_cmdmfg_terminal,
  /* CMDMFG_REMOTEUNLOCK */          dissect_r3_cmdmfg_remoteunlock,
  /* CMDMFG_AUXCTLRVERSION */        dissect_r3_cmdmfg_auxctlrversion,
  /* CMDMFG_IOPINS */                dissect_r3_cmdmfg_iopins,
  /* CMDMFG_ADCS */                  dissect_r3_cmdmfg_adcs,
  /* CMDMFG_HARDWAREID */            dissect_r3_cmdmfg_hardwareid,
  /* CMDMFG_CHECKPOINTLOGDUMP */     dissect_r3_cmdmfg_checkpointlogdump,
  /* CMDMFG_CHECKPOINTLOGCLEAR */    dissect_r3_cmdmfg_checkpointlogclear,
  /* CMDMFG_READREGISTERS */         dissect_r3_cmdmfg_readregisters,
  /* CMDMFG_FORCEOPTIONS */          dissect_r3_cmdmfg_forceoptions,
  /* CMDMFG_COMMUSER */              dissect_r3_cmdmfg_commuser,
  /* CMDMFG_DUMPKEYPAD */            dissect_r3_cmdmfg_dumpkeypad,
  /* CMDMFG_BATTERYCHECK */          dissect_r3_cmdmfg_batterycheck,
  /* CMDMFG_RAMREFRESH */            dissect_r3_cmdmfg_ramrefresh,
  /* CMDMFG_TASKFLAGS */             dissect_r3_cmdmfg_taskflags,
  /* CMDMFG_TIMERCHAIN */            dissect_r3_cmdmfg_timerchain,
  /* CMDMFG_PEEKPOKE */              dissect_r3_cmdmfg_peekpoke,
  /* CMDMFG_LOCKSTATE */             dissect_r3_cmdmfg_lockstate,
  /* CMDMFG_CAPABILITIES */          dissect_r3_cmdmfg_capabilities,
  /* CMDMFG_DUMPM41T81 */            dissect_r3_cmdmfg_dumpm41t81,
  /* CMDMFG_DEBUGLOGDUMP */          dissect_r3_cmdmfg_debuglogdump,
  /* CMDMFG_DEBUGLOGCLEAR */         dissect_r3_cmdmfg_debuglogclear,
  /* CMDMFG_TESTWDT */               dissect_r3_cmdmfg_testwdt,
  /* CMDMFG_QUERYCKSUM */            dissect_r3_cmdmfg_querycksum,
  /* CMDMFG_VALIDATECHECKSUMS */     dissect_r3_cmdmfg_validatechecksums,
  /* CMDMFG_REBUILDLRUCACHE */       dissect_r3_cmdmfg_rebuildlrucache,
  /* CMDMFG_TZUPDATE */              dissect_r3_cmdmfg_tzupdate,
  /* CMDMFG_TESTPRESERVE */          dissect_r3_cmdmfg_testpreserve,
  /* CMDMFG_MORTISESTATELOGDUMP */   dissect_r3_cmdmfg_mortisestatelogdump,
  /* CMDMFG_MORTISESTATELOGCLEAR */  dissect_r3_cmdmfg_mortisestatelogclear,
  /* CMDMFG_MORTISEPINS */           dissect_r3_cmdmfg_mortisepins,
  /* CMDMFG_HALTANDCATCHFIRE */      dissect_r3_cmdmfg_haltandcatchfire
};

static void dissect_r3_response_singlebyte (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_response_hasdata (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);

static void (*r3response_dissect []) (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *r3_tree) =
{
  /* RESPONSETYPE_OK */                  dissect_r3_response_singlebyte,
  /* RESPONSETYPE_ERROR */               dissect_r3_response_singlebyte,
  /* RESPONSETYPE_HASDATA */             dissect_r3_response_hasdata,
  /* RESPONSETYPE_NOHANDLER */           dissect_r3_response_singlebyte,
  /* RESPONSETYPE_NOSESSION */           dissect_r3_response_singlebyte,
  /* RESPONSETYPE_BADCOMMAND */          dissect_r3_response_singlebyte,
  /* RESPONSETYPE_BADPARAMETER */        dissect_r3_response_singlebyte,
  /* RESPONSETYPE_BADPARAMETERLEN */     dissect_r3_response_singlebyte,
  /* RESPONSETYPE_MISSINGPARAMETER */    dissect_r3_response_singlebyte,
  /* RESPONSETYPE_DUPLICATEPARAMETER */  dissect_r3_response_singlebyte,
  /* RESPONSETYPE_PARAMETERCONFLICT */   dissect_r3_response_singlebyte,
  /* RESPONSETYPE_BADDEVICE */           dissect_r3_response_singlebyte,
  /* RESPONSETYPE_NVRAMERROR */          dissect_r3_response_singlebyte,
  /* RESPONSETYPE_NVRAMERRORNOACK */     dissect_r3_response_singlebyte,
  /* RESPONSETYPE_NVRAMERRORNOACK32 */   dissect_r3_response_singlebyte,
  /* RESPONSETYPE_NOTI2CADDRESS */       dissect_r3_response_singlebyte,
  /* RESPONSETYPE_FIRMWAREERROR */       dissect_r3_response_singlebyte,
  /* RESPONSETYPE_DUMPINPROGRESS */      dissect_r3_response_singlebyte,
  /* RESPONSETYPE_INTERNALERROR */       dissect_r3_response_singlebyte,
  /* RESPONSETYPE_NOTIMPLEMENTED */      dissect_r3_response_singlebyte,
  /* RESPONSETYPE_PINFORMATERROR */      dissect_r3_response_singlebyte,
  /* RESPONSETYPE_PINEXISTS */           dissect_r3_response_singlebyte,
  /* RESPONSETYPE_PINNOTFOUND */         dissect_r3_response_singlebyte,
  /* RESPONSETYPE_USERACTIVE */          dissect_r3_response_singlebyte,
  /* RESPONSETYPE_USERINACTIVE */        dissect_r3_response_singlebyte,
  /* RESPONSETYPE_PARENTNOTFOUND */      dissect_r3_response_singlebyte,
  /* RESPONSETYPE_NOCHAIN */             dissect_r3_response_singlebyte,
  /* RESPONSETYPE_CAUGHTINLOOP */        dissect_r3_response_singlebyte,
  /* RESPONSETYPE_EVENTFILTERED */       dissect_r3_response_singlebyte,
  /* RESPONSETYPE_PAYLOADTOOLARGE */     dissect_r3_response_singlebyte,
  /* RESPONSETYPE_ENDOFDATA */           dissect_r3_response_singlebyte,
  /* RESPONSETYPE_RMTAUTHREJECTED */     dissect_r3_response_singlebyte,
  /* RESPONSETYPE_NVRAMVERSIONERROR */   dissect_r3_response_singlebyte,
  /* RESPONSETYPE_NOHARDWARE */          dissect_r3_response_singlebyte,
  /* RESPONSETYPE_SCHEDULERCONFLICT */   dissect_r3_response_singlebyte,
  /* RESPONSETYPE_NVRAMWRITEERROR */     dissect_r3_response_singlebyte,
  /* RESPONSETYPE_DECLINEDFILTERED */    dissect_r3_response_singlebyte,
  /* RESPONSETYPE_NECONFIGPARM */        dissect_r3_response_singlebyte,
  /* RESPONSETYPE_FLASHERASEERROR */     dissect_r3_response_singlebyte,
  /* RESPONSETYPE_FLASHWRITEERROR */     dissect_r3_response_singlebyte,
  /* RESPONSETYPE_BADNVBACKUP */         dissect_r3_response_singlebyte,
  /* RESPONSETYPE_EARLYACK */            dissect_r3_response_singlebyte,
  /* RESPONSETYPE_ALARMFILTERED */       dissect_r3_response_singlebyte,
  /* RESPONSETYPE_ACVFAILURE */          dissect_r3_response_singlebyte,
  /* RESPONSETYPE_USERCHECKSUMERROR */   dissect_r3_response_singlebyte,
  /* RESPONSETYPE_CHECKSUMERROR */       dissect_r3_response_singlebyte,
  /* RESPONSETYPE_RTCSQWFAILURE */       dissect_r3_response_singlebyte,
  /* RESPONSETYPE_PRIORITYSHUTDOWN */    dissect_r3_response_singlebyte,
  /* RESPONSETYPE_NOTMODIFIABLE */       dissect_r3_response_singlebyte,
  /* RESPONSETYPE_CANTPRESERVE */        dissect_r3_response_singlebyte,
  /* RESPONSETYPE_INPASSAGEMODE */       dissect_r3_response_singlebyte
};

static void dissect_r3_upstreamcommand_reserved (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_debugmsg (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_queryversion (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_querydatetime (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_queryserialnumber (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_dumpeventlog (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_dumpnvram (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_rmtquthrequest (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_retrieveuser (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_queryconfig (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_rmteventlogrecord (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_dpac (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_notify (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_mfg (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_eventlogwarning (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_dumpnvramrle (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_rmtdeclinedrecord (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_declinedwarning (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_dumpdeclinedlog (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_rmtalarmrecord (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_alarmwarning (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_dumpalarmlog (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_connectscheduler (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_connectcommuser (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_commandalarm (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreamcommand_dumpdebuglog (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);

static void (*r3upstreamcommand_dissect []) (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *r3_tree) =
{
  /* UPSTREAMCOMMAND_RESERVED */           dissect_r3_upstreamcommand_reserved,
  /* UPSTREAMCOMMAND_DEBUGMSG */           dissect_r3_upstreamcommand_debugmsg,
  /* UPSTREAMCOMMAND_QUERYVERSION */       dissect_r3_upstreamcommand_queryversion,
  /* UPSTREAMCOMMAND_QUERYDATETIME */      dissect_r3_upstreamcommand_querydatetime,
  /* UPSTREAMCOMMAND_QUERYSERIALNUMBER */  dissect_r3_upstreamcommand_queryserialnumber,
  /* UPSTREAMCOMMAND_DUMPEVENTLOG */       dissect_r3_upstreamcommand_dumpeventlog,
  /* UPSTREAMCOMMAND_DUMPNVRAM */          dissect_r3_upstreamcommand_dumpnvram,
  /* UPSTREAMCOMMAND_RMTAUTHREQUEST */     dissect_r3_upstreamcommand_rmtquthrequest,
  /* UPSTREAMCOMMAND_RETRIEVEUSER */       dissect_r3_upstreamcommand_retrieveuser,
  /* UPSTREAMCOMMAND_QUERYCONFIG */        dissect_r3_upstreamcommand_queryconfig,
  /* UPSTREAMCOMMAND_RMTEVENTLOGRECORD */  dissect_r3_upstreamcommand_rmteventlogrecord,
  /* UPSTREAMCOMMAND_DPAC */               dissect_r3_upstreamcommand_dpac,
  /* UPSTREAMCOMMAND_NOTIFY */             dissect_r3_upstreamcommand_notify,
  /* UPSTREAMCOMMAND_MFG */                dissect_r3_upstreamcommand_mfg,
  /* UPSTREAMCOMMAND_EVENTLOGWARNING */    dissect_r3_upstreamcommand_eventlogwarning,
  /* UPSTREAMCOMMAND_DUMPNVRAMRLE */       dissect_r3_upstreamcommand_dumpnvramrle,
  /* UPSTREAMCOMMAND_RMTDECLINEDRECORD */  dissect_r3_upstreamcommand_rmtdeclinedrecord,
  /* UPSTREAMCOMMAND_DECLINEDWARNING */    dissect_r3_upstreamcommand_declinedwarning,
  /* UPSTREAMCOMMAND_DUMPDECLINEDLOG */    dissect_r3_upstreamcommand_dumpdeclinedlog,
  /* UPSTREAMCOMMAND_RMTALARMRECORD */     dissect_r3_upstreamcommand_rmtalarmrecord,
  /* UPSTREAMCOMMAND_ALARMWARNING */       dissect_r3_upstreamcommand_alarmwarning,
  /* UPSTREAMCOMMAND_DUMPALARMLOG */       dissect_r3_upstreamcommand_dumpalarmlog,
  /* UPSTREAMCOMMAND_CONNECTSCHEDULER */   dissect_r3_upstreamcommand_connectscheduler,
  /* UPSTREAMCOMMAND_CONNECTCOMMUSER */    dissect_r3_upstreamcommand_connectcommuser,
  /* UPSTREAMCOMMAND_CONNECTALARM */       dissect_r3_upstreamcommand_commandalarm,
  /* UPSTREAMCOMMAND_DUMPDEBUGLOG */       dissect_r3_upstreamcommand_dumpdebuglog
};

static void dissect_r3_upstreammfgfield_iopins (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_adcs (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_hardwareid (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_checkpointlog (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_cpuregisters (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_taskflags (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_timerchain (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_peekpoke (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_lockstate (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_capabilities (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_dumpm41t81 (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_nvramchecksumvalue (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_checksumresults (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_mortisestatelog (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_mortisepins (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_keypadchar (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_magcard (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);
static void dissect_r3_upstreammfgfield_proxcard (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree);

static void (*r3upstreammfgfield_dissect []) (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *r3_tree) =
{
  /* MFGFIELD_IOPINS */              dissect_r3_upstreammfgfield_iopins,
  /* MFGFIELD_ADCS */                dissect_r3_upstreammfgfield_adcs,
  /* MFGFIELD_HARDWAREID */          dissect_r3_upstreammfgfield_hardwareid,
  /* MFGFIELD_CHECKPOINTLOG */       dissect_r3_upstreammfgfield_checkpointlog,
  /* MFGFIELD_CPUREGISTERS */        dissect_r3_upstreammfgfield_cpuregisters,
  /* MFGFIELD_TASKFLAGS */           dissect_r3_upstreammfgfield_taskflags,
  /* MFGFIELD_TIMERCHAIN */          dissect_r3_upstreammfgfield_timerchain,
  /* MFGFIELD_PEEKPOKE */            dissect_r3_upstreammfgfield_peekpoke,
  /* MFGFIELD_LOCKSTATE */           dissect_r3_upstreammfgfield_lockstate,
  /* MFGFIELD_CAPABILITIES */        dissect_r3_upstreammfgfield_capabilities,
  /* MFGFIELD_DUMPM41T81 */          dissect_r3_upstreammfgfield_dumpm41t81,
  /* MFGFIELD_NVRAMCHECKSUMVALUE */  dissect_r3_upstreammfgfield_nvramchecksumvalue,
  /* MFGFIELD_CHECKSUMRESULTS */     dissect_r3_upstreammfgfield_checksumresults,
  /* MFGFIELD_MORTISESTATELOG */     dissect_r3_upstreammfgfield_mortisestatelog,
  /* MFGFIELD_MORTISEPINS */         dissect_r3_upstreammfgfield_mortisepins,
  /* MFGFIELD_KEYPADCHAR */          dissect_r3_upstreammfgfield_keypadchar,
  /* MFGFIELD_MAGCARD */             dissect_r3_upstreammfgfield_magcard,
  /* MFGFIELD_PROXCARD */            dissect_r3_upstreammfgfield_proxcard
};

/*
 * ***************************************************************************
 *
 *  Cannot use wsutil/crc routines as ccitt-x25 uses a starting value of 0xffff
 *  and we use 0x0000 (legacy compatibility).  If an override method to set
 *  the starting value existed, these could be replaced.
 */
static const guint16 ccitt_16 [256] =
{
  0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
  0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
  0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
  0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
  0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
  0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
  0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
  0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
  0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
  0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
  0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
  0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
  0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
  0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
  0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
  0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
  0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
  0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
  0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
  0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
  0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
  0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
  0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
  0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
  0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
  0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
  0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
  0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
  0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
  0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
  0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
  0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
};

static guint16
utilCrcCalculate (const void *ptr, guint16 len, guint16 crc)
{
  const guint8 *p = (guint8 *) ptr;

  while (len--)
    crc = (guint16) ((crc << 8) ^ ccitt_16 [(crc >> 8) ^ *p++]);

  return crc;
}

/*
 * ***************************************************************************
 */
static void
dissect_serialnumber (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree, int hf_index)
{
  proto_item  *sn_item;
  proto_tree  *sn_tree;
  const gchar *s;

  tvb_ensure_bytes_exist (tvb, start_offset, 16);

  if (!tree)
    return;

  sn_item = proto_tree_add_item (tree, hf_index, tvb, start_offset, 16, ENC_ASCII|ENC_NA);
  sn_tree = proto_item_add_subtree (sn_item, ett_r3serialnumber);

  s = tvb_get_ephemeral_string (tvb, start_offset +  0, 2);
  proto_tree_add_text (sn_tree, tvb, start_offset +  0, 2, "Manufacturer .. : %s (%s)", s, str_to_str (s, r3_snmanufacturernames, "[Unknown]"));
  s = tvb_get_ephemeral_string (tvb, start_offset +  2, 1);
  proto_tree_add_text (sn_tree, tvb, start_offset +  2, 1, "Year .......... : %s (%s)", s, str_to_str (s, r3_snyearnames, "[Unknown]"));
  s = tvb_get_ephemeral_string (tvb, start_offset +  3, 2);
  proto_tree_add_text (sn_tree, tvb, start_offset +  3, 2, "Week .......... : %s",      s);
  s = tvb_get_ephemeral_string (tvb, start_offset +  5, 1);
  proto_tree_add_text (sn_tree, tvb, start_offset +  5, 1, "Model ......... : %s (%s)", s, str_to_str (s, r3_snmodelnames, "[Unknown]"));
  s = tvb_get_ephemeral_string (tvb, start_offset +  6, 4);
  proto_tree_add_text (sn_tree, tvb, start_offset +  6, 4, "Sequence ...... : %s",      s);
  s = tvb_get_ephemeral_string (tvb, start_offset + 10, 1);
  proto_tree_add_text (sn_tree, tvb, start_offset + 10, 1, "Group ......... : %s (%s)", s, str_to_str (s, r3_sngroupnames, "[Unknown]"));
  s = tvb_get_ephemeral_string (tvb, start_offset + 11, 1);
  proto_tree_add_text (sn_tree, tvb, start_offset + 11, 1, "NID ........... : %s (%s)", s, str_to_str (s, r3_snnidnames, "[Unknown]"));
  s = tvb_get_ephemeral_string (tvb, start_offset + 12, 2);
  proto_tree_add_text (sn_tree, tvb, start_offset + 12, 2, "HID ........... : %s (%s)", s, str_to_str (s, r3_snhidnames, "[Unknown]"));
  s = tvb_get_ephemeral_string (tvb, start_offset + 14, 1);
  proto_tree_add_text (sn_tree, tvb, start_offset + 14, 1, "Power Supply .. : %s (%s)", s, str_to_str (s, r3_snpowersupplynames, "[Unknown]"));
  s = tvb_get_ephemeral_string (tvb, start_offset + 15, 1);
  proto_tree_add_text (sn_tree, tvb, start_offset + 15, 1, "Mortise ....... : %s (%s)", s, str_to_str (s, r3_snmortisenames, "[Unknown]"));
}

/*
 * ***************************************************************************
 *
 * We've already ensured we have enough bytes in the table via tvb_ensure_bytes_exist()
 *
 */
static void
dissect_r3_upstreamfields (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  guint32 offset = 0;

  DISSECTOR_ASSERT(start_offset == 0);

  while (offset < tvb_reported_length (tvb))
  {
    guint32      fieldLength = tvb_get_guint8 (tvb, offset + 0);
    guint32      fieldType   = tvb_get_guint8 (tvb, offset + 1);
    guint32      dataLength  = fieldLength - 2;
    proto_item  *upstreamfield_item;
    proto_item  *upstreamfield_length;
    proto_tree  *upstreamfield_tree;
    const gchar *usfn;

    usfn = val_to_str_ext_const (fieldType, &r3_upstreamfieldnames_ext, "[Unknown Field]");

    upstreamfield_item = proto_tree_add_none_format (tree, hf_r3_upstreamfield, tvb, offset + 0, fieldLength, "Upstream Field: %s (%u)", usfn, fieldType);
    upstreamfield_tree = proto_item_add_subtree (upstreamfield_item, ett_r3upstreamfield);

    upstreamfield_length = proto_tree_add_item (upstreamfield_tree, hf_r3_upstreamfieldlength, tvb, offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (upstreamfield_tree, hf_r3_upstreamfieldtype, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);

    if (fieldLength < 2)
    {
      dataLength = 0;
      expert_add_info_format (pinfo, upstreamfield_length, PI_UNDECODED, PI_WARN,
                              "Malformed length value -- all fields are at least 2 octets.");
    }

    offset += 2;

    switch (fieldType)
    {
      /*
       *  Booleans, 8 & 16 bit values
       */
      case UPSTREAMFIELD_NOTUSED :
      case UPSTREAMFIELD_PRIMARYPIN :
      case UPSTREAMFIELD_AUXPIN :
      case UPSTREAMFIELD_ACCESSALWAYS :
      case UPSTREAMFIELD_CACHED :
      case UPSTREAMFIELD_ENTRYDEVICE :
      case UPSTREAMFIELD_PPMIFIELDTYPE :
      case UPSTREAMFIELD_RESPONSEWINDOW :
      case UPSTREAMFIELD_USERTYPE :
      case UPSTREAMFIELD_PRIMARYFIELDTYPE :
      case UPSTREAMFIELD_AUXFIELDTYPE :
      case UPSTREAMFIELD_ACCESSMODE :
      case UPSTREAMFIELD_USECOUNT :
      case UPSTREAMFIELD_EXCEPTIONGROUP :
      case UPSTREAMFIELD_NAR :
      case UPSTREAMFIELD_SEQUENCENUMBER :
      case UPSTREAMFIELD_USERNUMBER :
      case UPSTREAMFIELD_EVENTLOGRECORDCOUNT :
      case UPSTREAMFIELD_DECLINEDRECORDCOUNT :
      case UPSTREAMFIELD_ALARMRECORDCOUNT :
        proto_tree_add_item (upstreamfield_tree, hf_r3_upstreamfieldarray [fieldType], tvb, offset, dataLength, ENC_LITTLE_ENDIAN);
        break;

      /*
       *  Strings
       */
      case UPSTREAMFIELD_PIN :
      case UPSTREAMFIELD_VERSION :
      case UPSTREAMFIELD_AUXCTLRVERSION :
        proto_tree_add_item (upstreamfield_tree, hf_r3_upstreamfieldarray [fieldType], tvb, offset, dataLength, ENC_ASCII|ENC_NA);
        break;

      /*
       *  Special types
       */
      case UPSTREAMFIELD_SERIALNUMBER :
        {
          tvbuff_t *sn_tvb = tvb_new_subset (tvb, offset, dataLength, dataLength);

          dissect_serialnumber (sn_tvb, 0, length, pinfo, upstreamfield_tree, hf_r3_upstreamfieldarray [fieldType]);
        }
        break;

      case UPSTREAMFIELD_EVENTLOGRECORD :
        {
          if (dataLength != 9)
          {
            expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN,
                                    "Malformed event log field -- expected 9 octets");
          }
          else
          {
            proto_item *eventlog_item;
            proto_tree *eventlog_tree;

            if (!upstreamfield_tree)
              break;

            eventlog_item = proto_tree_add_text (upstreamfield_tree, tvb, offset, 9, "Event Log Record");
            eventlog_tree = proto_item_add_subtree (eventlog_item, ett_r3eventlogrecord);

            proto_tree_add_item (eventlog_tree, hf_r3_eventlog_year,       tvb, offset + 0, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (eventlog_tree, hf_r3_eventlog_month,      tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (eventlog_tree, hf_r3_eventlog_day,        tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (eventlog_tree, hf_r3_eventlog_hour,       tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (eventlog_tree, hf_r3_eventlog_minute,     tvb, offset + 4, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (eventlog_tree, hf_r3_eventlog_second,     tvb, offset + 5, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (eventlog_tree, hf_r3_eventlog_usernumber, tvb, offset + 6, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (eventlog_tree, hf_r3_eventlog_event,      tvb, offset + 8, 1, ENC_LITTLE_ENDIAN);
          }
        }
        break;

      case UPSTREAMFIELD_DATETIME :
        {
          if (dataLength != 8)
          {
            expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN,
                                    "Malformed date/time field -- expected 8 octets");
          }
          else
          {
            proto_item *datetime_item;
            proto_tree *datetime_tree;

            if (!upstreamfield_tree)
              break;

            datetime_item = proto_tree_add_text (upstreamfield_tree, tvb, offset, 8, "Date/Time: %02u/%02u/%02u-%u %02u:%02u:%02u %u",
                tvb_get_guint8 (tvb, offset + 0), tvb_get_guint8 (tvb, offset + 1), tvb_get_guint8 (tvb, offset + 2), tvb_get_guint8 (tvb, offset + 3),
                tvb_get_guint8 (tvb, offset + 4), tvb_get_guint8 (tvb, offset + 5), tvb_get_guint8 (tvb, offset + 6), tvb_get_guint8 (tvb, offset + 7));
            datetime_tree = proto_item_add_subtree (datetime_item, ett_r3datetime);

            proto_tree_add_item (datetime_tree, hf_r3_datetime_year,    tvb, offset + 0, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (datetime_tree, hf_r3_datetime_month,   tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (datetime_tree, hf_r3_datetime_day,     tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (datetime_tree, hf_r3_datetime_dow,     tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (datetime_tree, hf_r3_datetime_hours,   tvb, offset + 4, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (datetime_tree, hf_r3_datetime_minutes, tvb, offset + 5, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (datetime_tree, hf_r3_datetime_seconds, tvb, offset + 6, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (datetime_tree, hf_r3_datetime_dst,     tvb, offset + 7, 1, ENC_LITTLE_ENDIAN);
          }
        }
        break;

      case UPSTREAMFIELD_DECLINEDRECORD :
        {

          if (dataLength != 49)
          {
            expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN,
                                    "Malformed declined log field -- expected 49 octets");
          }
          else
          {
            proto_item *declinedlog_item;
            proto_tree *declinedlog_tree;
            guint8 cred1type;
            guint8 cred2type;

            if (!upstreamfield_tree)
              break;

            declinedlog_item = proto_tree_add_text (upstreamfield_tree, tvb, offset, 49, "Declined Log Record");
            declinedlog_tree = proto_item_add_subtree (declinedlog_item, ett_r3declinedlogrecord);

            proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_year,       tvb, offset + 0, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_month,      tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_day,        tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_hour,       tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_minute,     tvb, offset + 4, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_second,     tvb, offset + 5, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_usernumber, tvb, offset + 6, 2, ENC_LITTLE_ENDIAN);

            cred1type = tvb_get_guint8 (tvb, offset + 8) & 0x07;
            cred2type = (tvb_get_guint8 (tvb, offset + 8) & 0x38) >> 3;

            proto_tree_add_uint (declinedlog_tree, hf_r3_declinedlog_cred1type,  tvb, offset, 1, cred1type);
            proto_tree_add_uint (declinedlog_tree, hf_r3_declinedlog_cred2type,  tvb, offset, 1, cred2type);
            proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_cred1,      tvb, offset +  9, 19, ENC_NA);
            proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_cred2,      tvb, offset + 28, 19, ENC_NA);
          }
        }
        break;

      case UPSTREAMFIELD_EXPIREON :
        {
          if (dataLength != 3)
          {
            expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN,
                                    "Malformed expiration field -- expected 3 octets");
          }
          else
          {
            proto_item *expireon_item;
            proto_tree *expireon_tree;

            if (!upstreamfield_tree)
              break;

            expireon_item = proto_tree_add_text (upstreamfield_tree, tvb, offset, 3, "Expire YY/MM/DD: %02u/%02u/%02u",
                tvb_get_guint8 (tvb, offset + 2), tvb_get_guint8 (tvb, offset + 0), tvb_get_guint8 (tvb, offset + 1));
            expireon_tree = proto_item_add_subtree (expireon_item, ett_r3expireon);

            proto_tree_add_item (expireon_tree, hf_r3_expireon_month, tvb, offset + 0, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (expireon_tree, hf_r3_expireon_day,   tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (expireon_tree, hf_r3_expireon_year,  tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
          }
        }
        break;

      case UPSTREAMFIELD_TIMEZONE :
        {
          if (dataLength != 4)
          {
            expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN,
                                    "Malformed timezone field -- expected 4 octets");
          }
          else
          {
            proto_item *timezone_item;
            proto_tree *timezone_tree;
            guint32 i;
            guint32 tz;

            if (!upstreamfield_tree)
              break;

            tz = tvb_get_letohl (tvb, offset);
            timezone_item = proto_tree_add_item (upstreamfield_tree, hf_r3_upstreamfieldarray [fieldType], tvb, offset, 4, ENC_LITTLE_ENDIAN);
            timezone_tree = proto_item_add_subtree (timezone_item, ett_r3timezone);

            for (i = 0; i < 32; i++)
              proto_tree_add_boolean (timezone_tree, hf_r3_timezonearray [i], tvb, offset, 4, tz);
          }
        }
        break;

      case UPSTREAMFIELD_ALARMRECORD :
        {
          if (dataLength != 9)
          {
            expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN,
                                    "Malformed alarm log field -- expected 9 octets");
          }
          else
          {
            proto_item *alarmlog_item;
            proto_tree *alarmlog_tree;

            if (!upstreamfield_tree)
              break;

            alarmlog_item = proto_tree_add_text (upstreamfield_tree, tvb, offset, 9, "Alarm Record");
            alarmlog_tree = proto_item_add_subtree (alarmlog_item, ett_r3alarmlogrecord);

            proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_year,       tvb, offset + 0, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_month,      tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_day,        tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_hour,       tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_minute,     tvb, offset + 4, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_second,     tvb, offset + 5, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_id,         tvb, offset + 6, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_usernumber, tvb, offset + 7, 2, ENC_LITTLE_ENDIAN);
          }
        }
        break;

      default :
        proto_tree_add_none_format (upstreamfield_tree, hf_r3_upstreamfielderror, tvb, offset, dataLength, "Unknown Field Type");
        break;
    }

    offset += dataLength;
  }
}

/*
 * ***************************************************************************
 *
 *  These are passed a tvb that contains whatever occurs after the [UPSTREAMCOMMAND_*] byte
 */
static void
dissect_r3_upstreamcommand_reserved (tvbuff_t *tvb _U_, guint32 start_offset _U_, guint32 length _U_, packet_info *pinfo, proto_tree *tree)
{
  expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN,
                          "\"Reserved\" Upstream Command value");
}

static void
dissect_r3_upstreamcommand_debugmsg (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *debugmsg_item;
  proto_tree *debugmsg_tree;

  if (!tree)
    return;

  DISSECTOR_ASSERT(start_offset == 0);

  debugmsg_item = proto_tree_add_text (tree, tvb, 0, -1, "Debug message");
  debugmsg_tree = proto_item_add_subtree (debugmsg_item, ett_r3debugmsg);

  proto_tree_add_item (debugmsg_tree, hf_r3_debugmsg, tvb, 1, -1, ENC_ASCII|ENC_NA);
}

static void
dissect_r3_upstreamcommand_queryversion (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  dissect_r3_upstreamfields (tvb, start_offset, length, pinfo, tree);
}

static void
dissect_r3_upstreamcommand_querydatetime (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  dissect_r3_upstreamfields (tvb, start_offset, length, pinfo, tree);
}

static void
dissect_r3_upstreamcommand_queryserialnumber (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  dissect_r3_upstreamfields (tvb, start_offset, length, pinfo, tree);
}

static void
dissect_r3_upstreamcommand_dumpeventlog (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  DISSECTOR_ASSERT(start_offset == 0);

  tvb_ensure_bytes_exist (tvb, 0, 11);

  if (length != 11)
  {
    expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN,
                            "Malformed event log record -- expected 10 octets");
  }
  else
  {
    proto_item  *eventlog_item;
    proto_tree  *eventlog_tree;
    const gchar *en;

    if (!tree)
      return;

    en = val_to_str_ext_const (tvb_get_guint8 (tvb, 10), &r3_eventnames_ext, "[Unknown Event]");

    eventlog_item = proto_tree_add_text (tree, tvb, start_offset, 10, "Event Log Record %u (%s)", tvb_get_letohs (tvb, 0), en);
    eventlog_tree = proto_item_add_subtree (eventlog_item, ett_r3eventlogrecord);

    proto_tree_add_item (eventlog_tree, hf_r3_eventlog_recordnumber, tvb,  0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (eventlog_tree, hf_r3_eventlog_year,         tvb,  2, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (eventlog_tree, hf_r3_eventlog_month,        tvb,  3, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (eventlog_tree, hf_r3_eventlog_day,          tvb,  4, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (eventlog_tree, hf_r3_eventlog_hour,         tvb,  5, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (eventlog_tree, hf_r3_eventlog_minute,       tvb,  6, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (eventlog_tree, hf_r3_eventlog_second,       tvb,  7, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (eventlog_tree, hf_r3_eventlog_usernumber,   tvb,  8, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (eventlog_tree, hf_r3_eventlog_event,        tvb, 10, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_upstreamcommand_dumpnvram (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  DISSECTOR_ASSERT(start_offset == 0);

  tvb_ensure_bytes_exist (tvb, 0, 3);

  if (!tree)
    return;

  proto_tree_add_item (tree, hf_r3_nvramdump_record, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_nvramdump_length, tvb, 2, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_nvramdump_data,   tvb, 3, tvb_get_guint8 (tvb, 2), ENC_NA);
}

static void
dissect_r3_upstreamcommand_rmtquthrequest (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  dissect_r3_upstreamfields (tvb, start_offset, length, pinfo, tree);
}

static void
dissect_r3_upstreamcommand_retrieveuser (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  dissect_r3_upstreamfields (tvb, start_offset, length, pinfo, tree);
}

static void
dissect_r3_upstreamcommand_queryconfig (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  guint32 offset = 0;

  DISSECTOR_ASSERT(start_offset == 0);

  if (!tree)
    return;

  while (offset < tvb_reported_length (tvb))
  {
    proto_item  *upstreamfield_item;
    proto_tree  *upstreamfield_tree;
    const gchar *ci;

    ci = val_to_str_ext_const (tvb_get_guint8 (tvb, offset + 1), &r3_configitemnames_ext, "[Unknown Configuration Item]");

    upstreamfield_item = proto_tree_add_text (tree, tvb, offset + 0, tvb_get_guint8 (tvb, offset + 0), "Config Field: %s (%u)", ci, tvb_get_guint8 (tvb, offset + 1));
    upstreamfield_tree = proto_item_add_subtree (upstreamfield_item, ett_r3upstreamfield);

    proto_tree_add_item (upstreamfield_tree, hf_r3_configitemlength, tvb, offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (upstreamfield_tree, hf_r3_configitem,       tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (upstreamfield_tree, hf_r3_configitemtype,   tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);

    switch (tvb_get_guint8 (tvb, offset + 2))
    {
      case CONFIGTYPE_NONE :
        proto_tree_add_item (upstreamfield_tree, hf_r3_configitemdata, tvb, offset + 3, tvb_get_guint8 (tvb, offset + 0) - 3, ENC_NA);
        break;

      case CONFIGTYPE_BOOL :
        proto_tree_add_item (upstreamfield_tree, hf_r3_configitemdata_bool, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
        break;

      case CONFIGTYPE_8 :
        proto_tree_add_item (upstreamfield_tree, hf_r3_configitemdata_8, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
        break;

      case CONFIGTYPE_16 :
        proto_tree_add_item (upstreamfield_tree, hf_r3_configitemdata_16, tvb, offset + 3, 2, ENC_LITTLE_ENDIAN);
        break;

      case CONFIGTYPE_32 :
        proto_tree_add_item (upstreamfield_tree, hf_r3_configitemdata_32, tvb, offset + 3, 4, ENC_LITTLE_ENDIAN);
        break;

      case CONFIGTYPE_STRING :
        proto_tree_add_item (upstreamfield_tree, hf_r3_configitemdata_string, tvb, offset + 3, tvb_get_guint8 (tvb, offset + 0) - 3, ENC_ASCII|ENC_NA);
        break;

      default :
        proto_tree_add_none_format (upstreamfield_tree, hf_r3_upstreamfielderror, tvb, offset + 3, tvb_get_guint8 (tvb, offset + 0) - 3, "Unknown Field Type");
        break;
    }

    offset += tvb_get_guint8 (tvb, offset + 0);
  }
}

static void
dissect_r3_upstreamcommand_rmteventlogrecord (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  dissect_r3_upstreamfields (tvb, start_offset, length, pinfo, tree);
}

static void
dissect_r3_upstreamcommand_dpac (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    DISSECTOR_ASSERT(start_offset == 0);
    /* XXX: hf[] entries for the following hf indexes originally missing */
    proto_tree_add_item (tree, hf_r3_dpacreply_stuff,  tvb, 2,  1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_dpacreply_length, tvb, 3,  1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_dpacreply_reply,  tvb, 4, -1, ENC_NA);
  }
}

static void
dissect_r3_upstreamcommand_notify (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  dissect_r3_upstreamfields (tvb, start_offset, length, pinfo, tree);
}

static void
dissect_r3_upstreamcommand_mfg (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *mfg_tree = NULL;
  guint8      mfg_fld;
  tvbuff_t   *mfg_tvb;

  DISSECTOR_ASSERT(start_offset == 0);

  mfg_tvb = tvb_new_subset_remaining (tvb, 2);
  mfg_fld = tvb_get_guint8 (tvb, 1);

  if (tree)
  {
    proto_item  *mfg_item;
    const gchar *cn;

    cn = val_to_str_ext_const (mfg_fld, &r3_mfgfieldnames_ext, "[Unknown Mfg Field]");

    proto_tree_add_item (tree, hf_r3_mfgfield_length, tvb, 0, 1, ENC_LITTLE_ENDIAN);

    mfg_item = proto_tree_add_text (tree, tvb, 1, -1, "Upstream Manufacturing Field: %s (%u)", cn, mfg_fld);
    mfg_tree = proto_item_add_subtree (mfg_item, ett_r3commandmfg);

    proto_tree_add_item (mfg_tree, hf_r3_mfgfield, tvb, 1, 1, ENC_LITTLE_ENDIAN);
  }

  if (mfg_fld >= MFGFIELD_LAST)
  {
    expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN,
                            "Unknown manufacturing command value");
  }
  else if (r3upstreammfgfield_dissect [mfg_fld])
    (*r3upstreammfgfield_dissect [mfg_fld]) (mfg_tvb, 0, length, pinfo, mfg_tree);
}

static void
dissect_r3_upstreamcommand_eventlogwarning (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  dissect_r3_upstreamfields (tvb, start_offset, length, pinfo, tree);
}

static void
dissect_r3_upstreamcommand_dumpnvramrle (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
    return;

  DISSECTOR_ASSERT(start_offset == 0);

  proto_tree_add_item (tree, hf_r3_nvramdumprle_record, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_nvramdumprle_length, tvb, 3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_nvramdumprle_data,   tvb, 4, tvb_get_guint8 (tvb, 3), ENC_NA);
}

static void
dissect_r3_upstreamcommand_rmtdeclinedrecord (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  dissect_r3_upstreamfields (tvb, start_offset, length, pinfo, tree);
}

static void
dissect_r3_upstreamcommand_declinedwarning (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  dissect_r3_upstreamfields (tvb, start_offset, length, pinfo, tree);
}

static void
dissect_r3_upstreamcommand_dumpdeclinedlog (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *declinedlog_item;
  proto_tree *declinedlog_tree;
  guint8      cred1type;
  guint8      cred2type;

  if (!tree)
    return;

  DISSECTOR_ASSERT(start_offset == 0);

  declinedlog_item = proto_tree_add_text (tree, tvb, start_offset, 49, "Declined Log Record %u", tvb_get_letohs (tvb, 0));
  declinedlog_tree = proto_item_add_subtree (declinedlog_item, ett_r3declinedlogrecord);

  proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_recordnumber, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_year,         tvb, 2, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_month,        tvb, 3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_day,          tvb, 4, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_hour,         tvb, 5, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_minute,       tvb, 6, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_second,       tvb, 7, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_usernumber,   tvb, 8, 2, ENC_LITTLE_ENDIAN);

  cred1type = tvb_get_guint8 (tvb, 10) & 0x07;
  cred2type = (tvb_get_guint8 (tvb, 10) & 0x38) >> 3;

  proto_tree_add_uint (declinedlog_tree, hf_r3_declinedlog_cred1type, tvb, 10, 1, cred1type);
  proto_tree_add_uint (declinedlog_tree, hf_r3_declinedlog_cred2type, tvb, 10, 1, cred2type);
  proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_cred1, tvb, 11, 19, ENC_NA);
  proto_tree_add_item (declinedlog_tree, hf_r3_declinedlog_cred2, tvb, 30, 19, ENC_NA);
}

static void
dissect_r3_upstreamcommand_rmtalarmrecord (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  dissect_r3_upstreamfields (tvb, start_offset, length, pinfo, tree);
}

static void
dissect_r3_upstreamcommand_alarmwarning (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  dissect_r3_upstreamfields (tvb, start_offset, length, pinfo, tree);
}

static void
dissect_r3_upstreamcommand_dumpalarmlog (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *alarmlog_item;
  proto_tree *alarmlog_tree;

  if (!tree)
    return;

  DISSECTOR_ASSERT(start_offset == 0);

  alarmlog_item = proto_tree_add_text (tree, tvb, start_offset, 9, "Alarm Log Record %u", tvb_get_letohs (tvb, 0));
  alarmlog_tree = proto_item_add_subtree (alarmlog_item, ett_r3alarmlogrecord);

  proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_recordnumber, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_year,         tvb, 2, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_month,        tvb, 3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_day,          tvb, 4, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_hour,         tvb, 5, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_minute,       tvb, 6, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_second,       tvb, 7, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_id,           tvb, 8, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (alarmlog_tree, hf_r3_alarmlog_usernumber,   tvb, 9, 2, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_upstreamcommand_connectscheduler (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  dissect_r3_upstreamfields (tvb, start_offset, length, pinfo, tree);
}

static void
dissect_r3_upstreamcommand_connectcommuser (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  dissect_r3_upstreamfields (tvb, start_offset, length, pinfo, tree);
}

static void
dissect_r3_upstreamcommand_commandalarm (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  dissect_r3_upstreamfields (tvb, start_offset, length, pinfo, tree);
}

static void
dissect_r3_upstreamcommand_dumpdebuglog (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *debuglog_item;
  proto_tree *debuglog_tree;

  if (!tree)
    return;

  DISSECTOR_ASSERT(start_offset == 0);

  debuglog_item = proto_tree_add_text (tree, tvb, start_offset, 8, "Debug Log Record %u", tvb_get_letohs (tvb, 0));
  debuglog_tree = proto_item_add_subtree (debuglog_item, ett_r3debuglogrecord);

  proto_tree_add_item (debuglog_tree, hf_r3_debuglog_recordnumber, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (debuglog_tree, hf_r3_debuglog_flags,        tvb, 2, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (debuglog_tree, hf_r3_debuglog_tick,         tvb, 6, 2, ENC_LITTLE_ENDIAN);
}

/*
 * ***************************************************************************
 */
static void
dissect_r3_upstreammfgfield_iopins (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo, proto_tree *tree)
{
  gint len;

  DISSECTOR_ASSERT(start_offset == 0);

  len = MAX(0, tvb_length_remaining(tvb, start_offset));
  if (len % 3 != 0)
  {
    expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN,
                            "IOPINS data length not modulo 3 == 0");
  }
  else
  {
    char portname = 'A';
    gint i;

    if (!tree)
      return;

    for (i = 0; i < len; i += 3, portname++)
    {
      proto_item *port_item = proto_tree_add_text (tree, tvb, i, 3,
                                                   "Port %c Configuration", (portname == 'I') ? ++portname : portname);
      proto_tree *port_tree = proto_item_add_subtree (port_item, ett_r3iopins);

      proto_tree_add_item (port_tree, hf_r3_iopins_lat,  tvb, i + 0, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item (port_tree, hf_r3_iopins_port, tvb, i + 1, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item (port_tree, hf_r3_iopins_tris, tvb, i + 2, 1, ENC_LITTLE_ENDIAN);
    }
  }
}

static void
dissect_r3_upstreammfgfield_adcs (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo, proto_tree *tree)
{
  guint   len;
  guint32 i;

  if (!tree)
    return;

  DISSECTOR_ASSERT(start_offset == 0);

  len = tvb_reported_length(tvb);

  for (i = 0; i < MIN(len,8); i++)
  {
    proto_item *item = proto_tree_add_item (tree, hf_r3_adc [i], tvb, i, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text (item, " (%.2f Volts)", (float) tvb_get_guint8 (tvb, i) * 0.04154);
  }

  if (len > 8)
  {
    expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN,
                            "MFG Field: too many adc values");
  }

}

static void
dissect_r3_upstreammfgfield_hardwareid (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
    return;

  DISSECTOR_ASSERT(start_offset == 0);

  proto_tree_add_item (tree, hf_r3_hardwareid_board,  tvb, 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_hardwareid_cpuid,  tvb, 1, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_hardwareid_cpurev, tvb, 3, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_upstreammfgfield_checkpointlog (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *cpl_item;
  proto_tree *cpl_tree;
  guint       counter;
  gint        len;
  gint        i;

  if (!tree)
    return;

  DISSECTOR_ASSERT(start_offset == 0);

  len = tvb_length_remaining (tvb, 1);

  proto_tree_add_item (tree, hf_r3_checkpointlog_entryptr, tvb, 0, 1, ENC_LITTLE_ENDIAN);
  cpl_item = proto_tree_add_text (tree, tvb, 1, -1, "Checkpoint Log");
  cpl_tree = proto_item_add_subtree (cpl_item, ett_r3checkpointlog);

  counter = 0;
  for (i = 0; i < len; i += 2, counter++)
  {
    guint        rcon      = tvb_get_guint8 (tvb, i + 0);
    guint        cp        = tvb_get_guint8 (tvb, i + 1);
    proto_item  *cpe_item  = proto_tree_add_text (cpl_tree, tvb, i + 0, 2, "Checkpoint Log Entry %u", counter);
    proto_tree  *cpe_tree  = proto_item_add_subtree (cpe_item, ett_r3checkpointlogentry);
    guint        resettype;
    const gchar *desc;
    const gchar *resets [] = { "Stack underflow", "Stack overflow", "Power-On",
                               "Software", "Brown-out", "MCLR in sleep", "WDT",
                               "Normal", "[Unknown Reset Type]" };

    desc = val_to_str_ext_const (cp, &r3_checkpointnames_ext, "[Unknown Checkpoint]");

    if (rcon == 0xff)
      resettype = 8;
    else
    {
      rcon &= 0x1f;

      if (rcon == 0x1c)
        resettype = 2;
      else if ((rcon & 0x10) == 0x00)
        resettype = 3;
      else if ((rcon & 0x1d) == 0x1c)
        resettype = 4;
      else if ((rcon & 0x0c) == 0x08)
        resettype = 5;
      else if ((rcon & 0x0c) == 0x04)
        resettype = 6;
      else
        resettype = 7;
    }

    proto_item_append_text (cpe_item, " (%s, %s)", resets [resettype], desc);
    proto_item_append_text (
      proto_tree_add_item (cpe_tree, hf_r3_checkpointlog_rcon,       tvb, i + 0, 1, ENC_LITTLE_ENDIAN),
      " (%s)", resets [resettype]);
    proto_item_append_text (
      proto_tree_add_item (cpe_tree, hf_r3_checkpointlog_checkpoint, tvb, i + 1, 1, ENC_LITTLE_ENDIAN),
      " (%s)", desc);
  }
}

static void
dissect_r3_upstreammfgfield_cpuregisters (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree *tmp_tree [19];
  proto_item *cr_item;
  proto_tree *cr_tree;

  if (!tree)
    return;

  DISSECTOR_ASSERT(start_offset == 0);

  cr_item = proto_tree_add_text (tree, tvb, start_offset, -1, "CPU Registers");
  cr_tree = proto_item_add_subtree (cr_item, ett_r3cpuregisters);

  tmp_tree [ 0] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_intcon,  tvb,  0, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [ 1] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_intcon2, tvb,  1, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [ 2] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_intcon3, tvb,  2, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [ 3] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_pir1,    tvb,  3, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [ 4] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_pir2,    tvb,  4, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [ 5] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_pir3,    tvb,  5, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [ 6] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_pie1,    tvb,  6, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [ 7] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_pie2,    tvb,  7, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [ 8] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_pie3,    tvb,  8, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [ 9] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_ipr1,    tvb,  9, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [10] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_ipr2,    tvb, 10, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [11] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_ipr3,    tvb, 11, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [12] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_rcon,    tvb, 12, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [13] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_osccon,  tvb, 13, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [14] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_rcsta,   tvb, 14, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [15] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_txsta,   tvb, 15, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [16] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_rcsta2,  tvb, 16, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [17] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_txsta2,  tvb, 17, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);
  tmp_tree [18] = proto_item_add_subtree (proto_tree_add_item (cr_tree, hf_r3_cpuregisters_wdtcon,  tvb, 18, 1, ENC_LITTLE_ENDIAN), ett_r3cpuregister);

  proto_tree_add_item (tmp_tree [ 0], hf_r3_cpuregisters_intcon_rbif,     tvb,  0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 0], hf_r3_cpuregisters_intcon_int0if,   tvb,  0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 0], hf_r3_cpuregisters_intcon_tmr0if,   tvb,  0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 0], hf_r3_cpuregisters_intcon_rbie,     tvb,  0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 0], hf_r3_cpuregisters_intcon_int0ie,   tvb,  0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 0], hf_r3_cpuregisters_intcon_tmr0ie,   tvb,  0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 0], hf_r3_cpuregisters_intcon_giel,     tvb,  0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 0], hf_r3_cpuregisters_intcon_gieh,     tvb,  0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 1], hf_r3_cpuregisters_intcon2_rbip,    tvb,  1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 1], hf_r3_cpuregisters_intcon2_int3ip,  tvb,  1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 1], hf_r3_cpuregisters_intcon2_tmr0ip,  tvb,  1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 1], hf_r3_cpuregisters_intcon2_intedg3, tvb,  1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 1], hf_r3_cpuregisters_intcon2_intedg2, tvb,  1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 1], hf_r3_cpuregisters_intcon2_intedg1, tvb,  1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 1], hf_r3_cpuregisters_intcon2_intedg0, tvb,  1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 1], hf_r3_cpuregisters_intcon2_rbpu,    tvb,  1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 2], hf_r3_cpuregisters_intcon3_int1if,  tvb,  2, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 2], hf_r3_cpuregisters_intcon3_int2if,  tvb,  2, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 2], hf_r3_cpuregisters_intcon3_int3if,  tvb,  2, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 2], hf_r3_cpuregisters_intcon3_int1ie,  tvb,  2, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 2], hf_r3_cpuregisters_intcon3_int2ie,  tvb,  2, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 2], hf_r3_cpuregisters_intcon3_int3ie,  tvb,  2, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 2], hf_r3_cpuregisters_intcon3_int1ip,  tvb,  2, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 2], hf_r3_cpuregisters_intcon3_int2ip,  tvb,  2, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 3], hf_r3_cpuregisters_pir1_tmr1if,     tvb,  3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 3], hf_r3_cpuregisters_pir1_tmr2if,     tvb,  3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 3], hf_r3_cpuregisters_pir1_ccp1if,     tvb,  3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 3], hf_r3_cpuregisters_pir1_ssp1if,     tvb,  3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 3], hf_r3_cpuregisters_pir1_tx1if,      tvb,  3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 3], hf_r3_cpuregisters_pir1_rc1if,      tvb,  3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 3], hf_r3_cpuregisters_pir1_adif,       tvb,  3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 3], hf_r3_cpuregisters_pir1_pspif,      tvb,  3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 4], hf_r3_cpuregisters_pir2_ccp2if,     tvb,  4, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 4], hf_r3_cpuregisters_pir2_tmr3if,     tvb,  4, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 4], hf_r3_cpuregisters_pir2_hlvdif,     tvb,  4, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 4], hf_r3_cpuregisters_pir2_bcl1if,     tvb,  4, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 4], hf_r3_cpuregisters_pir2_eeif,       tvb,  4, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 4], hf_r3_cpuregisters_pir2_unused5,    tvb,  4, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 4], hf_r3_cpuregisters_pir2_cmif,       tvb,  4, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 4], hf_r3_cpuregisters_pir2_oscfif,     tvb,  4, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 5], hf_r3_cpuregisters_pir3_ccp3if,     tvb,  5, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 5], hf_r3_cpuregisters_pir3_ccp4if,     tvb,  5, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 5], hf_r3_cpuregisters_pir3_ccp5if,     tvb,  5, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 5], hf_r3_cpuregisters_pir3_tmr4if,     tvb,  5, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 5], hf_r3_cpuregisters_pir3_tx2if,      tvb,  5, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 5], hf_r3_cpuregisters_pir3_rc2if,      tvb,  5, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 5], hf_r3_cpuregisters_pir3_bcl2if,     tvb,  5, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 5], hf_r3_cpuregisters_pir3_ssp2if,     tvb,  5, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 6], hf_r3_cpuregisters_pie1_tmr1ie,     tvb,  6, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 6], hf_r3_cpuregisters_pie1_tmr2ie,     tvb,  6, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 6], hf_r3_cpuregisters_pie1_ccp1ie,     tvb,  6, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 6], hf_r3_cpuregisters_pie1_ssp1ie,     tvb,  6, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 6], hf_r3_cpuregisters_pie1_tx1ie,      tvb,  6, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 6], hf_r3_cpuregisters_pie1_rc1ie,      tvb,  6, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 6], hf_r3_cpuregisters_pie1_adie,       tvb,  6, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 6], hf_r3_cpuregisters_pie1_pspie,      tvb,  6, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 7], hf_r3_cpuregisters_pie2_oscfie,     tvb,  7, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 7], hf_r3_cpuregisters_pie2_cmie,       tvb,  7, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 7], hf_r3_cpuregisters_pie2_unused2,    tvb,  7, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 7], hf_r3_cpuregisters_pie2_eeie,       tvb,  7, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 7], hf_r3_cpuregisters_pie2_bcl1ie,     tvb,  7, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 7], hf_r3_cpuregisters_pie2_hlvdie,     tvb,  7, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 7], hf_r3_cpuregisters_pie2_tmr3ie,     tvb,  7, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 7], hf_r3_cpuregisters_pie2_ccp2ie,     tvb,  7, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 8], hf_r3_cpuregisters_pie3_ccp3ie,     tvb,  8, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 8], hf_r3_cpuregisters_pie3_ccp4ie,     tvb,  8, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 8], hf_r3_cpuregisters_pie3_ccp5ie,     tvb,  8, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 8], hf_r3_cpuregisters_pie3_tmr4ie,     tvb,  8, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 8], hf_r3_cpuregisters_pie3_tx2ie,      tvb,  8, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 8], hf_r3_cpuregisters_pie3_rc2ie,      tvb,  8, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 8], hf_r3_cpuregisters_pie3_bcl2ie,     tvb,  8, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 8], hf_r3_cpuregisters_pie3_ssp2ie,     tvb,  8, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 9], hf_r3_cpuregisters_ipr1_tmr1ip,     tvb,  9, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 9], hf_r3_cpuregisters_ipr1_tmr2ip,     tvb,  9, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 9], hf_r3_cpuregisters_ipr1_ccp1ip,     tvb,  9, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 9], hf_r3_cpuregisters_ipr1_ssp1ip,     tvb,  9, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 9], hf_r3_cpuregisters_ipr1_tx1ip,      tvb,  9, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 9], hf_r3_cpuregisters_ipr1_rc1ip,      tvb,  9, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 9], hf_r3_cpuregisters_ipr1_adip,       tvb,  9, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [ 9], hf_r3_cpuregisters_ipr1_pspip,      tvb,  9, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [10], hf_r3_cpuregisters_ipr2_ccp2ip,     tvb, 10, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [10], hf_r3_cpuregisters_ipr2_tmr3ip,     tvb, 10, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [10], hf_r3_cpuregisters_ipr2_hlvdip,     tvb, 10, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [10], hf_r3_cpuregisters_ipr2_bcl1ip,     tvb, 10, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [10], hf_r3_cpuregisters_ipr2_eeip,       tvb, 10, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [10], hf_r3_cpuregisters_ipr2_unused5,    tvb, 10, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [10], hf_r3_cpuregisters_ipr2_cmip,       tvb, 10, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [10], hf_r3_cpuregisters_ipr2_oscfip,     tvb, 10, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [11], hf_r3_cpuregisters_ipr3_ccp2ip,     tvb, 11, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [11], hf_r3_cpuregisters_ipr3_ccp4ip,     tvb, 11, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [11], hf_r3_cpuregisters_ipr3_ccp5ip,     tvb, 11, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [11], hf_r3_cpuregisters_ipr3_tmr4ip,     tvb, 11, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [11], hf_r3_cpuregisters_ipr3_tx2ip,      tvb, 11, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [11], hf_r3_cpuregisters_ipr3_rc2ip,      tvb, 11, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [11], hf_r3_cpuregisters_ipr3_bcl2ip,     tvb, 11, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [11], hf_r3_cpuregisters_ipr3_ssp2ip,     tvb, 11, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [12], hf_r3_cpuregisters_rcon_bor,        tvb, 12, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [12], hf_r3_cpuregisters_rcon_por,        tvb, 12, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [12], hf_r3_cpuregisters_rcon_pd,         tvb, 12, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [12], hf_r3_cpuregisters_rcon_to,         tvb, 12, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [12], hf_r3_cpuregisters_rcon_unused4,    tvb, 12, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [12], hf_r3_cpuregisters_rcon_ri,         tvb, 12, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [12], hf_r3_cpuregisters_rcon_sboren,     tvb, 12, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [12], hf_r3_cpuregisters_rcon_ipen,       tvb, 12, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [13], hf_r3_cpuregisters_osccon_scs0,     tvb, 13, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [13], hf_r3_cpuregisters_osccon_scs1,     tvb, 13, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [13], hf_r3_cpuregisters_osccon_iofs,     tvb, 13, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [13], hf_r3_cpuregisters_osccon_osts,     tvb, 13, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [13], hf_r3_cpuregisters_osccon_ircf0,    tvb, 13, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [13], hf_r3_cpuregisters_osccon_ircf1,    tvb, 13, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [13], hf_r3_cpuregisters_osccon_ircf2,    tvb, 13, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [13], hf_r3_cpuregisters_osccon_idlen,    tvb, 13, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [14], hf_r3_cpuregisters_rcsta_rx9d,      tvb, 14, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [14], hf_r3_cpuregisters_rcsta_oerr,      tvb, 14, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [14], hf_r3_cpuregisters_rcsta_ferr,      tvb, 14, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [14], hf_r3_cpuregisters_rcsta_adden,     tvb, 14, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [14], hf_r3_cpuregisters_rcsta_cren,      tvb, 14, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [14], hf_r3_cpuregisters_rcsta_sren,      tvb, 14, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [14], hf_r3_cpuregisters_rcsta_rx9,       tvb, 14, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [14], hf_r3_cpuregisters_rcsta_spen,      tvb, 14, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [15], hf_r3_cpuregisters_txsta_tx9d,      tvb, 15, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [15], hf_r3_cpuregisters_txsta_trmt,      tvb, 15, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [15], hf_r3_cpuregisters_txsta_brgh,      tvb, 15, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [15], hf_r3_cpuregisters_txsta_sendb,     tvb, 15, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [15], hf_r3_cpuregisters_txsta_sync,      tvb, 15, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [15], hf_r3_cpuregisters_txsta_txen,      tvb, 15, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [15], hf_r3_cpuregisters_txsta_tx9,       tvb, 15, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [15], hf_r3_cpuregisters_txsta_csrc,      tvb, 15, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [16], hf_r3_cpuregisters_rcsta2_rx9d,     tvb, 16, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [16], hf_r3_cpuregisters_rcsta2_oerr,     tvb, 16, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [16], hf_r3_cpuregisters_rcsta2_ferr,     tvb, 16, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [16], hf_r3_cpuregisters_rcsta2_adden,    tvb, 16, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [16], hf_r3_cpuregisters_rcsta2_cren,     tvb, 16, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [16], hf_r3_cpuregisters_rcsta2_sren,     tvb, 16, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [16], hf_r3_cpuregisters_rcsta2_rx9,      tvb, 16, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [16], hf_r3_cpuregisters_rcsta2_spen,     tvb, 16, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [17], hf_r3_cpuregisters_txsta2_tx9d,     tvb, 17, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [17], hf_r3_cpuregisters_txsta2_trmt,     tvb, 17, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [17], hf_r3_cpuregisters_txsta2_brgh,     tvb, 17, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [17], hf_r3_cpuregisters_txsta2_sendb,    tvb, 17, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [17], hf_r3_cpuregisters_txsta2_sync,     tvb, 17, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [17], hf_r3_cpuregisters_txsta2_txen,     tvb, 17, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [17], hf_r3_cpuregisters_txsta2_tx9,      tvb, 17, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [17], hf_r3_cpuregisters_txsta2_csrc,     tvb, 17, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [18], hf_r3_cpuregisters_wdtcon_swdten,   tvb, 18, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [18], hf_r3_cpuregisters_wdtcon_unused1,  tvb, 18, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [18], hf_r3_cpuregisters_wdtcon_unused2,  tvb, 18, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [18], hf_r3_cpuregisters_wdtcon_unused3,  tvb, 18, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [18], hf_r3_cpuregisters_wdtcon_unused4,  tvb, 18, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [18], hf_r3_cpuregisters_wdtcon_unused5,  tvb, 18, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [18], hf_r3_cpuregisters_wdtcon_unused6,  tvb, 18, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tmp_tree [18], hf_r3_cpuregisters_wdtcon_unused7,  tvb, 18, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_upstreammfgfield_taskflags (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  gint len;
  gint i;
  proto_item *tfg_item;
  proto_tree *tfg_tree;

  DISSECTOR_ASSERT(start_offset == 0);

  len      = MAX(0, tvb_length_remaining (tvb, 0));
  tfg_item = proto_tree_add_text (tree, tvb, 0, -1, "Task Flags (%u tasks)", len / 5);
  tfg_tree = proto_item_add_subtree (tfg_item, ett_r3taskflags);

  for (i = 0; i < len; i += 5)
  {
    proto_item *tf_item = proto_tree_add_text (tfg_tree, tvb, i, 5,
                                               "Task Flags (%2d: 0x%06x)",
                                               tvb_get_guint8 (tvb, i + 0),
                                               tvb_get_letohl (tvb, i + 1));
    proto_tree *tf_tree = proto_item_add_subtree (tf_item, ett_r3taskflagsentry);

    proto_tree_add_item (tf_tree, hf_r3_taskflags_taskid, tvb, i + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tf_tree, hf_r3_taskflags_flags,  tvb, i + 1, 4, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_upstreammfgfield_timerchain (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  gint len;
  gint i;

  if (!tree)
    return;

  DISSECTOR_ASSERT(start_offset == 0);

  len = tvb_length_remaining (tvb, 3);

  proto_tree_add_item (tree, hf_r3_timerchain_newtick,         tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_timerchain_currentboundary, tvb, 2, 1, ENC_LITTLE_ENDIAN);

  for (i = 0; i < len; i += 12)
  {
    proto_item *tc_item = proto_tree_add_text (tree, tvb, 3 + i, 12, "Timer Chain Entry");
    proto_tree *tc_tree = proto_item_add_subtree (tc_item, ett_r3timerchain);

    proto_tree_add_item (tc_tree, hf_r3_timerchain_tasktag,  tvb, 3 + i + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tc_tree, hf_r3_timerchain_address,  tvb, 3 + i + 1, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tc_tree, hf_r3_timerchain_reload,   tvb, 3 + i + 3, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tc_tree, hf_r3_timerchain_boundary, tvb, 3 + i + 5, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tc_tree, hf_r3_timerchain_count,    tvb, 3 + i + 6, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tc_tree, hf_r3_timerchain_flags,    tvb, 3 + i + 8, 4, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_upstreammfgfield_peekpoke (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  gint i;
  gint len;

  DISSECTOR_ASSERT(start_offset == 0);

  len = tvb_length_remaining (tvb, 0);

  for (i = 0; i < len; i += 3)
  {
    proto_item *peekpoke_item    = NULL;
    proto_item *peekpoke_op_item = NULL;
    proto_tree *peekpoke_tree    = NULL;

    if (tree)
    {
      peekpoke_item = proto_tree_add_text (tree, tvb, i, 3, "%s", "");
      peekpoke_tree = proto_item_add_subtree (peekpoke_item, ett_r3peekpoke);

      peekpoke_op_item = proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_operation, tvb, i + 0, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_address,   tvb, i + 1, 2, ENC_LITTLE_ENDIAN);
    }

    switch (tvb_get_guint8 (tvb, i + 0))
    {
      case PEEKPOKE_READU8 :
        if (peekpoke_tree)
        {
          proto_item_append_text (peekpoke_item, "Read (8 Bits @ 0x%04x = 0x%02x)",
                                  tvb_get_letohs (tvb, i + 1),
                                  tvb_get_guint8 (tvb, i + 3));
          proto_item_set_len (peekpoke_item, 4);
          proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_poke8, tvb, i + 3, 1, ENC_LITTLE_ENDIAN);
        }
        i += 1;
        break;

      case PEEKPOKE_READU16 :
        if (peekpoke_tree)
        {
          proto_item_append_text (peekpoke_item, "Read (16 Bits @ 0x%04x = 0x%04x)",
                                  tvb_get_letohs (tvb, i + 1),
                                  tvb_get_letohs (tvb, i + 3));
          proto_item_set_len (peekpoke_item, 5);
          proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_poke16, tvb, i + 3, 2, ENC_LITTLE_ENDIAN);
        }
        i += 2;
        break;

      case PEEKPOKE_READU24 :
        if (peekpoke_tree)
        {
          proto_item_append_text (peekpoke_item, "Read (24 Bits @ 0x%04x = 0x%06x)",
                                  tvb_get_letohs (tvb, i + 1),
                                  tvb_get_letoh24 (tvb, i + 3));
          proto_item_set_len (peekpoke_item, 6);
          proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_poke24, tvb, i + 3, 3, ENC_LITTLE_ENDIAN);
        }
        i += 3;
        break;

      case PEEKPOKE_READU32 :
        if (peekpoke_tree)
        {
          proto_item_append_text (peekpoke_item, "Read (32 Bits @ 0x%04x = 0x%08x)",
                                  tvb_get_letohs (tvb, i + 1),
                                  tvb_get_letohl (tvb, i + 3));
          proto_item_set_len (peekpoke_item, 7);
          proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_poke32, tvb, i + 3, 4, ENC_LITTLE_ENDIAN);
        }
        i += 4;
        break;

      case PEEKPOKE_READSTRING :
        if (peekpoke_tree)
        {
          proto_item_append_text (peekpoke_item, "Read (%u Bytes @ 0x%04x)",
                                  tvb_get_guint8 (tvb, i + 3),
                                  tvb_get_letohs (tvb, i + 1));
          proto_item_set_len (peekpoke_item, 3 + 1 + tvb_get_guint8 (tvb, i + 3));
          proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_length,     tvb, i + 3, 1, ENC_LITTLE_ENDIAN);
          proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_pokestring, tvb, i + 4, tvb_get_guint8 (tvb, i + 3), ENC_NA);
        }
        i += tvb_get_guint8 (tvb, i + 3) + 1;
        break;

      default :
        expert_add_info_format (pinfo, peekpoke_op_item, PI_UNDECODED, PI_WARN, "Unknown peekpoke operation value");
        return;  /* quit */
    }
  }
}

static void
dissect_r3_upstreammfgfield_lockstate (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *ls_item;
  proto_tree *ls_tree;
  guint       ls;

  if (!tree)
    return;

  DISSECTOR_ASSERT(start_offset == 0);

  ls      = tvb_get_letoh24 (tvb, 0);
  ls_item = proto_tree_add_text (tree, tvb, 0, -1, "Lock State (0x%06x)", ls);
  ls_tree = proto_item_add_subtree (ls_item, ett_r3lockstate);

  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_passage,            tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_panic,              tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_lockout,            tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_relock,             tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_autoopen,           tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_nextauto,           tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_lockstate,          tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_wantstate,          tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_remote,             tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_update,             tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_exceptionspresent,  tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_exceptionsactive,   tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_timezonespresent,   tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_timezonesactive,    tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_autounlockspresent, tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_autounlocksactive,  tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_uapmspresent,       tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_uapmsactive,        tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_uapmrelockspresent, tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_uapmreslocksactive, tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_nvramprotect,       tvb, 0, 3, ls);
  proto_tree_add_boolean (ls_tree, hf_r3_lockstate_nvramchecksum,      tvb, 0, 3, ls);
}

static void
dissect_r3_upstreammfgfield_capabilities (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *cf_item;
  proto_tree *cf_tree;
  gint        len;
  guint       items;
  guint       octets;
  gint        i;

  DISSECTOR_ASSERT(start_offset == 0);

  len = MAX(0, tvb_length_remaining (tvb, 0));

  items = 0;
  i     = 0;

  while (i < len)
  {
    items++;
    octets = tvb_get_guint8 (tvb, i);
    if (!octets)
    {
      cf_item = proto_tree_add_text (tree, tvb, 0, len, "Capabilities (unknown items)");
      expert_add_info_format(pinfo, cf_item, PI_MALFORMED, PI_WARN,
                             "Capabilities could not be decoded because length of 0 encountered");
      return;
    }
    i += octets;
  }

  if (!tree)
    return;

  cf_item = proto_tree_add_text (tree, tvb, 0, len, "Capabilities (%u items)", items);
  cf_tree = proto_item_add_subtree (cf_item, ett_r3capabilities);

  for (i = 0; i < len; i += tvb_get_guint8 (tvb, i))
  {
    proto_item  *tmp_item = proto_tree_add_item (cf_tree, hf_r3_capabilities, tvb, i, tvb_get_guint8 (tvb, i), ENC_NA);
    proto_tree  *tmp_tree = proto_item_add_subtree (tmp_item, ett_r3capabilities);
    const gchar *fn;

    fn = val_to_str_ext_const (tvb_get_guint8 (tvb, i + 1), &r3_capabilitiesnames_ext, "[Unknown Field Name]");

    proto_item_append_text (tmp_item, " (%s, %u)", fn, tvb_get_letohs (tvb, i + 2));
    proto_tree_add_item (tmp_tree, hf_r3_capabilities_length, tvb, i + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tmp_tree, hf_r3_capabilities_type,   tvb, i + 1, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tmp_tree, hf_r3_capabilities_value,  tvb, i + 2, 2, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_upstreammfgfield_dumpm41t81 (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo, proto_tree *tree)
{
  DISSECTOR_ASSERT(start_offset == 0);

  if (tvb_length_remaining (tvb, 0) != 20)
  {
    expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN,
                            "Length of M41T81 RTC register dump not 20 octets");
  }
  else
  {
    proto_item *rtc_item;
    proto_tree *rtc_tree;
    proto_tree *tmp_tree [20];
    guint       offset_in_bits;

    if (!tree)
      return;

    rtc_item = proto_tree_add_text (tree, tvb, 0, -1, "M41T81 RTC Registers");
    rtc_tree = proto_item_add_subtree (rtc_item, ett_r3m41t81registers);

    tmp_tree [ 0] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg00, tvb,  0, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [ 1] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg01, tvb,  1, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [ 2] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg02, tvb,  2, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [ 3] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg03, tvb,  3, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [ 4] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg04, tvb,  4, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [ 5] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg05, tvb,  5, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [ 6] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg06, tvb,  6, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [ 7] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg07, tvb,  7, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [ 8] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg08, tvb,  8, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [ 9] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg09, tvb,  9, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [10] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg0a, tvb, 10, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [11] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg0b, tvb, 11, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [12] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg0c, tvb, 12, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [13] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg0d, tvb, 13, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [14] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg0e, tvb, 14, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [15] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg0f, tvb, 15, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [16] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg10, tvb, 16, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [17] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg11, tvb, 17, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [18] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg12, tvb, 18, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);
    tmp_tree [19] = proto_item_add_subtree (proto_tree_add_item (rtc_tree, hf_r3_dumpm41t81_reg13, tvb, 19, 1, ENC_LITTLE_ENDIAN), ett_r3m41t81register);

    offset_in_bits = 0 * 8;

    proto_tree_add_bits_item (tmp_tree [ 0], hf_r3_dumpm41t81_reg00_sec1,       tvb, offset_in_bits, 4, ENC_LITTLE_ENDIAN);  offset_in_bits += 4;
    proto_tree_add_bits_item (tmp_tree [ 0], hf_r3_dumpm41t81_reg00_sec01,      tvb, offset_in_bits, 4, ENC_LITTLE_ENDIAN);  offset_in_bits += 4;
    proto_tree_add_bits_item (tmp_tree [ 1], hf_r3_dumpm41t81_reg01_st,         tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [ 1], hf_r3_dumpm41t81_reg01_10sec,      tvb, offset_in_bits, 3, ENC_LITTLE_ENDIAN);  offset_in_bits += 3;
    proto_tree_add_bits_item (tmp_tree [ 1], hf_r3_dumpm41t81_reg01_1sec,       tvb, offset_in_bits, 4, ENC_LITTLE_ENDIAN);  offset_in_bits += 4;
    proto_tree_add_bits_item (tmp_tree [ 2], hf_r3_dumpm41t81_reg02_notused,    tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [ 2], hf_r3_dumpm41t81_reg02_10min,      tvb, offset_in_bits, 3, ENC_LITTLE_ENDIAN);  offset_in_bits += 3;
    proto_tree_add_bits_item (tmp_tree [ 2], hf_r3_dumpm41t81_reg02_1min,       tvb, offset_in_bits, 4, ENC_LITTLE_ENDIAN);  offset_in_bits += 4;
    proto_tree_add_bits_item (tmp_tree [ 3], hf_r3_dumpm41t81_reg03_cbe,        tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [ 3], hf_r3_dumpm41t81_reg03_cb,         tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [ 3], hf_r3_dumpm41t81_reg03_10hour,     tvb, offset_in_bits, 2, ENC_LITTLE_ENDIAN);  offset_in_bits += 2;
    proto_tree_add_bits_item (tmp_tree [ 3], hf_r3_dumpm41t81_reg03_1hour,      tvb, offset_in_bits, 4, ENC_LITTLE_ENDIAN);  offset_in_bits += 4;
    proto_tree_add_bits_item (tmp_tree [ 4], hf_r3_dumpm41t81_reg04_notused,    tvb, offset_in_bits, 5, ENC_LITTLE_ENDIAN);  offset_in_bits += 5;
    proto_tree_add_bits_item (tmp_tree [ 4], hf_r3_dumpm41t81_reg04_dow,        tvb, offset_in_bits, 3, ENC_LITTLE_ENDIAN);  offset_in_bits += 3;
    proto_tree_add_bits_item (tmp_tree [ 5], hf_r3_dumpm41t81_reg05_notused,    tvb, offset_in_bits, 2, ENC_LITTLE_ENDIAN);  offset_in_bits += 2;
    proto_tree_add_bits_item (tmp_tree [ 5], hf_r3_dumpm41t81_reg05_10day,      tvb, offset_in_bits, 2, ENC_LITTLE_ENDIAN);  offset_in_bits += 2;
    proto_tree_add_bits_item (tmp_tree [ 5], hf_r3_dumpm41t81_reg05_1day,       tvb, offset_in_bits, 4, ENC_LITTLE_ENDIAN);  offset_in_bits += 4;
    proto_tree_add_bits_item (tmp_tree [ 6], hf_r3_dumpm41t81_reg06_notused,    tvb, offset_in_bits, 3, ENC_LITTLE_ENDIAN);  offset_in_bits += 3;
    proto_tree_add_bits_item (tmp_tree [ 6], hf_r3_dumpm41t81_reg06_10month,    tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [ 6], hf_r3_dumpm41t81_reg06_1month,     tvb, offset_in_bits, 4, ENC_LITTLE_ENDIAN);  offset_in_bits += 4;
    proto_tree_add_bits_item (tmp_tree [ 7], hf_r3_dumpm41t81_reg07_10year,     tvb, offset_in_bits, 4, ENC_LITTLE_ENDIAN);  offset_in_bits += 4;
    proto_tree_add_bits_item (tmp_tree [ 7], hf_r3_dumpm41t81_reg07_1year,      tvb, offset_in_bits, 4, ENC_LITTLE_ENDIAN);  offset_in_bits += 4;
    proto_tree_add_bits_item (tmp_tree [ 8], hf_r3_dumpm41t81_reg08_out,        tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [ 8], hf_r3_dumpm41t81_reg08_ft,         tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [ 8], hf_r3_dumpm41t81_reg08_s,          tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [ 8], hf_r3_dumpm41t81_reg08_cal,        tvb, offset_in_bits, 5, ENC_LITTLE_ENDIAN);  offset_in_bits += 5;
    proto_tree_add_bits_item (tmp_tree [ 9], hf_r3_dumpm41t81_reg09_notused,    tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [ 9], hf_r3_dumpm41t81_reg09_bmb,        tvb, offset_in_bits, 5, ENC_LITTLE_ENDIAN);  offset_in_bits += 5;
    proto_tree_add_bits_item (tmp_tree [ 9], hf_r3_dumpm41t81_reg09_rb,         tvb, offset_in_bits, 2, ENC_LITTLE_ENDIAN);  offset_in_bits += 2;
    proto_tree_add_bits_item (tmp_tree [10], hf_r3_dumpm41t81_reg0a_afe,        tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [10], hf_r3_dumpm41t81_reg0a_sqwe,       tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [10], hf_r3_dumpm41t81_reg0a_abe,        tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [10], hf_r3_dumpm41t81_reg0a_10monthalm, tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [10], hf_r3_dumpm41t81_reg0a_1monthalm,  tvb, offset_in_bits, 4, ENC_LITTLE_ENDIAN);  offset_in_bits += 4;
    proto_tree_add_bits_item (tmp_tree [11], hf_r3_dumpm41t81_reg0b_rpt5,       tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [11], hf_r3_dumpm41t81_reg0b_rpt4,       tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [11], hf_r3_dumpm41t81_reg0b_10dayalm,   tvb, offset_in_bits, 2, ENC_LITTLE_ENDIAN);  offset_in_bits += 2;
    proto_tree_add_bits_item (tmp_tree [11], hf_r3_dumpm41t81_reg0b_1dayalm,    tvb, offset_in_bits, 4, ENC_LITTLE_ENDIAN);  offset_in_bits += 4;
    proto_tree_add_bits_item (tmp_tree [12], hf_r3_dumpm41t81_reg0c_rpt3,       tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [12], hf_r3_dumpm41t81_reg0c_ht,         tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [12], hf_r3_dumpm41t81_reg0c_10houralm,  tvb, offset_in_bits, 2, ENC_LITTLE_ENDIAN);  offset_in_bits += 2;
    proto_tree_add_bits_item (tmp_tree [12], hf_r3_dumpm41t81_reg0c_1houralm,   tvb, offset_in_bits, 4, ENC_LITTLE_ENDIAN);  offset_in_bits += 4;
    proto_tree_add_bits_item (tmp_tree [13], hf_r3_dumpm41t81_reg0d_rpt2,       tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [13], hf_r3_dumpm41t81_reg0d_10minalm,   tvb, offset_in_bits, 3, ENC_LITTLE_ENDIAN);  offset_in_bits += 3;
    proto_tree_add_bits_item (tmp_tree [13], hf_r3_dumpm41t81_reg0d_1minalm,    tvb, offset_in_bits, 4, ENC_LITTLE_ENDIAN);  offset_in_bits += 4;
    proto_tree_add_bits_item (tmp_tree [14], hf_r3_dumpm41t81_reg0e_rpt1,       tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [14], hf_r3_dumpm41t81_reg0e_10secalm,   tvb, offset_in_bits, 3, ENC_LITTLE_ENDIAN);  offset_in_bits += 3;
    proto_tree_add_bits_item (tmp_tree [14], hf_r3_dumpm41t81_reg0e_1secalm,    tvb, offset_in_bits, 4, ENC_LITTLE_ENDIAN);  offset_in_bits += 4;
    proto_tree_add_bits_item (tmp_tree [15], hf_r3_dumpm41t81_reg0f_wdf,        tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [15], hf_r3_dumpm41t81_reg0f_af,         tvb, offset_in_bits, 1, ENC_LITTLE_ENDIAN);  offset_in_bits += 1;
    proto_tree_add_bits_item (tmp_tree [15], hf_r3_dumpm41t81_reg0f_notused,    tvb, offset_in_bits, 6, ENC_LITTLE_ENDIAN);  offset_in_bits += 6;
    proto_tree_add_bits_item (tmp_tree [16], hf_r3_dumpm41t81_reg10_notused,    tvb, offset_in_bits, 8, ENC_LITTLE_ENDIAN);  offset_in_bits += 8;
    proto_tree_add_bits_item (tmp_tree [17], hf_r3_dumpm41t81_reg11_notused,    tvb, offset_in_bits, 8, ENC_LITTLE_ENDIAN);  offset_in_bits += 8;
    proto_tree_add_bits_item (tmp_tree [18], hf_r3_dumpm41t81_reg12_notused,    tvb, offset_in_bits, 8, ENC_LITTLE_ENDIAN);  offset_in_bits += 8;
    proto_tree_add_bits_item (tmp_tree [19], hf_r3_dumpm41t81_reg13_rs,         tvb, offset_in_bits - 8, 4, ENC_LITTLE_ENDIAN);  offset_in_bits += 4;
    proto_tree_add_bits_item (tmp_tree [19], hf_r3_dumpm41t81_reg13_notused,    tvb, offset_in_bits - 8, 4, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_upstreammfgfield_nvramchecksumvalue (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    DISSECTOR_ASSERT(start_offset == 0);

    proto_tree_add_item (tree, hf_r3_nvramchecksumvalue,       tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_nvramchecksumvalue_fixup, tvb, 4, 4, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_upstreammfgfield_checksumresults (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo, proto_tree *tree)
{
  gint len;

  DISSECTOR_ASSERT(start_offset == 0);

  len = MAX(0, tvb_length_remaining(tvb, 0));
  if (len % 3 != 0)
  {
    expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN,
                            "Checksum results data length not modulo 3 == 0");
  }
  else
  {
    proto_item *cksum_item;
    proto_tree *cksum_tree;
    guint32     error = FALSE;
    gint        i;

    if (!tree)
      return;

    for (i = 0; i < len; i += tvb_get_guint8 (tvb, i))
      error |= tvb_get_guint8 (tvb, i + 2);

    cksum_item = proto_tree_add_text (tree, tvb, 0, len, "Checksum Results (%s)", error ? "Error" : "No Errors");
    cksum_tree = proto_item_add_subtree (cksum_item, ett_r3checksumresults);

    for (i = 0; i < len; i += tvb_get_guint8 (tvb, i))
    {
      proto_item  *res_item = proto_tree_add_item (cksum_tree, hf_r3_checksumresults,
                                                  tvb,
                                                  i,
                                                  tvb_get_guint8 (tvb, i),
                                                  ENC_NA);
      proto_tree  *res_tree = proto_item_add_subtree (res_item, ett_r3checksumresultsfield);
      const gchar *fn;

      fn = val_to_str_ext_const (tvb_get_guint8 (tvb, i + 1), &r3_checksumresultnames_ext, "[Unknown Field Name]");

      proto_item_append_text (res_item, " %s (%s)", fn, tvb_get_guint8 (tvb, i + 2) ? "Error" : "No Error");

      proto_tree_add_item (res_tree, hf_r3_checksumresults_length, tvb, i + 0, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item (res_tree, hf_r3_checksumresults_field,  tvb, i + 1, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item (res_tree, hf_r3_checksumresults_state,  tvb, i + 2, 1, ENC_LITTLE_ENDIAN);
    }
  }
}

static void
dissect_r3_upstreammfgfield_mortisestatelog (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  gint len;
  gint i;

  if (!tree)
    return;

  DISSECTOR_ASSERT(start_offset == 0);

  len = tvb_length_remaining (tvb, 3);

  proto_tree_add_item (tree, hf_r3_mortisestatelog_pointer,     tvb, 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_mortisestatelog_mortisetype, tvb, 1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_mortisestatelog_waiting,     tvb, 2, 1, ENC_LITTLE_ENDIAN);

  for (i = 0; i < len; i += 3)
  {
    guint       state   = tvb_get_guint8 (tvb, 3 + i + 0);
    guint       last    = tvb_get_guint8 (tvb, 3 + i + 1);
    guint       event   = tvb_get_guint8 (tvb, 3 + i + 2);
    proto_item *ms_item = proto_tree_add_text (tree, tvb, 3 + i, 3,
                                               "State Log Entry %2d (State=0x%02x, Last=0x%02x, Event=%s (0x%02x))",
                                               i / 3,
                                               state,
                                               last,
                                               val_to_str_ext_const (event, &r3_mortiseeventnames_ext, "[Unknown]"),
                                               event);
    proto_tree  *ms_tree = proto_item_add_subtree (ms_item, ett_r3mortisestatelog);

    proto_tree_add_item (ms_tree, hf_r3_mortisestatelog_state, tvb, 3 + i + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (ms_tree, hf_r3_mortisestatelog_last,  tvb, 3 + i + 1, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (ms_tree, hf_r3_mortisestatelog_event, tvb, 3 + i + 2, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_upstreammfgfield_mortisepins (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *iopins_item;
  proto_tree *iopins_tree;

  if (!tree)
    return;

  DISSECTOR_ASSERT(start_offset == 0);

  iopins_item = proto_tree_add_text (tree, tvb, 0, 1,
                                     "Mortise Pin States (0x%02x)", tvb_get_guint8 (tvb, 0));
  iopins_tree = proto_item_add_subtree (iopins_item, ett_r3iopins);

  proto_tree_add_item (iopins_tree, hf_r3_mortisepins_s1, tvb, 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (iopins_tree, hf_r3_mortisepins_s2, tvb, 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (iopins_tree, hf_r3_mortisepins_s3, tvb, 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (iopins_tree, hf_r3_mortisepins_s4, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_upstreammfgfield_keypadchar (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
    return;

  DISSECTOR_ASSERT(start_offset == 0);

  proto_item_append_text (
    proto_tree_add_item (tree, hf_r3_testkeypad, tvb, 0, 1, ENC_LITTLE_ENDIAN),
    " ('%c')", tvb_get_guint8 (tvb, 0));
}

static void
dissect_r3_upstreammfgfield_magcard (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  DISSECTOR_ASSERT(start_offset == 0);

  proto_tree_add_item (tree, hf_r3_testmagcard, tvb, 0, -1, ENC_ASCII|ENC_NA);
}

static void
dissect_r3_upstreammfgfield_proxcard (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  DISSECTOR_ASSERT(start_offset == 0);

  proto_tree_add_item (tree, hf_r3_testproxcard, tvb, 0, -1, ENC_ASCII|ENC_NA);
}

/*
 * ***************************************************************************
 *
 *  This is passed a tvb that contains [length] [CMD_RESPONSE] [responseType_e] [cmdCommand_e]
 */
static void
dissect_r3_response_singlebyte (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_responsetype,      tvb, start_offset + 2, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_responsetocommand, tvb, start_offset + 3, 1, ENC_LITTLE_ENDIAN);
  }
}

/*
 *  This is passed a tvb that contains [length] [CMD_RESPONSE] [RESPONSETYPE_HASDATA] [UPSTREAMCOMMAND_*]
 */
static void
dissect_r3_response_hasdata (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo, proto_tree *tree)
{
  guint32      commandPacketLen;
  guint8       upstreamCmd;

  DISSECTOR_ASSERT(start_offset == 0);

  tvb_ensure_bytes_exist (tvb, 0, 4);

  commandPacketLen    = tvb_get_guint8 (tvb, 0);
  upstreamCmd         = tvb_get_guint8 (tvb, 3);

  if (tvb_get_guint8 (tvb, 1) != CMD_RESPONSE)
    expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN, "Octet 1 not CMD_RESPONSE");
  else if (tvb_get_guint8 (tvb, 2) != RESPONSETYPE_HASDATA)
    expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN, "Octet 2 not RESPONSE_HASDATA");
  else if (upstreamCmd >= UPSTREAMCOMMAND_LAST)
    expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN, "Octet 3 >= UPSTREAMCOMMAND_LAST");
  else
  {
    proto_tree *upstreamcommand_tree = NULL;
    tvbuff_t   *upstreamcommand_tvb;

    if (tree)
    {
      proto_item  *upstreamcommand_item;
      const gchar *ct;
      ct = val_to_str_ext_const (upstreamCmd, &r3_upstreamcommandnames_ext, "[Unknown Command Type]");

      proto_tree_add_item (tree, hf_r3_responsetype, tvb, 2, 1, ENC_LITTLE_ENDIAN);

      upstreamcommand_item = proto_tree_add_text (tree, tvb, 3, -1,
                                                  "Upstream Command: %s (%u)", ct, upstreamCmd);
      upstreamcommand_tree = proto_item_add_subtree (upstreamcommand_item, ett_r3upstreamcommand);

      proto_tree_add_item (upstreamcommand_tree, hf_r3_upstreamcommand, tvb, 3, 1, ENC_LITTLE_ENDIAN);
    }
    tvb_ensure_bytes_exist (tvb, 0, commandPacketLen - 4);

    upstreamcommand_tvb = tvb_new_subset (tvb, 4, commandPacketLen - 4, commandPacketLen - 4);
    if (r3upstreamcommand_dissect [upstreamCmd])
      (*r3upstreamcommand_dissect [upstreamCmd]) (upstreamcommand_tvb, 0, commandPacketLen - 4, pinfo, upstreamcommand_tree);
  }
}

/*
 * ***************************************************************************
 *
 *  These are passed a tvb that starts with [length] [CMD_RESPONSE] ...
 */
static void
dissect_r3_cmd_response (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *tree)
{
  guint8          responseLen  = tvb_get_guint8 (tvb, start_offset + 0);
  responseType_e  responseType = tvb_get_guint8 (tvb, start_offset + 2);
  tvbuff_t       *payload_tvb  = tvb_new_subset (tvb, start_offset, responseLen, responseLen);

  if (tree)
  {
    const gchar *rt;

    rt = val_to_str_ext_const (responseType, &r3_responsetypenames_ext, "[Unknown Response Type]");

    proto_item_set_text (proto_tree_get_parent (tree), "Response Packet: %s (%u)", rt, responseType);
    proto_tree_add_item (tree, hf_r3_responselength,  tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_responsecommand, tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }

  if (responseType >= RESPONSETYPE_LAST)
  {
    expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN,
                            "Octet 3 >= UPSTREAMCOMMAND_LAST");
  }
  else if (r3response_dissect [responseType])
    (*r3response_dissect [responseType]) (payload_tvb, 0, length, pinfo, tree);
}

/*
 *  These are passed a tvb that contains [length] [cmdCommand_e] [[data]]
 */
static void
dissect_r3_cmd_handshake (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmd_killsession (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmd_queryserialnumber (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmd_queryversion (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmd_setdatetime (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree *dt_tree;
  proto_item *dt_item;
  guint8      cmdLen;
  tvbuff_t   *payload_tvb;

  if (!tree)
    return;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  dt_item = proto_tree_add_text (tree, payload_tvb, 0, -1,
                                 "Set Date/Time (%02u/%02u/%02u-%u %02u:%02u:%02u)",
                                 tvb_get_guint8 (payload_tvb, 0),
                                 tvb_get_guint8 (payload_tvb, 1),
                                 tvb_get_guint8 (payload_tvb, 2),
                                 tvb_get_guint8 (payload_tvb, 3),
                                 tvb_get_guint8 (payload_tvb, 4),
                                 tvb_get_guint8 (payload_tvb, 5),
                                 tvb_get_guint8 (payload_tvb, 6));
  dt_tree = proto_item_add_subtree (dt_item, ett_r3setdatetime);

  proto_tree_add_item (dt_tree, hf_r3_setdate_year,    payload_tvb, 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (dt_tree, hf_r3_setdate_month,   payload_tvb, 1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (dt_tree, hf_r3_setdate_day,     payload_tvb, 2, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (dt_tree, hf_r3_setdate_dow,     payload_tvb, 3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (dt_tree, hf_r3_setdate_hours,   payload_tvb, 4, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (dt_tree, hf_r3_setdate_minutes, payload_tvb, 5, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (dt_tree, hf_r3_setdate_seconds, payload_tvb, 6, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmd_querydatetime (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmd_setconfig (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  guint     cmdLen;
  tvbuff_t *payload_tvb;
  guint32   offset = 0;

  if (!tree)
    return;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  while (offset < (cmdLen - 2))
  {
    proto_item  *sc_item;
    proto_tree  *sc_tree;
    const gchar *ci;
    guint8       configItem;

    configItem = tvb_get_guint8 (payload_tvb, offset + 1);

    ci = val_to_str_ext_const (
      configItem,
      &r3_configitemnames_ext,
      "[Unknown Configuration Item]");

    sc_item = proto_tree_add_text (tree, payload_tvb, offset + 0, tvb_get_guint8 (payload_tvb, offset + 0),
                                   "Config Field: %s (%u)", ci, configItem);
    sc_tree = proto_item_add_subtree (sc_item, ett_r3upstreamfield);

    proto_tree_add_item (sc_tree, hf_r3_configitemlength, payload_tvb, offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (sc_tree, hf_r3_configitem,       payload_tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);

    if (configItem < array_length (configMap))
    {
      switch (configMap [configItem])
      {
        case CONFIGTYPE_NONE :
          proto_tree_add_item (sc_tree, hf_r3_configitemdata, payload_tvb, offset + 2,
                               tvb_get_guint8 (payload_tvb, offset + 0) - 3,
                               ENC_NA);
          break;

        case CONFIGTYPE_BOOL :
          proto_tree_add_item (sc_tree, hf_r3_configitemdata_bool,   payload_tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
          break;

        case CONFIGTYPE_8 :
          proto_tree_add_item (sc_tree, hf_r3_configitemdata_8,      payload_tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
          break;

        case CONFIGTYPE_16 :
          proto_tree_add_item (sc_tree, hf_r3_configitemdata_16,     payload_tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
          break;

        case CONFIGTYPE_32 :
          proto_tree_add_item (sc_tree, hf_r3_configitemdata_32,     payload_tvb, offset + 2, 4, ENC_LITTLE_ENDIAN);
          break;

        case CONFIGTYPE_STRING :
          proto_tree_add_item (sc_tree, hf_r3_configitemdata_string, payload_tvb, offset + 2,
                               tvb_get_guint8 (payload_tvb, offset + 0) - 2,
                               ENC_ASCII|ENC_NA);
          break;

        default :
          proto_tree_add_none_format (sc_tree, hf_r3_upstreamfielderror, payload_tvb, offset + 2,
                                      tvb_get_guint8 (payload_tvb, offset + 0) - 2,
                                      "Unknown Field Type");
          break;
      }
    }
    else {
      proto_tree_add_text (sc_tree, payload_tvb, offset + 2,
                           tvb_get_guint8 (payload_tvb, offset + 0) - 2,
                           "[Unknown Field Type]");
    }

    offset += tvb_get_guint8 (payload_tvb, offset + 0);
  }
}

static void
dissect_r3_cmd_getconfig (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *config_item;
  proto_tree *config_tree;
  guint32     cmdLen;
  guint32     i;

  if (!tree)
    return;

  cmdLen = tvb_get_guint8 (tvb, start_offset + 0);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  config_item = proto_tree_add_item (tree, hf_r3_configitems, tvb, start_offset + 2, cmdLen - 2, ENC_NA);
  config_tree = proto_item_add_subtree (config_item, ett_r3configitem);

  for (i = 2; i < cmdLen; i++)
    proto_tree_add_item (config_tree, hf_r3_configitem, tvb, start_offset + i, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmd_manageuser (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo, proto_tree *tree)
{
  guint8    cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  tvbuff_t *payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);
  guint32   offset      = 0;

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  while (offset < tvb_reported_length (payload_tvb))
  {
    guint32      paramLength = tvb_get_guint8 (payload_tvb, offset + 0);
    guint32      paramType   = tvb_get_guint8 (payload_tvb, offset + 1);
    guint32      dataLength  = paramLength - 2;
    proto_tree  *mu_tree     = NULL;
    proto_item  *len_field   = NULL;

    if (tree)
    {
      const gchar *auptn;
      auptn = val_to_str_ext_const (paramType, &r3_adduserparamtypenames_ext, "[Unknown Field]");

      mu_tree = proto_item_add_subtree (
        proto_tree_add_none_format (tree, hf_r3_adduserparamtype, payload_tvb, offset + 0, paramLength,
                                    "Manage User Field: %s (%u)", auptn, paramType), ett_r3manageuser);

      len_field = proto_tree_add_item (mu_tree, hf_r3_adduserparamtypelength, payload_tvb, offset + 0, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item (mu_tree, hf_r3_adduserparamtypetype, payload_tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
    }

    if (paramLength < 2)
    {
      dataLength = 0;
      expert_add_info_format (pinfo, len_field, PI_UNDECODED, PI_WARN,
                              "Malformed length value -- all fields are at least 2 octets.");
    }

    offset += 2;

    switch (paramType)
    {
      case ADDUSERPARAMTYPE_DISPOSITION :
      case ADDUSERPARAMTYPE_ACCESSALWAYS :
      case ADDUSERPARAMTYPE_ACCESSMODE :
      case ADDUSERPARAMTYPE_CACHED :
      case ADDUSERPARAMTYPE_USERTYPE :
      case ADDUSERPARAMTYPE_PRIMARYFIELDTYPE :
      case ADDUSERPARAMTYPE_AUXFIELDTYPE :
      case ADDUSERPARAMTYPE_USECOUNT :
      case ADDUSERPARAMTYPE_EXCEPTIONGROUP :
        if (dataLength != 1)
        {
          expert_add_info_format (pinfo, proto_tree_get_parent (mu_tree), PI_UNDECODED, PI_WARN,
                                  "Malformed field -- expected 1 octet");
        }
        else
          proto_tree_add_item (mu_tree, hf_r3_adduserparamtypearray [paramType], payload_tvb, offset, dataLength, ENC_LITTLE_ENDIAN);
        break;

      case ADDUSERPARAMTYPE_USERNO :
        if (dataLength != 2)
        {
          expert_add_info_format (pinfo, proto_tree_get_parent (mu_tree), PI_UNDECODED, PI_WARN,
                                  "Malformed field -- expected 2 octets");
        }
        else
          proto_tree_add_item (mu_tree, hf_r3_adduserparamtypearray [paramType], payload_tvb, offset, dataLength, ENC_LITTLE_ENDIAN);
        break;

      case ADDUSERPARAMTYPE_PRIMARYFIELD :
      case ADDUSERPARAMTYPE_AUXFIELD :
        proto_tree_add_item (mu_tree, hf_r3_adduserparamtypearray [paramType], payload_tvb, offset, dataLength, ENC_NA);
        break;

      case ADDUSERPARAMTYPE_EXPIREON :
        {
          if (dataLength != 3)
          {
            expert_add_info_format (pinfo, proto_tree_get_parent (mu_tree), PI_UNDECODED, PI_WARN,
                                    "Malformed expiration field -- expected 3 octets");
          }
          else
          {
            proto_item *expireon_item;
            proto_tree *expireon_tree;

            if (!tree)
              break;

            expireon_item = proto_tree_add_text (mu_tree, payload_tvb, offset, 3,
                                                 "Expire YY/MM/DD: %02u/%02u/%02u",
                                                 tvb_get_guint8 (payload_tvb, offset + 2),
                                                 tvb_get_guint8 (payload_tvb, offset + 0),
                                                 tvb_get_guint8 (payload_tvb, offset + 1));
            expireon_tree = proto_item_add_subtree (expireon_item, ett_r3expireon);

            proto_tree_add_item (expireon_tree, hf_r3_expireon_month, payload_tvb, offset + 0, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (expireon_tree, hf_r3_expireon_day,   payload_tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item (expireon_tree, hf_r3_expireon_year,  payload_tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
          }
        }
        break;

      case ADDUSERPARAMTYPE_TIMEZONE :
        {
          if (dataLength != 4)
          {
            expert_add_info_format (pinfo, proto_tree_get_parent (mu_tree), PI_UNDECODED, PI_WARN,
                                    "Malformed timezone field -- expected 4 octets");
          }
          else
          {
            proto_item *timezone_item;
            proto_tree *timezone_tree;
            guint32     i;
            guint32     tz;

            if (!tree)
              break;

            tz = tvb_get_letohl (payload_tvb, offset);
            timezone_item = proto_tree_add_item (mu_tree, hf_r3_upstreamfieldarray [paramType], payload_tvb, offset, 4, ENC_LITTLE_ENDIAN);
            timezone_tree = proto_item_add_subtree (timezone_item, ett_r3timezone);

            for (i = 0; i < 32; i++)
              proto_tree_add_boolean (timezone_tree, hf_r3_timezonearray [i], payload_tvb, offset, 4, tz);
          }
        }
        break;

      default :
        proto_tree_add_string (mu_tree, hf_r3_upstreamfielderror, payload_tvb, offset, dataLength, "Unknown Field Type");
        break;
    }

    offset += dataLength;
  }
}

static void
dissect_r3_cmd_deleteusers (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  guint8    cmdLen;
  tvbuff_t *payload_tvb;

  if (!tree)
    return;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  proto_tree_add_item (tree, hf_r3_deleteusers, payload_tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmd_defineexception (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *startdate_item;
  proto_tree *startdate_tree;
  proto_item *enddate_item;
  proto_tree *enddate_tree;
  guint8      cmdLen;
  tvbuff_t   *payload_tvb;

  if (!tree)
    return;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  proto_tree_add_item (tree, hf_r3_defineexception_number, payload_tvb, 0, 1, ENC_LITTLE_ENDIAN);

  startdate_item = proto_tree_add_text (tree, payload_tvb, 1, 4,
                                        "Start MM/DD HH:MM (%02u/%02u %02u:%02u)",
                                        tvb_get_guint8 (payload_tvb, 1),
                                        tvb_get_guint8 (payload_tvb, 2),
                                        tvb_get_guint8 (payload_tvb, 3),
                                        tvb_get_guint8 (payload_tvb, 4));
  startdate_tree = proto_item_add_subtree (startdate_item, ett_r3defineexceptionstartdate);
  proto_tree_add_item (startdate_tree, hf_r3_defineexception_startdate_month,   payload_tvb, 1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (startdate_tree, hf_r3_defineexception_startdate_day,     payload_tvb, 2, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (startdate_tree, hf_r3_defineexception_startdate_hours,   payload_tvb, 3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (startdate_tree, hf_r3_defineexception_startdate_minutes, payload_tvb, 4, 1, ENC_LITTLE_ENDIAN);

  enddate_item = proto_tree_add_text (tree, payload_tvb, 5, 4,
                                      "End MM/DD HH:MM (%02u/%02u %02u:%02u)",
                                      tvb_get_guint8 (payload_tvb, 5),
                                      tvb_get_guint8 (payload_tvb, 6),
                                      tvb_get_guint8 (payload_tvb, 7),
                                      tvb_get_guint8 (payload_tvb, 8));
  enddate_tree = proto_item_add_subtree (enddate_item, ett_r3defineexceptionenddate);
  proto_tree_add_item (enddate_tree, hf_r3_defineexception_enddate_month,   payload_tvb, 5, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (enddate_tree, hf_r3_defineexception_enddate_day,     payload_tvb, 6, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (enddate_tree, hf_r3_defineexception_enddate_hours,   payload_tvb, 7, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (enddate_tree, hf_r3_defineexception_enddate_minutes, payload_tvb, 8, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmd_defineexceptiongroup (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *bits_item;
  proto_tree *bits_tree;
  guint       cmdLen;
  tvbuff_t   *payload_tvb;
  guint32     i;
  guint32     bit = 0;

  if (!tree)
    return;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  proto_tree_add_item (tree, hf_r3_defineexceptiongroup_number, payload_tvb, 0, 1, ENC_LITTLE_ENDIAN);

  bits_item = proto_tree_add_text (tree, payload_tvb, 1, -1, "Exception Group Bit Field");
  bits_tree = proto_item_add_subtree (bits_item, ett_r3defineexceptiongroupbits);

  for (i = 1; i < (cmdLen - 2); i++)
  {
    guint32 j;
    guint8  byte = tvb_get_guint8 (payload_tvb, i);

    for (j = 0; j < 8; j++)
      proto_tree_add_none_format (bits_tree, hf_r3_defineexceptiongroup_bits, payload_tvb, i, 1,
                                  "Exception Group %2d: %s", bit++, (byte & (1 << j)) ? "Enabled" : "Disabled");
  }
}

static void
dissect_r3_cmd_definecalendar (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  guint8       cmdLen;
  tvbuff_t    *payload_tvb;
  const gchar *mn;
  guint32      i;

  if (!tree)
    return;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  proto_tree_add_item (tree, hf_r3_definecalendar_number, payload_tvb, 0, 1, ENC_LITTLE_ENDIAN);

  for (i = 0; i < 12; i++)
  {
    guint32     daymap = tvb_get_letohl (payload_tvb, (i * 4) + 1);
    proto_item *calendar_item = proto_tree_add_text (tree, payload_tvb, (i * 4) + 1, 4,
                                                     "Calendar Bit Field - %s (0x%08x)",
                                                     (mn = val_to_str_ext_const (i + 1, &r3_monthnames_ext, "[Unknown Month]")),
                                                     daymap);
    proto_tree *calendar_tree = proto_item_add_subtree (calendar_item, ett_r3definecalendarmonth [i + 1]);
    guint32     j;

    for (j = 0; j < 31; j++)
      proto_tree_add_none_format (calendar_tree, hf_r3_definecalendar_bits, payload_tvb, (i * 4) + 1, 4,
                                  "%s Of %s: %s",
                                  val_to_str_ext_const (j + 1, &r3_monthdaynames_ext, "[Unknown Day]"),
                                  mn,
                                  (daymap & (1 << j)) ? "Enabled" : "Disabled");
  }
}

static void
dissect_r3_cmd_definetimezone (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *starttime_item;
  proto_tree *starttime_tree;
  proto_item *endtime_item;
  proto_tree *endtime_tree;
  proto_item *daymap_item;
  proto_tree *daymap_tree;
  guint8      cmdLen;
  tvbuff_t   *payload_tvb;
  guint32     i;
  guint8      tzmode;

  if (!tree)
    return;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  proto_tree_add_item (tree, hf_r3_definetimezone_number, payload_tvb, 0, 1, ENC_LITTLE_ENDIAN);

  starttime_item = proto_tree_add_text (tree, payload_tvb, 1, 2,
                                        "Start HH:MM (%02u:%02u)",
                                        tvb_get_guint8 (payload_tvb, 1),
                                        tvb_get_guint8 (payload_tvb, 2));
  starttime_tree = proto_item_add_subtree (starttime_item, ett_r3definetimezonestarttime);
  proto_tree_add_item (starttime_tree, hf_r3_definetimezone_starttime_hours,   payload_tvb, 1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (starttime_tree, hf_r3_definetimezone_starttime_minutes, payload_tvb, 2, 1, ENC_LITTLE_ENDIAN);

  endtime_item = proto_tree_add_text (tree, payload_tvb, 3, 2,
                                      "End HH:MM (%02u:%02u)",
                                      tvb_get_guint8 (payload_tvb, 3),
                                      tvb_get_guint8 (payload_tvb, 4));
  endtime_tree = proto_item_add_subtree (endtime_item, ett_r3definetimezoneendtime);
  proto_tree_add_item (endtime_tree, hf_r3_definetimezone_endtime_hours,   payload_tvb, 3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (endtime_tree, hf_r3_definetimezone_endtime_minutes, payload_tvb, 4, 1, ENC_LITTLE_ENDIAN);

  daymap_item = proto_tree_add_text (tree, payload_tvb, 5, 1, "Day Map (0x%02x)", tvb_get_guint8 (payload_tvb, 5));
  daymap_tree = proto_item_add_subtree (daymap_item, ett_r3definetimezonedaymap);

  for (i = 0; i < 7; i++)
    proto_tree_add_boolean (daymap_tree, hf_r3_definetimezone_daymap [i], payload_tvb, 5, 1,
                            tvb_get_guint8 (payload_tvb, 5));

  proto_tree_add_item (tree, hf_r3_definetimezone_exceptiongroup, payload_tvb, 6, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_uint (tree, hf_r3_definetimezone_mode, payload_tvb, 7, 1,
                       (tzmode = tvb_get_guint8 (payload_tvb, 7)) & 0x0f);
  proto_tree_add_none_format (tree, hf_r3_definetimezone_calendar, payload_tvb, 7, 1,
                              "Access Always: %s", (tzmode & 0x10) ? "True" : "False");
}

static void
dissect_r3_cmd_rmtauthretry (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  guint8    cmdLen;
  tvbuff_t *payload_tvb;

  if (!tree)
    return;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  proto_tree_add_item (tree, hf_r3_rmtauthretry_sequence, payload_tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_rmtauthretry_retry,    payload_tvb, 2, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmd_filters (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *filter_item;
  proto_tree *filter_tree;
  guint8      cmdLen;
  tvbuff_t   *payload_tvb;
  guint32     i;

  if (!tree)
    return;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  proto_tree_add_item (tree, hf_r3_filter_type, payload_tvb, 1, 1, ENC_LITTLE_ENDIAN);

  filter_item = proto_tree_add_text (tree, payload_tvb, 2, -1,
                                     "Filters (%u specified)", tvb_get_guint8 (payload_tvb, 0));
  filter_tree = proto_item_add_subtree (filter_item, ett_r3filters);

  for (i = 0; i < tvb_get_guint8 (payload_tvb, 0); i++)
    proto_tree_add_item (filter_tree, hf_r3_filter_list, payload_tvb, i + 2, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmd_alarmconfigure (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo, proto_tree *tree)
{
  proto_item *alarm_item;
  proto_tree *alarm_tree;
  guint       cmdLen;
  tvbuff_t   *payload_tvb;
  guint32     offset = 0;
  guint32     alarms = 0;

  if (!tree)
    return;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  alarm_item = proto_tree_add_text (tree, payload_tvb, 0, -1, "Alarm List (0 items)");
  alarm_tree = proto_item_add_subtree (alarm_item, ett_r3alarmlist);

  while (offset < (cmdLen - 2))
  {
    proto_item  *alarmcfg_item, *pi;
    proto_tree  *alarmcfg_tree;
    const gchar *ai;
    const gchar *as;
    guint32 alarm_len;

    if (!(ai = match_strval_ext (tvb_get_guint8 (payload_tvb, offset + 1), &r3_alarmidnames_ext)))
    {
      ai = "[Unknown Alarm ID]";
      as = "N/A";
    }
    else
      as = (tvb_get_guint8 (payload_tvb, offset + 2) & 0xfe) ?
        "Error" : (tvb_get_guint8 (payload_tvb, offset + 2) & 0x01) ? "Enabled" : "Disabled";

    alarmcfg_item = proto_tree_add_text (alarm_tree, payload_tvb, offset, tvb_get_guint8 (payload_tvb, offset),
                                         "Alarm Item (%s, %s)", ai, as);
    alarmcfg_tree = proto_item_add_subtree (alarmcfg_item, ett_r3alarmcfg);

    alarm_len = tvb_get_guint8 (payload_tvb, offset + 0);
    pi = proto_tree_add_item (alarmcfg_tree, hf_r3_alarm_length, payload_tvb, offset + 0, 1, ENC_LITTLE_ENDIAN);
    if (alarm_len == 0) {
      expert_add_info_format (pinfo, pi, PI_MALFORMED, PI_WARN,
                              "Alarm length equal to 0; payload could be partially decoded");
      break;
    }

    proto_tree_add_item (alarmcfg_tree, hf_r3_alarm_id,     payload_tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (alarmcfg_tree, hf_r3_alarm_state,  payload_tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);

    alarms++;
    offset += alarm_len;
  }

  if (alarms)
    proto_item_set_text (alarm_item, "Alarm List (%d items)", alarms);
}

static void
dissect_r3_cmd_eventlogdump (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *starttime_item;
  proto_tree *starttime_tree;
  proto_item *endtime_item;
  proto_tree *endtime_tree;
  guint8      cmdLen;
  tvbuff_t   *payload_tvb;

  if (!tree)
    return;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  starttime_item = proto_tree_add_text (tree, payload_tvb, 0, 5,
                                        "Start YY/MM/DD HH:MM (%02u/%02u/%02u %02u:%02u)",
                                        tvb_get_guint8 (payload_tvb, 0),
                                        tvb_get_guint8 (payload_tvb, 1),
                                        tvb_get_guint8 (payload_tvb, 2),
                                        tvb_get_guint8 (payload_tvb, 3),
                                        tvb_get_guint8 (payload_tvb, 4));
  starttime_tree = proto_item_add_subtree (starttime_item, ett_r3eventlogdumpstarttime);
  proto_tree_add_item (starttime_tree, hf_r3_eventlogdump_starttime_year,    payload_tvb, 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (starttime_tree, hf_r3_eventlogdump_starttime_month,   payload_tvb, 1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (starttime_tree, hf_r3_eventlogdump_starttime_day,     payload_tvb, 2, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (starttime_tree, hf_r3_eventlogdump_starttime_hours,   payload_tvb, 3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (starttime_tree, hf_r3_eventlogdump_starttime_minutes, payload_tvb, 4, 1, ENC_LITTLE_ENDIAN);

  endtime_item = proto_tree_add_text (tree, payload_tvb, 5, 5,
                                      "End YY/MM/DD HH:MM (%02u/%02u/%02u %02u:%02u)",
                                      tvb_get_guint8 (payload_tvb, 5),
                                      tvb_get_guint8 (payload_tvb, 6),
                                      tvb_get_guint8 (payload_tvb, 7),
                                      tvb_get_guint8 (payload_tvb, 8),
                                      tvb_get_guint8 (payload_tvb, 9));
  endtime_tree = proto_item_add_subtree (endtime_item, ett_r3eventlogdumpendtime);
  proto_tree_add_item (endtime_tree, hf_r3_eventlogdump_endtime_year,    payload_tvb, 5, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (endtime_tree, hf_r3_eventlogdump_endtime_month,   payload_tvb, 6, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (endtime_tree, hf_r3_eventlogdump_endtime_day,     payload_tvb, 7, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (endtime_tree, hf_r3_eventlogdump_endtime_hours,   payload_tvb, 8, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (endtime_tree, hf_r3_eventlogdump_endtime_minutes, payload_tvb, 9, 1, ENC_LITTLE_ENDIAN);

  proto_tree_add_item (tree, hf_r3_eventlogdump_user, payload_tvb, 10, 2, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmd_declinedlogdump (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *starttime_item;
  proto_tree *starttime_tree;
  proto_item *endtime_item;
  proto_tree *endtime_tree;
  guint8      cmdLen;
  tvbuff_t   *payload_tvb;

  if (!tree)
    return;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  starttime_item = proto_tree_add_text (tree, payload_tvb, 0, 5,
                                        "Start YY/MM/DD HH:MM (%02u/%02u/%02u %02u:%02u)",
                                        tvb_get_guint8 (payload_tvb, 0),
                                        tvb_get_guint8 (payload_tvb, 1),
                                        tvb_get_guint8 (payload_tvb, 2),
                                        tvb_get_guint8 (payload_tvb, 3),
                                        tvb_get_guint8 (payload_tvb, 4));
  starttime_tree = proto_item_add_subtree (starttime_item, ett_r3declinedlogdumpstarttime);
  proto_tree_add_item (starttime_tree, hf_r3_declinedlogdump_starttime_year,    payload_tvb, 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (starttime_tree, hf_r3_declinedlogdump_starttime_month,   payload_tvb, 1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (starttime_tree, hf_r3_declinedlogdump_starttime_day,     payload_tvb, 2, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (starttime_tree, hf_r3_declinedlogdump_starttime_hours,   payload_tvb, 3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (starttime_tree, hf_r3_declinedlogdump_starttime_minutes, payload_tvb, 4, 1, ENC_LITTLE_ENDIAN);

  endtime_item = proto_tree_add_text (tree, payload_tvb, 5, 5,
                                      "End YY/MM/DD HH:MM (%02u/%02u/%02u %02u:%02u)",
                                      tvb_get_guint8 (payload_tvb, 5),
                                      tvb_get_guint8 (payload_tvb, 6),
                                      tvb_get_guint8 (payload_tvb, 7),
                                      tvb_get_guint8 (payload_tvb, 8),
                                      tvb_get_guint8 (payload_tvb, 9));
  endtime_tree = proto_item_add_subtree (endtime_item, ett_r3declinedlogdumpendtime);
  proto_tree_add_item (endtime_tree, hf_r3_declinedlogdump_endtime_year,    payload_tvb, 5, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (endtime_tree, hf_r3_declinedlogdump_endtime_month,   payload_tvb, 6, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (endtime_tree, hf_r3_declinedlogdump_endtime_day,     payload_tvb, 7, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (endtime_tree, hf_r3_declinedlogdump_endtime_hours,   payload_tvb, 8, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (endtime_tree, hf_r3_declinedlogdump_endtime_minutes, payload_tvb, 9, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmd_alarmlogdump (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *starttime_item;
  proto_tree *starttime_tree;
  proto_item *endtime_item;
  proto_tree *endtime_tree;
  guint8      cmdLen;
  tvbuff_t   *payload_tvb;

  if (!tree)
    return;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  starttime_item = proto_tree_add_text (tree, payload_tvb, 0, 5,
                                        "Start YY/MM/DD HH:MM (%02u/%02u/%02u %02u:%02u)",
                                        tvb_get_guint8 (payload_tvb, 0),
                                        tvb_get_guint8 (payload_tvb, 1),
                                        tvb_get_guint8 (payload_tvb, 2),
                                        tvb_get_guint8 (payload_tvb, 3),
                                        tvb_get_guint8 (payload_tvb, 4));
  starttime_tree = proto_item_add_subtree (starttime_item, ett_r3alarmlogdumpstarttime);
  proto_tree_add_item (starttime_tree, hf_r3_alarmlogdump_starttime_year,    payload_tvb, 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (starttime_tree, hf_r3_alarmlogdump_starttime_month,   payload_tvb, 1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (starttime_tree, hf_r3_alarmlogdump_starttime_day,     payload_tvb, 2, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (starttime_tree, hf_r3_alarmlogdump_starttime_hours,   payload_tvb, 3, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (starttime_tree, hf_r3_alarmlogdump_starttime_minutes, payload_tvb, 4, 1, ENC_LITTLE_ENDIAN);

  endtime_item = proto_tree_add_text (tree, payload_tvb, 5, 5,
                                      "End YY/MM/DD HH:MM (%02u/%02u/%02u %02u:%02u)",
                                      tvb_get_guint8 (payload_tvb, 5),
                                      tvb_get_guint8 (payload_tvb, 6),
                                      tvb_get_guint8 (payload_tvb, 7),
                                      tvb_get_guint8 (payload_tvb, 8),
                                      tvb_get_guint8 (payload_tvb, 9));
  endtime_tree = proto_item_add_subtree (endtime_item, ett_r3alarmlogdumpendtime);
  proto_tree_add_item (endtime_tree, hf_r3_alarmlogdump_endtime_year,    payload_tvb, 5, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (endtime_tree, hf_r3_alarmlogdump_endtime_month,   payload_tvb, 6, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (endtime_tree, hf_r3_alarmlogdump_endtime_day,     payload_tvb, 7, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (endtime_tree, hf_r3_alarmlogdump_endtime_hours,   payload_tvb, 8, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (endtime_tree, hf_r3_alarmlogdump_endtime_minutes, payload_tvb, 9, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmd_downloadfirmware (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *dlfw_item = NULL;
  proto_item *dlfw_action_item = NULL;
  proto_tree *dlfw_tree = NULL;
  guint8      cmdLen;
  tvbuff_t   *payload_tvb;
  guint32     packetCRC;
  guint32     calculatedCRC;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

    dlfw_item = proto_tree_add_text (tree, payload_tvb, 0, -1,
                                     "Download Record (Record #%u, ", tvb_get_letohs (payload_tvb, 2));
    dlfw_tree = proto_item_add_subtree (dlfw_item, ett_r3downloadfirmware);

    proto_tree_add_item (dlfw_tree, hf_r3_firmwaredownload_length, payload_tvb, 0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (dlfw_tree, hf_r3_firmwaredownload_record, payload_tvb, 2, 2, ENC_LITTLE_ENDIAN);
    dlfw_action_item = proto_tree_add_item (dlfw_tree, hf_r3_firmwaredownload_action, payload_tvb, 4, 1, ENC_LITTLE_ENDIAN);
  }

  switch (tvb_get_guint8 (payload_tvb, 4))
  {
    case DOWNLOADFIRMWARE_START :
      if (!dlfw_tree)
        break;
      proto_item_append_text (dlfw_item, "DOWNLOADFIRMWARE_START)");
      proto_tree_add_item (dlfw_tree, hf_r3_firmwaredownload_timeout, payload_tvb, 5, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item (dlfw_tree, hf_r3_firmwaredownload_nvram,   payload_tvb, 6, 1, ENC_LITTLE_ENDIAN);
      break;

    case DOWNLOADFIRMWARE_DATA :
      if (!dlfw_tree)
        break;
      proto_item_append_text (dlfw_item, "DOWNLOADFIRMWARE_DATA, Address 0x%08x, %u Bytes)",
                              tvb_get_letohl (payload_tvb, 5), tvb_get_guint8 (payload_tvb, 9));
      proto_tree_add_item (dlfw_tree, hf_r3_firmwaredownload_address, payload_tvb, 5, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item (dlfw_tree, hf_r3_firmwaredownload_bytes,   payload_tvb, 9, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item (dlfw_tree, hf_r3_firmwaredownload_data,    payload_tvb, 10,
                           tvb_get_guint8 (payload_tvb, 9), ENC_NA);
      break;

    case DOWNLOADFIRMWARE_COMPLETE :
      if (!dlfw_tree)
        break;
      proto_item_append_text (dlfw_item, "DOWNLOADFIRMWARE_COMPLETE)");
      break;

    case DOWNLOADFIRMWARE_ABORT :
      if (!dlfw_tree)
        break;
      proto_item_append_text (dlfw_item, "DOWNLOADFIRMWARE_ABORT)");
      break;

    case DOWNLOADFIRMWARE_RESET :
      if (!dlfw_tree)
        break;
      proto_item_append_text (dlfw_item, "DOWNLOADFIRMWARE_RESET)");
      break;

    default :
      expert_add_info_format (pinfo, dlfw_action_item, PI_UNDECODED, PI_WARN, "Unknown Firmware download action");
      return;  /* quit */
  }

  if (!dlfw_tree)
    return;

  packetCRC = tvb_get_letohs (payload_tvb, cmdLen - 2 - 2);

  if ((calculatedCRC = utilCrcCalculate (tvb_get_ptr (payload_tvb, 0, cmdLen - 2 - 2),
                                         cmdLen - 2,
                                         0x0000))
      == packetCRC)
    proto_tree_add_uint_format (dlfw_tree, hf_r3_firmwaredownload_crc, payload_tvb,
                                cmdLen - 2 - 2, 2,
                                packetCRC, "CRC: 0x%04x (correct)", packetCRC);
  else
  {
    proto_item *tmp_item;

    proto_tree_add_uint_format (dlfw_tree, hf_r3_firmwaredownload_crc, payload_tvb,
                                cmdLen - 2 - 2, 2,
                                packetCRC, "CRC: 0x%04x (incorrect, should be 0x%04x)", calculatedCRC, packetCRC);
    tmp_item = proto_tree_add_boolean (dlfw_tree, hf_r3_firmwaredownload_crc_bad, payload_tvb,
                                       cmdLen - 2 - 2, 2, TRUE);
    PROTO_ITEM_SET_GENERATED (tmp_item);
  }
}

static void
dissect_r3_cmd_downloadfirmwaretimeout (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo, proto_tree *tree)
{
  guint8    cmdLen;
  tvbuff_t *payload_tvb;

  if (tree)
  {
    cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
    payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

    proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item (tree, hf_r3_commanddata, payload_tvb, 0, -1, ENC_NA);
  }
  expert_add_info_format (pinfo, proto_tree_get_parent (tree), PI_UNDECODED, PI_WARN,
                          "[### Need nice warning here]"); /* XXX: ??? */
}

static void
dissect_r3_cmd_powertableselection (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  guint8    cmdLen;
  tvbuff_t *payload_tvb;

  if (!tree)
    return;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  proto_tree_add_item (tree, hf_r3_powertableselection, payload_tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmd_clearnvram (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *nvram_item;
  proto_tree *nvram_tree;
  guint8      cmdLen;
  tvbuff_t   *payload_tvb;
  guint32     nvramclearoptions;
  guint32     i;

  if (!tree)
    return;

  cmdLen            = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb       = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  nvramclearoptions = tvb_get_letohs (payload_tvb, 0);

  nvram_item = proto_tree_add_text (tree, payload_tvb, 0, 2, "NVRAM Clean Options (0x%04x)", nvramclearoptions);
  nvram_tree = proto_item_add_subtree (nvram_item, ett_r3clearnvram);

  for (i = 0; i < 16; i++)
    proto_tree_add_boolean (nvram_tree, hf_r3_nvramclearoptions [i], payload_tvb, 0, 2, nvramclearoptions);
}

static void
dissect_r3_cmd_dpac (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  guint8    cmdLen;
  tvbuff_t *payload_tvb;

  if (!tree)
    return;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  /* XXX: hf[] entries for the following hf indexes originally missing */
  proto_tree_add_item (tree, hf_r3_dpac_action,   payload_tvb, 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_dpac_waittime, payload_tvb, 1, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_dpac_command,  payload_tvb, 3, -1, ENC_NA);
}

static void
dissect_r3_cmd_selftest (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmd_reset (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmd_logwrite (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  guint8    cmdLen;
  tvbuff_t *payload_tvb;

  if (!tree)
    return;

  cmdLen      = tvb_get_guint8 (tvb, start_offset + 0);
  payload_tvb = tvb_new_subset (tvb, start_offset + 2, cmdLen - 2, cmdLen - 2);

  proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  proto_tree_add_item (tree, hf_r3_writeeventlog_user,  payload_tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_writeeventlog_event, payload_tvb, 2, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmd_mfgcommand (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
  mfgCommandFlag = TRUE;
}

static void
dissect_r3_cmd_nvrambackup (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmd_extendedresponse (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandlength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_command,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

/*
 * ***************************************************************************
 */
static void
dissect_r3_cmdmfg_setserialnumber (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  tvbuff_t *sn_tvb = tvb_new_subset (tvb, start_offset + 2, 16, 16);

  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
  dissect_serialnumber (sn_tvb, 0, length, pinfo, tree, hf_r3_mfgsetserialnumber);
}

static void
dissect_r3_cmdmfg_setcryptkey (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_mfgsetcryptkey,   tvb, start_offset + 2, -1, ENC_NA);
  }
}

static void
dissect_r3_cmdmfg_dumpnvram (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_mfgdumpnvram,     tvb, start_offset + 2, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmdmfg_terminal (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmdmfg_remoteunlock (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_mfgremoteunlock,  tvb, start_offset + 2, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmdmfg_auxctlrversion (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmdmfg_iopins (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmdmfg_adcs (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmdmfg_hardwareid (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmdmfg_checkpointlogdump (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmdmfg_checkpointlogclear (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmdmfg_readregisters (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmdmfg_forceoptions (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  gint i;
  gint len;

  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  start_offset += 2;
  len = tvb_length_remaining (tvb, start_offset);

  for (i = 0; i < len; i += tvb_get_guint8 (tvb, start_offset + i))
  {
    proto_item *force_item = proto_tree_add_text (tree, tvb, start_offset + i, tvb_get_guint8 (tvb, start_offset + i),
                                                  "Force Option %s (%u)",
                                                  val_to_str_ext_const (
                                                    tvb_get_guint8 (tvb, start_offset + i + 1),
                                                    &r3_forceitemnames_ext, "[Unknown]"),
                                                  tvb_get_guint8 (tvb, start_offset + i + 1));
    proto_tree *force_tree = proto_item_add_subtree (force_item, ett_r3forceoptions);
    proto_item *force_item_item;

    proto_tree_add_item (force_tree, hf_r3_forceoptions_length, tvb, start_offset + i + 0, 1, ENC_LITTLE_ENDIAN);
    force_item_item = proto_tree_add_item (force_tree, hf_r3_forceoptions_item,   tvb, start_offset + i + 1, 1, ENC_LITTLE_ENDIAN);

    switch (tvb_get_guint8 (tvb, start_offset + i) - 2)
    {
      case 1  : proto_tree_add_item (force_tree, hf_r3_forceoptions_state_8,  tvb, start_offset + i + 2, 1, ENC_LITTLE_ENDIAN);
        break;
      case 2  : proto_tree_add_item (force_tree, hf_r3_forceoptions_state_16, tvb, start_offset + i + 2, 2, ENC_LITTLE_ENDIAN);
        break;
      case 3  : proto_tree_add_item (force_tree, hf_r3_forceoptions_state_24, tvb, start_offset + i + 2, 3, ENC_LITTLE_ENDIAN);
        break;
      case 4  : proto_tree_add_item (force_tree, hf_r3_forceoptions_state_32, tvb, start_offset + i + 2, 4, ENC_LITTLE_ENDIAN);
        break;
      default :
        expert_add_info_format (pinfo, force_item_item, PI_UNDECODED, PI_WARN,
                                "Invalid length for Forceoptions State entry");
        return;  /* quit */
        break;
    }
  }
}

static void
dissect_r3_cmdmfg_commuser (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmdmfg_dumpkeypad (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmdmfg_batterycheck (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmdmfg_ramrefresh (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmdmfg_taskflags (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmdmfg_timerchain (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  if (tree)
  {
    proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  }
}

static void
dissect_r3_cmdmfg_peekpoke (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  gint i;
  gint len;

  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  start_offset += 2;
  len = tvb_length_remaining (tvb, start_offset);

  for (i = 0; i < len; i += 3)
  {
    proto_item *peekpoke_item;
    proto_item *peekpoke_op_item;
    proto_tree *peekpoke_tree;

    peekpoke_item = proto_tree_add_text (tree, tvb, start_offset + i, 3, "%s", "");
    peekpoke_tree = proto_item_add_subtree (peekpoke_item, ett_r3peekpoke);

    peekpoke_op_item = proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_operation, tvb, start_offset + i + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_address,   tvb, start_offset + i + 1, 2, ENC_LITTLE_ENDIAN);

    switch (tvb_get_guint8 (tvb, start_offset + i + 0))
    {
      case PEEKPOKE_READU8 :
        proto_item_append_text (peekpoke_item, "Read (8 Bits @ 0x%04x)", tvb_get_letohs (tvb, start_offset + i + 1));
        break;

      case PEEKPOKE_READU16 :
        proto_item_append_text (peekpoke_item, "Read (16 Bits @ 0x%04x)", tvb_get_letohs (tvb, start_offset + i + 1));
        break;

      case PEEKPOKE_READU24 :
        proto_item_append_text (peekpoke_item, "Read (24 Bits @ 0x%04x)", tvb_get_letohs (tvb, start_offset + i + 1));
        break;

      case PEEKPOKE_READU32 :
        proto_item_append_text (peekpoke_item, "Read (32 Bits @ 0x%04x)", tvb_get_letohs (tvb, start_offset + i + 1));
        break;

      case PEEKPOKE_READSTRING :
        proto_item_append_text (peekpoke_item,
                                "Read (%d Bytes @ 0x%04x)",
                                tvb_get_guint8 (tvb, start_offset + i + 3),
                                tvb_get_letohs (tvb, start_offset + i + 1));
        proto_item_set_len (peekpoke_item, 4);
        proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_length, tvb, start_offset + i + 3, 1, ENC_LITTLE_ENDIAN);
        i += 1;
        break;

      case PEEKPOKE_WRITEU8 :
        proto_item_append_text (peekpoke_item,
                                "Write (8 Bits: 0x%02x @ 0x%04x)",
                                tvb_get_guint8 (tvb, start_offset + i + 3),
                                tvb_get_letohs (tvb, start_offset + i + 1));
        proto_item_set_len (peekpoke_item, 4);
        proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_poke8, tvb, start_offset + i + 3, 1, ENC_LITTLE_ENDIAN);
        i += 1;
        break;

      case PEEKPOKE_WRITEU16 :
        proto_item_append_text (peekpoke_item,
                                "Write (16 Bits: 0x%04x @ 0x%04x)",
                                tvb_get_letohs (tvb, start_offset + i + 3),
                                tvb_get_letohs (tvb, start_offset + i + 1));
        proto_item_set_len (peekpoke_item, 5);
        proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_poke16, tvb, start_offset + i + 3, 2, ENC_LITTLE_ENDIAN);
        i += 2;
        break;

      case PEEKPOKE_WRITEU24 :
        proto_item_append_text (peekpoke_item,
                                "Write (24 Bits: 0x%06x @ 0x%04x)",
                                tvb_get_letoh24 (tvb, start_offset + i + 3),
                                tvb_get_letohs (tvb, start_offset + i + 1));
        proto_item_set_len (peekpoke_item, 6);
        proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_poke24, tvb, start_offset + i + 3, 3, ENC_LITTLE_ENDIAN);
        i += 3;
        break;

      case PEEKPOKE_WRITEU32 :
        proto_item_append_text (peekpoke_item,
                                "Write (32 Bits: 0x%08x @ 0x%04x)",
                                tvb_get_letohl (tvb, start_offset + i + 3),
                                tvb_get_letohs (tvb, start_offset + i + 1));
        proto_item_set_len (peekpoke_item, 7);
        proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_poke32, tvb, start_offset + i + 3, 4, ENC_LITTLE_ENDIAN);
        i += 4;
        break;

      case PEEKPOKE_WRITESTRING :
        proto_item_append_text (peekpoke_item,
                                "Write (%d Bytes @ 0x%04x)",
                                tvb_get_guint8 (tvb, start_offset + i + 3),
                                tvb_get_letohs (tvb, start_offset + i + 1));
        proto_item_set_len (peekpoke_item, 3 + 1 + tvb_get_guint8 (tvb, start_offset + i + 3));
        proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_length,     tvb, start_offset + i + 3, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item (peekpoke_tree, hf_r3_peekpoke_pokestring, tvb, start_offset + i + 4,
                             tvb_get_guint8 (tvb, start_offset + i + 3), ENC_NA);
        i += tvb_get_guint8 (tvb, start_offset + i + 3) + 1;
        break;

      default :
        expert_add_info_format (pinfo, peekpoke_op_item, PI_UNDECODED, PI_WARN, "Unknown Mfg peekpoke operation value");
        return;  /* quit */
    }
  }
}

static void
dissect_r3_cmdmfg_lockstate (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmdmfg_capabilities (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmdmfg_dumpm41t81 (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmdmfg_debuglogdump (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmdmfg_debuglogclear (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmdmfg_testwdt (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmdmfg_querycksum (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmdmfg_validatechecksums (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmdmfg_rebuildlrucache (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmdmfg_tzupdate (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmdmfg_testpreserve (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_mfgtestpreserve,  tvb, start_offset + 2, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmdmfg_mortisestatelogdump (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmdmfg_mortisestatelogclear (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmdmfg_mortisepins (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_r3_cmdmfg_haltandcatchfire (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg,       tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);
}

/*
 */
static gint
dissect_r3_command (tvbuff_t *tvb, guint32 start_offset, guint32 length, packet_info *pinfo, proto_tree *r3_tree)
{
  proto_item  *cmd_item;
  proto_tree  *cmd_tree;
  const gchar *cn;
  guint8       cmdLen;
  guint8       cmd;

  tvb_ensure_bytes_exist (tvb, start_offset, 2);

  cmdLen = tvb_get_guint8 (tvb, start_offset + 0);
  cmd    = tvb_get_guint8 (tvb, start_offset + 1);

  if (!mfgCommandFlag)
    cn = val_to_str_ext_const (cmd, &r3_cmdnames_ext, "[Unknown Command]");
  else
    cn = val_to_str_ext_const (cmd, &r3_cmdmfgnames_ext, "[Unknown Mfg Command]");

  cmd_item = proto_tree_add_text (r3_tree, tvb, start_offset, cmdLen, "Command Packet: %s (%d)", cn, cmd);
  cmd_tree = proto_item_add_subtree (cmd_item, ett_r3cmd);

  if (!mfgCommandFlag)
  {
    if (cmd >= CMD_LAST)
      expert_add_info_format (pinfo, proto_tree_get_parent (cmd_tree), PI_UNDECODED, PI_WARN, "Unknown command value");
    else if (r3command_dissect [cmd])
      (*r3command_dissect [cmd]) (tvb, start_offset, length, pinfo, cmd_tree);
  }
  else
  {
    mfgCommandFlag = FALSE;

    if (cmd >= CMDMFG_LAST)
    {
      expert_add_info_format (pinfo, proto_tree_get_parent (cmd_tree), PI_UNDECODED, PI_WARN,
                              "Unknown manufacturing command value");
    }
    else if (r3commandmfg_dissect [cmd])
      (*r3commandmfg_dissect [cmd]) (tvb, start_offset, length, pinfo, cmd_tree);
  }

  return tvb_get_guint8 (tvb, start_offset + 0);
}

/*
 * ***************************************************************************
 *
 *  Dissect a single r3 PDU
 *
 *  return: amount consumed
 */
static int
dissect_r3_packet (tvbuff_t *tvb, packet_info *pinfo, proto_tree *r3_tree)
{
  proto_item *payload_item = NULL;
  proto_tree *payload_tree = NULL;
  guint       offset       = 0;
  guint32     packetLen;
  guint       octConsumed;

  if (tvb_strneql (tvb, 0, "~~~ds", 5) == 0)
  {
    if (r3_tree)
      proto_tree_add_item (r3_tree, hf_r3_tildex3ds, tvb, 0, -1, ENC_ASCII|ENC_NA);

    return 5;
  }

  /*
   *  Show basic header stuff
   */
  if (r3_tree)
  {
    proto_item *header_item = proto_tree_add_item (r3_tree, hf_r3_header, tvb, 0, 5, ENC_NA);
    proto_tree *header_tree = proto_item_add_subtree (header_item, ett_r3header);

    proto_tree_add_item (header_tree, hf_r3_sigil,        tvb, 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (header_tree, hf_r3_address,      tvb, 1, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (header_tree, hf_r3_packetnumber, tvb, 2, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (header_tree, hf_r3_packetlength, tvb, 3, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (header_tree, hf_r3_encryption,   tvb, 4, 1, ENC_LITTLE_ENDIAN);
  }

  /* Note: packetLen == tvb_reported_length() */

  packetLen = tvb_get_guint8 (tvb, 3);

  if (r3_tree)
  {
    payload_item = proto_tree_add_item (r3_tree, hf_r3_payload, tvb, 5, -1, ENC_NA);
    payload_tree = proto_item_add_subtree (payload_item, ett_r3payload);
  }

  offset = 5;

  mfgCommandFlag = FALSE;   /* XXX: Assumption: mfgCmd always follows Cmd in same r3 "packet" */
  while (offset < (packetLen - 3))
  {
    octConsumed = dissect_r3_command (tvb, offset, 0, pinfo, payload_tree);
    if(octConsumed == 0)
    {
      expert_add_info_format (pinfo, proto_tree_get_parent (payload_tree), PI_MALFORMED, PI_WARN,
                              "Command length equal to 0; payload could be partially decoded");
      offset = tvb_reported_length (tvb) - 3; /* just do CRC stuff ?? */
      break;
    }
    offset += octConsumed;
  }

  /*
   *  Show the CRC and XOR status
   */
  if (r3_tree)
  {
    proto_item *tail_item     = proto_tree_add_item (r3_tree, hf_r3_tail, tvb, offset, 3, ENC_NA);
    proto_tree *tail_tree     = proto_item_add_subtree (tail_item, ett_r3tail);
    guint32     packetCRC     = tvb_get_letohs (tvb, offset);
    guint32     packetXor     = tvb_get_guint8 (tvb, offset + 2);
    guint32     calculatedCRC;

    if ((calculatedCRC = utilCrcCalculate (tvb_get_ptr (tvb, 1, packetLen - 3), packetLen - 3, 0x0000)) == packetCRC)
      proto_tree_add_uint_format (tail_tree, hf_r3_crc, tvb, offset, 2, packetCRC, "CRC: 0x%04x (correct)", packetCRC);
    else
    {
      proto_item *tmp_item;

      proto_tree_add_uint_format (tail_tree, hf_r3_crc, tvb, offset, 2, packetCRC,
                                  "CRC: 0x%04x (incorrect, should be 0x%04x)", calculatedCRC, packetCRC);
      tmp_item = proto_tree_add_boolean (tail_tree, hf_r3_crc_bad, tvb, offset, 2, TRUE);
      PROTO_ITEM_SET_GENERATED (tmp_item);
    }

    if ((packetLen ^ 0xff) == packetXor)
      proto_tree_add_uint_format (tail_tree, hf_r3_xor, tvb, offset + 2, 1, packetXor,
                                  "XOR: 0x%02x (correct)", packetXor);
    else
    {
      proto_item *tmp_item;

      proto_tree_add_uint_format (tail_tree, hf_r3_xor, tvb, offset + 7, 1, packetXor,
                                  "XOR: 0x%02x (incorrect, should be 0x%02x)", packetXor, packetLen ^ 0xff);
      tmp_item = proto_tree_add_boolean (tail_tree, hf_r3_xor_bad, tvb, offset + 7, 1, TRUE);
      PROTO_ITEM_SET_GENERATED (tmp_item);
    }
  }

  offset += 3;

  return offset;
}

/*
 * ***************************************************************************
 *
 *  Main dissector entry points
 */
static void
dissect_r3_message (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *r3_tree = NULL;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, "R3");
  col_clear (pinfo->cinfo, COL_INFO);

  /* Note: The tvb (provided via tcp_dissect_pdus()) will contain (at most) one PDU of the length
   *       specified via get_r3_message_len()
   */

  if (tree)
  {
    proto_item *r3_item;
    r3_item = proto_tree_add_item (tree, proto_r3, tvb, 0, -1, ENC_NA);
    r3_tree = proto_item_add_subtree (r3_item, ett_r3);
  }

  dissect_r3_packet (tvb, pinfo, r3_tree);

  return;
}

static guint
get_r3_message_len (packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  return (guint) tvb_get_guint8 (tvb, offset + 3) + 1;
}

static void
dissect_r3 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tcp_dissect_pdus (tvb, pinfo, tree, TRUE, 4, get_r3_message_len, dissect_r3_message);
}

/*
 * ***************************************************************************
 */
void proto_register_r3 (void)
{

  /* Setup list of header fields */
  static hf_register_info hf [] =
  {
    { &hf_r3_tildex3ds,
      { "DPAC Attention", "r3.dpac_attention",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL, HFILL }
    },

    { &hf_r3_header,
      { "Header", "r3.header",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_payload,
      { "Payload", "r3.payload",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_tail,
      { "Tail", "r3.tail",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_sigil,
      { "Sigil", "r3.sigil",
	  FT_UINT8, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_address,
      { "Address", "r3.address",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_packetnumber,
      { "Packet Number", "r3.packetnumber",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_packetlength,
      { "Packet Length", "r3.packetlength",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_encryption,
      { "Crypt Type", "r3.encryption",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_encryptionschemenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_crc,
      { "CRC", "r3.crc",
	  FT_UINT16, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_crc_bad,
      { "Bad CRC", "r3.crc_bad",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_xor,
      { "XOR", "r3.xor",
	  FT_UINT8, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_xor_bad,
      { "Bad XOR", "r3.xor_bad",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_commandlength,
      { "Command Length", "r3.command.length",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_command,
      { "Command", "r3.command.command",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_cmdnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_commanddata,
      { "Command Data", "r3.command.data",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_commandmfglength,
      { "Mfg Command Length", "r3.commandmfg.length",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_commandmfg,
      { "Mfg Command", "r3.commandmfg.command",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_cmdmfgnames_ext, 0x0,
	  NULL, HFILL }
    },
  #if 0
    { &hf_r3_commandmfgdata,
      { "Mfg Command Data", "r3.commandmfg.data",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
  #endif

    { &hf_r3_responselength,
      { "Response Length", "r3.response.length",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_responsecommand,
      { "Response Command", "r3.response.command",
	FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_cmdnames_ext, 0x0,
	NULL, HFILL }
    },
    { &hf_r3_responsetype,
      { "Response Type", "r3.response.responsetype",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_responsetypenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_responsetocommand,
      { "Response To Command", "r3.response.to_command",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_cmdnames_ext, 0x0,
	  NULL, HFILL }
    },
  #if 0
    { &hf_r3_responsedata,
      { "Response Data", "r3.response.data",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
  #endif

    { &hf_r3_upstreamcommand,
      { "Upstream Command", "r3.upstreamcommand.command",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_upstreamcommandnames_ext, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_upstreamfield,
      { "Upstream Field", "r3.upstreamfield",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldlength,
      { "Field Length", "r3.upstreamfield.length",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldtype,
      { "Field Type", "r3.upstreamfield.type",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_upstreamfieldnames_ext, 0x0,
	  NULL, HFILL }
    },
  #if 0
    { &hf_r3_upstreamfielddatalen,
      { "Data Length", "r3.upstreamfield.datalen",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
  #endif
    { &hf_r3_upstreamfielderror,
      { "Error", "r3.upstreamfield.error",
	  FT_STRING, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_SERIALNUMBER],
      { "Serial Number", "r3.upstreamfield.serialnumber",
	  FT_STRING, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_NAR],
      { "Next Available Record", "r3.upstreamfield.nar",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_ENTRYDEVICE],
      { "Entry Device", "r3.upstreamfield.entrydevice",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_ppmisourcenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_PPMIFIELDTYPE],
      { "PPMI Field Type", "r3.upstreamfield.ppmifieldtype",
	  FT_UINT8, BASE_HEX_DEC|BASE_EXT_STRING, &r3_ppmisourcenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_PIN],
      { "PIN", "r3.upstreamfield.pin",
	  FT_STRING, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_SEQUENCENUMBER],
      { "Sequence Number", "r3.upstreamfield.sequencenumber",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_RESPONSEWINDOW],
      { "Response Window", "r3.upstreamfield.responsewindow",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_USERNUMBER],
      { "User Number", "r3.upstreamfield.usernumber",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_VERSION],
      { "Version", "r3.upstreamfield.version",
	  FT_STRING, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_EVENTLOGRECORD],
      { "Event Log Record", "r3.upstreamfield.eventlogrecord",
	  FT_BYTES, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_DATETIME],
      { "Date/Time", "r3.upstreamfield.datetime",
	  FT_BYTES, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_EVENTLOGRECORDCOUNT],
      { "Event Log Record Count", "r3.upstreamfield.eventlogrecordcount",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_DECLINEDRECORDCOUNT],
      { "Declined Log Record", "r3.upstreamfield.declinedlogrecord",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_DECLINEDRECORD],
      { "Declined Log", "r3.upstreamfield.declinedlog",
	  FT_BYTES, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_USERTYPE],
      { "User Type", "r3.upstreamfield.usertype",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_usertypenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_ACCESSALWAYS],
      { "Access Always", "r3.upstreamfield.accessalways",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_CACHED],
      { "Cached", "r3.upstreamfield.cached",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_PRIMARYFIELDTYPE],
      { "Primary Field Type", "r3.upstreamfield.primaryfieldtype",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_ppmisourcenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_AUXFIELDTYPE],
      { "Aux Field Type", "r3.upstreamfield.auxfieldtype",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_ppmisourcenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_ACCESSMODE],
      { "Access Mode", "r3.upstreamfield.accessmode",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_accessmodenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_EXPIREON],
      { "Expire On", "r3.upstreamfield.expireon",
	  FT_UINT24, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_USECOUNT],
      { "Use Count", "r3.upstreamfield.usecount",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_TIMEZONE],
      { "Timezone", "r3.upstreamfield.timezone",
	  FT_UINT32, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_EXCEPTIONGROUP],
      { "Exception Group", "r3.upstreamfield.exceptiongroup",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_PRIMARYPIN],
      { "Primary PIN", "r3.upstreamfield.primarypin",
	  FT_BYTES, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_AUXPIN],
      { "Aux PIN", "r3.upstreamfield.auxpin",
	  FT_BYTES, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_ALARMRECORDCOUNT],
      { "Alarm Record Count", "r3.upstreamfield.alarmrecordcount",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_ALARMRECORD],
      { "Alarm Record", "r3.upstreamfield.alarmrecord",
	  FT_BYTES, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_upstreamfieldarray [UPSTREAMFIELD_AUXCTLRVERSION],
      { "Aux Controller Version", "r3.upstreamfield.auxctlrversion",
	  FT_STRING, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_configitems,
      { "Configuration Item List", "r3.configitems",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_configitem,
      { "Configuration Item", "r3.configitem",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_configitemnames_ext, 0x0,
	  NULL, HFILL }
    },
  #if 0
    { &hf_r3_configfield,
      { "Config Field", "r3.configfield",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
  #endif
    { &hf_r3_configitemlength,
      { "Configuration Item Length", "r3.configitem.length",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_configitemtype,
      { "Configuration Item Type", "r3.configitem.type",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_configtypenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_configitemdata,
      { "Configuration Item Data", "r3.configitem.data",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_configitemdata_bool,
      { "Configuration Item Boolean", "r3.configitem.data_boolean",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_configitemdata_8,
      { "Configuration Item 8-bit", "r3.configitem.data_8",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_configitemdata_16,
      { "Configuration Item 16-bit", "r3.configitem.data_16",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_configitemdata_32,
      { "Configuration Item 32-bit", "r3.configitem.data_32",
	  FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_configitemdata_string,
      { "Configuration Item String", "r3.configitem.data_string",
	  FT_STRING, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_timezonearray [ 0],
      { "Timezone  0", "r3.timezone.0",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00000001,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [ 1],
      { "Timezone  1", "r3.timezone.1",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00000002,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [ 2],
      { "Timezone  2", "r3.timezone.2",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00000004,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [ 3],
      { "Timezone  3", "r3.timezone.3",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00000008,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [ 4],
      { "Timezone  4", "r3.timezone.4",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00000010,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [ 5],
      { "Timezone  5", "r3.timezone.5",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00000020,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [ 6],
      { "Timezone  6", "r3.timezone.6",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00000040,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [ 7],
      { "Timezone  7", "r3.timezone.7",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00000080,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [ 8],
      { "Timezone  8", "r3.timezone.8",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00000100,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [ 9],
      { "Timezone  9", "r3.timezone.9",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00000200,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [10],
      { "Timezone 10", "r3.timezone.10",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00000400,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [11],
      { "Timezone 11", "r3.timezone.11",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00000800,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [12],
      { "Timezone 12", "r3.timezone.12",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00001000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [13],
      { "Timezone 13", "r3.timezone.13",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00002000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [14],
      { "Timezone 14", "r3.timezone.14",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00004000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [15],
      { "Timezone 15", "r3.timezone.15",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00008000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [16],
      { "Timezone 16", "r3.timezone.16",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00010000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [17],
      { "Timezone 17", "r3.timezone.17",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00020000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [18],
      { "Timezone 18", "r3.timezone.18",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00040000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [19],
      { "Timezone 19", "r3.timezone.19",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00080000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [20],
      { "Timezone 20", "r3.timezone.20",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00100000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [21],
      { "Timezone 21", "r3.timezone.21",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00200000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [22],
      { "Timezone 22", "r3.timezone.22",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00400000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [23],
      { "Timezone 23", "r3.timezone.23",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x00800000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [24],
      { "Timezone 24", "r3.timezone.24",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x01000000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [25],
      { "Timezone 25", "r3.timezone.25",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x02000000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [26],
      { "Timezone 26", "r3.timezone.26",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x04000000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [27],
      { "Timezone 27", "r3.timezone.27",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x08000000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [28],
      { "Timezone 28", "r3.timezone.28",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x10000000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [29],
      { "Timezone 29", "r3.timezone.29",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x20000000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [30],
      { "Timezone 30", "r3.timezone.30",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x40000000,
	  NULL, HFILL }
    },
    { &hf_r3_timezonearray [31],
      { "Timezone 31", "r3.timezone.31",
	  FT_BOOLEAN, 32, TFS (&tfs_enabled_disabled), 0x80000000,
	  NULL, HFILL }
    },

    { &hf_r3_expireon_year,
      { "Expiration Year", "r3.expireon.year",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_expireon_month,
      { "Expiration Month", "r3.expireon.month",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_monthnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_expireon_day,
      { "Expiration Day", "r3.expireon.day",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_datetime_year,
      { "Date/Time Year", "r3.datetime.year",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_datetime_month,
      { "Date/Time Month", "r3.datetime.month",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_monthnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_datetime_day,
      { "Date/Time Day", "r3.datetime.day",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_datetime_dow,
      { "Date/Time DOW", "r3.datetime.dow",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_daynames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_datetime_hours,
      { "Date/Time Hours", "r3.datetime.hours",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_datetime_minutes,
      { "Date/Time Minutes", "r3.datetime.minutes",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_datetime_seconds,
      { "Date/Time Seconds", "r3.datetime.seconds",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_datetime_dst,
      { "Date/Time DST", "r3.datetime.dst",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_eventlog_recordnumber,
      { "Record Number", "r3.eventlog.recordnumber",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlog_year,
      { "Year", "r3.eventlog.year",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlog_month,
      { "Month", "r3.eventlog.month",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_monthnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlog_day,
      { "Day", "r3.eventlog.day",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlog_hour,
      { "Hours", "r3.eventlog.hours",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlog_minute,
      { "Minutes", "r3.eventlog.minutes",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlog_second,
      { "Seconds", "r3.eventlog.seconds",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlog_usernumber,
      { "User Number", "r3.eventlog.usernumber",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlog_event,
      { "ID", "r3.eventlog.id",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_eventnames_ext, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_declinedlog_recordnumber,
      { "Record Number", "r3.declinedlog.recordnumber",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlog_year,
      { "Year", "r3.declinedlog.year",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlog_month,
      { "Month", "r3.declinedlog.month",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_monthnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlog_day,
      { "Day", "r3.declinedlog.day",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlog_hour,
      { "Hours", "r3.declinedlog.hours",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlog_minute,
      { "Minutes", "r3.declinedlog.minutes",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlog_second,
      { "Seconds", "r3.declinedlog.seconds",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlog_usernumber,
      { "User Number", "r3.declinedlog.usernumber",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlog_cred1type,
      { "Credential 1 Type", "r3.declinedlog.cred1type",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_fieldtypenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlog_cred2type,
      { "Credential 2 Type", "r3.declinedlog.cred2type",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_fieldtypenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlog_cred1,
      { "Credential 1", "r3.declinedlog.cred1",
	  FT_BYTES, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlog_cred2,
      { "Credential 2", "r3.declinedlog.cred2",
	  FT_BYTES, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_alarmlog_recordnumber,
      { "Record Number", "r3.alarmlog.recordnumber",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlog_year,
      { "Year", "r3.alarmlog.year",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlog_month,
      { "Month", "r3.alarmlog.month",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_monthnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlog_day,
      { "Day", "r3.alarmlog.day",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlog_hour,
      { "Hours", "r3.alarmlog.hours",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlog_minute,
      { "Minutes", "r3.alarmlog.minutes",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlog_second,
      { "Seconds", "r3.alarmlog.seconds",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlog_id,
      { "ID", "r3.alarmlog.id",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_alarmidnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlog_usernumber,
      { "User Number", "r3.alarmlog.usernumber",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_debugmsg,
      { "Debug Message", "r3.debug",
	  FT_STRING, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_setdate_year,
      { "Year", "r3.setdate.year",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_setdate_month,
      { "Month", "r3.setdate.month",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_monthnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_setdate_day,
      { "Day", "r3.setdate.day",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_setdate_dow,
      { "Day-Of-Week", "r3.setdate.dow",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_daynames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_setdate_hours,
      { "Hours", "r3.setdate.hours",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_setdate_minutes,
      { "Minutes", "r3.setdate.minutes",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_setdate_seconds,
      { "Seconds", "r3.setdate.seconds",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_deleteusers,
      { "Delete Users", "r3.deleteusers",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_deleteusersnames_ext, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_defineexception_number,
      { "Exception Number", "r3.defineexception.number",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_defineexception_startdate_month,
      { "Start Month", "r3.defineexception.start.month",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_monthnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_defineexception_startdate_day,
      { "Start Day", "r3.defineexception.start.day",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_defineexception_startdate_hours,
      { "Start Hours", "r3.defineexception.start.hours",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_defineexception_startdate_minutes,
      { "Start Minutes", "r3.defineexception.start.minutes",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_defineexception_enddate_month,
      { "End Month", "r3.defineexception.end.month",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_monthnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_defineexception_enddate_day,
      { "End Day", "r3.defineexception.end.day",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_defineexception_enddate_hours,
      { "End Hours", "r3.defineexception.end.hours",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_defineexception_enddate_minutes,
      { "End Minutes", "r3.defineexception.end.minutes",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_defineexceptiongroup_number,
      { "Define Exception Group Number", "r3.defineexceptiongroup.number",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_defineexceptiongroup_bits,
      { "Define Exception Group Bit Field", "r3.defineexceptiongroup.field",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_definecalendar_number,
      { "Define Calendar Number", "r3.definecalendar.number",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_definecalendar_bits,
      { "Define Calendar Bit Field", "r3.definecalendar.field",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_definetimezone_number,
      { "Timezone Number", "r3.definetimezone.number",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_definetimezone_starttime_hours,
      { "Start Hours", "r3.definetimezone.start.hours",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_definetimezone_starttime_minutes,
      { "Start Minutes", "r3.definetimezone.start.minutes",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_definetimezone_endtime_hours,
      { "End Hours", "r3.definetimezone.end.hours",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_definetimezone_endtime_minutes,
      { "End Minutes", "r3.definetimezone.end.minutes",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_definetimezone_daymap [0],
      { "Sunday", "r3.definetimezone.daymap.sunday",
	  FT_BOOLEAN, 8, TFS (&tfs_enabled_disabled), 0x00000001,
	  NULL, HFILL }
    },
    { &hf_r3_definetimezone_daymap [1],
      { "Monday", "r3.definetimezone.daymap.monday",
	  FT_BOOLEAN, 8, TFS (&tfs_enabled_disabled), 0x00000002,
	  NULL, HFILL }
    },
    { &hf_r3_definetimezone_daymap [2],
      { "Tuesday", "r3.definetimezone.daymap.tuesday",
	  FT_BOOLEAN, 8, TFS (&tfs_enabled_disabled), 0x00000004,
	  NULL, HFILL }
    },
    { &hf_r3_definetimezone_daymap [3],
      { "Wednesday", "r3.definetimezone.daymap.wednesday",
	  FT_BOOLEAN, 8, TFS (&tfs_enabled_disabled), 0x00000008,
	  NULL, HFILL }
    },
    { &hf_r3_definetimezone_daymap [4],
      { "Thursday", "r3.definetimezone.daymap.thursday",
	  FT_BOOLEAN, 8, TFS (&tfs_enabled_disabled), 0x00000010,
	  NULL, HFILL }
    },
    { &hf_r3_definetimezone_daymap [5],
      { "Friday", "r3.definetimezone.daymap.friday",
	  FT_BOOLEAN, 8, TFS (&tfs_enabled_disabled), 0x00000020,
	  NULL, HFILL }
    },
    { &hf_r3_definetimezone_daymap [6],
      { "Saturday", "r3.definetimezone.daymap.saturday",
	  FT_BOOLEAN, 8, TFS (&tfs_enabled_disabled), 0x00000040,
	  NULL, HFILL }
    },
    { &hf_r3_definetimezone_exceptiongroup,
      { "Exception Group", "r3.definetimezone.exceptiongroup",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_definetimezone_mode,
      { "Mode", "r3.definetimezone.mode",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_timezonemodenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_definetimezone_calendar,
      { "Calendar", "r3.definetimezone.calendar",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_rmtauthretry_sequence,
      { "Remote Auth Retry Sequence", "r3.rmtauthretry.sequence",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_rmtauthretry_retry,
      { "Remote Auth Retry Mode", "r3.rmtauthretry.mode",
	  FT_BOOLEAN, BASE_NONE, TFS (&tfs_rmtauthretry_flags), 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_eventlogdump_starttime_year,
      { "Start Year", "r3.eventlogdump.start.year",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlogdump_starttime_month,
      { "Start Month", "r3.eventlogdump.start.month",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_monthnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlogdump_starttime_day,
      { "Start Day", "r3.eventlogdump.start.day",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlogdump_starttime_hours,
      { "Start Hours", "r3.eventlogdump.start.hours",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlogdump_starttime_minutes,
      { "Start Minutes", "r3.eventlogdump.start.minutes",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlogdump_endtime_year,
      { "End Year", "r3.eventlogdump.end.year",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlogdump_endtime_month,
      { "End Month", "r3.eventlogdump.end.month",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_monthnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlogdump_endtime_day,
      { "End Day", "r3.eventlogdump.end.day",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlogdump_endtime_hours,
      { "End Hours", "r3.eventlogdump.end.hours",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlogdump_endtime_minutes,
      { "End Minutes", "r3.eventlogdump.end.minutes",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_eventlogdump_user,
      { "Filter User", "r3.eventlogdump.user",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_declinedlogdump_starttime_year,
      { "Start Year", "r3.declinedlogdump.start.year",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlogdump_starttime_month,
      { "Start Month", "r3.declinedlogdump.start.month",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_monthnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlogdump_starttime_day,
      { "Start Day", "r3.declinedlogdump.start.day",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlogdump_starttime_hours,
      { "Start Hours", "r3.declinedlogdump.start.hours",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlogdump_starttime_minutes,
      { "Start Minutes", "r3.declinedlogdump.start.minutes",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlogdump_endtime_year,
      { "End Year", "r3.declinedlogdump.end.year",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlogdump_endtime_month,
      { "End Month", "r3.declinedlogdump.end.month",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_monthnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlogdump_endtime_day,
      { "End Day", "r3.declinedlogdump.end.day",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlogdump_endtime_hours,
      { "End Hours", "r3.declinedlogdump.end.hours",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_declinedlogdump_endtime_minutes,
      { "End Minutes", "r3.declinedlogdump.end.minutes",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_alarmlogdump_starttime_year,
      { "Start Year", "r3.alarmlogdump.start.year",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlogdump_starttime_month,
      { "Start Month", "r3.alarmlogdump.start.month",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_monthnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlogdump_starttime_day,
      { "Start Day", "r3.alarmlogdump.start.day",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlogdump_starttime_hours,
      { "Start Hours", "r3.alarmlogdump.start.hours",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlogdump_starttime_minutes,
      { "Start Minutes", "r3.alarmlogdump.start.minutes",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlogdump_endtime_year,
      { "End Year", "r3.alarmlogdump.end.year",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlogdump_endtime_month,
      { "End Month", "r3.alarmlogdump.end.month",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_monthnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlogdump_endtime_day,
      { "End Day", "r3.alarmlogdump.end.day",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlogdump_endtime_hours,
      { "End Hours", "r3.alarmlogdump.end.hours",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarmlogdump_endtime_minutes,
      { "End Minutes", "r3.alarmlogdump.end.minutes",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_nvramclearoptions [ 0],
      { "NVRAMCLEAROPTIONS_CFGINSTALLER", "r3.nvramclear.cfginstaller",
	  FT_BOOLEAN, 16, TFS (&tfs_enabled_disabled), 0x00000001,
	  NULL, HFILL }
    },
    { &hf_r3_nvramclearoptions [ 1],
      { "NVRAMCLEAROPTIONS_CFGADMIN", "r3.nvramclear.cfgadmin",
	  FT_BOOLEAN, 16, TFS (&tfs_enabled_disabled), 0x00000002,
	  NULL, HFILL }
    },
    { &hf_r3_nvramclearoptions [ 2],
      { "NVRAMCLEAROPTIONS_EXCEPTIONS", "r3.nvramclear.exceptions",
	  FT_BOOLEAN, 16, TFS (&tfs_enabled_disabled), 0x00000004,
	  NULL, HFILL }
    },
    { &hf_r3_nvramclearoptions [ 3],
      { "NVRAMCLEAROPTIONS_EXCEPTIONGROUPS", "r3.nvramclear.exceptiongroups",
	  FT_BOOLEAN, 16, TFS (&tfs_enabled_disabled), 0x00000008,
	  NULL, HFILL }
    },
    { &hf_r3_nvramclearoptions [ 4],
      { "NVRAMCLEAROPTIONS_CALENDARS", "r3.nvramclear.calendars",
	  FT_BOOLEAN, 16, TFS (&tfs_enabled_disabled), 0x00000010,
	  NULL, HFILL }
    },
    { &hf_r3_nvramclearoptions [ 5],
      { "NVRAMCLEAROPTIONS_TIMEZONES", "r3.nvramclear.timezones",
	  FT_BOOLEAN, 16, TFS (&tfs_enabled_disabled), 0x00000020,
	  NULL, HFILL }
    },
    { &hf_r3_nvramclearoptions [ 6],
      { "NVRAMCLEAROPTIONS_FILTERS", "r3.nvramclear.filters",
	  FT_BOOLEAN, 16, TFS (&tfs_enabled_disabled), 0x00000040,
	  NULL, HFILL }
    },
    { &hf_r3_nvramclearoptions [ 7],
      { "NVRAMCLEAROPTIONS_EVENTLOG", "r3.nvramclear.eventlog",
	  FT_BOOLEAN, 16, TFS (&tfs_enabled_disabled), 0x00000080,
	  NULL, HFILL }
    },
    { &hf_r3_nvramclearoptions [ 8],
      { "NVRAMCLEAROPTIONS_USERDATA", "r3.nvramclear.userdata",
	  FT_BOOLEAN, 16, TFS (&tfs_enabled_disabled), 0x00000100,
	  NULL, HFILL }
    },
    { &hf_r3_nvramclearoptions [ 9],
      { "NVRAMCLEAROPTIONS_DECLINEDLOG", "r3.nvramclear.declinedlog",
	  FT_BOOLEAN, 16, TFS (&tfs_enabled_disabled), 0x00000200,
	  NULL, HFILL }
    },
    { &hf_r3_nvramclearoptions [10],
      { "NVRAMCLEAROPTIONS_ALARMLOG", "r3.nvramclear.alarmlog",
	  FT_BOOLEAN, 16, TFS (&tfs_enabled_disabled), 0x00000400,
	  NULL, HFILL }
    },
    { &hf_r3_nvramclearoptions [11],
      { "NVRAMCLEAROPTIONS_LRUCACHE", "r3.nvramclear.lrucache",
	  FT_BOOLEAN, 16, TFS (&tfs_enabled_disabled), 0x00000800,
	  NULL, HFILL }
    },
    { &hf_r3_nvramclearoptions [12],
      { "NVRAMCLEAROPTIONS_DBHASH", "r3.nvramclear.dbhash",
	  FT_BOOLEAN, 16, TFS (&tfs_enabled_disabled), 0x00001000,
	  NULL, HFILL }
    },
    { &hf_r3_nvramclearoptions [13],
      { "NVRAMCLEAROPTIONS_CFGSYSTEM", "r3.nvramclear.cfgsystem",
	  FT_BOOLEAN, 16, TFS (&tfs_enabled_disabled), 0x00002000,
	  NULL, HFILL }
    },
    { &hf_r3_nvramclearoptions [14],
      { "NVRAMCLEAROPTIONS_UNUSED", "r3.nvramclear.unused",
	  FT_BOOLEAN, 16, TFS (&tfs_enabled_disabled), 0x00004000,
	  NULL, HFILL }
    },
    { &hf_r3_nvramclearoptions [15],
      { "NVRAMCLEAROPTIONS_USEBACKUP", "r3.nvramclear.usebackup",
	  FT_BOOLEAN, 16, TFS (&tfs_enabled_disabled), 0x00008000,
	  NULL, HFILL }
    },

    { &hf_r3_writeeventlog_user,
      { "User", "r3.writeeventlog.user",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_writeeventlog_event,
      { "Event", "r3.writeeventlog.event",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_eventnames_ext, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_powertableselection,
      { "Table", "r3.powertableselection",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_powertablenames_ext, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_filter_type,
      { "Type", "r3.filter.type",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_filtertypenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_filter_list,
      { "Event", "r3.filter.event",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_filtereventnames_ext, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_alarm_length,
      { "Length", "r3.alarm.length",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarm_id,
      { "ID", "r3.alarm.id",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_alarmidnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_alarm_state,
      { "State", "r3.alarm.state",
	  FT_BOOLEAN, BASE_NONE, TFS (&tfs_enabled_disabled), 0x0,
	  NULL, HFILL }
    },

    /* XXX: start: Originally missing: Best guess */
    { &hf_r3_dpac_action,
      { "Dpac Action", "r3.dpac.action",
	FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	NULL, HFILL }
    },

    { &hf_r3_dpac_waittime,
      { "Dpac Waittime", "r3.dpac.waittime",
	FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	NULL, HFILL }
    },

    { &hf_r3_dpac_command,
      { "Dpac Command", "r3.dpac.command",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	NULL, HFILL }
    },

    { &hf_r3_dpacreply_stuff,
      { "Dpac Reply Stuff", "r3.dpacreply.stuff",
	FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	NULL, HFILL }
    },

    { &hf_r3_dpacreply_length,
      { "Dpac Reply Length", "r3.dpacreply.length",
	FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	NULL, HFILL }
    },

    { &hf_r3_dpacreply_reply,
      { "Dpac Reply", "r3.dpacreply.reply",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	NULL, HFILL }
    },
    /* XXX: end: Originally missing --- */

    { &hf_r3_mfgfield_length,
      { "Field Length", "r3.mfgfield.length",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_mfgfield,
      { "Field", "r3.mfgfield.field",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_mfgfieldnames_ext, 0x0,
	  NULL, HFILL }
    },
  #if 0
    { &hf_r3_mfgfield_data,
      { "Field Data", "r3.mfgfield.data",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
  #endif

    { &hf_r3_mfgsetserialnumber,
      { "Serial Number", "r3.mfgsetserialnumber",
	  FT_STRING, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_mfgsetcryptkey,
      { "Crypt Key", "r3.mfgsetcryptkey",
	  FT_BYTES, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_mfgdumpnvram,
      { "NVRAM Section", "r3.mfgnvramdump",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_mfgnvramdumpnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_mfgremoteunlock,
      { "Remote Unlock", "r3.mfgremoteunlock",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_mfgremoteunlocknames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_mfgtestpreserve,
      { "Preserve Mode", "r3.mfgtestpreserve",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_mfgtestpreservenames_ext, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_adc [0],
      { "ADC 0", "r3.adc.0",
	  FT_UINT8, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adc [1],
      { "ADC 1", "r3.adc.1",
	  FT_UINT8, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adc [2],
      { "ADC 2", "r3.adc.2",
	  FT_UINT8, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adc [3],
      { "ADC 3", "r3.adc.3",
	  FT_UINT8, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adc [4],
      { "ADC 4", "r3.adc.4",
	  FT_UINT8, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adc [5],
      { "ADC 5", "r3.adc.5",
	  FT_UINT8, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adc [6],
      { "ADC 6", "r3.adc.6",
	  FT_UINT8, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adc [7],
      { "ADC 7", "r3.adc.7",
	  FT_UINT8, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_hardwareid_board,
      { "Board ID", "r3.hardwareid.board",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_hardwareid_cpuid,
      { "CPU ID", "r3.hardwareid.cpuid",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_hardwareid_cpurev,
      { "CPU Rev", "r3.hardwareid.cpurev",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_testkeypad,
      { "Keypad Char", "r3.test.keypad",
	  FT_UINT8, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_testmagcard,
      { "Mag Card", "r3.test.magcard",
	  FT_STRING, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_testproxcard,
      { "Prox Card", "r3.test.proxcard",
	  FT_STRING, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_nvramdump_record,
      { "Record Number", "r3.nvramdump.record",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_nvramdump_length,
      { "Record Length", "r3.nvramdump.length",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_nvramdump_data,
      { "Record Data", "r3.nvramdump.data",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_nvramdumprle_record,
      { "Record Number", "r3.nvramdumprle.record",
	  FT_UINT24, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_nvramdumprle_length,
      { "Record Length", "r3.nvramdumprle.length",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_nvramdumprle_data,
      { "Record Data", "r3.nvramdumprle.data",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_iopins_lat,
      { "LAT", "r3.iopins.lat",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_iopins_port,
      { "PORT", "r3.iopins.port",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_iopins_tris,
      { "TRIS", "r3.iopins.tris",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_mortisepins_s1,
      { "Mortise Pin S1", "r3.mortisepins.s1",
	  FT_BOOLEAN, 8, TFS (&tfs_mortisepins_flags), 0x00000001,
	  NULL, HFILL }
    },
    { &hf_r3_mortisepins_s2,
      { "Mortise Pin S2", "r3.mortisepins.s2",
	  FT_BOOLEAN, 8, TFS (&tfs_mortisepins_flags), 0x00000002,
	  NULL, HFILL }
    },
    { &hf_r3_mortisepins_s3,
      { "Mortise Pin S3", "r3.mortisepins.s3",
	  FT_BOOLEAN, 8, TFS (&tfs_mortisepins_flags), 0x00000004,
	  NULL, HFILL }
    },
    { &hf_r3_mortisepins_s4,
      { "Mortise Pin S4", "r3.mortisepins.s4",
	  FT_BOOLEAN, 8, TFS (&tfs_mortisepins_flags), 0x00000008,
	  NULL, HFILL }
    },

    { &hf_r3_checksumresults ,
      { "Checksum Results", "r3.checksumresults",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_checksumresults_field,
      { "Field", "r3.checksumresults.field",
	  FT_UINT8, BASE_HEX|BASE_EXT_STRING, & r3_checksumresultnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_checksumresults_length,
      { "Length", "r3.checksumresults.length",
	  FT_UINT8, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_checksumresults_state,
      { "State", "r3.checksumresults.state",
	  FT_BOOLEAN, BASE_NONE, TFS (&tfs_errornoerror_flags), 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_forceoptions_item,
      { "Item", "r3.forceoptions.item",
	  FT_UINT8, BASE_HEX_DEC|BASE_EXT_STRING, &r3_forceitemnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_forceoptions_length,
      { "Length", "r3.forceoptions.length",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_forceoptions_state_8,
      { "State", "r3.forceoptions.state",
	  FT_BOOLEAN, BASE_NONE, TFS (&tfs_enabled_disabled), 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_forceoptions_state_16,
      { "State", "r3.forceoptions.state",
	  FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_forceoptions_state_24,
      { "State", "r3.forceoptions.state",
	  FT_UINT24, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_forceoptions_state_32,
      { "State", "r3.forceoptions.state",
	  FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_peekpoke_operation,
      { "Operation", "r3.peekpoke.operation",
	  FT_UINT8, BASE_HEX_DEC|BASE_EXT_STRING, &r3_peekpokenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_peekpoke_address,
      { "Address", "r3.peekpoke.address",
	  FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_peekpoke_length,
      { "Length", "r3.peekpoke.length",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_peekpoke_poke8,
      { "8 Bit Value", "r3.peekpoke.poke8",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_peekpoke_poke16,
      { "16 Bit Value", "r3.peekpoke.poke16",
	  FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_peekpoke_poke24,
      { "24 Bit Value", "r3.peekpoke.poke24",
	  FT_UINT24, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_peekpoke_poke32,
      { "32 Bit Value", "r3.peekpoke.poke32",
	  FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_peekpoke_pokestring,
      { "String Value", "r3.peekpoke.pokestring",
	  FT_BYTES, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_firmwaredownload_length,
      { "Length", "r3.firmwaredownload.length",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_firmwaredownload_record,
      { "Record Number", "r3.firmwaredownload.record",
	  FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_firmwaredownload_action,
      { "Action", "r3.firmwaredownload.action",
	  FT_UINT8, BASE_HEX_DEC|BASE_EXT_STRING, &r3_downloadfirmwarenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_firmwaredownload_timeout,
      { "Timeout", "r3.firmwaredownload.timeout",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_firmwaredownload_nvram,
      { "NVRAM", "r3.firmwaredownload.nvram",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_firmwaredownload_address,
      { "Address", "r3.firmwaredownload.address",
	  FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_firmwaredownload_bytes,
      { "Bytes", "r3.firmwaredownload.bytes",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_firmwaredownload_data,
      { "Data", "r3.firmwaredownload.data",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_firmwaredownload_crc,
      { "CRC", "r3.firmwaredownload.crc",
	  FT_UINT16, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_firmwaredownload_crc_bad,
      { "Bad CRC", "r3.firmwaredownload.crc_bad",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_nvramchecksumvalue,
      { "Value", "r3.nvramchecksum.value",
	  FT_UINT32, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_nvramchecksumvalue_fixup,
      { "Fixup", "r3.nvramchecksum.fixup",
	  FT_UINT32, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_capabilities,
      { "Capability", "r3.capabilities",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_capabilities_length,
      { "Length", "r3.capabilities.length",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_capabilities_type,
      { "Type", "r3.capabilities.type",
	  FT_UINT8, BASE_HEX_DEC|BASE_EXT_STRING, &r3_capabilitiesnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_capabilities_value,
      { "Value", "r3.capabilities.value",
	  FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_lockstate_passage,
      { "Passage", "r3.lockstate.passage",
	  FT_BOOLEAN, 24, NULL, 0x00000001,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_panic,
      { "Panic", "r3.lockstate.panic",
	  FT_BOOLEAN, 24, NULL, 0x00000002,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_lockout,
      { "Lockout", "r3.lockstate.lockout",
	  FT_BOOLEAN, 24, NULL, 0x00000004,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_relock,
      { "Relock", "r3.lockstate.relock",
	  FT_BOOLEAN, 24, NULL, 0x00000008,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_autoopen,
      { "Auto Open", "r3.lockstate.autoopen",
	  FT_BOOLEAN, 24, NULL, 0x00000010,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_nextauto,
      { "Next Auto", "r3.lockstate.nextauto",
	  FT_BOOLEAN, 24, NULL, 0x00000020,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_lockstate,
      { "Lock State", "r3.lockstate.lockstate",
	  FT_BOOLEAN, 24, NULL, 0x00000040,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_wantstate,
      { "Want State", "r3.lockstate.wantstate",
	  FT_BOOLEAN, 24, NULL, 0x00000080,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_remote,
      { "Remote", "r3.lockstate.remote",
	  FT_BOOLEAN, 24, NULL, 0x00000100,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_update,
      { "Update", "r3.lockstate.update",
	  FT_BOOLEAN, 24, NULL, 0x00000200,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_exceptionspresent,
      { "Exceptions Present", "r3.lockstate.exceptionspresent",
	  FT_BOOLEAN, 24, NULL, 0x00000400,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_exceptionsactive,
      { "Exceptions Active", "r3.lockstate.exceptionsactive",
	  FT_BOOLEAN, 24, NULL, 0x00000800,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_timezonespresent,
      { "Timezones Presents", "r3.lockstate.timezonespresent",
	  FT_BOOLEAN, 24, NULL, 0x00001000,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_timezonesactive,
      { "Timezones Active", "r3.lockstate.timezonesactive",
	  FT_BOOLEAN, 24, NULL, 0x00002000,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_autounlockspresent,
      { "Auto Unlocks Present", "r3.lockstate.autounlockspresent",
	  FT_BOOLEAN, 24, NULL, 0x00004000,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_autounlocksactive,
      { "Auto Unlocks Active", "r3.lockstate.autounlocksactive",
	  FT_BOOLEAN, 24, NULL, 0x00008000,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_uapmspresent,
      { "UAPMs Present", "r3.lockstate.uapmspresent",
	  FT_BOOLEAN, 24, NULL, 0x00010000,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_uapmsactive,
      { "UAPMs Active", "r3.lockstate.uapmsactive",
	  FT_BOOLEAN, 24, NULL, 0x00020000,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_uapmrelockspresent,
      { "UAPM Relocks Present", "r3.lockstate.uapmrelockspresent",
	  FT_BOOLEAN, 24, NULL, 0x00040000,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_uapmreslocksactive,
      { "UAPM Relocks Active", "r3.lockstate.uapmreslocksactive",
	  FT_BOOLEAN, 24, NULL, 0x00080000,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_nvramprotect,
      { "NVRAM Protect", "r3.lockstate.nvramprotect",
	  FT_BOOLEAN, 24, NULL, 0x00100000,
	  NULL, HFILL }
    },
    { &hf_r3_lockstate_nvramchecksum,
      { "MVRAM Checksum", "r3.lockstate.nvramchecksum",
	  FT_BOOLEAN, 24, NULL, 0x00200000,
	  NULL, HFILL }
    },

  #if 0
    { &hf_r3_mortisestatelog,
      { "Mortise State Log", "r3.mortisestatelog",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
  #endif
    { &hf_r3_mortisestatelog_pointer,
      { "Event Pointer", "r3.mortisestatelog.pointer",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_mortisestatelog_mortisetype,
      { "Mortise Type", "r3.mortisestatelog.mortisetype",
	  FT_UINT8, BASE_HEX_DEC|BASE_EXT_STRING, &r3_mortisetypenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_mortisestatelog_waiting,
      { "Waiting For Door Closed", "r3.mortisestatelog.waiting",
	  FT_BOOLEAN, BASE_NONE, TFS (&tfs_true_false ), 0x00,
	  NULL, HFILL }
    },
    { &hf_r3_mortisestatelog_state,
      { "State", "r3.mortisestatelog.state",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_mortisestatelog_last,
      { "Last State", "r3.mortisestatelog.laststate",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_mortisestatelog_event,
      { "Event", "r3.mortisestatelog.event",
	  FT_UINT8, BASE_HEX_DEC|BASE_EXT_STRING, &r3_mortiseeventnames_ext, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_timerchain_newtick,
      { "New Tick", "r3.timerchain.newtick",
	  FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_timerchain_currentboundary,
      { "Current Boundary", "r3.timerchain.currentboundary",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_timerchain_tasktag,
      { "Task Tag", "r3.timerchain.tasktag",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_timerchain_address,
      { "Address", "r3.timerchain.address",
	  FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_timerchain_reload,
      { "Reload", "r3.timerchain.reload",
	  FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_timerchain_boundary,
      { "Boundary", "r3.timerchain.boundary",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_timerchain_count,
      { "Count", "r3.timerchain.count",
	  FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_timerchain_flags,
      { "Flags", "r3.timerchain.flags",
	  FT_UINT32, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_taskflags_taskid,
      { "Task ID", "r3.taskflags.taskid",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_taskflags_flags,
      { "Flags", "r3.taskflags.flags",
	  FT_UINT32, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_checkpointlog_entryptr,
      { "Entry Pointer", "r3.checkpointlog.entrypointer",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_checkpointlog_rcon,
      { "RCON", "r3.checkpointlog.rcon",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_checkpointlog_checkpoint,
      { "Checkpoint", "r3.checkpointlog.checkpoint",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_cpuregisters_intcon,
      { "INTCON", "r3.cpuregisters.intcon",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon2,
      { "INTCON2", "r3.cpuregisters.intcon2",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon3,
      { "INTCON3", "r3.cpuregisters.intcon3",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir1,
      { "PIR1", "r3.cpuregisters.pir1",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir2,
      { "PIR2", "r3.cpuregisters.pir2",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir3,
      { "PIR3", "r3.cpuregisters.pir3",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie1,
      { "PIE1", "r3.cpuregisters.pie1",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie2,
      { "PIE2", "r3.cpuregisters.pie2",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie3,
      { "PIE3", "r3.cpuregisters.pie3",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr1,
      { "IPR1", "r3.cpuregisters.ipr1",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr2,
      { "IPR2", "r3.cpuregisters.ipr2",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr3,
      { "IPR3", "r3.cpuregisters.ipr3",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcon,
      { "RCON", "r3.cpuregisters.rcon",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_osccon,
      { "OSCCON", "r3.cpuregisters.osccon",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta,
      { "RCSTA", "r3.cpuregisters.rcsta",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta,
      { "TXSTA", "r3.cpuregisters.txsta",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta2,
      { "RCSTA2", "r3.cpuregisters.rcsta2",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta2,
      { "TXSTA2", "r3.cpuregisters.txsta2",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_wdtcon,
      { "WDTCON", "r3.cpuregisters.wdtcon",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_cpuregisters_intcon_rbif,
      { "INTCON.RBIF", "r3.cpuregisters.intcon.rbif",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon_int0if,
      { "INTCON.INT0IF", "r3.cpuregisters.intcon.int0if",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon_tmr0if,
      { "INTCON.TMR0IF", "r3.cpuregisters.intcon.tmr0if",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon_rbie,
      { "INTCON.RBIE", "r3.cpuregisters.intcon.rbie",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon_int0ie,
      { "INTCON.INT0IE", "r3.cpuregisters.intcon.int0ie",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon_tmr0ie,
      { "INTCON.TMR0IE", "r3.cpuregisters.intcon.tmr0ie",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon_giel,
      { "INTCON.GIEL", "r3.cpuregisters.intcon.giel",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon_gieh,
      { "INTCON.GIEH", "r3.cpuregisters.intcon.gieh",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon2_rbip,
      { "INTCON2.RBIP", "r3_cpuregisters_intcon2_rbip",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon2_int3ip,
      { "INTCON2.INT3IP", "r3_cpuregisters_intcon2_int3ip",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon2_tmr0ip,
      { "INTCON2.TMR0IP", "r3_cpuregisters_intcon2_tmr0ip",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon2_intedg3,
      { "INTCON2.INTEDG3", "r3_cpuregisters_intcon2_intedg3",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon2_intedg2,
      { "INTCON2.INTEDG2", "r3_cpuregisters_intcon2_intedg2",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon2_intedg1,
      { "INTCON2.INTEDG1", "r3_cpuregisters_intcon2_intedg1",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon2_intedg0,
      { "INTCON2.INTEDG0", "r3_cpuregisters_intcon2_intedg0",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon2_rbpu,
      { "INTCON2.RBPU", "r3_cpuregisters_intcon2_rbpu",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon3_int1if,
      { "INTCON3.INT1IF", "r3.cpuregisters.intcon3.int1if",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon3_int2if,
      { "INTCON3.INT2IF", "r3.cpuregisters.intcon3.int2if",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon3_int3if,
      { "INTCON3.INT3IF", "r3.cpuregisters.intcon3.int3if",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon3_int1ie,
      { "INTCON3.INT1IE", "r3.cpuregisters.intcon3.int1ie",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon3_int2ie,
      { "INTCON3.INT2IE", "r3.cpuregisters.intcon3.int2ie",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon3_int3ie,
      { "INTCON3.INT3IE", "r3.cpuregisters.intcon3.int3ie",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon3_int1ip,
      { "INTCON3.INT1IP", "r3.cpuregisters.intcon3.int1ip",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_intcon3_int2ip,
      { "INTCON3.INT2IP", "r3.cpuregisters.intcon3.int2ip",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir1_tmr1if,
      { "PIR1.TMR1IF", "r3.cpuregisters.pir1.tmr1if",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir1_tmr2if,
      { "PIR1.TMR2IF", "r3.cpuregisters.pir1.tmr2if",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir1_ccp1if,
      { "PIR1.CCP1IF", "r3.cpuregisters.pir1.ccp1if",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir1_ssp1if,
      { "PIR1.SSP1IF", "r3.cpuregisters.pir1.ssp1if",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir1_tx1if,
      { "PIR1.TX1IF", "r3.cpuregisters.pir1.tx1if",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir1_rc1if,
      { "PIR1.RC1IF", "r3.cpuregisters.pir1.rc1if",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir1_adif,
      { "PIR1.ADIF", "r3.cpuregisters.pir1.adif",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir1_pspif,
      { "PIR1.PSPIF", "r3.cpuregisters.pir1.pspif",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir2_ccp2if,
      { "PIR2.CCP2IF", "r3.cpuregisters.pir2.ccp2if",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir2_tmr3if,
      { "PIR2.TMR3IF", "r3.cpuregisters.pir2.tmr3if",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir2_hlvdif,
      { "PIR2.HLVDIF", "r3.cpuregisters.pir2.hlvdif",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir2_bcl1if,
      { "PIR2.BCL1IF", "r3.cpuregisters.pir2.bcl1if",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir2_eeif,
      { "PIR2.EEIF", "r3.cpuregisters.pir2.eeif",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir2_unused5,
      { "PIR2.UNUSED5", "r3.cpuregisters.pir2.unused5",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir2_cmif,
      { "PIR2.CMIF", "r3.cpuregisters.pir2.cmif",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir2_oscfif,
      { "PIR2.OSCFIF", "r3.cpuregisters.pir2.oscfif",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir3_ccp3if,
      { "PIR3.CCP3IF", "r3.cpuregisters.pir3.ccp3if",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir3_ccp4if,
      { "PIR3.CCP4IF", "r3.cpuregisters.pir3.ccp4if",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir3_ccp5if,
      { "PIR3.CCP5IF", "r3.cpuregisters.pir3.ccp5if",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir3_tmr4if,
      { "PIR3.TMR4IF", "r3.cpuregisters.pir3.tmr4if",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir3_tx2if,
      { "PIR3.TX2IF", "r3.cpuregisters.pir3.tx2if",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir3_rc2if,
      { "PIR3.RC2IF", "r3.cpuregisters.pir3.rc2if",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir3_bcl2if,
      { "PIR3.BCL2IF", "r3.cpuregisters.pir3.bcl2if",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pir3_ssp2if,
      { "PIR3.SSP2IF", "r3.cpuregisters.pir3.ssp2if",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie1_tmr1ie,
      { "PIE1.TMR1IE", "r3.cpuregisters.pie1.tmr1ie",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie1_tmr2ie,
      { "PIE1.TMR2IE", "r3.cpuregisters.pie1.tmr2ie",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie1_ccp1ie,
      { "PIE1.CCP1IE", "r3.cpuregisters.pie1.ccp1ie",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie1_ssp1ie,
      { "PIE1.SSP1IE", "r3.cpuregisters.pie1.ssp1ie",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie1_tx1ie,
      { "PIE1.TX1IE", "r3.cpuregisters.pie1.tx1ie",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie1_rc1ie,
      { "PIE1.RC1IE", "r3.cpuregisters.pie1.rc1ie",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie1_adie,
      { "PIE1.ADIE", "r3.cpuregisters.pie1.adie",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie1_pspie,
      { "PIE1.PSPIE", "r3.cpuregisters.pie1.pspie",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie2_oscfie,
      { "PIE2.OSCFIE", "r3.cpuregisters.pie2.oscfie",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie2_cmie,
      { "PIE2.CMIE", "r3.cpuregisters.pie2.cmie",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie2_unused2,
      { "PIE2.UNUSED2", "r3.cpuregisters.pie2.unused2",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie2_eeie,
      { "PIE2.EEIE", "r3.cpuregisters.pie2.eeie",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie2_bcl1ie,
      { "PIE2.BCL1IE", "r3.cpuregisters.pie2.bcl1ie",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie2_hlvdie,
      { "PIE2.HLVDIE", "r3.cpuregisters.pie2.hlvdie",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie2_tmr3ie,
      { "PIE2.TMR3IE", "r3.cpuregisters.pie2.tmr3ie",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie2_ccp2ie,
      { "PIE2.CCP2IE", "r3.cpuregisters.pie2.ccp2ie",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie3_ccp3ie,
      { "PIE3.CCP3IE", "r3.cpuregisters.pie3.ccp3ie",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie3_ccp4ie,
      { "PIE3.CCP4IE", "r3.cpuregisters.pie3.ccp4ie",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie3_ccp5ie,
      { "PIE3.CCP5IE", "r3.cpuregisters.pie3.ccp5ie",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie3_tmr4ie,
      { "PIE3.TMR4IE", "r3.cpuregisters.pie3.tmr4ie",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie3_tx2ie,
      { "PIE3.TX2IE", "r3.cpuregisters.pie3.tx2ie",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie3_rc2ie,
      { "PIE3.RC2IE", "r3.cpuregisters.pie3.rc2ie",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie3_bcl2ie,
      { "PIE3.BCL2IE", "r3.cpuregisters.pie3.bcl2ie",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_pie3_ssp2ie,
      { "PIE3.SSP2IE", "r3.cpuregisters.pie3.ssp2ie",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr1_tmr1ip,
      { "IPR1.TMR1IP", "r3.cpuregisters.ipr1.tmr1ip",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr1_tmr2ip,
      { "IPR1.TMR2IP", "r3.cpuregisters.ipr1.tmr2ip",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr1_ccp1ip,
      { "IPR1.CCP1IP", "r3.cpuregisters.ipr1.ccp1ip",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr1_ssp1ip,
      { "IPR1.SSP1IP", "r3.cpuregisters.ipr1.ssp1ip",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr1_tx1ip,
      { "IPR1.TX1IP", "r3.cpuregisters.ipr1.tx1ip",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr1_rc1ip,
      { "IPR1.RC1IP", "r3.cpuregisters.ipr1.rc1ip",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr1_adip,
      { "IPR1.ADIP", "r3.cpuregisters.ipr1.adip",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr1_pspip,
      { "IPR1.PSPIP", "r3.cpuregisters.ipr1.pspip",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr2_ccp2ip,
      { "IPR2.CCP2IP", "r3.cpuregisters.ipr2.ccp2ip",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr2_tmr3ip,
      { "IPR2.TMR3IP", "r3.cpuregisters.ipr2.tmr3ip",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr2_hlvdip,
      { "IPR2.HLVDIP", "r3.cpuregisters.ipr2.hlvdip",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr2_bcl1ip,
      { "IPR2.BCL1IP", "r3.cpuregisters.ipr2.bcl1ip",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr2_eeip,
      { "IPR2.EEIP", "r3.cpuregisters.ipr2.eeip",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr2_unused5,
      { "IPR2.UNUSED5", "r3.cpuregisters.ipr2.unused5",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr2_cmip,
      { "IPR2.CMIP", "r3.cpuregisters.ipr2.cmip",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr2_oscfip,
      { "IPR2.OSCFIP", "r3.cpuregisters.ipr2.oscfip",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr3_ccp2ip,
      { "IPR3.CCP2IP", "r3.cpuregisters.ipr3.ccp2ip",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr3_ccp4ip,
      { "IPR3.CCP4IP", "r3.cpuregisters.ipr3.ccp4ip",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr3_ccp5ip,
      { "IPR3.CCP5IP", "r3.cpuregisters.ipr3.ccp5ip",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr3_tmr4ip,
      { "IPR3.TMR4IP", "r3.cpuregisters.ipr3.tmr4ip",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr3_tx2ip,
      { "IPR3.TX2IP", "r3.cpuregisters.ipr3.tx2ip",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr3_rc2ip,
      { "IPR3.RC2IP", "r3.cpuregisters.ipr3.rc2ip",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr3_bcl2ip,
      { "IPR3.BCL2IP", "r3.cpuregisters.ipr3.bcl2ip",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_ipr3_ssp2ip,
      { "IPR3.SSP2IP", "r3.cpuregisters.ipr3.ssp2ip",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcon_bor,
      { "RCON./BOR", "r3.cpuregisters.rcon.bor",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcon_por,
      { "RCON./POR", "r3.cpuregisters.rcon.por",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcon_pd,
      { "RCON./PD", "r3.cpuregisters.rcon.pd",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcon_to,
      { "RCON./TO", "r3.cpuregisters.rcon.to",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcon_unused4,
      { "RCON.UNUSED4", "r3.cpuregisters.rcon.unused4",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcon_ri,
      { "RCON./RI", "r3.cpuregisters.rcon.ri",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcon_sboren,
      { "RCON.SBOREN", "r3.cpuregisters.rcon.sboren",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcon_ipen,
      { "RCON.IPEN", "r3.cpuregisters.rcon.ipen",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_osccon_scs0,
      { "OSCCON.SCS0", "r3.cpuregisters.osccon.scs0",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_osccon_scs1,
      { "OSCCON.SCS1", "r3.cpuregisters.osccon.scs1",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_osccon_iofs,
      { "OSCCON.IOFS", "r3.cpuregisters.osccon.iofs",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_osccon_osts,
      { "OSCCON.OSTS", "r3.cpuregisters.osccon.osts",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_osccon_ircf0,
      { "OSCCON.IRCF0", "r3.cpuregisters.osccon.ircf0",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_osccon_ircf1,
      { "OSCCON.IRCF1", "r3.cpuregisters.osccon.ircf1",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_osccon_ircf2,
      { "OSCCON.IRCF2", "r3.cpuregisters.osccon.ircf2",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_osccon_idlen,
      { "OSCCON.IDLEN", "r3.cpuregisters.osccon.idlen",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta_rx9d,
      { "RCSTA.RX9D", "r3.cpuregisters.rcsta.rx9d",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta_oerr,
      { "RCSTA.OERR", "r3.cpuregisters.rcsta.oerr",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta_ferr,
      { "RCSTA.FERR", "r3.cpuregisters.rcsta.ferr",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta_adden,
      { "RCSTA.ADDEN", "r3.cpuregisters.rcsta.adden",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta_cren,
      { "RCSTA.CREN", "r3.cpuregisters.rcsta.cren",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta_sren,
      { "RCSTA.SREN", "r3.cpuregisters.rcsta.sren",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta_rx9,
      { "RCSTA.RX9", "r3.cpuregisters.rcsta.rx9",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta_spen,
      { "RCSTA.SPEN", "r3.cpuregisters.rcsta.spen",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta_tx9d,
      { "TXSTA.TX9D", "r3.cpuregisters.txsta.tx9d",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta_trmt,
      { "TXSTA.TRMT", "r3.cpuregisters.txsta.trmt",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta_brgh,
      { "TXSTA.BRGH", "r3.cpuregisters.txsta.brgh",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta_sendb,
      { "TXSTA.SENDB", "r3.cpuregisters.txsta.sendb",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta_sync,
      { "TXSTA.SYNC", "r3.cpuregisters.txsta.sync",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta_txen,
      { "TXSTA.TXEN", "r3.cpuregisters.txsta.txen",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta_tx9,
      { "TXSTA.TX9", "r3.cpuregisters.txsta.tx9",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta_csrc,
      { "TXSTA.CSRC", "r3.cpuregisters.txsta.csrc",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta2_rx9d,
      { "RCSTA2.RX9D", "r3.cpuregisters.rcsta2.rx9d",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta2_oerr,
      { "RCSTA2.OERR", "r3.cpuregisters.rcsta2.oerr",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta2_ferr,
      { "RCSTA2.FERR", "r3.cpuregisters.rcsta2.ferr",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta2_adden,
      { "RCSTA2.ADDEN", "r3.cpuregisters.rcsta2.adden",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta2_cren,
      { "RCSTA2.CREN", "r3.cpuregisters.rcsta2.cren",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta2_sren,
      { "RCSTA2.SREN", "r3.cpuregisters.rcsta2.sren",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta2_rx9,
      { "RCSTA2.RX9", "r3.cpuregisters.rcsta2.rx9",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_rcsta2_spen,
      { "RCSTA2.SPEN", "r3.cpuregisters.rcsta2.spen",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta2_tx9d,
      { "TXSTA2.TX9D", "r3.cpuregisters.txsta2.tx9d",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta2_trmt,
      { "TXSTA2.TRMT", "r3.cpuregisters.txsta2.trmt",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta2_brgh,
      { "TXSTA2.BRGH", "r3.cpuregisters.txsta2.brgh",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta2_sendb,
      { "TXSTA2.SENDB", "r3.cpuregisters.txsta2.sendb",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta2_sync,
      { "TXSTA2.SYNC", "r3.cpuregisters.txsta2.sync",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta2_txen,
      { "TXSTA2.TXEN", "r3.cpuregisters.txsta2.txen",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta2_tx9,
      { "TXSTA2.TX9", "r3.cpuregisters.txsta2.tx9",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_txsta2_csrc,
      { "TXSTA2.CSRC", "r3.cpuregisters.txsta2.csrc",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_wdtcon_swdten,
      { "WDTCON.SWDTEN", "r3.cpuregisters.wdtcon.swdten",
	  FT_BOOLEAN, 8, NULL, 0x01,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_wdtcon_unused1,
      { "WDTCON.UNUSED1", "r3.cpuregisters.wdtcon.unused1",
	  FT_BOOLEAN, 8, NULL, 0x02,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_wdtcon_unused2,
      { "WDTCON.UNUSED2", "r3.cpuregisters.wdtcon.unused2",
	  FT_BOOLEAN, 8, NULL, 0x04,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_wdtcon_unused3,
      { "WDTCON.UNUSED3", "r3.cpuregisters.wdtcon.unused3",
	  FT_BOOLEAN, 8, NULL, 0x08,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_wdtcon_unused4,
      { "WDTCON.UNUSED4", "r3.cpuregisters.wdtcon.unused4",
	  FT_BOOLEAN, 8, NULL, 0x10,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_wdtcon_unused5,
      { "WDTCON.UNUSED5", "r3.cpuregisters.wdtcon.unused5",
	  FT_BOOLEAN, 8, NULL, 0x20,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_wdtcon_unused6,
      { "WDTCON.UNUSED6", "r3.cpuregisters.wdtcon.unused6",
	  FT_BOOLEAN, 8, NULL, 0x40,
	  NULL, HFILL }
    },
    { &hf_r3_cpuregisters_wdtcon_unused7,
      { "WDTCON.UNUSED7", "r3.cpuregisters.wdtcon.unused7",
	  FT_BOOLEAN, 8, NULL, 0x80,
	  NULL, HFILL }
    },

    { &hf_r3_dumpm41t81_reg00,
      { "REG 0x00", "r3.m41t81.reg00",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg01,
      { "REG 0x01", "r3.m41t81.reg01",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg02,
      { "REG 0x02", "r3.m41t81.reg02",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg03,
      { "REG 0x03", "r3.m41t81.reg03",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg04,
      { "REG 0x04", "r3.m41t81.reg04",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg05,
      { "REG 0x05", "r3.m41t81.reg05",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg06,
      { "REG 0x06", "r3.m41t81.reg06",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg07,
      { "REG 0x07", "r3.m41t81.reg07",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg08,
      { "REG 0x08", "r3.m41t81.reg08",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg09,
      { "REG 0x09", "r3.m41t81.reg09",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0a,
      { "REG 0x0a", "r3.m41t81.reg0a",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0b,
      { "REG 0x0b", "r3.m41t81.reg0b",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0c,
      { "REG 0x0c", "r3.m41t81.reg0c",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0d,
      { "REG 0x0d", "r3.m41t81.reg0d",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0e,
      { "REG 0x0e", "r3.m41t81.reg0e",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0f,
      { "REG 0x0f", "r3.m41t81.reg0f",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg10,
      { "REG 0x10", "r3.m41t81.reg10",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg11,
      { "REG 0x11", "r3.m41t81.reg11",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg12,
      { "REG 0x12", "r3.m41t81.reg12",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg13,
      { "REG 0x13", "r3.m41t81.reg13",
	  FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_dumpm41t81_reg00_sec1,
      { ".1 Seconds", "r3.m41t81.reg00.sec1",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg00_sec01,
      { ".01 Seconds", "r3.m41t81.reg00.sec01",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg01_st,
      { "ST", "r3.m41t81.reg01.st",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg01_10sec,
      { "10 Seconds", "r3.m41t81.reg01.10sec",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg01_1sec,
      { "1 Seconds", "r3.m41t81.reg01.1sec",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg02_notused,
      { "(not used)", "r3.m41t81.reg02.notused",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg02_10min,
      { "10 Minutes", "r3.m41t81.reg02.10min",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg02_1min,
      { "1 Minutes", "r3.m41t81.reg02.1min",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg03_cbe,
      { "CBE", "r3.m41t81.reg03.cbe",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg03_cb,
      { "CB", "r3.m41t81.reg03.cb",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg03_10hour,
      { "10 Hours", "r3.m41t81.reg03.10hour",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg03_1hour,
      { "1 Hours", "r3.m41t81.reg03.1hour",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg04_notused,
      { "(not used)", "r3.m41t81.reg04.notused",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg04_dow,
      { "DOW", "r3.m41t81.reg04.dow",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg05_notused,
      { "(not used)", "r3.m41t81.reg05.notused",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg05_10day,
      { "10 Day", "r3.m41t81.reg05.10day",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg05_1day,
      { "1 Day", "r3.m41t81.reg05.1day",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg06_notused,
      { "(not used)", "r3.m41t81.reg06.notused",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg06_10month,
      { "10 Month", "r3.m41t81.reg06.10month",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg06_1month,
      { "1 Month", "r3.m41t81.reg06.1month",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg07_10year,
      { "10 Year", "r3.m41t81.reg07.10year",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg07_1year,
      { "1 Year", "r3.m41t81.reg07.1year",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg08_out,
      { "OUT", "r3.m41t81.reg08.out",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg08_ft,
      { "FT", "r3.m41t81.reg08.ft",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg08_s,
      { "S", "r3.m41t81.reg08.s",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg08_cal,
      { "CAL", "r3.m41t81.reg08.cal",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg09_notused,
      { "(not used)", "r3.m41t81.reg09.notused",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg09_bmb,
      { "BMB", "r3.m41t81.reg09.bmb",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg09_rb,
      { "RB", "r3.m41t81.reg09.rb",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0a_afe,
      { "AFE", "r3.m41t81.reg0a.afe",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0a_sqwe,
      { "SQWE", "r3.m41t81.reg0a.sqwe",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0a_abe,
      { "ABE", "r3.m41t81.reg0a.abe",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0a_10monthalm,
      { "10 Month Alarm", "r3.m41t81.reg0a.10monthalm",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0a_1monthalm,
      { "1 Month Alarm", "r3.m41t81.reg0a.1monthalm",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0b_rpt5,
      { "RPT5", "r3.m41t81.reg0b.rpt5",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0b_rpt4,
      { "RPT4", "r3.m41t81.reg0b.rpt4",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0b_10dayalm,
      { "10 Day Alarm", "r3.m41t81.reg0b.10dayalm",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0b_1dayalm,
      { "1 Day Alarm", "r3.m41t81.reg0b.1dayalm",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0c_rpt3,
      { "RPT3", "r3.m41t81.reg0c.rpt3",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0c_ht,
      { "HT", "r3.m41t81.reg0c.ht",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0c_10houralm,
      { "10 Hour Alarm", "r3.m41t81.reg0c.10houralm",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0c_1houralm,
      { "1 Hour Alarm", "r3.m41t81.reg0c.1houralm",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0d_rpt2,
      { "RPT2", "r3.m41t81.reg0d.rpt2",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0d_10minalm,
      { "10 Min Alarm", "r3.m41t81.reg0d.10minalm",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0d_1minalm,
      { "1 Min Alarm", "r3.m41t81.reg0d.1minalm",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0e_rpt1,
      { "RPT1", "r3.m41t81.reg0e.rpt1",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0e_10secalm,
      { "10 Sec Alarm", "r3.m41t81.reg0e.10secalm",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0e_1secalm,
      { "1 Sec Alarm", "r3.m41t81.reg0e.1secalm",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0f_wdf,
      { "WDF", "r3.m41t81.reg0f.wdf",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0f_af,
      { "AF", "r3.m41t81.reg0f.af",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg0f_notused,
      { "(not used)", "r3.m41t81.reg0f.notused",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg10_notused,
      { "(not used)", "r3.m41t81.reg10.notused",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg11_notused,
      { "(not used)", "r3.m41t81.reg11.notused",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg12_notused,
      { "(not used)", "r3.m41t81.reg12.notused",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg13_rs,
      { "RS", "r3.m41t81.reg13.rs",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_dumpm41t81_reg13_notused,
      { "(not used)", "r3.m41t81.reg13.notused",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_debuglog_recordnumber,
      { "Record Number", "r3.debuglog.recordnumber",
	  FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_debuglog_flags,
      { "Flags", "r3.debuglog.flags",
	  FT_UINT32, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_debuglog_tick,
      { "Tick", "r3.debuglog.tick",
	  FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
	  NULL, HFILL }
    },

    { &hf_r3_adduserparamtype,
      { "Upstream Field", "r3.manageuser",
	  FT_NONE, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adduserparamtypelength,
      { "Field Length", "r3.manageuser.length",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adduserparamtypetype,
      { "Field Type", "r3.manageuser.type",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_adduserparamtypenames_ext, 0x0,
	  NULL, HFILL }
    },
  #if 0
    { &hf_r3_adduserparamtypedatalen,
      { "Data Length", "r3.manageuser.datalen",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adduserparamtypeerror,
      { "Error", "r3.manageuser.error",
	  FT_STRING, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
  #endif
    { &hf_r3_adduserparamtypearray [ADDUSERPARAMTYPE_DISPOSITION],
      { "Disposition", "r3.manageuser.disposition",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_dispositionnames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adduserparamtypearray [ADDUSERPARAMTYPE_USERNO],
      { "User Number", "r3.manageuser.usernumber",
	  FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adduserparamtypearray [ADDUSERPARAMTYPE_ACCESSALWAYS],
      { "Access Always", "r3.manageuser.accessalways",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adduserparamtypearray [ADDUSERPARAMTYPE_ACCESSMODE],
      { "Access Mode", "r3.manageuser.accessmode",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_accessmodenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adduserparamtypearray [ADDUSERPARAMTYPE_CACHED],
      { "Cached", "r3.manageuser.cached",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adduserparamtypearray [ADDUSERPARAMTYPE_USERTYPE],
      { "User Type", "r3.manageuser.usertype",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_usertypenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adduserparamtypearray [ADDUSERPARAMTYPE_PRIMARYFIELD],
      { "Primary Field", "r3.manageuser.primaryfield",
	  FT_BYTES, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adduserparamtypearray [ADDUSERPARAMTYPE_PRIMARYFIELDTYPE],
      { "Primary Field Type", "r3.manageuser.primaryfieldtype",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_ppmisourcenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adduserparamtypearray [ADDUSERPARAMTYPE_AUXFIELD],
      { "Aux Field", "r3.manageuser.auxfield",
	  FT_BYTES, BASE_NONE, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adduserparamtypearray [ADDUSERPARAMTYPE_AUXFIELDTYPE],
      { "Aux Field Type", "r3.manageuser.auxfieldtype",
	  FT_UINT8, BASE_DEC_HEX|BASE_EXT_STRING, &r3_ppmisourcenames_ext, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adduserparamtypearray [ADDUSERPARAMTYPE_USECOUNT],
      { "Use Count", "r3.manageuser.usecount",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adduserparamtypearray [ADDUSERPARAMTYPE_EXCEPTIONGROUP],
      { "Exception Group", "r3.manageuser.exceptiongroup",
	  FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adduserparamtypearray [ADDUSERPARAMTYPE_EXPIREON],
      { "Expire On", "r3.manageuser.expireon",
	  FT_UINT24, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    },
    { &hf_r3_adduserparamtypearray [ADDUSERPARAMTYPE_TIMEZONE],
      { "Timezone", "r3.manageuser.timezone",
	  FT_UINT32, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett [] =
  {
    &ett_r3,
    &ett_r3header,
    &ett_r3tail,
    &ett_r3payload,
    &ett_r3cmd,
    &ett_r3configitem,
    &ett_r3upstreamcommand,
    &ett_r3upstreamfield,
    &ett_r3timezone,
    &ett_r3expireon,
    &ett_r3datetime,
    &ett_r3eventlogrecord,
    &ett_r3declinedlogrecord,
    &ett_r3alarmlogrecord,
    &ett_r3debugmsg,
    &ett_r3defineexceptionstartdate,
    &ett_r3defineexceptionenddate,
    &ett_r3defineexceptiongroupbits,
    &ett_r3definecalendarmonth [1],
    &ett_r3definecalendarmonth [2],
    &ett_r3definecalendarmonth [3],
    &ett_r3definecalendarmonth [4],
    &ett_r3definecalendarmonth [5],
    &ett_r3definecalendarmonth [6],
    &ett_r3definecalendarmonth [7],
    &ett_r3definecalendarmonth [8],
    &ett_r3definecalendarmonth [9],
    &ett_r3definecalendarmonth [10],
    &ett_r3definecalendarmonth [11],
    &ett_r3definecalendarmonth [12],
    &ett_r3definetimezonestarttime,
    &ett_r3definetimezoneendtime,
    &ett_r3definetimezonedaymap,
    &ett_r3eventlogdumpstarttime,
    &ett_r3eventlogdumpendtime,
    &ett_r3declinedlogdumpstarttime,
    &ett_r3declinedlogdumpendtime,
    &ett_r3alarmlogdumpstarttime,
    &ett_r3alarmlogdumpendtime,
    &ett_r3clearnvram,
    &ett_r3filters,
    &ett_r3alarmlist,
    &ett_r3alarmcfg,
    &ett_r3commandmfg,
    &ett_r3serialnumber,
    &ett_r3iopins,
    &ett_r3checksumresults,
    &ett_r3checksumresultsfield,
    &ett_r3forceoptions,
    &ett_r3peekpoke,
    &ett_r3downloadfirmware,
    &ett_r3capabilities,
    &ett_r3lockstate,
    &ett_r3mortisestatelog,
    &ett_r3timerchain,
    &ett_r3taskflags,
    &ett_r3taskflagsentry,
    &ett_r3checkpointlog,
    &ett_r3checkpointlogentry,
    &ett_r3cpuregisters,
    &ett_r3cpuregister,
    &ett_r3m41t81registers,
    &ett_r3m41t81register,
    &ett_r3debuglogrecord,
    &ett_r3setdatetime,
    &ett_r3manageuser
  };

  proto_r3 = proto_register_protocol ("Assa Abloy R3", "R3", "r3");
  register_dissector ("r3", dissect_r3, proto_r3);
  proto_register_field_array (proto_r3, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void proto_reg_handoff_r3 (void)
{
  dissector_handle_t r3_handle = find_dissector ("r3");
  dissector_add_uint ("tcp.port", 2571, r3_handle);
  dissector_add_uint ("tcp.port", 8023, r3_handle);
}


/*
 * Editor modelines
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vim: set tabstop=2 softtabstop=2 shiftwidth=2 expandtab:
 */
