/* packet-r3_public.h
 * Routines for R3 packet dissection
 * Copyright (c) 2009 Assa Abloy USA <jcwren@assaabloyusa.com>
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

#ifndef __PACKET_ASSA_R3_PUBLIC_H__
#define __PACKET_ASSA_R3_PUBLIC_H__

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

  CONFIGITEM_LAST,                        /*  Must be last item defined (All non-virtual items added above) */

  CONFIGITEM_MAGIC_FIRST = 239,           /*  Next item is first magic command */
  CONFIGITEM_MAGIC_USERFIELD,             /*  240 - Virtual command to delete PIN '8989', add user '8989' */
  CONFIGITEM_MAGIC_USERADD,               /*  241 - Virtual command to add a user (PIN only) */
  CONFIGITEM_MAGIC_USERDELETE,            /*  242 - Virtual command to delete a user */
  CONFIGITEM_MAGIC_NVRAMBACKUP,           /*  243 - Virtual command to backup NVRAM to FLASH */
  CONFIGITEM_MAGIC_NVRAMRESTORE,          /*  244 - Virtual command to restore NVRAM from FLASH */
  CONFIGITEM_MAGIC_NVRAMERASE,            /*  245 - Virtual command to erase backed-up NVRAM */
  CONFIGITEM_MAGIC_LAST                   /*  *Really* the last item */
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

typedef enum
{
  FILTERMODE_NORMAL = 0,  /* 0 - Filters events specified */
  FILTERMODE_INVERT,      /* 1 - Filters events not specified */
  FILTERMODE_LAST
}
filterMode_e;

typedef enum
{
  FILTERSELECT_RECORDING = 0,   /* 0 - Recording filters */
  FILTERSELECT_REPORTING,       /* 1 - Reporting filters */
  FILTERSELECT_LAST
}
filterSelect_e;

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

typedef enum
{
  LOCKPRIORITY_NONE = 0,      /* 0 - Radio is not shut down for motor run, access not denied if radio is on */
  LOCKPRIORITY_DPAC,          /* 1 - Radio is not shut down for motor run, access denied if radio is on */
  LOCKPRIORITY_LOCK,          /* 2 - Radio is shut down for motor run, access not denied if radio is on */
  LOCKPRIORITY_LAST
}
lockPriority_e;

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

typedef enum
{
  NVRAMCOMMAND_BACKUP = 0,  /* 0 - Backup NVRAM to backup region */
  NVRAMCOMMAND_ERASE,       /* 1 - Erase backup region */
  NVRAMCOMMAND_RESTORE,     /* 2 - Restore NVRAM from backup region */
  NVRAMCOMMAND_LAST
}
nvramCommand_e;

typedef enum
{
  NVRAMDUMPSELECT_ALL = 0,  /* 0 - Dump all */
  NVRAMDUMPSELECT_PIC,      /* 1 - Dump NVRAM on PIC */
  NVRAMDUMPSELECT_USER,     /* 2 - Dump I2C NVRAM containing user data, exceptions, exception groups, calendars, timezones */
  NVRAMDUMPSELECT_EVENT,    /* 3 - Dump I2C NVRAM containing event log, declined log, alarm log, LRU cache */
  NVRAMDUMPSELECT_LAST
}
nvramDumpSelect_e;

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

typedef enum
{
  RADIOMODE_HOSTINITIATED = 0,  /* 0 - DPAC in listen mode (default) */
  RADIOMODE_LOCKINITIATED,      /* 1 - DPAC in pass-through mode */
  RADIOMODE_LAST
}
radioMode_e;

typedef enum
{
  RADIOTYPE_NONE = 0,     /* 0 - No radio present */
  RADIOTYPE_WIPORTNR,     /* 1 - WiPortNR */
  RADIOTYPE_DPAC80211B,   /* 2 - DPAC 802.11b */
  RADIOTYPE_DPAC80211BG,  /* 3 - DPAC 802.11bg */
  RADIOTYPE_LAST
}
radioType_e;

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
  RESPONSETYPE_LAST,
  /*
   *  These should not be exposed to the user
   */
  RESPONSETYPE_NOREPLY,               /* 51 - Do not send a reply, subroutine is posting it's own */
  RESPONSETYPE_TAKEABREAK,            /* 52 - Intermediate return result, when log searches taking too long */
  RESPONSETYPE_DPACBLOCKS,            /* 53 - PWM lock, battery powered, DPAC takes priority */
  RESPONSETYPE_ACKNAKTIMEOUT,         /* 54 - Added for console.c, not used in lock firmware */
  RESPONSETYPE_UNKNOWNCPUSPEED        /* 55 - Unknown CPU speed (utils.c, utilCalculateClockRate()) */
}
responseType_e;

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

typedef enum
{
  UNLOCKMODE_NORMAL = 0,  /* 0 - Normal unlock (CONFIGITEM_UNLOCK_TIME duration) */
  UNLOCKMODE_UNLOCK,      /* 1 - Unlock, switching to passage mode */
  UNLOCKMODE_LOCK,        /* 2 - Lock, regardless of mode */
  UNLOCKMODE_LAST
}
unlockMode_e;

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

#endif

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
