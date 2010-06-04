/* EPCglobal Low-Level Reader Protocol Packet Dissector
 *
 * Copyright 2008, Intermec Technologies Corp. <matt.poduska@intermec.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */   

#ifndef _LLRP_PARSER_H
#define _LLRP_PARSER_H

#include "llrpparsetypes.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* --------------------------------------------------------------------------------------- */
/* Parse error codes, passed as a parameter in t_llrp_HandleParseError                     */

#define LLRP_CONTEXT_ERROR                             0x00    

/* Message Errors */
#define LLRP_PARSE_ERROR_MESSAGE_DATA_UNDERFLOW        0x10
#define LLRP_PARSE_ERROR_MESSAGE_TYPE_UNKNOWN          0x11

/* Parameter Errors */
#define LLRP_PARSE_ERROR_PARAMETER_TYPE_UNKNOWN        0x50
#define LLRP_PARSE_ERROR_PARAMETER_TV_NOT_FOUND        0x51
#define LLRP_PARSE_ERROR_PARAMETER_DATA_UNDERFLOW      0x52
#define LLRP_PARSE_ERROR_PARAMETER_DATA_OVERFLOW       0x53

/* Field Errors */
#define LLRP_PARSE_ERROR_FIELD_TYPE_UNKNOWN            0x90
#define LLRP_PARSE_ERROR_FIELD_DATA_UNDERFLOW          0x91
#define LLRP_PARSE_ERROR_FIELD_DATA_OVERFLOW           0x92

/* --------------------------------------------------------------------------------------- */
/* Endian swappers                                                                         */
/*   For portability, these functions must be defined externally. Often, they will map     */
/*   directly to ntohs().                                                                  */

typedef unsigned short (*t_llrp_ntohs)(unsigned short value);
typedef unsigned long (*t_llrp_ntohl)(unsigned long value);

extern t_llrp_ntohs llrp_ntohs;
extern t_llrp_ntohl llrp_ntohl;

/* --------------------------------------------------------------------------------------- */
/* LLRP message parsing context                                                            */

/* Consume 'length' bytes from the stream, set 'consumed' to the number of bytes
    successfully consumed, return a pointer to the first consumed byte. */
typedef unsigned char *(*t_llrp_StreamRead)(void *context, const unsigned long length,
 const int wait_forever, unsigned long *consumed);

/* Return the number of bytes consumed from stream */
typedef unsigned long (*t_llrp_StreamGetOffset)(void *context);

/* Called upon successful parsing of an LLRP message header. If the parser should continue
 *  parsing this message, nonzero should be returned. If the parser should abort parsing this
 *  message, zero should be returned. */
typedef int (*t_llrp_HandleMessage)(void *context, const unsigned char version,
 const unsigned short type, const unsigned long length, const unsigned long id, const char *name);

/* Called upon successful parsing of an LLRP field. Note that data is in network byte order. */
typedef void (*t_llrp_HandleField)(void *context, const unsigned short field_index,
 const unsigned char type, const char *name, const unsigned long bitlength,
 const unsigned char *data, t_llrp_enumeration *enumeration);

/* Called upon completion of parsing all fields in a parameter/message */
typedef void (*t_llrp_HandleFieldComplete)(void *context, const unsigned short field_count);

/* Called upon successful parsing of an LLRP parameter */
typedef void (*t_llrp_HandleParameter)(void *context, const unsigned short type, const char *name,
 const unsigned short length);

/* Called upon successful parsing of an LLRP custom parameter */
typedef void (*t_llrp_HandleCustomParameter)(void *context, const unsigned short type,
 const unsigned long vendorID, const unsigned long subtype, const char *name,
 const unsigned short length);

/* Called upon completion of parsing all parameters */
typedef void (*t_llrp_HandleAllParametersComplete)(void *context);

/* Called upon detection of a parsing error */
typedef void (*t_llrp_HandleParseError)(void *context, const unsigned char code,
 const unsigned short item, const char *function_name, const char *format, ...);

/* Called by the parser to report an informational/debug message */
typedef void (*t_llrp_HandleDebugMessage)(void *context, const char *function_name,
 const char *format, ...);

typedef struct
{
    unsigned char depth; /* Parse tree depth (message header is always parsed at depth 0) */

    t_llrp_parse_validator **validator_list;
    unsigned char validator_count;

    /* Callback functions for stream management */
    t_llrp_StreamRead stream_read_handler;
    t_llrp_StreamGetOffset stream_get_offset_handler;

    /* Callback functions for handling parsing events */
    t_llrp_HandleMessage message_start_handler;
    t_llrp_HandleMessage message_finished_handler;
    t_llrp_HandleField field_handler;
    t_llrp_HandleFieldComplete field_complete_handler;
    t_llrp_HandleParameter parameter_start_handler;
    t_llrp_HandleParameter parameter_finished_handler;
    t_llrp_HandleCustomParameter custom_parameter_start_handler;
    t_llrp_HandleCustomParameter custom_parameter_finished_handler;
    t_llrp_HandleAllParametersComplete all_parameters_complete_handler;
    t_llrp_HandleParseError parse_error_handler;
    t_llrp_HandleDebugMessage debug_message_handler;

    void *data; /* user-defined data */
} t_llrp_parse_context;

/* --------------------------------------------------------------------------------------- */
/* Exported Functions                                                                      */

#define LLRP_PARSE_RESULT_SUCCESS      0  /* parse successful */
#define LLRP_PARSE_RESULT_PARSE_FAILED 1  /* received message, parse failed */
#define LLRP_PARSE_RESULT_NO_PARSE     2  /* no message received */
#define LLRP_PARSE_RESULT_FAILURE      3  /* unspecified failure */
int llrp_ParseMessage(t_llrp_parse_context *context);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _LLRP_PARSER_H */
