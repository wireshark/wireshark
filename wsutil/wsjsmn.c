/* wsjsmn.c
 * Utility to check if a payload is json using libjsmn
 *
 * Copyright 2016, Dario Lombardo
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

#include "wsjsmn.h"

#include <string.h>
#include <wsutil/jsmn.h>
#include "log.h"

gboolean jsmn_is_json(const guint8* buf, const size_t len)
{
        /* We expect no more than 1024 tokens */
        guint max_tokens = 1024;
        jsmntok_t* t;
        jsmn_parser p;
        gboolean ret = TRUE;
        int rcode;

        t = g_new0(jsmntok_t, max_tokens);

        if (!t)
                return FALSE;

        jsmn_init(&p);
        rcode = jsmn_parse(&p, buf, len, t, max_tokens);
        if (rcode < 0) {
                switch (rcode) {
                        case JSMN_ERROR_NOMEM:
                                g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "jsmn: not enough tokens were provided");
                                break;
                        case JSMN_ERROR_INVAL:
                                g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "jsmn: invalid character inside JSON string");
                                break;
                        case JSMN_ERROR_PART:
                                g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "jsmn: the string is not a full JSON packet, "
                                        "more bytes expected");
                                break;
                        default:
                                g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "jsmn: unexpected error");
                                break;
                }
                ret = FALSE;
        }

        g_free(t);

        return ret;
}

int wsjsmn_parse(const char *buf, jsmntok_t *tokens, unsigned int max_tokens)
{
        jsmn_parser p;

        jsmn_init(&p);
        return jsmn_parse(&p, buf, strlen(buf), tokens, max_tokens);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 noexpandtab:
 * :indentSize=4:tabSize=8:noTabs=false:
 */
