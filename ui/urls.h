/** @file
 *
 * Define URLs for various Wireshark sites, so that if they move, we only
 * have to change the URLs here.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define WS_HOME_PAGE_URL "https://www.wireshark.org"
#define WS_DOWNLOAD_URL  "https://www.wireshark.org/download.html"
#define WS_DOCS_URL      "https://www.wireshark.org/docs/"
#define WS_FAQ_URL       "https://www.wireshark.org/faq.html"
#define WS_Q_AND_A_URL   "https://ask.wireshark.org"
#define WS_WIKI_HOME_URL "https://wiki.wireshark.org"

/*
 * Construct a wiki URL given the path to the wiki page.
 */
#define WS_WIKI_URL(path)	WS_WIKI_HOME_URL "/" path
