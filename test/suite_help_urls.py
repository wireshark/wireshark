#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Help URL consistency tests.

The Wireshark Discord invitation is stored in three places because JSON
and AsciiDoc cannot include the C header: `WS_DISCORD_URL` in
`ui/urls.h` (Help menu), the "Discord" button in
`resources/json/learn_card.json` (Welcome page) and the
`:wireshark-discord-url:` attribute in `doc/attributes.adoc` (User's
Guide).  This test fails when the copies drift apart, so a stale invite
is fixed everywhere.
'''

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _normalize(url):
    return url.strip().rstrip('/')


def test_discord_url_consistent():
    urls_h = (REPO_ROOT / 'ui' / 'urls.h').read_text(encoding='utf-8')
    m = re.search(r'#define\s+WS_DISCORD_URL\s+"([^"]+)"', urls_h)
    assert m, 'WS_DISCORD_URL not found in ui/urls.h'
    header_url = _normalize(m.group(1))

    card_path = REPO_ROOT / 'resources' / 'json' / 'learn_card.json'
    card = json.loads(card_path.read_text(encoding='utf-8'))
    card_urls = [b['url'] for b in card.get('buttons', [])
                 if b.get('label') == 'Discord']
    assert card_urls, 'Discord button not found in resources/json/learn_card.json'
    card_url = _normalize(card_urls[0])

    attrs = (REPO_ROOT / 'doc' / 'attributes.adoc').read_text(encoding='utf-8')
    m = re.search(r'^:wireshark-discord-url:\s*(\S+)\s*$', attrs, re.MULTILINE)
    assert m, ':wireshark-discord-url: not found in doc/attributes.adoc'
    doc_url = _normalize(m.group(1))

    assert header_url == card_url == doc_url, (
        'Discord invite differs: ui/urls.h=%s, resources/json/learn_card.json=%s, '
        'doc/attributes.adoc=%s' % (header_url, card_url, doc_url))
