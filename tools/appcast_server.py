#!/usr/bin/env python3
"""
Minimal test server for Sparkle / WinSparkle appcast feeds.

Serves a dynamically generated appcast.xml so you can point your app's
feed URL at http://localhost:<port>/appcast.xml and test the update
check flow end-to-end.

Usage:
    python3 appcast_server.py --title "My App" --version 2.0.0 \
        --release-notes "https://example.com/release_notes.html"

    python3 appcast_server.py --title "Wireshark" --version 4.6.0 \
        --release-notes "https://www.wireshark.org/docs/relnotes/wireshark-4.6.0.html" \
        --port 8888

Then configure your app's feed URL to:
    http://localhost:8080/appcast.xml   (default port)
"""

import argparse
import html
import textwrap
from datetime import datetime, timezone
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, HTTPServer


def build_appcast(
    title: str, version: str, release_notes_url: str, download_url: str, os_tag: str
) -> str:
    pub_date = format_datetime(datetime.now(timezone.utc))
    title_escaped = html.escape(title)
    version_escaped = html.escape(version)
    rn_escaped = html.escape(release_notes_url)
    dl_escaped = html.escape(download_url)

    os_attr = ""
    if os_tag:
        os_attr = f' sparkle:os="{html.escape(os_tag)}"'

    return textwrap.dedent(f"""\
        <?xml version="1.0" encoding="utf-8"?>
        <rss version="2.0"
             xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"
             xmlns:dc="http://purl.org/dc/elements/1.1/">
          <channel>
            <title>{title_escaped}</title>
            <description>Appcast test feed for {title_escaped}</description>
            <language>en</language>
            <item>
              <title>Version {version_escaped}</title>
              <sparkle:version>{version_escaped}</sparkle:version>
              <sparkle:shortVersionString>{version_escaped}</sparkle:shortVersionString>
              <sparkle:releaseNotesLink>{rn_escaped}</sparkle:releaseNotesLink>
              <pubDate>{pub_date}</pubDate>
              <enclosure
                url="{dl_escaped}"
                length="0"
                type="application/octet-stream"{os_attr} />
            </item>
          </channel>
        </rss>
    """)


class AppcastHandler(BaseHTTPRequestHandler):
    """Serves the appcast XML and a simple index page."""

    appcast_xml: str = ""

    def do_GET(self):
        if self.path == "/appcast.xml":
            self._serve_xml()
        elif self.path == "/":
            self._serve_index()
        else:
            self.send_error(404)

    def _serve_xml(self):
        body = self.appcast_xml.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _serve_index(self):
        body = textwrap.dedent("""\
            <!doctype html>
            <html><body>
            <h2>Appcast Test Server</h2>
            <p>Feed URL: <a href="/appcast.xml">/appcast.xml</a></p>
            </body></html>
        """).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")


def main():
    parser = argparse.ArgumentParser(
        description="Serve a Sparkle/WinSparkle appcast.xml for testing."
    )

    parser.add_argument(
        "--title",
        default="Wireshark",
        help="Application title shown in the appcast (default: %(default)s)"
    )
    parser.add_argument(
        "--version",
        default="999.9.9",
        help="Version string advertised as available (default: %(default)s)",
    )
    parser.add_argument(
        "--release-notes",
        default="https://www.wireshark.org/update/relnotes/wireshark-4.4.4.html",
        help="URL to the release notes page (default: %(default)s)"
    )
    parser.add_argument(
        "--download-url",
        default="https://example.com/download/update.zip",
        help="Download URL in the enclosure (default: placeholder)",
    )
    parser.add_argument(
        "--os",
        default="",
        choices=["", "windows", "macos"],
        help="Set sparkle:os attribute on the enclosure "
        "(default: omit = all platforms)",
    )
    parser.add_argument(
        "--port", type=int, default=9999, help="Port to listen on (default: %(default)s)"
    )
    parser.add_argument(
        "--bind", default="0.0.0.0", help="Address to bind to (default: %(default)s)"
    )

    args = parser.parse_args()

    appcast = build_appcast(
        title=args.title,
        version=args.version,
        release_notes_url=args.release_notes,
        download_url=args.download_url,
        os_tag=args.os,
    )

    AppcastHandler.appcast_xml = appcast

    print(f'Serving appcast for "{args.title}" version {args.version}')
    print(f"Feed URL: http://{args.bind}:{args.port}/appcast.xml")
    print()
    print("--- Generated appcast.xml ---")
    print(appcast)
    print("-----------------------------")
    print()

    server = HTTPServer((args.bind, args.port), AppcastHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
