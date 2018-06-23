# SPDX-License-Identifier: MIT
require 'asciidoctor/extensions' unless RUBY_ENGINE == 'opal'

include ::Asciidoctor

# An inline macro that generates links to related man pages.
#
# Usage
#
#   cveidlink:<cve-number>[]
#
class CVEIdLinkInlineMacro < Extensions::InlineMacroProcessor
  include WsUtils
  use_dsl

  named :cveidlink

  def process(parent, cvenum, _attrs)
    cvename = "CVE-#{cvenum}"
    target = %(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-#{cvenum})
    create_doc_links(parent, target, cvename)
  end
end
