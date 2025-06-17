# SPDX-License-Identifier: MIT
require 'asciidoctor/extensions' unless RUBY_ENGINE == 'opal'

include ::Asciidoctor

# An inline macro that generates a link to a Wireshark bug report.
#
# Usage
#
#   wsbuglink:<number>[<issue text>]
#   Default bug text is "Issue <number>".
#
class WSBugLinkInlineMacro < Extensions::InlineMacroProcessor
  include WsUtils
  use_dsl

  named :wsbuglink
  parse_content_as :text

  def process(parent, issueid, attrs)
    bugtext = !attrs['text'].nil_or_empty? ? attrs['text'] : %(Issue #{issueid})
    target = %(https://gitlab.com/wireshark/wireshark/-/issues/#{issueid})
    create_doc_links(parent, target, bugtext)
  end
end
