# SPDX-License-Identifier: MIT
require 'asciidoctor/extensions' unless RUBY_ENGINE == 'opal'

include ::Asciidoctor

# An inline macro that generates links to related man pages.
#
# Usage
#
#   wsbuglink:<number>[<bug text>]
#   Default bug text is "Bug".
#
class WSBugLinkInlineMacro < Extensions::InlineMacroProcessor
  include WsUtils
  use_dsl

  named :wsbuglink
  parse_content_as :text
  name_positional_attributes 'bugtext'

  def process(parent, issueid, attrs)
    bugtext = attrs['bugtext'] || %(Bug #{issueid})
    target = %(https://gitlab.com/wireshark/wireshark/-/issues/#{issueid})
    create_doc_links(parent, target, bugtext)
  end
end
