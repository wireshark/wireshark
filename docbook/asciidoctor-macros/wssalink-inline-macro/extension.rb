# SPDX-License-Identifier: MIT
require 'asciidoctor/extensions' unless RUBY_ENGINE == 'opal'

include ::Asciidoctor

# An inline macro that generates links to related man pages.
#
# Usage
#
#   wssalink:<dddd>[]
#
class WSSALinkInlineMacro < Extensions::InlineMacroProcessor
  include WsUtils
  use_dsl

  named :'wssalink'

  def process(parent, sanum, attrs)
    satext = "wnpa-sec-#{sanum}"
    target = %(https://www.wireshark.org/security/wnpa-sec-#{sanum})
    create_doc_links(parent, target, satext)
  end
end
