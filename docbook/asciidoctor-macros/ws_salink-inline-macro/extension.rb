# SPDX-License-Identifier: MIT
require 'asciidoctor/extensions' unless RUBY_ENGINE == 'opal'

include ::Asciidoctor

# An inline macro that generates links to related man pages.
#
# Usage
#
#   ws_salink:<dddd>[]
#
class WSSALinkInlineMacro < Extensions::InlineMacroProcessor
  use_dsl

  named :'ws_salink'

  def process parent, sanum, attrs
    satext = "wnpa-sec-#{sanum}"
    target = %(https://www.wireshark.org/security/wnpa-sec-#{sanum})
    if parent.document.basebackend? 'html'
      parent.document.register :links, target
      %(#{(create_anchor parent, satext, type: :link, target: target).render})
    elsif parent.document.backend == 'manpage'
      %(\\fB#{satext})
    else
      %(#{satext})
    end
  end
end
