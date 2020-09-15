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
  use_dsl

  named :wsbuglink
  parse_content_as :text
  name_positional_attributes 'bugtext'

  def process parent, issueid, attrs
    bugtext = if (attrs['bugtext'])
      attrs['bugtext']
    else
      %(Bug #{issueid})
    end
    target = %(https://gitlab.com/wireshark/wireshark/-/issues/#{issueid})
    if parent.document.basebackend? 'html'
      parent.document.register :links, target
      %(#{(create_anchor parent, bugtext, type: :link, target: target).render})
    elsif parent.document.backend == 'manpage'
      %(\\fB#{bugtext})
    else
      %(#{bugtext})
    end
  end
end
