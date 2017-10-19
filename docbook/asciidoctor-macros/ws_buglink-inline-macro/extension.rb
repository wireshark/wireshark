# SPDX-License-Identifier: MIT
require 'asciidoctor/extensions' unless RUBY_ENGINE == 'opal'

include ::Asciidoctor

# An inline macro that generates links to related man pages.
#
# Usage
#
#   ws_buglink:<number>[<bug text>]
#   Default bug text is "Bug".
#
class WSBugLinkInlineMacro < Extensions::InlineMacroProcessor
  use_dsl

  named :'ws_buglink'
  name_positional_attributes 'bugtext'

  def process parent, target, attrs
    bugnum = target
    bugtext = if (attrs['bugtext'])
      attrs['bugtext']
    else
      'Bug'
    end
    target = %(https://bugs.wireshark.org/bugzilla/show_bug.cgi?id={bugnum})
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
