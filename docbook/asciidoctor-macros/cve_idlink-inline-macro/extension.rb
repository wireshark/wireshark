# SPDX-License-Identifier: MIT
require 'asciidoctor/extensions' unless RUBY_ENGINE == 'opal'

include ::Asciidoctor

# An inline macro that generates links to related man pages.
#
# Usage
#
#   cve_idlink:<cve-number>[]
#
class CVEIdLinkInlineMacro < Extensions::InlineMacroProcessor
  use_dsl

  named :cve_idlink

  def process parent, cvenum, attrs
    cvename = "CVE-#{cvenum}"
    suffix = ''
    target = %(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-#{cvenum})
    if parent.document.basebackend? 'html'
      parent.document.register :links, target
      %(#{(create_anchor parent, cvename, type: :link, target: target).render})
    elsif parent.document.backend == 'manpage'
      %(\\fB#{cvename})
    else
      %(#{cvename})
    end
  end
end
