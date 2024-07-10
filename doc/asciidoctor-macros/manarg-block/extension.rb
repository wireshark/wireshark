# SPDX-License-Identifier: MIT
require 'asciidoctor/extensions' unless RUBY_ENGINE == 'opal'

include Asciidoctor

# An inline macro that generates markup for man page arguments.
# Adapted from https://github.com/asciidoctor/asciidoctor-extensions-lab/blob/master/lib/man-inline-macro.rb
#
# Usage:
#
#   [manarg]
#   *command*
#   [ *--help* ]
#   [ *--flash-lights* ]
#
class ManArgBlock < Extensions::BlockProcessor
  use_dsl

  named :manarg
  parse_content_as :simple

  def process parent, reader, attrs
    nowrap_lines = reader.readlines.map {|line|
      if parent.document.basebackend? 'html'
        # Apply the custom style "[.nowrap]## ... ##" to each line.
        # This generates "<span content="nowrap"> ... </span>". Pass
        # each '#' through for extra paranoia.
        %([.nowrap]###{line.gsub('#', '+++#+++')}##)
      elsif parent.document.backend == 'manpage'
        # Replace spaces with non-breaking spaces ('&#160;'), then make
        # bold markup unconstrained ('*' -> '**'). For now we naively
        # assume that bolds are always constrained (that is, we only
        # have single '*'s). We *should* be able to do this properly
        # with a regex, but for some reason
        #   gsub(/([^*])\*([^*])/, '\1**\2')
        # doesn't match the first asterisk in "*--extcap-interface*=<interface>"
        %(#{line.gsub(' ', '&#160;').gsub('*', '**')})
      else
        line
      end
    }
    # STDERR.puts(nowrap_lines)
    create_paragraph parent, nowrap_lines, attrs
  end
end
