# SPDX-License-Identifier: MIT
require 'asciidoctor/extensions' unless RUBY_ENGINE == 'opal'

include Asciidoctor

# An extension that converts a list of lines to an inline Oxford comma-separated list.
#
# Usage
#
#   [commaize]
#   --
#   item1
#   item2
#   item3
#   --
#
class CommaizeBlock < Extensions::BlockProcessor
  include WsUtils
  use_dsl

  named :commaize
  on_contexts :paragraph, :open
  # XXX What's the difference between text, raw, simple, verbatim, etc?
  parse_content_as :simple

  def process(parent, reader, attrs)
    lines = reader.lines
    sort = attrs.fetch('sort', 'true') == 'true'

    lines = lines.reject(&:empty?)
    lines = lines.map(&:strip)
    lines = lines.sort_by(&:downcase) if sort

    if lines.length < 2
      create_paragraph parent, lines, attrs
    elsif lines.length == 2
      create_paragraph parent, lines.join(" and "), attrs
    else
      commaized = lines[0..-2].join(", ")
      commaized << ", and " + lines[-1]
      create_paragraph parent, commaized, attrs
    end
  end
end
