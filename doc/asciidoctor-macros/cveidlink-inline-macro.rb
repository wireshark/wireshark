# SPDX-License-Identifier: MIT
# Copied from https://github.com/asciidoctor/asciidoctor-extensions-lab/blob/master/lib/man-inline-macro.rb

RUBY_ENGINE == 'opal' ? (require 'cveidlink-inline-macro/extension') : (require_relative 'cveidlink-inline-macro/extension')

Extensions.register do
  inline_macro CVEIdLinkInlineMacro
end
