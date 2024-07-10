# SPDX-License-Identifier: MIT
# Copied from https://github.com/asciidoctor/asciidoctor-extensions-lab/blob/master/lib/man-inline-macro.rb

RUBY_ENGINE == 'opal' ? (require 'wssalink-inline-macro/extension') : (require_relative 'wssalink-inline-macro/extension')

Extensions.register do
  inline_macro WSSALinkInlineMacro
end
