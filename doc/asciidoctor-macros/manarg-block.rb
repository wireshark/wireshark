# SPDX-License-Identifier: MIT
# Adapted from https://github.com/asciidoctor/asciidoctor-extensions-lab/blob/master/lib/man-inline-macro.rb

RUBY_ENGINE == 'opal' ? (require 'manarg-block/extension') : (require_relative 'manarg-block/extension')

Extensions.register do
  block ManArgBlock
end
