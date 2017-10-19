# SPDX-License-Identifier: MIT
RUBY_ENGINE == 'opal' ? (require 'commaize-block/extension') : (require_relative 'commaize-block/extension')

Extensions.register do
  block CommaizeBlock
end
