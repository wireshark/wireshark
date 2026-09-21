# SPDX-License-Identifier: MIT
module WsUtils
  def create_doc_links(parent, target, text)
    if (parent.document.basebackend? 'docbook') || (parent.document.basebackend? 'html')
      parent.document.register :links, target
      create_anchor parent, text, type: :link, target: target
    elsif parent.document.backend == 'manpage'
      create_inline parent, :quoted, text, type: :strong
    else
      create_inline parent, :quoted, text
    end
  end
end
