# SPDX-License-Identifier: MIT
module WsUtils
  def create_doc_links(parent, target, text)
    if parent.document.basebackend? 'html'
      parent.document.register :links, target
      create_anchor(parent, text, type: :link, target: target).render.to_s
    elsif parent.document.backend == 'manpage'
      "\\fB#{text}"
    else
      bugtext
    end
  end
end
