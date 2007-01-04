all:
	(cd .. && touch dummy && make doc)
	env XML_CATALOG_FILES=../../../docbook/catalog.xml "xsltproc" --stringparam base.dir wsluarm_html/ --stringparam use.id.as.filename 1 --stringparam section.autolabel 1 --stringparam section.label.includes.component.label 1 --stringparam html.stylesheet ws.css --nonet http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl wsluarm.xml > wsluarm.html

clean:
	rm -f *.xml
	rm -rf wsluarm.html
