#
# Make the "Wireshark User Guide" and "Wireshark Developer Guide"
# in several formats.
# See the Readme.txt file for instructions.
#
# $Id$
#

# formatting objects processor
# Additional options to fop.
# This needs to contain at least the argument '-Xmx256m'
FOP_OPTS?=-Xmx256m

# fop executable
# Leave these commented out if you don't have fop installed or you
# don't want PDF documentation.
# (if you have problems with fop, try to use an absolute path here)
FOP=fop-0.20.5/fop.sh
#
# One SUSE 9.1 and newer uncomment the following line (make sure you have
# at least fop-0.20.5-71.2)
FOP=fop

# html to text converter for text version of release notes, e.g. elinks.
# This could also be "lynx", or "true" if neither elinks nor lynx is installed
#HTML2TXT=elinks -dump -dump-width 72
#HTML2TXT=links -dump -width 72
# (See Bug # 1446 for note re 'force-html' below)
HTML2TXT?=lynx -dump -width=72 -nolist -stdin -force-html
#HTML2TXT="true"


PERL = perl

############### YOU SHOULDN'T HAVE TO EDIT ANYTHING BELOW THIS LINE! ################

include Makefile.common

# the XSL processor
XSLTPROC?="xsltproc"

# the XML validator (from the xsltproc package)
XMLLINT?="xmllint"

# Automatically generate .pdf files from .fo files
# Suse needs FOP_OPTS, Debian needs JAVA_OPTS
.fo.pdf:
	FOP_OPTS=$(FOP_OPTS) JAVA_OPTS=$(FOP_OPTS) $(FOP) $< $@


all: svn_version_check wsug.validated wsdg.validated release_notes.validated wsug wsdg release_notes 

clean:
	rm -rf $(CLEANFILES)

.SUFFIXES: .fo .pdf

#
# on every build, record the working copy revision string
#
# FORCE is the portable version of .PHONY
FORCE:

svn_version_check: FORCE
	cat check_svn_version.sh | tr -d '\015' | /bin/bash

svn_version.xml: svn_version_check


wsug: wsug_html_chunked user-guide.html user-guide-a4.pdf user-guide-us.pdf 

# validate the content
wsug.validated: $(WSUG_SOURCE)
	@ echo --- WSUG - VALIDATING XML ---
	$(XMLLINT) --valid --noout $<
	touch $@

# create html single page file
user-guide.html: wsug_html/user-guide.html

wsug_html/user-guide.html: $(WSUG_SOURCE)
	@ echo --- WSUG - HTML SINGLE PAGE ---
	mkdir -p wsug_html/wsug_graphics/toolbar
	cp wsug_graphics/*.* wsug_html/wsug_graphics
	cp wsug_graphics/toolbar/* wsug_html/wsug_graphics/toolbar
	cp ws.css wsug_html
	$(XSLTPROC) --stringparam base.dir wsug_html/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path wsug_graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --stringparam html.stylesheet ws.css --nonet http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $< > $@
	-chmod -R og+rX wsug_html

# create html chunked page files
wsug_html_chunked: wsug_html_chunked/index.html

wsug_html_chunked/index.html: $(WSUG_SOURCE)
	@ echo --- WSUG - HTML CHUNKED ---
	mkdir -p wsug_html_chunked/wsug_graphics/toolbar
	cp wsug_graphics/*.* wsug_html_chunked/wsug_graphics
	cp wsug_graphics/toolbar/* wsug_html_chunked/wsug_graphics/toolbar
	cp ws.css wsug_html_chunked
	$(XSLTPROC) --stringparam base.dir wsug_html_chunked/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path wsug_graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --stringparam html.stylesheet ws.css --nonet http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl $<
	-chmod -R og+rX wsug_html_chunked

# create pdf file (through XSL-FO), portrait pages on US letter paper (the default)
# you will get lot's of errors, but that's ok
user-guide-us.fo: $(WSUG_SOURCE) custom_layer_pdf.xsl
ifdef FOP
	@ echo --- WSUG - PDF US PAPER ---
	$(XSLTPROC) --stringparam paper.type letter --nonet custom_layer_pdf.xsl $< > $@
endif

# create pdf file (through XSL-FO), portrait pages on A4 paper
# you will get lot's of errors, but that's ok
user-guide-a4.fo: $(WSUG_SOURCE) custom_layer_pdf.xsl
ifdef FOP
	@ echo --- WSUG - PDF A4 PAPER ---
	$(XSLTPROC) --stringparam paper.type A4 --nonet custom_layer_pdf.xsl $< > $@
endif


wsdg: wsdg_html_chunked developer-guide.html developer-guide-a4.pdf developer-guide-us.pdf

# validate the content
wsdg.validated: $(WSDG_SOURCE)
	@ echo --- WSDG - VALIDATING XML ---
	$(XMLLINT) --valid --noout $<
	touch $@

# create html single page file
developer-guide.html: wsdg_html/developer-guide.html

wsdg_html/developer-guide.html: $(WSDG_SOURCE)
	@ echo --- WSDG - HTML SINGLE PAGE ---
	mkdir -p wsdg_html/wsdg_graphics
	cp wsdg_graphics/* wsdg_html/wsdg_graphics
	cp ws.css wsdg_html
	$(XSLTPROC) --stringparam base.dir wsdg_html/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path wsdg_graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --stringparam html.stylesheet ws.css --nonet http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $< > $@
	-chmod -R og+rX wsdg_html

# create html chunked page files
wsdg_html_chunked: wsdg_html_chunked/index.html

wsdg_html_chunked/index.html: $(WSDG_SOURCE)
	@ echo --- WSDG - HTML CHUNKED ---
	mkdir -p wsdg_html_chunked
	mkdir -p wsdg_html_chunked/wsdg_graphics
	cp wsdg_graphics/* wsdg_html_chunked/wsdg_graphics
	cp ws.css wsdg_html_chunked
	$(XSLTPROC) --stringparam base.dir wsdg_html_chunked/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path wsdg_graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --stringparam html.stylesheet ws.css --nonet http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl $<
	-chmod -R og+rX wsdg_html_chunked

# create pdf file (through XSL-FO), portrait pages on US letter paper (the default)
# you will get lot's of errors, but that's ok
developer-guide-us.fo: $(WSDG_SOURCE) custom_layer_pdf.xsl
ifdef FOP
	@ echo --- WSDG - PDF US PAPER ---
	$(XSLTPROC) --stringparam paper.type letter --nonet custom_layer_pdf.xsl $< > $@
endif

# create pdf file (through XSL-FO), portrait pages on A4 paper
# you will get lot's of errors, but that's ok
developer-guide-a4.fo: $(WSDG_SOURCE) custom_layer_pdf.xsl
ifdef FOP
	@ echo --- WSDG - PDF A4 PAPER ---
	$(XSLTPROC) --stringparam paper.type A4 --nonet custom_layer_pdf.xsl $< > $@
endif


release_notes: release-notes.html release-notes.txt release-notes-a4.pdf release-notes-us.pdf

# validate the content
release_notes.validated: $(RELEASE_NOTES_SOURCE)
	@ echo --- RELEASE NOTES - VALIDATING XML ---
	$(XMLLINT) --valid --noout $<
	touch $@

# create html single page file
release-notes.html: $(RELEASE_NOTES_SOURCE)
	@ echo --- RELEASE NOTES - HTML ---
	$(XSLTPROC) --nonet http://docbook.sourceforge.net/release/xsl/current/xhtml/docbook.xsl $< > $@

# create txt single page file (through HTML)
release-notes.txt: $(RELEASE_NOTES_SOURCE)
	@ echo --- RELEASE NOTES - TXT ---
	$(XSLTPROC) --stringparam generate.toc "article nop" --nonet http://docbook.sourceforge.net/release/xsl/current/xhtml/docbook.xsl $< | $(HTML2TXT) > $@

news: release-notes.txt
	cp release-notes.txt ../NEWS 

# create pdf file (through XSL-FO), portrait pages on US letter paper (the default)
# you will get lot's of errors, but that's ok
release-notes-us.fo: $(RELEASE_NOTES_SOURCE) custom_layer_pdf.xsl
ifdef FOP
	@ echo --- RELEASE NOTES - PDF US PAPER ---
	$(XSLTPROC) --stringparam paper.type letter --nonet custom_layer_pdf.xsl $< > $@
endif

# create pdf file (through XSL-FO), portrait pages on A4 paper
# you will get lot's of errors, but that's ok
release-notes-a4.fo: $(RELEASE_NOTES_SOURCE) custom_layer_pdf.xsl
ifdef FOP
	@ echo --- RELEASE NOTES - PDF A4 PAPER ---
	$(XSLTPROC) --stringparam paper.type A4 --nonet custom_layer_pdf.xsl $< > $@
endif

wsluarm: make-wsluarm.pl $(WSLUA_MODULES)
	$(PERL) make-wsluarm.pl $(WSLUA_MODULES)
	touch wsluarm


