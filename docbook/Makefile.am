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
FOP_OPTS=-Xmx256m

# fop executable is found in configure.in .
# XXX - have it check for the right version (0.20.5 or newer)?

# html to text converter for text version of release notes, e.g. elinks.
# This could also be "lynx", or "true" if neither elinks nor lynx is installed
# (See Bug # 1446 for note re 'force-html' below)
# Sorry about the indenting, but that's what automake requires...
if HAVE_ELINKS
HTML2TXT=$(ELINKS) -dump -dump-width 72
## links: -dump requires 'url' argument (as opposed to elinks & lynx)
## (Rather than fixing things we'll just disable the use of links).
##else
##if HAVE_LINKS
##HTML2TXT=$(LINKS) -dump -width 72
else
if HAVE_LYNX
HTML2TXT=$(LYNX) -dump -width=72 -nolist -stdin -force-html
else
HTML2TXT="true"
endif
##endif
endif

############### YOU SHOULDN'T HAVE TO EDIT ANYTHING BELOW THIS LINE! ################

include Makefile.common

# Automatically generate .pdf files from .fo files
# Suse needs FOP_OPTS, Debian needs JAVA_OPTS
.fo.pdf:
if HAVE_FOP
	FOP_OPTS=$(FOP_OPTS) JAVA_OPTS=$(FOP_OPTS) $(FOP) $< $@
else
	false
endif


if HAVE_XSLTPROC
ALL_TARGETS=svn_version_check wsug wsdg release_notes
else
# if we don't have XSLTPROC, there's nothing to do...
ALL_TARGETS=svn_version_check
endif

all: $(ALL_TARGETS)

#
# on every build, record the working copy revision string
#
# FORCE is the portable version of .PHONY
FORCE:

svn_version_check: FORCE
	cat $(srcdir)/check_svn_version.sh | tr -d '\015' | /bin/bash

svn_version.xml: svn_version_check

# Wireshark User Guide
if HAVE_FOP
WSUG_TARGETS=wsug.validated wsug_html_chunked user-guide.html user-guide-a4.pdf user-guide-us.pdf 
else
WSUG_TARGETS=wsug.validated wsug_html_chunked user-guide.html
endif

wsug: $(WSUG_TARGETS)

# validate the content
wsug.validated: $(WSUG_SOURCE) wsluarm
if HAVE_XMLLINT
	@ echo --- WSUG - VALIDATING XML ---
	$(XMLLINT) --valid --noout $<
	touch $@
else
	@ echo --- WSUG - SKIP VALIDATION ---
endif

# create html single page file
user-guide.html: wsug_html/user-guide.html

wsug_html/user-guide.html: $(WSUG_SOURCE) wsluarm
	@ echo --- WSUG - HTML SINGLE PAGE ---
	mkdir -p wsug_html/wsug_graphics/toolbar
	cp $(srcdir)/wsug_graphics/*.* wsug_html/wsug_graphics
	cp $(srcdir)/wsug_graphics/toolbar/* wsug_html/wsug_graphics/toolbar
	cp $(srcdir)/ws.css wsug_html
	$(XSLTPROC) --stringparam base.dir wsug_html/ --stringparam  use.id.as.filename 1 \
		    --stringparam admon.graphics 1 --stringparam admon.graphics.path wsug_graphics/ \
		    --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 \
		    --stringparam html.stylesheet ws.css \
		    --nonet http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $< > $@
	-chmod -R og+rX wsug_html

# create html chunked page files
wsug_html_chunked: wsug_html_chunked/index.html

wsug_html_chunked/index.html: $(WSUG_SOURCE) wsluarm
	@ echo --- WSUG - HTML CHUNKED ---
	mkdir -p wsug_html_chunked/wsug_graphics/toolbar
	cp $(srcdir)/wsug_graphics/*.* wsug_html_chunked/wsug_graphics
	cp $(srcdir)/wsug_graphics/toolbar/* wsug_html_chunked/wsug_graphics/toolbar
	cp $(srcdir)/ws.css wsug_html_chunked
	$(XSLTPROC) --stringparam base.dir wsug_html_chunked/ --stringparam  use.id.as.filename 1 \
		    --stringparam admon.graphics 1 --stringparam admon.graphics.path wsug_graphics/ \
		    --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 \
		    --stringparam html.stylesheet ws.css \
		    --nonet http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl $<
	-chmod -R og+rX wsug_html_chunked

# create pdf file (through XSL-FO), portrait pages on US letter paper
# you will get lot's of errors, but that's ok
user-guide-us.fo: $(WSUG_SOURCE) custom_layer_pdf.xsl wsluarm
	@ echo --- WSUG - PDF US PAPER ---
	$(XSLTPROC) --stringparam paper.type letter --nonet custom_layer_pdf.xsl $< > $@

# create pdf file (through XSL-FO), portrait pages on A4 paper
# you will get lot's of errors, but that's ok
user-guide-a4.fo: $(WSUG_SOURCE) custom_layer_pdf.xsl wsluarm
	@ echo --- WSUG - PDF A4 PAPER ---
	$(XSLTPROC) --stringparam paper.type A4 --nonet custom_layer_pdf.xsl $< > $@

wsluarm: make-wsluarm.pl $(WSLUA_MODULES)
	mkdir -p wsluarm_src
	$(PERL) $(srcdir)/make-wsluarm.pl $(WSLUA_MODULES)
	touch wsluarm


# Wireshark Developer Guide
if HAVE_FOP
WSDG_TARGETS=wsdg.validated wsdg_html_chunked developer-guide.html developer-guide-a4.pdf developer-guide-us.pdf
else
WSDG_TARGETS=wsdg.validated wsdg_html_chunked developer-guide.html
endif

wsdg: $(WSDG_TARGETS)

# validate the content
wsdg.validated: $(WSDG_SOURCE)
if HAVE_XMLLINT
	@ echo --- WSDG - VALIDATING XML ---
	$(XMLLINT) --valid --noout $<
	touch $@
else
	@ echo --- WSDG - SKIP VALIDATION ---
endif

# create html single page file
developer-guide.html: wsdg_html/developer-guide.html

wsdg_html/developer-guide.html: $(WSDG_SOURCE)
	@ echo --- WSDG - HTML SINGLE PAGE ---
	mkdir -p wsdg_html/wsdg_graphics/toolbar
	cp $(srcdir)/wsdg_graphics/*.* wsdg_html/wsdg_graphics
	cp wsug_graphics/toolbar/* wsug_html/wsug_graphics/toolbar/
	cp $(srcdir)/ws.css wsdg_html
	$(XSLTPROC) --stringparam base.dir wsdg_html/ --stringparam  use.id.as.filename 1 \
		    --stringparam admon.graphics 1 --stringparam admon.graphics.path wsdg_graphics/ \
		    --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 \
		    --stringparam html.stylesheet ws.css \
		    --nonet http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $< > $@
	-chmod -R og+rX wsdg_html

# create html chunked page files
wsdg_html_chunked: wsdg_html_chunked/index.html

wsdg_html_chunked/index.html: $(WSDG_SOURCE)
	@ echo --- WSDG - HTML CHUNKED ---
	mkdir -p wsdg_html_chunked/wsdg_graphics/toolbar
	cp $(srcdir)/wsdg_graphics/*.* wsdg_html_chunked/wsdg_graphics
	cp wsug_graphics/toolbar/* wsug_html_chunked/wsug_graphics/toolbar/
	cp $(srcdir)/ws.css wsdg_html_chunked
	$(XSLTPROC) --stringparam base.dir wsdg_html_chunked/ --stringparam  use.id.as.filename 1 \
		    --stringparam admon.graphics 1 --stringparam admon.graphics.path wsdg_graphics/  \
		    --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 \
		    --stringparam html.stylesheet ws.css \
		    --nonet http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl $<
	-chmod -R og+rX wsdg_html_chunked

# create pdf file (through XSL-FO), portrait pages on US letter paper
# you will get lot's of errors, but that's ok
developer-guide-us.fo: $(WSDG_SOURCE) custom_layer_pdf.xsl
	@ echo --- WSDG - PDF US PAPER ---
	$(XSLTPROC) --stringparam paper.type letter --nonet custom_layer_pdf.xsl $< > $@

# create pdf file (through XSL-FO), portrait pages on A4 paper
# you will get lot's of errors, but that's ok
developer-guide-a4.fo: $(WSDG_SOURCE) custom_layer_pdf.xsl
	@ echo --- WSDG - PDF A4 PAPER ---
	$(XSLTPROC) --stringparam paper.type A4 --nonet custom_layer_pdf.xsl $< > $@


if HAVE_FOP
RELEASE_NOTES_TARGETS=release_notes.validated release-notes.html release-notes.txt release-notes-a4.pdf release-notes-us.pdf
else
RELEASE_NOTES_TARGETS=release_notes.validated release-notes.html release-notes.txt
endif

release_notes: $(RELEASE_NOTES_TARGETS)

# validate the content
release_notes.validated: $(RELEASE_NOTES_SOURCE)
if HAVE_XMLLINT
	@ echo --- RELEASE NOTES - VALIDATING XML ---
	$(XMLLINT) --valid --noout $<
	touch $@
else
	@ echo --- RELEASE NOTES - SKIP VALIDATION ---
endif

# create html single page file
release-notes.html: $(RELEASE_NOTES_SOURCE)
	@ echo --- RELEASE NOTES - HTML ---
	$(XSLTPROC) --nonet http://docbook.sourceforge.net/release/xsl/current/xhtml/docbook.xsl $< > $@

# create txt single page file (through HTML)
release-notes.txt: $(RELEASE_NOTES_SOURCE)
	@ echo --- RELEASE NOTES - TXT ---
	$(XSLTPROC) --stringparam generate.toc "article nop" \
		    --nonet http://docbook.sourceforge.net/release/xsl/current/xhtml/docbook.xsl $< | $(HTML2TXT) > $@

news: release-notes.txt
	cp release-notes.txt ../NEWS 

# create pdf file (through XSL-FO), portrait pages on US letter paper
# you will get lot's of errors, but that's ok
release-notes-us.fo: $(RELEASE_NOTES_SOURCE) custom_layer_pdf.xsl
	@ echo --- RELEASE NOTES - PDF US PAPER ---
	$(XSLTPROC) --stringparam paper.type letter --nonet custom_layer_pdf.xsl $< > $@

# create pdf file (through XSL-FO), portrait pages on A4 paper
# you will get lot's of errors, but that's ok
release-notes-a4.fo: $(RELEASE_NOTES_SOURCE) custom_layer_pdf.xsl
	@ echo --- RELEASE NOTES - PDF A4 PAPER ---
	$(XSLTPROC) --stringparam paper.type A4 --nonet custom_layer_pdf.xsl $< > $@

clean-local:
	-rm -rf $(CLEANDIRS)

EXTRA_DIST = \
	$(WSUG_SOURCE)		\
	$(WSDG_SOURCE)		\
	$(RELEASE_NOTES_SOURCE)	\
	check_svn_version.sh	\
	docbook.vcproj		\
	dfilter2xml.pl		\
	make-wsluarm.pl		\
	README.txt		\
	Makefile.nmake		\
	CMakeLists.txt	

MAINTAINERCLEANFILES = \
	Makefile.in

