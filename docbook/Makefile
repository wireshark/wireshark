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

# fop executable
# Leave these commented out if you don't have fop instlled or you
# don't want PDF documentation.
#
# for win32 (cygwin) environments (as of fop-0.20 the cygwin script does
# not use $FOP_OPTS)
FOP=fop-0.20.5/fop.bat
#
# for unix like environments (if you have problems with fop, try to use an absolute path here)
#FOP=fop-0.20.5/fop.sh
#
# One SUSE 9.1 and 9.2 uncomment the following line (make sure you have at least fop-0.20.5-71.2)
#FOP=fop

# html help compiler (Win32 only)
# Leave these commented out if you don't have HHC installed or you
# don't want CHM documentation.
HHC="/cygdrive/c/Program Files/HTML Help Workshop/hhc.exe"
#HHC="true"

# elinks (text version of release notes)
# This could also be "lynx", or "true" if neither elinks nor lynx is installed
#ELINKS=elinks
ELINKS="true"

############### YOU SHOULDN'T HAVE TO EDIT ANYTHING BELOW THIS LINE! ################

# the XSL processor
XSLTPROC="xsltproc"

# the XML validator (from the xsltproc package)
XMLLINT="xmllint"

# Automatically generate .pdf files from .fo files
.fo.pdf:
#	FOP_OPTS="$(FOP_OPTS)" $(FOP) $< $@
# On Debian use this line
	JAVA_OPTS="$(FOP_OPTS)" $(FOP) $< $@

WSUG_FILES =	\
	wsug_src/WSUG_app_files.xml \
	wsug_src/WSUG_app_howitworks.xml \
	wsug_src/WSUG_app_messages.xml \
	wsug_src/WSUG_app_protocols.xml \
	wsug_src/WSUG_app_tools.xml \
	wsug_src/WSUG_chapter_advanced.xml \
	wsug_src/WSUG_chapter_build_install.xml \
	wsug_src/WSUG_chapter_capture.xml \
	wsug_src/WSUG_chapter_customize.xml \
	wsug_src/WSUG_chapter_introduction.xml \
	wsug_src/WSUG_chapter_io.xml \
	wsug_src/WSUG_chapter_statistics.xml \
	wsug_src/WSUG_chapter_troubleshoot.xml \
	wsug_src/WSUG_chapter_use.xml \
	wsug_src/WSUG_chapter_work.xml \
	wsug_src/WSUG_meta_info.xml \
	wsug_src/WSUG_preface.xml \
	ws.css

WSUG_GRAPHICS =	\
	wsug_graphics/ws-analyze-menu.png		\
	wsug_graphics/ws-bytes-pane-popup-menu.png	\
	wsug_graphics/ws-bytes-pane-tabs.png		\
	wsug_graphics/ws-bytes-pane.png		\
	wsug_graphics/ws-capture-info.png		\
	wsug_graphics/ws-capture-interfaces.png	\
	wsug_graphics/ws-capture-menu.png		\
	wsug_graphics/ws-capture-options.png		\
	wsug_graphics/ws-capture-preferences.png	\
	wsug_graphics/ws-choose-color-rule.png		\
	wsug_graphics/ws-coloring-fields.png		\
	wsug_graphics/ws-coloring-rules-dialog.png	\
	wsug_graphics/ws-decode-as-show.png		\
	wsug_graphics/ws-decode-as.png			\
	wsug_graphics/ws-details-pane-popup-menu.png	\
	wsug_graphics/ws-details-pane.png		\
	wsug_graphics/ws-display-filter-tcp.png	\
	wsug_graphics/ws-edit-color-rule-dialog.png	\
	wsug_graphics/ws-edit-menu.png			\
	wsug_graphics/ws-enabled-protocols.png		\
	wsug_graphics/ws-export-pdml.png		\
	wsug_graphics/ws-export-plain.png		\
	wsug_graphics/ws-export-ps.png			\
	wsug_graphics/ws-export-psml.png		\
	wsug_graphics/ws-export-selected.png		\
	wsug_graphics/ws-file-menu.png			\
	wsug_graphics/ws-file-set-dialog.png		\
	wsug_graphics/ws-filter-add-expression.png	\
	wsug_graphics/ws-filter-toolbar.png		\
	wsug_graphics/ws-filters.png			\
	wsug_graphics/ws-find-packet.png		\
	wsug_graphics/ws-follow-stream.png		\
	wsug_graphics/ws-go-menu.png			\
	wsug_graphics/ws-goto-packet.png		\
	wsug_graphics/ws-gui-colors-preferences.png	\
	wsug_graphics/ws-gui-columns-preferences.png	\
	wsug_graphics/ws-gui-font-preferences.png	\
	wsug_graphics/ws-gui-layout-preferences.png	\
	wsug_graphics/ws-gui-preferences.png		\
	wsug_graphics/ws-help-menu.png			\
	wsug_graphics/ws-list-pane.png			\
	wsug_graphics/ws-main-toolbar.png		\
	wsug_graphics/ws-menu.png			\
	wsug_graphics/ws-merge.png			\
	wsug_graphics/ws-nameresolution-preferences.png	\
	wsug_graphics/ws-open.png			\
	wsug_graphics/ws-packet-format.png		\
	wsug_graphics/ws-packet-pane-popup-menu.png	\
	wsug_graphics/ws-packet-range.png		\
	wsug_graphics/ws-packet-selected.png		\
	wsug_graphics/ws-packet-sep-win.png		\
	wsug_graphics/ws-print.png			\
	wsug_graphics/ws-printing-preferences.png	\
	wsug_graphics/ws-save-as.png			\
	wsug_graphics/ws-statistics-menu.png		\
	wsug_graphics/ws-stats-conversations.png	\
	wsug_graphics/ws-stats-endpoints.png		\
	wsug_graphics/ws-stats-hierarchy.png		\
	wsug_graphics/ws-stats-iographs.png		\
	wsug_graphics/ws-stats-srt-dcerpc-filter.png	\
	wsug_graphics/ws-stats-srt-dcerpc.png		\
	wsug_graphics/ws-stats-summary.png		\
	wsug_graphics/ws-statusbar-empty.png		\
	wsug_graphics/ws-statusbar-loaded.png		\
	wsug_graphics/ws-statusbar-selected.png	\
	wsug_graphics/ws-time-reference.png		\
	wsug_graphics/ws-view-menu.png			\
	wsug_graphics/note.png				\
	wsug_graphics/tip.png				\
	wsug_graphics/warning.png				\
	wsug_graphics/toolbar/autoscroll_24.png		\
	wsug_graphics/toolbar/capture_filter_24.png		\
	wsug_graphics/toolbar/capture_interfaces_24.png 	\
	wsug_graphics/toolbar/capture_options_24.png 	\
	wsug_graphics/toolbar/capture_restart_24.png 	\
	wsug_graphics/toolbar/capture_start_24.png 		\
	wsug_graphics/toolbar/capture_stop_24.png 		\
	wsug_graphics/toolbar/colorize_24.png		\
	wsug_graphics/toolbar/display_filter_24.png		\
	wsug_graphics/toolbar/resize_columns_24.png		\
	wsug_graphics/toolbar/stock_add_24.png		\
	wsug_graphics/toolbar/stock_apply_20.png		\
	wsug_graphics/toolbar/stock_bottom_24.png		\
	wsug_graphics/toolbar/stock_clear_24.png		\
	wsug_graphics/toolbar/stock_close_24.png		\
	wsug_graphics/toolbar/stock_colorselector_24.png	\
	wsug_graphics/toolbar/stock_help_24.png		\
	wsug_graphics/toolbar/stock_jump_to_24.png		\
	wsug_graphics/toolbar/stock_left_arrow_24.png	\
	wsug_graphics/toolbar/stock_open_24.png		\
	wsug_graphics/toolbar/stock_preferences_24.png	\
	wsug_graphics/toolbar/stock_print_24.png		\
	wsug_graphics/toolbar/stock_properties_24.png	\
	wsug_graphics/toolbar/stock_refresh_24.png		\
	wsug_graphics/toolbar/stock_right_arrow_24.png	\
	wsug_graphics/toolbar/stock_save_24.png		\
	wsug_graphics/toolbar/stock_save_as_24.png		\
	wsug_graphics/toolbar/stock_search_24.png		\
	wsug_graphics/toolbar/stock_stop_24.png		\
	wsug_graphics/toolbar/stock_top_24.png		\
	wsug_graphics/toolbar/stock_zoom_1_24.png		\
	wsug_graphics/toolbar/stock_zoom_in_24.png		\
	wsug_graphics/toolbar/stock_zoom_out_24.png		\
	wsug_graphics/ws-logo.png			\
	wsug_graphics/ws-main.png

WSDG_FILES =	\
	wsdg_src/WSDG_chapter_build_intro.xml	\
	wsdg_src/WSDG_chapter_capture.xml	\
	wsdg_src/WSDG_chapter_dissection.xml	\
	wsdg_src/WSDG_chapter_env_intro.xml	\
	wsdg_src/WSDG_chapter_libraries.xml	\
	wsdg_src/WSDG_chapter_sources.xml	\
	wsdg_src/WSDG_chapter_tools.xml		\
	wsdg_src/WSDG_chapter_userinterface.xml	\
	wsdg_src/WSDG_chapter_works.xml		\
	wsdg_src/WSDG_meta_info.xml		\
	wsdg_src/WSDG_preface.xml		\
	ws.css

WSDG_GRAPHICS =	\
	wsdg_graphics/ws-capture-sync.dia		\
	wsdg_graphics/ws-capture-sync.png		\
	wsdg_graphics/ws-capture_internals.dia	\
	wsdg_graphics/ws-capture_internals.png	\
	wsdg_graphics/ws-function-blocks.dia	\
	wsdg_graphics/ws-function-blocks.png	\
	wsdg_graphics/ws-logo.png		\
	wsdg_graphics/note.png				\
	wsdg_graphics/tip.png				\
	wsdg_graphics/warning.png

# user-guide.xml must be first in the list (to match $<)
WSUG_SOURCE =	\
	user-guide.xml		\
	svn_version.xml		\
	Makefile		\
	$(WSUG_FILES)		\
	$(WSUG_GRAPHICS)

# developer-guide.xml must be first in the list (to match $<)
WSDG_SOURCE =	\
	developer-guide.xml	\
	svn_version.xml		\
	Makefile		\
	$(WSDG_FILES)		\
	$(WSDG_GRAPHICS)

RELEASE_NOTES_SOURCE = \
	release-notes.xml	\
	svn_version.xml		\
	Makefile

CLEANFILES =	\
	*.chm			\
	*.fo			\
	*.hhc			\
	*.hhp			\
	*.pdf			\
	*.validated		\
	wsdg_chm		\
	wsdg_html		\
	wsdg_html.zip		\
	wsdg_html_chunked	\
	wsdg_html_chunked.zip	\
	wsug_chm		\
	wsug_html		\
	wsug_html.zip		\
	wsug_html_chunked	\
	wsug_html_chunked.zip	\
	htmlhelp.*		\
	release_notes_chm	\
	release-notes.html	\
	release-notes.txt	\
	svn_version.xml		\


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
	@ check_svn_version.sh

svn_version.xml: svn_version_check


wsug: wsug_html_chunked user-guide.html user-guide-a4.pdf user-guide-us.pdf user-guide.chm

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
user-guide-us.fo: $(WSUG_SOURCE)
ifdef FOP
	@ echo --- WSUG - PDF US PAPER ---
	$(XSLTPROC) --stringparam paper.type letter --nonet custom_layer_pdf.xsl $< > $@
endif

# create pdf file (through XSL-FO), portrait pages on A4 paper
# you will get lot's of errors, but that's ok
user-guide-a4.fo: $(WSUG_SOURCE)
ifdef FOP
	@ echo --- WSUG - PDF A4 PAPER ---
	$(XSLTPROC) --stringparam paper.type A4 --nonet custom_layer_pdf.xsl $< > $@
endif

# create MS html help file (through html chunked pages)
user-guide.chm: $(WSUG_SOURCE)
ifdef HHC
	@ echo --- WSUG - MICROSOFT HTML HELP ---
	mkdir -p wsug_chm/wsug_graphics/toolbar
	-cp wsug_graphics/*.* wsug_chm/wsug_graphics/
	-cp wsug_graphics/toolbar/* wsug_chm/wsug_graphics/toolbar/
	$(XSLTPROC) --stringparam base.dir wsug_chm/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path wsug_graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1  --stringparam html.stylesheet ws.css --nonet http://docbook.sourceforge.net/release/xsl/current/htmlhelp/htmlhelp.xsl $<
	-$(HHC) htmlhelp.hhp
	-mv htmlhelp.chm $@
	-rm -r htmlhelp.hhp
	-rm -r toc.hhc
endif


wsdg: wsdg_html_chunked developer-guide.html developer-guide-a4.pdf developer-guide-us.pdf developer-guide.chm

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
developer-guide-us.fo: $(WSDG_SOURCE)
ifdef FOP
	@ echo --- WSDG - PDF US PAPER ---
	$(XSLTPROC) --stringparam paper.type letter --nonet custom_layer_pdf.xsl $< > $@
endif

# create pdf file (through XSL-FO), portrait pages on A4 paper
# you will get lot's of errors, but that's ok
developer-guide-a4.fo: $(WSDG_SOURCE)
ifdef FOP
	@ echo --- WSDG - PDF A4 PAPER ---
	$(XSLTPROC) --stringparam paper.type A4 --nonet custom_layer_pdf.xsl $< > $@
endif

# create MS html help file (through html chunked pages)
developer-guide.chm: $(WSDG_SOURCE)
ifdef HHC
	@ echo --- WSDG - MICROSOFT HTML HELP ---
	mkdir -p wsdg_chm/wsdg_graphics
	cp wsdg_graphics/* wsdg_chm/wsdg_graphics
	$(XSLTPROC) --stringparam base.dir wsdg_chm/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path wsdg_graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --stringparam html.stylesheet ws.css --nonet http://docbook.sourceforge.net/release/xsl/current/htmlhelp/htmlhelp.xsl $<
	-$(HHC) htmlhelp.hhp
	-mv htmlhelp.chm $@
	-rm -r htmlhelp.hhp
	-rm -r toc.hhc
endif


release_notes: release-notes.html release-notes.txt release-notes-a4.pdf release-notes-us.pdf release-notes.chm

# validate the content
release_notes.validated: $(RELEASE_NOTES_SOURCE)
	@ echo --- RELEASE NOTES - VALIDATING XML ---
	$(XMLLINT) --valid --noout $<
	touch $@

# create html single page file
release-notes.html: $(RELEASE_NOTES_SOURCE)
	@ echo --- RELEASE NOTES - HTML ---
	$(XSLTPROC) --nonet http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $< > $@

# create txt single page file
release-notes.txt: $(RELEASE_NOTES_SOURCE)
	@ echo --- RELEASE NOTES - TXT ---
	$(XSLTPROC) --stringparam generate.toc "article nop" --nonet http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $< | $(ELINKS) -dump -dump-width 72 > $@
	
# create pdf file (through XSL-FO), portrait pages on US letter paper (the default)
# you will get lot's of errors, but that's ok
release-notes-us.fo: $(RELEASE_NOTES_SOURCE)
ifdef FOP
	@ echo --- RELEASE NOTES - PDF US PAPER ---
	$(XSLTPROC) --stringparam paper.type letter --nonet custom_layer_pdf.xsl $< > $@
endif

# create pdf file (through XSL-FO), portrait pages on A4 paper
# you will get lot's of errors, but that's ok
release-notes-a4.fo: $(RELEASE_NOTES_SOURCE)
ifdef FOP
	@ echo --- RELEASE NOTES - PDF A4 PAPER ---
	$(XSLTPROC) --stringparam paper.type A4 --nonet custom_layer_pdf.xsl $< > $@
endif

# create MS html help file (through html chunked pages)
release-notes.chm: $(RELEASE_NOTES_SOURCE)
ifdef HHC
	@ echo --- RELEASE NOTES - MICROSOFT HTML HELP ---
	$(XSLTPROC) --stringparam base.dir release_notes_chm/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path wsug_graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --nonet http://docbook.sourceforge.net/release/xsl/current/htmlhelp/htmlhelp.xsl $<
	-$(HHC) htmlhelp.hhp
	-mv htmlhelp.chm $@
	-rm -r htmlhelp.hhp
	-rm -r toc.hhc
endif

