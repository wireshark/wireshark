#
# Make the "Ethereal User's Guide" in several formats.
# See the Readme.txt file for instructions.
#
# $Id$
#

# formatting objects processor
# Additional options to fop.
# This needs to contain at least the argument '-Xmx256m'
FOP_OPTS=-Xmx256m
# (comment this out, if you don't want pdf or don't have fop installed)
# for win32 (cygwin) environments (as of fop-0.20 the cygwin script does
# not use $FOP_OPTS)
#FOP=fop-0.20.5/fop.bat
# for unix like environments (if you have problems with fop, try to use an absolute path here)
FOP="~/devel/fop-0.20.5/fop.sh"
# One SUSE 9.1 and 9.2 uncomment the following line (make sure you have at least fop-0.20.5-71.2)
#FOP=fop

# html help compiler (Win32 only)
# (comment this out, if you don't want chm or don't have hhc installed)
#HHC="/cygdrive/c/Program Files/HTML Help Workshop/hhc.exe"
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
	FOP_OPTS="$(FOP_OPTS)" $(FOP) $< $@

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
	wsug_src/WSUG_preface.xml

WSUG_GRAPHICS =	\
	graphics/ethereal-3pane.png			\
	graphics/ethereal-analyze-menu.png		\
	graphics/ethereal-bytes-pane-popup-menu.png	\
	graphics/ethereal-bytes-pane-tabs.png		\
	graphics/ethereal-bytes-pane.png		\
	graphics/ethereal-capture-info.png		\
	graphics/ethereal-capture-interfaces.png	\
	graphics/ethereal-capture-menu.png		\
	graphics/ethereal-capture-options.png		\
	graphics/ethereal-capture-preferences.png	\
	graphics/ethereal-choose-color-rule.png		\
	graphics/ethereal-coloring-rules-dialog.png	\
	graphics/ethereal-decode-as-show.png		\
	graphics/ethereal-decode-as.png			\
	graphics/ethereal-details-pane-popup-menu.png	\
	graphics/ethereal-details-pane.png		\
	graphics/ethereal-display-filter-tcp.png	\
	graphics/ethereal-edit-color-rule-dialog.png	\
	graphics/ethereal-edit-menu.png			\
	graphics/ethereal-empty.png			\
	graphics/ethereal-enabled-protocols.png		\
	graphics/ethereal-error-file-exists.png		\
	graphics/ethereal-error-open.png		\
	graphics/ethereal-export-pdml.png		\
	graphics/ethereal-export-plain.png		\
	graphics/ethereal-export-ps.png			\
	graphics/ethereal-export-psml.png		\
	graphics/ethereal-export-selected.png		\
	graphics/ethereal-file-menu.png			\
	graphics/ethereal-file-set-dialog.png		\
	graphics/ethereal-filter-add-expression.png	\
	graphics/ethereal-filter-toolbar.png		\
	graphics/ethereal-filters-2.png			\
	graphics/ethereal-filters.png			\
	graphics/ethereal-find-packet.png		\
	graphics/ethereal-follow-stream.png		\
	graphics/ethereal-go-menu.png			\
	graphics/ethereal-goto-packet.png		\
	graphics/ethereal-gui-colors-preferences.png	\
	graphics/ethereal-gui-columns-preferences.png	\
	graphics/ethereal-gui-font-preferences.png	\
	graphics/ethereal-gui-layout-preferences.png	\
	graphics/ethereal-gui-preferences.png		\
	graphics/ethereal-help-menu.png			\
	graphics/ethereal-list-pane.png			\
	graphics/ethereal-main-toolbar.png		\
	graphics/ethereal-menu.png			\
	graphics/ethereal-merge.png			\
	graphics/ethereal-nameresolution-preferences.png	\
	graphics/ethereal-open.png			\
	graphics/ethereal-packet-format.png		\
	graphics/ethereal-packet-pane-popup-menu.png	\
	graphics/ethereal-packet-range.png		\
	graphics/ethereal-packet-selected.png		\
	graphics/ethereal-packet-sep-win.png		\
	graphics/ethereal-print.png			\
	graphics/ethereal-printing-preferences.png	\
	graphics/ethereal-save-as.png			\
	graphics/ethereal-statistics-menu.png		\
	graphics/ethereal-stats-conversations.png	\
	graphics/ethereal-stats-endpoints.png		\
	graphics/ethereal-stats-hierarchy.png		\
	graphics/ethereal-stats-iographs.png		\
	graphics/ethereal-stats-srt-dcerpc-filter.png	\
	graphics/ethereal-stats-srt-dcerpc.png		\
	graphics/ethereal-stats-summary.png		\
	graphics/ethereal-statusbar-empty.png		\
	graphics/ethereal-statusbar-loaded.png		\
	graphics/ethereal-statusbar-selected.png	\
	graphics/ethereal-time-reference.png		\
	graphics/ethereal-view-menu.png			\
	graphics/note.png				\
	graphics/tip.png				\
	graphics/warning.png				\
	graphics/toolbar/autoscroll_24.png		\
	graphics/toolbar/capture_filter_24.png		\
	graphics/toolbar/capture_interfaces_24.png 	\
	graphics/toolbar/capture_options_24.png 	\
	graphics/toolbar/capture_restart_24.png 	\
	graphics/toolbar/capture_start_24.png 		\
	graphics/toolbar/capture_stop_24.png 		\
	graphics/toolbar/colorize_24.png		\
	graphics/toolbar/display_filter_24.png		\
	graphics/toolbar/resize_columns_24.png		\
	graphics/toolbar/stock_add_24.png		\
	graphics/toolbar/stock_bottom_24.png		\
	graphics/toolbar/stock_close_24.png		\
	graphics/toolbar/stock_colorselector_24.png	\
	graphics/toolbar/stock_help_24.png		\
	graphics/toolbar/stock_jump_to_24.png		\
	graphics/toolbar/stock_left_arrow_24.png	\
	graphics/toolbar/stock_open_24.png		\
	graphics/toolbar/stock_preferences_24.png	\
	graphics/toolbar/stock_print_24.png		\
	graphics/toolbar/stock_properties_24.png	\
	graphics/toolbar/stock_refresh_24.png		\
	graphics/toolbar/stock_right_arrow_24.png	\
	graphics/toolbar/stock_save_24.png		\
	graphics/toolbar/stock_save_as_24.png		\
	graphics/toolbar/stock_search_24.png		\
	graphics/toolbar/stock_stop_24.png		\
	graphics/toolbar/stock_top_24.png		\
	graphics/toolbar/stock_zoom_1_24.png		\
	graphics/toolbar/stock_zoom_in_24.png		\
	graphics/toolbar/stock_zoom_out_24.png		\
	graphics/wireshark-logo.png			\
	graphics/wireshark-main.png

EDG_FILES =	\
	edg_src/EDG_chapter_build_intro.xml	\
	edg_src/EDG_chapter_capture.xml		\
	edg_src/EDG_chapter_dissection.xml	\
	edg_src/EDG_chapter_env_intro.xml	\
	edg_src/EDG_chapter_libraries.xml	\
	edg_src/EDG_chapter_sources.xml		\
	edg_src/EDG_chapter_tools.xml		\
	edg_src/EDG_chapter_userinterface.xml	\
	edg_src/EDG_chapter_works.xml		\
	edg_src/EDG_meta_info.xml		\
	edg_src/EDG_preface.xml

EDG_GRAPHICS =	\
	edg_graphics/ethereal-capture-sync.dia		\
	edg_graphics/ethereal-capture-sync.png		\
	edg_graphics/ethereal-capture_internals.dia	\
	edg_graphics/ethereal-capture_internals.png	\
	edg_graphics/ethereal-function-blocks.dia	\
	edg_graphics/ethereal-function-blocks.png	\
	edg_graphics/wireshark-logo.png			\
	edg_graphics/note.png				\
	edg_graphics/tip.png				\
	edg_graphics/warning.png

# user-guide.xml must be first in the list (to match $<)
WSUG_SOURCE =	\
	user-guide.xml		\
	svn_version.xml		\
	$(WSUG_FILES)		\
	$(WSUG_GRAPHICS)

# developer-guide.xml must be first in the list (to match $<)
EDG_SOURCE =	\
	developer-guide.xml	\
	svn_version.xml		\
	$(EDG_FILES)		\
	$(EDG_GRAPHICS)

RELEASE_NOTES_SOURCE = \
	release-notes.xml	\
	svn_version.xml

CLEANFILES =	\
	*.chm			\
	*.fo			\
	*.hhc			\
	*.hhp			\
	*.pdf			\
	*.validated		\
	edg_chm			\
	edg_html		\
	edg_html_chunked	\
	eug_chm			\
	eug_html		\
	eug_html_chunked	\
	htmlhelp.*		\
	release_notes_chm	\
	release-notes.html	\
	release-notes.txt	\
	svn_version.xml		\


all: eug.validated edg.validated release_notes.validated eug edg release_notes

clean:
	rm -rf $(CLEANFILES)

.SUFFIXES: .fo .pdf

#
# on every build, record the working copy revision string
#
# FORCE is the portable version of .PHONY
FORCE:

svn_version.xml: FORCE
	echo -n '<!ENTITY SvnVersion "' > svn_version.xml
	svnversion -n .                   >> svn_version.xml
	echo '">'   >> svn_version.xml


eug: eug_html_chunked user-guide.html user-guide-a4.pdf user-guide-us.pdf user-guide.chm

# validate the content
eug.validated: $(WSUG_SOURCE)
	@ echo --- WSUG - VALIDATING XML ---
	$(XMLLINT) --valid --noout $<
	touch $@

# create html single page file
user-guide.html: $(WSUG_SOURCE)
	@ echo --- WSUG - HTML SINGLE PAGE ---
	mkdir -p eug_html/graphics/toolbar
	cp graphics/*.* eug_html/graphics
	cp graphics/toolbar/* eug_html/graphics/toolbar
	cp ws.css eug_html
	$(XSLTPROC) --stringparam base.dir eug_html/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --stringparam html.stylesheet ws.css --nonet http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $< > eug_html/$@
	-chmod -R og+rX eug_html
	
# create html chunked page files
eug_html_chunked: $(WSUG_SOURCE)
	@ echo --- WSUG - HTML CHUNKED ---
	mkdir -p eug_html_chunked/graphics/toolbar
	cp graphics/*.* eug_html_chunked/graphics
	cp graphics/toolbar/* eug_html_chunked/graphics/toolbar
	cp ws.css eug_html_chunked
	$(XSLTPROC) --stringparam base.dir eug_html_chunked/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --stringparam html.stylesheet ws.css --nonet http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl $<
	-chmod -R og+rX eug_html_chunked

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
	mkdir -p eug_chm/graphics/toolbar
	-cp graphics/*.* eug_chm/graphics/
	-cp graphics/toolbar/* eug_chm/graphics/toolbar/
	$(XSLTPROC) --stringparam base.dir eug_chm/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1  --stringparam html.stylesheet ws.css --nonet http://docbook.sourceforge.net/release/xsl/current/htmlhelp/htmlhelp.xsl $<
	-$(HHC) htmlhelp.hhp
	-mv htmlhelp.chm $@
	-rm -r htmlhelp.hhp
	-rm -r toc.hhc
endif


edg: edg_html_chunked developer-guide.html developer-guide-a4.pdf developer-guide-us.pdf developer-guide.chm

# validate the content
edg.validated: $(EDG_SOURCE)
	@ echo --- EDG - VALIDATING XML ---
	$(XMLLINT) --valid --noout $<
	touch $@

# create html single page file
developer-guide.html: $(EDG_SOURCE)
	@ echo --- EDG - HTML SINGLE PAGE ---
	mkdir -p edg_html/edg_graphics
	cp edg_graphics/* edg_html/edg_graphics
	cp ws.css edg_html
	$(XSLTPROC) --stringparam base.dir edg_html/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path edg_graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --stringparam html.stylesheet ws.css --nonet http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $< > edg_html/$@
	-chmod -R og+rX edg_html
	
# create html chunked page files
edg_html_chunked: $(EDG_SOURCE)
	@ echo --- EDG - HTML CHUNKED ---
	mkdir -p edg_html_chunked
	mkdir -p edg_html_chunked/edg_graphics
	cp edg_graphics/* edg_html_chunked/edg_graphics
	cp ws.css edg_html_chunked
	$(XSLTPROC) --stringparam base.dir edg_html_chunked/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path edg_graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --stringparam html.stylesheet ws.css --nonet http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl $<
	-chmod -R og+rX edg_html_chunked

# create pdf file (through XSL-FO), portrait pages on US letter paper (the default)
# you will get lot's of errors, but that's ok
developer-guide-us.fo: $(EDG_SOURCE)
ifdef FOP
	@ echo --- EDG - PDF US PAPER ---
	$(XSLTPROC) --stringparam paper.type letter --nonet custom_layer_pdf.xsl $< > $@
endif

# create pdf file (through XSL-FO), portrait pages on A4 paper
# you will get lot's of errors, but that's ok
developer-guide-a4.fo: $(EDG_SOURCE)
ifdef FOP
	@ echo --- EDG - PDF A4 PAPER ---
	$(XSLTPROC) --stringparam paper.type A4 --nonet custom_layer_pdf.xsl $< > $@
endif

# create MS html help file (through html chunked pages)
developer-guide.chm: $(EDG_SOURCE)
ifdef HHC
	@ echo --- EDG - MICROSOFT HTML HELP ---
	mkdir -p edg_chm/edg_graphics
	cp edg_graphics/* edg_chm/edg_graphics
	$(XSLTPROC) --stringparam base.dir edg_chm/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path edg_graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --stringparam html.stylesheet ws.css --nonet http://docbook.sourceforge.net/release/xsl/current/htmlhelp/htmlhelp.xsl $<
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
	$(XSLTPROC) --stringparam base.dir release_notes_chm/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --nonet http://docbook.sourceforge.net/release/xsl/current/htmlhelp/htmlhelp.xsl $<
	-$(HHC) htmlhelp.hhp
	-mv htmlhelp.chm $@
	-rm -r htmlhelp.hhp
	-rm -r toc.hhc
endif

