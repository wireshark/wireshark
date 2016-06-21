#
# Make the "Wireshark User Guide" and "Wireshark Developer Guide"
# in several formats.
# See the Readme.txt file for instructions.
#

# formatting objects processor
# Additional options to fop.
# This needs to contain at least the argument '-Xmx256m'
# fop executable is found in configure.ac.
FOP_OPTS=-Xmx256m

# Asciidoc converter
A2X_HTML_OPTS="--stylesheet=ws.css"
A2X_TEXT_OPTS=

############### YOU SHOULDN'T HAVE TO EDIT ANYTHING BELOW THIS LINE! ################

WSUG_FILES =	\
	wsug_src/WSUG_app_files.asciidoc		\
	wsug_src/WSUG_app_howitworks.asciidoc		\
	wsug_src/WSUG_app_messages.asciidoc		\
	wsug_src/WSUG_app_protocols.asciidoc		\
	wsug_src/WSUG_app_tools.asciidoc		\
	wsug_src/WSUG_chapter_advanced.asciidoc		\
	wsug_src/WSUG_chapter_build_install.asciidoc	\
	wsug_src/WSUG_chapter_capture.asciidoc		\
	wsug_src/WSUG_chapter_customize.asciidoc	\
	wsug_src/WSUG_chapter_introduction.asciidoc	\
	wsug_src/WSUG_chapter_io.asciidoc		\
	wsug_src/WSUG_chapter_statistics.asciidoc	\
	wsug_src/WSUG_chapter_telephony.asciidoc	\
	wsug_src/WSUG_chapter_troubleshoot.asciidoc	\
	wsug_src/WSUG_chapter_use.asciidoc		\
	wsug_src/WSUG_chapter_work.asciidoc		\
	wsug_src/WSUG_preface.asciidoc			\
	ws.css

WSUG_GENERATED_SOURCE = \
	user-guide.xml

WSUG_GRAPHICS =	\
	wsug_graphics/captureOptions.png		\
	wsug_graphics/related-ack.png			\
	wsug_graphics/related-dup-ack.png		\
	wsug_graphics/related-last.png			\
	wsug_graphics/related-request.png		\
	wsug_graphics/related-segment.png		\
	wsug_graphics/related-current.png		\
	wsug_graphics/related-first.png			\
	wsug_graphics/related-other.png			\
	wsug_graphics/related-response.png		\
	wsug_graphics/ws-analyze-menu.png		\
	wsug_graphics/ws-bytes-pane-tabs.png		\
	wsug_graphics/ws-bytes-pane.png			\
	wsug_graphics/ws-capture-info.png		\
	wsug_graphics/ws-capture-interfaces.png		\
	wsug_graphics/ws-capture-interface-details.png		\
	wsug_graphics/ws-capture-interfaces-win32.png	\
	wsug_graphics/ws-capture-menu.png		\
	wsug_graphics/ws-capture-options.png		\
	wsug_graphics/ws-capture-options-compile-selected-bpfs.png	\
	wsug_graphics/ws-capture-options-manage-interfaces-local.png	\
	wsug_graphics/ws-capture-options-manage-interfaces-pipes.png	\
	wsug_graphics/ws-capture-options-manage-interfaces-remote-plus.png	\
	wsug_graphics/ws-capture-options-manage-interfaces-remote.png	\
	wsug_graphics/ws-capture-options-manage-interfaces.png	\
	wsug_graphics/ws-capture-options-remote-capture.png	\
	wsug_graphics/ws-capture-options-remote-interface.png	\
	wsug_graphics/ws-capture-options-remote-settings.png	\
	wsug_graphics/ws-capture-options-settings.png	\
	wsug_graphics/ws-capture-preferences.png	\
	wsug_graphics/ws-choose-color-rule.png		\
	wsug_graphics/ws-coloring-fields.png		\
	wsug_graphics/ws-coloring-rules-dialog.png	\
	wsug_graphics/ws-column-header-popup-menu.png	\
	wsug_graphics/ws-decode-as-show.png		\
	wsug_graphics/ws-decode-as.png			\
	wsug_graphics/ws-details-pane-popup-menu.png	\
	wsug_graphics/ws-details-pane.png		\
	wsug_graphics/ws-display-filter-tcp.png		\
	wsug_graphics/ws-edit-menu.png			\
	wsug_graphics/ws-enabled-protocols.png		\
	wsug_graphics/ws-expert-colored-tree.png	\
	wsug_graphics/ws-expert-column.png		\
	wsug_graphics/ws-expert-infos.png		\
	wsug_graphics/ws-export-objects.png		\
	wsug_graphics/ws-export-pdml.png		\
	wsug_graphics/ws-export-plain.png		\
	wsug_graphics/ws-export-ps.png			\
	wsug_graphics/ws-export-psml.png		\
	wsug_graphics/ws-export-selected.png		\
	wsug_graphics/ws-file-import.png			\
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
	wsug_graphics/ws-gui-config-profiles.png	\
	wsug_graphics/ws-gui-font-preferences.png	\
	wsug_graphics/ws-gui-interface-options.png	\
	wsug_graphics/ws-gui-layout-preferences.png	\
	wsug_graphics/ws-gui-preferences.png		\
	wsug_graphics/ws-help-menu.png			\
	wsug_graphics/ws-internals-menu.png			\
	wsug_graphics/ws-list-pane.png			\
	wsug_graphics/ws-logo.png			\
	wsug_graphics/ws-main-toolbar.png		\
	wsug_graphics/ws-main.png			\
	wsug_graphics/ws-menu.png			\
	wsug_graphics/ws-merge-gtk24.png		\
	wsug_graphics/ws-merge-win32.png		\
	wsug_graphics/ws-nameresolution-preferences.png	\
	wsug_graphics/ws-open-gtk24.png			\
	wsug_graphics/ws-open-win32.png			\
	wsug_graphics/ws-packet-format.png		\
	wsug_graphics/ws-packet-pane-popup-menu.png	\
	wsug_graphics/ws-packet-range.png		\
	wsug_graphics/ws-packet-selected.png		\
	wsug_graphics/ws-packet-sep-win.png		\
	wsug_graphics/ws-print.png			\
	wsug_graphics/ws-printing-preferences.png	\
	wsug_graphics/ws-save-as-gtk24.png		\
	wsug_graphics/ws-save-as-win32.png		\
	wsug_graphics/ws-statistics-menu.png		\
	wsug_graphics/ws-stats-compare.png		\
	wsug_graphics/ws-stats-conversations.png	\
	wsug_graphics/ws-stats-endpoints.png		\
	wsug_graphics/ws-stats-hierarchy.png		\
	wsug_graphics/ws-stats-iographs.png		\
	wsug_graphics/ws-stats-srt-dcerpc-filter.png	\
	wsug_graphics/ws-stats-srt-dcerpc.png		\
	wsug_graphics/ws-stats-summary.png		\
	wsug_graphics/ws-stats-lte-mac-traffic.png		\
	wsug_graphics/ws-stats-lte-rlc-traffic.png		\
	wsug_graphics/ws-stats-wlan-traffic.png		\
	wsug_graphics/ws-statusbar-empty.png		\
	wsug_graphics/ws-statusbar-filter.png		\
	wsug_graphics/ws-statusbar-loaded.png		\
	wsug_graphics/ws-statusbar-profile.png		\
	wsug_graphics/ws-statusbar-selected.png		\
	wsug_graphics/ws-tel-rtpstream-analysis.png		\
	wsug_graphics/ws-telephony-menu.png		\
	wsug_graphics/ws-tools-menu.png	\
	wsug_graphics/ws-time-reference.png		\
	wsug_graphics/ws-view-menu.png			\
	wsug_graphics/toolbar/autoscroll_24.png			\
	wsug_graphics/toolbar/capture_filter_24.png		\
	wsug_graphics/toolbar/capture_interfaces_24.png 	\
	wsug_graphics/toolbar/capture_options_24.png	 	\
	wsug_graphics/toolbar/capture_restart_24.png 		\
	wsug_graphics/toolbar/capture_start_24.png 		\
	wsug_graphics/toolbar/capture_stop_24.png 		\
	wsug_graphics/toolbar/colorize_24.png			\
	wsug_graphics/toolbar/display_filter_24.png		\
	wsug_graphics/toolbar/resize_columns_24.png		\
	wsug_graphics/toolbar/stock_add_24.png			\
	wsug_graphics/toolbar/stock_apply_20.png		\
	wsug_graphics/toolbar/stock_bottom_24.png		\
	wsug_graphics/toolbar/stock_clear_24.png		\
	wsug_graphics/toolbar/stock_close_24.png		\
	wsug_graphics/toolbar/stock_colorselector_24.png	\
	wsug_graphics/toolbar/stock_help_24.png			\
	wsug_graphics/toolbar/stock_jump_to_24.png		\
	wsug_graphics/toolbar/stock_left_arrow_24.png		\
	wsug_graphics/toolbar/stock_open_24.png			\
	wsug_graphics/toolbar/stock_preferences_24.png		\
	wsug_graphics/toolbar/stock_print_24.png		\
	wsug_graphics/toolbar/stock_properties_24.png		\
	wsug_graphics/toolbar/stock_refresh_24.png		\
	wsug_graphics/toolbar/stock_right_arrow_24.png		\
	wsug_graphics/toolbar/stock_save_24.png			\
	wsug_graphics/toolbar/stock_save_as_24.png		\
	wsug_graphics/toolbar/stock_search_24.png		\
	wsug_graphics/toolbar/stock_stop_24.png			\
	wsug_graphics/toolbar/stock_top_24.png			\
	wsug_graphics/toolbar/stock_zoom_1_24.png		\
	wsug_graphics/toolbar/stock_zoom_in_24.png		\
	wsug_graphics/toolbar/stock_zoom_out_24.png

WSDG_FILES =	\
	wsdg_src/WSDG_chapter_build_intro.asciidoc	\
	wsdg_src/WSDG_chapter_capture.asciidoc		\
	wsdg_src/WSDG_chapter_dissection.asciidoc	\
	wsdg_src/WSDG_chapter_env_intro.asciidoc	\
	wsdg_src/WSDG_chapter_libraries.asciidoc	\
	wsdg_src/WSDG_chapter_quick_setup.asciidoc	\
	wsdg_src/WSDG_chapter_sources.asciidoc		\
	wsdg_src/WSDG_chapter_tools.asciidoc		\
	wsdg_src/WSDG_chapter_userinterface.asciidoc	\
	wsdg_src/WSDG_chapter_works.asciidoc		\
	wsdg_src/WSDG_preface.asciidoc			\
	wsluarm.asciidoc				\
	ws.css

WSDG_GENERATED_SOURCE = \
	developer-guide.xml

WSDG_GRAPHICS =	\
	wsdg_graphics/ws-capture-sync.dia	\
	wsdg_graphics/ws-capture-sync.png	\
	wsdg_graphics/ws-capture_internals.dia	\
	wsdg_graphics/ws-capture_internals.png	\
	wsdg_graphics/ws-function-blocks.dia	\
	wsdg_graphics/ws-function-blocks.png	\
	wsdg_graphics/ws-logo.png		\
	wsdg_graphics/toolbar/dummy.dummy

COMMON_GRAPHICS = \
	common_graphics/note.svg	\
	common_graphics/tip.svg		\
	common_graphics/warning.svg

# user-guide.xml must be first in the list (to match $<)
WSUG_DIST =	\
	user-guide.asciidoc	\
	GPL_appendix.asciidoc	\
	custom_layer_chm.xsl	\
	custom_layer_pdf.xsl	\
	$(WSUG_FILES)		\
	$(WSUG_GRAPHICS)	\
	$(COMMON_GRAPHICS)

WSUG_SOURCE = $(WSUG_GENERATED_SOURCE) $(WSUG_DIST)

# developer-guide.asciidoc must be first in the list (to match $<)
WSDG_DIST =	\
	developer-guide.asciidoc	\
	GPL_appendix.asciidoc	\
	custom_layer_chm.xsl	\
	custom_layer_pdf.xsl	\
	$(WSDG_FILES)		\
	$(WSDG_GRAPHICS)	\
	$(COMMON_GRAPHICS)

WSDG_SOURCE = $(WSDG_GENERATED_SOURCE) $(WSDG_DIST)

RELEASE_NOTES_SOURCE = \
	release-notes.asciidoc	\
	asciidoc.conf		\
	asciidoctor-asciidoc.conf

CLEANFILES =	\
	*.chm			\
	*.fo			\
	*.hhc			\
	*.hhp			\
	*.pdf			\
	$(WSDG_GENERATED_SOURCE) \
	$(WSUG_GENERATED_SOURCE) \
	wsdg_chm		\
	wsdg_html.zip		\
	wsdg_html_chunked.zip	\
	wsug_chm		\
	wsug_html.zip		\
	wsug_html_chunked.zip	\
	htmlhelp.*		\
	release_notes_chm	\
	release-notes.html	\
	release-notes.txt	\
	user-guide.zip		\
	wsluarm

CLEANDIRS =	\
	wsdg_html		\
	wsdg_html_chunked	\
	wsug_html		\
	wsug_html_chunked	\
	wsluarm_src

# Note: file order here MATTERS!
# new WSLUA_MODULE files must come right before any WSLUA_CONTINUE_MODULE
# files for the same module
WSLUA_MODULES = \
	$(top_srcdir)/epan/wslua/wslua_dumper.c \
	$(top_srcdir)/epan/wslua/wslua_field.c \
	$(top_srcdir)/epan/wslua/wslua_gui.c \
	$(top_srcdir)/epan/wslua/wslua_listener.c \
	$(top_srcdir)/epan/wslua/wslua_pinfo.c \
	$(top_srcdir)/epan/wslua/wslua_address.c \
	$(top_srcdir)/epan/wslua/wslua_column.c \
	$(top_srcdir)/epan/wslua/wslua_nstime.c \
	$(top_srcdir)/epan/wslua/wslua_proto.c \
	$(top_srcdir)/epan/wslua/wslua_dissector.c \
	$(top_srcdir)/epan/wslua/wslua_pref.c \
	$(top_srcdir)/epan/wslua/wslua_proto_expert.c \
	$(top_srcdir)/epan/wslua/wslua_proto_field.c \
	$(top_srcdir)/epan/wslua/wslua_int64.c \
	$(top_srcdir)/epan/wslua/wslua_struct.c \
	$(top_srcdir)/epan/wslua/wslua_tree.c \
	$(top_srcdir)/epan/wslua/wslua_tvb.c \
	$(top_srcdir)/epan/wslua/wslua_byte_array.c \
	$(top_srcdir)/epan/wslua/wslua_file.c \
	$(top_srcdir)/epan/wslua/wslua_file_handler.c \
	$(top_srcdir)/epan/wslua/wslua_frame_info.c \
	$(top_srcdir)/epan/wslua/wslua_capture_info.c \
	$(top_srcdir)/epan/wslua/wslua_dir.c \
	$(top_srcdir)/epan/wslua/wslua_util.c

COMMON_XSLTPROC_ARGS = \
	--stringparam use.id.as.filename 1 \
	--stringparam admon.graphics 1 \
	--stringparam admon.graphics.extension .svg \
	--stringparam section.autolabel 1 \
	--stringparam section.label.includes.component.label 1 \
	--stringparam html.stylesheet ws.css

WSUG_XSLTPROC_ARGS = \
	--stringparam admon.graphics.path wsug_graphics/

WSUG_PDF_XSLTPROC_ARGS = \
		--stringparam img.src.path $(srcdir)/ \
		--stringparam admon.graphics.path $(srcdir)/common_graphics/

WSDG_XSLTPROC_ARGS = \
	--stringparam admon.graphics.path wsdg_graphics/

WSDG_PDF_XSLTPROC_ARGS = \
		--stringparam img.src.path $(srcdir)/ \
		--stringparam admon.graphics.path $(srcdir)/common_graphics/

SINGLE_XSLTPROC_ARGS = \
	--nonet http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl

CHUNKED_XSLTPROC_ARGS = \
	--nonet http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl

HTMLHELP_XSLTPROC_ARGS = \
	--nonet custom_layer_chm.xsl
#	--nonet http://docbook.sourceforge.net/release/xsl/current/htmlhelp/htmlhelp.xsl

# Automatically generate .pdf files from .fo files
# Suse needs FOP_OPTS, Debian needs JAVA_OPTS
.fo.pdf:
	FOP_OPTS=$(FOP_OPTS) JAVA_OPTS=$(FOP_OPTS) $(FOP) $< $@

all: wsug wsdg release-notes

all-pdf: wsug-pdf wsdg-pdf release-notes-pdf

# Wireshark User Guide
wsug: wsug_html_chunked wsug_html

wsug-pdf: wsug user-guide-a4.pdf user-guide-us.pdf

user-guide.xml: user-guide.asciidoc $(WSUG_FILES)
	$(A2X) --verbose \
		--attribute=docinfo \
		--asciidoc-opts="--conf-file=$(srcdir)/asciidoc.conf --conf-file=$(srcdir)/asciidoctor-asciidoc.conf" \
		--no-xmllint \
		--format=docbook \
		--destination-dir=$(builddir) \
		$<

# create html single page file
wsug_html: wsug_html/index.html

wsug_html/index.html: $(WSUG_SOURCE)
	@ echo --- WSUG - HTML SINGLE PAGE ---
	mkdir -p wsug_html/wsug_graphics/toolbar
	cp $(srcdir)/wsug_graphics/*.* wsug_html/wsug_graphics
	cp $(srcdir)/common_graphics/*.* wsug_html/wsug_graphics
	cp $(srcdir)/wsug_graphics/toolbar/* wsug_html/wsug_graphics/toolbar
	cp $(srcdir)/ws.css wsug_html
	$(XSLTPROC) --stringparam base.dir wsug_html/ $(COMMON_XSLTPROC_ARGS) \
		$(WSUG_XSLTPROC_ARGS) $(SINGLE_XSLTPROC_ARGS) $< > $@
	-chmod -R og+rX wsug_html

# create html chunked page files
wsug_html_chunked: wsug_html_chunked/index.html

wsug_html_chunked/index.html: $(WSUG_SOURCE)
	@ echo --- WSUG - HTML CHUNKED ---
	mkdir -p wsug_html_chunked/wsug_graphics/toolbar
	cp $(srcdir)/wsug_graphics/*.* wsug_html_chunked/wsug_graphics
	cp $(srcdir)/common_graphics/*.* wsug_html_chunked/wsug_graphics
	cp $(srcdir)/wsug_graphics/toolbar/* wsug_html_chunked/wsug_graphics/toolbar
	cp $(srcdir)/ws.css wsug_html_chunked
	$(XSLTPROC) --stringparam base.dir wsug_html_chunked/ $(COMMON_XSLTPROC_ARGS) \
		    $(WSUG_XSLTPROC_ARGS) $(CHUNKED_XSLTPROC_ARGS) $<
	-chmod -R og+rX wsug_html_chunked

# create pdf file (through XSL-FO), portrait pages on US letter paper
# you will get lot's of errors, but that's ok
user-guide-us.fo: $(WSUG_SOURCE) custom_layer_pdf.xsl
	@ echo --- WSUG - PDF US PAPER ---
	$(XSLTPROC) --stringparam paper.type letter \
		$(COMMON_XSLTPROC_ARGS) $(WSUG_PDF_XSLTPROC_ARGS) \
		--nonet $(srcdir)/custom_layer_pdf.xsl $< > $@

# create pdf file (through XSL-FO), portrait pages on A4 paper
# you will get lot's of errors, but that's ok
user-guide-a4.fo: $(WSUG_SOURCE) custom_layer_pdf.xsl
	@ echo --- WSUG - PDF A4 PAPER ---
	$(XSLTPROC) --stringparam paper.type A4 \
		$(COMMON_XSLTPROC_ARGS) $(WSUG_PDF_XSLTPROC_ARGS) \
		--nonet $(srcdir)/custom_layer_pdf.xsl $< > $@

wsluarm: make-wsluarm.pl $(WSLUA_MODULES)
	mkdir -p wsluarm_src
	$(PERL) $(srcdir)/make-wsluarm.pl $(WSLUA_MODULES)
	touch wsluarm


# Wireshark Developer Guide
wsdg: wsdg_html_chunked wsdg_html

wsdg-pdf: wsdg developer-guide-a4.pdf developer-guide-us.pdf

developer-guide.xml: developer-guide.asciidoc $(WSDG_FILES) wsluarm
	$(A2X) --verbose \
		--attribute=docinfo \
		--attribute=build_dir=$(abs_builddir) \
		--asciidoc-opts="--conf-file=$(srcdir)/asciidoc.conf --conf-file=$(srcdir)/asciidoctor-asciidoc.conf" \
		--no-xmllint \
		--format=docbook \
		--destination-dir=$(builddir) \
		$<

# create html single page file
wsdg_html: wsdg_html/index.html

wsdg_html/index.html: $(WSDG_SOURCE)
	@ echo --- WSDG - HTML SINGLE PAGE ---
	mkdir -p wsdg_html/wsdg_graphics/toolbar
	cp $(srcdir)/wsdg_graphics/*.* wsdg_html/wsdg_graphics
	cp $(srcdir)/common_graphics/*.* wsdg_html/wsdg_graphics
	cp $(srcdir)/wsdg_graphics/toolbar/* wsdg_html/wsdg_graphics/toolbar/
	cp $(srcdir)/ws.css wsdg_html
	$(XSLTPROC) --stringparam base.dir wsdg_html/ $(COMMON_XSLTPROC_ARGS) \
		--path .:wsluarm_src \
		$(WSDG_XSLTPROC_ARGS) $(SINGLE_XSLTPROC_ARGS) $< > $@
	-chmod -R og+rX wsdg_html

# create html chunked page files
wsdg_html_chunked: wsdg_html_chunked/index.html

wsdg_html_chunked/index.html: $(WSDG_SOURCE)
	@ echo --- WSDG - HTML CHUNKED ---
	mkdir -p wsdg_html_chunked/wsdg_graphics/toolbar
	cp $(srcdir)/wsdg_graphics/*.* wsdg_html_chunked/wsdg_graphics
	cp $(srcdir)/common_graphics/*.* wsdg_html_chunked/wsdg_graphics
	cp $(srcdir)/wsdg_graphics/toolbar/* wsdg_html_chunked/wsdg_graphics/toolbar/
	cp $(srcdir)/ws.css wsdg_html_chunked
	$(XSLTPROC) --stringparam base.dir wsdg_html_chunked/ $(COMMON_XSLTPROC_ARGS) \
		--path .:wsluarm_src \
		$(WSDG_XSLTPROC_ARGS) $(CHUNKED_XSLTPROC_ARGS) $<
	-chmod -R og+rX wsdg_html_chunked

# create pdf file (through XSL-FO), portrait pages on US letter paper
# you will get lot's of errors, but that's ok
developer-guide-us.fo: $(WSDG_SOURCE) custom_layer_pdf.xsl
	@ echo --- WSDG - PDF US PAPER ---
	$(XSLTPROC) --stringparam paper.type letter \
		    $(COMMON_XSLTPROC_ARGS) $(WSDG_PDF_XSLTPROC_ARGS) \
		    --path .:wsluarm_src:$(srcdir) \
		    --nonet $(srcdir)/custom_layer_pdf.xsl $< > $@

# create pdf file (through XSL-FO), portrait pages on A4 paper
# you will get lot's of errors, but that's ok
developer-guide-a4.fo: $(WSDG_SOURCE) custom_layer_pdf.xsl
	@ echo --- WSDG - PDF A4 PAPER ---
	$(XSLTPROC) --stringparam paper.type A4 \
		    $(COMMON_XSLTPROC_ARGS) $(WSDG_PDF_XSLTPROC_ARGS) \
		    --path .:wsluarm_src:$(srcdir) \
		    --nonet $(srcdir)/custom_layer_pdf.xsl $< > $@

# Release notes
if HAVE_A2X_TEXT
release-notes: release-notes.html release-notes.txt
else
release-notes: release-notes.html
endif

release-notes-pdf: release-notes release-notes-a4.pdf release-notes-us.pdf

# create html single page file
release-notes.html: $(RELEASE_NOTES_SOURCE)
	@ echo --- RELEASE NOTES - HTML ---
	$(A2X) --format=xhtml $(A2X_HTML_OPTS) \
		--destination-dir=$(builddir) \
		$(srcdir)/release-notes.asciidoc

# create txt single page file (through HTML)
release-notes.txt: $(RELEASE_NOTES_SOURCE)
	@ echo --- RELEASE NOTES - TXT ---
	TZ=UTC $(A2X) --format=text @A2X_LYNX@ $(A2X_TEXT_OPTS) \
		--xsltproc-opts "--stringparam generate.toc \"article nop\"" \
		--destination-dir=$(builddir) \
		$(srcdir)/release-notes.asciidoc && \
		mv release-notes.text $@

news: release-notes.txt
	cp release-notes.txt ../NEWS
	-cp release-notes.txt $(top_srcdir)/NEWS

# Apparently we can only run one instance of a2x at a time.
.NOTPARALLEL: release-notes-us.pdf release-notes-a4.pdf
# create pdf file, portrait pages on US letter paper
release-notes-us.pdf: $(RELEASE_NOTES_SOURCE) custom_layer_pdf.xsl
	@ echo --- RELEASE NOTES - PDF US LETTER PAPER ---
	$(A2X) --format=pdf $(A2X_HTML_OPTS) --fop \
		--xsltproc-opts "--stringparam paper.type letter --nonet" \
		--xsl-file=$(srcdir)/custom_layer_pdf.xsl \
		--destination-dir=$(builddir) \
		$(srcdir)/release-notes.asciidoc

# create pdf file, portrait pages on A4 paper
release-notes-a4.pdf: $(RELEASE_NOTES_SOURCE) custom_layer_pdf.xsl
	@ echo --- RELEASE NOTES - PDF A4 PAPER ---
	$(A2X) --format=pdf $(A2X_HTML_OPTS) --fop \
		--xsltproc-opts "--stringparam paper.type A4 --nonet" \
		--xsl-file=$(srcdir)/custom_layer_pdf.xsl \
		--destination-dir=$(builddir) \
		$(srcdir)/release-notes.asciidoc

clean-local:
	-rm -rf $(CLEANDIRS)

EXTRA_DIST = \
	$(WSUG_DIST)		\
	$(WSDG_DIST)		\
	$(RELEASE_NOTES_SOURCE)	\
	dfilter2xml.pl		\
	make-wsluarm.pl		\
	README.txt		\
	CMakeLists.txt

MAINTAINERCLEANFILES = \
	Makefile.in
