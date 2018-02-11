#
# Make the "Wireshark User Guide" and "Wireshark Developer Guide"
# in several formats.
# See the README.adoc file for instructions.
#

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

WSUG_TOOLS_HELP_FILES =	\
	wsug_src/capinfos-h.txt \
	wsug_src/dumpcap-h.txt \
	wsug_src/editcap-F.txt \
	wsug_src/editcap-T.txt \
	wsug_src/editcap-h.txt \
	wsug_src/mergecap-h.txt \
	wsug_src/rawshark-h.txt \
	wsug_src/reordercap-h.txt \
	wsug_src/text2pcap-h.txt \
	wsug_src/tshark-h.txt

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
	wsug_graphics/ws-capture-options-output.png			\
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

COMMON_FILES = \
	common_src/GPL_appendix.asciidoc	\
	common_src/typographic_conventions.asciidoc

COMMON_GRAPHICS = \
	common_graphics/note.svg	\
	common_graphics/tip.svg		\
	common_graphics/warning.svg

# user-guide.xml must be first in the list (to match $<)
WSUG_DIST =	\
	user-guide.asciidoc	\
	attributes.asciidoc	\
	custom_layer_chm.xsl	\
	custom_layer_single_html.xsl	\
	$(WSUG_FILES)		\
	$(WSUG_TOOLS_HELP_FILES)	\
	$(WSUG_GRAPHICS)	\
	$(COMMON_FILES)		\
	$(COMMON_GRAPHICS)

WSUG_SOURCE = $(WSUG_GENERATED_SOURCE) $(WSUG_DIST)

# developer-guide.asciidoc must be first in the list (to match $<)
WSDG_DIST =	\
	developer-guide.asciidoc	\
	attributes.asciidoc	\
	custom_layer_chm.xsl	\
	custom_layer_single_html.xsl	\
	$(WSDG_FILES)		\
	$(WSDG_GRAPHICS)	\
	$(COMMON_FILES)		\
	$(COMMON_GRAPHICS)

WSDG_SOURCE = $(WSDG_GENERATED_SOURCE) $(WSDG_DIST)

RELEASE_NOTES_SOURCE = \
	release-notes.asciidoc

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

WSDG_XSLTPROC_ARGS = \
	--stringparam admon.graphics.path wsdg_graphics/

SINGLE_XSLTPROC_ARGS = \
	--nonet custom_layer_single_html.xsl

CHUNKED_XSLTPROC_ARGS = \
	--stringparam chunker.output.encoding UTF-8 \
	--nonet http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl

HTMLHELP_XSLTPROC_ARGS = \
	--nonet custom_layer_chm.xsl
#	--nonet http://docbook.sourceforge.net/release/xsl/current/htmlhelp/htmlhelp.xsl

ASCIIDOCTOR_COMMON_ARGS = \
	--require $(srcdir)/asciidoctor-macros/commaize-block.rb \
	--require $(srcdir)/asciidoctor-macros/cve_idlink-inline-macro.rb \
	--require $(srcdir)/asciidoctor-macros/ws_buglink-inline-macro.rb \
	--require $(srcdir)/asciidoctor-macros/ws_salink-inline-macro.rb

ASCIIDOCTOR_COMMON_COMMAND = TZ=UTC ASCIIDOCTORJ_OPTS="-Xmx800m ${ASCIIDOCTORJ_OPTS}" \
	$(ASCIIDOCTOR) \
	$(ASCIIDOCTOR_COMMON_ARGS)

.asciidoc.pdf:
	$(ASCIIDOCTOR_COMMON_COMMAND) --backend pdf --out-file $@ $<

.asciidoc.xml:
	$(ASCIIDOCTOR_COMMON_COMMAND) --backend docbook --out-file $@ $<

docbook_all_local_targets =
if BUILD_USER_GUIDE
docbook_all_local_targets += wsug_html_chunked

all-local: $(docbook_all_local_targets)

all-html: wsug wsdg release_notes

all-pdf: wsug_pdf wsdg_pdf

# Wireshark User Guide
wsug: wsug_html_chunked wsug_html

wsug_pdf: wsug user-guide.pdf

user-guide.xml: user-guide.asciidoc $(WSUG_FILES)

user-guide.pdf: user-guide.asciidoc $(WSUG_FILES)
endif

# create html single page file
if BUILD_USER_GUIDE
wsug_html: wsug_html/index.html
endif

wsug_html/index.html: user-guide.xml
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
if BUILD_USER_GUIDE
wsug_html_chunked: wsug_html_chunked/index.html
endif

wsug_html_chunked/index.html: user-guide.xml
	@ echo --- WSUG - HTML CHUNKED ---
	mkdir -p wsug_html_chunked/wsug_graphics/toolbar
	cp $(srcdir)/wsug_graphics/*.* wsug_html_chunked/wsug_graphics
	cp $(srcdir)/common_graphics/*.* wsug_html_chunked/wsug_graphics
	cp $(srcdir)/wsug_graphics/toolbar/* wsug_html_chunked/wsug_graphics/toolbar
	cp $(srcdir)/ws.css wsug_html_chunked
	$(XSLTPROC) --stringparam base.dir wsug_html_chunked/ $(COMMON_XSLTPROC_ARGS) \
		    $(WSUG_XSLTPROC_ARGS) $(CHUNKED_XSLTPROC_ARGS) $<
	-chmod -R og+rX wsug_html_chunked

wsluarm: make-wsluarm.pl $(WSLUA_MODULES)
	mkdir -p wsluarm_src
	$(PERL) $(srcdir)/make-wsluarm.pl $(WSLUA_MODULES)
	touch wsluarm


# Wireshark Developer Guide
wsdg: wsdg_html_chunked wsdg_html

if BUILD_USER_GUIDE
wsdg_pdf: developer-guide.pdf
endif

developer-guide.xml: developer-guide.asciidoc $(WSDG_FILES) wsluarm

developer-guide.pdf: developer-guide.asciidoc $(WSDG_FILES) wsluarm

# create html single page file
if BUILD_USER_GUIDE
wsdg_html: wsdg_html/index.html
endif

wsdg_html/index.html: developer-guide.xml
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
if BUILD_USER_GUIDE
wsdg_html_chunked: developer-guide.xml wsdg_html_chunked/index.html
endif

wsdg_html_chunked/index.html: developer-guide.xml
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

# Release notes
if HAVE_ASCIIDOCTOR
release_note_deps = release-notes.html
release_note_deps += release-notes.txt
endif
release_notes: $(release_note_deps)

# create html single page file
release-notes.html: $(RELEASE_NOTES_SOURCE)
	@ echo --- RELEASE NOTES - HTML ---
	$(ASCIIDOCTOR_COMMON_COMMAND) \
		--backend html \
		--out-file $(builddir)/release-notes.html \
		$(srcdir)/release-notes.asciidoc

# create txt single page file (through HTML)
release-notes.txt: release-notes.html
	@ echo --- RELEASE NOTES - TXT ---
	$(PYTHON) $(srcdir)/tools/html2text.py \
		$(builddir)/release-notes.html \
		> $(builddir)/release-notes.txt

news: release-notes.txt
	cp release-notes.txt ../NEWS
	-cp release-notes.txt $(top_srcdir)/NEWS

install-data-local:
if BUILD_USER_GUIDE
	$(MKDIR_P) $(DESTDIR)$(docdir)/guides
	cp -rf $(builddir)/wsug_html_chunked $(DESTDIR)$(docdir)/guides
endif

uninstall-local:
	rm -rf $(DESTDIR)$(docdir)

clean-local:
	-rm -rf $(CLEANDIRS)

EXTRA_DIST = \
	$(WSUG_DIST)		\
	$(WSDG_DIST)		\
	asciidoctor-macros	\
	$(RELEASE_NOTES_SOURCE)	\
	make-wsluarm.pl		\
	README.adoc		\
	CMakeLists.txt
