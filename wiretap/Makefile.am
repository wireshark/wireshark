bin_PROGRAMS = wiretap filterc
noinst_LIBRARIES = @LIBWIRETAP_A@

EXTRA_LIBRARIES = libwiretap.a

EXTRA_DIST = \
	rt-grammar-skel.y	\
	rt-scanner-skel.l	\
	ct-grammar.y		\
	ct-scanner.l		\
	filter-eth		\
	filter-tr

CLEANFILES = \
	libwiretap.a		\
	filterc 		\
	*~ 			\
	ct-grammar.c		\
	ct-scanner.c		\
	ct-grammar.h		\
	rt-grammar.c		\
	rt-grammar.y		\
	rt-scanner.c		\
	rt-scanner.l		\
	rt-grammar.h

libwiretap_a_SOURCES = \
	bpf.h			\
	bpf.c			\
	bpf-engine.c		\
	bpf-engine.h		\
	buffer.c		\
	buffer.h		\
	config.h		\
	file.c			\
	iptrace.c		\
	iptrace.h		\
	lanalyzer.c		\
	lanalyzer.h		\
	libpcap.c		\
	libpcap.h		\
	netmon.c		\
	netmon.h		\
	netxray.c		\
	netxray.h		\
	ngsniffer.c		\
	ngsniffer.h		\
	rt-compile.h		\
	rt-compile.c		\
	rt-global.h		\
	rt-grammar.h		\
	rt-grammar.y		\
	rt-scanner.l		\
	snoop.c			\
	snoop.h			\
	wtap.c			\
	wtap.h


filterc_SOURCES = \
	ct-compile.c		\
	ct-compile.h		\
	ct-grammar.h		\
	ct-grammar.y		\
	ct-scanner.l		\
	ct-main.c		\
	glib-new.h		\
	glib-new.c

#BUILT_SOURCES = \
#	rt-grammar.h		\
#	rt-grammar.y		\
#	rt-scanner.l

FILTERS = \
	filter-eth		\
	filter-tr

YFLAGS=-d -p wtap_
LFLAGS=-i -Pwtap_

#ct-tokdefs.h ct-grammar.c : ct-grammar.y
#	@rm -f $@ ct-tokdefs.h
#	$(CT_YACC) -d $<
#	mv y.tab.c ct-grammar.c
#	mv y.tab.h ct-tokdefs.h

ct-scanner.c : ct-scanner.l
	@rm -f $@
	$(LEX) $(LFLAGS) -t $< > $@

rt-scanner.l : rt-scanner-skel.l filterc $(FILTERS)
	cat $(FILTERS) | ./filterc > /dev/null

rt-scanner.c : rt-scanner.l rt-grammar.c
	@rm -f $@
	$(LEX) $(LFLAGS) -t $< > $@

rt-grammar.y : rt-grammar-skel.y filterc $(FILTERS)
	cat $(FILTERS) | ./filterc > /dev/null

#rt-tokdefs.h rt-grammar.c : rt-grammar.y
#	@rm -f $@ rt-tokdefs.h
#	$(RT_YACC) -d $<
#	mv y.tab.c rt-grammar.c
#	mv y.tab.h rt-tokdefs.h

wiretap_SOURCES = \
	wiretap.c 		\
	glib-new.c

wiretap_LDADD = libwiretap.a
