bin_PROGRAMS = wiretap
noinst_LIBRARIES = @LIBWIRETAP_A@

EXTRA_PROGRAMS = filterc
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

FILTERS = \
	filter-eth		\
	filter-tr

YFLAGS=-d -p wtap_
LFLAGS=-i -Pwtap_

ct-scanner.c : ct-scanner.l
	@rm -f $@
	$(LEX) $(LFLAGS) -t $< > $@

rt-grammar.y rt-scanner.l : rt-grammar-skel.y rt-scanner-skel.l $(FILTERS)
	$(MAKE) filterc
	cat $(FILTERS) | ./filterc > /dev/null

rt-scanner.c : rt-scanner.l rt-grammar.c
	@rm -f $@
	$(LEX) $(LFLAGS) -t $< > $@

wiretap_SOURCES = \
	wiretap.c 		\
	glib-new.c

wiretap_LDADD = libwiretap.a
