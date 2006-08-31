## Makefile for building codecs.lib with Microsoft C and nmake
## Use: $(MAKE) /$(MAKEFLAGS) -f makefile.nmake
#
# $Id$

include ..\..\config.nmake

############### no need to modify below this line #########

CFLAGS=-DHAVE_CONFIG_H /I.. /I../wiretap $(GTK_CFLAGS) $(GLIB_CFLAGS) \
	/I$(PCAP_DIR)\WPCAP\LIBPCAP /I$(PCAP_DIR)\WPCAP\LIBPCAP\bpf \
	/I$(PCAP_DIR)\WPCAP\LIBPCAP\lbl \
	/I$(PCAP_DIR)\include /I$(NET_SNMP_DIR)\include \
	/I$(NET_SNMP_DIR)\win32 /Zm800 -D_U_="" -D_NEED_VAR_IMPORT_ $(LOCAL_CFLAGS)

.c.obj::
	$(CC) $(CFLAGS)  -Fd.\ -c $<

CODEC_OBJECTS= \
        G711udecode.obj \
	G711adecode.obj


codecs.lib	:  $(CODEC_OBJECTS) 
	link /lib /out:codecs.lib $(CODEC_OBJECTS) 


G711adecode.obj: G711a\G711adecode.c G711a\G711adecode.h G711a\G711atable.h
        $(CC) $(CFLAGS) -c /Zi /W1 /Od G711a\G711adecode.c -o $@

G711udecode.obj: G711u\G711udecode.c G711u\G711udecode.h G711u\G711utable.h
        $(CC) $(CFLAGS) -c /Zi /W1 /Od G711u\G711udecode.c -o $@

clean:
        rm -f $(CODEC_OBJECTS) codecs.lib *.pdb

distclean: clean

maintainer-clean: distclean

