struct ngsniffer_hdr {
	guint32	junk1;
	guint32	junk2;
	guint32	junk3;
	guint16	bytes;
	guint16	junk4;
	guint32	junk5;
};


int ngsniffer_read(wtap *wth);
