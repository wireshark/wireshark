
#include <stdio.h>
#include <string.h>
#include "wtap.h"

/* The open_file_* routines should return the WTAP_FILE_* type
 * that they are checking for if the file is successfully recognized
 * as such. If the file is not of that type, the routine should return
 * WTAP_FILE_UNKNOWN */
static int open_file_pcap(wtap *wth, char *filename);
static int open_file_ngsniffer(wtap *wth);
static int open_file_lanalyzer(wtap *wth);
static int convert_dlt_to_wtap_encap(int dlt);

/* Opens a file and prepares a wtap struct */
wtap* wtap_open_offline(char *filename, int filetype)
{
	wtap	*wth;

	wth = (wtap*)malloc(sizeof(wtap));

	/* Open the file */
	if (!(wth->fh = fopen(filename, "rb"))) {
		return NULL;
	}

	/* If the filetype is unknown, try all my file types */
	if (filetype == WTAP_FILE_UNKNOWN) {
		/* WTAP_FILE_PCAP */
		if (wth->file_type = open_file_pcap(wth, filename)) {
			goto success;
		}
		/* WTAP_FILE_NGSNIFFER */
		if (wth->file_type = open_file_ngsniffer(wth)) {
			goto success;
		}
		/* WTAP_FILE_LANALYZER */
		if (wth->file_type = open_file_lanalyzer(wth)) {
			goto success;
		}

		printf("failed\n");
		/* WTAP_FILE_UNKNOWN */
		goto failure;
	}

	/* If the user tells us what the file is supposed to be, check it */
	switch (filetype) {
		case WTAP_FILE_PCAP:
			if (wth->file_type = open_file_pcap(wth, filename)) {
				goto success;
			}
			break;
		case WTAP_FILE_NGSNIFFER:
			if (wth->file_type = open_file_ngsniffer(wth)) {
				goto success;
			}
			break;
		case WTAP_FILE_LANALYZER:
			if (wth->file_type = open_file_lanalyzer(wth)) {
				goto success;
			}
			break;
		default:
			goto failure;
	}

	/* If we made it through the switch() statement w/o going to "success",
	 * then we failed. */
	goto failure;

failure:
	fclose(wth->fh);
	free(wth);
	wth = NULL;
	return wth;

success:
	buffer_init(&wth->frame_buffer, 1500);
	wth->frame_number = 0;
	wth->file_byte_offset = 0;
	return wth;
}


/* libpcap/tcpdump files */
static
int open_file_pcap(wtap *wth, char *filename)
{
	int bytes_read, dlt;
	struct pcap_file_header	file_hdr;

	fseek(wth->fh, 0, SEEK_SET);
	bytes_read = fread((char*)&file_hdr, 1,
			sizeof(struct pcap_file_header), wth->fh);

	if (bytes_read != sizeof(struct pcap_file_header)) {
		return WTAP_FILE_UNKNOWN;
	}

	if (file_hdr.magic != 0xa1b2c3d4) {
		return WTAP_FILE_UNKNOWN;
	}

	/* This is a pcap file */
	wth->pcap = pcap_open_offline(filename, wth->err_str);
	dlt = pcap_datalink(wth->pcap);
	wth->encapsulation =  convert_dlt_to_wtap_encap(dlt);

	/* For most file types I don't fclose my handle, but for pcap I'm
	 * letting libpcap handle the file, so I don't need an open file
	 * handle. Libpcap already has the file open with the above
	 * pcap_open_offline() */
	fclose(wth->fh);

	return WTAP_FILE_PCAP;
}

/* Network General Sniffer (c) */
static
int open_file_ngsniffer(wtap *wth)
{
	int bytes_read;
	char magic[33];

	fseek(wth->fh, 0, SEEK_SET);
	bytes_read = fread(magic, 1, 32, wth->fh);

	if (bytes_read != 32) {
		return WTAP_FILE_UNKNOWN;
	}

	magic[16] = 0;

	if (strcmp(magic, "TRSNIFF data    ")) {
		return WTAP_FILE_UNKNOWN;
	}

	/* This is a ngsniffer file */
	wth->frame_number = 0;
	wth->file_byte_offset = 0x10b;

	/* I think this is link type */
	if (magic[30] == 0x25) {
		wth->encapsulation = WTAP_ENCAP_ETHERNET;
	}
	else if (magic[30] == 0x24) {
		wth->encapsulation = WTAP_ENCAP_TR;
	}
	else {
		g_error("The magic byte that I think tells DLT is 0x%02X\n", magic[30]);
		exit(-1);
	}

	if (fseek(wth->fh, 0x10b, SEEK_SET) < 0) {
		return WTAP_FILE_UNKNOWN; /* I should exit(-1) here */
	}
	return WTAP_FILE_NGSNIFFER;
}

/* Novell's LANAlyzer (c). */
static
int open_file_lanalyzer(wtap *wth)
{
	int bytes_read;
	char magic[2];

	fseek(wth->fh, 0, SEEK_SET);
	bytes_read = fread(magic, 1, 2, wth->fh);

	if (bytes_read != 2) {
		return WTAP_FILE_UNKNOWN;
	}

	if (pletohs(magic) != 0x1001 && pletohs(magic) != 0x1007) {
		return WTAP_FILE_UNKNOWN;
	}

/*	return WTAP_FILE_LANALYZER; until I work on it some more */
	return WTAP_FILE_UNKNOWN;
}

static
int convert_dlt_to_wtap_encap(dlt)
{
	int encap[] = {
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_ETHERNET,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_TR,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_SLIP,
		WTAP_ENCAP_PPP,
		WTAP_ENCAP_FDDI,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_RAW_IP,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_NONE
	};

	return encap[dlt];
}

