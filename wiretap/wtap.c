#include "wtap.h"
#include "ngsniffer.h"

static
void pcap_callback_wrapper(u_char *user, const struct pcap_pkthdr *phdr,
		const u_char *buf);

wtap_handler wtap_callback = NULL;

FILE* wtap_file(wtap *wth)
{
	if (wth->file_type == WTAP_FILE_PCAP) {
		return pcap_file(wth->pcap);
	}
	else
		return wth->fh;
}

int wtap_file_type(wtap *wth)
{
	return wth->file_type;
}

int wtap_encapsulation(wtap *wth)
{
	return wth->encapsulation;
}


int wtap_snapshot_length(wtap *wth)
{
	if (wth->file_type == WTAP_FILE_PCAP)
		return pcap_snapshot(wth->pcap);
	else
		return 5000;
}

void wtap_close(wtap *wth)
{
	if (wth->file_type == WTAP_FILE_PCAP)
		pcap_close(wth->pcap);
	else
		fclose(wth->fh);
}

void wtap_loop(wtap *wth, int count, wtap_handler callback, u_char* user)
{
	int i = 0;

	if (wth->file_type == WTAP_FILE_PCAP) {
		wtap_callback = callback;
		pcap_loop(wth->pcap, count, pcap_callback_wrapper, user);
	}
	else {
		while (ngsniffer_read(wth)) {
			i++;
			callback(user, &wth->phdr, buffer_start_ptr(&wth->frame_buffer));
		}
	}
}

static
void pcap_callback_wrapper(u_char *user, const struct pcap_pkthdr *phdr,
		const u_char *buf)
{
/*	struct wtap_pkthdr whdr;
	memcpy(&whdr, phdr, sizeof(struct wtap_pkthdr));*/
	wtap_callback(user, (struct wtap_pkthdr*) phdr, buf);
}
