#include "wtap.h"
#include "ngsniffer.h"

int ngsniffer_read(wtap *wth)
{
	struct ngsniffer_hdr frame_hdr;
	int	bytes_read, packet_size;

	bytes_read = fread(&frame_hdr, 1, sizeof(struct ngsniffer_hdr), wth->fh);

	if (bytes_read == sizeof(struct ngsniffer_hdr)) {
		wth->frame_number++;
		packet_size = frame_hdr.bytes;
		buffer_assure_space(&wth->frame_buffer, packet_size);

		bytes_read = fread(buffer_start_ptr(&wth->frame_buffer), 1,
						frame_hdr.bytes, wth->fh);

		if (bytes_read != packet_size) {
			g_error("no good fread for data: %d bytes out of %d read\n",
				bytes_read, packet_size);
			return 0;
		}

		wth->file_byte_offset += sizeof(struct ngsniffer_hdr) + packet_size;

		wth->phdr.ts.tv_sec = 0;
		wth->phdr.ts.tv_usec = 0;
		wth->phdr.caplen = packet_size;
		wth->phdr.len = packet_size;

		return 1;
	}

	return 0;
}
