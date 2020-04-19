#ifndef WIRESHARK_MARINE_H


#define WIRESHARK_MARINE_H

#include <glib.h>

typedef struct {
    char *output;
    int result;
} marine_result;

int init_marine(void);
void set_epan_auto_reset_count(guint32 auto_reset_count);
marine_result *marine_dissect_packet(int filter_id, unsigned char *data, int len);
int marine_add_filter(char *bpf, char *dfilter, char **fields, int fields_len, char **err_msg);
void marine_free(marine_result *ptr);
void destroy_marine(void);

#endif //WIRESHARK_MARINE_H
