#ifndef WIRESHARK_MARINE_H


#define WIRESHARK_MARINE_H

#include <glib.h>
#define ARRAY_SIZE(arr)     (sizeof(arr) / sizeof((arr)[0]))

typedef struct {
    char *output;
    int result;
} marine_result;

int init_marine(void);
void set_epan_auto_reset_count(guint32 auto_reset_count);
marine_result *marine_dissect_packet(int filter_id, unsigned char *data, int len);
int marine_add_filter(char *bpf, char *dfilter, char **fields, int* macro_indices, unsigned int fields_len, int wtap_encap, char **err_msg);
void marine_free_err_msg(char *ptr);
void marine_free(marine_result *ptr);
void destroy_marine(void);

extern const unsigned int ETHERNET_ENCAP;
extern const unsigned int WIFI_ENCAP;
extern const int MARINE_ALREADY_INITIALIZED_ERROR_CODE;
extern const int MARINE_INIT_INTERNAL_ERROR_CODE;


extern const int BAD_BPF_ERROR_CODE;
extern const int BAD_DISPLAY_FILTER_ERROR_CODE;
extern const int INVALID_FIELD_ERROR_CODE;

#endif //WIRESHARK_MARINE_H
