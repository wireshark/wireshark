typedef struct _e_ipv6_header{
    /* the version contains 4-bit version and 4-bit priority */
    guint8 	version;
    guint8 	flow_label[3];
    guint16 	payload_length;
    guint8	next_header;
    guint8	hop_limit;
} e_ipv6_header;
