
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http-parser.h"
#include <gmodule.h>

static const value_string http_response_codes[] = {
{ 200, "OK" },
{ 302, "Later" },
{0,NULL}
};

static gint ett_http = -1;
static int proto_http = -1;

static tvbparse_wanted_t* rule_http_crlf; 
static tvbparse_wanted_t* rule_http_header;
static tvbparse_wanted_t* rule_http_req_resp;

static dissector_handle_t http_handle;

static void dissect_http(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree) {
    http_info_value_t* msgdata = ep_alloc(sizeof(http_info_value_t));
    tvbparse_elem_t* reqresp;
    tpg_parser_data_t* tpg;
    proto_item* pi = proto_tree_add_item(tree,proto_http,tvb,0,-1,FALSE);
    proto_tree* pt = proto_item_add_subtree(pi,ett_http);
    
    tpg = tpg_start(pt,tvb,0,-1,msgdata);
    
    if (( reqresp = TPG_GET(tpg,rule_http_req_resp) )) {
        tvbparse_elem_t* hdr;
        
        while(( hdr = TPG_GET(tpg,rule_http_header) )) ;
        
        if ( TPG_GET(tpg,rule_http_crlf) ) {
            return;
        }
        
    } else {
        return;
    }
}

static void proto_register_http(void) {
    static hf_register_info hf[] = {
        HF_HTTP_PARSER
    };
    
    static gint *ett[] = {
        ETT_HTTP_PARSER,
        &ett_http
	};
    
    tpg_http_init();
    
    proto_http = proto_register_protocol("HyTeTrP",
                                         "HyTeTrP", "hytetrpr");
	proto_register_field_array(proto_http, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
    
    rule_http_crlf = wanted_http_crlf();
    rule_http_header = wanted_http_header();
    rule_http_req_resp =  wanted_http_req_resp();
        
}


static void proto_reg_handoff_http(void) {
    http_handle = create_dissector_handle(dissect_http, proto_http);

    dissector_delete("tcp.port", 80, NULL);
    dissector_add("tcp.port", 80, http_handle);

}

#ifndef ENABLE_STATIC

G_MODULE_EXPORT const gchar version[] = "0.0.0";

G_MODULE_EXPORT void
plugin_register(void)
{
	/* register the new protocol, protocol fields, and subtrees */
	if (proto_http == -1) { /* execute protocol initialization only once */
		proto_register_http();
	}
}

G_MODULE_EXPORT void
plugin_reg_handoff(void){
	proto_reg_handoff_http();
}

#endif

