#include "packet-lua.h"

LUA_CLASS_DEFINE(Tree,TREE,NOP);
LUA_CLASS_DEFINE(Item,ITEM,NOP);

/* Tree class */

static int Tree_add_item_any(lua_State *L, gboolean little_endian) {
    /*
     called with:
     tree,field,tvb,offset,len,datum
     tree,field,tvb,offset,len
     tree,tvb,offset,len,text
     tree,tvb,text
     */
    Tree tree = checkTree(L,1);
    ProtoField field;
    Item item;
    Tvb tvb;
    int offset;
    int len;
    
    if (!tree) {
        pushItem(L,NULL);
        return 1;
    }
    
    if (( luaL_checkudata (L, 2, TVB) )) {
        tvb = checkTvb(L,2);
        const char* str;
        
        if (lua_isnumber(L,3)) {
            offset = luaL_checkint(L,3);
            len = luaL_checkint(L,4);
            str = lua_tostring(L,5);
        } else if (lua_isstring(L,3)) {
            offset = 0;
            len = 0;
            str = lua_tostring(L,3);
        } else {
            luaL_error(L,"First arg must be either TVB or ProtoField");
            return 0;
        }
        
        item = proto_tree_add_text(tree,tvb,offset,len,"%s",str);
        
    } else if (( luaL_checkudata (L, 2, PROTO_FIELD) )) {
        field = checkProtoField(L,2);
        tvb = checkTvb(L,3);
        offset = luaL_checkint(L,4);
        len = luaL_checkint(L,5);
        
        if ( lua_gettop(L) == 6 ) {
            switch(field->type) {
                case FT_UINT8:
                case FT_UINT16:
                case FT_UINT24:
                case FT_UINT32:
                case FT_FRAMENUM:
                    item = proto_tree_add_uint(tree,field->hfid,tvb,offset,len,(guint32)luaL_checknumber(L,6));
                    break;
                case FT_INT8:
                case FT_INT16:
                case FT_INT24:
                case FT_INT32:
                    item = proto_tree_add_int(tree,field->hfid,tvb,offset,len,(gint32)luaL_checknumber(L,6));
                    break;
                case FT_FLOAT:
                    item = proto_tree_add_float(tree,field->hfid,tvb,offset,len,(float)luaL_checknumber(L,6));
                    break;
                case FT_DOUBLE:
                    item = proto_tree_add_double(tree,field->hfid,tvb,offset,len,(double)luaL_checknumber(L,6));
                    break;
                case FT_STRING:
                case FT_STRINGZ:
                    item = proto_tree_add_string(tree,field->hfid,tvb,offset,len,luaL_checkstring(L,6));
                    break;
                case FT_UINT64:
                case FT_INT64:
                case FT_ETHER:
                case FT_BYTES:
                case FT_UINT_BYTES:
                case FT_IPv4:
                case FT_IPv6:
                case FT_IPXNET:
                case FT_GUID:
                case FT_OID:
                default:
                    luaL_error(L,"FT_ not yet supported");
                    return 0;
            }
        } else {
            item = proto_tree_add_item(tree,field->hfid,tvb,offset,len,little_endian);
        }
    } else {
        luaL_error(L,"First arg must be either TVB or ProtoField");
        return 0;
    }
    
    pushItem(L,item);
    return 1;
}

static int Tree_add_item(lua_State *L) { return Tree_add_item_any(L,FALSE); }
static int Tree_add_item_le(lua_State *L) { return Tree_add_item_any(L,TRUE); }

static int Tree_tostring(lua_State *L) {
    Tree tree = checkTree(L,1);
    lua_pushstring(L,ep_strdup_printf("Tree %p",tree));
    return 1;
}


static int Tree_get_parent(lua_State *L) {
    Tree tree = checkTree(L,1);
    proto_item* item = NULL;
    
    if (tree) {
        item = proto_tree_get_parent(tree);
    }
    
    pushItem(L,item);
    
    return 1;
}

static const luaL_reg Tree_methods[] = {
    {"add_item",       Tree_add_item},
    {"add_item_le",       Tree_add_item_le},
    {"get_parent",       Tree_get_parent},
    {0, 0}
};

static const luaL_reg Tree_meta[] = {
    {"__tostring", Tree_tostring},
    {0, 0}
};

int Tree_register(lua_State* L) {
    luaL_openlib(L, TREE, Tree_methods, 0);
    luaL_newmetatable(L, TREE);
    luaL_openlib(L, 0, Tree_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
}

/* Item class */
static int Item_tostring(lua_State *L) {
    Item item = checkItem(L,1);
    lua_pushstring(L,ep_strdup_printf("Item %p",item));
    return 1;
}

static int Item_add_subtree(lua_State *L) {
    Item item = checkItem(L,1);
    Ett ett;
    Tree tree = NULL;
    
    if (item) {
        ett = checkEtt(L,2);
        
        if (ett && *ett >= 0) {
            tree = proto_item_add_subtree(item,*ett);
        } else {
            luaL_argerror(L,2,"bad ett");
        }
    }
    
    pushTree(L,tree);
    return 1;
}

static int Item_set_text(lua_State *L) {
    Item item = checkItem(L,1);
    
    if (!item) {
        const gchar* s = luaL_checkstring(L,2);
        proto_item_set_text(item,"%s",s);
    }
    
    return 0;
}

static int Item_append_text(lua_State *L) {
    Item item = checkItem(L,1);
    const gchar* s;
    
    if (item) {
        s = luaL_checkstring(L,2);
        proto_item_append_text(item,"%s",s);
    }
    return 0;
}

static int Item_set_len(lua_State *L) {
    Item item = checkItem(L,1);
    int len;

    if (item) {
        len = luaL_checkint(L,2);
        proto_item_set_len(item,len);
    }
    
    return 0;
}

struct _expert_severity {
    const gchar* str;
    int val;
};

static const struct _expert_severity severities[] = {
    {"PI_CHAT",PI_CHAT},
    {"PI_NOTE",PI_NOTE},
    {"PI_WARN",PI_WARN},
    {"PI_ERROR",PI_ERROR},
    {"PI_CHECKSUM",PI_CHECKSUM},
    {"PI_SEQUENCE",PI_SEQUENCE},
    {"PI_RESPONSE_CODE",PI_RESPONSE_CODE},
    {"PI_UNDECODED",PI_UNDECODED},
    {"PI_REASSEMBLE",PI_REASSEMBLE},
    {"PI_MALFORMED",PI_MALFORMED},
    {"PI_DEBUG",PI_DEBUG},
    {NULL,0}
};

static int str_to_expert(const gchar* str) {
    const struct _expert_severity* s;

    if (!str) return 0;
    
    for(s = severities; s->str; s++) {
        if (g_str_equal(str,s->str)) {
            return s->val;
        }
    }
    return 0;
}

#if 0
static const gchar* expert_to_str(int val) {
    const struct _expert_severity* s;
    for(s = severities; s->str; s++) {
        if (s->val == val) {
            return s->str;
        }
    }
    return NULL;
}
#endif

static int Item_set_expert_flags(lua_State *L) {
    Item item = checkItem(L,1);
    int group;
    int severity;

    if (item) {
        group = str_to_expert(luaL_checkstring(L,2));
        severity = str_to_expert(luaL_checkstring(L,3));

        if (group && severity) {
            proto_item_set_expert_flags(item,group,severity);
        }
    }

    return 0;
}


static int Item_set_generated(lua_State *L) {
    Item item = checkItem(L,1);
    if (item) {
        PROTO_ITEM_SET_GENERATED(item);
    }
    return 0;
}


static int Item_set_hidden(lua_State *L) {
    Item item = checkItem(L,1);
    if (item) {
        PROTO_ITEM_SET_HIDDEN(item);
    }
    return 0;
}

static const luaL_reg Item_methods[] = {
    {"add_subtree",       Item_add_subtree},
    {"set_text",       Item_set_text},
    {"append_text",       Item_append_text},
    {"set_len",       Item_set_len},
    {"set_expert_flags",       Item_set_expert_flags},
    {"set_generated",       Item_set_generated},
    {"set_hidden",       Item_set_hidden},
    {0, 0}
};

static const luaL_reg Item_meta[] = {
    {"__tostring", Item_tostring},
    {0, 0}
};



int Item_register(lua_State *L) {
   const struct _expert_severity* s;
    
    luaL_openlib(L, ITEM, Item_methods, 0);
    luaL_newmetatable(L, ITEM);
    luaL_openlib(L, 0, Item_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    for(s = severities; s->str; s++) {
        lua_pushstring(L, s->str);
        lua_pushstring(L, s->str);
        lua_settable(L, LUA_GLOBALSINDEX);
    }
    
    return 1;
}
