
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ftypes-int.h>
#include "ipv4.h"
#include "resolv.h"

static void
ftype_from_tvbuff(field_info *fi, tvbuff_t *tvb, int start, int length,
	gboolean little_endian)
{
	/* XXX */
	g_assert_not_reached();
}



static void
set_integer(fvalue_t *fv, guint32 value)
{
	ipv4_addr_set_net_order_addr(&(fv->value.ipv4), value);
	ipv4_addr_set_netmask_bits(&(fv->value.ipv4), 32);
}

static gpointer
value_get(fvalue_t *fv)
{
	return &(fv->value.ipv4);
}

static gboolean
val_from_string(fvalue_t *fv, char *s, LogFunc log)
{
	guint32	addr;

	if (!get_host_ipaddr(s, &addr)) {
		log("\"%s\" is not a valid hostname or IPv4 address.", s);
		return FALSE;
	}
	ipv4_addr_set_host_order_addr(&(fv->value.ipv4), addr);
        /*ipv4_addr_set_netmask_bits(&node->value.ipv4, nmask_bits);*/
	ipv4_addr_set_netmask_bits(&(fv->value.ipv4), 32);
	return TRUE;
}

static gboolean
cmp_eq(fvalue_t *a, fvalue_t *b)
{
	return ipv4_addr_eq(&a->value.ipv4, &b->value.ipv4);
}

static gboolean
cmp_ne(fvalue_t *a, fvalue_t *b)
{
	return ipv4_addr_ne(&a->value.ipv4, &b->value.ipv4);
}

static gboolean
cmp_gt(fvalue_t *a, fvalue_t *b)
{
	return ipv4_addr_gt(&a->value.ipv4, &b->value.ipv4);
}

static gboolean
cmp_ge(fvalue_t *a, fvalue_t *b)
{
	return ipv4_addr_ge(&a->value.ipv4, &b->value.ipv4);
}

static gboolean
cmp_lt(fvalue_t *a, fvalue_t *b)
{
	return ipv4_addr_lt(&a->value.ipv4, &b->value.ipv4);
}

static gboolean
cmp_le(fvalue_t *a, fvalue_t *b)
{
	return ipv4_addr_le(&a->value.ipv4, &b->value.ipv4);
}

void
ftype_register_ipv4(void)
{

	static ftype_t ipv4_type = {
		"FT_IPv4",
		"IPv4 address",
		4,
		NULL,
		NULL,
		ftype_from_tvbuff,
		val_from_string,

		NULL,
		set_integer,
		NULL,

		value_get,
		NULL,
		NULL,

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
	};

	ftype_register(FT_IPv4, &ipv4_type);
}
