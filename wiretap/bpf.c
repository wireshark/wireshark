/*
 * bpf.c
 * -----
 * Creates and handles the BPF code produced by wiretap.
 *
 * Gilbert Ramirez
 */

#ifndef __G_LIB_H__
#include <glib.h>
#endif

#include <netinet/in.h>

#include "wtap.h"
#include "rt-compile.h"
#include "rt-global.h"
#include "bpf-engine.h"
#include "bpf.h"


static GList *bpf_code_just_parsed = NULL;
static struct bpf_instruction *bpf_record = NULL;

static int
bpf_clean_jump(GList *L, int i_this, int jmp, int num_bpf_instructions,
		int i_ret_success, int i_ret_failure);
static void
bpf_pass1(GList *L);

static GList*
bpf_mk_bytecmp(int ftype, int rel_opcode, guint8 *bytes);

static void
bpf_optimize(GList *L);

static int
bpf_attach(wtap *wth);

static void
bpf_attach_record(gpointer bpf_code, gpointer junk);

static int
offline_attach(wtap *wth);


/* sets function pointers in rt-grammar.y to point to the BPF-related
 * functions */
void
wtap_filter_bpf_init(void)
{
	mk_bytecmp = bpf_mk_bytecmp;
	mk_optimize = bpf_optimize;
	mk_attach = bpf_attach;
}

/* almost the same as bpf_init... */
void
wtap_filter_offline_init(wtap *wth)
{
	int fi; /* filter index */

	mk_bytecmp = bpf_mk_bytecmp;
	mk_optimize = bpf_optimize;
	mk_attach = offline_attach;

	wtap_filter_offline_clear(wth);

	/* make the offline filter array */
	wth->filter.offline = g_malloc(sizeof(int*) * WTAP_NUM_ENCAP_TYPES);
	wth->filter_type = WTAP_FILTER_OFFLINE;
	wth->offline_filter_lengths = g_malloc(sizeof(int) * WTAP_NUM_ENCAP_TYPES);

	for (fi = 0; fi < WTAP_NUM_ENCAP_TYPES; fi++) {
		wth->filter.offline[fi] = NULL;
	}
}

/* Removes an offline filter from a wtap struct, and frees memory used
 * by that filter */
void
wtap_filter_offline_clear(wtap *wth)
{
	int fi; /* filter index */

	if (wth->filter.offline) {
		for (fi = 0; fi < WTAP_NUM_ENCAP_TYPES; fi++) {
			if (wth->filter.offline[fi])
				g_free(wth->filter.offline[fi]);
		}
		g_free(wth->filter.offline);
		g_free(wth->offline_filter_lengths);
	}
	wth->filter_type = WTAP_FILTER_NONE;
}

/* Allocate a new bpf_code_unit structure and initialize the BPF instruction
 * codes to the values passed by the caller. */
static struct bpf_code_unit *
bpf_code_unit_alloc(guint8 label, guint16 code, guint8 jt, guint8 jf, guint32 k)
{
	struct bpf_code_unit *bpf;

	bpf = g_malloc(sizeof(struct bpf_code_unit));
	bpf->line_label = label;
	bpf->bpf.code = code;
	bpf->bpf.jt = jt;
	bpf->bpf.jf = jf;
	bpf->bpf.k = k;

	/*g_print("{ %d { 0x%02x, %d, %d, 0x%08x }},\n",
			label, code, jt, jf, k);*/
	return bpf;
}


#define phtons(p)  ((guint16)                       \
                    ((guint16)*((guint8 *)p+0)<<8|  \
                     (guint16)*((guint8 *)p+1)<<0))

#define phtonl(p)  ((guint32)*((guint8 *)p+0)<<24|  \
                    (guint32)*((guint8 *)p+1)<<16|  \
                    (guint32)*((guint8 *)p+2)<<8|   \
                    (guint32)*((guint8 *)p+3)<<0)

/* Finds ftype in the bytecmp_table, the relation, and the n-string
byte array, and creates BPF that will check those bytes */
static GList*
bpf_mk_bytecmp(int ftype, int rel_opcode, guint8 *bytes)
{
	GList	*L;
	struct bpf_code_unit *bpf;
	int	len_to_cmp, offset, endpoint, label;
	bytecmp_info *b;

	L = g_list_alloc();

	/* find the field in the table */
	b = lookup_bytecmp(ftype);

	/* How many bytes do we have to compare, and where? */
	len_to_cmp = b->length;
	offset = b->offset;
	endpoint = len_to_cmp + offset;
	/*g_print("len_to_cmp=%d, offset=%d, endpoint=%d\n",
			len_to_cmp, offset, endpoint);
	g_print("bytes: (%d) %02X:%02X:%02X\n",
			bytes[0], bytes[1], bytes[2], bytes[3]);*/

	label = NEXT_BLOCK;
	/* loop until we have written instructions to compare
		all bytes */
	while (len_to_cmp) {

		if (len_to_cmp >= 4) {
			bpf = bpf_code_unit_alloc(label,
					BPF_LD|BPF_W|BPF_ABS,
					0, 0, endpoint - 4);
			g_list_append(L, bpf);
			label = NO_LABEL;

			endpoint -= 4;
			bpf = bpf_code_unit_alloc(NO_LABEL,
					BPF_JMP|BPF_JEQ,
					(len_to_cmp == 4 ? END_OF_PROGRAM_SUCCESS : 0),
					NEXT_BLOCK,
					phtonl(&bytes[len_to_cmp-3]));
			g_list_append(L, bpf);

			len_to_cmp -= 4;
		}
		else if (len_to_cmp == 3) {
			bpf = bpf_code_unit_alloc(label,
					BPF_LD|BPF_W|BPF_ABS,
					0, 0, endpoint - 3);
			g_list_append(L, bpf);
			label = NO_LABEL;
			endpoint -= 3;

			bpf = bpf_code_unit_alloc(NO_LABEL,
					BPF_ALU|BPF_AND,
					0, 0,
					htonl(0xffffff));
			g_list_append(L, bpf);

			bpf = bpf_code_unit_alloc(NO_LABEL,
					BPF_JMP|BPF_JEQ,
					(len_to_cmp == 3 ? END_OF_PROGRAM_SUCCESS : 0),
					NEXT_BLOCK,
					phtonl(&bytes[len_to_cmp-2]) & 0xffffff00);
			g_list_append(L, bpf);

			len_to_cmp -= 3;
		}
		else if (len_to_cmp == 2) {
			bpf = bpf_code_unit_alloc(label,
					BPF_LD|BPF_H|BPF_ABS,
					0, 0, endpoint - 2);
			g_list_append(L, bpf);
			label = NO_LABEL;

			endpoint -= 2;
			bpf = bpf_code_unit_alloc(NO_LABEL,
					BPF_JMP|BPF_JEQ,
					(len_to_cmp == 2 ? END_OF_PROGRAM_SUCCESS : 0),
					NEXT_BLOCK,
					(guint32)phtons(&bytes[len_to_cmp-1]));
			g_list_append(L, bpf);

			len_to_cmp -= 2;
		}
		else if (len_to_cmp == 1) {
			bpf = bpf_code_unit_alloc(label,
					BPF_LD|BPF_B|BPF_ABS,
					0, 0, endpoint - 1);
			g_list_append(L, bpf);
			label = NO_LABEL;

			endpoint--;
			bpf = bpf_code_unit_alloc(NO_LABEL,
					BPF_JMP|BPF_JEQ,
					END_OF_PROGRAM_SUCCESS, NEXT_BLOCK,
					bytes[len_to_cmp]);
			g_list_append(L, bpf);
			len_to_cmp--;
		}
	}


	L = g_list_remove(L, 0);
	return L;
}


static void
bpf_optimize(GList *L)
{
	bpf_pass1(L);
	bpf_code_just_parsed = L;
}

/* after the BPF code is constructed from the parser, this step is run. During
 * pass1 we:
 *
 * 1. Clean up the jump variables
 */
static void
bpf_pass1(GList *L)
{
	struct bpf_code_unit *bpf;
	int	num_bpf_instructions;
	int	i_ret_success;
	int	i_ret_failure;
	int	i;

	/* Attach a SUCCESS return to the end of the BPF code */
	bpf = bpf_code_unit_alloc(END_OF_PROGRAM_SUCCESS, BPF_RET, 0, 0, 0xffff);
	g_list_append(L, bpf);

	/* Attach a FAILURE return to the end of the BPF code */
	bpf = bpf_code_unit_alloc(END_OF_PROGRAM_FAILURE, BPF_RET, 0, 0, 0);
	g_list_append(L, bpf);

	num_bpf_instructions = g_list_length(L);
	i_ret_success = num_bpf_instructions - 2;
	i_ret_failure = num_bpf_instructions - 1;

	for(i = 0; i < num_bpf_instructions; i++) {
		bpf = (struct bpf_code_unit*) g_list_nth_data(L, i);
		if (!bpf)
			continue;

		/* Check for Jump to end failure/success */
		if (bpf->bpf.code & BPF_JMP) {

			bpf->bpf.jt = bpf_clean_jump(L, i, bpf->bpf.jt, num_bpf_instructions,
					i_ret_success, i_ret_failure);

			bpf->bpf.jf = bpf_clean_jump(L, i, bpf->bpf.jf, num_bpf_instructions,
					i_ret_success, i_ret_failure);
		}
	}
}

static int
bpf_clean_jump(GList *L, int i_this, int jmp, int num_bpf_instructions,
		int i_ret_success, int i_ret_failure)
{
	int i;
	struct bpf_code_unit *bpf;

	switch(jmp) {
		case END_OF_PROGRAM_SUCCESS:
			return i_ret_success - i_this - 1;

		case END_OF_PROGRAM_FAILURE:
			return i_ret_failure - i_this - 1;

		case NEXT_BLOCK:
			for (i = i_this + 1; i < num_bpf_instructions; i++) {
				bpf = (struct bpf_code_unit*) g_list_nth_data(L, i);
				if (!bpf)
					continue;
				if (bpf->line_label == NEXT_BLOCK) {
					return i - i_this - 1;
				}
			}
			/* failed to find NEXT_BLOCK.... chose FAILURE */
			return i_ret_failure - i_this - 1;

		/* default: nothing */
	}
	return jmp;
}



/* Takes code from bpf_code_just_parsed and attaches it to wth
 * returns 1 if sucessfull, 0 if not */
static int bpf_attach(wtap *wth)
{
	if (wth->filter.bpf)
		g_free(wth->filter.bpf);

	/* filter_length will be number of bpf_block records */
	wth->filter_length = g_list_length(bpf_code_just_parsed) - 1;

	wth->filter.bpf = g_malloc(wth->filter_length *
				sizeof(struct bpf_instruction));
	wth->filter_type = WTAP_FILTER_BPF;

	bpf_record = wth->filter.bpf;

	g_list_foreach(bpf_code_just_parsed, bpf_attach_record, NULL);

	if (bpf_chk_filter(wth->filter.bpf, wth->filter_length) == 0)
		return 1;
	else
		return 0;

}

void bpf_attach_record(gpointer bpf_code, gpointer junk)
{
	struct bpf_code_unit *bpf_c = (struct bpf_code_unit*) bpf_code;

	struct bpf_instruction *bpf_i;

	if (!bpf_c)
		return;

	bpf_i = &(bpf_c->bpf);
	memcpy(bpf_record, bpf_i, sizeof(struct bpf_instruction));
	bpf_record++;
}


/* Takes code from bpf_code_just_parsed and attachs it to wth.
 * returns 1 if sucessfull, 0 if not */
static int offline_attach(wtap *wth)
{
	/* filter_length will be number of bpf_instruction records */
	wth->offline_filter_lengths[comp_encap_type] =
		g_list_length(bpf_code_just_parsed);

	/* Make space for this filter */
	wth->filter.offline[comp_encap_type] =
		g_malloc(wth->offline_filter_lengths[comp_encap_type]
				* sizeof(struct bpf_instruction));

	bpf_record = wth->filter.offline[comp_encap_type];

	g_list_foreach(bpf_code_just_parsed, bpf_attach_record, NULL);

	if (bpf_chk_filter(wth->filter.offline[comp_encap_type],
			wth->offline_filter_lengths[comp_encap_type]) == 0)
		return 1;
	else
		return 0;
}

