
#include <stdio.h>
#include <glib.h>
#include "config.h"
#include "wtap.h"
#include "bpf-engine.h"

#ifdef HAVE_GLIB10
#include "glib-new.h"
#endif

void bpf_dump(wtap *wth);
char *bpf_image(struct bpf_instruction *p, int n);

int main(int argc, char **argv)
{
	wtap	*wth;
	char	*fsyntax;
	int	i;

	if (argc <= 1) {
		fprintf(stderr, "usage: wiretap filter\n");
		exit(-1);
	}
	
	fsyntax = g_strdup(argv[1]);

	for (i = 2; i < argc; i++) {
		fsyntax = g_strjoin(" ", fsyntax, argv[i], NULL);
	}
	wth = (wtap*)g_malloc(sizeof(wtap));

	/* initialization */
	wth->file_encap = WTAP_ENCAP_NONE;
	wth->filter.offline = NULL;
	wth->filter_type = WTAP_FILTER_NONE;
	wth->filter_length = 0;
	wth->offline_filter_lengths = NULL;

	wtap_offline_filter(wth, fsyntax);
	bpf_dump(wth);

	g_free(wth);
	return 0;
}

void
bpf_dump(wtap *wth)
{
	struct bpf_instruction *fentry;
	int flen;
	int i;
	
	fentry = wth->filter.offline[WTAP_ENCAP_ETHERNET];
	flen = wth->offline_filter_lengths[WTAP_ENCAP_ETHERNET];

	/* this loop is from tcpdump's bpf_dump.c */
	for (i = 0; i < flen; ++fentry, ++i) {
		puts(bpf_image(fentry, i));
	}
}

/* this entire function is from libpcap's bpf_image.c */
char *
bpf_image(struct bpf_instruction *p, int n)
{
	int v;
	char *fmt, *op;
	static char image[256];
	char operand[64];

	v = p->k;
	switch (p->code) {

	default:
		op = "unimp";
		fmt = "0x%x";
		v = p->code;
		break;

	case BPF_RET|BPF_K:
		op = "ret";
		fmt = "#%d";
		break;

	case BPF_RET|BPF_A:
		op = "ret";
		fmt = "";
		break;

	case BPF_LD|BPF_W|BPF_ABS:
		op = "ld";
		fmt = "[%d]";
		break;

	case BPF_LD|BPF_H|BPF_ABS:
		op = "ldh";
		fmt = "[%d]";
		break;

	case BPF_LD|BPF_B|BPF_ABS:
		op = "ldb";
		fmt = "[%d]";
		break;

	case BPF_LD|BPF_W|BPF_LEN:
		op = "ld";
		fmt = "#pktlen";
		break;

	case BPF_LD|BPF_W|BPF_IND:
		op = "ld";
		fmt = "[x + %d]";
		break;

	case BPF_LD|BPF_H|BPF_IND:
		op = "ldh";
		fmt = "[x + %d]";
		break;

	case BPF_LD|BPF_B|BPF_IND:
		op = "ldb";
		fmt = "[x + %d]";
		break;

	case BPF_LD|BPF_IMM:
		op = "ld";
		fmt = "#0x%x";
		break;

	case BPF_LDX|BPF_IMM:
		op = "ldx";
		fmt = "#0x%x";
		break;

	case BPF_LDX|BPF_MSH|BPF_B:
		op = "ldxb";
		fmt = "4*([%d]&0xf)";
		break;

	case BPF_LD|BPF_MEM:
		op = "ld";
		fmt = "M[%d]";
		break;

	case BPF_LDX|BPF_MEM:
		op = "ldx";
		fmt = "M[%d]";
		break;

	case BPF_ST:
		op = "st";
		fmt = "M[%d]";
		break;

	case BPF_STX:
		op = "stx";
		fmt = "M[%d]";
		break;

	case BPF_JMP|BPF_JA:
		op = "ja";
		fmt = "%d";
		v = n + 1 + p->k;
		break;

	case BPF_JMP|BPF_JGT|BPF_K:
		op = "jgt";
		fmt = "#0x%x";
		break;

	case BPF_JMP|BPF_JGE|BPF_K:
		op = "jge";
		fmt = "#0x%x";
		break;

	case BPF_JMP|BPF_JEQ|BPF_K:
		op = "jeq";
		fmt = "#0x%08x";
		break;

	case BPF_JMP|BPF_JSET|BPF_K:
		op = "jset";
		fmt = "#0x%x";
		break;

	case BPF_JMP|BPF_JGT|BPF_X:
		op = "jgt";
		fmt = "x";
		break;

	case BPF_JMP|BPF_JGE|BPF_X:
		op = "jge";
		fmt = "x";
		break;

	case BPF_JMP|BPF_JEQ|BPF_X:
		op = "jeq";
		fmt = "x";
		break;

	case BPF_JMP|BPF_JSET|BPF_X:
		op = "jset";
		fmt = "x";
		break;

	case BPF_ALU|BPF_ADD|BPF_X:
		op = "add";
		fmt = "x";
		break;

	case BPF_ALU|BPF_SUB|BPF_X:
		op = "sub";
		fmt = "x";
		break;

	case BPF_ALU|BPF_MUL|BPF_X:
		op = "mul";
		fmt = "x";
		break;

	case BPF_ALU|BPF_DIV|BPF_X:
		op = "div";
		fmt = "x";
		break;

	case BPF_ALU|BPF_AND|BPF_X:
		op = "and";
		fmt = "x";
		break;

	case BPF_ALU|BPF_OR|BPF_X:
		op = "or";
		fmt = "x";
		break;

	case BPF_ALU|BPF_LSH|BPF_X:
		op = "lsh";
		fmt = "x";
		break;

	case BPF_ALU|BPF_RSH|BPF_X:
		op = "rsh";
		fmt = "x";
		break;

	case BPF_ALU|BPF_ADD|BPF_K:
		op = "add";
		fmt = "#%d";
		break;

	case BPF_ALU|BPF_SUB|BPF_K:
		op = "sub";
		fmt = "#%d";
		break;

	case BPF_ALU|BPF_MUL|BPF_K:
		op = "mul";
		fmt = "#%d";
		break;

	case BPF_ALU|BPF_DIV|BPF_K:
		op = "div";
		fmt = "#%d";
		break;

	case BPF_ALU|BPF_AND|BPF_K:
		op = "and";
		fmt = "#0x%08x";
		break;

	case BPF_ALU|BPF_OR|BPF_K:
		op = "or";
		fmt = "#0x%x";
		break;

	case BPF_ALU|BPF_LSH|BPF_K:
		op = "lsh";
		fmt = "#%d";
		break;

	case BPF_ALU|BPF_RSH|BPF_K:
		op = "rsh";
		fmt = "#%d";
		break;

	case BPF_ALU|BPF_NEG:
		op = "neg";
		fmt = "";
		break;

	case BPF_MISC|BPF_TAX:
		op = "tax";
		fmt = "";
		break;

	case BPF_MISC|BPF_TXA:
		op = "txa";
		fmt = "";
		break;
	}
	(void)sprintf(operand, fmt, v);
	(void)sprintf(image,
		      (BPF_CLASS(p->code) == BPF_JMP &&
		       BPF_OP(p->code) != BPF_JA) ?
		      "(%03d) %-8s %-16s jt %d\tjf %d"
		      : "(%03d) %-8s %s",
		      n, op, operand, n + 1 + p->jt, n + 1 + p->jf);
	return image;
}
