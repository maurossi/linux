// SPDX-License-Identifier: GPL-2.0-only
/*
 * Software emulation of SSSE3, SSE4.1, SSE4.2, POPCNT and MOVBE for user
 * space, for CPUs which lack them.
 *
 * The x86_64 Android ABI assumes SSSE3, SSE4.1, SSE4.2 and POPCNT. Older
 * CPUs (Core 2 Merom, AMD K8/K10, ...) raise #UD on those instructions. This
 * decodes the faulting instruction with the generic x86 instruction decoder,
 * computes the result and updates the task's registers before resuming it.
 *
 * Only the legacy (non-VEX) encodings are handled. An instruction is only
 * emulated when the boot CPU really lacks the corresponding feature, so a
 * genuine #UD on a capable CPU is never masked.
 *
 * The user's SSE/MMX state is never accessed in the hardware registers: the
 * emulation runs between kernel_fpu_begin() and kernel_fpu_end(), which
 * saves the user state to the task's fpstate and forces it to be restored
 * from there on the way back to user space. All user memory accesses are
 * done outside of that region, as they may fault and sleep.
 */

#define pr_fmt(fmt) "sse-emu: " fmt

#include <linux/bitops.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kstrtox.h>
#include <linux/minmax.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/swab.h>
#include <linux/uaccess.h>
#include <linux/uprobes.h>

#include <asm/cpufeature.h>
#include <asm/fpu/api.h>
#include <asm/fpu/types.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/trapnr.h>
#include <asm/traps.h>

#define MXCSR_IE	0x0001
#define MXCSR_PE	0x0020
#define MXCSR_FLAGS	0x003f
#define MXCSR_DAZ	0x0040
#define MXCSR_MASKS	0x1f80
#define MXCSR_RC_SHIFT	13

enum { RC_NEAREST, RC_DOWN, RC_UP, RC_TRUNC };

#define ARITH_FLAGS (X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF | \
		     X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF)

union v128 {
	u8  b[16];
	s8  sb[16];
	u16 w[8];
	s16 sw[8];
	u32 d[4];
	s32 sd[4];
	u64 q[2];
	s64 sq[2];
};

enum mpfx { PFX_NONE, PFX_66, PFX_F3, PFX_F2 };

/* Operand properties of an instruction */
#define OPF_ALIGN	BIT(0)	/* 16-byte memory operand must be aligned */
#define OPF_STORE	BIT(1)	/* r/m is the destination */
#define OPF_MEMONLY	BIT(2)	/* r/m must be a memory operand */
#define OPF_GPR		BIT(3)	/* r/m, if a register, is a GPR */
#define OPF_NOFPU	BIT(4)	/* no SSE/MMX state involved */

struct op_desc {
	u16 feature;
	u8 memsz;
	u8 flags;
};

struct emu {
	struct insn *insn;
	struct pt_regs *regs;
	struct op_desc desc;
	unsigned int map;	/* 0x0f, 0x38 or 0x3a */
	unsigned int op;	/* last opcode byte */
	enum mpfx pfx;		/* mandatory prefix */
	bool rexw;
	bool has_rex;
	bool memop;		/* r/m is a memory operand */
	bool mmx;		/* operands are MMX registers */
	unsigned int vlen;	/* vector length in bytes */
	unsigned int reg, rm;	/* register numbers, REX extended */
	u8 imm;
	void __user *addr;
	union v128 mem;		/* loaded memory operand */
	union v128 store;	/* data to be stored to memory */
	bool do_store;

	/* Only valid between kernel_fpu_begin() and kernel_fpu_end() */
	struct fxregs_state *fx;
	u64 *xfeatures;
	bool sse_dirty, fp_dirty;
	u32 mxcsr_raised;
};

static bool sse_emu_enabled __ro_after_init = true;

static int __init sse_emu_setup(char *s)
{
	return kstrtobool(s, &sse_emu_enabled) == 0;
}
__setup("sse_emu=", sse_emu_setup);

/* Integer helpers */

static inline s16 sat_s16(s32 v)
{
	return clamp_t(s32, v, S16_MIN, S16_MAX);
}

static inline u16 sat_u16(s32 v)
{
	return clamp_t(s32, v, 0, U16_MAX);
}

static inline u64 size_mask(unsigned int size)
{
	return size >= 8 ? ~0ULL : (1ULL << (size * 8)) - 1;
}

static u64 bswap_n(u64 v, unsigned int size)
{
	switch (size) {
	case 2:
		return swab16(v);
	case 4:
		return swab32(v);
	default:
		return swab64(v);
	}
}

static unsigned long *gpr(struct emu *e, unsigned int n)
{
	return (unsigned long *)((void *)e->regs + pt_regs_offset(e->regs, n));
}

/* Write a GPR the way an instruction with operand size @size does */
static void gpr_write(unsigned long *r, u64 v, unsigned int size)
{
	if (size == 2)
		*r = (*r & ~0xffffUL) | (u16)v;
	else
		*r = v & size_mask(size);	/* 32-bit writes zero-extend */
}

/* Read the r/m operand as a GPR or memory integer of @size bytes */
static u64 rm_read(struct emu *e, unsigned int size)
{
	u64 v = 0;

	if (e->memop) {
		memcpy(&v, &e->mem, size);
		return v;
	}

	/* AH, CH, DH and BH without a REX prefix */
	if (size == 1 && !e->has_rex && (e->rm & 4))
		return (*gpr(e, e->rm & 3) >> 8) & 0xff;

	return *gpr(e, e->rm) & size_mask(size);
}

static void set_arith_flags(struct pt_regs *regs, unsigned long flags)
{
	regs->flags = (regs->flags & ~ARITH_FLAGS) | flags;
}

/* SSE/MMX register file access, within kernel_fpu_begin()/end() */

static void fpstate_prepare(struct emu *e)
{
	struct fpstate *fps = x86_task_fpu(current)->fpstate;
	struct fxregs_state *fx = &fps->regs.fxsave;

	e->fx = fx;
	e->xfeatures = NULL;

	if (!cpu_feature_enabled(X86_FEATURE_XSAVE))
		return;

	/*
	 * XSAVEOPT/XSAVES do not write components which are in their init
	 * state, the buffer contents are stale then. MXCSR is always written.
	 */
	e->xfeatures = &fps->regs.xsave.header.xfeatures;
	if (!(*e->xfeatures & XFEATURE_MASK_SSE))
		memset(fx->xmm_space, 0, sizeof(fx->xmm_space));
	if (e->mmx && !(*e->xfeatures & XFEATURE_MASK_FP)) {
		fx->cwd = 0x37f;
		fx->swd = 0;
		fx->twd = 0;
		fx->fop = 0;
		fx->rip = 0;
		fx->rdp = 0;
		memset(fx->st_space, 0, sizeof(fx->st_space));
	}
}

static void fpstate_commit(struct emu *e)
{
	if (!e->xfeatures)
		return;
	if (e->sse_dirty)
		*e->xfeatures |= XFEATURE_MASK_SSE;
	if (e->fp_dirty)
		*e->xfeatures |= XFEATURE_MASK_FP;
}

static union v128 *xmm(struct emu *e, unsigned int n)
{
	return (union v128 *)&e->fx->xmm_space[n * 4];
}

static void *mm(struct emu *e, unsigned int n)
{
	return &e->fx->st_space[n * 4];
}

/*
 * Every MMX instruction (other than EMMS) sets the x87 TOS to 0 and tags all
 * registers valid. FXSAVE stores ST(i), so with TOS != 0 the slots have to
 * be rotated to make slot n hold MMn.
 */
static void mmx_prepare(struct emu *e)
{
	struct fxregs_state *fx = e->fx;
	unsigned int top = (fx->swd >> 11) & 7, i;

	if (top) {
		u32 tmp[32];

		for (i = 0; i < 8; i++)
			memcpy(&tmp[i * 4], &fx->st_space[((i - top) & 7) * 4], 16);
		memcpy(fx->st_space, tmp, sizeof(tmp));
	}
	fx->swd &= ~(7 << 11);
	fx->twd = 0xff;
	e->fp_dirty = true;
}

static void vreg_read(struct emu *e, unsigned int n, union v128 *v)
{
	if (e->mmx) {
		memset(v, 0, sizeof(*v));
		memcpy(v, mm(e, n), 8);
	} else {
		*v = *xmm(e, n);
	}
}

static void vreg_write(struct emu *e, unsigned int n, const union v128 *v)
{
	if (e->mmx) {
		u8 *slot = mm(e, n);

		memcpy(slot, v, 8);
		slot[8] = 0xff;		/* exponent is all ones */
		slot[9] = 0xff;
		e->fp_dirty = true;
	} else {
		*xmm(e, n) = *v;
		e->sse_dirty = true;
	}
}

static inline void mx_load(u32 v)
{
	asm volatile("ldmxcsr %0" : : "m" (v));
}

static inline u32 mx_store(void)
{
	u32 v;

	asm volatile("stmxcsr %0" : "=m" (v));
	return v;
}

/*
 * Scalar SSE/SSE2 arithmetic for DPPS/DPPD. This runs within
 * kernel_fpu_begin() with the user's rounding/DAZ/FTZ settings loaded into
 * MXCSR and all exceptions masked, so the hardware produces exactly rounded
 * results and the exception flags. XMM0/XMM1 are not declared as clobbered:
 * the kernel is built with -mno-sse, so the compiler never allocates them,
 * and GCC refuses such clobbers for that target.
 */
static u32 ss_mul(u32 a, u32 b)
{
	asm volatile("movd %1, %%xmm0\n\t"
		     "movd %2, %%xmm1\n\t"
		     "mulss %%xmm1, %%xmm0\n\t"
		     "movd %%xmm0, %0"
		     : "=r" (a) : "r" (a), "r" (b));
	return a;
}

static u32 ss_add(u32 a, u32 b)
{
	asm volatile("movd %1, %%xmm0\n\t"
		     "movd %2, %%xmm1\n\t"
		     "addss %%xmm1, %%xmm0\n\t"
		     "movd %%xmm0, %0"
		     : "=r" (a) : "r" (a), "r" (b));
	return a;
}

static u64 sd_mul(u64 a, u64 b)
{
	asm volatile("movq %1, %%xmm0\n\t"
		     "movq %2, %%xmm1\n\t"
		     "mulsd %%xmm1, %%xmm0\n\t"
		     "movq %%xmm0, %0"
		     : "=r" (a) : "r" (a), "r" (b));
	return a;
}

static u64 sd_add(u64 a, u64 b)
{
	asm volatile("movq %1, %%xmm0\n\t"
		     "movq %2, %%xmm1\n\t"
		     "addsd %%xmm1, %%xmm0\n\t"
		     "movq %%xmm0, %0"
		     : "=r" (a) : "r" (a), "r" (b));
	return a;
}

/*
 * Round an IEEE 754 binary value with @mbits fraction and @ebits exponent
 * bits to an integral value, as ROUNDPS/PD/SS/SD do.
 */
static u64 fp_round(u64 x, unsigned int mbits, unsigned int ebits,
		    unsigned int mode, bool daz, u32 *flags)
{
	u64 emax = (1ULL << ebits) - 1;
	int bias = emax >> 1;
	u64 sign = x & (1ULL << (mbits + ebits));
	u64 exp = (x >> mbits) & emax;
	u64 frac = x & ((1ULL << mbits) - 1);
	u64 qbit = 1ULL << (mbits - 1);
	u64 m, fmask, rem, half, ip;
	int e = (int)exp - bias;
	unsigned int shift;
	bool up;

	if (exp == emax) {
		if (frac && !(frac & qbit)) {	/* SNaN */
			*flags |= MXCSR_IE;
			return x | qbit;
		}
		return x;			/* Inf, QNaN */
	}
	if (exp == 0 && (frac == 0 || daz))
		return sign;
	if (e >= (int)mbits)
		return x;			/* already integral */

	if (e < 0) {				/* 0 < |x| < 1 */
		*flags |= MXCSR_PE;
		switch (mode) {
		case RC_NEAREST:
			up = e == -1 && frac;	/* > 0.5; 0.5 goes to even 0 */
			break;
		case RC_DOWN:
			up = sign;
			break;
		case RC_UP:
			up = !sign;
			break;
		default:
			up = false;
			break;
		}
		return sign | (up ? (u64)bias << mbits : 0);
	}

	m = frac | (1ULL << mbits);
	shift = mbits - e;
	fmask = (1ULL << shift) - 1;
	rem = m & fmask;
	if (!rem)
		return x;
	*flags |= MXCSR_PE;

	half = 1ULL << (shift - 1);
	switch (mode) {
	case RC_NEAREST:
		up = rem > half || (rem == half && ((m >> shift) & 1));
		break;
	case RC_DOWN:
		up = sign;
		break;
	case RC_UP:
		up = !sign;
		break;
	default:
		up = false;
		break;
	}

	ip = m & ~fmask;
	if (up)
		ip += 1ULL << shift;
	if (ip >> (mbits + 1)) {
		ip >>= 1;
		exp++;
	}
	return sign | (exp << mbits) | (ip & ((1ULL << mbits) - 1));
}

/* SSSE3, 0F 38 00-0B and 1C-1E, both MMX and XMM forms */
static void emu_ssse3(struct emu *e, union v128 *r, const union v128 *a, const union v128 *s)
{
	unsigned int n = e->vlen, nw = n / 2, nd = n / 4, i;

	switch (e->op) {
	case 0x00:	/* pshufb */
		for (i = 0; i < n; i++)
			r->b[i] = (s->b[i] & 0x80) ? 0 : a->b[s->b[i] & (n - 1)];
		break;
	case 0x01:	/* phaddw */
	case 0x03:	/* phaddsw */
	case 0x05:	/* phsubw */
	case 0x07:	/* phsubsw */
		for (i = 0; i < nw; i++) {
			const union v128 *v = i < nw / 2 ? a : s;
			unsigned int k = (i % (nw / 2)) * 2;
			s32 x = v->sw[k], y = v->sw[k + 1];
			s32 t = (e->op & 4) ? x - y : x + y;

			r->sw[i] = (e->op & 2) ? sat_s16(t) : (s16)t;
		}
		break;
	case 0x02:	/* phaddd */
	case 0x06:	/* phsubd */
		for (i = 0; i < nd; i++) {
			const union v128 *v = i < nd / 2 ? a : s;
			unsigned int k = (i % (nd / 2)) * 2;

			r->d[i] = (e->op & 4) ? v->d[k] - v->d[k + 1] :
						v->d[k] + v->d[k + 1];
		}
		break;
	case 0x04:	/* pmaddubsw */
		for (i = 0; i < nw; i++)
			r->sw[i] = sat_s16(a->b[2 * i] * s->sb[2 * i] +
					   a->b[2 * i + 1] * s->sb[2 * i + 1]);
		break;
	case 0x08:	/* psignb */
		for (i = 0; i < n; i++)
			r->b[i] = s->sb[i] < 0 ? -a->b[i] : s->sb[i] ? a->b[i] : 0;
		break;
	case 0x09:	/* psignw */
		for (i = 0; i < nw; i++)
			r->w[i] = s->sw[i] < 0 ? -a->w[i] : s->sw[i] ? a->w[i] : 0;
		break;
	case 0x0a:	/* psignd */
		for (i = 0; i < nd; i++)
			r->d[i] = s->sd[i] < 0 ? -a->d[i] : s->sd[i] ? a->d[i] : 0;
		break;
	case 0x0b:	/* pmulhrsw */
		for (i = 0; i < nw; i++)
			r->sw[i] = ((((s32)a->sw[i] * s->sw[i]) >> 14) + 1) >> 1;
		break;
	case 0x1c:	/* pabsb */
		for (i = 0; i < n; i++)
			r->b[i] = s->sb[i] < 0 ? -s->b[i] : s->b[i];
		break;
	case 0x1d:	/* pabsw */
		for (i = 0; i < nw; i++)
			r->w[i] = s->sw[i] < 0 ? -s->w[i] : s->w[i];
		break;
	case 0x1e:	/* pabsd */
		for (i = 0; i < nd; i++)
			r->d[i] = s->sd[i] < 0 ? -s->d[i] : s->d[i];
		break;
	}
}

/* palignr, 0F 3A 0F, both MMX and XMM forms */
static void emu_palignr(struct emu *e, union v128 *r, const union v128 *a, const union v128 *s)
{
	unsigned int n = e->vlen, i;
	u8 t[32];

	memcpy(t, s, n);
	memcpy(t + n, a, n);
	for (i = 0; i < n; i++)
		r->b[i] = e->imm + i < 2 * n ? t[e->imm + i] : 0;
}

/* pmovsx/pmovzx, 66 0F 38 20-25 and 30-35 */
static void emu_pmovx(union v128 *r, const union v128 *s, unsigned int op)
{
	static const u8 from[] = { 1, 1, 1, 2, 2, 4 };
	static const u8 to[] = { 2, 4, 8, 4, 8, 8 };
	unsigned int k = op & 0xf, ts = to[k], i;
	bool sx = !(op & 0x10);

	for (i = 0; i < 16 / ts; i++) {
		u64 v;

		switch (from[k]) {
		case 1:
			v = sx ? (u64)(s64)s->sb[i] : s->b[i];
			break;
		case 2:
			v = sx ? (u64)(s64)s->sw[i] : s->w[i];
			break;
		default:
			v = sx ? (u64)(s64)s->sd[i] : s->d[i];
			break;
		}

		switch (ts) {
		case 2:
			r->w[i] = v;
			break;
		case 4:
			r->d[i] = v;
			break;
		default:
			r->q[i] = v;
			break;
		}
	}
}

/* SSE4.1/4.2, 66 0F 38 xx; returns false if only flags are written */
static bool emu_sse4_38(struct emu *e, union v128 *r, const union v128 *a, const union v128 *s)
{
	const union v128 *x0 = xmm(e, 0);
	unsigned int i;

	switch (e->op) {
	case 0x10:	/* pblendvb */
		for (i = 0; i < 16; i++)
			r->b[i] = (x0->b[i] & 0x80) ? s->b[i] : a->b[i];
		break;
	case 0x14:	/* blendvps */
		for (i = 0; i < 4; i++)
			r->d[i] = (x0->d[i] >> 31) ? s->d[i] : a->d[i];
		break;
	case 0x15:	/* blendvpd */
		for (i = 0; i < 2; i++)
			r->q[i] = (x0->q[i] >> 63) ? s->q[i] : a->q[i];
		break;
	case 0x17: {	/* ptest */
		unsigned long f = 0;

		if (!((a->q[0] & s->q[0]) | (a->q[1] & s->q[1])))
			f |= X86_EFLAGS_ZF;
		if (!((~a->q[0] & s->q[0]) | (~a->q[1] & s->q[1])))
			f |= X86_EFLAGS_CF;
		set_arith_flags(e->regs, f);
		return false;
	}
	case 0x20 ... 0x25:
	case 0x30 ... 0x35:
		emu_pmovx(r, s, e->op);
		break;
	case 0x28:	/* pmuldq */
		for (i = 0; i < 2; i++)
			r->sq[i] = (s64)a->sd[2 * i] * s->sd[2 * i];
		break;
	case 0x29:	/* pcmpeqq */
		for (i = 0; i < 2; i++)
			r->q[i] = a->q[i] == s->q[i] ? ~0ULL : 0;
		break;
	case 0x2a:	/* movntdqa */
		*r = *s;
		break;
	case 0x2b:	/* packusdw */
		for (i = 0; i < 4; i++) {
			r->w[i] = sat_u16(a->sd[i]);
			r->w[i + 4] = sat_u16(s->sd[i]);
		}
		break;
	case 0x37:	/* pcmpgtq */
		for (i = 0; i < 2; i++)
			r->q[i] = a->sq[i] > s->sq[i] ? ~0ULL : 0;
		break;
	case 0x38:	/* pminsb */
		for (i = 0; i < 16; i++)
			r->sb[i] = min(a->sb[i], s->sb[i]);
		break;
	case 0x39:	/* pminsd */
		for (i = 0; i < 4; i++)
			r->sd[i] = min(a->sd[i], s->sd[i]);
		break;
	case 0x3a:	/* pminuw */
		for (i = 0; i < 8; i++)
			r->w[i] = min(a->w[i], s->w[i]);
		break;
	case 0x3b:	/* pminud */
		for (i = 0; i < 4; i++)
			r->d[i] = min(a->d[i], s->d[i]);
		break;
	case 0x3c:	/* pmaxsb */
		for (i = 0; i < 16; i++)
			r->sb[i] = max(a->sb[i], s->sb[i]);
		break;
	case 0x3d:	/* pmaxsd */
		for (i = 0; i < 4; i++)
			r->sd[i] = max(a->sd[i], s->sd[i]);
		break;
	case 0x3e:	/* pmaxuw */
		for (i = 0; i < 8; i++)
			r->w[i] = max(a->w[i], s->w[i]);
		break;
	case 0x3f:	/* pmaxud */
		for (i = 0; i < 4; i++)
			r->d[i] = max(a->d[i], s->d[i]);
		break;
	case 0x40:	/* pmulld */
		for (i = 0; i < 4; i++)
			r->d[i] = a->d[i] * s->d[i];
		break;
	case 0x41: {	/* phminposuw */
		unsigned int idx = 0;

		for (i = 1; i < 8; i++)
			if (s->w[i] < s->w[idx])
				idx = i;
		memset(r, 0, sizeof(*r));
		r->w[0] = s->w[idx];
		r->w[1] = idx;
		break;
	}
	}
	return true;
}

static int pcmpstr_elem(const union v128 *v, unsigned int i, bool words, bool sgn)
{
	if (words)
		return sgn ? v->sw[i] : v->w[i];
	return sgn ? v->sb[i] : v->b[i];
}

static unsigned int pcmpstr_explicit_len(u64 reg, bool rexw, unsigned int max)
{
	s64 v = rexw ? (s64)reg : (s64)(s32)reg;
	u64 m = v < 0 ? -(u64)v : (u64)v;

	return min_t(u64, m, max);
}

/* pcmpestrm/pcmpestri/pcmpistrm/pcmpistri, 66 0F 3A 60-63 */
static void emu_pcmpstr(struct emu *e, const union v128 *a, const union v128 *b)
{
	bool words = e->imm & 1, sgn = e->imm & 2;
	unsigned int max = words ? 8 : 16, la, lb, i, j, k;
	unsigned int agg = (e->imm >> 2) & 3, pol = (e->imm >> 4) & 3;
	u32 res1 = 0, res2, all = (1U << max) - 1;
	struct pt_regs *regs = e->regs;
	unsigned long f = 0;

	if (e->op < 0x62) {
		la = pcmpstr_explicit_len(regs->ax, e->rexw, max);
		lb = pcmpstr_explicit_len(regs->dx, e->rexw, max);
	} else {
		for (la = 0; la < max && pcmpstr_elem(a, la, words, false); la++)
			;
		for (lb = 0; lb < max && pcmpstr_elem(b, lb, words, false); lb++)
			;
	}

#define A(i) pcmpstr_elem(a, i, words, sgn)
#define B(i) pcmpstr_elem(b, i, words, sgn)
	for (j = 0; j < max; j++) {
		bool r = false;

		switch (agg) {
		case 0:		/* equal any */
			for (i = 0; i < la && j < lb && !r; i++)
				r = A(i) == B(j);
			break;
		case 1:		/* ranges */
			for (i = 0; i + 1 < la && j < lb && !r; i += 2)
				r = A(i) <= B(j) && B(j) <= A(i + 1);
			break;
		case 2:		/* equal each */
			if (j < la && j < lb)
				r = A(j) == B(j);
			else
				r = j >= la && j >= lb;
			break;
		case 3:		/* equal ordered */
			r = true;
			for (k = 0; k < la && j + k < max; k++) {
				if (j + k >= lb || A(k) != B(j + k)) {
					r = false;
					break;
				}
			}
			break;
		}
		res1 |= (u32)r << j;
	}
#undef A
#undef B

	switch (pol) {
	case 1:
		res2 = ~res1 & all;
		break;
	case 3:
		res2 = res1 ^ ((1U << lb) - 1);
		break;
	default:
		res2 = res1;
		break;
	}

	if (e->op & 1) {
		/* Index into ECX, zero-extended */
		if (!res2)
			regs->cx = max;
		else
			regs->cx = (e->imm & 0x40) ? __fls(res2) : __ffs(res2);
	} else {
		union v128 m = {};

		if (!(e->imm & 0x40)) {
			m.d[0] = res2;
		} else {
			for (j = 0; j < max; j++) {
				if (!(res2 & BIT(j)))
					continue;
				if (words)
					m.w[j] = 0xffff;
				else
					m.b[j] = 0xff;
			}
		}
		*xmm(e, 0) = m;
		e->sse_dirty = true;
	}

	if (res2)
		f |= X86_EFLAGS_CF;
	if (lb < max)
		f |= X86_EFLAGS_ZF;
	if (la < max)
		f |= X86_EFLAGS_SF;
	if (res2 & 1)
		f |= X86_EFLAGS_OF;
	set_arith_flags(regs, f);
}

/* SSE4.1/4.2, 66 0F 3A xx; returns false if no XMM register is written */
static bool emu_sse4_3a(struct emu *e, union v128 *r, const union v128 *a, const union v128 *s)
{
	u32 mxcsr = e->fx->mxcsr;
	unsigned int imm = e->imm, i;
	u32 fl = 0;

	*r = *a;

	switch (e->op) {
	case 0x08 ... 0x0b: {	/* roundps/pd/ss/sd */
		unsigned int mode = (imm & 4) ? (mxcsr >> MXCSR_RC_SHIFT) & 3 : imm & 3;
		bool daz = mxcsr & MXCSR_DAZ;

		switch (e->op) {
		case 0x08:
			for (i = 0; i < 4; i++)
				r->d[i] = fp_round(s->d[i], 23, 8, mode, daz, &fl);
			break;
		case 0x09:
			for (i = 0; i < 2; i++)
				r->q[i] = fp_round(s->q[i], 52, 11, mode, daz, &fl);
			break;
		case 0x0a:
			r->d[0] = fp_round(s->d[0], 23, 8, mode, daz, &fl);
			break;
		case 0x0b:
			r->q[0] = fp_round(s->q[0], 52, 11, mode, daz, &fl);
			break;
		}
		if (imm & 8)
			fl &= ~MXCSR_PE;
		e->mxcsr_raised |= fl;
		break;
	}
	case 0x0c:	/* blendps */
		for (i = 0; i < 4; i++)
			if (imm & BIT(i))
				r->d[i] = s->d[i];
		break;
	case 0x0d:	/* blendpd */
		for (i = 0; i < 2; i++)
			if (imm & BIT(i))
				r->q[i] = s->q[i];
		break;
	case 0x0e:	/* pblendw */
		for (i = 0; i < 8; i++)
			if (imm & BIT(i))
				r->w[i] = s->w[i];
		break;
	case 0x14:	/* pextrb */
	case 0x15:	/* pextrw */
	case 0x16:	/* pextrd/q */
	case 0x17: {	/* extractps */
		u64 v;

		switch (e->op) {
		case 0x14:
			v = a->b[imm & 15];
			break;
		case 0x15:
			v = a->w[imm & 7];
			break;
		case 0x16:
			v = e->rexw ? a->q[imm & 1] : a->d[imm & 3];
			break;
		default:
			v = a->d[imm & 3];
			break;
		}
		if (e->memop) {
			memcpy(&e->store, &v, e->desc.memsz);
			e->do_store = true;
		} else {
			*gpr(e, e->rm) = v;	/* zero-extended */
		}
		return false;
	}
	case 0x20:	/* pinsrb */
		r->b[imm & 15] = s->b[0];
		break;
	case 0x21: {	/* insertps */
		u32 v = e->memop ? s->d[0] : s->d[(imm >> 6) & 3];

		r->d[(imm >> 4) & 3] = v;
		for (i = 0; i < 4; i++)
			if (imm & BIT(i))
				r->d[i] = 0;
		break;
	}
	case 0x22:	/* pinsrd/q */
		if (e->rexw)
			r->q[imm & 1] = s->q[0];
		else
			r->d[imm & 3] = s->d[0];
		break;
	case 0x40: {	/* dpps */
		u32 p[4], t01, t23, lo, hi;

		/*
		 * The operand order only matters for which NaN is propagated.
		 * It matches Intel hardware: the sums for the upper two lanes
		 * are computed with the halves swapped.
		 */
		mx_load((mxcsr & ~MXCSR_FLAGS) | MXCSR_MASKS);
		for (i = 0; i < 4; i++)
			p[i] = (imm & BIT(4 + i)) ? ss_mul(a->d[i], s->d[i]) : 0;
		t01 = ss_add(p[1], p[0]);
		t23 = ss_add(p[3], p[2]);
		lo = ss_add(t01, t23);
		hi = ss_add(t23, t01);
		e->mxcsr_raised |= mx_store() & MXCSR_FLAGS;
		for (i = 0; i < 4; i++)
			r->d[i] = (imm & BIT(i)) ? (i < 2 ? lo : hi) : 0;
		break;
	}
	case 0x41: {	/* dppd */
		u64 p0, p1, lo, hi;

		mx_load((mxcsr & ~MXCSR_FLAGS) | MXCSR_MASKS);
		p0 = (imm & BIT(4)) ? sd_mul(a->q[0], s->q[0]) : 0;
		p1 = (imm & BIT(5)) ? sd_mul(a->q[1], s->q[1]) : 0;
		lo = sd_add(p0, p1);
		hi = sd_add(p1, p0);
		e->mxcsr_raised |= mx_store() & MXCSR_FLAGS;
		r->q[0] = (imm & BIT(0)) ? lo : 0;
		r->q[1] = (imm & BIT(1)) ? hi : 0;
		break;
	}
	case 0x42: {	/* mpsadbw */
		unsigned int o1 = ((imm >> 2) & 1) * 4, o2 = (imm & 3) * 4, k;

		for (i = 0; i < 8; i++) {
			u16 sum = 0;

			for (k = 0; k < 4; k++)
				sum += abs((int)a->b[o1 + i + k] - (int)s->b[o2 + k]);
			r->w[i] = sum;
		}
		break;
	}
	case 0x60 ... 0x63:
		emu_pcmpstr(e, a, s);
		return false;
	}
	return true;
}

/*
 * Classify the instruction. Returns false if it is not one we emulate, in
 * which case the #UD is delivered as usual.
 */
static bool classify(struct emu *e)
{
	struct op_desc *d = &e->desc;
	unsigned int op = e->op;

	e->vlen = 16;

	switch (e->map) {
	case 0x0f:
		if (op != 0xb8 || e->pfx != PFX_F3)
			return false;
		/* popcnt */
		*d = (struct op_desc){ X86_FEATURE_POPCNT, e->insn->opnd_bytes,
				       OPF_GPR | OPF_NOFPU };
		return true;

	case 0x38:
		if (op <= 0x0b || (op >= 0x1c && op <= 0x1e)) {
			if (e->pfx == PFX_NONE) {
				e->mmx = true;
				e->vlen = 8;
				*d = (struct op_desc){ X86_FEATURE_SSSE3, 8, 0 };
			} else if (e->pfx == PFX_66) {
				*d = (struct op_desc){ X86_FEATURE_SSSE3, 16, OPF_ALIGN };
			} else {
				return false;
			}
			return true;
		}
		if (op == 0xf0 || op == 0xf1) {
			if (e->pfx == PFX_F2) {		/* crc32 */
				*d = (struct op_desc){ X86_FEATURE_XMM4_2,
					op == 0xf0 ? 1 : e->insn->opnd_bytes,
					OPF_GPR | OPF_NOFPU };
			} else if (e->pfx == PFX_NONE || e->pfx == PFX_66) {
				*d = (struct op_desc){ X86_FEATURE_MOVBE,
					e->insn->opnd_bytes,
					OPF_GPR | OPF_NOFPU | OPF_MEMONLY |
					(op == 0xf1 ? OPF_STORE : 0) };
			} else {
				return false;
			}
			return true;
		}
		if (e->pfx != PFX_66)
			return false;

		*d = (struct op_desc){ X86_FEATURE_XMM4_1, 16, OPF_ALIGN };
		switch (op) {
		case 0x10: case 0x14: case 0x15: case 0x17:
		case 0x28: case 0x29: case 0x2b:
		case 0x38 ... 0x41:
			return true;
		case 0x2a:
			d->flags |= OPF_MEMONLY;
			return true;
		case 0x37:
			d->feature = X86_FEATURE_XMM4_2;
			return true;
		case 0x20 ... 0x25:
		case 0x30 ... 0x35: {
			static const u8 sz[] = { 8, 4, 2, 8, 4, 8 };

			d->memsz = sz[op & 0xf];
			d->flags = 0;
			return true;
		}
		}
		return false;

	case 0x3a:
		if (op == 0x0f) {		/* palignr */
			if (e->pfx == PFX_NONE) {
				e->mmx = true;
				e->vlen = 8;
				*d = (struct op_desc){ X86_FEATURE_SSSE3, 8, 0 };
			} else if (e->pfx == PFX_66) {
				*d = (struct op_desc){ X86_FEATURE_SSSE3, 16, OPF_ALIGN };
			} else {
				return false;
			}
			return true;
		}
		if (e->pfx != PFX_66)
			return false;

		*d = (struct op_desc){ X86_FEATURE_XMM4_1, 16, OPF_ALIGN };
		switch (op) {
		case 0x08: case 0x09: case 0x0c: case 0x0d: case 0x0e:
		case 0x40: case 0x41: case 0x42:
			return true;
		case 0x0a:
			*d = (struct op_desc){ X86_FEATURE_XMM4_1, 4, 0 };
			return true;
		case 0x0b:
			*d = (struct op_desc){ X86_FEATURE_XMM4_1, 8, 0 };
			return true;
		case 0x14: case 0x15: case 0x16: case 0x17: {
			static const u8 sz[] = { 1, 2, 4, 4 };

			d->memsz = (op == 0x16 && e->rexw) ? 8 : sz[op - 0x14];
			d->flags = OPF_STORE | OPF_GPR;
			return true;
		}
		case 0x20:
			*d = (struct op_desc){ X86_FEATURE_XMM4_1, 1, OPF_GPR };
			return true;
		case 0x21:
			*d = (struct op_desc){ X86_FEATURE_XMM4_1, 4, 0 };
			return true;
		case 0x22:
			*d = (struct op_desc){ X86_FEATURE_XMM4_1,
					       e->rexw ? 8 : 4, OPF_GPR };
			return true;
		case 0x60 ... 0x63:	/* unaligned memory is fine */
			*d = (struct op_desc){ X86_FEATURE_XMM4_2, 16, 0 };
			return true;
		}
		return false;
	}
	return false;
}

/* popcnt, crc32, movbe */
static void emu_gpr(struct emu *e)
{
	unsigned int size = e->insn->opnd_bytes;
	unsigned long *reg = gpr(e, e->reg);

	if (e->map == 0x0f) {				/* popcnt */
		u64 v = rm_read(e, size);

		gpr_write(reg, hweight64(v), size);
		set_arith_flags(e->regs, v ? 0 : X86_EFLAGS_ZF);
	} else if (e->pfx == PFX_F2) {			/* crc32 */
		u64 v = rm_read(e, e->desc.memsz);
		u32 crc = *reg;
		unsigned int i, k;

		for (i = 0; i < e->desc.memsz; i++) {
			crc ^= (u8)(v >> (8 * i));
			for (k = 0; k < 8; k++)
				crc = (crc >> 1) ^ (0x82f63b78 & -(crc & 1));
		}
		*reg = crc;				/* zero-extended */
	} else if (e->op == 0xf0) {			/* movbe load */
		gpr_write(reg, bswap_n(rm_read(e, size), size), size);
	} else {					/* movbe store */
		u64 v = bswap_n(*reg & size_mask(size), size);

		memcpy(&e->store, &v, size);
		e->do_store = true;
	}
}

/* Run the SSE/MMX part; returns the SIGFPE si_code or 0 */
static int emu_vector(struct emu *e)
{
	union v128 a, s, r = {};
	bool write;
	int code = 0;

	kernel_fpu_begin();
	fpstate_prepare(e);
	if (e->mmx)
		mmx_prepare(e);

	vreg_read(e, e->reg, &a);
	if (e->memop)
		s = e->mem;
	else if (e->desc.flags & OPF_GPR)
		s = (union v128){ .q = { *gpr(e, e->rm) } };
	else
		vreg_read(e, e->rm, &s);

	if (e->map == 0x38 && e->desc.feature == X86_FEATURE_SSSE3) {
		emu_ssse3(e, &r, &a, &s);
		write = true;
	} else if (e->map == 0x3a && e->op == 0x0f) {
		emu_palignr(e, &r, &a, &s);
		write = true;
	} else if (e->map == 0x38) {
		write = emu_sse4_38(e, &r, &a, &s);
	} else {
		write = emu_sse4_3a(e, &r, &a, &s);
	}

	if (e->mxcsr_raised) {
		u32 mxcsr = e->fx->mxcsr | e->mxcsr_raised;
		u32 err = e->mxcsr_raised & ~(mxcsr >> 7) & MXCSR_FLAGS;

		e->fx->mxcsr = mxcsr;
		e->sse_dirty = true;
		if (err) {
			/* #XM: flags are updated, the destination is not */
			write = false;
			e->do_store = false;
			if (err & 0x001)
				code = FPE_FLTINV;
			else if (err & 0x004)
				code = FPE_FLTDIV;
			else if (err & 0x008)
				code = FPE_FLTOVF;
			else if (err & 0x012)
				code = FPE_FLTUND;
			else
				code = FPE_FLTRES;
		}
	}

	if (write)
		vreg_write(e, e->reg, &r);

	fpstate_commit(e);
	kernel_fpu_end();

	return code;
}

static bool sse_emulate(struct pt_regs *regs)
{
	unsigned char buf[MAX_INSN_SIZE];
	struct insn insn, *pinsn = &insn;
	struct emu e = {};
	bool p66 = false, pf2 = false, pf3 = false;
	insn_byte_t p;
	int nr, code;

	/* Do not interfere with uprobes' out-of-line single-stepping */
	if (uprobe_get_trap_addr(regs) != instruction_pointer(regs))
		return false;

	nr = insn_fetch_from_user(regs, buf);
	if (nr <= 0)
		return false;
	if (!insn_decode_from_regs(&insn, regs, buf, nr))
		return false;

	/* Legacy encodings only: no VEX/EVEX/XOP, no REX2 */
	if (insn.vex_prefix.nbytes || insn.rex_prefix.nbytes > 1)
		return false;
	if (insn.opcode.bytes[0] != 0x0f || insn.modrm.nbytes != 1)
		return false;

	for_each_insn_prefix(pinsn, p) {
		switch (p) {
		case 0xf0:		/* LOCK is #UD for all of these */
			return false;
		case 0x66:
			p66 = true;
			break;
		case 0xf2:
			pf2 = true;
			break;
		case 0xf3:
			pf3 = true;
			break;
		}
	}
	if (pf2 && pf3)
		return false;

	e.insn = &insn;
	e.regs = regs;
	e.pfx = pf2 ? PFX_F2 : pf3 ? PFX_F3 : p66 ? PFX_66 : PFX_NONE;
	e.has_rex = insn.rex_prefix.nbytes;
	e.rexw = e.has_rex && X86_REX_W(insn.rex_prefix.value);

	if (insn.opcode.nbytes == 3 &&
	    (insn.opcode.bytes[1] == 0x38 || insn.opcode.bytes[1] == 0x3a)) {
		e.map = insn.opcode.bytes[1];
		e.op = insn.opcode.bytes[2];
	} else if (insn.opcode.nbytes == 2) {
		e.map = 0x0f;
		e.op = insn.opcode.bytes[1];
	} else {
		return false;
	}

	if (!classify(&e))
		return false;
	if (boot_cpu_has(e.desc.feature))
		return false;
	if (e.map == 0x3a && insn.immediate.nbytes != 1)
		return false;

	e.imm = insn.immediate.value;
	e.reg = X86_MODRM_REG(insn.modrm.value);
	e.rm = X86_MODRM_RM(insn.modrm.value);
	if (!e.mmx) {
		if (e.has_rex && X86_REX_R(insn.rex_prefix.value))
			e.reg |= 8;
		if (e.has_rex && X86_REX_B(insn.rex_prefix.value))
			e.rm |= 8;
	}
	e.memop = X86_MODRM_MOD(insn.modrm.value) != 3;

	if (!e.memop && (e.desc.flags & OPF_MEMONLY))
		return false;

	pr_notice_once("emulating unsupported instructions for %s[%d], expect a large slowdown\n",
		       current->comm, task_pid_nr(current));

	if (e.memop) {
		e.addr = insn_get_addr_ref(&insn, regs);
		if ((unsigned long)e.addr == -1L) {
			force_sig(SIGSEGV);
			return true;
		}
		/* Legacy SSE m128 operands are #GP when misaligned */
		if ((e.desc.flags & OPF_ALIGN) && e.desc.memsz == 16 &&
		    !IS_ALIGNED((unsigned long)e.addr, 16)) {
			current->thread.error_code = 0;
			current->thread.trap_nr = X86_TRAP_GP;
			force_sig(SIGSEGV);
			return true;
		}
		if (!(e.desc.flags & OPF_STORE) &&
		    copy_from_user(&e.mem, e.addr, e.desc.memsz)) {
			force_sig_fault(SIGSEGV, SEGV_MAPERR, e.addr);
			return true;
		}
	}

	if (e.desc.flags & OPF_NOFPU) {
		emu_gpr(&e);
	} else {
		code = emu_vector(&e);
		if (code) {
			current->thread.error_code = 0;
			current->thread.trap_nr = X86_TRAP_XF;
			force_sig_fault(SIGFPE, code,
					(void __user *)uprobe_get_trap_addr(regs));
			return true;
		}
	}

	if (e.do_store && copy_to_user(e.addr, &e.store, e.desc.memsz)) {
		force_sig_fault(SIGSEGV, SEGV_MAPERR, e.addr);
		return true;
	}

	regs->ip += insn.length;

	/* The instruction completed: report a pending single-step trap */
	if (regs->flags & X86_EFLAGS_TF)
		send_sigtrap(regs, 0, TRAP_TRACE);

	return true;
}

/*
 * Called from the #UD handler with interrupts disabled. Returns true if the
 * instruction was emulated or a signal was raised for it.
 */
bool handle_sse_emulation(struct pt_regs *regs)
{
	bool handled;

	if (!sse_emu_enabled || !user_mode(regs))
		return false;

	local_irq_enable();
	handled = sse_emulate(regs);
	local_irq_disable();

	return handled;
}

static int __init sse_emu_init(void)
{
	static const struct { u16 feature; const char *name; } feats[] = {
		{ X86_FEATURE_SSSE3,	"ssse3" },
		{ X86_FEATURE_XMM4_1,	"sse4_1" },
		{ X86_FEATURE_XMM4_2,	"sse4_2" },
		{ X86_FEATURE_POPCNT,	"popcnt" },
		{ X86_FEATURE_MOVBE,	"movbe" },
	};
	char list[64] = "";
	unsigned int i;

	if (!sse_emu_enabled)
		return 0;

	for (i = 0; i < ARRAY_SIZE(feats); i++) {
		if (boot_cpu_has(feats[i].feature))
			continue;
		strlcat(list, " ", sizeof(list));
		strlcat(list, feats[i].name, sizeof(list));
	}
	if (list[0])
		pr_info("user space emulation enabled for:%s\n", list);
	return 0;
}
late_initcall(sse_emu_init);
