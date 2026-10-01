/* Relocating a loaded object: the part of the loader that differs by
 * architecture. okm_dl.c reads the object and decides which names bind where;
 * this file writes the words.
 *
 * A shared object carries three kinds of relocation, and each is answered here
 * as the psABI states it:
 *
 *   relative      the object's own addresses: where it was placed, plus the
 *                 addend;
 *   by name       a word that holds the address of a name: a pointer in data,
 *                 a slot the object's calls go through;
 *   thread-local  the module a variable belongs to, and its offset in that
 *                 module's storage (okm_tls_get_addr.c).
 *
 * Every word is written before any part of the object is published, so an
 * object that relocates its own instructions is relocated like any other.
 * Initial-exec thread-local storage in a loaded object is refused: it asks for
 * room beside the program's own storage, reserved when each context started,
 * and none was.
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>

#include "okm_dl.h"
#include "dynlink.h"

hidden int __okm_dl_resolve(struct okm_dso *from, const char *name, int tls,
                            struct okm_dso **def, const ElfW(Sym) **sym);
hidden void __okm_dl_unresolved(void);

#if defined(__x86_64__)
#define OKM_R_NONE      R_X86_64_NONE
#define OKM_R_ABS       R_X86_64_64
#define OKM_R_GLOB_DAT  R_X86_64_GLOB_DAT
#define OKM_R_JUMP_SLOT R_X86_64_JUMP_SLOT
#define OKM_R_RELATIVE  R_X86_64_RELATIVE
#define OKM_R_DTPMOD    R_X86_64_DTPMOD64
#define OKM_R_DTPOFF    R_X86_64_DTPOFF64
#define OKM_R_TPOFF     R_X86_64_TPOFF64
#define OKM_DTP_OFFSET  0
#elif defined(__aarch64__)
#define OKM_R_NONE      R_AARCH64_NONE
#define OKM_R_ABS       R_AARCH64_ABS64
#define OKM_R_GLOB_DAT  R_AARCH64_GLOB_DAT
#define OKM_R_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define OKM_R_RELATIVE  R_AARCH64_RELATIVE
#define OKM_R_DTPMOD    R_AARCH64_TLS_DTPMOD64
#define OKM_R_DTPOFF    R_AARCH64_TLS_DTPREL64
#define OKM_R_TPOFF     R_AARCH64_TLS_TPREL64
#define OKM_R_TLSDESC   R_AARCH64_TLSDESC
#define OKM_DTP_OFFSET  0
#elif defined(__riscv) && __riscv_xlen == 64
#define OKM_R_NONE      R_RISCV_NONE
#define OKM_R_ABS       R_RISCV_64
#define OKM_R_GLOB_DAT  R_RISCV_64
#define OKM_R_JUMP_SLOT R_RISCV_JUMP_SLOT
#define OKM_R_RELATIVE  R_RISCV_RELATIVE
#define OKM_R_DTPMOD    R_RISCV_TLS_DTPMOD64
#define OKM_R_DTPOFF    R_RISCV_TLS_DTPREL64
#define OKM_R_TPOFF     R_RISCV_TLS_TPREL64
/* The offset this architecture's psABI places between a module's storage and
 * the value its thread-local references carry. */
#define OKM_DTP_OFFSET  0x800
#else
#error "okm_dl_reloc.c: no relocations are written here for this architecture"
#endif

/* The machine this process runs, which a loaded object must be built for. */
hidden int __okm_dl_machine(void)
{
#if defined(__x86_64__)
	return EM_X86_64;
#elif defined(__aarch64__)
	return EM_AARCH64;
#else
	return EM_RISCV;
#endif
}

#ifdef OKM_R_TLSDESC
/* A TLS descriptor: the function a thread-local reference calls, and the
 * argument it calls it with. This architecture's toolchains reach a loaded
 * module's thread-local variables only this way. The function returns the
 * variable's address less the thread pointer, and preserves every register but
 * x0: so it saves what the C call it makes may clobber, and asks the same
 * per-context table __tls_get_addr does (okm_tls_get_addr.c). Every call takes
 * that path; a faster one would read the table from here, which a shared
 * object that carries this file could then not be linked with. */
struct okm_tlsdesc { size_t id, offset; };
hidden ptrdiff_t __okm_tlsdesc_dynamic(struct okm_tlsdesc **);
__asm__(
".text\n"
".global __okm_tlsdesc_dynamic\n"
".hidden __okm_tlsdesc_dynamic\n"
".type __okm_tlsdesc_dynamic,%function\n"
"__okm_tlsdesc_dynamic:\n"
"	sub sp, sp, #560\n"
"	stp x29, x30, [sp]\n"
"	mov x29, sp\n"
"	stp x1, x2, [sp, #16]\n"
"	stp x3, x4, [sp, #32]\n"
"	stp x5, x6, [sp, #48]\n"
"	stp x7, x8, [sp, #64]\n"
"	stp x9, x10, [sp, #80]\n"
"	stp x11, x12, [sp, #96]\n"
"	stp x13, x14, [sp, #112]\n"
"	stp x15, x16, [sp, #128]\n"
"	stp x17, x18, [sp, #144]\n"
"	stp q0, q1, [sp, #160]\n"
"	stp q2, q3, [sp, #192]\n"
"	stp q4, q5, [sp, #224]\n"
"	stp q6, q7, [sp, #256]\n"
"	stp q16, q17, [sp, #288]\n"
"	stp q18, q19, [sp, #320]\n"
"	stp q20, q21, [sp, #352]\n"
"	stp q22, q23, [sp, #384]\n"
"	stp q24, q25, [sp, #416]\n"
"	stp q26, q27, [sp, #448]\n"
"	stp q28, q29, [sp, #480]\n"
"	stp q30, q31, [sp, #512]\n"
"	ldr x0, [x0, #8]\n"
"	ldp x0, x1, [x0]\n"
"	bl __okm_tls_address\n"
"	mrs x1, tpidr_el0\n"
"	sub x0, x0, x1\n"
"	ldp q30, q31, [sp, #512]\n"
"	ldp q28, q29, [sp, #480]\n"
"	ldp q26, q27, [sp, #448]\n"
"	ldp q24, q25, [sp, #416]\n"
"	ldp q22, q23, [sp, #384]\n"
"	ldp q20, q21, [sp, #352]\n"
"	ldp q18, q19, [sp, #320]\n"
"	ldp q16, q17, [sp, #288]\n"
"	ldp q6, q7, [sp, #256]\n"
"	ldp q4, q5, [sp, #224]\n"
"	ldp q2, q3, [sp, #192]\n"
"	ldp q0, q1, [sp, #160]\n"
"	ldp x17, x18, [sp, #144]\n"
"	ldp x15, x16, [sp, #128]\n"
"	ldp x13, x14, [sp, #112]\n"
"	ldp x11, x12, [sp, #96]\n"
"	ldp x9, x10, [sp, #80]\n"
"	ldp x7, x8, [sp, #64]\n"
"	ldp x5, x6, [sp, #48]\n"
"	ldp x3, x4, [sp, #32]\n"
"	ldp x1, x2, [sp, #16]\n"
"	ldp x29, x30, [sp]\n"
"	add sp, sp, #560\n"
"	ret\n"
".size __okm_tlsdesc_dynamic, .-__okm_tlsdesc_dynamic\n"
);
#endif

static int one(struct okm_dso *d, const ElfW(Rela) *r, int lazy)
{
	const size_t type = ELF64_R_TYPE(r->r_info);
	const size_t index = ELF64_R_SYM(r->r_info);
	uintptr_t *where = (uintptr_t *)(d->lm.l_addr + r->r_offset);

	if (type == OKM_R_NONE) return 0;
	if (type == OKM_R_RELATIVE) {
		*where = d->lm.l_addr + r->r_addend;
		return 0;
	}

	/* The name the word refers to, and who defines it. A local symbol, and
	 * index 0 in a thread-local relocation, mean the object itself. */
	struct okm_dso *def = d;
	const ElfW(Sym) *sym = index ? &d->syms[index] : 0;
	const char *name = sym ? d->strings + sym->st_name : "";
	int tls = type == OKM_R_DTPMOD || type == OKM_R_DTPOFF || type == OKM_R_TPOFF;
#ifdef OKM_R_TLSDESC
	tls = tls || type == OKM_R_TLSDESC;
#endif
	if (sym && ELF64_ST_BIND(sym->st_info) != STB_LOCAL) {
		const ElfW(Sym) *found = 0;
		if (__okm_dl_resolve(d, name, tls, &def, &found) != 0) {
			def = 0;
			sym = 0;
			if (ELF64_ST_BIND(d->syms[index].st_info) == STB_WEAK) {
				/* An undefined weak name is null, as the link would have
				 * made it. */
			} else if (type == OKM_R_JUMP_SLOT && lazy) {
				/* Bound to a function that says what happened, not left to
				 * jump into the object's own stub: RTLD_LAZY lets an object
				 * load whose unreachable code names what nothing defines, the
				 * C library a plugin carries being the usual case. */
				*where = (uintptr_t)__okm_dl_unresolved;
				return 0;
			} else {
				__dl_seterr("Error relocating %s: %s: symbol not found", d->lm.l_name, name);
				return -1;
			}
		} else {
			sym = found;
		}
	}
	const uintptr_t value = def && sym ? def->lm.l_addr + sym->st_value : 0;

	switch (type) {
	case OKM_R_ABS:
#if OKM_R_GLOB_DAT != OKM_R_ABS
	case OKM_R_GLOB_DAT:
#endif
	case OKM_R_JUMP_SLOT:
		*where = value + r->r_addend;
		return 0;
	case OKM_R_DTPMOD:
		*where = def ? def->tls_id : 0;
		return 0;
	case OKM_R_DTPOFF:
		*where = (sym ? sym->st_value : 0) + r->r_addend - OKM_DTP_OFFSET;
		return 0;
#ifdef OKM_R_TLSDESC
	case OKM_R_TLSDESC: {
		struct okm_tlsdesc *arg = malloc(sizeof *arg);
		if (!arg) {
			__dl_seterr("Error relocating %s: out of memory", d->lm.l_name);
			return -1;
		}
		arg->id = def ? def->tls_id : 0;
		arg->offset = (sym ? sym->st_value : 0) + r->r_addend;
		where[0] = (uintptr_t)__okm_tlsdesc_dynamic;
		where[1] = (uintptr_t)arg;
		return 0;
	}
#endif
	case OKM_R_TPOFF:
		__dl_seterr("Error relocating %s: %s: initial-exec thread-local storage in a loaded object", d->lm.l_name, name);
		return -1;
	default:
		__dl_seterr("Error relocating %s: unsupported relocation type %zu", d->lm.l_name, type);
		return -1;
	}
}

/* A table of relocations with addends (every 64-bit psABI here uses them). */
hidden int __okm_dl_relocate(struct okm_dso *d, const ElfW(Rela) *table, size_t bytes, int lazy)
{
	for (size_t i = 0; table && i < bytes / sizeof *table; i++)
		if (one(d, &table[i], lazy) != 0) return -1;
	return 0;
}

/* The packed form of relative relocations (DT_RELR): an even entry is an
 * address, relocated, and each odd entry after it describes the words that
 * follow, one bit each. */
hidden void __okm_dl_relocate_packed(struct okm_dso *d, const uintptr_t *table, size_t bytes)
{
	uintptr_t *where = 0;
	for (size_t i = 0; table && i < bytes / sizeof *table; i++) {
		if ((table[i] & 1) == 0) {
			where = (uintptr_t *)(d->lm.l_addr + table[i]);
			*where++ += d->lm.l_addr;
		} else {
			uintptr_t bits = table[i] >> 1;
			for (size_t k = 0; bits; k++, bits >>= 1)
				if (bits & 1) where[k] += d->lm.l_addr;
			where += 8 * sizeof(uintptr_t) - 1;
		}
	}
}

/* Bytes written through the data path, about to be fetched as instructions.
 * x86_64 keeps the two coherent; the others are told, by the instructions their
 * architecture has for it --- not by the compiler's builtin, which becomes a
 * call into its support library there (openkal-linux's exec.cpp records the
 * same choice). */
hidden void __okm_dl_sync_instructions(unsigned char *begin, unsigned char *end)
{
#if defined(__aarch64__)
	uint64_t ctr;
	__asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
	const uintptr_t dline = 4u << ((ctr >> 16) & 15), iline = 4u << (ctr & 15);
	for (uintptr_t p = (uintptr_t)begin & ~(dline - 1); p < (uintptr_t)end; p += dline)
		__asm__ volatile("dc cvau, %0" :: "r"(p) : "memory");
	__asm__ volatile("dsb ish" ::: "memory");
	for (uintptr_t p = (uintptr_t)begin & ~(iline - 1); p < (uintptr_t)end; p += iline)
		__asm__ volatile("ic ivau, %0" :: "r"(p) : "memory");
	__asm__ volatile("dsb ish\n\tisb" ::: "memory");
#elif defined(__riscv)
	(void)begin; (void)end;
	__asm__ volatile("fence.i" ::: "memory");
#else
	(void)begin; (void)end;
#endif
}
