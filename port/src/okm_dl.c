/* dlopen, dlsym, dladdr --- a loader above openkal, for a static program.
 *
 * musl loads objects in its dynamic linker, which a static program does not
 * have, so a static musl answers dlopen with "Dynamic loading not supported"
 * (src/ldso/dlopen.c, a weak stub). This file is the strong definition, and it
 * is written above openkal because openkal says that is where a loader belongs
 * (openkal/exec.h; SPEC clause 11 entry 21): reading a format, relocating and
 * binding names are the same in every environment, and what a loader needs
 * from beneath is memory it may execute --- in parts, since an object's
 * instructions and its data lie at fixed distances in one region
 * (kal_exec_publish_part, openkal 0.15).
 *
 * WHAT A LOADED OBJECT BINDS TO. The names the program offers first, then
 * those of the objects loaded with RTLD_GLOBAL, then the object's own and those
 * of what it needs --- the order ELF's dynamic linking has always used. A
 * program offers names by being linked -static-pie with --export-dynamic:
 * its dynamic symbol table is what is searched (openkal-linux relocates such a
 * program when it starts). The order is also what makes an object built by a
 * toolchain that links every program with its C library usable here: the
 * copy of the C library inside the object is defined, and never reached,
 * because every name it defines is found in the program first. One C library,
 * one heap, one set of streams.
 *
 * WHAT IT DOES NOT DO. An object is never unloaded (dlclose succeeds and keeps
 * it, as musl's own dynamic linker does), so nothing it registered with atexit
 * can outlive its code. Initial-exec thread-local storage in a loaded object
 * is refused (okm_dl_reloc.c). A name a loaded object needs and nothing defines
 * fails the load under RTLD_NOW; under RTLD_LAZY a function is bound to one that
 * ends the program saying so, and a datum still fails the load.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "okm.h"
#include "okm_dl.h"
#include "dynlink.h"
#include "libc.h"
#include "lock.h"
#include "pthread_impl.h"

int __cxa_atexit(void (*)(void *), void *, void *);

/* openkal.exec is optional, and its partial form is 0.15's: an implementation
 * without them still links a program that never loads anything. */
#pragma weak kal_exec_alloc
#pragma weak kal_exec_free
#pragma weak kal_exec_granularity
#pragma weak kal_exec_publish_part

hidden int __okm_dl_machine(void);
hidden int __okm_dl_relocate(struct okm_dso *, const ElfW(Rela) *, size_t, int);
hidden void __okm_dl_relocate_packed(struct okm_dso *, const uintptr_t *, size_t);
hidden void __okm_dl_sync_instructions(unsigned char *, unsigned char *);

extern const ElfW(Dyn) _DYNAMIC[] __attribute__((__weak__, __visibility__("hidden")));
extern const ElfW(Ehdr) __ehdr_start __attribute__((__weak__, __visibility__("hidden")));

static struct okm_dso program;
static struct okm_dso *tail;

/* --- one lock, which a constructor that loads another object takes again --- */

static volatile int lock_word[1];
static pthread_t owner;
static int depth;

static void dl_lock(void)
{
	pthread_t self = __pthread_self();
	if (owner == self) { depth++; return; }
	LOCK(lock_word);
	owner = self;
	depth = 1;
}

static void dl_unlock(void)
{
	if (--depth == 0) {
		owner = 0;
		UNLOCK(lock_word);
	}
}

/* --- the program, as an object whose names can be looked up ------------------ */

static void read_dynamic(struct okm_dso *d, const ElfW(Dyn) *dyn)
{
	for (; dyn->d_tag != DT_NULL; dyn++) {
		const uintptr_t at = d->lm.l_addr + dyn->d_un.d_ptr;
		switch (dyn->d_tag) {
		case DT_SYMTAB:   d->syms = (const ElfW(Sym) *)at; break;
		case DT_STRTAB:   d->strings = (const char *)at; break;
		case DT_HASH:     d->hash = (const uint32_t *)at; break;
		case DT_GNU_HASH: d->gnu_hash = (const uint32_t *)at; break;
		case DT_SYMBOLIC: d->symbolic = 1; break;
		case DT_FLAGS:    if (dyn->d_un.d_val & DF_SYMBOLIC) d->symbolic = 1; break;
		}
	}
}

static void describe_program(void)
{
	if (program.is_program) return;
	program.is_program = 1;
	program.lm.l_name = "";
	program.refs = 1;
	program.global = 1;
	program.constructed = 1;
	const ElfW(Ehdr) *eh = &__ehdr_start;
	if (eh) {
		const ElfW(Phdr) *ph = (const ElfW(Phdr) *)((const char *)eh + eh->e_phoff);
		for (int i = 0; i < eh->e_phnum; i++)
			if (ph[i].p_type == PT_LOAD) {
				program.lm.l_addr = (uintptr_t)eh - ph[i].p_vaddr;
				break;
			}
		program.phdr = (ElfW(Phdr) *)ph;
		program.phnum = eh->e_phnum;
	}
	/* A program linked at a fixed address has no dynamic section and offers
	 * no names; one linked -static-pie offers those it was told to export. */
	if (_DYNAMIC) {
		program.lm.l_ld = (ElfW(Dyn) *)_DYNAMIC;
		read_dynamic(&program, _DYNAMIC);
	}
}

/* --- names ------------------------------------------------------------------ */

static uint32_t sysv_hash(const char *s)
{
	uint_fast32_t h = 0;
	while (*s) {
		h = 16 * h + (unsigned char)*s++;
		h ^= h >> 24 & 0xf0;
	}
	return h & 0xfffffff;
}

static uint32_t gnu_hash(const char *s)
{
	uint_fast32_t h = 5381;
	for (; *s; s++) h += h * 32 + (unsigned char)*s;
	return h;
}

static int defines(const ElfW(Sym) *s, int tls)
{
	if (s->st_shndx == SHN_UNDEF) return 0;
	const int bind = ELF64_ST_BIND(s->st_info), type = ELF64_ST_TYPE(s->st_info);
	if (bind != STB_GLOBAL && bind != STB_WEAK && bind != STB_GNU_UNIQUE) return 0;
	if (tls) return type == STT_TLS;
	return type == STT_NOTYPE || type == STT_OBJECT || type == STT_FUNC || type == STT_COMMON;
}

static const ElfW(Sym) *find(const struct okm_dso *d, const char *name, uint32_t gh, uint32_t sh, int tls)
{
	if (!d->syms || !d->strings) return 0;
	if (d->gnu_hash) {
		const uint32_t *h = d->gnu_hash;
		const uint32_t nbuckets = h[0], offset = h[1], words = h[2], shift = h[3];
		if (nbuckets == 0) return 0;
		const size_t *bloom = (const size_t *)(h + 4);
		const size_t bits = 8 * sizeof(size_t);
		const size_t word = bloom[(gh / bits) & (words - 1)];
		const size_t mask = (size_t)1 << (gh % bits) | (size_t)1 << ((gh >> shift) % bits);
		if ((word & mask) != mask) return 0;
		const uint32_t *buckets = (const uint32_t *)(bloom + words);
		const uint32_t *chain = buckets + nbuckets;
		uint32_t i = buckets[gh % nbuckets];
		if (i < offset) return 0;
		for (;; i++) {
			const uint32_t c = chain[i - offset];
			if ((gh | 1) == (c | 1) && !strcmp(name, d->strings + d->syms[i].st_name) && defines(&d->syms[i], tls))
				return &d->syms[i];
			if (c & 1) return 0;
		}
	}
	if (d->hash) {
		const uint32_t nbuckets = d->hash[0];
		const uint32_t *buckets = d->hash + 2, *chain = buckets + nbuckets;
		for (uint32_t i = buckets[sh % nbuckets]; i; i = chain[i])
			if (!strcmp(name, d->strings + d->syms[i].st_name) && defines(&d->syms[i], tls))
				return &d->syms[i];
	}
	return 0;
}

/* How many entries the dynamic symbol table has, which it does not state:
 * DT_HASH's chain is as long as the table, and DT_GNU_HASH's last chain ends
 * at its last entry. */
static size_t symbol_count(const struct okm_dso *d)
{
	if (d->hash) return d->hash[1];
	if (!d->gnu_hash) return 0;
	const uint32_t *h = d->gnu_hash;
	const uint32_t nbuckets = h[0], offset = h[1], words = h[2];
	const uint32_t *buckets = (const uint32_t *)((const size_t *)(h + 4) + words);
	const uint32_t *chain = buckets + nbuckets;
	uint32_t last = 0;
	for (uint32_t b = 0; b < nbuckets; b++)
		if (buckets[b] > last) last = buckets[b];
	if (last < offset) return offset;
	while (!(chain[last - offset] & 1)) last++;
	return last + 1;
}

static const ElfW(Sym) *find_in_needed(struct okm_dso *d, const char *name, uint32_t gh, uint32_t sh, int tls,
                                       struct okm_dso **def, int level)
{
	const ElfW(Sym) *s = find(d, name, gh, sh, tls);
	if (s) { *def = d; return s; }
	if (level > 16) return 0;
	for (struct okm_dso **n = d->deps; n && *n; n++)
		if ((s = find_in_needed(*n, name, gh, sh, tls, def, level + 1))) return s;
	return 0;
}

hidden int __okm_dl_resolve(struct okm_dso *from, const char *name, int tls,
                            struct okm_dso **def, const ElfW(Sym) **sym)
{
	const uint32_t gh = gnu_hash(name), sh = sysv_hash(name);
	const ElfW(Sym) *s;
	if (from->symbolic && (s = find(from, name, gh, sh, tls))) { *def = from; *sym = s; return 0; }
	if ((s = find(&program, name, gh, sh, tls))) { *def = &program; *sym = s; return 0; }
	for (struct okm_dso *d = __okm_dl_head; d; d = d->next)
		if (d->global && (s = find(d, name, gh, sh, tls))) { *def = d; *sym = s; return 0; }
	if ((s = find_in_needed(from, name, gh, sh, tls, def, 0))) { *sym = s; return 0; }
	return -1;
}

hidden void __okm_dl_unresolved(void)
{
	static const char m[] = "openkal-musl: a loaded object called a function nothing defines"
	                        " (it was loaded with RTLD_LAZY; RTLD_NOW names it)\n";
	kal_abort(m, sizeof m - 1);
}

/* --- thread-local storage: a number for each module that has any ------------ */

#define OKM_TLS_MODULES 1024
static struct okm_dso *tls_modules[OKM_TLS_MODULES];
static size_t tls_next = 1;

hidden struct okm_dso *__okm_dl_tls_module(size_t id)
{
	return id && id < OKM_TLS_MODULES ? __atomic_load_n(&tls_modules[id], __ATOMIC_ACQUIRE) : 0;
}

/* --- reading an object ------------------------------------------------------- */

static int read_at(int fd, void *buf, size_t n, off_t at)
{
	if (lseek(fd, at, SEEK_SET) != at) return -1;
	for (size_t done = 0; done < n;) {
		const ssize_t r = read(fd, (char *)buf + done, n - done);
		if (r <= 0) return -1;
		done += (size_t)r;
	}
	return 0;
}

static struct okm_dso *open_object(const char *name, struct okm_dso *requester, int mode);

/* The names a C and C++ program is linked with as shared libraries elsewhere.
 * Here the program carries them, so an object that records one as needed has
 * it already. */
static int provided_by_program(const char *name)
{
	static const char *const runtime[] = {
		"libc.so", "libm.so", "libdl.so", "libpthread.so", "librt.so", "libutil.so",
		"libxnet.so", "libresolv.so", "libcrypt.so", "libc++.so", "libc++abi.so",
		"libunwind.so", "libgcc_s.so", "libatomic.so", 0
	};
	if (!strncmp(name, "ld-musl-", 8)) return 1;
	for (int i = 0; runtime[i]; i++) {
		const size_t n = strlen(runtime[i]);
		if (!strncmp(name, runtime[i], n) && (name[n] == 0 || name[n] == '.')) return 1;
	}
	return 0;
}

static void unmap(struct okm_dso *d)
{
	if (d->base) kal_exec_free(d->base, d->span);
	free(d->phdr);
	free(d->deps);
	free(d->lm.l_name);
	free(d);
}

static struct okm_dso *map_object(const char *path, int mode)
{
	const int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		__dl_seterr("Error loading shared library %s: %m", path);
		return 0;
	}
	struct okm_dso *d = calloc(1, sizeof *d);
	ElfW(Ehdr) eh;
	if (!d || read_at(fd, &eh, sizeof eh, 0) != 0 || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
	    eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_type != ET_DYN ||
	    eh.e_machine != __okm_dl_machine() || eh.e_phentsize != sizeof(ElfW(Phdr))) {
		__dl_seterr("Error loading shared library %s: not a shared object for this machine", path);
		goto fail;
	}
	d->lm.l_name = strdup(path);
	d->phnum = eh.e_phnum;
	d->phdr = malloc(d->phnum * sizeof *d->phdr);
	if (!d->lm.l_name || !d->phdr || read_at(fd, d->phdr, d->phnum * sizeof *d->phdr, eh.e_phoff) != 0) {
		__dl_seterr("Error loading shared library %s: cannot read its program headers", path);
		goto fail;
	}

	/* One region for every loaded segment, in the environment's quantum. An
	 * executable segment is published and a writable one is not, so no
	 * quantum may hold some of each: an object linked for a finer page than
	 * this environment protects is refused here, before anything is reserved. */
	const size_t g = kal_exec_granularity();
	uintptr_t lo = UINTPTR_MAX, hi = 0;
	for (size_t i = 0; i < d->phnum; i++) {
		const ElfW(Phdr) *p = &d->phdr[i];
		if (p->p_type != PT_LOAD) continue;
		if (p->p_vaddr < lo) lo = p->p_vaddr;
		if (p->p_vaddr + p->p_memsz > hi) hi = p->p_vaddr + p->p_memsz;
	}
	if (hi == 0) {
		__dl_seterr("Error loading shared library %s: no loadable segment", path);
		goto fail;
	}
	lo &= -(uintptr_t)g;
	hi = (hi + g - 1) & -(uintptr_t)g;
	for (size_t i = 0; i < d->phnum; i++) {
		const ElfW(Phdr) *x = &d->phdr[i];
		if (x->p_type != PT_LOAD || !(x->p_flags & PF_X)) continue;
		const uintptr_t xa = x->p_vaddr & -(uintptr_t)g, xb = (x->p_vaddr + x->p_memsz + g - 1) & -(uintptr_t)g;
		for (size_t k = 0; k < d->phnum; k++) {
			const ElfW(Phdr) *w = &d->phdr[k];
			if (w->p_type != PT_LOAD || !(w->p_flags & PF_W)) continue;
			if (w->p_vaddr < xb && w->p_vaddr + w->p_memsz > xa) {
				__dl_seterr("Error loading shared library %s: its code and its data share a page of %zu bytes,"
				            " the quantum this environment protects in", path, g);
				goto fail;
			}
		}
	}
	d->span = hi - lo;
	d->base = kal_exec_alloc(d->span);
	if (!d->base) {
		__dl_seterr("Error loading shared library %s: no memory to place it in", path);
		goto fail;
	}
	memset(d->base, 0, d->span);
	d->lm.l_addr = (uintptr_t)d->base - lo;
	for (size_t i = 0; i < d->phnum; i++) {
		const ElfW(Phdr) *p = &d->phdr[i];
		if (p->p_type == PT_LOAD && p->p_filesz &&
		    read_at(fd, (void *)(d->lm.l_addr + p->p_vaddr), p->p_filesz, p->p_offset) != 0) {
			__dl_seterr("Error loading shared library %s: cannot read a segment", path);
			goto fail;
		}
	}
	close(fd);

	const ElfW(Dyn) *dyn = 0;
	for (size_t i = 0; i < d->phnum; i++) {
		const ElfW(Phdr) *p = &d->phdr[i];
		if (p->p_type == PT_DYNAMIC) dyn = (const ElfW(Dyn) *)(d->lm.l_addr + p->p_vaddr);
		if (p->p_type == PT_TLS && p->p_memsz) {
			d->tls_image = (const unsigned char *)(d->lm.l_addr + p->p_vaddr);
			d->tls_filesz = p->p_filesz;
			d->tls_memsz = p->p_memsz;
			d->tls_align = p->p_align ? p->p_align : 1;
		}
	}
	if (!dyn) {
		__dl_seterr("Error loading shared library %s: no dynamic section", path);
		unmap(d);
		return 0;
	}
	d->lm.l_ld = (ElfW(Dyn) *)dyn;
	read_dynamic(d, dyn);
	d->refs = 1;
	d->global = (mode & RTLD_GLOBAL) != 0;

	const ElfW(Rela) *rela = 0, *jmprel = 0;
	const uintptr_t *relr = 0;
	size_t relasz = 0, jmprelsz = 0, relrsz = 0, needed = 0;
	for (const ElfW(Dyn) *e = dyn; e->d_tag != DT_NULL; e++) {
		const uintptr_t at = d->lm.l_addr + e->d_un.d_ptr;
		switch (e->d_tag) {
		case DT_NEEDED:        needed++; break;
		case DT_SONAME:        d->soname = d->strings + e->d_un.d_val; break;
		case DT_RELA:          rela = (const ElfW(Rela) *)at; break;
		case DT_RELASZ:        relasz = e->d_un.d_val; break;
		case DT_JMPREL:        jmprel = (const ElfW(Rela) *)at; break;
		case DT_PLTRELSZ:      jmprelsz = e->d_un.d_val; break;
		case DT_RELR:          relr = (const uintptr_t *)at; break;
		case DT_RELRSZ:        relrsz = e->d_un.d_val; break;
		case DT_INIT:          d->init = (void (*)(void))at; break;
		case DT_INIT_ARRAY:    d->init_array = (void (**)(void))at; break;
		case DT_INIT_ARRAYSZ:  d->init_count = e->d_un.d_val / sizeof(void *); break;
		case DT_FINI:          d->fini = (void (*)(void))at; break;
		case DT_FINI_ARRAY:    d->fini_array = (void (**)(void))at; break;
		case DT_FINI_ARRAYSZ:  d->fini_count = e->d_un.d_val / sizeof(void *); break;
		case DT_PLTREL:
			if (e->d_un.d_val != DT_RELA) {
				__dl_seterr("Error loading shared library %s: relocations without addends", path);
				unmap(d);
				return 0;
			}
			break;
		}
	}

	/* What it needs, loaded first so that its names are there to bind to. */
	d->deps = calloc(needed + 1, sizeof *d->deps);
	if (!d->deps) {
		__dl_seterr("Error loading shared library %s: out of memory", path);
		unmap(d);
		return 0;
	}
	size_t n = 0;
	for (const ElfW(Dyn) *e = dyn; e->d_tag != DT_NULL; e++) {
		if (e->d_tag != DT_NEEDED) continue;
		const char *want = d->strings + e->d_un.d_val;
		if (provided_by_program(want)) continue;
		struct okm_dso *dep = open_object(want, d, mode & ~RTLD_NOLOAD);
		if (!dep) {
			unmap(d);
			return 0;
		}
		if (dep != &program) d->deps[n++] = dep;
	}

	if (d->tls_memsz) {
		if (tls_next >= OKM_TLS_MODULES) {
			__dl_seterr("Error loading shared library %s: too many objects with thread-local storage", path);
			unmap(d);
			return 0;
		}
		d->tls_id = tls_next++;
	}

	const int lazy = !(mode & RTLD_NOW);
	__okm_dl_relocate_packed(d, relr, relrsz);
	if (__okm_dl_relocate(d, rela, relasz, lazy) != 0 || __okm_dl_relocate(d, jmprel, jmprelsz, lazy) != 0) {
		unmap(d);
		return 0;
	}

	/* Every word is written; the instructions become executable, the rest
	 * stays writable. */
	for (size_t i = 0; i < d->phnum; i++) {
		const ElfW(Phdr) *p = &d->phdr[i];
		if (p->p_type != PT_LOAD || !(p->p_flags & PF_X)) continue;
		const uintptr_t from = (p->p_vaddr & -(uintptr_t)g) - lo;
		const uintptr_t to = ((p->p_vaddr + p->p_memsz + g - 1) & -(uintptr_t)g) - lo;
		__okm_dl_sync_instructions(d->base + from, d->base + to);
		const int rc = kal_exec_publish_part(d->base, from, to - from);
		if (rc != kal_ok) {
			__dl_seterr("Error loading shared library %s: the environment refused to make its code executable (%d)", path, rc);
			unmap(d);
			return 0;
		}
	}

	if (d->tls_id) __atomic_store_n(&tls_modules[d->tls_id], d, __ATOMIC_RELEASE);
	/* Complete: the unwinder may see it now, and a constructor that throws
	 * needs it to. */
	if (tail) __atomic_store_n(&tail->next, d, __ATOMIC_RELEASE);
	else __atomic_store_n(&__okm_dl_head, d, __ATOMIC_RELEASE);
	tail = d;
	__atomic_fetch_add(&__okm_dl_adds, 1, __ATOMIC_RELEASE);
	return d;

fail:
	close(fd);
	if (d) unmap(d);
	return 0;
}

static struct okm_dso *loaded(const char *name)
{
	const char *slash = strrchr(name, '/');
	for (struct okm_dso *d = __okm_dl_head; d; d = d->next) {
		if (!strcmp(d->lm.l_name, name)) return d;
		if (!slash && d->soname && !strcmp(d->soname, name)) return d;
	}
	return 0;
}

/* A directory list, with $ORIGIN the directory of the object that asks. */
static int search(const char *list, const char *origin, const char *name, char *out, size_t cap)
{
	for (const char *p = list; p && *p;) {
		const char *end = strchr(p, ':');
		const size_t n = end ? (size_t)(end - p) : strlen(p);
		int w;
		if (n >= 7 && !strncmp(p, "$ORIGIN", 7))
			w = snprintf(out, cap, "%s%.*s/%s", origin, (int)(n - 7), p + 7, name);
		else
			w = snprintf(out, cap, "%.*s/%s", (int)n, p, name);
		if (w > 0 && (size_t)w < cap && access(out, R_OK) == 0) return 0;
		p = end ? end + 1 : 0;
	}
	return -1;
}

static struct okm_dso *open_object(const char *name, struct okm_dso *requester, int mode)
{
	if (provided_by_program(name)) return &program;
	struct okm_dso *d = loaded(name);
	char path[4096];
	if (!d && !strchr(name, '/')) {
		/* Where an object's own record says to look, then LD_LIBRARY_PATH. */
		char origin[4096] = ".";
		if (requester && requester->lm.l_name) {
			const char *slash = strrchr(requester->lm.l_name, '/');
			if (slash) snprintf(origin, sizeof origin, "%.*s", (int)(slash - requester->lm.l_name), requester->lm.l_name);
		}
		int found = -1;
		for (const ElfW(Dyn) *e = requester ? requester->lm.l_ld : 0; found != 0 && e && e->d_tag != DT_NULL; e++)
			if (e->d_tag == DT_RUNPATH || e->d_tag == DT_RPATH)
				found = search(requester->strings + e->d_un.d_val, origin, name, path, sizeof path);
		if (found != 0) found = search(getenv("LD_LIBRARY_PATH"), origin, name, path, sizeof path);
		if (found != 0) {
			__dl_seterr("Error loading shared library %s: No such file or directory", name);
			return 0;
		}
		name = path;
		d = loaded(name);
	}
	if (d) {
		d->refs++;
		if (mode & RTLD_GLOBAL) d->global = 1;
		return d;
	}
	if (mode & RTLD_NOLOAD) return 0;
	return map_object(name, mode);
}

/* --- constructors ------------------------------------------------------------ */

static void finish(void *p)
{
	struct okm_dso *d = p;
	for (size_t i = d->fini_count; i-- > 0;)
		if (d->fini_array[i] && d->fini_array[i] != (void (*)(void))-1) d->fini_array[i]();
	if (d->fini) d->fini();
}

static void construct(struct okm_dso *d)
{
	if (d->constructed) return;
	d->constructed = 1;
	for (struct okm_dso **n = d->deps; n && *n; n++) construct(*n);
	/* Its destructors run at exit, after those its constructors register:
	 * so they are registered first. */
	if (d->fini || d->fini_count) __cxa_atexit(finish, d, 0);
	if (d->init) d->init();
	for (size_t i = 0; i < d->init_count; i++)
		if (d->init_array[i] && d->init_array[i] != (void (*)(void))-1) d->init_array[i]();
}

/* --- the interface ------------------------------------------------------------ */

void *dlopen(const char *file, int mode)
{
	describe_program();
	if (!file) return &program;
	if (!kal_exec_alloc || !kal_exec_granularity || !kal_exec_publish_part) {
		__dl_seterr("Dynamic loading not supported: the openkal implementation beneath provides"
		            " no memory a program may execute in parts (openkal.exec 0.15)");
		return 0;
	}
	dl_lock();
	struct okm_dso *d = open_object(file, 0, mode);
	if (d && d != &program) construct(d);
	dl_unlock();
	return d;
}

hidden int __dl_invalid_handle(void *h)
{
	if (h == &program) return 0;
	for (struct okm_dso *d = __okm_dl_head; d; d = d->next)
		if (d == h) return 0;
	__dl_seterr("Invalid library handle %p", h);
	return 1;
}

static struct okm_dso *containing(const void *addr)
{
	const uintptr_t a = (uintptr_t)addr;
	for (struct okm_dso *d = __okm_dl_head; d; d = d->next)
		if (a >= (uintptr_t)d->base && a < (uintptr_t)d->base + d->span) return d;
	for (size_t i = 0; i < program.phnum; i++) {
		const ElfW(Phdr) *p = &program.phdr[i];
		if (p->p_type == PT_LOAD && a >= program.lm.l_addr + p->p_vaddr &&
		    a < program.lm.l_addr + p->p_vaddr + p->p_memsz)
			return &program;
	}
	return 0;
}

hidden void *__dlsym(void *restrict handle, const char *restrict name, void *restrict ra)
{
	describe_program();
	const uint32_t gh = gnu_hash(name), sh = sysv_hash(name);
	struct okm_dso *def = 0;
	const ElfW(Sym) *s = 0;
	dl_lock();
	if (handle == RTLD_DEFAULT || handle == &program) {
		if ((s = find(&program, name, gh, sh, 0))) def = &program;
		for (struct okm_dso *d = __okm_dl_head; !s && d; d = d->next)
			if (d->global && (s = find(d, name, gh, sh, 0))) def = d;
	} else if (handle == RTLD_NEXT) {
		/* The objects after the caller's, in load order. */
		struct okm_dso *caller = containing(ra), *d = caller == &program ? __okm_dl_head : caller ? caller->next : 0;
		for (; !s && d; d = d->next)
			if ((s = find(d, name, gh, sh, 0))) def = d;
	} else if (__dl_invalid_handle(handle) == 0) {
		s = find_in_needed(handle, name, gh, sh, 0, &def, 0);
		if (!s && (s = find_in_needed(handle, name, gh, sh, 1, &def, 0))) {
			void *p = __okm_tls_address(def->tls_id, s->st_value);
			dl_unlock();
			return p;
		}
	} else {
		dl_unlock();
		return 0;
	}
	dl_unlock();
	if (!s) {
		__dl_seterr("Symbol not found: %s", name);
		return 0;
	}
	return (void *)(def->lm.l_addr + s->st_value);
}

int dladdr(const void *addr, Dl_info *info)
{
	describe_program();
	struct okm_dso *d = containing(addr);
	if (!d) return 0;
	info->dli_fname = d == &program ? __progname_full : d->lm.l_name;
	info->dli_fbase = d == &program ? (void *)&__ehdr_start : d->base;
	info->dli_sname = 0;
	info->dli_saddr = 0;
	const size_t count = symbol_count(d);
	uintptr_t best = 0;
	for (size_t i = 1; i < count; i++) {
		const ElfW(Sym) *s = &d->syms[i];
		const int type = ELF64_ST_TYPE(s->st_info);
		if (s->st_shndx == SHN_UNDEF || (type != STT_FUNC && type != STT_OBJECT)) continue;
		const uintptr_t at = d->lm.l_addr + s->st_value;
		if (at <= (uintptr_t)addr && at > best && (s->st_size == 0 || (uintptr_t)addr < at + s->st_size)) {
			best = at;
			info->dli_sname = d->strings + s->st_name;
			info->dli_saddr = (void *)at;
		}
	}
	return 1;
}
