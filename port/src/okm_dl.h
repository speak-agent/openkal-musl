/* The objects this process has loaded, as the loader (okm_dl.c), the unwinder's
 * enquiry (okm_phdr.c) and thread-local storage (okm_tls_get_addr.c) share
 * them. ELF only: the formats of the other two systems have no program headers
 * and are loaded differently.
 */
#ifndef OKM_DL_H
#define OKM_DL_H

#include <features.h>
#include <elf.h>
#include <link.h>
#include <stddef.h>
#include <stdint.h>

struct okm_dso {
	/* First, so that the handle dlopen returns is the link map dlinfo hands
	 * out for RTLD_DI_LINKMAP --- musl's own arrangement. l_addr is the
	 * difference between where the object is and where it was linked. */
	struct link_map lm;

	/* The next object in load order. The list only grows, and an entry is
	 * published after it is complete, so a reader --- the unwinder, during an
	 * exception thrown by a constructor while the loader holds its lock ---
	 * walks it without taking that lock. */
	struct okm_dso *next;         /* __atomic_load_n / __atomic_store_n */

	ElfW(Phdr) *phdr;             /* a copy of the object's program headers */
	size_t phnum;

	unsigned char *base;          /* the region kal_exec_alloc reserved */
	size_t span;

	const ElfW(Sym) *syms;
	const char *strings;
	const uint32_t *hash;         /* DT_HASH, or null */
	const uint32_t *gnu_hash;     /* DT_GNU_HASH, or null */
	const char *soname;

	/* Thread-local storage: the module's number (0 when it has none) and its
	 * initial image. */
	size_t tls_id;
	const unsigned char *tls_image;
	size_t tls_filesz, tls_memsz, tls_align;

	struct okm_dso **deps;        /* DT_NEEDED, loaded; null-terminated */

	/* Constructors and destructors, relocated. */
	void (*init)(void);
	void (**init_array)(void);
	size_t init_count;
	void (*fini)(void);
	void (**fini_array)(void);
	size_t fini_count;
	int global;                   /* RTLD_GLOBAL: in every later lookup */
	int symbolic;                 /* DT_SYMBOLIC: its own names first */
	int refs;
	int constructed;
	int is_program;
};

/* The objects loaded after the program, in load order, and how many have been
 * added --- the count the unwinder compares to decide whether what it cached
 * is still the whole list (okm_phdr.c). */
hidden extern struct okm_dso *__okm_dl_head;
hidden extern unsigned long long __okm_dl_adds;

/* The module whose thread-local storage has this number (okm_dl.c), or null. */
hidden struct okm_dso *__okm_dl_tls_module(size_t id);

/* The address of a module's thread-local variable in the calling context
 * (okm_tls_get_addr.c). */
hidden void *__okm_tls_address(size_t id, size_t offset);

#endif
