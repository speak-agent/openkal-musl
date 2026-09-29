/* __tls_get_addr: a loaded module's thread-local storage, in the calling context.
 *
 * musl answers this from the vector in front of its thread descriptor, which
 * its dynamic linker fills. This port has no dynamic linker and its descriptors
 * carry an empty vector (okm_start.c): the program's own thread-local storage is
 * the toolchain's, which openkal sets up for every context it starts, and a
 * program linked by itself never asks this question.
 *
 * A module loaded by okm_dl.c does. Its storage is made in each context the
 * first time that context asks --- from the module's initial image --- and
 * kept in a table that is itself thread-local, so every context has its own.
 * The block is not released when the context ends: nothing that ends a context
 * passes through here, and a module is never unloaded.
 */
#define _GNU_SOURCE
#include "pthread_impl.h"

#ifdef __ELF__
#include "okm.h"
#include "okm_dl.h"

#include <stdlib.h>
#include <string.h>

#if defined(__riscv)
#define OKM_DTP_OFFSET 0x800
#else
#define OKM_DTP_OFFSET 0
#endif

static __thread unsigned char **blocks;
static __thread size_t capacity;

static void *make(size_t id)
{
	struct okm_dso *m = __okm_dl_tls_module(id);
	if (!m) {
		static const char msg[] = "openkal-musl: thread-local storage of a module that was not loaded\n";
		kal_abort(msg, sizeof msg - 1);
	}
	if (id >= capacity) {
		size_t n = capacity ? 2 * capacity : 8;
		while (n <= id) n *= 2;
		unsigned char **grown = calloc(n, sizeof *grown);
		if (!grown) goto out_of_memory;
		if (blocks) memcpy(grown, blocks, capacity * sizeof *grown);
		free(blocks);
		blocks = grown;
		capacity = n;
	}
	const size_t align = m->tls_align < sizeof(void *) ? sizeof(void *) : m->tls_align;
	unsigned char *b = aligned_alloc(align, (m->tls_memsz + align - 1) & -align);
	if (!b) goto out_of_memory;
	memcpy(b, m->tls_image, m->tls_filesz);
	memset(b + m->tls_filesz, 0, m->tls_memsz - m->tls_filesz);
	blocks[id] = b;
	return b;
out_of_memory:;
	static const char msg[] = "openkal-musl: no memory for a loaded module's thread-local storage\n";
	kal_abort(msg, sizeof msg - 1);
	return 0;
}

hidden void *__okm_tls_address(size_t id, size_t offset)
{
	unsigned char *b = id < capacity && blocks[id] ? blocks[id] : make(id);
	return b + offset;
}

void *__tls_get_addr(tls_mod_off_t *v)
{
	return __okm_tls_address(v[0], v[1] + OKM_DTP_OFFSET);
}

#else

/* The formats without program headers: musl's own answer, unchanged. */
void *__tls_get_addr(tls_mod_off_t *v)
{
	pthread_t self = __pthread_self();
	return (void *)(self->dtv[v[0]] + v[1]);
}

#endif
