/* A constructor that uses the C library before the program starts.
 *
 * On macOS the loader runs every constructor before the entry point, and this
 * program's object precedes the C library's on the link line, so its
 * constructor runs before the library's own (port/src/mach/early_init.c). It
 * allocates (the allocator's first use), reads errno (per-context state) and
 * formats a number -- what a C++ program's static objects do before main: a
 * registry filled from constructors, a string built at namespace scope. Each
 * of the three brings the library up on first use; on the other formats the
 * library is up before any constructor runs and nothing changes.
 *
 * The library brought up that early still gives main the program's arguments
 * and environment (run as `early-constructor one two`): they were once taken
 * only when the entry point or the platform's own constructor had recorded
 * them, and a program started early saw none -- a test program asked to act as
 * its own child ran its tests instead, and spawned itself again.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char* early_block;
static int early_errno = -1;
static long early_value;
static char early_text[32];

__attribute__((constructor)) static void early(void)
{
	early_block = malloc(1 << 16);
	if (early_block) memset(early_block, 7, 1 << 16);
	errno = 0;
	early_value = strtol("123", 0, 10);
	early_errno = errno;
	snprintf(early_text, sizeof early_text, "early %d", 42);
}

static int failures;

static void check(int ok, const char* what)
{
	printf("%s  %s\n", ok ? "ok  " : "FAIL", what);
	if (!ok) failures++;
}

int main(int argc, char** argv)
{
	check(early_block != 0 && early_block[(1 << 16) - 1] == 7, "a constructor allocated before the program started");
	check(early_value == 123 && early_errno == 0, "and read errno");
	check(strcmp(early_text, "early 42") == 0, "and formatted a number");
	free(early_block);
	char* later = malloc(64);
	check(later != 0, "the allocator goes on after main starts");
	free(later);
	check(argc == 3 && strcmp(argv[1], "one") == 0 && strcmp(argv[2], "two") == 0, "main has the arguments the program was started with");
	check(getenv("PATH") != 0, "and the environment");
	printf("-- failures: %d --\n", failures);
	return failures != 0;
}
