/* One call from each of the four archives this fixture links explicitly:
 * `-lm', `-lpthread', `-ldl' and `-lrt'. Every one of the four functions
 * below is defined by musl's own objects, already on this program's link
 * line without any of the four --- so a correct run here is not evidence
 * that the flags were answered correctly, only that they were not answered
 * WRONGLY in a way that breaks the program. The evidence this fixture exists
 * to produce is read from the linker's own trace of the build that produced
 * this binary (see .github/workflows/ci.yml), not from anything below.
 */
#include <stdio.h>
#include <math.h>
#include <pthread.h>
#include <dlfcn.h>
#include <time.h>

static int failures = 0;
static void check(int ok, const char *what) {
	if (!ok) { printf("FAIL: %s\n", what); failures++; }
	else printf("ok: %s\n", what);
}

static void *thread_fn(void *arg) { return arg; }

int main(void) {
	check(fmax(1.0, 2.0) == 2.0, "fmax");

	pthread_t t;
	void *result = NULL;
	check(pthread_create(&t, NULL, thread_fn, (void *)1) == 0, "pthread_create");
	check(pthread_join(t, &result) == 0 && result == (void *)1, "pthread_join");

	struct timespec ts;
	check(clock_gettime(CLOCK_MONOTONIC, &ts) == 0, "clock_gettime");

	/* -ldl names this library. Where the format has a loader here (ELF,
	 * port/src/okm_dl.c), dlopen(NULL) is the program itself, as POSIX says;
	 * where it does not yet, it is declined with a reason. A file that is not
	 * there is declined everywhere, with a reason. */
#ifdef __ELF__
	check(dlopen(NULL, RTLD_NOW) != NULL, "dlopen(NULL) is the program");
#else
	check(dlopen(NULL, RTLD_NOW) == NULL && dlerror() != NULL, "dlopen declines where this format has no loader yet");
#endif
	check(dlopen("no-such-object.so", RTLD_NOW) == NULL && dlerror() != NULL,
	      "a file that is not there is declined, with a reason");

	printf("-- failures: %d --\n", failures);
	return failures ? 1 : 0;
}
