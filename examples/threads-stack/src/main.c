/* A thread started with the default attributes holds a deep recursion.
 *
 * A context's stack is openkal's, not the one musl allocates (port/src/
 * okm_thread.c), so its size is openkal's property: 256 KiB on Linux and the
 * system thread library's 512 KiB on macOS. Clang asks for 8 MiB and recurses
 * accordingly in template instantiation; mcppls, which runs Clang on threads of
 * this library, ran off the end of the macOS stack (a protection fault in
 * Sema::DeduceTemplateArguments, 500 frames deep). Each implementation now gives
 * a context 8 MiB, as a process's first context has.
 *
 * THE CRITERION is 4 MiB of frames on a started thread: 256 calls each holding
 * 16 KiB it writes at both ends, so no page of the range goes untouched. The
 * read after each call keeps every frame alive until the deepest returns.
 */
#include <pthread.h>
#include <stdio.h>

static int deep(int n)
{
    volatile unsigned char frame[16384];
    frame[0] = (unsigned char)n;
    frame[sizeof frame - 1] = 1;
    if (n == 0) return frame[sizeof frame - 1];
    return deep(n - 1) + frame[sizeof frame - 1];
}

static void* work(void* arg)
{
    *(int*)arg = deep(255);
    return arg;
}

int main(void)
{
    int depth = 0;
    pthread_t thread;
    if (pthread_create(&thread, 0, work, &depth) != 0) {
        puts("pthread_create failed");
        return 1;
    }
    pthread_join(thread, 0);
    printf("deep: %d frames of 16 KiB on a started thread\n", depth);
    printf("-- failures: %d --\n", depth == 256 ? 0 : 1);
    return depth == 256 ? 0 : 1;
}
