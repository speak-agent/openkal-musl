// dlopen in a static program (port/src/okm_dl.c): loads plugin/'s object and
// checks what a program and an object it loads share --- names, one heap,
// exceptions both ways, thread-local storage, constructors, dladdr.
#include <dlfcn.h>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>

extern "C" int host_value() { return 42; }

namespace {
int failures = 0;
void check(bool ok, const char* what) {
    std::printf("%s  %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) ++failures;
}
template <class F> F symbol(void* h, const char* name) { return reinterpret_cast<F>(dlsym(h, name)); }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: dlopen PLUGIN\n");
        return 2;
    }
    check(dlopen("no-such-object.so", RTLD_LAZY) == nullptr && std::strstr(dlerror(), "no-such-object.so"),
          "a missing object is refused, and dlerror names it");
    void* h = dlopen(argv[1], RTLD_LAZY);
    if (!h) {
        std::printf("FAIL  dlopen: %s\n-- failures: 1 --\n", dlerror());
        return 1;
    }
    check(dlopen(argv[1], RTLD_LAZY) == h, "the same object opened again is the same handle");

    auto constructed = static_cast<int*>(dlsym(h, "plugin_constructed"));
    check(constructed && *constructed == 42, "its constructor ran, and called the program");

    auto greet = symbol<std::string (*)(const std::string&)>(h, "plugin_greet");
    check(greet && greet("host") == "hello, host, from the plugin (42)", "a string made there is used and freed here");

    bool caught = false;
    try { symbol<void (*)(int)>(h, "plugin_throw")(7); }
    catch (const std::runtime_error& e) { caught = std::string(e.what()) == "plugin threw 7"; }
    check(caught, "an exception thrown there is caught here, as the program's type");

    caught = false;
    try {
        symbol<int (*)(int (*)(int))>(h, "plugin_calls_back")([](int x) -> int {
            if (x > 1) throw std::out_of_range("the program threw");
            return x;
        });
    } catch (const std::out_of_range&) { caught = true; }
    check(caught, "an exception thrown here passes through its frames");

    auto counter = symbol<int (*)()>(h, "plugin_counter");
    counter();
    const int here = counter();
    int there = 0;
    std::thread t([&] { there = counter(); });
    t.join();
    check(here == 2 && there == 1, "its thread-local variable is one per context");

    Dl_info info{};
    check(dladdr(reinterpret_cast<void*>(symbol<void (*)(int)>(h, "plugin_throw")), &info) &&
              info.dli_sname && std::strcmp(info.dli_sname, "plugin_throw") == 0,
          "dladdr names the function an address is in");
    check(dlsym(RTLD_DEFAULT, "host_value") == reinterpret_cast<void*>(host_value),
          "dlsym(RTLD_DEFAULT) finds the program's own names");
    check(dlsym(h, "no_such_name") == nullptr && dlerror() != nullptr, "a name nothing defines is not found");
    check(dlclose(h) == 0, "dlclose succeeds (the object stays)");

    std::printf("-- failures: %d --\n", failures);
    return failures != 0;
}
