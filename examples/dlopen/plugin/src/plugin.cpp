// What the program calls, each exercising one thing a loader must get right.
#include <cstdio>
#include <stdexcept>
#include <string>

extern "C" int host_value();
extern "C" int plugin_constructed = 0;

namespace {
// A constructor that calls back into the program: run after relocation, with
// the program's names bound. The destructor runs at exit.
struct Lifetime {
    Lifetime() { plugin_constructed = host_value(); }
    ~Lifetime() { std::puts("plugin: its static object destroyed at exit"); }
} lifetime;

thread_local int counter = 0;
}

// A class type made here and destroyed there: one allocator.
extern "C" std::string plugin_greet(const std::string& who) {
    return "hello, " + who + ", from the plugin (" + std::to_string(host_value()) + ")";
}
// Thrown here, caught in the program: the unwinder finds this object's frames,
// and the type is the program's.
extern "C" void plugin_throw(int n) { throw std::runtime_error("plugin threw " + std::to_string(n)); }
// Thrown in the program, through this object's frames.
extern "C" int plugin_calls_back(int (*f)(int)) { return f(1) + f(2); }
// A variable of each context.
extern "C" int plugin_counter() { return ++counter; }
