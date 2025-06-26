// memory_leak.cpp
#include <cstdlib>

int main() {
    // Vulnerable: memory allocated but never freed.
    char* leak = (char*)malloc(100);
    leak[0] = 'L'; // Use the memory so it’s not optimized out.
    return 0;
}
