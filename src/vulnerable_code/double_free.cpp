// double_free.cpp
#include <cstdlib>
#include <iostream>

int main() {
    // Allocate memory.
    char* buffer = (char*)malloc(20);
    if (!buffer) return 1;
    // Free the memory.
    free(buffer);
    // Vulnerable: freeing the same memory twice.
    free(buffer);
    std::cout << "Double free performed.\n";
    return 0;
}
