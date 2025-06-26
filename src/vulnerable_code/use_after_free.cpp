// use_after_free.cpp
#include <iostream>
#include <cstring>
#include <cstdlib>

int main() {
    // Allocate memory on the heap.
    char* buffer = (char*)malloc(20);
    strcpy(buffer, "Sensitive Data");
    free(buffer);  // Free the memory.
    // Vulnerable: using the memory after it has been freed.
    std::cout << "Buffer: " << buffer << "\n";
    return 0;
}