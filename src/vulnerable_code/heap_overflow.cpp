// heap_overflow.cpp
#include <iostream>
#include <cstring>
#include <cstdlib>

int main() {
    // Allocate 20 bytes on the heap.
    char* buffer = new char[20];
    // Vulnerable: writing 30 bytes into a 20-byte allocation.
    memset(buffer, 'B', 30);
    buffer[19] = '\0';  // Force a null terminator (although we already overran the boundary)
    std::cout << "Buffer: " << buffer << "\n";
    delete[] buffer;
    return 0;
}

