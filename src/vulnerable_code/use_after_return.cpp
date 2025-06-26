// use_after_return.cpp
#include <iostream>
#include <cstring>

// Vulnerable function that returns the address of a local (stack) variable.
char* getBuffer() {
    char localBuffer[20];
    strcpy(localBuffer, "Local Data");
    return localBuffer;  // Returning address of a local variable!
}

int main() {
    char* ptr = getBuffer();
    // Vulnerable: using a pointer to memory that has gone out of scope.
    std::cout << "Returned Buffer: " << ptr << "\n";
    return 0;
}
