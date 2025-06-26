#include <iostream>
#include <cstring>

int main(int argc, char* argv[]) { 
  char buffer[20];
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <input>\n";
    return 1;
  }

  strcpy(buffer, argv[1]);
  std::cout << "Input: " << buffer << "\n";
  return 0;
}