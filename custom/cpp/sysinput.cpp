#include <cstdlib>
#include <iostream>
#include <string>

int main() {
    std::string user_input;
    std::cout << "Enter command: ";
    std::getline(std::cin, user_input);

    // Dangerous: user input passed directly to system()
    system(user_input.c_str());

    return 0;
}
