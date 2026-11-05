#include <iostream>
#include <sstream>

class CoutToString {
public:
    CoutToString() : old_cout_buf(std::cout.rdbuf()) { std::cout.rdbuf(o_str.rdbuf()); }
    ~CoutToString() { std::cout.rdbuf(old_cout_buf); }

    std::string GetString() const { return o_str.str(); }

private:
    std::ostringstream o_str;
    std::streambuf *old_cout_buf;
};
