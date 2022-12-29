#ifndef __COMMON_STRINGS_H__
#define __COMMON_STRINGS_H__

#include "common.h"
#include <set>

// trim from start
std::string &ltrim(std::string &s);

// trim from end
std::string &rtrim(std::string &s);

// trim from both ends
std::string &trim(std::string &s);

std::string escape_string(const std::string& src);

//add '\' when is escape character
std::string escape_back_slash(const std::string& src);

std::set<std::string> split_string(std::string& str, const std::string& delimiter);
// to convert from string to int. use std::stoi
/*#if (__GNUC__ > 4) || (__GNUC_MINOR__ > 7 || __APPLE__)
#include <string>
#else
std::string to_string(u64 i);
std::string to_string(u32 i);
std::string to_string(s64 i);
std::string to_string(s32 i);
#endif
*/
#endif // __COMMON_STRINGS_H__
