#include "strings.h"

#include <algorithm> 
#include <functional> 
#include <cctype>
#include <locale>
#include <string>

// trim from start
std::string &ltrim(std::string &s) {
  s.erase(s.begin(),
          std::find_if(s.begin(),
                       s.end(),
                       std::not1(std::ptr_fun<int, int>(std::isspace))));
  return s;
}

// trim from end
std::string &rtrim(std::string &s) {
  s.erase(
      std::find_if(s.rbegin(),
                   s.rend(),
                   std::not1(std::ptr_fun<int, int>(std::isspace))).base(),
      s.end());
  return s;
}

// trim from both ends
std::string &trim(std::string &s) {
  return ltrim(rtrim(s));
}

////////////////////////////////////////////////////////////////////////////
std::string escape_string(const std::string& src)
{
   std::string result;
   std::string::const_iterator iter;
   static const char hex_chars[] = "0123456789ABCDEF";

   for (iter = src.begin(); iter != src.end(); ++iter) {
      unsigned char c = *iter;
      if (isalnum(c) || (c == '*') || (c == '@') || (c == '-')
      || (c == '_') || (c == '+') || (c == '.') || (c == '/')) {
            result.append(1, c);
      }
      else {
         result.append(1, '%');
         result.append(1, hex_chars[c >> 4]);
         result.append(1, hex_chars[c & 15]);
      }
   }
   return result;
}


std::string escape_back_slash(const std::string& src) {
  std::string result;
  std::string::const_iterator iter;
  for (iter = src.begin(); iter != src.end(); ++iter) {
    unsigned char c = *iter;
    if (c == '"')
      //result.append("\\\"");
      continue;
    else if (c == '\\')
      result.append("\\\\");
    else if (c == '\n')
      result.append("\\\\n");
    else if (c == '\r')
      result.append("\\\\r");
    else if (c == '\b')
      result.append("\\\\b");
    else if (c == '\v')
      result.append("\\\\v");
    else if (c == '\t')
      result.append("\\\\t");
    else if (c == '\f')
      result.append("\\\\f");
    else if (c > 0 && c < 32)
      continue;
    else
      result.append(1, c);
  }
  return result;
}

//////////////////////////////////////////////////////////////////////////
std::set<std::string> split_string(std::string& str, const std::string& delimiter) {
  std::set<std::string> vec;
  if (str.size() == 0) return vec;
  str = trim(str);
  size_t pos = str.find(delimiter);
  while (pos != std::string::npos) {
    std::string tmp = str.substr(0, pos);
    vec.emplace(trim(tmp));
    str = str.substr(pos+1);
    pos = str.find(delimiter);
  }
  vec.emplace(trim(str));
  return vec;
}



////////////////////////////////////////////////////////////////////////////
/*std::string to_string(u64 i) {
  return std::to_string((long long unsigned int)i);
}

std::string to_string(u32 i) {
  return std::to_string((long long unsigned int)i);
}

std::string to_string(s64 i) {
  return std::to_string((long long signed int)i);
}

std::string to_string(s32 i) {
  return std::to_string((long long signed int)i);
}
*/
