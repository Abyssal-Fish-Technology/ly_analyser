#ifndef __STRINGUTIL_H__
#define __STRINGUTIL_H__

#include <string>

void StringAppendV(std::string* dst, const char* format, va_list ap);
std::string StringPrintf(const char* format, ...);

#endif  // __STRINGUTIL_H__
