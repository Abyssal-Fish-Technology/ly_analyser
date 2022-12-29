#ifndef __COMMON_LOG_H__
#define __COMMON_LOG_H__

#include "common.h"

////////////////////////////////////////////////////////////////////////////
void inline log_err(const s8 * fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  //vfprintf(stderr, fmt, args);
  vsyslog(LOG_ERR, fmt, args);
  va_end(args);
}

////////////////////////////////////////////////////////////////////////////
void inline log_warning(const s8 * fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vsyslog(LOG_WARNING, fmt, args);
  va_end(args);
}

////////////////////////////////////////////////////////////////////////////
void inline log_info(const s8 * fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vsyslog(LOG_INFO, fmt, args);
  va_end(args);
}

bool inline is_debugging(const char* source_file) {
  auto debug = getenv("DEBUG");
  if (!debug) return false;
  return (strncmp(debug, "ALL", 3) == 0) || strstr(debug, source_file);
}

#define DEBUG is_debugging(__FILE__)

#endif // __COMMON_LOG_H__
