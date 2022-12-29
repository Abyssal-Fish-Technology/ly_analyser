#ifndef __COMMON_DATETIME_H__
#define __COMMON_DATETIME_H__

#include "common.h"

////////////////////////////////////////////////////////////////////////////

namespace datetime {

u32 latest_flow_time(void);

void format_timestamp(u32 timestamp, char* str, int str_size);
void format_timestamp(u32 timestamp, char* str, int str_size, const char format[]);
void format_timestamp(u32 timestamp, std::string* str);
void format_timestamp(u32 timestamp, std::string* str, const std::string& format);
std::string format_timestamp(u32 timestamp);
std::string format_timestamp(u32 timestamp, const std::string& format);
std::string format_date(u32 timestamp);
std::string format_date(u32 timestamp, const std::string& format);
std::string format_hour_min(u32 timestamp);
std::string format_hour_min(u32 timestamp, const std::string& format);

// return timestamp
u32 parse_timestamp(u64 date_number);
u32 parse_timestamp(u64 date_number, const char format[]);
u32 parse_timestamp(u64 date_number, const std::string& format);
u32 parse_timestamp(const std::string& date_string);
u32 parse_timestamp(const std::string& date_string, const std::string& format);

} // namespace datetime

#endif  // __COMMON_DATETIME_H__
