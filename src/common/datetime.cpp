#include "datetime.h"

using namespace std;

////////////////////////////////////////////////////////////////////////////

namespace datetime {

const char kDefaultDateTimeFormat[] = "%Y%m%d%H%M";
const char kDefaultDateFormat[] = "%Y%m%d";
const char kDefaultTimeFormat[] = "%H%M";

u32 latest_flow_time(void) {
  u32 aligned_now = time(NULL) - 10;
  return aligned_now - aligned_now % 300 - 300;
}

void format_timestamp(u32 timestamp, char* str, int str_size)
{
  format_timestamp(timestamp, str, str_size, kDefaultDateTimeFormat);
}

void format_timestamp(u32 timestamp, char* str, int str_size, const char format[])
{
  time_t t = timestamp;
  struct tm * tm = localtime(&t);
  int len = strftime(str, str_size, format, tm);
  str[len] = '\0';
}

string format_timestamp(u32 timestamp)
{
  return format_timestamp(timestamp, kDefaultDateTimeFormat);
}

string format_timestamp(u32 timestamp, const string& format)
{
  char datetimestr[1024];
  format_timestamp(timestamp, datetimestr, sizeof(datetimestr), format.c_str());
  return datetimestr;
}

void format_timestamp(u32 timestamp, string* str)
{
  format_timestamp(timestamp, str, kDefaultDateTimeFormat);
}

void format_timestamp(u32 timestamp, string* str, const string& format) 
{
  if (str) *str = format_timestamp(timestamp, format);
}

string format_date(u32 timestamp)
{
  return format_date(timestamp, kDefaultDateFormat);
}

string format_date(u32 timestamp, const string& format)
{
  return format_timestamp(timestamp, format);
}

string format_hour_min(u32 timestamp)
{
  return format_hour_min(timestamp, kDefaultTimeFormat);
}

string format_hour_min(u32 timestamp, const string& format)
{
  return format_timestamp(timestamp, format);
}

////////////////////////////////////////////////////////////////////////////

// return timestamp
u32 parse_timestamp(u64 date_number)
{
  return parse_timestamp(date_number, kDefaultDateTimeFormat);
}

u32 parse_timestamp(u64 date_number, const char format[])
{
  struct tm tm;
  char str[1024];
  snprintf(str, sizeof(str), "%ju", date_number);
  if (NULL == strptime(str, format, &tm)) return 0;
  return mktime(&tm);
}

u32 parse_timestamp(u64 date_number, const string& format)
{
  return parse_timestamp(date_number, format.c_str());
}

// return timestamp
u32 parse_timestamp(const string& date_string)
{
  return parse_timestamp(date_string, kDefaultDateTimeFormat);
}

u32 parse_timestamp(const string& date_string, const string& format)
{
  struct tm tm;
  if (NULL == strptime(date_string.c_str(), format.c_str(), &tm)) return 0;
  return mktime(&tm);
}
} // namespace datetime
