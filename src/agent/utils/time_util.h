#ifndef __AGENT_UTILS_TIME_UTIL_H
#define __AGENT_UTILS_TIME_UTIL_H

#include "../../common/common.h"

class TimeUtil {
 public:
  static bool ValidateTimeRange(u32* start_time, u32* end_time, u32* step, u32* time_unit);
};

#endif // __AGENT_UTILS_TIME_UTIL_H
