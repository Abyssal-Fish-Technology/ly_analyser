#include "time_util.h"

#include "../../common/log.h"

bool TimeUtil::ValidateTimeRange(u32* start_time, u32* end_time, u32* step, u32* time_unit) {
  *time_unit = std::max<u32>(*time_unit, 60);
  *step -= *step % *time_unit;
  *step = std::max<u32>(*step, *time_unit);
  if (DEBUG) log_info("timeunit:%u\tstep:%u\n", *time_unit, *step);
  *start_time -= *start_time % *time_unit;
  *end_time -= *end_time % *time_unit;
  return *start_time <= *end_time;
}

