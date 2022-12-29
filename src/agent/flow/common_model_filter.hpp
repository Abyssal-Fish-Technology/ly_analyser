#ifndef COMMON_MODEL_FILTER_H
#define COMMON_MODEL_FILTER_H

#include <time.h>
#include "../../common/config.pb.h"
#include "../../common/common.h"
#include "../model/model.h"

namespace common_model_filter {

static inline bool filter_time_range(const Pattern& e) {
	bool within = false;

	time_t t = e.start_time;
	struct tm *p = localtime(&t);

	for (u32 i=0; i<e.weekday.size(); i++) {
		if (e.weekday[i]==p->tm_wday) {
			within = true;
			break;
		}
	}

	if (within==false)
		return (e.coverrange==config::Event::WITHIN)?false:true;

	if (p->tm_hour >= e.stime_hour
		&& p->tm_min  >= e.stime_min
		&& p->tm_sec  >= e.stime_sec
		&& p->tm_hour <= e.etime_hour
		&& p->tm_min  <= e.etime_min
		&& p->tm_sec  <= e.etime_sec
	)
		within = true;
	else
		within = false;

	if ( (within==true && e.coverrange==config::Event::WITHIN) || (within==false && e.coverrange==config::Event::WITHOUT) )
		return true;
	else
		return false;
}

} // namespace

#endif
