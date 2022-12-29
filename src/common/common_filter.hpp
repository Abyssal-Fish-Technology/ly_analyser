#ifndef COMMON_FILTER_H
#define COMMON_FILTER_H

#include <time.h>
#include "config.pb.h"

namespace common_filter {

static inline bool filter_time_range(time_t t, const config::Event& e) {
	bool within = false;

	struct tm *p = localtime(&t);

	for (int i=0; i<e.weekday_size(); i++) {
		if (e.weekday(i)==p->tm_wday) {
			within = true;
			break;
		}
	}

	if (within==false)
		return (e.coverrange()==config::Event::WITHIN)?false:true;

	if (p->tm_hour >= e.stime_hour()
		&& p->tm_min  >= e.stime_min()
		&& p->tm_sec  >= e.stime_sec()
		&& p->tm_hour <= e.etime_hour()
		&& p->tm_min  <= e.etime_min()
		&& p->tm_sec  <= e.etime_sec()
	)
		within = true;
	else
		within = false;

	if ( (within==true && e.coverrange()==config::Event::WITHIN) || (within==false && e.coverrange()==config::Event::WITHOUT) )
		return true;
	else
		return false;
}

} // namespace

#endif
