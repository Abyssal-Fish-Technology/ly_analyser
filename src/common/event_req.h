#ifndef __COMMON_EVENT_REQ_H__
#define __COMMON_EVENT_REQ_H__

#include "common.h"
#include "event.pb.h"

namespace cgicc {
class Cgicc;
}

namespace event {

bool ParseWebReqFromUrlParams(cgicc::Cgicc& cgi, WebReq* req);
bool ParseWebReqFromCmdline(int argc, char*argv[], WebReq* req);
void usage(char * pn);

class Level {
public:
	Level(u32 id=0, std::string desc="", std::string profile="");
	u32 calc_level_id(u32 thres_value, u32 alarm_value) const;
	const std::string& get_desc() const;
	bool empty() const;
	u32 get_id() const { return _id; };

private:
	u32 _id;
	u32 _el, _l, _m, _h;
	std::string _desc;
	bool _empty;
};

struct Event_Data_Aggr_Record
{
	u32 id, event_id, devid, alarm_peak, sub_events, alarm_avg, duration, starttime, endtime, is_alive, model;
	std::string obj, type, level, value_type, desc;
};

} // namespace event

#endif //__COMMON_EVENT_REQ_H__

