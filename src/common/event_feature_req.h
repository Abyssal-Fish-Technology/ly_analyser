#ifndef __COMMON_EVENT_FEATURE_REQ_H__
#define __COMMON_EVENT_FEATURE_REQ_H__

#include "common.h"
#include "event_feature.pb.h"
#include <boost/algorithm/string.hpp>
#include <string>

namespace cgicc {
class Cgicc;
}

namespace eventfeature {
bool validate_request(EventFeatureReq* req);
bool ParseFeatureReqFromCmdline(int argc, char*argv[], EventFeatureReq* req);
bool ParseFeatureReqFromUrlParams(cgicc::Cgicc& cgi, EventFeatureReq* req);
} // namespace eventfeature

#endif //__COMMON_EVENT_FEATURE_REQ_H__

