#ifndef __COMMON_FEATURE_REQ_H__
#define __COMMON_FEATURE_REQ_H__

#include "common.h"
#include "feature.pb.h"
#include <boost/algorithm/string.hpp>
#include <string>

namespace cgicc {
class Cgicc;
}

namespace feature {
bool validate_request(FeatureReq* req);
bool ParseFeatureReqFromCmdline(int argc, char*argv[], FeatureReq* req);
bool ParseFeatureReqFromUrlParams(cgicc::Cgicc& cgi, FeatureReq* req);
} // namespace feature

#endif //__COMMON_FEATURE_REQ_H__

