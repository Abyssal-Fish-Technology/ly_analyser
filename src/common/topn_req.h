#ifndef __COMMON_TOPN_REQ_H__
#define __COMMON_TOPN_REQ_H__

#include "common.h"
#include "topn.pb.h"

namespace cgicc {
class Cgicc;
}

namespace topn {
bool ParseTopnReqFromCmdline(int argc, char*argv[], TopnReq* req);
bool ParseTopnReqFromUrlParams(cgicc::Cgicc& cgi, TopnReq* req);
void ComposeReqFilter(TopnReq* req);
} // namespace topn

#endif //__COMMON_TOPN_REQ_H__

