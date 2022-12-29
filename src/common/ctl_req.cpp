#include "ctl_req.h"
#include "log.h"
#include <algorithm>
#include <iostream>
#include <string>
#include <Cgicc.h>

using namespace std;
using namespace boost;

namespace ctl {

string GetReqTypeStr(CtlReq* req) {
  if (req->type() == CtlReq::SSH)
    return "ssh";
  else if (req->type() == CtlReq::HTTP)
    return "http";
  else if (req->type() == CtlReq::CAP)
    return "cap";
  else if (req->type() == CtlReq::PROBE)
    return "probe";
  else if (req->type() == CtlReq::DISK)
    return "disk";
  else if (req->type() == CtlReq::FSD)
    return "fsd";
  else if (req->type() == CtlReq::ALL)
    return "all";
  return "";
}

string GetReqOpStr(CtlReq* req) {
  if (req->op() == CtlReq::STAT)
    return "stat";
  else if (req->op() == CtlReq::STOP)
    return "stop";
  else if (req->op() == CtlReq::START)
    return "start";
  else if (req->op() == CtlReq::RESTART)
    return "restart";
  return "";
}
/*static void setTarget(const string& str, CtlReq* req) {
  if (str == "SERVER") 
    req->set_target(CtlReq::SERVER);
  else if (str == "AGENT") 
    req->set_target(CtlReq::AAGENT);
  else 
    req->set_target(CtlReq::EMPTY);
}*/

/////////////////////////////////////////////////////////
static void setService(const string& str, CtlReq* req) {
  if (str == "SSH")
    req->set_type(CtlReq::SSH);
  else if (str == "HTTP")
    req->set_type(CtlReq::HTTP);
  else if (str == "PROBE")
    req->set_type(CtlReq::PROBE);
  else if (str == "CAP")
    req->set_type(CtlReq::CAP);
  else if (str == "FSD")
    req->set_type(CtlReq::FSD);
  else if (str == "DISK")
    req->set_type(CtlReq::DISK);
  else
    req->set_type(CtlReq::ALL);
}

static void setOp(const string& str, CtlReq* req) {
  if (str == "START")
    req->set_op(CtlReq::START);
  else if (str == "STOP")
    req->set_op(CtlReq::STOP);
  else if (str == "STAT")
    req->set_op(CtlReq::STAT);
  else if (str == "RESTART")
    req->set_op(CtlReq::RESTART);
  else
    req->set_op(CtlReq::STAT);
}

/////////////////////////////////////////////////////////
bool validate_request(CtlReq* req) {
  if (!req->has_type() || !req->has_op() || !req->has_tid()) return false;
  if (req->type() == CtlReq::ALL || req->type() == CtlReq::DISK) {
    if (req->op() != CtlReq::STAT) return false;
  }
  if (req->type() == CtlReq::HTTP) {
    if (req->op() == CtlReq::STOP) return false;
  }
  return true;
}
  
/////////////////////////////////////////////////////////
bool ParseCtlReqFromUrlParams(cgicc::Cgicc& cgi, CtlReq* req) {
  if (!cgi("type").empty()) setService(boost::to_upper_copy(cgi("type")), req);
  if (!cgi("op").empty()) setOp(boost::to_upper_copy(cgi("op")), req);
  if (!cgi("tid").empty()) req->set_tid(cgi("tid"));
  if (!cgi("devid").empty()) req->set_devid(cgi("devid"));
  return validate_request(req);
}

}
