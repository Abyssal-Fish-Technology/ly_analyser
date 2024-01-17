#include "ctl_req.h"
#include "log.h"
#include <algorithm>
#include <iostream>
#include <string>
#include <Cgicc.h>

using namespace std;
using namespace boost;

namespace ctl {

string GetReqNodeStr(CtlReq* req) {
  switch(req->node()) {
    case CtlReq::NODE_ALL :
      return "all";
    case CtlReq::NODE_SERVER :
      return "server";
    case CtlReq::NODE_AGENT :
      return "agent";
    case CtlReq::NODE_PROBE :
      return "probe";
    default: 
      return "";
  }
  return "";
}

string GetReqSrvStr(CtlReq* req) {
  switch(req->srv()) {
    case CtlReq::SRV_ALL :
      return "all";
    case CtlReq::SRV_SSH :
      return "ssh";
    case CtlReq::SRV_HTTP :
      return "http";
    case CtlReq::SRV_CAP :
      return "cap";
    case CtlReq::SRV_PROBE :
      return "probe";
    case CtlReq::SRV_FSD :
      return "fsd";
    case CtlReq::SRV_DISK :
      return "disk";
    case CtlReq::SRV_BASIC :
      return "basic";
    default: 
      return "";
  }
  return "";
}

string GetReqOpStr(CtlReq* req) {
  switch(req->op()) {
    case CtlReq::STATUS :
      return "status";
    case CtlReq::STOP :
      return "stop";
    case CtlReq::START :
      return "start";
    case CtlReq::RESTART :
      return "restart";
    default: 
      return "";
  }
  return "";
}

static void setNode(const string& str, CtlReq* req) {
  if (str == "SERVER") 
    req->set_node(CtlReq::NODE_SERVER);
  else if (str == "AGENT") 
    req->set_node(CtlReq::NODE_AGENT);
  else if (str == "PROBE") 
    req->set_node(CtlReq::NODE_PROBE);
  else if (str == "ALL")
    req->set_node(CtlReq::NODE_ALL);
  else 
    req->set_node(CtlReq::NODE_ALL);
}

/////////////////////////////////////////////////////////
static void setSrv(const string& str, CtlReq* req) {
  if (str == "SSH")
    req->set_srv(CtlReq::SRV_SSH);
  else if (str == "HTTP")
    req->set_srv(CtlReq::SRV_HTTP);
  else if (str == "PROBE")
    req->set_srv(CtlReq::SRV_PROBE);
  else if (str == "CAP")
    req->set_srv(CtlReq::SRV_CAP);
  else if (str == "DISK")
    req->set_srv(CtlReq::SRV_DISK);
  else if (str == "FSD")
    req->set_srv(CtlReq::SRV_FSD);
  else if (str == "BASIC")
    req->set_srv(CtlReq::SRV_BASIC);
  // else if (str == "ALL")
  //   req->set_srv(CtlReq::SRV_ALL);
  else
    req->set_srv(CtlReq::SRV_ALL);
}

static void setOp(const string& str, CtlReq* req) {
  if (str == "STATUS")
    req->set_op(CtlReq::STATUS);
  else if (str == "START")
    req->set_op(CtlReq::START);
  else if (str == "STOP")
    req->set_op(CtlReq::STOP);
  else if (str == "RESTART")
    req->set_op(CtlReq::RESTART);
  else
    req->set_op(CtlReq::STATUS);
}

/////////////////////////////////////////////////////////
bool validate_request(CtlReq* req) {
  if (!req->has_node() || !req->has_op()) return false;
  
  if (req->node() == CtlReq::NODE_ALL) {
    if (req->op() != CtlReq::STATUS)  return false;
  }

  if (req->srv() == CtlReq::SRV_BASIC || req->srv() == CtlReq::SRV_DISK) {
    if (req->op() != CtlReq::STATUS) return false;
  }

  if (req->srv() == CtlReq::SRV_HTTP) {
    if (req->op() == CtlReq::STOP) return false;
  }
  return true;
}
  
/////////////////////////////////////////////////////////
bool ParseCtlReqFromUrlParams(cgicc::Cgicc& cgi, CtlReq* req) {
  if (!cgi("nodetype").empty())     setNode(boost::to_upper_copy(cgi("nodetype")), req);
  if (!cgi("servicetype").empty())  setSrv(boost::to_upper_copy(cgi("servicetype")), req);
  if (!cgi("op").empty())           setOp(boost::to_upper_copy(cgi("op")), req);
  if (!cgi("id").empty())           req->set_id(cgi("id"));
  return validate_request(req);
}

void ParseCtlReqFromCmdline(int argc, char*argv[], CtlReq* req) {
  char c;
  while ((c = getopt(argc, argv, "n:s:o:i:")) != -1)
  {
    if (optarg==NULL)
        continue;

    switch (c) {
      case 'n': {
        string node = optarg;
        setNode(boost::to_upper_copy(node), req);
        break;
      }
      case 's': {
        string type = optarg;
        setSrv(boost::to_upper_copy(type), req);
        break;
      }
      case 'o': {
        string op = optarg;
        setOp(boost::to_upper_copy(op), req);
        break;
      }
      case 'i':
        req->set_id(optarg);
        break;
      default:
        break;
    }
  }
}

}
