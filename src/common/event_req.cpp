#include "event_req.h"
#include "strings.h"
#include "log.h"
#include "datetime.h"
#include <algorithm>
#include <string>
#include <Cgicc.h>
#include <boost/algorithm/string.hpp>

using namespace std;

namespace event {

// Class Level
Level::Level(u32 id, std::string desc, std::string profile):_id(id), _desc(desc), _empty(profile=="") {
  if (profile.empty())
    return;

  std::stringstream str(profile);
  string val_str;

  std::getline(str, val_str, ':');
  _el = atol(val_str.c_str());
  std::getline(str, val_str, ':');
  _l = atol(val_str.c_str());
  std::getline(str, val_str, ':');
  _m = atol(val_str.c_str());
  std::getline(str, val_str, ':');
  _h = atol(val_str.c_str());
}

u32 Level::calc_level_id(u32 thres_value, u32 alarm_value) const{
  float rate = 100*((float)alarm_value-thres_value)/thres_value;
  if (rate<0)
    rate = 0 - rate;

  if (rate < _el)
    return 5;
  else if (rate < _l)
    return 4;
  else if (rate < _m)
    return 3;
  else if (rate < _h)
    return 2;
  else
    return 1;
}

const std::string& Level::get_desc() const{
  return _desc;
}

bool Level::empty() const{
  return _empty;
}

// End of Class Level

////////////////////////////////////////////////////////////////////////////
static bool validate_request(WebReq* req) {
  u32 ts = time(NULL);

  if (!req->has_id()) {
    if (!req->has_starttime())
      req->set_starttime( ts - 1800 );
    if (!req->has_endtime())
      req->set_endtime( ts );
    req->set_starttime(req->starttime() - req->starttime()%300);
    req->set_endtime(req->endtime() - req->endtime()%300);
    req->set_endtime(MAX(req->starttime()+300, req->endtime()));
  }
  if (req->has_step()){
    req->set_step(req->step() - req->step()%300);
    req->set_step(MAX(req->step(), 300));
  }
  if (!req->has_req_type())
    req->set_req_type(WebReq::ORI);
  if ( req->is_alive() > 1 ) {
    log_err("is_alive > 1: %u",req->is_alive());
    return false;
  }

  if (req->req_type()==WebReq::SET_PROC_STATUS) {
    if (!req->has_proc_status() || !req->has_id()) {
      log_err("no proc_status or no id, proc_status: '%s', id: %u", req->proc_status().c_str(), req->id());
      return false;
    }
    if (req->proc_status()!="processed" && req->proc_status()!="assigned" && req->proc_status()!="unprocessed") {
      log_err("invalid proc_status: %s", req->proc_status().c_str());
      return false;
    }
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////
bool ParseWebReqFromUrlParams(cgicc::Cgicc& cgi, WebReq* req) {
  if (!cgi("starttime").empty()) req->set_starttime(atoll(cgi("starttime").c_str()));
  if (!cgi("endtime").empty()) req->set_endtime(atoll(cgi("endtime").c_str()));
  if (!cgi("step").empty()) req->set_step(atol(cgi("step").c_str()));
  if (!cgi("type").empty()) req->set_type(cgi("type"));
  if (!cgi("devid").empty()) req->set_devid(atol(cgi("devid").c_str()));
  if (!cgi("event_id").empty()) req->set_event_id(atol(cgi("event_id").c_str()));
  if (!cgi("id").empty()) req->set_id(atol(cgi("id").c_str()));
  if (!cgi("obj").empty()) req->set_obj(cgi("obj"));
  if (!cgi("level").empty()) req->set_level(cgi("level"));
  if (!cgi("is_alive").empty()) req->set_is_alive(atol(cgi("is_alive").c_str()));

  if (!cgi("req_type").empty()) {
    string req_type = boost::to_upper_copy(cgi("req_type"));
    if (req_type=="AGGRE")
      req->set_req_type(WebReq::AGGRE);
    else if (req_type=="ORI")
      req->set_req_type(WebReq::ORI);
    else if (req_type=="SET_PROC_STATUS")
      req->set_req_type(WebReq::SET_PROC_STATUS);
  }
  if (!cgi("proc_status").empty()) req->set_proc_status(cgi("proc_status"));
  if (!cgi("proc_comment").empty()) req->set_proc_comment(cgi("proc_comment")=="null"?"":cgi("proc_comment"));

  return validate_request(req);
}

////////////////////////////////////////////////////////////////////////////
void usage(char * pn)
{
  fprintf(stderr, "usage: %s [options]\n\n", pn);
  fprintf(stderr, "-s <starttime>\tdefault:<latest>\n");
  fprintf(stderr, "-S <starttime>\tFormat:YYYYmmddHHMM default:<latest>\n");
  fprintf(stderr, "-e <endtime>\tdefault:latest\n");
  fprintf(stderr, "-E <endtime>\tFormat:YYYYmmddHHMM default:<latest>\n");
  fprintf(stderr, "-p <step>\t\n");
  fprintf(stderr, "-t <type>\t\n");
  fprintf(stderr, "-d <devid>\t\n");
  fprintf(stderr, "-i <event_id>\t\n");
  exit(1);
}

////////////////////////////////////////////////////////////////////////////
bool ParseWebReqFromCmdline(int argc, char*argv[], WebReq* req) {
  char c;
  while ((c = getopt(argc, argv, "s:S:e:E:p:t:d:i:")) != -1)
  {
    if (optarg==NULL)
        continue;

    switch (c)
    {
    case 's':
      req->set_starttime(atol(optarg));
      break;
    case 'S':
      req->set_starttime(datetime::parse_timestamp(optarg));
      break;
    case 'e':
      req->set_endtime(atol(optarg));
      break;
    case 'E':
      req->set_endtime(datetime::parse_timestamp(optarg));
      break;
    case 'p':
      req->set_step(atol(optarg));
      break;
    case 't':
      req->set_type(optarg);
      break;
    case 'd':
      req->set_devid(atol(optarg));
      break;
    case 'i':
      req->set_event_id(atol(optarg));
      break;
    default:
      return false;
    }
  }
  return validate_request(req);
}
} // namespace event
