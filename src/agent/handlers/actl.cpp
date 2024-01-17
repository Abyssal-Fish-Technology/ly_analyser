#include <Cgicc.h>
#include <dirent.h>
#include <google/protobuf/text_format.h>
#include <string>
#include <sstream>
#include <map>
#include <set>
#include<boost/algorithm/string.hpp>
#include "../../common/log.h"
#include "../../common/ctl_req.h"
#include "../../common/strings.h"
#include "../../common/config.pb.h"
#include "../config/cached_config.h"
#include "../../common/CMyINI.h"


using namespace std;
using namespace ctl;
using namespace config;
using namespace boost;


static CtlReq req;
static CtlResponse rsp;
static bool is_http = false;

#define TEMPLATE_THREAT "%IPV4_SRC_ADDR %IPV4_DST_ADDR \
%IN_PKTS %IN_BYTES %FIRST_SWITCHED %LAST_SWITCHED \
%L4_SRC_PORT %L4_DST_PORT %TCP_FLAGS %PROTOCOL %SRC_TOS \
%DNS_REQ_DOMAIN %DNS_REQ_TYPE %DNS_RES_IP \
%HTTP_URL %HTTP_REQ_METHOD %HTTP_HOST %HTTP_MIME %HTTP_RET_CODE \
%ICMP_DATA %ICMP_SEQ_NUM %ICMP_PAYLOAD_LEN \
%THREAT_TYPE %THREAT_NAME %THREAT_VERS %THREAT_TIME"

void add_response_record(const string& node, const string& srv, const string& op, string id,
        const string& result, const string& status, const string& desc) {
  CtlRecord rec;
  rec.set_node(node);
  rec.set_srv(srv);
  rec.set_op(op);
  rec.set_id(stoi(id));
  rec.set_result(result);
  rec.set_status(status);
  rec.set_desc(desc);
  auto new_rec = rsp.add_records();
  *new_rec = rec;
}

void start_fcapd() {
  string cmd;
  string dir;
  unique_ptr<CachedConfig> cfg(CachedConfig::Create());
  const auto& config = cfg->config();
  for (const auto& dev : config.dev()) {
    // if ( id != 0 && dev.id() != id ) continue;
    if (!dev.disabled()) {
      cmd = "/Agent/bin/";

      if (dev.flowtype() == "netflow") {
        cmd += "nfcapd";
      } else if (dev.flowtype() == "sflow") {
        cmd += "sfcapd";
      } else {
        continue;
      }

      if (dev.has_port()){
        cmd += " -p " + to_string(dev.port());
      } else {
        continue;
      }

      cmd += " -w -D -l ";
      dir = "/data/flow/" + to_string(dev.id());
      if (opendir(dir.c_str()) == NULL) {
        log_warning("opendir failed: %s", dir.c_str());
        if (mkdir(dir.c_str(), 755) != 0) {
          log_warning("mkdir failed: %s", dir.c_str());
          continue;
        }
      }
      cmd += dir;

      if(DEBUG) log_info("capd start: %s\n", cmd.c_str());
      system(cmd.c_str());
    }
  }
}

void start_probe(uint devid) {
  string cmd;
  string dir;
  string temp = TEMPLATE_THREAT;
  unique_ptr<CachedConfig> cfg(CachedConfig::Create());
  const auto& config = cfg->config();
  for (const auto& dev : config.dev()) {
    if ( devid != 0 && dev.id() != devid ) continue;
    if (!dev.disabled()) {
      cmd = "lyprobe";

      if (dev.interface() != ""){
        cmd += " -i " + dev.interface();
      }

      if (dev.has_port()){
        if (dev.ip() == ""){
          cmd += " -n 127.0.0.1:" + to_string(dev.port());
        } else {
          cmd += " -n " + dev.ip() + ":" + to_string(dev.port());
        }
      } else {
        continue;
      }

      if ( dev.pcap_level() > 0) {
        dir = "/data/cap/" + to_string(dev.id());        
        if (opendir(dir.c_str()) == NULL) {
        log_warning("opendir failed: %s", dir.c_str());
        if (mkdir(dir.c_str(), 755) != 0) {
          log_warning("mkdir failed: %s", dir.c_str());
          continue;
        }
      }
        cmd += " -k " + to_string(dev.pcap_level()) + " -K " + dir;
      }

      if (dev.temp() != ""){
        cmd += " -T \"" + dev.temp() + "\"";
      } else {
        cmd += " -T \"" + temp + "\"";
      }

      if (dev.filter() != ""){
        cmd += " -f \"" + dev.filter() + "\"";
      }

      cmd += " -e 0 -w 32768 -G &>/dev/null";

      if(DEBUG) log_info("probe start: %s\n", cmd.c_str());
      system(cmd.c_str());
    }
  }
}

static void ProcessCap() {
  FILE* fp = NULL;
  char line[LINE_MAX] = "";
  string cmd;
  string node = GetReqNodeStr(&req);
  string op = GetReqOpStr(&req);

  switch (req.op()) {
    case CtlReq::STOP: {
      cmd = "pkill fcapd";
      system(cmd.c_str());
      cmd = "ps -A | grep fcapd";
      fp = popen(cmd.c_str(), "r");
      if (fgets(line, sizeof(line), fp)) {
        add_response_record(node, "cap", op, req.id(), "failed", "active", "");  
      } else {
        add_response_record(node, "cap", op, req.id(), "succeed", "inactive", "");
      }
      pclose(fp);
      break; 
    }
    case CtlReq::START: {
        start_fcapd();
        fp = popen("ps -A | grep fcapd", "r");
        if (fgets(line, sizeof(line), fp)) {
          add_response_record(node, "cap", op, req.id(), "succeed", "active", "");
        } else {
          add_response_record(node, "cap", op, req.id(), "failed", "inactive", "");
        }
      
      pclose(fp);
      break;
    } 
    case CtlReq::RESTART: {
      cmd = "pkill fcapd";
      system(cmd.c_str()); //先kill进程再重新执行

      start_fcapd();
      fp = popen("ps -A | grep fcapd", "r");
      if (fgets(line, sizeof(line), fp)) {
        add_response_record(node, "cap", op, req.id(), "succeed", "active", "");
      } else {
        add_response_record(node, "cap", op, req.id(), "failed", "inactive", "");
      }
      pclose(fp);
      break;
    } 
    case CtlReq::STATUS: {
      cmd = "ps -A | grep fcapd";
      fp = popen(cmd.c_str(), "r");
      if (fp == NULL) return;
      if (fgets(line, sizeof(line), fp)) {
        add_response_record(node, "cap", op, req.id(), "succeed", "active", "");
      } else {
        add_response_record(node, "cap", op, req.id(), "succeed", "inactive", "");
      }
      pclose(fp);
      break;
    } 
    default:
      break;
  }
}

static string get_probe_port(const string& str) {
  auto pos = str.find("-n ");
  auto pos1 = str.find(":", pos);
  auto pos2 = str.find(" ", pos1);
  return str.substr(pos1+1, pos2-pos1-1);
}

static string get_pid(const string& str) {
  vector<string> vec;
  boost::split(vec, str, boost::is_any_of(" "), boost::token_compress_on);
  return vec[1];
}

static int get_probe_status(const string& cfg_port){
  char line[LINE_MAX] = "";
  FILE* fp = NULL;
  string cmd;

  cmd = "ps -ef | grep probe | grep -v grep";
  fp = popen(cmd.c_str(), "r");
  if (fp == NULL) return -1;
  set<string> active_probe;
  while (fgets(line, sizeof(line), fp)) {
    string sline = line;
    active_probe.insert(get_probe_port(sline));
  }
  pclose(fp);
  if (!active_probe.empty()) {
      return active_probe.count(cfg_port);
  } else {//无存活的probe进程
      return 0;
  }
}

static void ProcessProbe() {
  char line[LINE_MAX] = "";
  FILE* fp = NULL;
  string cmd;
  string cfg_port;
  string node = GetReqNodeStr(&req);
  string op = GetReqOpStr(&req);

  unique_ptr<CachedConfig> cfg(CachedConfig::Create());
  config::Device probe_cfg;
  if (req.has_id()) {
    uint req_id = stoi(req.id());
    for (const auto& dev : cfg->config().dev()) {
      if ( dev.id() == req_id && !dev.disabled())
        probe_cfg = dev;
        cfg_port = to_string(probe_cfg.port());
    }
  }

  switch (req.op()) {
    case CtlReq::STOP: {
      //先获取运行中的probe
      cmd = "ps -ef | grep probe | grep -v grep";
      fp = popen(cmd.c_str(), "r");
      if (fp == NULL) return;
      map<string, string> active_probe;
      while (fgets(line, sizeof(line), fp)) {
        string sline = line;
        active_probe[get_probe_port(sline)] = get_pid(sline);
      }
      pclose(fp);
      //kill掉进程
      if (req.has_id()) {
        // auto cfg_port = to_string(probe_cfg.port());
        if (active_probe.count(cfg_port)) {
          string ktr = "kill -9 " + active_probe[cfg_port];
          system(ktr.c_str());
        }
        int status = get_probe_status(cfg_port);
        if (status == 0) {
          add_response_record(node, "probe", op, req.id(), "succeed", "inactive", "no probe running");
        } else if (status > 0) {
          add_response_record(node, "probe", op, req.id(), "failed", "active", "still have probe running");
        } else {
          add_response_record(node, "probe", op, req.id(), "failed", "inactive", "unknown error");
        }
        
      } else {
        system("pkill probe");
        add_response_record(node, "probe", op, 0, "succeed", "inactive", "stop all probe");
      }
      break;
    } 
    case CtlReq::START: { 
      if (!req.has_id()) {
        add_response_record(node, "probe", op, req.id(), "failed", "inactive", "No id specified.");
        return;
      }

      // 检查后台
      int status = get_probe_status(cfg_port);
      if (status > 0) {
        add_response_record(node, "probe", op, req.id(), "failed", "active", "already running");
        return;
      }

      //启动probe
      start_probe(stoi(req.id()));

      //查看是否开启成功
      status = get_probe_status(cfg_port);
      if (status > 0) {
        add_response_record(node, "probe", op, req.id(), "succeed", "active", "probe running");
      } else {
        add_response_record(node, "probe", op, req.id(), "failed", "inactive", "no probe running");
      }
      break;
    } 
    case CtlReq::RESTART: {
      // add_response_record(node, "probe", op, req.id(), "failed", "inactive", "try to use stop & start");
 
      if (!req.has_id()) {
        add_response_record(node, "probe", op, req.id(), "failed", "inactive", "need to specified id");
        return;
      }

      cmd = "ps -ef | grep probe | grep -v grep";
      fp = popen(cmd.c_str(), "r");
      if (fp == NULL) return;
      map<string, string> active_probe;
      while (fgets(line, sizeof(line), fp)) {
        string sline = line;
        active_probe[get_probe_port(sline)] = get_pid(sline);
      }
      pclose(fp);
      //kill掉进程
      if (active_probe.count(cfg_port)) {
        string ktr = "kill -9 " + active_probe[cfg_port];
        system(ktr.c_str());
      }

      //启动probe
      start_probe(stoi(req.id()));

      //查看是否开启成功
      int status = get_probe_status(cfg_port);
      if (status > 0) {
        add_response_record(node, "probe", op, req.id(), "succeed", "active", "probe running");
      } else {
        add_response_record(node, "probe", op, req.id(), "failed", "inactive", "no probe running");
      }
      break;
    } 
    case CtlReq::STATUS: {
      int status = get_probe_status(cfg_port);
      if (status > 0) {
        add_response_record(node, "probe", op, req.id(), "succeed", "active", "probe running");
      } else {
        add_response_record(node, "probe", op, req.id(), "succeed", "inactive", "probe stop running");
      }
      break;
    }
    default:
      break;
  }
}

static void ProcessSsh() {
  FILE* fp = NULL;
  char line[LINE_MAX];
  string cmd;
  string node = GetReqNodeStr(&req);
  string op = GetReqOpStr(&req);   

  switch (req.op()) {
    case CtlReq::START:
    case CtlReq::RESTART: {
      cmd = "systemctl " + op + " sshd";
      system(cmd.c_str());
      cmd = "systemctl status sshd";
      fp = popen(cmd.c_str(), "r");
      while(fgets(line, sizeof(line), fp)) {
        string str = line;
        if (str.find("Active: active (running)") != string::npos) {
          add_response_record(node, "ssh", op, req.id(), "succeed", "active", "");
          break;
        } else if (str.find("Active: inactive (dead)") != string::npos) {
          add_response_record(node, "ssh", op, req.id(), "failed", "inactive", "");
          break;
        }
      }
      pclose(fp);
    } break;
    case CtlReq::STOP: {
      cmd = "systemctl stop sshd";
      system(cmd.c_str());
      cmd = "systemctl status sshd";
      fp = popen(cmd.c_str(), "r");
      while(fgets(line, sizeof(line), fp)) {
        string str = line;
        if (str.find("Active: active (running)") != string::npos) {
          add_response_record(node, "ssh", op, req.id(), "failed", "active", "");
          break;
        } else if (str.find("Active: inactive (dead)") != string::npos) {
          add_response_record(node, "ssh", op, req.id(), "succeed", "inactive", "");
          break;
        }
      }
      pclose(fp);
    } break;
    case CtlReq::STATUS: {
      cmd = "systemctl status sshd";
      fp = popen(cmd.c_str(), "r");
      while(fgets(line, sizeof(line), fp)) {
        string str = line;
        if (str.find("Active: active (running)") != string::npos) {
          add_response_record(node, "ssh", op, req.id(), "succeed", "active", "");
          break;
        } else if (str.find("Active: inactive (dead)") != string::npos) {
          add_response_record(node, "ssh", op, req.id(), "succeed", "inactive", "");
          break;
        }
      }
      pclose(fp);
    } break;
    default:
      break;
  }
}

static void ProcessHttp() {
  char line[LINE_MAX];
  FILE* fp = NULL;
  string cmd;
  string node = GetReqNodeStr(&req);
  string op = GetReqOpStr(&req);

  switch (req.op()) {
    case CtlReq::START:
    case CtlReq::RESTART: {
      cmd = "systemctl " + op + " httpd";
      system(cmd.c_str());
      cmd = "systemctl status httpd";
      fp = popen(cmd.c_str(), "r");
      while(fgets(line, sizeof(line), fp)) {
        string str = line;
        if (str.find("Active: active (running)") != string::npos) {
          add_response_record(node, "http", op, req.id(), "succeed", "active", "");
          break;
        } else if (str.find("Active: inactive (dead)") != string::npos) {
          add_response_record(node, "http", op, req.id(), "failed", "inactive", "");
          break;
        }
      }
      pclose(fp);
      break;
    }
    case CtlReq::STOP: {
      cmd = "systemctl stop httpd";
      popen(cmd.c_str(), "r");
      cmd = "systemctl status httpd";
      fp = popen(cmd.c_str(), "r");
      while(fgets(line, sizeof(line), fp)) {
        string str = line;
        if (str.find("Active: active (running)") != string::npos) {
          add_response_record(node, "http", op, req.id(), "failed", "active", "");
          break;
        } else if (str.find("Active: inactive (dead)") != string::npos) {
          add_response_record(node, "http", op, req.id(), "succeed", "inactive", "");
          break;
        }
      }     
      pclose(fp);
      break;
    } 
    case CtlReq::STATUS: {
      cmd = "systemctl status httpd";
      fp = popen(cmd.c_str(), "r");
      while(fgets(line, sizeof(line), fp)) {
        string str = line;
        if (str.find("Active: active (running)") != string::npos) {
          add_response_record(node, "http", op, req.id(), "succeed", "active", "");
          break;
        } else if (str.find("Active: inactive (dead)") != string::npos) {
          add_response_record(node, "http", op, req.id(), "succeed", "inactive", "");
          break;
        }
      }
      pclose(fp);
      break;
    } 
    default:
      break;
  }
}

static void ProcessDisk() {
  string node = GetReqNodeStr(&req);
  string op = GetReqOpStr(&req);
  string cmd = "df -h";
  FILE* fp = popen(cmd.c_str(), "r");
  char line[LINE_MAX];
  map<string, int> disk_rec;
  fgets(line, sizeof(line), fp);
  while(fgets(line, sizeof(line), fp)) {
    vector<string> vec;
    string str = line;
    size_t pos = str.find(" ");
    while (pos != string::npos) {
      vec.push_back(str.substr(0, pos));
      string str_right = str.substr(pos + 1);
      str = trim(str_right);
      pos = str.find(" ");
    }
    vec.push_back(str);
    string percent = vec[4].substr(0, vec[4].size()-1);
    string disk = vec[5].substr(0, vec[5].size());
    disk_rec[disk] = atoi(percent.c_str()); 
  }
  for (auto& it : disk_rec) {
    CtlRecord rec;
    rec.set_node(node);
    rec.set_srv("disk");
    rec.set_op(op);
    rec.set_id(stoi(req.id()));
    if (it.first == "/home" || it.first == "/data" || it.first == "/") {
      rec.set_status(to_string(it.second)+ "%");
      rec.set_desc(it.first);
      rec.set_result("succeed");
      auto new_rec = rsp.add_records();
      *new_rec = rec;
    }
  }
  pclose(fp); 
}

static void ProcessFsd() {
  char line[LINE_MAX];
  FILE* fp = NULL;
  string cmd;
  string node = GetReqNodeStr(&req);
  string op = GetReqOpStr(&req);

  switch (req.op()) {
    case CtlReq::START:
      cmd = "/Agent/bin/fsd";
      popen(cmd.c_str(), "r");
      fp = popen("ps -A | grep fsd", "r");
      if (!feof(fp)) {
        add_response_record(node, "fsd", op, req.id(), "succeed", "active", "");
      } else {
        add_response_record(node, "fsd", op, req.id(), "failed", "inactive", "");
      }
      pclose(fp);      
      break;
    case CtlReq::RESTART:
      cmd = "pkill fsd";
      popen(cmd.c_str(), "r");
      popen("/Agent/bin/fsd", "r");
      fp = popen("ps -A | grep fsd", "r");
      if (!feof(fp)) {
        add_response_record(node, "fsd", op, req.id(), "succeed", "active", "");
      } else {
        add_response_record(node, "fsd", op, req.id(), "failed", "inactive", "");
      }
      pclose(fp);      
      break;
    case CtlReq::STOP:
      cmd = "pkill fsd";
      popen(cmd.c_str(), "r");
      cmd = "ps -A | grep fsd";
      fp = popen(cmd.c_str(), "r");
      if (fgets(line, sizeof(line), fp)) {
        add_response_record(node, "fsd", op, req.id(), "failed", "active", "");
      } else {
        add_response_record(node, "fsd", op, req.id(), "succeed", "inactive", "");
      }
      pclose(fp);
      break;
    case CtlReq::STATUS:
      cmd = "ps -A | grep fsd";    
      fp = popen(cmd.c_str(), "r");
      if (fgets(line, sizeof(line), fp)) {
        add_response_record(node, "fsd", op, req.id(), "succeed", "active", "");
      } else {
        add_response_record(node, "fsd", op, req.id(), "succeed", "inactive", "");
      }
      pclose(fp);
      break;
    default:
      break; 
  }
}

static void process() {
  if (is_http) std::cout << "Content-Type: application/protobuf; charset=UTF-8\r\n\r\n";
  std::ostringstream out;
  uid_t uid = getuid();
  setuid(0);

  switch (req.node()) {

    case CtlReq::NODE_AGENT: {
      switch (req.srv()) {
        case CtlReq::SRV_DISK: {
          ProcessDisk();
          break;
        }
        case CtlReq::SRV_SSH: {
          ProcessSsh();
          break;
        }
        case CtlReq::SRV_HTTP: {
          ProcessHttp();
          break;
        }
        case CtlReq::SRV_CAP: {
          ProcessCap();
          break;
        }
        case CtlReq::SRV_FSD: {
          ProcessFsd();
          break;
        }
        case CtlReq::SRV_ALL: {
          ProcessDisk();
          ProcessSsh();
          ProcessHttp();
          ProcessCap();
          ProcessFsd();
          break;
        }
        default:
          break;
      }
      break;
    }

    case CtlReq::NODE_PROBE: {
      switch (req.srv()) {
        case CtlReq::SRV_DISK: {
          ProcessDisk();
          break;
        }
        case CtlReq::SRV_SSH: {
          ProcessSsh();
          break;
        }
        case CtlReq::SRV_PROBE: {
          ProcessProbe();
          break;
        }
        case CtlReq::SRV_ALL: {
          ProcessDisk();
          ProcessSsh();
          ProcessProbe();
          break;
        }
        case CtlReq::SRV_FSD: {
          ProcessFsd();
          break;
        }
        default:
          break;
      }
      break;
    }

    default: {
      break;
    }

  }

  setuid(uid);

  if (!rsp.SerializeToOstream(&out)) {
    log_err("failed to serialize to string");
    return;  
  }

  if (DEBUG) log_info("out: %s\n", out.str().c_str());

  std::cout << out.str();

  return;
}

int main(int argc, char* argv[])
{
  setvbuf(stdout, NULL, _IOFBF, 81920);
  is_http = getenv("REMOTE_ADDR") != NULL;
  bool parsed = false;
  if (is_http) {
    cgicc::Cgicc cgi;
    if (!cgi("dbg").empty()) setenv("DEBUG", "ALL", 1);
    const cgicc::CgiEnvironment &cgienv = cgi.getEnvironment();
    const std::string& method = cgienv.getRequestMethod();

    if (method == "PUT" || method == "POST") {
      parsed = google::protobuf::TextFormat::ParseFromString(cgienv.getPostData(), &req);
    } else if (method == "GET") {
      parsed = ParseCtlReqFromUrlParams(cgi, &req);
    }
    if (!parsed) {
      std::cout << "HTTP/1.1 400 Invalid Params\r\n\r\n";
      return 0;
    }
  } else {
    ParseCtlReqFromCmdline(argc, argv, &req);
  }

  try {
    if (DEBUG) log_info("ctl_req: %s\n", req.DebugString().c_str());
    process();
  } catch (std::exception const &e) {
    log_err(__FILE__":%s\n", e.what());
  }
  return 0;  
}
