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

void add_each_res(const string& type, const string& op, string tid,
        const string& result, const string& status, const string& desc) {
  CtlRecord rec;
  rec.set_type(type);
  rec.set_op(op);
  rec.set_tid(stoi(tid));
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
    if (!dev.disabled()) {
      dir = "/data/flow/" + to_string(dev.id());
      if (opendir(dir.c_str()) == NULL) {
        if (mkdir(dir.c_str(), 755)) return;
      }
      if (dev.flowtype() == "netflow") {
        cmd = "/Agent/bin/nfcapd -w -D -l " + dir + " " + "-p " + to_string(dev.port());
      } else if (dev.flowtype() == "sflow") {
        cmd = "/Agent/bin/sfcapd -w -D -l " + dir + " " + "-p " + to_string(dev.port());
      }
      system(cmd.c_str());
    }
  }
}


static void ProcessCap() {
  FILE* fp = NULL;
  char line[LINE_MAX] = "";
  string cmd;
  string op = GetReqOpStr(&req);

  switch (req.op()) {
    case CtlReq::STOP: {
      cmd = "pkill fcapd";
      system(cmd.c_str());
      cmd = "ps -A | grep fcapd";
      fp = popen(cmd.c_str(), "r");
      if (fgets(line, sizeof(line), fp)) {
        add_each_res("cap", op, req.tid(), "failed", "active", "");  
      } else {
        add_each_res("cap", op, req.tid(), "succeed", "inactive", "");
      }
      pclose(fp);   
    }break;
    case CtlReq::START: {
        start_fcapd();
        fp = popen("ps -A | grep fcapd", "r");
        if (fgets(line, sizeof(line), fp)) {
          add_each_res("cap", op, req.tid(), "succeed", "active", "");
        } else {
          add_each_res("cap", op, req.tid(), "failed", "inactive", "");
        }
      
      pclose(fp);
    } break;
    case CtlReq::RESTART: {
      cmd = "pkill fcapd";
      system(cmd.c_str()); //先kill进程再重新执行

      start_fcapd();
      fp = popen("ps -A | grep fcapd", "r");
      if (fgets(line, sizeof(line), fp)) {
        add_each_res("cap", op, req.tid(), "succeed", "active", "");
      } else {
        add_each_res("cap", op, req.tid(), "failed", "inactive", "");
      }
      pclose(fp);
    } break;
    case CtlReq::STAT: {
      cmd = "ps -A | grep fcapd";
      fp = popen(cmd.c_str(), "r");
      if (fp == NULL) return;
      if (fgets(line, sizeof(line), fp)) {
        add_each_res("cap", op, req.tid(), "succeed", "active", "");
      } else {
        add_each_res("cap", op, req.tid(), "succeed", "inactive", "");
      }
      pclose(fp);
    } break;
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


void start_probe_from_ini(unique_ptr<CMyINI>& myini, const config::Device& dev) {
  for (auto it= myini->map_ini.begin();it != myini->map_ini.end(); it++) {
    auto t = it->second.sub_node;
    if (t["disabled"] == "Y") continue;
    if (t["port"] != to_string(dev.port())) continue;
    string cmd;

    string probe = t["type"];
    if (dev.model() == "V4") {
      cmd = probe;
    } else {
      cmd = probe + " -f ip6";
      if (string::npos != t["plugins"].find("IPV4")) {
        log_err("probe ip type not match.\n");
        continue;
      }
    }

    cmd += " -b 0 -i " + t["if"] + " -n " + t["ip"] +
            ":" + t["port"] + " -e 0 -w 32768 -G" + " -k 1 -K " + t["pcap"] + "/" + to_string(dev.id());

    if (t["ver"] == "9")
      cmd += " -T \"" + t["plugins"] + "\"";

    system(cmd.c_str());
  } 
}


static void ProcessProbe() {
  unique_ptr<CachedConfig> cfg(CachedConfig::Create());
  std::map<string, config::Device> devs; 
  std::set<string> devids;
  for (const auto& dev : cfg->config().dev()) {
    if (!dev.disabled())
      devs[to_string(dev.id())] = dev;
  }

  if (req.has_devid()) {
    string ids = const_cast<char*>(req.devid().c_str()); 
    devids = split_string(ids, ",");
  
    for (auto it = devids.begin(); it != devids.end();) {
      auto& did = *it;
      if (devs.find(did) != devs.end()) {
        if (to_string(devs[did].agentid()) != req.tid()) {
          devids.erase(it++);
        } else {
          ++it;
        }
      } else {
        devids.erase(it++);
      }
    }
  } else {
    for (const auto& dev : cfg->config().dev()) {
      if (!dev.disabled() && to_string(dev.agentid()) == req.tid()) {
        devids.insert(to_string(dev.id()));
      }
    } 
  }
  if (req.has_devid() && devids.size()==0) return;

  char line[LINE_MAX] = "";
  FILE* fp = NULL;
  string cmd;
  string op = GetReqOpStr(&req);

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
      if (req.has_devid()) {
        for (auto& devid : devids) {
          auto port = to_string(devs[devid].port());
          if (active_probe.count(port)) {
            string ktr = "kill -9 " + active_probe[port];
            system(ktr.c_str());
            add_each_res("probe", op, req.tid(), "succeed", "inactive", devid);
          }
        }
      } else {
        system("pkill probe");
        add_each_res("probe", op, req.tid(), "succeed", "inactive", "");
      }
    } break;
    case CtlReq::RESTART: {
      ifstream ifs("/etc/rc.local");
      string sline;
      map<string, string> cmds;
      while(getline(ifs, sline)) {
        cmd.clear();
        trim(sline);
        if (sline.empty() || sline[0] == '#') continue;
        if (sline.find("probe -") != string::npos) {  //nprobe cmd line
          auto port_str = get_probe_port(sline);
          cmds[port_str] = sline;
        }
      }
      if (!req.has_devid()) {
        cmd = "pkill probe";
        system(cmd.c_str());
        for (auto itr : cmds) {
          auto& s = itr.first;
          auto& p = itr.second;
          system(p.c_str());
          CtlRecord rec;
          rec.set_type("probe");
          rec.set_op(GetReqOpStr(&req));
          rec.set_tid(stoi(req.tid()));
          rec.set_result("succeed");
          rec.set_status("active");
          for (auto it : devs) {
            if (to_string(it.second.agentid()) == req.tid() && to_string(it.second.port()) == s) {
              rec.set_desc(it.first);
              break;
            }
          }
          auto new_rec = rsp.add_records();
          *new_rec = rec;
        }
      } else {
        cmd = "ps -ef | grep probe | grep -v grep";
        fp = popen(cmd.c_str(), "r");
        if (fp == NULL) return;
        map<string, string> active_probe;
        while (fgets(line, sizeof(line), fp)) {
          string sline = line;
          active_probe[get_probe_port(sline)] = get_pid(sline);
        }
        for (auto& devid : devids) {
          auto id = to_string(devs[devid].port());
          if (active_probe.count(id)) {
            string ktr = "kill -9 " + active_probe[id];
            system(ktr.c_str());
            if (cmds.count(id)) {
              system(cmds[id].c_str());
              CtlRecord rec;
              rec.set_type("probe");
              rec.set_op(GetReqOpStr(&req));
              rec.set_tid(stoi(req.tid()));
              rec.set_result("succeed");
              rec.set_status("active");
              rec.set_desc(devid);
              auto new_rec = rsp.add_records();
              *new_rec = rec;
            }
          }
        }
      }
    } break;
    case CtlReq::START: { 
      unique_ptr<CMyINI> myini(new CMyINI());
      myini->ReadINI("/Agent/etc/probe.conf");
      //启动nprobei
      if (req.has_devid()) { 
        for (auto& did : devids) {
          start_probe_from_ini(myini, devs[did]);
        } 
      } else {
        for (auto& dev : devs) {
          start_probe_from_ini(myini, dev.second);
        }
      }

      //查看是否开启成功
      cmd = "ps -ef | grep probe | grep -v grep";
      fp = popen(cmd.c_str(), "r");
      if (fp == NULL) return;
      set<string> active_probe;
      while (fgets(line, sizeof(line), fp)) {
        string sline = line;
        active_probe.insert(get_probe_port(sline));
      }
      if (!active_probe.empty()) {
        if (req.has_devid()) { //指定devid 
          for (auto& did : devids) {
            if (active_probe.count(to_string(devs[did].port()))) 
              add_each_res("probe", op, req.tid(), "succeed", "active", did);
            else
              add_each_res("probe", op, req.tid(), "failed", "inactive", did);
          }
        } else {
          for (auto& k : active_probe) { //无devid参数,获取全部nprobe状态
            for (auto it : devs) {
              if (to_string(it.second.agentid()) == req.tid() && to_string(it.second.port()) == k) {
                add_each_res("probe", op, req.tid(), "succeed", "active", it.first);
                break;
              }
            }
          }
        }
      } else {//无存活的probe进程
        for (auto& id : devids) {
          add_each_res("probe", op, req.tid(), "failed", "inactive", id);
        }
      }

      pclose(fp); 
    } break;
    case CtlReq::STAT: {
      cmd = "ps -ef | grep probe | grep -v grep";
      fp = popen(cmd.c_str(), "r");
      if (fp == NULL) return;
      set<string> active_probe;
      while (fgets(line, sizeof(line), fp)) {
        string sline = line;
        active_probe.insert(get_probe_port(sline));
      }
      if (!active_probe.empty()) {
        if (req.has_devid()) {
          for (auto& did : devids) {
            if (active_probe.count(to_string(devs[did].port()))) {
              add_each_res("probe", op, req.tid(), "succeed", "active", did);
            } else {
              add_each_res("probe", op, req.tid(), "succeed", "inactive", did);
            }
          }
        } else {   //无devid参数,获取全部nprobe状态
          for (auto& k : active_probe) {
            for (auto it : devs) {
              if (to_string(it.second.agentid()) == req.tid() && to_string(it.second.port()) == k) {
                add_each_res("probe", op, req.tid(), "succeed", "active", it.first);
              }
            }
          }
        }  
      } else {
        for (auto& id : devids) {
          add_each_res("probe", op, req.tid(), "succeed", "inactive", id);
        }
      } 
      pclose(fp);
    } break;
    default:
      break;
  }
}

static void ProcessSsh() {
  FILE* fp = NULL;
  char line[LINE_MAX];
  string cmd;
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
          add_each_res("ssh", op, req.tid(), "succeed", "active", "");
          break;
        } else if (str.find("Active: inactive (dead)") != string::npos) {
          add_each_res("ssh", op, req.tid(), "failed", "inactive", "");
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
          add_each_res("ssh", op, req.tid(), "failed", "active", "");
          break;
        } else if (str.find("Active: inactive (dead)") != string::npos) {
          add_each_res("ssh", op, req.tid(), "succeed", "inactive", "");
          break;
        }
      }
      pclose(fp);
    } break;
    case CtlReq::STAT: {
      cmd = "systemctl status sshd";
      fp = popen(cmd.c_str(), "r");
      while(fgets(line, sizeof(line), fp)) {
        string str = line;
        if (str.find("Active: active (running)") != string::npos) {
          add_each_res("ssh", op, req.tid(), "succeed", "active", "");
          break;
        } else if (str.find("Active: inactive (dead)") != string::npos) {
          add_each_res("ssh", op, req.tid(), "succeed", "inactive", "");
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
  CtlRecord rec;
  char line[LINE_MAX];
  FILE* fp = NULL;
  string cmd;
  string op = GetReqOpStr(&req);
  //rec.set_type(GetReqTypeStr(&req));
  rec.set_type("http");
  rec.set_op(op);
  rec.set_tid(stoi(req.tid()));

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
          rec.set_status("active");
          rec.set_result("succeed");
          rec.set_desc("");
          break;
        } else if (str.find("Active: inactive (dead)") != string::npos) {
          rec.set_status("inactive");
          rec.set_result("failed");
          rec.set_desc("");
          break;
        }
      }
      pclose(fp);
    } break;
    case CtlReq::STOP: {
      cmd = "systemctl stop httpd";
      popen(cmd.c_str(), "r");
      cmd = "systemctl status httpd";
      fp = popen(cmd.c_str(), "r");
      while(fgets(line, sizeof(line), fp)) {
        string str = line;
        if (str.find("Active: active (running)") != string::npos) {
          rec.set_status("active");
          rec.set_result("failed");
          rec.set_desc("");
          break;
        } else if (str.find("Active: inactive (dead)") != string::npos) {
          rec.set_status("inactive");
          rec.set_result("succeed");
          rec.set_desc("");
          break;
        }
      }     
      pclose(fp);
    } break;
    case CtlReq::STAT: {
      cmd = "systemctl status httpd";
      fp = popen(cmd.c_str(), "r");
      while(fgets(line, sizeof(line), fp)) {
        string str = line;
        if (str.find("Active: active (running)") != string::npos) {
          rec.set_status("active");
          rec.set_result("succeed");
          rec.set_desc("");
          break;
        } else if (str.find("Active: inactive (dead)") != string::npos) {
          rec.set_status("inactive");
          rec.set_result("succeed");
          rec.set_desc("");
          break;
        }
      }
      pclose(fp);
    } break;
    default:
      break;
  }
  auto new_rec = rsp.add_records();
  *new_rec = rec;
}

static void ProcessDisk() {
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
    //rec.set_type(GetReqTypeStr(&req));
    rec.set_type("disk");
    rec.set_op(GetReqOpStr(&req));
    rec.set_tid(stoi(req.tid()));
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
  string op = GetReqOpStr(&req);

  switch (req.op()) {
    case CtlReq::START:
      cmd = "/Agent/bin/fsd";
      popen(cmd.c_str(), "r");
      fp = popen("ps -A | grep fsd", "r");
      if (!feof(fp)) {
        add_each_res("fsd", op, req.tid(), "succeed", "active", "");
      } else {
        add_each_res("fsd", op, req.tid(), "failed", "inactive", "");
      }
      pclose(fp);      
      break;
    case CtlReq::RESTART:
      cmd = "pkill fsd";
      popen(cmd.c_str(), "r");
      popen("/Agent/bin/fsd", "r");
      fp = popen("ps -A | grep fsd", "r");
      if (!feof(fp)) {
        add_each_res("fsd", op, req.tid(), "succeed", "active", "");
      } else {
        add_each_res("fsd", op, req.tid(), "failed", "inactive", "");
      }
      pclose(fp);      
      break;
    case CtlReq::STOP:
      cmd = "pkill fsd";
      popen(cmd.c_str(), "r");
      cmd = "ps -A | grep fsd";
      fp = popen(cmd.c_str(), "r");
      if (fgets(line, sizeof(line), fp)) {
        add_each_res("fsd", op, req.tid(), "failed", "active", "");
      } else {
        add_each_res("fsd", op, req.tid(), "succeed", "inactive", "");
      }
      pclose(fp);
      break;
    case CtlReq::STAT:
      cmd = "ps -A | grep fsd";    
      fp = popen(cmd.c_str(), "r");
      if (fgets(line, sizeof(line), fp)) {
        add_each_res("fsd", op, req.tid(), "succeed", "active", "");
      } else {
        add_each_res("fsd", op, req.tid(), "succeed", "inactive", "");
      }
      pclose(fp);
      break;
    default:
      break; 
  }
}

static void ProcessAll() {
  ProcessSsh();
  ProcessHttp();
  ProcessProbe();
  ProcessCap();
  ProcessDisk();
  ProcessFsd();
}

static void process() {
  if (is_http) std::cout << "Content-Type: application/protobuf; charset=UTF-8\r\n\r\n";
  std::ostringstream out;
  uid_t uid = getuid();
  setuid(0);

  switch (req.type()) {
    case CtlReq::SSH:
      ProcessSsh();
      break;
    case CtlReq::HTTP:
      ProcessHttp();
      break;
    case CtlReq::PROBE:
      ProcessProbe();
      break;
    case CtlReq::CAP:
      ProcessCap();
      break;
    case CtlReq::ALL:
      ProcessAll();
      break;
    case CtlReq::DISK:
      ProcessDisk();
      break;
    case CtlReq::FSD:
      ProcessFsd();
      break;
    default:
      break;
  }


  setuid(uid);
  if (!rsp.SerializeToOstream(&out)) {
    log_err("failed to serialize to string");
    return;  
  }

  std::cout << out.str();

  return;
}

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

void ParseFromCmdline(int argc, char*argv[]) {
  char c;
  while ((c = getopt(argc, argv, "t:o:i:d:")) != -1)
  {
    if (optarg==NULL)
        continue;

    switch (c)
    {
      case 'i':
        req.set_tid(optarg);
        break;
      case 'd':
        req.set_devid(optarg);
        break;
      case 't':
      {
        string type = optarg;
        setService(boost::to_upper_copy(type), &req);
        break;
      }
      case 'o':
      {
        string op = optarg;
        setOp(boost::to_upper_copy(op), &req);
        break;
      }
      default:
        break;
    }
  }
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
  } else 
    ParseFromCmdline(argc, argv);

  try {
    if (DEBUG) log_info("ctl_req: %s\n", req.DebugString().c_str());
    process();
  } catch (std::exception const &e) {
    log_err(__FILE__":%s\n", e.what());
  }
  return 0;  
}
