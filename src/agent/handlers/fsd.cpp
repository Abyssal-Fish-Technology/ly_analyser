#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string>
#include "../../common/log.h"
#include "../../common/config.h"
#include "../../common/config.pb.h"
#include "../../common/strings.h"
#include "../config/cached_config.h"
#include "../../common/CMyINI.h"

using namespace std;

static FILE* pFile;

void write_log(const char* fmt, ...) {
  va_list arg;
  va_start (arg, fmt);
  time_t time_log = time(NULL);
  struct tm* tm_log = localtime(&time_log);
  fprintf(pFile, "%04d-%02d-%02d %02d:%02d:%02d fsd:", 
          tm_log->tm_year + 1900, tm_log->tm_mon + 1, 
          tm_log->tm_mday, tm_log->tm_hour, tm_log->tm_min, tm_log->tm_sec);
  vfprintf(pFile, fmt, arg);
  va_end (arg);
  fflush(pFile);
}

void create_daemon() {
  pid_t pid;
  pid = fork();
  if (pid < 0) {
    log_err("error in fork.\n");
    exit(1);
  }
  else if (pid > 0) {
    exit(0);
  } 
  if (-1 == setsid()) {
    log_err("setsid error.\n");
    exit(1);
  }
  pid = fork();
  if (pid < 0) {
    log_err("error in fork.\n");
    exit(1);
  }
  else if (pid > 0) {
    exit(0);
  }
  chdir("/");
  int fd;
  fd = open("/dev/null",O_RDWR,0);
  if (fd != -1){
    dup2(fd,STDIN_FILENO);
    dup2(fd,STDOUT_FILENO);
    dup2(fd,STDERR_FILENO);
    if (fd > 2)
      close(fd);
  }

  umask(0);
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
        cmd = "nfcapd -w -D -l " + dir + " " + "-p " + to_string(dev.port());
      } else if (dev.flowtype() == "sflow") {
        cmd = "sfcapd -w -D -l " + dir + " " + "-p " + to_string(dev.port());
      }
      system(cmd.c_str());
    }
  }
}

void start_probe() {
  unique_ptr<CMyINI> myini(new CMyINI());
  myini->ReadINI("/Agent/etc/probe.conf");

  unique_ptr<CachedConfig> cfg(CachedConfig::Create());
  const auto& config = cfg->config();
  for (const auto& dev : config.dev()) {
    if (dev.disabled()) continue;
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
       
      cmd += " -i " + t["if"] + " -n " + t["ip"] +
              ":" + t["port"] + " -e 0 -w 32768 -G" + " -k 1 -K " + t["pcap"] + "/" + to_string(dev.id());

      if (t["ver"] == "9") 
        cmd += " -T \"" + t["plugins"] + "\"";
     
      system(cmd.c_str());
           
    }
  }
}

void check_disk() {
  string cmd = "df -h";
  FILE *fp = NULL;
  char line[LINE_MAX];
  map<string, int> Disk;
  fp = popen(cmd.c_str(), "r");
  if (fp == NULL) return;
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
    Disk[disk] = atoi(percent.c_str());
  }

  pclose(fp);
  unique_ptr<CMyINI> myini(new CMyINI());
  myini->ReadINI("/Agent/etc/disk.cnf");
  for (auto itr = myini->map_ini.begin();itr != myini->map_ini.end(); itr++) {
    auto t = itr->second.sub_node;
    string mount = t["mount"];
    if (Disk[mount] >= atoi(t["percent"].c_str())) 
      write_log("disk %s is full.\n", mount.c_str());
    else
      write_log("disk %s used %d.\n", mount.c_str(), Disk[mount]);
  }
}

void process() {
  create_daemon();
  char row[LINE_MAX];  
  string cmd_probe = "ps -A | grep probe";
  string cmd_nfcap = "ps -A | grep fcapd";
  while(1) {
    pFile = fopen("/Agent/data/log", "a");
    FILE* fp = NULL;
    fp = popen(cmd_probe.c_str(), "r");
    if (fp == NULL) {
      return;
    }
    string probe;
    if(fgets(row, sizeof(row), fp)) {
      string str = row;
      size_t pos = str.find_last_of(" ");
      if (pos != string::npos) {
        probe = str.substr(pos+1);
      }

      if (probe == "fprobe\n")
        write_log("fprobe is running.\n");
      else if (probe == "nprobe\n")
        write_log("nprobe is running.\n");
    } else {
      write_log("fprobe or nprobe is down.\n");
      start_probe();
    }
    pclose(fp);
 
    fp = popen(cmd_nfcap.c_str(), "r");
    if (fp == NULL)
      return;

    string fcapd;
    if(fgets(row, sizeof(row), fp)) {
      string str = row;
      size_t pos = str.find_last_of(" ");
      if (pos != string::npos) {
        fcapd = str.substr(pos+1);
      }
        
      if (fcapd == "nfcapd\n")
        write_log("nfcapd is running.\n");
      else if (fcapd == "sfcapd\n")
        write_log("sfcapd is running.\n");
    } else {
      write_log("nfcapd or sfcapd is down.\n");
      start_fcapd();
    }
    pclose(fp);

    check_disk();    

    fclose(pFile);
    sleep(60);
  }
}


int main(int argc, char* argv[])
{
  process();
  return 0;
}

