#include "../../common/common.h"
#include "../../common/config.h"
#include "../../common/config.pb.h"
#include "../../common/log.h"
#include "../../common/strings.h"
#include "../../common/stringutil.h"
#include "../define.h"

#define MAX_LISTENNER 200

using namespace std;

static int lsn_count = 0;
static struct t_lsn {
  int pid;
  u32 port;
  u32 devid;
  bool found;
} lsns[MAX_LISTENNER];
static config::Config cfg;
static bool dry_run = false;

////////////////////////////////////////////////////////////////////////////

static void get_listenner_list()
{
  FILE * fp;
  static char line[LINE_MAX];
  u32 id;
  lsn_count = 0;
  memset(lsns, 0, sizeof(lsns));
  fp = popen("ps -ef", "r");
  if (!fp) return;
  while (fgets(line, sizeof(line), fp))
  {
    char * s;
    int pid;
    s = strtok(line, " \r\n");
    if (!s) continue;
    s = strtok(NULL, " \r\n");
    pid = atoi(s);
    s = strtok(NULL, " \r\n");
    s = strtok(NULL, " \r\n");
    s = strtok(NULL, " \r\n");
    s = strtok(NULL, " \r\n");
    s = strtok(NULL, " \r\n");
    s = strtok(NULL, "\r\n");
    if (strncmp(s, "nfcapd ", strlen("nfcapd ")) &&
        strncmp(s, "sfcapd ", strlen("sfcapd "))) continue;

    // get dev id
    char * p = strstr(s, AGENT_FLOW_DIR);
    if (!p) continue;
    p += strlen(AGENT_FLOW_DIR) + 1; // add trailer '\'
    if (1 != sscanf(p, "%u", &id)) continue;
    lsns[lsn_count].devid = id;

    // get port
    int port  = 9995;
    p = strstr(s, "-p");
    if (p)
    {
      p += strlen("-p");
      while (*p == ' ') p++;
      char * q = strtok(p, " \r\n");
      if (!q) continue;
      port = atoi(q);
    }
    lsns[lsn_count].port = port;
    
    // others
    lsns[lsn_count].pid = pid;
    lsns[lsn_count].found = false;
    if (dry_run) printf("found flow capdd pid:%d devid:%u port:%d\n", pid, id, port);
    lsn_count++;
  }
  fclose(fp);
}

////////////////////////////////////////////////////////////////////////////
static bool read_config(void) 
{
  ConfigReader cfg_reader(AGENT_CFG_FILE);
  if (!cfg_reader.LoadFromFile()) return false;
  cfg.Swap(cfg_reader.mutable_config());
  return true;
}

////////////////////////////////////////////////////////////////////////////

static void process(const string& append_parameters)
{
  string cmd;
  if (!read_config()) {
    log_err("Can't load config file.\n");
    return;
  }

  get_listenner_list();
  for (auto i = 0; i < cfg.dev_size(); ++i)
  {
    const auto& dev = cfg.dev(i);
    if (dev.disabled()) continue;
   
    bool found;
    found = false;
    for (i = 0; i < lsn_count; i++)
    {
      if ((lsns[i].devid == dev.id()) && (lsns[i].port == dev.port()))
      {
        lsns[i].found = true;
        found = true;
      }
    }

    if (!found)
    {
      std::string dev_ip_dir = AGENT_FLOW_DIR"/" + dev.ip();
      std::string dev_id_dir = AGENT_FLOW_DIR"/" + to_string(dev.id());
      if (dry_run) {
        printf("mkdir %s\n", dev_ip_dir.c_str());
        printf("ln -s %s %s\n", dev_ip_dir.c_str(), dev_id_dir.c_str());
      } else {
        mkdir(dev_ip_dir.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        symlink(dev_ip_dir.c_str(), dev_id_dir.c_str());
      }
      string flowcapd;
      if (dev.flowtype() == "netflow") {
        flowcapd = "nfcapd";
      } else if (dev.flowtype() == "sflow") {
        flowcapd = "sfcapd";
      } else {
        flowcapd = "nfcapd";
      }
      cmd = StringPrintf(
        "%s -w -D -l %s -p %u %s", flowcapd.c_str(), dev_id_dir.c_str(),
        dev.port(), append_parameters.c_str());

      if (dry_run) {
        printf("%s\n", cmd.c_str());
      } else {
        log_info("%s\n", cmd.c_str());
        system(cmd.c_str());
      }
    }
  }

  for (auto i = 0; i < lsn_count; i++) {
    if (!lsns[i].found)
    {
      if (dry_run) {
        printf("kill %u\n", lsns[i].pid);
      } else {
        log_info("%s\n", cmd.c_str());
        kill(lsns[i].pid, SIGTERM);
      }
    }
  }
}

static void usage(char * pn)
{
  fprintf(stderr, "usage %s [-d] [-a append_parameters] \n", pn);
  exit(1);
}

int main(int argc, char *argv[])
{
  string append_parameters;
  char c;

  while ((c = getopt(argc, argv, "da:")) != -1)
  {
    switch (c)
    {
    case 'd':
      dry_run = true;
      break;
    case 'a':
      append_parameters = optarg;
      break;
    default:
      usage(argv[0]);
    }
  }
 
  if (optind < argc) 
  {
    fprintf(stderr, "non-option ARGV-elements: ");
    while (optind < argc)
      fprintf(stderr, "%s ", argv[optind++]);
    fprintf(stderr, "\n");
    usage(argv[0]);
  }

  process(append_parameters);
  return 0;
}
