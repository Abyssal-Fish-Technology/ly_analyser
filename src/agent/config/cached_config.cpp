#include "cached_config.h"

#include "../../common/log.h"
#include "../define.h"
#include "local_disk_config.h"

#define USE_REDIS false
#define USE_LOCAL_DISK true

CachedConfig* CachedConfig::Create() {
  if (USE_REDIS) {
    //return RedisConfig::Create(REDIS_HOST, REDIS_PORT);
  } else if (USE_LOCAL_DISK) {
    return LocalDiskConfig::Create(AGENT_CFG_FILE);
  }
  log_err("Could not create CachedConfig\n");
  return NULL;
}
