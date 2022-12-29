#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
typedef char s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#define APP_PROTO_LEN 8
#define MAX_DOMAIN_LEN 128
#define MAX_URL_LEN 256

//asset_srv
typedef struct SrvKey {
  u32 ip[4];
  u16 proto, port;
  u32 srv_mark;
} SrvKey_t;

// typedef struct UnqliteValue1 {
//   u32 first;
//   u32 last;
//   u64 flows;
//   u64 pkts;
//   u64 bytes;
//   char app_proto[APP_PROTO_LEN];//8
// } SrvValue_t;

typedef struct UnqliteValue1 {
  u32 first;
  u32 last;
  u64 flows;
  u64 pkts;
  u64 bytes;
  u32 srv_type;
  char app_proto[APP_PROTO_LEN];
  char srv_name[32];
  char srv_info1[64];
  char srv_info2[64];
} SrvValue_t;


//asset_ip
typedef struct IPKey {
  u32 ip[4];
} IPKey_t;

//asset_url
typedef struct UrlKey {
  u32 ip[4];
  u16 port;
  char url[MAX_URL_LEN];//256
  u16 retcode;
} UrlKey_t;

//asset_host
typedef struct HostKey {
  u32 ip[4];
  u16 port;
  char host[MAX_DOMAIN_LEN];//128
} HostKey_t;

typedef struct UnqliteValue2 {
  u32 first;
  u32 last;
  u64 flows;
  u64 pkts;
  u64 bytes;
} UrlValue_t, IPValue_t, HostValue_t;


