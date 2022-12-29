#ifndef _IPIP_H_
#define _IPIP_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json/json.h>
#include <arpa/inet.h>

namespace ipip {

typedef unsigned char byte;
typedef unsigned int uint;
#define B2IL(b) (((b)[0] & 0xFF) | (((b)[1] << 8) & 0xFF00) | (((b)[2] << 16) & 0xFF0000) | (((b)[3] << 24) & 0xFF000000))
#define B2IU(b) (((b)[3] & 0xFF) | (((b)[2] << 8) & 0xFF00) | (((b)[1] << 16) & 0xFF0000) | (((b)[0] << 24) & 0xFF000000))

static struct {
    byte *data;
    byte *index;
    uint *flag;
    uint offset;
} ipip;

namespace dat {

static inline int init(const char* ipdb) {
    if (ipip.offset) {
        return 0;
    }
    FILE *file = fopen(ipdb, "rb");
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    ipip.data = (byte *) malloc(size * sizeof(byte));
    size_t r = fread(ipip.data, sizeof(byte), (size_t) size, file);

    if (r == 0) {
        return 0;
    }

    fclose(file);

    uint length = B2IU(ipip.data);

    ipip.index = (byte *) malloc(length * sizeof(byte));
    memcpy(ipip.index, ipip.data + 4, length);

    ipip.offset = length;

    ipip.flag = (uint *) malloc(256 * sizeof(uint));
    memcpy(ipip.flag, ipip.index, 256 * sizeof(uint));

    return 0;
}

static inline int destroy() {
    if (!ipip.offset) {
        return 0;
    }
    free(ipip.flag);
    free(ipip.index);
    free(ipip.data);
    ipip.offset = 0;
    return 0;
}

static inline int find(const char *ip, char *result) {
    uint ips[4];
    int num = sscanf(ip, "%d.%d.%d.%d", &ips[0], &ips[1], &ips[2], &ips[3]);
    if (num == 4) {
        uint ip_prefix_value = ips[0];
        uint ip2long_value = B2IU(ips);
        uint start = ipip.flag[ip_prefix_value];
        uint max_comp_len = ipip.offset - 1028;
        uint index_offset = 0;
        uint index_length = 0;
        for (start = start * 8 + 1024; start < max_comp_len; start += 8) {
            if (B2IU(ipip.index + start) >= ip2long_value) {
                index_offset = B2IL(ipip.index + start + 4) & 0x00FFFFFF;
                index_length = ipip.index[start + 7];
                break;
            }
        }
        memcpy(result, ipip.data + ipip.offset + index_offset - 1024, index_length);
        result[index_length] = '\0';
    }
    return 0;
}

} // namespace dat

namespace datx {

static inline int init(const char* ipdb) {
    if (ipip.offset) {
        return 0;
    }
    FILE *file = fopen(ipdb, "rb");
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    ipip.data = (byte *) malloc(size * sizeof(byte));
    fread(ipip.data, sizeof(byte), (size_t) size, file);
    
    fclose(file);
    
    uint indexLength = B2IU(ipip.data);
    
    ipip.index = (byte *) malloc(indexLength * sizeof(byte));
    memcpy(ipip.index, ipip.data + 4, indexLength);
    
    ipip.offset = indexLength;
    
    ipip.flag = (uint *) malloc(65536 * sizeof(uint));
    memcpy(ipip.flag, ipip.index, 65536 * sizeof(uint));
    
    return 0;
}

static inline int destroy() {
    if (!ipip.offset) {
        return 0;
    }
    free(ipip.flag);
    free(ipip.index);
    free(ipip.data);
    ipip.offset = 0;
    return 0;
}

static inline int find(const char *ip, char *result) {
    uint ips[4];
    int num = sscanf(ip, "%d.%d.%d.%d", &ips[0], &ips[1], &ips[2], &ips[3]);
    if (num == 4) {
        uint ip_prefix_value = ips[0] * 256 + ips[1];
        uint ip2long_value = B2IU(ips);
        uint start = ipip.flag[ip_prefix_value];
        uint max_comp_len = ipip.offset - 262144 - 4;
        uint index_offset = 0;
        uint index_length = 0;
        for (start = start * 9 + 262144; start < max_comp_len; start += 9) {
            if (B2IU(ipip.index + start) >= ip2long_value) {
                index_offset = B2IL(ipip.index + start + 4) & 0x00FFFFFF;
                index_length = (ipip.index[start+7] << 8) + ipip.index[start+8];
                break;
            }
        }
        memcpy(result, ipip.data + ipip.offset + index_offset - 262144, index_length);
        result[index_length] = '\0';
    }
    return 0;
}

} // namespace datx

namespace ipdb {

#define  IPv4  0x01
#define  IPv6  0x02

#define ErrNoErr 0 //No error.
#define ErrFileSize 1 //"IP Database file size error."
#define ErrMetaData 2 //"IP Database metadata error."
//#define ErrReadFull 3 //"IP Database ReadFull error."
#define ErrDatabaseError 4 //"database error"

#define ErrIPFormat 5 //"Query IP Format error."

#define ErrNoSupportLanguage 6 //"language not support"
#define ErrNoSupportIPv4 7 //"IPv4 not support"
#define ErrNoSupportIPv6 8 //"IPv6 not support"

#define ErrDataNotExists 9 //"data is not exists"


typedef struct ipdb_meta_data_language {
  char name[8];
  int offset;
} ipdb_meta_data_language;

typedef struct ipdb_meta_data {
  int node_count;
  int total_size;
  short ip_version;
  long build_time;
  ipdb_meta_data_language *language;
  int language_length;
  char **fields;
  int fields_length;
} ipdb_meta_data;

typedef struct ipdb_reader {
  ipdb_meta_data *meta;
  int v4offset;
  int file_size;
  int data_size;
  unsigned char *data;
} ipdb_reader;


static inline int is_big_endian(void) {
  union {
    uint32_t i;
    char c[4];
  } e = {0x01000000};

  return e.c[0];
}

static inline  unsigned int l2b(unsigned int x) {
  return (((x >> 24) & 0x000000ff) | ((x >> 8) & 0x0000ff00) | ((x << 8) & 0x00ff0000) | ((x << 24) & 0xff000000));
}

static ipdb_meta_data *parse_meta_data(const char *meta_json) {
  ipdb_meta_data *meta_data = (ipdb_meta_data *) malloc(sizeof(ipdb_meta_data));
  memset(meta_data, 0, sizeof(ipdb_meta_data));
  json_object *obj = json_tokener_parse(meta_json);
  json_object *value;
  json_object_object_get_ex(obj, "node_count", &value);
  meta_data->node_count = json_object_get_int(value);
  json_object_object_get_ex(obj, "total_size", &value);
  meta_data->total_size = json_object_get_int(value);
  json_object_object_get_ex(obj, "build", &value);
  meta_data->build_time = json_object_get_int64(value);
  json_object_object_get_ex(obj, "ip_version", &value);
  meta_data->ip_version = (short) json_object_get_int(value);
  json_object_object_get_ex(obj, "fields", &value);
  meta_data->fields_length = json_object_array_length(value);
  meta_data->fields = (char **) malloc(sizeof(char *) * meta_data->fields_length);
  for (int i = 0; i < meta_data->fields_length; ++i) {
    json_object *it = json_object_array_get_idx(value, i);
    meta_data->fields[i] = (char *)malloc(sizeof(char) * json_object_get_string_len(it) + 1);
    strcpy(meta_data->fields[i], json_object_get_string(it));
  }
  json_object_object_get_ex(obj, "languages", &value);
  meta_data->language_length = json_object_object_length(value);
  meta_data->language = (ipdb_meta_data_language *) malloc(
          sizeof(ipdb_meta_data_language) * meta_data->language_length);
  struct json_object_iterator language = json_object_iter_begin(value);
  for (int i = 0; i < meta_data->language_length; ++i) {
    strcpy(meta_data->language[i].name, json_object_iter_peek_name(&language));
    struct json_object *it = json_object_iter_peek_value(&language);
    meta_data->language[i].offset = json_object_get_int(it);
    json_object_iter_next(&language);
  }
  json_object_iter_end(value);
  json_object_put(obj);
  return meta_data;
}
  
static inline int ipdb_read_node(ipdb_reader *reader, int node, int index) {
  int off = node * 8 + index * 4;
  int tar = *(int *) &reader->data[off];
  return l2b((unsigned int) tar);
}

static int ipdb_reader_new(const char *file, ipdb_reader **reader) {
  FILE *fd = fopen(file, "rb");
  if (!fd) {
      return ErrFileSize;
  }
  *reader = (ipdb_reader *)malloc(sizeof(ipdb_reader));
  ipdb_reader *rd = *reader;

  fseek(fd, 0, SEEK_END);
  long fsize = ftell(fd);
  fseek(fd, 0, SEEK_SET);
  unsigned int meta_length = 0;
  fread(&meta_length, sizeof(meta_length), 1, fd);
  meta_length = is_big_endian() ? meta_length : l2b(meta_length);

  char *meta_json = (char *) malloc(meta_length + 1);
  meta_json[meta_length] = 0;
  fread(meta_json, sizeof(char), meta_length, fd);
  rd->meta = parse_meta_data(meta_json);
  free(meta_json);
  if (rd->meta->language_length == 0 || rd->meta->fields_length == 0) {
      return ErrMetaData;
  }

  if (fsize != (4 + meta_length + rd->meta->total_size)) {
      return ErrFileSize;
  }
  rd->file_size = (int) fsize;
  int data_len = (int) fsize - 4 - meta_length;
  rd->data = (unsigned char *) malloc(sizeof(unsigned char) * data_len);
  fread(rd->data, sizeof(unsigned char), (size_t) data_len, fd);
  rd->data_size = data_len;

  int node = 0;
  for (int i = 0; i < 96 && node < rd->meta->node_count; ++i) {
      if (i >= 80) {
          node = ipdb_read_node(rd, node, 1);
      } else {
          node = ipdb_read_node(rd, node, 0);
      }
  }
  rd->v4offset = node;

  fclose(fd);
  return ErrNoErr;
}

static inline int ipdb_reader_is_ipv4_support(ipdb_reader *reader) {
  return (((int) reader->meta->ip_version) & IPv4) == IPv4;
}

static inline int ipdb_reader_is_ipv6_support(ipdb_reader *reader) {
  return (((int) reader->meta->ip_version) & IPv6) == IPv6;
}

static int ipdb_resolve(ipdb_reader *reader, int node, const char **bytes) {
  int resolved = node - reader->meta->node_count + reader->meta->node_count * 8;
  if (resolved >= reader->file_size) {
      return ErrDatabaseError;
  }

  int size = (reader->data[resolved] << 8) | reader->data[resolved + 2];
  if ((resolved + 2 + size) > reader->data_size) {
     return ErrDatabaseError;
  }
  *bytes = (const char *) reader->data + resolved + 2;
  return ErrNoErr;
}

static int ipdb_search(ipdb_reader *reader, const u_char *ip, int bit_count, int *node) {
  *node = 0;

  if (bit_count == 32) {
    *node = reader->v4offset;
  } else {
    *node = 0;
  }

  for (int i = 0; i < bit_count; ++i) {
    if (*node > reader->meta->node_count) {
      break;
    }

    *node = ipdb_read_node(reader, *node,
                           ((0xFF & ((int) ip[i >> 3])) >> (unsigned int) (7 - (i % 8))) & 1);
  }

  if (*node > reader->meta->node_count) {
    return ErrNoErr;
  }
  return ErrDataNotExists;
}

static int ipdb_find0(ipdb_reader *reader, const char *addr, const char **body) {
  int node = 0;
  int err;
  struct in_addr addr4;
  struct in6_addr addr6;
  if (inet_pton(AF_INET, addr, &addr4)) {
    if (!ipdb_reader_is_ipv4_support(reader)) {
        return ErrNoSupportIPv4;
    }
    err = ipdb_search(reader, (const u_char *) &addr4.s_addr, 32, &node);
    if (err != ErrNoErr) {
        return err;
    }
  } else if (inet_pton(AF_INET6, addr, &addr6)) {
    if (!ipdb_reader_is_ipv6_support(reader)) {
        return ErrNoSupportIPv6;
    }
    err = ipdb_search(reader, (const u_char *) &addr6.s6_addr, 128, &node);
    if (err != ErrNoErr) {
        return err;
    }
  } else {
    return ErrIPFormat;
  }
  err = ipdb_resolve(reader, node, body);
  return err;
}

static int ipdb_find1(ipdb_reader *reader, const char *addr, const char *language, char *body) {
  int err;
  int off = -1;
  for (int i = 0; i < reader->meta->language_length; ++i) {
    if (strcmp(language, reader->meta->language[i].name) == 0) {
        off = reader->meta->language[i].offset;
        break;
    }
  }
  if (off == -1) {
      return ErrNoSupportLanguage;
  }
  const char *content;
  err = ipdb_find0(reader, addr, &content);
  if (err != ErrNoErr) {
      return err;
  }
  int p = 0, o = 0, s = 0, e = 0;
  int len = reader->meta->fields_length;

  while (*(content + p)) {
      if (*(content + p) == '\t') {
          ++o;
      }
      if ((!e) && o == off + len) {
          e = p;
      }
      ++p;
      if (off && (!s) && o == off) {
          s = p;
      }
  }
  if (!e) e = p;
  if (off + len > o + 1) {
      err = ErrDatabaseError;
  } else {
      strncpy(body, content + s, e - s);
      body[e - s] = 0;
  }
  return err;
}

static int ipdb_reader_find(ipdb_reader *reader, const char *addr, const char *language, char *body) {
  return ipdb_find1(reader, addr, language, body);
}

  
} // namespace ipdb

} // namespace ipip

#endif //_IPIP_H_
