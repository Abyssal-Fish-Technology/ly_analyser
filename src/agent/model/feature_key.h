#ifndef __AGENT_MODEL_FEATURE_KEY_H__
#define __AGENT_MODEL_FEATURE_KEY_H__

#include <stdio.h>
#include "../common/common.h"
#include "../../common/config.pb.h"

using namespace config;

#define MAX_URL_LEN    256
#define MAX_DOMAIN_LEN    128
#define FP_TYPE_LEN   32
#define FP_NAME_LEN   32
#define APP_PROTO_LEN   32

//scanner key
struct PortScanKey {
  u32 ip[4]; 
  u16 proto, port;
  bool operator<(const PortScanKey& k) const {
    return memcmp(this, &k, sizeof(k)) < 0;
  }   
  bool operator==(const PortScanKey& s) const {
     return ip[0] == s.ip[0] && ip[1] == s.ip[1] && ip[2] == s.ip[2] && ip[3] == s.ip[3] && 
            proto == s.proto && port == s.port;
  }
};

//port scan key
struct IPScanKey {
  u32 sip[4];
  u16 proto;
  u32 dip[4];
  bool operator<(const IPScanKey& k) const {
    return memcmp(this, &k, sizeof(k)) < 0;
  }
  bool operator==(const IPScanKey& s) const {
     return sip[0] == s.sip[0] && sip[1] == s.sip[1] && sip[2] == s.sip[2] && sip[3] == s.sip[3] &&
            dip[0] == s.dip[0] && dip[1] == s.dip[1] && dip[2] == s.dip[2] && dip[3] == s.dip[3];
  }
};

//service key
struct PvcKey {
  u32 ip[4];
  u16 proto, port;
  u32 srv_mark;
  bool operator<(const PvcKey& k) const {
    return memcmp(this, &k, sizeof(k)) < 0;
  }
  bool operator==(const PvcKey& s) const {
     return ip[0] == s.ip[0] && ip[1] == s.ip[1] && ip[2] == s.ip[2] && ip[3] == s.ip[3] && 
            proto == s.proto && port == s.port && srv_mark == s.srv_mark;
  }
};

//asset_srv key
struct AssetsrvKey {
  u32 ip[4];
  u16 proto, port;
  u32 srv_mark;
  bool operator<(const AssetsrvKey& k) const {
    return memcmp(this, &k, sizeof(k)) < 0;
  }
  bool operator==(const AssetsrvKey& s) const {
     return ip[0] == s.ip[0] && ip[1] == s.ip[1] && ip[2] == s.ip[2] && ip[3] == s.ip[3] && 
            proto == s.proto && port == s.port && srv_mark == s.srv_mark;
  }
};

//tcpinit key
struct TvcKey {
  u32 sip[4], dip[4];
  u16 dport;
  u16 retcode;
  bool has_res;
  bool operator<(const TvcKey& k) const {
    return memcmp(this, &k, sizeof(k)) < 0;
  }
  bool operator==(const TvcKey& s) const {
     return sip[0] == s.sip[0] && sip[1] == s.sip[1] && sip[2] == s.sip[2] && sip[3] == s.sip[3] &&
            dip[0] == s.dip[0] && dip[1] == s.dip[1] && dip[2] == s.dip[2] && dip[3] == s.dip[3] &&
            dport == s.dport && retcode == s.retcode && ((has_res && s.has_res) || (!has_res && !s.has_res));
  }
};

//sus pop
struct IPsetKey {
	u32 sip[4], dip[4];
	u16 proto;
  bool ti_mark;
	bool operator<(const IPsetKey& k) const {
		return memcmp(this, &k, sizeof(k)) < 0;	
	}
	bool operator==(const IPsetKey& s) const {
		return sip[0] == s.sip[0] && sip[1] == s.sip[1] && sip[2] == s.sip[2] && sip[3] == s.sip[3] &&
           dip[0] == s.dip[0] && dip[1] == s.dip[1] && dip[2] == s.dip[2] && dip[3] == s.dip[3] && 
            ((ti_mark && s.ti_mark) || (!ti_mark && !s.ti_mark));
	}
};

//black white
struct BWKey {
	u32 sip[4], dip[4];
	u16 proto;
  bool ti_mark;
	bool operator<(const BWKey& k) const {
		return memcmp(this, &k, sizeof(k)) < 0;
	}
	bool operator==(const BWKey& s) const {
		return sip[0] == s.sip[0] && sip[1] == s.sip[1] && sip[2] == s.sip[2] && sip[3] == s.sip[3] &&
           dip[0] == s.dip[0] && dip[1] == s.dip[1] && dip[2] == s.dip[2] && dip[3] == s.dip[3] &&
            proto == s.proto && ((ti_mark && s.ti_mark) || (!ti_mark && !s.ti_mark));
	}
};

//mo
struct MOKey {
  u32 moid;
  bool operator<(const MOKey& k) const {
    return memcmp(this, &k, sizeof(k)) < 0;
  }
  bool operator==(const MOKey& s) const {
    return moid == s.moid;
  }
};

//dns key
struct DnsKey {
  u32 sip[4];
  u32 dip[4];
  char qname[MAX_DOMAIN_LEN];
  u16 qtype;
  bool operator<(const DnsKey& k) const {
    return memcmp(this, &k, sizeof(k)) < 0;
  }
  bool operator==(const DnsKey& s) const {
    return sip[0] == s.sip[0] && sip[1] == s.sip[1] && sip[2] == s.sip[2] && sip[3] == s.sip[3] &&
           dip[0] == s.dip[0] && dip[1] == s.dip[1] && dip[2] == s.dip[2] && dip[3] == s.dip[3] && 
            !strcmp(qname, s.qname) && qtype == s.qtype;
  }
};

//dns tunnel key
struct DtKey {
  u32 sip[4];
  u32 dip[4];
  char fqname[MAX_DOMAIN_LEN];
  bool operator<(const DtKey& k) const {
    return memcmp(this, &k, sizeof(k)) < 0;
  }
  bool operator==(const DtKey& s) const {
    return sip[0] == s.sip[0] && sip[1] == s.sip[1] && sip[2] == s.sip[2] && sip[3] == s.sip[3] && 
           dip[0] == s.dip[0] && dip[1] == s.dip[1] && dip[2] == s.dip[2] && dip[3] == s.dip[3] && 
            !strcmp(fqname, s.fqname);
  }
};


//url content 
struct UrlConKey {
  u32 sip[4];
  u16 sport;
  u32 dip[4];
  u16 dport;
  char url[MAX_URL_LEN];
  bool operator<(const UrlConKey& k) const {
    return memcmp(this, &k, sizeof(k)) < 0;
  }
  bool operator==(const UrlConKey& s) const {
    return sip[0] == s.sip[0] && sip[1] == s.sip[1] && sip[2] == s.sip[2] && sip[3] == s.sip[3]&& sport == s.sport &&
           dip[0] == s.dip[0] && dip[1] == s.dip[1] && dip[2] == s.dip[2] && dip[3] == s.dip[3]&& dport == s.dport &&
           !strcmp(url, s.url);
  }
};


//icmp tunnel
struct IcmpTunKey {
  u32 sip[4];
  u32 dip[4];
  bool operator<(const IcmpTunKey& k) const {
    return memcmp(this, &k, sizeof(k)) < 0;
  }
  bool operator==(const IcmpTunKey& s) const {
    return sip[0] == s.sip[0] && sip[1] == s.sip[1] && sip[2] == s.sip[2] && sip[3] == s.sip[3] &&
           dip[0] == s.dip[0] && dip[1] == s.dip[1] && dip[2] == s.dip[2] && dip[3] == s.dip[3];
  }
};


//dga
struct DgaKey {
  u32 sip[4];
  u32 dip[4];
  char qname[MAX_DOMAIN_LEN];
  bool operator<(const DgaKey& k) const {
    return memcmp(this, &k, sizeof(k)) < 0;
  }
  bool operator==(const DgaKey& s) const {
    return sip[0] == s.sip[0] && sip[1] == s.sip[1] && sip[2] == s.sip[2] && sip[3] == s.sip[3] &&
           dip[0] == s.dip[0] && dip[1] == s.dip[1] && dip[2] == s.dip[2] && dip[3] == s.dip[3] &&
            !strcmp(qname, s.qname);
  } 
};

//威胁（后门、挖矿、黑产、注入等，通过数据包指纹匹配识别）
struct ThreatKey {
  u32 sip[4];
  // u16 sport;
  u8 proto;
  u32 dip[4];
  u16 dport;
  // char url[MAX_URL_LEN];
  char fp_type[FP_TYPE_LEN];
  char fp_name[FP_NAME_LEN];
  bool operator<(const ThreatKey& k) const {
    return memcmp(this, &k, sizeof(k)) < 0;
  }
  bool operator==(const ThreatKey& s) const {
    return sip[0] == s.sip[0] && sip[1] == s.sip[1] && sip[2] == s.sip[2] && sip[3] == s.sip[3] && /* sport == s.sport && */
           dip[0] == s.dip[0] && dip[1] == s.dip[1] && dip[2] == s.dip[2] && dip[3] == s.dip[3] && dport == s.dport &&
           proto == s.proto && !strcmp(fp_type, s.fp_type) && !strcmp(fp_name, s.fp_name);
  }
};

#endif  // __AGENT_MODEL_FEATURE_KEY_H__ 
