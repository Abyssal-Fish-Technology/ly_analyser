#include "common.h"
#include "log.h"
#include "strings.h"
#include "ip.h"
#include <sstream>
#include <map>
#include <math.h>

using namespace std;

////////////////////////////////////////////////////////////////////////////
bool is_private_ip(const u32 ip) {
  u32 a,b;
  a = ip >> 24;
  b = (ip >> 16) & 0xff;
  if ((a == 192) && (b == 168)) return true;
  if ((a == 172) && (b >= 16) && (b < 32)) return true;
  if (a == 10) return  true;
  return false;
}

////////////////////////////////////////////////////////////////////////////
std::string ipnum_to_ipstr(const u32 ipnum)
{
  struct sockaddr_in in; 
  in.sin_addr.s_addr = htonl(ipnum);
  return inet_ntoa(in.sin_addr);
}

////////////////////////////////////////////////////////////////////////////
std::string ipnum_to_ipstr(const std::string& ipnum)
{
  struct sockaddr_in in; 
  in.sin_addr.s_addr = htonl(atol(ipnum.c_str()));
  return inet_ntoa(in.sin_addr);
}

////////////////////////////////////////////////////////////////////////////
u32 ipstr_to_ipnum(const std::string& ipstr)
{
  struct in_addr addr;
  return inet_aton(ipstr.c_str(), &addr) ? ntohl(addr.s_addr) : 0;
}

//////////////////////////////ipv4网段验证///////////////////////////////////
bool valid_ip(string ipstr, string ip_segment) {
  string str1, str2;
  if (ip_segment.empty()) return false;

  int len = ip_segment.size();
  size_t pos = ip_segment.find("/");
  if (pos != std::string::npos) {
    str1 = ip_segment.substr(0, pos);
    str2 = ip_segment.substr(pos + 1, len - pos - 1);
  } else {
    str1 = ip_segment;
    str2 = "32";
  }
  u32 ips = ipstr_to_ipnum(str1);
  u32 ip = ipstr_to_ipnum(ipstr);
  u32 mask;
  stringstream ss;
  ss << str2;
  ss >> mask;
  if (ip <= (ips + pow(2, 32 - mask)- 1) && ip >= ips)
    return true;
  else
    return false;
}

/*************************** ipv6转换 *************************************/
struct in6_addr ipstr_to_ipnum_v6(const string &ipstr){
  struct in6_addr ipnum;
  if(inet_pton(AF_INET6, ipstr.c_str(), &ipnum))
    for (int i = 0; i < 4; i++)
      ipnum.s6_addr32[i] = ntohl(ipnum.s6_addr32[i]);
  else
    for (int i = 0; i < 4; i++)
      ipnum.s6_addr32[i] = 0;

  return ipnum;
}

std::string ipnum_to_ipstr_v6(struct in6_addr ipnum){
  string tmp;
  char *ipstr = (char *)malloc(50);
  for (int i = 0; i < 4; i++)
    ipnum.s6_addr32[i] = htonl(ipnum.s6_addr32[i]);
  tmp = inet_ntop(AF_INET6, &ipnum, ipstr, 50);
  return tmp;
}

/*************************** ipv6 网段验证 *********************************/
bool valid_ip_v6(string ipstr, string ip_segment) {
  string str1, str2;
  if (ip_segment.empty()) return false;

  int len = ip_segment.size();
  size_t pos = ip_segment.find("/");
  if (pos != std::string::npos) {
    str1 = ip_segment.substr(0, pos);
    str2 = ip_segment.substr(pos + 1, len - pos - 1);
  } else {
    str1 = ip_segment;
    str2 = "128";
  }

  struct in6_addr net = ipstr_to_ipnum_v6(str1);
  struct in6_addr ip = ipstr_to_ipnum_v6(ipstr);
  u32 mask_len = atoi(str2.c_str());
  
  int pivot = mask_len / 32;
  int shift = mask_len % 32;

  if (pivot < 4) {
    ip.s6_addr32[pivot] = (ip.s6_addr32[pivot] >> shift) << shift;
  }
  for (int i = pivot+1; i < 4; i++) {
    ip.s6_addr32[i] = 0;
  }

  for (int i = 0; i < pivot; i++) {
    if( net.s6_addr32[i] != ip.s6_addr32[i])
      return false;
  }
  return true;
}

/****************************** ipv6 零压缩 *********************************/
std::string ipv6_zero_compress(const string &ipstr){
  struct in6_addr ipnum;

  if (!inet_pton(AF_INET6, ipstr.c_str(), &ipnum))
    return "Illegal IPv6 Address.";

  char *tmp = (char *)malloc(50);
  inet_ntop(AF_INET6, &ipnum, tmp, 50);
  std::string ret = tmp;

  return ret;
}

////////////////////////////////////////////////////////////////////////////
std::string proto_to_string(u16 prot) {
  map<u16, string> proto;
  proto[0] = "HOPOPT";
  proto[1] = "ICMP";
  proto[2] = "IGMP";
  proto[3] = "GGP";
  proto[4] = "IP";
  proto[5] = "ST";
  proto[6] = "TCP";
  proto[7] = "CBT";
  proto[8] = "EGP";
  proto[9] = "IGP";
  proto[10] = "BBN-RCC-MON";
  proto[11] = "NVP-II";
  proto[12] = "PUP";
  proto[13] = "ARGUS";
  proto[14] = "EMCON";
  proto[15] = "XNET";
  proto[16] = "CHAOS";
  proto[17] = "UDP";
  proto[18] = "MUX";
  proto[19] = "DCN-MEAS";
  proto[20] = "HMP";
  proto[21] = "PRM";
  proto[22] = "XNS-IDP";
  proto[23] = "TRUNK-1";
  proto[24] = "TRUNK-2";
  proto[25] = "LEAF-1";
  proto[26] = "LEAF-2";
  proto[27] = "RDP";
  proto[28] = "IRTP";
  proto[29] = "ISO-TP4";
  proto[30] = "NETBLT";
  proto[31] = "MFE-NSP";
  proto[32] = "MERIT-INP";
  proto[33] = "SEP";
  proto[34] = "3PC";
  proto[35] = "IDPR";
  proto[36] = "XTP";
  proto[37] = "DDP";
  proto[38] = "IDPR-CMTP";
  proto[39] = "TP++";
  proto[40] = "IL";
  proto[41] = "IPV6";
  proto[42] = "SDRP";
  proto[43] = "IPV6-ROUTE";
  proto[44] = "IPV6-FRAG";
  proto[45] = "IDRP";
  proto[46] = "RSVP";
  proto[47] = "GRE";
  proto[48] = "MHRP";
  proto[49] = "BNA";
  proto[50] = "ESP";
  proto[51] = "AH";
  proto[52] = "I-NLSP";
  proto[53] = "SWIPE";
  proto[54] = "NARP";
  proto[55] = "MOBILE";
  proto[56] = "TLSP";
  proto[57] = "SKIP";
  proto[58] = "IPV6-ICMP";
  proto[59] = "IPV6-NONXT";
  proto[60] = "IPV6-OPTS";
  proto[61] = "HOST"; //
  proto[62] = "CFTP";
  proto[63] = "NET"; //
  proto[64] = "SAT-EXPAK";
  proto[65] = "KRYPTOLAN";
  proto[66] = "RVD";
  proto[67] = "IPPC";
  proto[68] = "FS"; //
  proto[69] = "SAT-MON";
  proto[70] = "VISA";
  proto[71] = "IPCV";
  proto[72] = "CPNX";
  proto[73] = "CPHB";
  proto[74] = "WSN";
  proto[75] = "PVP";
  proto[76] = "BR-SAT-MON";
  proto[77] = "SUN-ND";
  proto[78] = "WB-MON";
  proto[79] = "WB-EXPAK";
  proto[80] = "ISO-IP";
  proto[81] = "VMTP";
  proto[82] = "SECURE-VMTP";
  proto[83] = "VINES";
  proto[84] = "TTP";
  proto[85] = "NSFNET-IGP";
  proto[86] = "DGP";
  proto[87] = "TCF";
  proto[88] = "EIGRP";
  proto[89] = "OSPFIGP";
  proto[90] = "SPRITE-RPC";
  proto[91] = "LARP";
  proto[92] = "MTP";
  proto[93] = "AX.25";
  proto[94] = "IPIP";
  proto[95] = "MICP";
  proto[96] = "SCC-SP";
  proto[97] = "ETHERIP";
  proto[98] = "ENCAP";
  proto[99] = "APES"; //
  proto[100] = "GMTP";
  proto[101] = "IFMP";
  proto[102] = "PNNI";
  proto[103] = "PIM";
  proto[104] = "ARIS";
  proto[105] = "SCPS";
  proto[106] = "QNX";
  proto[107] = "A/N";
  proto[108] = "IPCOMP";
  proto[109] = "SNP";
  proto[110] = "COMPAQ-PEER";
  proto[111] = "IPX-IN-IP";
  proto[112] = "VRRP";
  proto[113] = "PGM";
  proto[114] = "0HOP"; //
  proto[115] = "L2TP";
  proto[116] = "DDX";
  proto[117] = "IATP";
  proto[118] = "STP";
  proto[119] = "SRP";
  proto[120] = "UTI";
  proto[121] = "SMP";
  proto[122] = "SM";
  proto[123] = "PTP";
  proto[124] = "ISIS";
  proto[125] = "FIRE";
  proto[126] = "CRTP";
  proto[127] = "CRUDP";
  proto[128] = "SSCOPMCE";
  proto[129] = "IPLT";
  proto[130] = "SPS";
  proto[131] = "PIPE";
  proto[132] = "SCTP";

  if (proto.count(prot) == 0)
    return std::string("PROTO_") + to_string(prot);
  else
    return proto[prot];  
}

//////////////////////////////////////////////////////////////////////
std::string qtype_to_str(u16 qtype) {
  std::map<u16, string> all;
  all[1] = "A";
  all[2] = "CS";
  all[5] = "CNAME";
  all[6] = "SOA";
  all[12] = "PTR";
  all[15] = "MX";
  all[16] = "TXT";
  all[17] = "RP";
  all[18] = "AFSDB";
  all[24] = "SIG";
  all[25] = "KEY";
  all[28] = "AAAA";
  all[29] = "SOC";
  all[33] = "SRV";
  all[35] = "NAPTR";
  all[37] = "CERT";
  all[39] = "DNAME";
  all[42] = "APL";
  all[43] = "DS";
  all[45] = "IPSECKEY";
  all[44] = "SSHFP";
  all[47] = "NSEC";
  all[48] = "DNSKEY";
  all[46] = "RRSIG";
  all[49] = "DHCID";
  all[50] = "NSEC3";
  all[51] = "NSEC3PARAM";
  all[55] = "HIP";
  all[99] = "SPF";
  all[249] = "TKEY";
  all[250] = "TSIG";
  all[32768] = "TA";
  all[32769] = "DLV";

  if (all.count(qtype))
    return all[qtype];
  else
    return "QTYPE_" + to_string(qtype);
}

