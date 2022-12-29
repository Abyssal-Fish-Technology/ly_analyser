// #include <stdio.h>
// #include <stdlib.h>
#include <extract_pcap.h>

#include <Cgicc.h>
#include <google/protobuf/text_format.h>
#include <iomanip>

#include "boost/regex.hpp"
#include "../../common/common.h"
#include "../../common/datetime.h"
#include "../../common/log.h"
#include "../../common/sha256.h"
#include "../../common/strings.h"
#include "../../common/evidence_req.h"
#include "../../common/strings.h"
#include "../../common/ip.h"
#include "../data/dbctx.h"
#include "../define.h"
#include "../config/cached_config.h"


#include "pcap.h"

#define PCAP_FILE_PATH "/data/cap/"

using namespace std;
using namespace boost;
using namespace evidence;

static string err_str = "abnormal character";
static EvidenceReq req;
static EvidenceResponse rsp;
static bool is_http = false;
static bool first = true;

char *macnum_to_macstr(u_int8_t MACData[]){
  char *macstr = (char*)malloc(18);
  sprintf(macstr, "%02X-%02X-%02X-%02X-%02X-%02X", MACData[0], MACData[1], MACData[2], MACData[3], MACData[4], MACData[5]);
  return macstr;
}

string BinToHex(const string &strBin, bool bIsUpper = false)
{   
    string strHex;
    strHex.resize(strBin.size() * 2);
    for (size_t i = 0; i < strBin.size(); i++) {   
        uint8_t cTemp = strBin[i];
        for (size_t j = 0; j < 2; j++) {   
            uint8_t cCur = (cTemp & 0x0f);
            if (cCur < 10) {   
                cCur += '0';
            } else {   
                cCur += ((bIsUpper ? 'A' : 'a') - 10);
            }
            strHex[2 * i + 1 - j] = cCur;
            cTemp >>= 4;
        }
    }
    
    return strHex;
}

static void inline output_u64(stringstream& out, const string& name, u64 value)
{
  out << '"' << name << "\":" << value;
}

static void inline output_double(stringstream& out, const string& name, double value)
{
  out << '"' << name << "\":" << fixed << setprecision(2) << value;
}

static void inline output_string(stringstream& out, const string& name, const string& value)
{
  out << '"' << name << "\":\"" << value << '"';
}

static void inline output_hex(stringstream& out, const string& name, const string& value)
{
  out << '"' << name << "\":\"" << hex << value << '"';
}

static string inline transform_ascii(const string value)
{
  stringstream ascii;

  u_int32_t i;
  for( i = 0; i < value.length(); i++){
    if ((value[i]) >= 0x20 && (value[i]) <= 0x7E){
      if ((value[i]) == 0x22 || (value[i]) == 0x5c){
        ascii << '\\';
      }
      ascii << value[i];
    } else {
      ascii << '.';
    }
  }

  return ascii.str();
}

////////////////////////////////////////////////////////////////////////////
u_int32_t decodePacket(struct pcap_pkthdr *h, const u_char *p, pcap_t *handler, EvidenceRecord *rec) {
  struct ether_header ehdr;
  u_int caplen = h->caplen, length = h->len, offset;

  u_short eth_type;
  // u_short off=0, numPkts = 1;
  // u_int8_t flags = 0;
  u_int8_t proto = 0;
  // u_int32_t tunnel_id = 0;
  struct ip ip;
  struct ip6_hdr ipv6;
  struct ip6_ext ipv6ext;
  struct tcphdr tp;
  struct udphdr up;
  struct icmp_hdr icmpPkt;
  u_int16_t payload_shift = 0;
  int payloadLen = 0; /* Do not set it to unsigned */
  // char fingerprint[FINGERPRINT_LEN+1];
  IpAddress src, dst;
  // u_char isFragment = 0;
  u_int ehshift = 0;


  // readWriteGlobals->now = h->ts.tv_sec;

  if(caplen >= sizeof(struct ether_header)) {

    u_int plen, hlen=0;
    u_short sport, dport, tcp_len;
    // u_short numMplsLabels = 0;
    // u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN];
    u_int32_t null_type;
    struct ppp_header ppphdr;

    // traceEvent(TRACE_INFO, "Datalink: %d", datalink);

    u_int32_t datalink = pcap_datalink(handler);
    // std::cout << "datalink: " << hex << datalink << endl;

    switch(datalink) {
      case DLT_ANY: /* Linux 'any' device */
        eth_type = DLT_ANY;
        memset(&ehdr, 0, sizeof(struct ether_header));
        break;
      case DLT_RAW: /* Raw packet data */
        if(((p[0] & 0xF0) >> 4) == 4)
          eth_type = ETHERTYPE_IP;
        else
          eth_type = ETHERTYPE_IPV6;
        ehshift = 0;
        break;
      case DLT_NULL: /* loopaback interface */
        ehshift = 4;
        memcpy(&null_type, p, sizeof(u_int32_t));
        //null_type = ntohl(null_type);
        /* All this crap is due to the old little/big endian story... */
        /* FIX !!!! */
        switch(null_type) {
        case BSD_AF_INET:
          eth_type = ETHERTYPE_IP;
          break;
        case BSD_AF_INET6_BSD:
        case BSD_AF_INET6_FREEBSD:
        case BSD_AF_INET6_DARWIN:
          eth_type = ETHERTYPE_IPV6;
          break;
        default:
          return 1; /* Any other non IP protocol */
        }
        memset(&ehdr, 0, sizeof(struct ether_header));
        break;
      case DLT_PPP:
        memcpy(&ppphdr, p, sizeof(struct ppp_header));
        if(ntohs(ppphdr.proto) == 0x0021 /* IP */)
          eth_type = ETHERTYPE_IP, ehshift = sizeof(struct ppp_header);
        else
          return 2;
        break;
      default:
      ehshift = sizeof(struct ether_header);
      memcpy(&ehdr, p, ehshift);
      eth_type = ntohs(ehdr.ether_type);
      break;
    }

    // std::cout << "eth_type: " << hex << eth_type << endl;

    if((eth_type == ETHERTYPE_IP) || (eth_type == ETHERTYPE_IPV6) || (eth_type == ETHERTYPE_VLAN) /* Courtesy of Mikael Cam <mca@mgn.net> - 2002/08/28 */ || (eth_type == ETHERTYPE_MPLS) || (eth_type == ETHERTYPE_PPPoE) || (eth_type == DLT_NULL) || (eth_type == DLT_ANY) || (eth_type == 16385 /* MacOSX loopback */) || (eth_type == 16390 /* MacOSX loopback */)) {
      // u_short vlanId = 0;
      u_int estimatedLen=0;

      if((eth_type == ETHERTYPE_IP) || (eth_type == ETHERTYPE_IPV6)) {
        if((ehshift == 0) && (datalink != DLT_RAW)) /* still not set (used to handle the DLT_NULL case) */
          ehshift = sizeof(struct ether_header);
      } else if(eth_type == ETHERTYPE_VLAN) {
        Ether80211q qType;

        while(eth_type == ETHERTYPE_VLAN) {
          memcpy(&qType, p+ehshift, sizeof(Ether80211q));
          // vlanId = ntohs(qType.vlanId) & 0xFFF;
          eth_type = ntohs(qType.protoType);
          ehshift += sizeof(qType);
          /* printf("VlanId: %d\n", vlanId); <<<== NOT USED YET */
        }
      // } else if(eth_type == ETHERTYPE_MPLS) {
      //   char bos; /* bottom_of_stack */

      //   memset(mplsLabels, 0, sizeof(mplsLabels));
      //   bos = 0;
      //   while(bos == 0) {
      //     memcpy(&mplsLabels[numMplsLabels], p+ehshift, MPLS_LABEL_LEN);

      //     bos = (mplsLabels[numMplsLabels][2] & 0x1), ehshift += 4, numMplsLabels++;
      //     if((ehshift > caplen) || (numMplsLabels >= MAX_NUM_MPLS_LABELS))
      //       return 3; /* bad packet */
      //   }
      //   eth_type = ETHERTYPE_IP;
      // } else if(eth_type == ETHERTYPE_PPPoE) {
      //   eth_type = ETHERTYPE_IP, ehshift += 8;
      // } else if(eth_type == DLT_ANY) {
      //   ehshift += sizeof(AnyHeader);
      //   eth_type = ntohs(((AnyHeader*)p)->protoType);
      // } else {
      //   ehshift += NULL_HDRLEN;
      }

    // parse_ip:
      if(eth_type == ETHERTYPE_IP) {
        u_short ip_len;

        memcpy(&ip, p+ehshift, sizeof(struct ip));
        if(ip.ip_v != 4) return 4; /* IP v4 only */

        /* blacklist check */
        // if(isBlacklistedAddress(&ip.ip_src) || isBlacklistedAddress(&ip.ip_dst)) return 5;

        ip_len = ((u_short)ip.ip_hl * 4);
        estimatedLen = ehshift+htons(ip.ip_len);
        hlen = ip_len;
        payloadLen = htons(ip.ip_len)-ip_len;

        src.ipVersion = 4, dst.ipVersion = 4;
        // if(readOnlyGlobals.ignoreIP || (readOnlyGlobals.setAllNonLocalHostsToZero && (!isLocalAddress(&ip.ip_src))))
        //   src.ipType.ipv4 = 0; /* 0.0.0.0 */
        // else
          src.ipType.ipv4 = ntohl(ip.ip_src.s_addr);

        // if(readOnlyGlobals.ignoreIP || (readOnlyGlobals.setAllNonLocalHostsToZero && (!isLocalAddress(&ip.ip_dst))))
        //   dst.ipType.ipv4 = 0; /* 0.0.0.0 */
        // else
          dst.ipType.ipv4 = ntohl(ip.ip_dst.s_addr);

        proto = ip.ip_p;
        // isFragment = (ntohs(ip.ip_off) & 0x3fff) ? 1 : 0;

        // off = ntohs(ip.ip_off);

      } else if(eth_type == ETHERTYPE_IPV6) {
        memcpy(&ipv6, p+ehshift, sizeof(struct ip6_hdr));
        if(((ipv6.ip6_vfc >> 4) & 0x0f) != 6) return 6; /* IP v6 only */
        estimatedLen = sizeof(struct ip6_hdr)+ehshift+htons(ipv6.ip6_plen);
        hlen = sizeof(struct ip6_hdr);

        src.ipVersion = 6, dst.ipVersion = 6;
        payloadLen = ntohs(ipv6.ip6_plen)-hlen;

        /* FIX: blacklist check for IPv6 */

        /* FIX: isLocalAddress doesn't work with IPv6 */
        // if(readOnlyGlobals.ignoreIP)
        //   memset(&src.ipType.ipv6, 0, sizeof(struct in6_addr));
        // else
          memcpy(&src.ipType.ipv6, &ipv6.ip6_src, sizeof(struct in6_addr));

        // if(readOnlyGlobals.ignoreIP)
        //   memset(&dst.ipType.ipv6, 0, sizeof(struct in6_addr));
        // else
          memcpy(&dst.ipType.ipv6, &ipv6.ip6_dst, sizeof(struct in6_addr));

        proto = ipv6.ip6_nxt; /* next header (protocol) */

        if(proto == 0) {
          /* IPv6 hop-by-hop option */

          memcpy(&ipv6ext, p+ehshift+sizeof(struct ip6_hdr),
                 sizeof(struct ip6_ext));

          hlen += (ipv6ext.ip6e_len+1)*8;
          proto = ipv6ext.ip6e_nxt;
        }
      } else
        return 7; /* Anything else that's not IPv4/v6 */

      plen = length-ehshift;
      if(caplen > estimatedLen) caplen = estimatedLen;
      payloadLen -= (estimatedLen-caplen);

      sport = dport = 0; /* default */
      offset = ehshift+hlen;

      switch(proto) {
      case IPPROTO_TCP:
        if(plen < (hlen+sizeof(struct tcphdr))) return 8; /* packet too short */
        memcpy(&tp, p+offset, sizeof(struct tcphdr));
        // if(!readOnlyGlobals.ignorePorts) 
          sport = ntohs(tp.th_sport);
        // if(!readOnlyGlobals.ignorePorts) 
          dport = ntohs(tp.th_dport);
    
        // flags = tp.th_flags;


        tcp_len = (tp.th_off * 4);
        payloadLen -= tcp_len;
        if(payloadLen > 0)
          payload_shift = offset+tcp_len;
        else {
          payloadLen    = 0;
          payload_shift = 0;
        }

        break;
      case IPPROTO_UDP:
        if(plen < (hlen+sizeof(struct udphdr))) return 9; /* packet too short */
        memcpy(&up, p+offset, sizeof(struct udphdr));
        // if(!readOnlyGlobals.ignorePorts) 
          sport = ntohs(up.uh_sport);
        // if(!readOnlyGlobals.ignorePorts) 
          dport = ntohs(up.uh_dport);

        payloadLen = ntohs(up.uh_ulen)-sizeof(struct udphdr);
        if(payloadLen > 0) {
          if(payloadLen > LONG_SNAPLEN) return 10; /* packet too large */
          payload_shift = offset+sizeof(struct udphdr);
        } else {
          payloadLen    = 0;
          payload_shift = 0;
        }

        // if((readOnlyGlobals.tunnel_mode) && (payloadLen > sizeof(struct gtp_header))) {
        //   if((sport == GTP_DATA_PORT) && (dport == GTP_DATA_PORT)) {
        //     struct gtp_header *gtp = (struct gtp_header*)&p[payload_shift];
        //     u_int gtp_header_len = sizeof(struct gtp_header);

        //     if(((gtp->flags & 0xF0) == 0x30) /* GTPv1 */ && (ntohs(gtp->total_length) >= (payloadLen-gtp_header_len))) {
        //       tunnel_id = ntohl(gtp->tunnel_id);
        //       payload_shift += gtp_header_len;
        //       ehshift = payload_shift;
        //       eth_type = ETHERTYPE_IP;
        //       goto parse_ip;
        //     }
        //   }
        // }

        break;
      case IPPROTO_ICMP:
        if(plen < (hlen+sizeof(struct icmp_hdr))) return 11; /* packet too short */
        memcpy(&icmpPkt, p+offset, sizeof(struct icmp_hdr));
        payloadLen = caplen - offset- sizeof(struct icmp_hdr);
        //traceEvent(TRACE_ERROR, "[icmp_type=%d][icmp_code=%d]", icmpPkt.icmp_type, icmpPkt.icmp_code);
        // if(!(readOnlyGlobals.ignorePorts || readOnlyGlobals.ignorePorts)) {
        //   if(readOnlyGlobals.usePortsForICMP)
        //     sport = 0, dport = (icmpPkt.icmp_type * 256) + icmpPkt.icmp_code;
        // }
        if(payloadLen > 0)
          payload_shift = offset+sizeof(struct icmp_hdr);
        else {
          payloadLen    = 0;
          payload_shift = 0;
        }
        break;
      default:
        payloadLen = 0;
      }

      // proto, isFragment,
      // numPkts,
      // ip.ip_tos,
      // vlanId, tunnel_id, &ehdr, src, sport, dst, dport,
      // readOnlyGlobals.accountL2Traffic ? h->len : plen, flags,
      // (proto == IPPROTO_ICMP) ? icmpPkt.icmp_type : 0,
      // (proto == IPPROTO_ICMP) ? icmpPkt.icmp_code : 0,
      // &icmpPkt,
      // numMplsLabels, mplsLabels,
      // input_index, output_index,
      // readOnlyGlobals.computeFingerprint ? fingerprint : NULL,
      // (struct pcap_pkthdr*)h, (u_char*)p,
      // payload_shift, payloadLen


      rec->set_time_sec(h->ts.tv_sec);
      rec->set_time_usec(h->ts.tv_usec);
      rec->set_caplen(h->caplen);
      rec->set_pktlen(h->len);

      rec->set_smac(macnum_to_macstr(ehdr.ether_shost));// u_int_8[] to const char *
      rec->set_dmac(macnum_to_macstr(ehdr.ether_dhost));

      if (src.ipVersion == 4 && dst.ipVersion) {
        rec->set_sip(ipnum_to_ipstr(src.ipType.ipv4));
        rec->set_dip(ipnum_to_ipstr(dst.ipType.ipv4));
      } else if (src.ipVersion == 6) {
        rec->set_sip(ipnum_to_ipstr_v6(src.ipType.ipv6));
        rec->set_dip(ipnum_to_ipstr_v6(dst.ipType.ipv6));        
      }

      rec->set_protocol(proto);

      rec->set_sport(sport);
      rec->set_dport(dport);

      u_char *payload_char = (u_char *)malloc(payloadLen);
      memcpy(payload_char, (p+payload_shift), payloadLen);

      // string payload_string((char *)payload_char, payloadLen);
      int i;
      string payload_string = "";
      for (i = 0; i < payloadLen; i++)
        payload_string += payload_char[i];

      string payload_ascii = transform_ascii(payload_string);

      rec->set_payload(payload_ascii);

      free(payload_char);
    } else {
      log_err("Unknown ethernet type: %X", eth_type);
      //printf("Unknown ethernet type: 0x%X (%d)", eth_type, eth_type);
      return 12;
    }
  }
  return 0;
}

////////////////////////////////////////////////////////////////////////////
static inline void OutputRecord(const EvidenceRecord& rec, stringstream& output){
  output_u64(output, "devid", req.devid());
  if (rec.has_time_sec()) {
    output << ",";
    output_u64(output, "time_sec",  rec.time_sec());
  }
  if (rec.has_time_usec()) {
    output << ",";
    output_u64(output, "time_usec",  rec.time_usec());
  }
  if (rec.has_ip()) {
    output << ",";
    // output_string(output, "ip", ipnum_to_ipstr(rec.ip()));
    output_string(output, "ip", rec.ip());
  }
  if (rec.has_port()) {
    output << ",";
    output_u64(output, "port",  rec.port());
  }
  if (rec.has_caplen()) {
    output << ",";
    output_u64(output, "caplen",  rec.caplen());
  }
  if (rec.has_pktlen()) {
    output << ",";
    output_u64(output, "pktlen",  rec.pktlen());
  }
  if (rec.has_smac()) {
    output << ",";
    // output_string(output, "smac", mac_to_str(rec.smac()));
    output_string(output, "smac", rec.smac());
  }
  if (rec.has_dmac()) {
    output << ",";
    // output_string(output, "dmac", mac_to_str(rec.dmac()));
    output_string(output, "dmac", rec.dmac());
  }
  if (rec.has_sip()) {
    output << ",";
    // output_string(output, "sip", ipnum_to_ipstr(rec.sip()));
    output_string(output, "sip", rec.sip());
  }
  if (rec.has_sport()) {
    output << ",";
    output_u64(output, "sport",  rec.sport());
  }
  if (rec.has_dip()) {
    output << ",";
    // output_string(output, "dip", ipnum_to_ipstr(rec.dip()));
    output_string(output, "dip", rec.dip());
  }
  if (rec.has_dport()) {
    output << ",";
    output_u64(output, "dport",  rec.dport());
  }
  if (rec.has_protocol()) {
    output << ",";
    output_string(output, "protocol",  proto_to_string(rec.protocol()));
  }

  if (rec.has_payload()) {
    output << ",";
    output_string(output, "payload",  rec.payload());
  }


  if (rec.has_pkthdr()) {
    output << ",";
    output_hex(output, "pkthdr",  rec.pkthdr());
    // output_string(output, "pkthdr",  rec.pkthdr());
  }

  if (rec.has_packet()) {
    output << ",";
    output_hex(output, "packet",  rec.packet());
    // output_string(output, "packet",  rec.packet());
  }
}


static void OutputResult(EvidenceResponse& res) {
  stringstream sout;
  sout << "[" << endl;
  for (int i = 0;i < res.records_size();i++) {
    auto rec = res.records(i);
    if (first)
      first = false;
    else
      sout << ",\n";
    sout << "{";
    OutputRecord(rec, sout);
    sout << "}";
  }
  sout << "]" << endl;
  std::cout<<sout.str();
}

static void process_res() {
  std::ostringstream out;
  if (is_http) {
    if (!rsp.SerializeToOstream(&out)) {
      log_err("failed to serialize to string");
    }
    std::cout << out.str();
  } else {
    OutputResult(rsp);
  }
}

////////////////////////////////////////////////////////////////////////////
static void process() {
  if (is_http) std::cout << "Content-Type: application/protobuf; charset=UTF-8\r\n\r\n";

  char ebuf[PCAP_ERRBUF_SIZE];
  string pcap_file;

  u_int time_sec = req.time_sec();
  time_t file_time = (time_t)time_sec-time_sec%300;
  struct tm *file_time_tm = localtime(&file_time);
  char file_time_str[15];
  strftime(file_time_str, 15, "%Y%m%d%H%M", file_time_tm);
  string tmp = file_time_str;
  pcap_file = PCAP_FILE_PATH + to_string(req.devid()) + "/" + tmp + ".pcap";
  // std::cout << "pcap_file: " << pcap_file << endl;

  pcap_t *handler = pcap_open_offline(pcap_file.c_str(), ebuf);
  if (handler==NULL){
    log_err("open pcap file error: %s", ebuf);
    process_res();
    return;
  }

  const u_char *_packet;
  u_char packet[LONG_SNAPLEN];
  struct pcap_pkthdr *_h;
  u_char *h = (u_char *)malloc(4 * sizeof(u_int32_t));
  EvidenceRecord *rec;
  rec = rsp.add_records();

  while (pcap_next_ex(handler, &_h, &_packet) >= 0){
    if (_h->ts.tv_sec == req.time_sec() && _h->ts.tv_usec == req.time_usec()){
      // 比较IP/Port，进行确认

      u_char *h_ptr = h;
      /* 时间已经改为使用64位统计，旧版pcap文件仍使用32位 */
      u_int32_t h_sec    = (u_int32_t)_h->ts.tv_sec;
      u_int32_t h_usec   = (u_int32_t)_h->ts.tv_usec;
      u_int32_t h_caplen   = (u_int32_t)_h->caplen;
      u_int32_t h_len      = (u_int32_t)_h->len;
      memcpy(h_ptr, &h_sec, sizeof(u_int32_t));      h_ptr += sizeof(u_int32_t);
      memcpy(h_ptr, &h_usec, sizeof(u_int32_t));     h_ptr += sizeof(u_int32_t);
      memcpy(h_ptr, &h_caplen, sizeof(u_int32_t));   h_ptr += sizeof(u_int32_t);
      memcpy(h_ptr, &h_len, sizeof(u_int32_t)); 

      memcpy(packet, _packet, _h->caplen);

      u_int32_t ret = decodePacket(_h, packet, handler, rec);
      if (ret > 0) log_err("decodePacket return: %d ret");

      u_int32_t i;

      string rec_header = "";
      for (i = 0; i < 16; i++)
        rec_header += h[i];

      rec->set_pkthdr(BinToHex(rec_header));
      // rec->set_pkthdr((rec_header));


      string rec_packet = "";
      for (i = 0; i < h_caplen; i++)
        rec_packet += packet[i];

      rec->set_packet(BinToHex(rec_packet));
      // rec->set_packet((rec_packet));

      break;
    }
  }
  pcap_close(handler);
  free(h);

  process_res();
}


////////////////////////////////////////////////////////////////////////////
static void download() {
  if (is_http)
    std::cout << "Content-Type: application/octet-stream;\r\n\r\n";

  // EvidenceRecord *rec;
  // rec = rsp.add_records();

  char ebuf[PCAP_ERRBUF_SIZE];
  string pcap_file;

  u_int time_sec = req.time_sec();
  time_t file_time = (time_t)time_sec-time_sec%300;
  struct tm *file_time_tm = localtime(&file_time);
  char file_time_str[15];
  strftime(file_time_str, 15, "%Y%m%d%H%M", file_time_tm);
  string tmp = file_time_str;
  pcap_file = PCAP_FILE_PATH + to_string(req.devid()) + "/" + tmp + ".pcap";
  // std::cout << "pcap_file: " << pcap_file << endl;

  pcap_t *handler = pcap_open_offline(pcap_file.c_str(), ebuf);
  if (handler==NULL){
    log_err("open pcap file error: %s", ebuf);
    return;
  }

  const u_char *_packet;
  struct pcap_pkthdr *_h;

  while (pcap_next_ex(handler, &_h, &_packet) >= 0){
    if (_h->ts.tv_sec == req.time_sec() && _h->ts.tv_usec == req.time_usec()){

      pcap_dumper_t *t = pcap_dump_open(handler, "-");
      pcap_dump((u_char *)t, _h, _packet);
      pcap_dump_close(t);

      break;
    }
  }
  pcap_close(handler);


  // std::ostringstream out;
  // if (is_http) { 
  //   if (!rsp.SerializeToOstream(&out)) {
  //     log_err("failed to serialize to string");
  //   }
  //   std::cout << out.str();
  // } else {
  //   OutputResult(rsp);
  // }
}


int main(int argc, char *argv[])
{
  // setvbuf(stdout, NULL, _IOFBF, 81920);
  is_http = getenv("REMOTE_ADDR") != NULL;
  if (is_http) {
    bool parsed = false;
    cgicc::Cgicc cgi;
    if (!cgi("dbg").empty()) setenv("DEBUG", "true", 1);
    const cgicc::CgiEnvironment &cgienv = cgi.getEnvironment();

    const std::string& method = cgienv.getRequestMethod();
    if (method == "PUT" || method == "POST") {
      parsed = google::protobuf::TextFormat::ParseFromString(cgienv.getPostData(), &req);
    } else if (method == "GET") {
      parsed = ParseEvidenceReqFromUrlParams(cgi, &req);
    }
    if (!parsed) {
      std::cout << "HTTP/1.1 400 Invalid Params\r\n\r\n";
      return 0;
    }
  } else if (!ParseEvidenceReqFromCmdline(argc, argv, &req)){
    log_err("ParseEvidenceReqFromCmdline error\n");
    return 0;
  }

  try {
    if (DEBUG) log_info("evidence_req: %s\n", req.DebugString().c_str());
    if (req.has_download() && req.download()==true ) {
      download();
    } else {
      process();
    }
  } catch (std::exception const &e) {
    log_err(__FILE__":%s\n", e.what());
  }
  return 0;
}
