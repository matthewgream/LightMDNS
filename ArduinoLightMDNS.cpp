
// mgream 18/10/2024
//  - fixed buffer overrun bugs
//  - fixed case comparison for names
//  - removed query functionality, is incoming only not for lookup
//  - move malloc/frees to String
//  - tidy up uint8_t/char types
//  - remove useless code, e.g. ptr
//  - remove the recieve buffer to save memory and read from udp by parts
//  - harmonise return codes asnd function signatures and remove useless functions
//  - make TXT records compliant to RFC and support multiple TXT records (vector)
//  - fix some other bugs in there ... still some nasty code
//  - test w/ avahi
//  - fix to update ipaddress
//  - added debug messages while solving problems
//  - lifecycle support: begin -> (start -> process -> stop)
//  - changed service record storage from static to dynamic vector
//  - iterate in packet recv while packets still available

//  Copyright (C) 2010 Georg Kaindl
//  http://gkaindl.com
//
//  This file is part of Arduino EthernetBonjour.
//
//  EthernetBonjour is free software: you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public License
//  as published by the Free Software Foundation, either version 3 of
//  the License, or (at your option) any later version.
//
//  EthernetBonjour is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with EthernetBonjour. If not, see
//  <http://www.gnu.org/licenses/>.
//

#include <string.h>
#include <stdlib.h>
#include <Udp.h>

#include "ArduinoLightMDNS.hpp"

//#define MDNS_DEBUG
#ifdef MDNS_DEBUG
#define DEBUG_PRINTF Serial.printf
#else
#define DEBUG_PRINTF(...) \
  do { \
  } while (0)
#endif

//

#define MDNS_TLD ".local"
#define MDNS_SD_SERVICE "_services._dns-sd._udp.local"
#define MDNS_SD_SERVICE_LENGTH (sizeof(MDNS_SD_SERVICE) - 1)
#define MDNS_SERVER_PORT 5353
#define MDNS_RESPONSE_TTL 120
#define MDNS_XID_DEFAULT 0

static const IPAddress mdnsMulticastIPAddr(224, 0, 0, 251);

typedef enum {
  MDNSPacketTypeMyIPAnswer,
  MDNSPacketTypeNoIPv6AddrAvailable,
  MDNSPacketTypeServiceRecord,
  MDNSPacketTypeServiceRecordRelease,
} MDNSPacketType_t;

typedef struct {
  uint16_t xid;
  uint8_t recursionDesired : 1;
  uint8_t truncated : 1;
  uint8_t authoritiveAnswer : 1;
  uint8_t opCode : 4;
  uint8_t queryResponse : 1;
  uint8_t responseCode : 4;
  uint8_t checkingDisabled : 1;
  uint8_t authenticatedData : 1;
  uint8_t zReserved : 1;
  uint8_t recursionAvailable : 1;
  uint16_t queryCount;
  uint16_t answerCount;
  uint16_t authorityCount;
  uint16_t additionalCount;
} __attribute__((__packed__)) MDNSHeader_t;

//

MDNS::MDNS(UDP& udp)
  : _udp(&udp), _active(false), _announceLast(0) {
}
MDNS::~MDNS() {
  removeAllServiceRecords();  // ???
  stop();
}

//

// return values:
// 1 on success
// 0 otherwise
MDNSStatus_t MDNS::begin(void) {
  if (!(sizeof(MDNSHeader_t) > 10))
    return MDNSOutOfMemory;
  DEBUG_PRINTF("MDNS: begin\n");
  return MDNSSuccess;
}
MDNSStatus_t MDNS::start(const IPAddress& ip, const String& name) {
  _ipAddress = ip;
  this->_name = name + MDNS_TLD;
  MDNSStatus_t status = MDNSSuccess;
  if (!this->_active) {
    if (!this->_udp->beginMulticast(mdnsMulticastIPAddr, MDNS_SERVER_PORT))
      status = MDNSFailure;
    else this->_active = true;
  }
  if (status != MDNSSuccess)
    DEBUG_PRINTF("MDNS: start: failed _udp->beginMulticast error=%d, not active\n", status);
  else
    DEBUG_PRINTF("MDNS: start: active ip=%s, name=%s\n", IPAddress(_ipAddress).toString().c_str(), this->_name.c_str());
  return status;
}
MDNSStatus_t MDNS::process(void) {
  MDNSStatus_t status = MDNSSuccess;
  if (this->_active) {
#ifdef MDNS_DEBUG
    int count = 0;
#endif
    do {
      DEBUG_PRINTF("MDNS: process [%d]\n", count ++);
    } while ((status = _recvMDNSMessage()) == MDNSSuccess);
    if (status != MDNSSuccess && status != MDNSTryLater)
      DEBUG_PRINTF("MDNS: process: failed _recvMDNSMessage error=%d\n", status);
    else if (status == MDNSSuccess || status == MDNSTryLater)
      if ((status = _announceMDNS()) != MDNSSuccess)
        DEBUG_PRINTF("MDNS: process: failed _announceMDNS error=%d\n", status);
  }
  return status;
}
MDNSStatus_t MDNS::stop(void) {
  if (this->_active) {
    DEBUG_PRINTF("MDNS: stop\n");
    this->_udp->stop();
    this->_active = false;
  }
  return MDNSSuccess;
}

//

// return value:
// A DNSError_t (DNSSuccess on success, something else otherwise)
// in "int" mode: positive on success, negative on error
MDNSStatus_t MDNS::_sendMDNSMessage(uint16_t xid, int type, const MDNSServiceRecord_t* serviceRecord) {
  MDNSHeader_t dnsHeader{};
  dnsHeader.xid = htons(xid);
  dnsHeader.opCode = 0;  // Query
  switch (type) {
    case MDNSPacketTypeServiceRecordRelease:
    case MDNSPacketTypeMyIPAnswer:
      dnsHeader.answerCount = htons(1);
      break;
    case MDNSPacketTypeServiceRecord:
      dnsHeader.answerCount = htons(4);
      dnsHeader.additionalCount = htons(1);
      break;
    case MDNSPacketTypeNoIPv6AddrAvailable:
      dnsHeader.queryCount = htons(1);
      dnsHeader.additionalCount = htons(1);
      dnsHeader.responseCode = 0x03;
      break;
  }
  dnsHeader.authoritiveAnswer = 1;
  dnsHeader.queryResponse = 1;
  this->_udp->beginPacket(mdnsMulticastIPAddr, MDNS_SERVER_PORT);
  this->_udp->write((uint8_t*)&dnsHeader, sizeof(MDNSHeader_t));

  uint8_t* buf = (uint8_t*)&dnsHeader;
  const int bufSize = sizeof(MDNSHeader_t);

  // construct the answer section
  switch (type) {
    case MDNSPacketTypeMyIPAnswer:
      {
        DEBUG_PRINTF("MDNS: packet: sending IP, ip=%s, name=%s\n", IPAddress(_ipAddress).toString().c_str(), this->_name.c_str());
        this->_writeMyIPAnswerRecord(buf, bufSize);
        break;
      }
    case MDNSPacketTypeServiceRecord:
      {
        assert(serviceRecord != nullptr);
        DEBUG_PRINTF("MDNS: packet: sending SRV announce %d/%u/%s/%s/[%d]\n", serviceRecord->proto, serviceRecord->port, serviceRecord->name.c_str(), serviceRecord->servName.c_str(), serviceRecord->textRecords.size());

        // (1) SRV record
        this->_writeServiceRecordName(buf, bufSize, serviceRecord, false);
        buf[0] = 0x00;
        buf[1] = 0x21;  // SRV record
        buf[2] = 0x80;  // cache flush
        buf[3] = 0x01;  // class IN
        // ttl
        *((uint32_t*)&buf[4]) = htonl(MDNS_RESPONSE_TTL);
        // data length
        *((uint16_t*)&buf[8]) = htons(8 + this->_name.length());
        this->_udp->write(buf, 10);
        // priority and weight
        buf[0] = buf[1] = buf[2] = buf[3] = 0;
        // port
        *((uint16_t*)&buf[4]) = htons(serviceRecord->port);
        this->_udp->write(buf, 6);
        // target
        this->_writeDNSName(buf, bufSize, this->_name.c_str(), true);

        // (2) TXT record
        this->_writeServiceRecordName(buf, bufSize, serviceRecord, false);
        buf[0] = 0x00;
        buf[1] = 0x10;  // TXT record
        buf[2] = 0x80;  // cache flush
        buf[3] = 0x01;  // class IN
        // ttl
        *((uint32_t*)&buf[4]) = htonl(MDNS_RESPONSE_TTL);
        this->_udp->write(buf, 8);
        // data length && text
        if (serviceRecord->textRecords.size() == 0) {
          buf[0] = 0x00;
          buf[1] = 0x01;
          buf[2] = 0x00;
          this->_udp->write(buf, 3);
        } else {  // https://www.ietf.org/rfc/rfc6763.txt
#define __MY_MIN(a, b) ((a) < (b) ? (a) : (b))
          int length = 0;
          for (const auto& textRecord : serviceRecord->textRecords)
            length += __MY_MIN(textRecord.length(), 255) + 1;
          *((uint16_t*)&buf[0]) = htons(length);
          this->_udp->write(buf, 2);
          for (const auto& textRecord : serviceRecord->textRecords) {
            const int size = __MY_MIN(textRecord.length(), 255);
            buf[0] = (uint8_t)size;
            this->_udp->write(buf, 1);
            this->_udp->write((uint8_t*)textRecord.c_str(), size);
          }
        }

        // (3) PTR record (for the DNS-SD service in general)
        this->_writeDNSName(buf, bufSize, MDNS_SD_SERVICE, true);
        buf[0] = 0x00;
        buf[1] = 0x0c;  // PTR record
        buf[2] = 0x00;  // no cache flush
        buf[3] = 0x01;  // class IN
        // ttl
        *((uint32_t*)&buf[4]) = htonl(MDNS_RESPONSE_TTL);
        // data length.
        *((uint16_t*)&buf[8]) = htons(serviceRecord->servName.length() + 2);
        this->_udp->write(buf, 10);
        this->_writeServiceRecordName(buf, bufSize, serviceRecord, true);

        // (4) PTR record (our service)
        this->_writeServiceRecordPTR(buf, bufSize, serviceRecord, MDNS_RESPONSE_TTL);

        // (x) our IP address as additional record
        this->_writeMyIPAnswerRecord(buf, bufSize);

        break;
      }
    case MDNSPacketTypeServiceRecordRelease:
      {
        assert(serviceRecord != nullptr);
        DEBUG_PRINTF("MDNS: packet: sending SRV release %d/%u/%s/%s/[%d]\n", serviceRecord->proto, serviceRecord->port, serviceRecord->name.c_str(), serviceRecord->servName.c_str(), serviceRecord->textRecords.size());

        // just send our service PTR with a TTL of zero
        this->_writeServiceRecordPTR(buf, bufSize, serviceRecord, 0);
        break;
      }
    case MDNSPacketTypeNoIPv6AddrAvailable:
      {
        DEBUG_PRINTF("MDNS: packet: sending NO AAAA\n");

        this->_writeDNSName(buf, bufSize, this->_name.c_str(), true);
        buf[0] = 0x00;
        buf[1] = 0x1c;  // AAAA record
        buf[2] = 0x00;  // no cache flush
        buf[3] = 0x01;  // class IN
        this->_udp->write(buf, 4);

        // send our IPv4 address record as additional record, in case the peer wants it.
        this->_writeMyIPAnswerRecord(buf, bufSize);

        break;
      }
  }
  this->_udp->endPacket();
  return MDNSSuccess;
}

//

MDNSStatus_t MDNS::_recvMDNSMessage() {

  const uint16_t udp_len = this->_udp->parsePacket();
  if (udp_len == 0)
    return MDNSTryLater;

  DEBUG_PRINTF("MDNS: packet: receiving, size=%u\n", udp_len);

  MDNSHeader_t dnsHeader;
  uint8_t* buf = (uint8_t*)&dnsHeader;
  int offset = 0;

  for (int z = 0; z < sizeof(MDNSHeader_t); z++) {
    if (offset >= udp_len) goto bad_packet;
    const int r = this->_udp->read();
    if (r < 0) goto bad_packet;
    offset++;
    buf[z] = (uint8_t)r;
  }

  if (0 == dnsHeader.queryResponse && 0 == dnsHeader.opCode && MDNS_SERVER_PORT == this->_udp->remotePort()) {

    const uint16_t xid = ntohs(dnsHeader.xid);
    const uint16_t q = ntohs(dnsHeader.queryCount);

    const int recordsLength = this->_serviceRecords.size() + 2;
    struct _matcher_t {
      const char* name;
      int length, match, position;
    } recordsMatcherTop[recordsLength];
    bool recordsAskedFor[recordsLength];

    for (int j = 0; j < recordsLength; j++) {
      if (j == 0) recordsMatcherTop[j].name = this->_name.c_str(), recordsMatcherTop[0].length = this->_name.length();                                               // first entry is our own MDNS name, the rest are our services
      else if (j == 1) recordsMatcherTop[j].name = MDNS_SD_SERVICE, recordsMatcherTop[1].length = MDNS_SD_SERVICE_LENGTH;                                            // second entry is our own the general DNS-SD service
      else recordsMatcherTop[j].name = this->_serviceRecords[j - 2].servName.c_str(), recordsMatcherTop[j].length = this->_serviceRecords[j - 2].servName.length();  // the rest
      recordsMatcherTop[j].match = 1;
      recordsMatcherTop[j].position = 0;
      recordsAskedFor[j] = false;
    }
    bool ipv6AddrAskedFor = false;

    DEBUG_PRINTF("MDNS: packet: processing, xid=%u, queries=%u\n", xid, q);

    const auto __matchStringPart = [](const char** pCmpStr, int* pCmpLen, const uint8_t* buf, const int dataLen) -> int {
      const auto _memcmp_caseinsensitive = [](const char* a, const unsigned char* b, const int l) -> int {
        for (int i = 0; i < l; i++) {
          if (tolower(a[i]) < tolower(b[i])) return -1;
          else if (tolower(a[i]) > tolower(b[i])) return 1;
        }
        return 0;
      };
      const int matches = (*pCmpLen >= dataLen) ? 1 & (_memcmp_caseinsensitive(*pCmpStr, buf, dataLen) == 0) : 0;
      *pCmpStr += dataLen;
      *pCmpLen -= dataLen;
      if ('.' == **pCmpStr)
        (*pCmpStr)++, (*pCmpLen)--;
      return matches;
    };

    // read over the query section
    for (int i = 0; i < (int)q; i++) {
      DEBUG_PRINTF("MDNS: packet: processing, query[%d/%u]: ", i, q);

      struct _matcher_t recordsMatcher[recordsLength];
      memcpy((void*)recordsMatcher, (void*)recordsMatcherTop, sizeof(recordsMatcherTop));

      int tLen = 0, rLen = 0;
      do {

        if (offset >= udp_len) break;
        rLen = this->_udp->read();
        if (rLen < 0) break;
        offset++;

        tLen += 1;
        if (rLen > 128) {  // handle DNS name compression, kinda, sorta

          if (offset >= udp_len) goto bad_packet;
          const int xLen = this->_udp->read();
          if (xLen < 0) goto bad_packet;
          offset++;
          DEBUG_PRINTF("(%d)", xLen);

          for (int j = 0; j < recordsLength; j++)
            if (recordsMatcher[j].position && recordsMatcher[j].position != xLen)
              recordsMatcher[j].match = 0;
          tLen += 1;
        } else if (rLen > 0) {
          int tr = rLen;
          while (tr > 0) {
            const int ir = (tr > (int)sizeof(MDNSHeader_t)) ? sizeof(MDNSHeader_t) : tr;

            for (int z = 0; z < ir; z++) {
              if (offset >= udp_len) goto bad_packet;
              const int r = this->_udp->read();
              if (r < 0) goto bad_packet;
              offset++;
              buf[z] = (uint8_t)r;
            }
            DEBUG_PRINTF("[%.*s]", ir, buf);

            tr -= ir;
            for (int j = 0; j < recordsLength; j++)
              if (!recordsAskedFor[j] && recordsMatcher[j].match)
                recordsMatcher[j].match &= __matchStringPart(&recordsMatcher[j].name, &recordsMatcher[j].length, buf, ir);
          }
          tLen += rLen;
        }
      } while (rLen > 0 && rLen <= 128);

      // if this matched a name of ours (and there are no characters left), then
      // check whether this is an A record query (for our own name) or a PTR record query
      // (for one of our services).
      // if so, we'll note to send a record
      int next_bytes = 0;
      for (int z = 0; z < 4; z++) {
        if (offset >= udp_len) break;
        const int r = this->_udp->read();
        if (r < 0) break;
        offset++;
        buf[z] = (uint8_t)r;
        next_bytes++;
      }
      for (int j = 0; j < recordsLength; j++) {
        if (!recordsAskedFor[j] && recordsMatcher[j].match && 0 == recordsMatcher[j].length) {
          if (0 == recordsMatcher[j].position)
            recordsMatcher[j].position = offset - 4 - tLen;
          if (next_bytes == 4) {
            if (buf[0] == 0 && (buf[2] == 0x00 || buf[2] == 0x80) && buf[3] == 0x01) {
              if ((0 == j && 0x01 == buf[1]) || (0 < j && (0x0c == buf[1] || 0x10 == buf[1] || 0x21 == buf[1])))
                recordsAskedFor[j] = true;
              else if (0 == j && 0x1c == buf[1])
                ipv6AddrAskedFor = true;
            }
          }
        }
      }
      DEBUG_PRINTF("\n");
    }

    // now, handle the requests
    for (int j = 0; j < recordsLength; j++) {
      if (recordsAskedFor[1] || recordsAskedFor[j]) {
        if (j == 0) this->_sendMDNSMessage(xid, MDNSPacketTypeMyIPAnswer);
        else if (j > 1)
          this->_sendMDNSMessage(xid, MDNSPacketTypeServiceRecord, &this->_serviceRecords[j - 2]);
      }
    }
    // if we were asked for our IPv6 address, say that we don't have any
    if (ipv6AddrAskedFor)
      this->_sendMDNSMessage(xid, MDNSPacketTypeNoIPv6AddrAvailable);
  }

  this->_udp->flush();
  return MDNSSuccess;

bad_packet:
  this->_udp->flush();
  return MDNSPacketBad;
}

MDNSStatus_t MDNS::_announceMDNS() {
  // now, should we re-announce our services again?
  const uint32_t now = millis(), out = (((uint32_t)MDNS_RESPONSE_TTL / 2) + ((uint32_t)MDNS_RESPONSE_TTL / 4)) * 1000UL;
  if ((now - this->_announceLast) > out) {
    DEBUG_PRINTF("MDNS: announce: services\n");
    for (const auto& record : this->_serviceRecords)
      this->_sendMDNSMessage(MDNS_XID_DEFAULT, MDNSPacketTypeServiceRecord, &record);
    this->_announceLast = now;
  }
  return MDNSSuccess;
}

//

MDNSStatus_t MDNS::addServiceRecord(const MDNSServiceProtocol_t proto, const uint16_t port, const String& name, const MDNSServiceTextRecords_t& textRecords) {
#ifdef MDNS_DEBUG
  const auto __joinStrings = [](const std::vector<String>& strings) -> String {
    String joined = "";
    for (const auto& string : strings) {
      if (!joined.isEmpty()) joined += ",";
      joined += string;
    }
    return joined;
  };
#endif
  const auto __findFirstDotFromRight = [](const char* str) -> const char* {
    const char* p = str + strlen(str);
    while (p > str && '.' != *p--)
      ;
    return &p[2];
  };
  DEBUG_PRINTF("MDNS: addServiceRecord: proto=%d, port=%u, name=%s, textRecords.size=%d,text=[%s]\n", proto, port, name.c_str(), textRecords.size(), __joinStrings(textRecords).c_str());
  if (name.isEmpty() || port == 0 || (proto != MDNSServiceTCP && proto != MDNSServiceUDP))
    return MDNSInvalidArgument;
  try {
    auto& record = this->_serviceRecords.emplace_back(MDNSServiceRecord_t{
      .port = port,
      .proto = proto,
      .name = name,
      .servName = String(__findFirstDotFromRight(name.c_str())) + String(this->_postfixForProtocol(proto)),
      .textRecords = textRecords });
    if (this->_active)
      this->_sendMDNSMessage(MDNS_XID_DEFAULT, MDNSPacketTypeServiceRecord, &record);
    return MDNSSuccess;
  } catch (const std::bad_alloc&) {
    return MDNSOutOfMemory;
  }
}
MDNSStatus_t MDNS::removeServiceRecord(const MDNSServiceProtocol_t proto, const uint16_t port, const String& name) {
  DEBUG_PRINTF("MDNS: removeServiceRecord: proto=%d, port=%u, name=%s\n", proto, port, name.c_str());
  std::erase_if(this->_serviceRecords, [&](const MDNSServiceRecord_t& record) {
    if (!(record.port == port && record.proto == proto && (name.isEmpty() || record.name == name)))
      return false;
    if (this->_active)
      this->_sendMDNSMessage(MDNS_XID_DEFAULT, MDNSPacketTypeServiceRecordRelease, &record);
    return true;
  });
  return MDNSSuccess;
}
MDNSStatus_t MDNS::removeAllServiceRecords() {
  DEBUG_PRINTF("MDNS: removeAllServiceRecords\n");
  std::erase_if(this->_serviceRecords, [&](const MDNSServiceRecord_t& record) {
    if (this->_active)
      this->_sendMDNSMessage(MDNS_XID_DEFAULT, MDNSPacketTypeServiceRecordRelease, &record);
    return true;
  });
  return MDNSSuccess;
}

//

void MDNS::_writeDNSName(uint8_t* buf, int bufSize, const char* name, bool zeroTerminate) {
  uint8_t* p1 = (uint8_t*)name;
  while (*p1) {
    int c = 1;
    uint8_t* p2 = p1;
    while (0 != *p2 && '.' != *p2) {
      p2++;
      c++;
    };
    uint8_t* p3 = buf;
    int i = c, l = bufSize - 1;
    *p3++ = (uint8_t)--i;
    while (i-- > 0) {
      *p3++ = *p1++;
      if (--l <= 0) {
        this->_udp->write(buf, bufSize);
        l = bufSize;
        p3 = buf;
      }
    }
    while ('.' == *p1)
      ++p1;
    if (l != bufSize) {
      this->_udp->write(buf, bufSize - l);
    }
  }
  if (zeroTerminate) {
    buf[0] = 0;
    this->_udp->write(buf, 1);
  }
}
void MDNS::_writeMyIPAnswerRecord(uint8_t* buf, int bufSize) {
  this->_writeDNSName(buf, bufSize, this->_name.c_str(), true);
  buf[0] = 0x00;
  buf[1] = 0x01;
  buf[2] = 0x80;  // cache flush: true
  buf[3] = 0x01;
  this->_udp->write(buf, 4);
  *((uint32_t*)&buf[0]) = htonl(MDNS_RESPONSE_TTL);
  *((uint16_t*)&buf[4]) = htons(4);  // data length
  uint8_t myIp[4] = { _ipAddress[0], _ipAddress[1], _ipAddress[2], _ipAddress[3] };
  memcpy(&buf[6], &myIp, 4);  // our IP address
  this->_udp->write(buf, 10);
}
void MDNS::_writeServiceRecordPTR(uint8_t* buf, int bufSize, const MDNSServiceRecord_t* serviceRecord, uint32_t ttl) {
  this->_writeServiceRecordName(buf, bufSize, serviceRecord, true);
  buf[0] = 0x00;
  buf[1] = 0x0c;  // PTR record
  buf[2] = 0x00;  // no cache flush
  buf[3] = 0x01;  // class IN
  // ttl
  *((uint32_t*)&buf[4]) = htonl(ttl);
  // data length (+13 = "._tcp.local" or "._udp.local" + 1  byte zero termination)
  *((uint16_t*)&buf[8]) = htons(serviceRecord->name.length() + 13);
  this->_udp->write(buf, 10);
  this->_writeServiceRecordName(buf, bufSize, serviceRecord, false);
}
void MDNS::_writeServiceRecordName(uint8_t* buf, int bufSize, const MDNSServiceRecord_t* serviceRecord, bool tld) {
  this->_writeDNSName(buf, bufSize, tld ? serviceRecord->servName.c_str() : serviceRecord->name.c_str(), tld);
  if (!tld) {
    const char* srv_type = this->_postfixForProtocol(serviceRecord->proto);
    if (srv_type[0] != '\0')
      this->_writeDNSName(buf, bufSize, &srv_type[1], true);  // eat the dot at the beginning
  }
}
const char* MDNS::_postfixForProtocol(const MDNSServiceProtocol_t proto) {
  switch (proto) {
    case MDNSServiceTCP:
      return "._tcp" MDNS_TLD;
    case MDNSServiceUDP:
      return "._udp" MDNS_TLD;
    default:
      return "";
  }
};

//
