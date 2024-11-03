
// mgream 18/10/2024
//		- see body

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

#if !defined(__MDNS_H__)
#define __MDNS_H__ 1

#include <Arduino.h>
#include <vector>

typedef enum {
  MDNSTryLater = 2,
  MDNSSuccess = 1,
  MDNSFailure = 0,
  MDNSInvalidArgument = -1,
  MDNSOutOfMemory = -2,
  MDNSServerError = -3,
  MDNSPacketBad = -4,
} MDNSStatus_t;

typedef enum {
  MDNSServiceTCP,
  MDNSServiceUDP
} MDNSServiceProtocol_t;

class MDNS {
private:
  UDP* _udp;
  IPAddress _ipAddress;
  String _name;
  bool _active;

  using MDNSServiceTextRecords_t = std::vector<String>;
  typedef struct {
    uint16_t port;
    MDNSServiceProtocol_t proto;
    String name;
    String servName;
    MDNSServiceTextRecords_t textRecords;
  } MDNSServiceRecord_t;
  std::vector<MDNSServiceRecord_t> _serviceRecords;

  MDNSStatus_t _sendMDNSMessage(const uint16_t xid, const int type, const MDNSServiceRecord_t* serviceRecord = nullptr);
  MDNSStatus_t _recvMDNSMessage(void);
  unsigned long _announceLast;
  MDNSStatus_t _announceMDNS(void);

  void _writeServiceRecordName(uint8_t* buf, const int bufSize, const MDNSServiceRecord_t* serviceRecord, const bool tld);
  void _writeServiceRecordPTR(uint8_t* buf, const int bufSize, const MDNSServiceRecord_t* serviceRecord, const uint32_t ttl);
  void _writeDNSName(uint8_t* buf, int bufSize, const char* name, const bool zeroTerminate);
  void _writeMyIPAnswerRecord(uint8_t* buf, const int bufSize);
  const char* _postfixForProtocol(const MDNSServiceProtocol_t proto);

public:
  typedef struct {
    uint16_t port;
    MDNSServiceProtocol_t proto;
    String name;
    MDNSServiceTextRecords_t textRecords;
  } MDNSServiceRecordExt_t;

  explicit MDNS(UDP& udp);
  ~MDNS();

  MDNSStatus_t begin(void);
  MDNSStatus_t start(const IPAddress& ip, const String& name);
  MDNSStatus_t process(void);
  MDNSStatus_t stop(void);

  MDNSStatus_t addServiceRecord(const MDNSServiceRecordExt_t &record) {
    return addServiceRecord (record.proto, record.port, record.name, record.textRecords);
  }
  MDNSStatus_t removeServiceRecord(const MDNSServiceRecordExt_t &record) {
    return removeServiceRecord (record.proto, record.port, record.name);
  }
  MDNSStatus_t addServiceRecord(const MDNSServiceProtocol_t proto, const uint16_t port, const String& name, const MDNSServiceTextRecords_t& textRecords = MDNSServiceTextRecords_t());
  MDNSStatus_t removeServiceRecord(const MDNSServiceProtocol_t proto, const uint16_t port, const String& name);
  MDNSStatus_t removeAllServiceRecords(void);
};

#endif  // __MDNS_H__
