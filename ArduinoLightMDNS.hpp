
//  mgream 2024
//  - significantly refactored

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

class MDNS {

public:

    typedef enum {
        TryLater = 2,
        Success = 1,
        Failure = 0,
        InvalidArgument = -1,
        OutOfMemory = -2,
        ServerError = -3,
        PacketBad = -4,
    } Status;

    typedef enum {
        ServiceTCP,
        ServiceUDP
    } ServiceProtocol;

    using ServiceTextRecords = std::vector<String>;
    typedef struct {
        uint16_t port;
        ServiceProtocol proto;
        String name;
        String servName;
        ServiceTextRecords textRecords;
    } ServiceRecord;

private:
    UDP* _udp;
    IPAddress _ipAddress;
    String _name;
    bool _active;

    Status _messageSend(const uint16_t xid, const int type, const ServiceRecord* serviceRecord = nullptr);
    Status _messageRecv(void);

    unsigned long _announceLast;
    Status _announce(void);

    std::vector<ServiceRecord> _serviceRecords;
    void _writeServiceRecordName(uint8_t* buf, const int bufSize, const ServiceRecord* serviceRecord, const bool tld) const;
    void _writeServiceRecordPTR(uint8_t* buf, const int bufSize, const ServiceRecord* serviceRecord, const uint32_t ttl) const;
    void _writeDNSName(uint8_t* buf, int bufSize, const char* name, const bool zeroTerminate) const;
    void _writeMyIPAnswerRecord(uint8_t* buf, const int bufSize) const;
    const char* _postfixForProtocol(const ServiceProtocol proto) const;

public:
    explicit MDNS(UDP& udp);
    virtual ~MDNS();

    Status begin(void);
    Status start(const IPAddress& ip, const String& name);
    Status process(void);
    Status stop(void);

    inline Status addServiceRecord(const ServiceRecord& record) {
        return addServiceRecord(record.proto, record.port, record.name, record.textRecords);
    }
    inline Status removeServiceRecord(const ServiceRecord& record) {
        return removeServiceRecord(record.proto, record.port, record.name);
    }
    Status addServiceRecord(const ServiceProtocol proto, const uint16_t port, const String& name, const ServiceTextRecords& textRecords = ServiceTextRecords());
    Status removeServiceRecord(const ServiceProtocol proto, const uint16_t port, const String& name);
    Status removeAllServiceRecords(void);
};

#endif    // __MDNS_H__
