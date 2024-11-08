
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
        NameConflict = -5,
    } Status;
    static String toString(const Status status) {
        switch (status) {
            case TryLater: return "TryLater";
            case Success: return "Success";
            case Failure: return "Failure";
            case InvalidArgument: return "InvalidArgument";
            case OutOfMemory: return "OutOfMemory";
            case ServerError: return "ServerError";
            case PacketBad: return "PacketBad";
            case NameConflict: return "NameConflict";
            default: return "Unknown";
        }
    }

    typedef enum {
        ServiceTCP,
        ServiceUDP
    } ServiceProtocol;
    static String toString(const ServiceProtocol serviceProtocol) {
        if (serviceProtocol == ServiceTCP) return "TCP";
        else if (serviceProtocol == ServiceUDP) return "UDP";
        else return "Unknown";
    }

    using ServiceTextRecords = std::vector<String>;
    typedef struct {
        uint16_t port;
        ServiceProtocol proto;
        String name;
        String serv;
        ServiceTextRecords textRecords;
    } ServiceRecord;

private:
    UDP* _udp;
    IPAddress _addr;
    String _name, _fqhn, _arpa;
    bool _active;

    Status _messageRecv(void);
    Status _messageSend(const uint16_t xid, const int type, const ServiceRecord* serviceRecord = nullptr);

    unsigned long _announceLast;
    Status _announce(void);
    Status _conflicted(void);

    std::vector<ServiceRecord> _serviceRecords;
    void _writeNSECRecord(const ServiceRecord* serviceRecord, const uint32_t ttl, const bool cacheFlush) const;
    void _writeCompleteRecord(const uint32_t ttl, const bool cacheFlush = true, const bool anyType = false) const;
    void _writeReverseRecord(const uint32_t ttl) const;
    void _writeAddressRecord(const uint32_t ttl, const bool cacheFlush = true, const bool anyTime = false) const;
    void _writeServiceRecord(const ServiceRecord* serviceRecord, const uint32_t ttl, const bool cacheFlush, const bool includeAdditional = false) const;
    size_t _sizeofServiceRecord(const ServiceRecord* record, const bool includeAdditional = false) const;
    void _writeDNSName(const String& name) const;
    size_t _sizeofDNSName(const String& name) const;
    void _writeNameLengthAndContent(const String& name) const;
    void _writeAddressLengthAndContent(const IPAddress& address) const;
    void _writeLength(const uint16_t length) const;
    void _writeBits(const uint8_t byte1, const uint8_t byte2, const uint8_t byte3, const uint8_t byte4, const uint32_t ttl) const;

public:
    explicit MDNS(UDP& udp);
    virtual ~MDNS();

    Status begin(void);
    Status start(const IPAddress& ip, const String& name = String(), const bool checkForConflicts = false);
    Status process(void);
    Status stop(void);

    inline Status serviceRecordInsert(const ServiceRecord& record) {
        return serviceRecordInsert(record.proto, record.port, record.name, record.textRecords);
    }
    inline Status serviceRecordRemove(const ServiceRecord& record) {
        return serviceRecordRemove(record.proto, record.port, record.name);
    }
    Status serviceRecordInsert(const ServiceProtocol proto, const uint16_t port, const String& name, const ServiceTextRecords& textRecords = ServiceTextRecords());
    Status serviceRecordRemove(const ServiceProtocol proto, const uint16_t port, const String& name);
    Status serviceRecordClear(void);
};

#endif    // __MDNS_H__
