
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

    using TextRecords = std::vector<String>;
    typedef struct {
        uint16_t port;
        ServiceProtocol proto;
        String name, serv, fqsn;
        TextRecords text;
        uint16_t _cachedTextLength;
    } Service;
    using Services = std::vector<Service>;

private:
    UDP* _udp;
    IPAddress _addr;
    String _name, _fqhn, _arpa;
    bool _enabled;

    Status _messageRecv(void);
    Status _messageSend(const uint16_t xid, const int type, const Service* service = nullptr);

    unsigned long _announced;
    Status _announce(void);
    Status _conflicted(void);

    Services _services;
    void _writeAddressRecord(const uint32_t ttl, const bool cacheFlush = true, const bool anyTime = false) const;
    void _writeReverseRecord(const uint32_t ttl) const;
    void _writeServiceRecord(const Service& service, const uint32_t ttl, const bool cacheFlush, const bool includeAdditional = false) const;
    void _writeCompleteRecord(const uint32_t ttl, const bool cacheFlush = true, const bool anyType = false) const;
    void _writeNextSecureRecord(const String& name, const std::initializer_list<uint8_t>& types, const uint32_t ttl, const bool cacheFlush, const bool includeAdditional = false) const;

public:
    explicit MDNS(UDP& udp);
    virtual ~MDNS();

    Status begin(void);
    Status start(const IPAddress& addr, const String& name = String(), const bool checkForConflicts = false);
    Status process(void);
    Status stop(void);

    inline Status serviceRecordInsert(const Service& service) {
        return serviceRecordInsert(service.proto, service.port, service.name, service.text);
    }
    inline Status serviceRecordRemove(const Service& service) {
        return serviceRecordRemove(service.proto, service.port, service.name);
    }
    Status serviceRecordInsert(const ServiceProtocol proto, const uint16_t port, const String& name, const TextRecords& textRecords = TextRecords());
    Status serviceRecordRemove(const ServiceProtocol proto, const uint16_t port, const String& name);
    Status serviceRecordClear(void);
};

#endif    // __MDNS_H__
