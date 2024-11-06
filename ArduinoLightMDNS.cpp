
//  mgream 2024

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

#define DEBUG_MDNS
#ifdef DEBUG_MDNS
#define DEBUG_PRINTF Serial.printf
#else
#define DEBUG_PRINTF(...) \
    do { \
    } while (0)
#endif

//

#define TLD ".local"
#define SERVICE_SD "_services._dns-sd._udp.local"
#define SERVER_PORT 5353
#define TTL_RESPONSE 120
#define XID_DEFAULT 0

static const IPAddress ADDRESS_MULTICAST(224, 0, 0, 251);

typedef enum {
    PacketTypeMyIPAnswer,
    PacketTypeNoIPv6AddrAvailable,
    PacketTypeServiceRecord,
    PacketTypeServiceRecordRelease,
} PacketType;

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
} __attribute__((__packed__)) Header;

//

String parseDNSType(uint8_t typeByte1, uint8_t typeByte2) {
    uint16_t type = (typeByte1 << 8) | typeByte2;
    switch (type) {
        case 0x0001: return "A";
        case 0x0002: return "NS";
        case 0x0005: return "CNAME";
        case 0x0006: return "SOA";
        case 0x000C: return "PTR";
        case 0x000F: return "MX";
        case 0x0010: return "TXT";
        case 0x0021: return "SRV";
        case 0x001C: return "AAAA";
        case 0x00FB: return "DNSKEY";
        case 0x00FC: return "RRSIG";
        case 0x00FF: return "ANY";
        default: return "Unknown(" + String(type, HEX) + ")";
    }
}
String parseDNSFlags(uint8_t flagsByte) {
    String result = "";
    if (flagsByte & 0x80) result += "CACHE_FLUSH";
    return result.length() ? result : "NONE";
}
String parseDNSClass(uint8_t classByte) {
    switch (classByte & 0x7F) {    // Mask out cache flush bit
        case 0x01: return "IN";
        case 0x02: return "CS";
        case 0x03: return "CH";
        case 0x04: return "HS";
        case 0xFF: return "ANY";
        default: return "Unknown(" + String(classByte, HEX) + ")";
    }
}

#include <numeric>

String join (const std::vector<String>& elements, const String& delimiter) {
    return std::accumulate(std::next(elements.begin()), elements.end(), elements[0], [&delimiter](const String& a, const String& b) { return a + delimiter + b; });
}

String parseHeader(const Header& h) {
    static const char* opcodes[] = {
        "QUERY", "IQUERY", "STATUS", "RESERVED", "NOTIFY",
        "UPDATE", "UNK6", "UNK7", "UNK8", "UNK9",
        "UNK10", "UNK11", "UNK12", "UNK13", "UNK14", "UNK15"
    };
    static const char* rcodes[] = {
        "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN",
        "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET",
        "NXRRSET", "NOTAUTH", "NOTZONE", "UNK11",
        "UNK12", "UNK13", "UNK14", "UNK15"
    };
    return join({ "ID=0x" + String(h.xid, HEX),
                  "QR=" + String(h.queryResponse),
                  "OPCODE=" + String(opcodes[h.opCode]),
                  "AA=" + String(h.authoritiveAnswer),
                  "TC=" + String(h.truncated),
                  "RD=" + String(h.recursionDesired),
                  "RA=" + String(h.recursionAvailable),
                  "Z=" + String(h.zReserved),
                  "AD=" + String(h.authenticatedData),
                  "CD=" + String(h.checkingDisabled),
                  "RCODE=" + String(rcodes[h.responseCode]),
                  "QDCOUNT=" + String(h.queryCount),
                  "ANCOUNT=" + String(h.answerCount),
                  "NSCOUNT=" + String(h.authorityCount),
                  "ARCOUNT=" + String(h.additionalCount) },
                ",");
}

//

MDNS::MDNS(UDP& udp)
    : _udp(&udp), _active(false), _announceLast(0) {
}
MDNS::~MDNS() {
    removeAllServiceRecords();    // ???
    stop();
}

//

MDNS::Status MDNS::begin(void) {
    assert(sizeof(Header) > 10);    // due to use of Header as a buffer
    DEBUG_PRINTF("MDNS: begin\n");
    return Success;
}
MDNS::Status MDNS::start(const IPAddress& ip, const String& name) {
    _ipAddress = ip;
    _name = name + TLD;
    auto status = Success;
    if (!_active) {
        if (!_udp->beginMulticast(ADDRESS_MULTICAST, SERVER_PORT))
            status = Failure;
        else _active = true;
    }
    if (status != Success)
        DEBUG_PRINTF("MDNS: start: failed _udp->beginMulticast error=%s, not active\n", toString(status).c_str());
    else
        DEBUG_PRINTF("MDNS: start: active ip=%s, name=%s\n", IPAddress(_ipAddress).toString().c_str(), _name.c_str());
    return status;
}
MDNS::Status MDNS::process(void) {
    auto status = Success;
    if (_active) {
#ifdef DEBUG_MDNS
        auto count = 0;
#endif
        do {
            DEBUG_PRINTF("MDNS: process [%d]\n", count++);
        } while ((status = _messageRecv()) == Success);
        if (status != Success && status != TryLater)
            DEBUG_PRINTF("MDNS: process: failed _messageRecv error=%s\n", toString(status).c_str());
        else if (status == Success || status == TryLater)
            if ((status = _announce()) != Success)
                DEBUG_PRINTF("MDNS: process: failed _announce error=%s\n", toString(status).c_str());
    }
    return status;
}
MDNS::Status MDNS::stop(void) {
    if (_active) {
        DEBUG_PRINTF("MDNS: stop\n");
        _udp->stop();
        _active = false;
    }
    return Success;
}

//

MDNS::Status MDNS::_messageSend(uint16_t xid, int type, const ServiceRecord* serviceRecord) {

    Header dnsHeader{};
    dnsHeader.xid = htons(xid);
    dnsHeader.opCode = 0;    // Query
    switch (type) {
        case PacketTypeServiceRecordRelease:
        case PacketTypeMyIPAnswer:
            dnsHeader.answerCount = htons(1);
            break;
        case PacketTypeServiceRecord:
            dnsHeader.answerCount = htons(4);
            dnsHeader.additionalCount = htons(1);
            break;
        case PacketTypeNoIPv6AddrAvailable:
            dnsHeader.queryCount = htons(1);
            dnsHeader.additionalCount = htons(1);
            dnsHeader.responseCode = 0x03;
            break;
    }
    dnsHeader.authoritiveAnswer = 1;
    dnsHeader.queryResponse = 1;

    _udp->beginPacket(ADDRESS_MULTICAST, SERVER_PORT);
    _udp->write((uint8_t*)&dnsHeader, sizeof(Header));

    auto buf = (uint8_t*)&dnsHeader;
    auto bufSize = sizeof(Header);

    // construct the answer section
    switch (type) {
        case PacketTypeMyIPAnswer:
            DEBUG_PRINTF("MDNS: packet: sending IP answer, ip=%s, name=%s\n", IPAddress(_ipAddress).toString().c_str(), _name.c_str());
            _writeMyIPAnswerRecord(buf, bufSize);
            break;

        case PacketTypeServiceRecord:
            assert(serviceRecord != nullptr);
            DEBUG_PRINTF("MDNS: packet: sending SRV record %s/%u/%s/%s/[%d]\n", toString(serviceRecord->proto).c_str(), serviceRecord->port, serviceRecord->name.c_str(), serviceRecord->servName.c_str(), serviceRecord->textRecords.size());

            // (1) SRV record
            _writeServiceRecordName(buf, bufSize, serviceRecord, false);
            buf[0] = 0x00;
            buf[1] = 0x21;    // SRV record
            buf[2] = 0x80;    // cache flush
            buf[3] = 0x01;    // class IN
            // ttl
            *((uint32_t*)&buf[4]) = htonl(TTL_RESPONSE);
            // data length
            *((uint16_t*)&buf[8]) = htons(8 + _name.length());
            _udp->write(buf, 10);
            // priority and weight
            buf[0] = buf[1] = buf[2] = buf[3] = 0;
            // port
            *((uint16_t*)&buf[4]) = htons(serviceRecord->port);
            _udp->write(buf, 6);
            // target
            _writeDNSName(buf, bufSize, _name.c_str(), true);

            // (2) TXT record
            _writeServiceRecordName(buf, bufSize, serviceRecord, false);
            buf[0] = 0x00;
            buf[1] = 0x10;    // TXT record
            buf[2] = 0x80;    // cache flush
            buf[3] = 0x01;    // class IN
            // ttl
            *((uint32_t*)&buf[4]) = htonl(TTL_RESPONSE);
            _udp->write(buf, 8);
            // data length && text
            if (serviceRecord->textRecords.size() == 0) {
                buf[0] = 0x00;
                buf[1] = 0x01;
                buf[2] = 0x00;
                _udp->write(buf, 3);
            } else {    // https://www.ietf.org/rfc/rfc6763.txt
#define __MY_MIN(a, b) ((a) < (b) ? (a) : (b))
                auto length = 0;
                for (const auto& textRecord : serviceRecord->textRecords)
                    length += __MY_MIN(textRecord.length(), 255) + 1;
                *((uint16_t*)&buf[0]) = htons(length);
                _udp->write(buf, 2);
                for (const auto& textRecord : serviceRecord->textRecords) {
                    auto size = __MY_MIN(textRecord.length(), 255);
                    buf[0] = (uint8_t)size;
                    _udp->write(buf, 1);
                    _udp->write((uint8_t*)textRecord.c_str(), size);
                }
            }

            // (3) PTR record (for the DNS-SD service in general)
            _writeDNSName(buf, bufSize, SERVICE_SD, true);
            buf[0] = 0x00;
            buf[1] = 0x0c;    // PTR record
            buf[2] = 0x00;    // no cache flush
            buf[3] = 0x01;    // class IN
            // ttl
            *((uint32_t*)&buf[4]) = htonl(TTL_RESPONSE);
            // data length.
            *((uint16_t*)&buf[8]) = htons(serviceRecord->servName.length() + 2);
            _udp->write(buf, 10);
            _writeServiceRecordName(buf, bufSize, serviceRecord, true);

            // (4) PTR record (our service)
            _writeServiceRecordPTR(buf, bufSize, serviceRecord, TTL_RESPONSE);

            // (x) our IP address as additional record
            _writeMyIPAnswerRecord(buf, bufSize);
            break;

        case PacketTypeServiceRecordRelease:
            assert(serviceRecord != nullptr);
            DEBUG_PRINTF("MDNS: packet: sending SRV release %s/%u/%s/%s/[%d]\n", toString(serviceRecord->proto).c_str(), serviceRecord->port, serviceRecord->name.c_str(), serviceRecord->servName.c_str(), serviceRecord->textRecords.size());

            // just send our service PTR with a TTL of zero
            _writeServiceRecordPTR(buf, bufSize, serviceRecord, 0);
            break;

        case PacketTypeNoIPv6AddrAvailable:
            DEBUG_PRINTF("MDNS: packet: sending NO AAAA\n");

            _writeDNSName(buf, bufSize, _name.c_str(), true);
            buf[0] = 0x00;
            buf[1] = 0x1c;    // AAAA record
            buf[2] = 0x00;    // no cache flush
            buf[3] = 0x01;    // class IN
            _udp->write(buf, 4);

            // send our IPv4 address record as additional record, in case the peer wants it.
            _writeMyIPAnswerRecord(buf, bufSize);
            break;
    }
    _udp->endPacket();
    return Success;
}

//

MDNS::MDNS::Status MDNS::_messageRecv() {

    auto udp_len = _udp->parsePacket();
    if (udp_len == 0)
        return TryLater;

    DEBUG_PRINTF("MDNS: packet: receiving, size=%u\n", udp_len);

    Header dnsHeader;
    auto buf = (uint8_t*)&dnsHeader;
    auto offset = 0;

    for (auto z = 0; z < sizeof(Header); z++) {
        if (offset >= udp_len) goto bad_packet;    // READ
        int r = _udp->read();                      // READ
        if (r < 0) goto bad_packet;                // READ
        offset++;                                  // READ
        //
        buf[z] = (uint8_t)r;
    }

    if (dnsHeader.queryResponse == 0 && dnsHeader.opCode == 0 && _udp->remotePort() == SERVER_PORT) {

        auto xid = ntohs(dnsHeader.xid);
        auto q = ntohs(dnsHeader.queryCount);

        auto recordsLength = _serviceRecords.size() + 2;
        struct _matcher_t {
            const char* name;
            int length, match, position;
        } recordsMatcherTop[recordsLength];
        bool recordsAskedFor[recordsLength];

        for (auto j = 0; j < recordsLength; j++) {
            if (j == 0) recordsMatcherTop[j].name = _name.c_str(), recordsMatcherTop[0].length = _name.length();                                                 // first entry is our own MDNS name, the rest are our services
            else if (j == 1) recordsMatcherTop[j].name = SERVICE_SD, recordsMatcherTop[1].length = sizeof(SERVICE_SD) - 1;                                       // second entry is our own the general DNS-SD service
            else recordsMatcherTop[j].name = _serviceRecords[j - 2].servName.c_str(), recordsMatcherTop[j].length = _serviceRecords[j - 2].servName.length();    // the rest
            recordsMatcherTop[j].match = 1;
            recordsMatcherTop[j].position = 0;
            recordsAskedFor[j] = false;
        }
        auto ipv6AddrAskedFor = false;

        DEBUG_PRINTF("MDNS: packet: processing, %s / %s:%u\n", parseHeader(dnsHeader).c_str(), _udp->remoteIP().toString().c_str(), _udp->remotePort());

        const auto __matchStringPart = [](const char** pCmpStr, int* pCmpLen, const uint8_t* buf, const int dataLen) -> int {
            const auto _memcmp_caseinsensitive = [](const char* a, const unsigned char* b, const int l) -> int {
                for (auto i = 0; i < l; i++) {
                    if (tolower(a[i]) < tolower(b[i])) return -1;
                    if (tolower(a[i]) > tolower(b[i])) return 1;
                }
                return 0;
            };
            auto matches = (*pCmpLen >= dataLen) ? 1 & (_memcmp_caseinsensitive(*pCmpStr, buf, dataLen) == 0) : 0;
            *pCmpStr += dataLen;
            *pCmpLen -= dataLen;
            if ('.' == **pCmpStr)
                (*pCmpStr)++, (*pCmpLen)--;
            return matches;
        };

        // read over the query section
        for (auto i = 0; i < q; i++) {
            DEBUG_PRINTF("MDNS: packet: processing, query[%d/%u]: ", i, q);

            struct _matcher_t recordsMatcher[recordsLength];
            memcpy((void*)recordsMatcher, (void*)recordsMatcherTop, sizeof(recordsMatcherTop));

            auto tLen = 0, rLen = 0;
            do {
                if (offset >= udp_len) break;    // READ
                rLen = _udp->read();             // READ
                if (rLen < 0) break;             // READ
                offset++;                        // READ
                //
                tLen += 1;
                // https://www.ietf.org/rfc/rfc1035.txt
                if ((rLen & 0xC0) == 0xC0) {

                    if (offset >= udp_len) goto bad_packet;    // READ
                    int xLen = _udp->read();                   // READ
                    if (xLen < 0) goto bad_packet;             // READ
                    offset++;                                  // READ
                    //
                    const int offs = (static_cast<uint16_t>(rLen) & ~0xC000 << 8) | static_cast<uint16_t>(xLen);    // in practice, same as xLen
                    DEBUG_PRINTF("(%02X/%02X = %04X)", rLen, xLen, offs);
                    for (auto j = 0; j < recordsLength; j++)
                        if (recordsMatcher[j].position && recordsMatcher[j].position != offs)
                            recordsMatcher[j].match = 0;
                    tLen += 1;
                } else if (rLen > 0) {
                    DEBUG_PRINTF("[");
                    auto tr = rLen;
                    while (tr > 0) {
                        auto ir = (tr > (int)sizeof(Header)) ? sizeof(Header) : tr;

                        for (auto z = 0; z < ir; z++) {
                            if (offset >= udp_len) goto bad_packet;    // READ
                            int r = _udp->read();                      // READ
                            if (r < 0) goto bad_packet;                // READ
                            offset++;                                  // READ
                            //
                            buf[z] = (uint8_t)r;
                        }
                        DEBUG_PRINTF("%.*s", ir, buf);
                        tr -= ir;
                        for (auto j = 0; j < recordsLength; j++)
                            if (!recordsAskedFor[j] && recordsMatcher[j].match)
                                recordsMatcher[j].match &= __matchStringPart(&recordsMatcher[j].name, &recordsMatcher[j].length, buf, ir);
                    }
                    DEBUG_PRINTF("]");
                    tLen += rLen;
                }
            } while (rLen > 0 && rLen <= 128);

            // if this matched a name of ours (and there are no characters left), then
            // check whether this is an A record query (for our own name) or a PTR record query
            // (for one of our services).
            // if so, we'll note to send a record
            auto next_bytes = 0;
            for (auto z = 0; z < 4; z++) {
                if (offset >= udp_len) break;    // READ
                int r = _udp->read();            // READ
                if (r < 0) break;                // READ
                offset++;                        // READ
                //
                buf[z] = (uint8_t)r;
                next_bytes++;
            }
            for (auto j = 0; j < recordsLength; j++) {
                if (!recordsAskedFor[j] && recordsMatcher[j].match && !recordsMatcher[j].length) {
                    if (!recordsMatcher[j].position)
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
            if (next_bytes == 4)
                DEBUG_PRINTF(" <%s/%s/%s>\n", parseDNSType(buf[0], buf[1]).c_str(), parseDNSFlags(buf[2]).c_str(), parseDNSClass(buf[3]).c_str());
        }

        // now, handle the requests
        for (auto j = 0; j < recordsLength; j++) {
            if (recordsAskedFor[1] || recordsAskedFor[j]) {
                if (j == 0) _messageSend(xid, PacketTypeMyIPAnswer);
                else if (j > 1)
                    _messageSend(xid, PacketTypeServiceRecord, &_serviceRecords[j - 2]);
            }
        }
        // if we were asked for our IPv6 address, say that we don't have any
        if (ipv6AddrAskedFor)
            _messageSend(xid, PacketTypeNoIPv6AddrAvailable);
#ifdef DEBUG_MDNS            
    } else {
       
        struct Group {
            int offset;
            std::vector<String> names;
        };
        std::vector<Group> groups;
        auto uncompressAtOffset = [&](int offs) -> String { // not sure this is correct if > first group
            int cnts = 0;
            for (int i = 0; i < groups.size(); i++) {
                cnts += groups[i].offset;
                for (int j = 0; j < groups[i].names.size(); j++) {
                    if (offs < (cnts + groups[i].names[j].length()))
                        return (offs == cnts) ? groups[i].names[j] : String(groups[i].names[j].c_str()[offs - cnts]);
                    cnts += groups[i].names[j].length();
                }
            }
            return String();
        };

        int goffset = 0;
        DEBUG_PRINTF("MDNS: packet: debugging, %s / %s:%u\n", parseHeader(dnsHeader).c_str(), _udp->remoteIP().toString().c_str(), _udp->remotePort());
        for (int i = 0, q = static_cast<int>(ntohs(dnsHeader.queryCount)); i < q; i++) {
            std::vector<String> names;

            DEBUG_PRINTF("MDNS: packet: debugging (not for us), query[%d/%u]: ", i, q);
            int pCnt = 0, rLen = 0;
            do {
                if (offset >= udp_len) break;    // READ
                rLen = _udp->read();             // READ
                if (rLen < 0) break;             // READ
                offset++;                        // READ
                pCnt++;
                //
                // https://www.ietf.org/rfc/rfc1035.txt
                if ((rLen & 0xC0) == 0xC0) {
                    if (offset >= udp_len) goto bad_packet;    // READ
                    int xLen = _udp->read();                   // READ
                    if (xLen < 0) goto bad_packet;             // READ
                    offset++;                                  // READ
                    pCnt++;
                    //
                    const int offs = (static_cast<uint16_t>(rLen) & ~0xC000 << 8) | static_cast<uint16_t>(xLen);    // in practice, same as xLen
                    names.push_back("(" + uncompressAtOffset(offs) + ")");
                } else if (rLen > 0) {
                    String name;
                    for (auto z = 0; z < rLen; z++) {
                        if (offset >= udp_len) goto bad_packet;    // READ
                        int r = _udp->read();                      // READ
                        if (r < 0) goto bad_packet;                // READ
                        offset++;                                  // READ
                        pCnt++;
                        //
                        name += (char)r;
                    }
                    names.push_back("[" + name + "]");
                }
            } while (rLen > 0 && rLen <= 128);

            uint8_t buf[4];
            for (auto z = 0; z < 4; z++) {
                if (offset >= udp_len) break;    // READ
                int r = _udp->read();            // READ
                if (r < 0) break;                // READ
                offset++;                        // READ
                pCnt++;
                //
                buf[z] = static_cast<uint8_t>(r);
            }
            groups.push_back({ .offset = goffset, .names = names }); goffset += pCnt;
            DEBUG_PRINTF(" %s <%s/%s/%s>\n", join (names, "").c_str (), parseDNSType(buf[0], buf[1]).c_str(), parseDNSFlags(buf[2]).c_str(), parseDNSClass(buf[3]).c_str());
        }
#endif // DEBUG_MDNS        
    }

    _udp->flush();
    return Success;

bad_packet:
    _udp->flush();
    return PacketBad;
}

MDNS::Status MDNS::_announce() {
    // now, should we re-announce our services again?
    auto now = millis(), out = (((uint32_t)TTL_RESPONSE / 2) + ((uint32_t)TTL_RESPONSE / 4)) * 1000UL;
    if ((now - _announceLast) > out) {
        DEBUG_PRINTF("MDNS: announce: services (%d)\n", _serviceRecords.size());
        for (const auto& record : _serviceRecords)
            _messageSend(XID_DEFAULT, PacketTypeServiceRecord, &record);
        _announceLast = now;
    }
    return Success;
}

//

MDNS::Status MDNS::addServiceRecord(const ServiceProtocol proto, const uint16_t port, const String& name, const ServiceTextRecords& textRecords) {
#ifdef DEBUG_MDNS
    const auto __joinStrings = [](const std::vector<String>& strings) -> String {
        String joined;
        for (const auto& string : strings)
            joined += (joined.isEmpty() ? "" : ",") + string;
        return joined;
    };
#endif
    const auto __findFirstDotFromRight = [](const char* str) -> const char* {
        auto p = str + strlen(str);
        while (p > str && *p-- != '.')
            ;
        return &p[2];
    };
    DEBUG_PRINTF("MDNS: addServiceRecord: proto=%s, port=%u, name=%s, textRecords.size=%d,text=[%s]\n", toString(proto).c_str(), port, name.c_str(), textRecords.size(), __joinStrings(textRecords).c_str());
    if (name.isEmpty() || port == 0 || (proto != ServiceTCP && proto != ServiceUDP))
        return InvalidArgument;
    try {
        auto& record = _serviceRecords.emplace_back(ServiceRecord{
            .port = port,
            .proto = proto,
            .name = name,
            .servName = String(__findFirstDotFromRight(name.c_str())) + String(_postfixForProtocol(proto)),
            .textRecords = textRecords });
        if (_active)
            _messageSend(XID_DEFAULT, PacketTypeServiceRecord, &record);
        return Success;
    } catch (const std::bad_alloc&) {
        return OutOfMemory;
    }
}
MDNS::Status MDNS::removeServiceRecord(const ServiceProtocol proto, const uint16_t port, const String& name) {
    DEBUG_PRINTF("MDNS: removeServiceRecord: proto=%s, port=%u, name=%s\n", toString(proto).c_str(), port, name.c_str());
    std::erase_if(_serviceRecords, [&](const ServiceRecord& record) {
        if (!(record.port == port && record.proto == proto && (name.isEmpty() || record.name == name)))
            return false;
        if (_active)
            _messageSend(XID_DEFAULT, PacketTypeServiceRecordRelease, &record);
        return true;
    });
    return Success;
}
MDNS::Status MDNS::removeAllServiceRecords() {
    DEBUG_PRINTF("MDNS: removeAllServiceRecords\n");
    std::erase_if(_serviceRecords, [&](const ServiceRecord& record) {
        if (_active)
            _messageSend(XID_DEFAULT, PacketTypeServiceRecordRelease, &record);
        return true;
    });
    return Success;
}

//

void MDNS::_writeDNSName(uint8_t* buf, int bufSize, const char* name, bool zeroTerminate) const {
    auto p1 = (uint8_t*)name;
    while (*p1) {
        auto c = 1;
        auto p2 = p1;
        while (*p2 && *p2 != '.') {
            p2++;
            c++;
        };
        auto p3 = buf;
        auto i = c, l = bufSize - 1;
        *p3++ = (uint8_t)--i;
        while (i-- > 0) {
            *p3++ = *p1++;
            if (--l <= 0) {
                _udp->write(buf, bufSize);
                l = bufSize;
                p3 = buf;
            }
        }
        while (*p1 == '.')
            ++p1;
        if (l != bufSize)
            _udp->write(buf, bufSize - l);
    }
    if (zeroTerminate) {
        buf[0] = 0;
        _udp->write(buf, 1);
    }
}
void MDNS::_writeMyIPAnswerRecord(uint8_t* buf, int bufSize) const {
    _writeDNSName(buf, bufSize, _name.c_str(), true);
    buf[0] = 0x00;
    buf[1] = 0x01;
    buf[2] = 0x80;    // cache flush: true
    buf[3] = 0x01;
    _udp->write(buf, 4);
    *((uint32_t*)&buf[0]) = htonl(TTL_RESPONSE);
    *((uint16_t*)&buf[4]) = htons(4);    // data length
    buf[6] = _ipAddress[0];
    buf[7] = _ipAddress[1];
    buf[8] = _ipAddress[2];
    buf[9] = _ipAddress[3];
    _udp->write(buf, 10);
}
void MDNS::_writeServiceRecordPTR(uint8_t* buf, int bufSize, const ServiceRecord* serviceRecord, uint32_t ttl) const {
    _writeServiceRecordName(buf, bufSize, serviceRecord, true);
    buf[0] = 0x00;
    buf[1] = 0x0c;    // PTR record
    buf[2] = 0x00;    // no cache flush
    buf[3] = 0x01;    // class IN
    // ttl
    *((uint32_t*)&buf[4]) = htonl(ttl);
    // data length (+13 = "._tcp.local" or "._udp.local" + 1  byte zero termination)
    *((uint16_t*)&buf[8]) = htons(serviceRecord->name.length() + 13);
    _udp->write(buf, 10);
    _writeServiceRecordName(buf, bufSize, serviceRecord, false);
}
void MDNS::_writeServiceRecordName(uint8_t* buf, int bufSize, const ServiceRecord* serviceRecord, bool tld) const {
    _writeDNSName(buf, bufSize, tld ? serviceRecord->servName.c_str() : serviceRecord->name.c_str(), tld);
    if (!tld) {
        auto srv_type = _postfixForProtocol(serviceRecord->proto);
        if (srv_type[0] != '\0')
            _writeDNSName(buf, bufSize, &srv_type[1], true);    // eat the dot at the beginning
    }
}
const char* MDNS::_postfixForProtocol(const ServiceProtocol proto) const {
    switch (proto) {
        case ServiceTCP:
            return "._tcp" TLD;
        case ServiceUDP:
            return "._udp" TLD;
        default:
            return "";
    }
};

//
