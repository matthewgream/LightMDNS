
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

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#include <string.h>
#include <stdlib.h>

#include <Udp.h>

#include "ArduinoLightMDNS.hpp"

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#include <esp_mac.h>
static String getMacAddressBase(void) {
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_BASE);
    char str[6 * 2 + 1];
    snprintf(str, sizeof(str), "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return str;
}

#define DEBUG_MDNS
#ifdef DEBUG_MDNS
#define DEBUG_PRINTF Serial.printf
#else
#define DEBUG_PRINTF(...) \
    do { \
    } while (0)
#endif

// -----------------------------------------------------------------------------------------------

#include <numeric>

static String join(const std::vector<String>& elements, const String& delimiter) {
    return elements.empty() ? String() : std::accumulate(std::next(elements.begin()), elements.end(), elements[0], [&delimiter](const String& a, const String& b) {
        return a + delimiter + b;
    });
}

static void dump(const char* label, const uint8_t* data, const size_t size, const size_t offs = 0) {
    DEBUG_PRINTF("    <%s: 0x%04X>\n", label, size);
    for (auto i = 0; i < size; i += 16) {
        const auto left = (i + 16) > size ? 16 : size - i;
        DEBUG_PRINTF("    0x%04X: ", offs + i);
        for (auto j = 0; j < 16; j++) {
            if (j < left) DEBUG_PRINTF("%02X ", data[i + j]);
            else DEBUG_PRINTF("   ");
            if ((j + 1) % 8 == 0)
                DEBUG_PRINTF(" ");
        }
        DEBUG_PRINTF(" ");
        for (auto j = 0; j < 16; j++) {
            if (j < left) DEBUG_PRINTF("%c", isprint(data[i + j]) ? (char)data[i + j] : '.');
            else DEBUG_PRINTF(" ");
            if ((j + 1) % 8 == 0)
                DEBUG_PRINTF(" ");
        }
        DEBUG_PRINTF("\n");
    }
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#define TLD ".local"
static constexpr const char* SERVICE_SD_FQSN = "_services._dns-sd._udp.local";

typedef enum {
    PacketTypeCompleteRecord,     // All record provide
    PacketTypeCompleteRelease,    // All record release
    PacketTypeAddressRecord,      // A record provide
    PacketTypeAddressRelease,     // A record release
    PacketTypeReverseRecord,      // Reverse mapping provide
    PacketTypeServiceRecord,      // Service record provide (SRV/TXT/PTR)
    PacketTypeServiceRelease,     // Service record release
    PacketTypeProbe,              // Name probe (conflict detection)
    PacketTypeNextSecure,         // NextSecure record (indicate no other records exist)
} PacketType;

typedef struct {
    uint16_t xid;                      // Transaction ID: randomly chosen, used to match responses to queries
    uint8_t recursionDesired : 1;      // RD: Client sets this to request recursive resolution
    uint8_t truncated : 1;             // TC: Set when message is larger than transmission size allows
    uint8_t authoritiveAnswer : 1;     // AA: Server sets this when it's authoritative for the domain
    uint8_t opCode : 4;                // Operation type: 0=Query, 1=IQuery, 2=Status, 4=Notify, 5=Update
    uint8_t queryResponse : 1;         // QR: 0 for queries, 1 for responses
    uint8_t responseCode : 4;          // RCODE: 0=No error, 1=Format error, 2=Server fail, 3=Name error
    uint8_t checkingDisabled : 1;      // CD: Disables DNSSEC validation
    uint8_t authenticatedData : 1;     // AD: Indicates DNSSEC validation passed
    uint8_t zReserved : 1;             // Z: Reserved for future use, must be zero
    uint8_t recursionAvailable : 1;    // RA: Server sets this if it supports recursion
    uint16_t queryCount;               // QDCOUNT: Number of questions in the query section
    uint16_t answerCount;              // ANCOUNT: Number of records in the answer section
    uint16_t authorityCount;           // NSCOUNT: Number of records in the authority section
    uint16_t additionalCount;          // ARCOUNT: Number of records in the additional section
} __attribute__((__packed__)) Header;

// -----------------------------------------------------------------------------------------------

// HEADER

static constexpr uint16_t XID_DEFAULT = 0;

static constexpr uint8_t DNS_BIT_RD = 0;    // Recursion Desired

static constexpr uint8_t DNS_BIT_TC = 1;    // Truncation flag

static constexpr uint8_t DNS_BIT_AA = 2;    // Authoritative Answer
static constexpr uint8_t DNS_AA_NON_AUTHORITATIVE = 0;
static constexpr uint8_t DNS_AA_AUTHORITATIVE = 1;

static constexpr uint8_t DNS_OPCODE_QUERY = 0;     // Standard query
static constexpr uint8_t DNS_OPCODE_IQUERY = 1;    // Inverse query
static constexpr uint8_t DNS_OPCODE_STATUS = 2;    // Server status request
static constexpr uint8_t DNS_OPCODE_NOTIFY = 4;    // Zone change notification
static constexpr uint8_t DNS_OPCODE_UPDATE = 5;    // Dynamic update

static constexpr uint8_t DNS_BIT_QR = 7;    // Query/Response flag
static constexpr uint8_t DNS_QR_QUERY = 0;
static constexpr uint8_t DNS_QR_RESPONSE = 1;

static constexpr uint8_t DNS_RCODE_NOERROR = 0;     // No error
static constexpr uint8_t DNS_RCODE_FORMERR = 1;     // Format error
static constexpr uint8_t DNS_RCODE_SERVFAIL = 2;    // Server failure
static constexpr uint8_t DNS_RCODE_NXDOMAIN = 3;    // Non-existent domain
static constexpr uint8_t DNS_RCODE_NOTIMP = 4;      // Not implemented
static constexpr uint8_t DNS_RCODE_REFUSED = 5;     // Query refused
static constexpr uint8_t DNS_RCODE_YXDOMAIN = 6;    // Name exists when it should not
static constexpr uint8_t DNS_RCODE_YXRRSET = 7;     // RR set exists when it should not
static constexpr uint8_t DNS_RCODE_NXRRSET = 8;     // RR set that should exist does not
static constexpr uint8_t DNS_RCODE_NOTAUTH = 9;     // Server not authoritative
static constexpr uint8_t DNS_RCODE_NOTZONE = 10;    // Name not contained in zone

static constexpr uint8_t DNS_BIT_CD = 4;    // Checking Disabled
static constexpr uint8_t DNS_BIT_AD = 5;    // Authenticated Data
static constexpr uint8_t DNS_BIT_Z = 6;     // Reserved bit
static constexpr uint8_t DNS_BIT_RA = 7;    // Recursion Available

// RR

static constexpr uint8_t DNS_RECORD_HI = 0x00;       // High byte of record type
static constexpr uint8_t DNS_RECORD_A = 0x01;        // IPv4 host address
static constexpr uint8_t DNS_RECORD_NS = 0x02;       // Nameserver
static constexpr uint8_t DNS_RECORD_CNAME = 0x05;    // Canonical name (alias)
static constexpr uint8_t DNS_RECORD_SOA = 0x06;      // Start of Authority
static constexpr uint8_t DNS_RECORD_PTR = 0x0C;      // Domain name pointer
static constexpr uint8_t DNS_RECORD_MX = 0x0F;       // Mail exchange
static constexpr uint8_t DNS_RECORD_TXT = 0x10;      // Text record
static constexpr uint8_t DNS_RECORD_AAAA = 0x1C;     // IPv6 host address
static constexpr uint8_t DNS_RECORD_SRV = 0x21;      // Service location
static constexpr uint8_t DNS_RECORD_NSEC = 0x2F;     // Next Secure record
static constexpr uint8_t DNS_RECORD_ANY = 0xFF;      // Any type (query only)

static constexpr uint8_t DNS_CACHE_FLUSH = 0x80;       // Flag to tell others to flush cached entries
static constexpr uint8_t DNS_CACHE_NO_FLUSH = 0x00;    // Normal caching behavior

static constexpr uint8_t DNS_CLASS_IN = 0x01;    // Internet class

static constexpr uint32_t DNS_SRV_PRIORITY_DEFAULT = 0x00;    // Default SRV priority
static constexpr uint32_t DNS_SRV_WEIGHT_DEFAULT = 0x00;      // Default SRV weight

static constexpr uint8_t DNS_COMPRESS_MARK = 0xC0;    // Marker for compressed names

static constexpr uint8_t NSEC_WINDOW_BLOCK_0 = 0x00;    // First window block (types 1-255)
static constexpr uint8_t NSEC_BITMAP_LEN = 0x06;        // Length needed to cover up to type 33 (SRV)

static constexpr uint8_t DNS_TXT_LENGTH_MAX = 255;          // Maximum length of a single TXT record
static constexpr uint16_t DNS_TXT_EMPTY_LENGTH = 0x0001;    // Length for empty TXT
static constexpr uint8_t DNS_TXT_EMPTY_CONTENT = 0x00;      // Single null byte

static constexpr uint32_t DNS_TTL_DEFAULT = 120;
static constexpr uint32_t DNS_TTL_ZERO = 0;
static constexpr uint32_t DNS_TTL_SHARED_MAX = 10;    // per RFC

// CONSTANTS

static constexpr size_t DNS_LABEL_LENGTH_MAX = 63;        // Maximum length of a DNS label section
static constexpr size_t DNS_SERVICE_LENGTH_MAX = 100;     // Maximum number of services
static constexpr size_t DNS_PACKET_LENGTH_MAX = 9000;     // Maximum size of DNS packet
static constexpr size_t DNS_PACKET_LENGTH_SAFE = 1410;    // Safe size of DNS packet

static constexpr size_t DNS_RECORD_HEADER_SIZE = 10;    // Type(2) + Class(2) + TTL(4) + Length(2)
static constexpr size_t DNS_SRV_DETAILS_SIZE = 6;       // Priority(2) + Weight(2) + Port(2)

static constexpr uint32_t DNS_PROBE_WAIT_MS = 250;    // Wait time between probes
static constexpr size_t DNS_PROBE_COUNT = 3;          // Number of probes

static constexpr uint16_t DNS_COUNT_SINGLE = 1;         // Used for single record responses
static constexpr uint16_t DNS_COUNT_SERVICE = 4;        // Used for service announcements (SRV+TXT+2×PTR)
static constexpr uint16_t DNS_COUNT_A_RECORD = 1;       // A record
static constexpr uint16_t DNS_COUNT_PER_SERVICE = 3;    // SRV + TXT + PTR per service
static constexpr uint16_t DNS_COUNT_DNS_SD_PTR = 1;     // DNS-SD PTR record

// -----------------------------------------------------------------------------------------------

enum class DNSSections {
    Query = 1 << 0,
    Answer = 1 << 1,
    Authority = 1 << 2,
    Additional = 1 << 3,
    All = Query | Answer | Authority | Additional
};
static constexpr DNSSections operator|(const DNSSections a, const DNSSections b) {
    return static_cast<DNSSections>(static_cast<int>(a) | static_cast<int>(b));
}
static constexpr DNSSections operator&(const DNSSections a, const DNSSections b) {
    return static_cast<DNSSections>(static_cast<int>(a) & static_cast<int>(b));
}
static DNSSections getSection(const size_t i, const size_t qd, const size_t an, const size_t ns) {
    if (i < qd) return DNSSections::Query;
    if (i < an) return DNSSections::Answer;
    if (i < ns) return DNSSections::Authority;
    return DNSSections::Additional;
}
static const char* getSectionName(const DNSSections section) {
    switch (section) {
        case DNSSections::Query: return "query";
        case DNSSections::Answer: return "answer";
        case DNSSections::Authority: return "authority";
        default: return "additional";
    }
}

static String parseDNSType(const uint16_t type) {
    switch (type) {
        // Standard DNS types
        case 0x0001: return "A";        // IPv4 host address
        case 0x0002: return "NS";       // Authoritative name server
        case 0x0005: return "CNAME";    // Canonical name for an alias
        case 0x0006: return "SOA";      // Start of authority record
        case 0x000C: return "PTR";      // Domain name pointer
        case 0x000D: return "HINFO";    // Host information
        case 0x000F: return "MX";       // Mail exchange
        case 0x0010: return "TXT";      // Text strings
        case 0x001C: return "AAAA";     // IPv6 host address
        case 0x0021:
            return "SRV";    // Service locator
        // EDNS and Security
        case 0x0029: return "OPT";       // EDNS options (RFC 6891)
        case 0x002B: return "DS";        // Delegation signer
        case 0x002E: return "RRSIG";     // DNSSEC signature
        case 0x002F: return "NSEC";      // Next secure record
        case 0x0030: return "DNSKEY";    // DNS public key
        case 0x0032: return "NSEC3";     // NSEC version 3
        case 0x0033:
            return "NSEC3PARAM";    // NSEC3 parameters
        // Modern Extensions
        case 0x0034: return "TLSA";    // TLS cert association
        case 0x0100: return "CAA";     // Cert authority authorization
        case 0x0101:
            return "DHCID";    // DHCP identifier
        // Special Types
        case 0x00F9: return "TKEY";          // Transaction key
        case 0x00FA: return "TSIG";          // Transaction signature
        case 0x00FB: return "DNSKEY_ALT";    // Alternative DNSKEY
        case 0x00FC: return "RRSIG_ALT";     // Alternative RRSIG
        case 0x00FE: return "AXFR";          // Zone transfer
        case 0x00FF:
            return "ANY";    // Match any type
        // Experimental/Local Use (RFC 6762)
        case 0xFF00: return "LLQ";         // Long-lived query
        case 0xFF01: return "ULLQ";        // Update leases
        case 0xFF02: return "PRIVATE1";    // Private use
        case 0xFF03:
            return "PRIVATE2";    // Private use
        // Meta Queries (RFC 6763)
        case 0xFF1F: return "SERVICE_TYPE_ENUM";    // Service type enumeration
        case 0xFF20: return "SERVICE_PORT";         // Service port
        case 0xFF21: return "SERVICE_TXT";          // Service text
        case 0xFF22: return "SERVICE_TARGET";       // Service target host
        default:
            {
                String result = "Unknown(" + String(type, HEX) + ")";
                if (type >= 0xFFF0)
                    result += "/Reserved";
                else if (type >= 0xFF00)
                    result += "/Local";
                return result;
            }
    }
}

static String parseDNSFlags(const uint8_t flagsByte) {
    if (flagsByte & 0x80) return "CACHE_FLUSH";
    return String("CACHE_NO_FLUSH");
}

static String parseDNSClassOrEDNS(const uint8_t classByte1, const uint8_t classByte2, const uint16_t type) {
    if (type == 0x0029) {    // OPT record
        const uint16_t payloadSize = (static_cast<uint16_t>(classByte1) << 8) | classByte2;
        String result = "UDP_SIZE(" + String(payloadSize) + ")";
        if (payloadSize < 512)
            result += "/Small";
        else if (payloadSize > 1432)
            result += "/Large";
        return result;
    }
    switch (classByte2) {
        case 0x01: return "IN";
        case 0x02: return "CS";
        case 0x03: return "CH";
        case 0x04: return "HS";
        case 0xFE: return "NONE";
        case 0xFF: return "ANY";
        default: return "Unknown(" + String(classByte2, HEX) + ")";
    }
}

static String parseHeader(const Header& h) {
    static const char* opcodes[] = { "QUERY", "IQUERY", "STATUS", "RESERVED", "NOTIFY", "UPDATE", "UNK6", "UNK7", "UNK8", "UNK9", "UNK10", "UNK11", "UNK12", "UNK13", "UNK14", "UNK15" };
    static const char* rcodes[] = { "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE", "UNK11", "UNK12", "UNK13", "UNK14", "UNK15" };
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

static String parseControl(const uint8_t ctrl[4]) {
    const uint16_t type = (ctrl[0] << 8) | ctrl[1];
    return parseDNSType(type) + "/" + parseDNSFlags(ctrl[2]) + "/" + parseDNSClassOrEDNS(ctrl[2], ctrl[3], type);    // Pass both bytes
}

// -----------------------------------------------------------------------------------------------

static const IPAddress MDNS_ADDR_MULTICAST(224, 0, 0, 251);
static constexpr uint16_t MDNS_PORT = 5353;

static constexpr struct SupportedRecordType {
    uint8_t type;
    uint8_t byte;
    uint8_t mask;
} SupportedRecordTypes[] = {
    { DNS_RECORD_A, 0, 0x80 },      // Type 1  -> byte 0, bit 7, mask 0x80
    { DNS_RECORD_PTR, 1, 0x10 },    // Type 12 -> byte 1, bit 4, mask 0x10
    { DNS_RECORD_TXT, 1, 0x01 },    // Type 16 -> byte 1, bit 0, mask 0x01
    { DNS_RECORD_SRV, 4, 0x80 },    // Type 33 -> byte 4, bit 7, mask 0x80
};
static_assert([] {
    for (const auto& rt : SupportedRecordTypes)
        if (rt.byte != ((rt.type - 1) / 8) || rt.mask != (1 << (7 - ((rt.type - 1) % 8))))
            return false;
    return true;
}(),
              "SupportedRecordTypes bitmap calculations are incorrect");

static constexpr const char* protocolPostfix(const MDNS::ServiceProtocol proto) {
    switch (proto) {
        case MDNS::ServiceTCP:
            return "._tcp" TLD;
        case MDNS::ServiceUDP:
            return "._udp" TLD;
        default:
            return "";
    }
};

static constexpr bool DETAILED_CHECKS = true;
static constexpr uint16_t DETAILED_CHECKS_REASONABLE_COUNT = 100;

static inline String makeReverseArpaName(const IPAddress& addr) {
    return String(addr[3]) + "." + String(addr[2]) + "." + String(addr[1]) + "." + String(addr[0]) + ".in-addr.arpa";
}

// -----------------------------------------------------------------------------------------------

static inline size_t _sizeofDNSName(const String& name) {
    return name.length() + 2;    // string length + length byte + null terminator ('.'s just turn into byte lengths)
}

static inline size_t _sizeofService(const MDNS::Service& service, const String& fqhn, const bool includeAdditional = false) {
    size_t size = sizeof(Header);
    size += _sizeofDNSName(service.fqsn) + DNS_RECORD_HEADER_SIZE + DNS_SRV_DETAILS_SIZE + _sizeofDNSName(fqhn);    // SRV
    size += _sizeofDNSName(service.fqsn) + DNS_RECORD_HEADER_SIZE + service._cachedTextLength;                      // TXT
    size += _sizeofDNSName(service.serv) + DNS_RECORD_HEADER_SIZE + _sizeofDNSName(service.fqsn);                   // PTR SRV
    if (includeAdditional) {
        size += _sizeofDNSName(SERVICE_SD_FQSN) + DNS_RECORD_HEADER_SIZE + _sizeofDNSName(fqhn);    // PTR SD
        size += _sizeofDNSName(fqhn) + DNS_RECORD_HEADER_SIZE + 4;                                  // PTR IP
    }
    return size;
}

static inline size_t _sizeofCompleteRecord(const MDNS::Services& services, const String& fqhn) {
    size_t size = sizeof(Header);
    size += _sizeofDNSName(fqhn) + DNS_RECORD_HEADER_SIZE + 4;                                  // PTR IP
    size += _sizeofDNSName(SERVICE_SD_FQSN) + DNS_RECORD_HEADER_SIZE + _sizeofDNSName(fqhn);    // PTR SD
    size += services.empty() ? 0 : std::accumulate(services.begin(), services.end(), static_cast<size_t>(0), [&](const size_t size, const MDNS::Service& service) {
        return size + _sizeofService(service, fqhn);
    });
    return size;
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#define UDP_READ_START() _udp->beginMulticast(MDNS_ADDR_MULTICAST, MDNS_PORT)
#define UDP_READ_STOP() _udp->stop()

#define UDP_READ_BEGIN(u) \
    UDP* _udp_handle = u; \
    uint16_t _udp_offset = 0, _udp_length = _udp_handle->parsePacket();
#define UDP_READ_END() _udp_handle->flush()
#define UDP_READ_AVAILABLE() (_udp_length != static_cast<uint16_t>(0))
#define UDP_READ_BYTE_OR_FAIL(t, x, y) \
    { \
        if (_udp_offset >= _udp_length) y; \
        const int _udp_byte = _udp_handle->read(); \
        if (_udp_byte < 0) y; \
        x = static_cast<t>(_udp_byte); \
        _udp_offset++; \
    }
#define UDP_SKIP_BYTE_OR_FAIL(y) \
    { \
        if (_udp_offset >= _udp_length) y; \
        const int _udp_byte = _udp_handle->read(); \
        if (_udp_byte < 0) y; \
        _udp_offset++; \
    }
#define UDP_READ_PEEK() _udp_handle->peek()
#define UDP_READ_LENGTH() _udp_length
#define UDP_READ_OFFSET() _udp_offset
#define UDP_READ_PEER_ADDR() _udp_handle->remoteIP()
#define UDP_READ_PEER_PORT() _udp_handle->remotePort()

// a mess mixed with the specific handlers
template<typename Handler>
struct UDP_READ_PACKET_CLASS {
    Handler& _handler;
    const Header& _header;
    //
    UDP* _udp_handle;
    uint16_t& _udp_offset;
    uint16_t& _udp_length;

#define UDP_READ_PACKET_VARS _udp_handle, _udp_offset, _udp_length
    UDP_READ_PACKET_CLASS(Handler& handler, const Header& header, UDP* udp_handle, uint16_t& udp_offset, uint16_t& udp_length)
        : _handler(handler), _header(header), _udp_handle(udp_handle), _udp_offset(udp_offset), _udp_length(udp_length){};
    ~UDP_READ_PACKET_CLASS() {
        UDP_READ_END();
    }

    bool _extractLabels(const DNSSections section, uint16_t* consumed = nullptr) {
        uint8_t size = 0, comp;
        uint16_t used = 0;
        do {
            const uint16_t offset = UDP_READ_OFFSET();
            UDP_READ_BYTE_OR_FAIL(uint8_t, size, break);
            used++;
            if ((size & DNS_COMPRESS_MARK) == DNS_COMPRESS_MARK) {
                UDP_READ_BYTE_OR_FAIL(uint8_t, comp, return false);
                used++;
                const uint16_t offs = ((static_cast<uint16_t>(size) & ~DNS_COMPRESS_MARK) << 8) | static_cast<uint16_t>(comp);
                _handler.process_iscompressed(offs, section, offset);

            } else if (size > 0) {
                String name;
                name.reserve(size + 1);
                for (auto z = 0; z < size; z++) {
                    char c;
                    UDP_READ_BYTE_OR_FAIL(char, c, return false);
                    used++;
                    name += c;
                }
                _handler.process_nocompressed(name, section, offset);
            }
        } while (size > 0 && size <= DNS_LABEL_LENGTH_MAX);
        if (consumed != nullptr) (*consumed) += used;
        return true;
    }
    bool _extractControl(uint8_t ctrl[4]) {
        for (auto z = 0; z < 4; z++)
            UDP_READ_BYTE_OR_FAIL(uint8_t, ctrl[z], return false);
        return true;
    }
    bool _passoverTTL(void) {
        for (auto i = 0; i < 4; i++)
            UDP_SKIP_BYTE_OR_FAIL(return false);
        return true;
    }
    bool _extractLength(uint16_t* length) {
        uint8_t b1, b2;
        UDP_READ_BYTE_OR_FAIL(uint8_t, b1, return false);
        UDP_READ_BYTE_OR_FAIL(uint8_t, b2, return false);
        (*length) = (static_cast<uint16_t>(b1) << 8) | static_cast<uint16_t>(b2);
        return true;
    }
    bool _passbySRVDetails(uint16_t* consumed = nullptr) {
        for (auto i = 0; i < 6; i++)    // priority, weight, port
            UDP_SKIP_BYTE_OR_FAIL(return false);
        if (consumed) (*consumed) += 6;
        return true;
    }
    bool _passbyMXDetails(uint16_t* consumed = nullptr) {
        for (auto i = 0; i < 2; i++)    // preference
            UDP_SKIP_BYTE_OR_FAIL(return false);
        if (consumed) (*consumed) += 2;
        return true;
    }
    bool _passbySOADetails(uint16_t* consumed = nullptr) {
        for (auto i = 0; i < 20; i++)    // 5 x 32 bit values
            UDP_SKIP_BYTE_OR_FAIL(return false);
        if (consumed) (*consumed) += 20;
        return true;
    }

    bool process(void) {

        _handler.begin();

        const size_t qd = _header.queryCount, an = qd + _header.answerCount, ns = an + _header.authorityCount, ad = ns + _header.additionalCount;

        for (size_t i = 0; i < ad; i++) {

            const DNSSections section = getSection(i, qd, an, ns);

            DEBUG_PRINTF("MDNS: packet: %s[%d/%u]: ", getSectionName(section), i + 1, ad);

            _handler.process_begin(section, UDP_READ_OFFSET());

            if (!_extractLabels(section))
                return false;
            uint8_t control[4];
            if (!_extractControl(control))
                return false;
            const uint16_t type = (static_cast<uint16_t>(control[0]) << 8) | static_cast<uint16_t>(control[1]);

            _handler.process_update(section, control);

            const String name = _handler.name();
            DEBUG_PRINTF("<%s> [%s] (%s)\n", name.c_str(), parseControl(control).c_str(), getSectionName(section));

            if (section != DNSSections::Query) {

                if (!_passoverTTL())
                    return false;
                uint16_t length, consumed = 0;
                if (!_extractLength(&length))
                    return false;

                switch (type) {
                    case DNS_RECORD_CNAME:                                               // possible
                    case DNS_RECORD_NS:                                                  // unlikely
                    case DNS_RECORD_PTR:                                                 // typical
                    case DNS_RECORD_NSEC:                                                // typical
                        if (consumed < length && !_extractLabels(section, &consumed))    // target
                            return false;
                        break;
                    case DNS_RECORD_SRV:    // typical
                        if (consumed < length && !_passbySRVDetails(&consumed))
                            return false;
                        if (consumed < length && !_extractLabels(section, &consumed))    // target
                            return false;
                        break;
                    case DNS_RECORD_MX:    // possible
                        if (consumed < length && !_passbyMXDetails(&consumed))
                            return false;
                        if (consumed < length && !_extractLabels(section, &consumed))    // exchanger
                            return false;
                        break;
                    case DNS_RECORD_SOA:                                                 // unlikely
                        if (consumed < length && !_extractLabels(section, &consumed))    // MNAME
                            return false;
                        if (consumed < length && !_extractLabels(section, &consumed))    // RNAME
                            return false;
                        if (consumed < length && !_passbySOADetails(&consumed))
                            return false;
                        break;
                }

                while (consumed++ < length)
                    UDP_SKIP_BYTE_OR_FAIL(return false);
            }

            if (section != DNSSections::Query && name.isEmpty())
                DEBUG_PRINTF("**** EMPTY ****\n");

            _handler.process_end(section, UDP_READ_OFFSET());
        }

        _handler.end();

        return true;
    }
};

    struct NameCollector {
        MDNS& _mdns;
        const Header& _header;
        //
        using LabelOffset = std::pair<String, uint16_t>;
        using Labels = std::vector<LabelOffset>;
        struct Name {
            DNSSections section;
            Labels labels;
        };
        using Names = std::vector<Name>;
        Names _names;
        //
        String _uncompress(const size_t target) const {
            for (const auto& name : _names)
                for (const auto& [label, offset] : name.labels)
                    if (target >= offset && target < (offset + label.length()))
                        return (target == offset) ? label : label.substring(target - offset);
            DEBUG_PRINTF("*** WARNING: could not uncompress at %u ***\n", target);
            return String();
        }
        String _name(const Labels& labels) const {
            return labels.empty() ? String() : std::accumulate(labels.begin(), labels.end(), String(), [](const String& acc, const LabelOffset& label) {
                return acc.isEmpty() ? label.first : acc + "." + label.first;
            });
        }
        //
        String name() const {
            return _names.empty() ? String() : _name(_names.back().labels);
        }
        std::vector<String> names(const DNSSections section = DNSSections::All) const {
            std::vector<String> names;
            for (const auto& name : _names)
                if ((name.section & section) == name.section)
                    names.push_back(_name(name.labels));
            return names;
        }
        virtual void begin() {}
        virtual void end() {}
        void process_iscompressed(const uint16_t offs, const DNSSections, const uint16_t current) {
            _names.back().labels.push_back(LabelOffset(_uncompress(offs), current));
        }
        void process_nocompressed(const String& label, const DNSSections, const uint16_t current) {
            _names.back().labels.push_back(LabelOffset(label, current));
        }
        void process_begin(const DNSSections section, const uint16_t offset) {
            _names.push_back({ .section = section, .labels = Labels() });
        }
        void process_update(const DNSSections, const uint8_t[4]) {
        }
        void process_end(const DNSSections, const uint16_t) {
        }
        NameCollector(MDNS& mdns, const Header& header)
            : _mdns(mdns), _header(header){};
    };

#define UDP_WRITE_BEGIN() _udp->beginPacket(MDNS_ADDR_MULTICAST, MDNS_PORT)
#define UDP_WRITE_END() _udp->endPacket()
#define UDP_WRITE_BYTE(x) _udp->write(x)
#define UDP_WRITE_DATA(x, y) _udp->write(x, y)

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

MDNS::MDNS(UDP& udp)
    : _udp(&udp), _enabled(false), _announced(0) {
}
MDNS::~MDNS() {
    stop();
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

MDNS::Status MDNS::begin(void) {

    DEBUG_PRINTF("MDNS: begin\n");

    return Success;
}

MDNS::Status MDNS::start(const IPAddress& addr, const String& name, const bool checkForConflicts) {

    _addr = addr;
    _name = name.isEmpty() ? getMacAddressBase() : name;
    _fqhn = name + TLD;
    _arpa = makeReverseArpaName(_addr);

    if (!_sizeofDNSName(_name)) {
        DEBUG_PRINTF("MDNS: start: failed, invalid name %s\n", _name.c_str());
        return InvalidArgument;
    }

    Status status = Success;
    if (!_enabled) {
        if (!UDP_READ_START())
            status = Failure;
        else _enabled = true;
    }

    if (status != Success)
        DEBUG_PRINTF("MDNS: start: failed _udp->beginMulticast error=%s, not active\n", toString(status).c_str());
    else {
        DEBUG_PRINTF("MDNS: start: active ip=%s, name=%s\n", IPAddress(_addr).toString().c_str(), _fqhn.c_str());
        if (checkForConflicts) {
            for (auto i = 0; i < DNS_PROBE_COUNT; i++) {
                _messageSend(XID_DEFAULT, PacketTypeProbe);
                delay(DNS_PROBE_WAIT_MS);
            }
            delay(DNS_PROBE_WAIT_MS);
        }
        _messageSend(XID_DEFAULT, PacketTypeCompleteRecord);
    }

    return status;
}

MDNS::Status MDNS::stop(void) {

    if (_enabled) {
        DEBUG_PRINTF("MDNS: stop\n");
        // XXX: should send multiple messages 2 seconds apart
        _messageSend(XID_DEFAULT, PacketTypeCompleteRelease);
        UDP_READ_STOP();
        _enabled = false;
    }

    return Success;
}

MDNS::Status MDNS::process(void) {

    Status status = Success;
    if (_enabled) {
        auto count = 0;
        do {
            count++;
        } while ((status = _messageRecv()) == Success);

        if (status == NameConflict)
            return _conflicted();
        if (status != Success && status != TryLater)
            DEBUG_PRINTF("MDNS: process: failed _messageRecv error=%s\n", toString(status).c_str());
        else if (status == Success || status == TryLater)
            if ((status = _announce()) != Success)
                DEBUG_PRINTF("MDNS: process: failed _announce error=%s\n", toString(status).c_str());
        if (count > 1)
            DEBUG_PRINTF("MDNS: process [%d]\n", count - 1);
    }

    return status;
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

MDNS::Status MDNS::serviceRecordInsert(const ServiceProtocol proto, const uint16_t port, const String& name, const TextRecords& text) {

    DEBUG_PRINTF("MDNS: serviceRecordInsert: proto=%s, port=%u, name=%s, text.size=%d,text=[%s]\n", toString(proto).c_str(), port, name.c_str(), text.size(), join(text, ",").c_str());

    if (name.isEmpty() || port == 0 || (proto != ServiceTCP && proto != ServiceUDP))
        return InvalidArgument;
    if (_services.size() >= DNS_SERVICE_LENGTH_MAX)
        return InvalidArgument;
    if (!_sizeofDNSName(name))
        return InvalidArgument;

    const uint16_t textLength = text.empty() ? DNS_TXT_EMPTY_LENGTH : std::accumulate(text.begin(), text.end(), static_cast<uint16_t>(0), [](const uint16_t size, const auto& item) {
        return size + (1 + std::min(item.length(), static_cast<size_t>(DNS_TXT_LENGTH_MAX)));
    });
    Service serviceNew{ .port = port, .proto = proto, .name = name, .serv = name.substring(name.lastIndexOf('.') + 1) + protocolPostfix(proto), .fqsn = name + protocolPostfix(proto), .text = text, ._cachedTextLength = textLength };

    if ((_sizeofCompleteRecord(_services, _fqhn) + _sizeofService(serviceNew, _fqhn)) > DNS_PACKET_LENGTH_SAFE)    // could solve with truncation support
        return OutOfMemory;

    try {
        const auto& service = _services.emplace_back(serviceNew);
        if (_enabled)
            _messageSend(XID_DEFAULT, PacketTypeServiceRecord, &service);
        return Success;
    } catch (const std::bad_alloc&) {
        return OutOfMemory;
    }
}

MDNS::Status MDNS::serviceRecordRemove(const ServiceProtocol proto, const uint16_t port, const String& name) {

    DEBUG_PRINTF("MDNS: serviceRecordRemove: proto=%s, port=%u, name=%s\n", toString(proto).c_str(), port, name.c_str());

    std::erase_if(_services, [&](const Service& service) {
        if (!(service.port == port && service.proto == proto && (name.isEmpty() || service.name == name)))
            return false;
        if (_enabled)
            _messageSend(XID_DEFAULT, PacketTypeServiceRelease, &service);
        return true;
    });

    return Success;
}

MDNS::Status MDNS::serviceRecordClear() {

    DEBUG_PRINTF("MDNS: serviceRecordClear\n");

    if (_enabled)
        for (const auto& service : _services)
            _messageSend(XID_DEFAULT, PacketTypeServiceRelease, &service);
    _services.clear();

    return Success;
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

MDNS::Status MDNS::_announce() {

    if (_enabled && (millis() - _announced) > ((DNS_TTL_DEFAULT / 2) + (DNS_TTL_DEFAULT / 4)) * static_cast<uint32_t>(1000)) {

        DEBUG_PRINTF("MDNS: announce: services (%d)\n", _services.size());

        _messageSend(XID_DEFAULT, PacketTypeCompleteRecord);

        _announced = millis();
    }
    return Success;
}

MDNS::Status MDNS::_conflicted() {

    DEBUG_PRINTF("MDNS: conflicted: name=%s (will stop and start with new name)\n", _name.c_str());

    stop();
    return start(_addr, _name + "-" + getMacAddressBase());
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

const char* _checkHeader(const Header& header, const uint16_t packetSize, const int firstByte) {
    if (packetSize < (sizeof(Header) + (header.queryCount * 6) + (header.authorityCount * 6)))
        return "packet too small for claimed record counts";
    if (header.opCode > DNS_OPCODE_UPDATE)
        return "invalid opcode";
    if (header.responseCode > DNS_RCODE_NOTZONE)
        return "invalid response code";
    if (header.queryResponse == 0 && header.authoritiveAnswer == 1)
        return "query with AA set";
    if (header.queryCount > DETAILED_CHECKS_REASONABLE_COUNT || header.answerCount > DETAILED_CHECKS_REASONABLE_COUNT || header.authorityCount > DETAILED_CHECKS_REASONABLE_COUNT || header.additionalCount > DETAILED_CHECKS_REASONABLE_COUNT)
        return "unreasonable record counts";
    if (header.zReserved != 0)
        return "reserved bit set";
    if (firstByte < 0 || firstByte > DNS_LABEL_LENGTH_MAX)
        return "invalid first label length";
    if (header.truncated && packetSize < 512)
        return "suspicious: TC set but packet small";
    return nullptr;
}

const char* _checkAddress(const IPAddress& addrLocal, const IPAddress& addr) {
    if (addr[0] == 0 && (addr[1] | addr[2] | addr[3]) == 0)
        return "invalid unspecified address (0.0.0.0)";
    if (addr[0] == 127)
        return "invalid loopback address (127.x.x.x)";
    if (addr[0] == 169 && addr[1] == 254) {    // link-local
        if (addr[2] == 0 || addr[2] == 255)
            return "invalid link-local broadcast (169.254.0|255.x)";
        if (!(addrLocal[0] == 169 && addrLocal[1] == 254 && addr[2] == addrLocal[2]))
            return "invalid link-local subnet mismatch";
    }
    return nullptr;
}

// -----------------------------------------------------------------------------------------------

MDNS::Status MDNS::_messageRecv() {
    const char* detailedError = nullptr;

    UDP_READ_BEGIN(_udp);
    if (!UDP_READ_AVAILABLE())
        return TryLater;

    DEBUG_PRINTF("MDNS: packet: receiving, size=%u\n", UDP_READ_LENGTH());

    Header header;
    for (auto z = 0; z < sizeof(Header); z++)
        UDP_READ_BYTE_OR_FAIL(uint8_t, reinterpret_cast<uint8_t*>(&header)[z], goto bad_packet_failed_header);    // should throw
    header.xid = ntohs(header.xid);
    header.queryCount = ntohs(header.queryCount);
    header.answerCount = ntohs(header.answerCount);
    header.authorityCount = ntohs(header.authorityCount);
    header.additionalCount = ntohs(header.additionalCount);

    if ((detailedError = _checkAddress(_addr, UDP_READ_PEER_ADDR())) != nullptr)
        goto bad_packet_failed_checks;    // should throw
    if (DETAILED_CHECKS && (detailedError = _checkHeader(header, UDP_READ_LENGTH(), UDP_READ_PEEK())) != nullptr)
        goto bad_packet_failed_checks;    // should throw
    if (header.truncated)
        DEBUG_PRINTF("MDNS: packet: received truncated from %s, but will proceed\n", UDP_READ_PEER_ADDR().toString().c_str());

    if ((header.authorityCount > 0 || header.queryResponse == DNS_QR_RESPONSE) && UDP_READ_PEER_PORT() == MDNS_PORT) {

        DEBUG_PRINTF("MDNS: packet: checking, %s / %s:%u\n", parseHeader(header).c_str(), UDP_READ_PEER_ADDR().toString().c_str(), UDP_READ_PEER_PORT());

        NameCollector collector(*this, header);
        UDP_READ_PACKET_CLASS<NameCollector> processor(collector, header, UDP_READ_PACKET_VARS);
        if (!processor.process())
            return PacketBad;    // should throw
        for (const auto& name : collector.names(DNSSections::Answer | DNSSections::Authority | DNSSections::Additional)) {
            if (name.equalsIgnoreCase(_fqhn))    // XXX should check against services
                if ((header.authorityCount > 0 && UDP_READ_PEER_ADDR() > _addr) || (header.authorityCount == 0 && header.queryResponse == DNS_QR_RESPONSE)) {
                    DEBUG_PRINTF("MDNS: conflict detected in probe: %s from %s\n", _fqhn.c_str(), UDP_READ_PEER_ADDR().toString().c_str());
                    return NameConflict;    // should throw
                }
        }

    } else if (header.queryResponse == DNS_QR_QUERY && header.opCode == DNS_OPCODE_QUERY && UDP_READ_PEER_PORT() == MDNS_PORT) {

        DEBUG_PRINTF("MDNS: packet: processing, %s / %s:%u\n", parseHeader(header).c_str(), UDP_READ_PEER_ADDR().toString().c_str(), UDP_READ_PEER_PORT());

        /////////////////////////////////////////////
        /////////////////////////////////////////////

        struct Responder {
            MDNS& _mdns;
            const Header& _header;
            //
            // this is all horrible and brittle and needs replacement, but is getting there ...
            const size_t recordsLengthStatic, recordsLength;
            struct _matcher_t {
                const char* name;
                int length;
                int match = 1;
                uint16_t position = 0;
                bool requested = false, unsupported = false;
            };
            std::vector<_matcher_t> recordsMatcherTop, recordsMatcherEach;
            uint16_t _starting{};
            uint8_t _control[4]{};
            //
            int __matchStringPart(const char** pCmpStr, int* pCmpLen, const uint8_t* data, const int dataLen) {
                const auto _memcmp_caseinsensitive = [](const char* a, const unsigned char* b, const int l) -> int {
                    for (auto i = 0; i < l; i++) {
                        if (tolower(a[i]) < tolower(b[i])) return -1;
                        if (tolower(a[i]) > tolower(b[i])) return 1;
                    }
                    return 0;
                };
                int matches = (*pCmpLen >= dataLen) ? 1 & (_memcmp_caseinsensitive(*pCmpStr, data, dataLen) == 0) : 0;
                *pCmpStr += dataLen;
                *pCmpLen -= dataLen;
                if ('.' == **pCmpStr)
                    (*pCmpStr)++, (*pCmpLen)--;
                return matches;
            };
            String name() const {
                return "UNSUPPORTED";
            }
            void process_iscompressed(const uint16_t offs, const DNSSections section, const uint16_t) {
                if (section != DNSSections::Query) return;
                DEBUG_PRINTF("(%04X)", offs);
                for (auto& m : recordsMatcherEach)
                    if (m.position && m.position != offs)
                        m.match = 0;
            };
            void process_nocompressed(const String& name, const DNSSections section, const uint16_t) {
                if (section != DNSSections::Query) return;
                DEBUG_PRINTF("[%s]", name.c_str());
                for (auto& m : recordsMatcherEach)
                    if (!m.requested && m.match)
                        m.match &= __matchStringPart(&m.name, &m.length, reinterpret_cast<const uint8_t*>(name.c_str()), static_cast<int>(name.length()));
            };
            void process_begin(const DNSSections section, const uint16_t starting) {
                if (section != DNSSections::Query) return;
                _starting = starting;
            }
            void process_update(const DNSSections section, const uint8_t control[4]) {
                if (section != DNSSections::Query) return;
                memcpy(_control, control, sizeof(_control));
            }
            void process_end(const DNSSections section, const uint16_t) {
                if (section != DNSSections::Query) return;
                size_t r = 0;
                for (auto& m : recordsMatcherEach) {
                    if (!m.requested && m.match && !m.length) {
                        if (!m.position)
                            m.position = _starting;
                        if (_control[0] == DNS_RECORD_HI && (_control[2] == DNS_CACHE_NO_FLUSH || _control[2] == DNS_CACHE_FLUSH) && _control[3] == DNS_CLASS_IN) {
                            if (r == 0) {    // Query for our hostname
                                if (_control[1] == DNS_RECORD_A)
                                    m.requested = true;
                                else
                                    m.unsupported = true;
                            } else if (r == 1) {    // Query for our address
                                if (_control[1] == DNS_RECORD_PTR)
                                    m.requested = true;
                                else
                                    m.unsupported = true;
                            } else {    // Query for our service
                                if (_control[1] == DNS_RECORD_PTR || _control[1] == DNS_RECORD_TXT || _control[1] == DNS_RECORD_SRV)
                                    m.requested = true;
                                else
                                    m.unsupported = true;
                            }
                        }
                    }
                    recordsMatcherTop[r].requested = m.requested;
                    recordsMatcherTop[r].unsupported = m.unsupported;
                    r++;
                }
                recordsMatcherEach = recordsMatcherTop;
            };
            void begin() {
                size_t j = 0;
                // XXX should build once and cache ... and update each time service name / etc is changed
                recordsMatcherTop[j].name = _mdns._fqhn.c_str(), recordsMatcherTop[j].length = _mdns._fqhn.length(), j++;
                recordsMatcherTop[j].name = _mdns._arpa.c_str(), recordsMatcherTop[j].length = _mdns._arpa.length(), j++;
                recordsMatcherTop[j].name = SERVICE_SD_FQSN, recordsMatcherTop[j].length = strlen(SERVICE_SD_FQSN), j++;
                for (const auto& r : _mdns._services)    // XXX should only include unique r.serv ...
                    recordsMatcherTop[j].name = r.serv.c_str(), recordsMatcherTop[j].length = r.serv.length(), j++;
                for (const auto& m : recordsMatcherTop)
                    DEBUG_PRINTF("MDNS: packet: processing, matching[]: <%s>: %d/%d/%d\n", m.name, m.match, m.length, m.position);
                recordsMatcherEach = recordsMatcherTop;
            };
            void end() {
                // XXX should coaescle into single response(s)
                // XXX should only have unique service names and match from that
                if (recordsMatcherTop[0].unsupported || recordsMatcherTop[1].unsupported || recordsMatcherTop[2].unsupported) {
                    DEBUG_PRINTF("MDNS: packet: processing, negated[%d/%d/%d]\n", recordsMatcherTop[0].unsupported, recordsMatcherTop[1].unsupported, recordsMatcherTop[2].unsupported);
                    _mdns._messageSend(_header.xid, PacketTypeNextSecure);
                }
                if (recordsMatcherTop[0].requested) {
                    DEBUG_PRINTF("MDNS: packet: processing, matched[NAME]: %s\n", recordsMatcherTop[0].name);
                    _mdns._messageSend(_header.xid, PacketTypeAddressRecord);
                }
                if (recordsMatcherTop[1].requested) {
                    DEBUG_PRINTF("MDNS: packet: processing, matched[ADDR]: %s\n", recordsMatcherTop[1].name);
                    _mdns._messageSend(_header.xid, PacketTypeAddressRecord);
                }
                if (recordsMatcherTop[2].requested) {
                    DEBUG_PRINTF("MDNS: packet: processing, matched[DISC]: %s\n", recordsMatcherTop[2].name);
                    _mdns._messageSend(_header.xid, PacketTypeCompleteRecord);
                } else {
                    size_t mi = 0;
                    for (const auto& r : _mdns._services) {
                        const auto& m = recordsMatcherTop[mi + recordsLengthStatic];
                        if (m.requested) {
                            DEBUG_PRINTF("MDNS: packet: processing, matched[SERV:%d]: %s\n", mi, m.name);
                            _mdns._messageSend(_header.xid, PacketTypeServiceRecord, &r);
                        }
                        if (m.unsupported) {
                            DEBUG_PRINTF("MDNS: packet: processing, negated[SERV:%d]: %s\n", mi, m.name);
                            _mdns._messageSend(_header.xid, PacketTypeNextSecure, &r);
                        }
                        mi++;
                    }
                }
            }
            Responder(MDNS& mdns, const Header& header)
                : _mdns(mdns), _header(header),
                  recordsLengthStatic(3), recordsLength(_mdns._services.size() + recordsLengthStatic),
                  recordsMatcherTop(recordsLength), recordsMatcherEach(recordsLength){};
        } _responder(*this, header);

        /////////////////////////////////////////////
        /////////////////////////////////////////////

        UDP_READ_PACKET_CLASS<Responder> processor(_responder, header, UDP_READ_PACKET_VARS);
        if (!processor.process())
            return PacketBad;

    } else {
#ifdef DEBUG_MDNS

        DEBUG_PRINTF("MDNS: packet: debugging, %s / %s:%u\n", parseHeader(header).c_str(), UDP_READ_PEER_ADDR().toString().c_str(), UDP_READ_PEER_PORT());

        NameCollector collector(*this, header);    // will do nothing, already did debugging
        UDP_READ_PACKET_CLASS<NameCollector> processor(collector, header, UDP_READ_PACKET_VARS);
        if (!processor.process())
            return PacketBad;    // should throw

#endif
    }

    // udp flush already done
    return Success;

    // shouldn't be needed, as should have thrown
bad_packet_failed_header:
    detailedError = "invalid header";
bad_packet_failed_checks:
    DEBUG_PRINTF("MDNS: packet: faulty(%s), %s / %s:%u\n", detailedError, parseHeader(header).c_str(), UDP_READ_PEER_ADDR().toString().c_str(), UDP_READ_PEER_PORT());
    UDP_READ_END();
    return PacketBad;
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

MDNS::Status MDNS::_messageSend(const uint16_t xid, const int type, const Service* service) {

    Header header{};
    header.xid = htons(xid);
    header.opCode = DNS_OPCODE_QUERY;
    switch (type) {
        case PacketTypeAddressRecord:
        case PacketTypeAddressRelease:
        case PacketTypeReverseRecord:
            header.queryResponse = DNS_QR_RESPONSE;
            header.authoritiveAnswer = DNS_AA_AUTHORITATIVE;
            header.answerCount = htons(DNS_COUNT_A_RECORD);
            header.additionalCount = htons(type == PacketTypeReverseRecord ? DNS_COUNT_A_RECORD : 0);    // A record as additional
            break;
        case PacketTypeServiceRecord:
        case PacketTypeServiceRelease:
            header.queryResponse = DNS_QR_RESPONSE;
            header.authoritiveAnswer = DNS_AA_AUTHORITATIVE;
            header.answerCount = htons(DNS_COUNT_PER_SERVICE);
            header.additionalCount = htons(type == PacketTypeServiceRecord ? (DNS_COUNT_DNS_SD_PTR + DNS_COUNT_A_RECORD) : 0);    // DNS-SD + A record as additional
            break;
        case PacketTypeCompleteRecord:
        case PacketTypeCompleteRelease:
            header.queryResponse = DNS_QR_RESPONSE;
            header.authoritiveAnswer = DNS_AA_AUTHORITATIVE;
            header.answerCount = htons(DNS_COUNT_A_RECORD + (_services.empty() ? 0 : (DNS_COUNT_DNS_SD_PTR + (_services.size() * DNS_COUNT_PER_SERVICE))));
            break;
        case PacketTypeProbe:
            header.queryResponse = DNS_QR_QUERY;
            header.authoritiveAnswer = DNS_AA_NON_AUTHORITATIVE;
            header.queryCount = htons(DNS_COUNT_SINGLE);
            header.authorityCount = htons(DNS_COUNT_A_RECORD + (_services.empty() ? 0 : (DNS_COUNT_DNS_SD_PTR + (_services.size() * DNS_COUNT_PER_SERVICE))));
            break;
        case PacketTypeNextSecure:
            header.queryResponse = DNS_QR_RESPONSE;
            header.authoritiveAnswer = DNS_AA_AUTHORITATIVE;
            header.answerCount = htons(DNS_COUNT_A_RECORD);
            header.additionalCount = htons(!service ? DNS_COUNT_A_RECORD : 0);    // A record as additional
            break;
    }

    UDP_WRITE_BEGIN();
    UDP_WRITE_DATA(reinterpret_cast<uint8_t*>(&header), sizeof(Header));

    switch (type) {

        case PacketTypeAddressRecord:
            DEBUG_PRINTF("MDNS: packet: sending Address record, ip=%s, name=%s\n", IPAddress(_addr).toString().c_str(), _fqhn.c_str());
            _writeAddressRecord(DNS_TTL_DEFAULT, DNS_CACHE_FLUSH);
            break;
        case PacketTypeAddressRelease:
            DEBUG_PRINTF("MDNS: packet: sending Address release, ip=%s, name=%s\n", IPAddress(_addr).toString().c_str(), _fqhn.c_str());
            _writeAddressRecord(DNS_TTL_ZERO, DNS_CACHE_FLUSH);
            break;
        case PacketTypeReverseRecord:
            DEBUG_PRINTF("MDNS: packet: sending Reverse record, ip=%s, name=%s\n", IPAddress(_addr).toString().c_str(), _fqhn.c_str());
            _writeReverseRecord(DNS_TTL_DEFAULT);
            break;

        case PacketTypeServiceRecord:
            assert(service != nullptr);
            DEBUG_PRINTF("MDNS: packet: sending Service record %s/%u/%s/%s/[%d]\n", toString(service->proto).c_str(), service->port, service->name.c_str(), service->serv.c_str(), service->text.size());
            _writeServiceRecord(*service, DNS_TTL_DEFAULT, true, true);    // include additional
            break;
        case PacketTypeServiceRelease:
            assert(service != nullptr);
            DEBUG_PRINTF("MDNS: packet: sending Service release %s/%u/%s/%s/[%d]\n", toString(service->proto).c_str(), service->port, service->name.c_str(), service->serv.c_str(), service->text.size());
            _writeServiceRecord(*service, DNS_TTL_ZERO, true);
            break;

        case PacketTypeCompleteRecord:
            DEBUG_PRINTF("MDNS: packet: sending Complete record, ip=%s, name=%s\n", IPAddress(_addr).toString().c_str(), _fqhn.c_str());
            _writeCompleteRecord(DNS_TTL_DEFAULT, DNS_CACHE_FLUSH);
            break;
        case PacketTypeCompleteRelease:
            DEBUG_PRINTF("MDNS: packet: sending Complete release, ip=%s, name=%s\n", IPAddress(_addr).toString().c_str(), _fqhn.c_str());
            _writeCompleteRecord(DNS_TTL_ZERO, DNS_CACHE_FLUSH);
            break;

        case PacketTypeProbe:
            DEBUG_PRINTF("MDNS: packet: sending Probe query, name=%s\n", _fqhn.c_str());
            _writeCompleteRecord(DNS_TTL_ZERO, DNS_CACHE_NO_FLUSH, true);
            break;

        case PacketTypeNextSecure:
            DEBUG_PRINTF("MDNS: packet: sending NextSecure for supported types\n");
            _writeNextSecureRecord(service ? service->fqsn : _fqhn, { DNS_RECORD_PTR, DNS_RECORD_SRV, service ? DNS_RECORD_TXT : DNS_RECORD_A }, DNS_TTL_DEFAULT, true, service ? true : false);
            break;
    }

    UDP_WRITE_END();

    return Success;
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

static inline void _encodeUint16(uint8_t* ptr, const uint16_t val) {
    *((uint16_t*)ptr) = htons(val);
}

static inline void _encodeUint32(uint8_t* ptr, const uint32_t val) {
    *((uint32_t*)ptr) = htonl(val);
}

static inline void _writeByte(UDP* _udp, const uint8_t byte) {
    UDP_WRITE_BYTE(byte);
}

static inline void _writeBits(UDP* _udp, const uint8_t byte1, const uint8_t byte2, const uint8_t byte3, const uint8_t byte4, const uint32_t ttl) {
    uint8_t buffer[8];
    buffer[0] = byte1;
    buffer[1] = byte2;
    buffer[2] = byte3;
    buffer[3] = byte4;
    _encodeUint32(&buffer[4], ttl);
    UDP_WRITE_DATA(buffer, 8);
}

static inline void _writeLength(UDP* _udp, const uint16_t length) {
    uint8_t buffer[2];
    _encodeUint16(buffer, length);
    UDP_WRITE_DATA(buffer, 2);
}

static inline void _writeStringLengthAndContent(UDP* _udp, const String& str, const size_t max) {
    const uint8_t size = static_cast<uint8_t>(std::min(str.length(), max));
    UDP_WRITE_BYTE(size);
    UDP_WRITE_DATA(reinterpret_cast<const uint8_t*>(str.c_str()), size);
}

static inline void _writeDNSName(UDP* _udp, const String& name) {
    const size_t len = name.length();
    if (!len)
        UDP_WRITE_BYTE(static_cast<uint8_t>(0));
    else {
        uint8_t buffer[len + 2];    // stack usage up to ~64 bytes
        size_t write_pos = 1, length_pos = 0;
        for (size_t i = 0; i < len; i++) {
            const char c = name[i];
            if (c == '.' || i == len - 1) {
                buffer[length_pos] = static_cast<uint8_t>(write_pos - (length_pos + 1));
                length_pos = write_pos++;
            } else
                buffer[write_pos++] = c;
        }
        buffer[write_pos] = 0;    // null terminator
        UDP_WRITE_DATA(buffer, write_pos + 1);
    }
}

struct DNSBitmap {
    uint8_t data[2 + NSEC_BITMAP_LEN] = { 0 };
    inline size_t size() const {
        return static_cast<size_t>(data[1]);
    }
    DNSBitmap(const std::initializer_list<uint8_t>& types = {}) {
        data[0] = NSEC_WINDOW_BLOCK_0;
        data[1] = 2;
        for (const auto& type : types)
            addType(type);
    }
    DNSBitmap& addType(const uint8_t type) {
        for (const auto& rt : SupportedRecordTypes)
            if (rt.type == type) {
                const uint8_t offs = 2 + rt.byte;
                data[offs] |= rt.mask;
                if (data[1] < (offs + 1)) data[1] = (offs + 1);
            }
        return *this;
    }
};
static inline void _writeBitmap(UDP* _udp, const DNSBitmap& bitmap) {
    UDP_WRITE_DATA(bitmap.data, bitmap.size());
}

static inline void _writeNameLengthAndContent(UDP* _udp, const String& name) {
    _writeLength(_udp, name.length() + 2);
    _writeDNSName(_udp, name);
}

static inline void _writeAddressLengthAndContent(UDP* _udp, const IPAddress& address) {
    uint8_t buffer[4] = { address[0], address[1], address[2], address[3] };
    _writeLength(_udp, 4);
    UDP_WRITE_DATA(buffer, 4);
}

static inline void _writeSRVDetails(UDP* _udp, const uint16_t priority, const uint16_t weight, const uint16_t port) {
    uint8_t buffer[6];
    _encodeUint16(&buffer[0], priority);
    _encodeUint16(&buffer[2], weight);
    _encodeUint16(&buffer[4], port);
    UDP_WRITE_DATA(buffer, 2 + 2 + 2);
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

void MDNS::_writeAddressRecord(const uint32_t ttl, const bool cacheFlush, const bool anyType) const {

    // 1. Write our name + address
    _writeDNSName(_udp, _fqhn);
    _writeBits(_udp, DNS_RECORD_HI, anyType ? DNS_RECORD_ANY : DNS_RECORD_A, cacheFlush ? DNS_CACHE_FLUSH : DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, ttl);
    _writeAddressLengthAndContent(_udp, _addr);
}

// -----------------------------------------------------------------------------------------------

void MDNS::_writeReverseRecord(const uint32_t ttl) const {

    // 1. Write our reverse name + fq name
    _writeDNSName(_udp, _arpa);
    _writeBits(_udp, DNS_RECORD_HI, DNS_RECORD_PTR, DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, std::min(ttl, DNS_TTL_SHARED_MAX));
    _writeNameLengthAndContent(_udp, _fqhn);

    // 2. and our A record
    _writeAddressRecord(ttl, true);
}

// -----------------------------------------------------------------------------------------------

void MDNS::_writeServiceRecord(const Service& service, const uint32_t ttl, const bool cacheFlush, const bool includeAdditional) const {

    // 1. Write SRV Record for service instance
    _writeDNSName(_udp, service.fqsn);
    _writeBits(_udp, DNS_RECORD_HI, DNS_RECORD_SRV, cacheFlush ? DNS_CACHE_FLUSH : DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, ttl);
    _writeLength(_udp, 2 + 2 + 2 + _sizeofDNSName(_fqhn));
    _writeSRVDetails(_udp, DNS_SRV_PRIORITY_DEFAULT, DNS_SRV_WEIGHT_DEFAULT, service.port);
    _writeDNSName(_udp, _fqhn);

    // 2. Write TXT Record for service instance
    _writeDNSName(_udp, service.fqsn);
    _writeBits(_udp, DNS_RECORD_HI, DNS_RECORD_TXT, cacheFlush ? DNS_CACHE_FLUSH : DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, ttl);
    _writeLength(_udp, service._cachedTextLength);
    if (service.text.empty())
        _writeByte(_udp, static_cast<uint8_t>(DNS_TXT_EMPTY_CONTENT));
    else
        for (const auto& txt : service.text)
            _writeStringLengthAndContent(_udp, txt, DNS_TXT_LENGTH_MAX);

    // 3. Write PTR Record for service instance
    _writeDNSName(_udp, service.serv);
    _writeBits(_udp, DNS_RECORD_HI, DNS_RECORD_PTR, DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, std::min(ttl, DNS_TTL_SHARED_MAX));
    _writeNameLengthAndContent(_udp, service.fqsn);

    if (includeAdditional) {

        // 4. Write single DNS-SD PTR record that points to us
        _writeDNSName(_udp, SERVICE_SD_FQSN);
        _writeBits(_udp, DNS_RECORD_HI, DNS_RECORD_PTR, DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, std::min(ttl, DNS_TTL_SHARED_MAX));
        _writeNameLengthAndContent(_udp, _fqhn);

        // 5. Write our IP address
        _writeAddressRecord(ttl, cacheFlush);
    }
}

// -----------------------------------------------------------------------------------------------

void MDNS::_writeCompleteRecord(const uint32_t ttl, const bool cacheFlush, const bool anyType) const {

    // 1. Write A record for our hostname
    _writeAddressRecord(ttl, cacheFlush, anyType);

    if (!_services.empty()) {

        // 2. Write single DNS-SD PTR record that points to our services
        _writeDNSName(_udp, SERVICE_SD_FQSN);
        _writeBits(_udp, DNS_RECORD_HI, DNS_RECORD_PTR, DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, std::min(ttl, DNS_TTL_SHARED_MAX));
        _writeNameLengthAndContent(_udp, _fqhn);

        // 3-N Write individual service records
        for (const auto& service : _services)
            _writeServiceRecord(service, ttl, cacheFlush);
    }
}

// -----------------------------------------------------------------------------------------------

void MDNS::_writeNextSecureRecord(const String& name, const std::initializer_list<uint8_t>& types, const uint32_t ttl, const bool cacheFlush, const bool includeAdditional) const {

    // if not a service, still have an SRV for DNS-SD
    DNSBitmap bitmap(types);

    // 1. Write NextSecure with bitmap
    _writeDNSName(_udp, name);
    _writeBits(_udp, DNS_RECORD_HI, DNS_RECORD_NSEC, cacheFlush ? DNS_CACHE_FLUSH : DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, ttl);
    _writeLength(_udp, _sizeofDNSName(name) + bitmap.size());    // name + bitmap (2+x)
    _writeDNSName(_udp, name);
    _writeBitmap(_udp, bitmap);

    if (includeAdditional) {

        // 2. Write our address as additional if not for a service
        _writeAddressRecord(DNS_TTL_DEFAULT);
    }
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------
