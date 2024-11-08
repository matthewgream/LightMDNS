
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
String getMacAddressBase(void) {
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

String join(const std::vector<String>& elements, const String& delimiter) {
    return elements.empty() ? String() : std::accumulate(std::next(elements.begin()), elements.end(), elements[0], [&delimiter](const String& a, const String& b) {
        return a + delimiter + b;
    });
}

void dump(const char* label, const uint8_t* data, size_t len) {
    DEBUG_PRINTF("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        DEBUG_PRINTF("%02X ", data[i]);
        if ((i + 1) % 16 == 0) DEBUG_PRINTF("\n    ");
    }
    DEBUG_PRINTF("\n");
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
    PacketTypeNSEC,               // NSEC record (indicate no other records exist)
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

static constexpr uint8_t DNS_RECORD_HI = 0x00;      // High byte of record type (always 0 for our types)
static constexpr uint8_t DNS_RECORD_A = 0x01;       // IPv4 host address record
static constexpr uint8_t DNS_RECORD_PTR = 0x0c;     // Domain name pointer (reverse DNS)
static constexpr uint8_t DNS_RECORD_TXT = 0x10;     // Text record for additional data
static constexpr uint8_t DNS_RECORD_AAAA = 0x1c;    // IPv6 host address record
static constexpr uint8_t DNS_RECORD_SRV = 0x21;     // Service location record
static constexpr uint8_t DNS_RECORD_NSEC = 0x2F;    // Next Secure record (proves nonexistence)
static constexpr uint8_t DNS_RECORD_ANY = 255;      // Any type

static constexpr uint8_t DNS_CACHE_FLUSH = 0x80;       // Flag to tell others to flush cached entries
static constexpr uint8_t DNS_CACHE_NO_FLUSH = 0x00;    // Normal caching behavior

static constexpr uint8_t DNS_CLASS_IN = 0x01;    // Internet class

static constexpr uint32_t DNS_SRV_PRIORITY_DEFAULT = 0x00;    // Default SRV priority
static constexpr uint32_t DNS_SRV_WEIGHT_DEFAULT = 0x00;      // Default SRV weight

static constexpr uint8_t DNS_COMPRESS_MARK = 0xC0;    // Marker for compressed names

// CONSTANTS

static constexpr size_t DNS_LABEL_LENGTH_MAX = 63;        // Maximum length of a DNS label section
static constexpr size_t DNS_SERVICE_LENGTH_MAX = 100;     // Maximum number of services
static constexpr size_t DNS_PACKET_LENGTH_MAX = 9000;     // Maximum size of DNS packet
static constexpr size_t DNS_PACKET_LENGTH_SAFE = 1410;    // Safe size of DNS packet

static constexpr size_t DNS_RECORD_HEADER_SIZE = 10;    // Type(2) + Class(2) + TTL(4) + Length(2)
static constexpr size_t DNS_SRV_DETAILS_SIZE = 6;       // Priority(2) + Weight(2) + Port(2)

static constexpr uint8_t DNS_TXT_LENGTH_MAX = 255;          // Maximum length of a single TXT record
static constexpr uint16_t DNS_TXT_EMPTY_LENGTH = 0x0001;    // Length for empty TXT
static constexpr uint8_t DNS_TXT_EMPTY_CONTENT = 0x00;      // Single null byte

static constexpr uint32_t DNS_TTL_DEFAULT = 120;
static constexpr uint32_t DNS_TTL_ZERO = 0;
static constexpr uint32_t DNS_TTL_SHARED_MAX = 10;    // per RFC

static constexpr uint32_t DNS_PROBE_WAIT_MS = 250;    // Wait time between probes
static constexpr int DNS_PROBE_COUNT = 3;             // Number of probes

static constexpr uint8_t NSEC_WINDOW_BLOCK_0 = 0x00;    // First window block (types 1-255)
static constexpr uint8_t NSEC_BITMAP_LEN = 0x06;        // Length needed to cover up to type 33 (SRV)

static constexpr uint16_t DNS_COUNT_SINGLE = 1;         // Used for single record responses
static constexpr uint16_t DNS_COUNT_SERVICE = 4;        // Used for service announcements (SRV+TXT+2×PTR)
static constexpr uint16_t DNS_COUNT_A_RECORD = 1;       // A record
static constexpr uint16_t DNS_COUNT_PER_SERVICE = 3;    // SRV + TXT + PTR per service
static constexpr uint16_t DNS_COUNT_DNS_SD_PTR = 1;     // DNS-SD PTR record

// -----------------------------------------------------------------------------------------------

String parseDNSType(const uint16_t type) {
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
                // Add hints for ranges
                if (type >= 0xFF00)
                    result += "/LocalUse";
                else if (type >= 0xFFF0)
                    result += "/Reserved";
                return result;
            }
    }
}

String parseDNSFlags(const uint8_t flagsByte) {
    if (flagsByte & 0x80) return "CACHE_FLUSH";
    return String();
}

String parseDNSClassOrEDNS(const uint8_t classByte1, const uint8_t classByte2, const uint16_t type) {
    if (type == 0x0029) {    // OPT record
        const uint16_t payloadSize = (static_cast<uint16_t>(classByte1) << 8) | classByte2;
        String result = "UDP_SIZE(" + String(payloadSize) + ")";
        if (payloadSize < 512)
            result += "/Small";
        else if (payloadSize > 1432)
            result += "/Large";
        return result;
    }

    // Regular DNS class (using just the second byte as before)
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

String parseHeader(const Header& h) {
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

String parseControl(const uint8_t ctrl[4]) {
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

static inline String makeReverseArpaName(const IPAddress& address) {
    return String(address[3]) + "." + String(address[2]) + "." + String(address[1]) + "." + String(address[0]) + ".in-addr.arpa";
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

enum class DNSSections {
    Query = 1 << 0,         // 0x01
    Answer = 1 << 1,        // 0x02
    Authority = 1 << 2,     // 0x04
    Additional = 1 << 3,    // 0x08
    All = Query | Answer | Authority | Additional
};
constexpr DNSSections operator|(DNSSections a, DNSSections b) {
    return static_cast<DNSSections>(static_cast<int>(a) | static_cast<int>(b));
}
constexpr DNSSections operator&(DNSSections a, DNSSections b) {
    return static_cast<DNSSections>(static_cast<int>(a) & static_cast<int>(b));
}


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


DNSSections getSection(size_t i, size_t qd, size_t an, size_t ns) {
    if (i < qd) return DNSSections::Query;
    if (i < an) return DNSSections::Answer;
    if (i < ns) return DNSSections::Authority;
    return DNSSections::Additional;
}

const char* getSectionName(DNSSections section) {
    switch (section) {
        case DNSSections::Query: return "query";
        case DNSSections::Answer: return "answer";
        case DNSSections::Authority: return "authority";
        default: return "additional";
    }
}

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

    bool process(void) {

        _handler.begin();

        const size_t qd = _header.queryCount, an = qd + _header.answerCount, ns = an + _header.authorityCount, ad = ns + _header.additionalCount;

        for (size_t i = 0; i < ad; i++) {

            const DNSSections section = getSection(i, qd, an, ns);

            DEBUG_PRINTF("MDNS: packet: %s[%d/%u]: ", getSectionName(section), i + 1, ad);

            const uint16_t start = UDP_READ_OFFSET();
            uint8_t rLen = 0;
            do {
                UDP_READ_BYTE_OR_FAIL(uint8_t, rLen, break);
                if ((rLen & DNS_COMPRESS_MARK) == DNS_COMPRESS_MARK) {
                    uint8_t xLen;
                    UDP_READ_BYTE_OR_FAIL(uint8_t, xLen, return false);
                    const uint16_t offs = ((static_cast<uint16_t>(rLen) & ~DNS_COMPRESS_MARK) << 8) | static_cast<uint16_t>(xLen);    // in practice, same as xLen

                    _handler.process_iscompressed(offs, section);

                } else if (rLen > 0) {
                    String name;
                    name.reserve(rLen + 1);
                    for (auto z = 0; z < rLen; z++) {
                        char c;
                        UDP_READ_BYTE_OR_FAIL(char, c, return false);
                        name += c;
                    }

                    _handler.process_nocompressed(name, section);
                }
            } while (rLen > 0 && rLen <= DNS_LABEL_LENGTH_MAX);

            uint8_t ctrl[4];
            for (auto z = 0; z < 4; z++)
                UDP_READ_BYTE_OR_FAIL(uint8_t, ctrl[z], return false);

            if (section != DNSSections::Query) {
                for (auto i = 0; i < 4; i++)    // ttl
                    UDP_SKIP_BYTE_OR_FAIL(return false);
                uint8_t b1, b2;
                UDP_READ_BYTE_OR_FAIL(uint8_t, b1, return false);
                UDP_READ_BYTE_OR_FAIL(uint8_t, b2, return false);
                uint16_t rdlength = (static_cast<uint16_t>(b1) << 8) | static_cast<uint16_t>(b2);
                for (uint16_t j = 0; j < rdlength; j++)
                    UDP_SKIP_BYTE_OR_FAIL(return false);

                //////////////////////////////////
                // if (((ctrl[0] << 8) | ctrl[1]) == 0x0010) {    // TXT record
                //     DEBUG_PRINTF("(TXT:%d) ", rdlength);
                //     if (rdlength == 0) {
                //         DEBUG_PRINTF("(empty) ");
                //     } else {
                //         // Process TXT content
                //     }
                // }
                // if (((ctrl[0] << 8) | ctrl[1]) == 0x001C) {    // AAAA record
                //     if (rdlength != 16) {
                //         DEBUG_PRINTF("Invalid AAAA length: %d\n", rdlength);
                //         return false;
                //     }
                //     uint8_t ipv6[16];
                //     for (int i = 0; i < 16; i++)
                //         UDP_READ_BYTE_OR_FAIL(uint8_t, ipv6[i], return false);
                //     DEBUG_PRINTF ("(IP6:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x)",
                //              ipv6[0], ipv6[1], ipv6[2], ipv6[3], ipv6[4], ipv6[5], ipv6[6], ipv6[7],
                //              ipv6[8], ipv6[9], ipv6[10], ipv6[11], ipv6[12], ipv6[13], ipv6[14], ipv6[15]);
                // }
                //////////////////////////////////
            }

            _handler.update(section, ctrl, start, UDP_READ_OFFSET());
        }

        _handler.end();

        return true;
    }
};

#define UDP_WRITE_BEGIN() _udp->beginPacket(MDNS_ADDR_MULTICAST, MDNS_PORT)
#define UDP_WRITE_END() _udp->endPacket()
#define UDP_WRITE_BYTE(x) _udp->write(x)
#define UDP_WRITE_DATA(x, y) _udp->write(x, y)

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

MDNS::MDNS(UDP& udp)
    : _udp(&udp), _active(false), _announceLast(0) {
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

MDNS::Status MDNS::start(const IPAddress& ip, const String& name, const bool checkForConflicts) {

    _addr = ip;
    _name = name.isEmpty() ? getMacAddressBase() : name;
    _fqhn = name + TLD;
    _arpa = makeReverseArpaName(_addr);

    if (!_sizeofDNSName(_name)) {
        DEBUG_PRINTF("MDNS: start: failed, invalid name %s\n", _name.c_str());
        return InvalidArgument;
    }

    Status status = Success;
    if (!_active) {
        if (!UDP_READ_START())
            status = Failure;
        else _active = true;
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

    if (_active) {
        DEBUG_PRINTF("MDNS: stop\n");
        // XXX: should send multiple messages 2 seconds apart
        _messageSend(XID_DEFAULT, PacketTypeCompleteRelease);
        UDP_READ_STOP();
        _active = false;
    }

    return Success;
}

MDNS::Status MDNS::process(void) {

    Status status = Success;
    if (_active) {
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

MDNS::Status MDNS::serviceRecordInsert(const ServiceProtocol proto, const uint16_t port, const String& name, const ServiceTextRecords& textRecords) {

    DEBUG_PRINTF("MDNS: serviceRecordInsert: proto=%s, port=%u, name=%s, textRecords.size=%d,text=[%s]\n", toString(proto).c_str(), port, name.c_str(), textRecords.size(), join(textRecords, ",").c_str());

    if (name.isEmpty() || port == 0 || (proto != ServiceTCP && proto != ServiceUDP))
        return InvalidArgument;
    if (_serviceRecords.size() >= DNS_SERVICE_LENGTH_MAX)
        return InvalidArgument;
    if (!_sizeofDNSName(name))
        return InvalidArgument;

    ServiceRecord recordNew{ .port = port, .proto = proto, .name = name, .serv = name.substring(name.lastIndexOf('.') + 1) + String(protocolPostfix(proto)), .textRecords = textRecords };

    size_t size = sizeof(Header) + _sizeofDNSName(_fqhn) + 8 + 6;        // PTR record for our IP address
    size += _sizeofDNSName(SERVICE_SD_FQSN) + DNS_RECORD_HEADER_SIZE;    // DNS-SD
    size += _serviceRecords.empty() ? 0 : std::accumulate(_serviceRecords.begin(), _serviceRecords.end(), static_cast<size_t>(0), [this](const size_t size, const ServiceRecord& record) {
        return size + _sizeofServiceRecord(&record);
    });
    size += _sizeofServiceRecord(&recordNew);
    if (size > DNS_PACKET_LENGTH_SAFE)    // DNS_PACKET_LENGTH_MAX ... or we will need truncation support
        return OutOfMemory;

    try {
        const auto& record = _serviceRecords.emplace_back(recordNew);
        if (_active)
            _messageSend(XID_DEFAULT, PacketTypeServiceRecord, &record);
        return Success;
    } catch (const std::bad_alloc&) {
        return OutOfMemory;
    }
}

MDNS::Status MDNS::serviceRecordRemove(const ServiceProtocol proto, const uint16_t port, const String& name) {

    DEBUG_PRINTF("MDNS: serviceRecordRemove: proto=%s, port=%u, name=%s\n", toString(proto).c_str(), port, name.c_str());

    std::erase_if(_serviceRecords, [&](const ServiceRecord& record) {
        if (!(record.port == port && record.proto == proto && (name.isEmpty() || record.name == name)))
            return false;
        if (_active)
            _messageSend(XID_DEFAULT, PacketTypeServiceRelease, &record);
        return true;
    });

    return Success;
}

MDNS::Status MDNS::serviceRecordClear() {

    DEBUG_PRINTF("MDNS: serviceRecordClear\n");

    if (_active)
        for (const auto& record : _serviceRecords)
            _messageSend(XID_DEFAULT, PacketTypeServiceRelease, &record);
    _serviceRecords.clear();

    return Success;
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

MDNS::Status MDNS::_announce() {

    if (_active && (millis() - _announceLast) > ((DNS_TTL_DEFAULT / 2) + (DNS_TTL_DEFAULT / 4)) * static_cast<uint32_t>(1000)) {

        DEBUG_PRINTF("MDNS: announce: services (%d)\n", _serviceRecords.size());

        _messageSend(XID_DEFAULT, PacketTypeCompleteRecord);

        _announceLast = millis();
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

const char* _checkHeader(const Header& header, const uint16_t packet_size, const int firstByte) {
    if (packet_size < (sizeof(Header) + (header.queryCount * 6) + (header.authorityCount * 6)))
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
    if (header.truncated && packet_size < 512)
        return "suspicious: TC set but packet small";
    return nullptr;
}
const char* _checkAddress(const IPAddress& addr_local, const IPAddress& addr) {
    if (addr[0] == 0 && (addr[1] | addr[2] | addr[3]) == 0)
        return "invalid unspecified address (0.0.0.0)";
    if (addr[0] == 127)
        return "invalid loopback address (127.x.x.x)";
    if (addr[0] == 169 && addr[1] == 254) {    // link-local
        if (addr[2] == 0 || addr[2] == 255)
            return "invalid link-local broadcast (169.254.0|255.x)";
        if (!(addr_local[0] == 169 && addr_local[1] == 254 && addr[2] == addr_local[2]))
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

    /////////////////////////////////////////////

    struct NameCollector {
        MDNS& _mdns;
        const Header& _header;
        //
        using Label = std::pair<bool, String>;
        using Labels = std::vector<Label>;
        Labels _labels;
        struct Name {
            DNSSections section;
            uint16_t offset;
            Labels labels;
        };
        using Names = std::vector<Name>;
        Names _names;
        //
        String _uncompress(const size_t offs) const {
            for (const auto& name : _names) {
                if (name.offset <= offs) {
                    size_t pos = name.offset;
                    for (const auto& [wasCompressed, label] : name.labels) {
                        if (pos == offs) {
                            return _name(Labels(
                                std::find_if(name.labels.begin(), name.labels.end(),
                                             [&](const auto& l) {
                                                 return l.second == label;
                                             }),
                                name.labels.end()));
                        }
                        pos += wasCompressed ? 2 : (1 + label.length());    // compression markers
                    }
                }
            }
            return String();
        }
        String _name(const Labels& labels) const {
            return std::accumulate(labels.begin(), labels.end(), String(),
                                   [](const String& acc, const Label& label) {
                                       return acc.isEmpty() ? label.second : acc + "." + label.second;
                                   });
        }
        //
        String name() const {    // current
            return _name(_labels);
        }
        std::vector<String> names(const DNSSections section = DNSSections::All) const {    // all (except current)
            std::vector<String> names;
            for (const auto& name : _names)
                if ((name.section & section) == name.section)
                    names.push_back(_name(name.labels));
            return names;
        }
        virtual void begin() {}
        virtual void end() {}
        void process_iscompressed(const uint16_t offs, const DNSSections) {
            _labels.push_back(Label(true, _uncompress(offs)));
        }
        void process_nocompressed(const String& label, const DNSSections) {
            _labels.push_back(Label(false, label));
        }
        virtual void update(const DNSSections section, const uint8_t ctrl[4], const uint16_t start, const uint16_t) {
            DEBUG_PRINTF("<%s> [%s] (%s)\n", name().c_str(), parseControl(ctrl).c_str(), getSectionName(section));
            _names.push_back({ .section = section, .offset = start, .labels = _labels });
            _labels.clear();
        }
        NameCollector(MDNS& mdns, const Header& header)
            : _mdns(mdns), _header(header){};
    };

    /////////////////////////////////////////////

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
            void process_iscompressed(uint16_t offs, const DNSSections section) {
                if (section != DNSSections::Query) return;
                DEBUG_PRINTF("(%04X)", offs);
                for (auto& m : recordsMatcherEach)
                    if (m.position && m.position != offs)
                        m.match = 0;
            };
            void process_nocompressed(const String& name, const DNSSections section) {
                if (section != DNSSections::Query) return;
                DEBUG_PRINTF("[%s]", name.c_str());
                for (auto& m : recordsMatcherEach)
                    if (!m.requested && m.match)
                        m.match &= __matchStringPart(&m.name, &m.length, reinterpret_cast<const uint8_t*>(name.c_str()), static_cast<int>(name.length()));
            };
            void update(const DNSSections section, const uint8_t ctrl[4], const uint16_t start, const uint16_t) {
                if (section != DNSSections::Query) return;
                DEBUG_PRINTF("[%s]\n", parseControl(ctrl).c_str());
                size_t r = 0;
                for (auto& m : recordsMatcherEach) {
                    if (!m.requested && m.match && !m.length) {
                        if (!m.position)
                            m.position = start;
                        if (ctrl[0] == DNS_RECORD_HI && (ctrl[2] == DNS_CACHE_NO_FLUSH || ctrl[2] == DNS_CACHE_FLUSH) && ctrl[3] == DNS_CLASS_IN) {
                            if (r == 0) {    // Query for our hostname
                                if (ctrl[1] == DNS_RECORD_A)
                                    m.requested = true;
                                else
                                    m.unsupported = true;
                            } else if (r == 1) {    // Query for our address
                                if (ctrl[1] == DNS_RECORD_PTR)
                                    m.requested = true;
                                else
                                    m.unsupported = true;
                            } else {    // Query for our service
                                if (ctrl[1] == DNS_RECORD_PTR || ctrl[1] == DNS_RECORD_TXT || ctrl[1] == DNS_RECORD_SRV)
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
                for (const auto& r : _mdns._serviceRecords)    // XXX should only include unique r.serv ...
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
                    _mdns._messageSend(_header.xid, PacketTypeNSEC);
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
                    for (const auto& r : _mdns._serviceRecords) {
                        const auto& m = recordsMatcherTop[mi + recordsLengthStatic];
                        if (m.requested) {
                            DEBUG_PRINTF("MDNS: packet: processing, matched[SERV:%d]: %s\n", mi, m.name);
                            _mdns._messageSend(_header.xid, PacketTypeServiceRecord, &r);
                        }
                        if (m.unsupported) {
                            DEBUG_PRINTF("MDNS: packet: processing, negated[SERV:%d]: %s\n", mi, m.name);
                            _mdns._messageSend(_header.xid, PacketTypeNSEC, &r);
                        }
                        mi++;
                    }
                }
            }
            Responder(MDNS& mdns, const Header& header)
                : _mdns(mdns), _header(header),
                  recordsLengthStatic(3), recordsLength(_mdns._serviceRecords.size() + recordsLengthStatic),
                  recordsMatcherTop(recordsLength), recordsMatcherEach(recordsLength){};
        } _responder(*this, header);

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

MDNS::Status
MDNS::_messageSend(const uint16_t xid, const int type, const ServiceRecord* serviceRecord) {

    Header header{};
    header.xid = htons(xid);
    header.opCode = DNS_OPCODE_QUERY;
    switch (type) {
        case PacketTypeCompleteRecord:
        case PacketTypeCompleteRelease:
            header.queryResponse = DNS_QR_RESPONSE;
            header.authoritiveAnswer = DNS_AA_AUTHORITATIVE;
            header.answerCount = htons(DNS_COUNT_A_RECORD + (_serviceRecords.empty() ? 0 : (DNS_COUNT_DNS_SD_PTR + (_serviceRecords.size() * DNS_COUNT_PER_SERVICE))));
            break;
        case PacketTypeProbe:
            header.queryResponse = DNS_QR_QUERY;
            header.authoritiveAnswer = DNS_AA_NON_AUTHORITATIVE;
            header.queryCount = htons(DNS_COUNT_SINGLE);
            header.authorityCount = htons(DNS_COUNT_A_RECORD + (_serviceRecords.empty() ? 0 : (DNS_COUNT_DNS_SD_PTR + (_serviceRecords.size() * DNS_COUNT_PER_SERVICE))));
            break;
        case PacketTypeReverseRecord:
        case PacketTypeAddressRecord:
        case PacketTypeAddressRelease:
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
        case PacketTypeNSEC:
            header.queryResponse = DNS_QR_RESPONSE;
            header.authoritiveAnswer = DNS_AA_AUTHORITATIVE;
            header.answerCount = htons(DNS_COUNT_A_RECORD);
            header.additionalCount = htons(!serviceRecord ? DNS_COUNT_A_RECORD : 0);    // A record as additional
            break;
    }

    UDP_WRITE_BEGIN();
    UDP_WRITE_DATA(reinterpret_cast<uint8_t*>(&header), sizeof(Header));

    switch (type) {

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

        case PacketTypeReverseRecord:
            DEBUG_PRINTF("MDNS: packet: sending Reverse record, ip=%s, name=%s\n", IPAddress(_addr).toString().c_str(), _fqhn.c_str());
            _writeReverseRecord(DNS_TTL_DEFAULT);
            break;
        case PacketTypeAddressRecord:
            DEBUG_PRINTF("MDNS: packet: sending Address record, ip=%s, name=%s\n", IPAddress(_addr).toString().c_str(), _fqhn.c_str());
            _writeAddressRecord(DNS_TTL_DEFAULT, DNS_CACHE_FLUSH);
            break;
        case PacketTypeAddressRelease:
            DEBUG_PRINTF("MDNS: packet: sending Address release, ip=%s, name=%s\n", IPAddress(_addr).toString().c_str(), _fqhn.c_str());
            _writeAddressRecord(DNS_TTL_ZERO, DNS_CACHE_FLUSH);
            break;

        case PacketTypeServiceRecord:
            assert(serviceRecord != nullptr);
            DEBUG_PRINTF("MDNS: packet: sending Service record %s/%u/%s/%s/[%d]\n", toString(serviceRecord->proto).c_str(), serviceRecord->port, serviceRecord->name.c_str(), serviceRecord->serv.c_str(), serviceRecord->textRecords.size());
            _writeServiceRecord(serviceRecord, DNS_TTL_DEFAULT, true, true);    // include additional
            break;
        case PacketTypeServiceRelease:
            assert(serviceRecord != nullptr);
            DEBUG_PRINTF("MDNS: packet: sending Service release %s/%u/%s/%s/[%d]\n", toString(serviceRecord->proto).c_str(), serviceRecord->port, serviceRecord->name.c_str(), serviceRecord->serv.c_str(), serviceRecord->textRecords.size());
            _writeServiceRecord(serviceRecord, DNS_TTL_ZERO, true);
            break;

        case PacketTypeNSEC:
            DEBUG_PRINTF("MDNS: packet: sending NSEC for supported types\n");
            _writeNSECRecord(serviceRecord, DNS_TTL_DEFAULT, true);
            break;
    }

    UDP_WRITE_END();

    return Success;
}

// -----------------------------------------------------------------------------------------------

inline void _writeUint16(uint8_t* ptr, const uint16_t val) {
    *((uint16_t*)ptr) = htons(val);
}

inline void _writeUint32(uint8_t* ptr, const uint32_t val) {
    *((uint32_t*)ptr) = htonl(val);
}

void MDNS::_writeBits(const uint8_t byte1, const uint8_t byte2, const uint8_t byte3, const uint8_t byte4, const uint32_t ttl) const {
    uint8_t buffer[8];
    buffer[0] = byte1;
    buffer[1] = byte2;
    buffer[2] = byte3;
    buffer[3] = byte4;
    _writeUint32(&buffer[4], ttl);
    UDP_WRITE_DATA(buffer, 8);
}

void MDNS::_writeLength(const uint16_t length) const {
    uint8_t buffer[2];
    _writeUint16(buffer, length);
    UDP_WRITE_DATA(buffer, 2);
}

struct DNSBitmap {
    uint8_t _data[2 + NSEC_BITMAP_LEN] = { 0 };
    const uint8_t* data() const {
        return _data;
    }
    size_t size() const {
        return static_cast<size_t>(_data[1]);
    }
    DNSBitmap(std::initializer_list<uint8_t> types = {}) {
        _data[0] = NSEC_WINDOW_BLOCK_0;
        _data[1] = 2;
        for (const auto& type : types)
            addType(type);
    }
    DNSBitmap& addType(const uint8_t type) {
        for (const auto& rt : SupportedRecordTypes)
            if (rt.type == type) {
                const uint8_t offs = 2 + rt.byte;
                _data[offs] |= rt.mask;
                if (_data[1] < (offs + 1)) _data[1] = (offs + 1);
            }
        return *this;
    }
};

void MDNS::_writeNameLengthAndContent(const String& name) const {
    _writeLength(_sizeofDNSName(name));
    _writeDNSName(name);
}

void MDNS::_writeAddressLengthAndContent(const IPAddress& address) const {
    _writeLength(4);
    uint8_t buffer[4];
    buffer[0] = address[0];
    buffer[1] = address[1];
    buffer[2] = address[2];
    buffer[3] = address[3];
    UDP_WRITE_DATA(buffer, 4);
}

// -----------------------------------------------------------------------------------------------

void MDNS::_writeNSECRecord(const ServiceRecord* serviceRecord, const uint32_t ttl, const bool cacheFlush) const {

    // if not a service, still have an SRV for DNS-SD
    DNSBitmap bitmap({ DNS_RECORD_PTR, DNS_RECORD_SRV, serviceRecord ? DNS_RECORD_TXT : DNS_RECORD_A });

    // Write NSEC with bitmap -- for a service, this probably correct to use the FQSN and not just the plain name
    const String& name = serviceRecord ? serviceRecord->name : _fqhn;
    _writeDNSName(name);
    _writeBits(DNS_RECORD_HI, DNS_RECORD_NSEC, cacheFlush ? DNS_CACHE_FLUSH : DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, ttl);
    _writeLength(_sizeofDNSName(name) + bitmap.size());    // name + bitmap (2+x)
    _writeDNSName(name);
    UDP_WRITE_DATA(bitmap.data(), bitmap.size());

    // Write our address as additional if not for a service
    if (!serviceRecord)
        _writeAddressRecord(DNS_TTL_DEFAULT);
}

// -----------------------------------------------------------------------------------------------

void MDNS::_writeCompleteRecord(const uint32_t ttl, const bool cacheFlush, const bool anyType) const {

    // 1. Write A record for our hostname
    _writeAddressRecord(ttl, cacheFlush, anyType);

    if (!_serviceRecords.empty()) {

        // 2. Write single DNS-SD PTR record that points to our services
        _writeDNSName(SERVICE_SD_FQSN);
        _writeBits(DNS_RECORD_HI, DNS_RECORD_PTR, DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, std::min(ttl, DNS_TTL_SHARED_MAX));
        _writeNameLengthAndContent(_fqhn);

        // 3. Write individual service records
        for (const auto& r : _serviceRecords)
            _writeServiceRecord(&r, ttl, cacheFlush);
    }
}

// -----------------------------------------------------------------------------------------------

void MDNS::_writeReverseRecord(const uint32_t ttl) const {

    // Write our reverse name + fq name
    _writeDNSName(_arpa);
    _writeBits(DNS_RECORD_HI, DNS_RECORD_PTR, DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, std::min(ttl, DNS_TTL_SHARED_MAX));
    _writeNameLengthAndContent(_fqhn);

    // and our A record
    _writeAddressRecord(ttl, true);
}

void MDNS::_writeAddressRecord(const uint32_t ttl, const bool cacheFlush, const bool anyType) const {

    // Write our name + address
    _writeDNSName(_fqhn);
    _writeBits(DNS_RECORD_HI, anyType ? DNS_RECORD_ANY : DNS_RECORD_A, cacheFlush ? DNS_CACHE_FLUSH : DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, ttl);
    _writeAddressLengthAndContent(_addr);
}

// -----------------------------------------------------------------------------------------------

void MDNS::_writeServiceRecord(const ServiceRecord* serviceRecord, const uint32_t ttl, const bool cacheFlush, const bool includeAdditional) const {

    // 1. Write SRV Record for service instance
    _writeDNSName(serviceRecord->name);
    _writeBits(DNS_RECORD_HI, DNS_RECORD_SRV, cacheFlush ? DNS_CACHE_FLUSH : DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, ttl);
    _writeLength(4 + 2 + _sizeofDNSName(_fqhn));
    //
    uint8_t buffer[6];
    _writeUint16(&buffer[0], DNS_SRV_PRIORITY_DEFAULT);
    _writeUint16(&buffer[2], DNS_SRV_WEIGHT_DEFAULT);
    _writeUint16(&buffer[4], serviceRecord->port);
    UDP_WRITE_DATA(buffer, 4 + 2);
    _writeDNSName(_fqhn);

    // 2. Write TXT Record for service instance
    _writeDNSName(serviceRecord->name);
    _writeBits(DNS_RECORD_HI, DNS_RECORD_TXT, cacheFlush ? DNS_CACHE_FLUSH : DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, ttl);
    //
    if (serviceRecord->textRecords.empty()) {
        _writeLength(DNS_TXT_EMPTY_LENGTH);
        UDP_WRITE_BYTE(static_cast<uint8_t>(DNS_TXT_EMPTY_CONTENT));
    } else {
        const auto length = std::accumulate(serviceRecord->textRecords.begin(), serviceRecord->textRecords.end(), static_cast<uint16_t>(0), [](const uint16_t size, const auto& txt) {
            return size + (1 + std::min(txt.length(), static_cast<size_t>(DNS_TXT_LENGTH_MAX)));
        });
        _writeLength(length);
        for (const auto& txt : serviceRecord->textRecords) {
            uint8_t size = static_cast<uint8_t>(std::min(txt.length(), static_cast<size_t>(DNS_TXT_LENGTH_MAX)));
            UDP_WRITE_BYTE(size);
            UDP_WRITE_DATA(reinterpret_cast<const uint8_t*>(txt.c_str()), size);
        }
    }

    // 3. Write PTR Record for service instance
    _writeDNSName(serviceRecord->serv);
    _writeBits(DNS_RECORD_HI, DNS_RECORD_PTR, DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, std::min(ttl, DNS_TTL_SHARED_MAX));
    _writeNameLengthAndContent(serviceRecord->name);

    if (includeAdditional) {

        // 4. Write single DNS-SD PTR record that points to us
        _writeDNSName(SERVICE_SD_FQSN);
        _writeBits(DNS_RECORD_HI, DNS_RECORD_PTR, DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, std::min(ttl, DNS_TTL_SHARED_MAX));
        _writeNameLengthAndContent(_fqhn);

        // 5. Write our IP address
        _writeAddressRecord(ttl, cacheFlush);
    }
}

size_t MDNS::_sizeofServiceRecord(const ServiceRecord* record, const bool includeAdditional) const {
    size_t size = 0;
    // SRV record size:
    size += _sizeofDNSName(record->name) + DNS_RECORD_HEADER_SIZE + DNS_SRV_DETAILS_SIZE + _sizeofDNSName(_fqhn);
    // TXT record size:
    size += _sizeofDNSName(record->name) + DNS_RECORD_HEADER_SIZE;
    size += record->textRecords.empty() ? DNS_TXT_EMPTY_LENGTH : std::accumulate(record->textRecords.begin(), record->textRecords.end(), static_cast<uint16_t>(0), [](const uint16_t size, const auto& txt) {
        return size + (1 + std::min(txt.length(), static_cast<size_t>(DNS_TXT_LENGTH_MAX)));
    });
    // PTR record size:
    size += _sizeofDNSName(record->serv) + DNS_RECORD_HEADER_SIZE + _sizeofDNSName(record->name);
    // Additional size
    if (includeAdditional) {
        size += _sizeofDNSName(SERVICE_SD_FQSN) + DNS_RECORD_HEADER_SIZE + _sizeofDNSName(_fqhn);
        size += _sizeofDNSName(_fqhn) + DNS_RECORD_HEADER_SIZE + 4;
    }
    return size;
}

// -----------------------------------------------------------------------------------------------

void MDNS::_writeDNSName(const String& name) const {
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
size_t MDNS::_sizeofDNSName(const String& name) const {
    return name.length() + 2;    // string length + length byte + null terminator ('.'s just turn into byte lengths)
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------
