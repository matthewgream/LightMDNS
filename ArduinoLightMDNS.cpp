
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

/*

Known Answer Tracking:
    Maintains a fixed-size cache of known answers
    Records include name, type, TTL, and actual record data
    Automatically expires records based on TTL
    Compares full record data to ensure exact matches
Duplicate Question Suppression:
    Tracks recent questions with a 1-second window
    Uses fixed-size buffer to prevent memory growth
    Only suppresses exact matches (name + type)
    Auto-expires after 1 second per RFC

struct KnownAnswer {
    String name;
    uint16_t recordType;
    uint32_t ttl;
    uint64_t receivedAt;
    std::vector<uint8_t> rdata;  // Record-specific data

    bool isExpired(uint64_t now) const {
        return (now - receivedAt) >= ((uint64_t)ttl * 1000);
    }
};
struct RecentQuestion {
    String name;
    uint16_t recordType;
    uint64_t askedAt;

    bool isExpired(uint64_t now) const {
        return (now - askedAt) >= 1000; // 1 second suppression window
    }
};

static constexpr size_t MAX_KNOWN_ANSWERS = 32;
static constexpr size_t MAX_RECENT_QUESTIONS = 16;
std::vector<KnownAnswer> _knownAnswers;
std::vector<RecentQuestion> _recentQuestions;

private:
    void _cleanupExpiredRecords();
    bool _shouldSuppressAnswer(const String& name, uint16_t recordType, const uint8_t* rdata, size_t rdataLen);
    bool _shouldSuppressQuestion(const String& name, uint16_t recordType);
    void _recordKnownAnswer(const String& name, uint16_t recordType, uint32_t ttl, const uint8_t* rdata, size_t rdataLen);
    void _recordRecentQuestion(const String& name, uint16_t recordType);

void MDNS::_cleanupExpiredRecords() {
    auto now = millis();

    std::erase_if(_knownAnswers, [now](const KnownAnswer& ka) {
        return ka.isExpired(now);
    });
        std::erase_if(_recentQuestions, [now](const RecentQuestion& rq) {
        return rq.isExpired(now);
    });
}
bool MDNS::_shouldSuppressAnswer(const String& name, uint16_t recordType, const uint8_t* rdata, size_t rdataLen) {
    auto now = millis();
    for (const auto& ka : _knownAnswers)
        if (ka.name == name && ka.recordType == recordType && !ka.isExpired(now))
            if (ka.rdata.size() == rdataLen &&
                memcmp(ka.rdata.data(), rdata, rdataLen) == 0) {
                DEBUG_PRINTF("MDNS: suppressing known answer for %s\n", name.c_str());
                return true;
            }
    return false;
}
bool MDNS::_shouldSuppressQuestion(const String& name, uint16_t recordType) {
    auto now = millis();
    for (const auto& rq : _recentQuestions)
        if (rq.name == name && rq.recordType == recordType && !rq.isExpired(now)) {
            DEBUG_PRINTF("MDNS: suppressing duplicate question for %s\n", name.c_str());
            return true;
        }
    return false;
}
void MDNS::_recordKnownAnswer(const String& name, uint16_t recordType, uint32_t ttl, const uint8_t* rdata, size_t rdataLen) {
    if (_knownAnswers.size() >= MAX_KNOWN_ANSWERS)
        _knownAnswers.erase(_knownAnswers.begin());
    KnownAnswer ka;
    ka.name = name;
    ka.recordType = recordType;
    ka.ttl = ttl;
    ka.receivedAt = millis();
    ka.rdata.assign(rdata, rdata + rdataLen);
    _knownAnswers.push_back(std::move(ka));
}
void MDNS::_recordRecentQuestion(const String& name, uint16_t recordType) {
    if (_recentQuestions.size() >= MAX_RECENT_QUESTIONS)
        _recentQuestions.erase(_recentQuestions.begin());
    RecentQuestion rq;
    rq.name = name;
    rq.recordType = recordType;
    rq.askedAt = millis();
    _recentQuestions.push_back(std::move(rq));
}

// Modify _messageRecv() to handle Known Answers in responses
// ...

// Process Known Answer section
for (int i = 0; i < dnsHeader.answerCount; i++) {
    std::vector<String> labels;
    int rLen;

    // Read name
    do {
        if (offset >= udp_len) break;
        rLen = _udp->read();
        if (rLen < 0) break;
        offset++;

        if ((rLen & DNS_COMPRESS_MARK) == DNS_COMPRESS_MARK) {
            if (offset >= udp_len) goto bad_packet;
            int xLen = _udp->read();
            if (xLen < 0) goto bad_packet;
            offset++;
        } else if (rLen > 0) {
            String label;
            for (int z = 0; z < rLen; z++) {
                if (offset >= udp_len) goto bad_packet;
                int r = _udp->read();
                if (r < 0) goto bad_packet;
                offset++;
                label += (char)r;
            }
            labels.push_back(label);
        }
    } while (rLen > 0 && rLen <= DNS_LABEL_LENGTH_MAX);

    // Read record type, class, TTL, and length
    uint8_t recordData[10];
    for (int j = 0; j < 10; j++) {
        if (offset >= udp_len) goto bad_packet;
        int r = _udp->read();
        if (r < 0) goto bad_packet;
        offset++;
        recordData[j] = (uint8_t)r;
    }

    uint16_t recordType = (recordData[0] << 8) | recordData[1];
    uint32_t ttl = (recordData[4] << 24) | (recordData[5] << 16) | (recordData[6] << 8) | recordData[7];
    uint16_t rdataLen = (recordData[8] << 8) | recordData[9];

    // Read record data
    std::vector<uint8_t> rdata(rdataLen);
    for (int j = 0; j < rdataLen; j++) {
        if (offset >= udp_len) goto bad_packet;
        int r = _udp->read();
        if (r < 0) goto bad_packet;
        offset++;
        rdata[j] = (uint8_t)r;
    }

    String name = join(labels, ".");
    _recordKnownAnswer(name, recordType, ttl, rdata.data(), rdataLen);
}

// Before processing each query, add:
String queryName = join(names, ".");
if (_shouldSuppressQuestion(queryName, recordType)) {
    continue; // Skip this query
}
_recordRecentQuestion(queryName, recordType);

// In _messageSend(), before writing each record:
if (_shouldSuppressAnswer(recordName, recordType, rdataBuffer, rdataLen)) {
    continue; // Skip this response
}

Status MDNS::process(void) {
    auto status = Success;
    if (_active) {
        _cleanupExpiredRecords();  // Add this line
        ...
    }
    return status;
}

*/

/*

Probe Management:
    Proper priority-based probe deferral
    Correct timing for probe sequences
    Handles probe conflicts per RFC
    Clean integration with existing probe code

class ProbeManager {
private:
    static constexpr uint32_t PROBE_DEFER_TIME_MS = 1000;  // 1 second defer time
    static constexpr uint32_t PROBE_TIEBREAK_THRESHOLD_MS = 200;  // 200ms threshold

    MDNS& _mdns;
    uint32_t _probeStartTime;
    uint32_t _nextProbeTime;
    uint8_t _probeCount;
    bool _probing;

public:
    explicit ProbeManager(MDNS& mdns) :
        _mdns(mdns), _probeStartTime(0), _nextProbeTime(0),
        _probeCount(0), _probing(false) {}

    void startProbing();
    void stopProbing();
    bool handleIncomingProbe(const String& name, const IPAddress& remoteIP);
    bool isProbing() const { return _probing; }
    void processTimeouts();
};

// Add these as members to the MDNS class
private:
    ProbeManager _probeManager;

void ProbeManager::startProbing() {
    _probing = true;
    _probeCount = 0;
    _probeStartTime = millis();
    _nextProbeTime = _probeStartTime;
}

void ProbeManager::stopProbing() {
    _probing = false;
}

bool ProbeManager::handleIncomingProbe(const String& name, const IPAddress& remoteIP) {
    if (!_probing) return false;

    bool shouldDefer = remoteIP > _mdns._ipAddress;

    if (shouldDefer) {
        if (millis() - _probeStartTime < PROBE_TIEBREAK_THRESHOLD_MS)
            _probeCount = 0;
        _nextProbeTime = millis() + PROBE_DEFER_TIME_MS;
        DEBUG_PRINTF("MDNS: Probe deferred for %s due to %s\n",  name.c_str(), remoteIP.toString().c_str());
        return true;
    }

    return false;
}

void ProbeManager::processTimeouts() {
    if (!_probing) return;

    uint32_t now = millis();
    if (now >= _nextProbeTime) {
        if (_probeCount < DNS_PROBE_COUNT) {
            _mdns._messageSend(XID_DEFAULT, PacketTypeProbe);
            _probeCount++;
            _nextProbeTime = now + DNS_PROBE_WAIT_MS;
        } else {
            _probing = false;
            _mdns._messageSend(XID_DEFAULT, PacketTypeAddressRecord);
        }
    }
}

MDNS::MDNS(UDP& udp) :
    _udp(&udp), _active(false), _announceLast(0),
    _probeManager(*this) {
}

Status MDNS::start(const IPAddress& ip, const String& name, bool checkForConflicts) {
    _ipAddress = ip;
    _name = name + TLD;
    auto status = Success;
    if (!_active) {
        if (!_udp->beginMulticast(ADDRESS_MULTICAST, DNS_MDNS_PORT))
            status = Failure;
        else _active = true;
    }
    if (status == Success && checkForConflicts)
        _probeManager.startProbing();
    return status;
}

Status MDNS::process(void) {
    auto status = Success;
    if (_active) {
        _probeManager.processTimeouts();
        ...
    }
    return status;
}

// In _messageRecv():
// Add after parsing the header:
if (_probeManager.isProbing() && dnsHeader.authorityCount > 0) {
    if (_probeManager.handleIncomingProbe(join(names, "."), _udp->remoteIP()))
        return Success;  // Deferred our probe
}

*/

/*

Legacy Unicast Handling:
    Proper detection of unicast queries
    TTL adjustment for unicast responses
    Source-specific response routing
    RFC-compliant timing
Service Enumeration:
    Load-balanced responses
    Proper record ordering
    Additional record inclusion
    Efficient request tracking
Goodbye Handling:
    Reliable multi-packet goodbyes
    Proper service teardown
    Cache coherency maintenance
    Immediate goodbye processing

// Legacy Unicast Query Handler
class UnicastHandler {
private:
    MDNS& _mdns;
    static constexpr uint32_t UNICAST_TTL = 10;  // Shorter TTL for unicast responses

public:
    explicit UnicastHandler(MDNS& mdns) : _mdns(mdns) {}

    bool isUnicastQuery(const IPAddress& sourceIP, uint16_t sourcePort) const {
        return sourcePort != DNS_MDNS_PORT;
    }
    // Handle incoming unicast query
    void handleQuery(const String& name, uint16_t type, const IPAddress& sourceIP, uint16_t sourcePort);
    // Modify TTL for unicast responses
    uint32_t adjustTTL(uint32_t originalTTL) const {
        return std::min(originalTTL, UNICAST_TTL);
    }
};

// Service Enumeration Handler
class ServiceEnumerationHandler {
private:
    struct ServiceBrowseRequest {
        IPAddress requester;
        uint16_t port;
        uint64_t requestTime;
    };

    MDNS& _mdns;
    std::vector<ServiceBrowseRequest> _browseRequests;
    static constexpr uint32_t BROWSE_TIMEOUT_MS = 3000;

public:
    explicit ServiceEnumerationHandler(MDNS& mdns) : _mdns(mdns) {}

    void handleBrowseRequest(const IPAddress& source, uint16_t port);
    void sendServiceResponse(const ServiceRecord& service, bool immediate = false);
    void cleanup();

    // Load distribution helper
    bool shouldRespondNow(const IPAddress& source) const;
};

// Departure (Goodbye) Handler
class DepartureHandler {
private:
    struct PendingGoodbye {
        String name;
        uint16_t type;
        uint8_t remainingAttempts;
        uint64_t nextAttemptTime;
    };

    MDNS& _mdns;
    std::vector<PendingGoodbye> _pendingGoodbyes;
    static constexpr uint8_t GOODBYE_REPEAT_COUNT = 3;
    static constexpr uint32_t GOODBYE_INTERVAL_MS = 250;

public:
    explicit DepartureHandler(MDNS& mdns) : _mdns(mdns) {}

    void announceGoodbye(const String& name, uint16_t type);
    void announceServiceGoodbye(const ServiceRecord& service);
    void handleReceivedGoodbye(const String& name, uint16_t type);
    void process();
};

// Add to MDNS class private members:
private:
    UnicastHandler _unicastHandler;
    ServiceEnumerationHandler _serviceEnumHandler;
    DepartureHandler _departureHandler;

// Implementation in ArduinoLightMDNS.cpp:

void UnicastHandler::handleQuery(const String& name, uint16_t type, const IPAddress& sourceIP, uint16_t sourcePort) {
    DEBUG_PRINTF("MDNS: Unicast query from %s:%u for %s\n", sourceIP.toString().c_str(), sourcePort, name.c_str());

    if (type == DNS_RECORD_ANY || type == DNS_RECORD_A) {
        if (_mdns._name == name) {
            _mdns._responseScheduler.scheduleResponse(name, DNS_RECORD_A, true, sourceIP, sourcePort);
        }
    }
    for (const auto& service : _mdns._serviceRecords) {
        if (service.fqsn == name || service.name == name) {
            _mdns._responseScheduler.scheduleResponse(name, type, true, sourceIP, sourcePort);
        }
    }
}

void ServiceEnumerationHandler::handleBrowseRequest(
    const IPAddress& source, uint16_t port) {

    cleanup();  // Remove expired requests

    // Record this browse request
    _browseRequests.push_back({ source, port, millis() });

    // Determine if we should respond immediately or delay
    bool immediate = shouldRespondNow(source);

    // Send responses for all services
    for (const auto& service : _mdns._serviceRecords)
        sendServiceResponse(service, immediate);
}

void ServiceEnumerationHandler::sendServiceResponse(
    const ServiceRecord& service, bool immediate) {

    // Calculate response delay based on network load
    uint32_t delay = immediate ? 0 : random(20, 120);

    // Schedule responses in correct order:
    // 1. PTR record for service type
    _mdns._responseScheduler.scheduleResponse(service.fqsn, DNS_RECORD_PTR, false, IPAddress(), 0, delay);

    // 2. SRV record with slightly longer delay
    _mdns._responseScheduler.scheduleResponse(service.name, DNS_RECORD_SRV, false, IPAddress(), 0, delay + 1);

    // 3. TXT record
    _mdns._responseScheduler.scheduleResponse(service.name, DNS_RECORD_TXT, false, IPAddress(), 0, delay + 2);

    // 4. A record for host
    _mdns._responseScheduler.scheduleResponse(_mdns._name, DNS_RECORD_A, false, IPAddress(), 0, delay + 3);
}

bool ServiceEnumerationHandler::shouldRespondNow(
    const IPAddress& source) const {

    // Implement load distribution algorithm
    size_t knownResponders = 0;
    size_t ourPosition = 0;

    for (const auto& req : _browseRequests) {
        if (req.requester < source) knownResponders++;
        if (req.requester < _mdns._ipAddress) ourPosition++;
    }

    // Respond immediately if we're one of the first few responders
    return ourPosition <= (knownResponders / 4);
}

void ServiceEnumerationHandler::cleanup() {
    uint64_t now = millis();
    std::erase_if(_browseRequests, [now](const ServiceBrowseRequest& req) {
        return (now - req.requestTime) > BROWSE_TIMEOUT_MS;
    });
}

void DepartureHandler::announceGoodbye(const String& name, uint16_t type) {
    _pendingGoodbyes.push_back({ name, type, GOODBYE_REPEAT_COUNT, millis() });
}

void DepartureHandler::announceServiceGoodbye(const ServiceRecord& service) {
    // Announce goodbyes for all records associated with this service
    announceGoodbye(service.name, DNS_RECORD_SRV);
    announceGoodbye(service.name, DNS_RECORD_TXT);
    announceGoodbye(service.fqsn, DNS_RECORD_PTR);
}

void DepartureHandler::handleReceivedGoodbye(
    const String& name, uint16_t type) {

    DEBUG_PRINTF("MDNS: Received goodbye for %s\n", name.c_str());

    // Remove from cache immediately
    _mdns._cacheManager.handleCacheFlush(name, type);

    // Notify POOF manager
    _mdns._poofManager.recordExpired(name, type);
}

void DepartureHandler::process() {
    uint64_t now = millis();

    for (auto it = _pendingGoodbyes.begin();
         it != _pendingGoodbyes.end();) {

        if (now >= it->nextAttemptTime) {
            // Send goodbye packet (TTL=0)
            _mdns._messageSend(XID_DEFAULT, PacketTypeGoodbye,
                             it->name, it->type);

            if (--it->remainingAttempts > 0) {
                // Schedule next attempt
                it->nextAttemptTime = now + GOODBYE_INTERVAL_MS;
                ++it;
            } else {
                // All attempts completed
                it = _pendingGoodbyes.erase(it);
            }
        } else {
            ++it;
        }
    }
}

// Integration in main MDNS methods:

// In constructor:
MDNS::MDNS(UDP& udp) :
    _udp(&udp),
    _unicastHandler(*this),
    _serviceEnumHandler(*this),
    _departureHandler(*this),
    // ... rest of initialization
{}

// In _messageRecv():
if (_unicastHandler.isUnicastQuery(_udp->remoteIP(), _udp->remotePort())) {
    _unicastHandler.handleQuery(name, type,
                              _udp->remoteIP(),
                              _udp->remotePort());
    return Success;
}

// When processing PTR queries for "_services._dns-sd._udp.local":
if (name == SERVICE_SD_FQSN) {
    _serviceEnumHandler.handleBrowseRequest(_udp->remoteIP(),
                                          _udp->remotePort());
    return Success;
}

// In process():
Status MDNS::process(void) {
    auto status = Success;
    if (_active) {
        _departureHandler.process();
        _serviceEnumHandler.cleanup();
        // ... rest of process
    }
    return status;
}

// In stop():
Status MDNS::stop(void) {
    if (_active) {
        // Announce departure for all services
        for (const auto& service : _serviceRecords) {
            _departureHandler.announceServiceGoodbye(service);
        }
        // Announce departure for our hostname
        _departureHandler.announceGoodbye(_name, DNS_RECORD_A);

        // Wait for goodbyes to be sent
        unsigned long start = millis();
        while (millis() - start < 1000) {
            _departureHandler.process();
            delay(50);
        }

        _udp->stop();
        _active = false;
    }
    return Success;
}

*/

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

static constexpr size_t DNS_HEADER_LENGTH_MIN = 10;       // Minimum header size we need to process
static constexpr size_t DNS_LABEL_LENGTH_MAX = 63;        // Maximum length of a DNS label section
static constexpr size_t DNS_SERVICE_LENGTH_MAX = 100;     // Maximum number of services
static constexpr size_t DNS_PACKET_LENGTH_MAX = 9000;     // Maximum size of DNS packet
static constexpr size_t DNS_PACKET_LENGTH_SAFE = 1410;    // Safe size of DNS packet

static constexpr size_t DNS_RECORD_HEADER_SIZE = 10;    // Type(2) + Class(2) + TTL(4) + Length(2)
static constexpr size_t DNS_SRV_DETAILS_SIZE = 6;       // Priority(2) + Weight(2) + Port(2)

static constexpr uint8_t DNS_TXT_LENGTH_MAX = 255;          // Maximum length of a single TXT record
static constexpr uint16_t DNS_TXT_EMPTY_LENGTH = 0x0001;    // Length for empty TXT
static constexpr uint8_t DNS_TXT_EMPTY_CONTENT = 0x00;      // Single null byte

static constexpr uint16_t DNS_MDNS_PORT = 5353;

static constexpr uint32_t DNS_TTL_DEFAULT = 120;
static constexpr uint32_t DNS_TTL_ZERO = 0;
static constexpr uint32_t DNS_TTL_SHARED_MAX = 10;    // per RFC

static constexpr uint32_t DNS_PROBE_WAIT_MS = 250;    // Wait time between probes
static constexpr int DNS_PROBE_COUNT = 3;             // Number of probes

static constexpr uint8_t NSEC_WINDOW_BLOCK_0 = 0x00;    // First window block (types 1-255)
static constexpr uint8_t NSEC_BITMAP_LEN = 0x06;        // Length needed to cover up to type 33 (SRV)

static constexpr uint8_t DNS_MCAST_IP_0 = 224;
static constexpr uint8_t DNS_MCAST_IP_1 = 0;
static constexpr uint8_t DNS_MCAST_IP_2 = 0;
static constexpr uint8_t DNS_MCAST_IP_3 = 251;

static constexpr uint16_t DNS_COUNT_SINGLE = 1;         // Used for single record responses
static constexpr uint16_t DNS_COUNT_SERVICE = 4;        // Used for service announcements (SRV+TXT+2×PTR)
static constexpr uint16_t DNS_COUNT_A_RECORD = 1;       // A record
static constexpr uint16_t DNS_COUNT_PER_SERVICE = 3;    // SRV + TXT + PTR per service
static constexpr uint16_t DNS_COUNT_DNS_SD_PTR = 1;     // DNS-SD PTR record

// -----------------------------------------------------------------------------------------------

String parseDNSType(const uint8_t typeByte1, const uint8_t typeByte2) {
    switch ((typeByte1 << 8) | typeByte2) {
        case 0x0001: return "A";         // IPv4 host address
        case 0x0002: return "NS";        // Authoritative name server
        case 0x0005: return "CNAME";     // Canonical name for an alias
        case 0x0006: return "SOA";       // Start of authority record
        case 0x000C: return "PTR";       // Domain name pointer, used for reverse lookups
        case 0x000F: return "MX";        // Mail exchange record
        case 0x0010: return "TXT";       // Text strings (key-value pairs)
        case 0x0021: return "SRV";       // Service locator (port and host for services)
        case 0x001C: return "AAAA";      // IPv6 host address
        case 0x00FB: return "DNSKEY";    // Public key for DNSSEC
        case 0x00FC: return "RRSIG";     // Resource record digital signature
        case 0x00FF: return "ANY";       // Special type for queries, matches any record
        default: return "Unknown(" + String((typeByte1 << 8) | typeByte2, HEX) + ")";
    }
}

String parseDNSFlags(const uint8_t flagsByte) {
    if (flagsByte & 0x80) return "CACHE_FLUSH";
    return String();
}

String parseDNSClass(const uint8_t classByte) {
    switch (classByte) {
        case 0x01: return "IN";      // Internet
        case 0x02: return "CS";      // CSNET (Obsolete)
        case 0x03: return "CH";      // CHAOS
        case 0x04: return "HS";      // Hesiod
        case 0xFE: return "NONE";    // RFC 2136
        case 0xFF: return "ANY";     // QCLASS only (RFC 1035)
        default: return "Unknown(" + String(classByte, HEX) + ")";
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

// -----------------------------------------------------------------------------------------------

static const IPAddress ADDRESS_MULTICAST(DNS_MCAST_IP_0, DNS_MCAST_IP_1, DNS_MCAST_IP_2, DNS_MCAST_IP_3);

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

static constexpr bool isServiceRecord(const uint8_t type) {
    return type == DNS_RECORD_PTR || type == DNS_RECORD_TXT || type == DNS_RECORD_SRV;
}

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
    assert(sizeof(Header) > DNS_HEADER_LENGTH_MIN);    // due to use of Header as a buffer

    return Success;
}

MDNS::Status MDNS::start(const IPAddress& ip, const String& name, const bool checkForConflicts) {

    _ipAddress = ip;
    _name = name.isEmpty() ? getMacAddressBase() : name;
    _fqhn = name + TLD;
    _arpa = String(_ipAddress[3]) + "." + String(_ipAddress[2]) + "." + String(_ipAddress[1]) + "." + String(_ipAddress[0]) + ".in-addr.arpa";

    if (!_sizeofDNSName(_name)) {
        DEBUG_PRINTF("MDNS: start: failed, invalid name %s\n", _name.c_str());
        return InvalidArgument;
    }

    auto status = Success;
    if (!_active) {
        if (!_udp->beginMulticast(ADDRESS_MULTICAST, DNS_MDNS_PORT))
            status = Failure;
        else _active = true;
    }

    if (status != Success)
        DEBUG_PRINTF("MDNS: start: failed _udp->beginMulticast error=%s, not active\n", toString(status).c_str());
    else {
        DEBUG_PRINTF("MDNS: start: active ip=%s, name=%s\n", IPAddress(_ipAddress).toString().c_str(), _fqhn.c_str());
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
        _udp->stop();
        _active = false;
    }

    return Success;
}

MDNS::Status MDNS::process(void) {

    auto status = Success;
    if (_active) {
        auto count = 0;
        do {
            count++;
        } while ((status = _messageRecv()) == Success);

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

    ServiceRecord recordNew{ .port = port, .proto = proto, .name = name, .fqsn = name.substring(name.lastIndexOf('.') + 1) + String(protocolPostfix(proto)), .textRecords = textRecords };

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

    if (_active && (millis() - _announceLast) > (((uint32_t)DNS_TTL_DEFAULT / 2) + ((uint32_t)DNS_TTL_DEFAULT / 4)) * 1000UL) {

        DEBUG_PRINTF("MDNS: announce: services (%d)\n", _serviceRecords.size());

        _messageSend(XID_DEFAULT, PacketTypeCompleteRecord);

        _announceLast = millis();
    }
    return Success;
}

MDNS::Status MDNS::_conflicted() {

    DEBUG_PRINTF("MDNS: conflicted: name=%s (will stop and start with new name)\n", _name.c_str());

    stop();
    return start(_ipAddress, _name + "-" + getMacAddressBase());
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

MDNS::Status MDNS::_messageSend(uint16_t xid, int type, const ServiceRecord* serviceRecord) {

    Header dnsHeader{};
    dnsHeader.xid = htons(xid);
    dnsHeader.opCode = DNS_OPCODE_QUERY;
    switch (type) {
        case PacketTypeCompleteRecord:
        case PacketTypeCompleteRelease:
            dnsHeader.queryResponse = DNS_QR_RESPONSE;
            dnsHeader.authoritiveAnswer = DNS_AA_AUTHORITATIVE;
            dnsHeader.answerCount = htons(DNS_COUNT_A_RECORD + (_serviceRecords.empty() ? 0 : (DNS_COUNT_DNS_SD_PTR + (_serviceRecords.size() * DNS_COUNT_PER_SERVICE))));
            break;
        case PacketTypeProbe:
            dnsHeader.queryResponse = DNS_QR_QUERY;
            dnsHeader.authoritiveAnswer = DNS_AA_NON_AUTHORITATIVE;
            dnsHeader.queryCount = htons(DNS_COUNT_SINGLE);
            dnsHeader.authorityCount = htons(DNS_COUNT_A_RECORD + (_serviceRecords.empty() ? 0 : (DNS_COUNT_DNS_SD_PTR + (_serviceRecords.size() * DNS_COUNT_PER_SERVICE))));
            break;
        case PacketTypeReverseRecord:
        case PacketTypeAddressRecord:
        case PacketTypeAddressRelease:
            dnsHeader.queryResponse = DNS_QR_RESPONSE;
            dnsHeader.authoritiveAnswer = DNS_AA_AUTHORITATIVE;
            dnsHeader.answerCount = htons(DNS_COUNT_A_RECORD);
            dnsHeader.additionalCount = htons(type == PacketTypeReverseRecord ? DNS_COUNT_A_RECORD : 0);    // A record as additional
            break;
        case PacketTypeServiceRecord:
        case PacketTypeServiceRelease:
            dnsHeader.queryResponse = DNS_QR_RESPONSE;
            dnsHeader.authoritiveAnswer = DNS_AA_AUTHORITATIVE;
            dnsHeader.answerCount = htons(DNS_COUNT_PER_SERVICE);
            dnsHeader.additionalCount = htons(type == PacketTypeServiceRecord ? (DNS_COUNT_DNS_SD_PTR + DNS_COUNT_A_RECORD) : 0);    // DNS-SD + A record as additional
            break;
        case PacketTypeNSEC:
            dnsHeader.queryResponse = DNS_QR_RESPONSE;
            dnsHeader.authoritiveAnswer = DNS_AA_AUTHORITATIVE;
            dnsHeader.answerCount = htons(DNS_COUNT_A_RECORD);
            dnsHeader.additionalCount = htons(!serviceRecord ? DNS_COUNT_A_RECORD : 0);    // A record as additional
            break;
    }

    _udp->beginPacket(ADDRESS_MULTICAST, DNS_MDNS_PORT);
    _udp->write((uint8_t*)&dnsHeader, sizeof(Header));

    Buffer buffer = { .data = (uint8_t*)&dnsHeader, .size = sizeof(Header) };
    switch (type) {

        case PacketTypeCompleteRecord:
            DEBUG_PRINTF("MDNS: packet: sending Complete record, ip=%s, name=%s\n", IPAddress(_ipAddress).toString().c_str(), _fqhn.c_str());
            _writeCompleteRecord(&buffer, DNS_TTL_DEFAULT, DNS_CACHE_FLUSH);
            break;
        case PacketTypeCompleteRelease:
            DEBUG_PRINTF("MDNS: packet: sending Complete release, ip=%s, name=%s\n", IPAddress(_ipAddress).toString().c_str(), _fqhn.c_str());
            _writeCompleteRecord(&buffer, DNS_TTL_ZERO, DNS_CACHE_FLUSH);
            break;

        case PacketTypeProbe:
            DEBUG_PRINTF("MDNS: packet: sending Probe query, name=%s\n", _fqhn.c_str());
            _writeCompleteRecord(&buffer, DNS_TTL_ZERO, DNS_CACHE_NO_FLUSH, true);
            break;

        case PacketTypeReverseRecord:
            DEBUG_PRINTF("MDNS: packet: sending Reverse record, ip=%s, name=%s\n", IPAddress(_ipAddress).toString().c_str(), _fqhn.c_str());
            _writeReverseRecord(&buffer, DNS_TTL_DEFAULT);
            break;
        case PacketTypeAddressRecord:
            DEBUG_PRINTF("MDNS: packet: sending Address record, ip=%s, name=%s\n", IPAddress(_ipAddress).toString().c_str(), _fqhn.c_str());
            _writeAddressRecord(&buffer, DNS_TTL_DEFAULT, DNS_CACHE_FLUSH);
            break;
        case PacketTypeAddressRelease:
            DEBUG_PRINTF("MDNS: packet: sending Address release, ip=%s, name=%s\n", IPAddress(_ipAddress).toString().c_str(), _fqhn.c_str());
            _writeAddressRecord(&buffer, DNS_TTL_ZERO, DNS_CACHE_FLUSH);
            break;

        case PacketTypeServiceRecord:
            assert(serviceRecord != nullptr);
            DEBUG_PRINTF("MDNS: packet: sending Service record %s/%u/%s/%s/[%d]\n", toString(serviceRecord->proto).c_str(), serviceRecord->port, serviceRecord->name.c_str(), serviceRecord->fqsn.c_str(), serviceRecord->textRecords.size());
            _writeServiceRecord(&buffer, serviceRecord, DNS_TTL_DEFAULT, true, true);    // include additional
            break;
        case PacketTypeServiceRelease:
            assert(serviceRecord != nullptr);
            DEBUG_PRINTF("MDNS: packet: sending Service release %s/%u/%s/%s/[%d]\n", toString(serviceRecord->proto).c_str(), serviceRecord->port, serviceRecord->name.c_str(), serviceRecord->fqsn.c_str(), serviceRecord->textRecords.size());
            _writeServiceRecord(&buffer, serviceRecord, DNS_TTL_ZERO, true);
            break;

        case PacketTypeNSEC:
            DEBUG_PRINTF("MDNS: packet: sending NSEC for supported types\n");
            _writeNSECRecord(&buffer, serviceRecord, DNS_TTL_DEFAULT, true);
            break;
    }
    _udp->endPacket();
    return Success;
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

MDNS::MDNS::Status MDNS::_messageRecv() {

    const auto udp_len = _udp->parsePacket();
    if (udp_len == 0)
        return TryLater;

    DEBUG_PRINTF("MDNS: packet: receiving, size=%u\n", udp_len);

    const char* detailedError = "";

    auto offset = 0;
#define UDP_READ_ONE(t, x, y) \
    { \
        if (offset >= udp_len) y; \
        const int xx = _udp->read(); \
        if (xx < 0) y; \
        x = static_cast<t>(xx); \
        offset++; \
    }
#define UDP_READ_OFF() \
    offset

    Header dnsHeader;
    auto buf = (uint8_t*)&dnsHeader;
    for (auto z = 0; z < sizeof(Header); z++)
        UDP_READ_ONE(uint8_t, buf[z], goto bad_packet);
    dnsHeader.xid = ntohs(dnsHeader.xid);
    dnsHeader.queryCount = ntohs(dnsHeader.queryCount);
    dnsHeader.answerCount = ntohs(dnsHeader.answerCount);
    dnsHeader.authorityCount = ntohs(dnsHeader.authorityCount);
    dnsHeader.additionalCount = ntohs(dnsHeader.additionalCount);

    if (!_isAddressValid(_udp->remoteIP())) {
        detailedError = "invalid source address";
        goto bad_packet_failed_checks;
    }

    if (DETAILED_CHECKS) {
        if (udp_len < (sizeof(Header) + (dnsHeader.queryCount * 6) + (dnsHeader.authorityCount * 6))) {
            detailedError = "packet too small for claimed record counts";
            goto bad_packet_failed_checks;
        }
        if (dnsHeader.opCode > DNS_OPCODE_UPDATE) {
            detailedError = "invalid opcode";
            goto bad_packet_failed_checks;
        }
        if (dnsHeader.responseCode > DNS_RCODE_NOTZONE) {
            detailedError = "invalid response code";
            goto bad_packet_failed_checks;
        }
        if (dnsHeader.queryResponse == 0 && dnsHeader.authoritiveAnswer == 1) {
            detailedError = "query with AA set";
            goto bad_packet_failed_checks;
        }
        if (dnsHeader.queryCount > DETAILED_CHECKS_REASONABLE_COUNT || dnsHeader.answerCount > DETAILED_CHECKS_REASONABLE_COUNT || dnsHeader.authorityCount > DETAILED_CHECKS_REASONABLE_COUNT || dnsHeader.additionalCount > DETAILED_CHECKS_REASONABLE_COUNT) {
            detailedError = "unreasonable record counts";
            goto bad_packet_failed_checks;
        }
        if (dnsHeader.zReserved != 0) {
            detailedError = "reserved bit set";
            goto bad_packet_failed_checks;
        }
        const int firstByte = _udp->peek();
        if (firstByte < 0 || firstByte > DNS_LABEL_LENGTH_MAX) {
            detailedError = "invalid first label length";
            goto bad_packet_failed_checks;
        }
        if (dnsHeader.truncated && udp_len < 512) {
            detailedError = "suspicious: TC set but packet small";
            goto bad_packet_failed_checks;
        }
    }

    if (dnsHeader.truncated)
        DEBUG_PRINTF("MDNS: packet: received truncated from %s\n", _udp->remoteIP().toString().c_str());

    // Only check for conflicts if: 1. It's a probe (has authority records) OR 2. It's a response claiming our name
    if ((dnsHeader.authorityCount > 0 || dnsHeader.queryResponse == DNS_QR_RESPONSE) && _udp->remotePort() == DNS_MDNS_PORT) {

        DEBUG_PRINTF("MDNS: packet: checking, %s / %s:%u\n", parseHeader(dnsHeader).c_str(), _udp->remoteIP().toString().c_str(), _udp->remotePort());

        std::vector<String> names;
        uint8_t rLen = 0;

        do {
            UDP_READ_ONE(uint8_t, rLen, break);
            if ((rLen & DNS_COMPRESS_MARK) == DNS_COMPRESS_MARK) {    // shouldn't happen for first entry
                uint8_t xLen;
                UDP_READ_ONE(uint8_t, xLen, goto bad_packet);
                (void)xLen;
            } else if (rLen > 0) {
                String name;
                for (auto z = 0; z < rLen; z++) {
                    char r;
                    UDP_READ_ONE(char, r, goto bad_packet);
                    name += r;
                }
                names.push_back(name);
            }
        } while (rLen > 0 && rLen <= DNS_LABEL_LENGTH_MAX);
        if (names.empty() && dnsHeader.authorityCount > 0) {
            detailedError = "malformed packet - authority count > 0 but no names found";
            goto bad_packet_failed_checks;
        }

        if (!names.empty()) {
            const String fqhn = join(names, ".");
            if (fqhn.equalsIgnoreCase(_fqhn))
                if ((dnsHeader.authorityCount > 0 && _udp->remoteIP() > _ipAddress) || (dnsHeader.authorityCount == 0 && dnsHeader.queryResponse == DNS_QR_RESPONSE)) {
                    DEBUG_PRINTF("MDNS: conflict detected in probe: %s\n", fqhn.c_str());
                    return _conflicted();
                }
        }

    } else if (dnsHeader.queryResponse == DNS_QR_QUERY && dnsHeader.opCode == DNS_OPCODE_QUERY && _udp->remotePort() == DNS_MDNS_PORT) {

        DEBUG_PRINTF("MDNS: packet: processing, %s / %s:%u\n", parseHeader(dnsHeader).c_str(), _udp->remoteIP().toString().c_str(), _udp->remotePort());

        const auto xid = dnsHeader.xid;
        const auto q = dnsHeader.queryCount;

        //

        // this is all horrible and brittle and needs replacement
        const auto recordsLengthStatic = 3;
        const auto recordsLength = _serviceRecords.size() + recordsLengthStatic;
        struct _matcher_t {
            const char* name;
            int length, match = 1, position = 0;
            bool requested = false, unsupported = false;
        };
        std::vector<_matcher_t> recordsMatcherTop(recordsLength);

        int j = 0;
        recordsMatcherTop[j].name = _fqhn.c_str(), recordsMatcherTop[j].length = _fqhn.length(), j++;
        recordsMatcherTop[j].name = _arpa.c_str(), recordsMatcherTop[j].length = _arpa.length(), j++;
        recordsMatcherTop[j].name = SERVICE_SD_FQSN, recordsMatcherTop[j].length = strlen(SERVICE_SD_FQSN), j++;
        for (const auto& r : _serviceRecords)
            recordsMatcherTop[j].name = r.fqsn.c_str(), recordsMatcherTop[j].length = r.fqsn.length(), j++;
        for (const auto& m : recordsMatcherTop)
            DEBUG_PRINTF("MDNS: packet: processing, matching[]: <%s>: %d/%d/%d\n", m.name, m.match, m.length, m.position);

        const auto __matchStringPart = [](const char** pCmpStr, int* pCmpLen, const uint8_t* buf, const int dataLen) -> int {
            const auto _memcmp_caseinsensitive = [](const char* a, const unsigned char* b, const int l) -> int {
                for (auto i = 0; i < l; i++) {
                    if (tolower(a[i]) < tolower(b[i])) return -1;
                    if (tolower(a[i]) > tolower(b[i])) return 1;
                }
                return 0;
            };
            const auto matches = (*pCmpLen >= dataLen) ? 1 & (_memcmp_caseinsensitive(*pCmpStr, buf, dataLen) == 0) : 0;
            *pCmpStr += dataLen;
            *pCmpLen -= dataLen;
            if ('.' == **pCmpStr)
                (*pCmpStr)++, (*pCmpLen)--;
            return matches;
        };

        //

        for (auto i = 0; i < q; i++) {
            DEBUG_PRINTF("MDNS: packet: processing, query[%d/%u]: ", i + 1, q);

            std::vector<_matcher_t> recordsMatcher = recordsMatcherTop;

            uint8_t tLen = 0, rLen = 0;
            do {
                UDP_READ_ONE(uint8_t, rLen, break);
                tLen += 1;
                // https://www.ietf.org/rfc/rfc1035.txt
                if ((rLen & DNS_COMPRESS_MARK) == DNS_COMPRESS_MARK) {
                    uint8_t xLen;
                    UDP_READ_ONE(uint8_t, xLen, goto bad_packet);
                    const int offs = ((static_cast<uint16_t>(rLen) & ~DNS_COMPRESS_MARK) << 8) | static_cast<uint16_t>(xLen);    // in practice, same as xLen
                    DEBUG_PRINTF("(%02X/%02X = %04X)", rLen, xLen, offs);
                    for (auto& m : recordsMatcher)
                        if (m.position && m.position != offs)
                            m.match = 0;
                    tLen += 1;
                } else if (rLen > 0) {
                    DEBUG_PRINTF("[");
                    uint8_t tr = rLen;
                    while (tr > 0) {
                        uint8_t ir = (tr > (int)sizeof(Header)) ? sizeof(Header) : tr;
                        for (auto z = 0; z < ir; z++)
                            UDP_READ_ONE(uint8_t, buf[z], goto bad_packet);
                        DEBUG_PRINTF("%.*s", ir, buf);
                        tr -= ir;
                        for (auto& m : recordsMatcher)
                            if (!m.requested && m.match)
                                m.match &= __matchStringPart(&m.name, &m.length, buf, ir);
                    }
                    DEBUG_PRINTF("]");
                    tLen += rLen;
                }
            } while (rLen > 0 && rLen <= DNS_LABEL_LENGTH_MAX);

            // if this matched a name of ours (and there are no characters left), then
            // check whether this is an A record query (for our own name) or a PTR record query
            // (for one of our services).
            // if so, we'll note to send a record
            auto next_bytes = 0;
            for (auto z = 0; z < 4; z++) {
                UDP_READ_ONE(uint8_t, buf[z], break);
                next_bytes++;
            }

            //

            size_t r = 0;
            for (auto& m : recordsMatcher) {
                if (!m.requested && m.match && !m.length) {
                    if (!m.position)
                        m.position = UDP_READ_OFF() - 4 - tLen;
                    if ((next_bytes == 4) && buf[0] == DNS_RECORD_HI && (buf[2] == DNS_CACHE_NO_FLUSH || buf[2] == DNS_CACHE_FLUSH) && buf[3] == DNS_CLASS_IN) {
                        if (r == 0) {    // Query for our hostname
                            if (buf[1] == DNS_RECORD_A)
                                m.requested = true;
                            else
                                m.unsupported = true;
                        } else if (r == 1) {    // Query for our address
                            if (buf[1] == DNS_RECORD_PTR)
                                m.requested = true;
                            else
                                m.unsupported = true;
                        } else {    // Query for our service
                            if (isServiceRecord(buf[1]))
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

            //

            if (next_bytes == 4)
                DEBUG_PRINTF(" <%s/%s/%s>\n", parseDNSType(buf[0], buf[1]).c_str(), parseDNSFlags(buf[2]).c_str(), parseDNSClass(buf[3]).c_str());
        }

        //

        if (recordsMatcherTop[0].unsupported || recordsMatcherTop[1].unsupported || recordsMatcherTop[2].unsupported) {
            DEBUG_PRINTF("MDNS: packet: processing, negated[%d/%d/%d]\n", recordsMatcherTop[0].unsupported, recordsMatcherTop[1].unsupported, recordsMatcherTop[2].unsupported);
            _messageSend(xid, PacketTypeNSEC);
        }
        if (recordsMatcherTop[0].requested) {
            DEBUG_PRINTF("MDNS: packet: processing, matched[NAME]: %s\n", recordsMatcherTop[0].name);
            _messageSend(xid, PacketTypeAddressRecord);
        }
        if (recordsMatcherTop[1].requested) {
            DEBUG_PRINTF("MDNS: packet: processing, matched[ADDR]: %s\n", recordsMatcherTop[1].name);
            _messageSend(xid, PacketTypeAddressRecord);
        }
        if (recordsMatcherTop[2].requested) {
            DEBUG_PRINTF("MDNS: packet: processing, matched[DISC]: %s\n", recordsMatcherTop[2].name);
            _messageSend(xid, PacketTypeCompleteRecord);
        } else {
            int mi = 0;
            for (const auto& r : _serviceRecords) {
                const auto& m = recordsMatcherTop[mi + recordsLengthStatic];
                if (m.requested) {
                    DEBUG_PRINTF("MDNS: packet: processing, matched[SERV:%d]: %s\n", mi, m.name);
                    _messageSend(xid, PacketTypeServiceRecord, &r);
                }
                if (m.unsupported) {
                    DEBUG_PRINTF("MDNS: packet: processing, negated[SERV:%d]: %s\n", mi, m.name);
                    _messageSend(xid, PacketTypeNSEC, &r);
                }
                mi++;
            }
        }

        //

#ifdef DEBUG_MDNS
    } else {

        DEBUG_PRINTF("MDNS: packet: debugging, %s / %s:%u\n", parseHeader(dnsHeader).c_str(), _udp->remoteIP().toString().c_str(), _udp->remotePort());

        struct Group {
            int offset;
            std::vector<String> names;
        };
        std::vector<Group> groups;
        auto uncompressAtOffset = [&](int offs) -> String {
            int cnts = 0;
            for (const auto& group : groups) {
                cnts += group.offset;
                for (const auto& name : group.names)
                    if (name.startsWith("(") && name.endsWith(")")) {    // this is a hack
                    } else {
                        if (offs < (cnts + name.length()))
                            return (offs == cnts) ? name : String(name.c_str()[offs - cnts]);
                        cnts += name.length();
                    }
            }
            return String();
        };
        int goffset = 0;

        for (int i = 0, q = static_cast<int>(dnsHeader.queryCount); i < q; i++) {

            DEBUG_PRINTF("MDNS: packet: debugging (not for us), query[%d/%u]: ", i + 1, q);

            std::vector<String> names;
            int pCnt = 0;
            uint8_t rLen = 0;

            do {
                UDP_READ_ONE(uint8_t, rLen, break);
                pCnt++;
                // https://www.ietf.org/rfc/rfc1035.txt
                if ((rLen & DNS_COMPRESS_MARK) == DNS_COMPRESS_MARK) {
                    uint8_t xLen;
                    UDP_READ_ONE(uint8_t, xLen, goto bad_packet);
                    pCnt++;
                    const int offs = ((static_cast<uint16_t>(rLen) & ~DNS_COMPRESS_MARK) << 8) | static_cast<uint16_t>(xLen);    // in practice, same as xLen
                    names.push_back("(" + uncompressAtOffset(offs) + ")");
                } else if (rLen > 0) {
                    String name;
                    for (auto z = 0; z < rLen; z++) {
                        char r;
                        UDP_READ_ONE(char, r, goto bad_packet);
                        pCnt++;
                        name += r;
                    }
                    names.push_back(name);
                }
            } while (rLen > 0 && rLen <= DNS_LABEL_LENGTH_MAX);

            uint8_t ctrl[4];
            for (auto z = 0; z < 4; z++) {
                UDP_READ_ONE(uint8_t, ctrl[z], break);
                pCnt++;
            }
            groups.push_back({ .offset = goffset, .names = names });
            goffset += pCnt;

            DEBUG_PRINTF("%s <%s/%s/%s>\n", join(names, ".").c_str(), parseDNSType(ctrl[0], ctrl[1]).c_str(), parseDNSFlags(ctrl[2]).c_str(), parseDNSClass(ctrl[3]).c_str());
        }
#endif    // DEBUG_MDNS
    }

    _udp->flush();
    return Success;

bad_packet:
    _udp->flush();
    return PacketBad;

bad_packet_failed_checks:
    DEBUG_PRINTF("MDNS: packet: faulty(%s), %s / %s:%u\n", detailedError, parseHeader(dnsHeader).c_str(), _udp->remoteIP().toString().c_str(), _udp->remotePort());
    _udp->flush();
    return PacketBad;
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

bool MDNS::_isAddressValid(const IPAddress& addr) const {
    if (addr[0] == 0)
        return (addr[1] | addr[2] | addr[3]) == 0;
    if (addr[0] == 127)
        return false;
    if (addr[0] == 169 && addr[1] == 254) {
        if (addr[2] == 0 || addr[2] == 255) return false;
        if (_ipAddress[0] == 169 && _ipAddress[1] == 254) return addr[2] == _ipAddress[2];
        return false;
    }
    return true;
}
// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

inline void _writeUint16(uint8_t* ptr, const uint16_t val) {
    *((uint16_t*)ptr) = htons(val);
}

inline void _writeUint32(uint8_t* ptr, const uint32_t val) {
    *((uint32_t*)ptr) = htonl(val);
}

void MDNS::_writeBits(Buffer* buffer, const uint8_t byte1, const uint8_t byte2, const uint8_t byte3, const uint8_t byte4, const uint32_t ttl) const {
    buffer->data[0] = byte1;
    buffer->data[1] = byte2;
    buffer->data[2] = byte3;
    buffer->data[3] = byte4;
    _writeUint32(&buffer->data[4], ttl);
    _udp->write(buffer->data, 8);
}

void MDNS::_writeLength(Buffer* buffer, const uint16_t length) const {
    _writeUint16(&buffer->data[0], length);
    _udp->write(buffer->data, 2);
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

void MDNS::_writeNameLengthAndContent(Buffer* buffer, const String& name) const {
    _writeLength(buffer, _sizeofDNSName(name));
    _writeDNSName(buffer, name);
}

void MDNS::_writeAddressLengthAndContent(Buffer* buffer, const IPAddress& address) const {
    _writeLength(buffer, 4);
    buffer->data[0] = address[0];
    buffer->data[1] = address[1];
    buffer->data[2] = address[2];
    buffer->data[3] = address[3];
    _udp->write(buffer->data, 4);
}

// -----------------------------------------------------------------------------------------------

void MDNS::_writeNSECRecord(Buffer* buffer, const ServiceRecord* serviceRecord, const uint32_t ttl, const bool cacheFlush) const {

    // if not a service, still have an SRV for DNS-SD
    DNSBitmap bitmap({ DNS_RECORD_PTR, DNS_RECORD_SRV, serviceRecord ? DNS_RECORD_TXT : DNS_RECORD_A });

    // Write NSEC with bitmap -- for a service, this probably correct to use the FQSN and not just the plain name
    const String& name = serviceRecord ? serviceRecord->fqsn : _fqhn;
    _writeDNSName(buffer, name);
    _writeBits(buffer, DNS_RECORD_HI, DNS_RECORD_NSEC, cacheFlush ? DNS_CACHE_FLUSH : DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, ttl);
    _writeLength(buffer, _sizeofDNSName(name) + bitmap.size());    // name + bitmap (2+x)
    _writeDNSName(buffer, name);
    _udp->write(bitmap.data(), bitmap.size());

    // Write our address as additional if not for a service
    if (!serviceRecord)
        _writeAddressRecord(buffer, DNS_TTL_DEFAULT);
}

// -----------------------------------------------------------------------------------------------

void MDNS::_writeCompleteRecord(Buffer* buffer, const uint32_t ttl, const bool cacheFlush, const bool anyType) const {

    // 1. Write A record for our hostname
    _writeAddressRecord(buffer, ttl, cacheFlush, anyType);

    if (!_serviceRecords.empty()) {

        // 2. Write single DNS-SD PTR record that points to our services
        _writeDNSName(buffer, SERVICE_SD_FQSN);
        _writeBits(buffer, DNS_RECORD_HI, DNS_RECORD_PTR, DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, std::min(ttl, DNS_TTL_SHARED_MAX));
        _writeNameLengthAndContent(buffer, _fqhn);    // XXX is this correct, should it be the service name?

        // 3. Write individual service records
        for (const auto& r : _serviceRecords)
            _writeServiceRecord(buffer, &r, ttl, cacheFlush);
    }
}

// -----------------------------------------------------------------------------------------------

void MDNS::_writeReverseRecord(Buffer* buffer, const uint32_t ttl) const {

    // Write our reverse name + fq name
    _writeDNSName(buffer, _arpa);
    _writeBits(buffer, DNS_RECORD_HI, DNS_RECORD_PTR, DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, std::min(ttl, DNS_TTL_SHARED_MAX));
    _writeNameLengthAndContent(buffer, _fqhn);

    // and our A record
    _writeAddressRecord(buffer, ttl, true);
}

void MDNS::_writeAddressRecord(Buffer* buffer, const uint32_t ttl, const bool cacheFlush, const bool anyType) const {

    // Write our name + address
    _writeDNSName(buffer, _fqhn);
    _writeBits(buffer, DNS_RECORD_HI, anyType ? DNS_RECORD_ANY : DNS_RECORD_A, cacheFlush ? DNS_CACHE_FLUSH : DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, ttl);
    _writeAddressLengthAndContent(buffer, _ipAddress);
}

// -----------------------------------------------------------------------------------------------

void MDNS::_writeServiceRecord(Buffer* buffer, const ServiceRecord* serviceRecord, const uint32_t ttl, const bool cacheFlush, const bool includeAdditional) const {

    // 1. Write SRV Record for service instance
    _writeDNSName(buffer, serviceRecord->name);
    _writeBits(buffer, DNS_RECORD_HI, DNS_RECORD_SRV, cacheFlush ? DNS_CACHE_FLUSH : DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, ttl);
    _writeLength(buffer, 4 + 2 + _sizeofDNSName(_fqhn));
    //
    _writeUint16(&buffer->data[0], DNS_SRV_PRIORITY_DEFAULT);
    _writeUint16(&buffer->data[2], DNS_SRV_WEIGHT_DEFAULT);
    _writeUint16(&buffer->data[4], serviceRecord->port);
    _udp->write(buffer->data, 4 + 2);
    _writeDNSName(buffer, _fqhn);

    // 2. Write TXT Record for service instance
    _writeDNSName(buffer, serviceRecord->name);
    _writeBits(buffer, DNS_RECORD_HI, DNS_RECORD_TXT, cacheFlush ? DNS_CACHE_FLUSH : DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, ttl);
    //
    if (serviceRecord->textRecords.empty()) {
        _writeLength(buffer, DNS_TXT_EMPTY_LENGTH);
        //
        buffer->data[0] = DNS_TXT_EMPTY_CONTENT;
        _udp->write(buffer->data, 1);
    } else {
        const auto length = std::accumulate(serviceRecord->textRecords.begin(), serviceRecord->textRecords.end(), static_cast<uint16_t>(0), [](const uint16_t size, const auto& txt) {
            return size + (1 + std::min(txt.length(), static_cast<size_t>(DNS_TXT_LENGTH_MAX)));
        });
        _writeLength(buffer, length);
        //
        for (const auto& txt : serviceRecord->textRecords) {
            const auto size = std::min(txt.length(), static_cast<size_t>(DNS_TXT_LENGTH_MAX));
            buffer->data[0] = static_cast<uint8_t>(size);
            _udp->write(buffer->data, 1);
            _udp->write(reinterpret_cast<const uint8_t*>(txt.c_str()), size);
        }
    }

    // 3. Write PTR Record for service instance
    _writeDNSName(buffer, serviceRecord->fqsn);
    _writeBits(buffer, DNS_RECORD_HI, DNS_RECORD_PTR, DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, std::min(ttl, DNS_TTL_SHARED_MAX));
    _writeNameLengthAndContent(buffer, serviceRecord->name);

    if (includeAdditional) {

        // 4. Write single DNS-SD PTR record that points to our services
        _writeDNSName(buffer, SERVICE_SD_FQSN);
        _writeBits(buffer, DNS_RECORD_HI, DNS_RECORD_PTR, DNS_CACHE_NO_FLUSH, DNS_CLASS_IN, std::min(ttl, DNS_TTL_SHARED_MAX));
        _writeNameLengthAndContent(buffer, serviceRecord->fqsn);    // XXX is this correct?

        // 5. Write our IP address
        _writeAddressRecord(buffer, ttl, cacheFlush);
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
    size += _sizeofDNSName(record->fqsn) + DNS_RECORD_HEADER_SIZE + _sizeofDNSName(record->name);
    // Additional size
    if (includeAdditional) {
        size += _sizeofDNSName(SERVICE_SD_FQSN) + DNS_RECORD_HEADER_SIZE + _sizeofDNSName(record->fqsn);    // XXX is this correct?
        size += _sizeofDNSName(_fqhn) + DNS_RECORD_HEADER_SIZE + 4;                                         // IP Address size
    }
    return size;
}

// -----------------------------------------------------------------------------------------------

void MDNS::_writeDNSName(Buffer* buffer, const String& name) const {
    const uint8_t* p1 = reinterpret_cast<const uint8_t*> (name.c_str());
    while (*p1) {
        size_t c = 1;
        const uint8_t* p2 = p1;
        while (*p2 && *p2 != '.') {
            p2++;
            c++;
        };
        uint8_t* p3 = buffer->data;
        int i = c, l = buffer->size - 1;
        *p3++ = (uint8_t)--i;
        while (i-- > 0) {
            *p3++ = *p1++;
            if (--l <= 0) {
                _udp->write(buffer->data, buffer->size);
                l = buffer->size;
                p3 = buffer->data;
            }
        }
        while (*p1 == '.')
            ++p1;
        if (l != buffer->size)
            _udp->write(buffer->data, buffer->size - l);
    }
    buffer->data[0] = 0;
    _udp->write(buffer->data, 1);
}

size_t MDNS::_sizeofDNSName(const String& name) const {
    size_t length = 1;    // null terminator
    auto p = name.c_str();
    while (*p) {
        auto next = strchr(p, '.');
        const size_t labelLen = next ? (next - p) : strlen(p);
        length += 1 + labelLen;    // 1 for length byte
        p += labelLen;
        if (next) p++;    // skip the dot
        if (labelLen == 0 || labelLen > DNS_LABEL_LENGTH_MAX || length > DNS_MAX_NAME_LENGTH)
            return 0;
    }
    return length;
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------
