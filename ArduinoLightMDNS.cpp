
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

// Known Answer tracking
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

// Duplicate Question tracking
struct RecentQuestion {
    String name;
    uint16_t recordType;
    uint64_t askedAt;
    
    bool isExpired(uint64_t now) const {
        return (now - askedAt) >= 1000; // 1 second suppression window
    }
};

// Maintain lists of known answers and recent questions
static constexpr size_t MAX_KNOWN_ANSWERS = 32;
static constexpr size_t MAX_RECENT_QUESTIONS = 16;
std::vector<KnownAnswer> _knownAnswers;
std::vector<RecentQuestion> _recentQuestions;

// Add these methods to handle the suppression logic
private:
    void _cleanupExpiredRecords();
    bool _shouldSuppressAnswer(const String& name, uint16_t recordType, const uint8_t* rdata, size_t rdataLen);
    bool _shouldSuppressQuestion(const String& name, uint16_t recordType);
    void _recordKnownAnswer(const String& name, uint16_t recordType, uint32_t ttl, const uint8_t* rdata, size_t rdataLen);
    void _recordRecentQuestion(const String& name, uint16_t recordType);

// In ArduinoLightMDNS.cpp, add these implementations:
void MDNS::_cleanupExpiredRecords() {
    auto now = millis();
    
    // Remove expired known answers
    std::erase_if(_knownAnswers, [now](const KnownAnswer& ka) {
        return ka.isExpired(now);
    });
    
    // Remove expired recent questions
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
    // Remove oldest if at capacity
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
    // Remove oldest if at capacity
    if (_recentQuestions.size() >= MAX_RECENT_QUESTIONS)
        _recentQuestions.erase(_recentQuestions.begin());
    RecentQuestion rq;
    rq.name = name;
    rq.recordType = recordType;
    rq.askedAt = millis();
    _recentQuestions.push_back(std::move(rq));
}

// Modify _messageRecv() to handle Known Answers in responses
// Add this section after parsing the question count:

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
    } while (rLen > 0 && rLen <= DNS_LABEL_MAX_LENGTH);
    
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

// Modify the query processing section to check for duplicates:
// Before processing each query, add:

String queryName = join(names, ".");
if (_shouldSuppressQuestion(queryName, recordType)) {
    continue; // Skip this query
}
_recordRecentQuestion(queryName, recordType);

// Before sending responses, check if they should be suppressed:
// In _messageSend(), before writing each record:

if (_shouldSuppressAnswer(recordName, recordType, rdataBuffer, rdataLen)) {
    continue; // Skip this response
}

// Add cleanup call in process()
Status MDNS::process(void) {
    auto status = Success;
    if (_active) {
        _cleanupExpiredRecords();  // Add this line
        // ... rest of process() implementation
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
Cache Management:
    Proper handling of cache flush bit
    Separate handling for unique vs shared records
    Memory-bounded cache with automatic cleanup
    Efficient record updates and removals
POOF Implementation:
    Tracks record freshness
    Provides callback for expired records
    Automatic cleanup of stale records
    Memory-efficient tracking

// Probe Management
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

// Cache Management
class CacheManager {
private:
    struct CacheEntry {
        String name;
        uint16_t type;
        uint32_t ttl;
        uint64_t receivedAt;
        std::vector<uint8_t> rdata;
        bool uniqueRecord;  // True for records that should be unique
        
        bool isExpired(uint64_t now) const {
            return (now - receivedAt) >= (ttl * 1000ULL);
        }
    };

    static constexpr size_t MAX_CACHE_ENTRIES = 64;
    std::vector<CacheEntry> _cache;
    
public:
    void handleRecord(const String& name, uint16_t type, uint32_t ttl, const uint8_t* rdata, size_t rdataLen, bool uniqueRecord);
    void handleCacheFlush(const String& name, uint16_t type);
    void cleanup();
};

// POOF (Passive Observation Of Failures) Manager
class POOFManager {
private:
    struct TrackedRecord {
        String name;
        uint16_t type;
        uint64_t lastSeen;
        uint32_t ttl;
        bool announced;
        
        bool isExpired(uint64_t now) const {
            return (now - lastSeen) >= (ttl * 1000ULL);
        }
    };
    
    std::vector<TrackedRecord> _trackedRecords;
    std::function<void(const String&, uint16_t)> _expiryCallback;
    
public:
    void setExpiryCallback(std::function<void(const String&, uint16_t)> callback) {
        _expiryCallback = callback;
    }
    
    void recordSeen(const String& name, uint16_t type, uint32_t ttl);
    void cleanup();
};

// Add these as members to the MDNS class
private:
    ProbeManager _probeManager;
    CacheManager _cacheManager;
    POOFManager _poofManager;

// Now the implementation file (ArduinoLightMDNS.cpp):

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
    
    // Compare our IP with remote IP for tiebreaking
    bool shouldDefer = remoteIP > _mdns._ipAddress;
    
    if (shouldDefer) {
        // If we're within initial probing window, reset probe count
        if (millis() - _probeStartTime < PROBE_TIEBREAK_THRESHOLD_MS)
            _probeCount = 0;        
        // Defer our next probe
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
            // Probing complete
            _probing = false;
            // Signal successful probe completion
            _mdns._messageSend(XID_DEFAULT, PacketTypeAddressRecord);
        }
    }
}

void CacheManager::handleRecord(const String& name, uint16_t type, uint32_t ttl, const uint8_t* rdata, size_t rdataLen, bool uniqueRecord) {
    uint64_t now = millis();
    
    // Remove expired entries if we're at capacity
    if (_cache.size() >= MAX_CACHE_ENTRIES) {
        cleanup();
        if (_cache.size() >= MAX_CACHE_ENTRIES)
            _cache.erase(_cache.begin());
    }
    
    // Check for existing entry
    auto it = std::find_if(_cache.begin(), _cache.end(),
        [&](const CacheEntry& entry) {
            return entry.name == name && entry.type == type;
        });
    
    if (it != _cache.end()) {
        // Update existing entry
        it->ttl = ttl;
        it->receivedAt = now;
        it->rdata.assign(rdata, rdata + rdataLen);
        it->uniqueRecord = uniqueRecord;
    } else {
        // Add new entry
        _cache.push_back({
            name, type, ttl, now,
            std::vector<uint8_t>(rdata, rdata + rdataLen),
            uniqueRecord
        });
    }
}

void CacheManager::handleCacheFlush(const String& name, uint16_t type) {
    // Remove all records matching name and type
    std::erase_if(_cache, [&](const CacheEntry& entry) {
        return entry.uniqueRecord && 
               entry.name == name && 
               entry.type == type;
    });
}

void CacheManager::cleanup() {
    uint64_t now = millis();
    std::erase_if(_cache, [now](const CacheEntry& entry) {
        return entry.isExpired(now);
    });
}

void POOFManager::recordSeen(const String& name, uint16_t type, uint32_t ttl) {
    uint64_t now = millis();

    auto it = std::find_if(_trackedRecords.begin(), _trackedRecords.end(),
        [&](const TrackedRecord& record) {
            return record.name == name && record.type == type;
        });
    
    if (it != _trackedRecords.end()) {
        it->lastSeen = now;
        it->ttl = ttl;
        it->announced = true;
    } else {
        _trackedRecords.push_back({
            name, type, now, ttl, true
        });
    }
}

void POOFManager::cleanup() {
    uint64_t now = millis();
    
    for (auto it = _trackedRecords.begin(); it != _trackedRecords.end();) {
        if (it->isExpired(now) && it->announced) {
            if (_expiryCallback) {
                _expiryCallback(it->name, it->type);
            }
            it = _trackedRecords.erase(it);
        } else {
            ++it;
        }
    }
}

// Integration points in MDNS class:

// In constructor:
MDNS::MDNS(UDP& udp) : 
    _udp(&udp), _active(false), _announceLast(0),
    _probeManager(*this), _cacheManager(), _poofManager() {
    
    _poofManager.setExpiryCallback([this](const String& name, uint16_t type) {
        // Handle record expiry - could trigger requery or cleanup
        DEBUG_PRINTF("MDNS: Record expired: %s (type %d)\n", name.c_str(), type);
    });
}

// In start():
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

// In process():
Status MDNS::process(void) {
    auto status = Success;
    if (_active) {
        _probeManager.processTimeouts();
        _cacheManager.cleanup();
        _poofManager.cleanup();
        
        // Rest of process() implementation...
    }
    return status;
}

// In _messageRecv():
// Add after parsing the header:
if (_probeManager.isProbing() && dnsHeader.authorityCount > 0) {
    if (_probeManager.handleIncomingProbe(join(names, "."), _udp->remoteIP()))
        return Success;  // Deferred our probe
}

// When processing incoming records:
if (recordHasCacheFlushBit)
    _cacheManager.handleCacheFlush(recordName, recordType);
_cacheManager.handleRecord(recordName, recordType, ttl, rdataBuffer, rdataLen, recordHasCacheFlushBit);
_poofManager.recordSeen(recordName, recordType, ttl);

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
                
    // Check if we should respond to this query
    if (type == DNS_RECORD_ANY || type == DNS_RECORD_A) {
        if (_mdns._name == name) {
            // Schedule delayed unicast response (400-500ms)
            _mdns._responseScheduler.scheduleResponse(name, DNS_RECORD_A, true, sourceIP, sourcePort);
        }
    }
    
    // Handle service queries
    for (const auto& service : _mdns._serviceRecords) {
        if (service.servName == name || service.name == name) {
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
    _mdns._responseScheduler.scheduleResponse(service.servName, DNS_RECORD_PTR, false, IPAddress(), 0, delay);
    
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
    announceGoodbye(service.servName, DNS_RECORD_PTR);
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
if (name == SERVICE_SD) {
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

#include <string.h>
#include <stdlib.h>
#include <Udp.h>

#include "ArduinoLightMDNS.hpp"

//

#include <esp_mac.h>
String getMacAddressBase() {
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

//

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

//

#define TLD ".local"
static constexpr const char* SERVICE_SD = "_services._dns-sd._udp.local";

typedef enum {
    PacketTypeAddressRecord,     // A record response
    PacketTypeAddressRelease,    // A record release
    PacketTypeServiceRecord,     // SRV/TXT/PTR record combo for service announcement
    PacketTypeServiceRelease,    // Service shutdown announcement
    PacketTypeProbe,             // Name probing (conflict detection)
    PacketTypeNSEC,              // NSEC record (to indicate no other records exist)
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

//

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

static constexpr uint16_t XID_DEFAULT = 0;

static constexpr uint8_t DNS_BIT_QR = 7;    // Query/Response flag
static constexpr uint8_t DNS_QR_QUERY = 0;
static constexpr uint8_t DNS_QR_RESPONSE = 1;
static constexpr uint8_t DNS_BIT_AA = 2;    // Authoritative Answer
static constexpr uint8_t DNS_AA_NON_AUTHORITATIVE = 0;
static constexpr uint8_t DNS_AA_AUTHORITATIVE = 1;
static constexpr uint8_t DNS_BIT_TC = 1;    // Truncation flag
static constexpr uint8_t DNS_BIT_RD = 0;    // Recursion Desired
static constexpr uint8_t DNS_BIT_RA = 7;    // Recursion Available
static constexpr uint8_t DNS_BIT_Z = 6;     // Reserved bit
static constexpr uint8_t DNS_BIT_AD = 5;    // Authenticated Data
static constexpr uint8_t DNS_BIT_CD = 4;    // Checking Disabled

static constexpr uint8_t DNS_OPCODE_QUERY = 0;     // Standard query
static constexpr uint8_t DNS_OPCODE_IQUERY = 1;    // Inverse query
static constexpr uint8_t DNS_OPCODE_STATUS = 2;    // Server status request
static constexpr uint8_t DNS_OPCODE_NOTIFY = 4;    // Zone change notification
static constexpr uint8_t DNS_OPCODE_UPDATE = 5;    // Dynamic update

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

// DNS Message Structure Constants
static constexpr int DNS_HEADER_MIN_SIZE = 10;      // Minimum header size we need to process
static constexpr int DNS_LABEL_MAX_LENGTH = 128;    // Maximum length of a DNS label section
static constexpr int DNS_DATA_LENGTH_IPV4 = 4;      // Length of IPv4 address data

// DNS Record Priority/Weight
static constexpr uint8_t DNS_PRIORITY_DEFAULT = 0x00;    // Default SRV priority

// DNS Compression Constants
static constexpr uint8_t DNS_COMPRESS_MARK = 0xC0;    // Marker for compressed names

// DNS Text Record Constants
static constexpr uint8_t DNS_TXT_MAX_LENGTH = 255;          // Maximum length of a single TXT record
static constexpr uint16_t DNS_TXT_EMPTY_LENGTH = 0x0001;    // Length for empty TXT
static constexpr uint8_t DNS_TXT_EMPTY_CONTENT = 0x00;
static constexpr int DNS_TXT_DEFAULT_SIZE = 3;    // Size for empty TXT

// Timing and Port Constants (move existing defines to constexpr)
static constexpr uint16_t DNS_MDNS_PORT = 5353;       // Replace SERVER_PORT
static constexpr uint32_t DNS_TTL_DEFAULT = 120;      // Replace DNS_TTL_DEFAULT
static constexpr uint32_t DNS_TTL_ZERO = 0;           // Zero TTL for goodbyes
static constexpr uint32_t DNS_PROBE_WAIT_MS = 250;    // Wait time between probes
static constexpr int DNS_PROBE_COUNT = 3;             // Number of probes

static constexpr uint8_t DNS_RECORD_HI = 0x00;      // High byte of record type (always 0 for our types)
static constexpr uint8_t DNS_RECORD_A = 0x01;       // IPv4 host address record
static constexpr uint8_t DNS_RECORD_PTR = 0x0c;     // Domain name pointer (reverse DNS)
static constexpr uint8_t DNS_RECORD_TXT = 0x10;     // Text record for additional data
static constexpr uint8_t DNS_RECORD_AAAA = 0x1c;    // IPv6 host address record
static constexpr uint8_t DNS_RECORD_SRV = 0x21;     // Service location record
static constexpr uint8_t DNS_RECORD_NSEC = 0x2F;    // Next Secure record (proves nonexistence)

static constexpr uint8_t DNS_CACHE_FLUSH = 0x80;       // Flag to tell others to flush cached entries
static constexpr uint8_t DNS_CACHE_NO_FLUSH = 0x00;    // Normal caching behavior

static constexpr uint8_t DNS_CLASS_IN = 0x01;    // Internet class

static constexpr uint8_t DNS_BITMAP_WINDOW = 0x00;    // Bitmap window number (0 for first 256 types)
static constexpr uint8_t DNS_BITMAP_LENGTH = 0x04;    // Length of bitmap in bytes (covers types 0-31)
static constexpr uint8_t DNS_BITMAP_NO_BITS = 0x00;
static constexpr uint8_t DNS_BITMAP_A_BIT = 0x40;                                              // Bit 6 in byte 2 (type 1, A record)
static constexpr uint8_t DNS_BITMAP_TXT_BIT = 0x02;                                            // Bit 1 in byte 3 (type 16, TXT record)
static constexpr uint8_t DNS_BITMAP_SRV_BIT = 0x40;                                            // Bit 6 in byte 3 (type 33, SRV record)
static constexpr uint8_t DNS_BITMAP_SRV_TXT_BITS = DNS_BITMAP_TXT_BIT | DNS_BITMAP_SRV_BIT;    // Combined bits for service records

static constexpr uint16_t DNS_LENGTH_BITMAP = 6;    // NSEC bitmap length

// Common DNS record counts used in messages
static constexpr uint16_t DNS_COUNT_SINGLE = 1;     // Used for single record responses
static constexpr uint16_t DNS_COUNT_SERVICE = 4;    // Used for service announcements (SRV+TXT+2×PTR)

static constexpr uint8_t DNS_MCAST_IP_0 = 224;    // Multicast address bytes
static constexpr uint8_t DNS_MCAST_IP_1 = 0;
static constexpr uint8_t DNS_MCAST_IP_2 = 0;
static constexpr uint8_t DNS_MCAST_IP_3 = 251;

static const IPAddress ADDRESS_MULTICAST(DNS_MCAST_IP_0, DNS_MCAST_IP_1, DNS_MCAST_IP_2, DNS_MCAST_IP_3);

static constexpr bool isServiceRecord(uint8_t type) {
    return type == DNS_RECORD_PTR || type == DNS_RECORD_TXT || type == DNS_RECORD_SRV;
}

static constexpr bool DETAILED_CHECKS = true;
static constexpr uint16_t MAX_REASONABLE_COUNT = 100;

//

MDNS::MDNS(UDP& udp)
    : _udp(&udp), _active(false), _announceLast(0) {
}
MDNS::~MDNS() {
    stop();
}

//

MDNS::Status MDNS::begin(void) {
    assert(sizeof(Header) > DNS_HEADER_MIN_SIZE);    // due to use of Header as a buffer
    DEBUG_PRINTF("MDNS: begin\n");
    return Success;
}
MDNS::Status MDNS::start(const IPAddress& ip, const String& name, bool checkForConflicts) {
    _ipAddress = ip;
    _name = name + TLD;
    auto status = Success;
    if (!_active) {
        if (!_udp->beginMulticast(ADDRESS_MULTICAST, DNS_MDNS_PORT))
            status = Failure;
        else _active = true;
    }
    if (status != Success)
        DEBUG_PRINTF("MDNS: start: failed _udp->beginMulticast error=%s, not active\n", toString(status).c_str());
    else {
        DEBUG_PRINTF("MDNS: start: active ip=%s, name=%s\n", IPAddress(_ipAddress).toString().c_str(), _name.c_str());
        if (checkForConflicts) {
            for (int i = 0; i < DNS_PROBE_COUNT; i++) {
                _messageSend(XID_DEFAULT, PacketTypeProbe);
                delay(DNS_PROBE_WAIT_MS);
            }
            delay(DNS_PROBE_WAIT_MS);
        }
        // XXX should be all in one packet
        _messageSend(XID_DEFAULT, PacketTypeAddressRecord);
        for (const auto& record : _serviceRecords)
            _messageSend(XID_DEFAULT, PacketTypeServiceRecord, &record);
    }
    return status;
}
MDNS::Status MDNS::stop(void) {
    if (_active) {
        DEBUG_PRINTF("MDNS: stop\n");
        // XXX should be all in one packet
        for (const auto& record : _serviceRecords)
            _messageSend(XID_DEFAULT, PacketTypeServiceRelease, &record);
        _messageSend(XID_DEFAULT, PacketTypeAddressRelease);
        _udp->stop();
        _active = false;
    }
    return Success;
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

//

MDNS::Status MDNS::_messageSend(uint16_t xid, int type, const ServiceRecord* serviceRecord) {

    // HEADER
    Header dnsHeader{};
    dnsHeader.xid = htons(xid);
    dnsHeader.opCode = DNS_OPCODE_QUERY;
    switch (type) {
        case PacketTypeAddressRecord:
        case PacketTypeAddressRelease:
            dnsHeader.queryResponse = DNS_QR_RESPONSE;
            dnsHeader.authoritiveAnswer = DNS_AA_AUTHORITATIVE;
            dnsHeader.answerCount = htons(DNS_COUNT_SINGLE);
            break;
        case PacketTypeServiceRecord:
        case PacketTypeServiceRelease:
            dnsHeader.queryResponse = DNS_QR_RESPONSE;
            dnsHeader.authoritiveAnswer = DNS_AA_AUTHORITATIVE;
            dnsHeader.answerCount = htons(DNS_COUNT_SERVICE);
            if (type == PacketTypeServiceRecord)
                dnsHeader.additionalCount = htons(DNS_COUNT_SINGLE);
            break;
        case PacketTypeProbe:
            dnsHeader.queryResponse = DNS_QR_QUERY;
            dnsHeader.authoritiveAnswer = DNS_AA_NON_AUTHORITATIVE;
            dnsHeader.queryCount = htons(DNS_COUNT_SINGLE);
            dnsHeader.authorityCount = htons(DNS_COUNT_SINGLE + _serviceRecords.size());
            break;
        case PacketTypeNSEC:
            dnsHeader.queryResponse = DNS_QR_RESPONSE;
            dnsHeader.authoritiveAnswer = DNS_AA_AUTHORITATIVE;
            dnsHeader.answerCount = htons(DNS_COUNT_SINGLE);
            if (serviceRecord == nullptr)
                dnsHeader.additionalCount = htons(DNS_COUNT_SINGLE);    // We'll send A record as additional
            break;
    }
    _udp->beginPacket(ADDRESS_MULTICAST, DNS_MDNS_PORT);
    _udp->write((uint8_t*)&dnsHeader, sizeof(Header));

    // CONTENT
    auto buf = (uint8_t*)&dnsHeader;
    auto bufSize = sizeof(Header);
    switch (type) {
        case PacketTypeAddressRecord:
            DEBUG_PRINTF("MDNS: packet: sending Address record, ip=%s, name=%s\n", IPAddress(_ipAddress).toString().c_str(), _name.c_str());
            _writeAddressRecord(buf, bufSize, DNS_TTL_DEFAULT);
            break;

        case PacketTypeAddressRelease:
            DEBUG_PRINTF("MDNS: packet: sending Address release, ip=%s, name=%s\n", IPAddress(_ipAddress).toString().c_str(), _name.c_str());
            _writeAddressRecord(buf, bufSize, DNS_TTL_ZERO);
            break;

        case PacketTypeServiceRecord:
            assert(serviceRecord != nullptr);
            DEBUG_PRINTF("MDNS: packet: sending Service record %s/%u/%s/%s/[%d]\n", toString(serviceRecord->proto).c_str(), serviceRecord->port, serviceRecord->name.c_str(), serviceRecord->servName.c_str(), serviceRecord->textRecords.size());

            // (1) SRV record
            _writeSRVName(buf, bufSize, serviceRecord, false);
            buf[0] = DNS_RECORD_HI;
            buf[1] = DNS_RECORD_SRV;     // SRV record
            buf[2] = DNS_CACHE_FLUSH;    // cache flush
            buf[3] = DNS_CLASS_IN;       // class IN
            // ttl
            *((uint32_t*)&buf[4]) = htonl(DNS_TTL_DEFAULT);
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
            _writeSRVName(buf, bufSize, serviceRecord, false);
            buf[0] = DNS_RECORD_HI;
            buf[1] = DNS_RECORD_TXT;     // TXT record
            buf[2] = DNS_CACHE_FLUSH;    // cache flush
            buf[3] = DNS_CLASS_IN;       // class IN
            // ttl
            *((uint32_t*)&buf[4]) = htonl(DNS_TTL_DEFAULT);
            _udp->write(buf, 8);
            // data length && text
            if (serviceRecord->textRecords.size() == 0) {
                buf[0] = static_cast<uint8_t>((DNS_TXT_EMPTY_LENGTH >> 8) & 0xFF);
                buf[1] = static_cast<uint8_t>(DNS_TXT_EMPTY_LENGTH & 0xFF);
                buf[2] = DNS_TXT_EMPTY_CONTENT;
                _udp->write(buf, DNS_TXT_DEFAULT_SIZE);
            } else {    // https://www.ietf.org/rfc/rfc6763.txt
#define __MY_MIN(a, b) ((a) < (b) ? (a) : (b))
                uint16_t length = 0;
                for (const auto& textRecord : serviceRecord->textRecords)
                    length += __MY_MIN(textRecord.length(), DNS_TXT_MAX_LENGTH) + 1;
                *((uint16_t*)&buf[0]) = htons(length);
                _udp->write(buf, 2);
                for (const auto& textRecord : serviceRecord->textRecords) {
                    auto size = __MY_MIN(textRecord.length(), DNS_TXT_MAX_LENGTH);
                    buf[0] = (uint8_t)size;
                    _udp->write(buf, 1);
                    _udp->write((uint8_t*)textRecord.c_str(), size);
                }
            }

            // (3) PTR record (for the DNS-SD service in general)
            _writeDNSName(buf, bufSize, SERVICE_SD, true);
            buf[0] = DNS_RECORD_HI;
            buf[1] = DNS_RECORD_PTR;        // PTR record
            buf[2] = DNS_CACHE_NO_FLUSH;    // no cache flush
            buf[3] = DNS_CLASS_IN;          // class IN
            // ttl
            *((uint32_t*)&buf[4]) = htonl(DNS_TTL_DEFAULT);
            // data length.
            *((uint16_t*)&buf[8]) = htons(serviceRecord->servName.length() + 2);
            _udp->write(buf, 10);
            _writeSRVName(buf, bufSize, serviceRecord, true);

            // (4) PTR record (our service)
            _writeServiceRecord(buf, bufSize, serviceRecord, DNS_TTL_DEFAULT);

            // (x) our IP address as additional record
            _writeAddressRecord(buf, bufSize, DNS_TTL_DEFAULT);
            break;

        case PacketTypeServiceRelease:
            assert(serviceRecord != nullptr);
            DEBUG_PRINTF("MDNS: packet: sending Service release %s/%u/%s/%s/[%d]\n", toString(serviceRecord->proto).c_str(), serviceRecord->port, serviceRecord->name.c_str(), serviceRecord->servName.c_str(), serviceRecord->textRecords.size());
            _writeServiceRecord(buf, bufSize, serviceRecord, DNS_TTL_ZERO);
            break;

        case PacketTypeProbe:
            DEBUG_PRINTF("MDNS: packet: sending probe for name=%s\n", _name.c_str());

            // Write the question section - query for our own name
            _writeDNSName(buf, bufSize, _name.c_str(), true);
            buf[0] = DNS_RECORD_HI;
            buf[1] = DNS_RECORD_A;          // A record
            buf[2] = DNS_CACHE_NO_FLUSH;    // No cache flush in queries
            buf[3] = DNS_CLASS_IN;          // class IN
            _udp->write(buf, DNS_DATA_LENGTH_IPV4);

            // Write the authority section - our claimed name
            _writeDNSName(buf, bufSize, _name.c_str(), true);
            buf[0] = DNS_RECORD_HI;
            buf[1] = DNS_RECORD_A;          // A record
            buf[2] = DNS_CACHE_NO_FLUSH;    // No cache flush
            buf[3] = DNS_CLASS_IN;          // class IN
            _udp->write(buf, DNS_DATA_LENGTH_IPV4);
            *((uint32_t*)&buf[0]) = htonl(DNS_TTL_ZERO);    // TTL = 0 for probes
            *((uint16_t*)&buf[4]) = htons(4);               // data length
            buf[6] = _ipAddress[0];
            buf[7] = _ipAddress[1];
            buf[8] = _ipAddress[2];
            buf[9] = _ipAddress[3];
            _udp->write(buf, 10);

            // Add all our service records as additional authorities
            for (const auto& record : _serviceRecords) {
                _writeSRVName(buf, bufSize, &record, true);
                buf[0] = DNS_RECORD_HI;
                buf[1] = DNS_RECORD_SRV;        // SRV record
                buf[2] = DNS_CACHE_NO_FLUSH;    // No cache flush
                buf[3] = DNS_CLASS_IN;          // class IN
                _udp->write(buf, DNS_DATA_LENGTH_IPV4);
                // ttl
                *((uint32_t*)&buf[0]) = htonl(DNS_TTL_ZERO);    // TTL = 0 for probes
                // data length
                *((uint16_t*)&buf[4]) = htons(8 + _name.length());
                _udp->write(buf, 6);
                buf[0] = buf[1] = buf[2] = buf[3] = DNS_PRIORITY_DEFAULT;    // priority & weight
                // port
                *((uint16_t*)&buf[4]) = htons(record.port);
                _udp->write(buf, 6);
                // target
                _writeDNSName(buf, bufSize, _name.c_str(), true);
            }
            break;

        case PacketTypeNSEC:
            DEBUG_PRINTF("MDNS: packet: sending NSEC for supported types\n");
            uint8_t bitmap[6] = {
                DNS_BITMAP_WINDOW,    // Window Block 0
                DNS_BITMAP_LENGTH,    // Bitmap length
                0x00,                 // Will set bits based on what records exist
                0x00,                 // No records in this range
                0x00,                 // No records in this range
                0x00                  // No records in this range
            };
            if (serviceRecord == nullptr) {
                bitmap[2] = DNS_BITMAP_A_BIT;    // Only A record exists
                _writeDNSName(buf, bufSize, _name.c_str(), true);
            } else {
                bitmap[2] = DNS_BITMAP_NO_BITS;         // No records in this range
                bitmap[3] = DNS_BITMAP_SRV_TXT_BITS;    // Both SRV and TXT records exist
                _writeSRVName(buf, bufSize, serviceRecord, true);
            }
            buf[0] = DNS_RECORD_HI;
            buf[1] = DNS_RECORD_NSEC;    // NSEC record type
            buf[2] = DNS_CACHE_FLUSH;    // cache flush
            buf[3] = DNS_CLASS_IN;       // class IN
            *((uint32_t*)&buf[4]) = htonl(DNS_TTL_DEFAULT);
            *((uint16_t*)&buf[8]) = htons(DNS_LENGTH_BITMAP);    // name + bitmap length
            _udp->write(buf, 10);
            // Write "next" name (same as current in mDNS)
            if (serviceRecord == nullptr)
                _writeDNSName(buf, bufSize, _name.c_str(), true);
            else
                _writeSRVName(buf, bufSize, serviceRecord, true);
            // Write the bitmap of supported record types
            _udp->write(bitmap, 6);
            // For hostname NSEC, include our A record as additional
            if (serviceRecord == nullptr)
                _writeAddressRecord(buf, bufSize, DNS_TTL_DEFAULT);
            break;
    }
    _udp->endPacket();
    return Success;
}

//

MDNS::MDNS::Status MDNS::_messageRecv() {
    const char* detailedError = "";

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
    dnsHeader.xid = ntohs(dnsHeader.xid);
    dnsHeader.queryCount = ntohs(dnsHeader.queryCount);
    dnsHeader.answerCount = ntohs(dnsHeader.answerCount);
    dnsHeader.authorityCount = ntohs(dnsHeader.authorityCount);
    dnsHeader.additionalCount = ntohs(dnsHeader.additionalCount);

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
        if (dnsHeader.queryCount > MAX_REASONABLE_COUNT || dnsHeader.answerCount > MAX_REASONABLE_COUNT || dnsHeader.authorityCount > MAX_REASONABLE_COUNT || dnsHeader.additionalCount > MAX_REASONABLE_COUNT) {
            detailedError = "unreasonable record counts";
            goto bad_packet_failed_checks;
        }
        if (dnsHeader.zReserved != 0) {
            detailedError = "reserved bit set";
            goto bad_packet_failed_checks;
        }
        const int firstByte = _udp->peek();
        if (firstByte < 0 || firstByte > DNS_LABEL_MAX_LENGTH) {
            detailedError = "invalid first label length";
            goto bad_packet_failed_checks;
        }
        if (dnsHeader.truncated && udp_len < 512) {
            detailedError = "suspicious: TC set but packet small";
            goto bad_packet_failed_checks;
        }
    }

    // Only check for conflicts if: 1. It's a probe (has authority records) OR 2. It's a response claiming our name
    if ((dnsHeader.authorityCount > 0 || dnsHeader.queryResponse == DNS_QR_RESPONSE) && _udp->remotePort() == DNS_MDNS_PORT) {

        DEBUG_PRINTF("MDNS: packet: checking, %s / %s:%u\n", parseHeader(dnsHeader).c_str(), _udp->remoteIP().toString().c_str(), _udp->remotePort());

        std::vector<String> names;
        int rLen = 0;

        do {
            if (offset >= udp_len) break;    // READ
            rLen = _udp->read();             // READ
            if (rLen < 0) break;             // READ
            offset++;                        // READ
            //
            if ((rLen & DNS_COMPRESS_MARK) == DNS_COMPRESS_MARK) {
                // shouldn't happen in the first record, but just in case
                if (offset >= udp_len) goto bad_packet;    // READ
                int xLen = _udp->read();                   // READ
                if (xLen < 0) goto bad_packet;             // READ
                offset++;                                  // READ
                //
            } else if (rLen > 0) {
                String name;
                for (auto z = 0; z < rLen; z++) {
                    if (offset >= udp_len) goto bad_packet;    // READ
                    int r = _udp->read();                      // READ
                    if (r < 0) goto bad_packet;                // READ
                    offset++;                                  // READ
                    //
                    name += (char)r;
                }
                names.push_back(name);
            }
        } while (rLen > 0 && rLen <= DNS_LABEL_MAX_LENGTH);
        if (names.empty() && dnsHeader.authorityCount > 0) {
            detailedError = "malformed packet - authority count > 0 but no names found";
            goto bad_packet_failed_checks;
        }

        if (!names.empty()) {
            String fullName = join(names, ".");
            if (strcasecmp(fullName.c_str(), _name.c_str()) == 0) {
                if (dnsHeader.authorityCount > 0) {
                    if (_udp->remoteIP() > _ipAddress) {
                        DEBUG_PRINTF("MDNS: conflict detected in probe: %s\n", fullName.c_str());
                        _conflicted();
                        return NameConflict;
                    }
                } else if (dnsHeader.queryResponse == DNS_QR_RESPONSE) {
                    DEBUG_PRINTF("MDNS: conflict detected in response: %s\n", fullName.c_str());
                    _conflicted();
                    return NameConflict;
                }
            }
        }

    } else if (dnsHeader.queryResponse == DNS_QR_QUERY && dnsHeader.opCode == DNS_OPCODE_QUERY && _udp->remotePort() == DNS_MDNS_PORT) {

        DEBUG_PRINTF("MDNS: packet: processing, %s / %s:%u\n", parseHeader(dnsHeader).c_str(), _udp->remoteIP().toString().c_str(), _udp->remotePort());

        auto xid = dnsHeader.xid;
        auto q = dnsHeader.queryCount;

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
        auto unsupportedAddressTypeAskedFor = false;

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
                if ((rLen & DNS_COMPRESS_MARK) == DNS_COMPRESS_MARK) {

                    if (offset >= udp_len) goto bad_packet;    // READ
                    int xLen = _udp->read();                   // READ
                    if (xLen < 0) goto bad_packet;             // READ
                    offset++;                                  // READ
                    //
                    const int offs = ((static_cast<uint16_t>(rLen) & ~DNS_COMPRESS_MARK) << 8) | static_cast<uint16_t>(xLen);    // in practice, same as xLen
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
            } while (rLen > 0 && rLen <= DNS_LABEL_MAX_LENGTH);

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
                        if (buf[0] == 0x00 && (buf[2] == 0x00 || buf[2] == DNS_CACHE_FLUSH) && buf[3] == DNS_CLASS_IN) {
                            if ((0 == j && buf[1] == DNS_RECORD_A) || (0 < j && isServiceRecord(buf[1]))) {
                                recordsAskedFor[j] = true;
                            } else if (0 == j) {    // Query for our hostname
                                if (buf[1] != DNS_RECORD_A)
                                    unsupportedAddressTypeAskedFor = true;
                            } else if (j > 1) {    // Query for our service
                                if (!isServiceRecord(buf[1]))
                                    _messageSend(xid, PacketTypeNSEC, &_serviceRecords[j - 2]);
                            }
                        }
                    }
                }
            }
            if (next_bytes == 4)
                DEBUG_PRINTF(" <%s/%s/%s>\n", parseDNSType(buf[0], buf[1]).c_str(), parseDNSFlags(buf[2]).c_str(), parseDNSClass(buf[3]).c_str());
        }

        for (auto j = 0; j < recordsLength; j++) {
            if (recordsAskedFor[1] || recordsAskedFor[j]) {
                if (j == 0) _messageSend(xid, PacketTypeAddressRecord);
                else if (j > 1)
                    _messageSend(xid, PacketTypeServiceRecord, &_serviceRecords[j - 2]);
            }
        }

        if (unsupportedAddressTypeAskedFor)
            _messageSend(xid, PacketTypeNSEC);
#ifdef DEBUG_MDNS
    } else {

        DEBUG_PRINTF("MDNS: packet: debugging, %s / %s:%u\n", parseHeader(dnsHeader).c_str(), _udp->remoteIP().toString().c_str(), _udp->remotePort());

        struct Group {
            int offset;
            std::vector<String> names;
        };
        std::vector<Group> groups;
        auto uncompressAtOffset = [&](int offs) -> String {    // not sure this is correct if > first group
            int cnts = 0;
            for (int i = 0; i < groups.size(); i++) {
                cnts += groups[i].offset;
                for (int j = 0; j < groups[i].names.size(); j++) {
                    if (groups[i].names[j].startsWith("(") && groups[i].names[j].endsWith(")")) {
                    }    // XXX
                    else {
                        if (offs < (cnts + groups[i].names[j].length()))
                            return (offs == cnts) ? groups[i].names[j] : String(groups[i].names[j].c_str()[offs - cnts]);
                        cnts += groups[i].names[j].length();
                    }
                }
            }
            return String();
        };
        int goffset = 0;

        for (int i = 0, q = static_cast<int>(dnsHeader.queryCount); i < q; i++) {

            DEBUG_PRINTF("MDNS: packet: debugging (not for us), query[%d/%u]: ", i, q);

            std::vector<String> names;
            int pCnt = 0, rLen = 0;
            do {
                if (offset >= udp_len) break;    // READ
                rLen = _udp->read();             // READ
                if (rLen < 0) break;             // READ
                offset++;                        // READ
                pCnt++;
                //
                // https://www.ietf.org/rfc/rfc1035.txt
                if ((rLen & DNS_COMPRESS_MARK) == DNS_COMPRESS_MARK) {
                    if (offset >= udp_len) goto bad_packet;    // READ
                    int xLen = _udp->read();                   // READ
                    if (xLen < 0) goto bad_packet;             // READ
                    offset++;                                  // READ
                    pCnt++;
                    //
                    const int offs = ((static_cast<uint16_t>(rLen) & ~DNS_COMPRESS_MARK) << 8) | static_cast<uint16_t>(xLen);    // in practice, same as xLen
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
                    names.push_back(name);
                }
            } while (rLen > 0 && rLen <= DNS_LABEL_MAX_LENGTH);

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
            groups.push_back({ .offset = goffset, .names = names });
            goffset += pCnt;

            DEBUG_PRINTF("%s <%s/%s/%s>\n", join(names, "").c_str(), parseDNSType(buf[0], buf[1]).c_str(), parseDNSFlags(buf[2]).c_str(), parseDNSClass(buf[3]).c_str());
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

MDNS::Status MDNS::_announce() {
    // now, should we re-announce our services again?
    auto now = millis(), out = (((uint32_t)DNS_TTL_DEFAULT / 2) + ((uint32_t)DNS_TTL_DEFAULT / 4)) * 1000UL;
    if ((now - _announceLast) > out) {
        DEBUG_PRINTF("MDNS: announce: services (%d)\n", _serviceRecords.size());
        for (const auto& record : _serviceRecords)
            _messageSend(XID_DEFAULT, PacketTypeServiceRecord, &record);
        _announceLast = now;
    }
    return Success;
}

void MDNS::_conflicted() {
    DEBUG_PRINTF("MDNS: conflicted\n");
    stop();
    const String suffix = getMacAddressBase();
    String baseName = _name;
    baseName.replace(TLD, "");
    _name = baseName + "-" + suffix + TLD;
    for (auto& record : _serviceRecords) {
        String baseServiceName = record.name;
        baseServiceName.replace(record.servName, "");
        record.name = baseServiceName + "-" + suffix + "." + record.servName;
    }
    auto status = start(_ipAddress, _name);
    DEBUG_PRINTF("MDNS: conflicted: renamed to %s (status=%s)\n", _name.c_str(), toString(status).c_str());
}

//

MDNS::Status MDNS::addServiceRecord(const ServiceProtocol proto, const uint16_t port, const String& name, const ServiceTextRecords& textRecords) {
    const auto __findFirstDotFromRight = [](const char* str) -> const char* {
        auto p = str + strlen(str);
        while (p > str && *p-- != '.')
            ;
        return &p[2];
    };
    DEBUG_PRINTF("MDNS: addServiceRecord: proto=%s, port=%u, name=%s, textRecords.size=%d,text=[%s]\n", toString(proto).c_str(), port, name.c_str(), textRecords.size(), join(textRecords, ",").c_str());
    if (name.isEmpty() || port == 0 || (proto != ServiceTCP && proto != ServiceUDP))
        return InvalidArgument;
    try {
        auto& record = _serviceRecords.emplace_back(ServiceRecord{ .port = port, .proto = proto, .name = name, .servName = String(__findFirstDotFromRight(name.c_str())) + String(_postfixForProtocol(proto)), .textRecords = textRecords });
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
            _messageSend(XID_DEFAULT, PacketTypeServiceRelease, &record);
        return true;
    });
    return Success;
}
MDNS::Status MDNS::removeAllServiceRecords() {
    DEBUG_PRINTF("MDNS: removeAllServiceRecords\n");
    std::erase_if(_serviceRecords, [&](const ServiceRecord& record) {
        if (_active)
            _messageSend(XID_DEFAULT, PacketTypeServiceRelease, &record);
        return true;
    });
    return Success;
}

//

void MDNS::_writeAddressRecord(uint8_t* buf, const int bufSize, const uint32_t ttl) const {
    _writeDNSName(buf, bufSize, _name.c_str(), true);
    buf[0] = DNS_RECORD_HI;
    buf[1] = DNS_RECORD_A;       // A record
    buf[2] = DNS_CACHE_FLUSH;    // cache flush: true
    buf[3] = DNS_CLASS_IN;       // class IN
    _udp->write(buf, DNS_DATA_LENGTH_IPV4);
    *((uint32_t*)&buf[0]) = htonl(ttl);
    *((uint16_t*)&buf[4]) = htons(4);    // data length (IP address)
    _udp->write(buf, 6);
    buf[0] = _ipAddress[0];
    buf[1] = _ipAddress[1];
    buf[2] = _ipAddress[2];
    buf[3] = _ipAddress[3];
    _udp->write(buf, 4);
}
void MDNS::_writeServiceRecord(uint8_t* buf, const int bufSize, const ServiceRecord* serviceRecord, const uint32_t ttl) const {
    _writeSRVName(buf, bufSize, serviceRecord, true);
    buf[0] = DNS_RECORD_HI;
    buf[1] = DNS_RECORD_PTR;        // PTR record
    buf[2] = DNS_CACHE_NO_FLUSH;    // no cache flush
    buf[3] = DNS_CLASS_IN;          // class IN
    _udp->write(buf, DNS_DATA_LENGTH_IPV4);
    *((uint32_t*)&buf[0]) = htonl(ttl);
    *((uint16_t*)&buf[4]) = htons(serviceRecord->name.length() + 13); // data length (+13 = "._tcp.local" or "._udp.local" + 1  byte zero termination)
    _udp->write(buf, 6);
    _writeSRVName(buf, bufSize, serviceRecord, false);
}
void MDNS::_writeSRVName(uint8_t* buf, const int bufSize, const ServiceRecord* serviceRecord, const bool tld) const {
    _writeDNSName(buf, bufSize, tld ? serviceRecord->servName.c_str() : serviceRecord->name.c_str(), tld);
    if (!tld) {
        auto srv_type = _postfixForProtocol(serviceRecord->proto);
        if (srv_type[0] != '\0')
            _writeDNSName(buf, bufSize, &srv_type[1], true);    // eat the dot at the beginning
    }
}
void MDNS::_writeDNSName(uint8_t* buf, const int bufSize, const char* name, const bool zeroTerminate) const {
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
