
//  mgream 2024

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#include <Arduino.h>

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

//#define WIFI_SSID "ssid"    // Secrets.hpp
//#define WIFI_PASS "pass"    // Secrets.hpp
#define WIFI_HOST "arduinoLightMDNS"
#define WIFI_ADDR WiFi.localIP()

#if !defined(WIFI_SSID) || !defined(WIFI_PASS) || !defined(WIFI_HOST) || !defined(WIFI_ADDR)
#include "Secrets.hpp"
#endif
#if !defined(WIFI_SSID) || !defined(WIFI_PASS) || !defined(WIFI_HOST) || !defined(WIFI_ADDR)
#error "Require all of WIFI_SSID, WIFI_PASS, WIFI_HOST, WIFI_ADDR"
#endif

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#include <WiFi.h>
#include <WiFiUdp.h>
#include "LightMDNS.hpp"

WiFiUDP *udp;
MDNS *mdns;

#define HALT_ON_MDNS_ERROR(func, name) \
    { \
        MDNS::Status status; \
        if ((status = func) != MDNS::Status::Success) { \
            Serial.printf("MDNS %s: error=%s\n", name, MDNS::toString(status).c_str()); \
            esp_deep_sleep_start(); \
        } \
    }

void setupLightMDNS() {

    Serial.printf("MDNS setup\n");
    udp = new WiFiUDP();
    mdns = new MDNS(*udp);
    HALT_ON_MDNS_ERROR(mdns->begin(), "begin");

    // 1. MQTT Broker with SSL Certificate Fingerprint
    const uint8_t cert_fingerprint[] = {
        0x5A, 0x2E, 0x16, 0xC7, 0x61, 0x47, 0x83, 0x28, 0x39, 0x15, 0x56, 0x9C, 0x44, 0x7B, 0x89, 0x2B,
        0x17, 0xD2, 0x44, 0x84, 0x96, 0xA4, 0xE2, 0x83, 0x90, 0x53, 0x47, 0xBB, 0x1C, 0x47, 0xF2, 0x5A
    };
    HALT_ON_MDNS_ERROR(mdns->serviceInsert(
        MDNS::Service::Builder ()
            .withName ("Secure-MQTT._mqtt")
            .withPort (8883)
            .withProtocol (MDNS::Service::Protocol::TCP)
            .withTXT(MDNS::Service::TXT::Builder ()
                .add("cert", cert_fingerprint, sizeof(cert_fingerprint))
                .add("version", "3.1.1")
                .add("secure")
                .add("auth")
                .build())
            .build()
    ), "serviceRecordInsert");

    // 2. plain old web server
    HALT_ON_MDNS_ERROR(mdns->serviceInsert(
        MDNS::Service::Builder ()
            .withName ("webserver._http")
            .withPort (80)
            .withProtocol (MDNS::Service::Protocol::TCP)
            .withTXT(MDNS::Service::TXT::Builder ()
                .add("type", "example")
                .add("notreally", true)
                .build())
            .build()
    ), "serviceRecordInsert");

    HALT_ON_MDNS_ERROR(mdns->start(WIFI_ADDR, WIFI_HOST), "start");
    delay(25 * 100);
    HALT_ON_MDNS_ERROR(mdns->process(), "process");

    // 3. HTTP Print Service (IPP/AirPrint)
    HALT_ON_MDNS_ERROR(mdns->serviceInsert(
        MDNS::Service::Builder ()
            .withName ("ColorLaser._ipp")
            .withPort (631)
            .withProtocol (MDNS::Service::Protocol::TCP)
            .withTXT(MDNS::Service::TXT::Builder ()
                .add("txtvers", 1)
                .add("rp", "printers/colorlaser")
                .add("pdl", "application/pdf,image/jpeg,image/urf")
                .add("Color")
                .add("Duplex", false)
                .add("UUID", "564e4333-4230-3431-3533-186024c51c02")
                .build())
            .build()
    ), "serviceRecordInsert");
}

void loopLightMDNS() {
    HALT_ON_MDNS_ERROR(mdns->process(), "process");
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

void setupWiFi(const String &host, const String &ssid, const String &pass);

void setup() {

    Serial.begin(115200);
    delay(25 * 100);

    setupWiFi(WIFI_HOST, WIFI_SSID, WIFI_PASS);
    setupLightMDNS();
}

void loop() {
    delay(500);
    loopLightMDNS();
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#include <WiFi.h>

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

template<size_t N>
String BytesToHexString(const uint8_t bytes[], const char *separator = ":") {
    constexpr size_t separator_max = 1;    // change if needed
    if (strlen(separator) > separator_max)
        return String("");
    char buffer[(N * 2) + ((N - 1) * separator_max) + 1] = { '\0' }, *buffer_ptr = buffer;
    for (auto i = 0; i < N; i++) {
        if (i > 0 && separator[0] != '\0')
            for (auto separator_ptr = separator; *separator_ptr != '\0';)
                *buffer_ptr++ = *separator_ptr++;
        static const char hex_chars[] = "0123456789abcdef";
        *buffer_ptr++ = hex_chars[(bytes[i] >> 4) & 0x0F];
        *buffer_ptr++ = hex_chars[bytes[i] & 0x0F];
    }
    *buffer_ptr = '\0';
    return String(buffer);
}
template<typename T>
String ArithmeticToString(const T &n, const int x = -1, const bool t = false) {
    static_assert(std::is_arithmetic_v<T>, "T must be an arithmetic type");
    char s[64 + 1];
    if constexpr (std::is_integral_v<T>)
        return (x == -1 || x == 10) ? String(n) : String(ltoa(static_cast<long>(n), s, x));
    else if constexpr (std::is_floating_point_v<T>) {
        dtostrf(n, 0, x == -1 ? 2 : x, s);
        if (t) {
            char *d = nullptr, *e = s;
            while (*e != '\0') {
                if (*e == '.')
                    d = e;
                e++;
            }
            e--;
            if (d)
                while (e > d + 1 && *e == '0')
                    *e-- = '\0';
            else
                *e++ = '.', *e++ = '0', *e = '\0';
        }
        return String(s);
    }
};

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

static String _ssid_to_string(const uint8_t ssid[], const uint8_t ssid_len) {
    return String(reinterpret_cast<const char *>(ssid), ssid_len);
}
static String _bssid_to_string(const uint8_t bssid[]) {
    return BytesToHexString<6>(bssid);
}
static String _authmode_to_string(const wifi_auth_mode_t authmode) {
    switch (authmode) {
        case WIFI_AUTH_OPEN: return "OPEN";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA-PSK";
        case WIFI_AUTH_WPA2_PSK: return "WPA2-PSK";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/2-PSK";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "ENTERPRISE";
        default: return "UNDEFINED_(" + ArithmeticToString(static_cast<int>(authmode)) + ")";
    }
}
static String _error_to_string(const wifi_err_reason_t reason) {
    switch (reason) {
        case WIFI_REASON_UNSPECIFIED: return "UNSPECIFIED";
        case WIFI_REASON_AUTH_EXPIRE: return "AUTH_EXPIRE";
        case WIFI_REASON_AUTH_LEAVE: return "AUTH_LEAVE";
        case WIFI_REASON_ASSOC_EXPIRE: return "ASSOC_EXPIRE";
        case WIFI_REASON_ASSOC_TOOMANY: return "ASSOC_TOOMANY";
        case WIFI_REASON_NOT_AUTHED: return "NOT_AUTHED";
        case WIFI_REASON_NOT_ASSOCED: return "NOT_ASSOCED";
        case WIFI_REASON_ASSOC_LEAVE: return "ASSOC_LEAVE";
        case WIFI_REASON_ASSOC_NOT_AUTHED: return "ASSOC_NOT_AUTHED";
        case WIFI_REASON_DISASSOC_PWRCAP_BAD: return "DISASSOC_PWRCAP_BAD";
        case WIFI_REASON_DISASSOC_SUPCHAN_BAD: return "DISASSOC_SUPCHAN_BAD";
        case WIFI_REASON_IE_INVALID: return "IE_INVALID";
        case WIFI_REASON_MIC_FAILURE: return "MIC_FAILURE";
        case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT: return "4WAY_HANDSHAKE_TIMEOUT";
        case WIFI_REASON_GROUP_KEY_UPDATE_TIMEOUT: return "GROUP_KEY_UPDATE_TIMEOUT";
        case WIFI_REASON_IE_IN_4WAY_DIFFERS: return "IE_IN_4WAY_DIFFERS";
        case WIFI_REASON_GROUP_CIPHER_INVALID: return "GROUP_CIPHER_INVALID";
        case WIFI_REASON_PAIRWISE_CIPHER_INVALID: return "PAIRWISE_CIPHER_INVALID";
        case WIFI_REASON_AKMP_INVALID: return "AKMP_INVALID";
        case WIFI_REASON_UNSUPP_RSN_IE_VERSION: return "UNSUPP_RSN_IE_VERSION";
        case WIFI_REASON_INVALID_RSN_IE_CAP: return "INVALID_RSN_IE_CAP";
        case WIFI_REASON_802_1X_AUTH_FAILED: return "802_1X_AUTH_FAILED";
        case WIFI_REASON_CIPHER_SUITE_REJECTED: return "CIPHER_SUITE_REJECTED";
        case WIFI_REASON_BEACON_TIMEOUT: return "BEACON_TIMEOUT";
        case WIFI_REASON_NO_AP_FOUND: return "NO_AP_FOUND";
        case WIFI_REASON_AUTH_FAIL: return "AUTH_FAIL";
        case WIFI_REASON_ASSOC_FAIL: return "ASSOC_FAIL";
        case WIFI_REASON_HANDSHAKE_TIMEOUT: return "HANDSHAKE_TIMEOUT";
        case WIFI_REASON_CONNECTION_FAIL: return "CONNECTION_FAIL";
        default: return "UNDEFINED_(" + ArithmeticToString(static_cast<int>(reason)) + ")";
    }
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

static volatile bool wiFiConnected = false, wiFiAllocated = false;
static void wiFiEvents(WiFiEvent_t event, WiFiEventInfo_t info) {
    if (event == WiFiEvent_t::ARDUINO_EVENT_WIFI_STA_CONNECTED) {
        Serial.printf("WiFiEvent: ARDUINO_EVENT_WIFI_STA_CONNECTED (ssid=%s, bssid=%s, channel=%d, authmode=%s, rssi=%d)\n",
                      _ssid_to_string(info.wifi_sta_connected.ssid, info.wifi_sta_connected.ssid_len).c_str(),
                      _bssid_to_string(info.wifi_sta_connected.bssid).c_str(), (int)info.wifi_sta_connected.channel,
                      _authmode_to_string(info.wifi_sta_connected.authmode).c_str(), WiFi.RSSI());
        wiFiConnected = true;
    } else if (event == WiFiEvent_t::ARDUINO_EVENT_WIFI_STA_GOT_IP) {
        Serial.printf("WiFiEvent: ARDUINO_EVENT_WIFI_STA_GOT_IP (address=%s)\n", IPAddress(info.got_ip.ip_info.ip.addr).toString().c_str());
        wiFiAllocated = true;
    } else if (event == WiFiEvent_t::ARDUINO_EVENT_WIFI_STA_DISCONNECTED) {
        Serial.printf("WiFiEvent: ARDUINO_EVENT_WIFI_STA_DISCONNECTED (ssid=%s, bssid=%s, reason=%s)\n",
                      _ssid_to_string(info.wifi_sta_disconnected.ssid, info.wifi_sta_disconnected.ssid_len).c_str(),
                      _bssid_to_string(info.wifi_sta_disconnected.bssid).c_str(), _error_to_string((wifi_err_reason_t)info.wifi_sta_disconnected.reason).c_str());
        wiFiConnected = false;
        wiFiAllocated = false;
    }
}

// -----------------------------------------------------------------------------------------------

void wiFiWaitfor(const char *name, volatile bool &flag) {
    Serial.printf("WiFi waiting for state=%s ", name);
    while (!flag) {
        delay(500);
        Serial.print(".");
    }
    Serial.printf(" done\n");
}

// -----------------------------------------------------------------------------------------------

void setupWiFi(const String &host, const String &ssid, const String &pass) {
    Serial.printf("WiFi startup\n");
    WiFi.persistent(false);
    WiFi.onEvent(wiFiEvents);
    WiFi.setHostname(host.c_str());
    WiFi.setAutoReconnect(true);
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, pass);
    WiFi.setTxPower(WIFI_POWER_8_5dBm);    // XXX ?!? for AUTH_EXPIRE ... flash access problem ...  https://github.com/espressif/arduino-esp32/issues/2144
    wiFiWaitfor("connected", wiFiConnected);
    wiFiWaitfor("allocated", wiFiAllocated);
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------
