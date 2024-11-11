
//  mgream 2024

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#include <Arduino.h>

#include "Common.hpp"

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

//#define WIFI_SSID "ssid"    // Secrets.hpp
//#define WIFI_PASS "pass"    // Secrest.hpp
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
