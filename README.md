
## Overview

The original version was highly defective and non-compliant to RFC (in such ways as the encoding of TXT records was totally incorrect, DNS name compression being partly supported). Futhermore, it was poorly implemented and highly fragile with some very obtuse logic and hard coded and side-effectg behaviours.

The renovated version:

* compliant to RFC, interoperable tested (adoc against devices and tools)
* improved service handling, employs NSEC records, supports probing, does conflict checking, answers reverse address (arpa) queries
* removes horrific pointer and memory usage, by adopting Strings and C++ std components
* highly modular and extensible, with remaining questionable jailed (e.g. query matching, UDP read/write)
* adds robust error checking, data validation (class interface usage and network packet reception)
* removes magic numbers in place of defined and configurable constants
* is ***extensively*** instrumented at software, protocol and network levels
* employs const correctness, references, and modern C++ containers, algorithms
* reduced duplicative data copying and intermediate buffering

It still needs work, primarily the messageRecv flow to refactor the matching algorithm and tidy up the UDP / Name parsing.

The messageSend (messageSend -> message -> records -> elements) flow is pretty robust and clean and really to be reimplemented as OO.

Remaining major functionality in order of priority (1) duplicate question suppression (to reduce processing and network load), (2) message send DNS name compression (it's supported on receive) and/or truncated message support (both send/receive), (3) timing: probe/backoff timers, forward loss correction by duplicative sending (e.g. probes, goodbyes, etc). Some of these are captured in the TODO.

For performance increases, (1) build and cache the matching engine only when service/details are changed, (2) build and cache outgoing messages (except this is highly consumptive of memory). The duplicate question supression and improved use of timers would also help here.

## Origin

Significantly reworked from the original at https://github.com/arduino-libraries/ArduinoMDNS

## Usage

See LightMDNS.ino in examples: 

```C++

    udp = new WiFiUDP();
    mdns = new MDNS(*udp);

    mdns->serviceInsert(
        MDNS::Service::Builder ()
            .withName ("webserver._http")
            .withPort (80)
            .withProtocol (MDNS::Service::Protocol::TCP)
            .withTXT(MDNS::Service::TXT::Builder ()
                .add("type", "example")
                .add("notreally", true)
                .build())
            .build()
    );

  mdns->start(WiFi.localIP (), "arduinoLightMDNS");

  ...

  mdns->process();

  ...

    // 1. MQTT Broker with SSL Certificate Fingerprint
    const uint8_t cert_fingerprint[] = {
        0x5A, 0x2E, 0x16, 0xC7, 0x61, 0x47, 0x83, 0x28, 0x39, 0x15, 0x56, 0x9C, 0x44, 0x7B, 0x89, 0x2B,
        0x17, 0xD2, 0x44, 0x84, 0x96, 0xA4, 0xE2, 0x83, 0x90, 0x53, 0x47, 0xBB, 0x1C, 0x47, 0xF2, 0x5A
    };
    mdns->serviceInsert(
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
    );

```
