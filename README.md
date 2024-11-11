
The original version was highly defective and non-compliant to RFC (in such ways as the encoding of TXT records was totally incorrect, DNS name compression being partly supported). Futhermore, it was poorly implemented and highly fragile with some very obtuse logic and hard coded and side-effectg behaviours.

The renovated version:

1. RFC compliant to RFC, interoperable tested (adoc against devices and tools)
2. improved service handling, employs NSEC records, supports probing, does conflict checking, answers reverse address (arpa) queries
3. removes horrific pointer and memory usage, by adopting Strings and C++ std components
4. highly modular and extensible, with remaining questionable jailed (e.g. query matching, UDP read/write)
5. adds robust error checking, data validation (class interface usage and network packet reception)
6. removes magic numbers in place of defined and configurable constants
7. is ***extensively*** instrumented at software, protocol and network levels
8. employs const correctness, references, and modern C++ containers, algorithms
9. reduced duplicative data copying and intermediate buffering

It still needs work, primarily the messageRecv flow to refactor the matching algorithm and tidy up the UDP / Name parsing.

The messageSend (messageSend -> message -> records -> elements) flow is pretty robust and clean and really to be reimplemented as OO.

Remaining major functionality in order of priority (1) duplicate question suppression (to reduce processing and network load), (2) message send DNS name compression (it's supported on receive) and/or truncated message support (both send/receive), (3) timing: probe/backoff timers, forward loss correction by duplicative sending (e.g. probes, goodbyes, etc). Some of these are captured in the TODO.

For performance increases, (1) build and cache the matching engine only when service/details are changed, (2) build and cache outgoing messages (except this is highly consumptive of memory). The duplicate question supression and improved use of timers would also help here.

Originally from https://github.com/arduino-libraries/ArduinoMDNS


