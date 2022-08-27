#include "catch.hpp"
#include "PCAP.h"

struct PCAPFile {
    std::string fileName;
    uint64_t packetsCount;
    uint64_t payloadSize;
};

const std::vector<PCAPFile> inputs = {{"examples/PPP-config.pcap",        22,  1538},
                                      {"examples/rtp-norm-transfer.pcap", 226, 294586},
                                      {"examples/nlmon-big.pcap",         13,  10356}};

TEST_CASE("Проверка количества пакетов", "[pcap]")
{
    for (const auto &input: inputs) {
        PCAPReader pcapReader{input.fileName};
        INFO("FileName " << input.fileName);
        CHECK(pcapReader.packetsCount() == input.packetsCount);
    }
}

TEST_CASE("Проверка объёма полезной нагрузки", "[pcap]")
{
    for (const auto &input: inputs) {
        PCAPReader pcapReader{input.fileName};
        INFO("FileName " << input.fileName);
        CHECK(pcapReader.payloadSize() == input.payloadSize);
    }
}
