#pragma once

#include <string>
#include <vector>
#include <functional>

struct PCAPPacket {
    std::streampos offset_in_document;
    size_t payload_size;
};

#define IDENTICAL_NUMBER 0xa1b2c3d4
#define SWAPPED_NUMBER 0xd4c3b2a1
#define MODIFIED_NUMBER 0x0xa1b2cd34

typedef struct pcap_hdr_s {
    uint32_t magic_number;   
    uint16_t version_major;  
    uint16_t version_minor;  
    int32_t  thiszone;       
    uint32_t sigfigs;        
    uint32_t snaplen;        
    uint32_t network;        
    void applyToAllFields(std::function<void(char*, size_t)>);
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         
    uint32_t ts_usec;        
    uint32_t incl_len;       
    uint32_t orig_len;       
    void applyToAllFields(std::function<void(char*, size_t)>);
} pcaprec_hdr_t;

class PCAPReader {
    const std::string fileName;
    std::vector<PCAPPacket> packets;
    size_t preparedPayloadSize = 0;
    std::function<void(char*, size_t)> fromRawView;
public:
    explicit PCAPReader(const std::string &fileName);

    // Количество пакетов в файле
    uint64_t packetsCount() const;

    // Общий объём полезной нагрузки (без учёта заголовков)
    uint64_t payloadSize() const;
};
