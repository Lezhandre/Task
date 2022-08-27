#include "PCAP.h"
#include <fstream>

void pcap_hdr_t::applyToAllFields(std::function<void(char*, size_t)> func) {
    func((char*)&(this->magic_number), sizeof(this->magic_number));
    func((char*)&(this->network), sizeof(this->network));
    func((char*)&(this->sigfigs), sizeof(this->sigfigs));
    func((char*)&(this->snaplen), sizeof(this->snaplen));
    func((char*)&(this->thiszone), sizeof(this->thiszone));
    func((char*)&(this->version_major), sizeof(this->version_major));
    func((char*)&(this->version_minor), sizeof(this->version_minor));
}

void pcaprec_hdr_t::applyToAllFields(std::function<void(char*, size_t)> func) {
    func((char*)&(this->incl_len), sizeof(this->incl_len));
    func((char*)&(this->orig_len), sizeof(this->orig_len));
    func((char*)&(this->ts_sec), sizeof(this->ts_sec));
    func((char*)&(this->ts_usec), sizeof(this->ts_usec));
}

PCAPReader::PCAPReader(const std::string &fileName) : fileName(fileName) {
    pcap_hdr_t pcap_header;
    pcaprec_hdr_t pcap_pack_header;
    std::ifstream fin(fileName, std::ios::binary);
    fin.read((char*)&pcap_header, sizeof(pcap_hdr_t));
    switch (pcap_header.magic_number)
    {
        case IDENTICAL_NUMBER:
            fromRawView = [](char* data, size_t size){
            };
            break;
        case SWAPPED_NUMBER:
            fromRawView = [](char* data, size_t size){
                for (size_t i = 0; i < size / 2; ++i)
                    std::swap(data[i], data[size - 1 - i]);
            };
            break;
        default:
            throw std::runtime_error("Unknown format of file");
    }
    pcap_header.applyToAllFields(fromRawView);
    fromRawView((char*)&pcap_header.magic_number, sizeof(pcap_header.magic_number));
    if (fin.fail())
        throw std::runtime_error("Global header is uncompleted");
    while (!fin.eof()) {
        fin.read((char*)&pcap_pack_header, sizeof(pcaprec_hdr_t));
        pcap_pack_header.applyToAllFields(fromRawView);
        if (fin.eof())
            break;
        if (fin.fail())
            throw std::runtime_error("Record header is uncompleted");
        if (pcap_pack_header.orig_len > pcap_header.snaplen)
            throw std::runtime_error("Lengths in record header are incorrect");
        if (pcap_pack_header.orig_len >= pcap_pack_header.incl_len)
            packets.push_back({fin.tellg(), pcap_pack_header.orig_len});
        else
            packets.push_back({fin.tellg(), pcap_header.snaplen});
        preparedPayloadSize += packets.back().payload_size;
        fin.seekg(packets.back().payload_size, fin.cur);
    }
}

uint64_t PCAPReader::packetsCount() const {
    return packets.size();
}

uint64_t PCAPReader::payloadSize() const {
    return preparedPayloadSize;
}