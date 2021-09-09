#pragma once
#include <pcap.h>
#include <iostream>
class pcap_send_client {
public:
    virtual ~pcap_send_client() {
        if (handle_) {
            pcap_close(handle_);
            handle_ = nullptr;
        }
    }
    inline void set_snap_len(int len) {
        snap_len_ = len;
    }
    inline void set_time_out(int to) {
        time_out_ = to;
    }
    inline void set_device(const char *s) {
        if (s) {
            device_ = s;
        }
    }
    bool init() {
        handle_ = pcap_open_live(device_, snap_len_, 1, time_out_, err_buf_);
        if (!handle_) {
            std::cerr << "pcap open failed, error:" << err_buf_ << std::endl;
            return false;
        }
        if (pcap_setnonblock(handle_, 1, err_buf_) < 0) {
            std::cerr << "pcap set nonblock failed, error:" << err_buf_ << std::endl;
            return false;
        }
        return true;
    }
    bool send_pcap_file(const char *pcap_path) {
        static const int MTU_LEN = 1500;
        if (!pcap_path) {
            return false;
        }
        pcap_t *pcap_ptr = pcap_open_offline(pcap_path, err_buf_);
        if (!pcap_ptr) {
            std::cerr << "pcap open failed, error:" << err_buf_ << std::endl;
            return false;
        }
        bool succ = true;
        int len = 0;
        struct pcap_pkthdr pkthdr = { 0 };
        while (true) {
            const u_char *pkt_buffer = pcap_next(pcap_ptr, &pkthdr);
            if (!pkt_buffer) {
                break;
            }
            if (pkthdr.caplen > MTU_LEN) {
                succ = false;
                std::cerr << "read pcap body size over:" << MTU_LEN << "bytes!" << std::endl;
                break;
            }
            len = pcap_inject(handle_, pkt_buffer, pkthdr.caplen);
            if (len != pkthdr.caplen) {
                succ = false;
                std::cerr << "pcap_inject len:" << len << " not equal with real len:" << pkthdr.caplen << std::endl;
            }
        }
        pcap_close(pcap_ptr);
        return succ;
    }
private:
    pcap_t *handle_ = nullptr;
    const char *device_ = "ens192";
    int snap_len_ = 2048;
    int time_out_ = 10;              // 10s
    char err_buf_[PCAP_ERRBUF_SIZE] = "";
};
