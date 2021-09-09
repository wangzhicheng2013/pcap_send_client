#include "pcap_send_client.hpp"
int main() {
    char pcap_path[128] = "";
    char device[64] = "";
    std::cout << "pcap path = ";
    std::cin >> pcap_path;
    std::cout << "device = ";
    std::cin >> device;
    pcap_send_client client;
    client.set_device(device);
    if (client.init()) {
        std::cout << client.send_pcap_file(pcap_path) << std::endl;
    }

    return 0;
}